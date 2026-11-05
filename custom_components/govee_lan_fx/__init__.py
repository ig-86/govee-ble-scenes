"""Send Govee light scenes over Bluetooth, locally, without the Govee cloud.

Built for the Govee R1250 ceiling light, whose newer firmware:
  * applies cloud scenes late or not at all,
  * silently ignores LAN API ``ptReal`` packets,
  * only accepts *encrypted* BLE packets (Govee "v1" encryption).

This integration speaks that encrypted BLE protocol through Home Assistant's own
Bluetooth stack and wraps the light entity (e.g. from govee2mqtt) so that every
``light.turn_on`` call with an ``effect`` is delivered over Bluetooth. If Bluetooth
fails, the call falls back to the original (cloud) path.

configuration.yaml:

    govee_lan_fx:
      keep_alive: 300          # optional, seconds to keep the BLE link open after a scene
      lights:
        light.my_ceiling_light:
          mac: "AA:BB:CC:DD:EE:FF"   # the light's *Bluetooth* MAC
          sku: R1250

The domain name ``govee_lan_fx`` is kept for compatibility with dashboard cards that
look for a ``govee_lan_fx.play_scene`` / ``govee_lan_fx.effect_routes`` service.

See README.md for the protocol details.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import time
from typing import Any

import voluptuous as vol
from bleak_retry_connector import BleakClientWithServiceCache, establish_connection
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from homeassistant.components import bluetooth
from homeassistant.const import EVENT_HOMEASSISTANT_STARTED, EVENT_HOMEASSISTANT_STOP, EVENT_STATE_CHANGED
from homeassistant.core import Event, HomeAssistant, ServiceCall, ServiceResponse, SupportsResponse, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession

_LOGGER = logging.getLogger(__name__)
DOMAIN = "govee_lan_fx"

WRITE_UUID = "00010203-0405-0607-0809-0a0b0c0d2b11"
NOTIFY_UUID = "00010203-0405-0607-0809-0a0b0c0d2b10"
# Public pre-shared handshake key of Govee's "v1" BLE encryption (see README for sources).
PSK = b"MakingLifeSmarte"
# The Govee app sends scene data of <= 126 bytes as 20-byte "a3" rows and >= 165 bytes as
# large "a4" packets (no R1250 scene falls in between). Using the wrong one can lock up the light.
A3_MAX = 126
LIBRARY_URL = "https://app2.govee.com/appsku/v1/light-effect-libraries?sku={sku}"
LIBRARY_MAX_AGE = 7 * 86400

LIGHT_SCHEMA = vol.Schema({vol.Required("mac"): cv.string, vol.Optional("sku", default="R1250"): cv.string})
CONFIG_SCHEMA = vol.Schema(
    {DOMAIN: vol.Schema({
        vol.Required("lights"): vol.Schema({cv.entity_id: LIGHT_SCHEMA}),
        vol.Optional("keep_alive", default=300): vol.All(vol.Coerce(int), vol.Range(min=0, max=3600)),
    })},
    extra=vol.ALLOW_EXTRA,
)


# ---------------- encryption / packets ----------------
def _rc4(key: bytes, data: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 255
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 255
        j = (j + s[i]) & 255
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 255])
    return bytes(out)


def crypt(key: bytes, packet: bytes, decrypt: bool = False) -> bytes:
    """AES-128-ECB over the whole 16-byte blocks, RC4 (restarted per packet) over the rest."""
    n = len(packet) // 16 * 16
    c = Cipher(algorithms.AES(key), modes.ECB())
    o = c.decryptor() if decrypt else c.encryptor()
    return o.update(packet[:n]) + o.finalize() + _rc4(key, packet[n:])


def _xor(b: bytes) -> int:
    x = 0
    for v in b:
        x ^= v
    return x


def frame20(b) -> bytes:
    """Pad to 19 bytes and append the XOR checksum."""
    b = bytes(b) + bytes(19 - len(b))
    return b + bytes([_xor(b)])


def scene_packets(code: int, param_b64: str) -> list[bytes]:
    """Plain (unencrypted) packets for one scene from Govee's light-effect library."""
    v = bytearray(base64.b64decode(param_b64 or ""))
    out: list[bytes] = []
    if v:
        if v[0] == 0x50:  # the app rewrites the first byte of the library data
            v[0] = 0x58
        if len(v) <= A3_MAX:
            first, rest = v[:15], v[15:]
            parts = [rest[i:i + 17] for i in range(0, len(rest), 17)]
            out.append(frame20(bytes([0xA3, 0x00, 0x01, 1 + len(parts)]) + first))
            for i, p in enumerate(parts, 1):
                out.append(frame20(bytes([0xA3, 0xFF if i == len(parts) else i]) + p))
        else:
            first, rest = v[:237], v[237:]
            # even if everything fits in one packet the app adds an empty closing "a4 ffff" packet
            parts = [rest[i:i + 240] for i in range(0, len(rest), 240)] or [b""]
            n = 1 + len(parts)
            b = bytes([0xA4, 0, 0, 1, n & 255, n >> 8]) + first
            out.append(b + bytes([_xor(b)]))
            for i, p in enumerate(parts, 1):
                idx = 0xFFFF if i == len(parts) else i
                b = bytes([0xA4, idx & 255, idx >> 8]) + p
                out.append(b + bytes([_xor(b)]))
    out.append(frame20([0x33, 0x05, 0x04, code & 255, code >> 8]))
    return out


# ---------------- runtime ----------------
class GoveeFx:
    def __init__(self, hass: HomeAssistant, lights: dict[str, dict[str, str]], keep_alive: float = 300) -> None:
        self.hass = hass
        self.lights = lights
        self._library: dict[str, dict[str, dict[str, Any]]] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._sessions: dict[str, Session] = {}
        self._keep_alive = keep_alive

    def _cache_path(self, sku: str) -> str:
        return self.hass.config.path(".storage", f"govee_lan_fx_{sku}.json")

    async def library(self, sku: str) -> dict[str, dict[str, Any]]:
        if sku in self._library:
            return self._library[sku]
        path = self._cache_path(sku)

        def _read(max_age: float | None):
            if os.path.exists(path) and (max_age is None or time.time() - os.path.getmtime(path) < max_age):
                with open(path, encoding="utf-8") as f:
                    return json.load(f)
            return None

        scenes = await self.hass.async_add_executor_job(_read, LIBRARY_MAX_AGE)
        if scenes is None:
            try:
                scenes = await self._download(sku)
            except Exception as e:  # noqa: BLE001
                _LOGGER.warning("Could not download the Govee effect library for %s: %s", sku, e)
                scenes = await self.hass.async_add_executor_job(_read, None) or {}
            else:
                def _write():
                    with open(path, "w", encoding="utf-8") as f:
                        json.dump(scenes, f, ensure_ascii=False)
                await self.hass.async_add_executor_job(_write)
        self._library[sku] = scenes
        return scenes

    async def _download(self, sku: str) -> dict[str, dict[str, Any]]:
        session = async_get_clientsession(self.hass)
        async with session.get(LIBRARY_URL.format(sku=sku), timeout=20, headers={
            "AppVersion": "6.6.30",
            "User-Agent": "GoveeHome/6.6.30 (com.ihoment.GoVeeSensor; build:2; iOS 17.0.0) Alamofire/5.6.4",
        }) as r:
            data = await r.json(content_type=None)
        scenes = {}
        for cat in data["data"]["categories"]:
            for s in cat["scenes"]:
                if s.get("lightEffects"):
                    e = s["lightEffects"][0]
                    scenes[s["sceneName"]] = {"code": e["sceneCode"], "param": e.get("scenceParam") or ""}
        return scenes

    def _light(self, entity_id: str) -> dict[str, str]:
        light = self.lights.get(entity_id)
        if not light:
            raise HomeAssistantError(f"{entity_id} is not configured under govee_lan_fx")
        return light

    async def local_scenes(self, entity_id: str) -> list[str]:
        return sorted(await self.library(self._light(entity_id)["sku"]))

    async def play(self, entity_id: str, scene: str) -> float:
        light = self._light(entity_id)
        scenes = await self.library(light["sku"])
        s = scenes.get(scene) or next((v for k, v in scenes.items() if k.lower() == scene.lower()), None)
        if not s:
            raise HomeAssistantError(f"'{scene}' is not in the {light['sku']} effect library")
        packets = scene_packets(s["code"], s["param"])
        mac = light["mac"].upper()
        async with self._locks.setdefault(mac, asyncio.Lock()):
            t0 = time.monotonic()
            try:
                await asyncio.wait_for(self._send(mac, packets), 25)
            except asyncio.TimeoutError as e:
                raise HomeAssistantError(f"{entity_id}: Bluetooth timeout") from e
            took = time.monotonic() - t0
        _LOGGER.info("%s: '%s' sent over Bluetooth (%.1f s)", entity_id, scene, took)
        return took

    async def _send(self, mac: str, packets: list[bytes]) -> None:
        """Reuse the open session (fast); otherwise connect. Reconnect once on a write error."""
        session = self._sessions.get(mac)
        if session is not None and session.alive():
            try:
                await session.scene(packets)
                return
            except Exception as e:  # noqa: BLE001
                _LOGGER.debug("%s: open session failed, reconnecting: %s", mac, e)
                await session.close()
        session = await self._connect(mac, max(len(p) for p in packets))
        self._sessions[mac] = session
        await session.scene(packets)

    async def _connect(self, mac: str, largest: int) -> "Session":
        dev = bluetooth.async_ble_device_from_address(self.hass, mac, connectable=True)
        if dev is None:
            raise HomeAssistantError(
                f"{mac} is not visible over Bluetooth (is the Govee app connected to it?)")
        session = Session(mac, self._keep_alive)
        client = await establish_connection(
            BleakClientWithServiceCache, dev, f"govee {mac}", disconnected_callback=session.disconnected,
            max_attempts=3)
        session.client = client
        try:
            # large scenes ("a4") need 244-byte writes: MTU must be >= 247
            mtu = client.mtu_size
            backend = getattr(client, "_backend", None)
            if mtu < 247 and backend is not None and hasattr(backend, "_acquire_mtu"):
                try:
                    await backend._acquire_mtu()  # BlueZ: learn the real MTU
                except Exception as e:  # noqa: BLE001
                    _LOGGER.debug("Could not read MTU: %s", e)
                mtu = client.mtu_size
            if largest > mtu - 3:
                raise HomeAssistantError(f"Bluetooth MTU {mtu} is too small for a {largest}-byte packet")
            await session.handshake()
        except BaseException:
            await session.close()
            raise
        _LOGGER.info("%s: Bluetooth session opened (MTU %s)", mac, mtu)
        return session


class Session:
    """An open, encrypted BLE session with one light.

    Like the Govee app it sends a keep-alive (aa 00) every 2 s, and it closes `keep_alive`
    seconds after the last scene so the phone app can connect again (the light accepts a
    single BLE connection at a time).
    """

    def __init__(self, mac: str, keep_alive: float) -> None:
        self.mac = mac
        self.keep_alive = keep_alive
        self.client: Any = None
        self.key: bytes | None = None
        self.queue: asyncio.Queue[bytes] = asyncio.Queue()
        self.last_used = time.monotonic()
        self._task: asyncio.Task | None = None
        self._write_lock = asyncio.Lock()
        self._closed = False

    def alive(self) -> bool:
        return not self._closed and self.client is not None and self.client.is_connected and self.key is not None

    def disconnected(self, _client: Any = None) -> None:
        if not self._closed:
            _LOGGER.info("%s: Bluetooth session closed", self.mac)
        self._closed = True
        try:
            current = asyncio.current_task()
        except RuntimeError:
            current = None
        if self._task and not self._task.done() and self._task is not current:
            self._task.cancel()

    async def close(self) -> None:
        self.disconnected()
        if self.client is not None:
            try:
                await self.client.disconnect()
            except Exception:  # noqa: BLE001
                pass

    async def _write(self, data: bytes) -> None:
        async with self._write_lock:
            await self.client.write_gatt_char(WRITE_UUID, data, response=False)

    async def _wait(self, key: bytes, prefix: bytes, timeout: float = 2.0) -> bytes | None:
        end = time.monotonic() + timeout
        while (left := end - time.monotonic()) > 0:
            try:
                d = crypt(key, await asyncio.wait_for(self.queue.get(), left), decrypt=True)
            except asyncio.TimeoutError:
                return None
            if d[:len(prefix)] == prefix:
                return d
        return None

    def _drain(self) -> None:
        while not self.queue.empty():
            self.queue.get_nowait()

    async def handshake(self) -> None:
        await self.client.start_notify(NOTIFY_UUID, lambda _, d: self.queue.put_nowait(bytes(d)))
        await self._write(crypt(PSK, frame20([0xE7, 0x01])))
        r = await self._wait(PSK, b"\xe7\x01")
        if not r:
            raise HomeAssistantError("the light did not answer the handshake")
        key = r[2:18]  # session key
        await self._write(crypt(PSK, frame20([0xE7, 0x02])))
        await self._wait(PSK, b"\xe7\x02", 1.0)
        self.key = key
        self._task = asyncio.get_running_loop().create_task(self._keep_alive_loop())

    async def scene(self, packets: list[bytes]) -> None:
        key = self.key
        self.last_used = time.monotonic()
        self._drain()
        data = [p for p in packets if p[0] in (0xA3, 0xA4)]
        for p in data:
            await self._write(crypt(key, p))
        if data and not await self._wait(key, bytes([data[0][0], 0x58])):
            _LOGGER.warning("%s: the light did not acknowledge the scene data", self.mac)
        await self._write(crypt(key, packets[-1]))
        if not await self._wait(key, b"\x33\x05"):
            _LOGGER.warning("%s: the light did not acknowledge the scene command", self.mac)
        self.last_used = time.monotonic()

    async def _keep_alive_loop(self) -> None:
        try:
            while self.alive():
                await asyncio.sleep(2)
                if time.monotonic() - self.last_used > self.keep_alive:
                    _LOGGER.info("%s: idle for %d s, releasing Bluetooth", self.mac, self.keep_alive)
                    break
                await self._write(crypt(self.key, frame20([0xAA, 0x00])))
        except asyncio.CancelledError:
            return
        except Exception as e:  # noqa: BLE001
            _LOGGER.debug("%s: keep-alive failed: %s", self.mac, e)
        await self.close()


def _ids(v: Any) -> list[str]:
    return [v] if isinstance(v, str) else list(v or [])


# ---------------- intercept light.turn_on(effect=...) ----------------
# Dashboards, cards, scenes, voice and automations all call light.turn_on(effect=X).
# We wrap the configured light entity: if the effect is in the local library it goes over
# Bluetooth; on failure it falls back to the original (cloud) implementation.
_MARK = "_govee_lan_fx_wrapped"


def _entity(hass: HomeAssistant, entity_id: str):
    comp = hass.data.get("entity_components", {}).get("light")
    return comp.get_entity(entity_id) if comp else None


def _wrap(hass: HomeAssistant, fx: GoveeFx, entity_id: str) -> bool:
    ent = _entity(hass, entity_id)
    if ent is None or getattr(ent, _MARK, False):
        return ent is not None
    original = ent.async_turn_on

    async def turn_on(**kw: Any) -> None:
        effect = kw.get("effect")
        if not effect:
            return await original(**kw)
        scenes = await fx.library(fx.lights[entity_id]["sku"])
        if effect not in scenes:
            return await original(**kw)
        other = {k: v for k, v in kw.items() if k != "effect"}
        st = hass.states.get(entity_id)
        if other or st is None or st.state != "on":
            # turn on / set brightness first, without the effect (fast path of the original integration)
            await original(**other)
        try:
            await fx.play(entity_id, effect)
        except Exception as e:  # noqa: BLE001
            _LOGGER.warning("%s: could not send '%s' over Bluetooth, falling back: %s", entity_id, effect, e)
            await original(**kw)

    ent.async_turn_on = turn_on
    setattr(ent, _MARK, True)
    _LOGGER.info("%s: effects are now sent over Bluetooth", entity_id)
    return True


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    conf = config.get(DOMAIN) or {}
    lights = {k: dict(v) for k, v in (conf.get("lights") or {}).items()}
    if not lights:
        _LOGGER.error("govee_lan_fx: no lights configured")
        return False
    fx = hass.data[DOMAIN] = GoveeFx(hass, lights, conf.get("keep_alive", 300))

    async def _close_all(*_: Any) -> None:
        for s in list(fx._sessions.values()):
            await s.close()

    hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, _close_all)

    @callback
    def _wrap_all(*_: Any) -> None:
        for eid in fx.lights:
            _wrap(hass, fx, eid)

    # the entity may appear late (MQTT discovery) or be recreated on reload: retry on its state changes
    @callback
    def _state_changed(event: Event) -> None:
        if event.data.get("entity_id") in fx.lights:
            _wrap(hass, fx, event.data["entity_id"])

    hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STARTED, _wrap_all)
    hass.bus.async_listen(EVENT_STATE_CHANGED, _state_changed)
    _wrap_all()

    async def play_scene(call: ServiceCall) -> None:
        errors = []
        for eid in _ids(call.data["entity_id"]):
            try:
                await fx.play(eid, call.data["scene"])
            except HomeAssistantError as e:
                errors.append(str(e))
        if errors:
            raise HomeAssistantError("; ".join(errors))

    async def effect_routes(call: ServiceCall) -> ServiceResponse:
        eid = _ids(call.data["entity_id"])[0]
        if eid not in fx.lights:
            return {"local": []}
        return {"local": await fx.local_scenes(eid), "path": "ble"}

    hass.services.async_register(
        DOMAIN, "play_scene", play_scene,
        schema=vol.Schema({vol.Required("entity_id"): vol.Any(cv.entity_id, [cv.entity_id]),
                           vol.Required("scene"): cv.string}))
    hass.services.async_register(
        DOMAIN, "effect_routes", effect_routes,
        schema=vol.Schema({vol.Required("entity_id"): vol.Any(cv.entity_id, [cv.entity_id])}),
        supports_response=SupportsResponse.ONLY)
    return True
