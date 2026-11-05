#!/usr/bin/env python3
"""Send a Govee scene over encrypted BLE ("v1") from any computer - no Home Assistant needed.

Usage:
    pip install bleak cryptography
    python govee_ble_scene.py --list [--sku R1250]
    python govee_ble_scene.py <BLE_MAC> "<Scene name>" [--sku R1250]

Example:
    python govee_ble_scene.py AA:BB:CC:DD:EE:FF Fire

Close the Govee app on your phone first: the light accepts one BLE connection at a time.
"""
import argparse
import asyncio
import base64
import json
import os
import sys
import time
import urllib.request

from bleak import BleakClient, BleakScanner
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

WRITE_UUID = "00010203-0405-0607-0809-0a0b0c0d2b11"
NOTIFY_UUID = "00010203-0405-0607-0809-0a0b0c0d2b10"
PSK = b"MakingLifeSmarte"
A3_MAX = 126
CACHE_DIR = os.path.dirname(os.path.abspath(__file__))


def _rc4(key, data):
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


def crypt(key, p, decrypt=False):
    n = len(p) // 16 * 16
    c = Cipher(algorithms.AES(key), modes.ECB())
    o = c.decryptor() if decrypt else c.encryptor()
    return o.update(p[:n]) + o.finalize() + _rc4(key, p[n:])


def _xor(b):
    x = 0
    for v in b:
        x ^= v
    return x


def frame20(b):
    b = bytes(b) + bytes(19 - len(b))
    return b + bytes([_xor(b)])


def scene_packets(code, param_b64):
    v = bytearray(base64.b64decode(param_b64 or ""))
    out = []
    if v:
        if v[0] == 0x50:
            v[0] = 0x58
        if len(v) <= A3_MAX:
            first, rest = v[:15], v[15:]
            parts = [rest[i:i + 17] for i in range(0, len(rest), 17)]
            out.append(frame20(bytes([0xA3, 0x00, 0x01, 1 + len(parts)]) + first))
            for i, p in enumerate(parts, 1):
                out.append(frame20(bytes([0xA3, 0xFF if i == len(parts) else i]) + p))
        else:
            first, rest = v[:237], v[237:]
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


def library(sku):
    cache = os.path.join(CACHE_DIR, f"govee_scenes_{sku}.json")
    if os.path.exists(cache) and time.time() - os.path.getmtime(cache) < 7 * 86400:
        with open(cache, encoding="utf-8") as f:
            return json.load(f)
    req = urllib.request.Request(
        f"https://app2.govee.com/appsku/v1/light-effect-libraries?sku={sku}",
        headers={"AppVersion": "6.6.30",
                 "User-Agent": "GoveeHome/6.6.30 (com.ihoment.GoVeeSensor; build:2; iOS 17.0.0) Alamofire/5.6.4"})
    with urllib.request.urlopen(req, timeout=20) as r:
        data = json.load(r)
    scenes = {}
    for cat in data["data"]["categories"]:
        for s in cat["scenes"]:
            if s.get("lightEffects"):
                e = s["lightEffects"][0]
                scenes[s["sceneName"]] = {"code": e["sceneCode"], "param": e.get("scenceParam") or ""}
    with open(cache, "w", encoding="utf-8") as f:
        json.dump(scenes, f, ensure_ascii=False)
    return scenes


async def send(mac, packets):
    t0 = time.time()
    dev = await BleakScanner.find_device_by_address(mac, timeout=20)
    if not dev:
        raise RuntimeError("light not found over Bluetooth (is the Govee app connected?)")
    async with BleakClient(dev) as c:
        q = asyncio.Queue()
        await c.start_notify(NOTIFY_UUID, lambda _, d: q.put_nowait(bytes(d)))

        async def wait(key, prefix, timeout=2.0):
            end = time.time() + timeout
            while time.time() < end:
                try:
                    d = crypt(key, await asyncio.wait_for(q.get(), end - time.time()), decrypt=True)
                except asyncio.TimeoutError:
                    break
                if d[:len(prefix)] == prefix:
                    return d
            return None

        await c.write_gatt_char(WRITE_UUID, crypt(PSK, frame20([0xE7, 0x01])), response=False)
        r = await wait(PSK, b"\xe7\x01")
        if not r:
            raise RuntimeError("no handshake reply")
        key = r[2:18]
        await c.write_gatt_char(WRITE_UUID, crypt(PSK, frame20([0xE7, 0x02])), response=False)
        await wait(PSK, b"\xe7\x02", 1.0)
        data = [p for p in packets if p[0] in (0xA3, 0xA4)]
        for p in data:
            await c.write_gatt_char(WRITE_UUID, crypt(key, p), response=False)
        if data and not await wait(key, bytes([data[0][0], 0x58])):
            print("warning: scene data not acknowledged", file=sys.stderr)
        await c.write_gatt_char(WRITE_UUID, crypt(key, packets[-1]), response=False)
        ok = await wait(key, b"\x33\x05")
        await c.write_gatt_char(WRITE_UUID, crypt(key, frame20([0xAA, 0x00])), response=False)
        await asyncio.sleep(0.5)
        return ok is not None, time.time() - t0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mac", nargs="?")
    ap.add_argument("scene", nargs="?")
    ap.add_argument("--sku", default="R1250")
    ap.add_argument("--list", action="store_true", help="list the scenes of this SKU")
    a = ap.parse_args()
    scenes = library(a.sku)
    if a.list:
        print("\n".join(sorted(scenes)))
        return
    if not a.mac or not a.scene:
        ap.error("MAC and scene name are required")
    s = scenes.get(a.scene) or next((v for k, v in scenes.items() if k.lower() == a.scene.lower()), None)
    if not s:
        sys.exit(f"'{a.scene}' is not in the {a.sku} library (try --list)")
    ok, took = asyncio.run(send(a.mac, scene_packets(s["code"], s["param"])))
    print(f"{'OK' if ok else 'NOT ACKNOWLEDGED'}: '{a.scene}' (code {s['code']}) in {took:.1f} s")
    sys.exit(0 if ok else 3)


if __name__ == "__main__":
    main()
