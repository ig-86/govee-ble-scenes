# Govee BLE Scenes for Home Assistant

Send **Govee light scenes over Bluetooth, locally** – no cloud, no LAN API – for lights whose newer
firmware only accepts **encrypted BLE**. Built and verified on the **Govee R1250 ceiling light**.

🇹🇷 [Türkçe açıklama aşağıda](#türkçe)

## Why

On the R1250 (and likely other recent models):

| Path | Result |
|---|---|
| Govee cloud (e.g. govee2mqtt, official API) | Scenes applied seconds late or **not at all**. Scenes whose data is not stored on the light (e.g. *Fire*) turn the light **dark**. |
| LAN API `ptReal` | **Silently ignored** (power, brightness, scenes – nothing). Plain LAN commands (`turn`, `brightness`, `colorwc`) still work. |
| BLE (what the Govee app uses) | Works, but traffic is **encrypted** per session. |

This integration implements that encrypted BLE protocol on top of Home Assistant's own Bluetooth stack.

## What it does

- Wraps your existing light entity (for example from **govee2mqtt**): every `light.turn_on` with an
  `effect` – from any dashboard, card, scene, voice assistant or automation – is sent **over Bluetooth**.
  Other commands (on/off, brightness, color) keep using your existing integration.
- If Bluetooth fails, the command **falls back** to the original (cloud) path.
- Keeps the BLE link open for a while after a scene (default 5 min) so the next scene arrives in **~0.3 s**
  (the first one takes ~1–2 s to connect).
- Downloads the scene data from Govee's public effect library once and caches it (7 days).
- Services: `govee_lan_fx.play_scene` and `govee_lan_fx.effect_routes`.

## Install

**HACS:** HACS → ⋮ → *Custom repositories* → add `https://github.com/ig-86/govee-ble-scenes`
(category *Integration*) → install **Govee BLE Scenes** → restart Home Assistant.

**Manual:** copy `custom_components/govee_lan_fx` to `/config/custom_components/` and restart.

Then add to `configuration.yaml` and restart again:

```yaml
govee_lan_fx:
  keep_alive: 300            # optional: seconds to keep Bluetooth open after a scene (0 = disconnect each time)
  lights:
    light.my_ceiling_light:  # your existing Govee light entity
      mac: "AA:BB:CC:DD:EE:FF"   # the light's BLUETOOTH MAC (not the Wi-Fi one)
      sku: R1250
```

Find the Bluetooth MAC in HA → Settings → Devices → Bluetooth (the R1250 advertises as `GVR1250xxxx`),
or with any BLE scanner app. On the unit we tested it was the Wi-Fi MAC + 1.

**Requirements:** a Bluetooth adapter (or a connectable Bluetooth proxy) in range of the light, with
MTU ≥ 247 for large scenes. Tested with a Raspberry Pi 5's built-in Bluetooth.

## Important

- **The light accepts only one Bluetooth connection.** While the Govee phone app is connected over
  Bluetooth (even in the background), Home Assistant can't reach the light – close the app.
  Likewise, during `keep_alive` the phone app can only use Wi-Fi.
- ⚠️ **Malformed scene data can lock up the light** (no BLE, no LAN) until you power-cycle it at the
  wall switch. Don't experiment with the packet format; capture what the app does first
  (see `tools/decode_btsnoop.py`).
- After a Bluetooth scene, the entity's `effect` attribute is not updated (the original integration
  never saw the command).
- Speed-adjustable scenes are sent with the library's default speed.

## Protocol notes

**Encryption ("v1")** – known from earlier public work (see credits):
1. Write `e7 01` (20-byte frame, XOR checksum in the last byte) encrypted with the public pre-shared
   key `MakingLifeSmarte`. The reply (same key) carries the **session key** in bytes 2–17. Then `e7 02`.
2. Every packet: **AES-128-ECB** over its whole 16-byte blocks, **RC4** (restarted for every packet)
   over the remaining bytes. Large packets use the same rule.
3. GATT: service `00010203-0405-0607-0809-0a0b0c0d1910`, write `…2b11`, notify `…2b10`.
   Keep-alive `aa 00` every 2 s.

**Scenes on the R1250** – new findings, from decrypted Govee app captures:
- Scene data = `scenceParam` from `https://app2.govee.com/appsku/v1/light-effect-libraries?sku=R1250`.
  Its first byte is changed from **`0x50` to `0x58`**.
- **≤ 126 bytes → `a3` rows** (20 bytes each): `a3 00 01 <rows> + 15 bytes`, `a3 <i> + 17 bytes`, last row `a3 ff …`.
- **≥ 165 bytes → `a4` packets** (≤ 244 bytes, needs MTU 247): `a4 0000 01 <count LE16> + 237 bytes`,
  `a4 <i LE16> + 240 bytes`, last packet `a4 ffff + rest`. Even when the data fits in one packet, the app
  sends an **empty closing `a4 ffff`** packet and writes count = 2.
  (No R1250 scene is between 127 and 164 bytes. Sending small data as `a4` or large data as `a3` fails and can lock up the light.)
- The light acknowledges valid data with `a3 58` / `a4 58`, then the scene is started with
  `33 05 04 <sceneCode LE16>` (acknowledged with `33 05`).

## Tools

- `tools/govee_ble_scene.py` – send a scene from any computer (`pip install bleak cryptography`).
- `tools/decode_btsnoop.py` – decrypt the Govee app's BLE traffic from an Android HCI snoop log,
  to find out what your model expects.

## Credits

- Govee "v1" BLE encryption: [bartekpacia/govee](https://github.com/bartekpacia/govee), based on the
  openHAB Govee binding (openhab/openhab-addons#20976).
- GATT characteristics: [Beshelmek/govee_ble_lights](https://github.com/Beshelmek/govee_ble_lights).
- Govee LAN API and govee2mqtt: [wez/govee2mqtt](https://github.com/wez/govee2mqtt).

Not affiliated with or endorsed by Govee. Use at your own risk.

---

## Türkçe

Govee R1250 tavan lambasının efektlerini **Bluetooth ile, yerelden** gönderen Home Assistant eklentisi.

**Sorun:** Bu lambada bulut (govee2mqtt) efektleri geç uyguluyor ya da hiç uygulamıyor (*Fire* gibi
efektlerde lamba kararıyor). LAN API'deki `ptReal` komutu tamamen yok sayılıyor. Govee uygulamasının
kullandığı Bluetooth ise şifreli.

**Çözüm:** Eklenti şifreli Bluetooth protokolünü konuşuyor ve lambanın mevcut varlığına giden her
`light.turn_on(effect=…)` komutunu Bluetooth'tan gönderiyor. Hangi panelden, karttan, senaryodan ya da
sesli komuttan geldiği fark etmiyor. Bluetooth başarısız olursa komut eski yoldan (bulut) gider.
Bağlantı son efektten sonra 5 dakika açık kalır, böylece sonraki efektler yaklaşık 0,3 saniyede gelir.

**Kurulum:** HACS → ⋮ → Özel depolar → `https://github.com/ig-86/govee-ble-scenes` (Entegrasyon) →
yükle → yeniden başlat. Ardından yukarıdaki `govee_lan_fx:` ayarını kendi varlık adın ve lambanın
**Bluetooth** MAC adresiyle `configuration.yaml`'a ekle ve yeniden başlat.

**Dikkat:**
- Lamba aynı anda tek Bluetooth bağlantısı kabul eder. Telefonda Govee uygulaması arka planda açık
  kalırsa HA bağlanamaz.
- ⚠️ Yanlış biçimli efekt verisi lambayı kilitleyebilir. Duvar anahtarından kapatıp açmak gerekir.
  Paket biçimini deneme-yanılmayla değiştirmeyin, önce `tools/decode_btsnoop.py` ile uygulamanın ne
  gönderdiğine bakın.

Govee ile bir bağlantısı yoktur. Kullanım sorumluluğu kullanıcıya aittir.
