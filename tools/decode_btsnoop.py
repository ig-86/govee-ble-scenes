#!/usr/bin/env python3
"""Decrypt the Govee app's BLE traffic from an Android Bluetooth HCI snoop log.

Lets you see exactly what the Govee app sends to your light (e.g. for a model not
covered here), even though the traffic is encrypted with Govee's "v1" scheme.

How to get the log:
  1. Android: Developer options -> enable "Bluetooth HCI snoop log", toggle Bluetooth off/on.
  2. Use the Govee app over Bluetooth (turn phone Wi-Fi off), pick some scenes.
  3. `adb bugreport report.zip`, then extract FS/data/log/bt/btsnoop_hci.log from the zip.

Usage:
    pip install cryptography
    python decode_btsnoop.py btsnoop_hci.log AA:BB:CC:DD:EE:FF

Output: one line per ATT write (TX, phone -> light) / notification (RX), decrypted.
"""
import datetime
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PSK = b"MakingLifeSmarte"


def _rc4(key, data):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % 16]) & 255
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 255
        j = (j + s[i]) & 255
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 255])
    return bytes(out)


def decrypt(key, p):
    n = len(p) // 16 * 16
    d = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return d.update(p[:n]) + d.finalize() + _rc4(key, p[n:])


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    data = open(sys.argv[1], "rb").read()
    if data[:8] != b"btsnoop\0":
        sys.exit("not a btsnoop file")
    peer = bytes.fromhex(sys.argv[2].replace(":", ""))[::-1]
    pos, handles, frag, records = 16, set(), {}, []
    while pos + 24 <= len(data):
        _ol, il, flags, _drops, ts = struct.unpack(">IIIIq", data[pos:pos + 24])
        pkt = data[pos + 24:pos + 24 + il]
        pos += 24 + il
        if not pkt:
            continue
        t = datetime.datetime(2000, 1, 1) + datetime.timedelta(microseconds=ts - 0x00DCDDB30F2F8000)
        if pkt[0] == 4 and len(pkt) > 15 and pkt[1] == 0x3E and pkt[3] in (1, 0x0A) and pkt[4] == 0:
            h = struct.unpack("<H", pkt[5:7])[0] & 0xFFF
            if pkt[9:15] == peer:
                handles.add(h)
                records.append((t, "CONNECT", b""))
        elif pkt[0] == 2 and len(pkt) >= 5:
            hf, ln = struct.unpack("<HH", pkt[1:5])
            h, pb, body = hf & 0xFFF, (hf >> 12) & 3, pkt[5:5 + ln]
            if h not in handles:
                continue
            d = "TX" if flags & 1 == 0 else "RX"
            frag[(h, d)] = body if pb in (0, 2) else frag.get((h, d), b"") + body
            b = frag[(h, d)]
            if len(b) < 4:
                continue
            l2, cid = struct.unpack("<HH", b[:4])
            if len(b) - 4 < l2 or cid != 4:
                continue
            att = b[4:4 + l2]
            if att[0] in (0x52, 0x12, 0x1B) and len(att) > 3:  # write command/request, notification
                records.append((t, d, att[3:]))
    key = None
    for t, d, p in records:
        if d == "CONNECT":
            print(t.time(), "--- connection")
            key = None
            continue
        if len(p) == 20:
            pp = decrypt(PSK, p)
            if pp[0] == 0xE7 and pp[1] in (1, 2):
                if d == "RX" and pp[1] == 1:
                    key = pp[2:18]
                print(t.time(), d, "handshake", pp.hex())
                continue
        if key:
            print(t.time(), d, f"len{len(p)}", decrypt(key, p).hex())
        else:
            print(t.time(), d, f"len{len(p)}", "(no session key yet)", p.hex())


if __name__ == "__main__":
    main()
