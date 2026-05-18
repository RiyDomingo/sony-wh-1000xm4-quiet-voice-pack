#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["pycryptodome"]
# ///
"""Extract all 54 MP3 slots from a Sony VP_*_UPG_03.bin so you can play them
and identify which slot is which prompt.

Usage:
    uv run extract_slots.py voice-packs/VP_english_UPG_03.bin slots/

Outputs slots/slot_NN.mp3 for each non-empty slot.
"""
import argparse
import lzma
import struct
import sys
from pathlib import Path

from Crypto.Cipher import AES

KEY = b"eibohjeCh6uegahf"
IV  = b"miefeinuShu9eilo"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("input", type=Path)
    p.add_argument("outdir", type=Path)
    args = p.parse_args()

    raw = args.input.read_bytes()
    body = raw[0x1000:]
    plain = AES.new(KEY, AES.MODE_CBC, IV).decrypt(body)
    props = plain[0]
    lc = props % 9
    lp = (props // 9) % 5
    pb = (props // 9) // 5
    ds = struct.unpack_from("<I", plain, 1)[0]
    f = [{"id": lzma.FILTER_LZMA1, "lc": lc, "lp": lp, "pb": pb, "dict_size": ds}]
    img = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=f).decompress(plain[13:], max_length=0x100000)

    version = struct.unpack_from("<I", img, 0)[0]
    n = struct.unpack_from("<I", img, 4)[0]
    print(f"voice image: version={version} entries={n}")

    table_end = 8 + n * 8
    first_abs = struct.unpack_from("<I", img, 12)[0]
    base = first_abs - table_end

    args.outdir.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        sz, abs_off = struct.unpack_from("<II", img, 8 + i * 8)
        if sz == 0:
            print(f"  slot {i:2d}: EMPTY")
            continue
        file_off = abs_off - base
        data = img[file_off:file_off + sz]
        out = args.outdir / f"slot_{i:02d}.mp3"
        out.write_bytes(data)
        # MP3 frame estimate at 64 kbps mono: bytes / 8000 = seconds
        secs = sz / 8000
        print(f"  slot {i:2d}: {sz:6d} B ({secs:5.2f}s) → {out}")


if __name__ == "__main__":
    main()
