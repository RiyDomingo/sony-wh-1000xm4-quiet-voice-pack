#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["pycryptodome"]
# ///
"""Re-pack a Sony WH-1000XM4 voice pack with replaced MP3 slots.

Inverse of HelgeSverre/sony-vp-extract's extract_all.py.

Default behavior: take an existing VP_<lang>_UPG_03.bin, replace slots 6, 7, 8
("Noise canceling" / "Ambient Sound Control off" / "Ambient sound") with a
chosen short chime (default: slot 13, an existing notification tone), and emit
a re-packed .bin with valid SHA-256 in the TLV header.

Usage:
    uv run pack_voice_pack.py <input.bin> <output.bin> \
        [--chime-slot N] [--replace SLOT[,SLOT,...]] \
        [--mp3 SLOT=path.mp3] ...

Examples:
    # Default: copy slot 13 over slots 6,7,8
    uv run pack_voice_pack.py voice-packs/VP_english_UPG_03.bin patched.bin

    # Use a custom chime MP3 in slots 6,7,8
    uv run pack_voice_pack.py in.bin out.bin --mp3 6=chime.mp3 --mp3 7=chime.mp3 --mp3 8=chime.mp3

    # Replace only slot 8 (Ambient sound) with slot 11
    uv run pack_voice_pack.py in.bin out.bin --chime-slot 11 --replace 8

Notes:
- AES key/IV are the WH-1000XM4-wide hardcoded values.
- LZMA1 must be FORMAT_RAW (NOT FORMAT_ALONE) with explicit lc/lp/pb/dict_size
  matching the source pack — we read those from the source's LZMA props byte.
- TLV tags discovered by walking the source header at 0x100+. We patch the
  body_size, decompressed_size, and SHA-256(decompressed) fields in place;
  everything else (32-byte nonce at 0x000, version_string, etc.) is preserved.
"""
import argparse
import hashlib
import lzma
import struct
import sys
from pathlib import Path
from typing import Dict, List, Tuple

from Crypto.Cipher import AES

KEY = b"eibohjeCh6uegahf"
IV  = b"miefeinuShu9eilo"
HEADER_SIZE = 0x1000

# Slot semantics for WH-1000XM4 (per HelgeSverre/sony-vp-extract writeup).
SLOT_NAMES = {
    0: "Power on", 1: "Power off",
    2: "BT pairing", 3: "BT connected", 4: "BT disconnected",
    5: "Recharge / power off",
    6: "Noise canceling",
    7: "Ambient Sound Control off",
    8: "Ambient sound",
    15: "Battery fully charged",
    43: "Speak-to-chat on", 44: "Speak-to-chat off",
}
DEFAULT_REPLACE_SLOTS = (6, 7, 8)
DEFAULT_CHIME_SLOT = 13  # in 10–14 range described as "notification tones"


# ---------- decrypt / decompress (mirrors extract_all.py) ----------

def decrypt_body(enc_body: bytes) -> bytes:
    return AES.new(KEY, AES.MODE_CBC, IV).decrypt(enc_body)


def parse_lzma_props(blob: bytes) -> dict:
    """Parse the 13-byte LZMA1 header into filter parameters."""
    props = blob[0]
    lc = props % 9
    rem = props // 9
    lp = rem % 5
    pb = rem // 5
    dict_size = struct.unpack_from("<I", blob, 1)[0]
    # bytes 5..12 are the uncompressed size (signed -1 = unknown). Sony's packs
    # set it explicitly — we ignore it on decode (we know the upper bound) and
    # write the true size when re-encoding.
    return {"lc": lc, "lp": lp, "pb": pb, "dict_size": dict_size, "props_byte": props}


def lzma_decompress(blob: bytes, params: dict, max_size: int = 0x100000) -> bytes:
    filters = [{"id": lzma.FILTER_LZMA1, "lc": params["lc"], "lp": params["lp"],
                "pb": params["pb"], "dict_size": params["dict_size"]}]
    d = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
    return d.decompress(blob, max_length=max_size)


def lzma_compress(payload: bytes, params: dict) -> bytes:
    """Compress to raw LZMA1 with the same filter params, prepend a 13-byte
    LZMA1 header so the result decompresses with extract_all.py's logic."""
    filters = [{"id": lzma.FILTER_LZMA1, "lc": params["lc"], "lp": params["lp"],
                "pb": params["pb"], "dict_size": params["dict_size"],
                "preset": 0}]
    raw = lzma.compress(payload, format=lzma.FORMAT_RAW, filters=filters)
    header = bytes([params["props_byte"]]) + struct.pack("<I", params["dict_size"]) + struct.pack("<Q", len(payload))
    assert len(header) == 13
    return header + raw


# ---------- voice-image table ----------

class VoiceImage:
    """The decompressed ~1MB voice-guidance image."""

    def __init__(self, blob: bytes):
        self.version = struct.unpack_from("<I", blob, 0)[0]
        self.num_entries = struct.unpack_from("<I", blob, 4)[0]
        if self.num_entries == 0 or self.num_entries > 256:
            raise ValueError(f"implausible num_entries={self.num_entries}")
        # 8B header + N×8B entry table
        table_end = 8 + self.num_entries * 8
        first_abs = struct.unpack_from("<I", blob, 12)[0]
        self.base_offset = first_abs - table_end  # so file_offset = abs - base
        self.slots: List[bytes] = []
        for i in range(self.num_entries):
            off = 8 + i * 8
            sz = struct.unpack_from("<I", blob, off)[0]
            abs_off = struct.unpack_from("<I", blob, off + 4)[0]
            file_off = abs_off - self.base_offset
            self.slots.append(blob[file_off:file_off + sz])

    def serialize(self, fixed_size: int = 0x100000) -> bytes:
        """Re-emit the image with current slot data, recomputing offsets.

        The headphones expect the decompressed image to be exactly fixed_size
        bytes (1 MB by default for WH-1000XM4 voice guidance partition slot).
        We pad the trailing region with zero bytes to match the original
        Sony layout — without this, the headphones reject the install at the
        very end of BT transfer (~99% progress)."""
        n = len(self.slots)
        out = bytearray()
        out += struct.pack("<I", self.version)
        out += struct.pack("<I", n)
        out += b"\x00" * (n * 8)  # placeholder entry table
        while len(out) % 4 != 0:
            out += b"\x00"
        for i, data in enumerate(self.slots):
            off = 8 + i * 8
            abs_offset = self.base_offset + len(out)
            struct.pack_into("<I", out, off, len(data))
            struct.pack_into("<I", out, off + 4, abs_offset)
            out += data
        if fixed_size > 0:
            if len(out) > fixed_size:
                raise ValueError(
                    f"voice image is {len(out)} B, exceeds fixed slot size "
                    f"{fixed_size}. Use shorter chimes."
                )
            out += b"\x00" * (fixed_size - len(out))
        return bytes(out)


# ---------- TLV header patcher ----------

def walk_tlv(header: bytes, start: int = 0x100) -> List[Tuple[int, int, int, bytes]]:
    """Walk the TLV block in the 4096-B header. Returns [(offset, tag, length, value)].

    Encoding: u16 tag (LE) + u16 length (LE) + length bytes of value.
    Stop at a zero tag or padding (0xff bytes).
    """
    entries = []
    pos = start
    while pos + 4 <= HEADER_SIZE:
        tag = struct.unpack_from("<H", header, pos)[0]
        length = struct.unpack_from("<H", header, pos + 2)[0]
        # Sentinel: zero tag, all-ones tag (in 0xff padding), or out-of-bounds length.
        if tag == 0 or tag == 0xFFFF or pos + 4 + length > HEADER_SIZE:
            break
        val = bytes(header[pos + 4 : pos + 4 + length])
        entries.append((pos, tag, length, val))
        pos += 4 + length
    return entries


# Tag layout for WH-1000XM4 voice packs (decoded empirically against
# VP_english_UPG_03.bin):
#   0x0011  compression info: {u8 compression_type=2, u8 ?, u32 body_offset, u32 body_size}
#   0x0012  image info: {u32 version, u32 header_size, u32 decompressed_size, u32 base_offset}
#   0x0013  version_string: 28-B fixed C string (Sony typo "verion_string")
#   0x0014  digest: {u32 algo=1, u8[32] SHA-256(decompressed)}
TAG_COMPRESSION = 0x0011
TAG_IMAGE_INFO  = 0x0012
TAG_DIGEST      = 0x0014

# Field offsets *within* each tag's value (after the 4-byte TLV header).
COMPRESSION_BODY_SIZE_OFFSET = 6   # u8 type, u8 ?, u32 body_offset, u32 body_size
IMAGE_INFO_DECOMPRESSED_OFFSET = 8 # u32 version, u32 header_size, u32 decompressed_size, ...
DIGEST_SHA256_OFFSET = 4           # u32 algo, then 32-B SHA-256


def patch_header(header: bytearray, body_size: int, decompressed_size: int, sha256: bytes) -> None:
    """Patch body_size, decompressed_size, and SHA-256 in the TLV header.
    Field locations are pinned by tag — fail loudly if a tag's missing or
    the wrong length, so we don't silently corrupt headers from a different
    pack version."""
    entries = walk_tlv(header)
    by_tag = {tag: (off, length, value) for off, tag, length, value in entries}

    if TAG_COMPRESSION not in by_tag:
        raise RuntimeError(f"TLV tag 0x{TAG_COMPRESSION:04x} (compression info) missing")
    c_off, c_len, _ = by_tag[TAG_COMPRESSION]
    if c_len < COMPRESSION_BODY_SIZE_OFFSET + 4:
        raise RuntimeError(f"compression TLV too short: {c_len} B")
    struct.pack_into("<I", header, c_off + 4 + COMPRESSION_BODY_SIZE_OFFSET, body_size)

    if TAG_IMAGE_INFO not in by_tag:
        raise RuntimeError(f"TLV tag 0x{TAG_IMAGE_INFO:04x} (image info) missing")
    i_off, i_len, _ = by_tag[TAG_IMAGE_INFO]
    if i_len < IMAGE_INFO_DECOMPRESSED_OFFSET + 4:
        raise RuntimeError(f"image-info TLV too short: {i_len} B")
    struct.pack_into("<I", header, i_off + 4 + IMAGE_INFO_DECOMPRESSED_OFFSET, decompressed_size)

    if TAG_DIGEST not in by_tag:
        raise RuntimeError(f"TLV tag 0x{TAG_DIGEST:04x} (digest) missing")
    d_off, d_len, _ = by_tag[TAG_DIGEST]
    if d_len < DIGEST_SHA256_OFFSET + 32:
        raise RuntimeError(f"digest TLV too short: {d_len} B")
    header[d_off + 4 + DIGEST_SHA256_OFFSET : d_off + 4 + DIGEST_SHA256_OFFSET + 32] = sha256


# ---------- main ----------

def parse_args():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("input", type=Path, help="Source VP_*.bin")
    p.add_argument("output", type=Path, help="Patched VP_*.bin to write")
    p.add_argument("--chime-slot", type=int, default=DEFAULT_CHIME_SLOT,
                   help=f"Slot index to copy as the replacement chime (default {DEFAULT_CHIME_SLOT})")
    p.add_argument("--replace", default=",".join(str(s) for s in DEFAULT_REPLACE_SLOTS),
                   help=f"Comma-separated slot indices to overwrite (default {DEFAULT_REPLACE_SLOTS})")
    p.add_argument("--mp3", action="append", default=[], metavar="SLOT=PATH",
                   help="Replace SLOT with the given external MP3 file. Repeatable. "
                        "Overrides --chime-slot for the listed slots.")
    p.add_argument("--perturb-padding", action="store_true",
                   help="Diagnostic: keep Sony's LZMA stream verbatim, but flip "
                        "one byte of the trailing 0xff AES padding (after the "
                        "LZMA EOS marker). Re-encrypt with AES-CBC. Decompressed "
                        "content stays bit-identical to Sony's; only the "
                        "encrypted body's last AES block differs. If the "
                        "install still succeeds → device validates only "
                        "decompressed content. If it fails → device validates "
                        "encrypted/compressed bytes directly.")
    return p.parse_args()


def main():
    args = parse_args()
    raw = args.input.read_bytes()
    if len(raw) < HEADER_SIZE + 16:
        sys.exit(f"{args.input} is too small to be a voice pack")

    header = bytearray(raw[:HEADER_SIZE])
    encrypted_body = raw[HEADER_SIZE:]

    # AES decrypt + LZMA1 decompress (same as extract_all.py)
    decrypted = decrypt_body(encrypted_body)
    lzma_params = parse_lzma_props(decrypted)
    decompressed = lzma_decompress(decrypted[13:], lzma_params)

    img = VoiceImage(decompressed)
    print(f"Loaded {args.input.name}: version={img.version} entries={img.num_entries} "
          f"base_offset=0x{img.base_offset:x} decompressed={len(decompressed)} bytes")
    for i in (6, 7, 8, 13):
        print(f"  slot {i:2d} ({SLOT_NAMES.get(i, '?'):28s}): {len(img.slots[i]):5d} B")

    if args.perturb_padding:
        # Diagnostic mode: keep Sony's body, perturb 1 byte of trailing pad,
        # re-encrypt, re-emit. Note we ALSO recompute the offset-0x000 SHA-256
        # (since perturbing the padding changes file[0x100:end] → invalidates
        # the original signature).
        # Re-decompress with the streaming decoder so we know exactly how many
        # bytes of the AES-decrypted blob were consumed by the LZMA stream
        # (the rest is Sony's trailing 0xff AES padding).
        d = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[{
            "id": lzma.FILTER_LZMA1, "lc": lzma_params["lc"],
            "lp": lzma_params["lp"], "pb": lzma_params["pb"],
            "dict_size": lzma_params["dict_size"]}])
        _ = d.decompress(decrypted[13:], max_length=0x100000)
        if not d.eof:
            sys.exit("LZMA stream did not reach EOS — can't safely perturb padding")
        padding_len = len(d.unused_data)
        if padding_len == 0:
            sys.exit("Sony's body has zero trailing AES padding — nothing safe to flip")
        # Flip the very last byte of the decrypted body (guaranteed inside padding).
        # Sony's pad is 0xff; flipping to 0xfe changes one bit in one byte, which
        # AES-CBC encrypts into a single different ciphertext block.
        plaintext = bytearray(decrypted)
        assert plaintext[-1] == 0xff, f"expected 0xff padding, got 0x{plaintext[-1]:02x}"
        plaintext[-1] = 0xfe
        new_body = AES.new(KEY, AES.MODE_CBC, IV).encrypt(bytes(plaintext))
        assert len(new_body) == len(encrypted_body)
        # Confirm only one AES block differs (sanity check).
        diff_blocks = sum(1 for i in range(0, len(new_body), 16)
                          if new_body[i:i+16] != encrypted_body[i:i+16])
        # TLV stays the same — decompressed content is byte-identical.
        sha = hashlib.sha256(decompressed).digest()
        patch_header(header, body_size=len(new_body),
                     decompressed_size=len(decompressed), sha256=sha)
        print(f"\n[perturb-padding] LZMA stream consumed {len(decrypted) - padding_len} B, "
              f"trailing padding {padding_len} B (last byte 0xff→0xfe)")
        print(f"  AES blocks differing from Sony's: {diff_blocks} of "
              f"{len(new_body)//16} (expected 1)")
        print(f"  TLV unchanged: SHA-256={sha.hex()[:16]}…")
        full = bytes(header) + new_body
        nonce = hashlib.sha256(full[0x100:]).digest()
        final = nonce + full[32:]
        print(f"  Recomputed offset-0x000 SHA-256: {nonce.hex()[:16]}…")
        args.output.write_bytes(final)
        print(f"Wrote {args.output} ({len(final):,} B)")
        return

    # ---- Apply replacements ----
    explicit_mp3s: Dict[int, bytes] = {}
    for spec in args.mp3:
        if "=" not in spec:
            sys.exit(f"--mp3 expects SLOT=PATH, got {spec!r}")
        slot_str, path = spec.split("=", 1)
        explicit_mp3s[int(slot_str)] = Path(path).read_bytes()

    replace_slots = [int(s) for s in args.replace.split(",") if s.strip()]
    chime_data = img.slots[args.chime_slot]
    print(f"\nUsing slot {args.chime_slot} ({SLOT_NAMES.get(args.chime_slot, '?')}, "
          f"{len(chime_data)} B) as default chime")

    for slot in replace_slots:
        if slot in explicit_mp3s:
            new_data = explicit_mp3s[slot]
            src = "external file"
        else:
            new_data = chime_data
            src = f"slot {args.chime_slot}"
        old_size = len(img.slots[slot])
        img.slots[slot] = new_data
        print(f"  → slot {slot:2d} ({SLOT_NAMES.get(slot, '?'):28s}): "
              f"{old_size} B → {len(new_data)} B   (from {src})")
    # Apply any explicit-only mp3 slots not in --replace
    for slot, blob in explicit_mp3s.items():
        if slot not in replace_slots:
            old_size = len(img.slots[slot])
            img.slots[slot] = blob
            print(f"  → slot {slot:2d} (explicit MP3): {old_size} B → {len(blob)} B")

    # ---- Rebuild ----
    new_image = img.serialize()
    print(f"\nNew decompressed image: {len(new_image)} B (was {len(decompressed)} B)")

    new_lzma = lzma_compress(new_image, lzma_params)
    print(f"LZMA1-compressed body (incl. 13-B header): {len(new_lzma)} B")

    # AES-CBC requires multiple of 16 bytes. Sony pads the LZMA stream with
    # 0xff bytes (the natural NOR-flash erase state) before encrypting — the
    # firmware likely validates that the trailing region matches this pattern.
    # Padding with 0x00 caused the install to fail at 99% even when the
    # decompressed content was byte-identical to Sony's; switching to 0xff is
    # the next-most-likely fix.
    pad_len = (-len(new_lzma)) % 16
    if pad_len:
        new_lzma += b"\xff" * pad_len

    new_body = AES.new(KEY, AES.MODE_CBC, IV).encrypt(new_lzma)
    print(f"AES-128-CBC encrypted body: {len(new_body)} B (was {len(encrypted_body)} B)")

    sha = hashlib.sha256(new_image).digest()
    patch_header(header, body_size=len(new_body), decompressed_size=len(new_image), sha256=sha)
    print(f"Patched header: body_size={len(new_body)}, decompressed_size={len(new_image)}, "
          f"SHA-256={sha.hex()[:16]}…")

    # Final step: recompute the 32-byte signature at file offset 0x000.
    # Reverse-engineered from the on-device CheckIntegrity handler
    # (FUN_0814ddec → FUN_08147678 → FUN_0814f2d8 in heds_body.bin):
    # the device computes SHA-256 over flash[0x100:end] and compares against
    # the 32 bytes at flash[0:32]. Without this, install fails at 99%.
    full = bytes(header) + new_body
    nonce = hashlib.sha256(full[0x100:]).digest()
    final = nonce + full[32:]
    print(f"Recomputed file-offset 0x000 SHA-256 over file[0x100:]: "
          f"{nonce.hex()[:16]}…")

    args.output.write_bytes(final)
    print(f"\nWrote {args.output} ({len(final):,} B)")


if __name__ == "__main__":
    main()
