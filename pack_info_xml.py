#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["pycryptodome"]
# ///
"""Forge a Sony info.xml manifest so it advertises a patched VP_*.bin.

Sony's voice-pack install flow:
  1. App fetches  https://info.update.sony.net/<model>/<lang_pack>/info/info.xml
  2. App AES-128-ECB-decrypts the body (key extracted from
     com.sony.songpal.automagic Y6.d in the Android app — same across versions).
  3. App verifies plaintext-header `digest:` against
        SHA1_hex( SHA1_hex(decrypted_body) + lang_pack + model )
  4. Manifest XML lists each Distribution with `Size="…"` and `MAC="…"` (SHA-1
     of the .bin file). App downloads the .bin and verifies size + MAC.

This script:
  - decrypts the original info.xml,
  - rewrites Size and MAC for the FW Distribution to match our patched.bin,
  - re-encrypts with the same key + ZeroBytePadding,
  - recomputes the plaintext digest line,
  - emits the new info.xml.

Usage:
    uv run pack_info_xml.py <original info.xml> <patched.bin> \
        --lang-pack VGIDLPB0401 --model HP002 --out info.xml.patched
"""
import argparse
import hashlib
import re
import sys
from pathlib import Path

from Crypto.Cipher import AES

# Extracted from com.sony.songpal.automagic Y6.d (constant `c`):
#   private static final byte[] c = {79,-94,121,-103,-1,-48,-117,31,-28,-46,96,-43,123,109,60,23};
INFO_XML_KEY = bytes([0x4F, 0xA2, 0x79, 0x99, 0xFF, 0xD0, 0x8B, 0x1F,
                      0xE4, 0xD2, 0x60, 0xD5, 0x7B, 0x6D, 0x3C, 0x17])


# ---- crypto helpers -----------------------------------------------------

def split_header(buf: bytes) -> tuple[list[str], bytes]:
    """Split the leading plaintext header (eaid:/daid:/digest: lines) from the
    encrypted body. Returns (header_lines, encrypted_body)."""
    end = 0
    for _ in range(3):
        end = buf.index(b'\n', end) + 1
    while end < len(buf) and buf[end] in b'\r\n':
        end += 1
    header_lines = buf[:end].decode().splitlines()
    header_lines = [l for l in header_lines if l.strip()]
    return header_lines, buf[end:]


def decrypt(body: bytes) -> bytes:
    trim = (len(body) // 16) * 16
    plain = AES.new(INFO_XML_KEY, AES.MODE_ECB).decrypt(body[:trim])
    return plain.rstrip(b'\x00')


def encrypt(plain: bytes) -> bytes:
    pad = (-len(plain)) % 16
    padded = plain + b'\x00' * pad
    return AES.new(INFO_XML_KEY, AES.MODE_ECB).encrypt(padded)


def compute_header_digest(plain: bytes, lang_pack: str, model: str) -> str:
    """Per Y6.e + automagic.e.e():
        sha1_body_hex = SHA1_hex(decrypted_body)
        digest        = SHA1_hex( sha1_body_hex + lang_pack + model )
    Both inputs are UTF-8 encoded.
    """
    sha1_body_hex = hashlib.sha1(plain).hexdigest()
    combo = (sha1_body_hex + lang_pack + model).encode('utf-8')
    return hashlib.sha1(combo).hexdigest()


# ---- XML rewrite --------------------------------------------------------

def patch_distribution(xml_text: str, dist_id: str, new_size: int, new_mac: str) -> str:
    """Update Size and MAC attributes for the Distribution with matching ID,
    using regex (Sony's XML is single-line attributes, no quoted-attribute
    weirdness, and Python's xml.etree would normalize too aggressively)."""
    pattern = re.compile(
        r'(<Distribution\b[^>]*\bID="' + re.escape(dist_id) + r'"[^>]*?)/?>',
        re.DOTALL,
    )
    m = pattern.search(xml_text)
    if not m:
        raise SystemExit(f'Distribution ID="{dist_id}" not found in manifest XML')
    block = m.group(1)
    new_block, n_size = re.subn(r'\bSize="\d+"', f'Size="{new_size}"', block)
    new_block, n_mac  = re.subn(r'\bMAC="[0-9a-fA-F]+"', f'MAC="{new_mac}"', new_block)
    if n_size == 0 or n_mac == 0:
        raise SystemExit(f'Distribution ID="{dist_id}" found but Size/MAC attributes missing')
    new_xml = xml_text[:m.start(1)] + new_block + xml_text[m.end(1):]
    print(f'  Distribution[{dist_id}]:')
    for attr in ('Size', 'MAC'):
        old = re.search(rf'\b{attr}="([^"]*)"', block).group(1)
        new = re.search(rf'\b{attr}="([^"]*)"', new_block).group(1)
        print(f'    {attr}: {old}  ->  {new}')
    return new_xml


# ---- main --------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('info_xml', type=Path, help='original info.xml downloaded from Sony CDN')
    ap.add_argument('patched_bin', type=Path, help='our patched VP_*.bin')
    ap.add_argument('--lang-pack', required=True, help='URL component, e.g. VGIDLPB0401 (English)')
    ap.add_argument('--model', default='HP002', help='URL component (default HP002 for WH-1000XM4)')
    ap.add_argument('--dist-id', default='FW', help='Distribution element ID to patch (default "FW")')
    ap.add_argument('--out', type=Path, required=True, help='output patched info.xml')
    ap.add_argument('--rewrite-lang', action='store_true',
                    help='Rewrite the decrypted XML so the manifest looks like it natively '
                         'belongs to --lang-pack. Substitutes the source language code '
                         '(VGIDLPB04XX) and language name (english/spanish/…) inside the '
                         'XML to match the target. Use when adapting an English info.xml '
                         'as a template for a different language install.')
    args = ap.parse_args()

    raw = args.info_xml.read_bytes()
    header_lines, body = split_header(raw)
    print(f'Loaded {args.info_xml}: header={header_lines}, body={len(body)} B')

    plain = decrypt(body)
    xml = plain.decode('utf-8')
    if '<InformationFile' not in xml:
        sys.exit('decryption produced something that does not look like an InformationFile XML')
    print(f'Decrypted body: {len(plain)} B (looks like XML)')

    patched_bin = args.patched_bin.read_bytes()
    new_size = len(patched_bin)
    new_mac = hashlib.sha1(patched_bin).hexdigest()
    print(f'Patched .bin: size={new_size}  SHA-1={new_mac}')

    new_xml = patch_distribution(xml, args.dist_id, new_size, new_mac)

    if args.rewrite_lang:
        # Map VGIDLPB04XX → language name (per NOTES.md §5)
        LANG_NAMES = {
            '01': 'english', '02': 'french',  '03': 'german',
            '04': 'spanish', '05': 'italian', '06': 'portuguese',
            '07': 'dutch',   '08': 'swedish', '09': 'finnish',
            '10': 'turkish',
        }
        m = re.search(r'VGIDLPB04(\d{2})', new_xml)
        if not m:
            sys.exit('--rewrite-lang: could not find VGIDLPB04XX in source XML')
        src_code = m.group(1)
        m2 = re.match(r'VGIDLPB04(\d{2})$', args.lang_pack)
        if not m2:
            sys.exit(f'--rewrite-lang: --lang-pack must be VGIDLPB04XX, got {args.lang_pack}')
        dst_code = m2.group(1)
        src_name = LANG_NAMES.get(src_code)
        dst_name = LANG_NAMES.get(dst_code)
        if not src_name or not dst_name:
            sys.exit(f'--rewrite-lang: unknown lang code (src={src_code} dst={dst_code})')
        if src_code == dst_code:
            print('  --rewrite-lang: source and target match, no rewrite needed')
        else:
            before = new_xml
            # Order matters: do the language code first (more specific), then the name.
            new_xml = new_xml.replace(f'VGIDLPB04{src_code}', f'VGIDLPB04{dst_code}')
            new_xml = new_xml.replace(f'VP_{src_name}_', f'VP_{dst_name}_')
            # Some manifests also embed the bare language name elsewhere — rewrite
            # case-sensitively; warn if no substitutions happened.
            if new_xml == before:
                print('  --rewrite-lang: WARNING — no replacements made; XML may not '
                      'reference the source language directly')
            else:
                n_code = new_xml.count(f'VGIDLPB04{dst_code}') - before.count(f'VGIDLPB04{dst_code}')
                n_name = new_xml.count(f'VP_{dst_name}_')   - before.count(f'VP_{dst_name}_')
                print(f'  --rewrite-lang: {src_code}/{src_name} -> {dst_code}/{dst_name} '
                      f'({n_code} code, {n_name} name substitutions)')

    new_plain = new_xml.encode('utf-8')

    new_body = encrypt(new_plain)
    new_digest = compute_header_digest(new_plain, args.lang_pack, args.model)
    print(f'\nRe-encrypted body: {len(new_body)} B  (was {len(body)} B)')
    print(f'New header digest: {new_digest}')

    # Reassemble the file. Preserve any non-eaid/daid/digest header lines (none observed).
    new_header_lines = []
    for line in header_lines:
        if line.startswith('digest:'):
            new_header_lines.append(f'digest:{new_digest}')
        else:
            new_header_lines.append(line)
    rebuilt = ('\n'.join(new_header_lines) + '\n\n').encode() + new_body

    args.out.write_bytes(rebuilt)
    print(f'\nWrote {args.out} ({len(rebuilt)} B)')


if __name__ == '__main__':
    main()
