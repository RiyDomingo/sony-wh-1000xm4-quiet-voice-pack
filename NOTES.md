# Sony WH-1000XM4 voice-pack modification — full project notes

This doc is the single source of truth. Reading this should be enough to pick up where we left off without redoing any discovery work.

## TL;DR — FULLY WORKING

- **Confirmed end-to-end working:** Apple AirPods chimes audibly playing on WH-1000XM4 in slots 6/7/8 (Noise canceling, Ambient Sound Control off, Ambient sound) after fresh-language install via mitmproxy.
- **Two fixes were required, both non-obvious:**
  1. **SHA-256 signature at file offset `0x000`.** The 32 bytes long mislabeled "random nonce / file ID" are actually `SHA-256(file[0x100:end])`. Our packer recomputes this after building everything else. Verified: `file[0:32] == SHA-256(file[0x100:end])` exactly across all 5 reference Sony language packs. Found via Ghidra firmware RE — see §16 for the full call chain inside `heds_body.bin`.
  2. **info.xml must natively claim the target language.** A manifest built from English template but stamped with `--lang-pack VGIDLPB0404` is silently rejected somewhere downstream of CheckIntegrity — install reports success but runtime falls back to a default voice pack (likely English baked-in). Fix: `pack_info_xml.py --rewrite-lang` rewrites `VGIDLPB04XX` codes and `VP_<lang>_` URI segments inside the decrypted XML to match the target lang_pack before re-encrypting.
- Brute force (§11) missed fix #1 because we tried offsets `0x00` and `0x20` — never tried `0x100` specifically (where the TLV block starts; the `0x20–0x100` region is `0xff` padding). Fix #2 was discovered when an English-source install showed the post-install prompts sounded like default Sony, while a Spanish-source install with a Spanish-rewritten manifest produced the actual Apple chimes.
- **Cross-language install pattern that works:** if the headphones currently have language X installed, switch to language Y in the Sony app with patched bin + rewritten manifest matching Y. The fresh-language path triggers a full re-fetch and re-install.
- **Slot mapping confirmed correct (NOTES.md §5 is right):** slot 6 = "Noise canceling", slot 7 = "Ambient Sound Control off", slot 8 = "Ambient sound".

## 1. Hardware identity

- **SoC**: Airoha **MT2811** (MediaTek subsidiary), ARM Cortex-M4. Two chips per pair (Agent + Partner), kept in sync via LRSync.
- **External NC ASIC**: Sony **CXD-90050** (DNC + ASM control paths).
- **CM4 firmware runtime base**: `0x04200000` (XIP from internal flash partition 1 at `0x08002000`, 64 KB).
- **Flash partitions** (per HelgeSverre/sony-vp-extract writeup):

  | # | Address | Size | Description |
  |---|---|---|---|
  | 0 | `0x08001000` | 4 KB | Bootloader |
  | 1 | `0x08002000` | 64 KB | CM4 firmware (XIP) |
  | 2 | `0x08012000` | 128 KB | NVDM (config / calibration) |
  | 3 | `0x081B9000` | 2 MB | FOTA staging |
  | 6 | `0x0C510000` | 6 MB | External flash — voice guidance pack |

## 2. Decryption pipeline (UPG firmware files)

```
KEY = b"eibohjeCh6uegahf"   (16 ASCII bytes)
IV  = b"miefeinuShu9eilo"   (16 ASCII bytes)
```

These are the **firmware AND voice-pack** AES keys. Same key across every WH-1000XM4 unit. Same key for VP_*.bin AND UPG_*.bin (firmware).

Pipeline for `UPG_*.bin` (firmware):

```
strip 4096-B plaintext header → AES-128-CBC decrypt (no padding)
                              → LZMA1 decompress (FORMAT_ALONE)
                              → HEDS container (heds_body.bin)
```

Implemented in `decrypt.sh` and `decrypt.py`. Pre-decrypted output for all available versions (2.5.0 → 3.0.1) is in `out/`.

## 3. HEDS container layout (firmware only — voice packs are different)

```
+0x00  u16   container flag (0xB530 / 0xB550)
+0x02  6B    reserved (zero)
+0x08  14B   ASCII build date + 'a\n'  ("20250808100110a\n")
+0x16  10B   ASCII git short rev "G_<hex>\n"
+0x22  4B    "HEDS" magic
+0x26  u16   header words count (== 0x108A)
+0x28  u16   mirror of above
+0x2A  u32   load base (0x10000000)
+0x2E  u32   trailer / inverse marker (0xFFFFF846)
+0x32  u32   reserved (0x07FFFFFF)
+0x38..0xE8  size table — 43 u32 entries terminated by 0
[zero padding]
+0x138       payload start (heds_body.bin begins here)
```

Per-section load addresses are not yet decoded; entries appear to be `(size, attr)` or `(size, ram_size)` pairs. This is the main blocker for analyzing `heds_body.bin` in Ghidra (large unanalyzed regions).

## 4. Ghidra setup (for `heds_body.bin` only — not voice packs)

Project: `tryagain.rep` (other `.rep` dirs are stale).

1. Import as raw binary, language `ARM:LE:32:Cortex`, image base `0x08000000`.
2. **Add a byte-mapped mirror block** at `0x00000000`, size 5,906,120 B, source addr `0x08000000`, R+E. Without this, all string xrefs come back empty (the chip aliases the same flash at both `0x00000000` and `0x08000000`).
3. Run a full `reanalyze`. Function count climbs ~5,600 → ~8,200.

MCP scripting requires `GHIDRA_MCP_ALLOW_SCRIPTS=1` in **Ghidra's** env (not the bridge's), and `~/ghidra_scripts` must be a registered & enabled bundle (resolved literal path, not `$USER_HOME/...`).

NCASM debug strings (`bt_sink_app_*`, `[Sink][KEY] ncasm mask...`) are dead `__func__` data — the production logger strips them. Confirmed by exhaustive byte-pattern scan: zero references to any.

## 5. Voice pack file format

**CDN URL pattern**:
```
https://info.update.sony.net/HP002/VGIDLPB04XX/contents/0002/VP_<lang>_UPG_03.bin
https://info.update.sony.net/HP002/VGIDLPB04XX/info/info.xml          ← manifest
```

Languages (`XX`): 01 english, 02 french, 03 german, 04 spanish, 05 italian, 06 portuguese, 07 dutch, 08 swedish, 09 finnish, 10 turkish.

### `VP_*.bin` layout

```
0x000  32 bytes              SHA-256(file[0x100:end]) — the device-side
                              integrity hash. The on-device CheckIntegrity
                              handler (cmd 0x1C01) computes the same hash
                              over the just-written flash region and memcmps
                              against this field. Recompute after building
                              the rest of the file. See §9 / §16.
0x100+ TLV metadata block:
   tag 0x0011 (10 B): {u8 compression_type=2, u8 ?, u32 body_offset=0x1000, u32 body_size}
   tag 0x0012 (16 B): {u32 version=1, u32 header_size=0x1000, u32 decompressed_size=0x100000, u32 0x0c380000}
   tag 0x0013 (28 B): "verion_string\0" (Sony typo) + 0xff padding
   tag 0x0014 (36 B): {u32 algo=1, byte[32] SHA-256(decompressed_image)}
0x1000+ encrypted body      (AES-128-CBC with same KEY/IV as firmware)
        → after decrypt:    13-B LZMA1 header + raw LZMA1 payload + trailing padding to 16-B AES-block alignment
        → after decompress: voice guidance image (exactly 1 MiB = 0x100000)
```

**Critical**: LZMA1 here uses `lzma.FORMAT_RAW` with explicit `lc/lp/pb/dict_size` (= 3/0/2/0x4000) parsed from the props byte — NOT `FORMAT_ALONE`. The 13-byte header isn't standard ALONE format (uncompressed-size field semantics differ).

**The TLV `0x0012` 4th u32 (`0x0c380000`) is constant across all 5 verified language packs** — model-wide constant, NOT content-dependent. Don't try to recompute it.

**Trailing AES padding bytes**: Sony pads with `0xff` (NOR flash erase pattern). Our packer was changed to do the same.

### Decompressed voice-guidance image layout

```
+0x00  u32  version (1)
+0x04  u32  num_entries (54)
+0x08  N×8B entry table — each entry: u32 size, u32 absolute_offset
            absolute_offset is into the 6 MB partition; subtract
            base = first_abs_offset - table_end to get image-local file offset
+...   54× MP3 blobs (48 kHz mono, 64 kbps)
+...   trailing 0x00 padding to fill exactly 1 MiB (0x100000)
```

Original Sony image: last MP3 ends at offset `0xf5bf8` (= 1,006,584); remaining 41,992 bytes are zero-padding to 0x100000. **Our packer pads to 1 MiB** (any other size fails — the partition slot is fixed-size).

### Slot semantics (`__func__` of `prompt_NN.mp3`)

| # | Content | # | Content |
|---|---|---|---|
| 0 | Power on | 6 | **Noise canceling** ← long voice prompt |
| 1 | Power off | 7 | **Ambient Sound Control off** ← long voice prompt |
| 2 | Bluetooth pairing | 8 | **Ambient sound** ← long voice prompt |
| 3 | Bluetooth connected | 15 | Battery fully charged |
| 4 | Bluetooth disconnected | 16-18, 28-33 | Battery percentage |
| 5 | Recharge / power off | 43-44 | Speak-to-chat on/off |
| 9, 21, 24, 27, 38 | Assistant-related / unknown speech | 47-53 | BT device connect/disconnect states |
| **10-14, 19-20, 22-23, 25-26, 35-37, 39-42, 45-46** | **Notification tones (short chimes)** | | |

Shortest existing chime: **slot 19 (~0.34 s, 2,688 B)**.

## 6. info.xml manifest format

**Plaintext header** (3 lines):
```
eaid:ENC0003          # encryption algorithm ID 0003 = AES
daid:HAS0003          # digest algorithm ID 0003 = SHA-1
digest:<40 hex>       # SHA-1 of (SHA-1_hex(decrypted_body) + lang_pack + model)
```

Then a blank line, then **encrypted body** (multiple of 16 bytes).

**Body = AES-128-ECB with ZeroBytePadding**. Key extracted from the iOS Sony Headphones Connect app (com.sony.songpal.automagic Y6.d, field `c`):

```python
INFO_XML_KEY = bytes([0x4F, 0xA2, 0x79, 0x99, 0xFF, 0xD0, 0x8B, 0x1F,
                      0xE4, 0xD2, 0x60, 0xD5, 0x7B, 0x6D, 0x3C, 0x17])
```

Mode: `AES/ECB/ZeroBytePadding` (no IV). **Different key from voice-pack body.**

**Decrypted body** is plain XML:
```xml
<?xml version="1.0" encoding="UTF-8"?><InformationFile ...>
    <ApplyConditions>
        <ApplyCondition ApplyOrder="1" Force="false">
            <Distributions>
                <Distribution ID="FW" Size="911456"
                              MAC="b754767733623779af2b9f0faf13f07be0c43593"
                              URI="https://.../VP_english_UPG_03.bin" Version="3" InstallType="binary" .../>
                <Distribution ID="Disclaimer" Size="2019" MAC="..." URI=".../disclaimer.xml" .../>
            </Distributions>
            ...
        </ApplyCondition>
    </ApplyConditions>
</InformationFile>
```

The `MAC` is **SHA-1 of the file** as plain hex. The `Size` is the file size in bytes.

**Header digest computation** (the SHA-1 in the plaintext line):
```python
sha1_body_hex = sha1(decrypted_body).hexdigest()
header_digest = sha1((sha1_body_hex + lang_pack + model).encode("utf-8")).hexdigest()
# Where:
#   lang_pack = "VGIDLPB0401"  (English) — varies per language
#   model     = "HP002"        (WH-1000XM4)
```

To **forge a valid info.xml** advertising a custom `.bin`:
1. Decrypt original → modify Distribution Size + MAC for the FW entry → re-encrypt
2. Recompute the plaintext digest line
3. Reassemble: `eaid:ENC0003\ndaid:HAS0003\ndigest:<new>\n\n<new encrypted body>`

Implemented in `pack_info_xml.py`.

## 7. The mitmproxy interception chain

iPhone WiFi proxy (manual: laptop_ip:8080) → laptop runs `mitmdump -s swap_vp.py --listen-port 8080` → addon intercepts requests to `info.update.sony.net` matching `VGIDLPB*/info/info.xml` (returns `patched_info.xml`) and `VGIDLPB*/contents/0002/VP_*_UPG_03.bin` (returns `patched.bin`).

iOS requirements:
- mitmproxy CA installed (`http://mitm.it` in Safari with proxy active)
- CA fully trusted: Settings → General → About → Certificate Trust Settings → enable "mitmproxy"

Verified working: served Sony's byte-identical original file via this pipeline → install succeeded once. Our pipeline doesn't corrupt bytes.

## 8. Sony Headphones Connect app architecture (from APK reverse)

Source: `Sound_Connect_APK/SoundConnect_12.5.1.apk`, decompiled with jadx in `Sound_Connect_APK/src/`.

### Verification chain (com.sony.songpal.automagic)

`com.sony.songpal.automagic.a.e()` is the entry point that:
1. Downloads info.xml via `e.c()` → `HttpsDownloader`
2. Splits plaintext header (`eaid:`, `daid:`, `digest:`) from encrypted body
3. AES-decrypts body with `Y6.c.a()` → `Y6.d` impl uses key above
4. Verifies digest: `c.c(header_digest, sha1(plaintext_body) + lang + model, SHA1, eVar)`
5. Parses XML → extracts Distribution entries with Size + MAC
6. Downloads each Distribution URL → verifies size + MAC

### Transfer to headphones (com.airoha.* — Airoha SDK)

After verification, the file goes to the **Airoha FOTA SDK** (vendored into the Sony app, not Sony code):

- `com.airoha.project.sony.FotaControl2811` (specifically for MT2811 chip)
- `r2.C1856c` (extends `r2.C1855b`) — the AirohaRaceOtaMgr
- File loaded via `Q0(byte[] bArr)` → stored in `f24258X`
- Transfer started via `S0()`/`T0()` → calls `n0(bytes, ..., ..., 0x200000)`
  - `0x200000` = 2 MiB chunk size (`f24257d0`)

### Stage pipeline (the key discovery)

The Airoha SDK runs a sequence of **FotaStages**. Stage names from log strings in `v2/*` and `w2/*`:

| Stage | Class | Purpose |
|---|---|---|
| 00 | `v2.C1907a` | InquiryFota — query partition info (RACE_FOTA_PARTITION_INFO_QUERY) |
| 00 | `v2.C1908b` | QueryState — query FOTA state |
| 01 | `v2.C1909c` | StartTranscation [sic] — begin |
| 04 | `v2.C1910d` | CheckIntegrity — initial integrity check |
| 11 | `v2.f` | DiffFlashPartitionEraseStorage — erase chunks |
| 12 | `v2.g` | RACE_STORAGE_PAGE_PROGRAM — write 256-B pages |
| 13 | `v2.h` | GetPartitionEraseStatusStorage — query erase state |
| **24** | **`w2.m` / `v2.i`** | **Verify per-chunk SHA-256 (this is what fails for us)** |

### File parsing (in `v2.h.i()`)

```java
int iA = this.f22068b.A();                  // partition base address
InputStream is = this.f22068b.z();          // input stream of the .bin
com.airoha.android.lib.fota.stage.a.f22063w = new LinkedHashMap<>();
byte[] bArr = new byte[4096];
Arrays.fill(bArr, (byte) -1);               // init to 0xff
while ((i5 = is.read(bArr)) != -1) {
    f22063w.put(addrKey, new C0176a(addrBytes, bArr, i5));   // 4 KB chunks
    iA += 4096;
}
```

The **entire .bin file is split into sequential 4 KB chunks**, each written to `partition_base + chunk_index * 4096`. No knowledge of the LZMA/AES format — just raw bytes.

### Per-chunk SHA-256 (in `com.airoha.android.lib.fota.stage.a.C0176a` constructor)

```java
this.f22087c = new byte[i4];
System.arraycopy(bArr2, 0, this.f22087c, 0, i4);
this.f22088d = D2.e.a(this.f22087c);   // SHA-256 of the chunk

// D2/e.java:
public static byte[] a(byte[] bArr) {
    return MessageDigest.getInstance("SHA-256").digest(bArr);
}
```

Each 4 KB chunk gets a SHA-256 computed by the app, stored in `f22088d`.

### Page-write skip optimization (in `v2.g.i()` and `w2.k.i()`)

```java
byte[] bArr2 = new byte[256];
Arrays.fill(bArr2, (byte) -1);
System.arraycopy(c0176a.f22087c, i5, bArr2, 0, i7);
if (!D2.b.a(bArr2)) {                      // skip if all 0xff
    new D2.a((byte) 0).update(bArr2);      // 1-byte CRC for transport
    bArr[0] = checksum_byte;
    System.arraycopy(addrBytes, 0, bArr, 1, 4);
    System.arraycopy(bArr2, 0, bArr, 5, 256);
    // send 261-byte page-write packet
}

// D2/b.java:
public static boolean a(byte[] bArr) {
    for (byte b4 : bArr) if (b4 != -1) return false;
    return true;
}
```

256-byte pages that are **entirely `0xff`** are skipped (flash is already in that state after erase). This is the optimization that gets us into trouble.

### Stage 24 verification (in `w2.m.q()` and `v2.i.q()`)

For each chunk, the app sends the headphones the expected SHA-256:
```
"FotaStage_24 target sha256_2_addr: <addr>"
"FotaStage_24 target sha256_2_byteLen: <len>"
"FotaStage_24 target targetSHA256_2: <sha256 hex>"
```

Then a `C1808a` command goes out (cmd id 1073 / 1075 depending on stage). The headphones compute SHA-256 over what they wrote at the address, compare to expected, return success/fail.

## 9. Why our re-packs failed at 99% (root cause — SOLVED)

**The verifier:** `flash[file_base:file_base+32]` (the so-called "32-byte nonce" at file offset `0x000`) is `SHA-256(file[0x100:end])`. The device's CheckIntegrity handler (cmd `0x1C01`) computes the same SHA-256 over the just-written flash region and memcmps against the 32 bytes at file offset `0x000`. If they don't match → install rejected at 99%.

Our packer was preserving Sony's original 32-byte field while changing everything from offset `0x100` onward (TLV, encrypted body) — so the comparison always failed. Fix is one line: `file[0:32] = sha256(file[0x100:]).digest()` after building everything else. Verified to match exactly for all 5 Sony language packs.

See §16 for the full firmware call chain.

**Disproved hypotheses (kept for memory — don't re-explore these):**
- *On-device LZMA decoder rejects modern xz output.* Refuted by `--perturb-padding`: byte-identical decompressed image, only last AES block differs → still fails. The LZMA decoder is never the failure point.
- *Per-chunk SHA-256 mismatch from page-skip differences.* Disproved by direct count: Sony's bin and our bin both have exactly 14 all-`0xff` 256-byte pages, all in the header chunk. Skip behavior is identical on both.
- *Encoder-effort tuning matters.* `preset=0` produced a body within +72 bytes of Sony's (vs −5,092 with preset=6). Still failed — irrelevant to the actual check.
- *Stages 14, 23, 24 are the failure point.* Re-read of the Airoha SDK shows these are planning/compare stages — they don't fail on mismatch, they just decide skip vs write. The failure is Stage 04 (`v2.C1910d` CheckIntegrity, cmd `0x1C01`).

**Stage roles re-clarified by reading `v2/i.java`, `v2/h.java`, `w2/m.java` more carefully:**

| Stage | Role | Fails install? |
|---|---|---|
| 14 (`v2.h` ComparePartitionV2Storage) | **Optimization** — ask device for current flash SHA-256, decide skip vs write | No — never aborts |
| 23 (`w2.l`) | **Planning** — compare/skip-type decision | No |
| 24 (`w2.m` / `v2.i`) | **Planning** — compare/skip-type decision | No |
| 22 (`w2.k` / `v2.g`) | Page write (with `D2.b.a()` all-0xff skip) | No |
| **04 (`v2.C1910d` CheckIntegrity, cmd `0x1C01` / 7169)** | **Final device-side integrity check** | **YES — this is what fails** |

**Stage 04 packet:** payload is only 3 bytes `[1, role_byte, role_byte]`. No expected hash supplied by the app — the headphones perform the entire verification intrinsically using info already on-device.

**What the device verifies — narrowed:**
- **NOT** SHA-256 of decompressed image vs TLV `0x0014` alone — `--perturb-padding` proved this isn't sufficient (decompressed identical, install still fails).
- **NOT** any value stored in the .bin's TLV header — brute-forced the 32-byte field at offset `0x000` against ~20 SHA-256/HMAC candidate slices, no match. Walked all TLV tags, only `0x11/0x12/0x13/0x14` exist, all dynamic fields recomputed correctly by our packer.
- **NOT** anything in info.xml — only carries Size + SHA-1 MAC, both recomputed; no separate signature URL.

**Working hypothesis:** the 32-byte field at offset `0x000` (previously assumed to be a random nonce) is actually a **signature** — ECDSA component, Ed25519 half, or HMAC with a key we don't have. The device verifies it against a Sony pubkey/HMAC-key baked into firmware. Alternative: a digest stored in NVDM partition 2.

**Cross-pack nonce comparison (English/French/German/Spanish/Turkish):** all 32-byte fields are unique, high-entropy, with no structural correlation to the body via XOR/concat/hash. Consistent with signatures, not nonces.

**To resolve:** either (1) BLE-dump NVDM partition 2 before/after a Sony install and diff for any voice-pack-related expected value, or (2) firmware-RE the Stage 04 handler. Strings (`RACE_CmdHandler_FOTA_check_integrity` @ `0x0822ace9`) have zero xrefs — production logger strips `__func__` — so RE has to trace inward from BLE packet entry.

## 10. Files in this directory

| File | Purpose |
|---|---|
| `decrypt.sh`, `decrypt.py` | Decrypt UPG firmware: header strip → AES → LZMA → HEDS body |
| `heds_extract.py` | Parse HEDS container, dump body and size table |
| `pack_voice_pack.py` | Build a custom voice pack (`patched.bin`): replace MP3 slots, repack |
| `pack_info_xml.py` | Build a forged `info.xml` advertising patched.bin's actual size + SHA-1 |
| `swap_vp.py` | mitmproxy addon: swap CDN responses for VP_*.bin and info.xml |
| `find_ncasm_cycle.py` | (Earlier abandoned) byte-pattern scanner for NCASM cycle code |
| `extract_slots.py` | Decrypt + decompress a VP_*.bin and dump all 54 MP3 slots as `slot_NN.mp3` for listen-identification |
| `dump_nvdm.py` | (Mostly obsolete now) BLE NVDM dump via RACE_STORAGE_PAGE_READ — Sony locked it down on this firmware (status 0x03 on every probe). Kept for reference. |
| `voice-packs/VP_*_UPG_03.bin` | Original Sony voice packs (English, French, German, Spanish, Turkish) |
| `apple_chimes/*.mp3` | Apple AirPods chimes converted to 48kHz mono 64kbps MP3 |
| `out/` | Pre-decrypted UPG images for v2.5.0 → v3.0.1 + heds_body.bin |
| `tryagain.rep`, `WH1000XM4.rep`, `out/xm4.rep` | Ghidra projects (active: `tryagain`) |
| `patched.bin` | Current modified voice pack (regenerated by `pack_voice_pack.py`) |
| `patched_info.xml` | Current forged manifest matching `patched.bin` |

External:
- `~/Downloads/Sound_Connect_APK/` — APK + decompiled sources
- `/tmp/info_*.bin` — cached Sony info.xml downloads
- `/tmp/sony-vp-extract/` — reference repo (HelgeSverre)

## 11. What we PROVED (with tests)

| Test | Result | Conclusion |
|---|---|---|
| Sony's unmodified bin via our proxy | ✅ installed (once) | Pipeline works end-to-end |
| Same Sony bin attempted again later | ❌ 99% fail | Headphone state matters; previous installs leave state |
| No-op repack (decompressed identical, encoder bytes differ) of English | ❌ 99% fail | Byte-identical decompressed content isn't enough |
| No-op repack of Turkish (never installed on this device) | ❌ 99% fail | Not a "version already installed" lockout — purely byte-level |
| Apple-chimes patched bin (multiple variants) | ❌ 99% fail | Same root cause |
| Sony slot-19 (internal) chime patched bin | ❌ 99% fail | Not Apple-MP3-format-specific |
| Padded `patched.bin` to 911,456 B | ❌ 99% fail | Not a file-size invariant |
| `0x00` vs `0xff` trailing AES padding | ❌ 99% fail | Not the trailing pad |
| Decompressed image padded to 1 MiB (vs not) | ❌ 99% fail (with) / ❌ at 0% (without) | 1 MiB padding is REQUIRED — partition slot is fixed-size |
| LZMA `preset=0` (closer to old SDK 4.x) — body within +72 B of Sony | ❌ 99% fail | Encoder-effort tuning alone doesn't resolve; not just about byte count |
| `--perturb-padding`: byte-identical decompressed image, only last 16 ciphertext bytes differ from Sony | ❌ 99% fail | **Decisive**: device verifies encrypted/compressed bytes directly, not just decompressed content. On-device LZMA decoder is NOT the failure point. |
| Brute-force ~20 SHA-256/HMAC candidates against the 32-byte field at file offset `0x000` (offsets 0x00, 0x20 etc.) | No match | The 32-byte field isn't a hash of those slices. Missed offset `0x100` specifically. |
| **Recompute `file[0:32] = SHA-256(file[0x100:end])` after building everything** | ✅ **Install succeeded** | **Fix #1.** Verified against all 5 Sony packs: their offset-`0x000` field exactly matches `SHA-256(file[0x100:end])`. |
| English-source install (lang already English on device) with fix #1 only | ✅ install succeeds, ❌ runtime audio still default Sony | Silent fallback: install reports success but runtime uses default English voice pack. Manifest claiming English while installing onto English device hits a downstream check we never identified. |
| Spanish-source install with `--rewrite-lang` so manifest natively claims VGIDLPB0404 + VP_spanish_ URI | ✅ **install succeeds AND runtime plays Apple chimes** | **Fix #2.** Cross-language install via fresh-language switch + lang-consistent manifest is the working path. |

## 12. What we RULED OUT

- iOS proxy / cert trust (Sony's unmodified bytes installed via this same chain)
- mitmproxy byte corruption
- File size invariant (`file_size = header_size + body_size`)
- Decompressed image size (must be exactly 1 MiB — ruled IN)
- Trailing AES padding (`0xff` matches Sony but doesn't fix it)
- MP3 codec compatibility (Sony's own MP3 from slot 19 also fails)
- TLV `0x0012` 4th u32 (constant across all language packs)
- Headphone state alone (Turkish, never installed, also fails)

## 13. AES + LZMA encoder facts

Sony's encoder produces **larger** output (~907 KB body) than every modern encoder we tested:

| Encoder | English VP body size | Δ vs Sony |
|---|---|---|
| Sony's actual output | 907,348 B | baseline |
| Python `lzma` (xz-utils) | 902,256 B | -5,092 B |
| pylzma alg=2 eos=1 fb=273 | 902,194 B | -5,154 B |
| pylzma alg=1 eos=1 fb=128 | 902,235 B | -5,113 B |

`pylzma` is the LZMA SDK by Igor Pavlov but a **modern** version. Sony uses a much **older** SDK build (likely 4.x) with less aggressive optimization. We don't have the exact binary.

LZMA params (parsed from props byte): `lc=3, lp=0, pb=2, dict_size=0x4000`.

## 14. Concrete next-session tasks (in priority order)

### DONE — voice prompts replaced end-to-end

- §9 + §16: install succeeds via SHA-256 signature recompute.
- §17 (new): runtime audio actually plays our chimes via lang-consistent manifest rewrite + cross-language install.
- Slot mapping in §5 confirmed correct by listen-test (slots 6/7/8 = NC, ASC off, Ambient).

### Loose ends if revisited

- We never identified the downstream check that rejects same-language installs (post-CheckIntegrity, before runtime activation). Could be in the app, in NVDM, or in firmware. Not blocking since the cross-language install path works.
- BLE NVDM dump is locked (status 0x03 on RACE_STORAGE_PAGE_READ in this firmware). Blocked unless we find a session/auth setup we missed. Not needed for the working install path.

### Path B — fall back to direct BLE flash write

Use the RACE protocol directly via `bleak` to write to partition 6, bypassing the Sony app and FOTA SDK entirely. We identified the storage commands via Ghidra strings:
- `race_cmdhdl_storage_write_page` — write opcode (need to find numeric value)
- Sister to `RACE_STORAGE_PAGE_READ` (= 0x0403, per HelgeSverre writeup) — write opcode is probably 0x0404
- `race_cmdhdl_storage_check_is_encrypted` — partition encryption check (partition 6 may require encrypted writes — fits our voice pack format)
- BLE service: `dc405470-a351-4a59-97d8-2e2e3b207fbb`, TX `bfd869fa-...80cead`, RX (notify) `2a6b6575-...3a56d955`

Significant additional firmware RE work needed.

### Path C — patch firmware to skip Stage 24

The Stage 24 check is in the running CM4 firmware (partition 1, 64 KB). Dump it via RACE BLE reads (per HelgeSverre's approach), patch the SHA-256 verification routine to always return success, re-flash. Highest risk, most invasive.

## 16. The CheckIntegrity verifier — full Ghidra call chain

Found in `tryagain.rep` (heds_body.bin, ARM Cortex-M4, image base `0x08000000`, with byte-mapped SRAM mirror at `0x00000000`). Required reanalyze after the mirror was added (function count 5,596 → 8,183).

**Discovery path — how we found it:**
1. Searched for SHA-256 initial-hash constants (`67 E6 09 6A 85 AE 67 BB ...`) → hit at `0x0814952c`.
2. Only one xref → reader is `FUN_081494c0` = `sha256_init(state, mode)` (mode=0 → SHA-256).
3. Three callers of `sha256_init`. One (`FUN_0814d212`) builds a BLE response with opcode `0x5b` and cmd `0x431` (= 1073 = `C1808a` from APK = FotaStage_24 per-chunk SHA-256 query).
4. That made `FUN_0814fd90(role, opcode, cmd_id, payload_len, ctx)` identifiable as **the RACE response packet builder** — every RACE handler in firmware uses it.
5. Searched for code patterns `MOVW R2, #0x1C01` (encoding `41 F6 01 42`) → 2 hits, both inside `FUN_0814ddec`. That function makes two `FUN_0814fd90(..., 0x5b, 0x1C01, ...)` calls (ack + result). **`FUN_0814ddec` IS the on-device cmd `0x1C01` handler.** No string xrefs needed — `__func__` and live log strings are all dead in this release build.

**Call chain:**

```
FUN_0814ddec  (CheckIntegrity handler, cmd 0x1C01)
  ├── ack response (FUN_0814fd90, opcode 0x5b, cmd 0x1C01, len 1)
  │
  ├── FUN_08147678(&type, &file_base, &hash_start, &hash_len, &role)
  │     └── walks the .bin TLV at file_base+0x100, finds tag 0x0011 (10-B value),
  │         reads byte 1 as `type` (0x01 = "verify required"),
  │         returns: hash_start = file_base + 0x100
  │                  hash_len   = 0xF00 + body_size  (= entire file from 0x100 to end)
  │                  file_base  = .bin partition address
  │
  ├── FUN_0814ca0c(hash_start, hash_len, role, hash_out, ..., ctx)
  │     └── async SHA-256 over flash[hash_start : hash_start+hash_len]
  │     └── result written to hash_out (32 B)
  │
  └── FUN_0814dba8(0, hash_start, hash_len, role, hash_out, ctx)
        └── FUN_0814f2d8(file_base, role, hash_out, 32)
              ├── FUN_08148774(file_base, buf32, 32, opposite_role)   // read 32 B from PARTNER ear's flash at file_base
              ├── FUN_081e4300(buf32, hash_out, 32)                   // memcmp
              └── return 0 (= status byte) on match, 0xD on mismatch
```

**What the device verifies:**
- **Computed**: `SHA-256(flash[file_base + 0x100 : file_base + 0x100 + 0xF00 + body_size])` — i.e., everything in the .bin **except the first 256 bytes**.
- **Expected**: 32 bytes read from `flash[file_base : file_base + 32]` — the first 32 bytes of the .bin (file offset `0x000`).
- Cross-read with **opposite role** — agent ear reads partner's flash. Sync check: confirms both earcups received identical bytes via LRSync. For us this just means the same hash is read from either ear (we serve the same .bin to both).

**Why `0x100`, not `0x20`?** The first `0x20` bytes are the SHA-256 itself; bytes `0x20–0xFF` are `0xff` padding before the TLV; bytes `0x100–0xFFF` are the TLV block; bytes `0x1000–end` are the encrypted/compressed body. The hash covers everything except the hash itself + the padding before the TLV.

**Status byte semantics in the response packet:**
- `0` = success
- `0xD` = hash mismatch (= the "Voice data transfer failed" error at 99%)
- Other values = setup errors (`FUN_08147678` failed, etc.)

## 17. The working install procedure (cookbook)

Verified working as of 2026-04-27. Apple chimes audibly play on the headphones after this sequence.

**Prerequisites:**
- Headphones currently have a language other than the target installed (e.g., Italian on device, install Spanish below). Fresh-language switch is what triggers the full re-fetch path that works.
- mitmproxy CA installed + trusted on the iPhone (NOTES.md §7).
- iPhone WiFi proxy pointed at laptop:8080.

**Build the payload (Spanish + Apple chimes example):**
```bash
uv run pack_voice_pack.py voice-packs/VP_spanish_UPG_03.bin patched.bin \
  --mp3 6=apple_chimes/noiseCancellation.mp3 \
  --mp3 7=apple_chimes/noiseControlOff.mp3 \
  --mp3 8=apple_chimes/transparency.mp3

uv run pack_info_xml.py /tmp/info_english.bin patched.bin \
  --lang-pack VGIDLPB0404 --rewrite-lang \
  --out patched_info.xml
```

`/tmp/info_english.bin` works as a template for any target language because `--rewrite-lang` substitutes `VGIDLPB04XX` codes and `VP_<lang>_` URI segments to match `--lang-pack`. Any cached Sony info.xml works as the seed.

**Serve and install:**
```bash
mitmdump -s swap_vp.py --listen-port 8080
```

In Sony Headphones Connect on the iPhone: change voice guidance language to Spanish. Watch the proxy log — should show TWO `[sony] SWAPPED` lines (info.xml + VP_spanish_UPG_03.bin). Install runs to 100%, headphones reboot, then the configured prompts (NC, ambient, etc.) play your chimes.

**Language code reference** (per NOTES.md §5):

| Code | Lang | bin filename |
|---|---|---|
| VGIDLPB0401 | english | VP_english_UPG_03.bin |
| VGIDLPB0402 | french | VP_french_UPG_03.bin |
| VGIDLPB0403 | german | VP_german_UPG_03.bin |
| VGIDLPB0404 | spanish | VP_spanish_UPG_03.bin |
| VGIDLPB0405 | italian | VP_italian_UPG_03.bin |
| VGIDLPB0406 | portuguese | VP_portuguese_UPG_03.bin |
| VGIDLPB0407 | dutch | VP_dutch_UPG_03.bin |
| VGIDLPB0408 | swedish | VP_swedish_UPG_03.bin |
| VGIDLPB0409 | finnish | VP_finnish_UPG_03.bin |
| VGIDLPB0410 | turkish | VP_turkish_UPG_03.bin |

**Why same-language installs fall back silently:** unknown. The headphones accept the bytes (CheckIntegrity passes thanks to fix #1) but at runtime use a default voice pack instead of our patched one. The cross-language path (above) avoids this codepath entirely. If you want to swap voice prompts on a target that already has the language you want, switch to a *different* language first, then back to the target with the patched payload prepared for that target.

## 15. References

- HelgeSverre's writeup: <https://github.com/HelgeSverre/sony-vp-extract/blob/main/docs/WRITEUP.md>
- LZMA SDK by Igor Pavlov: <https://www.7-zip.org/sdk.html>
- Sony Headphones Connect APK (decompiled): `~/Downloads/Sound_Connect_APK/src/`
- Airoha FOTA SDK source path in APK: `src/classes/sources/com/airoha/{libfota1568,libfota2833,android/lib/fota,project/sony,libcommon}/`
- D2 helper classes (CRC, hash, hex): `src/classes/sources/D2/`
- FOTA stages: `src/classes/sources/v2/`, `src/classes/sources/w2/`, `src/classes/sources/r2/`
