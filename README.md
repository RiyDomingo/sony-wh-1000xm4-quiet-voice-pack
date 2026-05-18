# Sony WH-1000XM4 voice-pack mod

Replace the Sony voice prompts on Sony WH-1000XM4 headphones with custom audio
(Apple AirPods chimes, Zelda jingles, anything you want). Working as of
firmware **3.0.1**.

> **What this is**: a packer that builds a Sony-format voice pack with custom
> MP3s in any of the 54 slots, a forged manifest that matches it, and a
> mitmproxy addon that serves both to the iPhone Sony Headphones Connect app
> when it goes to download a voice pack from Sony's CDN.

**Why this took two long sessions to get right:** the .bin file's first 32
bytes are `SHA-256(file[0x100:end])` — a device-side integrity check
verified at install time. We initially mislabeled them "32 random bytes /
file ID" and burned a lot of time on dead-end theories. See [NOTES.md §16][16]
for the full Ghidra reverse-engineering story.

[16]: NOTES.md

---

## Quick start

### 1. Prerequisites

```bash
# Tools assumed in PATH
uv      # github.com/astral-sh/uv (runs the Python scripts with deps)
ffmpeg  # for converting custom audio to 48kHz mono 64kbps MP3
mitmdump # mitmproxy
```

### 2. Get a Sony voice pack as starting material

```bash
mkdir -p voice-packs
curl -fsSL -o voice-packs/VP_spanish_UPG_03.bin \
  https://info.update.sony.net/HP002/VGIDLPB0404/contents/0002/VP_spanish_UPG_03.bin
```

Language code reference (`VGIDLPB04XX`):

| XX | Language     | URL fragment                |
|----|--------------|-----------------------------|
| 01 | english      | `VP_english_UPG_03.bin`     |
| 02 | french       | `VP_french_UPG_03.bin`      |
| 03 | german       | `VP_german_UPG_03.bin`      |
| 04 | spanish      | `VP_spanish_UPG_03.bin`     |
| 05 | italian      | `VP_italian_UPG_03.bin`     |
| 06 | portuguese   | `VP_portuguese_UPG_03.bin`  |
| 07 | dutch        | `VP_dutch_UPG_03.bin`       |
| 08 | swedish      | `VP_swedish_UPG_03.bin`     |
| 09 | finnish      | `VP_finnish_UPG_03.bin`     |
| 10 | turkish      | `VP_turkish_UPG_03.bin`     |

Also grab a copy of an `info.xml` (used as a template for the forged
manifest — any language works, the packer rewrites it):

```bash
curl -fsSL -o info_english.bin \
  https://info.update.sony.net/HP002/VGIDLPB0401/info/info.xml
```

### 3. Convert your custom audio

Voice-pack slots expect **48 kHz mono 64 kbps MP3**. Convert anything else:

```bash
ffmpeg -i input.flac -ar 48000 -ac 1 -b:a 64k apple_chimes/my_sound.mp3
```

The repo includes a starter set in `apple_chimes/` — Apple AirPods chimes
+ a couple of extras.

### 4. Build the payload

```bash
# Pack: replace slots 6/7/8 (NC, ASC off, Ambient) with Apple chimes
uv run pack_voice_pack.py voice-packs/VP_spanish_UPG_03.bin patched.bin \
  --mp3 6=apple_chimes/noiseCancellation.mp3 \
  --mp3 7=apple_chimes/noiseControlOff.mp3 \
  --mp3 8=apple_chimes/transparency.mp3

# Forge the matching manifest (rewrites lang refs inside the XML)
uv run pack_info_xml.py info_english.bin patched.bin \
  --lang-pack VGIDLPB0404 --rewrite-lang \
  --out patched_info.xml
```

### 5. Install

```bash
mitmdump -s swap_vp.py --listen-port 8080
```

On your iPhone:
1. Settings → Wi-Fi → (your network) → manual proxy → laptop IP, port 8080.
2. Install the mitmproxy CA: visit `http://mitm.it` in Safari with the
   proxy active, install + fully trust the cert in Settings → General →
   About → Certificate Trust Settings.
3. Open Sony Headphones Connect.
4. Change voice guidance language to **whichever language you packed**.
   The proxy will swap the manifest and the .bin during download.
5. Wait for install to complete (it'll reach 100% — the SHA-256 fix is
   what gets it past the 99% wall).

---

## Slot index → prompt mapping

| Slot | Default prompt                | Notes                              |
|------|-------------------------------|------------------------------------|
| 0    | Power on                      |                                    |
| 1    | Power off                     |                                    |
| 2    | Bluetooth pairing             |                                    |
| 3    | Bluetooth connected           |                                    |
| 4    | Bluetooth disconnected        |                                    |
| 5    | Recharge / power off          | Battery low                        |
| 6    | Noise canceling               |                                    |
| 7    | Ambient Sound Control off     |                                    |
| 8    | Ambient sound                 |                                    |
| 9    | (assistant-related)           |                                    |
| 10–14| Notification tones / chimes   | Short clips                        |
| 15   | Battery fully charged         |                                    |
| 16–18, 28–33 | Battery percentages   |                                    |
| 19–27 (mostly) | Various tones       |                                    |
| 43–44| Speak-to-chat on/off          |                                    |
| 47–53| BT device connect/disconnect  | Per-device announcements           |

Run `uv run extract_slots.py voice-packs/VP_english_UPG_03.bin slots/` to
dump all 54 to listen-confirm.

---

## Important caveats

### Cross-language install required

Switching to the **same** language already on your headphones falls back
silently to a default voice pack at runtime — install reports success
but you hear stock Sony prompts. Always switch to a **different** language
than what's currently active.

Theory: the 6 MB voice partition holds multiple languages at different
offsets. Switching language is just a "read from offset X" — the device
caches what's already there. English specifically may be a factory-burned
fallback that overrides anything we install at its slot. See [NOTES.md §17][17].

[17]: NOTES.md

**Practical pattern**: if you want English custom prompts on the
headphones, install your custom payload as a *different* language (e.g.,
Portuguese using `--lang-pack VGIDLPB0406 --rewrite-lang`), with all 54
slots replaced by extracted English ones plus your custom overrides.
The headphones store this in the unused Portuguese slot, and switching
to Portuguese makes the runtime play your custom audio while saying
English for the unreplaced prompts.

### Disclaimer.xml MAC

The forged manifest references `disclaimer.xml`. If you rewrite the
manifest URI to a non-English language, the app will fetch *that
language's* disclaimer from Sony's CDN, whose SHA-1 won't match what
our manifest advertises. The proxy automatically intercepts
`disclaimer.xml` requests and serves the bundled English copy
(`disclaimer_english.xml` — its SHA-1 matches the inherited MAC).

### Don't expect to mod English on a device that's been on English

See "Cross-language install required" above. Same rule applies to
whichever language was on the device when you started.

---

## What's in the repo

| File                     | Purpose                                                           |
|--------------------------|-------------------------------------------------------------------|
| `pack_voice_pack.py`     | Build a custom `patched.bin` voice pack                           |
| `pack_info_xml.py`       | Forge a matching `patched_info.xml` manifest                      |
| `swap_vp.py`             | mitmproxy addon: serve patched files when Sony's CDN is hit       |
| `extract_slots.py`       | Dump all 54 MP3 slots from a Sony VP_*.bin for listen-identifying |
| `disclaimer_english.xml` | Cached English disclaimer; served on any language path            |
| `apple_chimes/`          | Starter set of 48k/mono/64kbps MP3s (AirPods chimes + extras)     |
| `NOTES.md`               | Full project writeup — formats, RE notes, every dead-end          |

---

## Credits & references

- [HelgeSverre/sony-vp-extract](https://github.com/HelgeSverre/sony-vp-extract)
  — extractor + key-extraction script + writeup. Foundation that this
  builds on.
- AES key/IV: `eibohjeCh6uegahf` / `miefeinuShu9eilo` (extracted from
  firmware — same across all WH-1000XM4 units).
- `info.xml` decryption key: `4F A2 79 99 FF D0 8B 1F E4 D2 60 D5 7B 6D
  3C 17` (extracted from `com.sony.songpal.automagic Y6.d` in the
  decompiled iOS Sony Headphones Connect app).

---

## Disclaimer

This is for personal use on your own headphones. Sony's voice packs are
copyrighted; don't redistribute the unmodified `VP_*.bin` files. The
tooling here only operates on files you fetch from Sony's CDN yourself.

If you brick your headphones, that's on you.
