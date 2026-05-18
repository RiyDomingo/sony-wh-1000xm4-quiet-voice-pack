"""mitmproxy addon: substitute Sony's voice-pack download AND its info.xml manifest.

Triggered when the Sony Headphones Connect app fetches:
  /<model>/<lang_pack>/info/info.xml         -> serve patched_info.xml (forged manifest)
  /<model>/<lang_pack>/contents/.../VP_*.bin -> serve patched.bin (chime replacement)

Both files must agree on Size + SHA-1 (MAC) of the .bin.

Run with:  mitmdump -s swap_vp.py --listen-port 8080
"""
from pathlib import Path
from mitmproxy import http, ctx

HERE = Path(__file__).parent
PATCHED_BIN = HERE / "patched.bin"
PATCHED_INFO = HERE / "patched_info.xml"
DISCLAIMER  = HERE / "disclaimer_english.xml"
SONY_HOSTS = ("info.update.sony.net", "update.sony.net")


def load(loader) -> None:
    if not PATCHED_BIN.exists():
        ctx.log.error(f"patched.bin not found at {PATCHED_BIN}")
        return
    if not PATCHED_INFO.exists():
        ctx.log.warn(f"patched_info.xml not found at {PATCHED_INFO} — only .bin will be swapped")
    bin_size = PATCHED_BIN.stat().st_size
    info_size = PATCHED_INFO.stat().st_size if PATCHED_INFO.exists() else 0
    ctx.log.info(f"swap_vp loaded — patched.bin={bin_size:,} B, patched_info.xml={info_size:,} B")


def request(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host
    path = flow.request.path

    # Log every Sony update-CDN request so we can see what else the app fetches.
    if any(h in host for h in SONY_HOSTS):
        ctx.log.info(f"[sony] {flow.request.method} {host}{path}")

    # Substitute the VP_*.bin voice-pack with our chime-patched version.
    if any(h in host for h in SONY_HOSTS) and "/VP_" in path and path.endswith(".bin"):
        body = PATCHED_BIN.read_bytes()
        flow.response = http.Response.make(
            200,
            body,
            {
                "Content-Type": "application/octet-stream",
                "Content-Length": str(len(body)),
                "Cache-Control": "no-store",
            },
        )
        ctx.log.info(f"[sony] SWAPPED {path}  ->  patched.bin ({len(body):,} B)")
        return

    # Substitute disclaimer.xml. Our manifest's Disclaimer.MAC is inherited
    # from the English disclaimer; serving the English file on any language
    # path keeps that MAC valid. Without this, cross-language installs that
    # rewrite the manifest URI to a non-English language fetch the real
    # (different) disclaimer for that language, MAC mismatches → app rejects.
    if any(h in host for h in SONY_HOSTS) and path.endswith("/disclaimer.xml"):
        if not DISCLAIMER.exists():
            ctx.log.warn(f"[sony] disclaimer.xml requested but {DISCLAIMER} missing — passing through")
            return
        body = DISCLAIMER.read_bytes()
        flow.response = http.Response.make(
            200,
            body,
            {
                "Content-Type": "application/xml",
                "Content-Length": str(len(body)),
                "Cache-Control": "no-store",
            },
        )
        ctx.log.info(f"[sony] SWAPPED {path}  ->  disclaimer_english.xml ({len(body):,} B)")
        return

    # Substitute the manifest with our forged version. The forged manifest
    # advertises patched.bin's actual size + SHA-1 so the app's verification
    # passes. We match ANY language pack (VGIDLPB04XX) — the addon doesn't
    # know which language was forged, but the user is responsible for making
    # sure patched_info.xml matches the language they're about to install.
    if any(h in host for h in SONY_HOSTS) and path.endswith("/info.xml") and "VGIDLPB" in path:
        if not PATCHED_INFO.exists():
            ctx.log.warn(f"[sony] info.xml requested but {PATCHED_INFO} missing — passing through")
            return
        body = PATCHED_INFO.read_bytes()
        flow.response = http.Response.make(
            200,
            body,
            {
                "Content-Type": "application/octet-stream",
                "Content-Length": str(len(body)),
                "Cache-Control": "no-store",
            },
        )
        ctx.log.info(f"[sony] SWAPPED {path}  ->  patched_info.xml ({len(body):,} B)")
        return


def response(flow: http.HTTPFlow) -> None:
    # Log the response side too, including content length (helps diagnose
    # manifest checks that compare expected size).
    host = flow.request.pretty_host
    if any(h in host for h in SONY_HOSTS) and flow.response and not flow.response.headers.get("X-Swapped"):
        cl = flow.response.headers.get("Content-Length", "?")
        ctx.log.info(f"[sony] response {flow.response.status_code} cl={cl}  for {flow.request.path}")
