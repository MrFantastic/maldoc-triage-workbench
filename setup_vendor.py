#!/usr/bin/env python3
"""Fetch Didier Stevens' tools (pdfid, pdf-parser, oledump, zipdump, rtfdump and
plugins) into ./vendor, unmodified.

    python setup_vendor.py                 # download from GitHub
    python setup_vendor.py --copy-from DIR # offline: copy from a folder (e.g. a REMnux box)
    python setup_vendor.py --pip           # also pip install requirements.txt
    python setup_vendor.py --peepdf        # install peepdf-3 without its JS engine (STPyV8)
    python setup_vendor.py --ref <commit>  # fetch a specific commit or tag instead of master
    python setup_vendor.py --record        # re-record vendor/manifest.json for the files present

Every fetch records each file's SHA-256 in vendor/manifest.json and reports any
file whose hash changed since the last fetch. The app re-checks those hashes at
startup (Help → Tool status) so a modified tool is noticed before it runs.

On REMnux pdfid.py is already on PATH and the app finds it without this step.
"""
import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
VENDOR = os.path.join(HERE, "vendor")
REPO = "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/"
BASE = REPO + "master/"

sys.path.insert(0, HERE)
from app.core import vendor_manifest  # noqa: E402  (stdlib-only module)

# (file, vendor sub-folder, required?)
FILES = [
    ("pdfid.py", "", True),
    ("plugin_triage.py", "", False),
    ("plugin_embeddedfile.py", "", False),
    ("plugin_nameobfuscation.py", "", False),
    ("pdf-parser.py", "", True),
    ("zipdump.py", "", False),
    ("rtfdump.py", "", False),
    # oledump and its plugins live in their own folder so pdfid's plugin list stays clean
    ("oledump.py", "oledump", True),
    ("plugin_vba_summary.py", "oledump", False),
    ("plugin_biff.py", "oledump", False),
    ("plugin_http_heuristics.py", "oledump", False),
    ("plugin_dridex.py", "oledump", False),
    ("plugin_msg.py", "oledump", False),
    ("plugin_stream_o.py", "oledump", False),
    ("plugin_vba_routines.py", "oledump", False),
    ("plugin_vba_dco.py", "oledump", False),
]


def download(name: str, sub: str, base: str = BASE) -> bool:
    """Fetch one DidierStevensSuite file into vendor/<sub>; print why and return False if it fails."""
    url = base + name
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = resp.read()
    except Exception as exc:
        print(f"  ! {name}: {exc}")
        return False
    folder = os.path.join(VENDOR, sub)
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, name), "wb") as fh:
        fh.write(data)
    print(f"  + {os.path.join(sub, name)}  sha256 {hashlib.sha256(data).hexdigest()[:16]}…  ({len(data):,} bytes)")
    return True


def main() -> int:
    """Fetch (or copy) the tools into vendor/, optionally install packages, and record their hashes."""
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--copy-from", metavar="DIR", help="copy the files from DIR instead of downloading")
    ap.add_argument("--pip", action="store_true", help="also pip install -r requirements.txt")
    ap.add_argument("--peepdf", action="store_true",
                    help="install peepdf-3 and its dependencies except STPyV8 (which often fails to "
                         "build; the app never executes JavaScript, so it isn't needed)")
    ap.add_argument("--ref", default=os.environ.get("MTW_VENDOR_REF", ""),
                    help="commit hash or tag of DidierStevensSuite to fetch (default: master; "
                         "or set MTW_VENDOR_REF)")
    ap.add_argument("--record", action="store_true",
                    help="only (re)write vendor/manifest.json for the files already in vendor")
    args = ap.parse_args()

    os.makedirs(VENDOR, exist_ok=True)
    print(f"Vendor folder: {VENDOR}")
    if args.record:
        manifest, changes = vendor_manifest.record(VENDOR, "recorded locally (--record)")
        print(f"Recorded {len(manifest['files'])} file hash(es) in vendor/{vendor_manifest.MANIFEST}")
        for line in changes:
            print(f"  ! {line}")
        return 0
    ref = args.ref.strip().strip("/")
    base = (REPO + ref + "/") if ref else BASE
    if not args.copy_from:
        print(f"Source: {base}" + ("" if ref else "  (unpinned: use --ref <commit> to pin a version)"))
    ok = True
    fetched = False
    for name, sub, required in (FILES if not (args.peepdf and not args.pip and not args.copy_from
                                             and os.path.isfile(os.path.join(VENDOR, "pdfid.py")))
                                else []):
        fetched = True
        if args.copy_from:
            src = os.path.join(args.copy_from, name)
            if os.path.isfile(src):
                os.makedirs(os.path.join(VENDOR, sub), exist_ok=True)
                shutil.copyfile(src, os.path.join(VENDOR, sub, name))
                print(f"  + {os.path.join(sub, name)} (copied)")
            else:
                print(f"  ! {name} not found in {args.copy_from}")
                ok = ok and not required
        else:
            got = download(name, sub, base)
            ok = ok and (got or not required)

    if fetched:
        source = f"copied from {args.copy_from}" if args.copy_from else base
        manifest, changes = vendor_manifest.record(VENDOR, source, "" if args.copy_from else (ref or "master"))
        print(f"Recorded {len(manifest['files'])} file hash(es) in vendor/{vendor_manifest.MANIFEST}")
        if changes:
            print("  Changed since the last fetch (review before trusting them):")
            for line in changes:
                print(f"    ! {line}")

    if args.pip:
        req = os.path.join(HERE, "requirements.txt")
        print("Installing Python requirements…")
        rc = subprocess.call([sys.executable, "-m", "pip", "install", "-r", req])
        ok = ok and rc == 0

    if args.peepdf:
        print("Installing peepdf-3 (without STPyV8)…")
        deps = ["requests", "pypdf", "colorama", "Pillow", "pythonaes", "lxml", "prettytable>=3.12.0",
                "jsbeautifier", "asn1crypto"]
        rc1 = subprocess.call([sys.executable, "-m", "pip", "install", "--no-deps", "peepdf-3"])
        rc2 = subprocess.call([sys.executable, "-m", "pip", "install"] + deps)
        ok = ok and rc1 == 0 and rc2 == 0
        if rc1 == 0 and rc2 == 0:
            print("peepdf installed. JavaScript emulation (js_eval) is unavailable by design.")

    print("Done." if ok else "Finished with errors (see above).")
    return 0 if ok else 1


def _launched_by_double_click() -> bool:
    """True on Windows when this script owns its console window (Explorer double-click)."""
    if os.name != "nt":
        return False
    try:
        import ctypes
        buf = (ctypes.c_uint * 4)()
        n = ctypes.windll.kernel32.GetConsoleProcessList(buf, 4)
        return 1 <= n <= 2 and sys.stdin is not None and sys.stdin.isatty()
    except Exception:
        return False


if __name__ == "__main__":
    code = main()
    if _launched_by_double_click():
        try:
            input("\nPress Enter to close this window...")
        except EOFError:
            pass
    sys.exit(code)
