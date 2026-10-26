#!/usr/bin/env python3
"""Fetch Didier Stevens' tools (pdfid, pdf-parser, oledump, zipdump, rtfdump and
plugins) into ./vendor, unmodified, from one pinned and verified commit.

    python setup_vendor.py                 # download the pinned commit; every file must match its pin
    python setup_vendor.py --pip           # also pip install requirements.txt (versions from constraints.txt)
    python setup_vendor.py --peepdf        # install peepdf-3 without its JS engine (STPyV8)
    python setup_vendor.py --copy-from DIR # offline: copy from a folder; the files must match the pins
    python setup_vendor.py --ref <commit> --allow-unverified   # another commit: installed, but UNVERIFIED
    python setup_vendor.py --record        # re-record vendor/manifest.json for the files present
    python setup_vendor.py --update-pin <commit>   # maintainers: move the pin (app/core/vendor_pins.py)

The pinned commit and every file's SHA-256 are in app/core/vendor_pins.py, computed when
the pin was made (never from what happens to be downloaded at install time). All files
are fetched and checked first; if any required file is missing or any hash differs,
nothing is installed (fail closed). The app re-checks the hashes at startup.

On REMnux use the REMnux edition: it uses REMnux's own copies and downloads nothing.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
VENDOR = os.path.join(HERE, "vendor")
CONSTRAINTS = os.path.join(HERE, "constraints.txt")
PINS_FILE = os.path.join(HERE, "app", "core", "vendor_pins.py")

sys.path.insert(0, HERE)
from app.core import vendor_manifest, vendor_pins  # noqa: E402  (stdlib-only modules)

RAW = "https://raw.githubusercontent.com/" + vendor_pins.REPO + "/"
API = "https://api.github.com/repos/" + vendor_pins.REPO + "/"

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


def rel_path(name: str, sub: str) -> str:
    return f"{sub}/{name}" if sub else name


def fetch(url: str) -> bytes:
    """Download one URL (replaced in tests)."""
    req = urllib.request.Request(url, headers={"User-Agent": "maldoc-triage-workbench-setup"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def collect(ref: str = "", copy_from: str = "") -> tuple:
    """Fetch (or copy) every file into memory.
    Returns (rel path -> bytes, problem lines, whether a required file is missing)."""
    staged = {}
    problems = []
    missing_required = False
    for name, sub, required in FILES:
        rel = rel_path(name, sub)
        try:
            if copy_from:
                with open(os.path.join(copy_from, name), "rb") as fh:
                    staged[rel] = fh.read()
            else:
                staged[rel] = fetch(RAW + ref + "/" + name)
        except Exception as exc:  # network error, 404, unreadable file
            problems.append(f"{rel}: could not get it ({exc})")
            missing_required = missing_required or required
    return staged, problems, missing_required


def pin_mismatches(staged: dict) -> list:
    """Lines for every staged file whose SHA-256 differs from (or has no) pinned hash."""
    out = []
    for rel, data in staged.items():
        want = vendor_pins.FILES.get(rel)
        got = sha256(data)
        if want is None:
            out.append(f"{rel}: no pinned hash")
        elif got != want:
            out.append(f"{rel}: SHA-256 mismatch (got {got[:16]}..., pinned {want[:16]}...)")
    return out


def install(staged: dict, vendor: str = VENDOR) -> None:
    """Write the staged files into vendor/, each via a temporary file and an atomic rename."""
    for rel, data in staged.items():
        dest = os.path.join(vendor, *rel.split("/"))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        tmp = dest + ".part"
        with open(tmp, "wb") as fh:
            fh.write(data)
        os.replace(tmp, dest)
        print(f"  + {rel}  sha256 {sha256(data)[:16]}...  ({len(data):,} bytes)")


def fetch_tools(ref: str = "", copy_from: str = "", allow_unverified: bool = False,
                vendor: str = VENDOR) -> int:
    """Fetch/copy, verify against the pins, then install all or nothing. Returns an exit code:
    0 installed, 1 failed (nothing installed), 2 refused (unpinned ref without --allow-unverified)."""
    ref = (ref or vendor_pins.COMMIT).strip().strip("/")
    pinned_ref = ref == vendor_pins.COMMIT
    if not copy_from and not pinned_ref and not allow_unverified:
        print(f"Refusing to fetch {ref!r}: only the pinned commit {vendor_pins.COMMIT[:12]} has trusted "
              "hashes.\nUse --allow-unverified to install another revision anyway (it will show as "
              "UNVERIFIED), or move the pin with --update-pin and review the diff.")
        return 2
    where = f"folder {copy_from}" if copy_from else RAW + ref + "/"
    print(f"Source: {where}" + ("  (pinned commit; every file is checked against its pinned hash)"
                                if pinned_ref and not copy_from else ""))
    staged, problems, missing_required = collect("" if copy_from else ref, copy_from)
    for line in problems:
        print(f"  ! {line}")
    mismatches = pin_mismatches(staged)
    if missing_required:
        print("A required tool could not be fetched. Nothing was installed.")
        return 1
    if mismatches and not allow_unverified:
        print("These files do not match the pinned hashes:")
        for line in mismatches:
            print(f"  ! {line}")
        print("Nothing was installed. If you didn't expect a change, treat this as possible tampering "
              "(or a rewritten upstream commit) and investigate before using any downloaded copy.")
        return 1
    if mismatches:
        print("WARNING: installing files that don't match the pins (--allow-unverified):")
        for line in mismatches:
            print(f"  ! {line}")
    install(staged, vendor)
    verified = not mismatches
    source = f"copied from {copy_from}" if copy_from else RAW + ref + "/"
    manifest, changes = vendor_manifest.record(vendor, source, vendor_pins.COMMIT if verified else ref,
                                               pinned=verified)
    print(f"Recorded {len(manifest['files'])} file hash(es) in vendor/{vendor_manifest.MANIFEST}"
          + (" (all match the pins)" if verified else " (UNVERIFIED: not the pinned files)"))
    for line in changes:
        print(f"  ~ {line}")
    return 0


def render_pins(commit: str, date: str, files: dict, verified_with: tuple) -> str:
    """The text of app/core/vendor_pins.py for a new pin."""
    q = '"' * 3
    lines = [
        q + "Trusted SHA-256 hashes of Didier Stevens' tools at one pinned DidierStevensSuite commit.",
        "",
        "setup_vendor.py downloads exactly these files from exactly this commit and refuses any",
        "file whose hash differs, so a tampered or rewritten upstream file is never installed.",
        "The hashes were computed when the pin was made, not at install time, and every change",
        "to this file is a reviewable diff.",
        "",
        f"Written by  python setup_vendor.py --update-pin {commit}",
        "Each file was fetched from raw.githubusercontent.com and its git blob hash checked",
        "against the commit's tree from the GitHub API (two different GitHub services). Before",
        "committing, compare with another independent copy (for example REMnux's) if you can.",
        q,
        "",
        f'REPO = "{vendor_pins.REPO}"',
        f'COMMIT = "{commit}"',
        f'COMMIT_DATE = "{date}"',
        "",
        "# vendor-relative path -> SHA-256 of the file at COMMIT (upstream name = last path part)",
        "FILES = {",
    ]
    lines += [f'    "{rel}": "{digest}",' for rel, digest in files.items()]
    lines += ["}", "", "# independent sources that agreed with FILES when the pin was made",
              f"VERIFIED_WITH = {verified_with!r}", ""]
    return "\n".join(lines)


def update_pin(commit: str, pins_file: str = PINS_FILE) -> int:
    """Maintainers: fetch every file at commit from the raw CDN, check each one's git blob hash
    against the commit's tree from the GitHub API, and rewrite vendor_pins.py only if all agree."""
    if not re.fullmatch(r"[0-9a-f]{40}", commit or ""):
        print("--update-pin needs a full 40-character commit hash.")
        return 2
    try:
        tree = json.loads(fetch(API + "git/trees/" + commit))
        info = json.loads(fetch(API + "commits/" + commit))
    except Exception as exc:
        print(f"Could not read commit {commit} from the GitHub API: {exc}")
        return 1
    blobs = {e.get("path"): e.get("sha") for e in tree.get("tree", []) if e.get("type") == "blob"}
    date = str(info.get("commit", {}).get("committer", {}).get("date", ""))[:10]
    files = {}
    for name, sub, _required in FILES:
        rel = rel_path(name, sub)
        try:
            data = fetch(RAW + commit + "/" + name)
        except Exception as exc:
            print(f"  ! {rel}: could not fetch ({exc}). Pin not changed.")
            return 1
        blob = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
        if blobs.get(name) != blob:
            print(f"  ! {rel}: the raw file does not match the commit's tree (git blob {blob[:12]} vs "
                  f"{str(blobs.get(name))[:12]}). Pin not changed.")
            return 1
        files[rel] = sha256(data)
        marker = "=" if vendor_pins.FILES.get(rel) == files[rel] else "*"
        print(f"  {marker} {rel}  {files[rel][:16]}...")
    text = render_pins(commit, date, files, ("raw.githubusercontent.com", "GitHub API git tree (blob SHA-1)"))
    with open(pins_file, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    print(f"Wrote {pins_file} for {commit[:12]} ({date}). '*' marks files that changed since the previous "
          "pin. Review the diff (and the upstream changes) before committing.")
    return 0


def pip_install(*args: str) -> int:
    """pip install, with the exact versions from constraints.txt when it's present."""
    cmd = [sys.executable, "-m", "pip", "install", *args]
    if os.path.isfile(CONSTRAINTS):
        cmd += ["-c", CONSTRAINTS]
    return subprocess.call(cmd)


def main() -> int:
    """Fetch (or copy) the tools into vendor/, optionally install packages, and record their hashes."""
    for stream in (sys.stdout, sys.stderr):     # a Windows console may not be UTF-8: never crash printing
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--copy-from", metavar="DIR", help="copy the files from DIR instead of downloading")
    ap.add_argument("--pip", action="store_true", help="also pip install -r requirements.txt")
    ap.add_argument("--peepdf", action="store_true",
                    help="install peepdf-3 and its dependencies except STPyV8 (which often fails to "
                         "build; the app never executes JavaScript, so it isn't needed)")
    ap.add_argument("--ref", default=os.environ.get("MTW_VENDOR_REF", ""),
                    help=f"DidierStevensSuite commit to fetch (default: the pinned {vendor_pins.COMMIT[:12]}); "
                         "anything else needs --allow-unverified")
    ap.add_argument("--allow-unverified", action="store_true",
                    help="install files that don't match the pinned hashes (shown as UNVERIFIED)")
    ap.add_argument("--record", action="store_true",
                    help="only (re)write vendor/manifest.json for the files already in vendor")
    ap.add_argument("--update-pin", metavar="COMMIT", help="maintainers: move the pin to COMMIT")
    args = ap.parse_args()

    if args.update_pin:
        return update_pin(args.update_pin.strip())
    os.makedirs(VENDOR, exist_ok=True)
    print(f"Vendor folder: {VENDOR}")
    if args.record:
        old = vendor_manifest.load(VENDOR) or {}
        manifest, changes = vendor_manifest.record(VENDOR, "recorded locally (--record)",
                                                   str(old.get("ref", "")), bool(old.get("pinned")))
        print(f"Recorded {len(manifest['files'])} file hash(es) in vendor/{vendor_manifest.MANIFEST} "
              "(pinned files are still checked against their pinned hashes)")
        for line in changes:
            print(f"  ! {line}")
        return 0
    ok = True
    skip_fetch = (args.peepdf and not args.pip and not args.copy_from
                  and os.path.isfile(os.path.join(VENDOR, "pdfid.py")))
    if not skip_fetch:
        rc = fetch_tools(args.ref, args.copy_from or "", args.allow_unverified)
        if rc == 2:
            return 2
        ok = rc == 0

    if args.pip:
        print("Installing Python requirements...")
        ok = pip_install("-r", os.path.join(HERE, "requirements.txt")) == 0 and ok

    if args.peepdf:
        print("Installing peepdf-3 (without STPyV8)...")
        deps = ["requests", "pypdf", "colorama", "Pillow", "pythonaes", "lxml", "prettytable>=3.12.0",
                "jsbeautifier", "asn1crypto"]
        rc1 = pip_install("--no-deps", "peepdf-3")
        rc2 = pip_install(*deps)
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
