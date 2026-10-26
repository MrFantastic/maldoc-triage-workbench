"""SHA-256 manifest of the vendored tools (vendor/manifest.json).

setup_vendor.py fetches the tools from the commit pinned in vendor_pins and only
installs files whose hash matches the pin. At startup the app re-hashes them:

  * files fetched from the pin are compared with the PINNED hashes themselves, so a
    tool that changed afterwards (edited, replaced, or overwritten by something a
    sample dropped) is reported even if someone re-recorded the manifest
  * files fetched from any other ref (setup_vendor.py --ref X --allow-unverified) are
    compared with the hashes recorded at fetch time. That proves they haven't changed
    since, not that they're genuine, so their status is UNVERIFIED.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os

from . import vendor_pins

MANIFEST = "manifest.json"
TRACKED_EXT = (".py",)


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def scan(vendor_dir: str) -> dict[str, str]:
    """relative path (forward slashes) -> sha256 for every tracked file under vendor_dir."""
    out: dict[str, str] = {}
    if not os.path.isdir(vendor_dir):
        return out
    for root, dirs, files in os.walk(vendor_dir):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        for name in sorted(files):
            if name.endswith(TRACKED_EXT):
                full = os.path.join(root, name)
                out[os.path.relpath(full, vendor_dir).replace(os.sep, "/")] = _sha256(full)
    return out


def load(vendor_dir: str) -> dict | None:
    """The vendor manifest (tool hashes), or None if it's missing or malformed."""
    try:
        with open(os.path.join(vendor_dir, MANIFEST), encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and isinstance(data.get("files"), dict) else None


def record(vendor_dir: str, source: str, ref: str = "", pinned: bool = False) -> tuple[dict, list[str]]:
    """Write the manifest for what is in vendor_dir now. pinned: the files were verified
    against vendor_pins when fetched. Returns (manifest, lines describing files whose
    hash differs from the previous manifest)."""
    old = (load(vendor_dir) or {}).get("files", {})
    files = scan(vendor_dir)
    changes = []
    for rel, digest in files.items():
        if rel in old and old[rel] != digest:
            changes.append(f"{rel}: hash changed ({old[rel][:12]}... -> {digest[:12]}...)")
        elif rel not in old and old:
            changes.append(f"{rel}: new file")
    for rel in old:
        if rel not in files:
            changes.append(f"{rel}: removed")
    manifest = {
        "source": source,
        "ref": ref,
        "pinned": bool(pinned),
        "recorded_at": _dt.datetime.now().isoformat(timespec="seconds"),
        "files": files,
    }
    os.makedirs(vendor_dir, exist_ok=True)
    with open(os.path.join(vendor_dir, MANIFEST), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    return manifest, changes


def _pinned(manifest: dict | None) -> bool:
    return bool(manifest and manifest.get("pinned")) and manifest.get("ref") == vendor_pins.COMMIT


def verify(vendor_dir: str) -> tuple[str, list[str]]:
    """('verified' | 'MODIFIED' | 'UNVERIFIED' | 'no manifest' | 'empty', problem lines).

    verified: every pinned file matches its pinned hash. UNVERIFIED: the files match what was
    recorded, but were fetched from an unpinned source."""
    current = scan(vendor_dir)
    if not current:
        return "empty", []
    manifest = load(vendor_dir)
    if manifest is None:
        return "no manifest", ["Run setup_vendor.py to fetch the pinned tools and record their hashes."]
    want = manifest["files"]
    pinned = _pinned(manifest)
    problems = []
    for rel, digest in current.items():
        pin = vendor_pins.FILES.get(rel)
        if pinned and pin is not None:
            if digest != pin:
                problems.append(f"{rel}: CHANGED (does not match the pinned hash)")
        elif rel not in want:
            problems.append(f"{rel}: not in the manifest (added after setup)")
        elif want[rel] != digest:
            problems.append(f"{rel}: CHANGED since it was fetched")
    for rel in want:
        if rel not in current:
            problems.append(f"{rel}: missing")
    if any("CHANGED" in p or "added" in p for p in problems):
        return "MODIFIED", problems
    if not pinned:
        return "UNVERIFIED", problems + [
            f"Fetched from {manifest.get('source') or 'an unpinned source'}, not the pinned commit "
            f"{vendor_pins.COMMIT[:12]}: the hashes show the files haven't changed since, not that they're "
            "genuine. Run setup_vendor.py (no --ref) to install the pinned, verified tools."]
    return "verified", problems


def file_status(vendor_dir: str, path: str | None) -> str:
    """Short status for one located tool path: 'verified' (matches the pin), 'CHANGED',
    'UNVERIFIED' (unpinned fetch, unchanged since), 'unrecorded' or '' (outside vendor,
    e.g. REMnux's own copy on PATH)."""
    if not path:
        return ""
    try:
        rel = os.path.relpath(os.path.abspath(path), os.path.abspath(vendor_dir))
    except ValueError:      # different drive on Windows
        return ""
    if rel.startswith(".."):
        return ""
    manifest = load(vendor_dir)
    rel = rel.replace(os.sep, "/")
    if manifest is None or rel not in manifest["files"]:
        return "unrecorded"
    digest = _sha256(path)
    if _pinned(manifest) and rel in vendor_pins.FILES:
        return "verified" if digest == vendor_pins.FILES[rel] else "CHANGED"
    if manifest["files"][rel] != digest:
        return "CHANGED"
    return "UNVERIFIED"
