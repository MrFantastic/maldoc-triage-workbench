#!/usr/bin/env python3
"""Make the two distribution zips from this source tree (maintainer script, not shipped).

    python package.py [output folder]          (default: dist/)

  maldoc-triage-workbench-<version>-standard.zip
      Windows / Linux. Fetches its own tools: windows/install.bat or linux/install.sh,
      setup_vendor.py.
  maldoc-triage-workbench-<version>-remnux.zip
      REMnux VM. Uses the tools REMnux installs; no setup_vendor.py, no vendor folder,
      no windows/ or linux/ scripts: its own install.sh, start.sh and README at the top.
"""
from __future__ import annotations

import os
import re
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOP = "maldoc-triage-workbench"
SKIP_DIRS = {"__pycache__", ".git", ".github", ".vscode", "dist", "build", ".venv", "packaging", "docs"}
SKIP_FILES = {"package.py", "EDITION", ".gitignore", ".gitattributes", ".editorconfig", "pyproject.toml",
              "CONTRIBUTING.md"}
STANDARD_ONLY = {"setup_vendor.py", "build.py", "requirements-peepdf.txt", "requirements-xlm.txt",
                 "requirements.txt"}
STANDARD_ONLY_DIRS = ("windows/", "linux/")      # the standard edition's setup scripts, per OS
EXECUTABLE = {"install.sh", "start.sh", "run.py", "setup_vendor.py"}


def app_version() -> str:
    """The version in app/__init__.py (the single source of truth)."""
    with open(os.path.join(HERE, "app", "__init__.py"), encoding="utf-8") as fh:
        m = re.search(r'^__version__ = "([^"]+)"', fh.read(), re.M)
    return m.group(1) if m else "dev"


def source_files() -> list[str]:
    """Files to ship, relative to the source tree and sorted (no caches, repo-only files or downloaded tools)."""
    out = []
    for root, dirs, files in os.walk(HERE):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        rel_root = os.path.relpath(root, HERE)
        for name in sorted(files):
            if name.endswith((".pyc", ".pyo")) or name in SKIP_FILES:
                continue
            rel = os.path.normpath(os.path.join(rel_root, name)).replace(os.sep, "/")
            if rel.startswith("vendor/") and name != ".gitkeep":
                continue            # never ship downloaded tools; the standard edition fetches its own
            out.append(rel)
    return out


def _add(zf: zipfile.ZipFile, arcname: str, data: bytes) -> None:
    info = zipfile.ZipInfo(f"{TOP}/{arcname}", date_time=(2026, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    mode = 0o755 if os.path.basename(arcname) in EXECUTABLE else 0o644
    info.external_attr = (0o100000 | mode) << 16
    zf.writestr(info, data)


def _read(rel: str) -> bytes:
    with open(os.path.join(HERE, rel), "rb") as fh:
        return fh.read()


def build(edition: str, dest: str) -> list[str]:
    """Write one edition's zip to dest and return the names it contains."""
    names = []
    with zipfile.ZipFile(dest, "w") as zf:
        for rel in source_files():
            if edition == "remnux":
                if rel in STANDARD_ONLY or rel.startswith(("vendor/",) + STANDARD_ONLY_DIRS):
                    continue
                if rel == "README.md":
                    continue                    # replaced by the REMnux README below
            _add(zf, rel, _read(rel))
            names.append(rel)
        if edition == "remnux":
            for rel, src in (("install.sh", "packaging/remnux/install.sh"),
                             ("start.sh", "packaging/remnux/start.sh"),
                             ("README.md", "packaging/remnux/README.md")):
                _add(zf, rel, _read(src))
                names.append(rel)
        _add(zf, "EDITION", (edition + "\n").encode())
        names.append("EDITION")
    return names


def main() -> int:
    """Build the standard and REMnux zips into the folder named on the command line (default dist/)."""
    out = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "dist"))
    os.makedirs(out, exist_ok=True)
    version = app_version()
    for edition in ("standard", "remnux"):
        dest = os.path.join(out, f"{TOP}-{version}-{edition}.zip")
        names = build(edition, dest)
        print(f"{dest}  ({len(names)} files, {os.path.getsize(dest):,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
