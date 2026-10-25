#!/usr/bin/env python3
"""Build a standalone app with PyInstaller (run on each target OS).

    pip install pyinstaller
    python build.py

Output: dist/MaldocTriageWorkbench/ (a folder build starts faster and is less
likely to be flagged by antivirus heuristics than --onefile).
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# Optional libraries: bundled when installed, so the frozen worker can use them too.
OPTIONAL = ("msoffcrypto", "pikepdf", "pypdf", "defusedxml", "jsbeautifier", "XLMMacroDeobfuscator")


def _have(module: str) -> bool:
    try:
        __import__(module)
        return True
    except Exception:
        return False


def main() -> int:
    """Check the vendored tools, then run PyInstaller with the app's data files and hidden imports."""
    if not os.path.isfile(os.path.join(HERE, "vendor", "pdfid.py")):
        sys.exit("vendor/pdfid.py is missing. Run: python setup_vendor.py")
    if not os.path.isfile(os.path.join(HERE, "vendor", "manifest.json")):
        print("note: vendor/manifest.json is missing; recording tool hashes now")
        subprocess.call([sys.executable, os.path.join(HERE, "setup_vendor.py"), "--record"], cwd=HERE)

    cmd = [
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--windowed",
        "--name", "MaldocTriageWorkbench",
        "--add-data", f"{os.path.join(HERE, 'vendor')}{os.pathsep}vendor",
        # JS-engine blockers put first on PYTHONPATH for every tool the app runs
        "--add-data", f"{os.path.join(HERE, 'app', 'adapters', 'nojs')}{os.pathsep}app/adapters/nojs",
        "--collect-submodules", "oletools",
        "--collect-data", "oletools",
        "--hidden-import", "app.worker",
    ]
    for mod in OPTIONAL:
        if _have(mod):
            cmd += ["--collect-submodules", mod]
    cmd.append(os.path.join(HERE, "run.py"))
    print(" ".join(cmd))
    return subprocess.call(cmd, cwd=HERE)


if __name__ == "__main__":
    sys.exit(main())
