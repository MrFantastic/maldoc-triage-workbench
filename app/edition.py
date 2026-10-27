"""Which package this is.

  standard  Windows / Linux. Fetches its own copies of the analysis tools into
            vendor/ (install.bat / install.sh) and can update them.
  remnux    For a REMnux VM. Uses only the tools REMnux installs (PATH,
            /usr/local/bin); never downloads tools and ignores any vendor/ folder.

The package's EDITION file decides; MTW_EDITION overrides it (for testing).
"""
from __future__ import annotations

import os

APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EDITION_FILE = os.path.join(APP_ROOT, "EDITION")
EDITIONS = ("standard", "remnux")


def edition() -> str:
    """The running edition: MTW_EDITION if it names one, else the EDITION file, else "standard"."""
    env = os.environ.get("MTW_EDITION", "").strip().lower()
    if env in EDITIONS:
        return env
    try:
        with open(EDITION_FILE, encoding="utf-8") as fh:
            value = fh.read().strip().lower()
    except OSError:
        return "standard"
    return value if value in EDITIONS else "standard"


def is_remnux() -> bool:
    """True when running the REMnux edition."""
    return edition() == "remnux"


def label() -> str:
    """The edition's display name."""
    return "REMnux edition" if is_remnux() else "Standard edition"


_STANDARD_HINTS = {
    "tools": "run install.bat / install.sh (setup_vendor.py)",
    "peepdf": "optional: python setup_vendor.py --peepdf",
    "xlm": "optional: pip install -r requirements-xlm.txt",
    "oletools": "pip install oletools",
    "msoffcrypto": "pip install msoffcrypto-tool",
    "pikepdf": "pip install pikepdf",
    "yara": "pip install yara-python",
}
_REMNUX_HINTS = {
    "tools": "not found on this VM: check PATH, or sudo remnux upgrade",
    "peepdf": "not found on this VM: check PATH, or sudo remnux upgrade",
    "xlm": "not found on this VM (REMnux normally provides xlmdeobfuscator)",
    "oletools": "run ./install.sh",
    "msoffcrypto": "run ./install.sh",
    "pikepdf": "run ./install.sh",
    "yara": "run ./install.sh",
}


def hint(what: str) -> str:
    """How to get a missing tool or library, in this edition's terms."""
    return (_REMNUX_HINTS if is_remnux() else _STANDARD_HINTS).get(what, "")
