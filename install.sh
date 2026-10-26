#!/usr/bin/env bash
# One-time setup for Maldoc Triage Workbench (standard edition) on Linux.
# Creates a private Python environment (.venv), installs the packages, and
# downloads Didier Stevens' tools into ./vendor. Needs internet access.
set -u
cd "$(dirname "$0")"

# A git clone has no EDITION file, so it would install the standard edition. On a REMnux VM,
# offer the REMnux edition instead (uses REMnux's own tools, downloads none).
#   ./install.sh --remnux | --standard     (or MTW_INSTALL_EDITION=remnux|standard) skips the question
if [ -f packaging/remnux/install.sh ]; then
  choice="${MTW_INSTALL_EDITION:-}"
  case "${1:-}" in --remnux) choice=remnux ;; --standard) choice=standard ;; esac
  if [ -z "$choice" ] && [ -f EDITION ]; then
    choice="$(tr -d '[:space:]' < EDITION)"
  elif [ -z "$choice" ] && { command -v remnux >/dev/null 2>&1 || [ -x /usr/local/bin/remnux ]; }; then
    echo "This looks like a REMnux VM. The REMnux edition uses the tools REMnux already has and"
    echo "downloads none; the standard edition downloads its own copies into ./vendor."
    if [ -t 0 ]; then
      read -r -p "Set up the REMnux edition? [Y/n] " answer
      case "$answer" in [nN]*) choice=standard ;; *) choice=remnux ;; esac
    else
      choice=remnux
    fi
  fi
  if [ "$choice" = remnux ]; then
    echo remnux > EDITION
    MTW_APP_DIR="$PWD" exec bash packaging/remnux/install.sh
  fi
  [ "$choice" = standard ] && echo standard > EDITION
fi

PY="${PYTHON:-python3}"
echo "============================================================"
echo " Maldoc Triage Workbench - setup (standard edition)"
echo "============================================================"
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "python3 was not found. Install Python 3.9 or newer (3.12+ recommended)."; exit 1
fi
if ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)'; then
  echo "Python 3.9 or newer is needed (found $("$PY" --version 2>&1))."; exit 1
fi

echo "[1/4] Creating the Python environment (.venv)..."
if ! "$PY" -m venv .venv; then
  echo "Could not create it. On Debian/Ubuntu: sudo apt install python3-venv"; exit 1
fi
VPY=.venv/bin/python
"$VPY" -m pip install --quiet --upgrade pip

echo "[2/4] Downloading the analysis tools and installing core packages..."
"$VPY" setup_vendor.py --pip || { echo "Setup failed (no internet, or github.com / pypi.org blocked?)"; exit 1; }
"$VPY" -m pip install -r requirements-safety.txt -c constraints.txt || echo "  (optional) PDF decryption / hardened XML packages could not be installed."

echo "[3/4] Installing peepdf (optional)..."
"$VPY" setup_vendor.py --peepdf || echo "  peepdf could not be installed. Everything else still works."

echo "[4/4] Installing the Excel 4.0 macro emulator (optional)..."
"$VPY" -m pip install -r requirements-xlm.txt -c constraints.txt || echo "  XLMMacroDeobfuscator could not be installed. Everything else still works."

if command -v ldconfig >/dev/null 2>&1 && ! ldconfig -p | grep -q libxcb-cursor; then
  echo "note: the GUI needs libxcb-cursor0. If it won't start: sudo apt install libxcb-cursor0"
fi
chmod +x start.sh 2>/dev/null
echo "Setup complete. Run ./start.sh  (or ./start.sh sample.pdf)"
