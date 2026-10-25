#!/usr/bin/env bash
# One-time setup for Maldoc Triage Workbench (REMnux edition).
# Uses the analysis tools REMnux already installs; downloads none. It only sets
# up a private Python environment (.venv) for the GUI, reusing REMnux's Python
# libraries (oletools, msoffcrypto, ...) when they're importable.
set -u
cd "${MTW_APP_DIR:-$(dirname "$0")}"   # MTW_APP_DIR: set when run from a git clone's install.sh
PY="${PYTHON:-python3}"
echo "============================================================"
echo " Maldoc Triage Workbench - setup (REMnux edition)"
echo "============================================================"
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "python3 was not found."; exit 1
fi
if ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)'; then
  echo "Python 3.9 or newer is needed for the GUI (found $("$PY" --version 2>&1))."
  echo "Install a newer Python (e.g. sudo apt install python3.10 python3.10-venv) and run:"
  echo "  PYTHON=python3.10 ./install.sh"
  exit 1
fi
if ! command -v pdfid.py >/dev/null 2>&1 && [ ! -e /usr/local/bin/pdfid.py ] && ! command -v remnux >/dev/null 2>&1; then
  echo "warning: this doesn't look like a REMnux VM (no pdfid.py on PATH). The REMnux edition"
  echo "         never downloads tools; on other machines use the standard edition."
fi

echo "[1/3] Creating the Python environment (.venv, sharing REMnux's Python packages)..."
if ! "$PY" -m venv --system-site-packages .venv; then
  echo "Could not create it: sudo apt install python3-venv"; exit 1
fi
VPY=.venv/bin/python

echo "[2/3] Installing what REMnux doesn't already provide..."
"$VPY" -c 'import PySide6' 2>/dev/null && echo "  GUI (PySide6): already available" || \
  "$VPY" -m pip install --quiet "PySide6>=6.6" || { echo "Could not install PySide6 (internet needed once)."; exit 1; }
# module:pip requirement:what needs it (oletools is required: Office triage and macro analysis use it)
for item in "oletools:oletools>=0.60.2:REQUIRED for Office triage and macro analysis" \
            "msoffcrypto:msoffcrypto-tool>=5.4:Office decryption" \
            "pikepdf:pikepdf>=8:Decrypt PDF" \
            "defusedxml:defusedxml>=0.7:hardened XML parsing"; do
  mod="${item%%:*}"; rest="${item#*:}"; req="${rest%%:*}"; what="${rest#*:}"
  if "$VPY" -c "import $mod" 2>/dev/null; then
    echo "  $mod: using REMnux's copy"
  elif "$VPY" -m pip install --quiet "$req"; then
    echo "  $mod: installed"
  else
    echo "  $mod: could not be installed (internet needed once): $what will be unavailable"
  fi
done

echo "[3/3] Checking the REMnux tools the app will use..."
missing=0
for t in pdfid.py pdf-parser.py oledump.py zipdump.py rtfdump.py peepdf xlmdeobfuscator olevba oleobj rtfobj msodde; do
  p="$(command -v "$t" 2>/dev/null)"
  [ -z "$p" ] && [ -e "/usr/local/bin/$t" ] && p="/usr/local/bin/$t"
  if [ -n "$p" ]; then printf "  %-16s %s\n" "$t" "$p"; else printf "  %-16s NOT FOUND\n" "$t"; missing=1; fi
done
[ "$missing" = 1 ] && echo "  Some tools are missing: the matching tabs will say so. 'sudo remnux upgrade' may add them."

if command -v ldconfig >/dev/null 2>&1 && ! ldconfig -p | grep -q libxcb-cursor; then
  echo "note: under an X11 session the GUI needs libxcb-cursor0. If it won't start: sudo apt install libxcb-cursor0"
fi
chmod +x start.sh 2>/dev/null
echo "Setup complete. Run ./start.sh  (or ./start.sh sample.pdf)"
