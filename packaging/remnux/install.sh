#!/usr/bin/env bash
# One-time setup for Maldoc Triage Workbench (REMnux edition).
# Uses the analysis tools REMnux already installs; downloads none. It only sets
# up a private Python environment (.venv) for the GUI. Python libraries REMnux
# provides are used from REMnux: oletools, msoffcrypto-tool, jsbeautifier and YARA from
# their own REMnux environments (/opt/...), which the app runs those tasks under;
# anything else REMnux's Python can import is shared into the .venv. Only what
# REMnux lacks is installed, at the versions in constraints.txt.
set -u
cd "${MTW_APP_DIR:-$(dirname "$0")}"   # MTW_APP_DIR: set when run from a git clone's linux/install.sh
PY="${PYTHON:-python3}"
echo "============================================================"
echo " Maldoc Triage Workbench - setup (REMnux edition)"
echo "============================================================"
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "python3 was not found."; exit 1
fi
if ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
  echo "Python 3.10 or newer is needed for the GUI (found $("$PY" --version 2>&1))."
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
PIPC=""; [ -f constraints.txt ] && PIPC="-c constraints.txt"   # the exact versions CI tests

# The interpreter of REMnux's environment for a library: the Python named on the #! line of
# one of its launchers (or REMnux's usual path), if it imports the modules and is 3.10+.
# Same rules as the app (app/adapters/toolenv.py), which looks again every time it starts.
remnux_python() {   # remnux_python "<modules,comma,separated>" <launcher-or-interpreter>...
  mods="$1"; shift
  for c in "$@"; do
    case "$c" in
      /*/python3) i="$c" ;;
      *) p="$(command -v "$c" 2>/dev/null)"; [ -z "$p" ] && [ -e "/usr/local/bin/$c" ] && p="/usr/local/bin/$c"
         [ -n "$p" ] || continue
         i="$(head -n1 "$(readlink -f "$p")" 2>/dev/null | sed -n 's/^#![[:space:]]*\([^[:space:]]*\).*/\1/p')" ;;
    esac
    case "$(basename "$i" 2>/dev/null)" in python|python3|python3.*) ;; *) continue ;; esac
    if [ -x "$i" ] && "$i" -I -c "import sys, $mods; sys.exit(0 if sys.version_info >= (3, 10) else 1)" 2>/dev/null; then
      echo "$i"; return 0
    fi
  done
  return 1
}

echo "[2/3] Using REMnux's Python libraries; installing only what REMnux lacks..."
"$VPY" -c 'import PySide6' 2>/dev/null && echo "  GUI (PySide6): already available" || \
  "$VPY" -m pip install --quiet "PySide6>=6.6" $PIPC || { echo "Could not install PySide6 (internet needed once)."; exit 1; }
# library|modules REMnux's copy must import|launchers or interpreters to try|pip fallback|what needs it
for item in "oletools|oletools.olevba,oletools.oleid,oletools.mraptor|olevba mraptor /opt/oletools/bin/python3|oletools>=0.60.2|REQUIRED for Office triage and macro analysis" \
            "msoffcrypto-tool|msoffcrypto|msoffcrypto-tool olevba /opt/msoffcrypto-tool/bin/python3 /opt/oletools/bin/python3|msoffcrypto-tool>=5.4|Office decryption" \
            "jsbeautifier|jsbeautifier|peepdf /opt/peepdf-3/bin/python3||nicer JavaScript formatting (optional)" \
            "yara-python|yara|oledump.py pdf-parser.py /opt/didier-stevens/bin/python3|yara-python>=4.3|YARA scanning"; do
  IFS='|' read -r name mods cands req what <<ITEM
$item
ITEM
  # shellcheck disable=SC2086
  if i="$(remnux_python "$mods" $cands)"; then
    echo "  $name: using REMnux's copy ($(dirname "$(dirname "$i")"))"
  elif [ -z "$req" ]; then
    echo "  $name: not found on this VM: $what unavailable"
  elif "$VPY" -m pip install --quiet "$req" $PIPC; then
    echo "  $name: REMnux's copy not found or not working; installed a copy for the app"
  else
    echo "  $name: could not be installed (internet needed once): $what will be unavailable"
  fi
done
# Used by the app's own Python (file-type detection, OLE metadata, PDF decryption, XML parsing).
# module:pip requirement:what needs it
for item in "olefile:olefile>=0.46:file-type detection and OLE metadata" \
            "pikepdf:pikepdf>=8:Decrypt PDF" \
            "defusedxml:defusedxml>=0.7:hardened XML parsing"; do
  mod="${item%%:*}"; rest="${item#*:}"; req="${rest%%:*}"; what="${rest#*:}"
  where="$("$VPY" -c "import sys, $mod; print('app' if $mod.__file__.startswith(sys.prefix) else 'remnux')" 2>/dev/null)"
  if [ "$where" = remnux ]; then
    echo "  $mod: using REMnux's copy"
  elif [ "$where" = app ]; then
    echo "  $mod: already installed for the app"
  elif "$VPY" -m pip install --quiet "$req" $PIPC; then
    echo "  $mod: installed (REMnux doesn't provide it)"
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
start=./start.sh; [ -f start.sh ] || start=linux/start.sh     # REMnux zip, or a git clone
chmod +x "$start" 2>/dev/null
echo "Setup complete. Run $start  (or $start sample.pdf)"
