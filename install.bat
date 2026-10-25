@echo off
rem One-time setup for Maldoc Triage Workbench on Windows.
rem Creates a private Python environment (.venv), installs the packages, and
rem downloads Didier Stevens' tools into .\vendor. Needs internet access.
cd /d "%~dp0"
echo ============================================================
echo  Maldoc Triage Workbench - setup
echo ============================================================
where python >nul 2>nul
if errorlevel 1 (
  echo.
  echo Python was not found.
  echo Install Python from https://www.python.org/downloads/ ^(3.12 or newer
  echo recommended; 3.9 is the minimum^) and tick "Add python.exe to PATH" on the
  echo first installer screen. Then run install.bat again.
  pause
  exit /b 1
)
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)"
if errorlevel 1 (
  echo.
  echo Python 3.9 or newer is needed. Found:
  python --version
  pause
  exit /b 1
)
python --version
echo.
echo [1/5] Creating the Python environment ^(.venv^)...
python -m venv .venv
if errorlevel 1 goto failed
set "VPY=.venv\Scripts\python.exe"
"%VPY%" -m pip install --quiet --upgrade pip
echo.
echo [2/5] Downloading analysis tools and installing core packages...
"%VPY%" setup_vendor.py --pip
if errorlevel 1 goto failed
echo.
echo [3/5] Installing peepdf (optional)...
"%VPY%" setup_vendor.py --peepdf
if errorlevel 1 echo peepdf could not be installed. Everything else still works.
echo.
echo [4/5] Installing Excel 4.0 macro emulator (optional)...
"%VPY%" -m pip install -r requirements-xlm.txt
if errorlevel 1 echo XLMMacroDeobfuscator could not be installed. Everything else still works.
echo.
echo [5/5] Installing PDF decryption and hardened XML parsing (optional)...
"%VPY%" -m pip install -r requirements-safety.txt
if errorlevel 1 echo Some optional packages could not be installed. Everything else still works.
echo.
echo ============================================================
echo  Setup complete. Double-click start.bat to run the app.
echo ============================================================
pause
exit /b 0
:failed
echo.
echo Setup failed (see the messages above). Common causes: no internet access,
echo or a proxy blocking github.com / pypi.org.
pause
exit /b 1
