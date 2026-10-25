@echo off
rem One-time setup for Maldoc Triage Workbench on Windows.
cd /d "%~dp0"
echo ============================================================
echo  Maldoc Triage Workbench - setup
echo ============================================================
where python >nul 2>nul
if errorlevel 1 (
  echo.
  echo Python was not found.
  echo Install Python 3.12 or newer from https://www.python.org/downloads/
  echo and tick "Add python.exe to PATH" on the first installer screen.
  echo Then run install.bat again.
  pause
  exit /b 1
)
python --version
echo.
echo [1/4] Downloading analysis tools and installing core packages...
python setup_vendor.py --pip
if errorlevel 1 goto failed
echo.
echo [2/4] Installing peepdf (optional)...
python setup_vendor.py --peepdf
if errorlevel 1 echo peepdf could not be installed. Everything else still works.
echo.
echo [3/4] Installing Excel 4.0 macro emulator (optional)...
python -m pip install -r requirements-xlm.txt
if errorlevel 1 echo XLMMacroDeobfuscator could not be installed. Everything else still works.
echo.
echo [4/4] Installing PDF decryption and hardened XML parsing (optional)...
python -m pip install -r requirements-safety.txt
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
