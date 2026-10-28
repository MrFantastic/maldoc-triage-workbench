@echo off
rem Start Maldoc Triage Workbench. Drag a file onto this .bat to open it directly.
rem Uses the .venv made by install.bat; falls back to the Python on PATH.
rem It lives in the windows folder and works in the app folder above it.
cd /d "%~dp0.."
if exist ".venv\Scripts\pythonw.exe" (
  start "" ".venv\Scripts\pythonw.exe" run.py %*
  exit /b 0
)
where pythonw >nul 2>nul
if errorlevel 1 (
  python run.py %*
) else (
  start "" pythonw run.py %*
)
