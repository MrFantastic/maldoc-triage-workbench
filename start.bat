@echo off
rem Start Maldoc Triage Workbench. Drag a file onto this .bat to open it directly.
cd /d "%~dp0"
where pythonw >nul 2>nul
if errorlevel 1 (
  python run.py %*
) else (
  start "" pythonw run.py %*
)
