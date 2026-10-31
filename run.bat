@echo off
REM ASK - one-command run for Windows. Double-click this file.
REM First run creates .venv and installs duckdb + networkx + pyyaml.
REM Then it prints the link to open in your browser.
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
  echo Sorry - Python 3 is not installed on this computer.
  echo Install Python 3 from python.org, tick "Add Python to PATH", then run this again.
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  echo First run: setting up ASK (this takes a minute, only once)...
  python -m venv .venv
  .venv\Scripts\pip install -q duckdb networkx pyyaml
)
echo.
echo ASK is starting. Open this link in your browser:
echo   http://127.0.0.1:8001/app
echo If that port is busy, ASK will print the next free port instead.
echo To stop it, close this window.
echo.
.venv\Scripts\python main.py serve --db ask.duckdb --port 8001
pause
