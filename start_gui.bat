@echo off
rem Narsaq Desktop launcher
cd /d "%~dp0"
echo Starting Narsaq Desktop at http://127.0.0.1:8791 ...
echo (the browser will open automatically; press Ctrl+C to stop)
python narsaq_gui.py
if errorlevel 1 (
  echo.
  echo Failed to start. Make sure Python 3.10+ is installed and on PATH:
  echo   https://www.python.org/downloads/
  pause
)
