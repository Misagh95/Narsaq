@echo off
rem Narsaq Desktop launcher (portable exe)
cd /d "%~dp0"
echo Starting Narsaq Desktop at http://127.0.0.1:8787 ...
echo (the browser will open automatically; press Ctrl+C to stop)
"NarsaqDesktop-v1.0.0.exe"
if errorlevel 1 (
  echo.
  echo Failed to start NarsaqDesktop.
  pause
)
