@echo off
rem Narsaq Desktop launcher (portable exe — version-agnostic)
cd /d "%~dp0"
for %%f in (NarsaqDesktop-v*.exe) do set NARSAQ_EXE=%%f
if not defined NARSAQ_EXE (
  echo NarsaqDesktop exe not found in this folder.
  pause
  exit /b 1
)
echo Starting Narsaq Desktop at http://127.0.0.1:8787 ...
echo (the browser will open automatically; press Ctrl+C to stop)
"%NARSAQ_EXE%"
if errorlevel 1 (
  echo.
  echo Failed to start NarsaqDesktop.
  pause
)
