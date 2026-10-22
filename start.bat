@echo off
cd /d "%~dp0"
if exist "%~dp0..\nmap.exe" set "PATH=%~dp0..;%PATH%"
where nmap >nul 2>&1
if errorlevel 1 (
  echo Nmap was not found. Install it from https://nmap.org/download.html
  echo Then open a new terminal, or put nmap.exe somewhere on PATH.
  echo.
  pause
  exit /b 1
)
python main.py
echo.
echo Choose 7 in the menu when you want this window to close.
echo Press any key to close this window.
pause >nul
