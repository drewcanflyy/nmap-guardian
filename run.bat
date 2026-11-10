@echo off
setlocal

cd /d "%~dp0"
title Nmap Guardian

echo [Nmap Guardian] Preparing the project...

where py >nul 2>&1
if %errorlevel% equ 0 (
    set "PYTHON_LAUNCHER=py"
) else (
    where python >nul 2>&1
    if errorlevel 1 (
        echo.
        echo ERROR: Python was not found. Install Python 3 and try again.
        pause
        exit /b 1
    )
    set "PYTHON_LAUNCHER=python"
)

if not exist ".venv\Scripts\python.exe" (
    echo [Nmap Guardian] Creating the local Python environment...
    %PYTHON_LAUNCHER% -m venv --system-site-packages .venv
    if errorlevel 1 goto :failed
)

echo [Nmap Guardian] Installing required packages...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements.txt
if errorlevel 1 goto :failed

where nmap >nul 2>&1
if errorlevel 1 (
    echo.
    echo ERROR: Nmap was not found in PATH.
    echo Install Nmap from https://nmap.org/download.html and try again.
    pause
    exit /b 1
)

echo.
echo [Nmap Guardian] Starting at http://127.0.0.1:5000
echo Press Ctrl+C in this window to stop the server.
start "" /b powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 2; Start-Process 'http://127.0.0.1:5000'"
".venv\Scripts\python.exe" app.py
exit /b %errorlevel%

:failed
echo.
echo ERROR: Project setup failed. Review the messages above.
pause
exit /b 1
