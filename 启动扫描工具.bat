@echo off
title LAN IP Scanner
cd /d "%~dp0"

echo ================================================
echo   LAN IP Scanner - Starting...
echo ================================================

echo.
echo [1/5] Checking Python...
where python
if %errorlevel% neq 0 (
    echo [ERROR] Python not found. Please install Python 3.
    echo https://www.python.org/downloads/
    pause
    exit /b 1
)
echo [OK] Python found

echo.
echo [2/5] Checking pip...
pip --version
if %errorlevel% neq 0 (
    echo [ERROR] pip not found
    pause
    exit /b 1
)
echo [OK] pip available

if not exist ".deps_installed" (
    echo.
    echo [3/5] Installing Flask - first run only...
    pip install flask
    if %errorlevel% equ 0 (
        echo. > ".deps_installed"
        echo [OK] Flask installed
    ) else (
        echo [ERROR] Failed to install Flask.
        pause
        exit /b 1
    )
) else (
    echo.
    echo [3/5] Dependencies OK
)

echo.
echo [4/5] Checking project files...
if not exist "scanner.py" (
    echo [ERROR] scanner.py not found
    pause
    exit /b 1
)
if not exist "templates\index.html" (
    echo [ERROR] templates/index.html not found
    pause
    exit /b 1
)
echo [OK] All files present

echo.
echo [5/5] Starting scanner service...
start "ScannerServer" /MIN python scanner.py
ping 127.0.0.1 -n 3
start "" http://127.0.0.1:5000

echo.
echo ================================================
echo   Scanner is running!
echo   Open http://127.0.0.1:5000 in browser
echo   Close this window to stop the service
echo ================================================
pause
