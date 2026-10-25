@echo off
title CyberVision AI - Platform Launcher
echo ========================================================
echo        CYBERVISION AI - Platform Launcher (Windows)
echo ========================================================
echo.

cd /d "%~dp0"

if not exist .venv (
    echo [INFO] Creating Python virtual environment in .venv...
    python -m venv .venv
)

echo [INFO] Activating virtual environment...
call .venv\Scripts\activate.bat

echo [INFO] Installing required dependencies...
python -m pip install -r requirements.txt -q

echo.
echo ========================================================
echo [SUCCESS] CyberVision AI Server Ready!
echo Dashboard URL:      http://127.0.0.1:8000
echo API Documentation:  http://127.0.0.1:8000/docs
echo Health Check:       http://127.0.0.1:8000/health
echo ========================================================
echo.
python -m uvicorn backend.main:app --reload --port 8000 --host 127.0.0.1
pause
