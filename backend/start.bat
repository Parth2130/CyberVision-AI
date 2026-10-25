@echo off
title CyberVision AI Backend Server
echo ===================================================
echo           CyberVision AI - Backend Setup           
echo ===================================================
echo.

cd /d "%~dp0"

if not exist venv (
    echo [INFO] Creating Python virtual environment...
    python -m venv venv
)

echo [INFO] Activating virtual environment...
call venv\Scripts\activate.bat

echo [INFO] Installing required packages...
pip install -r requirements.txt -q

echo.
echo ===================================================
echo [SUCCESS] Backend ready!
echo URL: http://localhost:8000
echo Interactive API Documentation: http://localhost:8000/api/docs
echo ===================================================
echo.
uvicorn main:app --reload --port 8000 --host 0.0.0.0
pause
