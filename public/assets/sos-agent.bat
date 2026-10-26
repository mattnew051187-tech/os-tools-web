@echo off
title SOS Tools - USB Bench Agent
echo ========================================================
echo   Starting SOS Tools USB Bench Agent (Port 7890)...
echo ========================================================
python sos-bench-agent.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Python not found in PATH or error occurred.
    echo Please install Python 3 or run via python3 sos-bench-agent.py
    pause
)
