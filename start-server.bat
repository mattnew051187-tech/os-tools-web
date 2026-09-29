@echo off
rem SOS Tools Web — server launcher
title SOS Tools Server
cd /d "%~dp0"
echo ============================================
echo   SOS Tools server running on port 3000
echo   Keep this window open. Close = stop server.
echo ============================================
node server.js
pause
