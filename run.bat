@echo off
chcp 65001 >nul
cd /d "%~dp0"
python snitch.py %*
echo.
pause
