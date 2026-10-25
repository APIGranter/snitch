@echo off
rem Build a single-file SNItch executable with PyInstaller (Windows).
setlocal
cd /d "%~dp0\.."

python -m pip install --upgrade pyinstaller || exit /b 1
python -m PyInstaller snitch.spec --noconfirm --clean || exit /b 1

echo.
echo Built: %cd%\dist\snitch.exe
echo Run:   dist\snitch.exe --help
endlocal
