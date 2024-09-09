@echo off
cls
echo Preparing to repair Windows...
echo.
sfc /scannow
timeout /t 60
exit