@echo off
cls
title iLostmyNudes - Mise … jours de Windows
mode con cols=79 lines=30
:updwin
echo updw>C:\Users\iLostmyNudes\Files\stt.txt
cls
echo.===============================================================================
echo                             Mise … jour de Windows                             
echo.===============================================================================
echo.
Powershell.exe -executionpolicy remotesigned -File  C:\Users\iLostmyNudes\Files\AutoUpdate.ps1
pause
EXIT