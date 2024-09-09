@echo off
cls
title iLostmyNudes - Nettoyage des fichiers doublons
mode con cols=79 lines=30
:netdoubfil
echo netdoub>C:\GetMeFixed\Files\PS1\stt.txt
cls
echo.===============================================================================
echo                         Nettoyage des fichiers doublons                       
echo.===============================================================================
echo.
echo  Avertissement! Cette op‚ration n‚cessite un certain temps, qui se calcul en
echo                 fonction de la taille de fichiers, du nombre de fichiers et 
echo                 de la vitesse du disque sur lequel les fichiers se trouve.
echo.
Powershell.exe -executionpolicy ByPass -File  C:\GetMeFixed\Files\PS1\deletedupfl.ps1
echo.
cls
echo.===============================================================================
echo                         Nettoyage des fichiers doublons                       
echo.===============================================================================
echo.
echo Voulez-vous d‚truire le r‚pertoire C:\GMF?
echo.
echo                            [O]ui               [N]on
echo.===============================================================================
choice /C:ON /N /M "Tapez votre choix : "
if errorlevel 2 EXIT
if errorlevel 1 goto :nettempfld
goto :menuprinc

:nettempfld
echo delboud>C:\GetMeFixed\Files\PS1\stt.txt
cd C:\
del /s /f /q C:\GMF\*
rmdir /s C:\GMF
if exist "C:\GMF" (goto :nettempfld) else (EXIT)
goto :nettempfld