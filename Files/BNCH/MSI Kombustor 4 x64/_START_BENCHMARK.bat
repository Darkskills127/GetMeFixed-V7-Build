@echo off

echo MSI Kombustor 4
echo ---------------

rem --------------------------------------------------------------------------
echo Obtenir la résolution de l'écran de l'utilisateur...

rem Utiliser PowerShell pour obtenir la résolution de l'écran
for /f "usebackq tokens=2 delims=:, " %%x in (`wmic path Win32_VideoController get CurrentHorizontalResolution^, CurrentVerticalResolution /value ^| findstr "="`) do (
    if not defined width (
        set width=%%x
    ) else (
        set height=%%x
    )
)

echo -width=%width% -height=%height%
rem --------------------------------------------------------------------------

rem --------------------------------------------------------------------------
echo Détermination de la quantité de mémoire vidéo dédiée...

rem Utiliser PowerShell pour obtenir la mémoire vidéo dédiée
for /f "usebackq tokens=2 delims== " %%i in (`powershell -command "Get-WmiObject Win32_VideoController | Select-Object -ExpandProperty AdapterRAM"`) do (
    set /a video_memory_kb=%%i
    set /a video_memory_gb=video_memory_kb / 1024 / 1024 / 1024
)

echo Video Memory: %video_memory_gb% GB

rem Vérification si la mémoire vidéo dédiée a été correctement détectée
if "%video_memory_gb%"=="0" (
    echo Erreur: Impossible de détecter la mémoire vidéo dédiée.
    pause
    exit /b 1
)

rem --------------------------------------------------------------------------
echo Sélection du test en fonction de la mémoire vidéo dédiée...
pause

if %video_memory_gb% lss 3 (
    MSI-Kombustor-x64.exe -width=%width% -height=%height% -glfurmark1700mb -benchmark -fullscreen
) else if %video_memory_gb% lss 5 (
    MSI-Kombustor-x64.exe -width=%width% -height=%height% -glfurmark3200mb -benchmark -fullscreen
) else if %video_memory_gb% lss 6.5 (
    MSI-Kombustor-x64.exe -width=%width% -height=%height% -glfurmark5200mb -benchmark -fullscreen
) else (
    MSI-Kombustor-x64.exe -width=%width% -height=%height% -glfurmark6500mb -benchmark -fullscreen
)

rem --------------------------------------------------------------------------
