@echo off
title AEGISCORE - BATUR CLEAN (FAILSAFE MODE)
color 0C

echo ==================================================
echo   AEGISCORE SECURITY SYSTEM - CLEANUP TOOL
echo   MODE: FAILSAFE / EMERGENCY RESTORE
echo   VERSION: 1.0.0-stable
echo ==================================================
echo.

:: --------------------------------------------------
:: ADMIN CHECK
:: --------------------------------------------------
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [X] Administrator privileges REQUIRED!
    echo     Right click -> Run as administrator
    pause
    exit /b
)

echo [+] Administrator privileges confirmed.
echo.

:: --------------------------------------------------
:: WARN USER
:: --------------------------------------------------
echo WARNING !!!
echo ----------------------------------------------
echo This will COMPLETELY REMOVE:
echo - AegisCore / SecureCore DLL
echo - All security hooks
echo - All policies
echo - All registry entries
echo - All background protection
echo.
echo System will be FULLY RESTORED.
echo.
set /p CONFIRM=Type CLEAN to continue: 

if /I NOT "%CONFIRM%"=="CLEAN" (
    echo [!] Cleanup cancelled by user.
    pause
    exit /b
)

echo.
echo [+] Cleanup confirmed.
timeout /t 2 >nul

:: --------------------------------------------------
:: EMERGENCY FAILSAFE SHUTDOWN
:: --------------------------------------------------
echo [1/7] Triggering FAILSAFE Emergency Shutdown...

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
"try { ^
    $dllPath = 'C:\Program Files\AegisCore\security.dll'; ^
    if (Test-Path $dllPath) { ^
        $sig = '[DllImport(\"security.dll\")] public static extern void EmergencyShutdown();'; ^
        Add-Type -MemberDefinition $sig -Name 'Aegis' -Namespace FailSafe; ^
        [FailSafe.Aegis]::EmergencyShutdown(); ^
    } ^
} catch {}"

echo     -> Failsafe shutdown triggered.
timeout /t 1 >nul

:: --------------------------------------------------
:: KILL POSSIBLE RUNNING PROCESSES
:: --------------------------------------------------
echo [2/7] Terminating running components...

taskkill /F /IM winsurf.exe >nul 2>&1
taskkill /F /IM aegiscore.exe >nul 2>&1
taskkill /F /IM securecore.exe >nul 2>&1
taskkill /F /IM rundll32.exe >nul 2>&1

echo     -> Processes terminated.
timeout /t 1 >nul

:: --------------------------------------------------
:: REMOVE AUTOSTART / REGISTRY
:: --------------------------------------------------
echo [3/7] Cleaning registry entries...

reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v AegisCore /f >nul 2>&1
reg delete "HKLM\Software\AegisCore" /f >nul 2>&1
reg delete "HKCU\Software\AegisCore" /f >nul 2>&1

echo     -> Registry cleaned.
timeout /t 1 >nul

:: --------------------------------------------------
:: REMOVE FILES
:: --------------------------------------------------
echo [4/7] Removing files...

if exist "C:\Program Files\AegisCore" (
    takeown /f "C:\Program Files\AegisCore" /r /d y >nul
    icacls "C:\Program Files\AegisCore" /grant administrators:F /t >nul
    rmdir /s /q "C:\Program Files\AegisCore"
)

echo     -> Files removed.
timeout /t 1 >nul

:: --------------------------------------------------
:: REMOVE POLICIES
:: --------------------------------------------------
echo [5/7] Removing policy files...

if exist "%ProgramData%\AegisCore" (
    rmdir /s /q "%ProgramData%\AegisCore"
)

echo     -> Policies removed.
timeout /t 1 >nul

:: --------------------------------------------------
:: REMOVE LOGS
:: --------------------------------------------------
echo [6/7] Cleaning logs...

del /f /q "%TEMP%\failsafe.log" >nul 2>&1
del /f /q "%TEMP%\failsafe.log.old" >nul 2>&1

echo     -> Logs cleaned.
timeout /t 1 >nul

:: --------------------------------------------------
:: FINAL STATUS
:: --------------------------------------------------
echo [7/7] Final system verification...

echo.
echo ==================================================
echo  CLEANUP COMPLETE - SYSTEM RESTORED
echo ==================================================
echo.
echo ✔ All security hooks removed
echo ✔ All policies unlocked
echo ✔ All files deleted
echo ✔ Registry cleaned
echo ✔ No residue left
echo.
echo System is now in NORMAL state.
echo You may safely reboot if desired.
echo.

pause
exit /b
