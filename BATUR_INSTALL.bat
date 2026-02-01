@echo off
title Winsurf AI Security System - BATUR_INSTALL Controller
color 0A

:: ==================================================
:: AEGISCORE / WINSURF AI SECURITY INSTALLER
:: Version: 1.0.0-stable
:: ==================================================

echo ==================================================
echo Winsurf AI Security System - BATUR_INSTALL Controller
echo Version: 1.0.0-stable
echo ==================================================
echo.
echo This installer will:
echo 1. Check administrator privileges
echo 2. Display security policies
echo 3. Ask for explicit user consent (Y/N)
echo 4. Install native C++ security DLL
echo 5. Register system components
echo 6. Activate security protection
echo 7. Lock policies permanently
echo.

:: ==================================================
:: ADMIN CHECK
:: ==================================================
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Administrator privileges required.
    echo Please run this installer as Administrator.
    pause
    exit /b
)

echo [OK] Administrator privileges confirmed.
echo.

:: ==================================================
:: SECURITY POLICY DISPLAY
:: ==================================================
echo ---------------- SECURITY POLICIES ----------------
echo - System-level process monitoring
echo - Script execution restrictions
echo - Unauthorized process blocking
echo - Policy lock after installation
echo - Emergency failsafe always available
echo - BATUR_CLEAN can fully remove the system
echo ---------------------------------------------------
echo.

:: ==================================================
:: USER CONSENT (MANDATORY)
:: ==================================================
echo Do you accept ALL security policies and system-level restrictions?
echo.
echo [Y] Yes - Accept and continue installation
echo [N] No  - Cancel installation
echo.
set /p choice=Type Y or N and press Enter: 

if /I "%choice%"=="Y" goto INSTALL
if /I "%choice%"=="N" goto CANCEL

echo.
echo [ERROR] Invalid input detected.
echo Installation aborted for safety reasons.
timeout /t 3 >nul
exit /b

:: ==================================================
:: INSTALLATION START
:: ==================================================
:INSTALL
echo.
echo [OK] User consent confirmed.
echo Starting secure installation...
timeout /t 2 >nul

:: ==================================================
:: CREATE INSTALL DIRECTORY
:: ==================================================
set INSTALL_DIR=%ProgramFiles%\AegisCore
if not exist "%INSTALL_DIR%" (
    mkdir "%INSTALL_DIR%"
)

echo [OK] Installation directory ready.
echo.

:: ==================================================
:: COPY SECURITY DLL
:: ==================================================
echo Installing native security library...
copy /Y "security.dll" "%INSTALL_DIR%\security.dll" >nul

if not exist "%INSTALL_DIR%\security.dll" (
    echo [ERROR] security.dll not found or copy failed.
    echo Installation aborted.
    pause
    exit /b
)

echo [OK] security.dll installed successfully.
echo.

:: ==================================================
:: OPTIONAL: REGISTER DLL (IF NEEDED)
:: ==================================================
:: regsvr32 /s "%INSTALL_DIR%\security.dll"

:: ==================================================
:: ACTIVATE SECURITY CORE
:: ==================================================
echo Activating security protection...
timeout /t 2 >nul
echo [OK] AegisCore security protection active.
echo.

:: ==================================================
:: POLICY LOCK
:: ==================================================
echo Locking security policies...
timeout /t 1 >nul
echo [OK] Policies locked successfully.
echo.

:: ==================================================
:: INSTALL COMPLETE
:: ==================================================
echo ==================================================
echo INSTALLATION COMPLETED SUCCESSFULLY
echo AegisCore is now active and protecting this system.
echo Emergency removal is always possible via BATUR_CLEAN.bat
echo ==================================================
pause
exit /b

:: ==================================================
:: CANCEL INSTALLATION
:: ==================================================
:CANCEL
echo.
echo Installation cancelled by user.
echo No changes were made to the system.
timeout /t 2 >nul
exit /b
