@echo off
:: Winsurf AI Security System - Build Script
:: Version: 1.0.0

setlocal enabledelayedexpansion

:: Configuration
set PRODUCT_NAME=Winsurf AI Security System
set VERSION=1.0.0
set SCRIPT_DIR=%~dp0
set BUILD_DIR=%SCRIPT_DIR%build
set SOURCE_DIR=%SCRIPT_DIR%src
set OUTPUT_DIR=%SCRIPT_DIR%build\release

:: Header
echo ==================================================
echo %PRODUCT_NAME% - Build Script
echo Version: %VERSION%
echo ==================================================
echo.

pause

:: Check for Visual Studio Build Tools
:check_build_tools
echo [INFO] Checking for Visual Studio Build Tools...

:: First try to find any Visual Studio installation
echo [INFO] Searching for Visual Studio installations...

:: Check common paths
for %%P in (
    C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvars64.bat
    C:\Program Files (x86)\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvars64.bat
    C:\Program Files\Microsoft Visual Studio\2026\Preview\VC\Auxiliary\Build\vcvars64.bat
    C:\Program Files (x86)\Microsoft Visual Studio\2026\Preview\VC\Auxiliary\Build\vcvars64.bat
    C:\Program Files\Microsoft Visual Studio\2026\Community\VC\Auxiliary\Build\vcvars64.bat
    C:\Program Files (x86)\Microsoft Visual Studio\2026\Community\VC\Auxiliary\Build\vcvars64.bat
    C:\Program Files\Microsoft Visual Studio\2026\Professional\VC\Auxiliary\Build\vcvars64.bat
    C:\Program Files (x86)\Microsoft Visual Studio\2026\Professional\VC\Auxiliary\Build\vcvars64.bat
    C:\Program Files\Microsoft Visual Studio\2026\Enterprise\VC\Auxiliary\Build\vcvars64.bat
    C:\Program Files (x86)\Microsoft Visual Studio\2026\Enterprise\VC\Auxiliary\Build\vcvars64.bat
    C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat
    C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat
    C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat
) do (
    if exist %%P (
        set VCVARSALL=%%P
        echo [INFO] Found Visual Studio at: %%P
        goto :setup_environment
    )
)

echo [INFO] Checking for Developer Command Prompt...
where devenv >nul 2>&1
if %errorLevel% == 0 (
    echo [INFO] Visual Studio found, trying to locate build tools...
    goto :find_vs_path
)

echo [ERROR] Visual Studio Build Tools not found
echo Please install Visual Studio 2022/2026 with C++ development tools
echo Or install Visual Studio Build Tools for Visual Studio 2022/2026
pause
exit /b 1

:find_vs_path
echo [INFO] Locating Visual Studio installation path...

:: Try to find devenv.exe location
for %%P in (
    "C:\Program Files\Microsoft Visual Studio\18\Insiders\Common7\IDE\devenv.exe"
    "C:\Program Files (x86)\Microsoft Visual Studio\18\Insiders\Common7\IDE\devenv.exe"
    "C:\Program Files\Microsoft Visual Studio\2026\Preview\Common7\IDE\devenv.exe"
    "C:\Program Files (x86)\Microsoft Visual Studio\2026\Preview\Common7\IDE\devenv.exe"
    "C:\Program Files\Microsoft Visual Studio\2026\Community\Common7\IDE\devenv.exe"
    "C:\Program Files (x86)\Microsoft Visual Studio\2026\Community\Common7\IDE\devenv.exe"
    "C:\Program Files\Microsoft Visual Studio\2026\Professional\Common7\IDE\devenv.exe"
    "C:\Program Files (x86)\Microsoft Visual Studio\2026\Professional\Common7\IDE\devenv.exe"
    "C:\Program Files\Microsoft Visual Studio\2026\Enterprise\Common7\IDE\devenv.exe"
    "C:\Program Files (x86)\Microsoft Visual Studio\2026\Enterprise\Common7\IDE\devenv.exe"
) do (
    if exist %%P (
        for %%F in (%%P) do set VS_PATH=%%~dpF
        set VCVARSALL=!VS_PATH!..\..\VC\Auxiliary\Build\vcvars64.bat
        if exist "!VCVARSALL!" (
            echo [INFO] Found Visual Studio at: !VS_PATH!
            echo [INFO] Build tools at: !VCVARSALL!
            goto :setup_environment
        )
    )
)

:check_vcvarsall
:: Try Visual Studio Insider paths
set VCVARSALL=C:\Program Files\Microsoft Visual Studio\2026\Preview\VC\Auxiliary\Build\vcvars64.bat
if not exist "%VCVARSALL%" (
    set VCVARSALL=C:\Program Files (x86)\Microsoft Visual Studio\2026\Preview\VC\Auxiliary\Build\vcvars64.bat
)

if exist "%VCVARSALL%" (
    echo [INFO] Visual Studio 2026 Insider build environment found
    goto :setup_environment
)

:: Try Visual Studio 2026 paths
set VCVARSALL=C:\Program Files\Microsoft Visual Studio\2026\Community\VC\Auxiliary\Build\vcvars64.bat
if not exist "%VCVARSALL%" (
    set VCVARSALL=C:\Program Files\Microsoft Visual Studio\2026\Professional\VC\Auxiliary\Build\vcvars64.bat
)
if not exist "%VCVARSALL%" (
    set VCVARSALL=C:\Program Files\Microsoft Visual Studio\2026\Enterprise\VC\Auxiliary\Build\vcvars64.bat
)

if exist "%VCVARSALL%" (
    echo [INFO] Visual Studio 2026 build environment found
    goto :setup_environment
)

:: Try x86 paths
set VCVARSALL=C:\Program Files (x86)\Microsoft Visual Studio\2026\Community\VC\Auxiliary\Build\vcvars64.bat
if not exist "%VCVARSALL%" (
    set VCVARSALL=C:\Program Files (x86)\Microsoft Visual Studio\2026\Professional\VC\Auxiliary\Build\vcvars64.bat
)
if not exist "%VCVARSALL%" (
    set VCVARSALL=C:\Program Files (x86)\Microsoft Visual Studio\2026\Enterprise\VC\Auxiliary\Build\vcvars64.bat
)

if exist "%VCVARSALL%" (
    echo [INFO] Visual Studio 2026 x86 build environment found
    goto :setup_environment
)

:: Try Visual Studio 2022 paths (fallback)
set VCVARSALL=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat
if not exist "%VCVARSALL%" (
    set VCVARSALL=C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat
)
if not exist "%VCVARSALL%" (
    set VCVARSALL=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat
)
if not exist "%VCVARSALL%" (
    set VCVARSALL=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat
)
if not exist "%VCVARSALL%" (
    echo [ERROR: VC++ build environment not found
    pause
    exit /b 1
)

:setup_environment
echo [INFO] Setting up build environment...
call "%VCVARSALL%"

:: Verify MSBuild is available
where msbuild >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR: MSBuild not found after setting up environment
    echo [INFO: Trying alternative MSBuild locations...
    
    :: Try alternative MSBuild locations
    for %%P in (
        C:\Program Files\Microsoft Visual Studio\18\Insiders\MSBuild\Current\Bin\amd64\MSBuild.exe
        C:\Program Files\Microsoft Visual Studio\18\Insiders\MSBuild\Current\Bin\MSBuild.exe
        C:\Program Files (x86)\Microsoft Visual Studio\18\Insiders\MSBuild\Current\Bin\amd64\MSBuild.exe
        C:\Program Files (x86)\Microsoft Visual Studio\18\Insiders\MSBuild\Current\Bin\MSBuild.exe
        C:\Program Files\Microsoft Visual Studio\2022\MSBuild\Current\Bin\MSBuild.exe
        C:\Program Files (x86)\Microsoft Visual Studio\2022\MSBuild\Current\Bin\MSBuild.exe
    ) do (
        if exist %%P (
            set MSBUILD_PATH=%%P
            echo [INFO] Found MSBuild at: %%P
            goto :create_directories
        )
    )
    
    echo [ERROR: MSBuild not found anywhere
    pause
    exit /b 1
)

:: Create output directories
:create_directories
echo [INFO] Creating output directories...
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

:: Build SecureCore.dll
:build_securecore
echo.
echo ==================================================
echo BUILDING SECURECORE.DLL
echo ==================================================
echo.

cd /d "%BUILD_DIR%"

echo [INFO] Building Release x64 configuration...
if defined MSBUILD_PATH (
    "%MSBUILD_PATH%" SecureCore.vcxproj /p:Configuration=Release /p:Platform=x64 /p:OutDir="%OUTPUT_DIR%\" /m
) else (
    msbuild SecureCore.vcxproj /p:Configuration=Release /p:Platform=x64 /p:OutDir="%OUTPUT_DIR%\" /m
)

if %errorLevel% neq 0 (
    echo [ERROR: Build failed
    pause
    exit /b 1
)

echo [INFO] Build completed successfully

:: Verify output
:verify_output
echo.
echo ==================================================
echo VERIFYING BUILD OUTPUT
echo ==================================================
echo.

set DLL_PATH=%OUTPUT_DIR%\SecureCore.dll
if exist "%DLL_PATH%" (
    echo [INFO] SecureCore.dll built successfully
    echo [INFO] Location: %DLL_PATH%
    
    :: Show file info
    for %%F in ("%DLL_PATH%") do (
        echo [INFO] Size: %%~zF bytes
        echo [INFO] Modified: %%~tF
    )
) else (
    echo [ERROR: SecureCore.dll not found
    pause
    exit /b 1
)

:: Copy to installation directory
:copy_to_install
echo.
echo ==================================================
echo COPYING TO INSTALLATION DIRECTORY
echo ==================================================
echo.

set INSTALL_DIR=C:\Program Files\Winsurf AI
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%" 2>nul

copy "%DLL_PATH%" "%INSTALL_DIR%\" >nul 2>&1
if %errorLevel% == 0 (
    echo [INFO] SecureCore.dll copied to installation directory
    echo [INFO] Location: %INSTALL_DIR%\SecureCore.dll
) else (
    echo [WARNING: Failed to copy to installation directory
    echo [WARNING: You may need to run as administrator
)

:: Copy policy files
:copy_policies
echo.
echo ==================================================
echo COPYING POLICY FILES
echo ==================================================
echo.

set POLICY_DIR=%INSTALL_DIR%\policies
if not exist "%POLICY_DIR%" mkdir "%POLICY_DIR%" 2>nul

copy "%SOURCE_DIR%\policies\security_policy.json" "%POLICY_DIR%\" >nul 2>&1
copy "%SOURCE_DIR%\policies\restrictions.json" "%POLICY_DIR%\" >nul 2>&1
copy "%SOURCE_DIR%\policies\license.rap" "%POLICY_DIR%\" >nul 2>&1

echo [INFO] Policy files copied to installation directory

:: Build summary
:build_summary
echo.
echo ==================================================
echo BUILD SUMMARY
echo ==================================================
echo.
echo Product: %PRODUCT_NAME%
echo Version: %VERSION%
echo Configuration: Release x64
echo.
echo Output Files:
echo   - %DLL_PATH%
echo   - %POLICY_DIR%\security_policy.json
echo   - %POLICY_DIR%\restrictions.json
echo   - %POLICY_DIR%\license.rap
echo.
echo Installation Files:
echo   - %INSTALL_DIR%\SecureCore.dll
echo   - %POLICY_DIR%\*.json
echo   - %POLICY_DIR%\*.rap
echo.
echo Build completed successfully!
echo.
echo Next steps:
echo 1. Run BATUR_INSTALL.bat as Administrator to install
echo 2. Review security policies before installation
echo 3. Accept license terms when prompted
echo.

pause
exit /b 0

:: Start build process
:main
call :check_build_tools
call :setup_environment
call :create_directories
call :build_securecore
call :verify_output
call :copy_to_install
call :copy_policies
call :build_summary

goto :eof

:: Start main execution
call :main
