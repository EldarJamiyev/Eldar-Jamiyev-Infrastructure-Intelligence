@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

echo ========================================================================
echo   EJII - Eldar Jamiyev's Infrastructure Intelligence
echo   NOC Topology ^& Wire-Level Packet Dissection Workstation
echo   Unprivileged Operator Workstation (Zero Administrative Elevation)
echo ========================================================================
echo.

:: 1. Check Node.js
where node >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Node.js is not installed or not in PATH.
    echo Please install Node.js v18+ from https://nodejs.org/
    pause
    exit /b 1
)

for /f "tokens=*" %%v in ('node -v') do set NODE_VERSION=%%v
echo [OK] Detected Node.js: %NODE_VERSION%

:: 2. Check Dependencies
if not exist "node_modules\" (
    echo [INFO] Installing required dependencies...
    call npm install --no-audit --no-fund
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] npm install failed.
        pause
        exit /b 1
    )
) else (
    echo [OK] Node modules verified.
)

:: 3. Run Automated Verification Test Suite (Strictly Isolated Pre-Flight Environment)
echo.
echo [INFO] Running Zero-Simulation Automated Verification Test Suite...
set PREFLIGHT_DIR=%TEMP%\ejii_preflight_%RANDOM%
if not exist "%PREFLIGHT_DIR%" mkdir "%PREFLIGHT_DIR%" >nul 2>&1
set EJII_DATA_DIR=%PREFLIGHT_DIR%
node src/db/seed.js >nul 2>&1
set NODE_ENV=test
node tests/run-all-tests.js
set TEST_EXIT=%ERRORLEVEL%
rmdir /s /q "%PREFLIGHT_DIR%" >nul 2>&1
set EJII_DATA_DIR=
if %TEST_EXIT% neq 0 (
    echo [ERROR] Test verification failed with exit code %TEST_EXIT%. Halting startup.
    pause
    exit /b %TEST_EXIT%
)

:: 4. Start EJII NOC Workstation
echo.
echo ========================================================================
echo   Starting EJII NOC Workstation on http://localhost:8443
echo   Access Mode: Unprivileged NOC Operator Access
echo ========================================================================
echo.

if not defined NODE_ENV set NODE_ENV=development
if "%NODE_ENV%"=="test" set NODE_ENV=development

:: Terminate any stale process currently holding port 8443
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8443" ^| findstr "LISTENING"') do (
    echo Terminating stale process holding port 8443 (PID: %%a)...
    taskkill /F /PID %%a >nul 2>&1
)

start http://localhost:8443/
node src/server.js

pause

