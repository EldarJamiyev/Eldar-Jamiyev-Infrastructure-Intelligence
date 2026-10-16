@echo off
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

:: 3. Run Automated Verification Test Suite
echo.
echo [INFO] Running Zero-Simulation Automated Verification Test Suite...
node tests/run-all-tests.js
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Test verification failed. Check logs above.
    pause
    exit /b 1
)

:: 4. Start EJII NOC Workstation
echo.
echo ========================================================================
echo   Starting EJII NOC Workstation on http://localhost:8443
echo   Access Mode: Unprivileged NOC Operator Access
echo ========================================================================
echo.

start http://localhost:8443/
node src/server.js

pause
