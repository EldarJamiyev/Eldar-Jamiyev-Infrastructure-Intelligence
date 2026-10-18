@echo off
echo ===================================================
echo   WINDOWS TEMPORARY STORAGE & PREFETCH DIAGNOSTICS
echo ===================================================
echo [1/3] Enumerating User Temp Directory: %TEMP%
if exist "%TEMP%" (
    dir "%TEMP%" /s /a /w | findstr /i "File(s) bytes"
) else (
    echo Temp directory not found.
)
echo.
echo [2/3] Checking System Temp Storage...
if exist "%SystemRoot%\Temp" (
    dir "%SystemRoot%\Temp" /s /a /w | findstr /i "File(s) bytes"
) else (
    echo System temp directory not accessible.
)
echo.
echo [3/3] Inspecting Prefetch Readiness...
if exist "%SystemRoot%\Prefetch" (
    echo Prefetch directory accessible: %SystemRoot%\Prefetch
) else (
    echo Prefetch requires elevated administrative privileges.
)
echo.
echo [INFO] Temp cleanup simulation and inspection completed safely.
