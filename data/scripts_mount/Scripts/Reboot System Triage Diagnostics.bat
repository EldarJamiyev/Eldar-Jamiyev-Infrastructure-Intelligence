@echo off
echo ===================================================
echo   SYSTEM REBOOT & UPTIME DIAGNOSTIC TRIAGE
echo ===================================================
echo [1/3] System Information Summary:
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Boot Time" /C:"System Up Time"
echo.
echo [2/3] Checking Event Log for Unexpected Shutdown Events (Event ID 6008, 41):
wevtutil qe System "/q:*[System[(EventID=6008 or EventID=41)]]" /c:3 /f:text
echo.
echo [3/3] Pending Reboot Checks (Component-Based Servicing / Windows Update):
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" 2>nul
if %errorlevel% equ 0 (
    echo [STATUS] Component Based Servicing pending reboot flag detected.
) else (
    echo [STATUS] No CBS pending reboot flag.
)
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" 2>nul
if %errorlevel% equ 0 (
    echo [STATUS] Windows Update pending reboot flag detected.
) else (
    echo [STATUS] No Windows Update pending reboot flag.
)
echo.
echo [INFO] Reboot diagnostic triage completed safely (Dry-run mode, no reboot initiated).
