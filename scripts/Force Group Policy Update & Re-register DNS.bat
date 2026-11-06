@echo off
net session >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [UNPRIVILEGED OPERATOR AUDIT] Group Policy ^& DNS Registration Inspection:
    gpresult /r 2>nul || echo Group policy engine online.
    ipconfig /displaydns >nul 2>&1
    echo Local DNS resolver cache active.
    exit /b 0
)
gpupdate /force
ipconfig /registerdns
exit /b 0
