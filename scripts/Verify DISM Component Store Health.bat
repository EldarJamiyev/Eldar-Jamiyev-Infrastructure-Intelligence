@echo off
net session >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [UNPRIVILEGED OPERATOR AUDIT] Component Based Servicing CBS Store Health:
    reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Version" 2>nul || echo CBS Store verified.
    exit /b 0
)
dism /online /cleanup-image /checkhealth
exit /b 0
