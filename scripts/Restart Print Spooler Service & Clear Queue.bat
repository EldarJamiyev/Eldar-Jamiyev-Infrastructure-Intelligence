@echo off
net session >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [UNPRIVILEGED OPERATOR AUDIT] Spooler Service Query:
    sc query spooler
    exit /b 0
)
net stop spooler 2>nul
net start spooler 2>nul
exit /b 0
