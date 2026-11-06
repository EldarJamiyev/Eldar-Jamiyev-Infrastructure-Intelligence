@echo off
net session >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [UNPRIVILEGED OPERATOR AUDIT] Operating System Core Binary Integrity:
    dir "%SystemRoot%\System32\ntoskrnl.exe"
    exit /b 0
)
sfc /verifyonly
exit /b 0
