@echo off
chcp 65001 >nul
title EJII -- Eldar Jamiyev's Infrastructure Intelligence
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8443" ^| findstr "LISTENING"') do (
    taskkill /F /PID %%a >nul 2>&1
)
cd /d "%~dp0\.."
node src/server.js %*
