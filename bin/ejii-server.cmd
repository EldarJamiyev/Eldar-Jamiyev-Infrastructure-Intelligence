@echo off
chcp 65001 >nul
title EJII -- Eldar Jamiyev's Infrastructure Intelligence
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8443" ^| findstr "LISTENING"') do (
    taskkill /F /PID %%a >nul 2>&1
)
cd /d "%~dp0\.."
if exist "sync_now.bat" del /f /q "sync_now.bat" >nul 2>&1
if exist "update_reports.js" del /f /q "update_reports.js" >nul 2>&1
if exist "patch_*.js" del /f /q "patch_*.js" >nul 2>&1
node src/server.js %*
