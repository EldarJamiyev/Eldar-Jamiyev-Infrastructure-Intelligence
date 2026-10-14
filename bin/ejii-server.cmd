@echo off
title EJII — Eldar Jamiyev's Infrastructure Intelligence
echo ====================================================================
echo   Starting EJII Enterprise Intelligence Platform
echo   Zero-Simulation IT Management ^& Observability Engine
echo ====================================================================
cd /d "%~dp0\.."
node src/server.js
pause
