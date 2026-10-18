@echo off
set "GW="
for /f "tokens=3" %%a in ('route print 0.0.0.0 ^| findstr "\<0.0.0.0\>"') do (
    if not defined GW set "GW=%%a"
)
if not defined GW (
    for /f "tokens=2 delims=:" %%g in ('ipconfig ^| findstr /i "Default Gateway"') do (
        if not defined GW (
            for /f "tokens=1" %%x in ("%%g") do set "GW=%%x"
        )
    )
)
if not defined GW set "GW=192.168.31.1"

echo ========================================================================
echo   EJI Network Diagnostics: Gateway ^& Cloudflare DNS Reachability
echo   Target Gateway: %GW%
echo ========================================================================
echo.
echo [1/2] Pinging Active Default Gateway (%GW%)...
ping -n 2 %GW%
echo.
echo [2/2] Pinging Cloudflare Primary DNS (1.1.1.1)...
ping -n 2 1.1.1.1
