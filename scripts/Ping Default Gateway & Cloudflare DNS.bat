@echo off
set "GW="
for /f "tokens=3" %%g in ('route print 0.0.0.0 ^| findstr "\<0.0.0.0\>"') do (
    if not defined GW set "GW=%%g"
)
if not defined GW set "GW=192.168.31.1"
echo Pinging Active Default Gateway (%GW%) and Cloudflare DNS (1.1.1.1)...
ping -n 2 -w 1000 %GW%
ping -n 2 -w 1000 1.1.1.1
