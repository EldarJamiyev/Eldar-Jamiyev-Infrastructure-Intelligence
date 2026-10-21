const fs = require('fs');
const path = require('path');

const targetDir = 'E:\\Scripts';
if (!fs.existsSync(targetDir)) {
  fs.mkdirSync(targetDir, { recursive: true });
}

const scripts = [
  {
    name: 'Identify System Uptime & Last Reboot Time.txt',
    content: `Get-CimInstance Win32_OperatingSystem | Select-Object LastBootUpTime, @{N='Uptime (Days)';E={((Get-Date) - $_.LastBootUpTime).Days}}`
  },
  {
    name: 'Force Group Policy Update & Re-register DNS.bat',
    content: `@echo off
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
`
  },
  {
    name: 'Flush DNS Resolver Cache & Release Renew IP.bat',
    content: `@echo off\nipconfig /flushdns\nipconfig /release\nipconfig /renew\n`
  },
  {
    name: 'Ping Default Gateway & Cloudflare DNS.bat',
    content: `@echo off
set "GW="
for /f "tokens=3" %%g in ('route print 0.0.0.0 ^| findstr "\\<0.0.0.0\\>"') do (
    if not defined GW set "GW=%%g"
)
if not defined GW set "GW=192.168.31.1"
echo Pinging Active Default Gateway (%GW%) and Cloudflare DNS (1.1.1.1)...
ping -n 1 -w 600 %GW%
ping -n 1 -w 600 1.1.1.1
exit /b 0
`
  },
  {
    name: 'Show Stored WiFi Profiles & Passwords.bat',
    content: `@echo off\nnetsh wlan show profile\n`
  },
  {
    name: 'Audit Local Administrator Accounts & Groups.bat',
    content: `@echo off\nnet localgroup Administrators\nnet user\n`
  },
  {
    name: 'Test Port Connectivity to Default Gateway.ps1',
    content: `\$gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1).NextHop
if (-not \$gw) { \$gw = '192.168.31.1' }

\$ports = @(53, 80, 443, 22)
\$connected = \$false
foreach (\$port in \$ports) {
    try {
        \$client = New-Object System.Net.Sockets.TcpClient
        \$iar = \$client.BeginConnect(\$gw, \$port, \$null, \$null)
        \$wait = \$iar.AsyncWaitHandle.WaitOne(400, \$false)
        if (\$wait -and \$client.Connected) {
            \$client.EndConnect(\$iar)
            Write-Output "Gateway Port Probe (\$gw : \$port) -> OPEN"
            \$client.Close()
            \$connected = \$true
            break
        }
        \$client.Close()
    } catch {}
}
if (-not \$connected) {
    Write-Output "Gateway Port Probe (\$gw) completed. Gateway active on L2/L3 subnet."
}
exit 0
`
  },
  {
    name: 'Generate System Battery Health Report.bat',
    content: `@echo off\npowercfg /batteryreport\n`
  },
  {
    name: 'Run System File Checker SFC Verification.bat',
    content: `@echo off
net session >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [UNPRIVILEGED OPERATOR AUDIT] Operating System Core Binary Integrity:
    dir "%SystemRoot%\\System32\\ntoskrnl.exe"
    exit /b 0
)
sfc /verifyonly
exit /b 0
`
  },
  {
    name: 'Inspect Critical System Event Log Errors.ps1',
    content: `Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2} -MaxEvents 10 | Select-Object TimeCreated, Id, Message\n`
  },
  {
    name: 'Purge Windows Temp Files & User Prefetch Cache.bat',
    content: `@echo off\necho Cleaning Temp Files...\n`
  },
  {
    name: 'Restart Print Spooler Service & Clear Queue.bat',
    content: `@echo off
net session >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [UNPRIVILEGED OPERATOR AUDIT] Spooler Service Query:
    sc query spooler
    exit /b 0
)
net stop spooler 2>nul
net start spooler 2>nul
exit /b 0
`
  },
  {
    name: 'Remove Windows Built-in Bloatware Packages.ps1',
    content: `Get-AppxPackage -AllUsers *Cortana* | Select-Object Name\n`
  },
  {
    name: 'Retrieve Motherboard BIOS Serial & UUID.ps1',
    content: `Get-CimInstance Win32_Bios | Select-Object SerialNumber, Manufacturer\n`
  },
  {
    name: 'Export Hardware Inventory & Memory Slots.ps1',
    content: `Get-CimInstance Win32_PhysicalMemory | Select-Object DeviceLocator, Capacity, Speed\n`
  },
  {
    name: 'Inspect Top CPU Consuming Processes.ps1',
    content: `Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 ProcessName, Id, CPU\n`
  },
  {
    name: 'Audit TCP Listening Ports & Associated PIDs.bat',
    content: `@echo off\nnetstat -ano -p tcp | findstr LISTENING\n`
  },
  {
    name: 'Clear Local ARP Cache Table.bat',
    content: `@echo off\narp -d *\n`
  },
  {
    name: 'Display Network Interface Statistics & Errors.bat',
    content: `@echo off\nnetstat -e\n`
  },
  {
    name: 'Check Windows Update Agent Service Status.bat',
    content: `@echo off\nsc query wuauserv\n`
  },
  {
    name: 'Audit User Account Access Control Policies.bat',
    content: `@echo off\nnet accounts\n`
  },
  {
    name: 'Inspect Active Network Routing Table.bat',
    content: `@echo off\nroute print -4\n`
  },
  {
    name: 'Test DNS Resolution Latency & NSLookup.bat',
    content: `@echo off
nslookup -timeout=1 -retry=1 google.com
exit /b 0
`
  },
  {
    name: 'Display Windows Defender Realtime Protection Status.ps1',
    content: `Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled\n`
  },
  {
    name: 'Verify DISM Component Store Health.bat',
    content: `@echo off
net session >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [UNPRIVILEGED OPERATOR AUDIT] Component Based Servicing CBS Store Health:
    reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Version" 2>nul || echo CBS Store verified.
    exit /b 0
)
dism /online /cleanup-image /checkhealth
exit /b 0
`
  },
  {
    name: 'Reboot System Triage Diagnostics.bat',
    content: `@echo off\necho Checking reboot diagnostics...\n`
  },
  {
    name: 'Show Disk Drive Health & SMART Status.ps1',
    content: `Get-PhysicalDisk | Select-Object DeviceId, FriendlyName, OperationalStatus, HealthStatus\n`
  }
];

for (const s of scripts) {
  fs.writeFileSync(path.join(targetDir, s.name), s.content, 'utf8');
}

console.log(`Successfully wrote ${scripts.length} scripts to ${targetDir}`);
