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
    content: `@echo off\ngpupdate /force\nipconfig /registerdns\n`
  },
  {
    name: 'Flush DNS Resolver Cache & Release Renew IP.bat',
    content: `@echo off\nipconfig /flushdns\nipconfig /release\nipconfig /renew\n`
  },
  {
    name: 'Ping Default Gateway & Cloudflare DNS.bat',
    content: `@echo off\nping -n 2 10.168.195.1\nping -n 2 1.1.1.1\n`
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
    content: `Test-NetConnection -ComputerName 10.168.195.1 -Port 80\n`
  },
  {
    name: 'Generate System Battery Health Report.bat',
    content: `@echo off\npowercfg /batteryreport\n`
  },
  {
    name: 'Run System File Checker SFC Verification.bat',
    content: `@echo off\nsfc /verifyonly\n`
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
    content: `@echo off\nnet stop spooler 2>nul\nnet start spooler 2>nul\n`
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
    content: `@echo off\nnslookup google.com 8.8.8.8\n`
  },
  {
    name: 'Display Windows Defender Realtime Protection Status.ps1',
    content: `Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled\n`
  },
  {
    name: 'Verify DISM Component Store Health.bat',
    content: `@echo off\ndism /online /cleanup-image /checkhealth\n`
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
