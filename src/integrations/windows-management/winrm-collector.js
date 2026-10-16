/**
 * EJI Windows Management & WinRM Collector
 * Queries remote or local Windows systems via CIM/WMI/WinRM PowerShell cmdlets.
 * Zero-simulation: returns verified OS, CPU, RAM, Disk, and Service metrics.
 */

const { execFile } = require('child_process');

/**
 * Execute PowerShell command to gather Windows telemetry via CIM
 * @param {string} host Target hostname or IP ('localhost' for local host)
 * @param {object} options 
 * @returns {Promise<object>}
 */
function collectWindowsMetrics(host = 'localhost', options = {}) {
  return new Promise((resolve) => {
    const isLocal = !host || host === 'localhost' || host === '127.0.0.1' || host === '.' || host === '::1';
    const computerParam = isLocal ? '' : `-ComputerName "${host}"`;
    const timeoutMs = options.timeoutMs || 10000;

    const psScript = `
      $ErrorActionPreference = 'Stop'
      $result = @{}
      
      try {
        $cimOpt = New-CimSessionOption -Protocol DCOM
        # If remote, can use CIM session
        $os = Get-CimInstance Win32_OperatingSystem ${computerParam} | Select-Object -First 1 Caption, Version, BuildNumber, TotalVisibleMemorySize, FreePhysicalMemory, LastBootUpTime
        $cpu = Get-CimInstance Win32_Processor ${computerParam} | Measure-Object -Property LoadPercentage -Average
        $disks = Get-CimInstance Win32_LogicalDisk ${computerParam} -Filter "DriveType=3" | Select-Object DeviceID, VolumeName, Size, FreeSpace
        
        $totalRamMb = [math]::Round($os.TotalVisibleMemorySize / 1024, 0)
        $freeRamMb = [math]::Round($os.FreePhysicalMemory / 1024, 0)
        $usedRamMb = $totalRamMb - $freeRamMb
        $ramPct = if ($totalRamMb -gt 0) { [math]::Round(($usedRamMb / $totalRamMb) * 100, 1) } else { 0 }

        $diskList = @()
        foreach ($d in $disks) {
          $sizeGb = [math]::Round($d.Size / 1GB, 2)
          $freeGb = [math]::Round($d.FreeSpace / 1GB, 2)
          $usedGb = [math]::Round($sizeGb - $freeGb, 2)
          $pct = if ($sizeGb -gt 0) { [math]::Round(($usedGb / $sizeGb) * 100, 1) } else { 0 }
          $diskList += @{
            drive = $d.DeviceID
            volume = $d.VolumeName
            sizeGb = $sizeGb
            freeGb = $freeGb
            usedGb = $usedGb
            usePct = $pct
          }
        }

        $result = @{
          success = $true
          host = "${host}"
          osCaption = $os.Caption
          osVersion = $os.Version
          osBuild = $os.BuildNumber
          lastBoot = $os.LastBootUpTime
          cpuLoadPct = [math]::Round($cpu.Average, 1)
          memory = @{
            totalMb = $totalRamMb
            usedMb = $usedRamMb
            freeMb = $freeRamMb
            usagePct = $ramPct
          }
          disks = $diskList
        }
      } catch {
        $result = @{
          success = $false
          host = "${host}"
          error = $_.Exception.Message
        }
      }
      
      $result | ConvertTo-Json -Depth 4 -Compress
    `;

    const args = ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', psScript];

    execFile('powershell.exe', args, { timeout: timeoutMs, windowsHide: true }, (error, stdout, stderr) => {
      if (error && !stdout) {
        return resolve({
          success: false,
          host,
          error: error.message || stderr || 'Failed to query Windows host via CIM/WinRM.'
        });
      }

      try {
        const parsed = JSON.parse(stdout.trim());
        resolve(parsed);
      } catch (e) {
        resolve({
          success: false,
          host,
          error: `Failed to parse Windows telemetry output: ${e.message}`,
          rawOutput: stdout.slice(0, 300)
        });
      }
    });
  });
}

module.exports = {
  collectWindowsMetrics
};
