/**
 * EJII Real Host & Server Metrics Driver
 * Real hardware and OS metrics via Windows native CIM/WMI / PowerShell & POSIX interfaces.
 */

const os = require('os');
const { exec } = require('child_process');
const { IS_WINDOWS } = require('../config');

// In-memory telemetry cache to avoid excessive OS query load
let cachedHostMetrics = null;
let lastHostMetricsTime = 0;
const CACHE_TTL_MS = 30000;
let isRefreshingBackground = false;

let previousCpuTickSample = null;

function readAggregateCpuTicks(cpusInput = null) {
  const cpus = Array.isArray(cpusInput) && cpusInput.length > 0 ? cpusInput : os.cpus();
  let busy = 0;
  let idle = 0;
  for (const core of cpus || []) {
    const t = core.times || {};
    busy += (Number(t.user) || 0) + (Number(t.nice) || 0) + (Number(t.sys) || 0) + (Number(t.irq) || 0);
    idle += Number(t.idle) || 0;
  }
  return { busy, idle, total: busy + idle, timestampMs: Date.now() };
}

// Seed initial CPU tick snapshot at module load so subsequent calls have a true delta window
previousCpuTickSample = readAggregateCpuTicks();

function computePosixCpuLoadPercentage(cpus) {
  try {
    const current = readAggregateCpuTicks(cpus);
    if (previousCpuTickSample && current.total > previousCpuTickSample.total) {
      const busyDelta = Math.max(0, current.busy - previousCpuTickSample.busy);
      const totalDelta = Math.max(1, current.total - previousCpuTickSample.total);
      const pct = Number(Math.min(100, Math.max(0, (busyDelta / totalDelta) * 100)).toFixed(1));
      if (current.timestampMs - previousCpuTickSample.timestampMs >= 25) {
        previousCpuTickSample = current;
      }
      return pct;
    }
    previousCpuTickSample = current;
    if (current.total > 0) {
      return Number(Math.min(100, Math.max(0, (current.busy / current.total) * 100)).toFixed(1));
    }
  } catch (_) {}
  return 0;
}

async function sampleCpuTickDeltaPercentage(windowMs = 50) {
  const startSample = readAggregateCpuTicks();
  await new Promise((resolve) => setTimeout(resolve, Math.max(10, Math.min(250, windowMs))));
  const endSample = readAggregateCpuTicks();
  previousCpuTickSample = endSample;
  const totalDelta = endSample.total - startSample.total;
  if (totalDelta > 0) {
    const busyDelta = Math.max(0, endSample.busy - startSample.busy);
    return Number(Math.min(100, Math.max(0, (busyDelta / totalDelta) * 100)).toFixed(1));
  }
  return computePosixCpuLoadPercentage();
}

function createBaselineHostMetrics() {
  const cpus = os.cpus();
  const totalMemBytes = os.totalmem();
  const freeMemBytes = os.freemem();
  const usedMemBytes = totalMemBytes - freeMemBytes;
  const memUsedPct = parseFloat(((usedMemBytes / totalMemBytes) * 100).toFixed(1));
  const loadAvg = os.loadavg() || [0, 0, 0];
  const cpuUsagePct = !IS_WINDOWS ? computePosixCpuLoadPercentage(cpus) : null;
  const posixDisks = !IS_WINDOWS ? collectPosixDiskMetrics() : null;
  const posixAdapters = !IS_WINDOWS ? collectPosixNetworkAdapters() : [];

  return {
    hostname: os.hostname(),
    platform: os.platform(),
    release: os.release(),
    architecture: os.arch(),
    uptimeSeconds: Math.floor(os.uptime()),
    cpu: {
      model: cpus[0] ? cpus[0].model.trim() : 'Generic Processor',
      cores: cpus.length,
      speedMHz: cpus[0] ? cpus[0].speed : 0,
      usagePercentage: cpuUsagePct,
      loadPercentage: cpuUsagePct,
      loadAverage1m: !IS_WINDOWS ? Number((loadAvg[0] || 0).toFixed(2)) : null,
      loadAverage5m: !IS_WINDOWS ? Number((loadAvg[1] || 0).toFixed(2)) : null,
      loadAverage15m: !IS_WINDOWS ? Number((loadAvg[2] || 0).toFixed(2)) : null,
      measurementMethod: !IS_WINDOWS ? 'posix_cpu_tick_delta' : 'windows_cim_pending'
    },
    memory: {
      totalBytes: totalMemBytes,
      usedBytes: usedMemBytes,
      freeBytes: freeMemBytes,
      usedPercentage: memUsedPct,
      usedPercent: memUsedPct,
      totalGb: parseFloat((totalMemBytes / (1024 ** 3)).toFixed(2)),
      usedGb: parseFloat((usedMemBytes / (1024 ** 3)).toFixed(2)),
      freeGb: parseFloat((freeMemBytes / (1024 ** 3)).toFixed(2)),
      totalFormatted: `${(totalMemBytes / (1024 ** 3)).toFixed(2)} GB`,
      usedFormatted: `${(usedMemBytes / (1024 ** 3)).toFixed(2)} GB`,
      freeFormatted: `${(freeMemBytes / (1024 ** 3)).toFixed(2)} GB`
    },
    disks: posixDisks && posixDisks.length > 0 ? posixDisks : [],
    diskCollectionStatus: !IS_WINDOWS
      ? {
          available: Boolean(posixDisks && posixDisks.length > 0),
          status: posixDisks && posixDisks.length > 0 ? 'OBSERVED' : 'NO_DISKS_OBSERVED',
          collectionMethod: posixDisks?.[0]?.collectionMethod || 'posix_df_statfs'
        }
      : {
          available: false,
          status: 'PENDING_CIM_QUERY',
          collectionMethod: 'windows_cim_logicaldisk',
          error: null
        },
    networkAdapters: posixAdapters,
    osDetails: {
      caption: `${os.type()} ${os.release()}`,
      version: os.release()
    }
  };
}

function collectPosixDiskMetrics() {
  const disks = [];
  if (IS_WINDOWS) return disks;
  const fs = require('fs');
  const { execSync } = require('child_process');
  try {
    const dfOut = execSync('df -kP / 2>/dev/null || true', { encoding: 'utf8', timeout: 1500 });
    const lines = dfOut.trim().split(/\r?\n/);
    if (lines.length >= 2) {
      const parts = lines[lines.length - 1].trim().split(/\s+/);
      if (parts.length >= 6) {
        const fsName = parts[0];
        const totalKb = Number(parts[1]) || 0;
        const usedKb = Number(parts[2]) || 0;
        const availKb = Number(parts[3]) || 0;
        const mountPoint = parts[5] || '/';
        if (totalKb > 0) {
          const totalBytes = totalKb * 1024;
          const usedBytes = usedKb * 1024;
          const freeBytes = availKb * 1024;
          const usedPct = parseFloat(((usedBytes / totalBytes) * 100).toFixed(1));
          const totalGb = parseFloat((totalBytes / (1024 ** 3)).toFixed(1));
          const usedGb = parseFloat((usedBytes / (1024 ** 3)).toFixed(1));
          const freeGb = parseFloat((freeBytes / (1024 ** 3)).toFixed(1));
          disks.push({
            mount: mountPoint,
            drive: mountPoint,
            filesystem: fsName,
            volumeName: mountPoint === '/' ? 'Root Filesystem (/)' : `Filesystem (${mountPoint})`,
            totalBytes,
            usedBytes,
            freeBytes,
            usedPercentage: usedPct,
            usedPercent: usedPct,
            usedGb,
            totalGb,
            freeGb,
            totalFormatted: `${totalGb} GB`,
            usedFormatted: `${usedGb} GB`,
            freeFormatted: `${freeGb} GB`,
            collectionMethod: 'posix_df_kP'
          });
        }
      }
    }
  } catch (_) {}

  if (disks.length === 0 && typeof fs.statfsSync === 'function') {
    try {
      const st = fs.statfsSync('/');
      const bsize = Number(st.bsize) || 4096;
      const totalBytes = Number(st.blocks) * bsize;
      const freeBytes = Number(st.bavail || st.bfree) * bsize;
      const usedBytes = Math.max(0, totalBytes - freeBytes);
      if (totalBytes > 0) {
        const usedPct = parseFloat(((usedBytes / totalBytes) * 100).toFixed(1));
        const totalGb = parseFloat((totalBytes / (1024 ** 3)).toFixed(1));
        const usedGb = parseFloat((usedBytes / (1024 ** 3)).toFixed(1));
        const freeGb = parseFloat((freeBytes / (1024 ** 3)).toFixed(1));
        disks.push({
          mount: '/',
          drive: '/',
          filesystem: 'rootfs',
          volumeName: 'Root Filesystem (/)',
          totalBytes,
          usedBytes,
          freeBytes,
          usedPercentage: usedPct,
          usedPercent: usedPct,
          usedGb,
          totalGb,
          freeGb,
          totalFormatted: `${totalGb} GB`,
          usedFormatted: `${usedGb} GB`,
          freeFormatted: `${freeGb} GB`,
          collectionMethod: 'node_fs_statfs'
        });
      }
    } catch (_) {}
  }
  return disks;
}

function collectPosixNetworkAdapters() {
  const adapters = [];
  if (IS_WINDOWS) return adapters;
  try {
    const rawIfaces = os.networkInterfaces() || {};
    for (const [name, addrs] of Object.entries(rawIfaces)) {
      if (!Array.isArray(addrs) || addrs.length === 0) continue;
      const v4 = addrs.find((a) => a.family === 'IPv4' || a.family === 4);
      const mac = addrs.find((a) => a.mac && a.mac !== '00:00:00:00:00:00')?.mac || '00:00:00:00:00:00';
      adapters.push({
        name,
        status: 'Up',
        linkSpeed: v4?.internal ? 'Loopback' : 'Virtual/NIC',
        macAddress: mac,
        ipv4: v4?.address || null,
        collectionMethod: 'os_network_interfaces'
      });
    }
  } catch (_) {}
  return adapters;
}

// Seed baseline at startup
cachedHostMetrics = createBaselineHostMetrics();
lastHostMetricsTime = Date.now();

/**
 * Execute a PowerShell command and return parsed JSON
 * @param {string} command 
 */
function runPowerShellJson(command) {
  return new Promise((resolve, reject) => {
    const wrapped = `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "${command} | ConvertTo-Json -Depth 3 -Compress"`;
    exec(wrapped, { timeout: 8000, maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        return reject(new Error(`PowerShell execution failed: ${err.message}`));
      }
      try {
        const clean = stdout.trim();
        if (!clean) return resolve(null);
        const parsed = JSON.parse(clean);
        resolve(parsed);
      } catch (parseErr) {
        reject(new Error(`Failed to parse PowerShell JSON: ${parseErr.message}. Output was: ${stdout.slice(0, 200)}`));
      }
    });
  });
}

/**
 * Retrieve comprehensive, real-time host metrics
 * @param {boolean} forceRefresh 
 */
async function getHostMetrics(forceRefresh = false) {
  const now = Date.now();
  if (!forceRefresh && cachedHostMetrics) {
    if ((now - lastHostMetricsTime >= CACHE_TTL_MS) && !isRefreshingBackground) {
      isRefreshingBackground = true;
      getHostMetrics(true).catch(() => {}).finally(() => { isRefreshingBackground = false; });
    }
    return cachedHostMetrics;
  }

  const cpus = os.cpus();
  const totalMemBytes = os.totalmem();
  const freeMemBytes = os.freemem();
  const usedMemBytes = totalMemBytes - freeMemBytes;
  const memUsedPct = parseFloat(((usedMemBytes / totalMemBytes) * 100).toFixed(1));
  const loadAvg = os.loadavg() || [0, 0, 0];
  const posixDisks = !IS_WINDOWS ? collectPosixDiskMetrics() : null;
  const posixAdapters = !IS_WINDOWS ? collectPosixNetworkAdapters() : [];
  const posixCpuUsage = !IS_WINDOWS ? await sampleCpuTickDeltaPercentage(35) : null;

  let hostData = {
    hostname: os.hostname(),
    platform: os.platform(),
    release: os.release(),
    architecture: os.arch(),
    uptimeSeconds: Math.floor(os.uptime()),
    cpu: {
      model: cpus[0] ? cpus[0].model.trim() : 'Unknown CPU',
      cores: cpus.length,
      speedMHz: cpus[0] ? cpus[0].speed : 0,
      usagePercentage: posixCpuUsage,
      loadPercentage: posixCpuUsage,
      loadAverage1m: !IS_WINDOWS ? Number((loadAvg[0] || 0).toFixed(2)) : null,
      loadAverage5m: !IS_WINDOWS ? Number((loadAvg[1] || 0).toFixed(2)) : null,
      loadAverage15m: !IS_WINDOWS ? Number((loadAvg[2] || 0).toFixed(2)) : null,
      measurementMethod: !IS_WINDOWS ? 'posix_cpu_tick_delta' : 'windows_cim_processor'
    },
    memory: {
      totalBytes: totalMemBytes,
      usedBytes: usedMemBytes,
      freeBytes: freeMemBytes,
      usedPercentage: memUsedPct,
      usedPercent: memUsedPct,
      totalGb: parseFloat((totalMemBytes / (1024 ** 3)).toFixed(2)),
      usedGb: parseFloat((usedMemBytes / (1024 ** 3)).toFixed(2)),
      freeGb: parseFloat((freeMemBytes / (1024 ** 3)).toFixed(2)),
      totalFormatted: `${(totalMemBytes / (1024 ** 3)).toFixed(2)} GB`,
      usedFormatted: `${(usedMemBytes / (1024 ** 3)).toFixed(2)} GB`,
      freeFormatted: `${(freeMemBytes / (1024 ** 3)).toFixed(2)} GB`
    },
    disks: posixDisks && posixDisks.length > 0 ? posixDisks : [],
    diskCollectionStatus: !IS_WINDOWS
      ? {
          available: Boolean(posixDisks && posixDisks.length > 0),
          status: posixDisks && posixDisks.length > 0 ? 'OBSERVED' : 'NO_DISKS_OBSERVED',
          collectionMethod: posixDisks?.[0]?.collectionMethod || 'posix_df_statfs',
          error: null
        }
      : {
          available: false,
          status: 'COLLECTION_FAILED',
          collectionMethod: 'windows_cim_logicaldisk',
          error: 'Windows LogicalDisk CIM collection did not complete.'
        },
    networkAdapters: posixAdapters,
    osDetails: {
      caption: `${os.type()} ${os.release()}`,
      version: os.release()
    }
  };

  if (IS_WINDOWS) {
    try {
      // Gather Windows OS info, Processor Load, Disks, and Network Adapters in parallel
      const [osInfo, cpuInfo, diskInfo, netInfo] = await Promise.allSettled([
        runPowerShellJson('Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, FreePhysicalMemory, TotalVisibleMemorySize'),
        runPowerShellJson('Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average | Select-Object Average'),
        runPowerShellJson('Get-CimInstance Win32_LogicalDisk | Where-Object DriveType -eq 3 | Select-Object DeviceID, VolumeName, Size, FreeSpace'),
        runPowerShellJson('Get-NetAdapter | Select-Object Name, Status, LinkSpeed, MacAddress')
      ]);

      if (osInfo.status === 'fulfilled' && osInfo.value) {
        hostData.osDetails.caption = osInfo.value.Caption || hostData.osDetails.caption;
        hostData.osDetails.version = osInfo.value.Version || hostData.osDetails.version;
      }

      if (cpuInfo.status === 'fulfilled' && cpuInfo.value && cpuInfo.value.Average !== undefined) {
        const avgCpu = Math.round(cpuInfo.value.Average);
        hostData.cpu.usagePercentage = avgCpu;
        hostData.cpu.loadPercentage = avgCpu;
      }

      if (diskInfo.status === 'fulfilled' && diskInfo.value) {
        const rawDisks = Array.isArray(diskInfo.value) ? diskInfo.value : [diskInfo.value];
        hostData.disks = rawDisks.map((d) => {
          const size = d.Size || 0;
          const free = d.FreeSpace || 0;
          const used = size - free;
          const usedPct = size > 0 ? parseFloat(((used / size) * 100).toFixed(1)) : 0;
          const totalGbVal = parseFloat((size / (1024 ** 3)).toFixed(1));
          const usedGbVal = parseFloat((used / (1024 ** 3)).toFixed(1));
          const freeGbVal = parseFloat((free / (1024 ** 3)).toFixed(1));
          return {
            mount: d.DeviceID,
            drive: d.DeviceID,
            volumeName: d.VolumeName || 'Local Disk',
            totalBytes: size,
            usedBytes: used,
            freeBytes: free,
            usedPercentage: usedPct,
            usedPercent: usedPct,
            totalGb: totalGbVal,
            usedGb: usedGbVal,
            freeGb: freeGbVal,
            totalFormatted: `${totalGbVal} GB`,
            usedFormatted: `${usedGbVal} GB`,
            freeFormatted: `${freeGbVal} GB`,
            collectionMethod: 'windows_cim_logicaldisk'
          };
        });
        hostData.diskCollectionStatus = {
          available: hostData.disks.length > 0,
          status: hostData.disks.length > 0 ? 'OBSERVED' : 'NO_DISKS_OBSERVED',
          collectionMethod: 'windows_cim_logicaldisk',
          error: null
        };
      } else if (diskInfo.status === 'rejected') {
        hostData.disks = [];
        hostData.diskCollectionStatus = {
          available: false,
          status: 'COLLECTION_FAILED',
          collectionMethod: 'windows_cim_logicaldisk',
          error: diskInfo.reason?.message || 'Win32_LogicalDisk query failed'
        };
      }

      if (netInfo.status === 'fulfilled' && netInfo.value) {
        const rawNets = Array.isArray(netInfo.value) ? netInfo.value : [netInfo.value];
        hostData.networkAdapters = rawNets.map((n) => ({
          name: n.Name,
          status: n.Status,
          linkSpeed: n.LinkSpeed,
          macAddress: n.MacAddress
        }));
      }
    } catch (e) {
      hostData.disks = [];
      hostData.diskCollectionStatus = {
        available: false,
        status: 'COLLECTION_FAILED',
        collectionMethod: 'windows_cim_logicaldisk',
        error: e.message || 'Windows CIM collection failed'
      };
    }
  }

  cachedHostMetrics = hostData;
  lastHostMetricsTime = now;
  return hostData;
}

/**
 * Retrieve Windows / System Services
 * @param {string} filter 
 */
async function getServices(filter = '') {
  // Sanitize filter to strictly alphanumeric, dash, underscore, and space
  const sanitizedFilter = String(filter || '').replace(/[^a-zA-Z0-9_\-\s]/g, '').trim();

  if (!IS_WINDOWS) {
    try {
      const { execSync } = require('child_process');
      const out = execSync('systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null || true', { encoding: 'utf8' });
      const lines = out.trim().split('\n').filter(Boolean).slice(0, 50);
      if (lines.length > 0) {
        return lines.map(line => {
          const parts = line.trim().split(/\s+/);
          return {
            name: parts[0] || 'service',
            displayName: parts[0] || 'service',
            status: parts[3] === 'running' ? 'Running' : 'Stopped',
            startType: 'Systemd',
            entityType: 'SYSTEM_SERVICE',
            collectionMethod: 'systemd_service_manager'
          };
        });
      }
      // Container / non-systemd POSIX fallback using active processes — clearly labeled as RUNNING_PROCESS
      const psOut = execSync('ps -eo pid,comm --no-headers 2>/dev/null || true', { encoding: 'utf8' });
      const psLines = psOut.trim().split('\n').filter(Boolean).slice(0, 25);
      const services = psLines.map(line => {
        const parts = line.trim().split(/\s+/);
        const comm = parts[1] || 'process';
        return {
          name: comm,
          displayName: `${comm} (PID ${parts[0]} · Process Inventory Fallback)`,
          status: 'Running',
          startType: 'Process (Non-systemd)',
          entityType: 'RUNNING_PROCESS',
          collectionMethod: 'posix_process_table_fallback'
        };
      });
      if (sanitizedFilter) {
        const lower = sanitizedFilter.toLowerCase();
        return services.filter(s => s.name.toLowerCase().includes(lower) || s.displayName.toLowerCase().includes(lower));
      }
      return services;
    } catch (e) {
      return [];
    }
  }

  try {
    const script = sanitizedFilter
      ? `Get-Service | Where-Object { $_.Name -like "*${sanitizedFilter}*" -or $_.DisplayName -like "*${sanitizedFilter}*" } | Select-Object Name, DisplayName, Status, StartType -First 50`
      : 'Get-Service | Select-Object Name, DisplayName, Status, StartType -First 50';

    const res = await runPowerShellJson(script);
    if (!res) return [];
    const list = Array.isArray(res) ? res : [res];
    return list.map((s) => ({
      name: s.Name,
      displayName: s.DisplayName,
      status: s.Status === 4 || s.Status === 'Running' ? 'Running' : (s.Status === 1 || s.Status === 'Stopped' ? 'Stopped' : String(s.Status)),
      startType: String(s.StartType || 'Auto')
    }));
  } catch (err) {
    console.error('[getServices Error]:', err.message);
    return [];
  }
}

/**
 * Retrieve Top Running Processes
 * @param {number} limit 
 */
async function getProcesses(limit = 25) {
  const safeLimit = Math.min(Math.max(1, parseInt(limit, 10) || 25), 100);

  if (!IS_WINDOWS) {
    try {
      const { execSync } = require('child_process');
      const out = execSync(`ps -eo pid,comm,%mem,%cpu --sort=-%mem | head -n ${safeLimit + 1}`, { encoding: 'utf8' });
      const lines = out.trim().split('\n').slice(1);
      return lines.map(l => {
        const parts = l.trim().split(/\s+/);
        return {
          pid: parseInt(parts[0], 10),
          name: parts[1],
          workingSetMB: parseFloat(parts[2]) || 0,
          cpuSeconds: parseFloat(parts[3]) || 0
        };
      });
    } catch (e) {
      return [];
    }
  }

  try {
    const script = `Get-Process | Sort-Object -Descending WorkingSet | Select-Object -First ${safeLimit} Id, ProcessName, WorkingSet, CPU`;
    const res = await runPowerShellJson(script);
    if (!res) return [];
    const list = Array.isArray(res) ? res : [res];
    return list.map((p) => ({
      pid: p.Id,
      name: p.ProcessName,
      workingSetMB: parseFloat(((p.WorkingSet || 0) / (1024 * 1024)).toFixed(1)),
      cpuSeconds: p.CPU ? parseFloat(p.CPU.toFixed(1)) : 0
    }));
  } catch (err) {
    console.error('[getProcesses Error]:', err.message);
    return [];
  }
}

/**
 * Retrieve Windows Event Logs (Errors and Warnings)
 * @param {string} logName ('System', 'Application')
 * @param {number} maxEvents 
 */
async function getEventLogs(logName = 'System', maxEvents = 15) {
  if (!IS_WINDOWS) {
    return [];
  }

  // Whitelist or sanitize logName
  const ALLOWED_LOGS = ['System', 'Application', 'Security', 'Setup'];
  const sanitizedLogName = ALLOWED_LOGS.find(l => l.toLowerCase() === String(logName).toLowerCase()) || 'System';
  const safeMaxEvents = Math.min(Math.max(1, parseInt(maxEvents, 10) || 15), 50);

  try {
    const script = `Get-WinEvent -FilterHashtable @{LogName='${sanitizedLogName}'; Level=1,2,3} -MaxEvents ${safeMaxEvents} -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message`;
    const res = await runPowerShellJson(script);
    if (!res) return [];
    const list = Array.isArray(res) ? res : [res];
    return list.map((e) => ({
      timestamp: e.TimeCreated ? new Date(e.TimeCreated).toISOString() : new Date().toISOString(),
      id: e.Id,
      level: e.LevelDisplayName || 'Error',
      provider: e.ProviderName,
      message: (e.Message || '').replace(/[\r\n]+/g, ' ').slice(0, 300)
    }));
  } catch (err) {
    console.error('[getEventLogs Error]:', err.message);
    return [];
  }
}

/**
 * Obtain the verified default gateway from the actual OS routing table.
 * Clearly distinguishes ROUTE_FOUND, NO_DEFAULT_ROUTE_OBSERVED, and COLLECTOR_UNAVAILABLE.
 * Never guesses .1 from the local IP address.
 */
function getVerifiedDefaultGateway() {
  const fs = require('fs');
  const { execSync } = require('child_process');

  const isContainer = Boolean(
    fs.existsSync('/.dockerenv') ||
    fs.existsSync('/run/.containerenv') ||
    (fs.existsSync('/proc/1/cgroup') && fs.readFileSync('/proc/1/cgroup', 'utf8').includes('docker'))
  );
  const environmentScope = isContainer ? 'container_network_namespace' : 'host_network_namespace';

  if (IS_WINDOWS) {
    try {
      const out = execSync('route print 0.0.0.0', { timeout: 2500, encoding: 'utf8' });
      const lines = out.split(/\r?\n/);
      for (const line of lines) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 4 && parts[0] === '0.0.0.0' && parts[1] === '0.0.0.0') {
          const gw = parts[2];
          const iface = parts[3] || null;
          if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(gw) && gw !== '0.0.0.0') {
            return {
              verified: true,
              status: 'ROUTE_FOUND',
              gatewayIp: gw,
              interfaceName: iface,
              family: 'IPv4',
              isContainer: false,
              environmentScope: 'host_network_namespace',
              collectionMethod: 'windows_route_print'
            };
          }
        }
      }
      return {
        verified: false,
        status: 'NO_DEFAULT_ROUTE_OBSERVED',
        gatewayIp: null,
        interfaceName: null,
        family: null,
        isContainer: false,
        environmentScope: 'host_network_namespace',
        collectionMethod: 'windows_route_print',
        limitationReason: 'The Windows routing table was read successfully, but no 0.0.0.0/0 default gateway route was observed.'
      };
    } catch (_) {
      return {
        verified: false,
        status: 'COLLECTOR_UNAVAILABLE',
        gatewayIp: null,
        interfaceName: null,
        family: null,
        isContainer: false,
        environmentScope: 'host_network_namespace',
        collectionMethod: 'windows_route_table_unverified',
        limitationReason: 'Could not read a verified 0.0.0.0/0 default route from the Windows routing table.'
      };
    }
  }

  // 1. Linux /proc/net/route inspection (fastest, zero-subprocess kernel routing table with UG flag & metric priority)
  let procRouteRead = false;
  try {
    if (fs.existsSync('/proc/net/route')) {
      const routeContent = fs.readFileSync('/proc/net/route', 'utf8');
      procRouteRead = true;
      const lines = routeContent.trim().split('\n').slice(1);
      const validDefaultRoutes = [];
      for (const line of lines) {
        const cols = line.trim().split(/\s+/);
        // Iface(0) Destination(1) Gateway(2) Flags(3) RefCnt(4) Use(5) Metric(6) Mask(7)
        if (cols.length >= 4 && cols[1] === '00000000' && cols[2] !== '00000000') {
          const hexGw = cols[2];
          const flagsNum = parseInt(cols[3], 16) || 0;
          // RTF_UP = 0x0001, RTF_GATEWAY = 0x0002 -> require UG (0x0003) when flags are non-zero
          const hasUpGatewayFlags = flagsNum === 0 || (flagsNum & 0x0003) === 0x0003;
          const metric = cols.length >= 7 ? (parseInt(cols[6], 10) || 0) : 0;
          if (hasUpGatewayFlags && /^[0-9a-fA-F]{8}$/.test(hexGw)) {
            const octets = [
              parseInt(hexGw.slice(6, 8), 16),
              parseInt(hexGw.slice(4, 6), 16),
              parseInt(hexGw.slice(2, 4), 16),
              parseInt(hexGw.slice(0, 2), 16)
            ];
            const gwIp = octets.join('.');
            if (gwIp !== '0.0.0.0') {
              validDefaultRoutes.push({
                gatewayIp: gwIp,
                interfaceName: cols[0] || null,
                metric,
                flagsHex: cols[3]
              });
            }
          }
        }
      }
      if (validDefaultRoutes.length > 0) {
        validDefaultRoutes.sort((a, b) => a.metric - b.metric);
        const best = validDefaultRoutes[0];
        return {
          verified: true,
          status: 'ROUTE_FOUND',
          gatewayIp: best.gatewayIp,
          interfaceName: best.interfaceName,
          metric: best.metric,
          flagsHex: best.flagsHex,
          family: 'IPv4',
          isContainer,
          environmentScope,
          collectionMethod: '/proc/net/route'
        };
      }
    }
  } catch (_) {}

  // 2. Fallback to ip route show default / netstat -rn
  let ipRouteExecuted = false;
  try {
    const out = execSync('ip route show default 2>/dev/null || route -n 2>/dev/null || netstat -rn 2>/dev/null || true', {
      timeout: 2000,
      encoding: 'utf8'
    });
    ipRouteExecuted = true;
    const viaMatch = out.match(/default\s+via\s+((?:\d{1,3}\.){3}\d{1,3})(?:\s+dev\s+(\S+))?/i);
    if (viaMatch && viaMatch[1] && viaMatch[1] !== '0.0.0.0') {
      return {
        verified: true,
        status: 'ROUTE_FOUND',
        gatewayIp: viaMatch[1],
        interfaceName: viaMatch[2] || null,
        family: 'IPv4',
        isContainer,
        environmentScope,
        collectionMethod: 'ip_route_show_default'
      };
    }
    for (const line of out.split('\n')) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 2 && (parts[0] === '0.0.0.0' || parts[0] === 'default')) {
        const candidate = parts[1];
        if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(candidate) && candidate !== '0.0.0.0') {
          return {
            verified: true,
            status: 'ROUTE_FOUND',
            gatewayIp: candidate,
            interfaceName: parts[parts.length - 1] || null,
            family: 'IPv4',
            isContainer,
            environmentScope,
            collectionMethod: 'posix_route_table'
          };
        }
      }
    }
  } catch (_) {}

  // 3. Check for IPv6 default route (ip -6 route show default)
  try {
    const out6 = execSync('ip -6 route show default 2>/dev/null || true', {
      timeout: 2000,
      encoding: 'utf8'
    });
    const via6Match = out6.match(/default\s+via\s+([a-fA-F0-9:]+)(?:\s+dev\s+(\S+))?/i);
    if (via6Match && via6Match[1]) {
      return {
        verified: true,
        status: 'ROUTE_FOUND',
        gatewayIp: via6Match[1],
        interfaceName: via6Match[2] || null,
        family: 'IPv6',
        isContainer,
        environmentScope,
        collectionMethod: 'ip_-6_route_show_default'
      };
    }
  } catch (_) {}

  const readSucceeded = procRouteRead || ipRouteExecuted;
  return {
    verified: false,
    status: readSucceeded ? 'NO_DEFAULT_ROUTE_OBSERVED' : 'COLLECTOR_UNAVAILABLE',
    gatewayIp: null,
    interfaceName: null,
    family: null,
    isContainer,
    environmentScope,
    collectionMethod: readSucceeded ? (procRouteRead ? '/proc/net/route' : 'ip_route_show_default') : 'os_routing_table_unavailable',
    limitationReason: readSucceeded
      ? `Routing tables were inspected via ${procRouteRead ? '/proc/net/route' : 'ip route'}, but no 0.0.0.0/0 default route is present in this ${environmentScope}.`
      : 'Could not access the OS routing table in this execution environment.'
  };
}

/**
 * Classifies the 4 explicit runtime/diagnostic environment scopes required by Section 6.1:
 *   1. 'cloud_sandbox_runtime' (gVisor / Cloud Run / container vNIC with 169.254.x.x link-local or 169.254.169.254 metadata DNS)
 *   2. 'container_network_namespace' (Docker / Podman / OCI container with standard bridge/overlay networking)
 *   3. 'physical_workstation' (Bare-metal / native workstation or server OS)
 *   4. 'remote_diagnostic_target' (When evaluating an external remote hostname/IP)
 */
function classifyEnvironmentScope(options = {}) {
  if (options.isRemoteTarget) {
    return {
      environmentScopeCategory: 'remote_diagnostic_target',
      executionScope: 'remote_diagnostic_target',
      isContainer: false,
      isCloudSandbox: false
    };
  }
  const fs = require('fs');
  let isContainer = Boolean(
    fs.existsSync('/.dockerenv') ||
    fs.existsSync('/run/.containerenv') ||
    (fs.existsSync('/proc/1/cgroup') && fs.readFileSync('/proc/1/cgroup', 'utf8').includes('docker'))
  );
  let isGvisorOrCloudSandbox = false;
  try {
    if (fs.existsSync('/proc/version')) {
      const ver = fs.readFileSync('/proc/version', 'utf8');
      if (/gvisor|google|cloud/i.test(ver)) {
        isGvisorOrCloudSandbox = true;
      }
    }
  } catch (_) {}

  const primaryIpv4 = options.primaryIpv4 || null;
  const dnsServers = Array.isArray(options.dnsServers) ? options.dnsServers : [];
  if (
    (primaryIpv4 && String(primaryIpv4).startsWith('169.254.')) ||
    dnsServers.includes('169.254.169.254')
  ) {
    isGvisorOrCloudSandbox = true;
    isContainer = true;
  }

  const environmentScopeCategory = isGvisorOrCloudSandbox
    ? 'cloud_sandbox_runtime'
    : (isContainer ? 'container_network_namespace' : 'physical_workstation');

  return {
    environmentScopeCategory,
    executionScope: isContainer ? 'container_network_namespace' : 'host_network_namespace',
    isContainer,
    isCloudSandbox: isGvisorOrCloudSandbox
  };
}

/**
 * Discovers the local DHCP server identifier from actual operating system client leases/config.
 * Inspects Linux lease paths (/run/systemd/netif/leases/*, /var/lib/dhcp/*, NetworkManager) or Windows ipconfig.
 * Distinguishes DHCP_LEASE_OBSERVED, STATIC_CONFIG_VERIFIED, STATIC_CONTAINER_NAMESPACE, NO_LEASE_OBSERVED, and COLLECTOR_UNAVAILABLE.
 * Never guesses an IP, never confuses DHCP with gateway, and never probes fake TCP ports 67/68.
 */
function discoverLocalDhcpServer(options = {}) {
  const fs = require('fs');
  const { execSync } = require('child_process');

  const isContainer = Boolean(
    fs.existsSync('/.dockerenv') ||
    fs.existsSync('/run/.containerenv') ||
    (fs.existsSync('/proc/1/cgroup') && fs.readFileSync('/proc/1/cgroup', 'utf8').includes('docker'))
  );
  const executionScope = isContainer ? 'container_network_namespace' : 'host_network_namespace';

  // 1. Windows: ipconfig /all
  if (IS_WINDOWS) {
    try {
      const out = execSync('ipconfig /all', { timeout: 3000, encoding: 'utf8' });
      const dhcpMatch = out.match(/DHCP Server[\s\.:]+((?:\d{1,3}\.){3}\d{1,3})/i);
      const dhcpEnabledNo = /DHCP Enabled[\s\.:]+No/i.test(out);
      if (dhcpMatch && dhcpMatch[1] && dhcpMatch[1] !== '0.0.0.0') {
        return {
          observed: true,
          status: 'DHCP_LEASE_OBSERVED',
          addressingMode: 'DHCP_LEASE_OBSERVED',
          dhcpServerIp: dhcpMatch[1],
          interfaceName: null,
          leaseFile: null,
          collectionMethod: 'windows_ipconfig_all',
          isContainer: false,
          executionScope: 'host_network_namespace',
          limitationReason: null
        };
      }
      return {
        observed: false,
        status: dhcpEnabledNo ? 'STATIC_CONFIG_VERIFIED' : 'NO_LEASE_OBSERVED',
        addressingMode: dhcpEnabledNo ? 'STATIC_CONFIG_VERIFIED' : 'NO_LEASE_OBSERVED',
        dhcpServerIp: null,
        interfaceName: null,
        leaseFile: null,
        collectionMethod: 'windows_ipconfig_all',
        isContainer: false,
        executionScope: 'host_network_namespace',
        limitationReason: dhcpEnabledNo
          ? 'Windows ipconfig /all confirmed DHCP Enabled: No (static IP configuration verified).'
          : 'Windows ipconfig /all was executed, but no active DHCP Server line was reported.'
      };
    } catch (_) {
      return {
        observed: false,
        status: 'COLLECTOR_UNAVAILABLE',
        addressingMode: 'COLLECTOR_UNAVAILABLE',
        dhcpServerIp: null,
        interfaceName: null,
        leaseFile: null,
        collectionMethod: 'windows_ipconfig_unavailable',
        isContainer: false,
        executionScope: 'host_network_namespace',
        limitationReason: 'Could not run ipconfig /all on this host.'
      };
    }
  }

  // 2. Linux systemd-networkd leases: /run/systemd/netif/leases/*
  try {
    const systemdLeaseDir = '/run/systemd/netif/leases';
    if (fs.existsSync(systemdLeaseDir)) {
      const files = fs.readdirSync(systemdLeaseDir);
      for (const file of files) {
        const fullPath = `${systemdLeaseDir}/${file}`;
        const content = fs.readFileSync(fullPath, 'utf8');
        const match = content.match(/SERVER_ADDRESS=((?:\d{1,3}\.){3}\d{1,3})/);
        if (match && match[1] && match[1] !== '0.0.0.0') {
          return {
            observed: true,
            status: 'DHCP_LEASE_OBSERVED',
            addressingMode: 'DHCP_LEASE_OBSERVED',
            dhcpServerIp: match[1],
            interfaceName: file,
            leaseFile: fullPath,
            collectionMethod: 'systemd_netif_leases',
            isContainer,
            executionScope,
            limitationReason: null
          };
        }
      }
    }
  } catch (_) {}

  // 3. Linux ISC dhclient lease files: /var/lib/dhcp/* or /var/lib/dhclient/*
  const dhclientDirs = ['/var/lib/dhcp', '/var/lib/dhclient', '/var/run'];
  for (const dir of dhclientDirs) {
    try {
      if (fs.existsSync(dir)) {
        const files = fs.readdirSync(dir);
        for (const file of files) {
          if (file.includes('lease') || file.includes('dhclient')) {
            const fullPath = `${dir}/${file}`;
            const content = fs.readFileSync(fullPath, 'utf8');
            const match = content.match(/dhcp-server-identifier\s+((?:\d{1,3}\.){3}\d{1,3});/i);
            if (match && match[1] && match[1] !== '0.0.0.0') {
              return {
                observed: true,
                status: 'DHCP_LEASE_OBSERVED',
                addressingMode: 'DHCP_LEASE_OBSERVED',
                dhcpServerIp: match[1],
                interfaceName: null,
                leaseFile: fullPath,
                collectionMethod: 'dhclient_leases',
                isContainer,
                executionScope,
                limitationReason: null
              };
            }
          }
        }
      }
    } catch (_) {}
  }

  // 4. Linux NetworkManager leases: /var/lib/NetworkManager/*
  try {
    const nmDir = '/var/lib/NetworkManager';
    if (fs.existsSync(nmDir)) {
      const files = fs.readdirSync(nmDir);
      for (const file of files) {
        if (file.endsWith('.lease')) {
          const fullPath = `${nmDir}/${file}`;
          const content = fs.readFileSync(fullPath, 'utf8');
          const match = content.match(/dhcp_server_identifier=((?:\d{1,3}\.){3}\d{1,3})/i) ||
                        content.match(/SERVER_ADDRESS=((?:\d{1,3}\.){3}\d{1,3})/i);
          if (match && match[1] && match[1] !== '0.0.0.0') {
            return {
              observed: true,
              status: 'DHCP_LEASE_OBSERVED',
              addressingMode: 'DHCP_LEASE_OBSERVED',
              dhcpServerIp: match[1],
              interfaceName: file.replace('.lease', ''),
              leaseFile: fullPath,
              collectionMethod: 'networkmanager_leases',
              isContainer,
              executionScope,
              limitationReason: null
            };
          }
        }
      }
    }
  } catch (_) {}

  // 5. Check whether static configuration is explicitly verified in /etc/network/interfaces or /etc/netplan
  let staticVerified = false;
  let staticSource = null;
  try {
    if (fs.existsSync('/etc/network/interfaces')) {
      const ifaceCfg = fs.readFileSync('/etc/network/interfaces', 'utf8');
      if (/\binet\s+static\b/i.test(ifaceCfg)) {
        staticVerified = true;
        staticSource = '/etc/network/interfaces';
      }
    }
  } catch (_) {}

  const status = isContainer
    ? 'STATIC_CONTAINER_NAMESPACE'
    : (staticVerified ? 'STATIC_CONFIG_VERIFIED' : 'NO_LEASE_OBSERVED');
  const addressingMode = isContainer
    ? 'CONTAINER_MANAGED_NETWORKING'
    : (staticVerified ? 'STATIC_CONFIG_VERIFIED' : 'NO_LEASE_OBSERVED');

  return {
    observed: false,
    status,
    addressingMode,
    staticConfigVerified: staticVerified,
    dhcpServerIp: null,
    interfaceName: null,
    leaseFile: staticSource,
    collectionMethod: staticSource || 'os_dhcp_lease_files_searched',
    isContainer,
    executionScope,
    verificationCommands: {
      windows: 'ipconfig /all | findstr /i "DHCP"',
      linux: 'ip -d addr show; nmcli dev show | grep -i dhcp; networkctl status'
    },
    limitationReason: isContainer
      ? 'In this containerized/sandbox runtime environment, virtual network interfaces are pre-assigned by the container orchestration plane rather than a local DHCP client daemon (no lease files present in /run/systemd/netif/leases or /var/lib/dhcp). Note: absence of a local lease file indicates container-managed networking, not necessarily static configuration on your physical workstation.'
      : (staticVerified
          ? `Static IP configuration was explicitly verified in ${staticSource}.`
          : 'No active DHCP lease file was observed in /run/systemd/netif/leases, /var/lib/dhcp, or /var/lib/NetworkManager. Note that absence of a readable lease file alone does not prove static configuration without inspecting ip -d addr show (proto dhcp vs proto kernel) or NetworkManager state.')
  };
}

/**
 * Inspect local host network configuration (`os.networkInterfaces()`, DNS servers, and verified OS default gateway).
 * Clearly distinguishes EJII host/container/cloud-sandbox interface addresses from loopback addresses, public IPs, and client workstation IPs.
 * Never presents 127.0.0.1 as a discovered non-loopback primary interface address.
 */
function inspectLocalNetworkConfiguration(options = {}) {
  const fs = require('fs');
  const { discoverSystemDnsConfiguration } = require('./dns-diag');
  const rawIfaces = (
    typeof options.networkInterfacesFn === 'function'
      ? options.networkInterfacesFn()
      : (options.networkInterfaces && typeof options.networkInterfaces === 'object'
          ? options.networkInterfaces
          : os.networkInterfaces())
  ) || {};
  const interfaces = [];
  const primaryIpv4List = [];
  const primaryIpv6List = [];
  const loopbackIpv4List = [];
  const loopbackIpv6List = [];

  for (const [ifaceName, addrs] of Object.entries(rawIfaces)) {
    if (!Array.isArray(addrs)) continue;
    const ipv4 = [];
    const ipv6 = [];
    let mac = null;
    let internal = false;

    for (const addr of addrs) {
      if (addr.mac && addr.mac !== '00:00:00:00:00:00' && !mac) {
        mac = addr.mac;
      }
      const isLoopback = Boolean(addr.internal || String(addr.address || '').startsWith('127.') || addr.address === '::1');
      if (isLoopback) internal = true;
      const isV4 = addr.family === 'IPv4' || addr.family === 4;
      const isV6 = addr.family === 'IPv6' || addr.family === 6;
      if (isV4) {
        const entry = {
          interfaceName: ifaceName,
          address: addr.address,
          netmask: addr.netmask || null,
          cidr: addr.cidr || null,
          internal: isLoopback
        };
        ipv4.push(entry);
        if (!isLoopback) {
          primaryIpv4List.push(entry);
        } else {
          loopbackIpv4List.push(entry);
        }
      } else if (isV6) {
        const entry = {
          interfaceName: ifaceName,
          address: addr.address,
          netmask: addr.netmask || null,
          cidr: addr.cidr || null,
          scopeid: addr.scopeid,
          internal: isLoopback
        };
        ipv6.push(entry);
        if (!isLoopback) {
          primaryIpv6List.push(entry);
        } else {
          loopbackIpv6List.push(entry);
        }
      }
    }

    interfaces.push({
      interfaceName: ifaceName,
      status: (ipv4.length > 0 || ipv6.length > 0) ? 'UP' : 'DOWN',
      internal,
      macAddress: mac || (internal ? 'loopback (none)' : 'unavailable'),
      ipv4Addresses: ipv4,
      ipv6Addresses: ipv6
    });
  }

  const gatewayInfo = typeof options.gatewayFn === 'function' ? options.gatewayFn() : getVerifiedDefaultGateway();
  const dnsConfig = typeof options.dnsDiscoveryFn === 'function'
    ? options.dnsDiscoveryFn()
    : discoverSystemDnsConfiguration();
  const dnsServers = dnsConfig.observedServers || [];

  const hasNonLoopbackV4 = primaryIpv4List.length > 0;
  const hasLoopbackV4 = loopbackIpv4List.length > 0;
  const primaryIpv4 = hasNonLoopbackV4 ? primaryIpv4List[0].address : null;
  const primaryIpv4Status = hasNonLoopbackV4
    ? 'observed_non_loopback'
    : (hasLoopbackV4 ? 'loopback_only' : 'unavailable');
  const primaryIpv4Label = hasNonLoopbackV4
    ? `${primaryIpv4List[0].address} (${primaryIpv4List[0].interfaceName})`
    : (hasLoopbackV4
        ? `Unavailable (loopback only: ${loopbackIpv4List.map((l) => l.address).join(', ')})`
        : 'Unavailable (no IPv4 interface addresses observed)');

  const scopeInfo = classifyEnvironmentScope({
    primaryIpv4,
    dnsServers
  });
  const isContainer = scopeInfo.isContainer;

  const limitationReason = !hasNonLoopbackV4
    ? (hasLoopbackV4
        ? `No non-loopback IPv4 interface address was observed via os.networkInterfaces(); only loopback address(es) (${loopbackIpv4List.map((l) => l.address).join(', ')}) are present.`
        : 'No IPv4 addresses were observed on any local network interface via os.networkInterfaces().')
    : null;

  return {
    hostname: os.hostname(),
    platform: os.platform(),
    isContainer,
    isCloudSandbox: scopeInfo.isCloudSandbox,
    environmentScopeCategory: scopeInfo.environmentScopeCategory,
    executionScope: scopeInfo.executionScope,
    scopeDistinctionNote: scopeInfo.isCloudSandbox
      ? 'These network interfaces belong to the EJII cloud sandbox / container runtime (environmentScopeCategory: cloud_sandbox_runtime). Link-local 169.254.x.x addresses and 169.254.169.254 metadata resolvers reflect the isolated cloud container vNIC, NOT your physical workstation LAN or external public IP.'
      : (isContainer
          ? 'These network interfaces belong to the EJII server/container environment (environmentScopeCategory: container_network_namespace). EJII observes its own container network namespace, not a remote browser client workstation or external NAT public egress IP.'
          : 'These network interfaces belong to the local EJII host machine (environmentScopeCategory: physical_workstation). External internet services see your router/NAT public IP rather than private RFC1918 interface addresses.'),
    primaryIpv4,
    primaryIpv4Status,
    primaryIpv4Label,
    nonLoopbackIpv4: primaryIpv4List,
    nonLoopbackIpv6: primaryIpv6List,
    loopbackIpv4: loopbackIpv4List[0]?.address || null,
    loopbackIpv4Addresses: loopbackIpv4List,
    loopbackIpv6: loopbackIpv6List[0]?.address || null,
    loopbackIpv6Addresses: loopbackIpv6List,
    interfaces,
    dnsServers,
    dnsConfiguration: dnsConfig,
    defaultGateway: gatewayInfo,
    collectionMethod: 'os.networkInterfaces + ' + gatewayInfo.collectionMethod + ' + ' + dnsConfig.collectionMethod,
    limitationReason,
    observedAt: new Date().toISOString()
  };
}

module.exports = {
  getHostMetrics,
  createBaselineHostMetrics,
  sampleCpuTickDeltaPercentage,
  getServices,
  getProcesses,
  getEventLogs,
  getVerifiedDefaultGateway,
  discoverLocalDhcpServer,
  inspectLocalNetworkConfiguration,
  classifyEnvironmentScope
};


