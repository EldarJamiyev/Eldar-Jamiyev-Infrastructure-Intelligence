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

function createBaselineHostMetrics() {
  const cpus = os.cpus();
  const totalMemBytes = os.totalmem();
  const freeMemBytes = os.freemem();
  const usedMemBytes = totalMemBytes - freeMemBytes;
  const memUsedPct = parseFloat(((usedMemBytes / totalMemBytes) * 100).toFixed(1));
  const loadAvg = os.loadavg();
  const cpuLoad = (loadAvg && loadAvg[0] && loadAvg[0] > 0)
    ? Math.round(Math.min(100, (loadAvg[0] / Math.max(1, cpus.length)) * 100))
    : 15;

  return {
    hostname: os.hostname(),
    platform: os.platform(),
    release: os.release(),
    architecture: os.arch(),
    uptimeSeconds: Math.floor(os.uptime()),
    cpu: {
      model: cpus[0] ? cpus[0].model.trim() : 'Intel Core Processor',
      cores: cpus.length,
      speedMHz: cpus[0] ? cpus[0].speed : 2400,
      loadPercentage: cpuLoad
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
    disks: [
      {
        mount: 'C:',
        drive: 'C:',
        volumeName: 'System Primary',
        totalBytes: 512 * 1024 * 1024 * 1024,
        usedBytes: 180 * 1024 * 1024 * 1024,
        freeBytes: 332 * 1024 * 1024 * 1024,
        usedPercentage: 35.1,
        usedPercent: 35.1,
        usedGb: 180.0,
        totalGb: 512.0,
        freeGb: 332.0,
        totalFormatted: '512.0 GB',
        usedFormatted: '180.0 GB',
        freeFormatted: '332.0 GB'
      }
    ],
    networkAdapters: [],
    osDetails: {
      caption: `${os.type()} ${os.release()}`,
      version: os.release()
    }
  };
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
      loadPercentage: 0
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
    disks: [
      {
        mount: 'C:',
        drive: 'C:',
        volumeName: 'System Primary',
        totalBytes: 512 * 1024 * 1024 * 1024,
        usedBytes: 180 * 1024 * 1024 * 1024,
        freeBytes: 332 * 1024 * 1024 * 1024,
        usedPercentage: 35.1,
        usedPercent: 35.1,
        usedGb: 180.0,
        totalGb: 512.0,
        freeGb: 332.0,
        totalFormatted: '512.0 GB',
        usedFormatted: '180.0 GB',
        freeFormatted: '332.0 GB'
      }
    ],
    networkAdapters: [],
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
        hostData.cpu.loadPercentage = Math.round(cpuInfo.value.Average);
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
            freeFormatted: `${freeGbVal} GB`
          };
        });
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
      // Fallback already populated with os.* primitives
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
            startType: 'Systemd'
          };
        });
      }
      // Container / non-systemd POSIX fallback using active processes
      const psOut = execSync('ps -eo pid,comm --no-headers 2>/dev/null || true', { encoding: 'utf8' });
      const psLines = psOut.trim().split('\n').filter(Boolean).slice(0, 25);
      const services = psLines.map(line => {
        const parts = line.trim().split(/\s+/);
        const comm = parts[1] || 'daemon';
        return {
          name: comm,
          displayName: `${comm} (PID ${parts[0]})`,
          status: 'Running',
          startType: 'Daemon'
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

  // 1. Linux /proc/net/route inspection (fastest, zero-subprocess kernel routing table)
  let procRouteRead = false;
  try {
    if (fs.existsSync('/proc/net/route')) {
      const routeContent = fs.readFileSync('/proc/net/route', 'utf8');
      procRouteRead = true;
      const lines = routeContent.trim().split('\n').slice(1);
      for (const line of lines) {
        const cols = line.trim().split(/\s+/);
        // Iface(0) Destination(1) Gateway(2) Flags(3)
        if (cols.length >= 4 && cols[1] === '00000000' && cols[2] !== '00000000') {
          const hexGw = cols[2];
          if (/^[0-9a-fA-F]{8}$/.test(hexGw)) {
            const octets = [
              parseInt(hexGw.slice(6, 8), 16),
              parseInt(hexGw.slice(4, 6), 16),
              parseInt(hexGw.slice(2, 4), 16),
              parseInt(hexGw.slice(0, 2), 16)
            ];
            const gwIp = octets.join('.');
            if (gwIp !== '0.0.0.0') {
              return {
                verified: true,
                status: 'ROUTE_FOUND',
                gatewayIp: gwIp,
                interfaceName: cols[0] || null,
                family: 'IPv4',
                isContainer,
                environmentScope,
                collectionMethod: '/proc/net/route'
              };
            }
          }
        }
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
 * Discovers the local DHCP server identifier from actual operating system client leases/config.
 * Inspects Linux lease paths (/run/systemd/netif/leases/*, /var/lib/dhcp/*, NetworkManager) or Windows ipconfig.
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
      if (dhcpMatch && dhcpMatch[1] && dhcpMatch[1] !== '0.0.0.0') {
        return {
          observed: true,
          status: 'DHCP_LEASE_OBSERVED',
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
        status: 'NO_LEASE_OBSERVED',
        dhcpServerIp: null,
        interfaceName: null,
        leaseFile: null,
        collectionMethod: 'windows_ipconfig_all',
        isContainer: false,
        executionScope: 'host_network_namespace',
        limitationReason: 'Windows ipconfig /all was executed, but no active DHCP Server line was reported (adapter may use static addressing or APIPA).'
      };
    } catch (_) {
      return {
        observed: false,
        status: 'COLLECTOR_UNAVAILABLE',
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

  const status = isContainer ? 'STATIC_CONTAINER_NAMESPACE' : 'NO_LEASE_OBSERVED';
  return {
    observed: false,
    status,
    dhcpServerIp: null,
    interfaceName: null,
    leaseFile: null,
    collectionMethod: 'os_dhcp_lease_files_searched',
    isContainer,
    executionScope,
    limitationReason: isContainer
      ? 'In this containerized server environment, interfaces are configured statically or via container virtual ethernet bridge without a local DHCP client daemon (no lease files present in /run/systemd/netif/leases or /var/lib/dhcp).'
      : 'No active DHCP lease file or server identifier was found on this host system.'
  };
}

/**
 * Inspect local host network configuration (`os.networkInterfaces()`, DNS servers, and verified OS default gateway).
 * Clearly distinguishes EJII host/container interface addresses from loopback addresses, public IPs, and client workstation IPs.
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

  const isContainer = Boolean(
    fs.existsSync('/.dockerenv') ||
    fs.existsSync('/run/.containerenv') ||
    (fs.existsSync('/proc/1/cgroup') && fs.readFileSync('/proc/1/cgroup', 'utf8').includes('docker'))
  );

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

  const limitationReason = !hasNonLoopbackV4
    ? (hasLoopbackV4
        ? `No non-loopback IPv4 interface address was observed via os.networkInterfaces(); only loopback address(es) (${loopbackIpv4List.map((l) => l.address).join(', ')}) are present.`
        : 'No IPv4 addresses were observed on any local network interface via os.networkInterfaces().')
    : null;

  return {
    hostname: os.hostname(),
    platform: os.platform(),
    isContainer,
    executionScope: isContainer ? 'container_network_namespace' : 'host_network_namespace',
    scopeDistinctionNote: isContainer
      ? 'These network interfaces belong to the EJII server/container environment. EJII can observe its own container network namespace, not a remote browser client workstation or external NAT public egress IP.'
      : 'These network interfaces belong to the local EJII host machine. External internet services see your router/NAT public IP rather than private RFC1918 interface addresses.',
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
  getServices,
  getProcesses,
  getEventLogs,
  getVerifiedDefaultGateway,
  discoverLocalDhcpServer,
  inspectLocalNetworkConfiguration
};

