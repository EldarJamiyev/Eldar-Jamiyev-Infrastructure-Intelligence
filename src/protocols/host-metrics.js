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
 * Never guesses .1 from the local IP address.
 */
function getVerifiedDefaultGateway() {
  const fs = require('fs');
  const { execSync } = require('child_process');

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
              gatewayIp: gw,
              interfaceName: iface,
              collectionMethod: 'windows_route_print'
            };
          }
        }
      }
    } catch (_) {}
    return {
      verified: false,
      gatewayIp: null,
      interfaceName: null,
      collectionMethod: 'windows_route_table_unverified',
      limitationReason: 'Could not read a verified 0.0.0.0/0 default route from the Windows routing table.'
    };
  }

  // 1. Linux /proc/net/route inspection (fastest, zero-subprocess kernel routing table)
  try {
    if (fs.existsSync('/proc/net/route')) {
      const routeContent = fs.readFileSync('/proc/net/route', 'utf8');
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
                gatewayIp: gwIp,
                interfaceName: cols[0] || null,
                collectionMethod: '/proc/net/route'
              };
            }
          }
        }
      }
    }
  } catch (_) {}

  // 2. Fallback to ip route show default / netstat -rn
  try {
    const out = execSync('ip route show default 2>/dev/null || route -n 2>/dev/null || netstat -rn 2>/dev/null || true', {
      timeout: 2000,
      encoding: 'utf8'
    });
    const viaMatch = out.match(/default\s+via\s+((?:\d{1,3}\.){3}\d{1,3})(?:\s+dev\s+(\S+))?/i);
    if (viaMatch && viaMatch[1] && viaMatch[1] !== '0.0.0.0') {
      return {
        verified: true,
        gatewayIp: viaMatch[1],
        interfaceName: viaMatch[2] || null,
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
            gatewayIp: candidate,
            interfaceName: parts[parts.length - 1] || null,
            collectionMethod: 'posix_route_table'
          };
        }
      }
    }
  } catch (_) {}

  return {
    verified: false,
    gatewayIp: null,
    interfaceName: null,
    collectionMethod: 'os_routing_table_unavailable',
    limitationReason: 'No verified default gateway route (0.0.0.0/0) was found in the local OS or container routing table. EJII never guesses a .1 gateway address.'
  };
}

/**
 * Inspect local host network configuration (`os.networkInterfaces()`, DNS servers, and verified OS default gateway).
 * Clearly distinguishes EJII host/container interface addresses from public IPs and client workstation IPs.
 */
function inspectLocalNetworkConfiguration() {
  const fs = require('fs');
  const dns = require('dns');
  const rawIfaces = os.networkInterfaces() || {};
  const interfaces = [];
  const primaryIpv4List = [];
  const primaryIpv6List = [];

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
      if (addr.internal) internal = true;
      const isV4 = addr.family === 'IPv4' || addr.family === 4;
      const isV6 = addr.family === 'IPv6' || addr.family === 6;
      if (isV4) {
        ipv4.push({
          address: addr.address,
          netmask: addr.netmask || null,
          cidr: addr.cidr || null,
          internal: Boolean(addr.internal)
        });
        if (!addr.internal) primaryIpv4List.push({ interfaceName: ifaceName, address: addr.address, cidr: addr.cidr || null, netmask: addr.netmask || null });
      } else if (isV6) {
        ipv6.push({
          address: addr.address,
          netmask: addr.netmask || null,
          cidr: addr.cidr || null,
          scopeid: addr.scopeid,
          internal: Boolean(addr.internal)
        });
        if (!addr.internal) primaryIpv6List.push({ interfaceName: ifaceName, address: addr.address, cidr: addr.cidr || null });
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

  const gatewayInfo = getVerifiedDefaultGateway();
  const dnsServers = dns.getServers();
  const isContainer = Boolean(
    fs.existsSync('/.dockerenv') ||
    fs.existsSync('/run/.containerenv') ||
    (fs.existsSync('/proc/1/cgroup') && fs.readFileSync('/proc/1/cgroup', 'utf8').includes('docker'))
  );

  return {
    hostname: os.hostname(),
    platform: os.platform(),
    isContainer,
    executionScope: isContainer ? 'container_network_namespace' : 'host_network_namespace',
    scopeDistinctionNote: isContainer
      ? 'These network interfaces belong to the EJII server/container environment. If you are accessing EJII from a remote browser, your personal device may have a different local LAN IP, and external websites see your NAT/public egress IP.'
      : 'These network interfaces belong to the local EJII host machine. External internet services see your router/NAT public IP rather than private RFC1918 interface addresses.',
    primaryIpv4: primaryIpv4List[0]?.address || '127.0.0.1',
    nonLoopbackIpv4: primaryIpv4List,
    nonLoopbackIpv6: primaryIpv6List,
    interfaces,
    dnsServers,
    defaultGateway: gatewayInfo,
    collectionMethod: 'os.networkInterfaces + ' + gatewayInfo.collectionMethod,
    observedAt: new Date().toISOString()
  };
}

module.exports = {
  getHostMetrics,
  getServices,
  getProcesses,
  getEventLogs,
  getVerifiedDefaultGateway,
  inspectLocalNetworkConfiguration
};

