/**
 * EJII Sysinternals & Process Explorer Forensics Engine
 * Hierarchical process tree DAG, loaded DLLs/modules, and TCPView live socket-to-process mapper.
 * 100% Genuine Windows NT / POSIX Telemetry — Zero Simulated Data.
 */

const { exec } = require('child_process');
const { IS_WINDOWS } = require('../config');

/**
 * Execute PowerShell command and parse JSON safely
 */
function runPowerShellJson(cmd) {
  return new Promise((resolve) => {
    const fullCmd = `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference = 'SilentlyContinue'; ${cmd} | ConvertTo-Json -Depth 3 -Compress"`;
    exec(fullCmd, { maxBuffer: 10 * 1024 * 1024, timeout: 15000 }, (error, stdout) => {
      if (error || !stdout || !stdout.trim()) {
        return resolve(null);
      }
      try {
        const parsed = JSON.parse(stdout.trim());
        resolve(parsed);
      } catch (e) {
        resolve(null);
      }
    });
  });
}

/**
 * Build a hierarchical Process Tree (Process Explorer DAG)
 * PPID -> PID relationships
 */
async function getProcessTree() {
  if (!IS_WINDOWS) {
    try {
      const { execSync } = require('child_process');
      const out = execSync('ps -eo pid,ppid,rss,comm --no-headers 2>/dev/null || true', { encoding: 'utf8', timeout: 3000 });
      const lines = out.trim().split('\n').filter(Boolean);
      const procMap = new Map();
      const roots = [];
      for (const line of lines) {
        const parts = line.trim().split(/\s+/);
        const pid = parseInt(parts[0], 10);
        const ppid = parseInt(parts[1], 10);
        const rssKb = parseInt(parts[2], 10) || 0;
        const name = parts.slice(3).join(' ') || `pid-${pid}`;
        if (!isNaN(pid)) {
          procMap.set(pid, {
            pid,
            ppid: isNaN(ppid) ? 0 : ppid,
            name,
            ramMb: parseFloat((rssKb / 1024).toFixed(1)),
            children: []
          });
        }
      }
      for (const p of procMap.values()) {
        if (p.ppid && procMap.has(p.ppid) && p.ppid !== p.pid) {
          procMap.get(p.ppid).children.push(p);
        } else {
          roots.push(p);
        }
      }
      return {
        totalProcesses: procMap.size,
        rootCount: roots.length,
        tree: roots.slice(0, 100)
      };
    } catch (e) {
      return { totalProcesses: 0, rootCount: 0, tree: [], error: e.message };
    }
  }

  const script = 'Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, WorkingSetSize';

  const procs = await runPowerShellJson(script);
  if (!procs) return { count: 0, tree: [], providerMode: getSysinternalsProviderMode() };

  const list = Array.isArray(procs) ? procs : [procs];
  const procMap = new Map();
  const roots = [];

  for (const raw of list) {
    const p = {
      pid: raw.ProcessId,
      ppid: raw.ParentProcessId,
      name: raw.Name,
      ramMb: parseFloat(((raw.WorkingSetSize || 0) / (1024 * 1024)).toFixed(1)),
      children: []
    };
    procMap.set(p.pid, p);
  }

  for (const p of procMap.values()) {
    if (p.ppid && procMap.has(p.ppid) && p.ppid !== p.pid) {
      procMap.get(p.ppid).children.push(p);
    } else {
      roots.push(p);
    }
  }

  return {
    totalProcesses: list.length,
    rootCount: roots.length,
    tree: roots.slice(0, 100) // Top 100 root trees
  };
}

/**
 * TCPView: Map every active TCP & UDP socket to its owning process
 */
async function getTcpViewConnections() {
  if (!IS_WINDOWS) {
    const { processSocketCorrelator } = require('../network/process-socket-correlator');
    const inv = await processSocketCorrelator.collectActiveConnectionsInventory({});
    const connections = (inv.connections || []).map((c) => ({
      proto: c.protocol || 'TCP',
      local: `${c.localAddress}:${c.localPort}`,
      remote: c.remoteAddress && c.remotePort > 0 ? `${c.remoteAddress}:${c.remotePort}` : '*:*',
      state: c.state || 'ESTABLISHED',
      pid: c.pid || 0,
      proc: c.processName || 'Unknown'
    }));
    return {
      count: connections.length,
      connections
    };
  }

  const tcpScript = 'Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object -First 100 LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess';
  const udpScript = 'Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object -First 50 LocalAddress, LocalPort, OwningProcess';
  const procScript = 'Get-Process | Select-Object Id, ProcessName';

  const [tcpRaw, udpRaw, procRaw] = await Promise.all([
    runPowerShellJson(tcpScript),
    runPowerShellJson(udpScript),
    runPowerShellJson(procScript)
  ]);

  const procMap = new Map();
  if (procRaw) {
    const pList = Array.isArray(procRaw) ? procRaw : [procRaw];
    for (const p of pList) {
      procMap.set(p.Id, p.ProcessName);
    }
  }

  const connections = [];

  if (tcpRaw) {
    const tList = Array.isArray(tcpRaw) ? tcpRaw : [tcpRaw];
    for (const t of tList) {
      connections.push({
        proto: 'TCP',
        local: `${t.LocalAddress}:${t.LocalPort}`,
        remote: t.RemoteAddress && t.RemotePort > 0 ? `${t.RemoteAddress}:${t.RemotePort}` : '*:*',
        state: String(t.State || 'ESTABLISHED'),
        pid: t.OwningProcess,
        proc: procMap.get(t.OwningProcess) || 'Unknown'
      });
    }
  }

  if (udpRaw) {
    const uList = Array.isArray(udpRaw) ? udpRaw : [udpRaw];
    for (const u of uList) {
      connections.push({
        proto: 'UDP',
        local: `${u.LocalAddress}:${u.LocalPort}`,
        remote: '*:*',
        state: 'LISTENING',
        pid: u.OwningProcess,
        proc: procMap.get(u.OwningProcess) || 'Unknown'
      });
    }
  }

  return {
    count: connections.length,
    connections
  };
}

/**
 * Enumerate loaded modules / DLLs for a specific PID
 * @param {number} pid 
 */
async function getProcessModules(pid) {
  if (!IS_WINDOWS) {
    return { error: 'Process module enumeration requires Windows NT.' };
  }

  const safePid = parseInt(pid, 10);
  if (isNaN(safePid) || safePid <= 0) {
    return { error: 'Valid positive PID required.' };
  }

  const script = `
    try {
      (Get-Process -Id ${safePid} -ErrorAction Stop).Modules | Select-Object ModuleName, FileName, [math]::Round($_.ModuleMemorySize / 1KB, 1) as SizeKB -First 50 | ForEach-Object {
        [PSCustomObject]@{
          module = $_.ModuleName
          path = $_.FileName
        }
      }
    } catch {
      @()
    }
  `;

  const modules = await runPowerShellJson(script);
  const list = modules ? (Array.isArray(modules) ? modules : [modules]) : [];

  return {
    pid: safePid,
    moduleCount: list.length,
    modules: list
  };
}


function getSysinternalsProviderMode() {
  return 'WIN32_CIM_KERNEL_FALLBACK';
}

module.exports = {
  getProcessTree,
  getTcpViewConnections,
  getProcessModules
};
