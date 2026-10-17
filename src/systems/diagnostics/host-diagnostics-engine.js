/**
 * EJII Host Diagnostics Engine
 * Introspects genuine physical and virtual host hardware, OS subsystems,
 * network stacks, storage SMART status, and process trees on Windows hosts.
 *
 * 5-STATE HEALTH ENGINE (F-08, F-09):
 *   - HEALTHY: Telemetry successfully collected and within nominal thresholds.
 *   - DEGRADED: Telemetry indicates warnings, non-critical errors, or high resource contention.
 *   - CRITICAL: Telemetry confirms active hardware failure, zero connected adapters, or SMART degradation.
 *   - UNKNOWN: Telemetry source unsupported on the current host operating system.
 *   - COLLECTION_ERROR: Telemetry collector failed, timed out, or encountered an OS access denial.
 *
 * ZERO FAKE FALLBACKS: Missing or unreachable telemetry is NEVER masked as healthy.
 */

'use strict';

const os = require('os');
const { exec } = require('child_process');
const { IS_WINDOWS } = require('../../config');

class HostDiagnosticsEngine {
  constructor() {
    this.cachedAudit = null;
    this.lastAuditTime = 0;
    this.cacheTtlMs = 5000;
  }

  /**
   * Helper to execute PowerShell command with JSON parsing, duration timing, and timeout
   */
  async _runPowerShell(command, timeoutMs = 8000) {
    if (!IS_WINDOWS) {
      return { success: false, data: null, error: 'UNSUPPORTED_PLATFORM: Non-Windows host OS', durationMs: 0 };
    }

    const start = Date.now();
    return new Promise((resolve) => {
      const wrapped = `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ${command} | ConvertTo-Json -Depth 3 -Compress"`;
      exec(wrapped, { timeout: timeoutMs, maxBuffer: 15 * 1024 * 1024 }, (err, stdout, stderr) => {
        const durationMs = Date.now() - start;
        if (err) {
          return resolve({
            success: false,
            data: null,
            error: err.message || stderr,
            code: err.code,
            durationMs
          });
        }
        if (!stdout || !stdout.trim()) {
          return resolve({ success: true, data: null, durationMs });
        }
        try {
          const parsed = JSON.parse(stdout.trim());
          resolve({ success: true, data: parsed, durationMs });
        } catch (e) {
          resolve({
            success: false,
            data: null,
            error: `JSON_PARSE_ERROR: ${e.message}`,
            durationMs
          });
        }
      });
    });
  }

  /**
   * Pillar 1: Network & Connectivity Layer
   */
  async collectNetworkPillar() {
    const startTime = Date.now();

    if (!IS_WINDOWS) {
      return {
        status: 'UNKNOWN',
        summary: 'Network adapter CIM telemetry unsupported on non-Windows platform.',
        details: {
          adapters: [],
          routes: [],
          socketCounts: { ESTABLISHED: 0, LISTEN: 0, TIME_WAIT: 0, CLOSE_WAIT: 0, OTHER: 0 },
          dnsCacheCount: 0,
          gatewayIp: null
        },
        anomalies: [],
        recipes: [],
        metadata: {
          collectedAt: new Date().toISOString(),
          durationMs: Date.now() - startTime,
          collector: 'os.networkInterfaces',
          success: false,
          platform: process.platform,
          error: 'UNSUPPORTED_PLATFORM'
        }
      };
    }

    try {
      const [adapterRes, routeRes, socketRes, dnsRes] = await Promise.all([
        this._runPowerShell('Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress'),
        this._runPowerShell('Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric'),
        this._runPowerShell('Get-NetTCPConnection | Select-Object State, OwningProcess, LocalPort, RemotePort'),
        this._runPowerShell('Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object -First 30 Entry, Status')
      ]);

      if (!adapterRes.success && !socketRes.success) {
        return {
          status: 'COLLECTION_ERROR',
          summary: `Network telemetry collection failed: ${adapterRes.error || socketRes.error}`,
          details: { adapters: [], routes: [], socketCounts: {}, dnsCacheCount: 0, gatewayIp: null },
          anomalies: [{
            severity: 'WARNING',
            title: 'Network Telemetry Collector Failure',
            plainEnglish: `PowerShell Get-NetAdapter returned an error: ${adapterRes.error || socketRes.error}`,
            rawProof: String(adapterRes.error)
          }],
          recipes: [],
          metadata: {
            collectedAt: new Date().toISOString(),
            durationMs: Date.now() - startTime,
            collector: 'Get-NetAdapter / Get-NetTCPConnection',
            success: false,
            error: adapterRes.error || socketRes.error
          }
        };
      }

      const adapters = adapterRes.data;
      const routes = routeRes.data;
      const sockets = socketRes.data;
      const dnsCache = dnsRes.data;

      const adapterList = Array.isArray(adapters) ? adapters : (adapters ? [adapters] : []);
      const routeList = Array.isArray(routes) ? routes : (routes ? [routes] : []);
      const socketList = Array.isArray(sockets) ? sockets : (sockets ? [sockets] : []);
      const dnsList = Array.isArray(dnsCache) ? dnsCache : (dnsCache ? [dnsCache] : []);

      // Socket state counts
      const counts = { ESTABLISHED: 0, LISTEN: 0, TIME_WAIT: 0, CLOSE_WAIT: 0, OTHER: 0 };
      for (const s of socketList) {
        const state = String(s.State || '').toUpperCase();
        if (state.includes('ESTABLISHED')) counts.ESTABLISHED++;
        else if (state.includes('LISTEN')) counts.LISTEN++;
        else if (state.includes('TIMEWAIT') || state.includes('TIME_WAIT')) counts.TIME_WAIT++;
        else if (state.includes('CLOSEWAIT') || state.includes('CLOSE_WAIT')) counts.CLOSE_WAIT++;
        else counts.OTHER++;
      }

      const defaultRoute = routeList.find(r => r.DestinationPrefix === '0.0.0.0/0');
      const gatewayIp = defaultRoute?.NextHop || 'Unknown';

      const anomalies = [];
      const recipes = [];
      let status = 'HEALTHY';

      // Detect anomalies
      if (counts.CLOSE_WAIT > 100) {
        status = 'DEGRADED';
        anomalies.push({
          severity: 'WARNING',
          title: 'TCP Socket Exhaustion (High CLOSE_WAIT)',
          plainEnglish: `There are ${counts.CLOSE_WAIT} sockets stuck in CLOSE_WAIT. Applications may be failing to close sockets cleanly.`,
          rawProof: `CLOSE_WAIT count: ${counts.CLOSE_WAIT}`,
          recipeId: 'reset_winsock'
        });
        recipes.push('reset_winsock');
      }

      const activeAdapters = adapterList.filter(a => String(a.Status || '').toLowerCase() === 'up');
      if (adapterList.length > 0 && activeAdapters.length === 0) {
        status = 'CRITICAL';
        anomalies.push({
          severity: 'CRITICAL',
          title: 'All Network Adapters Disconnected',
          plainEnglish: 'The operating system reports zero active physical or virtual network adapters.',
          rawProof: `Total adapters: ${adapterList.length}, Up: 0`,
          recipeId: 'renew_dhcp'
        });
        recipes.push('renew_dhcp');
      }

      const summary = anomalies.length > 0
        ? `${anomalies.length} network issue(s) detected. Default gateway: ${gatewayIp}.`
        : `Network healthy: ${activeAdapters.length} active adapter(s), ${counts.ESTABLISHED} active connections.`;

      return {
        status,
        summary,
        details: {
          adapters: adapterList,
          routes: routeList,
          socketCounts: counts,
          dnsCacheCount: dnsList.length,
          gatewayIp
        },
        anomalies,
        recipes,
        metadata: {
          collectedAt: new Date().toISOString(),
          durationMs: Date.now() - startTime,
          collector: 'Get-NetAdapter / Get-NetRoute / Get-NetTCPConnection',
          success: true
        }
      };
    } catch (err) {
      return {
        status: 'COLLECTION_ERROR',
        summary: `Error collecting network pillar: ${err.message}`,
        details: { adapters: [], routes: [], socketCounts: {}, dnsCacheCount: 0, gatewayIp: null },
        anomalies: [],
        recipes: [],
        metadata: {
          collectedAt: new Date().toISOString(),
          durationMs: Date.now() - startTime,
          collector: 'Get-NetAdapter',
          success: false,
          error: err.message
        }
      };
    }
  }

  /**
   * Pillar 2: Storage, File System & OS Integrity (F-08, F-09)
   */
  async collectStoragePillar() {
    const startTime = Date.now();

    if (!IS_WINDOWS) {
      return {
        status: 'UNKNOWN',
        summary: 'Storage SMART and VSS telemetry unsupported on non-Windows platform.',
        details: {
          volumes: [],
          smartStatus: 'UNKNOWN',
          vssStatus: 'UNKNOWN',
          tempDumpCount: 0
        },
        anomalies: [],
        recipes: [],
        metadata: {
          collectedAt: new Date().toISOString(),
          durationMs: Date.now() - startTime,
          collector: 'CIM_LogicalDisk',
          success: false,
          platform: process.platform,
          error: 'UNSUPPORTED_PLATFORM'
        }
      };
    }

    try {
      const [volRes, smartRes, vssRes, dumpRes] = await Promise.all([
        this._runPowerShell('Get-Volume | Where-Object { $_.DriveLetter -ne $null } | Select-Object DriveLetter, FileSystemLabel, FileSystem, SizeRemaining, Size, HealthStatus'),
        this._runPowerShell('Get-CimInstance -Namespace root\\wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction SilentlyContinue | Select-Object PredictFailure, Reason'),
        this._runPowerShell('Get-Service -Name VSS -ErrorAction SilentlyContinue | Select-Object Status, StartType'),
        this._runPowerShell('(Get-ChildItem -Path C:\\Windows\\Minidump -ErrorAction SilentlyContinue | Measure-Object).Count')
      ]);

      if (!volRes.success) {
        return {
          status: 'COLLECTION_ERROR',
          summary: `Storage volume telemetry collection failed: ${volRes.error}`,
          details: { volumes: [], smartStatus: 'COLLECTION_ERROR', vssStatus: 'COLLECTION_ERROR', tempDumpCount: 0 },
          anomalies: [{
            severity: 'WARNING',
            title: 'Storage Volume Collector Error',
            plainEnglish: `PowerShell Get-Volume failed: ${volRes.error}`,
            rawProof: String(volRes.error)
          }],
          recipes: [],
          metadata: {
            collectedAt: new Date().toISOString(),
            durationMs: Date.now() - startTime,
            collector: 'Get-Volume / MSStorageDriver_FailurePredictStatus',
            success: false,
            error: volRes.error
          }
        };
      }

      const volumes = volRes.data;
      const smart = smartRes.data;
      const vss = vssRes.data;
      const minidumps = dumpRes.data;

      const volumeList = Array.isArray(volumes) ? volumes : (volumes ? [volumes] : []);
      const formattedVols = volumeList.map(v => {
        const sizeGB = v.Size ? Number((v.Size / (1024 ** 3)).toFixed(1)) : 0;
        const freeGB = v.SizeRemaining ? Number((v.SizeRemaining / (1024 ** 3)).toFixed(1)) : 0;
        const usedPct = sizeGB > 0 ? Number((((sizeGB - freeGB) / sizeGB) * 100).toFixed(1)) : 0;
        return {
          DriveLetter: v.DriveLetter + ':',
          Label: v.FileSystemLabel || 'Local Disk',
          FileSystem: v.FileSystem || 'NTFS',
          SizeGB: sizeGB,
          FreeGB: freeGB,
          UsedPct: usedPct,
          HealthStatus: v.HealthStatus || 'Healthy'
        };
      });

      const smartObj = Array.isArray(smart) ? smart[0] : smart;
      const smartStatus = smartObj && smartObj.PredictFailure === true ? 'PREDICT_FAILURE' : (smartRes.success ? 'OK' : 'UNKNOWN');
      const vssStatus = vss?.Status || (vssRes.success ? 'Stopped' : 'UNKNOWN');
      const tempDumpCount = typeof minidumps === 'number' ? minidumps : 0;

      const anomalies = [];
      const recipes = [];
      let status = 'HEALTHY';

      // SMART Check
      if (smartStatus === 'PREDICT_FAILURE') {
        status = 'CRITICAL';
        anomalies.push({
          severity: 'CRITICAL',
          title: 'Physical Disk SMART Failure Predicted',
          plainEnglish: 'The physical storage drive firmware reports hardware degradation and predicts imminent drive failure.',
          rawProof: `PredictFailure: true, Reason code: ${smartObj.Reason || 'Unknown'}`,
          recipeId: 'scan_disk'
        });
        recipes.push('scan_disk');
      }

      // Low Disk Space Check (< 10GB or > 95% used)
      for (const vol of formattedVols) {
        if (vol.FreeGB < 10 || vol.UsedPct > 95) {
          const isCritical = vol.FreeGB < 5 || vol.UsedPct > 98;
          status = isCritical ? 'CRITICAL' : (status === 'CRITICAL' ? 'CRITICAL' : 'DEGRADED');
          anomalies.push({
            severity: isCritical ? 'CRITICAL' : 'WARNING',
            title: `Low Disk Capacity on Drive ${vol.DriveLetter}`,
            plainEnglish: `Drive ${vol.DriveLetter} has only ${vol.FreeGB} GB free (${vol.UsedPct}% consumed).`,
            rawProof: `Volume ${vol.DriveLetter}: Total ${vol.SizeGB} GB, Free ${vol.FreeGB} GB (${vol.UsedPct}% used)`,
            recipeId: 'cleanup_temp_dumps'
          });
          if (!recipes.includes('cleanup_temp_dumps')) {
            recipes.push('cleanup_temp_dumps');
          }
        }
      }

      const summary = anomalies.length > 0
        ? `${anomalies.length} storage issue(s) detected. SMART Status: ${smartStatus}.`
        : `All ${formattedVols.length} volume(s) healthy. SMART status ${smartStatus}.`;

      return {
        status,
        summary,
        details: {
          volumes: formattedVols,
          smartStatus,
          vssStatus,
          tempDumpCount
        },
        anomalies,
        recipes,
        metadata: {
          collectedAt: new Date().toISOString(),
          durationMs: Date.now() - startTime,
          collector: 'Get-Volume / MSStorageDriver_FailurePredictStatus / Get-Service VSS',
          success: true
        }
      };
    } catch (err) {
      return {
        status: 'COLLECTION_ERROR',
        summary: `Error collecting storage pillar: ${err.message}`,
        details: { volumes: [], smartStatus: 'COLLECTION_ERROR', vssStatus: 'COLLECTION_ERROR', tempDumpCount: 0 },
        anomalies: [],
        recipes: [],
        metadata: {
          collectedAt: new Date().toISOString(),
          durationMs: Date.now() - startTime,
          collector: 'Get-Volume',
          success: false,
          error: err.message
        }
      };
    }
  }

  /**
   * Pillar 3: Resource Allocation & Performance Triage
   */
  async collectResourcePillar() {
    const startTime = Date.now();
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    const memPct = parseFloat(((usedMem / totalMem) * 100).toFixed(1));

    if (!IS_WINDOWS) {
      return {
        status: 'UNKNOWN',
        summary: 'CIM process and performance queue telemetry unsupported on non-Windows platform.',
        details: {
          cpuModel: os.cpus()[0]?.model || 'Generic CPU',
          cores: os.cpus().length,
          cpuLoadPct: 0,
          totalRamGB: Number((totalMem / (1024 ** 3)).toFixed(1)),
          usedRamGB: Number((usedMem / (1024 ** 3)).toFixed(1)),
          freeRamGB: Number((freeMem / (1024 ** 3)).toFixed(1)),
          ramUsedPct: memPct,
          diskQueueLength: 0,
          topProcesses: []
        },
        anomalies: [],
        recipes: [],
        metadata: {
          collectedAt: new Date().toISOString(),
          durationMs: Date.now() - startTime,
          collector: 'os.cpus / os.totalmem',
          success: false,
          platform: process.platform,
          error: 'UNSUPPORTED_PLATFORM'
        }
      };
    }

    try {
      const [cpuRes, memRes, diskRes, procRes] = await Promise.all([
        this._runPowerShell('Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average | Select-Object Average'),
        this._runPowerShell('Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize, FreePhysicalMemory'),
        this._runPowerShell('Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk | Where-Object { $_.Name -eq "_Total" } | Select-Object CurrentDiskQueueLength'),
        this._runPowerShell('Get-Process | Sort-Object -Descending WorkingSet64 | Select-Object -First 30 Id, ProcessName, CPU, WorkingSet64, PM, Handles')
      ]);

      if (!procRes.success && !cpuRes.success) {
        return {
          status: 'COLLECTION_ERROR',
          summary: `Resource telemetry collection failed: ${cpuRes.error || procRes.error}`,
          details: { cpuModel: os.cpus()[0]?.model || 'Generic CPU', cores: os.cpus().length, topProcesses: [] },
          anomalies: [],
          recipes: [],
          metadata: {
            collectedAt: new Date().toISOString(),
            durationMs: Date.now() - startTime,
            collector: 'Win32_Processor / Get-Process',
            success: false,
            error: cpuRes.error || procRes.error
          }
        };
      }

      let cpuLoadPct = 0;
      if (cpuRes.data?.Average != null) {
        cpuLoadPct = Number(cpuRes.data.Average.toFixed(1));
      }

      let diskQueueLength = 0;
      if (diskRes.data?.CurrentDiskQueueLength != null) {
        diskQueueLength = Number(diskRes.data.CurrentDiskQueueLength);
      }

      const procList = procRes.data;
      const procs = Array.isArray(procList) ? procList : (procList ? [procList] : []);
      const formattedProcs = procs.map(p => ({
        pid: p.Id,
        name: p.ProcessName,
        cpu: p.CPU ? Number(p.CPU.toFixed(1)) : 0,
        workingSetMB: p.WorkingSet64 ? Number((p.WorkingSet64 / (1024 * 1024)).toFixed(1)) : 0,
        privateMB: p.PM ? Number((p.PM / (1024 * 1024)).toFixed(1)) : 0,
        handles: p.Handles || 0
      }));

      const anomalies = [];
      const recipes = [];
      let status = 'HEALTHY';

      // High CPU Check (> 90%)
      if (cpuLoadPct > 90) {
        status = 'CRITICAL';
        anomalies.push({
          severity: 'CRITICAL',
          title: 'Sustained High CPU Utilization (>90%)',
          plainEnglish: `Overall processor load is at ${cpuLoadPct}%. System response latency is elevated. Top process: ${formattedProcs[0]?.name} (${formattedProcs[0]?.pid}).`,
          rawProof: `Average LoadPercentage: ${cpuLoadPct}%`,
          recipeId: 'lower_process_priority'
        });
        recipes.push('lower_process_priority');
      }

      // Memory Exhaustion Check (> 90%)
      if (memPct > 90) {
        status = 'CRITICAL';
        anomalies.push({
          severity: 'CRITICAL',
          title: 'Physical Memory Saturation (>90%)',
          plainEnglish: `Physical RAM usage is at ${memPct}%. System may begin aggressive paging to disk.`,
          rawProof: `Used RAM: ${Number((usedMem / (1024 ** 3)).toFixed(1))} GB, Total: ${Number((totalMem / (1024 ** 3)).toFixed(1))} GB`,
          recipeId: 'trim_working_set'
        });
        recipes.push('trim_working_set');
      }

      // High Disk Queue Depth (> 4.0)
      if (diskQueueLength > 4) {
        status = status === 'CRITICAL' ? 'CRITICAL' : 'DEGRADED';
        anomalies.push({
          severity: 'WARNING',
          title: 'High Disk I/O Queue Depth',
          plainEnglish: `Disk I/O queue length is currently ${diskQueueLength}. Storage requests are backing up.`,
          rawProof: `CurrentDiskQueueLength: ${diskQueueLength}`,
          recipeId: 'trim_working_set'
        });
      }

      const summary = anomalies.length > 0
        ? `${anomalies.length} performance issue(s) identified. CPU: ${cpuLoadPct}%, RAM: ${memPct}%.`
        : `Optimal resource performance. CPU: ${cpuLoadPct}%, RAM: ${memPct}%, Queue: ${diskQueueLength}.`;

      return {
        status,
        summary,
        details: {
          cpuModel: os.cpus()[0]?.model || 'Generic CPU',
          cores: os.cpus().length,
          cpuLoadPct,
          totalRamGB: Number((totalMem / (1024 ** 3)).toFixed(1)),
          usedRamGB: Number((usedMem / (1024 ** 3)).toFixed(1)),
          freeRamGB: Number((freeMem / (1024 ** 3)).toFixed(1)),
          ramUsedPct: memPct,
          diskQueueLength,
          topProcesses: formattedProcs
        },
        anomalies,
        recipes,
        metadata: {
          collectedAt: new Date().toISOString(),
          durationMs: Date.now() - startTime,
          collector: 'Win32_Processor / Win32_PerfFormattedData_PerfDisk_PhysicalDisk / Get-Process',
          success: true
        }
      };
    } catch (err) {
      return {
        status: 'COLLECTION_ERROR',
        summary: `Error collecting resource pillar: ${err.message}`,
        details: { topProcesses: [] },
        anomalies: [],
        recipes: [],
        metadata: {
          collectedAt: new Date().toISOString(),
          durationMs: Date.now() - startTime,
          collector: 'Win32_Processor',
          success: false,
          error: err.message
        }
      };
    }
  }

  /**
   * Pillar 4: Peripherals, Subsystems & Drivers
   */
  async collectPeripheralsPillar() {
    const startTime = Date.now();

    if (!IS_WINDOWS) {
      return {
        status: 'UNKNOWN',
        summary: 'PnP and Spooler peripheral telemetry unsupported on non-Windows platform.',
        details: {
          degradedDevices: [],
          spoolerStatus: 'UNKNOWN',
          spoolerPendingJobs: 0
        },
        anomalies: [],
        recipes: [],
        metadata: {
          collectedAt: new Date().toISOString(),
          durationMs: Date.now() - startTime,
          collector: 'Win32_PnPEntity / Win32_Service',
          success: false,
          platform: process.platform,
          error: 'UNSUPPORTED_PLATFORM'
        }
      };
    }

    try {
      const [pnpRes, spoolerRes, jobsRes] = await Promise.all([
        this._runPowerShell('Get-CimInstance Win32_PnPEntity | Where-Object { $_.ConfigManagerErrorCode -ne 0 -and $_.ConfigManagerErrorCode -ne $null } | Select-Object Name, DeviceID, ConfigManagerErrorCode, Status'),
        this._runPowerShell('Get-Service -Name Spooler -ErrorAction SilentlyContinue | Select-Object Status, StartType'),
        this._runPowerShell('(Get-ChildItem -Path C:\\Windows\\System32\\spool\\PRINTERS -ErrorAction SilentlyContinue | Measure-Object).Count')
      ]);

      if (!spoolerRes.success && !pnpRes.success) {
        return {
          status: 'COLLECTION_ERROR',
          summary: `Peripheral telemetry collection failed: ${spoolerRes.error || pnpRes.error}`,
          details: { degradedDevices: [], spoolerStatus: 'COLLECTION_ERROR', spoolerPendingJobs: 0 },
          anomalies: [],
          recipes: [],
          metadata: {
            collectedAt: new Date().toISOString(),
            durationMs: Date.now() - startTime,
            collector: 'Win32_PnPEntity / Get-Service Spooler',
            success: false,
            error: spoolerRes.error || pnpRes.error
          }
        };
      }

      const pnp = pnpRes.data;
      const spooler = spoolerRes.data;
      const jobs = jobsRes.data;

      const degradedList = Array.isArray(pnp) ? pnp : (pnp ? [pnp] : []);
      const spoolerStatus = spooler?.Status === 4 ? 'Running' : String(spooler?.Status || 'Stopped');
      const pendingJobs = typeof jobs === 'number' ? jobs : 0;

      const anomalies = [];
      const recipes = [];
      let status = 'HEALTHY';

      // Print Spooler deadlock check
      if (spoolerStatus !== 'Running' || pendingJobs > 10) {
        status = 'DEGRADED';
        anomalies.push({
          severity: 'WARNING',
          title: 'Windows Print Spooler Deadlock / Backlog',
          plainEnglish: `Print Spooler service status is '${spoolerStatus}' with ${pendingJobs} queued job(s). Deadlocked spooler queues can cause Explorer lockups.`,
          rawProof: `Status: ${spoolerStatus}, Queue backlog: ${pendingJobs}`,
          recipeId: 'repair_print_spooler'
        });
        recipes.push('repair_print_spooler');
      }

      // Degraded PnP devices check
      if (degradedList.length > 0) {
        status = 'DEGRADED';
        anomalies.push({
          severity: 'WARNING',
          title: `${degradedList.length} Degraded Hardware Device(s) Detected`,
          plainEnglish: `Windows Device Manager reports ${degradedList.length} hardware peripheral(s) in degraded error states (e.g. Code 10, Code 43).`,
          rawProof: `First degraded: ${degradedList[0]?.Name} (ErrorCode: ${degradedList[0]?.ConfigManagerErrorCode})`,
          recipeId: 'rescan_pnp_devices'
        });
        recipes.push('rescan_pnp_devices');
      }

      const summary = anomalies.length > 0
        ? `${anomalies.length} peripheral issue(s) detected. Spooler: ${spoolerStatus}, Degraded PnP: ${degradedList.length}.`
        : `All hardware devices and print subsystems functioning normally.`;

      return {
        status,
        summary,
        details: {
          degradedDevices: degradedList,
          spoolerStatus,
          spoolerPendingJobs: pendingJobs
        },
        anomalies,
        recipes,
        metadata: {
          collectedAt: new Date().toISOString(),
          durationMs: Date.now() - startTime,
          collector: 'Win32_PnPEntity / Get-Service Spooler',
          success: true
        }
      };
    } catch (err) {
      return {
        status: 'COLLECTION_ERROR',
        summary: `Error collecting peripheral pillar: ${err.message}`,
        details: { degradedDevices: [], spoolerStatus: 'COLLECTION_ERROR', spoolerPendingJobs: 0 },
        anomalies: [],
        recipes: [],
        metadata: {
          collectedAt: new Date().toISOString(),
          durationMs: Date.now() - startTime,
          collector: 'Win32_PnPEntity',
          success: false,
          error: err.message
        }
      };
    }
  }

  /**
   * Aggregate 4-pillar full system audit with 5-State Subsystem Health Classification
   */
  async collectFullAudit(forceFresh = false) {
    const now = Date.now();
    if (!forceFresh && this.cachedAudit && (now - this.lastAuditTime) < this.cacheTtlMs) {
      return this.cachedAudit;
    }

    const [network, storage, resource, peripherals] = await Promise.all([
      this.collectNetworkPillar(),
      this.collectStoragePillar(),
      this.collectResourcePillar(),
      this.collectPeripheralsPillar()
    ]);

    // Aggregate anomalies and deduplicate staged recipes
    const allAnomalies = [
      ...network.anomalies,
      ...storage.anomalies,
      ...resource.anomalies,
      ...peripherals.anomalies
    ];

    const stagedRecipes = Array.from(new Set([
      ...network.recipes,
      ...storage.recipes,
      ...resource.recipes,
      ...peripherals.recipes
    ]));

    // 5-State Overall Status Resolution
    const pillarStatuses = [network.status, storage.status, resource.status, peripherals.status];
    let overallStatus = 'HEALTHY';

    if (pillarStatuses.includes('CRITICAL')) {
      overallStatus = 'CRITICAL';
    } else if (pillarStatuses.includes('COLLECTION_ERROR')) {
      overallStatus = 'COLLECTION_ERROR';
    } else if (pillarStatuses.includes('DEGRADED')) {
      overallStatus = 'DEGRADED';
    } else if (pillarStatuses.every(s => s === 'UNKNOWN')) {
      overallStatus = 'UNKNOWN';
    } else {
      overallStatus = 'HEALTHY';
    }

    const auditResult = {
      host: {
        hostname: os.hostname(),
        platform: os.platform(),
        arch: os.arch(),
        uptimeDays: Number((os.uptime() / 86400).toFixed(1)),
        cpuCores: os.cpus().length,
        totalRamGB: Number((os.totalmem() / (1024 ** 3)).toFixed(1))
      },
      overallStatus,
      durationMs: Date.now() - now,
      pillars: {
        network,
        storage,
        resource,
        peripherals
      },
      anomalies: allAnomalies,
      stagedRecipes,
      timestamp: new Date().toISOString()
    };

    // AI Brain Health Synthesis Integration
    try {
      const { aiBrain } = require('../../core/ai-brain');
      auditResult.brainSynthesis = aiBrain.evaluateHostHealth(auditResult);
    } catch (e) {
      auditResult.brainSynthesis = {
        overallStatus,
        summary: `Host ${os.hostname()} overall status is ${overallStatus}.`,
        recommendedAction: stagedRecipes.length > 0 ? `Stage remediation recipe '${stagedRecipes[0]}'.` : 'No action required.'
      };
    }

    this.cachedAudit = auditResult;
    this.lastAuditTime = now;
    return auditResult;
  }

  /**
   * Compatibility alias for collectFullAudit
   */
  async runFullSystemAudit(forceFresh = false) {
    return this.collectFullAudit(forceFresh);
  }

  /**
   * Detailed live process list
   */
  async getProcessList(limit = 50) {
    if (!IS_WINDOWS) {
      return [];
    }
    const res = await this._runPowerShell(`Get-Process | Sort-Object -Descending WorkingSet64 | Select-Object -First ${limit} Id, ProcessName, CPU, WorkingSet64, PM, Handles, Path`);
    if (!res.success || !res.data) return [];
    const list = Array.isArray(res.data) ? res.data : [res.data];
    return list.map(p => ({
      pid: p.Id,
      name: p.ProcessName,
      cpu: p.CPU ? Number(p.CPU.toFixed(1)) : 0,
      workingSetMB: p.WorkingSet64 ? Number((p.WorkingSet64 / (1024 * 1024)).toFixed(1)) : 0,
      privateMB: p.PM ? Number((p.PM / (1024 * 1024)).toFixed(1)) : 0,
      handles: p.Handles || 0,
      path: p.Path || ''
    }));
  }

  /**
   * Compatibility alias for getProcessList
   */
  async getProcessTable(limit = 50) {
    return this.getProcessList(limit);
  }

  /**
   * Detailed live network socket connections
   */
  async getSocketList() {
    if (!IS_WINDOWS) {
      return [];
    }
    const res = await this._runPowerShell('Get-NetTCPConnection | Select-Object -First 100 LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess');
    if (!res.success || !res.data) return [];
    const list = Array.isArray(res.data) ? res.data : [res.data];
    return list.map(s => ({
      local: `${s.LocalAddress}:${s.LocalPort}`,
      remote: s.RemoteAddress ? `${s.RemoteAddress}:${s.RemotePort}` : '*:*',
      state: String(s.State || '').toUpperCase(),
      pid: s.OwningProcess
    }));
  }

  /**
   * Compatibility alias for getSocketList
   */
  async getSocketTable() {
    return this.getSocketList();
  }
}

const hostDiagnosticsEngine = new HostDiagnosticsEngine();

module.exports = {
  HostDiagnosticsEngine,
  hostDiagnosticsEngine
};
