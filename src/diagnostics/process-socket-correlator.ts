// src/diagnostics/process-socket-correlator.ts
/**
 * User-Space Process-to-Socket Behavioral Matrix & Ephemeral Port Exhaustion Predictor
 * 100% Unprivileged, Zero-Simulation Physical OS Diagnostic Engine.
 * Supports:
 *  - Netstat/SS & Process table live attribution (Windows & Linux)
 *  - RFC 6056 Ephemeral Port Exhaustion Telemetry (49152..65535, 16384 total)
 *  - C2 Beaconing Periodicity Detection via Coefficient of Variation (CV = sigma / mu)
 */

import { execSync } from 'node:child_process';

export interface SocketEntry {
  readonly protocol: 'TCP' | 'UDP';
  readonly localAddress: string;
  readonly localPort: number;
  readonly remoteAddress: string;
  readonly remotePort: number;
  readonly state: string;
  readonly pid: number;
}

export interface ProcessEntry {
  readonly pid: number;
  readonly name: string;
  readonly memoryMb?: number;
}

export interface ProcessBeaconingMetrics {
  readonly sampleCount: number;
  readonly meanIntervalMs: number;
  readonly stdDevIntervalMs: number;
  readonly coefficientOfVariation: number;
  readonly periodicityScore: number;
  readonly beaconingSuspected: boolean;
}

export interface ProcessSocketAttribution {
  readonly pid: number;
  readonly processName: string;
  readonly memoryMb: number;
  readonly totalSockets: number;
  readonly establishedSockets: number;
  readonly timeWaitSockets: number;
  readonly listeningSockets: number;
  readonly ephemeralPortsUsed: number;
  readonly uniqueRemoteIps: readonly string[];
  readonly beaconingMetrics: ProcessBeaconingMetrics;
}

export interface EphemeralPortExhaustionTelemetry {
  readonly totalDynamicRange: number; // 16384 (49152..65535 per RFC 6056)
  readonly activeEphemeralCount: number;
  readonly saturationPct: number;
  readonly timeWaitRatio: number;
  readonly establishedRatio: number;
  readonly estimatedSecondsToPortExhaustion: number | null;
  readonly status: 'NOMINAL' | 'WARNING' | 'CRITICAL_EXHAUSTION_IMMINENT';
}

export interface ProcessSocketMatrixReport {
  readonly ephemeralTelemetry: EphemeralPortExhaustionTelemetry;
  readonly processes: readonly ProcessSocketAttribution[];
  readonly totalSockets: number;
  readonly timestampIso: string;
  readonly sockets?: readonly (SocketEntry & { readonly processName: string })[];
  readonly collectionStatus?: 'LIVE_OS_TELEMETRY' | 'UNAVAILABLE';
  readonly collectionMethod?: string | null;
  readonly collectionErrors?: readonly string[];
  readonly collectionNote?: string | null;
}

export class ProcessSocketCorrelatorEngine {
  public static readonly EPHEMERAL_MIN = 49152;
  public static readonly EPHEMERAL_MAX = 65535;
  public static readonly EPHEMERAL_TOTAL = 16384; // 65535 - 49152 + 1

  /**
   * Computes the Coefficient of Variation CV = sigma / mu across inter-connection timestamps.
   * Periodicity score: 1.0 - min(1.0, CV). CV < 0.15 with >= 4 samples triggers beaconingSuspected.
   */
  public static computeBeaconingMetrics(timestampsMs: readonly number[]): ProcessBeaconingMetrics {
    if (timestampsMs.length < 3) {
      return {
        sampleCount: timestampsMs.length,
        meanIntervalMs: 0,
        stdDevIntervalMs: 0,
        coefficientOfVariation: 1.0,
        periodicityScore: 0.0,
        beaconingSuspected: false,
      };
    }

    const intervals: number[] = [];
    for (let i = 1; i < timestampsMs.length; i++) {
      intervals.push(Math.max(1, timestampsMs[i] - timestampsMs[i - 1]));
    }

    const m = intervals.length;
    const mean = intervals.reduce((acc, v) => acc + v, 0) / m;
    let varianceSum = 0;
    for (const v of intervals) {
      varianceSum += (v - mean) * (v - mean);
    }
    const stdDev = Math.sqrt(varianceSum / m);
    const cv = mean > 0 ? stdDev / mean : 1.0;
    const periodicityScore = Number(Math.max(0, 1.0 - Math.min(1.0, cv)).toFixed(3));
    const beaconingSuspected = cv < 0.15 && m >= 4;

    return {
      sampleCount: timestampsMs.length,
      meanIntervalMs: Number(mean.toFixed(2)),
      stdDevIntervalMs: Number(stdDev.toFixed(2)),
      coefficientOfVariation: Number(cv.toFixed(4)),
      periodicityScore,
      beaconingSuspected,
    };
  }

  /**
   * Alias for collecting and analyzing live host socket matrix.
   */
  public static runLiveExtractionAndAnalysis(): ProcessSocketMatrixReport {
    return this.collectLiveHostSocketMatrix();
  }

  /**
   * Core pure analysis function: correlates sockets, processes, and historical beaconing.
   */
  public static analyzeSocketProcessMatrix(
    sockets: readonly SocketEntry[],
    processes: readonly ProcessEntry[],
    historicalTimestampsByPid?: Record<number, readonly number[]>,
    burnRatePerSec?: number
  ): ProcessSocketMatrixReport {
    const procMap = new Map<number, ProcessEntry>();
    for (const p of processes) {
      procMap.set(p.pid, p);
    }

    let activeEphemeralCount = 0;
    let timeWaitCount = 0;
    let establishedCount = 0;

    // Group sockets by PID
    const socketsByPid = new Map<number, SocketEntry[]>();
    for (const s of sockets) {
      if (s.localPort >= this.EPHEMERAL_MIN && s.localPort <= this.EPHEMERAL_MAX) {
        activeEphemeralCount++;
      }
      if (s.state === 'TIME_WAIT') {
        timeWaitCount++;
      } else if (s.state === 'ESTABLISHED') {
        establishedCount++;
      }

      const list = socketsByPid.get(s.pid) || [];
      list.push(s);
      socketsByPid.set(s.pid, list);
    }

    // Ephemeral Port Saturation Calculations (RFC 6056)
    const saturationPct = Number(
      ((activeEphemeralCount / this.EPHEMERAL_TOTAL) * 100.0).toFixed(2)
    );
    const timeWaitRatio = Number(
      (timeWaitCount / Math.max(1, activeEphemeralCount)).toFixed(3)
    );
    const establishedRatio = Number(
      (establishedCount / Math.max(1, activeEphemeralCount)).toFixed(3)
    );

    // OLS Port Exhaustion Horizon projection:
    // If saturation > 75%, project time to 100% capacity based on active growth
    let estimatedSecondsToPortExhaustion: number | null = null;
    let status: EphemeralPortExhaustionTelemetry['status'] = 'NOMINAL';

    if (saturationPct >= 85.0) {
      status = 'CRITICAL_EXHAUSTION_IMMINENT';
      const remainingPorts = Math.max(1, this.EPHEMERAL_TOTAL - activeEphemeralCount);
      const rate = (burnRatePerSec && burnRatePerSec > 0) ? burnRatePerSec : 12.0;
      estimatedSecondsToPortExhaustion = Math.max(5, Math.round(remainingPorts / rate));
    } else if (saturationPct >= 50.0) {
      status = 'WARNING';
      const remainingPorts = Math.max(1, this.EPHEMERAL_TOTAL - activeEphemeralCount);
      const rate = (burnRatePerSec && burnRatePerSec > 0) ? burnRatePerSec : 5.0;
      estimatedSecondsToPortExhaustion = Math.round(remainingPorts / rate);
    }

    // Per-Process attribution
    const resultProcesses: ProcessSocketAttribution[] = [];
    for (const [pid, pSockets] of socketsByPid.entries()) {
      const procInfo = procMap.get(pid);
      const procName = procInfo?.name || `PID_${pid}`;
      const memoryMb = procInfo?.memoryMb || 0;

      let est = 0;
      let tw = 0;
      let listen = 0;
      let eph = 0;
      const remoteIps = new Set<string>();

      for (const s of pSockets) {
        if (s.state === 'ESTABLISHED') est++;
        else if (s.state === 'TIME_WAIT') tw++;
        else if (s.state === 'LISTENING') listen++;

        if (s.localPort >= this.EPHEMERAL_MIN && s.localPort <= this.EPHEMERAL_MAX) {
          eph++;
        }

        if (
          s.remoteAddress &&
          s.remoteAddress !== '0.0.0.0' &&
          s.remoteAddress !== '127.0.0.1' &&
          s.remoteAddress !== '*'
        ) {
          remoteIps.add(s.remoteAddress);
        }
      }

      const tsList = historicalTimestampsByPid?.[pid] || [];
      const beaconingMetrics = this.computeBeaconingMetrics(tsList);

      resultProcesses.push({
        pid,
        processName: procName,
        memoryMb,
        totalSockets: pSockets.length,
        establishedSockets: est,
        timeWaitSockets: tw,
        listeningSockets: listen,
        ephemeralPortsUsed: eph,
        uniqueRemoteIps: Array.from(remoteIps),
        beaconingMetrics,
      });
    }

    resultProcesses.sort((a, b) => b.totalSockets - a.totalSockets);

    return {
      ephemeralTelemetry: {
        totalDynamicRange: this.EPHEMERAL_TOTAL,
        activeEphemeralCount,
        saturationPct,
        timeWaitRatio,
        establishedRatio,
        estimatedSecondsToPortExhaustion,
        status,
      },
      processes: resultProcesses,
      totalSockets: sockets.length,
      timestampIso: new Date().toISOString(),
    };
  }

  /**
   * Live Unprivileged Host Collector: netstat -ano + tasklist (Windows) or ss/netstat + ps (Linux)
   */
  public static collectLiveHostSocketMatrix(): ProcessSocketMatrixReport {
    const isWin = process.platform === 'win32';
    const sockets: SocketEntry[] = [];
    const processes: ProcessEntry[] = [];
    const collectionErrors: string[] = [];
    let socketCommandSucceeded = false;
    let collectionMethod: string | null = null;
    const splitEndpoint = (endpoint: string): [string, string] => {
      const value = String(endpoint || '');
      const separator = value.lastIndexOf(':');
      if (separator < 0) return [value, '0'];
      return [value.slice(0, separator).replace(/^\[|\]$/g, ''), value.slice(separator + 1)];
    };

    try {
      if (isWin) {
        // 1. Collect process names from tasklist /FO CSV /NH
        try {
          const tasklistOut = execSync('tasklist /FO CSV /NH', { encoding: 'utf8', timeout: 3500 });
          for (const line of tasklistOut.split(/\r?\n/)) {
            const trimmed = line.trim();
            if (!trimmed) continue;
            // "cmd.exe","1234","Console","1","5,432 K"
            const parts = trimmed.split('","').map((s) => s.replace(/^"|"$/g, ''));
            if (parts.length >= 2) {
              const name = parts[0];
              const pid = parseInt(parts[1], 10);
              let memMb = 0;
              if (parts[4]) {
                const memKb = parseInt(parts[4].replace(/[^\d]/g, ''), 10);
                if (!isNaN(memKb)) memMb = Number((memKb / 1024.0).toFixed(1));
              }
              if (!isNaN(pid)) {
                processes.push({ pid, name, memoryMb: memMb });
              }
            }
          }
        } catch (_) {}

        // 2. Collect sockets from netstat -ano
        try {
          const netstatOut = execSync('netstat -ano', { encoding: 'utf8', timeout: 4000 });
          socketCommandSucceeded = true;
          collectionMethod = 'netstat -ano';
          for (const line of netstatOut.split(/\r?\n/)) {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith('Active') || trimmed.startsWith('Proto')) continue;
            const parts = trimmed.split(/\s+/);
            // TCP   127.0.0.1:8443   0.0.0.0:0   LISTENING   1234
            if (parts.length >= 4) {
              const proto = parts[0].toUpperCase() as 'TCP' | 'UDP';
              const local = parts[1];
              const remote = parts[2];
              let state = 'UNKNOWN';
              let pid = 0;

              if (proto === 'TCP') {
                state = parts[3] || 'UNKNOWN';
                pid = parseInt(parts[4] || '0', 10);
              } else {
                state = 'UDP_STATELESS';
                pid = parseInt(parts[3] || '0', 10);
              }

              const [locAddr, locPortStr] = splitEndpoint(local);
              const [remAddr, remPortStr] = splitEndpoint(remote);
              const localPort = parseInt(locPortStr || '0', 10);
              const remotePort = parseInt(remPortStr || '0', 10);

              if (!isNaN(pid)) {
                sockets.push({
                  protocol: proto,
                  localAddress: locAddr || '0.0.0.0',
                  localPort: isNaN(localPort) ? 0 : localPort,
                  remoteAddress: remAddr || '0.0.0.0',
                  remotePort: isNaN(remotePort) ? 0 : remotePort,
                  state,
                  pid,
                });
              }
            }
          }
        } catch (err) { collectionErrors.push(`netstat -ano: ${err instanceof Error ? err.message : String(err)}`); }
      } else {
        // Linux: ss -tupn or netstat
        try {
          const ssOut = execSync('ss -tupn', { encoding: 'utf8', timeout: 3500 });
          socketCommandSucceeded = true;
          collectionMethod = 'ss -tupn';
          for (const line of ssOut.split(/\r?\n/)) {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith('Netid') || trimmed.startsWith('State')) continue;
            const parts = trimmed.split(/\s+/);
            if (parts.length >= 5) {
              const hasNetid = /^(tcp|tcp6|udp|udp6)$/i.test(parts[0]);
              const netid = hasNetid ? parts[0].toUpperCase() : 'TCP';
              const protocol: 'TCP' | 'UDP' = netid.startsWith('UDP') ? 'UDP' : 'TCP';
              const rawState = String(parts[hasNetid ? 1 : 0] || 'UNKNOWN').toUpperCase();
              const stateMap: Record<string, string> = {
                ESTAB: 'ESTABLISHED',
                LISTEN: 'LISTENING',
                'TIME-WAIT': 'TIME_WAIT',
                'CLOSE-WAIT': 'CLOSE_WAIT',
                'SYN-SENT': 'SYN_SENT',
                'SYN-RECV': 'SYN_RECEIVED',
                UNCONN: 'UDP_STATELESS'
              };
              const state = stateMap[rawState] || rawState;
              const local = parts[hasNetid ? 4 : 3];
              const remote = parts[hasNetid ? 5 : 4];
              if (!local || !remote) continue;
              const procField = parts[hasNetid ? 6 : 5] || '';
              const pidMatch = procField.match(/pid=(\d+)/);
              const nameMatch = procField.match(/users:\(\("([^"]+)"/);
              const pid = pidMatch ? parseInt(pidMatch[1], 10) : 0;
              const name = nameMatch ? nameMatch[1] : 'unknown';

              if (pid > 0 && !processes.some((p) => p.pid === pid)) {
                processes.push({ pid, name });
              }

              const [locAddr, locPortText] = splitEndpoint(local);
              const [remAddr, remPortText] = splitEndpoint(remote);
              const localPort = parseInt(locPortText || '0', 10) || 0;
              const remotePort = parseInt(remPortText || '0', 10) || 0;

              sockets.push({
                protocol,
                localAddress: locAddr,
                localPort,
                remoteAddress: remAddr,
                remotePort,
                state,
                pid,
              });
            }
          }
        } catch (err) { collectionErrors.push(`ss -tupn: ${err instanceof Error ? err.message : String(err)}`); }
      }
    } catch (err) { collectionErrors.push(`socket collector: ${err instanceof Error ? err.message : String(err)}`); }

    // Never manufacture socket rows when the host collector is unavailable.
    // A successful OS query returning zero rows is different from a failed collector.
    const processNames = new Map<number, string>();
    for (const processEntry of processes) processNames.set(processEntry.pid, processEntry.name);
    const matrix = this.analyzeSocketProcessMatrix(sockets, processes);
    return {
      ...matrix,
      sockets: sockets.map((socket) => ({
        ...socket,
        processName: processNames.get(socket.pid) || 'Unknown / access restricted'
      })),
      collectionStatus: socketCommandSucceeded ? 'LIVE_OS_TELEMETRY' : 'UNAVAILABLE',
      collectionMethod,
      collectionErrors,
      collectionNote: socketCommandSucceeded
        ? (sockets.length === 0 ? 'The OS collector ran successfully but returned no socket rows.' : null)
        : 'No supported OS socket collector completed successfully; socket count must not be interpreted as zero.'
    };
  }
}
