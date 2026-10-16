/**
 * EJI Systems Process Forensics & Sockets Analyzer
 * Inspects live OS processes, listening network sockets, and security postures.
 */

const { execSync } = require('child_process');
const os = require('os');

class ProcessForensics {
  /**
   * Capture active OS processes
   */
  static getLiveProcessList(maxResults = 50) {
    const isWin = os.platform() === 'win32';
    const processes = [];

    if (isWin) {
      try {
        const output = execSync('tasklist /FO CSV /NH', { encoding: 'utf8', timeout: 4000, stdio: ['ignore', 'pipe', 'ignore'] });
        const lines = output.trim().split('\n');

        for (const line of lines) {
          const parts = line.split('","').map(p => p.replace(/"/g, '').trim());
          if (parts.length >= 5) {
            const memKStr = parts[4].replace(/[^0-9]/g, '');
            const memKb = parseInt(memKStr, 10) || 0;
            processes.push({
              imageName: parts[0],
              pid: parseInt(parts[1], 10),
              sessionName: parts[2],
              sessionNum: parts[3],
              memoryKb: memKb,
              memoryMb: Number((memKb / 1024).toFixed(1))
            });
          }
        }
      } catch (err) {
        // Fallback to current node process info
        processes.push({
          imageName: 'node.exe',
          pid: process.pid,
          sessionName: 'Console',
          sessionNum: '1',
          memoryKb: Math.round(process.memoryUsage().rss / 1024),
          memoryMb: Number((process.memoryUsage().rss / (1024 * 1024)).toFixed(1))
        });
      }
    } else {
      try {
        const output = execSync('ps -eo pid,comm,rss --no-headers', { encoding: 'utf8', timeout: 4000 });
        const lines = output.trim().split('\n');
        for (const line of lines) {
          const [pid, comm, rss] = line.trim().split(/\s+/);
          const memKb = parseInt(rss, 10) || 0;
          processes.push({
            imageName: comm,
            pid: parseInt(pid, 10),
            sessionName: 'pts',
            sessionNum: '0',
            memoryKb: memKb,
            memoryMb: Number((memKb / 1024).toFixed(1))
          });
        }
      } catch (err) {
        processes.push({
          imageName: 'node',
          pid: process.pid,
          sessionName: 'pts',
          sessionNum: '0',
          memoryKb: Math.round(process.memoryUsage().rss / 1024),
          memoryMb: Number((process.memoryUsage().rss / (1024 * 1024)).toFixed(1))
        });
      }
    }

    // Sort by memory usage descending
    processes.sort((a, b) => b.memoryKb - a.memoryKb);
    return processes.slice(0, maxResults);
  }

  /**
   * Capture active listening network sockets and their owning PIDs
   */
  static getListeningSockets() {
    const isWin = os.platform() === 'win32';
    const sockets = [];

    try {
      const cmd = isWin ? 'netstat -ano -p tcp' : 'ss -tulpn';
      const output = execSync(cmd, { encoding: 'utf8', timeout: 4000, stdio: ['ignore', 'pipe', 'ignore'] });
      const lines = output.trim().split('\n');

      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.includes('LISTENING') || trimmed.includes('LISTEN')) {
          const parts = trimmed.split(/\s+/);
          if (parts.length >= 5) {
            const localAddress = parts[1];
            const state = parts[3];
            const pid = parseInt(parts[4], 10);

            sockets.push({
              protocol: parts[0],
              localAddress,
              state,
              pid: isNaN(pid) ? null : pid
            });
          }
        }
      }
    } catch (e) {
      // In case netstat is restricted
    }

    return sockets;
  }

  /**
   * Run full process and socket security analysis
   */
  static analyzeSystemSecurity() {
    const processes = this.getLiveProcessList(30);
    const sockets = this.getListeningSockets();

    // Map listening ports to processes
    const socketMap = new Map();
    for (const s of sockets) {
      if (s.pid) {
        if (!socketMap.has(s.pid)) socketMap.set(s.pid, []);
        socketMap.get(s.pid).push(s.localAddress);
      }
    }

    const analyzed = processes.map(p => ({
      ...p,
      listeningSockets: socketMap.get(p.pid) || [],
      isNetworkBound: socketMap.has(p.pid)
    }));

    return {
      totalProcessesScanned: processes.length,
      listeningSocketsCount: sockets.length,
      analyzedAt: new Date().toISOString(),
      topMemoryProcesses: analyzed
    };
  }
}

module.exports = ProcessForensics;
