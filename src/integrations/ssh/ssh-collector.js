/**
 * EJI Remote Linux SSH Collector
 * Gathers genuine physical hardware and OS telemetry from remote Linux hosts
 * using the system OpenSSH client with non-interactive batch mode.
 */

const { execFile } = require('child_process');

/**
 * Execute command on remote host via OpenSSH client
 * @param {string} host 
 * @param {string} command 
 * @param {object} options 
 * @returns {Promise<{ stdout: string, stderr: string, exitCode: number }>}
 */
function runRemoteSsh(host, command, options = {}) {
  return new Promise((resolve) => {
    const user = options.username || options.user || 'root';
    const port = options.port || 22;
    const timeoutMs = options.timeoutMs || 8000;
    const keyPath = options.identityFile || options.keyPath;

    const args = [
      '-p', String(port),
      '-o', 'BatchMode=yes',
      '-o', 'StrictHostKeyChecking=accept-new',
      '-o', `ConnectTimeout=${Math.ceil(timeoutMs / 1000)}`,
      '-o', 'LogLevel=ERROR'
    ];

    if (keyPath) {
      args.push('-i', keyPath);
    }

    const destination = `${user}@${host}`;
    args.push(destination, command);

    execFile('ssh', args, { timeout: timeoutMs, windowsHide: true }, (error, stdout, stderr) => {
      resolve({
        stdout: stdout ? stdout.trim() : '',
        stderr: stderr ? stderr.trim() : '',
        exitCode: error ? (error.code || 1) : 0,
        error: error ? error.message : null
      });
    });
  });
}

/**
 * Collect complete system telemetry from remote Linux host
 * @param {string} host 
 * @param {object} options 
 * @returns {Promise<object>}
 */
async function collectLinuxMetrics(host, options = {}) {
  const cleanHost = (host || '').trim();
  if (!cleanHost) {
    return { success: false, host: cleanHost, error: 'Target host is required.' };
  }

  // Probe with compound remote command
  const probeScript = [
    'echo "===UNAME==="; uname -a',
    'echo "===LOADAVG==="; cat /proc/loadavg 2>/dev/null || uptime',
    'echo "===MEM==="; free -m 2>/dev/null',
    'echo "===DISK==="; df -hP -x tmpfs -x devtmpfs 2>/dev/null',
    'echo "===INTERFACES==="; ip -br a 2>/dev/null || ifconfig -s 2>/dev/null'
  ].join('; ');

  const result = await runRemoteSsh(cleanHost, probeScript, options);

  if (result.exitCode !== 0 && !result.stdout) {
    return {
      success: false,
      host: cleanHost,
      error: result.error || result.stderr || 'SSH connection failed or authentication rejected.',
      details: 'Ensure public key is present in ~/.ssh/authorized_keys and SSH port is reachable.'
    };
  }

  const sections = result.stdout.split('===');
  const telemetry = {
    success: true,
    host: cleanHost,
    collectedAt: new Date().toISOString(),
    os: 'Unknown Linux',
    kernel: 'Unknown',
    loadAvg: [0, 0, 0],
    memory: { totalMb: 0, usedMb: 0, freeMb: 0, usagePct: 0 },
    disks: [],
    interfaces: []
  };

  for (let i = 1; i < sections.length; i += 2) {
    const title = sections[i].trim();
    const content = (sections[i + 1] || '').trim();

    if (title === 'UNAME') {
      telemetry.kernel = content;
      if (content.includes('Linux')) telemetry.os = 'Linux';
    } else if (title === 'LOADAVG') {
      const parts = content.split(/\s+/);
      if (parts.length >= 3) {
        telemetry.loadAvg = [parseFloat(parts[0]) || 0, parseFloat(parts[1]) || 0, parseFloat(parts[2]) || 0];
      }
    } else if (title === 'MEM') {
      const lines = content.split('\n');
      for (const line of lines) {
        if (line.toLowerCase().startsWith('mem:')) {
          const cols = line.split(/\s+/);
          const total = parseInt(cols[1], 10) || 0;
          const used = parseInt(cols[2], 10) || 0;
          const free = parseInt(cols[3], 10) || 0;
          telemetry.memory = {
            totalMb: total,
            usedMb: used,
            freeMb: free,
            usagePct: total > 0 ? parseFloat(((used / total) * 100).toFixed(1)) : 0
          };
        }
      }
    } else if (title === 'DISK') {
      const lines = content.split('\n').slice(1);
      telemetry.disks = lines.map(line => {
        const parts = line.split(/\s+/);
        return {
          filesystem: parts[0],
          size: parts[1],
          used: parts[2],
          available: parts[3],
          usePct: parts[4],
          mountedOn: parts[5]
        };
      }).filter(d => d.filesystem && d.mountedOn);
    } else if (title === 'INTERFACES') {
      const lines = content.split('\n');
      telemetry.interfaces = lines.map(line => {
        const parts = line.split(/\s+/);
        return {
          name: parts[0],
          state: parts[1],
          ipAddresses: parts.slice(2).join(' ')
        };
      }).filter(iface => iface.name);
    }
  }

  return telemetry;
}

module.exports = {
  runRemoteSsh,
  collectLinuxMetrics
};
