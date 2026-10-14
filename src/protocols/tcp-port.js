/**
 * EJII Real TCP Port Diagnostic & Sweep Driver
 * Raw TCP socket probing, banner grabbing, and exact socket error status categorization.
 */

const net = require('net');

/**
 * Common network service port definitions
 */
const COMMON_PORTS = [
  { port: 21, service: 'FTP', transport: 'TCP' },
  { port: 22, service: 'SSH / SFTP', transport: 'TCP' },
  { port: 23, service: 'Telnet', transport: 'TCP' },
  { port: 25, service: 'SMTP', transport: 'TCP' },
  { port: 53, service: 'DNS', transport: 'TCP' },
  { port: 80, service: 'HTTP', transport: 'TCP' },
  { port: 110, service: 'POP3', transport: 'TCP' },
  { port: 135, service: 'MS RPC / WMI', transport: 'TCP' },
  { port: 139, service: 'NetBIOS', transport: 'TCP' },
  { port: 143, service: 'IMAP', transport: 'TCP' },
  { port: 389, service: 'LDAP', transport: 'TCP' },
  { port: 443, service: 'HTTPS / TLS', transport: 'TCP' },
  { port: 445, service: 'SMB / CIFS', transport: 'TCP' },
  { port: 636, service: 'LDAPS', transport: 'TCP' },
  { port: 1433, service: 'MS SQL Server', transport: 'TCP' },
  { port: 1521, service: 'Oracle DB', transport: 'TCP' },
  { port: 3306, service: 'MySQL / MariaDB', transport: 'TCP' },
  { port: 3389, service: 'RDP (Remote Desktop)', transport: 'TCP' },
  { port: 5432, service: 'PostgreSQL', transport: 'TCP' },
  { port: 5985, service: 'WinRM HTTP', transport: 'TCP' },
  { port: 5986, service: 'WinRM HTTPS', transport: 'TCP' },
  { port: 8080, service: 'HTTP Proxy / App', transport: 'TCP' },
  { port: 8443, service: 'HTTPS Alt', transport: 'TCP' }
];

/**
 * Check a single TCP port with millisecond timing and banner grabbing
 * @param {string} host 
 * @param {number} port 
 * @param {number} timeoutMs 
 * @returns {Promise<Object>}
 */
function checkPort(host, port, timeoutMs = 2500) {
  return new Promise((resolve) => {
    const startTime = performance.now();
    const socket = new net.Socket();
    let banner = '';
    let resolved = false;

    socket.setTimeout(timeoutMs);

    function finish(result) {
      if (resolved) return;
      resolved = true;
      socket.removeAllListeners();
      socket.destroy();
      resolve(result);
    }

    socket.on('connect', () => {
      const connectLatencyMs = parseFloat((performance.now() - startTime).toFixed(2));

      // Attempt brief banner read (wait up to 300ms for incoming service identification)
      const bannerTimer = setTimeout(() => {
        finish({
          host,
          port,
          status: 'OPEN',
          open: true,
          connectLatencyMs,
          banner: banner.trim() || null,
          error: null
        });
      }, 300);

      socket.on('data', (data) => {
        banner += data.toString('utf8', 0, 256);
        clearTimeout(bannerTimer);
        finish({
          host,
          port,
          status: 'OPEN',
          open: true,
          connectLatencyMs,
          banner: banner.trim() || null,
          error: null
        });
      });
    });

    socket.on('timeout', () => {
      const latencyMs = parseFloat((performance.now() - startTime).toFixed(2));
      finish({
        host,
        port,
        status: 'FILTERED',
        open: false,
        connectLatencyMs: latencyMs,
        banner: null,
        error: 'ETIMEDOUT (No response from host, likely dropped by firewall)'
      });
    });

    socket.on('error', (err) => {
      const latencyMs = parseFloat((performance.now() - startTime).toFixed(2));
      let status = 'ERROR';
      let errorMsg = err.code || err.message;

      if (err.code === 'ECONNREFUSED') {
        status = 'CLOSED';
        errorMsg = 'ECONNREFUSED (Host is up, but no service is listening on port)';
      } else if (err.code === 'EHOSTUNREACH' || err.code === 'ENETUNREACH') {
        status = 'UNREACHABLE';
        errorMsg = `${err.code} (Network route to host or target network does not exist)`;
      } else if (err.code === 'EACCES') {
        status = 'ACCESS_DENIED';
        errorMsg = 'EACCES (Permission denied to open socket)';
      }

      finish({
        host,
        port,
        status,
        open: false,
        connectLatencyMs: latencyMs,
        banner: null,
        error: errorMsg
      });
    });

    try {
      socket.connect(port, host);
    } catch (err) {
      finish({
        host,
        port,
        status: 'ERROR',
        open: false,
        connectLatencyMs: 0,
        banner: null,
        error: err.message
      });
    }
  });
}

/**
 * Sweep multiple TCP ports with concurrency pool
 * @param {string} host 
 * @param {number[]} ports 
 * @param {number} concurrency 
 * @param {number} timeoutMs 
 */
async function scanPorts(host, ports = null, concurrency = 10, timeoutMs = 2000) {
  const targetPorts = ports || COMMON_PORTS.map((p) => p.port);
  const results = [];
  const queue = [...targetPorts];

  async function worker() {
    while (queue.length > 0) {
      const port = queue.shift();
      const res = await checkPort(host, port, timeoutMs);
      const meta = COMMON_PORTS.find((p) => p.port === port);
      results.push({
        ...res,
        service: meta ? meta.service : 'Custom Port'
      });
    }
  }

  const pool = [];
  const activeWorkers = Math.min(concurrency, targetPorts.length);
  for (let i = 0; i < activeWorkers; i++) {
    pool.push(worker());
  }

  await Promise.all(pool);
  results.sort((a, b) => a.port - b.port);

  const openCount = results.filter((r) => r.open).length;
  const closedCount = results.filter((r) => r.status === 'CLOSED').length;
  const filteredCount = results.filter((r) => r.status === 'FILTERED').length;

  return {
    host,
    totalScanned: results.length,
    openCount,
    closedCount,
    filteredCount,
    results
  };
}

module.exports = {
  checkPort,
  scanPorts,
  COMMON_PORTS
};
