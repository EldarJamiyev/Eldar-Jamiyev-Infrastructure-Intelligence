/**
 * EJII Real ICMP Ping Diagnostic Driver
 * Executes genuine system ping with RTT, jitter, and packet loss parsing.
 */

const { exec } = require('child_process');
const { IS_WINDOWS } = require('../config');
const { isSafeNetworkTarget } = require('../core/security');

/**
 * Perform a real ICMP ping against a target host
 * @param {string} host - IP address or hostname
 * @param {number} count - Number of echo requests (default: 4)
 * @param {number} timeoutMs - Timeout per request in milliseconds (default: 2000)
 * @returns {Promise<Object>} Detailed diagnostic result
 */
function realPing(host, count = 4, timeoutMs = 2000) {
  return new Promise((resolve) => {
    if (!host || typeof host !== 'string' || !isSafeNetworkTarget(host)) {
      return resolve({
        success: false,
        host: host || '',
        error: 'Target rejected by SSRF defense policy or invalid format',
        raw: '',
        status: 'SECURITY_BLOCKED'
      });
    }

    // Sanitize host input to prevent command injection
    const sanitizedHost = host.trim().replace(/[^a-zA-Z0-9.-]/g, '');
    if (!sanitizedHost) {
      return resolve({
        success: false,
        host,
        error: 'Invalid hostname or IP address format.',
        raw: ''
      });
    }

    // Sanitize and strictly constrain integer parameters
    const safeCount = Math.min(Math.max(1, parseInt(count, 10) || 4), 20);
    const safeTimeoutMs = Math.min(Math.max(200, parseInt(timeoutMs, 10) || 2000), 15000);

    const startTime = Date.now();
    let cmd = '';

    if (IS_WINDOWS) {
      cmd = `ping.exe -n ${safeCount} -w ${safeTimeoutMs} ${sanitizedHost}`;
    } else {
      const timeoutSec = Math.max(1, Math.ceil(safeTimeoutMs / 1000));
      const intervalFlag = safeCount > 1 ? '-i 0.2 ' : '';
      cmd = `ping -c ${safeCount} ${intervalFlag}-W ${timeoutSec} ${sanitizedHost}`;
    }

    exec(cmd, { timeout: Math.min((safeCount * safeTimeoutMs) + 1200, 3500) }, (error, stdout, stderr) => {
      const durationMs = Date.now() - startTime;
      const raw = (stdout || '') + (stderr || '');

      // When running in an unprivileged POSIX container without kernel Npcap/libpcap raw tap,
      // mirror the genuine OS ICMP Echo probe into packetStreamer if active and matching BPF.
      try {
        const { packetStreamer } = require('../network/packet-streaming/packet-streamer');
        if (packetStreamer && packetStreamer.isStreaming && !packetStreamer.snifferProcess) {
          const bpf = (packetStreamer.bpfFilter || '').toLowerCase();
          if (!bpf || bpf.includes('icmp') || bpf.includes(sanitizedHost.toLowerCase())) {
            packetStreamer.recordKernelIcmpProbeFrame(sanitizedHost, safeCount, !error && Boolean(stdout));
          }
        }
      } catch (_) {}

      if (!stdout && error) {
        return resolve({
          success: false,
          host: sanitizedHost,
          durationMs,
          packetsSent: safeCount,
          packetsReceived: 0,
          packetLossPct: 100,
          minRttMs: null,
          maxRttMs: null,
          avgRttMs: null,
          jitterMs: null,
          status: 'UNREACHABLE',
          error: error.message,
          raw
        });
      }

      // Parse Windows Ping output
      if (IS_WINDOWS) {
        // Sent = 4, Received = 4, Lost = 0 (0% loss)
        const lossMatch = raw.match(/Lost\s*=\s*\d+\s*\((\d+)%\s*loss\)/i);
        const sentMatch = raw.match(/Sent\s*=\s*(\d+)/i);
        const receivedMatch = raw.match(/Received\s*=\s*(\d+)/i);
        
        // Minimum = 14ms, Maximum = 18ms, Average = 16ms
        const rttMatch = raw.match(/Minimum\s*=\s*(\d+)ms,\s*Maximum\s*=\s*(\d+)ms,\s*Average\s*=\s*(\d+)ms/i);

        const packetsSent = sentMatch ? parseInt(sentMatch[1], 10) : count;
        const packetsReceived = receivedMatch ? parseInt(receivedMatch[1], 10) : 0;
        const packetLossPct = lossMatch ? parseInt(lossMatch[1], 10) : (packetsReceived === 0 ? 100 : 0);

        let minRttMs = null;
        let maxRttMs = null;
        let avgRttMs = null;
        let jitterMs = null;

        if (rttMatch) {
          minRttMs = parseInt(rttMatch[1], 10);
          maxRttMs = parseInt(rttMatch[2], 10);
          avgRttMs = parseInt(rttMatch[3], 10);
          jitterMs = maxRttMs - minRttMs;
        } else if (raw.includes('time<1ms')) {
          minRttMs = 0;
          maxRttMs = 0;
          avgRttMs = 0;
          jitterMs = 0;
        }

        const success = packetsReceived > 0;
        let status = 'HEALTHY';
        if (packetLossPct === 100) status = 'DOWN';
        else if (packetLossPct > 0 || (avgRttMs && avgRttMs > 150)) status = 'DEGRADED';

        return resolve({
          success,
          host: sanitizedHost,
          durationMs,
          packetsSent,
          packetsReceived,
          packetLossPct,
          minRttMs,
          maxRttMs,
          avgRttMs,
          jitterMs,
          status,
          raw
        });
      }

      // Parse Linux/POSIX Ping output
      const lossMatch = raw.match(/(\d+)%\s*packet loss/i);
      const rttMatch = raw.match(/(?:rtt|round-trip)\s*min\/avg\/max\/(?:mdev|stddev)\s*=\s*([\d.]+)\/([\d.]+)\/([\d.]+)\/([\d.]+)\s*ms/i);

      const packetLossPct = lossMatch ? parseInt(lossMatch[1], 10) : (error ? 100 : 0);
      let minRttMs = null;
      let maxRttMs = null;
      let avgRttMs = null;
      let jitterMs = null;

      if (rttMatch) {
        minRttMs = parseFloat(rttMatch[1]);
        avgRttMs = parseFloat(rttMatch[2]);
        maxRttMs = parseFloat(rttMatch[3]);
        jitterMs = parseFloat(rttMatch[4]);
      }

      const packetsReceived = Math.round(count * (1 - packetLossPct / 100));
      const success = packetsReceived > 0;

      let status = 'HEALTHY';
      if (packetLossPct === 100) status = 'DOWN';
      else if (packetLossPct > 0 || (avgRttMs && avgRttMs > 150)) status = 'DEGRADED';

      resolve({
        success,
        host: sanitizedHost,
        durationMs,
        packetsSent: count,
        packetsReceived,
        packetLossPct,
        minRttMs,
        maxRttMs,
        avgRttMs,
        jitterMs,
        status,
        raw
      });
    });
  });
}

/**
 * Execute real system traceroute
 * @param {string} host 
 * @param {number} maxHops 
 */
function realTraceroute(host, maxHops = 15) {
  return new Promise((resolve) => {
    const sanitizedHost = host.trim().replace(/[^a-zA-Z0-9.-]/g, '');
    if (!sanitizedHost) {
      return resolve({ success: false, error: 'Invalid host', hops: [] });
    }

    const safeMaxHops = Math.min(Math.max(1, parseInt(maxHops, 10) || 15), 32);

    const cmd = IS_WINDOWS
      ? `tracert.exe -d -h ${safeMaxHops} -w 1000 ${sanitizedHost}`
      : `traceroute -n -m ${safeMaxHops} -w 1 ${sanitizedHost}`;

    exec(cmd, { timeout: 35000 }, (error, stdout, stderr) => {
      const raw = (stdout || '') + (stderr || '');
      const hops = [];
      const lines = raw.split('\n');

      for (const line of lines) {
        // Windows format: "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
        const winHop = line.trim().match(/^(\d+)\s+([<\d\s*ms]+)\s+([0-9a-fA-F:.]+)/);
        if (winHop) {
          const hopNumber = parseInt(winHop[1], 10);
          const ip = winHop[3];
          hops.push({
            hop: hopNumber,
            ip,
            rawDetails: winHop[2].trim()
          });
        }
      }

      resolve({
        success: hops.length > 0,
        host: sanitizedHost,
        hopCount: hops.length,
        hops,
        raw
      });
    });
  });
}

async function pingHost(host, options = {}) {
  const timeoutMs = options.timeoutMs || 1000;
  const count = options.count || 1;
  const res = await realPing(host, count, timeoutMs);
  return {
    alive: Boolean(res && res.success),
    success: Boolean(res && res.success),
    rttMs: res.avgRttMs,
    timeMs: res.avgRttMs,
    raw: res.raw,
    packetLossPct: res.packetLossPct
  };
}

module.exports = {
  realPing,
  pingHost,
  realTraceroute
};
