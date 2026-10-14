/**
 * EJII Diagnostics API Routes
 * Targeted tools for Helpdesk Technicians & Administrators: real probes + plain-language explanation synthesis.
 */

const express = require('express');
const router = express.Router();
const { authenticate, requirePermission } = require('./middleware');
const { realPing, realTraceroute } = require('../protocols/icmp-ping');
const { checkPort } = require('../protocols/tcp-port');
const { resolveRecord } = require('../protocols/dns-diag');
const { probeHttp } = require('../protocols/http-probe');
const { logAction } = require('../core/audit-logger');

/**
 * Generate plain-language technical synthesis for helpdesk technicians & users
 */
function synthesizeExplanation({ probeType, target, result }) {
  let whatHappened = '';
  let whyItFailed = '';
  let recommendation = '';

  if (probeType === 'ping') {
    if (result.success && result.packetLossPct === 0) {
      whatHappened = `Host [${target}] is responding normally with an average latency of ${result.avgRttMs}ms.`;
      whyItFailed = 'No network failure detected.';
      recommendation = 'The network path to this system is healthy. If users cannot access the application, verify the application service/port itself.';
    } else if (result.packetLossPct === 100) {
      whatHappened = `Complete connectivity failure. Host [${target}] did not reply to any ping requests (100% packet loss).`;
      whyItFailed = 'The target computer or server is either powered off, disconnected from the local network, experiencing an OS crash, or blocking ICMP packets with a local firewall.';
      recommendation = '1. Check if the device is powered on.\n2. Verify the Ethernet cable or Wi-Fi connection.\n3. Ping the default gateway to confirm local switch reachability.';
    } else {
      whatHappened = `Degraded network connection to [${target}]. Experiencing ${result.packetLossPct}% packet loss and ${result.jitterMs}ms jitter.`;
      whyItFailed = 'Network congestion, faulty network cabling, duplex mismatch, or Wi-Fi signal interference.';
      recommendation = 'Investigate intermediate switches and Wi-Fi access points for interface packet drops.';
    }
  } else if (probeType === 'port') {
    if (result.status === 'OPEN') {
      whatHappened = `Port ${result.port} on [${target}] is open and accepting TCP network connections.`;
      whyItFailed = 'No port failure detected.';
      recommendation = 'The network socket is operational. You can test client application credentials.';
    } else if (result.status === 'CLOSED') {
      whatHappened = `Port ${result.port} on [${target}] rejected the connection (ECONNREFUSED).`;
      whyItFailed = 'The remote computer is online and reachable, but the specific software service assigned to port ' + result.port + ' is stopped or crashed.';
      recommendation = 'Log into the server and restart the service daemon (e.g. IIS, Apache, SQL Server, SSH).';
    } else if (result.status === 'FILTERED') {
      whatHappened = `Connection to port ${result.port} on [${target}] timed out with no response.`;
      whyItFailed = 'A hardware firewall, Windows Defender Firewall, or network security group is actively dropping traffic destined for this port.';
      recommendation = 'Inspect firewall inbound/outbound rules on both the host and intervening firewalls.';
    } else {
      whatHappened = `Unable to connect to port ${result.port}: ${result.error}`;
      whyItFailed = 'Route to destination host is unreachable.';
      recommendation = 'Verify routing table and default gateway status.';
    }
  } else if (probeType === 'dns') {
    if (result.success) {
      whatHappened = `Domain name [${target}] successfully resolved to IP addresses: ${result.records.join(', ')} in ${result.durationMs}ms.`;
      whyItFailed = 'DNS resolution is working correctly.';
      recommendation = 'Verify that the resolved IP address matches the intended production server.';
    } else {
      whatHappened = `Failed to resolve domain name [${target}]. Error code: ${result.error}.`;
      whyItFailed = 'The DNS name does not exist (NXDOMAIN), the DNS nameserver is unreachable, or the domain has expired.';
      recommendation = '1. Check the domain spelling.\n2. Test DNS resolution using 8.8.8.8 to verify if the issue is local to company DNS servers.\n3. Flush local DNS cache via Safe Automation.';
    }
  } else if (probeType === 'http') {
    if (result.success) {
      whatHappened = `Web service at [${target}] returned HTTP ${result.statusCode} (${result.statusMessage}) with a total response time of ${result.waterfall ? result.waterfall.totalMs : 0}ms.`;
      whyItFailed = 'Web server is operating normally.';
      recommendation = 'No corrective action required.';
    } else {
      whatHappened = `Web request failed: ${result.error || `HTTP ${result.statusCode}`}.`;
      whyItFailed = result.statusCode
        ? `The web server responded with error status ${result.statusCode}. This usually points to application runtime errors (500) or misconfigured routes (404/403).`
        : 'Could not complete HTTP handshake. Web server daemon is down or port 80/443 is blocked.';
      recommendation = 'Inspect web server application error logs and verify backend database connectivity.';
    }
  }

  return { whatHappened, whyItFailed, recommendation };
}

/**
 * POST /api/diagnostics/ping
 */
router.post('/ping', authenticate, requirePermission('diag:ping'), async (req, res) => {
  try {
    const { host, count = 4, timeoutMs = 2000 } = req.body;
    if (!host) return res.status(400).json({ error: 'Target host is required.' });

    const result = await realPing(host, count, timeoutMs);
    const explanation = synthesizeExplanation({ probeType: 'ping', target: host, result });

    logAction({
      userId: req.user.id,
      username: req.user.username,
      role: req.user.role,
      action: 'DIAGNOSTIC_PING',
      resource: host,
      details: `Ping probe: Status ${result.status}, Loss ${result.packetLossPct}%, Avg RTT: ${result.avgRttMs || 0}ms`
    });

    res.json({
      probe: 'ping',
      result,
      explanation
    });
  } catch (err) {
    res.status(500).json({ error: 'Ping probe failed: ' + err.message });
  }
});

/**
 * POST /api/diagnostics/traceroute
 */
router.post('/traceroute', authenticate, requirePermission('diag:traceroute'), async (req, res) => {
  try {
    const { host, maxHops = 15 } = req.body;
    if (!host) return res.status(400).json({ error: 'Target host is required.' });

    const result = await realTraceroute(host, maxHops);

    logAction({
      userId: req.user.id,
      username: req.user.username,
      role: req.user.role,
      action: 'DIAGNOSTIC_TRACEROUTE',
      resource: host,
      details: `Traceroute probe: Hops ${result.hopCount}, Success: ${result.success}`
    });

    res.json({
      probe: 'traceroute',
      result
    });
  } catch (err) {
    res.status(500).json({ error: 'Traceroute probe failed: ' + err.message });
  }
});

/**
 * POST /api/diagnostics/port
 */
router.post('/port', authenticate, requirePermission('diag:port_test'), async (req, res) => {
  try {
    const { host, port, timeoutMs = 2500 } = req.body;
    if (!host || !port) return res.status(400).json({ error: 'Host and port are required.' });

    const portNum = parseInt(port, 10);
    if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
      return res.status(400).json({ error: 'Port must be between 1 and 65535.' });
    }

    const result = await checkPort(host, portNum, timeoutMs);
    const explanation = synthesizeExplanation({ probeType: 'port', target: `${host}:${port}`, result });

    logAction({
      userId: req.user.id,
      username: req.user.username,
      role: req.user.role,
      action: 'DIAGNOSTIC_PORT',
      resource: `${host}:${portNum}`,
      details: `Port check: ${result.status} (${result.connectLatencyMs}ms)`
    });

    res.json({
      probe: 'port',
      result,
      explanation
    });
  } catch (err) {
    res.status(500).json({ error: 'Port check failed: ' + err.message });
  }
});

/**
 * POST /api/diagnostics/dns
 */
router.post('/dns', authenticate, requirePermission('diag:dns_test'), async (req, res) => {
  try {
    const { domain, recordType = 'A', nameserver = null } = req.body;
    if (!domain) return res.status(400).json({ error: 'Domain name is required.' });

    const result = await resolveRecord(domain, recordType, nameserver);
    const explanation = synthesizeExplanation({ probeType: 'dns', target: domain, result });

    logAction({
      userId: req.user.id,
      username: req.user.username,
      role: req.user.role,
      action: 'DIAGNOSTIC_DNS',
      resource: domain,
      details: `DNS lookup [${recordType}]: Success: ${result.success} in ${result.durationMs}ms`
    });

    res.json({
      probe: 'dns',
      result,
      explanation
    });
  } catch (err) {
    res.status(500).json({ error: 'DNS resolution failed: ' + err.message });
  }
});

/**
 * POST /api/diagnostics/http
 */
router.post('/http', authenticate, requirePermission('diag:http_check'), async (req, res) => {
  try {
    const { url, method = 'GET', timeoutMs = 5000 } = req.body;
    if (!url) return res.status(400).json({ error: 'Target URL is required.' });

    const result = await probeHttp(url, method, timeoutMs);
    const explanation = synthesizeExplanation({ probeType: 'http', target: url, result });

    logAction({
      userId: req.user.id,
      username: req.user.username,
      role: req.user.role,
      action: 'DIAGNOSTIC_HTTP',
      resource: url,
      details: `HTTP probe: Code ${result.statusCode || 'ERROR'} (${result.waterfall ? result.waterfall.totalMs : 0}ms)`
    });

    res.json({
      probe: 'http',
      result,
      explanation
    });
  } catch (err) {
    res.status(500).json({ error: 'HTTP probe failed: ' + err.message });
  }
});

/**
 * POST /api/diagnostics/explain
 */
router.post('/explain', authenticate, (req, res) => {
  const { probeType, target, result } = req.body;
  if (!probeType || !target || !result) {
    return res.status(400).json({ error: 'probeType, target, and result payload are required.' });
  }

  const explanation = synthesizeExplanation({ probeType, target, result });
  res.json({ explanation });
});

module.exports = router;
