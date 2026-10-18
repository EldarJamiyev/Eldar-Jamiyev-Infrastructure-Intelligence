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
const { verifyWebEndpoint, verifyMailEndpoint } = require('../protocols/service-verifier');
const { runConnectivityMatrix, getConnectivityHistory } = require('../network/routing/connectivity-matrix');
const { logAction } = require('../core/audit-logger');
const { diagnosticReasoningEngine } = require('../core/rca-engine');

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

// Government & Critical Enterprise Target Catalog
const GOVERNMENT_TARGETS = [
  { hostname: 'mail.taxes.gov.az', name: 'State Tax Service Webmail & Relay', agency: 'State Tax Service (DVX)', category: 'MAIL', defaultPort: 443 },
  { hostname: 'hesabat.taxes.gov.az', name: 'Electronic Tax Declarations Portal (BTP/EVHF)', agency: 'State Tax Service (DVX)', category: 'WEB', defaultPort: 443 },
  { hostname: 'e-qanun.az', name: 'Unified Database of Legal Acts (E-Qanun)', agency: 'Ministry of Justice (Ədliyyə Nazirliyi)', category: 'WEB', defaultPort: 443 },
  { hostname: 'ccms.taxes.gov.az', name: 'Centralized Call Center Management System', agency: 'State Tax Service (DVX)', category: 'WEB', defaultPort: 443 },
  { hostname: 'avis.taxes.gov.az', name: 'Automated Tax Information System (AVIS)', agency: 'State Tax Service (DVX)', category: 'WEB', defaultPort: 443 },
  { hostname: 'taxes.gov.az', name: 'State Tax Service Official Web Portal', agency: 'State Tax Service (DVX)', category: 'WEB', defaultPort: 443 },
  { hostname: 'e-gov.az', name: 'Electronic Government Portal', agency: 'Innovation and Digital Development Agency', category: 'WEB', defaultPort: 443 },
  { hostname: 'customs.gov.az', name: 'State Customs Committee Portal', agency: 'State Customs Committee', category: 'WEB', defaultPort: 443 }
];

/**
 * GET /api/diagnostics/gov-targets
 */
router.get('/gov-targets', authenticate, (req, res) => {
  res.json({ targets: GOVERNMENT_TARGETS });
});

/**
 * POST /api/diagnostics/verify-web & POST /api/diagnostics/web
 */
async function handleWebVerification(req, res) {
  try {
    const url = req.body.url || req.body.target || req.body.host;
    if (!url) return res.status(400).json({ error: 'Target URL or hostname is required.' });

    const safeTimeout = Math.min(Math.max(1000, parseInt(req.body.timeoutMs, 10) || 5000), 15000);
    const safeRedirects = Math.min(Math.max(1, parseInt(req.body.maxRedirects, 10) || 5), 10);

    const report = await verifyWebEndpoint(url, { timeoutMs: safeTimeout, maxRedirects: safeRedirects });

    // Attach government target intelligence if recognized
    const cleanHost = (report.hostname || '').toLowerCase();
    const matchedGov = GOVERNMENT_TARGETS.find(g => cleanHost.includes(g.hostname.toLowerCase()));
    if (matchedGov) {
      report.governmentIntel = matchedGov;
    }

    logAction({
      userId: req.user.id,
      username: req.user.username,
      role: req.user.role,
      action: 'DIAGNOSTIC_VERIFY_WEB',
      resource: url,
      details: `Web Verification: Verdict ${report.verdict}, Code: ${report.http.statusCode || 'FAIL'}, TCP: ${report.tcp.connectLatencyMs}ms`
    });

    res.json(report);
  } catch (err) {
    res.status(500).json({ error: 'Web verification failed: ' + err.message });
  }
}

router.post('/verify-web', authenticate, requirePermission('diag:verify_service'), handleWebVerification);
router.post('/web', authenticate, requirePermission('diag:verify_service'), handleWebVerification);

/**
 * POST /api/diagnostics/verify-mail & POST /api/diagnostics/mail
 */
async function handleMailVerification(req, res) {
  try {
    const host = req.body.host || req.body.target || req.body.url || 'mail.taxes.gov.az';
    if (!host) return res.status(400).json({ error: 'Target mail host or domain is required.' });

    const safeTimeout = Math.min(Math.max(1000, parseInt(req.body.timeoutMs, 10) || 3500), 10000);
    const report = await verifyMailEndpoint(host, { timeoutMs: safeTimeout });

    // Attach government target intelligence if recognized
    const cleanHost = (report.host || host || '').toLowerCase();
    const matchedGov = GOVERNMENT_TARGETS.find(g => cleanHost.includes(g.hostname.toLowerCase()));
    if (matchedGov) {
      report.governmentIntel = matchedGov;
    }

    logAction({
      userId: req.user.id,
      username: req.user.username,
      role: req.user.role,
      action: 'DIAGNOSTIC_VERIFY_MAIL',
      resource: host,
      details: `Mail Verification: Verdict ${report.verdict}, Open ports: ${report.ports.filter(p => p.status === 'OPEN').map(p => p.port).join(', ') || 'None'}`
    });

    res.json(report);
  } catch (err) {
    res.status(500).json({ error: 'Mail verification failed: ' + err.message });
  }
}

router.post('/verify-mail', authenticate, requirePermission('diag:verify_service'), handleMailVerification);
router.post('/mail', authenticate, requirePermission('diag:verify_service'), handleMailVerification);

/**
 * POST /api/diagnostics/connectivity-matrix
 */
router.post('/connectivity-matrix', authenticate, requirePermission('diag:connectivity_matrix'), async (req, res) => {
  try {
    const { sourceIp, destination, port, protocol = 'TCP', timeoutMs = 3000 } = req.body;
    if (!destination || !port) {
      return res.status(400).json({ error: 'Destination IP/host and port are required.' });
    }

    const safeTimeout = Math.min(Math.max(500, parseInt(timeoutMs, 10) || 3000), 10000);
    const result = await runConnectivityMatrix(sourceIp, destination, port, protocol, { timeoutMs: safeTimeout });

    logAction({
      userId: req.user.id,
      username: req.user.username,
      role: req.user.role,
      action: 'NETWORK_CONNECTIVITY_MATRIX',
      resource: `${destination}:${port}`,
      details: `Matrix Probe: Status ${result.status}, Error: ${result.errorCode || 'NONE'}, Regression: ${result.regression.isRegression}`
    });

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Connectivity matrix probe failed: ' + err.message });
  }
});

/**
 * GET /api/diagnostics/connectivity-history
 */
router.get('/connectivity-history', authenticate, requirePermission('diag:connectivity_matrix'), (req, res) => {
  try {
    const limit = parseInt(req.query.limit, 10) || 50;
    const history = getConnectivityHistory(limit);
    res.json({ history });
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve connectivity history: ' + err.message });
  }
});
/**
 * POST /api/diagnostics/analyze-incident
 * Evaluates network telemetry and produces Dual-Tier Experience:
 * 1. Simple Operator Mode (copyable incident briefing, non-jargon explanation)
 * 2. Expert Diagnostic Mode (RFC dissection, 5-tuple, sequence tracking, distinguishing tests)
 */
router.post('/analyze-incident', authenticate, (req, res) => {
  try {
    const analysis = diagnosticReasoningEngine.analyzeIncident(req.body);
    res.json({ success: true, ...analysis });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Incident analysis failed: ' + err.message });
  }
});

/**
 * POST /api/diagnostics/run-distinguishing-test
 * Executes an automated distinguishing probe (ping, TCP port check, external DNS query)
 */
router.post('/run-distinguishing-test', authenticate, async (req, res) => {
  try {
    const { testId, target, probeType } = req.body;
    if (!target) return res.status(400).json({ error: 'Probe target is required.' });

    let probeResult = null;
    if (probeType === 'ping' || probeType === 'ping_mtu') {
      probeResult = await realPing(target, 2, 1500);
    } else if (probeType === 'port') {
      const parts = target.split(':');
      const host = parts[0];
      const port = parseInt(parts[1] || '80', 10);
      probeResult = await checkPort(host, port, 1500);
    } else if (probeType === 'dns_external') {
      probeResult = await resolveRecord(target, 'A', { timeoutMs: 2000 });
    } else {
      probeResult = await realPing(target, 1, 1000);
    }

    res.json({
      success: true,
      testId,
      target,
      probeType,
      executedAt: new Date().toISOString(),
      result: probeResult
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Distinguishing probe failed: ' + err.message });
  }
});

/**
 * GET /api/diagnostics/api-telemetry
 * Returns API request correlation and latency telemetry
 */
router.get('/api-telemetry', authenticate, (req, res) => {
  try {
    const { getApiTelemetry } = require('./middleware');
    const telemetry = getApiTelemetry();
    res.json({
      success: true,
      telemetry,
      ...telemetry
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
