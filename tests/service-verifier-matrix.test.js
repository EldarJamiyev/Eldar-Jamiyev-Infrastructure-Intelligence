/**
 * EJII Enterprise Web & Mail Verifier and Two-Point Connectivity Matrix Test Suite
 * Validates real OS & network protocol layer 1-7 operations:
 * - Enterprise Web Service Verifier (DNS, TCP, TLS 1.3 certs, HTTP redirects & TTFB)
 * - Enterprise Mail Service Verifier (MX, SPF, DMARC, Raw Socket Banner Grabbing)
 * - Two-Point Connectivity Matrix (L1 Route, L2 ARP, L3 ICMP, L4 Socket, L5 App Banner)
 * - SQLite Historical Regression Engine & Azerbaijani Incident Standard
 */

const assert = require('assert');
const { verifyWebEndpoint, verifyMailEndpoint, isPrivateIp } = require('../src/protocols/service-verifier');
const { runConnectivityMatrix, getConnectivityHistory } = require('../src/network/routing/connectivity-matrix');
const { db } = require('../src/db/database');

async function runServiceVerifierMatrixTests() {
  console.log('--- Running Enterprise Web, Mail Verifier & Two-Point Connectivity Suite ---');

  // Test 1: Helper RFC1918 Private IP Classifier
  console.log('Testing RFC 1918 & CGNAT Private IP Detection...');
  assert.strictEqual(isPrivateIp('10.22.12.204'), true, '10.x.x.x must be private');
  assert.strictEqual(isPrivateIp('192.168.195.33'), true, '192.168.x.x must be private');
  assert.strictEqual(isPrivateIp('172.24.3.150'), true, '172.24.x.x must be private');
  assert.strictEqual(isPrivateIp('100.64.1.1'), true, '100.64.x.x CGNAT must be private');
  assert.strictEqual(isPrivateIp('8.8.8.8'), false, '8.8.8.8 is public');
  console.log('✓ RFC 1918 & CGNAT private IP classifier verified.');

  let targetHost = process.env.EJII_TEST_WEB_TARGET || 'taxes.gov.az';
  console.log(`Testing Enterprise Web Verifier on ${targetHost}...`);
  let webReport = null;
  const candidateTargets = [targetHost, 'google.com', 'cloudflare.com'];
  for (const candidate of candidateTargets) {
    for (let attempt = 1; attempt <= 3; attempt++) {
      webReport = await verifyWebEndpoint(candidate, { timeoutMs: 8000 });
      if (webReport && webReport.tcp && webReport.tcp.success && webReport.tls && webReport.tls.success && webReport.http && webReport.http.success && webReport.http.statusCode) {
        targetHost = candidate;
        break;
      }
      if (attempt < 3) await new Promise(r => setTimeout(r, 600));
    }
    if (webReport && webReport.tcp && webReport.tcp.success && webReport.tls && webReport.tls.success && webReport.http && webReport.http.success && webReport.http.statusCode) {
      break;
    }
    console.log(`Endpoint ${candidate} port 443 / HTTP unreachable or degraded on current network, falling back to next candidate...`);
  }
  assert.ok(webReport, 'Web report must exist');
  assert.strictEqual(webReport.hostname, targetHost);
  assert.strictEqual(webReport.dns.success, true, `DNS must resolve ${targetHost}`);
  assert.strictEqual(webReport.dns.ipv4.length > 0, true, 'IPv4 addresses must be present');
  assert.strictEqual(webReport.tcp.success, true, 'Port 443 must accept TCP connection');
  assert.ok(webReport.tcp.connectLatencyMs > 0, 'TCP connect latency must be recorded');
  assert.ok(webReport.tls, 'TLS audit must be performed');
  assert.strictEqual(webReport.tls.success, true, 'TLS handshake must succeed');
  assert.ok(webReport.tls.certificate, 'Certificate details must be extracted');
  assert.ok(webReport.http.statusCode >= 200, 'HTTP response must be received');
  assert.ok(webReport.helpdeskSummary.az.length > 20, 'Azerbaijani helpdesk summary must be generated');
  assert.ok(webReport.helpdeskSummary.en.length > 20, 'English helpdesk summary must be generated');
  console.log(`✓ Web Verifier passed: Status ${webReport.http.statusCode}, TCP: ${webReport.tcp.connectLatencyMs}ms, TLS: ${webReport.tls.protocol} (${webReport.tls.certificate.subjectCN}), Days: ${webReport.tls.certificate.daysRemaining}`);

  // Test 3: Real Enterprise Mail Service Verifier on mail.taxes.gov.az
  console.log('Testing Enterprise Mail Verifier & DNS Mail RFCs...');
  const mailReport = await verifyMailEndpoint('mail.taxes.gov.az', {
    timeoutMs: 1500,
    ports: [
      { port: 25, serviceType: 'SMTP' },
      { port: 587, serviceType: 'SUBMISSION' },
      { port: 443, serviceType: 'WEBMAIL' },
      { port: 110, serviceType: 'POP3' }
    ]
  });
  assert.ok(mailReport, 'Mail report must exist');
  assert.strictEqual(mailReport.dns.success, true, 'Mail host DNS must resolve');
  assert.strictEqual(mailReport.ports.length, 4, 'Must have probed 4 mail ports');
  assert.ok(['HEALTHY', 'WARNING', 'CRITICAL_ERROR'].includes(mailReport.verdict), 'Verdict must be valid enum');
  assert.ok(mailReport.helpdeskSummary.az.length > 20, 'Azerbaijani mail guidance must be generated');
  console.log(`✓ Mail Verifier passed: Verdict ${mailReport.verdict}, Probed ports: ${mailReport.ports.map(p => `${p.port}:${p.status}`).join(', ')}`);

    // Test 4: Two-Point Connectivity Matrix 5-Layer Stepper on taxes.gov.az
  console.log('Testing Two-Point Connectivity Matrix 5-Layer Stepper...');
  let matrixResult = null;
  const localHostIp = require('../src/network/routing/physical-network-detector').getPhysicalNetworkInfo().hostIp || '192.168.31.89';
  for (let attempt = 1; attempt <= 3; attempt++) {
    matrixResult = await runConnectivityMatrix(localHostIp, targetHost, 443, 'TCP', { timeoutMs: 6000 });
    if (matrixResult && matrixResult.status === 'OPEN') break;
    if (attempt < 3) await new Promise(r => setTimeout(r, 1000));
  }
  if (!matrixResult || matrixResult.status !== 'OPEN') {
    targetHost = 'google.com';
    matrixResult = await runConnectivityMatrix(localHostIp, targetHost, 443, 'TCP', { timeoutMs: 6000 });
  }
  assert.ok(matrixResult, 'Matrix result must exist');
  assert.strictEqual(matrixResult.status, 'OPEN', `${targetHost}:443 must be OPEN`);
  assert.strictEqual(matrixResult.port, 443);

  // Validate all 5 layers
  const st = matrixResult.stepper;
  assert.ok(st.layer1_route.success, 'Layer 1 routing must succeed');
  assert.ok(st.layer1_route.gatewayIp, 'Next hop gateway must be resolved');
  assert.ok(st.layer2_arp, 'Layer 2 ARP must be inspected');
  assert.ok(st.layer3_icmp, 'Layer 3 ICMP echo must be measured');
  assert.strictEqual(st.layer4_socket.status, 'OPEN', 'Layer 4 TCP socket must be OPEN');
  assert.ok(st.layer4_socket.latencyMs > 0, 'TCP connect latency must be positive');
  assert.ok(st.layer5_app.banner, 'Layer 5 application banner must be captured');
  assert.ok(matrixResult.helpdeskReport.az.includes(targetHost), `Azerbaijani report must include Destination ${targetHost}`);
  console.log(`✓ Two-Point Matrix passed: Status: ${matrixResult.status}, L1 Gateway: ${st.layer1_route.gatewayIp}, L2 Vendor: ${st.layer2_arp.vendor}, L3 Loss: ${st.layer3_icmp.lossPct}%, L4 RTT: ${st.layer4_socket.latencyMs}ms`);

  // Test 5: Firewall Block Detection (ETIMEDOUT) matching real corporate firewall log
  console.log('Testing Perimeter Firewall Drop Detection (ETIMEDOUT)...');
  const timeoutResult = await runConnectivityMatrix('10.168.195.33', '10.22.19.2', 8080, 'TCP', { timeoutMs: 1200 });
  assert.ok(timeoutResult, 'Timeout result must exist');
  assert.strictEqual(timeoutResult.status, 'TIMEOUT', 'Status must be TIMEOUT');
  assert.strictEqual(timeoutResult.errorCode, 'ETIMEDOUT', 'Error code must be ETIMEDOUT');
  assert.strictEqual(timeoutResult.verdict, 'FIREWALL_DROP', 'Verdict must identify firewall packet drop');
  assert.ok(timeoutResult.helpdeskReport.az.includes('ETIMEDOUT'), 'Report must mention ETIMEDOUT');
  console.log(`✓ Firewall Drop Detection passed: Caught ETIMEDOUT on 10.22.19.2:8080 (Verdict: ${timeoutResult.verdict})`);

  // Test 6: Historical Regression Baselining in SQLite
  console.log('Testing SQLite Historical Regression Detection...');
  // Seed a previous OPEN baseline for test host
  const testHost = '10.99.99.99';
  const testPort = 9443;
  
  db.prepare(`
    INSERT INTO connectivity_history (
      source_ip, destination_ip, port, protocol, status, error_code, latency_ms,
      stepper_summary, diagnostic_verdict, is_regression, regression_notes, timestamp
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    '10.168.195.33', testHost, testPort, 'TCP', 'OPEN', null, 5.2,
    JSON.stringify({}), 'HEALTHY', 0, null, new Date(Date.now() - 3600000).toISOString()
  );

  // Now run probe to closed port on loopback or unreachable test host to trigger regression
  const regResult = await runConnectivityMatrix('10.168.195.33', testHost, testPort, 'TCP', { timeoutMs: 1000 });
  assert.ok(regResult.regression.isRegression, 'Regression must be flagged when previously OPEN connection fails');
  assert.ok(regResult.regression.notes.includes('REGRESSION DETECTED'), 'Regression notes must be generated');

  // Verify getConnectivityHistory
  const history = getConnectivityHistory(10);
  assert.ok(history.length >= 2, 'History must contain recorded runs');
  const latestEntry = history.find(h => h.destination_ip === testHost);
  assert.ok(latestEntry, 'Latest test entry must be present in history');
  assert.strictEqual(latestEntry.is_regression, true, 'is_regression boolean must be true');
  console.log(`✓ SQLite Historical Regression Engine passed: Flagged ${regResult.regression.notes.slice(0, 75)}...`);

  console.log('--- Enterprise Web, Mail Verifier & Two-Point Connectivity Suite PASSED ---\n');
}

if (require.main === module) {
  runServiceVerifierMatrixTests().catch(err => {
    console.error(err);
    process.exit(1);
  });
}

module.exports = { runServiceVerifierMatrixTests };
