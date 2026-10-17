/**
 * EJII Test Suite: Network Protocol Probes
 */

const assert = require('assert');
const { realPing } = require('../src/protocols/icmp-ping');
const { checkPort } = require('../src/protocols/tcp-port');
const { resolveRecord } = require('../src/protocols/dns-diag');
const { auditTls } = require('../src/protocols/tls-audit');
const { probeHttp } = require('../src/protocols/http-probe');

async function runNetworkTests() {
  console.log('\n--- Running Network Protocol Probes Test Suite ---');

  // Test 1: Real Ping Loopback
  console.log('Testing Real ICMP Ping (127.0.0.1)...');
  const pingRes = await realPing('127.0.0.1', 2, 1000);
  assert.strictEqual(pingRes.success, true, 'Loopback ping should succeed');
  assert.strictEqual(pingRes.packetLossPct, 0, 'Loopback ping should have 0% loss');
  assert.ok(typeof pingRes.avgRttMs === 'number', 'avgRttMs must be a number');
  console.log(`✓ Real Ping passed: RTT=${pingRes.avgRttMs}ms, Loss=${pingRes.packetLossPct}%`);

  // Test 2: Real TCP Port Socket (Closed port)
  console.log('Testing Real TCP Port Socket (127.0.0.1:64123 - expected closed)...');
  const portRes = await checkPort('127.0.0.1', 64123, 1000);
  assert.strictEqual(portRes.open, false, 'Unused port should be closed');
  assert.strictEqual(portRes.status, 'CLOSED', 'Status must be CLOSED (ECONNREFUSED)');
  assert.ok(portRes.connectLatencyMs >= 0, 'Connect latency must be measured');
  console.log(`✓ Real TCP Port check passed: Status=${portRes.status}, Error=${portRes.error}`);

  // Test 3: Real DNS Resolver (system resolver)
  console.log('Testing Real RFC 1035 DNS Resolver (google.com via default resolver)...');
  const dnsRes = await resolveRecord('google.com', 'A');
  assert.strictEqual(dnsRes.success, true, 'DNS resolution must succeed');
  assert.ok(dnsRes.records.length > 0, 'Must return at least one IP record');
  assert.ok(dnsRes.durationMs >= 0, 'DNS query duration must be non-negative');
  console.log(`✓ Real DNS Resolution passed: ${dnsRes.records.join(', ')} (${dnsRes.durationMs}ms, NS: ${dnsRes.nameserver})`);

  // Test 4: Real DNS Negative / Non-Existent Domain Case
  console.log('Testing Real DNS Error Capture (non-existent domain)...');
  const dnsFail = await resolveRecord('ejii-fake-domain-that-does-not-exist-98472.org', 'A');
  assert.strictEqual(dnsFail.success, false, 'Non-existent domain must fail');
  assert.ok(dnsFail.error.includes('ENOTFOUND') || dnsFail.error.includes('ESERVFAIL'), 'Must return DNS error code');
  console.log(`✓ Real DNS Error Capture passed: Handled cleanly with code ${dnsFail.error}`);

  // Test 5: Real TLS Security Audit
  console.log('Testing Real TLS Handshake & Cert Chain (google.com:443)...');
  let tlsRes = await auditTls('google.com', 443, 7000);
  if (!tlsRes.success) {
    // Retry once in case of transient Wi-Fi jitter
    tlsRes = await auditTls('google.com', 443, 7000);
  }
  assert.strictEqual(tlsRes.success, true, 'TLS audit must succeed on google.com');
  assert.ok(tlsRes.protocol.startsWith('TLSv1.'), 'Protocol must be TLS 1.2 or 1.3');
  assert.ok(tlsRes.certificate.daysRemaining > 0, 'Certificate must not be expired');
  assert.ok(tlsRes.certificate.sans.length > 0, 'SANs must be populated');
  console.log(`✓ Real TLS Audit passed: Protocol=${tlsRes.protocol}, Cipher=${tlsRes.cipher.name}, DaysLeft=${tlsRes.certificate.daysRemaining}`);

  // Test 6: Real HTTP Synthetic Probe
  console.log('Testing Real HTTP Synthetic Probe (https://google.com)...');
  let httpRes = await probeHttp('https://google.com', 'GET', 10000);
  if (!httpRes.success) {
    // Retry once in case of transient Wi-Fi/WAN route latency
    httpRes = await probeHttp('https://google.com', 'GET', 10000);
  }
  assert.strictEqual(httpRes.success, true, 'HTTP probe must succeed');
  assert.ok(httpRes.statusCode >= 200 && httpRes.statusCode < 400, 'Status code must be 2xx or 3xx');
  assert.ok(httpRes.waterfall.totalMs > 0, 'Waterfall total duration must be measured');
  console.log(`✓ Real HTTP Probe passed: Code=${httpRes.statusCode}, Total=${httpRes.waterfall.totalMs}ms, TTFB=${httpRes.waterfall.ttfbMs}ms`);

  console.log('--- Network Protocol Probes Test Suite PASSED ---\n');
}

if (require.main === module) {
  runNetworkTests().catch((err) => {
    console.error('Network Tests FAILED:', err);
    process.exit(1);
  });
}

module.exports = { runNetworkTests };
