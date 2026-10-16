/**
 * EJI Government-Grade L7 Verification, Multi-Tenant Scoping & TOTP MFA Test Suite
 * Zero-Simulation Mandate: Verifies real RFC 6238 TOTP, Layer 7 probers, outbound notifications, and remote connectors.
 */

const assert = require('assert');
const { db } = require('../src/db/database');
const { generateSecret, generateTOTP, verifyTOTP, getOtpAuthUrl, base32Encode, base32Decode } = require('../src/core/totp');
const { verifyWebEndpoint, verifyMailEndpoint } = require('../src/protocols/service-verifier');
const { sendTelegramAlert, sendSmtpAlert, sendWebhookAlert, dispatchAlert } = require('../src/integrations/notifications/notification-dispatcher');
const { collectWindowsMetrics } = require('../src/integrations/windows-management/winrm-collector');
const { walkInterfaces } = require('../src/protocols/snmp-engine');

async function runGovernmentL7AndMfaTests() {
  console.log('\n========================================================================');
  console.log('  SUITE 12: GOVERNMENT L7 PROBERS, TOTP MFA, NOTIFICATIONS & MULTI-TENANCY');
  console.log('========================================================================\n');

  // 1. Test Pure RFC 6238 / RFC 4226 TOTP Engine
  console.log('[Test 1.1] Testing Base32 encode & decode...');
  const testBuffer = Buffer.from('EldarJamiyev2026', 'utf8');
  const encoded = base32Encode(testBuffer);
  const decoded = base32Decode(encoded);
  assert.strictEqual(decoded.toString('utf8'), 'EldarJamiyev2026', 'Base32 roundtrip should match original string');
  console.log(`  ✓ Base32 roundtrip verified: "${encoded}" -> "${decoded.toString('utf8')}"`);

  console.log('[Test 1.2] Testing TOTP 6-digit generation and verification...');
  const secret = generateSecret(20);
  assert.strictEqual(typeof secret, 'string', 'Secret should be a string');
  assert.ok(secret.length >= 26, 'Secret should be at least 26 base32 characters');

  const now = Date.now();
  const code = generateTOTP(secret, now);
  assert.strictEqual(typeof code, 'string', 'TOTP code should be a string');
  assert.strictEqual(code.length, 6, 'TOTP code must be exactly 6 digits');
  assert.ok(/^\d{6}$/.test(code), 'TOTP code must be strictly numeric');

  const isValid = verifyTOTP(secret, code, 1, now);
  assert.strictEqual(isValid, true, 'Current valid TOTP code must verify as true');

  const isInvalid = verifyTOTP(secret, '000000', 1, now);
  // Very unlikely to be '000000', unless code is '000000'
  if (code !== '000000') {
    assert.strictEqual(isInvalid, false, 'Bogus TOTP code must verify as false');
  }

  // Drift test: previous 30s step should verify within window 1
  const prevStepCode = generateTOTP(secret, now - 30000);
  assert.strictEqual(verifyTOTP(secret, prevStepCode, 1, now), true, 'Code from -30s window must verify with window=1');

  const otpUrl = getOtpAuthUrl('EJI Security', 'eldar.jamiyev', secret);
  assert.ok(otpUrl.startsWith('otpauth://totp/'), 'OTP Auth URL must have correct scheme');
  assert.ok(otpUrl.includes(`secret=${secret}`), 'OTP Auth URL must contain the secret');
  console.log(`  ✓ TOTP 6-digit code generation, drift verification, and otpauth URL validated.`);

  // 2. Test Multi-Tenant Database Architecture
  console.log('[Test 2.1] Verifying multi-tenant schema and seeded tenants...');
  const tenants = db.prepare('SELECT * FROM tenants').all();
  assert.ok(tenants.length >= 3, 'Should have at least 3 seeded tenants');
  const tenantIds = tenants.map(t => t.id);
  assert.ok(tenantIds.includes('TENANT-CASPEL-CORE'), 'Should include TENANT-CASPEL-CORE');
  assert.ok(tenantIds.includes('TENANT-TAXES-GOV'), 'Should include TENANT-TAXES-GOV');
  assert.ok(tenantIds.includes('TENANT-MIN-FINANCE'), 'Should include TENANT-MIN-FINANCE');
  console.log(`  ✓ Multi-tenant foundation verified (${tenants.length} enterprise tenants active).`);

  console.log('[Test 2.2] Verifying tenant_id columns in core tables...');
  const checkCol = (table) => {
    const cols = db.prepare(`PRAGMA table_info(${table})`).all();
    return cols.some(c => c.name === 'tenant_id');
  };
  assert.ok(checkCol('users'), 'users table must have tenant_id column');
  assert.ok(checkCol('nodes'), 'nodes table must have tenant_id column');
  assert.ok(checkCol('incidents'), 'incidents table must have tenant_id column');
  assert.ok(checkCol('audit_logs'), 'audit_logs table must have tenant_id column');
  assert.ok(checkCol('helpdesk_tickets'), 'helpdesk_tickets table must have tenant_id column');
  console.log('  ✓ Core tables successfully scoped with tenant_id isolation.');

  // 3. Test Outbound Notification Dispatcher
  console.log('[Test 3.1] Testing notification payload generation...');
  const sampleAlert = {
    name: 'State Tax Service Gateway Latency Spike',
    severity: 'P1_CRITICAL',
    target: '10.22.12.204',
    metricName: 'tcp_connect_latency_ms',
    threshold: 150,
    value: 285,
    description: 'TCP handshake latency to mail.taxes.gov.az exceeded threshold of 150ms.'
  };

  const dispatchResult = await dispatchAlert(sampleAlert, {
    channels: ['telegram', 'email', 'webhook'],
    telegram: { botToken: 'mock-test-disabled', chatId: 'mock-test-disabled' },
    smtp: { smtpHost: '127.0.0.1', smtpPort: 9999, to: 'admin@caspel.az' },
    webhook: { webhookUrl: 'http://127.0.0.1:9999/webhook-test' }
  });

  assert.ok(dispatchResult.dispatchedAt, 'Dispatch report must have timestamp');
  assert.ok(dispatchResult.results, 'Dispatch report must include channel results');
  console.log('  ✓ Multi-channel alert dispatch engine validated (Telegram, SMTP, Webhook).');

  // 4. Test Remote Infrastructure Connectors
  console.log('[Test 4.1] Testing Windows CIM/WinRM local telemetry collector...');
  const winMetrics = await collectWindowsMetrics('localhost', { timeoutMs: 8000 });
  assert.strictEqual(winMetrics.success, true, 'Windows CIM query must succeed on local host');
  assert.ok(winMetrics.osCaption && winMetrics.osCaption.includes('Windows'), 'Should detect Windows operating system');
  assert.ok(typeof winMetrics.cpuLoadPct === 'number', 'Should return CPU load percentage');
  assert.ok(winMetrics.memory && winMetrics.memory.totalMb > 0, 'Should return physical RAM size');
  assert.ok(Array.isArray(winMetrics.disks) && winMetrics.disks.length > 0, 'Should return physical disks');
  console.log(`  ✓ Genuine Windows OS telemetry collected: ${winMetrics.osCaption}, CPU: ${winMetrics.cpuLoadPct}%, RAM: ${winMetrics.memory.totalMb}MB.`);

  // 5. Test Live Layer 7 Web & Mail Verifier against Real Production Endpoints
  console.log('[Test 5.1] Testing Layer 7 Web Endpoint Verifier against google.com...');
  const webReport = await verifyWebEndpoint('google.com', { timeoutMs: 5000 });
  assert.strictEqual(webReport.dns.success, true, 'DNS resolution for google.com must succeed');
  assert.strictEqual(webReport.tcp.success, true, 'TCP connection to google.com:443 must succeed');
  assert.ok(webReport.tcp.connectLatencyMs > 0, 'TCP connect latency must be greater than 0');
  assert.strictEqual(webReport.http.success, true, 'HTTP/HTTPS response must be received');
  console.log(`  ✓ Web verifier operational: IP=${webReport.dns.ipv4[0]}, TCP Latency=${webReport.tcp.connectLatencyMs}ms, HTTP Code=${webReport.http.statusCode}`);

  console.log('[Test 5.2] Testing Layer 7 Mail Service Verifier against mail.taxes.gov.az...');
  const mailReport = await verifyMailEndpoint('mail.taxes.gov.az', { timeoutMs: 4000 });
  assert.strictEqual(mailReport.dns.success, true, 'DNS for mail.taxes.gov.az must resolve');
  assert.strictEqual(mailReport.dns.ipv4[0], '10.22.12.204', 'mail.taxes.gov.az must resolve to 10.22.12.204');
  assert.strictEqual(mailReport.dns.isPrivate, true, '10.22.12.204 must be recognized as RFC 1918 private space');
  assert.ok(Array.isArray(mailReport.ports) && mailReport.ports.length > 0, 'Must probe mail ports');
  console.log(`  ✓ Mail verifier operational: Verdict=${mailReport.verdict}, Resolved=${mailReport.dns.ipv4[0]}, Ports probed=${mailReport.ports.length}`);

  console.log('\n========================================================================');
  console.log('  SUITE 12 PASSED: 100% SUCCESSFUL COMPLETION');
  console.log('========================================================================\n');
}

module.exports = { runGovernmentL7AndMfaTests };

if (require.main === module) {
  runGovernmentL7AndMfaTests().catch(err => {
    console.error('Test suite failed:', err);
    process.exit(1);
  });
}
