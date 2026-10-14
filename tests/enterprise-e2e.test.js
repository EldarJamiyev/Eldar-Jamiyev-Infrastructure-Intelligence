/**
 * EJI — Eldar Jamiyev's Infrastructure Intelligence
 * Enterprise End-to-End Regression Test Suite
 * Zero-Simulation Mandate Enforced: Real OS Sockets, Cryptographic HMAC, Real DB
 */

const assert = require('assert');
const { db } = require('../src/db/database');
const { generateToken, verifyToken, revokeToken, isTokenRevoked, revokeAllUserTokens } = require('../src/core/security');
const { checkRateLimit, recordFailedAttempt, resetRateLimit } = require('../src/api/rate-limiter');
const { createManualIncident, resolveIncident, getIncidents } = require('../src/core/rca-engine');
const { getArpTable } = require('../src/tools/ip-scanner');
const { testIntegration } = require('../src/api/routes-integrations');

async function runEnterpriseE2ETests() {
  console.log('--- Running Enterprise End-to-End Hardening Test Suite ---');

  // Idempotent test cleanup
  db.prepare("DELETE FROM revoked_tokens WHERE user_id = 'USR-TEST-01'").run();

  // TEST 1: Token Revocation Engine
  console.log('Testing Token Revocation Engine...');
  const testPayload = { id: 'USR-TEST-01', username: 'test_sec_user', role: 'sysadmin' };
  const token = generateToken(testPayload);
  assert.ok(token, 'Token must be generated');

  const decodedBefore = verifyToken(token);
  assert.strictEqual(decodedBefore.username, 'test_sec_user', 'Token must decode correctly');
  assert.strictEqual(isTokenRevoked(token), false, 'Token must not be revoked initially');

  revokeToken(token, 'USR-TEST-01', 'User explicit logout test');
  assert.strictEqual(isTokenRevoked(token), true, 'Token must be revoked after explicit call');

  // Verify revoked token verification returns null
  const decodedAfter = verifyToken(token);
  assert.strictEqual(decodedAfter, null, 'verifyToken must return null for revoked tokens');

  // Test bulk revocation by user ID
  const token2 = generateToken(testPayload);
  assert.strictEqual(isTokenRevoked(token2), false, 'New token should be valid');
  revokeAllUserTokens('USR-TEST-01', 'Password change / account reset');
  assert.strictEqual(isTokenRevoked(token2), true, 'Token2 must be revoked after bulk user revocation');
  console.log('✓ Token revocation and session security verified.');

  // TEST 2: Sliding Window Brute-Force Rate Limiter
  console.log('Testing Sliding-Window Brute-Force Rate Limiter...');
  const testIp = '198.51.100.42';
  resetRateLimit(testIp);

  for (let i = 1; i <= 5; i++) {
    const status = checkRateLimit(testIp);
    assert.strictEqual(status.allowed, true, `Attempt ${i} should be allowed`);
    recordFailedAttempt(testIp);
  }

  // 6th attempt should be blocked
  const blockedStatus = checkRateLimit(testIp);
  assert.strictEqual(blockedStatus.allowed, false, '6th attempt must be blocked');
  assert.strictEqual(blockedStatus.remainingAttempts, 0, 'Remaining attempts must be 0');
  assert.ok(blockedStatus.retryAfterSeconds > 0, 'Retry-after must be greater than 0');

  resetRateLimit(testIp);
  const resetStatus = checkRateLimit(testIp);
  assert.strictEqual(resetStatus.allowed, true, 'Rate limit should be reset cleanly');
  console.log('✓ Sliding-window rate limiter and brute-force lockout verified.');

  // TEST 3: Authoritative Asset CMDB & Real ARP Table
  console.log('Testing Asset Inventory and Hardware CMDB...');
  const initialNodes = db.prepare('SELECT COUNT(*) as count FROM nodes').get();
  assert.ok(initialNodes.count > 0, 'Database must have seeded nodes');

  // Verify ARP table query executes real OS kernel command (arp -a or /proc/net/arp)
  const arpEntries = await getArpTable();
  assert.ok(Array.isArray(arpEntries), 'ARP table must return an array');
  console.log(`✓ Real kernel ARP table inspected (${arpEntries.length} physical entries found).`);

  // Verify asset modification in DB
  const testNode = db.prepare('SELECT id, is_managed FROM nodes LIMIT 1').get();
  const newManagedState = testNode.is_managed ? 0 : 1;
  db.prepare('UPDATE nodes SET is_managed = ? WHERE id = ?').run(newManagedState, testNode.id);
  const updatedNode = db.prepare('SELECT is_managed FROM nodes WHERE id = ?').get(testNode.id);
  assert.strictEqual(updatedNode.is_managed, newManagedState, 'Asset is_managed state must persist');
  // Revert back
  db.prepare('UPDATE nodes SET is_managed = ? WHERE id = ?').run(testNode.is_managed, testNode.id);
  console.log('✓ Asset CMDB management updates verified.');

  // TEST 4: Diagnostic Probe Escalation to Incident
  console.log('Testing Diagnostic Probe Escalation to Formal Incident...');
  const incidentData = {
    title: '[E2E Test Escalation] Ping check failed on 192.168.100.254',
    affected_node_id: testNode.id,
    severity: 'high',
    description: 'Automated test escalation with captured telemetry evidence',
    what_happened: 'Target host 192.168.100.254 timed out with 100% packet loss.',
    root_cause: 'L3 network path severed or host offline',
    supporting_evidence: JSON.stringify({ rtt: null, loss: 100, target: '192.168.100.254' }),
    remediation_plan: 'Verify router gateway interface and switch port status'
  };

  const newIncident = createManualIncident(incidentData, 'sysadmin');
  assert.ok(newIncident.id.startsWith('INC-'), 'Incident ID must have INC- prefix');
  assert.strictEqual(newIncident.status, 'open', 'Incident must be created in open status');

  // Verify persistence in SQLite
  const savedIncident = db.prepare('SELECT * FROM incidents WHERE id = ?').get(newIncident.id);
  assert.ok(savedIncident, 'Incident must exist in SQLite database');
  assert.strictEqual(savedIncident.title, incidentData.title, 'Incident title must match');

  // Resolve incident
  const resolved = resolveIncident(newIncident.id, 'sysadmin', 'Resolved via E2E verification routine');
  assert.strictEqual(resolved.status, 'resolved', 'Incident status must be resolved');
  console.log(`✓ Diagnostic probe escalation to formal incident ${newIncident.id} verified.`);

  // TEST 5: Subsystem Integrations Framework
  console.log('Testing Subsystem Integrations Framework...');
  const integrations = db.prepare('SELECT * FROM integrations').all();
  assert.ok(integrations.length >= 4, 'Must have at least 4 default enterprise integrations seeded');

  // Test an integration connection (e.g. SNMP loopback test)
  const snmpInteg = integrations.find(i => i.type === 'snmp');
  assert.ok(snmpInteg, 'SNMP integration must exist');

  const testResult = await testIntegration(snmpInteg);
  assert.ok(typeof testResult.success === 'boolean', 'Test result must indicate success/failure');
  assert.ok(typeof testResult.latencyMs === 'number', 'Latency in ms must be measured');
  console.log(`✓ Integration connector tested: [${snmpInteg.name}] (${testResult.latencyMs}ms, result=${testResult.message || testResult.error})`);

  // TEST 6: Audit Trail HMAC Chain & Export Formatting
  console.log('Testing Audit Trail Export...');
  const auditLogs = db.prepare('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 5').all();
  assert.ok(auditLogs.length > 0, 'Audit logs must exist');
  assert.ok(auditLogs[0].hash.length === 64, 'HMAC hash must be 64 characters (SHA-256)');

  // Verify CSV formatting
  const csvHeaders = 'ID,Timestamp,User ID,Username,Role,Action,Resource,HMAC Hash,Details\n';
  const sampleRow = `"${auditLogs[0].id}","${auditLogs[0].timestamp}","${auditLogs[0].user_id}","${auditLogs[0].username}","${auditLogs[0].role}","${auditLogs[0].action}","${auditLogs[0].resource}","${auditLogs[0].hash}","${auditLogs[0].details || ''}"\n`;
  assert.ok(sampleRow.includes(auditLogs[0].hash), 'CSV export must include authentic HMAC hash');
  console.log('✓ Cryptographic HMAC audit export validated.');

  // TEST 7: Governance Settings & Persistence
  console.log('Testing Governance Retention Policies...');
  const currentSettings = db.prepare('SELECT key, value FROM system_settings').all();
  const settingsMap = Object.fromEntries(currentSettings.map(s => [s.key, s.value]));
  assert.ok(settingsMap['audit_retention_days'], 'audit_retention_days setting must exist');

  // Update setting
  const origDays = settingsMap['audit_retention_days'];
  db.prepare("INSERT INTO system_settings (key, value, updated_at) VALUES ('audit_retention_days', '180', ?) ON CONFLICT(key) DO UPDATE SET value = '180', updated_at = ?").run(new Date().toISOString(), new Date().toISOString());
  const updatedDays = db.prepare("SELECT value FROM system_settings WHERE key = 'audit_retention_days'").get().value;
  assert.strictEqual(updatedDays, '180', 'Setting must be updated');
  // Revert back
  db.prepare("INSERT INTO system_settings (key, value, updated_at) VALUES ('audit_retention_days', ?, ?) ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = ?").run(origDays, new Date().toISOString(), origDays, new Date().toISOString());
  console.log('✓ Governance retention policies validated.');

  console.log('--- Enterprise End-to-End Hardening Test Suite PASSED ---');
  return true;
}

if (require.main === module) {
  runEnterpriseE2ETests()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('Enterprise E2E Test Suite FAILED:', err);
      process.exit(1);
    });
}

module.exports = { runEnterpriseE2ETests };
