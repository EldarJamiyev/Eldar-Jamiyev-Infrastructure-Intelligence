/**
 * EJII Test Suite: Authentication, RBAC Matrix & Cryptographic Audit Trail
 */

const assert = require('assert');
const { hashPassword, verifyPassword, createToken, verifyToken, hasPermission, ROLES } = require('../src/core/security');
const { logAction, verifyChainIntegrity, computeRecordHash, GENESIS_HASH } = require('../src/core/audit-logger');
const { db } = require('../src/db/database');

async function runAuthTests() {
  console.log('\n--- Running Authentication, RBAC & Audit Trail Test Suite ---');

  // Clear test tokens from previous runs
  db.prepare("DELETE FROM revoked_tokens WHERE user_id LIKE 'USR-TEST%'").run();

  // Test 1: Password Hashing & Verification
  console.log('Testing PBKDF2 Password Hashing...');
  const secret = 'EnterprisePassword987!';
  const { hash, salt } = hashPassword(secret);
  assert.ok(hash.length > 50, 'Hash must be generated');
  assert.ok(salt.length > 10, 'Salt must be generated');
  assert.strictEqual(verifyPassword(secret, hash, salt), true, 'Valid password must verify');
  assert.strictEqual(verifyPassword('WrongPass', hash, salt), false, 'Invalid password must fail');
  console.log('✓ Password hashing and verification verified.');

  // Test 2: Token Creation & Verification
  console.log('Testing JWT Token Handling...');
  const token = createToken({ id: 'USR-TEST-01', username: 'testuser', role: ROLES.SYSADMIN });
  const decoded = verifyToken(token);
  assert.ok(decoded, 'Token must decode');
  assert.strictEqual(decoded.id, 'USR-TEST-01', 'Decoded ID must match');
  assert.strictEqual(decoded.role, ROLES.SYSADMIN, 'Decoded role must match');
  assert.strictEqual(verifyToken('tampered.token.value'), null, 'Tampered token must return null');
  console.log('✓ Token signing and verification verified.');

  // Test 3: Four Operational Roles & Permission Capabilities Matrix
  console.log('Testing RBAC Matrix for 4 Operational Roles...');

  // Helpdesk: Can ping and test ports, cannot restart services or manage users
  assert.strictEqual(hasPermission(ROLES.HELPDESK, 'diag:ping'), true, 'Helpdesk can ping');
  assert.strictEqual(hasPermission(ROLES.HELPDESK, 'diag:port_test'), true, 'Helpdesk can test ports');
  assert.strictEqual(hasPermission(ROLES.HELPDESK, 'admin:user_manage'), false, 'Helpdesk CANNOT manage users');
  assert.strictEqual(hasPermission(ROLES.HELPDESK, 'admin:approval_action'), false, 'Helpdesk CANNOT approve actions');

  // Network Admin: Can poll SNMP and audit TLS, cannot manage users
  assert.strictEqual(hasPermission(ROLES.NETWORK_ADMIN, 'network:snmp_poll'), true, 'NetAdmin can poll SNMP');
  assert.strictEqual(hasPermission(ROLES.NETWORK_ADMIN, 'network:tls_audit'), true, 'NetAdmin can audit TLS');
  assert.strictEqual(hasPermission(ROLES.NETWORK_ADMIN, 'admin:user_manage'), false, 'NetAdmin CANNOT manage users');

  // System Administrator: Can view services and request automation, cannot approve own high-impact actions
  assert.strictEqual(hasPermission(ROLES.SYSADMIN, 'system:service_list'), true, 'Sysadmin can list services');
  assert.strictEqual(hasPermission(ROLES.SYSADMIN, 'system:automation_request'), true, 'Sysadmin can request automation');
  assert.strictEqual(hasPermission(ROLES.SYSADMIN, 'admin:user_manage'), false, 'Sysadmin CANNOT manage users');

  // Application Owner: Full administrative governance and approval powers
  assert.strictEqual(hasPermission(ROLES.APP_OWNER, 'admin:user_manage'), true, 'App Owner can manage users');
  assert.strictEqual(hasPermission(ROLES.APP_OWNER, 'admin:audit_verify'), true, 'App Owner can verify audit chain');
  assert.strictEqual(hasPermission(ROLES.APP_OWNER, 'admin:approval_action'), true, 'App Owner can approve actions');
  console.log('✓ Role capabilities matrix for all 4 operational roles verified.');

  // Test 4: Cryptographic HMAC Chained Audit Log Integrity
  console.log('Testing Cryptographic HMAC Audit Trail Chain...');
  logAction({
    userId: 'USR-SYSADMIN-01',
    username: 'sysadmin',
    role: ROLES.SYSADMIN,
    action: 'TEST_AUDIT_ACTION',
    resource: 'TEST_RESOURCE',
    details: 'Verifying hash chain continuity.'
  });

  const check1 = verifyChainIntegrity();
  assert.strictEqual(check1.valid, true, 'Audit log chain must be valid');
  assert.strictEqual(check1.brokenAtId, null, 'No broken links');
  console.log(`✓ Audit chain integrity check passed: ${check1.totalRecords} records verified.`);

  // Test 5: Tamper Detection Verification
  console.log('Testing Cryptographic Tamper Detection...');
  const lastRecord = db.prepare('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 1').get();
  let insertedId = null;

  try {
    const info = db.prepare(`
      INSERT INTO audit_logs (timestamp, user_id, username, role, action, resource, details, ip_address, prev_hash, hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      new Date().toISOString(),
      'ROGUE_USER',
      'attacker',
      'unknown',
      'UNAUTHORIZED_CHANGE',
      'SYSTEM_CONFIG',
      'Attacker modified setting without authorization.',
      '192.168.1.99',
      lastRecord.hash,
      'FORGED_HASH_THAT_DOES_NOT_MATCH_HMAC_CALCULATION'
    );
    insertedId = info.lastInsertRowid;

    const tamperCheck = verifyChainIntegrity();
    assert.strictEqual(tamperCheck.valid, false, 'Tampered record must be detected as INVALID');
    assert.ok(tamperCheck.brokenAtId > 0, 'Must pinpoint exact tampered record ID');
    assert.ok(tamperCheck.message.includes('Tampered record detected'), 'Message must indicate tampering');
    console.log(`✓ Tamper detection verified! Correctly caught forged record ID ${tamperCheck.brokenAtId}`);
  } finally {
    if (insertedId) {
      db.prepare('DELETE FROM audit_logs WHERE id = ?').run(insertedId);
    }
  }

  const restoredCheck = verifyChainIntegrity();
  assert.strictEqual(restoredCheck.valid, true, 'Restored audit chain must be valid');
  console.log('✓ Chain integrity successfully re-validated after cleanup.');

  console.log('--- Authentication, RBAC & Audit Trail Test Suite PASSED ---\n');
}

if (require.main === module) {
  runAuthTests().catch((err) => {
    console.error('Auth Tests FAILED:', err);
    process.exit(1);
  });
}

module.exports = { runAuthTests };
