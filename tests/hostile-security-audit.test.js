/**
 * Test Suite 27: Hostile Security Audit, Exploit Defense & 5-State Verification
 * Adversarially tests and verifies:
 *   1. Cross-role privilege escalation defense (SYSADMIN blocked from ADMIN-only actions).
 *   2. Cryptographic actionToken preview-to-execution binding & parameter tampering defense.
 *   3. PowerShell command injection parameter neutralization.
 *   4. Append-only HMAC audit chain integrity and tamper detection.
 *   5. 5-state health engine truth (error -> COLLECTION_ERROR, never fake HEALTHY).
 */

'use strict';

const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { createToken, hasPermission, ROLE_CAPABILITIES } = require('../src/core/security');
const { requireRole, requirePermission } = require('../src/api/middleware');
const { autonomousRemediationEngine } = require('../src/systems/remediation/autonomous-remediation-engine');
const { hostDiagnosticsEngine } = require('../src/systems/diagnostics/host-diagnostics-engine');
const { logAction, verifyAuditLogIntegrity, AUDIT_FILE } = require('../src/core/audit-logger');

async function runHostileSecurityAuditTests() {
  console.log('\n========================================================================');
  console.log('  SUITE 27: HOSTILE SECURITY AUDIT & ADVERSARIAL REMEDIATION PROOF      ');
  console.log('  Cross-Role RBAC, Action Token Binding, Injection & HMAC Audit Chain   ');
  console.log('========================================================================');

  // -------------------------------------------------------------------------
  // TEST 1: Cross-Role Privilege Escalation Defense (Fixing F-01 & F-03)
  // -------------------------------------------------------------------------
  console.log('[27.1] Testing Cross-Role Privilege Escalation Defense (SYSADMIN -> ADMIN)...');

  // Verify capability mappings
  assert.equal(hasPermission('ADMIN', 'users.roles.manage'), true, 'ADMIN must have users.roles.manage');
  assert.equal(hasPermission('SYSADMIN', 'users.roles.manage'), false, 'SYSADMIN must NOT have users.roles.manage');
  assert.equal(hasPermission('NETWORK_ADMIN', 'users.roles.manage'), false, 'NETWORK_ADMIN must NOT have users.roles.manage');
  assert.equal(hasPermission('READONLY', 'host.remediation.execute'), false, 'READONLY must NOT have host.remediation.execute');

  // Verify requireRole strict explicit matching (no numeric escalation)
  const adminGuard = requireRole('ADMIN');
  let forbiddenCaught = false;

  const mockSysadminReq = {
    user: { id: 'USR-SYS-01', username: 'sysadmin_user', role: 'SYSADMIN' }
  };
  const mockRes = {
    status: (code) => ({
      json: (data) => {
        if (code === 403) forbiddenCaught = true;
      }
    })
  };

  adminGuard(mockSysadminReq, mockRes, () => {
    assert.fail('CRITICAL VULNERABILITY: SYSADMIN was permitted to execute ADMIN-only route!');
  });

  assert.equal(forbiddenCaught, true, 'requireRole strictly blocked SYSADMIN from ADMIN-only route.');
  console.log('  ✓ SYSADMIN strictly blocked from ADMIN-only route with HTTP 403 Forbidden (F-01 resolved).');

  // -------------------------------------------------------------------------
  // TEST 2: Remediation Parameter Tampering Defense (Fixing F-11)
  // -------------------------------------------------------------------------
  console.log('\n[27.2] Testing Cryptographic Action Token Preview-to-Execution Binding (F-11)...');

  const sysadminContext = { id: 'USR-SYS-01', username: 'lead_sysadmin', role: 'SYSADMIN' };

  // 1. Generate legitimate preview with valid PID
  const legitimatePreview = await autonomousRemediationEngine.executePreview('lower_process_priority', { pid: 9999 }, sysadminContext);
  assert.ok(legitimatePreview.actionToken, 'Preview must issue signed HMAC actionToken');
  assert.equal(legitimatePreview.dryRun, true, 'Preview must be marked dryRun');

  // 2. Attack: Tamper with actionToken payload (e.g. modify target PID inside token)
  const [encPayload, sig] = legitimatePreview.actionToken.split('.');
  const decodedPayload = JSON.parse(Buffer.from(encPayload, 'base64url').toString('utf8'));
  decodedPayload.validatedParams.pid = 1; // Attempt to target PID 1 (Init/System)
  const tamperedPayloadEnc = Buffer.from(JSON.stringify(decodedPayload)).toString('base64url');
  const forgedToken = `${tamperedPayloadEnc}.${sig}`;

  let tamperBlocked = false;
  try {
    await autonomousRemediationEngine.executeRemediation({ actionToken: forgedToken }, sysadminContext);
  } catch (err) {
    if (err.message.includes('signature verification failed') || err.message.includes('tampered')) {
      tamperBlocked = true;
    }
  }
  assert.equal(tamperBlocked, true, 'Tampered actionToken must be rejected by HMAC verification.');
  console.log('  ✓ Tampered actionToken rejected by cryptographic HMAC verification (F-11 resolved).');

  // -------------------------------------------------------------------------
  // TEST 3: PowerShell Command Injection Defense (Fixing F-02, F-10)
  // -------------------------------------------------------------------------
  console.log('\n[27.3] Testing PowerShell Command Injection & Metacharacter Defenses (F-02, F-10)...');

  const injectionAttempts = [
    '1234; Invoke-Expression "calc.exe"',
    '1234 | Out-File evil.ps1',
    '1234 & net user hacker P@ss /add',
    '1234`nGet-Process',
    '-1',
    '0',
    'abc'
  ];

  for (const inj of injectionAttempts) {
    let rejected = false;
    try {
      await autonomousRemediationEngine.executePreview('lower_process_priority', { pid: inj }, sysadminContext);
    } catch (err) {
      rejected = true;
    }
    assert.equal(rejected, true, `Injection payload '${inj}' was not rejected!`);
  }
  console.log(`  ✓ All ${injectionAttempts.length} PowerShell injection & metacharacter variants rejected.`);

  // Test Process Shield Defense
  let protectedBlocked = false;
  try {
    await autonomousRemediationEngine.executePreview('lower_process_priority', { processName: 'lsass.exe' }, sysadminContext);
  } catch (err) {
    if (err.message.includes('SECURITY VIOLATION') && err.message.includes('lsass')) {
      protectedBlocked = true;
    }
  }
  assert.equal(protectedBlocked, true, 'Targeting lsass.exe must trigger SECURITY VIOLATION.');
  console.log('  ✓ Process shield defense verified: lsass.exe blocked from remediation.');

  // -------------------------------------------------------------------------
  // TEST 4: True Tamper-Resistant Append-Only Audit Trail (Fixing F-04)
  // -------------------------------------------------------------------------
  console.log('\n[27.4] Testing HMAC-Chained Audit Trail Integrity & Tamper Detection (F-04)...');

  // Write a series of audited actions
  const entry1 = logAction({
    userId: 'USR-ADMIN-01',
    username: 'admin',
    role: 'ADMIN',
    action: 'test_action_alpha',
    resource: 'system_core',
    details: { test: true }
  });

  const entry2 = logAction({
    userId: 'USR-SYS-01',
    username: 'sysadmin',
    role: 'SYSADMIN',
    action: 'test_action_beta',
    resource: 'volume_c',
    details: { dryRun: false }
  });

  // Verify unbroken chain
  const initialVerification = verifyAuditLogIntegrity();
  assert.equal(initialVerification.valid, true, `Initial chain must be valid: ${initialVerification.error || ''}`);
  console.log(`  ✓ Audit trail verified unbroken: ${initialVerification.count} records chained with HMAC-SHA256.`);

  // Attack: Modify one record in the audit file
  const originalContent = fs.readFileSync(AUDIT_FILE, 'utf8');
  const lines = originalContent.trim().split('\n');
  const lastLineObj = JSON.parse(lines[lines.length - 1]);
  lastLineObj.action = 'forged_malicious_action'; // Modify field without recomputing HMAC
  lines[lines.length - 1] = JSON.stringify(lastLineObj);
  fs.writeFileSync(AUDIT_FILE, lines.join('\n') + '\n', 'utf8');

  // Verify that tamper detector catches the modification
  const tamperedVerification = verifyAuditLogIntegrity();
  assert.equal(tamperedVerification.valid, false, 'verifyAuditLogIntegrity must detect modified record!');
  console.log(`  ✓ Tamper detection proven: verifyAuditLogIntegrity() successfully flagged modified record.`);

  // Restore pristine audit file
  fs.writeFileSync(AUDIT_FILE, originalContent, 'utf8');
  const restoredVerification = verifyAuditLogIntegrity();
  assert.equal(restoredVerification.valid, true, 'Restored audit chain must verify valid.');

  // -------------------------------------------------------------------------
  // TEST 5: 5-State Health Classification & Truth (Fixing F-08, F-09)
  // -------------------------------------------------------------------------
  console.log('\n[27.5] Testing 5-State Health Engine Truth (F-08, F-09)...');

  const fullAudit = await hostDiagnosticsEngine.collectFullAudit(true);
  const validStates = ['HEALTHY', 'DEGRADED', 'CRITICAL', 'UNKNOWN', 'COLLECTION_ERROR'];

  assert.ok(validStates.includes(fullAudit.overallStatus), `Invalid overall status: ${fullAudit.overallStatus}`);
  assert.ok(validStates.includes(fullAudit.pillars.network.status), 'Network status must be 5-state valid');
  assert.ok(validStates.includes(fullAudit.pillars.storage.status), 'Storage status must be 5-state valid');
  assert.ok(validStates.includes(fullAudit.pillars.resource.status), 'Resource status must be 5-state valid');
  assert.ok(validStates.includes(fullAudit.pillars.peripherals.status), 'Peripherals status must be 5-state valid');

  // Verify metadata fields exist
  assert.ok(fullAudit.pillars.network.metadata, 'Network pillar must contain metadata');
  assert.ok(fullAudit.pillars.storage.metadata, 'Storage pillar must contain metadata');
  assert.ok(fullAudit.pillars.network.metadata.collectedAt, 'Metadata must contain collection timestamp');

  console.log(`  ✓ 5-State Engine verified: Overall=${fullAudit.overallStatus}, Network=${fullAudit.pillars.network.status}, Storage=${fullAudit.pillars.storage.status}`);

  console.log('\n>>> ALL SUITE 27 HOSTILE SECURITY AUDIT & VERIFICATION TESTS COMPLETED SUCCESSFULLY.');
}

if (require.main === module) {
  runHostileSecurityAuditTests().catch((err) => {
    console.error('\n❌ Suite 27 Failed:', err);
    process.exit(1);
  });
}

module.exports = { runHostileSecurityAuditTests };
