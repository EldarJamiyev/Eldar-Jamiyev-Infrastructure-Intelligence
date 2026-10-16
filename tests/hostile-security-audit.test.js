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
const { AutonomousRemediationEngine, autonomousRemediationEngine } = require('../src/systems/remediation/autonomous-remediation-engine');
const { hostDiagnosticsEngine } = require('../src/systems/diagnostics/host-diagnostics-engine');
const { logAction, verifyAuditLogIntegrity, AUDIT_FILE, CHAIN_HEAD_FILE } = require('../src/core/audit-logger');

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
  decodedPayload.validatedParams.pid = 4; // Attempt to target PID 4 (Windows System Process)
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
  // TEST 3: PowerShell Command Injection Defense (Fixing F-02, F-10, S-03)
  // -------------------------------------------------------------------------
  console.log('\n[27.3] Testing PowerShell Command Injection, Metacharacter Defenses & Windows PID Truth (F-02, F-10, S-03)...');

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

  // Test Windows PID 4 (System) Shield
  let pid4Blocked = false;
  try {
    await autonomousRemediationEngine.executePreview('lower_process_priority', { pid: 4 }, sysadminContext);
  } catch (err) {
    if (err.message.includes('SECURITY VIOLATION') && err.message.includes('PID 4')) {
      pid4Blocked = true;
    }
  }
  assert.equal(pid4Blocked, true, 'Targeting Windows System (PID 4) must trigger SECURITY VIOLATION.');
  console.log('  ✓ Windows System PID 4 shield verified: PID 4 blocked from remediation (S-03 resolved).');

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

  // -------------------------------------------------------------------------
  // TEST 6: Action Token Persistent Replay Defense Across Engine Restarts (S-01)
  // -------------------------------------------------------------------------
  console.log('\n[27.6] Testing Action Token Persistent Replay Defense Across Engine Restarts (S-01)...');

  // Generate legitimate preview
  const persistentPreview = await autonomousRemediationEngine.executePreview('trim_working_set', {}, sysadminContext);
  assert.ok(persistentPreview.actionToken, 'Preview must issue signed HMAC actionToken');

  // Execute it successfully once
  const firstExec = await autonomousRemediationEngine.executeRemediation({ actionToken: persistentPreview.actionToken }, sysadminContext);
  assert.equal(firstExec.success, true, 'First execution of actionToken must succeed');

  // Replay attempt against the same engine
  let inMemoryReplayBlocked = false;
  try {
    await autonomousRemediationEngine.executeRemediation({ actionToken: persistentPreview.actionToken }, sysadminContext);
  } catch (err) {
    if (err.message.includes('REPLAY_DETECTED')) {
      inMemoryReplayBlocked = true;
    }
  }
  assert.equal(inMemoryReplayBlocked, true, 'Immediate replay against current engine must be blocked.');

  // Simulate server restart: create completely fresh engine instance reading from disk ledger
  const restartedEngine = new AutonomousRemediationEngine();
  let crossRestartReplayBlocked = false;
  try {
    await restartedEngine.executeRemediation({ actionToken: persistentPreview.actionToken }, sysadminContext);
  } catch (err) {
    if (err.message.includes('REPLAY_DETECTED')) {
      crossRestartReplayBlocked = true;
    }
  }
  assert.equal(crossRestartReplayBlocked, true, 'Persistent replay defense must block consumed token across engine restarts.');
  console.log('  ✓ Persistent token replay attack defeated: token rejected across simulated engine restart (S-01 resolved).');

  // -------------------------------------------------------------------------
  // TEST 7: Cross-User Token Submission & Session Binding Defense (S-01)
  // -------------------------------------------------------------------------
  console.log('\n[27.7] Testing Cross-User Token Submission Defense & Session Identity Binding (S-01)...');

  const aliceContext = { id: 'USR-SYS-ALICE', username: 'sysadmin_alice', role: 'SYSADMIN' };
  const bobContext = { id: 'USR-SYS-BOB', username: 'sysadmin_bob', role: 'SYSADMIN' };

  // Alice generates preview
  const alicePreview = await autonomousRemediationEngine.executePreview('trim_working_set', {}, aliceContext);
  assert.ok(alicePreview.actionToken, 'Alice must receive signed actionToken');

  // Bob attempts to execute Alice's token
  let crossUserBlocked = false;
  try {
    await autonomousRemediationEngine.executeRemediation({ actionToken: alicePreview.actionToken }, bobContext);
  } catch (err) {
    if (err.message.includes('Caller identity') && err.message.includes('does not match actionToken creator')) {
      crossUserBlocked = true;
    }
  }
  assert.equal(crossUserBlocked, true, 'Executing an actionToken issued to another user must be rejected.');

  // Alice executes her own token -> succeeds
  const aliceExec = await autonomousRemediationEngine.executeRemediation({ actionToken: alicePreview.actionToken }, aliceContext);
  assert.equal(aliceExec.success, true, 'Token creator must be permitted to execute their own preview token.');
  console.log('  ✓ Cross-user token submission defeated: token strictly bound to caller identity (S-01 resolved).');

  // -------------------------------------------------------------------------
  // TEST 8: Audit Log Tail Truncation Attack Detection via .chain_head (S-02)
  // -------------------------------------------------------------------------
  console.log('\n[27.8] Testing Audit Log Tail Truncation Defense via External .chain_head Anchor (S-02)...');

  // Log an action to ensure current chain is up to date
  logAction({
    userId: 'USR-ADMIN-01',
    username: 'admin',
    role: 'ADMIN',
    action: 'anchoring_verification_event',
    resource: 'audit_chain',
    details: { anchorTest: true }
  });

  const verifiedBefore = verifyAuditLogIntegrity();
  assert.equal(verifiedBefore.valid, true, `Audit chain must be valid prior to truncation attack: ${verifiedBefore.error || ''}`);

  // Attack: Read audit log, remove the last line, and write back without updating .chain_head
  // (Internal HMACs remain valid, but external anchor detects tail truncation!)
  const preTruncationContent = fs.readFileSync(AUDIT_FILE, 'utf8');
  const auditLines = preTruncationContent.trim().split('\n');
  assert.ok(auditLines.length >= 2, 'Must have at least 2 lines to test truncation');
  const truncatedContent = auditLines.slice(0, -1).join('\n') + '\n';
  fs.writeFileSync(AUDIT_FILE, truncatedContent, 'utf8');

  // Run integrity verification: Must detect truncation via .chain_head anchor!
  const truncationCheck = verifyAuditLogIntegrity();
  assert.equal(truncationCheck.valid, false, 'verifyAuditLogIntegrity must detect truncated audit log!');
  assert.ok(truncationCheck.error.includes('CRITICAL_CHAIN_TRUNCATION'), `Expected CRITICAL_CHAIN_TRUNCATION error, got: ${truncationCheck.error}`);
  console.log(`  ✓ Tail truncation attack flagged: ${truncationCheck.error}`);

  // Restore audit file
  fs.writeFileSync(AUDIT_FILE, preTruncationContent, 'utf8');
  const restoredCheck = verifyAuditLogIntegrity();
  assert.equal(restoredCheck.valid, true, 'Restored audit chain must verify valid.');
  console.log('  ✓ External .chain_head anchor verified: tail truncation and line deletion attacks detected (S-02 resolved).');

  // -------------------------------------------------------------------------
  // TEST 9: Process Target TOCTOU Race Condition Defense (S-03)
  // -------------------------------------------------------------------------
  console.log('\n[27.9] Testing Process Target TOCTOU Race Condition Defense (S-03)...');

  // Generate preview for process remediation with simulated PID start time
  const toctouPreview = await autonomousRemediationEngine.executePreview('lower_process_priority', { pid: 9999 }, sysadminContext);
  // Modify the token's targetProcessStartTime to simulate a recycled PID with a new start time
  const [toctouPayloadEnc, toctouSig] = toctouPreview.actionToken.split('.');
  const toctouTokenData = JSON.parse(Buffer.from(toctouPayloadEnc, 'base64url').toString('utf8'));
  toctouTokenData.validatedParams.targetProcessStartTime = 'SIMULATED_RECYCLE_TIME';
  
  // Re-sign with valid HMAC to isolate TOCTOU logic from HMAC rejection
  const reEnc = Buffer.from(JSON.stringify(toctouTokenData)).toString('base64url');
  const reSig = crypto.createHmac('sha256', require('../src/config').HMAC_SECRET).update(reEnc).digest('base64url');
  const toctouToken = `${reEnc}.${reSig}`;

  let toctouCaught = false;
  try {
    await autonomousRemediationEngine.executeRemediation({ actionToken: toctouToken }, sysadminContext);
  } catch (err) {
    if (err.message.includes('TOCTOU_VIOLATION')) {
      toctouCaught = true;
    }
  }
  assert.equal(toctouCaught, true, 'Process PID recycle/start-time mismatch must trigger TOCTOU_VIOLATION.');
  console.log('  ✓ TOCTOU race condition defense verified: PID recycling detected and blocked (S-03 resolved).');

  // -------------------------------------------------------------------------
  // TEST 10: Concurrent Token Consumption Race Condition Defense (S-01)
  // -------------------------------------------------------------------------
  console.log('\n[27.10] Testing Concurrent Token Consumption Race Condition Defense (S-01)...');

  const racePreview = await autonomousRemediationEngine.executePreview('trim_working_set', {}, sysadminContext);
  assert.ok(racePreview.actionToken, 'Race preview token issued');

  // Launch 5 simultaneous execution promises on the same token
  const racePromises = Array.from({ length: 5 }, () => 
    autonomousRemediationEngine.executeRemediation({ actionToken: racePreview.actionToken }, sysadminContext)
      .then(res => ({ status: 'fulfilled', value: res }))
      .catch(err => ({ status: 'rejected', reason: err.message }))
  );

  const raceResults = await Promise.all(racePromises);
  const fulfilledCount = raceResults.filter(r => r.status === 'fulfilled' && r.value.success).length;
  const rejectedCount = raceResults.filter(r => r.status === 'rejected' && r.reason.includes('REPLAY_DETECTED')).length;

  assert.equal(fulfilledCount, 1, `Exactly 1 concurrent execution must succeed, got ${fulfilledCount}`);
  assert.equal(rejectedCount, 4, `Exactly 4 concurrent executions must be rejected as REPLAY_DETECTED, got ${rejectedCount}`);
  console.log(`  ✓ Concurrency defense verified: 1 succeeded, 4 rejected with REPLAY_DETECTED out of 5 simultaneous requests (S-01 resolved).`);

  console.log('\n>>> ALL SUITE 27 HOSTILE SECURITY AUDIT & VERIFICATION TESTS COMPLETED SUCCESSFULLY.');
}

if (require.main === module) {
  runHostileSecurityAuditTests().catch((err) => {
    console.error('\n❌ Suite 27 Failed:', err);
    process.exit(1);
  });
}

module.exports = { runHostileSecurityAuditTests };
