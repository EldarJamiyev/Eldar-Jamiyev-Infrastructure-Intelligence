/**
 * EJII Test Suite: Automation Safety & Dual-Custody Gates
 */

const assert = require('assert');
const { validateActionSafety } = require('../src/automation/safety-validator');
const { requestAction, reviewAction, executeAction } = require('../src/automation/execution-engine');
const { db } = require('../src/db/database');

async function runAutomationTests() {
  console.log('\n--- Running Automation Safety & Dual-Custody Test Suite ---');

  // Test 1: Block Protected Operating System Processes
  console.log('Testing Protected System Process Guardrails...');
  const blockCsrss = validateActionSafety({
    actionType: 'kill_process',
    targetHost: 'localhost',
    targetResource: 'csrss.exe'
  });
  assert.strictEqual(blockCsrss.allowed, false, 'csrss.exe must be blocked');
  assert.ok(blockCsrss.reason.includes('CRITICAL SAFETY GUARD'), 'Reason must explain system protection');

  const blockLsass = validateActionSafety({
    actionType: 'kill_process',
    targetHost: 'localhost',
    targetResource: 'lsass'
  });
  assert.strictEqual(blockLsass.allowed, false, 'lsass must be blocked');

  const blockPid4 = validateActionSafety({
    actionType: 'kill_process',
    targetHost: 'localhost',
    targetResource: 'system',
    parameters: { pid: 4 }
  });
  assert.strictEqual(blockPid4.allowed, false, 'PID 4 must be blocked');
  console.log('✓ Protected process guardrails verified: csrss, lsass, and PID 4 blocked.');

  // Test 2: Tier 2 Safe Remediation (Flush DNS - No Approval Required)
  console.log('Testing Tier 2 Safe Action (Flush DNS)...');
  const dummyUser = { id: 'USR-SYSADMIN-01', username: 'sysadmin', role: 'sysadmin' };
  const dnsReq = requestAction({
    actionType: 'flush_dns',
    targetHost: 'localhost',
    targetResource: 'DNS Resolver Cache',
    user: dummyUser
  });
  assert.strictEqual(dnsReq.success, true, 'Flush DNS request must succeed');
  assert.strictEqual(dnsReq.tier, 2, 'Tier must be 2');
  assert.strictEqual(dnsReq.requiresApproval, false, 'Tier 2 does not require approval');
  assert.strictEqual(dnsReq.executionStatus, 'queued', 'Execution status must be queued');
  console.log(`✓ Tier 2 action verified: ${dnsReq.actionId} [Status: ${dnsReq.executionStatus}]`);

  // Test 3: Tier 3 High-Impact Action (Restart Service - Requires Approval)
  console.log('Testing Tier 3 Dual-Custody Action (Restart Service)...');
  const srvReq = requestAction({
    actionType: 'restart_service',
    targetHost: 'localhost',
    targetResource: 'Spooler',
    user: dummyUser
  });
  assert.strictEqual(srvReq.success, true, 'Request must succeed');
  assert.strictEqual(srvReq.tier, 3, 'Tier must be 3');
  assert.strictEqual(srvReq.requiresApproval, true, 'Tier 3 requires approval');
  assert.strictEqual(srvReq.approvalStatus, 'pending_approval', 'Approval status must be pending_approval');
  console.log(`✓ Tier 3 dual-custody gate verified: ${srvReq.actionId} placed in 'pending_approval'`);

  // Test 4: Execution Blocked Prior to Approval
  console.log('Testing Prevention of Execution While Pending Approval...');
  const blockedExec = await executeAction(srvReq.actionId, dummyUser);
  assert.strictEqual(blockedExec.success, false, 'Execution must fail');
  assert.ok(blockedExec.error.includes('requires Application Owner approval'), 'Must require approval');
  console.log(`✓ Execution blocked as expected: ${blockedExec.error}`);

  // Test 5: Application Owner Review & Approval
  console.log('Testing Application Owner Dual-Custody Approval...');
  const appOwnerUser = { id: 'USR-APPOWNER-01', username: 'appowner', role: 'app_owner' };
  const reviewRes = reviewAction(srvReq.actionId, {
    approved: true,
    comment: 'Approved for maintenance window.',
    user: appOwnerUser
  });
  assert.strictEqual(reviewRes.success, true, 'Review must succeed');
  assert.strictEqual(reviewRes.approvalStatus, 'approved', 'Must be approved');
  assert.strictEqual(reviewRes.executionStatus, 'queued', 'Must transition to queued');
  console.log(`✓ Application Owner approval verified: Status=${reviewRes.approvalStatus}`);

  // Test 6: Dry Run Simulation Mode
  console.log('Testing Dry Run Simulation Mode...');
  const dryRunReq = requestAction({
    actionType: 'restart_service',
    targetHost: 'localhost',
    targetResource: 'W32Time',
    user: dummyUser,
    dryRun: true
  });
  assert.strictEqual(dryRunReq.success, true, 'Dry run request must succeed');
  assert.strictEqual(dryRunReq.requiresApproval, false, 'Dry run does not require approval');
  assert.ok(dryRunReq.dryRunPlan.includes('W32Time'), 'Dry run plan must outline action');
  const dryRunExec = await executeAction(dryRunReq.actionId, dummyUser);
  assert.strictEqual(dryRunExec.dryRun, true, 'Must execute in dry run mode');
  console.log(`✓ Dry run simulation verified: ${dryRunExec.message}`);

  console.log('--- Automation Safety & Dual-Custody Test Suite PASSED ---\n');
}

if (require.main === module) {
  runAutomationTests().catch((err) => {
    console.error('Automation Tests FAILED:', err);
    process.exit(1);
  });
}

module.exports = { runAutomationTests };
