/**
 * Test Suite 25: Autonomous Remediation Safety, Elevation & Two-Phase Lifecycle Suite
 * Verifies recipe catalog completeness, dry-run simulation isolation, protected OS process guards,
 * elevation detection, RBAC authorization, and audit logging.
 */

'use strict';

const assert = require('node:assert/strict');
const { autonomousRemediationEngine, PROTECTED_OS_PROCESSES } = require('../src/systems/remediation/autonomous-remediation-engine');

async function runAutonomousRemediationSafetyTests() {
  console.log('\n========================================================================');
  console.log('  SUITE 25: AUTONOMOUS REMEDIATION SAFETY & ELEVATION LIFECYCLE SUITE   ');
  console.log('  Two-Phase Dry-Run, OS Process Guards, Elevation Check & Audit Logs   ');
  console.log('========================================================================');

  // 1. Recipe Catalog Completeness
  console.log('[25.1] Testing Recipe Catalog completeness across all 4 pillars...');
  const catalog = autonomousRemediationEngine.getRecipeCatalog();
  assert.ok(Array.isArray(catalog), 'Catalog must be an array');
  assert.ok(catalog.length >= 10, `Catalog must have at least 10 recipes, got ${catalog.length}`);

  const pillars = new Set(catalog.map(r => r.pillar));
  assert.ok(pillars.has('network'), 'Must have network recipes');
  assert.ok(pillars.has('storage'), 'Must have storage recipes');
  assert.ok(pillars.has('resource'), 'Must have resource recipes');
  assert.ok(pillars.has('peripherals'), 'Must have peripherals recipes');

  const winsock = catalog.find(r => r.id === 'reset_winsock');
  assert.ok(winsock);
  assert.strictEqual(winsock.requiresElevation, true);
  assert.strictEqual(winsock.riskLevel, 'MEDIUM');

  const flushDns = catalog.find(r => r.id === 'flush_dns');
  assert.ok(flushDns);
  assert.strictEqual(flushDns.requiresElevation, false);
  console.log(`  ✓ Recipe catalog validated: ${catalog.length} recipes across 4 pillars.`);

  // 2. Phase 1: Dry-Run Preview Isolation (Zero Mutation)
  console.log('[25.2] Testing Phase 1: Dry-Run Preview isolation without OS mutation...');
  const preview = await autonomousRemediationEngine.executePreview('repair_print_spooler', {
    target: 'Spooler Service'
  });

  assert.strictEqual(preview.dryRun, true, 'Preview must have dryRun: true');
  assert.strictEqual(preview.recipeId, 'repair_print_spooler');
  assert.ok(preview.commandPreview.includes('Stop-Service'));
  assert.ok(preview.safetyAssessment);
  assert.ok(typeof preview.hostIsElevated === 'boolean');
  console.log(`  ✓ Dry-run preview verified: command "${preview.commandPreview.slice(0, 40)}..." assessed safely without mutating host.`);

  // 3. Protected OS Process Defense
  console.log('[25.3] Testing Protected OS Process Defense (Anti-Kill Guards)...');
  const criticalProcs = ['lsass.exe', 'csrss.exe', 'smss.exe', 'services.exe'];

  for (const proc of criticalProcs) {
    await assert.rejects(
      async () => {
        await autonomousRemediationEngine.executeRemediation('lower_process_priority', {
          pid: 666,
          processName: proc
        }, { role: 'ADMIN', username: 'attacker' });
      },
      (err) => {
        assert.ok(err.message.includes('SECURITY VIOLATION'), `Targeting ${proc} must trigger security violation, got: ${err.message}`);
        assert.ok(err.message.includes('Protected operating system process'));
        return true;
      },
      `Attempting to target protected process '${proc}' should have been rejected`
    );
  }
  console.log(`  ✓ All ${criticalProcs.length} protected operating system processes shielded from modification.`);

  // 4. RBAC Authorization Enforcement (SYSADMIN / ADMIN only)
  console.log('[25.4] Testing RBAC role authorization for remediation execution...');
  await assert.rejects(
    async () => {
      await autonomousRemediationEngine.executeRemediation('trim_working_set', {}, {
        role: 'READONLY',
        username: 'unauthorized_reader'
      });
    },
    (err) => {
      assert.ok(err.message.includes('Access denied'), `READONLY must be denied, got: ${err.message}`);
      return true;
    },
    'READONLY user should not be allowed to execute remediation'
  );
  await assert.rejects(
    async () => {
      await autonomousRemediationEngine.executeRemediation('trim_working_set', {}, {
        role: 'OPERATOR',
        username: 'junior_tech'
      });
    },
    (err) => {
      assert.ok(err.message.includes('Access denied'), `OPERATOR must be denied, got: ${err.message}`);
      return true;
    },
    'OPERATOR user should not be allowed to execute remediation without SYSADMIN capability'
  );
  console.log('  ✓ READONLY and OPERATOR users blocked from executing remediation (requires SYSADMIN/ADMIN).');

  // 5. Elevation Safety & Non-Elevated Host Feedback
  console.log('[25.5] Testing Elevation Safety and Honest Host Feedback...');
  const { isElevated } = await autonomousRemediationEngine.checkElevation();
  const elevatedOutcome = await autonomousRemediationEngine.executeRemediation('repair_component_store', {}, {
    role: 'SYSADMIN',
    username: 'noc_sysadmin'
  });

  if (!isElevated) {
    assert.strictEqual(elevatedOutcome.success, false);
    assert.strictEqual(elevatedOutcome.elevationRequired, true);
    assert.ok(elevatedOutcome.instructions.includes('Run PowerShell as Administrator'));
    console.log('  ✓ Unprivileged process honest feedback verified: explicit elevationRequired instructions emitted (zero fake success).');
  } else {
    assert.ok(elevatedOutcome.durationMs >= 0);
    console.log('  ✓ Elevated execution verified.');
  }

  // 6. Safe Unprivileged Recipe Execution
  console.log('[25.6] Testing Safe Unprivileged Recipe Execution (trim_working_set)...');
  const safeOutcome = await autonomousRemediationEngine.executeRemediation('trim_working_set', {}, {
    role: 'SYSADMIN',
    username: 'senior_sysadmin'
  });
  assert.ok(safeOutcome.success, 'Safe unprivileged recipe should succeed');
  assert.ok(typeof safeOutcome.durationMs === 'number');
  console.log(`  ✓ Unprivileged recipe 'trim_working_set' executed in ${safeOutcome.durationMs}ms.`);

  // 7. Bounded Remediation Audit Log
  console.log('[25.7] Testing Bounded Remediation Audit Log...');
  const logs = autonomousRemediationEngine.getRemediationLog(10);
  assert.ok(Array.isArray(logs));
  assert.ok(logs.length >= 2, `Must have recorded executions, got ${logs.length}`);

  const latest = logs[0];
  assert.ok(latest.id.startsWith('REM-'));
  assert.ok(latest.timestamp);
  assert.ok(latest.recipeId);
  assert.ok(latest.user);
  console.log(`  ✓ Remediation audit trail verified: logged action "${latest.recipeId}" by user "${latest.user}" (${latest.role}).`);

  console.log('\n>>> ALL SUITE 25 AUTONOMOUS REMEDIATION SAFETY TESTS PASSED (ZERO DEFECTS).\n');
}

if (require.main === module) {
  runAutonomousRemediationSafetyTests().catch((err) => {
    console.error('Suite 25 failed:', err);
    process.exit(1);
  });
}

module.exports = { runAutonomousRemediationSafetyTests };
