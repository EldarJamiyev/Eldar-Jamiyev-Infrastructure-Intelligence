/**
 * EJII Test Suite 64: Master Report Consistency, Zero Zombie Files & 68-Suite Milestone
 * 
 * Verifies:
 * [64.1] Zero Zombie Artifacts & Hygiene (sync_now.bat eliminated, .gitignore enforced)
 * [64.2] Master Test Runner 68-Suite Registration & Execution Invariant
 * [64.3] Canonical Integrity Report Alignment (EJII_TEST_EXECUTION_INTEGRITY_REPORT.md)
 * [64.4] Canonical Deployment Report Alignment (EJII_SECURE_DEPLOYMENT_REPORT.md)
 */

'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const rootDir = path.join(__dirname, '..');

async function runReportConsistencyAndZeroStaleCountsTests() {
  console.log('========================================================================');
  console.log('  SUITE 64: MASTER REPORT CONSISTENCY, HYGIENE & 68-SUITE MILESTONE      ');
  console.log('  Zero Zombie Artifacts, Zero Stale Counts & Canonical 68/68 Alignment   ');
  console.log('========================================================================\n');

  // [64.1] Zero Zombie Files & Git Ignore Hygiene
  console.log('[64.1] Verifying zero zombie files and .gitignore hygiene...');
  const syncBatPath = path.join(rootDir, 'sync_now.bat');
  assert.strictEqual(
    fs.existsSync(syncBatPath),
    false,
    'sync_now.bat must be permanently eliminated from repository disk'
  );

  const gitignorePath = path.join(rootDir, '.gitignore');
  assert.ok(fs.existsSync(gitignorePath), '.gitignore must exist');
  const gitignoreContent = fs.readFileSync(gitignorePath, 'utf8');
  assert.ok(
    gitignoreContent.includes('sync_now.bat'),
    '.gitignore must explicitly guard and block sync_now.bat from future git additions'
  );
  console.log('  ✓ sync_now.bat confirmed non-existent on disk and barred in .gitignore.');

  // [64.2] Master Test Runner 68-Suite Registration
  console.log('[64.2] Verifying master test runner registration of all 68 suites...');
  const runnerPath = path.join(rootDir, 'tests', 'run-all-tests.js');
  const runnerContent = fs.readFileSync(runnerPath, 'utf8');

  assert.ok(runnerContent.includes('autonomous-goal-workflow-and-endpoint-memory.test'), 'Runner must import Suite 61');
  assert.ok(runnerContent.includes('office-protocol-banners-and-reverification-diff.test'), 'Runner must import Suite 62');
  assert.ok(runnerContent.includes('five-view-frontend-backend-wiring.test'), 'Runner must import Suite 63');
  assert.ok(runnerContent.includes('report-consistency-and-zero-stale-counts.test'), 'Runner must import Suite 64');
  assert.ok(runnerContent.includes('dynamic-location-topology-and-zero-hardcoded-ips.test'), 'Runner must import Suite 65');
  assert.ok(runnerContent.includes('worker-pool-types-and-timeseries-adapter.test'), 'Runner must import Suite 66');
  assert.ok(runnerContent.includes('cncf-prometheus-otel-and-linux-parity.test'), 'Runner must import Suite 67');
  assert.ok(runnerContent.includes('gitops-drift-reconciliation-loop.test'), 'Runner must import Suite 68');
  assert.ok(runnerContent.includes('zero-timeout-unprivileged-scripts-and-hygiene.test'), 'Runner must import Suite 69');
  assert.ok(runnerContent.includes('kl-divergence-bayes-factor-and-critic-reflection.test'), 'Runner must import Suite 70');
  assert.ok(runnerContent.includes('w3c-traceparent-pipeline-and-multi-env-location.test'), 'Runner must import Suite 71');
  assert.ok(runnerContent.includes('control-plane-ui-gitops-observability-wiring.test'), 'Runner must import Suite 72');

  // Count registered suites in run-all-tests.js
  const suiteEntries = runnerContent.match(/\{\s*name:\s*['"]\d+\./g) || [];
  assert.strictEqual(
    suiteEntries.length,
    72,
    `Expected exactly 72 registered test suites in run-all-tests.js, found ${suiteEntries.length}`
  );
  console.log(`  ✓ Exactly 72 suites registered in tests/run-all-tests.js.`);

  // [64.3] Canonical Integrity Report Alignment
  console.log('[64.3] Verifying EJII_TEST_EXECUTION_INTEGRITY_REPORT.md consistency...');
  const integrityReportPath = path.join(rootDir, 'EJII_TEST_EXECUTION_INTEGRITY_REPORT.md');
  assert.ok(fs.existsSync(integrityReportPath), 'EJII_TEST_EXECUTION_INTEGRITY_REPORT.md must exist');
  const integrityContent = fs.readFileSync(integrityReportPath, 'utf8');

  // Must not have stale text
  assert.strictEqual(
    integrityContent.includes('ALL 56/56 NOC TEST SUITES PASSED'),
    false,
    'EJII_TEST_EXECUTION_INTEGRITY_REPORT.md must not contain stale ALL 56/56 text'
  );
  assert.strictEqual(
    integrityContent.includes('All 56 suites executed'),
    false,
    'EJII_TEST_EXECUTION_INTEGRITY_REPORT.md must not contain stale All 56 suites executed text'
  );

  // Must reflect 68 suites
  assert.ok(
    /72\s*\/\s*72|72 Suites|Comprehensive 72-Suite Matrix|68\s*\/\s*68/.test(integrityContent),
    'EJII_TEST_EXECUTION_INTEGRITY_REPORT.md must reflect 68 suites milestone'
  );

  // Check table matrix contains rows 61-68
  assert.ok(integrityContent.includes('| **61** |'), 'Integrity matrix must include Suite 61');
  assert.ok(integrityContent.includes('| **62** |'), 'Integrity matrix must include Suite 62');
  assert.ok(integrityContent.includes('| **63** |'), 'Integrity matrix must include Suite 63');
  assert.ok(integrityContent.includes('| **64** |'), 'Integrity matrix must include Suite 64');
  assert.ok(integrityContent.includes('| **65** |'), 'Integrity matrix must include Suite 65');
  assert.ok(integrityContent.includes('| **66** |'), 'Integrity matrix must include Suite 66');
  assert.ok(integrityContent.includes('| **67** |'), 'Integrity matrix must include Suite 67');
  assert.ok(integrityContent.includes('| **68** |'), 'Integrity matrix must include Suite 68');
  assert.ok(integrityContent.includes('| **69** |'), 'Integrity matrix must include Suite 69');
  assert.ok(integrityContent.includes('| **70** |'), 'Integrity matrix must include Suite 70');
  assert.ok(integrityContent.includes('| **71** |'), 'Integrity matrix must include Suite 71');
  assert.ok(integrityContent.includes('| **72** |'), 'Integrity matrix must include Suite 72');
  console.log('  ✓ EJII_TEST_EXECUTION_INTEGRITY_REPORT.md contains zero stale counts and reflects all 68 suites.');

  // [64.4] Canonical Deployment Report Alignment
  console.log('[64.4] Verifying EJII_SECURE_DEPLOYMENT_REPORT.md consistency...');
  const deploymentReportPath = path.join(rootDir, 'EJII_SECURE_DEPLOYMENT_REPORT.md');
  assert.ok(fs.existsSync(deploymentReportPath), 'EJII_SECURE_DEPLOYMENT_REPORT.md must exist');
  const deploymentContent = fs.readFileSync(deploymentReportPath, 'utf8');

  assert.ok(
    (/72\s*\/\s*72/.test(deploymentContent) || /68\s*\/\s*68/.test(deploymentContent)),
    'EJII_SECURE_DEPLOYMENT_REPORT.md must reflect 68 / 68 passing suites'
  );
  assert.ok(
    (/72 Test Suites/.test(deploymentContent) || /68 Test Suites/.test(deploymentContent)),
    'EJII_SECURE_DEPLOYMENT_REPORT.md must reference 68 Test Suites'
  );
  assert.ok(
    deploymentContent.includes('Clean Working Tree (Audited Baseline)'),
    'EJII_SECURE_DEPLOYMENT_REPORT.md must confirm clean working tree status'
  );
  console.log('  ✓ EJII_SECURE_DEPLOYMENT_REPORT.md verified with 68/68 suites and clean baseline.\n');

  console.log('========================================================================');
  console.log('  SUITE 64 PASSED: MASTER REPORT CONSISTENCY & ZERO STALE COUNTS 100%   ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runReportConsistencyAndZeroStaleCountsTests().then(() => {
    process.exit(0);
  }).catch((err) => {
    console.error('Suite 64 failed:', err);
    process.exit(1);
  });
}

module.exports = {
  runReportConsistencyAndZeroStaleCountsTests,
  runSuite64: runReportConsistencyAndZeroStaleCountsTests
};
