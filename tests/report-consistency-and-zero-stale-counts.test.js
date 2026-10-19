/**
 * EJII Test Suite 64: Master Report Consistency, Zero Zombie Files & 64-Suite Milestone
 * 
 * Verifies:
 * [64.1] Zero Zombie Artifacts & Hygiene (sync_now.bat eliminated, .gitignore enforced)
 * [64.2] Master Test Runner 64-Suite Registration & Execution Invariant
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
  console.log('  SUITE 64: MASTER REPORT CONSISTENCY, HYGIENE & 64-SUITE MILESTONE      ');
  console.log('  Zero Zombie Artifacts, Zero Stale Counts & Canonical 64/64 Alignment   ');
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

  // [64.2] Master Test Runner 64-Suite Registration
  console.log('[64.2] Verifying master test runner registration of all 64 suites...');
  const runnerPath = path.join(rootDir, 'tests', 'run-all-tests.js');
  const runnerContent = fs.readFileSync(runnerPath, 'utf8');

  assert.ok(runnerContent.includes('autonomous-goal-workflow-and-endpoint-memory.test'), 'Runner must import Suite 61');
  assert.ok(runnerContent.includes('office-protocol-banners-and-reverification-diff.test'), 'Runner must import Suite 62');
  assert.ok(runnerContent.includes('five-view-frontend-backend-wiring.test'), 'Runner must import Suite 63');
  assert.ok(runnerContent.includes('report-consistency-and-zero-stale-counts.test'), 'Runner must import Suite 64');

  // Count registered suites in run-all-tests.js
  const suiteEntries = runnerContent.match(/\{\s*name:\s*['"]\d+\./g) || [];
  assert.strictEqual(
    suiteEntries.length,
    64,
    `Expected exactly 64 registered test suites in run-all-tests.js, found ${suiteEntries.length}`
  );
  console.log(`  ✓ Exactly 64 suites registered in tests/run-all-tests.js.`);

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

  // Must reflect 64 suites
  assert.ok(
    /64\s*\/\s*64|64 Suites|Comprehensive 64-Suite Matrix/.test(integrityContent),
    'EJII_TEST_EXECUTION_INTEGRITY_REPORT.md must reflect 64 suites milestone'
  );

  // Check table matrix contains rows 61-64
  assert.ok(integrityContent.includes('| **61** |'), 'Integrity matrix must include Suite 61');
  assert.ok(integrityContent.includes('| **62** |'), 'Integrity matrix must include Suite 62');
  assert.ok(integrityContent.includes('| **63** |'), 'Integrity matrix must include Suite 63');
  assert.ok(integrityContent.includes('| **64** |'), 'Integrity matrix must include Suite 64');
  console.log('  ✓ EJII_TEST_EXECUTION_INTEGRITY_REPORT.md contains zero stale counts and reflects all 64 suites.');

  // [64.4] Canonical Deployment Report Alignment
  console.log('[64.4] Verifying EJII_SECURE_DEPLOYMENT_REPORT.md consistency...');
  const deploymentReportPath = path.join(rootDir, 'EJII_SECURE_DEPLOYMENT_REPORT.md');
  assert.ok(fs.existsSync(deploymentReportPath), 'EJII_SECURE_DEPLOYMENT_REPORT.md must exist');
  const deploymentContent = fs.readFileSync(deploymentReportPath, 'utf8');

  assert.ok(
    /64\s*\/\s*64/.test(deploymentContent),
    'EJII_SECURE_DEPLOYMENT_REPORT.md must reflect 64 / 64 passing suites'
  );
  assert.ok(
    /64 Test Suites/.test(deploymentContent),
    'EJII_SECURE_DEPLOYMENT_REPORT.md must reference 64 Test Suites'
  );
  assert.ok(
    deploymentContent.includes('Clean Working Tree (Audited Baseline)'),
    'EJII_SECURE_DEPLOYMENT_REPORT.md must confirm clean working tree status'
  );
  console.log('  ✓ EJII_SECURE_DEPLOYMENT_REPORT.md verified with 64/64 suites and clean baseline.\n');

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
