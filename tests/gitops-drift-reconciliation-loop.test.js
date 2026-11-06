/**
 * EJII Test Suite 68: Category E Modernization Verification
 * Declarative GitOps Infrastructure-as-Code (IaC) Drift Detection Engine
 * & Continuous Autonomous Reconciliation Loop
 */

const assert = require('assert');
const { gitopsReconciliationEngine } = require('../src/core/gitops-reconciliation-engine');
const { db } = require('../src/db/database');

async function runGitopsDriftReconciliationLoopTests() {
  console.log('========================================================================');
  console.log('  SUITE 68: DECLARATIVE GITOPS DRIFT DETECTION & RECONCILIATION LOOP    ');
  console.log('========================================================================\n');

  // [68.1] Verify Desired State Manifest Loading & Cryptographic Hash
  console.log('[68.1] Verifying declarative GitOps manifest (policies/desired-infrastructure-state.json)...');
  const manifest = gitopsReconciliationEngine.loadDesiredStateManifest();
  assert.ok(manifest && manifest.desiredStateHash && manifest.desiredStateHash.length === 64);
  assert.strictEqual(manifest.spec.topologyInvariants.forbidHardcodedAlienAppIp, true);
  console.log(`  ✓ GitOps manifest loaded (SHA-256=${manifest.desiredStateHash.slice(0, 16)}...).`);

  // [68.2] Inject Deliberate Topology Drift (Alien 10.22.12.204 IP) -> Verify Drift Detection & Auto-Reconciliation
  console.log('[68.2] Simulating topology drift (injecting alien 10.22.12.204 into NODE-APP-01) and running reconciler...');
  db.prepare("UPDATE topology_nodes SET hostname_or_ip = '10.22.12.204' WHERE id = 'NODE-APP-01'").run();

  const driftBefore = gitopsReconciliationEngine.detectInfrastructureDrift();
  assert.strictEqual(driftBefore.status, 'DRIFT_DETECTED', 'Must detect forbidden static alien IP drift on NODE-APP-01');
  assert.ok(driftBefore.drifts.some((d) => d.driftType === 'DRIFT_FORBIDDEN_STATIC_IP' || d.driftType === 'DRIFT_TOPOLOGY_SUBNET_MISMATCH'));

  const reconcileRes = gitopsReconciliationEngine.reconcileDrift({ autoHealSafeTopologyDrift: true });
  assert.strictEqual(reconcileRes.reconciled, true);
  assert.ok(reconcileRes.actionsExecuted.length >= 1, 'Reconciler must execute topology location sync');

  const appNodeAfter = db.prepare("SELECT hostname_or_ip FROM topology_nodes WHERE id = 'NODE-APP-01'").get();
  assert.notStrictEqual(appNodeAfter.hostname_or_ip, '10.22.12.204', 'Reconciler must heal NODE-APP-01 back to current location subnet');
  console.log(`  ✓ GitOps Reconciler healed NODE-APP-01 from 10.22.12.204 -> ${appNodeAfter.hostname_or_ip}.\n`);

  console.log('========================================================================');
  console.log('  SUITE 68 PASSED: GITOPS DRIFT & RECONCILIATION LOOP 100% GREEN        ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runGitopsDriftReconciliationLoopTests()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('Suite 68 failed:', err);
      process.exit(1);
    });
}

module.exports = { runGitopsDriftReconciliationLoopTests };
