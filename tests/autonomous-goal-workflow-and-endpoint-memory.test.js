/**
 * EJII Test Suite 61: Autonomous Goal Workflow & Endpoint Behavioral Profile Memory
 * 
 * Verifies:
 * [61.1] SQLite WAL Migration v4 Schema (endpoint_behavioral_profiles & autonomous_workflow_runs)
 * [61.2] Brain Persistence Repository CRUD for Endpoint Behavioral Memory & Workflow Runs
 * [61.3] 8-Invariant Empirical Output Self-Validation (Zero Hallucination, Monotonic Timestamps, Uncertainty Bounds)
 * [61.4] Closed-Loop Multi-Turn Autonomous Workflow Execution (aiBrain.planAndExecuteAutonomousWorkflow)
 * [61.5] RCA REST Endpoints (/api/rca/brain/autonomous-workflow and /history)
 */

'use strict';

const assert = require('assert');
const path = require('path');
const { db } = require('../src/db/database');
const { runMigrations, MIGRATIONS } = require('../src/db/migrations');
const { brainPersistenceRepository: brainPersistenceRepo } = require('../src/db/brain-persistence-repository');
const { aiBrain } = require('../src/core/ai-brain');
const { aiModelOrchestrator } = require('../src/core/ai-model-orchestrator');

async function runAutonomousGoalWorkflowAndEndpointMemoryTests() {
  console.log('========================================================================');
  console.log('  SUITE 61: AUTONOMOUS GOAL WORKFLOW & ENDPOINT MEMORY                   ');
  console.log('  Closed-Loop Multi-Turn DAG, 8-Invariant Self-Validation & SQLite WAL v4');
  console.log('========================================================================\n');

  // [61.1] Migration v4 Verification
  console.log('[61.1] Verifying SQLite WAL Migration v4 schema...');
  runMigrations(db);

  const profileTable = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='endpoint_behavioral_profiles'").get();
  assert.ok(profileTable, 'Table endpoint_behavioral_profiles must exist in SQLite database');

  const workflowTable = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='autonomous_workflow_runs'").get();
  assert.ok(workflowTable, 'Table autonomous_workflow_runs must exist in SQLite database');

  const profileCols = db.prepare("PRAGMA table_info(endpoint_behavioral_profiles)").all().map(c => c.name);
  assert.ok(profileCols.includes('target_key'), 'endpoint_behavioral_profiles must have target_key');
  assert.ok(profileCols.includes('calibration_json'), 'endpoint_behavioral_profiles must have calibration_json');
  assert.ok(profileCols.includes('expected_equipment_type'), 'endpoint_behavioral_profiles must have expected_equipment_type');
  console.log('  ✓ SQLite WAL Migration v4 verified: endpoint_behavioral_profiles & autonomous_workflow_runs.');

  // [61.2] Brain Persistence Repository CRUD
  console.log('[61.2] Verifying endpoint behavioral profile and workflow run persistence...');
  const testTargetKey = '192.168.100.42:631';

  brainPersistenceRepo.upsertEndpointProfile({
    targetKey: testTargetKey,
    macAddress: '00:11:22:33:44:55',
    expectedEquipmentType: 'NETWORK_PRINTER',
    knownOpenPorts: [631, 80],
    calibration: {
      baselineLatencyMs: 4.8,
      observedJitterMs: 0.9,
      calibrationConfidence: 0.92,
      observedBanners: ['HP LaserJet IPP/2.0']
    }
  });

  const fetchedProfile = brainPersistenceRepo.getEndpointProfile(testTargetKey);
  assert.ok(fetchedProfile, 'Should retrieve upserted endpoint profile');
  assert.strictEqual(fetchedProfile.target_key, testTargetKey);
  assert.strictEqual(fetchedProfile.expected_equipment_type, 'NETWORK_PRINTER');
  assert.ok(Array.isArray(fetchedProfile.knownOpenPorts));
  assert.strictEqual(fetchedProfile.calibration.calibrationConfidence, 0.92);
  assert.strictEqual(fetchedProfile.calibration.observedBanners[0], 'HP LaserJet IPP/2.0');

  // Test workflow run persistence
  const testRunId = `wf-test-${Date.now()}`;
  brainPersistenceRepo.saveAutonomousWorkflowRun({
    workflowId: testRunId,
    targetHost: '192.168.100.42',
    targetPort: 631,
    goal: 'Test printer banner and responsiveness',
    status: 'COMPLETED',
    iterations: 3,
    durationMs: 450,
    plan: [{ step: 1, action: 'probe_port' }],
    executionSteps: [{ step: 1, tool: 'probe_port', output: { open: true } }],
    synthesis: { summary: 'Port 631 open, responsive HP printer' },
    invariantValidation: { valid: true }
  });

  const recentRuns = brainPersistenceRepo.getRecentAutonomousWorkflowRuns(10);
  assert.ok(Array.isArray(recentRuns) && recentRuns.length > 0, 'Recent runs must return non-empty array');
  const foundRun = recentRuns.find(r => r.workflow_id === testRunId);
  assert.ok(foundRun, `Workflow run ${testRunId} must be present in recent runs`);
  assert.strictEqual(foundRun.status, 'COMPLETED');
  assert.strictEqual(foundRun.target_host, '192.168.100.42');
  console.log('  ✓ Endpoint behavioral profile & workflow run persistence verified.');

  // [61.3] 8-Invariant Empirical Self-Validation
  console.log('[61.3] Verifying 8-invariant empirical self-validation in aiModelOrchestrator...');
  
  // Valid output passing all 8 invariants
  const validDiagnosis = {
    summary: 'Host 127.0.0.1 responds normally with nominal TCP connection latency.',
    rootCauseHypothesis: 'NORMAL_OPERATION',
    epistemicCertainty: 0.95,
    confidenceInterval: [0.90, 0.98],
    evidenceChain: ['TCP socket connected in 2.1ms', 'No dropped packets on wire'],
    recommendedActions: ['Continue periodic health monitoring'],
    probedPorts: [80, 443],
    startTimestamp: 1000,
    endTimestamp: 1200,
    entropyDelta: 0.42
  };

  const validTelemetry = {
    host: '127.0.0.1',
    openPorts: [80],
    rttMs: 2.1
  };

  const validResult = aiModelOrchestrator.validateDiagnosisOutput(validDiagnosis, validTelemetry);
  assert.strictEqual(validResult.valid, true, 'Valid diagnosis must pass all invariants');
  assert.strictEqual(validResult.results.length, 8, 'Must evaluate exactly 8 invariants');

  // Invalid: Port hallucination (claims port 8080 open without probing)
  const hallucinatedDiagnosis = {
    ...validDiagnosis,
    summary: 'Port 8080 is experiencing an HTTP connection reset attack!',
    probedPorts: [80] // Probed 80, but hallucinating about 8080
  };
  const invalidResult1 = aiModelOrchestrator.validateDiagnosisOutput(hallucinatedDiagnosis, validTelemetry);
  assert.strictEqual(invalidResult1.valid, false, 'Port hallucination must fail validation');
  assert.ok(invalidResult1.violations.some(v => v.includes('Port Hallucination')), 'Must flag Port Hallucination');

  // Invalid: Inverted confidence interval
  const invertedCiDiagnosis = {
    ...validDiagnosis,
    confidenceInterval: [0.95, 0.40] // Lower > upper
  };
  const invalidResult2 = aiModelOrchestrator.validateDiagnosisOutput(invertedCiDiagnosis, validTelemetry);
  assert.strictEqual(invalidResult2.valid, false, 'Inverted confidence interval must fail validation');
  assert.ok(invalidResult2.violations.some(v => v.includes('Confidence Interval')), 'Must flag Confidence Interval');
  console.log('  ✓ 8-invariant empirical self-validation engine verified.');

  // [61.4] Autonomous AI Goal Workflow Planner
  console.log('[61.4] Verifying closed-loop multi-turn autonomous workflow execution...');
  const workflowOutcome = await aiBrain.planAndExecuteAutonomousWorkflow({
    targetHost: '127.0.0.1',
    targetPort: 80,
    goal: 'Investigate localhost loopback endpoint and calibrate behavioral profile',
    maxIterations: 4
  });

  assert.ok(workflowOutcome, 'Workflow outcome must be returned');
  assert.ok(workflowOutcome.success, 'Workflow must report success');
  assert.strictEqual(workflowOutcome.status, 'COMPLETED');
  assert.ok(workflowOutcome.iterations >= 1 && workflowOutcome.iterations <= 4);
  assert.ok(Array.isArray(workflowOutcome.executionSteps) && workflowOutcome.executionSteps.length >= 1);
  assert.ok(workflowOutcome.synthesis, 'Workflow must produce synthesis');
  assert.ok(workflowOutcome.invariantValidation, 'Workflow must execute invariant validation');
  assert.strictEqual(workflowOutcome.invariantValidation.valid, true);

  // Verify calibrated endpoint profile exists in memory and DB
  assert.ok(workflowOutcome.profile, 'Workflow must return updated endpoint behavioral profile');
  assert.strictEqual(workflowOutcome.profile.target_key, '127.0.0.1');
  const storedProfile = brainPersistenceRepo.getEndpointProfile('127.0.0.1');
  assert.ok(storedProfile, 'Calibrated profile must be saved to SQLite WAL');
  console.log(`  ✓ Autonomous workflow executed (${workflowOutcome.iterations} iterations, ${workflowOutcome.durationMs}ms, profile calibrated).`);

  // [61.5] RCA REST Endpoints Integrity
  console.log('[61.5] Verifying RCA REST endpoints definition...');
  const routesPath = path.join(__dirname, '..', 'src', 'api', 'routes-rca.js');
  const routesContent = require('fs').readFileSync(routesPath, 'utf8');
  assert.ok(routesContent.includes('/brain/autonomous-workflow'), 'routes-rca.js must mount /brain/autonomous-workflow');
  assert.ok(routesContent.includes('/brain/autonomous-workflow/history'), 'routes-rca.js must mount /brain/autonomous-workflow/history');
  console.log('  ✓ Autonomous workflow REST API routes confirmed.\n');

  console.log('========================================================================');
  console.log('  SUITE 61 PASSED: AUTONOMOUS WORKFLOW & ENDPOINT MEMORY 100% GREEN     ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runAutonomousGoalWorkflowAndEndpointMemoryTests().then(() => {
    process.exit(0);
  }).catch((err) => {
    console.error('Suite 61 failed:', err);
    process.exit(1);
  });
}

module.exports = {
  runAutonomousGoalWorkflowAndEndpointMemoryTests,
  runSuite61: runAutonomousGoalWorkflowAndEndpointMemoryTests
};
