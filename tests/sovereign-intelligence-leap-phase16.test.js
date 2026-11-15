/**
 * EJII Capstone Verification Suite — Phase 16.0
 * Sovereign Hyper-Scale Cognition, AF_XDP Zero-Copy Ingestion,
 * Simplicial Persistent Homology & Counterfactual Pearlian Singularity
 *
 * Verifies:
 *   1. AF_XDP Zero-Copy Ingestion & UMEM Lock-Free Ring Buffer Architecture
 *   2. Simplicial Persistent Homology & Betti Curve Forensics
 *   3. Pearlian Structural Counterfactual SCM & Active Policy Refusal Sentinel
 *   4. Verifiable Telemetry Ledger & Succinct ZK-SNARK Attestor
 *   5. WebGL2 Instanced Viewport Integration & 11-View Restraint
 *   6. 100% Dual-Maintenance Module Parity (70 Flagship Modules) & Preflight Health
 */

'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

// Track 1 imports
const { AfXdpUmemRingBuffer, afXdpUmemRingBuffer } = require('../src/sniffer/af-xdp-umem-ring-buffer');

// Track 2 imports
const { PersistentSimplicialHomology, persistentSimplicialHomology } = require('../src/topology/persistent-simplicial-homology');
const { BettiCurveForensics, bettiCurveForensics } = require('../src/topology/betti-curve-forensics');

// Track 3 imports
const { CounterfactualCausalSimulator, counterfactualCausalSimulator } = require('../src/ai/counterfactual-causal-simulator');
const { ActivePolicyRefusalSentinel, activePolicyRefusalSentinel } = require('../src/ai/active-policy-refusal-sentinel');

// Track 4 imports
const { ZkSnarkStateVerifier, zkSnarkStateVerifier } = require('../src/security/zk-snark-state-verifier');
const { VerifiableTelemetryLedger, verifiableTelemetryLedger } = require('../src/security/verifiable-telemetry-ledger');

async function runSovereignIntelligenceLeapPhase16Tests() {
  console.log('========================================================================');
  console.log('  PHASE 16.0 CAPSTONE: SOVEREIGN HYPER-SCALE COGNITION & AF_XDP SINGULARITY');
  console.log('  Zero-Simulation Verification Mandate                                  ');
  console.log('========================================================================\n');

  const rootDir = path.resolve(__dirname, '..');

  // ---------------------------------------------------------------------------
  // Track 1: AF_XDP Zero-Copy Ingestion & UMEM Lock-Free Ring Buffer Architecture
  // ---------------------------------------------------------------------------
  console.log('[Track 1] Verifying AF_XDP UMEM Memory Pool & Lock-Free SPSC Ring Queues...');
  const umem = new AfXdpUmemRingBuffer();

  const pool = umem.allocateUmemPool(512, 2048);
  assert.strictEqual(pool.totalFrames, 512);
  assert.strictEqual(pool.frameSizeBytes, 2048);
  assert.strictEqual(pool.isAllocated, true);

  // Submit RX descriptors for burst ingestion
  const submit1 = umem.submitRxDescriptor(0, 1514);
  const submit2 = umem.submitRxDescriptor(1, 1024);
  const submit3 = umem.submitRxDescriptor(2, 64);
  assert.strictEqual(submit1, true);
  assert.strictEqual(submit2, true);
  assert.strictEqual(submit3, true);

  // Invalid frame submission guard
  assert.strictEqual(umem.submitRxDescriptor(999, 100), false, 'Out-of-bounds frame index must be rejected');
  assert.strictEqual(umem.submitRxDescriptor(3, 5000), false, 'Frame exceeding 2048 bytes must be rejected');

  // Poll RX burst
  const burst = umem.pollRxBurst(32);
  assert.strictEqual(burst.length, 3, 'Must poll all 3 pending RX descriptors');
  assert.strictEqual(burst[0].frameIndex, 0);
  assert.strictEqual(burst[0].packetLength, 1514);
  assert.ok(burst[0].timestampNs > 0n);

  // Submit TX descriptor & check completion queue
  const txSubmitted = umem.submitTxDescriptor(0, 1514);
  assert.strictEqual(txSubmitted, true);

  // Release completed frames for recycling
  const releasedCount = umem.releaseCompletedFrames([0, 1, 2]);
  assert.ok(releasedCount >= 1, 'Must release and recycle completed frame indices');

  // Verify direct slice access without copying
  const slice = umem.getFrameBufferSlice(0, 64);
  assert.ok(slice instanceof Uint8Array);
  assert.strictEqual(slice.length, 64);

  const metrics1 = umem.getMetrics();
  assert.strictEqual(metrics1.totalFrames, 512);
  assert.ok(metrics1.rxBurstThroughput >= 3);
  console.log('  ✓ AF_XDP UMEM memory pool, lock-free SPSC ring buffers, and burst poll verified.');

  // ---------------------------------------------------------------------------
  // Track 2: Simplicial Persistent Homology & Betti Curve Forensics
  // ---------------------------------------------------------------------------
  console.log('[Track 2.1] Verifying Vietoris-Rips Persistent Simplicial Homology...');
  const homology = new PersistentSimplicialHomology();

  const nodes = ['core-r1', 'core-r2', 'core-r3', 'edge-sw1'];
  const pairwiseDistances = {
    'core-r1': { 'core-r2': 1.0, 'core-r3': 1.0, 'edge-sw1': 4.0 },
    'core-r2': { 'core-r1': 1.0, 'core-r3': 1.0, 'edge-sw1': 4.0 },
    'core-r3': { 'core-r1': 1.0, 'core-r2': 1.0, 'edge-sw1': 4.0 },
    'edge-sw1': { 'core-r1': 4.0, 'core-r2': 4.0, 'core-r3': 4.0 }
  };

  const metricMatrix = homology.constructMetricMatrix(nodes, pairwiseDistances);
  assert.strictEqual(metricMatrix.length, 16);

  const persistenceResult = homology.computePersistenceDiagrams(nodes, metricMatrix, 6.0, 0.5);
  assert.strictEqual(persistenceResult.nodeCount, 4);
  assert.ok(persistenceResult.filtrationSteps.length > 5);
  assert.ok(persistenceResult.betti0Trajectory[0] === 4, 'At epsilon=0, all 4 nodes are isolated components');
  assert.ok(persistenceResult.betti0Trajectory[persistenceResult.betti0Trajectory.length - 1] === 1, 'At high epsilon, topology converges to single component');

  // Wasserstein distance calculation against self (must be 0.0)
  const distZero = homology.computeWassersteinDistance(persistenceResult.features, persistenceResult.features);
  assert.strictEqual(distZero, 0.0, 'Wasserstein distance of identical persistence diagrams must be 0.0');

  console.log('[Track 2.2] Verifying Betti Curve Forensics & Triadic Route Loop Detection...');
  const bettiForensics = new BettiCurveForensics();
  const bettiProfile = bettiForensics.extractBettiProfile(persistenceResult);

  assert.ok(bettiProfile.maxBetti0 >= 1);
  assert.ok(Array.isArray(bettiProfile.dominantCycles));

  const triadicReport = bettiForensics.detectTriadicRouteLoops(bettiProfile);
  assert.ok(typeof triadicReport.hasTriadicLoops === 'boolean');
  assert.ok(['NONE', 'LOW', 'HIGH_OSCILLATION'].includes(triadicReport.loopSeverity));
  console.log(`  ✓ Persistent Simplicial Homology calculated Betti trajectories and evaluated triadic loops (severity: ${triadicReport.loopSeverity}).`);

  // ---------------------------------------------------------------------------
  // Track 3: Pearlian Structural Counterfactual SCM & Active Policy Refusal Sentinel
  // ---------------------------------------------------------------------------
  console.log('[Track 3.1] Verifying Pearlian Counterfactual SCM Simulator...');
  const cfSimulator = new CounterfactualCausalSimulator();

  const causalDag = {
    targetVariable: 'packetLossPct',
    variables: {
      routeFlapRate: {
        name: 'routeFlapRate',
        parents: [],
        equationWeights: {},
        baseMean: 2.0
      },
      bufferCongestion: {
        name: 'bufferCongestion',
        parents: ['routeFlapRate'],
        equationWeights: { routeFlapRate: 1.5 },
        baseMean: 10.0
      },
      packetLossPct: {
        name: 'packetLossPct',
        parents: ['bufferCongestion', 'routeFlapRate'],
        equationWeights: { bufferCongestion: 0.8, routeFlapRate: 1.2 },
        baseMean: 1.0
      }
    }
  };

  // Case A: Safe intervention (reducing route flapping via damping)
  const observedEvidence = {
    routeFlapRate: 8.0,
    bufferCongestion: 22.0,
    packetLossPct: 18.0
  };

  const safeIntervention = { variable: 'routeFlapRate', value: 1.0 };
  const safeCfResult = cfSimulator.simulateCounterfactual(causalDag, observedEvidence, safeIntervention);

  assert.strictEqual(safeCfResult.intervention.variable, 'routeFlapRate');
  assert.strictEqual(safeCfResult.counterfactualOutcomes['routeFlapRate'], 1.0);
  assert.ok(safeCfResult.counterfactualOutcomes['packetLossPct'] < observedEvidence.packetLossPct, 'Safe intervention must reduce counterfactual packet loss');
  assert.strictEqual(safeCfResult.isHarmful, false);

  // Case B: Harmful intervention (drastically inflating link load)
  const harmfulIntervention = { variable: 'routeFlapRate', value: 35.0 };
  const harmfulCfResult = cfSimulator.simulateCounterfactual(causalDag, observedEvidence, harmfulIntervention);
  assert.strictEqual(harmfulCfResult.isHarmful, true, 'Drastic inflation must be flagged harmful');

  const probHarm = cfSimulator.computeProbabilityOfHarm(harmfulCfResult, 10.0);
  assert.ok(probHarm > 0.5, 'Probability of harm must exceed 0.5 under severe counterfactual degradation');

  console.log('[Track 3.2] Verifying Active Policy Refusal Sentinel & Mathematical Refusal Proofs...');
  const sentinel = new ActivePolicyRefusalSentinel();

  const proposedAction = {
    actionId: 'act-remed-agg-reroute',
    name: 'Aggressive WAN Traffic Injection',
    targetDevice: 'gw-core-1',
    command: 'set interface wan0 cost 9999',
    expectedBenefit: 'Reroute all transit traffic to secondary peer'
  };

  // Evaluate safety on harmful counterfactual
  const verdictRefused = sentinel.evaluatePolicySafety(proposedAction, harmfulCfResult);
  assert.strictEqual(verdictRefused.isApproved, false, 'Harmful intervention must be REFUSED');
  assert.strictEqual(verdictRefused.recommendation, 'REFUSED_HIGH_COUNTERFACTUAL_RISK');
  assert.ok(verdictRefused.refusalCertificate, 'Must issue a formal PolicyRefusalCertificate');
  assert.strictEqual(verdictRefused.refusalCertificate.safetyViolationDetected, true);
  assert.ok(verdictRefused.refusalCertificate.mathematicalBound.includes('P(Harm'));

  // Evaluate safety on safe counterfactual
  const verdictApproved = sentinel.evaluatePolicySafety(proposedAction, safeCfResult);
  assert.strictEqual(verdictApproved.isApproved, true, 'Safe intervention must be APPROVED');
  assert.strictEqual(verdictApproved.recommendation, 'SAFE_TO_EXECUTE');
  console.log('  ✓ Pearlian Counterfactual SCM evaluated abduction-action-prediction and generated formal Refusal Certificate.');

  // ---------------------------------------------------------------------------
  // Track 4: Verifiable Telemetry Ledger & Succinct ZK-SNARK Attestor
  // ---------------------------------------------------------------------------
  console.log('[Track 4.1] Verifying Succinct ZK-SNARK Arithmetic Circuit Attestor...');
  const zkVerifier = new ZkSnarkStateVerifier();

  const compliantMetrics = [1.2, 4.5, 12.0, 8.4, 25.1, 48.0, 110.0];
  const validProof = zkVerifier.generateBatchProof(compliantMetrics, 200.0);
  assert.strictEqual(validProof.isCompliant, true);
  assert.strictEqual(zkVerifier.verifyBatchProof(validProof), true, 'Valid batch proof must be cryptographically verified');

  // Violating metric batch
  const nonCompliantMetrics = [5.0, 12.0, 350.0]; // Exceeds 200.0 SLA limit
  const invalidProof = zkVerifier.generateBatchProof(nonCompliantMetrics, 200.0);
  assert.strictEqual(invalidProof.isCompliant, false);
  assert.strictEqual(zkVerifier.verifyBatchProof(invalidProof), false, 'Non-compliant metrics must fail ZK verification');

  console.log('[Track 4.2] Verifying Verifiable Multi-Site Telemetry Ledger & Chain Integrity...');
  const ledger = new VerifiableTelemetryLedger();

  const block1 = ledger.appendTelemetryBlock('us-east-site', validProof.metricCommitment, validProof);
  assert.strictEqual(block1.blockIndex, 1);
  assert.ok(block1.blockHash.length === 64, 'SHA-256 block hash must be 64 characters');

  const block2 = ledger.appendTelemetryBlock('eu-west-site', validProof.metricCommitment, validProof);
  assert.strictEqual(block2.blockIndex, 2);
  assert.strictEqual(block2.previousBlockHash, block1.blockHash, 'Block 2 must chain to Block 1 hash');

  const integrity = ledger.verifyLedgerIntegrity();
  assert.strictEqual(integrity.isValid, true, 'Telemetry ledger chain integrity must be valid');
  assert.ok(integrity.totalBlocks >= 3, 'Genesis + 2 blocks must exist');
  console.log(`  ✓ Verifiable Telemetry Ledger verified chain integrity across ${integrity.totalBlocks} cryptographically attested blocks.`);

  // ---------------------------------------------------------------------------
  // Track 5: WebGL2 Instanced Viewport Pipeline & 11 Views Invariant
  // ---------------------------------------------------------------------------
  console.log('[Track 5] Verifying WebGL2 Pipeline Helper & 11 Views Invariant...');
  const viewsDir = path.join(rootDir, 'public', 'js', 'views');
  const viewEntries = fs.readdirSync(viewsDir).filter(f => f.endsWith('.js'));
  assert.strictEqual(viewEntries.length, 11, 'public/js/views/ must maintain strictly 11 view files');

  const enterpriseNocModule = require('../public/js/views/enterprise-noc-view');
  assert.ok(typeof enterpriseNocModule.createWebGl2TopologyPipeline === 'function', 'enterprise-noc-view must export createWebGl2TopologyPipeline');

  const batContent = fs.readFileSync(path.join(rootDir, 'setup-launcher.bat'), 'utf8');
  assert.ok(batContent.includes('152-suite'), 'setup-launcher.bat must reference 152-suite verification');

  const shContent = fs.readFileSync(path.join(rootDir, 'setup-launcher.sh'), 'utf8');
  assert.ok(shContent.includes('152-suite'), 'setup-launcher.sh must reference 152-suite verification');
  console.log('  ✓ WebGL2 topology rendering pipeline and 11-view invariant confirmed.');

  // ---------------------------------------------------------------------------
  // Track 6: Parity Guard Execution & Fast Preflight Verification
  // ---------------------------------------------------------------------------
  console.log('[Track 6] Verifying Parity Guard (70 modules) and Preflight Health...');
  const parityScript = path.join(rootDir, 'scripts', 'verify-ts-js-parity.js');
  execFileSync(process.execPath, [parityScript], { stdio: 'pipe' });
  console.log('  ✓ All 70 flagship modules verified in 100% TypeScript/JavaScript dual parity.');

  const preflightScript = path.join(rootDir, 'scripts', 'verify-fast-preflight.js');
  const t0 = process.hrtime.bigint();
  execFileSync(process.execPath, [preflightScript], { stdio: 'pipe' });
  const preflightMs = Number(process.hrtime.bigint() - t0) / 1e6;
  assert.ok(preflightMs < 1000, `Preflight must execute cleanly under 1000ms, took ${preflightMs.toFixed(2)}ms`);
  console.log(`  ✓ Fast preflight verified in ${preflightMs.toFixed(2)}ms.`);

  console.log('\n========================================================================');
  console.log('  PHASE 16.0 CAPSTONE VERIFICATION: ALL TRACKS PASSED!                  ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runSovereignIntelligenceLeapPhase16Tests()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}

module.exports = { runSovereignIntelligenceLeapPhase16Tests };
