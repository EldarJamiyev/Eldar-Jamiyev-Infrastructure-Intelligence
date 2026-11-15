/**
 * EJII Capstone Verification Suite — Phase 18.0
 * Sovereign SIMD eBPF Vectorization, Lattice-Based Post-Quantum Attestation,
 * Continual Online Meta-Learning (MAML) & Geo-Quorum Lease Fencing
 *
 * Verifies:
 *   1. SIMD-Vectorized Packet Filter Engine & Bitmask Fastpath Compiler
 *   2. Post-Quantum Module Lattice Epistemic Attestor & Authority Delegator
 *   3. Continual Online Meta-Reinforcement Learning (MAML) & Concept Drift Compensator
 *   4. Geo-Quorum Lease Arbiter & Virtual STONITH Split-Brain Fencing Sentinel
 *   5. Quantum Attestation HUD & 11 Views Invariant
 *   6. 100% Dual-Maintenance Module Parity (84 Modules) & Fast Desktop Preflight
 */

'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

// Track 1 imports
const { SimdVectorizedPacketFilter, simdVectorizedPacketFilter } = require('../src/sniffer/simd-vectorized-packet-filter');

// Track 2 imports
const { LatticeEpistemicAttestor, latticeEpistemicAttestor } = require('../src/security/lattice-epistemic-attestor');
const { QuantumSafeRemediationDelegator, quantumSafeRemediationDelegator } = require('../src/security/quantum-safe-remediation-delegator');

// Track 3 imports
const { ContinuousOnlineMamlEngine, continuousOnlineMamlEngine } = require('../src/ai/continuous-online-maml-engine');
const { AdaptiveConceptDriftCompensator, adaptiveConceptDriftCompensator } = require('../src/ai/adaptive-concept-drift-compensator');

// Track 4 imports
const { GeoQuorumLeaseArbiter, geoQuorumLeaseArbiter } = require('../src/security/geo-quorum-lease-arbiter');
const { SplitBrainFencingSentinel, splitBrainFencingSentinel } = require('../src/security/split-brain-fencing-sentinel');

async function runSovereignIntelligenceLeapPhase18Tests() {
  console.log('========================================================================');
  console.log('  PHASE 18.0 CAPSTONE: SOVEREIGN SIMD VECTORIZATION & LATTICE SECURITY   ');
  console.log('  Zero-Simulation Verification Mandate                                  ');
  console.log('========================================================================\n');

  const rootDir = path.resolve(__dirname, '..');

  // ---------------------------------------------------------------------------
  // Track 1: SIMD-Vectorized Packet Filter Engine & Bitmask Fastpath Compiler
  // ---------------------------------------------------------------------------
  console.log('[Track 1] Verifying SIMD-Vectorized Bitmask Packet Filter...');
  const filter = new SimdVectorizedPacketFilter();

  filter.compileRule('rule-http-80', {
    protocol: 'TCP',
    dstPort: 80
  });

  const packets = [
    { packetId: 'pkt-01', srcIp: '10.0.0.1', dstIp: '192.168.1.5', srcPort: 49152, dstPort: 80, protocol: 'TCP', payloadLength: 200 },
    { packetId: 'pkt-02', srcIp: '10.0.0.2', dstIp: '192.168.1.5', srcPort: 49153, dstPort: 443, protocol: 'TCP', payloadLength: 400 },
    { packetId: 'pkt-03', srcIp: '10.0.0.3', dstIp: '192.168.1.5', srcPort: 49154, dstPort: 80, protocol: 'TCP', payloadLength: 150 },
    { packetId: 'pkt-04', srcIp: '10.0.0.4', dstIp: '192.168.1.5', srcPort: 53, dstPort: 53, protocol: 'UDP', payloadLength: 64 },
    { packetId: 'pkt-05', srcIp: '10.0.0.5', dstIp: '192.168.1.5', srcPort: 49155, dstPort: 80, protocol: 'TCP', payloadLength: 800 }
  ];

  const batchRes = filter.evaluateBatch(packets);
  assert.strictEqual(batchRes.batchSize, 5);
  assert.strictEqual(batchRes.matchedPacketIds.length, 3, 'Packets 1, 3, 5 must match rule');
  assert.strictEqual(batchRes.matchedPacketIds[0], 'pkt-01');
  assert.strictEqual(batchRes.matchedPacketIds[1], 'pkt-03');
  assert.strictEqual(batchRes.matchedPacketIds[2], 'pkt-05');
  assert.ok(batchRes.matchMask > 0n);

  const filterMetrics = filter.getMetrics();
  assert.strictEqual(filterMetrics.totalEvaluated, 5);
  assert.strictEqual(filterMetrics.totalMatched, 3);
  console.log(`  ✓ SIMD filter evaluated 5 packets in parallel, matching ${batchRes.matchedPacketIds.length} frames.`);

  // ---------------------------------------------------------------------------
  // Track 2: Post-Quantum Module Lattice Epistemic Attestor & Authority Delegator
  // ---------------------------------------------------------------------------
  console.log('[Track 2.1] Verifying Post-Quantum Module Lattice Keygen & Polynomial Attestation...');
  const attestor = new LatticeEpistemicAttestor();

  const keyPair = attestor.generateKeyPair();
  assert.ok(keyPair.publicKey.startsWith('lat_pub_'));
  assert.ok(keyPair.privateKey.startsWith('lat_sec_'));
  assert.strictEqual(keyPair.dimension, 256);

  const stateDigest = 'sha256:4a8b79e13b82142d76f8e71c99f18a280c436d54238e55e87a5369cf932145b2';
  const attestation = attestor.signStateAttestation(stateDigest, keyPair.privateKey);
  assert.strictEqual(attestation.stateDigest, stateDigest);
  assert.strictEqual(attestation.commitmentZ.length, 16);
  assert.strictEqual(attestation.signatureProof.length, 64);

  const isVerified = attestor.verifyStateAttestation(attestation, keyPair.publicKey);
  assert.strictEqual(isVerified, true, 'Valid lattice commitment must verify');

  console.log('[Track 2.2] Verifying Quantum-Safe Remediation Authority Delegator...');
  const delegator = new QuantumSafeRemediationDelegator();

  const token = delegator.issueDelegationToken('act-bgp-reroute', 'site-eu-west', 60000);
  assert.ok(token.tokenId.startsWith('qtok_'));
  assert.strictEqual(token.actionId, 'act-bgp-reroute');
  assert.strictEqual(token.targetSite, 'site-eu-west');
  assert.ok(token.expiresAt > Date.now());

  const tokenValidation = delegator.validateDelegationToken(token);
  assert.strictEqual(tokenValidation.isValid, true);
  console.log(`  ✓ Post-quantum lattice attestation and quantum delegation token issued and cryptographically validated.`);

  // ---------------------------------------------------------------------------
  // Track 3: Continual Online Meta-Learning (MAML) Engine & Concept Drift
  // ---------------------------------------------------------------------------
  console.log('[Track 3.1] Verifying Continuous Online MAML Gradient Adaptation...');
  const maml = new ContinuousOnlineMamlEngine();

  const taskBatch = [
    {
      taskId: 'task-cloud-burst-1',
      observations: [
        { metricName: 'dnsLatencyMs', observedValue: 85.0, expectedValue: 20.0 },
        { metricName: 'tcpRttMs', observedValue: 92.0, expectedValue: 25.0 }
      ]
    }
  ];

  const metaReceipt = maml.metaTrainStep(taskBatch);
  assert.strictEqual(metaReceipt.tasksEvaluated, 1);
  assert.ok(metaReceipt.metaAdaptedLoss < metaReceipt.initialLoss);

  // Few-shot adaptation
  const adapted = maml.adaptToIncident([
    { metricName: 'dnsLatencyMs', observedValue: 90.0, expectedValue: 20.0, weight: 1.2 }
  ], 3);
  assert.strictEqual(adapted.stepsExecuted, 3);
  assert.ok(adapted.adaptedWeights['dnsLatencyMs'] !== undefined);

  console.log('[Track 3.2] Verifying Page-Hinkley Adaptive Concept Drift Compensator...');
  const driftComp = new AdaptiveConceptDriftCompensator(20.0, 0.05);

  // Stream nominal values
  for (let i = 0; i < 20; i++) {
    const res = driftComp.observeMetricSample('dnsLatencyMs', 15.0 + Math.sin(i) * 2);
    assert.strictEqual(res.driftDetected, false);
  }

  // Inject severe sudden shift (concept drift)
  let driftTriggered = false;
  for (let i = 0; i < 15; i++) {
    const res = driftComp.observeMetricSample('dnsLatencyMs', 150.0 + i * 5);
    if (res.driftDetected) {
      driftTriggered = true;
      break;
    }
  }
  assert.strictEqual(driftTriggered, true, 'Sudden 10x telemetry shift must trigger concept drift detection');
  console.log(`  ✓ MAML few-shot inner loop adapted causal weights; Page-Hinkley detector caught non-stationary telemetry drift.`);

  // ---------------------------------------------------------------------------
  // Track 4: Geo-Quorum Lease Arbiter & Virtual STONITH Fencing Sentinel
  // ---------------------------------------------------------------------------
  console.log('[Track 4.1] Verifying Geo-Quorum Lease Arbiter with Epoch Fencing...');
  const leaseArbiter = new GeoQuorumLeaseArbiter();

  const l1 = leaseArbiter.acquireLease('wan-gw-01', 'site-us-east', 20000);
  assert.strictEqual(l1.isGranted, true);
  assert.strictEqual(l1.holderSiteId, 'site-us-east');
  assert.ok(l1.epochGeneration >= 1001);

  // Competing acquisition by another site must be rejected
  const l2 = leaseArbiter.acquireLease('wan-gw-01', 'site-eu-west', 20000);
  assert.strictEqual(l2.isGranted, false);
  assert.strictEqual(l2.holderSiteId, 'site-us-east');

  assert.strictEqual(leaseArbiter.isLeaseActive('wan-gw-01', 'site-us-east'), true);
  assert.strictEqual(leaseArbiter.isLeaseActive('wan-gw-01', 'site-eu-west'), false);

  console.log('[Track 4.2] Verifying Virtual STONITH Split-Brain Fencing Sentinel...');
  const fencing = new SplitBrainFencingSentinel();

  assert.strictEqual(fencing.isRegionFenced('site-ap-south'), false);

  const fenceReceipt = fencing.fencePartitionedRegion('site-ap-south', 'WAN heartbeat lost for > 60s');
  assert.strictEqual(fenceReceipt.isFenced, true);
  assert.strictEqual(fencing.isRegionFenced('site-ap-south'), true);

  fencing.releaseFencedRegion('site-ap-south');
  assert.strictEqual(fencing.isRegionFenced('site-ap-south'), false);
  console.log(`  ✓ Geo-quorum master leases fenced across epochs; virtual STONITH successfully fenced partitioned regions.`);

  // ---------------------------------------------------------------------------
  // Track 5: Quantum Attestation HUD & 11 Views Invariant
  // ---------------------------------------------------------------------------
  console.log('[Track 5] Verifying Quantum Attestation HUD Helper & 11 Views Invariant...');
  const viewsDir = path.join(rootDir, 'public', 'js', 'views');
  const viewEntries = fs.readdirSync(viewsDir).filter(f => f.endsWith('.js'));
  assert.strictEqual(viewEntries.length, 11, 'public/js/views/ must maintain strictly 11 view files');

  const enterpriseNocModule = require('../public/js/views/enterprise-noc-view');
  assert.ok(typeof enterpriseNocModule.renderQuantumAttestationStatusHUD === 'function');

  const hudRes = enterpriseNocModule.renderQuantumAttestationStatusHUD(null);
  assert.strictEqual(hudRes.rendered, false);
  assert.strictEqual(hudRes.status.isQuantumSafe, true);
  console.log('  ✓ Quantum attestation status HUD helper and strict 11-view invariant confirmed.');

  // ---------------------------------------------------------------------------
  // Track 6: Parity Guard Execution & Fast Preflight Verification
  // ---------------------------------------------------------------------------
  console.log('[Track 6] Verifying Parity Guard (84 modules) and Preflight Health...');
  const parityScript = path.join(rootDir, 'scripts', 'verify-ts-js-parity.js');
  execFileSync(process.execPath, [parityScript], { stdio: 'pipe' });
  console.log('  ✓ All 84 flagship modules verified in 100% TypeScript/JavaScript dual parity.');

  const preflightScript = path.join(rootDir, 'scripts', 'verify-fast-preflight.js');
  const t0 = process.hrtime.bigint();
  execFileSync(process.execPath, [preflightScript], { stdio: 'pipe' });
  const preflightMs = Number(process.hrtime.bigint() - t0) / 1e6;
  assert.ok(preflightMs < 1000, `Preflight must execute cleanly under 1000ms, took ${preflightMs.toFixed(2)}ms`);
  console.log(`  ✓ Fast preflight verified in ${preflightMs.toFixed(2)}ms.`);

  console.log('\n========================================================================');
  console.log('  PHASE 18.0 CAPSTONE VERIFICATION: ALL TRACKS PASSED!                  ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runSovereignIntelligenceLeapPhase18Tests()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}

module.exports = { runSovereignIntelligenceLeapPhase18Tests };
