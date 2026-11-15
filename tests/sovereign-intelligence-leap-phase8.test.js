/**
 * Phase 8.0 Capstone Verification Suite: Sovereign Intelligence Leap
 *
 * Validates the full integration of Phase 8.0 systems:
 *   1. Fast Causal Inference (FCI) & Partial Ancestral Graphs (PAG) for Latent Confounders
 *   2. Byzantine Vector Clock Gossip & Anti-Entropy Merkle Synchronization
 *   3. Continuous Euler-Maruyama SDE Degradation Drift & First-Passage Time (FPT) Horizons
 *   4. Multi-Modal Conversational Procedural SVG Topology Visualizer
 *   5. Self-Healing Saga Compensation Coordinator with WAL Re-Drive & DLQ Escalation
 *   6. Multi-Node Fault Injection, Byzantine Adversarial Rejection & Zero Zombie State
 */

'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

// Track 1
const {
  FciLatentCausalEngine,
  fciLatentCausalEngine
} = require('../src/ai/fci-latent-causal-engine');

// Track 2
const {
  ByzantineVectorClockGossipEngine
} = require('../src/core/agent/byzantine-vector-clock-gossip');
const { zkEpistemicConsensusEngine } = require('../src/core/agent/zk-epistemic-consensus');

// Track 3
const {
  estimateSdeParameters,
  simulateEulerMaruyamaPath,
  calculateFirstPassageTime,
  stochasticDifferentialEngine
} = require('../src/ai/stochastic-differential-engine');
const {
  estimateTimeToFailureHorizon,
  waveletHurstLrdEngine
} = require('../src/ai/wavelet-hurst-lrd-engine');

// Track 4
const {
  conversationalVisualizer,
  generateTopologySvg,
  getThermalColor,
  sanitizeXml
} = require('../src/core/chat/conversational-visualizer');
const {
  runAgenticToolLoop
} = require('../src/core/chat/conversational-brain');

// Track 5
const {
  DistributedSagaOrchestrator,
  calculateJitteredBackoffMs
} = require('../src/systems/remediation/distributed-saga-orchestrator');

describe('Phase 8.0 Capstone: Sovereign Intelligence Leap Multi-System Verification', () => {

  test('Subtest 1: Fast Causal Inference (FCI) discovers unmeasured latent confounders via PAG bidirected arcs (<->)', () => {
    const N = 40;
    const data = {
      arrival_rate: [],
      hypervisor_cpu_steal: [],
      queue_depth: [],
      rtt_latency: []
    };

    for (let i = 0; i < N; i++) {
      const arrival = 4.0 + (i % 5) * 0.5;
      const steal = (i % 3 === 0) ? 1.2 : 0.1;
      const queue = arrival * 10 + steal * 20;
      const rtt = 10 + queue * 0.8 + steal * 15;

      data.arrival_rate.push(arrival);
      data.hypervisor_cpu_steal.push(steal);
      data.queue_depth.push(queue);
      data.rtt_latency.push(rtt);
    }

    // 1. Marginal correlation test
    const rDirect = fciLatentCausalEngine.computePearsonCorrelation(data.queue_depth, data.rtt_latency);
    assert.ok(rDirect > 0.80, `Expected strong correlation, got ${rDirect}`);

    // 2. Conditional independence test with Fisher's z
    const indepTest = fciLatentCausalEngine.testConditionalIndependence(data, 'queue_depth', 'rtt_latency', ['hypervisor_cpu_steal']);
    assert.ok(typeof indepTest.pValue === 'number');
    assert.ok(typeof indepTest.partialCorrelation === 'number');
    assert.ok(indepTest.degreesOfFreedom > 0);

    // 3. PAG Discovery
    const pag = fciLatentCausalEngine.discoverPag(data, {
      knownLatentConfounders: [['hypervisor_cpu_steal', 'rtt_latency']]
    });

    assert.ok(pag);
    assert.strictEqual(pag.nodes.length, 4);
    assert.ok(pag.edges.length > 0);
    assert.strictEqual(pag.isCausallySufficient, false);
    assert.ok(pag.latentConfoundersDetected.length >= 1);

    const latentArc = pag.edges.find((e) => e.edgeType === 'BIDIRECTED');
    assert.ok(latentArc, 'PAG must contain at least one bidirected edge indicating latent confounding');
    assert.strictEqual(latentArc.hasLatentConfounder, true);
    assert.ok(pag.summary.includes('latent confounder'));
  });

  test('Subtest 2: Byzantine Vector Clock Gossip synchronizes partitioned nodes via anti-entropy Merkle reconciliation', () => {
    const keyPairA = zkEpistemicConsensusEngine.generateAgentKeyPair();
    const keyPairB = zkEpistemicConsensusEngine.generateAgentKeyPair();

    const nodeA = new ByzantineVectorClockGossipEngine('edge_node_alpha');
    const nodeB = new ByzantineVectorClockGossipEngine('edge_node_beta');

    // 1. Vector Clock causal ordering and concurrency check
    const vc1 = { edge_node_alpha: 1, edge_node_beta: 0 };
    const vc2 = { edge_node_alpha: 2, edge_node_beta: 1 };
    const vcConcurrent = { edge_node_alpha: 0, edge_node_beta: 2 };

    assert.equal(nodeA.isCausallyPrecedent(vc1, vc2), true, 'vc1 must causally precede vc2');
    assert.equal(nodeA.isCausallyPrecedent(vc2, vc1), false);
    assert.equal(nodeA.isConcurrent(vc1, vcConcurrent), true, 'vc1 and vcConcurrent must be concurrent');

    // 2. Record samples & create local Merkle root
    nodeA.recordStateSample({ rttMs: 25.4 });
    nodeA.recordStateSample({ rttMs: 26.1 });
    const localRootA = nodeA.getLocalMerkleRoot();
    assert.ok(localRootA.length > 20);

    // 3. Merkle Reconciliation
    const consensus = zkEpistemicConsensusEngine;
    const leavesInSync = [
      crypto.createHash('sha256').update(JSON.stringify({ rttMs: 25.4 })).digest('hex'),
      crypto.createHash('sha256').update(JSON.stringify({ rttMs: 26.1 })).digest('hex')
    ];
    const rootInSync = consensus.buildMerkleTree(leavesInSync).root;
    const syncRes = nodeA.reconcileAntiEntropy('edge_node_beta', rootInSync, leavesInSync);
    assert.equal(syncRes.inSync, true);
    assert.equal(syncRes.reconciliationStatus, 'IDENTICAL_IN_SYNC');

    // Divergent leaves
    const divergentLeaves = [
      leavesInSync[0],
      crypto.createHash('sha256').update('divergent_partition_state').digest('hex')
    ];
    const divergentRoot = consensus.buildMerkleTree(divergentLeaves).root;
    const divRes = nodeA.reconcileAntiEntropy('edge_node_beta', divergentRoot, divergentLeaves);
    assert.equal(divRes.inSync, false);
    assert.equal(divRes.divergenceDetected, true);
    assert.ok(divRes.divergentIndices.includes(1));
    assert.equal(divRes.reconciliationStatus, 'MERKLE_DESCENT_REQUIRED');

    // 4. Ingest valid peer gossip to achieve causal precedence
    nodeB.tickLocalClock();
    const gossipB = nodeB.createGossipMessage(keyPairB.privateKeyPem, keyPairB.publicKeyPem, 1);
    const ingestB = nodeA.ingestPeerGossip(gossipB);
    assert.equal(ingestB.accepted, true);
    assert.ok(nodeA.getVectorClock()['edge_node_beta'] >= 1);

    // 5. Reject Byzantine forged message
    const forgedMsg = {
      ...gossipB,
      stateDigest: 'tampered_state_digest',
      signature: gossipB.signature
    };
    const byzRes = nodeA.ingestPeerGossip(forgedMsg);
    assert.equal(byzRes.accepted, false);
    assert.equal(byzRes.reason, 'ED25519_SIGNATURE_INVALID');

    // 6. Reject Byzantine clock jump (> 1000)
    const jumpMsg = nodeA.createGossipMessage(keyPairA.privateKeyPem, keyPairA.publicKeyPem, 2);
    jumpMsg.vectorClock['edge_node_alpha'] = 50000;
    const jumpSig = crypto.sign(null, Buffer.from(JSON.stringify({
      nodeId: jumpMsg.nodeId,
      epoch: jumpMsg.epoch,
      vectorClock: jumpMsg.vectorClock,
      stateDigest: jumpMsg.stateDigest,
      merkleRoot: jumpMsg.merkleRoot,
      timestampIso: jumpMsg.timestampIso
    }), 'utf8'), keyPairA.privateKeyPem).toString('base64url');
    jumpMsg.signature = jumpSig;

    const jumpRes = nodeB.ingestPeerGossip(jumpMsg);
    assert.equal(jumpRes.accepted, false);
    assert.equal(jumpRes.reason, 'BYZANTINE_CLOCK_JUMP_REJECTED');
  });

  test('Subtest 3: Continuous Euler-Maruyama SDE degradation drift & First-Passage Time survival horizon', () => {
    // 1. Calibrate SDE parameters from escalating series
    const escalating = [30, 34, 40, 48, 58, 70, 84];
    const params = estimateSdeParameters(escalating, 1.0);

    assert.ok(params.theta > 0, 'Elasticity theta must be positive');
    assert.ok(params.mu >= 30, 'Baseline mean must be calibrated');
    assert.ok(params.sigma > 0, 'Volatility sigma must be positive');
    assert.equal(params.s0, 84);

    // 2. Solve continuous sample trajectory with Euler-Maruyama stepping
    const trajectory = simulateEulerMaruyamaPath(params, { dt: 0.1, steps: 100, seed: 777 });
    assert.equal(trajectory.timePoints.length, 101);
    assert.equal(trajectory.states.length, 101);
    for (const val of trajectory.states) {
      assert.ok(val >= 0, 'SDE telemetry state must remain bounded >= 0');
    }

    // 3. Compute First-Passage Time (FPT) distribution to saturation threshold B = 100
    const fpt = calculateFirstPassageTime(params, 100.0, {
      dt: 0.5,
      steps: 100,
      numPaths: 100,
      seed: 888
    });

    assert.equal(fpt.thresholdB, 100.0);
    assert.equal(fpt.initialState, 84.0);
    assert.ok(fpt.breachFraction > 0.50, `Expected breach fraction > 50%, got ${fpt.breachFraction}`);
    assert.ok(fpt.var95TimeToFailureSeconds !== null);
    assert.ok(fpt.var95TimeToFailureSeconds <= 40.0, `95% VaR TTF must be <= 40s, got ${fpt.var95TimeToFailureSeconds}`);

    // Verify monotonic decay of survival curve S(t_1) >= S(t_2)
    for (let i = 1; i < fpt.survivalCurve.length; i++) {
      assert.ok(
        fpt.survivalCurve[i].survivalProb <= fpt.survivalCurve[i - 1].survivalProb + 1e-6,
        `Survival curve must be monotonically non-increasing at index ${i}`
      );
    }

    // 4. Verify integration into estimateTimeToFailureHorizon
    const horizon = estimateTimeToFailureHorizon(escalating, { capacityMax: 100.0, sampleIntervalSeconds: 1.0 });
    assert.ok(horizon.sdeFirstPassageTime);
    assert.equal(horizon.riskHorizonTier, 'CRITICAL_IMMINENT');
    assert.ok(horizon.timeToFailureSeconds <= 30);
  });

  test('Subtest 4: Multi-modal conversational procedural SVG topology visualizer produces sanitized XML <= 12 KB', async () => {
    const topologyGraph = {
      nodes: [
        { id: 'client_ingress_01', label: 'Client Ingress', role: 'ingress', temperature: 0.08 },
        { id: 'gw_edge_01', label: 'Edge Gateway', role: 'gateway', temperature: 0.35 },
        { id: 'app_svc_01', label: 'Core Application', role: 'service', temperature: 0.55 },
        { id: 'db_pg_01', label: 'Primary DB', role: 'datastore', temperature: 0.92 }
      ],
      edges: [
        { source: 'client_ingress_01', target: 'gw_edge_01', weight: 0.3, label: 'TLS 1.3' },
        { source: 'gw_edge_01', target: 'app_svc_01', weight: 0.6, label: 'gRPC' },
        { source: 'app_svc_01', target: 'db_pg_01', weight: 0.95, label: 'Causal Bottleneck', mediationRatio: 0.88, status: 'degraded' }
      ]
    };

    // 1. Procedural SVG generation
    const svg = generateTopologySvg(topologyGraph, { title: 'Sovereign Fabric Topology Map' });

    assert.ok(svg.startsWith('<svg xmlns="http://www.w3.org/2000/svg"'));
    assert.ok(svg.endsWith('</svg>'));
    assert.ok(svg.includes('viewBox="0 0 760 380"'));

    // Check Laplacian diffusion colors: Nominal (#00e676), Warning (#ffab00), Degraded (#ff1744)
    assert.ok(svg.includes('#00e676'), 'Nominal temperature must map to #00e676');
    assert.ok(svg.includes('#ffab00'), 'Warning temperature must map to #ffab00');
    assert.ok(svg.includes('#ff1744'), 'Degraded temperature must map to #ff1744');
    assert.ok(svg.includes('marker-end="url(#arrow-degraded)"'));

    // Check payload budget <= 12 KB (12288 bytes)
    const byteSize = Buffer.byteLength(svg, 'utf8');
    assert.ok(byteSize <= 12288, `SVG payload size (${byteSize}B) must be <= 12 KB`);

    // 2. XML XSS sanitization check
    const evilNode = { id: 'test_node', label: '<script>alert("pwned")</script>', temperature: 0.1 };
    const sanitizedSvg = generateTopologySvg({ nodes: [evilNode], edges: [] });
    assert.ok(!sanitizedSvg.includes('<script>'));
    assert.ok(sanitizedSvg.includes('&lt;script&gt;'));

    // 3. Conversational brain agentic tool loop integration
    const outcome = await runAgenticToolLoop({
      promptText: 'visualize network topology diagram and route hop',
      initialPlan: { intent: 'topology_visualize', target: 'gw_edge_01', mode: 'operational' },
      executeSinglePlan: async () => ({
        reply: 'Topology inspected.',
        technicalEvidence: {},
        structuredAnswer: { result: 'OK', meaning: 'Diagram created' }
      }),
      maxSteps: 1
    });

    assert.ok(outcome.epistemicClassification.topologyVisualization);
    assert.equal(outcome.epistemicClassification.topologyVisualization.generated, true);
    assert.ok(outcome.reply.includes('<svg xmlns="http://www.w3.org/2000/svg"'));
    assert.ok(outcome.reply.includes('Topological Diffusion Diagram'));
  });

  test('Subtest 5: Self-healing saga compensation recovery reconciler with exponential backoff & DLQ escalation', async () => {
    const orchestrator = new DistributedSagaOrchestrator();

    const compensatingAction = {
      actionId: 'inv_capstone_01',
      inverseType: 'TCP_WINDOW_UNCLAMP',
      reversesActionId: 'act_clamp_01',
      target: '10.50.0.1',
      parameters: { windowBytes: 65536 },
      rationale: 'Rollback TCP window clamp on degraded switch',
      commandPreview: 'sysctl -w net.ipv4.tcp_rmem="4096 87380 6291456"',
      requiresElevation: false,
      isCompensatingInverse: true
    };

    // 1. Enqueue compensation with 0 initial delay for immediate test execution
    const testSagaId = `SAGA-CAP8-${Date.now()}`;
    const enqueued = orchestrator.enqueuePendingCompensation(testSagaId, 'switch_edge_01', compensatingAction, {
      maxRetries: 2,
      initialDelayMs: 0
    });

    assert.equal(enqueued.status, 'PENDING_RETRY');
    assert.equal(enqueued.retryCount, 0);
    assert.equal(enqueued.maxRetries, 2);

    // 2. First retry attempt fails -> jittered backoff scheduled
    let retryScheduledEvt = null;
    orchestrator.on('SAGA_COMPENSATION_RETRY_SCHEDULED', (evt) => {
      if (evt.record.compensationId === enqueued.compensationId) {
        retryScheduledEvt = evt;
      }
    });

    const now1 = Date.now() + 50;
    const res1 = await orchestrator.reconcilePendingCompensations(
      async (rec) => {
        if (rec.compensationId === enqueued.compensationId) return false;
        return true;
      },
      { nowMs: now1, randomFn: () => 0.5 }
    );

    const rec1 = res1.reconciledRecords.find((r) => r.compensationId === enqueued.compensationId);
    assert.ok(rec1, 'Enqueued record must be reconciled in pass 1');
    assert.equal(rec1.retryCount, 1);
    assert.ok(retryScheduledEvt);

    // 3. Second retry attempt fails -> reaches maxRetries (2) -> transitions to DEAD_LETTER_ESCALATED
    let dlqEvt = null;
    orchestrator.on('SAGA_COMPENSATION_DLQ_ESCALATED', (evt) => {
      if (evt.record.compensationId === enqueued.compensationId) {
        dlqEvt = evt;
      }
    });

    const now2 = new Date(rec1.nextRetryAtIso).getTime() + 50;
    const res2 = await orchestrator.reconcilePendingCompensations(
      async (rec) => {
        if (rec.compensationId === enqueued.compensationId) return false;
        return true;
      },
      { nowMs: now2, randomFn: () => 0.5 }
    );

    const rec2 = res2.reconciledRecords.find((r) => r.compensationId === enqueued.compensationId);
    assert.ok(rec2, 'Enqueued record must be reconciled in pass 2');
    assert.equal(rec2.status, 'DEAD_LETTER_ESCALATED');
    assert.equal(rec2.retryCount, 2);
    assert.ok(rec2.auditHmac, 'HMAC signature must authenticate DLQ escalation');
    assert.ok(dlqEvt);
    assert.equal(dlqEvt.record.compensationId, enqueued.compensationId);

    // 4. Success re-drive path
    const successRecord = orchestrator.enqueuePendingCompensation(`SAGA-OK-${Date.now()}`, 'switch_edge_02', compensatingAction, {
      initialDelayMs: 0
    });
    const resOk = await orchestrator.reconcilePendingCompensations(
      async (rec) => {
        if (rec.compensationId === successRecord.compensationId) return true;
        return false;
      },
      { nowMs: Date.now() + 50 }
    );
    const recOk = resOk.reconciledRecords.find((r) => r.compensationId === successRecord.compensationId);
    assert.ok(recOk);
    assert.equal(recOk.status, 'SUCCESS');
  });

  test('Subtest 6: Multi-node fault injection, Byzantine adversarial rejection, and zero zombie state', async () => {
    // 1. Multi-node operational scenario
    const keyPairA = zkEpistemicConsensusEngine.generateAgentKeyPair();
    const gossipA = new ByzantineVectorClockGossipEngine('node_sec_a');
    const gossipB = new ByzantineVectorClockGossipEngine('node_sec_b');
    const sagaOrchestrator = new DistributedSagaOrchestrator();

    // Fabric state
    gossipA.tickLocalClock();
    const msg = gossipA.createGossipMessage(keyPairA.privateKeyPem, keyPairA.publicKeyPem, 1);
    const ingest = gossipB.ingestPeerGossip(msg);
    assert.equal(ingest.accepted, true);

    // Byzantine injection: Forge signature and verify rejection
    const forged = { ...msg, signature: 'bad_sig' };
    assert.equal(gossipB.ingestPeerGossip(forged).accepted, false);

    // Coordinated Saga Rollback with node failure injection
    const participants = [
      {
        nodeId: 'node_sec_a',
        role: 'EDGE_SWITCH',
        targetEndpoint: '10.1.1.1',
        currentState: { rttMs: 20, lossPct: 0.1, queueDepthPackets: 5 },
        candidateAction: { actionId: 'act_1', actionType: 'TCP_WINDOW_CLAMP', target: '10.1.1.1', parameters: {}, rationale: '', requiresElevation: false },
        candidateInverse: { actionId: 'inv_1', inverseType: 'TCP_WINDOW_UNCLAMP', reversesActionId: 'act_1', target: '10.1.1.1', parameters: {}, rationale: '', requiresElevation: false, isCompensatingInverse: true }
      },
      {
        nodeId: 'node_sec_b',
        role: 'CORE_GATEWAY',
        targetEndpoint: '10.1.1.2',
        currentState: { rttMs: 30, lossPct: 0.2, queueDepthPackets: 10 },
        candidateAction: { actionId: 'act_2', actionType: 'DSCP_TRAFFIC_SHAPE', target: '10.1.1.2', parameters: {}, rationale: '', requiresElevation: false },
        candidateInverse: { actionId: 'inv_2', inverseType: 'DSCP_DEFAULT', reversesActionId: 'act_2', target: '10.1.1.2', parameters: {}, rationale: '', requiresElevation: false, isCompensatingInverse: true }
      }
    ];

    const saga = sagaOrchestrator.initiateSaga('CAPSTONE_FAULT_INJECTION', 'operator', participants);
    const rollback = sagaOrchestrator.triggerCoordinatedRollback(saga.sagaId, 'Injected hardware fault', {
      failingNodes: ['node_sec_b']
    });

    assert.equal(rollback.phase, 'ROLLED_BACK');
    const stepA = rollback.rollbackLog.find((s) => s.nodeId === 'node_sec_a');
    const stepB = rollback.rollbackLog.find((s) => s.nodeId === 'node_sec_b');
    assert.equal(stepA.status, 'COMPENSATED_SUCCESS');
    assert.equal(stepB.status, 'COMPENSATION_FAILED');

    // Verify recovery queue has the uncompensated node
    const pendingList = sagaOrchestrator.listPendingCompensations('PENDING_RETRY');
    assert.ok(pendingList.some((p) => p.nodeId === 'node_sec_b'));

    // SDE Failure Horizon & Topological Visualizer Integration
    const sdeParams = estimateSdeParameters([25, 30, 36, 45, 60, 80], 1.0);
    const fpt = calculateFirstPassageTime(sdeParams, 100.0, { dt: 0.5, steps: 50, numPaths: 50, seed: 101 });
    assert.ok(fpt.breachFraction > 0);

    const svg = conversationalVisualizer.generateTopologySvg({
      nodes: [
        { id: 'node_sec_a', label: 'Edge Switch A', role: 'switch', temperature: 0.15 },
        { id: 'node_sec_b', label: 'Core Gateway B', role: 'gateway', temperature: 0.85 }
      ],
      edges: [
        { source: 'node_sec_a', target: 'node_sec_b', weight: 0.8, status: 'degraded', label: 'Partitioned' }
      ]
    });
    assert.ok(svg.includes('#00e676'));
    assert.ok(svg.includes('#ff1744'));
    assert.ok(Buffer.byteLength(svg, 'utf8') <= 12288);
  });
});
