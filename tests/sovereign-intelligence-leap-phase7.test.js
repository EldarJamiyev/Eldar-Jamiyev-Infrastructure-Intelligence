/**
 * EJII Phase 7.0 Capstone Verification Suite:
 * Sovereign Intelligence Leap & Multi-Tier Epistemic Verification Battery
 *
 * Validates:
 *   1. Pearlian Causal Mediation Analysis (CDE, NDE, NIE, Mediated Proportion) & Multi-Hop Conversational Routing
 *   2. Streaming Epistemic Observer & Rolling Kullback-Leibler Divergence (D_KL >= 0.85 bits) Belief Invalidation
 *   3. Discrete Kalman-Lyapunov State Estimation & Trace Covariance Penalty Tracking Under Telemetry Noise
 *   4. Batch Ed25519 Cryptographic Attestation & Rollup Quorum Receipts with O(1) Commit Verification
 *   5. Digital Twin Pre-Flight M/M/1/K Chaos Simulation Sandbox & 4-Tier Memory Consolidation / Playbook Promotion
 *   6. Byzantine Adversarial Signature Rejection & Coordinated Compensating Rollback
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const {
  structuralCausalEngine,
  StructuralCausalEngine
} = require('../src/ai/structural-causal-engine');
const {
  runAgenticToolLoop,
  StreamingEpistemicObserver
} = require('../src/core/chat/conversational-brain');
const {
  DistributedSagaOrchestrator,
  TelemetryKalmanFilter,
  CANONICAL_RIEMANNIAN_WEIGHTS
} = require('../src/systems/remediation/distributed-saga-orchestrator');
const {
  zkEpistemicConsensusEngine,
  ZkEpistemicConsensusEngine
} = require('../src/core/agent/zk-epistemic-consensus');
const {
  generativeRemediationSynthesizer,
  GenerativeRemediationSynthesizer
} = require('../src/systems/remediation/generative-remediation-synthesizer');
const {
  OperationalMemoryEngine
} = require('../src/core/memory/operational-memory-engine');

test('EJII Phase 7.0 Capstone: Sovereign Intelligence Leap & Epistemic Verification Battery', async (t) => {

  await t.test('1. Pearlian Causal Mediation Analysis calculates CDE, NDE, NIE, Mediated Proportion, and conversational routing', async () => {
    const engine = new StructuralCausalEngine();
    const telemetry = {
      queueDepthPackets: 65.0,
      rttMs: 78.0,
      packetLossPct: 2.5
    };

    const mediation = engine.analyzeCausalMediation('queue_saturation', 'bufferbloat', 'latency_spike', telemetry);

    assert.ok(mediation);
    assert.strictEqual(mediation.treatment, 'queue_saturation');
    assert.strictEqual(mediation.mediator, 'bufferbloat');
    assert.strictEqual(mediation.outcome, 'latency_spike');

    // Total Effect = NDE + NIE
    assert.strictEqual(
      mediation.totalEffect,
      Math.round((mediation.naturalDirectEffect + mediation.naturalIndirectEffect) * 1000) / 1000,
      'Total effect must equal sum of natural direct and natural indirect effects'
    );
    assert.ok(mediation.controlledDirectEffect >= 0, 'CDE must be non-negative');
    assert.ok(mediation.mediatedProportion >= 0 && mediation.mediatedProportion <= 1.0, 'Mediated proportion in [0, 1]');
    assert.ok(
      ['DIRECT_ROOT_INTERVENTION', 'MEDIATOR_MITIGATION_SUFFICIENT', 'DUAL_INTERVENTION_REQUIRED'].includes(mediation.actionableInterventionTarget),
      'Must recommend valid actionableInterventionTarget'
    );
    assert.ok(mediation.rationale.includes('Pearlian causal mediation decomposition'));

    // Conversational multi-hop tool loop integration
    const outcome = await runAgenticToolLoop({
      promptText: 'is the latency spike mediated through bufferbloat or caused directly by queue saturation?',
      initialPlan: { intent: 'host_metrics', target: '10.0.0.1', mode: 'operational' },
      executeSinglePlan: async () => ({
        reply: 'Telemetry telemetry collected.',
        technicalEvidence: { queueDepthPackets: 65.0, rttMs: 78.0 },
        structuredAnswer: { result: 'OK' }
      }),
      sessionContext: {
        treatment: 'queue_saturation',
        mediator: 'bufferbloat',
        outcome: 'latency_spike',
        queueDepthPackets: 65.0,
        rttMs: 78.0
      },
      maxSteps: 1
    });

    assert.ok(outcome.epistemicClassification);
    assert.ok(outcome.epistemicClassification.causalMediationAnalysis, 'causalMediationAnalysis must be attached to epistemicClassification');
    assert.strictEqual(outcome.epistemicClassification.causalMediationAnalysis.treatment, 'queue_saturation');
  });

  await t.test('2. Streaming Epistemic Observer detects belief divergence via rolling Kullback-Leibler divergence (D_KL >= 0.85 bits)', () => {
    const observer = new StreamingEpistemicObserver({
      divergenceThresholdBits: 0.85,
      priorDistribution: [
        { id: 'BUFFERBLOAT_QUEUE_CONGESTION', probability: 0.70 },
        { id: 'LINK_BANDWIDTH_SATURATION', probability: 0.20 },
        { id: 'NOMINAL_STATE', probability: 0.10 }
      ]
    });

    let eventEmitted = null;
    observer.on('BELIEF_INVALIDATION', (evt) => {
      eventEmitted = evt;
    });

    // Ingest nominal telemetry: RTT drops from congested to 10ms, queue drops to 0
    const nominalTelemetry = { rttMs: 10.0, queueDepthPackets: 0, packetLossPct: 0.0 };
    const result = observer.ingestTelemetrySample(nominalTelemetry);

    assert.ok(result, 'Result event returned');
    assert.ok(eventEmitted, 'EventEmitter fired BELIEF_INVALIDATION');
    assert.strictEqual(eventEmitted.type, 'BELIEF_INVALIDATION_EVENT');
    assert.ok(eventEmitted.klDivergenceBits >= 0.85, `KL divergence (${eventEmitted.klDivergenceBits}) must exceed threshold 0.85 bits`);
    assert.strictEqual(eventEmitted.priorTopHypothesis, 'BUFFERBLOAT_QUEUE_CONGESTION');
    assert.strictEqual(eventEmitted.newTopHypothesis, 'NOMINAL_STATE');
    assert.ok(eventEmitted.advisoryMessage.includes('Telemetry Shift Detected'));

    // Ingest another nominal sample: no new invalidation since prior updated
    const secondNominal = observer.ingestTelemetrySample(nominalTelemetry);
    assert.strictEqual(secondNominal, null, 'Subsequent consistent sample must not trigger re-invalidation');
  });

  await t.test('3. Discrete Kalman-Lyapunov Filter smooths observational noise and accounts for trace covariance penalty', () => {
    const filter = new TelemetryKalmanFilter({
      qRtt: 0.1,
      rRtt: 1.0,
      initialState: { rttMs: 40.0, lossPct: 1.0, queueDepthPackets: 20 }
    });

    // Ingest noisy observations around 40ms
    const measurements = [
      { rttMs: 48.0, lossPct: 1.2, queueDepthPackets: 22 },
      { rttMs: 34.0, lossPct: 0.8, queueDepthPackets: 18 },
      { rttMs: 46.0, lossPct: 1.1, queueDepthPackets: 21 },
      { rttMs: 36.0, lossPct: 0.9, queueDepthPackets: 19 },
      { rttMs: 41.0, lossPct: 1.0, queueDepthPackets: 20 }
    ];

    let lastCov = null;
    let stateEst = null;
    for (const m of measurements) {
      const step = filter.update(m);
      stateEst = step.state;
      lastCov = step.covariance;
    }

    assert.ok(stateEst);
    assert.ok(Math.abs(stateEst.rttMs - 40.0) < 4.0, `Filtered RTT (${stateEst.rttMs}) should converge near 40ms`);

    const orchestrator = new DistributedSagaOrchestrator();
    const robustEnergy = orchestrator.computeRobustLyapunovEnergy(stateEst, lastCov);

    assert.ok(robustEnergy.meanEnergy > 0, 'Mean energy > 0');
    assert.ok(robustEnergy.traceCovariancePenalty > 0, 'Trace covariance penalty > 0');
    assert.strictEqual(
      robustEnergy.expectedEnergy,
      Math.round((robustEnergy.meanEnergy + robustEnergy.traceCovariancePenalty) * 1000) / 1000
    );
  });

  await t.test('4. Batch Ed25519 Cryptographic Attestation generates Rollup Quorum Receipts and verifies in O(1) time', () => {
    const orchestrator = new DistributedSagaOrchestrator();
    const consensus = new ZkEpistemicConsensusEngine();

    const kp1 = consensus.generateAgentKeyPair();
    const kp2 = consensus.generateAgentKeyPair();

    const participants = [
      {
        nodeId: 'node_alpha',
        role: 'EDGE_SWITCH',
        targetEndpoint: '10.0.1.1',
        privateKeyPem: kp1.privateKeyPem,
        publicKeyPem: kp1.publicKeyPem,
        currentState: { rttMs: 45.0, lossPct: 2.0, queueDepthPackets: 30 },
        candidateAction: {
          actionId: 'act_clamp_alpha',
          actionType: 'TCP_WINDOW_CLAMP',
          target: '10.0.1.1',
          parameters: { windowBytes: 32768 },
          rationale: 'Clamp window',
          expectedImpact: { rttDeltaMs: -20.0, lossDeltaPct: -1.0, queueDeltaPackets: -15 },
          requiresElevation: false,
          commandPreview: 'cmd_alpha'
        },
        candidateInverse: {
          actionId: 'inv_clamp_alpha',
          inverseType: 'TCP_WINDOW_UNCLAMP',
          reversesActionId: 'act_clamp_alpha',
          target: '10.0.1.1',
          parameters: {},
          rationale: 'Revert clamp',
          commandPreview: 'cmd_inv_alpha',
          requiresElevation: false,
          isCompensatingInverse: true
        }
      },
      {
        nodeId: 'node_beta',
        role: 'CORE_GATEWAY',
        targetEndpoint: '10.0.2.1',
        privateKeyPem: kp2.privateKeyPem,
        publicKeyPem: kp2.publicKeyPem,
        currentState: { rttMs: 30.0, lossPct: 1.0, queueDepthPackets: 15 },
        candidateAction: {
          actionId: 'act_shape_beta',
          actionType: 'DSCP_TRAFFIC_SHAPE',
          target: '10.0.2.1',
          parameters: { dscpClass: 'CS3' },
          rationale: 'Shape traffic',
          expectedImpact: { rttDeltaMs: -10.0, lossDeltaPct: -0.5, queueDeltaPackets: -8 },
          requiresElevation: false,
          commandPreview: 'cmd_beta'
        },
        candidateInverse: {
          actionId: 'inv_shape_beta',
          inverseType: 'DSCP_DEFAULT',
          reversesActionId: 'act_shape_beta',
          target: '10.0.2.1',
          parameters: {},
          rationale: 'Revert shape',
          commandPreview: 'cmd_inv_beta',
          requiresElevation: false,
          isCompensatingInverse: true
        }
      }
    ];

    const saga = orchestrator.initiateSaga('SAGA_PHASE7_CAPSTONE', 'lead_architect', participants);
    const prepared = orchestrator.executePreparePhase(saga.sagaId);

    assert.strictEqual(prepared.phase, 'COMMIT_VOTE_QUORUM');
    assert.ok(prepared.batchQuorumReceipt, 'batchQuorumReceipt must be present on prepared saga');
    assert.strictEqual(prepared.batchQuorumReceipt.isQuorumValid, true);
    assert.strictEqual(prepared.batchQuorumReceipt.quorumCount, 2);
    assert.strictEqual(prepared.batchQuorumReceipt.totalSignatures, 2);

    // O(1) batch verification check
    const batchValid = ZkEpistemicConsensusEngine.verifyBatchQuorumReceipt(prepared.batchQuorumReceipt, saga.sagaId);
    assert.strictEqual(batchValid, true, 'Batch quorum receipt must verify in O(1)');

    // Commit phase succeeds with atomic tokens
    const committed = orchestrator.executeCommitPhase(saga.sagaId);
    assert.strictEqual(committed.phase, 'COMMITTED');
    assert.ok(committed.commitTokens['node_alpha']);
    assert.ok(committed.commitTokens['node_beta']);
  });

  await t.test('5. Digital Twin Pre-Flight M/M/1/K Chaos Sandbox blocks unsafe actions & 4-tier memory consolidates playbooks', () => {
    const synth = new GenerativeRemediationSynthesizer();
    const baseline = { rttMs: 25.0, lossPct: 0.1, queueDepthPackets: 10 };

    const safeCandidate = {
      actionId: 'act_twin_safe',
      actionType: 'TCP_WINDOW_CLAMP',
      target: '192.168.1.1',
      parameters: { windowBytes: 32768 },
      rationale: 'Relieve queue pressure',
      expectedImpact: { rttDeltaMs: -10.0, lossDeltaPct: 0.0, queueDeltaPackets: -5 },
      requiresElevation: false,
      commandPreview: 'cmd'
    };
    const safePlan = synth.issueCryptographicActionPlan(safeCandidate, baseline);
    assert.ok(safePlan.preFlightSimulation);
    assert.strictEqual(safePlan.preFlightSimulation.isSimulationSafe, true);

    // Unsafe candidate that blows out the queue buffer
    const unsafeCandidate = {
      actionId: 'act_twin_unsafe',
      actionType: 'SOCKET_BUFFER_EXPEDITE',
      target: '192.168.1.1',
      parameters: { bufferBytes: 2097152 },
      rationale: 'Overly aggressive buffer allocation',
      expectedImpact: { rttDeltaMs: 120.0, lossDeltaPct: 10.0, queueDeltaPackets: 80 },
      requiresElevation: false,
      commandPreview: 'cmd_unsafe'
    };

    const unsafeSim = synth.simulatePreFlightChaos(unsafeCandidate, baseline);
    assert.strictEqual(unsafeSim.isSimulationSafe, false);

    assert.throws(
      () => synth.issueCryptographicActionPlan(unsafeCandidate, baseline),
      (err) => err.code === 'PRE_FLIGHT_SIMULATION_UNSAFE' || err.code === 'LYAPUNOV_INVARIANT_VIOLATED'
    );

    // 4-Tier Memory Consolidation and Automated Playbook Promotion
    const memory = new OperationalMemoryEngine({ useSqlite: true });
    const playbookId = `RB-PHASE7-PROMO-${Date.now()}`;

    // Promotion fails if criteria (>=3 successes, >=2 nodes, PN>=0.75, 0 rollbacks) not met
    const failedPromo = memory.evaluateAutomatedPlaybookPromotion(playbookId, {
      successCount: 2,
      distinctNodes: 1,
      pnNecessity: 0.65,
      rollbackCount: 0
    });
    assert.strictEqual(failedPromo.promoted, false);

    // Promotion succeeds when criteria are fully met
    const successPromo = memory.evaluateAutomatedPlaybookPromotion(playbookId, {
      successCount: 5,
      distinctNodes: ['node_1', 'node_2'],
      pnNecessity: 0.92,
      rollbackCount: 0
    });
    assert.strictEqual(successPromo.promoted, true);
    assert.strictEqual(successPromo.tier, 4);
    assert.strictEqual(successPromo.tierName, 'OPERATIONAL_PLAYBOOK');

    const consolidation = memory.consolidateMemoryTiers();
    assert.strictEqual(consolidation.isFullyConsolidated, true);
    assert.ok(consolidation.tiers.tier1_workingMemory);
    assert.ok(consolidation.tiers.tier2_episodicIncidents);
    assert.ok(consolidation.tiers.tier3_semanticTopology);
    assert.ok(consolidation.tiers.tier4_operationalPlaybooks);
  });

  await t.test('6. Byzantine adversarial signature tampering triggers immediate coordinated compensating rollback', () => {
    const orchestrator = new DistributedSagaOrchestrator();
    const consensus = new ZkEpistemicConsensusEngine();

    const legitimateKey = consensus.generateAgentKeyPair();
    const attackerKey = consensus.generateAgentKeyPair();

    const byzantineParticipants = [
      {
        nodeId: 'byzantine_node_alpha',
        role: 'EDGE_SWITCH',
        targetEndpoint: '10.10.10.1',
        privateKeyPem: attackerKey.privateKeyPem, // Signed by attacker
        publicKeyPem: legitimateKey.publicKeyPem, // Registered under legitimate node
        currentState: { rttMs: 50.0, lossPct: 1.0, queueDepthPackets: 20 },
        candidateAction: {
          actionId: 'act_byz_alpha',
          actionType: 'TCP_WINDOW_CLAMP',
          target: '10.10.10.1',
          parameters: {},
          rationale: 'Byzantine action',
          expectedImpact: { rttDeltaMs: -15.0, lossDeltaPct: -0.5, queueDeltaPackets: -10 },
          requiresElevation: false,
          commandPreview: 'cmd_byz'
        },
        candidateInverse: {
          actionId: 'inv_byz_alpha',
          inverseType: 'TCP_WINDOW_UNCLAMP',
          reversesActionId: 'act_byz_alpha',
          target: '10.10.10.1',
          parameters: {},
          rationale: 'Rollback byz',
          commandPreview: 'cmd_inv_byz',
          requiresElevation: false,
          isCompensatingInverse: true
        }
      }
    ];

    const saga = orchestrator.initiateSaga('SAGA_BYZANTINE_TAMPER', 'adversary', byzantineParticipants);
    const prepared = orchestrator.executePreparePhase(saga.sagaId);

    // Phase must abort due to cryptographic attestation failure
    assert.strictEqual(prepared.phase, 'ABORTED_PRE');
    assert.strictEqual(prepared.votes['byzantine_node_alpha'].attestationStatus, 'ATTESTATION_FAILED');
    assert.strictEqual(prepared.votes['byzantine_node_alpha'].vote, 'VOTE_ABORT');
    assert.strictEqual(prepared.batchQuorumReceipt.isQuorumValid, false);

    // Attempting commit on aborted saga triggers coordinated compensating rollback
    const committed = orchestrator.executeCommitPhase(saga.sagaId);
    assert.strictEqual(committed.phase, 'ROLLED_BACK');
    assert.strictEqual(committed.rollbackExecuted, true);
    assert.ok(committed.rollbackLog.length >= 1);
    assert.strictEqual(committed.rollbackLog[0].status, 'COMPENSATED_SUCCESS');
  });

});
