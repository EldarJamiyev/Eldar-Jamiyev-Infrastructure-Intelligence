/**
 * EJII Phase 6.0 Capstone Verification Suite:
 * Sovereign Intelligence Leap & Multi-Tier Epistemic Verification Battery
 *
 * Validates:
 *   1. Pearlian Bidirectional Causal Evidence Tracing (PN, PS, PNS, Likelihood Ratio Lambda)
 *   2. Conversational Causal Integration & Epistemic Classification in runAgenticToolLoop
 *   3. Wavelet Hurst LRD Predictive Time-to-Failure (TTF) Horizons & Dispersion Penalties
 *   4. Multi-Scale Incident Cascade Clustering with Propagation Pathways & Early Warnings
 *   5. Distributed 2PC Sagas with Asymmetric Ed25519 State Attestation & Merkle Proofs
 *   6. Byzantine Adversarial Signature Invalidation & Coordinated Compensating Rollback
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  structuralCausalEngine,
  StructuralCausalEngine
} = require('../src/ai/structural-causal-engine');
const { runAgenticToolLoop } = require('../src/core/chat/conversational-brain');
const {
  waveletHurstLrdEngine,
  estimateTimeToFailureHorizon
} = require('../src/ai/wavelet-hurst-lrd-engine');
const {
  hnswEpisodicIndex,
  HnswEpisodicIndex
} = require('../src/core/memory/hnsw-episodic-index');
const {
  DistributedSagaOrchestrator
} = require('../src/systems/remediation/distributed-saga-orchestrator');
const {
  zkEpistemicConsensusEngine,
  ZkEpistemicConsensusEngine
} = require('../src/core/agent/zk-epistemic-consensus');

test('EJII Phase 6.0 Capstone: Sovereign Intelligence Leap & Epistemic Verification Battery', async (t) => {

  await t.test('1. Analytical Pearlian Causal Evidence Tracing computes PN, PS, PNS, and Likelihood Ratio', () => {
    const engine = new StructuralCausalEngine();
    const trace = engine.traceCausalEvidencePath('latency_spike', 'bufferbloat', {
      queueDepthPackets: 65.0,
      rttMs: 55.0,
      packetLossPct: 4.0
    });

    assert.ok(trace.probabilityOfNecessity >= 0.70, `Expected PN >= 0.70, got ${trace.probabilityOfNecessity}`);
    assert.ok(trace.probabilityOfSufficiency >= 0.70, `Expected PS >= 0.70, got ${trace.probabilityOfSufficiency}`);
    assert.ok(trace.probabilityOfNecessityAndSufficiency >= 0.65, `Expected PNS >= 0.65, got ${trace.probabilityOfNecessityAndSufficiency}`);
    assert.ok(trace.empiricalLikelihoodRatio >= 3.0, `Expected Lambda >= 3.0, got ${trace.empiricalLikelihoodRatio}`);
    assert.strictEqual(trace.proofVerdict, 'NECESSARY_AND_SUFFICIENT_PROVEN');
    assert.ok(trace.causalPath.length >= 4);
    assert.strictEqual(trace.causalPath[0], 'bufferbloat');
    assert.strictEqual(trace.causalPath[trace.causalPath.length - 1], 'latency_spike');
    assert.ok(trace.rationale.includes('Pearlian causal validation'));
  });

  await t.test('2. Conversational Causal Twin binds into runAgenticToolLoop epistemic classification', async () => {
    const mockPlan = { intent: 'host_metrics', target: '10.0.0.15', mode: 'operational' };

    const outcome = await runAgenticToolLoop({
      promptText: 'what caused the latency spike on core-gateway-01?',
      initialPlan: mockPlan,
      executeSinglePlan: async (plan) => ({
        reply: 'Gateway metrics telemetry retrieved.',
        technicalEvidence: { rttMs: 58.0, queueDepthPackets: 60.0 },
        structuredAnswer: { result: 'OK', meaning: 'High queue saturation' }
      }),
      sessionContext: {
        diagnosedRootCause: 'bufferbloat',
        symptom: 'latency_spike',
        queueDepthPackets: 60.0,
        rttMs: 58.0
      },
      maxSteps: 1
    });

    assert.ok(outcome.epistemicClassification, 'epistemicClassification must be present');
    assert.ok(outcome.epistemicClassification.causalEvidenceTrace, 'causalEvidenceTrace must be populated');
    const trace = outcome.epistemicClassification.causalEvidenceTrace;
    assert.strictEqual(trace.proofVerdict, 'NECESSARY_AND_SUFFICIENT_PROVEN');
    assert.match(outcome.reply, /Pearlian Causal Evidence Trace/);
    assert.match(outcome.reply, /NECESSARY_AND_SUFFICIENT_PROVEN/);
  });

  await t.test('3. Wavelet Hurst LRD calculates predictive TTF capacity horizon with dispersion penalty', () => {
    // Escalate usage rapidly towards capacity ceiling
    const escalating = [40, 48, 57, 66, 75, 84, 92];
    const ttf = estimateTimeToFailureHorizon(escalating, {
      capacityMax: 100.0,
      sampleIntervalSeconds: 1.0
    });

    assert.strictEqual(ttf.capacityMax, 100.0);
    assert.strictEqual(ttf.usageCurrent, 92.0);
    assert.strictEqual(ttf.headroomRemaining, 8.0);
    assert.ok(ttf.driftRatePerSecond > 0);
    assert.ok(ttf.timeToFailureSeconds <= 60);
    assert.strictEqual(ttf.riskHorizonTier, 'CRITICAL_IMMINENT');
    assert.ok(ttf.actionableAdvisory.includes('CRITICAL'));

    // Stable linear drift
    const stable = [10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
    const ttfStable = waveletHurstLrdEngine.estimateTimeToFailureHorizon(stable, { capacityMax: 100.0 });
    assert.ok(ttfStable.timeToFailureSeconds > 60);
    assert.strictEqual(ttfStable.riskHorizonTier, 'WARNING_DRIFT');
  });

  await t.test('4. Multi-Scale Cascade Clustering derives propagation pathways and early-warning signatures', () => {
    const index = new HnswEpisodicIndex();
    const edges = [
      { source: 'bgp_route_withdraw', target: 'ingress_packet_loss', weight: 6 },
      { source: 'ingress_packet_loss', target: 'gateway_502_spike', weight: 5 },
      { source: 'gateway_502_spike', target: 'client_retry_storm', weight: 4 },
      { source: 'dns_nxdomain_flood', target: 'resolver_oom', weight: 7 },
      { source: 'resolver_oom', target: 'upstream_timeout', weight: 6 }
    ];

    const result = index.clusterMultiScaleCascades(edges, { leadTimeBaseSeconds: 20.0 });
    assert.ok(result.communities.length >= 2, 'Should discover distinct multi-hop incident communities');
    assert.ok(result.modularityQ > 0.15, `Modularity Q must be positive, got ${result.modularityQ}`);
    assert.ok(Array.isArray(result.pathways) && result.pathways.length >= 2);
    assert.ok(result.pathways[0].earlyWarningLeadTimeSeconds >= 20.0);
    assert.ok(typeof result.dominantFrequencyScale === 'number');
    assert.match(result.earlyWarningSignature, /CASCADE_EARLY_WARNING/);
  });

  await t.test('5. Distributed 2PC Sagas verify Ed25519 state attestations and Merkle inclusion proofs', () => {
    const orchestrator = new DistributedSagaOrchestrator();

    const kp1 = zkEpistemicConsensusEngine.generateAgentKeyPair();
    const kp2 = zkEpistemicConsensusEngine.generateAgentKeyPair();

    const participants = [
      {
        nodeId: 'node_capstone_01',
        role: 'EDGE_SWITCH',
        targetEndpoint: '10.0.1.1',
        privateKeyPem: kp1.privateKeyPem,
        publicKeyPem: kp1.publicKeyPem,
        currentState: { rttMs: 38.0, lossPct: 1.2, queueDepthPackets: 28 },
        candidateAction: {
          actionId: 'act_cap_01',
          actionType: 'TCP_WINDOW_CLAMP',
          target: '10.0.1.1',
          parameters: { windowBytes: 32768 },
          rationale: 'Clamp window',
          expectedImpact: { rttDeltaMs: -14.0, lossDeltaPct: -0.6, queueDeltaPackets: -14 },
          requiresElevation: false,
          commandPreview: 'cmd_cap_01'
        },
        candidateInverse: {
          actionId: 'inv_cap_01',
          inverseType: 'TCP_WINDOW_UNCLAMP',
          reversesActionId: 'act_cap_01',
          target: '10.0.1.1',
          parameters: {},
          rationale: 'Inverse cap 01',
          commandPreview: 'inv_cmd_01',
          requiresElevation: false,
          isCompensatingInverse: true
        }
      },
      {
        nodeId: 'node_capstone_02',
        role: 'CORE_GATEWAY',
        targetEndpoint: '10.0.1.254',
        privateKeyPem: kp2.privateKeyPem,
        publicKeyPem: kp2.publicKeyPem,
        currentState: { rttMs: 24.0, lossPct: 0.4, queueDepthPackets: 14 },
        candidateAction: {
          actionId: 'act_cap_02',
          actionType: 'DSCP_TRAFFIC_SHAPE',
          target: '10.0.1.254',
          parameters: {},
          rationale: 'Traffic shape',
          expectedImpact: { rttDeltaMs: -8.0, lossDeltaPct: -0.2, queueDeltaPackets: -6 },
          requiresElevation: false,
          commandPreview: 'cmd_cap_02'
        },
        candidateInverse: {
          actionId: 'inv_cap_02',
          inverseType: 'DSCP_DEFAULT',
          reversesActionId: 'act_cap_02',
          target: '10.0.1.254',
          parameters: {},
          rationale: 'Inverse cap 02',
          commandPreview: 'inv_cmd_02',
          requiresElevation: false,
          isCompensatingInverse: true
        }
      }
    ];

    const saga = orchestrator.initiateSaga('CAPSTONE_SAGA_01', 'sre_master', participants);
    const prepared = orchestrator.executePreparePhase(saga.sagaId);

    assert.strictEqual(prepared.phase, 'COMMIT_VOTE_QUORUM');
    for (const p of participants) {
      const v = prepared.votes[p.nodeId];
      assert.strictEqual(v.attestationStatus, 'ED25519_VERIFIED');
      assert.ok(v.merkleInclusionProof);
      assert.strictEqual(ZkEpistemicConsensusEngine.verifyMerkleProof(v.merkleInclusionProof), true);
    }

    const committed = orchestrator.executeCommitPhase(saga.sagaId);
    assert.strictEqual(committed.phase, 'COMMITTED');
    assert.ok(committed.commitTokens['node_capstone_01']);
    assert.ok(committed.commitTokens['node_capstone_02']);
  });

  await t.test('6. Byzantine forged signature triggers vote rejection and prevents commit quorum', () => {
    const orchestrator = new DistributedSagaOrchestrator();

    const legitimateKey = zkEpistemicConsensusEngine.generateAgentKeyPair();
    const rogueKey = zkEpistemicConsensusEngine.generateAgentKeyPair();

    const byzantineParticipants = [
      {
        nodeId: 'byzantine_edge_01',
        role: 'EDGE_SWITCH',
        targetEndpoint: '10.0.3.1',
        privateKeyPem: rogueKey.privateKeyPem,       // Signed with rogue private key
        publicKeyPem: legitimateKey.publicKeyPem,    // Evaluated against legitimate public key
        currentState: { rttMs: 35.0, lossPct: 1.0, queueDepthPackets: 20 },
        candidateAction: {
          actionId: 'act_byz_attack',
          actionType: 'TCP_WINDOW_CLAMP',
          target: '10.0.3.1',
          parameters: {},
          rationale: 'Byzantine injection',
          expectedImpact: { rttDeltaMs: -12.0, lossDeltaPct: -0.4, queueDeltaPackets: -10 },
          requiresElevation: false,
          commandPreview: 'cmd_attack'
        },
        candidateInverse: {
          actionId: 'inv_byz_attack',
          inverseType: 'TCP_WINDOW_UNCLAMP',
          reversesActionId: 'act_byz_attack',
          target: '10.0.3.1',
          parameters: {},
          rationale: 'Rollback attack',
          commandPreview: 'cmd_inv_attack',
          requiresElevation: false,
          isCompensatingInverse: true
        }
      }
    ];

    const saga = orchestrator.initiateSaga('BYZANTINE_REJECTION', 'auditor', byzantineParticipants);
    const prepared = orchestrator.executePreparePhase(saga.sagaId);

    assert.strictEqual(prepared.phase, 'ABORTED_PRE');
    assert.strictEqual(prepared.votes['byzantine_edge_01'].attestationStatus, 'ATTESTATION_FAILED');
    assert.strictEqual(prepared.votes['byzantine_edge_01'].vote, 'VOTE_ABORT');
  });

});
