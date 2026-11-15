/**
 * Test Suite: Phase 5.0 Distributed Transactional Remediation Saga & Multi-Node 2PC Orchestrator
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const {
  DistributedSagaOrchestrator,
  CANONICAL_RIEMANNIAN_WEIGHTS,
  MIN_RIEMANNIAN_CONTRACTION,
  TelemetryKalmanFilter,
  calculateJitteredBackoffMs
} = require('../src/systems/remediation/distributed-saga-orchestrator');
const { zkEpistemicConsensusEngine, ZkEpistemicConsensusEngine } = require('../src/core/agent/zk-epistemic-consensus');
const { formulateRemediationGate } = require('../src/core/chat/conversational-brain');

describe('Phase 5.0 Track 2: Distributed Transactional Remediation Saga & 2PC Orchestrator', () => {

  test('Sylvester criterion: Riemannian metric tensor M(s) is strictly positive-definite across state space', () => {
    const orchestrator = new DistributedSagaOrchestrator();

    const states = [
      { rttMs: 15.0, lossPct: 0.1, queueDepthPackets: 5 },    // Nominal regime
      { rttMs: 85.0, lossPct: 1.2, queueDepthPackets: 25 },   // RTT cliff regime
      { rttMs: 120.0, lossPct: 8.5, queueDepthPackets: 40 },  // Loss cliff regime
      { rttMs: 250.0, lossPct: 12.0, queueDepthPackets: 95 }  // Multi-cliff saturation
    ];

    for (const state of states) {
      const isPositiveDefinite = orchestrator.isMetricPositiveDefinite(state);
      assert.equal(isPositiveDefinite, true, `M(s) must be strictly positive-definite for state ${JSON.stringify(state)}`);

      const energy = orchestrator.computeRiemannianLyapunovEnergy(state);
      assert.ok(energy > 0, `Energy V(s) must be strictly positive (> 0) for non-zero state, got ${energy}`);
    }

    // Zero state energy must be exactly 0
    const zeroEnergy = orchestrator.computeRiemannianLyapunovEnergy({ rttMs: 0, lossPct: 0, queueDepthPackets: 0 });
    assert.equal(zeroEnergy, 0, 'Zero state must have 0 Lyapunov energy');
  });

  test('Happy Path: 3-node distributed saga achieves 2PC quorum commit and issues atomic HMAC execution tokens', () => {
    const orchestrator = new DistributedSagaOrchestrator();

    const participants = [
      {
        nodeId: 'edge_sw_01',
        role: 'EDGE_SWITCH',
        targetEndpoint: '192.168.1.1',
        currentState: { rttMs: 45.0, lossPct: 2.0, queueDepthPackets: 35 },
        candidateAction: {
          actionId: 'act_clamp_edge_01',
          actionType: 'TCP_WINDOW_CLAMP',
          target: '192.168.1.1',
          parameters: { windowBytes: 32768 },
          rationale: 'Clamp window on edge switch to relieve bufferbloat',
          expectedImpact: { rttDeltaMs: -20.0, lossDeltaPct: -1.0, queueDeltaPackets: -20 },
          requiresElevation: false,
          commandPreview: 'sysctl -w net.ipv4.tcp_rmem="4096 32768 65536"'
        },
        candidateInverse: {
          actionId: 'inv_clamp_edge_01',
          inverseType: 'TCP_WINDOW_UNCLAMP',
          reversesActionId: 'act_clamp_edge_01',
          target: '192.168.1.1',
          parameters: { windowBytes: 65536 },
          rationale: 'Revert window clamping on edge switch',
          commandPreview: 'sysctl -w net.ipv4.tcp_rmem="4096 87380 6291456"',
          requiresElevation: false,
          isCompensatingInverse: true
        }
      },
      {
        nodeId: 'core_gw_01',
        role: 'CORE_GATEWAY',
        targetEndpoint: '10.0.0.1',
        currentState: { rttMs: 25.0, lossPct: 0.8, queueDepthPackets: 15 },
        candidateAction: {
          actionId: 'act_shape_gw_01',
          actionType: 'DSCP_TRAFFIC_SHAPE',
          target: '10.0.0.1',
          parameters: { dscpClass: 'CS3' },
          rationale: 'Prioritize gateway control packets',
          expectedImpact: { rttDeltaMs: -10.0, lossDeltaPct: -0.4, queueDeltaPackets: -8 },
          requiresElevation: false,
          commandPreview: 'tc qdisc add dev eth0 root fq_codel'
        },
        candidateInverse: {
          actionId: 'inv_shape_gw_01',
          inverseType: 'DSCP_DEFAULT',
          reversesActionId: 'act_shape_gw_01',
          target: '10.0.0.1',
          parameters: {},
          rationale: 'Remove DSCP traffic shaping',
          commandPreview: 'tc qdisc del dev eth0 root',
          requiresElevation: false,
          isCompensatingInverse: true
        }
      },
      {
        nodeId: 'dns_res_01',
        role: 'DNS_RESOLVER',
        targetEndpoint: '10.0.0.53',
        currentState: { rttMs: 18.0, lossPct: 0.5, queueDepthPackets: 8 },
        candidateAction: {
          actionId: 'act_pivot_dns_01',
          actionType: 'DNS_UPSTREAM_PIVOT',
          target: '10.0.0.53',
          parameters: { newUpstream: '1.1.1.1' },
          rationale: 'Pivot upstream DNS to low-latency resolver',
          expectedImpact: { rttDeltaMs: -8.0, lossDeltaPct: -0.3, queueDeltaPackets: -4 },
          requiresElevation: false,
          commandPreview: 'resolvectl dns eth0 1.1.1.1'
        },
        candidateInverse: {
          actionId: 'inv_pivot_dns_01',
          inverseType: 'DNS_UPSTREAM_REVERT',
          reversesActionId: 'act_pivot_dns_01',
          target: '10.0.0.53',
          parameters: { revertUpstream: '10.0.0.2' },
          rationale: 'Revert upstream DNS to primary domain resolver',
          commandPreview: 'resolvectl dns eth0 10.0.0.2',
          requiresElevation: false,
          isCompensatingInverse: true
        }
      }
    ];

    // 1. Initiate
    const saga = orchestrator.initiateSaga('GATEWAY_BUFFERBLOAT', 'operator_admin', participants);
    assert.equal(saga.phase, 'INITIATED');
    assert.equal(saga.participants.length, 3);

    // 2. Prepare Phase (Vote Quorum)
    const prepared = orchestrator.executePreparePhase(saga.sagaId);
    assert.equal(prepared.phase, 'COMMIT_VOTE_QUORUM');
    assert.equal(Object.keys(prepared.votes).length, 3);
    for (const nodeId of ['edge_sw_01', 'core_gw_01', 'dns_res_01']) {
      const vote = prepared.votes[nodeId];
      assert.equal(vote.vote, 'VOTE_COMMIT');
      assert.ok(vote.lyapunovDelta < 0, `Delta V for ${nodeId} must be negative`);
      assert.ok(vote.signedProof.length > 0);
    }
    assert.ok(prepared.lyapunovAggregate.deltaV < 0, 'Aggregate Lyapunov delta must be negative');
    assert.equal(prepared.lyapunovAggregate.isRiemannianStable, true);

    // 3. Commit Phase
    const committed = orchestrator.executeCommitPhase(saga.sagaId);
    assert.equal(committed.phase, 'COMMITTED');
    assert.equal(Object.keys(committed.commitTokens).length, 3);
    for (const nodeId of ['edge_sw_01', 'core_gw_01', 'dns_res_01']) {
      assert.ok(committed.commitTokens[nodeId].includes('.'), 'Must contain token payload and signature');
    }

    // 4. Persistence verification
    const recovered = orchestrator.getSaga(saga.sagaId);
    assert.equal(recovered.phase, 'COMMITTED');
    assert.equal(recovered.rollbackExecuted, false);
  });

  test('Single-node invariant violation triggers coordinated compensating rollback', () => {
    const orchestrator = new DistributedSagaOrchestrator();

    const participants = [
      {
        nodeId: 'edge_sw_02',
        role: 'EDGE_SWITCH',
        targetEndpoint: '192.168.1.1',
        currentState: { rttMs: 30.0, lossPct: 1.0, queueDepthPackets: 20 },
        candidateAction: {
          actionId: 'act_good_edge',
          actionType: 'TCP_WINDOW_CLAMP',
          target: '192.168.1.1',
          parameters: {},
          rationale: 'Relieve edge queue',
          expectedImpact: { rttDeltaMs: -15.0, lossDeltaPct: -0.5, queueDeltaPackets: -12 },
          requiresElevation: false,
          commandPreview: 'cmd_edge'
        },
        candidateInverse: {
          actionId: 'inv_good_edge',
          inverseType: 'TCP_WINDOW_UNCLAMP',
          reversesActionId: 'act_good_edge',
          target: '192.168.1.1',
          parameters: {},
          rationale: 'Rollback edge',
          commandPreview: 'cmd_rollback_edge',
          requiresElevation: false,
          isCompensatingInverse: true
        }
      },
      {
        nodeId: 'flaky_gw_02',
        role: 'CORE_GATEWAY',
        targetEndpoint: '10.0.0.1',
        currentState: { rttMs: 20.0, lossPct: 0.5, queueDepthPackets: 10 },
        // Destabilizing candidate: increases latency and queue (positive delta V)
        candidateAction: {
          actionId: 'act_bad_gw',
          actionType: 'DSCP_TRAFFIC_SHAPE',
          target: '10.0.0.1',
          parameters: {},
          rationale: 'Miscalibrated queue expansion',
          expectedImpact: { rttDeltaMs: +40.0, lossDeltaPct: +2.0, queueDeltaPackets: +30 },
          requiresElevation: false,
          commandPreview: 'cmd_bad_gw'
        },
        candidateInverse: {
          actionId: 'inv_bad_gw',
          inverseType: 'DSCP_DEFAULT',
          reversesActionId: 'act_bad_gw',
          target: '10.0.0.1',
          parameters: {},
          rationale: 'Rollback gateway',
          commandPreview: 'cmd_rollback_gw',
          requiresElevation: false,
          isCompensatingInverse: true
        }
      }
    ];

    const saga = orchestrator.initiateSaga('GATEWAY_BUFFERBLOAT', 'operator_admin', participants);
    const prepared = orchestrator.executePreparePhase(saga.sagaId);

    // Flaky node must abort prepare
    assert.equal(prepared.phase, 'ABORTED_PRE');
    assert.equal(prepared.votes['flaky_gw_02'].vote, 'VOTE_ABORT');
    assert.equal(prepared.votes['edge_sw_02'].vote, 'VOTE_COMMIT');

    // Attempting commit must fail quorum and trigger coordinated compensating rollback
    const rolledBack = orchestrator.executeCommitPhase(saga.sagaId);
    assert.equal(rolledBack.phase, 'ROLLED_BACK');
    assert.equal(rolledBack.rollbackExecuted, true);
    assert.equal(rolledBack.rollbackLog.length, 2);
    assert.equal(rolledBack.rollbackLog[0].status, 'COMPENSATED_SUCCESS');
    assert.equal(rolledBack.rollbackLog[1].status, 'COMPENSATED_SUCCESS');
  });

  test('Replay prevention rejects duplicate saga execution', () => {
    const orchestrator = new DistributedSagaOrchestrator();

    const participants = [
      {
        nodeId: 'node_replay_test',
        role: 'HOST_KERNEL',
        targetEndpoint: '127.0.0.1',
        currentState: { rttMs: 20.0, lossPct: 0.1, queueDepthPackets: 5 },
        candidateAction: {
          actionId: 'act_replay',
          actionType: 'SOCKET_BUFFER_EXPEDITE',
          target: '127.0.0.1',
          parameters: {},
          rationale: 'Expedite buffer',
          expectedImpact: { rttDeltaMs: -5.0, lossDeltaPct: -0.05, queueDeltaPackets: -2 },
          requiresElevation: false,
          commandPreview: 'preview'
        },
        candidateInverse: {
          actionId: 'inv_replay',
          inverseType: 'SOCKET_BUFFER_RESET',
          reversesActionId: 'act_replay',
          target: '127.0.0.1',
          parameters: {},
          rationale: 'Reset buffer',
          commandPreview: 'reset_preview',
          requiresElevation: false,
          isCompensatingInverse: true
        }
      }
    ];

    const saga = orchestrator.initiateSaga('HIGH_TCP_LATENCY', 'operator_admin', participants);
    orchestrator.executePreparePhase(saga.sagaId);
    orchestrator.executeCommitPhase(saga.sagaId);

    // Replay prepare phase on committed saga must throw DUPLICATE_SAGA_REJECTED
    assert.throws(() => {
      orchestrator.executePreparePhase(saga.sagaId);
    }, /DUPLICATE_SAGA_REJECTED/);
  });

  test('formulateRemediationGate integration populates distributedSagaPlan with 2PC readiness', async () => {
    const gate = await formulateRemediationGate('GATEWAY_BUFFERBLOAT', '192.168.1.100');
    assert.ok(gate, 'Remediation gate must be produced');
    assert.ok(gate.distributedSagaPlan, 'Remediation gate must include distributedSagaPlan');
    assert.equal(gate.distributedSagaPlan.participantsCount, 2);
    assert.ok(gate.distributedSagaPlan.sagaId.startsWith('saga_'));
    assert.equal(gate.distributedSagaPlan.commitQuorumReady, true);
    assert.equal(gate.distributedSagaPlan.isRiemannianStable, true);
    assert.ok(gate.distributedSagaPlan.aggregateDeltaV < 0);
  });

  test('Cryptographic State Attestation: Ed25519 signatures and Merkle inclusion proofs in 2PC prepare/commit', () => {
    const orchestrator = new DistributedSagaOrchestrator();

    // Generate authentic Ed25519 keypairs for participants
    const keyPair1 = zkEpistemicConsensusEngine.generateAgentKeyPair();
    const keyPair2 = zkEpistemicConsensusEngine.generateAgentKeyPair();

    const participants = [
      {
        nodeId: 'crypto_edge_01',
        role: 'EDGE_SWITCH',
        targetEndpoint: '10.10.1.1',
        privateKeyPem: keyPair1.privateKeyPem,
        publicKeyPem: keyPair1.publicKeyPem,
        currentState: { rttMs: 40.0, lossPct: 1.5, queueDepthPackets: 25 },
        candidateAction: {
          actionId: 'act_crypto_01',
          actionType: 'TCP_WINDOW_CLAMP',
          target: '10.10.1.1',
          parameters: { windowBytes: 32768 },
          rationale: 'Relieve edge queue',
          expectedImpact: { rttDeltaMs: -15.0, lossDeltaPct: -0.8, queueDeltaPackets: -15 },
          requiresElevation: false,
          commandPreview: 'cmd_crypto_01'
        },
        candidateInverse: {
          actionId: 'inv_crypto_01',
          inverseType: 'TCP_WINDOW_UNCLAMP',
          reversesActionId: 'act_crypto_01',
          target: '10.10.1.1',
          parameters: {},
          rationale: 'Rollback crypto 01',
          commandPreview: 'cmd_inv_01',
          requiresElevation: false,
          isCompensatingInverse: true
        }
      },
      {
        nodeId: 'crypto_gw_01',
        role: 'CORE_GATEWAY',
        targetEndpoint: '10.10.1.254',
        privateKeyPem: keyPair2.privateKeyPem,
        publicKeyPem: keyPair2.publicKeyPem,
        currentState: { rttMs: 25.0, lossPct: 0.5, queueDepthPackets: 15 },
        candidateAction: {
          actionId: 'act_crypto_02',
          actionType: 'DSCP_TRAFFIC_SHAPE',
          target: '10.10.1.254',
          parameters: {},
          rationale: 'Prioritize traffic',
          expectedImpact: { rttDeltaMs: -10.0, lossDeltaPct: -0.3, queueDeltaPackets: -8 },
          requiresElevation: false,
          commandPreview: 'cmd_crypto_02'
        },
        candidateInverse: {
          actionId: 'inv_crypto_02',
          inverseType: 'DSCP_DEFAULT',
          reversesActionId: 'act_crypto_02',
          target: '10.10.1.254',
          parameters: {},
          rationale: 'Rollback crypto 02',
          commandPreview: 'cmd_inv_02',
          requiresElevation: false,
          isCompensatingInverse: true
        }
      }
    ];

    // 1. Initiate saga
    const saga = orchestrator.initiateSaga('PROVE_CRYPTO_2PC', 'secops_agent', participants);

    // 2. Prepare phase: verify Ed25519 signatures and Merkle inclusion proofs generated
    const prepared = orchestrator.executePreparePhase(saga.sagaId);
    assert.equal(prepared.phase, 'COMMIT_VOTE_QUORUM');

    for (const p of participants) {
      const vote = prepared.votes[p.nodeId];
      assert.ok(vote.ed25519Signature, `Participant ${p.nodeId} must have Ed25519 signature`);
      assert.equal(vote.attestationStatus, 'ED25519_VERIFIED');
      assert.ok(vote.merkleInclusionProof, `Participant ${p.nodeId} must have Merkle inclusion proof`);
      assert.equal(ZkEpistemicConsensusEngine.verifyMerkleProof(vote.merkleInclusionProof), true);
    }

    // 3. Commit phase: verify tokens issued after attestation check
    const committed = orchestrator.executeCommitPhase(saga.sagaId);
    assert.equal(committed.phase, 'COMMITTED');
    assert.ok(committed.commitTokens['crypto_edge_01']);
    assert.ok(committed.commitTokens['crypto_gw_01']);

    // 4. Byzantine forged signature test: verify tampered signature forces rollback
    const forgedParticipants = [
      {
        nodeId: 'byzantine_node_01',
        role: 'EDGE_SWITCH',
        targetEndpoint: '10.10.2.1',
        privateKeyPem: keyPair1.privateKeyPem,
        publicKeyPem: keyPair2.publicKeyPem, // Mismatched public key!
        currentState: { rttMs: 30.0, lossPct: 1.0, queueDepthPackets: 20 },
        candidateAction: {
          actionId: 'act_byz_01',
          actionType: 'TCP_WINDOW_CLAMP',
          target: '10.10.2.1',
          parameters: {},
          rationale: 'Byzantine action',
          expectedImpact: { rttDeltaMs: -10.0, lossDeltaPct: -0.5, queueDeltaPackets: -10 },
          requiresElevation: false,
          commandPreview: 'cmd_byz'
        },
        candidateInverse: {
          actionId: 'inv_byz_01',
          inverseType: 'TCP_WINDOW_UNCLAMP',
          reversesActionId: 'act_byz_01',
          target: '10.10.2.1',
          parameters: {},
          rationale: 'Rollback byz',
          commandPreview: 'cmd_inv_byz',
          requiresElevation: false,
          isCompensatingInverse: true
        }
      }
    ];

    const byzSaga = orchestrator.initiateSaga('BYZANTINE_TEST', 'attacker', forgedParticipants);
    const byzPrepared = orchestrator.executePreparePhase(byzSaga.sagaId);
    assert.equal(byzPrepared.phase, 'ABORTED_PRE');
    assert.equal(byzPrepared.votes['byzantine_node_01'].attestationStatus, 'ATTESTATION_FAILED');
    assert.equal(byzPrepared.votes['byzantine_node_01'].vote, 'VOTE_ABORT');
  });

  test('Phase 7.0 Track 3: TelemetryKalmanFilter smooths observational noise and computeRobustLyapunovEnergy evaluates covariance penalty', () => {
    const filter = new TelemetryKalmanFilter({
      qRtt: 0.2,
      rRtt: 1.5,
      initialState: { rttMs: 50.0, lossPct: 2.0, queueDepthPackets: 30 }
    });

    const trueRtt = 50.0;
    // Simulate noisy measurements with 15% fluctuation around true value
    const noisyMeasurements = [
      { rttMs: 57.5, lossPct: 2.3, queueDepthPackets: 34 },
      { rttMs: 43.1, lossPct: 1.7, queueDepthPackets: 26 },
      { rttMs: 56.2, lossPct: 2.2, queueDepthPackets: 33 },
      { rttMs: 44.8, lossPct: 1.8, queueDepthPackets: 27 },
      { rttMs: 51.5, lossPct: 2.0, queueDepthPackets: 30 }
    ];

    let lastCovariance = null;
    let filteredState = null;
    for (const meas of noisyMeasurements) {
      const res = filter.update(meas);
      filteredState = res.state;
      lastCovariance = res.covariance;
    }

    assert.ok(filteredState);
    assert.ok(Math.abs(filteredState.rttMs - trueRtt) < 5.0, `Filtered RTT (${filteredState.rttMs}) should stay close to true RTT (${trueRtt})`);
    assert.ok(lastCovariance);
    assert.equal(lastCovariance.length, 3);
    assert.ok(lastCovariance[0][0] > 0, 'Covariance diagonal element P[0][0] must be positive');

    const orchestrator = new DistributedSagaOrchestrator();
    const robustRes = orchestrator.computeRobustLyapunovEnergy(filteredState, lastCovariance);

    assert.ok(robustRes.meanEnergy > 0, 'Mean Lyapunov energy must be positive');
    assert.ok(robustRes.traceCovariancePenalty > 0, 'Trace covariance penalty must be positive');
    assert.ok(robustRes.expectedEnergy > robustRes.meanEnergy, 'Expected energy must exceed mean energy due to covariance penalty');
    assert.equal(
      robustRes.expectedEnergy,
      Math.round((robustRes.meanEnergy + robustRes.traceCovariancePenalty) * 1000) / 1000
    );
  });

  test('Phase 8.0 Track 5: Truncated exponential backoff with full jitter bounded correctly', () => {
    // retry 0: base 1000, range [500, 1000]
    for (let i = 0; i < 20; i++) {
      const b0 = calculateJitteredBackoffMs(0);
      assert.ok(b0 >= 500 && b0 <= 1000, `Expected backoff in [500, 1000], got ${b0}`);
    }

    // retry 1: base 2000, range [1000, 2000]
    const b1Min = calculateJitteredBackoffMs(1, () => 0.0);
    const b1Max = calculateJitteredBackoffMs(1, () => 1.0);
    assert.equal(b1Min, 1000);
    assert.equal(b1Max, 2000);

    // retry 6+: capped at base 60000, range [30000, 60000]
    const bCapMin = calculateJitteredBackoffMs(10, () => 0.0);
    const bCapMax = calculateJitteredBackoffMs(10, () => 1.0);
    assert.equal(bCapMin, 30000);
    assert.equal(bCapMax, 60000);
  });

  test('Phase 8.0 Track 5: Self-Healing Saga Compensation Coordinator WAL re-drive and DLQ escalation', async () => {
    const orchestrator = new DistributedSagaOrchestrator();

    const mockInverse = {
      actionId: 'inv_action_edge_99',
      inverseType: 'TCP_WINDOW_UNCLAMP',
      reversesActionId: 'act_clamp_edge_99',
      target: '192.168.10.1',
      parameters: { windowBytes: 65536 },
      rationale: 'Revert clamp after aborted saga',
      commandPreview: 'sysctl -w net.ipv4.tcp_rmem="4096 87380 6291456"',
      requiresElevation: false,
      isCompensatingInverse: true
    };

    // 1. Enqueue a pending compensation with 0 initial delay for immediate test reconciliation
    const enqueued = orchestrator.enqueuePendingCompensation('SAGA-TEST-DLQ', 'edge_sw_99', mockInverse, {
      maxRetries: 3,
      initialDelayMs: 0
    });

    assert.ok(enqueued.compensationId.startsWith('COMP-SAGA-TEST-DLQ'));
    assert.equal(enqueued.status, 'PENDING_RETRY');
    assert.equal(enqueued.retryCount, 0);
    assert.equal(enqueued.maxRetries, 3);

    // Verify lookup
    const lookedUp = orchestrator.getPendingCompensation(enqueued.compensationId);
    assert.ok(lookedUp);
    assert.equal(lookedUp.compensationId, enqueued.compensationId);

    // 2. First retry attempt fails -> retry scheduled with backoff
    let retryScheduledEvent = null;
    orchestrator.once('SAGA_COMPENSATION_RETRY_SCHEDULED', (evt) => {
      retryScheduledEvent = evt;
    });

    const fixedNow = Date.now() + 100;
    const res1 = await orchestrator.reconcilePendingCompensations(
      async () => false, // fails
      { nowMs: fixedNow, randomFn: () => 0.5 }
    );

    assert.equal(res1.processedCount, 1);
    assert.equal(res1.retriedCount, 1);
    assert.equal(res1.deadLetterCount, 0);
    assert.equal(res1.succeededCount, 0);
    assert.ok(retryScheduledEvent);
    assert.equal(retryScheduledEvent.record.retryCount, 1);

    // 3. Second retry attempt fails
    const fixedNow2 = new Date(res1.reconciledRecords[0].nextRetryAtIso).getTime() + 10;
    const res2 = await orchestrator.reconcilePendingCompensations(
      async () => false,
      { nowMs: fixedNow2, randomFn: () => 0.5 }
    );
    assert.equal(res2.reconciledRecords[0].retryCount, 2);
    assert.equal(res2.reconciledRecords[0].status, 'PENDING_RETRY');

    // 4. Third retry attempt reaches maxRetries (3) -> DLQ escalation with HMAC audit signature
    let dlqEvent = null;
    orchestrator.once('SAGA_COMPENSATION_DLQ_ESCALATED', (evt) => {
      dlqEvent = evt;
    });

    const fixedNow3 = new Date(res2.reconciledRecords[0].nextRetryAtIso).getTime() + 10;
    const res3 = await orchestrator.reconcilePendingCompensations(
      async () => false,
      { nowMs: fixedNow3, randomFn: () => 0.5 }
    );

    assert.equal(res3.deadLetterCount, 1);
    assert.equal(res3.retriedCount, 0);
    const dlqRecord = res3.reconciledRecords[0];
    assert.equal(dlqRecord.status, 'DEAD_LETTER_ESCALATED');
    assert.equal(dlqRecord.retryCount, 3);
    assert.ok(dlqRecord.auditHmac, 'HMAC audit signature must be generated');
    assert.ok(dlqEvent, 'SAGA_COMPENSATION_DLQ_ESCALATED event must be emitted');
    assert.equal(dlqEvent.record.compensationId, enqueued.compensationId);

    // 5. Success reconciliation scenario
    const successEnqueued = orchestrator.enqueuePendingCompensation('SAGA-SUCCESS-TEST', 'node_ok_1', mockInverse, {
      initialDelayMs: 0
    });
    let reconciledEvent = null;
    orchestrator.once('SAGA_COMPENSATION_RECONCILED', (evt) => {
      reconciledEvent = evt;
    });

    const resSuccess = await orchestrator.reconcilePendingCompensations(
      async () => true,
      { nowMs: Date.now() + 50 }
    );
    assert.ok(resSuccess.succeededCount >= 1);
    assert.ok(reconciledEvent);
    assert.equal(reconciledEvent.record.status, 'SUCCESS');
  });

  test('Phase 8.0 Track 5: triggerCoordinatedRollback with failingNodes enqueues pending compensations for WAL re-drive', () => {
    const orchestrator = new DistributedSagaOrchestrator();

    const participants = [
      {
        nodeId: 'node_healthy_01',
        role: 'EDGE_SWITCH',
        targetEndpoint: '10.0.1.1',
        currentState: { rttMs: 20, lossPct: 0.1, queueDepthPackets: 5 },
        candidateAction: {
          actionId: 'act_h1',
          actionType: 'TCP_WINDOW_CLAMP',
          target: '10.0.1.1',
          parameters: {},
          rationale: 'Clamp',
          requiresElevation: false
        },
        candidateInverse: {
          actionId: 'inv_h1',
          inverseType: 'TCP_WINDOW_UNCLAMP',
          reversesActionId: 'act_h1',
          target: '10.0.1.1',
          parameters: {},
          rationale: 'Unclamp',
          requiresElevation: false,
          isCompensatingInverse: true
        }
      },
      {
        nodeId: 'node_failing_02',
        role: 'CORE_GATEWAY',
        targetEndpoint: '10.0.2.1',
        currentState: { rttMs: 25, lossPct: 0.2, queueDepthPackets: 8 },
        candidateAction: {
          actionId: 'act_f2',
          actionType: 'DSCP_TRAFFIC_SHAPE',
          target: '10.0.2.1',
          parameters: {},
          rationale: 'Shape',
          requiresElevation: false
        },
        candidateInverse: {
          actionId: 'inv_f2',
          inverseType: 'DSCP_DEFAULT',
          reversesActionId: 'act_f2',
          target: '10.0.2.1',
          parameters: {},
          rationale: 'Default',
          requiresElevation: false,
          isCompensatingInverse: true
        }
      }
    ];

    const saga = orchestrator.initiateSaga('FAILING_ROLLBACK_TEST', 'tester', participants);
    const rollbackRecord = orchestrator.triggerCoordinatedRollback(saga.sagaId, 'Testing node failure during rollback', {
      failingNodes: ['node_failing_02']
    });

    assert.equal(rollbackRecord.phase, 'ROLLED_BACK');
    assert.equal(rollbackRecord.rollbackLog.length, 2);

    const healthyStep = rollbackRecord.rollbackLog.find((s) => s.nodeId === 'node_healthy_01');
    const failingStep = rollbackRecord.rollbackLog.find((s) => s.nodeId === 'node_failing_02');

    assert.equal(healthyStep.status, 'COMPENSATED_SUCCESS');
    assert.equal(failingStep.status, 'COMPENSATION_FAILED');

    // Verify it was enqueued in pending compensations
    const pendingList = orchestrator.listPendingCompensations('PENDING_RETRY');
    const enqueuedItem = pendingList.find((p) => p.sagaId === saga.sagaId && p.nodeId === 'node_failing_02');
    assert.ok(enqueuedItem, 'Failing rollback node must be enqueued into pending compensations');
    assert.equal(enqueuedItem.inverseAction.actionId, 'inv_f2');
  });
});
