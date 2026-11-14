/**
 * Test Suite: Phase 5.0 Distributed Transactional Remediation Saga & Multi-Node 2PC Orchestrator
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const {
  DistributedSagaOrchestrator,
  CANONICAL_RIEMANNIAN_WEIGHTS,
  MIN_RIEMANNIAN_CONTRACTION
} = require('../src/systems/remediation/distributed-saga-orchestrator');
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

});
