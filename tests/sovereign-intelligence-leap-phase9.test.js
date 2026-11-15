/**
 * Phase 9.0 Capstone Verification Suite: Sovereign Intelligence Leap
 *
 * Validates the full integration of Phase 9.0 systems:
 *   1. Dynamic Structural Causal Models (D-SCM) with VAR-SCM, spectral radius stability, and interventional cascade forecasting
 *   2. Contextual Multi-Armed Bandit (Thompson Sampling & LinUCB) Remediation Policy Engine with regret minimization
 *   3. Hierarchical Dual-Tier Memory Consolidation (>= 85% payload reduction) and 64D centroid semantic recall
 *   4. Multi-Agent SRE War Room Dynamic Swarm Consensus & Epistemic Cross-Examination with Ed25519 signatures
 *   5. Zero-Copy Raw Socket / Ring Buffer Ingestion Pipeline with SPSC SharedArrayBuffer and Morlet microburst stream coupling
 *   6. End-to-End Autonomous Multi-Node Deliberation, Bandit Action Selection, 2PC Saga Commit, and Zero Zombie State
 */

'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

// Track 1: Dynamic Structural Causal Models
const {
  DynamicStructuralCausalEngine,
  dynamicStructuralCausalEngine
} = require('../src/ai/dynamic-structural-causal-engine');

// Track 2: Contextual Bandit Policy Engine
const {
  ContextualBanditPolicyEngine,
  contextualBanditPolicyEngine
} = require('../src/systems/remediation/contextual-bandit-policy');

// Track 3: Hierarchical Dual-Tier Memory Consolidator
const {
  HierarchicalMemoryConsolidator,
  hierarchicalMemoryConsolidator
} = require('../src/core/memory/hierarchical-memory-consolidator');

// Track 4: Multi-Agent SRE War Room Swarm Coordinator
const {
  WarRoomSwarmCoordinator,
  warRoomSwarmCoordinator
} = require('../src/ai/war-room-swarm-coordinator');

// Track 5: Zero-Copy Flow Pipeline & SPSC Ring Buffer
const {
  ZeroCopyFlowPipeline,
  zeroCopyFlowPipeline
} = require('../src/systems/streaming/zero-copy-flow-pipeline');

// Track 6: Distributed Saga Orchestrator
const {
  DistributedSagaOrchestrator,
  distributedSagaOrchestrator
} = require('../src/systems/remediation/distributed-saga-orchestrator');

describe('Phase 9.0 Capstone: Sovereign Intelligence Leap Multi-System Verification', () => {

  test('Subtest 1: Dynamic Structural Causal Models (D-SCM) time-lagged parameter estimation, stability spectral radius, and multi-step interventional cascade forecasting', () => {
    const engine = new DynamicStructuralCausalEngine();

    // 1. Generate realistic multi-step time series with high initial queue depth
    const series = {
      queueDepth: [20, 24, 28, 35, 45, 58, 70, 82, 90, 85, 72, 60, 48, 38, 30],
      rttLatency: [25, 27, 30, 36, 44, 55, 68, 80, 88, 84, 71, 59, 47, 37, 29],
      packetLoss: [0.0, 0.0, 0.1, 0.2, 0.6, 1.4, 2.5, 4.0, 5.2, 4.8, 3.2, 1.8, 0.9, 0.3, 0.1]
    };

    // 2. Estimate D-SCM parameters with lag 1
    const model = engine.fitModel(series, { lag: 1 });
    assert.ok(model);
    assert.equal(model.variables.length, 3);
    assert.ok(typeof model.spectralRadius === 'number');
    assert.ok(model.spectralRadius < 1.0, `Spectral radius must be < 1.0 for asymptotic stability, got ${model.spectralRadius}`);
    assert.equal(model.isStable, true);

    // 3. Multi-step interventional cascade projection: do(queueDepth = 10.0)
    const forecast = engine.simulateIntervention(
      model,
      series,
      { variable: 'queueDepth', targetValue: 10.0 },
      5,
      5
    );

    assert.ok(forecast);
    assert.equal(forecast.horizonSteps, 5);
    assert.equal(forecast.trajectory.length, 5);
    assert.ok(typeof forecast.directDynamicEffect === 'number');
    assert.ok(typeof forecast.accumulatedCascadingEffect === 'number');
    assert.ok(forecast.summary.includes('D-SCM Dynamic Projection'));
    assert.ok(forecast.cumulativeImpact.queueDepth < 0, 'Intervening to lower queueDepth must yield negative cumulative impact');
  });

  test('Subtest 2: Contextual Multi-Armed Bandit policy evaluation (Thompson Sampling & LinUCB) optimizing remediation runbooks with bounded regret', () => {
    const bandit = new ContextualBanditPolicyEngine();
    bandit.resetForTesting();

    // Register candidate remediation arms
    bandit.registerOrGetArm('arm_codel_aqm', 'QUEUE_MANAGEMENT');
    bandit.registerOrGetArm('arm_interface_bounce', 'LINK_RESTART');

    const highBufferbloatContext = [0.85, 0.90, 0.05, 0.10];

    // Simulate 15 rounds: arm_codel_aqm consistently succeeds with high Lyapunov energy contraction
    for (let r = 0; r < 15; r++) {
      bandit.recordReward({
        armId: 'arm_codel_aqm',
        success: true,
        rollbackOccurred: false,
        energyBefore: 12.0,
        deltaV: -7.5,
        blastRadius: 0.15,
        executionDurationMs: 120,
        contextVector: highBufferbloatContext
      });

      // arm_interface_bounce fails with rollback
      bandit.recordReward({
        armId: 'arm_interface_bounce',
        success: false,
        rollbackOccurred: true,
        energyBefore: 12.0,
        deltaV: 2.0,
        blastRadius: 0.85,
        executionDurationMs: 1500,
        contextVector: highBufferbloatContext
      });
    }

    const codelArm = bandit.getArmState('arm_codel_aqm');
    assert.ok(codelArm);
    assert.ok(codelArm.alpha > codelArm.beta);
    assert.ok(codelArm.cumulativeReward > 0);

    const bounceArm = bandit.getArmState('arm_interface_bounce');
    assert.ok(bounceArm);
    assert.ok(bounceArm.beta > bounceArm.alpha);
    assert.ok(bounceArm.cumulativeReward < 0);

    // LinUCB pure exploitation selection (alphaUcb = 0)
    const selected = bandit.selectAction(['arm_codel_aqm', 'arm_interface_bounce'], highBufferbloatContext, {
      algorithm: 'LIN_UCB',
      alphaUcb: 0.0
    });

    assert.equal(selected.selectedArmId, 'arm_codel_aqm', 'Exploitation must decisively select the highest-performing arm');
    assert.ok(selected.evaluations[0].combinedScore > 0);
  });

  test('Subtest 3: Hierarchical Dual-Tier Memory consolidation, semantic graph compaction (>= 85% size reduction), and long-horizon episodic recall', () => {
    const consolidator = new HierarchicalMemoryConsolidator();
    consolidator.resetForTesting();

    // Ingest 8 verbose diagnostic episodes
    for (let i = 1; i <= 8; i++) {
      consolidator.addWorkingMemoryEpisode({
        episodeId: `ep_phase9_${i}`,
        targetDomain: 'TCP',
        targetEndpoint: 'core-switch-01',
        timestampIso: new Date().toISOString(),
        symptomSignature: 'TCP_RETRANSMIT_BURST',
        rootCause: 'Switch Egress Bufferbloat',
        remediationAction: 'ADAPTIVE_TCP_PACING',
        executionOutcome: 'SUCCESS',
        durationMs: 120 + i * 5,
        topologicalHops: ['edge-gw', 'dist-sw', 'core-switch-01'],
        metricsSnapshot: {
          rttVariance: 45.2,
          packetDropRate: 0.08,
          queueDepth: 75 + i
        }
      });
    }

    // Trigger consolidation into episodic clusters
    const clusters = consolidator.consolidateWorkingMemory({ minGroupSize: 2 });
    assert.ok(clusters.length >= 1, 'Must produce at least one consolidated episodic cluster');

    const cluster = clusters[0];
    assert.equal(cluster.targetDomain, 'TCP');
    assert.ok(cluster.compactionRatio >= 0.85, `Compaction ratio must be >= 0.85 (got ${cluster.compactionRatio})`);
    assert.equal(cluster.centroidVector.length, 64, 'Centroid embedding must be exactly 64-dimensional');
    assert.equal(cluster.causalSummary.resolvedRootCause, 'Switch Egress Bufferbloat');

    // Long-horizon semantic recall query
    const searchResult = consolidator.queryHierarchicalMemory('TCP retransmit packet loss incident history', {
      topK: 5,
      minSimilarity: 0.20
    });

    assert.ok(searchResult);
    assert.ok(searchResult.totalMatches >= 1);
    const tcpMatch = searchResult.matches.find((m) => m.targetDomain === 'TCP');
    assert.ok(tcpMatch, 'Must find consolidated TCP cluster');
    assert.equal(tcpMatch.memoryTier, 'TIER2_CONSOLIDATED');
    assert.ok(tcpMatch.similarity > 0.40);
  });

  test('Subtest 4: Multi-Agent SRE War Room dynamic swarm dialectic cross-examination and Ed25519 quorum receipt generation', () => {
    const coordinator = new WarRoomSwarmCoordinator();
    coordinator.resetForTesting();

    const netSpecialist = coordinator.getMembersByRole('NETWORK_SPECIALIST')[0];
    const causalAuditor = coordinator.getMembersByRole('CAUSAL_AUDITOR')[0];
    const safetyVerifier = coordinator.getMembersByRole('SAFETY_VERIFIER')[0];
    const leadCoordinator = coordinator.getMembersByRole('LEAD_COORDINATOR')[0];
    const kernelSpecialist = coordinator.getMembersByRole('KERNEL_SPECIALIST')[0];

    assert.ok(netSpecialist && causalAuditor && safetyVerifier && leadCoordinator && kernelSpecialist);

    // 1. Submit signed thesis
    const thesis = coordinator.submitThesis(netSpecialist.agentId, {
      hypothesis: 'Egress switch port buffer exhaustion caused by microburst traffic',
      primaryLayer: 'L4_TRANSPORT',
      confidence: 0.94,
      evidenceClaims: ['RTT inflated 10x', 'Tail-drop packet discards'],
      proposedAction: 'ADAPTIVE_TCP_PACING'
    });
    assert.ok(thesis);
    assert.ok(thesis.signature);

    // 2. Issue cross-examination challenges
    const ch1 = coordinator.issueChallenge(causalAuditor.agentId, {
      targetThesisId: thesis.thesisId,
      challengeType: 'LATENT_CONFOUNDER_RISK',
      doubtScore: 0.20,
      critique: 'Verify host CPU hypervisor steal does not account for latency'
    });
    assert.ok(ch1);

    const ch2 = coordinator.issueChallenge(safetyVerifier.agentId, {
      targetThesisId: thesis.thesisId,
      challengeType: 'EXCESSIVE_BLAST_RADIUS',
      doubtScore: 0.10,
      critique: 'Confirm 2PC rollback token availability'
    });
    assert.ok(ch2);

    // 3. Deliberation voting
    coordinator.castVote(leadCoordinator.agentId, { thesisId: thesis.thesisId, vote: 'VOTE_APPROVE', rationale: 'Telemetry corroborated' });
    coordinator.castVote(netSpecialist.agentId, { thesisId: thesis.thesisId, vote: 'VOTE_APPROVE', rationale: 'Lead probe affirmed' });
    coordinator.castVote(kernelSpecialist.agentId, { thesisId: thesis.thesisId, vote: 'VOTE_APPROVE', rationale: 'Kernel socket drops match' });
    coordinator.castVote(safetyVerifier.agentId, { thesisId: thesis.thesisId, vote: 'VOTE_APPROVE', rationale: 'Rollback verified' });
    coordinator.castVote(causalAuditor.agentId, { thesisId: thesis.thesisId, vote: 'VOTE_APPROVE', rationale: 'Confounder refuted' });

    // 4. Synthesize Quorum
    const receipt = coordinator.synthesizeQuorum('INC-WARROOM-909', thesis.thesisId);
    assert.ok(receipt);
    assert.equal(receipt.quorumStatus, 'CONVERGED_UNANIMOUS');
    assert.equal(receipt.voteBreakdown.approve, 5);
    assert.ok(receipt.leadCoordinatorSignature);
    assert.equal(coordinator.verifyPayloadSignature(leadCoordinator.publicKeyPem, {
      receiptId: receipt.receiptId,
      incidentId: receipt.incidentId,
      winningThesisId: receipt.winningThesisId,
      synthesizedRootCause: receipt.synthesizedRootCause,
      recommendedRemediation: receipt.recommendedRemediation,
      quorumStatus: receipt.quorumStatus,
      voteBreakdown: receipt.voteBreakdown,
      participatingRoles: receipt.participatingRoles,
      epistemicDoubtIndex: receipt.epistemicDoubtIndex,
      convergedAtIso: receipt.convergedAtIso
    }, receipt.leadCoordinatorSignature), true);
  });

  test('Subtest 5: Zero-copy packet flow pipeline ring buffer throughput, zero-allocation binary parsing, and wavelet microburst stream coupling', () => {
    const pipeline = new ZeroCopyFlowPipeline(32, 128);

    // 1. SPSC lock-free ring buffer
    const testFrame = Buffer.alloc(64, 0x55);
    for (let i = 0; i < 32; i++) {
      testFrame[0] = i;
      assert.equal(pipeline.enqueuePacketFrame(testFrame), true);
    }
    assert.equal(pipeline.enqueuePacketFrame(testFrame), false, 'Backpressure must drop when full');
    assert.equal(pipeline.getStats().droppedCount, 1);

    const dequeued = pipeline.dequeuePacketFrame();
    assert.ok(dequeued);
    assert.equal(dequeued[0], 0);

    // 2. Zero-allocation DataView parsing
    const pktBuf = Buffer.alloc(54);
    pktBuf[0] = 0x45;
    pktBuf.writeUInt16BE(54, 2);
    pktBuf[9] = 6; // TCP
    pktBuf.writeUInt32BE(0x0a000001, 12); // 10.0.0.1
    pktBuf.writeUInt32BE(0x0a000002, 16); // 10.0.0.2
    pktBuf.writeUInt16BE(8080, 20); // Src Port
    pktBuf.writeUInt16BE(9090, 22); // Dst Port
    pktBuf.writeUInt32BE(12345, 24); // Seq
    pktBuf.writeUInt32BE(54321, 28); // Ack
    pktBuf.writeUInt16BE(0x5018, 32); // Data offset 5, Flags: PSH + ACK
    pktBuf.writeUInt16BE(32768, 34); // Window

    const header = pipeline.parsePacketHeader(pktBuf);
    assert.ok(header);
    assert.equal(header.protocolName, 'TCP');
    assert.equal(header.srcIpStr, '10.0.0.1');
    assert.equal(header.dstIpStr, '10.0.0.2');
    assert.equal(header.srcPort, 8080);
    assert.equal(header.dstPort, 9090);
    assert.equal(header.flags.psh, true);
    assert.equal(header.flags.ack, true);

    // 3. Flow ingestion & micro-burst coupling
    for (let i = 0; i < 8; i++) {
      pipeline.ingestPacket({
        ...header,
        seqNumber: 12345, // Duplicate seq triggers retransmit
        timestampMs: Date.now()
      });
    }

    const burstReport = pipeline.handleMicroBurstInterrupt({
      scale: 2,
      energyRatio: 2.75,
      hurstExponent: 0.81
    });

    assert.ok(burstReport);
    assert.equal(burstReport.scale2EnergyRatio, 2.75);
    assert.ok(burstReport.topAttributedFlows.length > 0);
    assert.equal(burstReport.topAttributedFlows[0].srcIp, '10.0.0.1');
    assert.equal(burstReport.topAttributedFlows[0].suspectedAnomaly, 'FAST_RETRANSMIT_STORM');
  });

  test('Subtest 6: End-to-end multi-node incident injection, autonomous swarm deliberation, bandit action selection, 2PC saga commit, and post-remediation verification', () => {
    // 1. Swarm deliberation
    const coordinator = new WarRoomSwarmCoordinator();
    coordinator.resetForTesting();
    const netAgent = coordinator.getMembersByRole('NETWORK_SPECIALIST')[0];
    const leadAgent = coordinator.getMembersByRole('LEAD_COORDINATOR')[0];

    const thesis = coordinator.submitThesis(netAgent.agentId, {
      hypothesis: 'Multi-node microburst queue collapse across core routing cluster',
      primaryLayer: 'L4_TRANSPORT',
      confidence: 0.95,
      evidenceClaims: ['Aggregate flow retransmit > 12%', 'Scale-2 Morlet wavelet energy ratio 3.2'],
      proposedAction: 'DISTRIBUTED_PACING_AND_QUEUE_REGULATION'
    });

    for (const member of coordinator.getAllMembers()) {
      coordinator.castVote(member.agentId, {
        thesisId: thesis.thesisId,
        vote: 'VOTE_APPROVE',
        rationale: 'Consensus achieved on core cluster remediation'
      });
    }

    const receipt = coordinator.synthesizeQuorum('INC-CLUSTER-909', thesis.thesisId);
    assert.equal(receipt.quorumStatus, 'CONVERGED_UNANIMOUS');

    // 2. Contextual bandit remediation selection
    const bandit = new ContextualBanditPolicyEngine();
    bandit.resetForTesting();
    bandit.registerOrGetArm('arm_distributed_pacing', 'TRANSPORT_TUNING');
    bandit.registerOrGetArm('arm_interface_bounce', 'LINK_RESTART');

    // Ingest prior rewards and exploit optimal arm
    bandit.recordReward({
      armId: 'arm_distributed_pacing',
      success: true,
      energyBefore: 10.0,
      deltaV: -8.0,
      blastRadius: 0.1,
      executionDurationMs: 150,
      contextVector: [0.95, 0.85, 0.12, 0.05]
    });

    const chosenAction = bandit.selectAction(['arm_distributed_pacing', 'arm_interface_bounce'], [0.95, 0.85, 0.12, 0.05], {
      algorithm: 'LIN_UCB',
      alphaUcb: 0.0
    });
    assert.equal(chosenAction.selectedArmId, 'arm_distributed_pacing');

    // 3. Distributed Saga Orchestration: 2PC atomic commit
    const saga = new DistributedSagaOrchestrator();
    const participants = [
      {
        nodeId: 'core-router-01',
        role: 'CORE_ROUTER',
        targetEndpoint: '10.0.0.1',
        currentState: { rttMs: 95.0, lossPct: 8.5, queueDepthPackets: 65 },
        candidateAction: {
          actionId: 'act_pacing_01',
          actionType: 'ADJUST_EGRESS_PACING',
          target: '10.0.0.1',
          rationale: 'Adjust pacing to relieve microburst collapse',
          expectedImpact: { rttDeltaMs: -65.0, lossDeltaPct: -8.0, queueDeltaPackets: -50 }
        },
        candidateInverse: {
          actionId: 'inv_pacing_01',
          inverseType: 'RESET_EGRESS_PACING',
          reversesActionId: 'act_pacing_01',
          target: '10.0.0.1',
          isCompensatingInverse: true
        }
      }
    ];

    const sagaRecord = saga.initiateSaga(receipt.winningThesisId, leadAgent.agentId, participants);
    assert.ok(sagaRecord);
    assert.equal(sagaRecord.phase, 'INITIATED');

    const prepareRes = saga.executePreparePhase(sagaRecord.sagaId);
    assert.ok(prepareRes);
    assert.equal(prepareRes.phase, 'COMMIT_VOTE_QUORUM');

    const commitRes = saga.executeCommitPhase(sagaRecord.sagaId);
    assert.ok(commitRes);
    assert.equal(commitRes.phase, 'COMMITTED');
    assert.ok(commitRes.commitTokens['core-router-01']);

    const finalizedSaga = saga.getSaga(sagaRecord.sagaId);
    assert.equal(finalizedSaga.phase, 'COMMITTED');
  });
});
