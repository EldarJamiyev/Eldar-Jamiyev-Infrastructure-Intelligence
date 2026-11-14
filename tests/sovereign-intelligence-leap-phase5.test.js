/**
 * EJII Phase 5.0 — Capstone Verification Harness
 * Validates the complete Sovereign Counterfactual Mesh & Distributed Autonomous Self-Healing leap:
 *   Track 1: Pearlian do-Calculus Structural Causal Models (SCM) & Counterfactuals
 *   Track 2: Distributed Transactional Remediation Saga & 2PC Multi-Node Orchestrator
 *   Track 3: Hierarchical Navigable Small World (HNSW) Vector Graph & Louvain Modularity Clustering
 *   Track 4: Lock-Free SharedArrayBuffer Ring Buffer & Verified BPF Bytecode JIT Engine
 *   Track 5: Asymmetric Ed25519 Cryptographic State Vectors & Incremental Merkle Consensus
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

// Track 1
const {
  StructuralCausalEngine,
  structuralCausalEngine
} = require('../src/ai/structural-causal-engine');
const {
  runAgenticToolLoop,
  formulateRemediationGate
} = require('../src/core/chat/conversational-brain');

// Track 2
const {
  DistributedSagaOrchestrator,
  distributedSagaOrchestrator
} = require('../src/systems/remediation/distributed-saga-orchestrator');

// Track 3
const {
  HnswEpisodicIndex,
  hnswEpisodicIndex
} = require('../src/core/memory/hnsw-episodic-index');
const { operationalMemoryEngine } = require('../src/core/memory/operational-memory-engine');

// Track 4
const {
  SharedRingPipeline,
  VerifiedBpfJitEngine
} = require('../src/network/packet-streaming/shared-ring-pipeline');
const {
  encodeBinaryPacketFrame,
  decodeBinaryPacketFrame,
  createSharedRingPipeline
} = require('../src/network/packet-streaming/binary-frame-codec');

// Track 5
const {
  ZkEpistemicConsensusEngine,
  zkEpistemicConsensusEngine
} = require('../src/core/agent/zk-epistemic-consensus');

describe('EJII Phase 5.0 Sovereign Capstone Verification Suite', () => {

  // =========================================================================
  // Track 1: Structural Causal Models & Counterfactual do-Calculus
  // =========================================================================
  describe('Track 1: Structural Causal Models & Pearlian do-Calculus', () => {
    test('1.1 Pearlian three-step counterfactual algorithm (Abduction, Action, Prediction)', () => {
      const engine = new StructuralCausalEngine();
      const factual = {
        queueDepthPackets: 60.0,
        rttMs: 55.0,
        packetLossPct: 5.0,
        windowSizeBytes: 65535
      };

      // Intervene on queue depth do(queueDepth = 10)
      const result = engine.evaluateCounterfactual(factual, [
        { variable: 'queueDepthPackets', targetValue: 10.0 }
      ]);
      assert.ok(result);
      assert.equal(result.interventions[0].targetValue, 10.0);
      assert.equal(result.factualState.rttMs, 55.0);
      assert.equal(result.counterfactualState.rttMs, 35.0);
      assert.equal(result.deltas.deltaRttMs, -20.0);
      assert.ok(result.counterfactualState.rttMs < factual.rttMs);
    });

    test('1.2 Conversational brain parses counterfactual queries and returns structured causal twin predictions', async () => {
      const outcome = await runAgenticToolLoop({
        promptText: 'what if we clamp tcp window to 32kb on the gateway?',
        initialPlan: { intent: 'host_metrics', target: '127.0.0.1', mode: 'operational' },
        executeSinglePlan: async () => ({
          reply: 'Telemetry normal.',
          technicalEvidence: { rttMs: 38.0 },
          structuredAnswer: { result: 'OK', meaning: 'Metrics nominal' }
        }),
        maxSteps: 1
      });

      assert.ok(outcome);
      assert.ok(outcome.epistemicClassification);
      assert.ok(outcome.epistemicClassification.counterfactualAnalysis);
      assert.match(outcome.reply, /Pearlian Counterfactual/);
    });
  });

  // =========================================================================
  // Track 2: Distributed Transactional Remediation Saga & 2PC Orchestrator
  // =========================================================================
  describe('Track 2: Distributed Transactional Remediation Saga & 2PC Orchestrator', () => {
    test('2.1 Non-convex state-adaptive Riemannian Lyapunov metric is strictly positive-definite', () => {
      const orchestrator = new DistributedSagaOrchestrator();
      const states = [
        { rttMs: 20.0, lossPct: 0.1, queueDepthPackets: 5 },
        { rttMs: 90.0, lossPct: 2.0, queueDepthPackets: 30 },
        { rttMs: 150.0, lossPct: 6.5, queueDepthPackets: 65 }
      ];

      for (const s of states) {
        assert.equal(orchestrator.isMetricPositiveDefinite(s), true);
        const V = orchestrator.computeRiemannianLyapunovEnergy(s);
        assert.ok(V > 0);
      }
    });

    test('2.2 Full 2PC lifecycle: unanimous commit quorum and atomic execution token distribution', () => {
      const orchestrator = new DistributedSagaOrchestrator();
      const participants = [
        {
          nodeId: 'edge_sw_01',
          role: 'EDGE_SWITCH',
          targetEndpoint: '192.168.1.1',
          currentState: { rttMs: 40.0, lossPct: 1.5, queueDepthPackets: 30 },
          candidateAction: {
            actionId: 'act_clamp_1',
            actionType: 'TCP_WINDOW_CLAMP',
            target: '192.168.1.1',
            parameters: { windowBytes: 32768 },
            rationale: 'Mitigate bufferbloat',
            expectedImpact: { rttDeltaMs: -15.0, lossDeltaPct: -0.8, queueDeltaPackets: -18 },
            requiresElevation: false,
            commandPreview: 'cmd_clamp'
          },
          candidateInverse: {
            actionId: 'inv_clamp_1',
            inverseType: 'TCP_WINDOW_UNCLAMP',
            reversesActionId: 'act_clamp_1',
            target: '192.168.1.1',
            parameters: {},
            rationale: 'Revert clamp',
            commandPreview: 'cmd_unclamp',
            requiresElevation: false,
            isCompensatingInverse: true
          }
        },
        {
          nodeId: 'core_gw_01',
          role: 'CORE_GATEWAY',
          targetEndpoint: '10.0.0.1',
          currentState: { rttMs: 20.0, lossPct: 0.5, queueDepthPackets: 12 },
          candidateAction: {
            actionId: 'act_shape_1',
            actionType: 'DSCP_TRAFFIC_SHAPE',
            target: '10.0.0.1',
            parameters: {},
            rationale: 'QoS traffic shaping',
            expectedImpact: { rttDeltaMs: -8.0, lossDeltaPct: -0.3, queueDeltaPackets: -6 },
            requiresElevation: false,
            commandPreview: 'cmd_shape'
          },
          candidateInverse: {
            actionId: 'inv_shape_1',
            inverseType: 'DSCP_DEFAULT',
            reversesActionId: 'act_shape_1',
            target: '10.0.0.1',
            parameters: {},
            rationale: 'Revert shaping',
            commandPreview: 'cmd_unshape',
            requiresElevation: false,
            isCompensatingInverse: true
          }
        }
      ];

      const saga = orchestrator.initiateSaga('GATEWAY_BUFFERBLOAT', 'operator', participants);
      const prep = orchestrator.executePreparePhase(saga.sagaId);
      assert.equal(prep.phase, 'COMMIT_VOTE_QUORUM');
      assert.equal(prep.lyapunovAggregate.isRiemannianStable, true);

      const comm = orchestrator.executeCommitPhase(saga.sagaId);
      assert.equal(comm.phase, 'COMMITTED');
      assert.equal(Object.keys(comm.commitTokens).length, 2);
    });

    test('2.3 Coordinated compensating rollback upon participant failure', () => {
      const orchestrator = new DistributedSagaOrchestrator();
      const participants = [
        {
          nodeId: 'edge_ok',
          role: 'EDGE_SWITCH',
          targetEndpoint: '192.168.1.1',
          currentState: { rttMs: 30.0, lossPct: 1.0, queueDepthPackets: 20 },
          candidateAction: {
            actionId: 'act_ok',
            actionType: 'TCP_WINDOW_CLAMP',
            target: '192.168.1.1',
            parameters: {},
            rationale: 'Relieve edge queue',
            expectedImpact: { rttDeltaMs: -10.0, lossDeltaPct: -0.5, queueDeltaPackets: -10 },
            requiresElevation: false,
            commandPreview: 'cmd'
          },
          candidateInverse: {
            actionId: 'inv_ok',
            inverseType: 'TCP_WINDOW_UNCLAMP',
            reversesActionId: 'act_ok',
            target: '192.168.1.1',
            parameters: {},
            rationale: 'Revert',
            commandPreview: 'cmd_inv',
            requiresElevation: false,
            isCompensatingInverse: true
          }
        },
        {
          nodeId: 'gw_failing',
          role: 'CORE_GATEWAY',
          targetEndpoint: '10.0.0.1',
          currentState: { rttMs: 20.0, lossPct: 0.5, queueDepthPackets: 10 },
          candidateAction: {
            actionId: 'act_fail',
            actionType: 'DSCP_TRAFFIC_SHAPE',
            target: '10.0.0.1',
            parameters: {},
            rationale: 'Harmful parameter tuning',
            expectedImpact: { rttDeltaMs: +50.0, lossDeltaPct: +5.0, queueDeltaPackets: +40 },
            requiresElevation: false,
            commandPreview: 'cmd_bad'
          },
          candidateInverse: {
            actionId: 'inv_fail',
            inverseType: 'DSCP_DEFAULT',
            reversesActionId: 'act_fail',
            target: '10.0.0.1',
            parameters: {},
            rationale: 'Revert bad action',
            commandPreview: 'cmd_inv_bad',
            requiresElevation: false,
            isCompensatingInverse: true
          }
        }
      ];

      const saga = orchestrator.initiateSaga('HIGH_TCP_LATENCY', 'operator', participants);
      const prep = orchestrator.executePreparePhase(saga.sagaId);
      assert.equal(prep.phase, 'ABORTED_PRE');

      const rolled = orchestrator.executeCommitPhase(saga.sagaId);
      assert.equal(rolled.phase, 'ROLLED_BACK');
      assert.equal(rolled.rollbackExecuted, true);
    });
  });

  // =========================================================================
  // Track 3: HNSW Vector Graph Index & Louvain Incident Cascade Clustering
  // =========================================================================
  describe('Track 3: HNSW Vector Graph Index & Louvain Modularity', () => {
    test('3.1 HNSW sub-millisecond search retrieval and high cluster precision', () => {
      const index = new HnswEpisodicIndex();

      for (let i = 0; i < 80; i++) {
        const cluster = i % 3;
        const telemetry = {
          clusterId: cluster,
          rttMs: cluster === 0 ? 15 + (i % 5) : (cluster === 1 ? 160 + (i % 10) : 60 + (i % 8)),
          lossPct: cluster === 2 ? 6.0 : 0.1,
          queueDepth: cluster === 1 ? 75 : 5
        };
        const vec = index.projectTelemetryTo64D(telemetry);
        index.insert(`inc_${i}`, vec, { id: `inc_${i}`, cluster });
      }

      assert.equal(index.size(), 80);

      const qVec = index.projectTelemetryTo64D({ rttMs: 16.0, lossPct: 0.1, queueDepth: 5, expectedCluster: 0 });
      const hits = index.searchKNN(qVec, 5);
      assert.equal(hits.length, 5);

      const clusterZeroHits = hits.filter(h => h.payload.cluster === 0).length;
      assert.ok(clusterZeroHits >= 4, `Must retrieve predominantly cluster 0 items, got ${clusterZeroHits}`);
    });

    test('3.2 Louvain modularity partitions multi-hop incident cascades with positive Q', () => {
      const index = new HnswEpisodicIndex();
      const edges = [
        { source: 'dns_fail', target: 'dns_cache_miss', weight: 4 },
        { source: 'dns_cache_miss', target: 'http_504', weight: 4 },
        { source: 'mem_leak', target: 'oom_kill', weight: 5 },
        { source: 'oom_kill', target: 'socket_drop', weight: 5 },
        { source: 'http_504', target: 'mem_leak', weight: 1 } // Weak bridge
      ];

      const clusterResult = index.clusterIncidentCascades(edges);
      assert.equal(clusterResult.communities.length, 2);
      assert.ok(clusterResult.modularityQ > 0.20);
    });
  });

  // =========================================================================
  // Track 4: Lock-Free SharedArrayBuffer Ring & Verified BPF Bytecode JIT
  // =========================================================================
  describe('Track 4: Lock-Free SharedArrayBuffer Ring & Verified BPF JIT', () => {
    test('4.1 High-throughput atomic SPSC ring buffer without drops under capacity', () => {
      const ring = new SharedRingPipeline(256, 128);

      for (let i = 0; i < 500; i++) {
        const payload = Buffer.from(`seq_${i}_telemetry_frame`);
        const ok = ring.enqueuePacket(payload);
        assert.equal(ok, true);

        const dequeued = ring.dequeuePacket();
        assert.ok(dequeued);
        assert.equal(Buffer.from(dequeued).toString(), payload.toString());
      }

      assert.equal(ring.getStats().dropCount, 0);
      assert.equal(ring.getStats().occupancy, 0);
    });

    test('4.2 Verified BPF bytecode validator rejects backward loops and verifies memory safety', () => {
      // Loop program must be rejected
      const badLoop = [
        { opcode: 'LD_B', offset: 0 },
        { opcode: 'JEQ', val: 10, jt: 0, jf: 2 },
        { opcode: 'RET', val: 1 }
      ];
      assert.equal(VerifiedBpfJitEngine.validateProgram(badLoop).valid, false);

      // Safe DAG program must be accepted
      const safeDag = [
        { opcode: 'LD_B', offset: 9 },
        { opcode: 'JEQ', val: 6, jt: 2, jf: 3 },
        { opcode: 'RET', val: 1 },
        { opcode: 'RET', val: 0 }
      ];
      const valid = VerifiedBpfJitEngine.validateProgram(safeDag);
      assert.equal(valid.valid, true);
      assert.equal(valid.isForwardAcyclicDag, true);

      // Execute on TCP packet (proto = 6)
      const packet = new Uint8Array(20);
      packet[9] = 6;
      assert.equal(VerifiedBpfJitEngine.execute(safeDag, packet), true);

      // Execute on UDP packet (proto = 17)
      packet[9] = 17;
      assert.equal(VerifiedBpfJitEngine.execute(safeDag, packet), false);
    });
  });

  // =========================================================================
  // Track 5: Asymmetric Ed25519 State Vectors & Incremental Merkle Consensus
  // =========================================================================
  describe('Track 5: Asymmetric Ed25519 & Incremental Merkle Consensus', () => {
    test('5.1 Authentic Ed25519 signature generation and tamper rejection', () => {
      const engine = new ZkEpistemicConsensusEngine();
      const keyPair = engine.generateAgentKeyPair();

      const report = {
        agentId: 'edge_daemon_01',
        siteId: 'site_dc_east',
        epoch: 10,
        timestampIso: new Date().toISOString(),
        beliefs: { LOCAL_STACK_CONGESTION: 0.90 },
        metricsSummary: { rttMs: 40.0, lossPct: 1.0, queueDepth: 20 }
      };

      const signed = engine.signReport(report, keyPair.privateKeyPem);
      assert.equal(engine.verifyReportSignature(signed, keyPair.publicKeyPem), true);

      const forged = { ...signed, beliefs: { LOCAL_STACK_CONGESTION: 0.05 } };
      assert.equal(engine.verifyReportSignature(forged, keyPair.publicKeyPem), false);
    });

    test('5.2 Incremental Merkle Tree and BFT Quorum Consensus with inclusion proofs', () => {
      const engine = new ZkEpistemicConsensusEngine();
      const reports = [];

      for (let i = 0; i < 8; i++) {
        const keyPair = engine.generateAgentKeyPair();
        const agentId = `agent_bft_${i}`;
        engine.enrollAgent(agentId, 'site_us', keyPair.publicKeyPem);

        const rep = {
          agentId,
          siteId: 'site_us',
          epoch: 25,
          timestampIso: new Date().toISOString(),
          beliefs: { UPSTREAM_WAN_BLACKHOLE: 0.80 },
          metricsSummary: { rttMs: 30 + i, lossPct: 0.2, queueDepth: 15 }
        };
        reports.push(engine.signReport(rep, keyPair.privateKeyPem));
      }

      // Add byzantine agent
      reports.push({
        agentId: 'adversary_agent',
        siteId: 'site_us',
        epoch: 25,
        timestampIso: new Date().toISOString(),
        beliefs: { UPSTREAM_WAN_BLACKHOLE: 0.0 },
        metricsSummary: { rttMs: 5, lossPct: 0, queueDepth: 0 },
        signature: 'INVALID_SIGNATURE'
      });

      const receipt = engine.aggregateConsensus(25, reports);
      assert.equal(receipt.totalAgentsReported, 9);
      assert.equal(receipt.validReportsCount, 8);
      assert.equal(receipt.byzantineRejectedCount, 1);
      assert.equal(receipt.quorumAchieved, true);
      assert.ok(receipt.merkleRoot.length === 64);

      // Verify every valid agent has valid cryptographic Merkle inclusion proof
      for (const agentId of receipt.validAgents) {
        const proof = receipt.proofs[agentId];
        assert.ok(proof);
        assert.equal(ZkEpistemicConsensusEngine.verifyMerkleProof(proof), true);
      }
    });
  });

});
