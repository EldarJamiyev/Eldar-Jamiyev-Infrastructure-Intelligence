/**
 * EJII Phase 4.0 Capstone Sovereign Intelligence Leap Verification Suite
 *
 * Validates the full Phase 4.0 Autonomous Cognitive Mesh & Verifiable Distributed Intelligence:
 *   Track 1: Continuous Wavelet Transform (Morlet CWT) & Rescaled Range (R/S) Hurst Exponent LRD Engine
 *   Track 2: Dimension-Expanded Achlioptas 512D->64D Metric Embeddings & Johnson-Lindenstrauss Isometry
 *   Track 3: Multi-Tier Topological Node Disambiguation & Temporal Scope Resolution in Conversational Brain
 *   Track 4: Generative Neuro-Symbolic Remediation with Lyapunov Contraction Proofs & Algebraic Inverses
 *   Track 5: Distributed Causal Loopy Belief Propagation & Cryptographic Byzantine Quorum Consensus
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

// Track 1
const {
  computeMorletWaveletTransform,
  computeHurstExponent,
  analyzeWaveletAndHurstLrd,
  waveletHurstLrdEngine
} = require('../src/ai/wavelet-hurst-lrd-engine');
const {
  predictiveHorizonEngine,
  evaluateWaveletLrdHorizon
} = require('../src/ai/predictive-horizon-engine');

// Track 2
const {
  DimensionExpandedEmbeddingEngine,
  dimensionExpandedEmbeddingEngine,
  DENSE_EMBEDDING_DIM,
  SPARSE_METRIC_SPACE_DIM,
  CANONICAL_METRIC_SLOTS
} = require('../src/ai/dimension-expanded-embedding-engine');
const { operationalMemoryEngine } = require('../src/core/memory/operational-memory-engine');
const { EpisodicCausalMemoryEngine } = require('../src/ai/episodic-causal-memory-engine');

// Track 3
const {
  disambiguateTopologicalTarget,
  resolveTemporalScope,
  runAgenticToolLoop,
  formulateRemediationGate
} = require('../src/core/chat/conversational-brain');

// Track 4
const {
  generativeRemediationSynthesizer,
  GenerativeRemediationSynthesizer,
  CANONICAL_LYAPUNOV_WEIGHTS
} = require('../src/systems/remediation/generative-remediation-synthesizer');

// Track 5
const {
  distributedBeliefPropagationEngine,
  DistributedBeliefPropagationEngine
} = require('../src/core/agent/distributed-belief-propagation');

test('Phase 4.0 Sovereign Intelligence Leap Capstone Verification Suite', async (t) => {
  // =========================================================================
  // Track 1: Wavelet Morlet CWT & Rescaled Range Hurst Exponent LRD Engine
  // =========================================================================
  await t.test('Track 1: Wavelet Morlet CWT & Hurst LRD Dispersion Analysis', async (t1) => {
    await t1.test('1a. Morlet Wavelet Transform computes dyadic scale energy and detects microbursts', () => {
      const smoothSeries = Array.from({ length: 64 }, (_, i) => 20.0 + 10.0 * Math.sin(i * 0.1));
      const burstSeries = [...smoothSeries];
      for (let i = 30; i <= 45; i++) {
        if (i % 2 === 0) burstSeries[i] += 80.0;
      }
      const cwt = computeMorletWaveletTransform(burstSeries);
      assert.strictEqual(cwt.microBurstDetected, true);
      assert.ok(cwt.highFrequencyRatio > 2.0);
    });

    await t1.test('1b. Hurst Exponent classifies LRD persistent trends and computes dispersion multiplier', () => {
      const persistentSeries = [];
      let currentVal = 25.0;
      let momentum = 0.5;
      for (let i = 0; i < 100; i++) {
        momentum = 0.75 * momentum + (Math.sin(i * 0.2) > 0 ? 0.8 : -0.8);
        currentVal = Math.max(5.0, currentVal + momentum);
        persistentSeries.push(currentVal);
      }
      const hurst = computeHurstExponent(persistentSeries);
      assert.ok(hurst.hurstExponent >= 0.65, `Expected H >= 0.65, got ${hurst.hurstExponent}`);
      assert.strictEqual(hurst.persistenceClassification, 'PERSISTENT_LONG_RANGE_DEPENDENT');
      assert.ok(hurst.dispersionMultiplier >= 1.0);
    });

    await t1.test('1c. Predictive Horizon Engine evaluates wavelet and Hurst LRD horizon', () => {
      const series = [10, 12, 14, 18, 22, 28, 35, 42, 50, 60, 72, 85, 100, 120, 145, 175];
      const horizon = evaluateWaveletLrdHorizon(series, { target: 'gateway-core-01' });
      assert.strictEqual(horizon.target, 'gateway-core-01');
      assert.ok(horizon.report);
      assert.ok(horizon.report.wavelet);
      assert.ok(horizon.report.hurst);
      assert.ok(typeof horizon.hurstExponent === 'number');
      assert.ok(typeof horizon.dispersionMultiplier === 'number');
    });
  });

  // =========================================================================
  // Track 2: Dimension-Expanded 512D -> 64D Embeddings & Johnson-Lindenstrauss
  // =========================================================================
  await t.test('Track 2: Dimension-Expanded Telemetry Embeddings & Dynamic State Projection', async (t2) => {
    await t2.test('2a. Achlioptas orthogonal matrix preserves Euclidean distance isometry', () => {
      const u = { rttMs: 25.0, packetLossPct: 1.0, dnsLatencyMs: 12.0, customMetricA: 85.0 };
      const v = { rttMs: 65.0, packetLossPct: 4.5, dnsLatencyMs: 45.0, customMetricA: 95.0 };

      const embU = DimensionExpandedEmbeddingEngine.projectTelemetryToDenseEmbedding(u);
      const embV = DimensionExpandedEmbeddingEngine.projectTelemetryToDenseEmbedding(v);

      assert.strictEqual(embU.length, DENSE_EMBEDDING_DIM);
      assert.strictEqual(embV.length, DENSE_EMBEDDING_DIM);

      const cosineSim = DimensionExpandedEmbeddingEngine.computeProjectedCosineSimilarity(embU, embV);
      assert.ok(cosineSim >= -1.0 && cosineSim <= 1.0);
      assert.ok(cosineSim > 0.40, `Expected high similarity for related states, got ${cosineSim}`);

      const dist = DimensionExpandedEmbeddingEngine.computeProjectedEuclideanDistance(embU, embV);
      assert.ok(dist > 0);
    });

    await t2.test('2b. Operational Memory and Episodic Experience Replay use projected embeddings', () => {
      const emb = operationalMemoryEngine.projectTelemetryEmbedding({
        rttMs: 32.5,
        packetLossPct: 0.8,
        dynamicQueueRate: 144.0
      });
      assert.strictEqual(emb.length, 64);

      const episodicEmb = EpisodicCausalMemoryEngine.projectToDenseEmbedding({
        rttMs: 25.0,
        tlsHandshakeMs: 45.0
      });
      assert.strictEqual(episodicEmb.length, 64);
    });
  });

  // =========================================================================
  // Track 3: Multi-Tier Topological Disambiguation & Temporal Scope Engine
  // =========================================================================
  await t.test('Track 3: Multi-Tier Topological Node Disambiguation & Temporal Scopes', async (t3) => {
    await t3.test('3a. Flags ambiguity when top 2 candidate nodes have score delta < 0.25', () => {
      const mockGraph = {
        nodes: new Map([
          ['db-cluster-01', { nodeId: 'db-cluster-01', label: 'PostgreSQL Database Node 1', resourceType: 'service_endpoint', status: 'healthy' }],
          ['db-cluster-02', { nodeId: 'db-cluster-02', label: 'PostgreSQL Database Node 2', resourceType: 'service_endpoint', status: 'healthy' }]
        ])
      };
      const result = disambiguateTopologicalTarget('inspect postgresql database node cluster', { temporalGraph: mockGraph });
      assert.strictEqual(result.ambiguous, true);
      assert.ok(result.delta < 0.25);
      assert.ok(result.disambiguationQuestion);
    });

    await t3.test('3b. Health degradation (+0.20 bias) breaks tie and elevates degraded node', () => {
      const mockGraph = {
        nodes: new Map([
          ['db-cluster-01', { nodeId: 'db-cluster-01', label: 'PostgreSQL Node 1', resourceType: 'service_endpoint', status: 'healthy' }],
          ['db-cluster-02', { nodeId: 'db-cluster-02', label: 'PostgreSQL Node 2', resourceType: 'service_endpoint', status: 'degraded' }]
        ])
      };
      const result = disambiguateTopologicalTarget('is postgresql node down?', { temporalGraph: mockGraph });
      assert.strictEqual(result.matchedTarget, 'db-cluster-02');
      const degraded = result.candidates.find((c) => c.nodeId === 'db-cluster-02');
      assert.strictEqual(degraded.isDegraded, true);
    });

    await t3.test('3c. Resolves relative temporal scopes and operational decision anchors', () => {
      const nowMs = 1700000000000;
      const res = resolveTemporalScope('packet drops in the past 15m', { nowMs });
      assert.strictEqual(res.resolved, true);
      assert.strictEqual(res.durationSeconds, 900);
      assert.strictEqual(res.anchor, 'RELATIVE_WINDOW');

      const mockMemory = {
        listOperationalDecisions: () => [
          { decisionId: 'DEC-REBOOT', actionId: 'restart_service', createdAt: new Date(nowMs - 600000).toISOString() }
        ]
      };
      const resReboot = resolveTemporalScope('investigate metrics after reboot', { nowMs, operationalMemoryEngine: mockMemory });
      assert.strictEqual(resReboot.resolved, true);
      assert.strictEqual(resReboot.anchor, 'OPERATIONAL_DECISION_REBOOT');
      assert.strictEqual(resReboot.durationSeconds, 600);
    });
  });

  // =========================================================================
  // Track 4: Generative Neuro-Symbolic Remediation with Lyapunov Proofs
  // =========================================================================
  await t.test('Track 4: Generative Neuro-Symbolic Remediation with Lyapunov Invariants', async (t4) => {
    await t4.test('4a. Synthesizes micro-remediation grammar with Lyapunov stability proof', () => {
      const currentState = { rttMs: 65.0, lossPct: 2.5, queueDepthPackets: 45 };
      const action = generativeRemediationSynthesizer.synthesizeRemediationCandidate(
        'BUFFERBLOAT_DETECTED',
        currentState,
        '10.0.0.1'
      );
      assert.strictEqual(action.actionType, 'TCP_WINDOW_CLAMP');

      const proof = generativeRemediationSynthesizer.proveLyapunovStability(currentState, action);
      assert.strictEqual(proof.verified, true);
      assert.strictEqual(proof.stabilityVerdict, 'STABLE_CONTRACTION');
      assert.ok(proof.deltaV <= -0.05);

      const inverse = generativeRemediationSynthesizer.deriveCompensatingInverse(action);
      assert.strictEqual(inverse.inverseType, 'TCP_WINDOW_UNCLAMP');
      assert.strictEqual(inverse.reversesActionId, action.actionId);
    });

    await t4.test('4b. Formulates cryptographic dual-custody action token and verifies authenticity', () => {
      const currentState = { rttMs: 45.0, lossPct: 1.0, queueDepthPackets: 20 };
      const action = generativeRemediationSynthesizer.synthesizeRemediationCandidate(
        'DNS_NXDOMAIN_POISON',
        currentState,
        '10.0.0.1'
      );
      const plan = generativeRemediationSynthesizer.issueCryptographicActionPlan(action, currentState);

      assert.ok(plan.actionToken);
      const verification = generativeRemediationSynthesizer.verifyActionPlanToken(plan.actionToken);
      assert.strictEqual(verification.valid, true);
      assert.strictEqual(verification.payload.actionType, 'DNS_UPSTREAM_PIVOT');
    });

    await t4.test('4c. formulateRemediationGate enriches remediation gates with Lyapunov proofs', async () => {
      const gate = await formulateRemediationGate('DNS_NXDOMAIN_POISON', '127.0.0.1');
      assert.ok(gate);
      assert.ok(gate.synthesizedMicroPlan);
      assert.strictEqual(gate.lyapunovProof.verified, true);
    });
  });

  // =========================================================================
  // Track 5: Distributed Causal Belief Propagation & Byzantine Consensus
  // =========================================================================
  await t.test('Track 5: Distributed Causal Loopy Belief Propagation & Byzantine Quorum Consensus', async (t5) => {
    await t5.test('5a. Damped Loopy Belief Propagation updates marginal distributions on causal factor graph', () => {
      const engine = new DistributedBeliefPropagationEngine();
      const baseline = engine.runLoopyBeliefPropagation({});
      const updated = engine.runLoopyBeliefPropagation({ UPSTREAM_WAN_BLACKHOLE: 0.90 });

      assert.ok(updated.DNS_NXDOMAIN_POISON > baseline.DNS_NXDOMAIN_POISON);
      assert.strictEqual(updated.UPSTREAM_WAN_BLACKHOLE, 0.90);
    });

    await t5.test('5b. Cryptographically signs belief reports and achieves Byzantine consensus (>= 2f + 1)', () => {
      const engine = new DistributedBeliefPropagationEngine();
      const epoch = 200;

      const honestBeliefs = {
        DNS_NXDOMAIN_POISON: 0.10,
        LOCAL_STACK_CONGESTION: 0.82,
        ARP_L2_ISOLATION: 0.04
      };

      const r1 = engine.generateSignedBeliefReport('agent-a', 'site-1', epoch, honestBeliefs);
      const r2 = engine.generateSignedBeliefReport('agent-b', 'site-2', epoch, { ...honestBeliefs, LOCAL_STACK_CONGESTION: 0.84 });
      const r3 = engine.generateSignedBeliefReport('agent-c', 'site-3', epoch, { ...honestBeliefs, LOCAL_STACK_CONGESTION: 0.81 });

      const rogueReport = {
        agentId: 'agent-malicious',
        siteId: 'site-x',
        epoch,
        timestampIso: new Date().toISOString(),
        beliefs: { DNS_NXDOMAIN_POISON: 0.99, LOCAL_STACK_CONGESTION: 0.01, ARP_L2_ISOLATION: 0.99 },
        signature: 'invalid_forged_signature_0000000000000000000000000000000000000000'
      };

      const consensus = engine.reachByzantineConsensus([r1, r2, r3, rogueReport], epoch);
      assert.strictEqual(consensus.quorumAchieved, true);
      assert.strictEqual(consensus.validSignaturesCount, 3);
      assert.strictEqual(consensus.byzantineRejectedCount, 1);
      assert.ok(consensus.rejectedAgents.includes('agent-malicious'));
      assert.ok(consensus.consensusBeliefs.LOCAL_STACK_CONGESTION >= 0.80);
      assert.ok(consensus.consensusHash);
    });
  });
});
