/**
 * Track 2 Verification Test Suite:
 * Dynamic Dimension-Expanded Metric Embedding Space & Johnson-Lindenstrauss Projection Engine
 */

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  DimensionExpandedEmbeddingEngine,
  dimensionExpandedEmbeddingEngine,
  DENSE_EMBEDDING_DIM,
  SPARSE_METRIC_SPACE_DIM,
  CANONICAL_METRIC_SLOTS
} = require('../src/ai/dimension-expanded-embedding-engine');

const {
  OperationalMemoryEngine
} = require('../src/core/memory/operational-memory-engine');

const {
  EpisodicCausalMemoryEngine
} = require('../src/ai/episodic-causal-memory-engine');

describe('Track 2: Dynamic Dimension-Expanded Metric Embedding Space (Johnson-Lindenstrauss)', () => {
  it('Subtest 1: Dimension constraints and canonical metric slot mappings', () => {
    assert.strictEqual(DENSE_EMBEDDING_DIM, 64);
    assert.strictEqual(SPARSE_METRIC_SPACE_DIM, 512);

    // Canonical metric slots are uniquely assigned
    const assignedSlots = Object.values(CANONICAL_METRIC_SLOTS);
    const uniqueSlots = new Set(assignedSlots);
    assert.strictEqual(assignedSlots.length, uniqueSlots.size);

    // Known canonical metrics map to predictable slots < 32
    assert.strictEqual(DimensionExpandedEmbeddingEngine.resolveMetricSlot('rttMs'), 0);
    assert.strictEqual(DimensionExpandedEmbeddingEngine.resolveMetricSlot('packetLossPct'), 1);
    assert.strictEqual(DimensionExpandedEmbeddingEngine.resolveMetricSlot('dnsLatencyMs'), 2);
    assert.strictEqual(DimensionExpandedEmbeddingEngine.resolveMetricSlot('diskIoLatencyMs'), 7);
    assert.strictEqual(DimensionExpandedEmbeddingEngine.resolveMetricSlot('bgpPrefixFlapCount'), 10);

    // Dynamic unmapped metric names hash deterministically into slots >= 32
    const slotA1 = DimensionExpandedEmbeddingEngine.resolveMetricSlot('customQueueSaturationMetricX');
    const slotA2 = DimensionExpandedEmbeddingEngine.resolveMetricSlot('customQueueSaturationMetricX');
    assert.strictEqual(slotA1, slotA2);
    assert.ok(slotA1 >= 32 && slotA1 < 512);

    const slotB = DimensionExpandedEmbeddingEngine.resolveMetricSlot('storageNvmeReadIops');
    assert.ok(slotB >= 32 && slotB < 512);
  });

  it('Subtest 2: Projects heterogeneous telemetry maps into dense 64D Float32Array embeddings', () => {
    const rawMetrics = {
      rttMs: 24.5,
      packetLossPct: 0.0,
      dnsLatencyMs: 14.2,
      cpuSaturationPct: 35.0,
      tcpRetransmitRate: 0.02,
      diskIoLatencyMs: 8.5,
      memoryFragmentationPct: 12.0,
      bgpPrefixFlapCount: 0,
      tlsHandshakeMs: 42.0,
      customDaemonBacklog: 150
    };

    const dense1 = DimensionExpandedEmbeddingEngine.projectTelemetryToDenseEmbedding(rawMetrics);
    assert.ok(dense1 instanceof Float32Array);
    assert.strictEqual(dense1.length, 64);

    // Projection is deterministic across repeat executions
    const dense2 = DimensionExpandedEmbeddingEngine.projectTelemetryToDenseEmbedding(rawMetrics);
    for (let i = 0; i < 64; i++) {
      assert.strictEqual(dense1[i], dense2[i]);
    }

    // Has non-zero energy
    let sumSq = 0;
    for (let i = 0; i < 64; i++) sumSq += dense1[i] * dense1[i];
    assert.ok(sumSq > 0.01, 'Dense embedding must have non-zero energy');
  });

  it('Subtest 3: Preserves Euclidean metric distance via Johnson-Lindenstrauss Lemma', () => {
    // Generate two heterogeneous sparse telemetry vectors
    const vecA = {
      rttMs: 20.0,
      packetLossPct: 0.0,
      cpuSaturationPct: 30.0,
      diskIoLatencyMs: 5.0,
      tlsHandshakeMs: 30.0
    };

    // Perturb vector B by known deltas
    const vecB = {
      rttMs: 65.0, // delta = 45 / 100 = 0.45
      packetLossPct: 5.0, // delta = 5 / 100 = 0.05
      cpuSaturationPct: 75.0, // delta = 45 / 100 = 0.45
      diskIoLatencyMs: 25.0, // delta = 20 / 50 = 0.40
      tlsHandshakeMs: 110.0 // delta = 80 / 200 = 0.40
    };

    // Compute sparse normalized distance d_orig^2
    let dOrigSq = 0;
    for (const key of Object.keys(vecA)) {
      const normA = DimensionExpandedEmbeddingEngine.normalizeMetricValue(key, vecA[key]);
      const normB = DimensionExpandedEmbeddingEngine.normalizeMetricValue(key, vecB[key]);
      dOrigSq += Math.pow(normA - normB, 2);
    }
    assert.ok(dOrigSq > 0.1);

    // Project both
    const embA = DimensionExpandedEmbeddingEngine.projectTelemetryToDenseEmbedding(vecA);
    const embB = DimensionExpandedEmbeddingEngine.projectTelemetryToDenseEmbedding(vecB);

    const dProj = DimensionExpandedEmbeddingEngine.computeProjectedEuclideanDistance(embA, embB);
    const dProjSq = dProj * dProj;

    const ratio = dProjSq / dOrigSq;
    // Johnson-Lindenstrauss guarantees ratio is near 1.0 (within 0.5 to 1.6 on k=64)
    assert.ok(ratio >= 0.50 && ratio <= 1.65, `JL distance ratio (${ratio.toFixed(3)}) must preserve Euclidean scale`);
  });

  it('Subtest 4: Cosine similarity identifies identical vs disparate infrastructure states', () => {
    const baseline = {
      rttMs: 15.0,
      packetLossPct: 0.0,
      dnsLatencyMs: 10.0,
      cpuSaturationPct: 20.0
    };

    const slightlyDegraded = {
      rttMs: 18.0,
      packetLossPct: 0.2,
      dnsLatencyMs: 12.0,
      cpuSaturationPct: 25.0
    };

    const severeOutage = {
      rttMs: 550.0,
      packetLossPct: 45.0,
      dnsLatencyMs: 250.0,
      cpuSaturationPct: 98.0,
      socketQueueDropRate: 0.85
    };

    const embBase = DimensionExpandedEmbeddingEngine.projectTelemetryToDenseEmbedding(baseline);
    const embSlight = DimensionExpandedEmbeddingEngine.projectTelemetryToDenseEmbedding(slightlyDegraded);
    const embSevere = DimensionExpandedEmbeddingEngine.projectTelemetryToDenseEmbedding(severeOutage);

    // Identical vector similarity = 1.0
    const simSelf = DimensionExpandedEmbeddingEngine.computeProjectedCosineSimilarity(embBase, embBase);
    assert.strictEqual(simSelf, 1.0);

    // Slight degradation is highly similar to baseline
    const simSlight = DimensionExpandedEmbeddingEngine.computeProjectedCosineSimilarity(embBase, embSlight);
    assert.ok(simSlight > 0.85, `Slight degradation similarity (${simSlight}) must be high`);

    // Severe outage is distinct
    const simSevere = DimensionExpandedEmbeddingEngine.computeProjectedCosineSimilarity(embBase, embSevere);
    assert.ok(simSlight > simSevere, 'Slight degradation must have higher similarity than severe outage');

    // Distance to self is 0
    const distSelf = DimensionExpandedEmbeddingEngine.computeProjectedEuclideanDistance(embBase, embBase);
    assert.strictEqual(distSelf, 0.0);
  });

  it('Subtest 5: Integrates with OperationalMemoryEngine and EpisodicCausalMemoryEngine', () => {
    const memory = new OperationalMemoryEngine({ useSqlite: true });

    const embedding = memory.projectTelemetryEmbedding({
      rttMs: 25.0,
      diskIoLatencyMs: 12.0,
      bgpPrefixFlapCount: 2
    });
    assert.ok(embedding instanceof Float32Array);
    assert.strictEqual(embedding.length, 64);

    // Episodic causal memory engine integration
    const episodicEmbedding = EpisodicCausalMemoryEngine.projectToDenseEmbedding({
      rttMs: 25.0,
      tlsHandshakeMs: 45.0
    });
    assert.ok(episodicEmbedding instanceof Float32Array);
    assert.strictEqual(episodicEmbedding.length, 64);

    // Indexed record generation
    const record = DimensionExpandedEmbeddingEngine.createMetricEmbeddingRecord('gateway-core', {
      rttMs: 15.4,
      packetLossPct: 0.0
    });
    assert.strictEqual(record.target, 'gateway-core');
    assert.strictEqual(record.denseVector.length, 64);
    assert.ok(record.norm > 0);
  });
});
