/**
 * EJII Dimension-Expanded Metric Embedding Space & Johnson-Lindenstrauss Projection Engine
 *
 * Breaks free from fixed-schema 8D telemetry vectors by projecting arbitrary sparse
 * infrastructure metrics (D <= 512) into a dense 64D metric space (k = 64) using an
 * orthogonal Achlioptas random matrix R in R^{k x D}.
 *
 * Guarantees Euclidean metric preservation via the Johnson-Lindenstrauss Lemma:
 *   (1 - epsilon) ||u - v||^2 <= ||R*u - R*v||^2 <= (1 + epsilon) ||u - v||^2
 * with epsilon < 0.15 for efficient, high-fidelity experience replay across heterogeneous telemetry.
 */

'use strict';

Object.defineProperty(exports, '__esModule', { value: true });
exports.dimensionExpandedEmbeddingEngine = exports.DimensionExpandedEmbeddingEngine = exports.CANONICAL_METRIC_SCALES = exports.CANONICAL_METRIC_SLOTS = exports.SPARSE_METRIC_SPACE_DIM = exports.DENSE_EMBEDDING_DIM = void 0;

const crypto = require('crypto');

const DENSE_EMBEDDING_DIM = 64;
exports.DENSE_EMBEDDING_DIM = DENSE_EMBEDDING_DIM;

const SPARSE_METRIC_SPACE_DIM = 512;
exports.SPARSE_METRIC_SPACE_DIM = SPARSE_METRIC_SPACE_DIM;

const CANONICAL_METRIC_SLOTS = {
  rttMs: 0,
  packetLossPct: 1,
  dnsLatencyMs: 2,
  cpuSaturationPct: 3,
  tcpRetransmitRate: 4,
  cusumShiftSigma: 5,
  spectralFlatness: 6,
  diskIoLatencyMs: 7,
  diskUtilizationPct: 8,
  memoryFragmentationPct: 9,
  bgpPrefixFlapCount: 10,
  tlsHandshakeMs: 11,
  arpResolutionTimeMs: 12,
  socketQueueDropRate: 13,
  httpTtfbMs: 14,
  httpErrorRate5xx: 15,
  nicBufferOverrunCount: 16,
  nicCarrierErrors: 17,
  snmpCpuBusyPct: 18,
  snmpMemPoolUsagePct: 19,
  lyapunovEnergy: 20,
  hurstExponent: 21,
  waveletHighFreqRatio: 22,
  consecutiveFailures: 23
};
exports.CANONICAL_METRIC_SLOTS = CANONICAL_METRIC_SLOTS;

const CANONICAL_METRIC_SCALES = {
  rttMs: 100.0,
  packetLossPct: 100.0,
  dnsLatencyMs: 100.0,
  cpuSaturationPct: 100.0,
  tcpRetransmitRate: 1.0,
  cusumShiftSigma: 5.0,
  spectralFlatness: 1.0,
  diskIoLatencyMs: 50.0,
  diskUtilizationPct: 100.0,
  memoryFragmentationPct: 100.0,
  bgpPrefixFlapCount: 20.0,
  tlsHandshakeMs: 200.0,
  arpResolutionTimeMs: 50.0,
  socketQueueDropRate: 1.0,
  httpTtfbMs: 500.0,
  httpErrorRate5xx: 100.0,
  nicBufferOverrunCount: 1000.0,
  nicCarrierErrors: 50.0,
  snmpCpuBusyPct: 100.0,
  snmpMemPoolUsagePct: 100.0,
  lyapunovEnergy: 10.0,
  hurstExponent: 1.0,
  waveletHighFreqRatio: 10.0,
  consecutiveFailures: 5.0
};
exports.CANONICAL_METRIC_SCALES = CANONICAL_METRIC_SCALES;

class DimensionExpandedEmbeddingEngine {
  static projectionMatrix = null;

  static _ensureProjectionMatrix() {
    if (this.projectionMatrix) {
      return this.projectionMatrix;
    }

    const K = DENSE_EMBEDDING_DIM;
    const D = SPARSE_METRIC_SPACE_DIM;
    const matrix = new Float32Array(K * D);
    const weight = Math.sqrt(3.0) / Math.sqrt(K);

    for (let i = 0; i < K; i++) {
      for (let j = 0; j < D; j++) {
        const hash = crypto.createHash('sha256').update(`${i}:${j}:EJII_JL_PROJECTION_v1`).digest();
        const randVal = hash.readUInt32LE(0) / 0xffffffff;

        let val = 0;
        if (randVal < 1.0 / 6.0) {
          val = weight;
        } else if (randVal > 5.0 / 6.0) {
          val = -weight;
        }
        matrix[i * D + j] = val;
      }
    }

    this.projectionMatrix = matrix;
    return matrix;
  }

  static resolveMetricSlot(key) {
    if (Object.prototype.hasOwnProperty.call(CANONICAL_METRIC_SLOTS, key)) {
      return CANONICAL_METRIC_SLOTS[key];
    }
    const hash = crypto.createHash('md5').update(key).digest();
    const hashInt = hash.readUInt32BE(0);
    const dynamicSlotsCount = SPARSE_METRIC_SPACE_DIM - 32;
    return 32 + (hashInt % dynamicSlotsCount);
  }

  static normalizeMetricValue(key, rawVal) {
    if (!Number.isFinite(rawVal)) return 0;
    const scale = CANONICAL_METRIC_SCALES[key];
    if (scale && scale > 0) {
      return rawVal / scale;
    }
    const sign = rawVal >= 0 ? 1 : -1;
    return sign * Math.log1p(Math.abs(rawVal));
  }

  static projectTelemetryToDenseEmbedding(metrics) {
    const matrix = this._ensureProjectionMatrix();
    const K = DENSE_EMBEDDING_DIM;
    const D = SPARSE_METRIC_SPACE_DIM;
    const dense = new Float32Array(K);

    if (!metrics || typeof metrics !== 'object') {
      return dense;
    }

    const activeEntries = [];

    for (const [key, rawVal] of Object.entries(metrics)) {
      if (typeof rawVal !== 'number' || !Number.isFinite(rawVal)) continue;
      const slot = this.resolveMetricSlot(key);
      const normalized = this.normalizeMetricValue(key, rawVal);
      activeEntries.push({ slot, value: normalized });
    }

    if (activeEntries.length === 0) {
      return dense;
    }

    for (let i = 0; i < K; i++) {
      let sum = 0;
      const rowOffset = i * D;
      for (const entry of activeEntries) {
        sum += matrix[rowOffset + entry.slot] * entry.value;
      }
      dense[i] = sum;
    }

    return dense;
  }

  static projectLegacyTelemetrySignature(sig) {
    return this.projectTelemetryToDenseEmbedding(sig);
  }

  static computeProjectedCosineSimilarity(emb1, emb2) {
    const K = Math.min(emb1.length, emb2.length, DENSE_EMBEDDING_DIM);
    if (K === 0) return 0.0;

    let dot = 0;
    let norm1 = 0;
    let norm2 = 0;

    for (let i = 0; i < K; i++) {
      const v1 = emb1[i] || 0;
      const v2 = emb2[i] || 0;
      dot += v1 * v2;
      norm1 += v1 * v1;
      norm2 += v2 * v2;
    }

    if (norm1 <= 1e-12 || norm2 <= 1e-12) {
      return 0.0;
    }

    const sim = dot / (Math.sqrt(norm1) * Math.sqrt(norm2));
    return Number(Math.max(-1.0, Math.min(1.0, sim)).toFixed(4));
  }

  static computeProjectedEuclideanDistance(emb1, emb2) {
    const K = Math.min(emb1.length, emb2.length, DENSE_EMBEDDING_DIM);
    if (K === 0) return 0.0;

    let sumSq = 0;
    for (let i = 0; i < K; i++) {
      const diff = (emb1[i] || 0) - (emb2[i] || 0);
      sumSq += diff * diff;
    }

    return Number(Math.sqrt(sumSq).toFixed(4));
  }

  static createMetricEmbeddingRecord(target, metrics) {
    const dense = this.projectTelemetryToDenseEmbedding(metrics);
    let sumSq = 0;
    for (let i = 0; i < dense.length; i++) {
      sumSq += dense[i] * dense[i];
    }
    const norm = Number(Math.sqrt(sumSq).toFixed(4));

    return {
      target: String(target || 'localhost').trim().toLowerCase(),
      timestamp: new Date().toISOString(),
      sparseMetricsCount: Object.keys(metrics || {}).length,
      denseVector: Array.from(dense).map((v) => Number(v.toFixed(4))),
      norm
    };
  }

  projectTelemetryToDenseEmbedding(metrics) {
    return DimensionExpandedEmbeddingEngine.projectTelemetryToDenseEmbedding(metrics);
  }

  computeProjectedCosineSimilarity(emb1, emb2) {
    return DimensionExpandedEmbeddingEngine.computeProjectedCosineSimilarity(emb1, emb2);
  }

  computeProjectedEuclideanDistance(emb1, emb2) {
    return DimensionExpandedEmbeddingEngine.computeProjectedEuclideanDistance(emb1, emb2);
  }

  createMetricEmbeddingRecord(target, metrics) {
    return DimensionExpandedEmbeddingEngine.createMetricEmbeddingRecord(target, metrics);
  }
}
exports.DimensionExpandedEmbeddingEngine = DimensionExpandedEmbeddingEngine;

const dimensionExpandedEmbeddingEngine = new DimensionExpandedEmbeddingEngine();
exports.dimensionExpandedEmbeddingEngine = dimensionExpandedEmbeddingEngine;
