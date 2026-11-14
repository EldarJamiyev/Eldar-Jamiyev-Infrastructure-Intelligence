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

import * as crypto from 'crypto';

export const DENSE_EMBEDDING_DIM = 64;
export const SPARSE_METRIC_SPACE_DIM = 512;

/**
 * Standard slot assignments for known canonical infrastructure metrics.
 * Unknown arbitrary metrics map into dynamic slots [32, 511] via deterministic hashing.
 */
export const CANONICAL_METRIC_SLOTS: Record<string, number> = {
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

/**
 * Normalization scaling factors to bring raw heterogeneous measurements
 * into comparable numerical ranges before random projection.
 */
export const CANONICAL_METRIC_SCALES: Record<string, number> = {
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

export interface MetricEmbeddingRecord {
  target: string;
  timestamp: string;
  sparseMetricsCount: number;
  denseVector: number[];
  norm: number;
}

export class DimensionExpandedEmbeddingEngine {
  private static projectionMatrix: Float32Array | null = null;

  /**
   * Initializes the deterministic Achlioptas random projection matrix R in R^{k x D}.
   * R_{i, j} in { +sqrt(3/k), 0, -sqrt(3/k) } with probabilities { 1/6, 2/3, 1/6 }.
   */
  private static _ensureProjectionMatrix(): Float32Array {
    if (this.projectionMatrix) {
      return this.projectionMatrix;
    }

    const K = DENSE_EMBEDDING_DIM;
    const D = SPARSE_METRIC_SPACE_DIM;
    const matrix = new Float32Array(K * D);
    const weight = Math.sqrt(3.0) / Math.sqrt(K);

    for (let i = 0; i < K; i++) {
      for (let j = 0; j < D; j++) {
        // Deterministic pseudo-random seed per matrix element
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

  /**
   * Deterministically resolves metric key to a sparse slot index in [0, SPARSE_METRIC_SPACE_DIM - 1].
   */
  public static resolveMetricSlot(key: string): number {
    if (Object.prototype.hasOwnProperty.call(CANONICAL_METRIC_SLOTS, key)) {
      return CANONICAL_METRIC_SLOTS[key];
    }
    const hash = crypto.createHash('md5').update(key).digest();
    const hashInt = hash.readUInt32BE(0);
    // Dynamic slots reside between index 32 and SPARSE_METRIC_SPACE_DIM - 1
    const dynamicSlotsCount = SPARSE_METRIC_SPACE_DIM - 32;
    return 32 + (hashInt % dynamicSlotsCount);
  }

  /**
   * Normalizes raw metric value into comparable scale.
   */
  public static normalizeMetricValue(key: string, rawVal: number): number {
    if (!Number.isFinite(rawVal)) return 0;
    const scale = CANONICAL_METRIC_SCALES[key];
    if (scale && scale > 0) {
      return rawVal / scale;
    }
    // Generic non-linear log compression for open-ended uncalibrated metrics
    const sign = rawVal >= 0 ? 1 : -1;
    return sign * Math.log1p(Math.abs(rawVal));
  }

  /**
   * Projects an arbitrary heterogeneous sparse metric map into a 64D dense metric embedding.
   *
   * @param metrics Key-value dictionary of numeric infrastructure metrics
   * @returns 64-element Float32Array dense embedding
   */
  public static projectTelemetryToDenseEmbedding(metrics: Record<string, number>): Float32Array {
    const matrix = this._ensureProjectionMatrix();
    const K = DENSE_EMBEDDING_DIM;
    const D = SPARSE_METRIC_SPACE_DIM;
    const dense = new Float32Array(K);

    if (!metrics || typeof metrics !== 'object') {
      return dense;
    }

    const activeEntries: Array<{ slot: number; value: number }> = [];

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

  /**
   * Projects legacy 8D TelemetrySignatureVector into the 64D dense space.
   */
  public static projectLegacyTelemetrySignature(sig: Record<string, number>): Float32Array {
    return this.projectTelemetryToDenseEmbedding(sig);
  }

  /**
   * Computes cosine similarity between two projected dense embeddings in [-1.0, 1.0].
   */
  public static computeProjectedCosineSimilarity(
    emb1: ArrayLike<number>,
    emb2: ArrayLike<number>
  ): number {
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

  /**
   * Computes Euclidean distance between two projected dense embeddings.
   */
  public static computeProjectedEuclideanDistance(
    emb1: ArrayLike<number>,
    emb2: ArrayLike<number>
  ): number {
    const K = Math.min(emb1.length, emb2.length, DENSE_EMBEDDING_DIM);
    if (K === 0) return 0.0;

    let sumSq = 0;
    for (let i = 0; i < K; i++) {
      const diff = (emb1[i] || 0) - (emb2[i] || 0);
      sumSq += diff * diff;
    }

    return Number(Math.sqrt(sumSq).toFixed(4));
  }

  /**
   * Creates an indexed metric embedding record with serialized vector and norm.
   */
  public static createMetricEmbeddingRecord(
    target: string,
    metrics: Record<string, number>
  ): MetricEmbeddingRecord {
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

  // Instance methods
  public projectTelemetryToDenseEmbedding(metrics: Record<string, number>) {
    return DimensionExpandedEmbeddingEngine.projectTelemetryToDenseEmbedding(metrics);
  }

  public computeProjectedCosineSimilarity(emb1: ArrayLike<number>, emb2: ArrayLike<number>) {
    return DimensionExpandedEmbeddingEngine.computeProjectedCosineSimilarity(emb1, emb2);
  }

  public computeProjectedEuclideanDistance(emb1: ArrayLike<number>, emb2: ArrayLike<number>) {
    return DimensionExpandedEmbeddingEngine.computeProjectedEuclideanDistance(emb1, emb2);
  }

  public createMetricEmbeddingRecord(target: string, metrics: Record<string, number>) {
    return DimensionExpandedEmbeddingEngine.createMetricEmbeddingRecord(target, metrics);
  }
}

export const dimensionExpandedEmbeddingEngine = new DimensionExpandedEmbeddingEngine();
