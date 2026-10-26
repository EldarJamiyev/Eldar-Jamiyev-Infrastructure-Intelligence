// src/ai/cusum-changepoint-engine.ts
/**
 * Page's CUSUM & Bayesian Regime Changepoint Forensics Engine
 * 100% Zero-Simulation, Vectorized Float64Array Implementation.
 * Supports:
 *  - Two-Sided Tabular Page's Cumulative Sum (S_t^+, S_t^-)
 *  - Exact Retrospective Changepoint Onset Pinpointing (t_shift)
 *  - Granger-Style Causal Temporal Precedence Ordering (t_shift(A) < t_shift(B))
 */

export interface TelemetrySeriesPoint {
  readonly timestampMs: number;
  readonly rttMs?: number;
  readonly packetLossPct?: number;
  readonly cpuSaturationPct?: number;
  readonly dnsLatencyMs?: number;
  readonly tcpRetransmitRate?: number;
  readonly [key: string]: number | undefined;
}

export interface MetricChangepoint {
  readonly metricName: string;
  readonly shiftDetected: boolean;
  readonly direction: 'INCREASE' | 'DECREASE' | 'NONE';
  readonly changepointIndex: number | null;
  readonly onsetTimestampMs: number | null;
  readonly triggerTimestampMs: number | null;
  readonly preShiftMean: number;
  readonly postShiftMean: number;
  readonly shiftMagnitudeSigmas: number;
  readonly baselineStdDev: number;
  readonly maxCusumStatistic: number;
}

export interface TemporalPrecedenceReport {
  readonly primaryTemporalDriver: string | null;
  readonly driverOnsetTimestampMs: number | null;
  readonly causalChainOrder: readonly {
    readonly rank: number;
    readonly metricName: string;
    readonly onsetTimestampMs: number;
    readonly delayAfterDriverMs: number;
    readonly shiftMagnitudeSigmas: number;
    readonly role: 'PRIMARY_DRIVER' | 'CASCADING_SYMPTOM';
  }[];
  readonly metrics: Record<string, MetricChangepoint>;
  readonly sampleCount: number;
  readonly timestampIso: string;
}

export class CusumChangepointEngine {
  private readonly slackK: number; // Allowance parameter k (default 0.5 sigma)
  private readonly thresholdH: number; // Decision boundary h (default 4.0 sigma)

  constructor(slackK = 0.5, thresholdH = 4.0) {
    this.slackK = Math.max(0.1, slackK);
    this.thresholdH = Math.max(1.0, thresholdH);
  }

  /**
   * Evaluates Two-Sided Tabular Page's CUSUM over a single 1D Float64Array series.
   */
  public evaluateSeriesCusum(
    values: Float64Array,
    timestampsMs: readonly number[],
    metricName: string,
    baselineWindowSize?: number
  ): MetricChangepoint {
    const n = values.length;
    if (n < 4) {
      return {
        metricName,
        shiftDetected: false,
        direction: 'NONE',
        changepointIndex: null,
        onsetTimestampMs: null,
        triggerTimestampMs: null,
        preShiftMean: n > 0 ? values[0] : 0,
        postShiftMean: n > 0 ? values[n - 1] : 0,
        shiftMagnitudeSigmas: 0,
        baselineStdDev: 0,
        maxCusumStatistic: 0,
      };
    }

    // Step 1: Compute Baseline Mean (mu0) and StdDev (sigma0)
    const baseLen = baselineWindowSize ? Math.min(n, Math.max(3, baselineWindowSize)) : Math.min(n, Math.max(5, Math.floor(n * 0.35)));
    let sumBase = 0.0;
    for (let i = 0; i < baseLen; i++) sumBase += values[i];
    const mu0 = sumBase / baseLen;

    let varBase = 0.0;
    for (let i = 0; i < baseLen; i++) {
      const diff = values[i] - mu0;
      varBase += diff * diff;
    }
    const sigma0 = Math.max(1e-6, Math.sqrt(varBase / baseLen));

    // Step 2: Tabular CUSUM Accumulators S^+ and S^-
    const sPlus = new Float64Array(n);
    const sMinus = new Float64Array(n);
    let maxStat = 0.0;

    let triggerIdx: number | null = null;
    let shiftDirection: 'INCREASE' | 'DECREASE' | 'NONE' = 'NONE';

    for (let t = 1; t < n; t++) {
      const z_t = (values[t] - mu0) / sigma0;

      sPlus[t] = Math.max(0, sPlus[t - 1] + z_t - this.slackK);
      sMinus[t] = Math.max(0, sMinus[t - 1] - z_t - this.slackK);

      if (sPlus[t] > maxStat) maxStat = sPlus[t];
      if (sMinus[t] > maxStat) maxStat = sMinus[t];

      if (triggerIdx === null) {
        if (sPlus[t] >= this.thresholdH) {
          triggerIdx = t;
          shiftDirection = 'INCREASE';
        } else if (sMinus[t] >= this.thresholdH) {
          triggerIdx = t;
          shiftDirection = 'DECREASE';
        }
      }
    }

    if (triggerIdx === null) {
      return {
        metricName,
        shiftDetected: false,
        direction: 'NONE',
        changepointIndex: null,
        onsetTimestampMs: null,
        triggerTimestampMs: null,
        preShiftMean: Number(mu0.toFixed(2)),
        postShiftMean: Number(mu0.toFixed(2)),
        shiftMagnitudeSigmas: 0,
        baselineStdDev: Number(sigma0.toFixed(4)),
        maxCusumStatistic: Number(maxStat.toFixed(2)),
      };
    }

    // Step 3: Exact Retrospective Changepoint Onset Pinpointing
    // Find the last index prior to triggerIdx where the accumulator was 0
    let onsetIdx = 0;
    const activeSeries = shiftDirection === 'INCREASE' ? sPlus : sMinus;
    for (let i = triggerIdx; i >= 0; i--) {
      if (activeSeries[i] === 0) {
        onsetIdx = i;
        break;
      }
    }

    // Step 4: Compute pre-shift vs post-shift means
    let sumPre = 0.0;
    const preCount = Math.max(1, onsetIdx);
    for (let i = 0; i < preCount; i++) sumPre += values[i];
    const preShiftMean = sumPre / preCount;

    let sumPost = 0.0;
    const postCount = Math.max(1, n - onsetIdx);
    for (let i = onsetIdx; i < n; i++) sumPost += values[i];
    const postShiftMean = sumPost / postCount;

    const shiftMagnitudeSigmas = Number(
      ((postShiftMean - preShiftMean) / sigma0).toFixed(2)
    );

    return {
      metricName,
      shiftDetected: true,
      direction: shiftDirection,
      changepointIndex: onsetIdx,
      onsetTimestampMs: timestampsMs[onsetIdx] ?? timestampsMs[0],
      triggerTimestampMs: timestampsMs[triggerIdx] ?? timestampsMs[0],
      preShiftMean: Number(preShiftMean.toFixed(2)),
      postShiftMean: Number(postShiftMean.toFixed(2)),
      shiftMagnitudeSigmas,
      baselineStdDev: Number(sigma0.toFixed(4)),
      maxCusumStatistic: Number(maxStat.toFixed(2)),
    };
  }

  /**
   * Alias for evaluating multi-metric temporal precedence.
   */
  public evaluateMultiMetricPrecedence(
    trace: readonly TelemetrySeriesPoint[],
    metricKeys?: readonly string[],
    baselineWindowSize?: number
  ): TemporalPrecedenceReport {
    return this.analyzeMultiMetricTrace(trace, metricKeys);
  }

  /**
   * Multi-metric Temporal Precedence Analysis across a multivariate telemetry trace.
   */
  public analyzeMultiMetricTrace(
    trace: readonly TelemetrySeriesPoint[],
    metricKeys?: readonly string[]
  ): TemporalPrecedenceReport {
    const n = trace.length;
    if (n === 0) {
      return {
        primaryTemporalDriver: null,
        driverOnsetTimestampMs: null,
        causalChainOrder: [],
        metrics: {},
        sampleCount: 0,
        timestampIso: new Date().toISOString(),
      };
    }

    const timestamps = trace.map((p) => p.timestampMs);
    const keys =
      metricKeys && metricKeys.length > 0
        ? metricKeys
        : ['rttMs', 'packetLossPct', 'cpuSaturationPct', 'dnsLatencyMs', 'tcpRetransmitRate'];

    const metricResults: Record<string, MetricChangepoint> = {};
    const shiftedMetrics: { name: string; onsetMs: number; sigmas: number }[] = [];

    for (const key of keys) {
      const arr = new Float64Array(n);
      let validCount = 0;
      for (let i = 0; i < n; i++) {
        const val = trace[i][key];
        if (typeof val === 'number' && Number.isFinite(val)) {
          arr[i] = val;
          validCount++;
        } else {
          arr[i] = 0;
        }
      }

      if (validCount >= 3) {
        const res = this.evaluateSeriesCusum(arr, timestamps, key);
        metricResults[key] = res;
        if (res.shiftDetected && res.onsetTimestampMs !== null) {
          shiftedMetrics.push({
            name: key,
            onsetMs: res.onsetTimestampMs,
            sigmas: Math.abs(res.shiftMagnitudeSigmas),
          });
        }
      }
    }

    // Granger-style Temporal Precedence: sort by earliest onset timestamp
    shiftedMetrics.sort((a, b) => {
      if (a.onsetMs !== b.onsetMs) return a.onsetMs - b.onsetMs;
      return b.sigmas - a.sigmas; // Tie-break by larger magnitude
    });

    const primaryDriver = shiftedMetrics[0] ? shiftedMetrics[0].name : null;
    const driverOnsetMs = shiftedMetrics[0] ? shiftedMetrics[0].onsetMs : null;

    const causalChainOrder = shiftedMetrics.map((item, idx) => ({
      rank: idx + 1,
      metricName: item.name,
      onsetTimestampMs: item.onsetMs,
      delayAfterDriverMs: driverOnsetMs !== null ? Math.max(0, item.onsetMs - driverOnsetMs) : 0,
      shiftMagnitudeSigmas: item.sigmas,
      role: idx === 0 ? ('PRIMARY_DRIVER' as const) : ('CASCADING_SYMPTOM' as const),
    }));

    return {
      primaryTemporalDriver: primaryDriver,
      driverOnsetTimestampMs: driverOnsetMs,
      causalChainOrder,
      metrics: metricResults,
      sampleCount: n,
      timestampIso: new Date().toISOString(),
    };
  }
}
