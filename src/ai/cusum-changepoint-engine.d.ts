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
export declare class CusumChangepointEngine {
    private readonly slackK;
    private readonly thresholdH;
    constructor(slackK?: number, thresholdH?: number);
    /**
     * Evaluates Two-Sided Tabular Page's CUSUM over a single 1D Float64Array series.
     */
    evaluateSeriesCusum(values: Float64Array, timestampsMs: readonly number[], metricName: string, baselineWindowSize?: number): MetricChangepoint;
    /**
     * Alias for evaluating multi-metric temporal precedence.
     */
    evaluateMultiMetricPrecedence(trace: readonly TelemetrySeriesPoint[], metricKeys?: readonly string[], baselineWindowSize?: number): TemporalPrecedenceReport;
    /**
     * Multi-metric Temporal Precedence Analysis across a multivariate telemetry trace.
     */
    analyzeMultiMetricTrace(trace: readonly TelemetrySeriesPoint[], metricKeys?: readonly string[]): TemporalPrecedenceReport;
}
