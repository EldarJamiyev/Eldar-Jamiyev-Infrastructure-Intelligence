/**
 * EJII — Eldar Jamiyev's Infrastructure Intelligence
 * Holt-Winters Damped Linear Multi-Horizon SLA Forecaster & Confidence Engine
 *
 * Implements Holt's Damped Linear Exponential Smoothing with 95% prediction intervals
 * and SLA breach risk probabilities across +1m, +5m, and +15m horizons.
 *
 * Zero-Simulation Mandate: Pure Float64Array mathematical smoothing over genuine host metrics.
 */
export interface MetricForecastPoint {
    horizonMin: number;
    stepH: number;
    predictedValue: number;
    lowerBound95: number;
    upperBound95: number;
    stdError: number;
    slaBreachRiskPct: number;
}
export interface MetricSlaTrajectory {
    metricKey: string;
    metricLabel: string;
    unit: string;
    currentValue: number;
    slaThreshold: number;
    slaComparator: 'MAX' | 'MIN';
    level: number;
    trend: number;
    residualSigma: number;
    status: 'NOMINAL' | 'WARNING' | 'CRITICAL';
    history: number[];
    forecasts: {
        plus1m: MetricForecastPoint;
        plus5m: MetricForecastPoint;
        plus15m: MetricForecastPoint;
    };
    sparklineSvg: string;
}
export interface FullSlaForecastReport {
    timestamp: string;
    metrics: {
        cpuLoadPct: MetricSlaTrajectory;
        memoryUsedPct: MetricSlaTrajectory;
        gatewayRttMs: MetricSlaTrajectory;
        stlRobustnessRho: MetricSlaTrajectory;
    };
    overallSlaRiskPct: number;
    executiveSummary: string;
}
export declare class HoltWintersForecaster {
    private alpha;
    private beta;
    private phi;
    constructor(alpha?: number, beta?: number, phi?: number);
    /**
     * Standard normal cumulative distribution function (Abramowitz & Stegun approximation)
     */
    static stdNormCdf(z: number): number;
    /**
     * Forecasts a time series using Holt's Damped Linear Exponential Smoothing
     */
    forecastSeries(rawHistory: number[], metricKey: string, metricLabel: string, unit: string, slaThreshold: number, slaComparator?: 'MAX' | 'MIN'): MetricSlaTrajectory;
    /**
     * Generates a clean, compact inline SVG sparkline with 95% confidence bounds
     */
    generateInlineSparkline(history: number[], forecasts: {
        plus1m: MetricForecastPoint;
        plus5m: MetricForecastPoint;
        plus15m: MetricForecastPoint;
    }): string;
    /**
     * Run multi-metric SLA forecasts for the host
     */
    generateFullReport(cpuHistory: number[], memHistory: number[], rttHistory: number[], stlHistory: number[]): FullSlaForecastReport;
    /**
     * Computes Self-Tuning Adaptive Holt-Winters Forecasts and High-Precision
     * Time-to-Criticality (TTC) across Bandwidth, Latency Budget, TCP Socket Pool,
     * CPU/Memory Saturation, and Disk Health.
     */
    generateAdaptiveTtcForecasts(inputs?: {
        cpuHistory?: number[];
        memHistory?: number[];
        rttHistory?: number[];
        bandwidthMbpsHistory?: number[];
        tcpSocketsHistory?: number[];
        diskUsedPctHistory?: number[];
    }): {
        timestamp: string;
        resources: {
            key: string;
            label: string;
            ttcMinutes: number | null;
            breachRiskPct: number;
            runbookId: string;
            trajectory: MetricSlaTrajectory;
        }[];
        shortestTtcMinutes: number | null;
    };
}
