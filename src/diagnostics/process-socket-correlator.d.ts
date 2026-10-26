/**
 * User-Space Process-to-Socket Behavioral Matrix & Ephemeral Port Exhaustion Predictor
 * 100% Unprivileged, Zero-Simulation Physical OS Diagnostic Engine.
 * Supports:
 *  - Netstat/SS & Process table live attribution (Windows & Linux)
 *  - RFC 6056 Ephemeral Port Exhaustion Telemetry (49152..65535, 16384 total)
 *  - C2 Beaconing Periodicity Detection via Coefficient of Variation (CV = sigma / mu)
 */
export interface SocketEntry {
    readonly protocol: 'TCP' | 'UDP';
    readonly localAddress: string;
    readonly localPort: number;
    readonly remoteAddress: string;
    readonly remotePort: number;
    readonly state: string;
    readonly pid: number;
}
export interface ProcessEntry {
    readonly pid: number;
    readonly name: string;
    readonly memoryMb?: number;
}
export interface ProcessBeaconingMetrics {
    readonly sampleCount: number;
    readonly meanIntervalMs: number;
    readonly stdDevIntervalMs: number;
    readonly coefficientOfVariation: number;
    readonly periodicityScore: number;
    readonly beaconingSuspected: boolean;
}
export interface ProcessSocketAttribution {
    readonly pid: number;
    readonly processName: string;
    readonly memoryMb: number;
    readonly totalSockets: number;
    readonly establishedSockets: number;
    readonly timeWaitSockets: number;
    readonly listeningSockets: number;
    readonly ephemeralPortsUsed: number;
    readonly uniqueRemoteIps: readonly string[];
    readonly beaconingMetrics: ProcessBeaconingMetrics;
}
export interface EphemeralPortExhaustionTelemetry {
    readonly totalDynamicRange: number;
    readonly activeEphemeralCount: number;
    readonly saturationPct: number;
    readonly timeWaitRatio: number;
    readonly establishedRatio: number;
    readonly estimatedSecondsToPortExhaustion: number | null;
    readonly status: 'NOMINAL' | 'WARNING' | 'CRITICAL_EXHAUSTION_IMMINENT';
}
export interface ProcessSocketMatrixReport {
    readonly ephemeralTelemetry: EphemeralPortExhaustionTelemetry;
    readonly processes: readonly ProcessSocketAttribution[];
    readonly totalSockets: number;
    readonly timestampIso: string;
}
export declare class ProcessSocketCorrelatorEngine {
    static readonly EPHEMERAL_MIN = 49152;
    static readonly EPHEMERAL_MAX = 65535;
    static readonly EPHEMERAL_TOTAL = 16384;
    /**
     * Computes the Coefficient of Variation CV = sigma / mu across inter-connection timestamps.
     * Periodicity score: 1.0 - min(1.0, CV). CV < 0.15 with >= 4 samples triggers beaconingSuspected.
     */
    static computeBeaconingMetrics(timestampsMs: readonly number[]): ProcessBeaconingMetrics;
    /**
     * Alias for collecting and analyzing live host socket matrix.
     */
    static runLiveExtractionAndAnalysis(): ProcessSocketMatrixReport;
    /**
     * Core pure analysis function: correlates sockets, processes, and historical beaconing.
     */
    static analyzeSocketProcessMatrix(sockets: readonly SocketEntry[], processes: readonly ProcessEntry[], historicalTimestampsByPid?: Record<number, readonly number[]>, burnRatePerSec?: number): ProcessSocketMatrixReport;
    /**
     * Live Unprivileged Host Collector: netstat -ano + tasklist (Windows) or ss/netstat + ps (Linux)
     */
    static collectLiveHostSocketMatrix(): ProcessSocketMatrixReport;
}
