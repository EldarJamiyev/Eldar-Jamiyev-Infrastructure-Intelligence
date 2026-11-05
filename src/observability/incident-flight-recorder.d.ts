/**
 * Black-Box Incident Flight Recorder & Cryptographically Signed Post-Mortem Dossier Generator
 * 100% Zero-Simulation Multi-Pillar Cohesion Engine.
 * Supports:
 *  - Unified 5-Pillar Live Snapshot Capture
 *  - Executive Post-Mortem Markdown Dossier Synthesis
 *  - HMAC-SHA256 Cryptographic Signature & Tamper Verification
 */
export interface IncidentFlightSnapshot {
    readonly incidentId: string;
    readonly timestampIso: string;
    readonly topologySpectral: {
        readonly lambda2: number;
        readonly partitionRisk: string;
        readonly criticalCutCount: number;
        readonly routingAnomaliesCount: number;
    };
    readonly wireDissection: {
        readonly recentPacketsCaptured: number;
        readonly tlsJa4Sample: string | null;
        readonly dnsEntropyMax: number;
        readonly dgaSuspected: boolean;
    };
    readonly hostSocketMatrix: {
        readonly cpuLoadPct: number;
        readonly memoryUsedPct: number;
        readonly ephemeralSaturationPct: number;
        readonly topProcessName: string;
    };
    readonly aiCusumForensics: {
        readonly smoothRobustnessRho: number;
        readonly estimatedTtvSec: number | null;
        readonly primaryTemporalDriver: string | null;
        readonly topHypothesis: string;
        readonly confidencePct: number;
    };
    readonly dsrlLyapunovAudit: {
        readonly lastRemediationVerdict: string;
        readonly lyapunovDeltaEnergy: number;
        readonly merkleRootHex: string;
    };
}
export interface FlightRecorderDossier {
    readonly dossierVersion: '3.0.0-sovereign-enterprise';
    readonly incidentId: string;
    readonly generatedAt: string;
    readonly snapshot: IncidentFlightSnapshot;
    readonly executiveMarkdown: string;
    readonly snapshotSha256: string;
    readonly dossierSignatureHmac: string;
}
export declare class IncidentFlightRecorder {
    private readonly hmacSecret;
    constructor(secretKey?: string);
    /**
     * Assembles the 5-pillar unified flight snapshot.
     */
    assembleFlightSnapshot(overrides?: Partial<IncidentFlightSnapshot>): IncidentFlightSnapshot;
    /**
     * Renders the richly formatted Executive Post-Mortem Markdown Dossier.
     */
    generateMarkdownDossier(snapshot: IncidentFlightSnapshot): string;
    /**
     * Alias for signing and creating an Incident Flight Recorder Dossier.
     */
    signDossier(snapshotOrOverrides?: Partial<IncidentFlightSnapshot>): FlightRecorderDossier;
    /**
     * Creates a cryptographically signed Incident Flight Recorder Dossier.
     */
    createSignedDossier(overrides?: Partial<IncidentFlightSnapshot>): FlightRecorderDossier;
    /**
     * Verifies the HMAC-SHA256 signature of a FlightRecorderDossier.
     */
    verifyDossierSignature(dossier: FlightRecorderDossier): boolean;
}
