/**
 * EJII Cognitive Singularity: Episodic Incident Memory, Experience Replay,
 * Multi-Hop Causal Graph Reasoning, Dynamic Emergent Hypothesis Synthesis,
 * and Closed-Loop Post-Action Bayesian Self-Calibration.
 */
export interface TelemetrySignatureVector {
    cusumShiftSigma: number;
    spectralFlatness: number;
    rttMs: number;
    packetLossPct: number;
    dnsLatencyMs: number;
    cpuSaturationPct: number;
    tcpRetransmitRate: number;
}
export interface EpisodicIncidentRecord {
    episodeId: string;
    recordedAt: string;
    target: string;
    signature: TelemetrySignatureVector;
    rootCauseDomain: string;
    emergentHypothesisId: string | null;
    operatorObservation?: string;
    executedRunbookId: string;
    preActionRttMs: number;
    postActionRttMs: number;
    resolved: boolean;
    lyapunovDelta: number;
    lessonsLearned: string;
}
export interface SimilarEpisodeMatch {
    episode: EpisodicIncidentRecord;
    cosineSimilarity: number;
    recommendedRunbookId: string;
    priorBoostDomain: string;
    priorBoostWeight: number;
}
export interface TopologyCausalNode {
    id: string;
    label?: string;
    role?: 'GATEWAY' | 'SWITCH' | 'DNS' | 'AD_DC' | 'SERVER' | 'PRINTER' | 'WORKSTATION' | string;
    ip?: string;
    latencyMs?: number;
    packetLossPct?: number;
    status?: string;
    upstreamId?: string | null;
}
export interface MultiHopCausalInferenceResult {
    upstreamRootCauseConfirmed: boolean;
    patientZeroNodeId: string;
    patientZeroRole: string;
    classification: 'UPSTREAM_INFRASTRUCTURE_ROOT_CAUSE' | 'LOCALIZED_ENDPOINT_FAULT' | 'COMPOUND_MULTI_HOP_CASCADE';
    sympatheticDownstreamNodeIds: string[];
    blastRadiusPath: string[];
    causalExplanation: string;
}
export interface EmergentHypothesis {
    hypothesisId: string;
    title: string;
    interactingDomains: string[];
    posteriorProbability: number;
    probabilityPct: number;
    isEmergentCompound: boolean;
    mathematicalDerivation: string;
    recommendedRunbookId: string;
}
export interface MathematicalCounterfactualReport {
    winningHypothesisId: string;
    runnerUpHypothesisId: string;
    numericalEvidenceDelta: {
        rttDeltaFromBaselineMs: number;
        lossDeltaPct: number;
        dnsDeltaMs: number;
        cusumSigma: number;
        spectralFlatness: number;
        posteriorMarginPct: number;
    };
    whyWinnerWon: string;
    ifHypothesisFalseExpectedEvidence: string;
    disambiguatingProbe: string;
    expectedInformationGainBits: number;
}
export interface ClosedLoopLearningOutcome {
    episodeId: string;
    target: string;
    executedActionId: string;
    improvementVerified: boolean;
    rttDeltaMs: number;
    lossDeltaPct: number;
    lyapunovEnergyBefore: number;
    lyapunovEnergyAfter: number;
    beliefShiftExplanation: string;
    pivotedToHypothesisId: string | null;
    updatedDomainPriors: Record<string, number>;
}
export interface MultiHopCascadeTrace {
    primaryRootCause: {
        nodeId: string;
        role: string;
        layer: 'L1_PHYSICAL' | 'L2_DATA_LINK' | 'L3_NETWORK' | 'L4_TRANSPORT' | 'L7_APPLICATION';
        confidencePct: number;
        description: string;
        matchedRunbookId: string;
        supportingEvidence: string[];
        decisiveVerificationProbe: {
            probeType: string;
            target: string;
            expectedOutcome: string;
            actionableCommand: string;
        };
    };
    cascadingSymptoms: Array<{
        nodeId: string;
        role: string;
        symptom: string;
        layer: string;
        isRootCause: boolean;
    }>;
    rankedAlternativeHypotheses: Array<{
        hypothesisId: string;
        title: string;
        probabilityPct: number;
        whyRejectedOrRankedLower: string;
    }>;
    counterfactualFalsification: {
        falsificationCondition: string;
        shannonEntropyBits: number;
    };
}
export interface CognitiveFusionResult {
    synthesisTimestamp: string;
    targetScope: string;
    primaryHypothesis: {
        id: string;
        title: string;
        confidenceScore: number;
        domain: string;
        matchedRunbook: string;
        summary: string;
        supportingMetrics: Record<string, any>;
    };
    multiHopCascade: MultiHopCascadeTrace;
    episodicPrecedents: SimilarEpisodeMatch[];
    slaProjection: {
        slaBreachRiskPct: number;
        timeToViolationSeconds: number;
        projectedMetric: string;
    };
    decisiveAction: {
        probeOrRemediation: string;
        command: string;
        requiresElevation: boolean;
        policyClassification: string;
    };
}
export declare class EpisodicCausalMemoryEngine {
    private static episodes;
    private static learnedDomainWeights;
    private static normalizeVector;
    static computeCosineSimilarity(a: TelemetrySignatureVector, b: TelemetrySignatureVector): number;
    static findSimilarEpisodes(liveSig: TelemetrySignatureVector, topK?: number): SimilarEpisodeMatch[];
    static getAllEpisodes(): EpisodicIncidentRecord[];
    static getLearnedDomainWeights(): Record<string, number>;
    /**
     * Multi-Hop Causal Graph Reasoning:
     * Distinguishes upstream root causes (Gateway, Core Switch, DNS Resolver, AD DC)
     * from downstream sympathetic symptoms on dependent workstations and printers.
     */
    static evaluateUpstreamVsDownstreamCausality(target: string, nodes?: TopologyCausalNode[]): MultiHopCausalInferenceResult;
    /**
     * Dynamic Emergent Hypothesis Synthesis:
     * Synthesizes novel multi-fault hypotheses when telemetry proves 2+ domains are interacting.
     */
    static synthesizeEmergentCompoundHypotheses(sig: TelemetrySignatureVector, operatorObservation?: string): EmergentHypothesis[];
    /**
     * Mathematically Derived Counterfactuals from Live Numerical Deltas
     */
    static computeLiveMathematicalCounterfactuals(winningId: string, winningTitle: string, winningPct: number, runnerUpId: string, runnerUpTitle: string, runnerUpPct: number, sig: TelemetrySignatureVector, baselineRttMs?: number): MathematicalCounterfactualReport;
    /**
     * Closed-Loop Post-Action Learning & Bayesian Self-Calibration:
     * Ingests the outcome of an executed Runbook or diagnostic probe, computes the
     * Lyapunov energy delta, updates domain weights, and pivots if the action failed.
     */
    static ingestActionOutcomeAndRecalibrate(params: {
        target: string;
        executedActionId: string;
        winningDomainId: string;
        runnerUpDomainId: string;
        preMetrics: {
            rttMs: number;
            packetLossPct: number;
            dnsLatencyMs?: number;
            cpuSaturationPct?: number;
        };
        postMetrics: {
            rttMs: number;
            packetLossPct: number;
            dnsLatencyMs?: number;
            cpuSaturationPct?: number;
        };
        operatorObservation?: string;
    }): ClosedLoopLearningOutcome;
    /**
     * Genuine Multi-Hop Causal Cascade Tracer:
     * Traces causal propagation across physical, link, transport, and application layers,
     * distinguishing root causes (e.g. MTU blackhole RB-06, Core Switch dropped frames)
     * from downstream symptoms (TLS 1.3 timeouts RB-05, AD replication stalls, application unreachability RB-01).
     */
    static traceMultiHopCascade(target: string, sig: TelemetrySignatureVector, nodes?: TopologyCausalNode[]): MultiHopCascadeTrace;
    /**
     * Unified Cognitive Fusion Pipeline:
     * Orchestrates CUSUM, Holt-Winters, Episodic Memory, and Multi-Hop Causal Deductions.
     */
    static executeCognitiveFusion(params: {
        target: string;
        signature: TelemetrySignatureVector;
        nodes?: TopologyCausalNode[];
        slaThresholdMs?: number;
    }): CognitiveFusionResult;
}
