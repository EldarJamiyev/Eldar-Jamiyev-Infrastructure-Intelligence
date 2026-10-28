import { TelemetrySeriesPoint } from './cusum-changepoint-engine';
import { SpectralAnalysisResult } from './spectral-fourier-detector';
import { TopologyNode, TopologyEdge } from '../topology/spectral-gnn-apex';
import { ChaosSimulationResult } from '../topology/digital-twin-chaos-simulator';
import { QosAuditReport } from '../topology/multipath-qos-auditor';
import { MetricSlaTrajectory } from './holt-winters-forecaster';
import { ZeroTrustPolicyBundle } from '../security/zero-trust-policy-synthesizer';
export interface WarRoomTelemetryPayload {
    readonly timeSeries?: readonly TelemetrySeriesPoint[];
    readonly rawMetricValues?: readonly number[];
    readonly topologyNodes?: readonly TopologyNode[];
    readonly topologyEdges?: readonly TopologyEdge[];
    readonly wireFrames?: readonly any[];
    readonly rootNodeId?: string;
    readonly operatorRole?: string;
}
export interface Agent1TriageReport {
    readonly agentName: 'Agent 1 — Temporal & Spectral Triage';
    readonly cusumDriver: string | null;
    readonly onsetTimestampMs: number | null;
    readonly spectralAnalysis: SpectralAnalysisResult;
    readonly verdict: string;
    readonly epistemicStatus?: 'OBSERVED_AND_DERIVED' | 'DEFAULT_BASELINE_INPUT';
    readonly supportingEvidenceIds?: readonly string[];
    readonly unresolvedQuestions?: readonly string[];
}
export interface Agent2TopologicalReport {
    readonly agentName: 'Agent 2 — Topological & Queuing Analyst';
    readonly lambda2: number;
    readonly bottleneckEdges: readonly string[];
    readonly chaosQueuing: ChaosSimulationResult;
    readonly verdict: string;
    readonly epistemicStatus?: 'SIMULATED_PROJECTION';
    readonly supportingEvidenceIds?: readonly string[];
}
export interface Agent3WireForensicsReport {
    readonly agentName: 'Agent 3 — Deep Wire Forensics';
    readonly qosAudit: QosAuditReport;
    readonly l7Observations: readonly string[];
    readonly verdict: string;
    readonly epistemicStatus?: 'WIRE_OBSERVATION' | 'DEFAULT_WIRE_SAMPLE';
    readonly supportingEvidenceIds?: readonly string[];
    readonly contradictingEvidenceIds?: readonly string[];
}
export interface Agent4CausalPlannerReport {
    readonly agentName: 'Agent 4 — Causal Counterfactual Planner';
    readonly smoothStlRobustness: number;
    readonly ttvHorizonSeconds: number;
    readonly holtWintersForecast: MetricSlaTrajectory;
    readonly proposedRemediationAction: string;
    readonly rejectedProposals?: readonly {
        readonly action: string;
        readonly reason: string;
    }[];
    readonly verdict: string;
    readonly epistemicStatus?: 'HYPOTHESIS_AND_COUNTERFACTUAL_PLAN';
}
export interface Agent5SafetySignoffReport {
    readonly agentName: 'Agent 5 — DSRL Lyapunov Safety & Zero-Trust Officer';
    readonly lyapunovBarrierCleared: boolean;
    readonly operatorRoleChecked?: string;
    readonly operatorPermitted?: boolean;
    readonly zeroTrustPolicy: ZeroTrustPolicyBundle;
    readonly hmacSignature: string;
    readonly proofChain: string;
    readonly verdict: string;
}
export interface WarRoomExecutionResult {
    readonly warRoomSessionId: string;
    readonly executedAt: string;
    readonly status: 'RESOLVED_REMEDIATION_SIGNED' | 'INCIDENT_ESCALATED' | 'STABILIZED_MONITORING';
    readonly agent1: Agent1TriageReport;
    readonly agent2: Agent2TopologicalReport;
    readonly agent3: Agent3WireForensicsReport;
    readonly agent4: Agent4CausalPlannerReport;
    readonly agent5: Agent5SafetySignoffReport;
    readonly executiveSummary: string;
    readonly unresolvedUncertainties?: readonly string[];
    readonly contradictingSignals?: readonly string[];
}
export declare class AutonomousWarRoomOrchestrator {
    private readonly hmacSecret;
    private latestResult;
    constructor(secret?: string);
    getLatestResult(): WarRoomExecutionResult | null;
    /**
     * Executes the 5-Agent SRE War-Room Pipeline
     */
    execute(payload?: WarRoomTelemetryPayload): WarRoomExecutionResult;
}
