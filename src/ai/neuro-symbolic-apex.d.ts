export interface TelemetryPoint {
    readonly timestampMs: number;
    readonly rttMs: number;
    readonly packetLossPct: number;
    readonly cpuSaturationPct: number;
    readonly tcpRetransmitRate: number;
}
export interface STLAtomicPredicate {
    readonly id: string;
    readonly metric: keyof Omit<TelemetryPoint, 'timestampMs'>;
    readonly operator: 'LTE' | 'GTE';
    readonly threshold: number;
    readonly weight: number;
}
export interface STLApexEvaluation {
    readonly formulaId: string;
    readonly hardRobustness: number;
    readonly smoothRobustness: number;
    readonly satisfied: boolean;
    readonly velocityPerSec: number;
    readonly estimatedTimeToViolationSec: number | null;
    readonly metricSensitivityGradient: Record<string, number>;
}
export interface CounterfactualHypothesis {
    readonly id: string;
    readonly name: string;
    readonly priorProbability: number;
    readonly posteriorProbabilityPct: number;
    readonly counterfactualSurvivalGainPct: number;
    readonly recommendedRemediationId: string;
}
export declare class NeuroSymbolicApexEngine {
    private readonly smoothingBeta;
    constructor(smoothingBeta?: number);
    /**
     * Computes both classical Hard STL Robustness rho(phi, x, t) and
     * Smooth Differentiable STL Robustness with analytical gradient attribution
     * and deterministic Time-to-Violation (TTV) horizon forecasting.
     */
    evaluateTemporallyBoundedAlways(formulaId: string, predicates: readonly STLAtomicPredicate[], trace: readonly TelemetryPoint[]): STLApexEvaluation;
    /**
     * Exact OLS slope over (timestampMs, stepRobustness) in units of robustness/second.
     */
    private computeRobustnessVelocityPerSec;
    /**
     * Judea Pearl Level-3 Structural Causal Model (Abduction -> Action -> Prediction)
     * with Vectorized Float64Array Bayesian Updating, Shannon Entropy H(X),
     * and Exact 100.0% Hare-Niemeyer Largest Remainder Rounding.
     */
    evaluateCounterfactualMatrix(hypotheses: readonly {
        id: string;
        name: string;
        prior: number;
        likelihoodGivenEvidence: number;
        interventionalEfficacy: number;
        remediationId: string;
    }[]): {
        readonly hypotheses: CounterfactualHypothesis[];
        readonly shannonEntropyBits: number;
        readonly epistemicCertaintyRatio: number;
        readonly epistemicHash: string;
    };
    /**
     * Guarantees that the rounded percentage array sums to EXACTLY 100.0%
     * using the Hare-Niemeyer Largest Remainder method at 0.1% (1000-unit) resolution.
     */
    hareNiemeyerPercentageTenths(probabilities: Float64Array): Float64Array;
}
