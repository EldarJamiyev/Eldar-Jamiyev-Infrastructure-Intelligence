// src/ai/neuro-symbolic-apex.ts
import * as crypto from 'node:crypto';

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
  readonly estimatedTimeToViolationSec: number | null; // null if stable/improving
  readonly metricSensitivityGradient: Record<string, number>;
}

export interface CounterfactualHypothesis {
  readonly id: string;
  readonly name: string;
  readonly priorProbability: number;
  readonly posteriorProbabilityPct: number; // Exact Hare-Niemeyer 100.0% sum
  readonly counterfactualSurvivalGainPct: number;
  readonly recommendedRemediationId: string;
}

export class NeuroSymbolicApexEngine {
  private readonly smoothingBeta: number;

  constructor(smoothingBeta = 12.0) {
    if (smoothingBeta <= 0 || !Number.isFinite(smoothingBeta)) {
      throw new Error('STL smoothing parameter beta must be finite and positive.');
    }
    this.smoothingBeta = smoothingBeta;
  }

  /**
   * Computes both classical Hard STL Robustness rho(phi, x, t) and
   * Smooth Differentiable STL Robustness with analytical gradient attribution
   * and deterministic Time-to-Violation (TTV) horizon forecasting.
   */
  public evaluateTemporallyBoundedAlways(
    formulaId: string,
    predicates: readonly STLAtomicPredicate[],
    trace: readonly TelemetryPoint[]
  ): STLApexEvaluation {
    if (trace.length === 0 || predicates.length === 0) {
      return {
        formulaId,
        hardRobustness: 0,
        smoothRobustness: 0,
        satisfied: true,
        velocityPerSec: 0,
        estimatedTimeToViolationSec: null,
        metricSensitivityGradient: {},
      };
    }

    const n = trace.length;
    const m = predicates.length;
    const stepRobustness = new Float64Array(n);
    const predicateMargins = new Float64Array(m);
    const gradientAccum = new Float64Array(m);

    // Per-predicate trajectory tracking to compute un-mixed, physically grounded TTVs
    const perPredTrajectories: Float64Array[] = Array.from({ length: m }, () => new Float64Array(n));

    let globalHardMin = Number.POSITIVE_INFINITY;

    // Evaluate atomic margins mu(x(t)) = w * (threshold - x(t)) for LTE, or w * (x(t) - threshold) for GTE
    for (let t = 0; t < n; t++) {
      const sample = trace[t];
      let stepMin = Number.POSITIVE_INFINITY;

      for (let p = 0; p < m; p++) {
        const pred = predicates[p];
        const val = sample[pred.metric];
        const rawMargin = pred.operator === 'LTE'
          ? pred.threshold - val
          : val - pred.threshold;
        const margin = rawMargin * pred.weight;
        predicateMargins[p] = margin;
        perPredTrajectories[p][t] = margin;
        if (margin < stepMin) stepMin = margin;
      }

      stepRobustness[t] = stepMin;
      if (stepMin < globalHardMin) globalHardMin = stepMin;

      // Softmin gradient attribution across predicates at time t:
      // d/dx_p [-1/beta * ln(sum exp(-beta * margin_p))] = exp(-beta * margin_p) / sum_k exp(-beta * margin_k)
      let maxNegBeta = Number.NEGATIVE_INFINITY;
      for (let p = 0; p < m; p++) {
        const z = -this.smoothingBeta * predicateMargins[p];
        if (z > maxNegBeta) maxNegBeta = z;
      }
      let denom = 0.0;
      for (let p = 0; p < m; p++) {
        denom += Math.exp(-this.smoothingBeta * predicateMargins[p] - maxNegBeta);
      }
      for (let p = 0; p < m; p++) {
        const softWeight = Math.exp(-this.smoothingBeta * predicateMargins[p] - maxNegBeta) / denom;
        gradientAccum[p] += softWeight;
      }
    }

    // Smooth Always G_[t0, tn] operator using numerically stable Log-Sum-Exp
    let maxShift = Number.NEGATIVE_INFINITY;
    for (let t = 0; t < n; t++) {
      const s = -this.smoothingBeta * stepRobustness[t];
      if (s > maxShift) maxShift = s;
    }
    let lseSum = 0.0;
    for (let t = 0; t < n; t++) {
      lseSum += Math.exp(-this.smoothingBeta * stepRobustness[t] - maxShift);
    }
    const smoothRobustness = -(maxShift + Math.log(lseSum)) / this.smoothingBeta;

    // Normalize gradient attribution so sum of sensitivities = 1.0
    const metricSensitivityGradient: Record<string, number> = {};
    for (let p = 0; p < m; p++) {
      metricSensitivityGradient[predicates[p].id] = Number((gradientAccum[p] / n).toFixed(4));
    }

    // Per-predicate velocity & TTV analysis to prevent combining disparate metric units
    let minTtv: number | null = null;
    let criticalVelocity = this.computeRobustnessVelocityPerSec(trace, stepRobustness);

    for (let p = 0; p < m; p++) {
      const predTraj = perPredTrajectories[p];
      const pVelocity = this.computeRobustnessVelocityPerSec(trace, predTraj);
      const latestMargin = predTraj[n - 1];

      if (latestMargin <= 0) {
        minTtv = 0;
        criticalVelocity = pVelocity;
        break;
      } else if (pVelocity < -1e-6) {
        const ttv = Number((-latestMargin / pVelocity).toFixed(2));
        if (minTtv === null || ttv < minTtv) {
          minTtv = ttv;
          criticalVelocity = pVelocity;
        }
      }
    }

    return {
      formulaId,
      hardRobustness: Number(globalHardMin.toFixed(4)),
      smoothRobustness: Number(smoothRobustness.toFixed(4)),
      satisfied: globalHardMin >= 0,
      velocityPerSec: Number(criticalVelocity.toFixed(4)),
      estimatedTimeToViolationSec: minTtv,
      metricSensitivityGradient,
    };
  }

  /**
   * Exact OLS slope over (timestampMs, stepRobustness) in units of robustness/second.
   */
  private computeRobustnessVelocityPerSec(
    trace: readonly TelemetryPoint[],
    stepRobustness: Float64Array
  ): number {
    const n = trace.length;
    if (n < 2) return 0;

    const t0 = trace[0].timestampMs;
    let sumT = 0.0;
    let sumY = 0.0;
    let sumTT = 0.0;
    let sumTY = 0.0;

    for (let i = 0; i < n; i++) {
      const dtSec = (trace[i].timestampMs - t0) / 1000.0;
      const y = stepRobustness[i];
      sumT += dtSec;
      sumY += y;
      sumTT += dtSec * dtSec;
      sumTY += dtSec * y;
    }

    const denom = n * sumTT - sumT * sumT;
    if (Math.abs(denom) < 1e-12) return 0;
    return (n * sumTY - sumT * sumY) / denom;
  }

  /**
   * Judea Pearl Level-3 Structural Causal Model (Abduction -> Action -> Prediction)
   * with Vectorized Float64Array Bayesian Updating, Shannon Entropy H(X),
   * and Exact 100.0% Hare-Niemeyer Largest Remainder Rounding.
   */
  public evaluateCounterfactualMatrix(
    hypotheses: readonly {
      id: string;
      name: string;
      prior: number;
      likelihoodGivenEvidence: number;
      interventionalEfficacy: number; // P(Recovery | do(Remediation), Hypothesis)
      remediationId: string;
    }[]
  ): {
    readonly hypotheses: CounterfactualHypothesis[];
    readonly shannonEntropyBits: number;
    readonly epistemicCertaintyRatio: number;
    readonly epistemicHash: string;
  } {
    const k = hypotheses.length;
    if (k === 0) {
      return {
        hypotheses: [],
        shannonEntropyBits: 0,
        epistemicCertaintyRatio: 1,
        epistemicHash: '',
      };
    }

    // Step 1 (Abduction): Update exogenous latent state U given observed evidence E: P(U | E)
    const unnormalizedPosteriors = new Float64Array(k);
    let marginalEvidence = 0.0;

    for (let i = 0; i < k; i++) {
      const h = hypotheses[i];
      const joint = Math.max(1e-12, h.prior) * Math.max(1e-12, h.likelihoodGivenEvidence);
      unnormalizedPosteriors[i] = joint;
      marginalEvidence += joint;
    }

    const exactPosteriors = new Float64Array(k);
    for (let i = 0; i < k; i++) {
      exactPosteriors[i] = unnormalizedPosteriors[i] / marginalEvidence;
    }

    // Information-Theoretic Shannon Entropy H(X) = -sum P(h_i) log2 P(h_i)
    let entropy = 0.0;
    for (let i = 0; i < k; i++) {
      const p = exactPosteriors[i];
      if (p > 1e-15) {
        entropy -= p * Math.log2(p);
      }
    }
    const maxEntropy = k > 1 ? Math.log2(k) : 1.0;
    const certaintyRatio = k > 1 ? Math.max(0, Math.min(1, 1.0 - entropy / maxEntropy)) : 1.0;

    // Exact 100.0% Hare-Niemeyer (Largest Remainder) Rounding to 0.1% precision (1000 tenths)
    const roundedPct = this.hareNiemeyerPercentageTenths(exactPosteriors);

    // Step 2 & 3 (Action & Prediction): Compute counterfactual survival gain under do(Remediation_i)
    const resultHypotheses: CounterfactualHypothesis[] = hypotheses.map((h, i) => {
      const cfGain = exactPosteriors[i] * h.interventionalEfficacy * 100.0;
      return {
        id: h.id,
        name: h.name,
        priorProbability: h.prior,
        posteriorProbabilityPct: roundedPct[i],
        counterfactualSurvivalGainPct: Number(cfGain.toFixed(2)),
        recommendedRemediationId: h.remediationId,
      };
    });

    const epistemicHash = crypto
      .createHash('sha256')
      .update(JSON.stringify({ resultHypotheses, entropy }))
      .digest('hex');

    return {
      hypotheses: resultHypotheses,
      shannonEntropyBits: Number(entropy.toFixed(4)),
      epistemicCertaintyRatio: Number(certaintyRatio.toFixed(4)),
      epistemicHash,
    };
  }

  /**
   * Guarantees that the rounded percentage array sums to EXACTLY 100.0%
   * using the Hare-Niemeyer Largest Remainder method at 0.1% (1000-unit) resolution.
   */
  public hareNiemeyerPercentageTenths(probabilities: Float64Array): Float64Array {
    const n = probabilities.length;
    const quotas = new Float64Array(n);
    const integerParts = new Int32Array(n);
    const remainders = new Float64Array(n);

    let sumInteger = 0;
    for (let i = 0; i < n; i++) {
      const q = probabilities[i] * 1000.0;
      quotas[i] = q;
      const fl = Math.floor(q);
      integerParts[i] = fl;
      remainders[i] = q - fl;
      sumInteger += fl;
    }

    let deficit = 1000 - sumInteger;
    const indices = Array.from({ length: n }, (_, idx) => idx);
    indices.sort((a, b) => {
      const diff = remainders[b] - remainders[a];
      return Math.abs(diff) > 1e-12 ? diff : a - b; // Deterministic index tie-break
    });

    for (let i = 0; i < deficit && i < n; i++) {
      integerParts[indices[i]] += 1;
    }

    const result = new Float64Array(n);
    for (let i = 0; i < n; i++) {
      result[i] = Number((integerParts[i] / 10.0).toFixed(1));
    }
    return result;
  }
}
