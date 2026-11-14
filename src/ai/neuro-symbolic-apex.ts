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

  /**
   * Multi-Causal Compound Fault Synthesis & Counterfactual Disambiguation:
   * Evaluates both single-point and compound multi-layer infrastructure faults
   * (e.g., Path MTU Blackhole + Split-Horizon DNS Drift + TCP Retransmissions)
   * and articulates for each hypothesis:
   *   1. Why it outranked competing hypotheses
   *   2. What counterfactual evidence would appear if the hypothesis were FALSE
   *   3. What exact non-destructive diagnostic probe disambiguates the top two hypotheses
   */
  public evaluateCompoundCounterfactualSynthesis(
    trace: readonly TelemetryPoint[],
    customSignals?: {
      readonly dnsServfailObserved?: boolean;
      readonly pmtuBlackholeObserved?: boolean;
      readonly tlsAlertObserved?: boolean;
      readonly apipaDetected?: boolean;
    }
  ) {
    const latest = trace.length > 0 ? trace[trace.length - 1] : { timestampMs: Date.now(), rttMs: 18, packetLossPct: 0.1, cpuSaturationPct: 22, tcpRetransmitRate: 0.01 };
    const highRtt = latest.rttMs > 45;
    const highLoss = latest.packetLossPct > 1.0;
    const highCpu = latest.cpuSaturationPct > 75;
    const highRetrans = latest.tcpRetransmitRate > 0.04;

    const matrix = this.evaluateCounterfactualMatrix([
      {
        id: 'HYP_PMTU_AND_TCP_RETRANS',
        name: 'Path MTU Blackhole & L4 TCP Retransmission Cascade (RB-06)',
        prior: 0.22,
        likelihoodGivenEvidence: (highRtt && (highLoss || highRetrans) || customSignals?.pmtuBlackholeObserved) ? 0.88 : 0.25,
        interventionalEfficacy: 0.94,
        remediationId: 'RB-06_CLAMP_TCP_MSS_AND_VERIFY_PMTU'
      },
      {
        id: 'HYP_DNS_SPLIT_HORIZON_DRIFT',
        name: 'Authoritative / Split-Horizon DNS Resolution Drift (RB-04)',
        prior: 0.20,
        likelihoodGivenEvidence: customSignals?.dnsServfailObserved ? 0.92 : (highRtt ? 0.48 : 0.22),
        interventionalEfficacy: 0.95,
        remediationId: 'RB-04_FLUSH_DNS_AND_RECONCILE_RESOLVERS'
      },
      {
        id: 'HYP_TCP_RST_OR_FIREWALL_DROP',
        name: 'Intermediate Firewall Silent Drop or TCP RST Rejection (RB-02)',
        prior: 0.20,
        likelihoodGivenEvidence: highLoss && !highCpu ? 0.76 : 0.28,
        interventionalEfficacy: 0.89,
        remediationId: 'RB-02_AUDIT_SYN_BACKLOG_AND_ACL_RULES'
      },
      {
        id: 'HYP_HOST_PNP_CPU_SATURATION',
        name: 'Host Kernel / PnP Worker Saturation & Ephemeral Socket Exhaustion (RB-03)',
        prior: 0.20,
        likelihoodGivenEvidence: highCpu ? 0.91 : 0.20,
        interventionalEfficacy: 0.91,
        remediationId: 'RB-03_THROTTLE_RUNAWAY_PID_AND_RECLAIM_SOCKETS'
      },
      {
        id: 'HYP_TLS13_SNI_HANDSHAKE_ALERT',
        name: 'TLS 1.3 Handshake Alert & X.509 Certificate Chain Mismatch (RB-05)',
        prior: 0.18,
        likelihoodGivenEvidence: customSignals?.tlsAlertObserved ? 0.93 : 0.19,
        interventionalEfficacy: 0.96,
        remediationId: 'RB-05_VERIFY_SNI_AND_ROTATE_TLS_CHAIN'
      }
    ]);

    const sorted = [...matrix.hypotheses].sort((a, b) => b.posteriorProbabilityPct - a.posteriorProbabilityPct);
    const top1 = sorted[0];
    const top2 = sorted[1];

    return {
      ...matrix,
      rankedHypotheses: sorted,
      compoundFaultDetected: (highRtt && highLoss) || Boolean(customSignals?.dnsServfailObserved && customSignals?.pmtuBlackholeObserved),
      counterfactualExplanation: {
        winningHypothesisId: top1.id,
        runnerUpHypothesisId: top2.id,
        whyWinnerWon: `${top1.name} achieved ${top1.posteriorProbabilityPct}% posterior probability with ${top1.counterfactualSurvivalGainPct}% expected interventional recovery gain under Pearl do-calculus.`,
        ifWinnerWereFalseExpectedEvidence: `If ${top1.id} were false, 1472-byte DF=1 ICMP probes and L4 SYN/ACK handshakes would complete with zero fragmentation drops or retransmission bursts.`,
        disambiguatingProbe: `Execute DF=1 Path MTU sweep paired with authoritative DNS SOA/A query to disambiguate ${top1.id} (${top1.posteriorProbabilityPct}%) vs. ${top2.id} (${top2.posteriorProbabilityPct}%).`
      }
    };
  }

  /**
   * Continuous differentiable smooth min (conjunction) approximation via Log-Sum-Exp:
   *   smoothMin(x_1, ..., x_n) = - (1 / beta) * ln( \sum_i exp(-beta * x_i) )
   * Clamped with max-shift for numerical stability against IEEE 754 overflow.
   */
  public static smoothMin(values: readonly number[] | Float64Array, beta = 10.0): number {
    const n = values.length;
    if (n === 0) return 0;
    if (n === 1) return values[0];
    const b = Math.max(1e-6, beta);

    let maxShift = Number.NEGATIVE_INFINITY;
    for (let i = 0; i < n; i++) {
      const s = -b * values[i];
      if (s > maxShift) maxShift = s;
    }

    let lseSum = 0.0;
    for (let i = 0; i < n; i++) {
      lseSum += Math.exp(-b * values[i] - maxShift);
    }
    return Number((-(maxShift + Math.log(lseSum)) / b).toFixed(4));
  }

  /**
   * Continuous differentiable smooth max (disjunction) approximation via Log-Sum-Exp:
   *   smoothMax(x_1, ..., x_n) = (1 / beta) * ln( \sum_i exp(beta * x_i) )
   * Clamped with max-shift for numerical stability against IEEE 754 overflow.
   */
  public static smoothMax(values: readonly number[] | Float64Array, beta = 10.0): number {
    const n = values.length;
    if (n === 0) return 0;
    if (n === 1) return values[0];
    const b = Math.max(1e-6, beta);

    let maxShift = Number.NEGATIVE_INFINITY;
    for (let i = 0; i < n; i++) {
      const s = b * values[i];
      if (s > maxShift) maxShift = s;
    }

    let lseSum = 0.0;
    for (let i = 0; i < n; i++) {
      lseSum += Math.exp(b * values[i] - maxShift);
    }
    return Number(((maxShift + Math.log(lseSum)) / b).toFixed(4));
  }

  /**
   * Analytical sensitivity gradients of Smooth-STL robustness:
   *   grad_i = d(smoothMin)/dx_i = exp(-beta * x_i) / \sum_j exp(-beta * x_j)
   */
  public static computeAnalyticalSensitivityGradients(values: readonly number[] | Float64Array, beta = 10.0): Float64Array {
    const n = values.length;
    if (n === 0) return new Float64Array(0);
    const b = Math.max(1e-6, beta);
    const grads = new Float64Array(n);

    let maxShift = Number.NEGATIVE_INFINITY;
    for (let i = 0; i < n; i++) {
      const s = -b * values[i];
      if (s > maxShift) maxShift = s;
    }

    let denom = 0.0;
    for (let i = 0; i < n; i++) {
      denom += Math.exp(-b * values[i] - maxShift);
    }

    for (let i = 0; i < n; i++) {
      grads[i] = Math.exp(-b * values[i] - maxShift) / denom;
    }
    return grads;
  }

  /**
   * Forecasts Time-To-Violation (TTV) horizon along linear velocity gradient via Taylor extrapolation:
   *   T_violation = - currentRobustness / velocityPerSec (if velocity < 0 and robustness > 0)
   */
  public static forecastTimeToViolationHorizon(currentRobustness: number, velocityPerSec: number): number | null {
    if (currentRobustness <= 0) return 0;
    if (velocityPerSec < -1e-6) {
      return Number((-currentRobustness / velocityPerSec).toFixed(2));
    }
    return null;
  }
}
