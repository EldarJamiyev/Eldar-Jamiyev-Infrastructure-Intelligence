/**
 * EJII Expected Value of Information (EVOI) Probe Optimizer
 *
 * Optimizes active diagnostic probes under high epistemic conflict or entropy
 * by ranking diagnostic actions according to expected information gain minus
 * probe execution cost (EVOI = H(H) - E[H(H|o)] - lambda * Cost(P)).
 * Dual-Maintenance TypeScript Reference.
 */

export interface DiagnosticProbeCandidate {
  probeId: string;
  targetDomain: 'CAUSAL_SEM' | 'TOPOLOGICAL_HOMOLOGY' | 'SPECTRAL_FOURIER' | 'WIRE_EBPF';
  description: string;
  cost: number; // Cost score, e.g. 0.05 to 1.0
  expectedEntropyReductionBits: number; // Estimated bits of uncertainty reduction
}

export interface RankedProbe {
  probeId: string;
  targetDomain: string;
  description: string;
  expectedEntropyReductionBits: number;
  cost: number;
  netEvoiScore: number;
  recommendationRank: number;
}

export interface EvoiOptimizationResult {
  optimizationId: string;
  priorEntropyBits: number;
  costWeightLambda: number;
  rankedProbes: RankedProbe[];
  recommendedProbe: RankedProbe | null;
  optimizationRationale: string;
}

export class EvoiProbeOptimizer {
  private totalOptimizations: number = 0;
  private topProbesSelected: number = 0;

  constructor() {}

  public computePriorEntropy(beliefDistribution: Record<string, number>): number {
    let entropy = 0;
    const values = Object.values(beliefDistribution || {});
    for (const p of values) {
      if (p > 1e-6) {
        entropy -= p * Math.log2(p);
      }
    }
    return Number(entropy.toFixed(4));
  }

  public optimizeDiagnosticProbes(
    priorBelief: Record<string, number>,
    availableProbes: DiagnosticProbeCandidate[],
    costWeight: number = 0.15
  ): EvoiOptimizationResult {
    this.totalOptimizations++;
    const optimizationId = `evoi_${Date.now()}_${Math.floor(Math.random() * 100000)}`;
    const priorEntropy = this.computePriorEntropy(priorBelief);
    const lambda = Math.max(0.01, Math.min(2.0, costWeight));

    if (!availableProbes || availableProbes.length === 0) {
      return {
        optimizationId,
        priorEntropyBits: priorEntropy,
        costWeightLambda: lambda,
        rankedProbes: [],
        recommendedProbe: null,
        optimizationRationale: 'No candidate diagnostic probes provided for evaluation.'
      };
    }

    // Calculate Net EVOI: Expected Information Gain - (lambda * Cost)
    const evaluated: RankedProbe[] = availableProbes.map((probe) => {
      const infoGain = Math.min(priorEntropy, Math.max(0, probe.expectedEntropyReductionBits));
      const penalty = lambda * Math.max(0.01, probe.cost);
      const netEvoi = Number((infoGain - penalty).toFixed(4));

      return {
        probeId: probe.probeId,
        targetDomain: probe.targetDomain,
        description: probe.description,
        expectedEntropyReductionBits: probe.expectedEntropyReductionBits,
        cost: probe.cost,
        netEvoiScore: netEvoi,
        recommendationRank: 0
      };
    });

    // Rank descending by Net EVOI Score
    evaluated.sort((a, b) => b.netEvoiScore - a.netEvoiScore);

    // Assign rank numbers
    evaluated.forEach((p, idx) => {
      p.recommendationRank = idx + 1;
    });

    const recommendedProbe = evaluated.length > 0 && evaluated[0].netEvoiScore > -0.5 ? evaluated[0] : null;
    if (recommendedProbe) {
      this.topProbesSelected++;
    }

    const rationale = recommendedProbe
      ? `Selected probe ${recommendedProbe.probeId} (${recommendedProbe.targetDomain}) with optimal net EVOI score ${recommendedProbe.netEvoiScore} (expected entropy reduction ${recommendedProbe.expectedEntropyReductionBits} bits, cost penalty ${Number((lambda * recommendedProbe.cost).toFixed(4))}).`
      : 'All candidate probes incur cost penalties exceeding expected information gain.';

    return {
      optimizationId,
      priorEntropyBits: priorEntropy,
      costWeightLambda: lambda,
      rankedProbes: evaluated,
      recommendedProbe,
      optimizationRationale: rationale
    };
  }

  public getMetrics(): { totalOptimizations: number; topProbesSelected: number } {
    return {
      totalOptimizations: this.totalOptimizations,
      topProbesSelected: this.topProbesSelected
    };
  }
}

export const evoiProbeOptimizer = new EvoiProbeOptimizer();
