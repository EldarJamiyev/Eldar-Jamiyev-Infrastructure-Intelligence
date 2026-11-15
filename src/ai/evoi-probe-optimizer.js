/**
 * EJII Expected Value of Information (EVOI) Probe Optimizer
 *
 * Optimizes active diagnostic probes under high epistemic conflict or entropy
 * by ranking diagnostic actions according to expected information gain minus
 * probe execution cost (EVOI = H(H) - E[H(H|o)] - lambda * Cost(P)).
 * Dual-Maintenance CommonJS Implementation.
 */

'use strict';

class EvoiProbeOptimizer {
  constructor() {
    this.totalOptimizations = 0;
    this.topProbesSelected = 0;
  }

  computePriorEntropy(beliefDistribution) {
    let entropy = 0;
    const values = Object.values(beliefDistribution || {});
    for (const p of values) {
      if (p > 1e-6) {
        entropy -= p * Math.log2(p);
      }
    }
    return Number(entropy.toFixed(4));
  }

  optimizeDiagnosticProbes(priorBelief, availableProbes, costWeight = 0.15) {
    this.totalOptimizations++;
    const optimizationId = `evoi_${Date.now()}_${Math.floor(Math.random() * 100000)}`;
    const priorEntropy = this.computePriorEntropy(priorBelief);
    const lambda = Math.max(0.01, Math.min(2.0, Number(costWeight) || 0.15));

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
    const evaluated = availableProbes.map((probe) => {
      const infoGain = Math.min(priorEntropy, Math.max(0, Number(probe.expectedEntropyReductionBits) || 0));
      const penalty = lambda * Math.max(0.01, Number(probe.cost) || 0.1);
      const netEvoi = Number((infoGain - penalty).toFixed(4));

      return {
        probeId: probe.probeId,
        targetDomain: probe.targetDomain,
        description: probe.description,
        expectedEntropyReductionBits: Number(probe.expectedEntropyReductionBits) || 0,
        cost: Number(probe.cost) || 0,
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

  getMetrics() {
    return {
      totalOptimizations: this.totalOptimizations,
      topProbesSelected: this.topProbesSelected
    };
  }
}

const evoiProbeOptimizer = new EvoiProbeOptimizer();

module.exports = {
  EvoiProbeOptimizer,
  evoiProbeOptimizer
};
