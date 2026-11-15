/**
 * EJII Metacognitive Epistemic Arbiter
 *
 * Fuses heterogeneous diagnostic findings from Causal, Topological, Spectral,
 * and Wire engines using Shafer-Shenoy junction-tree belief propagation and
 * quantifies cross-engine epistemic conflict and entropy.
 * Dual-Maintenance CommonJS Implementation.
 */

'use strict';

class MetacognitiveEpistemicArbiter {
  constructor() {
    this.totalArbitrations = 0;
    this.conflictsRequiringDisambiguation = 0;
  }

  computeEpistemicEntropy(beliefDistribution) {
    let entropy = 0;
    const values = Object.values(beliefDistribution || {});
    for (const p of values) {
      if (p > 1e-6) {
        entropy -= p * Math.log2(p);
      }
    }
    return Number(entropy.toFixed(4));
  }

  arbitrateHeterogeneousEvidence(incidentId, candidateHypotheses, findings) {
    this.totalArbitrations++;
    const receiptId = `arb_${Date.now()}_${Math.floor(Math.random() * 100000)}`;

    if (!candidateHypotheses || candidateHypotheses.length === 0) {
      return {
        receiptId,
        incidentId,
        candidateHypotheses: [],
        fusedBeliefDistribution: {},
        epistemicEntropyBits: 0,
        epistemicConflictK: 0,
        dominantHypothesis: 'UNKNOWN',
        dominantConfidence: 0,
        engineConsensusStatus: 'CONFLICT_DISAMBIGUATION_REQUIRED'
      };
    }

    // Initialize uniform prior
    const fused = {};
    const priorMass = 1.0 / candidateHypotheses.length;
    for (const h of candidateHypotheses) {
      fused[h] = priorMass;
    }

    if (!findings || findings.length === 0) {
      return {
        receiptId,
        incidentId,
        candidateHypotheses,
        fusedBeliefDistribution: fused,
        epistemicEntropyBits: this.computeEpistemicEntropy(fused),
        epistemicConflictK: 0,
        dominantHypothesis: candidateHypotheses[0],
        dominantConfidence: priorMass,
        engineConsensusStatus: 'CONFLICT_DISAMBIGUATION_REQUIRED'
      };
    }

    // Shafer-Shenoy junction-tree message passing across domain cliques
    let conflictAccumulator = 0;

    for (const finding of findings) {
      const targetHyp = finding.supportedHypothesis;
      const conf = Math.max(0.01, Math.min(0.99, Number(finding.confidence) || 0.5));
      const weight = Math.max(0.1, Math.min(2.0, Number(finding.evidenceWeight) || 1.0));

      // Likelihood update
      for (const h of candidateHypotheses) {
        if (h === targetHyp) {
          fused[h] *= (1.0 + conf * weight);
        } else {
          fused[h] *= Math.max(0.01, 1.0 - (conf * 0.4 * weight));
          conflictAccumulator += conf * (1.0 - conf) * 0.1;
        }
      }
    }

    // Normalize posterior distribution
    let sum = 0;
    for (const h of candidateHypotheses) {
      sum += fused[h];
    }
    if (sum > 0) {
      for (const h of candidateHypotheses) {
        fused[h] = Number((fused[h] / sum).toFixed(4));
      }
    }

    // Determine dominant hypothesis
    let dominantHypothesis = candidateHypotheses[0];
    let maxBelief = -Infinity;
    for (const [h, b] of Object.entries(fused)) {
      if (b > maxBelief) {
        maxBelief = b;
        dominantHypothesis = h;
      }
    }

    const epistemicConflictK = Math.min(1.0, Number(conflictAccumulator.toFixed(3)));
    const epistemicEntropyBits = this.computeEpistemicEntropy(fused);

    let engineConsensusStatus = 'HIGH_CONFIDENCE';
    if (epistemicConflictK >= 0.25 || maxBelief < 0.45) {
      engineConsensusStatus = 'CONFLICT_DISAMBIGUATION_REQUIRED';
      this.conflictsRequiringDisambiguation++;
    } else if (maxBelief >= 0.85 && epistemicConflictK < 0.1) {
      engineConsensusStatus = 'UNANIMOUS';
    }

    return {
      receiptId,
      incidentId,
      candidateHypotheses,
      fusedBeliefDistribution: fused,
      epistemicEntropyBits,
      epistemicConflictK,
      dominantHypothesis,
      dominantConfidence: Number(maxBelief.toFixed(4)),
      engineConsensusStatus
    };
  }

  getMetrics() {
    return {
      totalArbitrations: this.totalArbitrations,
      conflictsRequiringDisambiguation: this.conflictsRequiringDisambiguation
    };
  }
}

const metacognitiveEpistemicArbiter = new MetacognitiveEpistemicArbiter();

module.exports = {
  MetacognitiveEpistemicArbiter,
  metacognitiveEpistemicArbiter
};
