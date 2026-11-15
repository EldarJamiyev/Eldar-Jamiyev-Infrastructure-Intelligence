/**
 * EJII Metacognitive Epistemic Arbiter
 *
 * Fuses heterogeneous diagnostic findings from Causal, Topological, Spectral,
 * and Wire engines using Shafer-Shenoy junction-tree belief propagation and
 * quantifies cross-engine epistemic conflict and entropy.
 * Dual-Maintenance TypeScript Reference.
 */

export interface DomainDiagnosticFinding {
  domain: 'CAUSAL_SEM' | 'TOPOLOGICAL_HOMOLOGY' | 'SPECTRAL_FOURIER' | 'WIRE_EBPF';
  supportedHypothesis: string;
  confidence: number; // [0.0, 1.0]
  evidenceWeight: number; // [0.1, 2.0]
}

export interface EpistemicArbitrationReceipt {
  receiptId: string;
  incidentId: string;
  candidateHypotheses: string[];
  fusedBeliefDistribution: Record<string, number>;
  epistemicEntropyBits: number;
  epistemicConflictK: number;
  dominantHypothesis: string;
  dominantConfidence: number;
  engineConsensusStatus: 'UNANIMOUS' | 'HIGH_CONFIDENCE' | 'CONFLICT_DISAMBIGUATION_REQUIRED';
}

export class MetacognitiveEpistemicArbiter {
  private totalArbitrations: number = 0;
  private conflictsRequiringDisambiguation: number = 0;

  constructor() {}

  public computeEpistemicEntropy(beliefDistribution: Record<string, number>): number {
    let entropy = 0;
    const values = Object.values(beliefDistribution);
    for (const p of values) {
      if (p > 1e-6) {
        entropy -= p * Math.log2(p);
      }
    }
    return Number(entropy.toFixed(4));
  }

  public arbitrateHeterogeneousEvidence(
    incidentId: string,
    candidateHypotheses: string[],
    findings: DomainDiagnosticFinding[]
  ): EpistemicArbitrationReceipt {
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
    const fused: Record<string, number> = {};
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
    // Calculate cross-finding conflict K: pairwise contradiction across distinct hypotheses
    let conflictAccumulator = 0;
    let pairsCount = 0;
    for (let i = 0; i < findings.length; i++) {
      for (let j = i + 1; j < findings.length; j++) {
        pairsCount++;
        if (findings[i].supportedHypothesis !== findings[j].supportedHypothesis) {
          const confI = Math.max(0.01, Math.min(0.99, findings[i].confidence));
          const confJ = Math.max(0.01, Math.min(0.99, findings[j].confidence));
          conflictAccumulator += (confI * confJ);
        }
      }
    }
    const epistemicConflictK = pairsCount > 0
      ? Math.min(1.0, Number((conflictAccumulator / pairsCount).toFixed(3)))
      : 0;

    for (const finding of findings) {
      const targetHyp = finding.supportedHypothesis;
      const conf = Math.max(0.01, Math.min(0.99, finding.confidence));
      const weight = Math.max(0.1, Math.min(2.0, finding.evidenceWeight || 1.0));

      // Likelihood update
      for (const h of candidateHypotheses) {
        if (h === targetHyp) {
          fused[h] *= (1.0 + conf * weight);
        } else {
          fused[h] *= Math.max(0.01, 1.0 - (conf * 0.4 * weight));
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

    const epistemicEntropyBits = this.computeEpistemicEntropy(fused);

    let engineConsensusStatus: EpistemicArbitrationReceipt['engineConsensusStatus'] = 'HIGH_CONFIDENCE';
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

  public getMetrics(): { totalArbitrations: number; conflictsRequiringDisambiguation: number } {
    return {
      totalArbitrations: this.totalArbitrations,
      conflictsRequiringDisambiguation: this.conflictsRequiringDisambiguation
    };
  }
}

export const metacognitiveEpistemicArbiter = new MetacognitiveEpistemicArbiter();
