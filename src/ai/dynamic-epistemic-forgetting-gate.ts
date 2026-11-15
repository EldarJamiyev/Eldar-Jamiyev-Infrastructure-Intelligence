/**
 * EJII Dynamic Epistemic Forgetting Gate
 *
 * Implements Ebbinghaus decay modulated by incident surprise to dynamically
 * consolidate significant causal invariants while pruning decayed associative noise.
 * Dual-Maintenance TypeScript Reference.
 */

import { HypergraphAssociativeMemory } from './hypergraph-associative-memory';

export class DynamicEpistemicForgettingGate {
  private evaluationsCount: number = 0;
  private prunedEdgesCount: number = 0;

  constructor() {}

  /**
   * Evaluates memory retention R(t) = exp(-t / (S * tau))
   * where S is the surprise factor (Delta Entropy) and tau is stability half-life in hours.
   */
  public evaluateRetention(
    lastAccessTimestamp: number,
    surpriseFactor: number = 1.0,
    halfLifeHours: number = 24.0
  ): number {
    this.evaluationsCount++;

    const s = Math.max(1.0, surpriseFactor);
    const tau = Math.max(0.1, halfLifeHours);

    let elapsedHours = 0;
    if (lastAccessTimestamp > 1e11) {
      // Millisecond timestamp
      const elapsedMs = Math.max(0, Date.now() - lastAccessTimestamp);
      elapsedHours = elapsedMs / (3600 * 1000);
    } else {
      // Direct elapsed hours passed
      elapsedHours = Math.max(0, lastAccessTimestamp);
    }

    const retention = Math.exp(-elapsedHours / (s * tau));
    return Number(Math.max(0.0, Math.min(1.0, retention)).toFixed(6));
  }

  /**
   * Prunes decayed hyper-edges from an associative memory instance.
   */
  public pruneDecayedEdges(
    memoryInstance: HypergraphAssociativeMemory,
    retentionThreshold: number = 0.15
  ): number {
    if (!memoryInstance || typeof memoryInstance.getAllEdges !== 'function') {
      return 0;
    }

    const allEdges = memoryInstance.getAllEdges();
    let pruned = 0;

    for (const edge of allEdges) {
      const retention = this.evaluateRetention(edge.lastAccessedAt, edge.surpriseFactor);
      if (retention < retentionThreshold) {
        if (memoryInstance.removeHyperEdge(edge.edgeId)) {
          pruned++;
        }
      }
    }

    this.prunedEdgesCount += pruned;
    return pruned;
  }

  /**
   * Returns operation metrics for the forgetting gate.
   */
  public getMetrics(): { evaluationsCount: number; prunedEdgesCount: number } {
    return {
      evaluationsCount: this.evaluationsCount,
      prunedEdgesCount: this.prunedEdgesCount
    };
  }
}

export const dynamicEpistemicForgettingGate = new DynamicEpistemicForgettingGate();
