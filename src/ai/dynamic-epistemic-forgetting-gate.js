/**
 * EJII Dynamic Epistemic Forgetting Gate
 *
 * Implements Ebbinghaus decay modulated by incident surprise to dynamically
 * consolidate significant causal invariants while pruning decayed associative noise.
 * Dual-Maintenance CommonJS Implementation.
 */

'use strict';

class DynamicEpistemicForgettingGate {
  constructor() {
    this.evaluationsCount = 0;
    this.prunedEdgesCount = 0;
  }

  /**
   * Evaluates memory retention R(t) = exp(-t / (S * tau))
   * where S is the surprise factor (Delta Entropy) and tau is stability half-life in hours.
   */
  evaluateRetention(lastAccessTimestamp, surpriseFactor = 1.0, halfLifeHours = 24.0) {
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
  pruneDecayedEdges(memoryInstance, retentionThreshold = 0.15) {
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
  getMetrics() {
    return {
      evaluationsCount: this.evaluationsCount,
      prunedEdgesCount: this.prunedEdgesCount
    };
  }
}

const dynamicEpistemicForgettingGate = new DynamicEpistemicForgettingGate();

module.exports = {
  DynamicEpistemicForgettingGate,
  dynamicEpistemicForgettingGate
};
