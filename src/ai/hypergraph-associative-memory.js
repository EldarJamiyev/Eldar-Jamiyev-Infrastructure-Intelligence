/**
 * EJII Dynamic Hypergraph Associative Epistemic Memory
 *
 * Structures incident knowledge, symptoms, interventions, and counterfactuals
 * into higher-order associative hyper-edges to prevent catastrophic forgetting.
 * Dual-Maintenance CommonJS Implementation.
 */

'use strict';

class HypergraphAssociativeMemory {
  constructor() {
    this.edges = new Map();
    this.nodeIncidence = new Map();
  }

  /**
   * Inserts an associative hyper-edge connecting heterogeneous incident entities.
   */
  insertHyperEdge(edgeId, nodeIds, properties = {}, surpriseFactor = 1.0) {
    if (!edgeId || !Array.isArray(nodeIds) || nodeIds.length === 0) {
      return false;
    }

    const normalizedSurprise = Math.max(1.0, surpriseFactor);
    const now = Date.now();

    const hyperEdge = {
      edgeId,
      nodeIds: Array.from(new Set(nodeIds)),
      properties: { ...properties },
      surpriseFactor: normalizedSurprise,
      weight: 1.0,
      createdAt: now,
      lastAccessedAt: now,
      accessCount: 1
    };

    this.edges.set(edgeId, hyperEdge);

    for (const nodeId of hyperEdge.nodeIds) {
      if (!this.nodeIncidence.has(nodeId)) {
        this.nodeIncidence.set(nodeId, new Set());
      }
      this.nodeIncidence.get(nodeId).add(edgeId);
    }

    return true;
  }

  /**
   * Queries hyper-edges incident to a given entity node with minimum associative weight.
   */
  queryIncidentAssociates(nodeId, minWeight = 0.0) {
    const incidentEdgeIds = this.nodeIncidence.get(nodeId);
    if (!incidentEdgeIds || incidentEdgeIds.size === 0) {
      return [];
    }

    const results = [];
    const now = Date.now();

    for (const edgeId of incidentEdgeIds) {
      const edge = this.edges.get(edgeId);
      if (edge && edge.weight >= minWeight) {
        edge.lastAccessedAt = now;
        edge.accessCount++;
        results.push({ ...edge });
      }
    }

    return results.sort((a, b) => b.surpriseFactor * b.weight - a.surpriseFactor * a.weight);
  }

  /**
   * Retrieves a single hyper-edge by identifier.
   */
  getEdge(edgeId) {
    return this.edges.get(edgeId);
  }

  /**
   * Retrieves all stored hyper-edges.
   */
  getAllEdges() {
    return Array.from(this.edges.values());
  }

  /**
   * Removes a hyper-edge and cleans up incidence maps.
   */
  removeHyperEdge(edgeId) {
    const edge = this.edges.get(edgeId);
    if (!edge) {
      return false;
    }

    for (const nodeId of edge.nodeIds) {
      const edgeSet = this.nodeIncidence.get(nodeId);
      if (edgeSet) {
        edgeSet.delete(edgeId);
        if (edgeSet.size === 0) {
          this.nodeIncidence.delete(nodeId);
        }
      }
    }

    return this.edges.delete(edgeId);
  }

  /**
   * Returns current hypergraph density and degree metrics.
   */
  getMetrics() {
    const totalNodes = this.nodeIncidence.size;
    const totalHyperEdges = this.edges.size;

    let degreeSum = 0;
    for (const edgeSet of this.nodeIncidence.values()) {
      degreeSum += edgeSet.size;
    }

    const avgDegree = totalNodes > 0 ? Number((degreeSum / totalNodes).toFixed(4)) : 0;

    return {
      totalNodes,
      totalHyperEdges,
      avgDegree
    };
  }
}

const hypergraphAssociativeMemory = new HypergraphAssociativeMemory();

module.exports = {
  HypergraphAssociativeMemory,
  hypergraphAssociativeMemory
};
