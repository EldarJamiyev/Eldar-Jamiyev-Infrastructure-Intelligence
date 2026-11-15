/**
 * EJII Cascading Failure Predictor
 *
 * Forecasts failure wavefront arrival times across infrastructure graphs
 * using continuous reaction-diffusion PDE integration and identifies
 * critical cut-off interventions to prevent network-wide partition collapse.
 * CommonJS Dual-Parity Implementation.
 */

'use strict';

const { topologicalDiffusionPdeEngine } = require('./topological-diffusion-pde-engine');

class CascadingFailurePredictor {
  constructor() {
    this.totalPredictions = 0;
    this.cascadesDetected = 0;
  }

  predictCascadingFailure(topology, horizonSec = 10.0) {
    this.totalPredictions++;
    const predictionId = `cascade_pred_${Date.now()}_${Math.floor(Math.random() * 10000)}`;

    if (!topology || !Array.isArray(topology.nodes) || topology.nodes.length === 0) {
      return {
        predictionId,
        horizonSec,
        isCascadingContagionLikely: false,
        affectedNodesCount: 0,
        nodeWavefronts: [],
        recommendedCutoffInterventions: []
      };
    }

    const nodeCount = topology.nodes.length;
    const nodeIdx = new Map();
    topology.nodes.forEach((n, idx) => nodeIdx.set(n.id, idx));

    const initialU = new Float64Array(nodeCount);
    topology.nodes.forEach((n, idx) => {
      initialU[idx] = Math.max(0.0, Math.min(1.0, n.initialStress || 0.0));
    });

    const numericEdges = [];
    for (const e of topology.edges) {
      const u = nodeIdx.get(e.source);
      const v = nodeIdx.get(e.target);
      if (u !== undefined && v !== undefined) {
        numericEdges.push({ source: u, target: v, weight: e.weight || 1.0 });
      }
    }

    const pdeResult = topologicalDiffusionPdeEngine.solveTrajectory(initialU, numericEdges, horizonSec, 0.05);

    const nodeWavefronts = [];
    const recommendedCutoffInterventions = [];
    let affectedCount = 0;

    for (let i = 0; i < nodeCount; i++) {
      const node = topology.nodes[i];
      let arrivalSec = null;

      for (let tIdx = 0; tIdx < pdeResult.timePoints.length; tIdx++) {
        const stress = pdeResult.stateSnapshots[tIdx][i];
        if (stress >= 0.5 && arrivalSec === null) {
          arrivalSec = pdeResult.timePoints[tIdx];
        }
      }

      const finalStress = pdeResult.stateSnapshots[pdeResult.stateSnapshots.length - 1][i];
      const riskTier = finalStress >= 0.7 ? 'CRITICAL' : (finalStress >= 0.35 ? 'ELEVATED' : 'STABLE');

      if (riskTier === 'CRITICAL' || riskTier === 'ELEVATED') {
        affectedCount++;
      }

      if (arrivalSec !== null && arrivalSec > 0.0 && arrivalSec <= horizonSec) {
        recommendedCutoffInterventions.push({
          nodeId: node.id,
          rationale: `Failure wavefront expected at T+${arrivalSec.toFixed(1)}s (stress=${finalStress.toFixed(2)}). Throttle ingress queues to break diffusion path.`,
          urgencySeconds: Math.max(1.0, Number((arrivalSec * 0.8).toFixed(1)))
        });
      }

      nodeWavefronts.push({
        nodeId: node.id,
        initialStress: initialU[i],
        finalPredictedStress: Number(finalStress.toFixed(3)),
        wavefrontArrivalSec: arrivalSec,
        riskTier
      });
    }

    const isCascadingContagionLikely = affectedCount >= 2 && recommendedCutoffInterventions.length > 0;
    if (isCascadingContagionLikely) {
      this.cascadesDetected++;
    }

    return {
      predictionId,
      horizonSec,
      isCascadingContagionLikely,
      affectedNodesCount: affectedCount,
      nodeWavefronts,
      recommendedCutoffInterventions
    };
  }

  getMetrics() {
    return {
      totalPredictions: this.totalPredictions,
      cascadesDetected: this.cascadesDetected
    };
  }
}

const cascadingFailurePredictor = new CascadingFailurePredictor();

module.exports = {
  CascadingFailurePredictor,
  cascadingFailurePredictor
};
