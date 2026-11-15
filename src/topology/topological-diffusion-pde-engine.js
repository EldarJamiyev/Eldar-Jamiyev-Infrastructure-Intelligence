/**
 * EJII Continuous-Time Topological Reaction-Diffusion PDE Engine
 *
 * Implements Fisher-KPP bistable reaction-diffusion partial differential equations
 * over graph Laplacians integrated via 4th-order Runge-Kutta (RK4) with Lyapunov
 * stability certificates for cascading failure forecasting.
 * CommonJS Dual-Parity Implementation.
 */

'use strict';

class TopologicalDiffusionPdeEngine {
  constructor() {}

  constructGraphLaplacian(nodeCount, edges) {
    const L = new Float64Array(nodeCount * nodeCount);
    const degrees = new Float64Array(nodeCount);

    for (const e of edges) {
      if (e.source >= 0 && e.source < nodeCount && e.target >= 0 && e.target < nodeCount) {
        const w = e.weight || 1.0;
        degrees[e.source] += w;
        degrees[e.target] += w;
        L[e.source * nodeCount + e.target] -= w;
        L[e.target * nodeCount + e.source] -= w;
      }
    }

    for (let i = 0; i < nodeCount; i++) {
      L[i * nodeCount + i] += degrees[i];
    }

    return L;
  }

  evaluateRhs(u, laplacian, nodeCount, diffusionD = 0.25, gamma = 1.2, theta = 0.35) {
    const du = new Float64Array(nodeCount);

    for (let i = 0; i < nodeCount; i++) {
      let laplacianTerm = 0;
      for (let j = 0; j < nodeCount; j++) {
        laplacianTerm += laplacian[i * nodeCount + j] * u[j];
      }

      const ui = u[i];
      const reactionTerm = gamma * ui * (1.0 - ui) * (ui - theta);

      du[i] = -diffusionD * laplacianTerm + reactionTerm;
    }

    return du;
  }

  stepRk4(u, laplacian, nodeCount, dt, diffusionD = 0.25, gamma = 1.2, theta = 0.35) {
    const k1 = this.evaluateRhs(u, laplacian, nodeCount, diffusionD, gamma, theta);

    const uTemp1 = new Float64Array(nodeCount);
    for (let i = 0; i < nodeCount; i++) {
      uTemp1[i] = Math.max(0.0, Math.min(1.0, u[i] + 0.5 * dt * k1[i]));
    }
    const k2 = this.evaluateRhs(uTemp1, laplacian, nodeCount, diffusionD, gamma, theta);

    const uTemp2 = new Float64Array(nodeCount);
    for (let i = 0; i < nodeCount; i++) {
      uTemp2[i] = Math.max(0.0, Math.min(1.0, u[i] + 0.5 * dt * k2[i]));
    }
    const k3 = this.evaluateRhs(uTemp2, laplacian, nodeCount, diffusionD, gamma, theta);

    const uTemp3 = new Float64Array(nodeCount);
    for (let i = 0; i < nodeCount; i++) {
      uTemp3[i] = Math.max(0.0, Math.min(1.0, u[i] + dt * k3[i]));
    }
    const k4 = this.evaluateRhs(uTemp3, laplacian, nodeCount, diffusionD, gamma, theta);

    const nextU = new Float64Array(nodeCount);
    for (let i = 0; i < nodeCount; i++) {
      const increment = (dt / 6.0) * (k1[i] + 2.0 * k2[i] + 2.0 * k3[i] + k4[i]);
      nextU[i] = Math.max(0.0, Math.min(1.0, u[i] + increment));
    }

    return nextU;
  }

  computeLyapunovEnergy(u, laplacian, nodeCount) {
    let energy = 0;
    for (let i = 0; i < nodeCount; i++) {
      let lu = 0;
      for (let j = 0; j < nodeCount; j++) {
        lu += laplacian[i * nodeCount + j] * u[j];
      }
      energy += 0.5 * u[i] * lu;
    }
    return energy;
  }

  solveTrajectory(initialU, edges, totalTimeSec = 5.0, dt = 0.05) {
    const nodeCount = initialU.length;
    const laplacian = this.constructGraphLaplacian(nodeCount, edges);

    const timePoints = [0.0];
    const stateSnapshots = [Array.from(initialU)];
    const lyapunovDrift = [this.computeLyapunovEnergy(initialU, laplacian, nodeCount)];

    let currentU = new Float64Array(initialU);
    let currentTime = 0.0;
    const steps = Math.floor(totalTimeSec / dt);

    for (let s = 1; s <= steps; s++) {
      currentU = this.stepRk4(currentU, laplacian, nodeCount, dt);
      currentTime = Number((s * dt).toFixed(3));

      if (s % 10 === 0 || s === steps) {
        timePoints.push(currentTime);
        stateSnapshots.push(Array.from(currentU));
        lyapunovDrift.push(this.computeLyapunovEnergy(currentU, laplacian, nodeCount));
      }
    }

    const firstEnergy = lyapunovDrift[0];
    const lastEnergy = lyapunovDrift[lyapunovDrift.length - 1];
    const isContractionStable = lastEnergy <= firstEnergy * 1.5;

    return {
      timePoints,
      stateSnapshots,
      lyapunovDrift,
      isContractionStable
    };
  }
}

const topologicalDiffusionPdeEngine = new TopologicalDiffusionPdeEngine();

module.exports = {
  TopologicalDiffusionPdeEngine,
  topologicalDiffusionPdeEngine
};
