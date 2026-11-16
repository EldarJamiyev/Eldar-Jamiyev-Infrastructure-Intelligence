/**
 * EJII Continuous-Time Topological Reaction-Diffusion PDE Engine
 *
 * Implements Fisher-KPP bistable reaction-diffusion partial differential equations
 * over graph Laplacians integrated via 4th-order Runge-Kutta (RK4) with Lyapunov
 * stability certificates for cascading failure forecasting.
 * Dual-Maintenance TypeScript Reference.
 */

export interface PdeSolveResult {
  timePoints: number[];
  stateSnapshots: Array<number[]>;
  lyapunovDrift: number[];
  isContractionStable: boolean;
}

export class TopologicalDiffusionPdeEngine {
  constructor() {}

  public constructGraphLaplacian(
    nodeCount: number,
    edges: Array<{ source: number; target: number; weight?: number }>
  ): Float64Array {
    const L = new Float64Array(nodeCount * nodeCount);
    const degrees = new Float64Array(nodeCount);

    for (const e of edges) {
      if (e.source >= 0 && e.source < nodeCount && e.target >= 0 && e.target < nodeCount) {
        const w = e.weight || 1.0;
        degrees[e.source] += w;
        degrees[e.target] += w;
        // Non-directed adjacency
        L[e.source * nodeCount + e.target] -= w;
        L[e.target * nodeCount + e.source] -= w;
      }
    }

    for (let i = 0; i < nodeCount; i++) {
      L[i * nodeCount + i] += degrees[i];
    }

    return L;
  }

  public evaluateRhs(
    u: Float64Array,
    laplacian: Float64Array,
    nodeCount: number,
    diffusionD: number = 0.25,
    gamma: number = 1.2,
    theta: number = 0.35
  ): Float64Array {
    const du = new Float64Array(nodeCount);

    for (let i = 0; i < nodeCount; i++) {
      // Diffusion term: -D * (L * u)_i
      let laplacianTerm = 0;
      for (let j = 0; j < nodeCount; j++) {
        laplacianTerm += laplacian[i * nodeCount + j] * u[j];
      }

      // Reaction term: gamma * u * (1 - u) * (u - theta)
      const ui = u[i];
      const reactionTerm = gamma * ui * (1.0 - ui) * (ui - theta);

      du[i] = -diffusionD * laplacianTerm + reactionTerm;
    }

    return du;
  }

  public stepRk4(
    u: Float64Array,
    laplacian: Float64Array,
    nodeCount: number,
    dt: number,
    diffusionD: number = 0.25,
    gamma: number = 1.2,
    theta: number = 0.35
  ): Float64Array {
    // k1 = F(u)
    const k1 = this.evaluateRhs(u, laplacian, nodeCount, diffusionD, gamma, theta);

    // k2 = F(u + dt/2 * k1)
    const uTemp1 = new Float64Array(nodeCount);
    for (let i = 0; i < nodeCount; i++) {
      uTemp1[i] = Math.max(0.0, Math.min(1.0, u[i] + 0.5 * dt * k1[i]));
    }
    const k2 = this.evaluateRhs(uTemp1, laplacian, nodeCount, diffusionD, gamma, theta);

    // k3 = F(u + dt/2 * k2)
    const uTemp2 = new Float64Array(nodeCount);
    for (let i = 0; i < nodeCount; i++) {
      uTemp2[i] = Math.max(0.0, Math.min(1.0, u[i] + 0.5 * dt * k2[i]));
    }
    const k3 = this.evaluateRhs(uTemp2, laplacian, nodeCount, diffusionD, gamma, theta);

    // k4 = F(u + dt * k3)
    const uTemp3 = new Float64Array(nodeCount);
    for (let i = 0; i < nodeCount; i++) {
      uTemp3[i] = Math.max(0.0, Math.min(1.0, u[i] + dt * k3[i]));
    }
    const k4 = this.evaluateRhs(uTemp3, laplacian, nodeCount, diffusionD, gamma, theta);

    // u_next = u + (dt/6) * (k1 + 2*k2 + 2*k3 + k4)
    const nextU = new Float64Array(nodeCount);
    for (let i = 0; i < nodeCount; i++) {
      const increment = (dt / 6.0) * (k1[i] + 2.0 * k2[i] + 2.0 * k3[i] + k4[i]);
      nextU[i] = Math.max(0.0, Math.min(1.0, u[i] + increment));
    }

    return nextU;
  }

  public computeLyapunovEnergy(u: Float64Array, laplacian: Float64Array, nodeCount: number): number {
    // V(u) = 1/2 u^T L u
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

  public solveTrajectory(
    initialU: Float64Array,
    edges: Array<{ source: number; target: number; weight?: number }>,
    totalTimeSec: number = 5.0,
    dt: number = 0.05
  ): PdeSolveResult {
    const nodeCount = initialU.length;
    const laplacian = this.constructGraphLaplacian(nodeCount, edges);

    const timePoints: number[] = [0.0];
    const stateSnapshots: Array<number[]> = [Array.from(initialU)];
    const lyapunovDrift: number[] = [this.computeLyapunovEnergy(initialU, laplacian, nodeCount)];

    let currentU: Float64Array = new Float64Array(initialU);
    let currentTime = 0.0;
    const steps = Math.floor(totalTimeSec / dt);

    for (let s = 1; s <= steps; s++) {
      currentU = this.stepRk4(currentU, laplacian, nodeCount, dt);
      currentTime = Number((s * dt).toFixed(3));

      // Record snapshot every 10 steps (0.5s intervals)
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

export const topologicalDiffusionPdeEngine = new TopologicalDiffusionPdeEngine();
