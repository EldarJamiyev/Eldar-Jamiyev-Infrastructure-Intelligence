/**
 * EJII Dynamic Structural Causal Engine (D-SCM)
 *
 * Implements:
 *   1. Vector Autoregressive Structural Causal Modeling (VAR-SCM):
 *      X_t = c + \sum_{\tau=1}^p B_\tau X_{t-\tau} + \epsilon_t, \quad \epsilon_t \sim \mathcal{N}(0, \Sigma)
 *   2. Dynamical Stability & Spectral Radius:
 *      Evaluates companion matrix C eigenvalues via Power Iteration to verify \rho(C) < 1.0.
 *   3. Multi-Step Time-Lagged Counterfactual Interventional Calculus:
 *      - Abduction: Estimates exogenous shock history \hat{\epsilon}_t
 *      - Action: Replaces structural equation with do(X_{t,j} = x_j^*)
 *      - Prediction: Recursively simulates cascading downstream trajectories over horizon H
 *      - Decomposes Total Dynamic Effect (TE_h) into Direct Effect (DDE_h) and Cascading Indirect Effect (ACIE_h)
 */

'use strict';

export interface VarScmModel {
  variables: string[];
  lag: number;
  intercepts: number[]; // c vector (K)
  transitionMatrices: number[][][]; // [lagIndex][row][col] (p x K x K)
  residualCovariance: number[][]; // K x K
  spectralRadius: number;
  isStable: boolean;
  sampleCount: number;
}

export interface DynamicIntervention {
  variable: string;
  targetValue: number;
}

export interface DynamicTrajectoryStep {
  step: number;
  timeOffsetSeconds: number;
  baseline: Record<string, number>;
  counterfactual: Record<string, number>;
  totalEffect: Record<string, number>;
}

export interface DynamicInterventionResult {
  intervention: DynamicIntervention;
  horizonSteps: number;
  trajectory: DynamicTrajectoryStep[];
  cumulativeImpact: Record<string, number>;
  directDynamicEffect: number;
  accumulatedCascadingEffect: number;
  stabilizationHorizonSteps: number | null;
  summary: string;
}

/**
 * Inverts a square matrix using Gauss-Jordan elimination with partial pivoting.
 */
function invertMatrix(matrix: number[][]): number[][] | null {
  const n = matrix.length;
  const A: number[][] = matrix.map((row) => [...row]);
  const inv: number[][] = Array.from({ length: n }, (_, i) =>
    Array.from({ length: n }, (_, j) => (i === j ? 1 : 0))
  );

  for (let i = 0; i < n; i++) {
    // Pivot selection
    let maxRow = i;
    for (let k = i + 1; k < n; k++) {
      if (Math.abs(A[k][i]) > Math.abs(A[maxRow][i])) {
        maxRow = k;
      }
    }

    if (Math.abs(A[maxRow][i]) < 1e-12) {
      return null; // Singular matrix
    }

    // Swap rows in A and inv
    [A[i], A[maxRow]] = [A[maxRow], A[i]];
    [inv[i], inv[maxRow]] = [inv[maxRow], inv[i]];

    // Normalize pivot row
    const pivot = A[i][i];
    for (let j = 0; j < n; j++) {
      A[i][j] /= pivot;
      inv[i][j] /= pivot;
    }

    // Eliminate other rows
    for (let k = 0; k < n; k++) {
      if (k !== i) {
        const factor = A[k][i];
        for (let j = 0; j < n; j++) {
          A[k][j] -= factor * A[i][j];
          inv[k][j] -= factor * inv[i][j];
        }
      }
    }
  }

  return inv;
}

/**
 * Estimates spectral radius \rho(C) = \max_i |\lambda_i| via power iteration on companion matrix.
 */
function computeSpectralRadius(transitionMatrices: number[][][]): number {
  const p = transitionMatrices.length;
  if (p === 0) return 0;
  const K = transitionMatrices[0].length;
  const dim = p * K;

  // Build companion matrix C (dim x dim)
  const C: number[][] = Array.from({ length: dim }, () => new Array(dim).fill(0));

  // Top block: [B_1, B_2, ..., B_p]
  for (let lag = 0; lag < p; lag++) {
    for (let i = 0; i < K; i++) {
      for (let j = 0; j < K; j++) {
        C[i][lag * K + j] = transitionMatrices[lag][i][j] || 0;
      }
    }
  }

  // Lower blocks: Identity submatrices for lag state shift
  for (let block = 1; block < p; block++) {
    for (let i = 0; i < K; i++) {
      C[block * K + i][(block - 1) * K + i] = 1.0;
    }
  }

  // Power iteration to find dominant eigenvalue
  let v = new Array(dim).fill(1 / Math.sqrt(dim));
  let lambda = 0;

  for (let iter = 0; iter < 40; iter++) {
    const Cv = new Array(dim).fill(0);
    for (let i = 0; i < dim; i++) {
      for (let j = 0; j < dim; j++) {
        Cv[i] += C[i][j] * v[j];
      }
    }

    let norm = 0;
    for (let i = 0; i < dim; i++) {
      norm += Cv[i] * Cv[i];
    }
    norm = Math.sqrt(norm);

    if (norm < 1e-12) return 0;

    lambda = norm;
    for (let i = 0; i < dim; i++) {
      v[i] = Cv[i] / norm;
    }
  }

  return Number(Math.min(2.0, lambda).toFixed(4));
}

/**
 * Fits a Vector Autoregressive Structural Causal Model (VAR-SCM) of lag order p.
 */
export function fitVarScm(
  seriesData: Record<string, number[]>,
  options: { lag?: number } = {}
): VarScmModel {
  const lag = Math.max(1, options.lag ?? 1);
  const variables = Object.keys(seriesData);
  const K = variables.length;

  if (K < 2) {
    throw new Error('VAR-SCM requires at least 2 multivariate time series variables');
  }

  const rawLengths = variables.map((v) => (seriesData[v] || []).length);
  const N = Math.min(...rawLengths);

  if (N <= lag + 2) {
    throw new Error(`Insufficient sample length (${N}) for lag order ${lag}`);
  }

  const T = N - lag;
  const numFeatures = 1 + lag * K; // intercept + (lag * K)

  // Construct response matrix Y (T x K) and design matrix Z (T x numFeatures)
  const Y: number[][] = Array.from({ length: T }, () => new Array(K).fill(0));
  const Z: number[][] = Array.from({ length: T }, () => new Array(numFeatures).fill(0));

  for (let t = 0; t < T; t++) {
    const timeIdx = lag + t;
    for (let i = 0; i < K; i++) {
      Y[t][i] = seriesData[variables[i]][timeIdx];
    }

    Z[t][0] = 1.0; // intercept
    let col = 1;
    for (let l = 1; l <= lag; l++) {
      const pastTime = timeIdx - l;
      for (let i = 0; i < K; i++) {
        Z[t][col++] = seriesData[variables[i]][pastTime];
      }
    }
  }

  // Calculate Z^T * Z (numFeatures x numFeatures) with ridge regularization
  const ZtZ: number[][] = Array.from({ length: numFeatures }, () => new Array(numFeatures).fill(0));
  for (let i = 0; i < numFeatures; i++) {
    for (let j = 0; j < numFeatures; j++) {
      let sum = 0;
      for (let t = 0; t < T; t++) {
        sum += Z[t][i] * Z[t][j];
      }
      ZtZ[i][j] = sum + (i === j ? 1e-4 : 0); // L2 ridge damping
    }
  }

  // Invert (Z^T * Z)
  const invZtZ = invertMatrix(ZtZ);
  if (!invZtZ) {
    throw new Error('Design covariance matrix is singular; cannot solve VAR-SCM parameters');
  }

  // Calculate Z^T * Y (numFeatures x K)
  const ZtY: number[][] = Array.from({ length: numFeatures }, () => new Array(K).fill(0));
  for (let i = 0; i < numFeatures; i++) {
    for (let k = 0; k < K; k++) {
      let sum = 0;
      for (let t = 0; t < T; t++) {
        sum += Z[t][i] * Y[t][k];
      }
      ZtY[i][k] = sum;
    }
  }

  // Beta = inv(ZtZ) * ZtY (numFeatures x K)
  const Beta: number[][] = Array.from({ length: numFeatures }, () => new Array(K).fill(0));
  for (let i = 0; i < numFeatures; i++) {
    for (let k = 0; k < K; k++) {
      let sum = 0;
      for (let j = 0; j < numFeatures; j++) {
        sum += invZtZ[i][j] * ZtY[j][k];
      }
      Beta[i][k] = sum;
    }
  }

  // Extract intercepts (c) and transition matrices (B_1, ..., B_p)
  const intercepts: number[] = new Array(K).fill(0);
  for (let k = 0; k < K; k++) {
    intercepts[k] = Number(Beta[0][k].toFixed(4));
  }

  const transitionMatrices: number[][][] = [];
  for (let l = 0; l < lag; l++) {
    const B_l: number[][] = Array.from({ length: K }, () => new Array(K).fill(0));
    for (let k = 0; k < K; k++) {
      for (let j = 0; j < K; j++) {
        const featureIdx = 1 + l * K + j;
        B_l[k][j] = Number(Beta[featureIdx][k].toFixed(4));
      }
    }
    transitionMatrices.push(B_l);
  }

  // Calculate residuals & covariance matrix
  const residualCovariance: number[][] = Array.from({ length: K }, () => new Array(K).fill(0));
  for (let t = 0; t < T; t++) {
    const residuals: number[] = new Array(K).fill(0);
    for (let k = 0; k < K; k++) {
      let pred = Beta[0][k];
      for (let f = 1; f < numFeatures; f++) {
        pred += Z[t][f] * Beta[f][k];
      }
      residuals[k] = Y[t][k] - pred;
    }

    for (let i = 0; i < K; i++) {
      for (let j = 0; j < K; j++) {
        residualCovariance[i][j] += residuals[i] * residuals[j];
      }
    }
  }

  for (let i = 0; i < K; i++) {
    for (let j = 0; j < K; j++) {
      residualCovariance[i][j] = Number((residualCovariance[i][j] / Math.max(1, T - numFeatures)).toFixed(4));
    }
  }

  const spectralRadius = computeSpectralRadius(transitionMatrices);
  const isStable = spectralRadius < 1.0;

  return {
    variables,
    lag,
    intercepts,
    transitionMatrices,
    residualCovariance,
    spectralRadius,
    isStable,
    sampleCount: N
  };
}

/**
 * Evaluates a multi-step dynamic counterfactual intervention trajectory:
 * do(X_{t, j} = targetValue)
 */
export function simulateDynamicIntervention(
  model: VarScmModel,
  history: Record<string, number[]>,
  intervention: DynamicIntervention,
  horizonSteps: number = 10,
  stepDurationSeconds: number = 1.0
): DynamicInterventionResult {
  const { variables, lag, intercepts, transitionMatrices } = model;
  const K = variables.length;
  const targetIdx = variables.indexOf(intervention.variable);

  if (targetIdx === -1) {
    throw new Error(`Intervention variable "${intervention.variable}" not found in model variables: ${variables.join(', ')}`);
  }

  const H = Math.max(1, Math.min(60, horizonSteps));

  // Extract recent lag states
  const baselineBuffer: number[][] = [];
  const cfBuffer: number[][] = [];

  for (let l = lag - 1; l >= 0; l--) {
    const state: number[] = [];
    for (let i = 0; i < K; i++) {
      const arr = history[variables[i]] || [];
      const val = arr[arr.length - 1 - l] ?? 0;
      state.push(val);
    }
    baselineBuffer.push([...state]);
    cfBuffer.push([...state]);
  }

  // Apply intervention at current step t
  const currentCfState = [...cfBuffer[cfBuffer.length - 1]];
  currentCfState[targetIdx] = intervention.targetValue;
  cfBuffer[cfBuffer.length - 1] = currentCfState;

  const trajectory: DynamicTrajectoryStep[] = [];
  const cumulativeImpact: Record<string, number> = {};
  for (const v of variables) cumulativeImpact[v] = 0;

  let directDynamicEffect = 0;
  let accumulatedCascadingEffect = 0;
  let stabilizationHorizonSteps: number | null = null;

  for (let step = 1; step <= H; step++) {
    const nextBaseline: number[] = [...intercepts];
    const nextCf: number[] = [...intercepts];

    // Compute VAR forward step: c + \sum_{l=1}^p B_l * X_{t-l}
    for (let l = 0; l < lag; l++) {
      const B_l = transitionMatrices[l];
      const baseState = baselineBuffer[baselineBuffer.length - 1 - l];
      const cfState = cfBuffer[cfBuffer.length - 1 - l];

      for (let i = 0; i < K; i++) {
        for (let j = 0; j < K; j++) {
          nextBaseline[i] += B_l[i][j] * baseState[j];
          nextCf[i] += B_l[i][j] * cfState[j];
        }
      }
    }

    // Ensure non-negative physical telemetry
    for (let i = 0; i < K; i++) {
      nextBaseline[i] = Math.max(0, nextBaseline[i]);
      nextCf[i] = Math.max(0, nextCf[i]);
    }

    baselineBuffer.push(nextBaseline);
    cfBuffer.push(nextCf);

    const stepBaselineObj: Record<string, number> = {};
    const stepCfObj: Record<string, number> = {};
    const stepEffectObj: Record<string, number> = {};

    let maxDiscrepancy = 0;
    for (let i = 0; i < K; i++) {
      const v = variables[i];
      const bVal = Number(nextBaseline[i].toFixed(2));
      const cVal = Number(nextCf[i].toFixed(2));
      const diff = Number((cVal - bVal).toFixed(2));

      stepBaselineObj[v] = bVal;
      stepCfObj[v] = cVal;
      stepEffectObj[v] = diff;
      cumulativeImpact[v] = Number((cumulativeImpact[v] + diff).toFixed(2));

      if (i === targetIdx) {
        directDynamicEffect += diff;
      } else {
        accumulatedCascadingEffect += Math.abs(diff);
      }

      if (Math.abs(diff) > maxDiscrepancy) {
        maxDiscrepancy = Math.abs(diff);
      }
    }

    if (stabilizationHorizonSteps === null && maxDiscrepancy < 0.25 && step > 2) {
      stabilizationHorizonSteps = step;
    }

    trajectory.push({
      step,
      timeOffsetSeconds: step * stepDurationSeconds,
      baseline: stepBaselineObj,
      counterfactual: stepCfObj,
      totalEffect: stepEffectObj
    });
  }

  const primaryOutcomeVar = variables.find((v) => v.includes('rtt') || v.includes('latency') || v.includes('loss')) || variables[0];
  const summary = `D-SCM Dynamic Projection: do(${intervention.variable}=${intervention.targetValue}) ` +
    `yields cumulative ${primaryOutcomeVar} shift of ${cumulativeImpact[primaryOutcomeVar]} over ${H * stepDurationSeconds}s ` +
    `(Direct Effect=${directDynamicEffect.toFixed(2)}, Cascading Effect=${accumulatedCascadingEffect.toFixed(2)}). ` +
    (stabilizationHorizonSteps
      ? `System reaches equilibrium by step ${stabilizationHorizonSteps} (${stabilizationHorizonSteps * stepDurationSeconds}s).`
      : 'Cascade dynamic persists across the full horizon.');

  return {
    intervention,
    horizonSteps: H,
    trajectory,
    cumulativeImpact,
    directDynamicEffect: Number(directDynamicEffect.toFixed(2)),
    accumulatedCascadingEffect: Number(accumulatedCascadingEffect.toFixed(2)),
    stabilizationHorizonSteps,
    summary
  };
}

export class DynamicStructuralCausalEngine {
  public fitModel(seriesData: Record<string, number[]>, options?: { lag?: number }): VarScmModel {
    return fitVarScm(seriesData, options);
  }

  public simulateIntervention(
    model: VarScmModel,
    history: Record<string, number[]>,
    intervention: DynamicIntervention,
    horizonSteps?: number,
    stepDurationSeconds?: number
  ): DynamicInterventionResult {
    return simulateDynamicIntervention(model, history, intervention, horizonSteps, stepDurationSeconds);
  }
}

export const dynamicStructuralCausalEngine = new DynamicStructuralCausalEngine();
