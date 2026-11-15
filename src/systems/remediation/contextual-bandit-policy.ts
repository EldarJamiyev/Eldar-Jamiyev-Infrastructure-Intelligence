/**
 * EJII Contextual Multi-Armed Bandit (MAB) Remediation Policy Engine
 *
 * Implements:
 *   1. Feature Vector Extraction x \in R^d (Lyapunov drift V(s), Hurst H, queue cliff proximity \kappa, blast radius risk \beta).
 *   2. Dual Bayesian Optimization:
 *      - Thompson Sampling: \theta_a \sim Beta(\alpha_a, \beta_a) via exact Marsaglia-Tsang Gamma generation.
 *      - Contextual LinUCB: \hat{\theta}_a = A_a^{-1} b_a, UCB_a = \hat{\theta}_a^T x + \alpha_{ucb} \sqrt{x^T A_a^{-1} x}.
 *   3. Bayesian Reward Attribution:
 *      R(a, x) = \omega_1 \Delta V / V - \omega_2 BlastRadius - \omega_3 Duration / T_max.
 *   4. Durable SQLite WAL Policy Journal (ejii_bandit_action_posteriors) for zero cold-start regret.
 */

'use strict';

import * as crypto from 'node:crypto';

function getDb(): any {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return require('../../db/database').db;
  } catch (_) {
    return null;
  }
}

export interface ContextVectorParams {
  lyapunovEnergy?: number;
  hurstParameter?: number;
  queueDepthPackets?: number;
  bufferCapacityPackets?: number;
  blastRadiusRisk?: number;
}

export interface BanditArmState {
  armId: string;
  actionType: string;
  pulls: number;
  successes: number;
  failures: number;
  alpha: number;
  beta: number;
  cumulativeReward: number;
  lastReward: number;
  matrixA: number[][]; // d x d ridge matrix
  vectorB: number[];   // d vector
  thetaHat: number[];  // d vector
  lastSelectedIso?: string;
  updatedAtIso: string;
}

export interface BanditArmEvaluation {
  armId: string;
  actionType: string;
  thompsonSample: number;
  linUcbScore: number;
  linUcbConfidence: number;
  combinedScore: number;
  alpha: number;
  beta: number;
  expectedMean: number;
}

export interface BanditSelectionResult {
  selectedArmId: string;
  selectedActionType: string;
  contextVector: number[];
  algorithmUsed: 'THOMPSON_SAMPLING' | 'LIN_UCB' | 'HYBRID_BANDIT';
  evaluations: BanditArmEvaluation[];
  confidenceRadius: number;
  selectionTimestampIso: string;
  explorationBonusApplied: boolean;
}

export interface RewardObservation {
  armId: string;
  contextVector: number[];
  deltaV: number;
  energyBefore?: number;
  blastRadius?: number;
  executionDurationMs?: number;
  success: boolean;
  rollbackOccurred?: boolean;
}

export interface BanditUpdateResult {
  armId: string;
  rawReward: number;
  normalizedReward: number;
  posteriorAlpha: number;
  posteriorBeta: number;
  totalPulls: number;
  cumulativeReward: number;
  updatedAtIso: string;
}

const FEATURE_DIMENSION = 4;

/**
 * Generates independent standard normal random variate using Box-Muller transform
 */
function sampleStandardNormal(): number {
  let u1 = 0;
  let u2 = 0;
  while (u1 === 0) u1 = Math.random();
  while (u2 === 0) u2 = Math.random();
  return Math.sqrt(-2.0 * Math.log(u1)) * Math.cos(2.0 * Math.PI * u2);
}

/**
 * Samples from Gamma(a, 1) using Marsaglia and Tsang method (2000)
 */
function sampleGamma(a: number): number {
  if (a < 1) {
    return sampleGamma(a + 1) * Math.pow(Math.random(), 1.0 / a);
  }
  const d = a - 1.0 / 3.0;
  const c = 1.0 / Math.sqrt(9.0 * d);
  while (true) {
    let z = sampleStandardNormal();
    let v = 1.0 + c * z;
    while (v <= 0) {
      z = sampleStandardNormal();
      v = 1.0 + c * z;
    }
    v = v * v * v;
    const u = Math.random();
    if (u < 1.0 - 0.0331 * z * z * z * z) {
      return d * v;
    }
    if (Math.log(u) < 0.5 * z * z + d * (1.0 - v + Math.log(v))) {
      return d * v;
    }
  }
}

/**
 * Samples from Beta(alpha, beta) using ratio of independent Gammas
 */
function sampleBeta(alpha: number, beta: number): number {
  const safeAlpha = Math.max(0.001, alpha);
  const safeBeta = Math.max(0.001, beta);
  const g1 = sampleGamma(safeAlpha);
  const g2 = sampleGamma(safeBeta);
  if (g1 + g2 === 0) return 0.5;
  return g1 / (g1 + g2);
}

/**
 * Inverts a positive-definite square matrix with ridge regularization
 */
function invertMatrixWithRidge(matrix: number[][], ridge: number = 1e-4): number[][] {
  const n = matrix.length;
  const A: number[][] = matrix.map((row, i) =>
    row.map((val, j) => val + (i === j ? ridge : 0))
  );
  const inv: number[][] = Array.from({ length: n }, (_, i) =>
    Array.from({ length: n }, (_, j) => (i === j ? 1 : 0))
  );

  for (let i = 0; i < n; i++) {
    let maxRow = i;
    for (let k = i + 1; k < n; k++) {
      if (Math.abs(A[k][i]) > Math.abs(A[maxRow][i])) {
        maxRow = k;
      }
    }
    if (Math.abs(A[maxRow][i]) < 1e-12) {
      // Degenerate matrix, return identity as fallback
      return Array.from({ length: n }, (_, r) =>
        Array.from({ length: n }, (_, c) => (r === c ? 1 : 0))
      );
    }

    if (maxRow !== i) {
      [A[i], A[maxRow]] = [A[maxRow], A[i]];
      [inv[i], inv[maxRow]] = [inv[maxRow], inv[i]];
    }

    const pivot = A[i][i];
    for (let j = 0; j < n; j++) {
      A[i][j] /= pivot;
      inv[i][j] /= pivot;
    }

    for (let k = 0; k < n; k++) {
      if (k === i) continue;
      const factor = A[k][i];
      for (let j = 0; j < n; j++) {
        A[k][j] -= factor * A[i][j];
        inv[k][j] -= factor * inv[i][j];
      }
    }
  }

  return inv;
}

/**
 * Matrix-vector product
 */
function matVecMul(matrix: number[][], vector: number[]): number[] {
  return matrix.map((row) =>
    row.reduce((sum, val, idx) => sum + val * vector[idx], 0)
  );
}

/**
 * Quadratic form x^T M x
 */
function quadForm(vector: number[], matrix: number[][]): number {
  const mv = matVecMul(matrix, vector);
  return vector.reduce((sum, val, idx) => sum + val * mv[idx], 0);
}

export class ContextualBanditPolicyEngine {
  private inMemoryArms: Map<string, BanditArmState> = new Map();
  private dbInitialized = false;

  constructor() {
    this.ensureDatabaseSchema();
  }

  public ensureDatabaseSchema(): void {
    if (this.dbInitialized) return;
    const db = getDb();
    if (!db) return;

    try {
      db.prepare(`
        CREATE TABLE IF NOT EXISTS ejii_bandit_action_posteriors (
          arm_id TEXT PRIMARY KEY,
          action_type TEXT NOT NULL,
          pulls INTEGER NOT NULL DEFAULT 0,
          successes INTEGER NOT NULL DEFAULT 0,
          failures INTEGER NOT NULL DEFAULT 0,
          alpha REAL NOT NULL DEFAULT 1.0,
          beta REAL NOT NULL DEFAULT 1.0,
          cumulative_reward REAL NOT NULL DEFAULT 0.0,
          last_reward REAL NOT NULL DEFAULT 0.0,
          matrix_a_json TEXT,
          vector_b_json TEXT,
          theta_hat_json TEXT,
          updated_at TEXT NOT NULL
        )
      `).run();
      this.dbInitialized = true;
    } catch (_) {}
  }

  /**
   * Constructs normalized feature vector x \in R^4
   */
  public buildContextVector(params: ContextVectorParams): number[] {
    const rawEnergy = Math.max(0, params.lyapunovEnergy ?? 10.0);
    const vNorm = Number(Math.min(1.0, rawEnergy / 100.0).toFixed(4));

    const rawHurst = Math.max(0.5, Math.min(1.0, params.hurstParameter ?? 0.75));
    const hNorm = Number(((rawHurst - 0.5) * 2.0).toFixed(4)); // [0, 1]

    const depth = Math.max(0, params.queueDepthPackets ?? 30.0);
    const capacity = Math.max(1, params.bufferCapacityPackets ?? 100.0);
    const cliffNorm = Number(Math.min(1.0, depth / capacity).toFixed(4));

    const blastNorm = Number(Math.max(0.0, Math.min(1.0, params.blastRadiusRisk ?? 0.2)).toFixed(4));

    return [vNorm, hNorm, cliffNorm, blastNorm];
  }

  /**
   * Registers or loads an arm state from SQLite WAL or in-memory cache
   */
  public registerOrGetArm(armId: string, actionType?: string): BanditArmState {
    if (this.inMemoryArms.has(armId)) {
      return this.inMemoryArms.get(armId)!;
    }

    const type = actionType || armId;
    const db = getDb();
    if (db) {
      try {
        const row = db.prepare('SELECT * FROM ejii_bandit_action_posteriors WHERE arm_id = ?').get(armId);
        if (row) {
          const arm: BanditArmState = {
            armId: row.arm_id,
            actionType: row.action_type,
            pulls: row.pulls,
            successes: row.successes,
            failures: row.failures,
            alpha: row.alpha,
            beta: row.beta,
            cumulativeReward: row.cumulative_reward,
            lastReward: row.last_reward,
            matrixA: row.matrix_a_json ? JSON.parse(row.matrix_a_json) : this.createIdentityMatrix(FEATURE_DIMENSION),
            vectorB: row.vector_b_json ? JSON.parse(row.vector_b_json) : new Array(FEATURE_DIMENSION).fill(0),
            thetaHat: row.theta_hat_json ? JSON.parse(row.theta_hat_json) : new Array(FEATURE_DIMENSION).fill(0),
            updatedAtIso: row.updated_at
          };
          this.inMemoryArms.set(armId, arm);
          return arm;
        }
      } catch (_) {}
    }

    // Default initialization: Beta(1, 1), A = I_d, b = 0_d
    const initialArm: BanditArmState = {
      armId,
      actionType: type,
      pulls: 0,
      successes: 0,
      failures: 0,
      alpha: 1.0,
      beta: 1.0,
      cumulativeReward: 0.0,
      lastReward: 0.0,
      matrixA: this.createIdentityMatrix(FEATURE_DIMENSION),
      vectorB: new Array(FEATURE_DIMENSION).fill(0),
      thetaHat: new Array(FEATURE_DIMENSION).fill(0),
      updatedAtIso: new Date().toISOString()
    };

    this.inMemoryArms.set(armId, initialArm);
    this.persistArm(initialArm);
    return initialArm;
  }

  /**
   * Evaluates candidate arms and selects the optimal action
   */
  public selectAction(
    candidateArms: (string | { armId: string; actionType?: string })[],
    context: number[] | ContextVectorParams,
    options?: {
      algorithm?: 'THOMPSON_SAMPLING' | 'LIN_UCB' | 'HYBRID_BANDIT';
      alphaUcb?: number;
    }
  ): BanditSelectionResult {
    if (!candidateArms || candidateArms.length === 0) {
      throw new Error('Candidate arms list cannot be empty for bandit policy selection');
    }

    const contextVector = Array.isArray(context) ? context : this.buildContextVector(context);
    const algorithm = options?.algorithm || 'HYBRID_BANDIT';
    const alphaUcb = options?.alphaUcb ?? 1.25;

    const evaluations: BanditArmEvaluation[] = [];

    for (const candidate of candidateArms) {
      const armId = typeof candidate === 'string' ? candidate : candidate.armId;
      const actionType = typeof candidate === 'string' ? candidate : (candidate.actionType || candidate.armId);
      const arm = this.registerOrGetArm(armId, actionType);

      // 1. Thompson Sampling draw
      const tsDraw = sampleBeta(arm.alpha, arm.beta);

      // 2. LinUCB calculation: UCB = theta^T x + alpha * sqrt(x^T A^{-1} x)
      const invA = invertMatrixWithRidge(arm.matrixA);
      const theta = matVecMul(invA, arm.vectorB);
      arm.thetaHat = theta;

      const expectedPayoff = contextVector.reduce((sum, x_i, idx) => sum + x_i * theta[idx], 0);
      const qf = quadForm(contextVector, invA);
      const confidenceRadius = alphaUcb * Math.sqrt(Math.max(0, qf));
      const linUcbScore = expectedPayoff + confidenceRadius;

      // 3. Combined / Hybrid Score
      let combinedScore = 0;
      if (algorithm === 'THOMPSON_SAMPLING') {
        combinedScore = tsDraw;
      } else if (algorithm === 'LIN_UCB') {
        combinedScore = linUcbScore;
      } else {
        // Hybrid: 50% Thompson sampling posterior draw + 50% contextual upper bound
        combinedScore = 0.5 * tsDraw + 0.5 * Math.tanh(linUcbScore);
      }

      evaluations.push({
        armId,
        actionType,
        thompsonSample: Number(tsDraw.toFixed(4)),
        linUcbScore: Number(linUcbScore.toFixed(4)),
        linUcbConfidence: Number(confidenceRadius.toFixed(4)),
        combinedScore: Number(combinedScore.toFixed(4)),
        alpha: Number(arm.alpha.toFixed(2)),
        beta: Number(arm.beta.toFixed(2)),
        expectedMean: Number((arm.alpha / (arm.alpha + arm.beta)).toFixed(4))
      });
    }

    // Sort descending by combined score
    evaluations.sort((a, b) => b.combinedScore - a.combinedScore);

    const winner = evaluations[0];
    const winningArm = this.inMemoryArms.get(winner.armId)!;
    winningArm.lastSelectedIso = new Date().toISOString();

    return {
      selectedArmId: winner.armId,
      selectedActionType: winner.actionType,
      contextVector,
      algorithmUsed: algorithm,
      evaluations,
      confidenceRadius: winner.linUcbConfidence,
      selectionTimestampIso: winningArm.lastSelectedIso,
      explorationBonusApplied: winner.linUcbConfidence > 0.5 || winningArm.pulls < 3
    };
  }

  /**
   * Records observed reward and updates Bayesian posteriors
   */
  public recordReward(observation: RewardObservation): BanditUpdateResult {
    const arm = this.registerOrGetArm(observation.armId);
    const context = observation.contextVector || [0.5, 0.5, 0.5, 0.2];

    let rawReward = 0;
    if (!observation.success || observation.rollbackOccurred) {
      rawReward = -1.0;
    } else {
      const vBefore = Math.max(0.1, observation.energyBefore ?? 10.0);
      const deltaRatio = Math.max(-1.0, Math.min(1.0, observation.deltaV / vBefore));
      // deltaV < 0 is contraction (good!), so negative deltaV contributes positive reward
      const energyGain = -deltaRatio;

      const blast = Math.max(0, Math.min(1.0, observation.blastRadius ?? 0.2));
      const durationNorm = Math.min(1.0, (observation.executionDurationMs ?? 200) / 3000.0);

      // Reward function: 0.60 * energyGain - 0.25 * blast - 0.15 * duration
      rawReward = 0.60 * energyGain - 0.25 * blast - 0.15 * durationNorm;
    }

    // Bound raw reward in [-1.0, 1.0]
    rawReward = Math.max(-1.0, Math.min(1.0, rawReward));

    // Normalized reward in [0, 1] for Beta conjugate update
    const normalizedReward = (rawReward + 1.0) / 2.0;

    // Beta update: alpha += normReward, beta += (1 - normReward)
    arm.pulls += 1;
    if (observation.success && !observation.rollbackOccurred) {
      arm.successes += 1;
      arm.alpha += normalizedReward;
      arm.beta += (1.0 - normalizedReward);
    } else {
      arm.failures += 1;
      arm.alpha += 0.05;
      arm.beta += 0.95;
    }

    // LinUCB update: A += x x^T, b += rawReward * x
    const d = FEATURE_DIMENSION;
    for (let i = 0; i < d; i++) {
      arm.vectorB[i] += rawReward * context[i];
      for (let j = 0; j < d; j++) {
        arm.matrixA[i][j] += context[i] * context[j];
      }
    }

    arm.cumulativeReward = Number((arm.cumulativeReward + rawReward).toFixed(4));
    arm.lastReward = Number(rawReward.toFixed(4));
    arm.updatedAtIso = new Date().toISOString();

    // Recompute theta
    const invA = invertMatrixWithRidge(arm.matrixA);
    arm.thetaHat = matVecMul(invA, arm.vectorB);

    this.persistArm(arm);

    return {
      armId: arm.armId,
      rawReward: arm.lastReward,
      normalizedReward: Number(normalizedReward.toFixed(4)),
      posteriorAlpha: Number(arm.alpha.toFixed(2)),
      posteriorBeta: Number(arm.beta.toFixed(2)),
      totalPulls: arm.pulls,
      cumulativeReward: arm.cumulativeReward,
      updatedAtIso: arm.updatedAtIso
    };
  }

  public getArmState(armId: string): BanditArmState | null {
    if (this.inMemoryArms.has(armId)) {
      return this.inMemoryArms.get(armId)!;
    }
    const db = getDb();
    if (db) {
      try {
        const row = db.prepare('SELECT * FROM ejii_bandit_action_posteriors WHERE arm_id = ?').get(armId);
        if (row) {
          return this.registerOrGetArm(armId, row.action_type);
        }
      } catch (_) {}
    }
    return null;
  }

  public getAllArms(): BanditArmState[] {
    return Array.from(this.inMemoryArms.values());
  }

  public resetForTesting(): void {
    this.inMemoryArms.clear();
    const db = getDb();
    if (db) {
      try {
        db.prepare('DELETE FROM ejii_bandit_action_posteriors').run();
      } catch (_) {}
    }
  }

  private createIdentityMatrix(dim: number): number[][] {
    return Array.from({ length: dim }, (_, i) =>
      Array.from({ length: dim }, (_, j) => (i === j ? 1 : 0))
    );
  }

  private persistArm(arm: BanditArmState): void {
    const db = getDb();
    if (!db) return;
    try {
      db.prepare(`
        INSERT INTO ejii_bandit_action_posteriors (
          arm_id, action_type, pulls, successes, failures,
          alpha, beta, cumulative_reward, last_reward,
          matrix_a_json, vector_b_json, theta_hat_json, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(arm_id) DO UPDATE SET
          action_type = excluded.action_type,
          pulls = excluded.pulls,
          successes = excluded.successes,
          failures = excluded.failures,
          alpha = excluded.alpha,
          beta = excluded.beta,
          cumulative_reward = excluded.cumulative_reward,
          last_reward = excluded.last_reward,
          matrix_a_json = excluded.matrix_a_json,
          vector_b_json = excluded.vector_b_json,
          theta_hat_json = excluded.theta_hat_json,
          updated_at = excluded.updated_at
      `).run(
        arm.armId,
        arm.actionType,
        arm.pulls,
        arm.successes,
        arm.failures,
        arm.alpha,
        arm.beta,
        arm.cumulativeReward,
        arm.lastReward,
        JSON.stringify(arm.matrixA),
        JSON.stringify(arm.vectorB),
        JSON.stringify(arm.thetaHat),
        arm.updatedAtIso
      );
    } catch (_) {}
  }
}

export const contextualBanditPolicy = new ContextualBanditPolicyEngine();
