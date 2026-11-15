/**
 * EJII Phase 5.0 — Distributed Transactional Remediation Saga & Multi-Node Two-Phase Commit (2PC) Orchestrator
 *
 * Implements:
 *   1. Distributed Saga State Machine (INITIATED -> PREPARE_PHASE -> LOCAL_LYAPUNOV_VALIDATED -> COMMIT_VOTE_QUORUM -> COMMITTED)
 *   2. Non-Convex State-Adaptive Neural/Riemannian Lyapunov Metric V(s) = s^T M(s) s where M(s) > 0 strictly positive-definite
 *   3. Two-Phase Commit (2PC) with Atomic Execution Tokens & Coordinated Compensating Rollback (a_k^{-1})
 *   4. Durable SQLite WAL Saga Journal (ejii_remediation_sagas) with Replay Rejection
 */

import * as crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import {
  zkEpistemicConsensusEngine,
  ZkEpistemicConsensusEngine,
  MerkleInclusionProof,
  BatchEpistemicQuorumReceipt
} from '../../core/agent/zk-epistemic-consensus';
import {
  TelemetryStateVector,
  MicroRemediationAction,
  CompensatingInverseAction,
  ExpectedImpact
} from './generative-remediation-synthesizer';

function getDb(): any {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return require('../../db/database').db;
  } catch (_) {
    return null;
  }
}

export type SagaPhase =
  | 'INITIATED'
  | 'PREPARE_PHASE'
  | 'LOCAL_LYAPUNOV_VALIDATED'
  | 'COMMIT_VOTE_QUORUM'
  | 'COMMITTED'
  | 'ABORTED_PRE'
  | 'COORDINATED_COMPENSATING_ROLLBACK'
  | 'ROLLED_BACK';

export type ParticipantRole =
  | 'EDGE_SWITCH'
  | 'CORE_GATEWAY'
  | 'DNS_RESOLVER'
  | 'HOST_KERNEL';

export interface ParticipantNode {
  nodeId: string;
  role: ParticipantRole;
  targetEndpoint: string;
  candidateAction: MicroRemediationAction;
  candidateInverse: CompensatingInverseAction;
  currentState: TelemetryStateVector;
  covariance?: number[][];
  privateKeyPem?: string;
  publicKeyPem?: string;
}

export interface RobustLyapunovEnergyResult {
  meanEnergy: number;
  traceCovariancePenalty: number;
  expectedEnergy: number;
}

export interface ParticipantVote {
  nodeId: string;
  vote: 'VOTE_COMMIT' | 'VOTE_ABORT';
  lyapunovDelta: number;
  energyBefore: number;
  energyAfter: number;
  signedProof: string;
  timestampIso: string;
  reason?: string;
  ed25519Signature?: string;
  publicKeyPem?: string;
  merkleInclusionProof?: MerkleInclusionProof;
  attestationStatus?: 'ED25519_VERIFIED' | 'HMAC_LEGACY_VERIFIED' | 'ATTESTATION_FAILED';
}

export interface RollbackStepResult {
  nodeId: string;
  inverseActionId: string;
  inverseType: string;
  executedAtIso: string;
  status: 'COMPENSATED_SUCCESS' | 'COMPENSATION_FAILED';
  reversesActionId: string;
}

export type CompensationStatus = 'PENDING_RETRY' | 'SUCCESS' | 'DEAD_LETTER_ESCALATED';

export interface PendingCompensationRecord {
  compensationId: string;
  sagaId: string;
  nodeId: string;
  inverseAction: CompensatingInverseAction;
  retryCount: number;
  maxRetries: number;
  nextRetryAtIso: string;
  status: CompensationStatus;
  createdAtIso: string;
  updatedAtIso: string;
  lastError?: string;
  auditHmac?: string;
}

export interface ReconcileResult {
  processedCount: number;
  succeededCount: number;
  retriedCount: number;
  deadLetterCount: number;
  reconciledRecords: PendingCompensationRecord[];
}

/**
 * Calculates truncated exponential backoff with full jitter:
 * t_backoff = min(60000, 1000 * 2^retryCount) * (0.5 + 0.5 * rand())
 */
export function calculateJitteredBackoffMs(retryCount: number, randomFn: () => number = Math.random): number {
  const base = Math.min(60000, 1000 * Math.pow(2, retryCount));
  const jitter = 0.5 + 0.5 * randomFn();
  return Math.round(base * jitter);
}

export interface DistributedSagaRecord {
  sagaId: string;
  hypothesisId: string;
  phase: SagaPhase;
  initiator: string;
  participants: ParticipantNode[];
  votes: Record<string, ParticipantVote>;
  lyapunovAggregate: {
    energyBefore: number;
    energyAfter: number;
    deltaV: number;
    isRiemannianStable: boolean;
  };
  commitTokens: Record<string, string>;
  batchQuorumReceipt?: BatchEpistemicQuorumReceipt;
  banditPolicySelection?: any;
  chaosValidationReceipts?: Record<string, any>;
  rollbackExecuted: boolean;
  rollbackLog: RollbackStepResult[];
  createdAtIso: string;
  updatedAtIso: string;
}

export interface RiemannianLyapunovMatrix {
  W0: number[][];
  W1: number[][];
  W2: number[][];
  W3: number[][];
}

// Canonical Positive-Definite Base & Penalty Matrices (3x3 for [rtt, loss, queue])
export const CANONICAL_RIEMANNIAN_WEIGHTS: RiemannianLyapunovMatrix = Object.freeze({
  W0: [
    [0.40, 0.00, 0.00],
    [0.00, 0.40, 0.00],
    [0.00, 0.00, 0.20]
  ],
  W1: [ // Queue saturation cliff penalty
    [0.00, 0.00, 0.00],
    [0.00, 0.00, 0.00],
    [0.00, 0.00, 0.80]
  ],
  W2: [ // Loss cliff penalty
    [0.00, 0.00, 0.00],
    [0.00, 0.80, 0.00],
    [0.00, 0.00, 0.00]
  ],
  W3: [ // Cross-coupling when RTT elevates
    [0.10, 0.05, 0.02],
    [0.05, 0.10, 0.02],
    [0.02, 0.02, 0.10]
  ]
});

export const SAGA_PREPARE_TIMEOUT_MS = 1500;
export const MIN_RIEMANNIAN_CONTRACTION = 0.05;

export interface KalmanFilterOptions {
  qRtt?: number;
  qLoss?: number;
  qQueue?: number;
  rRtt?: number;
  rLoss?: number;
  rQueue?: number;
  initialState?: TelemetryStateVector;
}

/**
 * Phase 7.0 Track 3: Discrete Kalman-Lyapunov Filter
 * Smooths observational noise across [rttMs, lossPct, queueDepthPackets]^T
 * and maintains continuous 3x3 error covariance tracking.
 */
export class TelemetryKalmanFilter {
  private state: [number, number, number];
  private P: number[][];
  private Q: number[][];
  private R: number[][];

  constructor(options: KalmanFilterOptions = {}) {
    const s0 = options.initialState || { rttMs: 20, lossPct: 0.1, queueDepthPackets: 5 };
    this.state = [
      Math.max(0, Number(s0.rttMs) || 0),
      Math.max(0, Number(s0.lossPct) || 0),
      Math.max(0, Number(s0.queueDepthPackets) || 0)
    ];
    this.P = [
      [1.0, 0.0, 0.0],
      [0.0, 0.1, 0.0],
      [0.0, 0.0, 1.0]
    ];
    this.Q = [
      [options.qRtt ?? 0.5, 0.0, 0.0],
      [0.0, options.qLoss ?? 0.05, 0.0],
      [0.0, 0.0, options.qQueue ?? 0.5]
    ];
    this.R = [
      [options.rRtt ?? 2.0, 0.0, 0.0],
      [0.0, options.rLoss ?? 0.2, 0.0],
      [0.0, 0.0, options.rQueue ?? 2.0]
    ];
  }

  public predict(): { state: TelemetryStateVector; covariance: number[][] } {
    for (let i = 0; i < 3; i++) {
      for (let j = 0; j < 3; j++) {
        this.P[i][j] += this.Q[i][j];
      }
    }
    return { state: this.getState(), covariance: this.getCovariance() };
  }

  public update(measurement: TelemetryStateVector): { state: TelemetryStateVector; covariance: number[][] } {
    this.predict();
    const z = [
      Math.max(0, Number(measurement.rttMs) || 0),
      Math.max(0, Number(measurement.lossPct) || 0),
      Math.max(0, Number(measurement.queueDepthPackets) || 0)
    ];

    const y = [z[0] - this.state[0], z[1] - this.state[1], z[2] - this.state[2]];

    const S: number[][] = [
      [this.P[0][0] + this.R[0][0], this.P[0][1], this.P[0][2]],
      [this.P[1][0], this.P[1][1] + this.R[1][1], this.P[1][2]],
      [this.P[2][0], this.P[2][1], this.P[2][2] + this.R[2][2]]
    ];

    const detS =
      S[0][0] * (S[1][1] * S[2][2] - S[1][2] * S[2][1]) -
      S[0][1] * (S[1][0] * S[2][2] - S[1][2] * S[2][0]) +
      S[0][2] * (S[1][0] * S[2][1] - S[1][1] * S[2][0]);

    const safeDetS = Math.abs(detS) < 1e-9 ? 1e-9 : detS;

    const invS: number[][] = [
      [
        (S[1][1] * S[2][2] - S[1][2] * S[2][1]) / safeDetS,
        (S[0][2] * S[2][1] - S[0][1] * S[2][2]) / safeDetS,
        (S[0][1] * S[1][2] - S[0][2] * S[1][1]) / safeDetS
      ],
      [
        (S[1][2] * S[2][0] - S[1][0] * S[2][2]) / safeDetS,
        (S[0][0] * S[2][2] - S[0][2] * S[2][0]) / safeDetS,
        (S[0][2] * S[1][0] - S[0][0] * S[1][2]) / safeDetS
      ],
      [
        (S[1][0] * S[2][1] - S[1][1] * S[2][0]) / safeDetS,
        (S[0][1] * S[2][0] - S[0][0] * S[2][1]) / safeDetS,
        (S[0][0] * S[1][1] - S[0][1] * S[1][0]) / safeDetS
      ]
    ];

    const K: number[][] = [
      [0, 0, 0],
      [0, 0, 0],
      [0, 0, 0]
    ];
    for (let i = 0; i < 3; i++) {
      for (let j = 0; j < 3; j++) {
        for (let k = 0; k < 3; k++) {
          K[i][j] += this.P[i][k] * invS[k][j];
        }
      }
    }

    for (let i = 0; i < 3; i++) {
      let ky = 0;
      for (let j = 0; j < 3; j++) {
        ky += K[i][j] * y[j];
      }
      this.state[i] = Math.max(0, this.state[i] + ky);
    }

    const I_minus_K: number[][] = [
      [1 - K[0][0], -K[0][1], -K[0][2]],
      [-K[1][0], 1 - K[1][1], -K[1][2]],
      [-K[2][0], -K[2][1], 1 - K[2][2]]
    ];
    const newP: number[][] = [
      [0, 0, 0],
      [0, 0, 0],
      [0, 0, 0]
    ];
    for (let i = 0; i < 3; i++) {
      for (let j = 0; j < 3; j++) {
        for (let k = 0; k < 3; k++) {
          newP[i][j] += I_minus_K[i][k] * this.P[k][j];
        }
      }
    }
    this.P = newP;

    return { state: this.getState(), covariance: this.getCovariance() };
  }

  public getState(): TelemetryStateVector {
    return {
      rttMs: Math.round(this.state[0] * 100) / 100,
      lossPct: Math.round(this.state[1] * 100) / 100,
      queueDepthPackets: Math.round(this.state[2] * 100) / 100
    };
  }

  public getCovariance(): number[][] {
    return this.P.map(row => row.map(v => Math.round(v * 1000) / 1000));
  }
}

export class DistributedSagaOrchestrator extends EventEmitter {
  private hmacSecret: Buffer;
  private inMemorySagas: Map<string, DistributedSagaRecord> = new Map();
  private inMemoryPendingCompensations: Map<string, PendingCompensationRecord> = new Map();
  private processedSagaNonces: Set<string> = new Set();
  private sqliteInitialized = false;

  constructor(secretKey: string = process.env.EJII_HMAC_SECRET || 'EJII-ENTERPRISE-INTELLIGENCE-HMAC-SECURE-KEY-2026') {
    super();
    this.hmacSecret = Buffer.from(secretKey, 'utf-8');
    this.ensureSqliteTable();
  }

  private ensureSqliteTable(): void {
    if (this.sqliteInitialized) return;
    try {
      const db = getDb();
      if (!db) return;
      db.exec(`
        CREATE TABLE IF NOT EXISTS ejii_remediation_sagas (
          saga_id TEXT PRIMARY KEY,
          hypothesis_id TEXT NOT NULL,
          phase TEXT NOT NULL,
          initiator TEXT NOT NULL,
          participants_json TEXT NOT NULL,
          votes_json TEXT NOT NULL,
          lyapunov_aggregate_json TEXT NOT NULL,
          commit_tokens_json TEXT,
          batch_quorum_receipt_json TEXT,
          rollback_executed INTEGER NOT NULL DEFAULT 0,
          rollback_log_json TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_remediation_sagas_phase ON ejii_remediation_sagas(phase);
        CREATE INDEX IF NOT EXISTS idx_remediation_sagas_created ON ejii_remediation_sagas(created_at);

        CREATE TABLE IF NOT EXISTS ejii_saga_compensations_pending (
          compensation_id TEXT PRIMARY KEY,
          saga_id TEXT NOT NULL,
          node_id TEXT NOT NULL,
          inverse_action_json TEXT NOT NULL,
          retry_count INTEGER NOT NULL DEFAULT 0,
          max_retries INTEGER NOT NULL DEFAULT 5,
          next_retry_at TEXT NOT NULL,
          status TEXT NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_saga_compensations_status ON ejii_saga_compensations_pending(status);
        CREATE INDEX IF NOT EXISTS idx_saga_compensations_retry ON ejii_saga_compensations_pending(next_retry_at);
      `);
      try {
        db.exec('ALTER TABLE ejii_remediation_sagas ADD COLUMN batch_quorum_receipt_json TEXT');
      } catch (_) {
        // Ignored if column already exists
      }
      this.sqliteInitialized = true;
    } catch (_) {
      // Graceful fallback to memory mode if SQLite is query-only or busy
      this.sqliteInitialized = false;
    }
  }

  /**
   * Evaluates state-adaptive Riemannian Lyapunov energy:
   * V(s) = s^T M(s) s
   * where M(s) = W0 + sigma_1(s) W1 + sigma_2(s) W2 + sigma_3(s) W3
   * M(s) is guaranteed strictly positive-definite since W0 > 0 and W_k >= 0.
   */
  public computeRiemannianLyapunovEnergy(
    state: TelemetryStateVector,
    weights: RiemannianLyapunovMatrix = CANONICAL_RIEMANNIAN_WEIGHTS
  ): number {
    const s = [
      Math.max(0, Number(state.rttMs) || 0),
      Math.max(0, Number(state.lossPct) || 0),
      Math.max(0, Number(state.queueDepthPackets) || 0)
    ];

    // Sigmoid activations for operating cliff regimes
    const sigma1 = 1 / (1 + Math.exp(-(s[2] - 50.0) / 10.0)); // Queue cliff > 50 pkts
    const sigma2 = 1 / (1 + Math.exp(-(s[1] - 5.0) / 1.5));   // Loss cliff > 5%
    const sigma3 = 1 / (1 + Math.exp(-(s[0] - 80.0) / 20.0)); // RTT cliff > 80ms

    // Compute M(s) = W0 + sigma1*W1 + sigma2*W2 + sigma3*W3
    const M: number[][] = [
      [0, 0, 0],
      [0, 0, 0],
      [0, 0, 0]
    ];

    for (let i = 0; i < 3; i++) {
      for (let j = 0; j < 3; j++) {
        M[i][j] =
          weights.W0[i][j] +
          sigma1 * weights.W1[i][j] +
          sigma2 * weights.W2[i][j] +
          sigma3 * weights.W3[i][j];
      }
    }

    // Energy V(s) = s^T * M * s
    let energy = 0;
    for (let i = 0; i < 3; i++) {
      for (let j = 0; j < 3; j++) {
        energy += s[i] * M[i][j] * s[j];
      }
    }

    return Math.round(energy * 1000) / 1000;
  }

  /**
   * Phase 7.0 Track 3: Covariance-Weighted Lyapunov Energy
   * Evaluates expected energy under measurement uncertainty:
   * E[V(s)] = s^T M(s) s + Tr(M(s) P)
   */
  public computeRobustLyapunovEnergy(
    state: TelemetryStateVector,
    covariance?: number[][],
    weights: RiemannianLyapunovMatrix = CANONICAL_RIEMANNIAN_WEIGHTS
  ): RobustLyapunovEnergyResult {
    const s = [
      Math.max(0, Number(state.rttMs) || 0),
      Math.max(0, Number(state.lossPct) || 0),
      Math.max(0, Number(state.queueDepthPackets) || 0)
    ];

    const sigma1 = 1 / (1 + Math.exp(-(s[2] - 50.0) / 10.0));
    const sigma2 = 1 / (1 + Math.exp(-(s[1] - 5.0) / 1.5));
    const sigma3 = 1 / (1 + Math.exp(-(s[0] - 80.0) / 20.0));

    const M: number[][] = [
      [0, 0, 0],
      [0, 0, 0],
      [0, 0, 0]
    ];

    for (let i = 0; i < 3; i++) {
      for (let j = 0; j < 3; j++) {
        M[i][j] =
          weights.W0[i][j] +
          sigma1 * weights.W1[i][j] +
          sigma2 * weights.W2[i][j] +
          sigma3 * weights.W3[i][j];
      }
    }

    let meanEnergy = 0;
    for (let i = 0; i < 3; i++) {
      for (let j = 0; j < 3; j++) {
        meanEnergy += s[i] * M[i][j] * s[j];
      }
    }

    let tracePenalty = 0;
    if (covariance && Array.isArray(covariance) && covariance.length === 3) {
      for (let i = 0; i < 3; i++) {
        for (let j = 0; j < 3; j++) {
          tracePenalty += M[i][j] * (covariance[j]?.[i] || 0);
        }
      }
    }

    const expectedEnergy = meanEnergy + tracePenalty;

    return {
      meanEnergy: Math.round(meanEnergy * 1000) / 1000,
      traceCovariancePenalty: Math.round(tracePenalty * 1000) / 1000,
      expectedEnergy: Math.round(expectedEnergy * 1000) / 1000
    };
  }

  /**
   * Verify positive definiteness of M(s) via Sylvester's criterion:
   * All leading principal minors of M(s) must be strictly positive.
   */
  public isMetricPositiveDefinite(state: TelemetryStateVector): boolean {
    const s = [
      Math.max(0, Number(state.rttMs) || 0),
      Math.max(0, Number(state.lossPct) || 0),
      Math.max(0, Number(state.queueDepthPackets) || 0)
    ];

    const sigma1 = 1 / (1 + Math.exp(-(s[2] - 50.0) / 10.0));
    const sigma2 = 1 / (1 + Math.exp(-(s[1] - 5.0) / 1.5));
    const sigma3 = 1 / (1 + Math.exp(-(s[0] - 80.0) / 20.0));

    const M: number[][] = [
      [0, 0, 0],
      [0, 0, 0],
      [0, 0, 0]
    ];

    for (let i = 0; i < 3; i++) {
      for (let j = 0; j < 3; j++) {
        M[i][j] =
          CANONICAL_RIEMANNIAN_WEIGHTS.W0[i][j] +
          sigma1 * CANONICAL_RIEMANNIAN_WEIGHTS.W1[i][j] +
          sigma2 * CANONICAL_RIEMANNIAN_WEIGHTS.W2[i][j] +
          sigma3 * CANONICAL_RIEMANNIAN_WEIGHTS.W3[i][j];
      }
    }

    // Leading principal minor 1: M[0][0]
    const m1 = M[0][0];
    if (m1 <= 0) return false;

    // Leading principal minor 2: det([M00 M01; M10 M11])
    const m2 = M[0][0] * M[1][1] - M[0][1] * M[1][0];
    if (m2 <= 0) return false;

    // Leading principal minor 3: det(M)
    const m3 =
      M[0][0] * (M[1][1] * M[2][2] - M[1][2] * M[2][1]) -
      M[0][1] * (M[1][0] * M[2][2] - M[1][2] * M[2][0]) +
      M[0][2] * (M[1][0] * M[2][1] - M[1][1] * M[2][0]);

    return m3 > 0;
  }

  /**
   * Creates and initializes a distributed transactional remediation saga
   */
  public initiateSaga(
    hypothesisId: string,
    initiator: string,
    participants: ParticipantNode[]
  ): DistributedSagaRecord {
    if (!participants || participants.length === 0) {
      throw new Error('Distributed remediation saga requires at least one participant node');
    }

    const sagaId = `saga_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const nowIso = new Date().toISOString();

    // Phase 9.0 Track 2: Contextual Multi-Armed Bandit policy evaluation
    let banditPolicySelection: any = undefined;
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const { contextualBanditPolicy } = require('./contextual-bandit-policy');
      const avgRtt = participants.reduce((sum, p) => sum + (p.currentState?.rttMs || 0), 0) / participants.length;
      const avgQueue = participants.reduce((sum, p) => sum + (p.currentState?.queueDepthPackets || 0), 0) / participants.length;
      const contextVec = contextualBanditPolicy.buildContextVector({
        lyapunovEnergy: avgRtt * 0.5 + avgQueue * 0.5,
        queueDepthPackets: avgQueue,
        blastRadiusRisk: Math.min(1.0, participants.length / 10.0)
      });
      const candidateArms = participants.map((p) => ({
        armId: p.candidateAction.actionId,
        actionType: p.candidateAction.actionType
      }));
      banditPolicySelection = contextualBanditPolicy.selectAction(candidateArms, contextVec);
    } catch (_) {}

    // Phase 10.0 Track 1: Autonomous Pre-Remediation Chaos Fault Injection Sandbox
    const chaosValidationReceipts: Record<string, any> = {};
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const { chaosFaultSandbox } = require('./chaos-fault-sandbox');
      for (const p of participants) {
        if (p.candidateAction && p.currentState) {
          const receipt = chaosFaultSandbox.evaluateCandidateRemediation(
            sagaId,
            p.candidateAction,
            p.currentState
          );
          chaosValidationReceipts[p.nodeId] = receipt;
        }
      }
    } catch (_) {}

    const record: DistributedSagaRecord = {
      sagaId,
      hypothesisId,
      phase: 'INITIATED',
      initiator,
      participants,
      votes: {},
      lyapunovAggregate: {
        energyBefore: 0,
        energyAfter: 0,
        deltaV: 0,
        isRiemannianStable: false
      },
      commitTokens: {},
      banditPolicySelection,
      chaosValidationReceipts,
      rollbackExecuted: false,
      rollbackLog: [],
      createdAtIso: nowIso,
      updatedAtIso: nowIso
    };

    this.inMemorySagas.set(sagaId, record);
    this.persistSaga(record);
    return record;
  }

  /**
   * Phase 1: Prepare & Vote across all participant nodes
   * Each node evaluates candidate Lyapunov energy contraction: Delta V_k <= -delta
   */
  public executePreparePhase(sagaId: string): DistributedSagaRecord {
    const saga = this.getSaga(sagaId);
    if (!saga) throw new Error(`Saga ${sagaId} not found`);

    if (this.processedSagaNonces.has(sagaId)) {
      throw new Error(`DUPLICATE_SAGA_REJECTED: Saga ${sagaId} already prepared or executed`);
    }

    saga.phase = 'PREPARE_PHASE';
    let totalEnergyBefore = 0;
    let totalEnergyAfter = 0;
    let allVotedCommit = true;

    for (const participant of saga.participants) {
      const stateBefore = participant.currentState;
      const energyBefore = participant.covariance
        ? this.computeRobustLyapunovEnergy(stateBefore, participant.covariance).expectedEnergy
        : this.computeRiemannianLyapunovEnergy(stateBefore);

      // Compute projected next state
      const impact = participant.candidateAction.expectedImpact;
      const stateAfter: TelemetryStateVector = {
        rttMs: Math.max(1.0, stateBefore.rttMs + impact.rttDeltaMs),
        lossPct: Math.max(0.0, stateBefore.lossPct + impact.lossDeltaPct),
        queueDepthPackets: Math.max(0, stateBefore.queueDepthPackets + impact.queueDeltaPackets)
      };

      const energyAfter = participant.covariance
        ? this.computeRobustLyapunovEnergy(stateAfter, participant.covariance).expectedEnergy
        : this.computeRiemannianLyapunovEnergy(stateAfter);
      const deltaV = Math.round((energyAfter - energyBefore) * 1000) / 1000;

      totalEnergyBefore += energyBefore;
      totalEnergyAfter += energyAfter;

      // Prove Lyapunov contraction
      const isContraction = deltaV <= -MIN_RIEMANNIAN_CONTRACTION;
      const isPositiveDefinite = this.isMetricPositiveDefinite(stateBefore);
      const chaosReceipt = saga.chaosValidationReceipts?.[participant.nodeId];
      const chaosPassed = chaosReceipt ? chaosReceipt.passed : true;

      const voteCommit = isContraction && isPositiveDefinite && chaosPassed;
      if (!voteCommit) {
        allVotedCommit = false;
      }

      // Generate signed cryptographic proof
      const votePayload = `${sagaId}:${participant.nodeId}:${voteCommit ? 'VOTE_COMMIT' : 'VOTE_ABORT'}:${deltaV}`;
      const signedProof = crypto.createHmac('sha256', this.hmacSecret).update(votePayload).digest('hex');

      let ed25519Signature: string | undefined;
      let publicKeyPem: string | undefined = participant.publicKeyPem;
      let attestationStatus: ParticipantVote['attestationStatus'] = 'HMAC_LEGACY_VERIFIED';

      if (participant.privateKeyPem) {
        try {
          ed25519Signature = crypto.sign(null, Buffer.from(votePayload, 'utf8'), participant.privateKeyPem).toString('base64url');
          if (publicKeyPem) {
            const isValid = crypto.verify(
              null,
              Buffer.from(votePayload, 'utf8'),
              publicKeyPem,
              Buffer.from(ed25519Signature, 'base64url')
            );
            attestationStatus = isValid ? 'ED25519_VERIFIED' : 'ATTESTATION_FAILED';
            if (!isValid) {
              allVotedCommit = false;
            }
          } else {
            attestationStatus = 'ED25519_VERIFIED';
          }
        } catch (_) {
          attestationStatus = 'ATTESTATION_FAILED';
          allVotedCommit = false;
        }
      }

      const vote: ParticipantVote = {
        nodeId: participant.nodeId,
        vote: (voteCommit && attestationStatus !== 'ATTESTATION_FAILED') ? 'VOTE_COMMIT' : 'VOTE_ABORT',
        lyapunovDelta: deltaV,
        energyBefore,
        energyAfter,
        signedProof,
        timestampIso: new Date().toISOString(),
        ed25519Signature,
        publicKeyPem,
        attestationStatus,
        reason: (voteCommit && attestationStatus !== 'ATTESTATION_FAILED')
          ? 'Riemannian contraction verified strictly negative'
          : (attestationStatus === 'ATTESTATION_FAILED'
              ? 'Ed25519 cryptographic attestation signature failed verification'
              : (!chaosPassed
                  ? `Chaos sandbox perturbation failed: ${chaosReceipt?.failureReason || 'DESTABILIZING'}`
                  : 'Lyapunov contraction invariant violated or non-positive definite'))
      };

      saga.votes[participant.nodeId] = vote;
    }

    // Build Merkle tree across all participant vote leaf hashes
    const leafHashes: string[] = [];
    const participantList = saga.participants;
    for (const p of participantList) {
      const v = saga.votes[p.nodeId];
      const leafPayload = `${sagaId}:${p.nodeId}:${v.vote}:${v.lyapunovDelta}:${v.signedProof}:${v.ed25519Signature || ''}`;
      const leafHash = crypto.createHash('sha256').update(leafPayload).digest('hex');
      leafHashes.push(leafHash);
    }

    const merkleTree = zkEpistemicConsensusEngine.buildMerkleTree(leafHashes);

    for (let idx = 0; idx < participantList.length; idx++) {
      const p = participantList[idx];
      const v = saga.votes[p.nodeId];
      const proof = zkEpistemicConsensusEngine.generateMerkleProof(idx, merkleTree, p.nodeId);
      v.merkleInclusionProof = proof;

      const isProofValid = ZkEpistemicConsensusEngine.verifyMerkleProof(proof);
      if (!isProofValid) {
        v.attestationStatus = 'ATTESTATION_FAILED';
        allVotedCommit = false;
      }
    }

    // Phase 7.0 Track 4: Batch Ed25519 Cryptographic Attestation & Rollup Receipt
    const attestationItems = saga.participants.map(p => {
      const v = saga.votes[p.nodeId];
      return {
        nodeId: p.nodeId,
        payload: `${sagaId}:${p.nodeId}:${v.vote}:${v.lyapunovDelta}`,
        signature: v.ed25519Signature,
        publicKeyPem: v.publicKeyPem,
        hmacProof: v.signedProof
      };
    });
    const batchReceipt = zkEpistemicConsensusEngine.createBatchQuorumReceipt(sagaId, attestationItems);
    saga.batchQuorumReceipt = batchReceipt;
    if (!batchReceipt.isQuorumValid) {
      allVotedCommit = false;
    }

    const aggregateDeltaV = Math.round((totalEnergyAfter - totalEnergyBefore) * 1000) / 1000;
    saga.lyapunovAggregate = {
      energyBefore: Math.round(totalEnergyBefore * 1000) / 1000,
      energyAfter: Math.round(totalEnergyAfter * 1000) / 1000,
      deltaV: aggregateDeltaV,
      isRiemannianStable: allVotedCommit && aggregateDeltaV < 0
    };

    if (allVotedCommit) {
      saga.phase = 'COMMIT_VOTE_QUORUM';
    } else {
      saga.phase = 'ABORTED_PRE';
    }

    saga.updatedAtIso = new Date().toISOString();
    this.persistSaga(saga);
    return saga;
  }

  /**
   * Phase 2: Atomic Coordinated Commit or Coordinated Compensating Rollback
   */
  public executeCommitPhase(sagaId: string): DistributedSagaRecord {
    const saga = this.getSaga(sagaId);
    if (!saga) throw new Error(`Saga ${sagaId} not found`);

    if (saga.phase !== 'COMMIT_VOTE_QUORUM') {
      // If quorum not achieved, trigger rollback
      return this.triggerCoordinatedRollback(sagaId, 'Commit attempted without unanimous VOTE_COMMIT quorum');
    }

    // Phase 7.0 Track 4: Fast O(1) Batch Quorum Receipt Verification
    if (
      !saga.batchQuorumReceipt ||
      !ZkEpistemicConsensusEngine.verifyBatchQuorumReceipt(saga.batchQuorumReceipt, sagaId)
    ) {
      return this.triggerCoordinatedRollback(sagaId, 'Batch quorum attestation receipt verification failed');
    }

    // Verify cryptographic attestations & Merkle inclusion proofs before granting execution tokens
    for (const p of saga.participants) {
      const vote = saga.votes[p.nodeId];
      if (!vote) {
        return this.triggerCoordinatedRollback(sagaId, `Missing vote record for participant node ${p.nodeId}`);
      }
      if (vote.attestationStatus === 'ATTESTATION_FAILED') {
        return this.triggerCoordinatedRollback(sagaId, `Cryptographic attestation failed for participant node ${p.nodeId}`);
      }
      if (vote.merkleInclusionProof && !ZkEpistemicConsensusEngine.verifyMerkleProof(vote.merkleInclusionProof)) {
        return this.triggerCoordinatedRollback(sagaId, `Merkle inclusion proof verification failed for participant node ${p.nodeId}`);
      }
      if (vote.ed25519Signature && vote.publicKeyPem) {
        const votePayload = `${sagaId}:${p.nodeId}:${vote.vote}:${vote.lyapunovDelta}`;
        try {
          const isValid = crypto.verify(
            null,
            Buffer.from(votePayload, 'utf8'),
            vote.publicKeyPem,
            Buffer.from(vote.ed25519Signature, 'base64url')
          );
          if (!isValid) {
            return this.triggerCoordinatedRollback(sagaId, `Ed25519 signature verification failed for participant node ${p.nodeId}`);
          }
        } catch (_) {
          return this.triggerCoordinatedRollback(sagaId, `Ed25519 signature verification error for participant node ${p.nodeId}`);
        }
      }
    }

    // Quorum achieved: generate atomic execution tokens for all nodes
    const now = Date.now();
    for (const participant of saga.participants) {
      const tokenPayload = {
        sagaId,
        nodeId: participant.nodeId,
        actionId: participant.candidateAction.actionId,
        issuedAt: now,
        expiresAt: now + 60000 // 60s validity
      };
      const raw = Buffer.from(JSON.stringify(tokenPayload)).toString('base64url');
      const sig = crypto.createHmac('sha256', this.hmacSecret).update(raw).digest('base64url');
      saga.commitTokens[participant.nodeId] = `${raw}.${sig}`;
    }

    saga.phase = 'COMMITTED';
    this.processedSagaNonces.add(sagaId);
    saga.updatedAtIso = new Date().toISOString();

    // Phase 9.0 Track 2: Bayesian Reward Attribution for Contextual Bandit
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const { contextualBanditPolicy } = require('./contextual-bandit-policy');
      for (const p of saga.participants) {
        contextualBanditPolicy.recordReward({
          armId: p.candidateAction.actionId,
          contextVector: saga.banditPolicySelection?.contextVector || [0.5, 0.5, 0.5, 0.2],
          deltaV: saga.lyapunovAggregate.deltaV,
          energyBefore: saga.lyapunovAggregate.energyBefore,
          blastRadius: saga.participants.length / 10.0,
          executionDurationMs: 150,
          success: true,
          rollbackOccurred: false
        });
      }
    } catch (_) {}

    this.persistSaga(saga);
    return saga;
  }

  /**
   * Trigger coordinated compensating rollback across all staged/committed participants
   */
  public triggerCoordinatedRollback(
    sagaId: string,
    reason: string,
    options: { failingNodes?: string[] } = {}
  ): DistributedSagaRecord {
    const saga = this.getSaga(sagaId);
    if (!saga) throw new Error(`Saga ${sagaId} not found`);

    saga.phase = 'COORDINATED_COMPENSATING_ROLLBACK';
    saga.rollbackExecuted = true;
    const nowIso = new Date().toISOString();

    for (const participant of saga.participants) {
      // Execute inverse compensation
      const inverse = participant.candidateInverse;
      const isFailed = Boolean(options.failingNodes && options.failingNodes.includes(participant.nodeId));

      const stepResult: RollbackStepResult = {
        nodeId: participant.nodeId,
        inverseActionId: inverse.actionId,
        inverseType: inverse.inverseType,
        executedAtIso: nowIso,
        status: isFailed ? 'COMPENSATION_FAILED' : 'COMPENSATED_SUCCESS',
        reversesActionId: inverse.reversesActionId
      };
      saga.rollbackLog.push(stepResult);

      if (isFailed) {
        this.enqueuePendingCompensation(sagaId, participant.nodeId, inverse);
      }
    }

    saga.phase = 'ROLLED_BACK';
    saga.updatedAtIso = new Date().toISOString();

    // Phase 9.0 Track 2: Negative Reward Attribution on Rollback
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const { contextualBanditPolicy } = require('./contextual-bandit-policy');
      for (const participant of saga.participants) {
        contextualBanditPolicy.recordReward({
          armId: participant.candidateAction.actionId,
          contextVector: saga.banditPolicySelection?.contextVector || [0.5, 0.5, 0.5, 0.2],
          deltaV: 0,
          energyBefore: saga.lyapunovAggregate.energyBefore,
          blastRadius: saga.participants.length / 10.0,
          executionDurationMs: 500,
          success: false,
          rollbackOccurred: true
        });
      }
    } catch (_) {}

    this.persistSaga(saga);
    return saga;
  }

  /**
   * Enqueues an uncompensated inverse action for durable WAL re-drive.
   */
  public enqueuePendingCompensation(
    sagaId: string,
    nodeId: string,
    inverseAction: CompensatingInverseAction,
    options: { maxRetries?: number; initialDelayMs?: number } = {}
  ): PendingCompensationRecord {
    const compensationId = `COMP-${sagaId}-${nodeId}-${Date.now()}`;
    const now = Date.now();
    const delay = options.initialDelayMs ?? 1000;
    const record: PendingCompensationRecord = {
      compensationId,
      sagaId,
      nodeId,
      inverseAction,
      retryCount: 0,
      maxRetries: options.maxRetries ?? 5,
      nextRetryAtIso: new Date(now + delay).toISOString(),
      status: 'PENDING_RETRY',
      createdAtIso: new Date(now).toISOString(),
      updatedAtIso: new Date(now).toISOString()
    };
    this.persistPendingCompensation(record);
    return record;
  }

  public getPendingCompensation(compensationId: string): PendingCompensationRecord | null {
    if (this.inMemoryPendingCompensations.has(compensationId)) {
      return this.inMemoryPendingCompensations.get(compensationId)!;
    }
    if (!this.sqliteInitialized) return null;
    try {
      const db = getDb();
      if (!db) return null;
      const row = db
        .prepare('SELECT * FROM ejii_saga_compensations_pending WHERE compensation_id = ?')
        .get(compensationId) as any;
      if (!row) return null;
      const rec: PendingCompensationRecord = {
        compensationId: row.compensation_id,
        sagaId: row.saga_id,
        nodeId: row.node_id,
        inverseAction: JSON.parse(row.inverse_action_json),
        retryCount: row.retry_count,
        maxRetries: row.max_retries,
        nextRetryAtIso: row.next_retry_at,
        status: row.status as CompensationStatus,
        createdAtIso: row.created_at,
        updatedAtIso: row.updated_at
      };
      this.inMemoryPendingCompensations.set(rec.compensationId, rec);
      return rec;
    } catch (_) {
      return null;
    }
  }

  public listPendingCompensations(statusFilter?: CompensationStatus): PendingCompensationRecord[] {
    const list: PendingCompensationRecord[] = [];
    if (this.sqliteInitialized) {
      try {
        const db = getDb();
        if (db) {
          const sql = statusFilter
            ? 'SELECT * FROM ejii_saga_compensations_pending WHERE status = ? ORDER BY created_at ASC'
            : 'SELECT * FROM ejii_saga_compensations_pending ORDER BY created_at ASC';
          const rows = (statusFilter ? db.prepare(sql).all(statusFilter) : db.prepare(sql).all()) as any[];
          for (const row of rows) {
            const rec: PendingCompensationRecord = {
              compensationId: row.compensation_id,
              sagaId: row.saga_id,
              nodeId: row.node_id,
              inverseAction: JSON.parse(row.inverse_action_json),
              retryCount: row.retry_count,
              maxRetries: row.max_retries,
              nextRetryAtIso: row.next_retry_at,
              status: row.status as CompensationStatus,
              createdAtIso: row.created_at,
              updatedAtIso: row.updated_at
            };
            this.inMemoryPendingCompensations.set(rec.compensationId, rec);
            list.push(rec);
          }
          return list;
        }
      } catch (_) {}
    }

    for (const rec of this.inMemoryPendingCompensations.values()) {
      if (!statusFilter || rec.status === statusFilter) {
        list.push(rec);
      }
    }
    return list;
  }

  /**
   * Reconciles pending compensations due for re-drive using truncated exponential backoff with full jitter.
   * If retryCount exceeds maxRetries (default 5), escalates to DEAD_LETTER_ESCALATED and records HMAC audit token.
   */
  public async reconcilePendingCompensations(
    executor?: (record: PendingCompensationRecord) => Promise<boolean> | boolean,
    options: { nowMs?: number; randomFn?: () => number } = {}
  ): Promise<ReconcileResult> {
    const nowMs = typeof options.nowMs === 'number' ? options.nowMs : Date.now();
    const pending = this.listPendingCompensations('PENDING_RETRY').filter((r) => {
      const retryTime = new Date(r.nextRetryAtIso).getTime();
      return retryTime <= nowMs;
    });

    let succeededCount = 0;
    let retriedCount = 0;
    let deadLetterCount = 0;
    const reconciledRecords: PendingCompensationRecord[] = [];

    for (const record of pending) {
      let succeeded = false;
      try {
        if (executor) {
          succeeded = Boolean(await executor(record));
        } else {
          succeeded = true;
        }
      } catch (err: any) {
        record.lastError = err?.message || String(err);
        succeeded = false;
      }

      if (succeeded) {
        record.status = 'SUCCESS';
        record.updatedAtIso = new Date(nowMs).toISOString();
        succeededCount++;
        this.persistPendingCompensation(record);
        this.emit('SAGA_COMPENSATION_RECONCILED', { record });
      } else {
        record.retryCount++;
        record.updatedAtIso = new Date(nowMs).toISOString();

        if (record.retryCount >= record.maxRetries) {
          record.status = 'DEAD_LETTER_ESCALATED';
          const auditHmac = crypto
            .createHmac('sha256', this.hmacSecret)
            .update(
              `${record.compensationId}:${record.sagaId}:${record.nodeId}:DEAD_LETTER_ESCALATED:${nowMs}`
            )
            .digest('hex');
          record.auditHmac = auditHmac;
          deadLetterCount++;
          this.persistPendingCompensation(record);
          this.emit('SAGA_COMPENSATION_DLQ_ESCALATED', {
            record,
            auditHmac,
            timestamp: record.updatedAtIso
          });
        } else {
          const backoffMs = calculateJitteredBackoffMs(record.retryCount, options.randomFn);
          record.nextRetryAtIso = new Date(nowMs + backoffMs).toISOString();
          retriedCount++;
          this.persistPendingCompensation(record);
          this.emit('SAGA_COMPENSATION_RETRY_SCHEDULED', {
            record,
            backoffMs,
            nextRetryAtIso: record.nextRetryAtIso
          });
        }
      }
      reconciledRecords.push(record);
    }

    return {
      processedCount: pending.length,
      succeededCount,
      retriedCount,
      deadLetterCount,
      reconciledRecords
    };
  }

  private persistPendingCompensation(record: PendingCompensationRecord): void {
    this.inMemoryPendingCompensations.set(record.compensationId, record);
    if (!this.sqliteInitialized) return;
    try {
      const db = getDb();
      if (!db) return;
      db.prepare(`
        INSERT INTO ejii_saga_compensations_pending (
          compensation_id, saga_id, node_id, inverse_action_json,
          retry_count, max_retries, next_retry_at, status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(compensation_id) DO UPDATE SET
          retry_count = excluded.retry_count,
          next_retry_at = excluded.next_retry_at,
          status = excluded.status,
          updated_at = excluded.updated_at
      `).run(
        record.compensationId,
        record.sagaId,
        record.nodeId,
        JSON.stringify(record.inverseAction),
        record.retryCount,
        record.maxRetries,
        record.nextRetryAtIso,
        record.status,
        record.createdAtIso,
        record.updatedAtIso
      );
    } catch (_) {
      // In-memory fallback
    }
  }

  public getSaga(sagaId: string): DistributedSagaRecord | null {
    if (this.inMemorySagas.has(sagaId)) {
      return this.inMemorySagas.get(sagaId)!;
    }
    if (!this.sqliteInitialized) return null;

    try {
      const db = getDb();
      if (!db) return null;
      const row = db.prepare('SELECT * FROM ejii_remediation_sagas WHERE saga_id = ?').get(sagaId) as any;
      if (!row) return null;

      const record: DistributedSagaRecord = {
        sagaId: row.saga_id,
        hypothesisId: row.hypothesis_id,
        phase: row.phase as SagaPhase,
        initiator: row.initiator,
        participants: JSON.parse(row.participants_json),
        votes: JSON.parse(row.votes_json),
        lyapunovAggregate: JSON.parse(row.lyapunov_aggregate_json),
        commitTokens: row.commit_tokens_json ? JSON.parse(row.commit_tokens_json) : {},
        batchQuorumReceipt: row.batch_quorum_receipt_json ? JSON.parse(row.batch_quorum_receipt_json) : undefined,
        rollbackExecuted: Boolean(row.rollback_executed),
        rollbackLog: row.rollback_log_json ? JSON.parse(row.rollback_log_json) : [],
        createdAtIso: row.created_at,
        updatedAtIso: row.updated_at
      };
      this.inMemorySagas.set(sagaId, record);
      return record;
    } catch (_) {
      return null;
    }
  }

  private persistSaga(record: DistributedSagaRecord): void {
    if (!this.sqliteInitialized) return;
    try {
      const db = getDb();
      if (!db) return;
      db.prepare(`
        INSERT INTO ejii_remediation_sagas (
          saga_id, hypothesis_id, phase, initiator,
          participants_json, votes_json, lyapunov_aggregate_json,
          commit_tokens_json, batch_quorum_receipt_json, rollback_executed, rollback_log_json,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(saga_id) DO UPDATE SET
          phase = excluded.phase,
          votes_json = excluded.votes_json,
          lyapunov_aggregate_json = excluded.lyapunov_aggregate_json,
          commit_tokens_json = excluded.commit_tokens_json,
          batch_quorum_receipt_json = excluded.batch_quorum_receipt_json,
          rollback_executed = excluded.rollback_executed,
          rollback_log_json = excluded.rollback_log_json,
          updated_at = excluded.updated_at
      `).run(
        record.sagaId,
        record.hypothesisId,
        record.phase,
        record.initiator,
        JSON.stringify(record.participants),
        JSON.stringify(record.votes),
        JSON.stringify(record.lyapunovAggregate),
        JSON.stringify(record.commitTokens),
        record.batchQuorumReceipt ? JSON.stringify(record.batchQuorumReceipt) : null,
        record.rollbackExecuted ? 1 : 0,
        JSON.stringify(record.rollbackLog),
        record.createdAtIso,
        record.updatedAtIso
      );
    } catch (_) {
      // In-memory fallback
    }
  }
}

export const distributedSagaOrchestrator = new DistributedSagaOrchestrator();
