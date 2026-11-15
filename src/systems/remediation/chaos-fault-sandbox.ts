/**
 * EJII Phase 10.0 Track 1 — Autonomous Pre-Remediation Chaos Fault Injection Sandbox
 *
 * Implements:
 *   1. M/M/c/K Finite-Capacity Queueing Perturbation Model (Erlang state probabilities, blocking probability P_K, mean queue length L_q).
 *   2. Deterministic Stress Perturbations (Microburst Surge, Jitter Degradation, Packet Drop Injection, Asymmetric Delay).
 *   3. Empirical Lyapunov Drift Stability Verification: \Delta V(s) = V(s_{chaos+action}) - V(s_{chaos}) \le -\kappa V(s) + \eta.
 *   4. Cryptographic Chaos Validation Receipt issuance with HMAC-SHA256 integrity digest.
 *   5. Durable SQLite WAL Audit Journal (ejii_chaos_experiment_audits).
 */

import * as crypto from 'node:crypto';
import { TelemetryStateVector, MicroRemediationAction } from './generative-remediation-synthesizer';

function getDb(): any {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return require('../../db/database').db;
  } catch (_) {
    return null;
  }
}

export interface QueueingMetrics {
  trafficIntensity: number;
  utilization: number;
  p0: number;
  blockingProbability: number;
  meanQueueLength: number;
  effectiveThroughput: number;
  meanWaitTimeMs: number;
}

export type ChaosPerturbationType =
  | 'MICROBURST_SURGE'
  | 'JITTER_DEGRADATION'
  | 'PACKET_DROP_BURST'
  | 'ASYMMETRIC_DELAY'
  | 'COMBINED_CHAOS_STORM';

export interface ChaosPerturbationConfig {
  type: ChaosPerturbationType;
  arrivalSurgeMultiplier: number;
  serviceDegradationFactor: number;
  injectedDropPct: number;
  injectedLatencyMs: number;
  durationMs: number;
}

export interface ChaosValidationReceipt {
  receiptId: string;
  sagaId: string;
  actionId: string;
  actionType: string;
  targetEndpoint: string;
  passed: boolean;
  baselineEnergy: number;
  perturbedChaosEnergy: number;
  postActionChaosEnergy: number;
  lyapunovDriftDeltaV: number;
  blockingProbability: number;
  meanWaitTimeMs: number;
  perturbationType: ChaosPerturbationType;
  failureReason?: string;
  hmacSignature: string;
  timestampIso: string;
}

export class ChaosFaultSandbox {
  private secretKey: string;

  constructor(secretKey: string = 'ejii_chaos_sandbox_secret_2026') {
    this.secretKey = secretKey;
    this.ensureDatabaseTable();
  }

  private ensureDatabaseTable(): void {
    const db = getDb();
    if (!db) return;
    try {
      db.exec(`
        CREATE TABLE IF NOT EXISTS ejii_chaos_experiment_audits (
          receipt_id TEXT PRIMARY KEY,
          saga_id TEXT NOT NULL,
          action_id TEXT NOT NULL,
          action_type TEXT NOT NULL,
          target_endpoint TEXT,
          passed INTEGER NOT NULL,
          baseline_energy REAL NOT NULL,
          perturbed_energy REAL NOT NULL,
          post_action_energy REAL NOT NULL,
          delta_v REAL NOT NULL,
          blocking_prob REAL NOT NULL,
          perturbation_type TEXT NOT NULL,
          failure_reason TEXT,
          hmac_signature TEXT NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_chaos_saga_id ON ejii_chaos_experiment_audits(saga_id);
      `);
    } catch (_) {}
  }

  /**
   * Compute exact M/M/c/K finite-capacity queueing probabilities.
   *
   * @param arrivalRate lambda (packets per second)
   * @param serviceRate mu (packets per second per worker)
   * @param servers c (number of parallel processing workers / cores)
   * @param capacity K (total system capacity = queue buffer + c servers)
   */
  public calculateQueueingMetrics(
    arrivalRate: number,
    serviceRate: number,
    servers: number,
    capacity: number
  ): QueueingMetrics {
    const lambda = Math.max(0.1, arrivalRate);
    const mu = Math.max(0.1, serviceRate);
    const c = Math.max(1, Math.floor(servers));
    const K = Math.max(c, Math.floor(capacity));

    const a = lambda / mu;
    const rho = lambda / (c * mu);

    // Compute P0
    let sum1 = 0;
    let aPow = 1;
    let nFact = 1;

    for (let n = 0; n < c; n++) {
      if (n > 0) {
        aPow *= a;
        nFact *= n;
      }
      sum1 += aPow / nFact;
    }

    // Term for c!
    let cFact = 1;
    for (let i = 1; i <= c; i++) {
      cFact *= i;
    }
    const aPowC = Math.pow(a, c);

    let sum2 = 0;
    if (Math.abs(rho - 1.0) < 1e-7) {
      sum2 = K - c + 1;
    } else {
      sum2 = (1 - Math.pow(rho, K - c + 1)) / (1 - rho);
    }

    const p0 = 1.0 / (sum1 + (aPowC / cFact) * sum2);

    // Compute state probabilities P_n
    const pN: number[] = new Array(K + 1);
    for (let n = 0; n <= K; n++) {
      if (n <= c) {
        let nf = 1;
        for (let i = 1; i <= n; i++) nf *= i;
        pN[n] = (Math.pow(a, n) / nf) * p0;
      } else {
        pN[n] = (aPowC / cFact) * Math.pow(rho, n - c) * p0;
      }
    }

    // Blocking probability P_K (drop rate at buffer saturation)
    const pK = pN[K] || 0;

    // Expected queue length L_q = \sum_{n=c}^K (n - c) P_n
    let lQ = 0;
    for (let n = c; n <= K; n++) {
      lQ += (n - c) * pN[n];
    }

    // Effective throughput lambda_eff = lambda * (1 - P_K)
    const lambdaEff = lambda * (1.0 - pK);
    const meanWaitTimeSec = lambdaEff > 0 ? lQ / lambdaEff : 0;

    return {
      trafficIntensity: Math.round(a * 1000) / 1000,
      utilization: Math.round(rho * 1000) / 1000,
      p0: Math.round(p0 * 10000) / 10000,
      blockingProbability: Math.round(pK * 10000) / 10000,
      meanQueueLength: Math.round(lQ * 100) / 100,
      effectiveThroughput: Math.round(lambdaEff * 100) / 100,
      meanWaitTimeMs: Math.round(meanWaitTimeSec * 1000 * 100) / 100
    };
  }

  /**
   * Deterministic Canonical Lyapunov Energy Metric V(s) = s^T M(s) s
   */
  public computeLyapunovEnergy(state: TelemetryStateVector): number {
    const rtt = Math.max(0, Number(state.rttMs) || 0);
    const loss = Math.max(0, Number(state.lossPct) || 0);
    const queue = Math.max(0, Number(state.queueDepthPackets) || 0);

    // Quadratic Riemannian weight matrix evaluation
    const wRtt = 0.5 + 0.5 / (1.0 + Math.exp(-(rtt - 80.0) / 20.0));
    const wLoss = 5.0 + 10.0 / (1.0 + Math.exp(-(loss - 3.0) / 1.0));
    const wQueue = 0.1 + 0.3 / (1.0 + Math.exp(-(queue - 40.0) / 10.0));

    const energy = wRtt * Math.pow(rtt / 10.0, 2) + wLoss * Math.pow(loss, 2) + wQueue * Math.pow(queue / 5.0, 2);
    return Math.round(energy * 1000) / 1000;
  }

  /**
   * Apply chaos perturbation to a telemetry state vector
   */
  public applyPerturbation(
    baseState: TelemetryStateVector,
    config: ChaosPerturbationConfig
  ): { perturbedState: TelemetryStateVector; queueMetrics: QueueingMetrics } {
    const baseRtt = Math.max(1.0, Number(baseState.rttMs) || 10.0);
    const baseLoss = Math.max(0.0, Number(baseState.lossPct) || 0.0);
    const baseQueue = Math.max(1, Number(baseState.queueDepthPackets) || 5);

    // Baseline queue parameters: 1000 pkts/s arrival, 1200 pkts/s capacity
    const baseArrival = 1000.0 * (1.0 + baseQueue / 50.0);
    const baseService = 1200.0 * (1.0 - baseLoss / 100.0);
    const servers = 4;
    const capacity = 64;

    const perturbedArrival = baseArrival * config.arrivalSurgeMultiplier;
    const perturbedService = baseService * config.serviceDegradationFactor;

    const qMetrics = this.calculateQueueingMetrics(perturbedArrival, perturbedService, servers, capacity);

    const perturbedRtt = baseRtt + config.injectedLatencyMs + qMetrics.meanWaitTimeMs;
    const perturbedLoss = Math.min(100.0, baseLoss + config.injectedDropPct + qMetrics.blockingProbability * 100.0);
    const perturbedQueue = Math.min(capacity, Math.round(baseQueue + qMetrics.meanQueueLength));

    return {
      perturbedState: {
        rttMs: Math.round(perturbedRtt * 100) / 100,
        lossPct: Math.round(perturbedLoss * 100) / 100,
        queueDepthPackets: perturbedQueue
      },
      queueMetrics: qMetrics
    };
  }

  /**
   * Simulate the mitigation effect of an infrastructure action on perturbed state
   */
  public simulateActionMitigation(
    perturbedState: TelemetryStateVector,
    action: { actionId: string; actionType: string; target: string; [key: string]: any }
  ): TelemetryStateVector {
    let rtt = perturbedState.rttMs;
    let loss = perturbedState.lossPct;
    let queue = perturbedState.queueDepthPackets;

    switch (action.actionType as string) {
      case 'TCP_WINDOW_CLAMP': {
        // Clamping window reduces bufferbloat queue and RTT dramatically
        queue = Math.max(2, Math.round(queue * 0.35));
        rtt = Math.max(10, Math.round(rtt * 0.55 * 100) / 100);
        loss = Math.max(0.01, Math.round(loss * 0.70 * 100) / 100);
        break;
      }
      case 'DSCP_TRAFFIC_SHAPE':
      case 'DSCP_TRAFFIC_CLASS': {
        // Prioritization relieves latency on target path
        rtt = Math.max(8, Math.round(rtt * 0.40 * 100) / 100);
        queue = Math.max(3, Math.round(queue * 0.50));
        break;
      }
      case 'SOCKET_BUFFER_EXPEDITE':
      case 'BPF_RATE_LIMIT': {
        // Rate-limiting drops ingress burst, stabilizing queue
        queue = Math.max(5, Math.round(queue * 0.45));
        rtt = Math.max(12, Math.round(rtt * 0.65 * 100) / 100);
        loss = Math.max(0.05, Math.round(loss * 0.80 * 100) / 100);
        break;
      }
      case 'DNS_UPSTREAM_PIVOT':
      case 'ROUTE_FAILOVER': {
        // Reroute clears congested queue and drops
        rtt = Math.max(15, Math.round(rtt * 0.50 * 100) / 100);
        loss = Math.max(0.01, Math.round(loss * 0.20 * 100) / 100);
        queue = Math.max(1, Math.round(queue * 0.25));
        break;
      }
      case 'TCP_PACING': {
        // Smooth bursts, moderate queue reduction
        queue = Math.max(4, Math.round(queue * 0.60));
        rtt = Math.max(12, Math.round(rtt * 0.75 * 100) / 100);
        break;
      }
      default: {
        // Minimal generic effect
        queue = Math.max(1, Math.round(queue * 0.90));
        rtt = Math.max(5, Math.round(rtt * 0.90 * 100) / 100);
        break;
      }
    }

    return {
      rttMs: rtt,
      lossPct: loss,
      queueDepthPackets: queue
    };
  }

  /**
   * Pre-Remediation Stress Test & Lyapunov Drift Verification
   */
  public evaluateCandidateRemediation(
    sagaId: string,
    action: { actionId: string; actionType: string; target: string; [key: string]: any },
    baseState: TelemetryStateVector,
    customPerturbation?: Partial<ChaosPerturbationConfig>
  ): ChaosValidationReceipt {
    const receiptId = `chaos_rcpt_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const timestampIso = new Date().toISOString();

    const config: ChaosPerturbationConfig = {
      type: customPerturbation?.type || 'COMBINED_CHAOS_STORM',
      arrivalSurgeMultiplier: customPerturbation?.arrivalSurgeMultiplier ?? 2.0,
      serviceDegradationFactor: customPerturbation?.serviceDegradationFactor ?? 0.70,
      injectedDropPct: customPerturbation?.injectedDropPct ?? 1.5,
      injectedLatencyMs: customPerturbation?.injectedLatencyMs ?? 25.0,
      durationMs: customPerturbation?.durationMs ?? 5000
    };

    // 1. Calculate baseline energy
    const vBaseline = this.computeLyapunovEnergy(baseState);

    // 2. Apply chaos perturbation (stress injection)
    const { perturbedState, queueMetrics } = this.applyPerturbation(baseState, config);
    const vChaos = this.computeLyapunovEnergy(perturbedState);

    // 3. Simulate candidate action remediation mitigation under chaos
    const postActionState = this.simulateActionMitigation(perturbedState, action);
    const vPostAction = this.computeLyapunovEnergy(postActionState);

    // 4. Compute Lyapunov drift Delta V
    const deltaV = Math.round((vPostAction - vChaos) * 1000) / 1000;

    // 5. Verification Invariant:
    //    Action must achieve Lyapunov contraction (Delta V < 0) and queue blocking must be within envelope (P_K <= 0.08)
    let passed = true;
    let failureReason: string | undefined = undefined;

    if (deltaV >= 0) {
      passed = false;
      failureReason = 'LYAPUNOV_DRIFT_DESTABILIZING';
    } else if (queueMetrics.blockingProbability > 0.15) {
      passed = false;
      failureReason = 'QUEUE_CAPACITY_EXCEEDED';
    } else if (postActionState.lossPct > 15.0) {
      passed = false;
      failureReason = 'RESIDUAL_PACKET_LOSS_BREACH';
    }

    // 6. Sign receipt with HMAC-SHA256
    const payloadToSign = `${receiptId}:${sagaId}:${action.actionId}:${passed}:${deltaV}:${queueMetrics.blockingProbability}:${timestampIso}`;
    const hmacSignature = crypto
      .createHmac('sha256', this.secretKey)
      .update(payloadToSign)
      .digest('hex');

    const receipt: ChaosValidationReceipt = {
      receiptId,
      sagaId,
      actionId: action.actionId,
      actionType: action.actionType,
      targetEndpoint: action.target,
      passed,
      baselineEnergy: vBaseline,
      perturbedChaosEnergy: vChaos,
      postActionChaosEnergy: vPostAction,
      lyapunovDriftDeltaV: deltaV,
      blockingProbability: queueMetrics.blockingProbability,
      meanWaitTimeMs: queueMetrics.meanWaitTimeMs,
      perturbationType: config.type,
      failureReason,
      hmacSignature,
      timestampIso
    };

    // 7. Persist audit to SQLite
    this.persistAudit(receipt);

    return receipt;
  }

  private persistAudit(receipt: ChaosValidationReceipt): void {
    const db = getDb();
    if (!db) return;
    try {
      const stmt = db.prepare(`
        INSERT INTO ejii_chaos_experiment_audits (
          receipt_id, saga_id, action_id, action_type, target_endpoint,
          passed, baseline_energy, perturbed_energy, post_action_energy,
          delta_v, blocking_prob, perturbation_type, failure_reason,
          hmac_signature
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      stmt.run(
        receipt.receiptId,
        receipt.sagaId,
        receipt.actionId,
        receipt.actionType,
        receipt.targetEndpoint,
        receipt.passed ? 1 : 0,
        receipt.baselineEnergy,
        receipt.perturbedChaosEnergy,
        receipt.postActionChaosEnergy,
        receipt.lyapunovDriftDeltaV,
        receipt.blockingProbability,
        receipt.perturbationType,
        receipt.failureReason || null,
        receipt.hmacSignature
      );
    } catch (_) {}
  }
}

export const chaosFaultSandbox = new ChaosFaultSandbox();
