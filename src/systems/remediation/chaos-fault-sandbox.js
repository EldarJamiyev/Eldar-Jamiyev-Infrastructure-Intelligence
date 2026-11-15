/**
 * EJII Phase 10.0 Track 1 — Autonomous Pre-Remediation Chaos Fault Injection Sandbox (CommonJS Parity)
 */

'use strict';

const crypto = require('node:crypto');

function getDb() {
  try {
    return require('../../db/database').db;
  } catch (_) {
    return null;
  }
}

class ChaosFaultSandbox {
  constructor(secretKey = 'ejii_chaos_sandbox_secret_2026') {
    this.secretKey = secretKey;
    this.ensureDatabaseTable();
  }

  ensureDatabaseTable() {
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

  calculateQueueingMetrics(arrivalRate, serviceRate, servers, capacity) {
    const lambda = Math.max(0.1, Number(arrivalRate) || 0.1);
    const mu = Math.max(0.1, Number(serviceRate) || 0.1);
    const c = Math.max(1, Math.floor(servers));
    const K = Math.max(c, Math.floor(capacity));

    const a = lambda / mu;
    const rho = lambda / (c * mu);

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

    const pN = new Array(K + 1);
    for (let n = 0; n <= K; n++) {
      if (n <= c) {
        let nf = 1;
        for (let i = 1; i <= n; i++) nf *= i;
        pN[n] = (Math.pow(a, n) / nf) * p0;
      } else {
        pN[n] = (aPowC / cFact) * Math.pow(rho, n - c) * p0;
      }
    }

    const pK = pN[K] || 0;

    let lQ = 0;
    for (let n = c; n <= K; n++) {
      lQ += (n - c) * pN[n];
    }

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

  computeLyapunovEnergy(state) {
    const rtt = Math.max(0, Number(state.rttMs) || 0);
    const loss = Math.max(0, Number(state.lossPct) || 0);
    const queue = Math.max(0, Number(state.queueDepthPackets) || 0);

    const wRtt = 0.5 + 0.5 / (1.0 + Math.exp(-(rtt - 80.0) / 20.0));
    const wLoss = 5.0 + 10.0 / (1.0 + Math.exp(-(loss - 3.0) / 1.0));
    const wQueue = 0.1 + 0.3 / (1.0 + Math.exp(-(queue - 40.0) / 10.0));

    const energy = wRtt * Math.pow(rtt / 10.0, 2) + wLoss * Math.pow(loss, 2) + wQueue * Math.pow(queue / 5.0, 2);
    return Math.round(energy * 1000) / 1000;
  }

  applyPerturbation(baseState, config) {
    const baseRtt = Math.max(1.0, Number(baseState.rttMs) || 10.0);
    const baseLoss = Math.max(0.0, Number(baseState.lossPct) || 0.0);
    const baseQueue = Math.max(1, Number(baseState.queueDepthPackets) || 5);

    // Dynamic queue sizing matching physical network buffer scale
    const baseArrival = 1000.0 * (1.0 + baseQueue / 50.0);
    const servers = 4;
    const capacity = Math.max(128, Math.round(baseQueue * 3));
    const baseService = Math.max(1200.0, (baseArrival / servers) * 1.5) * (1.0 - Math.min(0.5, baseLoss / 100.0));

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

  simulateActionMitigation(perturbedState, action) {
    let rtt = perturbedState.rttMs;
    let loss = perturbedState.lossPct;
    let queue = perturbedState.queueDepthPackets;

    switch (action.actionType) {
      case 'TCP_WINDOW_CLAMP': {
        queue = Math.max(2, Math.round(queue * 0.35));
        rtt = Math.max(10, Math.round(rtt * 0.55 * 100) / 100);
        loss = Math.max(0.01, Math.round(loss * 0.70 * 100) / 100);
        break;
      }
      case 'BPF_RATE_LIMIT': {
        queue = Math.max(5, Math.round(queue * 0.45));
        rtt = Math.max(12, Math.round(rtt * 0.65 * 100) / 100);
        loss = Math.max(0.05, Math.round(loss * 0.80 * 100) / 100);
        break;
      }
      case 'DSCP_TRAFFIC_CLASS': {
        rtt = Math.max(8, Math.round(rtt * 0.40 * 100) / 100);
        queue = Math.max(3, Math.round(queue * 0.50));
        break;
      }
      case 'ROUTE_FAILOVER': {
        rtt = Math.max(15, Math.round(rtt * 0.50 * 100) / 100);
        loss = Math.max(0.01, Math.round(loss * 0.20 * 100) / 100);
        queue = Math.max(1, Math.round(queue * 0.25));
        break;
      }
      case 'TCP_PACING':
      case 'ADJUST_EGRESS_PACING': {
        queue = Math.max(4, Math.round(queue * 0.40));
        rtt = Math.max(12, Math.round(rtt * 0.60 * 100) / 100);
        loss = Math.max(0.01, Math.round(loss * 0.20 * 100) / 100);
        break;
      }
      default: {
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

  evaluateCandidateRemediation(sagaId, action, baseState, customPerturbation) {
    const receiptId = `chaos_rcpt_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const timestampIso = new Date().toISOString();

    const config = {
      type: customPerturbation?.type || 'COMBINED_CHAOS_STORM',
      arrivalSurgeMultiplier: customPerturbation?.arrivalSurgeMultiplier ?? 2.0,
      serviceDegradationFactor: customPerturbation?.serviceDegradationFactor ?? 0.70,
      injectedDropPct: customPerturbation?.injectedDropPct ?? 1.5,
      injectedLatencyMs: customPerturbation?.injectedLatencyMs ?? 25.0,
      durationMs: customPerturbation?.durationMs ?? 5000
    };

    const vBaseline = this.computeLyapunovEnergy(baseState);
    const { perturbedState, queueMetrics } = this.applyPerturbation(baseState, config);
    const vChaos = this.computeLyapunovEnergy(perturbedState);

    const postActionState = this.simulateActionMitigation(perturbedState, action);
    const vPostAction = this.computeLyapunovEnergy(postActionState);

    const deltaV = Math.round((vPostAction - vChaos) * 1000) / 1000;

    let passed = true;
    let failureReason = undefined;

    if (deltaV >= 0) {
      passed = false;
      failureReason = 'LYAPUNOV_DRIFT_DESTABILIZING';
    } else if (postActionState.lossPct > 20.0) {
      passed = false;
      failureReason = 'RESIDUAL_PACKET_LOSS_BREACH';
    }

    const payloadToSign = `${receiptId}:${sagaId}:${action.actionId}:${passed}:${deltaV}:${queueMetrics.blockingProbability}:${timestampIso}`;
    const hmacSignature = crypto
      .createHmac('sha256', this.secretKey)
      .update(payloadToSign)
      .digest('hex');

    const receipt = {
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

    this.persistAudit(receipt);

    return receipt;
  }

  persistAudit(receipt) {
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

const chaosFaultSandbox = new ChaosFaultSandbox();

module.exports = {
  ChaosFaultSandbox,
  chaosFaultSandbox
};
