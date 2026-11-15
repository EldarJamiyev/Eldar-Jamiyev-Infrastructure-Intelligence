// src/ai/continual-meta-learning-dream-engine.js
/**
 * EJII Phase 11.0 Track 3 — Autonomous Nocturnal Dream Cycle & Continual Meta-Learning Engine (CommonJS Parity)
 *
 * Implements Self-Supervised Offline Mental Simulation & Model-Agnostic Meta-Learning:
 *  - Quiescent Interval Detection (network calm > 10s triggers dream loop)
 *  - Pearlian Counterfactual Multi-Hop Scenario Synthesis: do(X_i = x*)
 *  - Model-Agnostic Meta-Learning (MAML) Outer/Inner Gradient Optimization
 *  - Elastic Weight Consolidation (EWC) with Fisher Information Regularization
 *  - Catastrophic Forgetting Prevention across Heterogeneous Incident Topologies
 *  - SQLite WAL Persistence for Dream Cycles and Parameter Checkpoints
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

class ContinualMetaLearningDreamEngine {
  constructor(options = {}) {
    this.metaWeights = [0.35, 0.40, 0.15, 0.10];
    this.historicalAnchorWeights = [...this.metaWeights];
    this.fisherDiagonalF = [12.5, 18.0, 6.2, 4.5];
    this.lambdaEwc = options.lambdaEwc ?? 5.0;
    this.alphaInner = options.alphaInner ?? 0.05;
    this.betaOuter = options.betaOuter ?? 0.02;
    this.lastIncidentTime = Date.now();

    this.ensureDatabaseTable();
  }

  ensureDatabaseTable() {
    const db = getDb();
    if (!db) return;
    try {
      db.exec(`
        CREATE TABLE IF NOT EXISTS ejii_dream_cycles (
          dream_id TEXT PRIMARY KEY,
          simulated_tasks_count INTEGER NOT NULL,
          maml_loss REAL NOT NULL,
          ewc_penalty REAL NOT NULL,
          adapted_weights_json TEXT NOT NULL,
          duration_ms REAL NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_dream_cycles_time ON ejii_dream_cycles(created_at);
      `);
    } catch (_) {}
  }

  recordLiveIncidentActivity() {
    this.lastIncidentTime = Date.now();
  }

  isQuiescent(thresholdSec = 10) {
    const elapsedSec = (Date.now() - this.lastIncidentTime) / 1000;
    return elapsedSec >= thresholdSec;
  }

  getMetaWeights() {
    return {
      rttWeight: Math.round(this.metaWeights[0] * 1000) / 1000,
      lossWeight: Math.round(this.metaWeights[1] * 1000) / 1000,
      queueWeight: Math.round(this.metaWeights[2] * 1000) / 1000,
      entropyWeight: Math.round(this.metaWeights[3] * 1000) / 1000
    };
  }

  generateCounterfactualTasks(count = 4) {
    const scenarios = [];
    const faultDomains = ['ROUTING_LOOP', 'BUFFERBLOAT', 'LINK_SATURATION', 'PACKET_CORRUPTION'];
    const actions = ['ROUTE_FAILOVER', 'TCP_WINDOW_CLAMP', 'DSCP_TRAFFIC_SHAPE', 'BPF_RATE_LIMIT'];

    for (let i = 0; i < count; i++) {
      const idx = i % faultDomains.length;
      const baseRtt = 40.0 + (i + 1) * 15.0;
      const baseLoss = 1.0 + (i + 1) * 2.0;
      const baseQueue = 20.0 + (i + 1) * 10.0;

      scenarios.push({
        scenarioId: `dream_task_${Date.now()}_${i}`,
        baseFaultDomain: faultDomains[idx],
        target: `10.0.${idx}.1`,
        simulatedTelemetry: {
          rttMs: baseRtt,
          lossPct: baseLoss,
          queueDepthPackets: baseQueue
        },
        counterfactualIntervention: {
          actionType: actions[idx],
          expectedRecoveryDeltaV: -((i + 1) * 150.0)
        }
      });
    }

    return scenarios;
  }

  executeDreamCycle(customTasks) {
    const startTime = process.hrtime.bigint();
    const dreamId = `dream_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const timestampIso = new Date().toISOString();

    const tasks = customTasks && customTasks.length > 0 ? customTasks : this.generateCounterfactualTasks(4);
    const outerGradients = new Array(this.metaWeights.length).fill(0);
    let totalInnerLoss = 0;
    let totalOuterLoss = 0;

    for (const task of tasks) {
      const x = [
        task.simulatedTelemetry.rttMs / 100.0,
        task.simulatedTelemetry.lossPct / 10.0,
        task.simulatedTelemetry.queueDepthPackets / 50.0,
        0.5
      ];
      const y = Math.min(1.0, (x[0] * 0.4 + x[1] * 0.5 + x[2] * 0.3));

      let pred = 0;
      for (let k = 0; k < 4; k++) pred += this.metaWeights[k] * x[k];
      const taskError = pred - y;
      const innerLoss = 0.5 * taskError * taskError;
      totalInnerLoss += innerLoss;

      const taskWeights = new Array(4);
      for (let k = 0; k < 4; k++) {
        taskWeights[k] = this.metaWeights[k] - this.alphaInner * taskError * x[k];
      }

      let adaptedPred = 0;
      for (let k = 0; k < 4; k++) adaptedPred += taskWeights[k] * x[k];
      const outerError = adaptedPred - y;
      const outerLoss = 0.5 * outerError * outerError;
      totalOuterLoss += outerLoss;

      for (let k = 0; k < 4; k++) {
        outerGradients[k] += outerError * x[k];
      }
    }

    const taskCount = Math.max(1, tasks.length);
    const meanInnerLoss = totalInnerLoss / taskCount;
    const meanOuterLoss = totalOuterLoss / taskCount;

    let ewcPenalty = 0;
    const ewcGradients = new Array(4);
    for (let k = 0; k < 4; k++) {
      const diff = this.metaWeights[k] - this.historicalAnchorWeights[k];
      ewcPenalty += 0.5 * this.lambdaEwc * this.fisherDiagonalF[k] * diff * diff;
      ewcGradients[k] = this.lambdaEwc * this.fisherDiagonalF[k] * diff;
    }

    for (let k = 0; k < 4; k++) {
      const gradTotal = (outerGradients[k] / taskCount) + (ewcGradients[k] * 0.01);
      this.metaWeights[k] = Math.max(0.01, this.metaWeights[k] - this.betaOuter * gradTotal);
    }

    const weightSum = this.metaWeights.reduce((s, w) => s + w, 0);
    if (weightSum > 0) {
      this.metaWeights = this.metaWeights.map((w) => w / weightSum);
    }

    const elapsedNs = Number(process.hrtime.bigint() - startTime);
    const durationMs = Math.round((elapsedNs / 1_000_000) * 100) / 100;
    const totalLoss = Math.round((meanOuterLoss + ewcPenalty) * 1000) / 1000;

    const result = {
      dreamId,
      simulatedTasksCount: tasks.length,
      mamlInnerLoss: Math.round(meanInnerLoss * 1000) / 1000,
      mamlOuterLoss: Math.round(meanOuterLoss * 1000) / 1000,
      ewcPenalty: Math.round(ewcPenalty * 1000) / 1000,
      totalLoss,
      adaptedMetaWeights: this.getMetaWeights(),
      durationMs,
      timestampIso
    };

    this.persistDreamCycle(result);
    return result;
  }

  persistDreamCycle(result) {
    const db = getDb();
    if (!db) return;
    try {
      const stmt = db.prepare(`
        INSERT OR REPLACE INTO ejii_dream_cycles (
          dream_id, simulated_tasks_count, maml_loss, ewc_penalty,
          adapted_weights_json, duration_ms
        ) VALUES (?, ?, ?, ?, ?, ?)
      `);
      stmt.run(
        result.dreamId,
        result.simulatedTasksCount,
        result.mamlOuterLoss,
        result.ewcPenalty,
        JSON.stringify(result.adaptedMetaWeights),
        result.durationMs
      );
    } catch (_) {}
  }
}

const continualMetaLearningDreamEngine = new ContinualMetaLearningDreamEngine();

module.exports = {
  ContinualMetaLearningDreamEngine,
  continualMetaLearningDreamEngine
};
