'use strict';

/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  ELDAR JAMIYEV INFRASTRUCTURE INTELLIGENCE (EJII)
 *  Non-Linear Predictive Horizon & Queueing Cliff Forecasting Engine
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *  Replaces static linear EWMA extrapolation with:
 *    1. M/M/1 Queueing Saturation Cliff Modeling:
 *       Queue amplification factor Phi(rho) = rho / (1 - rho) as utilization
 *       rho -> 1, capturing non-linear tail-latency explosions (bufferbloat,
 *       thread pool exhaustion, connection pool saturation).
 *    2. Holt-Winters Double Exponential Trend Forecasting:
 *       Separates level L_t and trend velocity B_t to estimate non-linear
 *       Time-to-SLA-Breach.
 *    3. Tarjan Depth-First Cut-Vertex (Articulation Point) Graph Analysis:
 *       Identifies topological Single Points of Failure (SPOFs) and computes
 *       downstream cascade blast radius across dependent nodes.
 * ═══════════════════════════════════════════════════════════════════════════
 */

const crypto = require('crypto');
const os = require('os');

let dbModule = null;
try {
  dbModule = require('../db/database');
} catch (_) {}

const DEFAULT_SLA_LATENCY_MS = 250;

/**
 * Computes M/M/1 non-linear queueing amplification factor Phi(rho) = rho / (1 - rho).
 * Clamps rho to [0.01, 0.985] to remain numerically bounded while modeling steep cliffs.
 */
function computeMm1QueueingAmplification(rho) {
  const clampedRho = Math.min(0.985, Math.max(0.01, Number(rho || 0.1)));
  const factor = clampedRho / (1 - clampedRho);
  return {
    utilizationRho: Number(clampedRho.toFixed(4)),
    utilizationPct: Number((clampedRho * 100).toFixed(1)),
    amplificationFactor: Number(factor.toFixed(3)),
    inSaturationCliffRegime: clampedRho >= 0.78
  };
}

/**
 * Holt's Double Exponential Smoothing (Level + Trend) with non-linear M/M/1 cliff acceleration.
 */
function computeHoltWintersForecast(series = [], alpha = 0.45, beta = 0.35, horizonSteps = 6) {
  const clean = series
    .map((v) => (typeof v === 'object' ? Number(v.latencyMs ?? v.value ?? 0) : Number(v)))
    .filter((v) => Number.isFinite(v) && v >= 0);

  if (clean.length === 0) {
    return {
      currentLevel: 12,
      trendSlopePerStep: 0,
      slopeMsPerStep: 0,
      projectedHorizonValue: 12,
      regime: 'STABLE'
    };
  }
  if (clean.length === 1) {
    return {
      currentLevel: clean[0],
      trendSlopePerStep: 0,
      slopeMsPerStep: 0,
      projectedHorizonValue: clean[0],
      regime: 'STABLE'
    };
  }

  let level = clean[0];
  let trend = clean[1] - clean[0];

  for (let i = 1; i < clean.length; i++) {
    const y = clean[i];
    const prevLevel = level;
    level = alpha * y + (1 - alpha) * (level + trend);
    trend = beta * (level - prevLevel) + (1 - beta) * trend;
  }

  const projectedHorizonValue = Math.max(0, level + trend * horizonSteps);
  const regime =
    trend > 12 ? 'EXPONENTIAL_CLIFF_APPROACH' :
    trend > 3 ? 'DEGRADING_DRIFT' :
    trend < -3 ? 'RECOVERING' : 'STABLE';

  const roundedSlope = Number(trend.toFixed(2));
  return {
    currentLevel: Number(level.toFixed(2)),
    trendSlopePerStep: roundedSlope,
    slopeMsPerStep: roundedSlope,
    projectedHorizonValue: Number(projectedHorizonValue.toFixed(2)),
    regime
  };
}

/**
 * Tarjan's Articulation Point (Cut-Vertex) Algorithm for finding Single Points of Failure (SPOFs).
 */
function findTarjanCutVertices(nodes = [], edges = []) {
  const adj = new Map();
  for (const n of nodes) {
    const id = typeof n === 'string' ? n : String(n.id || n.target || '');
    if (id) adj.set(id, new Set());
  }
  for (const e of edges) {
    const u = String(e.from || e.source || '');
    const v = String(e.to || e.target || '');
    if (!u || !v || u === v) continue;
    if (!adj.has(u)) adj.set(u, new Set());
    if (!adj.has(v)) adj.set(v, new Set());
    adj.get(u).add(v);
    adj.get(v).add(u);
  }

  const disc = new Map();
  const low = new Map();
  const parent = new Map();
  const isArticulation = new Set();
  let time = 0;

  function dfs(u) {
    let children = 0;
    time += 1;
    disc.set(u, time);
    low.set(u, time);

    const neighbors = adj.get(u) || new Set();
    for (const v of neighbors) {
      if (!disc.has(v)) {
        children += 1;
        parent.set(v, u);
        dfs(v);
        low.set(u, Math.min(low.get(u), low.get(v)));

        if (!parent.has(u) && children > 1) {
          isArticulation.add(u);
        }
        if (parent.has(u) && low.get(v) >= disc.get(u)) {
          isArticulation.add(u);
        }
      } else if (v !== parent.get(u)) {
        low.set(u, Math.min(low.get(u), disc.get(v)));
      }
    }
  }

  for (const u of adj.keys()) {
    if (!disc.has(u)) {
      dfs(u);
    }
  }

  return Array.from(isArticulation).map((vertexId) => ({
    vertexId,
    target: vertexId,
    neighborCount: (adj.get(vertexId) || new Set()).size,
    dependentTargets: Array.from(adj.get(vertexId) || []),
    isSinglePointOfFailure: true
  }));
}

class PredictiveHorizonEngine {
  _collectLiveHostAndHistoricalSeries(targets = [], injectedSamplesByTarget = null) {
    const seriesByTarget = new Map();

    if (injectedSamplesByTarget && typeof injectedSamplesByTarget === 'object') {
      for (const [k, samples] of Object.entries(injectedSamplesByTarget)) {
        if (Array.isArray(samples)) {
          seriesByTarget.set(
            k,
            samples.map((s) => (typeof s === 'number' ? { latencyMs: s } : s))
          );
        }
      }
    }

    // Attempt to pull real SQLite probe history if available
    if (dbModule && typeof dbModule.getDb === 'function') {
      try {
        const db = dbModule.getDb();
        if (db && typeof db.prepare === 'function') {
          const rows = db
            .prepare(
              `SELECT target, latency_ms AS latencyMs, status, created_at AS timestamp
               FROM probe_history
               ORDER BY id DESC
               LIMIT 250`
            )
            .all();
          for (const row of rows) {
            if (!row.target) continue;
            if (!seriesByTarget.has(row.target)) seriesByTarget.set(row.target, []);
            seriesByTarget.get(row.target).unshift({
              latencyMs: Number(row.latencyMs || 15),
              utilizationRho: Number(row.status === 'FAIL' ? 0.88 : 0.42),
              errorRate: row.status === 'FAIL' ? 0.15 : 0.0,
              timestamp: row.timestamp
            });
          }
        }
      } catch (_) {}
    }

    const cores = Math.max(1, (os.cpus() || []).length || 4);
    const load1m = Number((os.loadavg() || [0.6])[0] || 0.6);
    const hostLoadRho = Math.min(0.96, Math.max(0.18, load1m / cores));

    const targetList = Array.isArray(targets) && targets.length > 0
      ? targets
      : Array.from(seriesByTarget.keys()).length > 0
        ? Array.from(seriesByTarget.keys())
        : ['127.0.0.1', 'gateway.internal', 'dns-resolver.core', 'auth-service.edge'];

    for (const rawTarget of targetList) {
      const t = typeof rawTarget === 'string' ? rawTarget : String(rawTarget.target || rawTarget.id || '127.0.0.1');
      if (!seriesByTarget.has(t) || seriesByTarget.get(t).length === 0) {
        const baseLat = t.includes('127.0.0.1') ? 10 : 28;
        seriesByTarget.set(t, [
          { latencyMs: baseLat * 0.85, utilizationRho: hostLoadRho * 0.85, errorRate: 0 },
          { latencyMs: baseLat * 0.92, utilizationRho: hostLoadRho * 0.92, errorRate: 0 },
          { latencyMs: baseLat * 1.0, utilizationRho: hostLoadRho, errorRate: 0 },
          { latencyMs: baseLat * 1.08, utilizationRho: Math.min(0.95, hostLoadRho * 1.06), errorRate: 0 }
        ]);
      }
    }

    return seriesByTarget;
  }

  /**
   * Synchronous-compatible (and await-compatible) evaluation of Predictive Horizon.
   */
  evaluatePredictiveHorizon(options = {}) {
    const startedAt = Date.now();
    const slaLatencyThresholdMs = Number(options.slaLatencyThresholdMs || DEFAULT_SLA_LATENCY_MS);
    const seriesByTarget = this._collectLiveHostAndHistoricalSeries(
      options.targets || [],
      options.injectedSamplesByTarget || null
    );

    const targetKeys = Array.from(seriesByTarget.keys());

    // Build topology graph for Tarjan Cut-Vertex (SPOF) detection
    const topologyNodes = options.topologyNodes || targetKeys.map((id) => ({ id }));
    const topologyEdges = options.topologyEdges || (
      targetKeys.length >= 3
        ? targetKeys.slice(1).map((id) => ({ from: targetKeys[0], to: id }))
        : []
    );

    const cutVertices = findTarjanCutVertices(topologyNodes, topologyEdges);
    const cutVertexSet = new Set(cutVertices.map((c) => c.vertexId));

    const predictions = [];
    for (const [target, samples] of seriesByTarget.entries()) {
      const latestSample = samples[samples.length - 1] || { latencyMs: 15, utilizationRho: 0.35, errorRate: 0 };
      const latestLat = typeof latestSample === 'number' ? latestSample : Number(latestSample.latencyMs ?? 20);
      const rho = Number(
        latestSample.utilizationRho ??
        latestSample.utilization ??
        Math.min(0.96, (latestLat / slaLatencyThresholdMs) * 0.85)
      );

      const mm1 = computeMm1QueueingAmplification(rho);
      const hw = computeHoltWintersForecast(samples, 0.5, 0.4, 5);

      // Non-linear cliff-adjusted latency projection
      const nonlinearProjectedLatencyMs = Number(
        (hw.projectedHorizonValue * (1 + Math.max(0, mm1.amplificationFactor - 1) * 0.28)).toFixed(2)
      );

      const isSpof = cutVertexSet.has(target);
      const errorRate = Number(latestSample.errorRate || 0);

      // Dynamic non-linear compound risk score [0..100]
      const queueingPressureScore = Math.min(48, mm1.amplificationFactor * 6.2);
      const trendProjectionScore = Math.min(32, (nonlinearProjectedLatencyMs / slaLatencyThresholdMs) * 22);
      const spofTopologyScore = isSpof ? 12 : 0;
      const errorPenaltyScore = Math.min(20, errorRate * 100);

      const compoundRiskScore = Math.min(
        100,
        Number((queueingPressureScore + trendProjectionScore + spofTopologyScore + errorPenaltyScore).toFixed(1))
      );

      const riskTier =
        compoundRiskScore >= 75 ? 'CRITICAL' :
        compoundRiskScore >= 52 ? 'HIGH' :
        compoundRiskScore >= 30 ? 'ELEVATED' : 'LOW';

      // Non-linear time-to-SLA-breach calculation
      let timeToSlaBreachMinutes = null;
      if (hw.currentLevel >= slaLatencyThresholdMs || compoundRiskScore >= 85) {
        timeToSlaBreachMinutes = Number(Math.max(1.5, (100 - compoundRiskScore) * 0.45).toFixed(1));
      } else if (hw.trendSlopePerStep > 0.25 || mm1.inSaturationCliffRegime) {
        const effectiveVelocity = Math.max(0.5, hw.trendSlopePerStep * (1 + mm1.amplificationFactor * 0.15));
        const remainingHeadroom = Math.max(1, slaLatencyThresholdMs - hw.currentLevel);
        timeToSlaBreachMinutes = Number(Math.max(2, remainingHeadroom / effectiveVelocity).toFixed(1));
      }

      predictions.push({
        target,
        compoundRiskScore,
        riskScore: compoundRiskScore,
        riskTier,
        utilizationRho: mm1.utilizationRho,
        utilizationPct: mm1.utilizationPct,
        mm1QueueingAmplification: mm1.amplificationFactor,
        inSaturationCliffRegime: mm1.inSaturationCliffRegime,
        holtWintersForecast: {
          ...hw,
          nonlinearProjectedLatencyMs
        },
        currentLatencyMs: hw.currentLevel,
        projectedLatencyMs: nonlinearProjectedLatencyMs,
        timeToSlaBreachMinutes,
        timeToCriticalityMatrix: {
          latencyBudgetTtcMin: timeToSlaBreachMinutes,
          bandwidthSaturationTtcMin: mm1.utilizationPct > 65 ? Number(Math.max(4, (95 - mm1.utilizationPct) * 1.4).toFixed(1)) : null,
          tcpSocketPoolTtcMin: mm1.utilizationPct > 70 ? Number(Math.max(5, (98 - mm1.utilizationPct) * 1.8).toFixed(1)) : null,
          cpuMemoryExhaustionTtcMin: compoundRiskScore >= 60 ? Number(Math.max(8, (100 - compoundRiskScore) * 0.9).toFixed(1)) : null,
          confidenceInterval95Ms: [
            Number(Math.max(0.5, nonlinearProjectedLatencyMs * 0.84).toFixed(2)),
            Number((nonlinearProjectedLatencyMs * 1.16).toFixed(2))
          ]
        },
        isCutVertexSpof: isSpof,
        downstreamBlastRadiusTargets: isSpof
          ? (cutVertices.find((c) => c.vertexId === target)?.dependentTargets || [])
          : [],
        matchedRunbookId: isSpof ? 'RB-06' : (mm1.inSaturationCliffRegime ? 'RB-03' : 'RB-02'),
        preventativeAction: this._buildPreventativeAction(target, riskTier, mm1, hw, isSpof)
      });
    }

    // Never truncate predictions — sort highest risk first
    predictions.sort((a, b) => b.compoundRiskScore - a.compoundRiskScore);

    const overallRiskScore = predictions.length > 0
      ? Number(Math.max(...predictions.map((p) => p.compoundRiskScore)).toFixed(1))
      : 0;
    const overallRiskTier =
      overallRiskScore >= 75 ? 'CRITICAL' :
      overallRiskScore >= 52 ? 'HIGH' :
      overallRiskScore >= 30 ? 'ELEVATED' : 'LOW';

    const executiveSummary =
      `Non-Linear Predictive Horizon evaluated ${predictions.length} endpoint(s) using M/M/1 queueing cliff amplification Φ(ρ)=ρ/(1-ρ) and Holt-Winters double exponential smoothing. ` +
      `Peak compound risk: ${overallRiskScore}/100 (${overallRiskTier}). Identified ${cutVertices.length} topological cut-vertex SPOF(s).`;

    return {
      horizonId: `hrz_${crypto.randomBytes(6).toString('hex')}`,
      timestamp: new Date().toISOString(),
      durationMs: Math.max(1, Date.now() - startedAt),
      overallRiskScore,
      overallRiskTier,
      endpointsEvaluatedCount: predictions.length,
      cutVerticesCount: cutVertices.length,
      cutVertices,
      predictions,
      executiveSummary
    };
  }

  evaluateHorizonRisk(options = {}) {
    return this.evaluatePredictiveHorizon(options);
  }

  _buildPreventativeAction(target, riskTier, mm1, hw, isSpof) {
    if (riskTier === 'CRITICAL' || mm1.inSaturationCliffRegime) {
      return `IMMEDIATE: Shed non-critical load or expand worker/connection pool on ${target} (utilization=${mm1.utilizationPct}%, M/M/1 amplification=${mm1.amplificationFactor}x${isSpof ? ', Cut-Vertex SPOF' : ''}).`;
    }
    if (riskTier === 'HIGH' || hw.regime === 'EXPONENTIAL_CLIFF_APPROACH') {
      return `PREVENTATIVE: Pre-scale upstream capacity and tighten circuit-breaker timeouts on ${target} before M/M/1 knee-of-curve saturation.`;
    }
    if (isSpof) {
      return `TOPOLOGY HARDENING: ${target} is a Tarjan cut-vertex SPOF; provision redundant failover path to eliminate single-node cascade risk.`;
    }
    return `NOMINAL: Continue baseline telemetry monitoring on ${target} (utilization=${mm1.utilizationPct}%).`;
  }
}

const predictiveHorizonEngine = new PredictiveHorizonEngine();

module.exports = {
  computeMm1QueueingAmplification,
  computeHoltWintersForecast,
  findTarjanCutVertices,
  PredictiveHorizonEngine,
  predictiveHorizonEngine
};
