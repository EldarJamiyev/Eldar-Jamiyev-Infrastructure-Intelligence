/**
 * Track 2: Dynamic Temporal Granger Causal Discovery Across Telemetry Streams
 *
 * Verifies:
 *   1. Mathematical Granger causality F-test, F_crit calculation, and dynamic effect size Delta sigma.
 *   2. Rejection of spurious causality on independent time-series telemetry streams.
 *   3. Dynamic edge upsert into Temporal Infrastructure Graph and SQLite WAL table temporal_causal_edges.
 *   4. Synchronization of causal graph with Conversational Brain Bayesian prior initialization.
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  computeGrangerCausality,
  temporalInfrastructureGraph
} = require('../src/core/topology/temporal-graph-engine');
const { computeProbeInformationGainRanking } = require('../src/core/chat/conversational-brain');
const { db } = require('../src/db/database');

test('Track 2: Dynamic Temporal Granger Causal Discovery Across Telemetry Streams', async (t) => {
  await t.test('1. computes authentic Granger causality on coupled synthetic telemetry streams', () => {
    // Generate coupled time series: X causes Y with lag 1
    const N = 50;
    const streamX = [];
    const streamY = [10.0, 10.0];

    for (let tIdx = 0; tIdx < N; tIdx++) {
      // Periodic traffic wave with mild noise
      const xVal = 20.0 + 15.0 * Math.sin(tIdx / 3.0) + (Math.random() - 0.5) * 2.0;
      streamX.push(xVal);
      if (tIdx >= 2) {
        // Y is driven by X at lag 1
        const yVal = 5.0 + 0.3 * streamY[tIdx - 1] + 0.65 * streamX[tIdx - 1] + (Math.random() - 0.5) * 1.5;
        streamY.push(yVal);
      }
    }

    const result = computeGrangerCausality(streamX, streamY, 2, { alpha: 0.05 });

    assert.ok(result.sampleSize >= 45, 'Sample size must be preserved');
    assert.equal(result.lagOrder, 2, 'Lag order must be 2');
    assert.ok(result.fStatistic > result.fCritical, `F-statistic (${result.fStatistic}) must exceed F-crit (${result.fCritical})`);
    assert.ok(result.pValue < 0.05, `p-value (${result.pValue}) must be statistically significant (< 0.05)`);
    assert.ok(result.effectSize > 0.20, `Dynamic effect size Delta sigma (${result.effectSize}) must exceed 0.20`);
    assert.equal(result.isCausal, true, 'Granger causality must be established');
  });

  await t.test('2. rejects causal link on uncorrelated independent noise streams', () => {
    const N = 50;
    const streamX = [];
    const streamY = [];

    for (let i = 0; i < N; i++) {
      streamX.push(20.0 + (Math.random() - 0.5) * 6.0);
      streamY.push(15.0 + (Math.random() - 0.5) * 6.0);
    }

    const result = computeGrangerCausality(streamX, streamY, 2, { alpha: 0.05 });
    assert.equal(result.isCausal, false, 'Uncorrelated noise must not be causal');
    assert.ok(result.pValue > 0.02, `p-value must not indicate false significance for independent noise (got ${result.pValue})`);
    assert.ok(result.fStatistic < result.fCritical || result.effectSize < 0.15);
  });

  await t.test('3. discovers and upserts causal edge in Temporal Graph and SQLite temporal_causal_edges', () => {
    const sourceId = 'gw-core-01';
    const targetId = 'edge-api-01';

    const N = 40;
    const streamX = [];
    const streamY = [2.0, 2.0];
    for (let tIdx = 0; tIdx < N; tIdx++) {
      const xVal = 10.0 + 8.0 * Math.sin(tIdx / 2.5);
      streamX.push(xVal);
      if (tIdx >= 2) {
        const yVal = 1.0 + 0.2 * streamY[tIdx - 1] + 0.7 * streamX[tIdx - 1] + (Math.random() - 0.5) * 0.5;
        streamY.push(yVal);
      }
    }

    const discovery = temporalInfrastructureGraph.discoverAndUpsertCausalEdge({
      sourceId,
      targetId,
      streamX,
      streamY,
      lagOrder: 2,
      sourceLabel: 'Core Datacenter WAN Gateway',
      targetLabel: 'Edge API Gateway'
    });

    assert.equal(discovery.isCausal, true, 'Discovery must flag causal relationship');
    assert.equal(discovery.edgeId, `CAUSAL_${sourceId}_${targetId}`);

    // Verify SQLite persistence
    const row = db.prepare('SELECT * FROM temporal_causal_edges WHERE id = ?').get(discovery.edgeId);
    assert.ok(row, 'Causal edge must be persisted in SQLite table');
    assert.equal(row.source_id, sourceId);
    assert.equal(row.target_id, targetId);
    assert.equal(row.is_causal, 1);
    assert.ok(row.f_statistic > 0);

    // Query causal ancestors
    const ancestors = temporalInfrastructureGraph.getCausalAncestors(targetId);
    assert.ok(ancestors.length >= 1, 'Must retrieve causal ancestors');
    const directAncestor = ancestors.find((a) => a.sourceId === sourceId);
    assert.ok(directAncestor, 'Source must appear as causal ancestor of target');
    assert.ok(directAncestor.effectSize > 0.1);
  });

  await t.test('4. integrates topological causal ancestry into Conversational Brain Bayesian prior initialization', () => {
    // When querying ranking for target with causal ancestor 'gw-core-01'
    const target = 'edge-api-01';
    const ranking = computeProbeInformationGainRanking([], {
      target,
      lastIntent: null
    });

    assert.ok(ranking.causalAncestry, 'Ranking output must include causalAncestry');
    assert.equal(ranking.causalAncestry.applied, true, 'Causal prior boost must be applied');
    assert.ok(ranking.causalAncestry.ancestorCount >= 1, 'At least 1 causal ancestor detected');

    // UPSTREAM_WAN_BLACKHOLE should receive boosted prior due to gateway causal ancestor
    const wanHypothesis = ranking.hypotheses.find((h) => h.id === 'UPSTREAM_WAN_BLACKHOLE');
    assert.ok(wanHypothesis, 'UPSTREAM_WAN_BLACKHOLE hypothesis must exist');
    assert.ok(wanHypothesis.probability > 0.08, `Causal boost should elevate upstream WAN probability (got ${wanHypothesis.probability})`);
  });
});
