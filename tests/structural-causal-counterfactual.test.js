'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  structuralCausalEngine,
  StructuralCausalEngine,
  CANONICAL_SCM_PARAMETERS
} = require('../src/ai/structural-causal-engine');
const { runAgenticToolLoop } = require('../src/core/chat/conversational-brain');

test('Phase 5.0 Track 1: Structural Causal Models & Pearlian do-Calculus Counterfactuals', async (t) => {
  await t.test('1. Abduces exogenous background noise U = (uQueue, uRtt, uLoss) from factual observation', () => {
    const engine = new StructuralCausalEngine();
    const factual = {
      queueDepthPackets: 40.0,
      rttMs: 35.0,
      packetLossPct: 2.0,
      windowSizeBytes: 65535,
      arrivalRateKpps: 4.5,
      serviceRateKpps: 4.0
    };

    const noise = engine.abduceExogenousNoise(factual);
    assert.ok(typeof noise.uQueue === 'number');
    assert.ok(typeof noise.uRtt === 'number');
    assert.ok(typeof noise.uLoss === 'number');

    // Verify consistency: forward evaluation without intervention with abduced noise reconstructs factual
    const cfIdentity = engine.evaluateCounterfactual(factual, []);
    assert.strictEqual(Math.round(cfIdentity.counterfactualState.queueDepthPackets), 40);
    assert.strictEqual(Math.round(cfIdentity.counterfactualState.rttMs), 35);
    assert.strictEqual(Math.round(cfIdentity.counterfactualState.packetLossPct), 2);
  });

  await t.test('2. Evaluates interventional action do(windowSizeBytes = 32768) and predicts queue/rtt reduction', () => {
    const engine = new StructuralCausalEngine();
    const factual = {
      queueDepthPackets: 50.0,
      rttMs: 45.0,
      packetLossPct: 3.5,
      windowSizeBytes: 65535,
      arrivalRateKpps: 5.0,
      serviceRateKpps: 4.0
    };

    // Intervene: do(windowSizeBytes = 32768)
    const result = engine.evaluateCounterfactual(factual, [
      { variable: 'windowSizeBytes', targetValue: 32768 }
    ]);

    assert.ok(result.deltas.deltaQueueDepth < 0, `Expected negative deltaQueue, got ${result.deltas.deltaQueueDepth}`);
    assert.ok(result.deltas.deltaRttMs < 0, `Expected negative deltaRtt, got ${result.deltas.deltaRttMs}`);
    assert.ok(result.counterfactualState.rttMs < factual.rttMs);
    assert.ok(result.relativeImprovements.rttImprovementPct > 0);
    assert.ok(result.synthesis.includes('Pearlian counterfactual analysis confirms positive stability gain'));
  });

  await t.test('3. Evaluates direct intervention on intermediate variable do(queueDepthPackets = 10)', () => {
    const engine = new StructuralCausalEngine();
    const factual = {
      queueDepthPackets: 60.0,
      rttMs: 55.0,
      packetLossPct: 5.0,
      windowSizeBytes: 65535
    };

    // Directly clamp queue to 10 packets (severing parent influence from window/arrival)
    const result = engine.evaluateCounterfactual(factual, [
      { variable: 'queueDepthPackets', targetValue: 10.0 }
    ]);

    assert.strictEqual(result.counterfactualState.queueDepthPackets, 10.0);
    assert.strictEqual(result.deltas.deltaQueueDepth, -50.0);
    assert.strictEqual(result.deltas.deltaRttMs, -20.0);
    assert.strictEqual(result.counterfactualState.rttMs, 35.0);
    assert.ok(result.counterfactualState.rttMs < factual.rttMs);
  });

  await t.test('4. Parses natural language counterfactual "What-If" queries', () => {
    const engine = new StructuralCausalEngine();
    const factual = {
      queueDepthPackets: 45.0,
      rttMs: 40.0,
      packetLossPct: 2.0,
      windowSizeBytes: 65535
    };

    // Query 1: window clamp
    const res1 = engine.parseCounterfactualQuery('what if we clamp window to 32kb?', factual);
    assert.ok(res1, 'Must parse window clamp counterfactual query');
    assert.strictEqual(res1.interventions[0].variable, 'windowSizeBytes');
    assert.strictEqual(res1.interventions[0].targetValue, 32768);

    // Query 2: queue reduction
    const res2 = engine.parseCounterfactualQuery('what would happen if queue was 15?', factual);
    assert.ok(res2);
    assert.strictEqual(res2.interventions[0].variable, 'queueDepthPackets');
    assert.strictEqual(res2.interventions[0].targetValue, 15);

    // Non-counterfactual query returns null
    const resNull = engine.parseCounterfactualQuery('is port 443 open?', factual);
    assert.strictEqual(resNull, null);
  });

  await t.test('5. Integrates into runAgenticToolLoop and populates epistemicClassification', async () => {
    const mockPlan = { intent: 'host_metrics', target: '127.0.0.1', mode: 'operational' };

    const outcome = await runAgenticToolLoop({
      promptText: 'what if we clamp tcp window to 32kb on the gateway?',
      initialPlan: mockPlan,
      executeSinglePlan: async (plan) => ({
        reply: 'Metrics retrieved.',
        technicalEvidence: { rttMs: 42.0 },
        structuredAnswer: { result: 'OK', meaning: 'Telemetry normal' }
      }),
      maxSteps: 1
    });

    assert.ok(outcome.epistemicClassification, 'epistemicClassification must be present');
    assert.ok(outcome.epistemicClassification.counterfactualAnalysis, 'counterfactualAnalysis must be present');
    assert.ok(outcome.epistemicClassification.counterfactualAnalysis.deltas);
    assert.match(outcome.reply, /Pearlian Counterfactual/);
  });
});
