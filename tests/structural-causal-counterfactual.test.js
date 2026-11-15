'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  structuralCausalEngine,
  StructuralCausalEngine,
  CANONICAL_SCM_PARAMETERS
} = require('../src/ai/structural-causal-engine');
const {
  dynamicStructuralCausalEngine,
  DynamicStructuralCausalEngine
} = require('../src/ai/dynamic-structural-causal-engine');
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

  await t.test('6. Computes bidirectional Pearlian causal evidence trace (PN, PS, PNS, Likelihood Ratio)', () => {
    const engine = new StructuralCausalEngine();
    const trace = engine.traceCausalEvidencePath('latency_spike', 'bufferbloat', {
      queueDepthPackets: 55.0,
      rttMs: 50.0,
      packetLossPct: 3.2
    });

    assert.ok(trace.probabilityOfNecessity >= 0.70, `Expected PN >= 0.70, got ${trace.probabilityOfNecessity}`);
    assert.ok(trace.probabilityOfSufficiency >= 0.70, `Expected PS >= 0.70, got ${trace.probabilityOfSufficiency}`);
    assert.ok(trace.probabilityOfNecessityAndSufficiency >= 0.65, `Expected PNS >= 0.65, got ${trace.probabilityOfNecessityAndSufficiency}`);
    assert.ok(trace.empiricalLikelihoodRatio >= 3.0, `Expected Lambda >= 3.0, got ${trace.empiricalLikelihoodRatio}`);
    assert.strictEqual(trace.proofVerdict, 'NECESSARY_AND_SUFFICIENT_PROVEN');
    assert.ok(Array.isArray(trace.causalPath) && trace.causalPath.length >= 4);
    assert.ok(trace.rationale.includes('Pearlian causal validation'));
  });

  await t.test('7. Integrates causal evidence trace into runAgenticToolLoop for diagnostic queries', async () => {
    const mockPlan = { intent: 'host_metrics', target: '10.0.0.1', mode: 'operational' };

    const outcome = await runAgenticToolLoop({
      promptText: 'why did latency spike on the database gateway?',
      initialPlan: mockPlan,
      executeSinglePlan: async (plan) => ({
        reply: 'Gateway metrics retrieved.',
        technicalEvidence: { rttMs: 52.0 },
        structuredAnswer: { result: 'OK', meaning: 'High queue depth detected' }
      }),
      sessionContext: {
        diagnosedRootCause: 'bufferbloat',
        symptom: 'latency_spike',
        queueDepthPackets: 60.0,
        rttMs: 52.0
      },
      maxSteps: 1
    });

    assert.ok(outcome.epistemicClassification.causalEvidenceTrace, 'causalEvidenceTrace must be populated');
    const trace = outcome.epistemicClassification.causalEvidenceTrace;
    assert.strictEqual(trace.proofVerdict, 'NECESSARY_AND_SUFFICIENT_PROVEN');
    assert.match(outcome.reply, /Pearlian Causal Evidence Trace/);
    assert.match(outcome.reply, /NECESSARY_AND_SUFFICIENT_PROVEN/);
  });

  await t.test('8. Computes analytical Pearlian causal mediation decomposition (CDE, NDE, NIE, Mediated Proportion)', () => {
    const engine = new StructuralCausalEngine();
    const mediation = engine.analyzeCausalMediation('arrival_burst', 'queue_accumulation', 'latency_spike', {
      queueDepthPackets: 55.0,
      rttMs: 50.0,
      packetLossPct: 3.0
    });

    assert.ok(mediation.totalEffect > 0, `Total effect must be positive, got ${mediation.totalEffect}`);
    assert.ok(typeof mediation.controlledDirectEffect === 'number');
    assert.ok(typeof mediation.naturalDirectEffect === 'number');
    assert.ok(mediation.naturalIndirectEffect > 0, `Natural indirect effect must be positive, got ${mediation.naturalIndirectEffect}`);
    assert.ok(mediation.mediatedProportion >= 0.50, `Mediated proportion should be >= 0.50, got ${mediation.mediatedProportion}`);
    assert.ok(['MEDIATOR_MITIGATION_SUFFICIENT', 'DUAL_INTERVENTION_REQUIRED'].includes(mediation.actionableInterventionTarget));
    assert.ok(mediation.rationale.includes('Pearlian causal mediation decomposition'));
  });

  await t.test('9. Integrates causal mediation analysis into runAgenticToolLoop for multi-hop queries', async () => {
    const mockPlan = { intent: 'host_metrics', target: '10.0.0.1', mode: 'operational' };

    const outcome = await runAgenticToolLoop({
      promptText: 'is the latency spike mediated through queue accumulation or directly caused by arrival burst?',
      initialPlan: mockPlan,
      executeSinglePlan: async (plan) => ({
        reply: 'Gateway metrics retrieved.',
        technicalEvidence: { rttMs: 52.0 },
        structuredAnswer: { result: 'OK', meaning: 'High queue depth detected' }
      }),
      sessionContext: {
        treatment: 'arrival_burst',
        mediator: 'queue_accumulation',
        outcome: 'latency_spike',
        queueDepthPackets: 60.0,
        rttMs: 52.0
      },
      maxSteps: 1
    });

    assert.ok(outcome.epistemicClassification.causalMediationAnalysis, 'causalMediationAnalysis must be populated');
    const med = outcome.epistemicClassification.causalMediationAnalysis;
    assert.ok(med.mediatedProportion >= 0.50);
    assert.match(outcome.reply, /Pearlian Causal Mediation Analysis/);
    assert.match(outcome.reply, /Total Effect/);
  });

  await t.test('10. Fast Causal Inference (FCI) tests conditional independence and discovers Partial Ancestral Graphs (PAG)', () => {
    const { fciLatentCausalEngine } = require('../src/ai/fci-latent-causal-engine');

    // Synthetic correlated series: X causes Z causes Y, plus latent L confounding X and Y
    const N = 50;
    const data = {
      arrival_rate: [],
      hypervisor_cpu_steal: [],
      queue_depth: [],
      rtt_latency: []
    };

    for (let i = 0; i < N; i++) {
      const arrival = 4.0 + (i % 5) * 0.5;
      const steal = (i % 3 === 0) ? 1.2 : 0.1;
      const queue = arrival * 10 + steal * 20;
      const rtt = 10 + queue * 0.8 + steal * 15;

      data.arrival_rate.push(arrival);
      data.hypervisor_cpu_steal.push(steal);
      data.queue_depth.push(queue);
      data.rtt_latency.push(rtt);
    }

    // 1. Marginal correlation test
    const rDirect = fciLatentCausalEngine.computePearsonCorrelation(data.queue_depth, data.rtt_latency);
    assert.ok(rDirect > 0.80, `Expected strong correlation, got ${rDirect}`);

    // 2. Conditional independence test with Fisher's z
    const indepTest = fciLatentCausalEngine.testConditionalIndependence(data, 'queue_depth', 'rtt_latency', ['hypervisor_cpu_steal']);
    assert.ok(typeof indepTest.pValue === 'number');
    assert.ok(typeof indepTest.partialCorrelation === 'number');
    assert.ok(indepTest.degreesOfFreedom > 0);

    // 3. PAG Discovery
    const pag = fciLatentCausalEngine.discoverPag(data, {
      knownLatentConfounders: [['hypervisor_cpu_steal', 'rtt_latency']]
    });

    assert.ok(pag);
    assert.strictEqual(pag.nodes.length, 4);
    assert.ok(pag.edges.length > 0);
    assert.strictEqual(pag.isCausallySufficient, false);
    assert.ok(pag.latentConfoundersDetected.length >= 1);

    const latentArc = pag.edges.find(e => e.edgeType === 'BIDIRECTED');
    assert.ok(latentArc, 'PAG must contain at least one bidirected edge indicating latent confounding');
    assert.strictEqual(latentArc.hasLatentConfounder, true);
    assert.ok(pag.summary.includes('latent confounder'));
  });

  await t.test('11. Integrates FCI latent confounder discovery into runAgenticToolLoop', async () => {
    const outcome = await runAgenticToolLoop({
      promptText: 'is there an unmeasured latent confounder or hypervisor steal affecting the queue latency?',
      initialPlan: { intent: 'host_metrics', target: '10.0.0.1', mode: 'operational' },
      executeSinglePlan: async () => ({
        reply: 'Host hypervisor metrics sampled.',
        technicalEvidence: { rttMs: 65.0 },
        structuredAnswer: { result: 'OK' }
      }),
      sessionContext: {
        diagnosedRootCause: 'hypervisor_cpu_steal',
        rttMs: 65.0
      },
      maxSteps: 1
    });

    assert.ok(outcome.epistemicClassification);
    assert.ok(outcome.epistemicClassification.latentConfounderAnalysis, 'latentConfounderAnalysis must be attached');
    assert.strictEqual(outcome.epistemicClassification.latentConfounderAnalysis.isCausallySufficient, false);
    assert.ok(outcome.epistemicClassification.latentConfounderAnalysis.latentConfoundersDetected.length >= 1);
  });

  await t.test('12. D-SCM fits VAR model, computes spectral radius and forecasts dynamic intervention cascade', () => {
    const engine = new DynamicStructuralCausalEngine();
    const series = {
      queueDepth: [20, 24, 28, 35, 45, 58, 70, 82, 90, 85, 72, 60, 48, 38, 30],
      rttLatency: [25, 27, 30, 36, 44, 55, 68, 80, 88, 84, 71, 59, 47, 37, 29],
      packetLoss: [0.0, 0.0, 0.1, 0.2, 0.6, 1.4, 2.5, 4.0, 5.2, 4.8, 3.2, 1.8, 0.9, 0.3, 0.1]
    };

    const model = engine.fitModel(series, { lag: 1 });
    assert.ok(model);
    assert.strictEqual(model.variables.length, 3);
    assert.ok(typeof model.spectralRadius === 'number');
    assert.ok(model.spectralRadius < 1.0, `Spectral radius must be < 1.0 for stability, got ${model.spectralRadius}`);
    assert.strictEqual(model.isStable, true);

    const result = engine.simulateIntervention(
      model,
      series,
      { variable: 'queueDepth', targetValue: 10.0 },
      5,
      5
    );

    assert.ok(result);
    assert.strictEqual(result.horizonSteps, 5);
    assert.strictEqual(result.trajectory.length, 5);
    assert.ok(typeof result.directDynamicEffect === 'number');
    assert.ok(typeof result.accumulatedCascadingEffect === 'number');
    assert.ok(result.summary.includes('D-SCM Dynamic Projection'));
    // Downstream variables (e.g. rttLatency, packetLoss) should experience cumulative reductions
    assert.ok(result.cumulativeImpact.queueDepth < 0, 'Intervening to lower queueDepth should produce negative cumulative shift');
  });

  await t.test('13. Integrates D-SCM dynamic trajectory forecasting into runAgenticToolLoop', async () => {
    const outcome = await runAgenticToolLoop({
      promptText: 'what is the future downstream cascade trajectory if we intervene on queueDepth over the next seconds?',
      initialPlan: { intent: 'host_metrics', target: '10.0.0.1', mode: 'operational' },
      executeSinglePlan: async () => ({
        reply: 'Dynamic telemetry observed.',
        technicalEvidence: { rttMs: 50.0 },
        structuredAnswer: { result: 'OK' }
      }),
      sessionContext: {
        dynamicIntervention: { variable: 'queueDepth', targetValue: 15.0 },
        horizonSteps: 4,
        stepDurationSeconds: 5
      },
      maxSteps: 1
    });

    assert.ok(outcome.epistemicClassification);
    assert.ok(outcome.epistemicClassification.dynamicCounterfactualTrajectory, 'dynamicCounterfactualTrajectory must be attached');
    assert.strictEqual(outcome.epistemicClassification.dynamicCounterfactualTrajectory.horizonSteps, 4);
    assert.ok(outcome.epistemicClassification.dynamicCounterfactualTrajectory.directDynamicEffect !== 0);
    assert.ok(outcome.reply.includes('D-SCM Dynamic Trajectory Forecast'));
  });
});
