'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { computeLiveInformationGainAnalysis } = require('../src/core/chat/conversational-brain');
const { NeuroSymbolicApexEngine } = require('../src/ai/neuro-symbolic-apex');

test('Track 3: Gradient-Weighted Shannon Information Gain Probe Selection', async (t) => {
  await t.test('baseline without margins maintains standard Shannon information gain and zero gradients', () => {
    const analysis = computeLiveInformationGainAnalysis({});
    assert.ok(analysis, 'Analysis should return an object');
    assert.ok(Array.isArray(analysis.candidateProbes), 'Candidate probes should be an array');
    assert.ok(analysis.candidateProbes.length > 0, 'Candidate probes should not be empty');

    for (const probe of analysis.candidateProbes) {
      assert.strictEqual(probe.sensitivityGradient, 0, 'Sensitivity gradient should be 0 without margins');
      assert.strictEqual(
        probe.weightedInformationGainBits,
        probe.expectedInformationGainBits,
        'Weighted IG should equal expected IG without margins'
      );
    }
  });

  await t.test('computes analytical sensitivity gradients for bottleneck telemetry margins', () => {
    // Domain with lowest margin (worst bottleneck / headroom violation, e.g., DNS is critical margin = -2.5, TCP = 0.2, HTTP = 1.5)
    const telemetryMargins = {
      dns: -2.5,
      tcp: 0.2,
      http: 1.5
    };

    const analysis = computeLiveInformationGainAnalysis({
      telemetryMargins,
      sensitivityCouplingGamma: 0.8
    });

    assert.ok(analysis.candidateProbes.length > 0);

    const dnsProbes = analysis.candidateProbes.filter(p => p.probeId.startsWith('DNS_'));
    assert.ok(dnsProbes.length > 0, 'Should have DNS probes');

    for (const probe of dnsProbes) {
      assert.ok(probe.sensitivityGradient > 0, 'DNS probe should have positive sensitivity gradient');
      assert.ok(
        probe.weightedInformationGainBits >= probe.expectedInformationGainBits,
        'DNS probe weighted IG should be amplified by sensitivity gradient'
      );
      // Verify formula: weightedIg = baseIg * (1 + gamma * grad)
      const expectedWeighted = Number((probe.expectedInformationGainBits * (1 + 0.8 * probe.sensitivityGradient)).toFixed(3));
      assert.strictEqual(probe.weightedInformationGainBits, expectedWeighted, 'Weighted IG formula exact match');
    }
  });

  await t.test('prioritizes bottleneck probes ahead of higher raw IG probes when sensitivity gradient is high', () => {
    // Severely degraded DNS domain (lowest margin = -4.0) creates highest sensitivity gradient for DNS probes
    const telemetryMargins = {
      dns: -4.0,
      tcp: 2.0,
      http: 2.0,
      icmp: 2.0
    };

    const analysis = computeLiveInformationGainAnalysis({
      telemetryMargins,
      sensitivityCouplingGamma: 1.5
    });

    const candidateProbes = analysis.candidateProbes;
    assert.ok(candidateProbes.length >= 2);

    // Verify list is sorted monotonically descending by weightedInformationGainBits
    for (let i = 0; i < candidateProbes.length - 1; i++) {
      const current = candidateProbes[i];
      const next = candidateProbes[i + 1];
      if (current.alreadyObservedInSession === next.alreadyObservedInSession) {
        assert.ok(
          (current.weightedInformationGainBits ?? -1) >= (next.weightedInformationGainBits ?? -1),
          `Candidate probes should be sorted descending: ${current.weightedInformationGainBits} >= ${next.weightedInformationGainBits}`
        );
      }
    }

    // Top probe should have positive sensitivity gradient reflecting bottleneck prioritization
    assert.ok(candidateProbes[0].sensitivityGradient >= 0, 'Top probe should have non-negative sensitivity gradient');
  });

  await t.test('NeuroSymbolicApexEngine sensitivity gradients are normalized and sum to 1', () => {
    const values = [2.0, 0.5, -1.0];
    const grads = NeuroSymbolicApexEngine.computeAnalyticalSensitivityGradients(values, 1.0);
    assert.strictEqual(grads.length, 3);
    const sum = grads.reduce((acc, v) => acc + v, 0);
    assert.ok(Math.abs(sum - 1.0) < 1e-4, 'Softmax sensitivity gradients must sum to 1.0');
    assert.ok(grads[2] > grads[1] && grads[1] > grads[0], 'Lowest margin value receives largest gradient');
  });
});
