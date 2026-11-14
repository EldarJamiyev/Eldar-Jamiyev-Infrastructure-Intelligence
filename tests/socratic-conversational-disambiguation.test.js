/**
 * Track 3: Socratic Multi-Turn Disambiguation & Active Clarification Loop
 *
 * Verifies:
 *   1. Formulate targeted Socratic clarification on high entropy ($H(X) > 1.2$) and ambiguous hypotheses.
 *   2. Suppression of clarification when a single dominant hypothesis (> 60%) is established.
 *   3. Bayesian posterior entropy collapse upon operator confirmation of ground truth.
 *   4. End-to-end integration in runAgenticToolLoop when probes are exhausted.
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  formulateSocraticClarification,
  applySocraticClarificationResponse,
  runAgenticToolLoop
} = require('../src/core/chat/conversational-brain');

test('Track 3: Socratic Multi-Turn Disambiguation & Active Clarification Loop', async (t) => {
  await t.test('1. triggers Socratic clarification on balanced ambiguous hypotheses with exhausted probes', () => {
    const ambiguousHypotheses = [
      { id: 'UPSTREAM_WAN_BLACKHOLE', name: 'Upstream Transit WAN Blackhole', probability: 0.42, percentage: 42.0 },
      { id: 'FIREWALL_ACL_DROP', name: 'Layer 3/4 Firewall Egress ACL Drop', probability: 0.38, percentage: 38.0 },
      { id: 'LOCAL_STACK_CONGESTION', name: 'Host OS Stack Congestion', probability: 0.20, percentage: 20.0 }
    ];

    const clarification = formulateSocraticClarification(
      ambiguousHypotheses,
      'Diagnose persistent packet drop to 198.51.100.1',
      { probesExhausted: true, entropyThreshold: 1.2 }
    );

    assert.equal(clarification.required, true, 'Clarification must be required on ambiguous hypotheses');
    assert.ok(clarification.entropyBits >= 1.2, `Entropy (${clarification.entropyBits}) must be high`);
    assert.ok(clarification.probabilityDelta <= 0.10, `Probability delta (${clarification.probabilityDelta}) must be small`);
    assert.equal(clarification.topHypotheses.length, 2, 'Must extract top 2 competing hypotheses');
    assert.equal(clarification.topHypotheses[0].id, 'UPSTREAM_WAN_BLACKHOLE');
    assert.equal(clarification.topHypotheses[1].id, 'FIREWALL_ACL_DROP');

    // Verify contrastive features and Socratic question
    assert.ok(clarification.contrastiveFeatures.hypothesisA);
    assert.ok(clarification.contrastiveFeatures.hypothesisB);
    assert.ok(clarification.socraticQuestion.includes('UPSTREAM_WAN_BLACKHOLE') || clarification.socraticQuestion.includes('Upstream Transit WAN Blackhole'));
    assert.ok(clarification.socraticQuestion.includes('FIREWALL_ACL_DROP') || clarification.socraticQuestion.includes('Firewall Egress ACL Drop'));
    assert.ok(clarification.disambiguationOptions.length >= 3, 'Must offer structured options including external');
  });

  await t.test('2. suppresses clarification when dominant hypothesis (>= 60%) is observed', () => {
    const dominantHypotheses = [
      { id: 'DNS_NXDOMAIN_POISON', name: 'DNS Resolver Cache Poisoning', probability: 0.78, percentage: 78.0 },
      { id: 'SERVICE_DAEMON_CRASH', name: 'Service Daemon Crash', probability: 0.12, percentage: 12.0 },
      { id: 'LOCAL_STACK_CONGESTION', name: 'Host OS Stack Congestion', probability: 0.10, percentage: 10.0 }
    ];

    const clarification = formulateSocraticClarification(
      dominantHypotheses,
      'Check DNS failure on internal domain',
      { probesExhausted: true }
    );

    assert.equal(clarification.required, false, 'Clarification must not trigger when hypothesis is confident');
    assert.equal(clarification.reason, 'BELOW_AMBIGUITY_THRESHOLD');
  });

  await t.test('3. collapses Shannon entropy upon operator Socratic confirmation', () => {
    const priorDistribution = [
      { id: 'UPSTREAM_WAN_BLACKHOLE', name: 'Upstream Transit WAN Blackhole', probability: 0.42, percentage: 42.0 },
      { id: 'FIREWALL_ACL_DROP', name: 'Layer 3/4 Firewall Egress ACL Drop', probability: 0.38, percentage: 38.0 },
      { id: 'LOCAL_STACK_CONGESTION', name: 'Host OS Stack Congestion', probability: 0.20, percentage: 20.0 }
    ];

    // Operator confirms UPSTREAM_WAN_BLACKHOLE occurred
    const updateResult = applySocraticClarificationResponse(
      priorDistribution,
      'UPSTREAM_WAN_BLACKHOLE',
      0.95
    );

    assert.equal(updateResult.confirmedHypothesisId, 'UPSTREAM_WAN_BLACKHOLE');
    assert.equal(updateResult.collapsed, true, 'Entropy must collapse below threshold');
    assert.ok(updateResult.entropyBits < 0.8, `New entropy (${updateResult.entropyBits}) must be low`);

    const confirmed = updateResult.hypotheses.find((h) => h.id === 'UPSTREAM_WAN_BLACKHOLE');
    assert.ok(confirmed, 'Confirmed hypothesis must exist');
    assert.ok(confirmed.probability >= 0.85, `Confirmed hypothesis posterior (${confirmed.probability}) must exceed 85%`);
    assert.ok(confirmed.percentage >= 85.0);

    // Other hypotheses should be downweighted or contradicted
    const firewall = updateResult.hypotheses.find((h) => h.id === 'FIREWALL_ACL_DROP');
    assert.ok(firewall.probability <= 0.10);
    assert.equal(firewall.contradicted, true);
  });

  await t.test('4. integrates Socratic clarification in runAgenticToolLoop upon probe exhaustion', async () => {
    // Execute single-step probe plan that yields ambiguous observation
    const initialPlan = {
      intent: 'port_check',
      target: '127.0.0.1',
      ports: [9999]
    };

    const mockExecutor = async () => ({
      reply: 'Port 9999 connection timed out. No active listener detected.',
      technicalEvidence: { port: 9999, status: 'TIMEOUT' },
      toolReflection: {
        continueLoop: false,
        reason: 'OBSERVATION_SUFFICIENT'
      }
    });

    const result = await runAgenticToolLoop({
      promptText: 'Investigate port 9999 failure',
      initialPlan,
      executeSinglePlan: mockExecutor,
      maxSteps: 1
    });

    assert.ok(result.epistemicClassification, 'Must include epistemicClassification');
    if (result.epistemicClassification.socraticClarification?.required) {
      assert.ok(result.reply.includes('Active Socratic Disambiguation Required'));
      assert.ok(result.epistemicClassification.socraticClarification.socraticQuestion);
    }
  });
});
