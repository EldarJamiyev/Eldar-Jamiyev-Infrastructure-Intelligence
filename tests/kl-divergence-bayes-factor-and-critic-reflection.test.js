/**
 * EJII Suite 70: Kullback-Leibler Information Gain, Bayes Factor Evidence Scale & Critic Reflection
 *
 * Verifies:
 * 1. [70.1] Epistemic Information Gain: KL-Divergence D_KL(P || U) calculation from uniform prior.
 * 2. [70.2] Harold Jeffreys Evidence Scale: Bayes Factor BF_12 computation and qualitative calibration.
 * 3. [70.3] Planner-Executor-Critic AI Brain: criticReflection tie-breaker stage in autonomous workflow.
 */

'use strict';

const assert = require('assert');
const { reasoningEngine } = require('../src/core/reasoning-engine');
const { aiBrain } = require('../src/core/ai-brain');

async function runKlDivergenceBayesFactorAndCriticReflectionTests() {
  console.log('========================================================================');
  console.log('  EJII SUITE 70: KL-DIVERGENCE, BAYES FACTOR & CRITIC REFLECTION SUITE   ');
  console.log('========================================================================');

  // [70.1] Epistemic Information Gain: KL-Divergence D_KL(P || U)
  console.log('[70.1] Verifying Kullback-Leibler information gain metrics...');

  // Case A: Uniform distribution (0 bits information gain over prior)
  const uniformHypotheses = [
    { id: 'H1', confidence: 20 },
    { id: 'H2', confidence: 20 },
    { id: 'H3', confidence: 20 },
    { id: 'H4', confidence: 20 },
    { id: 'H5', confidence: 20 }
  ];
  const uniformMetrics = reasoningEngine.computeEpistemicMetrics(uniformHypotheses);
  console.log(`  ✓ Uniform distribution (5x 20%): KL = ${uniformMetrics.klDivergenceBits} bits, BF = ${uniformMetrics.bayesFactorTop2}, Jeffreys = "${uniformMetrics.jeffreysEvidenceScale}"`);
  assert.strictEqual(uniformMetrics.klDivergenceBits, 0, 'KL divergence must be 0 for uniform distribution');
  assert.strictEqual(uniformMetrics.bayesFactorTop2, 1.0, 'BF_12 must be 1.0 for equal probabilities');
  assert.strictEqual(uniformMetrics.jeffreysEvidenceScale, 'Barely Worth Mentioning');

  // Case B: Concentrated distribution (High information gain)
  const concentratedHypotheses = [
    { id: 'H1', confidence: 90 },
    { id: 'H2', confidence: 10 }
  ];
  const concentratedMetrics = reasoningEngine.computeEpistemicMetrics(concentratedHypotheses);
  console.log(`  ✓ Concentrated distribution (90%/10%): KL = ${concentratedMetrics.klDivergenceBits} bits, BF = ${concentratedMetrics.bayesFactorTop2}, Jeffreys = "${concentratedMetrics.jeffreysEvidenceScale}"`);
  assert.ok(concentratedMetrics.klDivergenceBits > 0.4, `KL divergence should be >0.4 bits, got ${concentratedMetrics.klDivergenceBits}`);
  assert.strictEqual(concentratedMetrics.bayesFactorTop2, 9.0, 'BF_12 must be 9.0 for 90/10');
  assert.strictEqual(concentratedMetrics.jeffreysEvidenceScale, 'Substantial');

  // Case C: Decisive single hypothesis
  const decisiveHypotheses = [
    { id: 'H1', confidence: 100 },
    { id: 'H2', confidence: 0 }
  ];
  const decisiveMetrics = reasoningEngine.computeEpistemicMetrics(decisiveHypotheses);
  console.log(`  ✓ Decisive distribution (100%/0%): BF = ${decisiveMetrics.bayesFactorTop2}, Jeffreys = "${decisiveMetrics.jeffreysEvidenceScale}"`);
  assert.strictEqual(decisiveMetrics.bayesFactorTop2, 100.0, 'BF_12 must be 100.0 for decisive probability');
  assert.strictEqual(decisiveMetrics.jeffreysEvidenceScale, 'Decisive');

  // [70.2] Harold Jeffreys Scale Tiers
  console.log('[70.2] Verifying Harold Jeffreys scale tiers across hypothesis ratios...');
  const testTiers = [
    { h: [{ confidence: 60 }, { confidence: 40 }], expectedScale: 'Barely Worth Mentioning' },
    { h: [{ confidence: 80 }, { confidence: 20 }], expectedScale: 'Substantial' },
    { h: [{ confidence: 92 }, { confidence: 8 }], expectedScale: 'Strong' },
    { h: [{ confidence: 98 }, { confidence: 2 }], expectedScale: 'Very Strong' }
  ];
  for (const t of testTiers) {
    const m = reasoningEngine.computeEpistemicMetrics(t.h);
    assert.strictEqual(m.jeffreysEvidenceScale, t.expectedScale, `Expected ${t.expectedScale} for BF ${m.bayesFactorTop2}`);
    console.log(`  ✓ Tier verified: BF ${m.bayesFactorTop2} -> "${m.jeffreysEvidenceScale}"`);
  }

  // [70.3] Planner-Executor-Critic AI Brain Autonomous Workflow
  console.log('[70.3] Verifying Critic Reflection stage in planAndExecuteAutonomousWorkflow...');
  const workflowResult = await aiBrain.planAndExecuteAutonomousWorkflow({
    goal: 'Test Critic Reflection Architecture',
    targetHost: '127.0.0.1',
    targetPort: 80,
    maxIterations: 2
  });

  assert.ok(workflowResult, 'Workflow result must be returned');
  assert.ok(workflowResult.criticReflection, 'criticReflection must be present in workflow report');
  const cr = workflowResult.criticReflection;
  console.log(`  ✓ Critic Reflection Stage: [${cr.stage}]`);
  console.log(`    - Top Hypothesis: [${cr.topHypothesisId}]`);
  console.log(`    - Bayes Factor BF12: ${cr.bayesFactorTop2} (${cr.jeffreysEvidenceScale})`);
  console.log(`    - Critique: "${cr.critique}"`);
  console.log(`    - Recommendation: [${cr.recommendation}]`);

  assert.strictEqual(cr.stage, 'CRITIC_REFLECTION');
  assert.ok(typeof cr.bayesFactorTop2 === 'number', 'bayesFactorTop2 must be a number');
  assert.ok(typeof cr.jeffreysEvidenceScale === 'string', 'jeffreysEvidenceScale must be a string');
  assert.ok(typeof cr.critique === 'string' && cr.critique.length > 10, 'critique must be a descriptive string');
  assert.ok(['PROCEED_WITH_GITOPS_RECONCILIATION', 'RE_PROBE_WIRE_TELEMETRY'].includes(cr.recommendation));

  console.log('\n>>> ALL SUITE 70 KL-DIVERGENCE & CRITIC REFLECTION TESTS PASSED 100% GREEN.\n');
}

if (require.main === module) {
  runKlDivergenceBayesFactorAndCriticReflectionTests().then(() => {
    process.exit(0);
  }).catch((err) => {
    console.error('Suite 70 failed:', err);
    process.exit(1);
  });
}

module.exports = {
  runSuite70: runKlDivergenceBayesFactorAndCriticReflectionTests,
  runKlDivergenceBayesFactorAndCriticReflectionTests
};
