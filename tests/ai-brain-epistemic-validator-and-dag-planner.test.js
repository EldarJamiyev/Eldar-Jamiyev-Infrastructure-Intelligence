/**
 * EJII Test Suite 51: AI Brain Epistemic Entropy, Self-Validator & Causal DAG Planner
 *
 * Verifies:
 * [51.1] Shannon Entropy Math & Normalized Epistemic Metrics in Bayesian Engine
 * [51.2] Deterministic Output Self-Validator Auditing 6 Hard Empirical Invariants
 * [51.3] Causal DAG Planner with Backtracking & Acyclic Graph Topology
 * [51.4] Multi-Model Provider Health Matrix & Tiered Routing
 * [51.5] Natural Language to Wireshark AST Filter Compilation for Keep-Alives and Resets
 */

'use strict';

const assert = require('assert');
const { reasoningEngine } = require('../src/core/reasoning-engine');
const { aiModelOrchestrator } = require('../src/core/ai-model-orchestrator');
const { aiBrain } = require('../src/core/ai-brain');
const { PacketExplainEngine } = require('../src/network/packet-decoding/packet-explain-engine');

async function runSuite51() {
  console.log('========================================================================');
  console.log('  TEST SUITE 51: AI BRAIN EPISTEMIC VALIDATOR & CAUSAL DAG PLANNER      ');
  console.log('========================================================================\n');

  // -------------------------------------------------------------------------
  // [51.1] Shannon Entropy Math & Normalized Epistemic Metrics
  // -------------------------------------------------------------------------
  console.log('[Test 51.1] Verifying Shannon Entropy Math & Normalized Epistemic Metrics...');
  {
    // Test 1: Single certain hypothesis (0 entropy)
    const certainHypotheses = [{ id: 'H1', confidence: 100 }];
    const metricsCertain = reasoningEngine.computeEpistemicMetrics(certainHypotheses);
    assert.strictEqual(metricsCertain.shannonEntropyBits, 0, 'Certain hypothesis must have 0 bits of entropy');
    assert.strictEqual(metricsCertain.normalizedEntropyRatio, 0, 'Normalized entropy must be 0.0 for certain state');
    assert.strictEqual(metricsCertain.epistemicCertaintyRatio, 1.0, 'Epistemic certainty must be 1.0');

    // Test 2: Uniform distribution across 4 hypotheses (maximum entropy = log2(4) = 2.0 bits)
    const uniformHypotheses = [
      { id: 'H1', confidence: 25 },
      { id: 'H2', confidence: 25 },
      { id: 'H3', confidence: 25 },
      { id: 'H4', confidence: 25 }
    ];
    const metricsUniform = reasoningEngine.computeEpistemicMetrics(uniformHypotheses);
    assert.ok(Math.abs(metricsUniform.shannonEntropyBits - 2.0) < 0.01, 'Uniform 4-hypothesis distribution must yield ~2.0 bits');
    assert.strictEqual(metricsUniform.normalizedEntropyRatio, 1.0, 'Normalized entropy ratio must be 1.0 for uniform distribution');
    assert.strictEqual(metricsUniform.epistemicCertaintyRatio, 0.0, 'Epistemic certainty must be 0.0 for uniform distribution');

    // Test 3: Integrated evaluation attaches epistemicMetrics
    const evalRes = reasoningEngine.evaluateIncident({
      incidentType: 'TCP_SYN_TIMEOUT',
      destIp: '192.168.31.1',
      destPort: 443
    });
    assert.ok(evalRes.epistemicMetrics, 'Evaluation result must include epistemicMetrics');
    assert.ok(typeof evalRes.epistemicMetrics.shannonEntropyBits === 'number');
    assert.ok(evalRes.epistemicMetrics.normalizedEntropyRatio >= 0 && evalRes.epistemicMetrics.normalizedEntropyRatio <= 1.0);

    console.log('  ✓ Shannon entropy calculation and epistemic certainty normalization strictly verified.');
  }

  // -------------------------------------------------------------------------
  // [51.2] Deterministic Output Self-Validator Auditing 6 Invariants
  // -------------------------------------------------------------------------
  console.log('\n[Test 51.2] Verifying Deterministic Output Self-Validator...');
  {
    // Valid evaluation
    const validEval = reasoningEngine.evaluateIncident({
      incidentType: 'TCP_RST_REJECT',
      destIp: '192.168.31.89',
      destPort: 8080,
      tcpRstObserved: true
    });
    const auditValid = aiModelOrchestrator.validateDiagnosisOutput(validEval);
    assert.strictEqual(auditValid.isValid, true, 'Valid evaluation must pass self-validator');
    assert.strictEqual(auditValid.passedCount, 6, 'All 6 invariants must pass');
    assert.strictEqual(auditValid.violationsCount, 0, 'Zero violations expected on valid evaluation');
    assert.strictEqual(auditValid.auditScore, 100, 'Audit score must be 100%');

    // Invalid evaluation: violated confidence sum and unshielded dangerous command
    const invalidEval = {
      incidentType: 'CORRUPTED',
      totalEvidenceWeight: 0, // Invariant 4 violation
      rankedHypotheses: [
        { id: 'H1', confidence: 60, isContradicted: true, status: 'PROMOTED', priorScore: 1.5 }, // Invariants 1, 2, 3 violation
        { id: 'H2', confidence: 10, isContradicted: false, priorScore: 0.5 }
      ],
      synthesis: {
        recommendedRemediation: 'format C: /fs:ntfs /q' // Invariant 6 violation
      }
    };
    const auditInvalid = aiModelOrchestrator.validateDiagnosisOutput(invalidEval);
    assert.strictEqual(auditInvalid.isValid, false, 'Invalid evaluation must be rejected by self-validator');
    assert.ok(auditInvalid.violationsCount >= 4, 'Multiple invariant violations must be detected');

    console.log('  ✓ Deterministic output self-validator auditing all 6 empirical invariants verified.');
  }

  // -------------------------------------------------------------------------
  // [51.3] Causal DAG Planner with Backtracking & Acyclic Topology
  // -------------------------------------------------------------------------
  console.log('\n[Test 51.3] Verifying Causal DAG Planner in Autonomous Investigation...');
  {
    const invRes = await aiBrain.runAutonomousInvestigation({
      targetIp: '192.168.31.1',
      targetPort: 443,
      maxSteps: 2
    });

    assert.strictEqual(invRes.success, true, 'Autonomous investigation must succeed');
    assert.ok(invRes.dagSummary, 'Investigation must contain dagSummary');
    assert.strictEqual(invRes.dagSummary.isAcyclic, true, 'Causal DAG must be strictly acyclic');
    assert.ok(invRes.dagSummary.nodesCount >= 2, 'DAG must contain at least start and verdict nodes');
    assert.ok(invRes.dagSummary.edgesCount >= 1, 'DAG must contain at least one causal edge');
    assert.ok(Array.isArray(invRes.dagSummary.dagNodes), 'DAG nodes must be an array');
    assert.ok(Array.isArray(invRes.dagSummary.dagEdges), 'DAG edges must be an array');
    assert.ok(typeof invRes.dagSummary.backtrackingOccurred === 'boolean');

    assert.ok(invRes.epistemicProgress, 'Investigation must contain epistemicProgress');
    assert.ok(typeof invRes.epistemicProgress.informationGainBits === 'number');

    console.log(`  ✓ Causal DAG planner generated ${invRes.dagSummary.nodesCount} nodes, ${invRes.dagSummary.edgesCount} edges with verified acyclicity.`);
  }

  // -------------------------------------------------------------------------
  // [51.4] Multi-Model Provider Health Matrix & Tiered Routing
  // -------------------------------------------------------------------------
  console.log('\n[Test 51.4] Verifying Multi-Model Provider Health Matrix...');
  {
    const health = aiModelOrchestrator.getProviderHealthMatrix();
    assert.strictEqual(health.status, 'OPERATIONAL');
    assert.strictEqual(health.activeRoutingPolicy, 'LOCAL_FIRST_WITH_BAYESIAN_BYPASS');
    assert.ok(Array.isArray(health.providers), 'Providers must be an array');
    assert.strictEqual(health.providers.length, 4, 'Exactly 4 providers must be reported in matrix');

    const bayesianCore = health.providers.find(p => p.id === 'deterministic_bayesian_engine');
    assert.ok(bayesianCore, 'Deterministic Bayesian Engine must be present in matrix');
    assert.strictEqual(bayesianCore.status, 'HEALTHY');

    const localOllama = health.providers.find(p => p.id === 'ollama_local');
    assert.ok(localOllama, 'Local Ollama runtime must be present in matrix');

    console.log('  ✓ Multi-model provider health matrix and deterministic bypass policy verified.');
  }

  // -------------------------------------------------------------------------
  // [51.5] Natural Language to Wireshark AST Filter Compilation
  // -------------------------------------------------------------------------
  console.log('\n[Test 51.5] Verifying NL to Wireshark AST Filter Compilation for Keep-Alives & Resets...');
  {
    // Keep-alives
    const keepAliveFilter = PacketExplainEngine.translateNaturalLanguageToFilter('show keep alive packets');
    assert.strictEqual(keepAliveFilter.valid, true);
    assert.ok(keepAliveFilter.filter.includes('keep_alive') || keepAliveFilter.filter.includes('tcp.len == 0'));

    // TCP resets
    const resetFilter = PacketExplainEngine.translateNaturalLanguageToFilter('show tcp resets');
    assert.strictEqual(resetFilter.valid, true);
    assert.ok(resetFilter.filter.includes('tcp.flags.reset == 1'));

    // Retransmissions
    const retransFilter = PacketExplainEngine.translateNaturalLanguageToFilter('retransmissions');
    assert.strictEqual(retransFilter.valid, true);
    assert.ok(retransFilter.filter.includes('tcp.analysis.retransmission'));

    console.log('  ✓ Natural language translation to Wireshark display filter AST verified.');
  }

  console.log('\n========================================================================');
  console.log('  TEST SUITE 51: 100% PASSED (ALL 5 CHECKS VERIFIED)');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runSuite51().catch(err => {
    console.error('Suite 51 failed:', err);
    process.exit(1);
  });
}

module.exports = { runSuite51 };
