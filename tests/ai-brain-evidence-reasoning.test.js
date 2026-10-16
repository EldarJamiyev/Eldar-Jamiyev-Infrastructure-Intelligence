/**
 * Test Suite 22: Shared AI Brain Evidence Reasoning & LLM Provider Test Suite
 * Verifies evidence-first Bayesian hypothesis evaluation, continuous belief revision,
 * distinguishing probe recommendations, and LLM provider deterministic fallback.
 */

'use strict';

const assert = require('node:assert/strict');
const { reasoningEngine } = require('../src/core/reasoning-engine');
const { incidentBriefingProvider, IncidentBriefingProvider } = require('../src/core/llm-provider');

async function runAiBrainEvidenceReasoningTests() {
  console.log('\n========================================================================');
  console.log('  SUITE 22: SHARED AI BRAIN EVIDENCE REASONING & LLM PROVIDER SUITE    ');
  console.log('  Bayesian Ranking, Dynamic Belief Revision, Probes & Dual Briefings   ');
  console.log('========================================================================');

  // 1. Evidence-First Initial Hypothesis Evaluation
  console.log('[22.1] Testing initial multi-hypothesis evaluation with calibrated probabilities...');
  const initialEval = reasoningEngine.evaluateIncident({
    incidentType: 'TCP_SYN_TIMEOUT',
    destIp: '192.168.1.100',
    destPort: 443,
    retransCount: 2,
    gatewayReachable: null,
    targetPingReachable: null
  });

  assert.ok(initialEval, 'Evaluation must be returned');
  assert.ok(Array.isArray(initialEval.rankedHypotheses), 'Ranked hypotheses must be an array');
  assert.ok(initialEval.rankedHypotheses.length >= 4, 'Must evaluate at least 4 competing hypotheses');

  // Verify probabilities sum to 100%
  const totalConf = initialEval.rankedHypotheses.reduce((sum, h) => sum + h.confidence, 0);
  assert.strictEqual(totalConf, 100, `Hypothesis probabilities must sum to 100%, got ${totalConf}%`);

  // Verify none are 0% or 100% prematurely without contradictory evidence
  for (const h of initialEval.rankedHypotheses) {
    assert.ok(h.confidence > 0, `Hypothesis ${h.id} confidence must be >0% without proof, got ${h.confidence}%`);
    assert.ok(h.confidence < 100, `Hypothesis ${h.id} confidence must be <100% without proof, got ${h.confidence}%`);
  }
  console.log(`  ✓ Evaluated ${initialEval.rankedHypotheses.length} hypotheses; total sum: 100%; zero premature 0%/100% assignments.`);

  // 2. Dynamic Belief Revision upon Ingesting Empirical Evidence
  console.log('[22.2] Testing dynamic belief revision upon empirical probe evidence...');
  const revised = reasoningEngine.reviseBeliefs(initialEval, {
    gatewayReachable: true,
    targetPingReachable: true
  });

  assert.ok(revised, 'Revised evaluation must be returned');
  assert.ok(Array.isArray(revised.revisions), 'Revisions delta must be recorded');
  assert.ok(revised.revisions.length >= 1, 'At least one hypothesis must be revised');

  const revisedTotal = revised.rankedHypotheses.reduce((sum, h) => sum + h.confidence, 0);
  assert.strictEqual(revisedTotal, 100, `Revised probabilities must sum to 100%, got ${revisedTotal}%`);

  // Gateway unreachable and remote host down must be eliminated by contradictory proof
  const gwH = revised.rankedHypotheses.find(h => h.id === 'GATEWAY_UNREACHABLE');
  assert.strictEqual(gwH.confidence, 0, 'Gateway unreachable must be eliminated (0%) after verified ping');
  assert.strictEqual(gwH.isContradicted, true);

  const hostH = revised.rankedHypotheses.find(h => h.id === 'REMOTE_HOST_DOWN');
  assert.strictEqual(hostH.confidence, 0, 'Remote host down must be eliminated (0%) after verified ping');
  assert.strictEqual(hostH.isContradicted, true);

  // Firewall silent drop should be promoted
  const firewallH = revised.rankedHypotheses.find(h => h.id === 'FIREWALL_SILENT_DROP');
  assert.ok(firewallH.confidence >= 50, `Firewall silent drop must be promoted (>=50%), got ${firewallH.confidence}%`);
  console.log(`  ✓ Belief revision verified: GATEWAY_UNREACHABLE and REMOTE_HOST_DOWN eliminated to 0%; FIREWALL_SILENT_DROP promoted to ${firewallH.confidence}%.`);

  // 3. Information Gain & Distinguishing Probe Recommendations
  console.log('[22.3] Testing distinguishing probe recommendations for ambiguous states...');
  const probes = reasoningEngine.recommendDistinguishingTests(initialEval.rankedHypotheses, {
    destIp: '192.168.1.100',
    destPort: 443
  });

  assert.ok(Array.isArray(probes));
  assert.ok(probes.length >= 3, 'Must recommend at least 3 distinguishing probes');
  assert.ok(probes.some(p => p.probeType === 'ICMP_PING_GATEWAY'), 'Must recommend Gateway ping');
  assert.ok(probes.some(p => p.probeType === 'ICMP_PING_TARGET'), 'Must recommend Target ping');
  assert.ok(probes.some(p => p.probeType === 'PATH_MTU_DF_SWEEP'), 'Must recommend Path MTU sweep');
  console.log(`  ✓ Recommender generated ${probes.length} distinguishing probes prioritized by information gain.`);

  // 4. LLM Provider Deterministic Fallback & Dual Briefing Synthesis
  console.log('[22.4] Testing LLM Provider abstraction & deterministic fallback synthesis...');
  // Instantiate provider pointing to an unreachable offline endpoint
  const offlineProvider = new IncidentBriefingProvider({
    provider: 'ollama',
    endpoint: 'http://127.0.0.1:54321', // Offline port
    model: 'mistral'
  });

  const incidentContext = {
    incidentType: 'TCP_SYN_TIMEOUT',
    topHypothesis: revised.rankedHypotheses[0],
    rankedHypotheses: revised.rankedHypotheses,
    distinguishingProbes: probes,
    contradictoryEvidence: revised.contradictoryEvidence,
    sourceIp: '192.168.1.50',
    destIp: '192.168.1.100',
    destPort: 443,
    protocol: 'TCP',
    retransCount: 2
  };

  // Test synchronous fallback generation
  const briefingSync = offlineProvider.generateDualBriefing(incidentContext);
  assert.ok(briefingSync.simpleOperatorMode, 'Must generate simpleOperatorMode');
  assert.ok(briefingSync.expertDiagnosticMode, 'Must generate expertDiagnosticMode');
  assert.ok(briefingSync.expertDiagnosticMode.rfcReferences.length >= 2, 'Must cite relevant RFCs');
  assert.ok(briefingSync.expertDiagnosticMode.bayesianEvidenceProvenance.formula.includes('P(Hi | E)'));

  // Test async LLM briefing call with graceful fallback
  const briefingAsync = await offlineProvider.generateLlmBriefing(incidentContext);
  assert.ok(briefingAsync.simpleOperatorMode);
  assert.ok(briefingAsync.expertDiagnosticMode);
  assert.strictEqual(briefingAsync.provider, 'ollama');
  assert.strictEqual(briefingAsync.fallbackUsed, true, 'Fallback must be used when LLM endpoint is unreachable');
  console.log(`  ✓ LLM Provider fallback confirmed: generated dual briefing seamlessly when endpoint offline.`);

  console.log('\n>>> ALL SUITE 22 SHARED AI BRAIN REASONING TESTS COMPLETED SUCCESSFULLY.\n');
}

if (require.main === module) {
  runAiBrainEvidenceReasoningTests().then(() => {
    process.exit(0);
  }).catch((err) => {
    console.error('Suite 22 failed:', err);
    process.exit(1);
  });
}

module.exports = { runAiBrainEvidenceReasoningTests };
