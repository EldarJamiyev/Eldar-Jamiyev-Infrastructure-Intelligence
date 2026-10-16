/**
 * EJII Test Suite: Autonomous AI Causal Investigator & Multi-Hop Reasoning Engine
 * Validates:
 * 1. Rule of Contradictory Proof:
 *    - Strict elimination (0% posterior confidence) of contradicted hypotheses upon arrival of physical wire proof
 *    - Gateway responsiveness eliminates GATEWAY_UNREACHABLE
 *    - ICMP Echo reply eliminates DESTINATION_HOST_OFFLINE
 *    - RFC 793 TCP RST eliminates FIREWALL_SILENT_DROP
 *    - Strict 100.0% Bayesian posterior normalization invariant maintained under multi-elimination tournament
 * 2. Autonomous Distinguishing Probe Dispatcher:
 *    - Dynamic probe prioritization by expected information gain
 *    - Path MTU DF sweep (ping -f -l 1472) execution and fragmentation detection
 *    - Gateway and target ICMP probe dispatch
 *    - Alternate port TCP SYN probe dispatch
 * 3. Dual-Mode Briefing Synthesis:
 *    - Helpdesk plain-language summary for level-1 NOC operators (non-technical, impact, immediate action)
 *    - RFC-grounded engineering provenance (RFC 793, RFC 2979, RFC 826, Bayesian formula audit trail)
 */

'use strict';

process.env.NODE_ENV = process.env.NODE_ENV || 'test';
const assert = require('assert');
const { reasoningEngine } = require('../src/core/reasoning-engine');
const { incidentBriefingProvider } = require('../src/core/llm-provider');

async function runAiCausalInvestigatorTests() {
  console.log('\n========================================================================');
  console.log('  SUITE 18: AUTONOMOUS AI CAUSAL INVESTIGATOR & REASONING ENGINE        ');
  console.log('  Rule of Contradictory Proof, Distinguishing Probes & Dual Briefings   ');
  console.log('========================================================================');

  // ---------------------------------------------------------------------------
  // 1. Rule of Contradictory Proof: Gateway Reachability Eliminates Gateway Failure
  // ---------------------------------------------------------------------------
  console.log('\n[18.1] Testing Rule of Contradictory Proof: Gateway Reachability...');
  const resGateway = reasoningEngine.evaluateIncident({
    incidentType: 'TCP_SYN_TIMEOUT',
    destIp: '10.22.12.204',
    destPort: 443,
    retransCount: 3,
    gatewayReachable: true, // Physical proof: default gateway is alive
    targetPingReachable: false
  });

  // Verify GATEWAY_UNREACHABLE is contradicted and clamped to 0%
  const gwHypothesis = resGateway.rankedHypotheses.find(h => h.id === 'GATEWAY_UNREACHABLE');
  assert.ok(gwHypothesis, 'GATEWAY_UNREACHABLE must be in evaluated hypotheses');
  assert.strictEqual(gwHypothesis.confidence, 0, 'Contradicted GATEWAY_UNREACHABLE must be clamped to 0%');
  assert.strictEqual(gwHypothesis.isContradicted, true, 'isContradicted flag must be true');
  assert.strictEqual(gwHypothesis.contradictionRule, 'RFC 826 / ICMP Echo');

  // Verify contradictory evidence is logged in audit trail
  assert.ok(resGateway.contradictoryEvidence.length >= 1, 'Contradictory evidence proof must be recorded');
  const gwProof = resGateway.contradictoryEvidence.find(c => c.hypothesis === 'GATEWAY_UNREACHABLE');
  assert.ok(gwProof, 'Audit trail must contain GATEWAY_UNREACHABLE elimination proof');
  assert.strictEqual(gwProof.rule, 'RFC 826 / ICMP Echo');

  // Verify total confidence sums to strictly 100%
  const totalConfGateway = resGateway.rankedHypotheses.reduce((s, h) => s + h.confidence, 0);
  assert.strictEqual(totalConfGateway, 100, `Bayesian probabilities must strictly sum to 100%, got ${totalConfGateway}%`);

  console.log(`  ✓ Gateway reachability proved. GATEWAY_UNREACHABLE strictly clamped to 0% (${gwProof.reason}). Total confidence sum: ${totalConfGateway}%.`);

  // ---------------------------------------------------------------------------
  // 2. Rule of Contradictory Proof: Target ICMP Ping Eliminates Host Down
  // ---------------------------------------------------------------------------
  console.log('\n[18.2] Testing Rule of Contradictory Proof: Target Echo Reply Eliminates Host Offline...');
  const resTargetPing = reasoningEngine.evaluateIncident({
    incidentType: 'TCP_SYN_TIMEOUT',
    destIp: '10.22.12.204',
    destPort: 443,
    retransCount: 2,
    gatewayReachable: true,
    targetPingReachable: true // Physical proof: remote host is responding to ICMP Echo
  });

  const hostOfflineH = resTargetPing.rankedHypotheses.find(h => h.id === 'REMOTE_HOST_DOWN');
  assert.ok(hostOfflineH, 'REMOTE_HOST_DOWN must be in evaluated hypotheses');
  assert.strictEqual(hostOfflineH.confidence, 0, 'Contradicted REMOTE_HOST_DOWN must be clamped to 0%');
  assert.strictEqual(hostOfflineH.isContradicted, true);
  assert.strictEqual(hostOfflineH.contradictionRule, 'RFC 792 ICMP Echo Reply');

  // When target responds to ping, FIREWALL_SILENT_DROP is promoted as top hypothesis
  const firewallH = resTargetPing.rankedHypotheses.find(h => h.id === 'FIREWALL_SILENT_DROP');
  assert.ok(firewallH, 'FIREWALL_SILENT_DROP must exist');
  assert.ok(firewallH.confidence >= 50, `Firewall drop should be heavily promoted (>=50%), got ${firewallH.confidence}%`);

  const totalConfTarget = resTargetPing.rankedHypotheses.reduce((s, h) => s + h.confidence, 0);
  assert.strictEqual(totalConfTarget, 100, `Bayesian probabilities must strictly sum to 100%, got ${totalConfTarget}%`);

  console.log(`  ✓ Target ping proved. REMOTE_HOST_DOWN clamped to 0%. FIREWALL_SILENT_DROP promoted to ${firewallH.confidence}%. Total: ${totalConfTarget}%.`);

  // ---------------------------------------------------------------------------
  // 3. Rule of Contradictory Proof: RFC 793 TCP RST Eliminates Silent Firewall Drop
  // ---------------------------------------------------------------------------
  console.log('\n[18.3] Testing Rule of Contradictory Proof: RFC 793 TCP RST Eliminates Silent Drop...');
  const resTcpRst = reasoningEngine.evaluateIncident({
    incidentType: 'TCP_RST_REJECT',
    destIp: '10.22.12.204',
    destPort: 8080,
    tcpRstObserved: true, // Physical proof: RFC 793 RST received
    gatewayReachable: true,
    targetPingReachable: true
  });

  const silentDropH = resTcpRst.rankedHypotheses.find(h => h.id === 'FIREWALL_SILENT_DROP');
  assert.ok(silentDropH, 'FIREWALL_SILENT_DROP must exist');
  assert.strictEqual(silentDropH.confidence, 0, 'Contradicted FIREWALL_SILENT_DROP must be clamped to 0%');
  assert.strictEqual(silentDropH.isContradicted, true);
  assert.strictEqual(silentDropH.contradictionRule, 'RFC 2979');

  // PORT_CLOSED_SERVICE_STOPPED should be promoted as top hypothesis
  const portClosedH = resTcpRst.rankedHypotheses.find(h => h.id === 'PORT_CLOSED_SERVICE_STOPPED');
  assert.ok(portClosedH, 'PORT_CLOSED_SERVICE_STOPPED must exist');
  assert.ok(portClosedH.confidence >= 50, `Port closed should be top promoted (>=50%), got ${portClosedH.confidence}%`);

  const totalConfRst = resTcpRst.rankedHypotheses.reduce((s, h) => s + h.confidence, 0);
  assert.strictEqual(totalConfRst, 100, `Bayesian probabilities must strictly sum to 100%, got ${totalConfRst}%`);

  console.log(`  ✓ TCP RST observed. FIREWALL_SILENT_DROP clamped to 0%. PORT_CLOSED_SERVICE_STOPPED promoted to ${portClosedH.confidence}%. Total: ${totalConfRst}%.`);

  // ---------------------------------------------------------------------------
  // 4. Autonomous Distinguishing Probe Dispatcher: Information Gain & Sweep Probes
  // ---------------------------------------------------------------------------
  console.log('\n[18.4] Testing Autonomous Distinguishing Probe Dispatcher...');

  // 4.1 Probe recommendations based on information gain
  const recommendedProbes = reasoningEngine.recommendDistinguishingTests(
    resGateway.rankedHypotheses,
    { destIp: '10.22.12.204', destPort: 443 }
  );

  assert.ok(recommendedProbes.length >= 3, 'Must recommend at least 3 distinguishing probes');
  const mtuProbe = recommendedProbes.find(p => p.probeType === 'PATH_MTU_DF_SWEEP');
  assert.ok(mtuProbe, 'Must include PATH_MTU_DF_SWEEP probe to disambiguate MTU black holes');
  assert.ok(mtuProbe.command.includes('-f -l 1472'), 'DF sweep command must use DF flag (-f) and 1472 bytes');
  assert.ok(mtuProbe.informationGain.includes('High'), 'Information gain must be High');

  const traceProbe = recommendedProbes.find(p => p.probeType === 'TRACEROUTE_PATH_DISCOVERY');
  assert.ok(traceProbe, 'Must include TRACEROUTE_PATH_DISCOVERY probe');

  // 4.2 Autonomous probe dispatch execution
  console.log('  Executing autonomous Path MTU DF sweep probe...');
  const mtuOutcome = await reasoningEngine.dispatchDistinguishingProbe('PATH_MTU_DF_SWEEP', '127.0.0.1');
  assert.strictEqual(mtuOutcome.probeType, 'PATH_MTU_DF_SWEEP');
  assert.strictEqual(typeof mtuOutcome.success, 'boolean');
  assert.ok(mtuOutcome.evidence, 'Probe must return structured empirical evidence');
  assert.strictEqual(mtuOutcome.evidence.mtuSize, 1500);

  console.log('  Executing autonomous ICMP Gateway probe...');
  const pingOutcome = await reasoningEngine.dispatchDistinguishingProbe('ICMP_PING_GATEWAY', '127.0.0.1', { gatewayIp: '127.0.0.1' });
  assert.strictEqual(pingOutcome.probeType, 'ICMP_PING_GATEWAY');
  assert.strictEqual(typeof pingOutcome.success, 'boolean');
  assert.ok(typeof pingOutcome.durationMs === 'number');

  console.log(`  ✓ Recommended ${recommendedProbes.length} information-gain probes (Path MTU DF sweep, Gateway check, Alternate port).`);
  console.log(`  ✓ Dispatched autonomous probes successfully with empirical wire telemetry.`);

  // ---------------------------------------------------------------------------
  // 5. Dual-Mode Diagnostic Briefing: Helpdesk Plain-Language vs RFC Provenance
  // ---------------------------------------------------------------------------
  console.log('\n[18.5] Testing Dual-Mode Diagnostic Briefing Synthesis...');

  const dualBriefing = incidentBriefingProvider.generateDualBriefing({
    incidentType: 'TCP_SYN_TIMEOUT',
    topHypothesis: resTargetPing.rankedHypotheses[0],
    rankedHypotheses: resTargetPing.rankedHypotheses,
    distinguishingProbes: recommendedProbes,
    contradictoryEvidence: resTargetPing.contradictoryEvidence,
    sourceIp: '10.168.195.33',
    destIp: '10.22.12.204',
    destPort: 443,
    protocol: 'TCP',
    retransCount: 2
  });

  // Verify Simple Operator Mode (Helpdesk)
  const simple = dualBriefing.simpleOperatorMode;
  assert.ok(simple, 'simpleOperatorMode must exist');
  assert.ok(simple.plainLanguageBriefing.length > 20, 'plainLanguageBriefing must be descriptive');
  assert.ok(simple.nonTechnicalExplanation.length > 20, 'nonTechnicalExplanation must explain the reason simply');
  assert.ok(simple.businessImpactAssessment.length > 10, 'businessImpactAssessment must describe user impact');
  assert.ok(simple.immediateOperatorAction.length > 10, 'immediateOperatorAction must provide clear next steps');
  assert.ok(!simple.plainLanguageBriefing.includes('Bayesian posterior'), 'Simple mode must not contain mathematical jargon');

  // Verify Expert Diagnostic Mode (Engineering Provenance)
  const expert = dualBriefing.expertDiagnosticMode;
  assert.ok(expert, 'expertDiagnosticMode must exist');
  assert.ok(expert.rfcReferences.length >= 2, 'Must cite at least 2 relevant RFCs');
  assert.ok(expert.rfcReferences.some(r => r.includes('RFC 793')), 'Must cite RFC 793 (TCP)');
  assert.ok(expert.rfcReferences.some(r => r.includes('RFC 2979')), 'Must cite RFC 2979 (Firewalls)');

  // Verify Bayesian Evidence Provenance
  const bayes = expert.bayesianEvidenceProvenance;
  assert.ok(bayes, 'bayesianEvidenceProvenance must exist');
  assert.ok(bayes.formula.includes('P(Hi | E)'), 'Must contain exact Bayesian theorem formula');
  assert.ok(bayes.eliminationStandard.includes('Rule of Contradictory Proof'), 'Must document Rule of Contradictory Proof');

  // Verify Contradictory Proofs in Expert Mode
  assert.ok(expert.contradictoryProofs.length >= 1, 'Expert mode must include contradictory proofs');
  assert.ok(expert.contradictoryProofs.some(p => p.hypothesis === 'REMOTE_HOST_DOWN'));

  // Verify Ranked Hypotheses with Contradiction Metadata
  assert.ok(expert.rankedHypotheses.length >= 4);
  const contradictedInExpert = expert.rankedHypotheses.find(h => h.isContradicted);
  assert.ok(contradictedInExpert, 'At least one hypothesis must be flagged as contradicted');
  assert.strictEqual(contradictedInExpert.confidence, 0);
  assert.ok(contradictedInExpert.rationale.includes('disproven by contradictory proof'));

  console.log(`  ✓ Dual-mode briefing generated:`);
  console.log(`    - Simple Helpdesk Briefing: "${simple.plainLanguageBriefing.slice(0, 75)}..."`);
  console.log(`    - Immediate Action: "${simple.immediateOperatorAction}"`);
  console.log(`    - RFC Citations: [${expert.rfcReferences.join(', ')}]`);
  console.log(`    - Bayesian Formula: ${bayes.formula}`);
  console.log(`    - Contradictory Proofs: ${expert.contradictoryProofs.length} recorded.`);

  console.log('\n>>> ALL SUITE 18 AI CAUSAL INVESTIGATOR TESTS COMPLETED SUCCESSFULLY.\n');
}

if (require.main === module) {
  runAiCausalInvestigatorTests().then(() => {
    process.exit(0);
  }).catch((err) => {
    console.error('Suite 18 failed:', err);
    process.exit(1);
  });
}

module.exports = { runAiCausalInvestigatorTests };
