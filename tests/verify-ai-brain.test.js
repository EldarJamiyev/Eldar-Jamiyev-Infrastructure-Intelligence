/**
 * EJII Continuous Adaptive AI Brain & Bayesian Reasoning Verification Suite
 * Verifies:
 *  1. Autonomous continuous telemetry ingestion and learned baseline calculation
 *  2. Bayesian probability computation over competing hypotheses (P(Hi|E) = 100%)
 *  3. Dynamic belief revision when new probe evidence arrives
 *  4. Information-gain probe recommendations
 *  5. Dual-Tier briefing synthesis (Simple Operator vs Expert Diagnostic Mode)
 *  6. Disk memory persistence in data/brain_memory.json
 *
 * Zero-Elevation & Zero-Simulation Mandate.
 */

process.env.NODE_ENV = process.env.NODE_ENV || 'test';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { reasoningEngine } = require('../src/core/reasoning-engine');
const { aiBrain } = require('../src/core/ai-brain');
const { incidentBriefingProvider } = require('../src/core/llm-provider');
const { DEFAULT_BRAIN_CONFIG } = require('../src/core/brain-config-schema');

async function runAiBrainTests() {
  console.log('========================================================================');
  console.log('  EJII CONTINUOUS ADAPTIVE AI BRAIN & BAYESIAN REASONING TEST SUITE     ');
  console.log('========================================================================');

  // --------------------------------------------------------------------------
  // Test 1: Baseline Learning and Continuous Telemetry Ingestion
  // --------------------------------------------------------------------------
  console.log('\n[Test 1] Testing Continuous Telemetry Ingestion & Baseline Learning...');
  aiBrain.loadDynamicConfig(DEFAULT_BRAIN_CONFIG);
  const targetHost = 'hesabat.taxes.gov.az';
  aiBrain.baselineMetrics.delete(targetHost);
  
  aiBrain.ingestTelemetry({
    target: targetHost,
    rttMs: 14.5,
    destPort: 443,
    protocol: 'TCP'
  });
  aiBrain.ingestTelemetry({
    target: targetHost,
    rttMs: 18.2,
    destPort: 443,
    protocol: 'TCP'
  });
  aiBrain.ingestTelemetry({
    target: targetHost,
    rttMs: 12.1,
    destPort: 443,
    protocol: 'TCP'
  });

  const baseline = aiBrain.getTargetBaseline(targetHost);
  assert.ok(baseline, `Baseline must exist for ${targetHost}`);
  assert.strictEqual(baseline.minRtt, 12.1, 'Minimum RTT must be 12.1 ms');
  assert.strictEqual(baseline.maxRtt, 18.2, 'Maximum RTT must be 18.2 ms');
  assert.strictEqual(baseline.sampleCount >= 3, true, 'Sample count must be >= 3');
  assert.strictEqual(baseline.status, 'PROVISIONAL_INSUFFICIENT_SAMPLES', 'Sample count < 5 must be marked PROVISIONAL_INSUFFICIENT_SAMPLES');

  // Ingest 2 more samples to reach sampleCount >= 5 threshold
  aiBrain.ingestTelemetry({ target: targetHost, rttMs: 15.0, destPort: 443, protocol: 'TCP' });
  aiBrain.ingestTelemetry({ target: targetHost, rttMs: 16.5, destPort: 443, protocol: 'TCP' });
  const updatedEstBaseline = aiBrain.getTargetBaseline(targetHost);
  assert.strictEqual(updatedEstBaseline.sampleCount >= 5, true, 'Sample count must be >= 5');
  assert.strictEqual(updatedEstBaseline.status, 'ESTABLISHED', 'Baseline with >=5 samples must be ESTABLISHED');
  assert.ok(typeof updatedEstBaseline.variance === 'number' && updatedEstBaseline.variance > 0, 'Variance must be calculated');
  assert.ok(typeof updatedEstBaseline.stddev === 'number' && updatedEstBaseline.stddev > 0, 'StdDev must be calculated');
  console.log(`  ✓ Target baseline for ${targetHost} learned: Min=${baseline.minRtt}ms, Avg=${updatedEstBaseline.avgRtt}ms, Max=${baseline.maxRtt}ms, Variance=${updatedEstBaseline.variance}, StdDev=${updatedEstBaseline.stddev} (Status: ${updatedEstBaseline.status}).`);

  // --------------------------------------------------------------------------
  // Test 2: Bayesian Probability Scoring (Sum = 100%)
  // --------------------------------------------------------------------------
  console.log('\n[Test 2] Testing Bayesian Probability Scoring & Hypothesis Normalization...');
  const evaluation = reasoningEngine.evaluateIncident({
    incidentType: 'TCP_SYN_TIMEOUT',
    destIp: '10.22.12.204',
    destPort: 443,
    retransCount: 3,
    gatewayReachable: true,
    targetPingReachable: false
  });

  assert.ok(evaluation.rankedHypotheses.length >= 4, 'Must evaluate at least 4 competing hypotheses');
  
  // Verify strict Bayesian normalization sum
  const totalConfidence = evaluation.rankedHypotheses.reduce((sum, h) => sum + h.confidence, 0);
  assert.strictEqual(totalConfidence, 100, `Bayesian probabilities must strictly sum to 100%, found: ${totalConfidence}%`);

  // Gateway was reachable, so GATEWAY_UNREACHABLE must be eliminated (<5%)
  const gatewayH = evaluation.rankedHypotheses.find(h => h.id === 'GATEWAY_UNREACHABLE');
  assert.ok(gatewayH, 'Gateway hypothesis must exist');
  assert.ok(gatewayH.confidence <= 5, `Gateway hypothesis must be eliminated (confidence <= 5%), got ${gatewayH.confidence}%`);

  console.log(`  ✓ Evaluated ${evaluation.rankedHypotheses.length} competing hypotheses. Total probability sum: ${totalConfidence}%.`);
  console.log(`  ✓ Top hypothesis: [${evaluation.topHypothesis.id}] with ${evaluation.topHypothesis.confidence}% confidence.`);
  console.log(`  ✓ Gateway Unreachable was correctly eliminated to ${gatewayH.confidence}% due to successful gateway probe.`);

  // --------------------------------------------------------------------------
  // Test 3: Dynamic Belief Revision upon Arrival of New Evidence
  // --------------------------------------------------------------------------
  console.log('\n[Test 3] Testing Dynamic Belief Revision when New Probe Evidence Arrives...');
  // Operator runs ICMP ping to target, and target host surprisingly answers!
  const revisedEvaluation = reasoningEngine.reviseBeliefs(evaluation, {
    destIp: '10.22.12.204',
    targetPingReachable: true // TARGET IS ALIVE!
  });

  const revisedTotal = revisedEvaluation.rankedHypotheses.reduce((sum, h) => sum + h.confidence, 0);
  assert.strictEqual(revisedTotal, 100, `Revised Bayesian probabilities must strictly sum to 100%, found: ${revisedTotal}%`);

  // Since target host is alive, REMOTE_HOST_DOWN must plummet to ~0%, while FIREWALL_SILENT_DROP skyrockets!
  const hostDownH = revisedEvaluation.rankedHypotheses.find(h => h.id === 'REMOTE_HOST_DOWN');
  const firewallH = revisedEvaluation.rankedHypotheses.find(h => h.id === 'FIREWALL_SILENT_DROP');
  
  assert.ok(hostDownH.confidence <= 10, `Remote Host Down must drop to <= 10%, found: ${hostDownH.confidence}%`);
  assert.ok(firewallH.confidence >= 70, `Firewall Silent Drop must rise to >= 70%, found: ${firewallH.confidence}%`);
  assert.strictEqual(revisedEvaluation.topHypothesis.id, 'FIREWALL_SILENT_DROP', 'Firewall drop must become top hypothesis');

  assert.ok(revisedEvaluation.revisions.length > 0, 'Revisions array must record belief shifts');
  console.log(`  ✓ Dynamic belief revision succeeded:`);
  for (const rev of revisedEvaluation.revisions) {
    console.log(`    - [${rev.action}] ${rev.label}: ${rev.previousConfidence}% -> ${rev.newConfidence}% (${rev.delta > 0 ? '+' : ''}${rev.delta}%)`);
  }

  // --------------------------------------------------------------------------
  // Test 4: Next-Best Diagnostic Probe Recommendations
  // --------------------------------------------------------------------------
  console.log('\n[Test 4] Testing Next-Best Diagnostic Probe Recommendations (Max Information Gain)...');
  const unprobedEvaluation = reasoningEngine.evaluateIncident({
    incidentType: 'TCP_SYN_TIMEOUT',
    destIp: '10.22.12.204',
    destPort: 443,
    retransCount: 3
  });
  const probes = unprobedEvaluation.distinguishingProbes;
  assert.ok(probes.length >= 2, 'Must recommend at least 2 diagnostic probes');
  assert.ok(probes.some(p => p.probeType === 'ICMP_PING_TARGET'), 'Must recommend target ICMP probe');
  assert.ok(probes.some(p => p.probeType === 'TRACEROUTE_PATH_DISCOVERY'), 'Must recommend traceroute path discovery');
  console.log(`  ✓ Generated ${probes.length} distinguishing diagnostic probes with maximal information gain.`);

  // --------------------------------------------------------------------------
  // Test 5: Dual-Tier Briefing Generation
  // --------------------------------------------------------------------------
  console.log('\n[Test 5] Testing Dual-Tier Briefing Generation (Simple vs Expert)...');
  const briefing = incidentBriefingProvider.synthesizeBriefing(revisedEvaluation, {
    destIp: '10.22.12.204',
    destPort: 443
  });

  assert.ok(briefing.simpleOperatorMode.plainLanguageBriefing, 'Simple mode briefing must exist');
  assert.ok(briefing.simpleOperatorMode.immediateOperatorAction, 'Simple mode immediate action must exist');
  assert.ok(briefing.expertDiagnosticMode.rfcReferences.length > 0, 'Expert mode must cite RFCs');
  assert.ok(briefing.expertDiagnosticMode.rankedHypotheses.length > 0, 'Expert mode must include ranked hypotheses');
  console.log(`  ✓ Dual-Tier briefing synthesized: Simple non-technical briefing and Expert RFC citations verified.`);

  // --------------------------------------------------------------------------
  // Test 6: Memory Persistence to Disk (data/brain_memory.test.json)
  // --------------------------------------------------------------------------
  console.log(`\n[Test 6] Testing Brain Memory Disk Persistence (${path.basename(aiBrain.memoryFilePath)})...`);
  aiBrain._saveMemory();
  const memPath = aiBrain.memoryFilePath;
  assert.ok(fs.existsSync(memPath), `${path.basename(memPath)} must exist`);
  const memRaw = fs.readFileSync(memPath, 'utf8');
  const memJson = JSON.parse(memRaw);
  assert.ok(memJson.baselineMetrics[targetHost], `Memory file must contain learned baseline for ${targetHost}`);
  console.log(`  ✓ Disk persistence verified: ${path.basename(memPath)} stores ${memJson.baselinesCount} baselines and ${memJson.incidentsRecorded} incidents.`);

  // --------------------------------------------------------------------------
  // Test 7: Live Wire Frame Ingestion & Baseline Learning Loop
  // --------------------------------------------------------------------------
  console.log('\n[Test 7] Testing Live Wire Frame Ingestion & Dynamic Baseline Updating...');
  const wireIp = '10.22.12.204';
  const initialBase = aiBrain.getTargetBaseline(wireIp);
  const initialSamples = initialBase ? initialBase.sampleCount : 0;

  // Ingest wire frames with genuine RTT measurements
  aiBrain.ingestWireFrame({
    srcIp: '10.168.195.33',
    dstIp: wireIp,
    protocol: 'TCP',
    tcp: { flags: { ack: true } },
    tcpAnalysis: { rttMs: 2.4 }
  });
  aiBrain.ingestWireFrame({
    srcIp: '10.168.195.33',
    dstIp: wireIp,
    protocol: 'TCP',
    tcp: { flags: { ack: true } },
    tcpAnalysis: { rttMs: 3.1 }
  });

  const updatedBase = aiBrain.getTargetBaseline(wireIp);
  assert.ok(updatedBase, 'Updated baseline must exist for wire IP');
  assert.strictEqual(updatedBase.sampleCount, initialSamples + 2, 'Sample count must increase by exactly 2');

  // Ingest wire frame with only tcpDeltaMs (must be safely rejected from RTT baselines)
  aiBrain.ingestWireFrame({
    srcIp: '10.168.195.33',
    dstIp: wireIp,
    protocol: 'TCP',
    tcpDeltaMs: 42.5
  });
  const afterDeltaBase = aiBrain.getTargetBaseline(wireIp);
  assert.strictEqual(afterDeltaBase.sampleCount, updatedBase.sampleCount, 'tcpDeltaMs must NOT increment RTT baseline samples');
  console.log(`  ✓ Wire frame ingestion verified: ${wireIp} baseline updated to ${updatedBase.sampleCount} samples (avg: ${updatedBase.avgRtt}ms).`);
  console.log(`  ✓ Inter-packet delta (tcpDeltaMs) safely rejected from RTT baseline calculation.`);

  // --------------------------------------------------------------------------
  // Test 8: Idempotent Incident Deduplication (SHA-256 Keys)
  // --------------------------------------------------------------------------
  console.log('\n[Test 8] Testing Idempotent Incident Deduplication (SHA-256 Deterministic Keys)...');
  const incidentTarget = '85.132.27.92';
  const initialHistLen = aiBrain.incidentHistory.length;

  // Ingest anomaly 3 times consecutively
  const inc1 = aiBrain.ingestTelemetry({
    target: incidentTarget,
    destIp: incidentTarget,
    destPort: 443,
    incidentType: 'TCP_SYN_TIMEOUT',
    isAnomaly: true
  });
  const inc2 = aiBrain.ingestTelemetry({
    target: incidentTarget,
    destIp: incidentTarget,
    destPort: 443,
    incidentType: 'TCP_SYN_TIMEOUT',
    isAnomaly: true
  });
  const inc3 = aiBrain.ingestTelemetry({
    target: incidentTarget,
    destIp: incidentTarget,
    destPort: 443,
    incidentType: 'TCP_SYN_TIMEOUT',
    isAnomaly: true
  });

  assert.strictEqual(inc1.incidentKey, inc2.incidentKey, 'Incident keys must be identical for identical target/port/type');
  assert.strictEqual(inc2.incidentKey, inc3.incidentKey, 'Incident keys must be deterministic SHA-256');
  assert.ok(inc1.incidentKey.startsWith('INC-'), 'Incident key must have INC- prefix');

  // Verify history does not grow by 3 duplicate entries
  const matchingHist = aiBrain.incidentHistory.filter(h => h.incidentKey === inc1.incidentKey);
  assert.strictEqual(matchingHist.length, 1, 'Incident history must contain exactly 1 entry for the deterministic key');
  console.log(`  ✓ Deterministic key [${inc1.incidentKey}] generated; 3 duplicate ingestions resolved to 1 idempotent incident record.`);

  // --------------------------------------------------------------------------
  // Test 9: Live Operational Brain State API & Diagnostic Probe Execution
  // --------------------------------------------------------------------------
  console.log('\n[Test 9] Testing Live Brain State API & 1-Click Diagnostic Probe Execution...');
  const liveState = aiBrain.getLiveState();
  assert.ok(liveState, 'Live state must return valid object');
  assert.strictEqual(liveState.status, 'OPERATIONAL', 'Status must be OPERATIONAL');
  assert.strictEqual(liveState.engine, 'Continuous Bayesian (Hare-Niemeyer 100.0%)', 'Engine signature must match');

  const liveConfidenceSum = liveState.rankedHypotheses.reduce((sum, h) => sum + h.confidence, 0);
  assert.strictEqual(liveConfidenceSum, 100, `Live state probabilities must strictly sum to 100%, found: ${liveConfidenceSum}%`);

  // Execute diagnostic probe on physical wire
  const probeResult = await aiBrain.executeDiagnosticProbe({
    probeType: 'ICMP_PING_GATEWAY',
    targetIp: '10.168.195.1'
  });
  assert.ok(probeResult, 'Probe result must exist');
  assert.strictEqual(probeResult.success, true, 'Diagnostic probe execution must succeed');
  assert.ok(probeResult.revisedEvaluation, 'Probe must return revised Bayesian evaluation');

  const probeEvalSum = probeResult.revisedEvaluation.rankedHypotheses.reduce((sum, h) => sum + h.confidence, 0);
  assert.strictEqual(probeEvalSum, 100, `Revised evaluation probabilities must sum to 100%, found: ${probeEvalSum}%`);
  console.log(`  ✓ Live state API verified (100.0% normalized) and physical probe executed in ${probeResult.latencyMs}ms with belief revision.`);

  console.log('\n========================================================================');
  console.log('  ALL 9 AI BRAIN & BAYESIAN REASONING TESTS PASSED 100% GREEN!          ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runAiBrainTests().then(() => process.exit(0)).catch(err => {
    console.error(err);
    process.exit(1);
  });
}

module.exports = { runAiBrainTests };
