/**
 * EJII Test Suite 58: AI Episodic Context Window Manager, Shared Outage Correlator & Recovery Loop
 * 
 * Verifies:
 * [58.1] Context Window Token Estimation & Exponential Half-Life Temporal Decay ($w(\Delta t) = 2^{-\Delta t / \tau}$)
 * [58.2] Prioritized 3-Tier Context Window Budgeting within maxContextTokens limit
 * [58.3] Multi-Host Concurrent Shared Upstream Outage Correlation (Common Subnet / Switch Node isolation)
 * [58.4] Multi-Turn Autonomous Tool Recovery Loop (ICMP Drop -> L4 Socket Check) & Belief Revision
 */

'use strict';

const assert = require('assert');
const { ContextWindowManager } = require('../src/core/context-window-manager');
const { aiBrain } = require('../src/core/ai-brain');
const { reasoningEngine } = require('../src/core/reasoning-engine');

async function runAiContextWindowSharedOutageAndRecoveryLoopTests() {
  console.log('========================================================================');
  console.log('  SUITE 58: AI CONTEXT WINDOW, SHARED OUTAGE & RECOVERY LOOP SUITE       ');
  console.log('  Token Budgeting, Temporal Half-Life Decay & Multi-Turn Recovery      ');
  console.log('========================================================================\n');

  // [58.1] Context Window Token Estimation & Exponential Temporal Decay
  console.log('[58.1] Testing ContextWindowManager token estimation and exponential temporal decay...');
  const mgr = new ContextWindowManager({ maxContextTokens: 2048, halfLifeSec: 120 });

  const testText = 'Network packet drop detected on interface eth0 with high retransmissions.';
  const estimated = mgr.estimateTokenCount(testText);
  assert.ok(estimated >= 15 && estimated <= 25, `Expected token count around 18, got ${estimated}`);

  const now = Date.now();
  // Fresh event (0s old) -> decay weight should be 1.0
  const weightFresh = mgr.calculateDecayWeight(now, now);
  assert.strictEqual(weightFresh, 1.0, 'Fresh event weight must be 1.0');

  // Event 120s old (1 half-life) -> decay weight should be ~0.5
  const weightHalfLife = mgr.calculateDecayWeight(now - 120000, now);
  assert.ok(Math.abs(weightHalfLife - 0.5) < 0.05, `Expected weight around 0.5, got ${weightHalfLife}`);

  // Very old event (1 hour old) -> clamped to floor 0.05
  const weightOld = mgr.calculateDecayWeight(now - 3600000, now);
  assert.strictEqual(weightOld, 0.05, 'Very old event weight must clamp to floor of 0.05');
  console.log(`  ✓ Temporal decay validated: 0s=${weightFresh}, 120s=${weightHalfLife.toFixed(3)}, 1h=${weightOld}`);

  // [58.2] Prioritized 3-Tier Context Window Budgeting
  console.log('[58.2] Testing prioritized 3-tier budgeting within token budget limit...');
  const smallBudgetMgr = new ContextWindowManager({ maxContextTokens: 300 });

  const manyEvents = [];
  for (let i = 1; i <= 30; i++) {
    manyEvents.push({
      timestamp: new Date(now - i * 10000).toISOString(),
      eventType: `PACKET_ANOMALY_${i}`,
      details: `Detailed TCP packet sequence anomaly number ${i} on link eth0 connecting core switch to access floor`
    });
  }

  const baselineSnapshot = {
    target: '192.168.31.1',
    avgRttMs: 1.45,
    stdDev: 0.22,
    establishedSince: '2026-10-18T00:00:00Z'
  };

  const runbooks = [
    { title: 'RFC 793 TCP Retransmission Recovery', content: 'When retransmissions exceed 3%, inspect L2 switch buffers and MTU configuration.' }
  ];

  const payload = smallBudgetMgr.buildContextPayload({
    events: manyEvents,
    baselineSnapshot,
    runbookSnippets: runbooks,
    activeIncidents: [{ incidentType: 'TCP_SYN_TIMEOUT', destIp: '192.168.31.89', destPort: 443 }]
  });

  assert.ok(payload.estimatedTokens <= 300, `Payload estimated tokens (${payload.estimatedTokens}) must not exceed budget (300)`);
  assert.ok(payload.prompt.includes('Tier 1: High-Priority Active Incident'), 'Prompt must include Tier 1 incidents');
  console.log(`  ✓ Context window built: ${payload.estimatedTokens}/300 tokens used, remaining=${payload.remainingTokens}`);

  // [58.3] Multi-Host Shared Upstream Fault Correlation
  console.log('[58.3] Testing multi-host concurrent shared upstream outage correlation...');
  // Seed active incidents with multiple hosts in the same subnet
  aiBrain.activeIncidents.clear();
  aiBrain.activeIncidents.set('INC-TEST-01', {
    incidentId: 'INC-TEST-01',
    incidentType: 'TCP_SYN_TIMEOUT',
    targetIp: '192.168.10.15',
    destIp: '192.168.10.15',
    targetPort: 443,
    destPort: 443,
    timestamp: new Date().toISOString(),
    evaluation: { topHypothesis: { id: 'REMOTE_HOST_DOWN', label: 'Remote Host Down', confidence: 70 } }
  });

  aiBrain.activeIncidents.set('INC-TEST-02', {
    incidentId: 'INC-TEST-02',
    incidentType: 'TCP_SYN_TIMEOUT',
    targetIp: '192.168.10.16',
    destIp: '192.168.10.16',
    targetPort: 443,
    destPort: 443,
    timestamp: new Date().toISOString(),
    evaluation: { topHypothesis: { id: 'REMOTE_HOST_DOWN', label: 'Remote Host Down', confidence: 75 } }
  });

  const correlation = aiBrain.correlateSharedUpstreamFaults(120000);
  assert.ok(correlation.sharedOutagesDetected, 'Shared outage must be detected for 2 concurrent host failures in 192.168.10.0/24');
  assert.strictEqual(correlation.sharedOutagesCount, 1);
  const cluster = correlation.clusters[0];
  assert.strictEqual(cluster.subnet, '192.168.10.0/24');
  assert.strictEqual(cluster.failingHostsCount, 2);
  assert.ok(cluster.failingTargets.includes('192.168.10.15') && cluster.failingTargets.includes('192.168.10.16'));
  console.log(`  ✓ Shared outage correlated: Subnet=${cluster.subnet}, ParentNode=${cluster.parentNode}, FailingHosts=${cluster.failingHostsCount}, Hypothesis=${cluster.sharedFaultHypothesis}`);

  // [58.4] Multi-Turn Autonomous Tool Recovery Loop
  console.log('[58.4] Testing multi-turn tool recovery loop when ICMP is filtered...');
  // Test reasoning engine belief revision when hostAliveL2OrL4 or icmpFilteredButHostAlive is present
  const initial = reasoningEngine.evaluateIncident({
    incidentType: 'TCP_SYN_TIMEOUT',
    targetPingReachable: false,
    gatewayReachable: true
  });

  // When ICMP is false, REMOTE_HOST_DOWN is normally considered
  const remoteHostInitial = initial.rankedHypotheses.find(h => h.id === 'REMOTE_HOST_DOWN');
  assert.ok(remoteHostInitial && !remoteHostInitial.isContradicted, 'Initial should not contradict REMOTE_HOST_DOWN');

  // Revised with multi-turn recovery evidence: L4 TCP socket responded or RST actively returned
  const revised = reasoningEngine.reviseBeliefs(initial, {
    icmpFilteredButHostAlive: true,
    hostAliveL2OrL4: true,
    targetPingReachable: false
  });

  const remoteHostRevised = revised.rankedHypotheses.find(h => h.id === 'REMOTE_HOST_DOWN');
  assert.strictEqual(remoteHostRevised.confidence, 0, 'REMOTE_HOST_DOWN must be eliminated (0%) when L2/L4 evidence confirms host alive');
  assert.strictEqual(remoteHostRevised.isContradicted, true);

  console.log(`  ✓ Multi-turn recovery rule of contradictory proof verified: REMOTE_HOST_DOWN eliminated (${remoteHostRevised.confidence}%) despite ICMP drop.`);

  console.log('\n>>> ALL SUITE 58 AI CONTEXT WINDOW & SHARED OUTAGE RECOVERY TESTS PASSED 100% GREEN.\n');
}

if (require.main === module) {
  runAiContextWindowSharedOutageAndRecoveryLoopTests().then(() => {
    process.exit(0);
  }).catch((err) => {
    console.error('Suite 58 failed:', err);
    process.exit(1);
  });
}

module.exports = {
  runAiContextWindowSharedOutageAndRecoveryLoopTests,
  runSuite58: runAiContextWindowSharedOutageAndRecoveryLoopTests
};
