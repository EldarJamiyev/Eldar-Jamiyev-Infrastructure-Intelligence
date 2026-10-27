// tests/suite-95-multi-agent-sre-war-room-orchestrator.test.js
/**
 * EJII Test Suite 95: Autonomous Multi-Agent SRE War-Room Orchestrator
 * Verifies execution of the 5-Agent SRE consensus pipeline:
 *   Agent 1: Temporal CUSUM & Spectral FFT Triage
 *   Agent 2: Topological Graph & M/M/1/K Chaos Queuing
 *   Agent 3: Deep Wire L7 Protocol & QoS DSCP Forensics
 *   Agent 4: Causal Counterfactual Planner & Holt-Winters Forecast
 *   Agent 5: Lyapunov Stability Barrier & HMAC-SHA256 Zero-Trust Signoff
 * Plus REST API routes /api/rca/war-room/execute and /api/rca/war-room/latest.
 */

'use strict';

const assert = require('node:assert/strict');
const { AutonomousWarRoomOrchestrator } = require('../src/ai/autonomous-war-room');
const routesRca = require('../src/api/routes-rca');

async function runSuite95AutonomousWarRoom() {
  console.log('========================================================================');
  console.log('  === [SUITE 95] 5-AGENT SRE WAR-ROOM AUTONOMOUS ORCHESTRATOR ===        ');
  console.log('========================================================================\n');

  // [95.1] Convening 5-Agent Pipeline
  console.log('[Test 95.1] Executing full 5-Agent SRE War-Room consensus pipeline...');
  const orchestrator = new AutonomousWarRoomOrchestrator('sovereign-singularity-test-secret');

  const result = orchestrator.execute({
    incidentContext: 'Critical Gateway Tail Latency Spike & TCP Resets',
    targetSubnet: '10.0.0.0/24'
  });

  assert.ok(result, 'War-Room must produce execution result');
  assert.ok(result.warRoomSessionId.startsWith('sre-warroom-'), 'Must have valid session ID');
  assert.ok(['RESOLVED_REMEDIATION_SIGNED', 'INCIDENT_ESCALATED', 'STABILIZED_MONITORING'].includes(result.status));
  console.log(`  ✓ War-Room convened: Session=${result.warRoomSessionId}, Status=${result.status}`);

  // [95.2] Agent 1 & Agent 2 Findings
  console.log('[Test 95.2] Validating Agent 1 (Triage) and Agent 2 (Topology) consensus outputs...');
  assert.strictEqual(result.agent1.agentName, 'Agent 1 — Temporal & Spectral Triage');
  assert.ok(result.agent1.spectralAnalysis, 'Agent 1 must include spectral FFT analysis');
  assert.ok(typeof result.agent1.verdict === 'string' && result.agent1.verdict.length > 0);

  assert.strictEqual(result.agent2.agentName, 'Agent 2 — Topological & Queuing Analyst');
  assert.ok(typeof result.agent2.lambda2 === 'number', 'Agent 2 must output algebraic connectivity lambda2');
  assert.ok(result.agent2.chaosQueuing, 'Agent 2 must provide chaos simulation result');
  console.log(`  ✓ Agent 1 verdict: "${result.agent1.verdict}"`);
  console.log(`  ✓ Agent 2: λ₂=${result.agent2.lambda2.toFixed(4)}, Chaos Average Drop=${result.agent2.chaosQueuing.averageDropProbabilityPct}%`);

  // [95.3] Agent 3 & Agent 4 Findings
  console.log('[Test 95.3] Validating Agent 3 (Wire) and Agent 4 (Counterfactual Planner)...');
  assert.strictEqual(result.agent3.agentName, 'Agent 3 — Deep Wire Forensics');
  assert.ok(result.agent3.qosAudit, 'Agent 3 must include QoS audit report');
  assert.ok(Array.isArray(result.agent3.l7Observations), 'Agent 3 must report L7 observations');

  assert.strictEqual(result.agent4.agentName, 'Agent 4 — Causal Counterfactual Planner');
  assert.ok(typeof result.agent4.smoothStlRobustness === 'number');
  assert.ok(result.agent4.holtWintersForecast, 'Agent 4 must output Holt-Winters SLA trajectory');
  assert.ok(typeof result.agent4.proposedRemediationAction === 'string');
  console.log(`  ✓ Agent 3: QoS packets audited=${result.agent3.qosAudit.totalPacketsAudited}`);
  console.log(`  ✓ Agent 4: Smooth STL ρ̃=${result.agent4.smoothStlRobustness.toFixed(2)}, Action="${result.agent4.proposedRemediationAction}"`);

  // [95.4] Agent 5 Lyapunov Safety Barrier & Cryptographic HMAC Signoff
  console.log('[Test 95.4] Validating Agent 5 Lyapunov Safety barrier and HMAC-SHA256 signature...');
  const a5 = result.agent5;
  assert.strictEqual(a5.agentName, 'Agent 5 — DSRL Lyapunov Safety & Zero-Trust Officer');
  assert.strictEqual(a5.lyapunovBarrierCleared, true, 'Lyapunov derivative must guarantee asymptotic stability');
  assert.ok(a5.zeroTrustPolicy, 'Agent 5 must synthesize Zero-Trust least-privilege policy bundle');
  assert.ok(a5.zeroTrustPolicy.windowsNetshRules.length > 0);
  assert.ok(a5.hmacSignature && a5.hmacSignature.length === 64, 'HMAC signature must be a 64-char SHA256 hex string');
  assert.ok(a5.proofChain.startsWith('EJII-PROOF-V5:'), 'Proof chain must contain cryptographic proof');
  console.log(`  ✓ Agent 5: Lyapunov Cleared=${a5.lyapunovBarrierCleared}, HMAC-SHA256=${a5.hmacSignature.substring(0, 16)}...`);

  // [95.5] REST API POST /api/rca/war-room/execute
  console.log('[Test 95.5] Testing POST /api/rca/war-room/execute via router stack...');
  const execLayer = routesRca.stack.find(s => s.route && s.route.path === '/war-room/execute');
  assert.ok(execLayer, 'Route POST /war-room/execute must exist in routes-rca.js');

  let execJson = null;
  const mockReqPost = {
    body: {
      incidentContext: 'Production Outage Simulation',
      targetSubnet: '192.168.31.0/24'
    }
  };
  const mockResPost = {
    statusCode: 200,
    status(c) { this.statusCode = c; return this; },
    json(d) { execJson = d; return this; }
  };
  const execHandler = execLayer.route.stack[execLayer.route.stack.length - 1].handle;
  execHandler(mockReqPost, mockResPost, () => {});

  assert.ok(execJson, 'Must return JSON');
  assert.strictEqual(execJson.success, true);
  assert.ok(execJson.warRoomSessionId, 'Session ID must be returned');
  assert.ok(execJson.agent1, 'agent1 must be present');
  assert.ok(execJson.agent5, 'agent5 must be present');
  console.log(`  ✓ POST /api/rca/war-room/execute returned 200 OK: Session=${execJson.warRoomSessionId}`);

  // [95.6] REST API GET /api/rca/war-room/latest
  console.log('[Test 95.6] Testing GET /api/rca/war-room/latest via router stack...');
  const latestLayer = routesRca.stack.find(s => s.route && s.route.path === '/war-room/latest');
  assert.ok(latestLayer, 'Route GET /war-room/latest must exist in routes-rca.js');

  let latestJson = null;
  const mockReqGet = { query: {} };
  const mockResGet = {
    statusCode: 200,
    status(c) { this.statusCode = c; return this; },
    json(d) { latestJson = d; return this; }
  };
  const latestHandler = latestLayer.route.stack[latestLayer.route.stack.length - 1].handle;
  latestHandler(mockReqGet, mockResGet, () => {});

  assert.ok(latestJson, 'Must return JSON');
  assert.strictEqual(latestJson.success, true);
  assert.ok(latestJson.warRoomSessionId);
  console.log(`  ✓ GET /api/rca/war-room/latest returned 200 OK.`);

  console.log('\n========================================================================');
  console.log('  SUITE 95 PASSED: 5-AGENT SRE WAR-ROOM ORCHESTRATOR 100% GREEN         ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runSuite95AutonomousWarRoom().catch((err) => {
    console.error('Suite 95 failed:', err);
    process.exit(1);
  });
}

module.exports = {
  runSuite95AutonomousWarRoom,
  runSuite95: runSuite95AutonomousWarRoom
};
