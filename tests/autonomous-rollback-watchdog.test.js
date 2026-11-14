'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  formulateRemediationGate,
  executeRemediationAndVerifyPostcondition,
  evaluateControlBarrierInvariants
} = require('../src/core/chat/conversational-brain');

const { autonomousRemediationEngine } = require('../src/systems/remediation/autonomous-remediation-engine');
const { getAuditTrail } = require('../src/core/audit-logger');

test('Track 1: Closed-Loop Autonomous Rollback Watchdog & Control Barrier Safety Invariants', async (t) => {
  await t.test('1. verifies evaluateControlBarrierInvariants detects safety boundaries and Lyapunov energy', () => {
    // 1a. Healthy samples: low latency, zero loss, decreasing RTT
    const healthySamples = [
      { timestampMs: 1000, rttMs: 25.0, packetLossPct: 0.0 },
      { timestampMs: 2000, rttMs: 20.0, packetLossPct: 0.0 },
      { timestampMs: 3000, rttMs: 15.0, packetLossPct: 0.0 }
    ];
    const healthyCbf = evaluateControlBarrierInvariants(healthySamples, { maxSafeRttMs: 100, maxSafeLossPct: 2.0 });
    assert.equal(healthyCbf.satisfied, true, 'Healthy samples must satisfy Control Barrier Invariants');
    assert.ok(healthyCbf.minimumMargin > 0, 'Minimum margin must be strictly positive');
    assert.equal(healthyCbf.violatedBarriers.length, 0);

    // 1b. Latency ceiling violation (RTT exceeds 100ms)
    const highLatencySamples = [
      { timestampMs: 1000, rttMs: 120.0, packetLossPct: 0.0 },
      { timestampMs: 2000, rttMs: 150.0, packetLossPct: 0.0 },
      { timestampMs: 3000, rttMs: 180.0, packetLossPct: 0.0 }
    ];
    const latencyCbf = evaluateControlBarrierInvariants(highLatencySamples, { maxSafeRttMs: 100, maxSafeLossPct: 2.0 });
    assert.equal(latencyCbf.satisfied, false, 'Latency exceeding ceiling must violate CBF');
    assert.ok(latencyCbf.violatedBarriers.some(b => b.barrier === 'RTT_CEILING_BARRIER'));

    // 1c. Lyapunov divergence (RTT increased significantly instead of recovering)
    const divergingSamples = [
      { timestampMs: 1000, rttMs: 10.0, packetLossPct: 0.0 },
      { timestampMs: 2000, rttMs: 40.0, packetLossPct: 0.0 },
      { timestampMs: 3000, rttMs: 85.0, packetLossPct: 0.0 }
    ];
    const lyapunovCbf = evaluateControlBarrierInvariants(divergingSamples, { maxSafeRttMs: 150, maxSafeLossPct: 2.0 });
    assert.equal(lyapunovCbf.satisfied, false, 'Energy divergence post-remediation must violate CBF');
    assert.ok(lyapunovCbf.violatedBarriers.some(b => b.barrier === 'LYAPUNOV_STABILITY_BARRIER'));
  });

  await t.test('2. verifies successful remediation passes CBF and does not trigger rollback', async () => {
    const gate = await formulateRemediationGate(
      'LOCAL_STACK_CONGESTION',
      'host-prod-01.corp.internal',
      { username: 'lead_sre', role: 'ADMIN' }
    );
    assert.ok(gate.actionToken);

    const stableSampler = async () => [
      { timestampMs: Date.now() - 3000, rttMs: 12.0, packetLossPct: 0.0 },
      { timestampMs: Date.now() - 2000, rttMs: 10.0, packetLossPct: 0.0 },
      { timestampMs: Date.now() - 1000, rttMs: 9.0, packetLossPct: 0.0 }
    ];

    const outcome = await executeRemediationAndVerifyPostcondition({
      actionToken: gate.actionToken,
      userContext: { username: 'lead_sre', role: 'ADMIN' },
      verificationWindowSec: 30,
      telemetrySampler: stableSampler,
      controlBarrierOptions: { maxSafeRttMs: 100, maxSafeLossPct: 5.0 }
    });

    assert.equal(outcome.success, true);
    assert.equal(outcome.remediationExecution.success, true);
    assert.equal(outcome.controlBarrier.satisfied, true);
    assert.equal(outcome.autonomousRollback.triggered, false);
    assert.equal(outcome.autonomousRollback.rollbackStatus, 'NOT_REQUIRED');
  });

  await t.test('3. verifies unstable postcondition or CBF violation triggers autonomous sub-second rollback', async () => {
    // Generate valid preview & token
    const gate = await formulateRemediationGate(
      'DNS_NXDOMAIN_POISON',
      'dns-edge-01.corp.internal',
      { username: 'lead_sre', role: 'ADMIN' }
    );
    assert.ok(gate.actionToken);

    // Simulate postcondition telemetry that suffers severe latency degradation / instability
    const degradedSampler = async () => [
      { timestampMs: Date.now() - 3000, rttMs: 50.0, packetLossPct: 0.0 },
      { timestampMs: Date.now() - 2000, rttMs: 250.0, packetLossPct: 15.0 },
      { timestampMs: Date.now() - 1000, rttMs: 600.0, packetLossPct: 30.0 }
    ];

    const outcome = await executeRemediationAndVerifyPostcondition({
      actionToken: gate.actionToken,
      userContext: { username: 'lead_sre', role: 'ADMIN' },
      verificationWindowSec: 30,
      telemetrySampler: degradedSampler,
      controlBarrierOptions: { maxSafeRttMs: 100, maxSafeLossPct: 5.0 }
    });

    assert.equal(outcome.success, false, 'Divergent outcome must not be flagged success');
    assert.equal(outcome.controlBarrier.satisfied, false, 'Control barrier must be violated');
    assert.ok(outcome.controlBarrier.violatedBarriers.length > 0);

    // Rollback Watchdog verification
    assert.ok(outcome.autonomousRollback, 'Must include autonomousRollback section');
    assert.equal(outcome.autonomousRollback.triggered, true, 'Autonomous rollback must be triggered');
    assert.equal(outcome.autonomousRollback.rollbackStatus, 'ROLLED_BACK_CONFIRMED');
    assert.ok(outcome.autonomousRollback.compensatingRecipeId, 'Must specify compensating recipe ID');
    assert.ok(outcome.autonomousRollback.executedWithinMs < 1000, 'Rollback must execute rapidly');

    // Verify rollback recorded in HMAC audit trail
    const auditTrail = getAuditTrail(10);
    const rollbackEntry = auditTrail.find(e => e.action && e.action.includes('AUTONOMOUS_ROLLBACK'));
    assert.ok(rollbackEntry, 'Rollback event must be logged in HMAC audit trail');
    assert.ok(rollbackEntry.tamperResistantHmac, 'Audit entry must have cryptographic HMAC');
  });
});
