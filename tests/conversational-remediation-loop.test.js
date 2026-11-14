/**
 * EJII — Conversational Remediation Loop & Dual-Custody Action Tokens Suite
 * Verifies closed-loop transition from diagnostic isolation to cryptographic
 * dual-custody remediation and temporal Lyapunov postcondition verification.
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  formulateRemediationGate,
  executeRemediationAndVerifyPostcondition,
  runAgenticToolLoop,
  CANONICAL_REMEDIATION_MAP
} = require('../src/core/chat/conversational-brain');
const { autonomousRemediationEngine } = require('../src/systems/remediation/autonomous-remediation-engine');

test('EJII Conversational Remediation Loop & Dual-Custody Gate Suite', async (t) => {
  await t.test('1. verifies formulateRemediationGate issues cryptographically signed HMAC action tokens for canonical faults', async () => {
    // 1. DNS poisoning -> flush_dns (RB-01)
    const dnsGate = await formulateRemediationGate('DNS_NXDOMAIN_POISON', 'corrupt-dns.corp.test', {
      role: 'ADMIN',
      username: 'lead_architect'
    });

    assert.ok(dnsGate);
    assert.equal(dnsGate.status, 'REMEDIATION_RECOMMENDED');
    assert.equal(dnsGate.recipeId, 'flush_dns');
    assert.equal(dnsGate.runbookId, 'RB-01');
    assert.equal(dnsGate.targetHost, 'corrupt-dns.corp.test');
    assert.ok(dnsGate.actionToken, 'Must generate signed actionToken');
    assert.ok(dnsGate.actionTokenId, 'Must extract actionTokenId');
    assert.equal(dnsGate.dualCustodyRequired, true);
    assert.ok(dnsGate.expiresAt > Date.now(), 'Token expiresAt must be in the future');

    // 2. Kernel Socket Exhaustion -> trim_working_set (RB-02)
    const socketGate = await formulateRemediationGate('LOCAL_STACK_CONGESTION', '127.0.0.1', {
      role: 'ADMIN',
      username: 'lead_architect'
    });

    assert.ok(socketGate);
    assert.equal(socketGate.recipeId, 'trim_working_set');
    assert.equal(socketGate.runbookId, 'RB-02');
    assert.ok(socketGate.actionToken);

    // 3. ARP Isolation -> renew_dhcp (RB-03)
    const arpGate = await formulateRemediationGate('ARP_L2_ISOLATION', 'gateway.corp.test', {
      role: 'ADMIN',
      username: 'lead_architect'
    });

    assert.ok(arpGate);
    assert.equal(arpGate.recipeId, 'renew_dhcp');
    assert.equal(arpGate.runbookId, 'RB-03');
  });

  await t.test('2. verifies runAgenticToolLoop attaches remediationGate to epistemicClassification on dominant hypothesis', async () => {
    const mockExecute = async (plan, step) => {
      const isDns = plan.intent === 'dns';
      return {
        reply: `Step ${step}: Executed ${plan.intent}`,
        success: !isDns,
        findings: [{ label: isDns ? 'DNS Failure' : 'Port Healthy', value: isDns ? 'NXDOMAIN' : 'Reachable' }],
        technicalEvidence: { success: !isDns, failed: isDns }
      };
    };

    const target = 'outage-target.corp.internal';
    const initialPlan = {
      intent: 'dns',
      mode: 'operational',
      target,
      secondaryToolPlans: [
        { intent: 'port_check', target, ports: [80] },
        { intent: 'traceroute', target }
      ]
    };

    const loopResult = await runAgenticToolLoop({
      promptText: `Investigate DNS resolution on ${target}`,
      initialPlan,
      sessionContext: { target, userContext: { role: 'ADMIN', username: 'lead_architect' } },
      executeSinglePlan: mockExecute,
      maxSteps: 5
    });

    assert.ok(loopResult.epistemicClassification, 'Must return epistemicClassification');
    const gate = loopResult.epistemicClassification.remediationGate;
    assert.ok(gate, 'Must attach remediationGate when dominant hypothesis is isolated');
    assert.equal(gate.status, 'REMEDIATION_RECOMMENDED');
    assert.equal(gate.recipeId, 'flush_dns');
    assert.equal(gate.runbookId, 'RB-01');
    assert.ok(gate.actionToken);
    assert.ok(gate.actionTokenId);
    assert.ok(loopResult.reply.includes('Recommended Autonomous Remediation'), 'Reply must include remediation card');
  });

  await t.test('3. verifies executeRemediationAndVerifyPostcondition executes actionToken and evaluates temporal stability', async () => {
    // 1. Generate preview for safe user-space recipe trim_working_set
    const preview = await autonomousRemediationEngine.executePreview('trim_working_set', {}, {
      role: 'ADMIN',
      username: 'lead_architect'
    });
    assert.ok(preview.actionToken);

    // 2. Execute remediation with temporal post-condition sampling
    const customSampler = async () => [
      { timestampMs: Date.now() - 2000, rttMs: 2.4, packetLossPct: 0.0 },
      { timestampMs: Date.now() - 1000, rttMs: 2.1, packetLossPct: 0.0 },
      { timestampMs: Date.now(), rttMs: 1.9, packetLossPct: 0.0 }
    ];

    const result = await executeRemediationAndVerifyPostcondition({
      actionToken: preview.actionToken,
      userContext: { role: 'ADMIN', username: 'lead_architect' },
      verificationWindowSec: 30,
      telemetrySampler: customSampler
    });

    assert.equal(result.success, true);
    assert.equal(result.remediationExecution.success, true);
    assert.equal(result.stabilityVerification.verified, true);
    assert.equal(result.stabilityVerification.verificationStatus, 'TEMPORAL_STABILITY_CONFIRMED');
    assert.ok(result.stabilityVerification.meanRttMs > 0);
  });

  await t.test('4. verifies anti-replay protection prevents token re-use', async () => {
    // Generate preview
    const preview = await autonomousRemediationEngine.executePreview('trim_working_set', {}, {
      role: 'ADMIN',
      username: 'lead_architect'
    });

    // First execution succeeds
    const exec1 = await autonomousRemediationEngine.executeRemediation(preview.actionToken, {
      role: 'ADMIN',
      username: 'lead_architect'
    });
    assert.equal(exec1.success, true);

    // Second execution with same token MUST be rejected
    await assert.rejects(
      async () => {
        await autonomousRemediationEngine.executeRemediation(preview.actionToken, {
          role: 'ADMIN',
          username: 'lead_architect'
        });
      },
      /REPLAY_DETECTED/
    );
  });
});
