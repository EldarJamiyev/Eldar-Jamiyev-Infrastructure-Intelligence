'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  generativeRemediationSynthesizer,
  GenerativeRemediationSynthesizer,
  CANONICAL_LYAPUNOV_WEIGHTS
} = require('../src/systems/remediation/generative-remediation-synthesizer');
const { formulateRemediationGate } = require('../src/core/chat/conversational-brain');

test('Phase 4.0 Track 4: Generative Neuro-Symbolic Remediation Synthesizer & Lyapunov Proofs', async (t) => {
  await t.test('1. Computes positive definite quadratic Lyapunov energy V(s)', () => {
    const synthesizer = new GenerativeRemediationSynthesizer();
    const state = { rttMs: 20.0, lossPct: 2.0, queueDepthPackets: 10 };

    // V(s) = 0.40 * 400 + 0.40 * 4 + 0.20 * 100 = 160 + 1.6 + 20 = 181.6
    const energy = synthesizer.computeLyapunovEnergy(state);
    assert.strictEqual(energy, 181.6);

    const zeroState = { rttMs: 0, lossPct: 0, queueDepthPackets: 0 };
    assert.strictEqual(synthesizer.computeLyapunovEnergy(zeroState), 0.0);
  });

  await t.test('2. Synthesizes grammar primitives based on telemetry symptoms', () => {
    const synthesizer = new GenerativeRemediationSynthesizer();

    // Bufferbloat symptom
    const bbAction = synthesizer.synthesizeRemediationCandidate(
      'BUFFERBLOAT_DETECTED',
      { rttMs: 80.0, lossPct: 1.0, queueDepthPackets: 65 },
      '192.168.1.1'
    );
    assert.strictEqual(bbAction.actionType, 'TCP_WINDOW_CLAMP');
    assert.strictEqual(bbAction.parameters.windowSize, 32768);
    assert.ok(bbAction.expectedImpact.queueDeltaPackets < 0);

    // DNS failure symptom
    const dnsAction = synthesizer.synthesizeRemediationCandidate(
      'DNS_NXDOMAIN_POISON',
      { rttMs: 40.0, lossPct: 5.0, queueDepthPackets: 1 },
      '1.1.1.1'
    );
    assert.strictEqual(dnsAction.actionType, 'DNS_UPSTREAM_PIVOT');
    assert.ok(dnsAction.parameters.newResolver);
    assert.ok(dnsAction.expectedImpact.lossDeltaPct < 0);

    // High latency / congestion symptom
    const congAction = synthesizer.synthesizeRemediationCandidate(
      'LOCAL_STACK_CONGESTION',
      { rttMs: 120.0, lossPct: 4.0, queueDepthPackets: 35 },
      '127.0.0.1'
    );
    assert.strictEqual(congAction.actionType, 'SOCKET_BUFFER_EXPEDITE');
    assert.strictEqual(congAction.parameters.bufferBytes, 262144);

    // Traffic shaping default
    const dscpAction = synthesizer.synthesizeRemediationCandidate(
      'LATENCY_SENSITIVE_STREAM',
      { rttMs: 15.0, lossPct: 0.5, queueDepthPackets: 5 },
      '10.0.0.4'
    );
    assert.strictEqual(dscpAction.actionType, 'DSCP_TRAFFIC_SHAPE');
    assert.strictEqual(dscpAction.parameters.dscpClass, 'AF41');
  });

  await t.test('3. Proves Lyapunov stability invariant (delta V <= -delta < 0) and rejects non-contracting actions', () => {
    const synthesizer = new GenerativeRemediationSynthesizer();
    const currentState = { rttMs: 50.0, lossPct: 3.0, queueDepthPackets: 30 };

    const stabilizingAction = {
      actionId: 'ACT_STABILIZE',
      actionType: 'TCP_WINDOW_CLAMP',
      target: '10.0.0.1',
      parameters: { windowSize: 32768 },
      rationale: 'Reduce queue depth and RTT',
      expectedImpact: { rttDeltaMs: -15.0, lossDeltaPct: -1.0, queueDeltaPackets: -20.0 },
      requiresElevation: false,
      commandPreview: 'sysctl clamp'
    };

    const proof = synthesizer.proveLyapunovStability(currentState, stabilizingAction);
    assert.strictEqual(proof.verified, true);
    assert.strictEqual(proof.stabilityVerdict, 'STABLE_CONTRACTION');
    assert.ok(proof.deltaV < 0, `Expected negative deltaV, got ${proof.deltaV}`);
    assert.ok(proof.energyAfter < proof.energyBefore);

    // Non-contracting / destabilizing action (increases latency and queue depth)
    const destabilizingAction = {
      actionId: 'ACT_DESTABILIZE',
      actionType: 'SOCKET_BUFFER_EXPEDITE',
      target: '10.0.0.1',
      parameters: { bufferBytes: 1048576 },
      rationale: 'Blow up buffers',
      expectedImpact: { rttDeltaMs: +25.0, lossDeltaPct: +2.0, queueDeltaPackets: +50.0 },
      requiresElevation: false,
      commandPreview: 'sysctl expand'
    };

    const failProof = synthesizer.proveLyapunovStability(currentState, destabilizingAction);
    assert.strictEqual(failProof.verified, false);
    assert.strictEqual(failProof.stabilityVerdict, 'NEUTRAL_OR_EXPANSIVE_REJECTED');
    assert.ok(failProof.deltaV > 0);
  });

  await t.test('4. Derives exact algebraic compensating inverse action a^{-1} for each grammar primitive', () => {
    const synthesizer = new GenerativeRemediationSynthesizer();

    // 1. TCP_WINDOW_CLAMP -> TCP_WINDOW_UNCLAMP
    const tcpAct = {
      actionId: 'ACT_TCP_1',
      actionType: 'TCP_WINDOW_CLAMP',
      target: '10.0.0.5',
      parameters: { windowSize: 32768, originalWindowSize: 65535 },
      requiresElevation: false
    };
    const invTcp = synthesizer.deriveCompensatingInverse(tcpAct);
    assert.strictEqual(invTcp.inverseType, 'TCP_WINDOW_UNCLAMP');
    assert.strictEqual(invTcp.reversesActionId, 'ACT_TCP_1');
    assert.strictEqual(invTcp.parameters.windowSize, 65535);

    // 2. DNS_UPSTREAM_PIVOT -> DNS_UPSTREAM_REVERT
    const dnsAct = {
      actionId: 'ACT_DNS_1',
      actionType: 'DNS_UPSTREAM_PIVOT',
      target: '10.0.0.5',
      parameters: { newResolver: '8.8.8.8', previousResolver: '1.1.1.1' },
      requiresElevation: false
    };
    const invDns = synthesizer.deriveCompensatingInverse(dnsAct);
    assert.strictEqual(invDns.inverseType, 'DNS_UPSTREAM_REVERT');
    assert.strictEqual(invDns.parameters.targetResolver, '1.1.1.1');

    // 3. SOCKET_BUFFER_EXPEDITE -> SOCKET_BUFFER_RESET
    const sockAct = {
      actionId: 'ACT_SOCK_1',
      actionType: 'SOCKET_BUFFER_EXPEDITE',
      target: '10.0.0.5',
      parameters: { bufferBytes: 262144, originalBufferBytes: 32768 },
      requiresElevation: false
    };
    const invSock = synthesizer.deriveCompensatingInverse(sockAct);
    assert.strictEqual(invSock.inverseType, 'SOCKET_BUFFER_RESET');
    assert.strictEqual(invSock.parameters.bufferBytes, 32768);

    // 4. DSCP_TRAFFIC_SHAPE -> DSCP_DEFAULT
    const dscpAct = {
      actionId: 'ACT_DSCP_1',
      actionType: 'DSCP_TRAFFIC_SHAPE',
      target: '10.0.0.5',
      parameters: { dscpClass: 'AF41', originalDscpClass: 'CS0' },
      requiresElevation: false
    };
    const invDscp = synthesizer.deriveCompensatingInverse(dscpAct);
    assert.strictEqual(invDscp.inverseType, 'DSCP_DEFAULT');
    assert.strictEqual(invDscp.parameters.dscpClass, 'CS0');
  });

  await t.test('5. Issues cryptographic action plan with HMAC token and verifies authenticity', () => {
    const synthesizer = new GenerativeRemediationSynthesizer('SECRET_TEST_KEY_1234567890');
    const currentState = { rttMs: 40.0, lossPct: 2.0, queueDepthPackets: 20 };
    const action = synthesizer.synthesizeRemediationCandidate('BUFFERBLOAT_DETECTED', currentState, '10.0.0.1');

    const plan = synthesizer.issueCryptographicActionPlan(action, currentState);
    assert.ok(plan.actionToken, 'actionToken must be issued');
    assert.strictEqual(plan.lyapunovProof.verified, true);
    assert.strictEqual(plan.inverseAction.reversesActionId, action.actionId);

    // Verify valid token
    const verifyResult = synthesizer.verifyActionPlanToken(plan.actionToken);
    assert.strictEqual(verifyResult.valid, true);
    assert.strictEqual(verifyResult.payload.actionId, action.actionId);
    assert.strictEqual(verifyResult.payload.actionType, action.actionType);

    // Reject tampered token
    const tamperedToken = plan.actionToken.slice(0, -4) + 'abcd';
    const tamperedResult = synthesizer.verifyActionPlanToken(tamperedToken);
    assert.strictEqual(tamperedResult.valid, false);
  });

  await t.test('6. Verifies formulateRemediationGate enriches remediation gates with Lyapunov proof', async () => {
    const gate = await formulateRemediationGate('DNS_NXDOMAIN_POISON', '127.0.0.1');
    assert.ok(gate, 'Remediation gate must be returned');
    assert.strictEqual(gate.recipeId, 'flush_dns');
    assert.ok(gate.synthesizedMicroPlan, 'synthesizedMicroPlan must be present');
    assert.ok(gate.lyapunovProof, 'lyapunovProof must be attached');
    assert.strictEqual(gate.lyapunovProof.verified, true);
  });
});
