/**
 * EJII Chat-First Minimalist Infrastructure Intelligence & Security Verification Suite
 * Covers Scenarios A through I + Audit Fail-Closed, SSRF Pinning, Preflight & Blast-Radius Models
 */

'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');

const { chatOperatorService } = require('../chat/chat-operator-service');
const v6Router = require('../../api/routes-v6-fabric');
const { generateToken } = require('../security');
const { temporalInfrastructureGraph } = require('../topology/temporal-graph-engine');

describe('EJII Chat-First Conversational Diagnostic Engine & v6 Security Hardening', () => {
  let server;
  let baseUrl;
  let testTargetPort;
  let adminToken;
  let viewerToken;

  before(async () => {
    const app = express();
    app.use(express.json());
    app.use('/api/v6', v6Router);
    app.get('/health-probe-ok', (_req, res) => res.status(200).json({ ok: true }));

    await new Promise((resolve) => {
      server = http.createServer(app);
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        testTargetPort = addr.port;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    adminToken = generateToken({ id: 'u-admin', username: 'admin', role: 'ADMIN' });
    viewerToken = generateToken({ id: 'u-viewer', username: 'viewer_user', role: 'READONLY' });
  });

  after(async () => {
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it('Routes greetings and local-network requests without inheriting a previous remote target', async () => {
    const previousContext = {
      lastTarget: 'google.com',
      lastValidTarget: 'google.com',
      lastIntent: 'website_check',
      lastPorts: [443],
      lastUrl: 'https://google.com/',
      entityMemory: {}
    };

    const cases = [
      ['hello', 'conversation'],
      ['can you ping default gateway?', 'gateway_ping'],
      ['check my ip', 'local_network_info'],
      ['i want to know what is dest ip of my apps currently i am using and their dest ports', 'active_connections']
    ];

    for (const [message, expectedIntent] of cases) {
      const plan = chatOperatorService.parseIntentAndEntities(message, previousContext);
      assert.equal(plan.intent, expectedIntent, 'Intent should be correct for: ' + message);
      assert.equal(plan.target, null, 'Local or conversational request must not inherit google.com: ' + message);
    }
  });

  it('Scenario: A greeting does not launch an infrastructure probe after a previous target was checked', async () => {
    const sessionId = 'TEST-GREETING-NO-UNSOLICITED-PROBE';
    const user = { id: 'u1', username: 'analyst', role: 'ANALYST' };

    const seeded = await chatOperatorService.processMessage({
      sessionId,
      message: 'Check port 3000 on 127.0.0.1',
      user
    });
    assert.equal(seeded.success, true);
    assert.equal(seeded.data.target, '127.0.0.1');

    const hello = await chatOperatorService.processMessage({
      sessionId,
      message: 'hello',
      user
    });

    assert.equal(hello.success, true);
    assert.equal(hello.data.intent, 'conversation');
    assert.equal(hello.data.target, null);
    assert.equal(hello.data.steps.length, 0);
    assert.equal(hello.data.technicalEvidence.executedDiagnostic, false);
    assert.match(hello.data.reply, /no diagnostic was requested/i);

    const followUp = await chatOperatorService.processMessage({
      sessionId,
      message: 'Which layer failed?',
      user
    });
    assert.equal(followUp.success, true);
    assert.equal(followUp.data.intent, 'follow_up_explanation');
    assert.match(followUp.data.reply, /127\.0\.0\.1/);
    assert.ok(followUp.data.steps.some((step) => String(step.summary || step.label).includes('3000')), 'The previous diagnostic steps should survive a greeting');
  });

  it('Scenario A: Real DNS check returns actual records, latency, and Result/Meaning/Next step', async () => {
    const outcome = await chatOperatorService.processMessage({
      sessionId: 'TEST-SCENARIO-A',
      message: 'Check DNS for localhost',
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });

    assert.equal(outcome.success, true);
    assert.equal(outcome.data.intent, 'dns');
    assert.equal(outcome.data.target, 'localhost');
    assert.ok(outcome.data.reply.includes('**Result:**'));
    assert.ok(outcome.data.reply.includes('**Meaning:**'));
    assert.ok(outcome.data.reply.includes('**Next step:**'));
    assert.ok(Array.isArray(outcome.data.steps) && outcome.data.steps.length === 1);
    assert.equal(outcome.data.steps[0].status, 'PASS');
  });

  it('Scenario B: Real Ping check executes realPing and reports round-trip latency or loss honestly', async () => {
    const outcome = await chatOperatorService.processMessage({
      sessionId: 'TEST-SCENARIO-B',
      message: 'Ping 127.0.0.1',
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });

    assert.equal(outcome.success, true);
    assert.equal(outcome.data.intent, 'ping');
    assert.equal(outcome.data.target, '127.0.0.1');
    assert.ok(outcome.data.structuredAnswer.result.includes('127.0.0.1'));
    assert.ok(outcome.data.technicalEvidence.tool === 'realPing');
  });

  it('Scenario C: Real TCP Port check distinguishes OPEN vs CLOSED ports accurately', async () => {
    const openOutcome = await chatOperatorService.processMessage({
      sessionId: 'TEST-SCENARIO-C1',
      message: `Check whether port ${testTargetPort} is open on 127.0.0.1`,
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });

    assert.equal(openOutcome.success, true);
    assert.equal(openOutcome.data.intent, 'port_check');
    assert.ok(openOutcome.data.structuredAnswer.result.includes('OPEN'));

    // Multi-port check with one OPEN and one CLOSED port
    const multiOutcome = await chatOperatorService.processMessage({
      sessionId: 'TEST-SCENARIO-C2',
      message: `Test ports ${testTargetPort} and 59997 on 127.0.0.1`,
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });

    assert.equal(multiOutcome.success, true);
    assert.equal(multiOutcome.data.intent, 'port_check');
    assert.equal(multiOutcome.data.steps.length, 2);
    assert.equal(multiOutcome.data.steps[0].status, 'PASS');
    assert.equal(multiOutcome.data.steps[1].status, 'FAIL');
    assert.ok(multiOutcome.data.reply.includes('OPEN'));
    assert.ok(multiOutcome.data.reply.includes('CLOSED'));
  });

  it('Scenario D: Website accessibility check runs DNS, TCP, and HTTP probes in sequence', async () => {
    const outcome = await chatOperatorService.processMessage({
      sessionId: 'TEST-SCENARIO-D',
      message: `Check whether http://127.0.0.1:${testTargetPort}/health-probe-ok is working`,
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });

    assert.equal(outcome.success, true);
    assert.equal(outcome.data.intent, 'website_check');
    assert.ok(outcome.data.steps.length >= 3);
    assert.ok(outcome.data.reply.includes('200'));
    assert.equal(outcome.data.structuredAnswer.layerFailedFirst, null);
  });

  it('Scenario E: Multi-step investigation correlates cross-layer checks and isolates closed listener', async () => {
    const outcome = await chatOperatorService.processMessage({
      sessionId: 'TEST-SCENARIO-E',
      message: 'Investigate why 127.0.0.1:59996 is not responding',
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });

    assert.equal(outcome.success, true);
    assert.equal(outcome.data.intent, 'multi_step_investigation');
    assert.ok(outcome.data.steps.length >= 5);
    assert.ok(outcome.data.reply.includes('59996'));
    assert.ok(
      outcome.data.reply.includes('CLOSED') ||
      outcome.data.reply.includes('ECONNREFUSED') ||
      outcome.data.reply.includes('refused')
    );
  });

  it('Scenario F: Contextual follow-up remembers previous target and answers layer/summary questions', async () => {
    const sessionId = 'TEST-SCENARIO-F';
    await chatOperatorService.processMessage({
      sessionId,
      message: `Check port ${testTargetPort} on 127.0.0.1`,
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });

    // Follow-up 1: "Now test port 59995 on the same host"
    const followUp1 = await chatOperatorService.processMessage({
      sessionId,
      message: 'Now test port 59995 on the same host',
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });

    assert.equal(followUp1.success, true);
    assert.equal(followUp1.data.target, '127.0.0.1');
    assert.deepEqual(followUp1.data.ports, [59995]);
    assert.equal(followUp1.data.usedFollowUpTarget, true);
    assert.ok(followUp1.data.reply.includes('CLOSED'));

    // Follow-up 2: "Which layer failed first?"
    const followUp2 = await chatOperatorService.processMessage({
      sessionId,
      message: 'Which layer failed first?',
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });

    assert.equal(followUp2.success, true);
    assert.equal(followUp2.data.intent, 'follow_up_explanation');
    assert.ok(followUp2.data.reply.includes('59995') || followUp2.data.reply.includes('L4'));
  });

  it('Scenario G: Timeout / failure handling never fabricates a healthy result', async () => {
    const outcome = await chatOperatorService.processMessage({
      sessionId: 'TEST-SCENARIO-G',
      message: 'Ping 127.0.0.1',
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' },
      simulateTimeout: true
    });

    assert.equal(outcome.success, true);
    assert.equal(outcome.status, 'timeout');
    assert.ok(outcome.data.reply.includes('timed out'));
    assert.ok(outcome.data.reply.includes('No healthy result was assumed'));
  });

  it('Scenario H: RBAC blocks READONLY user from remediation and SSRF guard blocks metadata targets', async () => {
    // 1. READONLY user attempting remediation via HTTP API
    const remRes = await fetch(`${baseUrl}/api/v6/chat/message`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${viewerToken}`
      },
      body: JSON.stringify({
        sessionId: 'TEST-RBAC-1',
        message: 'Flush DNS cache and apply remediation now'
      })
    });
    assert.equal(remRes.status, 403);
    const remBody = await remRes.json();
    assert.equal(remBody.status, 'denied');
    assert.ok(remBody.error.code === 'INSUFFICIENT_PERMISSIONS');

    // 2. SSRF metadata IP blocked via HTTP API
    const ssrfRes = await fetch(`${baseUrl}/api/v6/chat/message`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`
      },
      body: JSON.stringify({
        sessionId: 'TEST-SSRF-1',
        message: 'Check port 80 on 169.254.169.254'
      })
    });
    assert.equal(ssrfRes.status, 400);
    const ssrfBody = await ssrfRes.json();
    assert.equal(ssrfBody.success, false);
    assert.equal(ssrfBody.error.code, 'SECURITY_VIOLATION_SSRF');
  });

  it('Scenario I: Cancellation stops an active request cleanly', async () => {
    const sessionId = 'TEST-CANCEL-SESSION';
    const controller = new AbortController();
    controller.abort();

    const outcome = await chatOperatorService.processMessage({
      sessionId,
      message: 'Ping 127.0.0.1',
      user: { id: 'u1', username: 'admin', role: 'ADMIN' },
      signal: controller.signal
    });

    assert.equal(outcome.success, false);
    assert.equal(outcome.status, 'cancelled');
    assert.equal(outcome.statusCode, 499);
  });

  it('Verifies GET /api/v6/system/preflight and POST /api/v6/investigate/blast-radius integrity fixes', async () => {
    // Preflight check
    const preRes = await fetch(`${baseUrl}/api/v6/system/preflight`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.equal(preRes.status, 200);
    const preBody = await preRes.json();
    assert.equal(preBody.data.checks.dnsResolver.passed, true);
    assert.equal(preBody.data.checks.runtimeSandbox.passed, true);
    assert.equal(preBody.data.checks.runtimeSandbox.classificationMethod, 'HEURISTIC_INSPECTION');

    // Blast-radius validation: reject >100 packet loss
    const invalidBrRes = await fetch(`${baseUrl}/api/v6/investigate/blast-radius`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`
      },
      body: JSON.stringify({ targetNodeId: 'node-1', simulatedPacketLossPct: 150 })
    });
    assert.equal(invalidBrRes.status, 400);

    // Blast-radius valid mathematical model with directed traversal
    temporalInfrastructureGraph.upsertNode({
      nodeId: 'br-test-gw',
      nodeType: 'Router',
      name: 'Gateway-A',
      attributes: { latencyMs: 4.0 }
    });
    temporalInfrastructureGraph.upsertNode({
      nodeId: 'br-test-app',
      nodeType: 'Service',
      name: 'App-B',
      attributes: {} // Unobserved latency -> must remain null!
    });
    temporalInfrastructureGraph.upsertEdge({
      edgeId: 'edge-gw-to-app',
      sourceId: 'br-test-gw',
      targetId: 'br-test-app',
      relationshipType: 'routes_to'
    });

    const validBrRes = await fetch(`${baseUrl}/api/v6/investigate/blast-radius`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`
      },
      body: JSON.stringify({ targetNodeId: 'br-test-gw', simulatedPacketLossPct: 20 })
    });
    assert.equal(validBrRes.status, 200);
    const validBrBody = await validBrRes.json();
    assert.equal(validBrBody.data.modelFidelity, 'MATHEMATICAL_MODEL');
    const impactedApp = validBrBody.data.downstreamImpact.find((n) => n.nodeId === 'br-test-app');
    assert.ok(impactedApp, 'Downstream dependent node should be traversed');
    assert.equal(impactedApp.currentLatencyMs, null, 'Unobserved baseline latency must remain null');
    assert.equal(impactedApp.projectedLatencyMs, null, 'Unobserved projected latency must remain null');
  });

  it('Scenario J: Typo Auto-Correction (google.ocm -> google.com), Fast System DNS Connection Check & Deep Session Memory', async () => {
    const sessionId = 'TEST-TYPO-AND-DNS-FAST';

    // 1. User types "check ping google.ocm" -> auto-corrects to google.com and saves google.com as lastTarget
    const t0 = performance.now();
    const typoTurn = await chatOperatorService.processMessage({
      sessionId,
      message: 'check ping google.ocm',
      user: { id: 'u1', username: 'admin', role: 'ADMIN' }
    });
    const elapsedTypoMs = performance.now() - t0;

    assert.equal(typoTurn.success, true);
    assert.equal(typoTurn.data.target, 'google.com', 'Should auto-correct google.ocm to google.com');
    assert.equal(typoTurn.data.sessionContext.lastTarget, 'google.com', 'Session memory must store google.com, never google.ocm');
    assert.ok(typoTurn.data.reply.includes('google.com'), 'Reply should reference auto-corrected google.com');
    assert.ok(elapsedTypoMs < 4000, `Ping + typo correction should complete in <4s (took ${elapsedTypoMs.toFixed(1)}ms)`);

    // 2. User types "check dns connection" -> runs fast system DNS health check in <2s without falling back to google.ocm
    const t1 = performance.now();
    const dnsConnTurn = await chatOperatorService.processMessage({
      sessionId,
      message: 'check dns connection',
      user: { id: 'u1', username: 'admin', role: 'ADMIN' }
    });
    const elapsedDnsMs = performance.now() - t1;

    assert.equal(dnsConnTurn.success, true);
    assert.ok(!dnsConnTurn.data.reply.includes('google.ocm'), 'Must never test broken typo google.ocm');
    assert.ok(dnsConnTurn.data.reply.includes('DNS connection check completed'), 'Should execute system DNS connection check');
    assert.ok(elapsedDnsMs < 2500, `System DNS connection check must complete in <2.5s (took ${elapsedDnsMs.toFixed(1)}ms)`);

    // 3. Deep memory recall: "What have we tested so far?"
    const memTurn = await chatOperatorService.processMessage({
      sessionId,
      message: 'What have we tested so far?',
      user: { id: 'u1', username: 'admin', role: 'ADMIN' }
    });
    assert.equal(memTurn.success, true);
    assert.ok(memTurn.data.reply.includes('Session Investigation Memory'), 'Should return structured session entity memory');
    assert.ok(memTurn.data.reply.includes('google.com'), 'Memory should include google.com');
  });
});

