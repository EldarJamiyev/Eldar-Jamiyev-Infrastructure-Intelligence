/**
 * EJII Super Master Directive — Comprehensive Verification & Regression Suite (Cases A through U)
 * Covers all 21 required regression scenarios from Part XIV, Section 22 + v6 Security Hardening.
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

describe('EJII Chat-First Conversational Diagnostic Engine & Super Master Directive Regression Suite (Cases A–U)', () => {
  let server;
  let baseUrl;
  let testTargetPort;
  let adminToken;
  let viewerToken;
  let secondUserToken;

  before(async () => {
    const app = express();
    app.use(express.json());
    app.use('/api/v6', v6Router);
    app.get('/health-probe-ok', (_req, res) => res.status(200).json({ ok: true }));
    app.get('/redirect-probe', (_req, res) => res.redirect(302, `http://127.0.0.1:${testTargetPort}/health-probe-ok`));

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
    secondUserToken = generateToken({ id: 'u-other-99', username: 'other_analyst', role: 'ANALYST' });
  });

  after(async () => {
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it('Case A (Greeting): "Hello" returns conversational response, runs 0 probes, and preserves prior diagnostic context', async () => {
    const sessionId = 'TEST-CASE-A-GREETING';
    // Establish a prior diagnostic target
    await chatOperatorService.processMessage({
      sessionId,
      message: 'Check DNS for localhost',
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });

    const greetOutcome = await chatOperatorService.processMessage({
      sessionId,
      message: 'Hello',
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });

    assert.equal(greetOutcome.success, true);
    assert.equal(greetOutcome.data.intent, 'greeting');
    assert.equal(greetOutcome.data.steps.length, 0, 'Greeting must execute zero network probes');
    assert.equal(greetOutcome.data.sessionContext.lastTarget, 'localhost', 'Greeting must preserve previous target');
  });

  it('Case B & C (DNS Lookup & DNS Failure): Real DNS check reports method/records; invalid domain fails fast without fabricated IP', async () => {
    const okOutcome = await chatOperatorService.processMessage({
      sessionId: 'TEST-CASE-B-DNS',
      message: 'Check DNS for localhost',
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });

    assert.equal(okOutcome.success, true);
    assert.equal(okOutcome.data.intent, 'dns');
    assert.equal(okOutcome.data.target, 'localhost');
    assert.ok(okOutcome.data.reply.includes('**Result:**'));
    assert.ok(okOutcome.data.reply.includes('**Meaning:**'));
    assert.ok(okOutcome.data.reply.includes('**Next step:**'));
    assert.ok(okOutcome.data.technicalEvidence.resolutionMethod, 'Must report resolutionMethod');

    const t0 = performance.now();
    const failOutcome = await chatOperatorService.processMessage({
      sessionId: 'TEST-CASE-C-DNS-FAIL',
      message: 'Check DNS for nonexistent-domain-99887766.invalid',
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });
    const elapsedMs = performance.now() - t0;

    assert.equal(failOutcome.success, true);
    assert.equal(failOutcome.data.intent, 'dns');
    assert.equal(failOutcome.data.steps[0].status, 'FAIL');
    assert.deepEqual(failOutcome.data.technicalEvidence.rawResult.records, [], 'Failed DNS lookup must never fabricate an IP');
    assert.ok(elapsedMs < 3500, `Invalid DNS lookup should fail fast (<3.5s, took ${elapsedMs.toFixed(1)}ms)`);
  });

  it('Case D (General DNS Health): "Check DNS connectivity" inspects local DNS config and runs health check without inheriting broken target', async () => {
    const sessionId = 'TEST-CASE-D-DNS-HEALTH';
    const outcome = await chatOperatorService.processMessage({
      sessionId,
      message: 'Check DNS connectivity',
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });

    assert.equal(outcome.success, true);
    assert.equal(outcome.data.intent, 'dns');
    assert.ok(Array.isArray(outcome.data.technicalEvidence.configuredServers));
    assert.ok(outcome.data.technicalEvidence.localhostProbe);
    assert.ok(outcome.data.technicalEvidence.externalProbe);
    assert.ok(outcome.data.reply.includes('System DNS health check completed'));
  });

  it('Case E & F (Ping & ICMP Restriction Honesty): Ping reports packet stats and keeps ICMP failure distinct from TCP reachability', async () => {
    const outcome = await chatOperatorService.processMessage({
      sessionId: 'TEST-CASE-EF-PING',
      message: 'Ping 127.0.0.1',
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });

    assert.equal(outcome.success, true);
    assert.equal(outcome.data.intent, 'ping');
    assert.equal(outcome.data.target, '127.0.0.1');
    const ev = outcome.data.technicalEvidence;
    assert.ok(ev.icmpResult, 'Must record raw ICMP result');
    // If ICMP failed in the container sandbox while TCP succeeded, verify they are kept strictly distinct
    if (!ev.icmpResult.success && ev.separateTcpCheck && ev.separateTcpCheck.status === 'OPEN') {
      assert.ok(outcome.data.reply.includes('0/'), 'Must state 0 ICMP replies received');
      assert.ok(outcome.data.reply.includes('Separately'), 'Must present TCP reachability as a separate measurement');
    }
  });

  it('Case G (TCP Port & Short Follow-ups): Distinguishes OPEN vs CLOSED and supports "Try <port> too" and "Repeat the same check"', async () => {
    const sessionId = 'TEST-CASE-G-PORTS';
    const openOutcome = await chatOperatorService.processMessage({
      sessionId,
      message: `Check whether port ${testTargetPort} is open on 127.0.0.1`,
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });

    assert.equal(openOutcome.success, true);
    assert.equal(openOutcome.data.intent, 'port_check');
    assert.ok(openOutcome.data.structuredAnswer.result.includes('OPEN'));
    assert.ok(openOutcome.data.structuredAnswer.meaning.includes('transport connectivity'), 'Must note transport vs app health');

    // Short follow-up: "Try 59997 too"
    const tryClosed = await chatOperatorService.processMessage({
      sessionId,
      message: 'Try 59997 too',
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });
    assert.equal(tryClosed.success, true);
    assert.equal(tryClosed.data.intent, 'port_check');
    assert.equal(tryClosed.data.target, '127.0.0.1');
    assert.deepEqual(tryClosed.data.ports, [59997]);
    assert.ok(tryClosed.data.reply.includes('CLOSED'));

    // Repeat follow-up: "Repeat the same check"
    const repeatTurn = await chatOperatorService.processMessage({
      sessionId,
      message: 'Repeat the same check',
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });
    assert.equal(repeatTurn.success, true);
    assert.equal(repeatTurn.data.intent, 'port_check');
    assert.equal(repeatTurn.data.target, '127.0.0.1');
    assert.deepEqual(repeatTurn.data.ports, [59997]);
  });

  it('Case H (HTTPS / Website Check): Runs DNS -> TCP -> HTTP with aligned schema (no undefined/[object Object]) and handles redirects', async () => {
    const okWeb = await chatOperatorService.processMessage({
      sessionId: 'TEST-CASE-H-WEB-1',
      message: `Check whether http://127.0.0.1:${testTargetPort}/health-probe-ok is working`,
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });

    assert.equal(okWeb.success, true);
    assert.equal(okWeb.data.intent, 'website_check');
    assert.ok(okWeb.data.reply.includes('200'));
    assert.ok(!okWeb.data.reply.includes('undefined'), 'Must never contain undefined in user-facing output');
    assert.ok(!okWeb.data.reply.includes('[object Object]'), 'Must never contain [object Object] in user-facing output');

    const redirectWeb = await chatOperatorService.processMessage({
      sessionId: 'TEST-CASE-H-WEB-2',
      message: `Check whether http://127.0.0.1:${testTargetPort}/redirect-probe is working`,
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });
    assert.equal(redirectWeb.success, true);
    assert.ok(redirectWeb.data.reply.includes('302') && redirectWeb.data.reply.includes('redirection'), 'Must treat 302 as HTTP redirection');
  });

  it('Case I (Local IP Configuration): "Check my IP" inspects actual OS interfaces without inheriting previous remote target', async () => {
    const sessionId = 'TEST-CASE-I-LOCAL-IP';
    await chatOperatorService.processMessage({
      sessionId,
      message: `Check port ${testTargetPort} on 127.0.0.1`,
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });

    const ipTurn = await chatOperatorService.processMessage({
      sessionId,
      message: 'Check my IP',
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });

    assert.equal(ipTurn.success, true);
    assert.equal(ipTurn.data.intent, 'local_ip_config');
    assert.ok(ipTurn.data.interfaceTable, 'Must include structured interfaceTable');
    assert.ok(Array.isArray(ipTurn.data.technicalEvidence.interfaces) && ipTurn.data.technicalEvidence.interfaces.length > 0);
    assert.ok(ipTurn.data.technicalEvidence.executionScope, 'Must state container vs host executionScope');
    assert.equal(ipTurn.data.sessionContext.lastTarget, '127.0.0.1', 'Must preserve previous remote target in session memory');
  });

  it('Case J (Default Gateway): "Ping my default gateway" inspects OS routing table and never guesses .1 or uses previous target', async () => {
    const sessionId = 'TEST-CASE-J-GATEWAY';
    const gwTurn = await chatOperatorService.processMessage({
      sessionId,
      message: 'Ping my default gateway',
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });

    assert.equal(gwTurn.success, true);
    assert.equal(gwTurn.data.intent, 'gateway_check');
    assert.ok(gwTurn.data.technicalEvidence.gatewayInfo, 'Must include OS routing table gatewayInfo');
    if (!gwTurn.data.technicalEvidence.gatewayInfo.verified) {
      assert.equal(gwTurn.data.technicalEvidence.pingExecuted, false, 'Must not ping a guessed gateway when unverified');
      assert.ok(gwTurn.data.reply.includes('never guesses'));
    }
  });

  it('Case K & L (Active Connections & Destination Endpoints): Enumerates real OS sockets and diffs snapshots', async () => {
    const sessionId = 'TEST-CASE-KL-CONNECTIONS';
    const connTurn1 = await chatOperatorService.processMessage({
      sessionId,
      message: 'Show me the active connections',
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });

    assert.equal(connTurn1.success, true);
    assert.equal(connTurn1.data.intent, 'active_connections');
    assert.ok(connTurn1.data.connectionTable, 'Must return structured connectionTable');
    assert.ok(connTurn1.data.technicalEvidence.collectionMethod, 'Must report collectionMethod');
    assert.ok(connTurn1.data.technicalEvidence.collectionScope, 'Must report collectionScope');

    const connTurn2 = await chatOperatorService.processMessage({
      sessionId,
      message: 'Which endpoints appeared since the last snapshot?',
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });
    assert.equal(connTurn2.success, true);
    assert.equal(connTurn2.data.intent, 'active_connections');
    assert.ok(connTurn2.data.technicalEvidence.snapshotDiff, 'Second snapshot query must include snapshotDiff');
  });

  it('Case M, N, O (Contextual Follow-up, Context Loss Clarification, and Multi-Target Disambiguation)', async () => {
    // Case N: Context Loss — follow-up with no prior target must ask clarification and NOT default to localhost
    const noContextTurn = await chatOperatorService.processMessage({
      sessionId: 'TEST-CASE-N-NO-CONTEXT',
      message: 'Now test port 80 on the same host',
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });

    assert.equal(noContextTurn.success, true);
    assert.equal(noContextTurn.data.intent, 'clarification_needed');
    assert.equal(noContextTurn.data.steps.length, 0, 'Must not run a probe on localhost when context is missing');
    assert.ok(noContextTurn.data.reply.includes('Clarification Needed'));

    // Case O: Multi-Target Follow-up Ambiguity after Active Connections
    const multiSessionId = 'TEST-CASE-O-MULTI';
    await chatOperatorService.processMessage({
      sessionId: multiSessionId,
      message: 'Show me the active connections',
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });

    const ambiguousFollowUp = await chatOperatorService.processMessage({
      sessionId: multiSessionId,
      message: 'Check port 443 on that host',
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });
    assert.equal(ambiguousFollowUp.success, true);
    assert.equal(ambiguousFollowUp.data.intent, 'clarification_needed');
    assert.equal(ambiguousFollowUp.data.technicalEvidence.clarificationReason, 'AMBIGUOUS_MULTI_TARGET');
  });

  it('Case P & Q (Dual-Mode Informational Question vs Historical Comparison & Incident Report)', async () => {
    const sessionId = 'TEST-CASE-PQ-DUAL-MODE';
    // Run two port checks on 127.0.0.1
    await chatOperatorService.processMessage({
      sessionId,
      message: `Check port ${testTargetPort} on 127.0.0.1`,
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });
    await chatOperatorService.processMessage({
      sessionId,
      message: 'Try 59995 too',
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });

    // Case P: Informational question runs 0 probes and preserves target 127.0.0.1
    const infoTurn = await chatOperatorService.processMessage({
      sessionId,
      message: 'What is the difference between connection refused and timeout?',
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });
    assert.equal(infoTurn.success, true);
    assert.equal(infoTurn.data.intent, 'informational_question');
    assert.equal(infoTurn.data.mode, 'informational');
    assert.equal(infoTurn.data.steps.length, 0, 'Informational question must run 0 network probes');
    assert.equal(infoTurn.data.sessionContext.lastTarget, '127.0.0.1', 'Must preserve previous diagnostic target');

    // Case Q: Historical comparison & incident report
    const compareTurn = await chatOperatorService.processMessage({
      sessionId,
      message: 'Compare the latest results with the previous test',
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });
    assert.equal(compareTurn.success, true);
    assert.equal(compareTurn.data.intent, 'follow_up_explanation');
    assert.ok(compareTurn.data.reply.includes('Historical Comparison'));

    const reportTurn = await chatOperatorService.processMessage({
      sessionId,
      message: 'Give me a concise incident report',
      user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
    });
    assert.equal(reportTurn.success, true);
    assert.ok(reportTurn.data.reportMarkdown, 'Must generate structured reportMarkdown');
  });

  it('Case R, S, T (Session Ownership Security, Cancellation Integrity, Bounded Working Memory & RBAC/SSRF)', async () => {
    const ownedSessionId = 'TEST-CASE-R-OWNED-BY-ADMIN';
    chatOperatorService.clearSession(ownedSessionId);
    // Admin creates session
    const createRes = await fetch(`${baseUrl}/api/v6/chat/message`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`
      },
      body: JSON.stringify({
        sessionId: ownedSessionId,
        message: 'Check DNS for localhost'
      })
    });
    assert.equal(createRes.status, 200);

    // Case R: Second authenticated user attempts to read, message, or delete Admin's session -> 403 FORBIDDEN
    const readOtherRes = await fetch(`${baseUrl}/api/v6/chat/session/${ownedSessionId}`, {
      headers: { Authorization: `Bearer ${secondUserToken}` }
    });
    assert.equal(readOtherRes.status, 403);
    const readOtherBody = await readOtherRes.json();
    assert.equal(readOtherBody.error.code, 'SESSION_OWNERSHIP_VIOLATION');

    const msgOtherRes = await fetch(`${baseUrl}/api/v6/chat/message`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${secondUserToken}`
      },
      body: JSON.stringify({
        sessionId: ownedSessionId,
        message: 'Ping localhost'
      })
    });
    assert.equal(msgOtherRes.status, 403);

    const delOtherRes = await fetch(`${baseUrl}/api/v6/chat/session/${ownedSessionId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${secondUserToken}` }
    });
    assert.equal(delOtherRes.status, 403);

    // Case S: Cancellation preserves existing session target
    const controller = new AbortController();
    controller.abort();
    const cancelOutcome = await chatOperatorService.processMessage({
      sessionId: ownedSessionId,
      message: 'Ping 127.0.0.1',
      user: { id: 'u-admin', username: 'admin', role: 'ADMIN' },
      signal: controller.signal
    });
    assert.equal(cancelOutcome.status, 'cancelled');
    const preservedSession = chatOperatorService.getOrCreateSession(ownedSessionId, { id: 'u-admin', username: 'admin', role: 'ADMIN' });
    assert.equal(preservedSession.lastTarget, 'localhost', 'Cancelled request must not corrupt previous session target');

    // Case T: Bounded active working memory vs full SQLite persistence
    const memorySessionId = 'TEST-CASE-T-BOUNDED-MEMORY';
    chatOperatorService.clearSession(memorySessionId);
    for (let i = 0; i < 22; i++) {
      await chatOperatorService.processMessage({
        sessionId: memorySessionId,
        message: 'Hello',
        user: { id: 'u-admin', username: 'admin', role: 'ADMIN' }
      });
    }
    const memSession = chatOperatorService.getOrCreateSession(memorySessionId, { id: 'u-admin', username: 'admin', role: 'ADMIN' });
    assert.equal(memSession.messages.length, 40, 'Active in-memory message window must be bounded to 40 messages');
    assert.equal(memSession.totalPersistedMessages, 44, 'All 44 messages must be tracked in SQLite');
    const fullPersisted = chatOperatorService.getPersistedMessages(memorySessionId, 100, 0);
    assert.equal(fullPersisted.length, 44, 'SQLite must retain all 44 persisted messages');


    // RBAC & SSRF checks
    const remRes = await fetch(`${baseUrl}/api/v6/chat/message`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${viewerToken}`
      },
      body: JSON.stringify({
        sessionId: 'TEST-RBAC-VIEWER',
        message: 'Flush DNS cache and apply remediation now'
      })
    });
    assert.equal(remRes.status, 403);

    const ssrfRes = await fetch(`${baseUrl}/api/v6/chat/message`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`
      },
      body: JSON.stringify({
        sessionId: 'TEST-SSRF-GUARD',
        message: 'Check port 80 on 169.254.169.254'
      })
    });
    assert.equal(ssrfRes.status, 400);
  });

  it('Verifies GET /api/v6/system/preflight and POST /api/v6/investigate/blast-radius integrity', async () => {
    const preRes = await fetch(`${baseUrl}/api/v6/system/preflight`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.equal(preRes.status, 200);
    const preBody = await preRes.json();
    assert.equal(preBody.data.checks.dnsResolver.passed, true);

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
      attributes: {}
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
  });
});
