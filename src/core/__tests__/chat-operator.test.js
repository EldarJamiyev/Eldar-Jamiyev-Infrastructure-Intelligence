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
    assert.ok(okOutcome.data.structuredAnswer.result, 'Must populate structuredAnswer.result');
    assert.ok(okOutcome.data.structuredAnswer.meaning, 'Must populate structuredAnswer.meaning');
    assert.ok(okOutcome.data.structuredAnswer.nextStep, 'Must populate structuredAnswer.nextStep');
    assert.ok(!okOutcome.data.reply.includes('**Result:**'), 'Natural reply must not force rigid **Result:** template headers');
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
    assert.equal(okWeb.data.technicalEvidence.dns.resolutionMethod, 'ip_literal_bypass', 'Literal IP website check must not claim a DNS query was performed');

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
    assert.equal(noContextTurn.data.technicalEvidence.clarificationReason, 'MISSING_TARGET_CONTEXT');

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

  it('Evidence-Integrity Audit Items 1, 2, 4, 5: No 8.8.8.8 system DNS fallback, no 1.2ms fabricated timing, truthful loopback-only local IP, and truthful socket collector failure', async () => {
    const { discoverSystemDnsConfiguration, getRealSystemDns } = require('../../protocols/dns-diag');
    const { extractObservedTimingMs } = require('../chat/chat-operator-service');
    const { inspectLocalNetworkConfiguration } = require('../../protocols/host-metrics');
    const { processSocketCorrelator } = require('../../network/process-socket-correlator');

    // Item 1: DNS resolver discovery when no resolver is found must return unavailable and never 8.8.8.8
    const unavailableDns = discoverSystemDnsConfiguration({
      resolvConfContent: '# empty resolv.conf\n',
      resolvectlOutput: '',
      nodeServers: []
    });
    assert.equal(unavailableDns.status, 'unavailable');
    assert.equal(unavailableDns.verified, false);
    assert.deepEqual(unavailableDns.configuredServers, []);
    assert.ok(!unavailableDns.configuredServers.includes('8.8.8.8'), 'Must never invent 8.8.8.8');
    assert.equal(getRealSystemDns({
      resolvConfContent: '# empty\n',
      resolvectlOutput: '',
      nodeServers: []
    }), null);

    // Stub resolver with upstream discovery via resolvectl
    const stubDns = discoverSystemDnsConfiguration({
      resolvConfContent: 'nameserver 127.0.0.53\n',
      resolvectlOutput: 'Global\n       DNS Servers: 9.9.9.9 149.112.112.112\n'
    });
    assert.equal(stubDns.status, 'local_stub_resolver');
    assert.equal(stubDns.isLocalStub, true);
    assert.deepEqual(stubDns.localStubServers, ['127.0.0.53']);
    assert.deepEqual(stubDns.upstreamServers, ['9.9.9.9', '149.112.112.112']);

    // Item 2: Timing extraction preserves 0 and returns null when absent (never 1.2)
    assert.equal(extractObservedTimingMs({ latencyMs: 0 }), 0, 'Must preserve legitimate 0ms measurement');
    assert.equal(extractObservedTimingMs({ durationMs: 0 }), 0, 'Must preserve legitimate 0ms duration');
    assert.equal(extractObservedTimingMs({}), null, 'Must return null when timing is absent');
    assert.equal(extractObservedTimingMs(null), null, 'Must return null for null input');
    assert.notEqual(extractObservedTimingMs({}), 1.2, 'Must never fabricate 1.2ms');

    // Item 4: Loopback-only local IP configuration must never report 127.0.0.1 as primary non-loopback IPv4
    const loopbackOnlyNet = inspectLocalNetworkConfiguration({
      networkInterfaces: {
        lo: [
          { address: '127.0.0.1', netmask: '255.0.0.0', family: 'IPv4', mac: '00:00:00:00:00:00', internal: true, cidr: '127.0.0.1/8' },
          { address: '::1', netmask: 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', family: 'IPv6', mac: '00:00:00:00:00:00', internal: true, cidr: '::1/128' }
        ]
      }
    });
    assert.equal(loopbackOnlyNet.primaryIpv4, null, 'Must not fall back primaryIpv4 to 127.0.0.1');
    assert.equal(loopbackOnlyNet.primaryIpv4Status, 'loopback_only');
    assert.equal(loopbackOnlyNet.loopbackIpv4, '127.0.0.1');

    // Item 5: Socket collector failure must return success: false and collectionStatus: collector_failed
    const failedSockets = await processSocketCorrelator.collectActiveConnectionsInventory({}, {
      forceFailureReason: 'Simulated ss/lsof/proc collector failure in restricted container'
    });
    assert.equal(failedSockets.success, false);
    assert.equal(failedSockets.collectionStatus, 'collector_failed');
    assert.equal(failedSockets.totalCount, null, 'Must not report 0 active sockets when collector failed');
  });

  it('Brain-First Intelligence Revolution: Semantic goal generalization, conversational restraint, and multi-target context switching', async () => {
    const user = { id: 'u1', username: 'analyst', role: 'ANALYST' };

    // 1. Conversational & meta questions execute 0 probes and do not probe localhost
    for (const msg of [
      'How are you?',
      'Do you understand me?',
      'That was interesting',
      'What can you help me with?',
      'Why did you say that?'
    ]) {
      const turn = await chatOperatorService.processMessage({
        sessionId: 'TEST-BRAIN-CONV',
        message: msg,
        user
      });
      assert.equal(turn.success, true);
      assert.equal(turn.data.steps.length, 0, `"${msg}" must execute 0 network probes`);
      assert.notEqual(turn.data.target, 'localhost', `"${msg}" must never target localhost`);
    }

    // 2. Conceptual questions and negative execution constraints execute 0 probes
    for (const msg of [
      'What exactly is a default gateway?',
      'Why can a server respond to ping but reject port 443?',
      'Can you explain what DNS actually does?',
      'Is a timeout the same thing as connection refused?',
      "Don't run anything; just explain what DNS resolution is"
    ]) {
      const turn = await chatOperatorService.processMessage({
        sessionId: 'TEST-BRAIN-CONCEPT',
        message: msg,
        user
      });
      assert.equal(turn.success, true);
      assert.equal(turn.data.intent, 'informational_question');
      assert.equal(turn.data.steps.length, 0, `"${msg}" must execute 0 network probes`);
    }

    // 3. Semantic goal generalization: IP/DNS lookup paraphrases for well-known brand shorthand
    for (const msg of [
      "What's Google's IP?",
      'IP of google',
      'What address does Google resolve to?',
      "Can you find Google's IP address?",
      'Resolve google.com',
      'Show me the IPs for Google',
      'Resolve Google for me'
    ]) {
      const parsed = chatOperatorService.parseIntentAndEntities(msg, null);
      assert.equal(parsed.intent, 'dns', `"${msg}" should map to dns intent`);
      assert.equal(parsed.target, 'google.com', `"${msg}" should generalize target to google.com`);
    }

    // 4. Problem descriptions without a target ask a clarifying question and never probe localhost
    for (const msg of [
      'The internet is not working',
      "I can't open the website",
      "The site won't open",
      "I'm getting connection errors",
      'Could you check whether this endpoint responds?',
      'It works on my laptop but not on the other computer',
      'The application has become really slow'
    ]) {
      const turn = await chatOperatorService.processMessage({
        sessionId: `TEST-BRAIN-PROBLEM-${Buffer.from(msg).toString('hex').slice(0, 8)}`,
        message: msg,
        user
      });
      assert.equal(turn.success, true);
      assert.equal(turn.data.intent, 'clarification_needed', `"${msg}" must ask for clarification`);
      assert.equal(turn.data.steps.length, 0, `"${msg}" must execute 0 probes`);
      assert.equal(turn.data.target, null, `"${msg}" must not default target to localhost`);
    }

    // 5. Contextual reasoning & switching to "the other host"
    const ctxSession = 'TEST-BRAIN-CONTEXT-SWITCH';
    await chatOperatorService.processMessage({
      sessionId: ctxSession,
      message: 'Check DNS for localhost',
      user
    });
    await chatOperatorService.processMessage({
      sessionId: ctxSession,
      message: `Check port ${testTargetPort} on 127.0.0.1`,
      user
    });

    const whyHealthy = await chatOperatorService.processMessage({
      sessionId: ctxSession,
      message: 'Why did you say the connection was healthy?',
      user
    });
    assert.equal(whyHealthy.success, true);
    assert.equal(whyHealthy.data.intent, 'follow_up_explanation');
    assert.equal(whyHealthy.data.steps.length, 0);
    assert.ok(whyHealthy.data.reply.includes('127.0.0.1'));

    const summaryTurn = await chatOperatorService.processMessage({
      sessionId: ctxSession,
      message: 'Can you summarize what we have found so far?',
      user
    });
    assert.equal(summaryTurn.success, true);
    assert.equal(summaryTurn.data.intent, 'follow_up_explanation');
    assert.ok(summaryTurn.data.reply.includes('Session Summary'));

    const otherHostTurn = await chatOperatorService.processMessage({
      sessionId: ctxSession,
      message: 'Try the same thing against the other host',
      user
    });
    assert.equal(otherHostTurn.success, true);
    assert.equal(otherHostTurn.data.intent, 'port_check');
    assert.equal(otherHostTurn.data.target, 'localhost', 'Must switch to the prior distinct host (localhost)');
    assert.deepEqual(otherHostTurn.data.ports, [testTargetPort]);
  });

  it('Phase 3: The Real Conversational Brain & Mega Development Directive Verification', async () => {
    const user = { id: 'u-brain-tester', username: 'brain_analyst', role: 'ANALYST' };
    const { semanticAiInterpreter } = require('../chat/semantic-ai-interpreter');
    const { classifyConversationalTurn } = require('../chat/technical-knowledge-base');

    // 1. Production Wiring: ChatOperatorService has real semantic interpreter wired
    chatOperatorService.setLlmInterpreter(semanticAiInterpreter);
    assert.ok(chatOperatorService.llmInterpreter !== null, 'llmInterpreter must be wired and not null');
    const brainStatus = chatOperatorService.getBrainStatus();
    assert.equal(brainStatus.llmInterpreterConfigured, true, 'getBrainStatus must report llmInterpreterConfigured: true');

    // 2. Contract Alignment: classifyConversationalTurn returns both type and subtype
    const convTurn = classifyConversationalTurn('How are you?');
    assert.ok(convTurn.matched, 'Must match conversational turn');
    assert.equal(convTurn.type, 'how_are_you', 'Must populate type property');
    assert.equal(convTurn.subtype, 'how_are_you', 'Must populate subtype property');

    // 3. Introductions ("I\'m Eldar"): 0 probes, natural greeting
    const introTurn = await chatOperatorService.processMessage({
      sessionId: 'TEST-BRAIN-INTRO',
      message: "I'm Eldar",
      user
    });
    assert.equal(introTurn.success, true);
    assert.equal(introTurn.data.intent, 'greeting');
    assert.equal(introTurn.data.steps.length, 0, 'Introductions must execute 0 probes');
    assert.ok(introTurn.data.reply.includes('Eldar'), 'Must welcome the user by name');

    // 4. Identity ("Who are you?"): 0 probes, natural explanation
    const idTurn = await chatOperatorService.processMessage({
      sessionId: 'TEST-BRAIN-IDENTITY',
      message: 'Who are you?',
      user
    });
    assert.equal(idTurn.success, true);
    assert.equal(idTurn.data.intent, 'greeting');
    assert.equal(idTurn.data.steps.length, 0, 'Identity must execute 0 probes');
    assert.ok(idTurn.data.reply.includes('EJII'), 'Must explain EJII identity');

    // 5. Open-ended Query ("What is Google?"): 0 probes, conceptual overview
    const googleOverview = await chatOperatorService.processMessage({
      sessionId: 'TEST-BRAIN-WHAT-IS-GOOGLE',
      message: 'What is Google?',
      user
    });
    assert.equal(googleOverview.success, true);
    assert.equal(googleOverview.data.intent, 'informational_question');
    assert.equal(googleOverview.data.steps.length, 0, 'What is Google must execute 0 network probes');
    assert.ok(googleOverview.data.reply.toLowerCase().includes('google'), 'Must provide Google overview');

    // 6. Bare "DNS" without prior target: asks for clarification and never probes localhost
    const bareDnsTurn = await chatOperatorService.processMessage({
      sessionId: 'TEST-BRAIN-BARE-DNS',
      message: 'DNS',
      user
    });
    assert.equal(bareDnsTurn.success, true);
    assert.equal(bareDnsTurn.data.intent, 'clarification_needed');
    assert.equal(bareDnsTurn.data.steps.length, 0, 'Bare DNS must execute 0 probes');
    assert.equal(bareDnsTurn.data.target, null, 'Bare DNS must not set target to localhost');

    // 7. "DNS test": runs general DNS health check without requiring a specific host
    const dnsTestTurn = await chatOperatorService.processMessage({
      sessionId: 'TEST-BRAIN-DNS-TEST',
      message: 'DNS test',
      user
    });
    assert.equal(dnsTestTurn.success, true);
    assert.equal(dnsTestTurn.data.intent, 'dns');
    assert.equal(dnsTestTurn.data.technicalEvidence.isSystemDnsHealthCheck, true);

    // 8. "Check mail server": requests domain/server hostname instead of pinging localhost
    const mailServerTurn = await chatOperatorService.processMessage({
      sessionId: 'TEST-BRAIN-MAIL-SERVER',
      message: 'Check mail server',
      user
    });
    assert.equal(mailServerTurn.success, true);
    assert.equal(mailServerTurn.data.intent, 'clarification_needed');
    assert.equal(mailServerTurn.data.steps.length, 0, 'Check mail server without domain must execute 0 probes');
    assert.equal(mailServerTurn.data.target, null, 'Check mail server without domain must never target localhost');

    // 9. "Check DHCP server connection": inspects DHCP and reports truthful environment status
    const dhcpTurn = await chatOperatorService.processMessage({
      sessionId: 'TEST-BRAIN-DHCP',
      message: 'Check DHCP server connection',
      user
    });
    assert.equal(dhcpTurn.success, true);
    assert.equal(dhcpTurn.data.intent, 'dhcp_check');
    assert.ok(dhcpTurn.data.steps.length >= 1, 'Must execute truthful DHCP inspection step');
    assert.ok(dhcpTurn.data.technicalEvidence.dhcpStatus, 'Must report dhcpStatus');
  });

  it('Phase 4/5: The Real Conversational Brain, Truthful Attribution & Healthy Hypothesis Verification', async () => {
    const user = { id: 'u-brain-tester', username: 'brain_analyst', role: 'ANALYST' };
    // 1. Name extraction & query: "my name is what" must NEVER name user "What"
    const nameQueryTurn = await chatOperatorService.processMessage({
      sessionId: 'TEST-BRAIN-NAME-QUERY',
      message: 'my name is what',
      user
    });
    assert.equal(nameQueryTurn.success, true);
    assert.equal(nameQueryTurn.data.intent, 'greeting');
    assert.equal(nameQueryTurn.data.steps.length, 0);
    assert.ok(!nameQueryTurn.data.reply.toLowerCase().includes('nice to meet you, what'), 'Must never name user "What"');

    // 2. Name introduction and correction
    const nameIntroTurn = await chatOperatorService.processMessage({
      sessionId: 'TEST-BRAIN-NAME-CORRECT',
      message: 'I am Elvin',
      user
    });
    assert.equal(nameIntroTurn.success, true);
    assert.ok(nameIntroTurn.data.reply.includes('Elvin'), 'Must acknowledge Elvin');

    const nameFollowUp = await chatOperatorService.processMessage({
      sessionId: 'TEST-BRAIN-NAME-CORRECT',
      message: 'what is my name?',
      user
    });
    assert.equal(nameFollowUp.success, true);
    assert.ok(nameFollowUp.data.reply.includes('Elvin'), 'Must remember name Elvin');

    // 3. Incomplete utterances: "what can you", "can you check", "why is", "how do I"
    const incTurn = await chatOperatorService.processMessage({
      sessionId: 'TEST-BRAIN-INCOMPLETE',
      message: 'what can you',
      user
    });
    assert.equal(incTurn.success, true);
    assert.equal(incTurn.data.steps.length, 0, 'Incomplete utterance runs 0 probes');
    assert.ok(incTurn.data.reply.toLowerCase().includes('troubleshoot') || incTurn.data.reply.toLowerCase().includes('help') || incTurn.data.reply.toLowerCase().includes('dns'), 'Must describe capabilities');

    // 4. Bare topic "network": 0 probes, asks for clarification
    const bareNetworkTurn = await chatOperatorService.processMessage({
      sessionId: 'TEST-BRAIN-BARE-NET',
      message: 'network',
      user
    });
    assert.equal(bareNetworkTurn.success, true);
    assert.equal(bareNetworkTurn.data.intent, 'clarification_needed');
    assert.equal(bareNetworkTurn.data.steps.length, 0);

    // 5. Bare "dns" after testing a target must NEVER launch full multi-step investigation on prior target
    const primeSession = await chatOperatorService.processMessage({
      sessionId: 'TEST-BRAIN-BARE-DNS-CONTEXT',
      message: 'resolve google.com',
      user
    });
    assert.equal(primeSession.success, true);
    assert.equal(primeSession.data.intent, 'dns');

    const bareDnsWithContext = await chatOperatorService.processMessage({
      sessionId: 'TEST-BRAIN-BARE-DNS-CONTEXT',
      message: 'dns',
      user
    });
    assert.equal(bareDnsWithContext.success, true);
    assert.equal(bareDnsWithContext.data.intent, 'clarification_needed');
    assert.equal(bareDnsWithContext.data.steps.length, 0, 'Bare DNS must not launch multi-step investigation on prior target');

    // 6. Gateway discussion followed by "okay what ip" -> gateway_ip_query with truthful attribution
    const gwExplainTurn = await chatOperatorService.processMessage({
      sessionId: 'TEST-BRAIN-GW-CONTEXT',
      message: 'explain default gateway',
      user
    });
    assert.equal(gwExplainTurn.success, true);
    assert.equal(gwExplainTurn.data.intent, 'informational_question');

    const gwIpTurn = await chatOperatorService.processMessage({
      sessionId: 'TEST-BRAIN-GW-CONTEXT',
      message: 'okay what ip',
      user
    });
    assert.equal(gwIpTurn.success, true);
    assert.equal(gwIpTurn.data.intent, 'gateway_ip_query');
    assert.equal(gwIpTurn.data.steps.length, 1);
    assert.ok(gwIpTurn.data.reply.includes('169.254.') || gwIpTurn.data.reply.includes('container') || gwIpTurn.data.reply.includes('Default Gateway IP'), 'Must explain server vs client gateway');

    // 7. Frustration context repair: "wtf" recovers gateway context
    const frustrationTurn = await chatOperatorService.processMessage({
      sessionId: 'TEST-BRAIN-GW-CONTEXT',
      message: 'wtf',
      user
    });
    assert.equal(frustrationTurn.success, true);
    assert.equal(frustrationTurn.data.intent, 'greeting');
    assert.ok(frustrationTurn.data.reply.toLowerCase().includes('gateway') || frustrationTurn.data.reply.toLowerCase().includes('apologize'), 'Must repair gateway context');

    // 8. Correlator healthy hypothesis: when all checks pass, HYP-TARGET-HEALTHY-AND-REACHABLE is confirmed
    const { crossLayerIncidentCorrelator } = require('../correlation/incident-correlator');
    const healthyReport = crossLayerIncidentCorrelator.correlateSignals({
      incidentId: 'INC-HEALTHY-TEST',
      target: 'google.com:443',
      signals: [
        { domain: 'dns', subject: 'dns:google.com', claim: 'DNS resolved google.com to 142.250.190.46', normalizedValue: 'RESOLVED:142.250.190.46', anomaly: false },
        { domain: 'tcp', subject: 'socket:142.250.190.46:443', claim: 'TCP port is OPEN', normalizedValue: 'TCP_OPEN_NONE', anomaly: false },
        { domain: 'icmp_pmtu', subject: 'ip:142.250.190.46', claim: 'ICMP Echo reply received', normalizedValue: 'ICMP_ALIVE', anomaly: false }
      ]
    });
    assert.ok(healthyReport.topHypothesis, 'Must have topHypothesis');
    assert.equal(healthyReport.topHypothesis.id, 'HYP-TARGET-HEALTHY-AND-REACHABLE', 'Top hypothesis must be healthy when all checks pass');
    assert.equal(healthyReport.topHypothesis.status, 'confirmed');
    const hostContentionHyp = healthyReport.hypotheses.find(h => h.id === 'HYP-LOCAL-HOST-SOCKET-OR-KERNEL-CONTENTION');
    assert.ok(hostContentionHyp.posteriorProbability < 0.10, 'Host contention hypothesis must not be inflated on healthy checks');
  });

  it('Phase 6 / Project Falcon: Operational Intelligence, Real & Mocked LLM Execution, Local Network Discovery & Multi-Turn Task Continuity', async () => {
    const { aiModelOrchestrator } = require('../ai-model-orchestrator');
    const {
      semanticAiInterpreter,
      getSemanticInterpreterMetrics,
      resetSemanticInterpreterMetrics
    } = require('../chat/semantic-ai-interpreter');

    chatOperatorService.setLlmInterpreter(semanticAiInterpreter);
    const adminUser = { id: 'u-admin-falcon', username: 'admin', role: 'ADMIN' };

    // A. Multi-turn Mail-Task Continuation & Port Ping without ICMP
    const mailSessionId = `TEST-FALCON-MAIL-CONTINUITY-${Date.now()}`;
    const turn1Mail = await chatOperatorService.processMessage({
      sessionId: mailSessionId,
      message: 'ping mail server',
      user: adminUser
    });
    assert.equal(turn1Mail.success, true);
    assert.equal(turn1Mail.data.intent, 'clarification_needed');
    assert.equal(turn1Mail.data.steps.length, 0);
    const sessAfterT1 = chatOperatorService.getOrCreateSession(mailSessionId, adminUser);
    assert.ok(sessAfterT1.pendingTask, 'pendingTask must be stored on session');
    assert.equal(sessAfterT1.pendingTask.type, 'mail_server_inspection');

    // Turn 2: casual unpunctuated reply "mail taxes gov az" must normalize to "mail.taxes.gov.az" and continue mail task
    const turn2Mail = await chatOperatorService.processMessage({
      sessionId: mailSessionId,
      message: 'mail taxes gov az',
      user: adminUser
    });
    assert.equal(turn2Mail.success, true);
    assert.equal(turn2Mail.data.target, 'mail.taxes.gov.az', 'Unpunctuated "mail taxes gov az" must normalize to mail.taxes.gov.az');
    assert.equal(turn2Mail.data.intent, 'port_check');
    assert.ok(!turn2Mail.data.reply.includes("I'm here to help with network troubleshooting"), 'Must never fall through to generic assistance');

    // Turn 3: "port ping for mail.taxes.gov.az" must execute TCP port check on mail ports without port 443 or ICMP
    const turn3Mail = await chatOperatorService.processMessage({
      sessionId: mailSessionId,
      message: 'port ping for mail.taxes.gov.az',
      user: adminUser
    });
    assert.equal(turn3Mail.success, true);
    assert.equal(turn3Mail.data.intent, 'port_check');
    assert.equal(turn3Mail.data.target, 'mail.taxes.gov.az');
    assert.ok(turn3Mail.data.ports.includes(25) && turn3Mail.data.ports.includes(587), 'Must test mail TCP ports');
    assert.ok(!turn3Mail.data.ports.includes(443), 'Must not inject HTTPS port 443 into mail port check');
    assert.ok(!turn3Mail.data.steps.some((s) => s.tool === 'realPing'), 'port ping must not run ICMP realPing');

    // Turn 4: "ping mail ports not ICMP" must inherit mail.taxes.gov.az and never run ICMP
    const turn4Mail = await chatOperatorService.processMessage({
      sessionId: mailSessionId,
      message: 'ping mail ports not ICMP',
      user: adminUser
    });
    assert.equal(turn4Mail.success, true);
    assert.equal(turn4Mail.data.intent, 'port_check');
    assert.equal(turn4Mail.data.target, 'mail.taxes.gov.az');
    assert.ok(!turn4Mail.data.steps.some((s) => s.tool === 'realPing'), '"not ICMP" must strictly prohibit ICMP probes');

    // B. DHCP Discovery vs Conceptual Question vs Explicit TCP Port 67 Check
    const dhcpIpTurn = await chatOperatorService.processMessage({
      sessionId: 'TEST-FALCON-DHCP-IP',
      message: 'what is my DHCP server IP',
      user: adminUser
    });
    assert.equal(dhcpIpTurn.success, true);
    assert.equal(dhcpIpTurn.data.intent, 'dhcp_check');
    assert.equal(dhcpIpTurn.data.ports.length, 0, 'DHCP discovery must not set fake TCP ports 67/68');
    assert.ok(dhcpIpTurn.data.steps.some((s) => s.tool === 'discoverLocalDhcpServer'), 'Must invoke discoverLocalDhcpServer');

    const findDhcpTurn = await chatOperatorService.processMessage({
      sessionId: 'TEST-FALCON-FIND-DHCP',
      message: 'find the IP of DHCP',
      user: adminUser
    });
    assert.equal(findDhcpTurn.success, true);
    assert.equal(findDhcpTurn.data.intent, 'dhcp_check');

    // Deterministic fixture test for DHCP lease discovery
    chatOperatorService.dhcpCollectorFn = () => ({
      observed: true,
      dhcpServerIp: '192.168.10.1',
      leaseServerIdentifier: '192.168.10.1',
      interfaceName: 'eth0',
      collectionMethod: '/var/lib/dhcp/dhclient.leases',
      status: 'DHCP_LEASE_OBSERVED',
      isContainer: false,
      environmentScope: 'local_host_os',
      limitationReason: null
    });
    const dhcpLeaseFixtureTurn = await chatOperatorService.processMessage({
      sessionId: 'TEST-FALCON-DHCP-FIXTURE',
      message: 'which DHCP server assigned my address',
      user: adminUser
    });
    chatOperatorService.dhcpCollectorFn = null;
    assert.equal(dhcpLeaseFixtureTurn.success, true);
    assert.equal(dhcpLeaseFixtureTurn.data.intent, 'dhcp_check');
    assert.ok(dhcpLeaseFixtureTurn.data.reply.includes('192.168.10.1'), 'Must report discovered DHCP server IP from lease collector');

    // Conceptual "what is DHCP?" must run 0 live probes
    const whatIsDhcpTurn = await chatOperatorService.processMessage({
      sessionId: 'TEST-FALCON-WHAT-IS-DHCP',
      message: 'what is DHCP?',
      user: adminUser
    });
    assert.equal(whatIsDhcpTurn.success, true);
    assert.equal(whatIsDhcpTurn.data.intent, 'informational_question');
    assert.equal(whatIsDhcpTurn.data.steps.length, 0, 'Conceptual DHCP question must run 0 probes');
    assert.ok(whatIsDhcpTurn.data.reply.includes('Dynamic Host Configuration Protocol'), 'Must explain DHCP');

    // Explicit "test TCP port 67 on 127.0.0.1" must run port_check, not dhcp_check
    const tcp67Turn = await chatOperatorService.processMessage({
      sessionId: 'TEST-FALCON-TCP-67',
      message: 'test TCP port 67 on 127.0.0.1',
      user: adminUser
    });
    assert.equal(tcp67Turn.success, true);
    assert.equal(tcp67Turn.data.intent, 'port_check');
    assert.deepEqual(tcp67Turn.data.ports, [67]);

    // C. Gateway Discovery & Fallback Removal (Never fabricate 169.254.8.254 or 192.168.1.1)
    chatOperatorService.gatewayCollectorFn = () => ({
      verified: false,
      status: 'NO_DEFAULT_ROUTE_OBSERVED',
      gatewayIp: null,
      interfaceName: null,
      family: null,
      collectionMethod: '/proc/net/route',
      isContainer: true,
      environmentScope: 'server_container_runtime',
      limitationReason: 'No default route (0.0.0.0/0) was found in /proc/net/route.'
    });
    const gwNoneSessionId = `TEST-FALCON-GW-NONE-${Date.now()}`;
    const gwUnobservedTurn = await chatOperatorService.processMessage({
      sessionId: gwNoneSessionId,
      message: 'what is the default gateway IP?',
      user: adminUser
    });
    assert.equal(gwUnobservedTurn.success, true);
    assert.equal(gwUnobservedTurn.data.intent, 'gateway_ip_query');
    assert.ok(!gwUnobservedTurn.data.reply.includes('169.254.8.254'), 'Must never fabricate 169.254.8.254');
    assert.ok(!gwUnobservedTurn.data.reply.includes('192.168.1.1'), 'Must never fabricate 192.168.1.1');

    const wtfAfterGwNone = await chatOperatorService.processMessage({
      sessionId: gwNoneSessionId,
      message: 'wtf',
      user: adminUser
    });
    assert.equal(wtfAfterGwNone.success, true);
    assert.ok(!wtfAfterGwNone.data.reply.includes('169.254.8.254'), 'Frustration repair must never fabricate 169.254.8.254');
    assert.ok(!wtfAfterGwNone.data.reply.includes('192.168.1.1'), 'Frustration repair must never fabricate 192.168.1.1');

    // Collector Unavailable state
    chatOperatorService.gatewayCollectorFn = () => ({
      verified: false,
      status: 'COLLECTOR_UNAVAILABLE',
      gatewayIp: null,
      interfaceName: null,
      family: null,
      collectionMethod: 'ip route',
      isContainer: true,
      environmentScope: 'server_container_runtime',
      limitationReason: 'Routing table collector command failed.'
    });
    const gwCollectorUnavailTurn = await chatOperatorService.processMessage({
      sessionId: `TEST-FALCON-GW-UNAVAIL-${Date.now()}`,
      message: 'check my gateway',
      user: adminUser
    });
    chatOperatorService.gatewayCollectorFn = null;
    assert.equal(gwCollectorUnavailTurn.success, true);
    assert.equal(gwCollectorUnavailTurn.data.intent, 'gateway_check');
    assert.ok(gwCollectorUnavailTurn.data.reply.toLowerCase().includes('collector is unavailable'), 'Must distinguish COLLECTOR_UNAVAILABLE from NO_DEFAULT_ROUTE_OBSERVED');

    // D. Layer-by-Layer Gateway & ISP Connection Diagnostic (Never asks for a hostname)
    const layerByLayerTurn = await chatOperatorService.processMessage({
      sessionId: 'TEST-FALCON-LOCAL-PATH',
      message: 'check layer by layer my connection to gateway and ISP',
      user: adminUser
    });
    assert.equal(layerByLayerTurn.success, true);
    assert.equal(layerByLayerTurn.data.intent, 'local_path_diagnostic');
    assert.equal(layerByLayerTurn.data.steps.length, 5, 'Must execute 5-layer local-to-ISP diagnostic');
    assert.ok(!layerByLayerTurn.data.reply.includes('Which hostname, IP address, or URL'), 'Must never ask for a hostname on layer-by-layer local path check');
    assert.ok(layerByLayerTurn.data.reply.includes('Layer 1') && layerByLayerTurn.data.reply.includes('Layer 3') && layerByLayerTurn.data.reply.includes('Layer 7'));

    // E. Identity & Account Username Separation
    const idSessionId = `TEST-FALCON-IDENTITY-SEPARATION-${Date.now()}`;
    const whoAmITurn1 = await chatOperatorService.processMessage({
      sessionId: idSessionId,
      message: 'who am i?',
      user: adminUser
    });
    assert.equal(whoAmITurn1.success, true);
    assert.ok(whoAmITurn1.data.reply.includes('admin'), 'Must mention authenticated account username admin');
    assert.ok(!whoAmITurn1.data.reply.toLowerCase().includes('your name is admin'), 'Must never claim account username admin is personal name');
    assert.ok(whoAmITurn1.data.reply.toLowerCase().includes("haven't shared your personal"), 'Must state personal name has not been shared');

    const whatIsMyNameTurn1 = await chatOperatorService.processMessage({
      sessionId: idSessionId,
      message: 'what is my name?',
      user: adminUser
    });
    assert.equal(whatIsMyNameTurn1.success, true);
    assert.ok(!whatIsMyNameTurn1.data.reply.toLowerCase().includes('your name is admin'), 'Must never say Your name is admin');

    const iAmEldarTurn = await chatOperatorService.processMessage({
      sessionId: idSessionId,
      message: 'I am Eldar',
      user: adminUser
    });
    assert.equal(iAmEldarTurn.success, true);
    assert.ok(iAmEldarTurn.data.reply.includes('Eldar'));

    const whatIsMyNameTurn2 = await chatOperatorService.processMessage({
      sessionId: idSessionId,
      message: 'what is my name?',
      user: adminUser
    });
    assert.equal(whatIsMyNameTurn2.success, true);
    assert.ok(whatIsMyNameTurn2.data.reply.includes('Eldar'), 'Must recall personal name Eldar');

    const myNameIsElvinTurn = await chatOperatorService.processMessage({
      sessionId: idSessionId,
      message: 'my name is Elvin',
      user: adminUser
    });
    assert.equal(myNameIsElvinTurn.success, true);
    assert.ok(myNameIsElvinTurn.data.reply.includes('Elvin'), 'Must update personal name to Elvin');

    const whatIsMyNameTurn3 = await chatOperatorService.processMessage({
      sessionId: idSessionId,
      message: 'what is my name?',
      user: adminUser
    });
    assert.equal(whatIsMyNameTurn3.success, true);
    assert.ok(whatIsMyNameTurn3.data.reply.includes('Elvin'), 'Must recall updated personal name Elvin');

    // F. Mocked & Real Model Invocation via AIModelOrchestrator.invokeModelProvider
    resetSemanticInterpreterMetrics();
    const originalInvoke = aiModelOrchestrator.invokeModelProvider;
    try {
      // 1. Test novel phrasing routed through mocked provider hook and verified in mockModelInvocationsCount
      aiModelOrchestrator.invokeModelProvider = async () => ({
        liveResponse: true,
        isMock: true,
        provider: 'MOCK_PROVIDER',
        text: JSON.stringify({
          intent: 'port_check',
          target: '127.0.0.1',
          ports: [3000],
          clarificationPrompt: null,
          naturalReply: null
        })
      });

      const novelTurn = await chatOperatorService.processMessage({
        sessionId: 'TEST-FALCON-MODEL-MOCK',
        message: 'Could you please see if local service 3000 is accepting traffic right now',
        user: adminUser
      });
      assert.equal(novelTurn.success, true);
      assert.equal(novelTurn.data.intent, 'port_check');
      assert.equal(novelTurn.data.target, '127.0.0.1');
      assert.deepEqual(novelTurn.data.ports, [3000]);

      const metricsAfterMock = getSemanticInterpreterMetrics();
      assert.equal(metricsAfterMock.modelInvocationsAttempted, 1);
      assert.equal(metricsAfterMock.mockModelInvocationsCount, 1, 'Must record mock model invocation separately from live model');
      assert.equal(metricsAfterMock.realModelInvocationsSucceeded, 0, 'Must not count mock invocation as real live model');

      // 2. Test provider failure safety: when model is unavailable on an ambiguous message, never invent a target or launch probes
      aiModelOrchestrator.invokeModelProvider = async () => ({
        liveResponse: false,
        status: 'OFFLINE',
        reason: 'ECONNREFUSED'
      });

      const offlineTurn = await chatOperatorService.processMessage({
        sessionId: 'TEST-FALCON-MODEL-OFFLINE',
        message: 'Check if the remote box is alive',
        user: adminUser
      });
      assert.equal(offlineTurn.success, true);
      assert.equal(offlineTurn.data.steps.length, 0, 'When model is offline and target is missing, must execute 0 probes');
      assert.equal(offlineTurn.data.target, null, 'Must never invent localhost or arbitrary target on model failure');
    } finally {
      delete aiModelOrchestrator.invokeModelProvider;
      if (originalInvoke && Object.prototype.hasOwnProperty.call(aiModelOrchestrator, 'invokeModelProvider')) {
        aiModelOrchestrator.invokeModelProvider = originalInvoke;
      }
    }

    // 3. Live Gemini Provider Verification (when GEMINI_API_KEY is configured in environment)
    if (process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY.trim()) {
      resetSemanticInterpreterMetrics();
      const prevPolicy = aiModelOrchestrator.localOnlyPolicy;
      aiModelOrchestrator.localOnlyPolicy = false;
      try {
        const livePlan = await semanticAiInterpreter(
          'Could you explain in two sentences how BGP route flapping affects internet routing tables?',
          {
            forceModelInterpretation: true,
            allowCloudFallback: true
          }
        );
        const liveMetrics = getSemanticInterpreterMetrics();
        assert.equal(liveMetrics.modelInvocationsAttempted, 1, 'Must attempt 1 live model invocation');
        assert.equal(liveMetrics.realModelInvocationsSucceeded, 1, 'Must succeed with 1 real live model invocation');
        assert.equal(liveMetrics.mockModelInvocationsCount, 0, 'Must record 0 mock invocations for live provider');
        assert.ok(livePlan && livePlan.modelInterpreted === true, 'Must return validated model-interpreted plan');
        assert.equal(livePlan.isMockModel, false, 'Live model invocation must have isMockModel: false');
      } finally {
        aiModelOrchestrator.localOnlyPolicy = prevPolicy;
      }
    }
  });
});


