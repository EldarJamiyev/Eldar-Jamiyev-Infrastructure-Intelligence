/**
 * EJII CEO Directive — Major Product & Innovation Leap Verification Suite
 *
 * Verifies:
 *   1. Terminal Startup Log & Multi-Port Readiness Mismatch Triage (SYNTRA 3000 vs 3001 + {"error":"Route not found."})
 *   2. Persistent Cross-Session Operational Memory, Baseline RTT Comparison & State Transition Detection (OPEN -> CLOSED)
 *   3. Episodic Incident Resolution & Playbook Recall (/api/v6/memory/overview & /api/v6/memory/resolutions + RBAC enforcement)
 *   4. Information-Gain Grounded Contextual Follow-Up Generation (suggestedFollowUps)
 */

'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');

const { chatOperatorService } = require('../src/core/chat/chat-operator-service');
const { operationalMemoryEngine } = require('../src/core/memory/operational-memory-engine');
const v6Router = require('../src/api/routes-v6-fabric');
const { generateToken } = require('../src/core/security');

describe('EJII CEO Directive — AI Intelligence, Operational Memory & Startup Log Triage Suite', () => {
  let server;
  let baseUrl;
  let adminToken;
  let readonlyToken;

  before(async () => {
    const app = express();
    app.use(express.json());
    app.use('/api/v6', v6Router);

    await new Promise((resolve) => {
      server = http.createServer(app);
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    adminToken = generateToken({ id: 'u-ceo-admin', username: 'admin', role: 'ADMIN' });
    readonlyToken = generateToken({ id: 'u-ceo-viewer', username: 'viewer', role: 'READONLY' });
  });

  after(async () => {
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it('1. Parses and diagnoses SYNTRA terminal startup log (port 3000 readiness failure vs port 3001 backend listener + Route not found)', async () => {
    const syntraLog = [
      'SYNTRA - one-click local startup',
      'Project: C:\\Users\\eldar\\OneDrive\\Documenti\\GitHub\\SYNTRA',
      '',
      '==> Checking prerequisites',
      'Node.js: v24.16.0',
      'Installed local model(s): qwen2.5-coder:14b',
      '',
      '==> Starting the local services',
      'Starting server ...',
      'Ready: server',
      'Starting dev ...',
      '',
      'SYNTRA could not start: Service did not become ready at http://127.0.0.1:3000/. Check its open service window for the actual error.',
      'PS C:\\Users\\eldar\\OneDrive\\Documenti\\GitHub\\SYNTRA>',
      '',
      '{"error":"Route not found."}',
      '',
      '> syntra@0.1.0 server',
      '> node local/server.mjs',
      '',
      'SYNTRA local workspace service listening on http://127.0.0.1:3001'
    ].join('\n');

    const parsedLog = operationalMemoryEngine.parseTerminalStartupLog(syntraLog);
    assert.equal(parsedLog.isStartupOrTerminalLog, true, 'Must recognize SYNTRA terminal log');
    assert.equal(parsedLog.projectName, 'SYNTRA');
    assert.equal(parsedLog.serviceCommand, 'node local/server.mjs');
    assert.ok(parsedLog.detectedPatterns.includes('PORT_SPLIT_READINESS_MISMATCH'), 'Must detect port 3000 vs 3001 split');
    assert.ok(parsedLog.detectedPatterns.includes('HTTP_ROUTE_NOT_FOUND_ON_HEALTH_PROBE'), 'Must detect Route not found on /');

    const outcome = await chatOperatorService.processMessage({
      sessionId: 'TEST-CEO-SYNTRA-LOG-' + Date.now(),
      message: syntraLog,
      user: { id: 'u-ceo-admin', username: 'admin', role: 'ADMIN' }
    });

    assert.equal(outcome.success, true);
    assert.equal(outcome.data.intent, 'log_and_startup_triage');
    assert.ok(outcome.data.steps.length >= 3, 'Must execute log parser + live probes on both extracted ports');
    assert.match(outcome.data.reply, /3000/);
    assert.match(outcome.data.reply, /3001/);
    assert.match(outcome.data.reply, /Route not found/i);
    assert.ok(Array.isArray(outcome.data.suggestedFollowUps) && outcome.data.suggestedFollowUps.length >= 2);
  });

  it('2. Tracks cross-session entity baselines and detects OPEN -> CLOSED state transitions in OperationalMemoryEngine', () => {
    const testTarget = `memory-test-${Date.now()}.example.com`;

    // Observation 1: Port 3000 is OPEN with 4.0ms RTT
    const obs1 = operationalMemoryEngine.recordObservation({
      target: testTarget,
      intent: 'port_check',
      status: 'PASS',
      resolvedIps: ['93.184.216.34'],
      openPorts: [3000],
      closedPorts: [],
      latencyMs: 4.0,
      summary: 'Port 3000 OPEN'
    });
    assert.ok(obs1);
    assert.equal(obs1.observationCount, 1);
    assert.deepEqual(obs1.knownOpenPorts, [3000]);
    assert.equal(obs1.stateTransitions.length, 0);

    // Observation 2: Port 3000 transitions to CLOSED
    const obs2 = operationalMemoryEngine.recordObservation({
      target: testTarget,
      intent: 'port_check',
      status: 'FAIL',
      resolvedIps: ['93.184.216.34'],
      openPorts: [],
      closedPorts: [3000],
      latencyMs: 5.0,
      failureLayer: 'L4 TCP Port 3000 Refused',
      summary: 'Port 3000 CLOSED'
    });
    assert.ok(obs2);
    assert.equal(obs2.observationCount, 2);
    assert.equal(obs2.failureCount, 1);
    assert.ok(
      obs2.stateTransitions.some((t) => t.type === 'PORT_REGRESSION_OPEN_TO_CLOSED' && t.port === 3000),
      'Must detect OPEN -> CLOSED port transition'
    );
    assert.ok(obs2.baselineDelta, 'Must compute baseline RTT delta');
  });

  it('3. Persists and recalls verified incident resolutions via /api/v6/memory/resolutions and /api/v6/memory/overview with RBAC', async () => {
    // READONLY viewer must be denied (403) when attempting to record a resolution
    const deniedRes = await fetch(`${baseUrl}/api/v6/memory/resolutions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${readonlyToken}`
      },
      body: JSON.stringify({
        target: '127.0.0.1',
        symptomSignature: 'PORT_SPLIT_3000_3001',
        rootCause: 'Frontend dev server not running on 3000 while backend bound to 3001',
        resolutionSteps: 'Start Vite dev server on 3000 and add GET /health on 3001'
      })
    });
    assert.equal(deniedRes.status, 403);

    // ADMIN records verified resolution
    const createRes = await fetch(`${baseUrl}/api/v6/memory/resolutions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`
      },
      body: JSON.stringify({
        target: '127.0.0.1',
        port: 3001,
        symptomSignature: 'PORT_SPLIT_3000_3001',
        rootCause: 'Frontend dev server not running on 3000 while backend bound to 3001',
        resolutionSteps: 'Start Vite dev server on 3000 and add GET /health on 3001'
      })
    });
    assert.equal(createRes.status, 200);
    const createBody = await createRes.json();
    assert.equal(createBody.success, true);
    assert.ok(createBody.data.resolutionId.startsWith('RES-'));

    // Overview endpoint returns both entities and verified resolutions
    const overviewRes = await fetch(`${baseUrl}/api/v6/memory/overview?limit=10`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.equal(overviewRes.status, 200);
    const overviewBody = await overviewRes.json();
    assert.equal(overviewBody.success, true);
    assert.ok(Array.isArray(overviewBody.data.entities));
    assert.ok(
      overviewBody.data.resolutions.some((r) => r.symptomSignature === 'PORT_SPLIT_3000_3001'),
      'Overview must include the newly recorded verified resolution'
    );
  });

  it('4. Computes EWMA, Z-score latency spikes, Stability Score, and auto-syncs into TemporalInfrastructureGraph', () => {
    const { temporalInfrastructureGraph } = require('../src/core/topology/temporal-graph-engine');
    const target = `ewma-sync-${Date.now()}.internal`;

    // Record 4 stable low-latency observations (~4ms)
    for (const rtt of [4.0, 4.2, 3.9, 4.1]) {
      operationalMemoryEngine.recordObservation({
        target,
        intent: 'port_check',
        status: 'PASS',
        resolvedIps: ['10.20.30.40'],
        openPorts: [443],
        closedPorts: [],
        latencyMs: rtt,
        summary: `Port 443 OPEN (${rtt} ms)`
      });
    }

    // Record 5th observation with a sharp latency spike (45ms)
    const spikeObs = operationalMemoryEngine.recordObservation({
      target,
      intent: 'port_check',
      status: 'PASS',
      resolvedIps: ['10.20.30.40'],
      openPorts: [443],
      closedPorts: [],
      latencyMs: 45.0,
      summary: 'Port 443 OPEN (45 ms spike)'
    });

    assert.ok(spikeObs);
    assert.equal(spikeObs.observationCount, 5);
    assert.equal(typeof spikeObs.stabilityScore, 'number');
    assert.ok(spikeObs.stabilityScore > 0 && spikeObs.stabilityScore <= 100);
    assert.ok(spikeObs.baselineDelta.zScore > 2.5, 'Must compute statistical Z-score > 2.5 on latency spike');
    assert.ok(
      spikeObs.stateTransitions.some((t) => t.type === 'LATENCY_SPIKE_DETECTED'),
      'Must emit LATENCY_SPIKE_DETECTED transition'
    );

    // Verify automatic synchronization into TemporalInfrastructureGraph
    const graphState = temporalInfrastructureGraph.getGraphState();
    const syncedHostNode = graphState.nodes.find((n) =>
      String(n.nodeId || n.id || '').includes(target.replace(/[^a-z0-9.-]/gi, '_')) ||
      String(n.hostname || n.label || '').includes(target)
    );
    assert.ok(syncedHostNode, 'Must auto-register observed host node in TemporalInfrastructureGraph');
    assert.ok(
      spikeObs.dependencyContext && Array.isArray(spikeObs.dependencyContext.downstreamDependents),
      'Must populate topological dependencyContext on memory insights'
    );
  });

  it('5. Records operational decisions and serves GET /api/v6/memory/intelligence-briefing and POST /api/v6/memory/decisions', async () => {
    // READONLY role denied on POST /api/v6/memory/decisions
    const deniedDecision = await fetch(`${baseUrl}/api/v6/memory/decisions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${readonlyToken}`
      },
      body: JSON.stringify({
        target: '127.0.0.1',
        actionId: 'verify_and_refresh_dns_resolution',
        rationale: 'Test RBAC enforcement'
      })
    });
    assert.equal(deniedDecision.status, 403);

    // ADMIN records decision
    const createDecision = await fetch(`${baseUrl}/api/v6/memory/decisions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`
      },
      body: JSON.stringify({
        target: '127.0.0.1',
        decisionType: 'GOVERNED_REMEDIATION',
        actionId: 'verify_and_refresh_dns_resolution',
        rationale: 'Approved DNS cache refresh and postcondition verification',
        outcomeStatus: 'APPLIED_AND_VERIFIED',
        beforeMetrics: { dnsRttMs: 14.2 },
        afterMetrics: { dnsRttMs: 1.8 }
      })
    });
    assert.equal(createDecision.status, 200);
    const decBody = await createDecision.json();
    assert.equal(decBody.success, true);
    assert.ok(decBody.data.decisionId.startsWith('DEC-'));

    // GET /api/v6/memory/intelligence-briefing returns synthesized fleet summary, regressions, risks, and decisions
    const briefingRes = await fetch(`${baseUrl}/api/v6/memory/intelligence-briefing`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.equal(briefingRes.status, 200);
    const briefingBody = await briefingRes.json();
    assert.equal(briefingBody.success, true);
    assert.ok(briefingBody.data.fleetSummary);
    assert.ok(briefingBody.data.fleetSummary.totalTrackedEntities >= 2);
    assert.ok(Array.isArray(briefingBody.data.activeRegressions));
    assert.ok(Array.isArray(briefingBody.data.predictiveRisks));
    assert.ok(
      briefingBody.data.recentDecisions.some((d) => d.decisionId === decBody.data.decisionId),
      'Intelligence briefing must include the recorded operational decision'
    );
  });

  it('6. Executes natural-language infrastructure_intelligence_synthesis and dependency_blast_radius scenarios in ChatOperatorService', async () => {
    const sessionId = 'TEST-CEO-SYNTHESIS-' + Date.now();

    // 1) Operational Intelligence Briefing & Anomaly Synthesis
    const synthOut = await chatOperatorService.processMessage({
      sessionId,
      message: 'Give me an operational intelligence briefing on active regressions and learned playbooks',
      user: { id: 'u-ceo-admin', username: 'admin', role: 'ADMIN' }
    });
    assert.equal(synthOut.success, true);
    assert.equal(synthOut.data.intent, 'infrastructure_intelligence_synthesis');
    assert.match(synthOut.data.reply, /Operational Intelligence & Anomaly Briefing/);
    assert.ok(synthOut.data.findings.some((f) => f.label === 'Fleet Stability'));

    // 2) Topological Dependency & Blast Radius Analysis
    const blastOut = await chatOperatorService.processMessage({
      sessionId,
      message: 'What is the dependency impact and blast radius for localhost?',
      user: { id: 'u-ceo-admin', username: 'admin', role: 'ADMIN' }
    });
    assert.equal(blastOut.success, true);
    assert.equal(blastOut.data.intent, 'dependency_blast_radius');
    assert.match(blastOut.data.reply, /Topological Dependency & Blast-Radius Analysis/);
    assert.ok(blastOut.data.findings.some((f) => f.label === 'Downstream Impact'));
  });

  it('7. Computes Predictive SLA Breach Forecast and Flapping Oscillation Index (/api/v6/memory/forecast/:target)', async () => {
    const driftTarget = `sla-drift-${Date.now()}.internal`;
    // Simulate monotonic latency climb: 20ms, 50ms, 85ms, 120ms, 160ms
    for (const rtt of [20, 50, 85, 120, 160]) {
      operationalMemoryEngine.recordObservation({
        target: driftTarget,
        intent: 'port_check',
        status: 'PASS',
        resolvedIps: ['10.99.0.10'],
        openPorts: [443],
        latencyMs: rtt,
        summary: `Port 443 OPEN (${rtt} ms)`
      });
    }

    const forecast = operationalMemoryEngine.computePredictiveForecast(driftTarget, 250);
    assert.ok(forecast, 'Must return forecast object');
    assert.equal(forecast.riskClassification, 'IMMINENT_SLA_LATENCY_BREACH');
    assert.ok(forecast.rttVelocityMsPerCheck > 20, 'Must detect strong positive RTT velocity');
    assert.ok(
      typeof forecast.estimatedObservationsToSlaBreach === 'number' &&
        forecast.estimatedObservationsToSlaBreach >= 1 &&
        forecast.estimatedObservationsToSlaBreach <= 10,
      'Must estimate observations until 250ms SLA threshold breach'
    );

    const apiRes = await fetch(`${baseUrl}/api/v6/memory/forecast/${encodeURIComponent(driftTarget)}?slaMs=250`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.equal(apiRes.status, 200);
    const apiBody = await apiRes.json();
    assert.equal(apiBody.success, true);
    assert.equal(apiBody.data.forecast.riskClassification, 'IMMINENT_SLA_LATENCY_BREACH');
  });

  it('8. Evaluates Closed-Loop Remediation Efficacy and warns against repeating rolled-back actions (/api/v6/memory/efficacy)', async () => {
    const remTarget = `rem-target-${Date.now()}.internal`;

    // Record a rolled-back decision on remTarget
    operationalMemoryEngine.recordOperationalDecision({
      target: remTarget,
      decisionType: 'GOVERNED_REMEDIATION',
      actionId: 'inspect_service_listener_and_socket_binding',
      rationale: 'Attempted daemon restart on port 3000',
      outcomeStatus: 'ROLLED_BACK',
      beforeMetrics: { liveTcpRttMs: null },
      afterMetrics: { liveTcpRttMs: null }
    });

    const recommendation = operationalMemoryEngine.recommendRemediationWithHistory({
      target: remTarget,
      failureLayer: 'L4_TCP_CLOSED',
      port: 3000
    });
    assert.ok(recommendation);
    assert.equal(recommendation.recommendedActionId, 'inspect_service_listener_and_socket_binding');
    assert.ok(
      recommendation.warningPriorFailure && recommendation.warningPriorFailure.includes('previously failed postcondition verification'),
      'Must warn operator when recommended action previously failed/rolled back on the target'
    );

    const effRes = await fetch(`${baseUrl}/api/v6/memory/efficacy`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.equal(effRes.status, 200);
    const effBody = await effRes.json();
    assert.equal(effBody.success, true);
    assert.equal(typeof effBody.data.overallEfficacyPct, 'number');
    assert.ok(Array.isArray(effBody.data.actions));
  });

  it('9. Disambiguates Primary Root Cause from Downstream Symptoms and detects Cross-Layer Contradictions in evaluateDiagnosticHypotheses', () => {
    // Case A: ICMP echo fails (timeout), but TCP 443 is OPEN -> ICMP_BLOCKED_BUT_TCP_OPEN contradiction
    const evalIcmpFiltered = operationalMemoryEngine.evaluateDiagnosticHypotheses({
      target: 'api.example.com',
      port: 443,
      dnsStep: { status: 'PASS', summary: 'Resolved api.example.com -> 93.184.216.34' },
      icmpStep: { status: 'FAIL', summary: '0/2 ICMP replies (100% packet loss)' },
      tcpStep: { status: 'PASS', details: { status: 'OPEN' }, summary: 'TCP port 443 OPEN (12 ms)' },
      httpStep: { status: 'PASS', summary: 'HTTP 200 OK' }
    });
    assert.ok(
      evalIcmpFiltered.contradictions.some((c) => c.type === 'ICMP_BLOCKED_BUT_TCP_OPEN'),
      'Must detect ICMP_BLOCKED_BUT_TCP_OPEN when ping fails but TCP succeeds'
    );
    assert.equal(evalIcmpFiltered.primaryRootCause.layer, 'None (All Probed Layers Healthy)');

    // Case B: Port 3000 is CLOSED while alternate port 3001 is OPEN -> SELECTIVE_PORT_REFUSAL & Root Cause vs Symptom separation
    const evalPortRefused = operationalMemoryEngine.evaluateDiagnosticHypotheses({
      target: '127.0.0.1',
      port: 3000,
      dnsStep: { status: 'PASS', summary: 'Loopback 127.0.0.1' },
      icmpStep: { status: 'PASS', summary: '2/2 ICMP replies (0.4 ms)' },
      tcpStep: { status: 'FAIL', details: { status: 'CLOSED' }, summary: 'TCP port 3000 CLOSED (ECONNREFUSED)' },
      extraPortResults: [{ port: 3001, status: 'OPEN', latencyMs: 0.8 }]
    });
    assert.equal(evalPortRefused.primaryRootCause.hypothesisId, 'H3_L4_TCP_LISTENER');
    assert.match(evalPortRefused.primaryRootCause.summary, /alternate TCP port 3001 on the same host is OPEN/);
    assert.ok(evalPortRefused.downstreamSymptoms.length >= 1, 'Must separate downstream symptoms from primary root cause');
    assert.ok(
      evalPortRefused.contradictions.some((c) => c.type === 'SELECTIVE_PORT_REFUSAL'),
      'Must detect SELECTIVE_PORT_REFUSAL when primary port is closed and secondary port is open'
    );
    assert.ok(typeof evalPortRefused.primaryRootCause.posteriorProbabilityPct === 'number', 'Must compute calibrated posterior probability percentage');
    assert.equal(evalPortRefused.primaryRootCause.causalRole, 'PRIMARY_ROOT_CAUSE');
    assert.ok(evalPortRefused.nextBestInvestigation && evalPortRefused.nextBestInvestigation.expectedInformationGainBits > 0, 'Must recommend highest information-gain next investigation');
  });

  it('13. compiles the 10-Stage Unified Operational Journey continuum end-to-end and serves GET /api/v6/intelligence/journey/:target', async () => {
    const target = 'unified-journey-node.internal';
    operationalMemoryEngine.recordObservation({
      target,
      intent: 'investigate_failure',
      status: 'FAIL',
      resolvedIps: ['10.88.0.15'],
      openPorts: [],
      closedPorts: [443],
      rttMs: 42.5,
      failureLayer: 'L4 TCP Port 443',
      summary: 'TCP port 443 connection refused on unified-journey-node.internal'
    });

    const journey = operationalMemoryEngine.compileUnifiedOperationalJourney({
      target,
      port: 443
    });

    assert.equal(journey.target, target);
    assert.equal(journey.stageCount, 10, 'Unified Operational Journey must contain all 10 stages');
    const stageIds = journey.stages.map((s) => s.stageId);
    assert.deepEqual(stageIds, [
      'OBSERVATION',
      'INVESTIGATION',
      'HYPOTHESES',
      'EVIDENCE',
      'ROOT_CAUSE',
      'INFRASTRUCTURE_IMPACT',
      'PREDICTION',
      'RECOMMENDED_ACTION',
      'GOVERNED_EXECUTION',
      'OUTCOME_LEARNING'
    ]);

    const res = await fetch(`${baseUrl}/api/v6/intelligence/journey/${encodeURIComponent(target)}?port=443`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.equal(body.data.stageCount, 10);
  });

  it('14. synthesizes the 7-Question Fleet Intelligence Matrix and Adaptive Closed-Loop Remediation Pivoting', async () => {
    const pivotTarget = 'adaptive-pivot-test.internal';
    // Record a failed / rolled-back primary remediation action on pivotTarget
    operationalMemoryEngine.recordOperationalDecision({
      target: pivotTarget,
      decisionType: 'GOVERNED_SELF_HEALING',
      actionId: 'inspect_service_listener_and_socket_binding',
      rationale: 'Attempted TCP listener inspection and restart',
      approvedBy: 'admin',
      role: 'ADMIN',
      outcomeStatus: 'ROLLED_BACK_ON_VERIFICATION_FAILURE',
      beforeMetrics: { rttMs: 120 },
      afterMetrics: { rttMs: 125 }
    });

    const rem = operationalMemoryEngine.recommendRemediationWithHistory({
      target: pivotTarget,
      failureLayer: 'L4 TCP Port 443',
      symptomSignature: 'TCP_PORT_443_CLOSED'
    });

    assert.equal(rem.recommendedActionId, 'inspect_service_listener_and_socket_binding');
    assert.ok(rem.previouslyFailedActions.includes('inspect_service_listener_and_socket_binding'));
    assert.equal(rem.adaptiveAlternativeActionId, 'verify_gateway_and_route_table', 'Must pivot to adaptive alternative action when primary action previously rolled back');
    assert.equal(rem.effectiveRecommendedActionId, 'verify_gateway_and_route_table');
    assert.match(rem.adaptivePivotRationale, /because 'inspect_service_listener_and_socket_binding' previously failed/i);

    const matrix = operationalMemoryEngine.getFleetIntelligenceMatrix();
    assert.ok(Array.isArray(matrix.whatIsDegrading), 'Must include whatIsDegrading array');
    assert.ok(Array.isArray(matrix.sharedDependencyRisks), 'Must include sharedDependencyRisks array');
    assert.ok(Array.isArray(matrix.whatChangedBeforeFailure), 'Must include whatChangedBeforeFailure array');
    assert.ok(Array.isArray(matrix.servicesAtRiskNext), 'Must include servicesAtRiskNext array');
    assert.ok(Array.isArray(matrix.similarHistoricalIncidents), 'Must include similarHistoricalIncidents array');
    assert.ok(Array.isArray(matrix.strongestEvidenceFindings), 'Must include strongestEvidenceFindings array');
    assert.ok(matrix.highestPriorityInvestigation, 'Must identify highestPriorityInvestigation across fleet');
    assert.ok(typeof matrix.highestPriorityInvestigation.priorityScore === 'number');

    const matrixRes = await fetch(`${baseUrl}/api/v6/intelligence/fleet-matrix`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.equal(matrixRes.status, 200);
    const matrixBody = await matrixRes.json();
    assert.equal(matrixBody.success, true);
    assert.ok(Array.isArray(matrixBody.data.whatIsDegrading));
  });

  it('15. Operational Environment Profiling, Knowledge Freshness Decay & Multi-Target Correlated Incidents', async () => {
    const profileDns = operationalMemoryEngine.inferOperationalEnvironmentProfile('1.1.1.1');
    assert.equal(profileDns.role, 'SHARED_INFRASTRUCTURE_COMPONENT');
    assert.equal(profileDns.criticalityTier, 'TIER_0_MISSION_CRITICAL');
    assert.ok(profileDns.ownership.team.includes('Core Network'));

    const profileCore = operationalMemoryEngine.inferOperationalEnvironmentProfile('127.0.0.1');
    assert.equal(profileCore.role, 'CORE_APPLICATION_SERVICE');
    assert.equal(profileCore.criticalityTier, 'TIER_0_MISSION_CRITICAL');

    // Record observations and a subsequent change to verify INVALIDATED_BY_CHANGE knowledge freshness
    const freshnessTarget = 'freshness-verify.example.com';
    operationalMemoryEngine.recordObservation({
      target: freshnessTarget,
      intent: 'website_check',
      resolvedIps: ['93.184.216.34'],
      openPorts: [443],
      closedPorts: [],
      tcpRttMs: 18.2,
      status: 'PASS',
      summary: 'Nominal check'
    });

    const freshCheck = operationalMemoryEngine.computeKnowledgeFreshnessAndDecay(freshnessTarget, []);
    assert.equal(freshCheck.freshnessState, 'FRESH');
    assert.equal(freshCheck.invalidatedByChange, false);

    // Wait 5ms and record a post-observation decision to invalidate prior observation
    await new Promise((r) => setTimeout(r, 5));
    operationalMemoryEngine.recordOperationalDecision({
      target: freshnessTarget,
      decisionType: 'GOVERNED_SELF_HEALING',
      actionId: 'verify_and_refresh_dns_resolution',
      rationale: 'Refreshed DNS after config update',
      approvedBy: 'admin',
      role: 'ADMIN',
      outcomeStatus: 'APPLIED_AND_VERIFIED'
    });

    const invalidatedCheck = operationalMemoryEngine.computeKnowledgeFreshnessAndDecay(freshnessTarget);
    assert.equal(invalidatedCheck.freshnessState, 'INVALIDATED_BY_CHANGE');
    assert.equal(invalidatedCheck.invalidatedByChange, true);
    assert.equal(invalidatedCheck.requiresReverification, true);

    // Correlate incidents across fleet and verify executive situation summary
    const corr = operationalMemoryEngine.correlateOperationalIncidents();
    assert.ok(corr.executiveSituationSummary, 'Must return executiveSituationSummary');
    assert.ok(typeof corr.executiveSituationSummary.whatIsHappening === 'string');
    assert.ok(typeof corr.executiveSituationSummary.mostImportantToAddress === 'string');
    assert.ok(Array.isArray(corr.correlatedIncidents));
    assert.ok(Array.isArray(corr.environmentProfiles));

    // Verify REST API endpoints for Command Center Overview & Incidents
    const ccRes = await fetch(`${baseUrl}/api/v6/command-center/overview?target=127.0.0.1&port=3000`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.equal(ccRes.status, 200);
    const ccBody = await ccRes.json();
    assert.equal(ccBody.success, true);
    assert.ok(ccBody.data.executiveSituationSummary);
    assert.ok(ccBody.data.operationsCommander);
    assert.ok(ccBody.data.remediationComparison);
    assert.ok(ccBody.data.defaultScenarioPreview);
    assert.equal(ccBody.data.defaultScenarioPreview.isSimulated, true);

    const incRes = await fetch(`${baseUrl}/api/v6/command-center/incidents`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.equal(incRes.status, 200);
    const incBody = await incRes.json();
    assert.equal(incBody.success, true);
    assert.ok(Array.isArray(incBody.data.correlatedIncidents));
  });

  it('16. AI Operations Commander Cross-Workspace Coordination & Duplicate Probe Avoidance', async () => {
    const coordTarget = 'commander-sync.example.com';
    const firstCoord = operationalMemoryEngine.coordinateOperationsCommander({
      target: coordTarget,
      port: 443,
      workspace: 'chat-workspace',
      intent: 'multi_step_investigation',
      status: 'ACTIVE',
      summary: 'Initial cross-layer check from Chat Workspace'
    });
    assert.equal(firstCoord.deduplicatedProbe, false);
    assert.ok(firstCoord.coordinatedInvestigation.workspaces.includes('chat-workspace'));

    // Second coordination within 45s freshness window with same intent + port must be deduplicated
    const secondCoord = operationalMemoryEngine.coordinateOperationsCommander({
      target: coordTarget,
      port: 443,
      workspace: 'ai-operator',
      intent: 'multi_step_investigation',
      status: 'DEGRADED',
      summary: 'Follow-up check from AI Operator'
    });
    assert.equal(secondCoord.deduplicatedProbe, true, 'Must detect and avoid duplicate probe within 45s freshness window');
    assert.ok(secondCoord.avoidedDuplicateProbesCount >= 1);
    assert.ok(secondCoord.coordinatedInvestigation.workspaces.includes('ai-operator'));
    assert.equal(secondCoord.coordinatedInvestigation.escalationRequired, true);

    const apiCoordRes = await fetch(`${baseUrl}/api/v6/command-center/coordinate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`
      },
      body: JSON.stringify({
        target: coordTarget,
        port: 443,
        workspace: 'core-diagnostics',
        intent: 'port_check',
        status: 'ACTIVE'
      })
    });
    assert.equal(apiCoordRes.status, 200);
    const apiCoordBody = await apiCoordRes.json();
    assert.equal(apiCoordBody.success, true);
    assert.ok(apiCoordBody.data.coordinatedInvestigation.workspaces.includes('core-diagnostics'));
  });

  it('17. Interactive What-If Scenario Simulator, Multi-Option Adaptive Remediation Comparator & Natural-Language Chat Integration', async () => {
    const sim = operationalMemoryEngine.simulateOperationalScenario({
      target: '127.0.0.1',
      scenarioType: 'GATEWAY_OR_DEPENDENCY_UNAVAILABLE',
      port: 3000
    });
    assert.equal(sim.isSimulated, true);
    assert.equal(sim.telemetryClassification, 'SIMULATED_SCENARIO_NOT_LIVE_TELEMETRY');
    assert.match(sim.simulationBadge, /SIMULATED SCENARIO/i);
    assert.ok(sim.questionsAnswered.whatHappensIfUnavailable.answer.length > 10);
    assert.ok(sim.questionsAnswered.whichServicesAffected.answer.length > 10);
    assert.ok(sim.questionsAnswered.impactOfConfigurationChange.answer.length > 10);
    assert.ok(sim.questionsAnswered.whichRemediationHasLowestRisk.answer.length > 10);
    assert.ok(sim.questionsAnswered.whatCouldHappenIfRecommendedActionFails.answer.length > 10);
    assert.ok(sim.remediationComparison.options.length >= 4);
    assert.equal(sim.remediationComparison.options[0].rank, 1);

    // REST API test for scenario & remediation-options
    const simApiRes = await fetch(`${baseUrl}/api/v6/command-center/scenario`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`
      },
      body: JSON.stringify({
        target: '127.0.0.1',
        scenarioType: 'CONFIGURATION_OR_PORT_CHANGE',
        port: 3000
      })
    });
    assert.equal(simApiRes.status, 200);
    const simApiBody = await simApiRes.json();
    assert.equal(simApiBody.success, true);
    assert.equal(simApiBody.data.isSimulated, true);

    const remOptRes = await fetch(`${baseUrl}/api/v6/command-center/remediation-options/127.0.0.1?port=3000`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.equal(remOptRes.status, 200);
    const remOptBody = await remOptRes.json();
    assert.equal(remOptBody.success, true);
    assert.ok(remOptBody.data.lowestRiskOption);

    // Natural-language Chat Scenario Planning query
    const chatSimRes = await chatOperatorService.processMessage({
      sessionId: 'TEST-CMD-CENTER-SIM',
      message: 'What happens if this gateway becomes unavailable and which remediation option has the lowest operational risk?',
      user: { username: 'admin', role: 'ADMIN' }
    });
    assert.equal(chatSimRes.success, true);
    assert.equal(chatSimRes.data.intent, 'scenario_planning_what_if');
    assert.ok(chatSimRes.data.scenarioSimulation, 'Must attach scenarioSimulation to chat response');
    assert.equal(chatSimRes.data.scenarioSimulation.isSimulated, true);
    assert.match(chatSimRes.data.reply, /SIMULATED SCENARIO/i);

    // Natural-language Chat Executive Command Center Situation query
    const chatSitRes = await chatOperatorService.processMessage({
      sessionId: 'TEST-CMD-CENTER-SIM',
      message: 'What is actually happening across the infrastructure, and what is the most important thing we should address?',
      user: { username: 'admin', role: 'ADMIN' }
    });
    assert.equal(chatSitRes.success, true);
    assert.equal(chatSitRes.data.intent, 'infrastructure_intelligence_synthesis');
    assert.ok(chatSitRes.data.commandCenterOverview, 'Must attach commandCenterOverview to chat response');
    assert.match(chatSitRes.data.reply, /IT Operations Command Center/i);
  });

  it('18. Technical Debt Radar, Human Firewall Resilience, Honest IT Cost Intelligence & The Last Admin Knowledge Vault', async () => {
    const newEntry = operationalMemoryEngine.recordOrganizationalKnowledge({
      targetKey: '127.0.0.1',
      category: 'SERVICE_ARCHITECTURE_RUNBOOK',
      title: 'Critical Loopback Readiness & Socket Verification Runbook',
      criticalDependencyNote: 'Core control plane on :3000 coordinates with auxiliary local workspace services.',
      runbookProcedure: 'Inspect active kernel sockets before restarting listeners.',
      historicalRationale: 'Prevents blind restarts during port-split configuration drift.',
      owningTeam: 'Core Platform & Systems SRE',
      author: 'admin'
    });
    assert.ok(newEntry.knowledgeId.startsWith('ORG-KB-'));

    const kb = operationalMemoryEngine.getOrganizationalKnowledgeAndResilience();
    assert.ok(kb.knowledgeVaultCount >= 2);
    assert.ok(Array.isArray(kb.entries));
    assert.ok(kb.humanFirewallResilience);
    assert.equal(typeof kb.humanFirewallResilience.runbookCoveragePct, 'number');
    assert.match(kb.humanFirewallResilience.privacyGuarantee, /zero invasive individual employee surveillance/i);

    const radar = operationalMemoryEngine.computeTechnicalDebtAndResilienceRadar();
    assert.equal(radar.topWeaknesses.length, 5, 'Must rank top 5 infrastructure weaknesses');
    assert.equal(radar.topWeaknesses[0].rank, 1);
    assert.ok(radar.topWeaknesses[0].priorityScore >= radar.topWeaknesses[1].priorityScore);
    assert.ok(radar.resourceEfficiencyIntelligence);
    assert.match(radar.resourceEfficiencyIntelligence.honestyPolicy, /No fabricated cloud billing/i);

    const apiRadarRes = await fetch(`${baseUrl}/api/v6/command-center/technical-debt-radar`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.equal(apiRadarRes.status, 200);
    const apiRadarBody = await apiRadarRes.json();
    assert.equal(apiRadarBody.success, true);
    assert.equal(apiRadarBody.data.topWeaknesses.length, 5);

    const apiKbRes = await fetch(`${baseUrl}/api/v6/command-center/organizational-knowledge`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.equal(apiKbRes.status, 200);
    const apiKbBody = await apiKbRes.json();
    assert.equal(apiKbBody.success, true);
    assert.ok(apiKbBody.data.knowledgeVaultCount >= 2);
  });

  it('19. Incident DNA Structural Fingerprinting, Network Black Box Flight Recorder & Subnet/VLAN Change Simulator', async () => {
    const dna = operationalMemoryEngine.computeIncidentDnaAndSimilarities({
      target: '127.0.0.1',
      failureLayer: 'L4_TCP_PORT_CLOSED',
      port: 3000
    });
    assert.ok(dna.dnaFingerprintId.startsWith('DNA-'));
    assert.ok(dna.structuralGenes.protocolLayerGene);
    assert.equal(typeof dna.answerSummary, 'string');
    assert.ok(Array.isArray(dna.similarHistoricalMatches));

    const blackBox = operationalMemoryEngine.reconstructNetworkBlackBoxTimeline({ windowHours: 24 });
    assert.equal(typeof blackBox.whatChangedBeforeOutageSummary, 'string');
    assert.ok(Array.isArray(blackBox.chronologicalFlightLog));
    assert.ok(Array.isArray(blackBox.preFailureChanges));

    const vlanSim = operationalMemoryEngine.simulateOperationalScenario({
      target: '127.0.0.1',
      scenarioType: 'SUBNET_OR_VLAN_MIGRATION',
      port: 3000
    });
    assert.equal(vlanSim.isSimulated, true);
    assert.match(vlanSim.questionAnswered, /another VLAN/i);
    assert.ok(vlanSim.questionsAnswered.impactOfSubnetOrVlanMove.answer.length > 20);
    assert.ok(Array.isArray(vlanSim.relationshipProvenance));

    const apiDnaRes = await fetch(`${baseUrl}/api/v6/command-center/incident-dna?target=127.0.0.1&port=3000`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.equal(apiDnaRes.status, 200);
    const apiDnaBody = await apiDnaRes.json();
    assert.equal(apiDnaBody.success, true);
    assert.ok(apiDnaBody.data.dnaFingerprintId.startsWith('DNA-'));

    const apiBbRes = await fetch(`${baseUrl}/api/v6/command-center/black-box-timeline`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.equal(apiBbRes.status, 200);
    const apiBbBody = await apiBbRes.json();
    assert.equal(apiBbBody.success, true);
    assert.ok(Array.isArray(apiBbBody.data.chronologicalFlightLog));
  });

  it('20. Dynamic Epistemic Reasoning, Self-Correction Trace, Stopping Conditions & Natural-Language Executive Queries', async () => {
    const epistemic = operationalMemoryEngine.evaluateDynamicEpistemicReasoning({
      prompt: 'Investigate why 127.0.0.1:3009 is failing',
      intent: 'multi_step_investigation',
      target: '127.0.0.1',
      port: 3009,
      steps: [
        { id: 'dns', label: 'DNS Resolution', layer: 'L3_DNS', status: 'PASS', detail: 'Resolved 127.0.0.1 in 0.4ms' },
        { id: 'ping', label: 'ICMP Echo', layer: 'L3_ICMP', status: 'PASS', detail: '1/1 replies in 0.3ms' },
        { id: 'tcp', label: 'TCP Port 3009', layer: 'L4_TCP', status: 'FAIL', detail: 'ECONNREFUSED (CLOSED)' }
      ]
    });
    assert.ok(Array.isArray(epistemic.knownFacts));
    assert.ok(epistemic.knownFacts.length >= 3);
    assert.ok(Array.isArray(epistemic.unknownsAndAssumptions));
    assert.ok(Array.isArray(epistemic.selfCorrectionEvents));
    assert.ok(
      epistemic.selfCorrectionEvents.some((e) => e.correctionType === 'REFUTED_NETWORK_OUTAGE_ASSUMPTION'),
      'Must record epistemic self-correction when L3 succeeds and L4 TCP fails'
    );
    assert.ok(Array.isArray(epistemic.dynamicToolSelectionRationale));
    assert.ok(epistemic.stoppingCondition);
    assert.equal(typeof epistemic.stoppingCondition.whyStopOrContinue, 'string');

    // Test Natural-Language Technical Debt Radar query in Chat Workspace
    const chatDebtRes = await chatOperatorService.processMessage({
      sessionId: 'TEST-BREAKTHROUGH-CHAT',
      message: 'Which five infrastructure weaknesses should management address first?',
      user: { username: 'admin', role: 'ADMIN' }
    });
    assert.equal(chatDebtRes.success, true);
    assert.equal(chatDebtRes.data.intent, 'infrastructure_intelligence_synthesis');
    assert.ok(chatDebtRes.data.epistemicReasoning, 'Must attach epistemicReasoning to operational chat response');
    assert.match(chatDebtRes.data.reply, /Technical Debt Radar/i);

    // Test Natural-Language Incident DNA query in Chat Workspace
    const chatDnaRes = await chatOperatorService.processMessage({
      sessionId: 'TEST-BREAKTHROUGH-CHAT',
      message: 'Have we experienced this type of outage before, and what actually resolved it?',
      user: { username: 'admin', role: 'ADMIN' }
    });
    assert.equal(chatDnaRes.success, true);
    assert.match(chatDnaRes.data.reply, /Incident DNA/i);

    // Test Natural-Language Subnet/VLAN move query in Chat Workspace
    const chatVlanRes = await chatOperatorService.processMessage({
      sessionId: 'TEST-BREAKTHROUGH-CHAT',
      message: 'What happens if I move this subnet to another VLAN?',
      user: { username: 'admin', role: 'ADMIN' }
    });
    assert.equal(chatVlanRes.success, true);
    assert.equal(chatVlanRes.data.intent, 'scenario_planning_what_if');
    assert.equal(chatVlanRes.data.scenarioSimulation.scenarioType, 'SUBNET_OR_VLAN_MIGRATION');
  });

  it('21. AI Cognition 2.0 — Deep Situation Understanding, Problem Decomposition & 7-Tier Epistemic Reasoning', async () => {
    const decomp = operationalMemoryEngine.decomposeOperationalProblemAndPlan({
      problemStatement: 'Several employees suddenly cannot access the internal application',
      target: '127.0.0.1',
      port: 3000
    });
    assert.equal(decomp.problemScopeClassification, 'MULTI_USER_SHARED_SERVICE_OR_SEGMENT_IMPACT');
    assert.ok(Array.isArray(decomp.causalDomains));
    assert.ok(decomp.causalDomains.length >= 4);
    assert.ok(Array.isArray(decomp.adaptiveInvestigationDag));
    assert.ok(decomp.adaptiveInvestigationDag.length >= 4);

    const cog2 = operationalMemoryEngine.evaluateEpistemicCognition2({
      prompt: 'Several employees suddenly cannot access the internal application',
      intent: 'multi_step_investigation',
      target: '127.0.0.1',
      port: 3009,
      steps: [
        { id: 'dns', label: 'DNS Resolution', layer: 'L7_DNS', status: 'PASS', detail: 'Resolved 127.0.0.1' },
        { id: 'ping', label: 'ICMP Echo', layer: 'L3_ICMP', status: 'PASS', detail: '0.2ms RTT' },
        { id: 'tcp', label: 'TCP Port 3009', layer: 'L4_TCP', status: 'FAIL', detail: 'ECONNREFUSED (CLOSED)' }
      ]
    });
    assert.ok(cog2.epistemicSevenPillars, 'Must expose all 7 epistemic pillars');
    assert.ok(Array.isArray(cog2.epistemicSevenPillars.directlyObserved));
    assert.ok(Array.isArray(cog2.epistemicSevenPillars.learnedFromMemory));
    assert.ok(Array.isArray(cog2.epistemicSevenPillars.inferredRelationships));
    assert.ok(Array.isArray(cog2.epistemicSevenPillars.workingAssumptions));
    assert.ok(Array.isArray(cog2.epistemicSevenPillars.remainingUnknowns));
    assert.ok(Array.isArray(cog2.epistemicSevenPillars.activeContradictions));
    assert.ok(Array.isArray(cog2.epistemicSevenPillars.highestValueMissingInformation));
    assert.ok(cog2.intelligentStoppingDecision);
    assert.equal(typeof cog2.intelligentStoppingDecision.residualShannonEntropyBits, 'number');

    const apiDecompRes = await fetch(`${baseUrl}/api/v6/command-center/cognition-decompose`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`
      },
      body: JSON.stringify({
        problemStatement: 'Several employees suddenly cannot access the internal application',
        target: '127.0.0.1',
        port: 3000
      })
    });
    assert.equal(apiDecompRes.status, 200);
    const apiDecompBody = await apiDecompRes.json();
    assert.equal(apiDecompBody.success, true);
    assert.equal(apiDecompBody.data.problemScopeClassification, 'MULTI_USER_SHARED_SERVICE_OR_SEGMENT_IMPACT');
  });

  it('22. AI Cognition 2.0 — Multi-Stage Autonomous Goal Agent & Adaptive Port-Split Recovery', async () => {
    const goalRes = await operationalMemoryEngine.executeAutonomousGoalInvestigation({
      objective: 'Several employees suddenly cannot access the internal application',
      target: '127.0.0.1',
      port: 3099, // Closed port so agent exercises autonomous port-split recovery to :3000
      initiatedBy: 'admin',
      role: 'ADMIN'
    });
    assert.ok(goalRes.goalId.startsWith('GOAL-'));
    assert.equal(goalRes.completedStages.length, 4);
    assert.ok(goalRes.adaptivePivotLog.length >= 1, 'Agent must log an adaptive pivot when port 3099 is closed');
    assert.ok(goalRes.epistemicCognition);
    assert.ok(goalRes.remediationSuitability);

    const persistedGoals = operationalMemoryEngine.getAutonomousAgentGoals(5);
    assert.ok(persistedGoals.some((g) => g.goalId === goalRes.goalId));

    // Verify Chat Workspace integration for multi-employee access objective
    const chatGoalRes = await chatOperatorService.processMessage({
      sessionId: 'TEST-COGNITION-2-CHAT',
      message: 'Several employees suddenly cannot access the internal application',
      user: { username: 'admin', role: 'ADMIN' }
    });
    assert.equal(chatGoalRes.success, true);
    assert.ok(chatGoalRes.data.problemDecomposition, 'Must attach problemDecomposition');
    assert.ok(chatGoalRes.data.remediationSuitability, 'Must attach remediationSuitability');
    assert.match(chatGoalRes.data.reply, /Autonomous Goal Decomposition/i);
  });

  it('23. AI Cognition 2.0 — The Last Admin Natural-Language Knowledge, 30-Minute Operational Time Machine & Signal-vs-Noise', async () => {
    const whyRes = operationalMemoryEngine.queryOrganizationalKnowledgeNaturalLanguage({
      question: 'Why was this gateway configured differently from the others?',
      target: '127.0.0.1'
    });
    assert.equal(typeof whyRes.synthesizedAnswer, 'string');
    assert.ok(whyRes.synthesizedAnswer.length > 20);
    assert.ok(Array.isArray(whyRes.matchedInstitutionalRecords));
    assert.ok(Array.isArray(whyRes.documentationVsRealityContradictions));
    assert.ok(Array.isArray(whyRes.memoryConflictsResolved));

    const tm30 = operationalMemoryEngine.reconstructOperationalTimeMachine({
      target: '127.0.0.1',
      windowMinutes: 30
    });
    assert.equal(tm30.windowMinutes, 30);
    assert.ok(tm30.patientZeroComponent);
    assert.ok(Array.isArray(tm30.propagationChain));
    assert.ok(Array.isArray(tm30.honestEvidenceGaps));
    assert.ok(tm30.honestEvidenceGaps.length >= 1, 'Must honestly disclose evidence gaps without inventing history');

    const causality = operationalMemoryEngine.analyzeCrossIncidentCausalityAndNoise();
    assert.ok(Array.isArray(causality.divergentCauseDisambiguations));
    assert.ok(causality.signalVsNoiseSummary);
    assert.ok(Array.isArray(causality.signalVsNoiseSummary.classifications));

    // Verify Chat Workspace integration for "Why was this gateway configured differently from the others?"
    const chatWhyRes = await chatOperatorService.processMessage({
      sessionId: 'TEST-COGNITION-2-CHAT',
      message: 'Why was this gateway configured differently from the others?',
      user: { username: 'admin', role: 'ADMIN' }
    });
    assert.equal(chatWhyRes.success, true);
    assert.match(chatWhyRes.data.reply, /The Last Admin Architectural Grounding/i);

    // Verify Chat Workspace integration for 30-minute Operational Time Machine
    const chatTmRes = await chatOperatorService.processMessage({
      sessionId: 'TEST-COGNITION-2-CHAT',
      message: 'Show me what happened in the 30 minutes before this outage and explain the most significant changes.',
      user: { username: 'admin', role: 'ADMIN' }
    });
    assert.equal(chatTmRes.success, true);
    assert.match(chatTmRes.data.reply, /30-Minute Pre-Outage Narrative/i);
  });

  it('24. AI Cognition 2.0 — DHCP Scope Capacity Exhaustion Simulator, Counterfactual Comparator & Context-Comparable Remediation', async () => {
    const dhcpSim = operationalMemoryEngine.simulateOperationalScenario({
      target: '127.0.0.1',
      scenarioType: 'DHCP_SCOPE_CAPACITY_EXHAUSTION',
      port: 3000
    });
    assert.equal(dhcpSim.isSimulated, true);
    assert.match(dhcpSim.questionAnswered, /DHCP scope capacity/i);
    assert.match(dhcpSim.consequenceSummary, /169\.254\.0\.0\/16/i);

    const comp = operationalMemoryEngine.compareCounterfactualScenarios({
      target: '127.0.0.1',
      port: 3000
    });
    assert.equal(comp.isSimulation, true);
    assert.ok(comp.lowestRiskAlternative);
    assert.ok(comp.scenariosCompared.length >= 5);

    const suit = operationalMemoryEngine.evaluateContextAwareRemediationSuitability({
      target: '127.0.0.1',
      port: 3000
    });
    assert.equal(typeof suit.whyHistoricalSolutionWorked, 'string');
    assert.equal(typeof suit.whyBlindRepetitionIsAvoided, 'string');
    assert.equal(typeof suit.fallbackPlanIfPrimaryActionFails, 'string');

    // Verify Chat Workspace DHCP exhaustion scenario
    const chatDhcpRes = await chatOperatorService.processMessage({
      sessionId: 'TEST-COGNITION-2-CHAT',
      message: 'What would happen if DHCP scope capacity is exhausted?',
      user: { username: 'admin', role: 'ADMIN' }
    });
    assert.equal(chatDhcpRes.success, true);
    assert.equal(chatDhcpRes.data.intent, 'scenario_planning_what_if');
    assert.equal(chatDhcpRes.data.scenarioSimulation.scenarioType, 'DHCP_SCOPE_CAPACITY_EXHAUSTION');
  });

  it('25. AI Cognition 3.0 — Dynamic Problem-Nature Classification, Adaptive Strategy Selection, 10-Part Reasoning & Capability Ecosystem', async () => {
    const { capabilityRegistry, CAPABILITY_DEFINITIONS } = require('../src/core/capability-registry');
    assert.ok(CAPABILITY_DEFINITIONS.length >= 21, 'Must preserve at least 21 canonical capability definitions');

    const ecosystem = capabilityRegistry.describeCapabilityEcosystem();
    assert.ok(ecosystem.totalCapabilities >= 21);
    assert.ok(Array.isArray(ecosystem.capabilities));
    assert.ok(ecosystem.capabilities[0].whatItAccomplishes);
    assert.ok(ecosystem.capabilities[0].limitationsAndBlindSpots);
    assert.ok(Array.isArray(ecosystem.capabilities[0].complementaryCapabilities));

    // Verify distinct problem-nature classification across fundamentally different operational situations
    const broadPlan = operationalMemoryEngine.classifyProblemNatureAndSelectStrategy({
      problemStatement: 'Something is wrong with our infrastructure. Find out what is causing the problem.',
      target: null,
      port: 3000
    });
    assert.equal(broadPlan.problemNatureClassification.natureCode, 'BROAD_UNSPECIFIED_INFRASTRUCTURE_ANOMALY');
    assert.equal(broadPlan.selectedStrategy.strategyCode, 'STRATEGY_WIDE_SPECTRUM_PARALLEL_TRIAGE_AND_CONVERGENCE');
    assert.ok(broadPlan.tenPartReasoningSynthesis.whatAppearsToBeHappening);
    assert.ok(broadPlan.tenPartReasoningSynthesis.whyOtherExplanationsWereRuledOut);
    assert.ok(broadPlan.capabilityExecutionPlan.parallelExecutionGroups.length >= 1);
    assert.ok(broadPlan.capabilityExecutionPlan.dependentExecutionStages.length >= 1);

    const perfPlan = operationalMemoryEngine.classifyProblemNatureAndSelectStrategy({
      problemStatement: 'Users report unexplained latency and slow response times on 127.0.0.1',
      target: '127.0.0.1',
      port: 3000
    });
    assert.equal(perfPlan.problemNatureClassification.natureCode, 'UNEXPLAINED_SYSTEM_OR_NETWORK_SLOWDOWN');
    assert.equal(perfPlan.selectedStrategy.strategyCode, 'STRATEGY_PERFORMANCE_BOTTLENECK_AND_SPECTRAL_JITTER_ISOLATION');

    const diffPlan = operationalMemoryEngine.classifyProblemNatureAndSelectStrategy({
      problemStatement: 'Why is this server configured differently from the other servers?',
      target: '127.0.0.1',
      port: 3000
    });
    assert.equal(diffPlan.problemNatureClassification.natureCode, 'MISCONFIGURED_APPLICATION_OR_SERVER_DIFFERENTIAL');
    assert.equal(diffPlan.selectedStrategy.strategyCode, 'STRATEGY_CONFIGURATION_DIFFERENTIAL_AND_KNOWLEDGE_PROVENANCE_AUDIT');

    const novelPlan = operationalMemoryEngine.classifyProblemNatureAndSelectStrategy({
      problemStatement: 'Bizarre intermittent quantum clock skew phenomenon never seen before',
      target: '127.0.0.1',
      port: 3000
    });
    assert.equal(novelPlan.problemNatureClassification.natureCode, 'NOVEL_UNANTICIPATED_OPERATIONAL_PHENOMENON');
    assert.equal(novelPlan.selectedStrategy.strategyCode, 'STRATEGY_EXPLORATORY_ABDUCTIVE_CAPABILITY_DISCOVERY');
  });

  it('26. AI Cognition 3.0 — Broad Unspecified Infrastructure Investigation & Resumable Long-Running Autonomous Goal Coordinator', async () => {
    const dynInv = await operationalMemoryEngine.executeDynamicCapabilityInvestigation({
      objective: 'Something is wrong with our infrastructure. Find out what is causing the problem.',
      target: null,
      port: 3000,
      initiatedBy: 'admin',
      role: 'ADMIN'
    });
    assert.ok(dynInv.investigationId.startsWith('DYN-COG3-'));
    assert.ok(dynInv.targetInspected, 'Must automatically discover target from Fleet Operational Memory when unspecified');
    assert.ok(dynInv.strategyPlan);
    assert.ok(Array.isArray(dynInv.parallelExecutionResults));
    assert.ok(dynInv.parallelExecutionResults.length >= 3);
    assert.ok(dynInv.criticalSelfCorrection);
    assert.ok(dynInv.collaborativeSynthesis);

    // Execute a goal and then resume it with circumstance check
    const initialGoal = await operationalMemoryEngine.executeAutonomousGoalInvestigation({
      objective: 'Investigate and isolate intermittent service fault on 127.0.0.1',
      target: '127.0.0.1',
      port: 3099,
      initiatedBy: 'admin',
      role: 'ADMIN'
    });
    assert.ok(initialGoal.goalId);

    const resumed = await operationalMemoryEngine.resumeAutonomousGoalInvestigation({
      goalId: initialGoal.goalId,
      additionalEvidence: 'Verified local loopback listener status after port check',
      initiatedBy: 'admin',
      role: 'ADMIN'
    });
    assert.equal(resumed.found, true);
    assert.equal(resumed.goalId, initialGoal.goalId);
    assert.ok(resumed.coordinatorState.originalObjective);
    assert.ok(resumed.coordinatorState.currentInvestigationStrategy);
    assert.ok(Array.isArray(resumed.coordinatorState.tasksAlreadyCompleted));
    assert.ok(Array.isArray(resumed.coordinatorState.findingsDiscovered));
    assert.ok(Array.isArray(resumed.coordinatorState.unresolvedQuestions));
    assert.ok(Array.isArray(resumed.coordinatorState.currentHypotheses));
    assert.ok(Array.isArray(resumed.coordinatorState.decisionsAlreadyMade));
    assert.ok(Array.isArray(resumed.coordinatorState.actionsRequiringApproval));
    assert.equal(typeof resumed.coordinatorState.whatShouldHappenNext, 'string');
    assert.ok(resumed.coordinatorState.resumptionCount >= 1);
  });

  it('27. AI Cognition 3.0 — Critical Self-Correction, Continuous Operational Experience & Institutional Server Configuration Differential', async () => {
    const selfCorr = operationalMemoryEngine.challengeConclusionsAndSelfCorrect({
      problemStatement: 'Complete network outage suspected on 127.0.0.1:3099',
      target: '127.0.0.1',
      port: 3099,
      steps: [
        { id: 'dns', label: 'DNS Resolution', layer: 'L7_DNS', status: 'PASS', detail: 'Resolved 127.0.0.1' },
        { id: 'ping', label: 'ICMP Echo', layer: 'L3_ICMP', status: 'PASS', detail: '0.3ms RTT' },
        { id: 'tcp', label: 'TCP Port 3099', layer: 'L4_TCP', status: 'FAIL', detail: 'ECONNREFUSED (CLOSED)' }
      ]
    });
    assert.ok(Array.isArray(selfCorr.challengedAssumptions));
    assert.ok(selfCorr.challengedAssumptions.some((c) => c.assumptionChallenged.includes('network outage')));
    assert.ok(Array.isArray(selfCorr.contradictionsDetected));
    assert.ok(selfCorr.contradictionsDetected.length >= 1);
    assert.ok(Array.isArray(selfCorr.reconsideredExplanations));
    assert.ok(selfCorr.insufficientEvidenceAssessment);
    assert.equal(typeof selfCorr.antiAttachmentDeclaration, 'string');

    const exp = operationalMemoryEngine.evaluateContinuousOperationalExperience({
      target: '127.0.0.1',
      port: 3000,
      currentFailureLayer: 'L4_TCP_PORT_CLOSED'
    });
    assert.ok(exp.recurringFailurePatterns);
    assert.ok(exp.historicalResolutionOutcomes);
    assert.ok(Array.isArray(exp.historicalResolutionOutcomes.scoredResolutions));
    assert.ok(exp.environmentSpecificQuirks);
    assert.ok(exp.outdatedMemoryFiltering);
    assert.equal(typeof exp.howExperienceInformedCurrentReasoning, 'string');

    const serverDiff = operationalMemoryEngine.analyzeServerConfigurationDifferential({
      question: 'Why is this server configured differently from the other servers?',
      target: '127.0.0.1',
      port: 3000
    });
    assert.equal(serverDiff.questionAnswered, 'Why is this server configured differently from the other servers?');
    assert.ok(Array.isArray(serverDiff.observedConfigurationDifferentials));
    assert.ok(serverDiff.observedConfigurationDifferentials.length >= 1);
    assert.ok(Array.isArray(serverDiff.documentedArchitecturalReasons));
    assert.ok(Array.isArray(serverDiff.undocumentedOrAssumptionOnly));
    assert.equal(typeof serverDiff.executiveSynthesis, 'string');
  });

  it('28. AI Cognition 3.0 — 6-Specialist Collaborative Synthesis, Proactive Horizon Attention, Closed-Loop Outcome Learning, REST APIs & Chat Integration', async () => {
    const collab = operationalMemoryEngine.synthesizeCollaborativeSpecialistIntelligence({
      problemStatement: 'Something is wrong with our infrastructure. Find out what is causing the problem.',
      target: '127.0.0.1',
      port: 3000
    });
    assert.equal(collab.specialistPerspectives.length, 6, 'Must synthesize 6 specialized operational domains');
    assert.ok(Array.isArray(collab.interSpecialistChallenges));
    assert.ok(collab.unifiedCollaborativeConclusion.leadDomain);
    assert.equal(typeof collab.unifiedCollaborativeConclusion.consensusStatement, 'string');

    const attention = operationalMemoryEngine.evaluateProactiveHorizonAttention();
    assert.ok(Array.isArray(attention.proactiveAttentionItems));
    assert.ok(Array.isArray(attention.noiseSuppressedItems));
    assert.equal(typeof attention.executiveAttentionSummary, 'string');

    const learned = operationalMemoryEngine.recordAndLearnFromDecisionOutcome({
      target: '127.0.0.1',
      port: 3000,
      problemNature: 'FAILING_OR_UNREACHABLE_SERVER',
      strategySelected: 'L3_VS_L4_REACHABILITY_BOUNDARY_ISOLATION',
      recommendedAction: 'Restart listener on port 3000 and verify socket readiness',
      verificationOutcome: 'VERIFIED_RESOLVED',
      preRttMs: 14.5,
      postRttMs: 1.2,
      prePortOpen: false,
      postPortOpen: true,
      notes: 'Socket bound cleanly after service restart',
      actor: 'admin'
    });
    assert.ok(learned.ledgerId.startsWith('EXP-LEDGER-'));
    assert.equal(learned.outcomeImprovedSituation, true);
    assert.ok(learned.experienceLedgerTotal >= 1);

    // Verify REST API endpoints for Cognition 3.0
    const apiEcoRes = await fetch(`${baseUrl}/api/v6/command-center/cognition3/capability-ecosystem?objective=Investigate+slowdown`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.equal(apiEcoRes.status, 200);
    const apiEcoBody = await apiEcoRes.json();
    assert.equal(apiEcoBody.success, true);
    assert.ok(apiEcoBody.data.ecosystem.totalCapabilities >= 21);

    const apiDiffRes = await fetch(`${baseUrl}/api/v6/command-center/cognition3/server-differential`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`
      },
      body: JSON.stringify({
        question: 'Why is this server configured differently from the other servers?',
        target: '127.0.0.1',
        port: 3000
      })
    });
    assert.equal(apiDiffRes.status, 200);
    const apiDiffBody = await apiDiffRes.json();
    assert.equal(apiDiffBody.success, true);
    assert.ok(apiDiffBody.data.executiveSynthesis.length > 20);

    // Verify Chat Workspace integration for broad unspecified infrastructure investigation
    const chatBroadRes = await chatOperatorService.processMessage({
      sessionId: 'TEST-COGNITION-3-CHAT',
      message: 'Something is wrong with our infrastructure. Find out what is causing the problem.',
      user: { username: 'admin', role: 'ADMIN' }
    });
    assert.equal(chatBroadRes.success, true);
    assert.ok(chatBroadRes.data.cognition3StrategyPlan, 'Must attach cognition3StrategyPlan');
    assert.ok(chatBroadRes.data.criticalSelfCorrection, 'Must attach criticalSelfCorrection');
    assert.ok(chatBroadRes.data.collaborativeSynthesis, 'Must attach collaborativeSynthesis');
    assert.match(chatBroadRes.data.reply, /AI Cognition 3\.0 — Autonomous Broad Infrastructure Investigation/i);

    // Verify Chat Workspace integration for "Why is this server configured differently from the other servers?"
    const chatServerDiffRes = await chatOperatorService.processMessage({
      sessionId: 'TEST-COGNITION-3-CHAT',
      message: 'Why is this server configured differently from the other servers?',
      user: { username: 'admin', role: 'ADMIN' }
    });
    assert.equal(chatServerDiffRes.success, true);
    assert.ok(chatServerDiffRes.data.serverConfigDifferential, 'Must attach serverConfigDifferential');
    assert.match(chatServerDiffRes.data.reply, /Institutional Server Configuration Differential/i);
  });
});






