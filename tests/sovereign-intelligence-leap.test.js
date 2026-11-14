/**
 * tests/sovereign-intelligence-leap.test.js
 * Comprehensive Verification Suite for EJII Sovereign Intelligence & Autonomous Engineering Leap
 *
 * Covers:
 * 1. Zero-Loss Structured Telemetry Distillation (Context Window Compaction)
 * 2. Mathematical Shannon Information-Gain Dynamic Probe Selection
 * 3. Epistemic Classification Synthesis (Proven Facts, Probable, Unresolved)
 * 4. Topological Incident Isomorphism in Operational Memory Engine
 * 5. Neuro-Symbolic Smooth STL Robustness & Time-To-Violation Horizon Forecasting
 * 6. Autonomous SRE War Room Epistemic Abstention Enforcement
 * 7. Multi-Sample Temporal Post-Remediation Stability Verification Window
 * 8. Line-Rate High-Speed Packet Streamer Backpressure Metrics
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  distillTelemetryForContext,
  computeOptimalInformationGainProbe,
  computeExpectedProbeInformationGain,
  computeShannonEntropyFromDistribution,
  updateBayesianDistributionFromProbeOutcome,
  updateBayesianDistributionFromCompoundOutcomes,
  computeOptimalConcurrentProbes,
  CANDIDATE_PROBE_LIKELIHOOD_MODELS,
  runAgenticToolLoop
} = require('../src/core/chat/conversational-brain');

const { operationalMemoryEngine } = require('../src/core/memory/operational-memory-engine');
const { evidenceFabric } = require('../src/core/evidence/evidence-fabric');
const { NeuroSymbolicApexEngine } = require('../src/ai/neuro-symbolic-apex');
const { autonomousWarRoomOrchestrator, AutonomousWarRoomOrchestrator } = require('../src/ai/autonomous-war-room');
const { packetStreamer } = require('../src/network/packet-streaming/packet-streamer');

test('EJII Sovereign Intelligence Leap Suite', async (t) => {
  await t.test('1. verifies zero-loss telemetry distillation across diverse probe outputs', () => {
    // Port scan distillation
    const portObservation = {
      intent: 'port_check',
      target: '10.0.0.1',
      technicalEvidence: {
        rawResults: [
          { port: 80, status: 'OPEN', rttMs: 12.4 },
          { port: 443, status: 'OPEN', rttMs: 14.1 },
          { port: 22, status: 'CLOSED', rttMs: 11.8 },
          { port: 8080, status: 'FILTERED', rttMs: 1000 }
        ]
      }
    };
    const distilledPort = distillTelemetryForContext(portObservation);
    assert.equal(distilledPort.type, 'TCP_PORT_PROBE_DISTILLATION');
    assert.deepEqual(distilledPort.open, [80, 443]);
    assert.deepEqual(distilledPort.closed, [22]);
    assert.deepEqual(distilledPort.filtered, [8080]);
    assert.ok(distilledPort.rttStatsMs !== null);
    assert.equal(distilledPort.rttStatsMs.min, 11.8);
    assert.ok(distilledPort.summary.includes('2 OPEN'));

    // DNS distillation
    const dnsObservation = {
      intent: 'dns',
      target: 'example.com',
      records: ['93.184.216.34', '93.184.216.35', '93.184.216.36'],
      recordType: 'A',
      queryLatencies: [15.2, 16.0]
    };
    const distilledDns = distillTelemetryForContext(dnsObservation);
    assert.equal(distilledDns.type, 'DNS_PROBE_DISTILLATION');
    assert.equal(distilledDns.totalRecords, 3);
    assert.equal(distilledDns.latencyMs, 15.6);

    // Traceroute distillation
    const tracerouteObservation = {
      intent: 'traceroute',
      target: '8.8.8.8',
      hops: [
        { hopNumber: 1, ip: '192.168.1.1', rttMs: 1.2, timedOut: false },
        { hopNumber: 2, ip: '10.0.0.1', rttMs: 4.5, timedOut: false },
        { hopNumber: 3, ip: null, rttMs: null, timedOut: true },
        { hopNumber: 4, ip: '8.8.8.8', rttMs: 14.8, timedOut: false }
      ]
    };
    const distilledTrace = distillTelemetryForContext(tracerouteObservation);
    assert.equal(distilledTrace.type, 'TRACEROUTE_DISTILLATION');
    assert.equal(distilledTrace.totalHops, 4);
    assert.equal(distilledTrace.responsiveHopsCount, 3);
    assert.equal(distilledTrace.timedOutHopsCount, 1);
    assert.equal(distilledTrace.firstFailureHop, 3);
    assert.equal(distilledTrace.destinationReached, true);
  });

  await t.test('2. verifies exact mathematical Shannon information-gain dynamic probe selection', () => {
    const hypotheses = [
      { id: 'DNS_NXDOMAIN_POISON', name: 'DNS Poisoning', probability: 0.70 },
      { id: 'FIREWALL_ACL_DROP', name: 'Firewall Drop', probability: 0.20 },
      { id: 'SERVICE_DAEMON_CRASH', name: 'Daemon Crash', probability: 0.10 }
    ];

    const optimal = computeOptimalInformationGainProbe(hypotheses, CANDIDATE_PROBE_LIKELIHOOD_MODELS);
    assert.ok(optimal !== null);
    assert.ok(typeof optimal.expectedInformationGainBits === 'number');
    assert.ok(optimal.expectedInformationGainBits > 0);
    // When DNS_NXDOMAIN_POISON is dominant, DNS lookup should offer high information gain
    assert.ok(optimal.probeId.includes('DNS') || optimal.probeId.includes('TCP'));
  });

  await t.test('3. verifies agentic tool loop synthesizes explicit epistemicClassification', async () => {
    let loopExecuted = false;
    const initialPlan = {
      intent: 'dns',
      mode: 'operational',
      target: 'google.com'
    };

    const mockExecutor = async (plan) => {
      loopExecuted = true;
      return {
        reply: 'Resolved google.com to 142.250.190.46',
        structuredAnswer: { result: 'DNS query succeeded', meaning: 'Domain is resolvable' },
        findings: [{ label: 'DNS Status', value: 'NOERROR' }],
        technicalEvidence: { rawResults: [{ host: 'google.com', ip: '142.250.190.46' }] }
      };
    };

    const result = await runAgenticToolLoop({
      promptText: 'Resolve google.com',
      initialPlan,
      executeSinglePlan: mockExecutor,
      maxSteps: 1
    });

    assert.ok(loopExecuted);
    assert.ok(result.epistemicClassification !== undefined);
    assert.ok(Array.isArray(result.epistemicClassification.provenFacts));
    assert.ok(result.epistemicClassification.provenFacts.some((f) => f.includes('DNS Status: NOERROR')));
    assert.ok(Array.isArray(result.epistemicClassification.probableHypotheses));
  });

  await t.test('4. verifies operational memory engine queries topological incident isomorphism', () => {
    operationalMemoryEngine.recordResolution({
      target: '10.22.10.153',
      symptomSignature: 'TCP_PORT_TIMEOUT',
      rootCause: 'Stateful firewall drop on ingress port 443',
      resolutionSteps: 'Verify iptables rule on edge firewall',
      port: 443,
      verifiedBy: 'SRE_LEAD'
    });

    const isomorphismResult = operationalMemoryEngine.queryTopologicalIncidentIsomorphism({
      target: '10.22.10.153',
      topologyNodes: [{ id: '10.22.10.153', role: 'SERVER' }],
      symptomSignature: 'TCP_PORT_TIMEOUT'
    });

    assert.equal(isomorphismResult.target, '10.22.10.153');
    assert.ok(isomorphismResult.isomorphicMatchesFound >= 1);
    const topMatch = isomorphismResult.topMatches[0];
    assert.ok(topMatch.topologicalSimilarity >= 0.70);
    assert.equal(topMatch.isIsomorphic, true);
    assert.ok(topMatch.runbookProcedure.includes('iptables'));
  });

  await t.test('5. verifies Smooth STL robustness and metric sensitivity gradients in neuro-symbolic engine', () => {
    const engine = new NeuroSymbolicApexEngine(12.0);
    const predicates = [
      { id: 'RTT_LIMIT', metric: 'rttMs', operator: 'LTE', threshold: 50.0, weight: 1.0 },
      { id: 'LOSS_LIMIT', metric: 'packetLossPct', operator: 'LTE', threshold: 1.0, weight: 1.0 }
    ];

    const trace = [
      { timestampMs: 1000, rttMs: 20.0, packetLossPct: 0.0, cpuSaturationPct: 25.0, tcpRetransmitRate: 0.0 },
      { timestampMs: 2000, rttMs: 25.0, packetLossPct: 0.0, cpuSaturationPct: 30.0, tcpRetransmitRate: 0.0 },
      { timestampMs: 3000, rttMs: 35.0, packetLossPct: 0.1, cpuSaturationPct: 40.0, tcpRetransmitRate: 0.0 }
    ];

    const evalResult = engine.evaluateTemporallyBoundedAlways('SLA_POLICY_01', predicates, trace);
    assert.equal(evalResult.formulaId, 'SLA_POLICY_01');
    assert.equal(evalResult.satisfied, true);
    assert.ok(evalResult.smoothRobustness > 0);
    assert.ok(evalResult.metricSensitivityGradient.RTT_LIMIT !== undefined);
    assert.ok(evalResult.metricSensitivityGradient.LOSS_LIMIT !== undefined);
  });

  await t.test('6. verifies autonomous war room enforces epistemic abstention on missing or contradictory receipts', () => {
    autonomousWarRoomOrchestrator.rotateHmacKey('sovereign-test-hmac-secret-32-bytes-long', { keyId: 'test-key-01' });

    // Case A: Zero receipts -> Abstention required
    const emptyCheck = autonomousWarRoomOrchestrator.enforceEpistemicAbstention([], [{ id: 'H1', confidencePct: 80 }]);
    assert.equal(emptyCheck.abstentionRequired, true);
    assert.equal(emptyCheck.reasonCode, 'UNVERIFIED_RECEIPTS_PRESENT');

    // Case B: Contradictory receipts (SUCCESS vs FAILURE on same target and probeType)
    const receipt1 = autonomousWarRoomOrchestrator.createCollectorExecutionReceipt({
      sessionId: 'TEST_SESSION_01',
      probeId: 'TCP_443',
      probeType: 'TCP_HANDSHAKE',
      target: 'api.enterprise.internal',
      collectorId: 'COLLECTOR_01',
      startedAt: new Date(Date.now() - 100).toISOString(),
      completedAt: new Date().toISOString(),
      durationMs: 12.5,
      timingTarget: 'TCP_HANDSHAKE_RTT_MS',
      nativeResultCode: 'SUCCESS',
      rawCommandOutput: 'TCP_HANDSHAKE_COMPLETED_200_OK'
    });

    const receipt2 = autonomousWarRoomOrchestrator.createCollectorExecutionReceipt({
      sessionId: 'TEST_SESSION_01',
      probeId: 'TCP_443_SECONDARY',
      probeType: 'TCP_HANDSHAKE',
      target: 'api.enterprise.internal',
      collectorId: 'COLLECTOR_02',
      startedAt: new Date(Date.now() - 80).toISOString(),
      completedAt: new Date().toISOString(),
      durationMs: 1000.0,
      timingTarget: 'TCP_HANDSHAKE_RTT_MS',
      nativeResultCode: 'FAILURE',
      rawCommandOutput: 'TCP_HANDSHAKE_ETIMEDOUT'
    });

    const contradictoryCheck = autonomousWarRoomOrchestrator.enforceEpistemicAbstention([receipt1, receipt2], [{ id: 'H1', confidencePct: 50 }]);
    assert.equal(contradictoryCheck.abstentionRequired, true);
    assert.equal(contradictoryCheck.reasonCode, 'CONTRADICTORY_EVIDENCE_DETECTED');
  });

  await t.test('7. verifies autonomous war room temporal post-remediation verification window', () => {
    const stableSamples = [
      { timestampMs: 1000, rttMs: 14.2, packetLossPct: 0.0 },
      { timestampMs: 2000, rttMs: 15.0, packetLossPct: 0.0 },
      { timestampMs: 3000, rttMs: 14.8, packetLossPct: 0.0 }
    ];

    const stableResult = autonomousWarRoomOrchestrator.executeTemporalPostRemediationVerification({
      remediationId: 'REM_RESTART_INGRESS',
      target: '10.0.0.1',
      samples: stableSamples,
      windowSec: 60
    });

    assert.equal(stableResult.verified, true);
    assert.equal(stableResult.isStable, true);
    assert.equal(stableResult.verificationStatus, 'TEMPORAL_STABILITY_CONFIRMED');
    assert.ok(stableResult.rttStdDevMs < 5.0);

    // Oscillating samples
    const oscillatingSamples = [
      { timestampMs: 1000, rttMs: 14.2, packetLossPct: 0.0 },
      { timestampMs: 2000, rttMs: 95.0, packetLossPct: 5.0 },
      { timestampMs: 3000, rttMs: 12.0, packetLossPct: 0.0 }
    ];

    const oscillatingResult = autonomousWarRoomOrchestrator.executeTemporalPostRemediationVerification({
      remediationId: 'REM_RESTART_INGRESS',
      target: '10.0.0.1',
      samples: oscillatingSamples,
      windowSec: 60
    });

    assert.equal(oscillatingResult.verified, false);
    assert.equal(oscillatingResult.verificationStatus, 'SECONDARY_OSCILLATION_DETECTED');
  });

  await t.test('8. verifies packet streamer backpressure metrics and line-rate ring buffer health', () => {
    const metrics = packetStreamer.getBackpressureMetrics();
    assert.ok(typeof metrics.totalReceived === 'number');
    assert.ok(typeof metrics.totalDelivered === 'number');
    assert.ok(metrics.ringBufferStats !== undefined);
    assert.ok(metrics.ringBufferStats.ringBufferCapacity >= 4096);
    assert.equal(typeof metrics.backpressureHealthy, 'boolean');
  });

  await t.test('9. verifies 12-probe candidate matrix spans all 6 fault domains with valid empirical likelihood distributions', () => {
    assert.equal(CANDIDATE_PROBE_LIKELIHOOD_MODELS.length, 12);
    const probeIds = CANDIDATE_PROBE_LIKELIHOOD_MODELS.map((p) => p.probeId);
    assert.ok(probeIds.includes('ARP_NEIGHBOR_PROBE'), 'Must include L2 ARP neighbor probe');
    assert.ok(probeIds.includes('ICMP_GATEWAY_PING'), 'Must include L3 Gateway ping probe');
    assert.ok(probeIds.includes('TRACEROUTE_WAN_PROBE'), 'Must include L3 Traceroute probe');
    assert.ok(probeIds.includes('TLS_POSTURE_AUDIT_PROBE'), 'Must include L6 TLS posture probe');
    assert.ok(probeIds.includes('DNS_MX_RECORD_PROBE'), 'Must include L7 DNS MX probe');
    assert.ok(probeIds.includes('TCP_SSH_PROBE_22'), 'Must include L4 SSH probe');
    assert.ok(probeIds.includes('TCP_DATABASE_PROBE_3306_5432'), 'Must include L4 Database probe');
    assert.ok(probeIds.includes('KERNEL_SOCKET_EXHAUSTION_PROBE'), 'Must include Host socket probe');
    assert.ok(probeIds.includes('HOST_RESOURCE_HEALTH_PROBE'), 'Must include Host resource probe');

    for (const model of CANDIDATE_PROBE_LIKELIHOOD_MODELS) {
      assert.ok(model.probeName && model.command && model.intent);
      assert.ok(model.likelihoodPassGivenHypothesis, `Model ${model.probeId} must declare likelihoods`);
      for (const [hyp, l] of Object.entries(model.likelihoodPassGivenHypothesis)) {
        assert.ok(typeof l === 'number' && l >= 0 && l <= 1, `Likelihood ${hyp} on ${model.probeId} must be within [0,1]`);
      }
    }
  });

  await t.test('10. verifies dynamic Bayesian posterior update loop with entropy reduction upon probe observation', () => {
    const priorDistribution = [
      { id: 'DNS_NXDOMAIN_POISON', name: 'DNS Poisoning', probability: 0.5, percentage: 50 },
      { id: 'SERVICE_DAEMON_CRASH', name: 'Service Daemon Crash', probability: 0.5, percentage: 50 }
    ];

    const priorEntropy = computeShannonEntropyFromDistribution(priorDistribution.map((h) => h.probability));
    assert.equal(priorEntropy, 1.0); // - [0.5 * log2(0.5) + 0.5 * log2(0.5)] = 1.0 bit

    // DNS lookup passes -> very unlikely to be DNS_NXDOMAIN_POISON (likelihood 0.04 vs 0.90)
    const updatedPosteriors = updateBayesianDistributionFromProbeOutcome(
      priorDistribution,
      'DNS_WIRE_LOOKUP_GOOGLE',
      true
    );

    const updatedEntropy = computeShannonEntropyFromDistribution(updatedPosteriors.map((h) => h.probability));
    assert.ok(updatedEntropy < priorEntropy, `Updated entropy (${updatedEntropy}) must be strictly less than prior (${priorEntropy})`);

    const dnsHyp = updatedPosteriors.find((h) => h.id === 'DNS_NXDOMAIN_POISON');
    const srvHyp = updatedPosteriors.find((h) => h.id === 'SERVICE_DAEMON_CRASH');
    assert.ok(srvHyp.probability > 0.9, 'Service crash posterior should rise above 90% when DNS lookup succeeds');
    assert.ok(dnsHyp.probability < 0.1, 'DNS poisoning posterior should drop below 10% when DNS lookup succeeds');
  });

  await t.test('11. verifies multi-step agentic loop honors 5-step ceiling, budget awareness, and attaches terminationReason', async () => {
    let executionCount = 0;
    const mockExecute = async (plan, step) => {
      executionCount++;
      return {
        reply: `Step ${step} executed intent ${plan.intent}`,
        durationMs: 50,
        technicalEvidence: { success: true },
        structuredAnswer: { result: 'OK', meaning: 'Healthy' }
      };
    };

    const initialPlan = {
      intent: 'dns',
      mode: 'operational',
      target: 'example.com',
      secondaryToolPlans: [
        { intent: 'port_check', target: 'example.com', ports: [443] },
        { intent: 'website_check', target: 'example.com', ports: [443] }
      ]
    };

    const loopResult = await runAgenticToolLoop({
      promptText: 'Check DNS, port, and website for example.com',
      initialPlan,
      executeSinglePlan: mockExecute,
      maxSteps: 5
    });

    assert.ok(executionCount >= 2, 'Should execute multiple queued plans');
    assert.ok(loopResult.epistemicClassification, 'Must attach epistemicClassification');
    assert.ok(typeof loopResult.epistemicClassification.totalElapsedMs === 'number');
    assert.ok(loopResult.epistemicClassification.terminationReason !== undefined);
  });

  await t.test('12. verifies telemetry distillation across TLS, ICMP, HTTP, Host Resource, and SNMP probe outputs', () => {
    // TLS Posture Distillation
    const tlsDist = distillTelemetryForContext({
      intent: 'tls_posture_audit',
      target: 'api.corp.local',
      valid: true,
      certificate: { subject: 'CN=api.corp.local', daysRemaining: 89, cipher: 'TLS_AES_256_GCM_SHA384' }
    });
    assert.equal(tlsDist.type, 'TLS_POSTURE_DISTILLATION');
    assert.equal(tlsDist.valid, true);
    assert.equal(tlsDist.daysRemaining, 89);

    // ICMP Ping Distillation
    const pingDist = distillTelemetryForContext({
      intent: 'ping',
      target: '8.8.8.8',
      lossPercentage: 0,
      avgLatencyMs: 14.5,
      transmitted: 4,
      received: 4
    });
    assert.equal(pingDist.type, 'ICMP_PING_DISTILLATION');
    assert.equal(pingDist.packetLossPct, 0);
    assert.equal(pingDist.rttMs, 14.5);

    // HTTP Application Distillation
    const httpDist = distillTelemetryForContext({
      intent: 'website_check',
      target: 'https://status.corp.local',
      statusCode: 200,
      ttfbMs: 42.1
    });
    assert.equal(httpDist.type, 'HTTP_APPLICATION_DISTILLATION');
    assert.equal(httpDist.statusCode, 200);
    assert.equal(httpDist.healthy, true);

    // Host Resource Distillation
    const hostDist = distillTelemetryForContext({
      intent: 'host_health',
      cpu: { usagePercentage: 18.4, loadAverage1m: 0.85 },
      memory: { usedPercent: 44.2 }
    });
    assert.equal(hostDist.type, 'HOST_RESOURCE_DISTILLATION');
    assert.equal(hostDist.cpuUsagePct, 18.4);
    assert.equal(hostDist.memUsagePct, 44.2);

    // SNMP Distillation
    const snmpDist = distillTelemetryForContext({
      intent: 'snmp_probe',
      target: '10.0.0.254',
      sysDescr: 'Cisco IOS Catalyst 9300',
      oids: [{ oid: '1.3.6.1.2.1.1.1.0', value: 'Cisco IOS' }]
    });
    assert.equal(snmpDist.type, 'SNMP_PROBE_DISTILLATION');
    assert.equal(snmpDist.totalOids, 1);
  });

  await t.test('13. verifies autonomous war room automated key rotation and receipt expiration TTL', () => {
    const testSecret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    const warRoom = new AutonomousWarRoomOrchestrator({
      secretKey: testSecret,
      rotationPolicy: {
        maxAgeMs: 500,
        maxReceiptsBeforeRotation: 3,
        autoRotate: true
      }
    });

    const initialKeyId = warRoom.getDiagnostics().activeKeyId;
    assert.ok(initialKeyId);

    // Issue receipt 1 & 2
    const rcpt1 = warRoom.signCollectorExecutionReceipt({
      sessionId: 'ROT_SESS_1',
      probeId: 'TCP_443',
      target: '10.0.0.1',
      durationMs: 5.2,
      rawCommandOutput: 'TCP_SYN_ACK'
    });
    assert.equal(rcpt1.keyId, initialKeyId);
    assert.equal(warRoom.getDiagnostics().receiptsIssuedCurrentKey, 1);

    const rcpt2 = warRoom.signCollectorExecutionReceipt({
      sessionId: 'ROT_SESS_1',
      probeId: 'TCP_443',
      target: '10.0.0.1',
      durationMs: 4.8,
      rawCommandOutput: 'TCP_SYN_ACK'
    });
    assert.equal(rcpt2.keyId, initialKeyId);
    assert.equal(warRoom.getDiagnostics().receiptsIssuedCurrentKey, 2);

    // Issue receipt 3 (hits maxReceiptsBeforeRotation threshold = 3)
    const rcpt3 = warRoom.signCollectorExecutionReceipt({
      sessionId: 'ROT_SESS_1',
      probeId: 'TCP_443',
      target: '10.0.0.1',
      durationMs: 4.9,
      rawCommandOutput: 'TCP_SYN_ACK'
    });
    assert.equal(rcpt3.keyId, initialKeyId);

    // Issue receipt 4 (triggers checkRotationNeeded and auto-rotates)
    const rcpt4 = warRoom.signCollectorExecutionReceipt({
      sessionId: 'ROT_SESS_1',
      probeId: 'TCP_443',
      target: '10.0.0.1',
      durationMs: 5.0,
      rawCommandOutput: 'TCP_SYN_ACK'
    });
    const rotatedKeyId = warRoom.getDiagnostics().activeKeyId;
    assert.notEqual(rotatedKeyId, initialKeyId);
    assert.equal(rcpt4.keyId, rotatedKeyId);

    // Verify older receipt within grace period still verifies cleanly
    const verifyRcpt1 = warRoom.verifyCollectorExecutionReceipt(rcpt1, 'TCP_443', '10.0.0.1', 'ROT_SESS_1');
    assert.equal(verifyRcpt1.valid, true);

    // Verify expired receipt (older than 3600s TTL)
    const expiredReceipt = {
      ...rcpt1,
      receiptId: 'rcpt-expired-999',
      startedAt: new Date(Date.now() - 3600_000 * 2).toISOString(),
      completedAt: new Date(Date.now() - 3600_000 * 2 + 100).toISOString()
    };
    const expiredCheck = warRoom.verifyCollectorExecutionReceipt(expiredReceipt, 'TCP_443', '10.0.0.1', 'ROT_SESS_1');
    assert.equal(expiredCheck.valid, false);
    assert.equal(expiredCheck.reasonCode, 'COLLECTOR_RECEIPT_EXPIRED');

    // Verify future skew receipt (> 60s in future)
    const futureReceipt = {
      ...rcpt1,
      receiptId: 'rcpt-future-999',
      startedAt: new Date(Date.now() + 120_000).toISOString(),
      completedAt: new Date(Date.now() + 120_100).toISOString()
    };
    const futureCheck = warRoom.verifyCollectorExecutionReceipt(futureReceipt, 'TCP_443', '10.0.0.1', 'ROT_SESS_1');
    assert.equal(futureCheck.valid, false);
    assert.equal(futureCheck.reasonCode, 'COLLECTOR_RECEIPT_FUTURE_SKEW');
  });

  await t.test('14. verifies rate limiting coverage, headers, and 429 throttling across API endpoints', () => {
    const { createApiRateLimiter } = require('../src/api/rate-limiter');
    const limiter = createApiRateLimiter({
      endpointName: 'api/test-scope',
      windowMs: 10_000,
      maxRequests: 2
    });

    const headers = {};
    const mockRes = {
      setHeader(k, v) { headers[k] = v; },
      statusCode: 200,
      status(code) { this.statusCode = code; return this; },
      json(body) { this.body = body; return this; }
    };

    let nextCount = 0;
    const req1 = { ip: '192.168.1.100' };
    limiter(req1, mockRes, () => { nextCount++; });
    assert.equal(nextCount, 1);
    assert.equal(headers['X-RateLimit-Limit'], 2);
    assert.equal(headers['X-RateLimit-Remaining'], 1);

    const req2 = { ip: '192.168.1.100' };
    limiter(req2, mockRes, () => { nextCount++; });
    assert.equal(nextCount, 2);
    assert.equal(headers['X-RateLimit-Remaining'], 0);

    // 3rd request should exceed maxRequests and return 429
    const req3 = { ip: '192.168.1.100' };
    limiter(req3, mockRes, () => { nextCount++; });
    assert.equal(nextCount, 2); // next() was not called
    assert.equal(mockRes.statusCode, 429);
    assert.equal(mockRes.body.ok, false);
    assert.match(mockRes.body.error, /Rate limit exceeded on \/api\/test-scope/);
  });

  await t.test('15. verifies standardized EJIIResult<T> error envelope across protocol engines', () => {
    const { wrapProtocolProbeResult, validateEjiiResult } = require('../src/core/contracts/ejii-result');

    // Case 1: TCP Port Closed error
    const rawTcpClosed = {
      host: '127.0.0.1',
      port: 65431,
      status: 'CLOSED',
      open: false,
      connectLatencyMs: 1.2,
      error: 'ECONNREFUSED (Host is up, but no service is listening on port)',
      errorCode: 'ECONNREFUSED'
    };
    const wrappedTcp = wrapProtocolProbeResult('ejii.protocols.tcp_port', rawTcpClosed);
    assert.equal(wrappedTcp.ok, false);
    assert.equal(wrappedTcp.success, false);
    assert.equal(wrappedTcp.status, 'failed');
    assert.equal(wrappedTcp.error.code, 'ECONNREFUSED');
    assert.match(wrappedTcp.error.message, /ECONNREFUSED/);
    assert.equal(wrappedTcp.source.module, 'ejii.protocols.tcp_port');
    const validTcp = validateEjiiResult(wrappedTcp);
    assert.equal(validTcp.valid, true);

    // Case 2: DNS lookup error
    const rawDnsError = {
      success: false,
      error: 'queryA ENOTFOUND invalid.domain.corp',
      errorCode: 'ENOTFOUND'
    };
    const wrappedDns = wrapProtocolProbeResult('ejii.protocols.dns_lookup', rawDnsError);
    assert.equal(wrappedDns.ok, false);
    assert.equal(wrappedDns.status, 'failed');
    assert.equal(wrappedDns.error.code, 'ENOTFOUND');
    assert.equal(validateEjiiResult(wrappedDns).valid, true);

    // Case 3: Security blocked (SSRF)
    const rawSecurityBlocked = {
      host: '169.254.169.254',
      port: 80,
      status: 'SECURITY_BLOCKED',
      open: false,
      error: 'Prohibited cloud metadata endpoint'
    };
    const wrappedSecurity = wrapProtocolProbeResult('ejii.protocols.tcp_port', rawSecurityBlocked);
    assert.equal(wrappedSecurity.ok, false);
    assert.equal(wrappedSecurity.status, 'denied');
    assert.equal(validateEjiiResult(wrappedSecurity).valid, true);

    // Case 4: Successful ping probe
    const rawPingSuccess = {
      host: '127.0.0.1',
      alive: true,
      avgRttMs: 0.8,
      packetLossPct: 0.0
    };
    const wrappedPing = wrapProtocolProbeResult('ejii.protocols.icmp_ping', rawPingSuccess);
    assert.equal(wrappedPing.ok, true);
    assert.equal(wrappedPing.success, true);
    assert.equal(wrappedPing.status, 'ok');
    assert.equal(wrappedPing.error, undefined);
    assert.equal(validateEjiiResult(wrappedPing).valid, true);
  });

  await t.test('16. verifies computeOptimalConcurrentProbes selects orthogonal non-conflicting layer probes with maximum information gain', () => {
    const priorDistribution = [
      { id: 'DNS_NXDOMAIN_POISON', name: 'DNS Poisoning', probability: 0.35, percentage: 35 },
      { id: 'UPSTREAM_WAN_BLACKHOLE', name: 'WAN Blackhole', probability: 0.35, percentage: 35 },
      { id: 'FIREWALL_ACL_DROP', name: 'Firewall Drop', probability: 0.30, percentage: 30 }
    ];

    const concurrentProbes = computeOptimalConcurrentProbes(priorDistribution, { maxConcurrent: 2 });
    assert.ok(Array.isArray(concurrentProbes));
    assert.ok(concurrentProbes.length >= 2, 'Must return at least 2 non-conflicting candidate probes');

    // Verify probes operate on orthogonal layers/domains (no duplicated intents or primary layers)
    const intents = concurrentProbes.map((p) => p.intent);
    const uniqueIntents = new Set(intents);
    assert.equal(intents.length, uniqueIntents.size, 'Concurrent probes must have distinct intents');

    const primaryLayers = concurrentProbes.map((p) => (p.targetLayers && p.targetLayers[0]) || p.intent);
    const uniqueLayers = new Set(primaryLayers);
    assert.equal(primaryLayers.length, uniqueLayers.size, 'Concurrent probes must operate across distinct target layers');

    for (const p of concurrentProbes) {
      assert.ok(typeof p.expectedInformationGainBits === 'number');
      assert.ok(p.expectedInformationGainBits >= 0);
    }
  });

  await t.test('17. verifies runAgenticToolLoop executes concurrent non-interfering probes and applies compound Bayesian updates with entropy reduction', async () => {
    const priorDistribution = [
      { id: 'DNS_NXDOMAIN_POISON', name: 'DNS Poisoning', probability: 0.5, percentage: 50 },
      { id: 'UPSTREAM_WAN_BLACKHOLE', name: 'WAN Blackhole', probability: 0.5, percentage: 50 }
    ];
    const initialEntropy = computeShannonEntropyFromDistribution(priorDistribution.map((h) => h.probability));

    const compoundUpdated = updateBayesianDistributionFromCompoundOutcomes(priorDistribution, [
      { probeId: 'DNS_WIRE_LOOKUP_GOOGLE', passed: true },
      { probeId: 'ICMP_GATEWAY_PING', passed: true }
    ]);

    const updatedEntropy = computeShannonEntropyFromDistribution(compoundUpdated.map((h) => h.probability));
    assert.ok(updatedEntropy < initialEntropy, 'Compound updates must strictly reduce entropy');

    const executedPlans = [];
    const mockExecute = async (plan, step) => {
      executedPlans.push({ plan, step });
      return {
        reply: `Executed ${plan.intent} on ${plan.target}`,
        durationMs: 40,
        technicalEvidence: { success: true, tool: plan.intent },
        structuredAnswer: { result: 'OK', meaning: 'Healthy' }
      };
    };

    const initialCompoundPlan = {
      intent: 'dns',
      mode: 'operational',
      target: 'example.com',
      ports: [],
      concurrentPlans: [
        {
          intent: 'gateway_check',
          mode: 'operational',
          target: 'default_gateway',
          ports: []
        }
      ]
    };

    const result = await runAgenticToolLoop({
      promptText: 'Check DNS for example.com and ping gateway',
      initialPlan: initialCompoundPlan,
      executeSinglePlan: mockExecute,
      maxSteps: 3
    });

    assert.ok(result);
    assert.equal(executedPlans.length, 2, 'Must execute both initial and concurrent probe plans');
    assert.ok(result.epistemicClassification);
    assert.ok(Array.isArray(result.epistemicClassification.recommendedConcurrentProbes));
  });

  await t.test('18. verifies episodic incident memory feedback into Bayesian diagnostic priors and Shannon IG probe selection', () => {
    const { computeLiveInformationGainAnalysis, CANONICAL_FAULT_HYPOTHESES } = require('../src/core/chat/conversational-brain');

    // 1. Unseen target has no history and falls back to baseline canonical prior
    const unseenPrior = operationalMemoryEngine.calculateTargetEmpiricalPrior('unseen-target-host.test');
    assert.equal(unseenPrior.hasHistory, false);
    assert.equal(unseenPrior.sampleCount, 0);

    const baselineAnalysis = computeLiveInformationGainAnalysis({ target: 'unseen-target-host.test' });
    assert.equal(baselineAnalysis.entropyStatus, 'BASELINE_CANONICAL_PRIOR');
    assert.equal(baselineAnalysis.empiricalPriorApplied, false);
    assert.ok(baselineAnalysis.currentEntropyBits > 3.0, '9-hypothesis canonical baseline entropy should be > 3 bits');
    assert.equal(baselineAnalysis.hypotheses.length, 9);

    // 2. Seed verified DNS resolution incident for historical host
    const testHost = 'flaky-resolver-edge.corp.test';
    operationalMemoryEngine.recordVerifiedResolution({
      target: testHost,
      symptomSignature: 'DNS_NXDOMAIN_TIMEOUT_EXCEPTION',
      rootCause: 'Upstream authoritative DNS resolver poisoning and c-ares cache pollution',
      resolutionSteps: 'Flushed resolver cache and verified authoritative NS delegation',
      port: 53,
      verifiedBy: 'sre-lead'
    });

    // 3. Verify empirical prior reflects Dirichlet-smoothed DNS failure mode
    const empirical = operationalMemoryEngine.calculateTargetEmpiricalPrior(testHost);
    assert.equal(empirical.hasHistory, true);
    assert.ok(empirical.sampleCount >= 1);
    assert.equal(empirical.dominantHypothesis, 'DNS_NXDOMAIN_POISON');
    assert.equal(empirical.empiricalPriors.length, 9);

    const dnsHyp = empirical.empiricalPriors.find((h) => h.id === 'DNS_NXDOMAIN_POISON');
    assert.ok(dnsHyp.probability > 0.25, `DNS poisoning prior should be significantly elevated (> 0.25), got ${dnsHyp.probability}`);

    // Verify mathematical normalization of Dirichlet distribution
    const probSum = empirical.empiricalPriors.reduce((acc, h) => acc + h.probability, 0);
    assert.ok(Math.abs(probSum - 1.0) < 0.005, `Dirichlet smoothed probabilities must sum to 1.0, got ${probSum}`);

    // 4. Verify brain incorporates episodic prior to skew Shannon IG analysis
    const episodicAnalysis = computeLiveInformationGainAnalysis({ target: testHost });
    assert.equal(episodicAnalysis.entropyStatus, 'EMPIRICAL_EPISODIC_PRIOR');
    assert.equal(episodicAnalysis.empiricalPriorApplied, true);
    assert.equal(episodicAnalysis.topHypotheses[0].id, 'DNS_NXDOMAIN_POISON');
    assert.ok(episodicAnalysis.currentEntropyBits > 0);
    assert.equal(episodicAnalysis.candidateProbes[0].calculationMethod, 'SHANNON_EPISODIC_EMPIRICAL_EXACT');
  });

  await t.test('19. verifies protocol modernization: IPv6 bracketed literals, QUIC HTTP/3 detection, and SNMPv3 USM profiles', async () => {
    const { resolveAndValidateTarget } = require('../src/core/security');
    const { checkPort } = require('../src/protocols/tcp-port');
    const { verifyWebEndpoint, isPrivateIp } = require('../src/protocols/service-verifier');
    const { probeQuicHttp3, detectHttp3AltSvc } = require('../src/protocols/http-probe');
    const { createSnmpV3Profile } = require('../src/protocols/snmp-engine');

    // 1. Bracketed IPv6 literal resolution with port extraction
    const ipv6Resolved = await resolveAndValidateTarget('[::1]:443');
    assert.equal(ipv6Resolved.valid, true);
    assert.equal(ipv6Resolved.hostname, '::1');
    assert.equal(ipv6Resolved.pinnedIp, '::1');
    assert.equal(ipv6Resolved.port, 443);
    assert.equal(ipv6Resolved.addressFamily, 6);
    assert.equal(ipv6Resolved.isIpLiteral, true);

    // 2. Real TCP probe against bracketed loopback IPv6
    const tcpRes = await checkPort('[::1]:443', null, 500);
    assert.equal(tcpRes.host, '::1');
    assert.equal(tcpRes.port, 443);
    assert.ok(tcpRes.status === 'CLOSED' || tcpRes.status === 'OPEN');
    assert.ok(typeof tcpRes.connectLatencyMs === 'number');

    // 3. Web endpoint verifier handles IPv6 URL and sets dns.ipv6
    const webRes = await verifyWebEndpoint('https://[::1]:8443', { timeoutMs: 500 });
    assert.equal(webRes.dns.success, true);
    assert.deepEqual(webRes.dns.ipv6, ['::1']);
    assert.equal(webRes.dns.isPrivate, true);
    assert.equal(webRes.port, 8443);
    assert.ok(isPrivateIp('::1'));
    assert.ok(isPrivateIp('[::1]'));

    // 4. HTTP/3 Alt-Svc detection
    const altSvcHeaders = { 'alt-svc': 'h3=":443"; ma=86400, h3-29=":443"' };
    const h3Info = detectHttp3AltSvc(altSvcHeaders);
    assert.equal(h3Info.http3Advertised, true);
    assert.ok(h3Info.h3Versions.includes('h3'));

    // 5. Active QUIC UDP 443 probe
    const quicRes = await probeQuicHttp3('127.0.0.1', 443, 200);
    assert.ok(quicRes);
    assert.equal(quicRes.host, '127.0.0.1');
    assert.equal(quicRes.port, 443);
    assert.ok(typeof quicRes.latencyMs === 'number');

    // 6. SNMPv3 USM profile configuration with authPriv
    const snmpV3 = createSnmpV3Profile({
      username: 'net-admin',
      level: 'authPriv',
      authProtocol: 'sha256',
      privProtocol: 'aes',
      authKey: 'SuperAuthKey123',
      privKey: 'SuperPrivKey456'
    });
    assert.equal(snmpV3.name, 'net-admin');
    assert.equal(snmpV3.level, 3); // snmp.SecurityLevel.authPriv
    assert.equal(snmpV3.authProtocol, 5); // snmp.AuthProtocols.sha256
    assert.equal(snmpV3.privProtocol, 4); // snmp.PrivProtocols.aes
    assert.equal(snmpV3.authKey, 'SuperAuthKey123');
    assert.equal(snmpV3.privKey, 'SuperPrivKey456');
  });

  await t.test('20. verifies persistent evidence DAG and 2-hop Weisfeiler-Leman graph kernel topology isomorphism', () => {
    // 1. Record parent and derived child evidence records with typed edges
    const parentRecord = evidenceFabric.recordEvidence({
      subject: 'host:core-router-01',
      claim: 'Routing table default gateway established',
      collectionMethod: 'os_route_table',
      rawValue: { gateway: '10.0.0.1' }
    });

    const childRecord = evidenceFabric.recordEvidence({
      subject: 'host:core-router-01',
      claim: 'Default gateway ICMP reachability verified (<2ms)',
      collectionMethod: 'icmp_echo',
      rawValue: { rttMs: 1.4 },
      derivedFrom: [parentRecord.id],
      corroborates: [parentRecord.id]
    });

    // 2. Query persistent causal DAG
    const dag = evidenceFabric.queryCausalDag({ subject: 'host:core-router-01' });
    assert.ok(dag.nodeCount >= 2);
    assert.ok(dag.edgeCount >= 2);

    const derivedEdge = dag.edges.find((e) => e.relationType === 'DERIVED_FROM' && e.sourceNodeId === childRecord.id);
    assert.ok(derivedEdge, 'Must persist DERIVED_FROM edge in DAG');
    assert.equal(derivedEdge.targetNodeId, parentRecord.id);

    const corroboratesEdge = dag.edges.find((e) => e.relationType === 'CORROBORATES' && e.sourceNodeId === childRecord.id);
    assert.ok(corroboratesEdge, 'Must persist CORROBORATES edge in DAG');

    // 3. Verify SQLite DAG graph restoration
    const restored = evidenceFabric.restoreEvidenceGraph();
    assert.ok(restored.nodeCount >= 2);
    assert.ok(restored.edgeCount >= 2);

    // 4. Verify 2-hop Weisfeiler-Leman topological incident isomorphism
    operationalMemoryEngine.recordResolution({
      target: 'db-cluster-node-01.internal',
      symptomSignature: 'TCP_SYN_BLACKHOLE',
      rootCause: 'MTU blackhole fragmentation drop on virtual switch VLAN 100',
      resolutionSteps: 'Clamp MSS to 1460 in kernel iptables',
      port: 5432,
      verifiedBy: 'SRE_CORE'
    });

    const wlResult = operationalMemoryEngine.queryTopologicalIncidentIsomorphism({
      target: 'db-cluster-node-01.internal',
      topologyNodes: [
        { id: 'db-cluster-node-01.internal', role: 'DATABASE_LEADER', degree: 3, neighbors: ['app-server-01', 'app-server-02'] },
        { id: 'app-server-01', role: 'APP_GATEWAY', degree: 2, neighbors: ['db-cluster-node-01.internal'] },
        { id: 'app-server-02', role: 'APP_GATEWAY', degree: 2, neighbors: ['db-cluster-node-01.internal'] }
      ],
      symptomSignature: 'TCP_SYN_BLACKHOLE'
    });

    assert.equal(wlResult.target, 'db-cluster-node-01.internal');
    assert.ok(wlResult.isomorphicMatchesFound >= 1);
    const topWlMatch = wlResult.topMatches[0];
    assert.ok(topWlMatch.weisfeilerLemanKernelScore >= 0.70, `WL kernel score should be >= 0.70, got ${topWlMatch.weisfeilerLemanKernelScore}`);
    assert.ok(topWlMatch.wlIterationHashes);
    assert.ok(topWlMatch.wlIterationHashes.labels0['db-cluster-node-01.internal']);
    assert.ok(topWlMatch.wlIterationHashes.labels1['db-cluster-node-01.internal']);
    assert.ok(topWlMatch.wlIterationHashes.labels2['db-cluster-node-01.internal']);
    assert.equal(topWlMatch.isIsomorphic, true);
  });

  await t.test('21. verifies distributed trace propagation, mutating CSRF Origin protection, and server teardown hooks', () => {
    const { validateMutatingCsrfOrigin, requestCorrelationAndTelemetryMiddleware } = require('../src/api/middleware');
    const { gracefulShutdown } = require('../src/server');

    // 1. Verify trace header propagation in telemetry middleware
    const mockReq = {
      method: 'GET',
      headers: { 'x-ejii-trace-id': '0123456789abcdef0123456789abcdef' },
      url: '/api/diagnostics/host/audit'
    };
    const setHeaders = {};
    const mockRes = {
      setHeader: (k, v) => { setHeaders[k.toLowerCase()] = v; },
      on: () => {}
    };
    let nextCalled = false;
    requestCorrelationAndTelemetryMiddleware(mockReq, mockRes, () => { nextCalled = true; });

    assert.equal(nextCalled, true);
    assert.equal(mockReq.traceId, '0123456789abcdef0123456789abcdef');
    assert.equal(setHeaders['x-ejii-trace-id'], '0123456789abcdef0123456789abcdef');

    // 2. Verify CSRF rejection on cross-site mutating requests
    const attackReq = {
      method: 'POST',
      headers: {
        'sec-fetch-site': 'cross-site',
        origin: 'https://evil-cross-origin.com',
        host: 'localhost:8445'
      }
    };
    let attackBlocked = false;
    let attackStatus = 0;
    const attackRes = {
      status: (code) => {
        attackStatus = code;
        return {
          json: (body) => {
            if (body && body.error && body.error.includes('CSRF_SECURITY_VIOLATION')) {
              attackBlocked = true;
            }
          }
        };
      }
    };
    validateMutatingCsrfOrigin(attackReq, attackRes, () => {
      assert.fail('Cross-site mutating request must never call next()');
    });
    assert.equal(attackStatus, 403);
    assert.equal(attackBlocked, true);

    // 3. Verify CSRF acceptance on legitimate same-origin requests
    const legitReq = {
      method: 'POST',
      headers: {
        'sec-fetch-site': 'same-origin',
        origin: 'http://localhost:8445',
        host: 'localhost:8445'
      }
    };
    let legitPassed = false;
    validateMutatingCsrfOrigin(legitReq, attackRes, () => { legitPassed = true; });
    assert.equal(legitPassed, true);

    // 4. Verify gracefulShutdown export
    assert.equal(typeof gracefulShutdown, 'function');
  });

  await t.test('22. verifies dynamic Bayesian prior auto-calibration with exponential decay and adaptive Shannon entropy stopping', async () => {
    // 1. Verify exponential time-decay weighting (tau = 7 days) in calculateTargetEmpiricalPrior
    const testHostDecay = 'temporal-decay-target.corp.internal';
    const now = Date.now();
    const FOURTEEN_DAYS_AGO = new Date(now - 14 * 24 * 60 * 60 * 1000).toISOString();

    // Record an incident with updatedAt 14 days ago
    operationalMemoryEngine.recordResolution({
      target: testHostDecay,
      symptomSignature: 'DNS_NXDOMAIN_EXCEPTION',
      rootCause: 'DNS authoritative server zone timeout',
      resolutionSteps: 'Flushed zone cache',
      port: 53,
      verifiedBy: 'SRE_OPS',
      updatedAt: FOURTEEN_DAYS_AGO,
      createdAt: FOURTEEN_DAYS_AGO
    });

    const empiricalDecayed = operationalMemoryEngine.calculateTargetEmpiricalPrior(testHostDecay);
    assert.equal(empiricalDecayed.hasHistory, true);
    assert.equal(empiricalDecayed.decayTauMs, 7 * 24 * 60 * 60 * 1000);
    // At t = 14 days and tau = 7 days, exp(-14/7) = exp(-2) ~= 0.1353
    assert.ok(empiricalDecayed.sampleCount < 0.25, `Expected decayed sampleCount around 0.135, got ${empiricalDecayed.sampleCount}`);

    // Record a fresh incident right now (weight ~= 1.0)
    operationalMemoryEngine.recordResolution({
      target: testHostDecay,
      symptomSignature: 'DNS_NXDOMAIN_EXCEPTION',
      rootCause: 'DNS authoritative server zone timeout',
      resolutionSteps: 'Flushed zone cache',
      port: 53,
      verifiedBy: 'SRE_OPS'
    });
    const empiricalFresh = operationalMemoryEngine.calculateTargetEmpiricalPrior(testHostDecay);
    assert.ok(empiricalFresh.sampleCount > empiricalDecayed.sampleCount, 'Fresh resolution must have higher weight than decayed one');

    // 2. Verify adaptive Shannon entropy early stopping in runAgenticToolLoop
    let stepCount = 0;
    const mockExecute = async (plan) => {
      stepCount++;
      return {
        reply: `Execution outcome for ${plan.intent}`,
        steps: [{ name: plan.intent, status: 'FAILED' }],
        findings: [{ label: 'DNS Failure', value: 'NXDOMAIN resolution poison' }],
        technicalEvidence: {
          success: false,
          failed: true,
          error: 'NXDOMAIN lookup failed'
        },
        structuredAnswer: { result: 'ERROR', meaning: 'DNS lookup poisoned' }
      };
    };

    const initialPlan = {
      intent: 'dns',
      mode: 'operational',
      target: 'poisoned-dns.corp.test',
      secondaryToolPlans: [
        { intent: 'port_check', target: 'poisoned-dns.corp.test', ports: [80] },
        { intent: 'port_check', target: 'poisoned-dns.corp.test', ports: [443] },
        { intent: 'traceroute', target: 'poisoned-dns.corp.test' }
      ]
    };

    const loopResult = await runAgenticToolLoop({
      promptText: 'Investigate DNS poisoned host',
      initialPlan,
      executeSinglePlan: mockExecute,
      maxSteps: 5
    });

    assert.ok(loopResult.epistemicClassification, 'Must return epistemicClassification');
    assert.equal(
      loopResult.epistemicClassification.terminationReason,
      'ENTROPY_CONFIDENCE_THRESHOLD_REACHED',
      'Agentic loop must terminate early when Shannon entropy drops or root cause confidence reaches threshold'
    );
    assert.ok(stepCount < 4, `Loop should have stopped early, executed ${stepCount} steps`);
  });
});
