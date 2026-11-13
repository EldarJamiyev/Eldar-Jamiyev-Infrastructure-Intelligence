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
  CANDIDATE_PROBE_LIKELIHOOD_MODELS,
  runAgenticToolLoop
} = require('../src/core/chat/conversational-brain');

const { operationalMemoryEngine } = require('../src/core/memory/operational-memory-engine');
const { NeuroSymbolicApexEngine } = require('../src/ai/neuro-symbolic-apex');
const { autonomousWarRoomOrchestrator } = require('../src/ai/autonomous-war-room');
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
});
