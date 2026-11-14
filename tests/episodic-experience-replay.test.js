'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const EventEmitter = require('node:events');
const { operationalMemoryEngine } = require('../src/core/memory/operational-memory-engine');
const { EpisodicCausalMemoryEngine } = require('../src/ai/episodic-causal-memory-engine');

test('Track 5: Event-Driven Episodic Memory Bus & Universal Experience Replay', async (t) => {
  await t.test('1. verifies operationalMemoryEngine is an EventEmitter instance', () => {
    assert.ok(operationalMemoryEngine instanceof EventEmitter, 'Must be an EventEmitter instance');
    assert.equal(typeof operationalMemoryEngine.on, 'function');
    assert.equal(typeof operationalMemoryEngine.emit, 'function');
  });

  await t.test('2. verifies recordVerifiedResolution emits INCIDENT_RESOLUTION_COMMITTED and indexes into episodic memory', async () => {
    let capturedEvent = null;
    const testListener = (record) => {
      capturedEvent = record;
    };

    operationalMemoryEngine.on('INCIDENT_RESOLUTION_COMMITTED', testListener);

    const testTarget = 'app-tier-01.infra.corp';
    const resolution = operationalMemoryEngine.recordVerifiedResolution({
      target: testTarget,
      symptomSignature: 'DNS_NXDOMAIN_FAILURE',
      rootCause: 'DNS Resolver Service Deadlock',
      resolutionSteps: 'RESTART_SYSTEMD_RESOLVED',
      verifiedBy: 'sre-lead'
    });

    assert.ok(resolution);
    assert.ok(capturedEvent, 'Event must be emitted on memory bus');
    assert.equal(capturedEvent.resolutionId, resolution.resolutionId);
    assert.equal(capturedEvent.targetKey, testTarget);
    assert.equal(capturedEvent.symptomSignature, 'DNS_NXDOMAIN_FAILURE');
    assert.equal(capturedEvent.rootCause, 'DNS Resolver Service Deadlock');

    operationalMemoryEngine.removeListener('INCIDENT_RESOLUTION_COMMITTED', testListener);
  });

  await t.test('3. verifies recordOperationalDecision emits OPERATIONAL_DECISION_COMMITTED', () => {
    let capturedDecision = null;
    const decisionListener = (decision) => {
      capturedDecision = decision;
    };

    operationalMemoryEngine.on('OPERATIONAL_DECISION_COMMITTED', decisionListener);

    const decision = operationalMemoryEngine.recordOperationalDecision({
      target: 'lb-gateway.infra.corp',
      decisionType: 'GOVERNED_REMEDIATION',
      actionId: 'RECYCLE_TCP_TIME_WAIT',
      rationale: 'High socket exhaustion detected on reverse proxy',
      approvedBy: 'sre-operator',
      role: 'ADMIN',
      outcomeStatus: 'APPLIED_AND_VERIFIED',
      beforeMetrics: { openSockets: 65000 },
      afterMetrics: { openSockets: 1200 }
    });

    assert.ok(decision);
    assert.ok(capturedDecision, 'Decision event must be emitted on memory bus');
    assert.equal(capturedDecision.actionId, 'RECYCLE_TCP_TIME_WAIT');
    assert.equal(capturedDecision.targetKey, 'lb-gateway.infra.corp');

    operationalMemoryEngine.removeListener('OPERATIONAL_DECISION_COMMITTED', decisionListener);
  });

  await t.test('4. verifies replayHistoricalExperiences computes composite similarity and recommends runbook', () => {
    const replay = operationalMemoryEngine.replayHistoricalExperiences({
      target: 'app-tier-01.infra.corp',
      failureLayer: 'DNS',
      symptomSignature: 'DNS_NXDOMAIN_FAILURE',
      topK: 3
    });

    assert.ok(replay, 'Replay result must exist');
    assert.equal(replay.queryTarget, 'app-tier-01.infra.corp');
    assert.equal(replay.queryDomain, 'DNS');
    assert.ok(Array.isArray(replay.topExperiences));
    assert.ok(replay.topExperiences.length > 0, 'Must surface historical experiences');

    const top = replay.bestMatch;
    assert.ok(top, 'Best match must exist');
    assert.ok(typeof top.compositeSimilarity === 'number');
    assert.ok(top.compositeSimilarity > 0, 'Composite similarity must be positive');
    assert.ok(top.provenRemediationRunbook, 'Must recommend a proven remediation runbook');
    assert.ok(replay.experienceReplayConfidence > 0);
  });

  await t.test('5. verifies topology-aware replay merges Weisfeiler-Leman graph kernel into composite ranking', () => {
    const topologyNodes = [
      { id: 'app-tier-01.infra.corp', role: 'APP_GATEWAY', status: 'CRITICAL' },
      { id: 'dns-resolver-01', role: 'DNS_SERVER', status: 'FAILED' }
    ];

    const replay = operationalMemoryEngine.replayHistoricalExperiences({
      target: 'app-tier-01.infra.corp',
      failureLayer: 'DNS',
      topologyNodes,
      topK: 5
    });

    assert.ok(replay.topExperiences.length > 0);
    for (const exp of replay.topExperiences) {
      assert.ok(typeof exp.topologicalSimilarity === 'number');
      assert.ok(typeof exp.cosineSimilarity === 'number');
      assert.ok(typeof exp.domainMatchScore === 'number');
      assert.ok(exp.compositeSimilarity >= exp.topologicalSimilarity * 0.35);
    }
  });

  await t.test('6. verifies _inferRootCauseDomain correctly maps domain categories', () => {
    assert.equal(operationalMemoryEngine._inferRootCauseDomain('DNS lookup failed', 'SERVFAIL'), 'DNS');
    assert.equal(operationalMemoryEngine._inferRootCauseDomain('TCP Connection Reset', 'RST flag received'), 'TCP');
    assert.equal(operationalMemoryEngine._inferRootCauseDomain('Gateway Timeout', '504 Bad Gateway'), 'HTTP');
    assert.equal(operationalMemoryEngine._inferRootCauseDomain('Certificate Expired', 'TLS handshake error'), 'TLS');
    assert.equal(operationalMemoryEngine._inferRootCauseDomain('Host Unreachable', 'ICMP Type 3'), 'ICMP');
    assert.equal(operationalMemoryEngine._inferRootCauseDomain('Socket exhaustion', 'EMFILE error'), 'SOCKETS');
  });
});
