'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const EventEmitter = require('node:events');
const { operationalMemoryEngine } = require('../src/core/memory/operational-memory-engine');
const {
  hierarchicalMemoryConsolidator,
  HierarchicalMemoryConsolidator
} = require('../src/core/memory/hierarchical-memory-consolidator');
const { EpisodicCausalMemoryEngine } = require('../src/ai/episodic-causal-memory-engine');
const { runAgenticToolLoop } = require('../src/core/chat/conversational-brain');

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

  await t.test('7. Phase 9.0 Track 3: Hierarchical memory consolidator groups episodes and achieves >= 85% compaction', () => {
    const consolidator = new HierarchicalMemoryConsolidator();
    consolidator.resetForTesting();

    // Generate 5 episodes for DNS domain with realistic telemetry dumps
    for (let i = 0; i < 5; i++) {
      consolidator.addWorkingMemoryEpisode({
        episodeId: `dns_ep_${i}`,
        targetDomain: 'DNS',
        targetEndpoint: `ns${i}.corp.net`,
        timestampIso: new Date().toISOString(),
        symptomSignature: 'DNS_NXDOMAIN_FAILURE',
        rootCause: 'DNS Resolver Service Deadlock',
        remediationAction: 'RESTART_RESOLVED_SYSTEMD',
        executionOutcome: 'SUCCESS',
        durationMs: 180 + i * 10,
        metricsSnapshot: {
          dnsLatencyMs: 120 + i * 5,
          packetLossPct: 0.5,
          cpuSaturationPct: 85
        },
        topologicalHops: ['gw-01.corp.net', `ns${i}.corp.net`],
        rawTelemetryPayload: {
          traceDump: new Array(50).fill(`DNS Query frame dump socket hex 0x4a82b99c turn_${i}`),
          syslogLines: new Array(20).fill(`systemd-resolved[${1000 + i}]: (DNS) Server failed: NXDOMAIN`)
        }
      });
    }

    assert.equal(consolidator.getWorkingMemoryEpisodes().length, 5);

    const clusters = consolidator.consolidateWorkingMemory({ minGroupSize: 2 });
    assert.equal(clusters.length, 1);
    const cluster = clusters[0];

    assert.equal(cluster.targetDomain, 'DNS');
    assert.equal(cluster.episodeCount, 5);
    assert.equal(cluster.centroidVector.length, 64);
    assert.ok(cluster.compactionRatio >= 0.85, `Compaction ratio must be >= 0.85 (85%), got ${cluster.compactionRatio}`);
    assert.equal(cluster.causalSummary.primarySymptom, 'DNS_NXDOMAIN_FAILURE');
    assert.equal(cluster.causalSummary.resolvedRootCause, 'DNS Resolver Service Deadlock');
    assert.equal(cluster.causalSummary.effectiveRemediation, 'RESTART_RESOLVED_SYSTEMD');
    assert.equal(cluster.causalSummary.successRate, 1.0);
    assert.equal(consolidator.getWorkingMemoryEpisodes().length, 0, 'Consolidated episodes must be cleared from working memory');
  });

  await t.test('8. Phase 9.0 Track 3: Dual-tier unified retrieval surfaces working memory and consolidated clusters', () => {
    const consolidator = new HierarchicalMemoryConsolidator();
    consolidator.resetForTesting();

    // 1. Add older consolidated cluster
    for (let i = 0; i < 4; i++) {
      consolidator.addWorkingMemoryEpisode({
        episodeId: `tcp_ep_${i}`,
        targetDomain: 'TCP',
        targetEndpoint: 'edge-router-01',
        timestampIso: new Date(Date.now() - 3600000).toISOString(),
        symptomSignature: 'TCP_RETRANSMIT_SPIKE',
        rootCause: 'NIC Ring Buffer Congestion',
        remediationAction: 'EXPAND_ETHTOOL_RX_RING',
        executionOutcome: 'SUCCESS',
        durationMs: 300,
        metricsSnapshot: {
          rttMs: 85.0,
          tcpRetransmitRate: 0.12,
          packetLossPct: 3.2
        },
        rawTelemetryPayload: { logs: ['retransmit spike on eth0'] }
      });
    }
    consolidator.consolidateWorkingMemory({ minGroupSize: 2 });

    // 2. Add hot working memory episode
    consolidator.addWorkingMemoryEpisode({
      episodeId: 'hot_ep_recent',
      targetDomain: 'HTTP',
      targetEndpoint: 'api-gateway',
      timestampIso: new Date().toISOString(),
      symptomSignature: 'HTTP_504_GATEWAY_TIMEOUT',
      rootCause: 'Upstream Pool Exhaustion',
      remediationAction: 'SCALE_UPSTREAM_PODS',
      executionOutcome: 'SUCCESS',
      durationMs: 150,
      metricsSnapshot: { httpTtfbMs: 4500, httpErrorRate5xx: 0.25 }
    });

    const searchResult = consolidator.queryHierarchicalMemory('TCP retransmit packet loss incident history', {
      topK: 5,
      minSimilarity: 0.20
    });

    assert.ok(searchResult);
    assert.ok(searchResult.totalMatches >= 1);
    const tcpMatch = searchResult.matches.find((m) => m.targetDomain === 'TCP');
    assert.ok(tcpMatch, 'Must find consolidated TCP cluster');
    assert.equal(tcpMatch.memoryTier, 'TIER2_CONSOLIDATED');
    assert.ok(tcpMatch.similarity > 0.40);

    const httpResult = consolidator.queryHierarchicalMemory('HTTP 504 timeout', { topK: 3 });
    const httpMatch = httpResult.matches.find((m) => m.targetDomain === 'HTTP');
    assert.ok(httpMatch);
    assert.equal(httpMatch.memoryTier, 'TIER1_WORKING');
  });

  await t.test('9. Phase 9.0 Track 3: runAgenticToolLoop attaches hierarchicalMemoryRecall for historical recall queries', async () => {
    const outcome = await runAgenticToolLoop({
      promptText: 'what is the prior incident history and learned cluster for DNS NXDOMAIN?',
      initialPlan: { intent: 'host_metrics', target: '10.0.0.1', mode: 'operational' },
      executeSinglePlan: async () => ({
        reply: 'Domain diagnostics completed.',
        technicalEvidence: { rttMs: 25.0 },
        structuredAnswer: { result: 'OK' }
      }),
      sessionContext: {
        enableHierarchicalRecall: true
      },
      maxSteps: 1
    });

    assert.ok(outcome.epistemicClassification);
    assert.ok(outcome.epistemicClassification.hierarchicalMemoryRecall, 'hierarchicalMemoryRecall must be attached');
    assert.ok(outcome.epistemicClassification.hierarchicalMemoryRecall.totalMatches >= 1);
  });
});
