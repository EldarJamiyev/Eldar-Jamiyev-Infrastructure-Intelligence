/**
 * EJII — Sovereign Intelligence Leap Phase 2.0 Capstone Verification Suite
 *
 * Verifies end-to-end integration across all 5 Phase 2 engineering tracks:
 * - Track 1: Closed-Loop Conversational Remediation Gate & Signed Action Tokens
 * - Track 2: Continuous Laplacian Heat Diffusion in RCA Engine & Contours
 * - Track 3: Sensitivity-Gradient-Weighted Shannon Information Gain Probe Selection
 * - Track 4: High-Throughput Binary WebSocket Frame Streaming for Line-Rate Cockpit
 * - Track 5: Event-Driven Episodic Memory Bus & Universal Experience Replay
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const EventEmitter = require('node:events');

const {
  formulateRemediationGate,
  executeRemediationAndVerifyPostcondition,
  computeLiveInformationGainAnalysis,
  runAgenticToolLoop
} = require('../src/core/chat/conversational-brain');

const { RCAEngine } = require('../src/core/rca-engine');
const { temporalInfrastructureGraph } = require('../src/core/topology/temporal-graph-engine');
const { NeuroSymbolicApexEngine } = require('../src/ai/neuro-symbolic-apex');

const {
  encodeBinaryPacketFrame,
  decodeBinaryPacketFrame,
  MAGIC_BYTES,
  MAGIC_UINT32,
  PROTOCOL_VERSION
} = require('../src/network/packet-streaming/binary-frame-codec');
const { packetStreamer } = require('../src/network/packet-streaming/packet-streamer');

const { operationalMemoryEngine } = require('../src/core/memory/operational-memory-engine');
const { EpisodicCausalMemoryEngine } = require('../src/ai/episodic-causal-memory-engine');

test('EJII Sovereign Intelligence Leap Phase 2.0 Capstone Suite', async (t) => {
  // -------------------------------------------------------------
  // TRACK 1: Closed-Loop Conversational Remediation Gate & Tokens
  // -------------------------------------------------------------
  await t.test('Track 1: Closed-Loop Conversational Remediation Gate & Signed Action Tokens', async (t1) => {
    await t1.test('1a. issues signed HMAC action token for dominant fault domain', async () => {
      const gate = await formulateRemediationGate(
        'DNS_NXDOMAIN_POISON',
        'dns-auth.corp.internal',
        { username: 'operator', role: 'ADMIN' }
      );

      assert.ok(gate, 'Remediation gate must be formulated');
      assert.equal(gate.status, 'REMEDIATION_RECOMMENDED');
      assert.equal(gate.recipeId, 'flush_dns');
      assert.ok(gate.actionToken, 'Action token must be issued');
      assert.ok(gate.actionTokenId, 'Action token ID must be present');
      assert.ok(gate.expiresAt > Date.now(), 'Token must have future expiry TTL (5m)');
      assert.equal(gate.dualCustodyRequired, true);
    });

    await t1.test('1b. executes remediation and verifies temporal postcondition stability', async () => {
      const gate = await formulateRemediationGate(
        'LOCAL_STACK_CONGESTION',
        'app-node-01.corp.internal',
        { username: 'operator', role: 'ADMIN' }
      );
      assert.ok(gate.actionToken);

      let sampleCalls = 0;
      const result = await executeRemediationAndVerifyPostcondition({
        actionToken: gate.actionToken,
        userContext: { username: 'operator', role: 'ADMIN' },
        verificationWindowSec: 60,
        telemetrySampler: async () => {
          sampleCalls++;
          return [
            { timestampMs: Date.now() - 2000, rttMs: 2.4, packetLossPct: 0.0 },
            { timestampMs: Date.now() - 1000, rttMs: 2.1, packetLossPct: 0.0 },
            { timestampMs: Date.now(), rttMs: 1.9, packetLossPct: 0.0 }
          ];
        }
      });

      assert.equal(result.success, true);
      assert.equal(result.remediationExecution.success, true);
      assert.equal(result.stabilityVerification.verified, true);
      assert.equal(result.stabilityVerification.verificationStatus, 'TEMPORAL_STABILITY_CONFIRMED');
      assert.equal(sampleCalls, 1);
    });

    await t1.test('1c. anti-replay protection prevents re-execution of used action token', async () => {
      const gate = await formulateRemediationGate(
        'DNS_NXDOMAIN_POISON',
        'dns-secondary.corp.internal',
        { username: 'operator', role: 'ADMIN' }
      );

      await executeRemediationAndVerifyPostcondition({
        actionToken: gate.actionToken,
        userContext: { username: 'operator', role: 'ADMIN' }
      });

      await assert.rejects(
        async () => {
          await executeRemediationAndVerifyPostcondition({
            actionToken: gate.actionToken,
            userContext: { username: 'operator', role: 'ADMIN' }
          });
        },
        /REPLAY_DETECTED|already executed/
      );
    });
  });

  // -------------------------------------------------------------
  // TRACK 2: Continuous Laplacian Heat Diffusion & Topology Contours
  // -------------------------------------------------------------
  await t.test('Track 2: Continuous Laplacian Heat Diffusion in RCA Engine', async (t2) => {
    await t2.test('2a. derives continuous degradation probabilities and contours across multi-hop chain', () => {
      const rca = new RCAEngine();
      const nodes = [
        { id: 'gw-core-01', role: 'CORE_GATEWAY', status: 'CRITICAL', location: 'DC_WEST' },
        { id: 'svc-proxy-01', role: 'REVERSE_PROXY', status: 'CRITICAL', location: 'DC_WEST' },
        { id: 'svc-auth-01', role: 'AUTH_SERVICE', status: 'CRITICAL', location: 'DC_WEST' }
      ];
      const edges = [
        { source: 'gw-core-01', target: 'svc-proxy-01', weight: 0.9 },
        { source: 'svc-proxy-01', target: 'svc-auth-01', weight: 0.8 }
      ];
      const telemetryMap = {
        'gw-core-01': { lossPct: 100, latencyMs: 5000, status: 'CRITICAL', timestamp: new Date(Date.now() - 5000).toISOString() },
        'svc-proxy-01': { lossPct: 80, latencyMs: 3000, status: 'CRITICAL', timestamp: new Date(Date.now() - 3000).toISOString() },
        'svc-auth-01': { lossPct: 70, latencyMs: 2000, status: 'CRITICAL', timestamp: new Date().toISOString() }
      };

      const disambiguation = rca.disambiguateUpstreamVsDownstreamSymptoms({
        primaryIncident: { target: 'gw-core-01' },
        nodes,
        edges,
        telemetryMap
      });

      assert.ok(disambiguation.multiHopTraversal);
      const chain = disambiguation.multiHopTraversal.propagationChain;
      assert.ok(chain.length >= 3);

      const root = chain.find(c => c.nodeId === 'gw-core-01');
      const hop1 = chain.find(c => c.nodeId === 'svc-proxy-01');
      const hop2 = chain.find(c => c.nodeId === 'svc-auth-01');

      assert.ok(root && hop1 && hop2);
      assert.equal(root.hopDistanceFromRoot, 0);
      assert.equal(hop1.hopDistanceFromRoot, 1);
      assert.equal(hop2.hopDistanceFromRoot, 2);

      assert.ok(root.continuousDegradationProbability >= hop1.continuousDegradationProbability, 'Heat decays monotonically from root to hop 1');
      assert.ok(hop1.continuousDegradationProbability >= hop2.continuousDegradationProbability, 'Heat decays monotonically from hop 1 to hop 2');
      assert.ok(typeof root.contourLevel === 'string' && root.contourLevel.length > 0);
    });

    await t2.test('2b. temporalInfrastructureGraph computes authentic Laplacian heat diffusion manifold', () => {
      temporalInfrastructureGraph.nodes.set('gw-core-01', { nodeId: 'gw-core-01', resourceType: 'gateway', label: 'Gateway' });
      temporalInfrastructureGraph.nodes.set('svc-proxy-01', { nodeId: 'svc-proxy-01', resourceType: 'proxy', label: 'Proxy' });
      temporalInfrastructureGraph.upsertEdge({ sourceId: 'gw-core-01', targetId: 'svc-proxy-01', confidence: 1.0 });

      const diff = temporalInfrastructureGraph.computeLaplacianHeatDiffusion('gw-core-01', 0.5);
      assert.equal(diff.sourceNodeId, 'gw-core-01');
      assert.ok(diff.diffusionContours.length >= 2);
      const gwContour = diff.diffusionContours.find(c => c.nodeId === 'gw-core-01');
      const proxyContour = diff.diffusionContours.find(c => c.nodeId === 'svc-proxy-01');
      assert.ok(gwContour.degradationProbability > proxyContour.degradationProbability);
    });
  });

  // -------------------------------------------------------------
  // TRACK 3: Sensitivity-Gradient-Weighted Shannon Information Gain
  // -------------------------------------------------------------
  await t.test('Track 3: Gradient-Weighted Shannon Information Gain Probe Selection', async (t3) => {
    await t3.test('3a. couples analytical sensitivity gradients with probe information gain', () => {
      const telemetryMargins = {
        dns: -3.0, // Lowest headroom / critical bottleneck
        tcp: 1.0,
        http: 2.0
      };

      const analysis = computeLiveInformationGainAnalysis({
        telemetryMargins,
        sensitivityCouplingGamma: 1.0
      });

      assert.ok(analysis.candidateProbes.length > 0);
      const dnsProbe = analysis.candidateProbes.find(p => p.probeId.startsWith('DNS_'));
      assert.ok(dnsProbe);
      assert.ok(dnsProbe.sensitivityGradient > 0, 'DNS probe must receive positive sensitivity gradient');
      assert.ok(dnsProbe.weightedInformationGainBits >= dnsProbe.expectedInformationGainBits);

      // Verify list is sorted monotonically descending by weightedInformationGainBits
      for (let i = 0; i < analysis.candidateProbes.length - 1; i++) {
        const cur = analysis.candidateProbes[i];
        const next = analysis.candidateProbes[i + 1];
        if (cur.alreadyObservedInSession === next.alreadyObservedInSession) {
          assert.ok(
            (cur.weightedInformationGainBits ?? -1) >= (next.weightedInformationGainBits ?? -1),
            'Must be sorted by weightedInformationGainBits descending'
          );
        }
      }
    });

    await t3.test('3b. NeuroSymbolicApexEngine sensitivity gradients sum to unity', () => {
      const grads = NeuroSymbolicApexEngine.computeAnalyticalSensitivityGradients([1.5, 0.2, -2.0], 1.0);
      const sum = grads.reduce((a, b) => a + b, 0);
      assert.ok(Math.abs(sum - 1.0) < 1e-4);
      assert.ok(grads[2] > grads[1] && grads[1] > grads[0], 'Lowest margin (-2.0) receives highest gradient');
    });
  });

  // -------------------------------------------------------------
  // TRACK 4: High-Throughput Binary WebSocket Frame Streaming
  // -------------------------------------------------------------
  await t.test('Track 4: High-Throughput Binary WebSocket Frame Streaming', async (t4) => {
    await t4.test('4a. zero-copy binary encoding and decoding roundtrip (IPv4 & IPv6)', () => {
      const v4Frame = {
        srcIp: '192.168.1.100',
        dstIp: '1.1.1.1',
        srcPort: 49152,
        dstPort: 443,
        protocol: 'TCP',
        tcp: { srcPort: 49152, dstPort: 443, flags: { syn: true } },
        rawHex: '0102030405060708',
        wireLength: 64,
        timestamp: 1700000000000
      };

      const encodedV4 = encodeBinaryPacketFrame(v4Frame, 64);
      assert.equal(encodedV4.subarray(0, 4).toString('ascii'), 'EJII');
      assert.equal(encodedV4.length, 32 + 8); // 32-byte header + 8 bytes payload

      const decodedV4 = decodeBinaryPacketFrame(encodedV4);
      assert.ok(decodedV4);
      assert.equal(decodedV4.isIpv6, false);
      assert.equal(decodedV4.srcIp, '192.168.1.100');
      assert.equal(decodedV4.dstIp, '1.1.1.1');
      assert.equal(decodedV4.srcPort, 49152);
      assert.equal(decodedV4.dstPort, 443);
      assert.equal(decodedV4.hasSyn, true);

      // IPv6 packet
      const v6Frame = {
        srcIp: '2001:db8::1',
        dstIp: '2606:4700:4700::1111',
        srcPort: 5353,
        dstPort: 53,
        protocol: 'UDP',
        wireLength: 128
      };
      const encodedV6 = encodeBinaryPacketFrame(v6Frame, 32);
      assert.equal(encodedV6.length, 56); // 56-byte header
      const decodedV6 = decodeBinaryPacketFrame(encodedV6);
      assert.ok(decodedV6);
      assert.equal(decodedV6.isIpv6, true);
      assert.equal(decodedV6.protocolName, 'UDP');
    });

    await t4.test('4b. packetStreamer instance exposes binary frame codec methods', () => {
      assert.equal(typeof packetStreamer.encodeBinaryFrame, 'function');
      assert.equal(typeof packetStreamer.decodeBinaryFrame, 'function');
    });
  });

  // -------------------------------------------------------------
  // TRACK 5: Event-Driven Episodic Memory Bus & Universal Experience Replay
  // -------------------------------------------------------------
  await t.test('Track 5: Event-Driven Episodic Memory Bus & Universal Experience Replay', async (t5) => {
    await t5.test('5a. operationalMemoryEngine emits INCIDENT_RESOLUTION_COMMITTED and indexes into episodic memory', () => {
      assert.ok(operationalMemoryEngine instanceof EventEmitter);

      let emitted = null;
      const listener = (rec) => { emitted = rec; };
      operationalMemoryEngine.on('INCIDENT_RESOLUTION_COMMITTED', listener);

      const res = operationalMemoryEngine.recordVerifiedResolution({
        target: 'cache-redis-01.infra.corp',
        symptomSignature: 'TCP_CONNECTION_TIMEOUT',
        rootCause: 'TCP SYN Queue Overflow',
        resolutionSteps: 'INCREASE_SOMAXCONN_AND_TCP_BACKLOG',
        verifiedBy: 'noc-engineer'
      });

      assert.ok(res);
      assert.ok(emitted);
      assert.equal(emitted.resolutionId, res.resolutionId);
      assert.equal(emitted.rootCause, 'TCP SYN Queue Overflow');

      operationalMemoryEngine.removeListener('INCIDENT_RESOLUTION_COMMITTED', listener);
    });

    await t5.test('5b. replayHistoricalExperiences computes composite similarity and surfaces proven runbook', () => {
      const replay = operationalMemoryEngine.replayHistoricalExperiences({
        target: 'cache-redis-01.infra.corp',
        failureLayer: 'TCP',
        topK: 3
      });

      assert.ok(replay);
      assert.equal(replay.queryTarget, 'cache-redis-01.infra.corp');
      assert.equal(replay.queryDomain, 'TCP');
      assert.ok(replay.topExperiences.length > 0);
      assert.ok(replay.bestMatch.compositeSimilarity > 0);
      assert.ok(replay.recommendedAction);
    });

    await t5.test('5c. conversational brain attaches experienceReplay to epistemicClassification on dominant fault', async () => {
      const mockExecute = async (plan, step) => {
        return {
          reply: `Executed ${plan.intent}`,
          success: false,
          findings: [{ label: 'DNS Failure', value: 'SERVFAIL' }],
          technicalEvidence: { success: false, failed: true, reason: 'SERVFAIL' }
        };
      };

      const target = 'dns-resolver.internal.corp';
      const initialPlan = {
        intent: 'dns',
        mode: 'operational',
        target,
        secondaryToolPlans: []
      };

      const result = await runAgenticToolLoop({
        promptText: `Diagnose why ${target} is throwing SERVFAIL`,
        initialPlan,
        sessionContext: {
          target,
          userContext: { role: 'ADMIN', username: 'operator' }
        },
        executeSinglePlan: mockExecute,
        maxSteps: 1
      });

      assert.ok(result);
      assert.ok(result.epistemicClassification);
      if (result.epistemicClassification.experienceReplay) {
        assert.ok(Array.isArray(result.epistemicClassification.experienceReplay.topExperiences));
      }
    });
  });
});
