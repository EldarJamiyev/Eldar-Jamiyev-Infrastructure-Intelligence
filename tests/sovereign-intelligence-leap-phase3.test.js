/**
 * EJII — Sovereign Intelligence Leap Phase 3.0 Capstone Verification Suite
 *
 * Verifies end-to-end integration across all 5 Phase 3 engineering tracks:
 * - Track 1: Closed-Loop Autonomous Rollback Watchdog & Control Barrier Safety Invariants (CBF)
 * - Track 2: Dynamic Temporal Granger Causal Discovery Across Telemetry Streams & Bayesian Prior Wiring
 * - Track 3: Socratic Multi-Turn Disambiguation & Active Clarification Loop
 * - Track 4: Line-Rate Binary Packet Cockpit Offscreen Worker & Equipotential Diffusion Shader
 * - Track 5: Episodic Playbook Lifecycle Governance, Degradation Quarantine & Replay Filtering
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  formulateRemediationGate,
  executeRemediationAndVerifyPostcondition,
  evaluateControlBarrierInvariants,
  formulateSocraticClarification,
  applySocraticClarificationResponse,
  computeProbeInformationGainRanking
} = require('../src/core/chat/conversational-brain');

const {
  temporalInfrastructureGraph,
  computeGrangerCausality
} = require('../src/core/topology/temporal-graph-engine');

const {
  OperationalMemoryEngine
} = require('../src/core/memory/operational-memory-engine');

const {
  EpisodicCausalMemoryEngine,
  PLAYBOOK_LIFECYCLE_STATES,
  validatePlaybookLifecycleTransition
} = require('../src/ai/episodic-causal-memory-engine');

const { encodeBinaryPacketFrame } = require('../src/network/packet-streaming/binary-frame-codec');
const { decodeBinaryFrameBuffer } = require('../public/js/workers/packet-binary-decoder-worker');
const {
  evaluateScalarPotential,
  computeEquipotentialField
} = require('../public/js/equipotential-contour-shader');

const { db } = require('../src/db/database');
const { getAuditTrail } = require('../src/core/audit-logger');

test('EJII Sovereign Intelligence Leap Phase 3.0 Capstone Suite', async (t) => {
  // --------------------------------------------------------------------------
  // TRACK 1: Closed-Loop Autonomous Rollback Watchdog & Control Barrier Safety (CBF)
  // --------------------------------------------------------------------------
  await t.test('Track 1: Autonomous Rollback Watchdog & Control Barrier Invariants', async (t1) => {
    await t1.test('1a. Evaluates Control Barrier Invariants (RTT, packet loss, Lyapunov stability)', () => {
      const healthySamples = [
        { timestampMs: 1000, rttMs: 25.0, packetLossPct: 0.0 },
        { timestampMs: 2000, rttMs: 20.0, packetLossPct: 0.0 },
        { timestampMs: 3000, rttMs: 15.0, packetLossPct: 0.0 }
      ];
      const healthyCbf = evaluateControlBarrierInvariants(healthySamples, { maxSafeRttMs: 100, maxSafeLossPct: 2.0 });
      assert.equal(healthyCbf.satisfied, true, 'Healthy samples must satisfy Control Barrier Invariants');
      assert.ok(healthyCbf.minimumMargin > 0, 'Minimum margin must be strictly positive');
      assert.equal(healthyCbf.violatedBarriers.length, 0);

      // Severe latency & loss violation
      const violatingSamples = [
        { timestampMs: 1000, rttMs: 150.0, packetLossPct: 15.0 },
        { timestampMs: 2000, rttMs: 220.0, packetLossPct: 25.0 },
        { timestampMs: 3000, rttMs: 310.0, packetLossPct: 40.0 }
      ];
      const violatingCbf = evaluateControlBarrierInvariants(violatingSamples, { maxSafeRttMs: 100, maxSafeLossPct: 2.0 });
      assert.equal(violatingCbf.satisfied, false, 'Degraded samples must violate Control Barrier Invariants');
      assert.ok(violatingCbf.violatedBarriers.length >= 1);
    });

    await t1.test('1b. Triggers automated rollback and records HMAC audit trail on severe regression', async () => {
      const gate = await formulateRemediationGate(
        'LOCAL_STACK_CONGESTION',
        'host-cbf-capstone.corp.internal',
        { username: 'operator', role: 'ADMIN' }
      );
      assert.ok(gate.actionToken);

      // Telemetry sampler simulating post-action degradation
      const degradedSampler = async () => [
        { timestampMs: Date.now() - 3000, rttMs: 40.0, packetLossPct: 0.0 },
        { timestampMs: Date.now() - 2000, rttMs: 120.0, packetLossPct: 10.0 },
        { timestampMs: Date.now() - 1000, rttMs: 280.0, packetLossPct: 35.0 }
      ];

      const outcome = await executeRemediationAndVerifyPostcondition({
        actionToken: gate.actionToken,
        userContext: { username: 'operator', role: 'ADMIN' },
        verificationWindowSec: 30,
        telemetrySampler: degradedSampler,
        controlBarrierOptions: { maxSafeRttMs: 100, maxSafeLossPct: 5.0 }
      });

      assert.equal(outcome.success, false, 'Overall remediation outcome must fail on CBF violation');
      assert.equal(outcome.controlBarrier.satisfied, false);
      assert.equal(outcome.autonomousRollback.triggered, true, 'Watchdog must trigger autonomous rollback');

      // Verify HMAC audit trail records rollback
      const auditTrail = getAuditTrail(15);
      const rollbackEntry = auditTrail.find((e) => e.action && e.action.includes('AUTONOMOUS_ROLLBACK'));
      assert.ok(rollbackEntry, 'Audit log must record AUTONOMOUS_ROLLBACK on CBF invariant breach');
      assert.ok(rollbackEntry.hash || rollbackEntry.tamperResistantHmac);
    });
  });

  // --------------------------------------------------------------------------
  // TRACK 2: Dynamic Temporal Granger Causal Discovery & Bayesian Prior Wiring
  // --------------------------------------------------------------------------
  await t.test('Track 2: Dynamic Temporal Granger Causal Discovery & Prior Initialization', async (t2) => {
    await t2.test('2a. Validates Granger Causality OLS solver with exact analytical p-value', () => {
      const N = 50;
      const streamX = [];
      const streamY = [10.0, 10.0];

      for (let tIdx = 0; tIdx < N; tIdx++) {
        const xVal = 20.0 + 15.0 * Math.sin(tIdx / 3.0) + (Math.random() - 0.5) * 2.0;
        streamX.push(xVal);
        if (tIdx >= 2) {
          const yVal = 5.0 + 0.3 * streamY[tIdx - 1] + 0.65 * streamX[tIdx - 1] + (Math.random() - 0.5) * 1.5;
          streamY.push(yVal);
        }
      }

      const result = computeGrangerCausality(streamX, streamY, 2, { alpha: 0.05 });
      assert.equal(result.isCausal, true);
      assert.ok(result.fStatistic > result.fCritical, `F-statistic (${result.fStatistic}) must exceed F-crit (${result.fCritical})`);
      assert.ok(result.pValue < 0.05, `p-value (${result.pValue}) must be statistically significant (< 0.05)`);
      assert.ok(result.effectSize > 0.20, `Effect size (${result.effectSize}) must exceed 0.20`);
    });

    const sharedSourceId = `gw-capstone-${Date.now()}`;
    const sharedTargetId = `api-capstone-${Date.now()}`;

    await t2.test('2b. Discovers and upserts causal edge in temporal graph and SQLite WAL', () => {
      const sourceId = sharedSourceId;
      const targetId = sharedTargetId;

      const N = 40;
      const streamX = [];
      const streamY = [2.0, 2.0];
      for (let tIdx = 0; tIdx < N; tIdx++) {
        const xVal = 10.0 + 8.0 * Math.sin(tIdx / 2.5);
        streamX.push(xVal);
        if (tIdx >= 2) {
          const yVal = 1.0 + 0.2 * streamY[tIdx - 1] + 0.7 * streamX[tIdx - 1] + (Math.random() - 0.5) * 0.5;
          streamY.push(yVal);
        }
      }

      const discovery = temporalInfrastructureGraph.discoverAndUpsertCausalEdge({
        sourceId,
        targetId,
        streamX,
        streamY,
        lagOrder: 2,
        sourceLabel: 'Capstone Gateway',
        targetLabel: 'Capstone API Service'
      });

      assert.equal(discovery.isCausal, true);
      assert.equal(discovery.edgeId, `CAUSAL_${sourceId}_${targetId}`);

      // Verify SQLite persistence
      const row = db.prepare('SELECT * FROM temporal_causal_edges WHERE id = ?').get(discovery.edgeId);
      assert.ok(row, 'Causal edge must be persisted in SQLite table');
      assert.equal(row.source_id, sourceId);
      assert.equal(row.target_id, targetId);
      assert.equal(row.is_causal, 1);
    });

    await t2.test('2c. Causal ancestors boost Bayesian prior distribution in information gain analysis', () => {
      const ranking = computeProbeInformationGainRanking([], {
        target: sharedTargetId,
        lastIntent: null
      });

      assert.ok(ranking.causalAncestry, 'Ranking output must include causalAncestry');
      assert.equal(ranking.causalAncestry.applied, true, 'Causal prior boost must be applied');
      assert.ok(ranking.causalAncestry.ancestorCount >= 1, 'At least 1 causal ancestor detected');
    });
  });

  // --------------------------------------------------------------------------
  // TRACK 3: Socratic Multi-Turn Disambiguation & Active Clarification Loop
  // --------------------------------------------------------------------------
  await t.test('Track 3: Socratic Conversational Disambiguation & Active Clarification', async (t3) => {
    await t3.test('3a. Formulates Socratic clarification query when entropy is high', () => {
      const ambiguousHypotheses = [
        { id: 'UPSTREAM_WAN_BLACKHOLE', name: 'Upstream Transit WAN Blackhole', probability: 0.42, percentage: 42.0 },
        { id: 'FIREWALL_ACL_DROP', name: 'Layer 3/4 Firewall Egress ACL Drop', probability: 0.38, percentage: 38.0 },
        { id: 'LOCAL_STACK_CONGESTION', name: 'Host OS Stack Congestion', probability: 0.20, percentage: 20.0 }
      ];

      const clarification = formulateSocraticClarification(
        ambiguousHypotheses,
        'Diagnose packet loss spike',
        { probesExhausted: true, entropyThreshold: 1.2 }
      );

      assert.equal(clarification.required, true);
      assert.ok(clarification.entropyBits >= 1.2);
      assert.ok(clarification.socraticQuestion);
      assert.ok(Array.isArray(clarification.disambiguationOptions));
      assert.ok(clarification.disambiguationOptions.length >= 3);
    });

    await t3.test('3b. Collapses Shannon entropy upon receiving disambiguation answer', () => {
      const priorDistribution = [
        { id: 'UPSTREAM_WAN_BLACKHOLE', name: 'Upstream Transit WAN Blackhole', probability: 0.42, percentage: 42.0 },
        { id: 'FIREWALL_ACL_DROP', name: 'Layer 3/4 Firewall Egress ACL Drop', probability: 0.38, percentage: 38.0 },
        { id: 'LOCAL_STACK_CONGESTION', name: 'Host OS Stack Congestion', probability: 0.20, percentage: 20.0 }
      ];

      const updateResult = applySocraticClarificationResponse(
        priorDistribution,
        'UPSTREAM_WAN_BLACKHOLE',
        0.95
      );

      assert.equal(updateResult.confirmedHypothesisId, 'UPSTREAM_WAN_BLACKHOLE');
      assert.equal(updateResult.collapsed, true);
      assert.ok(updateResult.entropyBits < 0.8);

      const confirmed = updateResult.hypotheses.find((h) => h.id === 'UPSTREAM_WAN_BLACKHOLE');
      assert.ok(confirmed);
      assert.ok(confirmed.probability >= 0.85);
    });
  });

  // --------------------------------------------------------------------------
  // TRACK 4: Line-Rate Binary Packet Cockpit Offscreen Worker & Equipotential Shader
  // --------------------------------------------------------------------------
  await t.test('Track 4: Line-Rate Binary Packet Offscreen Worker & Equipotential Shader', async (t4) => {
    await t4.test('4a. Encodes and decodes line-rate binary packet frames with zero-copy DataView', () => {
      const testFrame = {
        frameNumber: 1,
        timestamp: Date.now() * 1000,
        protocol: 'TCP',
        srcIp: '192.168.1.100',
        dstIp: '10.0.0.1',
        srcPort: 54321,
        dstPort: 443,
        length: 128,
        rawPayload: '454a494954455354'
      };

      const encodedBuffer = encodeBinaryPacketFrame(testFrame);
      assert.ok(encodedBuffer instanceof Buffer || encodedBuffer instanceof Uint8Array);

      const decoded = decodeBinaryFrameBuffer(encodedBuffer);
      assert.ok(decoded);
      assert.equal(decoded.srcIp, '192.168.1.100');
      assert.equal(decoded.dstIp, '10.0.0.1');
      assert.equal(decoded.srcPort, 54321);
      assert.equal(decoded.dstPort, 443);
      assert.equal(decoded.protocol, 'TLS');
      assert.equal(decoded.flags.isIpv6, false);
    });

    await t4.test('4b. Computes continuous scalar potential field with Gaussian decay u(x, y)', () => {
      const sources = [
        { x: 100, y: 100, potential: 1.0, sigma: 50 },
        { x: 300, y: 100, potential: 0.5, sigma: 50 }
      ];

      const uAtCenter1 = evaluateScalarPotential(100, 100, sources, 50);
      assert.ok(uAtCenter1 >= 1.0, `Potential at source center (${uAtCenter1}) must be >= 1.0`);

      const field = computeEquipotentialField(sources, 200, 200, 10);
      assert.equal(field.cols, 20);
      assert.equal(field.rows, 20);
      assert.equal(field.grid.length, 400);
      assert.ok(field.maxPotential >= 0.85);
    });
  });

  // --------------------------------------------------------------------------
  // TRACK 5: Episodic Playbook Lifecycle Governance & Degradation Quarantine
  // --------------------------------------------------------------------------
  await t.test('Track 5: Episodic Playbook Lifecycle Governance & Degradation Quarantine', async (t5) => {
    const memory = new OperationalMemoryEngine({ useSqlite: true });

    await t5.test('5a. Governs canonical 5-state lifecycle progression and transition rules', () => {
      assert.strictEqual(PLAYBOOK_LIFECYCLE_STATES.CANDIDATE, 'CANDIDATE');
      assert.strictEqual(PLAYBOOK_LIFECYCLE_STATES.VERIFIED_ACTIVE, 'VERIFIED_ACTIVE');
      assert.strictEqual(PLAYBOOK_LIFECYCLE_STATES.PROBATIONARY, 'PROBATIONARY');
      assert.strictEqual(PLAYBOOK_LIFECYCLE_STATES.QUARANTINED_DEGRADED, 'QUARANTINED_DEGRADED');
      assert.strictEqual(PLAYBOOK_LIFECYCLE_STATES.SUPERSEDED, 'SUPERSEDED');

      assert.strictEqual(validatePlaybookLifecycleTransition('CANDIDATE', 'VERIFIED_ACTIVE').valid, true);
      assert.strictEqual(validatePlaybookLifecycleTransition('VERIFIED_ACTIVE', 'PROBATIONARY').valid, true);
      assert.strictEqual(validatePlaybookLifecycleTransition('SUPERSEDED', 'VERIFIED_ACTIVE').valid, false);
    });

    await t5.test('5b. Automatically quarantines playbook on >= 2 failures and excludes it from experience replay', () => {
      const testPb = `RB-CAPSTONE-${Date.now()}`;
      const healthyPb = `RB-CAPSTONE-HEALTHY-${Date.now()}`;

      // Initialize healthy playbook
      memory.recordPlaybookExecution(healthyPb, { success: true });

      // Fail test playbook twice
      memory.recordPlaybookExecution(testPb, { success: false });
      const qRecord = memory.recordPlaybookExecution(testPb, {
        success: false,
        failureReason: 'Kernel route table deadlock'
      });

      assert.strictEqual(qRecord.lifecycleState, 'QUARANTINED_DEGRADED');
      assert.strictEqual(qRecord.consecutiveFailures, 2);

      const health = memory.evaluatePlaybookHealth(testPb);
      assert.strictEqual(health.isQuarantined, true);
      assert.strictEqual(health.confidenceMultiplier, 0.0);

      // Seed resolutions
      const targetHost = `capstone-host-${Date.now()}.corp`;
      memory.recordVerifiedResolution({
        target: targetHost,
        symptomSignature: 'ROUTE_BLACKHOLE',
        rootCause: 'Deadlock in routing daemon',
        resolutionSteps: testPb
      });
      memory.recordVerifiedResolution({
        target: targetHost,
        symptomSignature: 'ROUTE_BLACKHOLE',
        rootCause: 'Normal gateway failover',
        resolutionSteps: healthyPb
      });

      const replay = memory.replayHistoricalExperiences({
        target: targetHost,
        symptomSignature: 'ROUTE_BLACKHOLE',
        topK: 5
      });

      // Verify quarantined playbook is filtered out
      const quarantinedInTop = replay.topExperiences.some(
        (e) => e.provenRemediationRunbook === testPb
      );
      assert.strictEqual(quarantinedInTop, false);
      assert.strictEqual(replay.recommendedAction, healthyPb);

      // Operator rehabilitation
      const rehab = memory.rehabilitatePlaybook(testPb, {
        rehabilitatedBy: 'CHIEF_SRE',
        notes: 'Patch applied to kernel route daemon; verified.'
      });
      assert.strictEqual(rehab.lifecycleState, 'VERIFIED_ACTIVE');
      assert.strictEqual(rehab.consecutiveFailures, 0);
    });
  });
});
