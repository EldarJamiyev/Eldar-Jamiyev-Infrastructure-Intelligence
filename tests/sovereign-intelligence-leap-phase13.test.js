/**
 * EJII Phase 13.0 Sovereign Operative Singularity Capstone Verification Suite
 *
 * Verifies all 6 Subsystems:
 * 1. Sovereign Tool Sandbox Expansion & Cryptographic Execution HMAC Audit Integrity
 * 2. Conversational Brain Intent Dispatcher & Socratic Dialectic Operator Grounding
 * 3. Closed-Loop Multi-Agent War Room Triage & Epistemic Dialectic Cascade
 * 4. Real-Time Sovereign Fabric REST API & High-Frequency Streaming Protocols
 * 5. Autonomous Nocturnal Dream Cycle Scheduler & Episodic Causal Memory Refinement
 * 6. Fast Preflight, Desktop Launch Readiness & Dual-Maintenance Parity Battery
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

test('Phase 13.0 Capstone: Sovereign Operative Singularity & Full Closed-Loop Autonomy', async (t) => {

  await t.test('1. Sovereign Tool Sandbox Expansion & Cryptographic Execution HMAC Audit Integrity', async () => {
    const { toolSandbox } = require('../src/core/tool-sandbox');

    // 1. Verify Roster Mounting of All 5 Sovereign Tools
    const roster = typeof toolSandbox.getToolRoster === 'function' ? toolSandbox.getToolRoster() : [];
    const sovereignToolNames = [
      'pomdp_active_probe',
      'socratic_dialectic_debate',
      'compositional_remediation_synthesizer',
      'crdt_wan_reconcile',
      'cacheline_perf_inspect'
    ];

    for (const toolName of sovereignToolNames) {
      assert.ok(
        roster.some((t) => t.name === toolName),
        `Tool [${toolName}] must be registered in ToolSandbox roster`
      );
      const schema = toolSandbox.getToolSchema(toolName);
      assert.ok(schema, `Schema for [${toolName}] must be defined`);
      assert.ok(schema.description, `Description for [${toolName}] must be defined`);
      assert.ok(schema.parameters, `Parameters for [${toolName}] must be defined`);
    }

    const authContext = {
      user: { username: 'principal-sre', role: 'principal_sre' }
    };

    // 2. Execute pomdp_active_probe tool
    const probeRes = await toolSandbox.executeTool('pomdp_active_probe', {
      incidentId: 'inc-p13-tool-1',
      budgetMs: 40,
      priorBelief: { BUFFER_OVERFLOW: 0.6, BGP_MED_OSCILLATION: 0.4 }
    }, authContext);
    assert.equal(probeRes.executed, true);
    assert.ok(probeRes.executionId.startsWith('exec_'));
    assert.ok(probeRes.hmacSignature.length === 64);
    assert.ok(probeRes.result.selectedProbes.length > 0);
    assert.ok(typeof probeRes.result.expectedInformationGainBits === 'number');

    // 3. Execute socratic_dialectic_debate tool
    const debateRes = await toolSandbox.executeTool('socratic_dialectic_debate', {
      incidentId: 'inc-p13-tool-2',
      candidateHypotheses: ['BUFFER_OVERFLOW', 'BGP_MED_OSCILLATION', 'FIBER_ATTENUATION'],
      evidence: { packetLossElevated: true, queueDepthHigh: true, rttSpikeDetected: true }
    }, authContext);
    assert.equal(debateRes.executed, true);
    assert.ok(debateRes.result.winningHypothesis);
    assert.ok(debateRes.result.minimax);
    assert.ok(typeof debateRes.result.dempsterShafer.conflictK === 'number');

    // 4. Execute compositional_remediation_synthesizer tool
    const synthRes = await toolSandbox.executeTool('compositional_remediation_synthesizer', {
      incidentContext: {
        incidentId: 'inc-p13-tool-3',
        dominantFault: 'BUFFER_OVERFLOW',
        targetNode: 'switch-leaf-01'
      },
      envState: {
        nodes: [{ id: 'switch-leaf-01' }],
        paths: []
      }
    }, authContext);
    assert.equal(synthRes.executed, true);
    assert.ok(synthRes.result.programId.startsWith('prog_'));
    assert.equal(synthRes.result.isSafe, true);
    assert.ok(synthRes.result.ast.steps.length >= 2);

    // 5. Execute crdt_wan_reconcile tool
    const crdtRes = await toolSandbox.executeTool('crdt_wan_reconcile', {
      remoteSiteId: 'site-tokyo',
      vectorClock: { 'site-tokyo': 10 },
      deltas: []
    }, authContext);
    assert.equal(crdtRes.executed, true);
    assert.equal(crdtRes.result.convergenceStatus, 'CONVERGED');
    assert.ok(typeof crdtRes.result.appliedDeltasCount === 'number');

    // 6. Execute cacheline_perf_inspect tool
    const cacheRes = await toolSandbox.executeTool('cacheline_perf_inspect', {
      action: 'stats'
    }, authContext);
    assert.equal(cacheRes.executed, true);
    assert.equal(cacheRes.result.cachelineAlignmentVerified, true);
    assert.ok(cacheRes.result.hardwarePerf);
    assert.ok(typeof cacheRes.result.hardwarePerf.throughputMbps === 'number');
  });

  await t.test('2. Conversational Brain Intent Dispatcher & Socratic Dialectic Operator Grounding', async () => {
    const { chatOperatorService } = require('../src/core/chat/chat-operator-service');
    const { conversationalBrain } = require('../src/core/chat/conversational-brain');

    // 1. Verify Intent Classification Regex Matching
    const debateIntent = conversationalBrain.parseIntentAndEntities('execute socratic dialectic debate on incident inc-chat-001');
    assert.equal(debateIntent.intent, 'SOCRATIC_DEBATE');

    const probeIntent = conversationalBrain.parseIntentAndEntities('run adaptive pomdp active probe on target 192.168.1.50');
    assert.equal(probeIntent.intent, 'POMDP_ACTIVE_PROBE');

    const synthIntent = conversationalBrain.parseIntentAndEntities('synthesize compositional remediation plan for target switch-core-01');
    assert.equal(synthIntent.intent, 'COMPOSITIONAL_REMEDIATION_SYNTHESIS');

    const crdtIntent = conversationalBrain.parseIntentAndEntities('reconcile crdt state with remote peer site-london');
    assert.equal(crdtIntent.intent, 'CRDT_WAN_RECONCILE');

    const cacheIntent = conversationalBrain.parseIntentAndEntities('inspect 64-byte cacheline perf ring buffer');
    assert.equal(cacheIntent.intent, 'CACHELINE_PERF_INSPECT');

    // 2. Execute All 5 Intents Through Chat Operator Service
    const session = 'session-p13-chat-test';

    // A. Socratic Debate
    const debateOut = await chatOperatorService.processMessage({
      message: 'execute socratic dialectic debate on incident inc-chat-001',
      sessionId: session
    });
    assert.equal(debateOut.status, 'ok');
    assert.ok(debateOut.reply.includes('SOCRATIC DIALECTIC CONSENSUS') || debateOut.reply.includes('Socratic'));
    assert.ok(debateOut.technicalEvidence);
    assert.ok(debateOut.technicalEvidence.winningHypothesis);

    // B. Adaptive POMDP Probe
    const probeOut = await chatOperatorService.processMessage({
      message: 'run adaptive pomdp active probe on target 10.10.10.1',
      sessionId: session
    });
    assert.equal(probeOut.status, 'ok');
    assert.ok(probeOut.reply.includes('POMDP ACTIVE DIAGNOSTIC PROBING'));
    assert.ok(probeOut.technicalEvidence.selectedProbes.length > 0);

    // C. Compositional Remediation Synthesis
    const synthOut = await chatOperatorService.processMessage({
      message: 'synthesize compositional remediation plan for target switch-core-01',
      sessionId: session
    });
    assert.equal(synthOut.status, 'ok');
    assert.ok(synthOut.reply.includes('COMPOSITIONAL REMEDIATION PROGRAM'));
    assert.equal(synthOut.technicalEvidence.isSafe, true);

    // D. CRDT WAN Reconcile
    const crdtOut = await chatOperatorService.processMessage({
      message: 'reconcile crdt state with remote peer site-london',
      sessionId: session
    });
    assert.equal(crdtOut.status, 'ok');
    assert.ok(crdtOut.reply.includes('CRDT MULTI-SITE RECONCILIATION'));
    assert.equal(crdtOut.technicalEvidence.convergenceStatus, 'CONVERGED');

    // E. Cacheline Perf Inspect
    const cacheOut = await chatOperatorService.processMessage({
      message: 'inspect 64-byte cacheline perf ring buffer',
      sessionId: session
    });
    assert.equal(cacheOut.status, 'ok');
    assert.ok(cacheOut.reply.includes('CACHELINE-ALIGNED RING BUFFER'));
    assert.equal(cacheOut.technicalEvidence.cachelineAlignmentVerified, true);
  });

  await t.test('3. Closed-Loop Multi-Agent War Room Triage & Epistemic Dialectic Cascade', async () => {
    const { autonomousWarRoom } = require('../src/ai/autonomous-war-room');
    const { warRoomSwarmCoordinator } = require('../src/ai/war-room-swarm-coordinator');

    // 1. Conduct Closed-Loop Sovereign Triage
    const triageReceipt = autonomousWarRoom.conductClosedLoopSovereignTriage({
      incidentId: 'inc-p13-swarm-e2e',
      target: 'router-edge-01',
      anomalyType: 'PACKET_LOSS_BURST',
      telemetry: {
        rttMs: 140.0,
        lossPct: 0.09,
        queueDepthPackets: 450
      },
      candidateHypotheses: ['BUFFER_OVERFLOW', 'BGP_MED_OSCILLATION', 'HARDWARE_NIC_RING_OVERFLOW'],
      evidence: { packetLossElevated: true, queueDepthHigh: true, rttSpikeDetected: true },
      environment: {
        nodes: [{ id: 'router-edge-01' }],
        hyperedges: [{ id: 'trunk-wan-01', nodes: ['router-edge-01'], weight: 1.0 }]
      }
    });

    assert.equal(triageReceipt.success, true);
    assert.equal(triageReceipt.triagePhase, 'SOVEREIGN_RESOLVED');
    assert.ok(triageReceipt.topologicalCheck.betti0 >= 1);
    assert.ok(triageReceipt.dialecticDebate.winningHypothesis);
    assert.ok(triageReceipt.synthesizedRemediation.programId.startsWith('prog_'));
    assert.equal(triageReceipt.synthesizedRemediation.isSafe, true);
    assert.equal(triageReceipt.crdtReplication.convergenceStatus, 'CONVERGED');

    // 2. Execute Full Swarm Dialectic Cascade
    const cascade = warRoomSwarmCoordinator.executeFullSwarmDialecticCascade(
      'inc-p13-swarm-e2e',
      'Buffer exhaustion and intermittent BGP route flapping',
      'router-edge-01'
    );

    assert.equal(cascade.incidentId, 'inc-p13-swarm-e2e');
    assert.equal(cascade.quorum.status, 'CONVERGED_UNANIMOUS');
    assert.ok(cascade.quorum.synthesizedThesis.agreedHypothesis);
    assert.ok(cascade.quorum.totalVotesCast >= 3);
    assert.equal(cascade.closedLoopTriage.success, true);
  });

  await t.test('4. Real-Time Sovereign Fabric REST API & High-Frequency Streaming Protocols', async () => {
    const routesV6Fabric = require('../src/api/routes-v6-fabric');

    // Helper to invoke routes via Express router stack with mock req/res
    function invokeFabricRoute(router, method, pathStr, reqBody = {}, reqQuery = {}) {
      const normMethod = method.toLowerCase();
      const layer = router.stack.find((s) => {
        if (!s.route) return false;
        const matchesPath = Array.isArray(s.route.path) ? s.route.path.includes(pathStr) : s.route.path === pathStr;
        const matchesMethod = s.route.methods && s.route.methods[normMethod];
        return matchesPath && matchesMethod;
      });

      if (!layer) {
        throw new Error(`Route [${method.toUpperCase()} ${pathStr}] not found in routesV6Fabric stack!`);
      }

      let capturedJson = null;
      let capturedCode = 200;

      const mockReq = {
        body: reqBody,
        query: reqQuery,
        user: { username: 'admin', role: 'admin' },
        headers: { authorization: 'Bearer test-token' }
      };

      const mockRes = {
        statusCode: 200,
        status(c) { capturedCode = c; return this; },
        json(d) { capturedJson = d; return this; }
      };

      const handler = layer.route.stack[layer.route.stack.length - 1].handle;
      handler(mockReq, mockRes, () => {});

      return { statusCode: capturedCode, body: capturedJson };
    }

    // A. POST /sovereign/debate/execute
    const debateApi = invokeFabricRoute(routesV6Fabric, 'POST', '/sovereign/debate/execute', {
      incidentId: 'inc-p13-api-1',
      candidateHypotheses: ['WAN_FIBER_MICROBENDING', 'BUFFER_OVERFLOW'],
      evidence: { packetLossElevated: true, rttSpikeDetected: true }
    });
    assert.equal(debateApi.statusCode, 200);
    assert.equal(debateApi.body.success, true);
    assert.ok(debateApi.body.data.winningHypothesis);
    assert.ok(debateApi.body.data.minimax);

    // B. POST /sovereign/pomdp/select-probes
    const pomdpApi = invokeFabricRoute(routesV6Fabric, 'POST', '/sovereign/pomdp/select-probes', {
      incidentId: 'inc-p13-api-2',
      prior: { WAN_FIBER_MICROBENDING: 0.5, BUFFER_OVERFLOW: 0.5 },
      budgetMs: 35
    });
    assert.equal(pomdpApi.statusCode, 200);
    assert.equal(pomdpApi.body.success, true);
    assert.ok(pomdpApi.body.data.selectedProbes.length > 0);

    // C. POST /sovereign/remediation/synthesize
    const synthApi = invokeFabricRoute(routesV6Fabric, 'POST', '/sovereign/remediation/synthesize', {
      incidentContext: {
        incidentId: 'inc-p13-api-3',
        dominantFault: 'BUFFER_OVERFLOW',
        targetNode: 'switch-agg-01'
      }
    });
    assert.equal(synthApi.statusCode, 200);
    assert.equal(synthApi.body.success, true);
    assert.equal(synthApi.body.data.isSafe, true);
    assert.ok(synthApi.body.data.programId.startsWith('prog_'));

    // D. GET /sovereign/crdt/state
    const crdtStateApi = invokeFabricRoute(routesV6Fabric, 'GET', '/sovereign/crdt/state');
    assert.equal(crdtStateApi.statusCode, 200);
    assert.equal(crdtStateApi.body.success, true);
    assert.ok(crdtStateApi.body.data.siteId);

    // E. POST /sovereign/crdt/reconcile
    const crdtReconApi = invokeFabricRoute(routesV6Fabric, 'POST', '/sovereign/crdt/reconcile', {
      remoteSiteId: 'peer-tokyo',
      vectorClock: { 'peer-tokyo': 5 },
      deltas: []
    });
    assert.equal(crdtReconApi.statusCode, 200);
    assert.equal(crdtReconApi.body.success, true);
    assert.equal(crdtReconApi.body.data.convergenceStatus, 'CONVERGED');

    // F. GET /sovereign/sniffer/cacheline-perf
    const cacheApi = invokeFabricRoute(routesV6Fabric, 'GET', '/sovereign/sniffer/cacheline-perf');
    assert.equal(cacheApi.statusCode, 200);
    assert.equal(cacheApi.body.success, true);
    assert.equal(cacheApi.body.data.cachelineAlignmentVerified, true);
    assert.ok(cacheApi.body.data.hardwarePerf);
  });

  await t.test('5. Autonomous Nocturnal Dream Cycle Scheduler & Episodic Causal Memory Refinement', async () => {
    const {
      NocturnalDreamScheduler,
      nocturnalDreamScheduler
    } = require('../src/ai/nocturnal-dream-scheduler');

    const scheduler = new NocturnalDreamScheduler();

    // 1. Verify Database Table Initialization
    scheduler.ensureDatabaseTable();

    // 2. Execute Full Dream Cycle
    const cycleReceipt = scheduler.runCycleNow([
      'fisher_consolidation',
      'hnsw_index_rebuild',
      'granger_causal_pruning'
    ]);

    assert.ok(cycleReceipt.cycleId.startsWith('dream_'));
    assert.equal(cycleReceipt.status, 'COMPLETED');
    assert.ok(typeof cycleReceipt.durationMs === 'number');
    assert.ok(cycleReceipt.metrics);
    assert.ok(typeof cycleReceipt.metrics.episodesProcessed === 'number');
    assert.ok(typeof cycleReceipt.metrics.fisherParamsUpdated === 'number');
    assert.ok(typeof cycleReceipt.metrics.grangerEdgesPruned === 'number');
    assert.ok(typeof cycleReceipt.metrics.hnswNodesReindexed === 'number');

    // 3. Verify SQLite Persistence & Querying
    const history = scheduler.getDreamHistory(5);
    assert.ok(Array.isArray(history));
    assert.ok(history.length >= 1);
    const persisted = history.find((h) => h.cycleId === cycleReceipt.cycleId);
    assert.ok(persisted, 'Persisted dream cycle must be retrievable from SQLite');
    assert.equal(persisted.status, 'COMPLETED');

    // 4. Test Scheduler Lifecycle
    scheduler.startScheduler(60000, 120);
    const activeStatus = scheduler.getStatus();
    assert.equal(activeStatus.schedulerActive, true);
    assert.equal(activeStatus.checkIntervalMs, 60000);
    assert.equal(activeStatus.idleThresholdSec, 120);

    scheduler.stopScheduler();
    const stoppedStatus = scheduler.getStatus();
    assert.equal(stoppedStatus.schedulerActive, false);
  });

  await t.test('6. Fast Preflight, Desktop Launch Readiness & Dual-Maintenance Parity Battery', () => {
    const rootDir = path.resolve(__dirname, '..');

    // 1. Verify UI View Files Count and Non-Zero Bytes
    const viewsDir = path.join(rootDir, 'public', 'js', 'views');
    const viewFiles = fs.readdirSync(viewsDir).filter((f) => f.endsWith('.js'));
    assert.equal(
      viewFiles.length,
      11,
      `public/js/views/ must contain exactly 11 view files, found ${viewFiles.length}`
    );
    for (const vf of viewFiles) {
      const fullPath = path.join(viewsDir, vf);
      const stat = fs.statSync(fullPath);
      assert.ok(stat.size > 200, `View file ${vf} must be active (size: ${stat.size}B)`);
    }

    // 2. Execute Fast Preflight Verification in < 100ms
    const startPreflight = performance.now();

    // A. Node Version >= 20
    const nodeMajor = parseInt(process.versions.node.split('.')[0], 10);
    assert.ok(nodeMajor >= 20, `Node major version must be >= 20, got ${nodeMajor}`);

    // B. Native SQLite Available
    const sqlite = require('node:sqlite');
    assert.ok(sqlite && typeof sqlite.DatabaseSync === 'function', 'node:sqlite DatabaseSync must be available');

    // C. Key UI Files Exist
    assert.ok(fs.existsSync(path.join(rootDir, 'public', 'index.html')), 'public/index.html must exist');
    assert.ok(fs.existsSync(path.join(rootDir, 'public', 'js', 'app.js')), 'public/js/app.js must exist');

    // D. Preflight Timing Guard
    const preflightDuration = performance.now() - startPreflight;
    assert.ok(preflightDuration < 100, `Fast preflight must complete in < 100ms (took ${preflightDuration.toFixed(2)}ms)`);

    // 3. Verify TS/JS Dual Maintenance Parity Count
    const { getTsSourceFiles } = require('../scripts/verify-ts-js-parity');
    const allTsFiles = getTsSourceFiles(path.join(rootDir, 'src'));
    assert.equal(
      allTsFiles.length,
      48,
      `Dual-maintenance parity guard must audit exactly 48 TypeScript modules, found ${allTsFiles.length}`
    );
  });

});
