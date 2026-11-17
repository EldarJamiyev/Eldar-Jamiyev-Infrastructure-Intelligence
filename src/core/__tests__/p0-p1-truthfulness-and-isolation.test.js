'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const {
  isPathInsideDir,
  resolveCanonicalPath,
  DEFAULT_REPO_DATA_DIR
} = require('../../config');
const { db, initSchema } = require('../../db/database');
const { runMigrations } = require('../../db/migrations');
const { EvidenceFabric } = require('../evidence/evidence-fabric');
const { GitopsReconciliationEngine } = require('../gitops-reconciliation-engine');
const { TopologyEngine } = require('../../network/topology/topology-engine');
const { RoutingRadixIntelligenceEngine } = require('../../topology/routing-radix-intelligence');
const { validateStructuredInterpretation } = require('../chat/semantic-ai-interpreter');
const { RlofPreferenceAligner } = require('../../ai/rlof-preference-aligner');
const { SuperpowersSkillsEngine } = require('../skills/superpowers-skills-engine');
const { PreIncidentTimelineReconstructor } = require('../../observability/timeline-reconstructor');
const { chatOperatorService } = require('../chat/chat-operator-service');
const { GeoPartitionCrdtEngine } = require('../multisite/geo-partition-crdt-engine');

describe('EJII P0/P1 Truthfulness, Isolation & Integrity Regressions', () => {
  it('T1: resolveCanonicalPath & isPathInsideDir block symlink traversal pointing into repo data/', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ejii-symlink-test-'));
    const symlinkPath = path.join(tmpDir, 'escape-link');
    let symlinkCreated = false;
    try {
      try {
        fs.symlinkSync(DEFAULT_REPO_DATA_DIR, symlinkPath, 'dir');
        symlinkCreated = true;
      } catch (_) {
        // Fallback check on restricted systems without symlink creation permission
      }

      if (symlinkCreated) {
        const linkedDb = path.join(symlinkPath, 'ejii.sqlite');
        assert.strictEqual(
          isPathInsideDir(linkedDb, DEFAULT_REPO_DATA_DIR),
          true,
          'Symlink pointing into DEFAULT_REPO_DATA_DIR must be detected as inside repo data directory'
        );
        assert.strictEqual(
          resolveCanonicalPath(linkedDb),
          path.join(resolveCanonicalPath(DEFAULT_REPO_DATA_DIR), 'ejii.sqlite')
        );
      } else {
        const nestedNonExistent = path.join(DEFAULT_REPO_DATA_DIR, 'nonexistent-sub', 'ejii.sqlite');
        assert.strictEqual(isPathInsideDir(nestedNonExistent, DEFAULT_REPO_DATA_DIR), true);
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('T2: EvidenceFabric marks missing provenance honestly and restores pre-existing records on overwrite rollback', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ejii-ev-rollback-'));
    const dbPath = path.join(tmpDir, 'evidence.sqlite');
    const customDb = new DatabaseSync(dbPath);
    try {
      initSchema(customDb);
      const fabric = new EvidenceFabric(null, { dbHandle: customDb });

      const sparse = fabric.recordEvidence({
        id: 'EVD-OVERWRITE-TARGET',
        sessionId: 'SESS-RW',
        type: 'observation',
        claim: 'Initial verified claim',
        rawValue: { ok: true },
        normalizedValue: 1
      });
      assert.strictEqual(sparse.subject, 'unspecified_subject');
      assert.strictEqual(sparse.sourceCapabilityId, 'unspecified_source');
      assert.strictEqual(sparse.collectionMethod, 'unspecified_method');
      assert.strictEqual(sparse.provenanceComplete, false);
      assert.strictEqual(sparse.persistedToSqlite, true);

      const origPersistDagNode = fabric._persistDagNode.bind(fabric);
      fabric._persistDagNode = (_node, options) => {
        if (options && options.throwOnDbError) {
          throw new Error('SIMULATED_OVERWRITE_DAG_FAIL');
        }
        return origPersistDagNode(_node, options);
      };

      const failedOverwrite = fabric.recordEvidence({
        id: 'EVD-OVERWRITE-TARGET',
        sessionId: 'SESS-RW',
        type: 'observation',
        subject: 'host:9.9.9.9',
        claim: 'Corrupted overwrite that must roll back',
        rawValue: { ok: false },
        normalizedValue: 0,
        sourceCapabilityId: 'ejii.test',
        collectionMethod: 'test_probe'
      });
      assert.strictEqual(failedOverwrite.persistedToSqlite, false);

      const restored = fabric.getEvidenceById('EVD-OVERWRITE-TARGET');
      assert.ok(restored, 'Original evidence record must still exist after failed overwrite rollback');
      assert.strictEqual(restored.claim, 'Initial verified claim');
      assert.strictEqual(restored.subject, 'unspecified_subject');

      fabric._persistDagNode = origPersistDagNode;
      const initialFinding = fabric.recordFinding({
        findingId: 'FND-OVERWRITE-1',
        sessionId: 'SESS-RW',
        title: 'Original finding title',
        severity: 'warn',
        layer: 'L3',
        summary: 'Original finding summary'
      });
      assert.strictEqual(initialFinding.persistedToSqlite, true, 'Initial finding must persist before testing overwrite rollback');
      fabric._persistDagNode = (node, options) => {
        if (options && options.throwOnDbError) {
          throw new Error('SIMULATED_FINDING_DAG_FAIL');
        }
        return origPersistDagNode(node, options);
      };
      const failedFindingOverwrite = fabric.recordFinding({
        findingId: 'FND-OVERWRITE-1',
        sessionId: 'SESS-RW',
        title: 'Mutated finding title',
        severity: 'critical',
        layer: 'L7',
        summary: 'Mutated finding summary'
      });
      assert.strictEqual(failedFindingOverwrite.persistedToSqlite, false);
      const restoredFinding = fabric.getFindingById('FND-OVERWRITE-1');
      assert.ok(restoredFinding);
      assert.strictEqual(restoredFinding.title, 'Original finding title');
    } finally {
      customDb.close();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('T3: GitOpsReconciliationEngine distinguishes missing, unreadable, invalid manifests, DB failure, and unverified gateway', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ejii-gitops-'));
    try {
      const missingEngine = new GitopsReconciliationEngine({
        manifestPath: path.join(tmpDir, 'missing.json')
      });
      const missingRes = missingEngine.detectInfrastructureDrift();
      assert.strictEqual(missingRes.status, 'MANIFEST_MISSING');
      assert.strictEqual(missingRes.manifestPresent, false);

      // Existing directory triggers non-JSON readFileSync EISDIR error -> MANIFEST_UNREADABLE
      const unreadableEngine = new GitopsReconciliationEngine({ manifestPath: tmpDir });
      const unreadableRes = unreadableEngine.detectInfrastructureDrift();
      assert.strictEqual(unreadableRes.status, 'MANIFEST_UNREADABLE');

      const badJsonPath = path.join(tmpDir, 'bad.json');
      fs.writeFileSync(badJsonPath, '{ invalid json', 'utf8');
      const invalidEngine = new GitopsReconciliationEngine({ manifestPath: badJsonPath });
      const invalidRes = invalidEngine.detectInfrastructureDrift();
      assert.strictEqual(invalidRes.status, 'MANIFEST_INVALID');

      const validJsonPath = path.join(tmpDir, 'desired.json');
      fs.writeFileSync(validJsonPath, JSON.stringify({
        apiVersion: 'ejii.infrastructure.io/v1',
        kind: 'DesiredInfrastructureState',
        spec: {
          topologyInvariants: { requiredNodeIds: [] }
        }
      }), 'utf8');
      const brokenDb = {
        prepare() {
          throw new Error('SQLITE_BUSY');
        }
      };
      const dbErrEngine = new GitopsReconciliationEngine({
        manifestPath: validJsonPath,
        dbHandle: brokenDb,
        physicalDetector: () => ({ defaultGateway: null, gatewayVerified: false, dnsServers: [] })
      });
      const driftWithDbErr = dbErrEngine.detectInfrastructureDrift();
      assert.strictEqual(driftWithDbErr.status, 'LIVE_STATE_UNAVAILABLE');
      assert.strictEqual(driftWithDbErr.liveStateAvailable, false);
      assert.strictEqual(driftWithDbErr.driftCount, 0);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('T4: Database & migration schemas default status to unprobed and nullable telemetry columns to NULL', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ejii-schema-nulls-'));
    const dbPath = path.join(tmpDir, 'schema.sqlite');
    const customDb = new DatabaseSync(dbPath);
    try {
      initSchema(customDb);
      runMigrations(customDb);

      customDb.prepare(
        "INSERT INTO topology_nodes (id, name, hostname_or_ip, type, layer, layer_level) VALUES ('N1', 'Node 1', '10.0.0.10', 'server', 'server', 4)"
      ).run();
      customDb.prepare(
        "INSERT INTO topology_nodes (id, name, hostname_or_ip, type, layer, layer_level) VALUES ('N2', 'Node 2', '10.0.0.11', 'router', 'gateway', 2)"
      ).run();
      customDb.prepare(
        "INSERT INTO topology_edges (id, source_id, target_id) VALUES ('E1', 'N1', 'N2')"
      ).run();
      customDb.prepare(
        "INSERT INTO link_telemetry (edge_id, timestamp) VALUES ('E1', '2026-01-01T00:00:00.000Z')"
      ).run();

      const nodeRow = customDb.prepare("SELECT status, last_checked, last_latency_ms FROM topology_nodes WHERE id = 'N1'").get();
      assert.strictEqual(nodeRow.status, 'unprobed');
      assert.strictEqual(nodeRow.last_checked, null);
      assert.strictEqual(nodeRow.last_latency_ms, null);

      const edgeRow = customDb.prepare("SELECT bandwidth_mbps, latency_ms, utilization_pct, packet_rate, status FROM topology_edges WHERE id = 'E1'").get();
      assert.strictEqual(edgeRow.bandwidth_mbps, null);
      assert.strictEqual(edgeRow.latency_ms, null);
      assert.strictEqual(edgeRow.utilization_pct, null);
      assert.strictEqual(edgeRow.packet_rate, null);
      assert.strictEqual(edgeRow.status, 'unprobed');

      const telRow = customDb.prepare("SELECT latency_ms, loss_pct, bandwidth_utilization_pct, packet_rate, if_in_octets, if_out_octets FROM link_telemetry WHERE edge_id = 'E1'").get();
      assert.strictEqual(telRow.latency_ms, null);
      assert.strictEqual(telRow.loss_pct, null);
      assert.strictEqual(telRow.bandwidth_utilization_pct, null);
      assert.strictEqual(telRow.packet_rate, null);
      assert.strictEqual(telRow.if_in_octets, null);
      assert.strictEqual(telRow.if_out_octets, null);
    } finally {
      customDb.close();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('T5: TopologyEngine preserves Configured vs Inferred evidenceSource and surfaces unmeasured completeness counts', () => {
    const engine = new TopologyEngine();
    const nodeIds = ['NODE-T5-A', 'NODE-T5-B'];
    const edgeIds = ['EDGE-T5-CFG', 'EDGE-T5-INF'];
    try {
      db.prepare("DELETE FROM topology_edges WHERE id IN ('EDGE-T5-CFG', 'EDGE-T5-INF')").run();
      db.prepare("DELETE FROM topology_nodes WHERE id IN ('NODE-T5-A', 'NODE-T5-B')").run();
      db.prepare(
        "INSERT INTO topology_nodes (id, name, hostname_or_ip, type, layer, layer_level, status, metadata) VALUES ('NODE-T5-A', 'Node A', '10.0.1.10', 'server', 'service', 4, 'unprobed', '{}')"
      ).run();
      db.prepare(
        "INSERT INTO topology_nodes (id, name, hostname_or_ip, type, layer, layer_level, status, metadata) VALUES ('NODE-T5-B', 'Node B', '10.0.1.11', 'router', 'edge', 2, 'unprobed', '{}')"
      ).run();
      db.prepare(
        "INSERT INTO topology_edges (id, source_id, target_id, status, metadata) VALUES ('EDGE-T5-CFG', 'NODE-T5-A', 'NODE-T5-B', 'unprobed', ?)"
      ).run(JSON.stringify({ evidenceClassification: 'Architectural_Template' }));
      db.prepare(
        "INSERT INTO topology_edges (id, source_id, target_id, status, metadata) VALUES ('EDGE-T5-INF', 'NODE-T5-B', 'NODE-T5-A', 'unprobed', ?)"
      ).run(JSON.stringify({ autoSynthesized: true }));

      engine.cachedTopology = null;
      const topo = engine.getTopology();
      const cfgEdge = topo.edges.find((e) => e.id === 'EDGE-T5-CFG');
      const infEdge = topo.edges.find((e) => e.id === 'EDGE-T5-INF');
      assert.ok(cfgEdge);
      assert.ok(infEdge);
      assert.strictEqual(cfgEdge.evidenceSource, 'Configured');
      assert.strictEqual(infEdge.evidenceSource, 'Inferred');
      assert.ok(topo.spectralApex?.telemetryCompleteness);
      assert.ok(topo.spectralApex.telemetryCompleteness.unmeasuredEdgesCount >= 2);
      assert.ok(topo.spectralApex.telemetryCompleteness.unmeasuredNodesCount >= 2);
      assert.strictEqual(topo.spectralApex.telemetryCompleteness.baselinePriorAssumedForUnmeasured, true);
    } finally {
      db.prepare(`DELETE FROM topology_edges WHERE id IN (${edgeIds.map(() => '?').join(',')})`).run(...edgeIds);
      db.prepare(`DELETE FROM topology_nodes WHERE id IN (${nodeIds.map(() => '?').join(',')})`).run(...nodeIds);
    }
  });

  it('T6: RoutingRadixIntelligenceEngine never inserts synthetic 192.168.31.1 fallback routes when OS table is empty', () => {
    const trie = new RoutingRadixIntelligenceEngine();
    const emptyLookup = trie.lookupLongestPrefixMatch('192.168.31.1');
    assert.strictEqual(emptyLookup.matched, false);
    assert.strictEqual(emptyLookup.nextHop, null);

    const emptyAudit = RoutingRadixIntelligenceEngine.auditRoutingTable([]);
    assert.deepStrictEqual(emptyAudit.anomalies, []);
    assert.deepStrictEqual(emptyAudit.defaultGateways, []);
    assert.strictEqual(trie.getStats().nodeCount, 1);
  });

  it('T7: validateStructuredInterpretation strips string "null", infers MX recordType, rejects invalid intents, and downgrades targetless remote probes', () => {
    const invalid = validateStructuredInterpretation({ intent: 'nonexistent_intent', target: 'example.com' });
    assert.strictEqual(invalid.valid, false);

    const cleaned = validateStructuredInterpretation(
      {
        intent: 'dns',
        target: 'null',
        ports: ['53', 999999],
        confidence: 1.5
      },
      { rawText: 'check MX records for example.com', lastTarget: 'example.com' }
    );
    assert.strictEqual(cleaned.valid, true);
    assert.strictEqual(cleaned.plan.target, 'example.com');
    assert.strictEqual(cleaned.plan.explicitTarget, null);
    assert.strictEqual(cleaned.plan.recordType, 'MX');
    assert.deepStrictEqual(cleaned.plan.ports, [53]);

    const missingRemote = validateStructuredInterpretation(
      {
        intent: 'port_check',
        target: 'null',
        ports: ['443']
      },
      { rawText: 'check port 443' }
    );
    assert.strictEqual(missingRemote.valid, true);
    assert.strictEqual(missingRemote.downgradedToClarification, true);
    assert.strictEqual(missingRemote.plan.intent, 'clarification_needed');
    assert.strictEqual(missingRemote.plan.target, null);
  });

  it('T8: RlofPreferenceAligner rejects non-finite vectors and invalid hyperparameters', () => {
    const aligner = new RlofPreferenceAligner();
    assert.throws(
      () => aligner.computeReward([NaN, 0.2, 0.3, 0.4], 'ACTION_A'),
      /non-finite/i
    );
    assert.throws(
      () => aligner.computeReward([0.1, 0.2], 'ACTION_A'),
      /4-element/i
    );
    assert.throws(
      () => aligner.recordPreferenceAndAlign({ winningAction: 'ACTION_A', losingAction: 'ACTION_B', learningRate: -1 }),
      /learningRate/i
    );
    assert.throws(
      () => aligner.recordPreferenceAndAlign({ winningAction: 'ACTION_A', losingAction: 'ACTION_B', betaDpo: 0 }),
      /betaDpo/i
    );
    assert.throws(
      () => aligner.recordPreferenceAndAlign({ winningAction: 'ACTION_A', losingAction: 'ACTION_B', contextVector: [Infinity, 0, 0, 0] }),
      /non-finite/i
    );
    const reward = aligner.computeReward([0.5, 0.4, 0.3, 0.2], 'ACTION_A');
    assert.ok(Number.isFinite(reward));
  });

  it('T9: SuperpowersSkillsEngine fails closed on missing target and TimelineReconstructor emits zero fabricated RTTs', () => {
    const engine = new SuperpowersSkillsEngine();
    const audit = engine.enforceConstraintFloor({}, {}, {});
    assert.strictEqual(audit.passed, false);
    const ssrfInv = audit.invariantsChecked.find((i) => i.id === 'INV_SSRF_SAFE_TARGET');
    assert.ok(ssrfInv);
    assert.strictEqual(ssrfInv.status, 'FAILED');
    assert.match(ssrfInv.detail, /MISSING_TARGET/);

    const reconstructor = new PreIncidentTimelineReconstructor();
    const timeline = reconstructor.reconstructPreIncidentTimeline({
      target: null,
      injectedEvents: []
    });
    assert.strictEqual(timeline.target, 'UNSPECIFIED_TARGET');
    const combinedSummaries = timeline.timelineEvents.map((e) => e.summary).join(' ');
    assert.doesNotMatch(combinedSummaries, /1\.2ms RTT|0% packet loss|1\.1ms, 0 SYN drops|TTFB 1\.4ms/);
  });

  it('T10: ChatOperatorService requests clarification instead of probing 127.0.0.1 on targetless SNMP or log turns', async () => {
    const session = chatOperatorService.getOrCreateSession('p0p1-no-localhost', 'admin');
    const snmpTurn = await chatOperatorService._executeSnmpProbeScenario({ intent: 'snmp_walk', target: null }, session);
    assert.strictEqual(snmpTurn.promptClarification, true);
    assert.strictEqual(snmpTurn.target, null);
    assert.deepStrictEqual(snmpTurn.steps, []);

    const logPlan = chatOperatorService.parseIntentAndEntities(
      'ERROR: Failed starting application\nexit code 1',
      session
    );
    if (logPlan.intent === 'log_and_startup_triage') {
      assert.strictEqual(logPlan.target, null);
    }

    const scenarioPlan = chatOperatorService.parseIntentAndEntities(
      'What happens if our vlan segmentation policy changes?',
      chatOperatorService.getOrCreateSession('p0p1-fresh-scenario', 'admin')
    );
    assert.strictEqual(scenarioPlan.intent, 'scenario_planning_what_if');
    assert.notStrictEqual(scenarioPlan.target, '127.0.0.1');
  });

  it('T11: GeoPartitionCrdtEngine enforces fail-closed checks and converges cleanly with real remote deltas', () => {
    const crdt = new GeoPartitionCrdtEngine('site-test-primary');
    crdt.incrementCounter('packets_verified', 3);
    const summaryBefore = crdt.getStateSummary();
    assert.strictEqual(summaryBefore.localSiteId, 'site-test-primary');
    assert.strictEqual(summaryBefore.pnCounterCount, 1);

    // 1. Self-target is rejected fail-closed
    const selfReport = crdt.reconcileWithRemotePartition('site-test-primary', {}, []);
    assert.strictEqual(selfReport.convergenceStatus, 'INVALID_SELF_TARGET');

    // 2. Vacuous remote sync without clock advancement or deltas is rejected
    const emptyReport = crdt.reconcileWithRemotePartition('region-eu-west', {}, []);
    assert.strictEqual(emptyReport.convergenceStatus, 'NO_REMOTE_DELTAS_AVAILABLE');

    // 3. Real remote delta converges and tracks peer
    const report = crdt.reconcileWithRemotePartition('region-eu-west', { 'region-eu-west': 2 }, [
      {
        crdtType: 'PN_COUNTER',
        key: 'packets_verified',
        operation: 'MERGE',
        deltaPayload: { positive: { 'region-eu-west': 4 }, negative: {} }
      }
    ]);
    assert.strictEqual(report.remoteSiteId, 'region-eu-west');
    assert.strictEqual(report.convergenceStatus, 'CONVERGED');
    assert.ok(report.convergedVectorClock['site-test-primary'] >= 2);
    assert.strictEqual(report.convergedVectorClock['region-eu-west'], 2);
    assert.strictEqual(crdt.getCounterValue('packets_verified'), 7);

    const summaryAfter = crdt.getStateSummary();
    assert.strictEqual(summaryAfter.status, 'RECONCILED');
    assert.ok(summaryAfter.trackedPeers.includes('region-eu-west'));
  });
});
