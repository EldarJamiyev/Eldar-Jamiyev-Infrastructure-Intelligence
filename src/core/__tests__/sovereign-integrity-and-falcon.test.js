'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const {
    UniversalSkillRouter,
    CANONICAL_SKILL_INVENTORY_INVARIANTS
} = require('../skills/universal-skill-router');
const { rlofPreferenceAligner } = require('../../ai/rlof-preference-aligner');
const { EvidenceFabric } = require('../evidence/evidence-fabric');
const { FlowStateCompressor, AIModelOrchestrator } = require('../ai-model-orchestrator');
const { chatOperatorService } = require('../chat/chat-operator-service');
const { getPhysicalNetworkInfo } = require('../../network/routing/physical-network-detector');
const { db, initSchema } = require('../../db/database');
const { seedDatabase } = require('../../db/seed');

describe('EJII Sovereign Integrity, Evidence Fabric & Project Falcon Suite', () => {
    it('Preserves all 12 immutable canonical skill ecosystem quantities and honest disk availability', () => {
        const router = new UniversalSkillRouter();
        const inv = router.getInventoryInvariants();
        assert.strictEqual(inv.totalCatalogedPackages, 986);
        assert.strictEqual(inv.activePhysicalPackages, 972);
        assert.strictEqual(inv.quarantinedMetadataOnlyPackages, 14);
        assert.strictEqual(inv.ejiiExclusivePackages, 73);
        assert.strictEqual(inv.sovereignEnhancedPackages, 38);
        assert.strictEqual(inv.importedPackages, 861);
        assert.strictEqual(inv.topLevelPrimarySkillPackages, 85);
        assert.strictEqual(inv.nestedGstackWorkflows, 74);
        assert.strictEqual(inv.combinedPrimaryAndGstackManifests, 159);
        assert.strictEqual(inv.activeMirroredRuntimeModules, 111);
        assert.strictEqual(inv.registeredLockDefinitions, 71);
        assert.strictEqual(inv.directExternalLockEntries, 46);
        assert.strictEqual(inv.sovereignInternalExtensions, 25);
        assert.strictEqual(inv.superpowersAgentSkills, 15);
        assert.strictEqual(
            inv.ejiiExclusivePackages + inv.sovereignEnhancedPackages + inv.importedPackages,
            inv.activePhysicalPackages,
            'Source categories must sum to activePhysicalPackages (73 + 38 + 861 = 972)'
        );
        assert.strictEqual(
            inv.activePhysicalPackages + inv.quarantinedMetadataOnlyPackages,
            inv.totalCatalogedPackages,
            'Active + quarantined must sum to totalCatalogedPackages (972 + 14 = 986)'
        );
        assert.strictEqual(
            inv.directExternalLockEntries + inv.sovereignInternalExtensions,
            inv.registeredLockDefinitions,
            'Lock definitions must equal 46 external + 25 sovereign internal = 71'
        );

        const stats = router.detectAllSkills();
        assert.strictEqual(stats.total, 986);
        assert.strictEqual(stats.activeSkillsCount, 972);
        assert.strictEqual(stats.quarantined, 14);
        assert.strictEqual(typeof stats.physicalSkillDirectoryPresentOnDisk, 'boolean');
        assert.ok(
            [
                'PHYSICAL_DISK_VERIFIED',
                'OVERLAP_REPORT_METADATA_ONLY',
                'PHYSICAL_DISK_PARTIAL',
                'CANONICAL_LOCKED_METADATA_FALLBACK'
            ].includes(stats.availabilityMode),
            `Unexpected availabilityMode: ${stats.availabilityMode}`
        );
        assert.strictEqual(CANONICAL_SKILL_INVENTORY_INVARIANTS.totalCatalogedPackages, 986);
    });

    it('Fresh database seed inserts zero fabricated link_telemetry rows and marks template nodes unprobed', () => {
        const tmpDbFile = path.join(os.tmpdir(), `ejii-seed-audit-${Date.now()}.db`);
        const customDb = new DatabaseSync(tmpDbFile);
        try {
            initSchema(customDb);
            assert.strictEqual(customDb._ejiiSchemaInitialized, true, 'initSchema should mark database handle initialized');

            // Calling initSchema a second time without force should be a fast no-op
            initSchema(customDb);

            // Reset topology tables on default DB handle to verify fresh seed behavior deterministically
            db.exec('DELETE FROM link_telemetry; DELETE FROM topology_edges; DELETE FROM topology_nodes;');
            seedDatabase();
            const telemetryCount = db.prepare('SELECT COUNT(*) as count FROM link_telemetry').get().count;
            assert.strictEqual(telemetryCount, 0, 'Fresh seed must not insert fabricated link_telemetry rows');

            const edges = db.prepare('SELECT utilization_pct, latency_ms, packet_rate FROM topology_edges').all();
            assert.ok(edges.length > 0, 'Seeded topology edges must exist');
            for (const edge of edges) {
                assert.strictEqual(edge.utilization_pct, null, 'Unprobed seeded edge utilization_pct must be null');
                assert.strictEqual(edge.latency_ms, null, 'Unprobed seeded edge latency_ms must be null');
                assert.strictEqual(edge.packet_rate, null, 'Unprobed seeded edge packet_rate must be null');
            }

            const refNodes = db.prepare("SELECT id, status FROM topology_nodes WHERE id IN ('NODE-WAN-01', 'NODE-GW-01', 'NODE-CORE-01', 'NODE-APP-01')").all();
            assert.ok(refNodes.length >= 4, 'Reference template nodes should exist');
            for (const n of refNodes) {
                assert.strictEqual(n.status, 'unprobed', `Reference node ${n.id} must be labeled 'unprobed' rather than 'online'`);
            }
        } finally {
            customDb.close();
            for (const suffix of ['', '-wal', '-shm']) {
                try { fs.unlinkSync(tmpDbFile + suffix); } catch (_) { /* ignore */ }
            }
        }
    });

    it('Physical network detector never fabricates alien workstation IP/MAC or 100.64.0.1 WAN hops', () => {
        const netInfo = getPhysicalNetworkInfo(true);
        assert.notStrictEqual(netInfo.hostIp, '192.168.31.89', 'Must not fall back to alien workstation IP 192.168.31.89');
        assert.notStrictEqual(netInfo.macAddress, '70:15:FB:6B:F3:46', 'Must not fall back to alien MAC 70:15:FB:6B:F3:46');
        assert.notStrictEqual(netInfo.interfaceDescription, 'Intel(R) Wi-Fi 6E AX211 160MHz', 'Must not fall back to alien Wi-Fi adapter description');
        assert.strictEqual(typeof netInfo.gatewayVerified, 'boolean', 'Must expose gatewayVerified boolean');
        assert.strictEqual(typeof netInfo.gatewayDiscoveryStatus, 'string', 'Must expose gatewayDiscoveryStatus string');
        if (!netInfo.gatewayVerified) {
            assert.strictEqual(netInfo.defaultGateway, null, 'Unverified default gateway must be null (no .1/.254 guessing)');
        }
        const wanHops = Array.isArray(netInfo.wanHops) ? netInfo.wanHops : [];
        const fakeCarrierHop = wanHops.find(h => h.ip === '100.64.0.1' && h.rttMs === 9.5);
        assert.strictEqual(fakeCarrierHop, undefined, 'Must not seed fake 100.64.0.1 WAN hop');
    });

    it('EvidenceFabric uses custom dbHandle across all reads/writes and rolls back atomically on DAG failure', () => {
        const tmpDbFile = path.join(os.tmpdir(), `ejii-evidence-atomic-${Date.now()}.db`);
        const customDb = new DatabaseSync(tmpDbFile);
        try {
            initSchema(customDb);
            const fabric = new EvidenceFabric(null, { dbHandle: customDb });

            const ev = fabric.recordEvidence({
                sessionId: 'SESS-ATOMIC-01',
                type: 'observation',
                subject: 'host:1.1.1.1',
                claim: 'Verified ICMP echo reply from 1.1.1.1',
                rawValue: { rttMs: 1.4 },
                normalizedValue: 1.4,
                sourceCapabilityId: 'ejii.icmp.ping',
                collectionMethod: 'icmp_echo'
            });
            assert.strictEqual(ev.persistedToSqlite, true, 'First evidence record must persist to custom SQLite DB');

            // Clear in-memory cache to prove getEvidenceById & queryEvidence read from customDb
            fabric.memoryRecords.clear();
            const fetched = fabric.getEvidenceById(ev.id);
            assert.ok(fetched, 'getEvidenceById must read from custom dbHandle');
            assert.strictEqual(fetched.subject, 'host:1.1.1.1');

            const queried = fabric.queryEvidence({ subject: 'host:1.1.1.1' });
            assert.strictEqual(queried.length, 1, 'queryEvidence must read from custom dbHandle');

            const finding = fabric.recordFinding({
                sessionId: 'SESS-ATOMIC-01',
                title: 'Healthy L3 reachability to 1.1.1.1',
                severity: 'info',
                layer: 'L3',
                summary: 'ICMP probe succeeded',
                supportingEvidenceIds: [ev.id]
            });

            fabric.memoryFindings.clear();
            const fetchedFinding = fabric.getFindingById(finding.findingId);
            assert.ok(fetchedFinding, 'getFindingById must read from custom dbHandle');
            assert.strictEqual(fabric.listFindings().length, 1);

            // Simulate DAG write failure inside recordEvidence to verify SAVEPOINT rollback
            const chainHashBeforeFailure = fabric.lastChainHash;
            const origPersistDagNode = fabric._persistDagNode.bind(fabric);
            fabric._persistDagNode = (node, options) => {
                if (options && options.throwOnDbError) {
                    throw new Error('SIMULATED_DAG_INSERT_FAILURE');
                }
                return origPersistDagNode(node, options);
            };

            const failedEv = fabric.recordEvidence({
                sessionId: 'SESS-ATOMIC-01',
                type: 'observation',
                subject: 'host:1.1.1.1',
                claim: 'Should roll back on DAG failure',
                rawValue: { status: 'OPEN' },
                sourceCapabilityId: 'ejii.tcp.port_check'
            });

            fabric._persistDagNode = origPersistDagNode;
            assert.strictEqual(failedEv.persistedToSqlite, false, 'Failed DAG write must mark persistedToSqlite = false');
            assert.strictEqual(
                fabric.lastChainHash,
                chainHashBeforeFailure,
                'lastChainHash must not advance when SAVEPOINT rolls back'
            );
            const sqliteRecordCount = customDb.prepare('SELECT COUNT(*) as count FROM evidence_records').get().count;
            assert.strictEqual(
                sqliteRecordCount,
                1,
                'Rolled-back evidence record must not remain in SQLite evidence_records table'
            );
        } finally {
            customDb.close();
            for (const suffix of ['', '-wal', '-shm']) {
                try { fs.unlinkSync(tmpDbFile + suffix); } catch (_) { /* ignore */ }
            }
        }
    });

    it('FlowStateCompressor rejects incomplete packets without creating 0.0.0.0:0 flows', () => {
        const compressor = new FlowStateCompressor();
        const badResult1 = compressor.ingestPacket({});
        assert.strictEqual(badResult1.rejected, true);
        assert.strictEqual(badResult1.reason, 'INVALID_INCOMPLETE_PACKET_TUPLE');
        assert.strictEqual(badResult1.flowState, null);
        assert.strictEqual(compressor.flows.size, 0, 'Must not insert 0.0.0.0:0 flow into flows map');

        const badResult2 = compressor.ingestPacket({ srcIp: '192.168.1.10' });
        assert.strictEqual(badResult2.rejected, true);
        assert.strictEqual(compressor.flows.size, 0);

        const validResult = compressor.ingestPacket({
            srcIp: '192.168.1.10',
            dstIp: '8.8.8.8',
            srcPort: 51234,
            dstPort: 443,
            protocol: 'TCP',
            length: 128,
            flags: 'SYN'
        });
        assert.strictEqual(validResult.rejected, false);
        assert.ok(validResult.flowState);
        assert.strictEqual(compressor.flows.size, 1);
    });

    it('AIModelOrchestrator tracks explicit provider verificationState', () => {
        const orchestrator = new AIModelOrchestrator();
        const state = orchestrator.providerTelemetry.GOOGLE_GEMINI.verificationState;
        assert.ok(
            ['UNCONFIGURED', 'CONFIGURED_UNPROBED', 'VERIFIED_HEALTHY', 'AUTH_FAILED', 'RATE_LIMITED', 'TIMEOUT', 'DEGRADED'].includes(state),
            `Unexpected verificationState: ${state}`
        );
    });

    it('RLOF preference parser ignores conceptual questions containing "reject" or "approve"', () => {
        const parsed1 = rlofPreferenceAligner.parseOperatorFeedback(
            'Why can a server respond to ping but reject port 443?'
        );
        assert.strictEqual(parsed1.matched, false, 'Conceptual question with "reject port 443?" must have matched: false');

        const parsed2 = rlofPreferenceAligner.parseOperatorFeedback(
            'Can a firewall block ICMP echo requests while allowing TCP 443?'
        );
        assert.strictEqual(parsed2.matched, false, 'Conceptual firewall question must have matched: false');

        const validOverride = rlofPreferenceAligner.parseOperatorFeedback(
            'Reject Restart-Service Spooler because print queue is active'
        );
        assert.strictEqual(validOverride.matched, true, 'Explicit remediation override command must match');
        assert.strictEqual(validOverride.feedbackType, 'MANUAL_REJECTION');
    });

    it('ChatOperatorService handles vague server complaint, target switching, and baseline comparison', async () => {
        const sessionId = `TEST-FALCON-${Date.now()}`;

        // 1. Vague complaint without target -> clarification_needed, 0 probes
        const vagueRes = await chatOperatorService.processMessage({
            sessionId,
            message: 'I cannot access the server',
            user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
        });
        assert.strictEqual(vagueRes.success, true);
        assert.strictEqual(vagueRes.intent, 'clarification_needed');
        assert.strictEqual(vagueRes.steps.length, 0, 'Vague complaint must not run arbitrary probes');
        assert.ok(
            vagueRes.reply.toLowerCase().includes('hostname or ip') ||
            vagueRes.reply.toLowerCase().includes('which server'),
            'Clarification response must ask for target hostname/IP and symptom scope'
        );

        // 2. Establish two targets in session history, then switch with "Forget that target. I meant the other server."
        const session = chatOperatorService.sessions.get(sessionId);
        session.targetHistory = ['localhost', '127.0.0.1'];
        session.lastTarget = '127.0.0.1';
        session.lastValidTarget = '127.0.0.1';
        session.lastIntent = 'dns';
        session.lastTargetTimestampMs = Date.now();

        const switchRes = await chatOperatorService.processMessage({
            sessionId,
            message: 'Forget that target. I meant the other server.',
            user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
        });
        assert.strictEqual(switchRes.success, true);
        assert.strictEqual(
            switchRes.target,
            'localhost',
            'Must switch active target back to the other server (localhost) in targetHistory'
        );

        // 3. Compare current result with yesterday -> follow_up_explanation
        const compareRes = await chatOperatorService.processMessage({
            sessionId,
            message: 'Compare the current result with yesterday.',
            user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
        });
        assert.strictEqual(compareRes.success, true);
        assert.strictEqual(compareRes.intent, 'follow_up_explanation');
        assert.strictEqual(compareRes.steps.length, 0, 'Historical/baseline comparison must execute 0 live network probes');

        // 4. "Forget that target." -> clears active target
        const clearRes = await chatOperatorService.processMessage({
            sessionId,
            message: 'Forget that target.',
            user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
        });
        assert.strictEqual(clearRes.success, true);
        assert.strictEqual(clearRes.intent, 'clarification_needed');
        assert.strictEqual(session.lastTarget, null, 'Active target must be cleared');
    });
});
