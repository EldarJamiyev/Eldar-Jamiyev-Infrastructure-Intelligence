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

    it('Fresh database seed on isolated customDb inserts zero fabricated link_telemetry rows and never mutates pre-existing DB', () => {
        const tmpDbFile = path.join(os.tmpdir(), `ejii-seed-audit-${Date.now()}.db`);
        const externalSentinelFile = path.join(os.tmpdir(), `ejii-sentinel-audit-${Date.now()}.db`);
        const customDb = new DatabaseSync(tmpDbFile);
        const sentinelDb = new DatabaseSync(externalSentinelFile);
        try {
            // 1. Populate an independently controlled sentinel DB with pre-existing rows
            initSchema(sentinelDb);
            sentinelDb.prepare(`
                INSERT INTO topology_nodes (id, name, hostname_or_ip, type, layer, layer_level, status)
                VALUES ('NODE-SENTINEL-KEEP', 'Pre-Existing Sentinel Node', '10.99.88.77', 'host', 'endpoint', 6, 'healthy')
            `).run();
            const sentinelCountBefore = sentinelDb.prepare('SELECT COUNT(*) as count FROM topology_nodes').get().count;
            assert.strictEqual(sentinelCountBefore, 1);

            // 2. Seed the isolated customDb without touching sentinelDb or default db
            seedDatabase(customDb);
            assert.strictEqual(customDb._ejiiSchemaInitialized, true, 'initSchema should mark database handle initialized');

            // Calling initSchema a second time without force should be a fast no-op
            initSchema(customDb);

            const telemetryCount = customDb.prepare('SELECT COUNT(*) as count FROM link_telemetry').get().count;
            assert.strictEqual(telemetryCount, 0, 'Fresh seed must not insert fabricated link_telemetry rows');

            const edges = customDb.prepare('SELECT utilization_pct, latency_ms, packet_rate, bandwidth_mbps FROM topology_edges').all();
            assert.ok(edges.length > 0, 'Seeded topology edges must exist');
            for (const edge of edges) {
                assert.strictEqual(edge.utilization_pct, null, 'Unprobed seeded edge utilization_pct must be null');
                assert.strictEqual(edge.latency_ms, null, 'Unprobed seeded edge latency_ms must be null');
                assert.strictEqual(edge.packet_rate, null, 'Unprobed seeded edge packet_rate must be null');
                assert.strictEqual(edge.bandwidth_mbps, null, 'Unprobed seeded edge bandwidth_mbps must be null');
            }

            const refNodes = customDb.prepare("SELECT id, status FROM topology_nodes WHERE id IN ('NODE-WAN-01', 'NODE-GW-01', 'NODE-CORE-01', 'NODE-APP-01')").all();
            assert.ok(refNodes.length >= 4, 'Reference template nodes should exist');
            for (const n of refNodes) {
                assert.strictEqual(n.status, 'unprobed', `Reference node ${n.id} must be labeled 'unprobed' rather than 'online'`);
            }

            // 3. Prove pre-existing sentinel DB was 100% untouched
            const sentinelRowAfter = sentinelDb.prepare("SELECT id, hostname_or_ip FROM topology_nodes WHERE id = 'NODE-SENTINEL-KEEP'").get();
            assert.ok(sentinelRowAfter, 'Pre-existing sentinel record must remain intact');
            assert.strictEqual(sentinelRowAfter.hostname_or_ip, '10.99.88.77');
        } finally {
            customDb.close();
            sentinelDb.close();
            for (const f of [tmpDbFile, externalSentinelFile]) {
                for (const suffix of ['', '-wal', '-shm']) {
                    try { fs.unlinkSync(f + suffix); } catch (_) { /* ignore */ }
                }
            }
        }
    });

    it('Enforces fail-closed SQLite test isolation and truthful migration failure state', () => {
        const { resolveRuntimeStoragePaths, DEFAULT_REPO_DATA_DIR } = require('../../config');
        const { parseTapSummary } = require('../../../tests/run-all-tests');

        // 1. Fail closed when EJII_REQUIRE_EXPLICIT_TEST_ISOLATION=true without explicit paths
        assert.throws(
            () => resolveRuntimeStoragePaths({ NODE_ENV: 'test', EJII_REQUIRE_EXPLICIT_TEST_ISOLATION: 'true' }, ['node', '--test']),
            (err) => err && err.code === 'ERR_UNISOLATED_TEST_ENVIRONMENT',
            'Must fail closed when explicit test isolation is required but EJII_DATA_DIR/EJII_DB_PATH are missing'
        );

        // 2. Fail closed when test attempts to point to repository data/ directory
        assert.throws(
            () => resolveRuntimeStoragePaths({
                NODE_ENV: 'test',
                EJII_DATA_DIR: DEFAULT_REPO_DATA_DIR,
                EJII_DB_PATH: path.join(DEFAULT_REPO_DATA_DIR, 'ejii.sqlite')
            }, ['node', '--test']),
            (err) => err && err.code === 'ERR_UNISOLATED_TEST_ENVIRONMENT',
            'Must fail closed when test points to repository data directory'
        );

        // 3. Truthful TAP summary parsing rejects missing summary or 0-test output
        const emptyTap = parseTapSummary('no tap lines here');
        assert.strictEqual(emptyTap.hasSummary, false);
        assert.strictEqual(emptyTap.tests, 0);

        // 4. Failed migration leaves _ejiiSchemaInitialized = false and migrationStatus = FAILED
        const brokenDb = {
            _ejiiSchemaInitialized: false,
            exec(sql) {
                if (/schema_migrations/i.test(sql)) {
                    throw new Error('SIMULATED_MIGRATION_TABLE_FAILURE');
                }
            },
            prepare() {
                return {
                    all() { return []; },
                    get() { return null; },
                    run() { throw new Error('SIMULATED_MIGRATION_EXECUTION_FAILURE'); }
                };
            }
        };
        const initOk = initSchema(brokenDb);
        assert.strictEqual(initOk, false, 'initSchema must return false when migrations fail');
        assert.strictEqual(brokenDb._ejiiSchemaInitialized, false, '_ejiiSchemaInitialized must remain false on migration failure');
        assert.strictEqual(brokenDb._ejiiMigrationStatus, 'FAILED');
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

    it('EvidenceFabric uses custom dbHandle across all reads/writes and rolls back both SQLite and in-memory state on DAG failure', () => {
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

            // Simulate DAG write failure inside recordEvidence to verify SAVEPOINT rollback + in-memory rollback
            const chainHashBeforeFailure = fabric.lastChainHash;
            const dagCountBeforeFailure = fabric.queryCausalDag().nodeCount;
            const origPersistDagNode = fabric._persistDagNode.bind(fabric);
            fabric._persistDagNode = (node, options) => {
                if (options && options.throwOnDbError) {
                    throw new Error('SIMULATED_DAG_INSERT_FAILURE');
                }
                return origPersistDagNode(node, options);
            };

            const failedEv = fabric.recordEvidence({
                id: 'EVD-ROLLBACK-TEST-99',
                sessionId: 'SESS-ATOMIC-01',
                type: 'observation',
                subject: 'host:1.1.1.1',
                claim: 'Should roll back on DAG failure',
                rawValue: { status: 'OPEN' },
                sourceCapabilityId: 'ejii.tcp.port_check'
            });

            fabric._persistDagNode = origPersistDagNode;
            assert.strictEqual(failedEv.persistedToSqlite, false, 'Failed DAG write must mark persistedToSqlite = false');
            assert.strictEqual(failedEv.persistenceStatus, 'SQLITE_WRITE_FAILED');
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
            assert.strictEqual(
                fabric.getEvidenceById('EVD-ROLLBACK-TEST-99'),
                null,
                'Rolled-back evidence record must not remain in memoryRecords'
            );
            assert.strictEqual(
                fabric.queryCausalDag().nodeCount,
                dagCountBeforeFailure,
                'Rolled-back evidence record must not pollute in-memory causal DAG nodes'
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

    it('AIModelOrchestrator tracks canonical provider verificationState and requires explicit targetHost', async () => {
        const orchestrator = new AIModelOrchestrator();
        assert.strictEqual(orchestrator.providerTelemetry.OLLAMA.verificationState, 'CONFIGURED_UNPROBED');
        const geminiState = orchestrator.providerTelemetry.GOOGLE_GEMINI.verificationState;
        assert.ok(
            ['UNCONFIGURED', 'CONFIGURED_UNPROBED', 'VERIFIED_HEALTHY', 'AUTH_FAILED', 'RATE_LIMITED', 'TIMEOUT', 'DEGRADED'].includes(geminiState),
            `Unexpected verificationState: ${geminiState}`
        );

        const matrix = orchestrator.getProviderHealthMatrix();
        const ollamaEntry = matrix.providers.find(p => p.providerId === 'OLLAMA');
        assert.strictEqual(ollamaEntry.latencyMs, null, 'Unprobed OLLAMA provider must report latencyMs: null (never 15ms)');

        await assert.rejects(
            () => orchestrator.executeToolCallingInvestigation({ query: 'Check reachability' }),
            /MISSING_TARGET_HOST/,
            'executeToolCallingInvestigation must reject missing targetHost instead of defaulting to 192.168.31.1'
        );
    });

    it('RLOF preference parser rejects questions, negations, conditionals, quotes, and declarative sentences', () => {
        const negativeCases = [
            'Why can a server respond to ping but reject port 443?',
            'Can a firewall block ICMP echo requests while allowing TCP 443?',
            'Do not approve Restart-Spooler on this server',
            'Never prefer Flush-Dns over Restart-Service',
            "Don't reject Clear-Arp-Cache",
            'If latency exceeds 50ms, approve Flush-Dns',
            'A stateful firewall can reject TCP connections with RST packets',
            '"approve Restart-Spooler"'
        ];
        for (const text of negativeCases) {
            const res = rlofPreferenceAligner.parseOperatorFeedback(text);
            assert.strictEqual(res.matched, false, `Must NOT treat "${text}" as operator preference override`);
        }

        const validOverride = rlofPreferenceAligner.parseOperatorFeedback(
            'Reject Restart-Service Spooler because print queue is active'
        );
        assert.strictEqual(validOverride.matched, true, 'Explicit remediation override command must match');
        assert.strictEqual(validOverride.feedbackType, 'MANUAL_REJECTION');

        const validPrefer = rlofPreferenceAligner.parseOperatorFeedback(
            'Please prefer Flush-Dns-Cache over Restart-Network-Adapter'
        );
        assert.strictEqual(validPrefer.matched, true);
        assert.strictEqual(validPrefer.feedbackType, 'PREFERENCE_RANKING');
        assert.strictEqual(validPrefer.winningAction, 'FLUSH-DNS-CACHE');
        assert.strictEqual(validPrefer.losingAction, 'RESTART-NETWORK-ADAPTER');
    });

    it('GitOps reconciliation engine reports MANIFEST_MISSING and truthful post-reconciliation status', () => {
        const { GitopsReconciliationEngine } = require('../gitops-reconciliation-engine');

        // 1. Missing manifest file -> MANIFEST_MISSING, reconciled: false
        const missingEngine = new GitopsReconciliationEngine({
            manifestPath: path.join(os.tmpdir(), `non-existent-manifest-${Date.now()}.json`)
        });
        const missingDrift = missingEngine.detectInfrastructureDrift();
        assert.strictEqual(missingDrift.status, 'MANIFEST_MISSING');
        assert.strictEqual(missingDrift.manifestPresent, false);
        const missingRec = missingEngine.reconcileDrift();
        assert.strictEqual(missingRec.reconciled, false);
        assert.strictEqual(missingRec.reconciliationLifecycleState, 'MANIFEST_MISSING');

        // 2. Un-reconcilable requiredNodeIds drift -> reconciled: false, NO_PERMITTED_ACTION_AVAILABLE
        const tmpManifestPath = path.join(os.tmpdir(), `ejii-manifest-test-${Date.now()}.json`);
        fs.writeFileSync(tmpManifestPath, JSON.stringify({
            apiVersion: 'ejii.infrastructure.io/v1',
            kind: 'DesiredInfrastructureState',
            spec: {
                topologyInvariants: {
                    requiredNodeIds: ['NODE-NONEXISTENT-999']
                }
            }
        }), 'utf8');
        try {
            const customEngine = new GitopsReconciliationEngine({ manifestPath: tmpManifestPath });
            const recResult = customEngine.reconcileDrift({ autoHealSafeTopologyDrift: true });
            assert.strictEqual(recResult.reconciled, false, 'Must not claim reconciled: true when un-reconcilable drift remains');
            assert.strictEqual(recResult.reconciliationLifecycleState, 'NO_PERMITTED_ACTION_AVAILABLE');
            assert.strictEqual(recResult.remainingDrifts.length, 1);
        } finally {
            try { fs.unlinkSync(tmpManifestPath); } catch (_) {}
        }
    });

    it('ChatOperatorService handles vague complaints, targetless commands, multi-turn switching, and truthful history comparisons', async () => {
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

        // 2. Targetless POMDP / CRDT commands without session target -> clarification_needed, 0 probes
        const pomdpNoTarget = await chatOperatorService.processMessage({
            sessionId,
            message: 'Run POMDP active probe',
            user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
        });
        assert.strictEqual(pomdpNoTarget.intent, 'clarification_needed');
        assert.strictEqual(pomdpNoTarget.steps.length, 0);

        const crdtNoPartition = await chatOperatorService.processMessage({
            sessionId,
            message: 'Run CRDT anti-entropy sync',
            user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
        });
        assert.strictEqual(crdtNoPartition.intent, 'clarification_needed');
        assert.strictEqual(crdtNoPartition.steps.length, 0);

        // 3. Establish two targets in session history, then switch with "Forget that target. I meant the other server."
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

        // 4. Compare current result with yesterday -> follow_up_explanation, states truthfully that no yesterday observation exists
        const compareRes = await chatOperatorService.processMessage({
            sessionId,
            message: 'Compare that with yesterday.',
            user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
        });
        assert.strictEqual(compareRes.success, true);
        assert.strictEqual(compareRes.intent, 'follow_up_explanation');
        assert.strictEqual(compareRes.steps.length, 0, 'Historical/baseline comparison must execute 0 live network probes');
        assert.match(compareRes.reply, /no historical baseline|yesterday/i);

        // 5. "What did we discover earlier?" -> follow_up_explanation, 0 probes
        const earlierRes = await chatOperatorService.processMessage({
            sessionId,
            message: 'What did we discover earlier?',
            user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
        });
        assert.strictEqual(earlierRes.intent, 'follow_up_explanation');
        assert.strictEqual(earlierRes.steps.length, 0);

        // 6. "Forget the previous target." -> clears active target
        const clearRes = await chatOperatorService.processMessage({
            sessionId,
            message: 'Forget the previous target.',
            user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
        });
        assert.strictEqual(clearRes.success, true);
        assert.strictEqual(clearRes.intent, 'clarification_needed');
        assert.strictEqual(session.lastTarget, null, 'Active target must be cleared');

        // 7. Role contrast correction when no alternate target exists -> asks for the application server hostname
        const roleContrastRes = await chatOperatorService.processMessage({
            sessionId,
            message: 'I meant the application server, not the DNS server.',
            user: { id: 'u1', username: 'analyst', role: 'ANALYST' }
        });
        assert.strictEqual(roleContrastRes.intent, 'clarification_needed');
        assert.strictEqual(roleContrastRes.steps.length, 0);
        assert.match(roleContrastRes.reply, /application server/i);
    });
});
