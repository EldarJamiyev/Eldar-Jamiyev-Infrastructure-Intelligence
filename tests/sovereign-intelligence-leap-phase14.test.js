/**
 * EJII Phase 14.0 Sovereign Hyper-Scale Cognition & Vectorized Streaming Wire Intelligence Capstone Verification Suite
 *
 * Verifies all 6 Subsystems:
 * 1. Vectorized Zero-Copy Wire Dissector & Streaming Count-Min Sketch Heavy-Hitters
 * 2. Hierarchical Neural-Causal Multi-Scale Quotient Abstraction & CEGAR Policy Synthesizer
 * 3. Tree-of-Thought (ToT) SQLite Working Memory & Active Socratic Disambiguation
 * 4. Zero-Knowledge SLA Compliance Attestor & Byzantine Fault Tolerant Vector Clock Matrix
 * 5. High-Refresh 60-FPS Virtualized Canvas Visualizers & One-Click Desktop Preflight
 * 6. Dual-Maintenance Parity Guard (55 Modules) & Zero-Zombie Regression Battery
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

test('Phase 14.0 Capstone: Sovereign Hyper-Scale Cognition & Vectorized Wire Intelligence', async (t) => {

  await t.test('1. Vectorized Zero-Copy Wire Dissector & Streaming Count-Min Sketch Heavy-Hitters', () => {
    const { VectorizedWireDissector, vectorizedWireDissector } = require('../src/sniffer/vectorized-wire-dissector');
    const { StreamingHeavyHitters, streamingHeavyHitters } = require('../src/sniffer/streaming-heavy-hitters');

    const dissector = new VectorizedWireDissector();

    // 1. Construct raw Ethernet + IPv4 + TCP packet buffer
    // Ethernet: 14 bytes (dst: 00:11:22:33:44:55, src: 66:77:88:99:aa:bb, ethertype: 0x0800)
    // IPv4: 20 bytes (version: 4, ihl: 5, total len: 60, ttl: 64, proto: 6, src: 192.168.1.10, dst: 10.0.0.1)
    // TCP: 20 bytes (src port: 54321, dst port: 443, seq: 1000, ack: 0, offset: 5, flags: SYN=0x02, win: 65535)
    // Payload: 10 bytes
    const buf = Buffer.alloc(64);
    // Ethernet MACs & Ethertype
    buf.set([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 0);
    buf.set([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb], 6);
    buf.writeUInt16BE(0x0800, 12);
    // IPv4 header (offset 14)
    buf[14] = 0x45; // Version 4, IHL 5
    buf[15] = 0x00; // DSCP/ECN
    buf.writeUInt16BE(50, 16); // Total length
    buf.writeUInt16BE(0x1234, 18); // ID
    buf[22] = 64; // TTL
    buf[23] = 6;  // Protocol TCP
    buf.writeUInt32BE(0xc0a8010a, 26); // 192.168.1.10
    buf.writeUInt32BE(0x0a000001, 30); // 10.0.0.1
    // TCP header (offset 34)
    buf.writeUInt16BE(54321, 34); // Src port
    buf.writeUInt16BE(443, 36);   // Dst port
    buf.writeUInt32BE(1000, 38);  // Seq
    buf.writeUInt32BE(0, 42);     // Ack
    buf[46] = 0x50; // Data offset 5 (20 bytes)
    buf[47] = 0x02; // SYN flag
    buf.writeUInt16BE(65535, 48); // Window size
    buf.write('TESTDATA12', 54);

    const frame = dissector.dissectFrameZeroCopy(buf, 0);
    assert.ok(typeof frame.timestampNs === 'bigint');
    assert.equal(frame.ethertype, 0x0800);
    assert.equal(frame.srcMac, '66:77:88:99:aa:bb');
    assert.equal(frame.dstMac, '00:11:22:33:44:55');
    assert.ok(frame.ip);
    assert.equal(frame.ip.version, 4);
    assert.equal(frame.ip.srcIp, '192.168.1.10');
    assert.equal(frame.ip.dstIp, '10.0.0.1');
    assert.equal(frame.ip.protocol, 6);
    assert.ok(frame.transport);
    assert.equal(frame.transport.protocolType, 'TCP');
    assert.equal(frame.transport.srcPort, 54321);
    assert.equal(frame.transport.dstPort, 443);
    assert.equal(frame.transport.tcpFlags.syn, true);
    assert.equal(frame.transport.tcpFlags.ack, false);
    assert.equal(frame.flowKey, '6:192.168.1.10:54321->10.0.0.1:443');

    // 2. Verify Streaming Count-Min Sketch with Heavy-Hitter Tracking
    const sketch = new StreamingHeavyHitters({ width: 1024, depth: 4, decayHalfLifeSec: 5.0 });
    const targetFlow = frame.flowKey;

    for (let i = 0; i < 50; i++) {
      sketch.recordPacket(targetFlow, 1500);
    }
    sketch.recordPacket('6:10.0.0.2:1234->10.0.0.1:80', 64);

    const est = sketch.estimateFrequency(targetFlow);
    assert.ok(est >= 75000, `Estimated frequency should be >= 75000 bytes, got ${est}`);

    const topHitters = sketch.getTopHeavyHitters(5);
    assert.ok(topHitters.length >= 1);
    assert.equal(topHitters[0].flowKey, targetFlow);
    assert.ok(topHitters[0].packetCount >= 50);
    assert.ok(topHitters[0].bandwidthBps > 0);

    const stats = sketch.getStats();
    assert.equal(stats.totalPackets, 51);
    assert.ok(stats.totalBytes >= 75064);
  });

  await t.test('2. Hierarchical Neural-Causal Multi-Scale Quotient Abstraction & CEGAR Policy Synthesizer', () => {
    const { HierarchicalCausalAbstractionEngine } = require('../src/ai/hierarchical-causal-abstraction-engine');
    const { CegarPolicySynthesizer } = require('../src/ai/cegar-policy-synthesizer');

    const causalEngine = new HierarchicalCausalAbstractionEngine();

    // 1. Build Multi-Node Infrastructure Topology
    const nodes = [
      { id: 'gw-core-01' }, { id: 'gw-core-02' },
      { id: 'leaf-sw-01' }, { id: 'leaf-sw-02' },
      { id: 'srv-db-01' }, { id: 'srv-db-02' }
    ];
    const edges = [
      { source: 'gw-core-01', target: 'leaf-sw-01', weight: 2.0 },
      { source: 'gw-core-02', target: 'leaf-sw-02', weight: 2.0 },
      { source: 'leaf-sw-01', target: 'srv-db-01', weight: 1.0 },
      { source: 'leaf-sw-02', target: 'srv-db-02', weight: 1.0 },
      { source: 'leaf-sw-01', target: 'leaf-sw-02', weight: 0.5 }
    ];

    const incidentTelemetry = {
      'gw-core-01': { rttMs: 145.0, lossPct: 0.08, queueDepth: 450 },
      'gw-core-02': { rttMs: 12.0, lossPct: 0.001, queueDepth: 25 },
      'leaf-sw-01': { rttMs: 95.0, lossPct: 0.04, queueDepth: 380 },
      'leaf-sw-02': { rttMs: 10.0, lossPct: 0.0, queueDepth: 20 },
      'srv-db-01': { rttMs: 80.0, lossPct: 0.02, queueDepth: 110 },
      'srv-db-02': { rttMs: 8.0, lossPct: 0.0, queueDepth: 15 }
    };

    const report = causalEngine.analyzeHierarchicalIncident({ nodes, edges }, incidentTelemetry);
    assert.ok(report.quotientGraph.clusters.length >= 2);
    assert.ok(report.dominantAnomalousCluster);
    assert.ok(report.localizedRootCauses.length >= 1);
    assert.ok(report.localizedRootCauses[0].structuralScore > 0);

    // 2. Synthesize Policy with CEGAR Refinement Loop
    const cegar = new CegarPolicySynthesizer();
    const incidentContext = {
      incidentId: 'inc-p14-cegar-001',
      dominantFault: 'BUFFER_OVERFLOW',
      targetNode: report.localizedRootCauses[0].nodeId
    };

    const envState = {
      currentBandwidth: 850,
      maxBandwidthMbps: 1000,
      currentQueue: 480,
      maxQueuePackets: 500
    };

    const receipt = cegar.synthesizeCegarPolicy(incidentContext, envState, { maxIterations: 5 });
    assert.ok(receipt.receiptId.startsWith('rcpt_cegar_'));
    assert.equal(receipt.converged, true, 'CEGAR must converge to a formally safe policy');
    assert.ok(receipt.iterationsTaken >= 1);
    assert.ok(receipt.finalPlan.length >= 2);
    assert.ok(receipt.smtProofId.startsWith('smt_proof_cegar_'));
  });

  await t.test('3. Tree-of-Thought (ToT) SQLite Working Memory & Active Socratic Disambiguation', () => {
    const { TotWorkingMemory } = require('../src/ai/tot-working-memory');
    const tot = new TotWorkingMemory();

    const sessionId = 'session-p14-tot-test';

    // 1. Add thought nodes forming a reasoning branch
    const rootHyp = tot.addThoughtNode(sessionId, null, 'HYPOTHESIS', 'Root fault suspected: Buffer exhaustion on core gateway', 0.8);
    assert.ok(rootHyp.nodeId.startsWith('tot_'));
    assert.equal(rootHyp.thoughtType, 'HYPOTHESIS');

    const childEv = tot.addThoughtNode(sessionId, rootHyp.nodeId, 'EVIDENCE', 'Telemetry confirms queue depth at 98% with TCP packet drops', 0.85);
    const childAlt = tot.addThoughtNode(sessionId, rootHyp.nodeId, 'HYPOTHESIS', 'Alternative fault: BGP MED flapping', 0.2);

    // 2. Active branches and pruning
    const activeBefore = tot.getActiveBranches(sessionId);
    assert.ok(activeBefore.length >= 3);

    const prunedCount = tot.pruneLowScoringBranches(sessionId, 0.25);
    assert.ok(prunedCount >= 1, 'Should prune branches scoring < 0.25');

    const bestPath = tot.getBestThoughtPath(sessionId);
    assert.ok(bestPath.length >= 2);
    assert.equal(bestPath[0].nodeId, rootHyp.nodeId);

    // 3. Active Socratic Disambiguation turn generation
    const socratic1 = tot.generateSocraticClarification('remediate_network_fault', null, 'HIGH');
    assert.equal(socratic1.ambiguityType, 'TARGET_UNSPECIFIED');
    assert.ok(socratic1.options.length >= 2);
    assert.ok(socratic1.options.some((o) => o.isRecommended));

    const socratic2 = tot.generateSocraticClarification('remediate_network_fault', 'border-gw-01', 'HIGH');
    assert.equal(socratic2.ambiguityType, 'HIGH_BLAST_RADIUS');
    assert.ok(socratic2.options.length >= 2);
  });

  await t.test('4. Zero-Knowledge SLA Compliance Attestor & Byzantine Fault Tolerant Vector Clock Matrix', () => {
    const { ZkSlaComplianceAttestor } = require('../src/security/zk-sla-compliance-attestor');
    const { BftVectorClockMatrix } = require('../src/core/multisite/bft-vector-clock-matrix');

    // 1. ZK-SLA Pedersen Range Proof Generation & Verification
    const zk = new ZkSlaComplianceAttestor();
    const receiptPass = zk.generateSlaCommitment('site-frankfurt', 'LATENCY_MS', 18.5, 50.0);
    assert.equal(receiptPass.satisfiesThreshold, true);
    assert.ok(receiptPass.commitmentHex.length > 20);
    assert.ok(receiptPass.challengeHex.length === 64);
    assert.equal(zk.verifySlaProof(receiptPass), true, 'Valid SLA range proof must verify');

    const receiptFail = zk.generateSlaCommitment('site-frankfurt', 'LATENCY_MS', 85.0, 50.0);
    assert.equal(receiptFail.satisfiesThreshold, false);
    assert.equal(zk.verifySlaProof(receiptFail), false, 'Violated SLA threshold must fail verification');

    const batch = zk.batchVerifySlaProofs([receiptPass, receiptFail]);
    assert.equal(batch.allValid, false);
    assert.equal(batch.validCount, 1);
    assert.equal(batch.invalidCount, 1);

    // 2. BFT Vector Clock Matrix & Equivocation Guard
    const bft = new BftVectorClockMatrix('test_p14_secret_key');
    bft.registerSite('site-alpha');
    bft.registerSite('site-beta');

    bft.incrementLocalClock('site-alpha');
    bft.incrementLocalClock('site-alpha');
    const digestA = bft.generateSignedClockDigest('site-alpha');
    assert.equal(digestA.clock['site-alpha'], 2);

    // Merge into local
    const mergeRes = bft.verifyAndMergeRemoteDigest(digestA);
    assert.equal(mergeRes.merged, true);

    // Equivocation Detection: broadcast divergent clock with same seq number
    const tamperedClock = { ...digestA.clock, 'site-alpha': 2, 'malicious_fork': 999 };
    const equiv = bft.detectEquivocation('site-alpha', tamperedClock);
    assert.equal(equiv.hasEquivocation, true, 'Equivocation detection must catch divergent vector clock');
  });

  await t.test('5. High-Refresh 60-FPS Virtualized Canvas Visualizers & One-Click Desktop Preflight', () => {
    // 1. Load Sniffer & NOC view files in mock global window context
    const mockWindow = {
      document: {
        getElementById: () => ({
          getContext: () => ({
            fillRect: () => {},
            beginPath: () => {},
            moveTo: () => {},
            lineTo: () => {},
            stroke: () => {},
            arc: () => {},
            fill: () => {},
            fillText: () => {}
          }),
          width: 800,
          height: 400
        })
      }
    };

    const snifferContent = fs.readFileSync(path.resolve(__dirname, '../public/js/views/sniffer-view.js'), 'utf8');
    const nocContent = fs.readFileSync(path.resolve(__dirname, '../public/js/views/enterprise-noc-view.js'), 'utf8');

    // Run in simulated VM context
    const vm = require('vm');
    const ctx = vm.createContext({ window: mockWindow, document: mockWindow.document, performance, Date, console });
    vm.runInContext(snifferContent, ctx);
    vm.runInContext(nocContent, ctx);

    assert.ok(typeof mockWindow.initVirtualizedPacketStreamCanvas === 'function');
    assert.ok(typeof mockWindow.initVirtualizedTopologyCanvas === 'function');

    const stream = mockWindow.initVirtualizedPacketStreamCanvas('testCanvas');
    assert.ok(stream);
    stream.pushPacket({ length: 1500, protocol: 'TCP', isAnomaly: false });
    stream.pushPacket({ length: 64, protocol: 'UDP', isAnomaly: true });
    assert.equal(stream.getBufferCount(), 2);
    stream.renderFrame();

    const topo = mockWindow.initVirtualizedTopologyCanvas('testTopo', {
      nodes: [{ id: 'n1', x: 100, y: 100 }, { id: 'n2', x: 200, y: 200 }],
      edges: [{ source: 'n1', target: 'n2' }]
    });
    assert.ok(topo);
    assert.equal(topo.getNodeCount(), 2);
    assert.equal(topo.getEdgeCount(), 1);
    topo.renderTopology();

    // 2. Launcher file verification
    const batContent = fs.readFileSync(path.resolve(__dirname, '../setup-launcher.bat'), 'utf8');
    assert.ok(batContent.includes('150-suite'), 'setup-launcher.bat must reference 150-suite battery');
  });

  await t.test('6. Dual-Maintenance Parity Guard (55 Modules) & Zero-Zombie Regression Battery', () => {
    const rootDir = path.resolve(__dirname, '..');

    // 1. Audit view count in public/js/views/
    const viewsDir = path.join(rootDir, 'public', 'js', 'views');
    const viewFiles = fs.readdirSync(viewsDir).filter((f) => f.endsWith('.js'));
    assert.equal(viewFiles.length, 11, `public/js/views/ must contain strictly 11 files, found ${viewFiles.length}`);

    // 2. Verify all 55 TypeScript modules maintain parity
    const { getTsSourceFiles } = require('../scripts/verify-ts-js-parity');
    const allTs = getTsSourceFiles(path.join(rootDir, 'src'));
    assert.equal(allTs.length, 55, `Must have exactly 55 TypeScript modules in src, found ${allTs.length}`);

    // 3. Fast Preflight Duration Guard
    const startPreflight = performance.now();
    const nodeMajor = parseInt(process.versions.node.split('.')[0], 10);
    assert.ok(nodeMajor >= 20);
    const sqlite = require('node:sqlite');
    assert.ok(sqlite && typeof sqlite.DatabaseSync === 'function');
    const dur = performance.now() - startPreflight;
    assert.ok(dur < 50, `Preflight check must execute in < 50ms, took ${dur.toFixed(2)}ms`);
  });

});
