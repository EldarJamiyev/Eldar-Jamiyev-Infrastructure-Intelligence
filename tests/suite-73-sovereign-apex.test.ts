// tests/suite-73-sovereign-apex.test.ts
import { strict as assert } from 'node:assert';
import * as crypto from 'node:crypto';
import { NeuroSymbolicApexEngine } from '../src/ai/neuro-symbolic-apex';
import { WireDissectorApex } from '../src/sniffer/wire-dissector-apex';
import { SpectralGNNTopologyEngine } from '../src/topology/spectral-gnn-apex';
import { DSRLLyapunovSafetyVault } from '../src/security/dsrl-lyapunov-vault';

// Host engine integrations
const { PacketDecoder } = require('../src/network/packet-decoding/packet-decoder');
const { TopologyEngine } = require('../src/network/topology/topology-engine');
const { AIBrain } = require('../src/core/ai-brain');
const { AutonomousRemediationEngine } = require('../src/systems/remediation/autonomous-remediation-engine');

export async function runSuite73SovereignApex(): Promise<void> {
  console.log('=== [SUITE 73] EJII v2.0.0-SOVEREIGN-APEX VERIFICATION ===');

  // 1. Verify Smooth Differentiable STL, Velocity, TTV & Hare-Niemeyer Exact 100.0% Sum
  const ai = new NeuroSymbolicApexEngine(12.0);
  const stlRes = ai.evaluateTemporallyBoundedAlways(
    'SLA_WAN_GATEWAY',
    [
      { id: 'RTT_BOUND', metric: 'rttMs', operator: 'LTE', threshold: 50, weight: 1.0 },
      { id: 'LOSS_BOUND', metric: 'packetLossPct', operator: 'LTE', threshold: 2.0, weight: 10.0 },
    ],
    [
      { timestampMs: 1000, rttMs: 20, packetLossPct: 0.1, cpuSaturationPct: 15, tcpRetransmitRate: 0.01 },
      { timestampMs: 2000, rttMs: 30, packetLossPct: 0.2, cpuSaturationPct: 18, tcpRetransmitRate: 0.02 },
      { timestampMs: 3000, rttMs: 40, packetLossPct: 0.3, cpuSaturationPct: 22, tcpRetransmitRate: 0.03 },
    ]
  );

  assert.equal(stlRes.satisfied, true, 'STL trajectory within bounds must be satisfied');
  assert.ok(stlRes.velocityPerSec < 0, 'Degrading RTT trajectory must yield negative robustness velocity');
  assert.equal(stlRes.estimatedTimeToViolationSec, 1.0, 'At +10ms/sec from 40ms toward 50ms threshold, TTV must be exactly 1.0s');

  const cf = ai.evaluateCounterfactualMatrix([
    { id: 'H1', name: 'ISP Upstream Congestion', prior: 0.333, likelihoodGivenEvidence: 0.81, interventionalEfficacy: 0.9, remediationId: 'REM_QOS' },
    { id: 'H2', name: 'Local NIC Buffer Exhaustion', prior: 0.333, likelihoodGivenEvidence: 0.47, interventionalEfficacy: 0.85, remediationId: 'REM_NIC_RESET' },
    { id: 'H3', name: 'DNS Resolver Timeout', prior: 0.334, likelihoodGivenEvidence: 0.19, interventionalEfficacy: 0.95, remediationId: 'REM_DNS_FLUSH' },
  ]);
  const pctSum = cf.hypotheses.reduce((acc, h) => acc + Math.round(h.posteriorProbabilityPct * 10), 0);
  assert.equal(pctSum, 1000, 'Hare-Niemeyer posterior percentages must sum to EXACTLY 100.0% (1000 tenths)');

  // 2. Verify Hardened RFC 1035 DNS Cyclic Pointer Protection
  const maliciousDnsPacket = new Uint8Array([
    0x13, 0x37, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xc0, 0x0c, // Self-referencing compression pointer at offset 12 -> offset 12
    0x00, 0x01, 0x00, 0x01,
  ]);
  const dnsResult = WireDissectorApex.dissectDNSFrame(maliciousDnsPacket, 0, maliciousDnsPacket.byteLength);
  assert.ok(dnsResult !== null, 'Malicious cyclic DNS pointer must be safely handled without hanging');
  assert.equal(dnsResult?.questions.length, 0, 'Cyclic pointer loop must terminate cleanly with 0 extracted questions');

  // 3. Verify Spectral Graph Laplacian Fiedler Value (lambda_2) & Blast Radius
  const topoEngine = new SpectralGNNTopologyEngine();
  const topoReport = topoEngine.analyzeTopology(
    [
      { id: 'WS-01', role: 'WORKSTATION', latencyMs: 1, packetLossPct: 0 },
      { id: 'SW-CORE', role: 'SWITCH', latencyMs: 2, packetLossPct: 0 },
      { id: 'GW-EDGE', role: 'GATEWAY', latencyMs: 8, packetLossPct: 0 },
      { id: 'PRN-FLOOR2', role: 'PRINTER', latencyMs: 4, packetLossPct: 0 },
    ],
    [
      { source: 'WS-01', target: 'SW-CORE', bandwidthMbps: 1000, linkLossPct: 0, rttMs: 1 },
      { source: 'SW-CORE', target: 'GW-EDGE', bandwidthMbps: 1000, linkLossPct: 0, rttMs: 5 },
      { source: 'SW-CORE', target: 'PRN-FLOOR2', bandwidthMbps: 100, linkLossPct: 0, rttMs: 2 },
    ],
    'WS-01'
  );
  assert.ok(topoReport.algebraicConnectivityLambda2 > 0, 'Connected topology must have strictly positive Fiedler eigenvalue lambda_2 > 0');
  const coreSwitchNode = topoReport.nodes.find((n) => n.nodeId === 'SW-CORE');
  assert.equal(coreSwitchNode?.blastRadiusCount, 2, 'SW-CORE failure must strand exactly 2 downstream nodes (GW-EDGE and PRN-FLOOR2)');

  // 4. Verify DSRL Safety Vault Stage-6 Lyapunov Rollback & Merkle Root
  const validScriptHash = crypto.createHash('sha256').update('ipconfig /flushdns').digest('hex');
  const vault = new DSRLLyapunovSafetyVault('EJII_SOVEREIGN_HMAC_SECRET_KEY_2026', [validScriptHash]);
  let rollbackTriggered = false;
  let callCount = 0;

  const entry = await vault.executeGuardedRemediation(
    {
      actionId: 'REM_TEST_DEGRADATION',
      scriptSha256: validScriptHash,
      requiresElevation: false,
      inverseRollbackActionId: 'REM_UNDO',
      maxAllowedCpuPct: 85,
      symbolicPrecondition: (s) => s.gatewayReachable,
      executeUserSpaceAction: async () => ({ exitCode: 0, stdout: 'applied' }),
      executeInverseRollback: async () => {
        rollbackTriggered = true;
        return { exitCode: 0, stdout: 'rolled back' };
      },
    },
    async () => {
      callCount++;
      // Simulate empirical state degradation after action to test automatic Stage-6 Lyapunov Rollback
      return callCount === 1
        ? { timestampMs: 1000, stlRobustnessRho: 25.0, cpuLoadPct: 30, memoryUsedPct: 40, activeManagementSocketAlive: true, gatewayReachable: true }
        : { timestampMs: 2000, stlRobustnessRho: 10.0, cpuLoadPct: 35, memoryUsedPct: 40, activeManagementSocketAlive: true, gatewayReachable: true };
    }
  );

  assert.equal(entry.verdict, 'ROLLED_BACK_LYAPUNOV_VIOLATION', 'Degraded post-action STL robustness must trigger Stage-6 rollback');
  assert.equal(rollbackTriggered, true, 'Inverse rollback handler must be invoked automatically');
  const verification = vault.verifyAuditLedgerAndMerkleRoot();
  assert.equal(verification.intact, true, 'HMAC-SHA256 Merkle Audit Ledger must verify 100% intact');

  // 5. End-to-End Production Host Engine Wiring Verification
  console.log('--- 5. End-to-End Production Host Engine Wiring Verification ---');

  // 5.1 Strict HMAC Secret Length Gate
  assert.throws(
    () => new DSRLLyapunovSafetyVault('short', []),
    /requires a cryptographic HMAC secret >= 16 characters/,
    'DSRLLyapunovSafetyVault must strictly reject keys < 16 characters'
  );

  // 5.2 PacketDecoder TLS 1.3 JA4 Wire Dissection Integration (Full Ethernet Frame decode() and dissectFrame())
  const sni = 'noc.ejii.internal';
  const sniBuf = Buffer.from(sni, 'utf8');
  const sniExt = Buffer.concat([Buffer.from([0x00, 0x00, 0x00, sniBuf.length + 5, 0x00, sniBuf.length + 3, 0x00, 0x00, sniBuf.length]), sniBuf]);
  const supVerExt = Buffer.from([0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
  const extBuf = Buffer.concat([sniExt, supVerExt]);
  const extLenBuf = Buffer.alloc(2);
  extLenBuf.writeUInt16BE(extBuf.length, 0);
  const body = Buffer.concat([Buffer.from([0x03, 0x03]), Buffer.alloc(32, 0xaa), Buffer.from([0x00]), Buffer.from([0x00, 0x04, 0x13, 0x01, 0x13, 0x02]), Buffer.from([0x01, 0x00]), extLenBuf, extBuf]);
  const hsHeader = Buffer.alloc(4);
  hsHeader.writeUInt8(0x01, 0);
  hsHeader.writeUIntBE(body.length, 1, 3);
  const record = Buffer.concat([Buffer.from([0x16, 0x03, 0x01]), Buffer.alloc(2), hsHeader, body]);
  record.writeUInt16BE(record.length - 5, 3);

  // Wrap in full raw Ethernet + IPv4 + TCP frame (54 bytes header + TLS record)
  const totalEthLen = 14 + 20 + 20 + record.length;
  const rawEthFrame = Buffer.alloc(totalEthLen);
  rawEthFrame.set([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00], 0);
  rawEthFrame.writeUInt8(0x45, 14);
  rawEthFrame.writeUInt16BE(20 + 20 + record.length, 16);
  rawEthFrame.writeUInt8(64, 22);
  rawEthFrame.writeUInt8(6, 23); // TCP
  rawEthFrame.set([192, 168, 31, 89], 26);
  rawEthFrame.set([192, 168, 31, 1], 30);
  rawEthFrame.writeUInt16BE(54321, 34); // srcPort
  rawEthFrame.writeUInt16BE(443, 36);   // dstPort
  rawEthFrame.writeUInt8(0x50, 46);     // dataOffset 5 (20 bytes)
  rawEthFrame.writeUInt8(0x18, 47);     // ACK, PSH
  rawEthFrame.set(record, 54);

  const decodedTls = PacketDecoder.decode(rawEthFrame);
  assert.ok(decodedTls.tlsApex !== null, 'PacketDecoder.decode must automatically produce tlsApex on TLS 1.3 frame');
  assert.ok(decodedTls.ja4Fingerprint && decodedTls.ja4Fingerprint.startsWith('t13d'), 'JA4 fingerprint from decode() must start with t13d');
  assert.strictEqual(decodedTls.sniHostName, 'noc.ejii.internal', 'SNI from decode() must decode to noc.ejii.internal');
  assert.strictEqual(decodedTls.negotiatedTlsVersion, 'TLS 1.3 (RFC 8446)', 'negotiatedTlsVersion from decode() must be TLS 1.3 (RFC 8446)');

  const dissectedTls = PacketDecoder.dissectFrame(rawEthFrame);
  assert.strictEqual(dissectedTls.ja4Fingerprint, decodedTls.ja4Fingerprint, 'dissectFrame() and decode() must produce identical ja4Fingerprint');

  // 5.3 PacketDecoder DNS Shannon Entropy & DGA Wire Integration (Full Ethernet Frame decode())
  const dnsLabels = Buffer.from('\x05ejii2\x08internal\x00', 'binary');
  const dnsPayload = Buffer.concat([Buffer.from([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), dnsLabels, Buffer.from([0x00, 0x01, 0x00, 0x01])]);

  // Wrap in full raw Ethernet + IPv4 + UDP frame (42 bytes header + DNS payload)
  const totalDnsLen = 14 + 20 + 8 + dnsPayload.length;
  const rawDnsEthFrame = Buffer.alloc(totalDnsLen);
  rawDnsEthFrame.set([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00], 0);
  rawDnsEthFrame.writeUInt8(0x45, 14);
  rawDnsEthFrame.writeUInt16BE(20 + 8 + dnsPayload.length, 16);
  rawDnsEthFrame.writeUInt8(64, 22);
  rawDnsEthFrame.writeUInt8(17, 23); // UDP
  rawDnsEthFrame.set([192, 168, 31, 89], 26);
  rawDnsEthFrame.set([192, 168, 31, 1], 30);
  rawDnsEthFrame.writeUInt16BE(53535, 34); // srcPort
  rawDnsEthFrame.writeUInt16BE(53, 36);   // dstPort
  rawDnsEthFrame.writeUInt16BE(8 + dnsPayload.length, 38);
  rawDnsEthFrame.set(dnsPayload, 42);

  const decodedDns = PacketDecoder.decode(rawDnsEthFrame);
  assert.ok(decodedDns.dnsApex !== null, 'PacketDecoder.decode must produce dnsApex on DNS frame');
  assert.strictEqual(typeof decodedDns.shannonEntropyBitsPerChar, 'number', 'Entropy must be a number');
  assert.strictEqual(typeof decodedDns.dgaOrTunnelSuspected, 'boolean', 'dgaOrTunnelSuspected must be boolean');
  assert.strictEqual(typeof decodedDns.dnsPointerCompressionJumps, 'number', 'dnsPointerCompressionJumps must be a number');

  // 5.4 TopologyEngine Live Spectral GNN Integration
  const hostTopoEngine = new TopologyEngine();
  const liveTopo = hostTopoEngine.getTopology();
  assert.strictEqual(typeof liveTopo.algebraicConnectivityLambda2, 'number', 'Topology must include algebraicConnectivityLambda2');
  assert.ok(['NOMINAL', 'FRAGILE_BRIDGE', 'CRITICAL_PARTITION_IMMINENT'].includes(liveTopo.partitionRiskLevel), 'Partition risk must be valid enum');
  assert.ok(Array.isArray(liveTopo.criticalCutEdges), 'Critical cut edges must be array');
  const sampledNode = liveTopo.nodes.find((n: any) => n.fiedlerCoordinate !== undefined);
  assert.ok(sampledNode !== undefined, 'Live topology nodes must be enriched with fiedlerCoordinate');

  // 5.5 AIBrain Live Neuro-Symbolic Evaluation
  const brain = new AIBrain({ autoStart: false });
  const brainEval = brain.evaluateApexNeuroSymbolic([], []);
  assert.strictEqual(typeof brainEval.smoothRobustness, 'number', 'smoothRobustness must be a number');
  assert.ok(Object.keys(brainEval.metricSensitivityGradient).length > 0, 'metricSensitivityGradient must have keys');
  assert.ok(brainEval.counterfactualApex.hypotheses.length >= 2, 'Counterfactual hypotheses must evaluate');
  const liveBrainState = brain.getLiveState();
  assert.ok(liveBrainState.stlApex !== undefined, 'getLiveState must include stlApex');
  assert.strictEqual(typeof liveBrainState.smoothRobustness, 'number', 'Live smoothRobustness must be number');

  // 5.6 AutonomousRemediationEngine Lyapunov Guarded Execution
  const remediationEng = new AutonomousRemediationEngine({ allowLiveOsMutation: false });
  const guardedExec = await remediationEng.executeGuardedApexRemediation();
  assert.strictEqual(typeof guardedExec.lyapunovDeltaEnergy, 'number', 'Lyapunov delta energy must be number');
  assert.strictEqual(typeof guardedExec.merkleRootHex, 'string', 'Merkle root must be string');
  assert.strictEqual(guardedExec.merkleRootHex.length, 64, 'Merkle root must be 64-character SHA-256 hex');

  console.log('=== [SUITE 73] ALL SOVEREIGN-APEX ASSERTIONS PASSED (100%) ===');
}

if (require.main === module) {
  runSuite73SovereignApex().catch((err) => {
    console.error('Suite 73 failed:', err);
    process.exit(1);
  });
}
