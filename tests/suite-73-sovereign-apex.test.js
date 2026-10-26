"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.runSuite73SovereignApex = runSuite73SovereignApex;
// tests/suite-73-sovereign-apex.test.ts
const node_assert_1 = require("node:assert");
const crypto = __importStar(require("node:crypto"));
const neuro_symbolic_apex_1 = require("../src/ai/neuro-symbolic-apex");
const wire_dissector_apex_1 = require("../src/sniffer/wire-dissector-apex");
const spectral_gnn_apex_1 = require("../src/topology/spectral-gnn-apex");
const dsrl_lyapunov_vault_1 = require("../src/security/dsrl-lyapunov-vault");
// Host engine integrations
const { PacketDecoder } = require('../src/network/packet-decoding/packet-decoder');
const { TopologyEngine } = require('../src/network/topology/topology-engine');
const { AIBrain } = require('../src/core/ai-brain');
const { AutonomousRemediationEngine } = require('../src/systems/remediation/autonomous-remediation-engine');
async function runSuite73SovereignApex() {
    console.log('=== [SUITE 73] EJII v2.0.0-SOVEREIGN-APEX VERIFICATION ===');
    // 1. Verify Smooth Differentiable STL, Velocity, TTV & Hare-Niemeyer Exact 100.0% Sum
    const ai = new neuro_symbolic_apex_1.NeuroSymbolicApexEngine(12.0);
    const stlRes = ai.evaluateTemporallyBoundedAlways('SLA_WAN_GATEWAY', [
        { id: 'RTT_BOUND', metric: 'rttMs', operator: 'LTE', threshold: 50, weight: 1.0 },
        { id: 'LOSS_BOUND', metric: 'packetLossPct', operator: 'LTE', threshold: 2.0, weight: 10.0 },
    ], [
        { timestampMs: 1000, rttMs: 20, packetLossPct: 0.1, cpuSaturationPct: 15, tcpRetransmitRate: 0.01 },
        { timestampMs: 2000, rttMs: 30, packetLossPct: 0.2, cpuSaturationPct: 18, tcpRetransmitRate: 0.02 },
        { timestampMs: 3000, rttMs: 40, packetLossPct: 0.3, cpuSaturationPct: 22, tcpRetransmitRate: 0.03 },
    ]);
    node_assert_1.strict.equal(stlRes.satisfied, true, 'STL trajectory within bounds must be satisfied');
    node_assert_1.strict.ok(stlRes.velocityPerSec < 0, 'Degrading RTT trajectory must yield negative robustness velocity');
    node_assert_1.strict.equal(stlRes.estimatedTimeToViolationSec, 1.0, 'At +10ms/sec from 40ms toward 50ms threshold, TTV must be exactly 1.0s');
    const cf = ai.evaluateCounterfactualMatrix([
        { id: 'H1', name: 'ISP Upstream Congestion', prior: 0.333, likelihoodGivenEvidence: 0.81, interventionalEfficacy: 0.9, remediationId: 'REM_QOS' },
        { id: 'H2', name: 'Local NIC Buffer Exhaustion', prior: 0.333, likelihoodGivenEvidence: 0.47, interventionalEfficacy: 0.85, remediationId: 'REM_NIC_RESET' },
        { id: 'H3', name: 'DNS Resolver Timeout', prior: 0.334, likelihoodGivenEvidence: 0.19, interventionalEfficacy: 0.95, remediationId: 'REM_DNS_FLUSH' },
    ]);
    const pctSum = cf.hypotheses.reduce((acc, h) => acc + Math.round(h.posteriorProbabilityPct * 10), 0);
    node_assert_1.strict.equal(pctSum, 1000, 'Hare-Niemeyer posterior percentages must sum to EXACTLY 100.0% (1000 tenths)');
    // 2. Verify Hardened RFC 1035 DNS Cyclic Pointer Protection
    const maliciousDnsPacket = new Uint8Array([
        0x13, 0x37, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc0, 0x0c, // Self-referencing compression pointer at offset 12 -> offset 12
        0x00, 0x01, 0x00, 0x01,
    ]);
    const dnsResult = wire_dissector_apex_1.WireDissectorApex.dissectDNSFrame(maliciousDnsPacket, 0, maliciousDnsPacket.byteLength);
    node_assert_1.strict.ok(dnsResult !== null, 'Malicious cyclic DNS pointer must be safely handled without hanging');
    node_assert_1.strict.equal(dnsResult?.questions.length, 0, 'Cyclic pointer loop must terminate cleanly with 0 extracted questions');
    // 3. Verify Spectral Graph Laplacian Fiedler Value (lambda_2) & Blast Radius
    const topoEngine = new spectral_gnn_apex_1.SpectralGNNTopologyEngine();
    const topoReport = topoEngine.analyzeTopology([
        { id: 'WS-01', role: 'WORKSTATION', latencyMs: 1, packetLossPct: 0 },
        { id: 'SW-CORE', role: 'SWITCH', latencyMs: 2, packetLossPct: 0 },
        { id: 'GW-EDGE', role: 'GATEWAY', latencyMs: 8, packetLossPct: 0 },
        { id: 'PRN-FLOOR2', role: 'PRINTER', latencyMs: 4, packetLossPct: 0 },
    ], [
        { source: 'WS-01', target: 'SW-CORE', bandwidthMbps: 1000, linkLossPct: 0, rttMs: 1 },
        { source: 'SW-CORE', target: 'GW-EDGE', bandwidthMbps: 1000, linkLossPct: 0, rttMs: 5 },
        { source: 'SW-CORE', target: 'PRN-FLOOR2', bandwidthMbps: 100, linkLossPct: 0, rttMs: 2 },
    ], 'WS-01');
    node_assert_1.strict.ok(topoReport.algebraicConnectivityLambda2 > 0, 'Connected topology must have strictly positive Fiedler eigenvalue lambda_2 > 0');
    const coreSwitchNode = topoReport.nodes.find((n) => n.nodeId === 'SW-CORE');
    node_assert_1.strict.equal(coreSwitchNode?.blastRadiusCount, 2, 'SW-CORE failure must strand exactly 2 downstream nodes (GW-EDGE and PRN-FLOOR2)');
    // 4. Verify DSRL Safety Vault Stage-6 Lyapunov Rollback & Merkle Root
    const validScriptHash = crypto.createHash('sha256').update('ipconfig /flushdns').digest('hex');
    const vault = new dsrl_lyapunov_vault_1.DSRLLyapunovSafetyVault('EJII_SOVEREIGN_HMAC_SECRET_KEY_2026', [validScriptHash]);
    let rollbackTriggered = false;
    let callCount = 0;
    const entry = await vault.executeGuardedRemediation({
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
    }, async () => {
        callCount++;
        // Simulate empirical state degradation after action to test automatic Stage-6 Lyapunov Rollback
        return callCount === 1
            ? { timestampMs: 1000, stlRobustnessRho: 25.0, cpuLoadPct: 30, memoryUsedPct: 40, activeManagementSocketAlive: true, gatewayReachable: true }
            : { timestampMs: 2000, stlRobustnessRho: 10.0, cpuLoadPct: 35, memoryUsedPct: 40, activeManagementSocketAlive: true, gatewayReachable: true };
    });
    node_assert_1.strict.equal(entry.verdict, 'ROLLED_BACK_LYAPUNOV_VIOLATION', 'Degraded post-action STL robustness must trigger Stage-6 rollback');
    node_assert_1.strict.equal(rollbackTriggered, true, 'Inverse rollback handler must be invoked automatically');
    const verification = vault.verifyAuditLedgerAndMerkleRoot();
    node_assert_1.strict.equal(verification.intact, true, 'HMAC-SHA256 Merkle Audit Ledger must verify 100% intact');
    // 5. End-to-End Production Host Engine Wiring Verification
    console.log('--- 5. End-to-End Production Host Engine Wiring Verification ---');
    // 5.1 Strict HMAC Secret Length Gate
    node_assert_1.strict.throws(() => new dsrl_lyapunov_vault_1.DSRLLyapunovSafetyVault('short', []), /requires a cryptographic HMAC secret >= 16 characters/, 'DSRLLyapunovSafetyVault must strictly reject keys < 16 characters');
    // 5.2 PacketDecoder TLS 1.3 JA4 Wire Dissection Integration
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
    const tlsDecodeRes = PacketDecoder.dissectApexWirePayload(record, 'TCP', 54321, 443, 0, record.length);
    node_assert_1.strict.ok(tlsDecodeRes.tlsApex !== null, 'PacketDecoder must produce tlsApex on TLS 1.3 payload');
    node_assert_1.strict.ok(tlsDecodeRes.ja4Fingerprint && tlsDecodeRes.ja4Fingerprint.startsWith('t13d'), 'JA4 fingerprint must start with t13d');
    node_assert_1.strict.strictEqual(tlsDecodeRes.sniHostName, 'noc.ejii.internal', 'SNI must decode to noc.ejii.internal');
    // 5.3 PacketDecoder DNS Shannon Entropy & DGA Wire Integration
    const dnsLabels = Buffer.from('\x05ejii2\x08internal\x00', 'binary');
    const dnsPayload = Buffer.concat([Buffer.from([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), dnsLabels, Buffer.from([0x00, 0x01, 0x00, 0x01])]);
    const dnsDecodeRes = PacketDecoder.dissectApexWirePayload(dnsPayload, 'UDP', 53535, 53, 0, dnsPayload.length);
    node_assert_1.strict.ok(dnsDecodeRes.dnsApex !== null, 'PacketDecoder must produce dnsApex on DNS payload');
    node_assert_1.strict.strictEqual(typeof dnsDecodeRes.shannonEntropyBitsPerChar, 'number', 'Entropy must be a number');
    node_assert_1.strict.strictEqual(typeof dnsDecodeRes.dgaOrTunnelSuspected, 'boolean', 'dgaOrTunnelSuspected must be boolean');
    // 5.4 TopologyEngine Live Spectral GNN Integration
    const hostTopoEngine = new TopologyEngine();
    const liveTopo = hostTopoEngine.getTopology();
    node_assert_1.strict.strictEqual(typeof liveTopo.algebraicConnectivityLambda2, 'number', 'Topology must include algebraicConnectivityLambda2');
    node_assert_1.strict.ok(['NOMINAL', 'FRAGILE_BRIDGE', 'CRITICAL_PARTITION_IMMINENT'].includes(liveTopo.partitionRiskLevel), 'Partition risk must be valid enum');
    node_assert_1.strict.ok(Array.isArray(liveTopo.criticalCutEdges), 'Critical cut edges must be array');
    const sampledNode = liveTopo.nodes.find((n) => n.fiedlerCoordinate !== undefined);
    node_assert_1.strict.ok(sampledNode !== undefined, 'Live topology nodes must be enriched with fiedlerCoordinate');
    // 5.5 AIBrain Live Neuro-Symbolic Evaluation
    const brain = new AIBrain({ autoStart: false });
    const brainEval = brain.evaluateApexNeuroSymbolic([], []);
    node_assert_1.strict.strictEqual(typeof brainEval.smoothRobustness, 'number', 'smoothRobustness must be a number');
    node_assert_1.strict.ok(Object.keys(brainEval.metricSensitivityGradient).length > 0, 'metricSensitivityGradient must have keys');
    node_assert_1.strict.ok(brainEval.counterfactualApex.hypotheses.length >= 2, 'Counterfactual hypotheses must evaluate');
    const liveBrainState = brain.getLiveState();
    node_assert_1.strict.ok(liveBrainState.stlApex !== undefined, 'getLiveState must include stlApex');
    node_assert_1.strict.strictEqual(typeof liveBrainState.smoothRobustness, 'number', 'Live smoothRobustness must be number');
    // 5.6 AutonomousRemediationEngine Lyapunov Guarded Execution
    const remediationEng = new AutonomousRemediationEngine({ allowLiveOsMutation: false });
    const guardedExec = await remediationEng.executeGuardedApexRemediation();
    node_assert_1.strict.strictEqual(typeof guardedExec.lyapunovDeltaEnergy, 'number', 'Lyapunov delta energy must be number');
    node_assert_1.strict.strictEqual(typeof guardedExec.merkleRootHex, 'string', 'Merkle root must be string');
    node_assert_1.strict.strictEqual(guardedExec.merkleRootHex.length, 64, 'Merkle root must be 64-character SHA-256 hex');
    console.log('=== [SUITE 73] ALL SOVEREIGN-APEX ASSERTIONS PASSED (100%) ===');
}
if (require.main === module) {
    runSuite73SovereignApex().catch((err) => {
        console.error('Suite 73 failed:', err);
        process.exit(1);
    });
}
//# sourceMappingURL=suite-73-sovereign-apex.test.js.map