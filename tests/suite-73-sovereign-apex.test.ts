// tests/suite-73-sovereign-apex.test.ts
import { strict as assert } from 'node:assert';
import * as crypto from 'node:crypto';
import { NeuroSymbolicApexEngine } from '../src/ai/neuro-symbolic-apex';
import { WireDissectorApex } from '../src/sniffer/wire-dissector-apex';
import { SpectralGNNTopologyEngine } from '../src/topology/spectral-gnn-apex';
import { DSRLLyapunovSafetyVault } from '../src/security/dsrl-lyapunov-vault';

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

  console.log('=== [SUITE 73] ALL SOVEREIGN-APEX ASSERTIONS PASSED (100%) ===');
}

if (require.main === module) {
  runSuite73SovereignApex().catch((err) => {
    console.error('Suite 73 failed:', err);
    process.exit(1);
  });
}
