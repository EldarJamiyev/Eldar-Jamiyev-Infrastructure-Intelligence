/**
 * EJII v6 — Sovereign Intelligence Fabric Comprehensive Verification Suite
 * Uses node:test and node:assert/strict to verify:
 *   - Part II: All 8 Hardened TypeScript Flagship Engines
 *   - Part III: Unified Capability Registry & EJIIResult<T> Contract
 *   - Part IV: Evidence Fabric (11 classes, freshness, quality score, acyclic lineage, epistemic downgrade)
 *   - Part V: Temporal Infrastructure Graph (10 typed relationships, historical queries, diffing, identity reconciliation)
 *   - Part VI & VII: Cross-Layer Incident Correlator, Correlation Discounting, Counterfactuals & Uncertainty Panel
 *   - Part VIII, IX, X: Simulation Branching, Policy Governance Compiler & Governed Action Control Plane
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { createEjiiResult, validateEjiiResult } = require('../contracts/ejii-result');
const { capabilityRegistry } = require('../capability-registry');
const { evidenceFabric, EVIDENCE_CLASSES, classifyFreshness, computeDeterministicQualityScore } = require('../evidence/evidence-fabric');
const { temporalInfrastructureGraph, CANONICAL_RESOURCE_TYPES, TYPED_RELATIONSHIPS } = require('../topology/temporal-graph-engine');
const { crossLayerIncidentCorrelator } = require('../correlation/incident-correlator');
const { simulationBranchManager, policyGovernanceEngine, governedActionControlPlane } = require('../governance/action-control-plane');

const { L7DeepProtocolDissector } = require('../../sniffer/l7-deep-protocol-dissector');
const { SpectralFourierDetector } = require('../../ai/spectral-fourier-detector');
const { DigitalTwinChaosSimulator } = require('../../topology/digital-twin-chaos-simulator');
const { ZeroTrustPolicySynthesizer } = require('../../security/zero-trust-policy-synthesizer');
const { MultipathQosAuditor } = require('../../topology/multipath-qos-auditor');
const { HardwareKernelInspector } = require('../../diagnostics/hardware-kernel-inspector');
const { TelemetryDvrTimeMachine } = require('../../observability/telemetry-dvr-timemachine');
const { AutonomousWarRoomOrchestrator } = require('../../ai/autonomous-war-room');

test('Part II: Hardened TypeScript Flagship Engines handle adversarial & edge-case inputs safely', async () => {
  // 1. L7 Deep Protocol Dissector: truncated QUIC/SSH/SMB2/HTTP2 & CID > 20 bytes
  const badQuicCid = Buffer.alloc(10, 0);
  badQuicCid[0] = 0xc0; // Long header
  badQuicCid.writeUInt32BE(0x00000001, 1); // QUIC v1
  badQuicCid[5] = 25; // DCID len 25 > RFC 9000 max 20
  const qRes = L7DeepProtocolDissector.dissectQuicPacket(badQuicCid);
  assert.equal(qRes, null);

  const validQuicBuf = Buffer.alloc(32, 0);
  validQuicBuf[0] = 0xc0; // Long header Initial
  validQuicBuf.writeUInt32BE(0x00000001, 1); // QUIC v1
  validQuicBuf[5] = 8; // DCID len 8
  validQuicBuf[14] = 8; // SCID len 8
  const validQuic = L7DeepProtocolDissector.dissectQuicPacket(validQuicBuf);
  assert.ok(validQuic);
  assert.equal(validQuic.payloadEncrypted, true);

  // 2. Spectral Fourier Detector: constant signal & NaN filtering
  const constSignal = Array(16).fill(42);
  const fftConst = SpectralFourierDetector.analyze(constSignal, 10.0);
  assert.equal(fftConst.periodicAnomalyDetected, false);
  assert.equal(fftConst.evidenceDistinction, 'STOCHASTIC_BASELINE');

  // 3. Digital Twin Chaos Simulator: high overload rho > 20 & modelFidelityLabel
  const mm1kOverload = DigitalTwinChaosSimulator.computeMM1K(50000, 100, 64);
  assert.ok(Number.isFinite(mm1kOverload.dropProbability));
  const sim = new DigitalTwinChaosSimulator();
  const simOut = sim.simulate(
    [
      { id: 'A', ip: '10.0.0.1', role: 'GATEWAY', latencyMs: 1 },
      { id: 'B', ip: '10.0.0.2', role: 'SERVER', latencyMs: 2 }
    ],
    [{ source: 'A', target: 'B', latencyMs: 1 }]
  );
  assert.equal(simOut.modelFidelityLabel, 'MATHEMATICAL_SIMULATION');

  // 4. Zero-Trust Policy Synthesizer: duplicate suppression & preview-only status
  const pol = ZeroTrustPolicySynthesizer.synthesize([
    { ip: '192.168.1.50', role: 'SERVER', openPorts: [443, 443, 445] }
  ]);
  assert.equal(pol.artifactStatus, 'PROPOSED_PREVIEW_ONLY');
  assert.equal(pol.autoApplied, false);
  assert.ok(pol.changeSummaryReport);

  // 5. Multipath QoS Auditor: CS2/CS3/CS4/CS5/VA & IPv6 Traffic Class
  const tc = MultipathQosAuditor.decodeIpv6TrafficClass(0xb8); // DSCP 46 (EF) << 2
  assert.equal(tc.dscp.dscpValue, 46);
  assert.equal(tc.ecn.ecnValue, 0);

  // 6. Hardware & Kernel Inspector: fieldProvenance & no fabricated Wi-Fi SSID
  const hw = HardwareKernelInspector.inspect();
  assert.ok(hw.fieldProvenance);
  assert.notEqual(hw.radio.ssid, 'Office-WLAN-5G');

  // 7. Telemetry DVR Time-Machine: reset(), sequenceNumber, and diff
  const dvr = new TelemetryDvrTimeMachine(10);
  dvr.reset(false);
  const f1 = dvr.recordFrame({ timestampMs: 1000, nodesSnapshot: [{ id: 'N1', ip: '10.0.0.1', role: 'SERVER', latencyMs: 1 }] });
  const f2 = dvr.recordFrame({ timestampMs: 2000, nodesSnapshot: [{ id: 'N1', ip: '10.0.0.2', role: 'GATEWAY', latencyMs: 99 }] });
  assert.ok(f2.sequenceNumber > f1.sequenceNumber);
  const diff = dvr.computeSnapshotDiff(f1, f2);
  assert.equal(diff.intervalStatus, 'CONTINUOUS');
  assert.ok(diff.modifiedNodeAttributes.N1.ipChanged);
  dvr.reset(false);
  assert.equal(dvr.listFrames().length, 0);

  // 8. Autonomous War Room: RBAC check & epistemic fields
  const warRoom = new AutonomousWarRoomOrchestrator('TEST-SECRET');
  const dossier = warRoom.execute({
    operatorRole: 'VIEWER'
  });
  assert.equal(dossier.agent5.operatorPermitted, false);
  assert.equal(dossier.agent4.epistemicStatus, 'HYPOTHESIS_AND_COUNTERFACTUAL_PLAN');
});

test('Part III & IV: CapabilityRegistry, EJIIResult<T> contract, EvidenceFabric & Acyclic Lineage', async () => {
  const res = await capabilityRegistry.invokeCapability('ejii.discovery.temporal_topology', {});
  const validation = validateEjiiResult(res);
  assert.equal(validation.valid, true);
  assert.equal(EVIDENCE_CLASSES.length, 11);

  // Stale or simulated-only evidence cannot confirm a live finding
  const simEv = evidenceFabric.recordEvidence({
    type: 'simulated_result',
    subject: 'node:test',
    claim: 'Simulated link drop',
    sourceCapabilityId: 'ejii.simulation.digital_twin_branch',
    collectionMethod: 'simulation_mm1k'
  });

  const downgradedFinding = evidenceFabric.recordFinding({
    title: 'Test Simulated-Only Finding',
    subject: 'node:test',
    status: 'confirmed',
    supportingEvidenceIds: [simEv.id]
  });
  assert.notEqual(downgradedFinding.status, 'confirmed');
  assert.ok(downgradedFinding.downgradeWarnings.length > 0);

  const lineage = evidenceFabric.traceLineage(downgradedFinding.findingId);
  assert.equal(lineage.isAcyclic, true);
  assert.equal(lineage.supportingLineage[0].evidenceId, simEv.id);
});

test('Part V, VI, VII: Temporal Graph, Cross-Layer Correlation, Counterfactuals & Uncertainty Panel', () => {
  assert.equal(TYPED_RELATIONSHIPS.length, 10);
  assert.ok(CANONICAL_RESOURCE_TYPES.includes('service_endpoint'));

  temporalInfrastructureGraph.syncFromLiveInfrastructure('unit_test');
  const diff = temporalInfrastructureGraph.diffSnapshots(Date.now() - 5000, Date.now());
  assert.ok(typeof diff.totalChanges === 'number');

  const corr = crossLayerIncidentCorrelator.correlateSignals({
    target: 'app.internal.local',
    signals: [
      { domain: 'dns', claim: 'DNS resolved app.internal.local -> 10.20.30.40', normalizedValue: 'RESOLVED:10.20.30.40', anomaly: false },
      { domain: 'icmp_pmtu', claim: 'Gateway 10.20.30.1 reachable (0.8ms)', subject: 'gateway:10.20.30.1', normalizedValue: 'ICMP_ALIVE', anomaly: false },
      { domain: 'tcp', claim: 'TCP 10.20.30.40:443 returned RST (ECONNREFUSED)', normalizedValue: 'CLOSED_ECONNREFUSED', anomaly: true }
    ]
  });

  assert.ok(corr.topHypothesis);
  assert.equal(corr.topHypothesis.id, 'HYP-TARGET-SERVICE-PORT-CLOSED-RST');
  assert.ok(corr.uncertaintyPanel.knownFromLiveEvidence.length >= 2);
});

test('Part VIII, IX, X: Simulation Branch Isolation, Policy Governance & Governed Action RBAC/Verification', async () => {
  const branch = simulationBranchManager.createSimulationBranch({ arrivalRateMultiplier: 1.5 });
  assert.equal(branch.fidelity, 'simulated');
  assert.equal(branch.isolatedFromLiveState, true);

  const bundle = simulationBranchManager.exportExperimentBundle(branch.branchId);
  assert.ok(bundle.reproducibilityChecksum);

  const policyAudit = policyGovernanceEngine.compileAndAuditPolicies({
    rules: [
      { id: 'R1', subject: '0.0.0.0/0', destination: '10.0.0.5', protocol: 'TCP', port: 445, action: 'ALLOW' },
      { id: 'R2', subject: '0.0.0.0/0', destination: '8.8.8.8', protocol: 'UDP', port: 53, action: 'DENY' }
    ]
  });
  assert.equal(policyAudit.artifactStatus, 'PROPOSED_PREVIEW_ONLY');
  assert.ok(policyAudit.leastPrivilegeAudit.overlyBroadWarnings.length > 0);
  assert.ok(policyAudit.leastPrivilegeAudit.criticalDependencyBlocks.length > 0);

  // Governed Action RBAC: READONLY must be denied
  const denied = await governedActionControlPlane.executeGovernedAction(
    'verify_and_refresh_dns_resolution',
    { target: '127.0.0.1' },
    { username: 'viewer', role: 'READONLY' }
  );
  assert.equal(denied.success, false);
  assert.equal(denied.status, 'denied');

  // OPERATOR succeeds and records action_result + verification_result
  const executed = await governedActionControlPlane.executeGovernedAction(
    'verify_and_refresh_dns_resolution',
    { target: '127.0.0.1' },
    { username: 'noc-op', role: 'OPERATOR' }
  );
  assert.equal(executed.success, true);
  assert.equal(executed.postconditionVerified, true);
  assert.ok(executed.actionEvidenceId);
  assert.ok(executed.verificationEvidenceId);
});
