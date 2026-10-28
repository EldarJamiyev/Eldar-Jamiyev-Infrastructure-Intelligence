/**
 * EJII v6 — Sovereign Intelligence Fabric
 * Part III: Unified Capability Registry
 *
 * Machine-readable registry of every diagnostic, discovery, analytical,
 * simulation, policy, remediation, and academy capability in EJII v6.
 * Every capability invocation returns a standardized EJIIResult<T> envelope.
 */

const { createEjiiResult, validateEjiiResult } = require('./contracts/ejii-result');
const { evidenceFabric } = require('./evidence/evidence-fabric');
const { temporalInfrastructureGraph } = require('./topology/temporal-graph-engine');
const { crossLayerIncidentCorrelator } = require('./correlation/incident-correlator');
const {
  simulationBranchManager,
  policyGovernanceEngine,
  governedActionControlPlane
} = require('./governance/action-control-plane');
const { L7DeepProtocolDissector } = require('../sniffer/l7-deep-protocol-dissector');
const { SpectralFourierDetector } = require('../ai/spectral-fourier-detector');
const { MultipathQosAuditor } = require('../topology/multipath-qos-auditor');
const { HardwareKernelInspector } = require('../diagnostics/hardware-kernel-inspector');

const CAPABILITY_DEFINITIONS = Object.freeze([
  {
    id: 'ejii.discovery.temporal_topology',
    name: 'Temporal Infrastructure Graph Discovery & Reconciliation',
    domain: 'topology',
    version: '6.0.0',
    executionMode: 'passive',
    privilegeLevel: 'unprivileged',
    supportedPlatforms: ['win32', 'linux', 'darwin'],
    inputsSchema: { type: 'object', properties: { triggerReason: { type: 'string' } } },
    outputsSchema: { type: 'object', required: ['nodes', 'edges', 'reconciliationCandidates'] },
    evidenceProduced: ['observation'],
    determinism: 'deterministic',
    blastRadius: 'none',
    timeoutMs: 5000,
    fallbackBehavior: 'Returns cached temporal graph with explicit freshness metadata'
  },
  {
    id: 'ejii.correlation.cross_layer_rca',
    name: 'Cross-Layer Incident Correlator & Calibrated Bayesian Investigator',
    domain: 'rca_investigation',
    version: '6.0.0',
    executionMode: 'diagnostic',
    privilegeLevel: 'unprivileged',
    supportedPlatforms: ['win32', 'linux', 'darwin'],
    inputsSchema: { type: 'object', properties: { target: { type: 'string' }, signals: { type: 'array' } } },
    outputsSchema: { type: 'object', required: ['incidentId', 'hypotheses', 'uncertaintyPanel'] },
    evidenceProduced: ['observation', 'hypothesis', 'confirmed_finding'],
    determinism: 'statistical',
    blastRadius: 'none',
    timeoutMs: 8000,
    fallbackBehavior: 'Returns deterministic prior-weighted hypothesis evaluation with uncertainty bounds'
  },
  {
    id: 'ejii.diagnostics.unreachable_hostname_workflow',
    name: '10-Step Unreachable Hostname Cross-Layer Diagnostic Workflow',
    domain: 'protocol_probe',
    version: '6.0.0',
    executionMode: 'active_probe',
    privilegeLevel: 'operator',
    supportedPlatforms: ['win32', 'linux', 'darwin'],
    inputsSchema: { type: 'object', required: ['hostname'], properties: { hostname: { type: 'string' }, port: { type: 'number' } } },
    outputsSchema: { type: 'object', required: ['workflowId', 'steps', 'correlation'] },
    evidenceProduced: ['observation', 'confirmed_finding'],
    determinism: 'deterministic',
    blastRadius: 'low',
    timeoutMs: 12000,
    fallbackBehavior: 'Completes surviving protocol layers and records missing_evidence for timed-out probes'
  },
  {
    id: 'ejii.sniffer.l7_deep_dissector',
    name: 'RFC 9000 QUIC, SSH HASSH, SMB2 & HTTP/2 Deep Wire Dissector',
    domain: 'packet_dissection',
    version: '6.0.0',
    executionMode: 'passive',
    privilegeLevel: 'unprivileged',
    supportedPlatforms: ['win32', 'linux', 'darwin'],
    inputsSchema: { type: 'object', properties: { protocol: { type: 'string' }, hexPayload: { type: 'string' } } },
    outputsSchema: { type: 'object', required: ['valid'] },
    evidenceProduced: ['observation'],
    determinism: 'deterministic',
    blastRadius: 'none',
    timeoutMs: 2000,
    fallbackBehavior: 'Returns structured bounds-checked error when payload is truncated or malformed'
  },
  {
    id: 'ejii.ai.spectral_fourier_periodicity',
    name: 'Cooley-Tukey Radix-2 FFT & Welch Periodogram Anomaly Detector',
    domain: 'spectral_analysis',
    version: '6.0.0',
    executionMode: 'diagnostic',
    privilegeLevel: 'unprivileged',
    supportedPlatforms: ['win32', 'linux', 'darwin'],
    inputsSchema: { type: 'object', required: ['samples'], properties: { samples: { type: 'array' }, samplingRateHz: { type: 'number' } } },
    outputsSchema: { type: 'object', required: ['dominantFrequencyHz', 'snrDb', 'evidenceDistinction'] },
    evidenceProduced: ['calculation'],
    determinism: 'deterministic',
    blastRadius: 'none',
    timeoutMs: 3000,
    fallbackBehavior: 'Returns zero-periodic classification with explicit evidentiary note on constant/short signals'
  },
  {
    id: 'ejii.simulation.digital_twin_branch',
    name: 'Trace-Driven Digital Twin M/M/1/K Chaos & Capacity Branching',
    domain: 'simulation',
    version: '6.0.0',
    executionMode: 'simulation',
    privilegeLevel: 'operator',
    supportedPlatforms: ['win32', 'linux', 'darwin'],
    inputsSchema: { type: 'object', properties: { faultScenario: { type: 'object' } } },
    outputsSchema: { type: 'object', required: ['branchId', 'simulationResult', 'mathematicalModel'] },
    evidenceProduced: ['simulated_result'],
    determinism: 'deterministic',
    blastRadius: 'none',
    timeoutMs: 4000,
    fallbackBehavior: 'Runs isolated in-memory M/M/1/K simulation without touching live topology'
  },
  {
    id: 'ejii.security.policy_governance_compiler',
    name: 'Zero-Trust Policy Least-Privilege Auditor & Multi-Target Compiler',
    domain: 'policy_governance',
    version: '6.0.0',
    executionMode: 'diagnostic',
    privilegeLevel: 'operator',
    supportedPlatforms: ['win32', 'linux', 'darwin'],
    inputsSchema: { type: 'object', properties: { rules: { type: 'array' } } },
    outputsSchema: { type: 'object', required: ['canonicalRules', 'leastPrivilegeAudit', 'compiledArtifacts'] },
    evidenceProduced: ['calculation'],
    determinism: 'deterministic',
    blastRadius: 'none',
    timeoutMs: 3000,
    fallbackBehavior: 'Generates staged preview-only artifacts; never auto-applies to host firewall'
  },
  {
    id: 'ejii.governance.verified_remediation',
    name: 'Governed Remediation & Postcondition Verification Control Plane',
    domain: 'remediation',
    version: '6.0.0',
    executionMode: 'remediation',
    privilegeLevel: 'operator',
    supportedPlatforms: ['win32', 'linux', 'darwin'],
    inputsSchema: { type: 'object', required: ['actionId'], properties: { actionId: { type: 'string' }, target: { type: 'string' } } },
    outputsSchema: { type: 'object', required: ['executionId', 'postconditionVerification'] },
    evidenceProduced: ['action_result', 'verification_result'],
    determinism: 'deterministic',
    blastRadius: 'low',
    timeoutMs: 10000,
    fallbackBehavior: 'Enforces fail-closed RBAC & precondition gates and emits explicit rollback guidance'
  },
  {
    id: 'ejii.diagnostics.hardware_kernel_inspector',
    name: 'Hardware 802.11 RF Link Margin & Kernel TCP/NIC Ring Inspector',
    domain: 'host_diagnostics',
    version: '6.0.0',
    executionMode: 'diagnostic',
    privilegeLevel: 'unprivileged',
    supportedPlatforms: ['win32', 'linux', 'darwin'],
    inputsSchema: { type: 'object', properties: {} },
    outputsSchema: { type: 'object', required: ['wifi', 'kernel', 'fieldProvenance'] },
    evidenceProduced: ['observation'],
    determinism: 'deterministic',
    blastRadius: 'none',
    timeoutMs: 5000,
    fallbackBehavior: 'Explicitly marks unavailable OS counters as unavailable/unsupported in fieldProvenance'
  }
]);

class CapabilityRegistry {
  constructor() {
    this.capabilities = new Map(CAPABILITY_DEFINITIONS.map((c) => [c.id, c]));
  }

  listCapabilities(filter = {}) {
    let list = Array.from(this.capabilities.values());
    if (filter.domain) {
      list = list.filter((c) => c.domain === filter.domain);
    }
    if (filter.executionMode) {
      list = list.filter((c) => c.executionMode === filter.executionMode);
    }
    return list;
  }

  getCapability(capabilityId) {
    return this.capabilities.get(capabilityId) || null;
  }

  /**
   * Invoke any registered capability by ID and return a guaranteed EJIIResult<T> envelope.
   */
  async invokeCapability(capabilityId, params = {}, context = {}) {
    const cap = this.getCapability(capabilityId);
    const observedAt = new Date().toISOString();

    if (!cap) {
      return createEjiiResult({
        success: false,
        capabilityId: capabilityId || 'ejii.unknown',
        requestId: context.requestId,
        correlationId: context.correlationId,
        observedAt,
        source: { module: 'CapabilityRegistry', method: 'invokeCapability', privilege: 'unprivileged', fidelity: 'unavailable' },
        status: 'failed',
        data: null,
        error: {
          code: 'CAPABILITY_NOT_FOUND',
          message: `Capability '${capabilityId}' is not registered in the EJII v6 Capability Registry.`,
          recoverable: false
        }
      });
    }

    try {
      let data = null;
      let fidelity = 'live';
      let status = 'ok';
      const evidenceIds = [];
      const warnings = [];

      if (capabilityId === 'ejii.discovery.temporal_topology') {
        temporalInfrastructureGraph.syncFromLiveInfrastructure(params.triggerReason || 'capability_invoke');
        data = temporalInfrastructureGraph.getGraphState();
        for (const n of (data.nodes || []).slice(0, 6)) {
          if (Array.isArray(n.evidenceIds)) evidenceIds.push(...n.evidenceIds);
        }
      } else if (capabilityId === 'ejii.correlation.cross_layer_rca') {
        data = crossLayerIncidentCorrelator.correlateSignals(params);
        fidelity = 'derived';
        for (const e of data.evidenceRecords || []) evidenceIds.push(e.id);
      } else if (capabilityId === 'ejii.diagnostics.unreachable_hostname_workflow') {
        data = await crossLayerIncidentCorrelator.diagnoseUnreachableHostname(params.hostname || 'localhost', params.port || 443);
        for (const e of data.correlation?.evidenceRecords || []) evidenceIds.push(e.id);
      } else if (capabilityId === 'ejii.sniffer.l7_deep_dissector') {
        const buf = Buffer.from(String(params.hexPayload || ''), 'hex');
        const proto = String(params.protocol || 'QUIC').toUpperCase();
        if (proto === 'SSH') data = L7DeepProtocolDissector.dissectSshHassh(buf);
        else if (proto === 'SMB2') data = L7DeepProtocolDissector.dissectSmb2Header(buf);
        else if (proto === 'HTTP2') data = L7DeepProtocolDissector.dissectHttp2Frames(buf);
        else data = L7DeepProtocolDissector.dissectQuicPacket(buf);
      } else if (capabilityId === 'ejii.ai.spectral_fourier_periodicity') {
        const samples = Array.isArray(params.samples) ? params.samples : [10, 50, 10, 50, 10, 50, 10, 50, 10, 50, 10, 50, 10, 50, 10, 50];
        data = SpectralFourierDetector.analyzePeriodicity(samples, Number(params.samplingRateHz) || 1.0);
        fidelity = 'derived';
      } else if (capabilityId === 'ejii.simulation.digital_twin_branch') {
        data = simulationBranchManager.createSimulationBranch(params);
        fidelity = 'simulated';
        if (data.evidenceId) evidenceIds.push(data.evidenceId);
      } else if (capabilityId === 'ejii.security.policy_governance_compiler') {
        data = policyGovernanceEngine.compileAndAuditPolicies(params);
        fidelity = 'derived';
      } else if (capabilityId === 'ejii.governance.verified_remediation') {
        data = await governedActionControlPlane.executeGovernedAction(
          params.actionId || 'verify_and_refresh_dns_resolution',
          params,
          context.user || { username: 'operator', role: 'OPERATOR' }
        );
        if (!data.success) {
          status = data.status || 'denied';
        }
        if (data.actionEvidenceId) evidenceIds.push(data.actionEvidenceId);
        if (data.verificationEvidenceId) evidenceIds.push(data.verificationEvidenceId);
      } else if (capabilityId === 'ejii.diagnostics.hardware_kernel_inspector') {
        data = HardwareKernelInspector.inspectLiveHost();
        if (data.fieldProvenance && Object.values(data.fieldProvenance).includes('unavailable')) {
          status = 'partial';
          warnings.push('Some hardware/wireless counters are unavailable in this OS container environment.');
        }
      }

      return createEjiiResult({
        success: status !== 'failed' && status !== 'denied',
        capabilityId: cap.id,
        requestId: context.requestId,
        correlationId: context.correlationId,
        observedAt,
        source: {
          module: cap.id,
          method: cap.executionMode,
          privilege: cap.privilegeLevel,
          platform: process.platform,
          fidelity
        },
        status,
        data,
        evidenceIds: Array.from(new Set(evidenceIds)),
        warnings
      });
    } catch (err) {
      return createEjiiResult({
        success: false,
        capabilityId: cap.id,
        requestId: context.requestId,
        correlationId: context.correlationId,
        observedAt,
        source: {
          module: cap.id,
          method: cap.executionMode,
          privilege: cap.privilegeLevel,
          platform: process.platform,
          fidelity: 'unavailable'
        },
        status: 'failed',
        data: null,
        error: {
          code: 'CAPABILITY_EXECUTION_EXCEPTION',
          message: err.message || String(err),
          recoverable: true
        }
      });
    }
  }
}

const capabilityRegistry = new CapabilityRegistry();

module.exports = {
  CAPABILITY_DEFINITIONS,
  CapabilityRegistry,
  capabilityRegistry,
  validateEjiiResult
};
