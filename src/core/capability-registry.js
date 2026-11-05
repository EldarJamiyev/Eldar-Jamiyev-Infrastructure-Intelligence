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
  },
  {
    id: 'ejii.dns.lookup',
    name: 'Real DNS Record Resolution & Error Classification',
    domain: 'protocol_probe',
    version: '6.0.0',
    executionMode: 'active_probe',
    privilegeLevel: 'unprivileged',
    supportedPlatforms: ['win32', 'linux', 'darwin'],
    cancellable: true,
    safetyConstraints: ['SSRF_GUARD', 'NO_FABRICATED_IP'],
    inputsSchema: { type: 'object', required: ['domain'], properties: { domain: { type: 'string' }, recordType: { type: 'string' }, nameserver: { type: 'string' } } },
    outputsSchema: { type: 'object', required: ['success', 'domain', 'recordType', 'records', 'resolutionMethod'] },
    evidenceProduced: ['observation'],
    determinism: 'deterministic',
    blastRadius: 'none',
    timeoutMs: 1500,
    fallbackBehavior: 'Falls back to OS getaddrinfo with explicit resolutionMethod label; never invents IP addresses'
  },
  {
    id: 'ejii.dns.connectivity_health',
    name: 'System DNS Configuration & Connectivity Health Check',
    domain: 'protocol_probe',
    version: '6.0.0',
    executionMode: 'active_probe',
    privilegeLevel: 'unprivileged',
    supportedPlatforms: ['win32', 'linux', 'darwin'],
    cancellable: true,
    safetyConstraints: ['READ_ONLY_RESOLVER_INSPECTION'],
    inputsSchema: { type: 'object', properties: { probeDomain: { type: 'string' } } },
    outputsSchema: { type: 'object', required: ['configuredServers', 'primaryResolver', 'healthy'] },
    evidenceProduced: ['observation'],
    determinism: 'deterministic',
    blastRadius: 'none',
    timeoutMs: 2500,
    fallbackBehavior: 'Distinguishes local hosts resolution from recursive external DNS failures'
  },
  {
    id: 'ejii.icmp.ping',
    name: 'ICMP Echo Reachability Probe with Explicit Sandbox Restriction Detection',
    domain: 'protocol_probe',
    version: '6.0.0',
    executionMode: 'active_probe',
    privilegeLevel: 'unprivileged',
    supportedPlatforms: ['win32', 'linux', 'darwin'],
    cancellable: true,
    safetyConstraints: ['SSRF_GUARD', 'DISTINCT_ICMP_VS_TCP'],
    inputsSchema: { type: 'object', required: ['host'], properties: { host: { type: 'string' }, count: { type: 'number' }, timeoutMs: { type: 'number' } } },
    outputsSchema: { type: 'object', required: ['success', 'host', 'packetsSent', 'packetsReceived', 'packetLossPct'] },
    evidenceProduced: ['observation'],
    determinism: 'deterministic',
    blastRadius: 'none',
    timeoutMs: 3000,
    fallbackBehavior: 'Reports ICMP restriction or timeout honestly; never fabricates ICMP replies from TCP handshakes'
  },
  {
    id: 'ejii.tcp.port_check',
    name: 'TCP 3-Way Handshake & Listener State Verifier',
    domain: 'protocol_probe',
    version: '6.0.0',
    executionMode: 'active_probe',
    privilegeLevel: 'unprivileged',
    supportedPlatforms: ['win32', 'linux', 'darwin'],
    cancellable: true,
    safetyConstraints: ['SSRF_GUARD', 'PINNED_IP'],
    inputsSchema: { type: 'object', required: ['host', 'port'], properties: { host: { type: 'string' }, port: { type: 'number' }, timeoutMs: { type: 'number' } } },
    outputsSchema: { type: 'object', required: ['status', 'host', 'port', 'connectLatencyMs'] },
    evidenceProduced: ['observation'],
    determinism: 'deterministic',
    blastRadius: 'none',
    timeoutMs: 2500,
    fallbackBehavior: 'Distinguishes OPEN, CLOSED (ECONNREFUSED), and FILTERED (ETIMEDOUT)'
  },
  {
    id: 'ejii.web.https_diagnose',
    name: 'Layered Website & HTTPS Diagnostic (DNS -> TCP -> TLS -> HTTP)',
    domain: 'protocol_probe',
    version: '6.0.0',
    executionMode: 'active_probe',
    privilegeLevel: 'unprivileged',
    supportedPlatforms: ['win32', 'linux', 'darwin'],
    cancellable: true,
    safetyConstraints: ['SSRF_GUARD', 'REDIRECT_HOP_SSRF_DEFENSE'],
    inputsSchema: { type: 'object', required: ['url'], properties: { url: { type: 'string' }, timeoutMs: { type: 'number' } } },
    outputsSchema: { type: 'object', required: ['success', 'url', 'statusCode', 'waterfall'] },
    evidenceProduced: ['observation'],
    determinism: 'deterministic',
    blastRadius: 'none',
    timeoutMs: 5000,
    fallbackBehavior: 'Reports exact failing layer (DNS, TCP, TLS, or HTTP status code)'
  },
  {
    id: 'ejii.host.local_ip_config',
    name: 'Local OS Network Interface, DNS & Verified Gateway Inspector',
    domain: 'host_diagnostics',
    version: '6.0.0',
    executionMode: 'passive',
    privilegeLevel: 'unprivileged',
    supportedPlatforms: ['win32', 'linux', 'darwin'],
    cancellable: false,
    safetyConstraints: ['NO_GUESSED_GATEWAY', 'EXPLICIT_CONTAINER_SCOPE'],
    inputsSchema: { type: 'object', properties: {} },
    outputsSchema: { type: 'object', required: ['hostname', 'interfaces', 'dnsServers', 'defaultGateway', 'executionScope'] },
    evidenceProduced: ['observation'],
    determinism: 'deterministic',
    blastRadius: 'none',
    timeoutMs: 2500,
    fallbackBehavior: 'Reports unverified gateway honestly without guessing .1'
  },
  {
    id: 'ejii.host.gateway_ping',
    name: 'Verified OS Default Gateway Reachability Probe',
    domain: 'host_diagnostics',
    version: '6.0.0',
    executionMode: 'active_probe',
    privilegeLevel: 'unprivileged',
    supportedPlatforms: ['win32', 'linux', 'darwin'],
    cancellable: true,
    safetyConstraints: ['VERIFIED_ROUTING_TABLE_ONLY', 'NO_GUESSED_GATEWAY'],
    inputsSchema: { type: 'object', properties: {} },
    outputsSchema: { type: 'object', required: ['gatewayVerified', 'gatewayIp'] },
    evidenceProduced: ['observation'],
    determinism: 'deterministic',
    blastRadius: 'none',
    timeoutMs: 3000,
    fallbackBehavior: 'Refuses to ping a guessed address if the OS routing table does not expose a verified default gateway'
  },
  {
    id: 'ejii.host.active_connections',
    name: 'Active Socket, Process & Remote Destination Endpoint Inventory',
    domain: 'host_diagnostics',
    version: '6.0.0',
    executionMode: 'passive',
    privilegeLevel: 'unprivileged',
    supportedPlatforms: ['win32', 'linux', 'darwin'],
    cancellable: true,
    safetyConstraints: ['ZERO_FABRICATED_SOCKETS', 'EXPLICIT_PERMISSION_AND_NAMESPACE_SCOPE'],
    inputsSchema: { type: 'object', properties: { process: { type: 'string' }, port: { type: 'number' }, state: { type: 'string' }, externalOnly: { type: 'boolean' } } },
    outputsSchema: { type: 'object', required: ['connections', 'collectionMethod', 'collectionScope', 'processAttributionAvailable'] },
    evidenceProduced: ['observation'],
    determinism: 'deterministic',
    blastRadius: 'none',
    timeoutMs: 4000,
    fallbackBehavior: 'Returns explicit collectorError if OS socket enumeration fails; never returns fake fallback rows'
  },
  {
    id: 'ejii.host.dhcp_status',
    name: 'Local OS DHCP Lease & Addressing Mode Inspector',
    domain: 'host_diagnostics',
    version: '6.0.0',
    executionMode: 'passive',
    privilegeLevel: 'unprivileged',
    supportedPlatforms: ['win32', 'linux', 'darwin'],
    cancellable: false,
    safetyConstraints: ['READ_ONLY_DHCP_INSPECTION'],
    inputsSchema: { type: 'object', properties: {} },
    outputsSchema: { type: 'object', required: ['status', 'observed', 'addressingMode'] },
    evidenceProduced: ['observation'],
    determinism: 'deterministic',
    blastRadius: 'none',
    timeoutMs: 2500,
    fallbackBehavior: 'Reports container-managed or static addressing honestly without fabricating a fake DHCP lease'
  },
  {
    id: 'ejii.icmp.traceroute',
    name: 'Layer 3 Hop-by-Hop Traceroute Probe',
    domain: 'protocol_probe',
    version: '6.0.0',
    executionMode: 'active_probe',
    privilegeLevel: 'unprivileged',
    supportedPlatforms: ['win32', 'linux', 'darwin'],
    cancellable: true,
    safetyConstraints: ['SSRF_GUARD'],
    inputsSchema: { type: 'object', required: ['target'], properties: { target: { type: 'string' }, maxHops: { type: 'number' } } },
    outputsSchema: { type: 'object', required: ['success', 'host', 'hopCount', 'hops'] },
    evidenceProduced: ['observation'],
    determinism: 'deterministic',
    blastRadius: 'none',
    timeoutMs: 35000,
    fallbackBehavior: 'Captures hop progression and reports unreached intermediate hops honestly'
  },
  {
    id: 'ejii.host.health_metrics',
    name: 'Live Host CPU, Load Average, Memory & Disk Telemetry',
    domain: 'host_diagnostics',
    version: '6.0.0',
    executionMode: 'passive',
    privilegeLevel: 'unprivileged',
    supportedPlatforms: ['win32', 'linux', 'darwin'],
    cancellable: false,
    safetyConstraints: ['NO_FABRICATED_COUNTERS'],
    inputsSchema: { type: 'object', properties: {} },
    outputsSchema: { type: 'object', required: ['hostname', 'cpu', 'memory', 'disks'] },
    evidenceProduced: ['observation'],
    determinism: 'deterministic',
    blastRadius: 'none',
    timeoutMs: 3000,
    fallbackBehavior: 'Returns truthful POSIX CPU tick deltas and uninvented disk status'
  },
  {
    id: 'ejii.path.5_layer_diagnostic',
    name: '5-Layer Local-to-ISP Path Diagnostic Workflow',
    domain: 'protocol_probe',
    version: '6.0.0',
    executionMode: 'active_probe',
    privilegeLevel: 'unprivileged',
    supportedPlatforms: ['win32', 'linux', 'darwin'],
    cancellable: true,
    safetyConstraints: ['SSRF_GUARD'],
    inputsSchema: { type: 'object', properties: {} },
    outputsSchema: { type: 'object', required: ['layers', 'verdict', 'healthy'] },
    evidenceProduced: ['observation'],
    determinism: 'deterministic',
    blastRadius: 'low',
    timeoutMs: 12000,
    fallbackBehavior: 'Identifies the lowest failing OSI layer (L1 NIC -> L2 ARP -> L3 Gateway -> L4 Anycast -> L7 HTTPS)'
  },
  {
    id: 'ejii.ai.closed_loop_hypothesis_arbiter',
    name: 'Autonomous Closed-Loop 6-Domain Hypothesis Arbiter & Information-Gain Investigator',
    domain: 'rca_investigation',
    version: '6.0.0',
    executionMode: 'active_probe',
    privilegeLevel: 'unprivileged',
    supportedPlatforms: ['win32', 'linux', 'darwin'],
    cancellable: true,
    safetyConstraints: ['SSRF_GUARD', 'READ_ONLY_PROBES'],
    inputsSchema: { type: 'object', properties: { target: { type: 'string' }, port: { type: 'number' }, executeClosedLoop: { type: 'boolean' } } },
    outputsSchema: { type: 'object', required: ['arbitrationId', 'hypotheses', 'winningHypothesis', 'closedLoopExecutionTrace'] },
    evidenceProduced: ['observation', 'hypothesis', 'confirmed_finding'],
    determinism: 'statistical',
    blastRadius: 'none',
    timeoutMs: 10000,
    fallbackBehavior: 'Returns Operational Memory-conditioned Bayesian posteriors across all 6 domains if active probe times out'
  },
  {
    id: 'ejii.ai.nonlinear_predictive_horizon',
    name: 'Non-Linear M/M/1 Queueing Cliff & Cut-Vertex Predictive Horizon Engine',
    domain: 'predictive_analytics',
    version: '6.0.0',
    executionMode: 'diagnostic',
    privilegeLevel: 'unprivileged',
    supportedPlatforms: ['win32', 'linux', 'darwin'],
    cancellable: false,
    safetyConstraints: ['READ_ONLY_TELEMETRY'],
    inputsSchema: { type: 'object', properties: { target: { type: 'string' }, slaLatencyThresholdMs: { type: 'number' } } },
    outputsSchema: { type: 'object', required: ['horizonId', 'predictions', 'cutVertices', 'overallRiskScore'] },
    evidenceProduced: ['calculation', 'observation'],
    determinism: 'deterministic',
    blastRadius: 'none',
    timeoutMs: 4000,
    fallbackBehavior: 'Evaluates all tracked endpoints with Holt-Winters & M/M/1 saturation modeling without array truncation'
  },
  {
    id: 'ejii.observability.patient_zero_timeline',
    name: 'MAD & CUSUM Pre-Incident Chronological Timeline & Patient Zero Reconstructor',
    domain: 'observability',
    version: '6.0.0',
    executionMode: 'diagnostic',
    privilegeLevel: 'unprivileged',
    supportedPlatforms: ['win32', 'linux', 'darwin'],
    cancellable: false,
    safetyConstraints: ['READ_ONLY_TELEMETRY'],
    inputsSchema: { type: 'object', properties: { target: { type: 'string' }, windowMinutes: { type: 'number' } } },
    outputsSchema: { type: 'object', required: ['reconstructionId', 'patientZero', 'timelineEvents', 'changepointAnalysis'] },
    evidenceProduced: ['observation', 'calculation'],
    determinism: 'deterministic',
    blastRadius: 'none',
    timeoutMs: 4000,
    fallbackBehavior: 'Reconstructs full un-truncated chronological event stream and honest evidence gap disclosures'
  },
  {
    id: 'ejii.superpowers.unified_synthesis',
    name: 'Composable Superpowers 4-Phase Systematic Debugging & Multi-Engine Unified Synthesis',
    domain: 'rca_investigation',
    version: '6.0.0',
    executionMode: 'active_probe',
    privilegeLevel: 'unprivileged',
    supportedPlatforms: ['win32', 'linux', 'darwin'],
    cancellable: true,
    safetyConstraints: ['SSRF_GUARD', 'VERIFICATION_BEFORE_COMPLETION'],
    inputsSchema: { type: 'object', properties: { objective: { type: 'string' }, target: { type: 'string' }, port: { type: 'number' } } },
    outputsSchema: { type: 'object', required: ['synthesisId', 'systematicDebugging4Phases', 'timelineReconstruction', 'hypothesisArbitration', 'predictiveHorizon'] },
    evidenceProduced: ['observation', 'hypothesis', 'confirmed_finding', 'verification_result'],
    determinism: 'deterministic',
    blastRadius: 'none',
    timeoutMs: 12000,
    fallbackBehavior: 'Composes Timeline, 6-Domain Arbiter, Predictive Horizon, and L7 verification in parallel'
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
      } else if (capabilityId === 'ejii.dns.lookup') {
        const { resolveRecord } = require('../protocols/dns-diag');
        data = await resolveRecord(params.domain || 'localhost', params.recordType || 'A', params.nameserver || null);
        if (!data.success) status = 'failed';
      } else if (capabilityId === 'ejii.dns.connectivity_health') {
        const { checkDnsConnectivityHealth } = require('../protocols/dns-diag');
        data = await checkDnsConnectivityHealth(params.probeDomain || 'example.com');
        if (!data.healthy) status = data.localOnlyHealthy ? 'partial' : 'failed';
      } else if (capabilityId === 'ejii.icmp.ping') {
        const { realPing } = require('../protocols/icmp-ping');
        data = await realPing(params.host || '127.0.0.1', Number(params.count) || 2, Number(params.timeoutMs) || 1000);
        if (!data.success) status = 'failed';
      } else if (capabilityId === 'ejii.tcp.port_check') {
        const { checkPort } = require('../protocols/tcp-port');
        data = await checkPort(params.host || '127.0.0.1', Number(params.port) || 443, Number(params.timeoutMs) || 1800);
        if (data.status !== 'OPEN') status = 'failed';
      } else if (capabilityId === 'ejii.web.https_diagnose') {
        const { probeHttp } = require('../protocols/http-probe');
        data = await probeHttp(params.url || 'http://localhost:3000', 'GET', Number(params.timeoutMs) || 3000);
        if (!data.success) status = 'failed';
      } else if (capabilityId === 'ejii.host.local_ip_config') {
        const { inspectLocalNetworkConfiguration } = require('../protocols/host-metrics');
        data = inspectLocalNetworkConfiguration();
      } else if (capabilityId === 'ejii.host.gateway_ping') {
        const { getVerifiedDefaultGateway } = require('../protocols/host-metrics');
        const { realPing } = require('../protocols/icmp-ping');
        const gw = getVerifiedDefaultGateway();
        if (!gw.verified || !gw.gatewayIp) {
          status = 'partial';
          data = { gatewayVerified: false, gatewayIp: null, gatewayInfo: gw, pingResult: null };
        } else {
          const pingResult = await realPing(gw.gatewayIp, 2, 1000);
          data = { gatewayVerified: true, gatewayIp: gw.gatewayIp, gatewayInfo: gw, pingResult };
          if (!pingResult.success) status = 'partial';
        }
      } else if (capabilityId === 'ejii.host.active_connections') {
        const { processSocketCorrelator } = require('../network/process-socket-correlator');
        data = await processSocketCorrelator.collectActiveConnectionsInventory(params || {});
        if (!data.success) status = 'failed';
      } else if (capabilityId === 'ejii.host.dhcp_status') {
        const { discoverLocalDhcpServer } = require('../protocols/host-metrics');
        data = discoverLocalDhcpServer();
        if (data.status === 'UNAVAILABLE' || data.status === 'ERROR') status = 'partial';
      } else if (capabilityId === 'ejii.icmp.traceroute') {
        const { realTraceroute } = require('../protocols/icmp-ping');
        data = await realTraceroute(params.target || params.host || '127.0.0.1', Number(params.maxHops) || 15);
        if (!data.success) status = 'partial';
      } else if (capabilityId === 'ejii.host.health_metrics') {
        const { getHostMetrics, createBaselineHostMetrics } = require('../protocols/host-metrics');
        try {
          const forceRefresh = Boolean(params && (params.forceRefresh || params.live));
          data = await getHostMetrics(forceRefresh);

          // Evaluate live telemetry completeness and platform observability
          const hasCpuUsage = data.cpu && data.cpu.usagePercentage !== null && !isNaN(data.cpu.usagePercentage);
          const hasDisks = Array.isArray(data.disks) && data.disks.length > 0;
          const diskStatus = data.diskCollectionStatus?.status;

          if (diskStatus === 'COLLECTION_FAILED' || !hasDisks) {
            status = 'partial';
            fidelity = 'partial_live_collection';
            warnings.push(data.diskCollectionStatus?.error || 'Disk counters unobserved in current runtime environment.');
          } else if (!hasCpuUsage) {
            status = 'partial';
            fidelity = 'partial_live_collection';
            warnings.push('CPU tick delta sampling unavailable; CPU usage percentage is pending or null.');
          } else if (data._isCached) {
            status = 'ok';
            fidelity = 'cached_telemetry';
          } else {
            status = 'ok';
            fidelity = 'live_observed';
          }

          data.telemetryMetadata = {
            collectionMode: fidelity,
            hardwareObserved: hasCpuUsage && hasDisks,
            diskStatus: diskStatus || (hasDisks ? 'OBSERVED' : 'UNAVAILABLE'),
            cpuMeasurementMethod: data.cpu?.measurementMethod || 'os_standard'
          };
        } catch (collectorErr) {
          data = createBaselineHostMetrics();
          status = 'partial';
          fidelity = 'baseline_snapshot';
          warnings.push(`Live hardware collector error (${collectorErr.message}); degraded to static baseline snapshot.`);
          data.telemetryMetadata = {
            collectionMode: 'baseline_snapshot',
            hardwareObserved: false,
            error: collectorErr.message
          };
        }
      } else if (capabilityId === 'ejii.path.5_layer_diagnostic') {
        const { chatOperatorService } = require('./chat/chat-operator-service');
        const plan = { intent: 'path_diagnostic', mode: 'operational', ports: [] };
        const session = { id: context.sessionId || 'CAP-5LAYER' };
        data = await chatOperatorService._executePathDiagnosticScenario(plan, session, null);
        if (data.structuredAnswer?.status === 'FAIL') status = 'failed';
        else if (data.structuredAnswer?.status === 'WARN') status = 'partial';
      } else if (capabilityId === 'ejii.ai.closed_loop_hypothesis_arbiter') {
        const { hypothesisArbiter } = require('../ai/hypothesis-arbiter');
        data = await hypothesisArbiter.arbitrateAndExecuteClosedLoop({
          target: params.target || '127.0.0.1',
          port: Number(params.port) || 3000,
          symptomDescription: params.symptomDescription || 'Multi-domain closed-loop arbitration',
          executeClosedLoop: params.executeClosedLoop !== false,
          maxClosedLoopSteps: Number(params.maxClosedLoopSteps) || 3
        });
        fidelity = 'live';
      } else if (capabilityId === 'ejii.ai.nonlinear_predictive_horizon') {
        const { predictiveHorizonEngine } = require('../ai/predictive-horizon-engine');
        data = predictiveHorizonEngine.evaluatePredictiveHorizon({
          target: params.target || null,
          slaLatencyThresholdMs: Number(params.slaLatencyThresholdMs) || 150
        });
        fidelity = 'derived';
      } else if (capabilityId === 'ejii.observability.patient_zero_timeline') {
        const { timelineReconstructor } = require('../observability/timeline-reconstructor');
        data = timelineReconstructor.reconstructPreIncidentTimeline({
          target: params.target || '127.0.0.1',
          windowMinutes: Number(params.windowMinutes) || 60
        });
        fidelity = 'derived';
      } else if (capabilityId === 'ejii.superpowers.unified_synthesis') {
        const { superpowersSkillsEngine } = require('./skills/superpowers-skills-engine');
        data = await superpowersSkillsEngine.executeUnifiedSuperpowersSynthesis({
          objective: params.objective || 'Full-stack unified Superpowers synthesis',
          target: params.target || '127.0.0.1',
          port: Number(params.port) || 3000,
          windowMinutes: Number(params.windowMinutes) || 60,
          executeClosedLoop: params.executeClosedLoop !== false
        });
        fidelity = 'live';
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
  getFunctionDeclarations() {
    const { EJII_FUNCTION_DECLARATIONS } = require('./chat/conversational-brain');
    return EJII_FUNCTION_DECLARATIONS;
  }

  getFunctionDeclaration(toolName) {
    const { EJII_FUNCTION_DECLARATIONS } = require('./chat/conversational-brain');
    return EJII_FUNCTION_DECLARATIONS.find((fn) => fn.name === toolName) || null;
  }

  mapFunctionCallToPlan(toolNameOrCall, args = {}, session = null) {
    const { mapFunctionCallToExecutionPlan } = require('./chat/conversational-brain');
    const callObj = (typeof toolNameOrCall === 'object' && toolNameOrCall !== null && toolNameOrCall.name)
      ? toolNameOrCall
      : { name: toolNameOrCall, args };
    const sess = (typeof toolNameOrCall === 'object' && toolNameOrCall !== null && !session && args && (args.lastTarget || args.sessionId))
      ? args
      : session;
    return mapFunctionCallToExecutionPlan(callObj, sess);
  }

  /**
   * COGNITION 3.0 (Phase 4) — Capability Ecosystem Awareness & Complementary Selection
   * Explains what each capability accomplishes, its limitations/blind spots, what inputs it requires,
   * and which capabilities complement one another across network, host/OS, discovery, application,
   * packet analysis, temporal topology, memory, and simulation.
   */
  describeCapabilityEcosystem() {
    const complementaryMap = {
      'ejii.discovery.temporal_topology': {
        accomplishes: 'Discovers live L2/L3/L4 infrastructure nodes, edges, and algebraic connectivity (λ₂).',
        limitations: 'Does not inspect internal OS process CPU/RAM or L7 HTTP payload responses.',
        complementaryCapabilities: ['ejii.correlation.cross_layer_rca', 'ejii.host.active_connections', 'ejii.simulation.digital_twin_branch'],
        parallelizableWith: ['ejii.host.health_metrics', 'ejii.host.local_ip_config']
      },
      'ejii.correlation.cross_layer_rca': {
        accomplishes: 'Correlates cross-layer telemetry into calibrated Bayesian root-cause hypotheses with uncertainty bounds.',
        limitations: 'Requires upstream observations from wire probes or host collectors to narrow posterior entropy.',
        complementaryCapabilities: ['ejii.diagnostics.unreachable_hostname_workflow', 'ejii.discovery.temporal_topology'],
        parallelizableWith: ['ejii.ai.spectral_fourier_periodicity']
      },
      'ejii.diagnostics.unreachable_hostname_workflow': {
        accomplishes: 'Executes a 10-step cross-layer reachability workflow across DNS, ICMP, TCP, TLS, and HTTP.',
        limitations: 'Active wire probe only; does not inspect local OS process bindings or historical config rationale.',
        complementaryCapabilities: ['ejii.host.active_connections', 'ejii.discovery.temporal_topology'],
        parallelizableWith: ['ejii.host.health_metrics']
      },
      'ejii.host.health_metrics': {
        accomplishes: 'Measures live OS CPU load average, memory pressure, and disk capacity.',
        limitations: 'Does not test external network routing or remote service ports.',
        complementaryCapabilities: ['ejii.host.active_connections', 'ejii.diagnostics.hardware_kernel_inspector', 'ejii.tcp.port_check'],
        parallelizableWith: ['ejii.dns.resolve', 'ejii.icmp.ping', 'ejii.discovery.temporal_topology']
      },
      'ejii.host.active_connections': {
        accomplishes: 'Enumerates local kernel TCP/UDP sockets, listening ports, and owning OS processes.',
        limitations: 'Observes local host network namespace only; cannot see remote firewall drops.',
        complementaryCapabilities: ['ejii.tcp.port_check', 'ejii.http.probe', 'ejii.host.health_metrics'],
        parallelizableWith: ['ejii.dns.resolve', 'ejii.discovery.temporal_topology']
      },
      'ejii.dns.resolve': {
        accomplishes: 'Resolves A/AAAA/CNAME/TXT DNS records with resolver latency measurement.',
        limitations: 'Proves naming resolution only; does not verify L3 routing or L4 port openness.',
        complementaryCapabilities: ['ejii.icmp.ping', 'ejii.tcp.port_check', 'ejii.http.probe'],
        parallelizableWith: ['ejii.host.local_ip_config', 'ejii.host.active_connections']
      },
      'ejii.icmp.ping': {
        accomplishes: 'Measures Layer 3 ICMP echo reachability, RTT, and packet loss.',
        limitations: 'Some hosts filter ICMP while still serving TCP, or reply to ICMP while L4 listener is down.',
        complementaryCapabilities: ['ejii.tcp.port_check', 'ejii.icmp.traceroute'],
        parallelizableWith: ['ejii.dns.resolve', 'ejii.host.health_metrics']
      },
      'ejii.tcp.port_check': {
        accomplishes: 'Executes a real 3-way TCP SYN/SYN-ACK handshake to verify L4 listener state.',
        limitations: 'Cannot verify whether an open socket returns valid HTTP 200 vs HTTP 500/404.',
        complementaryCapabilities: ['ejii.http.probe', 'ejii.tls.audit', 'ejii.host.active_connections'],
        parallelizableWith: ['ejii.icmp.ping', 'ejii.host.health_metrics']
      },
      'ejii.http.probe': {
        accomplishes: 'Verifies Layer 7 HTTP/HTTPS status code, headers, and TTFB waterfall.',
        limitations: 'Depends on working DNS and TCP transport; if TCP fails, HTTP cannot complete.',
        complementaryCapabilities: ['ejii.tcp.port_check', 'ejii.tls.audit'],
        parallelizableWith: []
      },
      'ejii.ai.spectral_fourier_periodicity': {
        accomplishes: 'Applies Cooley-Tukey Radix-2 FFT & Welch Periodogram to detect periodic jitter or throttling.',
        limitations: 'Requires a time-series sample array; does not identify which process caused the spike.',
        complementaryCapabilities: ['ejii.topology.multipath_qos_audit', 'ejii.host.health_metrics'],
        parallelizableWith: ['ejii.discovery.temporal_topology']
      },
      'ejii.simulation.digital_twin_branch': {
        accomplishes: 'Simulates M/M/1/K queueing, link failures, and chaos scenarios in an isolated branch.',
        limitations: 'Produces mathematical simulation results; never substitutes for live wire verification.',
        complementaryCapabilities: ['ejii.discovery.temporal_topology', 'ejii.governance.verified_remediation'],
        parallelizableWith: []
      }
    };

    const list = CAPABILITY_DEFINITIONS.map((cap) => {
      const meta = complementaryMap[cap.id] || {
        accomplishes: cap.name,
        limitations: cap.fallbackBehavior || 'Scoped to its specific protocol/diagnostic domain.',
        complementaryCapabilities: ['ejii.correlation.cross_layer_rca', 'ejii.discovery.temporal_topology'],
        parallelizableWith: ['ejii.host.health_metrics']
      };
      return {
        id: cap.id,
        name: cap.name,
        domain: cap.domain,
        executionMode: cap.executionMode,
        privilegeLevel: cap.privilegeLevel,
        blastRadius: cap.blastRadius,
        timeoutMs: cap.timeoutMs,
        requiredInputs: cap.inputsSchema?.required || [],
        accomplishes: meta.accomplishes,
        whatItAccomplishes: meta.accomplishes,
        limitations: meta.limitations,
        limitationsAndBlindSpots: meta.limitations,
        complementaryCapabilities: meta.complementaryCapabilities,
        parallelizableWith: meta.parallelizableWith
      };
    });
    list.totalCapabilities = list.length;
    list.capabilities = list;
    return list;
  }

  /**
   * COGNITION 3.0 (Phase 3 & 4) — Dynamic Capability Selector & Parallel/Sequential Task Organizer
   */
  selectComplementaryCapabilitiesForObjective({
    objective = '',
    problemNature = 'BROAD_UNSPECIFIED_INFRASTRUCTURE_ANOMALY',
    target = '127.0.0.1',
    port = 3000
  } = {}) {
    const ecosystem = this.describeCapabilityEcosystem();
    const byId = new Map(ecosystem.map((c) => [c.id, c]));
    const pick = (id, whySelected, inputParams = {}) => {
      const base = byId.get(id) || {
        id,
        name: id,
        domain: 'cognition',
        executionMode: 'diagnostic',
        blastRadius: 'none',
        accomplishes: whySelected,
        limitations: 'Bounded to observed telemetry.',
        complementaryCapabilities: []
      };
      return {
        ...base,
        whySelected,
        inputParams
      };
    };

    let selectedCapabilities = [];
    let parallelExecutionGroups = [];
    let dependentExecutionStages = [];

    if (problemNature === 'BROAD_UNSPECIFIED_INFRASTRUCTURE_ANOMALY') {
      selectedCapabilities = [
        pick('ejii.discovery.temporal_topology', 'Map active infrastructure topology, gateway links, and algebraic connectivity λ₂.', { triggerReason: 'cognition3_broad_triage' }),
        pick('ejii.host.health_metrics', 'Check local host CPU, RAM, and disk saturation in parallel with network discovery.', { forceRefresh: false }),
        pick('ejii.host.active_connections', 'Inspect active local kernel sockets and listening service ports to spot unbound listeners.', {}),
        pick('ejii.dns.resolve', `Verify DNS naming resolution for target '${target}'.`, { domain: target, rrtype: 'A' }),
        pick('ejii.tcp.port_check', `Test L4 TCP listener reachability on ${target}:${port}.`, { host: target, port }),
        pick('ejii.http.probe', `Verify L7 HTTP readiness on http://${target}:${port}/ once L4 state is known.`, { url: `http://${target}:${port}/` }),
        pick('ejii.correlation.cross_layer_rca', 'Synthesize cross-domain findings into calibrated root-cause hypotheses.', { target })
      ];
      parallelExecutionGroups = [
        {
          groupIndex: 1,
          groupLabel: 'Parallel Wide-Spectrum Environment Sweep (Topology + Host OS + Kernel Sockets + DNS)',
          capabilities: ['ejii.discovery.temporal_topology', 'ejii.host.health_metrics', 'ejii.host.active_connections', 'ejii.dns.resolve'],
          rationale: 'Independent passive/read-only collectors across topology, OS resources, socket table, and DNS run concurrently to localize the anomaly domain without waiting sequentially.'
        },
        {
          groupIndex: 2,
          groupLabel: 'Targeted Transport & Service Verification',
          capabilities: ['ejii.tcp.port_check', 'ejii.icmp.ping'],
          rationale: 'Simultaneously probes Layer 3 host reachability and Layer 4 service listener state.'
        }
      ];
      dependentExecutionStages = [
        {
          stageOrder: 1,
          capabilityId: 'ejii.http.probe',
          dependsOn: ['ejii.tcp.port_check'],
          condition: 'Run L7 HTTP readiness probe only if primary or recovered alternate TCP port is open.'
        },
        {
          stageOrder: 2,
          capabilityId: 'ejii.correlation.cross_layer_rca',
          dependsOn: ['ejii.discovery.temporal_topology', 'ejii.host.active_connections', 'ejii.tcp.port_check'],
          condition: 'Synthesize multi-domain observations after parallel sweep completes.'
        }
      ];
    } else if (problemNature === 'UNEXPLAINED_SYSTEM_OR_NETWORK_SLOWDOWN') {
      selectedCapabilities = [
        pick('ejii.host.health_metrics', 'Determine whether slowdown stems from host CPU/memory/load saturation.', { forceRefresh: false }),
        pick('ejii.diagnostics.hardware_kernel_inspector', 'Inspect kernel TCP retransmissions, socket buffer queues, and RF link margin.', {}),
        pick('ejii.icmp.ping', `Measure live RTT baseline and packet loss to ${target}.`, { host: target, count: 2 }),
        pick('ejii.ai.spectral_fourier_periodicity', 'Detect periodic latency spikes or throttling cadence via Cooley-Tukey FFT.', {}),
        pick('ejii.topology.multipath_qos_audit', 'Audit DSCP QoS markings and multipath congestion.', {}),
        pick('ejii.http.probe', `Measure L7 HTTP TTFB waterfall on ${target}:${port}.`, { url: `http://${target}:${port}/` })
      ];
      parallelExecutionGroups = [
        {
          groupIndex: 1,
          groupLabel: 'Parallel Host Saturation, Kernel Queue & Wire RTT Profiling',
          capabilities: ['ejii.host.health_metrics', 'ejii.diagnostics.hardware_kernel_inspector', 'ejii.icmp.ping'],
          rationale: 'Separates local compute/kernel bottlenecks from network path latency in a single parallel pass.'
        }
      ];
      dependentExecutionStages = [
        {
          stageOrder: 1,
          capabilityId: 'ejii.ai.spectral_fourier_periodicity',
          dependsOn: ['ejii.icmp.ping'],
          condition: 'Analyze RTT series for periodic microbursts or background contention.'
        },
        {
          stageOrder: 2,
          capabilityId: 'ejii.http.probe',
          dependsOn: ['ejii.icmp.ping'],
          condition: 'Decompose DNS vs TCP vs TLS vs HTTP TTFB latency contribution.'
        }
      ];
    } else if (problemNature === 'MISCONFIGURED_APPLICATION_OR_SERVER_DIFFERENTIAL') {
      selectedCapabilities = [
        pick('ejii.host.local_ip_config', 'Inspect local interfaces, DNS servers, and verified default gateway configuration.', {}),
        pick('ejii.host.active_connections', 'Compare active listening ports and process bindings against expected configuration.', {}),
        pick('ejii.tcp.port_check', `Probe expected service port ${target}:${port} and alternate ports (:3000/:3001).`, { host: target, port }),
        pick('ejii.discovery.temporal_topology', 'Compare target node attributes and dependencies against peer servers/gateways.', {}),
        pick('ejii.security.policy_governance_compiler', 'Audit zero-trust policy rules for port/subnet mismatches.', {})
      ];
      parallelExecutionGroups = [
        {
          groupIndex: 1,
          groupLabel: 'Parallel Configuration, Socket Binding & Topology Peer Comparison',
          capabilities: ['ejii.host.local_ip_config', 'ejii.host.active_connections', 'ejii.discovery.temporal_topology'],
          rationale: 'Collects live OS network config, socket bindings, and peer topology nodes simultaneously.'
        }
      ];
      dependentExecutionStages = [
        {
          stageOrder: 1,
          capabilityId: 'ejii.tcp.port_check',
          dependsOn: ['ejii.host.active_connections'],
          condition: 'Verify external vs loopback reachability on discovered and expected ports.'
        }
      ];
    } else if (problemNature === 'FAILING_HOST_OR_SERVER_RESOURCE_DEGRADATION') {
      selectedCapabilities = [
        pick('ejii.host.health_metrics', 'Inspect live CPU load, RAM exhaustion, and filesystem capacity.', { forceRefresh: true }),
        pick('ejii.host.active_connections', 'Identify crashed or zombie listeners and active socket states.', {}),
        pick('ejii.diagnostics.hardware_kernel_inspector', 'Check kernel ring buffer and NIC/TCP error counters.', {}),
        pick('ejii.tcp.port_check', `Verify whether critical service port ${target}:${port} is still accepting connections.`, { host: target, port })
      ];
      parallelExecutionGroups = [
        {
          groupIndex: 1,
          groupLabel: 'Parallel Host OS X-Ray (CPU/RAM/Disk + Kernel Inspector + Socket Table)',
          capabilities: ['ejii.host.health_metrics', 'ejii.diagnostics.hardware_kernel_inspector', 'ejii.host.active_connections'],
          rationale: 'Captures complete host operating system state in parallel.'
        }
      ];
      dependentExecutionStages = [
        {
          stageOrder: 1,
          capabilityId: 'ejii.tcp.port_check',
          dependsOn: ['ejii.host.active_connections'],
          condition: 'Confirm service socket responsiveness after OS resource audit.'
        }
      ];
    } else {
      // INFRASTRUCTURE_DEPENDENCY_AND_CASCADING_IMPACT or NOVEL_UNANTICIPATED_OPERATIONAL_PHENOMENON
      selectedCapabilities = [
        pick('ejii.discovery.temporal_topology', 'Traverse upstream/downstream dependencies and cut-edges in TemporalInfrastructureGraph.', {}),
        pick('ejii.host.gateway_ping', 'Verify default gateway reachability from OS routing table.', {}),
        pick('ejii.dns.resolve', `Check DNS resolution for ${target}.`, { domain: target, rrtype: 'A' }),
        pick('ejii.tcp.port_check', `Check L4 transport reachability on ${target}:${port}.`, { host: target, port }),
        pick('ejii.simulation.digital_twin_branch', 'Evaluate cascading blast radius and counterfactual failover in Digital Twin.', {}),
        pick('ejii.correlation.cross_layer_rca', 'Correlate upstream root cause vs downstream cascading symptoms.', { target })
      ];
      parallelExecutionGroups = [
        {
          groupIndex: 1,
          groupLabel: 'Parallel Dependency Graph, Gateway & DNS Verification',
          capabilities: ['ejii.discovery.temporal_topology', 'ejii.host.gateway_ping', 'ejii.dns.resolve'],
          rationale: 'Evaluates shared infrastructure dependencies concurrently.'
        }
      ];
      dependentExecutionStages = [
        {
          stageOrder: 1,
          capabilityId: 'ejii.tcp.port_check',
          dependsOn: ['ejii.dns.resolve'],
          condition: 'Probe target service transport after verifying upstream naming and gateway.'
        },
        {
          stageOrder: 2,
          capabilityId: 'ejii.simulation.digital_twin_branch',
          dependsOn: ['ejii.discovery.temporal_topology'],
          condition: 'Simulate cascading failure or remediation impact before modifying production.'
        }
      ];
    }

    return {
      totalRegisteredPlatformCapabilities: CAPABILITY_DEFINITIONS.length,
      objective,
      problemNature,
      target,
      port,
      selectedCapabilitiesCount: selectedCapabilities.length,
      selectedCapabilities,
      parallelExecutionGroups,
      dependentExecutionStages,
      complementarySynergyExplanation:
        `Selected ${selectedCapabilities.length} complementary capabilities across ${Array.from(new Set(selectedCapabilities.map((c) => c.domain))).join(', ')} ` +
        `organized into ${parallelExecutionGroups.length} parallel execution group(s) and ${dependentExecutionStages.length} conditional dependent stage(s), ` +
        `ensuring wire-level observations are cross-checked against host OS state, temporal topology dependencies, and historical memory.`
    };
  }
}

const capabilityRegistry = new CapabilityRegistry();

module.exports = {
  CAPABILITY_DEFINITIONS,
  CapabilityRegistry,
  capabilityRegistry,
  validateEjiiResult,
  get EJII_FUNCTION_DECLARATIONS() {
    const { EJII_FUNCTION_DECLARATIONS } = require('./chat/conversational-brain');
    return EJII_FUNCTION_DECLARATIONS;
  }
};

