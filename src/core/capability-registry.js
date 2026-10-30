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

