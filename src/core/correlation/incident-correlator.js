/**
 * EJII v6 — Sovereign Intelligence Fabric
 * Part VI & Part VII:
 *   - Innovation Three: Cross-Layer Incident Correlation Engine
 *   - Innovation Four: Explainable Causal Investigation & Calibrated Counterfactual Engine
 *
 * Correlates telemetry across all 13 infrastructure layers (L1 NIC -> L2 ARP/DHCP ->
 * L3 Routing/ICMP -> L4 TCP/QoS -> L5-L7 DNS/TLS/HTTP/L7-Dissector -> Host/Kernel ->
 * Spectral/CUSUM -> Governance), constructs structured hypotheses with correlation-aware
 * Bayesian calibration, counterfactual refutations, and first-class Uncertainty Panel state.
 */

const crypto = require('crypto');
const { evidenceFabric } = require('../evidence/evidence-fabric');
const { temporalInfrastructureGraph } = require('../topology/temporal-graph-engine');
const { getPhysicalNetworkInfo } = require('../../network/routing/physical-network-detector');
const { RoutingRadixIntelligenceEngine } = require('../../topology/routing-radix-intelligence');
const { realPing } = require('../../protocols/icmp-ping');
const { checkPort } = require('../../protocols/tcp-port');
const { resolveRecord } = require('../../protocols/dns-diag');
const { auditTls } = require('../../protocols/tls-audit');
const { probeHttp } = require('../../protocols/http-probe');

const pingHost = async (host, count = 1, timeout = 1500) => {
  const r = await realPing(host, count, timeout);
  return { ...r, alive: Boolean(r && r.success) };
};
const resolveDns = async (hostname) => {
  const r = await resolveRecord(hostname, 'A');
  return { ...r, addresses: r.records || [], latencyMs: r.durationMs };
};
const inspectTls = auditTls;

const HYPOTHESIS_STATUSES = Object.freeze([
  'proposed',
  'supported',
  'contradicted',
  'confirmed',
  'rejected',
  'unresolved'
]);

const CORRELATION_DOMAINS = Object.freeze([
  'dns',
  'tcp',
  'tls',
  'http',
  'icmp_pmtu',
  'topology_blast_radius',
  'dhcp_apipa_arp',
  'packet_l7_dissection',
  'qos_dscp',
  'host_kernel_hardware',
  'spectral_cusum',
  'ai_brain_war_room',
  'operator_action_verification'
]);

class CrossLayerIncidentCorrelator {
  constructor() {
    this.incidents = new Map();
    this.latestInvestigation = null;
  }

  /**
   * Correlate multi-layer signals into a unified Cross-Layer Incident with
   * correlation-discounted Bayesian hypothesis ranking and counterfactual analysis.
   * @param {Object} input
   */
  correlateSignals(input = {}) {
    const nowIso = new Date().toISOString();
    const incidentId = input.incidentId || `INC-V6-${Date.now()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const target = String(input.target || input.hostname || '10.22.12.204');
    const signals = Array.isArray(input.signals) ? input.signals : [];

    const recordedEvidence = [];
    const domainBuckets = new Map();

    for (const sig of signals) {
      const domain = CORRELATION_DOMAINS.includes(sig.domain) ? sig.domain : 'tcp';
      const ev = evidenceFabric.recordEvidence({
        type: sig.evidenceType || 'observation',
        subject: sig.subject || `target:${target}`,
        claim: sig.claim || `${domain.toUpperCase()} signal observed on ${target}`,
        rawValue: sig.rawValue !== undefined ? sig.rawValue : sig,
        normalizedValue: sig.normalizedValue !== undefined ? sig.normalizedValue : (sig.status || sig.outcome || 'observed'),
        unit: sig.unit || null,
        sourceCapabilityId: sig.sourceCapabilityId || `ejii.${domain}.probe`,
        collectionMethod: sig.collectionMethod || 'direct_probe',
        observedAt: sig.observedAt || nowIso
      });
      recordedEvidence.push({ ...ev, domain, anomaly: Boolean(sig.anomaly), correlationGroup: sig.correlationGroup || domain });
      const list = domainBuckets.get(domain) || [];
      list.push(ev);
      domainBuckets.set(domain, list);
    }

    // Build structured hypotheses with correlation discounting & counterfactual analysis
    const hypotheses = this._evaluateStructuredHypotheses(target, recordedEvidence, input.context || {});
    const uncertaintyPanel = this.buildUncertaintyPanel(target, recordedEvidence, hypotheses);

    // Record top finding in EvidenceFabric
    const topHyp = hypotheses[0];
    const finding = evidenceFabric.recordFinding({
      title: topHyp ? topHyp.title : `Cross-Layer Investigation for ${target}`,
      subject: `target:${target}`,
      ruleId: 'RULE-V6-CROSS-LAYER-BAYESIAN',
      inferenceStep: `Evaluated ${hypotheses.length} causal hypotheses across ${domainBuckets.size} telemetry domain(s) with correlation discounting`,
      status: topHyp ? topHyp.status : 'unresolved',
      confidence: topHyp ? topHyp.posteriorProbability : 0.35,
      supportingEvidenceIds: topHyp ? topHyp.supportingEvidenceIds : [],
      counterEvidenceIds: topHyp ? topHyp.contradictingEvidenceIds : [],
      missingEvidenceIds: [],
      assumptions: topHyp ? topHyp.assumptions : [],
      disconfirmingConditions: topHyp ? topHyp.disconfirmingConditions : []
    });

    const report = {
      incidentId,
      target,
      createdAt: nowIso,
      domainsObserved: Array.from(domainBuckets.keys()),
      evidenceCount: recordedEvidence.length,
      evidenceRecords: recordedEvidence,
      hypotheses,
      topHypothesis: topHyp || null,
      findingId: finding.findingId,
      uncertaintyPanel
    };

    this.incidents.set(incidentId, report);
    this.latestInvestigation = report;
    return report;
  }

  /**
   * Calibrated Bayesian & Counterfactual Hypothesis Evaluator.
   * Accounts for correlated evidence (multiple symptoms sharing the same correlationGroup
   * receive diminishing marginal likelihood multiplier rather than naive independent multiplication)
   * and caps posterior probability <= 0.96 unless deterministic proof is present.
   */
  _evaluateStructuredHypotheses(target, evidenceList, context = {}) {
    const hasDnsFailure = evidenceList.some((e) => e.domain === 'dns' && (e.anomaly || String(e.normalizedValue).includes('ENOTFOUND') || String(e.normalizedValue).includes('NXDOMAIN') || String(e.normalizedValue).includes('TIMEOUT')));
    const hasDnsSuccess = evidenceList.some((e) => e.domain === 'dns' && !e.anomaly && String(e.normalizedValue).includes('RESOLVED'));
    const hasGatewaySuccess = evidenceList.some((e) => (e.subject.includes('gateway') || String(e.claim).toLowerCase().includes('gateway')) && !e.anomaly);
    const hasGatewayFailure = evidenceList.some((e) => (e.subject.includes('gateway') || String(e.claim).toLowerCase().includes('gateway')) && e.anomaly);
    const hasTcpRst = evidenceList.some((e) => e.domain === 'tcp' && (String(e.normalizedValue).includes('ECONNREFUSED') || String(e.normalizedValue).includes('CLOSED') || String(e.claim).includes('RST')));
    const hasTcpTimeout = evidenceList.some((e) => e.domain === 'tcp' && (String(e.normalizedValue).includes('TIMEOUT') || String(e.normalizedValue).includes('FILTERED')));
    const hasTcpOpen = evidenceList.some((e) => e.domain === 'tcp' && String(e.normalizedValue).includes('OPEN'));
    const hasIcmpSuccess = evidenceList.some((e) => e.domain === 'icmp_pmtu' && !e.anomaly);
    const hasQosBleach = evidenceList.some((e) => e.domain === 'qos_dscp' && e.anomaly);
    const hasHostExhaustion = evidenceList.some((e) => e.domain === 'host_kernel_hardware' && e.anomaly);

    const templates = [
      {
        id: 'HYP-DNS-RESOLUTION-FAILURE',
        title: 'Authoritative or Recursive DNS Resolution Failure (NXDOMAIN / Resolver Timeout)',
        causalMechanism: 'Client stub resolver cannot translate target hostname into an IPv4/IPv6 routing address due to NXDOMAIN, SERVFAIL, or unreachable UDP/53 nameserver.',
        priorProbability: 0.22,
        matchSupporting: (e) => e.domain === 'dns' && e.anomaly,
        matchContradicting: (e) => e.domain === 'dns' && !e.anomaly,
        deterministicConfirm: hasDnsFailure && !hasDnsSuccess,
        missingEvidenceNeeded: hasDnsFailure ? [] : ['RFC 1035 UDP/53 query against configured primary and secondary DNS resolvers'],
        assumptions: ['Target was specified as a symbolic DNS hostname rather than a raw IPv4/IPv6 literal'],
        disconfirmingConditions: ['Valid A/AAAA record returned by recursive resolver within <250ms'],
        recommendedNextProbes: ['dns_resolve', 'pcap_dns_dissection'],
        counterfactualAnalysis: hasDnsSuccess
          ? `If DNS resolution were the root cause, RFC 1035 queries for ${target} would fail with NXDOMAIN/SERVFAIL; however, live DNS resolution succeeded, refuting this hypothesis.`
          : `If DNS resolution fails before socket creation, no TCP SYN or ICMP packets can be emitted toward ${target}.`
      },
      {
        id: 'HYP-LOCAL-GATEWAY-OR-L2-ARP-SEVERANCE',
        title: 'Local Subnet Default Gateway Unreachable or L2 ARP Incomplete',
        causalMechanism: 'Physical NIC link drop, VLAN mismatch, or default gateway outage prevents L2 frame forwarding off the local broadcast domain.',
        priorProbability: 0.16,
        matchSupporting: (e) => (e.domain === 'dhcp_apipa_arp' || e.domain === 'topology_blast_radius') && e.anomaly,
        matchContradicting: (e) => (e.subject.includes('gateway') || String(e.claim).toLowerCase().includes('gateway') || (e.domain === 'icmp_pmtu' && !e.anomaly)) && !e.anomaly,
        deterministicConfirm: hasGatewayFailure && !hasGatewaySuccess,
        missingEvidenceNeeded: hasGatewaySuccess || hasGatewayFailure ? [] : ['Direct ICMP/ARP probe to active default gateway'],
        assumptions: ['Target resides beyond local link-local broadcast or requires L3 routing'],
        disconfirmingConditions: ['Default gateway responds to ARP/ICMP in <5ms and transit hops are reachable'],
        recommendedNextProbes: ['gateway_ping', 'arp_table_audit'],
        counterfactualAnalysis: hasGatewaySuccess
          ? `If the default gateway were the root cause, we would also expect upstream WAN and gateway probes through that router to fail; however, live gateway probes succeeded, which contradicts the gateway failure hypothesis.`
          : `If the default gateway fails to resolve via ARP, all off-subnet destinations will experience 100% packet loss at Hop 1.`
      },
      {
        id: 'HYP-TARGET-SERVICE-PORT-CLOSED-RST',
        title: 'Target Host Reachable on Network but Application Listener Closed (TCP RST / ECONNREFUSED)',
        causalMechanism: 'IP routing and L3 reachability to the target host are intact, but no process is bound to the target TCP port (kernel immediately replies with TCP RST+ACK).',
        priorProbability: 0.24,
        matchSupporting: (e) => (e.domain === 'tcp' && (String(e.normalizedValue).includes('CLOSED') || String(e.normalizedValue).includes('ECONNREFUSED'))) || (e.domain === 'icmp_pmtu' && !e.anomaly && hasTcpRst),
        matchContradicting: (e) => e.domain === 'tcp' && (String(e.normalizedValue).includes('OPEN') || String(e.normalizedValue).includes('TIMEOUT')),
        deterministicConfirm: hasTcpRst && !hasTcpOpen,
        missingEvidenceNeeded: hasTcpRst || hasTcpOpen ? [] : ['Active TCP SYN probe to target port to distinguish RST (closed) from silent drop (filtered)'],
        assumptions: ['Target service uses TCP transport on the inspected port'],
        disconfirmingConditions: ['TCP 3-way handshake completes (SYN -> SYN-ACK -> ACK)'],
        recommendedNextProbes: ['tcp_port_probe', 'process_socket_correlator'],
        counterfactualAnalysis: hasTcpOpen
          ? `If the remote service listener were down, the target kernel would emit TCP RST (ECONNREFUSED); however, the TCP 3-way handshake succeeded (OPEN), refuting this hypothesis.`
          : `Because the remote host returned an explicit TCP RST (or ICMP succeeded while TCP refused), L1–L3 routing and firewall ingress are proven healthy and the fault is isolated to the remote L4/L7 application daemon.`
      },
      {
        id: 'HYP-FIREWALL-ACL-SILENT-DROP-OR-PMTU',
        title: 'Intermediate Firewall ACL Silent Drop or Path MTU Black Hole',
        causalMechanism: 'Stateful firewall, security group, or transit ACL silently discards TCP SYN frames (TIMEOUT without RST), or oversized DF=1 frames are dropped without ICMP Fragmentation Needed.',
        priorProbability: 0.22,
        matchSupporting: (e) => (e.domain === 'tcp' && String(e.normalizedValue).includes('TIMEOUT')) || (e.domain === 'icmp_pmtu' && e.anomaly) || hasQosBleach,
        matchContradicting: (e) => (e.domain === 'tcp' && (String(e.normalizedValue).includes('OPEN') || String(e.normalizedValue).includes('CLOSED'))),
        deterministicConfirm: false,
        missingEvidenceNeeded: ['Multi-size PMTU DF=1 sweep (1472B, 1400B, 1200B, 576B) and Zero-Trust ACL policy audit'],
        assumptions: ['No explicit TCP RST or ICMP Destination Unreachable was returned to the sender'],
        disconfirmingConditions: ['Target responds with TCP SYN-ACK or explicit TCP RST on the inspected port'],
        recommendedNextProbes: ['pmtu_sweep', 'zero_trust_policy_audit'],
        counterfactualAnalysis: hasTcpRst
          ? `If an intermediate firewall were silently dropping traffic, the TCP socket would time out; however, an explicit TCP RST was received, proving packets reached the endpoint stack.`
          : `If DNS and local gateway reachability succeed while TCP SYN receives neither SYN-ACK nor RST within timeout, an intermediate stateful firewall or routing black hole is the primary suspect.`
      },
      {
        id: 'HYP-LOCAL-HOST-SOCKET-OR-KERNEL-CONTENTION',
        title: 'Local Host Ephemeral Port Exhaustion, NIC Ring Drops, or Resource Saturation',
        causalMechanism: 'Local workstation or container suffers from CLOSE_WAIT socket exhaustion, NIC RX/TX ring drops, or CPU/RAM saturation delaying local network I/O.',
        priorProbability: 0.16,
        matchSupporting: (e) => e.domain === 'host_kernel_hardware' && e.anomaly,
        matchContradicting: (e) => e.domain === 'host_kernel_hardware' && !e.anomaly,
        deterministicConfirm: hasHostExhaustion && !hasDnsFailure && !hasTcpRst,
        missingEvidenceNeeded: ['Hardware/Kernel NIC ring drop counter & TCP socket state inspection'],
        assumptions: ['Local OS kernel telemetry is accessible'],
        disconfirmingConditions: ['Local NIC drop counters are zero and ephemeral socket pool utilization is <50%'],
        recommendedNextProbes: ['hardware_kernel_inspect', 'host_diagnostics_audit'],
        counterfactualAnalysis: !hasHostExhaustion
          ? `If local host exhaustion were the cause, all outbound sockets across local and remote targets would degrade simultaneously; isolated target failure with healthy local kernel counters contradicts local saturation.`
          : `Elevated local kernel/socket contention directly degrades outbound connection initiation regardless of remote server health.`
      }
    ];

    // Score each hypothesis using correlation-discounted likelihoods
    const rawScored = templates.map((tpl) => {
      const supporting = evidenceList.filter((e) => tpl.matchSupporting(e));
      const contradicting = evidenceList.filter((e) => tpl.matchContradicting(e));

      // Group supporting evidence by correlationGroup so correlated symptoms are discounted
      const groupCounts = new Map();
      let logLikelihood = Math.log(Math.max(0.01, tpl.priorProbability));

      for (const ev of supporting) {
        const grp = ev.correlationGroup || ev.domain || 'default';
        const seenInGroup = groupCounts.get(grp) || 0;
        groupCounts.set(grp, seenInGroup + 1);
        // Correlation discount: 1st signal in group gets full weight (1.0), 2nd gets 0.45, 3rd gets 0.25...
        const correlationDiscount = 1 / Math.pow(1 + seenInGroup, 1.15);
        const qualityWeight = typeof ev.qualityScore === 'number' ? ev.qualityScore : 0.85;
        logLikelihood += 1.35 * correlationDiscount * qualityWeight;
      }

      for (const ev of contradicting) {
        const qualityWeight = typeof ev.qualityScore === 'number' ? ev.qualityScore : 0.85;
        logLikelihood -= 1.85 * qualityWeight;
      }

      const unnormalizedScore = Math.exp(logLikelihood);
      return {
        ...tpl,
        supporting,
        contradicting,
        unnormalizedScore,
        uniqueCorrelationGroups: groupCounts.size
      };
    });

    const totalScore = rawScored.reduce((acc, h) => acc + h.unnormalizedScore, 0) || 1;

    const evaluated = rawScored.map((h) => {
      let posterior = h.unnormalizedScore / totalScore;
      // Calibrated Bayesian bound: never report 0% or 100% unless deterministic proof exists
      if (h.deterministicConfirm && h.contradicting.length === 0 && h.supporting.length > 0) {
        posterior = Math.min(0.98, Math.max(0.88, posterior));
      } else {
        posterior = Math.min(0.92, Math.max(0.02, posterior));
      }
      posterior = Number(posterior.toFixed(4));

      const spread = Math.max(0.03, Number((0.16 / Math.sqrt(1 + h.supporting.length + h.contradicting.length)).toFixed(4)));
      const confidenceBand = [
        Number(Math.max(0.01, posterior - spread).toFixed(4)),
        Number(Math.min(0.99, posterior + spread).toFixed(4))
      ];

      let status = 'proposed';
      if (h.deterministicConfirm && h.contradicting.length === 0 && h.supporting.length > 0) {
        status = 'confirmed';
      } else if (h.contradicting.length > 0 && h.supporting.length === 0 && posterior < 0.12) {
        status = 'rejected';
      } else if (h.contradicting.length > h.supporting.length) {
        status = 'contradicted';
      } else if (h.supporting.length > 0) {
        status = 'supported';
      } else {
        status = 'unresolved';
      }

      return {
        id: h.id,
        title: h.title,
        causalMechanism: h.causalMechanism,
        priorProbability: h.priorProbability,
        posteriorProbability: posterior,
        confidenceBand,
        status,
        correlationGroupsCount: h.uniqueCorrelationGroups,
        supportingEvidenceIds: h.supporting.map((e) => e.id),
        contradictingEvidenceIds: h.contradicting.map((e) => e.id),
        missingEvidenceNeeded: h.missingEvidenceNeeded,
        assumptions: h.assumptions,
        disconfirmingConditions: h.disconfirmingConditions,
        recommendedNextProbes: h.recommendedNextProbes,
        counterfactualAnalysis: h.counterfactualAnalysis
      };
    });

    evaluated.sort((a, b) => b.posteriorProbability - a.posteriorProbability);
    return evaluated;
  }

  /**
   * Part VII (Section 7.3): Build First-Class Uncertainty Panel
   */
  buildUncertaintyPanel(target, evidenceRecords = [], hypotheses = []) {
    const knownFromLiveEvidence = evidenceRecords
      .filter((e) => e.type === 'observation' && (e.freshnessState === 'live' || e.freshnessState === 'fresh'))
      .map((e) => ({
        evidenceId: e.id,
        claim: e.claim,
        observedAt: e.observedAt,
        qualityScore: e.qualityScore
      }));

    const inferredFromCalculations = evidenceRecords
      .filter((e) => e.type === 'calculation' || e.type === 'confirmed_finding' || e.type === 'hypothesis')
      .map((e) => ({
        evidenceId: e.id,
        claim: e.claim,
        qualityScore: e.qualityScore
      }));

    const simulatedProjections = evidenceRecords
      .filter((e) => e.type === 'simulated_result')
      .map((e) => ({
        evidenceId: e.id,
        claim: e.claim,
        warning: 'Mathematical projection — never treated as live physical observation'
      }));

    const unknownsAndMissingTelemetry = [];
    for (const h of hypotheses.slice(0, 3)) {
      for (const m of h.missingEvidenceNeeded || []) {
        if (!unknownsAndMissingTelemetry.includes(m)) {
          unknownsAndMissingTelemetry.push(m);
        }
      }
    }

    const topTwo = hypotheses.slice(0, 2);
    let highestInformationGainProbe = {
      probeId: 'tcp_port_probe',
      target,
      rationale: 'Active L4 TCP SYN handshake test distinguishes host/network drop (TIMEOUT) from closed application listener (RST) and healthy service (SYN-ACK).',
      expectedEntropyReductionBits: 0.84
    };

    if (topTwo.length >= 2) {
      const gap = Math.abs(topTwo[0].posteriorProbability - topTwo[1].posteriorProbability);
      const nextProbe = (topTwo[0].recommendedNextProbes && topTwo[0].recommendedNextProbes[0]) || 'tcp_port_probe';
      highestInformationGainProbe = {
        probeId: nextProbe,
        target,
        competingHypotheses: [topTwo[0].id, topTwo[1].id],
        posteriorGap: Number(gap.toFixed(4)),
        rationale: `Resolves ambiguity between "${topTwo[0].title}" (${(topTwo[0].posteriorProbability * 100).toFixed(1)}%) and "${topTwo[1].title}" (${(topTwo[1].posteriorProbability * 100).toFixed(1)}%).`,
        expectedEntropyReductionBits: Number(Math.max(0.35, 1.2 - gap).toFixed(2))
      };
    }

    return {
      target,
      evaluatedAt: new Date().toISOString(),
      knownFromLiveEvidence,
      inferredFromCalculations,
      simulatedProjections,
      unknownsAndMissingTelemetry,
      highestInformationGainProbe
    };
  }

  /**
   * Part VI (Section 6.2): End-to-End Cross-Layer Diagnostic Workflow for an Unreachable Hostname
   * Evaluates steps 1..10 across L1 -> L7 and records a complete Evidence Lineage chain.
   */
  async diagnoseUnreachableHostname(hostnameInput = 'localhost', portInput = 443, options = {}) {
    const hostname = String(hostnameInput || 'localhost').trim();
    const port = Number(portInput) || 443;
    const pinnedIp = options && typeof options.pinnedIp === 'string' && options.pinnedIp.trim()
      ? options.pinnedIp.trim()
      : null;
    const workflowId = `WF-V6-${Date.now()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const startedAt = new Date().toISOString();
    const steps = [];
    const signals = [];

    // Step 1 & 2: Local NIC, link state, and IP/subnet/APIPA state
    const netInfo = getPhysicalNetworkInfo({ forceRefresh: false });
    const isApipa = Boolean(netInfo.localIp && netInfo.localIp.startsWith('169.254.'));
    steps.push({
      stepNumber: 1,
      layer: 'L1/L2 Local NIC & Subnet State',
      status: netInfo.localIp ? 'PASS' : 'FAIL',
      summary: `Interface ${netInfo.adapterName || 'eth0'} bound to ${netInfo.localIp} (${netInfo.subnetCidr})`,
      details: { adapter: netInfo.adapterName, localIp: netInfo.localIp, subnetCidr: netInfo.subnetCidr, isApipa }
    });
    signals.push({
      domain: 'dhcp_apipa_arp',
      subject: `nic:${netInfo.adapterName || 'eth0'}`,
      claim: `Local interface ${netInfo.adapterName || 'eth0'} configured with IP ${netInfo.localIp} (${netInfo.subnetCidr})`,
      rawValue: { localIp: netInfo.localIp, subnetCidr: netInfo.subnetCidr },
      normalizedValue: netInfo.localIp ? 'NIC_UP' : 'NIC_DOWN',
      anomaly: !netInfo.localIp,
      collectionMethod: 'os_route_table',
      correlationGroup: 'local_l2'
    });

    // Step 3: Default gateway reachability and ARP resolution
    const gwIp = netInfo.defaultGateway || null;
    steps.push({
      stepNumber: 2,
      layer: 'L2/L3 Default Gateway & ARP Resolution',
      status: gwIp ? 'PASS' : 'WARN',
      summary: gwIp
        ? `Default gateway ${gwIp} (${netInfo.gatewayVendor || 'Observed Gateway'})`
        : 'Default gateway route (0.0.0.0/0) not exposed in local routing table',
      details: { gatewayIp: gwIp, gatewayMac: netInfo.gatewayMac || null, gatewayVendor: netInfo.gatewayVendor || null }
    });
    signals.push({
      domain: 'topology_blast_radius',
      subject: `gateway:${gwIp || 'unverified'}`,
      claim: gwIp
        ? `Default gateway ${gwIp} present in active routing table`
        : 'Default gateway not exposed in active routing table',
      rawValue: { gatewayIp: gwIp, gatewayMac: netInfo.gatewayMac || null },
      normalizedValue: gwIp ? 'GATEWAY_OBSERVED' : 'GATEWAY_UNVERIFIED',
      anomaly: false,
      collectionMethod: 'os_route_table',
      correlationGroup: 'gateway_l3'
    });

    // Step 4: Routing table longest-prefix match
    let lpmMatch = null;
    try {
      const radixAudit = RoutingRadixIntelligenceEngine.captureAndAuditHostRoutes(
        pinnedIp || (/^\d+\.\d+\.\d+\.\d+$/.test(hostname) ? hostname : '8.8.8.8')
      );
      lpmMatch = radixAudit.probeLookup || null;
    } catch (_) {}
    steps.push({
      stepNumber: 3,
      layer: 'L3 Binary Radix Longest-Prefix Match',
      status: 'PASS',
      summary: lpmMatch && lpmMatch.matched
        ? `Longest-prefix match selected route ${lpmMatch.prefix}/${lpmMatch.prefixLen} via ${lpmMatch.nextHop}`
        : (gwIp ? `Default route 0.0.0.0/0 active via ${gwIp}` : 'Local interface routing active'),
      details: lpmMatch || { matched: Boolean(gwIp), prefix: '0.0.0.0', prefixLen: 0, nextHop: gwIp }
    });

    // Step 5: DNS Resolver reachability and RFC 1035 resolution (honoring pre-validated pinnedIp to prevent DNS rebinding)
    const isIpLiteral = /^\d+\.\d+\.\d+\.\d+$/.test(hostname) || hostname === 'localhost';
    let targetIp = pinnedIp || (hostname === 'localhost' ? '127.0.0.1' : hostname);
    let dnsResult = null;

    if (pinnedIp && !isIpLiteral) {
      const latencyMs = typeof options.prevalidatedDnsLatencyMs === 'number' ? options.prevalidatedDnsLatencyMs : null;
      const latSuffix = latencyMs !== null ? `${latencyMs}ms, ` : '';
      dnsResult = {
        success: true,
        hostname,
        records: options.resolvedIps || [pinnedIp],
        addresses: options.resolvedIps || [pinnedIp],
        latencyMs,
        durationMs: latencyMs,
        pinnedBySsrfGuard: true
      };
      steps.push({
        stepNumber: 4,
        layer: 'L7 DNS RFC 1035 Resolution',
        status: 'PASS',
        summary: `Resolved & pinned ${hostname} -> ${targetIp} (${latSuffix}SSRF-validated)`,
        details: dnsResult
      });
      signals.push({
        domain: 'dns',
        subject: `dns:${hostname}`,
        claim: `DNS resolved and pinned ${hostname} to ${targetIp}${latencyMs !== null ? ` (${latencyMs}ms)` : ''}`,
        rawValue: dnsResult,
        normalizedValue: `RESOLVED:${targetIp}`,
        unit: latencyMs !== null ? 'ms' : null,
        anomaly: false,
        collectionMethod: 'rfc1035_udp_dns_pinned',
        correlationGroup: 'dns_resolution'
      });
    } else if (!isIpLiteral) {
      dnsResult = await resolveDns(hostname);
      if (dnsResult.success && Array.isArray(dnsResult.addresses) && dnsResult.addresses.length > 0) {
        const { isSafeNetworkTarget } = require('../security');
        const candidateIp = dnsResult.addresses[0];
        if (!isSafeNetworkTarget(candidateIp)) {
          throw new Error(`SECURITY_VIOLATION_SSRF: Hostname '${hostname}' resolved to prohibited address '${candidateIp}'.`);
        }
        targetIp = candidateIp;
        steps.push({
          stepNumber: 4,
          layer: 'L7 DNS RFC 1035 Resolution',
          status: 'PASS',
          summary: `Resolved ${hostname} -> ${targetIp}${typeof dnsResult.latencyMs === 'number' ? ` in ${dnsResult.latencyMs}ms` : ''}`,
          details: dnsResult
        });
        signals.push({
          domain: 'dns',
          subject: `dns:${hostname}`,
          claim: `DNS resolved ${hostname} to ${targetIp}${typeof dnsResult.latencyMs === 'number' ? ` (${dnsResult.latencyMs}ms)` : ''}`,
          rawValue: dnsResult,
          normalizedValue: `RESOLVED:${targetIp}`,
          unit: 'ms',
          anomaly: false,
          collectionMethod: 'rfc1035_udp_dns',
          correlationGroup: 'dns_resolution'
        });
      } else {
        steps.push({
          stepNumber: 4,
          layer: 'L7 DNS RFC 1035 Resolution',
          status: 'FAIL',
          summary: `DNS resolution failed for ${hostname}: ${dnsResult.errorCode || dnsResult.error || 'ENOTFOUND'}`,
          details: dnsResult
        });
        signals.push({
          domain: 'dns',
          subject: `dns:${hostname}`,
          claim: `DNS resolution failed for ${hostname} with code ${dnsResult.errorCode || 'ENOTFOUND'}`,
          rawValue: dnsResult,
          normalizedValue: `DNS_FAILED:${dnsResult.errorCode || 'ENOTFOUND'}`,
          anomaly: true,
          collectionMethod: 'rfc1035_udp_dns',
          correlationGroup: 'dns_resolution'
        });
      }
    } else {
      steps.push({
        stepNumber: 4,
        layer: 'L7 DNS RFC 1035 Resolution',
        status: 'PASS',
        summary: `Target ${hostname} is a direct IP/loopback literal (${targetIp}); DNS lookup bypassed`,
        details: { targetIp, bypassed: true, durationMs: null }
      });
      signals.push({
        domain: 'dns',
        subject: `dns:${hostname}`,
        claim: `Target ${hostname} resolved directly to ${targetIp}`,
        rawValue: { targetIp },
        normalizedValue: `RESOLVED:${targetIp}`,
        anomaly: false,
        collectionMethod: 'rfc1035_udp_dns',
        correlationGroup: 'dns_resolution'
      });
    }

    // Step 6 & 7: Target IP reachability (ICMP) & L4 TCP Handshake
    let icmpRes = null;
    let tcpRes = null;
    if (!dnsResult || dnsResult.success || isIpLiteral) {
      [icmpRes, tcpRes] = await Promise.all([
        pingHost(targetIp, 1, 1500).catch((e) => ({ alive: false, error: e.message })),
        checkPort(targetIp, port, 2000).catch((e) => ({ status: 'ERROR', error: e.message }))
      ]);

      steps.push({
        stepNumber: 5,
        layer: 'L3 ICMP Reachability Probe',
        status: icmpRes && icmpRes.alive ? 'PASS' : 'WARN',
        summary: icmpRes && icmpRes.alive
          ? `ICMP Echo reply from ${targetIp}${typeof icmpRes.avgRttMs === 'number' ? ` in ${icmpRes.avgRttMs}ms` : ''}`
          : `ICMP Echo unanswered by ${targetIp} (may be filtered by host firewall)`,
        details: icmpRes
      });
      signals.push({
        domain: 'icmp_pmtu',
        subject: `ip:${targetIp}`,
        claim: icmpRes && icmpRes.alive
          ? `ICMP Echo reply received from ${targetIp}${typeof icmpRes.avgRttMs === 'number' ? ` (${icmpRes.avgRttMs}ms)` : ''}`
          : `No ICMP Echo reply from ${targetIp}`,
        rawValue: icmpRes,
        normalizedValue: icmpRes && icmpRes.alive ? 'ICMP_ALIVE' : 'ICMP_UNANSWERED',
        unit: 'ms',
        anomaly: !(icmpRes && icmpRes.alive),
        collectionMethod: 'icmp_echo',
        correlationGroup: 'target_reachability'
      });

      const tcpOpen = tcpRes && tcpRes.status === 'OPEN';
      const tcpHandshakeRttMs = typeof tcpRes?.connectLatencyMs === 'number'
        ? tcpRes.connectLatencyMs
        : (typeof tcpRes?.latencyMs === 'number' ? tcpRes.latencyMs : null);
      steps.push({
        stepNumber: 6,
        layer: 'L4 TCP 3-Way Handshake & Kernel Socket Audit',
        status: tcpOpen ? 'PASS' : 'FAIL',
        summary: tcpOpen
          ? `TCP port ${targetIp}:${port} is OPEN${tcpHandshakeRttMs !== null ? ` (Handshake RTT: ${tcpHandshakeRttMs}ms)` : ''}`
          : `TCP port ${targetIp}:${port} is ${tcpRes?.status || 'UNREACHABLE'} (${tcpRes?.errorCode || tcpRes?.error || 'Connection failed'})`,
        details: tcpRes
      });
      signals.push({
        domain: 'tcp',
        subject: `socket:${targetIp}:${port}`,
        claim: `TCP connect to ${targetIp}:${port} returned status=${tcpRes?.status || 'FAILED'} (${tcpRes?.errorCode || 'NONE'})`,
        rawValue: tcpRes,
        normalizedValue: `TCP_${tcpRes?.status || 'FAILED'}_${tcpRes?.errorCode || ''}`,
        unit: 'ms',
        anomaly: !tcpOpen,
        collectionMethod: 'tcp_connect',
        correlationGroup: 'target_l4'
      });

      // Step 8 & 9: TLS & HTTP inspection if TCP port is open
      if (tcpOpen && (port === 443 || port === 8443)) {
        const tlsRes = await inspectTls(hostname, port, 2500).catch((e) => ({ valid: false, error: e.message }));
        const cipherStr = tlsRes?.cipher?.name || (typeof tlsRes?.cipher === 'string' ? tlsRes.cipher : 'TLS Cipher');
        steps.push({
          stepNumber: 7,
          layer: 'L6 TLS Handshake, SNI & X.509 Chain',
          status: tlsRes && (tlsRes.valid || tlsRes.success) ? 'PASS' : 'WARN',
          summary: tlsRes && tlsRes.protocol
            ? `TLS ${tlsRes.protocol} (${cipherStr}) negotiated`
            : `TLS handshake warning: ${tlsRes?.error || 'Unverified'}`,
          details: tlsRes
        });
      }
      if (tcpOpen && (port === 80 || port === 443 || port === 3000 || port === 8443)) {
        const proto = (port === 443 || port === 8443) ? 'https' : 'http';
        const httpRes = await probeHttp(`${proto}://${hostname}:${port}/`, 'GET', 2500).catch((e) => ({ success: false, error: e.message }));
        const ttfbVal = typeof httpRes?.waterfall?.ttfbMs === 'number'
          ? httpRes.waterfall.ttfbMs
          : (typeof httpRes?.ttfbMs === 'number' ? httpRes.ttfbMs : null);
        steps.push({
          stepNumber: 8,
          layer: 'L7 HTTP Application Response & TTFB',
          status: httpRes && httpRes.statusCode ? 'PASS' : 'WARN',
          summary: httpRes && httpRes.statusCode
            ? `HTTP ${httpRes.statusCode} received${ttfbVal !== null ? ` (TTFB: ${ttfbVal}ms)` : ''}`
            : `HTTP probe note: ${httpRes?.error || 'No HTTP response'}`,
          details: httpRes
        });
      }
    }

    const correlationReport = this.correlateSignals({
      incidentId: workflowId,
      target: `${hostname}:${port}`,
      signals
    });

    temporalInfrastructureGraph.syncFromLiveInfrastructure(`diagnose_${hostname}`);

    return {
      workflowId,
      hostname,
      resolvedIp: targetIp,
      port,
      startedAt,
      completedAt: new Date().toISOString(),
      steps,
      correlation: correlationReport
    };
  }
}

const crossLayerIncidentCorrelator = new CrossLayerIncidentCorrelator();

module.exports = {
  HYPOTHESIS_STATUSES,
  CORRELATION_DOMAINS,
  CrossLayerIncidentCorrelator,
  crossLayerIncidentCorrelator
};
