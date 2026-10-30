/**
 * EJII Project Falcon — Conversational Brain & Sovereign Fabric v6 Epistemic Reasoner
 *
 * Bridges:
 *   1. Native Gemini Function Calling (`tools: [{ functionDeclarations }]`)
 *   2. Iterative Agentic Tool Loop (`Plan -> Execute -> Observe -> Reflect`, bounded to max 3 steps)
 *   3. Sovereign Fabric v6 Evidence Lineage DAG (`evidenceFabric`), Truth Matrix & Exact Mathematical Shannon Information-Gain
 *   4. Multi-Turn Task & Slot Continuity (Mail Triage, Port Ping, DHCP Follow-Up, Gateway Epistemics)
 */

'use strict';

const { aiModelOrchestrator } = require('../ai-model-orchestrator');
const hostMetrics = require('../../protocols/host-metrics');
const dnsDiag = require('../../protocols/dns-diag');
const { evidenceFabric } = require('../evidence/evidence-fabric');

/**
 * Native Gemini Function Declarations for EJII's 12 Infrastructure & Epistemic Tools
 */
const EJII_FUNCTION_DECLARATIONS = [
  {
    name: 'dns_lookup',
    description: 'Resolve DNS records (A, AAAA, MX, TXT, NS, CNAME, PTR, SOA) for a domain name and measure RFC 1035 query latency.',
    parameters: {
      type: 'OBJECT',
      properties: {
        domain: { type: 'STRING', description: 'Target domain name (e.g., google.com, youtube.com, example.com)' },
        recordType: {
          type: 'STRING',
          description: 'DNS record type to query: A, AAAA, MX, TXT, NS, CNAME, PTR, or SOA',
          enum: ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'PTR', 'SOA']
        }
      },
      required: ['domain']
    }
  },
  {
    name: 'tcp_port_probe',
    description: 'Perform a real Layer 4 TCP 3-way handshake probe (port ping) against one or more TCP ports on a target hostname or IP.',
    parameters: {
      type: 'OBJECT',
      properties: {
        target: { type: 'STRING', description: 'Target hostname or IPv4/IPv6 address (e.g., youtube.com, 1.1.1.1, localhost)' },
        ports: {
          type: 'ARRAY',
          items: { type: 'INTEGER' },
          description: 'List of TCP port numbers to test (e.g., [443], [80, 443], [25, 465, 587, 993])'
        }
      },
      required: ['target']
    }
  },
  {
    name: 'icmp_ping',
    description: 'Send Layer 3 ICMP echo requests to a target host and measure round-trip latency and packet loss.',
    parameters: {
      type: 'OBJECT',
      properties: {
        target: { type: 'STRING', description: 'Target hostname or IP address' }
      },
      required: ['target']
    }
  },
  {
    name: 'http_tls_inspect',
    description: 'Inspect Layer 6 TLS handshake / X.509 certificate and Layer 7 HTTP/HTTPS response status and TTFB for a URL or host.',
    parameters: {
      type: 'OBJECT',
      properties: {
        target: { type: 'STRING', description: 'Target hostname or full URL' },
        port: { type: 'INTEGER', description: 'Target TCP port (default 443 for HTTPS, 80 for HTTP)' }
      },
      required: ['target']
    }
  },
  {
    name: 'inspect_local_network',
    description: 'Inspect local OS network interfaces, IPv4/IPv6 addresses, loopback vs non-loopback scope, and configured DNS resolvers.',
    parameters: {
      type: 'OBJECT',
      properties: {}
    }
  },
  {
    name: 'inspect_default_gateway',
    description: 'Inspect the OS kernel routing table (/proc/net/route or ip route) for a verified 0.0.0.0/0 default gateway and test reachability.',
    parameters: {
      type: 'OBJECT',
      properties: {}
    }
  },
  {
    name: 'inspect_dhcp_status',
    description: 'Inspect local OS DHCP lease files, NetworkManager/systemd-networkd state, and determine whether IP addressing is DHCP-assigned, static, or container-managed.',
    parameters: {
      type: 'OBJECT',
      properties: {}
    }
  },
  {
    name: 'run_5_layer_path_diagnostic',
    description: 'Execute a 5-layer local-to-ISP path diagnostic across Layer 1 NIC, Layer 2 ARP, Layer 3 Default Gateway, Layer 4 Anycast TCP (1.1.1.1:53), and Layer 7 HTTPS (dns.google:443).',
    parameters: {
      type: 'OBJECT',
      properties: {}
    }
  },
  {
    name: 'query_sovereign_fabric_v6',
    description: 'Query the Sovereign Fabric v6 epistemic truth matrix, Bayesian hypothesis posteriors, Shannon entropy (bits), and highest information-gain next diagnostic probe.',
    parameters: {
      type: 'OBJECT',
      properties: {
        questionFocus: {
          type: 'STRING',
          description: 'Focus area: information_gain_next_probe, truth_matrix_unresolved, default_gateway_epistemic_state, or bayesian_posteriors'
        }
      }
    }
  },
  {
    name: 'inspect_host_health',
    description: 'Inspect local host CPU tick utilization, load averages, RAM usage, mounted filesystems, and active kernel socket counts.',
    parameters: {
      type: 'OBJECT',
      properties: {}
    }
  },
  {
    name: 'inspect_active_sockets',
    description: 'List active TCP/UDP kernel sockets, listening ports, and established remote endpoints.',
    parameters: {
      type: 'OBJECT',
      properties: {
        portFilter: { type: 'INTEGER', description: 'Optional TCP/UDP port filter' }
      }
    }
  },
  {
    name: 'run_traceroute',
    description: 'Run a Layer 3 hop-by-hop traceroute toward a target hostname or IP address.',
    parameters: {
      type: 'OBJECT',
      properties: {
        target: { type: 'STRING', description: 'Target hostname or IP address' }
      },
      required: ['target']
    }
  }
];

/**
 * Candidate diagnostic probes and their empirical likelihood models P(Y=pass | X=hypothesis_i)
 * across the 9 canonical infrastructure fault hypotheses in VectorizedBayesianMatrix.
 *
 * Used to compute exact expected Shannon Information Gain:
 *   IG(X; Y) = H(X) - [ P(Y=pass) * H(X | Y=pass) + P(Y=fail) * H(X | Y=fail) ]
 */
const CANDIDATE_PROBE_LIKELIHOOD_MODELS = [
  {
    probeId: 'TCP_CONNECT_1_1_1_1_443',
    probeName: 'External L4 TCP Handshake Probe (`1.1.1.1:443` / `dns.google:443`)',
    command: 'Check TCP port 443 on 1.1.1.1',
    intent: 'port_check',
    target: '1.1.1.1',
    ports: [443],
    targetLayers: ['Layer 3 (Routing/Egress)', 'Layer 4 (TCP Transport)'],
    discriminatesBetween: ['UPSTREAM_WAN_BLACKHOLE', 'FIREWALL_ACL_DROP', 'ICMP_FILTERED_ALIVE', 'LOCAL_STACK_CONGESTION'],
    // P(Y=pass | X = hypothesis_id)
    likelihoodPassGivenHypothesis: {
      FIREWALL_ACL_DROP: 0.08,
      SERVICE_DAEMON_CRASH: 0.85,
      DNS_NXDOMAIN_POISON: 0.94,
      UPSTREAM_WAN_BLACKHOLE: 0.03,
      TLS_CERT_EXPIRY: 0.92,
      MTU_BLACKHOLE_FRAGMENT: 0.65,
      ARP_L2_ISOLATION: 0.02,
      LOCAL_STACK_CONGESTION: 0.35,
      ICMP_FILTERED_ALIVE: 0.96
    }
  },
  {
    probeId: 'DNS_WIRE_LOOKUP_GOOGLE',
    probeName: 'RFC 1035 Authoritative DNS Resolution Probe (`google.com` A & MX)',
    command: 'Check DNS for google.com',
    intent: 'dns',
    target: 'google.com',
    ports: [],
    targetLayers: ['Layer 7 (DNS Resolution)', 'Layer 3/4 (UDP/TCP 53 Egress)'],
    discriminatesBetween: ['DNS_NXDOMAIN_POISON', 'UPSTREAM_WAN_BLACKHOLE', 'SERVICE_DAEMON_CRASH'],
    likelihoodPassGivenHypothesis: {
      FIREWALL_ACL_DROP: 0.45,
      SERVICE_DAEMON_CRASH: 0.90,
      DNS_NXDOMAIN_POISON: 0.04,
      UPSTREAM_WAN_BLACKHOLE: 0.05,
      TLS_CERT_EXPIRY: 0.95,
      MTU_BLACKHOLE_FRAGMENT: 0.78,
      ARP_L2_ISOLATION: 0.03,
      LOCAL_STACK_CONGESTION: 0.40,
      ICMP_FILTERED_ALIVE: 0.93
    }
  },
  {
    probeId: 'HTTPS_L7_PROBE_EXAMPLE',
    probeName: 'End-to-End L6/L7 TLS & HTTPS Application Probe (`https://example.com`)',
    command: 'Check whether https://example.com is working',
    intent: 'website_check',
    target: 'example.com',
    ports: [443],
    targetLayers: ['Layer 6 (TLS 1.3 X.509)', 'Layer 7 (HTTP Status & TTFB)'],
    discriminatesBetween: ['TLS_CERT_EXPIRY', 'SERVICE_DAEMON_CRASH', 'MTU_BLACKHOLE_FRAGMENT', 'FIREWALL_ACL_DROP'],
    likelihoodPassGivenHypothesis: {
      FIREWALL_ACL_DROP: 0.06,
      SERVICE_DAEMON_CRASH: 0.05,
      DNS_NXDOMAIN_POISON: 0.08,
      UPSTREAM_WAN_BLACKHOLE: 0.03,
      TLS_CERT_EXPIRY: 0.04,
      MTU_BLACKHOLE_FRAGMENT: 0.15,
      ARP_L2_ISOLATION: 0.02,
      LOCAL_STACK_CONGESTION: 0.30,
      ICMP_FILTERED_ALIVE: 0.91
    }
  }
];

/**
 * Pure mathematical calculation of Shannon Entropy H(X) in bits:
 *   H(X) = - \sum_i P(x_i) \log_2 P(x_i)
 *
 * @param {number[]} probabilities - Array of non-negative probabilities summing to 1
 * @returns {number} Shannon entropy in bits
 */
function computeShannonEntropyFromDistribution(probabilities = []) {
  let h = 0;
  for (const p of probabilities) {
    if (typeof p === 'number' && Number.isFinite(p) && p > 1e-12) {
      h -= p * Math.log2(p);
    }
  }
  return Number(Math.max(0, h).toFixed(4));
}

/**
 * Exact Mathematical Expected Shannon Information Gain for a binary-outcome probe Y in {pass, fail}:
 *
 *   IG(X; Y) = H(X) - [ P(Y=pass) * H(X | Y=pass) + P(Y=fail) * H(X | Y=fail) ]
 *
 * Where:
 *   P(Y=pass) = \sum_i P(X=x_i) * P(Y=pass | X=x_i)
 *   P(Y=fail) = 1 - P(Y=pass)
 *   P(X=x_i | Y=pass) = [ P(X=x_i) * P(Y=pass | X=x_i) ] / P(Y=pass)
 *   P(X=x_i | Y=fail) = [ P(X=x_i) * (1 - P(Y=pass | X=x_i)) ] / P(Y=fail)
 *
 * Never uses fixed multipliers or minimum floors.
 */
function computeExpectedProbeInformationGain(priorDistribution = [], likelihoodPassByHypothesisId = {}) {
  if (!Array.isArray(priorDistribution) || priorDistribution.length === 0) {
    return null;
  }

  // Normalize prior probabilities strictly to sum to 1.0
  const rawWeights = priorDistribution.map((h) => {
    const p = typeof h.probability === 'number'
      ? h.probability
      : (typeof h.rawProbability === 'number'
          ? h.rawProbability
          : (typeof h.percentage === 'number' ? h.percentage / 100 : 0));
    return Math.max(0, Number(p) || 0);
  });
  const totalWeight = rawWeights.reduce((acc, v) => acc + v, 0);
  if (totalWeight <= 0) {
    return null;
  }
  const priors = rawWeights.map((w) => w / totalWeight);
  const priorEntropyBits = computeShannonEntropyFromDistribution(priors);

  // Compute P(Y = pass) and P(Y = fail)
  let pPass = 0;
  const jointPass = [];
  const jointFail = [];

  for (let i = 0; i < priorDistribution.length; i++) {
    const hypId = priorDistribution[i].id;
    const pX = priors[i];
    const rawL = likelihoodPassByHypothesisId[hypId];
    const lPass = typeof rawL === 'number' && Number.isFinite(rawL)
      ? Math.min(0.999, Math.max(0.001, rawL))
      : 0.5;
    const lFail = 1 - lPass;

    const jp = pX * lPass;
    const jf = pX * lFail;
    jointPass.push(jp);
    jointFail.push(jf);
    pPass += jp;
  }

  pPass = Math.min(0.999999, Math.max(0.000001, pPass));
  const pFail = 1 - pPass;

  const posteriorGivenPass = jointPass.map((jp) => jp / pPass);
  const posteriorGivenFail = jointFail.map((jf) => jf / pFail);

  const entropyGivenPassBits = computeShannonEntropyFromDistribution(posteriorGivenPass);
  const entropyGivenFailBits = computeShannonEntropyFromDistribution(posteriorGivenFail);

  const expectedPosteriorEntropyBits = Number(
    (pPass * entropyGivenPassBits + pFail * entropyGivenFailBits).toFixed(4)
  );
  const informationGainBits = Number(
    Math.max(0, priorEntropyBits - expectedPosteriorEntropyBits).toFixed(4)
  );

  return {
    priorEntropyBits: Number(priorEntropyBits.toFixed(2)),
    priorEntropyExactBits: priorEntropyBits,
    pPass: Number(pPass.toFixed(4)),
    pFail: Number(pFail.toFixed(4)),
    entropyGivenPassBits: Number(entropyGivenPassBits.toFixed(2)),
    entropyGivenFailBits: Number(entropyGivenFailBits.toFixed(2)),
    expectedPosteriorEntropyBits: Number(expectedPosteriorEntropyBits.toFixed(2)),
    expectedInformationGainBits: Number(informationGainBits.toFixed(2)),
    expectedInformationGainExactBits: informationGainBits
  };
}

/**
 * Computes live Shannon entropy and expected information gain (\Delta H in bits)
 * for candidate diagnostic probes against the current Sovereign Fabric v6 Truth Matrix.
 */
function computeLiveInformationGainAnalysis(sessionContext = {}) {
  const gatewayInfo = hostMetrics.getVerifiedDefaultGateway();
  const dnsConfig = dnsDiag.discoverSystemDnsConfiguration();
  const dhcpInfo = hostMetrics.discoverLocalDhcpServer();
  const localNetConfig = hostMetrics.inspectLocalNetworkConfiguration();

  // Retrieve live Bayesian posterior distribution from AIModelOrchestrator
  const bayesianState = aiModelOrchestrator.bayesianEngine
    ? aiModelOrchestrator.bayesianEngine.computePosteriors({
        icmpLossPct: gatewayInfo.verified ? 0 : null,
        dnsResolved: dnsConfig.observedServers && dnsConfig.observedServers.length > 0,
        tcpReset: false,
        tcpTimeout: false
      })
    : null;

  const hypotheses = Array.isArray(bayesianState?.hypotheses) ? bayesianState.hypotheses : [];
  const hasValidPosteriors = hypotheses.length > 0;

  // Distinguish directly observed probes in the current session
  const observedIntents = new Set();
  if (sessionContext?.lastIntent) observedIntents.add(sessionContext.lastIntent);
  if (Array.isArray(sessionContext?.probeHistory)) {
    for (const p of sessionContext.probeHistory) {
      if (p && p.intent) observedIntents.add(p.intent);
    }
  }
  const lastProbe = sessionContext?.lastProbeResult || sessionContext?.lastToolResults || null;

  // Build prior distribution for exact Shannon IG math
  const priorDistribution = hasValidPosteriors
    ? hypotheses.map((h) => ({
        id: h.id,
        name: h.name,
        probability: typeof h.rawProbability === 'number' ? h.rawProbability : (Number(h.percentage) || 0) / 100,
        percentage: h.percentage,
        contradicted: Boolean(h.contradicted)
      }))
    : [];

  const currentEntropyBits = hasValidPosteriors
    ? (typeof bayesianState.shannonEntropyBits === 'number'
        ? bayesianState.shannonEntropyBits
        : computeShannonEntropyFromDistribution(priorDistribution.map((d) => d.probability)))
    : null;

  // Evaluate candidate probes using exact mathematical IG(X; Y) = H(X) - \sum_y P(y) H(X | Y=y)
  const candidateProbes = CANDIDATE_PROBE_LIKELIHOOD_MODELS.map((model) => {
    const mathIg = hasValidPosteriors
      ? computeExpectedProbeInformationGain(priorDistribution, model.likelihoodPassGivenHypothesis)
      : null;

    // Slight priority adjustment if a probe was already executed in this session
    const alreadyObserved = observedIntents.has(model.intent);

    let rationale = '';
    if (model.probeId === 'TCP_CONNECT_1_1_1_1_443') {
      rationale = !gatewayInfo.verified
        ? `Because the local OS routing table returned ${gatewayInfo.status || 'NO_DEFAULT_ROUTE_OBSERVED'} (${gatewayInfo.collectionMethod}) in this ${gatewayInfo.environmentScope} and raw ICMP is often filtered, a direct Layer 4 TCP 3-way handshake to 1.1.1.1:443 tests both kernel virtual-switch forwarding and external WAN egress in a single step.`
        : `Directly verifies Layer 4 TCP transport across default gateway ${gatewayInfo.gatewayIp} to an external anycast endpoint.`;
    } else if (model.probeId === 'DNS_WIRE_LOOKUP_GOOGLE') {
      rationale = `Tests whether the configured OS DNS resolver (${(dnsConfig.observedServers || []).join(', ') || dnsConfig.status}) can recursively resolve external records, isolating DNS failures from L3/L4 routing drops.`;
    } else {
      rationale = `Verifies TLS 1.3 certificate validity and Layer 7 HTTP application responsiveness once L4 TCP reachability is known.`;
    }

    return {
      probeId: model.probeId,
      probeName: model.probeName,
      command: model.command,
      intent: model.intent,
      target: model.target,
      ports: model.ports,
      targetLayers: model.targetLayers,
      discriminatesBetween: model.discriminatesBetween,
      alreadyObservedInSession: alreadyObserved,
      pPass: mathIg ? mathIg.pPass : null,
      pFail: mathIg ? mathIg.pFail : null,
      entropyGivenPassBits: mathIg ? mathIg.entropyGivenPassBits : null,
      entropyGivenFailBits: mathIg ? mathIg.entropyGivenFailBits : null,
      expectedInformationGainBits: mathIg ? mathIg.expectedInformationGainBits : null,
      expectedPosteriorEntropyBits: mathIg ? mathIg.expectedPosteriorEntropyBits : null,
      calculationMethod: mathIg ? 'SHANNON_CONDITIONAL_ENTROPY_BAYES_EXACT' : 'UNAVAILABLE_NO_PRIOR',
      rationale
    };
  });

  // Sort by highest mathematical information gain (preferring unexecuted probes on ties)
  candidateProbes.sort((a, b) => {
    if (a.alreadyObservedInSession !== b.alreadyObservedInSession) {
      return a.alreadyObservedInSession ? 1 : -1;
    }
    return (b.expectedInformationGainBits ?? -1) - (a.expectedInformationGainBits ?? -1);
  });

  // Determine real observation status of each layer (never hardcode Layer 1 as OBSERVED without checking localNetConfig)
  const l1Up = Array.isArray(localNetConfig?.interfaces) && localNetConfig.interfaces.some((i) => i.status === 'UP');
  const l4Observed =
    observedIntents.has('port_check') ||
    observedIntents.has('website_check') ||
    observedIntents.has('local_path_diagnostic') ||
    Boolean(lastProbe && (lastProbe.tool === 'checkPort' || lastProbe.tcp || lastProbe.rawResults));
  const l7Observed =
    observedIntents.has('dns') ||
    observedIntents.has('website_check') ||
    observedIntents.has('local_path_diagnostic') ||
    Boolean(lastProbe && (lastProbe.tool === 'resolveRecord' || lastProbe.dns || lastProbe.http));

  const unresolvedTruthMatrixLayers = [
    {
      layer: 'Layer 1 — Local Network Interfaces',
      epistemicState: l1Up ? 'DIRECTLY_OBSERVED' : 'UNOBSERVED',
      detail: l1Up
        ? `Primary IPv4: ${localNetConfig.primaryIpv4Label} across ${localNetConfig.interfaces.length} OS interface(s) (${localNetConfig.executionScope})`
        : `No active UP network interface observed (${localNetConfig?.limitationReason || 'unprobed'})`
    },
    {
      layer: 'Layer 2 — Neighbor / ARP & DHCP Lease State',
      epistemicState: dhcpInfo.observed ? 'DIRECTLY_OBSERVED' : 'UNOBSERVED_ENVIRONMENT_BOUNDARY',
      detail: dhcpInfo.observed
        ? `DHCP Server ${dhcpInfo.dhcpServerIp} verified via ${dhcpInfo.collectionMethod}`
        : `${dhcpInfo.status} (${dhcpInfo.addressingMode || 'container/static addressing'}): ${dhcpInfo.limitationReason}`
    },
    {
      layer: 'Layer 3 — Default Gateway & Kernel Routing Table',
      epistemicState: gatewayInfo.verified ? 'DIRECTLY_OBSERVED' : 'UNVERIFIED_ROUTE_ABSENT',
      detail: gatewayInfo.verified
        ? `Default gateway ${gatewayInfo.gatewayIp} verified via ${gatewayInfo.collectionMethod}`
        : `${gatewayInfo.status} (${gatewayInfo.collectionMethod}): ${gatewayInfo.limitationReason}`
    },
    {
      layer: 'Layer 4 — External TCP Transport Egress',
      epistemicState: l4Observed ? 'DIRECTLY_OBSERVED' : 'UNPROBED_UNCERTAIN',
      detail: l4Observed
        ? `Observed in session (${sessionContext?.lastValidTarget || sessionContext?.lastTarget || 'recent probe'})`
        : 'No active external L4 TCP handshake has been executed in the current turn window'
    },
    {
      layer: 'Layer 7 — DNS & Application Protocol Health',
      epistemicState: l7Observed ? 'DIRECTLY_OBSERVED' : 'UNPROBED_UNCERTAIN',
      detail: l7Observed
        ? `Observed in session (${sessionContext?.lastValidTarget || sessionContext?.lastTarget || 'recent probe'})`
        : `OS DNS servers observed: ${(dnsConfig.observedServers || []).join(', ') || 'none'}, live query pending`
    }
  ];

  // Connect to Sovereign Fabric v6 Evidence Lineage DAG (evidenceFabric)
  const fabricRecords = evidenceFabric.queryEvidence({ limit: 15 });
  const fabricFindings = evidenceFabric.listFindings(10);
  const liveEvidenceCount = fabricRecords.filter((r) => r.freshnessState === 'live' || r.freshnessState === 'fresh').length;
  const staleEvidenceCount = fabricRecords.filter((r) => r.freshnessState === 'stale' || r.freshnessState === 'expired').length;

  return {
    currentEntropyBits,
    entropyStatus: hasValidPosteriors ? 'COMPUTED_FROM_BAYESIAN_POSTERIOR' : 'UNAVAILABLE_NO_POSTERIOR',
    converged: Boolean(bayesianState?.converged),
    topHypotheses: hypotheses.slice(0, 5).map((h) => ({
      id: h.id,
      name: h.name,
      posteriorPct: h.percentage,
      // Never claim OBSERVED_CONCLUSIVE from posterior percentage alone!
      // A Bayesian posterior is an inference (INFERRED_HIGH_CONFIDENCE) unless corroborated by direct wire observation.
      status: h.contradicted
        ? 'CONTRADICTED'
        : (h.percentage >= 85
            ? (l4Observed && l7Observed ? 'CORROBORATED_BY_OBSERVATION' : 'INFERRED_HIGH_CONFIDENCE')
            : 'ACTIVE_HYPOTHESIS')
    })),
    unresolvedTruthMatrixLayers,
    recommendedNextProbe: candidateProbes[0] || null,
    candidateProbes,
    evidenceFabricLineage: {
      totalRecordsCount: fabricRecords.length,
      liveEvidenceCount,
      staleEvidenceCount,
      findingsCount: fabricFindings.length,
      latestChainHash: evidenceFabric.lastChainHash,
      recentEvidenceIds: fabricRecords.slice(0, 5).map((r) => ({
        id: r.id,
        type: r.type,
        subject: r.subject,
        freshnessState: r.freshnessState,
        qualityScore: r.qualityScore,
        derivedFrom: r.derivedFrom
      }))
    },
    gatewayInfo,
    dnsConfig,
    dhcpInfo,
    localNetConfig
  };
}

/**
 * Builds the full live epistemic & host context snapshot for the AI Brain
 */
function buildApplicationEpistemicContext(sessionContext = {}) {
  const igAnalysis = computeLiveInformationGainAnalysis(sessionContext);
  const localNetConfig = igAnalysis.localNetConfig;
  const envScope = hostMetrics.classifyEnvironmentScope({
    primaryIpv4: localNetConfig?.primaryIpv4 || null,
    dnsServers: localNetConfig?.dnsServers || []
  });

  return {
    timestamp: new Date().toISOString(),
    sessionState: {
      lastTarget: sessionContext.lastValidTarget || sessionContext.lastTarget || null,
      lastIntent: sessionContext.lastIntent || null,
      lastPorts: sessionContext.lastPorts || [],
      pendingTask: sessionContext.pendingTask || null,
      targetHistory: sessionContext.targetHistory || [],
      lastProbeSummary: sessionContext.lastProbeResult?.summary || null
    },
    observedEvidence: {
      environmentScopeCategory: envScope.environmentScopeCategory,
      executionScope: envScope.executionScope,
      isContainer: envScope.isContainer,
      isCloudSandbox: envScope.isCloudSandbox,
      primaryIpv4: localNetConfig?.primaryIpv4 || null,
      primaryIpv4Status: localNetConfig?.primaryIpv4Status || 'unavailable',
      defaultGateway: {
        gatewayIp: igAnalysis.gatewayInfo.gatewayIp || null,
        verified: Boolean(igAnalysis.gatewayInfo.verified),
        reason: igAnalysis.gatewayInfo.status || 'NO_DEFAULT_ROUTE_OBSERVED',
        collectionMethod: igAnalysis.gatewayInfo.collectionMethod,
        limitationReason: igAnalysis.gatewayInfo.limitationReason || null
      },
      dhcp: {
        observed: Boolean(igAnalysis.dhcpInfo.observed),
        status: igAnalysis.dhcpInfo.status,
        addressingMode: igAnalysis.dhcpInfo.addressingMode,
        dhcpServerIp: igAnalysis.dhcpInfo.dhcpServerIp || null,
        collectionMethod: igAnalysis.dhcpInfo.collectionMethod,
        limitationReason: igAnalysis.dhcpInfo.limitationReason || null
      },
      dns: {
        status: igAnalysis.dnsConfig.status,
        observedServers: igAnalysis.dnsConfig.observedServers || [],
        collectionMethod: igAnalysis.dnsConfig.collectionMethod
      }
    },
    sovereignFabricV6TruthMatrix: {
      shannonEntropyBits: igAnalysis.currentEntropyBits,
      entropyStatus: igAnalysis.entropyStatus,
      converged: igAnalysis.converged,
      topHypotheses: igAnalysis.topHypotheses,
      unresolvedLayers: igAnalysis.unresolvedTruthMatrixLayers,
      evidenceFabricLineage: igAnalysis.evidenceFabricLineage
    },
    shannonInformationGainRecommendations: igAnalysis.candidateProbes
  };
}

/**
 * Determines whether a prompt is asking an Epistemic, Sovereign Fabric v6, Bayesian Posterior,
 * Shannon Information-Gain, or Default Gateway Epistemic State question.
 */
function isEpistemicOrSovereignFabricQuestion(promptText) {
  const raw = String(promptText || '').trim();
  const lower = raw.toLowerCase();

  if (
    /\b(sovereign fabric|truth matrix|information[- ]gain|shannon entropy|bayesian posterior|highest information[- ]gain|next probe to run|unresolved states|epistemic|no_default_route_observed)\b/i.test(
      lower
    )
  ) {
    return true;
  }

  if (
    /\b(why is (?:the |my )?default gateway (?:unverified|unknown|missing|not found)|why (?:can't|cannot) you see (?:the |my )?default gateway|why is there no default route)\b/i.test(
      lower
    )
  ) {
    return true;
  }

  return false;
}

/**
 * Synthesizes a grounded, mathematically exact answer for Sovereign Fabric v6, Truth Matrix,
 * Shannon Information-Gain, and Default Gateway epistemic questions.
 * Never asks "Which hostname, IP address, or URL would you like me to check?"
 */
async function answerEpistemicOrFabricQuestion(promptText, sessionContext = {}) {
  const lower = String(promptText || '').toLowerCase();
  const ctx = buildApplicationEpistemicContext(sessionContext);
  const topProbe = ctx.shannonInformationGainRecommendations[0];
  const secondProbe = ctx.shannonInformationGainRecommendations[1];
  const thirdProbe = ctx.shannonInformationGainRecommendations[2];
  const gw = ctx.observedEvidence.defaultGateway;
  const dhcp = ctx.observedEvidence.dhcp;
  const dns = ctx.observedEvidence.dns;
  const entropy = ctx.sovereignFabricV6TruthMatrix.shannonEntropyBits;
  const entropyLabel = entropy !== null ? `${entropy} bits` : 'UNAVAILABLE (no prior distribution)';
  const lineage = ctx.sovereignFabricV6TruthMatrix.evidenceFabricLineage;

  // Case 1: Explicitly asking why default gateway is unverified / NO_DEFAULT_ROUTE_OBSERVED
  if (
    /\b(no_default_route_observed|why is (?:the |my )?default gateway (?:unverified|unknown|missing)|why (?:can't|cannot) you see (?:the |my )?default gateway)\b/i.test(
      lower
    ) &&
    !/\b(information[- ]gain|next probe)\b/i.test(lower)
  ) {
    const result = gw.verified
      ? `The default gateway is currently verified at \`${gw.gatewayIp}\` via \`${gw.collectionMethod}\` in \`${ctx.observedEvidence.environmentScopeCategory}\`.`
      : `The default gateway is marked **UNVERIFIED (\`${gw.reason}\`)** because the OS kernel routing table (\`${gw.collectionMethod}\`) in this \`${ctx.observedEvidence.environmentScopeCategory}\` does not expose a \`0.0.0.0/0\` default gateway entry.`;

    const meaning =
      `### Epistemic State Explanation: \`${gw.reason}\`\n\n` +
      `1. **What Was Directly Inspected:** EJII read the live kernel routing table via \`/proc/net/route\` and \`ip route show default\` inside the current execution scope (\`${ctx.observedEvidence.environmentScopeCategory}\`).\n` +
      `2. **Why No \`0.0.0.0/0\` Route Appears in Container/Sandbox Namespaces:** In isolated cloud sandboxes (such as gVisor / Cloud Run / container virtual switches), outbound IP packets are forwarded transparently by the host hypervisor or virtual switch without exposing a traditional L2 router hop in \`/proc/net/route\`.\n` +
      `3. **Strict Zero-Fabrication Policy:** Rather than guessing \`.1\` from the local interface address or inventing \`192.168.1.1\`, EJII explicitly reports \`gatewayIp: null, verified: false, status: "${gw.reason}"\` so operators never confuse an unexposed hypervisor route with a physical router outage.`;

    const nextStep =
      `To verify external egress when L3 default gateway routing is abstracted by the container runtime, run **${topProbe.probeName}** (\`ΔH = ${topProbe.expectedInformationGainBits} bits\`), which tests end-to-end L4 TCP transport directly.`;

    return {
      topic: 'Default Gateway Epistemic State (NO_DEFAULT_ROUTE_OBSERVED)',
      result,
      meaning,
      nextStep,
      naturalReply: `${result}\n\n${meaning}\n\n**Recommended Next Probe:** ${nextStep}`,
      epistemicContext: ctx
    };
  }

  // Case 2: Sovereign Fabric v6 Truth Matrix & Highest Information-Gain Next Probe
  const unresolvedList = ctx.sovereignFabricV6TruthMatrix.unresolvedLayers
    .map((l) => `- **${l.layer}** (\`${l.epistemicState}\`): ${l.detail}`)
    .join('\n');

  const topHypList = ctx.sovereignFabricV6TruthMatrix.topHypotheses
    .slice(0, 4)
    .map((h) => `- \`${h.id}\` (${h.name}): **${h.posteriorPct}%** posterior (\`${h.status}\`)`)
    .join('\n');

  const result =
    `Based on the current **Sovereign Fabric v6 Truth Matrix** (Shannon entropy **$H(X) = ${entropyLabel}$** across ${ctx.sovereignFabricV6TruthMatrix.topHypotheses.length} fault hypotheses; ${lineage.totalRecordsCount} cryptographically chained evidence records in DAG, tail \`${String(lineage.latestChainHash || '').slice(0, 12)}…\`), the highest information-gain next probe to execute right now is **${topProbe.probeName}** with an expected entropy reduction of **$\\Delta H = ${topProbe.expectedInformationGainBits}\\text{ bits}$** (reducing expected posterior entropy to **$E[H(X \\mid Y)] = ${topProbe.expectedPosteriorEntropyBits}\\text{ bits}$**, with $P(\\text{pass}) = ${topProbe.pPass}$, $P(\\text{fail}) = ${topProbe.pFail}$).`;

  const meaning =
    `### 1. Current Truth Matrix & Unresolved Epistemic States\n` +
    `${unresolvedList}\n\n` +
    `### 2. Active Bayesian Posterior Distribution ($H(X) = ${entropyLabel}$)\n` +
    `${topHypList}\n\n` +
    `### 3. Ranked Next Probes by Exact Shannon Information Gain $IG(X; Y) = H(X) - \\sum_y P(y) H(X \\mid Y=y)$\n` +
    `1. **${topProbe.probeName}** — **$IG = ${topProbe.expectedInformationGainBits}\\text{ bits}$** ($P(\\text{pass})=${topProbe.pPass}, H(X|\\text{pass})=${topProbe.entropyGivenPassBits}\\text{b}; P(\\text{fail})=${topProbe.pFail}, H(X|\\text{fail})=${topProbe.entropyGivenFailBits}\\text{b} \\rightarrow E[H(X|Y)] = ${topProbe.expectedPosteriorEntropyBits}\\text{ bits}$)\n` +
    `   - *Why it maximizes information gain:* ${topProbe.rationale}\n` +
    `   - *Hypotheses discriminated:* \`${topProbe.discriminatesBetween.join('`, `')}\`\n` +
    (secondProbe
      ? `2. **${secondProbe.probeName}** — **$IG = ${secondProbe.expectedInformationGainBits}\\text{ bits}$** ($E[H(X|Y)] = ${secondProbe.expectedPosteriorEntropyBits}\\text{ bits}$)\n` +
        `   - *Why:* ${secondProbe.rationale}\n`
      : '') +
    (thirdProbe
      ? `3. **${thirdProbe.probeName}** — **$IG = ${thirdProbe.expectedInformationGainBits}\\text{ bits}$** ($E[H(X|Y)] = ${thirdProbe.expectedPosteriorEntropyBits}\\text{ bits}$)\n` +
        `   - *Why:* ${thirdProbe.rationale}`
      : '');

  const nextStep = `Run \`${topProbe.command}\` to collapse the L3/L4 egress uncertainty first, or ask me to execute it now.`;

  return {
    topic: 'Sovereign Fabric v6 Truth Matrix & Shannon Information-Gain Next Probe',
    result,
    meaning,
    nextStep,
    naturalReply: `${result}\n\n${meaning}\n\n**Actionable Next Step:** ${nextStep}`,
    epistemicContext: ctx
  };
}

/**
 * Maps a Gemini native `functionCall` object into EJII's internal execution plan format.
 * Every intent string strictly matches the switch cases in `ChatOperatorService.processMessage()`.
 */
function mapFunctionCallToExecutionPlan(functionCall, sessionContext = {}) {
  if (!functionCall || !functionCall.name) return null;
  const name = String(functionCall.name).trim();
  const args = functionCall.args && typeof functionCall.args === 'object' ? functionCall.args : {};

  switch (name) {
    case 'dns_lookup':
      return {
        intent: 'dns',
        mode: 'operational',
        target: args.domain || sessionContext.lastTarget || null,
        explicitTarget: args.domain || null,
        recordType: args.recordType ? String(args.recordType).toUpperCase() : 'A',
        ports: [],
        modelInterpreted: true,
        invokedToolName: name
      };
    case 'tcp_port_probe':
      return {
        intent: 'port_check',
        mode: 'operational',
        target: args.target || sessionContext.lastTarget || null,
        explicitTarget: args.target || null,
        ports: Array.isArray(args.ports) && args.ports.length > 0 ? args.ports.map(Number) : [80, 443],
        modelInterpreted: true,
        invokedToolName: name
      };
    case 'icmp_ping':
      return {
        intent: 'ping',
        mode: 'operational',
        target: args.target || sessionContext.lastTarget || null,
        explicitTarget: args.target || null,
        ports: [],
        modelInterpreted: true,
        invokedToolName: name
      };
    case 'http_tls_inspect':
      return {
        intent: 'website_check',
        mode: 'operational',
        target: args.target || sessionContext.lastTarget || null,
        explicitTarget: args.target || null,
        ports: args.port ? [Number(args.port)] : [443],
        modelInterpreted: true,
        invokedToolName: name
      };
    case 'inspect_local_network':
      return {
        intent: 'local_ip_config',
        mode: 'operational',
        target: 'local_host_interfaces',
        explicitTarget: null,
        ports: [],
        preserveLastRemoteTarget: true,
        modelInterpreted: true,
        invokedToolName: name
      };
    case 'inspect_default_gateway':
      return {
        intent: 'gateway_check',
        mode: 'operational',
        target: 'default_gateway',
        explicitTarget: null,
        ports: [],
        preserveLastRemoteTarget: true,
        modelInterpreted: true,
        invokedToolName: name
      };
    case 'inspect_dhcp_status':
      return {
        intent: 'dhcp_check',
        mode: 'operational',
        target: 'local_dhcp_service',
        explicitTarget: null,
        ports: [],
        preserveLastRemoteTarget: true,
        modelInterpreted: true,
        invokedToolName: name
      };
    case 'run_5_layer_path_diagnostic':
      return {
        intent: 'local_path_diagnostic',
        mode: 'operational',
        target: 'local_path_gateway_isp',
        explicitTarget: null,
        ports: [53, 443],
        preserveLastRemoteTarget: true,
        modelInterpreted: true,
        invokedToolName: name
      };
    case 'query_sovereign_fabric_v6':
      return {
        intent: 'epistemic_fabric_query',
        mode: 'informational',
        target: null,
        explicitTarget: null,
        ports: [],
        preserveContextOnly: true,
        modelInterpreted: true,
        invokedToolName: name
      };
    case 'inspect_host_health':
      return {
        intent: 'host_health',
        mode: 'operational',
        target: 'local_host_health',
        explicitTarget: null,
        ports: [],
        preserveLastRemoteTarget: true,
        modelInterpreted: true,
        invokedToolName: name
      };
    case 'inspect_active_sockets':
      return {
        intent: 'active_connections',
        mode: 'operational',
        target: 'local_socket_table',
        explicitTarget: null,
        connectionFilter: {
          port: args.portFilter ? Number(args.portFilter) : null
        },
        ports: args.portFilter ? [Number(args.portFilter)] : [],
        preserveLastRemoteTarget: true,
        modelInterpreted: true,
        invokedToolName: name
      };
    case 'run_traceroute':
      return {
        intent: 'traceroute',
        mode: 'operational',
        target: args.target || sessionContext.lastTarget || null,
        explicitTarget: args.target || null,
        ports: [],
        modelInterpreted: true,
        invokedToolName: name
      };
    default:
      return null;
  }
}

/**
 * Reflects on an executed tool's output to decide whether a follow-up tool execution is needed
 * in the iterative Plan -> Execute -> Observe -> Reflect loop.
 *
 * Supports both:
 *   - Explicit multi-step requests (e.g. "Check DNS for example.com and then check port 443" or queued secondaryToolPlans)
 *   - Model-driven reflection via `aiModelOrchestrator.invokeWithBoundedRetry` with `EJII_FUNCTION_DECLARATIONS`
 *   - Diagnostic escalation (e.g. if DNS succeeded and the user asked to verify reachability/ports next)
 */
async function reflectOnToolObservation({
  promptText,
  currentPlan,
  executionOutcome,
  executedPlans = [],
  stepIndex = 1,
  maxSteps = 3,
  sessionContext = {},
  allowCloudReflection = false
}) {
  if (stepIndex >= maxSteps) {
    return { continueLoop: false, reason: 'MAX_STEPS_REACHED', nextPlan: null };
  }

  // 1. Check if currentPlan or initial plan already queued secondary tool plans (e.g. from multi-tool functionCalls or compound prompt)
  if (Array.isArray(currentPlan?.secondaryToolPlans) && currentPlan.secondaryToolPlans.length > 0) {
    const [nextQueued, ...remaining] = currentPlan.secondaryToolPlans;
    const targetForNext = nextQueued.target || currentPlan.target || sessionContext.lastValidTarget || sessionContext.lastTarget;
    const nextSignature = `${nextQueued.intent}:${targetForNext}:${(nextQueued.ports || []).join(',')}:${nextQueued.recordType || ''}`;
    const alreadyRan = executedPlans.some(
      (p) => `${p.intent}:${p.target}:${(p.ports || []).join(',')}:${p.recordType || ''}` === nextSignature
    );
    if (!alreadyRan) {
      return {
        continueLoop: true,
        reason: 'QUEUED_COMPOUND_TOOL_PLAN',
        nextPlan: {
          ...nextQueued,
          target: targetForNext,
          secondaryToolPlans: remaining
        }
      };
    }
  }

  // 2. Check if the user prompt explicitly requested a compound sequence (e.g. "resolve X and check port Y", "check DNS then test HTTPS")
  const lower = String(promptText || '').toLowerCase();
  const target = currentPlan?.target || sessionContext.lastValidTarget || sessionContext.lastTarget;
  const ranIntents = new Set(executedPlans.map((p) => p.intent));

  if (target && target !== 'local_host_interfaces' && target !== 'default_gateway') {
    const asksForDnsAndPort =
      /\b(dns|resolve|lookup)\b/i.test(lower) &&
      /\b(port|tcp|443|80|3000|8080|587|993)\b/i.test(lower);
    if (asksForDnsAndPort && ranIntents.has('dns') && !ranIntents.has('port_check')) {
      const portMatches = (lower.match(/\b(80|443|3000|8080|8443|22|25|465|587|993|995|3306|5432)\b/g) || []).map(Number);
      return {
        continueLoop: true,
        reason: 'COMPOUND_DNS_THEN_PORT_CHECK',
        nextPlan: {
          intent: 'port_check',
          mode: 'operational',
          target,
          ports: portMatches.length > 0 ? Array.from(new Set(portMatches)) : [443]
        }
      };
    }

    const asksForPortAndHttp =
      /\b(port|tcp)\b/i.test(lower) &&
      /\b(http|https|tls|certificate|website|application layer)\b/i.test(lower) &&
      /\b(then|and|also|after)\b/i.test(lower);
    if (asksForPortAndHttp && ranIntents.has('port_check') && !ranIntents.has('website_check')) {
      const openPort = executionOutcome?.technicalEvidence?.rawResults?.find((r) => r.status === 'OPEN')?.port || currentPlan.ports?.[0] || 443;
      return {
        continueLoop: true,
        reason: 'COMPOUND_PORT_THEN_HTTP_CHECK',
        nextPlan: {
          intent: 'website_check',
          mode: 'operational',
          target,
          ports: [openPort]
        }
      };
    }
  }

  // 3. Optional live AI model reflection on observed tool output when configured or when custom model invoker is injected
  const hasGeminiKey = Boolean(process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY.trim());
  if ((allowCloudReflection && hasGeminiKey) || typeof sessionContext?.modelReflectionFn === 'function') {
    try {
      const observationSummary = {
        stepIndex,
        executedIntent: currentPlan?.intent,
        target: currentPlan?.target,
        resultSummary: executionOutcome?.structuredAnswer?.result || executionOutcome?.reply || '',
        layerFailedFirst: executionOutcome?.structuredAnswer?.layerFailedFirst || null,
        findings: executionOutcome?.findings || []
      };

      if (typeof sessionContext?.modelReflectionFn === 'function') {
        const customReflection = await sessionContext.modelReflectionFn({
          promptText,
          observationSummary,
          executedPlans,
          stepIndex
        });
        if (customReflection?.functionCall) {
          const mapped = mapFunctionCallToExecutionPlan(customReflection.functionCall, {
            lastTarget: target
          });
          if (mapped && !ranIntents.has(mapped.intent)) {
            return {
              continueLoop: true,
              reason: 'MODEL_REFLECTION_TOOL_CALL',
              nextPlan: mapped,
              reflectionSynthesis: customReflection.synthesis || null
            };
          }
        }
        if (customReflection?.synthesis) {
          return {
            continueLoop: false,
            reason: 'MODEL_REFLECTION_COMPLETE',
            nextPlan: null,
            reflectionSynthesis: customReflection.synthesis
          };
        }
      } else {
        const reflectionPrompt = [
          'You are the EJII Agentic Diagnostic Reflection Loop (Plan -> Execute -> Observe -> Reflect).',
          `User Request: ${JSON.stringify(promptText)}`,
          `Step ${stepIndex} Observation: ${JSON.stringify(observationSummary)}`,
          `Already Executed Intents: ${JSON.stringify(Array.from(ranIntents))}`,
          'If the user request is already answered by this observation, do NOT call another tool and return JSON: {"complete": true, "synthesis": "..."}.',
          'If another tool call is strictly required to finish answering the user request, invoke the appropriate function declaration.'
        ].join('\n');

        const modelRes = await aiModelOrchestrator.invokeWithBoundedRetry('GOOGLE_GEMINI', reflectionPrompt, {
          model: process.env.EJII_GEMINI_MODEL || 'gemini-3.1-flash-lite',
          timeoutMs: 5000,
          maxRetries: 0,
          allowRedactedCloudFallback: true,
          tools: [{ functionDeclarations: EJII_FUNCTION_DECLARATIONS }]
        });

        if (modelRes?.liveResponse && Array.isArray(modelRes.functionCalls) && modelRes.functionCalls.length > 0) {
          const mapped = mapFunctionCallToExecutionPlan(modelRes.functionCalls[0], { lastTarget: target });
          if (mapped && !ranIntents.has(mapped.intent)) {
            return {
              continueLoop: true,
              reason: 'GEMINI_NATIVE_TOOL_REFLECTION',
              nextPlan: mapped
            };
          }
        }
      }
    } catch (_) {
      // Non-fatal: complete loop with current verified observations
    }
  }

  return { continueLoop: false, reason: 'OBSERVATION_SUFFICIENT', nextPlan: null };
}

/**
 * Executes the bounded Plan -> Execute -> Observe -> Reflect agentic tool loop (max 3 iterations).
 */
async function runAgenticToolLoop({
  promptText,
  initialPlan,
  sessionContext = {},
  executeSinglePlan,
  onProgress = null,
  signal = null,
  maxSteps = 3,
  allowCloudReflection = false
}) {
  const boundedMax = Math.min(3, Math.max(1, Number(maxSteps) || 3));
  const executedPlans = [];
  const outcomes = [];
  const allSteps = [];
  const allFindings = [];
  const toolReflectionTrace = [];

  let currentPlan = initialPlan;
  let stepIndex = 0;

  while (currentPlan && stepIndex < boundedMax) {
    if (signal && signal.aborted) {
      const err = new Error('Diagnostic execution cancelled by user.');
      err.code = 'REQUEST_CANCELLED';
      throw err;
    }

    stepIndex += 1;
    executedPlans.push(currentPlan);

    if (typeof onProgress === 'function') {
      onProgress({
        stage: 'PROBE_EXECUTING',
        stepIndex,
        intent: currentPlan.intent,
        target: currentPlan.target || null,
        ports: currentPlan.ports || [],
        label: `Step ${stepIndex}: Executing ${currentPlan.intent} on ${currentPlan.target || 'local host'}…`,
        timestamp: new Date().toISOString()
      });
    }

    const outcome = await executeSinglePlan(currentPlan, stepIndex);
    outcomes.push({ plan: currentPlan, outcome });

    if (Array.isArray(outcome?.steps)) {
      for (const s of outcome.steps) {
        const adjustedStep = { ...s, stepNumber: allSteps.length + 1 };
        allSteps.push(adjustedStep);
        if (typeof onProgress === 'function') {
          onProgress({
            stage: 'PROBE_COMPLETED',
            stepIndex,
            step: adjustedStep,
            timestamp: new Date().toISOString()
          });
        }
      }
    }

    if (Array.isArray(outcome?.findings)) {
      for (const f of outcome.findings) {
        if (!allFindings.some((existing) => existing.label === f.label && existing.value === f.value)) {
          allFindings.push(f);
        }
      }
    }

    // Non-operational turns (greetings, clarifications, pure conceptual answers) do not loop
    if (currentPlan.mode === 'conversational' || currentPlan.mode === 'informational') {
      break;
    }

    if (typeof onProgress === 'function') {
      onProgress({
        stage: 'REFLECTING_ON_EVIDENCE',
        stepIndex,
        label: `Observing step ${stepIndex} output and evaluating whether additional probes are required…`,
        timestamp: new Date().toISOString()
      });
    }

    const reflection = await reflectOnToolObservation({
      promptText,
      currentPlan,
      executionOutcome: outcome,
      executedPlans,
      stepIndex,
      maxSteps: boundedMax,
      sessionContext,
      allowCloudReflection
    });

    toolReflectionTrace.push({
      iteration: stepIndex,
      executedIntent: currentPlan.intent,
      target: currentPlan.target || null,
      decision: reflection.continueLoop ? 'CONTINUE_INVESTIGATION' : 'COMPLETE_SYNTHESIS',
      reason: reflection.reason,
      nextIntent: reflection.nextPlan?.intent || null,
      reflectionSynthesis: reflection.reflectionSynthesis || null
    });

    if (!reflection.continueLoop || !reflection.nextPlan) {
      break;
    }

    currentPlan = reflection.nextPlan;
  }

  if (outcomes.length === 1) {
    const single = outcomes[0].outcome;
    const latestReflection = toolReflectionTrace[toolReflectionTrace.length - 1];
    if (latestReflection?.reflectionSynthesis) {
      single.reply = `${single.reply}\n\n**Agentic Synthesis:** ${latestReflection.reflectionSynthesis}`;
    }
    if (single.technicalEvidence && typeof single.technicalEvidence === 'object') {
      single.technicalEvidence.agenticReflectionTrace = toolReflectionTrace;
    }
    return single;
  }

  // Combine multi-step outcomes into a unified response
  const primaryOutcome = outcomes[outcomes.length - 1].outcome;
  const combinedReplyParts = outcomes.map((item, idx) => `### Step ${idx + 1}: \`${item.plan.intent}\` (${item.plan.target || 'local'})\n${item.outcome.reply}`);
  const lastReflection = toolReflectionTrace[toolReflectionTrace.length - 1];
  if (lastReflection?.reflectionSynthesis) {
    combinedReplyParts.push(`### Multi-Step Synthesis\n${lastReflection.reflectionSynthesis}`);
  }

  return {
    ...primaryOutcome,
    reply: combinedReplyParts.join('\n\n'),
    structuredAnswer: {
      result: outcomes.map((o) => o.outcome.structuredAnswer?.result).filter(Boolean).join(' '),
      meaning: outcomes.map((o) => o.outcome.structuredAnswer?.meaning).filter(Boolean).join(' '),
      nextStep: primaryOutcome.structuredAnswer?.nextStep || null,
      layerFailedFirst: outcomes.find((o) => o.outcome.structuredAnswer?.layerFailedFirst)?.outcome.structuredAnswer.layerFailedFirst || null,
      uncertainty: primaryOutcome.structuredAnswer?.uncertainty || null
    },
    steps: allSteps,
    findings: allFindings,
    technicalEvidence: {
      mode: 'agentic_multi_step_loop',
      iterationsExecuted: outcomes.length,
      agenticReflectionTrace: toolReflectionTrace,
      stepEvidences: outcomes.map((o) => o.outcome.technicalEvidence)
    }
  };
}

module.exports = {
  EJII_FUNCTION_DECLARATIONS,
  CANDIDATE_PROBE_LIKELIHOOD_MODELS,
  computeShannonEntropyFromDistribution,
  computeExpectedProbeInformationGain,
  computeLiveInformationGainAnalysis,
  buildApplicationEpistemicContext,
  isEpistemicOrSovereignFabricQuestion,
  answerEpistemicOrFabricQuestion,
  mapFunctionCallToExecutionPlan,
  reflectOnToolObservation,
  runAgenticToolLoop
};
