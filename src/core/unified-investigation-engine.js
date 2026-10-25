/**
 * EJII Unified Cross-Section Guided Investigation & Post-Fix Verification Engine
 * Connects all 5 EJII sections (Topology, Wireshark Sniffer, Ultra IP Scanner,
 * PC Automation Scripts, and Core Host Diagnostics + AI Brain) into a single
 * evidence-driven troubleshooting workflow.
 */

const crypto = require('crypto');
const { aiBrain, isSafeNetworkTarget } = require('./ai-brain');
const { ragKnowledgeEngine } = require('./rag-knowledge-engine');
const { aiModelOrchestrator } = require('./ai-model-orchestrator');
const { processSocketCorrelator } = require('../network/process-socket-correlator');
const { packetStreamer, troubleshootEndpoint } = require('../network/packet-streaming/packet-streamer');
const { topologyEngine } = require('../network/topology/topology-engine');
const { hostDiagnosticsEngine } = require('../systems/diagnostics/host-diagnostics-engine');
const { brainPersistenceRepository } = require('../db/brain-persistence-repository');

class UnifiedInvestigationEngine {
  constructor() {
    this.investigations = new Map(); // investigationId -> full workflow record
    this.maxInvestigations = 50;
  }

  /**
   * Executes a complete, cross-section guided investigation for an application,
   * process name, hostname, or target IP:port.
   */
  async runGuidedInvestigation({
    symptom = 'Application or service connectivity failure',
    processQuery = '',
    targetHost = '',
    targetPort = 443,
    initiatedBy = 'operator'
  } = {}) {
    const investigationId = `INV-${Date.now()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const startedAt = new Date().toISOString();
    const stages = [];

    // STAGE 1: Application & Process Endpoint Discovery (Correlating OS Sockets + Wire)
    let discoveredEndpoints = [];
    let resolvedTargetHost = targetHost ? String(targetHost).trim() : '';
    let resolvedTargetPort = Number(targetPort) || 443;
    let matchedProcess = null;

    try {
      const allEndpoints = await processSocketCorrelator.getCorrelatedEndpoints({
        processFilter: processQuery || '',
        externalOnly: false
      });
      discoveredEndpoints = Array.isArray(allEndpoints) ? allEndpoints : (allEndpoints?.endpoints || []);

      if (processQuery && discoveredEndpoints.length > 0) {
        const q = processQuery.toLowerCase();
        // F-01: Strict process match; NEVER fallback to arbitrary discoveredEndpoints[0]
        matchedProcess = discoveredEndpoints.find(
          (e) =>
            String(e.processName || '').toLowerCase().includes(q) ||
            String(e.pid || '') === q ||
            String(e.domain || '').toLowerCase().includes(q)
        ) || null;

        if (matchedProcess && !resolvedTargetHost && matchedProcess.remoteIp && matchedProcess.remoteIp !== '0.0.0.0') {
          resolvedTargetHost = matchedProcess.remoteIp;
          resolvedTargetPort = Number(matchedProcess.remotePort) || resolvedTargetPort;
        }
      }

      // F-04: Process-socket correlation validation
      const processFound = Boolean(matchedProcess);
      const stage1Status = processQuery
        ? (processFound ? 'COMPLETED' : (resolvedTargetHost ? 'PARTIAL' : 'ENDPOINT_NOT_FOUND_FOR_PROCESS'))
        : (resolvedTargetHost ? 'COMPLETED' : 'PARTIAL');

      let stage1Summary = '';
      if (processQuery && !processFound) {
        if (resolvedTargetHost) {
          stage1Summary = `Scanned ${discoveredEndpoints.length} OS sockets; no socket matched process "${processQuery}". Proceeding with explicitly specified target ${resolvedTargetHost}:${resolvedTargetPort}.`;
        } else {
          stage1Summary = `ENDPOINT_NOT_FOUND_FOR_PROCESS: No active network sockets or endpoints found matching process query "${processQuery}".`;
        }
      } else if (matchedProcess) {
        stage1Summary = `Discovered process ${matchedProcess.processName} (PID ${matchedProcess.pid}) communicating with ${matchedProcess.remoteIp || '0.0.0.0'}:${matchedProcess.remotePort || resolvedTargetPort} (${matchedProcess.state || 'ACTIVE'}).`;
      } else if (resolvedTargetHost) {
        stage1Summary = `Targeting explicitly supplied endpoint ${resolvedTargetHost}:${resolvedTargetPort} (${discoveredEndpoints.length} active host sockets scanned).`;
      } else {
        stage1Summary = `Scanned ${discoveredEndpoints.length} OS sockets; no specific remote endpoint provided.`;
      }

      stages.push({
        stageNumber: 1,
        stageId: 'ENDPOINT_DISCOVERY',
        section: 'Section 2: App Server & Port Finder',
        status: stage1Status,
        summary: stage1Summary,
        evidence: {
          matchedProcess,
          processQuery: processQuery || null,
          totalOsSocketsScanned: discoveredEndpoints.length,
          sampleEndpoints: discoveredEndpoints.slice(0, 5)
        }
      });

      // F-01 & F-04: If process query was specified without targetHost and no matching process socket exists, do not proceed
      if (processQuery && !processFound && !targetHost) {
        const record = {
          investigationId,
          symptom,
          processQuery,
          targetHost: null,
          targetPort: null,
          initiatedBy,
          startedAt,
          completedAt: new Date().toISOString(),
          overallVerdict: 'ENDPOINT_NOT_FOUND_FOR_PROCESS',
          confidence: 100,
          uncertaintyWarning: false,
          stages,
          diagnosis: null,
          secondOpinion: null,
          recommendedActions: [
            {
              actionType: 'START_PROCESS_OR_VERIFY_NAME',
              label: `Verify process "${processQuery}" is running with active network bindings`,
              targetView: 'scripts'
            }
          ],
          reverificationHistory: []
        };
        this.investigations.set(investigationId, record);
        return record;
      }
    } catch (err) {
      stages.push({
        stageNumber: 1,
        stageId: 'ENDPOINT_DISCOVERY',
        section: 'Section 2: App Server & Port Finder',
        status: 'ERROR',
        summary: `OS socket discovery encountered error: ${err.message}`,
        evidence: {}
      });
    }

    if (!resolvedTargetHost) {
      const topo = topologyEngine.getTopology();
      const gwNode = (topo.nodes || []).find((n) => n.id === 'NODE-GW-01');
      resolvedTargetHost = gwNode?.hostname_or_ip || '127.0.0.1';
      resolvedTargetPort = 80;
    }

    // Security SSRF Gate
    if (!isSafeNetworkTarget(resolvedTargetHost)) {
      throw new Error(`SECURITY_VIOLATION: Investigation target "${resolvedTargetHost}" rejected by SSRF defense policy.`);
    }

    // STAGE 2: Multi-Protocol Wire & Endpoint Probing (DNS, L3/L4 TCP, L6 TLS, Wire Packets)
    let endpointDiag = null;
    try {
      endpointDiag = await troubleshootEndpoint(resolvedTargetHost, resolvedTargetPort);
      stages.push({
        stageNumber: 2,
        stageId: 'WIRE_AND_PROTOCOL_EVIDENCE',
        section: 'Section 2 & 3: Wireshark Sniffer & Protocol Drivers',
        status: 'COMPLETED',
        summary: endpointDiag.verdict || `Completed 5-stage wire probe against ${resolvedTargetHost}:${resolvedTargetPort}.`,
        evidence: {
          target: resolvedTargetHost,
          port: resolvedTargetPort,
          stages: endpointDiag.stages || [],
          healthScore: endpointDiag.healthScore
        }
      });
    } catch (err) {
      stages.push({
        stageNumber: 2,
        stageId: 'WIRE_AND_PROTOCOL_EVIDENCE',
        section: 'Section 2 & 3: Wireshark Sniffer & Protocol Drivers',
        status: 'ERROR',
        summary: `Wire probe failed: ${err.message}`,
        evidence: {}
      });
    }

    // STAGE 3: Topology Path & Local Workstation Health Correlation (Section 1 & Section 5)
    const topo = topologyEngine.getTopology();
    const matchedNode = (topo.nodes || []).find(
      (n) => n.hostname_or_ip === resolvedTargetHost || (n.name || '').includes(resolvedTargetHost)
    ) || null;
    const hostTrends = hostDiagnosticsEngine.getTrendAnalysis();
    // F-02: Treat null or provisional warm baseline as UNKNOWN (Zero Silent Healthy Fallbacks)
    const snapshot = aiBrain.lastHostHealthSnapshot;
    const isProvisional = snapshot?.isProvisional || snapshot?.overallStatus === 'INITIALIZING';
    const hostContext = (!snapshot || isProvisional) ? {
      overallStatus: 'UNKNOWN',
      localHostSaturated: null,
      localNicDegraded: null,
      isProvisional: Boolean(isProvisional)
    } : snapshot;

    stages.push({
      stageNumber: 3,
      stageId: 'TOPOLOGY_AND_HOST_CORRELATION',
      section: 'Section 1 & 5: NOC Topology & Host Diagnostics',
      status: 'COMPLETED',
      summary: `Workstation status: ${hostContext.overallStatus} (localHostSaturated=${Boolean(hostContext.localHostSaturated)}). Topology node match: ${matchedNode ? matchedNode.name : 'External / Unmapped Endpoint'}.`,
      evidence: {
        matchedTopologyNode: matchedNode,
        hostContext,
        telemetryTrends: hostTrends?.trend || null
      }
    });

    // STAGE 4: Bayesian Root-Cause Assessment + RAG Knowledge & Second-Opinion Verification
    const tcpStage = (endpointDiag?.stages || []).find((s) => s.stage === 'L3_L4_TCP_CONNECT');
    const dnsStage = (endpointDiag?.stages || []).find((s) => s.stage === 'L7_DNS_RESOLUTION');
    const tlsStage = (endpointDiag?.stages || []).find((s) => s.stage === 'L6_TLS_HANDSHAKE');

    const tcpOk = tcpStage?.status === 'PASS' || tcpStage?.status === 'HEALTHY';
    // F-03: Strict positive check for DNS pass; missing or unobserved stage is NOT pass
    const dnsOk = dnsStage?.status === 'PASS' || dnsStage?.status === 'SUCCESS' || dnsStage?.status === 'HEALTHY';
    const observedRst = /ECONNREFUSED|RST/i.test(JSON.stringify(tcpStage || {}));

    let incidentType = 'NORMAL_OPERATION';
    if (!dnsOk) incidentType = 'DNS_RESOLUTION_FAILURE';
    else if (observedRst) incidentType = 'TCP_RST_REJECT';
    else if (!tcpOk) incidentType = 'TCP_SYN_TIMEOUT';
    else if (tlsStage && tlsStage.status === 'FAIL') incidentType = 'TLS_HANDSHAKE_FAILURE';

    const diagnosis = aiBrain.diagnoseIncident({
      incidentType,
      destIp: resolvedTargetHost,
      destPort: resolvedTargetPort,
      tcpRstObserved: observedRst,
      targetPortReachable: tcpOk,
      dnsResolved: dnsOk,
      hostContext
    });

    const secondOpinion = await aiModelOrchestrator.verifyHighImpactDiagnosis({
      bayesianEvaluation: diagnosis,
      telemetryContext: {
        symptom,
        incidentType,
        target: resolvedTargetHost,
        port: resolvedTargetPort,
        errorCode: observedRst ? 'ECONNREFUSED' : (!tcpOk ? 'ETIMEDOUT' : null)
      },
      ragEngine: ragKnowledgeEngine
    });

    stages.push({
      stageNumber: 4,
      stageId: 'BAYESIAN_AND_RAG_ASSESSMENT',
      section: 'Central AI Brain & RAG Knowledge Engine',
      status: 'COMPLETED',
      summary: `Top Hypothesis: ${diagnosis.topHypothesis?.label || 'Nominal'} (${diagnosis.topHypothesis?.confidence || 0}% confidence). RAG Citations retrieved: ${secondOpinion.ragCitations.length}.`,
      evidence: {
        incidentType,
        topHypothesis: diagnosis.topHypothesis,
        rankedHypotheses: diagnosis.rankedHypotheses,
        secondOpinion,
        ragCitations: secondOpinion.ragCitations
      }
    });

    // STAGE 5: Actionable Cross-Section Next Steps & Safe Resolution Plan
    const recommendedActions = [
      {
        actionType: 'SCOPE_WIRESHARK_SNIFFER',
        label: `Scope Wireshark Sniffer to ${resolvedTargetHost}:${resolvedTargetPort}`,
        targetView: 'sniffer',
        filterExpression: `ip.addr == ${resolvedTargetHost} && tcp.port == ${resolvedTargetPort}`
      },
      {
        actionType: 'DEEP_HOST_PORT_AUDIT',
        label: `Run 15-Port Deep Host Inspection on ${resolvedTargetHost}`,
        targetView: 'scanner',
        targetIp: resolvedTargetHost
      }
    ];

    if (!dnsOk) {
      recommendedActions.push({
        actionType: 'RUN_SAFE_SCRIPT',
        label: 'Flush Local DNS Resolver Cache (ipconfig /flushdns)',
        targetView: 'scripts',
        scriptName: 'Flush DNS Resolver Cache & Release Renew IP.bat'
      });
    }

    stages.push({
      stageNumber: 5,
      stageId: 'SAFE_RESOLUTION_AND_VERIFICATION_PLAN',
      section: 'Section 4 & 5: Safe Remediation & Verification',
      status: 'READY',
      summary: `Prepared ${recommendedActions.length} cross-section diagnostic/remediation actions with post-action re-verification support.`,
      evidence: {
        recommendedActions
      }
    });

    const record = {
      investigationId,
      symptom,
      processQuery: processQuery || null,
      targetHost: resolvedTargetHost,
      targetPort: resolvedTargetPort,
      initiatedBy,
      startedAt,
      completedAt: new Date().toISOString(),
      overallVerdict: diagnosis.topHypothesis?.label || 'Nominal Connectivity',
      confidence: diagnosis.topHypothesis?.confidence || 100,
      uncertaintyWarning: secondOpinion.uncertaintyWarning,
      stages,
      diagnosis,
      secondOpinion,
      recommendedActions,
      reverificationHistory: []
    };

    this.investigations.set(investigationId, record);
    if (this.investigations.size > this.maxInvestigations) {
      const oldest = this.investigations.keys().next().value;
      this.investigations.delete(oldest);
    }

    try {
      if (brainPersistenceRepository) {
        brainPersistenceRepository.saveInvestigation(record);
      }
    } catch (_) {}

    return record;
  }

  /**
   * Closed-Loop Post-Remediation Re-Verification:
   * Re-tests the exact endpoint from an existing investigation after a fix is applied
   * and compares Before vs. After evidence to confirm whether the symptom disappeared.
   */
  async verifyInvestigationResolution(investigationId) {
    const existing = this.investigations.get(investigationId);
    if (!existing) {
      throw new Error(`Investigation "${investigationId}" not found.`);
    }

    const recheckDiag = await troubleshootEndpoint(existing.targetHost, existing.targetPort);
    const tcpStageAfter = (recheckDiag?.stages || []).find((s) => s.stage === 'L3_L4_TCP_CONNECT');
    const tcpStageBefore = (existing.stages[1]?.evidence?.stages || []).find((s) => s.stage === 'L3_L4_TCP_CONNECT');

    const beforeStatus = tcpStageBefore?.status || 'UNKNOWN';
    const afterStatus = tcpStageAfter?.status || 'UNKNOWN';
    const symptomResolved = afterStatus === 'PASS' || afterStatus === 'HEALTHY';

    const verificationEntry = {
      verifiedAt: new Date().toISOString(),
      targetHost: existing.targetHost,
      targetPort: existing.targetPort,
      beforeTcpStatus: beforeStatus,
      afterTcpStatus: afterStatus,
      afterHealthScore: recheckDiag.healthScore,
      symptomResolved,
      verdict: symptomResolved
        ? `VERIFIED FIXED: Endpoint ${existing.targetHost}:${existing.targetPort} responded cleanly (${afterStatus}).`
        : `SYMPTOM PERSISTS: Endpoint ${existing.targetHost}:${existing.targetPort} still reports ${afterStatus}.`
    };

    existing.reverificationHistory.push(verificationEntry);
    return {
      investigationId,
      verificationEntry,
      investigation: existing
    };
  }


  /**
   * Constructs an Authoritative Shared Investigation Context across all 5 EJII Operational Pillars.
   * Defeats L2/L3 MAC conflation by strictly distinguishing localLinkMac vs routedNextHopMac:
   *   - If target is in local subnet: macAddress is localLinkMac (L2 physical host MAC)
   *   - If target is outside local subnet: macAddress is routedNextHopMac (L2 default gateway router MAC)
   *
   * @param {string|object} targetQuery
   * @param {object} [stageResults={}]
   * @returns {object} Shared investigation context
   */
  buildSharedInvestigationContext(targetQuery, stageResults = {}) {
    const { getPhysicalNetworkInfo, isIpInSubnet } = require('../network/routing/physical-network-detector');
    const { attachEpistemicEnvelope } = require('./type-contract-validator');

    const netInfo = getPhysicalNetworkInfo();
    const localSubnet = netInfo?.subnetCidr || '192.168.31.0/24';
    const gatewayMac = netInfo?.gatewayMac || netInfo?.mac || '00:00:00:00:00:00';
    const gatewayIp = netInfo?.gatewayIp || netInfo?.defaultGateway || '192.168.31.1';

    const targetHost = typeof targetQuery === 'string' ? targetQuery : (targetQuery?.host || targetQuery?.targetHost || targetQuery?.targetIp || '127.0.0.1');
    const targetPort = typeof targetQuery === 'object' && targetQuery?.port ? Number(targetQuery.port) : 443;
    const processName = typeof targetQuery === 'object' ? targetQuery?.processName : null;
    const pid = typeof targetQuery === 'object' ? targetQuery?.pid : null;

    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(targetHost);
    const isLocal = isIp ? isIpInSubnet(targetHost, localSubnet) : false;

    let macAddress = null;
    let macType = 'UNKNOWN';
    if (isIp) {
      if (isLocal) {
        const arpMatch = (netInfo?.arpNeighbors || []).find(n => n.ip === targetHost);
        macAddress = arpMatch ? arpMatch.mac : (netInfo?.macAddress || null);
        macType = 'LOCAL_LINK_MAC';
      } else {
        macAddress = gatewayMac;
        macType = 'ROUTED_NEXT_HOP_GATEWAY_MAC';
      }
    }

    const contextId = `CTX-${Date.now()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const timestamp = new Date().toISOString();

    const sharedContext = {
      contextId,
      timestamp,
      targetHost,
      targetPort,
      targetIp: isIp ? targetHost : null,
      isLocalSubnet: isLocal,
      macAddress,
      macType,
      gatewayIp,
      gatewayMac,
      processName: processName || stageResults?.processName || null,
      pid: pid || stageResults?.pid || null,
      compositeProcessIdentity: pid ? `pid:${processName || 'proc'}:t0:${pid}` : null,
      activeViewPivots: {
        view1Topology: {
          filterNodeId: isLocal ? `NODE-HOST-${targetHost}` : 'NODE-GW-01',
          focusLayer: isLocal ? 'endpoint' : 'edge',
          highlightIp: targetHost
        },
        view2Sniffer: {
          bpfFilter: isIp ? `host ${targetHost}${targetPort ? ` and port ${targetPort}` : ''}` : `port ${targetPort}`,
          highlightHost: targetHost,
          highlightPort: targetPort
        },
        view3Scanner: {
          targetSubnet: isLocal ? localSubnet : null,
          highlightIp: targetHost,
          autoInspect: true
        },
        view4Automation: {
          recommendedScriptIds: isLocal
            ? ['clear_arp_cache', 'display_net_stats']
            : ['flush_dns_renew_ip', 'audit_tcp_ports'],
          contextTarget: targetHost
        },
        view5Diagnostics: {
          targetHost,
          targetPort,
          autoExecuteProbe: false
        }
      }
    };

    attachEpistemicEnvelope(sharedContext, {
      epistemicState: 'OBSERVED',
      sourceAdapter: 'ejii.core.unified_investigation',
      observedAt: timestamp
    });

    return sharedContext;
  }

  getRecentInvestigations(limit = 10) {
    return Array.from(this.investigations.values()).slice(-limit).reverse();
  }
}

const unifiedInvestigationEngine = new UnifiedInvestigationEngine();

module.exports = {
  UnifiedInvestigationEngine,
  unifiedInvestigationEngine
};
