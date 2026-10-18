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
        matchedProcess = discoveredEndpoints.find(
          (e) =>
            String(e.processName || '').toLowerCase().includes(q) ||
            String(e.pid || '') === q ||
            String(e.domain || '').toLowerCase().includes(q)
        ) || discoveredEndpoints[0];

        if (matchedProcess && !resolvedTargetHost && matchedProcess.remoteIp && matchedProcess.remoteIp !== '0.0.0.0') {
          resolvedTargetHost = matchedProcess.remoteIp;
          resolvedTargetPort = Number(matchedProcess.remotePort) || resolvedTargetPort;
        }
      }

      stages.push({
        stageNumber: 1,
        stageId: 'ENDPOINT_DISCOVERY',
        section: 'Section 2: App Server & Port Finder',
        status: matchedProcess || resolvedTargetHost ? 'COMPLETED' : 'PARTIAL',
        summary: matchedProcess
          ? `Discovered process ${matchedProcess.processName} (PID ${matchedProcess.pid}) communicating with ${matchedProcess.remoteIp}:${matchedProcess.remotePort} (${matchedProcess.state || 'ACTIVE'}).`
          : resolvedTargetHost
            ? `Targeting explicitly supplied endpoint ${resolvedTargetHost}:${resolvedTargetPort} (${discoveredEndpoints.length} active host sockets scanned).`
            : `Scanned ${discoveredEndpoints.length} OS sockets; no specific remote endpoint matched "${processQuery}". Defaulting to perimeter gateway check.`,
        evidence: {
          matchedProcess,
          totalOsSocketsScanned: discoveredEndpoints.length,
          sampleEndpoints: discoveredEndpoints.slice(0, 5)
        }
      });
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
    const hostContext = aiBrain.lastHostHealthSnapshot || {
      overallStatus: 'HEALTHY',
      localHostSaturated: false,
      localNicDegraded: false
    };

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
    const dnsOk = dnsStage?.status !== 'FAIL';
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

  getRecentInvestigations(limit = 10) {
    return Array.from(this.investigations.values()).slice(-limit).reverse();
  }
}

const unifiedInvestigationEngine = new UnifiedInvestigationEngine();

module.exports = {
  UnifiedInvestigationEngine,
  unifiedInvestigationEngine
};
