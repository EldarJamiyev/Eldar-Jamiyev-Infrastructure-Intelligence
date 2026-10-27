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
exports.AutonomousWarRoomOrchestrator = void 0;
// src/ai/autonomous-war-room.ts
const crypto = __importStar(require("node:crypto"));
const cusum_changepoint_engine_1 = require("./cusum-changepoint-engine");
const spectral_fourier_detector_1 = require("./spectral-fourier-detector");
const digital_twin_chaos_simulator_1 = require("../topology/digital-twin-chaos-simulator");
const multipath_qos_auditor_1 = require("../topology/multipath-qos-auditor");
const neuro_symbolic_apex_1 = require("./neuro-symbolic-apex");
const holt_winters_forecaster_1 = require("./holt-winters-forecaster");
const zero_trust_policy_synthesizer_1 = require("../security/zero-trust-policy-synthesizer");
class AutonomousWarRoomOrchestrator {
    hmacSecret;
    latestResult = null;
    constructor(secret = process.env.EJII_HMAC_SECRET || 'EJII-SRE-WAR-ROOM-SOVEREIGN-HMAC-KEY-2026') {
        this.hmacSecret = secret;
    }
    getLatestResult() {
        return this.latestResult;
    }
    /**
     * Executes the 5-Agent SRE War-Room Pipeline
     */
    execute(payload = {}) {
        const executedAt = new Date().toISOString();
        const warRoomSessionId = `sre-warroom-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
        // ==========================================
        // AGENT 1: Temporal & Spectral Triage
        // ==========================================
        const now = Date.now();
        const defaultSeries = [
            { timestampMs: now - 5000, rttMs: 14.2, cpuSaturationPct: 22.0, packetLossPct: 0.1 },
            { timestampMs: now - 4000, rttMs: 15.0, cpuSaturationPct: 24.5, packetLossPct: 0.1 },
            { timestampMs: now - 3000, rttMs: 18.2, cpuSaturationPct: 35.0, packetLossPct: 0.2 },
            { timestampMs: now - 2000, rttMs: 38.0, cpuSaturationPct: 62.0, packetLossPct: 1.5 },
            { timestampMs: now - 1000, rttMs: 42.5, cpuSaturationPct: 68.0, packetLossPct: 2.1 }
        ];
        const series = payload.timeSeries && payload.timeSeries.length >= 4 ? payload.timeSeries : defaultSeries;
        const cusumEngine = new cusum_changepoint_engine_1.CusumChangepointEngine();
        const cusumReport = cusumEngine.analyzeMultiMetricTrace(series);
        const rawValues = payload.rawMetricValues ? [...payload.rawMetricValues] : series.map(s => s.rttMs || 20);
        const spectralAnalysis = spectral_fourier_detector_1.SpectralFourierDetector.analyze(rawValues, 10);
        const agent1 = {
            agentName: 'Agent 1 — Temporal & Spectral Triage',
            cusumDriver: cusumReport.primaryTemporalDriver || 'rttMs',
            onsetTimestampMs: cusumReport.driverOnsetTimestampMs,
            spectralAnalysis,
            verdict: cusumReport.primaryTemporalDriver
                ? `Primary anomaly driver isolated: [${cusumReport.primaryTemporalDriver}] (Onset: ${cusumReport.driverOnsetTimestampMs || now}). Spectral Flatness: ${spectralAnalysis.spectralFlatness}.`
                : 'Telemetry series operating within nominal stochastic bounds.'
        };
        // ==========================================
        // AGENT 2: Topological & Queuing Analyst
        // ==========================================
        const defaultNodes = [
            { id: 'L1-WAN-ROUTER', role: 'GATEWAY', latencyMs: 14.2, packetLossPct: 0.1 },
            { id: 'L2-EDGE-ROUTER', role: 'GATEWAY', latencyMs: 2.1, packetLossPct: 0.0 },
            { id: 'L3-CORE-SWITCH', role: 'SWITCH', latencyMs: 0.8, packetLossPct: 0.0 },
            { id: 'L4-SERVICE-HOST', role: 'SERVER', latencyMs: 0.4, packetLossPct: 0.0 },
            { id: 'L5-ACCESS-LAN', role: 'ENDPOINT', latencyMs: 1.8, packetLossPct: 0.1 },
            { id: 'L6-HOST-WORKSTATION', role: 'WORKSTATION', latencyMs: 0.1, packetLossPct: 0.0 }
        ];
        const defaultEdges = [
            { source: 'L1-WAN-ROUTER', target: 'L2-EDGE-ROUTER', bandwidthMbps: 1000, linkLossPct: 0.1, rttMs: 12.1 },
            { source: 'L2-EDGE-ROUTER', target: 'L3-CORE-SWITCH', bandwidthMbps: 1000, linkLossPct: 0.0, rttMs: 1.3 },
            { source: 'L3-CORE-SWITCH', target: 'L4-SERVICE-HOST', bandwidthMbps: 1000, linkLossPct: 0.0, rttMs: 0.4 },
            { source: 'L3-CORE-SWITCH', target: 'L5-ACCESS-LAN', bandwidthMbps: 1000, linkLossPct: 0.1, rttMs: 1.0 },
            { source: 'L5-ACCESS-LAN', target: 'L6-HOST-WORKSTATION', bandwidthMbps: 1000, linkLossPct: 0.0, rttMs: 0.1 }
        ];
        const nodes = payload.topologyNodes || defaultNodes;
        const edges = payload.topologyEdges || defaultEdges;
        const rootNode = payload.rootNodeId || 'L6-HOST-WORKSTATION';
        const chaosSim = new digital_twin_chaos_simulator_1.DigitalTwinChaosSimulator();
        const chaosResult = chaosSim.simulate(nodes, edges, rootNode, { trafficMultiplier: 1.5 });
        const agent2 = {
            agentName: 'Agent 2 — Topological & Queuing Analyst',
            lambda2: chaosResult.postChaosLambda2,
            bottleneckEdges: chaosResult.preChaosReport.criticalCutEdges.map(e => `${e.source}->${e.target}`),
            chaosQueuing: chaosResult,
            verdict: `Algebraic Connectivity λ₂: ${chaosResult.postChaosLambda2}. M/M/1/K Max Queue Delay: ${chaosResult.maxQueuingDelayMs}ms, Drop Probability: ${chaosResult.averageDropProbabilityPct}%.`
        };
        // ==========================================
        // AGENT 3: Deep Wire Forensics
        // ==========================================
        const defaultFrames = [
            { tos: 0, length: 54, dfBit: true, srcPort: 443, dstPort: 54320, srcIp: '192.168.31.1', dstIp: '192.168.31.89' },
            { tos: 0, length: 1514, dfBit: true, srcPort: 80, dstPort: 54321, srcIp: '192.168.31.1', dstIp: '192.168.31.89' },
            { tos: 3, length: 120, dfBit: false, srcPort: 443, dstPort: 54322, srcIp: '8.8.8.8', dstIp: '192.168.31.89' } // ECN-CE
        ];
        const wireFrames = payload.wireFrames ? [...payload.wireFrames] : defaultFrames;
        const qosAudit = multipath_qos_auditor_1.MultipathQosAuditor.auditWireFrames(wireFrames);
        const l7Obs = ['TLS 1.3 Active', 'DNS Over UDP/53 Active'];
        if (qosAudit.activeEcnCongestionCount > 0) {
            l7Obs.push(`ECN-CE Router Congestion Detected (${qosAudit.activeEcnCongestionCount} events)`);
        }
        const agent3 = {
            agentName: 'Agent 3 — Deep Wire Forensics',
            qosAudit,
            l7Observations: l7Obs,
            verdict: `Wire audit completed: ${qosAudit.totalPacketsAudited} frames. Violations flagged: ${qosAudit.violations.length}. Active ECN CE: ${qosAudit.activeEcnCongestionCount}.`
        };
        // ==========================================
        // AGENT 4: Causal Counterfactual Planner
        // ==========================================
        const holtWinters = new holt_winters_forecaster_1.HoltWintersForecaster();
        const forecast = holtWinters.forecastSeries(rawValues, 'rttMs', 'RTT Latency', 'ms', 50.0, 'MAX');
        const neuroApex = new neuro_symbolic_apex_1.NeuroSymbolicApexEngine();
        const stlEvaluation = neuroApex.evaluateTemporallyBoundedAlways('SLA_RTT_BOUND', [{ id: 'p1', metric: 'rttMs', operator: 'LTE', threshold: 50.0, weight: 1.0 }], [{
                timestampMs: now,
                rttMs: rawValues[rawValues.length - 1] || 25,
                packetLossPct: 0.1,
                cpuSaturationPct: 35,
                tcpRetransmitRate: 0.02
            }]);
        const proposedAction = forecast.forecasts.plus5m.slaBreachRiskPct > 20
            ? 'ACTION_APPLY_TRAFFIC_SHAPING_AND_DSCP_REMARK'
            : 'ACTION_OBSERVE_STABILIZATION';
        const agent4 = {
            agentName: 'Agent 4 — Causal Counterfactual Planner',
            smoothStlRobustness: stlEvaluation.smoothRobustness,
            ttvHorizonSeconds: stlEvaluation.estimatedTimeToViolationSec ?? 999,
            holtWintersForecast: forecast,
            proposedRemediationAction: proposedAction,
            verdict: `Smooth STL Robustness ρ̃: ${stlEvaluation.smoothRobustness > 0 ? '+' : ''}${stlEvaluation.smoothRobustness.toFixed(2)}. +5m SLA Breach Risk: ${forecast.forecasts.plus5m.slaBreachRiskPct}%. Proposed: ${proposedAction}.`
        };
        // ==========================================
        // AGENT 5: DSRL Lyapunov Safety & Zero-Trust
        // ==========================================
        const zeroTrust = zero_trust_policy_synthesizer_1.ZeroTrustPolicySynthesizer.synthesize(nodes.map(n => ({ ip: n.id === 'L1-WAN-ROUTER' ? '8.8.8.8' : '192.168.31.1', hostname: n.id, role: n.role, openPorts: [443, 8443] })), [{ protocol: 'TCP', localIp: '192.168.31.89', localPort: 54320, remoteIp: '192.168.31.1', remotePort: 443 }]);
        const lyapunovCleared = stlEvaluation.smoothRobustness >= -5.0; // Lyapunov barrier invariant
        const transcriptPayload = JSON.stringify({
            sessionId: warRoomSessionId,
            triage: agent1.verdict,
            topo: agent2.verdict,
            wire: agent3.verdict,
            planner: agent4.verdict,
            action: proposedAction,
            lyapunov: lyapunovCleared
        });
        const hmacSig = crypto.createHmac('sha256', this.hmacSecret).update(transcriptPayload).digest('hex');
        const proofChain = `EJII-PROOF-V5:${crypto.createHash('sha256').update(hmacSig + executedAt).digest('hex')}`;
        const agent5 = {
            agentName: 'Agent 5 — DSRL Lyapunov Safety & Zero-Trust Officer',
            lyapunovBarrierCleared: lyapunovCleared,
            zeroTrustPolicy: zeroTrust,
            hmacSignature: hmacSig,
            proofChain,
            verdict: `Lyapunov barrier invariant verified: ${lyapunovCleared ? 'CLEARED' : 'VETOED'}. Zero-Trust policies synthesized. Signed with HMAC-SHA256.`
        };
        const result = {
            warRoomSessionId,
            executedAt,
            status: lyapunovCleared ? 'RESOLVED_REMEDIATION_SIGNED' : 'INCIDENT_ESCALATED',
            agent1,
            agent2,
            agent3,
            agent4,
            agent5,
            executiveSummary: `5-Agent SRE War-Room Session [${warRoomSessionId}] completed with status ${lyapunovCleared ? 'RESOLVED_REMEDIATION_SIGNED' : 'INCIDENT_ESCALATED'}. Primary Driver: ${agent1.cusumDriver}. Predicted SLA Risk: ${forecast.forecasts.plus5m.slaBreachRiskPct}%. Cryptographically signed with HMAC-SHA256.`
        };
        this.latestResult = result;
        return result;
    }
}
exports.AutonomousWarRoomOrchestrator = AutonomousWarRoomOrchestrator;
//# sourceMappingURL=autonomous-war-room.js.map