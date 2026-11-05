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
exports.TelemetryDvrTimeMachine = void 0;
// src/observability/telemetry-dvr-timemachine.ts
const crypto = __importStar(require("node:crypto"));
class TelemetryDvrTimeMachine {
    maxFrames;
    ringBuffer = [];
    frameCounter = 0;
    constructor(maxFrames = 240) {
        this.maxFrames = Math.max(1, maxFrames);
        this.seedInitialBaseline();
    }
    seedInitialBaseline() {
        this.recordFrame({
            label: 'Initial Baseline Boot',
            topologyNodeCount: 6,
            lambda2: 0.182,
            stlRobustness: 0.85,
            cpuPct: 14.5,
            ramPct: 48.2,
            activeAnomalies: 0,
            nodesSnapshot: [
                { id: 'L1-WAN-ROUTER', ip: '8.8.8.8', role: 'GATEWAY', latencyMs: 14.2 },
                { id: 'L2-EDGE-ROUTER', ip: '192.168.31.1', role: 'GATEWAY', latencyMs: 2.1 },
                { id: 'L3-CORE-SWITCH', ip: '192.168.31.2', role: 'SWITCH', latencyMs: 0.8 },
                { id: 'L4-SERVICE-HOST', ip: '192.168.31.89', role: 'SERVER', latencyMs: 0.4 },
                { id: 'L5-ACCESS-LAN', ip: '192.168.31.0/24', role: 'ENDPOINT', latencyMs: 1.8 },
                { id: 'L6-HOST-WORKSTATION', ip: '192.168.31.89', role: 'WORKSTATION', latencyMs: 0.1 }
            ],
            socketsSnapshot: [
                { protocol: 'TCP', localPort: 8443, remoteIp: '0.0.0.0', remotePort: 0, processName: 'node.exe' },
                { protocol: 'TCP', localPort: 54320, remoteIp: '192.168.31.1', remotePort: 443, processName: 'chrome.exe' }
            ]
        });
    }
    /**
     * Resets the DVR ring buffer and sequence counter cleanly
     */
    reset(reseedBaseline = false) {
        this.ringBuffer.length = 0;
        this.frameCounter = 0;
        if (reseedBaseline) {
            this.seedInitialBaseline();
        }
    }
    shutdown() {
        this.ringBuffer.length = 0;
    }
    /**
     * Records a new keyframe into the ring buffer
     */
    recordFrame(data) {
        this.frameCounter++;
        const now = Date.now();
        const capturedAtMs = data.capturedAtMs ?? data.timestampMs ?? now;
        const ingestedAtMs = data.ingestedAtMs ?? now;
        const frame = {
            id: data.id || `dvr-frame-${this.frameCounter}-${crypto.randomBytes(3).toString('hex')}`,
            sequenceNumber: data.sequenceNumber ?? this.frameCounter,
            timestampMs: capturedAtMs,
            capturedAtMs,
            ingestedAtMs,
            isoTime: data.isoTime || new Date(capturedAtMs).toISOString(),
            label: data.label || `Telemetry Checkpoint #${this.frameCounter}`,
            topologyNodeCount: data.topologyNodeCount ?? (data.nodesSnapshot ? data.nodesSnapshot.length : 6),
            lambda2: Number((data.lambda2 ?? 0.182).toFixed(4)),
            stlRobustness: Number((data.stlRobustness ?? 0.85).toFixed(4)),
            cpuPct: Number((data.cpuPct ?? 15.0).toFixed(1)),
            ramPct: Number((data.ramPct ?? 50.0).toFixed(1)),
            activeAnomalies: data.activeAnomalies ?? 0,
            nodesSnapshot: data.nodesSnapshot || [],
            socketsSnapshot: data.socketsSnapshot || []
        };
        if (this.ringBuffer.length >= this.maxFrames) {
            this.ringBuffer.shift();
        }
        this.ringBuffer.push(frame);
        return frame;
    }
    /**
     * Lists all recorded keyframes in chronological order
     */
    listFrames() {
        return [...this.ringBuffer];
    }
    /**
     * Retrieves a specific keyframe by ID
     */
    getFrame(id) {
        return this.ringBuffer.find(f => f.id === id) || null;
    }
    /**
     * Computes structural delta between two keyframe snapshots
     */
    computeSnapshotDiff(fromFrame, toFrame) {
        const timeDeltaMs = toFrame.timestampMs - fromFrame.timestampMs;
        const seqFrom = fromFrame.sequenceNumber ?? 0;
        const seqTo = toFrame.sequenceNumber ?? 0;
        const sequenceDelta = seqTo - seqFrom;
        const missingFramesCount = sequenceDelta > 1 ? (sequenceDelta - 1) : 0;
        let intervalStatus = 'CONTINUOUS';
        if (missingFramesCount > 0) {
            intervalStatus = 'INCOMPLETE_INTERVAL';
        }
        else if (Math.abs(timeDeltaMs) > 300000) {
            intervalStatus = 'TELEMETRY_GAP';
        }
        const fromNodes = new Map((fromFrame.nodesSnapshot || []).map(n => [n.id, n]));
        const toNodes = new Map((toFrame.nodesSnapshot || []).map(n => [n.id, n]));
        const addedNodes = [];
        const removedNodes = [];
        const latencyDeltaByNode = {};
        const modifiedNodeAttributes = {};
        for (const [id, toNode] of toNodes) {
            if (!fromNodes.has(id)) {
                addedNodes.push(id);
            }
            else {
                const fromNode = fromNodes.get(id);
                const delta = Number((toNode.latencyMs - fromNode.latencyMs).toFixed(2));
                latencyDeltaByNode[id] = delta;
                const ipChanged = fromNode.ip !== toNode.ip;
                const roleChanged = fromNode.role !== toNode.role;
                if (ipChanged || roleChanged) {
                    modifiedNodeAttributes[id] = { ipChanged, roleChanged };
                }
            }
        }
        for (const id of fromNodes.keys()) {
            if (!toNodes.has(id)) {
                removedNodes.push(id);
            }
        }
        const socketKey = (s) => `${s.protocol}:${s.localPort}->${s.remoteIp}:${s.remotePort}`;
        const fromSockets = new Set((fromFrame.socketsSnapshot || []).map(socketKey));
        const toSockets = new Set((toFrame.socketsSnapshot || []).map(socketKey));
        const newSockets = [...toSockets].filter(k => !fromSockets.has(k));
        const closedSockets = [...fromSockets].filter(k => !toSockets.has(k));
        const stlRobustnessDelta = Number((toFrame.stlRobustness - fromFrame.stlRobustness).toFixed(4));
        const lambda2Delta = Number((toFrame.lambda2 - fromFrame.lambda2).toFixed(4));
        const cpuDeltaPct = Number((toFrame.cpuPct - fromFrame.cpuPct).toFixed(1));
        const ramDeltaPct = Number((toFrame.ramPct - fromFrame.ramPct).toFixed(1));
        const anomaliesDelta = toFrame.activeAnomalies - fromFrame.activeAnomalies;
        const summaryParts = [];
        if (addedNodes.length > 0)
            summaryParts.push(`+${addedNodes.length} nodes added`);
        if (removedNodes.length > 0)
            summaryParts.push(`-${removedNodes.length} nodes severed`);
        if (lambda2Delta !== 0)
            summaryParts.push(`Δλ₂: ${lambda2Delta > 0 ? '+' : ''}${lambda2Delta}`);
        if (newSockets.length > 0)
            summaryParts.push(`+${newSockets.length} new connections`);
        if (closedSockets.length > 0)
            summaryParts.push(`-${closedSockets.length} closed connections`);
        if (intervalStatus !== 'CONTINUOUS')
            summaryParts.push(`[${intervalStatus}]`);
        if (summaryParts.length === 0)
            summaryParts.push('Steady-state telemetry nominal (0 structural diff)');
        return {
            fromId: fromFrame.id,
            toId: toFrame.id,
            timeDeltaMs,
            sequenceDelta,
            intervalStatus,
            missingFramesCount,
            addedNodes,
            removedNodes,
            modifiedNodeAttributes,
            latencyDeltaByNode,
            newSockets,
            closedSockets,
            stlRobustnessDelta,
            lambda2Delta,
            cpuDeltaPct,
            ramDeltaPct,
            anomaliesDelta,
            summary: summaryParts.join(' | ')
        };
    }
}
exports.TelemetryDvrTimeMachine = TelemetryDvrTimeMachine;
//# sourceMappingURL=telemetry-dvr-timemachine.js.map