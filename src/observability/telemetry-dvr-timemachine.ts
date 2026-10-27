// src/observability/telemetry-dvr-timemachine.ts
import * as crypto from 'node:crypto';

export interface DvrNodeSnapshot {
  readonly id: string;
  readonly ip: string;
  readonly role?: string;
  readonly latencyMs: number;
}

export interface DvrSocketSnapshot {
  readonly protocol: string;
  readonly localPort: number;
  readonly remoteIp: string;
  readonly remotePort: number;
  readonly processName?: string;
}

export interface DvrKeyframe {
  readonly id: string;
  readonly timestampMs: number;
  readonly isoTime: string;
  readonly label: string;
  readonly topologyNodeCount: number;
  readonly lambda2: number;
  readonly stlRobustness: number;
  readonly cpuPct: number;
  readonly ramPct: number;
  readonly activeAnomalies: number;
  readonly nodesSnapshot: readonly DvrNodeSnapshot[];
  readonly socketsSnapshot: readonly DvrSocketSnapshot[];
}

export interface DvrSnapshotDiff {
  readonly fromId: string;
  readonly toId: string;
  readonly timeDeltaMs: number;
  readonly addedNodes: readonly string[];
  readonly removedNodes: readonly string[];
  readonly latencyDeltaByNode: Readonly<Record<string, number>>;
  readonly newSockets: readonly string[];
  readonly closedSockets: readonly string[];
  readonly stlRobustnessDelta: number;
  readonly lambda2Delta: number;
  readonly cpuDeltaPct: number;
  readonly ramDeltaPct: number;
  readonly anomaliesDelta: number;
  readonly summary: string;
}

export class TelemetryDvrTimeMachine {
  private readonly maxFrames: number;
  private readonly ringBuffer: DvrKeyframe[] = [];
  private frameCounter = 0;

  constructor(maxFrames = 240) {
    this.maxFrames = Math.max(1, maxFrames);
    // Automatically record an initial baseline boot keyframe
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
   * Records a new keyframe into the ring buffer
   */
  public recordFrame(data: Partial<DvrKeyframe>): DvrKeyframe {
    this.frameCounter++;
    const now = Date.now();
    const frame: DvrKeyframe = {
      id: data.id || `dvr-frame-${this.frameCounter}-${crypto.randomBytes(3).toString('hex')}`,
      timestampMs: data.timestampMs || now,
      isoTime: data.isoTime || new Date(now).toISOString(),
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
  public listFrames(): readonly DvrKeyframe[] {
    return [...this.ringBuffer];
  }

  /**
   * Retrieves a specific keyframe by ID
   */
  public getFrame(id: string): DvrKeyframe | null {
    return this.ringBuffer.find(f => f.id === id) || null;
  }

  /**
   * Computes structural delta between two keyframe snapshots
   */
  public computeSnapshotDiff(fromFrame: DvrKeyframe, toFrame: DvrKeyframe): DvrSnapshotDiff {
    const timeDeltaMs = toFrame.timestampMs - fromFrame.timestampMs;

    const fromNodes = new Map(fromFrame.nodesSnapshot.map(n => [n.id, n]));
    const toNodes = new Map(toFrame.nodesSnapshot.map(n => [n.id, n]));

    const addedNodes: string[] = [];
    const removedNodes: string[] = [];
    const latencyDeltaByNode: Record<string, number> = {};

    for (const [id, toNode] of toNodes) {
      if (!fromNodes.has(id)) {
        addedNodes.push(id);
      } else {
        const fromNode = fromNodes.get(id)!;
        const delta = Number((toNode.latencyMs - fromNode.latencyMs).toFixed(2));
        latencyDeltaByNode[id] = delta;
      }
    }

    for (const id of fromNodes.keys()) {
      if (!toNodes.has(id)) {
        removedNodes.push(id);
      }
    }

    const socketKey = (s: DvrSocketSnapshot) => `${s.protocol}:${s.localPort}->${s.remoteIp}:${s.remotePort}`;
    const fromSockets = new Set(fromFrame.socketsSnapshot.map(socketKey));
    const toSockets = new Set(toFrame.socketsSnapshot.map(socketKey));

    const newSockets = [...toSockets].filter(k => !fromSockets.has(k));
    const closedSockets = [...fromSockets].filter(k => !toSockets.has(k));

    const stlRobustnessDelta = Number((toFrame.stlRobustness - fromFrame.stlRobustness).toFixed(4));
    const lambda2Delta = Number((toFrame.lambda2 - fromFrame.lambda2).toFixed(4));
    const cpuDeltaPct = Number((toFrame.cpuPct - fromFrame.cpuPct).toFixed(1));
    const ramDeltaPct = Number((toFrame.ramPct - fromFrame.ramPct).toFixed(1));
    const anomaliesDelta = toFrame.activeAnomalies - fromFrame.activeAnomalies;

    const summaryParts: string[] = [];
    if (addedNodes.length > 0) summaryParts.push(`+${addedNodes.length} nodes added`);
    if (removedNodes.length > 0) summaryParts.push(`-${removedNodes.length} nodes severed`);
    if (lambda2Delta !== 0) summaryParts.push(`Δλ₂: ${lambda2Delta > 0 ? '+' : ''}${lambda2Delta}`);
    if (newSockets.length > 0) summaryParts.push(`+${newSockets.length} new connections`);
    if (closedSockets.length > 0) summaryParts.push(`-${closedSockets.length} closed connections`);
    if (summaryParts.length === 0) summaryParts.push('Steady-state telemetry nominal (0 structural diff)');

    return {
      fromId: fromFrame.id,
      toId: toFrame.id,
      timeDeltaMs,
      addedNodes,
      removedNodes,
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
