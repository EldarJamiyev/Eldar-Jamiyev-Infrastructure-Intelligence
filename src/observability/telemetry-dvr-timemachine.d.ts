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
export declare class TelemetryDvrTimeMachine {
    private readonly maxFrames;
    private readonly ringBuffer;
    private frameCounter;
    constructor(maxFrames?: number);
    /**
     * Records a new keyframe into the ring buffer
     */
    recordFrame(data: Partial<DvrKeyframe>): DvrKeyframe;
    /**
     * Lists all recorded keyframes in chronological order
     */
    listFrames(): readonly DvrKeyframe[];
    /**
     * Retrieves a specific keyframe by ID
     */
    getFrame(id: string): DvrKeyframe | null;
    /**
     * Computes structural delta between two keyframe snapshots
     */
    computeSnapshotDiff(fromFrame: DvrKeyframe, toFrame: DvrKeyframe): DvrSnapshotDiff;
}
