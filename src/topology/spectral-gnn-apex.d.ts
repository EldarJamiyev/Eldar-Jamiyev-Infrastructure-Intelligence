export interface TopologyNode {
    readonly id: string;
    readonly role: 'WORKSTATION' | 'SWITCH' | 'GATEWAY' | 'SERVER' | 'PRINTER' | 'VOIP' | 'ENDPOINT';
    readonly latencyMs: number;
    readonly packetLossPct: number;
}
export interface TopologyEdge {
    readonly source: string;
    readonly target: string;
    readonly bandwidthMbps: number;
    readonly linkLossPct: number;
    readonly rttMs: number;
}
export interface NodeTopologicalIntelligence {
    readonly nodeId: string;
    readonly gcnEmbedding: readonly [number, number, number];
    readonly fiedlerCoordinate: number;
    readonly blastRadiusCount: number;
    readonly strandedDownstreamIds: readonly string[];
    readonly isArticulationBottleneck: boolean;
}
export interface SpectralTopologyReport {
    readonly algebraicConnectivityLambda2: number;
    readonly partitionRiskLevel: 'NOMINAL' | 'FRAGILE_BRIDGE' | 'CRITICAL_PARTITION_IMMINENT';
    readonly criticalCutEdges: readonly {
        source: string;
        target: string;
        spectralTension: number;
    }[];
    readonly nodes: readonly NodeTopologicalIntelligence[];
}
export declare class SpectralGNNTopologyEngine {
    /**
     * Runs 3-Layer Kipf-Welling Spatial GCN + Spectral Laplacian Fiedler (lambda_2) analysis
     * + Deterministic Rooted Blast Radius computation in pure Float64Array.
     */
    analyzeTopology(nodes: readonly TopologyNode[], edges: readonly TopologyEdge[], rootWorkstationId: string): SpectralTopologyReport;
    /**
     * Computes the second-smallest eigenvalue (lambda_2) and eigenvector of L = D - W
     * via shifted inverse-free deflated power iteration orthogonal to the constant 1-vector.
     */
    private computeFiedlerEigenpair;
    private orthogonalizeAndNormalize;
    private compute3LayerKipfWellingGCN;
    private bfsReachable;
}
