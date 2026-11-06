import { TopologyNode, TopologyEdge, SpectralTopologyReport } from './spectral-gnn-apex';
export interface ChaosScenario {
    readonly trafficMultiplier?: number;
    readonly degradedNodeIds?: readonly string[];
    readonly severedEdgeKeys?: readonly string[];
    readonly injectedLatencyMsByNode?: Readonly<Record<string, number>>;
    readonly bufferCapacityK?: number;
}
export interface NodeQueuingMetrics {
    readonly nodeId: string;
    readonly arrivalRatePps: number;
    readonly serviceRatePps: number;
    readonly utilizationRho: number;
    readonly dropProbabilityPct: number;
    readonly averageQueueLengthPkts: number;
    readonly queuingDelayMs: number;
    readonly totalSimulatedLatencyMs: number;
    readonly isSlaBreached: boolean;
}
export interface ChaosSimulationResult {
    readonly preChaosLambda2: number;
    readonly postChaosLambda2: number;
    readonly deltaLambda2: number;
    readonly partitionedNodeIds: readonly string[];
    readonly strandedNodeCount: number;
    readonly trafficMultiplier: number;
    readonly nodeMetrics: readonly NodeQueuingMetrics[];
    readonly averageDropProbabilityPct: number;
    readonly maxQueuingDelayMs: number;
    readonly slaBreachCascadeOrder: readonly string[];
    readonly preChaosReport: SpectralTopologyReport;
    readonly postChaosReport: SpectralTopologyReport;
    readonly modelFidelityLabel?: 'MATHEMATICAL_SIMULATION';
    readonly inputProvenance?: 'VERIFIED_TOPOLOGY_AND_TELEMETRY' | 'SCENARIO_PARAMETERIZED';
    readonly assumptions?: readonly string[];
}
export declare class DigitalTwinChaosSimulator {
    private readonly spectralEngine;
    /**
     * Computes M/M/1/K finite buffer queuing metrics for a single node/queue
     */
    static computeMM1K(arrivalRatePps: number, serviceRatePps: number, bufferCapacityK?: number): {
        utilizationRho: number;
        dropProbability: number;
        averageQueueLength: number;
        queuingDelaySec: number;
    };
    /**
     * Simulates a What-If Chaos Scenario on the digital twin topology
     */
    simulate(nodes: readonly TopologyNode[], edges: readonly TopologyEdge[], rootNodeId?: string, scenario?: ChaosScenario): ChaosSimulationResult;
}
