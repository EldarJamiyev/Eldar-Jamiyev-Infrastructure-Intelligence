"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DigitalTwinChaosSimulator = void 0;
// src/topology/digital-twin-chaos-simulator.ts
const spectral_gnn_apex_1 = require("./spectral-gnn-apex");
class DigitalTwinChaosSimulator {
    spectralEngine = new spectral_gnn_apex_1.SpectralGNNTopologyEngine();
    /**
     * Computes M/M/1/K finite buffer queuing metrics for a single node/queue
     */
    static computeMM1K(arrivalRatePps, serviceRatePps, bufferCapacityK = 40) {
        const safeK = Number.isFinite(bufferCapacityK) ? Math.max(1, Math.min(10000, Math.floor(bufferCapacityK))) : 40;
        const safeMu = Number.isFinite(serviceRatePps) && serviceRatePps > 0 ? serviceRatePps : 1.0;
        const safeLambda = Number.isFinite(arrivalRatePps) ? Math.max(0, arrivalRatePps) : 0;
        if (safeLambda === 0) {
            return {
                utilizationRho: 0,
                dropProbability: 0,
                averageQueueLength: 0,
                queuingDelaySec: 0
            };
        }
        const rho = safeLambda / safeMu;
        let p0;
        let pK;
        let avgL = 0;
        if (Math.abs(rho - 1.0) < 1e-6) {
            // Rho == 1.0 exact degenerate limit
            p0 = 1.0 / (safeK + 1);
            pK = p0;
            avgL = safeK / 2.0;
        }
        else if (rho > 20.0) {
            // Asymptotic high-overload regime to avoid floating-point overflow of rho^(K+1)
            pK = (rho - 1.0) / rho;
            p0 = 0;
            avgL = safeK - (1.0 / (rho - 1.0));
        }
        else {
            const rhoPowK = Math.pow(rho, safeK);
            const rhoPowKPlus1 = rhoPowK * rho;
            p0 = (1.0 - rho) / (1.0 - rhoPowKPlus1);
            pK = p0 * rhoPowK;
            for (let n = 1; n <= safeK; n++) {
                avgL += n * (p0 * Math.pow(rho, n));
            }
        }
        pK = Math.min(1.0, Math.max(0.0, Number.isFinite(pK) ? pK : 1.0));
        avgL = Math.min(safeK, Math.max(0.0, Number.isFinite(avgL) ? avgL : safeK));
        const lambdaEff = safeLambda * (1.0 - pK);
        const queuingDelaySec = lambdaEff > 1e-9 ? (avgL / lambdaEff) : (avgL / safeMu);
        return {
            utilizationRho: Number(rho.toFixed(4)),
            dropProbability: Number(pK.toFixed(6)),
            averageQueueLength: Number(avgL.toFixed(3)),
            queuingDelaySec: Math.max(0, Number.isFinite(queuingDelaySec) ? queuingDelaySec : 0)
        };
    }
    /**
     * Simulates a What-If Chaos Scenario on the digital twin topology
     */
    simulate(nodes, edges, rootNodeId = 'L6-HOST-WORKSTATION', scenario = {}) {
        const safeNodes = Array.isArray(nodes) ? nodes : [];
        const safeEdges = Array.isArray(edges) ? edges : [];
        const rawMult = scenario?.trafficMultiplier ?? 1.0;
        const trafficMultiplier = Number.isFinite(rawMult) ? Math.max(0.0, rawMult) : 1.0;
        const bufferCapacityK = Number.isFinite(scenario?.bufferCapacityK) ? Math.max(1, Math.floor(scenario.bufferCapacityK)) : 40;
        const degradedSet = new Set(scenario?.degradedNodeIds || []);
        const severedSet = new Set((scenario?.severedEdgeKeys || []).map(k => String(k).replace(':', '-').toLowerCase()));
        const injectedLatencies = scenario?.injectedLatencyMsByNode || {};
        // 1. Evaluate Pre-Chaos Baseline
        const preChaosReport = this.spectralEngine.analyzeTopology(safeNodes, safeEdges, rootNodeId);
        const preChaosLambda2 = preChaosReport.algebraicConnectivityLambda2;
        // 2. Filter out severed edges for post-chaos graph
        const postEdges = safeEdges.filter(edge => {
            const k1 = `${edge.source}-${edge.target}`.toLowerCase();
            const k2 = `${edge.target}-${edge.source}`.toLowerCase();
            return !severedSet.has(k1) && !severedSet.has(k2);
        });
        // 3. Evaluate Post-Chaos Graph
        const postChaosReport = this.spectralEngine.analyzeTopology(safeNodes, postEdges, rootNodeId);
        const postChaosLambda2 = postChaosReport.algebraicConnectivityLambda2;
        const deltaLambda2 = Number((postChaosLambda2 - preChaosLambda2).toFixed(4));
        // 4. Calculate Queuing Delay & Drops per Node
        const nodeMetrics = [];
        let totalDropProb = 0;
        let maxDelayMs = 0;
        for (const node of safeNodes) {
            const isDegraded = degradedSet.has(node.id);
            const rawInj = injectedLatencies[node.id] || 0;
            const injectedLatency = Number.isFinite(rawInj) ? Math.max(0, rawInj) : 0;
            // Base capacity calibrated by role
            let baseCapacity = 300.0; // pps
            if (node.role === 'GATEWAY' || node.role === 'SWITCH')
                baseCapacity = 800.0;
            else if (node.role === 'SERVER')
                baseCapacity = 500.0;
            else if (node.role === 'PRINTER')
                baseCapacity = 80.0;
            if (isDegraded) {
                baseCapacity *= 0.35; // Severe service degradation
            }
            const baseArrival = 120.0 * (node.role === 'GATEWAY' ? 2.5 : 1.0);
            const simulatedArrival = baseArrival * trafficMultiplier;
            const q = DigitalTwinChaosSimulator.computeMM1K(simulatedArrival, baseCapacity, bufferCapacityK);
            const queuingDelayMs = Number((q.queuingDelaySec * 1000.0).toFixed(2));
            const baseNodeLat = Number.isFinite(node.latencyMs) ? Math.max(0, node.latencyMs) : 0;
            const totalSimulatedLatencyMs = Number((baseNodeLat + queuingDelayMs + injectedLatency + (isDegraded ? 85.0 : 0)).toFixed(2));
            const dropPct = Number((q.dropProbability * 100.0).toFixed(3));
            const isSlaBreached = totalSimulatedLatencyMs > 100.0 || dropPct > 2.0;
            totalDropProb += dropPct;
            if (queuingDelayMs > maxDelayMs)
                maxDelayMs = queuingDelayMs;
            nodeMetrics.push({
                nodeId: node.id,
                arrivalRatePps: Number(simulatedArrival.toFixed(1)),
                serviceRatePps: Number(baseCapacity.toFixed(1)),
                utilizationRho: q.utilizationRho,
                dropProbabilityPct: dropPct,
                averageQueueLengthPkts: q.averageQueueLength,
                queuingDelayMs,
                totalSimulatedLatencyMs,
                isSlaBreached
            });
        }
        // 5. Detect newly partitioned or stranded nodes
        const partitionedNodeIds = postChaosReport.nodes
            .filter(n => n.strandedDownstreamIds.length > 0 || n.blastRadiusCount === 0)
            .map(n => n.nodeId);
        // 6. SLA Breach Cascade Order (nodes sorted by severity: drop % and latency)
        const slaBreachCascadeOrder = [...nodeMetrics]
            .filter(m => m.isSlaBreached)
            .sort((a, b) => (b.dropProbabilityPct * b.totalSimulatedLatencyMs) - (a.dropProbabilityPct * a.totalSimulatedLatencyMs))
            .map(m => m.nodeId);
        const averageDropProbabilityPct = safeNodes.length > 0 ? Number((totalDropProb / safeNodes.length).toFixed(3)) : 0;
        return {
            preChaosLambda2,
            postChaosLambda2,
            deltaLambda2,
            partitionedNodeIds,
            strandedNodeCount: partitionedNodeIds.length,
            trafficMultiplier,
            nodeMetrics,
            averageDropProbabilityPct,
            maxQueuingDelayMs: maxDelayMs,
            slaBreachCascadeOrder,
            preChaosReport,
            postChaosReport,
            modelFidelityLabel: 'MATHEMATICAL_SIMULATION',
            inputProvenance: 'SCENARIO_PARAMETERIZED',
            assumptions: [
                `Poisson arrival process and exponential service times (M/M/1/K finite buffer K=${bufferCapacityK} packets).`,
                `Role-calibrated baseline service capacities with traffic multiplier ${trafficMultiplier}x.`,
                'Simulation outputs represent counterfactual mathematical projections and are never merged into live topology state.'
            ]
        };
    }
}
exports.DigitalTwinChaosSimulator = DigitalTwinChaosSimulator;
//# sourceMappingURL=digital-twin-chaos-simulator.js.map