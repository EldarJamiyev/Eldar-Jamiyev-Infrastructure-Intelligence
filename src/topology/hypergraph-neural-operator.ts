// src/topology/hypergraph-neural-operator.ts
/**
 * EJII Phase 11.0 Track 1 — Topological Hypergraph Neural Operator & Persistent Homology Engine
 *
 * Implements Non-Euclidean higher-order topological modeling:
 *  - Hypergraph Representation H = (V, E, W) where a hyperedge connects k >= 2 nodes
 *  - Incidence matrix B \in R^{|V| x |E|}, Vertex degree matrix D_v, Hyperedge degree matrix D_e
 *  - Normalized Hypergraph Laplacian Operator L_H = I - D_v^{-1/2} B W D_e^{-1} B^T D_v^{-1/2}
 *  - Persistent Homology & Betti Numbers (\beta_0 connected components, \beta_1 routing loops/vortexes)
 *  - Higher-Order Routing Vortex & Topological Sink Anomaly Detection
 *  - SQLite WAL Persistence for Historical Topology Drift
 */

import * as crypto from 'node:crypto';

export interface HypergraphNode {
  readonly id: string;
  readonly role?: 'ROUTER' | 'SWITCH' | 'GATEWAY' | 'SERVER' | 'POD' | 'ENDPOINT';
  readonly metrics?: {
    rttMs?: number;
    lossPct?: number;
    queueDepthPackets?: number;
    throughputMbps?: number;
  };
}

export interface Hyperedge {
  readonly id: string;
  readonly nodes: readonly string[];
  readonly weight: number;
  readonly hyperedgeType:
    | 'SHARED_BROADCAST_VLAN'
    | 'ECMP_BUNDLE'
    | 'BGP_CONFEDERATION'
    | 'K8S_SERVICE_MESH'
    | 'TRUNK_GROUP';
  readonly metricCost?: number;
}

export interface FiltrationStep {
  readonly threshold: number;
  readonly activeHyperedges: number;
  readonly betti0: number;
  readonly betti1: number;
  readonly eulerCharacteristic: number;
}

export interface HypergraphTopologyReport {
  readonly topologyId: string;
  readonly nodeCount: number;
  readonly hyperedgeCount: number;
  readonly betti0: number;
  readonly betti1: number;
  readonly hasVortex: boolean;
  readonly spectralRadius: number;
  readonly algebraicConnectivity: number;
  readonly filtrationSeries: readonly FiltrationStep[];
  readonly anomalies: readonly string[];
  readonly timestampIso: string;
}

function getDb(): any {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    return require('../../db/database').db;
  } catch (_) {
    return null;
  }
}

export class HypergraphNeuralOperator {
  constructor() {
    this.ensureDatabaseTable();
  }

  public ensureDatabaseTable(): void {
    const db = getDb();
    if (!db) return;
    try {
      db.exec(`
        CREATE TABLE IF NOT EXISTS ejii_hypergraph_topologies (
          topology_id TEXT PRIMARY KEY,
          node_count INTEGER NOT NULL,
          hyperedge_count INTEGER NOT NULL,
          betti_0 INTEGER NOT NULL,
          betti_1 INTEGER NOT NULL,
          has_vortex INTEGER NOT NULL,
          spectral_radius REAL NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_hypergraph_topologies_time ON ejii_hypergraph_topologies(created_at);
      `);
    } catch (_) {}
  }

  /**
   * Constructs the Incidence Matrix B (|V| x |E|), Vertex degrees D_v, and Hyperedge degrees D_e.
   */
  public computeIncidenceAndDegrees(
    nodes: readonly HypergraphNode[],
    hyperedges: readonly Hyperedge[]
  ): {
    nodeIndexMap: Map<string, number>;
    edgeIndexMap: Map<string, number>;
    B: number[][];
    Dv: number[];
    De: number[];
    weights: number[];
  } {
    const n = nodes.length;
    const m = hyperedges.length;

    const nodeIndexMap = new Map<string, number>();
    nodes.forEach((node, idx) => nodeIndexMap.set(node.id, idx));

    const edgeIndexMap = new Map<string, number>();
    hyperedges.forEach((edge, idx) => edgeIndexMap.set(edge.id, idx));

    const B: number[][] = Array.from({ length: n }, () => new Array(m).fill(0));
    const Dv: number[] = new Array(n).fill(0);
    const De: number[] = new Array(m).fill(0);
    const weights: number[] = new Array(m).fill(1.0);

    for (let j = 0; j < m; j++) {
      const e = hyperedges[j];
      const w = Math.max(0.001, e.weight || 1.0);
      weights[j] = w;

      for (const nodeId of e.nodes) {
        const i = nodeIndexMap.get(nodeId);
        if (i !== undefined) {
          B[i][j] = 1;
          Dv[i] += w;
          De[j] += 1;
        }
      }
    }

    return { nodeIndexMap, edgeIndexMap, B, Dv, De, weights };
  }

  /**
   * Evaluates the Normalized Hypergraph Laplacian operator:
   * L_H = I - D_v^{-1/2} B W D_e^{-1} B^T D_v^{-1/2}
   */
  public computeHypergraphLaplacian(
    nodes: readonly HypergraphNode[],
    hyperedges: readonly Hyperedge[]
  ): {
    L: number[][];
    spectralRadius: number;
    algebraicConnectivity: number;
  } {
    const n = nodes.length;
    const m = hyperedges.length;

    if (n === 0) {
      return { L: [], spectralRadius: 0, algebraicConnectivity: 0 };
    }

    const { B, Dv, De, weights } = this.computeIncidenceAndDegrees(nodes, hyperedges);

    // Compute D_v^{-1/2}
    const invSqrtDv = Dv.map((d) => (d > 0 ? 1.0 / Math.sqrt(d) : 0));
    // Compute W * D_e^{-1}
    const wInvDe = De.map((d, j) => (d > 0 ? weights[j] / d : 0));

    // Construct operator Theta = D_v^{-1/2} B W D_e^{-1} B^T D_v^{-1/2}
    const Theta: number[][] = Array.from({ length: n }, () => new Array(n).fill(0));

    for (let i1 = 0; i1 < n; i1++) {
      for (let i2 = 0; i2 < n; i2++) {
        let sum = 0;
        for (let j = 0; j < m; j++) {
          if (B[i1][j] > 0 && B[i2][j] > 0) {
            sum += B[i1][j] * wInvDe[j] * B[i2][j];
          }
        }
        Theta[i1][i2] = invSqrtDv[i1] * sum * invSqrtDv[i2];
      }
    }

    // L_H = I - Theta
    const L: number[][] = Array.from({ length: n }, (_, i) => {
      const row = new Array(n).fill(0);
      for (let j = 0; j < n; j++) {
        row[j] = (i === j ? 1.0 : 0.0) - Theta[i][j];
      }
      return row;
    });

    // Estimate Spectral Radius via Power Iteration
    const spectralRadius = this.estimateSpectralRadius(L, n);

    // Estimate Algebraic Connectivity (second smallest eigenvalue)
    const algebraicConnectivity = this.estimateAlgebraicConnectivity(L, n);

    return {
      L,
      spectralRadius: Math.round(spectralRadius * 1000) / 1000,
      algebraicConnectivity: Math.round(algebraicConnectivity * 1000) / 1000
    };
  }

  private estimateSpectralRadius(matrix: number[][], size: number): number {
    if (size === 0) return 0;
    let v = new Array(size).fill(1 / Math.sqrt(size));
    let lambda = 0;

    for (let iter = 0; iter < 25; iter++) {
      const Av = new Array(size).fill(0);
      for (let i = 0; i < size; i++) {
        for (let j = 0; j < size; j++) {
          Av[i] += matrix[i][j] * v[j];
        }
      }

      let norm = 0;
      for (let i = 0; i < size; i++) norm += Av[i] * Av[i];
      norm = Math.sqrt(norm);

      if (norm < 1e-9) break;
      lambda = norm;
      v = Av.map((x) => x / norm);
    }

    return lambda;
  }

  private estimateAlgebraicConnectivity(L: number[][], size: number): number {
    if (size <= 1) return 0;

    // Smallest eigenvalue is 0 with eigenvector (1, 1, ..., 1) * D_v^{1/2}
    // Deflate with first eigenvector
    let v0 = new Array(size).fill(1 / Math.sqrt(size));
    let v = Array.from({ length: size }, (_, i) => Math.sin(i + 1));

    // Orthogonalize against v0
    let dot = v.reduce((sum, val, idx) => sum + val * v0[idx], 0);
    v = v.map((val, idx) => val - dot * v0[idx]);
    let norm = Math.sqrt(v.reduce((sum, val) => sum + val * val, 0));
    if (norm > 0) v = v.map((x) => x / norm);

    let lambda2 = 0;
    for (let iter = 0; iter < 30; iter++) {
      const Lv = new Array(size).fill(0);
      for (let i = 0; i < size; i++) {
        for (let j = 0; j < size; j++) {
          Lv[i] += L[i][j] * v[j];
        }
      }

      // Re-orthogonalize against v0
      dot = Lv.reduce((sum, val, idx) => sum + val * v0[idx], 0);
      for (let i = 0; i < size; i++) Lv[i] -= dot * v0[i];

      norm = Math.sqrt(Lv.reduce((sum, val) => sum + val * val, 0));
      if (norm < 1e-9) break;

      // Rayleigh quotient
      let rayleigh = 0;
      for (let i = 0; i < size; i++) rayleigh += v[i] * Lv[i];
      lambda2 = Math.max(0, rayleigh);

      v = Lv.map((x) => x / norm);
    }

    return Math.max(0, lambda2);
  }

  /**
   * Evaluates Persistent Homology across metric filtration thresholds:
   *  \beta_0 = number of connected components
   *  \beta_1 = 1-dimensional homology cycles (Euler-Poincare formula \chi = |V| - |E| = \beta_0 - \beta_1)
   */
  public computePersistentHomology(
    nodes: readonly HypergraphNode[],
    hyperedges: readonly Hyperedge[],
    filtrationThresholds: readonly number[] = [10.0, 25.0, 50.0, 100.0, 200.0]
  ): {
    filtrationSeries: FiltrationStep[];
    topologicalVortexDetected: boolean;
    betti0: number;
    betti1: number;
  } {
    const n = nodes.length;
    if (n === 0) {
      return {
        filtrationSeries: [],
        topologicalVortexDetected: false,
        betti0: 0,
        betti1: 0
      };
    }

    const filtrationSeries: FiltrationStep[] = [];
    let persistentVortexCount = 0;

    for (const threshold of filtrationThresholds) {
      // Filter hyperedges active under metric cost threshold
      const activeEdges = hyperedges.filter((e) => (e.metricCost ?? e.weight) <= threshold);

      // Disjoint-set union-find for connected components (\beta_0)
      const parent = new Map<string, string>();
      nodes.forEach((node) => parent.set(node.id, node.id));

      const find = (id: string): string => {
        let root = id;
        while (parent.get(root) !== root) {
          root = parent.get(root)!;
        }
        let curr = id;
        while (curr !== root) {
          const next = parent.get(curr)!;
          parent.set(curr, root);
          curr = next;
        }
        return root;
      };

      const union = (id1: string, id2: string): boolean => {
        const root1 = find(id1);
        const root2 = find(id2);
        if (root1 !== root2) {
          parent.set(root2, root1);
          return true;
        }
        return false;
      };

      // Each hyperedge connects all its member nodes in a clique/star complex
      let pairwiseEdgeCount = 0;
      for (const e of activeEdges) {
        const members = e.nodes.filter((nodeId) => parent.has(nodeId));
        if (members.length > 1) {
          for (let i = 0; i < members.length; i++) {
            for (let j = i + 1; j < members.length; j++) {
              union(members[i], members[j]);
              pairwiseEdgeCount++;
            }
          }
        }
      }

      // Count distinct roots for \beta_0
      const uniqueRoots = new Set<string>();
      nodes.forEach((node) => uniqueRoots.add(find(node.id)));
      const betti0 = uniqueRoots.size;

      // Euler characteristic \chi = |V| - |E| = \beta_0 - \beta_1
      // Hence \beta_1 = pairwiseEdgeCount - |V| + \beta_0
      const betti1 = Math.max(0, pairwiseEdgeCount - n + betti0);

      if (betti1 >= 1) {
        persistentVortexCount++;
      }

      filtrationSeries.push({
        threshold,
        activeHyperedges: activeEdges.length,
        betti0,
        betti1,
        eulerCharacteristic: n - pairwiseEdgeCount
      });
    }

    const baselineStep = filtrationSeries[filtrationSeries.length - 1];
    const betti0 = baselineStep ? baselineStep.betti0 : 1;
    const betti1 = baselineStep ? baselineStep.betti1 : 0;
    const topologicalVortexDetected = persistentVortexCount >= 2;

    return {
      filtrationSeries,
      topologicalVortexDetected,
      betti0,
      betti1
    };
  }

  /**
   * Runs the full Non-Euclidean Hypergraph Neural Operator Pipeline
   */
  public analyzeHypergraph(
    nodes: readonly HypergraphNode[],
    hyperedges: readonly Hyperedge[],
    options?: { filtrationThresholds?: readonly number[]; topologyId?: string }
  ): HypergraphTopologyReport {
    const topologyId = options?.topologyId || `topo_hg_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const timestampIso = new Date().toISOString();

    const { spectralRadius, algebraicConnectivity } = this.computeHypergraphLaplacian(nodes, hyperedges);
    const { filtrationSeries, topologicalVortexDetected, betti0, betti1 } =
      this.computePersistentHomology(nodes, hyperedges, options?.filtrationThresholds);

    const anomalies: string[] = [];

    if (topologicalVortexDetected) {
      anomalies.push(`TOPOLOGICAL_ROUTING_VORTEX_DETECTED: Persistent 1D homology cycle (beta_1 = ${betti1})`);
    }

    if (betti0 > 1) {
      anomalies.push(`HYPERGRAPH_PARTITION_DETECTED: Disconnected topology components (beta_0 = ${betti0})`);
    }

    if (algebraicConnectivity < 0.05 && nodes.length > 2) {
      anomalies.push(`FRAGILE_HYPERGRAPH_BOTTLENECK: Near-zero algebraic connectivity (lambda_2 = ${algebraicConnectivity})`);
    }

    const report: HypergraphTopologyReport = {
      topologyId,
      nodeCount: nodes.length,
      hyperedgeCount: hyperedges.length,
      betti0,
      betti1,
      hasVortex: topologicalVortexDetected,
      spectralRadius,
      algebraicConnectivity,
      filtrationSeries,
      anomalies,
      timestampIso
    };

    this.persistTopology(report);
    return report;
  }

  private persistTopology(report: HypergraphTopologyReport): void {
    const db = getDb();
    if (!db) return;
    try {
      const stmt = db.prepare(`
        INSERT OR REPLACE INTO ejii_hypergraph_topologies (
          topology_id, node_count, hyperedge_count, betti_0, betti_1,
          has_vortex, spectral_radius
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `);
      stmt.run(
        report.topologyId,
        report.nodeCount,
        report.hyperedgeCount,
        report.betti0,
        report.betti1,
        report.hasVortex ? 1 : 0,
        report.spectralRadius
      );
    } catch (_) {}
  }
}

export const hypergraphNeuralOperator = new HypergraphNeuralOperator();
