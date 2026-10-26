// src/topology/spectral-gnn-apex.ts

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
  readonly criticalCutEdges: readonly { source: string; target: string; spectralTension: number }[];
  readonly nodes: readonly NodeTopologicalIntelligence[];
}

export class SpectralGNNTopologyEngine {
  /**
   * Runs 3-Layer Kipf-Welling Spatial GCN + Spectral Laplacian Fiedler (lambda_2) analysis
   * + Deterministic Rooted Blast Radius computation in pure Float64Array.
   */
  public analyzeTopology(
    nodes: readonly TopologyNode[],
    edges: readonly TopologyEdge[],
    rootWorkstationId: string
  ): SpectralTopologyReport {
    const n = nodes.length;
    if (n === 0) {
      return {
        algebraicConnectivityLambda2: 0,
        partitionRiskLevel: 'NOMINAL',
        criticalCutEdges: [],
        nodes: [],
      };
    }

    const idToIndex = new Map<string, number>();
    nodes.forEach((node, idx) => idToIndex.set(node.id, idx));

    // Weighted Adjacency Matrix W (n x n) and Degree Vector D (n)
    const W = new Float64Array(n * n);
    const D = new Float64Array(n);
    const adjList: number[][] = Array.from({ length: n }, () => []);

    for (const edge of edges) {
      const u = idToIndex.get(edge.source);
      const v = idToIndex.get(edge.target);
      if (u === undefined || v === undefined || u === v) continue;

      // Conductance weight inversely proportional to RTT and loss
      const healthFactor = Math.max(0.05, 1.0 - edge.linkLossPct / 100.0);
      const latencyPenalty = 1.0 / (1.0 + Math.max(0, edge.rttMs) / 25.0);
      const weight = healthFactor * latencyPenalty;

      if (W[u * n + v] === 0) {
        adjList[u].push(v);
        adjList[v].push(u);
      }
      W[u * n + v] = weight;
      W[v * n + u] = weight;
    }

    for (let i = 0; i < n; i++) {
      let deg = 0.0;
      for (let j = 0; j < n; j++) deg += W[i * n + j];
      D[i] = deg;
    }

    // 1. Compute Fiedler Value (lambda_2) and Fiedler Vector (v_2) of Laplacian L = D - W
    const { lambda2, fiedlerVector } = this.computeFiedlerEigenpair(W, D, n);

    // 2. Compute 3-Layer Kipf-Welling GCN Embeddings H^(l+1) = tanh(D_hat^-1/2 A_hat D_hat^-1/2 H^(l) W^(l))
    const gcnEmbeddings = this.compute3LayerKipfWellingGCN(nodes, W, D, n);

    // 3. Identify Critical Spectral Cut Edges (highest |v_2(u) - v_2(v)| across active links)
    const criticalCutEdges: { source: string; target: string; spectralTension: number }[] = [];
    for (const edge of edges) {
      const u = idToIndex.get(edge.source);
      const v = idToIndex.get(edge.target);
      if (u === undefined || v === undefined) continue;
      const tension = Math.abs(fiedlerVector[u] - fiedlerVector[v]);
      if (fiedlerVector[u] * fiedlerVector[v] < 0 || tension > 0.35) {
        criticalCutEdges.push({
          source: edge.source,
          target: edge.target,
          spectralTension: Number(tension.toFixed(4)),
        });
      }
    }
    criticalCutEdges.sort((a, b) => b.spectralTension - a.spectralTension);

    // 4. Deterministic Blast Radius from Root Workstation
    const rootIdx = idToIndex.get(rootWorkstationId) ?? 0;
    const baselineReachable = this.bfsReachable(adjList, rootIdx, -1, n);

    const nodeReports: NodeTopologicalIntelligence[] = nodes.map((node, idx) => {
      const stranded: string[] = [];
      if (idx !== rootIdx) {
        const reachableWithoutIdx = this.bfsReachable(adjList, rootIdx, idx, n);
        for (let targetIdx = 0; targetIdx < n; targetIdx++) {
          if (targetIdx !== idx && baselineReachable[targetIdx] && !reachableWithoutIdx[targetIdx]) {
            stranded.push(nodes[targetIdx].id);
          }
        }
      }

      return {
        nodeId: node.id,
        gcnEmbedding: [
          Number(gcnEmbeddings[idx * 3].toFixed(4)),
          Number(gcnEmbeddings[idx * 3 + 1].toFixed(4)),
          Number(gcnEmbeddings[idx * 3 + 2].toFixed(4)),
        ],
        fiedlerCoordinate: Number(fiedlerVector[idx].toFixed(4)),
        blastRadiusCount: stranded.length,
        strandedDownstreamIds: stranded,
        isArticulationBottleneck: stranded.length > 0,
      };
    });

    const partitionRiskLevel =
      lambda2 < 0.08
        ? 'CRITICAL_PARTITION_IMMINENT'
        : lambda2 < 0.25
        ? 'FRAGILE_BRIDGE'
        : 'NOMINAL';

    return {
      algebraicConnectivityLambda2: Number(lambda2.toFixed(4)),
      partitionRiskLevel,
      criticalCutEdges,
      nodes: nodeReports,
    };
  }

  /**
   * Computes the second-smallest eigenvalue (lambda_2) and eigenvector of L = D - W
   * via shifted inverse-free deflated power iteration orthogonal to the constant 1-vector.
   */
  private computeFiedlerEigenpair(
    W: Float64Array,
    D: Float64Array,
    n: number
  ): { lambda2: number; fiedlerVector: Float64Array } {
    if (n <= 1) {
      return { lambda2: 0, fiedlerVector: new Float64Array(n) };
    }

    // Upper bound on max eigenvalue of L by Gershgorin Circle Theorem: max_i (2 * D[i])
    let maxGershgorin = 1.0;
    for (let i = 0; i < n; i++) {
      if (2.0 * D[i] > maxGershgorin) maxGershgorin = 2.0 * D[i];
    }
    const alpha = maxGershgorin + 1.0;

    // Initialize deterministic non-constant vector orthogonal to 1
    const v = new Float64Array(n);
    for (let i = 0; i < n; i++) {
      v[i] = Math.sin(((i + 1) * Math.PI) / (n + 1));
    }
    this.orthogonalizeAndNormalize(v, n);

    const nextV = new Float64Array(n);
    const ITERATIONS = 60;

    // Power iteration on shifted matrix M = alpha * I - L (whose largest eigenvalue orthogonal to 1 is alpha - lambda_2)
    for (let iter = 0; iter < ITERATIONS; iter++) {
      for (let i = 0; i < n; i++) {
        let l_vi = D[i] * v[i];
        for (let j = 0; j < n; j++) {
          if (i !== j && W[i * n + j] !== 0) {
            l_vi -= W[i * n + j] * v[j];
          }
        }
        nextV[i] = alpha * v[i] - l_vi;
      }
      this.orthogonalizeAndNormalize(nextV, n);
      v.set(nextV);
    }

    // Rayleigh quotient v^T L v
    let rayleigh = 0.0;
    for (let i = 0; i < n; i++) {
      let l_vi = D[i] * v[i];
      for (let j = 0; j < n; j++) {
        if (i !== j) l_vi -= W[i * n + j] * v[j];
      }
      rayleigh += v[i] * l_vi;
    }

    return {
      lambda2: Math.max(0, rayleigh),
      fiedlerVector: v,
    };
  }

  private orthogonalizeAndNormalize(vec: Float64Array, n: number): void {
    let mean = 0.0;
    for (let i = 0; i < n; i++) mean += vec[i];
    mean /= n;

    let normSq = 0.0;
    for (let i = 0; i < n; i++) {
      vec[i] -= mean;
      normSq += vec[i] * vec[i];
    }
    const norm = Math.sqrt(normSq);
    if (norm > 1e-12) {
      for (let i = 0; i < n; i++) vec[i] /= norm;
    }
  }

  private compute3LayerKipfWellingGCN(
    nodes: readonly TopologyNode[],
    W: Float64Array,
    D: Float64Array,
    n: number
  ): Float64Array {
    // Normalized Adjacency with self-loops: A_hat = D_tilde^-1/2 (W + I) D_tilde^-1/2
    const invSqrtDeg = new Float64Array(n);
    for (let i = 0; i < n; i++) {
      invSqrtDeg[i] = 1.0 / Math.sqrt(D[i] + 1.0);
    }

    // Layer 0 input features (n x 3): [normalizedLatency, normalizedLoss, roleEncoding]
    let H = new Float64Array(n * 3);
    const roleWeights: Record<TopologyNode['role'], number> = {
      GATEWAY: 1.0,
      SWITCH: 0.85,
      SERVER: 0.7,
      WORKSTATION: 0.5,
      VOIP: 0.35,
      PRINTER: 0.2,
      ENDPOINT: 0.1,
    };

    for (let i = 0; i < n; i++) {
      H[i * 3] = Math.min(1.0, nodes[i].latencyMs / 200.0);
      H[i * 3 + 1] = Math.min(1.0, nodes[i].packetLossPct / 100.0);
      H[i * 3 + 2] = roleWeights[nodes[i].role] ?? 0.1;
    }

    // Deterministic orthogonal projection weights (3x3) across 3 spatial GCN hops
    const W_proj = new Float64Array([
      0.82, -0.31,  0.48,
      0.39,  0.91, -0.14,
     -0.42,  0.27,  0.86,
    ]);

    for (let layer = 0; layer < 3; layer++) {
      const nextH = new Float64Array(n * 3);
      for (let i = 0; i < n; i++) {
        let agg0 = 0.0;
        let agg1 = 0.0;
        let agg2 = 0.0;

        for (let j = 0; j < n; j++) {
          const w_ij = i === j ? 1.0 : W[i * n + j];
          if (w_ij === 0) continue;
          const normEdge = invSqrtDeg[i] * w_ij * invSqrtDeg[j];
          agg0 += normEdge * H[j * 3];
          agg1 += normEdge * H[j * 3 + 1];
          agg2 += normEdge * H[j * 3 + 2];
        }

        // Linear projection + tanh activation
        nextH[i * 3]     = Math.tanh(agg0 * W_proj[0] + agg1 * W_proj[3] + agg2 * W_proj[6]);
        nextH[i * 3 + 1] = Math.tanh(agg0 * W_proj[1] + agg1 * W_proj[4] + agg2 * W_proj[7]);
        nextH[i * 3 + 2] = Math.tanh(agg0 * W_proj[2] + agg1 * W_proj[5] + agg2 * W_proj[8]);
      }
      H = nextH;
    }

    return H;
  }

  private bfsReachable(
    adjList: readonly number[][],
    startIdx: number,
    excludedIdx: number,
    n: number
  ): Uint8Array {
    const visited = new Uint8Array(n);
    if (startIdx === excludedIdx) return visited;

    const queue = new Int32Array(n);
    let head = 0;
    let tail = 0;

    visited[startIdx] = 1;
    queue[tail++] = startIdx;

    while (head < tail) {
      const curr = queue[head++];
      const neighbors = adjList[curr];
      for (let i = 0; i < neighbors.length; i++) {
        const nxt = neighbors[i];
        if (nxt !== excludedIdx && visited[nxt] === 0) {
          visited[nxt] = 1;
          queue[tail++] = nxt;
        }
      }
    }
    return visited;
  }
}
