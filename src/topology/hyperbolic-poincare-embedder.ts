/**
 * EJII Hyperbolic Poincaré Disk Embedder
 *
 * Maps complex hierarchical network topologies into the 2D Poincaré disk model
 * (D^2, d_D) preserving non-Euclidean tree-likeness and negative curvature.
 * Dual-Maintenance TypeScript Reference.
 */

export interface PoincareEmbeddingReceipt {
  embeddingId: string;
  dimension: number;
  nodesCount: number;
  edgesCount: number;
  coordinates: Record<string, [number, number]>;
  averageRadius: number;
  distortionScore: number;
  timestamp: number;
}

export class HyperbolicPoincareEmbedder {
  private totalNodesEmbedded: number = 0;
  private lastAverageRadius: number = 0;
  private lastDistortionScore: number = 0;

  constructor() {}

  /**
   * Computes exact geodesic distance in the 2D Poincaré disk model:
   * d_D(u, v) = arcosh(1 + 2 * ||u - v||^2 / ((1 - ||u||^2) * (1 - ||v||^2)))
   */
  public computeHyperbolicDistance(coordA: [number, number], coordB: [number, number]): number {
    const dx = coordA[0] - coordB[0];
    const dy = coordA[1] - coordB[1];
    const diffNormSq = dx * dx + dy * dy;

    if (diffNormSq < 1e-15) {
      return 0.0;
    }

    const uNormSq = Math.min(0.9999, coordA[0] * coordA[0] + coordA[1] * coordA[1]);
    const vNormSq = Math.min(0.9999, coordB[0] * coordB[0] + coordB[1] * coordB[1]);

    const denom = Math.max(1e-14, (1.0 - uNormSq) * (1.0 - vNormSq));
    const arg = 1.0 + (2.0 * diffNormSq) / denom;

    return Math.acosh(Math.max(1.0, arg));
  }

  /**
   * Embeds a network topology into the 2D Poincaré disk.
   */
  public embedTopology(
    nodes: string[],
    edges: Array<{ source: string; target: string; weight?: number }>
  ): PoincareEmbeddingReceipt {
    const embeddingId = `poincare_${Date.now()}_${Math.floor(Math.random() * 10000)}`;
    const n = nodes.length;

    if (n === 0) {
      return {
        embeddingId,
        dimension: 2,
        nodesCount: 0,
        edgesCount: 0,
        coordinates: {},
        averageRadius: 0,
        distortionScore: 0,
        timestamp: Date.now()
      };
    }

    const adj = new Map<string, string[]>();
    for (const node of nodes) {
      adj.set(node, []);
    }
    for (const edge of edges) {
      if (adj.has(edge.source) && adj.has(edge.target)) {
        adj.get(edge.source)!.push(edge.target);
        adj.get(edge.target)!.push(edge.source);
      }
    }

    // Find node with highest degree to serve as the hyperbolic center (core router)
    let root = nodes[0];
    let maxDegree = -1;
    for (const node of nodes) {
      const deg = adj.get(node)!.length;
      if (deg > maxDegree) {
        maxDegree = deg;
        root = node;
      }
    }

    // BFS tree layout in hyperbolic space
    const visited = new Set<string>();
    const depthMap = new Map<string, number>();
    const angleSector = new Map<string, { start: number; end: number }>();
    const coordinates: Record<string, [number, number]> = {};

    visited.add(root);
    depthMap.set(root, 0);
    angleSector.set(root, { start: 0, end: 2 * Math.PI });
    coordinates[root] = [0, 0];

    const queue: string[] = [root];
    let maxDepth = 0;

    while (queue.length > 0) {
      const current = queue.shift()!;
      const curDepth = depthMap.get(current)!;
      maxDepth = Math.max(maxDepth, curDepth);
      const neighbors = (adj.get(current) || []).filter((nb) => !visited.has(nb));

      if (neighbors.length > 0) {
        const sector = angleSector.get(current)!;
        const sectorSpan = sector.end - sector.start;
        const step = sectorSpan / neighbors.length;

        for (let i = 0; i < neighbors.length; i++) {
          const nb = neighbors[i];
          visited.add(nb);
          const nbDepth = curDepth + 1;
          depthMap.set(nb, nbDepth);

          const childSectorStart = sector.start + i * step;
          const childSectorEnd = childSectorStart + step;
          angleSector.set(nb, { start: childSectorStart, end: childSectorEnd });

          const angle = (childSectorStart + childSectorEnd) / 2;
          // Hyperbolic radial scaling: tanh(0.55 * depth)
          const radius = Math.min(0.92, Math.tanh(0.55 * nbDepth));
          coordinates[nb] = [radius * Math.cos(angle), radius * Math.sin(angle)];

          queue.push(nb);
        }
      }
    }

    // Handle disconnected nodes
    for (const node of nodes) {
      if (!visited.has(node)) {
        visited.add(node);
        const idx = Object.keys(coordinates).length;
        const angle = (2 * Math.PI * idx) / n;
        const radius = 0.85;
        coordinates[node] = [radius * Math.cos(angle), radius * Math.sin(angle)];
      }
    }

    // Calculate metrics
    let totalRadius = 0;
    for (const node of nodes) {
      const [x, y] = coordinates[node];
      totalRadius += Math.sqrt(x * x + y * y);
    }
    const averageRadius = totalRadius / n;

    // Estimate metric distortion on connected pairs
    let totalDistortion = 0;
    let sampledPairs = 0;
    const sampleLimit = Math.min(nodes.length, 15);

    for (let i = 0; i < sampleLimit; i++) {
      for (let j = i + 1; j < sampleLimit; j++) {
        const u = nodes[i];
        const v = nodes[j];
        const hypDist = this.computeHyperbolicDistance(coordinates[u], coordinates[v]);
        const dU = depthMap.get(u) || 1;
        const dV = depthMap.get(v) || 1;
        const approxGraphDist = Math.abs(dU - dV) + 1;
        const relErr = Math.abs(hypDist - approxGraphDist) / Math.max(1, approxGraphDist);
        totalDistortion += Math.min(1.0, relErr);
        sampledPairs++;
      }
    }

    const distortionScore = sampledPairs > 0 ? totalDistortion / sampledPairs : 0.05;

    this.totalNodesEmbedded += n;
    this.lastAverageRadius = averageRadius;
    this.lastDistortionScore = distortionScore;

    return {
      embeddingId,
      dimension: 2,
      nodesCount: n,
      edgesCount: edges.length,
      coordinates,
      averageRadius: Number(averageRadius.toFixed(4)),
      distortionScore: Number(distortionScore.toFixed(4)),
      timestamp: Date.now()
    };
  }

  public getMetrics(): { nodesEmbedded: number; averageRadius: number; distortionScore: number } {
    return {
      nodesEmbedded: this.totalNodesEmbedded,
      averageRadius: Number(this.lastAverageRadius.toFixed(4)),
      distortionScore: Number(this.lastDistortionScore.toFixed(4))
    };
  }
}

export const hyperbolicPoincareEmbedder = new HyperbolicPoincareEmbedder();
