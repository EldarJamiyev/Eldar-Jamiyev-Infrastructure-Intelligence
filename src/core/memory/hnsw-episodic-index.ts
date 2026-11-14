/**
 * EJII Phase 5.0 — Hierarchical Navigable Small World (HNSW) Vector Graph Index
 * & Multi-Scale Incident Cascade Clustering (Louvain Modularity)
 *
 * Implements:
 *   1. O(log N) Multi-Layer HNSW Metric Graph Index (M=16, M0=32, efConstruction=64, efSearch=32)
 *   2. Normalized 64-Dimensional Cosine Metric Space
 *   3. Newman-Girvan Modularity Community Detection (Louvain Algorithm) for Incident Cascades
 *   4. JSON Serialization & Sub-Millisecond Search Retrieval
 */

export interface VectorSearchResult<T = any> {
  id: string;
  distance: number;
  similarity: number;
  payload: T;
}

export interface HnswNode<T = any> {
  id: string;
  vector: number[];
  payload: T;
  level: number;
  neighbors: Map<number, Set<string>>;
}

export interface IncidentGraphEdge {
  source: string;
  target: string;
  weight: number;
}

export interface IncidentCommunity {
  communityId: number;
  incidentIds: string[];
  totalWeight: number;
  internalWeight: number;
  modularityContribution: number;
}

export interface CascadeClusteringResult {
  communities: IncidentCommunity[];
  modularityQ: number;
  nodesCount: number;
  edgesCount: number;
}

export interface HnswIndexConfig {
  M?: number;
  M0?: number;
  efConstruction?: number;
  efSearch?: number;
  mL?: number;
  dimensions?: number;
}

export class HnswEpisodicIndex<T = any> {
  public readonly M: number;
  public readonly M0: number;
  public readonly efConstruction: number;
  public readonly efSearch: number;
  public readonly mL: number;
  public readonly dimensions: number;

  private nodes: Map<string, HnswNode<T>> = new Map();
  private enterNodeId: string | null = null;
  private maxLevel: number = -1;

  constructor(config: HnswIndexConfig = {}) {
    this.M = config.M || 16;
    this.M0 = config.M0 || 32;
    this.efConstruction = config.efConstruction || 64;
    this.efSearch = config.efSearch || 32;
    this.mL = config.mL || 1.0 / Math.log(this.M);
    this.dimensions = config.dimensions || 64;
  }

  public size(): number {
    return this.nodes.size;
  }

  public getMaxLevel(): number {
    return this.maxLevel;
  }

  /**
   * Deterministic 64D feature projection from telemetry attributes
   */
  public projectTelemetryTo64D(telemetry: Record<string, any>): number[] {
    const vec = new Float64Array(this.dimensions);
    const keys = Object.keys(telemetry).sort();

    for (let i = 0; i < keys.length; i++) {
      const k = keys[i];
      const val = typeof telemetry[k] === 'number' ? Number(telemetry[k]) : 1.0;
      // Distribute features across dimensions using deterministic hash
      let h = 0x811c9dc5;
      for (let c = 0; c < k.length; c++) {
        h ^= k.charCodeAt(c);
        h = Math.imul(h, 0x01000193);
      }
      const idx1 = Math.abs(h) % this.dimensions;
      const idx2 = Math.abs(h >> 5) % this.dimensions;
      const idx3 = Math.abs(h >> 11) % this.dimensions;

      vec[idx1] += val * 0.5;
      vec[idx2] += Math.sin(val) * 0.3;
      vec[idx3] += Math.cos(val) * 0.2;
    }

    // Add positional baseline signature
    for (let d = 0; d < this.dimensions; d++) {
      vec[d] += Math.sin((d + 1) * 0.2);
    }

    return this.normalizeVector(Array.from(vec));
  }

  /**
   * L2 Vector Normalization
   */
  public normalizeVector(vec: number[]): number[] {
    let sumSq = 0;
    for (let i = 0; i < vec.length; i++) {
      sumSq += vec[i] * vec[i];
    }
    const norm = Math.sqrt(sumSq);
    if (norm < 1e-12) return new Array(vec.length).fill(0);
    const normalized = new Array(vec.length);
    for (let i = 0; i < vec.length; i++) {
      normalized[i] = vec[i] / norm;
    }
    return normalized;
  }

  /**
   * Projected Cosine Distance: D_cos(u, v) = 1 - (u . v) / (||u|| * ||v||)
   * Returns value in range [0, 2]
   */
  public computeCosineDistance(u: number[], v: number[]): number {
    let dot = 0;
    let normU = 0;
    let normV = 0;
    const len = Math.min(u.length, v.length);

    for (let i = 0; i < len; i++) {
      dot += u[i] * v[i];
      normU += u[i] * u[i];
      normV += v[i] * v[i];
    }

    if (normU < 1e-12 || normV < 1e-12) return 1.0;
    const similarity = dot / (Math.sqrt(normU) * Math.sqrt(normV));
    // Clamp to [-1, 1] for numerical stability
    const clamped = Math.max(-1.0, Math.min(1.0, similarity));
    return Math.max(0, 1.0 - clamped);
  }

  /**
   * Random level assignment using exponential decay: l = floor(-ln(uniform(0, 1)) * mL)
   */
  private generateRandomLevel(): number {
    const r = Math.max(1e-10, Math.random());
    return Math.floor(-Math.log(r) * this.mL);
  }

  /**
   * Insert vector into HNSW index with multi-layer bidirectional edge wiring
   */
  public insert(id: string, vector: number[], payload: T): void {
    const normVec = this.normalizeVector(vector);
    const nodeLevel = this.generateRandomLevel();

    const node: HnswNode<T> = {
      id,
      vector: normVec,
      payload,
      level: nodeLevel,
      neighbors: new Map()
    };

    for (let l = 0; l <= nodeLevel; l++) {
      node.neighbors.set(l, new Set());
    }

    if (this.enterNodeId === null || this.nodes.size === 0) {
      this.nodes.set(id, node);
      this.enterNodeId = id;
      this.maxLevel = nodeLevel;
      return;
    }

    let currObj = this.nodes.get(this.enterNodeId)!;
    let currDist = this.computeCosineDistance(normVec, currObj.vector);

    // 1. Greedy routing from top level down to nodeLevel + 1
    for (let level = this.maxLevel; level > nodeLevel; level--) {
      let changed = true;
      while (changed) {
        changed = false;
        const neighborIds = currObj.neighbors.get(level) || new Set();
        for (const nId of neighborIds) {
          const neighbor = this.nodes.get(nId);
          if (!neighbor) continue;
          const dist = this.computeCosineDistance(normVec, neighbor.vector);
          if (dist < currDist) {
            currDist = dist;
            currObj = neighbor;
            changed = true;
          }
        }
      }
    }

    // 2. From min(maxLevel, nodeLevel) down to level 0: search candidates and wire bidirectional edges
    const topLevelForInsert = Math.min(this.maxLevel, nodeLevel);
    let epList: Array<{ id: string; dist: number }> = [{ id: currObj.id, dist: currDist }];

    for (let level = topLevelForInsert; level >= 0; level--) {
      const candidates = this.searchLevelCandidates(normVec, epList, this.efConstruction, level);
      const maxM = level === 0 ? this.M0 : this.M;
      const selectedNeighbors = this.selectNeighbors(candidates, maxM);

      // Connect node to selected neighbors
      for (const neighborId of selectedNeighbors) {
        node.neighbors.get(level)!.add(neighborId);
        const neighborNode = this.nodes.get(neighborId);
        if (neighborNode) {
          const nNeighbors = neighborNode.neighbors.get(level);
          if (nNeighbors) {
            nNeighbors.add(node.id);
            // Prune excess edges on neighbor if degree exceeds maxM
            if (nNeighbors.size > maxM) {
              this.pruneNeighbors(neighborNode, level, maxM);
            }
          }
        }
      }

      epList = candidates;
    }

    this.nodes.set(id, node);

    if (nodeLevel > this.maxLevel) {
      this.maxLevel = nodeLevel;
      this.enterNodeId = id;
    }
  }

  /**
   * Search level with beam search width ef
   */
  private searchLevelCandidates(
    queryVec: number[],
    enterPoints: Array<{ id: string; dist: number }>,
    ef: number,
    level: number
  ): Array<{ id: string; dist: number }> {
    const visited = new Set<string>();
    const candidates: Array<{ id: string; dist: number }> = [];
    const w: Array<{ id: string; dist: number }> = [];

    for (const ep of enterPoints) {
      visited.add(ep.id);
      candidates.push(ep);
      w.push(ep);
    }

    candidates.sort((a, b) => a.dist - b.dist);
    w.sort((a, b) => a.dist - b.dist);

    while (candidates.length > 0) {
      const c = candidates.shift()!;
      const furthestInW = w[w.length - 1];

      if (c.dist > furthestInW.dist && w.length >= ef) {
        break;
      }

      const cNode = this.nodes.get(c.id);
      if (!cNode) continue;
      const neighborIds = cNode.neighbors.get(level) || new Set();

      for (const eId of neighborIds) {
        if (visited.has(eId)) continue;
        visited.add(eId);

        const eNode = this.nodes.get(eId);
        if (!eNode) continue;
        const dist = this.computeCosineDistance(queryVec, eNode.vector);

        const currentFurthest = w[w.length - 1];
        if (dist < currentFurthest.dist || w.length < ef) {
          const entry = { id: eId, dist };
          candidates.push(entry);
          candidates.sort((a, b) => a.dist - b.dist);

          w.push(entry);
          w.sort((a, b) => a.dist - b.dist);
          if (w.length > ef) {
            w.pop();
          }
        }
      }
    }

    return w;
  }

  private selectNeighbors(candidates: Array<{ id: string; dist: number }>, maxM: number): string[] {
    const sorted = [...candidates].sort((a, b) => a.dist - b.dist);
    return sorted.slice(0, maxM).map(c => c.id);
  }

  private pruneNeighbors(node: HnswNode<T>, level: number, maxM: number): void {
    const neighborSet = node.neighbors.get(level);
    if (!neighborSet || neighborSet.size <= maxM) return;

    const list: Array<{ id: string; dist: number }> = [];
    for (const nId of neighborSet) {
      const nNode = this.nodes.get(nId);
      if (nNode) {
        list.push({ id: nId, dist: this.computeCosineDistance(node.vector, nNode.vector) });
      }
    }

    list.sort((a, b) => a.dist - b.dist);
    neighborSet.clear();
    for (let i = 0; i < Math.min(list.length, maxM); i++) {
      neighborSet.add(list[i].id);
    }
  }

  /**
   * K-Nearest Neighbors sub-millisecond search
   */
  public searchKNN(queryVector: number[], k: number = 5, efSearch: number = this.efSearch): VectorSearchResult<T>[] {
    if (this.nodes.size === 0 || this.enterNodeId === null) {
      return [];
    }

    const normQuery = this.normalizeVector(queryVector);
    let currObj = this.nodes.get(this.enterNodeId)!;
    let currDist = this.computeCosineDistance(normQuery, currObj.vector);

    // Greedy routing from top level down to 1
    for (let level = this.maxLevel; level > 0; level--) {
      let changed = true;
      while (changed) {
        changed = false;
        const neighborIds = currObj.neighbors.get(level) || new Set();
        for (const nId of neighborIds) {
          const neighbor = this.nodes.get(nId);
          if (!neighbor) continue;
          const dist = this.computeCosineDistance(normQuery, neighbor.vector);
          if (dist < currDist) {
            currDist = dist;
            currObj = neighbor;
            changed = true;
          }
        }
      }
    }

    // Search layer 0 with efSearch
    const ef = Math.max(efSearch, k);
    const candidates = this.searchLevelCandidates(normQuery, [{ id: currObj.id, dist: currDist }], ef, 0);

    const results: VectorSearchResult<T>[] = [];
    for (let i = 0; i < Math.min(k, candidates.length); i++) {
      const c = candidates[i];
      const node = this.nodes.get(c.id);
      if (node) {
        results.push({
          id: node.id,
          distance: Math.round(c.dist * 10000) / 10000,
          similarity: Math.round((1.0 - c.dist) * 10000) / 10000,
          payload: node.payload
        });
      }
    }

    return results;
  }

  /**
   * Linear Brute Force KNN (for exact baseline verification and recall benchmarking)
   */
  public searchExactKNN(queryVector: number[], k: number = 5): VectorSearchResult<T>[] {
    const normQuery = this.normalizeVector(queryVector);
    const all: Array<{ id: string; dist: number; node: HnswNode<T> }> = [];

    for (const [id, node] of this.nodes) {
      const dist = this.computeCosineDistance(normQuery, node.vector);
      all.push({ id, dist, node });
    }

    all.sort((a, b) => a.dist - b.dist);
    return all.slice(0, k).map(a => ({
      id: a.id,
      distance: Math.round(a.dist * 10000) / 10000,
      similarity: Math.round((1.0 - a.dist) * 10000) / 10000,
      payload: a.node.payload
    }));
  }

  /**
   * Louvain Modularity Community Detection on Incident Co-occurrence Graphs
   * Partitions the incident graph into cohesive communities by maximizing Newman-Girvan modularity:
   * Q = 1/(2m) * sum_{i,j} [ A_ij - (k_i * k_j)/(2m) ] * delta(c_i, c_j)
   */
  public clusterIncidentCascades(edges: IncidentGraphEdge[]): CascadeClusteringResult {
    if (!edges || edges.length === 0) {
      return { communities: [], modularityQ: 0, nodesCount: 0, edgesCount: 0 };
    }

    const nodeSet = new Set<string>();
    const adjacency: Map<string, Map<string, number>> = new Map();
    const nodeDegree: Map<string, number> = new Map();
    let totalEdgeWeight2m = 0;

    for (const edge of edges) {
      nodeSet.add(edge.source);
      nodeSet.add(edge.target);
      const w = Math.max(0.1, Number(edge.weight) || 1.0);
      totalEdgeWeight2m += 2 * w;

      if (!adjacency.has(edge.source)) adjacency.set(edge.source, new Map());
      if (!adjacency.has(edge.target)) adjacency.set(edge.target, new Map());

      const cur1 = adjacency.get(edge.source)!.get(edge.target) || 0;
      adjacency.get(edge.source)!.set(edge.target, cur1 + w);

      const cur2 = adjacency.get(edge.target)!.get(edge.source) || 0;
      adjacency.get(edge.target)!.set(edge.source, cur2 + w);

      nodeDegree.set(edge.source, (nodeDegree.get(edge.source) || 0) + w);
      nodeDegree.set(edge.target, (nodeDegree.get(edge.target) || 0) + w);
    }

    const nodes = Array.from(nodeSet);
    const m = totalEdgeWeight2m / 2;

    // Initial partition: each node is in its own community
    const communityAssignment: Map<string, string> = new Map();
    const communityTotalDegree: Map<string, number> = new Map();

    for (const n of nodes) {
      communityAssignment.set(n, n);
      communityTotalDegree.set(n, nodeDegree.get(n) || 0);
    }

    let improvement = true;
    let iterations = 0;
    const maxIterations = 20;

    while (improvement && iterations < maxIterations) {
      improvement = false;
      iterations++;

      for (const i of nodes) {
        const currentComm = communityAssignment.get(i)!;
        const ki = nodeDegree.get(i) || 0;

        // Remove node i from current community
        communityTotalDegree.set(currentComm, (communityTotalDegree.get(currentComm) || 0) - ki);

        // Find neighbor communities and compute weights to them
        const neighborCommunities: Map<string, number> = new Map();
        const neighbors = adjacency.get(i) || new Map();

        for (const [neighbor, weight] of neighbors) {
          const nComm = communityAssignment.get(neighbor)!;
          neighborCommunities.set(nComm, (neighborCommunities.get(nComm) || 0) + weight);
        }

        let bestComm = currentComm;
        let bestGain = 0;

        for (const [c, k_i_in] of neighborCommunities) {
          const totDegree = communityTotalDegree.get(c) || 0;
          // Louvain modularity gain formula: Delta Q = [ k_i_in / m ] - [ 2 * totDegree * ki / (2m)^2 ]
          const gain = (k_i_in / m) - ((totDegree * ki) / (2 * m * m));
          if (gain > bestGain) {
            bestGain = gain;
            bestComm = c;
          }
        }

        // Place node into best community
        communityAssignment.set(i, bestComm);
        communityTotalDegree.set(bestComm, (communityTotalDegree.get(bestComm) || 0) + ki);

        if (bestComm !== currentComm) {
          improvement = true;
        }
      }
    }

    // Compute Newman-Girvan modularity Q
    let modularityQ = 0;
    for (const u of nodes) {
      for (const v of nodes) {
        if (communityAssignment.get(u) === communityAssignment.get(v)) {
          const A_uv = adjacency.get(u)?.get(v) || 0;
          const ku = nodeDegree.get(u) || 0;
          const kv = nodeDegree.get(v) || 0;
          modularityQ += A_uv - (ku * kv) / (2 * m);
        }
      }
    }
    modularityQ = modularityQ / (2 * m);

    // Group communities
    const grouped: Map<string, string[]> = new Map();
    for (const [n, c] of communityAssignment) {
      if (!grouped.has(c)) grouped.set(c, []);
      grouped.get(c)!.push(n);
    }

    let cIndex = 0;
    const communities: IncidentCommunity[] = [];
    for (const [, incIds] of grouped) {
      let internalWeight = 0;
      let totalWeight = 0;
      for (const id of incIds) {
        totalWeight += nodeDegree.get(id) || 0;
        const neighbors = adjacency.get(id) || new Map();
        for (const targetId of incIds) {
          internalWeight += neighbors.get(targetId) || 0;
        }
      }
      internalWeight = internalWeight / 2; // Undirected double count correction

      communities.push({
        communityId: ++cIndex,
        incidentIds: incIds,
        totalWeight: Math.round(totalWeight * 100) / 100,
        internalWeight: Math.round(internalWeight * 100) / 100,
        modularityContribution: Math.round((internalWeight / m - Math.pow(totalWeight / (2 * m), 2)) * 10000) / 10000
      });
    }

    // Sort by incident count descending
    communities.sort((a, b) => b.incidentIds.length - a.incidentIds.length);

    return {
      communities,
      modularityQ: Math.round(modularityQ * 10000) / 10000,
      nodesCount: nodes.length,
      edgesCount: edges.length
    };
  }

  /**
   * Serializes the HNSW index to JSON
   */
  public toJSON(): string {
    const serializedNodes: any[] = [];
    for (const [id, node] of this.nodes) {
      const neighborsObj: Record<number, string[]> = {};
      for (const [level, nSet] of node.neighbors) {
        neighborsObj[level] = Array.from(nSet);
      }
      serializedNodes.push({
        id,
        vector: node.vector,
        payload: node.payload,
        level: node.level,
        neighbors: neighborsObj
      });
    }

    return JSON.stringify({
      M: this.M,
      M0: this.M0,
      efConstruction: this.efConstruction,
      efSearch: this.efSearch,
      mL: this.mL,
      dimensions: this.dimensions,
      enterNodeId: this.enterNodeId,
      maxLevel: this.maxLevel,
      nodes: serializedNodes
    });
  }

  /**
   * Deserializes HNSW index from JSON string
   */
  public static fromJSON<T = any>(jsonStr: string): HnswEpisodicIndex<T> {
    const data = JSON.parse(jsonStr);
    const index = new HnswEpisodicIndex<T>({
      M: data.M,
      M0: data.M0,
      efConstruction: data.efConstruction,
      efSearch: data.efSearch,
      mL: data.mL,
      dimensions: data.dimensions
    });

    index.enterNodeId = data.enterNodeId;
    index.maxLevel = data.maxLevel;

    for (const n of data.nodes) {
      const neighborsMap = new Map<number, Set<string>>();
      for (const levelStr of Object.keys(n.neighbors)) {
        const lvl = Number(levelStr);
        neighborsMap.set(lvl, new Set(n.neighbors[levelStr]));
      }

      index.nodes.set(n.id, {
        id: n.id,
        vector: n.vector,
        payload: n.payload,
        level: n.level,
        neighbors: neighborsMap
      });
    }

    return index;
  }
}

export const hnswEpisodicIndex = new HnswEpisodicIndex();
