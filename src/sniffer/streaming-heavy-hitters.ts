/**
 * EJII Streaming Heavy-Hitters & Count-Min Sketch Engine
 *
 * Line-rate streaming frequency estimation with continuous exponential time-decay
 * and Space-Saving heavy-hitter tracking for microburst and volumetric anomaly detection.
 * Dual-Maintenance TypeScript Reference.
 */

export interface HeavyHitterEntry {
  flowKey: string;
  estimatedBytes: number;
  packetCount: number;
  bandwidthBps: number;
  lastSeenMs: number;
}

export interface StreamingSketchStats {
  totalPackets: number;
  totalBytes: number;
  activeFlowsCount: number;
  width: number;
  depth: number;
  decayHalfLifeSec: number;
}

export class StreamingHeavyHitters {
  private width: number;
  private depth: number;
  private matrix: Float64Array;
  private seeds: Uint32Array;
  private decayHalfLifeSec: number;
  private lambdaPerMs: number;
  private lastDecayTimeMs: number;

  private totalPackets: number = 0;
  private totalBytes: number = 0;

  // Space-saving Top-K tracked flows
  private trackedFlows: Map<string, { bytes: number; packets: number; firstSeenMs: number; lastSeenMs: number }> = new Map();
  private maxTrackedFlows: number = 64;

  constructor(options?: { width?: number; depth?: number; decayHalfLifeSec?: number; maxTrackedFlows?: number }) {
    this.width = options?.width || 4096;
    this.depth = options?.depth || 5;
    this.decayHalfLifeSec = options?.decayHalfLifeSec || 5.0;
    this.maxTrackedFlows = options?.maxTrackedFlows || 64;

    this.matrix = new Float64Array(this.depth * this.width);
    this.seeds = new Uint32Array([0x9747b28c, 0xc141f767, 0x517cc1b7, 0x76274415, 0x3b246a51]);
    this.lambdaPerMs = Math.LN2 / (this.decayHalfLifeSec * 1000);
    this.lastDecayTimeMs = Date.now();
  }

  public recordPacket(
    flowKey: string,
    byteCount: number,
    timestampMs: number = Date.now()
  ): { estimatedBytes: number; isHeavyHitter: boolean } {
    this.applyDecay(timestampMs);

    this.totalPackets++;
    this.totalBytes += byteCount;

    // Update Count-Min Sketch with Conservative Update
    let minVal = Infinity;
    const indices: number[] = [];

    for (let d = 0; d < this.depth; d++) {
      const col = this.hash(flowKey, this.seeds[d]) % this.width;
      const idx = d * this.width + col;
      indices.push(idx);
      if (this.matrix[idx] < minVal) {
        minVal = this.matrix[idx];
      }
    }

    const newVal = minVal + byteCount;
    for (const idx of indices) {
      if (this.matrix[idx] < newVal) {
        this.matrix[idx] = newVal;
      }
    }

    // Space-Saving update
    let entry = this.trackedFlows.get(flowKey);
    if (!entry) {
      if (this.trackedFlows.size >= this.maxTrackedFlows) {
        // Evict item with smallest estimated volume
        let minKey = '';
        let minBytes = Infinity;
        for (const [k, v] of this.trackedFlows.entries()) {
          if (v.bytes < minBytes) {
            minBytes = v.bytes;
            minKey = k;
          }
        }
        if (minKey) {
          this.trackedFlows.delete(minKey);
        }
      }
      entry = { bytes: byteCount, packets: 1, firstSeenMs: timestampMs, lastSeenMs: timestampMs };
      this.trackedFlows.set(flowKey, entry);
    } else {
      entry.bytes += byteCount;
      entry.packets++;
      entry.lastSeenMs = timestampMs;
    }

    // Heavy hitter if flow constitutes >= 10% of window volume or >= 50KB in last window
    const isHeavyHitter = newVal >= 50000 || (this.totalBytes > 0 && newVal / this.totalBytes >= 0.1);

    return {
      estimatedBytes: newVal,
      isHeavyHitter
    };
  }

  public estimateFrequency(flowKey: string): number {
    let minVal = Infinity;
    for (let d = 0; d < this.depth; d++) {
      const col = this.hash(flowKey, this.seeds[d]) % this.width;
      const idx = d * this.width + col;
      if (this.matrix[idx] < minVal) {
        minVal = this.matrix[idx];
      }
    }
    return minVal === Infinity ? 0 : minVal;
  }

  public getTopHeavyHitters(limit: number = 10): HeavyHitterEntry[] {
    const now = Date.now();
    const result: HeavyHitterEntry[] = [];

    for (const [flowKey, v] of this.trackedFlows.entries()) {
      const estimatedBytes = this.estimateFrequency(flowKey);
      const durationSec = Math.max(0.1, (v.lastSeenMs - v.firstSeenMs) / 1000);
      const bandwidthBps = (v.bytes * 8) / durationSec;

      result.push({
        flowKey,
        estimatedBytes,
        packetCount: v.packets,
        bandwidthBps,
        lastSeenMs: v.lastSeenMs
      });
    }

    result.sort((a, b) => b.estimatedBytes - a.estimatedBytes);
    return result.slice(0, limit);
  }

  public reset(): void {
    this.matrix.fill(0);
    this.trackedFlows.clear();
    this.totalPackets = 0;
    this.totalBytes = 0;
    this.lastDecayTimeMs = Date.now();
  }

  public getStats(): StreamingSketchStats {
    return {
      totalPackets: this.totalPackets,
      totalBytes: this.totalBytes,
      activeFlowsCount: this.trackedFlows.size,
      width: this.width,
      depth: this.depth,
      decayHalfLifeSec: this.decayHalfLifeSec
    };
  }

  private applyDecay(nowMs: number): void {
    const elapsedMs = nowMs - this.lastDecayTimeMs;
    if (elapsedMs < 500) {
      return;
    }

    const decayFactor = Math.exp(-this.lambdaPerMs * elapsedMs);
    for (let i = 0; i < this.matrix.length; i++) {
      this.matrix[i] *= decayFactor;
    }

    for (const entry of this.trackedFlows.values()) {
      entry.bytes *= decayFactor;
    }

    this.lastDecayTimeMs = nowMs;
  }

  private hash(key: string, seed: number): number {
    let h = seed ^ key.length;
    for (let i = 0; i < key.length; i++) {
      h = Math.imul(h ^ key.charCodeAt(i), 0x5bd1e995);
      h ^= h >>> 15;
    }
    return (h >>> 0);
  }
}

export const streamingHeavyHitters = new StreamingHeavyHitters();
