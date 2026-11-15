/**
 * EJII Virtual STONITH Split-Brain Fencing Sentinel
 *
 * Enforces automated partition fencing and execution barriers against split-brain
 * edge cloud sites to isolate uncoordinated remediation attempts.
 * Dual-Maintenance TypeScript Reference.
 */

export interface FencingReceipt {
  regionId: string;
  isFenced: boolean;
  fencedAt: number;
  reason: string;
}

export class SplitBrainFencingSentinel {
  private fencedRegions: Map<string, FencingReceipt> = new Map();
  private fencingEventsTotal: number = 0;

  constructor() {}

  /**
   * Fences off a partitioned edge region, revoking all remediation execution permissions.
   */
  public fencePartitionedRegion(regionId: string, reason: string): FencingReceipt {
    this.fencingEventsTotal++;
    const receipt: FencingReceipt = {
      regionId,
      isFenced: true,
      fencedAt: Date.now(),
      reason
    };

    this.fencedRegions.set(regionId, receipt);
    return receipt;
  }

  /**
   * Checks whether a given region is currently fenced.
   */
  public isRegionFenced(regionId: string): boolean {
    return this.fencedRegions.has(regionId);
  }

  /**
   * Releases a previously fenced region following partition healing.
   */
  public releaseFencedRegion(regionId: string): boolean {
    return this.fencedRegions.delete(regionId);
  }

  /**
   * Returns operational metrics for split-brain fencing.
   */
  public getMetrics(): { fencedRegionsCount: number; fencingEventsTotal: number } {
    return {
      fencedRegionsCount: this.fencedRegions.size,
      fencingEventsTotal: this.fencingEventsTotal
    };
  }
}

export const splitBrainFencingSentinel = new SplitBrainFencingSentinel();
