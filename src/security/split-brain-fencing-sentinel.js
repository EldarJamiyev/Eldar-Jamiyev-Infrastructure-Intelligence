/**
 * EJII Virtual STONITH Split-Brain Fencing Sentinel
 *
 * Enforces automated partition fencing and execution barriers against split-brain
 * edge cloud sites to isolate uncoordinated remediation attempts.
 * Dual-Maintenance CommonJS Implementation.
 */

'use strict';

class SplitBrainFencingSentinel {
  constructor() {
    this.fencedRegions = new Map();
    this.fencingEventsTotal = 0;
  }

  /**
   * Fences off a partitioned edge region, revoking all remediation execution permissions.
   */
  fencePartitionedRegion(regionId, reason) {
    this.fencingEventsTotal++;
    const receipt = {
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
  isRegionFenced(regionId) {
    return this.fencedRegions.has(regionId);
  }

  /**
   * Releases a previously fenced region following partition healing.
   */
  releaseFencedRegion(regionId) {
    return this.fencedRegions.delete(regionId);
  }

  /**
   * Returns operational metrics for split-brain fencing.
   */
  getMetrics() {
    return {
      fencedRegionsCount: this.fencedRegions.size,
      fencingEventsTotal: this.fencingEventsTotal
    };
  }
}

const splitBrainFencingSentinel = new SplitBrainFencingSentinel();

module.exports = {
  SplitBrainFencingSentinel,
  splitBrainFencingSentinel
};
