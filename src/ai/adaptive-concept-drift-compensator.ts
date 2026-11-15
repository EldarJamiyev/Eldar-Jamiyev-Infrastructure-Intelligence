/**
 * EJII Adaptive Concept Drift Compensator
 *
 * Implements Page-Hinkley cumulative sum change detection over non-stationary
 * infrastructure telemetry to dynamically detect concept drift and trigger causal model updates.
 * Dual-Maintenance TypeScript Reference.
 */

export interface DriftDetectorState {
  count: number;
  mean: number;
  cumulativeSum: number;
  minCumulativeSum: number;
  driftDetected: boolean;
}

export class AdaptiveConceptDriftCompensator {
  private detectors: Map<string, DriftDetectorState> = new Map();
  private totalDriftEvents: number = 0;
  private lambdaThreshold: number = 25.0; // Cumulative drift threshold
  private deltaTolerance: number = 0.05; // Noise margin

  constructor(lambdaThreshold: number = 25.0, deltaTolerance: number = 0.05) {
    this.lambdaThreshold = lambdaThreshold;
    this.deltaTolerance = deltaTolerance;
  }

  /**
   * Observes a streaming metric sample and checks for Page-Hinkley concept drift.
   */
  public observeMetricSample(
    metricName: string,
    value: number
  ): { driftDetected: boolean; cumulativeDriftScore: number } {
    if (!this.detectors.has(metricName)) {
      this.detectors.set(metricName, {
        count: 0,
        mean: value,
        cumulativeSum: 0,
        minCumulativeSum: 0,
        driftDetected: false
      });
    }

    const state = this.detectors.get(metricName)!;
    state.count++;

    // Welford's online mean
    state.mean += (value - state.mean) / state.count;

    // Page-Hinkley cumulative sum: U_n = \sum (x_i - \bar{x} - \delta)
    state.cumulativeSum += value - state.mean - this.deltaTolerance;
    if (state.cumulativeSum < state.minCumulativeSum) {
      state.minCumulativeSum = state.cumulativeSum;
    }

    const driftScore = state.cumulativeSum - state.minCumulativeSum;
    const isDrifting = driftScore > this.lambdaThreshold;

    if (isDrifting && !state.driftDetected) {
      state.driftDetected = true;
      this.totalDriftEvents++;
    }

    return {
      driftDetected: isDrifting,
      cumulativeDriftScore: Number(driftScore.toFixed(4))
    };
  }

  /**
   * Resets the drift detector for a given metric after adaptation.
   */
  public resetDetector(metricName: string): void {
    this.detectors.delete(metricName);
  }

  /**
   * Returns operational metrics for concept drift monitoring.
   */
  public getMetrics(): { metricsMonitored: number; driftEventsDetected: number } {
    return {
      metricsMonitored: this.detectors.size,
      driftEventsDetected: this.totalDriftEvents
    };
  }
}

export const adaptiveConceptDriftCompensator = new AdaptiveConceptDriftCompensator();
