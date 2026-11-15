/**
 * EJII Adaptive Concept Drift Compensator
 *
 * Implements Page-Hinkley cumulative sum change detection over non-stationary
 * infrastructure telemetry to dynamically detect concept drift and trigger causal model updates.
 * Dual-Maintenance CommonJS Implementation.
 */

'use strict';

class AdaptiveConceptDriftCompensator {
  constructor(lambdaThreshold = 25.0, deltaTolerance = 0.05) {
    this.detectors = new Map();
    this.totalDriftEvents = 0;
    this.lambdaThreshold = lambdaThreshold;
    this.deltaTolerance = deltaTolerance;
  }

  /**
   * Observes a streaming metric sample and checks for Page-Hinkley concept drift.
   */
  observeMetricSample(metricName, value) {
    if (!this.detectors.has(metricName)) {
      this.detectors.set(metricName, {
        count: 0,
        mean: value,
        cumulativeSum: 0,
        minCumulativeSum: 0,
        driftDetected: false
      });
    }

    const state = this.detectors.get(metricName);
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
  resetDetector(metricName) {
    this.detectors.delete(metricName);
  }

  /**
   * Returns operational metrics for concept drift monitoring.
   */
  getMetrics() {
    return {
      metricsMonitored: this.detectors.size,
      driftEventsDetected: this.totalDriftEvents
    };
  }
}

const adaptiveConceptDriftCompensator = new AdaptiveConceptDriftCompensator();

module.exports = {
  AdaptiveConceptDriftCompensator,
  adaptiveConceptDriftCompensator
};
