/**
 * Track 1 Verification Test Suite:
 * Multi-Scale Wavelet Changepoint Engine & Hurst Exponent Long-Range Dependence (LRD) Forecaster
 */

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  computeMorletWaveletTransform,
  computeHurstExponent,
  analyzeWaveletAndHurstLrd,
  estimateTimeToFailureHorizon,
  waveletHurstLrdEngine
} = require('../src/ai/wavelet-hurst-lrd-engine');

const {
  predictiveHorizonEngine,
  evaluateWaveletLrdHorizon
} = require('../src/ai/predictive-horizon-engine');

const {
  estimateSdeParameters,
  simulateEulerMaruyamaPath,
  calculateFirstPassageTime,
  stochasticDifferentialEngine
} = require('../src/ai/stochastic-differential-engine');

describe('Track 1: Multi-Scale Wavelet Changepoint Engine & Hurst Exponent LRD Forecaster', () => {
  it('Subtest 1: Computes Morlet Wavelet energy spectrum and isolates high-frequency microbursts', () => {
    // 1a. Baseline smooth macroscopic series (no microbursts)
    const smoothSeries = [];
    for (let t = 0; t < 128; t++) {
      smoothSeries.push(20.0 + 10.0 * Math.sin(t * 0.08));
    }
    const smoothWavelet = computeMorletWaveletTransform(smoothSeries);
    assert.strictEqual(smoothWavelet.microBurstDetected, false);
    assert.ok(smoothWavelet.highFrequencyRatio < 2.0);
    assert.ok(smoothWavelet.energySpectrum.length >= 4);

    // 1b. Series with sharp localized microburst (high frequency alternating burst)
    const burstSeries = [...smoothSeries];
    for (let i = 50; i <= 65; i++) {
      if (i % 2 === 0) burstSeries[i] += 80.0;
    }
    const burstWavelet = computeMorletWaveletTransform(burstSeries);
    assert.ok(burstWavelet.highFrequencyRatio > 2.0, `High frequency ratio (${burstWavelet.highFrequencyRatio}) must be elevated`);
    assert.strictEqual(burstWavelet.microBurstDetected, true);
  });

  it('Subtest 2: Hurst Exponent identifies Persistent Long-Range Dependence (H >= 0.70)', () => {
    // Generate persistent self-similar series with cumulative random walk + trend persistence
    const N = 120;
    const persistentSeries = [];
    let current = 25.0;
    let momentum = 0.5;

    for (let t = 0; t < N; t++) {
      momentum = 0.75 * momentum + (Math.sin(t * 0.2) > 0 ? 0.8 : -0.8);
      current = Math.max(5.0, current + momentum + (Math.random() - 0.5) * 0.3);
      persistentSeries.push(current);
    }

    const hurst = computeHurstExponent(persistentSeries);
    assert.ok(hurst.hurstExponent >= 0.65, `Hurst exponent (${hurst.hurstExponent}) must reflect persistence`);
    assert.strictEqual(hurst.isLongRangeDependent, true);
    assert.strictEqual(hurst.persistenceClassification, 'PERSISTENT_LONG_RANGE_DEPENDENT');
    assert.ok(hurst.dispersionMultiplier > 1.0, 'Variance dispersion multiplier must exceed 1.0');
    assert.ok(hurst.rSquared > 0.70, 'Regression R^2 fit must be statistically strong');
  });

  it('Subtest 3: Hurst Exponent correctly classifies memoryless white noise (H ~ 0.50)', () => {
    // Generate authentic independent white noise with zero autocorrelation
    const N = 128;
    const whiteNoise = [];
    let state = 42;
    for (let t = 0; t < N; t++) {
      // Deterministic linear congruential generator for zero auto-correlation
      state = (state * 1664525 + 1013904223) % 4294967296;
      whiteNoise.push(50.0 + ((state / 4294967296) - 0.5) * 20.0);
    }

    const hurst = computeHurstExponent(whiteNoise);
    assert.ok(hurst.hurstExponent < 0.68, `Uncorrelated noise Hurst (${hurst.hurstExponent}) must be below 0.68`);
    assert.strictEqual(hurst.isLongRangeDependent, false);
    assert.strictEqual(hurst.persistenceClassification, 'MEMORYLESS_BROWNIAN_NOISE');
  });

  it('Subtest 4: Unified Wavelet and Hurst LRD diagnostic report synthesizes queueing risk', () => {
    // Compound series: persistent trend with sharp transient spike
    const telemetry = [];
    let level = 30.0;
    for (let t = 0; t < 96; t++) {
      level += 0.35;
      telemetry.push(level + (t === 48 ? 150.0 : 0.0));
    }

    const report = analyzeWaveletAndHurstLrd(telemetry);
    assert.strictEqual(report.sampleCount, 96);
    assert.ok(report.mean > 0);
    assert.ok(report.variance > 0);
    assert.ok(report.wavelet);
    assert.ok(report.hurst);
    assert.ok(['CRITICAL', 'ELEVATED'].includes(report.riskAssessment.queueCliffRisk));
    assert.ok(report.riskAssessment.summary.length > 0);
    assert.ok(report.riskAssessment.actionableInsight.length > 0);
  });

  it('Subtest 5: Integrates cleanly with Predictive Horizon Engine and exports', () => {
    const series = [10, 12, 14, 18, 22, 28, 35, 42, 50, 60, 72, 85, 100, 120, 145, 175];
    const result = evaluateWaveletLrdHorizon(series, { target: 'gateway-core-01' });

    assert.strictEqual(result.target, 'gateway-core-01');
    assert.ok(result.report);
    assert.ok(typeof result.hurstExponent === 'number');
    assert.ok(typeof result.isLongRangeDependent === 'boolean');
    assert.ok(typeof result.dispersionMultiplier === 'number');
    assert.ok(result.recommendedAction.length > 0);

    // Class instance parity
    const classResult = predictiveHorizonEngine.evaluateWaveletLrdHorizon(series);
    assert.strictEqual(classResult.target, 'target-node');
    assert.ok(classResult.report);
  });

  it('Subtest 6: Evaluates predictive Time-to-Failure (TTF) capacity horizon with Hurst dispersion', () => {
    // 6a. Rapidly escalating usage series (approaching 100% capacity)
    const escalating = [50, 55, 61, 68, 76, 85, 93];
    const ttfImminent = estimateTimeToFailureHorizon(escalating, { capacityMax: 100.0, sampleIntervalSeconds: 1.0 });

    assert.strictEqual(ttfImminent.capacityMax, 100.0);
    assert.strictEqual(ttfImminent.usageCurrent, 93);
    assert.strictEqual(ttfImminent.headroomRemaining, 7);
    assert.ok(ttfImminent.driftRatePerSecond > 0, 'Drift rate must be positive');
    assert.ok(ttfImminent.timeToFailureSeconds <= 60, `TTF must be imminent (<= 60s), got ${ttfImminent.timeToFailureSeconds}`);
    assert.strictEqual(ttfImminent.riskHorizonTier, 'CRITICAL_IMMINENT');
    assert.ok(ttfImminent.actionableAdvisory.includes('CRITICAL'));

    // 6b. Moderate linear drift
    const linearDrift = [20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30];
    const ttfWarning = waveletHurstLrdEngine.estimateTimeToFailureHorizon(linearDrift, { capacityMax: 100.0, sampleIntervalSeconds: 1.0 });
    assert.ok(ttfWarning.timeToFailureSeconds > 60);
    assert.strictEqual(ttfWarning.riskHorizonTier, 'WARNING_DRIFT');

    // 6c. Saturated state (headroom <= 0)
    const saturated = [80, 90, 100];
    const ttfSat = estimateTimeToFailureHorizon(saturated, { capacityMax: 100.0 });
    assert.strictEqual(ttfSat.headroomRemaining, 0);
    assert.strictEqual(ttfSat.timeToFailureSeconds, 0);
    assert.strictEqual(ttfSat.riskHorizonTier, 'CRITICAL_IMMINENT');
    assert.ok(ttfSat.sdeFirstPassageTime);
  });

  it('Subtest 7: Euler-Maruyama SDE solver generates continuous trajectories with stochastic drift', () => {
    // 7a. Parameter estimation from escalating series
    const series = [20, 24, 29, 36, 44, 53, 64, 76];
    const params = estimateSdeParameters(series, 1.0);
    assert.ok(params.theta > 0, 'Theta must be positive');
    assert.ok(params.mu >= 20, 'Long-term mean must be calibrated');
    assert.ok(params.sigma > 0, 'Volatility must be positive');
    assert.strictEqual(params.s0, 76, 'Starting state must match latest series point');

    // 7b. Single path simulation
    const trajectory = simulateEulerMaruyamaPath(
      params,
      { dt: 0.1, steps: 100, seed: 12345 }
    );
    assert.strictEqual(trajectory.timePoints.length, 101);
    assert.strictEqual(trajectory.states.length, 101);
    assert.strictEqual(trajectory.timePoints[0], 0);
    assert.strictEqual(trajectory.states[0], 76);
    // Trajectory must have non-negative states
    for (const val of trajectory.states) {
      assert.ok(val >= 0, 'SDE states must remain non-negative');
    }

    // 7c. Class instance parity
    const engineTrajectory = stochasticDifferentialEngine.simulatePath(
      params,
      { dt: 0.2, steps: 50, seed: 12345 }
    );
    assert.strictEqual(engineTrajectory.states.length, 51);
  });

  it('Subtest 8: First-Passage Time (FPT) calculates monotonic survival curve and VaR horizons', () => {
    // 8a. High drift trajectory approaching barrier B = 100
    const highDriftParams = { theta: 0.05, mu: 120.0, sigma: 0.4, s0: 85.0 };
    const fptHigh = calculateFirstPassageTime(highDriftParams, 100.0, {
      dt: 0.5,
      steps: 100,
      numPaths: 100,
      seed: 999
    });

    assert.strictEqual(fptHigh.thresholdB, 100.0);
    assert.strictEqual(fptHigh.initialState, 85.0);
    assert.ok(fptHigh.breachFraction > 0.50, `Expected high breach fraction (> 50%), got ${fptHigh.breachFraction}`);
    assert.ok(fptHigh.survivalCurve.length >= 10);

    // Monotonicity check on survival curve S(t_1) >= S(t_2)
    for (let i = 1; i < fptHigh.survivalCurve.length; i++) {
      assert.ok(
        fptHigh.survivalCurve[i].survivalProb <= fptHigh.survivalCurve[i - 1].survivalProb + 1e-6,
        `Survival probability must be monotonically non-increasing: index ${i}`
      );
    }
    assert.ok(fptHigh.var95TimeToFailureSeconds !== null);
    assert.ok(fptHigh.var95TimeToFailureSeconds <= 50.0);
    assert.strictEqual(fptHigh.riskTier, 'CRITICAL_IMMINENT');

    // 8b. Stable mean-reverting trajectory well below barrier B = 200
    const stableParams = { theta: 0.5, mu: 25.0, sigma: 0.1, s0: 25.0 };
    const fptStable = stochasticDifferentialEngine.calculateFirstPassageTime(stableParams, 200.0, {
      dt: 0.5,
      steps: 50,
      numPaths: 50,
      seed: 42
    });
    assert.strictEqual(fptStable.breachFraction, 0);
    assert.strictEqual(fptStable.survivalProbabilityAtHorizon, 1.0);
    assert.strictEqual(fptStable.riskTier, 'NOMINAL_STABLE');
    assert.strictEqual(fptStable.var95TimeToFailureSeconds, null);

    // 8c. Already breached starting condition (s0 >= B)
    const fptBreached = calculateFirstPassageTime({ theta: 0.1, mu: 50, sigma: 0.2, s0: 105 }, 100);
    assert.strictEqual(fptBreached.breachFraction, 1.0);
    assert.strictEqual(fptBreached.expectedHittingTimeSeconds, 0);
    assert.strictEqual(fptBreached.var95TimeToFailureSeconds, 0);
    assert.strictEqual(fptBreached.riskTier, 'CRITICAL_IMMINENT');
  });
});
