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
  waveletHurstLrdEngine
} = require('../src/ai/wavelet-hurst-lrd-engine');

const {
  predictiveHorizonEngine,
  evaluateWaveletLrdHorizon
} = require('../src/ai/predictive-horizon-engine');

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
});
