/**
 * EJII Wavelet Hurst Long-Range Dependence (LRD) & Micro-Burst Detection Engine
 *
 * Implements:
 *   1. Continuous Morlet Wavelet Transform (CWT):
 *      psi(t) = pi^(-1/4) * exp(i * omega_0 * t) * exp(-t^2 / 2), omega_0 = 6.0
 *      Calculates multi-scale wavelet modulus and energy spectrum E(a) across dyadic scales
 *      a in [2, 4, 8, 16, 32, 64] to isolate high-frequency microbursts.
 *   2. Rescaled Range (R/S) Hurst Exponent (H) Analysis:
 *      Evaluates long-range dependence, self-similarity, and memory in telemetry time series.
 *      - H >= 0.70: PERSISTENT_LONG_RANGE_DEPENDENT (heavy-tailed bufferbloat / queueing cliff)
 *      - 0.40 <= H < 0.70: MEMORYLESS_BROWNIAN_NOISE (Poisson traffic)
 *      - H < 0.40: ANTI_PERSISTENT_MEAN_REVERTING (rapid flapping / oscillation)
 */

'use strict';

Object.defineProperty(exports, '__esModule', { value: true });
exports.waveletHurstLrdEngine = exports.WaveletHurstLrdEngine = exports.estimateTimeToFailureHorizon = exports.analyzeWaveletAndHurstLrd = exports.computeHurstExponent = exports.computeMorletWaveletTransform = void 0;

const { stochasticDifferentialEngine } = require('./stochastic-differential-engine');

const PI_POW_MINUS_QUARTER = 0.7511255444649425; // pi^(-1/4)
const OMEGA_0 = 6.0;

/**
 * Computes Continuous Morlet Wavelet Transform on a 1D real series.
 *
 * @param {number[]} series Array of numeric telemetry samples
 * @param {number[]} scales Array of dyadic octave scales (default: [2, 4, 8, 16, 32, 64])
 * @returns {Object} Wavelet transform analysis
 */
function computeMorletWaveletTransform(series, scales = [2, 4, 8, 16, 32, 64]) {
  const cleanSeries = (series || []).filter((v) => typeof v === 'number' && Number.isFinite(v));
  const N = cleanSeries.length;

  if (N < 8) {
    const defaultSpectrum = scales.map((s) => ({
      scale: s,
      energy: 0,
      relativeEnergyPct: 0
    }));
    return {
      scales,
      energySpectrum: defaultSpectrum,
      highFrequencyRatio: 1.0,
      microBurstDetected: false,
      peakEnergyScale: scales[0] || 2
    };
  }

  // Mean-center the series
  const mean = cleanSeries.reduce((a, b) => a + b, 0) / N;
  const centered = cleanSeries.map((x) => x - mean);

  const energies = [];

  for (const a of scales) {
    if (a >= N) continue;
    let sumModulusSq = 0;
    const invSqrtA = 1.0 / Math.sqrt(a);
    const radius = Math.min(N, Math.ceil(4 * a));

    for (let b = 0; b < N; b++) {
      let realPart = 0;
      let imagPart = 0;

      const tMin = Math.max(0, b - radius);
      const tMax = Math.min(N - 1, b + radius);

      for (let t = tMin; t <= tMax; t++) {
        const u = (t - b) / a;
        const envelope = PI_POW_MINUS_QUARTER * Math.exp(-0.5 * u * u);
        const psiReal = envelope * Math.cos(OMEGA_0 * u);
        const psiImag = -envelope * Math.sin(OMEGA_0 * u);

        const x = centered[t];
        realPart += x * psiReal;
        imagPart += x * psiImag;
      }

      realPart *= invSqrtA;
      imagPart *= invSqrtA;

      const modSq = realPart * realPart + imagPart * imagPart;
      sumModulusSq += modSq;
    }

    const energy = sumModulusSq / N;
    energies.push({ scale: a, energy });
  }

  const totalEnergy = energies.reduce((acc, e) => acc + e.energy, 0);
  const energySpectrum = energies.map((e) => ({
    scale: e.scale,
    energy: Number(e.energy.toFixed(4)),
    relativeEnergyPct: totalEnergy > 0 ? Number(((e.energy / totalEnergy) * 100).toFixed(2)) : 0
  }));

  // Find peak energy scale
  let peakScale = scales[0] || 2;
  let maxEnergy = -1;
  for (const e of energySpectrum) {
    if (e.energy > maxEnergy) {
      maxEnergy = e.energy;
      peakScale = e.scale;
    }
  }

  // Micro-burst high-frequency energy ratio: scale 2 vs intermediate scales (4 and 8)
  const e2 = energySpectrum.find((e) => e.scale === 2)?.energy || 0;
  const e4 = energySpectrum.find((e) => e.scale === 4)?.energy || 0;
  const e8 = energySpectrum.find((e) => e.scale === 8)?.energy || 0;
  const intermediateAvg = Math.max(0.01, (e4 + e8) / 2);

  const highFrequencyRatio = Number((e2 / intermediateAvg).toFixed(3));
  const microBurstDetected = highFrequencyRatio > 2.0 && e2 > 1.0;

  return {
    scales,
    energySpectrum,
    highFrequencyRatio,
    microBurstDetected,
    peakEnergyScale: peakScale
  };
}
exports.computeMorletWaveletTransform = computeMorletWaveletTransform;

/**
 * Computes Empirical Rescaled Range (R/S) Hurst Exponent.
 *
 * @param {number[]} series Time series of measurements
 * @returns {Object} Hurst analysis result
 */
function computeHurstExponent(series) {
  const clean = (series || []).filter((v) => typeof v === 'number' && Number.isFinite(v));
  const N = clean.length;

  if (N < 16) {
    return {
      hurstExponent: 0.50,
      rSquared: 0.0,
      standardError: 0.1,
      persistenceClassification: 'MEMORYLESS_BROWNIAN_NOISE',
      isLongRangeDependent: false,
      dispersionMultiplier: 1.0
    };
  }

  // Construct logarithmic block sizes k
  const candidateSizes = [8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256];
  const validSizes = candidateSizes.filter((k) => k <= Math.floor(N / 2) && k >= 8);

  if (validSizes.length < 3) {
    validSizes.length = 0;
    const minK = 6;
    const maxK = Math.floor(N / 2);
    const step = Math.max(2, Math.floor((maxK - minK) / 4));
    for (let k = minK; k <= maxK; k += step) {
      validSizes.push(k);
    }
  }

  const logK = [];
  const logRS = [];

  for (const k of validSizes) {
    const numBlocks = Math.floor(N / k);
    if (numBlocks < 1) continue;

    let sumRS = 0;
    let validBlocks = 0;

    for (let m = 0; m < numBlocks; m++) {
      const block = clean.slice(m * k, (m + 1) * k);
      const mean = block.reduce((a, b) => a + b, 0) / k;

      // Sample variance & standard deviation
      const variance = block.reduce((acc, x) => acc + (x - mean) * (x - mean), 0) / (k - 1 || 1);
      const stdDev = Math.sqrt(Math.max(1e-9, variance));

      // Cumulative deviates
      let cumDev = 0;
      let minDev = 0;
      let maxDev = 0;

      for (let i = 0; i < k; i++) {
        cumDev += block[i] - mean;
        if (cumDev < minDev) minDev = cumDev;
        if (cumDev > maxDev) maxDev = cumDev;
      }

      const range = maxDev - minDev;
      const rs = range / stdDev;

      if (Number.isFinite(rs) && rs > 0) {
        sumRS += rs;
        validBlocks++;
      }
    }

    if (validBlocks > 0) {
      const avgRS = sumRS / validBlocks;
      logK.push(Math.log(k));
      logRS.push(Math.log(avgRS));
    }
  }

  if (logK.length < 2) {
    return {
      hurstExponent: 0.50,
      rSquared: 0.0,
      standardError: 0.1,
      persistenceClassification: 'MEMORYLESS_BROWNIAN_NOISE',
      isLongRangeDependent: false,
      dispersionMultiplier: 1.0
    };
  }

  // Linear regression of logRS on logK
  const nPoints = logK.length;
  const meanLogK = logK.reduce((a, b) => a + b, 0) / nPoints;
  const meanLogRS = logRS.reduce((a, b) => a + b, 0) / nPoints;

  let num = 0;
  let den = 0;
  for (let i = 0; i < nPoints; i++) {
    const dk = logK[i] - meanLogK;
    const dr = logRS[i] - meanLogRS;
    num += dk * dr;
    den += dk * dk;
  }

  let slope = den > 1e-12 ? num / den : 0.50;
  slope = Math.max(0.05, Math.min(0.98, slope));

  // Compute R^2 goodness of fit
  let ssTot = 0;
  let ssRes = 0;
  for (let i = 0; i < nPoints; i++) {
    const pred = meanLogRS + slope * (logK[i] - meanLogK);
    ssTot += Math.pow(logRS[i] - meanLogRS, 2);
    ssRes += Math.pow(logRS[i] - pred, 2);
  }
  const rSquared = ssTot > 1e-12 ? Math.max(0, 1 - ssRes / ssTot) : 0.85;
  const standardError = nPoints > 2 ? Math.sqrt(ssRes / (nPoints - 2)) : 0.05;

  let classification = 'MEMORYLESS_BROWNIAN_NOISE';
  let isLrd = false;

  if (slope >= 0.68) {
    classification = 'PERSISTENT_LONG_RANGE_DEPENDENT';
    isLrd = true;
  } else if (slope < 0.40) {
    classification = 'ANTI_PERSISTENT_MEAN_REVERTING';
    isLrd = false;
  }

  const effectiveN = Math.min(64, Math.max(10, N));
  const dispersionMultiplier = Number(Math.pow(effectiveN, Math.max(0, 2 * slope - 1)).toFixed(3));

  return {
    hurstExponent: Number(slope.toFixed(4)),
    rSquared: Number(rSquared.toFixed(4)),
    standardError: Number(standardError.toFixed(4)),
    persistenceClassification: classification,
    isLongRangeDependent: isLrd,
    dispersionMultiplier
  };
}
exports.computeHurstExponent = computeHurstExponent;

/**
 * Executes unified multi-scale Wavelet and Hurst LRD diagnostic evaluation.
 *
 * @param {number[]} series Telemetry observation series
 * @returns {Object} Unified diagnostic report
 */
function analyzeWaveletAndHurstLrd(series) {
  const clean = (series || []).filter((v) => typeof v === 'number' && Number.isFinite(v));
  const sampleCount = clean.length;
  const mean = sampleCount > 0 ? clean.reduce((a, b) => a + b, 0) / sampleCount : 0;
  const variance = sampleCount > 1
    ? clean.reduce((acc, x) => acc + Math.pow(x - mean, 2), 0) / (sampleCount - 1)
    : 0;

  const wavelet = computeMorletWaveletTransform(clean);
  const hurst = computeHurstExponent(clean);

  let queueCliffRisk = 'NOMINAL';
  let summary = 'Telemetry series displays memoryless Poisson dynamics without persistence.';
  let actionableInsight = 'Nominal queueing headroom; standard periodic polling is sufficient.';

  if (hurst.isLongRangeDependent && wavelet.microBurstDetected) {
    queueCliffRisk = 'CRITICAL';
    summary = `CRITICAL: Compounding self-similar traffic persistence (H=${hurst.hurstExponent}) with active micro-burst energy (ratio=${wavelet.highFrequencyRatio}).`;
    actionableInsight = `Queueing amplification risk is extreme (${hurst.dispersionMultiplier}x variance inflation). Tighten circuit-breaker timeouts and expand socket buffer headroom.`;
  } else if (hurst.isLongRangeDependent) {
    queueCliffRisk = 'ELEVATED';
    summary = `ELEVATED: High persistence / Long-Range Dependence detected (H=${hurst.hurstExponent}). Traffic bursts will not dissipate via memoryless smoothing.`;
    actionableInsight = 'Traffic exhibits self-similarity. Pre-scale worker concurrency before M/M/1 knee-of-curve threshold.';
  } else if (wavelet.microBurstDetected) {
    queueCliffRisk = 'ELEVATED';
    summary = `ELEVATED: Transient high-frequency microbursts detected (scale=2 energy ratio=${wavelet.highFrequencyRatio}).`;
    actionableInsight = 'Transient burst detected on sub-second timescale. Inspect interface MTU and burst buffer ring capacity.';
  }

  return {
    sampleCount,
    mean: Number(mean.toFixed(2)),
    variance: Number(variance.toFixed(2)),
    wavelet,
    hurst,
    riskAssessment: {
      queueCliffRisk,
      summary,
      actionableInsight
    }
  };
}
exports.analyzeWaveletAndHurstLrd = analyzeWaveletAndHurstLrd;

/**
 * Track 4: Predictive Time-to-Failure (TTF) Capacity Horizon Estimation
 *
 * Implements:
 *   TTF = (Capacity_max - Usage_current) / (d/dt(Usage) + sigma_hurst * Dispersion)
 *
 * Evaluates drift velocity, long-range dispersion expansion under Hurst LRD,
 * and categorizes degradation risk into CRITICAL_IMMINENT, WARNING_DRIFT, or STABLE_NOMINAL.
 *
 * @param {number[]} usageSeries Chronological telemetry usage samples (e.g. CPU %, Buffer %, RAM %)
 * @param {Object} options Configuration parameters
 * @param {number} [options.capacityMax=100.0] Saturation capacity threshold (default: 100)
 * @param {number} [options.sampleIntervalSeconds=1.0] Time delta between successive samples
 * @returns {Object} TTF horizon projection
 */
function estimateTimeToFailureHorizon(usageSeries, options = {}) {
  const clean = (usageSeries || []).filter((v) => typeof v === 'number' && Number.isFinite(v));
  const capacityMax = typeof options.capacityMax === 'number' ? options.capacityMax : 100.0;
  const sampleIntervalSeconds = Math.max(0.1, Number(options.sampleIntervalSeconds) || 1.0);

  if (clean.length === 0) {
    return {
      capacityMax,
      usageCurrent: 0,
      headroomRemaining: capacityMax,
      driftRatePerSecond: 0,
      hurstExponent: 0.5,
      dispersionMultiplier: 1.0,
      effectiveDegradationRate: 0,
      timeToFailureSeconds: Infinity,
      timeToFailureFormatted: 'INFINITE_HEADROOM',
      riskHorizonTier: 'STABLE_NOMINAL',
      actionableAdvisory: 'Insufficient telemetry to calculate drift horizon.'
    };
  }

  const usageCurrent = clean[clean.length - 1];
  const headroomRemaining = Math.max(0, capacityMax - usageCurrent);

  // Compute Hurst & Wavelet properties
  const hurst = computeHurstExponent(clean);
  const N = clean.length;
  const mean = clean.reduce((a, b) => a + b, 0) / N;
  const variance = N > 1 ? clean.reduce((acc, x) => acc + Math.pow(x - mean, 2), 0) / (N - 1) : 0;
  const sigma = Math.sqrt(variance);

  // Calculate drift rate d/dt(Usage) using ordinary least squares regression over the series
  let sumT = 0, sumU = 0, sumTU = 0, sumT2 = 0;
  for (let i = 0; i < N; i++) {
    const t = i * sampleIntervalSeconds;
    const u = clean[i];
    sumT += t;
    sumU += u;
    sumTU += t * u;
    sumT2 += t * t;
  }
  const denom = N * sumT2 - sumT * sumT;
  const slopePerSec = denom !== 0 ? (N * sumTU - sumT * sumU) / denom : 0;
  const driftRatePerSecond = Math.round(slopePerSec * 10000) / 10000;

  // Dispersion penalty: sigma_hurst = sigma * (dispersionMultiplier - 1) / 10.0
  // When series is persistent (H >= 0.70), heavy-tailed bursts increase effective degradation rate
  const dispersionPenalty = hurst.isLongRangeDependent
    ? Math.max(0, (sigma * (hurst.dispersionMultiplier - 1)) / 10.0)
    : 0;

  const effectiveDegradationRate = Math.round(
    Math.max(0.0001, driftRatePerSecond + dispersionPenalty) * 10000
  ) / 10000;

  let timeToFailureSeconds = Infinity;
  if (headroomRemaining <= 0) {
    timeToFailureSeconds = 0;
  } else if (effectiveDegradationRate > 0.0001) {
    timeToFailureSeconds = Math.round(headroomRemaining / effectiveDegradationRate);
  }

  let riskHorizonTier = 'STABLE_NOMINAL';
  let actionableAdvisory = 'Nominal capacity headroom; telemetry slope is stable.';

  if (timeToFailureSeconds <= 60) {
    riskHorizonTier = 'CRITICAL_IMMINENT';
    actionableAdvisory = `CRITICAL: Saturation failure projected within ${timeToFailureSeconds}s. Trigger preemptive shed / rate-limiting immediately.`;
  } else if (timeToFailureSeconds <= 600) {
    riskHorizonTier = 'WARNING_DRIFT';
    actionableAdvisory = `WARNING: Monotonic drift detected with TTF horizon ${Math.round(timeToFailureSeconds / 60)} minutes. Scale buffer/worker capacity.`;
  }

  const formatTtf = (sec) => {
    if (!Number.isFinite(sec)) return 'INFINITE_HEADROOM';
    if (sec < 60) return `${sec}s`;
    if (sec < 3600) return `${Math.round(sec / 60)}m ${sec % 60}s`;
    return `${(sec / 3600).toFixed(1)}h`;
  };

  let sdeFirstPassageTime = undefined;
  if (options.enableSde !== false && clean.length >= 3) {
    const sdeParams = stochasticDifferentialEngine.estimateParameters(clean, sampleIntervalSeconds);
    const horizonSteps = Math.min(
      500,
      Math.max(50, Math.ceil(timeToFailureSeconds / sampleIntervalSeconds) || 100)
    );
    sdeFirstPassageTime = stochasticDifferentialEngine.calculateFirstPassageTime(
      sdeParams,
      capacityMax,
      {
        dt: sampleIntervalSeconds,
        steps: horizonSteps,
        numPaths: 50,
        seed: 42
      }
    );
  }

  return {
    capacityMax,
    usageCurrent: Number(usageCurrent.toFixed(2)),
    headroomRemaining: Number(headroomRemaining.toFixed(2)),
    driftRatePerSecond,
    hurstExponent: hurst.hurstExponent,
    dispersionMultiplier: hurst.dispersionMultiplier,
    effectiveDegradationRate,
    timeToFailureSeconds,
    timeToFailureFormatted: formatTtf(timeToFailureSeconds),
    riskHorizonTier,
    actionableAdvisory,
    sdeFirstPassageTime
  };
}
exports.estimateTimeToFailureHorizon = estimateTimeToFailureHorizon;

class WaveletHurstLrdEngine {
  computeMorletWaveletTransform(series, scales) {
    return computeMorletWaveletTransform(series, scales);
  }

  computeHurstExponent(series) {
    return computeHurstExponent(series);
  }

  analyzeWaveletAndHurstLrd(series) {
    return analyzeWaveletAndHurstLrd(series);
  }

  estimateTimeToFailureHorizon(series, options) {
    return estimateTimeToFailureHorizon(series, options);
  }
}
exports.WaveletHurstLrdEngine = WaveletHurstLrdEngine;

const waveletHurstLrdEngine = new WaveletHurstLrdEngine();
exports.waveletHurstLrdEngine = waveletHurstLrdEngine;
