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

export interface WaveletScaleEnergy {
  scale: number;
  energy: number;
  relativeEnergyPct: number;
}

export interface WaveletTransformResult {
  scales: number[];
  energySpectrum: WaveletScaleEnergy[];
  highFrequencyRatio: number;
  microBurstDetected: boolean;
  peakEnergyScale: number;
}

export interface HurstAnalysisResult {
  hurstExponent: number;
  rSquared: number;
  standardError: number;
  persistenceClassification:
    | 'PERSISTENT_LONG_RANGE_DEPENDENT'
    | 'MEMORYLESS_BROWNIAN_NOISE'
    | 'ANTI_PERSISTENT_MEAN_REVERTING';
  isLongRangeDependent: boolean;
  dispersionMultiplier: number;
}

export interface WaveletLrdAnalysisReport {
  sampleCount: number;
  mean: number;
  variance: number;
  wavelet: WaveletTransformResult;
  hurst: HurstAnalysisResult;
  riskAssessment: {
    queueCliffRisk: 'CRITICAL' | 'ELEVATED' | 'NOMINAL';
    summary: string;
    actionableInsight: string;
  };
}

const PI_POW_MINUS_QUARTER = 0.7511255444649425; // pi^(-1/4)
const OMEGA_0 = 6.0;

/**
 * Computes Continuous Morlet Wavelet Transform on a 1D real series.
 *
 * @param series Array of numeric telemetry samples
 * @param scales Array of dyadic octave scales (default: [2, 4, 8, 16, 32, 64])
 * @returns Wavelet transform analysis
 */
export function computeMorletWaveletTransform(
  series: number[],
  scales: number[] = [2, 4, 8, 16, 32, 64]
): WaveletTransformResult {
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

  const energies: Array<{ scale: number; energy: number }> = [];

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
  const energySpectrum: WaveletScaleEnergy[] = energies.map((e) => ({
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

  // Micro-burst high-frequency energy ratio: scale 2 vs macro scales (>= 16)
  const lowScaleEnergy = energySpectrum.find((e) => e.scale === 2)?.energy || 0;
  const macroEnergies = energySpectrum.filter((e) => e.scale >= 16).map((e) => e.energy);
  const macroAvg = macroEnergies.length > 0
    ? macroEnergies.reduce((a, b) => a + b, 0) / macroEnergies.length
    : 0.1;

  const highFrequencyRatio = Number((lowScaleEnergy / Math.max(0.0001, macroAvg)).toFixed(3));
  const microBurstDetected = highFrequencyRatio > 2.5 && lowScaleEnergy > 1.0;

  return {
    scales,
    energySpectrum,
    highFrequencyRatio,
    microBurstDetected,
    peakEnergyScale: peakScale
  };
}

/**
 * Computes Empirical Rescaled Range (R/S) Hurst Exponent.
 *
 * @param series Time series of measurements
 * @returns Hurst analysis result
 */
export function computeHurstExponent(series: number[]): HurstAnalysisResult {
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
    // Dynamically generate sizes if series is compact
    validSizes.length = 0;
    const minK = 6;
    const maxK = Math.floor(N / 2);
    const step = Math.max(2, Math.floor((maxK - minK) / 4));
    for (let k = minK; k <= maxK; k += step) {
      validSizes.push(k);
    }
  }

  const logK: number[] = [];
  const logRS: number[] = [];

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
  slope = Math.max(0.05, Math.min(0.98, slope)); // Bounded within (0, 1)

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

  let classification: HurstAnalysisResult['persistenceClassification'] = 'MEMORYLESS_BROWNIAN_NOISE';
  let isLrd = false;

  if (slope >= 0.68) {
    classification = 'PERSISTENT_LONG_RANGE_DEPENDENT';
    isLrd = true;
  } else if (slope < 0.40) {
    classification = 'ANTI_PERSISTENT_MEAN_REVERTING';
    isLrd = false;
  }

  // Dispersion multiplier: kappa = n^(2H - 1)
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

/**
 * Executes unified multi-scale Wavelet and Hurst LRD diagnostic evaluation.
 *
 * @param series Telemetry observation series
 * @returns Unified diagnostic report
 */
export function analyzeWaveletAndHurstLrd(series: number[]): WaveletLrdAnalysisReport {
  const clean = (series || []).filter((v) => typeof v === 'number' && Number.isFinite(v));
  const sampleCount = clean.length;
  const mean = sampleCount > 0 ? clean.reduce((a, b) => a + b, 0) / sampleCount : 0;
  const variance = sampleCount > 1
    ? clean.reduce((acc, x) => acc + Math.pow(x - mean, 2), 0) / (sampleCount - 1)
    : 0;

  const wavelet = computeMorletWaveletTransform(clean);
  const hurst = computeHurstExponent(clean);

  let queueCliffRisk: 'CRITICAL' | 'ELEVATED' | 'NOMINAL' = 'NOMINAL';
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

export class WaveletHurstLrdEngine {
  public computeMorletWaveletTransform(series: number[], scales?: number[]) {
    return computeMorletWaveletTransform(series, scales);
  }

  public computeHurstExponent(series: number[]) {
    return computeHurstExponent(series);
  }

  public analyzeWaveletAndHurstLrd(series: number[]) {
    return analyzeWaveletAndHurstLrd(series);
  }
}

export const waveletHurstLrdEngine = new WaveletHurstLrdEngine();
