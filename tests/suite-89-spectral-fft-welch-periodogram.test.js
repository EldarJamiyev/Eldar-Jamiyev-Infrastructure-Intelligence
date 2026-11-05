// tests/suite-89-spectral-fft-welch-periodogram.test.js
/**
 * EJII Test Suite 89: Spectral Fourier Detector, Welch Periodogram & Wiener Entropy
 * Verifies pure Float64Array Cooley-Tukey Radix-2 FFT, Hann windowing math,
 * Power Spectral Density (PSD) periodogram, Wiener Entropy (Spectral Flatness),
 * periodic beacon / C2 periodicity classification, and /api/rca/spectral-fft REST endpoints.
 */

'use strict';

const assert = require('node:assert/strict');
const { SpectralFourierDetector } = require('../src/ai/spectral-fourier-detector');
const routesRca = require('../src/api/routes-rca');

async function runSuite89SpectralFftWelchPeriodogram() {
  console.log('========================================================================');
  console.log('  === [SUITE 89] SPECTRAL FFT & WIENER ENTROPY PERIODOGRAM ===           ');
  console.log('========================================================================\n');

  // [89.1] Next Power of 2 & Hann Window Generation
  console.log('[Test 89.1] Verifying nextPowerOf2 and Hann window symmetry...');
  assert.strictEqual(SpectralFourierDetector.nextPowerOf2(1), 1);
  assert.strictEqual(SpectralFourierDetector.nextPowerOf2(5), 8);
  assert.strictEqual(SpectralFourierDetector.nextPowerOf2(60), 64);
  assert.strictEqual(SpectralFourierDetector.nextPowerOf2(64), 64);
  assert.strictEqual(SpectralFourierDetector.nextPowerOf2(65), 128);

  const N = 32;
  const hann = SpectralFourierDetector.generateHannWindow(N);
  assert.strictEqual(hann.length, N);
  assert.ok(Math.abs(hann[0]) < 1e-6, `Hann[0] must be ~0, got ${hann[0]}`);
  assert.ok(Math.abs(hann[N - 1]) < 1e-6, `Hann[N-1] must be ~0, got ${hann[N - 1]}`);
  assert.ok(hann[N / 2] > 0.95, `Hann peak at midpoint must be near 1.0, got ${hann[N / 2]}`);

  // Test Hann symmetry: w[i] == w[N-1-i]
  for (let i = 0; i < N / 2; i++) {
    assert.ok(Math.abs(hann[i] - hann[N - 1 - i]) < 1e-9, `Hann window must be symmetric at index ${i}`);
  }
  console.log('  ✓ Hann windowing mathematically verified (symmetric, zero-ends, unit peak).');

  // [89.2] Radix-2 Cooley-Tukey FFT of Known Sinusoid
  console.log('[Test 89.2] Testing Radix-2 Cooley-Tukey FFT on a pure 2 Hz sine wave (fs = 16 Hz)...');
  // Sampling rate fs = 16 Hz, N = 16 points (duration = 1.0s, resolution delta_f = 1 Hz)
  // 2 Hz tone means energy must peak at bin k = 2 and conjugate bin k = 14
  const fs1 = 16;
  const nPoints = 16;
  const real = new Float64Array(nPoints);
  const imag = new Float64Array(nPoints);

  const targetFreq = 2.0;
  for (let i = 0; i < nPoints; i++) {
    const t = i / fs1;
    real[i] = 5.0 * Math.cos(2 * Math.PI * targetFreq * t);
    imag[i] = 0;
  }

  SpectralFourierDetector.fft(real, imag);

  // Peak power calculation: P[k] = real[k]^2 + imag[k]^2
  let maxBin = 0;
  let maxPower = -1;
  for (let k = 0; k < nPoints / 2; k++) {
    const p = real[k] * real[k] + imag[k] * imag[k];
    if (p > maxPower) {
      maxPower = p;
      maxBin = k;
    }
  }

  assert.strictEqual(maxBin, 2, `Peak frequency bin must be exactly 2 for 2 Hz sinusoid, got bin ${maxBin}`);
  console.log(`  ✓ Pure 2 Hz sinusoid correctly resolved at bin ${maxBin} (Power=${maxPower.toFixed(2)}).`);

  // [89.3] Wiener Entropy (Spectral Flatness Measure - SFM)
  console.log('[Test 89.3] Validating Wiener Entropy (SFM) discrimination (Tone vs White Noise)...');
  // Generate 64-sample pure tone with low noise: SFM should be << 0.5
  const toneSeries = [];
  for (let i = 0; i < 64; i++) {
    const t = i / 10.0;
    toneSeries.push(10.0 * Math.sin(2 * Math.PI * 1.5 * t));
  }
  const toneAnalysis = SpectralFourierDetector.analyze(toneSeries, 10.0);
  assert.ok(toneAnalysis.spectralFlatness < 0.40, `Tone spectral flatness must be < 0.40, got ${toneAnalysis.spectralFlatness}`);
  assert.ok(toneAnalysis.periodicAnomalyDetected, 'Periodic anomaly must be flagged for pure tone');
  assert.ok(toneAnalysis.dominantPeaks.length > 0, 'Must detect at least 1 dominant peak');
  const primaryPeak = toneAnalysis.dominantPeaks[0];
  assert.ok(Math.abs(primaryPeak.frequencyHz - 1.5) <= 0.35, `Primary peak (${primaryPeak.frequencyHz} Hz) must be near 1.5 Hz`);
  console.log(`  ✓ Tone analyzed: SFM=${toneAnalysis.spectralFlatness.toFixed(3)}, Peak=${primaryPeak.frequencyHz.toFixed(2)} Hz, Classification=${toneAnalysis.anomalyClassification}`);

  // Generate 64-sample Gaussian pseudo-white noise: SFM should be significantly higher
  const noiseSeries = [];
  for (let i = 0; i < 64; i++) {
    noiseSeries.push((Math.random() - 0.5) * 20.0);
  }
  const noiseAnalysis = SpectralFourierDetector.analyze(noiseSeries, 10.0);
  assert.ok(noiseAnalysis.spectralFlatness > toneAnalysis.spectralFlatness, 'Noise SFM must be higher than pure tone SFM');
  console.log(`  ✓ White noise analyzed: SFM=${noiseAnalysis.spectralFlatness.toFixed(3)} (Flat spectrum).`);

  // [89.4] REST API Endpoint: POST /api/rca/spectral-fft
  console.log('[Test 89.4] Testing POST /api/rca/spectral-fft via Express router stack...');
  const postLayer = routesRca.stack.find(s => s.route && s.route.path === '/spectral-fft' && s.route.methods.post);
  assert.ok(postLayer, 'Route POST /spectral-fft must exist in routes-rca.js');

  let postJson = null;
  const mockReqPost = {
    body: {
      timeSeries: toneSeries,
      samplingRateHz: 10
    }
  };
  const mockResPost = {
    statusCode: 200,
    status(c) { this.statusCode = c; return this; },
    json(d) { postJson = d; return this; }
  };
  const postHandler = postLayer.route.stack[postLayer.route.stack.length - 1].handle;
  postHandler(mockReqPost, mockResPost, () => {});

  assert.ok(postJson, 'POST must return JSON');
  assert.strictEqual(postJson.success, true);
  assert.strictEqual(postJson.sampleCount, 64);
  assert.ok(typeof postJson.spectralFlatness === 'number');
  console.log(`  ✓ POST /api/rca/spectral-fft responded with 200 OK: SFM=${postJson.spectralFlatness.toFixed(3)}`);

  // [89.5] REST API Endpoint: GET /api/rca/spectral-fft
  console.log('[Test 89.5] Testing GET /api/rca/spectral-fft via Express router stack...');
  const getLayer = routesRca.stack.find(s => s.route && s.route.path === '/spectral-fft' && s.route.methods.get);
  assert.ok(getLayer, 'Route GET /spectral-fft must exist in routes-rca.js');

  let getJson = null;
  const mockReqGet = { query: {} };
  const mockResGet = {
    statusCode: 200,
    status(c) { this.statusCode = c; return this; },
    json(d) { getJson = d; return this; }
  };
  const getHandler = getLayer.route.stack[getLayer.route.stack.length - 1].handle;
  getHandler(mockReqGet, mockResGet, () => {});

  assert.ok(getJson, 'GET must return JSON');
  assert.strictEqual(getJson.success, true);
  assert.ok(Array.isArray(getJson.frequencies));
  assert.ok(Array.isArray(getJson.powerSpectrumDb));
  console.log(`  ✓ GET /api/rca/spectral-fft responded with 200 OK: ${getJson.frequencies.length} frequency bins.`);

  console.log('\n========================================================================');
  console.log('  SUITE 89 PASSED: SPECTRAL FFT & WIENER ENTROPY 100% GREEN             ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runSuite89SpectralFftWelchPeriodogram().catch((err) => {
    console.error('Suite 89 failed:', err);
    process.exit(1);
  });
}

module.exports = {
  runSuite89SpectralFftWelchPeriodogram,
  runSuite89: runSuite89SpectralFftWelchPeriodogram
};
