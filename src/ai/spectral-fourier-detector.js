"use strict";
// src/ai/spectral-fourier-detector.ts
/**
 * Fast Fourier Transform (FFT) Welch Periodogram & Spectral Beacon Detector
 * Pure Float64Array implementation of Radix-2 Cooley-Tukey FFT, Hann windowing,
 * Wiener Entropy (Spectral Flatness), and Periodic Anomaly Detection.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.SpectralFourierDetector = void 0;
class SpectralFourierDetector {
    /**
     * Finds the next power of 2 >= n
     */
    static nextPowerOf2(n) {
        let p = 1;
        while (p < n)
            p <<= 1;
        return p;
    }
    /**
     * Generates a Hann window array of size N
     * w[n] = 0.5 * (1 - cos(2 * pi * n / (N - 1)))
     */
    static generateHannWindow(N) {
        const safeN = Math.max(0, Math.floor(N));
        const window = new Float64Array(safeN);
        if (safeN === 0)
            return window;
        if (safeN === 1) {
            window[0] = 1.0;
            return window;
        }
        const factor = (2 * Math.PI) / (safeN - 1);
        for (let i = 0; i < safeN; i++) {
            window[i] = 0.5 * (1.0 - Math.cos(factor * i));
        }
        return window;
    }
    /**
     * In-place Radix-2 Cooley-Tukey Fast Fourier Transform (Decimation-in-time)
     */
    static fft(real, imag) {
        const n = real.length;
        if (n !== imag.length) {
            throw new Error('Real and imaginary buffers must have matching lengths');
        }
        if (n === 0 || (n & (n - 1)) !== 0) {
            throw new Error(`FFT size must be a power of 2, received: ${n}`);
        }
        // Bit-reversal permutation
        let j = 0;
        for (let i = 0; i < n - 1; i++) {
            if (i < j) {
                const tempR = real[i];
                real[i] = real[j];
                real[j] = tempR;
                const tempI = imag[i];
                imag[i] = imag[j];
                imag[j] = tempI;
            }
            let k = n >> 1;
            while (k <= j) {
                j -= k;
                k >>= 1;
            }
            j += k;
        }
        // Cooley-Tukey butterfly computation
        for (let len = 2; len <= n; len <<= 1) {
            const halfLen = len >> 1;
            const angle = (-2 * Math.PI) / len;
            const wStepR = Math.cos(angle);
            const wStepI = Math.sin(angle);
            for (let i = 0; i < n; i += len) {
                let wR = 1.0;
                let wI = 0.0;
                for (let k = 0; k < halfLen; k++) {
                    const posEven = i + k;
                    const posOdd = i + k + halfLen;
                    const uR = real[posEven];
                    const uI = imag[posEven];
                    // Complex multiply: odd * w
                    const tR = real[posOdd] * wR - imag[posOdd] * wI;
                    const tI = real[posOdd] * wI + imag[posOdd] * wR;
                    real[posEven] = uR + tR;
                    imag[posEven] = uI + tI;
                    real[posOdd] = uR - tR;
                    imag[posOdd] = uI - tI;
                    const nextWR = wR * wStepR - wI * wStepI;
                    const nextWI = wR * wStepI + wI * wStepR;
                    wR = nextWR;
                    wI = nextWI;
                }
            }
        }
    }
    /**
     * Computes the one-sided Power Spectral Density (PSD) periodogram and analyzes periodicity.
     * @param timeSeries Float64Array or number[] of discrete real-valued samples
     * @param samplingRateHz Sampling frequency fs in Hertz (default: 10 Hz)
     */
    static analyze(timeSeries, samplingRateHz = 10) {
        const safeFs = Number.isFinite(samplingRateHz) && samplingRateHz > 0 ? samplingRateHz : 10;
        const rawLen = timeSeries ? timeSeries.length : 0;
        // Filter/sanitize NaN and Infinity samples
        const cleanSamples = [];
        for (let i = 0; i < rawLen; i++) {
            const v = Number(timeSeries[i]);
            if (Number.isFinite(v)) {
                cleanSamples.push(v);
            }
        }
        if (cleanSamples.length < 4) {
            return {
                sampleCount: rawLen,
                samplingRateHz: safeFs,
                nyquistFrequencyHz: safeFs / 2,
                frequencyBins: 0,
                spectralFlatness: 1.0,
                noiseFloorDb: -100,
                dominantPeaks: [],
                periodicAnomalyDetected: false,
                anomalyClassification: 'NOMINAL_STOCHASTIC',
                evidenceDistinction: 'STOCHASTIC_BASELINE',
                corroborationRequired: false,
                evidentiaryNote: 'Insufficient finite samples (<4) for spectral periodogram analysis.',
                frequencies: [],
                powerSpectrumDb: []
            };
        }
        const effLen = cleanSamples.length;
        // Remove DC offset (mean centering)
        let sum = 0;
        for (let i = 0; i < effLen; i++)
            sum += cleanSamples[i];
        const mean = sum / effLen;
        // Check for constant / DC-only series (zero AC variance)
        let acEnergy = 0;
        for (let i = 0; i < effLen; i++) {
            const diff = cleanSamples[i] - mean;
            acEnergy += diff * diff;
        }
        const N = Math.max(16, this.nextPowerOf2(effLen));
        const halfN = N >> 1;
        const df = safeFs / N;
        if (acEnergy < 1e-12) {
            const flatFreqs = Array.from({ length: halfN }, (_, k) => Number((k * df).toFixed(3)));
            const flatDb = new Array(halfN).fill(-120);
            return {
                sampleCount: rawLen,
                samplingRateHz: safeFs,
                nyquistFrequencyHz: safeFs / 2,
                frequencyBins: halfN,
                spectralFlatness: 1.0,
                noiseFloorDb: -120,
                dominantPeaks: [],
                periodicAnomalyDetected: false,
                anomalyClassification: 'NOMINAL_STOCHASTIC',
                evidenceDistinction: 'STOCHASTIC_BASELINE',
                corroborationRequired: false,
                evidentiaryNote: 'Constant DC signal (zero AC variance); no periodic oscillation present.',
                frequencies: flatFreqs,
                powerSpectrumDb: flatDb
            };
        }
        const real = new Float64Array(N);
        const imag = new Float64Array(N);
        const window = this.generateHannWindow(effLen);
        // Window and copy into padded buffer
        let windowSumSq = 0;
        for (let i = 0; i < effLen; i++) {
            const w = window[i];
            windowSumSq += w * w;
            real[i] = (cleanSamples[i] - mean) * w;
        }
        if (windowSumSq === 0)
            windowSumSq = 1;
        this.fft(real, imag);
        const psd = new Float64Array(halfN);
        const powerDbArr = new Array(halfN);
        const freqArr = new Array(halfN);
        const scalingFactor = 2.0 / (effLen * safeFs * (windowSumSq / effLen));
        let logPsdSum = 0;
        let psdSum = 0;
        const epsilon = 1e-12;
        for (let k = 0; k < halfN; k++) {
            const magSq = real[k] * real[k] + imag[k] * imag[k];
            const p = Math.max(epsilon, magSq * scalingFactor);
            psd[k] = p;
            const db = 10 * Math.log10(p);
            powerDbArr[k] = Number(db.toFixed(2));
            freqArr[k] = Number((k * df).toFixed(3));
            // Exclude DC component (k=0) from Wiener entropy calculation
            if (k > 0) {
                logPsdSum += Math.log(p);
                psdSum += p;
            }
        }
        // Compute Spectral Flatness Measure (SFM / Wiener Entropy)
        const validBins = Math.max(1, halfN - 1);
        const geometricMean = Math.exp(logPsdSum / validBins);
        const arithmeticMean = psdSum / validBins;
        let spectralFlatness = arithmeticMean > 0 ? (geometricMean / arithmeticMean) : 1.0;
        spectralFlatness = Math.min(1.0, Math.max(0.0, spectralFlatness));
        // Calculate Noise Floor (median of PSD power)
        const sortedDb = [...powerDbArr.slice(1)].sort((a, b) => a - b);
        const noiseFloorDb = sortedDb.length > 0 ? sortedDb[Math.floor(sortedDb.length * 0.5)] : -80;
        // Peak Extraction
        const peaks = [];
        for (let k = 2; k < halfN - 1; k++) {
            if (powerDbArr[k] > powerDbArr[k - 1] && powerDbArr[k] > powerDbArr[k + 1]) {
                const peakPower = powerDbArr[k];
                const snr = peakPower - noiseFloorDb;
                if (snr > 3.0 && freqArr[k] > 0) {
                    peaks.push({
                        frequencyHz: freqArr[k],
                        periodSeconds: Number((1.0 / freqArr[k]).toFixed(3)),
                        powerDb: peakPower,
                        signalToNoiseRatioDb: Number(snr.toFixed(2))
                    });
                }
            }
        }
        // Sort peaks by SNR descending and take top 3
        peaks.sort((a, b) => b.signalToNoiseRatioDb - a.signalToNoiseRatioDb);
        const dominantPeaks = peaks.slice(0, 3);
        const highestSnr = dominantPeaks.length > 0 ? dominantPeaks[0].signalToNoiseRatioDb : 0;
        const periodicAnomalyDetected = highestSnr >= 8.0 && spectralFlatness < 0.45;
        let anomalyClassification = 'NOMINAL_STOCHASTIC';
        let evidenceDistinction = 'STOCHASTIC_BASELINE';
        let corroborationRequired = false;
        let evidentiaryNote = 'Stochastic signal distribution within normal Wiener entropy bounds.';
        if (periodicAnomalyDetected && dominantPeaks.length > 0) {
            const topPeak = dominantPeaks[0];
            corroborationRequired = true;
            if (topPeak.periodSeconds >= 5.0 && topPeak.periodSeconds <= 300.0) {
                anomalyClassification = 'C2_PERIODIC_BEACON';
                evidenceDistinction = highestSnr >= 14.0 ? 'SUSPICIOUS_PERIODICITY' : 'BENIGN_PERIODIC_BEHAVIOR';
                evidentiaryNote = `Periodic spectral peak at T=${topPeak.periodSeconds}s (SNR ${topPeak.signalToNoiseRatioDb} dB). Note: Spectral periodicity alone can reflect benign polling, NTP/keepalive timers, or scheduled health checks; corroboration with process/socket/DNS evidence is required before confirming C2 activity.`;
            }
            else if (topPeak.periodSeconds < 1.0) {
                anomalyClassification = 'MICROBURST_CYCLE';
                evidenceDistinction = 'STATISTICAL_ANOMALY';
                evidentiaryNote = `High-frequency periodic microburst cycle at f=${topPeak.frequencyHz}Hz (T=${topPeak.periodSeconds}s).`;
            }
            else {
                anomalyClassification = 'ROUTING_TIMER_STORM';
                evidenceDistinction = 'BENIGN_PERIODIC_BEHAVIOR';
                evidentiaryNote = `Low-frequency control-plane timer periodicity at T=${topPeak.periodSeconds}s.`;
            }
        }
        return {
            sampleCount: rawLen,
            samplingRateHz: safeFs,
            nyquistFrequencyHz: safeFs / 2,
            frequencyBins: halfN,
            spectralFlatness: Number(spectralFlatness.toFixed(4)),
            noiseFloorDb: Number(noiseFloorDb.toFixed(2)),
            dominantPeaks,
            periodicAnomalyDetected,
            anomalyClassification,
            evidenceDistinction,
            corroborationRequired,
            evidentiaryNote,
            frequencies: freqArr,
            powerSpectrumDb: powerDbArr
        };
    }
}
exports.SpectralFourierDetector = SpectralFourierDetector;
//# sourceMappingURL=spectral-fourier-detector.js.map