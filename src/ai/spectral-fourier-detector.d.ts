/**
 * Fast Fourier Transform (FFT) Welch Periodogram & Spectral Beacon Detector
 * Pure Float64Array implementation of Radix-2 Cooley-Tukey FFT, Hann windowing,
 * Wiener Entropy (Spectral Flatness), and Periodic Anomaly Detection.
 */
export interface SpectralPeak {
    readonly frequencyHz: number;
    readonly periodSeconds: number;
    readonly powerDb: number;
    readonly signalToNoiseRatioDb: number;
}
export interface SpectralAnalysisResult {
    readonly sampleCount: number;
    readonly samplingRateHz: number;
    readonly nyquistFrequencyHz: number;
    readonly frequencyBins: number;
    readonly spectralFlatness: number;
    readonly noiseFloorDb: number;
    readonly dominantPeaks: readonly SpectralPeak[];
    readonly periodicAnomalyDetected: boolean;
    readonly anomalyClassification?: 'C2_PERIODIC_BEACON' | 'ROUTING_TIMER_STORM' | 'MICROBURST_CYCLE' | 'NOMINAL_STOCHASTIC';
    readonly evidenceDistinction?: 'STOCHASTIC_BASELINE' | 'BENIGN_PERIODIC_BEHAVIOR' | 'SUSPICIOUS_PERIODICITY' | 'STATISTICAL_ANOMALY' | 'CORROBORATED_SECURITY_FINDING';
    readonly corroborationRequired?: boolean;
    readonly evidentiaryNote?: string;
    readonly frequencies: readonly number[];
    readonly powerSpectrumDb: readonly number[];
}
export declare class SpectralFourierDetector {
    /**
     * Finds the next power of 2 >= n
     */
    static nextPowerOf2(n: number): number;
    /**
     * Generates a Hann window array of size N
     * w[n] = 0.5 * (1 - cos(2 * pi * n / (N - 1)))
     */
    static generateHannWindow(N: number): Float64Array;
    /**
     * In-place Radix-2 Cooley-Tukey Fast Fourier Transform (Decimation-in-time)
     */
    static fft(real: Float64Array, imag: Float64Array): void;
    /**
     * Computes the one-sided Power Spectral Density (PSD) periodogram and analyzes periodicity.
     * @param timeSeries Float64Array or number[] of discrete real-valued samples
     * @param samplingRateHz Sampling frequency fs in Hertz (default: 10 Hz)
     */
    static analyze(timeSeries: ArrayLike<number>, samplingRateHz?: number): SpectralAnalysisResult;
}
