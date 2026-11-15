/**
 * EJII Betti Curve Forensics & Triadic Loop Detection Engine
 *
 * Extracts Betti profiles (beta_0, beta_1, beta_2) across filtration sweeps and detects
 * persistent 1-dimensional cycles and triadic routing loops in network topologies.
 * Dual-Maintenance CommonJS Implementation.
 */

'use strict';

class BettiCurveForensics {
  constructor() {
    this.profilesExtracted = 0;
    this.loopsDetected = 0;
  }

  extractBettiProfile(persistenceResult) {
    this.profilesExtracted++;
    const profileId = `betti_${Date.now()}_${Math.floor(Math.random() * 10000)}`;

    if (!persistenceResult) {
      return {
        profileId,
        filtrationSteps: [],
        maxBetti0: 0,
        maxBetti1: 0,
        maxBetti2: 0,
        persistentCyclesCount: 0,
        dominantCycles: []
      };
    }

    const maxBetti0 = Math.max(0, ...(persistenceResult.betti0Trajectory || [0]));
    const maxBetti1 = Math.max(0, ...(persistenceResult.betti1Trajectory || [0]));
    const maxBetti2 = Math.max(0, ...(persistenceResult.betti2Trajectory || [0]));

    const dominantCycles = (persistenceResult.features || [])
      .filter((f) => f.dimension === 1 && f.lifespan >= 1.0)
      .sort((a, b) => b.lifespan - a.lifespan);

    return {
      profileId,
      filtrationSteps: persistenceResult.filtrationSteps || [],
      maxBetti0,
      maxBetti1,
      maxBetti2,
      persistentCyclesCount: dominantCycles.length,
      dominantCycles
    };
  }

  detectTriadicRouteLoops(bettiProfile) {
    const reportId = `loop_rep_${Date.now()}_${Math.floor(Math.random() * 10000)}`;

    if (!bettiProfile || !bettiProfile.dominantCycles || bettiProfile.dominantCycles.length === 0) {
      return {
        reportId,
        hasTriadicLoops: false,
        loopSeverity: 'NONE',
        detectedLoops: []
      };
    }

    const detected = bettiProfile.dominantCycles.map((cycle, idx) => {
      return {
        loopId: `triad_loop_${idx + 1}`,
        lifespan: cycle.lifespan,
        description: `Persistent 1D simplicial cycle alive across filtration interval [${Number(cycle.birth).toFixed(2)}, ${Number(cycle.death).toFixed(2)}]`
      };
    });

    const hasTriadicLoops = detected.length > 0;
    if (hasTriadicLoops) {
      this.loopsDetected += detected.length;
    }

    const loopSeverity = detected.length >= 2 ? 'HIGH_OSCILLATION' : 'LOW';

    return {
      reportId,
      hasTriadicLoops,
      loopSeverity,
      detectedLoops: detected
    };
  }

  getMetrics() {
    return {
      profilesExtracted: this.profilesExtracted,
      loopsDetected: this.loopsDetected
    };
  }
}

const bettiCurveForensics = new BettiCurveForensics();

module.exports = {
  BettiCurveForensics,
  bettiCurveForensics
};
