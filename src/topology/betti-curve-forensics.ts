/**
 * EJII Betti Curve Forensics & Triadic Loop Detection Engine
 *
 * Extracts Betti profiles (beta_0, beta_1, beta_2) across filtration sweeps and detects
 * persistent 1-dimensional cycles and triadic routing loops in network topologies.
 * Dual-Maintenance TypeScript Reference.
 */

import { PersistenceResult, PersistenceFeature } from './persistent-simplicial-homology';

export interface BettiProfileReceipt {
  profileId: string;
  filtrationSteps: number[];
  maxBetti0: number;
  maxBetti1: number;
  maxBetti2: number;
  persistentCyclesCount: number;
  dominantCycles: PersistenceFeature[];
}

export interface TriadicLoopReport {
  reportId: string;
  hasTriadicLoops: boolean;
  loopSeverity: 'NONE' | 'LOW' | 'HIGH_OSCILLATION';
  detectedLoops: Array<{
    loopId: string;
    lifespan: number;
    description: string;
  }>;
}

export class BettiCurveForensics {
  private profilesExtracted: number = 0;
  private loopsDetected: number = 0;

  constructor() {}

  public extractBettiProfile(persistenceResult: PersistenceResult): BettiProfileReceipt {
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

    const maxBetti0 = Math.max(0, ...persistenceResult.betti0Trajectory);
    const maxBetti1 = Math.max(0, ...persistenceResult.betti1Trajectory);
    const maxBetti2 = Math.max(0, ...persistenceResult.betti2Trajectory);

    const dominantCycles = (persistenceResult.features || [])
      .filter((f) => f.dimension === 1 && f.lifespan >= 1.0)
      .sort((a, b) => b.lifespan - a.lifespan);

    return {
      profileId,
      filtrationSteps: persistenceResult.filtrationSteps,
      maxBetti0,
      maxBetti1,
      maxBetti2,
      persistentCyclesCount: dominantCycles.length,
      dominantCycles
    };
  }

  public detectTriadicRouteLoops(bettiProfile: BettiProfileReceipt): TriadicLoopReport {
    const reportId = `loop_rep_${Date.now()}_${Math.floor(Math.random() * 10000)}`;

    if (!bettiProfile || bettiProfile.dominantCycles.length === 0) {
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
        description: `Persistent 1D simplicial cycle alive across filtration interval [${cycle.birth.toFixed(2)}, ${cycle.death.toFixed(2)}]`
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

  public getMetrics(): { profilesExtracted: number; loopsDetected: number } {
    return {
      profilesExtracted: this.profilesExtracted,
      loopsDetected: this.loopsDetected
    };
  }
}

export const bettiCurveForensics = new BettiCurveForensics();
