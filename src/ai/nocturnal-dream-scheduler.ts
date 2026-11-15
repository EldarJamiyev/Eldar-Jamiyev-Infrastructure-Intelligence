/**
 * EJII Autonomous Nocturnal Dream Cycle Scheduler
 *
 * Implements:
 *   1. Quiescence Monitoring:
 *      Monitors operator idle time (e.g. >= 300 seconds without state modifications)
 *      via continualMetaLearningDreamEngine.isQuiescent(idleSeconds).
 *   2. Autonomous Mental Simulation & Continual Learning:
 *      Dispatches counterfactual MAML + EWC offline dream loops during low-load windows.
 *   3. SQLite WAL Persistence:
 *      Tracks dream cycle iterations, Fisher information consolidation, and parameter shifts in ejii_nocturnal_dream_cycles.
 *   4. Safe Timer Architecture:
 *      Interval timers are unref'd to prevent blocking process termination during tests and graceful shutdowns.
 */

'use strict';

import * as crypto from 'node:crypto';

export interface NocturnalSchedulerStatus {
  isRunning: boolean;
  checkIntervalMs: number;
  idleThresholdSec: number;
  totalCyclesExecuted: number;
  lastCycleAt: string | null;
  lastCycleOutcome: any | null;
}

export interface NocturnalDreamRecord {
  cycleId: string;
  dreamId: string;
  triggeredBy: string;
  tasksCount: number;
  totalLoss: number;
  ewcPenalty: number;
  durationMs: number;
  executedAt: string;
}

function getDatabase(): any {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { db } = require('../db/database');
    return db;
  } catch (_) {
    return null;
  }
}

export class NocturnalDreamScheduler {
  private timer: NodeJS.Timeout | null = null;
  private isRunning: boolean = false;
  private checkIntervalMs: number = 60000;
  private idleThresholdSec: number = 300;
  private totalCyclesExecuted: number = 0;
  private lastCycleAt: string | null = null;
  private lastCycleOutcome: any | null = null;

  constructor() {
    this.ensureDatabaseTable();
  }

  public ensureDatabaseTable(): void {
    const db = getDatabase();
    if (!db) return;
    try {
      db.exec(`
        CREATE TABLE IF NOT EXISTS ejii_nocturnal_dream_cycles (
          cycle_id TEXT PRIMARY KEY,
          dream_id TEXT NOT NULL,
          triggered_by TEXT NOT NULL,
          tasks_count INTEGER NOT NULL,
          total_loss REAL NOT NULL,
          ewc_penalty REAL NOT NULL,
          duration_ms REAL NOT NULL,
          executed_at TEXT NOT NULL
        )
      `);
    } catch (_) {}
  }

  public startScheduler(checkIntervalMs: number = 60000, idleThresholdSec: number = 300): boolean {
    if (this.isRunning) {
      return false;
    }
    this.checkIntervalMs = checkIntervalMs;
    this.idleThresholdSec = idleThresholdSec;
    this.isRunning = true;

    this.timer = setInterval(() => {
      this.evaluateAndRunDreamCycle();
    }, this.checkIntervalMs);

    if (this.timer && typeof this.timer.unref === 'function') {
      this.timer.unref();
    }
    return true;
  }

  public stopScheduler(): boolean {
    if (!this.isRunning) {
      return false;
    }
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.isRunning = false;
    return true;
  }

  public evaluateAndRunDreamCycle(): any | null {
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const { continualMetaLearningDreamEngine } = require('./continual-meta-learning-dream-engine');
      if (continualMetaLearningDreamEngine && continualMetaLearningDreamEngine.isQuiescent(this.idleThresholdSec)) {
        return this.runCycleNow();
      }
    } catch (_) {}
    return null;
  }

  public runCycleNow(customTasks?: any[]): any {
    const cycleId = `CYC-DREAM-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
    const executedAt = new Date().toISOString();

    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { continualMetaLearningDreamEngine } = require('./continual-meta-learning-dream-engine');
    const dreamRes = continualMetaLearningDreamEngine.executeDreamCycle(customTasks);

    this.totalCyclesExecuted++;
    this.lastCycleAt = executedAt;
    this.lastCycleOutcome = dreamRes;

    this.persistCycleRecord({
      cycleId,
      dreamId: dreamRes.dreamId || `dream_${Date.now()}`,
      triggeredBy: customTasks ? 'MANUAL_TRIGGER' : 'QUIESCENCE_SCHEDULER',
      tasksCount: dreamRes.simulatedTasksCount || 4,
      totalLoss: dreamRes.totalLoss || 0.0,
      ewcPenalty: dreamRes.ewcPenalty || 0.0,
      durationMs: dreamRes.durationMs || 0.0,
      executedAt
    });

    return {
      cycleId,
      executedAt,
      dreamResult: dreamRes
    };
  }

  private persistCycleRecord(record: NocturnalDreamRecord): void {
    const db = getDatabase();
    if (!db) return;
    try {
      const stmt = db.prepare(`
        INSERT OR REPLACE INTO ejii_nocturnal_dream_cycles (
          cycle_id, dream_id, triggered_by, tasks_count, total_loss,
          ewc_penalty, duration_ms, executed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);
      stmt.run(
        record.cycleId,
        record.dreamId,
        record.triggeredBy,
        record.tasksCount,
        record.totalLoss,
        record.ewcPenalty,
        record.durationMs,
        record.executedAt
      );
    } catch (_) {}
  }

  public getStatus(): NocturnalSchedulerStatus {
    return {
      isRunning: this.isRunning,
      checkIntervalMs: this.checkIntervalMs,
      idleThresholdSec: this.idleThresholdSec,
      totalCyclesExecuted: this.totalCyclesExecuted,
      lastCycleAt: this.lastCycleAt,
      lastCycleOutcome: this.lastCycleOutcome
    };
  }

  public getDreamHistory(limit: number = 10): NocturnalDreamRecord[] {
    const db = getDatabase();
    if (!db) return [];
    try {
      const rows = db.prepare(`
        SELECT
          cycle_id as cycleId,
          dream_id as dreamId,
          triggered_by as triggeredBy,
          tasks_count as tasksCount,
          total_loss as totalLoss,
          ewc_penalty as ewcPenalty,
          duration_ms as durationMs,
          executed_at as executedAt
        FROM ejii_nocturnal_dream_cycles
        ORDER BY executed_at DESC
        LIMIT ?
      `).all(limit);
      return rows || [];
    } catch (_) {
      return [];
    }
  }
}

export const nocturnalDreamScheduler = new NocturnalDreamScheduler();
export default nocturnalDreamScheduler;
