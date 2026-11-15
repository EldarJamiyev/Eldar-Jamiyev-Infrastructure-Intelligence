#!/usr/bin/env node
/**
 * EJII Autonomous Process Supervisor & Safe Crash Recovery Watchdog
 *
 * Spawns and monitors the EJII server process, collects heartbeats via /health,
 * executes graceful SIGTERM with 5000ms escalation to SIGKILL, performs clean
 * SQLite WAL checkpoints (PRAGMA wal_checkpoint(TRUNCATE)) before reboot,
 * and prevents zombie worker leakages.
 */

'use strict';

const { spawn } = require('child_process');
const http = require('http');
const path = require('path');

class EjiiSupervisor {
  constructor(options = {}) {
    this.serverScript = options.serverScript || path.resolve(__dirname, '..', 'src', 'server.js');
    this.port = options.port || Number(process.env.EJII_PORT) || 3000;
    this.host = options.host || process.env.EJII_HOST || '127.0.0.1';
    this.maxRestarts = options.maxRestarts || 10;
    this.checkIntervalMs = options.checkIntervalMs || 5000;
    this.gracePeriodMs = options.gracePeriodMs || 5000;
    
    this.childProcess = null;
    this.restartCount = 0;
    this.isShuttingDown = false;
    this.healthTimer = null;
    this.consecutiveFailures = 0;
  }

  checkpointWal() {
    try {
      const dbModule = require('../src/db/database');
      if (dbModule && dbModule.db && typeof dbModule.db.prepare === 'function') {
        dbModule.db.prepare('PRAGMA wal_checkpoint(TRUNCATE)').run();
        console.log('[Supervisor] Executed clean SQLite PRAGMA wal_checkpoint(TRUNCATE).');
      }
    } catch (err) {
      // Best-effort WAL checkpoint
    }
  }

  start() {
    if (this.childProcess) return;
    this.isShuttingDown = false;
    this.spawnChild();
    this.startHealthChecks();
  }

  spawnChild() {
    console.log(`[Supervisor] Spawning EJII server: node ${this.serverScript}`);
    this.childProcess = spawn(process.execPath, [this.serverScript], {
      stdio: 'inherit',
      env: { ...process.env, EJII_SUPERVISED: '1', EJII_PORT: String(this.port), EJII_HOST: this.host }
    });

    this.childProcess.on('exit', (code, signal) => {
      console.log(`[Supervisor] Child exited with code=${code}, signal=${signal}`);
      this.childProcess = null;
      if (!this.isShuttingDown) {
        this.restartCount++;
        this.checkpointWal();
        if (this.restartCount < this.maxRestarts) {
          console.log(`[Supervisor] Auto-restarting child in 1500ms (attempt ${this.restartCount}/${this.maxRestarts})...`);
          setTimeout(() => this.spawnChild(), 1500);
        } else {
          console.error('[Supervisor] Max restart limit reached. Halting supervisor.');
          process.exit(1);
        }
      }
    });
  }

  startHealthChecks() {
    if (this.healthTimer) clearInterval(this.healthTimer);
    this.healthTimer = setInterval(() => {
      this.checkHealth();
    }, this.checkIntervalMs);
    if (this.healthTimer.unref) this.healthTimer.unref();
  }

  checkHealth() {
    if (!this.childProcess || this.isShuttingDown) return;

    const req = http.get(`http://${this.host}:${this.port}/health`, { timeout: 3000 }, (res) => {
      if (res.statusCode >= 200 && res.statusCode < 400) {
        this.consecutiveFailures = 0;
      } else {
        this.handleHealthFailure(`Status code: ${res.statusCode}`);
      }
    });

    req.on('error', (err) => {
      this.handleHealthFailure(err.message);
    });

    req.on('timeout', () => {
      req.destroy();
      this.handleHealthFailure('Timeout after 3000ms');
    });
  }

  handleHealthFailure(reason) {
    this.consecutiveFailures++;
    console.warn(`[Supervisor] Health probe warning (${this.consecutiveFailures}/5): ${reason}`);
    if (this.consecutiveFailures >= 5) {
      console.error('[Supervisor] Health probe failed 5 consecutive times. Recycling child process...');
      this.consecutiveFailures = 0;
      this.recycleChild();
    }
  }

  async recycleChild() {
    if (!this.childProcess) return;
    const target = this.childProcess;
    target.kill('SIGTERM');

    const forceKillTimer = setTimeout(() => {
      try {
        if (target && !target.killed) {
          target.kill('SIGKILL');
        }
      } catch (_) {}
    }, this.gracePeriodMs);

    if (forceKillTimer.unref) forceKillTimer.unref();
  }

  async stop() {
    this.isShuttingDown = true;
    if (this.healthTimer) {
      clearInterval(this.healthTimer);
      this.healthTimer = null;
    }

    if (this.childProcess) {
      const target = this.childProcess;
      return new Promise((resolve) => {
        const forceKillTimer = setTimeout(() => {
          try {
            if (target && !target.killed) {
              target.kill('SIGKILL');
            }
          } catch (_) {}
          this.checkpointWal();
          resolve();
        }, this.gracePeriodMs);

        target.once('exit', () => {
          clearTimeout(forceKillTimer);
          this.checkpointWal();
          resolve();
        });

        target.kill('SIGTERM');
      });
    } else {
      this.checkpointWal();
    }
  }
}

const ejiiSupervisor = new EjiiSupervisor();

if (require.main === module) {
  console.log('========================================================================');
  console.log('  EJII Autonomous Process Supervisor & Safe Crash Recovery Watchdog     ');
  console.log('========================================================================');

  ejiiSupervisor.start();

  const shutdownSignals = ['SIGINT', 'SIGTERM'];
  for (const sig of shutdownSignals) {
    process.on(sig, async () => {
      console.log(`\n[Supervisor] Caught ${sig}, initiating graceful shutdown...`);
      await ejiiSupervisor.stop();
      process.exit(0);
    });
  }
}

module.exports = {
  EjiiSupervisor,
  ejiiSupervisor
};
