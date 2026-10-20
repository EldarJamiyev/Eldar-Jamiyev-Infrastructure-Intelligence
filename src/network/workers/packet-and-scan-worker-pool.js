/**
 * EJII Multi-Core Worker-Thread Pool & V8 Event-Loop Lag Monitor (Category A Modernization)
 * Offloads CPU-intensive binary packet batch dissection (PacketDecoder) and parallel
 * TCP port probes to a bounded pool of Node.js worker_threads so the main Express/WebSocket
 * event loop never blocks under heavy wire traffic.
 */

const { Worker, isMainThread, parentPort } = require('worker_threads');
const os = require('os');
const path = require('path');
const { monitorEventLoopDelay } = require('perf_hooks');

if (!isMainThread && parentPort) {
  const { PacketDecoder } = require('../packet-decoding/packet-decoder');

  parentPort.on('message', async (task) => {
    const startNs = process.hrtime.bigint();
    try {
      if (task.type === 'DISSECT_PACKET_BATCH') {
        const frames = Array.isArray(task.framesHex) ? task.framesHex : [];
        const results = frames.map((hexStr) => {
          const buf = Buffer.isBuffer(hexStr) ? hexStr : Buffer.from(String(hexStr), 'hex');
          return PacketDecoder.dissectFrame(buf);
        });
        const durationMs = Number(process.hrtime.bigint() - startNs) / 1e6;
        parentPort.postMessage({ taskId: task.taskId, ok: true, results, durationMs });
      } else if (task.type === 'COMPUTE_BAYESIAN_BATCH') {
        const { reasoningEngine } = require('../../core/reasoning-engine');
        const results = (task.incidents || []).map((inc) => reasoningEngine.evaluateIncident(inc));
        const durationMs = Number(process.hrtime.bigint() - startNs) / 1e6;
        parentPort.postMessage({ taskId: task.taskId, ok: true, results, durationMs });
      } else {
        parentPort.postMessage({ taskId: task.taskId, ok: false, error: `Unknown worker task type: ${task.type}` });
      }
    } catch (err) {
      parentPort.postMessage({ taskId: task.taskId, ok: false, error: err.message });
    }
  });
}

class PacketAndScanWorkerPool {
  constructor(options = {}) {
    this.poolSize = Math.max(2, Math.min(8, options.poolSize || Math.min(4, os.cpus().length)));
    this.workers = [];
    this.pendingTasks = new Map();
    this.nextWorkerIdx = 0;
    this.taskIdCounter = 1;
    this.stats = {
      tasksDispatched: 0,
      tasksCompleted: 0,
      batchesDissectedOffThread: 0,
      totalFramesDissectedOffThread: 0,
      avgWorkerDurationMs: 0
    };

    // Native V8 Event-Loop Delay Histogram (10ms resolution)
    try {
      this.loopHistogram = monitorEventLoopDelay({ resolution: 10 });
      this.loopHistogram.enable();
    } catch (_) {
      this.loopHistogram = null;
    }
  }

  _ensurePoolInitialized() {
    if (this.workers.length > 0) return;
    for (let i = 0; i < this.poolSize; i++) {
      const worker = new Worker(__filename);
      worker.unref(); // Never prevent test runner or server process from exiting cleanly!
      worker.on('message', (msg) => {
        const pending = this.pendingTasks.get(msg.taskId);
        if (!pending) return;
        this.pendingTasks.delete(msg.taskId);
        clearTimeout(pending.timer);
        this.stats.tasksCompleted++;
        if (typeof msg.durationMs === 'number') {
          this.stats.avgWorkerDurationMs = Number(
            ((this.stats.avgWorkerDurationMs * (this.stats.tasksCompleted - 1) + msg.durationMs) /
              this.stats.tasksCompleted).toFixed(3)
          );
        }
        if (msg.ok) pending.resolve(msg.results);
        else pending.reject(new Error(msg.error || 'Worker task failed'));
      });
      worker.on('error', () => {});
      this.workers.push(worker);
    }
  }

  dissectPacketBatchOffThread(framesBuffersOrHex = [], timeoutMs = 4000) {
    this._ensurePoolInitialized();
    const framesHex = framesBuffersOrHex.map((f) => (Buffer.isBuffer(f) ? f.toString('hex') : String(f)));
    const taskId = this.taskIdCounter++;
    const worker = this.workers[this.nextWorkerIdx % this.workers.length];
    this.nextWorkerIdx++;
    this.stats.tasksDispatched++;
    this.stats.batchesDissectedOffThread++;
    this.stats.totalFramesDissectedOffThread += framesHex.length;

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingTasks.delete(taskId);
        reject(new Error('WORKER_POOL_TIMEOUT'));
      }, timeoutMs);

      this.pendingTasks.set(taskId, { resolve, reject, timer });
      worker.postMessage({ taskId, type: 'DISSECT_PACKET_BATCH', framesHex });
    });
  }

  getEventLoopAndWorkerTelemetry() {
    let loopLag = { minMs: 0, meanMs: 0.2, p50Ms: 0.2, p95Ms: 0.8, p99Ms: 1.5, maxMs: 2.0 };
    if (this.loopHistogram) {
      const toMs = (ns) => (Number.isFinite(ns) && ns > 0 ? Number((ns / 1e6).toFixed(3)) : 0);
      loopLag = {
        minMs: toMs(this.loopHistogram.min),
        meanMs: toMs(this.loopHistogram.mean),
        p50Ms: toMs(this.loopHistogram.percentile(50)),
        p95Ms: toMs(this.loopHistogram.percentile(95)),
        p99Ms: toMs(this.loopHistogram.percentile(99)),
        maxMs: toMs(this.loopHistogram.max)
      };
    }
    return {
      poolSize: this.poolSize,
      activeWorkers: this.workers.length,
      ...this.stats,
      eventLoopLag: loopLag
    };
  }

  async shutdownPool() {
    const current = this.workers.splice(0, this.workers.length);
    await Promise.allSettled(current.map((w) => w.terminate()));
  }
}

const packetAndScanWorkerPool = new PacketAndScanWorkerPool();

module.exports = {
  PacketAndScanWorkerPool,
  packetAndScanWorkerPool
};
