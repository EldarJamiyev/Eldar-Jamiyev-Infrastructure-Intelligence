/**
 * EJII Standalone Lightweight Edge Agent Daemon (`ejii-agent`)
 *
 * Runs locally on remote branches, VLAN observation points, or container hosts.
 * Executes:
 *   - Local DNS resolutions against branch DNS
 *   - Local TCP connect timing against local servers
 *   - Local ICMP ping against branch gateways
 *   - Local HTTP health checks
 * Reports back to EJII central control plane.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;
const net = require('net');
const http = require('http');
const https = require('https');
const { realPing } = require('../../protocols/icmp-ping');
const { db } = require('../../db/database');
const { DATA_DIR } = require('../../config');
const { deriveAgentCredential } = require('./edge-agent-service');

class EdgeAgentDaemon {
  constructor(config = {}) {
    this.agentId = config.agentId || 'agent-lon-01';
    this.secretKey = config.secretKey || process.env.EJII_AGENT_SECRET || deriveAgentCredential(this.agentId);
    this.serverUrl = config.serverUrl || 'http://localhost:3000';
    this.siteId = config.siteId || 'site-hq-lon';
    this.isRunning = false;
    this.maxPendingQueueSize = Number(config.maxPendingQueueSize) || 100;
    const safeAgentFileKey = String(this.agentId).replace(/[^a-zA-Z0-9_-]/g, '_');
    this.outboxFilePath = config.outboxFilePath || path.join(DATA_DIR, `agent-outbox-${safeAgentFileKey}.json`);
    this.durableStorageMode = 'SQLITE_AND_DISK_OUTBOX';
    this._ensureOutboxTable();
    this.pendingResultQueue = this._loadDurableOutbox();
  }

  _ensureOutboxTable() {
    try {
      db.exec(`
        CREATE TABLE IF NOT EXISTS edge_agent_durable_outbox (
          task_id TEXT NOT NULL,
          agent_id TEXT NOT NULL,
          lease_epoch INTEGER DEFAULT 1,
          result_json TEXT NOT NULL,
          attempts INTEGER DEFAULT 1,
          queued_at INTEGER NOT NULL,
          PRIMARY KEY (agent_id, task_id)
        );
      `);
    } catch (_) {}
  }

  /**
   * Hydrate pending task results from SQLite and/or atomic disk outbox file across daemon restarts
   */
  _loadDurableOutbox() {
    const mergedMap = new Map();
    try {
      const rows = db.prepare(`
        SELECT task_id, lease_epoch, result_json, attempts, queued_at
        FROM edge_agent_durable_outbox
        WHERE agent_id = ?
        ORDER BY queued_at ASC
      `).all(this.agentId);
      for (const r of rows) {
        let parsedResult = {};
        try {
          parsedResult = JSON.parse(r.result_json);
        } catch (_) {}
        mergedMap.set(r.task_id, {
          taskId: r.task_id,
          result: parsedResult,
          leaseEpoch: r.lease_epoch !== null && r.lease_epoch !== undefined ? Number(r.lease_epoch) : null,
          attempts: Number(r.attempts) || 1,
          queuedAt: Number(r.queued_at) || Date.now(),
          durablePersisted: true
        });
      }
    } catch (_) {}

    try {
      if (this.outboxFilePath && fs.existsSync(this.outboxFilePath)) {
        const raw = fs.readFileSync(this.outboxFilePath, 'utf8');
        const diskItems = JSON.parse(raw);
        if (Array.isArray(diskItems)) {
          for (const item of diskItems) {
            if (item && item.taskId && !mergedMap.has(item.taskId)) {
              mergedMap.set(item.taskId, {
                taskId: item.taskId,
                result: item.result || {},
                leaseEpoch: item.leaseEpoch !== undefined ? item.leaseEpoch : null,
                attempts: Number(item.attempts) || 1,
                queuedAt: Number(item.queuedAt) || Date.now(),
                durablePersisted: true
              });
            }
          }
        }
      }
    } catch (_) {}

    return Array.from(mergedMap.values()).slice(0, this.maxPendingQueueSize);
  }

  /**
   * Synchronize in-memory pendingResultQueue to durable SQLite table and atomic disk outbox file
   */
  _syncDurableOutbox() {
    try {
      db.prepare('DELETE FROM edge_agent_durable_outbox WHERE agent_id = ?').run(this.agentId);
      const insertStmt = db.prepare(`
        INSERT INTO edge_agent_durable_outbox (task_id, agent_id, lease_epoch, result_json, attempts, queued_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `);
      for (const item of this.pendingResultQueue) {
        insertStmt.run(
          String(item.taskId),
          this.agentId,
          item.leaseEpoch !== null && item.leaseEpoch !== undefined ? Number(item.leaseEpoch) : null,
          JSON.stringify(item.result || {}),
          Number(item.attempts) || 1,
          Number(item.queuedAt) || Date.now()
        );
      }
    } catch (_) {}

    try {
      if (this.outboxFilePath) {
        const dir = path.dirname(this.outboxFilePath);
        if (!fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true });
        }
        if (this.pendingResultQueue.length === 0) {
          if (fs.existsSync(this.outboxFilePath)) {
            fs.unlinkSync(this.outboxFilePath);
          }
        } else {
          const tmpPath = `${this.outboxFilePath}.tmp`;
          fs.writeFileSync(tmpPath, JSON.stringify(this.pendingResultQueue, null, 2), 'utf8');
          fs.renameSync(tmpPath, this.outboxFilePath);
        }
      }
    } catch (_) {}
  }

  /**
   * Clear all durable outbox entries for this agent
   */
  clearDurableOutbox() {
    this.pendingResultQueue = [];
    this._syncDurableOutbox();
  }

  /**
   * Execute a remote probe task locally
   */
  async executeProbe(taskType, target, port = 80, params = {}) {
    const startedAt = Date.now();

    switch (taskType) {
      case 'probe_dns': {
        try {
          const records = await dns.resolve4(target);
          return {
            success: true,
            target,
            records,
            durationMs: Date.now() - startedAt,
            probeType: 'DNS'
          };
        } catch (err) {
          return {
            success: false,
            target,
            error: err.message,
            durationMs: Date.now() - startedAt,
            probeType: 'DNS'
          };
        }
      }

      case 'probe_tcp': {
        return new Promise((resolve) => {
          const socket = new net.Socket();
          const targetPort = Number(port) || 80;
          socket.setTimeout(params.timeoutMs || 2500);

          socket.on('connect', () => {
            const durationMs = Date.now() - startedAt;
            socket.destroy();
            resolve({
              success: true,
              target,
              port: targetPort,
              durationMs,
              probeType: 'TCP'
            });
          });

          socket.on('timeout', () => {
            socket.destroy();
            resolve({
              success: false,
              target,
              port: targetPort,
              error: 'Connection timed out',
              durationMs: Date.now() - startedAt,
              probeType: 'TCP'
            });
          });

          socket.on('error', (err) => {
            socket.destroy();
            resolve({
              success: false,
              target,
              port: targetPort,
              error: err.message,
              durationMs: Date.now() - startedAt,
              probeType: 'TCP'
            });
          });

          socket.connect(targetPort, target);
        });
      }

      case 'probe_http': {
        return new Promise((resolve) => {
          const urlStr = target.startsWith('http') ? target : `http://${target}:${port || 80}/`;
          try {
            const url = new URL(urlStr);
            const client = url.protocol === 'https:' ? https : http;
            const req = client.get(url, { timeout: params.timeoutMs || 3000 }, (res) => {
              resolve({
                success: res.statusCode < 400,
                target,
                statusCode: res.statusCode,
                headers: { 'content-type': res.headers['content-type'] },
                durationMs: Date.now() - startedAt,
                probeType: 'HTTP'
              });
            });

            req.on('timeout', () => {
              req.destroy();
              resolve({
                success: false,
                target,
                error: 'HTTP request timed out',
                durationMs: Date.now() - startedAt,
                probeType: 'HTTP'
              });
            });

            req.on('error', (err) => {
              resolve({
                success: false,
                target,
                error: err.message,
                durationMs: Date.now() - startedAt,
                probeType: 'HTTP'
              });
            });
          } catch (err) {
            resolve({
              success: false,
              target,
              error: err.message,
              durationMs: Date.now() - startedAt,
              probeType: 'HTTP'
            });
          }
        });
      }

      case 'probe_ping': {
        const count = params.count || 2;
        const timeoutMs = params.timeoutMs || 2000;
        try {
          const pingRes = await realPing(target, count, timeoutMs);
          return {
            success: pingRes.success,
            target,
            port: Number(port) || null,
            probeType: 'PING',
            protocol: 'ICMP',
            fidelity: 'REAL_OS_ICMP_ECHO',
            packetsSent: pingRes.packetsSent,
            packetsReceived: pingRes.packetsReceived,
            packetLossPct: pingRes.packetLossPct,
            rttMs: pingRes.avgRttMs,
            minRttMs: pingRes.minRttMs,
            maxRttMs: pingRes.maxRttMs,
            jitterMs: pingRes.jitterMs,
            status: pingRes.status,
            error: pingRes.error || null,
            durationMs: Date.now() - startedAt
          };
        } catch (err) {
          return {
            success: false,
            target,
            port: Number(port) || null,
            probeType: 'PING',
            protocol: 'ICMP',
            fidelity: 'REAL_OS_ICMP_ECHO',
            packetsSent: count,
            packetsReceived: 0,
            packetLossPct: 100,
            rttMs: null,
            status: 'UNREACHABLE',
            error: err.message,
            durationMs: Date.now() - startedAt
          };
        }
      }

      default:
        return {
          success: false,
          error: `Unsupported probe task type: ${taskType}`,
          probeType: taskType
        };
    }
  }

  /**
   * Send heartbeat to central EJII server and process assigned tasks
   */
  async sendHeartbeat(metrics = {}) {
    const payload = JSON.stringify({
      agentId: this.agentId,
      secretKey: this.secretKey,
      metrics: {
        uptimeSec: process.uptime(),
        memoryRssMb: Math.round(process.memoryUsage().rss / (1024 * 1024)),
        durableOutboxDepth: this.pendingResultQueue.length,
        ...metrics
      }
    });

    try {
      const url = new URL(`${this.serverUrl}/api/enterprise/agents/heartbeat`);
      const client = url.protocol === 'https:' ? https : http;

      const response = await new Promise((resolve, reject) => {
        const req = client.request(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload)
          },
          timeout: 5000
        }, (res) => {
          let data = '';
          res.on('data', chunk => { data += chunk; });
          res.on('end', () => {
            try {
              resolve({ statusCode: res.statusCode, body: JSON.parse(data) });
            } catch (_) {
              resolve({ statusCode: res.statusCode, body: data });
            }
          });
        });

        req.on('timeout', () => { req.destroy(); reject(new Error('Heartbeat request timeout')); });
        req.on('error', reject);
        req.write(payload);
        req.end();
      });

      if (response.statusCode >= 200 && response.statusCode < 300 && response.body?.assignedTasks) {
        // Execute assigned probe tasks sequentially and propagate leaseEpoch end-to-end
        for (const task of response.body.assignedTasks) {
          const taskLeaseEpoch = task.leaseEpoch !== undefined && task.leaseEpoch !== null
            ? Number(task.leaseEpoch)
            : 1;
          try {
            const probeResult = await this.executeProbe(task.taskType, task.target, task.port, task.parameters);
            await this.submitTaskResult(task.taskId, probeResult, taskLeaseEpoch);
          } catch (taskErr) {
            await this.submitTaskResult(task.taskId, { success: false, error: taskErr.message }, taskLeaseEpoch);
          }
        }
      }

      // Flush any offline buffered results once heartbeat confirms connection
      await this.flushPendingResults();

      return { success: response.statusCode === 200, response: response.body };
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  /**
   * Flush pending task execution results from durable offline outbox with leaseEpoch preservation.
   * Drops superseded tasks if central server responds with STALE_LEASE_EPOCH_IGNORED (HTTP 409 or body status)
   * or terminal non-existent tasks (HTTP 400/404 Task not found), while retaining transient 5xx/network failures.
   */
  async flushPendingResults() {
    if (this.pendingResultQueue.length === 0) {
      this.pendingResultQueue = this._loadDurableOutbox();
    }
    if (this.pendingResultQueue.length === 0) {
      return { flushed: 0, droppedStale: 0, droppedTerminal: 0, remaining: 0 };
    }
    const queueSnapshot = [...this.pendingResultQueue];
    this.pendingResultQueue = [];
    let flushed = 0;
    let droppedStale = 0;
    let droppedTerminal = 0;

    for (const item of queueSnapshot) {
      try {
        const res = await this._postTaskResult(item.taskId, item.result, item.leaseEpoch);
        const bodyStatus = res && res.body && typeof res.body === 'object' ? res.body.status : null;
        const bodyError = res && res.body && typeof res.body === 'object' ? String(res.body.error || '') : '';
        if (res.statusCode >= 200 && res.statusCode < 300) {
          flushed++;
        } else if (
          res.statusCode === 409 ||
          res.status === 'STALE_LEASE_EPOCH_IGNORED' ||
          bodyStatus === 'STALE_LEASE_EPOCH_IGNORED'
        ) {
          // Superseded by a newer lease epoch on the server; drop from durable offline queue
          droppedStale++;
        } else if (
          (res.statusCode === 400 || res.statusCode === 404) &&
          /Task not found|agent mismatch/i.test(bodyError)
        ) {
          // Terminal non-existent task ID; remove from durable outbox
          droppedTerminal++;
        } else if (item.attempts < 5) {
          item.attempts = (item.attempts || 1) + 1;
          this.pendingResultQueue.push(item);
        }
      } catch (_) {
        if (item.attempts < 5) {
          item.attempts = (item.attempts || 1) + 1;
          this.pendingResultQueue.push(item);
        }
      }
    }

    this._syncDurableOutbox();
    return { flushed, droppedStale, droppedTerminal, remaining: this.pendingResultQueue.length };
  }

  /**
   * Raw POST helper for task results including leaseEpoch
   */
  async _postTaskResult(taskId, result, leaseEpoch = null) {
    const resolvedEpoch = leaseEpoch !== null && leaseEpoch !== undefined
      ? Number(leaseEpoch)
      : (result && result.leaseEpoch !== undefined ? Number(result.leaseEpoch) : null);
    const enrichedResult = (result && typeof result === 'object' && resolvedEpoch !== null)
      ? { ...result, leaseEpoch: resolvedEpoch }
      : result;

    const payload = JSON.stringify({
      taskId,
      agentId: this.agentId,
      secretKey: this.secretKey,
      leaseEpoch: resolvedEpoch,
      result: enrichedResult
    });

    const url = new URL(`${this.serverUrl}/api/enterprise/agents/task-result`);
    const client = url.protocol === 'https:' ? https : http;

    return await new Promise((resolve, reject) => {
      const req = client.request(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload)
        },
        timeout: 5000
      }, (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => {
          try {
            resolve({ statusCode: res.statusCode, body: JSON.parse(data) });
          } catch (_) {
            resolve({ statusCode: res.statusCode, body: data });
          }
        });
      });

      req.on('timeout', () => { req.destroy(); reject(new Error('Submit task result timeout')); });
      req.on('error', reject);
      req.write(payload);
      req.end();
    });
  }

  /**
   * Submit task execution result back to central server (with durable SQLite/disk offline persistence & leaseEpoch fencing)
   */
  async submitTaskResult(taskId, result, leaseEpoch = null) {
    const resolvedEpoch = leaseEpoch !== null && leaseEpoch !== undefined
      ? Number(leaseEpoch)
      : (result && result.leaseEpoch !== undefined ? Number(result.leaseEpoch) : null);
    try {
      const response = await this._postTaskResult(taskId, result, resolvedEpoch);
      if (response.statusCode >= 200 && response.statusCode < 300) {
        // Ensure any previously queued copy of this taskId is removed from durable outbox
        const beforeLen = this.pendingResultQueue.length;
        this.pendingResultQueue = this.pendingResultQueue.filter((item) => item.taskId !== taskId);
        if (this.pendingResultQueue.length !== beforeLen) {
          this._syncDurableOutbox();
        }
        return { success: true, leaseEpoch: resolvedEpoch, response: response.body };
      }
      if (
        response.statusCode === 409 ||
        response.status === 'STALE_LEASE_EPOCH_IGNORED' ||
        (response.body && typeof response.body === 'object' && response.body.status === 'STALE_LEASE_EPOCH_IGNORED')
      ) {
        this.pendingResultQueue = this.pendingResultQueue.filter((item) => item.taskId !== taskId);
        this._syncDurableOutbox();
        return {
          success: false,
          staleLeaseDropped: true,
          leaseEpoch: resolvedEpoch,
          statusCode: response.statusCode,
          response: response.body
        };
      }
      // Buffered for retry if HTTP status indicated transient error
      this._enqueueDurableItem(taskId, result, resolvedEpoch);
      return {
        success: false,
        queuedForRetry: true,
        durablePersisted: true,
        leaseEpoch: resolvedEpoch,
        statusCode: response.statusCode
      };
    } catch (err) {
      // Durable offline buffering on network failure / connection refused
      this._enqueueDurableItem(taskId, result, resolvedEpoch);
      return {
        success: false,
        queuedForRetry: true,
        durablePersisted: true,
        leaseEpoch: resolvedEpoch,
        error: err.message
      };
    }
  }

  _enqueueDurableItem(taskId, result, leaseEpoch) {
    const existingIdx = this.pendingResultQueue.findIndex((i) => i.taskId === taskId);
    const entry = {
      taskId,
      result,
      leaseEpoch,
      attempts: existingIdx >= 0 ? (this.pendingResultQueue[existingIdx].attempts || 1) + 1 : 1,
      queuedAt: existingIdx >= 0 ? this.pendingResultQueue[existingIdx].queuedAt : Date.now(),
      durablePersisted: true
    };
    if (existingIdx >= 0) {
      this.pendingResultQueue[existingIdx] = entry;
    } else if (this.pendingResultQueue.length < this.maxPendingQueueSize) {
      this.pendingResultQueue.push(entry);
    }
    this._syncDurableOutbox();
  }

  /**
   * Start daemon heartbeat loop
   */
  start({ heartbeatIntervalMs = 15000 } = {}) {
    if (this.isRunning) return;
    this.isRunning = true;
    this._heartbeatTimer = setInterval(() => {
      if (!this.isRunning) return;
      this.sendHeartbeat().catch(() => {});
    }, heartbeatIntervalMs);
  }

  /**
   * Stop daemon heartbeat loop
   */
  stop() {
    this.isRunning = false;
    if (this._heartbeatTimer) {
      clearInterval(this._heartbeatTimer);
      this._heartbeatTimer = null;
    }
  }
}

module.exports = {
  EdgeAgentDaemon
};

