/**
 * EJII Lightweight Edge Agent Service (Control Plane)
 *
 * Implements:
 *   1. Secure Token / mTLS Handshake & Enrollment
 *   2. Heartbeat Health Ingestion & Status Tracking
 *   3. Remote Observation Task Dispatch:
 *      - DNS queries from remote VLANs
 *      - TCP port latency / synthetic handshakes
 *      - ICMP ping & path MTU discovery
 *      - HTTP/HTTPS endpoint availability
 *   4. Agent Task Results Aggregation & Telemetry Forwarding
 */

'use strict';

const crypto = require('crypto');
const { db } = require('../../db/database');
const { JWT_SECRET } = require('../../config');

/**
 * Derive a runtime-bound HMAC-SHA256 credential for built-in fleet agents using the platform JWT_SECRET.
 * Eliminates static predictable plaintext default tokens.
 * @param {string} agentId
 * @returns {string}
 */
function deriveAgentCredential(agentId) {
  if (!agentId || typeof agentId !== 'string') return '';
  return 'ejii_agt_hmac_' + crypto
    .createHmac('sha256', String(JWT_SECRET || 'ejii-runtime-secret'))
    .update(`ejii:edge-agent-credential:v2:${agentId.trim()}`)
    .digest('hex')
    .slice(0, 36);
}

class EdgeAgentService {
  constructor() {
    this._ensureTables();
    this._seedDefaultAgents();
  }

  _ensureTables() {
    try {
      db.exec(`
        CREATE TABLE IF NOT EXISTS enterprise_edge_agents (
          id TEXT PRIMARY KEY,
          agent_name TEXT NOT NULL,
          site_id TEXT NOT NULL,
          hostname TEXT NOT NULL,
          platform TEXT NOT NULL, -- 'linux', 'windows', 'docker'
          ip_address TEXT NOT NULL,
          observed_subnets TEXT NOT NULL, -- JSON array
          version TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'ONLINE', -- 'ONLINE', 'DEGRADED', 'OFFLINE'
          last_heartbeat TEXT NOT NULL,
          token_hash TEXT NOT NULL,
          capabilities TEXT NOT NULL, -- JSON array: ['dns', 'tcp', 'icmp', 'http']
          enrollment_state TEXT NOT NULL DEFAULT 'ACTIVE',
          is_sample_simulation INTEGER DEFAULT 0,
          created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS enterprise_agent_tasks (
          id TEXT PRIMARY KEY,
          agent_id TEXT NOT NULL,
          task_type TEXT NOT NULL, -- 'probe_dns', 'probe_tcp', 'probe_ping', 'probe_http'
          target TEXT NOT NULL,
          port INTEGER,
          parameters_json TEXT,
          status TEXT NOT NULL DEFAULT 'PENDING', -- 'PENDING', 'RUNNING', 'COMPLETED', 'FAILED'
          retry_count INTEGER DEFAULT 0,
          dispatched_at TEXT,
          lease_epoch INTEGER DEFAULT 0,
          result_json TEXT,
          created_at TEXT NOT NULL,
          completed_at TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_agent_tasks_agent ON enterprise_agent_tasks(agent_id, status);

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

      // Migrations for existing database tables
      try {
        db.exec("ALTER TABLE enterprise_edge_agents ADD COLUMN is_sample_simulation INTEGER DEFAULT 0;");
      } catch (_) {}
      try {
        db.exec("ALTER TABLE enterprise_agent_tasks ADD COLUMN retry_count INTEGER DEFAULT 0;");
      } catch (_) {}
      try {
        db.exec("ALTER TABLE enterprise_agent_tasks ADD COLUMN dispatched_at TEXT;");
      } catch (_) {}
      try {
        db.exec("ALTER TABLE enterprise_agent_tasks ADD COLUMN lease_epoch INTEGER DEFAULT 0;");
      } catch (_) {}
    } catch (_) {}
  }

  _seedDefaultAgents() {
    try {
      const defaultAgents = [
        {
          id: 'agent-lon-01',
          name: 'London HQ Core Edge Collector',
          siteId: 'site-hq-lon',
          hostname: 'lon-edge-probe-01.corp',
          platform: 'linux',
          ipAddress: '10.10.10.15',
          observedSubnets: ['10.10.10.0/24', '10.10.20.0/24'],
          version: '2.5.0',
          status: 'ONLINE',
          capabilities: ['dns', 'tcp', 'icmp', 'http', 'ja4']
        },
        {
          id: 'agent-fra-01',
          name: 'Frankfurt DC Monitoring Probe',
          siteId: 'site-dc-fra',
          hostname: 'fra-dc-collector-01.internal',
          platform: 'docker',
          ipAddress: '10.20.50.25',
          observedSubnets: ['10.20.50.0/24', '10.20.60.0/24'],
          version: '2.5.0',
          status: 'ONLINE',
          capabilities: ['dns', 'tcp', 'icmp', 'http', 'ja4']
        },
        {
          id: 'agent-nyc-01',
          name: 'NYC Trading Floor Probe',
          siteId: 'site-br-nyc',
          hostname: 'nyc-trading-probe.ny.corp',
          platform: 'windows',
          ipAddress: '10.30.100.5',
          observedSubnets: ['10.30.100.0/24'],
          version: '2.5.0',
          status: 'ONLINE',
          capabilities: ['dns', 'tcp', 'icmp', 'http']
        }
      ];

      const existing = db.prepare('SELECT COUNT(*) as cnt FROM enterprise_edge_agents').get();
      if (!existing || existing.cnt === 0) {
        const insert = db.prepare(`
          INSERT INTO enterprise_edge_agents 
            (id, agent_name, site_id, hostname, platform, ip_address, observed_subnets, version, status, last_heartbeat, token_hash, capabilities, enrollment_state, is_sample_simulation, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 1, ?)
        `);

        for (const a of defaultAgents) {
          const secretToken = deriveAgentCredential(a.id);
          const tokenHash = crypto.createHmac('sha256', JWT_SECRET).update(secretToken).digest('hex');
          insert.run(
            a.id,
            a.name,
            a.siteId,
            a.hostname,
            a.platform,
            a.ipAddress,
            JSON.stringify(a.observedSubnets),
            a.version,
            a.status,
            new Date().toISOString(),
            tokenHash,
            JSON.stringify(a.capabilities),
            new Date().toISOString()
          );
        }
      } else {
        // Ensure seeded simulation agents use runtime HMAC-derived credentials rather than legacy static tokens
        const updateHash = db.prepare(`
          UPDATE enterprise_edge_agents
          SET token_hash = ?
          WHERE id = ? AND is_sample_simulation = 1
        `);
        for (const a of defaultAgents) {
          const secretToken = deriveAgentCredential(a.id);
          const tokenHash = crypto.createHmac('sha256', JWT_SECRET).update(secretToken).digest('hex');
          updateHash.run(tokenHash, a.id);
        }
      }
    } catch (_) {}
  }

  /**
   * Enroll a new Edge Agent with 256-bit cryptographic secret
   */
  enrollAgent({ name, siteId, hostname, platform = 'linux', ipAddress, observedSubnets = [], capabilities = ['dns', 'tcp', 'icmp', 'http'] }) {
    const agentId = 'agent-' + crypto.randomBytes(4).toString('hex');
    const secretKey = 'ejii_agt_' + crypto.randomBytes(24).toString('hex');
    const tokenHash = crypto.createHmac('sha256', JWT_SECRET).update(secretKey).digest('hex');
    const nowIso = new Date().toISOString();

    db.prepare(`
      INSERT INTO enterprise_edge_agents 
        (id, agent_name, site_id, hostname, platform, ip_address, observed_subnets, version, status, last_heartbeat, token_hash, capabilities, enrollment_state, is_sample_simulation, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, '2.5.0', 'ONLINE', ?, ?, ?, 'ACTIVE', 0, ?)
    `).run(
      agentId,
      name || `Edge-Agent-${agentId}`,
      siteId || 'site-hq-lon',
      hostname || `host-${agentId}`,
      platform,
      ipAddress || '127.0.0.1',
      JSON.stringify(observedSubnets),
      nowIso,
      tokenHash,
      JSON.stringify(capabilities),
      nowIso
    );

    return {
      success: true,
      agentId,
      secretKey,
      enrollmentToken: `${agentId}:${secretKey}`,
      siteId,
      status: 'ONLINE',
      isSampleSimulation: false,
      createdAt: nowIso
    };
  }

  /**
   * Rotate an enrolled Edge Agent's cryptographic secret key
   */
  rotateAgentCredential(agentId) {
    if (!agentId) return { success: false, error: 'Missing agentId' };
    try {
      const existing = db.prepare('SELECT id, enrollment_state FROM enterprise_edge_agents WHERE id = ?').get(agentId);
      if (!existing) return { success: false, error: `Agent '${agentId}' not found.` };
      if (existing.enrollment_state === 'REVOKED') {
        return { success: false, error: `Cannot rotate credentials for revoked agent '${agentId}'.` };
      }
      const newSecretKey = 'ejii_agt_' + crypto.randomBytes(24).toString('hex');
      const newTokenHash = crypto.createHmac('sha256', JWT_SECRET).update(newSecretKey).digest('hex');
      db.prepare('UPDATE enterprise_edge_agents SET token_hash = ? WHERE id = ?').run(newTokenHash, agentId);
      return {
        success: true,
        agentId,
        secretKey: newSecretKey,
        newSecretKey,
        enrollmentToken: `${agentId}:${newSecretKey}`,
        rotatedAt: new Date().toISOString()
      };
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  /**
   * Revoke an Edge Agent's enrollment and immediately block authentication
   */
  revokeAgent(agentId) {
    if (!agentId) return { success: false, error: 'Missing agentId' };
    try {
      const info = db.prepare(`
        UPDATE enterprise_edge_agents
        SET enrollment_state = 'REVOKED', status = 'OFFLINE'
        WHERE id = ?
      `).run(agentId);
      if (!info || info.changes === 0) {
        return { success: false, error: `Agent '${agentId}' not found.` };
      }
      return {
        success: true,
        agentId,
        enrollmentState: 'REVOKED',
        status: 'OFFLINE',
        revokedAt: new Date().toISOString()
      };
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  /**
   * Verify an incoming agent secret key with timing-safe comparison and enrollment state check
   */
  verifyAgentAuth(agentId, secretKey) {
    if (!agentId || !secretKey || typeof secretKey !== 'string') return false;
    // Reject deprecated static literal default tokens
    if (/^ejii_token_.*_secret$/.test(secretKey)) return false;
    try {
      const row = db.prepare('SELECT token_hash, status, enrollment_state FROM enterprise_edge_agents WHERE id = ?').get(agentId);
      if (!row || row.enrollment_state !== 'ACTIVE') return false;
      const computedHash = crypto.createHmac('sha256', JWT_SECRET).update(secretKey).digest('hex');
      return crypto.timingSafeEqual(Buffer.from(row.token_hash, 'hex'), Buffer.from(computedHash, 'hex'));
    } catch (_) {
      return false;
    }
  }

  /**
   * Reap stale dispatched tasks whose lease has expired
   * @param {number} leaseTimeoutSec - Max duration a task can stay in DISPATCHED state without completion (default 60s)
   */
  reapStaleDispatchedTasks(leaseTimeoutSec = 60) {
    const nowIso = new Date().toISOString();
    const thresholdDate = new Date(Date.now() - (leaseTimeoutSec * 1000)).toISOString();
    let retried = 0;
    let failed = 0;

    try {
      const staleTasks = db.prepare(`
        SELECT * FROM enterprise_agent_tasks 
        WHERE status = 'DISPATCHED' AND dispatched_at IS NOT NULL AND dispatched_at < ?
      `).all(thresholdDate);

      const updateRetry = db.prepare(`
        UPDATE enterprise_agent_tasks 
        SET status = 'PENDING', retry_count = COALESCE(retry_count, 0) + 1, dispatched_at = NULL 
        WHERE id = ?
      `);

      const updateFail = db.prepare(`
        UPDATE enterprise_agent_tasks 
        SET status = 'TIMEOUT_FAILED', completed_at = ?, result_json = ? 
        WHERE id = ?
      `);

      for (const t of staleTasks) {
        const retries = Number(t.retry_count) || 0;
        if (retries < 3) {
          updateRetry.run(t.id);
          retried++;
        } else {
          updateFail.run(nowIso, JSON.stringify({ success: false, error: 'TASK_LEASE_EXPIRED_AGENT_UNRESPONSIVE', maxRetriesExceeded: true }), t.id);
          failed++;
        }
      }

      return { reaped: staleTasks.length, retried, failed };
    } catch (err) {
      return { reaped: 0, retried: 0, failed: 0, error: err.message };
    }
  }

  /**
   * Ingest Heartbeat from Agent
   */
  processHeartbeat(agentId, metrics = {}) {
    const nowIso = new Date().toISOString();
    try {
      // Clean up any stale leased tasks
      this.reapStaleDispatchedTasks(60);

      db.prepare(`
        UPDATE enterprise_edge_agents 
        SET last_heartbeat = ?, status = 'ONLINE'
        WHERE id = ?
      `).run(nowIso, agentId);

      // Check for any pending tasks assigned to this agent
      const pendingTasks = db.prepare(`
        SELECT * FROM enterprise_agent_tasks 
        WHERE agent_id = ? AND status = 'PENDING'
        ORDER BY created_at ASC
        LIMIT 5
      `).all(agentId);

      // Immediately mark returned tasks as DISPATCHED with timestamp lease and increment lease_epoch
      if (pendingTasks.length > 0) {
        const updateTask = db.prepare(`
          UPDATE enterprise_agent_tasks
          SET status = 'DISPATCHED', dispatched_at = ?, lease_epoch = COALESCE(lease_epoch, 0) + 1
          WHERE id = ?
        `);
        for (const t of pendingTasks) {
          updateTask.run(nowIso, t.id);
          t.lease_epoch = (Number(t.lease_epoch) || 0) + 1;
        }
      }

      return {
        acknowledged: true,
        timestamp: nowIso,
        assignedTasks: pendingTasks.map(t => ({
          taskId: t.id,
          taskType: t.task_type,
          target: t.target,
          port: t.port,
          leaseEpoch: Number(t.lease_epoch) || 1,
          parameters: t.parameters_json ? JSON.parse(t.parameters_json) : {}
        }))
      };
    } catch (err) {
      return { acknowledged: false, error: err.message };
    }
  }

  /**
   * Dispatch a diagnostic probe task to an Edge Agent
   */
  dispatchProbeTask({ agentId, taskType, target, port = 80, parameters = {} }) {
    const taskId = 'task-' + crypto.randomBytes(6).toString('hex');
    const nowIso = new Date().toISOString();

    db.prepare(`
      INSERT INTO enterprise_agent_tasks 
        (id, agent_id, task_type, target, port, parameters_json, status, retry_count, lease_epoch, created_at)
      VALUES (?, ?, ?, ?, ?, ?, 'PENDING', 0, 0, ?)
    `).run(taskId, agentId, taskType, target, port, JSON.stringify(parameters), nowIso);

    return {
      success: true,
      taskId,
      agentId,
      taskType,
      target,
      status: 'PENDING',
      leaseEpoch: 0,
      createdAt: nowIso
    };
  }

  /**
   * Submit task execution result from an Edge Agent with idempotent lease_epoch enforcement
   */
  submitTaskResult(taskId, agentId, result = {}, leaseEpoch = null) {
    const nowIso = new Date().toISOString();
    try {
      const existing = db.prepare(`
        SELECT id, agent_id, status, lease_epoch FROM enterprise_agent_tasks
        WHERE id = ? AND agent_id = ?
      `).get(taskId, agentId);

      if (!existing) {
        return { success: false, error: 'Task not found or agent mismatch.' };
      }

      const currentEpoch = Number(existing.lease_epoch) || 0;
      const submittedEpoch = leaseEpoch !== null && leaseEpoch !== undefined && leaseEpoch !== ''
        ? Number(leaseEpoch)
        : (result && result.leaseEpoch !== undefined && result.leaseEpoch !== null ? Number(result.leaseEpoch) : null);

      // 1. Explicit stale epoch rejection when submittedEpoch < currentEpoch
      // 2. Missing epoch rejection when task has been re-leased (currentEpoch > 1) or already COMPLETED
      const isExplicitlyStale = submittedEpoch !== null && currentEpoch > 0 && submittedEpoch < currentEpoch;
      const isMissingEpochAfterReLease = submittedEpoch === null && (currentEpoch > 1 || existing.status === 'COMPLETED');

      if (isExplicitlyStale || isMissingEpochAfterReLease) {
        return {
          success: false,
          status: 'STALE_LEASE_EPOCH_IGNORED',
          taskId,
          submittedEpoch,
          currentEpoch,
          error: isExplicitlyStale
            ? `Stale task result from expired lease epoch ${submittedEpoch} ignored idempotently (active epoch: ${currentEpoch}).`
            : `Task result missing leaseEpoch rejected because task '${taskId}' was re-leased or completed at epoch ${currentEpoch}.`
        };
      }

      if (existing.status === 'COMPLETED' && submittedEpoch !== null && submittedEpoch === currentEpoch) {
        return {
          success: true,
          idempotentDuplicate: true,
          taskId,
          status: 'COMPLETED',
          leaseEpoch: currentEpoch,
          completedAt: nowIso
        };
      }

      const persistedResult = (result && typeof result === 'object')
        ? { ...result, leaseEpoch: submittedEpoch !== null ? submittedEpoch : currentEpoch }
        : { value: result, leaseEpoch: submittedEpoch !== null ? submittedEpoch : currentEpoch };

      const info = db.prepare(`
        UPDATE enterprise_agent_tasks 
        SET status = 'COMPLETED', result_json = ?, completed_at = ?
        WHERE id = ? AND agent_id = ?
      `).run(JSON.stringify(persistedResult), nowIso, taskId, agentId);

      if (!info || info.changes === 0) {
        return { success: false, error: 'Task not found or agent mismatch.' };
      }

      return {
        success: true,
        taskId,
        status: 'COMPLETED',
        leaseEpoch: currentEpoch,
        completedAt: nowIso
      };
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  /**
   * List all registered Edge Agents with live task queue and lease epoch metrics
   */
  getAllAgents(options = {}) {
    try {
      const rows = db.prepare('SELECT * FROM enterprise_edge_agents ORDER BY id ASC').all();
      const taskStatsRows = db.prepare(`
        SELECT agent_id,
               SUM(CASE WHEN status IN ('PENDING', 'DISPATCHED') THEN 1 ELSE 0 END) AS active_count,
               SUM(CASE WHEN status = 'COMPLETED' THEN 1 ELSE 0 END) AS completed_count,
               MAX(COALESCE(lease_epoch, 0)) AS max_lease_epoch
        FROM enterprise_agent_tasks
        GROUP BY agent_id
      `).all();
      const taskStatsByAgent = new Map(taskStatsRows.map((tr) => [tr.agent_id, tr]));

      const outboxRows = db.prepare(`
        SELECT agent_id, COUNT(*) AS outbox_count
        FROM edge_agent_durable_outbox
        GROUP BY agent_id
      `).all();
      const outboxByAgent = new Map(outboxRows.map((or) => [or.agent_id, Number(or.outbox_count) || 0]));

      const now = Date.now();
      let agents = rows.map((r) => {
        let computedStatus = r.status;
        if (r.enrollment_state === 'REVOKED') {
          computedStatus = 'OFFLINE';
        } else if (!r.is_sample_simulation && r.last_heartbeat) {
          const ageMs = now - Date.parse(r.last_heartbeat);
          if (ageMs > 180000) {
            computedStatus = 'OFFLINE';
          } else if (ageMs > 60000) {
            computedStatus = 'DEGRADED';
          }
        }
        const stats = taskStatsByAgent.get(r.id);
        const isSim = Boolean(r.is_sample_simulation);
        return {
          id: r.id,
          name: r.agent_name,
          siteId: r.site_id,
          hostname: r.hostname,
          platform: r.platform,
          ipAddress: r.ip_address,
          observedSubnets: JSON.parse(r.observed_subnets || '[]'),
          version: r.version,
          status: computedStatus,
          lastHeartbeat: r.last_heartbeat,
          capabilities: JSON.parse(r.capabilities || '[]'),
          enrollmentState: r.enrollment_state,
          isSampleSimulation: isSim,
          isSimulated: isSim,
          activeTaskCount: Number(stats?.active_count) || 0,
          completedTaskCount: Number(stats?.completed_count) || 0,
          latestLeaseEpoch: Number(stats?.max_lease_epoch) || 0,
          durableOutboxCount: outboxByAgent.get(r.id) || 0,
          createdAt: r.created_at
        };
      });

      if (options.includeSimulated === false) {
        agents = agents.filter(a => !a.isSampleSimulation);
      }

      return agents;
    } catch (_) {
      return [];
    }
  }

  getAgentsSummary() {
    const agents = this.getAllAgents({ includeSimulated: true });
    return {
      totalAgents: agents.length,
      onlineAgents: agents.filter(a => a.status === 'ONLINE').length,
      degradedAgents: agents.filter(a => a.status === 'DEGRADED').length,
      offlineAgents: agents.filter(a => a.status === 'OFFLINE').length,
      productionAgents: agents.filter(a => !a.isSampleSimulation).length,
      simulationAgents: agents.filter(a => a.isSampleSimulation).length
    };
  }

  getAgentById(agentId) {
    const agents = this.getAllAgents();
    return agents.find(a => a.id === agentId) || null;
  }
}

const edgeAgentService = new EdgeAgentService();

module.exports = {
  EdgeAgentService,
  edgeAgentService,
  deriveAgentCredential
};

const { EdgeAgentDaemon } = require('./edge-agent-daemon');
module.exports.EdgeAgentDaemon = EdgeAgentDaemon;

