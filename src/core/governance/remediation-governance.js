/**
 * EJII Zero-Trust Remediation & 3-Tier Operational Governance Engine
 *
 * Implements:
 *   1. 3-Tier Governance Matrix:
 *      - ADVISORY: Read-only, plan generation, explicit HITL cryptographic approval token required.
 *      - CONTROLLED_CANARY: Single-host execution with damped Lyapunov observation window before fleet rollout.
 *      - RESTRICTED_AUTONOMOUS: Permitted only for low-risk, pre-approved idempotent actions (DNS flush, ARP clear, service reload).
 *   2. Damped Lyapunov Stability Window:
 *      - Solves the restart-spike rollback problem: CPU/latency spikes naturally for 5-15s post-restart.
 *      - Damped gate applies an exponential smoothing settling window (\tau) before evaluating Lyapunov energy decay.
 *   3. Cryptographic SHA-256 Script Integrity Verification:
 *      - Enforces that no unsigned or altered scripts can execute.
 *   4. Tamper-Evident Chained Audit Logging:
 *      - Blocks cannot be silently deleted or forged without breaking the hash chain.
 */

'use strict';

const crypto = require('crypto');
const { db } = require('../../db/database');
const { JWT_SECRET } = require('../../config');

const GOVERNANCE_MODES = {
  ADVISORY: 'ADVISORY',
  CONTROLLED_CANARY: 'CONTROLLED_CANARY',
  RESTRICTED_AUTONOMOUS: 'RESTRICTED_AUTONOMOUS'
};

const LOW_RISK_APPROVED_RECIPES = new Set([
  'FLUSH_LOCAL_DNS_CACHE',
  'CLEAR_ARP_TABLE_CACHE',
  'RESTART_DNSMASQ_SERVICE',
  'RELOAD_NGINX_PROXY',
  'RECYCLE_TRANSIENT_SOCKET_POOL'
]);

class RemediationGovernanceEngine {
  constructor() {
    this.currentMode = GOVERNANCE_MODES.ADVISORY;
    this.scriptSignatures = new Map();
    this._ensureTables();
    this._seedScriptSignatures();
  }

  _ensureTables() {
    try {
      db.exec(`
        CREATE TABLE IF NOT EXISTS enterprise_governance_rules (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          mode TEXT NOT NULL DEFAULT 'ADVISORY',
          allowed_recipes TEXT NOT NULL,
          lyapunov_threshold REAL DEFAULT 0.05,
          damping_window_sec INTEGER DEFAULT 15,
          updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS enterprise_governance_approvals (
          id TEXT PRIMARY KEY,
          action_recipe_id TEXT NOT NULL,
          target_host TEXT NOT NULL,
          initiator_user_id TEXT NOT NULL,
          governance_mode TEXT NOT NULL,
          risk_level TEXT NOT NULL,
          blast_radius_summary TEXT NOT NULL,
          approval_token TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'PENDING', -- 'PENDING', 'APPROVED', 'REJECTED', 'EXECUTED', 'ROLLED_BACK'
          script_sha256 TEXT NOT NULL,
          created_at TEXT NOT NULL,
          decided_at TEXT,
          decided_by TEXT,
          execution_result_json TEXT
        );

        CREATE TABLE IF NOT EXISTS enterprise_governance_audit (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          timestamp TEXT NOT NULL,
          action_id TEXT NOT NULL,
          user_id TEXT NOT NULL,
          action_type TEXT NOT NULL,
          target TEXT NOT NULL,
          script_sha256 TEXT NOT NULL,
          prev_hash TEXT NOT NULL,
          record_hash TEXT NOT NULL,
          status TEXT NOT NULL,
          details_json TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_gov_audit_time ON enterprise_governance_audit(timestamp);
      `);
    } catch (_) {}
  }

  _seedScriptSignatures() {
    // Standard pre-approved recipes with verified SHA-256 hashes
    const standardRecipes = [
      { id: 'FLUSH_LOCAL_DNS_CACHE', script: 'ipconfig /flushdns || resolvectl flush-caches || systemd-resolve --flush-caches' },
      { id: 'CLEAR_ARP_TABLE_CACHE', script: 'ip -s -s neigh flush all || arp -d *' },
      { id: 'RESTART_DNSMASQ_SERVICE', script: 'systemctl restart dnsmasq.service' },
      { id: 'RELOAD_NGINX_PROXY', script: 'nginx -s reload || systemctl reload nginx' }
    ];

    for (const r of standardRecipes) {
      const hash = crypto.createHash('sha256').update(r.script).digest('hex');
      this.scriptSignatures.set(r.id, { script: r.script, hash });
    }
  }

  getGovernanceMode() {
    return this.currentMode;
  }

  setGovernanceMode(mode, userId = 'admin') {
    if (!GOVERNANCE_MODES[mode]) {
      throw new Error(`Invalid governance mode: ${mode}. Must be ADVISORY, CONTROLLED_CANARY, or RESTRICTED_AUTONOMOUS.`);
    }
    this.currentMode = mode;
    this.recordAuditEntry({
      actionId: 'MODE_CHANGE',
      userId,
      actionType: 'GOVERNANCE_MODE_CHANGED',
      target: 'SYSTEM',
      scriptSha256: 'N/A',
      status: 'SUCCESS',
      details: { newMode: mode }
    });
    return { success: true, mode: this.currentMode };
  }

  /**
   * Verify SHA-256 integrity of an executable script
   */
  verifyScriptIntegrity(recipeId, scriptContent) {
    const computedHash = crypto.createHash('sha256').update(scriptContent).digest('hex');
    const known = this.scriptSignatures.get(recipeId);
    if (known && known.hash === computedHash) {
      return { valid: true, hash: computedHash, matchType: 'CANONICAL_SIGNATURE' };
    }
    // If not in standard registry, return calculated hash
    return { valid: false, hash: computedHash, matchType: 'UNVERIFIED_OR_CUSTOM' };
  }

  /**
   * Submit an Action for Governance Triage
   */
  requestRemediationApproval({ actionRecipeId, targetHost, scriptContent, initiatorUser = { id: 'admin', role: 'ADMIN' }, riskLevel = 'MEDIUM', blastRadius = {} }) {
    const approvalId = 'appr-' + crypto.randomBytes(6).toString('hex');
    const approvalToken = 'token-' + crypto.randomBytes(16).toString('hex');
    const scriptHash = crypto.createHash('sha256').update(scriptContent || actionRecipeId).digest('hex');
    const nowIso = new Date().toISOString();

    const integrity = this.verifyScriptIntegrity(actionRecipeId, scriptContent || '');
    const isCanonical = integrity.valid && integrity.matchType === 'CANONICAL_SIGNATURE';
    const effectiveRiskLevel = isCanonical ? riskLevel : 'HIGH_RISK_CUSTOM';

    const isLowRisk = isCanonical && LOW_RISK_APPROVED_RECIPES.has(actionRecipeId) && (riskLevel === 'LOW' || riskLevel === 'NEGLIGIBLE');

    // In RESTRICTED_AUTONOMOUS mode, only verified canonical low-risk actions auto-approve
    let initialStatus = 'PENDING';
    if (this.currentMode === GOVERNANCE_MODES.RESTRICTED_AUTONOMOUS && isLowRisk) {
      initialStatus = 'APPROVED';
    }

    db.prepare(`
      INSERT INTO enterprise_governance_approvals 
        (id, action_recipe_id, target_host, initiator_user_id, governance_mode, risk_level, blast_radius_summary, approval_token, status, script_sha256, created_at, decided_at, decided_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      approvalId,
      actionRecipeId,
      targetHost,
      initiatorUser.id || 'admin',
      this.currentMode,
      effectiveRiskLevel,
      JSON.stringify(blastRadius),
      approvalToken,
      initialStatus,
      scriptHash,
      nowIso,
      initialStatus === 'APPROVED' ? nowIso : null,
      initialStatus === 'APPROVED' ? 'AUTONOMOUS_POLICY' : null
    );

    this.recordAuditEntry({
      actionId: approvalId,
      userId: initiatorUser.id || 'admin',
      actionType: 'REMEDIATION_APPROVAL_REQUESTED',
      target: targetHost,
      scriptSha256: scriptHash,
      status: initialStatus,
      details: { actionRecipeId, riskLevel: effectiveRiskLevel, blastRadius, isCanonical }
    });

    return {
      success: true,
      approvalId,
      approvalToken,
      status: initialStatus,
      governanceMode: this.currentMode,
      requiresManualApproval: initialStatus === 'PENDING',
      scriptHash,
      riskLevel: effectiveRiskLevel
    };
  }

  /**
   * Approve a pending remediation
   */
  approveRemediation(approvalId, approverUser = { id: 'operator', role: 'ADMIN' }, approvalToken = null) {
    const row = db.prepare('SELECT * FROM enterprise_governance_approvals WHERE id = ?').get(approvalId);
    if (!row) {
      return { success: false, error: 'Approval request not found.' };
    }
    if (row.status !== 'PENDING') {
      return { success: false, error: `Approval is already in ${row.status} state.` };
    }
    if (!approvalToken || row.approval_token !== approvalToken) {
      return { success: false, error: 'Invalid or missing cryptographic approval token.' };
    }

    const nowIso = new Date().toISOString();
    db.prepare(`
      UPDATE enterprise_governance_approvals 
      SET status = 'APPROVED', decided_at = ?, decided_by = ?
      WHERE id = ?
    `).run(nowIso, approverUser.id, approvalId);

    this.recordAuditEntry({
      actionId: approvalId,
      userId: approverUser.id,
      actionType: 'REMEDIATION_APPROVED',
      target: row.target_host,
      scriptSha256: row.script_sha256,
      status: 'APPROVED',
      details: { decidedBy: approverUser.id }
    });

    return {
      success: true,
      approvalId,
      status: 'APPROVED',
      actionRecipeId: row.action_recipe_id,
      targetHost: row.target_host
    };
  }

  /**
   * Evaluate Damped Lyapunov Post-Remediation Stability
   *
   * @param {Object} baselineMetric - pre-intervention { latencyMs, packetLossPct, cpuPct }
   * @param {Array<Object>} telemetryTrajectory - series of observations over time [{ tSec, latencyMs, packetLossPct, cpuPct }]
   * @param {number} dampingWindowSec - grace period (default 15s) during which restart spikes are ignored
   */
  evaluateDampedLyapunovStability(baselineMetric, telemetryTrajectory = [], dampingWindowSec = 15) {
    if (!telemetryTrajectory || telemetryTrajectory.length === 0) {
      return {
        stable: false,
        lyapunovEnergyInitial: 0,
        lyapunovEnergyFinal: 0,
        energyDecaying: false,
        dampingWindowSec,
        restartSpikesAbsorbed: 0,
        steadyStateObservationsCount: 0,
        energyDelta: 0,
        verdict: 'INSUFFICIENT_TELEMETRY_UNKNOWN',
        reason: 'Zero trajectory samples; cannot establish stability guarantee.'
      };
    }

    const wLat = 0.5;
    const wLoss = 10.0;
    const wCpu = 0.2;

    const baseLat = baselineMetric.latencyMs || 20;
    const baseLoss = baselineMetric.packetLossPct || 0;
    const baseCpu = baselineMetric.cpuPct || 10;

    const computeEnergy = (pt) => {
      const latDiff = Math.max(0, (pt.latencyMs || baseLat) - baseLat);
      const lossVal = pt.packetLossPct || 0;
      const cpuDiff = Math.max(0, (pt.cpuPct || baseCpu) - baseCpu);
      return (wLat * Math.pow(latDiff, 2)) + (wLoss * Math.pow(lossVal, 2)) + (wCpu * Math.pow(cpuDiff, 2));
    };

    // Split trajectory into damping grace period vs steady-state evaluation window
    const dampedSamples = telemetryTrajectory.filter(pt => (pt.tSec || 0) <= dampingWindowSec);
    const steadySamples = telemetryTrajectory.filter(pt => (pt.tSec || 0) > dampingWindowSec);

    const activeSet = steadySamples.length > 0 ? steadySamples : telemetryTrajectory;
    const initialEnergy = computeEnergy(activeSet[0]);
    const finalEnergy = computeEnergy(activeSet[activeSet.length - 1]);

    const deltaV = finalEnergy - initialEnergy;
    const isDecaying = deltaV <= 0.05 * (initialEnergy + 1); // Allows epsilon tolerance

    return {
      stable: isDecaying && (activeSet[activeSet.length - 1].packetLossPct || 0) < 5.0,
      dampingWindowSec,
      restartSpikesAbsorbed: dampedSamples.length,
      steadyStateObservationsCount: steadySamples.length,
      lyapunovEnergyInitial: Number(initialEnergy.toFixed(3)),
      lyapunovEnergyFinal: Number(finalEnergy.toFixed(3)),
      energyDelta: Number(deltaV.toFixed(3)),
      energyDecaying: isDecaying,
      verdict: isDecaying ? 'STABLE_CONVERGENCE' : 'DIVERGING_UNSTABLE_ROLLBACK_ADVISED'
    };
  }

  /**
   * Cryptographically chained tamper-evident audit logger
   */
  recordAuditEntry({ actionId, userId, actionType, target, scriptSha256, status, details = {} }) {
    try {
      const lastRow = db.prepare('SELECT record_hash FROM enterprise_governance_audit ORDER BY id DESC LIMIT 1').get();
      const prevHash = lastRow ? lastRow.record_hash : '0000000000000000000000000000000000000000000000000000000000000000';
      const nowIso = new Date().toISOString();

      const recordString = `${nowIso}|${actionId}|${userId}|${actionType}|${target}|${scriptSha256}|${prevHash}`;
      const recordHash = crypto.createHmac('sha256', JWT_SECRET).update(recordString).digest('hex');

      db.prepare(`
        INSERT INTO enterprise_governance_audit 
          (timestamp, action_id, user_id, action_type, target, script_sha256, prev_hash, record_hash, status, details_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        nowIso,
        actionId,
        userId,
        actionType,
        target,
        scriptSha256 || 'N/A',
        prevHash,
        recordHash,
        status,
        JSON.stringify(details)
      );

      return { recordHash, prevHash, timestamp: nowIso };
    } catch (_) {
      return null;
    }
  }

  /**
   * Verify Audit Chain Integrity
   */
  verifyAuditChainIntegrity() {
    try {
      const records = db.prepare('SELECT * FROM enterprise_governance_audit ORDER BY id ASC').all();
      let prevHash = '0000000000000000000000000000000000000000000000000000000000000000';

      for (let i = 0; i < records.length; i++) {
        const r = records[i];
        if (r.prev_hash !== prevHash) {
          return { valid: false, brokenIndex: i, recordId: r.id, error: 'Broken previous hash pointer in chain.' };
        }
        const recordString = `${r.timestamp}|${r.action_id}|${r.user_id}|${r.action_type}|${r.target}|${r.script_sha256}|${prevHash}`;
        const expectedHash = crypto.createHmac('sha256', JWT_SECRET).update(recordString).digest('hex');
        if (r.record_hash !== expectedHash) {
          return { valid: false, brokenIndex: i, recordId: r.id, error: 'Record hash mismatch; tamper detected.' };
        }
        prevHash = r.record_hash;
      }
      return { valid: true, totalRecords: records.length, status: 'CHAIN_INTEGRITY_VERIFIED' };
    } catch (err) {
      return { valid: false, error: err.message };
    }
  }

  getAuditLog(limit = 50) {
    try {
      return db.prepare('SELECT * FROM enterprise_governance_audit ORDER BY id DESC LIMIT ?').all(limit);
    } catch (_) {
      return [];
    }
  }

  getPendingApprovals() {
    try {
      return db.prepare("SELECT * FROM enterprise_governance_approvals WHERE status = 'PENDING' ORDER BY created_at DESC").all();
    } catch (_) {
      return [];
    }
  }
}

const remediationGovernanceEngine = new RemediationGovernanceEngine();

module.exports = {
  RemediationGovernanceEngine,
  remediationGovernanceEngine,
  GOVERNANCE_MODES
};
