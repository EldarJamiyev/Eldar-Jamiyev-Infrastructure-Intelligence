/**
 * EJI Configuration Drift Repository
 * Authoritative persistence for baseline intents, observed drift diffs, and reconciliation executions.
 */

const { db } = require('../database');
const crypto = require('crypto');

class DriftRepository {
  /**
   * Create or update a configuration baseline
   */
  static upsertBaseline({
    targetCiId,
    name,
    baselineType,
    expectedState
  }) {
    const jsonStr = typeof expectedState === 'string' ? expectedState : JSON.stringify(expectedState);
    const hash = crypto.createHash('sha256').update(jsonStr).digest('hex');
    const now = new Date().toISOString();

    const existing = db.prepare(`
      SELECT * FROM drift_baselines
      WHERE target_ci_id = ? AND baseline_type = ?
    `).get(targetCiId, baselineType);

    if (existing) {
      db.prepare(`
        UPDATE drift_baselines
        SET name = ?, expected_state_json = ?, hash_sha256 = ?, updated_at = ?
        WHERE id = ?
      `).run(name, jsonStr, hash, now, existing.id);
      return this.getBaselineById(existing.id);
    }

    const id = 'BASE-' + crypto.randomBytes(4).toString('hex').toUpperCase();
    db.prepare(`
      INSERT INTO drift_baselines (
        id, target_ci_id, name, baseline_type, expected_state_json, hash_sha256, is_active, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
    `).run(id, targetCiId, name, baselineType, jsonStr, hash, now, now);

    return this.getBaselineById(id);
  }

  /**
   * Get baseline by ID
   */
  static getBaselineById(id) {
    const b = db.prepare('SELECT * FROM drift_baselines WHERE id = ?').get(id);
    if (!b) return null;
    return {
      ...b,
      expectedState: JSON.parse(b.expected_state_json)
    };
  }

  /**
   * List all baselines
   */
  static listBaselines({ targetCiId = null, baselineType = null } = {}) {
    let query = 'SELECT * FROM drift_baselines WHERE 1=1';
    const params = [];

    if (targetCiId) {
      query += ' AND target_ci_id = ?';
      params.push(targetCiId);
    }
    if (baselineType) {
      query += ' AND baseline_type = ?';
      params.push(baselineType);
    }
    query += ' ORDER BY created_at DESC';

    const rows = db.prepare(query).all(...params);
    return rows.map(r => ({
      ...r,
      expectedState: JSON.parse(r.expected_state_json)
    }));
  }

  /**
   * Record a drift observation
   */
  static recordObservation({
    baselineId,
    targetCiId,
    observedState,
    diff,
    hasDrift,
    severity = 'P3_MEDIUM'
  }) {
    const id = 'OBS-' + crypto.randomBytes(5).toString('hex').toUpperCase();
    const now = new Date().toISOString();
    const obsJson = typeof observedState === 'string' ? observedState : JSON.stringify(observedState);
    const diffJson = typeof diff === 'string' ? diff : JSON.stringify(diff);

    db.prepare(`
      INSERT INTO drift_observations (
        id, baseline_id, target_ci_id, observed_state_json, diff_json, has_drift, severity, checked_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      baselineId,
      targetCiId,
      obsJson,
      diffJson,
      hasDrift ? 1 : 0,
      severity,
      now
    );

    return this.getObservationById(id);
  }

  /**
   * Get observation by ID
   */
  static getObservationById(id) {
    const row = db.prepare(`
      SELECT o.*, b.name as baseline_name, b.baseline_type
      FROM drift_observations o
      LEFT JOIN drift_baselines b ON o.baseline_id = b.id
      WHERE o.id = ?
    `).get(id);

    if (!row) return null;
    return {
      ...row,
      observedState: JSON.parse(row.observed_state_json),
      diff: JSON.parse(row.diff_json)
    };
  }

  /**
   * List recent drift observations
   */
  static listRecentObservations({ hasDriftOnly = false, limit = 50 } = {}) {
    let query = `
      SELECT o.*, b.name as baseline_name, b.baseline_type
      FROM drift_observations o
      LEFT JOIN drift_baselines b ON o.baseline_id = b.id
      WHERE 1=1
    `;
    const params = [];
    if (hasDriftOnly) {
      query += ' AND o.has_drift = 1';
    }
    query += ' ORDER BY o.checked_at DESC LIMIT ?';
    params.push(limit);

    const rows = db.prepare(query).all(...params);
    return rows.map(r => ({
      ...r,
      observedState: JSON.parse(r.observed_state_json),
      diff: JSON.parse(r.diff_json)
    }));
  }

  /**
   * Start a reconciliation run
   */
  static createReconciliationRun({ baselineId, remediationActionId = null, details = null }) {
    const id = 'RECON-' + crypto.randomBytes(4).toString('hex').toUpperCase();
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO drift_reconciliation_runs (
        id, baseline_id, status, remediation_action_id, started_at, details
      ) VALUES (?, ?, 'running', ?, ?, ?)
    `).run(id, baselineId, remediationActionId, now, details);

    return this.getReconciliationRunById(id);
  }

  /**
   * Get reconciliation run by ID
   */
  static getReconciliationRunById(id) {
    return db.prepare('SELECT * FROM drift_reconciliation_runs WHERE id = ?').get(id) || null;
  }

  /**
   * Complete a reconciliation run
   */
  static completeReconciliationRun(id, status = 'reconciled', details = null) {
    const now = new Date().toISOString();
    db.prepare(`
      UPDATE drift_reconciliation_runs
      SET status = ?, completed_at = ?, details = coalesce(?, details)
      WHERE id = ?
    `).run(status, now, details, id);

    return this.getReconciliationRunById(id);
  }

  /**
   * Get drift summary metrics
   */
  static getDriftMetrics() {
    const baselinesCount = db.prepare('SELECT COUNT(*) as count FROM drift_baselines WHERE is_active = 1').get().count;
    const driftedCount = db.prepare(`
      SELECT COUNT(DISTINCT baseline_id) as count
      FROM drift_observations
      WHERE has_drift = 1 AND checked_at >= datetime('now', '-24 hours')
    `).get().count;

    return {
      activeBaselinesCount: baselinesCount,
      driftedBaselinesCount24h: driftedCount,
      complianceRatePercent: baselinesCount > 0 ? Number((((baselinesCount - driftedCount) / baselinesCount) * 100).toFixed(1)) : 100.0
    };
  }
}

module.exports = DriftRepository;
