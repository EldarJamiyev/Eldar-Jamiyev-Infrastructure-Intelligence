/**
 * EJI Monitoring & Alerting Repository
 * Authoritative persistence for alert rules, firing alerts, and notification dispatches.
 */

const { db } = require('../database');
const crypto = require('crypto');

class MonitoringRepository {
  /**
   * List all alert rules
   */
  static listAlertRules({ enabledOnly = false } = {}) {
    let query = 'SELECT * FROM monitoring_alert_rules';
    const params = [];
    if (enabledOnly) {
      query += ' WHERE enabled = 1';
    }
    query += ' ORDER BY severity ASC, name ASC';
    return db.prepare(query).all(...params);
  }

  /**
   * Get alert rule by ID
   */
  static getAlertRuleById(id) {
    return db.prepare('SELECT * FROM monitoring_alert_rules WHERE id = ?').get(id) || null;
  }

  /**
   * Create a new alert rule
   */
  static createAlertRule({
    name,
    metricName,
    targetCiType = null,
    conditionOperator = '>=',
    thresholdValue,
    durationSeconds = 60,
    severity = 'P2_HIGH',
    enabled = 1,
    description = null
  }) {
    const id = 'RULE-' + crypto.randomBytes(4).toString('hex').toUpperCase();
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO monitoring_alert_rules (
        id, name, metric_name, target_ci_type, condition_operator,
        threshold_value, duration_seconds, severity, enabled, description, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      name,
      metricName,
      targetCiType,
      conditionOperator,
      Number(thresholdValue),
      Number(durationSeconds),
      severity,
      enabled ? 1 : 0,
      description,
      now
    );

    return this.getAlertRuleById(id);
  }

  /**
   * Update an alert rule
   */
  static updateAlertRule(id, updates = {}) {
    const existing = this.getAlertRuleById(id);
    if (!existing) throw new Error(`Alert rule ${id} not found`);

    const name = updates.name !== undefined ? updates.name : existing.name;
    const metricName = updates.metricName !== undefined ? updates.metricName : existing.metric_name;
    const targetCiType = updates.targetCiType !== undefined ? updates.targetCiType : existing.target_ci_type;
    const conditionOperator = updates.conditionOperator !== undefined ? updates.conditionOperator : existing.condition_operator;
    const thresholdValue = updates.thresholdValue !== undefined ? Number(updates.thresholdValue) : existing.threshold_value;
    const durationSeconds = updates.durationSeconds !== undefined ? Number(updates.durationSeconds) : existing.duration_seconds;
    const severity = updates.severity !== undefined ? updates.severity : existing.severity;
    const enabled = updates.enabled !== undefined ? (updates.enabled ? 1 : 0) : existing.enabled;
    const description = updates.description !== undefined ? updates.description : existing.description;

    db.prepare(`
      UPDATE monitoring_alert_rules
      SET name = ?, metric_name = ?, target_ci_type = ?, condition_operator = ?,
          threshold_value = ?, duration_seconds = ?, severity = ?, enabled = ?, description = ?
      WHERE id = ?
    `).run(
      name, metricName, targetCiType, conditionOperator,
      thresholdValue, durationSeconds, severity, enabled, description, id
    );

    return this.getAlertRuleById(id);
  }

  /**
   * Record a new firing alert or update existing active alert for same CI & rule
   */
  static recordAlert({
    ruleId,
    ciId,
    metricName,
    observedValue,
    thresholdValue,
    severity,
    incidentId = null
  }) {
    // Check if there is already an active firing alert for this rule and CI
    const existing = db.prepare(`
      SELECT * FROM monitoring_alerts
      WHERE rule_id = ? AND ci_id = ? AND status = 'firing'
      LIMIT 1
    `).get(ruleId, ciId);

    if (existing) {
      // Update observed value
      db.prepare(`
        UPDATE monitoring_alerts
        SET observed_value = ?
        WHERE id = ?
      `).run(Number(observedValue), existing.id);
      return this.getAlertById(existing.id);
    }

    const id = 'ALT-' + crypto.randomBytes(5).toString('hex').toUpperCase();
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO monitoring_alerts (
        id, rule_id, ci_id, metric_name, observed_value, threshold_value,
        severity, status, incident_id, fired_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'firing', ?, ?)
    `).run(
      id,
      ruleId,
      ciId,
      metricName,
      Number(observedValue),
      Number(thresholdValue),
      severity,
      incidentId,
      now
    );

    return this.getAlertById(id);
  }

  /**
   * Get alert by ID
   */
  static getAlertById(id) {
    return db.prepare(`
      SELECT a.*, r.name as rule_name, r.condition_operator
      FROM monitoring_alerts a
      LEFT JOIN monitoring_alert_rules r ON a.rule_id = r.id
      WHERE a.id = ?
    `).get(id) || null;
  }

  /**
   * List active alerts (firing or acknowledged)
   */
  static listActiveAlerts({ severity = null, limit = 100 } = {}) {
    let query = `
      SELECT a.*, r.name as rule_name, r.condition_operator
      FROM monitoring_alerts a
      LEFT JOIN monitoring_alert_rules r ON a.rule_id = r.id
      WHERE a.status IN ('firing', 'acknowledged')
    `;
    const params = [];
    if (severity) {
      query += ' AND a.severity = ?';
      params.push(severity);
    }
    query += " ORDER BY CASE a.severity WHEN 'P1_CRITICAL' THEN 1 WHEN 'P2_HIGH' THEN 2 WHEN 'P3_MEDIUM' THEN 3 ELSE 4 END, a.fired_at DESC LIMIT ?";
    params.push(limit);

    return db.prepare(query).all(...params);
  }

  /**
   * Acknowledge an alert
   */
  static acknowledgeAlert(id) {
    const alert = this.getAlertById(id);
    if (!alert) throw new Error(`Alert ${id} not found`);

    const now = new Date().toISOString();
    db.prepare(`
      UPDATE monitoring_alerts
      SET status = 'acknowledged', acknowledged_at = ?
      WHERE id = ?
    `).run(now, id);

    return this.getAlertById(id);
  }

  /**
   * Resolve an alert
   */
  static resolveAlert(id) {
    const alert = this.getAlertById(id);
    if (!alert) throw new Error(`Alert ${id} not found`);

    const now = new Date().toISOString();
    db.prepare(`
      UPDATE monitoring_alerts
      SET status = 'resolved', resolved_at = ?
      WHERE id = ?
    `).run(now, id);

    return this.getAlertById(id);
  }

  /**
   * Suppress an alert (e.g. during maintenance or flapping)
   */
  static suppressAlert(id, reason = 'Maintenance window active') {
    const alert = this.getAlertById(id);
    if (!alert) throw new Error(`Alert ${id} not found`);

    db.prepare(`
      UPDATE monitoring_alerts
      SET status = 'suppressed', suppressed_reason = ?
      WHERE id = ?
    `).run(reason, id);

    return this.getAlertById(id);
  }

  /**
   * Record a notification dispatch
   */
  static recordNotification({ alertId, channel, destination, payloadJson, status = 'sent' }) {
    const id = 'NOTIF-' + crypto.randomBytes(4).toString('hex').toUpperCase();
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO monitoring_notifications (
        id, alert_id, channel, destination, payload_json, status, sent_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, alertId, channel, destination, typeof payloadJson === 'string' ? payloadJson : JSON.stringify(payloadJson), status, now);

    return { id, alertId, channel, destination, status, sent_at: now };
  }

  /**
   * Get alert statistics
   */
  static getAlertStatistics() {
    const counts = db.prepare(`
      SELECT
        COUNT(*) as total_alerts,
        SUM(CASE WHEN status = 'firing' THEN 1 ELSE 0 END) as firing_count,
        SUM(CASE WHEN status = 'acknowledged' THEN 1 ELSE 0 END) as ack_count,
        SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved_count,
        SUM(CASE WHEN severity = 'P1_CRITICAL' AND status IN ('firing', 'acknowledged') THEN 1 ELSE 0 END) as active_critical_count
      FROM monitoring_alerts
    `).get();

    return {
      totalAlerts: counts.total_alerts || 0,
      firingCount: counts.firing_count || 0,
      acknowledgedCount: counts.ack_count || 0,
      resolvedCount: counts.resolved_count || 0,
      activeCriticalCount: counts.active_critical_count || 0
    };
  }
}

module.exports = MonitoringRepository;
