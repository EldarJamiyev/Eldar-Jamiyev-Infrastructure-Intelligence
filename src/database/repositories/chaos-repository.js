/**
 * EJI Chaos Engineering & Resilience Repository
 * Authoritative persistence for lab fault scenarios, execution safety, and detection verification.
 */

const { db } = require('../database');
const crypto = require('crypto');

class ChaosRepository {
  /**
   * List all chaos scenarios
   */
  static listScenarios({ labOnly = true } = {}) {
    let query = 'SELECT * FROM chaos_scenarios';
    const params = [];
    if (labOnly) {
      query += ' WHERE is_lab_only = 1';
    }
    query += ' ORDER BY created_at DESC';

    const rows = db.prepare(query).all(...params);
    return rows.map(r => ({
      ...r,
      parameters: JSON.parse(r.parameters_json),
      safetyGuardrails: JSON.parse(r.safety_guardrails_json)
    }));
  }

  /**
   * Get scenario by ID
   */
  static getScenarioById(id) {
    const row = db.prepare('SELECT * FROM chaos_scenarios WHERE id = ?').get(id);
    if (!row) return null;
    return {
      ...row,
      parameters: JSON.parse(row.parameters_json),
      safetyGuardrails: JSON.parse(row.safety_guardrails_json)
    };
  }

  /**
   * Create a new chaos scenario
   */
  static createScenario({
    name,
    description,
    targetType,
    targetResource,
    parameters,
    durationSeconds = 30,
    safetyGuardrails,
    isLabOnly = 1
  }) {
    const id = 'CHAOS-' + crypto.randomBytes(4).toString('hex').toUpperCase();
    const now = new Date().toISOString();
    const paramsJson = typeof parameters === 'string' ? parameters : JSON.stringify(parameters);
    const guardrailsJson = typeof safetyGuardrails === 'string' ? safetyGuardrails : JSON.stringify(safetyGuardrails);

    db.prepare(`
      INSERT INTO chaos_scenarios (
        id, name, description, target_type, target_resource, parameters_json,
        duration_seconds, safety_guardrails_json, is_lab_only, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      name,
      description,
      targetType,
      targetResource,
      paramsJson,
      Number(durationSeconds),
      guardrailsJson,
      isLabOnly ? 1 : 0,
      now
    );

    return this.getScenarioById(id);
  }

  /**
   * Schedule a chaos execution
   */
  static createExecution({ scenarioId, operatorUsername, logs = [] }) {
    const scenario = this.getScenarioById(scenarioId);
    if (!scenario) throw new Error(`Chaos scenario ${scenarioId} not found`);

    const id = 'CHX-' + crypto.randomBytes(5).toString('hex').toUpperCase();
    const now = new Date().toISOString();
    const logsJson = JSON.stringify(logs);

    db.prepare(`
      INSERT INTO chaos_executions (
        id, scenario_id, status, operator_username, logs_json, created_at
      ) VALUES (?, ?, 'scheduled', ?, ?, ?)
    `).run(id, scenarioId, operatorUsername, logsJson, now);

    return this.getExecutionById(id);
  }

  /**
   * Update execution state and telemetry verification metrics
   */
  static updateExecution(id, updates = {}) {
    const existing = this.getExecutionById(id);
    if (!existing) throw new Error(`Chaos execution ${id} not found`);

    const status = updates.status || existing.status;
    const injectedAt = updates.injectedAt !== undefined ? updates.injectedAt : existing.injected_at;
    const healedAt = updates.healedAt !== undefined ? updates.healedAt : existing.healed_at;
    const detectionLatencyMs = updates.detectionLatencyMs !== undefined ? updates.detectionLatencyMs : existing.detection_latency_ms;
    const rcaMatched = updates.rcaMatched !== undefined ? (updates.rcaMatched ? 1 : 0) : existing.rca_matched;
    
    let logsJson = existing.logs_json;
    if (updates.logs) {
      logsJson = JSON.stringify(updates.logs);
    } else if (updates.logMessage) {
      const currentLogs = existing.logs || [];
      currentLogs.push({ timestamp: new Date().toISOString(), message: updates.logMessage });
      logsJson = JSON.stringify(currentLogs);
    }

    db.prepare(`
      UPDATE chaos_executions
      SET status = ?, injected_at = ?, healed_at = ?, detection_latency_ms = ?,
          rca_matched = ?, logs_json = ?
      WHERE id = ?
    `).run(status, injectedAt, healedAt, detectionLatencyMs, rcaMatched, logsJson, id);

    return this.getExecutionById(id);
  }

  /**
   * Get execution by ID
   */
  static getExecutionById(id) {
    const row = db.prepare(`
      SELECT e.*, s.name as scenario_name, s.target_type, s.target_resource, s.duration_seconds
      FROM chaos_executions e
      LEFT JOIN chaos_scenarios s ON e.scenario_id = s.id
      WHERE e.id = ?
    `).get(id);

    if (!row) return null;
    return {
      ...row,
      logs: row.logs_json ? JSON.parse(row.logs_json) : []
    };
  }

  /**
   * List recent chaos executions
   */
  static listExecutions({ limit = 20 } = {}) {
    const rows = db.prepare(`
      SELECT e.*, s.name as scenario_name, s.target_type, s.target_resource, s.duration_seconds
      FROM chaos_executions e
      LEFT JOIN chaos_scenarios s ON e.scenario_id = s.id
      ORDER BY e.created_at DESC LIMIT ?
    `).all(limit);

    return rows.map(r => ({
      ...r,
      logs: r.logs_json ? JSON.parse(r.logs_json) : []
    }));
  }
}

module.exports = ChaosRepository;
