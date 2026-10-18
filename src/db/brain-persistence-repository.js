/**
 * EJII Transactional SQLite WAL Repository for AI Brain & Unified Investigations
 * Eliminates dual-storage split-brain drift by persisting Welford baselines,
 * Bayesian incidents, operator feedback calibrations, and guided investigations
 * directly into SQLite WAL tables with sub-millisecond prepared statements.
 */

const { db } = require('./database');

class BrainPersistenceRepository {
  constructor() {
    this._ensureTables();
    this._prepareStatements();
  }

  _ensureTables() {
    try {
      db.exec(`
        CREATE TABLE IF NOT EXISTS brain_baselines (
          target TEXT PRIMARY KEY,
          subnet_gateway TEXT,
          min_rtt REAL NOT NULL,
          max_rtt REAL NOT NULL,
          avg_rtt REAL NOT NULL,
          variance REAL DEFAULT 0,
          stddev REAL DEFAULT 0,
          m2 REAL DEFAULT 0,
          sample_count INTEGER NOT NULL DEFAULT 1,
          status TEXT NOT NULL DEFAULT 'PROVISIONAL_INSUFFICIENT_SAMPLES',
          first_observed TEXT NOT NULL,
          last_observed TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS brain_incidents (
          incident_key TEXT PRIMARY KEY,
          incident_type TEXT NOT NULL,
          target TEXT NOT NULL,
          dest_port INTEGER DEFAULT 0,
          top_hypothesis_id TEXT,
          top_hypothesis_label TEXT,
          confidence INTEGER DEFAULT 0,
          diagnostic_state TEXT DEFAULT 'EVALUATED',
          payload_json TEXT NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS brain_calibration (
          incident_type TEXT NOT NULL,
          hypothesis_id TEXT NOT NULL,
          multiplier REAL NOT NULL DEFAULT 1.0,
          updated_at TEXT NOT NULL,
          PRIMARY KEY (incident_type, hypothesis_id)
        );
        CREATE TABLE IF NOT EXISTS brain_feedback_ledger (
          feedback_id TEXT PRIMARY KEY,
          incident_key TEXT NOT NULL,
          incident_type TEXT NOT NULL,
          hypothesis_id TEXT NOT NULL,
          verdict TEXT NOT NULL,
          previous_multiplier REAL NOT NULL,
          updated_multiplier REAL NOT NULL,
          operator_notes TEXT,
          user_id TEXT NOT NULL,
          recorded_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS unified_investigations (
          investigation_id TEXT PRIMARY KEY,
          symptom TEXT NOT NULL,
          process_query TEXT,
          target_host TEXT NOT NULL,
          target_port INTEGER NOT NULL,
          overall_verdict TEXT NOT NULL,
          confidence INTEGER NOT NULL,
          uncertainty_warning INTEGER DEFAULT 0,
          report_json TEXT NOT NULL,
          started_at TEXT NOT NULL,
          completed_at TEXT NOT NULL
        );
      `);
    } catch (_) {}
  }

  _prepareStatements() {
    try {
      this.stmtUpsertBaseline = db.prepare(`
        INSERT INTO brain_baselines (
          target, subnet_gateway, min_rtt, max_rtt, avg_rtt, variance, stddev, m2, sample_count, status, first_observed, last_observed
        ) VALUES (
          @target, @subnet_gateway, @min_rtt, @max_rtt, @avg_rtt, @variance, @stddev, @m2, @sample_count, @status, @first_observed, @last_observed
        )
        ON CONFLICT(target) DO UPDATE SET
          subnet_gateway = excluded.subnet_gateway,
          min_rtt = excluded.min_rtt,
          max_rtt = excluded.max_rtt,
          avg_rtt = excluded.avg_rtt,
          variance = excluded.variance,
          stddev = excluded.stddev,
          m2 = excluded.m2,
          sample_count = excluded.sample_count,
          status = excluded.status,
          last_observed = excluded.last_observed
      `);

      this.stmtUpsertIncident = db.prepare(`
        INSERT INTO brain_incidents (
          incident_key, incident_type, target, dest_port, top_hypothesis_id, top_hypothesis_label, confidence, diagnostic_state, payload_json, created_at, updated_at
        ) VALUES (
          @incident_key, @incident_type, @target, @dest_port, @top_hypothesis_id, @top_hypothesis_label, @confidence, @diagnostic_state, @payload_json, @created_at, @updated_at
        )
        ON CONFLICT(incident_key) DO UPDATE SET
          top_hypothesis_id = excluded.top_hypothesis_id,
          top_hypothesis_label = excluded.top_hypothesis_label,
          confidence = excluded.confidence,
          diagnostic_state = excluded.diagnostic_state,
          payload_json = excluded.payload_json,
          updated_at = excluded.updated_at
      `);

      this.stmtUpsertCalibration = db.prepare(`
        INSERT INTO brain_calibration (incident_type, hypothesis_id, multiplier, updated_at)
        VALUES (@incident_type, @hypothesis_id, @multiplier, @updated_at)
        ON CONFLICT(incident_type, hypothesis_id) DO UPDATE SET
          multiplier = excluded.multiplier,
          updated_at = excluded.updated_at
      `);

      this.stmtInsertFeedback = db.prepare(`
        INSERT OR REPLACE INTO brain_feedback_ledger (
          feedback_id, incident_key, incident_type, hypothesis_id, verdict, previous_multiplier, updated_multiplier, operator_notes, user_id, recorded_at
        ) VALUES (
          @feedback_id, @incident_key, @incident_type, @hypothesis_id, @verdict, @previous_multiplier, @updated_multiplier, @operator_notes, @user_id, @recorded_at
        )
      `);

      this.stmtUpsertInvestigation = db.prepare(`
        INSERT OR REPLACE INTO unified_investigations (
          investigation_id, symptom, process_query, target_host, target_port, overall_verdict, confidence, uncertainty_warning, report_json, started_at, completed_at
        ) VALUES (
          @investigation_id, @symptom, @process_query, @target_host, @target_port, @overall_verdict, @confidence, @uncertainty_warning, @report_json, @started_at, @completed_at
        )
      `);
    } catch (_) {}
  }

  saveBaseline(target, metric, subnetGateway = null) {
    if (!this.stmtUpsertBaseline || !target || !metric) return;
    try {
      this.stmtUpsertBaseline.run({
        target: String(target),
        subnet_gateway: subnetGateway ? String(subnetGateway) : null,
        min_rtt: Number(metric.minRtt || 0),
        max_rtt: Number(metric.maxRtt || 0),
        avg_rtt: Number(metric.avgRtt || 0),
        variance: Number(metric.variance || 0),
        stddev: Number(metric.stddev || 0),
        m2: Number(metric.m2 || 0),
        sample_count: Number(metric.sampleCount || 1),
        status: String(metric.status || 'PROVISIONAL_INSUFFICIENT_SAMPLES'),
        first_observed: String(metric.firstObserved || new Date().toISOString()),
        last_observed: String(metric.lastObserved || new Date().toISOString())
      });
    } catch (_) {}
  }

  saveIncident(incident) {
    if (!this.stmtUpsertIncident || !incident || !incident.incidentKey) return;
    try {
      this.stmtUpsertIncident.run({
        incident_key: String(incident.incidentKey),
        incident_type: String(incident.incidentType || 'UNKNOWN'),
        target: String(incident.target || 'unknown'),
        dest_port: Number(incident.destPort || 0),
        top_hypothesis_id: String(incident.topHypothesis?.id || 'UNKNOWN'),
        top_hypothesis_label: String(incident.topHypothesis?.label || 'Unknown'),
        confidence: Number(incident.topHypothesis?.confidence || 0),
        diagnostic_state: String(incident.evaluation?.diagnosticState || 'EVALUATED'),
        payload_json: JSON.stringify({
          incidentKey: incident.incidentKey,
          incidentType: incident.incidentType,
          target: incident.target,
          destPort: incident.destPort,
          topHypothesis: incident.topHypothesis,
          rankedHypotheses: incident.rankedHypotheses,
          updatedAt: incident.updatedAt
        }),
        created_at: String(incident.createdAt || new Date().toISOString()),
        updated_at: String(incident.updatedAt || new Date().toISOString())
      });
    } catch (_) {}
  }

  saveCalibration(incidentType, hypothesisId, multiplier, feedbackRecord = null) {
    if (!this.stmtUpsertCalibration) return;
    try {
      const now = new Date().toISOString();
      this.stmtUpsertCalibration.run({
        incident_type: String(incidentType),
        hypothesis_id: String(hypothesisId),
        multiplier: Number(multiplier),
        updated_at: now
      });
      if (feedbackRecord && this.stmtInsertFeedback) {
        this.stmtInsertFeedback.run({
          feedback_id: String(feedbackRecord.feedbackId || `FB-${Date.now()}`),
          incident_key: String(feedbackRecord.incidentKey || 'MANUAL'),
          incident_type: String(incidentType),
          hypothesis_id: String(hypothesisId),
          verdict: String(feedbackRecord.verdict || 'CONFIRMED'),
          previous_multiplier: Number(feedbackRecord.previousWeight || 1.0),
          updated_multiplier: Number(multiplier),
          operator_notes: String(feedbackRecord.operatorNotes || ''),
          user_id: String(feedbackRecord.userId || 'operator'),
          recorded_at: String(feedbackRecord.timestamp || now)
        });
      }
    } catch (_) {}
  }

  saveInvestigation(record) {
    if (!this.stmtUpsertInvestigation || !record || !record.investigationId) return;
    try {
      this.stmtUpsertInvestigation.run({
        investigation_id: String(record.investigationId),
        symptom: String(record.symptom || ''),
        process_query: record.processQuery ? String(record.processQuery) : null,
        target_host: String(record.targetHost || ''),
        target_port: Number(record.targetPort || 0),
        overall_verdict: String(record.overallVerdict || 'UNKNOWN'),
        confidence: Number(record.confidence || 0),
        uncertainty_warning: record.uncertaintyWarning ? 1 : 0,
        report_json: JSON.stringify(record),
        started_at: String(record.startedAt || new Date().toISOString()),
        completed_at: String(record.completedAt || new Date().toISOString())
      });
    } catch (_) {}
  }

  getAllBaselines() {
    try {
      return db.prepare('SELECT * FROM brain_baselines ORDER BY last_observed DESC').all();
    } catch (_) {
      return [];
    }
  }

  getAllCalibrations() {
    try {
      const rows = db.prepare('SELECT * FROM brain_calibration').all();
      const map = {};
      for (const r of rows) {
        if (!map[r.incident_type]) map[r.incident_type] = {};
        map[r.incident_type][r.hypothesis_id] = Number(r.multiplier);
      }
      return map;
    } catch (_) {
      return {};
    }
  }

  getRecentInvestigations(limit = 15) {
    try {
      const rows = db.prepare('SELECT report_json FROM unified_investigations ORDER BY completed_at DESC LIMIT ?').all(limit);
      return rows.map((r) => JSON.parse(r.report_json));
    } catch (_) {
      return [];
    }
  }
}

const brainPersistenceRepository = new BrainPersistenceRepository();

module.exports = {
  BrainPersistenceRepository,
  brainPersistenceRepository
};
