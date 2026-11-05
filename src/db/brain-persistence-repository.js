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
        CREATE TABLE IF NOT EXISTS endpoint_behavioral_profiles (
          target_key TEXT PRIMARY KEY,
          mac_address TEXT,
          icmp_filtered_normal INTEGER DEFAULT 0,
          known_open_ports_json TEXT DEFAULT '[]',
          expected_equipment_type TEXT DEFAULT 'UNKNOWN',
          apipa_flap_count INTEGER DEFAULT 0,
          last_root_cause_id TEXT,
          operator_notes TEXT,
          calibration_json TEXT DEFAULT '{}',
          first_learned_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_endpoint_profile_mac ON endpoint_behavioral_profiles(mac_address);
        CREATE TABLE IF NOT EXISTS autonomous_workflow_runs (
          workflow_id TEXT PRIMARY KEY,
          goal TEXT NOT NULL,
          target_host TEXT NOT NULL,
          target_port INTEGER DEFAULT 0,
          status TEXT NOT NULL,
          top_hypothesis_id TEXT,
          confidence INTEGER DEFAULT 0,
          plain_summary_json TEXT NOT NULL,
          workflow_report_json TEXT NOT NULL,
          started_at TEXT NOT NULL,
          completed_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS investigation_sessions (
          session_id TEXT PRIMARY KEY,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          state TEXT NOT NULL,
          symptom_type TEXT NOT NULL,
          target_host TEXT,
          target_port INTEGER,
          process_name TEXT,
          target_pid INTEGER,
          operator_role TEXT,
          top_hypothesis_id TEXT,
          calibrated_confidence REAL,
          evidence_coverage_ratio REAL,
          orchestration_mode TEXT,
          critic_passed INTEGER DEFAULT 1,
          verification_outcome TEXT,
          plan_json TEXT NOT NULL,
          critic_json TEXT,
          summary_json TEXT
        );
        CREATE TABLE IF NOT EXISTS investigation_evidence_ledger (
          evidence_id TEXT PRIMARY KEY,
          session_id TEXT NOT NULL,
          metric_key TEXT NOT NULL,
          evidence_class TEXT NOT NULL,
          outcome TEXT NOT NULL,
          value_json TEXT,
          unit TEXT,
          collector_id TEXT NOT NULL,
          collection_method TEXT NOT NULL,
          is_authoritative INTEGER NOT NULL,
          is_provisional INTEGER NOT NULL,
          timestamp_iso TEXT NOT NULL,
          supports_json TEXT,
          contradicts_json TEXT,
          FOREIGN KEY (session_id) REFERENCES investigation_sessions(session_id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS historical_incident_signatures (
          incident_id TEXT PRIMARY KEY,
          session_id TEXT,
          created_at TEXT NOT NULL,
          symptom_type TEXT NOT NULL,
          signature_vector_json TEXT NOT NULL,
          observed_keys_json TEXT NOT NULL,
          validated_root_cause_id TEXT,
          remediation_recipe_id TEXT,
          remediation_verified INTEGER DEFAULT 0,
          pre_post_delta_json TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_investigation_sessions_created ON investigation_sessions(created_at);
        CREATE INDEX IF NOT EXISTS idx_investigation_evidence_session ON investigation_evidence_ledger(session_id);
        CREATE INDEX IF NOT EXISTS idx_historical_signatures_symptom ON historical_incident_signatures(symptom_type);
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

  /**
   * Execute atomic batch transaction across baselines, incidents, calibrations, and investigations
   */
  saveSnapshotTransaction(snapshot = {}) {
    if (!snapshot || typeof snapshot !== 'object') return { success: false, error: 'Invalid snapshot' };
    const { baselines = [], incidents = [], calibrations = {}, investigations = [] } = snapshot;

    try {
      db.exec('BEGIN TRANSACTION;');

      // 1. Baselines
      for (const b of baselines) {
        if (b && b.target) {
          this.saveBaseline(b.target, b);
        }
      }

      // 2. Incidents
      for (const inc of incidents) {
        if (inc && inc.key) {
          this.saveIncident(inc.key, inc);
        }
      }

      // 3. Calibrations
      for (const [incType, hypMap] of Object.entries(calibrations)) {
        if (typeof hypMap === 'object' && hypMap !== null) {
          for (const [hId, mult] of Object.entries(hypMap)) {
            this.saveCalibration(incType, hId, mult);
          }
        }
      }

      // 4. Investigations
      for (const inv of investigations) {
        if (inv && inv.investigationId) {
          this.saveInvestigation(inv);
        }
      }

      db.exec('COMMIT;');
      return {
        success: true,
        itemsCommitted: baselines.length + incidents.length + Object.keys(calibrations).length + investigations.length,
        timestamp: new Date().toISOString()
      };
    } catch (err) {
      try { db.exec('ROLLBACK;'); } catch (_) {}
      return { success: false, error: err.message };
    }
  }

  /**
   * Upsert an Endpoint Behavioral Profile (Migration v4)
   */
  upsertEndpointProfile({
    targetKey,
    macAddress = 'Unknown',
    icmpFilteredNormal = 0,
    knownOpenPorts = [],
    expectedEquipmentType = 'UNKNOWN',
    apipaFlapIncrement = 0,
    lastRootCauseId = null,
    operatorNotes = null,
    calibration = {}
  }) {
    if (!targetKey) return null;
    const now = new Date().toISOString();
    const existing = this.getEndpointProfile(targetKey);
    const firstLearned = existing?.first_learned_at || now;
    const newFlapCount = (existing?.apipa_flap_count || 0) + (apipaFlapIncrement || 0);
    const portsJson = JSON.stringify(Array.isArray(knownOpenPorts) ? knownOpenPorts : []);
    const calJson = JSON.stringify(calibration || {});

    const stmt = db.prepare(`
      INSERT INTO endpoint_behavioral_profiles (
        target_key, mac_address, icmp_filtered_normal, known_open_ports_json,
        expected_equipment_type, apipa_flap_count, last_root_cause_id,
        operator_notes, calibration_json, first_learned_at, updated_at
      ) VALUES (
        @target_key, @mac_address, @icmp_filtered_normal, @known_open_ports_json,
        @expected_equipment_type, @apipa_flap_count, @last_root_cause_id,
        @operator_notes, @calibration_json, @first_learned_at, @updated_at
      )
      ON CONFLICT(target_key) DO UPDATE SET
        mac_address = CASE WHEN excluded.mac_address != 'Unknown' THEN excluded.mac_address ELSE endpoint_behavioral_profiles.mac_address END,
        icmp_filtered_normal = MAX(endpoint_behavioral_profiles.icmp_filtered_normal, excluded.icmp_filtered_normal),
        known_open_ports_json = excluded.known_open_ports_json,
        expected_equipment_type = CASE WHEN excluded.expected_equipment_type != 'UNKNOWN' THEN excluded.expected_equipment_type ELSE endpoint_behavioral_profiles.expected_equipment_type END,
        apipa_flap_count = @apipa_flap_count,
        last_root_cause_id = COALESCE(excluded.last_root_cause_id, endpoint_behavioral_profiles.last_root_cause_id),
        operator_notes = COALESCE(excluded.operator_notes, endpoint_behavioral_profiles.operator_notes),
        calibration_json = excluded.calibration_json,
        updated_at = excluded.updated_at
    `);

    stmt.run({
      target_key: targetKey,
      mac_address: macAddress,
      icmp_filtered_normal: icmpFilteredNormal ? 1 : 0,
      known_open_ports_json: portsJson,
      expected_equipment_type: expectedEquipmentType,
      apipa_flap_count: newFlapCount,
      last_root_cause_id: lastRootCauseId,
      operator_notes: operatorNotes,
      calibration_json: calJson,
      first_learned_at: firstLearned,
      updated_at: now
    });

    return this.getEndpointProfile(targetKey);
  }

  /**
   * Retrieve an Endpoint Behavioral Profile by IP or Target Key
   */
  getEndpointProfile(targetKey) {
    if (!targetKey) return null;
    try {
      const row = db.prepare('SELECT * FROM endpoint_behavioral_profiles WHERE target_key = ?').get(targetKey);
      if (!row) return null;
      let knownOpenPorts = [];
      let calibration = {};
      try { knownOpenPorts = JSON.parse(row.known_open_ports_json || '[]'); } catch (_) {}
      try { calibration = JSON.parse(row.calibration_json || '{}'); } catch (_) {}
      return {
        ...row,
        knownOpenPorts,
        calibration
      };
    } catch (_) {
      return null;
    }
  }

  /**
   * Persist an Autonomous Workflow Execution Run
   */
  saveAutonomousWorkflowRun(report) {
    if (!report || !report.workflowId) return null;
    const now = new Date().toISOString();
    try {
      const stmt = db.prepare(`
        INSERT OR REPLACE INTO autonomous_workflow_runs (
          workflow_id, goal, target_host, target_port, status,
          top_hypothesis_id, confidence, plain_summary_json,
          workflow_report_json, started_at, completed_at
        ) VALUES (
          @workflow_id, @goal, @target_host, @target_port, @status,
          @top_hypothesis_id, @confidence, @plain_summary_json,
          @workflow_report_json, @started_at, @completed_at
        )
      `);
      stmt.run({
        workflow_id: report.workflowId,
        goal: report.goal || 'General Investigation',
        target_host: report.targetHost || '127.0.0.1',
        target_port: report.targetPort || 0,
        status: report.status || 'COMPLETED',
        top_hypothesis_id: report.bayesianEvaluation?.topHypothesis?.id || null,
        confidence: report.bayesianEvaluation?.topHypothesis?.confidence || 0,
        plain_summary_json: JSON.stringify(report.plainLanguageDiagnosis || {}),
        workflow_report_json: JSON.stringify(report),
        started_at: report.startedAt || now,
        completed_at: report.completedAt || now
      });
      return report;
    } catch (err) {
      console.error('[BrainPersistenceRepository] Error saving autonomous workflow run:', err.message);
      return null;
    }
  }

  /**
   * Get Recent Autonomous Workflow Runs
   */
  getRecentAutonomousWorkflowRuns(limit = 20) {
    try {
      const rows = db.prepare('SELECT * FROM autonomous_workflow_runs ORDER BY completed_at DESC LIMIT ?').all(limit);
      return rows.map((r) => {
        let plainSummary = {};
        let workflowReport = {};
        try { plainSummary = JSON.parse(r.plain_summary_json || '{}'); } catch (_) {}
        try { workflowReport = JSON.parse(r.workflow_report_json || '{}'); } catch (_) {}
        return {
          ...r,
          plainSummary,
          workflowReport
        };
      });
    } catch (_) {
      return [];
    }
  }

  /**
   * Transactional upsert of an Investigation Session + all Evidence Ledger records (EJII Phase 4)
   */
  async saveInvestigationSession(session) {
    if (!session || !session.sessionId) return null;

    const upsertSessionStmt = db.prepare(`
      INSERT INTO investigation_sessions (
        session_id, created_at, updated_at, state, symptom_type, target_host, target_port,
        process_name, target_pid, operator_role, top_hypothesis_id, calibrated_confidence,
        evidence_coverage_ratio, orchestration_mode, critic_passed, verification_outcome,
        plan_json, critic_json, summary_json
      ) VALUES (
        @session_id, @created_at, @updated_at, @state, @symptom_type, @target_host, @target_port,
        @process_name, @target_pid, @operator_role, @top_hypothesis_id, @calibrated_confidence,
        @evidence_coverage_ratio, @orchestration_mode, @critic_passed, @verification_outcome,
        @plan_json, @critic_json, @summary_json
      )
      ON CONFLICT(session_id) DO UPDATE SET
        updated_at = excluded.updated_at,
        state = excluded.state,
        top_hypothesis_id = excluded.top_hypothesis_id,
        calibrated_confidence = excluded.calibrated_confidence,
        evidence_coverage_ratio = excluded.evidence_coverage_ratio,
        critic_passed = excluded.critic_passed,
        verification_outcome = excluded.verification_outcome,
        plan_json = excluded.plan_json,
        critic_json = excluded.critic_json,
        summary_json = excluded.summary_json
    `);

    const insertEvidenceStmt = db.prepare(`
      INSERT OR REPLACE INTO investigation_evidence_ledger (
        evidence_id, session_id, metric_key, evidence_class, outcome, value_json, unit,
        collector_id, collection_method, is_authoritative, is_provisional, timestamp_iso,
        supports_json, contradicts_json
      ) VALUES (
        @evidence_id, @session_id, @metric_key, @evidence_class, @outcome, @value_json, @unit,
        @collector_id, @collection_method, @is_authoritative, @is_provisional, @timestamp_iso,
        @supports_json, @contradicts_json
      )
    `);

    const runTx = () => {
      upsertSessionStmt.run({
        session_id: session.sessionId,
        created_at: session.createdAtIso || new Date().toISOString(),
        updated_at: session.updatedAtIso || new Date().toISOString(),
        state: session.state || 'COMPLETED',
        symptom_type: session.symptomType || 'GENERAL_CONNECTIVITY_OR_LATENCY',
        target_host: session.targetScope?.targetHost || null,
        target_port: session.targetScope?.port || 443,
        process_name: session.targetScope?.processName || null,
        target_pid: session.targetScope?.pid || null,
        operator_role: session.operatorRole || 'OPERATOR',
        top_hypothesis_id: session.topHypothesisId || null,
        calibrated_confidence: session.calibratedConfidence || 0,
        evidence_coverage_ratio: session.evidenceCoverageRatio || 0,
        orchestration_mode: session.orchestrationMode || 'LOCAL_DETERMINISTIC_BAYESIAN',
        critic_passed: session.criticPassed ? 1 : 0,
        verification_outcome: session.remediationVerification?.verificationOutcome || null,
        plan_json: JSON.stringify(session.steps || []),
        critic_json: JSON.stringify(session.criticEvaluation || {}),
        summary_json: JSON.stringify({
          recommendedActions: session.recommendedActions || [],
          hypothesisHistory: session.hypothesisHistory || []
        })
      });

      for (const ev of (session.evidenceLedger || [])) {
        insertEvidenceStmt.run({
          evidence_id: ev.evidenceId,
          session_id: session.sessionId,
          metric_key: ev.metricKey,
          evidence_class: ev.evidenceClass || 'OBSERVED',
          outcome: ev.outcome || 'SUCCESS',
          value_json: JSON.stringify(ev.value),
          unit: ev.unit || '',
          collector_id: ev.collectorId || 'default_collector',
          collection_method: ev.collectionMethod || 'PROBE',
          is_authoritative: ev.isAuthoritative ? 1 : 0,
          is_provisional: ev.isProvisional ? 1 : 0,
          timestamp_iso: ev.timestampIso || new Date().toISOString(),
          supports_json: JSON.stringify(ev.supports || []),
          contradicts_json: JSON.stringify(ev.contradicts || [])
        });
      }
    };

    if (typeof db.transaction === 'function') {
      db.transaction(runTx)();
    } else {
      runTx();
    }

    return session;
  }

  /**
   * Retrieves an Investigation Session by ID including its complete evidence ledger.
   */
  getInvestigationSession(sessionId) {
    if (!sessionId) return null;
    try {
      const sessionRow = db.prepare('SELECT * FROM investigation_sessions WHERE session_id = ?').get(sessionId);
      if (!sessionRow) return null;

      const evidenceRows = db.prepare('SELECT * FROM investigation_evidence_ledger WHERE session_id = ? ORDER BY timestamp_iso ASC').all(sessionId);

      let steps = [];
      let criticEvaluation = {};
      let summary = {};
      try { steps = JSON.parse(sessionRow.plan_json || '[]'); } catch (_) {}
      try { criticEvaluation = JSON.parse(sessionRow.critic_json || '{}'); } catch (_) {}
      try { summary = JSON.parse(sessionRow.summary_json || '{}'); } catch (_) {}

      const evidenceLedger = evidenceRows.map(r => {
        let val = null;
        let supports = [];
        let contradicts = [];
        try { val = JSON.parse(r.value_json); } catch (_) { val = r.value_json; }
        try { supports = JSON.parse(r.supports_json || '[]'); } catch (_) {}
        try { contradicts = JSON.parse(r.contradicts_json || '[]'); } catch (_) {}
        return {
          evidenceId: r.evidence_id,
          sessionId: r.session_id,
          metricKey: r.metric_key,
          evidenceClass: r.evidence_class,
          outcome: r.outcome,
          value: val,
          unit: r.unit,
          collectorId: r.collector_id,
          collectionMethod: r.collection_method,
          isAuthoritative: Boolean(r.is_authoritative),
          isProvisional: Boolean(r.is_provisional),
          timestampIso: r.timestamp_iso,
          supports,
          contradicts
        };
      });

      return {
        sessionId: sessionRow.session_id,
        createdAtIso: sessionRow.created_at,
        updatedAtIso: sessionRow.updated_at,
        state: sessionRow.state,
        symptomType: sessionRow.symptom_type,
        targetScope: {
          targetHost: sessionRow.target_host,
          port: sessionRow.target_port,
          processName: sessionRow.process_name,
          pid: sessionRow.target_pid
        },
        operatorRole: sessionRow.operator_role,
        topHypothesisId: sessionRow.top_hypothesis_id,
        calibratedConfidence: sessionRow.calibrated_confidence,
        evidenceCoverageRatio: sessionRow.evidence_coverage_ratio,
        orchestrationMode: sessionRow.orchestration_mode,
        criticPassed: Boolean(sessionRow.critic_passed),
        verificationOutcome: sessionRow.verification_outcome,
        steps,
        criticEvaluation,
        hypothesisHistory: summary.hypothesisHistory || [],
        recommendedActions: summary.recommendedActions || [],
        evidenceLedger
      };
    } catch (err) {
      console.error('[BrainPersistenceRepository] Error fetching investigation session:', err.message);
      return null;
    }
  }

  /**
   * List recent investigation sessions.
   */
  listRecentInvestigations(limit = 25) {
    try {
      const rows = db.prepare('SELECT * FROM investigation_sessions ORDER BY created_at DESC LIMIT ?').all(limit);
      return rows.map(r => {
        let steps = [];
        try { steps = JSON.parse(r.plan_json || '[]'); } catch (_) {}
        return {
          sessionId: r.session_id,
          createdAtIso: r.created_at,
          updatedAtIso: r.updated_at,
          state: r.state,
          symptomType: r.symptom_type,
          targetHost: r.target_host,
          targetPort: r.target_port,
          processName: r.process_name,
          topHypothesisId: r.top_hypothesis_id,
          calibratedConfidence: r.calibrated_confidence,
          verificationOutcome: r.verification_outcome,
          stepsCount: steps.length
        };
      });
    } catch (_) {
      return [];
    }
  }

  /**
   * Record a historical incident signature for Case-Based Reasoning retrieval
   */
  recordHistoricalIncidentSignature(incidentRecord = {}) {
    try {
      const incidentId = incidentRecord.incidentId || `SIGN-${Date.now()}-${Math.random().toString(36).slice(2, 7).toUpperCase()}`;
      const now = new Date().toISOString();

      const stmt = db.prepare(`
        INSERT OR REPLACE INTO historical_incident_signatures (
          incident_id, session_id, created_at, symptom_type, signature_vector_json,
          observed_keys_json, validated_root_cause_id, remediation_recipe_id,
          remediation_verified, pre_post_delta_json
        ) VALUES (
          @incident_id, @session_id, @created_at, @symptom_type, @signature_vector_json,
          @observed_keys_json, @validated_root_cause_id, @remediation_recipe_id,
          @remediation_verified, @pre_post_delta_json
        )
      `);

      stmt.run({
        incident_id: incidentId,
        session_id: incidentRecord.sessionId || null,
        created_at: incidentRecord.createdAt || now,
        symptom_type: incidentRecord.symptomType || 'GENERAL_CONNECTIVITY_OR_LATENCY',
        signature_vector_json: JSON.stringify(incidentRecord.signatureVector || this._extract16DimFeatureVector(incidentRecord.evidenceRecords || [])),
        observed_keys_json: JSON.stringify(incidentRecord.observedKeys || []),
        validated_root_cause_id: incidentRecord.validatedRootCauseId || incidentRecord.rootCauseId || null,
        remediation_recipe_id: incidentRecord.remediationRecipeId || null,
        remediation_verified: incidentRecord.remediationVerified ? 1 : 0,
        pre_post_delta_json: JSON.stringify(incidentRecord.prePostDelta || {})
      });

      return incidentId;
    } catch (err) {
      console.error('[BrainPersistenceRepository] Error recording incident signature:', err.message);
      return null;
    }
  }

  /**
   * Case-Based Reasoning (CBR) Historical Matcher
   * Calculates hybrid similarity score:
   * Similarity = 0.6 * Cosine(V_curr, V_hist) + 0.4 * Jaccard(K_curr, K_hist)
   */
  findSimilarHistoricalIncidents(currentSymptoms = '', observedEvidenceRecords = [], topK = 5) {
    try {
      const rows = db.prepare('SELECT * FROM historical_incident_signatures ORDER BY created_at DESC LIMIT 100').all();
      if (!rows || rows.length === 0) return [];

      const currentVec = this._extract16DimFeatureVector(observedEvidenceRecords);
      const currentObservedKeys = new Set(observedEvidenceRecords.map(e => e.metricKey));

      const scored = [];
      for (const row of rows) {
        let histVec = [];
        let histKeys = [];
        try { histVec = JSON.parse(row.signature_vector_json || '[]'); } catch (_) {}
        try { histKeys = JSON.parse(row.observed_keys_json || '[]'); } catch (_) {}

        const cosineSim = this._cosineSimilarity(currentVec, histVec);
        const jaccardSim = this._jaccardSimilarity(currentObservedKeys, new Set(histKeys));
        const hybridScore = Number((0.6 * cosineSim + 0.4 * jaccardSim).toFixed(4));

        let prePostDelta = {};
        try { prePostDelta = JSON.parse(row.pre_post_delta_json || '{}'); } catch (_) {}

        scored.push({
          incidentId: row.incident_id,
          sessionId: row.session_id,
          createdAt: row.created_at,
          symptomType: row.symptom_type,
          validatedRootCauseId: row.validated_root_cause_id,
          remediationRecipeId: row.remediation_recipe_id,
          remediationVerified: Boolean(row.remediation_verified),
          similarityScore: hybridScore,
          cosineSimilarity: cosineSim,
          jaccardSimilarity: jaccardSim,
          prePostDelta
        });
      }

      scored.sort((a, b) => b.similarityScore - a.similarityScore);
      return scored.slice(0, topK);
    } catch (err) {
      console.error('[BrainPersistenceRepository] Error finding similar historical incidents:', err.message);
      return [];
    }
  }

  _extract16DimFeatureVector(evidenceRecords = []) {
    const CANONICAL_DIMS = [
      'dnsFailure', 'tcpRstReceived', 'tcpSynTimeout', 'tlsAlert',
      'gatewayUnreachable', 'arpIncomplete', 'apipaAddress', 'highCpu',
      'highRam', 'diskQueueSaturated', 'spoolerStopped', 'packetRetransmissionHigh',
      'mtuBlackhole', 'http5xx', 'loopbackFailure', 'pnpDeviceError'
    ];

    const vec = new Array(16).fill(0);
    for (const ev of evidenceRecords) {
      const k = String(ev.metricKey || '').toLowerCase();
      const isBad = ev.outcome !== 'SUCCESS';

      if (k.includes('dns') && isBad) vec[0] = 1;
      if (k.includes('rst') || (k.includes('tcp') && ev.value === 'RST')) vec[1] = 1;
      if (k.includes('timeout') || (k.includes('syn') && isBad)) vec[2] = 1;
      if (k.includes('tls') && isBad) vec[3] = 1;
      if (k.includes('gateway') && isBad) vec[4] = 1;
      if (k.includes('arp') && isBad) vec[5] = 1;
      if (k.includes('apipa') || (k.includes('ip') && String(ev.value).startsWith('169.254'))) vec[6] = 1;
      if (k.includes('cpu') && (Number(ev.value) > 85)) vec[7] = 1;
      if (k.includes('ram') && (Number(ev.value) > 90)) vec[8] = 1;
      if (k.includes('disk') && isBad) vec[9] = 1;
      if (k.includes('spooler') && isBad) vec[10] = 1;
      if (k.includes('retrans') && (Number(ev.value) > 5)) vec[11] = 1;
      if (k.includes('mtu') && isBad) vec[12] = 1;
      if (k.includes('http') && (Number(ev.value) >= 500)) vec[13] = 1;
      if (k.includes('loopback') && isBad) vec[14] = 1;
      if (k.includes('pnp') && isBad) vec[15] = 1;
    }
    return vec;
  }

  _cosineSimilarity(vecA, vecB) {
    if (!Array.isArray(vecA) || !Array.isArray(vecB) || vecA.length === 0 || vecB.length === 0) return 0;
    const len = Math.min(vecA.length, vecB.length);
    let dot = 0;
    let normA = 0;
    let normB = 0;
    for (let i = 0; i < len; i++) {
      dot += vecA[i] * vecB[i];
      normA += vecA[i] * vecA[i];
      normB += vecB[i] * vecB[i];
    }
    if (normA === 0 || normB === 0) return 0;
    return Number((dot / (Math.sqrt(normA) * Math.sqrt(normB))).toFixed(4));
  }

  _jaccardSimilarity(setA, setB) {
    if (!setA || !setB) return 1.0;
    const sA = setA instanceof Set ? setA : new Set(setA);
    const sB = setB instanceof Set ? setB : new Set(setB);
    if (sA.size === 0 && sB.size === 0) return 1.0;

    let intersectionCount = 0;
    for (const item of sA) {
      if (sB.has(item)) intersectionCount++;
    }
    const unionCount = sA.size + sB.size - intersectionCount;
    if (unionCount === 0) return 1.0;
    return Number((intersectionCount / unionCount).toFixed(4));
  }

  /**
   * Diagnostic integrity check for SQLite WAL database
   */
  getDatabaseIntegrityDiagnostics() {
    try {
      const integrityCheck = db.prepare('PRAGMA integrity_check;').all();
      const walQuickCheck = db.prepare('PRAGMA quick_check;').all();
      const journalMode = db.prepare('PRAGMA journal_mode;').all();
      const synchronous = db.prepare('PRAGMA synchronous;').all();
      const busyTimeout = db.prepare('PRAGMA busy_timeout;').all();

      const baselinesCount = db.prepare('SELECT COUNT(*) as c FROM brain_baselines;').get()?.c || 0;
      const incidentsCount = db.prepare('SELECT COUNT(*) as c FROM brain_incidents;').get()?.c || 0;
      const investigationsCount = db.prepare('SELECT COUNT(*) as c FROM unified_investigations;').get()?.c || 0;

      return {
        healthy: integrityCheck?.[0]?.integrity_check === 'ok',
        journalMode: journalMode?.[0]?.journal_mode || 'wal',
        synchronous: synchronous?.[0]?.synchronous ?? 1,
        busyTimeoutMs: busyTimeout?.[0]?.timeout ?? 8000,
        integrityResult: integrityCheck?.[0]?.integrity_check || 'ok',
        quickCheckResult: walQuickCheck?.[0]?.quick_check || 'ok',
        records: {
          baselines: baselinesCount,
          incidents: incidentsCount,
          investigations: investigationsCount
        },
        checkedAt: new Date().toISOString()
      };
    } catch (err) {
      return {
        healthy: false,
        error: err.message,
        checkedAt: new Date().toISOString()
      };
    }
  }
}

const brainPersistenceRepository = new BrainPersistenceRepository();

module.exports = {
  BrainPersistenceRepository,
  brainPersistenceRepository
};
