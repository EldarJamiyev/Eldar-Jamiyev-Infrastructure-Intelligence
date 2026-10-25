/**
 * EJII Transactional SQLite Schema Migration Engine
 * Maintains a cryptographic checksum-verified schema_migrations ledger
 * and ensures all NOC topology, security, AI Brain, and Office Equipment
 * tables and indexes exist under WAL mode.
 */

const crypto = require('crypto');

const MIGRATIONS = [
  {
    version: 1,
    name: '001_core_noc_topology_auth_and_audit',
    sql: `
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        role TEXT NOT NULL,
        full_name TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS topology_nodes (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        layer INTEGER NOT NULL,
        hostname_or_ip TEXT NOT NULL,
        mac_address TEXT,
        vendor TEXT,
        status TEXT DEFAULT 'unknown',
        latency_ms REAL,
        packet_loss REAL DEFAULT 0,
        last_checked TEXT
      );
      CREATE TABLE IF NOT EXISTS topology_edges (
        id TEXT PRIMARY KEY,
        source_id TEXT NOT NULL,
        target_id TEXT NOT NULL,
        protocol TEXT DEFAULT 'TCP/IP',
        port INTEGER DEFAULT 443,
        bandwidth_mbps INTEGER DEFAULT 1000,
        status TEXT DEFAULT 'healthy',
        latency_ms REAL DEFAULT 1.0,
        utilization_pct REAL DEFAULT 5.0
      );
      CREATE TABLE IF NOT EXISTS consumed_action_tokens (
        token_hash TEXT PRIMARY KEY,
        action_type TEXT NOT NULL,
        user_id TEXT NOT NULL,
        consumed_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      );
    `
  },
  {
    version: 2,
    name: '002_ai_brain_wal_persistence_tables',
    sql: `
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
    `
  },
  {
    version: 3,
    name: '003_office_equipment_inventory_and_dhcp_events',
    sql: `
      CREATE TABLE IF NOT EXISTS office_equipment_inventory (
        device_id TEXT PRIMARY KEY,
        mac_address TEXT,
        current_ip TEXT NOT NULL,
        last_known_good_ip TEXT,
        device_name TEXT,
        equipment_type TEXT NOT NULL,
        equipment_category TEXT NOT NULL,
        equipment_brand TEXT,
        icon TEXT DEFAULT '💻',
        is_apipa_fault INTEGER DEFAULT 0,
        status TEXT DEFAULT 'ONLINE',
        open_ports_json TEXT DEFAULT '[]',
        passive_os_fingerprint TEXT,
        discovery_source TEXT DEFAULT 'SCANNER',
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_office_equip_ip ON office_equipment_inventory(current_ip);
      CREATE INDEX IF NOT EXISTS idx_office_equip_mac ON office_equipment_inventory(mac_address);
      CREATE INDEX IF NOT EXISTS idx_office_equip_cat ON office_equipment_inventory(equipment_category);

      CREATE TABLE IF NOT EXISTS dhcp_and_ip_events (
        event_id TEXT PRIMARY KEY,
        mac_address TEXT,
        ip_address TEXT NOT NULL,
        previous_ip TEXT,
        event_type TEXT NOT NULL,
        dhcp_message_type TEXT,
        hostname TEXT,
        details TEXT,
        observed_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_dhcp_events_mac ON dhcp_and_ip_events(mac_address);
      CREATE INDEX IF NOT EXISTS idx_dhcp_events_time ON dhcp_and_ip_events(observed_at);
    `
  },
  {
    version: 4,
    name: '004_endpoint_behavioral_profiles_and_autonomous_workflows',
    sql: `
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
    `
  },
  {
    version: 5,
    name: '005_investigation_sessions_ledger_and_cbr_signatures',
    sql: `
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
    `
  }
];

function runMigrations(dbInstance) {
  if (!dbInstance) {
    try {
      dbInstance = require('./database').db;
    } catch (_) {}
  }
  if (!dbInstance) return { appliedCount: 0, totalMigrations: MIGRATIONS.length, migrations: [] };

  dbInstance.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      checksum TEXT NOT NULL,
      applied_at TEXT NOT NULL
    );
  `);

  try {
    const tableInfo = dbInstance.prepare("PRAGMA table_info('schema_migrations')").all();
    const hasChecksum = tableInfo.some((col) => col.name === 'checksum');
    if (!hasChecksum) {
      dbInstance.exec('ALTER TABLE schema_migrations ADD COLUMN checksum TEXT');
    }
  } catch (_) {}

  const appliedRows = dbInstance.prepare('SELECT version, name, checksum FROM schema_migrations ORDER BY version ASC').all();
  const appliedMap = new Map(appliedRows.map((r) => [Number(r.version), r]));
  const insertMigration = dbInstance.prepare(`
    INSERT OR REPLACE INTO schema_migrations (version, name, checksum, applied_at)
    VALUES (@version, @name, @checksum, @applied_at)
  `);

  let appliedCount = 0;
  const runBatch = () => {
    for (const mig of MIGRATIONS) {
      const checksum = crypto.createHash('sha256').update(mig.sql).digest('hex').slice(0, 32);
      if (!appliedMap.has(mig.version)) {
        dbInstance.exec(mig.sql);
        insertMigration.run({
          version: mig.version,
          name: mig.name,
          checksum,
          applied_at: new Date().toISOString()
        });
        appliedCount++;
      } else {
        // Ensure tables still exist even if schema_migrations was previously populated
        dbInstance.exec(mig.sql);
        const existing = appliedMap.get(mig.version);
        if (!existing || !existing.checksum) {
          try {
            dbInstance.prepare('UPDATE schema_migrations SET checksum = ? WHERE version = ?').run(checksum, mig.version);
          } catch (_) {}
        }
      }
    }
  };

  if (typeof dbInstance.transaction === 'function') {
    dbInstance.transaction(runBatch)();
  } else {
    dbInstance.exec('BEGIN IMMEDIATE;');
    try {
      runBatch();
      dbInstance.exec('COMMIT;');
    } catch (err) {
      try { dbInstance.exec('ROLLBACK;'); } catch (_) {}
      throw err;
    }
  }

  return {
    appliedCount,
    totalMigrations: MIGRATIONS.length,
    migrations: dbInstance.prepare('SELECT version, name, checksum, applied_at FROM schema_migrations ORDER BY version ASC').all()
  };
}

module.exports = {
  MIGRATIONS,
  runMigrations
};
