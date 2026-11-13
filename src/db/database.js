/**
 * EJII Database Module using Node.js Native SQLite (node:sqlite)
 * Pure NOC Workstation Database Layer: Topology Nodes, Edges, Link Telemetry, Capture Sessions, Network Anomalies.
 * Purged of all ITSM, Helpdesk, CMDB asset inventory, Configuration Drift, and Chaos modules.
 */

const { DatabaseSync } = require('node:sqlite');
const fs = require('fs');
const path = require('path');
const { DB_PATH, DATA_DIR } = require('../config');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const db = new DatabaseSync(DB_PATH);

if (typeof db.pragma !== 'function') {
  db.pragma = (str) => db.exec('PRAGMA ' + str + ';');
}

// High-performance WAL mode for low latency
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA busy_timeout = 8000;');
db.exec('PRAGMA synchronous = NORMAL;');
db.exec('PRAGMA cache_size = -64000;');
db.exec('PRAGMA foreign_keys = ON;');

let lastMigrationStatus = 'UNINITIALIZED';
let lastMigrationError = null;
let lastMigrationResult = null;

/**
 * Initialize NOC schema non-destructively (preserving all existing tables and records)
 */
function initSchema(targetDb = db) {
  targetDb.exec('PRAGMA foreign_keys = OFF;');

  // Non-destructive schema initialization: existing tables and records are strictly preserved.
  targetDb.exec(`
    -- Cryptographic HMAC Audit Trail
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL,
      user_id TEXT NOT NULL,
      username TEXT NOT NULL,
      role TEXT NOT NULL,
      action TEXT NOT NULL,
      resource TEXT NOT NULL,
      details TEXT,
      ip_address TEXT,
      prev_hash TEXT NOT NULL,
      hash TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);

    -- Single-Operator / Unprivileged Local Authentication
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      full_name TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'noc_operator',
      is_active INTEGER DEFAULT 1,
      mfa_enabled INTEGER DEFAULT 0,
      mfa_secret TEXT,
      mfa_pending_secret TEXT,
      mfa_last_counter INTEGER DEFAULT 0,
      mfa_updated_at TEXT,
      created_at TEXT NOT NULL,
      last_login TEXT
    );

    -- Session Security: Revoked Tokens
    CREATE TABLE IF NOT EXISTS revoked_tokens (
      token TEXT PRIMARY KEY,
      user_id TEXT,
      reason TEXT,
      revoked_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_revoked_tokens_user ON revoked_tokens(user_id);

    -- Pillar 4: Cryptographic Remediation Replay Ledger (S-01)
    CREATE TABLE IF NOT EXISTS consumed_action_tokens (
      token_id TEXT PRIMARY KEY,
      user_id TEXT,
      recipe_id TEXT,
      expires_at INTEGER NOT NULL,
      consumed_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_consumed_tokens_exp ON consumed_action_tokens(expires_at);

    -- Pillar 1: NOC Topology Nodes (Layer 1 - Layer 6 Physical/Logical Network Graph)
    CREATE TABLE IF NOT EXISTS topology_nodes (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      hostname_or_ip TEXT NOT NULL,
      mac_address TEXT,
      type TEXT NOT NULL DEFAULT 'host',
      layer TEXT NOT NULL DEFAULT 'access',
      layer_level INTEGER DEFAULT 5,
      parent_id TEXT,
      status TEXT DEFAULT 'healthy',
      last_checked TEXT,
      last_latency_ms REAL,
      vendor TEXT,
      if_name TEXT,
      x REAL DEFAULT 0,
      y REAL DEFAULT 0,
      metadata TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_topo_nodes_ip ON topology_nodes(hostname_or_ip);
    CREATE INDEX IF NOT EXISTS idx_topo_nodes_status ON topology_nodes(status);

    -- Pillar 1: NOC Topology Edges (Interconnect links, bandwidth, congestion status)
    CREATE TABLE IF NOT EXISTS topology_edges (
      id TEXT PRIMARY KEY,
      source_id TEXT NOT NULL,
      target_id TEXT NOT NULL,
      link_type TEXT DEFAULT 'ethernet',
      status TEXT DEFAULT 'up',
      bandwidth_mbps REAL DEFAULT 1000,
      utilization_pct REAL DEFAULT 15,
      latency_ms REAL DEFAULT 1.0,
      packet_rate REAL DEFAULT 120,
      metadata TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_topo_edges_src_tgt ON topology_edges(source_id, target_id);

    -- Pillar 1: NOC Topology Snapshots (Adaptive Topology History & Invalidation Archive)
    CREATE TABLE IF NOT EXISTS topology_snapshots (
      id TEXT PRIMARY KEY,
      snapshot_name TEXT NOT NULL,
      environment_cidr TEXT NOT NULL,
      gateway_ip TEXT NOT NULL,
      host_ip TEXT NOT NULL,
      interface_alias TEXT,
      trigger_reason TEXT NOT NULL,
      nodes_count INTEGER NOT NULL,
      edges_count INTEGER NOT NULL,
      topology_data TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_topo_snapshots_time ON topology_snapshots(created_at);

    -- Pillar 1 & 4: Link Telemetry & Heatmap Metrics (Latency, loss, octets, packet rates)
    CREATE TABLE IF NOT EXISTS link_telemetry (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      edge_id TEXT,
      node_id TEXT,
      latency_ms REAL,
      loss_pct REAL DEFAULT 0,
      bandwidth_utilization_pct REAL DEFAULT 0,
      packet_rate REAL DEFAULT 0,
      if_in_octets INTEGER DEFAULT 0,
      if_out_octets INTEGER DEFAULT 0,
      timestamp TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_link_telemetry_time ON link_telemetry(timestamp);
    CREATE INDEX IF NOT EXISTS idx_link_telemetry_edge ON link_telemetry(edge_id);
    CREATE INDEX IF NOT EXISTS idx_link_telemetry_node ON link_telemetry(node_id);

    -- Pillar 2: Packet Capture Sessions & Stream Metrics Cache
    CREATE TABLE IF NOT EXISTS packet_capture_sessions (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      bpf_filter TEXT,
      interface_name TEXT,
      start_time TEXT NOT NULL,
      end_time TEXT,
      packet_count INTEGER DEFAULT 0,
      bytes_count INTEGER DEFAULT 0,
      status TEXT DEFAULT 'active',
      metrics_json TEXT
    );

    -- Pillar 2, 3 & 4: Network Wire-Level Anomalies (TCP resets, retransmits, MTU black holes, latency spikes)
    CREATE TABLE IF NOT EXISTS network_anomalies (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      anomaly_type TEXT NOT NULL,
      source_ip TEXT,
      target_ip TEXT,
      stream_id INTEGER,
      severity TEXT DEFAULT 'warning',
      details TEXT,
      resolved INTEGER DEFAULT 0
    );

    CREATE INDEX IF NOT EXISTS idx_network_anomalies_time ON network_anomalies(timestamp);
    CREATE INDEX IF NOT EXISTS idx_network_anomalies_type ON network_anomalies(anomaly_type);

    -- Helper table for backward compatibility with diagnostic probes
    CREATE TABLE IF NOT EXISTS nodes (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      hostname_or_ip TEXT NOT NULL,
      mac_address TEXT,
      type TEXT NOT NULL DEFAULT 'host',
      parent_id TEXT,
      status TEXT DEFAULT 'healthy',
      last_checked TEXT,
      last_latency_ms REAL,
      vendor TEXT,
      metadata TEXT
    );

    CREATE TABLE IF NOT EXISTS telemetry_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      node_id TEXT NOT NULL,
      metric_type TEXT NOT NULL DEFAULT 'latency',
      metric_name TEXT NOT NULL DEFAULT 'latency_ms',
      value REAL,
      unit TEXT DEFAULT 'ms',
      status TEXT DEFAULT 'healthy',
      raw_payload TEXT,
      timestamp TEXT NOT NULL
    );

    -- Synchronization Triggers: topology_nodes <-> nodes
    CREATE TRIGGER IF NOT EXISTS trigger_sync_topo_to_nodes_ins AFTER INSERT ON topology_nodes
    BEGIN
      INSERT OR REPLACE INTO nodes (id, name, hostname_or_ip, mac_address, type, parent_id, status, last_checked, last_latency_ms, vendor, metadata)
      VALUES (NEW.id, NEW.name, NEW.hostname_or_ip, NEW.mac_address, NEW.type, NEW.parent_id, NEW.status, NEW.last_checked, NEW.last_latency_ms, NEW.vendor, NEW.metadata);
    END;

    CREATE TRIGGER IF NOT EXISTS trigger_sync_topo_to_nodes_upd AFTER UPDATE ON topology_nodes
    BEGIN
      UPDATE nodes SET
        name = NEW.name,
        hostname_or_ip = NEW.hostname_or_ip,
        mac_address = NEW.mac_address,
        type = NEW.type,
        parent_id = NEW.parent_id,
        status = NEW.status,
        last_checked = NEW.last_checked,
        last_latency_ms = NEW.last_latency_ms,
        vendor = NEW.vendor,
        metadata = NEW.metadata
      WHERE id = NEW.id;
    END;

    CREATE TRIGGER IF NOT EXISTS trigger_sync_nodes_to_topo_upd AFTER UPDATE ON nodes
    BEGIN
      UPDATE topology_nodes SET
        name = NEW.name,
        hostname_or_ip = NEW.hostname_or_ip,
        mac_address = NEW.mac_address,
        status = NEW.status,
        last_checked = NEW.last_checked,
        last_latency_ms = NEW.last_latency_ms,
        vendor = NEW.vendor
      WHERE id = NEW.id;
    END;

    -- Sync telemetry_history -> link_telemetry
    CREATE TRIGGER IF NOT EXISTS trigger_sync_telemetry_ins AFTER INSERT ON telemetry_history
    BEGIN
      INSERT INTO link_telemetry (node_id, latency_ms, timestamp)
      VALUES (NEW.node_id, NEW.value, NEW.timestamp);
    END;

    -- Pillar 5 & AI Brain: SQLite WAL Persistence Tables
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

    CREATE TABLE IF NOT EXISTS connectivity_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source_ip TEXT NOT NULL,
      destination_ip TEXT NOT NULL,
      port INTEGER NOT NULL,
      protocol TEXT NOT NULL,
      status TEXT NOT NULL,
      error_code TEXT,
      latency_ms REAL,
      stepper_summary TEXT,
      diagnostic_verdict TEXT,
      is_regression INTEGER DEFAULT 0,
      regression_notes TEXT,
      timestamp TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_conn_hist_dest_port ON connectivity_history(destination_ip, port);
    CREATE TABLE IF NOT EXISTS incidents (
      id TEXT PRIMARY KEY,
      primary_node_id TEXT NOT NULL,
      title TEXT NOT NULL,
      status TEXT NOT NULL,
      what_happened TEXT,
      root_cause TEXT,
      supporting_evidence TEXT,
      remediation_plan TEXT,
      suppressed_count INTEGER DEFAULT 0,
      resolved_by TEXT,
      resolved_at TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_incidents_node ON incidents(primary_node_id);
    CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
  `);

  try {
    const userCols = targetDb.prepare('PRAGMA table_info(users)').all().map((c) => c.name);
    const mfaCols = [
      ['mfa_enabled', 'INTEGER DEFAULT 0'],
      ['mfa_secret', 'TEXT'],
      ['mfa_pending_secret', 'TEXT'],
      ['mfa_last_counter', 'INTEGER DEFAULT 0'],
      ['mfa_updated_at', 'TEXT']
    ];
    for (const [colName, colDef] of mfaCols) {
      if (!userCols.includes(colName)) {
        targetDb.exec(`ALTER TABLE users ADD COLUMN ${colName} ${colDef};`);
      }
    }
  } catch (_) {}

  try {
    const { runMigrations } = require('./migrations');
    const migResult = runMigrations(targetDb);
    targetDb._ejiiMigrationResult = migResult;
    targetDb._ejiiMigrationStatus = 'SUCCESS';
    targetDb._ejiiMigrationError = null;
    if (targetDb === db) {
      lastMigrationResult = migResult;
      lastMigrationStatus = 'SUCCESS';
      lastMigrationError = null;
    }
  } catch (err) {
    const errMsg = err && err.message ? err.message : String(err);
    targetDb._ejiiMigrationStatus = 'FAILED';
    targetDb._ejiiMigrationError = errMsg;
    if (targetDb === db) {
      lastMigrationStatus = 'FAILED';
      lastMigrationError = errMsg;
    }
    console.error('[EJII Database Migration Error]:', errMsg);
  }

  targetDb.exec('PRAGMA foreign_keys = ON;');
}

function getDatabaseHealth(targetDb = db) {
  const probeStartNs = process.hrtime.bigint();
  try {
    if (!targetDb || typeof targetDb.prepare !== 'function') {
      throw new Error('Database handle is null or closed');
    }
    const journalRow = targetDb.prepare('PRAGMA journal_mode').get();
    const fkRow = targetDb.prepare('PRAGMA foreign_keys').get();
    const queryOnlyRow = targetDb.prepare('PRAGMA query_only').get();
    const isQueryOnly = queryOnlyRow ? Boolean(Number(Object.values(queryOnlyRow)[0])) : false;
    const journalMode = journalRow ? String(Object.values(journalRow)[0]).toLowerCase() : 'unknown';
    const migRows = targetDb
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'")
      .all();
    const appliedMigrations = migRows.length > 0
      ? targetDb.prepare('SELECT version, name, checksum, applied_at FROM schema_migrations ORDER BY version ASC').all()
      : [];

    // Execute a bounded, non-destructive transactional write probe using SAVEPOINT + ROLLBACK
    // so we verify actual write capability (detecting read-only filesystems, query_only, or lock contention)
    // without mutating any persistent rows.
    let writeCapable = !isQueryOnly;
    let writeProbeError = null;
    let lockContentionDetected = false;
    if (writeCapable) {
      try {
        targetDb.exec('SAVEPOINT ejii_write_health_probe;');
        try {
          if (migRows.length > 0) {
            targetDb.prepare('UPDATE schema_migrations SET version = version WHERE version = -999999').run();
          } else {
            targetDb.exec('CREATE TEMP TABLE IF NOT EXISTS _ejii_write_probe (id INTEGER); INSERT INTO _ejii_write_probe VALUES (1);');
          }
        } finally {
          try { targetDb.exec('ROLLBACK TO SAVEPOINT ejii_write_health_probe;'); } catch (_) {}
          try { targetDb.exec('RELEASE SAVEPOINT ejii_write_health_probe;'); } catch (_) {}
        }
      } catch (probeErr) {
        writeCapable = false;
        writeProbeError = probeErr && probeErr.message ? probeErr.message : String(probeErr);
        if (/BUSY|LOCKED/i.test(writeProbeError)) {
          lockContentionDetected = true;
        }
      }
    } else {
      writeProbeError = 'Connection has PRAGMA query_only = 1 (read-only mode)';
    }

    const instanceMigrationStatus = targetDb._ejiiMigrationStatus || (targetDb === db ? lastMigrationStatus : (migRows.length > 0 ? 'SUCCESS' : 'UNINITIALIZED'));
    const instanceMigrationError = targetDb._ejiiMigrationError !== undefined
      ? targetDb._ejiiMigrationError
      : (targetDb === db ? lastMigrationError : null);

    const probeLatencyMs = Number((Number(process.hrtime.bigint() - probeStartNs) / 1e6).toFixed(3));
    const healthy = instanceMigrationStatus !== 'FAILED' && writeCapable;
    let operationalState = 'HEALTHY_DURABLE_WAL';
    if (instanceMigrationStatus === 'FAILED') {
      operationalState = 'MIGRATION_FAILED';
    } else if (instanceMigrationStatus === 'UNINITIALIZED') {
      operationalState = 'INITIALIZATION_IN_PROGRESS';
    } else if (lockContentionDetected) {
      operationalState = 'TEMPORARY_LOCK_CONTENTION';
    } else if (!writeCapable) {
      operationalState = 'TEMPORARY_WRITE_FAILURE';
    } else if (journalMode !== 'wal') {
      operationalState = 'HEALTHY_DURABLE';
    }
    return {
      healthy,
      operationalState,
      writeCapable,
      queryOnlyPragma: isQueryOnly,
      writeProbeVerified: writeCapable,
      writeProbeError,
      probeLatencyMs,
      journalMode,
      foreignKeysEnabled: fkRow ? Boolean(Object.values(fkRow)[0]) : false,
      migrationStatus: instanceMigrationStatus,
      lastMigrationError: instanceMigrationError,
      appliedMigrationsCount: appliedMigrations.length,
      appliedMigrations
    };
  } catch (err) {
    const probeLatencyMs = Number((Number(process.hrtime.bigint() - probeStartNs) / 1e6).toFixed(3));
    return {
      healthy: false,
      operationalState: 'DATABASE_UNAVAILABLE',
      writeCapable: false,
      queryOnlyPragma: false,
      writeProbeVerified: false,
      writeProbeError: err && err.message ? err.message : String(err),
      probeLatencyMs,
      journalMode: 'error',
      foreignKeysEnabled: false,
      migrationStatus: 'ERROR',
      lastMigrationError: err && err.message ? err.message : String(err),
      appliedMigrationsCount: 0,
      appliedMigrations: []
    };
  }
}

initSchema(db);

module.exports = {
  db,
  initSchema,
  getDatabaseHealth
};
