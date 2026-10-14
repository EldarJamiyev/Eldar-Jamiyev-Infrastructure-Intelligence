/**
 * EJII Database Module using Node.js Native SQLite (node:sqlite)
 * Zero external compilation dependencies, high-performance WAL mode.
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

// Enable WAL mode for high concurrency
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');

/**
 * Initialize all database tables and schema
 */
function initSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      full_name TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('helpdesk', 'network_admin', 'sysadmin', 'app_owner')),
      is_active INTEGER DEFAULT 1,
      created_at TEXT NOT NULL,
      last_login TEXT
    );

    CREATE TABLE IF NOT EXISTS nodes (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      hostname_or_ip TEXT NOT NULL,
      type TEXT NOT NULL,
      parent_id TEXT,
      snmp_community TEXT DEFAULT 'public',
      snmp_version TEXT DEFAULT '2c',
      check_interval_sec INTEGER DEFAULT 30,
      status TEXT DEFAULT 'unknown',
      last_checked TEXT,
      last_latency_ms REAL,
      metadata TEXT,
      FOREIGN KEY(parent_id) REFERENCES nodes(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS telemetry_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      node_id TEXT NOT NULL,
      metric_type TEXT NOT NULL,
      metric_name TEXT NOT NULL,
      value REAL,
      unit TEXT,
      status TEXT,
      raw_payload TEXT,
      timestamp TEXT NOT NULL,
      FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_telemetry_node_time ON telemetry_history(node_id, timestamp);
    CREATE INDEX IF NOT EXISTS idx_telemetry_type ON telemetry_history(metric_type);

    CREATE TABLE IF NOT EXISTS incidents (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'investigating', 'resolved')),
      severity TEXT NOT NULL CHECK(severity IN ('P1_CRITICAL', 'P2_HIGH', 'P3_MEDIUM', 'P4_LOW')),
      primary_node_id TEXT NOT NULL,
      what_happened TEXT NOT NULL,
      root_cause TEXT NOT NULL,
      supporting_evidence TEXT NOT NULL,
      remediation_plan TEXT NOT NULL,
      suppressed_count INTEGER DEFAULT 0,
      detected_at TEXT NOT NULL,
      resolved_at TEXT,
      resolved_by TEXT,
      FOREIGN KEY(primary_node_id) REFERENCES nodes(id)
    );

    CREATE TABLE IF NOT EXISTS automation_actions (
      id TEXT PRIMARY KEY,
      action_type TEXT NOT NULL,
      tier INTEGER NOT NULL,
      target_host TEXT NOT NULL,
      target_resource TEXT NOT NULL,
      parameters TEXT,
      requested_by_id TEXT NOT NULL,
      requested_by_role TEXT NOT NULL,
      approval_status TEXT NOT NULL DEFAULT 'not_required' CHECK(approval_status IN ('not_required', 'pending_approval', 'approved', 'rejected')),
      approved_by_id TEXT,
      approval_comment TEXT,
      execution_status TEXT NOT NULL DEFAULT 'queued' CHECK(execution_status IN ('queued', 'running', 'success', 'failed', 'cancelled')),
      execution_output TEXT,
      execution_error TEXT,
      dry_run INTEGER DEFAULT 0,
      requested_at TEXT NOT NULL,
      executed_at TEXT,
      FOREIGN KEY(requested_by_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL,
      user_id TEXT,
      username TEXT,
      role TEXT,
      action TEXT NOT NULL,
      resource TEXT NOT NULL,
      details TEXT,
      ip_address TEXT,
      prev_hash TEXT NOT NULL,
      hash TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(timestamp);

    CREATE TABLE IF NOT EXISTS system_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
  `);
}

initSchema();

module.exports = {
  db,
  initSchema
};
