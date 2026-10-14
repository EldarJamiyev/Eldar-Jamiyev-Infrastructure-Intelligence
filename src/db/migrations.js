/**
 * EJI Database Migration Engine
 * Safely executes forward-compatible, versioned migrations on SQLite authoritative store.
 */

const { db } = require('./database');

function getAppliedMigrations() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      applied_at TEXT NOT NULL
    );
  `);
  const rows = db.prepare('SELECT version FROM schema_migrations ORDER BY version ASC').all();
  return new Set(rows.map(r => r.version));
}

function hasColumn(tableName, columnName) {
  try {
    const columns = db.prepare(`PRAGMA table_info(${tableName})`).all();
    return columns.some(c => c.name === columnName);
  } catch (err) {
    return false;
  }
}

const MIGRATIONS = [
  {
    version: 1,
    name: 'create_revoked_tokens_and_integrations',
    up: () => {
      db.exec(`
        CREATE TABLE IF NOT EXISTS revoked_tokens (
          token_hash TEXT PRIMARY KEY,
          user_id TEXT NOT NULL,
          revoked_at TEXT NOT NULL,
          expires_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_revoked_tokens_exp ON revoked_tokens(expires_at);

        CREATE TABLE IF NOT EXISTS integrations (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          type TEXT NOT NULL CHECK(type IN ('snmp', 'ssh', 'wmi', 'webhook', 'syslog', 'prometheus')),
          endpoint TEXT NOT NULL,
          config_json TEXT,
          status TEXT DEFAULT 'configured' CHECK(status IN ('configured', 'connected', 'failed', 'disabled')),
          last_sync TEXT,
          last_error TEXT,
          enabled INTEGER DEFAULT 1,
          created_at TEXT NOT NULL
        );
      `);
    }
  },
  {
    version: 2,
    name: 'expand_nodes_asset_inventory',
    up: () => {
      const assetColumns = [
        { name: 'mac_address', def: 'TEXT' },
        { name: 'vendor', def: 'TEXT' },
        { name: 'os_name', def: 'TEXT' },
        { name: 'os_version', def: 'TEXT' },
        { name: 'model', def: 'TEXT' },
        { name: 'serial_number', def: 'TEXT' },
        { name: 'location', def: 'TEXT' },
        { name: 'assigned_to', def: 'TEXT' },
        { name: 'discovery_source', def: "TEXT DEFAULT 'manual'" },
        { name: 'is_managed', def: 'INTEGER DEFAULT 1' },
        { name: 'tags', def: 'TEXT' }
      ];

      for (const col of assetColumns) {
        if (!hasColumn('nodes', col.name)) {
          db.exec(`ALTER TABLE nodes ADD COLUMN ${col.name} ${col.def};`);
        }
      }
    }
  },
  {
    version: 3,
    name: 'expand_incidents_and_automation_links',
    up: () => {
      const incidentColumns = [
        { name: 'assigned_role', def: 'TEXT' },
        { name: 'assigned_to_user_id', def: 'TEXT' },
        { name: 'operator_notes', def: 'TEXT' },
        { name: 'probe_evidence_json', def: 'TEXT' }
      ];

      for (const col of incidentColumns) {
        if (!hasColumn('incidents', col.name)) {
          db.exec(`ALTER TABLE incidents ADD COLUMN ${col.name} ${col.def};`);
        }
      }

      if (!hasColumn('automation_actions', 'incident_id')) {
        db.exec('ALTER TABLE automation_actions ADD COLUMN incident_id TEXT;');
      }
    }
  },
  {
    version: 4,
    name: 'seed_baseline_integrations_and_settings',
    up: () => {
      const existingSettings = db.prepare('SELECT COUNT(*) as count FROM system_settings').get();
      if (existingSettings.count === 0) {
        const insertSetting = db.prepare('INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES (?, ?, ?)');
        const now = new Date().toISOString();
        insertSetting.run('platform_name', 'EJI — Eldar Jamiyev’s Infrastructure Intelligence', now);
        insertSetting.run('polling_interval_sec', '30', now);
        insertSetting.run('stale_threshold_multiplier', '2', now);
        insertSetting.run('security_login_max_attempts', '5', now);
        insertSetting.run('security_login_lockout_min', '15', now);
      }
    }
  }
];

function runMigrations() {
  const applied = getAppliedMigrations();
  let newlyApplied = 0;

  for (const m of MIGRATIONS) {
    if (!applied.has(m.version)) {
      console.log(`[Migration] Applying Migration v${m.version}: ${m.name}...`);
      m.up();
      db.prepare('INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)').run(
        m.version,
        m.name,
        new Date().toISOString()
      );
      newlyApplied++;
      console.log(`✓ [Migration] v${m.version} applied successfully.`);
    }
  }

  return { total: MIGRATIONS.length, newlyApplied };
}

module.exports = {
  runMigrations,
  getAppliedMigrations
};
