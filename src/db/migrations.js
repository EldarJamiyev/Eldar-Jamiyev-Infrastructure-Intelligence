/**
 * EJII Pure NOC Database Migration Engine
 * Establishes and tracks schema for topology and packet dissection.
 */

const { db } = require('./database');

function runMigrations() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      applied_at TEXT NOT NULL
    );
  `);

  const appliedRows = db.prepare('SELECT version FROM schema_migrations ORDER BY version ASC').all();
  const applied = new Set(appliedRows.map(r => r.version));

  const migrations = [
    {
      version: 1,
      name: 'noc_pure_topology_and_capture_foundation',
      up: () => {
        // Already initialized in database.js initSchema
      }
    }
  ];

  let newlyApplied = 0;
  for (const m of migrations) {
    if (!applied.has(m.version)) {
      m.up();
      db.prepare('INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)').run(
        m.version,
        m.name,
        new Date().toISOString()
      );
      newlyApplied++;
    }
  }

  return { total: migrations.length, newlyApplied };
}

module.exports = {
  runMigrations
};
