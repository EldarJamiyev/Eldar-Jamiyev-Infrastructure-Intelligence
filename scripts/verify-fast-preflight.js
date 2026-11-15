#!/usr/bin/env node
/**
 * EJII High-Speed Instant Launch Pre-Flight Verification (< 150ms)
 * Validates runtime readiness, SQLite WAL database integrity, and core dependencies
 * for instant 1-click launch experience like modern international desktop apps.
 */

'use strict';

const fs = require('fs');
const path = require('path');

const startTime = process.hrtime.bigint();

// 1. Check Node.js version >= 18
const [major] = process.versions.node.split('.').map(Number);
if (major < 18) {
  console.error(`[Preflight ERROR] Node.js version ${process.version} is unsupported. EJII requires Node.js v18 or newer.`);
  process.exit(1);
}

// 2. Check essential project paths
const ROOT_DIR = path.resolve(__dirname, '..');
const requiredPaths = [
  path.join(ROOT_DIR, 'src', 'server.js'),
  path.join(ROOT_DIR, 'src', 'db', 'database.js'),
  path.join(ROOT_DIR, 'public', 'index.html'),
  path.join(ROOT_DIR, 'node_modules')
];

for (const p of requiredPaths) {
  if (!fs.existsSync(p)) {
    console.error(`[Preflight ERROR] Missing essential path: ${p}`);
    process.exit(1);
  }
}

// 3. Verify SQLite WAL database connectivity
try {
  const { db } = require('../src/db/database');
  const res = db.prepare('SELECT 1 AS ready').get();
  if (!res || res.ready !== 1) {
    throw new Error('Database read health check failed');
  }
} catch (dbErr) {
  console.error(`[Preflight ERROR] SQLite database check failed: ${dbErr.message}`);
  process.exit(1);
}

const elapsedMs = Number(process.hrtime.bigint() - startTime) / 1e6;
console.log(`[Fast Preflight] [OK] Ready for instant launch in ${elapsedMs.toFixed(2)} ms.`);
process.exit(0);
