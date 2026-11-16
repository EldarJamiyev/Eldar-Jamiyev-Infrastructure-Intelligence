#!/usr/bin/env node
/**
 * EJII Authoritative Test Runner (`npm test` -> `node tests/run-all-tests.js`)
 *
 * Discovers and executes all first-party test suites in `src/core/__tests__/` and `tests/`
 * with isolated per-suite SQLite database instances so concurrent dev servers or sibling
 * test suites never contaminate stateful rollback or lineage assertions.
 *
 * Reports exact per-suite and aggregate test counts, duration, and exits non-zero on any failure.
 */

'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT_DIR = path.resolve(__dirname, '..');

function discoverTestFiles() {
  const searchDirs = [
    path.join(ROOT_DIR, 'src', 'core', '__tests__'),
    path.join(ROOT_DIR, 'tests')
  ];
  const files = [];
  for (const dir of searchDirs) {
    if (!fs.existsSync(dir)) continue;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.isFile() && entry.name.endsWith('.test.js')) {
        files.push(path.join(dir, entry.name));
      }
    }
  }
  return files.sort();
}

function parseTapSummary(output) {
  const testsMatch = output.match(/# tests\s+(\d+)/);
  const passMatch = output.match(/# pass\s+(\d+)/);
  const failMatch = output.match(/# fail\s+(\d+)/);
  return {
    tests: testsMatch ? Number(testsMatch[1]) : 0,
    pass: passMatch ? Number(passMatch[1]) : 0,
    fail: failMatch ? Number(failMatch[1]) : 0
  };
}

function cleanupDbFiles(dbPath) {
  for (const suffix of ['', '-wal', '-shm']) {
    try {
      const target = `${dbPath}${suffix}`;
      if (fs.existsSync(target)) fs.unlinkSync(target);
    } catch (_) {}
  }
}

function main() {
  const startedAt = Date.now();
  const filterArg = process.argv.slice(2).find((a) => !a.startsWith('-')) || '';
  let testFiles = discoverTestFiles();
  if (filterArg) {
    testFiles = testFiles.filter((f) => f.includes(filterArg));
  }

  if (testFiles.length === 0) {
    console.error('[EJII Test Runner] No test files matched.');
    process.exit(1);
  }

  console.log('========================================================================');
  console.log(`  EJII Sovereign Infrastructure Intelligence — Test Runner (${testFiles.length} suites)`);
  console.log('========================================================================');

  let totalTests = 0;
  let totalPass = 0;
  let totalFail = 0;
  let failedSuites = 0;

  for (const file of testFiles) {
    const relPath = path.relative(ROOT_DIR, file);
    const suiteStart = Date.now();
    const tmpDbPath = path.join(
      os.tmpdir(),
      `ejii-test-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.db`
    );

    const res = spawnSync(process.execPath, ['--test', file], {
      cwd: ROOT_DIR,
      env: {
        ...process.env,
        NODE_ENV: 'test',
        DB_PATH: tmpDbPath
      },
      encoding: 'utf8',
      maxBuffer: 20 * 1024 * 1024
    });

    cleanupDbFiles(tmpDbPath);

    const combinedOutput = `${res.stdout || ''}\n${res.stderr || ''}`;
    const summary = parseTapSummary(combinedOutput);
    const suiteDurationMs = Date.now() - suiteStart;

    const suiteTests = summary.tests || (res.status === 0 ? 1 : 1);
    const suitePass = summary.tests ? summary.pass : (res.status === 0 ? 1 : 0);
    const suiteFail = summary.tests ? summary.fail : (res.status === 0 ? 0 : 1);

    totalTests += suiteTests;
    totalPass += suitePass;
    totalFail += suiteFail;

    if (res.status === 0 && suiteFail === 0) {
      console.log(`  [PASS] ${relPath} (${suitePass}/${suiteTests} passed in ${suiteDurationMs}ms)`);
    } else {
      failedSuites++;
      console.error(`  [FAIL] ${relPath} (${suitePass} passed, ${suiteFail} failed in ${suiteDurationMs}ms)`);
      console.error(combinedOutput);
    }
  }

  const totalDurationMs = Date.now() - startedAt;
  console.log('========================================================================');
  console.log(
    `  Summary: ${testFiles.length - failedSuites}/${testFiles.length} suites passed | ` +
    `${totalPass}/${totalTests} tests passed | ${totalFail} failed | ${totalDurationMs}ms`
  );
  console.log('========================================================================');

  if (failedSuites > 0 || totalFail > 0) {
    process.exit(1);
  }
}

main();
