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
    path.join(ROOT_DIR, 'src'),
    path.join(ROOT_DIR, 'tests')
  ];
  const ignoredDirs = new Set(['node_modules', '.git', 'dist', 'build', '.agents']);
  const discovered = new Set();

  function walk(dir) {
    if (!fs.existsSync(dir)) return;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (ignoredDirs.has(entry.name)) continue;
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile() && entry.name.endsWith('.test.js')) {
        discovered.add(fullPath);
      }
    }
  }

  for (const dir of searchDirs) {
    walk(dir);
  }
  return Array.from(discovered).sort();
}

function parseTapSummary(output) {
  const text = String(output || '');
  const testsMatch = text.match(/^(?:# |ℹ )tests\s+(\d+)/m);
  const passMatch = text.match(/^(?:# |ℹ )pass\s+(\d+)/m);
  const failMatch = text.match(/^(?:# |ℹ )fail\s+(\d+)/m);
  const hasSummary = Boolean(testsMatch && passMatch && failMatch);
  return {
    hasSummary,
    tests: testsMatch ? Number(testsMatch[1]) : 0,
    pass: passMatch ? Number(passMatch[1]) : 0,
    fail: failMatch ? Number(failMatch[1]) : 0
  };
}

function cleanupIsolatedDir(dirPath) {
  if (!dirPath) return;
  try {
    fs.rmSync(dirPath, { recursive: true, force: true });
  } catch (_) {}
}

function runSuiteChildProcess(file, extraEnv = {}) {
  const suiteTmpDir = fs.mkdtempSync(
    path.join(os.tmpdir(), `ejii-suite-${process.pid}-${Date.now()}-`)
  );
  const tmpDbPath = path.join(suiteTmpDir, 'ejii-test.sqlite');

  let res;
  try {
    res = spawnSync(process.execPath, ['--test', file], {
      cwd: ROOT_DIR,
      env: {
        ...process.env,
        NODE_ENV: 'test',
        EJII_DATA_DIR: suiteTmpDir,
        EJII_DB_PATH: tmpDbPath,
        DB_PATH: tmpDbPath,
        EJII_REQUIRE_EXPLICIT_TEST_ISOLATION: 'true',
        ...extraEnv
      },
      encoding: 'utf8',
      maxBuffer: 20 * 1024 * 1024
    });
  } finally {
    cleanupIsolatedDir(suiteTmpDir);
  }

  const combinedOutput = `${res.stdout || ''}\n${res.stderr || ''}`;
  const summary = parseTapSummary(combinedOutput);
  const hasProcessFailure =
    Boolean(res.error) ||
    Boolean(res.signal) ||
    res.status !== 0 ||
    !summary.hasSummary ||
    summary.tests <= 0 ||
    summary.fail > 0;

  return {
    status: res.status,
    signal: res.signal || null,
    error: res.error || null,
    stdout: res.stdout || '',
    stderr: res.stderr || '',
    combinedOutput,
    summary,
    passed: !hasProcessFailure,
    suiteTests: summary.hasSummary ? summary.tests : 0,
    suitePass: summary.hasSummary ? summary.pass : 0,
    suiteFail: summary.hasSummary && summary.tests > 0
      ? summary.fail + (res.status !== 0 && summary.fail === 0 ? 1 : 0)
      : 1
  };
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
    const outcome = runSuiteChildProcess(file);
    const suiteDurationMs = Date.now() - suiteStart;

    totalTests += outcome.suiteTests;
    totalPass += outcome.suitePass;
    totalFail += outcome.suiteFail;

    if (outcome.passed) {
      console.log(`  [PASS] ${relPath} (${outcome.suitePass}/${outcome.suiteTests} passed in ${suiteDurationMs}ms)`);
    } else {
      failedSuites++;
      const failureReason = outcome.error
        ? `spawn error: ${outcome.error.message}`
        : outcome.signal
          ? `terminated by signal ${outcome.signal}`
          : !outcome.summary.hasSummary || outcome.suiteTests === 0
            ? 'missing TAP summary or 0 tests executed'
            : `exit status ${outcome.status}`;
      console.error(
        `  [FAIL] ${relPath} (${outcome.suitePass} passed, ${outcome.suiteFail} failed in ${suiteDurationMs}ms — ${failureReason})`
      );
      console.error(outcome.combinedOutput);
    }
  }

  const totalDurationMs = Date.now() - startedAt;
  console.log('========================================================================');
  console.log(
    `  Summary: ${testFiles.length - failedSuites}/${testFiles.length} suites passed | ` +
    `${totalPass}/${totalTests} tests passed | ${totalFail} failed | ${totalDurationMs}ms`
  );
  console.log('========================================================================');

  if (failedSuites > 0 || totalFail > 0 || totalTests === 0) {
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  discoverTestFiles,
  parseTapSummary,
  runSuiteChildProcess
};
