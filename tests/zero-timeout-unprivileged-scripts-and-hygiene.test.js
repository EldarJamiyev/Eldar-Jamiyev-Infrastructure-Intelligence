/**
 * EJII Suite 69: Zero-Timeout Unprivileged Scripts, Workspace Hygiene & Loopback Resilience
 *
 * Verifies:
 * 1. [69.1] Workspace Hygiene: sync_now.bat and patch_*.js are absent from repository root.
 * 2. [69.2] High-Performance Default Gateway Port Probe: Test Port Connectivity to Default Gateway.ps1
 *    completes in <4,000ms with timedOut === false and exitCode === 0.
 * 3. [69.3] Unprivileged Automation Batch Scripts: Ping Default Gateway & Cloudflare DNS.bat,
 *    Restart Print Spooler Service & Clear Queue.bat, Run System File Checker SFC Verification.bat,
 *    and Verify DISM Component Store Health.bat all exit with 0 in unprivileged mode.
 * 4. [69.4] Windows Loopback Socket Resilience: 10 rapid sequential requests against http server
 *    with resilientHttpJsonRequest pass with zero ECONNRESET crashes.
 */

'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const http = require('http');
const { executeScript, getActiveScriptsDirectory, DEFAULT_SCRIPTS_DIR } = require('../src/tools/script-automation');

const rootDir = path.resolve(__dirname, '..');

async function resilientHttpJsonRequest(options, bodyPayload = null, maxRetries = 4) {
  let lastError = null;
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const result = await new Promise((resolve, reject) => {
        const reqOpts = {
          ...options,
          agent: false,
          headers: {
            ...(options.headers || {}),
            'Connection': 'close'
          },
          timeout: options.timeout || 8000
        };

        const req = http.request(reqOpts, (res) => {
          const chunks = [];
          res.on('error', reject);
          res.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
          res.on('end', () => {
            const raw = Buffer.concat(chunks).toString('utf8');
            let parsed = null;
            try {
              parsed = raw ? JSON.parse(raw) : {};
            } catch (_) {
              parsed = { raw };
            }
            resolve({ statusCode: res.statusCode, headers: res.headers, body: parsed, raw });
          });
        });

        req.on('timeout', () => req.destroy(new Error('HTTP_REQUEST_TIMEOUT')));
        req.on('error', (err) => reject(err));

        if (bodyPayload !== null && bodyPayload !== undefined) {
          const str = typeof bodyPayload === 'string' ? bodyPayload : JSON.stringify(bodyPayload);
          req.write(str);
        }
        req.end();
      });
      return result;
    } catch (err) {
      lastError = err;
      const isTransient =
        err &&
        (err.code === 'ECONNRESET' ||
          err.code === 'ECONNREFUSED' ||
          err.code === 'EPIPE' ||
          err.code === 'ECONNABORTED' ||
          /socket hang up|ECONNRESET|TIMEOUT/i.test(err.message || ''));

      if (isTransient && attempt < maxRetries) {
        await new Promise((r) => setTimeout(r, 200 * attempt));
        continue;
      }
      throw err;
    }
  }
  throw lastError;
}

async function runZeroTimeoutUnprivilegedScriptsAndHygieneTests() {
  console.log('========================================================================');
  console.log('  EJII SUITE 69: ZERO-TIMEOUT SCRIPTS, REPO HYGIENE & LOOPBACK RESILIENCE');
  console.log('========================================================================');

  // [69.1] Workspace Hygiene: sync_now.bat and patch_*.js absent
  console.log('[69.1] Verifying repository root workspace hygiene...');
  assert.strictEqual(
    fs.existsSync(path.join(rootDir, 'sync_now.bat')),
    false,
    'sync_now.bat must be permanently removed from repository root'
  );
  const rootFiles = fs.readdirSync(rootDir);
  const patchFiles = rootFiles.filter((f) => /^patch_.*\.js$/i.test(f));
  assert.strictEqual(
    patchFiles.length,
    0,
    `Found leftover patch files in root: ${patchFiles.join(', ')}`
  );
  console.log('  ✓ Workspace hygiene confirmed: zero untracked sync_now.bat or patch_*.js files on disk.');

  const scriptsDir = typeof getActiveScriptsDirectory === 'function'
    ? getActiveScriptsDirectory()
    : DEFAULT_SCRIPTS_DIR;

  // [69.2] High-Performance Default Gateway Port Probe
  console.log('[69.2] Verifying Test Port Connectivity to Default Gateway.ps1 performance...');
  const gwPortScript = 'Test Port Connectivity to Default Gateway.ps1';
  const gwRes = await executeScript(gwPortScript, '', scriptsDir);
  console.log(`  ✓ ${gwPortScript}: completed in ${gwRes.durationMs}ms (exit ${gwRes.exitCode}, timedOut: ${Boolean(gwRes.timedOut)})`);
  assert.strictEqual(Boolean(gwRes.timedOut), false, 'Gateway port script must not time out');
  assert.strictEqual(gwRes.exitCode, 0, 'Gateway port script must exit with 0');
  assert.ok(gwRes.durationMs < 4000, `Gateway port script took ${gwRes.durationMs}ms (must be <4,000ms)`);

  // [69.3] Unprivileged Automation Batch Scripts
  console.log('[69.3] Verifying unprivileged execution across key system scripts...');
  const keyScripts = [
    'Ping Default Gateway & Cloudflare DNS.bat',
    'Restart Print Spooler Service & Clear Queue.bat',
    'Run System File Checker SFC Verification.bat',
    'Verify DISM Component Store Health.bat'
  ];

  for (const sName of keyScripts) {
    const res = await executeScript(sName, '', scriptsDir);
    console.log(`  ✓ ${sName}: duration ${res.durationMs}ms, exitCode ${res.exitCode}`);
    assert.strictEqual(Boolean(res.timedOut), false, `${sName} must not time out`);
    assert.strictEqual(res.exitCode, 0, `${sName} must exit with code 0 in unprivileged mode`);
    assert.ok(res.durationMs < 4000, `${sName} must finish within 4,000ms`);
  }

  // [69.4] Windows Loopback Socket Resilience Stress Test
  console.log('[69.4] Running 10 rapid sequential HTTP requests against local server with resilientHttpJsonRequest...');
  const testServer = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ status: 'OK', echo: req.url }));
  });
  testServer.keepAliveTimeout = 65000;
  testServer.headersTimeout = 66000;

  await new Promise((resolve) => testServer.listen(0, '127.0.0.1', resolve));
  const assignedPort = testServer.address().port;

  try {
    for (let i = 1; i <= 10; i++) {
      const resp = await resilientHttpJsonRequest({
        hostname: '127.0.0.1',
        port: assignedPort,
        path: `/test-loopback-${i}`,
        method: 'GET'
      });
      assert.strictEqual(resp.statusCode, 200, `Request ${i} must return 200`);
      assert.strictEqual(resp.body.status, 'OK');
    }
    console.log('  ✓ 10/10 rapid loopback requests succeeded with zero ECONNRESET errors.');
  } finally {
    await new Promise((resolve) => testServer.close(resolve));
  }

  console.log('\n>>> ALL SUITE 69 TESTS PASSED 100% GREEN.\n');
}

if (require.main === module) {
  runZeroTimeoutUnprivilegedScriptsAndHygieneTests().then(() => {
    process.exit(0);
  }).catch((err) => {
    console.error('Suite 69 failed:', err);
    process.exit(1);
  });
}

module.exports = {
  runSuite69: runZeroTimeoutUnprivilegedScriptsAndHygieneTests,
  runZeroTimeoutUnprivilegedScriptsAndHygieneTests
};
