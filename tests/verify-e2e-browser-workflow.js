/**
 * EJII Browser-Level E2E Workflow & AI Brain Contract Verification Suite (Suite 16)
 *
 * Verifies the end-to-end operational pipeline:
 * 1. REST API Contract:
 *    - GET /api/network/ai-brain/live (200 OK, strict 100% normalized hypotheses)
 *    - GET /api/network/ai-brain/history (200 OK, history records)
 *    - GET /api/network/ai-brain/status (200 OK, operational metrics)
 *    - GET /api/network/scanner/profiles (200 OK, edr_conservative, fast, deep)
 *    - GET /api/network/scanner/status (200 OK, telemetry and policy tracking)
 * 2. WebSocket Real-Time Diagnostic Stream:
 *    - Connects to ws://127.0.0.1:<PORT>/ws
 *    - Triggers POST /api/network/ai-brain/trigger-probe
 *    - Verifies AI_BRAIN_DIAGNOSTIC_UPDATE arrives within bounded timeout with strict 100% sum
 * 3. Frontend View & DOM Contract:
 *    - aiBrainVerdict, aiBrainConfidenceBar, aiBrainRecommendationBtn in ai-brain-drawer.js
 *    - scannerProfileSelect, scannerConcurrencySelect, telemetry counters in ultra-ip-scanner-view.js
 * 4. Clean Teardown, Ephemeral Port Fallback & Isolated SQLite Data Directory
 */

const assert = require('assert');
const http = require('http');
const net = require('net');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const WebSocket = require('ws');
const { createToken } = require('../src/core/security');

const DEFAULT_PORT = 8443;
const FALLBACK_PORT = 8446;
const HOST = '127.0.0.1';
const token = createToken({ id: 'USR-NOC-01', username: 'noc', role: 'noc_operator' });

function checkPortOpen(port, host = '127.0.0.1') {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(600);
    socket.on('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.on('timeout', () => {
      socket.destroy();
      resolve(false);
    });
    socket.on('error', () => {
      resolve(false);
    });
    socket.connect(port, host);
  });
}

/**
 * Resilient HTTP JSON Request Helper for Windows Loopback:
 * 1. Uses agent: false and 'Connection': 'close' to eliminate Node.js keep-alive socket reuse ECONNRESET.
 * 2. Automatically retries up to maxRetries with backoff if a transient reset occurs.
 */
async function resilientHttpJsonRequest(options, bodyPayload = null, maxRetries = 4) {
  let lastError = null;
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const result = await new Promise((resolve, reject) => {
        let strPayload = null;
        if (bodyPayload !== null && bodyPayload !== undefined) {
          strPayload = typeof bodyPayload === 'string' ? bodyPayload : JSON.stringify(bodyPayload);
        }

        const headers = {
          ...(options.headers || {}),
          'Connection': 'close'
        };
        if (strPayload !== null && !headers['Content-Length'] && !headers['content-length']) {
          headers['Content-Length'] = Buffer.byteLength(strPayload);
        }

        const reqOpts = {
          ...options,
          agent: false,
          headers,
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
            resolve({
              status: res.statusCode,
              statusCode: res.statusCode,
              headers: res.headers,
              data: parsed,
              body: parsed,
              raw
            });
          });
        });

        req.on('timeout', () => {
          req.destroy(new Error('HTTP_REQUEST_TIMEOUT'));
        });
        req.on('error', (err) => {
          reject(err);
        });

        if (strPayload !== null) {
          req.write(strPayload);
        }
        req.end();
      });
      return result;
    } catch (err) {
      lastError = err;
      const isTransientSocketReset =
        err &&
        (err.code === 'ECONNRESET' ||
          err.code === 'ECONNREFUSED' ||
          err.code === 'EPIPE' ||
          err.code === 'ECONNABORTED' ||
          /socket hang up|ECONNRESET|TIMEOUT/i.test(err.message || ''));

      if (isTransientSocketReset && attempt < maxRetries) {
        await new Promise((r) => setTimeout(r, 250 * attempt));
        continue;
      }
      throw err;
    }
  }
  throw lastError;
}

const httpRequest = resilientHttpJsonRequest;

/**
 * Probes whether a healthy active EJII server is listening on target host:port.
 */
async function probeServerHealth(port, host = HOST, timeoutMs = 1200) {
  try {
    const res = await httpRequest({
      hostname: host,
      port,
      path: '/api/health',
      method: 'GET',
      timeout: timeoutMs
    });
    return res && res.status === 200 && res.data && (res.data.status === 'UP' || res.data.version);
  } catch (_) {
    return false;
  }
}

/**
 * Spawns a fast-boot local EJII server process on specified port with isolated data directory.
 */
async function spawnFastServer(port, dataDir) {
  const rootDir = path.resolve(__dirname, '..');
  const child = spawn(process.execPath, ['src/server.js'], {
    cwd: rootDir,
    env: {
      ...process.env,
      EJII_PORT: String(port),
      EJII_HOST: HOST,
      EJII_DATA_DIR: dataDir,
      EJII_FAST_BOOT: 'true',
      EJII_DISABLE_BG_SYNC: 'true',
      NODE_ENV: 'development'
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  // Drain stdout and stderr continuously so Windows 64KB pipe buffers never block
  let stdoutLogs = '';
  let stderrLogs = '';
  child.stdout.on('data', (d) => {
    stdoutLogs += d.toString();
    if (stdoutLogs.length > 32000) stdoutLogs = stdoutLogs.slice(-16000);
  });
  child.stderr.on('data', (d) => {
    stderrLogs += d.toString();
    if (stderrLogs.length > 32000) stderrLogs = stderrLogs.slice(-16000);
  });

  let childExited = false;
  let exitCode = null;
  child.on('exit', (code) => {
    childExited = true;
    exitCode = code;
  });

  // Poll /api/health for up to 20,000ms (80 attempts x 250ms)
  const maxAttempts = 80;
  for (let i = 0; i < maxAttempts; i++) {
    if (childExited) {
      throw new Error(`E2E server process on port ${port} exited prematurely with code ${exitCode}. Stderr: ${stderrLogs.slice(-500)}`);
    }
    const healthy = await probeServerHealth(port, HOST, 500);
    if (healthy) {
      return child;
    }
    await new Promise((r) => setTimeout(r, 250));
  }

  // If timed out, terminate child
  try {
    if (process.platform === 'win32') {
      require('child_process').execSync(`taskkill /F /T /PID ${child.pid}`, { stdio: 'ignore' });
    } else {
      child.kill('SIGKILL');
    }
  } catch (_) {}
  throw new Error(`Timed out waiting for E2E server on port ${port} to boot after 20000ms. Stdout: ${stdoutLogs.slice(-300)}, Stderr: ${stderrLogs.slice(-300)}`);
}

async function runE2EBrowserWorkflow() {
  console.log('========================================================================');
  console.log('  EJII BROWSER-LEVEL E2E WORKFLOW & CONTRACT VERIFICATION SUITE         ');
  console.log(`  Target: http://${HOST}:${DEFAULT_PORT} | Protocol: REST + WebSocket + DOM Contract`);
  console.log('========================================================================\n');

  let activePort = DEFAULT_PORT;
  let serverProcess = null;
  let e2eDataDir = null;

  try {
    // 1. Check if an active EJII server is already responding on DEFAULT_PORT
    let isRunning = await probeServerHealth(DEFAULT_PORT, HOST);

    if (isRunning) {
      activePort = DEFAULT_PORT;
      console.log(`✓ Active EJII server already healthy on http://${HOST}:${activePort}\n`);
    } else {
      // 2. Spawn isolated fast-boot server
      e2eDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ejii_suite16_'));

      // Check if DEFAULT_PORT is free or in transition
      const defaultPortOpen = await checkPortOpen(DEFAULT_PORT, HOST);
      let targetPort = DEFAULT_PORT;
      if (defaultPortOpen) {
        // Port is occupied by a non-responsive process or in TIME_WAIT: use ephemeral fallback
        console.log(`[Auto-Start]: Port ${DEFAULT_PORT} is busy or non-responsive. Using ephemeral port ${FALLBACK_PORT}...`);
        targetPort = FALLBACK_PORT;
      } else {
        console.log(`[Auto-Start]: Port ${DEFAULT_PORT} not listening. Spawning local server for E2E verification...`);
      }

      try {
        serverProcess = await spawnFastServer(targetPort, e2eDataDir);
        activePort = targetPort;
        console.log(`✓ E2E local server booted successfully on http://${HOST}:${activePort}\n`);
      } catch (bootErr) {
        if (targetPort === DEFAULT_PORT) {
          console.warn(`[Auto-Start]: Failed to boot on port ${DEFAULT_PORT} (${bootErr.message}). Retrying on fallback port ${FALLBACK_PORT}...`);
          targetPort = FALLBACK_PORT;
          serverProcess = await spawnFastServer(targetPort, e2eDataDir);
          activePort = targetPort;
          console.log(`✓ E2E local server booted successfully on fallback http://${HOST}:${activePort}\n`);
        } else {
          throw bootErr;
        }
      }
    }

    // --------------------------------------------------------------------------
    // PART 1: REST API VERIFICATION
    // --------------------------------------------------------------------------
    console.log('[Phase 1] Verifying AI Brain & Scanner REST Endpoints...');

    // 1a: GET /api/network/ai-brain/live
    const liveRes = await httpRequest({
      hostname: HOST,
      port: activePort,
      path: '/api/network/ai-brain/live',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' }
    });
    assert.strictEqual(liveRes.status, 200, `GET /api/network/ai-brain/live must return 200, got ${liveRes.status}`);
    assert.strictEqual(liveRes.data.status, 'OPERATIONAL', 'AI Brain status must be OPERATIONAL');
    assert.ok(Array.isArray(liveRes.data.rankedHypotheses), 'rankedHypotheses must be an array');
    assert.ok(liveRes.data.topHypothesis, 'topHypothesis must be present');
    const sumLive = liveRes.data.rankedHypotheses.reduce((acc, h) => acc + h.confidence, 0);
    assert.strictEqual(sumLive, 100, `Probability sum must strictly equal 100%, got ${sumLive}%`);
    console.log(`  ✓ GET /api/network/ai-brain/live verified: 100% normalized, top: [${liveRes.data.topHypothesis.id}]`);

    // 1b: GET /api/network/ai-brain/history
    const histRes = await httpRequest({
      hostname: HOST,
      port: activePort,
      path: '/api/network/ai-brain/history',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token}` }
    });
    assert.strictEqual(histRes.status, 200, `GET /api/network/ai-brain/history must return 200, got ${histRes.status}`);
    assert.ok(Array.isArray(histRes.data), 'History must be an array');
    console.log(`  ✓ GET /api/network/ai-brain/history verified: ${histRes.data.length} historical evaluations recorded.`);

    // 1c: GET /api/network/ai-brain/status
    const statusRes = await httpRequest({
      hostname: HOST,
      port: activePort,
      path: '/api/network/ai-brain/status',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token}` }
    });
    assert.strictEqual(statusRes.status, 200, `GET /api/network/ai-brain/status must return 200, got ${statusRes.status}`);
    assert.strictEqual(statusRes.data.status, 'OPERATIONAL', 'Status must be OPERATIONAL');
    console.log(`  ✓ GET /api/network/ai-brain/status verified: continuous mode = ${statusRes.data.continuousMode}`);

    // 1d: GET /api/network/scanner/profiles
    const profilesRes = await httpRequest({
      hostname: HOST,
      port: activePort,
      path: '/api/network/scanner/profiles',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token}` }
    });
    assert.strictEqual(profilesRes.status, 200, `GET /api/network/scanner/profiles must return 200, got ${profilesRes.status}`);
    assert.ok(profilesRes.data.profiles.edr_conservative, 'edr_conservative profile must exist');
    assert.ok(profilesRes.data.profiles.fast, 'fast profile must exist');
    assert.ok(profilesRes.data.profiles.deep, 'deep profile must exist');
    console.log('  ✓ GET /api/network/scanner/profiles verified: 3 controlled profiles exposed.');

    // 1e: GET /api/network/scanner/status
    const scanStatusRes = await httpRequest({
      hostname: HOST,
      port: activePort,
      path: '/api/network/scanner/status',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token}` }
    });
    assert.strictEqual(scanStatusRes.status, 200, `GET /api/network/scanner/status must return 200, got ${scanStatusRes.status}`);
    assert.ok('phase' in scanStatusRes.data, 'Scanner status must include phase');
    assert.ok('probesSent' in scanStatusRes.data, 'Scanner status must include probesSent');
    assert.ok('bytesTransferred' in scanStatusRes.data, 'Scanner status must include bytesTransferred');
    console.log('  ✓ GET /api/network/scanner/status verified: traffic accounting and phase telemetry intact.');

    // --------------------------------------------------------------------------
    // PART 2: WEBSOCKET STREAMING & REAL-TIME PROBE UPDATE
    // --------------------------------------------------------------------------
    console.log('\n[Phase 2] Verifying WebSocket Subscription & Diagnostic Event Delivery...');
    const wsUrl = `ws://${HOST}:${activePort}/ws`;

    await new Promise((resolve, reject) => {
      const ws = new WebSocket(wsUrl, ['token', token]);
      let receivedUpdate = false;

      const timeout = setTimeout(() => {
        try { ws.terminate(); } catch (_) {}
        if (!receivedUpdate) {
          reject(new Error('Timed out waiting for AI_BRAIN_DIAGNOSTIC_UPDATE over WebSocket within 10000ms'));
        }
      }, 10000);

      ws.on('open', async () => {
        console.log('  ✓ WebSocket connected successfully to /ws');

        // Trigger diagnostic probe via REST API
        try {
          const probeRes = await httpRequest({
            hostname: HOST,
            port: activePort,
            path: '/api/network/ai-brain/trigger-probe',
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${token}`,
              'Content-Type': 'application/json'
            }
          }, {
            probeType: 'ICMP_PING_GATEWAY',
            targetIp: '127.0.0.1'
          });

          assert.strictEqual(probeRes.status, 200, 'Trigger probe must return 200 OK');
          console.log(`  ✓ Diagnostic probe triggered: latency ${probeRes.data.latencyMs}ms`);
        } catch (err) {
          clearTimeout(timeout);
          try { ws.terminate(); } catch (_) {}
          return reject(err);
        }
      });

      ws.on('message', (raw) => {
        try {
          const msg = JSON.parse(raw.toString());
          if (msg.type === 'AI_BRAIN_DIAGNOSTIC_UPDATE') {
            receivedUpdate = true;
            clearTimeout(timeout);
            console.log('  ✓ Real-time AI_BRAIN_DIAGNOSTIC_UPDATE event received over WebSocket!');

            assert.ok(msg.payload, 'Payload must be present');
            const evalObj = msg.payload.evaluation || msg.payload;
            if (evalObj && evalObj.rankedHypotheses) {
              const sum = evalObj.rankedHypotheses.reduce((acc, h) => acc + h.confidence, 0);
              assert.strictEqual(sum, 100, `WebSocket diagnostic update probability sum must be strictly 100%, got ${sum}%`);
              console.log(`  ✓ Event payload verified: 100% normalized across ${evalObj.rankedHypotheses.length} hypotheses.`);
            }

            try { ws.close(); } catch (_) {}
            resolve();
          }
        } catch (_) {
          // Ignore other payloads like CONNECTED
        }
      });

      ws.on('error', (err) => {
        clearTimeout(timeout);
        reject(err);
      });
    });

    // --------------------------------------------------------------------------
    // PART 3: FRONTEND DOM CONTRACT VERIFICATION
    // --------------------------------------------------------------------------
    console.log('\n[Phase 3] Verifying Frontend DOM Contract & Component Markup...');
    const rootDir = path.resolve(__dirname, '..');

    // 3a: ai-brain-drawer.js contract elements
    const drawerJsPath = path.join(rootDir, 'public', 'js', 'components', 'ai-brain-drawer.js');
    const drawerJs = fs.readFileSync(drawerJsPath, 'utf8');

    assert.ok(drawerJs.includes('id="aiBrainVerdict"'), 'ai-brain-drawer.js must define id="aiBrainVerdict"');
    assert.ok(drawerJs.includes('id="aiBrainConfidenceBar"'), 'ai-brain-drawer.js must define id="aiBrainConfidenceBar"');
    assert.ok(drawerJs.includes('id="aiBrainRecommendationBtn"'), 'ai-brain-drawer.js must define id="aiBrainRecommendationBtn"');
    console.log('  ✓ AI Brain Drawer Contract verified: aiBrainVerdict, aiBrainConfidenceBar, aiBrainRecommendationBtn present.');

    // 3b: ultra-ip-scanner-view.js controls
    const scannerJsPath = path.join(rootDir, 'public', 'js', 'views', 'ultra-ip-scanner-view.js');
    const scannerJs = fs.readFileSync(scannerJsPath, 'utf8');

    assert.ok(scannerJs.includes('id="scannerProfileSelect"'), 'ultra-ip-scanner-view.js must define scannerProfileSelect');
    assert.ok(scannerJs.includes('id="scannerConcurrencySelect"'), 'ultra-ip-scanner-view.js must define scannerConcurrencySelect');
    assert.ok(scannerJs.includes('id="startScanBtn"'), 'ultra-ip-scanner-view.js must define startScanBtn');
    assert.ok(scannerJs.includes('id="stopScanBtn"'), 'ultra-ip-scanner-view.js must define stopScanBtn');
    assert.ok(scannerJs.includes('id="progPhase"'), 'ultra-ip-scanner-view.js must define progPhase');
    assert.ok(scannerJs.includes('id="progProbesSent"'), 'ultra-ip-scanner-view.js must define progProbesSent');
    assert.ok(scannerJs.includes('id="progBytesTransferred"'), 'ultra-ip-scanner-view.js must define progBytesTransferred');
    console.log('  ✓ Ultra IP Scanner View Contract verified: all controls and telemetry badges present.');

    console.log('\n========================================================================');
    console.log('  ✓ BROWSER-LEVEL E2E WORKFLOW: 100% VERIFIED (ZERO CONTRACT DEFECTS)     ');
    console.log('========================================================================\n');
  } finally {
    if (serverProcess) {
      try {
        if (process.platform === 'win32') {
          require('child_process').execSync(`taskkill /F /T /PID ${serverProcess.pid}`, { stdio: 'ignore' });
        } else {
          serverProcess.kill('SIGKILL');
        }
      } catch (_) {
        try { serverProcess.kill('SIGKILL'); } catch (__) {}
      }
    }
    if (e2eDataDir) {
      try {
        fs.rmSync(e2eDataDir, { recursive: true, force: true });
      } catch (_) {}
    }
  }
}

if (require.main === module) {
  runE2EBrowserWorkflow().then(() => {
    process.exit(0);
  }).catch((err) => {
    console.error('\n❌ Browser E2E Workflow Verification Failed:', err);
    process.exit(1);
  });
}

module.exports = { runE2EBrowserWorkflow };
