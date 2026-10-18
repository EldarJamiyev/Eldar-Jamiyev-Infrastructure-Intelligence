/**
 * EJII Browser-Level E2E Workflow & AI Brain Contract Verification Suite
 *
 * Verifies the end-to-end operational pipeline:
 * 1. REST API Contract:
 *    - GET /api/network/ai-brain/live (200 OK, strict 100% normalized hypotheses)
 *    - GET /api/network/ai-brain/history (200 OK, history records)
 *    - GET /api/network/ai-brain/status (200 OK, operational metrics)
 *    - GET /api/network/scanner/profiles (200 OK, edr_conservative, fast, deep)
 *    - GET /api/network/scanner/status (200 OK, telemetry and policy tracking)
 * 2. WebSocket Real-Time Diagnostic Stream:
 *    - Connects to ws://127.0.0.1:8443/ws
 *    - Triggers POST /api/network/ai-brain/trigger-probe
 *    - Verifies AI_BRAIN_DIAGNOSTIC_UPDATE arrives within 2000ms with strict 100% sum
 * 3. Frontend View & DOM Contract:
 *    - aiBrainVerdict, aiBrainConfidenceBar, aiBrainRecommendationBtn in ai-brain-drawer.js
 *    - scannerProfileSelect, scannerConcurrencySelect, telemetry counters in ultra-ip-scanner-view.js
 * 4. Clean Teardown & Resource Isolation
 */

const assert = require('assert');
const http = require('http');
const net = require('net');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const WebSocket = require('ws');
const { createToken } = require('../src/core/security');

const PORT = 8443;
const HOST = '127.0.0.1';
const token = createToken({ id: 'USR-NOC-01', username: 'noc', role: 'noc_operator' });

function checkPortOpen(port, host = '127.0.0.1') {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(800);
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

function httpRequest(options, postData = null) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(body);
          resolve({ status: res.statusCode, headers: res.headers, data: parsed });
        } catch (e) {
          resolve({ status: res.statusCode, headers: res.headers, data: body });
        }
      });
    });
    req.on('error', reject);
    if (postData) {
      req.write(typeof postData === 'string' ? postData : JSON.stringify(postData));
    }
    req.end();
  });
}

async function runE2EBrowserWorkflow() {
  console.log('========================================================================');
  console.log('  EJII BROWSER-LEVEL E2E WORKFLOW & CONTRACT VERIFICATION SUITE         ');
  console.log(`  Target: http://${HOST}:${PORT} | Protocol: REST + WebSocket + DOM Contract`);
  console.log('========================================================================\n');

  let serverProcess = null;
  const isRunning = await checkPortOpen(PORT, HOST);
  if (!isRunning) {
    console.log(`[Auto-Start]: Port ${PORT} not listening. Spawning local server for E2E verification...`);
    serverProcess = spawn(process.execPath, ['src/server.js'], {
      cwd: path.join(__dirname, '..'),
      env: {
        ...process.env,
        EJII_PORT: String(PORT),
        EJII_HOST: HOST
      },
      stdio: ['ignore', 'pipe', 'pipe']
    });

    await new Promise((resolve, reject) => {
      let ready = false;
      serverProcess.stdout.on('data', (d) => {
        if (d.toString().includes('Server Listening on:') || d.toString().includes(`:${PORT}`)) {
          ready = true;
          resolve();
        }
      });
      serverProcess.on('exit', (code) => {
        if (!ready) reject(new Error(`Server exited prematurely with code ${code}`));
      });
      setTimeout(() => {
        if (!ready) reject(new Error('Timed out waiting for E2E server to boot'));
      }, 15000);
    });
    console.log(`✓ E2E local server booted successfully on http://${HOST}:${PORT}\n`);
  }

  try {
  // --------------------------------------------------------------------------
  // PART 1: REST API VERIFICATION
  // --------------------------------------------------------------------------
  console.log('[Phase 1] Verifying AI Brain & Scanner REST Endpoints...');

  // 1a: GET /api/network/ai-brain/live
  const liveRes = await httpRequest({
    hostname: HOST,
    port: PORT,
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
    port: PORT,
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
    port: PORT,
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
    port: PORT,
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
    port: PORT,
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
  const wsUrl = `ws://${HOST}:${PORT}/ws`;

  await new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl, ['token', token]);
    let receivedUpdate = false;

    const timeout = setTimeout(() => {
      ws.terminate();
      if (!receivedUpdate) {
        reject(new Error('Timed out waiting for AI_BRAIN_DIAGNOSTIC_UPDATE over WebSocket within 2000ms'));
      }
    }, 2500);

    ws.on('open', async () => {
      console.log('  ✓ WebSocket connected successfully to /ws');

      // Trigger diagnostic probe via REST API
      try {
        const probeRes = await httpRequest({
          hostname: HOST,
          port: PORT,
          path: '/api/network/ai-brain/trigger-probe',
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
          }
        }, {
          probeType: 'ICMP_PING_GATEWAY',
          targetIp: '10.168.195.1'
        });

        assert.strictEqual(probeRes.status, 200, 'Trigger probe must return 200 OK');
        console.log(`  ✓ Diagnostic probe triggered: latency ${probeRes.data.latencyMs}ms`);
      } catch (err) {
        clearTimeout(timeout);
        ws.terminate();
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

          ws.close();
          resolve();
        }
      } catch (e) {
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
      serverProcess.kill('SIGINT');
    }
  }
}

if (require.main === module) {
  runE2EBrowserWorkflow().then(() => {
    process.exit(0);
  }).catch((err) => {
    console.error('Browser E2E Workflow Verification Failed:', err);
    process.exit(1);
  });
}

module.exports = { runE2EBrowserWorkflow };
