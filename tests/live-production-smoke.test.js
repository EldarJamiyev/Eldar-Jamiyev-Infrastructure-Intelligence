/**
 * EJII — Live Production Server Socket & API Smoke Test
 * Verifies real end-to-end runtime against standalone `src/server.js` process.
 * Tests physical socket binding, HTTP endpoints, WebSocket stream, RBAC defenses & Live Diagnostics.
 */

const { spawn } = require('child_process');
const http = require('http');
const path = require('path');
const WebSocket = require('ws');
const { createToken } = require('../src/core/security');

const TEST_PORT = 8445;
const TEST_HOST = '127.0.0.1';

function generateToken(user, role) {
  return createToken({ username: user, role: role }, 3600);
}

function makeRequest(options, postData = null) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => {
        let parsed = null;
        try {
          parsed = JSON.parse(body);
        } catch (e) {
          parsed = body;
        }
        resolve({ statusCode: res.statusCode, headers: res.headers, body: parsed });
      });
    });
    req.on('error', reject);
    if (postData) {
      req.write(typeof postData === 'string' ? postData : JSON.stringify(postData));
    }
    req.end();
  });
}

async function runLiveProductionSmoke() {
  console.log('========================================================================');
  console.log('  EJII LIVE PRODUCTION SERVER SOCKET & SMOKE TEST                      ');
  console.log(`  Spawning node src/server.js on ${TEST_HOST}:${TEST_PORT}...          `);
  console.log('========================================================================');

  const serverProcess = spawn('node', ['src/server.js'], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env,
      EJII_PORT: String(TEST_PORT),
      EJII_HOST: TEST_HOST
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  let serverStarted = false;

  const serverReady = new Promise((resolve, reject) => {
    serverProcess.stdout.on('data', (data) => {
      const text = data.toString();
      if (text.includes('Server Listening on:') || text.includes(`:${TEST_PORT}`)) {
        serverStarted = true;
        resolve();
      }
    });

    serverProcess.stderr.on('data', (data) => {
      console.error('[SERVER STDERR]:', data.toString());
    });

    serverProcess.on('exit', (code) => {
      if (!serverStarted) {
        reject(new Error(`Server exited unexpectedly with code ${code}`));
      }
    });

    // Timeout safety: 15 seconds
    setTimeout(() => {
      if (!serverStarted) {
        reject(new Error('Timed out waiting for production server to start.'));
      }
    }, 15000);
  });

  try {
    await serverReady;
    console.log(`✓ Production server started and listening on http://${TEST_HOST}:${TEST_PORT}\n`);

    // 1. WebSocket Live Stream Connection with Sec-WebSocket-Protocol Auth (S-04)
    console.log('[SMOKE 1] Connecting real WebSocket client with Sec-WebSocket-Protocol authentication...');
    const adminToken = generateToken('lead_architect', 'ADMIN');
    const ws = new WebSocket(`ws://${TEST_HOST}:${TEST_PORT}`, ['token', adminToken]);
    const wsConnectedPromise = new Promise((resolve, reject) => {
      ws.on('message', (msg) => {
        try {
          const parsed = JSON.parse(msg.toString());
          if (parsed.type === 'CONNECTED') {
            resolve(parsed);
          }
        } catch (e) {}
      });
      ws.on('error', reject);
    });

    const wsGreeting = await wsConnectedPromise;
    console.log(`  ✓ WebSocket verified: received greeting "${wsGreeting.message}" (User: ${wsGreeting.user.username}, Role: ${wsGreeting.user.role})`);
    if (wsGreeting.user.role !== 'ADMIN') {
      throw new Error(`WebSocket Auth Failure: Expected role ADMIN, got ${wsGreeting.user.role}`);
    }

    // Verify authenticated START_PACKET_STREAM control frame
    ws.send(JSON.stringify({ type: 'START_PACKET_STREAM' }));
    const streamStatus = await new Promise((resolve, reject) => {
      const handler = (msg) => {
        try {
          const parsed = JSON.parse(msg.toString());
          if (parsed.type === 'PACKET_STREAM_STATUS') {
            ws.off('message', handler);
            resolve(parsed);
          }
        } catch (e) {}
      };
      ws.on('message', handler);
      setTimeout(() => reject(new Error('Timeout waiting for PACKET_STREAM_STATUS')), 5000);
    });
    console.log(`  ✓ Authenticated START_PACKET_STREAM verified: active = ${streamStatus.active}`);
    ws.send(JSON.stringify({ type: 'STOP_PACKET_STREAM' }));

    // 2. Security Test: Spoofed Header Without Token -> Must Be 401
    console.log('\n[SMOKE 2] Attacking live server with spoofed X-EJII-Role: ADMIN header (no token)...');
    const attack1 = await makeRequest({
      hostname: TEST_HOST,
      port: TEST_PORT,
      path: '/api/tools/execute',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-EJII-Role': 'ADMIN'
      }
    }, { tool: 'pmtu_sweep', params: { target: '127.0.0.1' } });

    if (attack1.statusCode === 401) {
      console.log('  ✓ Attack Defeated: Live server returned 401 Unauthorized.');
    } else {
      throw new Error(`Security Failure: Expected 401, got ${attack1.statusCode}`);
    }

    // 3. Security Test: Valid READONLY token attempting X-EJII-Role: ADMIN privilege escalation -> Must Be 403
    console.log('\n[SMOKE 3] Attacking live server with valid READONLY token + spoofed X-EJII-Role: ADMIN...');
    const readonlyToken = generateToken('junior_analyst', 'READONLY');
    const attack2 = await makeRequest({
      hostname: TEST_HOST,
      port: TEST_PORT,
      path: '/api/tools/execute',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${readonlyToken}`,
        'X-EJII-Role': 'ADMIN'
      }
    }, { tool: 'pmtu_sweep', params: { target: '127.0.0.1' } });

    if (attack2.statusCode === 403) {
      console.log('  ✓ Attack Defeated: Live server ignored spoofed header and enforced token role READONLY (403 Forbidden).');
    } else {
      console.error('  -> attack2 response:', attack2.statusCode, attack2.body);
      throw new Error(`Security Failure: Expected 403, got ${attack2.statusCode}`);
    }

    // 4. Live Core Diagnostics Audit Endpoint
    console.log('\n[SMOKE 4] Querying live /api/diagnostics/host/audit with ADMIN token...');
    // Reusing verified adminToken from SMOKE 1
    const auditRes = await makeRequest({
      hostname: TEST_HOST,
      port: TEST_PORT,
      path: '/api/diagnostics/host/audit',
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${adminToken}`
      }
    });

    if (auditRes.statusCode === 200 && auditRes.body && auditRes.body.pillars) {
      const audit = auditRes.body;
      console.log(`  ✓ Audit endpoint returned 200 OK`);
      console.log(`  ✓ Telemetry Host: ${audit.host.hostname} (${audit.host.platform} ${audit.host.arch})`);
      console.log(`  ✓ 4-Pillar Summary: Network=${audit.pillars.network.status}, Storage=${audit.pillars.storage.status}, Resources=${audit.pillars.resource.status}, Peripherals=${audit.pillars.peripherals.status}`);
      console.log(`  ✓ AI Brain Synthesis: "${audit.brainSynthesis ? audit.brainSynthesis.summary : 'N/A'}"`);
    } else {
      throw new Error(`Diagnostics Failure: Expected 200 with audit body, got ${auditRes.statusCode}: ${JSON.stringify(auditRes.body)}`);
    }

    // 5. Live Remediation Preview Endpoint with Cryptographic Action Token
    console.log('\n[SMOKE 5] Querying live /api/diagnostics/remediation/preview for "trim_working_set"...');
    const previewRes = await makeRequest({
      hostname: TEST_HOST,
      port: TEST_PORT,
      path: '/api/diagnostics/remediation/preview',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminToken}`
      }
    }, { recipeId: 'trim_working_set' });

    let actionToken = null;
    if (previewRes.statusCode === 200 && previewRes.body && previewRes.body.preview && previewRes.body.preview.actionToken) {
      const preview = previewRes.body.preview;
      actionToken = preview.actionToken;
      console.log(`  ✓ Preview returned 200 OK: Recipe "${preview.name}", dryRun: ${preview.dryRun}`);
      console.log(`  ✓ Signed HMAC actionToken issued: ${actionToken.substring(0, 32)}...`);
    } else {
      throw new Error(`Remediation Preview Failure: Expected 200 with actionToken, got ${previewRes.statusCode}: ${JSON.stringify(previewRes.body)}`);
    }

    // 6. Live Remediation Cryptographically Bound Execution Endpoint
    console.log('\n[SMOKE 6] Executing remediation using cryptographic actionToken...');
    const execRes = await makeRequest({
      hostname: TEST_HOST,
      port: TEST_PORT,
      path: '/api/diagnostics/remediation/execute',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminToken}`
      }
    }, { actionToken });

    if (execRes.statusCode === 200 && execRes.body && execRes.body.outcome && execRes.body.outcome.success) {
      const outcome = execRes.body.outcome;
      console.log(`  ✓ Cryptographically bound execution succeeded: "${outcome.output}" in ${outcome.durationMs}ms`);
      console.log(`  ✓ Verified actionTokenId: ${outcome.actionTokenId}`);
    } else {
      throw new Error(`Remediation Execute Failure: Expected 200 with success outcome, got ${execRes.statusCode}: ${JSON.stringify(execRes.body)}`);
    }

    // 6b. Live Remediation Token Replay Defense (S-01)
    console.log('\n[SMOKE 6b] Attacking live server with replayed actionToken (must be rejected)...');
    const replayRes = await makeRequest({
      hostname: TEST_HOST,
      port: TEST_PORT,
      path: '/api/diagnostics/remediation/execute',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminToken}`
      }
    }, { actionToken });

    if (replayRes.statusCode === 400 && String(replayRes.body.error).includes('REPLAY_DETECTED')) {
      console.log('  ✓ Replay Attack Defeated: Live server rejected replayed actionToken with REPLAY_DETECTED (S-01 verified).');
    } else {
      throw new Error(`Security Failure: Expected 400 with REPLAY_DETECTED, got ${replayRes.statusCode}: ${JSON.stringify(replayRes.body)}`);
    }

    // 7. Live Cryptographic Audit Trail Verification
    console.log('\n[SMOKE 7] Verifying live tamper-resistant HMAC audit trail...');
    const auditVerifyRes = await makeRequest({
      hostname: TEST_HOST,
      port: TEST_PORT,
      path: '/api/diagnostics/remediation/audit-verify',
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${adminToken}`
      }
    });

    if (auditVerifyRes.statusCode === 200 && auditVerifyRes.body && auditVerifyRes.body.verification && auditVerifyRes.body.verification.valid) {
      const ver = auditVerifyRes.body.verification;
      console.log(`  ✓ Audit trail verified: ${ver.count} records in unbroken cryptographic chain (head: ${ver.headHash ? ver.headHash.substring(0, 16) : 'genesis'}...)`);
    } else {
      throw new Error(`Audit Trail Verification Failure: Expected 200 with valid chain, got ${auditVerifyRes.statusCode}: ${JSON.stringify(auditVerifyRes.body)}`);
    }

    // Close WebSocket
    ws.close();

    console.log('\n========================================================================');
    console.log('  ALL LIVE PRODUCTION SERVER SOCKET & SMOKE TESTS PASSED (100% GREEN)  ');
    console.log('========================================================================\n');
  } finally {
    // Terminate server process cleanly
    serverProcess.kill('SIGINT');
  }
}

if (require.main === module) {
  runLiveProductionSmoke().catch((err) => {
    console.error('\n❌ Smoke Test Failed:', err);
    process.exit(1);
  });
}

module.exports = { runLiveProductionSmoke };
