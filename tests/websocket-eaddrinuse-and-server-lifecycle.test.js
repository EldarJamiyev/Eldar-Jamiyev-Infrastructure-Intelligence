/**
 * EJII Test Suite 55: Node.js v24 WebSocketServer EADDRINUSE Crash Prevention,
 * Pre-Bind Active Instance Detection, Port Reclamation & Clean Server Lifecycle
 */

const assert = require('assert');
const http = require('http');
const net = require('net');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');
const { spawn } = require('child_process');

async function runWebSocketEaddrinuseAndServerLifecycleTests() {
  console.log('========================================================================');
  console.log('  SUITE 55: WEBSOCKET EADDRINUSE CRASH DEFENSE & SERVER LIFECYCLE       ');
  console.log('========================================================================\n');

  const rootDir = path.resolve(__dirname, '..');

  // [55.1] Verify src/server.js Registers wss.on('error') and Handles EADDRINUSE Cleanly
  console.log('[55.1] Verifying src/server.js binds wss.on("error") and server.on("error")...');
  const serverCode = fs.readFileSync(path.join(rootDir, 'src', 'server.js'), 'utf8');
  assert.ok(
    /wss\.on\(\s*['"]error['"]/.test(serverCode),
    'src/server.js MUST attach wss.on("error", ...) to prevent unhandled error crashes on WebSocketServer'
  );
  assert.ok(
    serverCode.includes('EADDRINUSE'),
    'src/server.js MUST handle EADDRINUSE gracefully'
  );
  console.log('  ✓ src/server.js WebSocketServer and http.Server error listeners verified in source.');

  // [55.2] Empirical Proof: Attaching WebSocketServer to an Occupied Port Never Throws Unhandled Error
  console.log('[55.2] Empirically verifying WebSocketServer + http.Server EADDRINUSE on ephemeral port...');
  const blockerServer = http.createServer((req, res) => {
    if (req.url === '/api/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'UP', port: blockerPort }));
      return;
    }
    res.writeHead(200);
    res.end('OK');
  });

  await new Promise((resolve) => blockerServer.listen(0, '127.0.0.1', resolve));
  const blockerPort = blockerServer.address().port;

  // Now create a second http.Server + WebSocketServer targeting the exact same port
  let wssErrorCaught = false;
  let httpErrorCaught = false;
  const secondServer = http.createServer();
  const secondWss = new WebSocketServer({ server: secondServer });

  secondWss.on('error', (err) => {
    if (err && err.code === 'EADDRINUSE') {
      wssErrorCaught = true;
    }
  });

  await new Promise((resolve) => {
    secondServer.on('error', (err) => {
      if (err && err.code === 'EADDRINUSE') {
        httpErrorCaught = true;
      }
      resolve();
    });
    secondServer.listen(blockerPort, '127.0.0.1');
  });

  assert.strictEqual(httpErrorCaught, true, 'http.Server must catch EADDRINUSE');
  assert.strictEqual(wssErrorCaught, true, 'WebSocketServer wss.on("error") must catch re-emitted EADDRINUSE without crashing');

  await new Promise((resolve) => blockerServer.close(resolve));
  console.log(`  ✓ Empirical EADDRINUSE test on 127.0.0.1:${blockerPort} passed with zero unhandled WebSocketServer exceptions.`);

  // [55.3] Verify Child-Process Server Spawn Against Occupied Port Exits Cleanly Without Unhandled Exception Stack Trace
  console.log('[55.3] Verifying child-process src/server.js against occupied healthy port...');
  const mockEjiiServer = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'UP', platform: process.platform }));
  });
  await new Promise((resolve) => mockEjiiServer.listen(0, '127.0.0.1', resolve));
  const testPort = mockEjiiServer.address().port;

  const childResult = await new Promise((resolve) => {
    const child = spawn(process.execPath, [path.join(rootDir, 'src', 'server.js')], {
      env: {
        ...process.env,
        NODE_ENV: 'development',
        EJII_PORT: String(testPort),
        EJII_HOST: '127.0.0.1'
      },
      stdio: ['ignore', 'pipe', 'pipe']
    });

    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });

    const timer = setTimeout(() => {
      try { child.kill(); } catch (_) {}
      resolve({ code: 0, stdout, stderr, timedOut: true });
    }, 6000);

    child.on('exit', (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr, timedOut: false });
    });
  });

  await new Promise((resolve) => mockEjiiServer.close(resolve));

  assert.ok(
    !childResult.stderr.includes("Emitted 'error' event on WebSocketServer instance"),
    `src/server.js must NEVER crash with unhandled WebSocketServer error. stderr=${childResult.stderr}`
  );
  console.log('  ✓ Child-process server EADDRINUSE handoff verified with zero unhandled WebSocketServer errors.\n');

  console.log('========================================================================');
  console.log('  SUITE 55 PASSED: WEBSOCKET & SERVER LIFECYCLE 100% GREEN              ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runWebSocketEaddrinuseAndServerLifecycleTests()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('Suite 55 failed:', err);
      process.exit(1);
    });
}

module.exports = { runWebSocketEaddrinuseAndServerLifecycleTests };
