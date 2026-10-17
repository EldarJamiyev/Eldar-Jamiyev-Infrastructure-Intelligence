/**
 * Suite 31: Autonomous Self-Updating AI Brain Harness, Schema Gatekeeper,
 * Isolated Child-Process Sandbox Verification & Watchdog Circuit-Breaker Rollback
 */

'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { AIBrain, isSafeNetworkTarget } = require('../src/core/ai-brain');
const {
  DEFAULT_BRAIN_CONFIG,
  parseBrainConfig,
  safeParseBrainConfig,
  hashBrainConfig
} = require('../src/core/brain-config-schema');

async function runBrainSelfUpdatingHarnessTests() {
  console.log('\n========================================================================');
  console.log('  SUITE 31: AI BRAIN SELF-UPDATING HARNESS & CIRCUIT BREAKER AUDIT');
  console.log('========================================================================');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ejii-brain-selfupdate-'));
  const memFile = path.join(tmpDir, 'brain_memory.json');
  const cfgFile = path.join(tmpDir, 'brain-config.json');

  const brain = new AIBrain({
    dataDir: tmpDir,
    memoryFilePath: memFile,
    configFilePath: cfgFile,
    autoStart: true
  });

  try {
    // 31.1 Strict Schema Validation & Injection / Prototype Pollution Rejection
    console.log('  [31.1] Verifying BrainConfigSchema rejects out-of-bounds, floats, unknown keys & pollution...');
    assert.strictEqual(safeParseBrainConfig({ brainTickIntervalMs: 50 }).success, false, 'Must reject tick < 1000ms');
    assert.strictEqual(safeParseBrainConfig({ adaptiveLatencyMultiplier: 99 }).success, false, 'Must reject multiplier > 10');
    assert.strictEqual(safeParseBrainConfig({ maxEvents: 123.45 }).success, false, 'Must reject float for integer field');
    assert.strictEqual(safeParseBrainConfig({ maliciousKey: 'exec("calc")' }).success, false, 'Must reject unknown keys');
    assert.strictEqual(
      safeParseBrainConfig({ minBaselineSamples: 20, establishedSampleThreshold: 5 }).success,
      false,
      'Must reject establishedSampleThreshold < minBaselineSamples'
    );
    console.log('  ✓ Schema boundary invariants and unknown key rejections verified.');

    // 31.2 Command Injection Defense in executeDiagnosticProbe
    console.log('  [31.2] Verifying network target sanitizer blocks shell metacharacters...');
    assert.strictEqual(isSafeNetworkTarget('192.168.31.1'), true);
    assert.strictEqual(isSafeNetworkTarget('127.0.0.1 & calc.exe'), false);
    assert.strictEqual(isSafeNetworkTarget('8.8.8.8; rm -rf /'), false);
    assert.strictEqual(isSafeNetworkTarget('$(whoami)'), false);
    console.log('  ✓ Diagnostic probe target sanitizer verified.');

    // 31.3 Day-Bucket SHA-256 Incident Key Alignment in executeDiagnosticProbe
    console.log('  [31.3] Verifying executeDiagnosticProbe revises existing day-bucketed incident in place...');
    const createdIncident = brain.ingestTelemetry({
      target: '127.0.0.1',
      destIp: '127.0.0.1',
      destPort: 443,
      incidentType: 'TCP_SYN_TIMEOUT',
      isAnomaly: true
    });
    const countBeforeProbe = brain.activeIncidents.size;
    const probeRes = await brain.executeDiagnosticProbe({
      probeType: 'ICMP_PING_TARGET',
      targetIp: '127.0.0.1'
    });
    assert.strictEqual(probeRes.success, true);
    assert.strictEqual(
      brain.activeIncidents.size,
      countBeforeProbe,
      'executeDiagnosticProbe must update existing day-bucketed incident rather than creating a duplicate'
    );
    assert.ok(brain.activeIncidents.has(createdIncident.incidentKey), 'Original incidentKey must remain in activeIncidents');
    console.log('  ✓ Day-bucketed SHA-256 incident belief revision verified.');

    // 31.4 Autonomous Drift Detection & Sandboxed Hot-Swap
    console.log('  [31.4] Verifying autonomous drift trigger, child-process sandbox gate & live hot-swap...');
    // Populate baseline + anomaly burst to exceed drift ratio
    for (let i = 0; i < 6; i++) {
      brain.ingestWireFrame({
        srcIp: '192.168.31.89',
        dstIp: '192.168.31.250',
        dstPort: 443,
        tcpAnalysis: { handshakeRttMs: 20 + (i * 5) }
      });
    }
    for (let i = 0; i < 12; i++) {
      brain.ingestWireFrame({
        srcIp: '192.168.31.89',
        dstIp: '192.168.31.250',
        dstPort: 443,
        tcpAnalysis: { handshakeRttMs: 420 + i * 10, isRetransmission: true },
        tcp: { flags: { rst: true } }
      });
    }

    const initialHash = hashBrainConfig(brain.dynamicConfig);
    const optResult = await brain.optimizeBrainParameters({
      triggerSource: 'SUITE_31_TEST'
    });

    assert.strictEqual(optResult.success, true, 'Optimization cycle must succeed');
    assert.strictEqual(optResult.status, 'APPLIED_AND_VERIFIED');
    const updatedHash = hashBrainConfig(brain.dynamicConfig);
    assert.notStrictEqual(updatedHash, initialHash, 'Dynamic config hash must update after optimization');
    assert.strictEqual(fs.existsSync(cfgFile), true, 'brain-config.json must be persisted to disk');
    const diskCfg = parseBrainConfig(JSON.parse(fs.readFileSync(cfgFile, 'utf8')));
    assert.strictEqual(hashBrainConfig(diskCfg), updatedHash, 'Disk config must match live hot-swapped config');
    console.log('  ✓ Sandbox gate verification and atomic hot-swap verified.');

    // 31.5 Watchdog Circuit Breaker Automatic Rollback on Runtime Fault
    console.log('  [31.5] Verifying Watchdog Circuit Breaker immediately rolls back to stable config on fault...');
    const rollbackRes = brain.recordRuntimeFault('Simulated post-deployment telemetry stall');
    assert.strictEqual(rollbackRes.status, 'ROLLED_BACK', 'Watchdog must trigger immediate rollback');
    assert.strictEqual(
      hashBrainConfig(brain.dynamicConfig),
      initialHash,
      'Rollback must restore exact pre-modification configuration hash'
    );
    const diskRestored = parseBrainConfig(JSON.parse(fs.readFileSync(cfgFile, 'utf8')));
    assert.strictEqual(hashBrainConfig(diskRestored), initialHash, 'Disk config must be restored on rollback');
    console.log('  ✓ Watchdog Circuit Breaker automatic rollback verified.');

    // 31.6 Real Multi-Protocol Probe Execution, Belief Revision & Autonomous Investigation
    console.log('  [31.6] Verifying real multi-protocol probe execution (TCP, DNS, HTTP) and Hare-Niemeyer 100% belief revision...');
    const http = require('http');
    const express = require('express');
    const { generateToken } = require('../src/core/security');
    const rcaRouter = require('../src/api/routes-rca');

    // Spin up local HTTP server to act as live wire target
    let localPort = 0;
    const probeServer = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('EJII Live Target Wire Listener OK');
    });

    await new Promise((resolve) => {
      probeServer.listen(0, '127.0.0.1', () => {
        localPort = probeServer.address().port;
        resolve();
      });
    });

    try {
      // 1. TCP Alternate Port Probe
      const altProbe = await brain.executeDiagnosticProbe({
        probeType: 'TCP_SYN_ALTERNATE_PORT',
        targetIp: '127.0.0.1',
        alternatePort: localPort
      });
      assert.strictEqual(altProbe.success, true);
      assert.strictEqual(altProbe.probeSuccess, true);
      assert.ok(altProbe.rawOutput.includes('connected in'));

      // 2. DNS Query Probe (RFC 1035)
      const dnsProbe = await brain.executeDiagnosticProbe({
        probeType: 'DNS_QUERY_PROBE',
        targetIp: '127.0.0.1'
      });
      assert.strictEqual(dnsProbe.success, true);
      assert.strictEqual(typeof dnsProbe.probeSuccess, 'boolean');
      assert.ok(dnsProbe.rawOutput.length > 0);

      // 3. HTTP HEAD Probe
      const httpProbe = await brain.executeDiagnosticProbe({
        probeType: 'HTTP_HEAD_PROBE',
        targetIp: '127.0.0.1',
        targetPort: localPort
      });
      assert.strictEqual(httpProbe.success, true);
      assert.strictEqual(httpProbe.probeSuccess, true);
      assert.ok(httpProbe.rawOutput.includes('HTTP HEAD status: 200'));

      // 4. Verify belief revision sums strictly to 100.0% (Hare-Niemeyer invariant)
      const revEval = httpProbe.revisedEvaluation;
      assert.ok(revEval, 'revisedEvaluation must be populated');
      const sumPct = revEval.rankedHypotheses.reduce((acc, h) => acc + h.confidence, 0);
      assert.strictEqual(sumPct, 100, 'All hypothesis probabilities must sum to exactly 100%');

      // 5. Unrecognized probe rejection (no fake fallback)
      const unkProbe = await brain.executeDiagnosticProbe({
        probeType: 'NON_EXISTENT_PROBE_TYPE',
        targetIp: '127.0.0.1'
      });
      assert.strictEqual(unkProbe.probeSuccess, false, 'Unknown probe must NOT fake success');

      // 6. Autonomous Investigation Run
      const invResult = await brain.runAutonomousInvestigation({
        targetIp: '127.0.0.1',
        targetPort: localPort,
        maxSteps: 3
      });
      assert.strictEqual(invResult.success, true);
      assert.ok(invResult.stepsExecuted >= 1, 'Must execute at least 1 probe step');
      assert.ok(invResult.investigationId.startsWith('INV-'));
      assert.ok(invResult.finalTopHypothesis);
      assert.ok(Array.isArray(invResult.steps));
      console.log('  ✓ Multi-protocol probe execution and belief revision verified.');
    } finally {
      await new Promise(r => probeServer.close(r));
    }

    // 31.7 Live HTTP REST Endpoint RBAC Enforcement (401, 403, 200)
    console.log('  [31.7] Verifying live HTTP RBAC enforcement on /api/rca/brain endpoints...');
    const app = express();
    app.use(express.json());
    app.use('/api/rca', rcaRouter);

    let apiPort = 0;
    const apiServer = http.createServer(app);
    await new Promise((resolve) => {
      apiServer.listen(0, '127.0.0.1', () => {
        apiPort = apiServer.address().port;
        resolve();
      });
    });

    function requestHttp(urlPath, method = 'GET', token = null, body = null) {
      return new Promise((resolve, reject) => {
        const payload = body ? JSON.stringify(body) : null;
        const options = {
          hostname: '127.0.0.1',
          port: apiPort,
          path: urlPath,
          method,
          headers: {
            'Content-Type': 'application/json',
            ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
            ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {})
          }
        };
        const req = http.request(options, (res) => {
          let data = '';
          res.on('data', chunk => { data += chunk; });
          res.on('end', () => {
            let json = null;
            try { json = JSON.parse(data); } catch (_) {}
            resolve({ statusCode: res.statusCode, data: json || data });
          });
        });
        req.on('error', reject);
        if (payload) req.write(payload);
        req.end();
      });
    }

    try {
      const adminToken = generateToken({ id: 'u-admin', username: 'sec_admin', role: 'ADMIN' });
      const opToken = generateToken({ id: 'u-operator', username: 'net_op', role: 'OPERATOR' });
      const roToken = generateToken({ id: 'u-auditor', username: 'auditor', role: 'READONLY' });

      // 1. Unauthenticated requests must receive 401
      const resUnauthStatus = await requestHttp('/api/rca/brain/self-update-status');
      assert.strictEqual(resUnauthStatus.statusCode, 401, 'Unauthenticated status must be 401');

      const resUnauthOpt = await requestHttp('/api/rca/brain/self-update/optimize', 'POST', null, {});
      assert.strictEqual(resUnauthOpt.statusCode, 401, 'Unauthenticated optimize must be 401');

      const resUnauthRbk = await requestHttp('/api/rca/brain/self-update/rollback', 'POST', null, {});
      assert.strictEqual(resUnauthRbk.statusCode, 401, 'Unauthenticated rollback must be 401');

      const resUnauthInv = await requestHttp('/api/rca/brain/investigate', 'POST', null, {});
      assert.strictEqual(resUnauthInv.statusCode, 401, 'Unauthenticated investigate must be 401');

      // 2. READONLY user: Can read status (200), but blocked from self-update mutations (403)
      const resRoStatus = await requestHttp('/api/rca/brain/self-update-status', 'GET', roToken);
      assert.strictEqual(resRoStatus.statusCode, 200, 'READONLY must be allowed to read self-update status');

      const resRoOpt = await requestHttp('/api/rca/brain/self-update/optimize', 'POST', roToken, {});
      assert.strictEqual(resRoOpt.statusCode, 403, 'READONLY must receive 403 on self-update optimize');

      const resRoRbk = await requestHttp('/api/rca/brain/self-update/rollback', 'POST', roToken, {});
      assert.strictEqual(resRoRbk.statusCode, 403, 'READONLY must receive 403 on self-update rollback');

      // 3. OPERATOR user: Blocked from system.config.manage (403), but allowed on network.diagnostics.execute (200)
      const resOpOpt = await requestHttp('/api/rca/brain/self-update/optimize', 'POST', opToken, {});
      assert.strictEqual(resOpOpt.statusCode, 403, 'OPERATOR must receive 403 on self-update optimize');

      const resOpRbk = await requestHttp('/api/rca/brain/self-update/rollback', 'POST', opToken, {});
      assert.strictEqual(resOpRbk.statusCode, 403, 'OPERATOR must receive 403 on self-update rollback');

      const resOpInv = await requestHttp('/api/rca/brain/investigate', 'POST', opToken, {
        targetIp: '127.0.0.1',
        maxSteps: 1
      });
      assert.strictEqual(resOpInv.statusCode, 200, 'OPERATOR must be allowed to trigger autonomous investigation');

      // 4. ADMIN user: Full capability on all endpoints (200)
      const resAdmStatus = await requestHttp('/api/rca/brain/self-update-status', 'GET', adminToken);
      assert.strictEqual(resAdmStatus.statusCode, 200, 'ADMIN must be permitted on self-update status');

      const resAdmRbk = await requestHttp('/api/rca/brain/self-update/rollback', 'POST', adminToken, {});
      assert.strictEqual(resAdmRbk.statusCode, 200, 'ADMIN must be permitted on self-update rollback');

      console.log('  ✓ Live HTTP endpoint RBAC enforcement (401, 403, 200) strictly verified.');
    } finally {
      await new Promise(r => apiServer.close(r));
    }

    console.log('\n========================================================================');
    console.log('  ALL 7 AI BRAIN SELF-UPDATING HARNESS TESTS PASSED (100% GREEN)        ');
    console.log('========================================================================\n');
  } finally {
    brain.stopContinuousReasoning();
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (_) {}
  }
}

module.exports = { runBrainSelfUpdatingHarnessTests };

if (require.main === module) {
  runBrainSelfUpdatingHarnessTests()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('Suite 31 Failed:', err);
      process.exit(1);
    });
}
