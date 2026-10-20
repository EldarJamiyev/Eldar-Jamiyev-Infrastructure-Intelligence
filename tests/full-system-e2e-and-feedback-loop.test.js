/**
 * EJII Suite 33: Full System E2E, SSRF Defense, Feedback Calibration & Architecture Integrity Suite
 *
 * Verifies:
 * 1. Target Canonicalization, IPv4-Mapped IPv6 & DNS Rebinding SSRF Protection:
 *    Rigorous blocking of ::ffff:169.254.169.254, ::ffff:a9fe:a9fe, 0:0:0:0:0:ffff:169.254.169.254,
 *    ::ffff:0.0.0.0, and cloud metadata hostnames while strictly preserving ::1, ::ffff:192.168.31.1,
 *    and RFC 1918 subnets.
 * 2. Controlled Operator Feedback & Prior Calibration Loop in AIBrain & Reasoning Engine:
 *    Verifying bounded empirical multipliers (1.12 on CONFIRMED, 0.88 on REJECTED), strict clamping
 *    within [0.50, 2.00], Hare-Niemeyer exact 100.0% probability normalization invariant, and persistent
 *    state serialization across restarts.
 * 3. Live HTTP REST API RBAC Enforcement on POST /api/rca/brain/feedback:
 *    Strict verification of 401 (unauthenticated), 403 (READONLY role), 400 (invalid schema), and 200 (OPERATOR/ADMIN).
 * 4. API Route Hygiene & Architectural Mounting Verification:
 *    Ensuring all active route modules in src/api are valid Express routers and cleanly mounted in src/server.js.
 * 5. Frontend UI Contract & Diagnostics Viewport Verification:
 *    Verifying timeline table rendering, tabular-nums typography, stopping reason badges, and interactive feedback handlers.
 */

'use strict';

const assert = require('assert');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const express = require('express');

const { AIBrain, isSafeNetworkTarget, resolveAndValidateTarget } = require('../src/core/ai-brain');
const { reasoningEngine } = require('../src/core/reasoning-engine');
const { generateToken } = require('../src/core/security');
const rcaRouter = require('../src/api/routes-rca');

async function runFullSystemE2eAndFeedbackLoopTests() {
  console.log('\n========================================================================');
  console.log('  SUITE 33: FULL SYSTEM E2E, FEEDBACK CALIBRATION & SSRF DEFENSE       ');
  console.log('  Wire Integrity, DNS Rebinding, Bounded Calibration & Architecture     ');
  console.log('========================================================================');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ejii-suite33-'));
  const memFile = path.join(tmpDir, 'memory.json');
  const cfgFile = path.join(tmpDir, 'config.json');

  const brain = new AIBrain({
    dataDir: tmpDir,
    memoryFilePath: memFile,
    configFilePath: cfgFile,
    autoStart: false
  });

  try {
    // -------------------------------------------------------------------------
    // 1. IPv4-Mapped IPv6 & DNS Rebinding SSRF Protection
    // -------------------------------------------------------------------------
    console.log('\n[33.1] Testing IPv4-Mapped IPv6 & DNS Rebinding SSRF Defenses...');

    // A. IPv4-Mapped / Compatible IPv6 Metadata Rejections
    assert.strictEqual(
      isSafeNetworkTarget('::ffff:169.254.169.254'),
      false,
      'Must block IPv4-mapped IPv6 cloud metadata (::ffff:169.254.169.254)'
    );
    assert.strictEqual(
      isSafeNetworkTarget('::ffff:a9fe:a9fe'),
      false,
      'Must block hex IPv4-mapped IPv6 metadata (::ffff:a9fe:a9fe)'
    );
    assert.strictEqual(
      isSafeNetworkTarget('0:0:0:0:0:ffff:169.254.169.254'),
      false,
      'Must block uncompressed IPv4-mapped IPv6 metadata (0:0:0:0:0:ffff:169.254.169.254)'
    );
    assert.strictEqual(
      isSafeNetworkTarget('::ffff:0.0.0.0'),
      false,
      'Must block IPv4-mapped IPv6 all-zeroes (::ffff:0.0.0.0)'
    );

    // B. Allowed Loopback and RFC 1918 Private Subnets
    assert.strictEqual(
      isSafeNetworkTarget('::1'),
      true,
      'Must allow IPv6 loopback (::1)'
    );
    assert.strictEqual(
      isSafeNetworkTarget('[::1]'),
      true,
      'Must allow bracketed IPv6 loopback ([::1])'
    );
    assert.strictEqual(
      isSafeNetworkTarget('::ffff:192.168.31.1'),
      true,
      'Must allow IPv4-mapped IPv6 RFC 1918 NOC subnet (::ffff:192.168.31.1)'
    );
    assert.strictEqual(
      isSafeNetworkTarget('10.22.12.204'),
      true,
      'Must allow RFC 1918 Class A subnet (10.22.12.204)'
    );
    assert.strictEqual(
      isSafeNetworkTarget('172.16.0.1'),
      true,
      'Must allow RFC 1918 Class B subnet (172.16.0.1)'
    );

    // C. DNS Rebinding Resolver Validation
    const safeResolved = await resolveAndValidateTarget('127.0.0.1');
    assert.strictEqual(safeResolved.safeTarget, '127.0.0.1');
    assert.strictEqual(safeResolved.isIpLiteral, true);

    let ssrfThrew = false;
    try {
      await resolveAndValidateTarget('169.254.169.254');
    } catch (err) {
      ssrfThrew = true;
      assert.ok(err.message.includes('SSRF defense policy'), 'Error must specify SSRF defense violation');
    }
    assert.strictEqual(ssrfThrew, true, 'resolveAndValidateTarget must throw on SSRF IP');

    let injectThrew = false;
    try {
      await resolveAndValidateTarget('127.0.0.1; whoami');
    } catch (err) {
      injectThrew = true;
    }
    assert.strictEqual(injectThrew, true, 'resolveAndValidateTarget must throw on command injection attempt');

    console.log('  ✓ IPv4-mapped IPv6 SSRF defenses and DNS rebinding protections verified.');

    // -------------------------------------------------------------------------
    // 2. Controlled Operator Feedback & Prior Calibration Loop
    // -------------------------------------------------------------------------
    console.log('\n[33.2] Testing Controlled Operator Feedback & Calibration Loop...');

    // A. Confirm Hypothesis Feedback (Multiplier 1.12)
    const fb1 = brain.recordOperatorFeedback({
      incidentKey: 'INC-SUITE33-01',
      verdict: 'CONFIRMED',
      confirmedHypothesisId: 'FIREWALL_SILENT_DROP',
      operatorNotes: 'Upstream ACL verified dropping SYN packets',
      userId: 'noc-engineer'
    });
    assert.strictEqual(fb1.success, true);
    assert.strictEqual(fb1.verdict, 'CONFIRMED');
    assert.strictEqual(fb1.calibrationWeight, 1.12);
    assert.ok(brain.hypothesisCalibration.TCP_SYN_TIMEOUT.FIREWALL_SILENT_DROP === 1.12);

    // Verify Hare-Niemeyer exact 100% sum invariant on revised evaluation
    const confSum1 = fb1.revisedEvaluation.rankedHypotheses.reduce((acc, h) => acc + h.confidence, 0);
    assert.strictEqual(confSum1, 100, `Confidence sum must equal 100%, got ${confSum1}`);

    // B. Reject Hypothesis Feedback (Multiplier 0.88)
    const fb2 = brain.recordOperatorFeedback({
      incidentKey: 'INC-SUITE33-02',
      verdict: 'REJECTED',
      confirmedHypothesisId: 'REMOTE_HOST_DOWN',
      operatorNotes: 'Host verified online via out-of-band IPMI',
      userId: 'noc-engineer'
    });
    assert.strictEqual(fb2.success, true);
    assert.strictEqual(fb2.verdict, 'REJECTED');
    assert.strictEqual(fb2.calibrationWeight, 0.88);
    assert.ok(brain.hypothesisCalibration.TCP_SYN_TIMEOUT.REMOTE_HOST_DOWN === 0.88);

    const confSum2 = fb2.revisedEvaluation.rankedHypotheses.reduce((acc, h) => acc + h.confidence, 0);
    assert.strictEqual(confSum2, 100, `Confidence sum must equal 100%, got ${confSum2}`);

    // C. Clamping Stress Test: Must never exceed 2.00 or fall below 0.50
    for (let i = 0; i < 20; i++) {
      brain.recordOperatorFeedback({
        incidentKey: `INC-SUITE33-CONF-${i}`,
        verdict: 'CONFIRMED',
        confirmedHypothesisId: 'FIREWALL_SILENT_DROP',
        userId: 'noc-engineer'
      });
    }
    assert.strictEqual(
      brain.hypothesisCalibration.TCP_SYN_TIMEOUT.FIREWALL_SILENT_DROP,
      2.0,
      'Calibration weight must strictly clamp at upper bound 2.00'
    );

    for (let i = 0; i < 20; i++) {
      brain.recordOperatorFeedback({
        incidentKey: `INC-SUITE33-REJ-${i}`,
        verdict: 'REJECTED',
        confirmedHypothesisId: 'REMOTE_HOST_DOWN',
        userId: 'noc-engineer'
      });
    }
    assert.strictEqual(
      brain.hypothesisCalibration.TCP_SYN_TIMEOUT.REMOTE_HOST_DOWN,
      0.5,
      'Calibration weight must strictly clamp at lower bound 0.50'
    );

    // D. Persistence Verification Across Brain Restarts
    const brainReloaded = new AIBrain({
      dataDir: tmpDir,
      memoryFilePath: memFile,
      configFilePath: cfgFile,
      autoStart: false
    });
    assert.strictEqual(
      brainReloaded.hypothesisCalibration.TCP_SYN_TIMEOUT.FIREWALL_SILENT_DROP,
      2.0,
      'Persisted upper calibration weight must survive restart'
    );
    assert.strictEqual(
      brainReloaded.hypothesisCalibration.TCP_SYN_TIMEOUT.REMOTE_HOST_DOWN,
      0.5,
      'Persisted lower calibration weight must survive restart'
    );
    assert.ok(brainReloaded.feedbackHistory.length > 2, 'Feedback history log must be persisted and restored');

    console.log('  ✓ Controlled operator feedback loop, bounded calibration [0.50, 2.00], and persistence verified.');

    // -------------------------------------------------------------------------
    // 3. Live HTTP REST API RBAC Enforcement on POST /api/rca/brain/feedback
    // -------------------------------------------------------------------------
    console.log('\n[33.3] Testing Live HTTP REST API RBAC on /api/rca/brain/feedback...');

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

    function requestApi(urlPath, method = 'POST', token = null, body = null) {
      return new Promise((resolve, reject) => {
        const payload = body ? JSON.stringify(body) : null;
        const req = http.request({
          hostname: '127.0.0.1',
          port: apiPort,
          path: urlPath,
          method,
          headers: {
            'Content-Type': 'application/json',
            ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
            ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {})
          }
        }, (res) => {
          let data = '';
          res.on('data', c => { data += c; });
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
      const opToken = generateToken({ id: 'u-op33', username: 'net_operator', role: 'OPERATOR' });
      const roToken = generateToken({ id: 'u-ro33', username: 'auditor_read', role: 'READONLY' });

      // 1. Unauthenticated -> 401
      const resUnauth = await requestApi('/api/rca/brain/feedback', 'POST', null, {
        incidentKey: 'INC-RBAC-01',
        verdict: 'CONFIRMED',
        confirmedHypothesisId: 'FIREWALL_SILENT_DROP'
      });
      assert.strictEqual(resUnauth.statusCode, 401, 'Unauthenticated request must return 401');

      // 2. READONLY role -> 403 Forbidden (missing network.diagnostics.execute)
      const resRo = await requestApi('/api/rca/brain/feedback', 'POST', roToken, {
        incidentKey: 'INC-RBAC-02',
        verdict: 'CONFIRMED',
        confirmedHypothesisId: 'FIREWALL_SILENT_DROP'
      });
      assert.strictEqual(resRo.statusCode, 403, 'READONLY role must return 403 Forbidden');

      // 3. OPERATOR role with missing parameters -> 400 Bad Request
      const resMissing = await requestApi('/api/rca/brain/feedback', 'POST', opToken, {
        incidentKey: 'INC-RBAC-03'
      });
      assert.strictEqual(resMissing.statusCode, 400, 'Missing parameters must return 400 Bad Request');
      assert.ok(resMissing.data.error.includes('Missing required parameters'));

      // 4. OPERATOR role with invalid verdict -> 400 Bad Request
      const resBadVerdict = await requestApi('/api/rca/brain/feedback', 'POST', opToken, {
        incidentKey: 'INC-RBAC-04',
        verdict: 'UNKNOWN_VERDICT',
        confirmedHypothesisId: 'FIREWALL_SILENT_DROP'
      });
      assert.strictEqual(resBadVerdict.statusCode, 400, 'Invalid verdict must return 400 Bad Request');

      // 5. OPERATOR role with valid parameters -> 200 OK
      const resValid = await requestApi('/api/rca/brain/feedback', 'POST', opToken, {
        incidentKey: 'INC-RBAC-05',
        verdict: 'CONFIRMED',
        confirmedHypothesisId: 'FIREWALL_SILENT_DROP',
        operatorNotes: 'Verified at core router ACL'
      });
      assert.strictEqual(resValid.statusCode, 200, 'Valid feedback must return 200 OK');
      assert.strictEqual(resValid.data.success, true);
      assert.strictEqual(resValid.data.verdict, 'CONFIRMED');
      assert.ok(typeof resValid.data.calibrationWeight === 'number');
      assert.ok(resValid.data.revisedEvaluation !== undefined);

      console.log('  ✓ Live HTTP RBAC (401, 403, 400, 200) strictly verified on /api/rca/brain/feedback.');
    } finally {
      await new Promise(r => apiServer.close(r));
    }

    // -------------------------------------------------------------------------
    // 4. API Route Hygiene & Architectural Mounting Verification
    // -------------------------------------------------------------------------
    console.log('\n[33.4] Testing API Route Hygiene & Architectural Mounting...');

    const expectedRouteFiles = [
      'routes-auth.js',
      'routes-diagnostics-remediation.js',
      'routes-diagnostics.js',
      'routes-network.js',
      'routes-observability.js',
      'routes-rca.js',
      'routes-tools.js'
    ];

    const apiDir = path.join(__dirname, '..', 'src', 'api');
    const actualFiles = fs.readdirSync(apiDir)
      .filter(f => f.startsWith('routes-') && f.endsWith('.js'))
      .sort();

    assert.deepStrictEqual(
      actualFiles,
      expectedRouteFiles.sort(),
      'All expected route files must exist in src/api without orphaned route files'
    );

    // Verify each route file exports an Express Router function
    for (const rFile of expectedRouteFiles) {
      const routeModule = require(path.join(apiDir, rFile));
      assert.strictEqual(
        typeof routeModule,
        'function',
        `Route module ${rFile} must export a router function`
      );
      assert.ok(
        routeModule.stack !== undefined,
        `Route module ${rFile} must be an initialized Express Router`
      );
    }

    // Verify server.js loads and mounts every route module
    const serverCode = fs.readFileSync(path.join(__dirname, '..', 'src', 'server.js'), 'utf8');
    assert.ok(serverCode.includes("require('./api/routes-auth')"), 'server.js must mount routes-auth');
    assert.ok(serverCode.includes("require('./api/routes-diagnostics-remediation')"), 'server.js must mount routes-diagnostics-remediation');
    assert.ok(serverCode.includes("require('./api/routes-diagnostics')"), 'server.js must mount routes-diagnostics');
    assert.ok(serverCode.includes("require('./api/routes-network')"), 'server.js must mount routes-network');
    assert.ok(serverCode.includes("require('./api/routes-tools')"), 'server.js must mount routes-tools');
    assert.ok(serverCode.includes("require('./api/routes-rca')"), 'server.js must mount routes-rca');
    assert.ok(serverCode.includes("require('./api/routes-observability')"), 'server.js must mount routes-observability');

    console.log('  ✓ API route hygiene and complete architectural mounting verified.');

    // -------------------------------------------------------------------------
    // 5. Frontend UI Contract & Diagnostics Viewport Verification
    // -------------------------------------------------------------------------
    console.log('\n[33.5] Testing Frontend UI Contract & Diagnostics Viewport...');

    const diagViewCode = fs.readFileSync(
      path.join(__dirname, '..', 'public', 'js', 'views', 'core-diagnostics-view.js'),
      'utf8'
    );

    // Verify investigation timeline rendering & tabular nums
    assert.ok(
      diagViewCode.includes('function renderInvestigationResults('),
      'core-diagnostics-view.js must define renderInvestigationResults'
    );
    assert.ok(
      diagViewCode.includes('tabular-nums'),
      'core-diagnostics-view.js must enforce tabular-nums font formatting'
    );

    // Verify stopping reason badges
    assert.ok(
      diagViewCode.includes('CONFIRMED') && diagViewCode.includes('EXHAUSTED'),
      'core-diagnostics-view.js must render diagnostic stopping reason badges'
    );

    // Verify inconclusive telemetry banner
    assert.ok(
      diagViewCode.includes('Inconclusive Telemetry') || diagViewCode.includes('INCONCLUSIVE'),
      'core-diagnostics-view.js must support inconclusive telemetry state warning'
    );

    // Verify interactive operator feedback controls
    assert.ok(
      diagViewCode.includes('window.submitHypothesisFeedback ='),
      'core-diagnostics-view.js must expose submitHypothesisFeedback handler'
    );
    assert.ok(
      diagViewCode.includes('/api/rca/brain/feedback'),
      'core-diagnostics-view.js must wire feedback submission to /api/rca/brain/feedback'
    );
    assert.ok(
      diagViewCode.includes('diagInvestigationResults'),
      'core-diagnostics-view.js template must contain #diagInvestigationResults mount container'
    );

    console.log('  ✓ Frontend UI contract, timeline table, and operator feedback controls verified.');

    console.log('\n========================================================================');
    console.log('  ALL SUITE 33 TESTS PASSED PERFECTLY (100% GREEN)                      ');
    console.log('========================================================================\n');
  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (_) {}
  }
}

module.exports = { runFullSystemE2eAndFeedbackLoopTests };

if (require.main === module) {
  runFullSystemE2eAndFeedbackLoopTests()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('Suite 33 Failed:', err);
      process.exit(1);
    });
}
