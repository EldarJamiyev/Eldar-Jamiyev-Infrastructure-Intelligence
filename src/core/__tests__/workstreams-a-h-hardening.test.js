'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const express = require('express');
const { DatabaseSync } = require('node:sqlite');

const { db, initSchema } = require('../../db/database');
const { seedDatabase } = require('../../db/seed');
const { verifyChainIntegrity } = require('../audit-logger');
const { calculateSubnet } = require('../../network/routing/physical-network-detector');
const { GeoPartitionCrdtEngine } = require('../multisite/geo-partition-crdt-engine');
const { AIModelOrchestrator } = require('../ai-model-orchestrator');
const { chatOperatorService } = require('../chat/chat-operator-service');
const { crossLayerIncidentCorrelator } = require('../correlation/incident-correlator');
const { probeNodeDual } = require('../../protocols/dual-prober');
const { generateToken } = require('../security');
const v6FabricRouter = require('../../api/routes-v6-fabric');
const enterpriseRouter = require('../../api/routes-enterprise');

function invokeExpressApp(app, { method = 'GET', url = '/', headers = {}, body = null }) {
  return new Promise((resolve, reject) => {
    const server = http.createServer(app);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      const payload = body !== null ? JSON.stringify(body) : null;
      const reqHeaders = {
        ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}),
        ...headers
      };
      const req = http.request(
        {
          hostname: '127.0.0.1',
          port: addr.port,
          path: url,
          method,
          headers: reqHeaders
        },
        (res) => {
          let raw = '';
          res.on('data', (chunk) => { raw += chunk; });
          res.on('end', () => {
            server.close(() => {
              let json = null;
              try { json = JSON.parse(raw); } catch (_) {}
              resolve({ status: res.statusCode, body: json, raw });
            });
          });
        }
      );
      req.on('error', (err) => {
        server.close(() => reject(err));
      });
      if (payload) req.write(payload);
      req.end();
    });
  });
}

describe('Workstreams A-H Production Hardening Suite', () => {
  it('WS-A: Seeded topology starts unprobed and genesis audit_logs passes verifyChainIntegrity()', () => {
    initSchema();
    seedDatabase();

    const lan = db.prepare("SELECT status, last_checked FROM topology_nodes WHERE id = 'NODE-LAN-01'").get();
    const host = db.prepare("SELECT status, last_checked FROM topology_nodes WHERE id = 'NODE-HOST-01'").get();
    assert.ok(lan && host, 'NODE-LAN-01 and NODE-HOST-01 must exist after seedDatabase()');
    assert.strictEqual(lan.status, 'unprobed');
    assert.strictEqual(lan.last_checked, null);
    assert.strictEqual(host.status, 'unprobed');
    assert.strictEqual(host.last_checked, null);

    const auditCheck = verifyChainIntegrity();
    assert.strictEqual(auditCheck.valid, true, `Genesis audit chain must validate cleanly: ${auditCheck.message}`);
    assert.ok(auditCheck.recordsChecked >= 1);
    assert.strictEqual(typeof auditCheck.details, 'string');
  });

  it('WS-A: calculateSubnet supports /0 and rejects invalid/empty IPv4 without falling back to 127.0.0.1', () => {
    const slashZero = calculateSubnet('10.20.30.40', 0);
    assert.ok(slashZero);
    assert.strictEqual(slashZero.prefixLength, 0);
    assert.strictEqual(slashZero.networkAddress, '0.0.0.0');
    assert.strictEqual(slashZero.subnetMask, '0.0.0.0');

    assert.strictEqual(calculateSubnet(''), null);
    assert.strictEqual(calculateSubnet(null), null);
    assert.strictEqual(calculateSubnet('999.1.2.3', 24), null);
    assert.strictEqual(calculateSubnet('not-an-ip', 24), null);
  });

  it('WS-B: GeoPartitionCrdtEngine rolls back both SQLite and in-memory state on persistence failure', () => {
    const tmpDbFile = path.join(os.tmpdir(), `ejii-crdt-rollback-${Date.now()}.sqlite`);
    const sqliteDb = new DatabaseSync(tmpDbFile);
    try {
      const crdt = new GeoPartitionCrdtEngine('site-primary-rb', { dbHandle: sqliteDb });
      crdt.incrementCounter('flow_count', 5);
      const clockBefore = crdt.getVectorClock();

      // Wrap prepare to simulate SQLite write failure inside reconciliation transaction
      const origPrepare = sqliteDb.prepare.bind(sqliteDb);
      sqliteDb.prepare = (sql) => {
        if (/INSERT\s+INTO\s+ejii_crdt_delta_records/i.test(sql)) {
          const stmt = origPrepare(sql);
          return {
            ...stmt,
            run(...args) {
              if (args[1] === 'RECONCILIATION') {
                throw new Error('SIMULATED_DISK_IO_FAILURE');
              }
              return stmt.run(...args);
            }
          };
        }
        return origPrepare(sql);
      };

      const failReport = crdt.reconcileWithRemotePartition('region-eu-west', { 'region-eu-west': 3 }, [
        {
          crdtType: 'PN_COUNTER',
          key: 'flow_count',
          operation: 'MERGE',
          deltaPayload: { positive: { 'region-eu-west': 9 }, negative: {} }
        }
      ]);

      assert.strictEqual(failReport.convergenceStatus, 'SQLITE_PERSISTENCE_FAILED');
      assert.strictEqual(crdt.getCounterValue('flow_count'), 5, 'In-memory counter must roll back on DB failure');
      assert.deepStrictEqual(crdt.getVectorClock(), clockBefore, 'Vector clock must roll back on DB failure');
      const diag = crdt.getPersistenceDiagnostics();
      assert.strictEqual(diag.persistenceState, 'SQLITE_DEGRADED');

      // Restore normal SQLite handle and verify real convergence persists cleanly
      sqliteDb.prepare = origPrepare;
      const okReport = crdt.reconcileWithRemotePartition('region-eu-west', { 'region-eu-west': 3 }, [
        {
          crdtType: 'PN_COUNTER',
          key: 'flow_count',
          operation: 'MERGE',
          deltaPayload: { positive: { 'region-eu-west': 9 }, negative: {} }
        }
      ]);
      assert.strictEqual(okReport.convergenceStatus, 'CONVERGED');
      assert.strictEqual(crdt.getCounterValue('flow_count'), 14);
    } finally {
      sqliteDb.close();
      for (const suffix of ['', '-wal', '-shm']) {
        try { fs.unlinkSync(tmpDbFile + suffix); } catch (_) {}
      }
    }
  });

  it('WS-B & WS-G: v6 API routes reject self/vacuous CRDT sync, missing correlate target, and SSRF targets fail-closed', async () => {
    const app = express();
    app.use(express.json());
    app.use('/api/v6', v6FabricRouter);
    app.use('/api/enterprise', enterpriseRouter);

    const adminToken = generateToken({ id: 'USR-ADMIN-1', username: 'admin', role: 'ADMIN' });
    const authHdr = { Authorization: `Bearer ${adminToken}` };

    const missingTargetRes = await invokeExpressApp(app, {
      method: 'POST',
      url: '/api/v6/correlate',
      headers: authHdr,
      body: {}
    });
    assert.strictEqual(missingTargetRes.status, 400);
    assert.strictEqual(missingTargetRes.body.error.code, 'VALIDATION_FAILED');

    const ssrfRes = await invokeExpressApp(app, {
      method: 'POST',
      url: '/api/v6/correlate',
      headers: authHdr,
      body: { target: '169.254.169.254' }
    });
    assert.strictEqual(ssrfRes.status, 400);
    assert.strictEqual(ssrfRes.body.error.code, 'SECURITY_VIOLATION_SSRF');

    const crdtMissingRes = await invokeExpressApp(app, {
      method: 'POST',
      url: '/api/v6/sovereign/crdt/reconcile',
      headers: authHdr,
      body: {}
    });
    assert.strictEqual(crdtMissingRes.status, 400);
    assert.strictEqual(crdtMissingRes.body.error.code, 'INVALID_TARGET_PARTITION');

    const crdtVacuousRes = await invokeExpressApp(app, {
      method: 'POST',
      url: '/api/v6/sovereign/crdt/reconcile',
      headers: authHdr,
      body: { targetPartition: 'region-ap-test' }
    });
    assert.strictEqual(crdtVacuousRes.status, 409);
    assert.strictEqual(crdtVacuousRes.body.error.code, 'NO_REMOTE_DELTAS_AVAILABLE');

    const unauthTimelineRes = await invokeExpressApp(app, {
      method: 'GET',
      url: '/api/enterprise/memory/timeline'
    });
    assert.strictEqual(unauthTimelineRes.status, 401);
  });

  it('WS-C & WS-D: AIModelOrchestrator never claims Gemini is OPERATIONAL unprobed, and Chat handles natural follow-ups & honest CRDT reporting', async () => {
    const prevKey = process.env.GEMINI_API_KEY;
    process.env.GEMINI_API_KEY = 'dummy-test-key-unprobed';
    try {
      const orch = new AIModelOrchestrator();
      assert.strictEqual(orch.providers.google_gemini.adapterStatus, 'CONFIGURED_UNPROBED');
      assert.strictEqual(orch.providers.google_gemini.model, 'gemini-4-hydrogen');
    } finally {
      if (prevKey === undefined) delete process.env.GEMINI_API_KEY;
      else process.env.GEMINI_API_KEY = prevKey;
    }

    const s1 = chatOperatorService.getOrCreateSession(`ws-cd-conv-${Date.now()}`, 'admin');
    const slowPlan = chatOperatorService.parseIntentAndEntities('The internet is slow.', s1);
    assert.strictEqual(slowPlan.intent, 'local_path_diagnostic');

    s1.lastTarget = 'example.org';
    s1.lastValidTarget = 'example.org';
    s1.lastTargetTimestampMs = Date.now();
    s1.targetHistory = ['alpha.internal', 'example.org'];
    s1.lastStructuredAnswer = { result: 'Connection timed out on example.org:443' };
    s1.lastSteps = [{ tool: 'tcp', label: 'TCP/443', status: 'FAIL', summary: 'ETIMEDOUT' }];

    const whyPlan = chatOperatorService.parseIntentAndEntities('Why is it responding like that?', s1);
    assert.strictEqual(whyPlan.intent, 'follow_up_explanation');

    const otherPlan = chatOperatorService.parseIntentAndEntities('No, I meant the other machine', s1);
    assert.strictEqual(otherPlan.target, 'alpha.internal');

    const crdtOut = await chatOperatorService._executeCrdtWanReconcileScenario(
      { targetPartition: 'region-eu-unconverged', syncMode: 'delta' },
      s1,
      null
    );
    assert.strictEqual(crdtOut.structuredAnswer.convergenceStatus, 'NO_REMOTE_DELTAS_AVAILABLE');
    assert.strictEqual(crdtOut.steps[0].status, 'WARN');
  });

  it('WS-E, WS-F & WS-H: incidentCorrelator fails closed without target, dualProber measures loopback latency, initSchema restores foreign_keys=ON', async () => {
    assert.throws(
      () => crossLayerIncidentCorrelator.correlateSignals({}),
      (err) => err && err.code === 'INVALID_CORRELATION_TARGET'
    );

    const loopbackProbe = await probeNodeDual({ id: 'NODE-HOST-01', hostname_or_ip: '127.0.0.1', type: 'host' });
    assert.strictEqual(loopbackProbe.success, true);
    assert.ok(typeof loopbackProbe.latencyMs === 'number' && loopbackProbe.latencyMs > 0);
    assert.notStrictEqual(loopbackProbe.probeType, 'loopback');

    const executedSql = [];
    const failingDb = {
      _ejiiSchemaInitialized: false,
      exec(sql) {
        executedSql.push(String(sql).trim());
        if (/CREATE TABLE IF NOT EXISTS audit_logs/i.test(sql)) {
          throw new Error('SIMULATED_SCHEMA_ERROR');
        }
      }
    };
    assert.throws(
      () => initSchema(failingDb, { force: true }),
      /SIMULATED_SCHEMA_ERROR/
    );
    assert.strictEqual(executedSql[0], 'PRAGMA foreign_keys = OFF;');
    assert.strictEqual(executedSql[executedSql.length - 1], 'PRAGMA foreign_keys = ON;');
  });

  it('WS-B & WS-C: OperationalMemoryEngine computes Welford online baselines & z-scores, and HypothesisArbiter registers EVD-* evidence records', async () => {
    const { OperationalMemoryEngine } = require('../memory/operational-memory-engine');
    const { hypothesisArbiter } = require('../../ai/hypothesis-arbiter');
    const mem = new OperationalMemoryEngine({ useSqlite: false });

    const b1 = mem.updateWelfordBaseline('edge-gw.internal', 10);
    assert.strictEqual(b1.sampleCount, 1);
    assert.strictEqual(b1.avgRttMs, 10);
    assert.strictEqual(b1.zScore, null);

    const b2 = mem.updateWelfordBaseline('edge-gw.internal', 12);
    assert.strictEqual(b2.sampleCount, 2);
    assert.strictEqual(b2.avgRttMs, 11);
    assert.ok(b2.stdDevMs > 0);

    const b3 = mem.updateWelfordBaseline('edge-gw.internal', 48);
    assert.strictEqual(b3.sampleCount, 3);
    assert.ok(b3.zScore > 2.5, `Expected spike zScore > 2.5, got ${b3.zScore}`);
    assert.strictEqual(b3.isSpike, true);

    const arb = await hypothesisArbiter.arbitrateAndExecuteClosedLoop({
      target: '127.0.0.1',
      port: 3000,
      symptoms: ['latency_spike'],
      maxClosedLoopSteps: 2
    });
    assert.ok(Array.isArray(arb.evidenceIds) && arb.evidenceIds.length >= 1, 'Closed-loop arbitration must register EVD-* IDs');
    assert.ok(arb.evidenceIds.every((id) => String(id).startsWith('EVD-')));
  });

  it('WS-G & Login Glassmorphism: #loginScreen preserves 100% of authentication IDs/handlers while enforcing frosted-glass pill layout', () => {
    const htmlPath = path.resolve(__dirname, '../../../public/index.html');
    const cssPath = path.resolve(__dirname, '../../../public/css/ejii-meridian.css');
    const appJsPath = path.resolve(__dirname, '../../../public/js/app.js');

    const html = fs.readFileSync(htmlPath, 'utf8');
    const css = fs.readFileSync(cssPath, 'utf8');
    const appJs = fs.readFileSync(appJsPath, 'utf8');

    // Critical Preservation Rule checks
    const requiredIds = [
      'id="loginScreen"',
      'id="loginForm"',
      'id="loginUsername"',
      'id="loginPassword"',
      'id="btnSubmitLogin"',
      'id="loginBtnText"',
      'id="loginErrorAlert"',
      'id="loginErrorMessage"',
      'id="evaluationLoginPills"',
      'id="loginRolePills"',
      'id="pill-admin"',
      'id="pill-sysadmin"',
      'id="pill-netadmin"',
      'id="pill-noc"',
      'id="evaluationQuickCta"',
      'id="evaluationLoginDivider"',
      'id="loginTelemetryBar"',
      'id="loginTelHost"',
      'id="loginTelGateway"',
      'id="loginTelSubnet"',
      'id="loginTelDriver"',
      'id="btnTogglePassword"',
      'id="loginRememberMe"',
      'id="btnForgotPassword"'
    ];
    for (const token of requiredIds) {
      assert.ok(html.includes(token), `public/index.html must preserve ${token}`);
    }
    assert.ok(html.includes('window.handleLoginFormSubmit(event)'));
    assert.ok(html.includes('window.quickNocLogin()'));
    assert.ok(html.includes('window.toggleLoginPasswordVisibility()'));

    // Visual & Layout Design checks in CSS & JS
    assert.ok(css.includes('#050811'), 'Atmospheric base must use deep obsidian-midnight #050811');
    assert.ok(css.includes('backdrop-filter: blur(22px) saturate(165%)'), 'Frosted glass card must use blur(22px) saturate(165%)');
    assert.ok(css.includes('border-radius: 9999px'), 'Inputs and primary CTA button must use pill border-radius: 9999px');
    assert.ok(appJs.includes('window.toggleLoginPasswordVisibility = function'));
    assert.ok(appJs.includes('window.handleForgotPasswordClick = function'));
  });
});

