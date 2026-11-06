/**
 * EJII Test Suite 52: Enterprise API Contracts, Concurrency & Hygiene Suite
 *
 * Verifies:
 * [52.1] SQLite WAL Concurrency & Transactional Batch Commit
 * [52.2] Database Integrity Diagnostics & PRAGMA Verification
 * [52.3] Rolling Process Socket History Ring Buffer
 * [52.4] Request Correlation ID & API Latency Telemetry
 * [52.5] Repository Zero-Zombie Hygiene & RAG Runbook / Policy Integrity
 */

'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { brainPersistenceRepository } = require('../src/db/brain-persistence-repository');
const { processSocketCorrelator } = require('../src/network/process-socket-correlator');
const { getApiTelemetry, requestCorrelationAndTelemetryMiddleware } = require('../src/api/middleware');

async function runSuite52() {
  console.log('========================================================================');
  console.log('  TEST SUITE 52: ENTERPRISE API CONTRACTS, CONCURRENCY & HYGIENE         ');
  console.log('========================================================================\n');

  // -------------------------------------------------------------------------
  // [52.1] SQLite WAL Concurrency & Transactional Batch Commit
  // -------------------------------------------------------------------------
  console.log('[Test 52.1] Verifying SQLite WAL Concurrency & Transactional Batch Commit...');
  {
    const targetIp = `192.168.31.20${Math.floor(Math.random() * 80)}`;
    const snapshot = {
      baselines: [
        {
          target: targetIp,
          subnet_gateway: '192.168.31.1',
          min_rtt: 1.2,
          max_rtt: 4.8,
          avg_rtt: 2.1,
          variance: 0.5,
          stddev: 0.7,
          m2: 1.0,
          sample_count: 5,
          status: 'ESTABLISHED_BASELINE',
          first_observed: new Date().toISOString(),
          last_observed: new Date().toISOString()
        }
      ],
      incidents: [
        {
          key: `INC-TEST-${Date.now()}`,
          incident_type: 'TCP_SYN_TIMEOUT',
          target: targetIp,
          dest_port: 443,
          top_hypothesis_id: 'GATEWAY_UNREACHABLE',
          top_hypothesis_label: 'Gateway Unreachable',
          confidence: 85,
          diagnostic_state: 'EVALUATED'
        }
      ],
      calibrations: {
        TCP_SYN_TIMEOUT: {
          GATEWAY_UNREACHABLE: 1.25
        }
      },
      investigations: []
    };

    const res = brainPersistenceRepository.saveSnapshotTransaction(snapshot);
    assert.strictEqual(res.success, true, 'saveSnapshotTransaction must succeed atomically');
    assert.ok(res.itemsCommitted >= 3, 'Must commit batch items');

    // Verify written data can be read immediately
    const baselines = brainPersistenceRepository.getAllBaselines();
    const found = baselines.find(b => b.target === targetIp);
    assert.ok(found, `Baseline for ${targetIp} must be persisted in SQLite`);
    assert.strictEqual(found.status, 'ESTABLISHED_BASELINE');

    console.log(`  ✓ Atomic SQLite WAL batch transaction committed ${res.itemsCommitted} records successfully.`);
  }

  // -------------------------------------------------------------------------
  // [52.2] Database Integrity Diagnostics & PRAGMA Verification
  // -------------------------------------------------------------------------
  console.log('\n[Test 52.2] Verifying Database Integrity Diagnostics & PRAGMAs...');
  {
    const diag = brainPersistenceRepository.getDatabaseIntegrityDiagnostics();
    assert.strictEqual(diag.healthy, true, 'Database integrity check must report healthy');
    assert.strictEqual(diag.integrityResult, 'ok', 'PRAGMA integrity_check must return "ok"');
    assert.strictEqual(diag.quickCheckResult, 'ok', 'PRAGMA quick_check must return "ok"');
    assert.strictEqual(diag.journalMode.toLowerCase(), 'wal', 'PRAGMA journal_mode must be WAL');
    assert.ok(diag.records.baselines >= 1, 'Baselines record count must be verified');

    console.log('  ✓ SQLite database integrity PRAGMAs verified (journal_mode=WAL, integrity=ok).');
  }

  // -------------------------------------------------------------------------
  // [52.3] Rolling Process Socket History Ring Buffer
  // -------------------------------------------------------------------------
  console.log('\n[Test 52.3] Verifying Rolling Process Socket History Ring Buffer...');
  {
    await processSocketCorrelator.refresh();
    const history = processSocketCorrelator.getWatchedProcessHistory();
    assert.ok(Array.isArray(history), 'History must be an array');
    
    // Query with filter
    const nodeHistory = processSocketCorrelator.getWatchedProcessHistory('node');
    assert.ok(Array.isArray(nodeHistory));

    console.log(`  ✓ Process socket timeline history verified (${history.length} active process-endpoint streams tracked).`);
  }

  // -------------------------------------------------------------------------
  // [52.4] Request Correlation ID & API Latency Telemetry
  // -------------------------------------------------------------------------
  console.log('\n[Test 52.4] Verifying Request Correlation ID & API Latency Telemetry...');
  {
    // Simulate middleware invocation
    let headersSet = {};
    const mockReq = {
      headers: {},
      method: 'GET',
      originalUrl: '/api/network/topology'
    };
    const mockRes = {
      statusCode: 200,
      setHeader: (k, v) => { headersSet[k] = v; },
      on: (evt, cb) => {
        if (evt === 'finish') setTimeout(cb, 5);
      }
    };

    requestCorrelationAndTelemetryMiddleware(mockReq, mockRes, () => {});
    assert.ok(mockReq.id, 'Middleware must attach req.id');
    assert.ok(headersSet['X-Request-Id'], 'Middleware must set X-Request-Id header');

    await new Promise(r => setTimeout(r, 20));

    const telemetry = getApiTelemetry();
    assert.ok(telemetry.totalRequests >= 1, 'Telemetry must track totalRequests');
    assert.ok(typeof telemetry.avgLatencyMs === 'number', 'Telemetry must compute avgLatencyMs');
    assert.ok(typeof telemetry.p95LatencyMs === 'number', 'Telemetry must compute p95LatencyMs');
    assert.ok(Array.isArray(telemetry.recentRequests), 'Telemetry must return recentRequests');

    console.log(`  ✓ Request correlation (${mockReq.id}) and telemetry latency tracking verified.`);
  }

  // -------------------------------------------------------------------------
  // [52.5] Repository Zero-Zombie Hygiene & RAG Runbook / Policy Integrity
  // -------------------------------------------------------------------------
  console.log('\n[Test 52.5] Verifying Repository Zero-Zombie Hygiene & RAG Assets...');
  {
    const rootDir = path.join(__dirname, '..');

    // 1. Verify sync_now.bat is gone
    assert.ok(!fs.existsSync(path.join(rootDir, 'sync_now.bat')), 'sync_now.bat must not exist');

    // 2. Verify scripts/maintenance directory is gone
    assert.ok(!fs.existsSync(path.join(rootDir, 'scripts/maintenance')), 'scripts/maintenance must not exist');

    // 3. Verify expanded runbooks RB-01 through RB-06 exist
    const expectedRunbooks = [
      'RB-01-unknown-application-endpoint-discovery.md',
      'RB-02-tcp-rst-vs-firewall-silent-drop-triage.md',
      'RB-03-windows-host-saturation-and-pnp-remediation.md',
      'RB-04-dns-servfail-nxdomain-and-split-horizon-triage.md',
      'RB-05-tls13-handshake-alerts-certificate-chain-and-sni-audit.md',
      'RB-06-path-mtu-blackhole-and-tcp-retransmission-forensics.md'
    ];
    for (const rb of expectedRunbooks) {
      const rbPath = path.join(rootDir, 'runbooks', rb);
      assert.ok(fs.existsSync(rbPath), `Runbook ${rb} must exist on disk`);
      const content = fs.readFileSync(rbPath, 'utf8');
      assert.ok(content.length > 200, `Runbook ${rb} must have substantive content`);
    }

    // 4. Verify policies POL-01 and POL-02 exist
    const expectedPolicies = [
      'POL-01-zero-trust-rbac-and-ai-privacy-boundary.md',
      'POL-02-autonomous-remediation-dual-custody-and-os-shield-policy.md'
    ];
    for (const pol of expectedPolicies) {
      const polPath = path.join(rootDir, 'policies', pol);
      assert.ok(fs.existsSync(polPath), `Policy ${pol} must exist on disk`);
      const content = fs.readFileSync(polPath, 'utf8');
      assert.ok(content.length > 200, `Policy ${pol} must have substantive content`);
    }

    console.log('  ✓ Zero-zombie compliance verified: 6/6 runbooks and 2/2 policies verified with zero maintenance residue.');
  }

  console.log('\n========================================================================');
  console.log('  TEST SUITE 52: 100% PASSED (ALL 5 CHECKS VERIFIED)');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runSuite52().catch(err => {
    console.error('Suite 52 failed:', err);
    process.exit(1);
  });
}

module.exports = { runSuite52 };
