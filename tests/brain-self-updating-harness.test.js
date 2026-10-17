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

    console.log('\n========================================================================');
    console.log('  ALL 5 AI BRAIN SELF-UPDATING HARNESS TESTS PASSED (100% GREEN)        ');
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
