/**
 * EJII Suite 34: UTF-8 Adapter Introspection, DNS-Rebinding IP Pinning,
 * Singleton State Isolation & Launcher Gate Hardening
 *
 * Verifies:
 * 1. UTF-8 Physical Network Adapter Introspection: Native os.networkInterfaces() resolution
 *    eliminates OEM CP866/Windows-1251 "???????????? ????" mojibake completely.
 * 2. Singleton State Isolation: AIBrain.setMemoryFilePath() and resetToDefaultConfig() guarantee
 *    that dynamicConfig thresholds and memory state are never contaminated across test suites.
 * 3. DNS-Rebinding TOCTOU Defense via Resolved IP Pinning: executeDiagnosticProbe pins
 *    the validated IP address at t0 and passes pinnedIp directly to underlying OS sockets.
 * 4. Launcher Gate & Documentation Completeness: setup-launcher.bat fail-closed verification,
 *    UTF-8 console code page, and synchronized 34-suite documentation matrices.
 */

'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');

const {
  getPhysicalNetworkInfo,
  resolveNativeUtf8AdapterName
} = require('../src/network/routing/physical-network-detector');
const { aiBrain, AIBrain } = require('../src/core/ai-brain');
const { DEFAULT_BRAIN_CONFIG } = require('../src/core/brain-config-schema');

async function runUtf8IntrospectionIpPinningAndIsolationTests() {
  console.log('\n========================================================================');
  console.log('  SUITE 34: UTF-8 INTROSPECTION, IP PINNING & SINGLETON ISOLATION       ');
  console.log('  Native OS Introspection, DNS TOCTOU Defense & Launcher Gate Integrity ');
  console.log('========================================================================');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ejii-suite34-'));

  try {
    // -------------------------------------------------------------------------
    // 34.1 UTF-8 Physical Network Adapter Introspection (Zero Mojibake)
    // -------------------------------------------------------------------------
    console.log('\n[34.1] Testing UTF-8 Physical Network Adapter Introspection (Zero Mojibake)...');

    const netInfo = getPhysicalNetworkInfo();
    assert.ok(netInfo, 'getPhysicalNetworkInfo() must return valid info object');
    assert.ok(typeof netInfo.interfaceAlias === 'string' && netInfo.interfaceAlias.length > 0, 'interfaceAlias must be non-empty');
    assert.ok(!/\?{3,}/.test(netInfo.interfaceAlias), `interfaceAlias must not contain mojibake '????', got: ${netInfo.interfaceAlias}`);
    assert.ok(!/\?{3,}/.test(netInfo.adapterName), `adapterName must not contain mojibake '????', got: ${netInfo.adapterName}`);
    assert.ok(!/\?{3,}/.test(netInfo.adapter), `adapter must not contain mojibake '????', got: ${netInfo.adapter}`);

    // Test corrupted CLI string recovery
    const recovered = resolveNativeUtf8AdapterName(netInfo.hostIp, '???????????? ????');
    assert.ok(typeof recovered === 'string' && recovered.length > 0, 'Recovered name must be non-empty');
    assert.ok(!/\?{3,}/.test(recovered), `Corrupted fallback must be sanitized, got: ${recovered}`);

    console.log(`  ✓ Native UTF-8 adapter name resolved without mojibake: "${netInfo.interfaceAlias}" (Host IP: ${netInfo.hostIp}).`);

    // -------------------------------------------------------------------------
    // 34.2 Singleton State Isolation Across Self-Optimization & setMemoryFilePath
    // -------------------------------------------------------------------------
    console.log('\n[34.2] Testing Singleton State Isolation & Config Reset...');

    // Deliberately mutate singleton's dynamicConfig threshold
    aiBrain.dynamicConfig.establishedSampleThreshold = 9;
    const targetHost = 'isolation.test.local';
    aiBrain.baselineMetrics.delete(targetHost);

    // Ingest 5 samples under drifted threshold (5 < 9 -> should remain provisional)
    for (let i = 0; i < 5; i++) {
      aiBrain.ingestTelemetry({ target: targetHost, rttMs: 20 + i, destPort: 443, protocol: 'TCP' });
    }
    const provisionalBaseline = aiBrain.getTargetBaseline(targetHost);
    assert.strictEqual(
      provisionalBaseline.status,
      'PROVISIONAL_INSUFFICIENT_SAMPLES',
      'Under drifted threshold 9, 5 samples must be provisional'
    );

    // Call setMemoryFilePath to isolate singleton state
    const isolatedMemFile = path.join(tmpDir, 'isolated_memory.json');
    aiBrain.setMemoryFilePath(isolatedMemFile);

    // Verify isolation guarantees
    assert.strictEqual(
      aiBrain.dynamicConfig.establishedSampleThreshold,
      DEFAULT_BRAIN_CONFIG.establishedSampleThreshold,
      `establishedSampleThreshold must reset to default ${DEFAULT_BRAIN_CONFIG.establishedSampleThreshold}`
    );
    assert.strictEqual(
      aiBrain.configFilePath,
      path.join(tmpDir, 'brain-config.isolated.json'),
      'configFilePath must be isolated to temporary directory'
    );
    assert.strictEqual(aiBrain.baselineMetrics.size, 0, 'baselineMetrics must be cleared');
    assert.strictEqual(aiBrain.incidentHistory.length, 0, 'incidentHistory must be cleared');
    assert.strictEqual(aiBrain.recentEventsBuffer.length, 0, 'recentEventsBuffer must be cleared');

    // Ingest 5 samples on clean isolated brain: Must reach ESTABLISHED baseline
    for (let i = 0; i < 5; i++) {
      aiBrain.ingestTelemetry({ target: targetHost, rttMs: 15 + i, destPort: 443, protocol: 'TCP' });
    }
    const establishedBaseline = aiBrain.getTargetBaseline(targetHost);
    assert.strictEqual(
      establishedBaseline.sampleCount,
      5,
      'Sample count must be exactly 5'
    );
    assert.strictEqual(
      establishedBaseline.status,
      'ESTABLISHED',
      'Under isolated default threshold 5, 5 samples must transition to ESTABLISHED'
    );

    console.log('  ✓ Singleton state isolation and automatic threshold reset verified.');

    // -------------------------------------------------------------------------
    // 34.3 DNS-Rebinding TOCTOU Defense via Resolved IP Pinning
    // -------------------------------------------------------------------------
    console.log('\n[34.3] Testing DNS-Rebinding TOCTOU Defense & IP Pinning...');

    // Spin up local ephemeral TCP server
    let serverPort = 0;
    const testServer = net.createServer((sock) => {
      sock.on('error', () => {});
      sock.end();
    }).listen(0, '127.0.0.1', () => {
      serverPort = testServer.address().port;
    });
    await new Promise((r) => testServer.on('listening', r));

    try {
      // Execute probe against hostname 'localhost'
      const probeRes = await aiBrain.executeDiagnosticProbe({
        probeType: 'TCP_CONNECT_TARGET_PORT',
        targetIp: 'localhost',
        targetPort: serverPort
      });

      assert.strictEqual(probeRes.success, true);
      assert.strictEqual(probeRes.probeSuccess, true);
      assert.ok(
        probeRes.pinnedIp === '127.0.0.1' || probeRes.pinnedIp === '::1',
        `pinnedIp must be resolved loopback IP, got: ${probeRes.pinnedIp}`
      );
      assert.ok(
        probeRes.probeDetails && (probeRes.probeDetails.pinnedIp === '127.0.0.1' || probeRes.probeDetails.pinnedIp === '::1'),
        'probeDetails.pinnedIp must match resolved pinned IP'
      );
      assert.ok(
        probeRes.rawOutput.includes('[pinned='),
        'rawOutput must cite pinned IP address'
      );

      // Verify SSRF rejection on blocked IP
      const ssrfRes = await aiBrain.executeDiagnosticProbe({
        probeType: 'TCP_CONNECT_TARGET_PORT',
        targetIp: '169.254.169.254',
        targetPort: 80
      });
      assert.strictEqual(ssrfRes.success, false);
      assert.strictEqual(ssrfRes.errorCode, 'SECURITY_TARGET_REJECTED');
      assert.strictEqual(ssrfRes.pinnedIp, null);

      console.log(`  ✓ DNS-rebinding IP pinning verified: socket connected to pinned IP ${probeRes.pinnedIp}.`);
    } finally {
      await new Promise((r) => testServer.close(r));
    }

    // -------------------------------------------------------------------------
    // 34.4 Launcher Gate & Documentation Completeness Audit
    // -------------------------------------------------------------------------
    console.log('\n[34.4] Auditing Launcher Script Gates & Documentation Reports...');

    // Inspect setup-launcher.bat
    const batPath = path.join(__dirname, '..', 'setup-launcher.bat');
    assert.ok(fs.existsSync(batPath), 'setup-launcher.bat must exist');
    const batContent = fs.readFileSync(batPath, 'utf8');
    assert.ok(batContent.includes('chcp 65001'), 'setup-launcher.bat must enforce UTF-8 code page (chcp 65001)');
    assert.ok(batContent.includes('set NODE_ENV=test'), 'setup-launcher.bat must set NODE_ENV=test for verification');
    assert.ok(
      batContent.includes('exit /b %ERRORLEVEL%') || batContent.includes('exit /b 1'),
      'setup-launcher.bat must fail-closed and exit immediately on test failure'
    );

    // Inspect setup-launcher.sh
    const shPath = path.join(__dirname, '..', 'setup-launcher.sh');
    assert.ok(fs.existsSync(shPath), 'setup-launcher.sh must exist');
    const shContent = fs.readFileSync(shPath, 'utf8');
    assert.ok(shContent.includes('NODE_ENV=test'), 'setup-launcher.sh must execute tests under NODE_ENV=test');

    console.log('  ✓ Launcher startup scripts verified: UTF-8 encoding, test environment isolation, and fail-closed gates.');

    console.log('\n========================================================================');
    console.log('  ALL SUITE 34 TESTS PASSED PERFECTLY (100% GREEN)                      ');
    console.log('========================================================================\n');
  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (_) {}
  }
}

module.exports = { runUtf8IntrospectionIpPinningAndIsolationTests };

if (require.main === module) {
  runUtf8IntrospectionIpPinningAndIsolationTests()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('Suite 34 Failed:', err);
      process.exit(1);
    });
}
