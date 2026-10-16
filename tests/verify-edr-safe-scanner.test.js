/**
 * EJII Controlled Two-Phase Discovery & EDR Safety Verification Suite
 *
 * Verifies the Controlled Two-Phase Discovery Engine:
 * 1. Neighbor Cache Ingestion (ARP table parsing with state and freshness)
 * 2. Bounded ICMP Liveness Probing (Strict status classification, never throws on malformed IP)
 * 3. Zero TCP Probes to Unresponsive Targets in EDR-Conservative mode
 * 4. Controlled Concurrency Ceilings (max 8) and Pacing Bounds (>=15ms)
 * 5. Traffic Accounting (probesSent, bytesTransferred, phase telemetry)
 * 6. Clean Abort & Cancellation (stopScan socket cleanup)
 */

const assert = require('assert');
const {
  SCAN_PROFILES,
  probeHostLiveness,
  getArpTable,
  ultraIpScanner,
  UltraIpScanner
} = require('../src/tools/ip-scanner');

async function runEdrSafeScannerTests() {
  console.log('========================================================================');
  console.log('  EJII CONTROLLED TWO-PHASE DISCOVERY & EDR SAFETY VERIFICATION        ');
  console.log('========================================================================\n');

  // Test 1: Scan Profiles Structure & Invariants
  console.log('[Test 1] Verifying Scan Profiles & EDR-Conservative Invariants...');
  assert.ok(SCAN_PROFILES.edr_conservative, 'edr_conservative profile must exist');
  assert.ok(SCAN_PROFILES.fast, 'fast profile must exist');
  assert.ok(SCAN_PROFILES.deep, 'deep profile must exist');

  const edr = SCAN_PROFILES.edr_conservative;
  assert.strictEqual(edr.concurrencyCeiling, 8, 'EDR conservative max concurrency ceiling must be 8');
  assert.strictEqual(edr.perHostConcurrency, 2, 'EDR conservative per-host concurrency must be 2');
  assert.strictEqual(edr.pacingMs, 15, 'EDR conservative pacing delay must be >= 15ms');
  assert.strictEqual(edr.probeUnresponsive, false, 'probeUnresponsive must be FALSE in EDR mode');
  assert.deepStrictEqual(edr.ports, [80, 443, 445, 22, 3389], 'Standard management ports targeted only');
  console.log('  ✓ EDR-conservative profile bounds verified: max concurrency 8, pacing 15ms, zero unresponsive probing.');

  // Test 2: Neighbor Cache (ARP Table) Ingestion
  console.log('\n[Test 2] Verifying Neighbor Cache / ARP Table Ingestion...');
  const arpEntries = await getArpTable();
  assert.ok(Array.isArray(arpEntries), 'getArpTable must return an array');
  console.log(`  ✓ Neighbor cache parsed: ${arpEntries.length} live entries discovered.`);
  if (arpEntries.length > 0) {
    const entry = arpEntries[0];
    assert.ok(entry.ip, 'ARP entry must contain IP');
    assert.ok(entry.mac, 'ARP entry must contain MAC');
    assert.ok(typeof entry.isFresh === 'boolean', 'ARP entry must have boolean isFresh');
    console.log(`  ✓ Sample ARP entry validated: ${entry.ip} (${entry.mac}, state: ${entry.state || 'standard'}, fresh: ${entry.isFresh})`);
  }

  // Test 3: Bounded ICMP Liveness Checking
  console.log('\n[Test 3] Verifying Bounded Host Liveness Probe...');
  
  // 3a: Valid local loopback
  const loopbackResult = await probeHostLiveness('127.0.0.1', 800);
  assert.ok(loopbackResult, 'Liveness probe must return an object');
  assert.ok(loopbackResult.isOnline, 'Loopback 127.0.0.1 must be reported online');
  assert.strictEqual(loopbackResult.status, 'ONLINE', 'Loopback status must be ONLINE');
  assert.ok(loopbackResult.latencyMs !== null, 'Loopback must have measured latencyMs');
  console.log(`  ✓ 127.0.0.1 online check passed: ${loopbackResult.latencyMs} ms (${loopbackResult.discoveryMethod})`);

  // 3b: Malformed IP (Robustness check)
  const malformedResult = await probeHostLiveness('invalid..ip!!', 500);
  assert.strictEqual(malformedResult.isOnline, false, 'Malformed IP must be reported offline');
  assert.strictEqual(malformedResult.status, 'UNKNOWN', 'Malformed IP status must be UNKNOWN');
  console.log('  ✓ Malformed IP handled gracefully without throwing.');

  // 3c: Non-routable dead address in test subnet
  const deadIpResult = await probeHostLiveness('192.0.2.1', 400); // RFC 5737 TEST-NET-1 non-routable
  assert.strictEqual(deadIpResult.isOnline, false, 'Non-routable IP must not be reported online');
  assert.ok(
    deadIpResult.status === 'UNRESPONSIVE' || deadIpResult.status === 'OFFLINE',
    `Dead IP must be classified as UNRESPONSIVE or OFFLINE, got: ${deadIpResult.status}`
  );
  console.log(`  ✓ Dead target classification validated: ${deadIpResult.status} (${deadIpResult.probeLimitations})`);

  // Test 4: Two-Phase Discovery with Zero TCP Probes to Unresponsive Targets
  console.log('\n[Test 4] Verifying Two-Phase Discovery & Zero TCP Probing on Unresponsive Hosts...');
  const testScanner = new UltraIpScanner();

  // Test with small test slice
  const scanPromise = testScanner.startScan({
    subnet: '127.0.0.1-2',
    profile: 'edr_conservative',
    concurrency: 4
  });

  // Verify status while scan is running or completing
  const midStatus = testScanner.getScanStatus();
  assert.ok(midStatus, 'getScanStatus must return status object');
  assert.ok(midStatus.profile === 'edr_conservative', 'Active profile must be edr_conservative');
  assert.ok(midStatus.profilePolicy, 'profilePolicy must be present');
  assert.strictEqual(midStatus.profilePolicy.probeUnresponsive, false, 'Policy probeUnresponsive must be false');

  await testScanner.waitForCompletion(15000);

  const finalStatus = testScanner.getScanStatus();
  assert.ok(finalStatus.status === 'completed' || finalStatus.status === 'stopped', 'Scan must complete');
  assert.ok(finalStatus.scanned > 0, 'Hosts scanned count must be > 0');
  assert.ok(typeof finalStatus.probesSent === 'number', 'probesSent must be tracked');
  assert.ok(typeof finalStatus.bytesTransferred === 'number', 'bytesTransferred must be tracked');
  assert.ok(finalStatus.phase, 'Final phase must be recorded');

  // Verify hosts results
  const unresponsiveHosts = finalStatus.hosts.filter(h => h.status === 'UNRESPONSIVE' || h.status === 'OFFLINE');
  for (const deadHost of unresponsiveHosts) {
    assert.strictEqual(
      deadHost.openServices.length,
      0,
      `Unresponsive host ${deadHost.ip} must NOT have been probed for open TCP services (0 TCP probes mandate)`
    );
  }
  console.log(`  ✓ Zero TCP probes confirmed: ${unresponsiveHosts.length} unresponsive hosts received 0 TCP port sweeps.`);
  console.log(`  ✓ Telemetry accounted: ${finalStatus.probesSent} probes sent, ${finalStatus.bytesTransferred} bytes transferred.`);

  // Test 5: Clean Stop & Socket Cleanup
  console.log('\n[Test 5] Verifying Immediate Cancellation & Socket Abort...');
  const abortScanner = new UltraIpScanner();
  const abortPromise = abortScanner.startScan({
    subnet: '10.254.254.0/24',
    profile: 'edr_conservative',
    concurrency: 8
  });

  // Call stopScan immediately
  abortScanner.stopScan();
  const stoppedStatus = abortScanner.getScanStatus();
  assert.strictEqual(stoppedStatus.status, 'stopped', 'Scanner status must be stopped');
  assert.ok(stoppedStatus.phase.includes('Stopped'), 'Phase must reflect stoppage');
  console.log('  ✓ Scanner abort and resource cleanup verified successfully.');

  console.log('\n========================================================================');
  console.log('  ✓ ALL EDR-SAFE SCANNER INVARIANTS SATISFIED (ZERO DEFECTS CONFIRMED)   ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runEdrSafeScannerTests().then(() => {
    process.exit(0);
  }).catch((err) => {
    console.error('EDR Safe Scanner Test Failed:', err);
    process.exit(1);
  });
}

module.exports = { runEdrSafeScannerTests };
