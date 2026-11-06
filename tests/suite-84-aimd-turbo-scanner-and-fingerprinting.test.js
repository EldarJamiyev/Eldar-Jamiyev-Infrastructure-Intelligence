// tests/suite-84-aimd-turbo-scanner-and-fingerprinting.test.js
/**
 * EJII Test Suite 84: AIMD Turbo Scanner & Hardware Fingerprinting
 * Verifies high-speed adaptive worker pool, ARP cache ingestion, OUI resolution,
 * passive OS/device classification, and /api/network/scan-turbo endpoint.
 */

'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const { AimdTurboScanner } = require('../src/scanner/aimd-turbo-scanner');

async function runSuite84AimdTurboScannerAndFingerprinting() {
  console.log('========================================================================');
  console.log('  === [SUITE 84] AIMD TURBO SCANNER & HARDWARE FINGERPRINTING ===       ');
  console.log('========================================================================\n');

  const scanner = new AimdTurboScanner({
    initialConcurrency: 32,
    minConcurrency: 16,
    maxConcurrency: 96,
    portTimeoutMs: 150
  });

  // [84.1] OUI Hardware Vendor Resolution
  console.log('[Test 84.1] Verifying OUI Hardware Vendor resolution...');
  const ouiXiaomi = scanner.lookupOUI('50:64:2B:1A:E8:42');
  assert.ok(ouiXiaomi.includes('Xiaomi'), `Expected Xiaomi vendor, got: ${ouiXiaomi}`);

  const ouiApple = scanner.lookupOUI('F4:F5:DB:11:22:33');
  assert.ok(ouiApple.includes('Apple'), `Expected Apple vendor, got: ${ouiApple}`);

  const ouiVMware = scanner.lookupOUI('00:0C:29:AA:BB:CC');
  assert.ok(ouiVMware.includes('VMware'), `Expected VMware vendor, got: ${ouiVMware}`);

  const ouiRpi = scanner.lookupOUI('B8:27:EB:01:02:03');
  assert.ok(ouiRpi.includes('Raspberry Pi'), `Expected Raspberry Pi vendor, got: ${ouiRpi}`);

  const ouiMs = scanner.lookupOUI('00:15:5D:88:99:AA');
  assert.ok(ouiMs.includes('Microsoft'), `Expected Microsoft vendor, got: ${ouiMs}`);
  console.log('  ✓ OUI Hardware database lookups verified across major enterprise vendors.');

  // [84.2] Passive OS & Device Signature Classification
  console.log('[Test 84.2] Verifying Passive OS & Device Classification signatures...');
  const routerSig = scanner.classifyHostBySignature([53, 80], 'Xiaomi Communications Co Ltd', 'miwifi', '192.168.31.1');
  assert.strictEqual(routerSig.category, 'Gateway / Router');
  assert.ok(routerSig.osHint.includes('RouterOS') || routerSig.osHint.includes('Linux'));

  const printerSig = scanner.classifyHostBySignature([9100, 631], 'Hewlett Packard Printer', 'hp-laserjet', '192.168.31.45');
  assert.strictEqual(printerSig.category, 'Network Printer');
  assert.ok(printerSig.osHint.includes('Print Server'));

  const winSig = scanner.classifyHostBySignature([135, 445, 3389], 'Intel Corporation', 'DESKTOP-ELDAR', '192.168.31.89');
  assert.strictEqual(winSig.category, 'Windows Workstation');
  assert.ok(winSig.osHint.includes('Windows'));

  const linuxSig = scanner.classifyHostBySignature([22], 'Raspberry Pi Foundation', 'pi-node-01', '192.168.31.150');
  assert.strictEqual(linuxSig.category, 'Linux / Server');
  assert.ok(linuxSig.osHint.includes('Linux Kernel'));
  console.log('  ✓ Multi-protocol passive fingerprinting classified 4 distinct device archetypes.');

  // [84.3] Port-to-Service Mapping
  console.log('[Test 84.3] Verifying Port-to-Service mapping...');
  assert.strictEqual(scanner.mapPortToService(53), 'DNS');
  assert.strictEqual(scanner.mapPortToService(80), 'HTTP');
  assert.strictEqual(scanner.mapPortToService(443), 'HTTPS');
  assert.strictEqual(scanner.mapPortToService(445), 'SMB');
  assert.strictEqual(scanner.mapPortToService(3389), 'RDP');
  console.log('  ✓ Well-known ports mapped to human-readable RFC protocol services.');

  // [84.4] OS ARP Cache Ingestion
  console.log('[Test 84.4] Verifying OS ARP cache ingestion...');
  const arpMap = await scanner.getLocalArpCache();
  assert.ok(arpMap instanceof Map, 'getLocalArpCache must return a Map');
  console.log(`  ✓ Read ${arpMap.size} genuine physical entries from system ARP table.`);

  // [84.5] Streaming Turbo Sweep Demonstration
  console.log('[Test 84.5] Verifying high-speed streaming sweep over local loopback subnet...');
  const discovered = [];
  const scanResult = await scanner.scanSubnet('127.0.0.1/30', (host) => {
    discovered.push(host);
  });
  assert.ok(scanResult.success, 'Scan must succeed');
  assert.ok(typeof scanResult.durationMs === 'number', 'durationMs must be numeric');
  assert.ok(scanResult.totalHostsScanned >= 1, 'At least 1 host scanned');
  console.log(`  ✓ Scanned ${scanResult.totalHostsScanned} hosts in ${scanResult.durationMs}ms (Speed: ${scanResult.scanRateHostsPerSec} hosts/sec).`);

  // [84.6] Express Route Mock Verification
  console.log('[Test 84.6] Verifying Express POST /api/network/scan-turbo contract...');
  const req = {
    app: { locals: { aimdTurboScanner: scanner } },
    body: { subnet: '127.0.0.1/30' }
  };
  let responseData = null;
  const res = {
    json: (data) => { responseData = data; },
    status: () => res
  };

  const routesNetwork = require('../src/api/routes-network');
  const layer = routesNetwork.stack.find(s => s.route && Array.isArray(s.route.path) ? s.route.path.includes('/scan-turbo') : s.route?.path === '/scan-turbo');
  assert.ok(layer, 'Route /scan-turbo must be registered in routes-network.js');
  await layer.route.stack[0].handle(req, res, () => {});

  assert.ok(responseData, 'Route must respond with JSON');
  assert.strictEqual(responseData.success, true);
  assert.ok(typeof responseData.scanRateHostsPerSec === 'number');
  console.log(`  ✓ Route returned success with scan rate: ${responseData.scanRateHostsPerSec} hosts/sec.`);

  console.log('\n========================================================================');
  console.log('  SUITE 84 PASSED: AIMD TURBO SCANNER & FINGERPRINTING 100% GREEN      ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runSuite84AimdTurboScannerAndFingerprinting().catch((err) => {
    console.error('Suite 84 failed:', err);
    process.exit(1);
  });
}

module.exports = {
  runSuite84AimdTurboScannerAndFingerprinting,
  runSuite84: runSuite84AimdTurboScannerAndFingerprinting
};
