// tests/suite-93-hardware-wifi-and-kernel-tcp-inspector.test.js
/**
 * EJII Test Suite 93: Physical Wi-Fi Radio & Windows Kernel TCP Stack Inspector
 * Verifies unprivileged hardware inspection of 802.11 PHY parameters (SSID, BSSID, Signal %, Band, Rx/Tx Mbps),
 * Windows TCP stack auto-tuning, congestion provider, ECN, RSS, RSC, and /api/diagnostics/kernel-radio-inspector.
 */

'use strict';

const assert = require('node:assert/strict');
const os = require('node:os');
const { HardwareKernelInspector } = require('../src/diagnostics/hardware-kernel-inspector');
const routesDiagnostics = require('../src/api/routes-diagnostics');

async function runSuite93HardwareKernelInspector() {
  console.log('========================================================================');
  console.log('  === [SUITE 93] PHYSICAL RADIO & KERNEL TCP STACK INSPECTOR ===        ');
  console.log('========================================================================\n');

  // [93.1] Hardware Kernel Inspection Execution
  console.log('[Test 93.1] Inspecting host radio and kernel network stack parameters...');
  const report = HardwareKernelInspector.inspect();

  assert.ok(report, 'Inspection report must be returned');
  assert.ok(typeof report.inspectedAt === 'string');
  assert.strictEqual(report.hostName, os.hostname());
  assert.strictEqual(report.osPlatform, os.platform());
  assert.ok(report.rawInspectionStatus === 'LIVE_OS_TELEMETRY' || report.rawInspectionStatus === 'DETERMINISTIC_FALLBACK');
  console.log(`  ✓ Host inspected: ${report.hostName} (${report.osPlatform} ${report.osRelease}), Status=${report.rawInspectionStatus}`);

  // [93.2] Physical Wi-Fi Radio Telemetry
  console.log('[Test 93.2] Validating physical 802.11 radio telemetry structures...');
  const radio = report.radio;
  assert.ok(radio, 'Radio object must be present');
  assert.ok(typeof radio.interfaceName === 'string');
  assert.ok(['Wi-Fi 802.11ax/ac', 'Gigabit Ethernet', 'Loopback', 'Virtual Adapter'].includes(radio.interfaceType));
  assert.ok(['2.4 GHz', '5 GHz', '6 GHz', 'Wired', 'Unknown'].includes(radio.radioBand));
  assert.ok(typeof radio.signalQualityPct === 'number' && radio.signalQualityPct >= 0 && radio.signalQualityPct <= 100);
  assert.ok(typeof radio.rxRateMbps === 'number' && radio.rxRateMbps >= 0);
  assert.ok(typeof radio.txRateMbps === 'number' && radio.txRateMbps >= 0);
  console.log(`  ✓ Physical Radio: Interface="${radio.interfaceName}", Type=${radio.interfaceType}, Band=${radio.radioBand}, Signal=${radio.signalQualityPct}%, Rx/Tx=${radio.rxRateMbps}/${radio.txRateMbps} Mbps`);

  // [93.3] Windows Kernel TCP Stack Parameters
  console.log('[Test 93.3] Validating kernel TCP/IP auto-tuning and congestion parameters...');
  const tcp = report.kernelTcp;
  assert.ok(tcp, 'Kernel TCP parameters must be present');
  assert.ok(typeof tcp.autoTuningLevel === 'string');
  assert.ok(typeof tcp.congestionControlProvider === 'string');
  assert.ok(['enabled', 'disabled'].includes(tcp.ecnCapability));
  assert.ok(['enabled', 'disabled'].includes(tcp.receiveSideScalingRss));
  assert.ok(['enabled', 'disabled'].includes(tcp.receiveSegmentCoalescingRsc));
  assert.ok(Array.isArray(tcp.activeDnsServers));
  assert.ok(tcp.mtu >= 576 && tcp.mtu <= 9000);
  console.log(`  ✓ Kernel TCP: AutoTuning=${tcp.autoTuningLevel}, CongestionProvider=${tcp.congestionControlProvider}, ECN=${tcp.ecnCapability}, RSS=${tcp.receiveSideScalingRss}, RSC=${tcp.receiveSegmentCoalescingRsc}, MTU=${tcp.mtu}`);

  // [93.4] REST API Endpoint: GET /api/diagnostics/kernel-radio-inspector
  console.log('[Test 93.4] Testing GET /api/diagnostics/kernel-radio-inspector via router stack...');
  const layer = routesDiagnostics.stack.find(s => s.route && s.route.path === '/kernel-radio-inspector');
  assert.ok(layer, 'Route GET /kernel-radio-inspector must exist in routes-diagnostics.js');

  let jsonRes = null;
  const mockReq = { query: {} };
  const mockRes = {
    statusCode: 200,
    status(c) { this.statusCode = c; return this; },
    json(d) { jsonRes = d; return this; }
  };
  const handler = layer.route.stack[layer.route.stack.length - 1].handle;
  handler(mockReq, mockRes, () => {});

  assert.ok(jsonRes, 'Route must respond with JSON');
  assert.strictEqual(jsonRes.success, true);
  assert.ok(jsonRes.radio, 'Radio info must be present');
  assert.ok(jsonRes.kernelTcp, 'Kernel TCP info must be present');
  assert.strictEqual(jsonRes.hostName, os.hostname());
  console.log(`  ✓ GET /api/diagnostics/kernel-radio-inspector responded 200 OK.`);

  console.log('\n========================================================================');
  console.log('  SUITE 93 PASSED: PHYSICAL RADIO & KERNEL TCP INSPECTOR 100% GREEN     ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runSuite93HardwareKernelInspector().catch((err) => {
    console.error('Suite 93 failed:', err);
    process.exit(1);
  });
}

module.exports = {
  runSuite93HardwareKernelInspector,
  runSuite93: runSuite93HardwareKernelInspector
};
