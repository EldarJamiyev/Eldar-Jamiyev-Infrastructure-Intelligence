// tests/suite-98-frontend-zerotrust-and-warroom-studio-wiring.test.js
/**
 * EJII Test Suite 98: Frontend Zero-Trust Policy Synthesizer & Autonomous War-Room Studio Wiring
 * Verifies UI integration of:
 *   1. Zero-Trust Policy Synthesizer in ultra-ip-scanner-view.js (#btnSynthesizeZeroTrust, openZeroTrustPolicyModal)
 *   2. 5-Agent SRE War-Room in core-diagnostics-view.js (#btnLaunchWarRoom, openWarRoomModal, runWarRoomExecution)
 *   3. Kernel Radio Inspector in core-diagnostics-view.js (#btnKernelRadioAudit, openKernelRadioModal).
 */

'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const read = (rel) => fs.readFileSync(path.join(__dirname, '..', rel), 'utf8');

async function runSuite98FrontendZeroTrustAndWarRoomWiring() {
  console.log('========================================================================');
  console.log('  === [SUITE 98] FRONTEND ZERO-TRUST & SRE WAR-ROOM WIRING ===          ');
  console.log('========================================================================\n');

  const scannerView = read('public/js/views/ultra-ip-scanner-view.js');
  const diagView = read('public/js/views/core-diagnostics-view.js');

  // [98.1] Zero-Trust Policy Synthesizer in Scanner View
  console.log('[Test 98.1] Verifying #btnSynthesizeZeroTrust and modal generator in ultra-ip-scanner-view.js...');
  assert.ok(scannerView.includes('id="btnSynthesizeZeroTrust"'), 'ultra-ip-scanner-view.js must define #btnSynthesizeZeroTrust');
  assert.ok(scannerView.includes('onclick="window.openZeroTrustPolicyModal()"'), 'Button must trigger window.openZeroTrustPolicyModal()');
  assert.ok(scannerView.includes('window.openZeroTrustPolicyModal ='), 'ultra-ip-scanner-view.js must define window.openZeroTrustPolicyModal');
  assert.ok(scannerView.includes('window.closeZeroTrustPolicyModal ='), 'ultra-ip-scanner-view.js must define window.closeZeroTrustPolicyModal');
  assert.ok(scannerView.includes('/api/network/zero-trust-policies'), 'Modal must query /api/network/zero-trust-policies');
  console.log('  ✓ Zero-Trust Micro-Segmentation policy generator verified in ultra-ip-scanner-view.js.');

  // [98.2] 5-Agent Autonomous SRE War-Room in Core Diagnostics View
  console.log('[Test 98.2] Verifying 5-Agent War-Room button and modal controllers in core-diagnostics-view.js...');
  assert.ok(diagView.includes('id="btnLaunchWarRoom"'), 'core-diagnostics-view.js must define #btnLaunchWarRoom');
  assert.ok(diagView.includes('onclick="window.openWarRoomModal()"'), 'Button must trigger window.openWarRoomModal()');
  assert.ok(diagView.includes('window.openWarRoomModal ='), 'core-diagnostics-view.js must define window.openWarRoomModal');
  assert.ok(diagView.includes('window.runWarRoomExecution ='), 'core-diagnostics-view.js must define window.runWarRoomExecution');
  assert.ok(diagView.includes('window.closeWarRoomModal ='), 'core-diagnostics-view.js must define window.closeWarRoomModal');
  assert.ok(diagView.includes('/api/rca/war-room/execute'), 'Must post to /api/rca/war-room/execute');
  assert.ok(diagView.includes('/api/rca/war-room/latest'), 'Must query /api/rca/war-room/latest');
  console.log('  ✓ 5-Agent SRE War-Room modal and live API consensus dispatch verified in core-diagnostics-view.js.');

  // [98.3] Physical Radio & Kernel TCP Stack Inspector in Core Diagnostics View
  console.log('[Test 98.3] Verifying #btnKernelRadioAudit button and modal controllers...');
  assert.ok(diagView.includes('id="btnKernelRadioAudit"'), 'core-diagnostics-view.js must define #btnKernelRadioAudit');
  assert.ok(diagView.includes('onclick="window.openKernelRadioModal()"'), 'Button must trigger window.openKernelRadioModal()');
  assert.ok(diagView.includes('window.openKernelRadioModal ='), 'core-diagnostics-view.js must define window.openKernelRadioModal');
  assert.ok(diagView.includes('window.closeKernelRadioModal ='), 'core-diagnostics-view.js must define window.closeKernelRadioModal');
  assert.ok(diagView.includes('/api/diagnostics/kernel-radio-inspector'), 'Must query /api/diagnostics/kernel-radio-inspector');
  console.log('  ✓ Physical Radio & Kernel TCP Stack modal verified in core-diagnostics-view.js.');

  console.log('\n========================================================================');
  console.log('  SUITE 98 PASSED: ZERO-TRUST & WAR-ROOM STUDIO WIRING 100% GREEN       ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runSuite98FrontendZeroTrustAndWarRoomWiring().catch((err) => {
    console.error('Suite 98 failed:', err);
    process.exit(1);
  });
}

module.exports = {
  runSuite98FrontendZeroTrustAndWarRoomWiring,
  runSuite98: runSuite98FrontendZeroTrustAndWarRoomWiring
};
