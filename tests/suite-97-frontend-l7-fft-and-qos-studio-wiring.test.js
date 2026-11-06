// tests/suite-97-frontend-l7-fft-and-qos-studio-wiring.test.js
/**
 * EJII Test Suite 97: Frontend Spectral FFT & QoS Studio Workbench Wiring
 * Verifies the UI integration of:
 *   1. Spectral FFT & QoS Studio Workbench button (#btnFftQosModal) in sniffer-view.js
 *   2. Modal controller functions window.toggleFftQosModal() and window.closeFftQosModal()
 *   3. Dual REST dispatch to /api/rca/spectral-fft and /api/network/qos-dscp-audit
 *   4. Wireshark-grade 3-pane dissection architecture (#protocolTreePane, #hexDumpPane).
 */

'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const read = (rel) => fs.readFileSync(path.join(__dirname, '..', rel), 'utf8');

async function runSuite97FrontendFftAndQosWiring() {
  console.log('========================================================================');
  console.log('  === [SUITE 97] FRONTEND SPECTRAL FFT & QOS STUDIO WIRING ===          ');
  console.log('========================================================================\n');

  const snifferView = read('public/js/views/sniffer-view.js');

  // [97.1] Spectral FFT & QoS Studio Workbench Trigger
  console.log('[Test 97.1] Verifying #btnFftQosModal button and modal trigger in sniffer-view.js...');
  assert.ok(snifferView.includes('id="btnFftQosModal"'), 'sniffer-view.js must define #btnFftQosModal');
  assert.ok(snifferView.includes('onclick="window.toggleFftQosModal()"'), 'Button must trigger window.toggleFftQosModal()');
  console.log('  ✓ #btnFftQosModal trigger verified in Sniffer toolbar.');

  // [97.2] Modal Controller Implementation & API Wiring
  console.log('[Test 97.2] Verifying window.toggleFftQosModal() and dual API queries...');
  assert.ok(snifferView.includes('window.toggleFftQosModal ='), 'sniffer-view.js must define window.toggleFftQosModal');
  assert.ok(snifferView.includes('window.closeFftQosModal ='), 'sniffer-view.js must define window.closeFftQosModal');
  assert.ok(snifferView.includes('/api/rca/spectral-fft'), 'Modal must fetch /api/rca/spectral-fft for Welch periodogram');
  assert.ok(snifferView.includes('/api/network/qos-dscp-audit'), 'Modal must fetch /api/network/qos-dscp-audit for DSCP breakdown');
  console.log('  ✓ Dual API queries to /api/rca/spectral-fft and /api/network/qos-dscp-audit confirmed.');

  // [97.3] Wireshark-Grade 3-Pane Dissection Layout
  console.log('[Test 97.3] Verifying 3-pane dissection view architecture in sniffer-view.js...');
  assert.ok(snifferView.includes('protocolTreePane'), 'sniffer-view.js must define #protocolTreePane');
  assert.ok(snifferView.includes('hexDumpPane'), 'sniffer-view.js must define #hexDumpPane');
  console.log('  ✓ Wireshark-grade 3-pane synchronized layout verified (#protocolTreePane and #hexDumpPane).');

  console.log('\n========================================================================');
  console.log('  SUITE 97 PASSED: FRONTEND SPECTRAL FFT & QOS STUDIO WIRING 100% GREEN ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runSuite97FrontendFftAndQosWiring().catch((err) => {
    console.error('Suite 97 failed:', err);
    process.exit(1);
  });
}

module.exports = {
  runSuite97FrontendFftAndQosWiring,
  runSuite97: runSuite97FrontendFftAndQosWiring
};
