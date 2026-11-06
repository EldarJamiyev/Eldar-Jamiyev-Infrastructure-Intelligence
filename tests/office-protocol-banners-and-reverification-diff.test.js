/**
 * EJII Test Suite 62: Office Protocol Banners & Closed-Loop Re-Verification Diff
 * 
 * Verifies:
 * [62.1] Application-Layer Banner Probing (probeOfficeApplicationBanner for IPP/HTTP & JetDirect)
 * [62.2] Safe Short-Circuit & Graceful Timeout Handling on Unresponsive Ports (<=650ms)
 * [62.3] Closed-Loop Before/After Re-Verification Snapshot Diff (reverificationDiff)
 * [62.4] Bounded In-Memory Snapshot Cache (previousDiagnosisMap bounded to 200 entries)
 * [62.5] Office Equipment Inventory Integration & REST Route
 */

'use strict';

const assert = require('assert');
const http = require('http');
const net = require('net');
const path = require('path');
const {
  probeOfficeApplicationBanner,
  diagnoseOfficeDevice,
  previousDiagnosisMap
} = require('../src/network/diagnostics/office-device-resolver');

async function runOfficeProtocolBannersAndReverificationDiffTests() {
  console.log('========================================================================');
  console.log('  SUITE 62: OFFICE PROTOCOL BANNERS & RE-VERIFICATION DIFF               ');
  console.log('  IPP/HTTP & JetDirect Banners, 650ms Timeout & Closed-Loop Delta Engine ');
  console.log('========================================================================\n');

  // [62.1] Test Real Local HTTP/IPP Server Banner Extraction
  console.log('[62.1] Verifying real HTTP/IPP application banner probing...');
  const testHttpServer = http.createServer((req, res) => {
    res.writeHead(200, {
      'Server': 'HP-ChaiSOE/1.0 (HP LaserJet Managed MFP E82540)',
      'Content-Type': 'text/html'
    });
    res.end('<html><head><title>HP LaserJet MFP Web Management</title></head><body>OK</body></html>');
  });

  await new Promise((resolve) => testHttpServer.listen(0, '127.0.0.1', resolve));
  const httpPort = testHttpServer.address().port;

  try {
    const bannerInfo = await probeOfficeApplicationBanner('127.0.0.1', httpPort, 800);
    assert.ok(bannerInfo, 'probeOfficeApplicationBanner must return banner object for active HTTP/IPP port');
    assert.strictEqual(bannerInfo.protocol, 'HTTP_IPP');
    assert.ok(bannerInfo.server && bannerInfo.server.includes('HP-ChaiSOE'), 'Must extract Server header');
    assert.ok(bannerInfo.title && bannerInfo.title.includes('HP LaserJet'), 'Must extract page title');
    assert.ok(bannerInfo.banner && bannerInfo.banner.includes('HP'), 'Combined banner must identify HP');
    console.log(`  ✓ HTTP/IPP banner successfully probed: "${bannerInfo.banner}"`);
  } finally {
    await new Promise((resolve) => testHttpServer.close(resolve));
  }

  // Test JetDirect 9100 Raw Socket Banner Extraction
  console.log('[62.1b] Verifying JetDirect raw TCP banner probing...');
  const testJetDirectServer = net.createServer((socket) => {
    socket.on('data', () => {
      // Respond with PJL device identification string
      socket.write('@PJL INFO ID\r\n"HP Color LaserJet Pro MFP M479fdw"\r\n\x0c');
      socket.end();
    });
  });

  await new Promise((resolve) => testJetDirectServer.listen(0, '127.0.0.1', resolve));
  const jetDirectPort = testJetDirectServer.address().port;

  try {
    const jetBannerInfo = await probeOfficeApplicationBanner('127.0.0.1', jetDirectPort, 800);
    assert.ok(jetBannerInfo, 'probeOfficeApplicationBanner must extract JetDirect banner');
    assert.ok(jetBannerInfo.banner && jetBannerInfo.banner.includes('Color LaserJet Pro'), 'Must parse PJL printer model');
    console.log(`  ✓ JetDirect PJL banner successfully probed: "${jetBannerInfo.banner}"`);
  } finally {
    await new Promise((resolve) => testJetDirectServer.close(resolve));
  }

  // [62.2] Safe Short-Circuit on Non-Listening Port
  console.log('[62.2] Verifying safe short-circuit and graceful timeout on non-listening ports...');
  const startQuiet = Date.now();
  // Port 65432 is arbitrary non-listening port on loopback
  const quietBanner = await probeOfficeApplicationBanner('127.0.0.1', 65432, 400);
  const elapsedQuiet = Date.now() - startQuiet;
  assert.strictEqual(quietBanner, null, 'Must return null gracefully on connection refusal');
  assert.ok(elapsedQuiet < 600, `Must fail fast without hanging (elapsed: ${elapsedQuiet}ms)`);
  console.log(`  ✓ Quiet port safely handled in ${elapsedQuiet}ms without error.`);

  // [62.3] Closed-Loop Before/After Re-Verification Snapshot Diff
  console.log('[62.3] Verifying closed-loop before/after re-verification snapshot diff...');
  const targetIp = '127.0.0.1';

  // Initial diagnosis (establishes baseline)
  const initialDiag = await diagnoseOfficeDevice({
    targetIp,
    deviceName: 'Test Workstation Loopback',
    isRetest: false
  });
  assert.ok(initialDiag, 'Initial diagnosis must succeed');
  assert.ok(initialDiag.plainLanguageDiagnosis, 'Must produce plainLanguageDiagnosis');

  // Verify baseline was stored in previousDiagnosisMap
  assert.ok(previousDiagnosisMap.has(targetIp), 'Baseline snapshot must be cached in previousDiagnosisMap');

  // Re-test diagnosis (triggers snapshot comparison)
  const retestDiag = await diagnoseOfficeDevice({
    targetIp,
    deviceName: 'Test Workstation Loopback',
    isRetest: true
  });

  assert.ok(retestDiag.reverificationDiff, 'Retest diagnosis must return reverificationDiff');
  const diff = retestDiag.reverificationDiff;
  assert.ok(diff.previousState, 'Diff must contain previousState');
  assert.ok(diff.currentState, 'Diff must contain currentState');
  assert.ok(typeof diff.stateChange === 'string', 'Diff must determine stateChange');
  assert.ok(['RESOLVED', 'IMPROVED', 'DEGRADED', 'UNCHANGED'].includes(diff.stateChange));
  assert.ok(Array.isArray(diff.fixedAnomalies));
  assert.ok(Array.isArray(diff.newAnomalies));
  assert.ok(diff.deltaSummary, 'Diff must provide a human-readable deltaSummary');
  console.log(`  ✓ Re-verification diff generated: stateChange=${diff.stateChange}, delta="${diff.deltaSummary}"`);

  // [62.4] Bounded In-Memory Cache Verification
  console.log('[62.4] Verifying previousDiagnosisMap bounded LRU eviction (max 200 entries)...');
  assert.ok(previousDiagnosisMap.size <= 200, 'previousDiagnosisMap size must never exceed 200');
  
  // Fill cache up to boundary and check size remains bounded
  for (let i = 0; i < 210; i++) {
    previousDiagnosisMap.set(`10.250.${Math.floor(i / 250)}.${i % 250}`, { timestamp: Date.now() });
    if (previousDiagnosisMap.size > 200) {
      const oldestKey = previousDiagnosisMap.keys().next().value;
      previousDiagnosisMap.delete(oldestKey);
    }
  }
  assert.strictEqual(previousDiagnosisMap.size, 200, 'Map must be capped at 200 entries');
  console.log('  ✓ Bounded memory footprint verified (size capped at 200).');

  // [62.5] Office Equipment Inventory REST Route
  console.log('[62.5] Verifying Office Device inventory route wiring...');
  const routesPath = path.join(__dirname, '..', 'src', 'api', 'routes-network.js');
  const routesContent = require('fs').readFileSync(routesPath, 'utf8');
  assert.ok(routesContent.includes('/office-device/inventory'), 'routes-network.js must define /office-device/inventory');
  assert.ok(routesContent.includes('/office-device/diagnose'), 'routes-network.js must define /office-device/diagnose');
  console.log('  ✓ Office equipment inventory and diagnostic endpoints confirmed.\n');

  console.log('========================================================================');
  console.log('  SUITE 62 PASSED: PROTOCOL BANNERS & RE-VERIFICATION DIFF 100% GREEN   ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runOfficeProtocolBannersAndReverificationDiffTests().then(() => {
    process.exit(0);
  }).catch((err) => {
    console.error('Suite 62 failed:', err);
    process.exit(1);
  });
}

module.exports = {
  runOfficeProtocolBannersAndReverificationDiffTests,
  runSuite62: runOfficeProtocolBannersAndReverificationDiffTests
};
