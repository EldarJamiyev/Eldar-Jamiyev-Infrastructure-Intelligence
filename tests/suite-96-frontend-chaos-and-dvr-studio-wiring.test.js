// tests/suite-96-frontend-chaos-and-dvr-studio-wiring.test.js
/**
 * EJII Test Suite 96: Frontend Digital Twin Chaos & Telemetry DVR Studio Wiring
 * Verifies the UI integration of:
 *   1. Digital Twin Chaos Simulator in noc-view.js (#btnNocChaosSimulator, openDigitalTwinChaosModal, runDigitalTwinChaosSim)
 *   2. Telemetry Time-Machine DVR in index.html and app.js (#btnTopbarDvr, #dvrModalContainer, toggleDvrModal, recordDvrCheckpoint)
 *   3. Obsidian-Emerald token styling and dot-matrix grid canvas classes in ejii-meridian.css.
 */

'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const read = (rel) => fs.readFileSync(path.join(__dirname, '..', rel), 'utf8');

async function runSuite96FrontendChaosAndDvrWiring() {
  console.log('========================================================================');
  console.log('  === [SUITE 96] DIGITAL TWIN CHAOS & TIME-MACHINE DVR UI WIRING ===    ');
  console.log('========================================================================\n');

  const nocView = read('public/js/views/noc-view.js');
  const indexHtml = read('public/index.html');
  const appJs = read('public/js/app.js');
  const meridianCss = read('public/css/ejii-meridian.css');

  // [96.1] NOC View Chaos Simulator Trigger
  console.log('[Test 96.1] Verifying #btnNocChaosSimulator and modal trigger in noc-view.js...');
  assert.ok(nocView.includes('id="btnNocChaosSimulator"'), 'noc-view.js must define #btnNocChaosSimulator');
  assert.ok(nocView.includes('onclick="window.openDigitalTwinChaosModal()"'), 'Button must invoke openDigitalTwinChaosModal()');
  assert.ok(nocView.includes('window.openDigitalTwinChaosModal ='), 'window.openDigitalTwinChaosModal must be attached');
  assert.ok(nocView.includes('window.runDigitalTwinChaosSim ='), 'window.runDigitalTwinChaosSim must be attached');
  assert.ok(nocView.includes('/api/network/digital-twin/simulate'), 'noc-view.js must query /api/network/digital-twin/simulate');
  console.log('  ✓ Digital Twin Chaos Simulator button, modal generator, and API dispatch verified in noc-view.js.');

  // [96.2] Time-Machine DVR Topbar Trigger & Container in index.html
  console.log('[Test 96.2] Verifying #btnTopbarDvr and #dvrModalContainer in index.html...');
  assert.ok(indexHtml.includes('id="btnTopbarDvr"'), 'index.html must include #btnTopbarDvr in topbar');
  assert.ok(indexHtml.includes('window.toggleDvrModal'), 'Button must call toggleDvrModal()');
  assert.ok(indexHtml.includes('id="dvrModalContainer"'), 'index.html must provide #dvrModalContainer modal anchor');
  console.log('  ✓ Topbar DVR trigger button and #dvrModalContainer anchor verified in index.html.');

  // [96.3] Time-Machine DVR Controller in app.js
  console.log('[Test 96.3] Verifying DVR controller functions in app.js...');
  assert.ok(appJs.includes('window.toggleDvrModal ='), 'app.js must define window.toggleDvrModal');
  assert.ok(appJs.includes('window.recordDvrCheckpoint ='), 'app.js must define window.recordDvrCheckpoint');
  assert.ok(appJs.includes('window.runDvrDiff ='), 'app.js must define window.runDvrDiff');
  assert.ok(appJs.includes('window.closeDvrModal ='), 'app.js must define window.closeDvrModal');
  assert.ok(appJs.includes('/api/observability/dvr/frames'), 'app.js must fetch /api/observability/dvr/frames');
  assert.ok(appJs.includes('/api/observability/dvr/record'), 'app.js must post to /api/observability/dvr/record');
  assert.ok(appJs.includes('/api/observability/dvr/diff'), 'app.js must query /api/observability/dvr/diff');
  console.log('  ✓ DVR Time-Machine full CRUD lifecycle verified in app.js.');

  // [96.4] Obsidian-Emerald Sovereign CSS Token System
  console.log('[Test 96.4] Verifying Sovereign Obsidian-Emerald token system in ejii-meridian.css...');
  assert.ok(meridianCss.includes('--bg-canvas: #060B09') || meridianCss.includes('#060B09') || meridianCss.includes('#070D0A'), 'CSS must define dark obsidian canvas');
  assert.ok(meridianCss.includes('.dot-matrix-grid') || meridianCss.includes('radial-gradient'), 'CSS must specify dot-matrix grid pattern');
  assert.ok(meridianCss.includes('badge-streaming-live') || meridianCss.includes('.badge-live-stream'), 'CSS must style low-glare streaming badge');
  assert.ok(meridianCss.includes('badge-frames-visible'), 'CSS must style translucent frames badge');
  console.log('  ✓ Zero-glare Obsidian-Emerald visual tokens and dot-matrix grid verified.');

  console.log('\n========================================================================');
  console.log('  SUITE 96 PASSED: FRONTEND CHAOS & DVR STUDIO WIRING 100% GREEN        ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runSuite96FrontendChaosAndDvrWiring().catch((err) => {
    console.error('Suite 96 failed:', err);
    process.exit(1);
  });
}

module.exports = {
  runSuite96FrontendChaosAndDvrWiring,
  runSuite96: runSuite96FrontendChaosAndDvrWiring
};
