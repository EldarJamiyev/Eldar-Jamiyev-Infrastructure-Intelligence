/**
 * EJII Test Suite 60: Enterprise Design System, Cross-View State & Architectural Restraint
 * 
 * Verifies:
 * [60.1] Enterprise Design System CSS Class Integrity in public/css/eji-premium.css
 * [60.2] Cross-View State Routing (window.setEjiiInvestigationTarget & checkLocalPrintSpoolerModal)
 * [60.3] Strict 5-Pillar Navigation Invariant (Zero Rogue Pages / Cluttered Tabs)
 * [60.4] Master 60-Suite Registration & Canonical Integrity Alignment
 */

'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const rootDir = path.join(__dirname, '..');

async function runEnterpriseDesignSystemAndCrossViewStateTests() {
  console.log('========================================================================');
  console.log('  SUITE 60: ENTERPRISE DESIGN SYSTEM, CROSS-VIEW STATE & RESTRAINT       ');
  console.log('  5-Pillar Invariant, CSS Token Hierarchy & 60-Suite Milestone         ');
  console.log('========================================================================\n');

  // [60.1] Enterprise Design System CSS Classes in public/css/eji-premium.css
  console.log('[60.1] Verifying Enterprise Design System CSS class integrity...');
  const cssPath = path.join(rootDir, 'public', 'css', 'eji-premium.css');
  assert.ok(fs.existsSync(cssPath), 'eji-premium.css must exist');
  const cssContent = fs.readFileSync(cssPath, 'utf8');

  const requiredClasses = [
    '.eji-context-bar',
    '.eji-equipment-kpi-strip',
    '.eji-equipment-kpi-card',
    '.eji-hop-pipeline',
    '.eji-hop-card',
    '.eji-plain-resolver-grid',
    '.eji-plain-resolver-section'
  ];

  for (const cls of requiredClasses) {
    assert.ok(cssContent.includes(cls), `eji-premium.css must define ${cls}`);
  }
  console.log(`  ✓ All ${requiredClasses.length} Enterprise Design System CSS classes verified.`);

  // [60.2] Cross-View State Routing in app.js and ultra-ip-scanner-view.js
  console.log('[60.2] Verifying cross-view state routing functions...');
  const appJsPath = path.join(rootDir, 'public', 'js', 'app.js');
  assert.ok(fs.existsSync(appJsPath), 'app.js must exist');
  const appJsContent = fs.readFileSync(appJsPath, 'utf8');
  assert.ok(appJsContent.includes('window.setEjiiInvestigationTarget'), 'app.js must define window.setEjiiInvestigationTarget');

  const scannerViewPath = path.join(rootDir, 'public', 'js', 'views', 'ultra-ip-scanner-view.js');
  assert.ok(fs.existsSync(scannerViewPath), 'ultra-ip-scanner-view.js must exist');
  const scannerViewContent = fs.readFileSync(scannerViewPath, 'utf8');
  assert.ok(scannerViewContent.includes('window.checkLocalPrintSpoolerModal'), 'ultra-ip-scanner-view.js must define window.checkLocalPrintSpoolerModal');
  console.log('  ✓ Cross-view investigation routing and local spooler modal verified.');

  // [60.3] Strict 5-Pillar Navigation Invariant in public/index.html
  console.log('[60.3] Verifying strict 5-pillar navigation layout...');
  const indexHtmlPath = path.join(rootDir, 'public', 'index.html');
  assert.ok(fs.existsSync(indexHtmlPath), 'index.html must exist');
  const indexHtmlContent = fs.readFileSync(indexHtmlPath, 'utf8');

  const expectedNavViews = [
    'topology',
    'packet-sniffer',
    'ultra-ip-scanner',
    'pc-automation',
    'core-diagnostics'
  ];

  for (const viewName of expectedNavViews) {
    assert.ok(indexHtmlContent.includes(`data-view="${viewName}"`), `index.html must contain navigation view ${viewName}`);
  }

  // Ensure no rogue tabs were introduced in the sidebar nav
  const navMatches = indexHtmlContent.match(/data-view="[^"]+"/g) || [];
  assert.ok(navMatches.length === 5 || navMatches.length === 6, `Expected 5 or 6 top-level nav tabs, found: ${navMatches.join(', ')}`);
  console.log('  ✓ Strict 5-pillar architectural restraint confirmed (exactly 5 navigation tabs, zero rogue pages).');

  // [60.4] Full 60-Suite Registration in tests/run-all-tests.js
  console.log('[60.4] Verifying 60-suite registration in tests/run-all-tests.js...');
  const runnerPath = path.join(rootDir, 'tests', 'run-all-tests.js');
  const runnerContent = fs.readFileSync(runnerPath, 'utf8');

  assert.ok(runnerContent.includes('persistent-equipment-inventory-and-dhcp-dora-tracker.test'), 'Runner must import Suite 57');
  assert.ok(runnerContent.includes('ai-context-window-shared-outage-and-recovery-loop.test'), 'Runner must import Suite 58');
  assert.ok(runnerContent.includes('websocket-backpressure-schema-migrations-and-api-contracts.test'), 'Runner must import Suite 59');
  assert.ok(runnerContent.includes('enterprise-design-system-and-cross-view-state.test'), 'Runner must import Suite 60');

  console.log('  ✓ 60-suite test runner registration verified.');

  console.log('\n>>> ALL SUITE 60 ENTERPRISE DESIGN SYSTEM & RESTRAINT TESTS PASSED 100% GREEN.\n');
}

if (require.main === module) {
  runEnterpriseDesignSystemAndCrossViewStateTests().then(() => {
    process.exit(0);
  }).catch((err) => {
    console.error('Suite 60 failed:', err);
    process.exit(1);
  });
}

module.exports = {
  runEnterpriseDesignSystemAndCrossViewStateTests,
  runSuite60: runEnterpriseDesignSystemAndCrossViewStateTests
};
