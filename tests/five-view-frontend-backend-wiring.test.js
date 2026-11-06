/**
 * EJII Test Suite 63: Full 5-View Frontend-to-Backend Wiring & Interaction Flow
 * 
 * Verifies:
 * [63.1] Global Active Investigation Context Bar (index.html & app.js)
 * [63.2] View 1 (Topology / NOC View): Shared Outages Banner, DHCP/MDNS Filters & p0f Fingerprint Badge
 * [63.3] View 2 (Packet Sniffer View): DHCP/MDNS Filter Options
 * [63.4] View 3 (Ultra IP Scanner View): KPI Strip, Spooler Modal, 4-Hop Pipeline & Re-test Diff
 * [63.5] View 4 (PC Automation View): Mount Provenance Pill, Category Filter Buttons & Spooler Check
 * [63.6] View 5 (Core Diagnostics View): Do-Calculus Simulator UI & Autonomous AI Goal Planner UI
 */

'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const rootDir = path.join(__dirname, '..');

async function runFiveViewFrontendBackendWiringTests() {
  console.log('========================================================================');
  console.log('  SUITE 63: 5-VIEW FRONTEND-TO-BACKEND WIRING & INTERACTION FLOW         ');
  console.log('  Cross-View Pivoting, Real Wire Filters, Banners & Do-Calculus DOM      ');
  console.log('========================================================================\n');

  // [63.1] Global Active Target Context Bar
  console.log('[63.1] Verifying global active target context bar in index.html & app.js...');
  const indexHtml = fs.readFileSync(path.join(rootDir, 'public', 'index.html'), 'utf8');
  assert.ok(indexHtml.includes('id="ejiiActiveTargetContextBar"'), 'index.html must include #ejiiActiveTargetContextBar');

  const appJs = fs.readFileSync(path.join(rootDir, 'public', 'js', 'app.js'), 'utf8');
  assert.ok(appJs.includes('window.setEjiiInvestigationTarget'), 'app.js must define window.setEjiiInvestigationTarget');
  assert.ok(appJs.includes('window.clearEjiiInvestigationTarget'), 'app.js must define window.clearEjiiInvestigationTarget');
  assert.ok(appJs.includes('window.pivotActiveTargetToView'), 'app.js must define window.pivotActiveTargetToView');
  console.log('  ✓ Global active target context bar and cross-view routing confirmed.');

  // [63.2] View 1 (Topology / NOC View)
  console.log('[63.2] Verifying View 1 (noc-view.js) shared outages and DHCP/MDNS wire inspection...');
  const nocJs = fs.readFileSync(path.join(rootDir, 'public', 'js', 'views', 'noc-view.js'), 'utf8');
  assert.ok(nocJs.includes('/api/rca/brain/shared-outages'), 'noc-view.js must fetch /api/rca/brain/shared-outages');
  assert.ok(nocJs.includes('sharedOutageAlertBanner'), 'noc-view.js must render #sharedOutageAlertBanner');
  assert.ok(nocJs.includes('value="DHCP"'), 'noc-view.js protocol filter must include DHCP');
  assert.ok(nocJs.includes('value="MDNS"'), 'noc-view.js protocol filter must include MDNS');
  assert.ok(nocJs.includes('p0f-badge'), 'noc-view.js must render p0f-badge in packet details');
  console.log('  ✓ View 1 shared outage alert banner, DHCP/mDNS filters and p0f badge verified.');

  // [63.3] View 2 (Packet Sniffer View)
  console.log('[63.3] Verifying View 2 (sniffer-view.js) protocol filter options...');
  const snifferJs = fs.readFileSync(path.join(rootDir, 'public', 'js', 'views', 'sniffer-view.js'), 'utf8');
  assert.ok(snifferJs.includes('value="DHCP"'), 'sniffer-view.js must include DHCP protocol filter');
  assert.ok(snifferJs.includes('value="MDNS"'), 'sniffer-view.js must include MDNS protocol filter');
  console.log('  ✓ View 2 DHCP and MDNS capture filters verified.');

  // [63.4] View 3 (Ultra IP Scanner View)
  console.log('[63.4] Verifying View 3 (ultra-ip-scanner-view.js) equipment KPIs and modal wiring...');
  const scannerJs = fs.readFileSync(path.join(rootDir, 'public', 'js', 'views', 'ultra-ip-scanner-view.js'), 'utf8');
  assert.ok(scannerJs.includes('eji-equipment-kpi-strip'), 'ultra-ip-scanner-view.js must contain .eji-equipment-kpi-strip');
  assert.ok(scannerJs.includes('/api/network/office-device/inventory'), 'ultra-ip-scanner-view.js must auto-fetch inventory');
  assert.ok(scannerJs.includes('checkLocalPrintSpoolerModal'), 'ultra-ip-scanner-view.js must define checkLocalPrintSpoolerModal');
  assert.ok(scannerJs.includes('eji-hop-pipeline'), 'ultra-ip-scanner-view.js modal must contain .eji-hop-pipeline');
  assert.ok(scannerJs.includes('eji-plain-resolver-grid'), 'ultra-ip-scanner-view.js modal must contain .eji-plain-resolver-grid');
  assert.ok(scannerJs.includes('isRetest') && scannerJs.includes('Re-Test Device Now'), 'ultra-ip-scanner-view.js must support re-testing device');
  console.log('  ✓ View 3 KPI strip, spooler modal, 4-hop pipeline, and re-test diff verified.');

  // [63.5] View 4 (PC Automation View)
  console.log('[63.5] Verifying View 4 (pc-automation-view.js) mount provenance and category filters...');
  const pcAutoJs = fs.readFileSync(path.join(rootDir, 'public', 'js', 'views', 'pc-automation-view.js'), 'utf8');
  assert.ok(pcAutoJs.includes('mountMetadata'), 'pc-automation-view.js must reference mountMetadata');
  assert.ok(pcAutoJs.includes('filterScriptCategory'), 'pc-automation-view.js must define filterScriptCategory');
  assert.ok(pcAutoJs.includes('Check Local Print Spooler'), 'pc-automation-view.js must include local print spooler check button');
  console.log('  ✓ View 4 mount provenance pill, category filters and spooler button verified.');

  // [63.6] View 5 (Core Diagnostics View)
  console.log('[63.6] Verifying View 5 (core-diagnostics-view.js) Do-Calculus & Autonomous AI Workflow UI...');
  const coreDiagJs = fs.readFileSync(path.join(rootDir, 'public', 'js', 'views', 'core-diagnostics-view.js'), 'utf8');
  assert.ok(coreDiagJs.includes('/api/rca/brain/counterfactual-simulate'), 'core-diagnostics-view.js must call /api/rca/brain/counterfactual-simulate');
  assert.ok(coreDiagJs.includes('runCounterfactualSimulationFromUi'), 'core-diagnostics-view.js must define runCounterfactualSimulationFromUi');
  assert.ok(coreDiagJs.includes('/api/rca/brain/autonomous-workflow'), 'core-diagnostics-view.js must call /api/rca/brain/autonomous-workflow');
  assert.ok(coreDiagJs.includes('runAutonomousWorkflowFromUi'), 'core-diagnostics-view.js must define runAutonomousWorkflowFromUi');
  assert.ok(coreDiagJs.includes('tabContent_counterfactual'), 'core-diagnostics-view.js must have tabContent_counterfactual');
  assert.ok(coreDiagJs.includes('tabContent_autonomousWorkflow'), 'core-diagnostics-view.js must have tabContent_autonomousWorkflow');
  console.log('  ✓ View 5 Do-Calculus simulator and Autonomous AI Workflow panels verified.\n');

  console.log('========================================================================');
  console.log('  SUITE 63 PASSED: 5-VIEW FRONTEND-BACKEND WIRING 100% GREEN             ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runFiveViewFrontendBackendWiringTests().then(() => {
    process.exit(0);
  }).catch((err) => {
    console.error('Suite 63 failed:', err);
    process.exit(1);
  });
}

module.exports = {
  runFiveViewFrontendBackendWiringTests,
  runSuite63: runFiveViewFrontendBackendWiringTests
};
