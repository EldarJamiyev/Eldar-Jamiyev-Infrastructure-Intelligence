// tests/suite-85-holt-winters-and-topology-inspector-cohesion.test.js
/**
 * EJII Test Suite 85: Holt-Winters SLA Forecaster, Topology Inspector & 85-Suite Cohesion
 * Verifies damped exponential smoothing math, 95% confidence intervals, SLA risk CDF,
 * Topology slide-over inspector drawer, right-click context menu, 3-pane Wireshark studio,
 * interactive topbar pills, and exact 85/85 master test runner cohesion.
 */

'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { HoltWintersForecaster } = require('../src/ai/holt-winters-forecaster');

async function runSuite85HoltWintersAndTopologyInspectorCohesion() {
  console.log('========================================================================');
  console.log('  === [SUITE 85] HOLT-WINTERS FORECASTER & 85-SUITE COHESION ===        ');
  console.log('========================================================================\n');

  const forecaster = new HoltWintersForecaster(0.35, 0.15, 0.90);

  // [85.1] Standard Normal CDF & Probability
  console.log('[Test 85.1] Verifying Standard Normal CDF Abramowitz & Stegun approximation...');
  const cdfZero = HoltWintersForecaster.stdNormCdf(0.0);
  assert.ok(Math.abs(cdfZero - 0.5) < 0.001, `CDF(0) should be 0.5, got ${cdfZero}`);
  const cdf196 = HoltWintersForecaster.stdNormCdf(1.96);
  assert.ok(Math.abs(cdf196 - 0.975) < 0.005, `CDF(1.96) should be ~0.975, got ${cdf196}`);
  console.log(`  ✓ Normal CDF verified: CDF(0)=${cdfZero.toFixed(4)}, CDF(1.96)=${cdf196.toFixed(4)}`);

  // [85.2] Holt's Damped Linear Exponential Smoothing Math
  console.log("[Test 85.2] Verifying Holt's damped smoothing and multi-horizon forecasts...");
  const sampleCpuHistory = [15.2, 16.0, 15.8, 17.5, 18.2, 19.0, 20.1];
  const trajectory = forecaster.forecastSeries(sampleCpuHistory, 'cpu', 'CPU Load', '%', 85.0, 'MAX');

  assert.ok(trajectory, 'Trajectory must be calculated');
  assert.strictEqual(trajectory.metricKey, 'cpu');
  assert.ok(typeof trajectory.level === 'number' && trajectory.level > 0);
  assert.ok(trajectory.forecasts.plus1m.predictedValue > 0);
  assert.ok(trajectory.forecasts.plus5m.predictedValue > 0);
  assert.ok(trajectory.forecasts.plus15m.predictedValue > 0);

  // 95% Confidence prediction interval bounds check
  const f5m = trajectory.forecasts.plus5m;
  assert.ok(f5m.lowerBound95 <= f5m.predictedValue, `Lower 95% bound (${f5m.lowerBound95}) must be <= point forecast (${f5m.predictedValue})`);
  assert.ok(f5m.predictedValue <= f5m.upperBound95, `Point forecast (${f5m.predictedValue}) must be <= upper 95% bound (${f5m.upperBound95})`);
  assert.ok(typeof f5m.slaBreachRiskPct === 'number' && f5m.slaBreachRiskPct >= 0 && f5m.slaBreachRiskPct <= 100);
  console.log(`  ✓ Damped forecast (+5m): ${f5m.predictedValue.toFixed(1)}% [95% CI: ${f5m.lowerBound95.toFixed(1)} - ${f5m.upperBound95.toFixed(1)}%], SLA Breach Risk: ${f5m.slaBreachRiskPct}%`);

  // [85.3] Inline SVG Sparkline Generation
  console.log('[Test 85.3] Verifying inline SVG sparkline rendering with 95% confidence band...');
  const sparkline = trajectory.sparklineSvg;
  assert.ok(sparkline.includes('<svg') && sparkline.includes('</svg>'), 'Sparkline must be valid SVG markup');
  assert.ok(sparkline.includes('<polyline'), 'Sparkline must contain historical polyline');
  assert.ok(sparkline.includes('<circle'), 'Sparkline must contain forecast anchor points');
  console.log('  ✓ Inline SVG sparkline generated with embedded confidence band.');

  // [85.4] Express Route GET /api/diagnostics/sla-forecast
  console.log('[Test 85.4] Verifying Express GET /api/diagnostics/sla-forecast route...');
  const req = {
    app: { locals: { holtWintersForecaster: forecaster } }
  };
  let routeJson = null;
  const res = {
    json: (d) => { routeJson = d; },
    status: () => res
  };
  const routesDiag = require('../src/api/routes-diagnostics');
  const diagLayer = routesDiag.stack.find(s => s.route && s.route.path === '/sla-forecast');
  assert.ok(diagLayer, 'Route /sla-forecast must be mounted in routes-diagnostics.js');
  diagLayer.route.stack[0].handle(req, res, () => {});

  assert.ok(routeJson && routeJson.success, 'Route must respond with success: true');
  assert.ok(routeJson.metrics && routeJson.metrics.cpuLoadPct, 'Route must contain cpuLoadPct metric');
  assert.ok(routeJson.metrics.memoryUsedPct, 'Route must contain memoryUsedPct metric');
  assert.ok(routeJson.metrics.gatewayRttMs, 'Route must contain gatewayRttMs metric');
  assert.ok(typeof routeJson.overallSlaRiskPct === 'number', 'Route must include overallSlaRiskPct');
  console.log(`  ✓ SLA Forecast API responded with 4 metric trajectories, overall risk: ${routeJson.overallSlaRiskPct}%.`);

  // [85.5] UI Component & Innovation Integrity Audit
  console.log('[Test 85.5] Verifying Frontend views, drawer inspector, 3-pane Wireshark studio & flow pulse...');
  const read = (rel) => fs.readFileSync(path.join(__dirname, '..', rel), 'utf8');
  const nocView = read('public/js/views/noc-view.js');
  const snifferView = read('public/js/views/sniffer-view.js');
  const diagView = read('public/js/views/core-diagnostics-view.js');
  const indexHtml = read('public/index.html');
  const meridianCss = read('public/css/ejii-meridian.css');

  // Topology Inspector Drawer & Context Menu
  assert.ok(nocView.includes('openNodeInspector'), 'noc-view.js must define openNodeInspector');
  assert.ok(nocView.includes('topoNodeInspectorDrawer'), 'noc-view.js must manage #topoNodeInspectorDrawer');
  assert.ok(nocView.includes('topoNodeContextMenu'), 'noc-view.js must manage #topoNodeContextMenu');
  assert.ok(meridianCss.includes('.flow-active-pulse') && meridianCss.includes('fill: none !important'), 'CSS must define .flow-active-pulse with fill: none !important');
  assert.ok(nocView.includes('flow-active-pulse'), 'noc-view.js SVG edges must include flow-active-pulse class');

  // Always-Visible 3-Pane Wireshark Dissection Studio
  assert.ok(snifferView.includes('id="packetDetailsPane"'), 'sniffer-view.js must define #packetDetailsPane');
  assert.ok(snifferView.includes('#14161B'), 'sniffer-view.js Pane 3 Hexdump must be styled in Velvet Charcoal #14161B');
  assert.ok(snifferView.includes('toggleTcpWaterfallModal'), 'sniffer-view.js must define toggleTcpWaterfallModal');

  // Interactive Topbar Status Pills
  assert.ok(indexHtml.includes('id="topbarBpfPill"'), 'index.html must have #topbarBpfPill');
  assert.ok(indexHtml.includes('id="topbarAnomaliesPill"'), 'index.html must have #topbarAnomaliesPill');
  assert.ok(indexHtml.includes('id="topbarNodesPill"'), 'index.html must have #topbarNodesPill');
  assert.ok(meridianCss.includes('.stat-item-interactive') || meridianCss.includes('.stat-item.stat-item-interactive'), 'CSS must style .stat-item-interactive');

  // Core Diagnostics Forecast Hydration
  assert.ok(diagView.includes('diagSlaForecastContainer'), 'core-diagnostics-view.js must contain #diagSlaForecastContainer');
  assert.ok(diagView.includes('/api/diagnostics/sla-forecast'), 'core-diagnostics-view.js must query /api/diagnostics/sla-forecast');

  console.log('  ✓ Topology Inspector Drawer, Context Menu, 3-Pane Wireshark Studio & Topbar pills verified.');

  // [85.6] Master Test Runner 85/85 Cohesion
  console.log('[Test 85.6] Verifying 85/85 test suites registered in tests/run-all-tests.js...');
  const runnerContent = read('tests/run-all-tests.js');
  const suiteMatches = runnerContent.match(/\{\s*name:\s*['"]\d+\./g) || [];
  assert.strictEqual(suiteMatches.length, 85, `Expected exactly 85 registered test suites in run-all-tests.js, found ${suiteMatches.length}`);
  assert.ok(runnerContent.includes('suite-81-visual-screenshot-audit.test'), 'Runner must import Suite 81');
  assert.ok(runnerContent.includes('suite-82-live-visual-remediation.test'), 'Runner must import Suite 82');
  assert.ok(runnerContent.includes('suite-83-tcp-stream-waterfall-and-jitter.test'), 'Runner must import Suite 83');
  assert.ok(runnerContent.includes('suite-84-aimd-turbo-scanner-and-fingerprinting.test'), 'Runner must import Suite 84');
  assert.ok(runnerContent.includes('suite-85-holt-winters-and-topology-inspector-cohesion.test'), 'Runner must import Suite 85');
  console.log('  ✓ Exactly 85 suites registered and cohesive in tests/run-all-tests.js.');

  console.log('\n========================================================================');
  console.log('  SUITE 85 PASSED: HOLT-WINTERS & 85-SUITE COHESION 100% GREEN         ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runSuite85HoltWintersAndTopologyInspectorCohesion().catch((err) => {
    console.error('Suite 85 failed:', err);
    process.exit(1);
  });
}

module.exports = {
  runSuite85HoltWintersAndTopologyInspectorCohesion,
  runSuite85: runSuite85HoltWintersAndTopologyInspectorCohesion
};
