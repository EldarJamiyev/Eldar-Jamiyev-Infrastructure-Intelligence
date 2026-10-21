/**
 * EJII Suite 71: W3C traceparent Telemetry Pipeline, OTLP Spans & Multi-Environment Topology
 *
 * Verifies:
 * 1. [71.1] W3C traceparent Middleware: RFC trace context generation (00-<32hex>-<16hex>-01) and propagation.
 * 2. [71.2] CNCF OpenTelemetry Span Recording: Verifies Otel spans recorded with correlation IDs.
 * 3. [71.3] Hardware OUI Vendor Resolution: 50:64:2B resolves to "Xiaomi Communications / Mi Router"
 *    and 78:9A:18 resolves to "MikroTik RouterOS".
 * 4. [71.4] Dynamic Location Environment Profile: STANDARD_LAN_OR_WIFI vs ENTERPRISE_CORPORATE_INTRANET.
 */

'use strict';

const assert = require('assert');
const express = require('express');
const http = require('http');
const { requestCorrelationAndTelemetryMiddleware } = require('../src/api/middleware');
const { cncfObservabilityExporter } = require('../src/integrations/observability/cncf-observability-exporter');
const { resolveGatewayOuiVendor, getPhysicalNetworkInfo } = require('../src/network/routing/physical-network-detector');
const { resolveOuiVendor } = require('../src/tools/ip-scanner');

async function runW3cTraceparentPipelineAndMultiEnvLocationTests() {
  console.log('========================================================================');
  console.log('  EJII SUITE 71: W3C TRACEPARENT, OTEL SPANS & MULTI-ENV LOCATION        ');
  console.log('========================================================================');

  // [71.1] W3C traceparent generation and propagation
  console.log('[71.1] Verifying W3C traceparent header generation and propagation...');
  const app = express();
  app.use(requestCorrelationAndTelemetryMiddleware);
  app.get('/test-trace', (req, res) => {
    res.json({
      traceId: req.traceId,
      spanId: req.spanId,
      traceparent: req.traceparent
    });
  });

  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  try {
    // 1a: Auto-generation when caller sends no traceparent
    const res1 = await new Promise((resolve, reject) => {
      const req = http.get(`http://127.0.0.1:${port}/test-trace`, (res) => {
        let b = '';
        res.on('data', c => b += c);
        res.on('end', () => resolve({ headers: res.headers, body: JSON.parse(b) }));
      });
      req.on('error', reject);
    });

    const tp1 = res1.headers['traceparent'];
    console.log(`  ✓ Auto-generated traceparent: ${tp1}`);
    assert.ok(tp1, 'traceparent header must be present in response');
    assert.match(tp1, /^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/i, 'Must match W3C traceparent specification');
    assert.strictEqual(res1.body.traceId.length, 32);
    assert.strictEqual(res1.body.spanId.length, 16);

    // 1b: Propagation when caller passes upstream traceparent
    const incomingTrace = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';
    const res2 = await new Promise((resolve, reject) => {
      const req = http.get(`http://127.0.0.1:${port}/test-trace`, {
        headers: { 'traceparent': incomingTrace }
      }, (res) => {
        let b = '';
        res.on('data', c => b += c);
        res.on('end', () => resolve({ headers: res.headers, body: JSON.parse(b) }));
      });
      req.on('error', reject);
    });

    console.log(`  ✓ Propagated upstream trace ID: ${res2.body.traceId}`);
    assert.strictEqual(res2.body.traceId, '4bf92f3577b34da6a3ce929d0e0e4736', 'Must preserve incoming traceId');
    assert.notStrictEqual(res2.body.spanId, '00f067aa0ba902b7', 'Must generate new child spanId');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }

  // [71.2] CNCF OpenTelemetry Span Recording
  console.log('[71.2] Verifying OpenTelemetry span recording in CNCF exporter...');
  const otelTraces = cncfObservabilityExporter.exportOtelTracesJson();
  assert.ok(otelTraces && otelTraces.resourceSpans, 'resourceSpans must exist in export');
  const allSpans = cncfObservabilityExporter.getRecentSpans(10);
  assert.ok(allSpans.length > 0, 'Spans ring buffer must contain recent spans');
  const testSpan = allSpans.find(s => s.attributes && s.attributes['http.target'] === '/test-trace');
  assert.ok(testSpan, 'Must have recorded span for /test-trace');
  assert.strictEqual(testSpan.attributes['service.name'], 'ejii-noc-control-plane');
  console.log(`  ✓ OTLP span recorded: [${testSpan.name}] with traceId ${testSpan.traceId}`);

  // [71.3] Hardware OUI Vendor Resolution for 50:64:2B & 78:9A:18
  console.log('[71.3] Verifying IEEE OUI resolution for 50:64:2B (Xiaomi) & 78:9A:18 (MikroTik)...');

  // In physical-network-detector.js
  const vPndXiaomiColon = resolveGatewayOuiVendor('50:64:2B:4B:DD:31');
  const vPndXiaomiDash = resolveGatewayOuiVendor('50-64-2B-4B-DD-31');
  const vPndMikroTik = resolveGatewayOuiVendor('78:9A:18:01:02:03');
  console.log(`  ✓ physical-network-detector: 50:64:2B:4B:DD:31 -> "${vPndXiaomiColon}"`);
  console.log(`  ✓ physical-network-detector: 78:9A:18:01:02:03 -> "${vPndMikroTik}"`);
  assert.ok(vPndXiaomiColon.includes('Xiaomi Communications / Mi Router'), 'Must resolve Xiaomi router');
  assert.ok(vPndXiaomiDash.includes('Xiaomi Communications / Mi Router'), 'Must resolve Xiaomi router with dashes');
  assert.ok(vPndMikroTik.includes('MikroTik RouterOS'), 'Must resolve MikroTik RouterOS');

  // In ip-scanner.js
  const vScanXiaomi = resolveOuiVendor('50:64:2B:4B:DD:31');
  console.log(`  ✓ ip-scanner: 50:64:2B:4B:DD:31 -> "${vScanXiaomi}"`);
  assert.ok(vScanXiaomi.includes('Xiaomi Communications / Mi Router'), 'ip-scanner must resolve Xiaomi router');

  // [71.4] Dynamic Location Environment Profile Detection
  console.log('[71.4] Verifying dynamic location environment profile detection...');
  const netInfo = getPhysicalNetworkInfo({ forceRefresh: true });
  console.log(`  ✓ Detected local subnet: [${netInfo.subnetCidr}], Gateway: [${netInfo.defaultGateway}]`);
  console.log(`  ✓ Environment Profile:   [${netInfo.environmentProfile}]`);
  assert.ok(
    ['STANDARD_LAN_OR_WIFI', 'ENTERPRISE_CORPORATE_INTRANET'].includes(netInfo.environmentProfile),
    'environmentProfile must be STANDARD_LAN_OR_WIFI or ENTERPRISE_CORPORATE_INTRANET'
  );

  console.log('\n>>> ALL SUITE 71 W3C TRACEPARENT & MULTI-ENV TESTS PASSED 100% GREEN.\n');
}

if (require.main === module) {
  runW3cTraceparentPipelineAndMultiEnvLocationTests().then(() => {
    process.exit(0);
  }).catch((err) => {
    console.error('Suite 71 failed:', err);
    process.exit(1);
  });
}

module.exports = {
  runSuite71: runW3cTraceparentPipelineAndMultiEnvLocationTests,
  runW3cTraceparentPipelineAndMultiEnvLocationTests
};
