// tests/suite-99-full-api-route-and-schema-contract-matrix.test.js
/**
 * EJII Test Suite 99: Full Sovereign Singularity API Route & Schema Contract Matrix
 * Executes full schema contract validation across all 13 new REST API endpoints:
 *   1. POST /api/network/dissect-l7
 *   2. GET /api/network/l7-protocol-stats
 *   3. POST /api/network/digital-twin/simulate
 *   4. GET /api/network/qos-dscp-audit
 *   5. GET /api/network/zero-trust-policies
 *   6. POST /api/rca/spectral-fft
 *   7. GET /api/rca/spectral-fft
 *   8. POST /api/rca/war-room/execute
 *   9. GET /api/rca/war-room/latest
 *  10. GET /api/diagnostics/kernel-radio-inspector
 *  11. GET /api/observability/dvr/frames
 *  12. POST /api/observability/dvr/record
 *  13. GET /api/observability/dvr/diff
 */

'use strict';

const assert = require('node:assert/strict');
const routesNetwork = require('../src/api/routes-network');
const routesRca = require('../src/api/routes-rca');
const routesDiagnostics = require('../src/api/routes-diagnostics');
const routesObservability = require('../src/api/routes-observability');

function invokeRoute(router, method, pathStr, reqBody = {}, reqQuery = {}) {
  const normMethod = method.toLowerCase();
  const layer = router.stack.find(s => {
    if (!s.route) return false;
    const matchesPath = Array.isArray(s.route.path) ? s.route.path.includes(pathStr) : s.route.path === pathStr;
    const matchesMethod = s.route.methods && s.route.methods[normMethod];
    return matchesPath && matchesMethod;
  });

  if (!layer) {
    throw new Error(`Route [${method.toUpperCase()} ${pathStr}] not found in router stack!`);
  }

  let capturedJson = null;
  let capturedCode = 200;

  const mockReq = { body: reqBody, query: reqQuery };
  const mockRes = {
    statusCode: 200,
    status(c) { capturedCode = c; return this; },
    json(d) { capturedJson = d; return this; }
  };

  const handler = layer.route.stack[layer.route.stack.length - 1].handle;
  handler(mockReq, mockRes, () => {});

  return { statusCode: capturedCode, body: capturedJson };
}

async function runSuite99ApiContractMatrix() {
  console.log('========================================================================');
  console.log('  === [SUITE 99] SOVEREIGN SINGULARITY 13-API CONTRACT MATRIX ===        ');
  console.log('========================================================================\n');

  // [99.1] Network Family (5 Endpoints)
  console.log('[Test 99.1] Validating Network Family API Contract Matrix...');
  // 1. POST /dissect-l7
  const r1 = invokeRoute(routesNetwork, 'POST', '/dissect-l7', { hex: '505249202a20485454502f322e300d0a0d0a534d0d0a0d0a' });
  assert.strictEqual(r1.statusCode, 200);
  assert.strictEqual(r1.body.success, true);
  assert.strictEqual(r1.body.identifiedProtocol, 'HTTP/2');
  console.log('  ✓ 1/13: POST /api/network/dissect-l7 -> 200 OK (HTTP/2)');

  // 2. GET /l7-protocol-stats
  const r2 = invokeRoute(routesNetwork, 'GET', '/l7-protocol-stats');
  assert.strictEqual(r2.statusCode, 200);
  assert.strictEqual(r2.body.success, true);
  assert.ok(r2.body.protocols.quicRfc9000);
  console.log('  ✓ 2/13: GET /api/network/l7-protocol-stats -> 200 OK');

  // 3. POST /digital-twin/simulate
  const r3 = invokeRoute(routesNetwork, 'POST', '/digital-twin/simulate', { scenario: { trafficMultiplier: 1.5 } });
  assert.strictEqual(r3.statusCode, 200);
  assert.strictEqual(r3.body.success, true);
  assert.ok(typeof r3.body.deltaLambda2 === 'number');
  console.log('  ✓ 3/13: POST /api/network/digital-twin/simulate -> 200 OK (deltaLambda2)');

  // 4. GET /qos-dscp-audit
  const r4 = invokeRoute(routesNetwork, 'GET', '/qos-dscp-audit');
  assert.strictEqual(r4.statusCode, 200);
  assert.strictEqual(r4.body.success, true);
  assert.ok(r4.body.dscpDistribution);
  console.log('  ✓ 4/13: GET /api/network/qos-dscp-audit -> 200 OK');

  // 5. GET /zero-trust-policies
  const r5 = invokeRoute(routesNetwork, 'GET', '/zero-trust-policies');
  assert.strictEqual(r5.statusCode, 200);
  assert.strictEqual(r5.body.success, true);
  assert.ok(r5.body.windowsNetshRules.length > 0);
  console.log('  ✓ 5/13: GET /api/network/zero-trust-policies -> 200 OK');

  // [99.2] RCA Family (4 Endpoints)
  console.log('\n[Test 99.2] Validating RCA Family API Contract Matrix...');
  // 6. POST /spectral-fft
  const r6 = invokeRoute(routesRca, 'POST', '/spectral-fft', { timeSeries: [10, 20, 10, 20, 10, 20, 10, 20], samplingRateHz: 10 });
  assert.strictEqual(r6.statusCode, 200);
  assert.strictEqual(r6.body.success, true);
  assert.ok(typeof r6.body.spectralFlatness === 'number');
  console.log('  ✓ 6/13: POST /api/rca/spectral-fft -> 200 OK');

  // 7. GET /spectral-fft
  const r7 = invokeRoute(routesRca, 'GET', '/spectral-fft');
  assert.strictEqual(r7.statusCode, 200);
  assert.strictEqual(r7.body.success, true);
  assert.ok(Array.isArray(r7.body.frequencies));
  console.log('  ✓ 7/13: GET /api/rca/spectral-fft -> 200 OK');

  // 8. POST /war-room/execute
  const r8 = invokeRoute(routesRca, 'POST', '/war-room/execute', { incidentContext: 'Matrix verification run' });
  assert.strictEqual(r8.statusCode, 200);
  assert.strictEqual(r8.body.success, true);
  assert.ok(r8.body.warRoomSessionId);
  console.log('  ✓ 8/13: POST /api/rca/war-room/execute -> 200 OK');

  // 9. GET /war-room/latest
  const r9 = invokeRoute(routesRca, 'GET', '/war-room/latest');
  assert.strictEqual(r9.statusCode, 200);
  assert.strictEqual(r9.body.success, true);
  assert.ok(r9.body.warRoomSessionId);
  console.log('  ✓ 9/13: GET /api/rca/war-room/latest -> 200 OK');

  // [99.3] Diagnostics Family (1 Endpoint)
  console.log('\n[Test 99.3] Validating Diagnostics Family API Contract Matrix...');
  // 10. GET /kernel-radio-inspector
  const r10 = invokeRoute(routesDiagnostics, 'GET', '/kernel-radio-inspector');
  assert.strictEqual(r10.statusCode, 200);
  assert.strictEqual(r10.body.success, true);
  assert.ok(r10.body.radio);
  assert.ok(r10.body.kernelTcp);
  console.log('  ✓ 10/13: GET /api/diagnostics/kernel-radio-inspector -> 200 OK');

  // [99.4] Observability Family (3 Endpoints)
  console.log('\n[Test 99.4] Validating Observability DVR Family API Contract Matrix...');
  // 11. GET /dvr/frames
  const r11 = invokeRoute(routesObservability, 'GET', '/dvr/frames');
  assert.strictEqual(r11.statusCode, 200);
  assert.strictEqual(r11.body.success, true);
  assert.ok(Array.isArray(r11.body.frames));
  console.log('  ✓ 11/13: GET /api/observability/dvr/frames -> 200 OK');

  // 12. POST /dvr/record
  const r12 = invokeRoute(routesObservability, 'POST', '/dvr/record', { label: 'Matrix Test Frame', lambda2: 0.18 });
  assert.strictEqual(r12.statusCode, 200);
  assert.strictEqual(r12.body.success, true);
  assert.ok(r12.body.frame.id);
  console.log('  ✓ 12/13: POST /api/observability/dvr/record -> 200 OK');

  // 13. GET /dvr/diff
  const r13 = invokeRoute(routesObservability, 'GET', '/dvr/diff');
  assert.strictEqual(r13.statusCode, 200);
  assert.strictEqual(r13.body.success, true);
  assert.ok(r13.body.diff);
  console.log('  ✓ 13/13: GET /api/observability/dvr/diff -> 200 OK');

  console.log('\n========================================================================');
  console.log('  SUITE 99 PASSED: FULL 13-API ROUTE & SCHEMA CONTRACT MATRIX 100% GREEN');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runSuite99ApiContractMatrix().catch((err) => {
    console.error('Suite 99 failed:', err);
    process.exit(1);
  });
}

module.exports = {
  runSuite99ApiContractMatrix,
  runSuite99: runSuite99ApiContractMatrix
};
