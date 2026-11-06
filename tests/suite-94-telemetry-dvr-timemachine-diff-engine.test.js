// tests/suite-94-telemetry-dvr-timemachine-diff-engine.test.js
/**
 * EJII Test Suite 94: Telemetry Time-Machine DVR & Keyframe Differential Diff Engine
 * Verifies 240-frame ring-buffer eviction, deterministic keyframe recording,
 * structural delta diffing (added/removed nodes, latency deltas, socket changes),
 * and REST API endpoints /api/observability/dvr/frames, /record, and /diff.
 */

'use strict';

const assert = require('node:assert/strict');
const { TelemetryDvrTimeMachine } = require('../src/observability/telemetry-dvr-timemachine');
const routesObservability = require('../src/api/routes-observability');

async function runSuite94TelemetryDvrTimeMachine() {
  console.log('========================================================================');
  console.log('  === [SUITE 94] TELEMETRY DVR TIME-MACHINE & SNAPSHOT DIFF ENGINE ===   ');
  console.log('========================================================================\n');

  // [94.1] Ring Buffer Capacity and FIFO Eviction
  console.log('[Test 94.1] Validating ring-buffer capacity enforcement and FIFO eviction (capacity = 5)...');
  const dvr = new TelemetryDvrTimeMachine(5);

  for (let i = 1; i <= 8; i++) {
    dvr.recordFrame({
      label: `Checkpoint ${i}`,
      cpuPct: 10 + i,
      ramPct: 40 + i,
      nodesSnapshot: [{ id: `N-${i}`, ip: `10.0.0.${i}`, latencyMs: i * 2 }]
    });
  }

  const frames = dvr.listFrames();
  assert.strictEqual(frames.length, 5, `Ring buffer must be clamped to maxFrames 5, got ${frames.length}`);
  assert.strictEqual(frames[0].label, 'Checkpoint 4', 'Oldest frames (1, 2, 3) must be evicted first');
  assert.strictEqual(frames[4].label, 'Checkpoint 8', 'Newest frame must be Checkpoint 8');
  console.log(`  ✓ Ring buffer enforced: ${frames.length} frames active [Checkpoint 4 .. Checkpoint 8].`);

  // [94.2] Snapshot Recording Integrity & Cryptographic ID
  console.log('[Test 94.2] Testing keyframe recording with cryptographic ID and ISO timestamp...');
  const recorded = dvr.recordFrame({
    label: 'Incident Baseline',
    lambda2: 0.1824,
    stlRobustness: 1.50,
    cpuPct: 22.4,
    ramPct: 48.0,
    activeAnomalies: 0,
    nodesSnapshot: [
      { id: 'L1', ip: '192.168.1.1', latencyMs: 2.1 },
      { id: 'L2', ip: '192.168.1.2', latencyMs: 0.8 }
    ],
    socketsSnapshot: [
      { protocol: 'TCP', localPort: 8443, remoteIp: '192.168.1.89', remotePort: 51200, processName: 'node.exe' }
    ]
  });

  assert.ok(recorded.id.startsWith('dvr-'), 'Keyframe ID must have dvr- prefix');
  assert.strictEqual(recorded.label, 'Incident Baseline');
  assert.strictEqual(recorded.topologyNodeCount, 2);
  assert.strictEqual(recorded.lambda2, 0.1824);
  assert.strictEqual(recorded.nodesSnapshot.length, 2);
  assert.strictEqual(recorded.socketsSnapshot.length, 1);
  console.log(`  ✓ Keyframe recorded: ID=${recorded.id}, Nodes=${recorded.topologyNodeCount}, Time=${recorded.isoTime}`);

  // [94.3] Structural Delta Diffing
  console.log('[Test 94.3] Computing structural delta diff between two keyframe snapshots...');
  const frameA = dvr.recordFrame({
    label: 'State A: Normal Operations',
    lambda2: 0.22,
    stlRobustness: 1.8,
    cpuPct: 18.0,
    ramPct: 42.0,
    activeAnomalies: 0,
    nodesSnapshot: [
      { id: 'GW-01', ip: '10.0.0.1', latencyMs: 1.5 },
      { id: 'APP-01', ip: '10.0.0.10', latencyMs: 0.4 }
    ],
    socketsSnapshot: [
      { protocol: 'TCP', localPort: 443, remoteIp: '10.0.0.50', remotePort: 50100 }
    ]
  });

  const frameB = dvr.recordFrame({
    label: 'State B: Link Severance & Latency Spike',
    lambda2: 0.08,
    stlRobustness: -0.4,
    cpuPct: 45.0,
    ramPct: 50.0,
    activeAnomalies: 2,
    nodesSnapshot: [
      { id: 'GW-01', ip: '10.0.0.1', latencyMs: 18.5 }, // +17.0ms latency shift
      { id: 'DB-01', ip: '10.0.0.20', latencyMs: 2.1 }  // Added node; APP-01 removed
    ],
    socketsSnapshot: [
      { protocol: 'TCP', localPort: 3389, remoteIp: '10.0.0.99', remotePort: 49200 } // New RDP socket
    ]
  });

  const diff = dvr.computeSnapshotDiff(frameA, frameB);
  assert.ok(diff, 'Diff must be computed');
  assert.strictEqual(diff.fromId, frameA.id);
  assert.strictEqual(diff.toId, frameB.id);
  assert.deepStrictEqual(diff.addedNodes, ['DB-01'], 'DB-01 must be detected as added');
  assert.deepStrictEqual(diff.removedNodes, ['APP-01'], 'APP-01 must be detected as removed');
  assert.strictEqual(diff.latencyDeltaByNode['GW-01'], 17.0, 'GW-01 latency delta must be +17.0ms');
  assert.ok(diff.lambda2Delta < 0, `lambda2Delta must be negative (${diff.lambda2Delta})`);
  assert.strictEqual(diff.anomaliesDelta, 2, 'Anomalies delta must be +2');
  assert.ok(diff.summary.includes('nodes added'), 'Summary must mention node deltas');
  console.log(`  ✓ Structural diff verified:\n    Added: ${diff.addedNodes.join(', ')} | Removed: ${diff.removedNodes.join(', ')} | GW-01 Delta: +${diff.latencyDeltaByNode['GW-01']}ms | Summary: ${diff.summary}`);

  // [94.4] REST API Endpoint: GET /api/observability/dvr/frames
  console.log('[Test 94.4] Testing GET /api/observability/dvr/frames via router stack...');
  const framesLayer = routesObservability.stack.find(s => s.route && s.route.path === '/dvr/frames');
  assert.ok(framesLayer, 'Route GET /dvr/frames must exist in routes-observability.js');

  let framesJson = null;
  const mockReqFrames = { query: {} };
  const mockResFrames = {
    statusCode: 200,
    status(c) { this.statusCode = c; return this; },
    json(d) { framesJson = d; return this; }
  };
  const framesHandler = framesLayer.route.stack[framesLayer.route.stack.length - 1].handle;
  framesHandler(mockReqFrames, mockResFrames, () => {});

  assert.ok(framesJson, 'Must return JSON');
  assert.strictEqual(framesJson.success, true);
  assert.ok(Array.isArray(framesJson.frames));
  console.log(`  ✓ GET /api/observability/dvr/frames returned ${framesJson.frames.length} keyframes.`);

  // [94.5] REST API Endpoint: POST /api/observability/dvr/record
  console.log('[Test 94.5] Testing POST /api/observability/dvr/record via router stack...');
  const recordLayer = routesObservability.stack.find(s => s.route && s.route.path === '/dvr/record');
  assert.ok(recordLayer, 'Route POST /dvr/record must exist in routes-observability.js');

  let recordJson = null;
  const mockReqRecord = {
    body: {
      label: 'Automated Test Checkpoint',
      lambda2: 0.19,
      cpuPct: 15.0
    }
  };
  const mockResRecord = {
    statusCode: 200,
    status(c) { this.statusCode = c; return this; },
    json(d) { recordJson = d; return this; }
  };
  const recordHandler = recordLayer.route.stack[recordLayer.route.stack.length - 1].handle;
  recordHandler(mockReqRecord, mockResRecord, () => {});

  assert.ok(recordJson, 'Must return JSON');
  assert.strictEqual(recordJson.success, true);
  assert.strictEqual(recordJson.frame.label, 'Automated Test Checkpoint');
  console.log(`  ✓ POST /api/observability/dvr/record captured: ID=${recordJson.frame.id}`);

  // [94.6] REST API Endpoint: GET /api/observability/dvr/diff
  console.log('[Test 94.6] Testing GET /api/observability/dvr/diff via router stack...');
  const diffLayer = routesObservability.stack.find(s => s.route && s.route.path === '/dvr/diff');
  assert.ok(diffLayer, 'Route GET /dvr/diff must exist in routes-observability.js');

  let diffJson = null;
  const mockReqDiff = { query: {} };
  const mockResDiff = {
    statusCode: 200,
    status(c) { this.statusCode = c; return this; },
    json(d) { diffJson = d; return this; }
  };
  const diffHandler = diffLayer.route.stack[diffLayer.route.stack.length - 1].handle;
  diffHandler(mockReqDiff, mockResDiff, () => {});

  assert.ok(diffJson, 'Must return JSON');
  assert.strictEqual(diffJson.success, true);
  assert.ok(diffJson.diff, 'diff object must be returned');
  assert.ok(typeof diffJson.diff.summary === 'string');
  console.log(`  ✓ GET /api/observability/dvr/diff returned 200 OK: summary="${diffJson.diff.summary}"`);

  console.log('\n========================================================================');
  console.log('  SUITE 94 PASSED: TELEMETRY DVR & SNAPSHOT DIFF ENGINE 100% GREEN      ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runSuite94TelemetryDvrTimeMachine().catch((err) => {
    console.error('Suite 94 failed:', err);
    process.exit(1);
  });
}

module.exports = {
  runSuite94TelemetryDvrTimeMachine,
  runSuite94: runSuite94TelemetryDvrTimeMachine
};
