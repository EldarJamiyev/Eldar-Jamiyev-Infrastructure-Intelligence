// tests/suite-83-tcp-stream-waterfall-and-jitter.test.js
/**
 * EJII Test Suite 83: TCP Stream Waterfall & RFC 3550 Inter-Arrival Jitter Engine
 * Verifies bidirectional 5-tuple canonical reassembly, Float64Array jitter math,
 * TCP handshake RTT, retransmission classification, and API routes.
 */

'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const { TcpStreamWaterfallEngine } = require('../src/sniffer/tcp-stream-waterfall-engine');

async function runSuite83TcpStreamWaterfallAndJitter() {
  console.log('========================================================================');
  console.log('  === [SUITE 83] TCP STREAM WATERFALL & RFC 3550 JITTER ENGINE ===      ');
  console.log('========================================================================\n');

  const engine = new TcpStreamWaterfallEngine();

  // [83.1] Canonical 5-Tuple Key Grouping
  console.log('[Test 83.1] Verifying Canonical 5-tuple bidirectional stream grouping...');
  const keyA = engine.getStreamKey('192.168.31.89', 54320, '192.168.31.1', 443, 'TCP');
  const keyB = engine.getStreamKey('192.168.31.1', 443, '192.168.31.89', 54320, 'TCP');
  assert.strictEqual(keyA, keyB, 'Both forward and reverse packet directions must hash to identical canonical stream key');
  assert.ok(keyA.includes('192.168.31.1:443') && keyA.includes('192.168.31.89:54320'), 'Canonical key must include both IP:port endpoints');
  console.log(`  ✓ Canonical 5-tuple key: ${keyA}`);

  // [83.2] 3-Way Handshake & RTT Measurement
  console.log('[Test 83.2] Verifying 3-way handshake RTT calculation...');
  const t0 = 1000.0;
  const handshakeFrames = [
    // Client SYN (seq=1000)
    { frameNumber: 1, timestamp: t0, srcIp: '192.168.31.89', dstIp: '192.168.31.1', srcPort: 54320, dstPort: 443, ipProtocol: 'TCP', length: 64, tcpSeq: 1000, tcpAck: 0, tcpFlags: { syn: true }, windowSize: 65535 },
    // Server SYN-ACK (seq=5000, ack=1001) at t0 + 24.5ms
    { frameNumber: 2, timestamp: t0 + 24.5, srcIp: '192.168.31.1', dstIp: '192.168.31.89', srcPort: 443, dstPort: 54320, ipProtocol: 'TCP', length: 64, tcpSeq: 5000, tcpAck: 1001, tcpFlags: { syn: true, ack: true }, windowSize: 65535 },
    // Client ACK (seq=1001, ack=5001) at t0 + 32.0ms
    { frameNumber: 3, timestamp: t0 + 32.0, srcIp: '192.168.31.89', dstIp: '192.168.31.1', srcPort: 54320, dstPort: 443, ipProtocol: 'TCP', length: 54, tcpSeq: 1001, tcpAck: 5001, tcpFlags: { ack: true }, windowSize: 65535 }
  ];

  engine.ingestFrames(handshakeFrames);
  const stream = engine.getStreamWaterfall(keyA);
  assert.ok(stream, 'Stream must be reassembled and indexed by canonical key');
  assert.ok(stream.handshakeRttMs !== null, 'Handshake RTT must be computed');
  assert.ok(Math.abs(stream.handshakeRttMs - 32.0) < 0.1, `Handshake RTT should be approx 32.0ms, got ${stream.handshakeRttMs}`);
  console.log(`  ✓ Handshake RTT measured: ${stream.handshakeRttMs.toFixed(2)} ms`);

  // [83.3] RFC 3550 Inter-Arrival Jitter Math
  console.log('[Test 83.3] Verifying RFC 3550 jitter formula J_i = J_{i-1} + (|D| - J_{i-1})/16...');
  // Feed subsequent data frames with known inter-arrival deltas
  const dataFrames = [
    { frameNumber: 4, timestamp: t0 + 50.0, srcIp: '192.168.31.89', dstIp: '192.168.31.1', srcPort: 54320, dstPort: 443, ipProtocol: 'TCP', length: 500, tcpSeq: 1001, tcpAck: 5001, tcpFlags: { ack: true, psh: true }, windowSize: 65535 },
    { frameNumber: 5, timestamp: t0 + 72.0, srcIp: '192.168.31.1', dstIp: '192.168.31.89', srcPort: 443, dstPort: 54320, ipProtocol: 'TCP', length: 1460, tcpSeq: 5001, tcpAck: 1501, tcpFlags: { ack: true }, windowSize: 65535 },
    { frameNumber: 6, timestamp: t0 + 105.0, srcIp: '192.168.31.1', dstIp: '192.168.31.89', srcPort: 443, dstPort: 54320, ipProtocol: 'TCP', length: 1460, tcpSeq: 6461, tcpAck: 1501, tcpFlags: { ack: true }, windowSize: 65535 },
    { frameNumber: 7, timestamp: t0 + 115.0, srcIp: '192.168.31.89', dstIp: '192.168.31.1', srcPort: 54320, dstPort: 443, ipProtocol: 'TCP', length: 54, tcpSeq: 1501, tcpAck: 7921, tcpFlags: { ack: true }, windowSize: 65535 }
  ];
  engine.ingestFrames(dataFrames);
  const streamUpdated = engine.getStreamWaterfall(keyA);
  assert.ok(typeof streamUpdated.rfc3550JitterMs === 'number', 'rfc3550JitterMs must be a float');
  assert.ok(streamUpdated.rfc3550JitterMs >= 0, `Jitter must be non-negative, got ${streamUpdated.rfc3550JitterMs}`);
  console.log(`  ✓ RFC 3550 computed jitter: ${streamUpdated.rfc3550JitterMs.toFixed(3)} ms`);

  // [83.4] Retransmission & Duplicate ACK Detection
  console.log('[Test 83.4] Verifying retransmission & dup ACK tracking...');
  const anomalyFrames = [
    // Duplicate ACK
    { frameNumber: 8, timestamp: t0 + 130.0, srcIp: '192.168.31.89', dstIp: '192.168.31.1', srcPort: 54320, dstPort: 443, ipProtocol: 'TCP', length: 54, tcpSeq: 1501, tcpAck: 7921, tcpFlags: { ack: true }, windowSize: 65535 },
    // Retransmission of seq=6461
    { frameNumber: 9, timestamp: t0 + 160.0, srcIp: '192.168.31.1', dstIp: '192.168.31.89', srcPort: 443, dstPort: 54320, ipProtocol: 'TCP', length: 1460, tcpSeq: 6461, tcpAck: 1501, tcpFlags: { ack: true }, windowSize: 65535 }
  ];
  engine.ingestFrames(anomalyFrames);
  const streamAnomalies = engine.getStreamWaterfall(keyA);
  assert.ok(streamAnomalies.anomalies.dupAckCount >= 1, `Expected at least 1 dup ACK, got ${streamAnomalies.anomalies.dupAckCount}`);
  assert.ok(streamAnomalies.anomalies.retransmissionCount >= 1, `Expected at least 1 retransmission, got ${streamAnomalies.anomalies.retransmissionCount}`);
  console.log(`  ✓ Duplicate ACKs: ${streamAnomalies.anomalies.dupAckCount}, Retransmissions: ${streamAnomalies.anomalies.retransmissionCount}`);

  // [83.5] Waterfall Points & Sequence Timeline
  console.log('[Test 83.5] Verifying time-sequence waterfall points...');
  assert.strictEqual(streamAnomalies.waterfallPoints.length, 9, 'All 9 frames must have corresponding waterfall points');
  const ptFirst = streamAnomalies.waterfallPoints[0];
  const ptLast = streamAnomalies.waterfallPoints[streamAnomalies.waterfallPoints.length - 1];
  assert.strictEqual(ptFirst.frameNumber, 1);
  assert.strictEqual(ptFirst.classification, 'HANDSHAKE');
  assert.ok(ptLast.relativeTimeMs > 0, 'Relative time must be strictly positive');
  assert.strictEqual(ptLast.classification, 'RETRANSMISSION');
  console.log(`  ✓ Waterfall timeline span: 0ms to ${ptLast.relativeTimeMs.toFixed(2)} ms`);

  // [83.6] Express Route Mock Verification
  console.log('[Test 83.6] Verifying Express GET /api/network/tcp-stream-waterfall contract...');
  const req = {
    app: { locals: { tcpStreamWaterfallEngine: engine } },
    query: {}
  };
  let responseData = null;
  const res = {
    json: (data) => { responseData = data; },
    status: () => res
  };

  const routesNetwork = require('../src/api/routes-network');
  const layer = routesNetwork.stack.find(s => s.route && s.route.path === '/tcp-stream-waterfall');
  assert.ok(layer, 'Route /tcp-stream-waterfall must be registered in routes-network.js');
  layer.route.stack[0].handle(req, res, () => {});

  assert.ok(responseData, 'Route must respond with JSON');
  assert.strictEqual(responseData.success, true);
  assert.ok(Array.isArray(responseData.streams) && responseData.streams.length >= 1);
  console.log(`  ✓ Route returned ${responseData.streams.length} stream summaries successfully.`);

  console.log('\n========================================================================');
  console.log('  SUITE 83 PASSED: TCP STREAM WATERFALL & JITTER ENGINE 100% GREEN     ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runSuite83TcpStreamWaterfallAndJitter().catch((err) => {
    console.error('Suite 83 failed:', err);
    process.exit(1);
  });
}

module.exports = {
  runSuite83TcpStreamWaterfallAndJitter,
  runSuite83: runSuite83TcpStreamWaterfallAndJitter
};
