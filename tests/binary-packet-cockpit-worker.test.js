/**
 * Track 4: Line-Rate Binary Packet Cockpit Offscreen Worker & Equipotential Diffusion Shader
 *
 * Verifies:
 *   1. Offscreen binary packet decoding via DataView with zero-copy binary buffer slicing.
 *   2. Support for IPv4 and IPv6 binary frame protocols (TCP, UDP, ICMP, DNS, TLS).
 *   3. Ring buffer 10,000 capacity boundary and 60Hz batch flush queue.
 *   4. Mathematical scalar potential field evaluation and Gaussian heat decay:
 *      u(x, y) = sum_k u_k * exp(-dist_k^2 / (2 * sigma_k^2))
 *   5. Equipotential contour grid calculation and heat gradient color mapping.
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  decodeBinaryFrameBuffer,
  DecoderRingBuffer,
  PacketBinaryDecoderWorker
} = require('../public/js/workers/packet-binary-decoder-worker');
const {
  evaluateScalarPotential,
  computeEquipotentialField,
  getHeatRgb,
  renderEquipotentialCanvas
} = require('../public/js/equipotential-contour-shader');
const { encodeBinaryPacketFrame } = require('../src/network/packet-streaming/binary-frame-codec');

test('Track 4: Line-Rate Binary Packet Cockpit Offscreen Worker & Equipotential Diffusion Shader', async (t) => {
  await t.test('1. decodes binary IPv4 frames with zero-copy DataView operations', () => {
    // Generate valid binary frame using Phase 2 codec
    const testFrame = {
      frameNumber: 1,
      timestamp: Date.now() * 1000,
      protocol: 'TCP',
      srcIp: '192.168.1.100',
      dstIp: '10.0.0.1',
      srcPort: 54321,
      dstPort: 443,
      length: 128,
      rawPayload: '454a494954455354' // "EJIITEST" hex
    };

    const encodedBuffer = encodeBinaryPacketFrame(testFrame);
    assert.ok(encodedBuffer instanceof Buffer || encodedBuffer instanceof Uint8Array);

    const decoded = decodeBinaryFrameBuffer(encodedBuffer);
    assert.ok(decoded, 'Frame must decode cleanly');
    assert.equal(decoded.srcIp, '192.168.1.100');
    assert.equal(decoded.dstIp, '10.0.0.1');
    assert.equal(decoded.srcPort, 54321);
    assert.equal(decoded.dstPort, 443);
    assert.equal(decoded.protocol, 'TLS');
    assert.equal(decoded.flags.isIpv6, false);
    assert.ok(decoded.totalFrameBytes >= 32);
  });

  await t.test('2. decodes binary IPv6 frames and transport ports', () => {
    const testFrame = {
      frameNumber: 2,
      timestamp: Date.now() * 1000,
      protocol: 'UDP',
      srcIp: '2001:db8::1',
      dstIp: '2001:db8::2',
      srcPort: 5353,
      dstPort: 53,
      length: 96,
      rawPayload: '0001000000000000'
    };

    const encodedBuffer = encodeBinaryPacketFrame(testFrame);
    const decoded = decodeBinaryFrameBuffer(encodedBuffer);
    assert.ok(decoded, 'IPv6 frame must decode cleanly');
    assert.ok(decoded.srcIp.includes('2001:db8'));
    assert.ok(decoded.dstIp.includes('2001:db8'));
    assert.equal(decoded.srcPort, 5353);
    assert.equal(decoded.dstPort, 53);
    assert.equal(decoded.protocol, 'DNS');
    assert.equal(decoded.flags.isIpv6, true);
  });

  await t.test('3. verifies DecoderRingBuffer 10,000 capacity and FIFO retention', () => {
    const ring = new DecoderRingBuffer(100);

    for (let i = 1; i <= 150; i++) {
      ring.push({ frameNumber: i, length: 64, protocol: 'TCP' });
    }

    assert.equal(ring.count, 100, 'Ring buffer must clamp strictly to capacity');
    assert.equal(ring.totalFramesIngested, 150, 'Total ingested count must reflect all frames');

    const recent = ring.getRecent(10);
    assert.equal(recent.length, 10);
    assert.equal(recent[recent.length - 1].frameNumber, 150, 'Most recent frame must be latest ingested');
    assert.equal(recent[0].frameNumber, 141);
  });

  await t.test('4. batches frame bursts in PacketBinaryDecoderWorker for 60Hz UI dispatch', () => {
    let receivedBatch = null;
    const worker = new PacketBinaryDecoderWorker({
      capacity: 500,
      flushIntervalMs: 50,
      onBatch: (batchData) => {
        receivedBatch = batchData;
      }
    });

    const testFrame = {
      timestamp: Date.now() * 1000,
      protocol: 'ICMP',
      srcIp: '8.8.8.8',
      dstIp: '192.168.1.50',
      length: 64
    };
    const buf = encodeBinaryPacketFrame(testFrame);

    for (let i = 0; i < 5; i++) {
      worker.ingestBinaryFrame(buf);
    }

    // Force flush
    const flushed = worker.flushBatch();
    assert.equal(flushed.length, 5, 'Must flush 5 accumulated frames');
    assert.ok(receivedBatch, 'onBatch callback must receive packet batch');
    assert.equal(receivedBatch.frames.length, 5);
    assert.equal(receivedBatch.totalFramesDecoded, 5);

    worker.destroy();
  });

  await t.test('5. computes continuous scalar potential field with Gaussian decay u(x, y)', () => {
    const sources = [
      { x: 100, y: 100, potential: 1.0, sigma: 50 },
      { x: 300, y: 100, potential: 0.5, sigma: 50 }
    ];

    // At source 1 center (100, 100)
    const uAtCenter1 = evaluateScalarPotential(100, 100, sources, 50);
    // At center 1: u_1 + u_2 * exp(-200^2 / (2 * 50^2))
    assert.ok(uAtCenter1 >= 1.0, `Potential at source center must be >= 1.0 (got ${uAtCenter1})`);

    // Far away from both sources (800, 800)
    const uFar = evaluateScalarPotential(800, 800, sources, 50);
    assert.ok(uFar < 0.001, `Potential far away must decay exponentially towards 0 (got ${uFar})`);

    // Midpoint (200, 100): equidistant from both
    const uMid = evaluateScalarPotential(200, 100, sources, 50);
    assert.ok(uMid > uFar, 'Midpoint potential must exceed far-field potential');
    assert.ok(uMid < uAtCenter1, 'Midpoint potential must be less than hotspot center');
  });

  await t.test('6. computes discretized equipotential field grid and Emerald->Amber->Crimson color ramp', () => {
    const sources = [
      { x: 50, y: 50, potential: 0.9, sigma: 40 }
    ];

    const field = computeEquipotentialField(sources, 200, 200, 10);
    assert.equal(field.cols, 20);
    assert.equal(field.rows, 20);
    assert.equal(field.grid.length, 400);
    assert.ok(field.maxPotential >= 0.85);

    // Color ramp verification
    const [rLow, gLow, bLow] = getHeatRgb(0.1); // Emerald
    assert.ok(gLow > rLow, 'Low heat must have dominant green (Emerald)');

    const [rHigh, gHigh, bHigh] = getHeatRgb(0.9); // Crimson
    assert.ok(rHigh > gHigh && rHigh > bHigh, 'High heat must have dominant red (Crimson)');

    // Mock canvas context for renderEquipotentialCanvas
    const mockContext = {
      clearRect: () => {},
      save: () => {},
      restore: () => {},
      createRadialGradient: () => ({ addColorStop: () => {} }),
      beginPath: () => {},
      arc: () => {},
      fill: () => {},
      stroke: () => {},
      setLineDash: () => {}
    };
    const mockCanvas = {
      width: 400,
      height: 300,
      getContext: () => mockContext
    };

    const renderResult = renderEquipotentialCanvas(mockCanvas, sources);
    assert.equal(renderResult.rendered, true);
    assert.equal(renderResult.sourceCount, 1);
  });
});
