'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  MAGIC_BYTES,
  MAGIC_UINT32,
  PROTOCOL_VERSION,
  FLAGS,
  ipv4ToUint32,
  uint32ToIpv4,
  encodeBinaryPacketFrame,
  decodeBinaryPacketFrame
} = require('../src/network/packet-streaming/binary-frame-codec');
const { packetStreamer } = require('../src/network/packet-streaming/packet-streamer');
const {
  ZeroCopyFlowPipeline,
  zeroCopyFlowPipeline
} = require('../src/systems/streaming/zero-copy-flow-pipeline');

test('Track 4: High-Throughput Binary WebSocket Packet Frame Streaming', async (t) => {
  await t.test('1. verifies IPv4 TCP packet frame roundtrip encoding and decoding', () => {
    const rawPayloadHex = '4500003c1a2b40004006c0a801010a000001';
    const testFrame = {
      srcIp: '192.168.1.50',
      dstIp: '10.0.0.1',
      srcPort: 51234,
      dstPort: 443,
      protocol: 'TCP',
      tcp: { srcPort: 51234, dstPort: 443, flags: { syn: true } },
      rawHex: rawPayloadHex,
      wireLength: 1514,
      isTruncated: false,
      timestamp: 1700000000000
    };

    const encoded = encodeBinaryPacketFrame(testFrame, 64);
    assert.ok(Buffer.isBuffer(encoded), 'Encoded output must be a Buffer');
    assert.equal(encoded.subarray(0, 4).toString('ascii'), 'EJII', 'Magic header must be EJII');
    assert.equal(encoded.readUInt8(4), PROTOCOL_VERSION, 'Version must be 1');

    // IPv4 header is 32 bytes + payload slice length (18 bytes from 36 hex chars)
    const expectedPayloadLen = rawPayloadHex.length / 2;
    assert.equal(encoded.length, 32 + expectedPayloadLen, 'Total buffer length must equal header + payload');

    const decoded = decodeBinaryPacketFrame(encoded);
    assert.ok(decoded, 'Decoded frame must not be null');
    assert.equal(decoded.magic, 'EJII');
    assert.equal(decoded.version, 1);
    assert.equal(decoded.isIpv6, false);
    assert.equal(decoded.protocolName, 'TCP');
    assert.equal(decoded.protocol, 6);
    assert.equal(decoded.srcIp, '192.168.1.50');
    assert.equal(decoded.dstIp, '10.0.0.1');
    assert.equal(decoded.srcPort, 51234);
    assert.equal(decoded.dstPort, 443);
    assert.equal(decoded.wireLength, 1514);
    assert.equal(decoded.sliceLength, expectedPayloadLen);
    assert.equal(decoded.payloadHex, rawPayloadHex);
    assert.equal(decoded.hasSyn, true);
    assert.ok(decoded.tcp && decoded.tcp.flags.syn);
  });

  await t.test('2. verifies IPv6 UDP packet frame roundtrip encoding and decoding', () => {
    const rawPayloadHex = 'deadbeefcafe1234';
    const testFrame = {
      srcIp: '2001:db8::1',
      dstIp: '2606:4700:4700::1111',
      srcPort: 49152,
      dstPort: 53,
      protocol: 'UDP',
      udp: { srcPort: 49152, dstPort: 53 },
      rawHex: rawPayloadHex,
      wireLength: 1280,
      timestamp: 1700000005000
    };

    const encoded = encodeBinaryPacketFrame(testFrame, 128);
    // IPv6 fixed header is 56 bytes + payload slice length (8 bytes)
    assert.equal(encoded.length, 56 + 8);

    const decoded = decodeBinaryPacketFrame(encoded);
    assert.ok(decoded);
    assert.equal(decoded.isIpv6, true);
    assert.equal(decoded.protocolName, 'UDP');
    assert.equal(decoded.protocol, 17);
    assert.equal(decoded.srcPort, 49152);
    assert.equal(decoded.dstPort, 53);
    assert.equal(decoded.wireLength, 1280);
    assert.equal(decoded.sliceLength, 8);
    assert.equal(decoded.payloadHex, rawPayloadHex);
    assert.ok(decoded.summary.includes('UDP'));
  });

  await t.test('3. verifies payload slice clipping respects maxPayloadSlice limit', () => {
    // 500 bytes of raw payload
    const longHex = 'aa'.repeat(500);
    const testFrame = {
      srcIp: '10.10.10.10',
      dstIp: '10.10.10.20',
      protocol: 'ICMP',
      rawHex: longHex,
      wireLength: 500
    };

    // Clip to max 64 bytes
    const encoded = encodeBinaryPacketFrame(testFrame, 64);
    assert.equal(encoded.length, 32 + 64);

    const decoded = decodeBinaryPacketFrame(encoded);
    assert.equal(decoded.wireLength, 500, 'Original wire length must be preserved');
    assert.equal(decoded.sliceLength, 64, 'Slice length must be clamped to 64');
    assert.equal(decoded.payloadSlice.length, 64);
  });

  await t.test('4. verifies browser ArrayBuffer and Uint8Array zero-copy decoding', () => {
    const testFrame = {
      srcIp: '172.16.0.1',
      dstIp: '172.16.0.254',
      srcPort: 8080,
      dstPort: 80,
      protocol: 'HTTP',
      wireLength: 200
    };

    const nodeBuf = encodeBinaryPacketFrame(testFrame, 32);

    // Simulate browser receiving an ArrayBuffer
    const arrayBuffer = nodeBuf.buffer.slice(nodeBuf.byteOffset, nodeBuf.byteOffset + nodeBuf.byteLength);
    const decodedFromArrayBuffer = decodeBinaryPacketFrame(arrayBuffer);
    assert.ok(decodedFromArrayBuffer);
    assert.equal(decodedFromArrayBuffer.srcIp, '172.16.0.1');
    assert.equal(decodedFromArrayBuffer.dstIp, '172.16.0.254');
    assert.equal(decodedFromArrayBuffer.srcPort, 8080);
    assert.equal(decodedFromArrayBuffer.dstPort, 80);

    // Simulate browser Uint8Array subarray
    const uint8View = new Uint8Array(arrayBuffer);
    const decodedFromUint8 = decodeBinaryPacketFrame(uint8View);
    assert.ok(decodedFromUint8);
    assert.equal(decodedFromUint8.srcIp, '172.16.0.1');
  });

  await t.test('5. rejects invalid or corrupted binary frames cleanly', () => {
    // Null / undefined input
    assert.strictEqual(decodeBinaryPacketFrame(null), null);
    assert.strictEqual(decodeBinaryPacketFrame(undefined), null);

    // Frame smaller than header (32 bytes)
    assert.strictEqual(decodeBinaryPacketFrame(Buffer.alloc(20)), null);

    // Corrupted magic bytes
    const badMagic = Buffer.alloc(40);
    badMagic.writeUInt32BE(0x12345678, 0);
    assert.strictEqual(decodeBinaryPacketFrame(badMagic), null);

    // Unsupported version
    const badVersion = Buffer.alloc(40);
    badVersion.writeUInt32BE(MAGIC_UINT32, 0);
    badVersion.writeUInt8(99, 4); // Version 99
    assert.strictEqual(decodeBinaryPacketFrame(badVersion), null);
  });

  await t.test('6. verifies packetStreamer instance convenience methods and exports', () => {
    assert.equal(typeof packetStreamer.encodeBinaryFrame, 'function');
    assert.equal(typeof packetStreamer.decodeBinaryFrame, 'function');

    const testFrame = {
      srcIp: '8.8.8.8',
      dstIp: '192.168.1.1',
      srcPort: 53,
      dstPort: 61234,
      protocol: 'DNS',
      wireLength: 95
    };

    const encoded = packetStreamer.encodeBinaryFrame(testFrame);
    const decoded = packetStreamer.decodeBinaryFrame(encoded);

    assert.ok(decoded);
    assert.equal(decoded.srcIp, '8.8.8.8');
    assert.equal(decoded.dstIp, '192.168.1.1');
    assert.equal(decoded.srcPort, 53);
    assert.equal(decoded.dstPort, 61234);
    assert.equal(decoded.protocolName, 'DNS');
  });

  await t.test('7. verifies IPv4 Uint32 conversion helpers', () => {
    const ipStr = '192.168.100.200';
    const num = ipv4ToUint32(ipStr);
    assert.equal(uint32ToIpv4(num), ipStr);

    assert.equal(ipv4ToUint32('invalid'), 0);
    assert.equal(uint32ToIpv4(0), '0.0.0.0');
  });

  await t.test('8. verifies lock-free SPSC circular ring buffer and backpressure frame dropping', () => {
    const ring = new ZeroCopyFlowPipeline(16, 64);
    const initialStats = ring.getStats();
    assert.equal(initialStats.capacity, 16);
    assert.equal(initialStats.occupancy, 0);
    assert.equal(initialStats.droppedCount, 0);

    const dummyFrame = Buffer.alloc(64, 0xab);

    // Enqueue 16 frames to fill capacity
    for (let i = 0; i < 16; i++) {
      dummyFrame[0] = i;
      const ok = ring.enqueuePacketFrame(dummyFrame);
      assert.equal(ok, true, `Frame ${i} must enqueue successfully`);
    }

    const fullStats = ring.getStats();
    assert.equal(fullStats.occupancy, 16);
    assert.equal(fullStats.occupancyPct, 100);

    // 17th frame must drop due to backpressure
    const dropOk = ring.enqueuePacketFrame(dummyFrame);
    assert.equal(dropOk, false, '17th frame must drop due to capacity limit');
    assert.equal(ring.getStats().droppedCount, 1, 'Dropped count must increment to 1');

    // Dequeue all 16 frames
    for (let i = 0; i < 16; i++) {
      const dequeued = ring.dequeuePacketFrame();
      assert.ok(dequeued, `Dequeued slice ${i} must not be null`);
      assert.equal(dequeued[0], i, `Dequeued frame ${i} must match FIFO sequence`);
    }

    // Now empty
    assert.equal(ring.getStats().occupancy, 0);
    assert.strictEqual(ring.dequeuePacketFrame(), null, 'Empty buffer must return null');
  });

  await t.test('9. verifies zero-allocation DataView IPv4 and TCP binary header parsing', () => {
    const pipeline = new ZeroCopyFlowPipeline(64, 128);

    // Construct synthetic 54-byte IPv4 + TCP packet
    const pktBuf = Buffer.alloc(54);

    // IPv4 Header (20 bytes)
    pktBuf[0] = 0x45; // Version 4, IHL 5 (20 bytes)
    pktBuf[1] = 0x00; // DSCP / ECN
    pktBuf.writeUInt16BE(54, 2); // Total length
    pktBuf.writeUInt16BE(0x1234, 4); // Identification
    pktBuf.writeUInt16BE(0x4000, 6); // Flags (DF)
    pktBuf[8] = 64; // TTL
    pktBuf[9] = 6; // Protocol: TCP
    pktBuf.writeUInt16BE(0x0000, 10); // Checksum
    // Src: 192.168.1.100 (0xC0A80164)
    pktBuf.writeUInt32BE(0xc0a80164, 12);
    // Dst: 10.0.0.1 (0x0A000001)
    pktBuf.writeUInt32BE(0x0a000001, 16);

    // TCP Header (20 bytes at offset 20)
    pktBuf.writeUInt16BE(54321, 20); // Src Port
    pktBuf.writeUInt16BE(443, 22); // Dst Port
    pktBuf.writeUInt32BE(100000, 24); // Seq Number
    pktBuf.writeUInt32BE(50000, 28); // Ack Number
    pktBuf.writeUInt16BE(0x5012, 32); // Data offset 5 (20 bytes), Flags: SYN (0x02) + ACK (0x10) = 0x12
    pktBuf.writeUInt16BE(65535, 34); // Window Size
    pktBuf.writeUInt16BE(0x0000, 36); // Checksum
    pktBuf.writeUInt16BE(0x0000, 38); // Urgent Pointer

    // Payload (14 bytes)
    pktBuf.fill(0xee, 40, 54);

    const parsed = pipeline.parsePacketHeader(pktBuf);
    assert.ok(parsed, 'Parsed packet header must not be null');
    assert.equal(parsed.version, 4);
    assert.equal(parsed.protocol, 6);
    assert.equal(parsed.protocolName, 'TCP');
    assert.equal(parsed.srcIpStr, '192.168.1.100');
    assert.equal(parsed.dstIpStr, '10.0.0.1');
    assert.equal(parsed.srcPort, 54321);
    assert.equal(parsed.dstPort, 443);
    assert.equal(parsed.seqNumber, 100000);
    assert.equal(parsed.ackNumber, 50000);
    assert.equal(parsed.windowSize, 65535);
    assert.equal(parsed.flags.syn, true);
    assert.equal(parsed.flags.ack, true);
    assert.equal(parsed.flags.fin, false);
    assert.equal(parsed.flags.rst, false);
    assert.equal(parsed.payloadLength, 34);
    assert.ok(parsed.flowHash > 0, 'Flow hash must be non-zero');
  });

  await t.test('10. verifies real-time active flow telemetry registry and retransmission detection', () => {
    const pipeline = new ZeroCopyFlowPipeline(64, 128);

    const baseHeader = {
      version: 4,
      protocol: 6,
      protocolName: 'TCP',
      srcIpUint32: 0xc0a80164,
      dstIpUint32: 0x0a000001,
      srcIpStr: '192.168.1.100',
      dstIpStr: '10.0.0.1',
      srcPort: 49152,
      dstPort: 8080,
      totalLength: 1000,
      headerLength: 40,
      payloadLength: 960,
      seqNumber: 1000,
      ackNumber: 1,
      windowSize: 64240,
      flags: { syn: false, ack: true, fin: false, rst: false, psh: true, urg: false, ece: false, cwr: false },
      flowHash: 1234567,
      timestampMs: 1700000000000
    };

    // Packet 1: Initial normal packet
    const f1 = pipeline.ingestPacket(baseHeader);
    assert.equal(f1.packetCount, 1);
    assert.equal(f1.retransmitCount, 0);
    assert.equal(f1.outOfOrderCount, 0);

    // Packet 2: Next sequence
    const f2 = pipeline.ingestPacket({
      ...baseHeader,
      seqNumber: 1960,
      timestampMs: 1700000000010
    });
    assert.equal(f2.packetCount, 2);
    assert.equal(f2.retransmitCount, 0);

    // Packet 3: Duplicate sequence number (Retransmission)
    const f3 = pipeline.ingestPacket({
      ...baseHeader,
      seqNumber: 1960,
      timestampMs: 1700000000020
    });
    assert.equal(f3.packetCount, 3);
    assert.equal(f3.retransmitCount, 1, 'Duplicate seq must increment retransmitCount');

    // Packet 4: Prior sequence number (Out-of-order)
    const f4 = pipeline.ingestPacket({
      ...baseHeader,
      seqNumber: 500,
      timestampMs: 1700000000030
    });
    assert.equal(f4.packetCount, 4);
    assert.equal(f4.outOfOrderCount, 1, 'Lesser seq must increment outOfOrderCount');
  });

  await t.test('11. verifies micro-burst stream coupling and Morlet wavelet energy attribution', () => {
    const pipeline = new ZeroCopyFlowPipeline(64, 128);

    // Flow 1: Bursty retransmitting elephant flow
    const elephantFlow = {
      version: 4,
      protocol: 6,
      protocolName: 'TCP',
      srcIpUint32: 0x0a000005,
      dstIpUint32: 0x0a000010,
      srcIpStr: '10.0.0.5',
      dstIpStr: '10.0.0.10',
      srcPort: 9000,
      dstPort: 443,
      totalLength: 1460,
      headerLength: 40,
      payloadLength: 1420,
      seqNumber: 50000,
      ackNumber: 1,
      windowSize: 32000,
      flowHash: 11111,
      timestampMs: Date.now()
    };

    // Ingest 15 packets with duplicate seq causing retransmits
    for (let i = 0; i < 15; i++) {
      pipeline.ingestPacket({
        ...elephantFlow,
        seqNumber: 50000
      });
    }

    // Flow 2: Moderate background flow
    const bgFlow = {
      version: 4,
      protocol: 6,
      protocolName: 'TCP',
      srcIpUint32: 0x0a000006,
      dstIpUint32: 0x0a000010,
      srcIpStr: '10.0.0.6',
      dstIpStr: '10.0.0.10',
      srcPort: 9001,
      dstPort: 80,
      totalLength: 300,
      headerLength: 40,
      payloadLength: 260,
      seqNumber: 1000,
      ackNumber: 1,
      windowSize: 65535,
      flowHash: 22222,
      timestampMs: Date.now()
    };
    for (let i = 0; i < 3; i++) {
      pipeline.ingestPacket({ ...bgFlow, seqNumber: 1000 + i * 300 });
    }

    // Trigger scale-2 Morlet wavelet energy ratio spike (> 2.0)
    const report = pipeline.handleMicroBurstInterrupt({
      scale: 2,
      energyRatio: 2.85,
      hurstExponent: 0.82
    });

    assert.ok(report);
    assert.equal(report.scale2EnergyRatio, 2.85);
    assert.equal(report.hurstExponent, 0.82);
    assert.equal(report.topAttributedFlows.length, 2);

    const topFlow = report.topAttributedFlows[0];
    assert.equal(topFlow.srcIp, '10.0.0.5');
    assert.equal(topFlow.srcPort, 9000);
    assert.ok(topFlow.attributionScore > 1000);
    assert.equal(topFlow.suspectedAnomaly, 'FAST_RETRANSMIT_STORM');
    assert.ok(report.mitigationRecommendation.includes('TCP pacing') || report.mitigationRecommendation.includes('initcwnd'));
  });
});
