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
});
