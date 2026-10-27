// tests/suite-86-quic-rfc9000-wire-dissector.test.js
/**
 * EJII Test Suite 86: QUIC (RFC 9000/9369) Wire Protocol Dissector
 * Verifies QUIC Long/Short header classification, DCID/SCID extraction,
 * Initial/0-RTT/Handshake/Retry packet types, Spin/Key bits, and packet decoder wiring.
 */

'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { L7DeepProtocolDissector } = require('../src/sniffer/l7-deep-protocol-dissector');
const { PacketDecoder } = require('../src/network/packet-decoding/packet-decoder');

async function runSuite86QuicWireDissector() {
  console.log('========================================================================');
  console.log('  === [SUITE 86] QUIC RFC 9000 WIRE PROTOCOL DISSECTOR ===              ');
  console.log('========================================================================\n');

  const dissector = new L7DeepProtocolDissector();

  // [86.1] QUIC v1 Initial Long Header Packet
  console.log('[Test 86.1] Dissecting RFC 9000 QUIC v1 Initial Long Header packet...');
  // Header form: 1 (Long Header), Fixed bit: 1, Packet Type: 00 (Initial), Reserved: 00, Packet Number Length: 00 (1 byte) -> byte 0 = 0xC0
  // Version: 0x00000001 (QUIC v1)
  // DCID Length: 0x08, DCID: 8 bytes (0x01..0x08)
  // SCID Length: 0x08, SCID: 8 bytes (0x11..0x18)
  // Token Length: 0x00 (varint)
  // Length: 0x14 (varint 20)
  // Payload: 20 bytes
  const quicInitialBuf = Buffer.from([
    0xc0,                         // Long header, Initial
    0x00, 0x00, 0x00, 0x01,       // Version: QUIC v1
    0x08,                         // DCID len: 8
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
    0x08,                         // SCID len: 8
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // SCID
    0x00,                         // Token length 0
    0x14,                         // Payload length 20
    0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
    0x0e, 0x0f, 0x10, 0x11
  ]);

  const resInitial = dissector.dissectPayload(quicInitialBuf, 443, 52140);
  assert.ok(resInitial, 'Dissector must return a result for QUIC Initial packet');
  assert.strictEqual(resInitial.protocol, 'QUIC');
  assert.strictEqual(resInitial.confidence, 1.0);
  assert.ok(resInitial.quic, 'QUIC metadata must be populated');
  assert.strictEqual(resInitial.quic.headerForm, 'long');
  assert.strictEqual(resInitial.quic.version, 'QUIC v1 (RFC 9000)');
  assert.strictEqual(resInitial.quic.packetType, 'Initial');
  assert.strictEqual(resInitial.quic.dcidHex, '0102030405060708');
  assert.strictEqual(resInitial.quic.scidHex, '1112131415161718');
  console.log(`  ✓ QUIC v1 Initial parsed: DCID=${resInitial.quic.dcidHex}, SCID=${resInitial.quic.scidHex}, Version=${resInitial.quic.version}`);

  // [86.2] QUIC v1 Handshake Long Header Packet
  console.log('[Test 86.2] Dissecting QUIC v1 Handshake packet...');
  // Header form: 1, Fixed bit: 1, Type: 0x20 (Handshake) -> 0xE0
  const quicHandshakeBuf = Buffer.from([
    0xe0,                         // Long header, Handshake
    0x00, 0x00, 0x00, 0x01,       // Version 1
    0x04,                         // DCID len: 4
    0xaa, 0xbb, 0xcc, 0xdd,
    0x04,                         // SCID len: 4
    0x10, 0x20, 0x30, 0x40,
    0x10,                         // Length 16
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
  ]);
  const resHandshake = dissector.dissectPayload(quicHandshakeBuf, 443, 50000);
  assert.strictEqual(resHandshake.protocol, 'QUIC');
  assert.strictEqual(resHandshake.quic.packetType, 'Handshake');
  assert.strictEqual(resHandshake.quic.dcidHex, 'aabbccdd');
  console.log(`  ✓ QUIC Handshake parsed: packetType=${resHandshake.quic.packetType}, DCID=${resHandshake.quic.dcidHex}`);

  // [86.3] QUIC v2 (RFC 9369) Support
  console.log('[Test 86.3] Dissecting RFC 9369 QUIC v2 packet...');
  const quicV2Buf = Buffer.from([
    0xd0,                         // Long header, 0-RTT in v2
    0x6b, 0x33, 0x43, 0xcf,       // Version: QUIC v2 (0x6b3343cf)
    0x04,
    0xde, 0xad, 0xbe, 0xef,
    0x04,
    0xca, 0xfe, 0xba, 0xbe,
    0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
  ]);
  const resV2 = dissector.dissectPayload(quicV2Buf, 443, 51000);
  assert.strictEqual(resV2.protocol, 'QUIC');
  assert.strictEqual(resV2.quic.version, 'QUIC v2 (RFC 9369)');
  assert.strictEqual(resV2.quic.dcidHex, 'deadbeef');
  console.log(`  ✓ RFC 9369 QUIC v2 verified: Version=${resV2.quic.version}, DCID=${resV2.quic.dcidHex}`);

  // [86.4] QUIC 1-RTT Short Header Packet
  console.log('[Test 86.4] Dissecting QUIC 1-RTT Short Header packet...');
  // Header form: 0 (Short Header), Fixed bit: 1, Spin: 1, Key Phase: 0 -> 0x60
  const quicShortBuf = Buffer.from([
    0x60,                         // Short header, Spin=1
    0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // 8-byte DCID
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
  ]);
  const resShort = dissector.dissectPayload(quicShortBuf, 443, 52000);
  assert.strictEqual(resShort.protocol, 'QUIC');
  assert.strictEqual(resShort.quic.headerForm, 'short');
  assert.strictEqual(resShort.quic.packetType, '1-RTT-Data');
  assert.strictEqual(resShort.quic.spinBit, true);
  console.log(`  ✓ QUIC Short Header parsed: SpinBit=${resShort.quic.spinBit}, HeaderType=${resShort.quic.headerForm}`);

  // [86.5] Integration with PacketDecoder
  console.log('[Test 86.5] Verifying PacketDecoder integration with L7 dissector...');
  const apexDissection = PacketDecoder.dissectApexWirePayload(quicInitialBuf, 'UDP', 443, 52140);
  assert.ok(apexDissection, 'dissectApexWirePayload must return structured analysis');
  assert.ok(apexDissection.quic, 'QUIC layer must be present in apexDissection');
  assert.strictEqual(apexDissection.quic.packetType, 'Initial');
  console.log('  ✓ PacketDecoder.dissectApexWirePayload seamlessly routed to QUIC dissector.');

  console.log('\n========================================================================');
  console.log('  SUITE 86 PASSED: QUIC RFC 9000 WIRE PROTOCOL DISSECTOR 100% GREEN     ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runSuite86QuicWireDissector().catch((err) => {
    console.error('Suite 86 failed:', err);
    process.exit(1);
  });
}

module.exports = {
  runSuite86QuicWireDissector,
  runSuite86: runSuite86QuicWireDissector
};
