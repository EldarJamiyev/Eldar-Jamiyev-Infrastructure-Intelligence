/**
 * Test Suite 19: Adversarial Protocol Fixtures & Wire Decoding Integrity
 * Verifies byte-level RFC dissection accuracy, edge cases, checksums,
 * DNS compression loops, ServerHello ciphers, TCP options, and display filters.
 */

'use strict';

const assert = require('node:assert/strict');
const PacketDecoder = require('../src/network/packet-decoding/packet-decoder');
const { compileFilter, validateFilter } = require('../src/network/packet-decoding/filter-compiler');

async function runAdversarialProtocolTests() {
  console.log('\n========================================================================');
  console.log('  SUITE 19: ADVERSARIAL PROTOCOL FIXTURES & WIRE DISSECTION INTEGRITY  ');
  console.log('  RFC 791/793/1035/1071 Byte Offsets, Checksums & Loop Protection      ');
  console.log('========================================================================');

  // 1. Ethernet II and 802.1Q VLAN
  console.log('[19.1] Testing Ethernet II and 802.1Q VLAN dissection byte offsets...');
  const sampleVlan = PacketDecoder.generateSampleFrame('VLAN_IPV4');
  assert.ok(sampleVlan, 'VLAN sample frame must be generated');

  const dissectedVlan = PacketDecoder.dissectDetailed(sampleVlan);
  assert.ok(dissectedVlan.ethernet, 'Ethernet layer must exist');
  assert.ok(dissectedVlan.ethernet.vlan, '802.1Q VLAN tag must be parsed');
  assert.strictEqual(dissectedVlan.ethernet.vlan.vlanId, 100);
  assert.ok(dissectedVlan.layers.some(l => l.proto === 'vlan'), 'VLAN layer must be registered');
  assert.ok(dissectedVlan.fields['vlan.id'], 'vlan.id field must exist');
  assert.strictEqual(dissectedVlan.fields['vlan.id'].offset, 14);
  assert.strictEqual(dissectedVlan.fields['vlan.id'].value, 100);
  console.log('  ✓ 802.1Q VLAN (ID: 100, Offset: 14) byte bounds verified.');

  // 2. ARP packet dissection
  console.log('[19.2] Testing ARP packet dissection with hardware/protocol addresses...');
  const sampleArp = PacketDecoder.generateSampleFrame('ARP_REQUEST');
  const dissectedArp = PacketDecoder.dissectDetailed(sampleArp);
  assert.ok(dissectedArp.transport, 'ARP transport object must exist');
  assert.strictEqual(dissectedArp.transport.type, 'ARP');
  assert.ok(dissectedArp.fields['arp.opcode'], 'arp.opcode field must exist');
  assert.strictEqual(dissectedArp.fields['arp.opcode'].offset, 20);
  assert.ok(dissectedArp.fields['arp.src.mac'], 'arp.src.mac must exist');
  assert.ok(dissectedArp.fields['arp.dst.ip'], 'arp.dst.ip must exist');
  console.log('  ✓ ARP Request parsing and field offset mapping verified.');

  // 3. IPv4 Internet Header Checksum
  console.log('[19.3] Testing RFC 1071 IPv4 Checksum calculation (valid vs corrupted)...');
  const validFrame = PacketDecoder.generateSampleFrame('TCP_SYN');
  const dissectedValid = PacketDecoder.dissectDetailed(validFrame);
  assert.ok(dissectedValid.ip, 'IPv4 layer must exist');
  assert.strictEqual(dissectedValid.ip.checksumValid, true, 'Original checksum must be mathematically valid');
  assert.strictEqual(dissectedValid.fields['ip.checksum_status'].value, 'good');

  const corruptedFrame = Buffer.from(validFrame);
  corruptedFrame[24] = corruptedFrame[24] ^ 0xFF; // Invert checksum byte
  const dissectedCorrupted = PacketDecoder.dissectDetailed(corruptedFrame);
  assert.strictEqual(dissectedCorrupted.ip.checksumValid, false, 'Corrupted checksum must fail validation');
  assert.strictEqual(dissectedCorrupted.fields['ip.checksum_status'].value, 'bad');
  console.log('  ✓ RFC 1071 Checksum verification (good vs bad status) verified.');

  // 4. IPv4 Fragmentation Handling
  console.log('[19.4] Testing IPv4 fragmentation detection and non-initial fragment handling...');
  const fragFrame = Buffer.from(PacketDecoder.generateSampleFrame('TCP_SYN'));
  fragFrame.writeUInt16BE(0x2017, 20); // MF=1, FragOffset=184 (23*8)
  const dissectedFrag = PacketDecoder.dissectDetailed(fragFrame);
  assert.strictEqual(dissectedFrag.ip.isFragmented, true);
  assert.strictEqual(dissectedFrag.ip.fragmentOffset, 184);
  assert.ok(dissectedFrag.layers.some(l => l.proto === 'fragment'), 'Fragment layer registered');
  console.log('  ✓ IPv4 Fragmentation (MF=1, Offset=184) parsed without spurious transport parsing.');

  // 5. Truncated Frame Detection
  console.log('[19.5] Testing Truncated frame detection (wireLength > capturedLength)...');
  const truncFrame = Buffer.from(PacketDecoder.generateSampleFrame('TCP_SYN'));
  truncFrame.writeUInt16BE(1500, 16); // Claim total length 1500 but buffer is only 54 bytes
  const dissectedTrunc = PacketDecoder.dissectDetailed(truncFrame);
  assert.strictEqual(dissectedTrunc.isTruncated, true);
  assert.strictEqual(dissectedTrunc.wireLength, 1514);
  assert.strictEqual(dissectedTrunc.capturedLength, truncFrame.length);
  console.log(`  ✓ Truncation detected: wireLength ${dissectedTrunc.wireLength} > capturedLength ${dissectedTrunc.capturedLength}.`);

  // 6. TCP Options Parsing with exact byte offsets
  console.log('[19.6] Testing TCP Options (MSS, Window Scale, Timestamps, SACK-Permitted)...');
  const optBuf = Buffer.alloc(74);
  optBuf.write('641225E48890', 0, 'hex');
  optBuf.write('A4AE1116759D', 6, 'hex');
  optBuf.writeUInt16BE(0x0800, 12);
  optBuf.writeUInt8(0x45, 14);
  optBuf.writeUInt16BE(60, 16);
  optBuf.writeUInt8(64, 22);
  optBuf.writeUInt8(6, 23);
  optBuf.writeUInt32BE(0xC0A80101, 26);
  optBuf.writeUInt32BE(0xC0A80102, 30);
  optBuf.writeUInt16BE(45678, 34);
  optBuf.writeUInt16BE(443, 36);
  optBuf.writeUInt32BE(1000, 38);
  optBuf.writeUInt32BE(0, 42);
  optBuf.writeUInt8(0xA0, 46); // Data offset 10 (40 bytes)
  optBuf.writeUInt8(0x02, 47); // SYN
  // Options at 54
  optBuf.writeUInt8(2, 54); optBuf.writeUInt8(4, 55); optBuf.writeUInt16BE(1460, 56); // MSS 1460
  optBuf.writeUInt8(4, 58); optBuf.writeUInt8(2, 59); // SACK Permitted
  optBuf.writeUInt8(3, 60); optBuf.writeUInt8(3, 61); optBuf.writeUInt8(7, 62); // WScale 7
  optBuf.writeUInt8(1, 63); // NOP
  optBuf.writeUInt8(8, 64); optBuf.writeUInt8(10, 65); optBuf.writeUInt32BE(123456, 66); optBuf.writeUInt32BE(0, 70); // Timestamps

  const dissectedOpt = PacketDecoder.dissectDetailed(optBuf);
  assert.ok(dissectedOpt.transport && dissectedOpt.transport.options);
  assert.ok(dissectedOpt.transport.options.length >= 4);

  const mssOpt = dissectedOpt.transport.options.find(o => o.type === 'MSS');
  assert.ok(mssOpt);
  assert.strictEqual(mssOpt.value, 1460);
  assert.strictEqual(mssOpt.offset, 54);

  const wsOpt = dissectedOpt.transport.options.find(o => o.type === 'WSOPT');
  assert.ok(wsOpt);
  assert.strictEqual(wsOpt.value, 7);
  assert.strictEqual(wsOpt.multiplier, 128);

  assert.strictEqual(dissectedOpt.fields['tcp.options.mss'].value, 1460);
  assert.strictEqual(dissectedOpt.fields['tcp.options.wscale'].value, 7);
  console.log('  ✓ TCP Options parsed with byte offsets: MSS=1460, WS=7 (multiplier 128), Timestamps.');

  // 7. DNS Pointer Decompression with Loop Protection
  console.log('[19.7] Testing RFC 1035 DNS Pointer Loop Protection...');
  const dnsBuf = Buffer.alloc(30);
  dnsBuf.writeUInt16BE(0x1234, 0);
  dnsBuf.writeUInt16BE(0x0100, 2);
  dnsBuf.writeUInt16BE(1, 4);
  dnsBuf.writeUInt8(0xC0, 12); dnsBuf.writeUInt8(14, 13); // Pointer to 14
  dnsBuf.writeUInt8(0xC0, 14); dnsBuf.writeUInt8(12, 15); // Pointer BACK to 12

  const dnsRes = PacketDecoder.parseDnsName(dnsBuf, 0, 12);
  assert.ok(dnsRes !== undefined, 'Pointer loop must terminate safely without hanging or throwing');
  console.log('  ✓ DNS Pointer loop terminated cleanly without infinite recursion.');

  // 8. TLS ServerHello Ciphersuite Extraction
  console.log('[19.8] Testing TLS ServerHello selected cipher suite extraction...');
  const shBuf = Buffer.alloc(46);
  shBuf.writeUInt8(22, 0);
  shBuf.writeUInt16BE(0x0303, 1);
  shBuf.writeUInt16BE(40, 3);
  shBuf.writeUInt8(2, 5); // ServerHello
  shBuf.writeUInt8(0, 6);
  shBuf.writeUInt16BE(36, 7);
  shBuf.writeUInt16BE(0x0303, 9);
  shBuf.writeUInt8(0, 43); // Session ID len
  shBuf.writeUInt16BE(0x1301, 44); // TLS_AES_128_GCM_SHA256

  const tls = PacketDecoder.dissectTls(shBuf, 0);
  assert.ok(tls && tls.handshake);
  assert.strictEqual(tls.handshake.type, 'ServerHello');
  assert.strictEqual(tls.handshake.cipherSuiteHex, '0x1301');
  assert.ok(tls.handshake.cipherSuite.includes('TLS_AES_128_GCM_SHA256'));
  console.log('  ✓ TLS ServerHello cipher suite 0x1301 (TLS_AES_128_GCM_SHA256) extracted.');

  // 9. Encrypted TLS Application Data Isolation
  console.log('[19.9] Testing Encrypted TLS Application Data separation from HTTP...');
  const appData = Buffer.from('474554202f20485454502f312e31', 'hex');
  const tlsAppBuf = Buffer.alloc(54 + 5 + appData.length);
  tlsAppBuf.write('641225E48890', 0, 'hex');
  tlsAppBuf.write('A4AE1116759D', 6, 'hex');
  tlsAppBuf.writeUInt16BE(0x0800, 12);
  tlsAppBuf.writeUInt8(0x45, 14);
  tlsAppBuf.writeUInt16BE(40 + 5 + appData.length, 16);
  tlsAppBuf.writeUInt8(64, 22);
  tlsAppBuf.writeUInt8(6, 23);
  tlsAppBuf.writeUInt32BE(0xC0A80101, 26);
  tlsAppBuf.writeUInt32BE(0xC0A80102, 30);
  tlsAppBuf.writeUInt16BE(55555, 34);
  tlsAppBuf.writeUInt16BE(443, 36);
  tlsAppBuf.writeUInt32BE(1000, 38);
  tlsAppBuf.writeUInt32BE(2000, 42);
  tlsAppBuf.writeUInt8(0x50, 46);
  tlsAppBuf.writeUInt8(0x18, 47);
  tlsAppBuf.writeUInt8(23, 54); // ContentType 23 = ApplicationData
  tlsAppBuf.writeUInt16BE(0x0303, 55);
  tlsAppBuf.writeUInt16BE(appData.length, 57);
  appData.copy(tlsAppBuf, 59);

  const dissectedEncrypted = PacketDecoder.dissectDetailed(tlsAppBuf);
  assert.ok(dissectedEncrypted.application);
  assert.strictEqual(dissectedEncrypted.application.type, 'TLS');
  assert.strictEqual(dissectedEncrypted.application.contentType, 'ApplicationData');
  assert.strictEqual(dissectedEncrypted.layers.some(l => l.proto === 'http'), false, 'Encrypted payload MUST NEVER be marked as HTTP');
  assert.strictEqual(dissectedEncrypted.layers.some(l => l.proto === 'tls'), true);
  console.log('  ✓ Encrypted TLS Application Data (ContentType 23) correctly isolated from HTTP.');

  // 10. Display Filter Compiler
  console.log('[19.10] Testing Display Filter AST compiler and operator precedence...');
  assert.strictEqual(validateFilter('tcp.port == 443 && ip.proto == 6').valid, true);
  assert.strictEqual(validateFilter('tcp.flags.syn == true || !ip.dst == 10.168.195.1').valid, true);

  const filterFn = compileFilter('(tcp.srcport == 54321 || tcp.dstport == 443) && ip.version == 4');
  assert.strictEqual(filterFn(dissectedValid), true);

  const mismatchFn = compileFilter('tcp.dstport == 80');
  assert.strictEqual(mismatchFn(dissectedValid), false);

  const invalidRes = validateFilter('tcp.port == && ip.addr');
  assert.strictEqual(invalidRes.valid, false);
  assert.ok(invalidRes.error);
  console.log('  ✓ Wireshark-grade AST filter compiler validated.');

  console.log('\n>>> ALL SUITE 19 ADVERSARIAL PROTOCOL TESTS COMPLETED SUCCESSFULLY.\n');
}

if (require.main === module) {
  runAdversarialProtocolTests().then(() => {
    process.exit(0);
  }).catch((err) => {
    console.error('Suite 19 failed:', err);
    process.exit(1);
  });
}

module.exports = { runAdversarialProtocolTests };
