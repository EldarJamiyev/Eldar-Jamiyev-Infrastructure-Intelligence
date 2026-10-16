/**
 * Test Suite: Adversarial Protocol Fixtures & Wire Decoding Integrity
 * Verifies byte-level RFC dissection accuracy, edge cases, checksums,
 * DNS compression loops, ServerHello ciphers, TCP options, and display filters.
 */

'use strict';

const PacketDecoder = require('../src/network/packet-decoding/packet-decoder');
const { compileFilter, validateFilter } = require('../src/network/packet-decoding/filter-compiler');

describe('Adversarial Protocol Fixtures & Wire Dissection', () => {

  test('1. Ethernet II and 802.1Q VLAN dissection with byte-accurate offsets', () => {
    // 14 Eth + 4 VLAN + 20 IPv4 + 20 TCP = 58 bytes
    const sample = PacketDecoder.generateSampleFrame('VLAN_IPV4');
    expect(sample).toBeDefined();

    const dissected = PacketDecoder.dissectDetailed(sample);
    expect(dissected.ethernet).toBeDefined();
    expect(dissected.ethernet.vlan).toBeDefined();
    expect(dissected.ethernet.vlan.vlanId).toBe(100);
    expect(dissected.layers.some(l => l.proto === 'vlan')).toBe(true);

    // Verify fieldsMap contains exact byte offsets
    expect(dissected.fields['vlan.id']).toBeDefined();
    expect(dissected.fields['vlan.id'].offset).toBe(14);
    expect(dissected.fields['vlan.id'].value).toBe(100);
  });

  test('2. ARP packet dissection with hardware and protocol addresses', () => {
    const sample = PacketDecoder.generateSampleFrame('ARP_REQUEST');
    const dissected = PacketDecoder.dissectDetailed(sample);

    expect(dissected.transport).toBeDefined();
    expect(dissected.transport.type).toBe('ARP');
    expect(dissected.fields['arp.opcode']).toBeDefined();
    expect(dissected.fields['arp.src.mac']).toBeDefined();
    expect(dissected.fields['arp.dst.ip']).toBeDefined();
    expect(dissected.fields['arp.opcode'].offset).toBe(20);
  });

  test('3. IPv4 Internet Header Checksum verification (valid vs corrupted)', () => {
    const validFrame = PacketDecoder.generateSampleFrame('TCP_SYN');
    const dissectedValid = PacketDecoder.dissectDetailed(validFrame);

    expect(dissectedValid.ip).toBeDefined();
    expect(dissectedValid.ip.checksumValid).toBe(true);
    expect(dissectedValid.fields['ip.checksum_status'].value).toBe('good');

    // Corrupt the checksum byte in IPv4 header (offset 24)
    const corruptedFrame = Buffer.from(validFrame);
    corruptedFrame[24] = corruptedFrame[24] ^ 0xFF;

    const dissectedCorrupted = PacketDecoder.dissectDetailed(corruptedFrame);
    expect(dissectedCorrupted.ip.checksumValid).toBe(false);
    expect(dissectedCorrupted.fields['ip.checksum_status'].value).toBe('bad');
  });

  test('4. IPv4 fragmentation detection and non-initial fragment handling', () => {
    const frame = Buffer.from(PacketDecoder.generateSampleFrame('TCP_SYN'));
    // Set Flags/Fragment Offset: MF = 1, Offset = 184 (23 * 8)
    frame.writeUInt16BE(0x2017, 20); // 0x2000 (MF) | 0x0017 (23 * 8 = 184)

    const dissected = PacketDecoder.dissectDetailed(frame);
    expect(dissected.ip.isFragmented).toBe(true);
    expect(dissected.ip.fragmentOffset).toBe(184);
    expect(dissected.layers.some(l => l.proto === 'fragment')).toBe(true);
  });

  test('5. Truncated frame detection (wireLength > capturedLength)', () => {
    const frame = Buffer.from(PacketDecoder.generateSampleFrame('TCP_SYN'));
    // Declare IPv4 total length = 1500 bytes, but captured buffer is only 54 bytes
    frame.writeUInt16BE(1500, 16);

    const dissected = PacketDecoder.dissectDetailed(frame);
    expect(dissected.isTruncated).toBe(true);
    expect(dissected.wireLength).toBe(1514); // 14 eth + 1500 ip
    expect(dissected.capturedLength).toBe(frame.length);
  });

  test('6. TCP Options Parsing with exact byte offsets (MSS, Window Scale, Timestamps)', () => {
    // Construct TCP packet with options: MSS (kind 2, len 4), Window Scale (kind 3, len 3), NOP, Timestamps (kind 8, len 10)
    // 14 eth + 20 ip + 40 tcp (20 base + 20 options) = 74 bytes
    const buf = Buffer.alloc(74);
    buf.write('641225E48890', 0, 'hex');
    buf.write('A4AE1116759D', 6, 'hex');
    buf.writeUInt16BE(0x0800, 12); // IPv4

    // IPv4
    buf.writeUInt8(0x45, 14);
    buf.writeUInt16BE(60, 16); // Total length 60 (20 IP + 40 TCP)
    buf.writeUInt8(64, 22);    // TTL
    buf.writeUInt8(6, 23);     // TCP
    buf.writeUInt32BE(0xC0A80101, 26); // 192.168.1.1
    buf.writeUInt32BE(0xC0A80102, 30); // 192.168.1.2

    // TCP
    buf.writeUInt16BE(45678, 34); // Src Port
    buf.writeUInt16BE(443, 36);   // Dst Port
    buf.writeUInt32BE(1000, 38);  // Seq
    buf.writeUInt32BE(0, 42);     // Ack
    buf.writeUInt8(0xA0, 46);     // Data Offset = 10 (40 bytes header)
    buf.writeUInt8(0x02, 47);     // SYN

    // Options at offset 54:
    // Option 1: MSS = 1460 (kind 2, len 4, val 1460)
    buf.writeUInt8(2, 54);
    buf.writeUInt8(4, 55);
    buf.writeUInt16BE(1460, 56);

    // Option 2: SACK Permitted (kind 4, len 2)
    buf.writeUInt8(4, 58);
    buf.writeUInt8(2, 59);

    // Option 3: Window Scale = 7 (kind 3, len 3, shift 7)
    buf.writeUInt8(3, 60);
    buf.writeUInt8(3, 61);
    buf.writeUInt8(7, 62);

    // Option 4: NOP (kind 1)
    buf.writeUInt8(1, 63);

    // Option 5: Timestamps (kind 8, len 10, tsVal 123456, tsEcho 0)
    buf.writeUInt8(8, 64);
    buf.writeUInt8(10, 65);
    buf.writeUInt32BE(123456, 66);
    buf.writeUInt32BE(0, 70);

    const dissected = PacketDecoder.dissectDetailed(buf);
    expect(dissected.transport).toBeDefined();
    expect(dissected.transport.options).toBeDefined();
    expect(dissected.transport.options.length).toBeGreaterThanOrEqual(4);

    const mssOpt = dissected.transport.options.find(o => o.type === 'MSS');
    expect(mssOpt).toBeDefined();
    expect(mssOpt.value).toBe(1460);
    expect(mssOpt.offset).toBe(54);

    const wsOpt = dissected.transport.options.find(o => o.type === 'WSOPT');
    expect(wsOpt).toBeDefined();
    expect(wsOpt.value).toBe(7);
    expect(wsOpt.multiplier).toBe(128);

    expect(dissected.fields['tcp.options.mss']).toBeDefined();
    expect(dissected.fields['tcp.options.mss'].value).toBe(1460);
    expect(dissected.fields['tcp.options.wscale']).toBeDefined();
    expect(dissected.fields['tcp.options.wscale'].value).toBe(7);
  });

  test('7. DNS Pointer Decompression with Circular Loop Protection', () => {
    // Construct DNS packet with circular pointer loop
    const dnsBuf = Buffer.alloc(30);
    dnsBuf.writeUInt16BE(0x1234, 0); // ID
    dnsBuf.writeUInt16BE(0x0100, 2); // Standard query
    dnsBuf.writeUInt16BE(1, 4);      // 1 question

    // Question Name at offset 12: Pointer to offset 14
    dnsBuf.writeUInt8(0xC0, 12);
    dnsBuf.writeUInt8(14, 13);
    // At offset 14: Pointer BACK to offset 12! (Circular Loop)
    dnsBuf.writeUInt8(0xC0, 14);
    dnsBuf.writeUInt8(12, 15);

    // Loop-protected pointer chasing must terminate cleanly without throwing or hanging
    expect(() => {
      const res = PacketDecoder.parseDnsName(dnsBuf, 0, 12);
      expect(res).toBeDefined();
    }).not.toThrow();
  });

  test('8. TLS ServerHello selected cipher suite extraction', () => {
    // Construct TLS ServerHello
    const shBuf = Buffer.alloc(45);
    shBuf.writeUInt8(22, 0);       // Handshake
    shBuf.writeUInt16BE(0x0303, 1); // TLS 1.2
    shBuf.writeUInt16BE(40, 3);    // Record length
    shBuf.writeUInt8(2, 5);        // ServerHello
    shBuf.writeUInt8(0, 6);
    shBuf.writeUInt16BE(36, 7);    // Handshake length
    shBuf.writeUInt16BE(0x0303, 9); // Server Version TLS 1.2
    // 32 random bytes at 11..42
    shBuf.writeUInt8(0, 43);       // Session ID len 0
    shBuf.writeUInt16BE(0x1301, 44); // Selected Cipher Suite: TLS_AES_128_GCM_SHA256

    const tls = PacketDecoder.dissectTls(shBuf, 0);
    expect(tls).toBeDefined();
    expect(tls.handshake).toBeDefined();
    expect(tls.handshake.type).toBe('ServerHello');
    expect(tls.handshake.cipherSuiteHex).toBe('0x1301');
    expect(tls.handshake.cipherSuite).toContain('TLS_AES_128_GCM_SHA256');
  });

  test('9. Encrypted TLS Application Data is NEVER misrepresented as HTTP', () => {
    // Construct packet with TLS Application Data (Content Type 23)
    const appData = Buffer.from('474554202f20485454502f312e31', 'hex'); // Looks like "GET / HTTP/1.1" if decrypted, but encrypted in record
    const buf = Buffer.alloc(54 + 5 + appData.length);

    buf.write('641225E48890', 0, 'hex');
    buf.write('A4AE1116759D', 6, 'hex');
    buf.writeUInt16BE(0x0800, 12); // IPv4

    buf.writeUInt8(0x45, 14);
    buf.writeUInt16BE(40 + 5 + appData.length, 16);
    buf.writeUInt8(64, 22);
    buf.writeUInt8(6, 23); // TCP
    buf.writeUInt32BE(0xC0A80101, 26);
    buf.writeUInt32BE(0xC0A80102, 30);

    buf.writeUInt16BE(55555, 34);
    buf.writeUInt16BE(443, 36);
    buf.writeUInt32BE(1000, 38);
    buf.writeUInt32BE(2000, 42);
    buf.writeUInt8(0x50, 46); // Data offset 5 (20 bytes)
    buf.writeUInt8(0x18, 47); // PSH, ACK

    // TLS Record at offset 54:
    buf.writeUInt8(23, 54); // ContentType 23 = ApplicationData
    buf.writeUInt16BE(0x0303, 55);
    buf.writeUInt16BE(appData.length, 57);
    appData.copy(buf, 59);

    const dissected = PacketDecoder.dissectDetailed(buf);
    expect(dissected.application).toBeDefined();
    expect(dissected.application.type).toBe('TLS');
    expect(dissected.application.contentType).toBe('ApplicationData');

    // Crucial check: Must NOT have HTTP layer!
    expect(dissected.layers.some(l => l.proto === 'http')).toBe(false);
    expect(dissected.layers.some(l => l.proto === 'tls')).toBe(true);
  });

  test('10. Display Filter Compiler AST evaluation and operator precedence', () => {
    const validFrame = PacketDecoder.dissectDetailed(PacketDecoder.generateSampleFrame('TCP_SYN'));

    // Validate AST expressions
    expect(validateFilter('tcp.port == 443 && ip.proto == 6').valid).toBe(true);
    expect(validateFilter('tcp.flags.syn == true || !ip.dst == 10.168.195.1').valid).toBe(true);

    // Operator precedence: () > ! > && > ||
    const filterFn = compileFilter('(tcp.srcport == 54321 || tcp.dstport == 443) && ip.version == 4');
    expect(filterFn(validFrame)).toBe(true);

    const mismatchFn = compileFilter('tcp.dstport == 80');
    expect(mismatchFn(validFrame)).toBe(false);

    // Malformed expressions must report syntax error cleanly
    const invalidRes = validateFilter('tcp.port == && ip.addr');
    expect(invalidRes.valid).toBe(false);
    expect(invalidRes.error).toBeDefined();
  });
});
