/**
 * EJII High-Throughput Binary WebSocket Packet Frame Codec (Track 4)
 *
 * Line-Rate Zero-Copy Binary Encoding & Decoding for Network Sniffer Cockpit.
 * Replaces high-overhead JSON serialization with compact, deterministic binary frames.
 *
 * Frame Format Specification:
 * -------------------------------------------------------------
 *  Offset | Size | Type        | Description
 * -------------------------------------------------------------
 *   0..3  |  4   | Magic       | 0x45 0x4A 0x49 0x49 ("EJII")
 *   4     |  1   | Uint8       | Protocol Version (1)
 *   5     |  1   | Uint8       | Flags (IPv6, Truncated, Protocols)
 *   6..7  |  2   | Uint16 BE   | IP Protocol Number (6=TCP, 17=UDP, 1=ICMP, 2054=ARP, etc.)
 *   8..15 |  8   | Int64 BE    | Timestamp (epoch microseconds)
 *  -- IPv4 Frame (Flags bit 0 = 0, Header Length = 32 bytes) --
 *  16..19 |  4   | Uint32 BE   | Source IPv4 Address
 *  20..23 |  4   | Uint32 BE   | Destination IPv4 Address
 *  24..25 |  2   | Uint16 BE   | Source Port (0 for non-transport)
 *  26..27 |  2   | Uint16 BE   | Destination Port (0 for non-transport)
 *  28..29 |  2   | Uint16 BE   | Total Wire Length (bytes)
 *  30..31 |  2   | Uint16 BE   | Payload Slice Length (L bytes)
 *  32..   |  L   | Bytes       | Raw Frame Payload Slice
 *  -- IPv6 Frame (Flags bit 0 = 1, Header Length = 56 bytes) --
 *  16..31 | 16   | Bytes       | Source IPv6 Address
 *  32..47 | 16   | Bytes       | Destination IPv6 Address
 *  48..49 |  2   | Uint16 BE   | Source Port
 *  50..51 |  2   | Uint16 BE   | Destination Port
 *  52..53 |  2   | Uint16 BE   | Total Wire Length
 *  54..55 |  2   | Uint16 BE   | Payload Slice Length (L bytes)
 *  56..   |  L   | Bytes       | Raw Frame Payload Slice
 */

'use strict';

const net = require('node:net');

const MAGIC_BYTES = Buffer.from([0x45, 0x4A, 0x49, 0x49]); // "EJII"
const MAGIC_UINT32 = 0x454A4949;
const PROTOCOL_VERSION = 1;

// Flags bitmask definition
const FLAGS = {
  IPV6: 0x01,
  TRUNCATED: 0x02,
  TCP: 0x04,
  UDP: 0x08,
  ICMP: 0x10,
  ARP: 0x20,
  DNS: 0x40,
  SYN: 0x80
};

// Protocol numbers mapping
const PROTO_NAME_TO_NUM = {
  'HOPOPT': 0,
  'ICMP': 1,
  'IGMP': 2,
  'TCP': 6,
  'UDP': 17,
  'IPV6-ROUTE': 43,
  'IPV6-FRAG': 44,
  'GRE': 47,
  'ESP': 50,
  'AH': 51,
  'ICMPV6': 58,
  'IPV6-NONXT': 59,
  'IPV6-OPTS': 60,
  'OSPF': 89,
  'SCTP': 132,
  'ARP': 2054,
  'DNS': 53,
  'TLS': 443,
  'HTTP': 80
};

const PROTO_NUM_TO_NAME = Object.entries(PROTO_NAME_TO_NUM).reduce((acc, [name, num]) => {
  if (!acc[num]) acc[num] = name;
  return acc;
}, {
  1: 'ICMP',
  6: 'TCP',
  17: 'UDP',
  58: 'ICMPv6',
  2054: 'ARP'
});

/**
 * Convert an IPv4 dot-decimal string to a 32-bit unsigned integer.
 */
function ipv4ToUint32(ipStr) {
  if (typeof ipStr !== 'string') return 0;
  const parts = ipStr.split('.');
  if (parts.length !== 4) return 0;
  const a = parseInt(parts[0], 10) & 0xff;
  const b = parseInt(parts[1], 10) & 0xff;
  const c = parseInt(parts[2], 10) & 0xff;
  const d = parseInt(parts[3], 10) & 0xff;
  return (((a << 24) >>> 0) | (b << 16) | (c << 8) | d) >>> 0;
}

/**
 * Convert a 32-bit unsigned integer to an IPv4 dot-decimal string.
 */
function uint32ToIpv4(u32) {
  return `${(u32 >>> 24) & 0xff}.${(u32 >>> 16) & 0xff}.${(u32 >>> 8) & 0xff}.${u32 & 0xff}`;
}

/**
 * Convert an IPv6 string to 16 bytes Buffer.
 */
function ipv6ToBuffer(ipStr) {
  const buf = Buffer.alloc(16);
  if (typeof ipStr !== 'string' || !ipStr.includes(':')) return buf;

  // Handle IPv4-mapped IPv6 or standard expansion
  const doubleColonIndex = ipStr.indexOf('::');
  let leftParts = [];
  let rightParts = [];

  if (doubleColonIndex !== -1) {
    const leftStr = ipStr.slice(0, doubleColonIndex);
    const rightStr = ipStr.slice(doubleColonIndex + 2);
    if (leftStr.length > 0) leftParts = leftStr.split(':');
    if (rightStr.length > 0) rightParts = rightStr.split(':');
  } else {
    leftParts = ipStr.split(':');
  }

  const fillCount = 8 - (leftParts.length + rightParts.length);
  const words = [];
  for (const part of leftParts) words.push(parseInt(part || '0', 16) & 0xffff);
  for (let i = 0; i < fillCount; i++) words.push(0);
  for (const part of rightParts) words.push(parseInt(part || '0', 16) & 0xffff);

  for (let i = 0; i < 8; i++) {
    buf.writeUInt16BE(words[i] || 0, i * 2);
  }
  return buf;
}

/**
 * Convert 16 bytes from Buffer or Uint8Array to IPv6 string.
 */
function bufferToIpv6(buf, offset = 0) {
  const words = [];
  for (let i = 0; i < 8; i++) {
    if (buf.readUInt16BE) {
      words.push(buf.readUInt16BE(offset + i * 2));
    } else {
      const u16 = (buf[offset + i * 2] << 8) | buf[offset + i * 2 + 1];
      words.push(u16);
    }
  }
  return words.map(w => w.toString(16)).join(':');
}

/**
 * Encodes a live packet frame object into an authentic binary EJII frame Buffer.
 *
 * @param {Object} frame - Real packet frame emitted by packet-streamer / sniffer
 * @param {number} [maxPayloadSlice=128] - Maximum raw payload bytes to slice and attach
 * @returns {Buffer} Binary frame
 */
function encodeBinaryPacketFrame(frame, maxPayloadSlice = 128) {
  if (!frame || typeof frame !== 'object') {
    return Buffer.alloc(0);
  }

  const isIpv6 = Boolean(
    frame.isIpv6 ||
    (frame.srcIp && frame.srcIp.includes(':')) ||
    (frame.dstIp && frame.dstIp.includes(':'))
  );

  // Determine protocol number and name
  let protoNum = 0;
  if (typeof frame.protocol === 'number') {
    protoNum = frame.protocol;
  } else if (typeof frame.protocol === 'string') {
    const upper = frame.protocol.toUpperCase();
    protoNum = PROTO_NAME_TO_NUM[upper] || 0;
  }
  if (!protoNum) {
    if (frame.tcp) protoNum = 6;
    else if (frame.udp) protoNum = 17;
    else if (frame.icmp) protoNum = isIpv6 ? 58 : 1;
    else if (frame.arp) protoNum = 2054;
  }

  // Build flags bitmask
  let flags = 0;
  if (isIpv6) flags |= FLAGS.IPV6;
  if (frame.isTruncated) flags |= FLAGS.TRUNCATED;
  if (protoNum === 6 || frame.tcp) flags |= FLAGS.TCP;
  if (protoNum === 17 || frame.udp) flags |= FLAGS.UDP;
  if (protoNum === 1 || protoNum === 58 || frame.icmp) flags |= FLAGS.ICMP;
  if (protoNum === 2054 || frame.arp) flags |= FLAGS.ARP;
  if (protoNum === 53 || frame.dns || frame.appProto === 'DNS') flags |= FLAGS.DNS;
  if (frame.tcp && frame.tcp.flags && (frame.tcp.flags.syn || frame.tcp.flags.SYN)) flags |= FLAGS.SYN;

  // Timestamp extraction (microseconds)
  let tsMicros = 0n;
  if (typeof frame.timestampMicros === 'bigint') {
    tsMicros = frame.timestampMicros;
  } else if (typeof frame.timestamp === 'number') {
    tsMicros = BigInt(Math.floor(frame.timestamp * 1000));
  } else if (typeof frame.timestamp === 'string') {
    const parsed = Date.parse(frame.timestamp);
    tsMicros = BigInt(isNaN(parsed) ? Date.now() : parsed) * 1000n;
  } else {
    tsMicros = BigInt(Date.now()) * 1000n;
  }

  // Extract ports
  const srcPort = Number(
    frame.srcPort ||
    (frame.tcp && frame.tcp.srcPort) ||
    (frame.udp && frame.udp.srcPort) ||
    0
  ) & 0xffff;

  const dstPort = Number(
    frame.dstPort ||
    (frame.tcp && frame.tcp.dstPort) ||
    (frame.udp && frame.udp.dstPort) ||
    0
  ) & 0xffff;

  // Extract payload slice
  let sliceBuf = Buffer.alloc(0);
  if (frame.rawBuf && Buffer.isBuffer(frame.rawBuf)) {
    sliceBuf = frame.rawBuf.subarray(0, maxPayloadSlice);
  } else if (typeof frame.rawHex === 'string' && frame.rawHex.length > 0) {
    const maxHexLen = maxPayloadSlice * 2;
    const cleanHex = frame.rawHex.slice(0, maxHexLen);
    sliceBuf = Buffer.from(cleanHex, 'hex');
  } else if (frame.payload && Buffer.isBuffer(frame.payload)) {
    sliceBuf = frame.payload.subarray(0, maxPayloadSlice);
  }

  const wireLength = Number(frame.wireLength || frame.length || frame.capturedLength || sliceBuf.length) & 0xffff;
  const sliceLength = sliceBuf.length & 0xffff;

  const headerLength = isIpv6 ? 56 : 32;
  const totalLength = headerLength + sliceLength;
  const outBuf = Buffer.allocUnsafe(totalLength);

  // 1. Magic (4 bytes)
  MAGIC_BYTES.copy(outBuf, 0);

  // 2. Version (1 byte)
  outBuf.writeUInt8(PROTOCOL_VERSION, 4);

  // 3. Flags (1 byte)
  outBuf.writeUInt8(flags, 5);

  // 4. Protocol Number (2 bytes)
  outBuf.writeUInt16BE(protoNum, 6);

  // 5. Timestamp (8 bytes BigInt64 BE)
  outBuf.writeBigInt64BE(tsMicros, 8);

  if (!isIpv6) {
    // 6. IPv4 Addresses (4 + 4 bytes)
    const srcU32 = ipv4ToUint32(frame.srcIp || '0.0.0.0');
    const dstU32 = ipv4ToUint32(frame.dstIp || '0.0.0.0');
    outBuf.writeUInt32BE(srcU32, 16);
    outBuf.writeUInt32BE(dstU32, 20);

    // 7. Ports (2 + 2 bytes)
    outBuf.writeUInt16BE(srcPort, 24);
    outBuf.writeUInt16BE(dstPort, 26);

    // 8. Lengths (2 + 2 bytes)
    outBuf.writeUInt16BE(wireLength, 28);
    outBuf.writeUInt16BE(sliceLength, 30);

    // 9. Payload Slice
    if (sliceLength > 0) {
      sliceBuf.copy(outBuf, 32);
    }
  } else {
    // 6. IPv6 Addresses (16 + 16 bytes)
    const srcV6 = ipv6ToBuffer(frame.srcIp || '::');
    const dstV6 = ipv6ToBuffer(frame.dstIp || '::');
    srcV6.copy(outBuf, 16);
    dstV6.copy(outBuf, 32);

    // 7. Ports (2 + 2 bytes)
    outBuf.writeUInt16BE(srcPort, 48);
    outBuf.writeUInt16BE(dstPort, 50);

    // 8. Lengths (2 + 2 bytes)
    outBuf.writeUInt16BE(wireLength, 52);
    outBuf.writeUInt16BE(sliceLength, 54);

    // 9. Payload Slice
    if (sliceLength > 0) {
      sliceBuf.copy(outBuf, 56);
    }
  }

  return outBuf;
}

/**
 * Decodes a binary packet frame into a structured JavaScript object.
 * Compatible with Node.js Buffers, browser ArrayBuffers, and Uint8Arrays.
 *
 * @param {Buffer|ArrayBuffer|Uint8Array} input
 * @returns {Object|null} Decoded packet frame or null if invalid
 */
function decodeBinaryPacketFrame(input) {
  if (!input) return null;

  let view;
  let rawBytes;

  if (Buffer.isBuffer(input)) {
    view = new DataView(input.buffer, input.byteOffset, input.byteLength);
    rawBytes = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  } else if (input instanceof ArrayBuffer) {
    view = new DataView(input);
    rawBytes = new Uint8Array(input);
  } else if (input.buffer instanceof ArrayBuffer) {
    view = new DataView(input.buffer, input.byteOffset, input.byteLength);
    rawBytes = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  } else {
    return null;
  }

  if (view.byteLength < 32) return null;

  // Validate Magic (0x454A4949)
  const magic = view.getUint32(0, false);
  if (magic !== MAGIC_UINT32) return null;

  // Validate Version
  const version = view.getUint8(4);
  if (version !== PROTOCOL_VERSION) return null;

  const flags = view.getUint8(5);
  const isIpv6 = (flags & FLAGS.IPV6) !== 0;
  const isTruncated = (flags & FLAGS.TRUNCATED) !== 0;
  const hasSyn = (flags & FLAGS.SYN) !== 0;

  const headerLength = isIpv6 ? 56 : 32;
  if (view.byteLength < headerLength) return null;

  const protocolNum = view.getUint16(6, false);
  const protocolName = PROTO_NUM_TO_NAME[protocolNum] || `IP-${protocolNum}`;

  const tsMicros = view.getBigInt64(8, false);
  const timestampMs = Number(tsMicros / 1000n);
  const timestampIso = new Date(timestampMs).toISOString();

  let srcIp;
  let dstIp;
  let srcPort;
  let dstPort;
  let wireLength;
  let sliceLength;
  let payloadOffset;

  if (!isIpv6) {
    const srcU32 = view.getUint32(16, false);
    const dstU32 = view.getUint32(20, false);
    srcIp = uint32ToIpv4(srcU32);
    dstIp = uint32ToIpv4(dstU32);
    srcPort = view.getUint16(24, false);
    dstPort = view.getUint16(26, false);
    wireLength = view.getUint16(28, false);
    sliceLength = view.getUint16(30, false);
    payloadOffset = 32;
  } else {
    srcIp = bufferToIpv6(rawBytes, 16);
    dstIp = bufferToIpv6(rawBytes, 32);
    srcPort = view.getUint16(48, false);
    dstPort = view.getUint16(50, false);
    wireLength = view.getUint16(52, false);
    sliceLength = view.getUint16(54, false);
    payloadOffset = 56;
  }

  const payloadEnd = Math.min(view.byteLength, payloadOffset + sliceLength);
  const payloadSlice = rawBytes.subarray(payloadOffset, payloadEnd);

  // Format hex string representation
  let payloadHex = '';
  for (let i = 0; i < payloadSlice.length; i++) {
    const hex = payloadSlice[i].toString(16).padStart(2, '0');
    payloadHex += hex;
  }

  const endpointStr = srcPort || dstPort
    ? `${srcIp}:${srcPort} -> ${dstIp}:${dstPort}`
    : `${srcIp} -> ${dstIp}`;

  const summary = `${protocolName} ${endpointStr} [${wireLength} bytes]`;

  return {
    magic: 'EJII',
    version,
    flags,
    isIpv6,
    isTruncated,
    hasSyn,
    protocol: protocolNum,
    protocolName,
    timestamp: timestampMs,
    timestampMicros: tsMicros,
    timestampIso,
    srcIp,
    dstIp,
    srcPort,
    dstPort,
    wireLength,
    sliceLength: payloadSlice.length,
    payloadSlice,
    payloadHex,
    summary,
    // Protocol-specific convenience structure
    ...(flags & FLAGS.TCP ? { tcp: { srcPort, dstPort, flags: { syn: hasSyn } } } : {}),
    ...(flags & FLAGS.UDP ? { udp: { srcPort, dstPort } } : {}),
    ...(flags & FLAGS.ICMP ? { icmp: { type: protocolNum === 58 ? 'ICMPv6' : 'ICMP' } } : {}),
    ...(flags & FLAGS.ARP ? { arp: { operation: 'ARP' } } : {})
  };
}

module.exports = {
  MAGIC_BYTES,
  MAGIC_UINT32,
  PROTOCOL_VERSION,
  FLAGS,
  PROTO_NAME_TO_NUM,
  PROTO_NUM_TO_NAME,
  ipv4ToUint32,
  uint32ToIpv4,
  ipv6ToBuffer,
  bufferToIpv6,
  encodeBinaryPacketFrame,
  decodeBinaryPacketFrame
};
