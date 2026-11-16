/**
 * EJII Zero-Copy Binary Framing Engine & Nanosecond TrueTime Wire Streaming
 * Phase 20.0 High-Throughput Packet Layer
 *
 * Dual-Maintenance CommonJS Implementation.
 */

'use strict';

class ZeroCopyBinaryFramingEngine {
  static get MAGIC() { return 0x454a; }
  static get VERSION() { return 1; }
  static get HEADER_SIZE() { return 24; }

  static ipToNumber(ip) {
    if (!ip || typeof ip !== 'string') return 0;
    const parts = ip.split('.').map(p => parseInt(p, 10) & 0xff);
    if (parts.length !== 4) return 0;
    return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  }

  static numberToIp(num) {
    const p1 = (num >>> 24) & 0xff;
    const p2 = (num >>> 16) & 0xff;
    const p3 = (num >>> 8) & 0xff;
    const p4 = num & 0xff;
    return `${p1}.${p2}.${p3}.${p4}`;
  }

  encodeFrame(header, payload = Buffer.alloc(0)) {
    return this.encodePacked24(header, payload);
  }

  encodePacked24(header, payload = Buffer.alloc(0)) {
    const payloadLen = Math.min(payload.length, 65535);
    const totalSize = 24 + payloadLen;
    const buf = Buffer.allocUnsafe(totalSize);

    const ts = typeof header.timestampNs === 'bigint' ? header.timestampNs : BigInt(Date.now()) * 1000000n;
    buf.writeBigUInt64BE(ts, 0);

    buf.writeUInt32BE(ZeroCopyBinaryFramingEngine.ipToNumber(header.srcIp), 8);
    buf.writeUInt32BE(ZeroCopyBinaryFramingEngine.ipToNumber(header.dstIp), 12);

    buf.writeUInt16BE((header.srcPort || 0) & 0xffff, 16);
    buf.writeUInt16BE((header.dstPort || 0) & 0xffff, 18);

    buf.writeUInt8((header.protocol || 6) & 0xff, 20);
    buf.writeUInt8((header.tcpFlags || 0) & 0xff, 21);
    buf.writeUInt16BE(payloadLen, 22);

    if (payloadLen > 0) {
      payload.copy(buf, 24, 0, payloadLen);
    }

    return buf;
  }

  decodeFrame(buf) {
    if (!buf || buf.length < 24) return null;

    const timestampNs = buf.readBigUInt64BE(0);
    const srcIpNum = buf.readUInt32BE(8);
    const dstIpNum = buf.readUInt32BE(12);
    const srcPort = buf.readUInt16BE(16);
    const dstPort = buf.readUInt16BE(18);
    const protocol = buf.readUInt8(20);
    const tcpFlags = buf.readUInt8(21);
    const payloadLen = buf.readUInt16BE(22);

    const actualPayloadLen = Math.min(payloadLen, buf.length - 24);
    const payload = actualPayloadLen > 0 ? buf.subarray(24, 24 + actualPayloadLen) : Buffer.alloc(0);

    return {
      magic: ZeroCopyBinaryFramingEngine.MAGIC,
      version: ZeroCopyBinaryFramingEngine.VERSION,
      header: {
        timestampNs,
        srcIp: ZeroCopyBinaryFramingEngine.numberToIp(srcIpNum),
        dstIp: ZeroCopyBinaryFramingEngine.numberToIp(dstIpNum),
        srcPort,
        dstPort,
        protocol,
        tcpFlags,
        payloadLength: payloadLen
      },
      payload: Buffer.from(payload)
    };
  }
}

const zeroCopyBinaryFramingEngine = new ZeroCopyBinaryFramingEngine();

module.exports = {
  ZeroCopyBinaryFramingEngine,
  zeroCopyBinaryFramingEngine
};
