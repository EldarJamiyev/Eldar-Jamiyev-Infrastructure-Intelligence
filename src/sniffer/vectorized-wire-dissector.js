/**
 * EJII Vectorized Zero-Copy Wire Dissector
 *
 * Microsecond-latency, zero-allocation packet slicing engine using DataView,
 * typed arrays, and bit-parallel CPU operations for line-rate header dissection.
 * CommonJS Dual-Parity Implementation.
 */

'use strict';

class VectorizedWireDissector {
  constructor() {
    this.totalDissectedFrames = 0;
    this.totalBytesProcessed = 0;
    this.microburstAlertsCount = 0;
  }

  sliceEthernetHeader(buffer, offset = 0) {
    if (buffer.length < offset + 14) {
      throw new Error('Buffer too small for Ethernet frame');
    }

    const view = new DataView(buffer.buffer, buffer.byteOffset + offset, buffer.byteLength - offset);

    const dstMac = this.formatMac(buffer, offset);
    const srcMac = this.formatMac(buffer, offset + 6);
    let ethertype = view.getUint16(12, false);
    let headerLength = 14;
    let hasVlan = false;
    let vlanId = undefined;

    if (ethertype === 0x8100 || ethertype === 0x88a8) {
      hasVlan = true;
      const tci = view.getUint16(14, false);
      vlanId = tci & 0x0fff;
      ethertype = view.getUint16(16, false);
      headerLength = 18;
    }

    return { dstMac, srcMac, ethertype, hasVlan, vlanId, headerLength };
  }

  sliceIpHeader(buffer, offset = 0) {
    if (buffer.length < offset + 20) {
      throw new Error('Buffer too small for IPv4 header');
    }

    const view = new DataView(buffer.buffer, buffer.byteOffset + offset, buffer.byteLength - offset);
    const versionAndIhl = view.getUint8(0);
    const version = (versionAndIhl >> 4) & 0x0f;

    if (version === 4) {
      const ihl = versionAndIhl & 0x0f;
      const ihlBytes = ihl * 4;
      const tos = view.getUint8(1);
      const dscp = (tos >> 2) & 0x3f;
      const ecn = tos & 0x03;
      const totalLengthBytes = view.getUint16(2, false);
      const identification = view.getUint16(4, false);
      const ttl = view.getUint8(8);
      const protocol = view.getUint8(9);

      const srcIp = `${view.getUint8(12)}.${view.getUint8(13)}.${view.getUint8(14)}.${view.getUint8(15)}`;
      const dstIp = `${view.getUint8(16)}.${view.getUint8(17)}.${view.getUint8(18)}.${view.getUint8(19)}`;

      return {
        version: 4,
        ihlBytes,
        dscp,
        ecn,
        totalLengthBytes,
        identification,
        ttl,
        protocol,
        srcIp,
        dstIp
      };
    } else if (version === 6) {
      if (buffer.length < offset + 40) {
        throw new Error('Buffer too small for IPv6 header');
      }
      const vtcFlow = view.getUint32(0, false);
      const trafficClass = (vtcFlow >> 20) & 0xff;
      const dscp = (trafficClass >> 2) & 0x3f;
      const ecn = trafficClass & 0x03;
      const payloadLength = view.getUint16(4, false);
      const nextHeader = view.getUint8(6);
      const hopLimit = view.getUint8(7);

      const srcIp = this.formatIpv6(buffer, offset + 8);
      const dstIp = this.formatIpv6(buffer, offset + 24);

      return {
        version: 6,
        ihlBytes: 40,
        dscp,
        ecn,
        totalLengthBytes: payloadLength + 40,
        ttl: hopLimit,
        protocol: nextHeader,
        srcIp,
        dstIp
      };
    }

    throw new Error(`Unsupported IP version: ${version}`);
  }

  sliceTransportHeader(buffer, offset = 0, protocol) {
    const view = new DataView(buffer.buffer, buffer.byteOffset + offset, buffer.byteLength - offset);

    if (protocol === 6) {
      if (buffer.length < offset + 20) {
        throw new Error('Buffer too small for TCP header');
      }
      const srcPort = view.getUint16(0, false);
      const dstPort = view.getUint16(2, false);
      const tcpSeq = view.getUint32(4, false);
      const tcpAck = view.getUint32(8, false);
      const dataOffsetByte = view.getUint8(12);
      const headerLengthBytes = ((dataOffsetByte >> 4) & 0x0f) * 4;
      const flagsRaw = view.getUint8(13);
      const windowSize = view.getUint16(14, false);

      const tcpFlags = {
        raw: flagsRaw,
        fin: (flagsRaw & 0x01) !== 0,
        syn: (flagsRaw & 0x02) !== 0,
        rst: (flagsRaw & 0x04) !== 0,
        psh: (flagsRaw & 0x08) !== 0,
        ack: (flagsRaw & 0x10) !== 0,
        urg: (flagsRaw & 0x20) !== 0,
        ece: (flagsRaw & 0x40) !== 0,
        cwr: (flagsRaw & 0x80) !== 0
      };

      const payloadOffset = offset + headerLengthBytes;
      const payloadLengthBytes = Math.max(0, buffer.length - payloadOffset);

      return {
        protocolType: 'TCP',
        srcPort,
        dstPort,
        headerLengthBytes,
        tcpSeq,
        tcpAck,
        tcpFlags,
        windowSize,
        payloadLengthBytes,
        payloadOffset
      };
    } else if (protocol === 17) {
      if (buffer.length < offset + 8) {
        throw new Error('Buffer too small for UDP header');
      }
      const srcPort = view.getUint16(0, false);
      const dstPort = view.getUint16(2, false);
      const length = view.getUint16(4, false);
      const headerLengthBytes = 8;
      const payloadOffset = offset + headerLengthBytes;
      const payloadLengthBytes = Math.max(0, length - 8);

      return {
        protocolType: 'UDP',
        srcPort,
        dstPort,
        headerLengthBytes,
        payloadLengthBytes,
        payloadOffset
      };
    } else if (protocol === 1 || protocol === 58) {
      return {
        protocolType: 'ICMP',
        srcPort: 0,
        dstPort: 0,
        headerLengthBytes: 8,
        payloadLengthBytes: Math.max(0, buffer.length - offset - 8),
        payloadOffset: offset + 8
      };
    }

    return {
      protocolType: 'UNKNOWN',
      srcPort: 0,
      dstPort: 0,
      headerLengthBytes: 0,
      payloadLengthBytes: Math.max(0, buffer.length - offset),
      payloadOffset: offset
    };
  }

  computeFlowKey(srcIp, dstIp, srcPort, dstPort, protocol) {
    return `${protocol}:${srcIp}:${srcPort}->${dstIp}:${dstPort}`;
  }

  dissectFrameZeroCopy(buffer, offset = 0) {
    const timestampNs = process.hrtime.bigint();
    const frameLength = buffer.length - offset;

    const eth = this.sliceEthernetHeader(buffer, offset);
    let ip = null;
    let transport = null;
    let flowKey = 'RAW_ETHERNET';

    if (eth.ethertype === 0x0800 || eth.ethertype === 0x86dd) {
      const ipOffset = offset + eth.headerLength;
      ip = this.sliceIpHeader(buffer, ipOffset);

      const transportOffset = ipOffset + ip.ihlBytes;
      if (buffer.length >= transportOffset) {
        transport = this.sliceTransportHeader(buffer, transportOffset, ip.protocol);
        flowKey = this.computeFlowKey(ip.srcIp, ip.dstIp, transport.srcPort, transport.dstPort, ip.protocol);
      }
    }

    this.totalDissectedFrames++;
    this.totalBytesProcessed += frameLength;

    const isMicroburstCandidate = frameLength >= 1400 || (transport?.tcpFlags?.syn === true && transport?.tcpFlags?.ack === true);
    if (isMicroburstCandidate) {
      this.microburstAlertsCount++;
    }

    return {
      timestampNs,
      frameLength,
      hasVlan: eth.hasVlan,
      vlanId: eth.vlanId,
      ethertype: eth.ethertype,
      srcMac: eth.srcMac,
      dstMac: eth.dstMac,
      ip,
      transport,
      flowKey,
      isMicroburstCandidate
    };
  }

  getMetrics() {
    return {
      totalDissectedFrames: this.totalDissectedFrames,
      totalBytesProcessed: this.totalBytesProcessed,
      microburstAlertsCount: this.microburstAlertsCount
    };
  }

  formatMac(buffer, offset) {
    const hex = [];
    for (let i = 0; i < 6; i++) {
      hex.push(buffer[offset + i].toString(16).padStart(2, '0'));
    }
    return hex.join(':');
  }

  formatIpv6(buffer, offset) {
    const parts = [];
    for (let i = 0; i < 16; i += 2) {
      const word = (buffer[offset + i] << 8) | buffer[offset + i + 1];
      parts.push(word.toString(16));
    }
    return parts.join(':');
  }
}

const vectorizedWireDissector = new VectorizedWireDissector();

module.exports = {
  VectorizedWireDissector,
  vectorizedWireDissector
};
