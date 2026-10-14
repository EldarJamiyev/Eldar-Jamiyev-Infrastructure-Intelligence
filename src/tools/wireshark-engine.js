/**
 * EJII Wireshark Engine
 * Deep packet inspection, pcap file parser, and Layer 2 through Layer 7 protocol dissector.
 * 100% Genuine Protocol Decoding — Zero Simulated Data.
 */

const fs = require('fs');

/**
 * Protocol Numbers & Constants
 */
const ETHER_TYPES = {
  0x0800: 'IPv4',
  0x0806: 'ARP',
  0x86DD: 'IPv6',
  0x8100: '802.1Q VLAN'
};

const IP_PROTOCOLS = {
  1: 'ICMP',
  6: 'TCP',
  17: 'UDP',
  47: 'GRE',
  50: 'ESP',
  51: 'AH',
  58: 'ICMPv6',
  89: 'OSPF'
};

/**
 * Parse an Ethernet II frame (Layer 2)
 */
function dissectEthernetFrame(buffer, offset = 0) {
  if (buffer.length < offset + 14) {
    return { error: 'Buffer too short for Ethernet II header' };
  }

  const dstMac = buffer.subarray(offset, offset + 6).toString('hex').match(/../g).join(':').toUpperCase();
  const srcMac = buffer.subarray(offset + 6, offset + 12).toString('hex').match(/../g).join(':').toUpperCase();
  const etherType = buffer.readUInt16BE(offset + 12);
  const etherTypeName = ETHER_TYPES[etherType] || `0x${etherType.toString(16).padStart(4, '0')}`;

  const payload = buffer.subarray(offset + 14);

  return {
    layer: 'L2_DataLink',
    dstMac,
    srcMac,
    etherType,
    etherTypeName,
    payload
  };
}

/**
 * Parse an IPv4 Header (Layer 3)
 */
function dissectIpv4Header(buffer, offset = 0) {
  if (buffer.length < offset + 20) {
    return { error: 'Buffer too short for IPv4 header' };
  }

  const verIhl = buffer.readUInt8(offset);
  const version = (verIhl >> 4) & 0x0F;
  const ihl = (verIhl & 0x0F) * 4; // Header length in bytes
  const dscpEcn = buffer.readUInt8(offset + 1);
  const totalLength = buffer.readUInt16BE(offset + 2);
  const identification = buffer.readUInt16BE(offset + 4);
  const flagsFragment = buffer.readUInt16BE(offset + 6);
  const flags = {
    reserved: Boolean(flagsFragment & 0x8000),
    dontFragment: Boolean(flagsFragment & 0x4000),
    moreFragments: Boolean(flagsFragment & 0x2000),
    fragmentOffset: flagsFragment & 0x1FFF
  };
  const ttl = buffer.readUInt8(offset + 8);
  const protocolNum = buffer.readUInt8(offset + 9);
  const protocolName = IP_PROTOCOLS[protocolNum] || `Protocol-${protocolNum}`;
  const headerChecksum = buffer.readUInt16BE(offset + 10);

  const srcIp = [
    buffer.readUInt8(offset + 12),
    buffer.readUInt8(offset + 13),
    buffer.readUInt8(offset + 14),
    buffer.readUInt8(offset + 15)
  ].join('.');

  const dstIp = [
    buffer.readUInt8(offset + 16),
    buffer.readUInt8(offset + 17),
    buffer.readUInt8(offset + 18),
    buffer.readUInt8(offset + 19)
  ].join('.');

  const payload = buffer.subarray(offset + ihl);

  return {
    layer: 'L3_Network',
    version,
    headerLength: ihl,
    totalLength,
    identification,
    flags,
    ttl,
    protocol: protocolNum,
    protocolName,
    headerChecksum: `0x${headerChecksum.toString(16).padStart(4, '0')}`,
    srcIp,
    dstIp,
    payload
  };
}

/**
 * Parse a TCP Header (Layer 4)
 */
function dissectTcpHeader(buffer, offset = 0) {
  if (buffer.length < offset + 20) {
    return { error: 'Buffer too short for TCP header' };
  }

  const srcPort = buffer.readUInt16BE(offset);
  const dstPort = buffer.readUInt16BE(offset + 2);
  const sequenceNumber = buffer.readUInt32BE(offset + 4);
  const acknowledgmentNumber = buffer.readUInt32BE(offset + 8);
  const dataOffsetByte = buffer.readUInt8(offset + 12);
  const headerLength = ((dataOffsetByte >> 4) & 0x0F) * 4;
  const flagsByte = buffer.readUInt8(offset + 13);

  const flags = {
    cwr: Boolean(flagsByte & 0x80),
    ece: Boolean(flagsByte & 0x40),
    urg: Boolean(flagsByte & 0x20),
    ack: Boolean(flagsByte & 0x10),
    psh: Boolean(flagsByte & 0x08),
    rst: Boolean(flagsByte & 0x04),
    syn: Boolean(flagsByte & 0x02),
    fin: Boolean(flagsByte & 0x01)
  };

  const windowSize = buffer.readUInt16BE(offset + 14);
  const checksum = buffer.readUInt16BE(offset + 16);
  const urgentPointer = buffer.readUInt16BE(offset + 18);

  const payload = buffer.subarray(offset + headerLength);

  return {
    layer: 'L4_Transport',
    srcPort,
    dstPort,
    sequenceNumber,
    acknowledgmentNumber,
    headerLength,
    flags,
    windowSize,
    checksum: `0x${checksum.toString(16).padStart(4, '0')}`,
    urgentPointer,
    payloadLength: payload.length,
    payload
  };
}

/**
 * Parse a UDP Header (Layer 4)
 */
function dissectUdpHeader(buffer, offset = 0) {
  if (buffer.length < offset + 8) {
    return { error: 'Buffer too short for UDP header' };
  }

  const srcPort = buffer.readUInt16BE(offset);
  const dstPort = buffer.readUInt16BE(offset + 2);
  const length = buffer.readUInt16BE(offset + 4);
  const checksum = buffer.readUInt16BE(offset + 6);
  const payload = buffer.subarray(offset + 8);

  return {
    layer: 'L4_Transport',
    srcPort,
    dstPort,
    length,
    checksum: `0x${checksum.toString(16).padStart(4, '0')}`,
    payloadLength: payload.length,
    payload
  };
}

/**
 * Parse a full raw packet buffer (L2 -> L3 -> L4 -> L7)
 */
function dissectPacket(rawBuffer) {
  const result = {
    timestamp: new Date().toISOString(),
    rawLength: rawBuffer.length,
    layers: {}
  };

  // 1. Try Ethernet L2
  const eth = dissectEthernetFrame(rawBuffer);
  if (eth && !eth.error) {
    result.layers.ethernet = {
      srcMac: eth.srcMac,
      dstMac: eth.dstMac,
      etherType: eth.etherTypeName
    };

    let nextBuffer = eth.payload;

    // 2. Try IPv4 L3
    if (eth.etherTypeName === 'IPv4') {
      const ip = dissectIpv4Header(nextBuffer);
      if (ip && !ip.error) {
        result.layers.ipv4 = {
          srcIp: ip.srcIp,
          dstIp: ip.dstIp,
          protocol: ip.protocolName,
          ttl: ip.ttl,
          totalLength: ip.totalLength,
          flags: ip.flags
        };

        // 3. Try L4 (TCP or UDP)
        if (ip.protocolName === 'TCP') {
          const tcp = dissectTcpHeader(ip.payload);
          if (tcp && !tcp.error) {
            result.layers.tcp = {
              srcPort: tcp.srcPort,
              dstPort: tcp.dstPort,
              seq: tcp.sequenceNumber,
              ack: tcp.acknowledgmentNumber,
              flags: tcp.flags,
              windowSize: tcp.windowSize,
              payloadBytes: tcp.payloadLength
            };

            // 4. Try L7 inspection (HTTP detection)
            if (tcp.payloadLength > 0) {
              const ascii = tcp.payload.toString('utf8', 0, Math.min(tcp.payloadLength, 200));
              if (/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|HTTP\/1\.)/i.test(ascii)) {
                result.layers.application = {
                  protocol: 'HTTP',
                  snippet: ascii.split('\r\n')[0]
                };
              }
            }
          }
        } else if (ip.protocolName === 'UDP') {
          const udp = dissectUdpHeader(ip.payload);
          if (udp && !udp.error) {
            result.layers.udp = {
              srcPort: udp.srcPort,
              dstPort: udp.dstPort,
              length: udp.length
            };

            if (udp.srcPort === 53 || udp.dstPort === 53) {
              result.layers.application = { protocol: 'DNS' };
            }
          }
        }
      }
    }
  } else {
    // If not Ethernet frame, try direct IPv4 packet dissection
    const ip = dissectIpv4Header(rawBuffer);
    if (ip && !ip.error) {
      result.layers.ipv4 = {
        srcIp: ip.srcIp,
        dstIp: ip.dstIp,
        protocol: ip.protocolName,
        ttl: ip.ttl
      };
    }
  }

  return result;
}

/**
 * Parse a standard PCAP file buffer
 * PCAP Global Header: 24 bytes
 * Packet Header: 16 bytes per packet
 */
function parsePcapBuffer(buffer) {
  if (buffer.length < 24) {
    return { success: false, error: 'File too small to be a valid PCAP (less than 24 bytes).' };
  }

  const magic = buffer.readUInt32LE(0);
  const isLittleEndian = (magic === 0xA1B2C3D4);
  const isBigEndian = (magic === 0xD4C3B2A1);

  if (!isLittleEndian && !isBigEndian) {
    return { success: false, error: `Invalid PCAP magic number: 0x${magic.toString(16)}. Not standard libpcap format.` };
  }

  const readU16 = (buf, off) => isLittleEndian ? buf.readUInt16LE(off) : buf.readUInt16BE(off);
  const readU32 = (buf, off) => isLittleEndian ? buf.readUInt32LE(off) : buf.readUInt32BE(off);

  const majorVersion = readU16(buffer, 4);
  const minorVersion = readU16(buffer, 6);
  const snaplen = readU32(buffer, 16);
  const linkType = readU32(buffer, 20);

  const packets = [];
  let offset = 24;
  let packetIdx = 0;

  while (offset + 16 <= buffer.length && packetIdx < 500) { // Limit to 500 packets per parse
    const tsSec = readU32(buffer, offset);
    const tsUsec = readU32(buffer, offset + 4);
    const inclLen = readU32(buffer, offset + 8);
    const origLen = readU32(buffer, offset + 12);
    offset += 16;

    if (offset + inclLen > buffer.length) break;

    const packetBuffer = buffer.subarray(offset, offset + inclLen);
    offset += inclLen;
    packetIdx++;

    const dissected = dissectPacket(packetBuffer);
    packets.push({
      index: packetIdx,
      timestamp: new Date(tsSec * 1000 + Math.floor(tsUsec / 1000)).toISOString(),
      capturedLength: inclLen,
      originalLength: origLen,
      dissection: dissected
    });
  }

  return {
    success: true,
    fileInfo: {
      version: `${majorVersion}.${minorVersion}`,
      endianness: isLittleEndian ? 'Little-Endian' : 'Big-Endian',
      snaplen,
      linkType: linkType === 1 ? 'Ethernet (1)' : `LinkType-${linkType}`,
      totalPacketsParsed: packets.length
    },
    packets
  };
}

module.exports = {
  dissectEthernetFrame,
  dissectIpv4Header,
  dissectTcpHeader,
  dissectUdpHeader,
  dissectPacket,
  parsePcapBuffer
};
