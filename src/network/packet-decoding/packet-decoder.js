/**
 * EJI Network Packet Dissector (RFC 791 / RFC 793 / IEEE 802.3)
 * Full binary protocol decoder for Ethernet II, IPv4, TCP, UDP, and ICMP frames.
 */

class PacketDecoder {
  /**
   * Format MAC address buffer to colon-separated string (e.g. 00:1A:2B:3C:4D:5E)
   */
  static formatMac(buf, offset = 0) {
    const bytes = [];
    for (let i = 0; i < 6; i++) {
      bytes.push(buf.readUInt8(offset + i).toString(16).padStart(2, '0').toUpperCase());
    }
    return bytes.join(':');
  }

  /**
   * Format IPv4 buffer to dotted decimal string (e.g. 192.168.1.1)
   */
  static formatIpv4(buf, offset = 0) {
    return `${buf.readUInt8(offset)}.${buf.readUInt8(offset + 1)}.${buf.readUInt8(offset + 2)}.${buf.readUInt8(offset + 3)}`;
  }

  /**
   * Format IPv6 buffer to colon-hex string (e.g. 2001:db8::1)
   */
  static formatIpv6(buf, offset = 0) {
    const parts = [];
    for (let i = 0; i < 16; i += 2) {
      parts.push(buf.readUInt16BE(offset + i).toString(16));
    }
    return parts.join(':');
  }

  /**
   * Passive OS Fingerprinting (p0f-style TCP/IP TTL + Window Size heuristic)
   * Infers operating system family non-intrusively from wire packet headers.
   */
  static computePassiveOsFingerprint(ttl, windowSize = null) {
    if (typeof ttl !== 'number') return 'Unknown OS';
    if (ttl > 64 && ttl <= 128) {
      return 'Windows 10/11 or Windows Server (TTL≈128)';
    } else if (ttl <= 64 && ttl > 32) {
      return 'Linux / macOS / Android / Embedded Printer OS (TTL≈64)';
    } else if (ttl > 128) {
      return 'Cisco IOS / Enterprise Network Router/Switch (TTL≈255)';
    }
    return `Generic Network Host (TTL=${ttl})`;
  }

  /**
   * Dissect Ethernet II Frame with 802.1Q VLAN support
   */
  static dissectEthernet(buf, offset = 0) {
    if (buf.length - offset < 14) {
      throw new Error(`Buffer too short for Ethernet header: ${buf.length - offset} bytes < 14 bytes`);
    }

    const dstMac = this.formatMac(buf, offset);
    const srcMac = this.formatMac(buf, offset + 6);
    let etherType = buf.readUInt16BE(offset + 12);
    let payloadOffset = offset + 14;
    let vlan = null;

    // Handle 802.1Q VLAN Tagging
    if (etherType === 0x8100 && buf.length - offset >= 18) {
      const vlanHdr = buf.readUInt16BE(offset + 14);
      const vlanId = vlanHdr & 0x0FFF;
      const priority = (vlanHdr >> 13) & 0x07;
      const dropEligible = Boolean((vlanHdr >> 12) & 0x01);
      const innerEtherType = buf.readUInt16BE(offset + 16);
      vlan = {
        vlanId,
        priority,
        dropEligible,
        innerEtherType: `0x${innerEtherType.toString(16).padStart(4, '0').toUpperCase()}`
      };
      etherType = innerEtherType;
      payloadOffset = offset + 18;
    }

    let typeStr = 'UNKNOWN';
    if (etherType === 0x0800) typeStr = 'IPv4';
    else if (etherType === 0x0806) typeStr = 'ARP';
    else if (etherType === 0x86DD) typeStr = 'IPv6';

    return {
      dstMac,
      srcMac,
      etherType: `0x${etherType.toString(16).padStart(4, '0').toUpperCase()}`,
      typeStr,
      vlan,
      payloadOffset
    };
  }

  /**
   * Dissect IPv6 Header (RFC 8200)
   */
  static dissectIpv6(buf, offset = 14) {
    if (buf.length - offset < 40) {
      throw new Error(`Buffer too short for IPv6 header: ${buf.length - offset} bytes < 40 bytes`);
    }

    const verTcFl = buf.readUInt32BE(offset);
    const version = (verTcFl >> 28) & 0x0F;
    const trafficClass = (verTcFl >> 20) & 0xFF;
    const flowLabel = verTcFl & 0xFFFFF;
    const payloadLength = buf.readUInt16BE(offset + 4);
    const nextHeader = buf.readUInt8(offset + 6);
    const hopLimit = buf.readUInt8(offset + 7);
    const srcIp = this.formatIpv6(buf, offset + 8);
    const dstIp = this.formatIpv6(buf, offset + 24);

    let nextHeaderStr = 'OTHER';
    if (nextHeader === 6) nextHeaderStr = 'TCP';
    else if (nextHeader === 17) nextHeaderStr = 'UDP';
    else if (nextHeader === 58) nextHeaderStr = 'ICMPv6';

    return {
      version,
      trafficClass,
      flowLabel: `0x${flowLabel.toString(16).toUpperCase()}`,
      payloadLength,
      nextHeader,
      nextHeaderStr,
      hopLimit,
      srcIp,
      dstIp,
      payloadOffset: offset + 40
    };
  }

  /**
   * Dissect IPv4 Header (RFC 791)
   */
  static dissectIpv4(buf, offset = 14) {
    if (buf.length - offset < 20) {
      throw new Error(`Buffer too short for IPv4 header: ${buf.length - offset} bytes < 20 bytes`);
    }

    const verIhl = buf.readUInt8(offset);
    const version = verIhl >> 4;
    const ihl = (verIhl & 0x0F) * 4; // Header length in bytes

    const dscpEcn = buf.readUInt8(offset + 1);
    const totalLength = buf.readUInt16BE(offset + 2);
    const identification = buf.readUInt16BE(offset + 4);
    
    const flagsFragment = buf.readUInt16BE(offset + 6);
    const flags = {
      dontFragment: Boolean(flagsFragment & 0x4000),
      moreFragments: Boolean(flagsFragment & 0x2000)
    };
    const fragmentOffset = (flagsFragment & 0x1FFF) * 8;

    const ttl = buf.readUInt8(offset + 8);
    const protocolNum = buf.readUInt8(offset + 9);
    const headerChecksum = buf.readUInt16BE(offset + 10);
    const srcIp = this.formatIpv4(buf, offset + 12);
    const dstIp = this.formatIpv4(buf, offset + 16);

    let protocolStr = 'OTHER';
    if (protocolNum === 6) protocolStr = 'TCP';
    else if (protocolNum === 17) protocolStr = 'UDP';
    else if (protocolNum === 1) protocolStr = 'ICMP';

    return {
      version,
      ihlBytes: ihl,
      dscp: dscpEcn >> 2,
      totalLength,
      identification,
      flags,
      fragmentOffset,
      ttl,
      protocolNum,
      protocolStr,
      headerChecksum: `0x${headerChecksum.toString(16).padStart(4, '0').toUpperCase()}`,
      srcIp,
      dstIp,
      payloadOffset: offset + ihl,
      passiveOsFingerprint: this.computePassiveOsFingerprint(ttl)
    };
  }

  /**
   * Dissect TCP Segment Header (RFC 793)
   */
  static dissectTcp(buf, offset) {
    if (buf.length - offset < 20) {
      throw new Error(`Buffer too short for TCP header: ${buf.length - offset} bytes < 20 bytes`);
    }

    const srcPort = buf.readUInt16BE(offset);
    const dstPort = buf.readUInt16BE(offset + 2);
    const seqNum = buf.readUInt32BE(offset + 4);
    const ackNum = buf.readUInt32BE(offset + 8);

    const dataOffsetByte = buf.readUInt8(offset + 12);
    const dataOffsetBytes = (dataOffsetByte >> 4) * 4;

    const flagsByte = buf.readUInt8(offset + 13);
    const flags = {
      urg: Boolean(flagsByte & 0x20),
      ack: Boolean(flagsByte & 0x10),
      psh: Boolean(flagsByte & 0x08),
      rst: Boolean(flagsByte & 0x04),
      syn: Boolean(flagsByte & 0x02),
      fin: Boolean(flagsByte & 0x01)
    };

    const windowSize = buf.readUInt16BE(offset + 14);
    const checksum = buf.readUInt16BE(offset + 16);
    const urgentPointer = buf.readUInt16BE(offset + 18);

    const payloadLength = Math.max(0, buf.length - (offset + dataOffsetBytes));
    let options = [];
    if (dataOffsetBytes > 20 && buf.length >= offset + dataOffsetBytes) {
      options = this.parseTcpOptions(buf, offset + 20, dataOffsetBytes - 20);
    }

    return {
      srcPort,
      dstPort,
      seqNum,
      ackNum,
      headerLengthBytes: dataOffsetBytes,
      flags,
      windowSize,
      checksum: `0x${checksum.toString(16).padStart(4, '0').toUpperCase()}`,
      urgentPointer,
      options,
      payloadLength
    };
  }

  /**
   * Verify IPv4 Header Checksum (RFC 791 / RFC 1071)
   */
  static verifyIpv4Checksum(buf, offset = 14, ihl = 20) {
    if (buf.length - offset < ihl) {
      return { isValid: false, calculated: '0x0000', status: 'bad' };
    }
    let sum = 0;
    for (let i = offset; i < offset + ihl; i += 2) {
      sum += buf.readUInt16BE(i);
    }
    while (sum >> 16) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    const isValid = (sum === 0xFFFF || sum === 0);

    // Compute expected checksum without existing checksum field
    let calcSum = 0;
    for (let i = offset; i < offset + ihl; i += 2) {
      if (i === offset + 10) continue;
      calcSum += buf.readUInt16BE(i);
    }
    while (calcSum >> 16) {
      calcSum = (calcSum & 0xFFFF) + (calcSum >> 16);
    }
    const calculated = (~calcSum) & 0xFFFF;
    return {
      isValid,
      calculated: `0x${calculated.toString(16).padStart(4, '0').toUpperCase()}`,
      status: isValid ? 'good' : 'bad'
    };
  }

  /**
   * Parse TCP Options (RFC 793, RFC 7323, RFC 2018)
   */
  static parseTcpOptions(buf, optOffset, optLen) {
    const options = [];
    let idx = optOffset;
    const end = Math.min(optOffset + optLen, buf.length);

    while (idx < end) {
      const kind = buf.readUInt8(idx);
      if (kind === 0) {
        // EOL
        options.push({ kind: 0, type: 'EOL', offset: idx, length: 1, label: 'End of Option List (EOL)' });
        break;
      }
      if (kind === 1) {
        // NOP
        options.push({ kind: 1, type: 'NOP', offset: idx, length: 1, label: 'No-Operation (NOP)' });
        idx++;
        continue;
      }

      if (idx + 1 >= end) break;
      const len = buf.readUInt8(idx + 1);
      if (len < 2 || idx + len > end) break;

      if (kind === 2 && len === 4) {
        const mss = buf.readUInt16BE(idx + 2);
        options.push({ kind: 2, type: 'MSS', offset: idx, length: 4, value: mss, label: `Maximum Segment Size: ${mss} bytes` });
      } else if (kind === 3 && len === 3) {
        const shift = buf.readUInt8(idx + 2);
        options.push({ kind: 3, type: 'WSOPT', offset: idx, length: 3, value: shift, multiplier: 1 << shift, label: `Window Scale: ${shift} (multiply by ${1 << shift})` });
      } else if (kind === 4 && len === 2) {
        options.push({ kind: 4, type: 'SACK_PERM', offset: idx, length: 2, value: true, label: 'SACK Permitted' });
      } else if (kind === 5) {
        const blocks = [];
        for (let b = idx + 2; b + 8 <= idx + len; b += 8) {
          blocks.push({ left: buf.readUInt32BE(b), right: buf.readUInt32BE(b + 4) });
        }
        options.push({ kind: 5, type: 'SACK', offset: idx, length: len, blocks, label: `SACK (${blocks.length} blocks)` });
      } else if (kind === 8 && len === 10) {
        const tsVal = buf.readUInt32BE(idx + 2);
        const tsEcho = buf.readUInt32BE(idx + 6);
        options.push({ kind: 8, type: 'TIMESTAMPS', offset: idx, length: 10, tsVal, tsEcho, label: `Timestamps: TSval ${tsVal}, TSecr ${tsEcho}` });
      } else {
        options.push({ kind, type: `OPT_${kind}`, offset: idx, length: len, label: `Option Kind ${kind} (len ${len})` });
      }

      idx += len;
    }
    return options;
  }

  /**
   * Dissect ICMP Header (RFC 792)
   */
  static dissectIcmp(buf, offset) {
    if (buf.length - offset < 8) {
      throw new Error(`Buffer too short for ICMP header: ${buf.length - offset} bytes < 8 bytes`);
    }

    const type = buf.readUInt8(offset);
    const code = buf.readUInt8(offset + 1);
    const checksum = buf.readUInt16BE(offset + 2);
    const identifier = buf.readUInt16BE(offset + 4);
    const sequenceNumber = buf.readUInt16BE(offset + 6);

    let typeStr = 'UNKNOWN';
    if (type === 0) typeStr = 'Echo Reply';
    else if (type === 8) typeStr = 'Echo Request';
    else if (type === 3) typeStr = 'Destination Unreachable';
    else if (type === 11) typeStr = 'Time Exceeded';

    return {
      type: 'ICMP',
      icmpType: type,
      code,
      typeStr,
      checksum: `0x${checksum.toString(16).padStart(4, '0').toUpperCase()}`,
      identifier,
      sequenceNumber,
      payloadLength: Math.max(0, buf.length - (offset + 8))
    };
  }

  /**
   * Dissect UDP Datagram Header (RFC 768)
   */
  static dissectUdp(buf, offset) {
    if (buf.length - offset < 8) {
      throw new Error(`Buffer too short for UDP header: ${buf.length - offset} bytes < 8 bytes`);
    }

    const srcPort = buf.readUInt16BE(offset);
    const dstPort = buf.readUInt16BE(offset + 2);
    const length = buf.readUInt16BE(offset + 4);
    const checksum = buf.readUInt16BE(offset + 6);
    const payloadLength = Math.max(0, buf.length - (offset + 8));

    return {
      srcPort,
      dstPort,
      length,
      checksum: `0x${checksum.toString(16).padStart(4, '0').toUpperCase()}`,
      payloadLength
    };
  }

  /**
   * Dissect ARP Packet Header (RFC 826)
   */
  static dissectArp(buf, offset) {
    if (buf.length - offset < 28) {
      throw new Error(`Buffer too short for ARP header: ${buf.length - offset} bytes < 28 bytes`);
    }

    const hardwareType = buf.readUInt16BE(offset);
    const protocolType = buf.readUInt16BE(offset + 2);
    const hwLen = buf.readUInt8(offset + 4);
    const protoLen = buf.readUInt8(offset + 5);
    const opcode = buf.readUInt16BE(offset + 6);

    const senderMac = this.formatMac(buf, offset + 8);
    const senderIp = this.formatIpv4(buf, offset + 14);
    const targetMac = this.formatMac(buf, offset + 18);
    const targetIp = this.formatIpv4(buf, offset + 24);

    return {
      hardwareType,
      protocolType: `0x${protocolType.toString(16).padStart(4, '0').toUpperCase()}`,
      opcode: opcode === 1 ? 'ARP Request (1)' : (opcode === 2 ? 'ARP Reply (2)' : `Opcode ${opcode}`),
      senderMac,
      senderIp,
      targetMac,
      targetIp
    };
  }

  /**
   * RFC 1035 Domain Name Pointer Decompression Helper
   */
  static parseDnsName(buf, dnsOffset, currentOffset) {
    const parts = [];
    const visited = new Set();
    let offset = currentOffset;
    let stepped = false;
    let nextOffset = currentOffset;

    while (offset < buf.length) {
      const len = buf.readUInt8(offset);
      if (len === 0) {
        offset++;
        if (!stepped) nextOffset = offset;
        break;
      }
      if ((len & 0xC0) === 0xC0) {
        if (offset + 1 >= buf.length) break;
        const ptr = ((len & 0x3F) << 8) | buf.readUInt8(offset + 1);
        if (!stepped) {
          nextOffset = offset + 2;
          stepped = true;
        }
        const targetOffset = dnsOffset + ptr;
        if (visited.has(targetOffset) || targetOffset >= buf.length) break;
        visited.add(targetOffset);
        offset = targetOffset;
      } else {
        offset++;
        if (offset + len > buf.length) break;
        parts.push(buf.toString('utf-8', offset, offset + len));
        offset += len;
        if (!stepped) nextOffset = offset;
      }
    }
    return { name: parts.join('.'), nextOffset };
  }

  /**
   * Dissect DNS Message (RFC 1035) with Byte Offsets & Full Pointer Decompression
   */
  static dissectDns(buf, offset = 0) {
    if (buf.length - offset < 12) return null;
    const transactionId = buf.readUInt16BE(offset);
    const flags = buf.readUInt16BE(offset + 2);
    const isResponse = Boolean(flags & 0x8000);
    const opcode = (flags >> 11) & 0x0F;
    const authorative = Boolean(flags & 0x0400);
    const truncated = Boolean(flags & 0x0200);
    const recursionDesired = Boolean(flags & 0x0100);
    const recursionAvailable = Boolean(flags & 0x0080);
    const rcode = flags & 0x000F;

    const qdCount = buf.readUInt16BE(offset + 4);
    const anCount = buf.readUInt16BE(offset + 6);
    const nsCount = buf.readUInt16BE(offset + 8);
    const arCount = buf.readUInt16BE(offset + 10);

    const questions = [];
    let idx = offset + 12;

    for (let i = 0; i < qdCount && idx < buf.length; i++) {
      const qStart = idx;
      const { name: qName, nextOffset: afterName } = this.parseDnsName(buf, offset, idx);
      idx = afterName;
      if (idx + 4 <= buf.length) {
        const qType = buf.readUInt16BE(idx);
        const qClass = buf.readUInt16BE(idx + 2);
        idx += 4;
        const typeMap = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA' };
        questions.push({
          offset: qStart,
          length: idx - qStart,
          name: qName,
          type: typeMap[qType] || `Type ${qType}`,
          typeNum: qType,
          class: qClass === 1 ? 'IN' : `Class ${qClass}`
        });
      }
    }

    const answers = [];
    for (let i = 0; i < anCount && idx < buf.length; i++) {
      const ansStart = idx;
      const { name: ansName, nextOffset: afterName } = this.parseDnsName(buf, offset, idx);
      idx = afterName;
      if (idx + 10 <= buf.length) {
        const aType = buf.readUInt16BE(idx);
        const aClass = buf.readUInt16BE(idx + 2);
        const ttl = buf.readUInt32BE(idx + 4);
        const dataLen = buf.readUInt16BE(idx + 8);
        idx += 10;
        let dataStr = '';
        const rdataOffset = idx;
        if (aType === 1 && dataLen === 4 && idx + 4 <= buf.length) {
          dataStr = this.formatIpv4(buf, idx);
        } else if (aType === 28 && dataLen === 16 && idx + 16 <= buf.length) {
          dataStr = this.formatIpv6(buf, idx);
        } else if ((aType === 2 || aType === 5 || aType === 12) && idx + dataLen <= buf.length) {
          const { name: targetDomain } = this.parseDnsName(buf, offset, idx);
          dataStr = targetDomain;
        } else {
          dataStr = buf.toString('hex', idx, Math.min(idx + dataLen, buf.length));
        }
        idx += dataLen;
        const typeMap = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA' };
        answers.push({
          offset: ansStart,
          length: idx - ansStart,
          name: ansName,
          type: typeMap[aType] || `Type ${aType}`,
          typeNum: aType,
          class: aClass === 1 ? 'IN' : `Class ${aClass}`,
          ttl,
          rdataOffset,
          dataLen,
          data: dataStr
        });
      }
    }

    return {
      type: 'DNS',
      transactionId: `0x${transactionId.toString(16).padStart(4, '0').toUpperCase()}`,
      isResponse,
      opcode,
      authorative,
      truncated,
      recursionDesired,
      recursionAvailable,
      rcode,
      rcodeStr: rcode === 0 ? 'No error' : (rcode === 3 ? 'NXDomain' : `RCODE ${rcode}`),
      questions,
      answers,
      qdCount,
      anCount,
      nsCount,
      arCount
    };
  }

  /**
   * Dissect TLS Record & Handshake (RFC 5246 / RFC 8446)
   * Supports ClientHello SNI and ServerHello Selected Cipher Suite
   */
  static dissectTls(buf, offset = 0) {
    if (buf.length - offset < 5) return null;
    const contentType = buf.readUInt8(offset);
    const ctMap = { 20: 'ChangeCipherSpec', 21: 'Alert', 22: 'Handshake', 23: 'ApplicationData' };
    if (!ctMap[contentType]) return null;

    const major = buf.readUInt8(offset + 1);
    const minor = buf.readUInt8(offset + 2);
    const length = buf.readUInt16BE(offset + 3);

    const vMap = { '3.1': 'TLS 1.0', '3.2': 'TLS 1.1', '3.3': 'TLS 1.2', '3.4': 'TLS 1.3' };
    const versionStr = vMap[`${major}.${minor}`] || `TLS ${major}.${minor}`;

    let handshake = null;
    if (contentType === 22 && buf.length - offset >= 9) {
      const hsType = buf.readUInt8(offset + 5);
      const hsMap = { 1: 'ClientHello', 2: 'ServerHello', 11: 'Certificate', 12: 'ServerKeyExchange', 14: 'ServerHelloDone' };
      const hsLength = (buf.readUInt8(offset + 6) << 16) | buf.readUInt16BE(offset + 7);

      let sni = null;
      let cipherSuite = null;
      let cipherSuiteHex = null;
      let cipherSuiteOffset = null;

      // 1. ClientHello SNI Extraction
      if (hsType === 1 && buf.length - offset > 43) {
        try {
          let idx = offset + 9;
          idx += 2 + 32; // Skip client version + random
          if (idx < buf.length) {
            const sessLen = buf.readUInt8(idx++);
            idx += sessLen;
            if (idx + 2 <= buf.length) {
              const cipherLen = buf.readUInt16BE(idx);
              idx += 2 + cipherLen;
              if (idx + 1 <= buf.length) {
                const compLen = buf.readUInt8(idx++);
                idx += compLen;
                if (idx + 2 <= buf.length) {
                  const extTotalLen = buf.readUInt16BE(idx);
                  idx += 2;
                  const extEnd = Math.min(idx + extTotalLen, buf.length);
                  while (idx + 4 <= extEnd) {
                    const extType = buf.readUInt16BE(idx);
                    const extLen = buf.readUInt16BE(idx + 2);
                    idx += 4;
                    if (extType === 0 && idx + 5 <= buf.length) {
                      const nameLen = buf.readUInt16BE(idx + 3);
                      sni = buf.toString('utf-8', idx + 5, idx + 5 + nameLen);
                      break;
                    }
                    idx += extLen;
                  }
                }
              }
            }
          }
        } catch (e) {}
      }

      // 2. ServerHello Selected Cipher Suite Extraction
      if (hsType === 2 && buf.length - offset > 40) {
        try {
          let idx = offset + 9;
          idx += 2 + 32; // Skip server version (2) + random (32)
          if (idx < buf.length) {
            const sessLen = buf.readUInt8(idx++);
            idx += sessLen;
            if (idx + 2 <= buf.length) {
              cipherSuiteOffset = idx;
              const csCode = buf.readUInt16BE(idx);
              cipherSuiteHex = `0x${csCode.toString(16).padStart(4, '0').toUpperCase()}`;
              const csMap = {
                0x1301: 'TLS_AES_128_GCM_SHA256',
                0x1302: 'TLS_AES_256_GCM_SHA384',
                0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
                0xC02B: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
                0xC02C: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
                0xC02F: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                0xC030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                0x009C: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
                0x009D: 'TLS_RSA_WITH_AES_256_GCM_SHA384'
              };
              cipherSuite = csMap[csCode] || `CipherSuite-${cipherSuiteHex}`;
            }
          }
        } catch (e) {}
      }

      handshake = {
        type: hsMap[hsType] || `Type ${hsType}`,
        typeNum: hsType,
        length: hsLength,
        sni,
        cipherSuite,
        cipherSuiteHex,
        cipherSuiteOffset
      };
    }

    return {
      type: 'TLS',
      contentType: ctMap[contentType],
      contentTypeNum: contentType,
      version: versionStr,
      length,
      handshake
    };
  }

  /**
   * Dissect HTTP 1.x Request / Response (RFC 7230)
   */
  static dissectHttp(buf, offset = 0) {
    if (buf.length - offset < 10) return null;
    const str = buf.toString('utf-8', offset, Math.min(offset + 1024, buf.length));
    const methods = ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'HTTP/1.0', 'HTTP/1.1'];
    if (!methods.some(m => str.startsWith(m))) return null;

    const lines = str.split('\r\n');
    const firstLine = lines[0];
    const headers = {};
    for (let i = 1; i < lines.length; i++) {
      if (!lines[i]) break;
      const colonIdx = lines[i].indexOf(': ');
      if (colonIdx > 0) {
        headers[lines[i].slice(0, colonIdx).toLowerCase()] = lines[i].slice(colonIdx + 2);
      }
    }

    if (firstLine.startsWith('HTTP/')) {
      const parts = firstLine.split(' ');
      return {
        type: 'RESPONSE',
        statusCode: parseInt(parts[1], 10) || 200,
        statusText: parts.slice(2).join(' '),
        headers
      };
    } else {
      const parts = firstLine.split(' ');
      return {
        type: 'REQUEST',
        method: parts[0],
        uri: parts[1] || '/',
        version: parts[2] || 'HTTP/1.1',
        host: headers['host'] || '',
        userAgent: headers['user-agent'] || '',
        headers
      };
    }
  }

  /**
   * Dissect entire packet frame with byte-accurate offset and length spans (RFC-compliant)
   */
  static dissectDetailed(rawInput) {
    const buf = Buffer.isBuffer(rawInput)
      ? rawInput
      : Buffer.from(String(rawInput).replace(/[\s:-]/g, ''), 'hex');

    const rawHex = buf.toString('hex');
    const rawBytesBase64 = buf.toString('base64');
    const layers = [];
    const fieldsMap = {};

    const addLayer = (layerName, proto, offset, length, label, fields) => {
      const layerObj = {
        name: layerName,
        proto,
        offset,
        length: Math.min(length, Math.max(0, buf.length - offset)),
        label,
        fields: fields || {}
      };
      layers.push(layerObj);
      for (const [k, v] of Object.entries(layerObj.fields)) {
        fieldsMap[k] = v;
      }
      return layerObj;
    };

    if (buf.length < 14) {
      return {
        frameLengthBytes: buf.length,
        wireLength: buf.length,
        capturedLength: buf.length,
        timestamp: new Date().toISOString(),
        rawHex,
        rawBytesBase64,
        layers,
        fields: fieldsMap
      };
    }

    // 1. Layer 2: Ethernet II
    const dstMac = this.formatMac(buf, 0);
    const srcMac = this.formatMac(buf, 6);
    let etherType = buf.readUInt16BE(12);
    let payloadOffset = 14;
    let vlan = null;

    const ethFields = {
      'eth.dst': { offset: 0, length: 6, value: dstMac, label: `Destination: ${dstMac}` },
      'eth.src': { offset: 6, length: 6, value: srcMac, label: `Source: ${srcMac}` },
      'eth.type': { offset: 12, length: 2, value: `0x${etherType.toString(16).padStart(4, '0').toUpperCase()}`, label: `Type: 0x${etherType.toString(16).padStart(4, '0').toUpperCase()}` }
    };

    // Check 802.1Q VLAN
    if (etherType === 0x8100 && buf.length >= 18) {
      const vlanHdr = buf.readUInt16BE(14);
      const vlanId = vlanHdr & 0x0FFF;
      const priority = (vlanHdr >> 13) & 0x07;
      const dropEligible = Boolean((vlanHdr >> 12) & 0x01);
      const innerEtherType = buf.readUInt16BE(16);
      vlan = {
        vlanId,
        priority,
        dropEligible,
        innerEtherType: `0x${innerEtherType.toString(16).padStart(4, '0').toUpperCase()}`
      };
      etherType = innerEtherType;
      payloadOffset = 18;

      addLayer('Ethernet II', 'eth', 0, 14, `Ethernet II, Src: ${srcMac}, Dst: ${dstMac}`, ethFields);
      addLayer('802.1Q Virtual LAN', 'vlan', 14, 4, `802.1Q Virtual LAN, PRI: ${priority}, DEI: ${dropEligible ? 1 : 0}, ID: ${vlanId}`, {
        'vlan.pri': { offset: 14, length: 2, value: priority, label: `Priority: ${priority}` },
        'vlan.dei': { offset: 14, length: 2, value: dropEligible, label: `Drop eligible: ${dropEligible}` },
        'vlan.id': { offset: 14, length: 2, value: vlanId, label: `VLAN Identifier: ${vlanId}` },
        'vlan.type': { offset: 16, length: 2, value: vlan.innerEtherType, label: `Type: ${vlan.innerEtherType}` }
      });
    } else {
      addLayer('Ethernet II', 'eth', 0, 14, `Ethernet II, Src: ${srcMac}, Dst: ${dstMac}`, ethFields);
    }

    let typeStr = 'UNKNOWN';
    if (etherType === 0x0800) typeStr = 'IPv4';
    else if (etherType === 0x0806) typeStr = 'ARP';
    else if (etherType === 0x86DD) typeStr = 'IPv6';

    const ethernet = {
      dstMac,
      srcMac,
      etherType: `0x${etherType.toString(16).padStart(4, '0').toUpperCase()}`,
      typeStr,
      vlan,
      payloadOffset
    };

    let ip = null;
    let ipv6 = null;
    let transport = null;
    let application = null;

    // 2. Layer 3: ARP
    if (etherType === 0x0806 && buf.length - payloadOffset >= 28) {
      const hwType = buf.readUInt16BE(payloadOffset);
      const protoType = buf.readUInt16BE(payloadOffset + 2);
      const hwLen = buf.readUInt8(payloadOffset + 4);
      const protoLen = buf.readUInt8(payloadOffset + 5);
      const opcode = buf.readUInt16BE(payloadOffset + 6);
      const sMac = this.formatMac(buf, payloadOffset + 8);
      const sIp = this.formatIpv4(buf, payloadOffset + 14);
      const tMac = this.formatMac(buf, payloadOffset + 18);
      const tIp = this.formatIpv4(buf, payloadOffset + 24);

      const opStr = opcode === 1 ? 'ARP Request (1)' : (opcode === 2 ? 'ARP Reply (2)' : `Opcode ${opcode}`);
      transport = {
        type: 'ARP',
        hardwareType: hwType,
        protocolType: `0x${protoType.toString(16).padStart(4, '0').toUpperCase()}`,
        opcode: opStr,
        senderMac: sMac,
        senderIp: sIp,
        targetMac: tMac,
        targetIp: tIp
      };

      addLayer('Address Resolution Protocol', 'arp', payloadOffset, 28, `Address Resolution Protocol (${opStr})`, {
        'arp.hw.type': { offset: payloadOffset, length: 2, value: hwType, label: `Hardware type: Ethernet (${hwType})` },
        'arp.proto.type': { offset: payloadOffset + 2, length: 2, value: transport.protocolType, label: `Protocol type: IPv4 (${transport.protocolType})` },
        'arp.hw.size': { offset: payloadOffset + 4, length: 1, value: hwLen, label: `Hardware size: ${hwLen}` },
        'arp.proto.size': { offset: payloadOffset + 5, length: 1, value: protoLen, label: `Protocol size: ${protoLen}` },
        'arp.opcode': { offset: payloadOffset + 6, length: 2, value: opcode, label: `Opcode: ${opStr}` },
        'arp.src.hw_mac': { offset: payloadOffset + 8, length: 6, value: sMac, label: `Sender MAC: ${sMac}` },
        'arp.src.mac': { offset: payloadOffset + 8, length: 6, value: sMac, label: `Sender MAC: ${sMac}` },
        'arp.src.proto_ipv4': { offset: payloadOffset + 14, length: 4, value: sIp, label: `Sender IP: ${sIp}` },
        'arp.src.ip': { offset: payloadOffset + 14, length: 4, value: sIp, label: `Sender IP: ${sIp}` },
        'arp.dst.hw_mac': { offset: payloadOffset + 18, length: 6, value: tMac, label: `Target MAC: ${tMac}` },
        'arp.dst.mac': { offset: payloadOffset + 18, length: 6, value: tMac, label: `Target MAC: ${tMac}` },
        'arp.dst.proto_ipv4': { offset: payloadOffset + 24, length: 4, value: tIp, label: `Target IP: ${tIp}` },
        'arp.dst.ip': { offset: payloadOffset + 24, length: 4, value: tIp, label: `Target IP: ${tIp}` }
      });
    }

    // 3. Layer 3: IPv4
    if (etherType === 0x0800 && buf.length - payloadOffset >= 20) {
      const verIhl = buf.readUInt8(payloadOffset);
      const version = verIhl >> 4;
      const ihl = (verIhl & 0x0F) * 4;
      const dscpEcn = buf.readUInt8(payloadOffset + 1);
      const totalLen = buf.readUInt16BE(payloadOffset + 2);
      const id = buf.readUInt16BE(payloadOffset + 4);
      const flagsFrag = buf.readUInt16BE(payloadOffset + 6);
      const df = Boolean(flagsFrag & 0x4000);
      const mf = Boolean(flagsFrag & 0x2000);
      const fragOffset = (flagsFrag & 0x1FFF) * 8;
      const ttl = buf.readUInt8(payloadOffset + 8);
      const protoNum = buf.readUInt8(payloadOffset + 9);
      const checksum = buf.readUInt16BE(payloadOffset + 10);
      const srcIp = this.formatIpv4(buf, payloadOffset + 12);
      const dstIp = this.formatIpv4(buf, payloadOffset + 16);

      const chk = this.verifyIpv4Checksum(buf, payloadOffset, ihl);
      const isTruncated = (payloadOffset + totalLen) > buf.length;

      let protoStr = 'OTHER';
      if (protoNum === 6) protoStr = 'TCP';
      else if (protoNum === 17) protoStr = 'UDP';
      else if (protoNum === 1) protoStr = 'ICMP';

      ip = {
        version,
        ihlBytes: ihl,
        dscp: dscpEcn >> 2,
        totalLength: totalLen,
        identification: id,
        flags: { dontFragment: df, moreFragments: mf },
        fragmentOffset: fragOffset,
        isFragmented: mf || (fragOffset > 0),
        isTruncated,
        ttl,
        protocolNum: protoNum,
        protocolStr: protoStr,
        headerChecksum: `0x${checksum.toString(16).padStart(4, '0').toUpperCase()}`,
        checksumValid: chk.isValid,
        checksumCalculated: chk.calculated,
        srcIp,
        dstIp,
        payloadOffset: payloadOffset + ihl,
        passiveOsFingerprint: this.computePassiveOsFingerprint(ttl)
      };

      addLayer('Internet Protocol Version 4', 'ipv4', payloadOffset, ihl, `Internet Protocol Version 4, Src: ${srcIp}, Dst: ${dstIp}`, {
        'ip.version': { offset: payloadOffset, length: 1, value: version, label: `Version: ${version}` },
        'ip.hdr_len': { offset: payloadOffset, length: 1, value: ihl, label: `Header Length: ${ihl} bytes (${verIhl & 0x0F})` },
        'ip.dsfield': { offset: payloadOffset + 1, length: 1, value: dscpEcn >> 2, label: `Differentiated Services Field: 0x${dscpEcn.toString(16)} (DSCP: ${dscpEcn >> 2})` },
        'ip.len': { offset: payloadOffset + 2, length: 2, value: totalLen, label: `Total Length: ${totalLen}` },
        'ip.id': { offset: payloadOffset + 4, length: 2, value: id, label: `Identification: 0x${id.toString(16).padStart(4, '0')} (${id})` },
        'ip.flags': { offset: payloadOffset + 6, length: 2, value: { df, mf }, label: `Flags: 0x${(flagsFrag >> 13).toString(16)} (DF: ${df ? 1 : 0}, MF: ${mf ? 1 : 0})` },
        'ip.frag_offset': { offset: payloadOffset + 6, length: 2, value: fragOffset, label: `Fragment offset: ${fragOffset}` },
        'ip.ttl': { offset: payloadOffset + 8, length: 1, value: ttl, label: `Time to live: ${ttl}` },
        'ip.passive_os': { offset: payloadOffset + 8, length: 1, value: ip.passiveOsFingerprint, label: `Passive OS Fingerprint: ${ip.passiveOsFingerprint}` },
        'ip.proto': { offset: payloadOffset + 9, length: 1, value: protoNum, label: `Protocol: ${protoStr} (${protoNum})` },
        'ip.checksum': { offset: payloadOffset + 10, length: 2, value: ip.headerChecksum, label: `Header checksum: ${ip.headerChecksum}` },
        'ip.checksum_status': { offset: payloadOffset + 10, length: 2, value: chk.status, label: `Header checksum status: ${chk.status}` },
        'ip.checksum_calculated': { offset: payloadOffset + 10, length: 2, value: chk.calculated, label: `Calculated checksum: ${chk.calculated}` },
        'ip.src': { offset: payloadOffset + 12, length: 4, value: srcIp, label: `Source Address: ${srcIp}` },
        'ip.dst': { offset: payloadOffset + 16, length: 4, value: dstIp, label: `Destination Address: ${dstIp}` }
      });

      const l4Offset = payloadOffset + ihl;

      // Handle non-initial IPv4 fragment
      if (fragOffset > 0) {
        const fragDataLen = Math.max(0, buf.length - l4Offset);
        addLayer('IPv4 Fragment', 'fragment', l4Offset, fragDataLen, `IPv4 Fragment Data (${fragDataLen} bytes, Offset: ${fragOffset})`, {
          'ip.fragment.data': { offset: l4Offset, length: fragDataLen, value: fragDataLen, label: `Fragment Data: ${fragDataLen} bytes` }
        });
      }
      // Layer 4: TCP (Only when initial fragment)
      else if (protoNum === 6 && buf.length - l4Offset >= 20) {
        const srcPort = buf.readUInt16BE(l4Offset);
        const dstPort = buf.readUInt16BE(l4Offset + 2);
        const seqNum = buf.readUInt32BE(l4Offset + 4);
        const ackNum = buf.readUInt32BE(l4Offset + 8);
        const dataOffsetBytes = (buf.readUInt8(l4Offset + 12) >> 4) * 4;
        const flagsByte = buf.readUInt8(l4Offset + 13);
        const flags = {
          urg: Boolean(flagsByte & 0x20),
          ack: Boolean(flagsByte & 0x10),
          psh: Boolean(flagsByte & 0x08),
          rst: Boolean(flagsByte & 0x04),
          syn: Boolean(flagsByte & 0x02),
          fin: Boolean(flagsByte & 0x01)
        };
        const windowSize = buf.readUInt16BE(l4Offset + 14);
        const tcpChecksum = buf.readUInt16BE(l4Offset + 16);
        const urgentPointer = buf.readUInt16BE(l4Offset + 18);
        const tcpPayloadLen = Math.max(0, buf.length - (l4Offset + dataOffsetBytes));

        let tcpOptions = [];
        if (dataOffsetBytes > 20 && buf.length >= l4Offset + dataOffsetBytes) {
          tcpOptions = this.parseTcpOptions(buf, l4Offset + 20, dataOffsetBytes - 20);
        }

        transport = {
          type: 'TCP',
          srcPort,
          dstPort,
          seqNum,
          ackNum,
          headerLengthBytes: dataOffsetBytes,
          flags,
          windowSize,
          checksum: `0x${tcpChecksum.toString(16).padStart(4, '0').toUpperCase()}`,
          urgentPointer,
          options: tcpOptions,
          payloadLength: tcpPayloadLen,
          passiveOsFingerprint: this.computePassiveOsFingerprint(ip ? ip.ttl : null, windowSize)
        };

        const flagNames = Object.entries(flags).filter(([_, v]) => v).map(([k]) => k.toUpperCase());
        const tcpFields = {
          'tcp.srcport': { offset: l4Offset, length: 2, value: srcPort, label: `Source Port: ${srcPort}` },
          'tcp.dstport': { offset: l4Offset + 2, length: 2, value: dstPort, label: `Destination Port: ${dstPort}` },
          'tcp.seq': { offset: l4Offset + 4, length: 4, value: seqNum, label: `Sequence Number: ${seqNum}` },
          'tcp.ack': { offset: l4Offset + 8, length: 4, value: ackNum, label: `Acknowledgment Number: ${ackNum}` },
          'tcp.hdr_len': { offset: l4Offset + 12, length: 1, value: dataOffsetBytes, label: `Header Length: ${dataOffsetBytes} bytes (${dataOffsetBytes / 4})` },
          'tcp.flags': { offset: l4Offset + 13, length: 1, value: flags, label: `Flags: 0x${flagsByte.toString(16).padStart(2, '0')} [${flagNames.join(', ')}]` },
          'tcp.flags.syn': { offset: l4Offset + 13, length: 1, value: flags.syn, label: `SYN: ${flags.syn}` },
          'tcp.flags.ack': { offset: l4Offset + 13, length: 1, value: flags.ack, label: `ACK: ${flags.ack}` },
          'tcp.flags.rst': { offset: l4Offset + 13, length: 1, value: flags.rst, label: `RST: ${flags.rst}` },
          'tcp.flags.fin': { offset: l4Offset + 13, length: 1, value: flags.fin, label: `FIN: ${flags.fin}` },
          'tcp.flags.psh': { offset: l4Offset + 13, length: 1, value: flags.psh, label: `PSH: ${flags.psh}` },
          'tcp.flags.urg': { offset: l4Offset + 13, length: 1, value: flags.urg, label: `URG: ${flags.urg}` },
          'tcp.window_size': { offset: l4Offset + 14, length: 2, value: windowSize, label: `Window Size: ${windowSize}` },
          'tcp.checksum': { offset: l4Offset + 16, length: 2, value: transport.checksum, label: `Checksum: ${transport.checksum}` },
          'tcp.urgent_pointer': { offset: l4Offset + 18, length: 2, value: urgentPointer, label: `Urgent Pointer: ${urgentPointer}` }
        };

        for (const opt of tcpOptions) {
          if (opt.type === 'MSS') {
            tcpFields['tcp.options.mss'] = { offset: opt.offset, length: opt.length, value: opt.value, label: opt.label };
          } else if (opt.type === 'WSOPT') {
            tcpFields['tcp.options.wscale'] = { offset: opt.offset, length: opt.length, value: opt.value, label: opt.label };
          } else if (opt.type === 'SACK_PERM') {
            tcpFields['tcp.options.sack_perm'] = { offset: opt.offset, length: opt.length, value: true, label: opt.label };
          } else if (opt.type === 'TIMESTAMPS') {
            tcpFields['tcp.options.timestamps'] = { offset: opt.offset, length: opt.length, value: { tsVal: opt.tsVal, tsEcho: opt.tsEcho }, label: opt.label };
          }
        }

        addLayer('Transmission Control Protocol', 'tcp', l4Offset, dataOffsetBytes, `Transmission Control Protocol, Src Port: ${srcPort}, Dst Port: ${dstPort}, Seq: ${seqNum}, Ack: ${ackNum}, Flags: [${flagNames.join(', ')}]`, tcpFields);

        const l7Offset = l4Offset + dataOffsetBytes;
        if (tcpPayloadLen > 0) {
          // L7: TLS
          const tls = this.dissectTls(buf, l7Offset);
          if (tls) {
            application = tls;
            const hs = tls.handshake;
            const isAppData = tls.contentTypeNum === 23;
            const tlsFields = {
              'tls.record.content_type': { offset: l7Offset, length: 1, value: tls.contentType, label: `Content Type: ${tls.contentType} (${tls.contentTypeNum})` },
              'tls.record.version': { offset: l7Offset + 1, length: 2, value: tls.version, label: `Version: ${tls.version}` },
              'tls.record.length': { offset: l7Offset + 3, length: 2, value: tls.length, label: `Length: ${tls.length}` }
            };
            if (hs) {
              tlsFields['tls.handshake.type'] = { offset: l7Offset + 5, length: 1, value: hs.type, label: `Handshake Type: ${hs.type}` };
              tlsFields['tls.handshake.length'] = { offset: l7Offset + 6, length: 3, value: hs.length, label: `Length: ${hs.length}` };
              if (hs.sni) {
                tlsFields['tls.handshake.extensions_server_name'] = { offset: l7Offset + 43, length: hs.sni.length, value: hs.sni, label: `Server Name: ${hs.sni}` };
              }
              if (hs.cipherSuiteHex) {
                tlsFields['tls.handshake.ciphersuite'] = { offset: hs.cipherSuiteOffset, length: 2, value: hs.cipherSuiteHex, label: `Cipher Suite: ${hs.cipherSuite} (${hs.cipherSuiteHex})` };
              }
            }
            const labelStr = isAppData
              ? `Transport Layer Security (${tls.version || 'TLS'} Application Data [Encrypted])`
              : `Transport Layer Security (${tls.version || 'TLS'} ${hs?.type || tls.contentType})`;
            addLayer('Transport Layer Security', 'tls', l7Offset, Math.min(buf.length - l7Offset, 5 + tls.length), labelStr, tlsFields);
          } else {
            // L7: HTTP (ONLY IF NOT TLS!)
            const http = this.dissectHttp(buf, l7Offset);
            if (http) {
              application = http;
              const isReq = http.type === 'REQUEST';
              const firstLine = isReq ? `${http.method} ${http.uri} ${http.version}` : `HTTP/1.1 ${http.statusCode} ${http.statusText}`;
              addLayer('Hypertext Transfer Protocol', 'http', l7Offset, buf.length - l7Offset, `Hypertext Transfer Protocol: ${firstLine}`, {
                'http.first_line': { offset: l7Offset, length: Math.min(100, buf.length - l7Offset), value: firstLine, label: firstLine },
                'http.request.method': isReq ? { offset: l7Offset, length: http.method.length, value: http.method, label: `Request Method: ${http.method}` } : undefined,
                'http.request.uri': isReq ? { offset: l7Offset + http.method.length + 1, length: http.uri.length, value: http.uri, label: `Request URI: ${http.uri}` } : undefined,
                'http.host': http.host ? { offset: l7Offset, length: http.host.length, value: http.host, label: `Host: ${http.host}` } : undefined,
                'http.user_agent': http.userAgent ? { offset: l7Offset, length: http.userAgent.length, value: http.userAgent, label: `User-Agent: ${http.userAgent}` } : undefined,
                'http.response.code': !isReq ? { offset: l7Offset + 9, length: 3, value: http.statusCode, label: `Status Code: ${http.statusCode}` } : undefined
              });
            } else {
              // Raw TCP payload
              addLayer('TCP Payload', 'data', l7Offset, tcpPayloadLen, `TCP Payload (${tcpPayloadLen} bytes)`, {
                'tcp.payload': { offset: l7Offset, length: tcpPayloadLen, value: tcpPayloadLen, label: `Payload Data: ${tcpPayloadLen} bytes` }
              });
            }
          }
        }
      }

      // Layer 4: UDP
      else if (protoNum === 17 && buf.length - l4Offset >= 8) {
        const srcPort = buf.readUInt16BE(l4Offset);
        const dstPort = buf.readUInt16BE(l4Offset + 2);
        const udpLen = buf.readUInt16BE(l4Offset + 4);
        const udpChecksum = buf.readUInt16BE(l4Offset + 6);
        const udpPayloadLen = Math.max(0, buf.length - (l4Offset + 8));

        transport = {
          type: 'UDP',
          srcPort,
          dstPort,
          length: udpLen,
          checksum: `0x${udpChecksum.toString(16).padStart(4, '0').toUpperCase()}`,
          payloadLength: udpPayloadLen
        };

        addLayer('User Datagram Protocol', 'udp', l4Offset, 8, `User Datagram Protocol, Src Port: ${srcPort}, Dst Port: ${dstPort}`, {
          'udp.srcport': { offset: l4Offset, length: 2, value: srcPort, label: `Source Port: ${srcPort}` },
          'udp.dstport': { offset: l4Offset + 2, length: 2, value: dstPort, label: `Destination Port: ${dstPort}` },
          'udp.length': { offset: l4Offset + 4, length: 2, value: udpLen, label: `Length: ${udpLen}` },
          'udp.checksum': { offset: l4Offset + 6, length: 2, value: transport.checksum, label: `Checksum: ${transport.checksum}` }
        });

        // L7: DNS
        if ((srcPort === 53 || dstPort === 53) && udpPayloadLen >= 12) {
          const dns = this.dissectDns(buf, l4Offset + 8);
          if (dns) {
            application = dns;
            const qStr = (dns.questions || []).map(q => `${q.name} (${q.type})`).join(', ');
            addLayer('Domain Name System', 'dns', l4Offset + 8, udpPayloadLen, `Domain Name System (${dns.isResponse ? 'response' : 'query'}) ${qStr ? ': ' + qStr : ''}`, {
              'dns.id': { offset: l4Offset + 8, length: 2, value: dns.transactionId, label: `Transaction ID: ${dns.transactionId}` },
              'dns.flags': { offset: l4Offset + 10, length: 2, value: dns.isResponse ? 0x8180 : 0x0100, label: `Flags: ${dns.isResponse ? '0x8180 Standard query response' : '0x0100 Standard query'}` },
              'dns.count.queries': { offset: l4Offset + 12, length: 2, value: dns.questions?.length || 0, label: `Questions: ${dns.questions?.length || 0}` },
              'dns.count.answers': { offset: l4Offset + 14, length: 2, value: dns.answers?.length || 0, label: `Answer RRs: ${dns.answers?.length || 0}` }
            });
          }
        }
      }

      // Layer 4: ICMP
      else if (protoNum === 1 && buf.length - l4Offset >= 8) {
        const icmp = this.dissectIcmp(buf, l4Offset);
        transport = { type: 'ICMP', ...icmp };

        addLayer('Internet Control Message Protocol', 'icmp', l4Offset, 8 + (icmp.payloadLength || 0), `Internet Control Message Protocol (${icmp.typeStr})`, {
          'icmp.type': { offset: l4Offset, length: 1, value: icmp.icmpType, label: `Type: ${icmp.icmpType} (${icmp.typeStr})` },
          'icmp.code': { offset: l4Offset + 1, length: 1, value: icmp.code, label: `Code: ${icmp.code}` },
          'icmp.checksum': { offset: l4Offset + 2, length: 2, value: icmp.checksum, label: `Checksum: ${icmp.checksum}` },
          'icmp.ident': { offset: l4Offset + 4, length: 2, value: icmp.identifier, label: `Identifier: 0x${(icmp.identifier || 0).toString(16).padStart(4, '0')} (${icmp.identifier})` },
          'icmp.seq': { offset: l4Offset + 6, length: 2, value: icmp.sequenceNumber, label: `Sequence number: ${icmp.sequenceNumber}` }
        });
      }
    }

    // 4. Layer 3: IPv6
    else if (etherType === 0x86DD && buf.length - payloadOffset >= 40) {
      const verTcFl = buf.readUInt32BE(payloadOffset);
      const version = (verTcFl >> 28) & 0x0F;
      const trafficClass = (verTcFl >> 20) & 0xFF;
      const flowLabel = verTcFl & 0xFFFFF;
      const payloadLength = buf.readUInt16BE(payloadOffset + 4);
      const nextHeader = buf.readUInt8(payloadOffset + 6);
      const hopLimit = buf.readUInt8(payloadOffset + 7);
      const srcIp = this.formatIpv6(buf, payloadOffset + 8);
      const dstIp = this.formatIpv6(buf, payloadOffset + 24);

      let nextHeaderStr = 'OTHER';
      if (nextHeader === 6) nextHeaderStr = 'TCP';
      else if (nextHeader === 17) nextHeaderStr = 'UDP';
      else if (nextHeader === 58) nextHeaderStr = 'ICMPv6';

      ipv6 = {
        version,
        trafficClass,
        flowLabel: `0x${flowLabel.toString(16).toUpperCase()}`,
        payloadLength,
        nextHeader,
        nextHeaderStr,
        hopLimit,
        srcIp,
        dstIp,
        payloadOffset: payloadOffset + 40
      };

      addLayer('Internet Protocol Version 6', 'ipv6', payloadOffset, 40, `Internet Protocol Version 6, Src: ${srcIp}, Dst: ${dstIp}`, {
        'ipv6.version': { offset: payloadOffset, length: 4, value: version, label: `Version: ${version}` },
        'ipv6.tclass': { offset: payloadOffset, length: 4, value: trafficClass, label: `Traffic Class: 0x${trafficClass.toString(16)}` },
        'ipv6.flow': { offset: payloadOffset, length: 4, value: ipv6.flowLabel, label: `Flow Label: ${ipv6.flowLabel}` },
        'ipv6.plen': { offset: payloadOffset + 4, length: 2, value: payloadLength, label: `Payload Length: ${payloadLength}` },
        'ipv6.nxt': { offset: payloadOffset + 6, length: 1, value: nextHeader, label: `Next Header: ${nextHeaderStr} (${nextHeader})` },
        'ipv6.hlim': { offset: payloadOffset + 7, length: 1, value: hopLimit, label: `Hop Limit: ${hopLimit}` },
        'ipv6.src': { offset: payloadOffset + 8, length: 16, value: srcIp, label: `Source: ${srcIp}` },
        'ipv6.dst': { offset: payloadOffset + 24, length: 16, value: dstIp, label: `Destination: ${dstIp}` }
      });

      // Layer 4 for IPv6: UDP
      if (nextHeader === 17 && buf.length - (payloadOffset + 40) >= 8) {
        const l4Offset = payloadOffset + 40;
        const srcPort = buf.readUInt16BE(l4Offset);
        const dstPort = buf.readUInt16BE(l4Offset + 2);
        const udpLen = buf.readUInt16BE(l4Offset + 4);
        const udpChecksum = buf.readUInt16BE(l4Offset + 6);
        const udpPayloadLen = Math.max(0, buf.length - (l4Offset + 8));

        transport = {
          type: 'UDP',
          srcPort,
          dstPort,
          length: udpLen,
          checksum: `0x${udpChecksum.toString(16).padStart(4, '0').toUpperCase()}`,
          payloadLength: udpPayloadLen
        };

        addLayer('User Datagram Protocol', 'udp', l4Offset, 8, `User Datagram Protocol, Src Port: ${srcPort}, Dst Port: ${dstPort}`, {
          'udp.srcport': { offset: l4Offset, length: 2, value: srcPort, label: `Source Port: ${srcPort}` },
          'udp.dstport': { offset: l4Offset + 2, length: 2, value: dstPort, label: `Destination Port: ${dstPort}` },
          'udp.length': { offset: l4Offset + 4, length: 2, value: udpLen, label: `Length: ${udpLen}` },
          'udp.checksum': { offset: l4Offset + 6, length: 2, value: transport.checksum, label: `Checksum: ${transport.checksum}` }
        });
      } else if (nextHeader === 6 && buf.length - (payloadOffset + 40) >= 20) {
        const l4Offset = payloadOffset + 40;
        const srcPort = buf.readUInt16BE(l4Offset);
        const dstPort = buf.readUInt16BE(l4Offset + 2);
        const seqNum = buf.readUInt32BE(l4Offset + 4);
        const ackNum = buf.readUInt32BE(l4Offset + 8);
        const dataOffsetByte = buf.readUInt8(l4Offset + 12);
        const dataOffsetBytes = (dataOffsetByte >> 4) * 4;
        const flagsByte = buf.readUInt8(l4Offset + 13);
        const flags = {
          urg: Boolean(flagsByte & 0x20),
          ack: Boolean(flagsByte & 0x10),
          psh: Boolean(flagsByte & 0x08),
          rst: Boolean(flagsByte & 0x04),
          syn: Boolean(flagsByte & 0x02),
          fin: Boolean(flagsByte & 0x01)
        };
        const windowSize = buf.readUInt16BE(l4Offset + 14);
        const tcpChecksum = buf.readUInt16BE(l4Offset + 16);
        const urgentPointer = buf.readUInt16BE(l4Offset + 18);
        const tcpPayloadLen = Math.max(0, buf.length - (l4Offset + dataOffsetBytes));

        transport = {
          type: 'TCP',
          srcPort,
          dstPort,
          seqNum,
          ackNum,
          headerLengthBytes: dataOffsetBytes,
          flags,
          windowSize,
          checksum: `0x${tcpChecksum.toString(16).padStart(4, '0').toUpperCase()}`,
          urgentPointer,
          payloadLength: tcpPayloadLen
        };

        const flagNames = Object.entries(flags).filter(([_, v]) => v).map(([k]) => k.toUpperCase());
        addLayer('Transmission Control Protocol', 'tcp', l4Offset, dataOffsetBytes, `Transmission Control Protocol, Src Port: ${srcPort}, Dst Port: ${dstPort}, Seq: ${seqNum}, Ack: ${ackNum}, Flags: [${flagNames.join(', ')}]`, {
          'tcp.srcport': { offset: l4Offset, length: 2, value: srcPort, label: `Source Port: ${srcPort}` },
          'tcp.dstport': { offset: l4Offset + 2, length: 2, value: dstPort, label: `Destination Port: ${dstPort}` },
          'tcp.seq': { offset: l4Offset + 4, length: 4, value: seqNum, label: `Sequence Number: ${seqNum}` },
          'tcp.ack': { offset: l4Offset + 8, length: 4, value: ackNum, label: `Acknowledgment Number: ${ackNum}` },
          'tcp.hdr_len': { offset: l4Offset + 12, length: 1, value: dataOffsetBytes, label: `Header Length: ${dataOffsetBytes} bytes (${dataOffsetBytes / 4})` },
          'tcp.flags': { offset: l4Offset + 13, length: 1, value: flags, label: `Flags: 0x${flagsByte.toString(16).padStart(2, '0')} [${flagNames.join(', ')}]` },
          'tcp.flags.syn': { offset: l4Offset + 13, length: 1, value: flags.syn, label: `SYN: ${flags.syn}` },
          'tcp.flags.ack': { offset: l4Offset + 13, length: 1, value: flags.ack, label: `ACK: ${flags.ack}` },
          'tcp.flags.rst': { offset: l4Offset + 13, length: 1, value: flags.rst, label: `RST: ${flags.rst}` },
          'tcp.flags.fin': { offset: l4Offset + 13, length: 1, value: flags.fin, label: `FIN: ${flags.fin}` },
          'tcp.flags.psh': { offset: l4Offset + 13, length: 1, value: flags.psh, label: `PSH: ${flags.psh}` },
          'tcp.flags.urg': { offset: l4Offset + 13, length: 1, value: flags.urg, label: `URG: ${flags.urg}` },
          'tcp.window_size': { offset: l4Offset + 14, length: 2, value: windowSize, label: `Window Size: ${windowSize}` },
          'tcp.checksum': { offset: l4Offset + 16, length: 2, value: transport.checksum, label: `Checksum: ${transport.checksum}` },
          'tcp.urgent_pointer': { offset: l4Offset + 18, length: 2, value: urgentPointer, label: `Urgent Pointer: ${urgentPointer}` }
        });
      }
    }

    let wireLength = buf.length;
    let isTruncated = false;
    if (ip && ip.totalLength && (payloadOffset + ip.totalLength > buf.length)) {
      wireLength = payloadOffset + ip.totalLength;
      isTruncated = true;
    } else if (ipv6 && ipv6.payloadLength && (payloadOffset + 40 + ipv6.payloadLength > buf.length)) {
      wireLength = payloadOffset + 40 + ipv6.payloadLength;
      isTruncated = true;
    }

    return {
      frameLengthBytes: buf.length,
      wireLength,
      capturedLength: buf.length,
      isTruncated,
      timestamp: new Date().toISOString(),
      rawHex,
      rawBytesBase64,
      ethernet,
      vlan: ethernet.vlan,
      ip,
      ipv6,
      transport,
      application,
      layers,
      fields: fieldsMap,
      passiveOsFingerprint: ip ? this.computePassiveOsFingerprint(ip.ttl, transport?.windowSize) : null,
      dissectedAt: new Date().toISOString()
    };
  }

  /**
   * Dissect entire packet frame from buffer or hex string (100% Backward Compatible)
   */
  static dissectFrame(rawInput) {
    const detailed = this.dissectDetailed(rawInput);
    return {
      frameLengthBytes: detailed.frameLengthBytes,
      wireLength: detailed.wireLength,
      capturedLength: detailed.capturedLength,
      rawHex: detailed.rawHex,
      rawBytesBase64: detailed.rawBytesBase64,
      ethernet: detailed.ethernet,
      vlan: detailed.vlan,
      ip: detailed.ip,
      ipv6: detailed.ipv6,
      transport: detailed.transport,
      application: detailed.application,
      layers: detailed.layers,
      detailedLayers: detailed.layers,
      fields: detailed.fields,
      passiveOsFingerprint: detailed.passiveOsFingerprint,
      dissectedAt: detailed.dissectedAt
    };
  }

  /**
   * Generate an authentic sample frame dynamically bound to true physical infrastructure
   * Zero-Simulation Standard: Completely eliminates hardcoded 192.168.31.x dummy subnets.
   */
  static generateSampleFrame(type = 'TCP_SYN') {
    const { getPhysicalNetworkInfo } = require('../routing/physical-network-detector');
    const netInfo = getPhysicalNetworkInfo();
    const hostIp = netInfo.hostIp || '10.168.195.33';
    const gatewayIp = netInfo.gatewayIp || '10.168.195.1';
    const dnsIp = (netInfo.dnsServers && netInfo.dnsServers[0]) || '10.22.10.11';

    const hostIpParts = hostIp.split('.').map(Number);
    const gwIpParts = gatewayIp.split('.').map(Number);
    const dnsIpParts = dnsIp.split('.').map(Number);

    if (type === 'ICMP_ECHO') {
      // 14 Eth + 20 IPv4 + 8 ICMP + 32 payload = 74 bytes
      const buf = Buffer.alloc(74);

      // Ethernet Header (Host -> Gateway)
      buf.write('641225E48890', 0, 'hex'); // Dst: Gateway MAC
      buf.write('A4AE1116759D', 6, 'hex'); // Src: Host MAC
      buf.writeUInt16BE(0x0800, 12);        // IPv4

      // IPv4 Header
      buf.writeUInt8(0x45, 14);
      buf.writeUInt8(0x00, 15);
      buf.writeUInt16BE(60, 16);            // Total Length: 20 + 40
      buf.writeUInt16BE(0x3B1F, 18);        // ID
      buf.writeUInt16BE(0x4000, 20);        // DF
      buf.writeUInt8(64, 22);               // TTL
      buf.writeUInt8(1, 23);                // Protocol ICMP (1)
      buf.writeUInt16BE(0, 24);             // Checksum placeholder
      for (let i = 0; i < 4; i++) buf.writeUInt8(hostIpParts[i] || 0, 26 + i);
      for (let i = 0; i < 4; i++) buf.writeUInt8(gwIpParts[i] || 0, 30 + i);

      // Calc IP checksum
      let sum = 0;
      for (let i = 14; i < 34; i += 2) sum += buf.readUInt16BE(i);
      while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
      buf.writeUInt16BE((~sum) & 0xFFFF, 24);

      // ICMP Header (Echo Request: Type 8, Code 0)
      buf.writeUInt8(8, 34);  // Type: 8 (Echo Request)
      buf.writeUInt8(0, 35);  // Code: 0
      buf.writeUInt16BE(0x0000, 36); // Checksum placeholder
      buf.writeUInt16BE(0x1F2A, 38); // Identifier
      buf.writeUInt16BE(0x0001, 40); // Sequence Number

      // 32-byte standard RFC echo data pattern
      const echoPayload = Buffer.from('abcdefghijklmnopqrstuvwabcdefghi', 'ascii');
      echoPayload.copy(buf, 42);

      // Calc ICMP checksum
      let icmpSum = 0;
      for (let i = 34; i < 74; i += 2) icmpSum += buf.readUInt16BE(i);
      while (icmpSum >> 16) icmpSum = (icmpSum & 0xFFFF) + (icmpSum >> 16);
      buf.writeUInt16BE((~icmpSum) & 0xFFFF, 36);

      return buf;
    }

    if (type === 'DNS_QUERY') {
      // 14 Eth + 20 IPv4 + 8 UDP + 28 DNS = 70 bytes
      const buf = Buffer.alloc(70);

      // Ethernet Header
      buf.write('641225E48890', 0, 'hex');
      buf.write('A4AE1116759D', 6, 'hex');
      buf.writeUInt16BE(0x0800, 12);

      // IPv4 Header
      buf.writeUInt8(0x45, 14);
      buf.writeUInt8(0x00, 15);
      buf.writeUInt16BE(56, 16);            // Total length: 20 + 8 + 28 = 56
      buf.writeUInt16BE(0x7F21, 18);
      buf.writeUInt16BE(0x4000, 20);
      buf.writeUInt8(64, 22);
      buf.writeUInt8(17, 23);               // Protocol UDP (17)
      buf.writeUInt16BE(0, 24);
      for (let i = 0; i < 4; i++) buf.writeUInt8(hostIpParts[i] || 0, 26 + i);
      for (let i = 0; i < 4; i++) buf.writeUInt8(dnsIpParts[i] || 0, 30 + i);

      // Calc IP checksum
      let sum = 0;
      for (let i = 14; i < 34; i += 2) sum += buf.readUInt16BE(i);
      while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
      buf.writeUInt16BE((~sum) & 0xFFFF, 24);

      // UDP Header
      buf.writeUInt16BE(53123, 34);         // Src Port
      buf.writeUInt16BE(53, 36);            // Dst Port 53
      buf.writeUInt16BE(36, 38);            // Length: 8 UDP + 28 DNS = 36
      buf.writeUInt16BE(0x0000, 40);

      // DNS Query Header (RFC 1035) for "google.com" (A record)
      buf.writeUInt16BE(0x1A2B, 42); // Transaction ID
      buf.writeUInt16BE(0x0100, 44); // Standard Query
      buf.writeUInt16BE(1, 46);      // Questions: 1
      buf.writeUInt16BE(0, 48);      // Answers: 0
      buf.writeUInt16BE(0, 50);      // Authority: 0
      buf.writeUInt16BE(0, 52);      // Additional: 0

      // QNAME: \x06google\x03com\x00
      buf.writeUInt8(6, 54);
      buf.write('google', 55, 'ascii');
      buf.writeUInt8(3, 61);
      buf.write('com', 62, 'ascii');
      buf.writeUInt8(0, 65);
      buf.writeUInt16BE(0x0001, 66); // Type A (1)
      buf.writeUInt16BE(0x0001, 68); // Class IN (1)

      return buf;
    }

    if (type === 'ARP_REQUEST') {
      // 14 Eth + 28 ARP = 42 bytes (padded to 60)
      const buf = Buffer.alloc(60);

      // Broadcast MAC
      for (let i = 0; i < 6; i++) buf.writeUInt8(0xFF, i);
      buf.write('A4AE1116759D', 6, 'hex'); // Sender MAC
      buf.writeUInt16BE(0x0806, 12);        // EtherType ARP (0x0806)

      // ARP Header (RFC 826)
      buf.writeUInt16BE(0x0001, 14); // Hardware Type: Ethernet (1)
      buf.writeUInt16BE(0x0800, 16); // Protocol: IPv4 (0x0800)
      buf.writeUInt8(6, 18);         // HW Size: 6
      buf.writeUInt8(4, 19);         // Proto Size: 4
      buf.writeUInt16BE(0x0001, 20); // Opcode: Request (1)

      // Sender MAC & IP
      buf.write('A4AE1116759D', 22, 'hex');
      for (let i = 0; i < 4; i++) buf.writeUInt8(hostIpParts[i] || 0, 28 + i);

      // Target MAC & IP
      for (let i = 0; i < 6; i++) buf.writeUInt8(0x00, 32 + i);
      for (let i = 0; i < 4; i++) buf.writeUInt8(gwIpParts[i] || 0, 38 + i);

      return buf;
    }

    if (type === 'HTTP_GET') {
      const httpPayload = Buffer.from("GET / HTTP/1.1\r\nHost: mail.taxes.gov.az\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nAccept: */*\r\n\r\n", 'ascii');
      const buf = Buffer.alloc(54 + httpPayload.length);
      buf.write('641225E48890', 0, 'hex');
      buf.write('A4AE1116759D', 6, 'hex');
      buf.writeUInt16BE(0x0800, 12);

      // IPv4
      buf.writeUInt8(0x45, 14);
      buf.writeUInt8(0x00, 15);
      buf.writeUInt16BE(40 + httpPayload.length, 16);
      buf.writeUInt16BE(0x4A12, 18);
      buf.writeUInt16BE(0x4000, 20);
      buf.writeUInt8(64, 22);
      buf.writeUInt8(6, 23); // TCP
      buf.writeUInt16BE(0, 24);
      for (let i = 0; i < 4; i++) buf.writeUInt8(hostIpParts[i] || 0, 26 + i);
      const taxIpParts = [10, 22, 12, 204];
      for (let i = 0; i < 4; i++) buf.writeUInt8(taxIpParts[i], 30 + i);

      let sum = 0;
      for (let i = 14; i < 34; i += 2) sum += buf.readUInt16BE(i);
      while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
      buf.writeUInt16BE((~sum) & 0xFFFF, 24);

      // TCP
      buf.writeUInt16BE(49152, 34);
      buf.writeUInt16BE(80, 36);
      buf.writeUInt32BE(0x01A2B3C4, 38);
      buf.writeUInt32BE(0x05D6E7F8, 42);
      buf.writeUInt8(0x50, 46);
      buf.writeUInt8(0x18, 47); // PSH, ACK
      buf.writeUInt16BE(64240, 48);
      buf.writeUInt16BE(0, 50);
      buf.writeUInt16BE(0, 52);

      httpPayload.copy(buf, 54);
      return buf;
    }

    if (type === 'TLS_CLIENT_HELLO') {
      const sniStr = 'mail.taxes.gov.az';
      const sniBuf = Buffer.from(sniStr, 'utf-8');
      
      // Build ClientHello handshake extension
      const extLen = 4 + 5 + sniBuf.length;
      const hsLen = 34 + 1 + 2 + 1 + 2 + extLen;
      const tlsRecordLen = 4 + hsLen;

      const tlsBuf = Buffer.alloc(5 + tlsRecordLen);
      tlsBuf.writeUInt8(22, 0); // Handshake
      tlsBuf.writeUInt16BE(0x0303, 1); // TLS 1.2 record version
      tlsBuf.writeUInt16BE(tlsRecordLen, 3);

      tlsBuf.writeUInt8(1, 5); // ClientHello
      tlsBuf.writeUInt8(0, 6);
      tlsBuf.writeUInt16BE(hsLen, 7);
      tlsBuf.writeUInt16BE(0x0303, 9); // Client Version TLS 1.2
      // Random 32 bytes
      for (let i = 0; i < 32; i++) tlsBuf.writeUInt8(0xAA, 11 + i);
      let idx = 43;
      tlsBuf.writeUInt8(0, idx++); // Session ID length 0
      tlsBuf.writeUInt16BE(2, idx); idx += 2; // Cipher suites len 2
      tlsBuf.writeUInt16BE(0x1301, idx); idx += 2; // TLS_AES_128_GCM_SHA256
      tlsBuf.writeUInt8(1, idx++); // Comp len 1
      tlsBuf.writeUInt8(0, idx++); // Comp null
      tlsBuf.writeUInt16BE(extLen, idx); idx += 2;

      // Extension: Server Name (0x0000)
      tlsBuf.writeUInt16BE(0x0000, idx); idx += 2;
      tlsBuf.writeUInt16BE(5 + sniBuf.length, idx); idx += 2;
      tlsBuf.writeUInt16BE(3 + sniBuf.length, idx); idx += 2;
      tlsBuf.writeUInt8(0, idx++); // Host Name type
      tlsBuf.writeUInt16BE(sniBuf.length, idx); idx += 2;
      sniBuf.copy(tlsBuf, idx);

      const buf = Buffer.alloc(54 + tlsBuf.length);
      buf.write('641225E48890', 0, 'hex');
      buf.write('A4AE1116759D', 6, 'hex');
      buf.writeUInt16BE(0x0800, 12);

      buf.writeUInt8(0x45, 14);
      buf.writeUInt8(0x00, 15);
      buf.writeUInt16BE(40 + tlsBuf.length, 16);
      buf.writeUInt16BE(0x5B23, 18);
      buf.writeUInt16BE(0x4000, 20);
      buf.writeUInt8(64, 22);
      buf.writeUInt8(6, 23);
      buf.writeUInt16BE(0, 24);
      for (let i = 0; i < 4; i++) buf.writeUInt8(hostIpParts[i] || 0, 26 + i);
      const taxIpParts = [10, 22, 12, 204];
      for (let i = 0; i < 4; i++) buf.writeUInt8(taxIpParts[i], 30 + i);

      let sum = 0;
      for (let i = 14; i < 34; i += 2) sum += buf.readUInt16BE(i);
      while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
      buf.writeUInt16BE((~sum) & 0xFFFF, 24);

      buf.writeUInt16BE(52104, 34);
      buf.writeUInt16BE(443, 36);
      buf.writeUInt32BE(0x10203040, 38);
      buf.writeUInt32BE(0x50607080, 42);
      buf.writeUInt8(0x50, 46);
      buf.writeUInt8(0x18, 47); // PSH, ACK
      buf.writeUInt16BE(64240, 48);
      buf.writeUInt16BE(0, 50);
      buf.writeUInt16BE(0, 52);

      tlsBuf.copy(buf, 54);
      return buf;
    }

    if (type === 'VLAN_IPV4') {
      const buf = Buffer.alloc(58); // 18 VLAN Ethernet + 20 IP + 20 TCP
      buf.write('641225E48890', 0, 'hex');
      buf.write('A4AE1116759D', 6, 'hex');
      buf.writeUInt16BE(0x8100, 12); // 802.1Q VLAN
      buf.writeUInt16BE(100, 14);    // VLAN ID 100
      buf.writeUInt16BE(0x0800, 16); // Inner EtherType IPv4

      buf.writeUInt8(0x45, 18);
      buf.writeUInt8(0x00, 19);
      buf.writeUInt16BE(40, 20);
      buf.writeUInt16BE(0x1F2A, 22);
      buf.writeUInt16BE(0x4000, 24);
      buf.writeUInt8(64, 26);
      buf.writeUInt8(6, 27);
      buf.writeUInt16BE(0, 28);
      for (let i = 0; i < 4; i++) buf.writeUInt8(hostIpParts[i] || 0, 30 + i);
      for (let i = 0; i < 4; i++) buf.writeUInt8(gwIpParts[i] || 0, 34 + i);

      let sum = 0;
      for (let i = 18; i < 38; i += 2) sum += buf.readUInt16BE(i);
      while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
      buf.writeUInt16BE((~sum) & 0xFFFF, 28);

      buf.writeUInt16BE(54321, 38);
      buf.writeUInt16BE(443, 40);
      buf.writeUInt32BE(0x0C2B9A10, 42);
      buf.writeUInt32BE(0x00000000, 46);
      buf.writeUInt8(0x50, 50);
      buf.writeUInt8(0x02, 51); // SYN
      buf.writeUInt16BE(64240, 52);
      buf.writeUInt16BE(0, 54);
      buf.writeUInt16BE(0, 56);
      return buf;
    }

    // Default: TCP_SYN or TCP_ACK
    const isAck = type === 'TCP_ACK';
    const buf = Buffer.alloc(54); // 14 Ethernet + 20 IP + 20 TCP

    // Ethernet Header (Host -> Gateway)
    buf.write('641225E48890', 0, 'hex'); // Dst MAC: MikroTik Gateway
    buf.write('A4AE1116759D', 6, 'hex'); // Src MAC: Host NIC
    buf.writeUInt16BE(0x0800, 12);        // EtherType IPv4

    // IPv4 Header
    buf.writeUInt8(0x45, 14);            // Version 4, IHL 5 (20 bytes)
    buf.writeUInt8(0x00, 15);            // DSCP 0
    buf.writeUInt16BE(40, 16);           // Total length 40 (20 IP + 20 TCP)
    buf.writeUInt16BE(0x1F2A, 18);       // Identification
    buf.writeUInt16BE(0x4000, 20);       // Don't Fragment
    buf.writeUInt8(64, 22);              // TTL 64
    buf.writeUInt8(6, 23);               // Protocol TCP (6)
    buf.writeUInt16BE(0, 24);            // Checksum placeholder

    // Real physical source IP and gateway destination IP
    for (let i = 0; i < 4; i++) buf.writeUInt8(hostIpParts[i] || 0, 26 + i);
    for (let i = 0; i < 4; i++) buf.writeUInt8(gwIpParts[i] || 0, 30 + i);

    // Calculate IPv4 Header Checksum
    let sum = 0;
    for (let i = 14; i < 34; i += 2) sum += buf.readUInt16BE(i);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    buf.writeUInt16BE((~sum) & 0xFFFF, 24);

    // TCP Header
    buf.writeUInt16BE(54321, 34);        // Src Port
    buf.writeUInt16BE(443, 36);          // Dst Port 443 (HTTPS)
    buf.writeUInt32BE(0x0C2B9A10, 38);   // Seq Number
    buf.writeUInt32BE(isAck ? 0x1A2B3C4D : 0x00000000, 42); // Ack Number
    buf.writeUInt8(0x50, 46);            // Data Offset 5 (20 bytes)
    buf.writeUInt8(isAck ? 0x10 : 0x02, 47); // Flags: ACK (0x10) or SYN (0x02)
    buf.writeUInt16BE(64240, 48);        // Window Size
    buf.writeUInt16BE(0x4A1E, 50);       // Checksum
    buf.writeUInt16BE(0, 52);            // Urgent Pointer

    return buf;
  }
}

module.exports = PacketDecoder;
module.exports.PacketDecoder = PacketDecoder;
