// src/sniffer/wire-dissector-apex.ts
import * as crypto from 'node:crypto';

export interface ByteSpan {
  readonly field: string;
  readonly offset: number;
  readonly length: number;
  readonly value: string;
}

export interface TLSClientHelloDissection {
  readonly recordVersion: string;
  readonly handshakeVersion: string;
  readonly negotiatedTlsVersion: string;
  readonly sniHostName: string | null;
  readonly alpnProtocols: readonly string[];
  readonly cipherSuitesHex: readonly string[];
  readonly extensionsHex: readonly string[];
  readonly ja4Fingerprint: string;
  readonly byteSpans: readonly ByteSpan[];
}

export interface DNSWireDissection {
  readonly transactionId: number;
  readonly isResponse: boolean;
  readonly rcode: number;
  readonly questions: readonly string[];
  readonly shannonEntropyBitsPerChar: number;
  readonly dgaOrTunnelSuspected: boolean;
  readonly pointerCompressionJumps: number;
  readonly byteSpans: readonly ByteSpan[];
}

// RFC 8701 GREASE table bitmask check: (val & 0x0f0f) === 0x0a0a and high byte === low byte
function isGreaseValue(val: number): boolean {
  return ((val & 0x0f0f) === 0x0a0a) && (((val >> 8) & 0xff) === (val & 0xff));
}

export class WireDissectorApex {
  /**
   * Dissects a TLS Record containing a ClientHello directly from a raw TCP payload buffer
   * using zero-copy DataView offsets and computes the JA4 Fingerprint.
   */
  public static dissectTLSClientHello(
    frameBuffer: Uint8Array,
    tcpPayloadOffset: number,
    tcpPayloadLength: number
  ): TLSClientHelloDissection | null {
    if (tcpPayloadLength < 43 || tcpPayloadOffset < 0 || tcpPayloadOffset + tcpPayloadLength > frameBuffer.byteLength) {
      return null;
    }

    const view = new DataView(
      frameBuffer.buffer,
      frameBuffer.byteOffset + tcpPayloadOffset,
      tcpPayloadLength
    );
    const spans: ByteSpan[] = [];

    // ContentType 0x16 = Handshake
    const contentType = view.getUint8(0);
    if (contentType !== 0x16) return null;

    const recordVer = view.getUint16(1, false);
    const recordLen = view.getUint16(3, false);
    spans.push({
      field: 'tls.record.content_type',
      offset: tcpPayloadOffset,
      length: 1,
      value: '0x16 (Handshake)',
    });
    spans.push({
      field: 'tls.record.length',
      offset: tcpPayloadOffset + 3,
      length: 2,
      value: String(recordLen),
    });

    // HandshakeType 0x01 = ClientHello
    if (tcpPayloadLength < 6) return null;
    const handshakeType = view.getUint8(5);
    if (handshakeType !== 0x01) return null;

    if (tcpPayloadLength < 11) return null;
    const clientVersion = view.getUint16(9, false);
    spans.push({
      field: 'tls.handshake.version',
      offset: tcpPayloadOffset + 9,
      length: 2,
      value: `0x${clientVersion.toString(16).padStart(4, '0')}`,
    });

    // Skip 32-byte Random (offset 11..43)
    let cursor = 43;
    if (cursor >= tcpPayloadLength) return null;

    // Session ID
    const sessionIdLen = view.getUint8(cursor);
    cursor += 1 + sessionIdLen;
    if (cursor + 2 > tcpPayloadLength) return null;

    // Cipher Suites
    const cipherSuitesByteLen = view.getUint16(cursor, false);
    spans.push({
      field: 'tls.handshake.ciphersuites_len',
      offset: tcpPayloadOffset + cursor,
      length: 2,
      value: String(cipherSuitesByteLen),
    });
    cursor += 2;
    if (cursor + cipherSuitesByteLen > tcpPayloadLength) return null;

    const cipherSuites: string[] = [];
    for (let i = 0; i < cipherSuitesByteLen; i += 2) {
      const cs = view.getUint16(cursor + i, false);
      if (!isGreaseValue(cs)) {
        cipherSuites.push(cs.toString(16).padStart(4, '0'));
      }
    }
    cursor += cipherSuitesByteLen;
    if (cursor + 1 > tcpPayloadLength) return null;

    // Compression Methods
    const compMethodsLen = view.getUint8(cursor);
    cursor += 1 + compMethodsLen;
    if (cursor + 2 > tcpPayloadLength) return null;

    // Extensions
    const extensionsTotalLen = view.getUint16(cursor, false);
    cursor += 2;
    const extensionsEnd = Math.min(tcpPayloadLength, cursor + extensionsTotalLen);

    const extensions: string[] = [];
    const signatureAlgs: string[] = [];
    const alpnList: string[] = [];
    let sniHostName: string | null = null;
    let highestSupportedVer = clientVersion;

    while (cursor + 4 <= extensionsEnd) {
      const extType = view.getUint16(cursor, false);
      const extLen = view.getUint16(cursor + 2, false);
      const extDataStart = cursor + 4;
      if (extDataStart + extLen > extensionsEnd) break;

      if (!isGreaseValue(extType)) {
        extensions.push(extType.toString(16).padStart(4, '0'));
      }

      // Extension 0x0000: Server Name Indication (SNI)
      if (extType === 0x0000 && extLen >= 5) {
        const nameType = view.getUint8(extDataStart + 2);
        const nameLen = view.getUint16(extDataStart + 3, false);
        if (nameType === 0 && extDataStart + 5 + nameLen <= extensionsEnd) {
          const nameBytes = frameBuffer.subarray(
            tcpPayloadOffset + extDataStart + 5,
            tcpPayloadOffset + extDataStart + 5 + nameLen
          );
          sniHostName = new TextDecoder('utf-8', { fatal: false }).decode(nameBytes);
          spans.push({
            field: 'tls.handshake.extensions_server_name',
            offset: tcpPayloadOffset + extDataStart + 5,
            length: nameLen,
            value: sniHostName,
          });
        }
      }
      // Extension 0x0010: ALPN
      else if (extType === 0x0010 && extLen >= 3) {
        let alpnCursor = extDataStart + 2;
        const alpnEnd = extDataStart + extLen;
        while (alpnCursor < alpnEnd) {
          const protoLen = view.getUint8(alpnCursor);
          alpnCursor += 1;
          if (alpnCursor + protoLen <= alpnEnd) {
            const protoBytes = frameBuffer.subarray(
              tcpPayloadOffset + alpnCursor,
              tcpPayloadOffset + alpnCursor + protoLen
            );
            alpnList.push(new TextDecoder().decode(protoBytes));
          }
          alpnCursor += protoLen;
        }
      }
      // Extension 0x002b: Supported Versions (TLS 1.3 detection)
      else if (extType === 0x002b && extLen >= 3) {
        const listLen = view.getUint8(extDataStart);
        for (let i = 0; i + 1 < listLen && extDataStart + 1 + i + 2 <= extensionsEnd; i += 2) {
          const v = view.getUint16(extDataStart + 1 + i, false);
          if (!isGreaseValue(v) && v > highestSupportedVer) {
            highestSupportedVer = v;
          }
        }
      }
      // Extension 0x000d: Signature Algorithms
      else if (extType === 0x000d && extLen >= 2) {
        const sigLen = view.getUint16(extDataStart, false);
        for (let i = 0; i + 1 < sigLen && extDataStart + 2 + i + 2 <= extensionsEnd; i += 2) {
          const sig = view.getUint16(extDataStart + 2 + i, false);
          if (!isGreaseValue(sig)) {
            signatureAlgs.push(sig.toString(16).padStart(4, '0'));
          }
        }
      }

      cursor = extDataStart + extLen;
    }

    const verMap: Record<number, string> = {
      0x0304: '13',
      0x0303: '12',
      0x0302: '11',
      0x0301: '10',
    };
    const ja4Ver = verMap[highestSupportedVer] ?? '00';
    const sniIndicator = sniHostName ? 'd' : 'i';
    const cipherCount = Math.min(99, cipherSuites.length).toString().padStart(2, '0');
    const extCount = Math.min(99, extensions.length).toString().padStart(2, '0');
    const firstAlpn = alpnList[0] ?? '00';
    const alpnCode = firstAlpn.length >= 2
      ? `${firstAlpn[0]}${firstAlpn[firstAlpn.length - 1]}`
      : '00';

    const ja4_a = `t${ja4Ver}${sniIndicator}${cipherCount}${extCount}${alpnCode}`;
    const sortedCiphers = [...cipherSuites].sort().join(',');
    const ja4_b = sortedCiphers
      ? crypto.createHash('sha256').update(sortedCiphers).digest('hex').slice(0, 12)
      : '000000000000';

    // JA4_c excludes SNI (0000) and ALPN (0010) before sorting
    const filteredExts = extensions.filter((e) => e !== '0000' && e !== '0010').sort();
    const extPayload = signatureAlgs.length > 0
      ? `${filteredExts.join(',')}_${signatureAlgs.join(',')}`
      : filteredExts.join(',');
    const ja4_c = extPayload
      ? crypto.createHash('sha256').update(extPayload).digest('hex').slice(0, 12)
      : '000000000000';

    const ja4Fingerprint = `${ja4_a}_${ja4_b}_${ja4_c}`;

    return {
      recordVersion: `0x${recordVer.toString(16).padStart(4, '0')}`,
      handshakeVersion: `0x${clientVersion.toString(16).padStart(4, '0')}`,
      negotiatedTlsVersion: highestSupportedVer === 0x0304 ? 'TLS 1.3 (RFC 8446)' : 'TLS 1.2',
      sniHostName,
      alpnProtocols: alpnList,
      cipherSuitesHex: cipherSuites,
      extensionsHex: extensions,
      ja4Fingerprint,
      byteSpans: spans,
    };
  }

  /**
   * Hardened RFC 1035 DNS Wire Dissector with cyclic compression pointer guard
   * and Shannon Entropy DGA / DNS-Tunneling detection.
   */
  public static dissectDNSFrame(
    frameBuffer: Uint8Array,
    udpPayloadOffset: number,
    udpPayloadLength: number
  ): DNSWireDissection | null {
    if (udpPayloadLength < 12 || udpPayloadOffset < 0 || udpPayloadOffset + udpPayloadLength > frameBuffer.byteLength) {
      return null;
    }

    const view = new DataView(
      frameBuffer.buffer,
      frameBuffer.byteOffset + udpPayloadOffset,
      udpPayloadLength
    );
    const spans: ByteSpan[] = [];

    const txId = view.getUint16(0, false);
    const flags = view.getUint16(2, false);
    const qdCount = Math.min(32, view.getUint16(4, false));

    const isResponse = (flags & 0x8000) !== 0;
    const rcode = flags & 0x000f;

    spans.push({
      field: 'dns.id',
      offset: udpPayloadOffset,
      length: 2,
      value: `0x${txId.toString(16).padStart(4, '0')}`,
    });

    let cursor = 12;
    let totalPointerJumps = 0;
    const questions: string[] = [];

    for (let q = 0; q < qdCount && cursor < udpPayloadLength; q++) {
      const startOffset = cursor;
      const decoded = this.readDnsNameBounded(frameBuffer, udpPayloadOffset, udpPayloadLength, cursor);
      if (!decoded) break;

      totalPointerJumps += decoded.pointerJumps;
      if (decoded.name.length > 0) {
        questions.push(decoded.name);
        spans.push({
          field: 'dns.qry.name',
          offset: udpPayloadOffset + startOffset,
          length: Math.max(1, decoded.nextCursor - startOffset),
          value: decoded.name,
        });
      }
      cursor = decoded.nextCursor + 4; // Skip QTYPE (2) + QCLASS (2)
    }

    const primaryQuery = questions[0] ?? '';
    const leftmostLabel = primaryQuery.split('.')[0] ?? '';
    const entropy = this.computeStringShannonEntropy(leftmostLabel);
    const dgaOrTunnelSuspected =
      (leftmostLabel.length >= 14 && entropy >= 3.75) || leftmostLabel.length > 42;

    return {
      transactionId: txId,
      isResponse,
      rcode,
      questions,
      shannonEntropyBitsPerChar: Number(entropy.toFixed(3)),
      dgaOrTunnelSuspected,
      pointerCompressionJumps: totalPointerJumps,
      byteSpans: spans,
    };
  }

  /**
   * Decodes RFC 1035 compressed domain names with a strict cycle-detection barrier (max 16 jumps).
   */
  private static readDnsNameBounded(
    frameBuffer: Uint8Array,
    baseOffset: number,
    maxLen: number,
    initialCursor: number
  ): { name: string; nextCursor: number; pointerJumps: number } | null {
    const labels: string[] = [];
    let pos = initialCursor;
    let nextCursor = initialCursor;
    let jumped = false;
    let jumps = 0;
    const MAX_JUMPS = 16;
    const visitedOffsets = new Set<number>();

    while (pos < maxLen) {
      if (visitedOffsets.has(pos)) {
        // Direct cycle loop detection
        return null;
      }
      visitedOffsets.add(pos);

      const lenByte = frameBuffer[baseOffset + pos];
      if (lenByte === 0) {
        if (!jumped) nextCursor = pos + 1;
        break;
      }

      // Compression pointer (top 2 bits = 11 -> 0xC0)
      if ((lenByte & 0xc0) === 0xc0) {
        if (pos + 1 >= maxLen) return null;
        if (!jumped) nextCursor = pos + 2;
        jumped = true;
        jumps += 1;
        if (jumps > MAX_JUMPS) {
          // Malformed cyclic DNS pointer compression attack detected and neutralized
          return null;
        }
        const pointerOffset = ((lenByte & 0x3f) << 8) | frameBuffer[baseOffset + pos + 1];
        if (pointerOffset >= maxLen || pointerOffset === pos) return null;
        pos = pointerOffset;
        continue;
      }

      // Standard label (max 63 octets per RFC 1035)
      const labelLen = lenByte & 0x3f;
      pos += 1;
      if (pos + labelLen > maxLen) return null;

      const labelSlice = frameBuffer.subarray(baseOffset + pos, baseOffset + pos + labelLen);
      labels.push(new TextDecoder().decode(labelSlice));
      pos += labelLen;
      if (!jumped) nextCursor = pos;
    }

    return {
      name: labels.join('.'),
      nextCursor,
      pointerJumps: jumps,
    };
  }

  private static computeStringShannonEntropy(str: string): number {
    if (str.length <= 1) return 0;
    const counts = new Map<number, number>();
    for (let i = 0; i < str.length; i++) {
      const code = str.charCodeAt(i);
      counts.set(code, (counts.get(code) ?? 0) + 1);
    }
    let entropy = 0.0;
    const len = str.length;
    for (const c of counts.values()) {
      const p = c / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }
}
