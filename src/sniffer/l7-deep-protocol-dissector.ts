// src/sniffer/l7-deep-protocol-dissector.ts
import * as crypto from 'node:crypto';

export interface QuicDissection {
  readonly isQuic: boolean;
  readonly headerForm: 'long' | 'short';
  readonly fixedBit: boolean;
  readonly packetType: 'Initial' | '0-RTT' | 'Handshake' | 'Retry' | '1-RTT-Data' | 'Version-Negotiation' | 'Unknown';
  readonly version: string;
  readonly versionHex: string;
  readonly dcidHex: string;
  readonly scidHex: string;
  readonly packetNumberLength: number;
  readonly spinBit?: boolean;
  readonly keyPhase?: boolean;
  readonly payloadEncrypted?: boolean;
  readonly decryptionStatus?: 'KEYS_UNAVAILABLE' | 'NOT_ENCRYPTED';
  readonly truncatedHeader?: boolean;
}

export interface SshDissection {
  readonly isSsh: boolean;
  readonly banner?: string;
  readonly isKexInit: boolean;
  readonly hasshString?: string;
  readonly hasshMd5?: string;
  readonly hasshSha256?: string;
  readonly kexAlgorithms?: readonly string[];
  readonly encryptionAlgorithms?: readonly string[];
  readonly macAlgorithms?: readonly string[];
  readonly compressionAlgorithms?: readonly string[];
  readonly identityProvenance?: 'UNAUTHENTICATED_BANNER_ADVERTISEMENT' | 'PRE_AUTH_KEX_FINGERPRINT' | 'BINARY_TRANSPORT';
  readonly truncatedKexInit?: boolean;
}

export interface Smb2Dissection {
  readonly isSmb2: boolean;
  readonly commandCode: number;
  readonly commandName: string;
  readonly status: number;
  readonly statusHex: string;
  readonly creditCharge: number;
  readonly messageId: string;
  readonly treeId: number;
  readonly sessionId: string;
  readonly isResponse: boolean;
  readonly lateralMovementSuspected: boolean;
  readonly lateralTargetOrShare?: string;
  readonly lateralMovementAssessment?: 'NONE' | 'ADMINISTRATIVE_SHARE_INDICATOR' | 'REMOTE_EXECUTION_PIPE_INDICATOR';
  readonly evidentiaryNote?: string;
}

export interface Http2FrameInfo {
  readonly length: number;
  readonly typeCode: number;
  readonly typeName: string;
  readonly flags: number;
  readonly streamId: number;
  readonly partialFrame?: boolean;
}

export interface Http2Dissection {
  readonly isHttp2: boolean;
  readonly hasConnectionPreface: boolean;
  readonly frames: readonly Http2FrameInfo[];
  readonly truncatedStream?: boolean;
}

export interface L7DeepDissectionResult {
  readonly quic?: QuicDissection;
  readonly ssh?: SshDissection;
  readonly smb2?: Smb2Dissection;
  readonly http2?: Http2Dissection;
  readonly identifiedProtocol?: 'QUIC' | 'SSH' | 'SMB2/3' | 'HTTP/2';
  readonly protocol?: string;
  readonly confidence?: number;
}

const HTTP2_CLIENT_PREFACE = Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n', 'ascii');
const SMB2_MAGIC = [0xfe, 0x53, 0x4d, 0x42]; // 0xFE 'S' 'M' 'B'

const SMB2_COMMAND_NAMES: Record<number, string> = {
  0x0000: 'NEGOTIATE',
  0x0001: 'SESSION_SETUP',
  0x0002: 'LOGOFF',
  0x0003: 'TREE_CONNECT',
  0x0004: 'TREE_DISCONNECT',
  0x0005: 'CREATE',
  0x0006: 'CLOSE',
  0x0007: 'FLUSH',
  0x0008: 'READ',
  0x0009: 'WRITE',
  0x000a: 'LOCK',
  0x000b: 'IOCTL',
  0x000c: 'CANCEL',
  0x000d: 'ECHO',
  0x000e: 'QUERY_DIRECTORY',
  0x000f: 'CHANGE_NOTIFY',
  0x0010: 'QUERY_INFO',
  0x0011: 'SET_INFO',
  0x0012: 'OPLOCK_BREAK'
};

const HTTP2_FRAME_TYPES: Record<number, string> = {
  0x0: 'DATA',
  0x1: 'HEADERS',
  0x2: 'PRIORITY',
  0x3: 'RST_STREAM',
  0x4: 'SETTINGS',
  0x5: 'PUSH_PROMISE',
  0x6: 'PING',
  0x7: 'GOAWAY',
  0x8: 'WINDOW_UPDATE',
  0x9: 'CONTINUATION'
};

export class L7DeepProtocolDissector {
  private static isValidSlice(rawBuffer: Uint8Array | null | undefined, offset: number, length: number, minLen: number): boolean {
    if (!rawBuffer || !(rawBuffer instanceof Uint8Array)) return false;
    if (!Number.isInteger(offset) || !Number.isInteger(length)) return false;
    if (offset < 0 || length < minLen) return false;
    if (offset + length > rawBuffer.byteLength) return false;
    return true;
  }

  /**
   * Dissects QUIC wire packets (RFC 9000 / RFC 9369)
   */
  public static dissectQuicPacket(
    rawBuffer: Uint8Array,
    offset = 0,
    length = rawBuffer ? rawBuffer.byteLength - offset : 0
  ): QuicDissection | null {
    if (!this.isValidSlice(rawBuffer, offset, length, 6)) return null;

    const view = new DataView(rawBuffer.buffer, rawBuffer.byteOffset + offset, length);
    const firstByte = view.getUint8(0);
    const isLongHeader = (firstByte & 0x80) !== 0;
    const fixedBit = (firstByte & 0x40) !== 0;

    if (!fixedBit && !isLongHeader) {
      // Not a valid QUIC header format per RFC 9000
      return null;
    }

    if (!isLongHeader && ((firstByte & 0x18) !== 0 || !fixedBit)) {
      // RFC 9000 Section 17.3.1: Reserved bits (0x18) MUST be 0 in short header
      return null;
    }

    if (isLongHeader) {
      if (length < 7) return null;
      const typeBits = (firstByte & 0x30) >> 4;
      const versionInt = view.getUint32(1, false);
      const versionHex = '0x' + versionInt.toString(16).padStart(8, '0');

      let versionStr = 'Unknown';
      if (versionInt === 0x00000000) versionStr = 'Version Negotiation';
      else if (versionInt === 0x00000001) versionStr = 'QUIC v1 (RFC 9000)';
      else if (versionInt === 0x6b3343cf) versionStr = 'QUIC v2 (RFC 9369)';
      else if ((versionInt & 0x0f0f0f0f) === 0x0a0a0a0a) versionStr = 'Draft / GREASE';
      else versionStr = `QUIC ${versionHex}`;

      let packetType: QuicDissection['packetType'] = 'Unknown';
      if (versionInt === 0x00000000) {
        packetType = 'Version-Negotiation';
      } else {
        switch (typeBits) {
          case 0x00: packetType = 'Initial'; break;
          case 0x01: packetType = '0-RTT'; break;
          case 0x02: packetType = 'Handshake'; break;
          case 0x03: packetType = 'Retry'; break;
        }
      }

      const dcidLen = view.getUint8(5);
      // RFC 9000 Section 17.2: In QUIC v1/v2, CID length MUST NOT exceed 20 bytes
      if ((versionInt === 0x00000001 || versionInt === 0x6b3343cf) && dcidLen > 20) {
        return null;
      }
      if (length < 6 + dcidLen + 1) return null;

      let dcidHex = '';
      for (let i = 0; i < dcidLen; i++) {
        dcidHex += view.getUint8(6 + i).toString(16).padStart(2, '0');
      }

      const scidOffset = 6 + dcidLen;
      const scidLen = view.getUint8(scidOffset);
      if ((versionInt === 0x00000001 || versionInt === 0x6b3343cf) && scidLen > 20) {
        return null;
      }
      let scidHex = '';
      let truncatedHeader = false;
      if (length >= scidOffset + 1 + scidLen) {
        for (let i = 0; i < scidLen; i++) {
          scidHex += view.getUint8(scidOffset + 1 + i).toString(16).padStart(2, '0');
        }
      } else {
        truncatedHeader = true;
      }

      const packetNumberLength = (firstByte & 0x03) + 1;
      const isVersionNeg = packetType === 'Version-Negotiation';

      return {
        isQuic: true,
        headerForm: 'long',
        fixedBit,
        packetType,
        version: versionStr,
        versionHex,
        dcidHex,
        scidHex,
        packetNumberLength,
        payloadEncrypted: !isVersionNeg,
        decryptionStatus: isVersionNeg ? 'NOT_ENCRYPTED' : 'KEYS_UNAVAILABLE',
        truncatedHeader
      };
    } else {
      // Short Header (1-RTT Data)
      const spinBit = (firstByte & 0x20) !== 0;
      const keyPhase = (firstByte & 0x04) !== 0;
      const packetNumberLength = (firstByte & 0x03) + 1;

      // In short header, DCID is connection-context dependent; extract first 8 bytes if available
      let dcidHex = '';
      const sampleLen = Math.min(8, length - 1);
      for (let i = 0; i < sampleLen; i++) {
        dcidHex += view.getUint8(1 + i).toString(16).padStart(2, '0');
      }

      return {
        isQuic: true,
        headerForm: 'short',
        fixedBit,
        packetType: '1-RTT-Data',
        version: 'QUIC 1-RTT',
        versionHex: '0x00000001',
        dcidHex,
        scidHex: '',
        packetNumberLength,
        spinBit,
        keyPhase,
        payloadEncrypted: true,
        decryptionStatus: 'KEYS_UNAVAILABLE',
        truncatedHeader: false
      };
    }
  }

  /**
   * Dissects SSHv2 (RFC 4253) identification banner and SSH_MSG_KEXINIT HASSH fingerprinter
   */
  public static dissectSshPacket(
    rawBuffer: Uint8Array,
    offset = 0,
    length = rawBuffer ? rawBuffer.byteLength - offset : 0
  ): SshDissection | null {
    if (!this.isValidSlice(rawBuffer, offset, length, 4)) return null;

    const slice = Buffer.from(rawBuffer.buffer, rawBuffer.byteOffset + offset, length);
    const asciiPrefix = slice.subarray(0, Math.min(8, length)).toString('ascii');

    // 1. Check for SSH-2.0 banner identification string
    if (asciiPrefix.startsWith('SSH-2.0-') || asciiPrefix.startsWith('SSH-1.99-')) {
      const lineEnd = slice.indexOf('\n');
      const banner = (lineEnd !== -1 ? slice.subarray(0, lineEnd) : slice).toString('utf8').replace(/\r$/, '');
      return {
        isSsh: true,
        banner,
        isKexInit: false,
        identityProvenance: 'UNAUTHENTICATED_BANNER_ADVERTISEMENT'
      };
    }

    // 2. Binary SSH packet parsing
    if (length < 6) return null;
    const view = new DataView(rawBuffer.buffer, rawBuffer.byteOffset + offset, length);
    const packetLength = view.getUint32(0, false);
    const paddingLength = view.getUint8(4);

    if (packetLength < 2 || packetLength > 65536 || paddingLength >= packetLength) {
      return null;
    }

    const msgCode = view.getUint8(5);
    // 20 = 0x14 = SSH_MSG_KEXINIT
    if (msgCode !== 20) {
      return {
        isSsh: true,
        isKexInit: false,
        identityProvenance: 'BINARY_TRANSPORT'
      };
    }

    // Parse SSH_MSG_KEXINIT
    // 16 bytes cookie starting at offset 6
    if (length < 22) {
      return {
        isSsh: true,
        isKexInit: true,
        truncatedKexInit: true,
        identityProvenance: 'PRE_AUTH_KEX_FINGERPRINT'
      };
    }
    let cur = 6 + 16;
    let truncatedKexInit = false;
    const readNameList = (): string[] => {
      if (cur + 4 > length) {
        truncatedKexInit = true;
        return [];
      }
      const strLen = view.getUint32(cur, false);
      cur += 4;
      if (cur + strLen > length || strLen > 4096) {
        truncatedKexInit = true;
        return [];
      }
      const str = slice.subarray(cur, cur + strLen).toString('ascii');
      cur += strLen;
      return str.split(',').filter(Boolean);
    };

    const kexAlgos = readNameList();
    /* server_host_key_algorithms */ readNameList();
    const encClientServer = readNameList();
    /* enc_server_client */ readNameList();
    const macClientServer = readNameList();
    /* mac_server_client */ readNameList();
    const compClientServer = readNameList();

    const hasshString = `${kexAlgos.join(',')};${encClientServer.join(',')};${macClientServer.join(',')};${compClientServer.join(',')}`;
    const hasshMd5 = crypto.createHash('md5').update(hasshString).digest('hex');
    const hasshSha256 = crypto.createHash('sha256').update(hasshString).digest('hex');

    return {
      isSsh: true,
      isKexInit: true,
      hasshString,
      hasshMd5,
      hasshSha256,
      kexAlgorithms: kexAlgos,
      encryptionAlgorithms: encClientServer,
      macAlgorithms: macClientServer,
      compressionAlgorithms: compClientServer,
      identityProvenance: 'PRE_AUTH_KEX_FINGERPRINT',
      truncatedKexInit
    };
  }

  /**
   * Dissects SMBv2/v3 header and flags lateral movement signatures
   */
  public static dissectSmb2Packet(
    rawBuffer: Uint8Array,
    offset = 0,
    length = rawBuffer ? rawBuffer.byteLength - offset : 0
  ): Smb2Dissection | null {
    if (!this.isValidSlice(rawBuffer, offset, length, 64)) return null;

    // Check magic 0xFE 'S' 'M' 'B'
    if (
      rawBuffer[offset] !== SMB2_MAGIC[0] ||
      rawBuffer[offset + 1] !== SMB2_MAGIC[1] ||
      rawBuffer[offset + 2] !== SMB2_MAGIC[2] ||
      rawBuffer[offset + 3] !== SMB2_MAGIC[3]
    ) {
      return null;
    }

    const view = new DataView(rawBuffer.buffer, rawBuffer.byteOffset + offset, length);
    const structureSize = view.getUint16(4, true);
    if (structureSize !== 64) return null;

    const creditCharge = view.getUint16(6, true);
    const status = view.getUint32(8, true);
    const commandCode = view.getUint16(12, true);
    const flags = view.getUint32(16, true);
    const isResponse = (flags & 0x00000001) !== 0;

    const messageId = view.getBigUint64(24, true).toString();
    const treeId = view.getUint32(36, true);
    const sessionId = view.getBigUint64(40, true).toString(16).padStart(16, '0');

    const commandName = SMB2_COMMAND_NAMES[commandCode] || `SMB2_CMD_0x${commandCode.toString(16)}`;

    // Inspect lateral movement indicators (IPC$, ADMIN$, C$, or named pipes)
    let lateralMovementSuspected = false;
    let lateralTargetOrShare: string | undefined;
    let lateralMovementAssessment: Smb2Dissection['lateralMovementAssessment'] = 'NONE';

    // Look for ASCII / UTF-16 strings in payload past the 64-byte header
    if (length > 68) {
      const payloadSlice = Buffer.from(rawBuffer.buffer, rawBuffer.byteOffset + offset + 64, length - 64);
      const textUtf8 = payloadSlice.toString('utf8');
      const textUtf16 = payloadSlice.toString('utf16le');
      const combined = (textUtf8 + ' ' + textUtf16).toUpperCase();

      if (combined.includes('ADMIN$') || combined.includes('C$') || combined.includes('IPC$') || combined.includes('D$')) {
        lateralMovementSuspected = true;
        lateralMovementAssessment = 'ADMINISTRATIVE_SHARE_INDICATOR';
        if (combined.includes('ADMIN$')) lateralTargetOrShare = 'ADMIN$';
        else if (combined.includes('C$')) lateralTargetOrShare = 'C$';
        else if (combined.includes('IPC$')) lateralTargetOrShare = 'IPC$';
      }

      if (combined.includes('PSEXEC') || combined.includes('SVCCTL') || combined.includes('ATSVC') || combined.includes('SAMR')) {
        lateralMovementSuspected = true;
        lateralMovementAssessment = 'REMOTE_EXECUTION_PIPE_INDICATOR';
        lateralTargetOrShare = lateralTargetOrShare ? `${lateralTargetOrShare}+PIPE` : 'NAMED_PIPE';
      }
    }

    return {
      isSmb2: true,
      commandCode,
      commandName,
      status,
      statusHex: '0x' + status.toString(16).padStart(8, '0'),
      creditCharge,
      messageId,
      treeId,
      sessionId,
      isResponse,
      lateralMovementSuspected,
      lateralTargetOrShare,
      lateralMovementAssessment,
      evidentiaryNote: lateralMovementSuspected
        ? 'SMB share/pipe indicator observed in wire payload; requires correlation with host authentication and authorization policy before confirming unauthorized lateral movement.'
        : 'Standard SMB2/3 protocol header observed.'
    };
  }

  /**
   * Dissects HTTP/2 (RFC 9113) connection preface and 9-byte frame headers
   */
  public static dissectHttp2Frame(
    rawBuffer: Uint8Array,
    offset = 0,
    length = rawBuffer ? rawBuffer.byteLength - offset : 0
  ): Http2Dissection | null {
    if (!this.isValidSlice(rawBuffer, offset, length, 9)) return null;

    const slice = Buffer.from(rawBuffer.buffer, rawBuffer.byteOffset + offset, length);
    let cur = 0;
    let hasConnectionPreface = false;

    // Check for HTTP/2 Client Preface
    if (length >= 24 && slice.subarray(0, 24).equals(HTTP2_CLIENT_PREFACE)) {
      hasConnectionPreface = true;
      cur = 24;
    }

    const frames: Http2FrameInfo[] = [];
    const view = new DataView(rawBuffer.buffer, rawBuffer.byteOffset + offset, length);
    let truncatedStream = false;

    // Parse up to 16 HTTP/2 frames in the slice
    while (cur + 9 <= length && frames.length < 16) {
      const b0 = view.getUint8(cur);
      const b1 = view.getUint8(cur + 1);
      const b2 = view.getUint8(cur + 2);
      const frameLength = (b0 << 16) | (b1 << 8) | b2;

      const typeCode = view.getUint8(cur + 3);
      const flags = view.getUint8(cur + 4);
      const streamId = view.getUint32(cur + 5, false) & 0x7fffffff;

      const typeName = HTTP2_FRAME_TYPES[typeCode];

      // Without preface, frames must strictly adhere to known HTTP/2 types and bounds
      if (!hasConnectionPreface) {
        if (!typeName || frameLength > 16384) {
          return null;
        }
        // SETTINGS / PING / GOAWAY must be on stream 0
        if ((typeCode === 0x4 || typeCode === 0x6 || typeCode === 0x7) && streamId !== 0) {
          return null;
        }
        if (typeCode === 0x4 && frameLength % 6 !== 0) {
          return null;
        }
      }

      const partialFrame = (cur + 9 + frameLength) > length;
      if (partialFrame) {
        truncatedStream = true;
      }

      frames.push({
        length: frameLength,
        typeCode,
        typeName: typeName || `FRAME_0x${typeCode.toString(16)}`,
        flags,
        streamId,
        partialFrame
      });

      // Advance to next frame header
      cur += 9 + frameLength;
    }

    if (!hasConnectionPreface && frames.length === 0) {
      return null;
    }

    return {
      isHttp2: true,
      hasConnectionPreface,
      frames,
      truncatedStream
    };
  }

  /**
   * Universal L7 protocol detector and dissector
   */
  public static dissect(
    rawBuffer: Uint8Array,
    offset = 0,
    length = rawBuffer ? rawBuffer.byteLength - offset : 0
  ): L7DeepDissectionResult {
    if (!this.isValidSlice(rawBuffer, offset, length, 4)) {
      return { protocol: 'Unknown', confidence: 0.0 };
    }

    // Try SMB2 (magic 0xFE 'S' 'M' 'B')
    const smb2 = this.dissectSmb2Packet(rawBuffer, offset, length);
    if (smb2) {
      return { smb2, identifiedProtocol: 'SMB2/3', protocol: 'SMB2/3', confidence: 1.0 };
    }

    // Try SSH (SSH-2.0- banner or KEXINIT)
    const ssh = this.dissectSshPacket(rawBuffer, offset, length);
    if (ssh) {
      return { ssh, identifiedProtocol: 'SSH', protocol: 'SSH', confidence: 1.0 };
    }

    // Try HTTP/2 (preface or frames)
    const http2 = this.dissectHttp2Frame(rawBuffer, offset, length);
    if (http2) {
      return { http2, identifiedProtocol: 'HTTP/2', protocol: 'HTTP/2', confidence: 1.0 };
    }

    // Try QUIC
    const quic = this.dissectQuicPacket(rawBuffer, offset, length);
    if (quic) {
      return { quic, identifiedProtocol: 'QUIC', protocol: 'QUIC', confidence: 1.0 };
    }

    return { protocol: 'Unknown', confidence: 0.0 };
  }

  /**
   * Instance-level convenience wrapper for dissecting payloads
   */
  public dissectPayload(
    rawBuffer: Uint8Array,
    sport?: number,
    dport?: number,
    offset = 0,
    length = rawBuffer ? rawBuffer.byteLength - offset : 0
  ): L7DeepDissectionResult {
    return L7DeepProtocolDissector.dissect(rawBuffer, offset, length);
  }
}
