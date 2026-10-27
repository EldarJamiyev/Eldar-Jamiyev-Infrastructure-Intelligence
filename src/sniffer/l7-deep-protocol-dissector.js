"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.L7DeepProtocolDissector = void 0;
// src/sniffer/l7-deep-protocol-dissector.ts
const crypto = __importStar(require("node:crypto"));
const HTTP2_CLIENT_PREFACE = Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n', 'ascii');
const SMB2_MAGIC = [0xfe, 0x53, 0x4d, 0x42]; // 0xFE 'S' 'M' 'B'
const SMB2_COMMAND_NAMES = {
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
const HTTP2_FRAME_TYPES = {
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
class L7DeepProtocolDissector {
    /**
     * Dissects QUIC wire packets (RFC 9000 / RFC 9369)
     */
    static dissectQuicPacket(rawBuffer, offset = 0, length = rawBuffer.byteLength - offset) {
        if (length < 6 || offset + length > rawBuffer.byteLength)
            return null;
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
            if (length < 7)
                return null;
            const typeBits = (firstByte & 0x30) >> 4;
            const versionInt = view.getUint32(1, false);
            const versionHex = '0x' + versionInt.toString(16).padStart(8, '0');
            let versionStr = 'Unknown';
            if (versionInt === 0x00000000)
                versionStr = 'Version Negotiation';
            else if (versionInt === 0x00000001)
                versionStr = 'QUIC v1 (RFC 9000)';
            else if (versionInt === 0x6b3343cf)
                versionStr = 'QUIC v2 (RFC 9369)';
            else if ((versionInt & 0x0f0f0f0f) === 0x0a0a0a0a)
                versionStr = 'Draft / GREASE';
            else
                versionStr = `QUIC ${versionHex}`;
            let packetType = 'Unknown';
            if (versionInt === 0x00000000) {
                packetType = 'Version-Negotiation';
            }
            else {
                switch (typeBits) {
                    case 0x00:
                        packetType = 'Initial';
                        break;
                    case 0x01:
                        packetType = '0-RTT';
                        break;
                    case 0x02:
                        packetType = 'Handshake';
                        break;
                    case 0x03:
                        packetType = 'Retry';
                        break;
                }
            }
            const dcidLen = view.getUint8(5);
            if (length < 6 + dcidLen + 1)
                return null;
            let dcidHex = '';
            for (let i = 0; i < dcidLen; i++) {
                dcidHex += view.getUint8(6 + i).toString(16).padStart(2, '0');
            }
            const scidOffset = 6 + dcidLen;
            const scidLen = view.getUint8(scidOffset);
            let scidHex = '';
            if (length >= scidOffset + 1 + scidLen) {
                for (let i = 0; i < scidLen; i++) {
                    scidHex += view.getUint8(scidOffset + 1 + i).toString(16).padStart(2, '0');
                }
            }
            const packetNumberLength = (firstByte & 0x03) + 1;
            return {
                isQuic: true,
                headerForm: 'long',
                fixedBit,
                packetType,
                version: versionStr,
                versionHex,
                dcidHex,
                scidHex,
                packetNumberLength
            };
        }
        else {
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
                keyPhase
            };
        }
    }
    /**
     * Dissects SSHv2 (RFC 4253) identification banner and SSH_MSG_KEXINIT HASSH fingerprinter
     */
    static dissectSshPacket(rawBuffer, offset = 0, length = rawBuffer.byteLength - offset) {
        if (length < 4 || offset + length > rawBuffer.byteLength)
            return null;
        const slice = Buffer.from(rawBuffer.buffer, rawBuffer.byteOffset + offset, length);
        const asciiPrefix = slice.subarray(0, 8).toString('ascii');
        // 1. Check for SSH-2.0 banner identification string
        if (asciiPrefix.startsWith('SSH-2.0-') || asciiPrefix.startsWith('SSH-1.99-')) {
            const lineEnd = slice.indexOf('\n');
            const banner = (lineEnd !== -1 ? slice.subarray(0, lineEnd) : slice).toString('utf8').replace(/\r$/, '');
            return {
                isSsh: true,
                banner,
                isKexInit: false
            };
        }
        // 2. Binary SSH packet parsing
        if (length < 6)
            return null;
        const view = new DataView(rawBuffer.buffer, rawBuffer.byteOffset + offset, length);
        const packetLength = view.getUint32(0, false);
        const paddingLength = view.getUint8(4);
        if (packetLength > 65536 || paddingLength >= packetLength) {
            return null;
        }
        const msgCode = view.getUint8(5);
        // 20 = 0x14 = SSH_MSG_KEXINIT
        if (msgCode !== 20) {
            return {
                isSsh: true,
                isKexInit: false
            };
        }
        // Parse SSH_MSG_KEXINIT
        // 16 bytes cookie starting at offset 6
        let cur = 6 + 16;
        const readNameList = () => {
            if (cur + 4 > length)
                return [];
            const strLen = view.getUint32(cur, false);
            cur += 4;
            if (cur + strLen > length || strLen > 4096)
                return [];
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
            compressionAlgorithms: compClientServer
        };
    }
    /**
     * Dissects SMBv2/v3 header and flags lateral movement signatures
     */
    static dissectSmb2Packet(rawBuffer, offset = 0, length = rawBuffer.byteLength - offset) {
        if (length < 64 || offset + length > rawBuffer.byteLength)
            return null;
        // Check magic 0xFE 'S' 'M' 'B'
        if (rawBuffer[offset] !== SMB2_MAGIC[0] ||
            rawBuffer[offset + 1] !== SMB2_MAGIC[1] ||
            rawBuffer[offset + 2] !== SMB2_MAGIC[2] ||
            rawBuffer[offset + 3] !== SMB2_MAGIC[3]) {
            return null;
        }
        const view = new DataView(rawBuffer.buffer, rawBuffer.byteOffset + offset, length);
        const structureSize = view.getUint16(4, true);
        if (structureSize !== 64)
            return null;
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
        let lateralTargetOrShare;
        // Look for ASCII / UTF-16 strings in payload past the 64-byte header
        if (length > 68) {
            const payloadSlice = Buffer.from(rawBuffer.buffer, rawBuffer.byteOffset + offset + 64, length - 64);
            const textUtf8 = payloadSlice.toString('utf8');
            const textUtf16 = payloadSlice.toString('utf16le');
            const combined = (textUtf8 + ' ' + textUtf16).toUpperCase();
            if (combined.includes('ADMIN$') || combined.includes('C$') || combined.includes('IPC$') || combined.includes('D$')) {
                lateralMovementSuspected = true;
                if (combined.includes('ADMIN$'))
                    lateralTargetOrShare = 'ADMIN$';
                else if (combined.includes('C$'))
                    lateralTargetOrShare = 'C$';
                else if (combined.includes('IPC$'))
                    lateralTargetOrShare = 'IPC$';
            }
            if (combined.includes('PSEXEC') || combined.includes('SVCCTL') || combined.includes('ATSVC') || combined.includes('SAMR')) {
                lateralMovementSuspected = true;
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
            lateralTargetOrShare
        };
    }
    /**
     * Dissects HTTP/2 (RFC 9113) connection preface and 9-byte frame headers
     */
    static dissectHttp2Frame(rawBuffer, offset = 0, length = rawBuffer.byteLength - offset) {
        if (length < 9 || offset + length > rawBuffer.byteLength)
            return null;
        const slice = Buffer.from(rawBuffer.buffer, rawBuffer.byteOffset + offset, length);
        let cur = 0;
        let hasConnectionPreface = false;
        // Check for HTTP/2 Client Preface
        if (length >= 24 && slice.subarray(0, 24).equals(HTTP2_CLIENT_PREFACE)) {
            hasConnectionPreface = true;
            cur = 24;
        }
        const frames = [];
        const view = new DataView(rawBuffer.buffer, rawBuffer.byteOffset + offset, length);
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
            frames.push({
                length: frameLength,
                typeCode,
                typeName: typeName || `FRAME_0x${typeCode.toString(16)}`,
                flags,
                streamId
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
            frames
        };
    }
    /**
     * Universal L7 protocol detector and dissector
     */
    static dissect(rawBuffer, offset = 0, length = rawBuffer.byteLength - offset) {
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
    dissectPayload(rawBuffer, sport, dport, offset = 0, length = rawBuffer.byteLength - offset) {
        return L7DeepProtocolDissector.dissect(rawBuffer, offset, length);
    }
}
exports.L7DeepProtocolDissector = L7DeepProtocolDissector;
//# sourceMappingURL=l7-deep-protocol-dissector.js.map