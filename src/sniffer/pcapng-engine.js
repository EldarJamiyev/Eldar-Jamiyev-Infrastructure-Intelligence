"use strict";
// src/sniffer/pcapng-engine.ts
/**
 * IETF PCAP Next Generation (PCAPNG) Binary Capture Writer, Parser & Replay Engine
 * 100% Unprivileged, Zero-Simulation Binary Implementation compliant with Wireshark & tcpdump.
 * Supports:
 *  - Section Header Block (SHB: 0x0A0D0D0A) with Byte-Order Magic 0x1A2B3C4D
 *  - Interface Description Block (IDB: 0x00000001) for LINKTYPE_ETHERNET (1)
 *  - Enhanced Packet Block (EPB: 0x00000006) with 64-bit microsecond timestamps
 *  - Embedded JA4 & STL metadata options (opt_comment = 1)
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.PcapngEngine = void 0;
class PcapngEngine {
    static SHB_MAGIC = 0x0a0d0d0a;
    static BYTE_ORDER_MAGIC = 0x1a2b3c4d;
    static IDB_TYPE = 0x00000001;
    static EPB_TYPE = 0x00000006;
    static LINKTYPE_ETHERNET = 1;
    static DEFAULT_SNAPLEN = 65535;
    /**
     * Helper to pad a byte count up to the next 4-byte boundary.
     */
    static pad4(len) {
        return (len + 3) & ~3;
    }
    /**
     * Serializes an array of captured frames into a standard IETF PCAPNG binary buffer.
     */
    static serializeFramesToPcapng(frames) {
        const parts = [];
        // --- 1. Section Header Block (SHB) ---
        const shbComment = 'EJII v3.0.0-sovereign-enterprise Wire Capture';
        const shbCommentBytes = new TextEncoder().encode(shbComment);
        const shbCommentPadded = this.pad4(shbCommentBytes.length);
        // Header (8) + Body (16) + Option 1 (4 + shbCommentPadded) + EndOfOpt (4) + Trailer (4)
        const shbOptLen = 4 + shbCommentPadded + 4;
        const shbTotalLen = 8 + 16 + shbOptLen + 4;
        const shbBuf = new Uint8Array(shbTotalLen);
        const shbView = new DataView(shbBuf.buffer);
        shbView.setUint32(0, this.SHB_MAGIC, true); // Block Type 0x0A0D0D0A
        shbView.setUint32(4, shbTotalLen, true); // Total Length
        shbView.setUint32(8, this.BYTE_ORDER_MAGIC, true); // Byte-Order Magic 0x1A2B3C4D
        shbView.setUint16(12, 1, true); // Major 1
        shbView.setUint16(14, 0, true); // Minor 0
        shbView.setBigInt64(16, -1n, true); // Section Length -1 (unspecified)
        // Option: opt_comment (1)
        let optOffset = 24;
        shbView.setUint16(optOffset, 1, true); // opt_code = 1
        shbView.setUint16(optOffset + 2, shbCommentBytes.length, true);
        shbBuf.set(shbCommentBytes, optOffset + 4);
        optOffset += 4 + shbCommentPadded;
        // Option: opt_endofopt (0)
        shbView.setUint16(optOffset, 0, true);
        shbView.setUint16(optOffset + 2, 0, true);
        optOffset += 4;
        shbView.setUint32(shbTotalLen - 4, shbTotalLen, true); // Trailing Total Length
        parts.push(shbBuf);
        // --- 2. Interface Description Block (IDB) ---
        // Header (8) + Body (8: linkType 2, reserved 2, snapLen 4) + EndOfOpt (4) + Trailer (4) = 24 bytes
        const idbTotalLen = 24;
        const idbBuf = new Uint8Array(idbTotalLen);
        const idbView = new DataView(idbBuf.buffer);
        idbView.setUint32(0, this.IDB_TYPE, true); // Block Type 0x00000001
        idbView.setUint32(4, idbTotalLen, true);
        idbView.setUint16(8, this.LINKTYPE_ETHERNET, true); // LinkType = 1 (Ethernet)
        idbView.setUint16(10, 0, true); // Reserved 0
        idbView.setUint32(12, this.DEFAULT_SNAPLEN, true); // SnapLen = 65535
        idbView.setUint16(16, 0, true); // opt_endofopt
        idbView.setUint16(18, 0, true);
        idbView.setUint32(20, idbTotalLen, true);
        parts.push(idbBuf);
        // --- 3. Enhanced Packet Blocks (EPB) ---
        for (const frame of frames) {
            const pktLen = frame.rawBytes.length;
            const pktPadded = this.pad4(pktLen);
            // Metadata option if available
            let optBytesLen = 0;
            let optPadded = 0;
            let commentJsonBytes = null;
            if (frame.metadata && Object.keys(frame.metadata).length > 0) {
                commentJsonBytes = new TextEncoder().encode(JSON.stringify(frame.metadata));
                optPadded = this.pad4(commentJsonBytes.length);
                optBytesLen = 4 + optPadded + 4; // opt_code(2)+opt_len(2) + value + endOfOpt(4)
            }
            // EPB: Type (4) + TotalLen (4) + ifId (4) + tsHigh (4) + tsLow (4) + capLen (4) + origLen (4) = 28
            // + pktPadded + optBytesLen + Trailer TotalLen (4)
            const epbTotalLen = 28 + pktPadded + optBytesLen + 4;
            const epbBuf = new Uint8Array(epbTotalLen);
            const epbView = new DataView(epbBuf.buffer);
            epbView.setUint32(0, this.EPB_TYPE, true); // 0x00000006
            epbView.setUint32(4, epbTotalLen, true);
            epbView.setUint32(8, 0, true); // Interface ID = 0
            // Compute 64-bit microsecond timestamp (default PCAPNG if_tsresol = 1e-6)
            const tsMicros = BigInt(Math.max(0, Math.floor(frame.timestampMs * 1000)));
            const tsHigh = Number((tsMicros >> 32n) & 0xffffffffn);
            const tsLow = Number(tsMicros & 0xffffffffn);
            epbView.setUint32(12, tsHigh, true);
            epbView.setUint32(16, tsLow, true);
            epbView.setUint32(20, pktLen, true); // Captured Len
            epbView.setUint32(24, pktLen, true); // Original Len
            // Write raw packet bytes
            epbBuf.set(frame.rawBytes, 28);
            let epbCursor = 28 + pktPadded;
            if (commentJsonBytes) {
                epbView.setUint16(epbCursor, 1, true); // opt_code = 1 (opt_comment)
                epbView.setUint16(epbCursor + 2, commentJsonBytes.length, true);
                epbBuf.set(commentJsonBytes, epbCursor + 4);
                epbCursor += 4 + optPadded;
                // End of Options
                epbView.setUint16(epbCursor, 0, true);
                epbView.setUint16(epbCursor + 2, 0, true);
                epbCursor += 4;
            }
            epbView.setUint32(epbTotalLen - 4, epbTotalLen, true);
            parts.push(epbBuf);
        }
        // Concatenate all parts into a single Uint8Array
        const totalBytes = parts.reduce((acc, p) => acc + p.length, 0);
        const result = new Uint8Array(totalBytes);
        let offset = 0;
        for (const part of parts) {
            result.set(part, offset);
            offset += part.length;
        }
        return result;
    }
    /**
     * Parses a standard PCAPNG binary buffer into structured packets and metadata.
     */
    static parsePcapng(buffer) {
        return this.parsePcapngBuffer(buffer);
    }
    static parsePcapngBuffer(buffer) {
        if (buffer.length < 32) {
            return {
                valid: false,
                shbInfo: { major: 0, minor: 0, comment: null },
                linkType: 0,
                snapLen: 0,
                packets: [],
            };
        }
        const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
        let cursor = 0;
        let validShb = false;
        let shbMajor = 0;
        let shbMinor = 0;
        let shbComment = null;
        let linkType = 0;
        let snapLen = 0;
        const packets = [];
        while (cursor + 8 <= buffer.byteLength) {
            const blockType = view.getUint32(cursor, true);
            const blockLen = view.getUint32(cursor + 4, true);
            if (blockLen < 12 || cursor + blockLen > buffer.byteLength) {
                break; // Corrupted or truncated block
            }
            const trailingLen = view.getUint32(cursor + blockLen - 4, true);
            if (trailingLen !== blockLen) {
                break; // Length mismatch
            }
            if (blockType === this.SHB_MAGIC) {
                const bom = view.getUint32(cursor + 8, true);
                if (bom === this.BYTE_ORDER_MAGIC) {
                    validShb = true;
                    shbMajor = view.getUint16(cursor + 12, true);
                    shbMinor = view.getUint16(cursor + 14, true);
                    // Parse SHB Options
                    let optCursor = cursor + 24;
                    const optEnd = cursor + blockLen - 4;
                    while (optCursor + 4 <= optEnd) {
                        const optCode = view.getUint16(optCursor, true);
                        const optLength = view.getUint16(optCursor + 2, true);
                        if (optCode === 0)
                            break; // opt_endofopt
                        if (optCode === 1 && optCursor + 4 + optLength <= optEnd) {
                            const strBytes = buffer.subarray(optCursor + 4, optCursor + 4 + optLength);
                            shbComment = new TextDecoder('utf-8').decode(strBytes);
                        }
                        optCursor += 4 + this.pad4(optLength);
                    }
                }
            }
            else if (blockType === this.IDB_TYPE) {
                linkType = view.getUint16(cursor + 8, true);
                snapLen = view.getUint32(cursor + 12, true);
            }
            else if (blockType === this.EPB_TYPE) {
                const ifId = view.getUint32(cursor + 8, true);
                const tsHigh = view.getUint32(cursor + 12, true);
                const tsLow = view.getUint32(cursor + 16, true);
                const capLen = view.getUint32(cursor + 20, true);
                const origLen = view.getUint32(cursor + 24, true);
                const tsMicros = (BigInt(tsHigh) << 32n) | BigInt(tsLow);
                const timestampMs = Number(tsMicros) / 1000.0;
                const rawPacketData = buffer.subarray(cursor + 28, cursor + 28 + capLen);
                // Options parsing after padded packet
                let optCursor = cursor + 28 + this.pad4(capLen);
                const optEnd = cursor + blockLen - 4;
                let commentMeta = null;
                while (optCursor + 4 <= optEnd) {
                    const optCode = view.getUint16(optCursor, true);
                    const optLength = view.getUint16(optCursor + 2, true);
                    if (optCode === 0)
                        break;
                    if (optCode === 1 && optCursor + 4 + optLength <= optEnd) {
                        try {
                            const optStr = new TextDecoder('utf-8').decode(buffer.subarray(optCursor + 4, optCursor + 4 + optLength));
                            commentMeta = JSON.parse(optStr);
                        }
                        catch (_) {
                            commentMeta = null;
                        }
                    }
                    optCursor += 4 + this.pad4(optLength);
                }
                packets.push({
                    interfaceId: ifId,
                    timestampMs,
                    capturedLen: capLen,
                    originalLen: origLen,
                    rawBytes: new Uint8Array(rawPacketData),
                    commentMetadata: commentMeta,
                });
            }
            cursor += blockLen;
        }
        return {
            valid: validShb,
            shbInfo: {
                major: shbMajor,
                minor: shbMinor,
                comment: shbComment,
            },
            linkType,
            snapLen,
            packets,
        };
    }
}
exports.PcapngEngine = PcapngEngine;
//# sourceMappingURL=pcapng-engine.js.map