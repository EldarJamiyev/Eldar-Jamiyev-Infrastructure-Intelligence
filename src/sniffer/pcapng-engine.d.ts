/**
 * IETF PCAP Next Generation (PCAPNG) Binary Capture Writer, Parser & Replay Engine
 * 100% Unprivileged, Zero-Simulation Binary Implementation compliant with Wireshark & tcpdump.
 * Supports:
 *  - Section Header Block (SHB: 0x0A0D0D0A) with Byte-Order Magic 0x1A2B3C4D
 *  - Interface Description Block (IDB: 0x00000001) for LINKTYPE_ETHERNET (1)
 *  - Enhanced Packet Block (EPB: 0x00000006) with 64-bit microsecond timestamps
 *  - Embedded JA4 & STL metadata options (opt_comment = 1)
 */
export interface PcapngFrameInput {
    readonly timestampMs: number;
    readonly rawBytes: Uint8Array;
    readonly metadata?: Record<string, unknown>;
}
export interface PcapngParsedPacket {
    readonly interfaceId: number;
    readonly timestampMs: number;
    readonly capturedLen: number;
    readonly originalLen: number;
    readonly rawBytes: Uint8Array;
    readonly commentMetadata: Record<string, unknown> | null;
}
export interface PcapngParseResult {
    readonly valid: boolean;
    readonly shbInfo: {
        readonly major: number;
        readonly minor: number;
        readonly comment: string | null;
    };
    readonly linkType: number;
    readonly snapLen: number;
    readonly packets: PcapngParsedPacket[];
}
export declare class PcapngEngine {
    static readonly SHB_MAGIC = 168627466;
    static readonly BYTE_ORDER_MAGIC = 439041101;
    static readonly IDB_TYPE = 1;
    static readonly EPB_TYPE = 6;
    static readonly LINKTYPE_ETHERNET = 1;
    static readonly DEFAULT_SNAPLEN = 65535;
    /**
     * Helper to pad a byte count up to the next 4-byte boundary.
     */
    private static pad4;
    /**
     * Serializes an array of captured frames into a standard IETF PCAPNG binary buffer.
     */
    static serializeFramesToPcapng(frames: readonly PcapngFrameInput[]): Uint8Array;
    /**
     * Parses a standard PCAPNG binary buffer into structured packets and metadata.
     */
    static parsePcapng(buffer: Uint8Array): PcapngParseResult;
    static parsePcapngBuffer(buffer: Uint8Array): PcapngParseResult;
}
