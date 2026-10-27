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
}
export interface Http2FrameInfo {
    readonly length: number;
    readonly typeCode: number;
    readonly typeName: string;
    readonly flags: number;
    readonly streamId: number;
}
export interface Http2Dissection {
    readonly isHttp2: boolean;
    readonly hasConnectionPreface: boolean;
    readonly frames: readonly Http2FrameInfo[];
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
export declare class L7DeepProtocolDissector {
    /**
     * Dissects QUIC wire packets (RFC 9000 / RFC 9369)
     */
    static dissectQuicPacket(rawBuffer: Uint8Array, offset?: number, length?: number): QuicDissection | null;
    /**
     * Dissects SSHv2 (RFC 4253) identification banner and SSH_MSG_KEXINIT HASSH fingerprinter
     */
    static dissectSshPacket(rawBuffer: Uint8Array, offset?: number, length?: number): SshDissection | null;
    /**
     * Dissects SMBv2/v3 header and flags lateral movement signatures
     */
    static dissectSmb2Packet(rawBuffer: Uint8Array, offset?: number, length?: number): Smb2Dissection | null;
    /**
     * Dissects HTTP/2 (RFC 9113) connection preface and 9-byte frame headers
     */
    static dissectHttp2Frame(rawBuffer: Uint8Array, offset?: number, length?: number): Http2Dissection | null;
    /**
     * Universal L7 protocol detector and dissector
     */
    static dissect(rawBuffer: Uint8Array, offset?: number, length?: number): L7DeepDissectionResult;
    /**
     * Instance-level convenience wrapper for dissecting payloads
     */
    dissectPayload(rawBuffer: Uint8Array, sport?: number, dport?: number, offset?: number, length?: number): L7DeepDissectionResult;
}
