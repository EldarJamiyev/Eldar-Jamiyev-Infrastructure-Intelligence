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
export declare class WireDissectorApex {
    /**
     * Dissects a TLS Record containing a ClientHello directly from a raw TCP payload buffer
     * using zero-copy DataView offsets and computes the JA4 Fingerprint.
     */
    static dissectTLSClientHello(frameBuffer: Uint8Array, tcpPayloadOffset: number, tcpPayloadLength: number): TLSClientHelloDissection | null;
    /**
     * Hardened RFC 1035 DNS Wire Dissector with cyclic compression pointer guard
     * and Shannon Entropy DGA / DNS-Tunneling detection.
     */
    static dissectDNSFrame(frameBuffer: Uint8Array, udpPayloadOffset: number, udpPayloadLength: number): DNSWireDissection | null;
    /**
     * Decodes RFC 1035 compressed domain names with a strict cycle-detection barrier (max 16 jumps).
     */
    private static readDnsNameBounded;
    private static computeStringShannonEntropy;
}
