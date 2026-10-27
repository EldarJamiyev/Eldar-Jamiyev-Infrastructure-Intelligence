/**
 * EJII — Eldar Jamiyev's Infrastructure Intelligence
 * Passive TCP Stream Reassembly, RFC 3550 Inter-Arrival Jitter & Waterfall Engine
 *
 * Provides bidirectional 5-tuple conversation reassembly, exact RFC 3550 jitter
 * tracking, micro-burst telemetry, handshake RTT extraction, and sequence-time
 * waterfall points for deep Wireshark-grade packet dissection.
 *
 * Zero-Simulation Mandate: Pure Float64Array computational math over genuine wire frames.
 */
export interface PacketFrameWire {
    frameNumber?: number;
    timestamp?: number | string;
    sourceAddress?: string;
    destinationAddress?: string;
    srcIp?: string;
    dstIp?: string;
    sourcePort?: number;
    destinationPort?: number;
    srcPort?: number;
    dstPort?: number;
    ipProtocol?: string | number;
    protocol?: string;
    length?: number;
    totalPacketsSize?: number;
    tcpSeq?: number;
    tcpAck?: number;
    tcpFlags?: {
        syn?: boolean;
        ack?: boolean;
        fin?: boolean;
        rst?: boolean;
        psh?: boolean;
        urg?: boolean;
    } | string;
    windowSize?: number;
    payloadLength?: number;
    payload?: any;
}
export interface WaterfallPoint {
    index: number;
    frameNumber: number;
    timestamp: number;
    relativeTimeMs: number;
    direction: 'CLIENT_TO_SERVER' | 'SERVER_TO_CLIENT';
    seqNumber: number;
    ackNumber: number;
    payloadLength: number;
    flags: string;
    windowSize: number;
    rttDeltaMs: number;
    jitterMs: number;
    classification: 'NOMINAL' | 'RETRANSMISSION' | 'DUP_ACK' | 'ZERO_WINDOW' | 'HANDSHAKE';
}
export interface StreamMetrics {
    streamId: string;
    protocol: string;
    clientEndpoint: string;
    serverEndpoint: string;
    firstTimestampMs: number;
    lastTimestampMs: number;
    durationMs: number;
    totalPackets: number;
    clientToServerPackets: number;
    serverToClientPackets: number;
    totalBytes: number;
    meanPacketSize: number;
    peakBurstRateKbps: number;
    rfc3550JitterMs: number;
    handshakeRttMs: number | null;
    state: 'ESTABLISHING' | 'ESTABLISHED' | 'TERMINATING' | 'RESET' | 'CLOSED';
    anomalies: {
        retransmissionCount: number;
        dupAckCount: number;
        outOfOrderCount: number;
        zeroWindowCount: number;
    };
    waterfallPoints: WaterfallPoint[];
}
export declare class TcpStreamWaterfallEngine {
    private streams;
    private maxStoredStreams;
    private maxPointsPerStream;
    constructor(maxStoredStreams?: number);
    getStreamKey(ipA: string, portA: number, ipB: string, portB: number, protocol?: string): string;
    /**
     * Generates a canonical bidirectional 5-tuple conversation key
     */
    static getCanonicalKey(protocol: string, ipA: string, portA: number, ipB: string, portB: number): {
        key: string;
        isClientToServer: boolean;
        client: string;
        server: string;
    };
    /**
     * Ingest a batch of dissected wire frames
     */
    ingestFrames(frames: PacketFrameWire[]): void;
    /**
     * Ingest a single packet frame and update conversation stream telemetry
     */
    ingestFrame(frame: PacketFrameWire): void;
    /**
     * Return high-level summary of all reconstructed TCP conversations
     */
    getStreamsSummary(): StreamMetrics[];
    /**
     * Return specific stream with full waterfall time-sequence points
     */
    getStreamWaterfall(streamId: string): StreamMetrics | null;
    /**
     * Clear all stream memory
     */
    clear(): void;
}
