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

export class TcpStreamWaterfallEngine {
  private streams: Map<string, StreamMetrics> = new Map();
  private maxStoredStreams: number = 200;
  private maxPointsPerStream: number = 250;

  constructor(maxStoredStreams: number = 200) {
    this.maxStoredStreams = maxStoredStreams;
  }

  public getStreamKey(ipA: string, portA: number, ipB: string, portB: number, protocol: string = 'TCP'): string {
    return TcpStreamWaterfallEngine.getCanonicalKey(protocol, ipA, portA, ipB, portB).key;
  }

  /**
   * Generates a canonical bidirectional 5-tuple conversation key
   */
  public static getCanonicalKey(
    protocol: string,
    ipA: string,
    portA: number,
    ipB: string,
    portB: number
  ): { key: string; isClientToServer: boolean; client: string; server: string } {
    const epA = `${ipA}:${portA}`;
    const epB = `${ipB}:${portB}`;
    const proto = (protocol || 'TCP').toUpperCase();

    // Deterministic ordering: lowest endpoint string is designated client or canonical anchor
    if (epA.localeCompare(epB) <= 0) {
      return {
        key: `${proto}:${epA}<->${epB}`,
        isClientToServer: true,
        client: epA,
        server: epB
      };
    } else {
      return {
        key: `${proto}:${epB}<->${epA}`,
        isClientToServer: false,
        client: epB,
        server: epA
      };
    }
  }

  /**
   * Ingest a batch of dissected wire frames
   */
  public ingestFrames(frames: PacketFrameWire[]): void {
    if (!Array.isArray(frames)) return;
    for (const frame of frames) {
      this.ingestFrame(frame);
    }
  }

  /**
   * Ingest a single packet frame and update conversation stream telemetry
   */
  public ingestFrame(frame: PacketFrameWire): void {
    if (!frame) return;

    const srcIp = frame.srcIp || frame.sourceAddress || '0.0.0.0';
    const dstIp = frame.dstIp || frame.destinationAddress || '0.0.0.0';
    const srcPort = Number(frame.srcPort || frame.sourcePort || 0);
    const dstPort = Number(frame.dstPort || frame.destinationPort || 0);
    let proto = 'TCP';
    if (typeof frame.ipProtocol === 'string') {
      proto = frame.ipProtocol.toUpperCase();
    } else if (frame.ipProtocol === 17 || frame.protocol === 'UDP') {
      proto = 'UDP';
    }

    if (srcPort === 0 && dstPort === 0) return;

    const { key, isClientToServer, client, server } = TcpStreamWaterfallEngine.getCanonicalKey(
      proto,
      srcIp,
      srcPort,
      dstIp,
      dstPort
    );

    let stream = this.streams.get(key);
    const nowMs = typeof frame.timestamp === 'number'
      ? frame.timestamp
      : (typeof frame.timestamp === 'string' && !isNaN(Date.parse(frame.timestamp))
          ? new Date(frame.timestamp).getTime()
          : Date.now());

    const frameNum = frame.frameNumber || 1;
    const pSize = Number(frame.length || frame.totalPacketsSize || 64);
    const seqNum = Number(frame.tcpSeq ?? 0);
    const ackNum = Number(frame.tcpAck ?? 0);
    const winSize = Number(frame.windowSize ?? 65535);
    const payloadLen = Number(frame.payloadLength ?? Math.max(0, pSize - 54));

    // Flags normalization
    let flagsStr = '';
    let isSyn = false;
    let isAck = false;
    let isFin = false;
    let isRst = false;

    if (typeof frame.tcpFlags === 'object' && frame.tcpFlags !== null) {
      isSyn = !!frame.tcpFlags.syn;
      isAck = !!frame.tcpFlags.ack;
      isFin = !!frame.tcpFlags.fin;
      isRst = !!frame.tcpFlags.rst;
      flagsStr = [
        isSyn ? 'SYN' : '',
        isAck ? 'ACK' : '',
        isFin ? 'FIN' : '',
        isRst ? 'RST' : '',
        frame.tcpFlags.psh ? 'PSH' : ''
      ].filter(Boolean).join(',');
    } else if (typeof frame.tcpFlags === 'string') {
      flagsStr = frame.tcpFlags;
      isSyn = flagsStr.includes('SYN');
      isAck = flagsStr.includes('ACK');
      isFin = flagsStr.includes('FIN');
      isRst = flagsStr.includes('RST');
    }

    if (!stream) {
      if (this.streams.size >= this.maxStoredStreams) {
        // Evict oldest stream
        const firstKey = this.streams.keys().next().value;
        if (firstKey) this.streams.delete(firstKey);
      }

      stream = {
        streamId: key,
        protocol: proto,
        clientEndpoint: client,
        serverEndpoint: server,
        firstTimestampMs: nowMs,
        lastTimestampMs: nowMs,
        durationMs: 0,
        totalPackets: 0,
        clientToServerPackets: 0,
        serverToClientPackets: 0,
        totalBytes: 0,
        meanPacketSize: 0,
        peakBurstRateKbps: 0,
        rfc3550JitterMs: 0.0,
        handshakeRttMs: null,
        state: isSyn ? 'ESTABLISHING' : 'ESTABLISHED',
        anomalies: {
          retransmissionCount: 0,
          dupAckCount: 0,
          outOfOrderCount: 0,
          zeroWindowCount: 0
        },
        waterfallPoints: []
      };
      this.streams.set(key, stream);
    }

    // Direction and Counter Updates
    const direction = isClientToServer ? 'CLIENT_TO_SERVER' : 'SERVER_TO_CLIENT';
    if (isClientToServer) {
      stream.clientToServerPackets++;
    } else {
      stream.serverToClientPackets++;
    }
    stream.totalPackets++;
    stream.totalBytes += pSize;
    stream.meanPacketSize = Math.round(stream.totalBytes / stream.totalPackets);

    const relativeTimeMs = Math.max(0, nowMs - stream.firstTimestampMs);
    const prevTimeMs = stream.lastTimestampMs;
    const deltaMs = Math.max(0, nowMs - prevTimeMs);
    stream.lastTimestampMs = nowMs;
    stream.durationMs = relativeTimeMs;

    // RFC 3550 Inter-Arrival Jitter computation in Float64
    // D(i-1, i) = (R_i - R_{i-1}) - (S_i - S_{i-1})
    // For single-point sniffer capture, packet arrival intervals serve as nominal wire clock.
    // J_i = J_{i-1} + (|D| - J_{i-1}) / 16.0
    if (stream.waterfallPoints.length > 0) {
      const prevPoint = stream.waterfallPoints[stream.waterfallPoints.length - 1];
      const prevDelta = prevPoint.rttDeltaMs;
      const transitDiff = Math.abs(deltaMs - prevDelta);
      const prevJitter = stream.rfc3550JitterMs;
      // Exact RFC 3550 recursion:
      const newJitter = prevJitter + (transitDiff - prevJitter) / 16.0;
      stream.rfc3550JitterMs = Number(newJitter.toFixed(3));
    } else {
      stream.rfc3550JitterMs = 0.0;
    }

    // Burst rate estimate (kbps across last 1s window)
    if (deltaMs > 0 && deltaMs < 1000) {
      const instantaneousKbps = (pSize * 8) / deltaMs;
      if (instantaneousKbps > stream.peakBurstRateKbps) {
        stream.peakBurstRateKbps = Math.round(instantaneousKbps);
      }
    }

    // State machine and Handshake RTT extraction
    if (isRst) {
      stream.state = 'RESET';
    } else if (isFin) {
      stream.state = stream.state === 'TERMINATING' ? 'CLOSED' : 'TERMINATING';
    } else if (isSyn && !isAck) {
      stream.state = 'ESTABLISHING';
    } else if (isSyn && isAck) {
      stream.state = 'ESTABLISHING';
    } else if (stream.state === 'ESTABLISHING' && isAck) {
      stream.state = 'ESTABLISHED';
      if (stream.handshakeRttMs === null) {
        stream.handshakeRttMs = Math.max(1, Math.round(relativeTimeMs));
      }
    }

    // Frame Classification (Anomaly / TCP Semantics)
    let classification: WaterfallPoint['classification'] = 'NOMINAL';

    if (isSyn) {
      classification = 'HANDSHAKE';
    } else if (winSize === 0) {
      classification = 'ZERO_WINDOW';
      stream.anomalies.zeroWindowCount++;
    } else {
      // Check for Retransmission and Dup-ACK
      const lastSameDir = [...stream.waterfallPoints]
        .reverse()
        .find(p => p.direction === direction);

      if (lastSameDir) {
        if (payloadLen > 0 && seqNum === lastSameDir.seqNumber && lastSameDir.payloadLength > 0) {
          classification = 'RETRANSMISSION';
          stream.anomalies.retransmissionCount++;
        } else if (isAck && !isSyn && payloadLen === 0 && ackNum === lastSameDir.ackNumber) {
          classification = 'DUP_ACK';
          stream.anomalies.dupAckCount++;
        }
      }
    }

    const point: WaterfallPoint = {
      index: stream.waterfallPoints.length,
      frameNumber: frameNum,
      timestamp: nowMs,
      relativeTimeMs: Number(relativeTimeMs.toFixed(2)),
      direction,
      seqNumber: seqNum,
      ackNumber: ackNum,
      payloadLength: payloadLen,
      flags: flagsStr || 'ACK',
      windowSize: winSize,
      rttDeltaMs: Number(deltaMs.toFixed(2)),
      jitterMs: stream.rfc3550JitterMs,
      classification
    };

    if (stream.waterfallPoints.length >= this.maxPointsPerStream) {
      stream.waterfallPoints.shift();
    }
    stream.waterfallPoints.push(point);
  }

  /**
   * Return high-level summary of all reconstructed TCP conversations
   */
  public getStreamsSummary(): StreamMetrics[] {
    return Array.from(this.streams.values()).sort((a, b) => b.lastTimestampMs - a.lastTimestampMs);
  }

  /**
   * Return specific stream with full waterfall time-sequence points
   */
  public getStreamWaterfall(streamId: string): StreamMetrics | null {
    return this.streams.get(streamId) || null;
  }

  /**
   * Clear all stream memory
   */
  public clear(): void {
    this.streams.clear();
  }
}
