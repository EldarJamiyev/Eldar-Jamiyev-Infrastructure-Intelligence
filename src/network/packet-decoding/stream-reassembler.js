/**
 * EJII TCP Stream Reassembler & Conversation Reconstruction Engine (RFC 793)
 * Full bidirectional TCP sequence stitching, out-of-order buffering, overlap trimming,
 * and conversation chunking (Client #F87171 vs Server #38BDF8) with RTT & TTFB telemetry.
 */

'use strict';

class TcpStreamReassembler {
  /**
   * Reassemble a stream from an array of frames belonging to a streamId or 4-tuple
   * @param {Array} frames List of raw or decoded frames
   * @param {number|string} targetStreamId
   */
  static reconstructStream(frames, targetStreamId = null) {
    // 1. Filter frames for stream
    const matchingFrames = frames.filter(f => {
      if (targetStreamId !== null && targetStreamId !== undefined) {
        const sId = f.tcpAnalysis?.streamId ?? f.streamId;
        if (sId !== undefined && sId !== null) {
          return String(sId) === String(targetStreamId);
        }
      }
      return f.protocol === 'TCP' || f.protocol === 'HTTP' || f.protocol === 'TLS' || f.tcp;
    });

    if (matchingFrames.length === 0) {
      return {
        streamId: targetStreamId || 0,
        clientEndpoint: '0.0.0.0:0',
        serverEndpoint: '0.0.0.0:0',
        rttMs: 0,
        ttfbMs: 0,
        totalClientBytes: 0,
        totalServerBytes: 0,
        retransmissions: 0,
        chunks: [],
        framesCount: 0
      };
    }

    // 2. Determine Client (Initiator) and Server endpoints
    let clientEndpoint = '';
    let serverEndpoint = '';
    let initialSynTime = null;
    let initialSynAckTime = null;
    let firstClientPayloadTime = null;
    let firstServerPayloadTime = null;
    let rttMs = 0;
    let ttfbMs = 0;

    // Check for SYN to identify client
    const synFrame = matchingFrames.find(f => {
      const tcp = f.tcp || f.dissection?.layers?.tcp;
      return tcp?.flags?.syn && !tcp?.flags?.ack;
    });

    if (synFrame) {
      clientEndpoint = `${synFrame.srcIp}:${synFrame.srcPort}`;
      serverEndpoint = `${synFrame.dstIp}:${synFrame.dstPort}`;
      initialSynTime = new Date(synFrame.timestamp).getTime();
    } else {
      // Heuristic: lowest port is usually server (< 1024 or standard services 80, 443, 8080, 8443)
      const f0 = matchingFrames[0];
      const p1 = f0.srcPort;
      const p2 = f0.dstPort;
      if (p1 > p2) {
        clientEndpoint = `${f0.srcIp}:${f0.srcPort}`;
        serverEndpoint = `${f0.dstIp}:${f0.dstPort}`;
      } else {
        clientEndpoint = `${f0.dstIp}:${f0.dstPort}`;
        serverEndpoint = `${f0.srcIp}:${f0.srcPort}`;
      }
    }

    // Find SYN-ACK for RTT
    const synAckFrame = matchingFrames.find(f => {
      const tcp = f.tcp || f.dissection?.layers?.tcp;
      return tcp?.flags?.syn && tcp?.flags?.ack;
    });
    if (synAckFrame && initialSynTime) {
      initialSynAckTime = new Date(synAckFrame.timestamp).getTime();
      rttMs = Math.max(0, initialSynAckTime - initialSynTime);
    }

    // 3. Separate segments into Client -> Server and Server -> Client
    const clientSegments = [];
    const serverSegments = [];
    let retransmissions = 0;

    for (const f of matchingFrames) {
      const ep = `${f.srcIp}:${f.srcPort}`;
      const isClient = ep === clientEndpoint;
      const tcp = f.tcp || f.dissection?.layers?.tcp || {};
      const seq = tcp.seqNum ?? tcp.seq ?? 0;
      const ack = tcp.ackNum ?? tcp.ack ?? 0;
      const ts = new Date(f.timestamp).getTime();

      // Extract payload buffer
      let payloadBuf = Buffer.alloc(0);
      if (f.rawPayloadHex) {
        payloadBuf = Buffer.from(f.rawPayloadHex, 'hex');
      } else if (f.payloadHex) {
        payloadBuf = Buffer.from(f.payloadHex, 'hex');
      } else if (f.rawHex) {
        const raw = Buffer.from(f.rawHex, 'hex');
        const l7Offset = (f.payloadOffset) || (14 + 20 + (tcp.headerLengthBytes || 20));
        if (raw.length > l7Offset) {
          payloadBuf = raw.subarray(l7Offset);
        }
      } else if (f.payload) {
        payloadBuf = Buffer.isBuffer(f.payload) ? f.payload : Buffer.from(f.payload);
      }

      const segment = {
        frameNumber: f.frameNumber,
        timestamp: f.timestamp,
        ts,
        isClient,
        seq,
        ack,
        flags: tcp.flags || {},
        payloadLength: payloadBuf.length,
        payloadBuf
      };

      if (isClient) {
        clientSegments.push(segment);
        if (payloadBuf.length > 0) {
          firstClientPayloadTime = firstClientPayloadTime ? Math.min(firstClientPayloadTime, ts) : ts;
        }
      } else {
        serverSegments.push(segment);
        if (payloadBuf.length > 0) {
          firstServerPayloadTime = firstServerPayloadTime ? Math.min(firstServerPayloadTime, ts) : ts;
        }
      }
    }

    // Calculate TTFB
    if (firstClientPayloadTime && firstServerPayloadTime && firstServerPayloadTime >= firstClientPayloadTime) {
      ttfbMs = firstServerPayloadTime - firstClientPayloadTime;
    }

    let isReset = false;

    // Helper: RFC 1982 modular sequence comparison
    const seqDiff = (s1, s2) => ((s1 - s2) | 0);

    // 4. Reassemble streams and remove duplicates / overlaps with 32-bit wraparound support
    const reassembleDirection = (segments) => {
      if (segments.length === 0) return [];

      // Sort with RFC 1982 modular sequence comparison
      segments.sort((a, b) => seqDiff(a.seq, b.seq) || (a.ts - b.ts));

      const orderedChunks = [];
      let expectedSeq = null;

      for (const seg of segments) {
        if (seg.flags && seg.flags.rst) {
          isReset = true;
        }
        if (seg.payloadLength === 0) continue;

        if (expectedSeq === null) {
          expectedSeq = (seg.seq + seg.payloadLength) >>> 0;
          orderedChunks.push(seg);
          continue;
        }

        const diff = seqDiff(expectedSeq, seg.seq);
        if (diff > 0) {
          // seg.seq < expectedSeq (modulo 2^32): overlap or duplicate
          const overlapBytes = diff;
          if (overlapBytes >= seg.payloadLength) {
            // Complete duplicate retransmission
            retransmissions++;
            continue;
          } else {
            // Partial overlap: trim already seen bytes
            retransmissions++;
            const trimmedBuf = seg.payloadBuf.subarray(overlapBytes);
            const trimmedSeg = {
              ...seg,
              seq: expectedSeq,
              payloadLength: trimmedBuf.length,
              payloadBuf: trimmedBuf
            };
            expectedSeq = (expectedSeq + trimmedBuf.length) >>> 0;
            orderedChunks.push(trimmedSeg);
          }
        } else {
          // Contiguous or forward gap
          expectedSeq = (seg.seq + seg.payloadLength) >>> 0;
          orderedChunks.push(seg);
        }
      }
      return orderedChunks;
    };

    const reassembledClient = reassembleDirection(clientSegments);
    const reassembledServer = reassembleDirection(serverSegments);

    // 5. Merge reassembled segments chronologically into conversation turns
    const allPayloadSegments = [...reassembledClient, ...reassembledServer];
    allPayloadSegments.sort((a, b) => a.ts - b.ts);

    let totalClientBytes = 0;
    let totalServerBytes = 0;
    const conversationChunks = [];

    let currentTurn = null;
    const baseTime = matchingFrames[0]?.timestamp ? new Date(matchingFrames[0].timestamp).getTime() : Date.now();

    for (const seg of allPayloadSegments) {
      const sender = seg.isClient ? 'client' : 'server';
      if (seg.isClient) totalClientBytes += seg.payloadLength;
      else totalServerBytes += seg.payloadLength;

      // Group contiguous packets from same sender into conversation turns
      if (!currentTurn || currentTurn.sender !== sender) {
        if (currentTurn) {
          currentTurn.dataAscii = this._bufferToAscii(currentTurn.buf);
          currentTurn.dataHex = currentTurn.buf.toString('hex');
          currentTurn.dataBase64 = currentTurn.buf.toString('base64');
          delete currentTurn.buf;
          conversationChunks.push(currentTurn);
        }
        currentTurn = {
          sender,
          senderLabel: sender === 'client' ? `Client (${clientEndpoint})` : `Server (${serverEndpoint})`,
          firstFrame: seg.frameNumber,
          timestamp: seg.timestamp,
          deltaMs: Math.max(0, seg.ts - baseTime),
          buf: Buffer.from(seg.payloadBuf),
          length: seg.payloadLength
        };
      } else {
        currentTurn.buf = Buffer.concat([currentTurn.buf, seg.payloadBuf]);
        currentTurn.length += seg.payloadLength;
      }
    }

    if (currentTurn) {
      currentTurn.dataAscii = this._bufferToAscii(currentTurn.buf);
      currentTurn.dataHex = currentTurn.buf.toString('hex');
      currentTurn.dataBase64 = currentTurn.buf.toString('base64');
      delete currentTurn.buf;
      conversationChunks.push(currentTurn);
    }

    return {
      streamId: targetStreamId || 0,
      clientEndpoint,
      serverEndpoint,
      rttMs,
      ttfbMs,
      totalClientBytes,
      totalServerBytes,
      totalBytes: totalClientBytes + totalServerBytes,
      retransmissions,
      isReset,
      chunks: conversationChunks,
      framesCount: matchingFrames.length
    };
  }

  static _bufferToAscii(buf) {
    let ascii = '';
    for (let i = 0; i < buf.length; i++) {
      const byte = buf[i];
      if ((byte >= 32 && byte <= 126) || byte === 10 || byte === 13 || byte === 9) {
        ascii += String.fromCharCode(byte);
      } else {
        ascii += '.';
      }
    }
    return ascii;
  }

  /**
   * Format stream to plain ASCII conversation view (Wireshark-like)
   */
  static formatStreamAscii(reconstruction) {
    if (!reconstruction.chunks || reconstruction.chunks.length === 0) {
      return '[[ No payload data recorded in TCP stream ]]';
    }
    return reconstruction.chunks.map(chunk => {
      const prefix = chunk.sender === 'client' ? '>>> CLIENT:\n' : '<<< SERVER:\n';
      return prefix + chunk.dataAscii + '\n';
    }).join('\n');
  }

  /**
   * Format stream to HTML with Red (Client #F87171) and Blue (Server #38BDF8)
   */
  static formatStreamHtml(reconstruction) {
    if (!reconstruction.chunks || reconstruction.chunks.length === 0) {
      return '<div style="color: var(--text-dim); padding: 16px; text-align: center;">No payload data transmitted on this TCP stream.</div>';
    }
    return reconstruction.chunks.map(chunk => {
      const isClient = chunk.sender === 'client';
      const color = isClient ? '#F87171' : '#38BDF8';
      const bg = isClient ? 'rgba(248, 113, 113, 0.08)' : 'rgba(56, 189, 248, 0.08)';
      const align = isClient ? 'margin-right: 40px;' : 'margin-left: 40px;';
      const label = isClient ? `📤 ${chunk.senderLabel}` : `📥 ${chunk.senderLabel}`;

      const safeAscii = (chunk.dataAscii || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');

      return `
        <div style="background: ${bg}; border-left: 3px solid ${color}; padding: 8px 12px; margin-bottom: 8px; border-radius: 4px; ${align} font-family: var(--font-mono); font-size: 11px;">
          <div style="color: ${color}; font-weight: 700; margin-bottom: 4px; display: flex; justify-content: space-between;">
            <span>${label} &bull; ${chunk.length} B</span>
            <span style="font-size: 10px; color: var(--text-dim);">+${chunk.deltaMs} ms</span>
          </div>
          <pre style="margin: 0; white-space: pre-wrap; word-break: break-all; color: var(--text-main); font-size: 11px; max-height: 300px; overflow-y: auto;">${safeAscii}</pre>
        </div>
      `;
    }).join('');
  }
}

module.exports = TcpStreamReassembler;
module.exports.TcpStreamReassembler = TcpStreamReassembler;
