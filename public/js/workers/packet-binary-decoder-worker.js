/**
 * EJII Track 4: Line-Rate Binary Packet Cockpit Offscreen Worker
 *
 * Dedicated Web Worker for offloading 15,000+ pps binary frame decoding from the main UI thread.
 * Decodes compact 28/32-byte binary frames using zero-copy DataView operations.
 * Maintains an internal ring buffer of the last 10,000 frames.
 * Emits batched frame bursts to main thread at a capped 60Hz (~16ms) animation frame tick.
 * Universal Module Definition: runs in Web Worker (`self`), Window, and Node.js (`module.exports`).
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    const exported = factory();
    if (typeof self !== 'undefined') {
      root.PacketBinaryDecoderWorker = exported.PacketBinaryDecoderWorker;
      root.decodeBinaryFrameBuffer = exported.decodeBinaryFrameBuffer;
      // Initialize worker message listener if running in Web Worker scope
      if (typeof self.postMessage === 'function' && typeof self.importScripts === 'function') {
        exported.initWorkerMessageHandlers(self);
      }
    }
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const MAGIC_UINT32 = 0x454A4949; // "EJII"
  const PROTOCOL_VERSION = 1;

  const FLAGS = {
    IPV6: 0x01,
    TRUNCATED: 0x02,
    TCP: 0x04,
    UDP: 0x08,
    ICMP: 0x10,
    ARP: 0x20,
    DNS: 0x40,
    SYN: 0x80
  };

  const PROTO_NUM_TO_NAME = {
    1: 'ICMP',
    2: 'IGMP',
    6: 'TCP',
    17: 'UDP',
    41: 'IPv6',
    47: 'GRE',
    50: 'ESP',
    51: 'AH',
    58: 'ICMPv6',
    89: 'OSPF',
    132: 'SCTP',
    2054: 'ARP',
    53: 'DNS',
    443: 'TLS',
    80: 'HTTP'
  };

  function uint32ToIpv4(u32) {
    return `${(u32 >>> 24) & 0xff}.${(u32 >>> 16) & 0xff}.${(u32 >>> 8) & 0xff}.${u32 & 0xff}`;
  }

  function uint8ArrayToIpv6(bytes, offset) {
    const parts = [];
    for (let i = 0; i < 16; i += 2) {
      const val = (bytes[offset + i] << 8) | bytes[offset + i + 1];
      parts.push(val.toString(16));
    }
    return parts.join(':').replace(/(^|:)0(:0)+(:|$)/, '::');
  }

  /**
   * Fast DataView-based Binary Frame Decoder
   */
  function decodeBinaryFrameBuffer(arrayBufferOrView, byteOffset = 0) {
    let view;
    let rawBytes;
    if (arrayBufferOrView instanceof DataView) {
      view = arrayBufferOrView;
      rawBytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
    } else if (arrayBufferOrView instanceof ArrayBuffer) {
      view = new DataView(arrayBufferOrView);
      rawBytes = new Uint8Array(arrayBufferOrView);
    } else if (ArrayBuffer.isView(arrayBufferOrView)) {
      view = new DataView(arrayBufferOrView.buffer, arrayBufferOrView.byteOffset, arrayBufferOrView.byteLength);
      rawBytes = new Uint8Array(arrayBufferOrView.buffer, arrayBufferOrView.byteOffset, arrayBufferOrView.byteLength);
    } else {
      throw new TypeError('Expected ArrayBuffer or TypedArray view');
    }

    if (view.byteLength < 32) {
      return null;
    }

    const magic = view.getUint32(byteOffset + 0, false);
    if (magic !== MAGIC_UINT32) {
      return null;
    }

    const version = view.getUint8(byteOffset + 4);
    if (version !== PROTOCOL_VERSION) {
      return null;
    }

    const flags = view.getUint8(byteOffset + 5);
    const isIpv6 = Boolean(flags & FLAGS.IPV6);
    const isTruncated = Boolean(flags & FLAGS.TRUNCATED);
    const isSyn = Boolean(flags & FLAGS.SYN);

    const protoNum = view.getUint16(byteOffset + 6, false);
    let protocolName = PROTO_NUM_TO_NAME[protoNum] || 'UNKNOWN';

    // Read 64-bit timestamp (microseconds)
    const tsHigh = view.getUint32(byteOffset + 8, false);
    const tsLow = view.getUint32(byteOffset + 12, false);
    const timestampUs = tsHigh * 4294967296 + tsLow;
    const timestampMs = Math.floor(timestampUs / 1000);

    let srcIp = '0.0.0.0';
    let dstIp = '0.0.0.0';
    let srcPort = 0;
    let dstPort = 0;
    let totalLength = 0;
    let payloadLength = 0;
    let payloadOffset = 0;

    if (!isIpv6) {
      // IPv4: 32-byte header
      const srcU32 = view.getUint32(byteOffset + 16, false);
      const dstU32 = view.getUint32(byteOffset + 20, false);
      srcIp = uint32ToIpv4(srcU32);
      dstIp = uint32ToIpv4(dstU32);
      srcPort = view.getUint16(byteOffset + 24, false);
      dstPort = view.getUint16(byteOffset + 26, false);
      totalLength = view.getUint16(byteOffset + 28, false);
      payloadLength = view.getUint16(byteOffset + 30, false);
      payloadOffset = byteOffset + 32;
    } else {
      // IPv6: 56-byte header
      if (view.byteLength < 56) return null;
      srcIp = uint8ArrayToIpv6(rawBytes, byteOffset + 16);
      dstIp = uint8ArrayToIpv6(rawBytes, byteOffset + 32);
      srcPort = view.getUint16(byteOffset + 48, false);
      dstPort = view.getUint16(byteOffset + 50, false);
      totalLength = view.getUint16(byteOffset + 52, false);
      payloadLength = view.getUint16(byteOffset + 54, false);
      payloadOffset = byteOffset + 56;
    }

    if (flags & FLAGS.DNS || srcPort === 53 || dstPort === 53) {
      protocolName = 'DNS';
    } else if (flags & FLAGS.TCP || protoNum === 6) {
      if (srcPort === 443 || dstPort === 443) protocolName = 'TLS';
      else if (srcPort === 80 || dstPort === 80) protocolName = 'HTTP';
      else protocolName = 'TCP';
    } else if (flags & FLAGS.UDP || protoNum === 17) {
      protocolName = 'UDP';
    } else if (flags & FLAGS.ARP || protoNum === 2054) {
      protocolName = 'ARP';
    } else if (flags & FLAGS.ICMP || protoNum === 1) {
      protocolName = 'ICMP';
    }

    let payload = null;
    if (payloadLength > 0 && (payloadOffset + payloadLength) <= view.byteLength) {
      payload = rawBytes.subarray(payloadOffset, payloadOffset + payloadLength);
    }

    const frameHeaderLength = isIpv6 ? 56 : 32;
    const totalFrameBytes = frameHeaderLength + payloadLength;

    return {
      timestampUs,
      timestampMs,
      timestampIso: new Date(timestampMs).toISOString(),
      srcIp,
      dstIp,
      srcPort,
      dstPort,
      protocol: protocolName,
      protoNum,
      wireLength: totalLength || totalFrameBytes,
      payloadLength,
      payload,
      flags: {
        isIpv6,
        isTruncated,
        isSyn,
        rawFlags: flags
      },
      totalFrameBytes
    };
  }

  /**
   * Circular Ring Buffer for worker retention of last 10,000 frames
   */
  class DecoderRingBuffer {
    constructor(capacity = 10000) {
      this.capacity = capacity;
      this.buffer = new Array(capacity);
      this.head = 0;
      this.count = 0;
      this.totalFramesIngested = 0;
    }

    push(frame) {
      if (!frame) return;
      const slot = (this.head + this.count) % this.capacity;
      if (this.count < this.capacity) {
        this.count++;
      } else {
        this.head = (this.head + 1) % this.capacity;
      }
      this.buffer[slot] = frame;
      this.totalFramesIngested++;
    }

    getRecent(limit = 100) {
      const count = Math.min(limit, this.count);
      const result = [];
      for (let i = 0; i < count; i++) {
        const idx = (this.head + this.count - count + i) % this.capacity;
        result.push(this.buffer[idx]);
      }
      return result;
    }

    clear() {
      this.buffer = new Array(this.capacity);
      this.head = 0;
      this.count = 0;
      this.totalFramesIngested = 0;
    }
  }

  /**
   * PacketBinaryDecoderWorker Class (used in Node and UI)
   */
  class PacketBinaryDecoderWorker {
    constructor(options = {}) {
      this.ringBuffer = new DecoderRingBuffer(options.capacity || 10000);
      this.batchQueue = [];
      this.flushIntervalMs = options.flushIntervalMs || 16.6; // 60Hz tick
      this.timer = null;
      this.onBatch = options.onBatch || null;
      this.totalDecodedCount = 0;
      this.startFlushTimer();
    }

    startFlushTimer() {
      if (this.timer) return;
      this.timer = setInterval(() => {
        this.flushBatch();
      }, this.flushIntervalMs);
      if (typeof this.timer?.unref === 'function') {
        this.timer.unref();
      }
    }

    stopFlushTimer() {
      if (this.timer) {
        clearInterval(this.timer);
        this.timer = null;
      }
    }

    ingestBinaryFrame(bufferOrView) {
      const frame = decodeBinaryFrameBuffer(bufferOrView);
      if (!frame) return null;

      frame.frameNumber = ++this.totalDecodedCount;
      this.ringBuffer.push(frame);
      this.batchQueue.push(frame);
      return frame;
    }

    ingestConcatenatedBinaryBuffer(buffer) {
      const view = buffer instanceof DataView ? buffer : new DataView(buffer.buffer || buffer);
      let offset = 0;
      const decodedFrames = [];

      while (offset + 32 <= view.byteLength) {
        const frame = decodeBinaryFrameBuffer(view, offset);
        if (!frame || frame.totalFrameBytes <= 0) break;
        frame.frameNumber = ++this.totalDecodedCount;
        this.ringBuffer.push(frame);
        this.batchQueue.push(frame);
        decodedFrames.push(frame);
        offset += frame.totalFrameBytes;
      }

      return decodedFrames;
    }

    flushBatch() {
      if (this.batchQueue.length === 0) return [];
      const batch = this.batchQueue;
      this.batchQueue = [];

      if (typeof this.onBatch === 'function') {
        this.onBatch({
          type: 'PACKET_BATCH',
          frames: batch,
          totalFramesDecoded: this.totalDecodedCount,
          ringCount: this.ringBuffer.count,
          timestampMs: Date.now()
        });
      }
      return batch;
    }

    destroy() {
      this.stopFlushTimer();
      this.ringBuffer.clear();
      this.batchQueue = [];
    }
  }

  function initWorkerMessageHandlers(workerScope) {
    const decoder = new PacketBinaryDecoderWorker({
      onBatch: (batchData) => {
        workerScope.postMessage(batchData);
      }
    });

    workerScope.onmessage = function (event) {
      const msg = event.data;
      if (!msg) return;

      if (msg.type === 'INGEST_FRAME' && msg.buffer) {
        decoder.ingestBinaryFrame(msg.buffer);
      } else if (msg.type === 'INGEST_CONCATENATED' && msg.buffer) {
        decoder.ingestConcatenatedBinaryBuffer(msg.buffer);
      } else if (msg.type === 'FORCE_FLUSH') {
        const batch = decoder.flushBatch();
        workerScope.postMessage({
          type: 'FLUSH_CONFIRMED',
          batchSize: batch.length,
          totalFramesDecoded: decoder.totalDecodedCount
        });
      } else if (msg.type === 'GET_RECENT') {
        const frames = decoder.ringBuffer.getRecent(msg.limit || 100);
        workerScope.postMessage({
          type: 'RECENT_FRAMES',
          frames
        });
      } else if (msg.type === 'CLEAR') {
        decoder.ringBuffer.clear();
        workerScope.postMessage({ type: 'CLEARED' });
      }
    };
  }

  return {
    MAGIC_UINT32,
    PROTOCOL_VERSION,
    FLAGS,
    PROTO_NUM_TO_NAME,
    decodeBinaryFrameBuffer,
    DecoderRingBuffer,
    PacketBinaryDecoderWorker,
    initWorkerMessageHandlers
  };
});
