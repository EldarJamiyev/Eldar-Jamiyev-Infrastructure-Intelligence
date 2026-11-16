/**
 * EJII Polyglot L7 Protocol Wire Dissector (gRPC, HTTP/2, Redis RESP3)
 * Phase 21.0 High-Throughput Packet Layer
 *
 * Dual-Maintenance CommonJS Implementation.
 */

'use strict';

class PolyglotProtocolDissector {
  static get HTTP2_FRAME_TYPES() {
    return {
      0x00: 'DATA',
      0x01: 'HEADERS',
      0x02: 'PRIORITY',
      0x03: 'RST_STREAM',
      0x04: 'SETTINGS',
      0x05: 'PUSH_PROMISE',
      0x06: 'PING',
      0x07: 'GOAWAY',
      0x08: 'WINDOW_UPDATE',
      0x09: 'CONTINUATION'
    };
  }

  dissectHttp2Frames(buf) {
    const frames = [];
    if (!buf || buf.length < 9) return frames;

    let offset = 0;
    if (buf.length >= 24 && buf.subarray(0, 16).toString() === 'PRI * HTTP/2.0\r\n') {
      offset = 24;
    }

    const typeMap = PolyglotProtocolDissector.HTTP2_FRAME_TYPES;

    while (offset + 9 <= buf.length) {
      const length = (buf.readUInt8(offset) << 16) | buf.readUInt16BE(offset + 1);
      const type = buf.readUInt8(offset + 3);
      const flags = buf.readUInt8(offset + 4);
      const streamId = buf.readUInt32BE(offset + 5) & 0x7fffffff;

      const typeName = typeMap[type] || `UNKNOWN_0x${type.toString(16)}`;
      const frame = {
        length,
        type,
        typeName,
        flags,
        streamId
      };

      if (type === 0x01 && offset + 9 + length <= buf.length) {
        const payloadSlice = buf.subarray(offset + 9, offset + 9 + length).toString('utf8');
        const match = payloadSlice.match(/grpc-status:\s*(\d+)/i);
        if (match) {
          frame.grpcStatus = parseInt(match[1], 10);
        }
      }

      frames.push(frame);
      offset += 9 + length;
      if (frames.length > 50) break;
    }

    return frames;
  }

  dissectRedisResp(buf) {
    if (!buf || buf.length < 3) return null;

    const firstChar = String.fromCharCode(buf[0]);
    if (!['+', '-', ':', '$', '*', '_', '%', '~'].includes(firstChar)) {
      return null;
    }

    const str = buf.toString('utf8', 0, Math.min(buf.length, 512));
    const lines = str.split('\r\n');

    if (firstChar === '-') {
      return {
        protocol: 'RESP2',
        typeIndicator: firstChar,
        argumentsCount: 1,
        isError: true,
        errorMessage: lines[0].substring(1)
      };
    }

    if (firstChar === '*') {
      const count = parseInt(lines[0].substring(1), 10);
      let commandName = undefined;
      if (lines.length > 2 && lines[2]) {
        commandName = lines[2].toUpperCase();
      }
      return {
        protocol: 'RESP2',
        typeIndicator: firstChar,
        commandName,
        argumentsCount: isNaN(count) ? 0 : count,
        isError: false
      };
    }

    if (firstChar === '+' || firstChar === ':') {
      return {
        protocol: 'RESP2',
        typeIndicator: firstChar,
        commandName: lines[0].substring(1),
        argumentsCount: 1,
        isError: false
      };
    }

    return {
      protocol: 'RESP3',
      typeIndicator: firstChar,
      argumentsCount: 1,
      isError: false
    };
  }

  classifyL7Payload(buf, port = 0) {
    if (!buf || buf.length === 0) {
      return { classifiedProtocol: 'GENERIC_TCP', confidence: 0.1, summary: 'Empty payload' };
    }

    const redis = this.dissectRedisResp(buf);
    if (redis && (port === 6379 || port === 6380 || redis.commandName || redis.isError)) {
      return {
        classifiedProtocol: 'REDIS_RESP',
        confidence: 0.95,
        redisCommand: redis,
        summary: `Redis ${redis.protocol} Command: ${redis.commandName || redis.typeIndicator} (Args: ${redis.argumentsCount})`
      };
    }

    const http2 = this.dissectHttp2Frames(buf);
    if (http2.length > 0) {
      const hasGrpc = http2.some(f => f.grpcStatus !== undefined);
      return {
        classifiedProtocol: 'HTTP2_GRPC',
        confidence: hasGrpc ? 0.98 : 0.92,
        http2Frames: http2,
        summary: `HTTP/2 stream with ${http2.length} frames (${http2.map(f => f.typeName).join(', ')})${hasGrpc ? ' [gRPC active]' : ''}`
      };
    }

    return {
      classifiedProtocol: 'GENERIC_TCP',
      confidence: 0.5,
      summary: `Generic TCP stream payload (${buf.length} bytes)`
    };
  }
}

const polyglotProtocolDissector = new PolyglotProtocolDissector();

module.exports = {
  PolyglotProtocolDissector,
  polyglotProtocolDissector
};
