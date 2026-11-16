/**
 * EJII Polyglot QUIC (RFC 9000) & Apache Kafka Binary Protocol Dissector
 * Phase 22.0 High-Throughput Packet Layer
 *
 * Dual-Maintenance CommonJS Implementation.
 */

'use strict';

class QuicKafkaProtocolDissector {
  static get KAFKA_API_KEYS() {
    return {
      0: 'PRODUCE',
      1: 'FETCH',
      2: 'LIST_OFFSETS',
      3: 'METADATA',
      8: 'OFFSET_COMMIT',
      9: 'OFFSET_FETCH',
      10: 'FIND_COORDINATOR',
      11: 'JOIN_GROUP',
      12: 'HEARTBEAT',
      13: 'LEAVE_GROUP',
      14: 'SYNC_GROUP'
    };
  }

  decodeVarInt(buf, offset = 0) {
    if (!buf || offset >= buf.length) return null;

    const first = buf.readUInt8(offset);
    const prefix = first >> 6;

    if (prefix === 0) {
      return { value: first & 0x3f, bytesRead: 1 };
    } else if (prefix === 1) {
      if (offset + 2 > buf.length) return null;
      return { value: buf.readUInt16BE(offset) & 0x3fff, bytesRead: 2 };
    } else if (prefix === 2) {
      if (offset + 4 > buf.length) return null;
      return { value: buf.readUInt32BE(offset) & 0x3fffffff, bytesRead: 4 };
    } else {
      if (offset + 8 > buf.length) return null;
      const high = buf.readUInt32BE(offset) & 0x3fffffff;
      const low = buf.readUInt32BE(offset + 4);
      return { value: high * 0x100000000 + low, bytesRead: 8 };
    }
  }

  dissectQuicPacket(buf) {
    if (!buf || buf.length < 5) return null;

    const firstByte = buf.readUInt8(0);
    const isFixedBitSet = (firstByte & 0x40) !== 0;
    const isLongHeader = (firstByte & 0x80) !== 0;

    if (!isFixedBitSet) {
      return null;
    }

    if (isLongHeader) {
      if (buf.length < 7) return null;
      const versionRaw = buf.readUInt32BE(1);
      const rawType = (firstByte & 0x30) >> 4;
      let packetType = 'UNKNOWN';
      if (rawType === 0x00) packetType = 'INITIAL';
      else if (rawType === 0x01) packetType = '0-RTT';
      else if (rawType === 0x02) packetType = 'HANDSHAKE';
      else if (rawType === 0x03) packetType = 'RETRY';

      let offset = 5;
      let dcidHex = '';
      let scidHex = '';

      if (offset < buf.length) {
        const dcil = buf.readUInt8(offset);
        offset += 1;
        if (offset + dcil <= buf.length) {
          dcidHex = buf.subarray(offset, offset + dcil).toString('hex');
          offset += dcil;
        }
      }

      if (offset < buf.length) {
        const scil = buf.readUInt8(offset);
        offset += 1;
        if (offset + scil <= buf.length) {
          scidHex = buf.subarray(offset, offset + scil).toString('hex');
          offset += scil;
        }
      }

      let versionStr = `0x${versionRaw.toString(16).padStart(8, '0')}`;
      if (versionRaw === 0x00000001) versionStr = 'QUIC v1 (RFC 9000)';
      else if (versionRaw === 0x6b3343cf) versionStr = 'QUIC v2 (RFC 9369)';

      return {
        isQuic: true,
        headerForm: 'LONG',
        packetType,
        version: versionStr,
        versionRaw,
        dcidHex,
        scidHex,
        payloadLength: buf.length
      };
    } else {
      return {
        isQuic: true,
        headerForm: 'SHORT',
        packetType: '1-RTT_PROTECTED',
        payloadLength: buf.length
      };
    }
  }

  dissectKafkaFrame(buf) {
    if (!buf || buf.length < 12) return null;

    const messageSize = buf.readUInt32BE(0);
    if (messageSize > 64 * 1024 * 1024 || messageSize === 0) {
      return null;
    }

    const apiKey = buf.readInt16BE(4);
    const apiVersion = buf.readInt16BE(6);
    const correlationId = buf.readInt32BE(8);

    const apiKeyName = QuicKafkaProtocolDissector.KAFKA_API_KEYS[apiKey];
    if (!apiKeyName) {
      return null;
    }

    let clientId = undefined;
    if (buf.length >= 14) {
      const clientIdLen = buf.readInt16BE(12);
      if (clientIdLen > 0 && 14 + clientIdLen <= buf.length) {
        clientId = buf.toString('utf8', 14, 14 + clientIdLen);
      }
    }

    return {
      isKafka: true,
      messageSize,
      apiKey,
      apiKeyName,
      apiVersion,
      correlationId,
      clientId
    };
  }

  classifyTransportPayload(buf, port = 0) {
    if (!buf || buf.length === 0) {
      return {
        protocol: 'GENERIC_PAYLOAD',
        confidence: 0.1,
        summary: 'Empty transport buffer'
      };
    }

    const quic = this.dissectQuicPacket(buf);
    if (quic && (port === 443 || port === 8443 || quic.headerForm === 'LONG')) {
      return {
        protocol: 'QUIC_RFC9000',
        confidence: 0.98,
        quicDetails: quic,
        summary: `QUIC ${quic.headerForm} Header [${quic.packetType}] Version: ${quic.version || '1-RTT'}`
      };
    }

    const kafka = this.dissectKafkaFrame(buf);
    if (kafka && (port === 9092 || port === 9093 || kafka.apiKeyName)) {
      return {
        protocol: 'APACHE_KAFKA',
        confidence: 0.96,
        kafkaDetails: kafka,
        summary: `Kafka ${kafka.apiKeyName} (v${kafka.apiVersion}) CorrId: ${kafka.correlationId}`
      };
    }

    return {
      protocol: 'GENERIC_PAYLOAD',
      confidence: 0.5,
      summary: `Opaque transport frame (${buf.length} bytes)`
    };
  }
}

const quicKafkaProtocolDissector = new QuicKafkaProtocolDissector();

module.exports = {
  QuicKafkaProtocolDissector,
  quicKafkaProtocolDissector
};
