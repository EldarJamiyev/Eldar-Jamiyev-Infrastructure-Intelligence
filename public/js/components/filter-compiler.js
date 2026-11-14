/**
 * EJII Wireshark-Grade Boolean Display Filter AST Compiler & Evaluator
 * Supports RFC protocol fields, comparison operators, logical operators, and syntax validation.
 * Zero-Simulation Mandate: Evaluates against real packet structures and byte-accurate dissections.
 */

'use strict';

class FilterSyntaxError extends Error {
  constructor(message, offset = 0) {
    super(message);
    this.name = 'FilterSyntaxError';
    this.offset = offset;
  }
}

/**
 * Token Types
 */
const TOKEN_TYPES = {
  FIELD: 'FIELD',
  NUMBER: 'NUMBER',
  STRING: 'STRING',
  IP_ADDR: 'IP_ADDR',
  MAC_ADDR: 'MAC_ADDR',
  HEX_NUM: 'HEX_NUM',
  COMP_OP: 'COMP_OP',     // ==, !=, >, <, >=, <=, contains, matches, in
  LOGIC_OP: 'LOGIC_OP',   // &&, ||, and, or
  NOT_OP: 'NOT_OP',       // !, not
  LPAREN: 'LPAREN',       // (
  RPAREN: 'RPAREN',       // )
  LBRACE: 'LBRACE',       // {
  RBRACE: 'RBRACE',       // }
  COMMA: 'COMMA',         // ,
  EOF: 'EOF'
};

/**
 * Tokenizer
 */
class FilterTokenizer {
  constructor(input) {
    this.input = String(input || '').trim();
    this.pos = 0;
    this.len = this.input.length;
  }

  tokenize() {
    const tokens = [];
    while (this.pos < this.len) {
      this._skipWhitespace();
      if (this.pos >= this.len) break;

      const ch = this.input[this.pos];
      const startPos = this.pos;

      // Parentheses & Braces
      if (ch === '(') {
        tokens.push({ type: TOKEN_TYPES.LPAREN, value: '(', offset: startPos });
        this.pos++;
        continue;
      }
      if (ch === ')') {
        tokens.push({ type: TOKEN_TYPES.RPAREN, value: ')', offset: startPos });
        this.pos++;
        continue;
      }
      if (ch === '{') {
        tokens.push({ type: TOKEN_TYPES.LBRACE, value: '{', offset: startPos });
        this.pos++;
        continue;
      }
      if (ch === '}') {
        tokens.push({ type: TOKEN_TYPES.RBRACE, value: '}', offset: startPos });
        this.pos++;
        continue;
      }
      if (ch === ',') {
        tokens.push({ type: TOKEN_TYPES.COMMA, value: ',', offset: startPos });
        this.pos++;
        continue;
      }

      // Logical operators: &&, ||, !
      if (this.input.startsWith('&&', this.pos)) {
        tokens.push({ type: TOKEN_TYPES.LOGIC_OP, value: '&&', offset: startPos });
        this.pos += 2;
        continue;
      }
      if (this.input.startsWith('||', this.pos)) {
        tokens.push({ type: TOKEN_TYPES.LOGIC_OP, value: '||', offset: startPos });
        this.pos += 2;
        continue;
      }
      if (ch === '!' && !this.input.startsWith('!=', this.pos)) {
        tokens.push({ type: TOKEN_TYPES.NOT_OP, value: '!', offset: startPos });
        this.pos++;
        continue;
      }

      // Comparison operators: ==, !=, <=, >=, <, >
      if (this.input.startsWith('==', this.pos)) {
        tokens.push({ type: TOKEN_TYPES.COMP_OP, value: '==', offset: startPos });
        this.pos += 2;
        continue;
      }
      if (this.input.startsWith('!=', this.pos)) {
        tokens.push({ type: TOKEN_TYPES.COMP_OP, value: '!=', offset: startPos });
        this.pos += 2;
        continue;
      }
      if (this.input.startsWith('<=', this.pos)) {
        tokens.push({ type: TOKEN_TYPES.COMP_OP, value: '<=', offset: startPos });
        this.pos += 2;
        continue;
      }
      if (this.input.startsWith('>=', this.pos)) {
        tokens.push({ type: TOKEN_TYPES.COMP_OP, value: '>=', offset: startPos });
        this.pos += 2;
        continue;
      }
      if (ch === '<') {
        tokens.push({ type: TOKEN_TYPES.COMP_OP, value: '<', offset: startPos });
        this.pos++;
        continue;
      }
      if (ch === '>') {
        tokens.push({ type: TOKEN_TYPES.COMP_OP, value: '>', offset: startPos });
        this.pos++;
        continue;
      }

      // Quoted Strings: "..." or '...'
      if (ch === '"' || ch === "'") {
        const quote = ch;
        this.pos++;
        let strVal = '';
        while (this.pos < this.len && this.input[this.pos] !== quote) {
          if (this.input[this.pos] === '\\' && this.pos + 1 < this.len) {
            this.pos++;
            strVal += this.input[this.pos];
          } else {
            strVal += this.input[this.pos];
          }
          this.pos++;
        }
        if (this.pos >= this.len) {
          throw new FilterSyntaxError(`Unterminated string literal starting at position ${startPos}`, startPos);
        }
        this.pos++; // consume closing quote
        tokens.push({ type: TOKEN_TYPES.STRING, value: strVal, offset: startPos });
        continue;
      }

      // Word / Identifier / Keyword / Number / IP / MAC
      const wordMatch = this.input.slice(this.pos).match(/^([a-zA-Z0-9_.:/-]+)/);
      if (wordMatch) {
        const raw = wordMatch[1];
        const lower = raw.toLowerCase();
        this.pos += raw.length;

        // Named logical / comparison keywords
        if (lower === 'and') {
          tokens.push({ type: TOKEN_TYPES.LOGIC_OP, value: '&&', offset: startPos });
          continue;
        }
        if (lower === 'or') {
          tokens.push({ type: TOKEN_TYPES.LOGIC_OP, value: '||', offset: startPos });
          continue;
        }
        if (lower === 'not') {
          tokens.push({ type: TOKEN_TYPES.NOT_OP, value: '!', offset: startPos });
          continue;
        }
        if (lower === 'eq') {
          tokens.push({ type: TOKEN_TYPES.COMP_OP, value: '==', offset: startPos });
          continue;
        }
        if (lower === 'ne') {
          tokens.push({ type: TOKEN_TYPES.COMP_OP, value: '!=', offset: startPos });
          continue;
        }
        if (lower === 'gt') {
          tokens.push({ type: TOKEN_TYPES.COMP_OP, value: '>', offset: startPos });
          continue;
        }
        if (lower === 'lt') {
          tokens.push({ type: TOKEN_TYPES.COMP_OP, value: '<', offset: startPos });
          continue;
        }
        if (lower === 'ge') {
          tokens.push({ type: TOKEN_TYPES.COMP_OP, value: '>=', offset: startPos });
          continue;
        }
        if (lower === 'le') {
          tokens.push({ type: TOKEN_TYPES.COMP_OP, value: '<=', offset: startPos });
          continue;
        }
        if (lower === 'contains') {
          tokens.push({ type: TOKEN_TYPES.COMP_OP, value: 'contains', offset: startPos });
          continue;
        }
        if (lower === 'matches') {
          tokens.push({ type: TOKEN_TYPES.COMP_OP, value: 'matches', offset: startPos });
          continue;
        }
        if (lower === 'in') {
          tokens.push({ type: TOKEN_TYPES.COMP_OP, value: 'in', offset: startPos });
          continue;
        }

        // MAC Address (e.g. 00:1A:2B:3C:4D:5E or 00-1a-2b-3c-4d-5e)
        if (/^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$/.test(raw)) {
          tokens.push({ type: TOKEN_TYPES.MAC_ADDR, value: raw.replace(/-/g, ':').toUpperCase(), offset: startPos });
          continue;
        }

        // IPv4 Address
        if (/^(\d{1,3}\.){3}\d{1,3}$/.test(raw)) {
          tokens.push({ type: TOKEN_TYPES.IP_ADDR, value: raw, offset: startPos });
          continue;
        }

        // Hex number (e.g. 0x0800)
        if (/^0x[0-9a-fA-F]+$/i.test(raw)) {
          tokens.push({ type: TOKEN_TYPES.HEX_NUM, value: parseInt(raw, 16), raw, offset: startPos });
          continue;
        }

        // Integer Number
        if (/^\d+$/.test(raw)) {
          tokens.push({ type: TOKEN_TYPES.NUMBER, value: parseInt(raw, 10), raw, offset: startPos });
          continue;
        }

        // Field or protocol identifier (e.g. ip.addr, tcp.flags.syn, http, dns)
        tokens.push({ type: TOKEN_TYPES.FIELD, value: lower, raw, offset: startPos });
        continue;
      }

      throw new FilterSyntaxError(`Unexpected character '${ch}' at position ${startPos}`, startPos);
    }

    tokens.push({ type: TOKEN_TYPES.EOF, value: '', offset: this.pos });
    return tokens;
  }

  _skipWhitespace() {
    while (this.pos < this.len && /\s/.test(this.input[this.pos])) {
      this.pos++;
    }
  }
}

/**
 * AST Nodes:
 * - BinaryOp: { type: 'LogicalOp', op: '&&'|'||', left, right }
 * - UnaryOp: { type: 'NotOp', expr }
 * - Comparison: { type: 'Comparison', field, op: '=='|'!='|... , value }
 * - ProtocolPresence: { type: 'ProtocolPresence', protocol }
 * - FieldPresence: { type: 'FieldPresence', field }
 */

class FilterParser {
  constructor(tokens) {
    this.tokens = tokens;
    this.idx = 0;
  }

  current() {
    return this.tokens[this.idx] || { type: TOKEN_TYPES.EOF, value: '', offset: 0 };
  }

  peek(offset = 1) {
    return this.tokens[this.idx + offset] || { type: TOKEN_TYPES.EOF, value: '', offset: 0 };
  }

  consume(expectedType = null) {
    const tok = this.current();
    if (expectedType && tok.type !== expectedType) {
      throw new FilterSyntaxError(
        `Expected ${expectedType} but found '${tok.value}' (${tok.type}) at position ${tok.offset}`,
        tok.offset
      );
    }
    this.idx++;
    return tok;
  }

  parse() {
    if (this.current().type === TOKEN_TYPES.EOF) {
      return null; // Empty filter matches all
    }
    const ast = this.parseOr();
    if (this.current().type !== TOKEN_TYPES.EOF) {
      const tok = this.current();
      throw new FilterSyntaxError(`Unexpected trailing token '${tok.value}' at position ${tok.offset}`, tok.offset);
    }
    return ast;
  }

  parseOr() {
    let left = this.parseAnd();
    while (this.current().type === TOKEN_TYPES.LOGIC_OP && this.current().value === '||') {
      this.consume();
      const right = this.parseAnd();
      left = { type: 'LogicalOp', op: '||', left, right };
    }
    return left;
  }

  parseAnd() {
    let left = this.parseUnary();
    while (this.current().type === TOKEN_TYPES.LOGIC_OP && this.current().value === '&&') {
      this.consume();
      const right = this.parseUnary();
      left = { type: 'LogicalOp', op: '&&', left, right };
    }
    return left;
  }

  parseUnary() {
    if (this.current().type === TOKEN_TYPES.NOT_OP) {
      const notTok = this.consume();
      const expr = this.parseUnary();
      return { type: 'NotOp', expr, offset: notTok.offset };
    }
    return this.parsePrimary();
  }

  parsePrimary() {
    const tok = this.current();

    // Grouping: ( expr )
    if (tok.type === TOKEN_TYPES.LPAREN) {
      this.consume(TOKEN_TYPES.LPAREN);
      const expr = this.parseOr();
      this.consume(TOKEN_TYPES.RPAREN);
      return expr;
    }

    // Comparison or Presence
    if (tok.type === TOKEN_TYPES.FIELD) {
      const fieldTok = this.consume(TOKEN_TYPES.FIELD);
      const nextTok = this.current();

      if (nextTok.type === TOKEN_TYPES.COMP_OP) {
        const opTok = this.consume(TOKEN_TYPES.COMP_OP);
        if (opTok.value === 'in') {
          if (this.current().type !== TOKEN_TYPES.LBRACE) {
            throw new FilterSyntaxError(`Expected '{' after 'in' operator at position ${this.current().offset}`, this.current().offset);
          }
          this.consume(TOKEN_TYPES.LBRACE);
          const setValues = [];
          while (this.current().type !== TOKEN_TYPES.RBRACE && this.current().type !== TOKEN_TYPES.EOF) {
            const itemTok = this.current();
            if (
              itemTok.type !== TOKEN_TYPES.NUMBER &&
              itemTok.type !== TOKEN_TYPES.HEX_NUM &&
              itemTok.type !== TOKEN_TYPES.STRING &&
              itemTok.type !== TOKEN_TYPES.IP_ADDR &&
              itemTok.type !== TOKEN_TYPES.FIELD
            ) {
              throw new FilterSyntaxError(`Expected value in set at position ${itemTok.offset}`, itemTok.offset);
            }
            this.consume();
            setValues.push(itemTok.value);
            if (this.current().type === TOKEN_TYPES.COMMA) {
              this.consume(TOKEN_TYPES.COMMA);
              if (this.current().type === TOKEN_TYPES.RBRACE) {
                throw new FilterSyntaxError(`Unexpected trailing comma in set at position ${this.current().offset}`, this.current().offset);
              }
            } else {
              break;
            }
          }
          this.consume(TOKEN_TYPES.RBRACE);
          return {
            type: 'Comparison',
            field: fieldTok.value,
            op: 'in',
            value: setValues,
            rawVal: setValues,
            offset: fieldTok.offset
          };
        }

        const valTok = this.current();
        if (
          valTok.type !== TOKEN_TYPES.NUMBER &&
          valTok.type !== TOKEN_TYPES.HEX_NUM &&
          valTok.type !== TOKEN_TYPES.STRING &&
          valTok.type !== TOKEN_TYPES.IP_ADDR &&
          valTok.type !== TOKEN_TYPES.MAC_ADDR &&
          valTok.type !== TOKEN_TYPES.FIELD
        ) {
          throw new FilterSyntaxError(
            `Expected value after operator '${opTok.value}' at position ${valTok.offset}`,
            valTok.offset
          );
        }
        this.consume();
        return {
          type: 'Comparison',
          field: fieldTok.value,
          op: opTok.value,
          value: valTok.value,
          rawVal: valTok.raw !== undefined ? valTok.raw : valTok.value,
          offset: fieldTok.offset
        };
      }

      // Standalone protocol keyword or field presence (e.g. "tcp", "http", "arp", "dns", "ip.addr")
      return {
        type: 'Presence',
        identifier: fieldTok.value,
        offset: fieldTok.offset
      };
    }

    throw new FilterSyntaxError(`Unexpected token '${tok.value}' at position ${tok.offset}`, tok.offset);
  }
}

/**
 * Filter Evaluator
 */
class FilterEvaluator {
  /**
   * Extract field value from frame object
   * Supports both flat frame summaries and deep packet dissections
   */
  static extractFieldValue(frame, fieldName) {
    if (!frame) return undefined;
    const lower = fieldName.toLowerCase();

    // Direct byte-accurate field lookup from dissectDetailed
    if (frame.fields && frame.fields[lower] !== undefined) {
      const f = frame.fields[lower];
      return f?.value !== undefined ? f.value : f;
    }

    // Dissected layers lookup
    const d = frame.dissection || frame;
    const layers = d.layers || {};

    switch (lower) {
      // IP addresses (L3)
      case 'ip.addr':
        return [
          frame.srcIp,
          frame.dstIp,
          layers.ipv4?.srcIp,
          layers.ipv4?.dstIp,
          layers.ip?.srcIp,
          layers.ip?.dstIp
        ].filter(Boolean);
      case 'ip.src':
      case 'ip.src_host':
        return frame.srcIp || layers.ipv4?.srcIp || layers.ip?.srcIp;
      case 'ip.dst':
      case 'ip.dst_host':
        return frame.dstIp || layers.ipv4?.dstIp || layers.ip?.dstIp;
      case 'ip.proto':
        return layers.ipv4?.protocolNum || layers.ipv4?.protocol || layers.ip?.protocolNum || frame.ip?.proto || (frame.protocol === 'TCP' ? 6 : (frame.protocol === 'UDP' ? 17 : (frame.protocol === 'ICMP' ? 1 : undefined)));
      case 'ip.ttl':
        return layers.ipv4?.ttl || layers.ip?.ttl;
      case 'ip.len':
        return layers.ipv4?.totalLength || layers.ip?.totalLength || frame.wireLength || frame.length;

      // IPv6
      case 'ipv6.addr':
        return [frame.srcIp, frame.dstIp, layers.ipv6?.srcIp, layers.ipv6?.dstIp].filter(Boolean);
      case 'ipv6.src':
        return frame.srcIp || layers.ipv6?.srcIp;
      case 'ipv6.dst':
        return frame.dstIp || layers.ipv6?.dstIp;

      // Ethernet (L2)
      case 'eth.addr':
        return [layers.ethernet?.srcMac, layers.ethernet?.dstMac].filter(Boolean);
      case 'eth.src':
        return layers.ethernet?.srcMac;
      case 'eth.dst':
        return layers.ethernet?.dstMac;
      case 'eth.type':
        return layers.ethernet?.etherType || layers.ethernet?.etherTypeName;

      // TCP (L4)
      case 'tcp.port':
        return [
          frame.srcPort,
          frame.dstPort,
          layers.tcp?.srcPort,
          layers.tcp?.dstPort
        ].filter(v => v !== undefined && v !== null);
      case 'tcp.srcport':
        return frame.srcPort || layers.tcp?.srcPort;
      case 'tcp.dstport':
        return frame.dstPort || layers.tcp?.dstPort;
      case 'tcp.seq':
        return layers.tcp?.seqNum ?? layers.tcp?.seq;
      case 'tcp.ack':
        return layers.tcp?.ackNum ?? layers.tcp?.ack;
      case 'tcp.window_size':
      case 'tcp.window':
        return layers.tcp?.windowSize;
      case 'tcp.stream':
        return frame.tcpAnalysis?.streamId ?? frame.streamId;
      case 'tcp.len':
        return layers.tcp?.payloadLength ?? layers.tcp?.payloadBytes ?? 0;
      case 'tcp.flags.syn':
        return Boolean(layers.tcp?.flags?.syn ?? frame.tcp?.flags?.syn);
      case 'tcp.flags.ack':
        return Boolean(layers.tcp?.flags?.ack ?? frame.tcp?.flags?.ack);
      case 'tcp.flags.rst':
        return Boolean(layers.tcp?.flags?.rst ?? frame.tcp?.flags?.rst);
      case 'tcp.flags.fin':
        return Boolean(layers.tcp?.flags?.fin ?? frame.tcp?.flags?.fin);
      case 'tcp.flags.psh':
        return Boolean(layers.tcp?.flags?.psh ?? frame.tcp?.flags?.psh);
      case 'tcp.flags.urg':
        return Boolean(layers.tcp?.flags?.urg ?? frame.tcp?.flags?.urg);
      case 'tcp.analysis.keep_alive':
      case 'tcp.analysis.keepalive':
      case 'tcp.keepalive':
      case 'keepalive':
        return Boolean(frame.isKeepAlive || frame.isKeepAliveAck || frame.tcpAnalysis?.isKeepAlive || frame.tcpAnalysis?.isKeepAliveAck || frame.tcpDeltaStatus === 'KEEP_ALIVE');

      // UDP (L4)
      case 'udp.port':
        return [
          frame.srcPort,
          frame.dstPort,
          layers.udp?.srcPort,
          layers.udp?.dstPort
        ].filter(v => v !== undefined && v !== null);
      case 'udp.srcport':
        return frame.srcPort || layers.udp?.srcPort;
      case 'udp.dstport':
        return frame.dstPort || layers.udp?.dstPort;
      case 'udp.length':
        return layers.udp?.length;

      // ICMP
      case 'icmp.type':
        return layers.icmp?.icmpType ?? layers.transport?.icmpType;
      case 'icmp.code':
        return layers.icmp?.code ?? layers.transport?.code;

      // DNS (L7)
      case 'dns.qry.name':
      case 'dns.name': {
        const dnsObj = layers.application?.dns || layers.dns || layers.application || frame.dns;
        const qNames = (dnsObj?.questions || []).map(q => q.name);
        if (dnsObj?.queryName) qNames.push(dnsObj.queryName);
        if (dnsObj?.qname) qNames.push(dnsObj.qname);
        return qNames.length > 0 ? (qNames.length === 1 ? qNames[0] : qNames) : (frame.info || frame.summary || '');
      }
      case 'dns.flags.response':
        return Boolean(layers.dns?.isResponse ?? layers.application?.isResponse);
      case 'dns.id':
        return layers.dns?.transactionId ?? layers.application?.transactionId;

      // HTTP (L7)
      case 'http.request.method':
        return layers.application?.method ?? layers.http?.method;
      case 'http.request.uri':
      case 'http.uri':
        return layers.application?.uri ?? layers.http?.uri;
      case 'http.response.code':
      case 'http.status_code':
        return layers.application?.statusCode ?? layers.http?.statusCode;
      case 'http.host':
        return layers.application?.host ?? layers.http?.host;

      // TLS (L7)
      case 'tls.handshake.extensions_server_name':
      case 'tls.sni':
        return layers.application?.handshake?.sni ?? layers.tls?.handshake?.sni ?? frame.sni;
      case 'tls.handshake.type':
        return layers.application?.handshake?.type ?? layers.tls?.handshake?.type;
      case 'tls.version':
        return layers.application?.version ?? layers.tls?.version;

      // Frame metadata
      case 'frame.len':
      case 'frame.length':
        return frame.wireLength ?? frame.length ?? frame.frameLengthBytes ?? 0;
      case 'frame.number':
        return frame.frameNumber ?? frame.index;
      case 'frame.time':
        return frame.timestamp;

      // General fallback
      default: {
        if (frame[fieldName] !== undefined) return frame[fieldName];
        if (layers[fieldName] !== undefined) return layers[fieldName];
        if (frame[lower] !== undefined) return frame[lower];
        if (layers[lower] !== undefined) return layers[lower];
        // Support deep nested dot-notation path evaluation (e.g. "tcp.flags.syn", "ip.hdr.version")
        if (fieldName.includes('.')) {
          const parts = fieldName.split('.');
          let cur = frame;
          for (const p of parts) {
            if (cur && typeof cur === 'object' && p in cur) {
              cur = cur[p];
            } else {
              cur = undefined;
              break;
            }
          }
          if (cur !== undefined) return cur;

          let layerCur = layers;
          for (const p of parts) {
            if (layerCur && typeof layerCur === 'object' && p in layerCur) {
              layerCur = layerCur[p];
            } else {
              layerCur = undefined;
              break;
            }
          }
          if (layerCur !== undefined) return layerCur;
        }
        return undefined;
      }
    }
  }

  /**
   * Check if protocol or field is present in frame
   */
  static checkPresence(frame, identifier) {
    if (!frame) return false;
    const lower = identifier.toLowerCase();
    const proto = (frame.protocol || '').toLowerCase();
    const d = frame.dissection || frame;
    const layers = d.layers || {};

    // Protocol check
    if (proto === lower) return true;
    if (layers[lower]) return true;

    // Common protocols
    if (lower === 'tcp') return proto === 'tcp' || Boolean(layers.tcp);
    if (lower === 'udp') return proto === 'udp' || Boolean(layers.udp);
    if (lower === 'icmp') return proto === 'icmp' || Boolean(layers.icmp) || proto.includes('icmp');
    if (lower === 'arp') return proto === 'arp' || Boolean(layers.arp);
    if (lower === 'dns') return proto === 'dns' || layers.dns || layers.application?.type === 'DNS' || frame.dstPort === 53 || frame.srcPort === 53;
    if (lower === 'http') return proto === 'http' || layers.http || layers.application?.type === 'REQUEST' || layers.application?.type === 'RESPONSE';
    if (lower === 'tls') return proto === 'tls' || layers.tls || layers.application?.type === 'TLS' || frame.dstPort === 443 || frame.srcPort === 443;
    if (lower === 'ip' || lower === 'ipv4') return Boolean(layers.ipv4 || layers.ip || frame.srcIp);
    if (lower === 'ipv6') return Boolean(layers.ipv6);
    if (lower === 'vlan') return Boolean(frame.vlan || layers.vlan);
    if (lower === 'keepalive' || lower === 'tcp.keepalive' || lower === 'tcp.analysis.keep_alive') {
      return Boolean(frame.isKeepAlive || frame.isKeepAliveAck || frame.tcpAnalysis?.isKeepAlive || frame.tcpAnalysis?.isKeepAliveAck || frame.tcpDeltaStatus === 'KEEP_ALIVE');
    }

    // If identifier is a field, check if non-empty
    const val = this.extractFieldValue(frame, lower);
    return val !== undefined && val !== null && val !== false && val !== '';
  }

  /**
   * Evaluate comparison node against frame
   */
  static evaluateComparison(node, frame) {
    const targetVal = node.value;
    const actualVal = this.extractFieldValue(frame, node.field);

    if (actualVal === undefined || actualVal === null) {
      return node.op === '!=';
    }

    if (node.op === 'in') {
      const set = Array.isArray(targetVal) ? targetVal : [targetVal];
      if (Array.isArray(actualVal)) {
        return actualVal.some(a => set.some(s => String(a).toLowerCase() === String(s).toLowerCase() || Number(a) === Number(s)));
      }
      return set.some(s => String(actualVal).toLowerCase() === String(s).toLowerCase() || Number(actualVal) === Number(s));
    }

    // If actual value is array (e.g. ip.addr returns [src, dst]), any match satisfies comparison
    if (Array.isArray(actualVal)) {
      if (node.op === '!=') {
        return actualVal.every(v => this._comparePrimitives(v, node.op, targetVal));
      }
      return actualVal.some(v => this._comparePrimitives(v, node.op, targetVal));
    }

    return this._comparePrimitives(actualVal, node.op, targetVal);
  }

  static _comparePrimitives(actual, op, target) {
    // String comparisons
    if (typeof actual === 'string' && typeof target === 'string') {
      const a = actual.toLowerCase();
      const b = target.toLowerCase();
      switch (op) {
        case '==': return a === b;
        case '!=': return a !== b;
        case 'contains': return a.includes(b);
        case 'matches': {
          try {
            return new RegExp(target, 'i').test(actual);
          } catch {
            return false;
          }
        }
        case '>': return a > b;
        case '<': return a < b;
        case '>=': return a >= b;
        case '<=': return a <= b;
      }
    }

    // Number comparisons
    const numA = Number(actual);
    const numB = Number(target);
    if (!isNaN(numA) && !isNaN(numB)) {
      switch (op) {
        case '==': return numA === numB;
        case '!=': return numA !== numB;
        case '>': return numA > numB;
        case '<': return numA < numB;
        case '>=': return numA >= numB;
        case '<=': return numA <= numB;
      }
    }

    // Boolean comparisons
    if (typeof actual === 'boolean') {
      const targetBool = target === true || target === 'true' || target === 1 || target === '1';
      if (op === '==') return actual === targetBool;
      if (op === '!=') return actual !== targetBool;
    }

    // Fallback equality
    if (op === '==') return String(actual).toLowerCase() === String(target).toLowerCase();
    if (op === '!=') return String(actual).toLowerCase() !== String(target).toLowerCase();
    if (op === 'contains') return String(actual).toLowerCase().includes(String(target).toLowerCase());

    return false;
  }

  /**
   * Recursively evaluate AST node against frame
   */
  static evaluate(node, frame) {
    if (!node) return true; // Empty filter matches all

    switch (node.type) {
      case 'LogicalOp': {
        if (node.op === '&&') {
          return this.evaluate(node.left, frame) && this.evaluate(node.right, frame);
        }
        if (node.op === '||') {
          return this.evaluate(node.left, frame) || this.evaluate(node.right, frame);
        }
        return false;
      }
      case 'NotOp': {
        return !this.evaluate(node.expr, frame);
      }
      case 'Comparison': {
        return this.evaluateComparison(node, frame);
      }
      case 'Presence': {
        return this.checkPresence(frame, node.identifier);
      }
      default:
        return false;
    }
  }
}

/**
 * Public Filter Compiler API
 */
function compileFilter(filterString) {
  const str = String(filterString || '').trim();
  if (!str) {
    return () => true;
  }

  const tokenizer = new FilterTokenizer(str);
  const tokens = tokenizer.tokenize();
  const parser = new FilterParser(tokens);
  const ast = parser.parse();

  return function filterFn(frame) {
    return FilterEvaluator.evaluate(ast, frame);
  };
}

function validateFilter(filterString) {
  const str = String(filterString || '').trim();
  if (!str) {
    return { valid: true };
  }

  try {
    const tokenizer = new FilterTokenizer(str);
    const tokens = tokenizer.tokenize();
    const parser = new FilterParser(tokens);
    const ast = parser.parse();
    return { valid: true, ast };
  } catch (err) {
    return {
      valid: false,
      error: err.message,
      offset: err.offset !== undefined ? err.offset : 0
    };
  }
}

function evaluateFilter(filterString, frame) {
  const filterFn = compileFilter(filterString);
  return filterFn(frame);
}

/**
 * AI-Assisted Natural-Language-to-Display-Filter Translator & Autocomplete Engine
 * Translates plain English operational queries into valid Wireshark-grade AST filter expressions.
 */
function translateNaturalLanguageToFilter(naturalQuery) {
  const q = String(naturalQuery || '').trim();
  if (!q) {
    return { filterExpression: '', translated: false, explanation: 'All wire packets (no filter applied).' };
  }

  // If already a valid structured filter expression, return directly
  const directCheck = validateFilter(q);
  if (directCheck.valid && /[=<>!&|.]/.test(q) && !/\s+(from|excluding|except|followed by|where|show|packets)\s+/i.test(q)) {
    return { filterExpression: q, translated: false, explanation: 'Valid structured display filter syntax.' };
  }

  const positiveClauses = [];
  const negativeClauses = [];
  const lower = q.toLowerCase();

  // Temporal sequence & compound TCP state detection (e.g. SYN followed by RST, handshake teardown)
  if ((/\bsyn\b/.test(lower) && /\b(rst|reset)\b/.test(lower)) || /\b(followed by|teardown|refused handshake)\b/.test(lower)) {
    positiveClauses.push('(tcp.flags.syn == 1 || tcp.flags.rst == 1)');
  } else {
    if (/\b(rst|reset|resets|rejected|refused)\b/.test(lower)) {
      positiveClauses.push('tcp.flags.rst == 1');
    }
    if (/\b(syn)\b/.test(lower) && !/\b(rst|reset)\b/.test(lower)) {
      positiveClauses.push('tcp.flags.syn == 1');
    }
  }

  // TCP Zero-Window / Window exhaustion / Bufferbloat stalls
  if (/\b(zero[- ]?window|window full|bufferbloat|stall)\b/.test(lower)) {
    positiveClauses.push('tcp.window_size == 0');
  }

  // TCP Duplicate ACK / Fast Retransmit
  if (/\b(dup[- ]?ack|duplicate[- ]?ack|fast[- ]?retransmit)\b/.test(lower)) {
    positiveClauses.push('tcp.analysis.duplicate_ack');
  }

  // TCP Retransmissions
  if (/\b(retransmit|retransmissions|packet drop)\b/.test(lower) && !positiveClauses.includes('tcp.analysis.retransmission')) {
    positiveClauses.push('tcp.analysis.retransmission');
  }

  // Path MTU Blackhole (RB-06)
  if (/\b(mtu[- ]?black[- ]?hole|pmtud|df flag|fragmentation needed)\b/.test(lower)) {
    positiveClauses.push('(ip.flags.df == 1 && ip.len > 1400) || icmp.type == 3');
  }

  // DHCP Starvation / DORA Flooding (RB-07)
  if (/\b(dhcp starvation|dhcp storm|rogue dhcp|dhcp discover flood|dhcp)\b/.test(lower)) {
    positiveClauses.push('(udp.port == 67 || udp.port == 68)');
  }

  // TCP Keep-Alive
  if (/\b(keep[- ]?alive)\b/.test(lower)) {
    positiveClauses.push('tcp.analysis.keep_alive');
  }

  // DNS / NXDOMAIN / SERVFAIL (RB-04)
  if (/\b(dns|servfail|nxdomain|rcode|lookup|domain)\b/.test(lower)) {
    if (/\b(servfail|nxdomain)\b/.test(lower)) {
      positiveClauses.push('(dns && dns.flags.rcode > 0)');
    } else {
      positiveClauses.push('dns');
    }
  }

  // TLS / SSL / Handshake / Alert / Certificate Mismatch (RB-05)
  if (/\b(tls|ssl|https|handshake|sni|certificate|alert)\b/.test(lower)) {
    if (/\b(alert|bad[- ]?cert|handshake[- ]?failure)\b/.test(lower)) {
      positiveClauses.push('(tls.record.type == 21 || (tls && tcp.flags.rst == 1))');
    } else {
      positiveClauses.push('(tls || tcp.port == 443)');
    }
  }

  // ICMP / Ping / MTU / Fragmentation
  if (/\b(icmp|ping|mtu|fragment)\b/.test(lower)) {
    positiveClauses.push('icmp');
  }

  // HTTP
  if (/\b(http)\b/.test(lower) && !/\b(https)\b/.test(lower)) {
    positiveClauses.push('http');
  }

  // ARP
  if (/\b(arp|mac|neighbor)\b/.test(lower)) {
    positiveClauses.push('arp');
  }

  // Multicast and Broadcast Noise (mDNS 5353, LLMNR 5355, WS-Discovery 3702, NetBIOS-NS 137, Limited Broadcast)
  if (/\b(multicast|broadcast|noise|llmnr|mdns|ws-discovery|netbios-ns|nbns)\b/.test(lower)) {
    positiveClauses.push('(udp.port == 5353 || udp.port == 5355 || udp.port == 3702 || udp.port == 137 || ip.dst == 255.255.255.255)');
  }

  // Cleartext HTTP flows (e.g. 10.168.195.33 <-> 10.22.10.153:80)
  if (/\b(cleartext|unencrypted http|http flows)\b/.test(lower)) {
    positiveClauses.push('(tcp.port == 80 || http)');
  }

  // Intel AMT (623) or Hyper-V (2179 / 172.29.192.1) sockets
  if (/\b(intel amt|amt|lms\.exe|hyper-v|vmconnect|vmms)\b/.test(lower)) {
    positiveClauses.push('(tcp.port == 623 || tcp.port == 2179 || ip.addr == 172.29.192.1)');
  }

  // Printer / JetDirect / Port 9100
  if (/\b(printer|jetdirect|9100|spooler)\b/.test(lower)) {
    positiveClauses.push('tcp.port == 9100');
  }

  // APIPA link-local
  if (/\b(apipa|169\.254)\b/.test(lower)) {
    positiveClauses.push('ip.addr == 169.254.8.1');
  }

  // Extract excluded IPs ("excluding 192.168.31.1", "except 10.0.0.1", "not 127.0.0.1")
  const exclusionRegex = /\b(?:excluding|except|without|not from|not)\s+(?:host\s+|ip\s+|gateway\s+)?(\d{1,3}(?:\.\d{1,3}){3})\b/gi;
  const excludedIps = new Set();
  let exMatch;
  while ((exMatch = exclusionRegex.exec(q)) !== null) {
    excludedIps.add(exMatch[1]);
    negativeClauses.push(`!(ip.addr == ${exMatch[1]})`);
  }

  // Extract positive IP addresses
  const allIps = q.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g) || [];
  for (const ip of allIps) {
    if (!excludedIps.has(ip) && !positiveClauses.some((c) => c.includes(ip))) {
      positiveClauses.push(`ip.addr == ${ip}`);
    }
  }

  // Extract port numbers
  const portMatch = q.match(/\bport\s+(\d{1,5})\b/i);
  if (portMatch) {
    positiveClauses.push(`tcp.port == ${portMatch[1]}`);
  }

  // Frame size / large packets / jumbo frames
  const lenMatch = q.match(/\b(?:larger than|greater than|size >|length >)\s*(\d+)\b/i);
  if (lenMatch) {
    positiveClauses.push(`frame.len > ${lenMatch[1]}`);
  }

  const joinOp = /\b(and|with|from|on|where)\b/i.test(lower) && !/\b(multicast and broadcast)\b/i.test(lower) ? ' && ' : ' || ';
  let synthesized = positiveClauses.length > 0 ? positiveClauses.join(joinOp) : (directCheck.valid ? q : 'tcp || udp || icmp');
  if (negativeClauses.length > 0) {
    synthesized = positiveClauses.length > 0
      ? `(${synthesized}) && ${negativeClauses.join(' && ')}`
      : negativeClauses.join(' && ');
  }

  return {
    filterExpression: synthesized,
    translated: true,
    explanation: `AI Multi-Clause Filter Compiler synthesized "${synthesized}" (with ${positiveClauses.length} match clause(s) and ${negativeClauses.length} exclusion(s)).`
  };
}

function getFilterAutocompleteSuggestions(prefix = '') {
  const catalog = [
    'ip.addr == 10.168.195.33',
    'ip.addr == 172.29.192.1',
    'ip.addr == 10.168.195.188',
    'ip.addr == 10.22.10.153 && tcp.port == 80',
    'udp.port == 5353 || udp.port == 5355 || udp.port == 3702 || udp.port == 137',
    'tcp.port == 623 || tcp.port == 2179',
    '(tcp.flags.syn == 1 || tcp.flags.rst == 1) && !(ip.addr == 127.0.0.1)',
    'tcp.window_size == 0',
    'tcp.port == 443',
    'tcp.port == 9100',
    'tcp.flags.syn == 1',
    'tcp.flags.rst == 1',
    'dns && udp.port == 53',
    'http || tls',
    'icmp'
  ];
  const clean = String(prefix || '').trim().toLowerCase();
  if (!clean) return catalog;
  return catalog.filter((item) => item.toLowerCase().includes(clean));
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    compileFilter,
    validateFilter,
    evaluateFilter,
    translateNaturalLanguageToFilter,
    getFilterAutocompleteSuggestions,
    FilterTokenizer,
    FilterParser,
    FilterEvaluator,
    FilterSyntaxError
  };
}

if (typeof window !== 'undefined') {
  window.FilterTokenizer = FilterTokenizer;
  window.FilterParser = FilterParser;
  window.FilterEvaluator = FilterEvaluator;
  window.FilterSyntaxError = FilterSyntaxError;
  window.compileFilter = compileFilter;
  window.validateFilter = validateFilter;
  window.evaluateFilter = evaluateFilter;
  window.translateNaturalLanguageToFilter = translateNaturalLanguageToFilter;
  window.getFilterAutocompleteSuggestions = getFilterAutocompleteSuggestions;
}
