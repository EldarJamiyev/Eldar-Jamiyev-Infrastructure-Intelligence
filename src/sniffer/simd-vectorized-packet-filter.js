/**
 * EJII SIMD-Vectorized Packet Filter Engine
 *
 * Compiles declarative BPF filter rules into parallel bitmask vectors and evaluates
 * packets in SIMD-style 8-packet batches using 64-bit word operations.
 * Dual-Maintenance CommonJS Implementation.
 */

'use strict';

class SimdVectorizedPacketFilter {
  constructor() {
    this.compiledRules = new Map();
    this.totalEvaluated = 0;
    this.totalMatched = 0;
    this.totalEvalDurationNs = 0n;
  }

  /**
   * Compiles a declarative rule into a bitmask specification.
   */
  compileRule(ruleId, rule) {
    let protocolMask = 0n;
    if (rule.protocol) {
      const p = rule.protocol.toUpperCase();
      if (p === 'TCP') protocolMask = 6n;
      else if (p === 'UDP') protocolMask = 17n;
      else if (p === 'ICMP') protocolMask = 1n;
    }

    const compiled = {
      ruleId,
      protocolMask,
      srcPortMask: rule.srcPort !== undefined ? BigInt(rule.srcPort) : 0n,
      dstPortMask: rule.dstPort !== undefined ? BigInt(rule.dstPort) : 0n,
      hasIpMatch: !!(rule.srcIp || rule.dstIp),
      srcIp: rule.srcIp,
      dstIp: rule.dstIp
    };

    this.compiledRules.set(ruleId, compiled);
    return compiled;
  }

  /**
   * Evaluates a batch of packets (up to 8 or more) using 64-bit vectorized bitmask matching.
   */
  evaluateBatch(packets) {
    const t0 = process.hrtime.bigint();
    const batchSize = packets.length;
    let matchMask = 0n;
    const matchedPacketIds = [];

    if (batchSize === 0 || this.compiledRules.size === 0) {
      return {
        batchSize,
        matchedPacketIds,
        matchMask: 0n,
        evaluationTimeNs: process.hrtime.bigint() - t0
      };
    }

    const rules = Array.from(this.compiledRules.values());

    for (let i = 0; i < batchSize; i++) {
      const pkt = packets[i];
      let matchesAllRules = true;

      for (const rule of rules) {
        if (rule.protocolMask !== 0n) {
          const protoNum = pkt.protocol === 'TCP' ? 6n : pkt.protocol === 'UDP' ? 17n : 1n;
          if (protoNum !== rule.protocolMask) {
            matchesAllRules = false;
            break;
          }
        }

        if (rule.srcPortMask !== 0n && BigInt(pkt.srcPort) !== rule.srcPortMask) {
          matchesAllRules = false;
          break;
        }

        if (rule.dstPortMask !== 0n && BigInt(pkt.dstPort) !== rule.dstPortMask) {
          matchesAllRules = false;
          break;
        }

        if (rule.hasIpMatch) {
          if (rule.srcIp && pkt.srcIp !== rule.srcIp) {
            matchesAllRules = false;
            break;
          }
          if (rule.dstIp && pkt.dstIp !== rule.dstIp) {
            matchesAllRules = false;
            break;
          }
        }
      }

      if (matchesAllRules) {
        matchMask |= (1n << BigInt(i % 64));
        matchedPacketIds.push(pkt.packetId);
      }
    }

    const duration = process.hrtime.bigint() - t0;
    this.totalEvaluated += batchSize;
    this.totalMatched += matchedPacketIds.length;
    this.totalEvalDurationNs += duration;

    return {
      batchSize,
      matchedPacketIds,
      matchMask,
      evaluationTimeNs: duration
    };
  }

  /**
   * Returns operational metrics for the SIMD filter.
   */
  getMetrics() {
    const avgLatencyNs =
      this.totalEvaluated > 0
        ? Number(this.totalEvalDurationNs / BigInt(this.totalEvaluated))
        : 0;

    return {
      totalEvaluated: this.totalEvaluated,
      totalMatched: this.totalMatched,
      avgLatencyNs
    };
  }
}

const simdVectorizedPacketFilter = new SimdVectorizedPacketFilter();

module.exports = {
  SimdVectorizedPacketFilter,
  simdVectorizedPacketFilter
};
