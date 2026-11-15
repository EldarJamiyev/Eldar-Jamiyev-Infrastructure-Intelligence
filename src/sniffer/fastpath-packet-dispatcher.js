/**
 * EJII Zero-Copy Fast-Path Packet Dispatcher
 *
 * Line-rate packet classification, filtering, and DSCP remarking engine
 * executing over raw packet buffers with microsecond dispatch latency.
 * CommonJS Dual-Parity Implementation.
 */

'use strict';

class FastpathPacketDispatcher {
  constructor() {
    this.rules = new Map();
    this.totalDispatched = 0;
    this.totalDrops = 0;
    this.totalTraps = 0;
    this.totalLatencyNs = 0;
  }

  installRule(ruleId, criteria, action, params = {}) {
    this.rules.set(ruleId, {
      ruleId,
      criteria,
      action,
      params,
      hitCount: 0,
      installedAt: new Date().toISOString()
    });
  }

  removeRule(ruleId) {
    return this.rules.delete(ruleId);
  }

  dispatchPacket(packetBuffer, offset = 0) {
    const startHr = process.hrtime.bigint();
    this.totalDispatched++;

    if (!packetBuffer || packetBuffer.length < offset + 14) {
      const latencyNs = Number(process.hrtime.bigint() - startHr);
      this.totalLatencyNs += latencyNs;
      return { action: 'DROP', latencyNs };
    }

    const ethertype = (packetBuffer[offset + 12] << 8) | packetBuffer[offset + 13];
    let ipOffset = offset + 14;
    if (ethertype === 0x8100 || ethertype === 0x88a8) {
      ipOffset = offset + 18;
    }

    let srcIp = '';
    let dstIp = '';
    let protocol = 0;
    let srcPort = 0;
    let dstPort = 0;
    let tcpFlags = 0;

    if (packetBuffer.length >= ipOffset + 20) {
      const verIhl = packetBuffer[ipOffset];
      const ver = (verIhl >> 4) & 0x0f;

      if (ver === 4) {
        protocol = packetBuffer[ipOffset + 9];
        srcIp = `${packetBuffer[ipOffset + 12]}.${packetBuffer[ipOffset + 13]}.${packetBuffer[ipOffset + 14]}.${packetBuffer[ipOffset + 15]}`;
        dstIp = `${packetBuffer[ipOffset + 16]}.${packetBuffer[ipOffset + 17]}.${packetBuffer[ipOffset + 18]}.${packetBuffer[ipOffset + 19]}`;
        const ihlBytes = (verIhl & 0x0f) * 4;
        const transportOffset = ipOffset + ihlBytes;

        if (packetBuffer.length >= transportOffset + 4) {
          srcPort = (packetBuffer[transportOffset] << 8) | packetBuffer[transportOffset + 1];
          dstPort = (packetBuffer[transportOffset + 2] << 8) | packetBuffer[transportOffset + 3];
          if (protocol === 6 && packetBuffer.length >= transportOffset + 14) {
            tcpFlags = packetBuffer[transportOffset + 13];
          }
        }
      }
    }

    for (const rule of this.rules.values()) {
      const c = rule.criteria;
      if (c.protocol !== undefined && c.protocol !== protocol) continue;
      if (c.srcIp !== undefined && c.srcIp !== srcIp) continue;
      if (c.dstIp !== undefined && c.dstIp !== dstIp) continue;
      if (c.port !== undefined && c.port !== srcPort && c.port !== dstPort) continue;
      if (c.tcpFlags !== undefined && (tcpFlags & c.tcpFlags) !== c.tcpFlags) continue;

      rule.hitCount++;
      if (rule.action === 'DROP') {
        this.totalDrops++;
      } else if (rule.action === 'TRAP_TO_BRAIN') {
        this.totalTraps++;
      }

      const latencyNs = Number(process.hrtime.bigint() - startHr);
      this.totalLatencyNs += latencyNs;

      return {
        action: rule.action,
        ruleId: rule.ruleId,
        latencyNs,
        dscpRemark: rule.params?.dscpRemark,
        redirectInterface: rule.params?.redirectInterface
      };
    }

    const latencyNs = Number(process.hrtime.bigint() - startHr);
    this.totalLatencyNs += latencyNs;
    return { action: 'PASS', latencyNs };
  }

  getStats() {
    const avgLatencyNs = this.totalDispatched > 0 ? this.totalLatencyNs / this.totalDispatched : 0;
    return {
      totalDispatched: this.totalDispatched,
      totalDrops: this.totalDrops,
      totalTraps: this.totalTraps,
      activeRulesCount: this.rules.size,
      avgLatencyNs: Math.round(avgLatencyNs)
    };
  }

  reset() {
    this.rules.clear();
    this.totalDispatched = 0;
    this.totalDrops = 0;
    this.totalTraps = 0;
    this.totalLatencyNs = 0;
  }
}

const fastpathPacketDispatcher = new FastpathPacketDispatcher();

module.exports = {
  FastpathPacketDispatcher,
  fastpathPacketDispatcher
};
