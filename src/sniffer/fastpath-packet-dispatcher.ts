/**
 * EJII Zero-Copy Fast-Path Packet Dispatcher
 *
 * Line-rate packet classification, filtering, and DSCP remarking engine
 * executing over raw packet buffers with microsecond dispatch latency.
 * Dual-Maintenance TypeScript Reference.
 */

export interface FastpathRuleCriteria {
  srcIp?: string;
  dstIp?: string;
  protocol?: number; // 6 = TCP, 17 = UDP, 1 = ICMP
  port?: number;
  tcpFlags?: number;
}

export type FastpathAction = 'PASS' | 'DROP' | 'REDIRECT' | 'DSCP_REMARK' | 'TRAP_TO_BRAIN';

export interface FastpathRule {
  ruleId: string;
  criteria: FastpathRuleCriteria;
  action: FastpathAction;
  params: Record<string, any>;
  hitCount: number;
  installedAt: string;
}

export interface DispatchReceipt {
  action: FastpathAction;
  ruleId?: string;
  latencyNs: number;
  dscpRemark?: number;
  redirectInterface?: string;
}

export class FastpathPacketDispatcher {
  private rules: Map<string, FastpathRule> = new Map();
  private totalDispatched: number = 0;
  private totalDrops: number = 0;
  private totalTraps: number = 0;
  private totalLatencyNs: number = 0;

  constructor() {}

  public installRule(
    ruleId: string,
    criteria: FastpathRuleCriteria,
    action: FastpathAction,
    params: Record<string, any> = {}
  ): void {
    this.rules.set(ruleId, {
      ruleId,
      criteria,
      action,
      params,
      hitCount: 0,
      installedAt: new Date().toISOString()
    });
  }

  public removeRule(ruleId: string): boolean {
    return this.rules.delete(ruleId);
  }

  public dispatchPacket(packetBuffer: Buffer, offset: number = 0): DispatchReceipt {
    const startHr = process.hrtime.bigint();
    this.totalDispatched++;

    if (!packetBuffer || packetBuffer.length < offset + 14) {
      const latencyNs = Number(process.hrtime.bigint() - startHr);
      this.totalLatencyNs += latencyNs;
      return { action: 'DROP', latencyNs };
    }

    // Fast parse Ethernet + IP
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

    // Match rules in order of installation
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

  public getStats(): {
    totalDispatched: number;
    totalDrops: number;
    totalTraps: number;
    activeRulesCount: number;
    avgLatencyNs: number;
  } {
    const avgLatencyNs = this.totalDispatched > 0 ? this.totalLatencyNs / this.totalDispatched : 0;
    return {
      totalDispatched: this.totalDispatched,
      totalDrops: this.totalDrops,
      totalTraps: this.totalTraps,
      activeRulesCount: this.rules.size,
      avgLatencyNs: Math.round(avgLatencyNs)
    };
  }

  public reset(): void {
    this.rules.clear();
    this.totalDispatched = 0;
    this.totalDrops = 0;
    this.totalTraps = 0;
    this.totalLatencyNs = 0;
  }
}

export const fastpathPacketDispatcher = new FastpathPacketDispatcher();
