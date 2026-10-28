// src/topology/multipath-qos-auditor.ts
/**
 * Multi-Path DSCP/ECN QoS Auditor & Path MTU Analyzer
 * Audits 6-bit DSCP (RFC 4594), 2-bit ECN (RFC 3168), QoS bleaching, and PMTU blackhole risks.
 */

export interface DscpClassInfo {
  readonly dscpValue: number;
  readonly name: string;
  readonly description: string;
  readonly category: 'STANDARD' | 'ASSURED_FORWARDING' | 'EXPEDITED_FORWARDING' | 'NETWORK_CONTROL' | 'CUSTOM';
}

export interface EcnStatusInfo {
  readonly ecnValue: number;
  readonly code: 'NOT_ECT' | 'ECT_1' | 'ECT_0' | 'CE';
  readonly isCongested: boolean;
  readonly description: string;
}

export interface QosAuditViolation {
  readonly type: 'QOS_BLEACHING' | 'ECN_CONGESTION_ALERT' | 'PMTU_FRAGMENTATION_RISK';
  readonly severity: 'INFO' | 'MEDIUM' | 'HIGH';
  readonly description: string;
  readonly packetIndex?: number;
  readonly flowKey?: string;
  readonly bleachingProvenance?: 'SINGLE_OBSERVATION_POINT_INFERENCE' | 'MULTI_HOP_CONFIRMED';
}

export interface QosAuditReport {
  readonly totalPacketsAudited: number;
  readonly dscpDistribution: Readonly<Record<string, number>>;
  readonly ecnDistribution: Readonly<Record<string, number>>;
  readonly pmtuDistribution: {
    readonly normalFramesCount: number;
    readonly largeFramesCount: number; // > 1472 bytes
    readonly dfBitSetCount: number;
    readonly pmtuRiskCount: number;
  };
  readonly activeEcnCongestionCount: number;
  readonly violations: readonly QosAuditViolation[];
  readonly observationScopeNote?: string;
}

export const DSCP_RFC4594_MAP: Record<number, DscpClassInfo> = {
  0: { dscpValue: 0, name: 'CS0 (Default)', description: 'Best Effort / Standard Traffic', category: 'STANDARD' },
  8: { dscpValue: 8, name: 'CS1 (Scavenger)', description: 'Low Priority / Bulk Transfers', category: 'STANDARD' },
  10: { dscpValue: 10, name: 'AF11', description: 'Assured Forwarding 11 (Low Drop)', category: 'ASSURED_FORWARDING' },
  12: { dscpValue: 12, name: 'AF12', description: 'Assured Forwarding 12 (Med Drop)', category: 'ASSURED_FORWARDING' },
  14: { dscpValue: 14, name: 'AF13', description: 'Assured Forwarding 13 (High Drop)', category: 'ASSURED_FORWARDING' },
  16: { dscpValue: 16, name: 'CS2 (OAM)', description: 'Operations, Administration, and Maintenance', category: 'STANDARD' },
  18: { dscpValue: 18, name: 'AF21', description: 'Assured Forwarding 21 (Low Drop)', category: 'ASSURED_FORWARDING' },
  20: { dscpValue: 20, name: 'AF22', description: 'Assured Forwarding 22 (Med Drop)', category: 'ASSURED_FORWARDING' },
  22: { dscpValue: 22, name: 'AF23', description: 'Assured Forwarding 23 (High Drop)', category: 'ASSURED_FORWARDING' },
  24: { dscpValue: 24, name: 'CS3 (Broadcast Video)', description: 'Broadcast Video / Call Signaling', category: 'STANDARD' },
  26: { dscpValue: 26, name: 'AF31', description: 'Assured Forwarding 31 (Low Drop)', category: 'ASSURED_FORWARDING' },
  28: { dscpValue: 28, name: 'AF32', description: 'Assured Forwarding 32 (Med Drop)', category: 'ASSURED_FORWARDING' },
  30: { dscpValue: 30, name: 'AF33', description: 'Assured Forwarding 33 (High Drop)', category: 'ASSURED_FORWARDING' },
  32: { dscpValue: 32, name: 'CS4 (Real-Time Interactive)', description: 'Real-Time Interactive / Gaming', category: 'STANDARD' },
  34: { dscpValue: 34, name: 'AF41', description: 'Assured Forwarding 41 (Video Streaming)', category: 'ASSURED_FORWARDING' },
  36: { dscpValue: 36, name: 'AF42', description: 'Assured Forwarding 42 (Interactive Video)', category: 'ASSURED_FORWARDING' },
  38: { dscpValue: 38, name: 'AF43', description: 'Assured Forwarding 43 (High Drop Video)', category: 'ASSURED_FORWARDING' },
  40: { dscpValue: 40, name: 'CS5 (Signaling)', description: 'Signaling / Media Control', category: 'STANDARD' },
  44: { dscpValue: 44, name: 'VA (44)', description: 'Voice Admit (RFC 5865)', category: 'EXPEDITED_FORWARDING' },
  46: { dscpValue: 46, name: 'EF (46)', description: 'Expedited Forwarding (Telephony / VoIP)', category: 'EXPEDITED_FORWARDING' },
  48: { dscpValue: 48, name: 'CS6 (48)', description: 'Network Control (BGP, OSPF, STP)', category: 'NETWORK_CONTROL' },
  56: { dscpValue: 56, name: 'CS7 (56)', description: 'Reserved Critical Network Infrastructure', category: 'NETWORK_CONTROL' }
};

export class MultipathQosAuditor {
  /**
   * Decodes an 8-bit IPv4 TOS or IPv6 Traffic Class byte into DSCP and ECN structures
   */
  public static decodeTosByte(tosByte: number): {
    dscp: DscpClassInfo;
    ecn: EcnStatusInfo;
    rawTos: number;
  } {
    const safeTos = (Number.isFinite(tosByte) && tosByte >= 0 ? Math.floor(tosByte) : 0) & 0xff;
    const dscpVal = (safeTos >> 2) & 0x3f;
    const ecnVal = safeTos & 0x03;

    const dscp = DSCP_RFC4594_MAP[dscpVal] || {
      dscpValue: dscpVal,
      name: `DSCP_${dscpVal}`,
      description: 'Custom DSCP Codepoint',
      category: 'CUSTOM' as const
    };

    let ecnCode: EcnStatusInfo['code'] = 'NOT_ECT';
    let isCongested = false;
    let ecnDesc = 'Non-ECT: Not ECN-Capable Transport';

    switch (ecnVal) {
      case 0x01:
        ecnCode = 'ECT_1';
        ecnDesc = 'ECT(1): ECN-Capable Transport';
        break;
      case 0x02:
        ecnCode = 'ECT_0';
        ecnDesc = 'ECT(0): ECN-Capable Transport';
        break;
      case 0x03:
        ecnCode = 'CE';
        isCongested = true;
        ecnDesc = 'CE (11): Congestion Experienced (RFC 3168 Alert)';
        break;
    }

    return {
      dscp,
      ecn: { ecnValue: ecnVal, code: ecnCode, isCongested, description: ecnDesc },
      rawTos: safeTos
    };
  }

  /**
   * Decodes an IPv6 Traffic Class byte (RFC 8200 / RFC 2474)
   */
  public static decodeIpv6TrafficClass(trafficClassByte: number): {
    dscp: DscpClassInfo;
    ecn: EcnStatusInfo;
    rawTos: number;
  } {
    return this.decodeTosByte(trafficClassByte);
  }

  /**
   * Audits a collection of wire frames for QoS remarking, ECN congestion, and PMTU risks
   */
  public static auditWireFrames(
    frames: Array<{
      tos?: number;
      ipv6TrafficClass?: number;
      expectedDscp?: number;
      hopCountObserved?: number;
      length?: number;
      dfBit?: boolean;
      srcPort?: number;
      dstPort?: number;
      srcIp?: string;
      dstIp?: string;
    }>
  ): QosAuditReport {
    const safeFrames = Array.isArray(frames) ? frames : [];
    const dscpCounts: Record<string, number> = {};
    const ecnCounts: Record<string, number> = {
      NOT_ECT: 0,
      ECT_0: 0,
      ECT_1: 0,
      CE: 0
    };

    let normalFrames = 0;
    let largeFrames = 0;
    let dfSet = 0;
    let pmtuRisks = 0;
    let activeEcnCongestion = 0;
    const violations: QosAuditViolation[] = [];

    safeFrames.forEach((f, idx) => {
      if (!f) return;
      const tos = f.tos !== undefined ? f.tos : (f.ipv6TrafficClass ?? 0);
      const { dscp, ecn } = this.decodeTosByte(tos);

      dscpCounts[dscp.name] = (dscpCounts[dscp.name] || 0) + 1;
      ecnCounts[ecn.code] = (ecnCounts[ecn.code] || 0) + 1;

      if (ecn.isCongested) {
        activeEcnCongestion++;
        violations.push({
          type: 'ECN_CONGESTION_ALERT',
          severity: 'HIGH',
          description: `Active ECN-CE router congestion experienced on flow ${f.srcIp || '*'}:${f.srcPort || 0} -> ${f.dstIp || '*'}:${f.dstPort || 0}`,
          packetIndex: idx,
          flowKey: `${f.srcIp || '*'}:${f.srcPort || 0}->${f.dstIp || '*'}:${f.dstPort || 0}`
        });
      }

      // Check QoS bleaching (VoIP ports on CS0 or explicit expectedDscp mismatch)
      const isVoicePort = f.srcPort === 5060 || f.dstPort === 5060 || (f.srcPort && f.srcPort >= 10000 && f.srcPort <= 10100);
      const explicitBleach = typeof f.expectedDscp === 'number' && f.expectedDscp > 0 && dscp.dscpValue === 0;
      if ((isVoicePort && dscp.dscpValue === 0) || explicitBleach) {
        const multiHopConfirmed = (f.hopCountObserved || 1) >= 2;
        violations.push({
          type: 'QOS_BLEACHING',
          severity: 'MEDIUM',
          description: `VoIP / Realtime traffic carried on CS0 (Best Effort) instead of EF 46; QoS bleaching suspected (${multiHopConfirmed ? 'multi-hop comparison confirmed' : 'single capture point inference; intermediate hop attribution requires multi-point capture'}).`,
          packetIndex: idx,
          flowKey: `${f.srcIp || '*'}:${f.srcPort || 0}->${f.dstIp || '*'}:${f.dstPort || 0}`,
          bleachingProvenance: multiHopConfirmed ? 'MULTI_HOP_CONFIRMED' : 'SINGLE_OBSERVATION_POINT_INFERENCE'
        });
      }

      // PMTU Audit
      const len = Number.isFinite(f.length) && f.length! > 0 ? f.length! : 0;
      if (len > 1472) {
        largeFrames++;
        if (f.dfBit) {
          pmtuRisks++;
          violations.push({
            type: 'PMTU_FRAGMENTATION_RISK',
            severity: 'HIGH',
            description: `Frame size ${len}B with DF bit set exceeds 1472B; high risk of Path MTU ICMP Type 3 Code 4 blackhole.`,
            packetIndex: idx
          });
        }
      } else {
        normalFrames++;
      }

      if (f.dfBit) dfSet++;
    });

    return {
      totalPacketsAudited: safeFrames.length,
      dscpDistribution: dscpCounts,
      ecnDistribution: ecnCounts,
      pmtuDistribution: {
        normalFramesCount: normalFrames,
        largeFramesCount: largeFrames,
        dfBitSetCount: dfSet,
        pmtuRiskCount: pmtuRisks
      },
      activeEcnCongestionCount: activeEcnCongestion,
      violations,
      observationScopeNote: 'Single-vantage capture observes DSCP/ECN values arriving at this interface; attributing DSCP remarking/bleaching to a specific transit hop requires multi-vantage capture correlation.'
    };
  }
}
