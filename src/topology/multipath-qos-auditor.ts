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
}

export const DSCP_RFC4594_MAP: Record<number, DscpClassInfo> = {
  0: { dscpValue: 0, name: 'CS0 (Default)', description: 'Best Effort / Standard Traffic', category: 'STANDARD' },
  8: { dscpValue: 8, name: 'CS1 (Scavenger)', description: 'Low Priority / Bulk Transfers', category: 'STANDARD' },
  10: { dscpValue: 10, name: 'AF11', description: 'Assured Forwarding 11 (Low Drop)', category: 'ASSURED_FORWARDING' },
  12: { dscpValue: 12, name: 'AF12', description: 'Assured Forwarding 12 (Med Drop)', category: 'ASSURED_FORWARDING' },
  14: { dscpValue: 14, name: 'AF13', description: 'Assured Forwarding 13 (High Drop)', category: 'ASSURED_FORWARDING' },
  18: { dscpValue: 18, name: 'AF21', description: 'Assured Forwarding 21 (Low Drop)', category: 'ASSURED_FORWARDING' },
  20: { dscpValue: 20, name: 'AF22', description: 'Assured Forwarding 22 (Med Drop)', category: 'ASSURED_FORWARDING' },
  22: { dscpValue: 22, name: 'AF23', description: 'Assured Forwarding 23 (High Drop)', category: 'ASSURED_FORWARDING' },
  26: { dscpValue: 26, name: 'AF31', description: 'Assured Forwarding 31 (Low Drop)', category: 'ASSURED_FORWARDING' },
  28: { dscpValue: 28, name: 'AF32', description: 'Assured Forwarding 32 (Med Drop)', category: 'ASSURED_FORWARDING' },
  30: { dscpValue: 30, name: 'AF33', description: 'Assured Forwarding 33 (High Drop)', category: 'ASSURED_FORWARDING' },
  34: { dscpValue: 34, name: 'AF41', description: 'Assured Forwarding 41 (Video Streaming)', category: 'ASSURED_FORWARDING' },
  36: { dscpValue: 36, name: 'AF42', description: 'Assured Forwarding 42 (Interactive Video)', category: 'ASSURED_FORWARDING' },
  38: { dscpValue: 38, name: 'AF43', description: 'Assured Forwarding 43 (High Drop Video)', category: 'ASSURED_FORWARDING' },
  46: { dscpValue: 46, name: 'EF (46)', description: 'Expedited Forwarding (Telephony / VoIP)', category: 'EXPEDITED_FORWARDING' },
  48: { dscpValue: 48, name: 'CS6 (48)', description: 'Network Control (BGP, OSPF, STP)', category: 'NETWORK_CONTROL' },
  56: { dscpValue: 56, name: 'CS7 (56)', description: 'Reserved Critical Network Infrastructure', category: 'NETWORK_CONTROL' }
};

export class MultipathQosAuditor {
  /**
   * Decodes an 8-bit TOS byte into DSCP and ECN structures
   */
  public static decodeTosByte(tosByte: number): {
    dscp: DscpClassInfo;
    ecn: EcnStatusInfo;
    rawTos: number;
  } {
    const dscpVal = (tosByte >> 2) & 0x3f;
    const ecnVal = tosByte & 0x03;

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
      rawTos: tosByte
    };
  }

  /**
   * Audits a collection of wire frames for QoS remarking, ECN congestion, and PMTU risks
   */
  public static auditWireFrames(
    frames: Array<{
      tos?: number;
      length?: number;
      dfBit?: boolean;
      srcPort?: number;
      dstPort?: number;
      srcIp?: string;
      dstIp?: string;
    }>
  ): QosAuditReport {
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

    frames.forEach((f, idx) => {
      const tos = f.tos ?? 0;
      const { dscp, ecn } = this.decodeTosByte(tos);

      dscpCounts[dscp.name] = (dscpCounts[dscp.name] || 0) + 1;
      ecnCounts[ecn.code] = (ecnCounts[ecn.code] || 0) + 1;

      if (ecn.isCongested) {
        activeEcnCongestion++;
        violations.push({
          type: 'ECN_CONGESTION_ALERT',
          severity: 'HIGH',
          description: `Active ECN-CE router congestion experienced on flow ${f.srcIp || '*'}:${f.srcPort || 0} -> ${f.dstIp || '*'}:${f.dstPort || 0}`,
          packetIndex: idx
        });
      }

      // Check QoS bleaching (VoIP ports on CS0)
      const isVoicePort = f.srcPort === 5060 || f.dstPort === 5060 || (f.srcPort && f.srcPort >= 10000 && f.srcPort <= 10100);
      if (isVoicePort && dscp.dscpValue === 0) {
        violations.push({
          type: 'QOS_BLEACHING',
          severity: 'MEDIUM',
          description: `VoIP / Realtime traffic carried on CS0 (Best Effort) instead of EF 46; QoS bleaching suspected.`,
          packetIndex: idx
        });
      }

      // PMTU Audit
      const len = f.length || 0;
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
      totalPacketsAudited: frames.length,
      dscpDistribution: dscpCounts,
      ecnDistribution: ecnCounts,
      pmtuDistribution: {
        normalFramesCount: normalFrames,
        largeFramesCount: largeFrames,
        dfBitSetCount: dfSet,
        pmtuRiskCount: pmtuRisks
      },
      activeEcnCongestionCount: activeEcnCongestion,
      violations
    };
  }
}
