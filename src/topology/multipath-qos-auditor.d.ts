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
        readonly largeFramesCount: number;
        readonly dfBitSetCount: number;
        readonly pmtuRiskCount: number;
    };
    readonly activeEcnCongestionCount: number;
    readonly violations: readonly QosAuditViolation[];
}
export declare const DSCP_RFC4594_MAP: Record<number, DscpClassInfo>;
export declare class MultipathQosAuditor {
    /**
     * Decodes an 8-bit TOS byte into DSCP and ECN structures
     */
    static decodeTosByte(tosByte: number): {
        dscp: DscpClassInfo;
        ecn: EcnStatusInfo;
        rawTos: number;
    };
    /**
     * Audits a collection of wire frames for QoS remarking, ECN congestion, and PMTU risks
     */
    static auditWireFrames(frames: Array<{
        tos?: number;
        length?: number;
        dfBit?: boolean;
        srcPort?: number;
        dstPort?: number;
        srcIp?: string;
        dstIp?: string;
    }>): QosAuditReport;
}
