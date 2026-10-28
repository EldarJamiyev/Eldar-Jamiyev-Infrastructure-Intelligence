/**
 * Zero-Trust Micro-Segmentation Firewall Policy Synthesizer
 * Generates least-privilege policies in Windows netsh, Linux nftables, and Kubernetes NetworkPolicy YAML.
 * Detects unauthorized lateral movement, shadow admin port access, and abnormal egress.
 */
export interface ObservedHostAsset {
    readonly ip: string;
    readonly hostname?: string;
    readonly role?: string;
    readonly openPorts?: readonly number[];
    readonly mac?: string;
}
export interface ObservedSocketFlow {
    readonly protocol: 'TCP' | 'UDP';
    readonly localIp: string;
    readonly localPort: number;
    readonly remoteIp: string;
    readonly remotePort: number;
    readonly processName?: string;
    readonly processId?: number;
}
export interface LateralMovementViolation {
    readonly flow: ObservedSocketFlow;
    readonly severity: 'HIGH' | 'CRITICAL';
    readonly reason: string;
    readonly violationType: 'SHADOW_ADMIN_PORT' | 'WORKSTATION_LATERAL_SMB_RDP' | 'UNEXPECTED_PROCESS_EGRESS';
}
export interface ZeroTrustPolicyBundle {
    readonly generatedAt: string;
    readonly targetSubnet: string;
    readonly assetCount: number;
    readonly windowsNetshRules: readonly string[];
    readonly linuxNftablesManifest: string;
    readonly kubernetesNetworkPolicyYaml: string;
    readonly lateralMovementViolations: readonly LateralMovementViolation[];
    readonly shadowAdminPortsBlocked: readonly number[];
    readonly artifactStatus?: 'PROPOSED_PREVIEW_ONLY';
    readonly autoApplied?: false;
    readonly validationWarnings?: readonly string[];
    readonly changeSummaryReport?: {
        readonly rulesAdded: number;
        readonly shadowPortsBlockedCount: number;
        readonly leastPrivilegeScore: number;
        readonly humanReadableSummary: string;
    };
}
export declare class ZeroTrustPolicySynthesizer {
    static isValidPort(port: unknown): port is number;
    static isValidIpOrCidr(val: unknown): boolean;
    /**
     * Synthesizes 3-format firewall policies and analyzes flow violations
     */
    static synthesize(assets: readonly ObservedHostAsset[], flows?: readonly ObservedSocketFlow[], targetSubnet?: string): ZeroTrustPolicyBundle;
}
