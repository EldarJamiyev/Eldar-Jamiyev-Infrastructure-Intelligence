/**
 * Binary Radix / Patricia Trie Longest-Prefix Match (LPM) & Routing Anomaly Auditor
 * 100% Zero-Simulation, Unprivileged Physical Network Topology Engine.
 * Supports:
 *  - 32-bit IPv4 Radix Trie insertion & O(k) Longest-Prefix Match (LPM)
 *  - Deterministic Routing Anomaly Auditing:
 *      * SHADOWED_ROUTES
 *      * SPLIT_TUNNEL_LEAKS
 *      * CGNAT_OR_APIPA_ANOMALIES
 *      * GATEWAY_METRIC_AMBIGUITY
 *  - Live OS Route Table Extraction (Windows 'route print -4' / Linux 'ip route')
 */
export interface RouteEntry {
    readonly cidr: string;
    readonly destination: string;
    readonly netmask: string;
    readonly gateway: string;
    readonly interfaceName: string;
    readonly metric: number;
}
export interface LPMMatchResult {
    readonly matched: boolean;
    readonly matchedCidr: string | null;
    readonly prefixLength: number;
    readonly nextHop: string | null;
    readonly interfaceName: string | null;
    readonly metric: number;
    readonly trieDepth: number;
}
export interface RoutingAnomaly {
    readonly anomalyType: 'SHADOWED_ROUTES' | 'SPLIT_TUNNEL_LEAKS' | 'CGNAT_OR_APIPA_ANOMALIES' | 'GATEWAY_METRIC_AMBIGUITY';
    readonly severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    readonly description: string;
    readonly affectedRoutes: readonly RouteEntry[];
    readonly remediationAdvice: string;
}
export interface RoutingRadixAuditReport {
    readonly totalRoutes: number;
    readonly trieNodeCount: number;
    readonly maxTrieDepth: number;
    readonly defaultGateways: readonly RouteEntry[];
    readonly anomalies: readonly RoutingAnomaly[];
    readonly sampleLpmProbes: Record<string, LPMMatchResult>;
    readonly routes: readonly RouteEntry[];
    readonly timestampIso: string;
}
export declare class RoutingRadixIntelligenceEngine {
    private root;
    private nodeCount;
    private maxDepth;
    constructor();
    private createNode;
    static ipToUint32(ip: string): number;
    static uint32ToIp(n: number): string;
    static netmaskToPrefixLen(maskStr: string): number;
    /**
     * Inserts an IPv4 route into the Radix Trie.
     */
    insertRoute(cidrOrDest: string, nextHop: string, interfaceName: string, metric: number, netmask?: string): void;
    /**
     * Performs an O(k) Longest-Prefix Match (LPM) on target IPv4.
     */
    lookupLongestPrefixMatch(ipStr: string): LPMMatchResult;
    getStats(): {
        nodeCount: number;
        maxDepth: number;
    };
    static auditRouteTable(routes: readonly RouteEntry[]): RoutingAnomaly[];
    auditRouteTable(routes: readonly RouteEntry[]): RoutingAnomaly[];
    static runComprehensiveAudit(probeTargetIp?: string): RoutingRadixAuditReport;
    runComprehensiveAudit(probeTargetIp?: string): RoutingRadixAuditReport;
    /**
     * Deterministically audits an array of RouteEntry objects for 4 enterprise anomalies.
     */
    static auditRoutingTable(routes: readonly RouteEntry[]): {
        anomalies: RoutingAnomaly[];
        defaultGateways: RouteEntry[];
    };
    /**
     * Unprivileged Live OS Routing Table Extractor (Windows / Linux)
     */
    static extractHostRoutes(): RouteEntry[];
    /**
     * Complete Host Routing Audit: captures real OS routes, populates Radix Trie,
     * conducts LPM probes, and audits for anomalies.
     */
    static captureAndAuditHostRoutes(probeTargetIp?: string): RoutingRadixAuditReport;
}
