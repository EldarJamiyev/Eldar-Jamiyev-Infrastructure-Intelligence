/**
 * EJII — Eldar Jamiyev's Infrastructure Intelligence
 * AIMD Parallel Turbo Fleet Scanner & Behavioral Device Fingerprinting Engine
 *
 * Implements an Additive-Increase / Multiplicative-Decrease (AIMD) adaptive concurrency
 * pool (16 - 96 workers, 280ms local timeouts) combined with live OS ARP cache ingestion
 * and passive OS/device behavioral fingerprinting to sweep a /24 subnet in 3-6 seconds.
 *
 * Zero-Simulation Mandate: 100% genuine local OS sockets and physical ARP table telemetry.
 */
export interface DiscoveredHost {
    ip: string;
    hostname: string;
    mac: string;
    vendor: string;
    category: 'Gateway / Router' | 'Windows Workstation' | 'Linux / Server' | 'Apple / Mobile' | 'Network Printer' | 'VoIP Phone' | 'IoT / Smart Device' | 'Unknown Device';
    openPorts: number[];
    services: string[];
    rttMs: number;
    status: 'ONLINE' | 'OFFLINE';
    firstSeen: string;
    osHint: string;
}
export interface TurboScanResult {
    success: boolean;
    subnet: string;
    startTime: string;
    endTime: string;
    durationMs: number;
    totalHostsScanned: number;
    onlineHostsCount: number;
    scanRateHostsPerSec: number;
    effectiveConcurrency: number;
    hosts: DiscoveredHost[];
}
export declare class AimdTurboScanner {
    private initialConcurrency;
    private minConcurrency;
    private maxConcurrency;
    private currentConcurrency;
    private defaultPorts;
    private portTimeoutMs;
    constructor(options?: {
        initialConcurrency?: number;
        minConcurrency?: number;
        maxConcurrency?: number;
        portTimeoutMs?: number;
    });
    /**
     * Reads the genuine OS ARP cache to discover active physical endpoints instantly
     */
    getLocalArpCache(): Promise<Map<string, {
        mac: string;
        vendor: string;
    }>>;
    /**
     * Fast OUI vendor lookup
     */
    lookupOUI(mac: string): string;
    /**
     * Probe an individual port with tight non-blocking timeout
     */
    probePort(ip: string, port: number, timeoutMs?: number): Promise<{
        open: boolean;
        rttMs: number;
    }>;
    /**
     * Passive OS & Device Behavioral Fingerprinting
     */
    classifyHostBySignature(openPorts: number[], vendor: string, hostname: string, ip: string): {
        category: DiscoveredHost['category'];
        osHint: string;
    };
    /**
     * Run turbo parallel scan over a CIDR subnet
     */
    scanSubnet(subnetCidr: string, onHostDiscovered?: (host: DiscoveredHost) => void): Promise<TurboScanResult>;
    private mapPortToService;
}
