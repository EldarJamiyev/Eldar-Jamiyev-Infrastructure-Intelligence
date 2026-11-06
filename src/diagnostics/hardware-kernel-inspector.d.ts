export type FieldProvenanceStatus = 'live' | 'cached' | 'unavailable' | 'unsupported' | 'simulated';
export interface PhysicalRadioTelemetry {
    readonly interfaceName: string;
    readonly interfaceType: 'Wi-Fi 802.11ax/ac' | 'Gigabit Ethernet' | 'Loopback' | 'Virtual Adapter';
    readonly ssid: string;
    readonly bssid: string;
    readonly radioBand: '2.4 GHz' | '5 GHz' | '6 GHz' | 'Wired' | 'Unknown';
    readonly channel: number;
    readonly signalQualityPct: number;
    readonly rxRateMbps: number;
    readonly txRateMbps: number;
    readonly linkState: 'connected' | 'disconnected' | 'loopback';
    readonly wirelessHardwarePresent?: boolean;
}
export interface KernelTcpParameters {
    readonly autoTuningLevel: string;
    readonly congestionControlProvider: string;
    readonly ecnCapability: 'enabled' | 'disabled';
    readonly receiveSideScalingRss: 'enabled' | 'disabled';
    readonly receiveSegmentCoalescingRsc: 'enabled' | 'disabled';
    readonly activeDnsServers: readonly string[];
    readonly mtu: number;
}
export interface HardwareKernelInspectionReport {
    readonly inspectedAt: string;
    readonly hostName: string;
    readonly osPlatform: string;
    readonly osRelease: string;
    readonly radio: PhysicalRadioTelemetry;
    readonly kernelTcp: KernelTcpParameters;
    readonly rawInspectionStatus: 'LIVE_OS_TELEMETRY' | 'DETERMINISTIC_FALLBACK';
    readonly fieldProvenance?: Readonly<Record<string, FieldProvenanceStatus>>;
    readonly evidentiaryNote?: string;
}
export declare class HardwareKernelInspector {
    /**
     * Safely inspects physical Wi-Fi radio and kernel TCP stack without elevated privileges
     */
    static inspect(): HardwareKernelInspectionReport;
    private static inspectWindows;
    private static inspectLinuxOrFallback;
}
