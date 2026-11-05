# Runbook RB-03: Cross-Layer Workstation Resource Saturation & Degraded PnP Device Remediation

## Cross-Layer Host + Network Correlation (RFC 1122)
Before attributing high application TTFB or packet drops to upstream WAN links, inspect the 4-Pillar Host Diagnostics Engine:
1. **CPU & Working Set Pressure:** If normalized multi-core CPU load $\ge 90\%$ or physical RAM utilization $\ge 92\%$, local socket buffer scheduling delays cause apparent RTT spikes (`LOCAL_HOST_RESOURCE_EXHAUSTION`). Use the `trim_working_set` (`EmptyWorkingSet`) or process priority throttling recipe (excluding `🛡️ OS Protected` processes).
2. **Degraded PnP / NDIS Adapters:** If `Win32_PnPEntity` reports `ConfigManagerErrorCode != 0` (e.g., Code 22 Disabled or Code 10/43 Driver Fault), stage a dry-run preview of `rescan_pnp_devices` or `reset_network_adapter` with a cryptographic `actionToken`.
