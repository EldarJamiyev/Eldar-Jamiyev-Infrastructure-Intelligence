# Policy POL-02: Autonomous Remediation Dual-Custody, Action Tiering, and OS Kernel Shield Policy

## Purpose & Scope
This policy governs automated, semi-automated, and operator-confirmed remediation actions executed by the Autonomous AI Diagnostic Brain and PC Automation subsystems on Windows host systems and network infrastructure.

## Tiered Action Classification
Remediations are strictly categorized into three risk tiers:

### Tier 1: Read-Only Diagnostics & Observation (Autonomous Allowed)
- Passive packet capture and BPF filtering.
- Socket state collection (`Get-NetTCPConnection`, `Get-NetUDPEndpoint`).
- Ephemeral ping sweep and DNS resolution probes.
- System metrics inspection (CPU, Memory, Disk Queue, Paging).
- **Execution Rule:** May run fully autonomously without user prompt.

### Tier 2: Non-Destructive Soft Mitigations (Operator Confirmation Recommended)
- DNS client cache flushing (`Clear-DnsClientCache`).
- Process CPU priority throttling (`BelowNormal` / `Idle`).
- Network interface statistics counter reset.
- Temp file cache purge in user-scoped directories (`%TEMP%`).
- **Execution Rule:** Requires explicit operator confirmation or validated high-confidence AI recommendation (>=85% Bayesian confidence).

### Tier 3: High-Impact / Disruptive Remediation (Mandatory Dual-Custody Confirmation)
- Process termination (`taskkill`, `Stop-Process`).
- Network adapter reset (`Restart-NetAdapter`, `ipconfig /release /renew`).
- Routing table modifications (`route add`, `route delete`).
- System reboot / shutdown (`shutdown /r /t 60`).
- Registry policy or MTU permanent modification.
- **Execution Rule:** MANDATORY dual-custody verification modal with impact analysis and explicit user approval before execution.

## OS Kernel Shielding
Critical Windows system processes (`System`, `Idle`, `smss.exe`, `csrss.exe`, `wininit.exe`, `services.exe`, `lsass.exe`, `svchost.exe`, `dwm.exe`, `explorer.exe`) are hard-shielded and CANNOT be terminated or starved by automated scripts.
