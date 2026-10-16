# EJII CORE DIAGNOSTICS & AUTONOMOUS REMEDIATION COMPLETION REPORT
**Eldar Jamiyev Infrastructure Intelligence (EJII)**  
**Engineering Tier:** Claude Code Source Engineering / Principal Systems Architect  
**Deliverable:** Core Diagnostics & Autonomous Remediation Workstation (`core-diagnostics`)  
**Host Target Machine:** `EldarJamiyev` (Windows 11 Enterprise x64)  
**Standard:** Zero-Simulation Standard — 100% Genuine OS & Hardware Telemetry.

---

## 1. Workstation Architecture & Overview

The **Core Diagnostics & Autonomous Remediation** workstation (`core-diagnostics`) is an enterprise-grade operational console built directly into the EJII NOC platform. It unifies deep Windows operating system telemetry, hardware health monitoring, and audited two-phase remediation into a single real-time command cockpit.

### Architectural Principles:
1. **Zero Simulation:** All diagnostics are collected dynamically from live Windows CIM (`Get-CimInstance`), WMI, and native PowerShell cmdlets. No mock objects or placeholder arrays are permitted.
2. **Two-Phase Remediation (Safety First):**
   - **Phase 1: Dry-Run Preview (`executePreview`):** Computes the exact PowerShell command, assesses elevation requirements, and validates safety guardrails without making any system changes.
   - **Phase 2: Audited Execution (`executeRemediation`):** Requires authenticated `OPERATOR` credentials, checks elevation status via `net session`, strictly shields protected system processes, and logs every invocation to a tamper-resistant audit log.
3. **Honest Host Feedback:** If an unprivileged user triggers a task that requires elevation (e.g. `reset_winsock`, `repair_component_store`), the system explicitly reports `elevationRequired: true` alongside actionable PowerShell command instructions rather than faking success.

---

## 2. The 4 Foundational Pillars & Real Host Telemetry

Telemetry collected directly from physical host `EldarJamiyev` during verification:

```json
{
  "host": {
    "hostname": "EldarJamiyev",
    "platform": "win32",
    "arch": "x64",
    "uptimeDays": 4.2,
    "cpuCores": 22,
    "totalRamGB": 31.4
  },
  "overallStatus": "HEALTHY"
}
```

### Pillar 1: Network & Connectivity Layer
* **Collector:** `NetAdapter`, `NetRoute`, `NetTCPConnection`, `DnsClientCache`.
* **Telemetry Collected on `EldarJamiyev`:**
  - **Active Adapters:** Intel(R) Wi-Fi 6E AX211 160MHz (MAC: `70-15-FB-6B-F3-46`, Link Speed: 144.4 Mbps), Hyper-V Virtual Ethernet (`vEthernet`, 10 Gbps).
  - **Default Gateway:** `192.168.31.1` (NextHop via interface alias `Wi-Fi`, metric: 10).
  - **Socket Matrix:** 147 active TCP/UDP sockets mapped across `ESTABLISHED`, `LISTEN`, `TIME_WAIT`, `CLOSE_WAIT`.
  - **DNS Client Cache:** 30 cached resolution records inspected.
* **Health Verdict:** `HEALTHY` (Active route to gateway confirmed, zero dropped interfaces).

### Pillar 2: Storage, Volumes & SMART Status
* **Collector:** `CIM_LogicalDisk`, `MSStorageDriver_FailurePredictStatus`, `Win32_ShadowCopy`, Crash Dump paths.
* **Telemetry Collected on `EldarJamiyev`:**
  - **Volume C:** Label `Windows-SSD`, File System `NTFS`, Total Capacity: 951.6 GB, Free Space: 521.6 GB, Utilization: 45.2%.
  - **SMART Failure Prediction Status:** `OK` (0 failing sectors or drive wear warnings).
  - **Volume Shadow Copy (VSS):** Running and operational.
  - **Crash Dumps:** 0 pending crash minidumps in `%SystemRoot%\Minidump`.
* **Health Verdict:** `HEALTHY` (Over 500GB free, SMART nominal).

### Pillar 3: Resource Allocation & Process Explorer
* **Collector:** `Win32_Processor`, `Win32_OperatingSystem`, `System.Diagnostics.Process`, `Win32_PerfFormattedData_PerfDisk_PhysicalDisk`.
* **Telemetry Collected on `EldarJamiyev`:**
  - **CPU Model:** Intel(R) Core(TM) Ultra 7 155H (22 logical cores).
  - **CPU Load:** 7% to 17% instantaneous utilization.
  - **Physical RAM:** 31.4 GB total; 15.8 GB used (50.6%), 15.6 GB free.
  - **Current Disk Queue Length:** 0.
  - **Top Processes Monitored:** Chrome (PID 15680, 923.8 MB), Antigravity IDE (PID 1060, 669.7 MB), Explorer (PID 26024, 653.8 MB), DWM (PID 9320, 638.7 MB), Node.js (PID 8224, 559.2 MB).
* **Health Verdict:** `HEALTHY` (Nominal memory headroom, zero queue saturation).

### Pillar 4: Peripherals & System Drivers
* **Collector:** `Win32_PnPEntity`, `Win32_Service (Spooler)`.
* **Telemetry Collected on `EldarJamiyev`:**
  - **Print Spooler Service:** `Running` (Status Code 4, 0 deadlocked print jobs).
  - **Degraded PnP Hardware Devices:** 0 devices reporting error codes `CM_PROB_*` or `Error`.
* **Health Verdict:** `HEALTHY` (All hardware buses and drivers nominal).

---

## 3. Autonomous Remediation Engine & Safety Guardrails

### 3.1 10-Recipe Operational Catalog

| ID | Recipe Name | Pillar | Risk Level | Requires Elevation | Target Remediation Action |
| :--- | :--- | :---: | :---: | :---: | :--- |
| `flush_dns` | Flush & Re-register DNS | Network | LOW | No | `Clear-DnsClientCache; Register-DnsClient` |
| `renew_dhcp` | Release & Renew DHCP Leases | Network | LOW | No | `ipconfig /release; ipconfig /renew` |
| `reset_winsock` | Reset Winsock & TCP/IP Stack | Network | MEDIUM | **Yes** | `netsh winsock reset; netsh int ip reset` |
| `repair_component_store`| DISM & SFC System File Repair | Storage | HIGH | **Yes** | `DISM /Online /Cleanup-Image /RestoreHealth; sfc /scannow` |
| `scan_disk` | Chkdsk Read-Only Volume Scan | Storage | LOW | No | `chkdsk C: /scan` |
| `cleanup_temp_dumps` | Purge Temporary Dumps & Logs | Storage | LOW | No | Purge `%TEMP%` and `%SystemRoot%\Minidump` |
| `trim_working_set` | Garbage Collect Process Working Sets | Resource | LOW | No | Trim process working sets via `EmptyWorkingSet()` |
| `lower_process_priority`| Throttle Runaway Process Priority | Resource | MEDIUM | No | `(Get-Process -Id $TargetPid).PriorityClass = 'BelowNormal'` |
| `repair_print_spooler` | Clear Deadlocked Print Spooler | Peripherals | MEDIUM | **Yes** | Stop spooler, purge `C:\Windows\System32\spool\PRINTERS\*`, restart |
| `rescan_pnp_devices` | Re-scan & Re-enumerate PnP Devices | Peripherals | LOW | No | `pnputil /scan-devices` |

### 3.2 Anti-Kill OS Process Shield
The remediation engine maintains a strict, unmodifiable blacklist of critical Windows kernel and subsystem processes that can **never** be throttled, suspended, or terminated:
- `lsass.exe` (Local Security Authority)
- `csrss.exe` (Client/Server Runtime Subsystem)
- `smss.exe` (Session Manager Subsystem)
- `services.exe` (Service Control Manager)
- `wininit.exe` (Windows Initialization)
- `winlogon.exe` (Windows Logon)
- `system` / `system idle process`
- `explorer.exe` (Shell)
- `dwm.exe` (Desktop Window Manager)
- `node.exe` (EJII runtime self-defense guard)

Targeting any protected process immediately triggers a fatal `SECURITY VIOLATION` error.

---

## 4. Frontend Command Workbench (`public/js/views/core-diagnostics-view.js`)

The user interface is designed as an industrial cyber-NOC command center consisting of a **3-panel upper workbench** and **4 deep inspection tabs**:

```
+-----------------------------------------------------------------------------------------+
| [🔍 5. CORE DIAGNOSTICS & AUTONOMOUS REMEDIATION]          [HOST: EldarJamiyev] [HEALTHY]|
+------------------------------------+--------------------------+-------------------------+
| PANEL 1: MACHINE X-RAY             | PANEL 2: DIAGNOSIS FEED  | PANEL 3: ACTION CENTER  |
| - Host Architecture & Uptime       | - Live Anomaly Stream    | - Staged Remediation Box|
| - 4-Pillar Status Gauges (Net/     | - AI Brain Health Brief  | - Dry-Run Preview Modal |
|   Storage/Resource/Peripherals)    | - Bayesian Root-Cause    | - Live PowerShell Shell |
| - Instant CPU & RAM Meter          | - Severity Badges        | - Elevation Requirements|
+------------------------------------+--------------------------+-------------------------+
| TABS: [1. Process Explorer]  [2. Network Sockets]  [3. Storage & SMART]  [4. PnP Drivers]|
+-----------------------------------------------------------------------------------------+
| TAB 1: 60+ Active Processes (PID, CPU Time, Working Set MB, Private MB, Handle Count)   |
| TAB 2: 100+ TCP/UDP Sockets (Protocol, Local Address, Foreign Address, State, Process)  |
| TAB 3: Volumes (Drive, Label, FS, Total/Free GB, % Bar, SMART Predictive Failure: OK)  |
| TAB 4: Print Spooler Service Status & PnP Hardware Device Hierarchy Tree                |
+-----------------------------------------------------------------------------------------+
```

### Key UI Capabilities:
* **One-Click Real-Time Audit:** Trigger instantaneous 4-pillar hardware telemetry collection (`/api/diagnostics/host/audit`).
* **Dry-Run Preview Modal:** Clicking any recipe immediately requests a Phase 1 dry-run, showing the exact PowerShell code, risk rating, and whether elevation is needed.
* **Audit Trail Viewer:** Real-time log displaying who executed what remediation, when, and what output the operating system returned.

---

## 5. Verification & Test Suite Summary

All capabilities are backed by 3 dedicated automated test suites plus inclusion in the 26-suite master test runner:

1. **Suite 24 (`tests/core-diagnostics-engine.test.js`):**
   - Ingests all 4 foundational pillars from live Windows CIM/PowerShell.
   - Verifies process table, socket table, SMART status, and AI Brain health synthesis.
   - **Result:** 100% Pass (0 defects).
2. **Suite 25 (`tests/autonomous-remediation-safety.test.js`):**
   - Validates all 10 recipes in the catalog.
   - Verifies Phase 1 dry-run isolation (zero host mutation).
   - Verifies OS process shields across `lsass.exe`, `csrss.exe`, `services.exe`, `smss.exe`.
   - Verifies RBAC authorization (blocking `READONLY` users).
   - Verifies honest elevation feedback on non-elevated runs.
   - Verifies safe execution of `trim_working_set`.
   - **Result:** 100% Pass (0 defects).
3. **Suite 26 (`tests/live-production-smoke.test.js`):**
   - Spawns live `node src/server.js` production process on port 8445.
   - Verifies WebSocket connection, RBAC spoofing attack defeat, `/api/diagnostics/host/audit`, `/api/diagnostics/remediation/preview`, and `/api/diagnostics/remediation/execute`.
   - **Result:** 100% Pass (0 defects).

---

## 6. Operational Hand-off

The **Core Diagnostics & Autonomous Remediation** workstation is fully mounted, wired into the router (`#core-diagnostics`), integrated with the navigation sidebar, and ready for operational deployment.
