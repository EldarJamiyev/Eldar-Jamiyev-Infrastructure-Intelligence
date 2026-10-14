# EJII — Eldar Jamiyev’s Infrastructure Intelligence

> **Commercial-Grade Enterprise IT Management, Observability & Safe Remediation Platform**  
> Built under the **Zero-Simulation & Production-Reality Doctrine**: 100% genuine OS APIs, native network protocol sockets, deterministic Root Cause Analysis (RCA), and tamper-evident cryptographic audit trails.

---

## 🎯 Executive Overview

**EJII (Eldar Jamiyev’s Infrastructure Intelligence)** is an enterprise platform engineered for corporations, government institutions, and mission-critical infrastructure teams. It provides a single, unified operational pane of glass across:

- **Web Application**: High-density, real-time responsive dashboard accessible from any modern browser.
- **Desktop Application**: Standalone background service and application window for Windows.
- **Mobile Application**: Responsive companion interface optimized for on-call incident triage and swipe-to-approve remediation.

**EJII is NOT a ticketing system.** It does not contain ticket queues, mock telemetry, fake graphs, or simulated laboratories. Its central purpose is to detect real infrastructure problems, investigate root causes using dependency graph correlation, present transparent technical evidence, recommend concrete solutions in plain language, and safely automate repetitive operations.

---

## 👥 The Four Operational Roles

EJII enforces strict Role-Based Access Control (RBAC) across four distinct operational roles:

| Role | Responsibility | Key Capabilities |
| :--- | :--- | :--- |
| **Helpdesk Technician** | First-line incident triage & client endpoint support | Real-time ICMP ping, traceroute, port check, DNS test, synthetic HTTP checks, and **Automated Plain-Language Explanations** (*What Happened, Why it Failed, Recommended Action*). Read-only. |
| **Network Administrator** | L2–L7 network infrastructure & connectivity | High-concurrency TCP port sweeps, multi-nameserver DNS propagation analysis, TLS/SSL certificate & cipher auditing, SNMP v1/v2c/v3 polling and MIB walking, dependency topology management. |
| **System Administrator** | Server health, operating system telemetry & services | Live Windows kernel metrics (CPU load, memory breakdown, storage volumes, network interfaces), Windows Services management, live Process Explorer with protected kernel isolation, Windows Event Log inspection, automation playbooks. |
| **Application Owner** | EJII platform governance, approvals & compliance | Dual-custody approval queue for Tier 3 dangerous remediation actions, user and role provisioning, **HMAC-SHA256 Cryptographic Audit Trail Verification**, system runtime diagnostics. |

---

## 🔐 The "Zero-Simulation" Production Mandate

Every feature in EJII operates against actual infrastructure:

1. **Genuine Sockets & Kernel I/O**:
   - **ICMP Ping**: Real OS ping executions calculating min/avg/max RTT, packet loss %, and RFC 3550 jitter.
   - **TCP Port Sockets**: Native non-blocking socket connections with millisecond latency measurement, banner grabbing, and exact Win32/POSIX error categorization (`CLOSED / ECONNREFUSED`, `FILTERED / ETIMEDOUT`, `UNREACHABLE / EHOSTUNREACH`).
   - **DNS Resolver**: Direct RFC 1035 resolver querying specific nameservers (or system defaults) without relying on local OS cache.
   - **TLS/SSL Auditor**: Real TLS handshake, X.509 certificate chain validation, expiration countdown, SAN extraction, and cipher security rating.
   - **HTTP Synthetic Probing**: Full network waterfall timing breakdown ($\Delta t_{\text{DNS}}$, $\Delta t_{\text{TCP}}$, $\Delta t_{\text{TLS}}$, $\Delta t_{\text{TTFB}}$, $\Delta t_{\text{Transfer}}$).
   - **Host Hardware Telemetry**: Native Windows CIM/WMI queries extracting physical CPU model, core counts, load %, physical memory, drive capacities, and services.
   - **SNMP Engine**: SNMPv1/v2c PDU encoder/decoder querying standard MIBs (`sysDescr`, `sysUpTime`, `ifTable`, etc.).

2. **Deterministic Root Cause Analysis (RCA)**:
   - Maintains an in-memory Directed Acyclic Graph (DAG) of infrastructure dependencies (Gateway $\rightarrow$ Switches $\rightarrow$ Hosts $\rightarrow$ Services).
   - When an upstream root node fails, downstream symptom alarms are automatically suppressed into a single primary incident ticket, preventing alert storms.
   - Incidents synthesize structured evidence: **What Happened**, **Root Cause**, **Supporting Telemetry**, and **Step-by-Step Remediation Plan**.

3. **Safe Automation & Dual-Custody Approval Gates**:
   - **Tier 1 (Read-Only Diagnostics)**: Automatic execution (ping, port check).
   - **Tier 2 (Safe Remediation)**: Single-operator execution (flush DNS cache).
   - **Tier 3 (High-Impact Destructive)**: Held in `pending_approval` until an **Application Owner** provides dual-custody authorization with audit notes (service restart, process termination, adapter reset).
   - **Protected Process Isolation**: Hardcoded kernel safety checks physically reject any termination attempt targeting core OS processes (`csrss`, `lsass`, `services`, `explorer`, `system`, PID 4, `node.exe`).
   - **Dry-Run Capability**: Pre-execution simulation displaying the exact command line and impacted resources before running.

4. **Cryptographic Tamper-Evident Audit Trail**:
   - Every login, probe, configuration change, automation request, and approval is logged sequentially with an HMAC-SHA256 hash chaining back to the previous record:
     $$\text{Hash}_n = \text{HMAC-SHA256}(\text{Secret}, \text{Hash}_{n-1} \parallel \text{Timestamp} \parallel \text{User} \parallel \text{Role} \parallel \text{Action} \parallel \text{Resource} \parallel \text{Details})$$
   - Built-in one-click cryptographic verification checks the entire chain and flags any modified or deleted record immediately.

---

## 🛠️ The 14 Integrated Native Tool Subsystems

EJII natively subsumes the discrete forensic, monitoring, and administrative capabilities of the industry's most critical standalone utilities into a unified zero-simulation engine:

| # | Integrated Tool Subsystem | Native Engine Capabilities in EJII |
|---|---|---|
| 1 | **Wireshark** | Deep packet capture and L2–L7 dissection (Ethernet II, ARP, IPv4/IPv6, TCP, UDP, ICMP, DNS, HTTP) and libpcap binary parser. |
| 2 | **Nmap** | Non-blocking TCP Connect scanning (`-sT`), service banner and version detection (`-sV`), and OS TCP/IP stack fingerprinting (`-O`). |
| 3 | **PuTTY** | Embedded protocol terminal bridge and native launcher for Windows RDP (`mstsc.exe`), OpenSSH, and PowerShell administrative consoles. |
| 4 | **Sysinternals & Process Explorer** | Hierarchical process tree DAG (PPID &rarr; PID), loaded DLL/module inspection, and TCPView live socket-to-process mapper. |
| 5 | **Advanced IP Scanner & Angry IP Scanner** | Parallel asynchronous subnet sweeper, live host ARP cache reader, and IEEE MAC OUI hardware manufacturer resolution. |
| 6 | **iPerf / iPerf3** | Active TCP socket bandwidth throughput saturation benchmarking and UDP RFC 3550 interarrival jitter and packet loss analysis. |
| 7 | **Netcat (nc)** | Raw TCP/UDP socket streaming, port listener, custom ASCII/hex payload piping, and banner grabbing. |
| 8 | **Fiddler** | HTTP/HTTPS synthetic inspection, request waterfall latency decomposition ($\Delta t_{\text{DNS}}$, $\Delta t_{\text{TCP}}$, $\Delta t_{\text{TLS}}$, $\Delta t_{\text{TTFB}}$, $\Delta t_{\text{Transfer}}$), and weak cipher detection. |
| 9 | **Nagios / Zabbix / PRTG / SolarWinds NPM** | SNMPv1/v2c MIB-II tree walker and live interface bandwidth throughput calculation via RFC 2863 octet deltas. |
| 10 | **Cisco Packet Tracer** | Interactive topology canvas, real host routing table inspection (`Get-NetRoute`), longest prefix match evaluation, and L2/L3 packet traversal stepper. |
| 11 | **BleachBit** | Safe temporary file cache audit (`%TEMP%`, crash dumps) and SQLite database fragmentation vacuuming (`VACUUM; ANALYZE;`). |
| 12 | **HWiNFO & CPU-Z** | Bare-metal hardware telemetry via Windows CIM/WMI: SMBIOS motherboard vendor/model, CPU core topology, RAM SPD slots, and S.M.A.R.T. disk health. |
| 13 | **FileZilla** | Secure file transfer subsystem: directory navigation, file checksumming, and SHA-256 differential transfer verification. |
| 14 | **MTR (My Traceroute)** | Continuous multi-hop path analysis with real-time running statistical table: Hop, IP, Reverse DNS, Loss %, Sent, Received, Best/Avg/Worst RTT, and Jitter. |

---

## 🚀 One-Click Launchers

EJII provides turnkey launchers for every environment:

- **Windows Turnkey Launcher**:
  ```cmd
  setup-launcher.bat
  ```
  *(Checks Node.js, installs dependencies, executes all 6 verification test suites, and opens http://localhost:8443 automatically).*

- **Linux / POSIX Launcher**:
  ```bash
  chmod +x setup-launcher.sh
  ./setup-launcher.sh
  ```

- **Docker Containerized Deployment**:
  ```bash
  docker compose up -d
  ```

---

## 🔑 Default Operational Accounts

| Role | Username | Password |
| :--- | :--- | :--- |
| **Helpdesk Technician** | `helpdesk` | `HelpdeskPassword2026!` |
| **Network Administrator** | `netadmin` | `NetadminPassword2026!` |
| **System Administrator** | `sysadmin` | `SysadminPassword2026!` |
| **Application Owner** | `appowner` | `AppownerPassword2026!` |

*(One-click demo buttons are provided on the login screen for rapid role evaluation).*

---

## 🛠️ CLI Diagnostics Utility

You can also run real low-level diagnostics directly from your command line:

```bash
# Run real ping
node bin/run-diagnostics-cli.js ping 127.0.0.1

# Check TCP port socket
node bin/run-diagnostics-cli.js port 127.0.0.1 80

# Sweep 23 enterprise ports
node bin/run-diagnostics-cli.js sweep 127.0.0.1

# Resolve DNS record
node bin/run-diagnostics-cli.js dns google.com

# Audit TLS Certificate & Ciphers
node bin/run-diagnostics-cli.js tls google.com

# Probe HTTP Waterfall
node bin/run-diagnostics-cli.js http https://google.com

# Inspect Host CPU, RAM, and Storage
node bin/run-diagnostics-cli.js host

# Cryptographically Verify Audit Trail
node bin/run-diagnostics-cli.js audit-verify
```

---

## 📂 Project Architecture

```text
├── bin/
│   ├── ejii-server.cmd          # Windows quick-launcher
│   ├── ejii-desktop.js          # Desktop launcher with auto-open browser
│   └── run-diagnostics-cli.js   # CLI utility for terminal operators
├── data/
│   └── ejii.sqlite              # High-performance WAL-mode SQLite database
├── public/                      # Multi-platform responsive UI
│   ├── css/style.css            # High-density dark operations theme
│   ├── js/app.js                # Single Page Application engine, WebSockets & 14-tool UI
│   ├── index.html               # Main enterprise dashboard layout
│   └── manifest.json            # PWA manifest for desktop/mobile installability
├── src/
│   ├── api/                     # REST API route handlers (Auth, Diag, Network, System, RCA, Automation, Admin, Tools)
│   ├── automation/              # Safety validator, protected process list & execution engine
│   ├── core/                    # Security, cryptographic audit logger & RCA correlation DAG
│   ├── db/                      # Schema definition & database seeder
│   ├── protocols/               # Real network & host protocol drivers (ICMP, TCP, DNS, TLS, SNMP, CIM)
│   ├── tools/                   # 14 Native Tool Engines (Wireshark, Nmap, Sysinternals, IP Scanner, iPerf, Netcat, etc.)
│   ├── config.js                # Configuration constants
│   └── server.js                # Express & WebSocket telemetry daemon
├── tests/                       # Complete automated unit & integration test suites
│   ├── network-probes.test.js
│   ├── system-probes.test.js
│   ├── tools-engines.test.js
│   ├── rca-engine.test.js
│   ├── automation-safety.test.js
│   ├── auth-rbac.test.js
│   └── run-all-tests.js
├── Dockerfile                   # Production container definition
├── docker-compose.yml           # Multi-tier container orchestrator
├── setup-launcher.bat           # Windows one-click launcher
└── setup-launcher.sh            # Linux/POSIX launcher
```

---

## 📜 License & Ownership
Copyright © 2026 **Eldar Jamiyev**. All Rights Reserved. Built for real-world enterprise infrastructure operations.
