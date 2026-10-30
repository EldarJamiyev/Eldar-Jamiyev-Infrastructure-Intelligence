<div align="center">

<img src="docs/assets/ejii-aurora-banner.svg" alt="EJII — Eldar Jamiyev's Infrastructure Intelligence (Project Aurora & Falcon v7.0)" width="100%" />

<br />

# EJII — Eldar Jamiyev's Infrastructure Intelligence

**AI-Native Conversational Infrastructure Assistant · L1–L7 Protocol & Wire Dissector · Epistemic Evidence Fabric · Governed Self-Healing Workbench**

[![Verification Suites](https://img.shields.io/badge/NOC_Verification_Suites-100%2F100_PASS-059669?style=for-the-badge)](tests/run-all-tests.js)
[![Core Unit Tests](https://img.shields.io/badge/Core_Brain_Unit_Tests-46%2F46_PASS-2563EB?style=for-the-badge)](src/core/__tests__)
[![Design System](https://img.shields.io/badge/UI_Architecture-Project_Aurora_v7.0-0F172A?style=for-the-badge)](public/css/ejii-meridian.css)
[![AI Engine](https://img.shields.io/badge/Conversational_Brain-Project_Falcon_%2B_Gemini_3.8_Flash-1D4ED8?style=for-the-badge)](src/core/chat/conversational-brain.js)
[![Storage](https://img.shields.io/badge/Persistence-SQLite_WAL_%2B_RBAC-334155?style=for-the-badge)](src/db/database.js)

[**Executive Vision**](#1-executive-overview) · [**Visual Product Tour (12 Live Screens)**](#2-visual-product-tour--every-workstation-in-action) · [**System Architecture**](#3-system-architecture--dataflow) · [**Project Falcon AI Brain**](#4-project-falcon--ai-native-conversational-intelligence) · [**Epistemic Guarantees**](#5-epistemic-integrity--zero-fabrication-engineering) · [**Quick Start & Testing**](#7-quick-start-configuration--verification)

</div>

---

## 1. Executive Overview

**EJII (Eldar Jamiyev's Infrastructure Intelligence)** is an enterprise-grade, sovereign infrastructure intelligence platform that unifies **natural-language conversational diagnostics**, **live L1–L7 protocol probing**, **Wireshark-grade packet dissection**, **L1–L6 network topology mapping**, **Sysinternals-grade host kernel telemetry**, and **cryptographically governed remediation with automatic rollback** inside one cohesive software product.

Built across two flagship engineering milestones—**Project Falcon** (AI-Native Conversational Brain) and **Project Aurora** (Unified Architectural Slate & Executive Blue Frontend Experience)—EJII is designed for Network Operations Center (NOC) engineers, Systems Administrators, Site Reliability Engineers, and IT Support Operators who require **verifiable live evidence** rather than black-box guesses.

### Why EJII Exists

Traditional infrastructure tooling forces operators to choose between rigid command-line utilities (`dig`, `ping`, `traceroute`, `ss`, `tcpdump`) and fragmented dashboards that cannot reason across protocol layers. Conversely, generic conversational AI assistants lack direct access to live kernel sockets, OS routing tables, DNS resolvers, and TCP/TLS handshakes—often hallucinating network state or giving generic troubleshooting checklists.

**EJII bridges both worlds:**

1. **Understands What You Mean, Not Just Keywords**: You can describe symptoms naturally (*"My email isn't working"*, *"Internet is slow on this machine"*, *"Check whether port 3000 is open on localhost, then test HTTP"*), provide incomplete information, switch topics mid-conversation, or ask follow-up questions (*"Why did that fail?"*, *"Now check port 443 on the same host"*).
2. **Executes Real Protocol & Host Probes**: Every diagnostic conclusion is backed by live OS and network measurements—RFC 1035 DNS wire queries, verified OS resolver discovery, TCP 3-way handshake timing, TLS 1.3 / X.509 certificate inspection, HTTP/L7 status verification, DHCP/NIC lease inspection, and kernel socket enumeration.
3. **Strict Epistemic Honesty (Zero Fabrication)**: EJII never invents DNS resolvers, never fabricates fallback latencies, and never confuses a transport-layer `TCP OPEN` result with application-layer health. Unmeasured or unverified states are explicitly reported with their collection method and sandbox/OS constraints.
4. **One Unified Design Language Across 9 Workstations**: From the two-column architectural sign-in experience to the 3-pane packet dissector and Sovereign Fabric v6 studio, every screen shares a disciplined typographic scale (`Plus Jakarta Sans` + `JetBrains Mono` `tabular-nums`), semantic status tokens, and effortless cross-workstation context pivoting.

---

## 2. Visual Product Tour — Every Workstation in Action

Every screenshot below is captured directly from the live running EJII application (`http://localhost:3000`) via automated Playwright browser verification.

### 2.1 Architectural Sign-In & Role-Based Access Control (`#loginScreen`)

![EJII Login Screen](docs/screenshots/login.png)

* **Two-Column Executive Layout**: Pairs an obsidian-slate architectural brand briefing on the left (highlighting live protocol probes, L1–L6 topology mapping, and governed remediation) with a focused, high-contrast PBKDF2-SHA512 / JWT authentication card on the right.
* **Granular Capability RBAC**: Enforces 9 distinct operational roles (`ADMIN`, `APP_OWNER`, `SYSADMIN`, `NETWORK_ADMIN`, `ANALYST`, `OPERATOR`, `NOC_OPERATOR`, `HELPDESK`, `READONLY`) with per-endpoint capability verification and session-ownership isolation.

---

### 2.2 AI-Native Conversational Diagnostic Assistant (`chat-workspace-view.js`)

![AI Conversational Diagnostic Result](docs/screenshots/ai-operator-diagnostic-result.png)

* **Natural-Language Infrastructure Investigation**: Operators converse naturally while EJII's **Conversational Brain** (`src/core/chat/conversational-brain.js`) and live **Gemini Semantic Interpreter** (`src/core/chat/semantic-ai-interpreter.js`) resolve intent, pronouns, and multi-turn context before dispatching live probes.
* **Structured Evidence Cards & Collapsible Raw Telemetry**: Every probe reply presents a clear human-readable answer, measured RTT badges in `tabular-nums` monospace, transport-vs-application layer caveats, and expandable raw protocol evidence.
* **Unified App Shell Integration**: Lives seamlessly inside the main EJII shell alongside the Sidebar, Topbar telemetry pills, and Sovereign Fabric v6 command ribbon.

---

### 2.3 Autonomous AI Infrastructure Operator Console (`ai-operator-view.js`)

![Autonomous AI Operator Console](docs/screenshots/ai-operator.png)

* **9-Capability Autonomous Operations Cockpit**: Combines real-time L7 DNS and L4 TCP handshake monitors, kernel socket counters, host CPU/RAM/disk gauges, and SQLite probe cycle metrics in a scannable 6-card telemetry strip.
* **Governed Self-Healing with Proof & Auto-Rollback**: Proposes low-risk corrective playbooks (such as process DNS resolver refresh and SQLite topology reconciliation), captures pre-execution state snapshots, verifies postcondition RTTs, and automatically rolls back if postcondition checks fail.
* **Persona-Tailored Cockpits**: Instant switching between **NOC Mode**, **Helpdesk Mode**, and **Systems Admin Mode** with role-aware action controls.

---

### 2.4 Hierarchical L1–L6 Network Topology & Dependency Graph (`topology-view.js`)

![Network Topology & Dependency Graph](docs/screenshots/network-topology.png)

* **6-Layer Physical & Logical Fabric Map**: Visualizes infrastructure across **L1 WAN Transit**, **L2 Edge Router**, **L3 Core Backbone**, **L4 Enterprise Servers**, **L5 Access Fabric**, and **L6 Operator Host** with algebraic connectivity ($\lambda_2$ Fiedler value), cut-edge detection, and live hop latency badges.
* **Interactive Blast-Radius & Path Trace**: Supports Longest-Prefix Match (LPM) route trie inspection, blast-radius simulation, and one-click pivoting into deep endpoint diagnostics.

---

### 2.5 NOC Dual-Pane Operations Center (`noc-view.js`)

![NOC Dual-Pane Dashboard](docs/screenshots/noc-dashboard.png)

* **Integrated Command View**: Pairs the live AI Brain confidence ribbon and RFC 1122 perimeter health controls with the interactive L1–L6 topology canvas, fleet inventory table, and real-time congestion telemetry.

---

### 2.6 Wireshark-Grade 3-Pane Live Packet Analysis (`sniffer-view.js`)

![Wireshark-Grade 3-Pane Packet Analysis](docs/screenshots/packet-analysis.png)

* **Three-Pane RFC Binary Dissector**:
  1. **Packet Stream Table**: Live kernel socket and wire capture with microsecond timestamps, source/destination endpoints, protocol badges (`HTTP`, `TCP`, `TLS`, `DNS`, `ICMP`), and TCP delta/retransmission tracking.
  2. **L2–L7 Protocol Tree & TLS 1.3 JA4 Fingerprint**: Inspects RFC 8446 TLS 1.3 ClientHello SNI and JA4 wire fingerprints alongside expandable protocol header trees.
  3. **Synchronized Hex & ASCII Dump**: Byte-accurate hexadecimal and ASCII payload inspection with one-click **Explain with AI** and **Follow Stream** workflows.
* **Dual-Stage Filtering**: Supports both **Kernel BPF Filters** (`tcp port 443 and host ...`) and **Wireshark AST Display Filters** (`ip.addr == ...`), plus L7 HTTP Waterfall and FFT Jitter Spectrum analyzers.

---

### 2.7 Ultra IP & Infrastructure Fleet Discovery Scanner (`ultra-ip-scanner-view.js`)

![Ultra IP & Asset Discovery Scanner](docs/screenshots/ip-asset-scanner.png)

* **Multi-Threaded Subnet Sweep**: Discovers active hosts, servers, gateways, printers, and network gear with configurable EDR-safe worker profiles (`8 Safe` up to high-concurrency sweeps).
* **Category & Fault Triage**: Summarizes **Total Active**, **Office Printers**, **Computers**, **VoIP Phones**, **Network Gear**, and **APIPA / Faults** with instant CSV/JSON export and printable audit reports.

---

### 2.8 Sysinternals-Grade Core Diagnostics & Recovery Workbench (`core-diagnostics-view.js`)

![Core Diagnostics & Recovery Workbench](docs/screenshots/diagnostics-workbench.png)

* **Three-Column Triage Architecture**:
  1. **The Machine X-Ray**: Live OS/kernel hardware profile and 4 Core Health Pillars (*Network Layer*, *Storage & SMART*, *Resource Allocation*, *Peripherals & Drivers*).
  2. **The Diagnosis Feed & Anomaly Triage**: Real-time anomaly detection backed by CUSUM change-point forensics and the 5-Agent Adversarial War-Room.
  3. **Action Center & Live Remediation Console**: Staged remediation queue with cryptographic action tokens and streaming execution output.

---

### 2.9 Governed Host Automation & Audited Remediation Library (`pc-automation-view.js`)

![Host Automation & Audited Remediation Library](docs/screenshots/host-automation.png)

* **28 Verified Diagnostic & Remediation Scripts**: Categorized across **Network**, **Diagnostic**, **Repair**, **Security**, and **Performance** with explicit privilege badges (`Standard User` vs `Administrator`) and risk tiers (`LOW`, `MEDIUM`, `HIGH`).
* **User-Space Sandbox Terminal**: Streams real-time `stdout`, `stderr`, exit codes, and execution latency with full audit-log persistence.

---

### 2.10 Sovereign Infrastructure Engineering Academy (`learning-center-view.js`)

![Sovereign Learning Center](docs/screenshots/learning-center.png)

* **Two Complete Professional Academies**:
  * **Network Engineering Academy (40 Hours)**: Cisco CCNA 200-301 blueprint covering physical transmission, IPv4/IPv6 subnetting, VLANs, OSPF, BGP, ACLs, and Python network automation.
  * **System Administration Academy (40 Hours)**: Enterprise Windows Server, Active Directory, PowerShell, Linux `systemd` daemons, kernel tuning, and SRE incident response.
* **Interactive Labs, Flashcards & Scored Quizzes**: Features **8 comprehensive courses**, **24 curriculum modules**, **72 lessons**, **8 simulated labs**, and **8 scored assessments** persisted in SQLite.

---

### 2.11 Sovereign Intelligence Fabric v6 — Unified Epistemic Control Plane (`v6-sovereign-fabric.js`)

![Sovereign Intelligence Fabric v6](docs/screenshots/sovereign-fabric-v6.png)

* **4-Column Epistemic Truth Matrix**:
  1. **Known from Live Evidence (Observations)**: Cryptographically tagged evidence records (`EVD-*`) with quality score $Q$ and provenance.
  2. **Simulated Projections (Isolated from Live Truth)**: Explicitly quarantined `M/M/1/K` digital-twin projections that can never pollute live operational state.
  3. **What EJII Does Not Know Yet (Unknowns)**: Transparent disclosure of unprobed protocol layers or sandbox boundaries.
  4. **Highest Information-Gain Next Probe**: Recommends the next diagnostic probe ranked by Shannon entropy reduction ($\Delta H$ in bits).

---

### 2.12 Responsive Mobile & Field Operator Experience (`390×844`)

<div align="center">
  <img src="docs/screenshots/mobile-overview.png" alt="EJII Mobile Responsive Experience" width="380" />
</div>

* **Field-Ready Compact Viewport**: Automatically collapses desktop command ribbons and adapts the navigation drawer, topbar actions, and conversational diagnostic cards for zero-horizontal-scroll operation on mobile devices (`390×844` and `768×1024`).

---

## 3. System Architecture & Dataflow

<div align="center">
  <img src="docs/assets/ejii-architecture-diagram.svg" alt="EJII v7.0 System Architecture Diagram" width="100%" />
</div>

### 3.1 End-to-End Request & Evidence Lifecycle

```mermaid
flowchart TB
    subgraph UI["Tier 1 · Project Aurora Unified Frontend (Browser)"]
        ChatUI["AI Assistant Workspace\n(chat-workspace-view.js)"]
        OpUI["AI Operator Console\n(ai-operator-view.js)"]
        Workstations["Topology · NOC · Sniffer · Scanner\nDiagnostics · Automation · Academy"]
    end

    subgraph Brain["Tier 2 · Project Falcon Conversational Brain & Sovereign Fabric v6"]
        ConvBrain["Conversational Brain\n(conversational-brain.js)"]
        Gemini["Semantic AI Interpreter\n(@google/genai · gemini-3.8-flash)"]
        ChatOp["Chat Operator Service\n(chat-operator-service.js)"]
        EvFabric["Sovereign Fabric v6\nEvidence Lineage DAG & Epistemic Guard"]
    end

    subgraph Probes["Tier 3 · Live Protocol Dissectors, OS Collectors & SQLite WAL"]
        LocalISP["5-Layer Local-to-ISP Engine\n(NIC/DHCP -> Gateway -> DNS -> TCP -> HTTP)"]
        Proto["Protocol Probes\n(dns-diag · tcp · tls · http · icmp)"]
        HostOS["Host & Kernel Collectors\n(Sockets · Routes · ARP · CPU/RAM)"]
        DB[("SQLite WAL Database\n(Users · Sessions · Evidence · Baselines)")]
    end

    ChatUI -->|"Natural Language + Session Context"| ConvBrain
    ConvBrain <-->|"Structured JSON Intent & Synthesis"| Gemini
    ConvBrain -->|"Resolved Action & Target"| ChatOp
    ChatOp --> LocalISP & Proto & HostOS
    OpUI & Workstations --> EvFabric
    EvFabric --> Proto & HostOS & DB
    ChatOp -->|"Persisted Turn & Ownership"| DB
```

---

## 4. Project Falcon — AI-Native Conversational Intelligence

EJII's conversational engine (`src/core/chat/conversational-brain.js`, `src/core/chat/semantic-ai-interpreter.js`, and `src/core/chat/chat-operator-service.js`) is architected to behave like a senior infrastructure engineer—never a rigid keyword parser.

### 4.1 Multi-Turn Contextual Reasoning & Pronoun Resolution

```mermaid
sequenceDiagram
    participant User as Operator
    participant Brain as ConversationalBrain
    participant LLM as Gemini Semantic AI
    participant Probes as Live Protocol Engine
    participant DB as SQLite Session Store

    User->>Brain: "Check DNS for example.com"
    Brain->>Probes: Execute RFC 1035 DNS lookup (example.com)
    Probes-->>Brain: A=93.184.215.14, RTT=18.4ms, Resolver=Observed OS
    Brain->>DB: Save lastTarget="example.com", lastCheckType="dns"
    Brain-->>User: "example.com resolves to 93.184.215.14 (18.4 ms)..."

    User->>Brain: "Now check port 443 on the same host"
    Brain->>Brain: Resolve "the same host" -> "example.com" from session state
    Brain->>Probes: Execute TCP 3-way handshake (example.com:443)
    Probes-->>Brain: TCP OPEN, RTT=21.2ms
    Brain->>LLM: Synthesize multi-turn contextual answer
    Brain-->>User: "TCP port 443 on example.com is OPEN (21.2 ms)..."
```

### 4.2 Guided Multi-Turn Troubleshooting Workflows

* **Email Service Troubleshooting (`mail_troubleshooting`)**:
  * When a user says *"My email is not working"* or *"I cannot login to my mail"*, EJII never confuses external email troubleshooting with EJII's own sign-in screen.
  * Instead, it asks which email provider or domain is affected (e.g., `gmail.com`, `outlook.com`, or a custom corporate mail domain) and whether the failure occurs in a browser or a mail client (Outlook/Apple Mail/Thunderbird).
  * Once the user replies (e.g., *"gmail.com in browser"*), EJII automatically runs a coordinated multi-probe check (DNS resolution, MX record lookup, HTTPS webmail reachability, and SMTP/IMAP submission ports `993`/`587`/`465`) and synthesizes a clear diagnosis.
* **5-Layer Local-to-ISP Connectivity Diagnosis (`local_network_diagnosis`)**:
  * When a user reports *"Internet is not working on this machine"* or *"Check my local network and ISP connection"*, EJII executes a structured 5-layer diagnostic progression:
    1. **Layer 1 — Network Interface & DHCP Status**: Inspects active non-loopback NICs, IPv4/IPv6 addresses, and real OS DHCP lease status (`dhcpEnabled`, `dhcpServer`, `verificationMethod`).
    2. **Layer 2 — Default Gateway Reachability**: Discovers the real OS default route (`ip route` / `/proc/net/route` / `route print`) without hardcoded `192.168.1.1` fallbacks and probes gateway reachability.
    3. **Layer 3 — System DNS Resolver Health**: Verifies the actual OS-configured DNS server (`resolvectl`, `scutil --dns`, `/etc/resolv.conf`, `Get-DnsClientServerAddress`), distinguishing local stub resolvers (`127.0.0.53`) from upstream resolvers.
    4. **Layer 4 — External TCP Reachability**: Tests direct TCP transport connectivity (`1.1.1.1:443`) to isolate DNS failures from routing/ISP drops.
    5. **Layer 5 — External HTTP/HTTPS Reachability**: Verifies end-to-end DNS + TLS + HTTP application-layer connectivity.

---

## 5. Epistemic Integrity & Zero-Fabrication Engineering

EJII enforces strict engineering guardrails across every backend collector and frontend view:

| Engineering Guarantee | Implementation File(s) | Verification Behavior |
| :--- | :--- | :--- |
| **No Assumed DNS Resolver Fallbacks** | `src/protocols/dns-diag.js` (`getRealSystemDns`) | Never substitutes `8.8.8.8` when OS resolver discovery is unavailable. Explicitly classifies `observed_os_config`, `local_stub_resolver`, or `unknown` with collection provenance. |
| **Zero Fabricated Timing Values** | `src/core/chat/chat-operator-service.js`, `src/protocols/*` | Eliminates synthetic fallback durations (`\|\| 1.2`, `\|\| 1.0`). Uses `performance.now()` / `process.hrtime.bigint()` and reports `null` (`unmeasured`) if timing was not captured. |
| **No Hardcoded Gateway Fallbacks** | `src/protocols/host-metrics.js` (`getVerifiedDefaultGateway`) | Never fabricates `192.168.1.1` when the OS routing table cannot be read; returns `gatewayIp: null, verified: false, reason: 'NO_DEFAULT_ROUTE_OBSERVED'`. |
| **Transport vs. Application Distinction** | `src/core/chat/chat-operator-service.js` | A successful TCP port check (`SYN -> SYN-ACK`) is reported strictly as transport-layer reachability, explicitly noting that HTTP/TLS verification is required for application health. |
| **Simulated vs. Live Evidence Isolation** | `src/core/evidence/evidence-fabric.js` | Every `M/M/1/K` digital-twin simulation record carries `isolatedFromLiveTruth: true` and is capped at `HYPOTHESIS` confidence so simulations never masquerade as live wire truth. |
| **Strict Session Ownership & RBAC** | `src/server.js`, `src/core/security.js` | Every chat session and diagnostic history record is bound to `ownerUserId`. Non-owners receive `403 Forbidden` on read, write, and delete operations. |

---

## 6. Complete Capability Matrix

| Workstation / Domain | Key Modules | Core Capabilities |
| :--- | :--- | :--- |
| **1. AI Diagnostic Assistant** | `public/js/views/chat-workspace-view.js`<br>`src/core/chat/conversational-brain.js` | Multi-turn natural-language diagnostics, Gemini 3.8 Flash semantic interpretation, pronoun/context resolution, guided mail & ISP workflows, collapsible raw telemetry. |
| **2. Autonomous AI Operator** | `public/js/views/ai-operator-view.js`<br>`src/core/operator/autonomous-infrastructure-operator.js` | Continuous anomaly detection, natural-language goal planner, 4-agent AI Operations Council, pre-snapshot self-healing, postcondition verification, honest auto-rollback. |
| **3. Network Topology & NOC** | `public/js/views/topology-view.js`<br>`public/js/views/noc-view.js` | L1–L6 hierarchical dependency graph, Fiedler algebraic connectivity ($\lambda_2$), cut-vertex detection, LPM route trie, blast-radius simulator, live hop telemetry. |
| **4. 3-Pane Packet Analysis** | `public/js/views/sniffer-view.js`<br>`src/sniffer/wire-dissector-apex.js` | Live kernel socket & wire capture, L2–L7 binary header tree, TLS 1.3 JA4 fingerprinting, hex/ASCII inspector, Kernel BPF & Wireshark AST filters, FFT jitter & QoS studio. |
| **5. Ultra IP & Asset Scanner** | `public/js/views/ultra-ip-scanner-view.js` | Multi-threaded subnet discovery, EDR-safe scan profiles, MAC OUI vendor resolution, open port auditing, printer/VoIP/APIPA classification, CSV/JSON/Print export. |
| **6. Core Diagnostics Workbench** | `public/js/views/core-diagnostics-view.js` | 4-pillar host health X-ray, CUSUM change-point anomaly triage, 5-Agent War-Room root-cause arbitration, process-to-socket matrix, staged remediation console. |
| **7. Host Automation Library** | `public/js/views/pc-automation-view.js` | 28 audited remediation & audit scripts across Network, Repair, Security, and Performance with risk-tier badges and streaming execution terminal. |
| **8. Sovereign Learning Center** | `public/js/views/learning-center-view.js`<br>`src/core/learning-academy-data.js` | 2 specialist academies (Network CCNA 200-301 & System Administration), 8 courses, 24 modules, 72 lessons, 8 interactive labs, flashcards, and scored quizzes. |
| **9. Sovereign Fabric v6 Studio** | `public/js/views/v6-sovereign-fabric.js`<br>`src/core/evidence/*` | 17 registered capabilities, 11 evidence classes, acyclic evidence lineage DAG, Shannon information-gain probe recommender, and governed remediation control plane. |

---

## 7. Quick Start, Configuration & Verification

### 7.1 Prerequisites

* **Node.js**: `v20.0.0+` or `v22.0.0+` (uses native `node:sqlite` and high-resolution diagnostics)
* **Operating Systems**: Linux, Windows, or macOS (automatically adapts OS-native collectors for `ip`/`ss`/`resolvectl`, PowerShell/`netstat`, or `scutil`/`route`)

### 7.2 Installation & Startup

```bash
# 1. Install dependencies
npm install

# 2. Start the EJII server (defaults to port 3000 in development or EJII_PORT)
npm run dev
```

Open **`http://localhost:3000`** in your browser.

### 7.3 Environment Configuration (`.env.example`)

| Environment Variable | Default | Description |
| :--- | :--- | :--- |
| `EJII_PORT` / `PORT` | `3000` (dev) / `8443` | HTTP/WebSocket listener port |
| `EJII_HOST` | `127.0.0.1` | Bind address (`0.0.0.0` supported in container/cloud preview) |
| `GEMINI_API_KEY` | *(System-injected)* | Enables live `@google/genai` (`gemini-3.8-flash`) semantic interpretation, native function calling, and natural-language synthesis in `ConversationalBrain` |
| `EJII_DB_PATH` | `./data/ejii.sqlite` | Path to the SQLite WAL persistence database |
| `EJII_EVALUATION_MODE` | `false` | When `true` on local loopback, enables one-click evaluation persona selectors on the sign-in screen |

### 7.4 Running the Automated Verification Suites

EJII includes **100 end-to-end NOC verification suites** and **46+ core conversational, epistemic, & protocol unit tests**:

```bash
# Run all Project Falcon & Phase 6 core unit tests (DNS, DHCP, 5-layer ISP, Conversational Brain, Eval Suite)
node --test src/core/__tests__/*.test.js

# Run the complete 100-suite EJII NOC architectural, security, protocol, and UI verification harness
node tests/run-all-tests.js

# Re-capture all 12 live application screenshots via Playwright
node scripts/capture-aurora-screenshots.js
```

---

## 8. Repository Structure

```text
├── docs/
│   ├── assets/                        # Custom SVG hero banner & system architecture diagrams
│   └── screenshots/                   # 12 real Playwright browser screenshots (1440x900 & 390x844)
├── public/
│   ├── css/
│   │   ├── ejii-meridian.css          # Project Aurora Architectural Slate & Executive Blue design system
│   │   └── chat-minimal.css           # Conversational AI workspace & responsive layout styles
│   ├── js/
│   │   ├── app.js                     # Unified router, WebSocket client, RBAC session manager
│   │   └── views/                     # 9 modular frontend workstations (Chat, AI Operator, Topology, Sniffer, etc.)
│   └── index.html                     # Single-page application shell, login screen, sidebar & topbar
├── scripts/
│   ├── capture-aurora-screenshots.js  # Automated Playwright visual capture across all 12 views
│   └── *.bat                          # 28 audited host diagnostic & remediation scripts
├── src/
│   ├── core/
│   │   ├── chat/                      # Project Falcon ConversationalBrain, Gemini AI Interpreter, ChatOperatorService
│   │   ├── evidence/                  # Sovereign Intelligence Fabric v6 (Evidence DAG, Causal RCA, Governance)
│   │   ├── operator/                  # Autonomous Infrastructure Operator & Self-Healing Playbooks
│   │   ├── __tests__/                 # Unit & evaluation tests for conversational brain, DNS/DHCP, and Sovereign Fabric v6
│   │   └── security.js                # PBKDF2-SHA512 password hashing, HMAC-SHA256 JWTs, capability RBAC
│   ├── db/
│   │   └── database.js                # Native node:sqlite WAL schema, triggers, and persistence layer
│   ├── protocols/                     # Real L2–L7 protocol engines (dns-diag, tcp-port, tls-audit, http-probe, host-metrics)
│   ├── sniffer/                       # Wireshark-grade RFC binary packet dissector (wire-dissector-apex.js)
│   └── server.js                      # HTTP/REST API & WebSocket real-time telemetry server
└── tests/
    ├── run-all-tests.js               # Master runner for all 100 NOC verification suites
    └── *.test.js                      # Suites 1–100 covering security, protocols, AI brain, and UI cohesion
```

---

<div align="center">
  <sub>Architected & Engineered for <strong>Eldar Jamiyev's Infrastructure Intelligence (EJII)</strong> · Project Falcon & Project Aurora Release</sub>
</div>
