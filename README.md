<div align="center">
  <img width="100%" alt="EJII — Eldar Jamiyev's Infrastructure Intelligence" src="https://capsule-render.vercel.app/api?type=waving&amp;color=0:0F172A,48:17324D,100:2563EB&amp;height=230&amp;section=header&amp;text=EJII&amp;fontSize=82&amp;fontColor=F8FAFC&amp;fontAlignY=36&amp;desc=ELDAR%20JAMIYEV%27S%20INFRASTRUCTURE%20INTELLIGENCE&amp;descAlignY=62&amp;descSize=16" />
  <h1>EJII · Infrastructure Intelligence</h1>
  <p><strong>Observe the system. Understand the evidence. Verify the outcome.</strong></p>
  <p>A local-first infrastructure workstation for network visibility, packet analysis, host diagnostics, evidence-aware investigation, controlled automation, telemetry history, and hands-on engineering education.</p>
  <p>
    <a href="https://github.com/EldarJamiyev/Eldar-Jamiyev-Infrastructure-Intelligence"><img alt="Repository" src="https://img.shields.io/badge/Repository-EldarJamiyev-111827?style=for-the-badge&amp;logo=github&amp;logoColor=white"></a>
    <a href="https://nodejs.org/"><img alt="Node.js" src="https://img.shields.io/badge/Runtime-Node.js-43853D?style=for-the-badge&amp;logo=nodedotjs&amp;logoColor=white"></a>
    <a href="https://www.typescriptlang.org/"><img alt="TypeScript" src="https://img.shields.io/badge/Engines-TypeScript-3178C6?style=for-the-badge&amp;logo=typescript&amp;logoColor=white"></a>
    <a href="https://expressjs.com/"><img alt="Express" src="https://img.shields.io/badge/API-Express-404D59?style=for-the-badge&amp;logo=express&amp;logoColor=white"></a>
    <a href="https://www.sqlite.org/"><img alt="SQLite" src="https://img.shields.io/badge/Storage-SQLite-003B57?style=for-the-badge&amp;logo=sqlite&amp;logoColor=white"></a>
    <img alt="Package license" src="https://img.shields.io/badge/License-UNLICENSED-B91C1C?style=for-the-badge">
  </p>
  <p>
    <a href="#-start-here">Start here</a> ·
    <a href="#-capability-map">Capabilities</a> ·
    <a href="#-architecture">Architecture</a> ·
    <a href="#-sovereign-academy">Academy</a> ·
    <a href="#-security--operational-boundaries">Security</a> ·
    <a href="#-tests--verification">Tests</a>
  </p>
</div>

---

## The idea

**EJII — Eldar Jamiyev’s Infrastructure Intelligence** is an engineering project that brings network operations, packet-level inspection, system diagnostics, investigation tooling, automation safeguards, observability, and technical training into one application.

Instead of treating each diagnostic as an isolated command, EJII aims to help an operator move through a complete investigation:

<div align="center">
  <table>
    <tr>
      <td align="center"><strong>01 · OBSERVE</strong><br>Collect available evidence</td>
      <td align="center">→</td>
      <td align="center"><strong>02 · CORRELATE</strong><br>Connect related signals</td>
      <td align="center">→</td>
      <td align="center"><strong>03 · INVESTIGATE</strong><br>Test competing explanations</td>
    </tr>
    <tr>
      <td align="center"><strong>04 · PLAN</strong><br>Choose a supported action</td>
      <td align="center">→</td>
      <td align="center"><strong>05 · VERIFY</strong><br>Check the observed result</td>
      <td align="center">→</td>
      <td align="center"><strong>06 · LEARN</strong><br>Preserve reusable knowledge</td>
    </tr>
  </table>
</div>

The governing principle is simple: **an observation, a calculation, a hypothesis, a simulation, and a verified result are different things.** The interface and documentation should preserve those distinctions.

> **Project status:** This repository contains substantial operational and educational code, including real diagnostic paths and explicitly simulated learning labs. Available features depend on the host operating system, permissions, installed tools, drivers, configuration, and the quality of the collected evidence. Read the limits below before using EJII against a real environment.

## ✦ Capability map

<table>
  <tr>
    <td width="50%" valign="top">
      <h3>🌐 Network topology &amp; path analysis</h3>
      Model observed network nodes and relationships, inspect topology snapshots, trace supported paths, explore dependency impact, and review topology-related findings.
    </td>
    <td width="50%" valign="top">
      <h3>🦈 Packet &amp; protocol inspection</h3>
      Inspect captured frames, flows, protocol fields, TCP stream information, and hex/ASCII data where available. Supported parsing includes selected QUIC, SSH, SMB2/3, HTTP/2, DHCP, DNS and mDNS-related structures.
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <h3>🔎 Network discovery &amp; diagnostics</h3>
      Use supported host probes, port checks, DNS/TLS/HTTP diagnostics, ARP information, scanner workflows, SNMP operations, and office-device investigation.
    </td>
    <td width="50%" valign="top">
      <h3>🖥️ Host &amp; system intelligence</h3>
      Inspect available host metrics, services, process/socket relationships, hardware information, network configuration, diagnostic trends, and platform-specific system information.
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <h3>🧠 Reasoning &amp; investigations</h3>
      Use the existing AI Brain, RCA endpoints, evidence-oriented diagnostic workflows, selected causal and temporal reasoning components, and the five-stage War-Room orchestration model.
    </td>
    <td width="50%" valign="top">
      <h3>🛡️ Governed automation</h3>
      Discover registered scripts, inspect execution history, apply role and permission checks, use configured safety gates, and verify supported remediation outcomes.
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <h3>🕒 Telemetry history &amp; observability</h3>
      Record and compare supported snapshots, inspect telemetry history, export observability data, and use available Prometheus/OpenTelemetry-oriented endpoints.
    </td>
    <td width="50%" valign="top">
      <h3>🎓 Sovereign Academy</h3>
      Study networking and system administration through structured courses, lessons, server-scored quizzes, saved progress, and deterministic educational labs.
    </td>
  </tr>
</table>

### The eight highlighted v5 engines

| Engine | Purpose | Important boundary |
|---|---|---|
| **L7 Deep Protocol Dissector** | Parses selected fields from supported QUIC, SSH, SMB2/3 and HTTP/2 input. | It can only decode fields present in the supplied bytes; encrypted application payloads are not automatically decrypted. |
| **Spectral Fourier Detector** | Applies FFT-based spectral analysis and flags selected periodic patterns. | A spectral anomaly is a signal for investigation, not proof of malicious activity. |
| **Digital Twin Chaos Simulator** | Models selected topology failures and queueing/graph effects. | Its outputs are model results, not guaranteed predictions of a live production network. |
| **Zero-Trust Policy Synthesizer** | Generates proposed policy representations for supported platforms. | Generated configuration requires validation and review before any real application. |
| **Multipath QoS Auditor** | Interprets DSCP/ECN markings and selected QoS or fragmentation-related signals. | A difference between observations does not by itself identify the device that caused it. |
| **Hardware &amp; Kernel Inspector** | Reads supported OS, network-adapter and kernel settings. | Results vary by OS, driver, permissions and available interfaces. |
| **Telemetry DVR Time Machine** | Maintains a bounded snapshot history and compares supported node/edge state. | Gaps or stale captures must not be interpreted as continuous observation. |
| **Autonomous War-Room** | Orchestrates triage, topology, wire analysis, planning and safety review stages. | Its conclusions depend on its inputs and rules; the safety stage does not replace authorization. |

The names above describe the implemented engine areas. They do not imply an independent certification, a calibrated prediction rate, or complete support for every protocol feature.

## ◈ The Sovereign Academy

EJII includes two separate learning tracks using the same learning interface and API.

<div align="center">
  <table>
    <tr>
      <td width="50%" valign="top">
        <h3>🌐 Network Academy</h3>
        <p><strong>CCNA preparation &amp; network administration</strong></p>
        <ul>
          <li>Network foundations and Ethernet</li>
          <li>Switching, VLANs and trunking</li>
          <li>IPv4, CIDR, VLSM and IPv6 fundamentals</li>
          <li>Routing tables and longest-prefix match</li>
          <li>DNS, DHCP, QoS and network troubleshooting</li>
          <li>Packet journey and switching simulations</li>
        </ul>
        <p><a href="https://github.com/EldarJamiyev/Eldar-Jamiyev-Infrastructure-Intelligence/tree/main/public/js/learning">Explore learning implementation →</a></p>
      </td>
      <td width="50%" valign="top">
        <h3>🖥️ System Administration Academy</h3>
        <p><strong>Windows, Linux &amp; enterprise operations</strong></p>
        <ul>
          <li>Windows Server and Active Directory concepts</li>
          <li>Users, groups, services and permissions</li>
          <li>PowerShell practice in a safe sandbox</li>
          <li>Linux filesystem, services and command exercises</li>
          <li>DNS/DHCP incident scenarios</li>
          <li>Operational troubleshooting and service health</li>
        </ul>
        <p><a href="https://github.com/EldarJamiyev/Eldar-Jamiyev-Infrastructure-Intelligence/tree/main/src/learning">Explore curriculum source →</a></p>
      </td>
    </tr>
  </table>
</div>

### Curriculum snapshot

The current curriculum and accompanying test report describe the following structure:

| Component | Reported count |
|---|---:|
| Learning tracks | 2 |
| Courses | 8 |
| Modules | 24 |
| Lessons | 72 |
| Course quizzes | 8 |
| Educational labs | 8 |

Counts describe the current catalog structure and can change as the curriculum evolves. Run the catalog tests to verify the current branch rather than treating these numbers as immutable.

### Interactive learning labs

| Lab | What it teaches |
|---|---|
| **IPv4 Subnetting Trainer** | Network boundaries, CIDR masks, address ranges, edge prefixes and step-by-step calculations. |
| **Packet Journey** | Layer 2 frame changes versus Layer 3 packet addressing across hops. |
| **VLAN Lab** | Access VLANs, trunk allowances, link state and simulated connectivity outcomes. |
| **Routing Explorer** | Route matching and longest-prefix selection using structured sample routes. |
| **PowerShell Sandbox** | Supported educational commands against a simulated Windows environment. |
| **Linux Sandbox** | Supported commands against a simulated filesystem and service model. |
| **Active Directory Lab** | A fictional domain, organizational units, group membership and permission exercises. |
| **DNS/DHCP Lab** | Deterministic troubleshooting scenarios with evidence and remediation scoring. |

> **Lab safety:** educational labs are simulated environments. Their outputs must not be interpreted as changes made to the real host, a real domain controller, or a production network. The networking and system tools exposed elsewhere in EJII have different execution and permission boundaries.

## ⌁ Architecture

EJII uses a conventional server-backed architecture: a browser interface, an Express API, specialized diagnostic and reasoning modules, and persistent local data.

~~~mermaid
flowchart TB
    OP["Operator"] --> UI["Web UI<br/>HTML · CSS · JavaScript"]
    UI --> API["Express API<br/>Authentication · Validation · Permissions"]
    API --> NET["Network Intelligence<br/>Discovery · Capture · Protocol Analysis"]
    API --> SYS["System Diagnostics<br/>Host · Services · Hardware"]
    API --> RCA["RCA & Reasoning<br/>AI Brain · War-Room · Spectral Analysis"]
    API --> OBS["Observability<br/>Snapshots · DVR · Export"]
    API --> EDU["Sovereign Academy<br/>Courses · Quizzes · Labs"]
    NET --> OS["Supported OS / Network I/O"]
    SYS --> OS
    RCA --> EV["Diagnostic Evidence & Derived Results"]
    OBS --> DB[("SQLite / Local Data")]
    EDU --> DB
    API --> DB
    style OP fill:#0F172A,color:#FFFFFF,stroke:#334155
    style API fill:#1D4ED8,color:#FFFFFF,stroke:#60A5FA
    style DB fill:#F1F5F9,color:#0F172A,stroke:#94A3B8
~~~

### Architectural layers

| Layer | Location | Responsibility |
|---|---|---|
| Application shell | <code>public/index.html</code>, <code>public/js/app.js</code> | Main navigation, frontend state, view dispatch and authenticated API access. |
| Workbenches | <code>public/js/views/</code>, <code>public/js/components/</code> | Topology, sniffer, scanner, automation, diagnostics, learning and shared UI. |
| API | <code>src/api/</code> | Express routes for authentication, diagnostics, network tools, RCA, observability and learning. |
| Protocol engines | <code>src/sniffer/</code>, <code>src/network/</code>, <code>src/protocols/</code> | Parsing, probes, capture integrations and network-level utilities. |
| Reasoning | <code>src/ai/</code>, <code>src/core/</code> | Investigation, AI Brain, evidence processing and orchestration components. |
| Policy and safety | <code>src/security/</code> | Permissions, policy synthesis, safe execution controls and audit-related functions. |
| Observability | <code>src/observability/</code> | Snapshot recording, diffs, telemetry-oriented routes and exports. |
| Learning | <code>src/learning/</code>, <code>public/js/learning/</code> | Curriculum catalog, validation, quizzes, progress services, view rendering and labs. |
| Persistence and configuration | <code>src/db/</code>, <code>src/config.js</code> | SQLite initialization, configuration, data directories and runtime settings. |

### API surface

The server currently mounts these API groups:

| Base path | Area |
|---|---|
| <code>/api/auth</code> | Authentication and account-related flows. |
| <code>/api/network</code> | Topology, packet capture, network discovery, protocol tools and scanner operations. |
| <code>/api/diagnostics</code> | Host diagnostics and supported remediation-related routes. |
| <code>/api/tools</code> | Supporting diagnostic tools. |
| <code>/api/rca</code> | Root-cause analysis, investigations, reasoning and War-Room operations. |
| <code>/api/observability</code> | Telemetry, snapshot, export and observability-oriented endpoints. |
| <code>/api/learning</code> | Learning catalog, lessons, progress, notes, bookmarks, quizzes and recommendations. |

Use the endpoint implementations and their middleware as the source of truth for precise route contracts and permission requirements. Not every endpoint has the same access policy.

## ⚙️ Technology stack

<p>
  <img alt="JavaScript" src="https://img.shields.io/badge/Frontend-JavaScript-F7DF1E?style=flat-square&amp;logo=javascript&amp;logoColor=111827">
  <img alt="HTML5" src="https://img.shields.io/badge/UI-HTML5-E34F26?style=flat-square&amp;logo=html5&amp;logoColor=white">
  <img alt="CSS3" src="https://img.shields.io/badge/Styling-CSS3-1572B6?style=flat-square&amp;logo=css3&amp;logoColor=white">
  <img alt="TypeScript" src="https://img.shields.io/badge/Engines-TypeScript-3178C6?style=flat-square&amp;logo=typescript&amp;logoColor=white">
  <img alt="Node.js" src="https://img.shields.io/badge/Runtime-Node.js-43853D?style=flat-square&amp;logo=nodedotjs&amp;logoColor=white">
  <img alt="Express" src="https://img.shields.io/badge/Server-Express-404D59?style=flat-square&amp;logo=express&amp;logoColor=white">
  <img alt="SQLite" src="https://img.shields.io/badge/Data-SQLite-003B57?style=flat-square&amp;logo=sqlite&amp;logoColor=white">
  <img alt="WebSockets" src="https://img.shields.io/badge/Realtime-WebSockets-4B5563?style=flat-square&amp;logo=socketdotio&amp;logoColor=white">
</p>

- **Frontend:** vanilla JavaScript, HTML, CSS and the existing EJII design system.
- **Backend:** Node.js and Express.
- **Typed engines:** TypeScript compiled using the repository's TypeScript configuration.
- **Persistence:** SQLite through the runtime's native SQLite support.
- **Live updates:** WebSocket support is provided by the installed <code>ws</code> dependency and application integrations.
- **Network tooling:** native sockets and platform-specific integrations; physical capture depends on supported adapters, drivers and permissions.
- **SNMP:** <code>net-snmp</code> is included for supported SNMP operations.

This repository does not use a React/Vite build pipeline in its current package scripts. The existing frontend is loaded through the application shell and its script references.

## 🚀 Start here

### Prerequisites

- Git.
- Node.js with support for the built-in <code>node:sqlite</code> module. Node.js 22.5 or newer is a practical starting point; support and experimental flags vary by Node release.
- npm.
- A supported operating system and required permissions for the features you intend to use.
- Optional: Npcap on Windows for supported physical packet-capture functionality.

Check your runtime before running the application:

~~~bash
node --version
npm --version
~~~

### 1 · Clone and install

~~~bash
git clone https://github.com/EldarJamiyev/Eldar-Jamiyev-Infrastructure-Intelligence.git
cd Eldar-Jamiyev-Infrastructure-Intelligence
npm ci
~~~

If the lockfile cannot be used with your environment, investigate the dependency/runtime mismatch before switching to an unconstrained installation.

### 2 · Build the TypeScript engines

~~~bash
npm run build
~~~

This runs the configured TypeScript compiler. A successful build verifies compilation, not every runtime path or live operating-system integration.

### 3 · Run the test suite

~~~bash
npm test
~~~

The package's <code>pretest</code> hook runs TypeScript compilation before the master test runner. The runner is <code>node tests/run-all-tests.js</code>.

### 4 · Start EJII

For a local development session, set the bind address and port explicitly.

**PowerShell:**

~~~powershell
$env:NODE_ENV = "development"
$env:EJII_HOST = "127.0.0.1"
$env:EJII_PORT = "8443"
npm start
~~~

**Linux / macOS shell:**

~~~bash
export NODE_ENV=development
export EJII_HOST=127.0.0.1
export EJII_PORT=8443
npm start
~~~

Open [http://127.0.0.1:8443](http://127.0.0.1:8443).

The default configuration is intended to bind to loopback. Keep it local unless you have deliberately configured and reviewed a protected deployment.

### Optional launchers and containers

The repository also contains:

- <code>setup-launcher.bat</code> — Windows launcher.
- <code>setup-launcher.sh</code> — POSIX/Linux launcher.
- <code>Dockerfile</code> and <code>docker-compose.yml</code> — container deployment files.

Inspect launcher and container configuration before using it on a workstation or production system. In particular, the checked-in Compose file contains default signing-secret values while production configuration rejects those defaults. **Do not deploy the Compose file unchanged in production.** Supply unique secret values through a secure runtime configuration and review network exposure, capabilities and persistent-volume behavior first.

## 🔐 Configuration and security

EJII interacts with real host and network capabilities. Treat it as operational software, not a harmless static dashboard.

### Core configuration

| Variable | Purpose | Guidance |
|---|---|---|
| <code>NODE_ENV</code> | Runtime mode. | Use <code>production</code> only after supplying secure production configuration. |
| <code>EJII_HOST</code> | Network bind address. | Keep <code>127.0.0.1</code> for local use; expose externally only behind deliberate network controls. |
| <code>EJII_PORT</code> | HTTP service port. | Defaults to <code>8443</code>. |
| <code>EJII_DATA_DIR</code> | Persistent runtime data directory. | Use a controlled writable directory with appropriate backups and access permissions. |
| <code>EJII_DB_PATH</code> | Optional explicit SQLite path. | Ensure it points to the intended database. |
| <code>EJII_HMAC_SECRET</code> | HMAC signing secret. | Required in production; use a unique random value of at least 32 characters. |
| <code>EJII_JWT_SECRET</code> | Token-signing secret. | Required in production; use a separate unique random value of at least 32 characters. |
| <code>EJII_ADMIN_PASSWORD</code> | Optional first-run bootstrap password. | Use only through a protected initial setup process; never commit real credentials. |
| <code>EJII_EVALUATION_MODE</code> | Controls evaluation-mode behavior. | Review the source configuration and consequences before changing it. |

The repository includes <code>.env.example</code> as a configuration template. Runtime settings are read from process environment variables; ensure that the launcher or service manager actually exports them. Do not assume that creating a file named <code>.env</code> automatically loads it.

Generate production secrets with a trusted random generator. For example, run the following command separately for each secret and store the results in a secret manager or protected environment configuration:

~~~bash
node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
~~~

Never reuse the same value for the HMAC and JWT secrets. Never commit real secrets, tokens, credentials, live databases or private keys.

### Operational boundaries

- **Live versus simulated:** the normal diagnostic paths and educational simulations have different purposes. Never read a lab result as proof of live network state.
- **Capture prerequisites:** physical capture depends on the OS, Npcap or another supported capture path, selected adapter and permissions.
- **Encrypted traffic:** packet inspection can reveal fields available in the capture, but it does not automatically decrypt TLS, SSH or QUIC application payloads.
- **Anomaly interpretation:** spectral patterns, fingerprints and heuristic indicators are evidence to investigate, not conclusive proof of compromise.
- **Remediation:** real system changes can cause disruption. Review action inputs, permissions, preconditions and verification outcomes.
- **Network scope:** scan and probe only systems you own or are explicitly authorized to assess.
- **Exposure:** loopback is the safer default for a single workstation. Binding to all interfaces changes the risk profile.
- **Audit evidence:** integrity protection can help detect changes to records; it does not make the original observation or conclusion infallible.

## ⌘ CLI diagnostics

The project includes a terminal diagnostic utility at <code>bin/run-diagnostics-cli.js</code>.

~~~bash
# Show supported commands
node bin/run-diagnostics-cli.js help

# Test ICMP reachability
node bin/run-diagnostics-cli.js ping example.com

# Test a TCP port
node bin/run-diagnostics-cli.js port example.com 443

# Sweep the utility's configured common ports
node bin/run-diagnostics-cli.js sweep example.com

# Resolve a DNS A record
node bin/run-diagnostics-cli.js dns example.com

# Inspect the TLS endpoint on port 443
node bin/run-diagnostics-cli.js tls example.com

# Probe an HTTP(S) endpoint
node bin/run-diagnostics-cli.js http https://example.com

# Inspect available local host metrics
node bin/run-diagnostics-cli.js host

# Verify the local HMAC audit chain
node bin/run-diagnostics-cli.js audit-verify

# Emit the supported JSON diagnostic summary
node bin/run-diagnostics-cli.js json
~~~

Use only authorized target systems. A timeout, permission error or unavailable local tool must be interpreted as that specific result—not automatically as proof that the target is offline.

## 🧪 Tests and verification

The current package scripts are:

| Command | Purpose |
|---|---|
| <code>npm run build</code> | Compile TypeScript using <code>tsc</code>. |
| <code>npm test</code> | Run the configured <code>pretest</code> build and master test runner. |
| <code>node tests/run-all-tests.js</code> | Invoke the master suite runner directly when the build prerequisite has already been satisfied. |
| <code>npm start</code> | Start the Express application. |
| <code>npm run cli</code> | Invoke the diagnostic CLI entry point. |
| <code>npm run seed</code> | Run the database seeding/bootstrap script; review its behavior before using it against an existing data directory. |

The repository's test inventory covers network probes, topology, packet parsing, diagnostics, security, automation, observability, frontend behavior, Academy services and other regressions.

The accompanying test-integrity report records a 100-suite milestone. That is a report of a particular verification state, not a live CI status badge. Re-run the current branch's tests and inspect the process exit code and failure output before relying on any test count or pass claim.

### What strong verification means

- Unit assertions exercise real calculations and edge cases.
- Integration tests verify actual route and service wiring.
- Security tests verify both allowed and rejected requests.
- Browser tests confirm the intended screen and interactions—not just that an image file exists.
- Runtime checks verify server health independently of compilation.
- A successful screenshot process must produce a valid, decodable image of the expected page.
- A simulated lab test must never be counted as a live network test.

Reports should identify the exact commit, command, environment, executed suite count, failures and artifacts that were actually observed.

## 📁 Repository map

~~~text
Eldar-Jamiyev-Infrastructure-Intelligence/
├── bin/                    # CLI and desktop entry points
├── data/                   # Runtime data and script mounts; inspect before sharing
├── desktop/                # Desktop-related assets or integration
├── docs/                   # Supporting technical documentation
├── mobile/                 # Mobile-related assets or integration
├── policies/               # Policy material
├── public/
│   ├── css/                # Main and learning design systems
│   ├── js/
│   │   ├── components/     # Shared interface components
│   │   ├── learning/       # Learning client, router, store and labs
│   │   └── views/          # Application workbenches
│   └── index.html          # Frontend shell
├── runbooks/               # Operational runbooks
├── scripts/                # Supported automation scripts
├── src/
│   ├── ai/                 # Reasoning and analysis engines
│   ├── api/                # Express API routes and middleware
│   ├── core/               # Shared services, security and AI Brain
│   ├── db/                 # Database initialization and seeding
│   ├── diagnostics/        # Host and kernel diagnostics
│   ├── learning/           # Curriculum, quiz and lab data/services
│   ├── network/            # Network discovery and packet tooling
│   ├── observability/      # Telemetry recording and export
│   ├── security/           # Policy and safety modules
│   ├── sniffer/            # Protocol-dissection engines
│   ├── systems/            # System diagnostics
│   └── server.js           # Express application entry point
├── tests/                  # Regression and capability tests
├── .env.example            # Environment template, not real secrets
├── Dockerfile
├── docker-compose.yml
├── package.json
├── package-lock.json
├── tsconfig.json
├── setup-launcher.bat
└── setup-launcher.sh
~~~

The tree is representative rather than exhaustive. Some source folders contain generated JavaScript, declarations and source maps produced by the current TypeScript workflow.

## 📚 Documentation and useful entry points

| Resource | Purpose |
|---|---|
| [Source tree](https://github.com/EldarJamiyev/Eldar-Jamiyev-Infrastructure-Intelligence/tree/main/src) | Backend, engines, diagnostics and persistence. |
| [Frontend](https://github.com/EldarJamiyev/Eldar-Jamiyev-Infrastructure-Intelligence/tree/main/public) | App shell, workbenches, styles and learning interface. |
| [Tests](https://github.com/EldarJamiyev/Eldar-Jamiyev-Infrastructure-Intelligence/tree/main/tests) | Test runner and verification suites. |
| [Policies](https://github.com/EldarJamiyev/Eldar-Jamiyev-Infrastructure-Intelligence/tree/main/policies) | Policy-related material. |
| [Runbooks](https://github.com/EldarJamiyev/Eldar-Jamiyev-Infrastructure-Intelligence/tree/main/runbooks) | Operational procedures and knowledge references. |
| [Secure Deployment Report](EJII_SECURE_DEPLOYMENT_REPORT.md) | Deployment, configuration and security review notes. |
| [Test Execution Integrity Report](EJII_TEST_EXECUTION_INTEGRITY_REPORT.md) | Test-runner architecture and reported verification matrix. |
| [Package scripts and dependencies](package.json) | Authoritative npm commands and declared dependencies. |
| [Environment template](.env.example) | Runtime configuration reference. |

## 🧭 Practical operating principles

<div align="center">
  <table>
    <tr>
      <td align="center"><strong>Grounded</strong><br>Facts must have a source.</td>
      <td align="center"><strong>Explainable</strong><br>Conclusions should expose their reasoning.</td>
      <td align="center"><strong>Bounded</strong><br>Operations must respect scope and permissions.</td>
      <td align="center"><strong>Verifiable</strong><br>Outcomes require evidence.</td>
    </tr>
  </table>
</div>

EJII is an engineering platform, not a guarantee that every host is discoverable, every packet is decodable, every hypothesis is correct, or every remediation is safe in every environment. Validate findings against the relevant evidence and your own operational requirements.

## 🧾 Release and version note

The repository's v5.0.0 release and test reports use the milestone name <strong>v5.0.0-sovereign-singularity</strong>, while the current <code>package.json</code> declares <strong>2.0.0-sovereign-apex</strong>. These identifiers should be reconciled by a dedicated release-metadata change before they are treated as one consistent semantic version. This README update does not change package metadata, lockfiles, source code, configuration or the test suite.

## 📜 License and use

The package declares <strong>UNLICENSED</strong>, and no separate root <code>LICENSE</code> file is present in the repository. Do not assume that the code is available under an open-source license or that redistribution and commercial use are permitted. Obtain the appropriate permission from the rights holder before reuse.

---

<div align="center">
  <h3>Built around one principle: make infrastructure easier to understand—and harder to misrepresent.</h3>
  <p><strong>EJII · Eldar Jamiyev’s Infrastructure Intelligence</strong></p>
  <p><a href="https://github.com/EldarJamiyev/Eldar-Jamiyev-Infrastructure-Intelligence">Repository</a> · <a href="https://github.com/EldarJamiyev/Eldar-Jamiyev-Infrastructure-Intelligence/issues">Issues</a> · <a href="https://github.com/EldarJamiyev/Eldar-Jamiyev-Infrastructure-Intelligence/tree/main/docs">Documentation</a></p>
  <img alt="End banner" width="100%" src="https://capsule-render.vercel.app/api?type=waving&amp;color=0:2563EB,50:17324D,100:0F172A&amp;height=110&amp;section=footer"/>
</div>