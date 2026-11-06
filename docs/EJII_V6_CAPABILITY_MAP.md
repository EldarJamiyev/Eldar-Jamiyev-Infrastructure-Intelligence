# EJII v6 — Sovereign Intelligence Fabric Capability Map

**Release Version:** `6.0.0-sovereign-intelligence-fabric`  
**Operating Loop:** `Discover → Observe → Correlate → Investigate → Explain → Simulate → Plan → Authorize → Execute → Verify → Learn → Improve`

---

## 1. Unified Capability Matrix (`src/core/capability-registry.js`)

| Capability ID | Domain | Execution Mode | Privilege | Determinism | Blast Radius | Evidence Classes Produced | Primary Implementation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `ejii.discovery.temporal_topology` | `topology` | `passive` | `unprivileged` | `deterministic` | `none` | `observation` | `src/core/topology/temporal-graph-engine.js` |
| `ejii.correlation.cross_layer_rca` | `rca_investigation` | `diagnostic` | `unprivileged` | `statistical` | `none` | `observation`, `hypothesis`, `confirmed_finding` | `src/core/correlation/incident-correlator.js` |
| `ejii.diagnostics.unreachable_hostname_workflow` | `protocol_probe` | `active_probe` | `operator` | `deterministic` | `low` | `observation`, `confirmed_finding` | `src/core/correlation/incident-correlator.js` |
| `ejii.sniffer.l7_deep_dissector` | `packet_dissection` | `passive` | `unprivileged` | `deterministic` | `none` | `observation` | `src/sniffer/l7-deep-protocol-dissector.ts` |
| `ejii.ai.spectral_fourier_periodicity` | `spectral_analysis` | `diagnostic` | `unprivileged` | `deterministic` | `none` | `calculation` | `src/ai/spectral-fourier-detector.ts` |
| `ejii.simulation.digital_twin_branch` | `simulation` | `simulation` | `operator` | `deterministic` | `none` | `simulated_result` | `src/topology/digital-twin-chaos-simulator.ts` |
| `ejii.security.policy_governance_compiler` | `policy_governance` | `diagnostic` | `operator` | `deterministic` | `none` | `calculation` | `src/security/zero-trust-policy-synthesizer.ts` |
| `ejii.governance.verified_remediation` | `remediation` | `remediation` | `operator` | `deterministic` | `low` | `action_result`, `verification_result` | `src/core/governance/action-control-plane.js` |
| `ejii.diagnostics.hardware_kernel_inspector` | `host_diagnostics` | `diagnostic` | `unprivileged` | `deterministic` | `none` | `observation` | `src/diagnostics/hardware-kernel-inspector.ts` |

---

## 2. The Seven Architectural Innovations of EJII v6

1. **Innovation One — The EJII Evidence Fabric (`src/core/evidence/evidence-fabric.js`)**
   - Enforces 11 typed evidence classes (`observation`, `calculation`, `hypothesis`, `confirmed_finding`, `counter_evidence`, `missing_evidence`, `stale_evidence`, `simulated_result`, `human_annotation`, `action_result`, `verification_result`).
   - Computes freshness states (`live`, `fresh`, `aging`, `stale`, `expired`, `historical_snapshot`) and deterministic quality scores in $[0, 1]$.
   - Provides acyclic lineage tracing (`Finding → Rule → Supporting Evidence → Original Diagnostic Result → Source Capability → Observation Time`) and prevents stale or simulated-only evidence from confirming live findings.

2. **Innovation Two — The Temporal Infrastructure Graph (`src/core/topology/temporal-graph-engine.js`)**
   - Unifies 16 canonical resource types and 10 typed relationships (`connected_to`, `routes_to`, `member_of`, `depends_on`, `resolves_to`, `served_by`, `hosted_on`, `observed_by`, `affected_by`, `evidenced_by`).
   - Supports historical point-in-time queries, snapshot diffing (`intervalStatus`, `dataGapDetected`), upstream change causality, and explicit identity reconciliation candidates for randomized MACs and DHCP lease churn.

3. **Innovation Three — Cross-Layer Incident Correlation (`src/core/correlation/incident-correlator.js`)**
   - Correlates DNS, TCP, TLS, HTTP, ICMP/PMTU, topology, DHCP/ARP, L7 packet dissection, QoS DSCP, host/kernel, spectral, AI Brain, and remediation verification events.
   - Provides a 10-step L1–L7 unreachable-hostname diagnostic workflow (`/api/v6/diagnose-hostname`).

4. **Innovation Four — Explainable Causal Investigation & Counterfactuals (`src/core/correlation/incident-correlator.js`)**
   - Evaluates structured hypotheses (`proposed`, `supported`, `contradicted`, `confirmed`, `rejected`, `unresolved`) with correlation discounting so multiple symptoms of one root cause are not double-counted as independent proofs.
   - Generates counterfactual refutations and a first-class Uncertainty Panel.

5. **Innovation Five — Trace-Driven Digital Twin & Chaos Branching (`src/core/governance/action-control-plane.js`)**
   - Forks isolated simulation branches from live or historical topology snapshots using M/M/1/K queueing and shortest-path rerouting (`fidelity: 'simulated'`), never mutating live state.

6. **Innovation Six — Policy Intelligence & Safe Configuration Governance (`src/core/governance/action-control-plane.js`)**
   - Audits candidate policies for overly broad `0.0.0.0/0` exposure, rule shadowing, lateral movement vectors (SMB/RDP/SSH/WinRM), and critical DNS/gateway dependencies before compiling preview artifacts for Linux `nftables`, `iptables`, Windows `netsh advfirewall`, and Cisco IOS Extended ACLs.

7. **Innovation Seven — Governed Remediation & Postcondition Verification (`src/core/governance/action-control-plane.js`)**
   - Enforces a 6-phase action lifecycle (Preconditions → Dry-Run Preview → RBAC & Replay Gate → Execution → Postcondition Re-Probe Verification → Rollback Guidance) linked to Sovereign Learning Center modules and labs.
