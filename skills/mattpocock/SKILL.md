---
name: mattpocock-skills
description: Engineering workflow interrogation and specification elicitation. Features /grillme and deep iterative Q&A to interrogate incomplete diagnostic intents, clarify hidden edge cases, and eliminate silent assumptions before executing probes.
license: MIT
---

# Matt Pocock Skills — Deep Engineering Intake & `/grillme`

Inspired by Matt Pocock's *Skills for Real Engineers*, this skill equips autonomous agents with structured interrogation behaviors. Instead of rushing to write speculative code or firing unverified diagnostic probes, the agent conducts an interactive, rigorous architectural interview (`/grillme`) to uncover hidden requirements and constraints.

---

## 🎯 The `/grillme` Protocol

When an operator provides a vague or high-stakes instruction (e.g., *"Fix the DNS latency"*, *"Reconfigure the firewall rules"*, *"Automate host triage"*):

### 1. Stop and Interrogate
- **Do not write speculative code.**
- **Do not execute intrusive diagnostics.**
- Formulate 3 to 5 targeted, high-leverage multiple-choice questions or structured inquiries.

### 2. Core Question Categories
1. **Scope & Blast Radius**:
   - What network segment or cluster is affected?
   - Is this an isolated host or an entire availability zone?
2. **Operational Constraints**:
   - Are there unprivileged user constraints (Zero-Elevation Doctrine)?
   - Can network interfaces be bounced, or is active traffic uninterrupted?
3. **Success & Verification Criteria**:
   - What exact metric defines resolution (e.g., RTT < 10ms, 0% packet loss)?
   - Which specific verification test or synthetic probe must pass?

---

## 🛠️ Execution Modes

### Mode 1: Standard `/grillme`
Directly questions the human operator with prioritized options:
```text
Operator Request: "Diagnose gateway latency spikes."

Agent Response:
Before firing network probes, let's nail down the parameters:
1. Target Scope: Are we testing the local default gateway (192.168.31.1) or the upstream ISP next-hop?
2. Probe Aggressiveness: Should we run passive Npcap wire sniffing (zero packets sent) or an active ICMP/TCP jitter sweep?
3. Thresholds: At what millisecond latency do you want alerts flagged (default: > 25ms)?
```

### Mode 2: `/grillme with docs`
Grounds the interrogation against local project documentation, RFC specifications, and system runbooks:
- Extracts contradictory statements between the user prompt and established architecture docs.
- Cites specific runbooks (e.g. `RB-01-default-gateway-unreachable.md` or RFC 1035) to validate assumptions.

---

## 💻 EJII Integration: Gemini Semantic Interpreter Gate

In EJII, `mattpocock-skills` hooks into the **Gemini Semantic Interpreter** before dispatching tool operations:
- If `epistemicUncertainty > 0.40`, automatically trigger an internal grill-down routine.
- Validate inputs against the 24 Sandboxed Diagnostic Tool schemas.
- Ensure all required parameters (`targetIp`, `portRange`, `timeoutMs`) are unambiguously defined.
