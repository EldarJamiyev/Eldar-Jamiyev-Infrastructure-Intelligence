---
name: claude-code-best-practice
description: Agentic engineering handbook for terminal workflows, sub-process monitoring, and cross-examination cycles during long-running tasks. Used by EJII's 5-Agent Autonomous War Room to handle cross-examination cycles during root-cause triage.
license: MIT
---

# Claude Code Best Practices — Agentic Engineering Handbook

This skill outlines operational disciplines for running autonomous agents on local development terminals, managing asynchronous sub-processes, and preventing runaway execution loops.

---

## 🧭 Core Terminal & Task Practices

1. **Incremental Validation**:
   - Run tests or verification commands immediately after making small code changes.
   - Never pile multiple unverified modifications into a single batch commit.

2. **Non-Blocking Background Tasks**:
   - Long-running commands (e.g. multi-packet sweeps, continuous PCAP recording, full repository builds) must be spawned in the background.
   - Use asynchronous notification hooks rather than busy-waiting in tight loops.

3. **Cross-Examination Cycles in Triage**:
   - In multi-agent root cause analysis, separate the *Hypothesis Proposer* from the *Evidence Verifier*.
   - Require empirical counter-evidence to be checked before accepting an anomaly explanation.

---

## 💻 EJII Integration: 5-Agent War Room Triage

In EJII, this handbook governs how the 5 agents interact during network incident war rooms:
- **Triage Agent** proposes root causes.
- **Topology Specialist** checks upstream blast radius to rule out upstream switch failure.
- **Wire Analyst** validates TCP flag distributions and sequence deltas.
- **Lyapunov Officer** calculates potential energy $\dot{V} \le 0$ before permitting any remediation action.
