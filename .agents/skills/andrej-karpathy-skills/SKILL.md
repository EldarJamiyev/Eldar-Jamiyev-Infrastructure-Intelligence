---
name: andrej-karpathy-skills
description: Karpathy Guidelines for epistemic honesty and lean engineering. Enforces the 4 core rules targeting over-engineering, speculative features, and silent assumptions. Binds to EJII's Doubt-Driven Review engine to prevent hallucinated telemetry.
license: MIT
---

# Andrej Karpathy Skills & Guidelines

This skill implements Andrej Karpathy's core principles for working with AI models and engineering autonomous systems:
1. **Think Before Coding**: Surface tradeoffs, state assumptions explicitly, and never hide confusion.
2. **Simplicity First**: Minimum code that solves the problem. Absolutely zero speculative abstractions or unused configurability.
3. **Surgical Changes**: Touch only what you must. Match existing project styles and clean up only your own changes.
4. **Goal-Driven Execution**: Define measurable, verifiable success criteria before touching any code.

---

## 🛡️ Epistemic Honesty & Anti-Hallucination Invariants

In observability and infrastructure diagnostics, hallucinated metrics or fabricated socket results can cause real-world outages. This skill strictly enforces:

- **Zero-Simulation Doctrine**: Never return mock telemetry, simulated ping results, or fabricated packet bytes when real OS metrics or wire streams fail. If a probe fails, return the exact OS error code (`ECONNREFUSED`, `ETIMEDOUT`, `EHOSTUNREACH`).
- **Epistemic Labeling**:
  - `OBSERVED`: Ground truth measured directly from Win32 APIs, Npcap buffers, or sockets.
  - `INFERRED`: Derived statistical probabilities calculated via Bayesian belief matrices.
  - `UNKNOWN`: Explicitly acknowledged lack of visibility. Never guess.

---

## 💻 EJII Integration: Doubt-Driven Review Engine

- Intercepts all AI Brain hypothesis updates.
- Validates that Bayesian posterior probabilities sum to exactly 100.0% using the Hare-Niemeyer method.
- Automatically rejects any autonomous remediation recommendation that lacks an empirical before-and-after verification metric.
