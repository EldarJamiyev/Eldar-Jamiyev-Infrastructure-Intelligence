---
name: obra-superpowers
description: Spec-driven multi-agent software engineering framework. Enforces rigorous brainstorming, formal specification drafting, subagent dispatch, and rigid TDD red-green-refactor loops.
license: MIT
---

# Obra Superpowers — Spec-Driven Multi-Agent Framework

Derived from Jesse Vincent's (obra) *Superpowers* agent methodology, this skill enforces a disciplined engineering cadence: **Brainstorm $\rightarrow$ Formal Specification $\rightarrow$ Subagent Dispatch $\rightarrow$ Strict TDD Execution**.

---

## 🔄 The 4-Phase Superpower Lifecycle

```
[ Phase 1: Brainstorm ]
       │
       ▼
[ Phase 2: Spec Drafting & Plan Approval ]
       │
       ▼
[ Phase 3: Subagent Decomposition & Dispatch ]
       │
       ▼
[ Phase 4: Strict Test-Driven Development (TDD) ]
       ├── Red: Write failing test fixture
       ├── Green: Minimal surgical code change
       └── Refactor: Clean debt under green bar
```

---

## 📋 Operational Directives

### 1. Formal Specification Before Code
- Never begin editing production files (`src/`, `policies/`, `scripts/`) without a written plan detailing:
  - Exact file paths to be touched
  - Input/Output data schemas
  - Corner cases and failure modes
  - Rollback strategies

### 2. Subagent Specialization
- Isolate distinct concerns into focused subagents:
  - **Researcher Subagent**: Read-only codebase and RFC survey.
  - **Test Engineer Subagent**: Authors executable assertions and edge-case mocks.
  - **Implementation Subagent**: Implements core logic to turn tests green.
  - **Reviewer Subagent**: Enforces linting, security guardrails, and no-slop invariants.

### 3. Rigid TDD Red-Green-Refactor
- Write the test first. Run it. Confirm it fails for the expected reason (`RED`).
- Implement the simplest possible solution that satisfies the contract (`GREEN`).
- Refactor for readability, performance, and maintainability without breaking tests (`REFACTOR`).

---

## 💻 EJII Integration: 7-Engine Cognitive Core

In the EJII architecture, `obra-superpowers` powers the validation of all 100 test suites:
- Every diagnostic engine (`src/sniffer/wire-dissector-apex.ts`, `src/topology/spectral-gnn-apex.ts`, etc.) must have corresponding unit and integration suites under `tests/`.
- Synthetic network packet fixtures verify RFC checksum calculations (RFC 1071) and 32-bit TCP sequence wraparounds before deployment.
