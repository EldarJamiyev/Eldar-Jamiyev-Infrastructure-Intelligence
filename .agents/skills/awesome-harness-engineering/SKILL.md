---
name: awesome-harness-engineering
description: "Comprehensive harness engineering patterns for AI agents: sandbox isolation, deterministic verification, context trimming, test-driven self-correction, maker-checker loops, and long-running agent reliability."
triggers:
  - "harness engineering"
  - "agent harness"
  - "agent reliability"
  - "eval harness"
---

# Awesome Harness Engineering

Harness engineering is the discipline of engineering the scaffolding, runtime environment, and feedback control loops around an AI model so it performs deterministically, reliably, and safely.

## Core Primitives

### 1. Deterministic Verification Loops
Never rely on an LLM's self-assessment of whether code works.
- **Compiler/Linter Feedback:** Route compiler errors, static type checks (`tsc`, `pyright`, `dotnet build`, `cargo check`), and linter warnings directly back to the agent before declaring a task complete.
- **Unit & Integration Gates:** Execute tests (`pytest`, `dotnet test`, `npm test`) with verifiable stdout/stderr assertions.
- **Idempotency:** A good harness ensures repeated execution produces identical artifacts.

### 2. Guardrails & Sandboxing
- Scoped filesystem access (boundary enforcement).
- Safety Net interceptors for destructive actions (`rm -rf`, `DROP DATABASE`, uncommitted git overwrites).
- Incident trackers with automatic back-off on consecutive tool failures.

### 3. Context & Working Memory Trimming
- **Progressive Disclosure:** Load L0 abstracts, L1 summaries, and L2 source files on demand.
- **Compaction at Milestones:** Compact conversation history only at well-defined phase boundaries (never in the middle of active implementation).
- **Living Task Lists:** Persist state into external files (`TODO.md`, `TASK_STATE.json`) rather than keeping the entire trajectory in prompt memory.

### 4. Maker-Checker & Evaluator Loops
- Separate the Producer/Operator agent from the Verifier/Auditor agent.
- Independent exit criteria review against the original user prompt before turn completion.
