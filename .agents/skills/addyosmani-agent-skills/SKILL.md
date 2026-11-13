---
name: addyosmani-agent-skills
description: Production engineering runtimes, enterprise security boundaries, and task-isolation pipelines for autonomous coding agents. Hardens EJII's loopback and sub-process sandbox constraints during unprivileged automation runs.
license: MIT
---

# Addy Osmani Agent Skills — Production Engineering & Security Isolation

Derived from Addy Osmani's engineering patterns for agentic development, this skill defines enterprise-grade runtime boundaries, task isolation, and performance-first architecture for AI coding assistants.

---

## 🛡️ Enterprise Security Boundaries

When an autonomous agent writes or executes code in production repositories:

### 1. Loopback & Host Isolation
- All background processes and socket listeners MUST bind explicitly to loopback (`127.0.0.1`) unless explicitly flagged for external listening with authenticated TLS.
- Rejects wildcard listening addresses (`0.0.0.0`) in production configs to prevent unauthorized network exposure.

### 2. Task Sandboxing & Sub-Process Shielding
- Restrict file modifications to the current repository root. Block path traversal attempts (`../../etc/shadow`, `C:\Windows\System32\`).
- Sanitize command arguments against shell injection attacks (command chaining via `;`, `&&`, `|`, `` ` ``).

### 3. Unprivileged User-Space Operation
- Never assume root or Administrator privileges.
- Always implement graceful fallbacks for unprivileged execution (e.g., user-space socket streaming when raw Npcap driver elevation is unavailable).

---

## 💻 EJII Integration: Sandbox Hardening

In EJII, this skill hardens the **Tool Sandbox (`src/core/tool-sandbox.js`)**:
- Enforces strict regex validation on IP targets and hostnames.
- Restricts diagnostic script arguments to approved whitelist patterns.
- Writes cryptographic HMAC-SHA256 signatures to `.chain_head` for every automated script run.
