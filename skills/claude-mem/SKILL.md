---
name: claude-mem
description: Persistent cross-session episodic memory and vector recall system. Automatically captures project milestones, architectural decisions, and situational context across agent restarts.
license: MIT
---

# Claude-Mem — Cross-Session Persistent Situational Memory

Claude-Mem provides a persistent memory architecture that bridges disparate agent sessions, container restarts, and user conversations. It eliminates context loss by storing structured architectural decisions, telemetry baselines, and historical resolutions in an embedded, high-performance database.

---

## 🧠 Memory Layers

```
┌─────────────────────────────────────────────────────────┐
│ 1. Working Memory (Active Turn Context / Prompt Window) │
├─────────────────────────────────────────────────────────┤
│ 2. Short-Term Episodic Buffer (Last 24 Hours / Ring)   │
├─────────────────────────────────────────────────────────┤
│ 3. Long-Term Situational Memory (SQLite WAL Database)   │
└─────────────────────────────────────────────────────────┘
```

---

## 🛠️ Memory Schemas & Operations

### 1. Architectural Decisions (ADR Ingestion)
Records key decisions with rationale and constraints:
```sql
CREATE TABLE IF NOT EXISTS architectural_memory (
  id TEXT PRIMARY KEY,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  decision TEXT NOT NULL,
  context TEXT NOT NULL,
  consequences TEXT NOT NULL,
  tags TEXT
);
```

### 2. Situational Baselines & Failure Profiles
Maintains baseline network latencies, normal CPU consumption, and standard ARP entries to immediately detect statistical drifts (CUSUM anomalies).

---

## 💻 EJII Integration: Universal Cross-Workspace Memory

In EJII, `claude-mem` connects to the SQLite WAL database (`data/ejii-production.sqlite`):
- Persists AI Brain confidence weightings across server restarts.
- Carries forward active incident investigation state if an operator closes their browser tab.
- Automatically initializes new sessions with known topology parameters (Default Gateway, Subnet mask, Active NIC).
