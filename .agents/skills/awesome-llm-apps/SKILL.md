---
name: awesome-llm-apps
description: Agent & RAG playbooks and multi-step orchestration workflows. Provides battle-tested patterns for hybrid retrieval, episodic memory indexing, and self-correcting agent loops.
license: Apache-2.0
---

# Awesome LLM Apps — Agent & RAG Orchestration Playbooks

This skill curates production-tested architectural blueprints for agentic workflows, multi-modal routing, and Retrieval-Augmented Generation (RAG) pipelines. In the EJII platform, it guides the **Episodic Causal Memory Engine** and historical incident pattern matching.

---

## 🏛️ Essential Agent Architectural Patterns

### 1. Self-Correcting RAG Loop
```
[ Query ] ──> [ Hybrid Retrieval (BM25 + Dense Vectors) ]
                       │
                       ▼
              [ Relevance Evaluator ]
              ├── High Confidence ──> [ Answer Generation ]
              └── Low Confidence  ──> [ Query Decomposition / Re-rank ] ──┐
                                                    ▲                    │
                                                    └────────────────────┘
```

### 2. Episodic Memory Pattern Matching
- Index historical diagnostic sessions with high-dimensional feature vectors:
  - Failure signature (e.g. `TCP_SYN_FLOOD`, `PMTU_BLACKHOLE`, `APIPA_UNROUTED`)
  - Topological context (Gateway, Switch, Core Router)
  - Successful remediation script ID
- When a new incident occurs, query the episodic memory store for top-3 nearest neighbor incidents to accelerate root cause analysis.

---

## 💻 EJII Integration: Episodic Causal Memory
```javascript
import { EpisodicMemoryManager } from './core/episodic-memory-manager.js';

export async function matchHistoricalIncident(currentAnomaly) {
  const memoryStore = new EpisodicMemoryManager();
  
  // Retrieve top-3 structurally similar past incidents
  const matches = await memoryStore.findNearestIncidents({
    anomalyType: currentAnomaly.type,
    affectedProtocols: currentAnomaly.protocols,
    limit: 3
  });

  return matches.map(m => ({
    incidentId: m.id,
    rootCause: m.resolvedRootCause,
    effectivePlaybook: m.remediationPlaybookId,
    confidenceScore: m.similarity
  }));
}
```
