---
name: langchain-agents
description: "Build agents and RAG with LangChain/LangGraph/Deep Agents: tools, middleware, persistence, human-in-the-loop, quickstarts. Use when designing an agent or RAG system with that stack."
---

# langchain-agents — official `langchain-ai/langchain-skills` (20 of 22 merged)

Source: https://github.com/langchain-ai/langchain-skills (official). Originals unmodified: `references/<name>/main.md`. Not copied: `swarm` (8 scripts) and `eval-engineering` (167 KB, 5 scripts) — add after reviewing them.

**Always start with `ecosystem-primer`** (picks LangChain vs LangGraph vs Deep Agents), then `langchain-dependencies` (correct package versions) before writing code.

| Need | Read |
|---|---|
| Simple tool-calling agent, middleware, human approval | `langchain-fundamentals`, `langchain-middleware` |
| **RAG** (loaders, splitters, vector stores, retrieval) | `langchain-rag` |
| Explicit control flow / state machines | `langgraph-fundamentals`; routing with a decision model → `langgraph-decision-models` |
| Remember across turns/sessions | `langgraph-persistence` |
| Pause for approval | `langgraph-human-in-the-loop` |
| Batteries-included planning + subagents + files | `deep-agents-core`, `deep-agents-orchestration`, `deep-agents-memory` |
| Hosted/managed deployment (LangSmith) | `managed-deep-agents`, `langgraph-cli` |
| Scaffold in 2 minutes | `*-quickstart` (python/typescript for langchain, langgraph, deepagents) |

## Local rules
- **iqtisad-bot already runs FastAPI + ChromaDB + Ollama.** Use LangChain only if it earns its keep; compare with the current hand-built pipeline before adding a dependency. Keep the model local (Ollama) for the ministry project; no data to hosted LLMs/LangSmith without explicit approval.
- **agentos**: LangGraph persistence + human-in-the-loop map well to its layers; pair with the `ethos` skill (one `ethos.md` per agent).
- Python 3.11+ and `uv`; install into the project venv only. API keys via environment/.env (gitignored), never in chat.
- LangSmith tracing sends traces to a cloud service — leave it off unless the user opts in (Langfuse self-host is an alternative; see `refs/mcpmarket-skills/09-publishers-wave1.md`).
