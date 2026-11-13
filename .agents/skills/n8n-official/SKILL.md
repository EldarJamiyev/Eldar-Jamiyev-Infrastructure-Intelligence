---
name: n8n-official
description: "Official n8n workflow rules: expressions, Code nodes, node config, loops, sub-workflows, error handling, debugging, credentials, AI agents, MCP. Use when designing or debugging n8n workflows (local n8n on :5678)."
---

# n8n-official — 14 official n8n skills as one router

Source: `n8n-io/skills` (official; marketplace's duplicate "n8n …" entries are variants of these). Bodies: `references/<topic>/main.md`. Read the topic(s) that match; the always-on protocol is `references/using-n8n-skills/main.md` (its SessionStart-hook loading is **not** installed — read it once per n8n task if workflow quality matters).

| Situation | Read |
|---|---|
| Starting / organizing / finishing a workflow (sticky notes, descriptions, testing, shipping) | `n8n-workflow-lifecycle` |
| Configuring any node (HTTP, webhook, DB, Slack/Gmail/Discord, AI, triggers, Merge) | `n8n-node-configuration` |
| `{{ }}` expressions, `$json`/`$node`, Luxon dates, expression errors | `n8n-expressions` |
| About to write a Code node (JS/Python) | `n8n-code-nodes` (prefer expressions/native nodes first) |
| Multi-item data, batches, pagination, rate limits, fan-out | `n8n-loops` |
| >10 nodes, repeated logic, reuse | `n8n-subworkflows` |
| Webhook/scheduled/production workflows, silent failures | `n8n-error-handling` |
| "It isn't working", wrong output, errors | `n8n-debugging` |
| Any auth, API key, token, OAuth, secret | `n8n-credentials-and-security` |
| Built-in Data Tables, dedupe, upsert | `n8n-data-tables` |
| Files, images, attachments, binary into/out of agent tools | `n8n-binary-and-data` |
| AI Agent / LLM chain / classifier / extractor nodes | `n8n-agents` |
| Expose a workflow as a tool for coding agents (MCP), or wrap n8n API gaps | `n8n-extending-mcp` |

## Local notes
- The n8n container runs at `http://localhost:5678` (see `C:\Claude\check-services.ps1`). Check it is up before promising live edits; if no n8n MCP/API key is configured, produce workflow JSON or step lists instead of acting.
- Credentials live in n8n's credential store — never inline keys in node parameters or in files under git (see `n8n-credentials-and-security`).
- Webhook workflows exposed beyond localhost need auth and error output wired; follow `n8n-error-handling`.
- For automation systems like OpenClaw/Hermes-style agents, n8n is the glue layer: model it with `n8n-agents` + `n8n-extending-mcp`.
