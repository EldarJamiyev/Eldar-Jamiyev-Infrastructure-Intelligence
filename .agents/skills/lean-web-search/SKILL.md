---
name: lean-web-search
description: Token-efficient web search/extraction via Brave, Tavily, DuckDuckGo (keyless) or SearXNG, keeping raw pages out of context. Use when fresh web facts are needed without flooding the context.
---

# lean-web-search — Brave + Tavily + keyless fallbacks, around one goal: small context

Originals: `references/brave-*/main.md` (official `brave/brave-search-skills`), `references/tavily-*/main.md` (official `tavily-ai/skills`), `references/ddg-search`, `references/searxng-search` (Hermes `optional-skills/research`). The Brave and Tavily "CLI" skills were not copied (Tavily's installs via `curl | bash`; run nothing like that unasked).

## Status
Neither Brave nor Tavily is configured. Brave needs `BRAVE_SEARCH_API_KEY` (https://api.search.brave.com — check the current plan/free quota there, it changes). Tavily's `tvly` CLI is not installed; it advertises capped keyless use, then login/API key. The user creates keys and sets env vars; never ask for a key in chat.
Already available without any key: the built-in `WebSearch`/`WebFetch`, Firecrawl skills, Playwright/Chrome tools. Use those first for one-off lookups; reach for this skill when volume, freshness or grounding quality matters.

## Pick the tool
| Need | Use |
|---|---|
| Snippets/chunks to ground an answer, ranked and pre-extracted | Brave **LLM Context** (`brave-llm-context`) — set `maximum_number_of_tokens` (default 8192; lower it for simple questions) and `count` |
| Plain links/snippets, news, freshness filter | Brave `web-search`, `news-search` (`freshness=pd/pw/pm`) |
| Ready synthesized, cited answer | Brave `answers` (OpenAI-compatible endpoint) or Tavily `research` |
| Many sources, big pages, multi-query triage | Tavily **dynamic-search**: save raw JSON to disk (`-o`), print only 150–600 tokens per source |
| Pull clean markdown from known URLs | Tavily `extract` (add `--query` + `--chunks-per-source`) |
| Discover site structure / crawl docs | Tavily `map` then `crawl` |
| Quality rules for production search | `tavily-best-practices` |

## Token rules (merged)
1. Search broad **without** raw content; read titles/URLs/scores; fetch full text only for the best 1–3 sources.
2. Save large payloads to files; filter locally; show bounded evidence with the source URL beside every fact.
3. Restrict domains when the user names official sources, and **re-check each URL's hostname** — include-domain filters are not proof.
4. If a page body wasn't fetched, label the conclusion "search-snippet evidence".
5. Don't swallow errors (`except: continue`) — auth/cap/429 messages are actionable.
6. Temp files: use a unique folder under the project/scratch on C:, not a shared path.
7. Caveman/Headroom already shrink output; this skill shrinks *input* — apply it before pulling pages into context.

## Keyless fallbacks (2026-10-17, from Hermes `optional-skills/research`, MIT)
| Tool | Read | Notes |
|---|---|---|
| DuckDuckGo via `ddgs` | `references/ddg-search/main.md` | No key. Run without installing: `uv run --with ddgs ddgs text -q "<query>" -m 5`. `ddgs` is an **unofficial scraping library** - rate-limits/ToS-grey; fine for light use |
| SearXNG meta-search (70+ engines) | `references/searxng-search/main.md` | No key but needs `SEARXNG_URL`: **self-host** (Docker; Docker Desktop is currently stopped) - don't send queries to unknown public instances |

Use these before paid APIs when volume is low; use Brave/Tavily when you need ranked, pre-extracted content.
