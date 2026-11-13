---
name: claude-config-hygiene
description: "Keep the Claude setup lean and safe: clean stale skills/memory/hooks (confirm each), audit skills, review MCP configs, lint skills for portability. Use for \"clean up config\", \"too many skills\" or before writing a new skill."
---

# claude-config-hygiene — 6 ECC skills (MIT, commit 76aaa77) as one router

Source: `affaan-m/ECC` → `skills/<name>` (originals in `references/<name>/main.md`; only `skill-stocktake` was edited: script paths + results location, see its note). Read only the one that fits.

| Goal | Read | Notes |
|---|---|---|
| Too many/stale skills, memory, hooks, permissions, MCP; "config GC" | `config-gc` | Soft-delete only (`.disabled` rename or `~/.claude/_gc_trash/<date>/`), **one item, one decision**, log in `~/.claude/gc_log.md`. Never "delete all" |
| Quality/usage audit of skills (Quick = changed only, Full = all) | `skill-stocktake` | Scripts need `bash` + **`jq` (not installed — ask before installing)**; results in `~/.claude/skill-stocktake-results.json`; batches of ~20 skills per subagent (costs tokens) |
| Is this MCP config safe to approve? (mutable `npx -y`/`latest` refs) | `mcp-dependency-review` | Static, never runs discovered servers. Pair with `mcp-security` |
| What can this environment actually do / what's missing? | `workspace-surface-audit` | Recommends skills/hooks; treat its "ECC-native" suggestions as optional — don't install ECC wholesale |
| Will this skill load in Codex/Cursor/Antigravity (frontmatter, Claude-only features)? | `skill-host-compat` | Use before copying skills to Antigravity/Gemini CLI |
| About to write a new skill | `skill-scout` | Searches local, marketplace, GitHub first (use the router+references install pattern from `memory/skills_mcpmarket_install.md`) |

## Local rules
- Read-only first: list findings, then ask. Deletions/renames only after an explicit yes per item; back up `settings.json` / `.claude.json` before editing.
- Protected: `~/.claude/projects/*/memory/`, `C:\Claude\refs\`, hooks in `C:\Claude\.claude\hooks\` (Obsidian sync) — flag, never remove without the user's decision.
- Not included on purpose: ECC `security-scan` (runs a third-party npm package, `--fix` edits files). For config security use `mcp-security`, `mcp-dependency-review`, `claude-security`.
- Skill-count context: ~98 skills installed; the previous cleanup archived 42 overlapping ones (`refs\skills-archive\`). Prefer merging into routers over adding top-level skills.
