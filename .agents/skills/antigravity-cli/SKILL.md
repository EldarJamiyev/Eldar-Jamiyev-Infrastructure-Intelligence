---
name: antigravity-cli
description: "Operate/delegate to the Google Antigravity CLI (agy): one-shot -p prompts for a Gemini second opinion, models, permissions, plugins, auth. Use when the user mentions Antigravity/agy."
---

# antigravity-cli — Hermes `antigravity-cli` guide (MIT), adapted for Claude Code

Original (unmodified, written for Hermes' `terminal`/`read_file` tools): `references/hermes-original/main.md` + `references/hermes-original/references/cli-docs.md`. Read it for the full command/flag/slash-command/settings reference. Translate its `terminal(command=...)` calls to the **Bash/PowerShell tool**, and `read_file` to **Read**.

## Status on this machine
`agy` is **not installed**. Verify with `agy --version`. Official installer (from the reference): `irm https://antigravity.google/cli/install.ps1 | iex` — a remote script: **never run it unasked**; show it to the user (or have them download/inspect it first). Auth is a browser Google sign-in (OS keyring) — the user signs in; never request credentials.

## Quick use (once installed)
```powershell
agy --version ; agy models                       # exact model display strings
agy -p "Review this diff for bugs and security issues" --model "Gemini 3.1 Pro (High)" --print-timeout 10m
agy plugin list                                  # skills/agents/MCP/hooks staged under ~/.gemini/antigravity-cli/plugins
```
- `-p/--print` is non-interactive and returns **plain text** (no JSON envelope, no `--max-turns`; bound with `--print-timeout`).
- Run from the project directory; extra read roots via `--add-dir`.
- Data/logs live in `~/.gemini/antigravity-cli/` (settings.json, log/cli-*.log, conversations/).

## Rules
1. **Do not use `--dangerously-skip-permissions`** (the reference shows it for unattended runs) unless the user explicitly asks; prefer default permission prompts or `--sandbox`.
2. Delegation = sending code to Google's service: confirm with the user before sending anything private (iqtisad-bot is a government project; secrets and `.env` stay out).
3. Treat the output of `agy` as a second opinion, not authority; verify claims against the code.
4. It's a worker/reviewer backend, not an orchestrator — keep planning in this session.
5. Skills in this folder format also work in Antigravity (same SKILL.md standard); to share a skill, copy its folder into the plugin/skills location the `agy` docs specify (check `agy plugin --help` first).
