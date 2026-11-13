---
name: repo-wiki
description: "Turn a repository into documentation: wiki catalogue, Mermaid pages, onboarding guides, AGENTS.md, llms.txt, changelog, VitePress, Q&A. Use to document a repo or explain how a component works."
---

# repo-wiki — Microsoft `deep-wiki` skills (9) as one router

Source: `microsoft/skills` → `.github/plugins/deep-wiki/skills/` (official, MIT; copy of the license in this folder). Originals are unmodified in `references/<name>/main.md`. `wiki-ado-convert` (Azure DevOps wiki format) was left out. The plugin's slash commands/agents were not installed.

| Goal | Read |
|---|---|
| Plan the whole wiki: hierarchical catalogue + onboarding structure (**start here for "document this repo"**) | `wiki-architect` |
| Write one rich page (Mermaid dark-mode diagrams, first-principles, citations) | `wiki-page-writer` |
| Deep multi-turn investigation of one subsystem | `wiki-researcher` |
| Answer "how does X work" from source, with citations | `wiki-qa` |
| Four onboarding guides in `onboarding/` | `wiki-onboarding` |
| `AGENTS.md` per folder (build/test/style/boundaries; only where missing) — also read by Codex/Antigravity | `wiki-agents-md` |
| `llms.txt` / `llms-full.txt` | `wiki-llms-txt` |
| Changelog from git history | `wiki-changelog` |
| Browsable static site from the generated markdown | `wiki-vitepress` |

## Rules (local)
1. **Source-repo question first** (the architect skill requires it): ask whether the repo has a remote URL for linked citations or is local-only — and check `git remote get-url origin`.
2. **Write only inside the target repo** (e.g. `docs/wiki/`, `onboarding/`) on **C:**; never overwrite existing docs, AGENTS.md or README without asking. Show the catalogue before generating dozens of pages (cost/time).
3. VitePress needs Node; `npm install`/build is the user's call for each project.
4. Large repos: generate level by level (catalogue → onboarding → deep dives on request) to keep token use bounded; use `graphify` first if a graph already exists for the project.

## Overlap — pick the right tool
- Code graph / "what connects to what" → `graphify` (existing). Text docs for humans/agents → this skill.
- Single missing-docs gap (one module) → `document-generate` (gstack) is lighter.
- Obsidian vault pages → `claude-obsidian:wiki*`. Project onboarding for CLAUDE.md → `claude-md-improver`.
