---
name: agentplay
description: Visual session replay and debugging for AI coding agents. Replays every agent session as an interactive timeline map (files read/edited, tools called, MCP servers used, tokens consumed).
---

# agentplay

Visual session replay and debugging for AI coding agents. Replays every agent session as an interactive timeline map (files read/edited, tools called, MCP servers used, tokens consumed).

## Quick Command / Usage
```bash
uvx agentplay@latest
```

## Documentation & Reference
# agentplay

<p>
  <a href="https://pypi.org/project/agentplay/"><img alt="PyPI" src="https://img.shields.io/pypi/v/agentplay"></a>
  <a href="https://pypi.org/project/agentplay/"><img alt="Python" src="https://img.shields.io/pypi/pyversions/agentplay"></a>
  <a href="https://pepy.tech/project/agentplay"><img alt="Downloads" src="https://static.pepy.tech/badge/agentplay/month"></a>
  <a href="https://github.com/Entelligence-AI/agentplay/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Entelligence-AI/agentplay/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/license-Apache%202.0-blue"></a>
  <a href="https://github.com/Entelligence-AI/agentplay/stargazers"><img alt="GitHub stars" src="https://img.shields.io/github/stars/Entelligence-AI/agentplay?style=social"></a>
</p>

**See what your coding agent actually did. Replay every session as a map and a timeline: what it read, what it edited, what failed, and what it shipped. Local, open source, works across Claude Code, Codex, Cursor, Copilot, OpenCode, Kiro, Gemini CLI, Antigravity CLI, Command Code and Goose.**

```bash
uvx agentplay@latest
```

That one command finds the agent sessions already on your machine, builds a redacted replay of each one, and opens a local viewer. No account and no API key are required, and your session data never leaves your machine. The only network call is an optional email signup in the viewer, described under [Privacy](#privacy); set `AGENTPLAY_NO_NETWORK=1` to switch it off.

![The session explorer replaying a Claude Code session: a radial map of every file, tool, MCP server, subagent and model the session touched, the replay timeline underneath, and details on the right](docs/images/explorer-light.png)

<sub>Screenshot of the bundled demo session (synthetic data). Dark mode: [docs/images/explorer-dark.png](docs/images/explorer-dark.png).</sub>

If agentplay shows you something about your agent you didn't know, a ⭐ helps other people find it.

---

## Contents

- [Why this exists](#why-this-exists)
- [Install](#install)
- [Using the viewer](#using-the-viewer)
- [Supported agents](#supported-agents)
- [Privacy](#privacy)
- [Command reference](#command-reference)
- [The session map format](#the-session-map-format)
- [How it works](#how-it-works)
- [Configuration](#configuration)
- [Development](#development)
- [Contributing](#contributing)
- [Known limitations](#known-limitations)
- [License and credits](#license-and-credits)

## Why this exists

Your agent's transcripts already record what it did: which files it read before editing, which commands it retried, which MCP servers failed, where the context window filled up, and which subagents came back empty. That data sits in `~/.claude`, `~/.codex`, `~/.cursor` and similar folders, and almost nobody looks at it.

agentplay makes that data readable. Every session becomes a map of everything it touched and a timeline you can play 
