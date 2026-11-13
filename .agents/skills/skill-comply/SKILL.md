---
name: skill-comply
description: Visualize whether skills, rules, and agent definitions are actually followed — auto-generates scenarios at 3 prompt strictness levels, runs agents, classifies behavioral sequences, and reports compliance rates with full tool call timelines. Use when checking whether agents actually follow the skills, rules, and definitions they were given, rather than assuming they do.
metadata:
  origin: ECC
tools: Read, Bash
---

# skill-comply: Automated Compliance Measurement

Measures whether coding agents actually follow skills, rules, or agent definitions by:
1. Auto-generating expected behavioral sequences (specs) from any .md file
2. Auto-generating scenarios with decreasing prompt strictness (supportive → neutral → competing)
3. Running `claude -p` and capturing tool call traces via stream-json
4. Classifying tool calls against spec steps using LLM (not regex)
5. Checking temporal ordering deterministically
6. Generating self-contained reports with spec, prompts, and timelines

## Supported Targets

- **Skills** (`skills/*/SKILL.md`): Workflow skills like search-first, TDD guides
- **Rules** (`rules/common/*.md`): Mandatory rules like testing.md, security.md, git-workflow.md
- **Agent definitions** (`agents/*.md`): Whether an agent gets invoked when expected (internal workflow verification not yet supported)

## When to Activate

- User runs `/skill-comply <path>`
- User asks "is this rule actually being followed?"
- After adding new rules/skills, to verify agent compliance
- Periodically as part of quality maintenance

## Safety / cost (local notes — read before running)

- A **full run** launches several real `claude -p` sessions with `Read,Write,Edit,Bash,Glob,Grep` allowed. They only get `--add-dir <sandbox>`, which is not an OS sandbox → they can touch anything the user account can. It also **spends quota**. Never run a full run without the user's explicit OK for that specific target.
- Default to `--dry-run` (spec + scenarios only, cheap).
- Sandbox dir was moved to `C:\Users\sahin\.claude\tools\skill-comply-sandbox` (override: env `SKILL_COMPLY_SANDBOX`), so nothing is written to the drive root. C: only.
- Run from this skill folder: `cd "$HOME\.claude\skills\skill-comply"`.

## Usage

```bash
# Dry run (no cost, spec + scenarios only) — DEFAULT
uv run python -m scripts.run --dry-run ~/.claude/skills/<skill>/SKILL.md

# Full run (spends quota, real agent sessions) — only with explicit approval
uv run python -m scripts.run ~/.claude/rules/common/testing.md

# Custom models
uv run python -m scripts.run --gen-model haiku --model sonnet <path>
```

## Key Concept: Prompt Independence

Measures whether a skill/rule is followed even when the prompt doesn't explicitly support it.

## Report Contents

Reports are self-contained and include:
1. Expected behavioral sequence (auto-generated spec)
2. Scenario prompts (what was asked at each strictness level)
3. Compliance scores per scenario
4. Tool call timelines with LLM classification labels

### Advanced (optional)

For users familiar with hooks, reports also include hook promotion recommendations for steps with low compliance. This is informational — the main value is the compliance visibility itself.
