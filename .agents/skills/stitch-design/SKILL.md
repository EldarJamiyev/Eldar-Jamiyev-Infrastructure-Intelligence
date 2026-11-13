---
name: stitch-design
description: "Design UI with Google Stitch (needs Stitch MCP): prompt enhancement, DESIGN.md taste rules, screen generation, then React/shadcn/React Native/Remotion output. Use for AI-generated UI/UX and Stitch-to-code."
---

# stitch-design — Google Labs Stitch skills (16 merged into one router)

Source: `google-labs-code/stitch-skills` (official). Original skill bodies: `references/<name>/main.md` (+ `scripts/`, `resources/`). Read only what the step needs.

**Prerequisite:** the Stitch MCP server (Google account / API key via https://stitch.withgoogle.com/docs/mcp/setup/). It is **not configured yet** — if its tools are absent, say so and stop; do not fake designs. Never put a Stitch key in chat or files; `upload_to_stitch.py` takes `--api-key`, so prefer an env var.

## Pipeline (pick the stages you need)
1. **Brief** → `enhance-prompt` (vague idea → Stitch-optimised prompt) ; `site-md` (project constitution for multi-page builds)
2. **Taste** → `taste-design` (premium anti-generic DESIGN.md rules: typography, spacing, motion) and/or `design-md` (derive DESIGN.md from an existing Stitch project)
3. **Generate** → `generate-design` (screens from text/image via MCP) ; `stitch-loop` (autonomous multi-page build)
4. **Systems** → `manage-design-system`, `extract-design-md` (from code), `extract-static-html`, `code-to-design` (code → Stitch), `upload-to-stitch` (bypasses the model's output-token limit for big files)
5. **Build** → `react-components` (modular React + style extraction), `react-vite-dashboard`, `shadcn-ui`, `react-native` (mobile), `remotion` (walkthrough video of the design)

## Local synthesis (avoid duplicate work)
- Already installed and overlapping: `design-taste-frontend` (taste-skill), `ui-ux-pro-max`, `frontend-design`, and the DESIGN.md families in `C:\Claude\awesome-claude-design\design-md\`. Use those for non-Stitch work. Use Stitch's `taste-design` **in addition** when the target is a Stitch project; reconcile by keeping ONE DESIGN.md per project (start from the awesome-claude-design family that matches, then let `taste-design` tighten it).
- Finish every UI task with `ui-quality` (WCAG 2.2 + polish) — Stitch output is not accessibility-checked.
- Shell scripts (`fetch-stitch.sh`, `download-stitch-asset.sh`, `verify-setup.sh`) are bash: run through Git Bash, only against URLs Stitch returned.
