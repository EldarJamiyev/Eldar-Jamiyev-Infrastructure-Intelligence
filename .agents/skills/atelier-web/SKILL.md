---
name: atelier-web
description: "Measured web checks via local CLI (axe-core + Chromium): WCAG accessibility audit, runtime UX audit, responsive AVIF/WebP image pipeline. Use for real audits of a running page or build, not just code reading."
---

# atelier-web — 3 skills from `EthanY33/atelier` (MIT) via a pinned local CLI

CLI: `C:\Users\sahin\.claude\tools\atelier\bin\atelier` (copy of `plugins/atelier` at commit `848320d77ae1d2218a80d1b97be5804191651e82`, 2026-10-14; `node_modules` + Playwright Chromium 153 installed, ~250 MB, on C:). The three skill texts are in `references/*/main.md`; wherever they say `node "${CLAUDE_PLUGIN_ROOT}/bin/atelier" …` use `node "C:\Users\sahin\.claude\tools\atelier\bin\atelier" …`.

| Goal | Command | Read |
|---|---|---|
| WCAG A/AA audit of a URL or built `.html` (axe-core in real Chromium); writes `a11y-report.md` + `a11y-raw.json` | `atelier a11y <url\|file> [--out dir] [--wait-for sel] [--tags …]` | `references/a11y-audit/main.md` |
| Runtime UX audit (static by default; `--dynamic` loads the page in Chromium) → `ux-report.md` + `ux-raw.json` | `atelier ux <url\|file> [--dynamic] [--out dir] [--area mobile,panels]` | `references/runtime-ux-audit/main.md` |
| Resize to AVIF/WebP srcset + LQIP + `<picture>` snippet | `atelier images <file\|dir> --out <dir> --alt "…" --base-url /img/` | `references/responsive-images/main.md` |

Exit code `1` just means violations were found (verified on a sample page: 3 critical + 2 serious). Reports are Markdown — read the report, not the raw JSON, then fix.

## Rules
- Only audit pages the user owns or that are local/staging. `--dynamic` runs the page's own scripts in Chromium; for local files it serves the folder on loopback and blocks `.env`/`.git`/`.ssh`.
- Write outputs to the target project (e.g. `docs/audits/`), not the tool dir. `images` overwrites nothing silently — pick a fresh `--out`.
- Don't re-run `npm install`/`playwright install` unasked; the install is pinned. To update: review the upstream diff, then change `PINNED-COMMIT.txt`.
- Not exposed on purpose: brand-memory, design-token-sync, og-card-generator, brand-asset-pipeline, html-to-video (overlap `web-asset-generator`, `stitch-design`, HyperFrames). The CLI contains them if ever needed.
- Pairs with `web-quality` (static performance/CWV/SEO) and `ui-quality`: static review first, then this skill for measured proof. For iqtisad-bot (government) an axe report is a good deliverable for the accessibility section.