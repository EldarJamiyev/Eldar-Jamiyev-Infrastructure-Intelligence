---
name: web-quality
description: Audit websites for performance, Core Web Vitals, accessibility, SEO and best practices, with a read-only HTML analyzer. Use to speed up a site, fix CWV/Lighthouse issues or run a web quality audit.
---

# web-quality — Addy Osmani `web-quality-skills` (MIT), 6 skills as one router

Source: https://github.com/addyosmani/web-quality-skills → `skills/<name>` (originals in `references/<name>/main.md` + their `references/` subfolders; `.gemini`/`codex` host copies not copied).

| Goal | Read |
|---|---|
| Full audit across all areas (start here when the request is broad) | `web-quality-audit` (+ `scripts/analyze.sh`) |
| LCP / INP / CLS | `core-web-vitals` (`references/LCP.md`, `INP.md`, `CLS.md`) |
| Load speed, bundle/resource strategy, measurement, RUM | `performance` (`MEASUREMENT.md`, `RUM.md`) |
| WCAG 2.2 audit/fixes | `accessibility` (`WCAG.md`, `A11Y-PATTERNS.md`) |
| Search visibility, structured data | `seo` (`STRUCTURED-DATA.md`) |
| Security headers, compatibility, code hygiene | `best-practices` (`SECURITY.md`) |

## Local rules
- `analyze.sh <file-or-dir>`: read-only static check of HTML; needs `bash` (Git Bash) and `jq` (installed via winget). Output is JSON on stdout.
- Lab data: real measurements need Lighthouse/DevTools — use the `chrome-devtools-mcp` plugin (`debug-optimize-lcp`, `a11y-debugging`) or `browse`/`canary` (gstack); say clearly when numbers are estimates from static reading.
- Overlap: `ui-quality` (a11y checklist + visual polish) and `web-design-guidelines` (fast UI checklist). Use `web-quality` for performance/CWV/SEO and a measured, site-wide audit; use the others while building UI.
- Government projects (iqtisad-bot): accessibility and security-headers sections are required, not optional. Do not change production settings or add third-party trackers/CDN scripts without asking.
