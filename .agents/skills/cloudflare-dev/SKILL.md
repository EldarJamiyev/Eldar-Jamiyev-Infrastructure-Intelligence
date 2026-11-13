---
name: cloudflare-dev
description: "Build and deploy on Cloudflare: product choice, Workers, Wrangler, Agents SDK, Durable Objects, Next.js on Workers, email, web perf. Use for free-tier hosting, serverless APIs or edge agents."
---

# cloudflare-dev — official `cloudflare/skills` (9 of 19 merged into one router)

Source: https://github.com/cloudflare/skills (official). Originals: `references/<name>/main.md` (the `cloudflare` entry is large with its own sub-references). Not copied: Zero Trust/SASE (`cloudflare-one*`, `gateway-workers`), `basin`, `k2`, `sandbox-*`, `turnstile-spin` (5 scripts), profiling.

| Task | Read |
|---|---|
| "What Cloudflare product fits this?" / pricing-limits orientation | `cloudflare` (start at its top-level index) |
| Writing or reviewing a Worker for production | `workers-best-practices` |
| Wrangler config, dev, deploy, secrets | `wrangler` (and `cf-cli` for the beta `cf` CLI) |
| AI agents on the edge (state, tools, scheduling, MCP) | `agents-sdk` — relevant to **agentos** |
| Strongly-consistent state, coordination, websockets | `durable-objects` |
| Next.js app on Workers | `nextjs-on-cloudflare` |
| Transactional email (Email Sending / Routing) | `cloudflare-email-service` |
| Core Web Vitals, slow loads | `web-perf` |

## Local rules
- **Nothing is deployed or paid by default.** Deploying needs the user's Cloudflare account and an API token set in the environment by the user (never pasted into chat or committed). Ask before `wrangler deploy`, creating resources, or DNS changes; show cost/limit implications (free-tier quotas change — check current docs).
- Prefer local dev (`wrangler dev`) and dry runs first.
- For the government iqtisad-bot: do not move data to a third-party edge without an explicit data-residency decision by the user.
- Pair with `ui-quality`/`web-design-guidelines` for front-end work and `vercel:*` skills if the project targets Vercel instead — don't mix hosts in one project.
