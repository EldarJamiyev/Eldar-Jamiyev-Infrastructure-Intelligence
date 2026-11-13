---
name: design-md-library
description: 84 DESIGN.md design-system analyses of known sites (Stripe, Linear, Apple, Vercel, Spotify, Tesla…). Use for "in the style of" UI requests or to seed a project's own DESIGN.md.
---

# design-md-library — VoltAgent/awesome-design-md (MIT), 84 brands

Source: https://github.com/VoltAgent/awesome-design-md → `design-md/<brand>/DESIGN.md` (copied unmodified into `references/<brand>/`). This is also the origin of Hermes' "popular-web-designs" (which converted a subset to HTML/CSS) — the original DESIGN.md set is used here.

Brands: 1win, airbnb, airtable, aljazeera, apple, binance, bmw, bmw-m, bugatti, cal, claude, clay, clickhouse, cohere, coinbase, composio, cursor, dell-1996, dji, elevenlabs, expo, ferrari, figma, framer, hashicorp, hp, ibm, intercom, jobright, kraken, lamborghini, linear.app, lovable, mastercard, mercury, meta, minimax, mintlify, miro, mistral.ai, mongodb, mydealz, nerdwallet, nike, nintendo-2001, notion, nvidia, ollama, opencode.ai, oracle, oura, pinterest, playstation, posthog, raycast, renault, replicate, resend, revolut, runwayml, sanity, sap, sentry, shopify, slack, spacex, spotify, starbucks, stripe, supabase, superhuman, tesla, theverge, together.ai, uber, vercel, vodafone, voltagent, warp, webflow, wired, wise, x.ai, zapier.

## Use
1. Pick 1–2 brands that match the product's mood; read only those `references/<brand>/DESIGN.md` files (each ~15–25 KB; front matter = tokens, body = rules).
2. Derive the project's **own** `DESIGN.md` (tokens + rules) — don't copy a brand wholesale. Keep ONE DESIGN.md per project.
3. Implement; then run `web-design-guidelines` and `ui-quality`.

## Rules
- These are *inspired-by analyses* of other companies' sites. Use them as reference for structure and token ranges; do **not** reproduce logos, brand names, proprietary fonts (e.g. Söhne) or make a UI pass as that company's product. Substitute available fonts (Inter, Geist, DM Sans…).
- For multi-family aesthetics (editorial, glass, brutalist, terminal…) the existing `C:\Claude\awesome-claude-design\design-md\` families come first; this library supplies brand-grade specificity.
- With `stitch-design`: a DESIGN.md here is the same Stitch format and can seed `taste-design`/`generate-design`.
