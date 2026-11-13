---
name: refero-styles
description: Curated collection of 30+ production DESIGN.md specifications, design tokens, and Tailwind v4 themes extracted from real premier brands (Anthropic, Raycast, MotherDuck, Monad, Mercury, Seline Analytics, etc.) via styles.refero.design. Use when grounding SaaS landing pages, dashboards, portfolios, or redesigns in concrete, high-aesthetic real-world design systems.
---

# Refero Styles Design Systems Library

`refero-styles` provides 30 production-grade design token systems and narrative design specifications extracted from real web products on [styles.refero.design](https://styles.refero.design).

## Brand Catalog & Available Styles

Each directory under `refero-styles/<Brand>/` contains:
- `DESIGN.md`: Narrative design philosophy, color rationale, typography pairings, and signature visual moves.
- `tokens.json`: Exact machine-readable numeric design token layer.
- `variables.css`: Native CSS custom properties.
- `theme.css`: Tailwind CSS v4 `@theme` block.

### Curated Brand Systems:
1. **Anthropic**: High-gravitas editorial warmth, Serif + Sans pairing, earthy limestone & warm clay tones.
2. **Raycast**: Deep hyper-contrast dark mode, glowing accents, razor-sharp borders, precision keyboard-first iconography.
3. **MotherDuck**: Whimsical yet professional duck-yellow accents, dark teal base, friendly geometric typography.
4. **Monad**: High-speed crypto/fintech performance aesthetic, neon cyan and deep violet gradients.
5. **Mercury**: Refined banking & fintech minimalism, crisp monochrome structure with subtle stone warmth.
6. **Seline Analytics**: Ultra-clean data analytics aesthetic, privacy-first typography, muted slate & violet highlights.
7. **Discover**: Playful, vibrant creative agency style.
8. **IKEA**: Functional, human-centric Scandinavian flat color blocking and bold sans hierarchy.
9. **SuperHi Plus**: Creative technologist aesthetic with high-saturation retro-modern accents.
10. **Wispr Flow**: Calming voice-AI interface, frosted glass layers, ethereal gradients.
...and 20+ additional premier brand systems (Lamanna, Henry, Huddle, Monopo Saigon, etc.).

## Usage Instructions for AI Agents

1. **Selecting a Style**:
   - Match the user's project to one of the 30 brand systems based on audience, vibe, and domain.
   - For B2B / DevTools: choose **Raycast**, **Anthropic**, or **Monad**.
   - For Fintech / Banking: choose **Mercury** or **Seline Analytics**.
   - For Creative / Portfolio: choose **SuperHi Plus**, **Good Glyphs**, or **Monopo Saigon**.
2. **Applying the Tokens**:
   - Read `refero-styles/<Brand>/DESIGN.md` for the core design rules.
   - Import `refero-styles/<Brand>/theme.css` into your Tailwind config or copy CSS variables from `variables.css`.
   - Never mix disparate design tokens without deliberate intention.
