---
name: ui-quality
description: "Final UI quality pass: WCAG 2.2 AA accessibility checklist plus design-engineering polish (radii, motion, hit areas, text-wrap). Use after building UI or when it feels flat/generic or must meet accessibility rules."
---

# ui-quality — accessibility + polish in one pass

Merged from ECC `accessibility` (→ `references/accessibility-wcag.md`) and `make-interfaces-feel-better` (→ `references/interface-polish.md`; this is the "UI Polish & Design Engineering" skill). Read the reference only for details/code samples.

## A. Accessibility gate (WCAG 2.2 AA) — do first, it can change markup
- **Semantics before ARIA:** native `button/a/input/label/nav/main`; no clickable `div`.
- **Names:** every control has an accessible name; icon-only buttons get `aria-label` (web) / `accessibilityLabel` (iOS) / `contentDescription` (Android); decorative SVG `aria-hidden`.
- **Contrast:** text 4.5:1 (3:1 large/UI components); never color-only meaning.
- **Target size:** ≥24×24 CSS px minimum (WCAG 2.5.8); aim 44×44 for touch.
- **Focus:** visible, high-contrast focus ring (2.4.11); logical order; modals trap focus **and** close with Escape; menus restore focus to trigger.
- **Forms:** text error messages with fix suggestions (3.3.3); don't ask for the same data twice (3.3.7); labels linked to inputs.
- **Dynamic content:** `aria-live` for status; reflow to 400% zoom; respect `prefers-reduced-motion`.
- Language: set `lang` correctly (`az`, `en`, `ru`, `tr`); multi-language UIs switch `lang` with the content.

## B. Polish checklist (apply after A)
1. Nested rounded surfaces: **outer radius = inner radius + padding** (treat big padding as separate surfaces).
2. Optically center icons/play triangles (offset 1–2px or fix the SVG).
3. Borders for separation/focus, soft layered shadows for depth; neutral black/white alpha, no brand tint on image outlines (`outline: 1px solid rgba(0,0,0,.1); outline-offset:-1px`).
4. `text-wrap: balance` on headings, `pretty` on short body; `font-variant-numeric: tabular-nums` for changing numbers.
5. Motion: CSS transitions for interactive state; enter = opacity + small translateY (+blur), exit shorter (~150ms); press `scale(.96)`; never `transition: all`, never `will-change: all`.
6. Hit areas ≥40–44px (expand with a pseudo-element, no overlap).

## C. Output
Report only what changed, as `Principle | Before | After` rows with file paths; omit checks that already passed. Pair with `design-taste-frontend` / `stitch-design` for the look, this skill for the details. For the iqtisad-bot (government) project, treat section A as required, not optional.
