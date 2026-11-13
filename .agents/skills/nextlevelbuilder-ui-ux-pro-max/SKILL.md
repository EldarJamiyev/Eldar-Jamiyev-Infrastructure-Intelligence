---
name: nextlevelbuilder-ui-ux-pro-max
description: Production UI refinement and quiet luxury styling. Strips visual clutter, ensures 60fps rendering, and enforces EJII's Quiet Luxury Meridian UI Design System tokens.
license: MIT
---

# NextLevelBuilder UI/UX Pro Max — Production Design Refinement

This skill grounds frontend design in high-density, quiet luxury aesthetics, eliminating amateur visual fluff, nested card containers, and sluggish CSS transitions. It directly governs the **EJII Quiet Luxury Meridian Design System**.

---

## 🎨 Meridian Design Tokens

```css
:root {
  /* Obsidian & Emerald Cyber-NOC Palette */
  --bg-deep: #0a0c10;
  --bg-surface: #12151c;
  --bg-elevated: #1a1e28;
  --border-subtle: rgba(255, 255, 255, 0.08);
  --border-strong: rgba(255, 255, 255, 0.16);

  /* Semantic State Accents */
  --accent-cyan: #06b6d4;
  --accent-emerald: #10b981;
  --accent-amber: #f59e0b;
  --accent-rose: #f43f5e;

  /* Typography */
  --font-mono: "JetBrains Mono", "SF Mono", monospace;
  --font-sans: "Inter", -apple-system, BlinkMacSystemFont, sans-serif;
}
```

---

## 📐 Layout & Interaction Directives
1. **Zero Layout Shifts (CLS = 0)**: Pre-allocate bounding boxes for dynamic topology SVGs and packet dissection panels.
2. **High-Density Information Architecture**: NOC operators require maximum data density without ocular fatigue. Use 11px/13px mono tabular data with alternate row banding.
3. **Hardware-Accelerated Rendering**: All animations must use `transform` and `opacity` on dedicated GPU compositing layers (`will-change: transform`).
