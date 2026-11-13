---
name: tailwind-v4
description: Tailwind CSS v4 CSS-first config, @theme directive, container queries, syntax changes
metadata:
  type: skill
  triggers: ["tailwind", "tailwind v4", "tailwind css", "@theme", "utility css", "tw"]
---

# Tailwind CSS v4

## Config (CSS-first, no tailwind.config.js)
```css
@import 'tailwindcss';

@theme {
  --font-display: 'Inter', sans-serif;
  --color-primary: oklch(55% 0.2 250);
  --radius: 0.5rem;
  --spacing: 0.25rem;
}
```

## Arbitrary values
```html
<div class="mt-[13px] text-[#1a1a2e] grid-cols-[repeat(3,minmax(200px,1fr))]">
```

## Container queries (new in v4)
```html
<div class="@container">
  <div class="@lg:flex @sm:grid">content</div>
</div>
```

## v3 → v4 migration
| v3 | v4 |
|----|-----|
| `border-opacity-50` | `border-black/50` |
| `flex-shrink-0` | `shrink-0` |
| `overflow-ellipsis` | `text-ellipsis` |

## Notes
- v4 requires CSS import (`@import 'tailwindcss'`), not PostCSS config
- Lightning CSS is now the default engine (10x faster)
- `@apply` still works but prefer utilities in HTML
