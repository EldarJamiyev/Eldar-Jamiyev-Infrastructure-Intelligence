---
name: footer-design
description: Creative website footer design patterns, multi-column sitemaps, newsletter subscription forms, and dark editorial sub-footers inspired by footer.design. Use when building aesthetic, conversion-oriented, and comprehensive website footers in React, Tailwind CSS, and HTML/CSS.
---

# Footer Design Component & Layout Guide

`footer-design` provides production-ready architectural patterns for modern website footers based on curated excellence from [footer.design](https://footer.design).

## Key Footer Archetypes

### 1. The Editorial Big-Typography Footer (Awwwards Style)
- **Signature Feature**: Massive brand name or slogan rendered across the entire bottom boundary (`text-[12vw] font-black tracking-tighter opacity-15 select-none`).
- **Layout**: Clean horizontal grid above the big text with local time indicators (`London 14:32 GMT`), social links, and email inquiry trigger.
- **Best For**: Creative agencies, design studios, high-end portfolios, editorial publications.

### 2. Multi-Column SaaS Sitemap & Resource Grid
- **Columns**:
  - *Column 1 (Brand & Pitch)*: Logo, 1-2 sentence mission statement, status pill (`System Operational`), and social icon links.
  - *Column 2 (Product)*: Features, Integrations, Changelog, Roadmap, Pricing, Documentation.
  - *Column 3 (Solutions)*: Enterprise, Startups, Freelancers, Case Studies.
  - *Column 4 (Company)*: About, Blog, Careers (with "We're hiring" badge), Press, Contact.
  - *Column 5 (Legal)*: Privacy Policy, Terms of Service, Cookie Settings, Security.
- **Bottom Bar**: Copyright statement, language selector, theme toggle.

### 3. Bento-Grid Interactive Footer
- **Layout**: Non-traditional card-based layout using CSS Grid (`grid-cols-1 md:grid-cols-3 gap-4`).
- **Cards**:
  - *Card A (Newsletter)*: Inline email capture with instant validation and micro-confetti.
  - *Card B (Community / Discord / Twitter)*: Live member count badge with hover tilt.
  - *Card C (Latest Release)*: Quick changelog snippet with "Read v2.4 Release Notes" button.

### 4. Minimalist Single-Row Footer
- **Layout**: Ultra-lean single flex row (`flex flex-col md:flex-row justify-between items-center py-8 border-t border-white/10`).
- **Content**: Left: Copyright + Made with love; Center: 4 key links (`Privacy`, `Terms`, `Docs`, `Status`); Right: Social icon cluster.

## Design Best Practices

1. **Visual Hierarchy & Contrast**:
   - Headers for link columns should be crisp, uppercase, and slightly subdued (`text-xs font-semibold uppercase tracking-wider text-neutral-400`).
   - Links should have subtle hover transitions (`hover:text-white transition-colors duration-150`).
2. **Newsletter Input UX**:
   - Accessible `<form>` with `<label class="sr-only">`.
   - Prevent layout shifts on error / success states.
   - Clean button inside input styling (`relative flex items-center`).
