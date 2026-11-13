---
name: navbar-gallery
description: Curated navigation bar architecture, header patterns, and interactive menu systems inspired by navbar.gallery. Covers floating island navbars, mega-menus, blur-glass headers, scroll-aware sticky headers, and mobile off-canvas drawers in React, Tailwind CSS, and Framer Motion.
---

# Navbar Gallery Component & Architecture Guide

`navbar-gallery` provides design blueprints and implementation recipes for modern, responsive, and accessible navigation bars based on curated patterns from [navbar.gallery](https://www.navbar.gallery).

## Key Navbar Archetypes

### 1. Floating Island Navbar (Pill / Capsule)
- **Visual Style**: Detached capsule floating centered at the top of the viewport (`top-4 mx-auto w-fit`).
- **Surface**: Translucent dark/light glass (`backdrop-blur-md bg-neutral-900/80 border border-white/10 shadow-2xl`).
- **Interactions**: Smooth pill indicator that glides behind hovered links using Framer Motion layout animations (`layoutId="nav-pill"`).
- **Best For**: Modern SaaS landing pages, portfolios, developer tools (Linear, Vercel, Raycast style).

### 2. Multi-Tier Mega Menu (Stripe / Enterprise Style)
- **Visual Style**: Clean top bar with category triggers (`Products`, `Solutions`, `Developers`, `Pricing`).
- **Dropdown Architecture**: Single animated dropdown card that dynamically morphs width, height, and content as the cursor transitions between top-level triggers without flickering or closing.
- **Content Layout**: 2-3 column grid featuring icons, descriptions, "Featured" callouts, and changelog/documentation links.

### 3. Scroll-Aware Sticky Header (Transforming Navbar)
- **States**:
  - *At Top (`y === 0`)*: Transparent background, full-width, larger typography and generous padding (`py-6`).
  - *Scrolled (`y > 50`)*: Animates into a condensed header with backdrop blur, subtle bottom border, reduced height (`py-3`), and elevation shadow.
- **Scroll Direction Intelligence**: Automatically hides when scrolling down (`translate-y-[-100%]`) to maximize screen estate, and smoothly slides back down when scrolling up (`translate-y-0`).

### 4. Fullscreen / Off-Canvas Mobile Drawer
- **Trigger**: Minimalist animated hamburger icon transitioning into an 'X' (`svg` morphing).
- **Menu Body**: Smooth slide-in from right or spring-loaded fullscreen overlay with staggered link entrance animations.
- **Auxiliary Controls**: Theme toggle (Dark/Light), language switcher, primary CTA button at the bottom.

## Implementation Guidelines

1. **Accessibility (a11y)**:
   - Always wrap in semantic `<header>` and `<nav aria-label="Main Navigation">`.
   - Provide `aria-expanded` and `aria-controls` on dropdown triggers and mobile toggles.
   - Support `Escape` key to close open menus and return focus to the trigger.
2. **Responsive Breakpoints**:
   - Clean separation: desktop navigation rendered on `md:` or `lg:`, hamburger trigger on mobile.
   - Prevent background body scrolling when mobile overlay is active (`document.body.style.overflow = 'hidden'`).
