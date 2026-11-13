---
name: supahero
description: Curated hero section design patterns, typography hierarchy, responsive hero layouts, and 3D/video backdrop treatments inspired by supahero.io. Use when designing standout landing page hero sections, value propositions, and primary viewport experiences in React, Tailwind CSS, and Framer Motion.
---

# Supahero Hero Section Design & Architecture Guide

`supahero` provides design blueprints and structural formulas for world-class landing page hero sections inspired by the curated showcase on [supahero.io](https://www.supahero.io).

## Hero Anatomy Formula

A high-converting, visually memorable hero section follows this sequential hierarchy:
1. **Eyebrow Badge**: Pill announcement ("Announcing v3.0 • Read Changelog →").
2. **Main Headline (H1)**: Bold, opinionated statement (48px–72px) with clamp typography (`text-4xl md:text-6xl lg:text-7xl font-extrabold tracking-tight`).
3. **Sub-headline**: 1-2 concise sentences answering: What is it, who is it for, and why does it matter?
4. **Primary + Secondary Action Cluster**: Primary high-contrast button paired with an interactive secondary action (e.g. "Watch 2-min demo" or "View on GitHub").
5. **Social Proof Ribbon**: "Trusted by leaders at..." with monochrome logos at 40% opacity.
6. **Hero Visual / Interactive Stage**: 3D interactive canvas, code editor mock, animated dashboard preview, or video demonstration.

## Key Hero Archetypes

### 1. Centered Hero with Interactive Product Stage
- **Alignment**: Text elements centered in a max-w-4xl column.
- **Stage**: An angled 3D perspective dashboard or window mock tilted with CSS 3D transforms (`rotate-x-12 perspective-1000 shadow-2xl`).
- **Best For**: DevTools, SaaS dashboards, productivity apps (Linear, Supabase, Raycast style).

### 2. Split Hero (Text Left, Interactive 3D / Graphic Right)
- **Grid**: `grid grid-cols-1 lg:grid-cols-12 gap-12 items-center min-h-[85vh]`.
- **Left (5-6 cols)**: Content cluster, CTAs, and customer quote.
- **Right (6-7 cols)**: WebGL 3D canvas (Three.js/Spline), fluid interactive particle mesh, or live product simulation.
- **Best For**: AI applications, creative tech, high-end consumer hardware.

### 3. Editorial Minimalist Hero (Typography-First)
- **Signature Feature**: Asymmetric layout, serif + sans font pairing, expansive whitespace, warm neutral background (limestone, eggshell, warm obsidian).
- **Decorations**: Restrained; zero generic gradient blobs; high-quality editorial photography or abstract vector art instead.
- **Best For**: Venture capital, design agencies, luxury brands, media companies.

### 4. Interactive Terminal / Code Hero
- **Stage**: Live interactive code terminal with syntax highlighting, copyable `npm i` or `curl` command, and a tabbed language switcher (TypeScript, Python, Go, Rust).
- **Best For**: APIs, developer platforms, open-source libraries.

## Responsive Typography Scale (Tailwind)

```html
<h1 class="text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-black tracking-tight text-white leading-[1.08] max-w-4xl mx-auto">
  Build apps people <span class="bg-gradient-to-r from-blue-400 via-indigo-300 to-purple-400 bg-clip-text text-transparent">remember</span>.
</h1>
<p class="mt-6 text-lg sm:text-xl text-neutral-400 max-w-2xl mx-auto leading-relaxed">
  The composable toolkit for modern engineering teams. Zero setup, infinite scale.
</p>
```
