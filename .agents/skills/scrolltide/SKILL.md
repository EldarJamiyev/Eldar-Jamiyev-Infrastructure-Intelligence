---
name: scrolltide
description: Cinematic scroll interactions, viewport progression, subtle parallax depth, and performance-conscious section reveals using Framer Motion, Lenis, and modern CSS. Use when crafting Awwwards-caliber scroll-driven web experiences, landing pages, and interactive product reveals.
---

# ScrollTide Motion & Scroll Guidelines

`scrolltide` sets the standard for cinematic, viewport-driven scroll animations inspired by Awwwards-winning websites and [scrolltide.co](https://scrolltide.co).

## Core Principles

1. **Perceptual Smoothness**:
   - Use spring transitions (`cubic-bezier(0.16, 1, 0.3, 1)`) for natural, fluid acceleration and deceleration.
   - Smooth out wheel events with Lenis or CSS `scroll-timeline` without hijacking the native browser scrollbar.
2. **Viewport Progression**:
   - Subtle vertical translations (`y: 20` to `y: 0`) and gentle opacity fades (`opacity: 0` to `1`) on section entry.
   - Staggered children reveals (80ms–120ms delay per child element) to create a visual wave effect.
   - Horizontal scrub effects for showcase cards during vertical page scrolling.
3. **Parallax Depth & Layering**:
   - Foreground, midground, and background layers moving at differential rates (e.g., speed multipliers: 0.1x, 0.25x, 0.5x).
   - Sticky pinned containers where text or UI elements transform as the page scrolls past.
4. **Performance & FPS Protection**:
   - **Never animate layout properties**: Never animate `width`, `height`, `margin`, `padding`, or `top/left`.
   - **Composite-only properties**: Only animate `transform` (`translate3d`, `scale3d`, `rotate3d`) and `opacity`.
   - Use `will-change: transform` conservatively during active scroll bounds, and remove it on idle.
   - Apply `content-visibility: auto` to offscreen sections to minimize layout overhead.
5. **Accessibility First**:
   - Always wrap motion in `prefers-reduced-motion` checks:
     ```css
     @media (prefers-reduced-motion: reduce) {
       *, *::before, *::after {
         animation-duration: 0.01ms !important;
         transition-duration: 0.01ms !important;
         scroll-behavior: auto !important;
       }
     }
     ```
