---
name: canvas-ui
description: Creative Canvas UI component library with real HTML and WebGL/WebGPU effects running over it. Includes 35+ components (AsciiObject, GlassObject, LiquidObject, ParticleObject, Glitch, GlyphRain, VHS, Droplets, ForceField, Laser, Ripple, Frost, Cloth, etc.). Use when building hyper-aesthetic 3D, retro, fluid, glass, and shader-driven UI in React, Next.js, Vue, Svelte, or vanilla web apps.
---

# Canvas UI Component Library Skill

`canvas-ui` is a library of creative canvas components where real, interactive HTML elements run alongside GPU-accelerated WebGL2 and WebGPU shaders.

## Key Component Directory

### 1. 3D & Physical Objects
- **AsciiObject**: 3D geometric meshes redrawn as shape-matched live ASCII typography.
- **GlassObject**: Physically-accurate liquid glass refraction with real chromatic dispersion.
- **LiquidObject**: DOM content dragged through viscous swirling liquid simulations.
- **ParticleObject**: Volumetric particle clouds that scatter on interaction and spring back.
- **DitheredObject**: 1-bit / retro ordered Bayer matrix dithered mesh rendering.
- **InkObject**: Fluid bleeding sumi-e ink dissolution.

### 2. Environmental & Fluid Shaders
- **Droplets**: Condensation and sliding water droplets refracting background content.
- **Ripple**: Water surface caustics and interactive concentric wave ripples.
- **Frost**: Crystallizing ice creeping across glass boundaries.
- **Cloth**: Spring-mass physics cloth simulation with tactile deformation.
- **Clouds**: Volumetric raymarched rayleigh-scattering clouds.

### 3. Cyberpunk & Retro Digital Effects
- **Glitch**: RGB chromatic aberration, scanline jumps, and block displacement.
- **GlyphRain**: Matrix-style cascading digital rain interacting with element perimeters.
- **VHS**: Authentic CRT phosphor glow, tape tracking lines, and barrel distortion.
- **RetroDither**: Old-school Macintosh / Game Boy 1-bit aesthetic post-processing.
- **Laser**: Coherent high-intensity beam tracing boundaries with particle sparks.
- **ForceField**: Hexagonal glowing energy shield deflecting cursor interactions.

## Architecture & Integration

1. **Rendering Model**:
   - WebGL2 and GLSL for standard GPU cross-browser support.
   - WebGPU with WGSL for high-throughput modern hardware.
   - HTML-in-Canvas capture using `drawElementImage()` or GPU overlay fallbacks.
2. **Framework Compatibility**:
   - React / Next.js (Tailwind v4 compatible).
   - Vue 3, Svelte 5, and vanilla JavaScript/TypeScript.
3. **Best Practices**:
   - Maintain 60 FPS budgets by capping DPR at 2.0x (`Math.min(window.devicePixelRatio, 2)`).
   - Clean up textures, shaders, framebuffers, and event listeners on unmount.
