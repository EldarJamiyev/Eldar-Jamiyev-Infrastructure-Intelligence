---
name: 3dicons
description: Open-source 3D icon library (1440+ icon variations across 100+ unique concepts, 4 styles: Clay, Gradient, Color, Dynamic, and 3 camera angles: Front, Perspective, Isometric) by @realvjy via 3dicons.co. Use when incorporating high-quality 3D icons into web products, landing pages, feature grids, hero sections, and Three.js environments.
---

# 3Dicons Design & Implementation Guide

`3dicons` is a crafted open-source library of 3D icons created in Blender by [@realvjy](https://github.com/realvjy/3dicons) and hosted at [3dicons.co](https://3dicons.co).

## Catalog Dimensions & Variations

Each of the 100+ icon concepts (Bell, Rocket, Shield, Lock, Star, Heart, Chat, Folder, Wallet, Search, etc.) is rendered in **4 distinct visual styles** across **3 camera angles**:

### 1. Visual Styles
- **Gradient Style**: Smooth, multi-hue iridescence with specular edge highlights. Perfect for high-tech, AI, and consumer web applications.
- **Clay Style**: Matte, tactile, soft-shadow finish mimicking sculptured clay. Ideal for clean, playful, and minimalist interfaces.
- **Color Style**: High-contrast, vibrant primary tones with distinct material differentiation.
- **Dynamic (Metallic / Dark) Style**: Deep glossy obsidian and chrome finishes for dark mode and futuristic tech.

### 2. Camera Angles
- **Front Angle (0°)**: Direct head-on orthographic or slight perspective. Best for inline buttons, list items, and tabular layouts.
- **Perspective Angle (30°)**: Dramatic angled view showing depth and side bevels. Best for feature cards, hero clusters, and marketing grids.
- **Isometric Angle (45°)**: Classic isometric diagonal elevation. Best for architecture diagrams, bento grids, and product workflows.

## Web Integration Recipes

### 1. CDN Direct Embed (PNG / WebP)
High-resolution rendered assets can be directly served from unpkg or the official 3dicons CDN:
```html
<img
  src="https://raw.githubusercontent.com/realvjy/3dicons/main/preview.jpg"
  alt="Feature Icon"
  class="w-16 h-16 drop-shadow-xl hover:scale-110 transition-transform duration-300"
  loading="lazy"
/>
```

### 2. Bento-Grid Card with 3D Float Interaction
Pair the 3D icon with CSS floating animation and specular glow:
```html
<div class="group relative p-8 rounded-2xl bg-neutral-900/60 border border-white/10 hover:border-white/20 transition-all">
  <div class="relative w-20 h-20 mb-6 transition-transform duration-500 ease-out group-hover:-translate-y-2 group-hover:scale-105">
    <img src="/icons/3d-rocket-gradient.png" alt="Speed" class="w-full h-full object-contain" />
    <div class="absolute inset-0 bg-blue-500/20 blur-xl rounded-full -z-10 group-hover:bg-blue-500/30 transition-colors"></div>
  </div>
  <h3 class="text-xl font-bold text-white mb-2">Instant Deployment</h3>
  <p class="text-sm text-neutral-400">Push to git and go live globally across edge networks in seconds.</p>
</div>
```

### 3. GLB / Three.js 3D Interactive Scene
When interactive rotation or cursor tracking is desired, load the raw `.glb` model into a Three.js canvas using `GLTFLoader`:
```typescript
import { GLTFLoader } from 'three/examples/jsm/loaders/GLTFLoader';

const loader = new GLTFLoader();
loader.load('/models/rocket.glb', (gltf) => {
  const model = gltf.scene;
  scene.add(model);
  // Animate gentle hover / cursor rotation
});
```
