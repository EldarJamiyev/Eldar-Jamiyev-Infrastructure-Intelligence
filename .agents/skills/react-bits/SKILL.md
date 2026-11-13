---
name: react-bits
description: Production-grade animated, interactive, and customizable React & Next.js components library (216+ components across Text Animations, Backgrounds, UI Components, Micro Interactions, and Animations). Use when the user asks to build animated web interfaces, hero sections, interactive cards, particle/shader backgrounds, cursor trails, or modern micro-interactions in React/Next.js with Tailwind or CSS.
---

# React Bits Component Library

[React Bits](https://www.reactbits.dev) is the largest open-source collection of animated, interactive, and customizable UI components for React and Next.js (created by David Haz / `DavidHDev/react-bits`, 50,000+ GitHub stars).

Every component is available in **4 implementation variants**:
1. `TS-TW`: TypeScript + Tailwind CSS (Recommended for modern Next.js/Vite)
2. `TS-CSS`: TypeScript + CSS Modules
3. `JS-TW`: JavaScript + Tailwind CSS
4. `JS-CSS`: JavaScript + CSS

Full component directory and documentation links: [llms.txt](./references/llms.txt) (contains all 216+ components and specifications).

---

## 🚀 Installation & CLI Usage

### Option 1: Via shadcn CLI (Recommended)
Add any React Bits component directly into your project using the shadcn CLI:
```bash
npx shadcn@latest add https://reactbits.dev/r/<Component>-<LANG>-<STYLE>
```
* `<LANG>`: `TS` or `JS`
* `<STYLE>`: `TW` (Tailwind) or `CSS`

Examples:
```bash
# SplitText in TypeScript + Tailwind
npx shadcn@latest add https://reactbits.dev/r/SplitText-TS-TW

# Aurora Background in TypeScript + Tailwind
npx shadcn@latest add https://reactbits.dev/r/Aurora-TS-TW

# SpotlightCard in TypeScript + Tailwind
npx shadcn@latest add https://reactbits.dev/r/SpotlightCard-TS-TW

# SplashCursor in TypeScript + Tailwind
npx shadcn@latest add https://reactbits.dev/r/SplashCursor-TS-TW
```

### Option 2: Via jsrepo CLI
```bash
npx jsrepo@latest add https://reactbits.dev/r/<Component>-<LANG>-<STYLE>
```

---

## 📦 Component Categories & Highlights

### 1. Text Animations (33+ components)
- **SplitText**: Word and letter-staggered reveals with customizable ease and timing.
- **BlurText**: Progressive soft-focus depth reveal on page load or scroll.
- **ShinyText**: Shimmering light beam sliding horizontally across text.
- **DecryptedText**: Cyberpunk letter-cycling decryption effect that settles onto target string.
- **TrueFocus**: Interactive spotlight that zooms into words on hover.
- **VariableProximity**: Variable font weight / width shifts responding to cursor position.
- **CircularText**: Text wrapped around an interactive or rotating circle.
- **CountUp**: Smooth numerical ticker with easing, formatting, and decimals.
- **ASCII Text**: Real-time ASCII rendering that ripples on click and mouse hover.
- **GlitchText**: RGB split distortion with customizable jitter intervals.

### 2. Backgrounds & Canvas Shaders (62+ components)
- **Aurora**: Dynamic Northern Lights color waves using WebGL or canvas.
- **LiquidChrome**: Metallic reflective fluid raymarching simulation.
- **Hyperspeed**: High-velocity light trail tunnel (Star Wars / Tron aesthetic).
- **Particles**: Interactive physics particles reacting to cursor velocity.
- **Waves**: 3D geometric sinusoidal wave grid.
- **Iridescence**: Holographic, pearlescent color shift shader.
- **Ballpit**: 3D gravity-driven bouncing spheres powered by Matter.js.
- **GridDistortion**: Elastic cursor-reactive warping mesh.
- **Threads**: Silky flowing curves in harmonic oscillation.

### 3. UI Components & Cards (48+ components)
- **TiltedCard**: 3D parallax tilt with specular glare tracking mouse position.
- **SpotlightCard**: Radial glow beam highlighting card border on mouse movement.
- **FlowingMenu**: Expandable editorial marquee navigation menu.
- **ElasticSlider**: Physics-based drag slider with elastic rubber-band feel.
- **RollingGallery**: 3D cylindrical carousel rotation.
- **DecayCard**: Grunge/peel-away interactive hover card.
- **Stepper**: Smooth animated multi-step progress indicator.
- **PixelCard**: Pixelated reveal hover state.

### 4. Micro Interactions (34+ components)
- **SplashCursor**: Realistic fluid dynamics following cursor movement with colored dye injection.
- **BlobCursor**: Gooey SVG metaball trail tracking the cursor.
- **Magnet**: Elastic magnetic pull attracting buttons to the pointer.
- **StarBorder**: Animated stellar border glowing around action buttons.
- **FollowCursor**: Interactive object trailing cursor with spring physics.

---

## 🛠️ Typical Dependencies

Different components leverage specialized lightweight libraries:
- **Animations**: `gsap` (`npm i gsap @gsap/react`), `motion` (`npm i motion` or `framer-motion`)
- **3D & Shaders**: `three` (`npm i three @types/three`), `ogl` (`npm i ogl`)
- **Physics**: `matter-js` (`npm i matter-js`)
- **Utilities**: `clsx`, `tailwind-merge` (`npm i clsx tailwind-merge`)

When authoring or integrating React Bits code:
1. Always declare and install the required peer dependency.
2. Clean up event listeners and animation frames inside `useEffect` / `useGSAP` cleanup functions.
3. Support `prefers-reduced-motion` for accessibility.
