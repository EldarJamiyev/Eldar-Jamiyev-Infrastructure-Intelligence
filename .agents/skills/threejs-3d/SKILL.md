---
name: threejs-3d
description: "Build interactive 3D in the browser with Three.js/WebGL: scenes, materials, lighting, GLTF loading, animation, interaction, post-processing, shaders. Use for 3D sites, viewers or showing generated 3D models."
---

# threejs-3d — 10 Three.js skills as one router

Source: `CloudAI-X/threejs-skills` (community, MIT-style; the marketplace's "Three.js …" variants are copies of these). Each topic is in `references/<topic>/main.md`; load **only the topics the task touches**.

| Task | Read |
|---|---|
| New scene, camera, renderer, resize, Object3D tree, coordinates | `fundamentals` |
| Shapes, BufferGeometry, instancing | `geometry` |
| Materials (PBR, Basic, Phong, ShaderMaterial) | `materials` |
| Textures, UVs, env maps / HDR | `textures` |
| Lights, shadows, IBL | `lighting` |
| Load GLTF/GLB models, textures, loading manager | `loaders` |
| Play GLTF animations, mixers, morph targets, procedural motion | `animation` |
| Click/hover picking, OrbitControls, touch | `interaction` |
| EffectComposer, bloom, DOF, color grading | `postprocessing` |
| GLSL vertex/fragment, uniforms, custom effects | `shaders` |

## Rules
- Use ES modules + a bundler (Vite) for real projects; a single-file demo may use an import map from a pinned CDN version (pin the version; check it is ≥2 weeks old).
- Performance budget first: cap `devicePixelRatio` (≤2), reuse geometries/materials, instance repeats, dispose of GPU resources, compress textures; test on a mid phone.
- Accessibility: provide a non-3D fallback/description and honor `prefers-reduced-motion`; run `ui-quality` on surrounding UI.
- 3D assets: generated models come from `fal-media-studio` (text/image-to-3d) → export GLB → `loaders`. Verify licensing of any downloaded model.
- 3D game logic beyond the browser (Godot/Unity/Unreal) is out of scope — see `game-studio-pipeline`.
