---
name: opendlss-nr
description: Vulkan & WebGPU reimplementation of NVIDIA DLSS 5 Neural Rendering network. Neural supersampling, temporal anti-aliasing, and real-time ray reconstruction shaders.
---

# OpenDLSS-NR

Vulkan & WebGPU reimplementation of NVIDIA DLSS 5 Neural Rendering network. Neural supersampling, temporal anti-aliasing, and real-time ray reconstruction shaders.

## Documentation
# DLSS 5 NR: native demo on Filament

The NR network running live inside a [Filament](https://github.com/google/filament) frame: real scenes, real
per-object motion vectors, and the temporal history the network was trained to use.

Windows only. See [Platform support](#platform-support).

## Build and run

```
scripts\fetch_tools.ps1 -Npm        # once: the toolchain under tools\ (and the scene converter's npm modules)
scripts\fetch_filament.ps1          # once: clone Filament v1.77.0, apply third_party\filament.patch
scripts\build_filament.ps1          # Filament + SDL2 + filagui -> third_party\filament-install (~15 min, once)
scripts\build.ps1                   # NR kernels / PTX (build\shaders, build\ptx) + the dlss5vk tool
scripts\build_demo.ps1              # demo shaders + materials (build\data) + build\demo\dlss5-demo.exe
build\demo\dlss5-demo.exe [scene.gltf|.glb [environment.hdr]] --model <nr model dir>
```

`--model` is the network's model directory (see the top-level README; it is not part of this repository), or
`DLSS5VK_MODEL`, or `models\nr` next to the repository. Without a scene argument the demo starts on the first
directory under `build\scenes` that holds a `view.json`. `scripts\run_demo.ps1 -Model <dir>` does the same.

## Controls

The window can be resized; the network re-fits to the new size.

- **WASD / QE** move, **shift** faster
- **left drag** look around
- **N** NR on/off, **T** temporal history, **R** reset history
- **B** background
- **C** capture: a PPM of the output and of the HDR scene
- **Esc** quit

## Command line

- `--width w --height h`, `--scenes <dir>`, `--kernels <dir>`
- `--view px,py,pz,tx,ty,tz[,fov]` places the camera
- `--nr 0` runs without the network, `--temporal 0` without history
- `--style 1|2`, `--intensity x`, `--animation n`
- `--frames N --capture prefix` is the scripted run: it captures at frames 40, 100, 160 and 200 of a
  static, orbit, settle, NR-off sequence, and dumps the raw scene and velocity buffers at frames 99 and 100 and
  the unpacked motion (with its history flag) at 100. `--orbit deg` yaws the camera by that much per frame from
  frame 40.
- `DLSS5_DEMO_VALIDATION=1` enables the Khronos validation layer and refuses to start without it (a Vulkan SDK, or
  `VK_LAYER_PATH` at a build of Vulkan-ValidationLayers; `VK_KHRONOS_VALIDATION_VALIDATE_SYNC=true` adds
  synchronization validation). The NR pass runs clean under both; the remaining messages are Filament's.

## Scenes

No scenes come with this repository. gltfio reads glTF 2.0 with Draco and meshopt compression, KTX2 textures
and the KHR material extensions (clearcoat, sheen, transmission, volume, IOR, specular, emissive strength).

### Getting one

- **Lone Monk**, Carlo Bergonzini / Monorender, CC BY 4.0, in the Cycles section of
  [blender.org/download/demo-files](https://www.blender.org/download/demo-files/). That download is a `.blend`,
  so it needs a glTF export first; the commands below take the web build of it.
- **Bistro**, Amazon Lumberyard, CC BY 4.0, from
  [ORCA](https://developer.nvidia.com/orca/amazon-lumberyard-bistro). That download is FBX, so it needs a glTF
  export too, and it is large: about 2.8 million triangles for the exterior, 381 MB once converted.
- The Filament checkout brings in two small assets that need **no conversion**, under
  `third_party\filament\third_party\models`: `Fox\Fox.glb` (CC0 model, CC BY 4.0 rig and animation) and
  `AnimatedMorphCube\AnimatedMorphCube.glb` (CC0). `dem
