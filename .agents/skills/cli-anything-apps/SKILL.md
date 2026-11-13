---
name: cli-anything-apps
description: "Drive installed apps from the command line via CLI-Anything: Blender (3D/render), Godot (projects/GDScript), LibreOffice (documents), Ollama (local models). Use when scripting one of these apps beats hand-editing."
---

# cli-anything-apps — HKUDS/CLI-Anything harnesses (Apache-2.0), 4 apps

Installed with `uv tool install` from GitHub, **pinned to commit `34f519533bc175d2fe287ab8316b0dd99bb9cc43`** (isolated envs under uv's tool dir; no `cli-hub`): `cli-anything-blender`, `cli-anything-godot`, `cli-anything-libreoffice`, `cli-anything-ollama`. Each harness's own SKILL.md is in `references/<app>/main.md` (read the one you need for exact commands). Security review (2026-10-17): no `shell=True`/`eval`/pickle, no telemetry; network only to `localhost:11434` (Ollama). Do **not** install `cli-hub` (it runs install commands from a remote registry with `shell=True` and sends analytics).

## Per-app notes
| App | CLI | Needs | Notes |
|---|---|---|---|
| Blender 5.2.1 | `cli-anything-blender` (groups: scene, object, camera, light, material, modifier, animation, render, preview, session) | `blender` on PATH | Builds a JSON scene → generates a bpy script → runs `blender --background --python`. Review generated scripts before rendering untrusted input |
| Godot 4.6.3 | `cli-anything-godot --json -p <project>` (engine, project, scene, script, export, session) | `godot` (on PATH via WinGet) | `script run` executes GDScript — only trusted scripts |
| LibreOffice | `cli-anything-libreoffice` (writer, calc, impress, document, style, export) | `soffice` on PATH | Complements `anthropic-skills:docx/xlsx/pptx`; use for LibreOffice-native conversion/export (e.g. to PDF) |
| Ollama | `cli-anything-ollama --json model list` etc. | Ollama running at `localhost:11434` | Currently **not running** → start with `ollama serve` (ask first) |

## Run (PATH is session-scoped — do not edit the global PATH)
```powershell
$env:PATH = "C:\Program Files\Blender Foundation\Blender 5.2;C:\Program Files\LibreOffice\program;$env:PATH"
cli-anything-blender --help ; cli-anything-godot --json engine version ; cli-anything-libreoffice --help
```
Use `--json` where available for machine-readable output. If Blender is updated, the folder name changes (`Blender 5.x`).

## Rules
- Outputs/projects go to a project folder on **C:**; never overwrite user files without asking.
- Heavy renders/exports take minutes — say so first. Don't run `ollama pull` of large models without confirming size/time.
- Not installed (apps absent): GIMP, Krita, Inkscape, Kdenlive, Shotcut, OBS. Audacity (installed) and Obsidian harnesses were not installed: Audacity needs `sox`; Obsidian needs the "Local REST API" plugin + API key (user supplies it, never in chat).
- Update/pin policy: re-review the diff of a newer upstream commit before changing the pinned SHA.
