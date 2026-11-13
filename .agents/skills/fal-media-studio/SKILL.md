---
name: fal-media-studio
description: Generate/edit images, video, audio and 3D via fal.ai with recipes for cinematic shots, character consistency/anime, storyboards, UGC, ads, upscaling. Use for any "generate image/video/3D/voice" request.
---

# fal-media-studio — one entry for fal.ai media work

Synthesis of two sources: **`fal-ai-community/skills`** (official community pack; CLI `genmedia`, endpoint-first routing, recipes) and **ECC `fal-ai-media`** (MCP-server path). Originals: `references/*/main.md`. Both rely on endpoint IDs that change monthly — **verify before use**.

## 0. Gate (do this first)
- Needs a fal.ai account + `FAL_KEY`. Paid per generation (credits). **Not configured yet.** If no key is set, tell the user to create one at https://fal.ai/dashboard/keys and set env `FAL_KEY` themselves — never ask them to paste it into chat, never write it into files in git.
- Always show an estimate (`pricing` / `estimate_cost`) and get a yes before video, batch or 3D jobs. Draft cheap (small/fast model, 1 output), finalize expensive.
- Output goes to the project's folder on **C:** only.

## 1. Pick the execution path
| Path | When | Setup (user decides — nothing is auto-installed) |
|---|---|---|
| **genmedia CLI** (`references/genmedia/`) | Preferred: smart routing (`genmedia run "prompt" --json`), `schema`, `pricing`, `upload`, `status`, `--download` | Installer is a remote script (`irm https://genmedia.sh/install.ps1 \| iex`) — **do not run it unasked**; show it to the user, or have them install manually from the genmedia-cli repo, then `genmedia setup` |
| **fal MCP server** (`references/mcp-path/`) | If a `fal-ai` MCP is already registered (tools `search/find/generate/result/estimate_cost/upload`) | `npx -y fal-ai-mcp-server` with `FAL_KEY` in env — user adds it |
If neither is installed, stop after planning (prompts, endpoint choice, cost) and ask which path to set up.

## 2. Choose model/endpoint (merged defaults)
Use `references/model-routing/main.md` (newest, endpoint-first) and confirm with `models --endpoint_id` / `schema` / `pricing`. Never invent IDs. Rule of thumb from both sources:
- Text-heavy / premium still → GPT Image 2 (`openai/gpt-image-2`), else Nano Banana Pro; cheap drafts → Nano Banana 2 / FLUX Klein.
- Edits (inpaint, restyle, bg swap) → Nano Banana Pro/2 `edit`, GPT Image 2 `edit`; upscale/restore → `references/fal-recipes/references/image-restoration.md`.
- Final video → Seedance 2.0 (text/image/reference-to-video); quick/cheap → Grok Imagine Video; multi-shot with controls → Kling v3; sound baked in → Veo 3 / Kling v3 (see `video-with-audio.md`).
- Talking head / lip-sync → `veed/fabric-1.0`, `creatify/aurora`, `sync-lipsync`.
- Music/TTS/SFX → see `references/fal-models-catalog/references/text-to-audio.md` (ECC lists CSM-1B, ThinkSound; ElevenLabs is a separate paid API).
- **3D** → `references/fal-models-catalog/references/text-to-3d.md` and `image-to-3d.md`; to display the result in a browser use `threejs-3d` (GLTF loaders).

## 3. Craft (read on demand)
- Prompt grammar per model family → `references/fal-prompting/` (Kling, GPT Image 2, Happy Horse).
- Use-case playbooks → `references/fal-recipes/` (cinematography, character-design, storytelling, commercial, product-shot, realism, lipsync, virtual try-on, video-with-audio).
- **Cinema / cartoon / anime:** `character-design` (identity anchors → consistent character), `cinematography` (shot language, lens, light), `storytelling` (storyboard → multi-shot continuity). Anime/cartoon look = fix the style anchor first (one reference sheet), then reuse it as reference input for every shot.
- Ads and social: `commercial`, `marketing`, `ugc`. Games: `fal-gamedev` (sprites, parallax). Pipelines: `fal-workflow`.

## 4. Handoffs
Edit/assemble clips → `video-studio` (ffmpeg + Remotion). Offline voice → `local-tts`. Web 3D → `threejs-3d`. Image-to-3D character viewer → see `fal-regenerate-3d` idea in the community repo (not copied).
