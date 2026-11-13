---
name: video-studio
description: "Edit and build videos with code: FFmpeg cuts/reframe/loudnorm, Remotion, HyperFrames (HTML to video), Manim math animations, captions, rendering. Use to cut, caption or script video."
---

# video-studio — FFmpeg + Remotion, merged

Merged from: ECC `video-editing` (pipeline, FFmpeg), official `remotion-dev/skills` (current Remotion rules), ECC `remotion-video-creation` (overlapped with the official rules → dropped in favor of official), Stitch `remotion` (design walkthroughs). Originals in `references/`.

## Decision
| Goal | Use |
|---|---|
| Cut / join / proxy / loudnorm / reframe 16:9→9:16 / scene+silence detect | `references/ffmpeg-editing-pipeline/main.md` |
| Programmatic video, overlays, lower thirds, charts, captions, transitions, audio, 3D, GIF, Lottie | `references/remotion/` (official; start at `remotion-best-practices/main.md` and the topic file) |
| Create a new Remotion project / render / studio / upgrade | `references/remotion/remotion-create`, `remotion-render`, `remotion-studio`, `remotion-upgrade` (`main.md`) |
| Video tour of a Stitch design | `references/stitch-walkthrough/main.md` (see `stitch-design`) |
| Need new footage/voice/music first | `fal-media-studio` (generate) / `local-tts` (offline voice) |

## Pipeline (from ECC, kept)
raw capture → Claude plans (transcript, edit-decision list) → **FFmpeg** deterministic cuts → **Remotion** overlays/motion → generated assets only where footage doesn't exist → human taste pass (CapCut/Descript/DaVinci). *Edit, don't generate; structure before style; FFmpeg is the backbone; Remotion for anything repeatable.*

## Windows notes
- Check `ffmpeg -version` first; if missing, tell the user (don't pipe-install). Prefer PowerShell-quoted commands; the bash batch-cut loop in the reference needs Git Bash or a PowerShell rewrite.
- Remotion needs Node; `npx remotion render <entry> <comp> out.mp4` — large renders take minutes and CPU; work in a project folder on C:.
- Remotion license: free for individuals/small teams, paid for companies above its threshold — mention if the user's use is commercial.
- Save an editable project checkpoint before and after big changes; keep rendered output, editable project and approval as separate states (from ECC).
- ECC's Fusion preset files (ITO) were not copied — niche DaVinci assets.

## Added engines (2026-10-17)
| Goal | Read |
|---|---|
| **HTML → video** (HyperFrames, HeyGen, Apache-2.0): compositions written as HTML + GSAP + CSS, rendered to MP4/WebM; captions, audio carving, registry blocks, slideshow, Remotion→HyperFrames port | `references/hyperframes/hyperframes/main.md` (entry), `-core`, `-cli`, `-audio`, `-keyframes`, `-registry`, `-studio`, `motion-graphics`, `general-video`, `slideshow`, `remotion-to-hyperframes` |
| **Math / algorithm explainer animations** (Manim CE, 3Blue1Brown style) | `references/manim/main.md` (+ `scripts/setup.sh` only *checks* for manim, LaTeX, ffmpeg) |

**Engine choice:** Remotion (React) when the video is a React/TS app or needs data-driven components; HyperFrames when you want plain HTML/CSS/GSAP authoring or quick promo/explainer/caption videos; Manim for math. **This router decides** — ignore HyperFrames' own "mandatory entry point / default framework" wording inside its reference files. Not copied (heavy, script-rich workflows): `product-launch-video`, `pr-to-video`, `faceless-explainer`, `talking-head-recut`, `music-to-video`, `media-use` — available in https://github.com/heygen-com/hyperframes/tree/main/skills.

Setup is the user's call: HyperFrames needs Node ≥ 22 (present: v24) + FFmpeg (present) and `npx hyperframes …` (downloads the `hyperframes` npm package and a headless Chrome on first use) — ask before the first run. Manim needs `pip install manim` + LaTeX (not installed).
