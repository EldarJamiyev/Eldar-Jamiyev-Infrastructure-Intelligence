---
name: gemini-api
description: "Build with the Google Gemini API: text, chat, multimodal, tools, structured output, Live API voice/video, Omni Flash video. Use when code calls Gemini/Gemma or the user wants Gemini features."
---

# gemini-api — official Google skills (3 merged into one entry)

Source: `google-gemini/gemini-skills` (official). Original `SKILL.md` bodies are in `references/*/main.md` — read only the one you need.

| Task | Read |
|---|---|
| Any Gemini call: generate, chat, multimodal, image/audio output, tools, structured output, Interactions API / managed agents, SDK versions, model IDs | `references/api-dev/main.md` |
| Real-time bidirectional voice/video (Live API, WebSockets), migrating older Live models | `references/live-api/main.md` |
| Text/image/video → video, first/last-frame, video editing with Omni Flash (+ ffmpeg helper scripts) | `references/omni-flash-video/main.md` (scripts in `references/omni-flash-video/scripts/`) |

## Rules
1. **Model IDs and SDK versions drift fast.** Take them from the reference file / live docs, never from memory. SDKs: Python `google-genai`, JS `@google/genai` (install into the project, not globally).
2. **Key handling:** read `GEMINI_API_KEY` from the environment or a project `.env` (gitignored). Never paste a key into code, chat or logs. If missing, tell the user to create one at https://aistudio.google.com/apikey — do not ask them to paste it here.
3. **Free tier:** AI Studio has a free tier with per-model rate/quota limits that change; check the current limits page before promising throughput. Handle 429 with backoff.
4. Omni Flash scripts need `ffmpeg`/`ffprobe` on PATH. Generated video is billed per second — confirm cost/length with the user before long renders.
5. Cross-tool: for polished image/video/voice from many vendors use `fal-media-studio`; for fully offline narration use `local-tts`; Gemini-powered UI design is `stitch-design`.

## Antigravity / Gemini CLI
These skills follow the open Agent Skills format (a folder with `SKILL.md`), which Google lists as compatible with Antigravity and Gemini CLI. To use them there, copy the skill folder into that tool's skills directory — confirm the exact path in the tool's docs first (not verified here).
