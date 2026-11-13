---
name: local-tts
description: Offline text-to-speech on this PC (sherpa-onnx; Turkish and English voices, no cloud or key). Use to narrate text, make a voiceover or read a document aloud locally.
---

# local-tts — offline TTS (sherpa-onnx)

Everything lives on C: — runtime `C:\Users\sahin\.claude\tools\sherpa-onnx-tts\runtime`, voices in `...\models`. Source: openclaw `sherpa-onnx-tts` skill + k2-fsa sherpa-onnx v1.13.6 (runtime SHA256-verified).

## Use (always prefer `speak.py` — full Unicode)

```powershell
# write text to a UTF-8 file first (Windows argv mangles ə ş ğ ı)
uv run "$HOME\.claude\skills\local-tts\bin\speak.py" --model tr --text-file in.txt -o out.wav
uv run "$HOME\.claude\skills\local-tts\bin\speak.py" --model en --text "Hello there" -o out.wav --speed 1.0
```

- `--model tr` → `vits-piper-tr_TR-fettah-medium` (male, Turkish; reads Azerbaijani text with a Turkish accent, `ə` is approximated)
- `--model en` → `vits-piper-en_US-lessac-high` (English)
- First run downloads the `sherpa-onnx` wheel (~18 MB) via uv, then cached.
- Output is 16-bit mono WAV. Convert/trim with ffmpeg if needed (`ffmpeg -i out.wav out.mp3`).

`bin/sherpa-onnx-tts.mjs` is the original Node wrapper (ASCII only; set `SHERPA_ONNX_RUNTIME_DIR` and `SHERPA_ONNX_MODEL_DIR`). `--text-file` was added locally but the underlying exe still reads argv in the ANSI codepage, so non-ASCII text is corrupted — use `speak.py`.

## Add another voice
Models: https://github.com/k2-fsa/sherpa-onnx/releases/tag/tts-models (`vits-piper-*`; also `ru_RU`, `kk_KZ`, `tr_TR-fahrettin`). Download the `.tar.bz2`, extract into `...\models`, then pass the folder name to `--model`. Keep everything on C:.

## Limits / when not to use
- Quality is "good local", below ElevenLabs/Gemini Live/fal.ai TTS. For polished narration use `fal-media-studio` or `gemini-api` (Live/TTS).
- CPU only; ~4× real-time on first call (model load), faster afterwards.
- No voice cloning (see `C:\Claude\refs\VoiceStudio` for that).
