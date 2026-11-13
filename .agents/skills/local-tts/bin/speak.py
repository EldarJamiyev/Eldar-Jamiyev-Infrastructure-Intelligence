# /// script
# requires-python = ">=3.9"
# dependencies = ["sherpa-onnx"]
# ///
"""Offline TTS via sherpa-onnx Python API (full Unicode: ə ş ğ ı ç ö ü work).

Usage:
  uv run speak.py --model tr --text-file in.txt -o out.wav
  uv run speak.py --model en --text "Hello" -o out.wav [--speed 1.0] [--sid 0]
Models live in C:\\Users\\sahin\\.claude\\tools\\sherpa-onnx-tts\\models (override: SHERPA_ONNX_MODELS_DIR).
"""
import argparse, os, sys, wave
from array import array
from pathlib import Path

import sherpa_onnx

MODELS = Path(os.environ.get("SHERPA_ONNX_MODELS_DIR", r"C:\Users\sahin\.claude\tools\sherpa-onnx-tts\models"))
ALIASES = {"tr": "vits-piper-tr_TR-fettah-medium", "en": "vits-piper-en_US-lessac-high"}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--model", default="tr", help="alias (tr/en) or model folder name")
    p.add_argument("--text")
    p.add_argument("--text-file")
    p.add_argument("-o", "--output", default="tts.wav")
    p.add_argument("--speed", type=float, default=1.0)
    p.add_argument("--sid", type=int, default=0)
    a = p.parse_args()

    text = Path(a.text_file).read_text(encoding="utf-8") if a.text_file else (a.text or "")
    if not text.strip():
        print("Missing text (--text or --text-file)", file=sys.stderr)
        return 1

    d = MODELS / ALIASES.get(a.model, a.model)
    onnx = [f for f in d.glob("*.onnx")]
    if len(onnx) != 1:
        print(f"Expected exactly one .onnx in {d}, found {len(onnx)}", file=sys.stderr)
        return 1

    cfg = sherpa_onnx.OfflineTtsConfig(
        model=sherpa_onnx.OfflineTtsModelConfig(
            vits=sherpa_onnx.OfflineTtsVitsModelConfig(
                model=str(onnx[0]), tokens=str(d / "tokens.txt"), data_dir=str(d / "espeak-ng-data")
            ),
            num_threads=2,
            provider="cpu",
        )
    )
    audio = sherpa_onnx.OfflineTts(cfg).generate(text, sid=a.sid, speed=a.speed)
    pcm = array("h", (int(max(-1.0, min(1.0, s)) * 32767) for s in audio.samples))
    out = Path(a.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with wave.open(str(out), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(audio.sample_rate)
        w.writeframes(pcm.tobytes())
    print(f"saved {out} ({len(pcm) / audio.sample_rate:.1f}s, {audio.sample_rate} Hz)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
