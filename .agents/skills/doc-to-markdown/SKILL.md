---
name: doc-to-markdown
description: Convert PDF, Word and Excel files to clean Markdown (uv + markitdown) before analysing or summarising them, saving tokens. Use when asked to read or summarise a .pdf/.docx/.xlsx (not to edit one).
---

# doc-to-markdown — 3 awesome-copilot converters (MIT) as one router

Source: `github/awesome-copilot` → `convert-pdf-to-md`, `convert-word-to-md`, `convert-excel-to-md` (community-contributed; each = SKILL.md→`main.md`, `setup.md`, one Python script, `requirements.txt`). Originals unmodified under `references/<name>/`. Engine: Microsoft **markitdown** (+ **pymupdf** for PDF images).

## Run (nothing is installed globally — use `uv`)
```powershell
$s = "$HOME\.claude\skills\doc-to-markdown\references"
uv run --with "markitdown[pdf]" --with pymupdf python "$s\convert-pdf-to-md\scripts\convert_pdf_to_md.py"  "C:\path\file.pdf"  -o "C:\path\out"
uv run --with "markitdown[docx]" python "$s\convert-word-to-md\scripts\convert_word_to_md.py"  "C:\path\file.docx" -o "C:\path\out"
uv run --with "markitdown[xlsx]" python "$s\convert-excel-to-md\scripts\convert_excel_to_md.py" "C:\path\file.xlsx" -o "C:\path\out"
```
Folder input works (add `--recursive`). Read each `references/<name>/main.md` for exact options (image folders, output naming). `uv` fetches the packages into a cached temp env on first run (needs network once).

## Decide
| Goal | Use |
|---|---|
| Read/summarise/search a PDF, Word or Excel | this skill → then read the produced `.md` |
| Scanned PDF (no text layer) | markitdown may return little; use OCR path (`sk-pdf` OCR, or `anthropic-skills:pdf`) |
| Create/edit Word/Excel/PDF | `anthropic-skills:docx` / `xlsx` / `pdf`; Markdown→Word quick path: `md-to-docx` |

## Rules
- Write outputs next to the source or a project folder on **C:** only; never overwrite an existing `.md` without asking.
- Conversion runs locally (no upload). Don't convert files that hold secrets/PII unless the user asked, and keep outputs out of git (gitignore).
- After converting, read the `.md` (not the original) and cite page/sheet where available; large outputs: read headings first, then the needed sections.

