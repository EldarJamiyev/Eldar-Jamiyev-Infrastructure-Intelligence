# Style guide

Choose a register from the content, then let the subject tint it (Topic motif). `templates/page.html` is the Instrument register built to this guide.

## Registers

| Register | Use for | Display / body / mono | Signature |
|---|---|---|---|
| **Instrument** | diff and plan reviews, audits, metrics, status | Geist 600 / Geist / Geist Mono | A KPI strip near the top when there are metrics. Tabular numbers everywhere. Cells split by hairlines, not floating cards. Status as shape + word. |
| **Blueprint** | architecture, data flow, systems, visual plans | IBM Plex Sans 600 / IBM Plex Sans / IBM Plex Mono | 24px grid on the background. Boundaries as dashed frames with a mono tag. Numbered callouts ① ② on the drawing. Dimension lines for spans. |
| **Paper** | concepts, how-it-works, fact-checks, long reading | Newsreader 500 / Atkinson Hyperlegible Next / Atkinson Hyperlegible Mono | Narrow text column, wide figures. Margin notes at ≥ 1200px. `Fig. N` labels. |
| **Editorial** | recaps, narratives, decks, showcases | Instrument Serif / Instrument Sans / JetBrains Mono | Display type at full scale. Asymmetric grid with large empty areas. One number or phrase per screen carries the page. |

The project's own design system overrides the register; a named palette → `themes.md`. Each register's tokens, in both schemes, are in `kit/kit.css`: a kit page gets them from `data-register`, and a slide or video deck copies its register's block from there. Text tokens reach 4.5:1 on `--bg` and `--surface`; `--border-bright` (3:1) carries meaningful outlines, `--border` only decorative rules.

## Visual principles

1. **Quiet ground, one signal.** About 90% of the page is neutral. The accent marks only what the reader must look at now: the key node, the hot path, the active control, the one number that matters.
2. **The figure is the interface.** A prose term and its element in the figure light up together (`diagrams.md` → Linked highlighting).
3. **Overview, then detail.** The full picture first; the reader steps, hovers, or expands for detail. Raw material goes in `<details>`, but sources stay in a visible section at the end.
4. **Motion shows change or flow.** Blocks rise in once, dots move at the real rate, steps reveal parts. No parallax, scroll-jacking, or decorative loops. Under reduced motion, show the final state.
5. **Craft is part of the meaning.** Nodes sit raised on a dot-grid stage, shapes say what a thing is (a cylinder is a store), the one focal element gets a soft halo, the hot path a glow.

## Typography

| | Rule |
|---|---|
| Hierarchy | Few sizes, big jumps: contrast comes from the gap between body and display. Each level changes one or two of size, weight, and color. Start quiet; promote only what must be read first. |
| Measure | Body about 65ch; side notes 40–50ch; lead 40–50ch. |
| Breaks | Break display lines at phrase boundaries. Flush left, ragged right; never justify. |
| Numerals | `tabular-nums` in tables, KPIs, and anything that updates; proportional in prose (oldstyle in Paper). Number columns right-aligned. Format for reading (`5.6k`, `−86%`), repeat the unit in every label, and state the comparison (`from 5,600`). |
| Characters | Curly quotes. `–` for ranges, `—` for a break, `−` for minus, `×` for multipliers, `…`, `≤`. A no-break space between number and unit (`1&nbsp;ms`). |
| Emphasis | Bold or italic, never both; italics and uppercase only for a few words. Underline only links and linked terms. |

## Layout

| | Rule |
|---|---|
| Grid | 12 columns, `s-5` gutter. Text about 8 columns, figures 12, section labels and side notes 3. Every left edge on a column line. |
| One axis | Kicker, headline, deck, figures, captions, and section labels share one flush-left edge. Center only a single number or a title slide. |
| Entry points | Kicker → headline → deck → figure → caption → body. Each screen has one dominant element, one or two secondary ones, and quiet text; blurred, the dominant element still reads. Show position (`2 / 5`, section nav). |
| Section opener | One kind per page. Swiss head: a hairline, a mono label in columns 1–3, the `h2` in 4–12 on one baseline (reviews). Kicker head: a small label above the `h2` (explainers). Figure head: a full-width figure, the `h2` as its title (narratives). |
| Proximity | Space above a heading is 2–3× the space below it. A caption sits `s-3` from its figure. Related things sit closer than unrelated ones. |
| Rhythm | Vary width and density: wide figure → number strip → small multiples → short text. Never three identical blocks in a row. |
| Structure | Space first, a hairline second, a frame last. No card inside a card. Asymmetric empty space reads as deliberate; evenly spread gaps read as unfinished. |

## Figures

| | Rule |
|---|---|
| Pick by relationship | Change over time → line or sparkline. Magnitude → bars. Part of a whole → waffle or stacked bar. Ranking → sorted bars. Deviation → bars around zero. Distribution → strip or histogram. Correlation → scatter. Flow → diagram with flow dots. Place → map. |
| Data-ink | Every mark carries data or guides the eye. No chart borders, plot backgrounds, heavy gridlines, or 3D bars. Gridlines in `--border`, only when values must be read. |
| Layering | Ground < structure < data < signal (accent), each quieter than the one above. Two lines close together make a third shape: add space or merge them. |
| Smallest difference | Each distinction as subtle as it can be while still clear. Two label levels: small and dim, larger and bright. |
| Labels | On the data, horizontal, left-aligned, with the unit. No legend under 5 series. A `--bg` halo where a label crosses a line. |
| Annotate | One or two notes per chart at the point the caption names: a short leader line and a plain phrase. |
| Honest scale | Bars start at zero. Small multiples share one scale. Sort by value unless the order means something. Line charts about 2:1 to 3:1. |
| Line weights | 1 for structure, 1.5–1.75 for data and outlines, 2.5–3 for the signal. |
| Color scales | Sequential: one hue in OKLCH lightness steps. Diverging: two hues around a neutral middle. Categorical: up to 5 hues at equal OKLCH lightness and chroma. |

## Topic motif

The subject adds a light touch of its own, so a page about Postgres does not look like a page about audio: 2–3 touches at most.

| Lever | Rule | Examples |
|---|---|---|
| Accent hue | The subject's own color, adjusted to 4.5:1 in both schemes. Keep the register accent if the hue reads as a status (red ≈ risk, green ≈ ok). | Postgres blue · Rust orange · Redis red → keep the register accent |
| Stage texture | Dot grid by default; 24px line grid for systems and plans, ruled lines for writing, isometric grid for hardware. 15% contrast or less. | |
| Glyphs | Node glyphs from the domain's own symbols, line-drawn. | circuit symbols · map pins · waveform · git branch |
| Type detail | One typographic habit of the domain. | price columns for finance · mono timestamps for incidents · small caps for specs |
| Shape language | The domain's own diagram convention. | swimlanes for processes · ledger for accounting · timing staff for protocols |

Cut any touch whose removal makes the page no harder to read and no less specific. No puns, mascots, or illustration.

## Scale

The kit defines the steps: `--t-label` to `--t-h1`, `--s-1` to `--s-8`, `--r-1` and `--r-2`, and `--fast`, `--med`, `--slow` with `--ease`. Your own CSS uses them and nothing else.

| Decision | Rule |
|---|---|
| Spacing | Inside a component `s-2`–`s-4`; between components `s-5`–`s-6`; between sections `s-8`. A bigger gap means less related. |
| Type | `--t-small` only for buttons, code, and mono labels. |
| Labels | `.ve-label`; uppercase (`.caps`) only for 3 words or fewer. |
| Radius | `r-1` for chips, buttons, inputs, and inline highlights; `r-2` for frames, tables, and overlays. Nothing else is rounded. |
| Accent | One accent, on 10% of the screen or less. Status colors (`ok warn risk info`) only mean status. |
| Motion | Your own motion uses only `transform`, `opacity`, and `stroke-dashoffset`: `fast` for hover, `med` for state, `slow` for steps, always `--ease`. |
| Effects | Shadow (`--lift`) only on raised nodes and overlays; glow only on the key node and the hot edge. |
| Layout | Figures use the full width. Card grids: `repeat(auto-fit, minmax(13rem, 1fr))`. |

## Components

| Component | Spec |
|---|---|
| Page header | `h1` states the answer; a number that is the answer leads it in accent. A lead of a sentence or two with one bold phrase. |
| Dimming | Never fade text: a dimmed label changes to `--text-dim`. No accent text on `--accent-dim`; use `--text` there. |
| KPI strip | Each cell: label → value → its picture. |
| Table | Header in the label style on surface; cells `t-body`, padding `s-3 s-4`; row rules only; numbers right-aligned and tabular; in a scroll container with an `r-2` frame. |
| Callout | Surface, `r-2`, padding `s-4`, a status chip as its title. No colored side bar. |
| Code | Mono `t-small`, surface, `r-2`, padding `s-4`, scrolls sideways. Inline code `.875em`, no box. |

## Polish pass

- Anything you draw yourself reuses the kit's classes, so the same element looks the same everywhere.
- Sections get `scroll-margin-top` under a sticky nav.
- Nothing shifts on load: every SVG has a `viewBox`, every image a width and height.
