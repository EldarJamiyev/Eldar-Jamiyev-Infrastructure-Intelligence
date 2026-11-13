# Hand-drawn SVG figures

Inline SVG is the default figure: exact placement, page tokens and fonts, and motion. The kit (`kit.md`) styles and runs every pattern here; this file gives the markup contracts and the rules.

## Plan on a grid

```
x:  40        280        520        760      columns 240 apart
    ┌──────┐  GET /u   ┌──────┐  miss   ┌──────┐
y:90│Client│──────────►│ API  │────────►│  DB  │
    └──────┘           └──┬───┘         └──────┘
                     hit  │ reads
y:210                  ┌──▼───┐
                       │Cache │
                       └──────┘
```

- Sketch in ASCII first, then turn columns and rows into coordinates. A viewBox width of 720–1000 keeps `14` units ≈ 14px.
- At least 40 units between boxes. Orthogonal edges (`M x y H x V y`). Labels 9 units above their line.
- SVG text does not wrap: lines of about 18 characters, `<tspan x=".." dy="1.2em">` for a second line.
- A boundary (process, network, trust zone) is a dashed rect with a mono label in its top-left corner.
- Over about 12 nodes, draw a 5–8 node overview and put the detail in cards or a second figure.
- Sequence: one column per actor with a thin lifeline, time runs down, each arrow labeled with its call. Schema: one box per table with its key fields in mono, crow's-foot ends for many.

## Shapes

- **Shape says what a thing is.** Rect for a service. Cylinder for a datastore (`path.sh` + `ellipse.sh.lid`). Rect with 3 short dividers for a queue. Dashed rect for something optional or down.
- **Glyph** (`.gl`): a 16-unit line drawing in the node's top-left corner, only when the name does not say the kind. Never emoji.
- **Edges:** solid = sync call · dashed = async or optional · thick glowing accent = the path this figure is about · red ✕ = blocked.

## Dimensions

A number that measures a span sits on that span: latency down a sequence's time axis, a TTL window on a timeline, a field's size on a byte layout.

```
   ┼                       ┼    extension lines from the two measured points
   │◄─────── 9 ms ────────►│    dimension line, value in a gap at its middle
```

```html
<g class="ve-dim"><path class="ext" d="M120 300V322M380 300V322"/><path class="ln" d="M120 316H380M116 320l8-8M376 320l8-8"/><text x="250" y="310">9 ms</text></g>
```

- A short 45° tick at each end. The value sits centered 6 units above the line, never on it.
- Dimensions run on rails beside the shapes, the shortest nearest. Spans that add up (`1 ms` then `9 ms`) chain on one rail, with the total on the next rail out.
- The dimension that carries the claim takes the accent (`.is-key`), one per figure.

## Flow dots

Moving dots show direction and volume on the main figure when traffic or data moves. The ratio of spawn intervals is the real split.

```html
<path data-flow="hit"  data-every="420"  d="M95 105H375V80H695V105H375"/>   <!-- invisible route -->
<path data-flow="miss" data-every="7000" d="M95 105H355V270H395V130H695"/>  <!-- 420:7000 ≈ 94:6 -->
<g class="ve-dots" aria-hidden="true"></g>                                   <!-- after edges, before nodes -->
```

Routes pass through node centers, so dots enter one box and leave the next. One moving layer per page.

## Linked highlighting

Elements that share a `data-ref` light up together: a prose term, a node, an edge, a card, a button. Prose terms get `tabindex="0"`; one element can carry several refs (`data-ref="hit miss"`). Link 2–4 key terms per figure, not every noun.

## Stepper and scene player

Each step brings its parts forward with a one-line caption. With Play and a scrub bar it becomes a scene player.

```
<figure class="ve-steps">  parts: data-s="N" (appears at step N) · paths with pathLength="1" draw in
  .ve-player → ol.ve-cap > li[data-n="1/5"] · button[data-go=-1] · button[data-play] · input[type=range] · button[data-go=1]
```

It opens on the complete picture. One claim per scene; something visibly changes at every step. Never autoplay.

**Callouts.** A numbered circle with a short leader line that ends exactly on the point it names; plan heroes use the same mark. Callout N is step N: give the circle and its leader `data-s="N"`. Without a stepper, list them under the figure as one-line notes (`③ the miss reads Postgres`). 3–6 per figure.

```html
<path class="ann" data-s="3" d="M520 71V96"/><g class="ve-co" data-s="3" transform="translate(520 60)"><circle r="11"/><text>3</text></g>
```

## Replay: states and events

For a state machine, a workflow, or a reducer, each step is one event. The caption says what happened and why: `miss → fetch, because the TTL expired (cache.ts:48)`. The "because" is the guard or branch that fired: cite it, never invent it. Pick 6–12 events that carry one claim; show the other branch as a second stepper or small multiples. If the events come from a real run, say so in the figcaption.

`data-s` may list steps: a part appears at the first and lights on each; `0` draws it from the start. Draw the whole machine with `0` and let the run light its path. On a step, the edges that fired and the node's border light, and each token runs once. To light a route, give every edge on it the step and run one token along the joined `d`. The last step is the full picture.

```html
<path class="ve-e" data-s="0 3 5" d="M730 90H800"/>                                              <!-- drawn all along; lights on 3 and 5 -->
<g class="ve-co q" data-s="0 3 5" transform="translate(765 68)"><circle r="11"/><text>3</text></g>   <!-- its number, filled on 3 and 5 -->
<circle class="ve-tok" data-s="6" r="5" style="offset-path: path('M910 150V295H650V150'); --dur: 2200ms"/>   <!-- a route -->
<circle class="ve-tok" data-s="1" r="5" style="offset-path: path('M170 90H240'); --d: 130ms"/>   <!-- one of a burst -->
<g class="ve-at job" data-s="3 4" style="--d: 850ms"><rect x="217" y="72" width="26" height="26" rx="4"/><text x="230" y="85">J3</text></g>   <!-- .ve-at shows and hides it; .job is your own fill and stroke, over an empty slot you draw -->
<g class="ve-vals"><text class="sub" data-s="0" x="236" y="52">0 / 8</text><text class="sub" data-s="2" x="236" y="52">5 / 8</text></g>
```

- **Tokens** run under the nodes, entering each box and leaving from the far side; a token that lands in or leaves a slot goes after the nodes. `--dur` lengthens a run (900 ms default); `--d` delays it, so a burst is tokens about 150 ms apart.
- **Parts that come and go** (a queued job, a busy worker, the current state's ring) are `.ve-at` groups, shown only on the steps their `data-s` lists. Draw the empty slot underneath.
- **A changing value** (a count, a TTL, a state name) is one text per step at one spot inside `.ve-vals`, in step order.
- **A shared resource** (a worker pool, permits) is a dashed boundary holding its slots and its count.
- **Kind labels:** `<text class="ve-kind">` above a node name: `fact`, `decision`, `state`, or `effect`. Number edges with `.ve-co.q` when captions refer to them.

## Before / after

One drawing in the same coordinates with a toggle (`button[aria-pressed]` flips `figure[data-view]`; `.only-before` / `.only-after` groups). Added = `--ok` stroke; removed = `--risk` dashed. Static: two panels side by side at the same scale.

## Live figure

Controls that recompute the picture, so the reader feels a setting: a TTL slider moves the hit rate, the dot split, and the headline. A policy toggle can show the bad rule giving a nicer, wrong number.

- One to three controls (`input[type=range]`, `button[aria-pressed]`), each changing something the reader cares about.
- One pure `model(settings)` feeds the figure, the numbers, and the sentence.
- Default to the real current value and mark it on the scale. Insert controls from JS and hide them in print, so print and no-JS show that state.
- Show the formula in the caption or a `<details>`; label a simplified model "illustrative". Model the concept; never copy production logic.

## Small multiples

The same small diagram once per case, in the same coordinates, so the eye sees only the difference. The part that changes takes the case's status color (`.case[data-st]`; mark it `.is-st`). Each card: status chip, short title, mini diagram, no sentence. Mini labels 14 units or more.

## Small charts

A number that does not measure a span gets a small chart beside it: `<ve-waffle>` for "N of 100", `<ve-bars>` for 2–5 values (`hot` on the one that matters), `<ve-stack>` for a share of a whole (`kit.md`). A trend is a sparkline: `0 0 100 24`, one `polyline`, `vector-effect: non-scaling-stroke`, with `role="img"` and an `aria-label` holding the values.

## 3D with three.js

Only when depth carries data: embeddings, physical or spatial layouts, stacks where height is a quantity, geometry. A graph of boxes and arrows is never 3D.

```html
<script type="importmap">{"imports":{"three":"https://cdn.jsdelivr.net/npm/three@0.186/build/three.module.js","three/addons/":"https://cdn.jsdelivr.net/npm/three@0.186/examples/jsm/"}}</script>
```

- Canvas in a `.frame` with a fixed aspect ratio, `role="img"`, an `aria-label`, a `Fig. N` caption, and a one-line text fallback with the key numbers.
- Colors from the page tokens via `getComputedStyle`; labels with `CSS2DRenderer`. One directional light plus ambient; no bloom, fog, or particles.
- `OrbitControls` with damping and zoom limits, plus "Reset view". Open on an angle that shows the answer; auto-rotate only until the first interaction, never under reduced motion.
- `setPixelRatio(Math.min(devicePixelRatio, 2))`, a `ResizeObserver`, and render only while visible.

## Page structure for 4+ sections

A sticky `<nav>` table of contents on the left; below 1000px a sticky top bar whose link list alone scrolls sideways (hidden scrollbar, right edge faded with `mask-image`). Mark the active section with an `IntersectionObserver` (`rootMargin:'-10% 0px -80% 0px'`). Wrap `history.replaceState` in `try/catch`; it throws on `file://` pages.

## Other shapes

- **File map:** nested `<ul>` in mono; each path gets a status chip (added, modified, deleted) and a `+12 −3` count.
- **Timeline:** a CSS grid with one rail line and dated nodes; the newest gets the accent.
