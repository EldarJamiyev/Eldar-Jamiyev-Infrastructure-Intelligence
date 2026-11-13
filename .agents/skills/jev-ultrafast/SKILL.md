---
name: jev-ultrafast
description: Ultra-fast browser automation agent built on browser-use. Operates on numbered page elements for rapid web scraping, testing, and UI navigation.
---

# jev-ultrafast

Ultra-fast browser automation agent built on browser-use. Operates on numbered page elements for rapid web scraping, testing, and UI navigation.

## Quick Command / Usage
```bash
python -m browser_use
```

## Documentation & Reference
<img src="docs/banner.svg" alt="Jev Ultrafast · Browser Use × TypeSafe" width="100%" />

> [!NOTE]
> **Jev Ultrafast is now ultrafast mode in [Browser Use](https://github.com/browser-use/browser-use).** Same idea, built in: the agent acts on numbered page elements. Browser Use also handles long multi-step tasks.
>
> Python: `pip install browser-use`, then `Agent(task, mode='ultrafast')` (already the default on the `bu-fast` and `bu-ultrafast` models). Hosted: the `bu-ultrafast` model in Browser Use Cloud.
>
> This repo stays up as the original Browser Use × TypeSafe experiment.

# Jev Ultrafast ⚡

> [!IMPORTANT]
> **BU Ultrafast, Browser Use Cloud's own hosted agent, is live on every plan.** Set `model: "bu-ultrafast"` to use it.
> **[Learn more](https://browser-use.com/ultrafast?utm_source=github&utm_medium=readme&utm_campaign=jev-ultrafast)** · **[Open Browser Use Cloud](https://cloud.browser-use.com?utm_source=github&utm_medium=readme&utm_campaign=jev-ultrafast)**

**A browser agent with a dynamic, indexed action space.**

Give it one goal. [TypeSafe's Jev](https://docs.typesafe.ai/introduction) picks an operation and an element. A small LLM writes text only when the operation is `TYPE_TEXT`.

**Zürich → London on Google Flights in 7.1 seconds.** One natural-language goal, actual text generation, and loading waits included.

<a href="docs/demo.mp4"><img src="docs/demo.gif" alt="A real Google Flights search at 1× speed, with generated city names and dynamic operation/target decisions" width="100%" /></a>

[Watch the MP4](docs/demo.mp4) · [Measurements](docs/performance.md) · [Read the loop](jev_ultrafast/agent.py)

## The action space

Every observation produces a new element table:

```text
[1] button    Change ticket type · Round trip
[2] combobox  Where from?        · San Francisco
[3] combobox  Where to?          · empty
[4] textbox   Departure          · empty
...
```

The operations are `CLICK`, `TYPE_TEXT`, `SELECT`, `SCROLL_UP`, `SCROLL_DOWN`, `WAIT`, `DONE`, and `BLOCKED`. Only supported operations and targets are offered.

```text
                      one TypeSafe request
                     ┌───────────────────────────┐
page → element table → operation                 │
                     │ click_target              │
                     │ type_text_target          │
                     │ select_target, if present │
                     └─────────────┬─────────────┘
                         use the matching target
                                   │
                    CLICK [7] ─────┤──→ browser
                TYPE_TEXT [3] ─────┘
                          ↓
                   small LLM → text → browser
```

Target questions are speculative. If the operation is `CLICK`, only `click_target` can execute. Two decisions, **one network round trip**. Each target head contains only compatible elements. Native dropdown choices carry an observed element/option index.

There are no site-specific action scripts or prepared field string
