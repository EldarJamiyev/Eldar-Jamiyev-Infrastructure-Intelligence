---
name: humanizer
description: Rewrite AI-sounding text to read as human-written — removes stock phrasing, over-hedging, and robotic structure. Use when the user says text "sounds like AI," wants it "humanized," or asks to de-robotify a draft.
---

# Humanizer

Rewrite text so it stops reading as AI-generated. This is a rewrite pass, not a rewording pass — cut structure, don't just swap synonyms.

## Tells to remove

**Phrases** — delete or replace, don't soften: "In today's fast-paced world," "It's important to note that," "Let's dive in," "In conclusion," "I hope this helps," "Furthermore," "Moreover," "That being said," "At the end of the day," "delve into," "leverage" (as a verb), "robust," "seamless," "game-changer," "unlock the potential of."

**Structure**:
- The rule-of-three list ("fast, reliable, and scalable") appearing everywhere — vary it or cut to one strong point.
- Every paragraph ending with a summary sentence that restates what it just said.
- Perfectly balanced pro/con sections when the real opinion is lopsided.
- Uniform sentence length — real writing has short punchy lines next to longer ones.
- Excessive hedging ("may potentially," "could possibly help") when the writer actually knows the answer.

**Tone**:
- Relentless positivity / enthusiasm with no texture ("This is such an exciting opportunity!").
- Explaining the obvious to a reader who clearly already knows it.
- Emoji or bold-text overuse as a substitute for actual emphasis.

## How to rewrite

1. Read the whole draft first — identify the actual point being made.
2. Cut every sentence that doesn't add new information (restatements, transitions-for-transition's-sake).
3. Vary sentence length on purpose. Let some sentences be short. Fragments are fine.
3. Replace vague claims with specific ones — a number, a name, a concrete detail beats an abstraction.
4. Keep one clear opinion instead of a balanced survey, if the source material supports having one.
5. If [[personal-voice]] profile exists for this user, apply it after the structural cleanup — voice is a separate pass from de-AI-ing.

## Output

Show the rewritten text. If the change is substantial, don't also explain every edit — the rewrite speaks for itself. Flag only non-obvious calls (e.g. "cut the third paragraph — it just restated the second").
