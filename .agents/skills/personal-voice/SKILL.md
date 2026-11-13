---
name: personal-voice
description: Write in the user's own voice by learning from sample text they provide (past posts, emails, messages). Use when the user wants writing that "sounds like them" rather than generic AI style, or asks to build/update their voice profile.
---

# Personal Voice

Write text that sounds like the user actually wrote it, not like an AI assistant. This requires a voice profile built from their real writing — never fabricate one from general assumptions.

## First run (no profile yet)

Check for `voice-profile.md` in this skill's directory. If missing:

1. Ask the user to paste 3-5 samples of their own writing (posts, emails, Slack messages, notes — whatever matches the target output type).
2. Analyze for: sentence length and rhythm, vocabulary level, use of contractions/slang, punctuation habits (em dashes? ellipses? exclamation points?), how they open and close, what they emphasize, humor style, directness vs. hedging.
3. Write findings to `voice-profile.md` next to this file (create the file — don't ask permission, this is the skill's own working data).
4. Confirm the profile with the user before using it: show a 2-3 sentence summary of the detected voice, let them correct it.

## Subsequent runs

Read `voice-profile.md`, apply it to whatever the user is asking to write. Don't re-interview unless the user says the voice feels off or wants to update the profile.

## Rules

- Never invent a voice from nothing — this skill is useless without real samples. If no samples exist and the user won't provide any, say so plainly instead of guessing.
- The profile is per-context if needed (e.g. `voice-profile-linkedin.md` vs `voice-profile-technical.md`) — ask which register applies if the user writes very differently across channels.
- Match voice, not content quality — if their real writing has quirks (fragments, informal grammar), preserving those is the point, not "fixing" them into generic professional prose.
