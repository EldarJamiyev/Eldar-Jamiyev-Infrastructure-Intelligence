---
name: prompt-engineering
description: Chain-of-thought, few-shot, system prompt design, temperature guide, structured output
metadata:
  type: skill
  triggers: ["prompt", "system prompt", "chain of thought", "few-shot", "temperature", "prompt design"]
---

# Prompt Engineering

## System prompt structure
```
You are [role]. Your job is [task].

## Rules
- [constraint 1]
- [constraint 2]

## Output format
[exact format with example]
```

## Chain-of-thought
Add "Think step by step" or use `<thinking>` tags. Better: show steps in few-shot examples.

## Few-shot (most reliable)
```
Input: "The product broke after 2 days"
Sentiment: negative
Issue: product quality

Input: {{USER_INPUT}}
Sentiment:
```

## Temperature guide
| Value | Use |
|-------|-----|
| 0.0 | Fact extraction, structured output |
| 0.3 | Classification, consistent output |
| 0.7 | Creative writing, brainstorming |
| 1.0+ | Maximum diversity (rarely useful) |

## Structured output
Claude: use XML tags to request structured output — `response_format: {type: "json_object"}` is OpenAI-only syntax, not Claude API.
OpenAI: `response_format: {type: "json_object"}` works.
Always specify exact schema with example in system prompt.

## Anti-patterns
- Don't say "do not" — say what TO do
- Don't use vague words ("good", "clear") — give examples
- Don't put all constraints in one paragraph — use bullet list
