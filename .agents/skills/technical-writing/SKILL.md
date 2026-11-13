---
name: technical-writing
description: Docs-as-code, Diátaxis framework (tutorial/how-to/reference/explanation), API docs, README
metadata:
  type: skill
  triggers: ["technical writing", "documentation", "docs", "readme", "how-to", "tutorial", "diataxis"]
---

# Technical Writing (Diátaxis)

## 4 doc types (never mix)
| Type | Goal | User state |
|------|------|------------|
| **Tutorial** | Learning | Beginner, following along |
| **How-to** | Solving problem | Knows what they want |
| **Reference** | Information | Looking something up |
| **Explanation** | Understanding | Wants to understand why |

## README structure
```markdown
# Project Name
One-line description.

## Quick start (< 5 lines to working state)
## Why this exists
## Installation
## Usage
## API Reference
## Contributing
```

## Tutorial structure
1. What you'll build (end state, concrete)
2. Prerequisites (exact versions)
3. Steps numbered: command → expected output → explanation
4. Troubleshooting at end

## Code example rules
- Working, copy-pasteable (no ellipsis unless explained)
- Simplest case first, complex after
- Error messages shown exactly as they appear

## Style
- Active voice: "Run the command" not "The command should be run"
- Present tense: "This function returns" not "will return"
- Concrete over abstract: "3 seconds" not "a moment"
