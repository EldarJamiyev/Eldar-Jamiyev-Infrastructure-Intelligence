---
name: design-tokens
description: W3C design token format, CSS custom property system, Figma Token sync, theme generation
metadata:
  type: skill
  triggers: ["design tokens", "token", "css variables", "theme tokens", "figma tokens", "style dictionary"]
---

# Design Tokens

## Token structure (W3C)
```json
{
  "color": {
    "primary": {
      "500": { "$value": "#3b82f6", "$type": "color" }
    },
    "semantic": {
      "background":   { "$value": "{color.neutral.50}", "$type": "color" },
      "text-primary": { "$value": "{color.neutral.900}", "$type": "color" },
      "accent":       { "$value": "{color.primary.500}", "$type": "color" }
    }
  },
  "spacing": {
    "sm": { "$value": "8px",  "$type": "dimension" },
    "md": { "$value": "16px", "$type": "dimension" },
    "lg": { "$value": "24px", "$type": "dimension" }
  }
}
```

## Style Dictionary (token → CSS/JS)
```javascript
module.exports = {
  source: ['tokens/**/*.json'],
  platforms: {
    css: { transformGroup: 'css', buildPath: 'dist/', files: [{ destination: 'variables.css', format: 'css/variables' }] },
    js:  { transformGroup: 'js',  buildPath: 'dist/', files: [{ destination: 'tokens.js',   format: 'javascript/es6' }] }
  }
};
```

## Rules
- Layer: primitive → semantic → component (never skip)
- Semantic tokens reference primitive tokens, never raw values
- Dark mode: only redefine semantic tokens in dark theme
- Never use primitive tokens directly in component CSS
