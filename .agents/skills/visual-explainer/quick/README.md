# Quick renderer

The agent emits a compact JSON spec; `render.mjs` validates it and writes one self-contained HTML page. Pi:

```json
{
  "action": "render_quick",
  "filename": "auth-flow-quick",
  "spec": {
    "title": "Authentication flow",
    "sections": [
      {
        "title": "Request path",
        "flow": {
          "nodes": [
            { "id": "browser", "label": "Browser" },
            { "id": "api", "label": "API", "tone": "positive" }
          ],
          "edges": [{ "from": "browser", "to": "api", "label": "token" }]
        }
      }
    ]
  }
}
```

Elsewhere: save the spec and run `node <skill>/quick/render.mjs spec.json ~/.agent/diagrams/auth-flow-quick.html`. On an error, write the full page instead.

`schema.json` is the authoritative schema. A spec has a `title`, optional `subtitle` and `summary`, and one or more `sections`, each with any of: `cards` (findings or concepts), `table` (columns and string rows), `risks` (severity-tagged), `files` (paths, details, change status), `steps` (ordered work or a timeline), `flow` (nodes and directed edges), `callouts` (notes, decisions, warnings), `evidence` (a label, value, and optional source). All text is HTML-escaped. Unknown properties, bad enum values, bad flow references, and rows with the wrong column count fail validation.
