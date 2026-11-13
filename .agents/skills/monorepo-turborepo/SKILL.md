---
name: monorepo-turborepo
description: Turborepo/NX monorepo setup, shared packages, build cache, workspace protocol
metadata:
  type: skill
  triggers: ["monorepo", "turborepo", "nx", "workspace", "pnpm workspace", "shared packages"]
---

# Monorepo with Turborepo

## Structure
```
apps/web/   apps/api/
packages/ui/   packages/config/   packages/types/
turbo.json   pnpm-workspace.yaml
```

## turbo.json
```json
{
  "tasks": {
    "build": { "dependsOn": ["^build"], "outputs": [".next/**", "dist/**"] },
    "dev": { "cache": false, "persistent": true },
    "test": { "dependsOn": ["^build"] },
    "lint": {}
  }
}
```

## Cross-reference
```json
{ "dependencies": { "@repo/ui": "workspace:*" } }
```

## Commands
```bash
turbo run build
turbo run dev
turbo run build --filter=web
```

## Rules
- Internal packages: declare `exports` in package.json
- Never import via `../../packages/` — use package name
- `turbo prune --scope=web` for Docker builds
