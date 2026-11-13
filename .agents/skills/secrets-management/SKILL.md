---
name: secrets-management
description: .env audit, secret rotation, leaked key detection + revoke, CI/CD secrets
metadata:
  type: skill
  triggers: ["secrets", "env", "api key", "secret rotation", "leaked", "credential"]
---

# Secrets Management

## Never commit secrets
```bash
# Install gitleaks
winget install zricethezav.gitleaks
gitleaks detect --source . --verbose
```

## .env best practices
```bash
# .env (gitignored)
DATABASE_URL=postgres://localhost/mydb
API_KEY=sk-...

# .env.example (committed)
DATABASE_URL=
API_KEY=
```

## Secret rotation (dual-key pattern)
```typescript
const validKeys = [process.env.API_KEY_NEW, process.env.API_KEY_OLD].filter(Boolean);

function validateApiKey(key: string): boolean {
  return validKeys.some(valid => timingSafeEqual(Buffer.from(key), Buffer.from(valid!)));
}
```

## GitHub Actions
```yaml
env:
  DATABASE_URL: ${{ secrets.DATABASE_URL }}  # never log these
```

## If key leaked
1. Revoke immediately at provider
2. Rotate all keys in that environment
3. Check audit logs for unauthorized usage
4. `git filter-repo` to remove from history
5. Force-push + notify all collaborators to re-clone
