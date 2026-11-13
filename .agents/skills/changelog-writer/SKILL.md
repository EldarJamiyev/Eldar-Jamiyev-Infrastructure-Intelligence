---
name: changelog-writer
description: Conventional commits to changelog, semver versioning, release notes, GitHub release automation
metadata:
  type: skill
  triggers: ["changelog", "release notes", "semver", "conventional commits", "version bump", "release"]
---

# Changelog + Release Notes

## Conventional commit format
```
feat: add user authentication
fix: resolve memory leak in WebSocket handler
feat!: change API response shape (BREAKING CHANGE)
docs: update installation guide
chore: upgrade dependencies
```

## Semver rules
- `feat` → minor bump (1.1.0)
- `fix`, `docs`, `chore` → patch (1.0.1)
- `feat!` or `BREAKING CHANGE:` footer → major (2.0.0)

## CHANGELOG.md format
```markdown
## [2.1.0] - 2026-11-07
### Added
- User authentication with OAuth2

### Fixed
- Memory leak in WebSocket connection handler

### Breaking Changes
- API response now wraps data in `{ data: ... }` envelope
```

## Automate
```bash
# standard-version deprecated (2022). Alternatives:
npx release-it              # popular, actively maintained
npx release-it --dry-run

# or Changesets (monorepo-friendly):
npx changeset               # create changeset
npx changeset version       # bump versions
npx changeset publish       # publish + tag
```

## GitHub Release
```yaml
- uses: softprops/action-gh-release@v1
  with:
    body_path: CHANGELOG.md
    files: dist/*.zip
```
