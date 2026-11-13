---
name: flutter-dart
description: "Official Flutter/Dart guidance: architecture, responsive layouts, go_router, localization, JSON, testing, layout fixes, static analysis, Dart 3. Use for any Flutter or Dart work (e.g. LinguaLeap)."
---

# flutter-dart — official `flutter/skills` (25 merged into one router)

Source: https://github.com/flutter/skills → `skills/` (dart-* and flutter-*). Originals unmodified in `references/<name>/main.md` (+ `examples/`). The repo's six generic "reidbaker-agent" skills (code-review, grill-with-docs, natural-writing…) were not copied — they overlap installed skills.

| Task | Read |
|---|---|
| Structure the app (UI / logic / data layers) | `flutter-apply-architecture-best-practices` |
| Layout adapts to screen size | `flutter-build-responsive-layout`; overflow / unbounded-constraint errors → `flutter-fix-layout-issues` |
| Navigation, deep links, URL routing | `flutter-setup-declarative-routing` (go_router) |
| **Multi-language UI** (intl, ARB, `generate: true`) | `flutter-setup-localization` |
| Models ↔ JSON | `flutter-implement-json-serialization` |
| REST calls | `flutter-use-http-package` |
| Tests | `flutter-add-widget-test`, `flutter-add-integration-test`, `dart-add-unit-test`, `dart-generate-test-mocks` (mockito), `dart-migrate-to-checks-package`, `dart-collect-coverage` |
| Live widget previews | `flutter-add-widget-preview` |
| Crash / stack trace | `dart-fix-runtime-errors` (uses runtime-errors tool + LSP) |
| Lint, `dart fix`, dependency clashes | `dart-run-static-analysis`, `dart-resolve-package-conflicts` |
| Modern Dart 3 | `dart-use-pattern-matching`, `dart-use-primary-constructors`, `dart-use-path-package` |
| Docs / dartdoc | `dart-write-documentation`, `dart-use-doc-examples` |
| Native interop | `dart-setup-ffi-assets`, `dart-use-ffigen` |
| Dart command-line tools | `dart-build-cli-app` |

## Local rules
- LinguaLeap (`C:\Claude\lingualeap\`): check `pubspec.yaml` Flutter/Dart versions first; skill advice targets current stable — adapt, don't blindly upgrade.
- Windows: prefer `flutter`/`dart` from PowerShell; builds for iOS need macOS (not available) — Android APK and Windows desktop only.
- Run `flutter analyze` and the existing 49 tests after changes; keep files < 500 lines (CLAUDE.md).
- Dart MCP/LSP tools referenced by some skills are optional; fall back to CLI (`dart analyze`, `flutter test`).
- Finish UI work with `ui-quality` (a11y: semantics labels, 48dp targets).
