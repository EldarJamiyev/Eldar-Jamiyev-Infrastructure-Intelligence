# Contributing to EJII

Thank you for considering a contribution to Eldar Jamiyev's Infrastructure Intelligence (EJII). Contributions should improve the reliability, usability, security, or maintainability of the existing infrastructure diagnostics platform.

## Before contributing

- Check existing issues and pull requests to avoid duplicate work.
- Keep changes focused on a specific defect, requirement, or measurable improvement.
- Preserve the existing architecture and working functionality unless a change explicitly requires otherwise.
- Do not introduce mock operations, fabricated telemetry, synthetic measurements presented as real, placeholder AI responses, or success states without evidence.
- Do not weaken authentication, authorization, target validation, auditability, or operational safety controls.
- Treat the bundled agent-skill collections as protected, read-only project assets unless an explicitly approved change requires otherwise.

## Development environment

The continuous-integration workflow currently uses Node.js 22. Install dependencies from the repository root:

```bash
npm ci
```

Run the project checks before opening a pull request:

```bash
npm run lint
node --test --test-concurrency=1 src/core/__tests__/*.test.js
npm test
npm run build
```

The complete regression command may execute environment-dependent integration checks. Report any skipped, unavailable, or failing checks accurately; do not describe an incomplete run as passing.

## Engineering expectations

- Use actual operating-system and network evidence for diagnostic functionality.
- Preserve clear distinctions between observed measurements, inferred conclusions, unavailable data, and simulations.
- Validate network targets and enforce authorization before executing probes or operational actions.
- Keep secrets out of source control, logs, screenshots, test fixtures, and pull-request descriptions.
- Add regression coverage for behavior changes, failure paths, and relevant security boundaries.
- Keep dependencies justified, pinned through the project lockfile, and compatible with the existing stack.
- Update documentation when a change materially affects setup, behavior, configuration, or operational limitations.

## Pull request requirements

A pull request should explain:

1. The problem being addressed and its user or operational impact.
2. The implementation and affected components.
3. The tests and checks actually executed, including their results.
4. Any security, data-handling, compatibility, or deployment implications.
5. Any remaining limitations, skipped checks, or unverified behavior.

Include relevant logs or screenshots when they provide useful evidence, after removing credentials, personal information, and sensitive infrastructure details.

Keep pull requests reviewable and avoid unrelated refactoring or changes to application scope.
