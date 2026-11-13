# Claude Code Configuration & Guidelines — EJII

Welcome to **Eldar Jamiyev Infrastructure Intelligence (EJII)**.

---

## 1. Skill Discovery & Canonical Path

All agent skills are maintained under:
```
.agents/skills/
```

- Canonical Catalog: [`.agents/skills/skills-manifest.json`](file:///.agents/skills/skills-manifest.json)
- Tiered Profiles: [`.agents/skill-profiles.json`](file:///.agents/skill-profiles.json)
- Upstream Lock: [`.agents/skills/upstream-skills-lock.json`](file:///.agents/skills/upstream-skills-lock.json)

To link `.agents/skills` to `.claude/skills` locally:
```powershell
.\scripts\setup-agent-skills.ps1 -Agent claude
```
or on Unix/macOS:
```bash
./scripts/setup-agent-skills.sh --agent claude
```

---

## 2. Priority Core Skills (Always Active)

1. **`gravitas` & `gravitas-highstakes`**: Epistemic checkpoints for irreversible and critical changes.
2. **`doubt-driven-development`**: Prevents speculative assumptions and validates telemetry with empirical probes.
3. **`security-review`**: Validates credentials, secret boundaries, and input sanitization.
4. **`verification-before-completion`**: Demands verifiable evidence before claiming any task is done.
5. **`always-verify-gcp`**: Strict Google Cloud command verification against official schemas.

---

## 3. Strict Operating Invariants

- **Read-Only Runtime Engines**: Never mutate `src/core/skills/read-only-skill-router.js` or `src/core/skills/superpowers-skills-engine.js` into writable routers.
- **Never Overwrite Protected Target Suites**: Never overwrite or delete `gstack`, `gravitas`, `always-verify-gcp`, `database-schema-validator`, or other EJII sovereign suites.
- **Never Rewriting `skills-lock.json`**: Upstream updates are locked exclusively in `.agents/skills/upstream-skills-lock.json`.
- **Zero Hallucinated Telemetry**: Do not fabricate mock hostnames or dummy network addresses in NOC or war room flows.
