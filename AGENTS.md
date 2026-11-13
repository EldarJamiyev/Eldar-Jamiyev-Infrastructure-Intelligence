# EJII Agent Architecture & Skills Ecosystem Standards

This document establishes canonical operational rules, skill routing conventions, and safety boundaries for all AI coding agents (Claude Code, Cursor IDE, OpenAI Codex, and Google Antigravity) working within the **Eldar Jamiyev Infrastructure Intelligence (EJII)** repository.

---

## 1. Canonical Skill Ecosystem Directory

All standardized AI Agent Skills reside under the canonical project-level directory:
```
.agents/skills/<skill-name>/SKILL.md
```

- **Total Cataloged Packages**: 986 packages
  - **Core Infrastructure & SRE**: 52 packages
  - **Cybersecurity & DevSecOps**: 15 packages
  - **Google Cloud & BigQuery**: 52 packages
  - **Backend & Cloud Native**: 24 packages
  - **Harness Engineering & Multi-Agent**: 22 packages
  - **UI/UX & Design Systems**: 38 packages
  - **Mobile & Scientific Workflows**: 80 packages
- **Tiered Skill Profiles Definition**: [`.agents/skill-profiles.json`](file:///.agents/skill-profiles.json)
- **Upstream Cryptographic Lockfile**: [`.agents/skills/upstream-skills-lock.json`](file:///.agents/skills/upstream-skills-lock.json)
- **Detailed Overlap & Security Report**: [`docs/skills-migration/overlap-report.json`](file:///docs/skills-migration/overlap-report.json)

---

## 2. Invariant & Governance Rules (Strict Enforcement)

1. **Strict Read-Only Runtime Contract**:
   `src/core/skills/read-only-skill-router.js` and `src/core/skills/superpowers-skills-engine.js` are strictly read-only engines. They enforce zero runtime mutation, TOCTOU protection, and symlink containment. Never weaken these boundaries.
2. **Non-Destructive Workflows**:
   Never delete existing skill directories or overwrite locally modified packages (`gstack`, `gravitas`, `always-verify-gcp`, `doubt-driven-development`).
3. **No Arbitrary Third-Party Script Execution**:
   Scripts inside `.agents/skills/*/scripts/` are untrusted third-party assets unless explicitly reviewed. Never execute untrusted scripts during migration or CI bootstrap.
4. **Context Window Protection**:
   Do not preload hundreds of skill manifests into conversation context. Follow the 4-tier routing profile:
   - **Tier 0 (Core Governance)**: Always active (`gravitas`, `doubt-driven-development`, `security-review`, `verification-before-completion`).
   - **Tier 1 (Infrastructure Core)**: High-priority networking, SRE, and cloud infrastructure skills.
   - **Tier 2 (On-Demand)**: Loaded when working on frontend, mobile, or science tasks.
   - **Tier 3 (Dormant)**: Searchable in catalog but only loaded upon explicit request.

---

## 3. Harness Setup & Interoperability

Use the repository integration scripts to establish symlinks or references for your preferred harness:

- **PowerShell (Windows)**:
  ```powershell
  .\scripts\setup-agent-skills.ps1 -Agent all
  ```
- **Bash (macOS / Linux / WSL)**:
  ```bash
  ./scripts/setup-agent-skills.sh --agent all
  ```

---

## 4. Multi-Agent Discovery API

Any agent or runtime service can dynamically query the catalog in read-only mode:

```javascript
const { readOnlySkillCatalog } = require('./src/core/skills/read-only-skill-router');

// Query by keyword or category
const results = readOnlySkillCatalog.searchEcosystemCatalog('kubernetes network', { limit: 5 });

// Intelligent task routing
const route = readOnlySkillCatalog.routeTaskToUniversalSkills('diagnose packet drop on gcp vpc');
console.log(route.selectedSkills);
```
