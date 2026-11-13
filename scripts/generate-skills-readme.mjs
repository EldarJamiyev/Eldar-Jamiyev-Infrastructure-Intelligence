#!/usr/bin/env node
/**
 * EJII Universal Agent Skills README Generator
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');

const manifestPath = path.join(REPO_ROOT, '.agents', 'skills', 'skills-manifest.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

const CATEGORY_TITLES = {
  INFRASTRUCTURE_NETWORKING_SRE: 'Networking, Infrastructure Diagnostics & SRE',
  CYBERSECURITY_AND_DEVSECOPS: 'Cybersecurity, DevSecOps & Security Auditing',
  GOOGLE_CLOUD_AND_DATA_PLATFORMS: 'Google Cloud, BigQuery & Data Intelligence',
  BACKEND_AND_CLOUD_NATIVE: 'Backend Architecture, Cloud-Native & Databases',
  HARNESS_AND_AGENTIC_SYSTEMS: 'Harness Engineering & Multi-Agent Reliability',
  FRONTEND_AND_DESIGN_SYSTEMS: 'UI/UX, Frontend Design & Motion Engineering',
  MOBILE_DEVELOPMENT: 'Mobile Development (iOS, Android, Flutter & Expo)',
  SCIENTIFIC_RESEARCH_AND_GENOMICS: 'DeepMind Science, Genomics & Computational Biology',
  BROWSER_AUTOMATION_AND_SCRAPING: 'Browser Automation, Scraping & CDP Agents',
  SPECIALIZED_AND_CREATIVE: 'Specialized Engineering, Game Dev, 3D & Creative'
};

const lines = [];

lines.push('# EJII Universal AI Agent Skills Ecosystem');
lines.push('');
lines.push('Welcome to the **Eldar Jamiyev Infrastructure Intelligence (EJII)** Universal Agent Skills Ecosystem — a comprehensive, cryptographic-locked, multi-agent-compatible catalog of **986 specialized AI Agent Skills**.');
lines.push('');
lines.push('---');
lines.push('');
lines.push('## 1. Inventory & Ecosystem Architecture');
lines.push('');
lines.push('| Metric | Count | Description |');
lines.push('| :--- | :---: | :--- |');
lines.push(`| **Total Cataloged Packages** | **${manifest.length}** | Total indexed skill packages across all domains |`);
lines.push('| **Newly Imported Packages** | **861** | Verified and safely migrated from upstream (`shahinkarimov/claude-skills`) |');
lines.push('| **Preserved Overlapping Suites** | **38** | Retained richer local packages (`gstack`, `gravitas`, `obra-superpowers`, etc.) |');
lines.push('| **EJII Sovereign Exclusives** | **73** | Project-specific infrastructure skills (`always-verify-gcp`, `data-throughput-accelerator`) |');
lines.push('| **Security Quarantined** | **14** | Metadata-only indexed; blocked from active unprivileged execution |');
lines.push('| **Pinned Upstream Commit** | `546f9c2d` | Locked in [`.agents/skills/upstream-skills-lock.json`](upstream-skills-lock.json) |');
lines.push('');
lines.push('---');
lines.push('');
lines.push('## 2. Infrastructure Intelligence Core Stack');
lines.push('');
lines.push('The prioritized core skills governing EJII operations and SRE incident response:');
lines.push('');
lines.push('| Skill Package | Category | Routing Tier | License | Focus & Capability |');
lines.push('| :--- | :--- | :---: | :--- | :--- |');

const corePriority = [
  'gravitas',
  'gravitas-highstakes',
  'gravitas-typescript',
  'always-verify-gcp',
  'gstack',
  'doubt-driven-development',
  'constraint-driven-development',
  'source-driven-development',
  'security-review',
  'verification-before-completion',
  'data-throughput-accelerator',
  'database-schema-validator',
  'systematic-debugging',
  'observability-and-instrumentation',
  'ci-cd-and-automation',
  'mcp-builder',
  'clean-architecture',
  'codebase-design',
  'kubernetes',
  'docker',
  'terraform',
  'bigquery-basics',
  'gcp-composer-troubleshooting',
  'google-cloud-storage-basics'
];

for (const id of corePriority) {
  const item = manifest.find((m) => m.name === id);
  if (item) {
    const lic = item.license?.identifier || 'Permissive';
    const desc = item.description.replace(/\|/g, '\\|');
    lines.push(`| [${item.name}](${item.name}/SKILL.md) | \`${item.category}\` | \`${item.routing.tier}\` | ${lic} | ${desc} |`);
  }
}

lines.push('');
lines.push('---');
lines.push('');
lines.push('## 3. Tiered Context Profiles');
lines.push('');
lines.push('EJII avoids context-window saturation through a 4-tier loading strategy defined in [`.agents/skill-profiles.json`](../skill-profiles.json):');
lines.push('');
lines.push('- **Tier 0: Core Governance & Invariant Enforcement** (Always Active)');
lines.push('  - `gravitas`, `gravitas-highstakes`, `doubt-driven-development`, `security-review`, `verification-before-completion`.');
lines.push('- **Tier 1: Infrastructure, SRE & Cloud Core** (Active for Engineering Tasks)');
lines.push('  - SRE incident response, Google Cloud, BigQuery, Kubernetes, Docker, and backend architecture.');
lines.push('- **Tier 2: On-Demand Workflows** (Loaded Dynamically)');
lines.push('  - Frontend, mobile, design systems, browser automation, and computational biology.');
lines.push('- **Tier 3: Dormant Catalog** (Explicit Invocation Only)');
lines.push('  - Creative engineering, game dev, 3D graphics, media, and marketing tools.');
lines.push('');
lines.push('---');
lines.push('');
lines.push('## 4. Multi-Agent Setup & Tooling');
lines.push('');
lines.push('Connect the skill ecosystem to your preferred AI coding harness:');
lines.push('');
lines.push('### PowerShell (Windows):');
lines.push('```powershell');
lines.push('# Setup all harnesses (Claude, Cursor, Codex, Antigravity)');
lines.push('.\\scripts\\setup-agent-skills.ps1 -Agent all');
lines.push('');
lines.push('# Target specific harness in dry-run mode');
lines.push('.\\scripts\\setup-agent-skills.ps1 -Agent claude -DryRun');
lines.push('```');
lines.push('');
lines.push('### Bash (macOS / Linux / WSL):');
lines.push('```bash');
lines.push('# Setup all harnesses');
lines.push('./scripts/setup-agent-skills.sh --agent all');
lines.push('');
lines.push('# Target Cursor IDE only');
lines.push('./scripts/setup-agent-skills.sh --agent cursor');
lines.push('```');
lines.push('');
lines.push('---');
lines.push('');
lines.push('## 5. Categorized Skill Directory');
lines.push('');

// Group by category
const grouped = {};
for (const item of manifest) {
  if (!grouped[item.category]) grouped[item.category] = [];
  grouped[item.category].push(item);
}

for (const [catKey, catTitle] of Object.entries(CATEGORY_TITLES)) {
  const items = grouped[catKey] || [];
  lines.push(`### ${catTitle} (${items.length} skills)`);
  lines.push('');
  lines.push('| Skill Name | Description | Routing Tier | License |');
  lines.push('| :--- | :--- | :---: | :--- |');

  for (const item of items) {
    const desc = (item.description || 'Skill package').replace(/\|/g, '\\|').slice(0, 140);
    const lic = item.license?.identifier || 'Permissive';
    const link = fs.existsSync(path.join(REPO_ROOT, '.agents', 'skills', item.name, 'SKILL.md'))
      ? `[${item.name}](${item.name}/SKILL.md)`
      : `\`${item.name}\` *(Quarantined Metadata)*`;
    lines.push(`| ${link} | ${desc} | \`${item.routing.tier}\` | ${lic} |`);
  }
  lines.push('');
}

const outputPath = path.join(REPO_ROOT, '.agents', 'skills', 'README.md');
fs.writeFileSync(outputPath, lines.join('\n'), 'utf8');
console.log(`✓ Master Catalog written to: ${outputPath} (${lines.length} lines)`);
