'use strict';

/**
 * Universal Agent Skills Ecosystem Migration, Integrity & Interoperability Verification Suite
 *
 * Validates:
 * 1. Upstream source pinning (commit 546f9c2dc424fdccb6bdae5a60b44f4785a0aeb5).
 * 2. Non-destructive preservation of existing EJII packages (gstack, gravitas, always-verify-gcp).
 * 3. Root skills-lock.json integrity.
 * 4. Comprehensive manifest schema, SHA-256 hashing, and license classification.
 * 5. Tiered context profiles (Tier 0 through Tier 3) in .agents/skill-profiles.json.
 * 6. Read-only programmatic discovery & multi-agent routing engines.
 * 7. Security quarantine enforcement (excluding quarantined packages from execution).
 * 8. Cross-platform harness setup tooling.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const { readOnlySkillCatalog } = require('../src/core/skills/read-only-skill-router');
const { superpowersSkillsEngine } = require('../src/core/skills/superpowers-skills-engine');

const REPO_ROOT = path.resolve(__dirname, '..');
const CANONICAL_SKILLS_DIR = path.join(REPO_ROOT, '.agents', 'skills');
const MANIFEST_PATH = path.join(CANONICAL_SKILLS_DIR, 'skills-manifest.json');
const UPSTREAM_LOCK_PATH = path.join(CANONICAL_SKILLS_DIR, 'upstream-skills-lock.json');
const PROFILES_PATH = path.join(REPO_ROOT, '.agents', 'skill-profiles.json');
const OVERLAP_REPORT_PATH = path.join(REPO_ROOT, 'docs', 'skills-migration', 'overlap-report.json');

describe('EJII Universal Agent Skills Ecosystem Migration & Governance Suite', () => {
  it('1. verifies upstream source pinning and upstream-skills-lock.json metadata', () => {
    assert.ok(fs.existsSync(UPSTREAM_LOCK_PATH), 'upstream-skills-lock.json must exist');
    const lock = JSON.parse(fs.readFileSync(UPSTREAM_LOCK_PATH, 'utf8'));

    assert.equal(lock.version, 1);
    assert.equal(lock.source.repository, 'https://github.com/shahinkarimov/claude-skills.git');
    assert.equal(lock.source.commit, '546f9c2dc424fdccb6bdae5a60b44f4785a0aeb5');
    assert.equal(lock.source.tree, '2eb092a0ecbc2f494c66a6eee3ae4b97b2173e4e');
    assert.equal(lock.source.branch, 'master');
    assert.equal(lock.totalLockedSkills, 912);
  });

  it('2. verifies non-destructive preservation of existing sovereign EJII suites (gstack, gravitas, always-verify-gcp)', () => {
    const protectedSuites = [
      'gstack',
      'gravitas',
      'gravitas-highstakes',
      'gravitas-typescript',
      'always-verify-gcp',
      'doubt-driven-development',
      'constraint-driven-development',
      'data-throughput-accelerator',
      'database-schema-validator'
    ];

    for (const suite of protectedSuites) {
      const suiteDir = path.join(CANONICAL_SKILLS_DIR, suite);
      assert.ok(fs.existsSync(suiteDir), `Protected suite directory must exist: ${suite}`);
      assert.ok(fs.existsSync(path.join(suiteDir, 'SKILL.md')), `Protected suite SKILL.md must exist: ${suite}`);
    }

    // Verify gstack has its complete multi-workflow tree (at least 60 nested workflows)
    const gstackDirs = fs
      .readdirSync(path.join(CANONICAL_SKILLS_DIR, 'gstack'), { withFileTypes: true })
      .filter((d) => d.isDirectory() && fs.existsSync(path.join(CANONICAL_SKILLS_DIR, 'gstack', d.name, 'SKILL.md')));
    assert.ok(gstackDirs.length >= 60, `gstack must have retained at least 60 nested workflows, found ${gstackDirs.length}`);
  });

  it('3. verifies skills-manifest.json schema, full 986-package inventory, and valid licensing', () => {
    assert.ok(fs.existsSync(MANIFEST_PATH), 'skills-manifest.json must exist');
    const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf8'));

    assert.equal(manifest.length, 986, 'Must contain exactly 986 cataloged packages');

    const validTiers = new Set([
      'TIER_0_CORE_GOVERNANCE',
      'TIER_1_INFRASTRUCTURE_CORE',
      'TIER_2_ON_DEMAND',
      'TIER_3_DORMANT_EXPLICIT_INVOCATION'
    ]);

    const validLicenseStatuses = new Set([
      'LICENSED_APPROVED',
      'LICENSED_WITH_ATTRIBUTION',
      'LICENSE_REVIEW_REQUIRED',
      'PERMISSION_REQUIRED'
    ]);

    for (const pkg of manifest) {
      assert.ok(pkg.name, 'Every package must have a name');
      assert.ok(pkg.category, `Package ${pkg.name} must have a category`);
      assert.ok(validTiers.has(pkg.routing?.tier), `Package ${pkg.name} has invalid tier: ${pkg.routing?.tier}`);
      assert.ok(
        validLicenseStatuses.has(pkg.license?.status),
        `Package ${pkg.name} has invalid license status: ${pkg.license?.status}`
      );
      assert.ok(pkg.integrity?.sha256, `Package ${pkg.name} must have integrity sha256`);
    }
  });

  it('4. verifies tiered skill profiles in .agents/skill-profiles.json', () => {
    assert.ok(fs.existsSync(PROFILES_PATH), '.agents/skill-profiles.json must exist');
    const profiles = JSON.parse(fs.readFileSync(PROFILES_PATH, 'utf8'));

    assert.equal(profiles.version, 1);
    assert.ok(profiles.tiers.tier0_core_governance.skills.length >= 8);
    assert.ok(profiles.tiers.tier1_infrastructure_core.skills.length >= 100);
    assert.ok(profiles.tiers.tier2_on_demand.skills.length >= 150);
    assert.ok(profiles.tiers.tier3_dormant_explicit.skills.length >= 300);

    // Verify key Tier 0 governance skills
    const tier0 = profiles.tiers.tier0_core_governance.skills;
    assert.ok(tier0.includes('gravitas'));
    assert.ok(tier0.includes('gravitas-highstakes'));
    assert.ok(tier0.includes('doubt-driven-development'));
    assert.ok(tier0.includes('security-review'));
    assert.ok(tier0.includes('verification-before-completion'));
  });

  it('5. verifies overlap report contains comprehensive migration statistics', () => {
    assert.ok(fs.existsSync(OVERLAP_REPORT_PATH), 'overlap-report.json must exist');
    const report = JSON.parse(fs.readFileSync(OVERLAP_REPORT_PATH, 'utf8'));

    assert.equal(report.summary.totalCataloged, 986);
    assert.equal(report.summary.newPackages, 861);
    assert.equal(report.summary.targetOnlyPackages, 73);
    assert.equal(report.summary.targetRicherPackages, 5);
    assert.equal(report.summary.sourceDivergentPackages, 32);
    assert.equal(report.summary.securityQuarantinedPackages, 14);

    // Verify conflicts diff files were generated
    const conflictsDir = path.join(REPO_ROOT, 'docs', 'skills-migration', 'conflicts');
    assert.ok(fs.existsSync(conflictsDir), 'conflicts directory must exist');
    const diffFiles = fs.readdirSync(conflictsDir).filter((f) => f.endsWith('.diff'));
    assert.ok(diffFiles.length >= 30, 'Must have generated conflict diffs for divergent packages');
  });

  it('6. verifies read-only search and discovery API on ReadOnlySkillCatalog', () => {
    const searchRes = readOnlySkillCatalog.searchEcosystemCatalog('kubernetes network', { limit: 10 });
    assert.ok(searchRes.totalCataloged === 986);
    assert.ok(searchRes.matchedCount > 0);
    assert.ok(searchRes.results.length <= 10);
    assert.equal(searchRes.results[0].name, 'kubernetes');

    // Category filter
    const gcpSkills = readOnlySkillCatalog.searchEcosystemCatalog('', {
      category: 'GOOGLE_CLOUD_AND_DATA_PLATFORMS',
      limit: 50
    });
    assert.ok(gcpSkills.results.length >= 30);
    for (const s of gcpSkills.results) {
      assert.equal(s.category, 'GOOGLE_CLOUD_AND_DATA_PLATFORMS');
    }
  });

  it('7. verifies quarantine security enforcement: quarantined packages are excluded from operational execution', () => {
    const defaultSearch = readOnlySkillCatalog.searchEcosystemCatalog('tob-code-audit');
    const defaultMatch = defaultSearch.results.find((s) => s.name === 'tob-code-audit');
    assert.equal(defaultMatch, undefined, 'Quarantined package must be excluded by default');

    // Explicit request with excludeQuarantined: false
    const auditSearch = readOnlySkillCatalog.searchEcosystemCatalog('tob-code-audit', { excludeQuarantined: false });
    const auditMatch = auditSearch.results.find((s) => s.name === 'tob-code-audit');
    assert.ok(auditMatch, 'Quarantined package should be visible when explicit audit query is made');
    assert.equal(auditMatch.security?.status, 'SECURITY_QUARANTINED');
  });

  it('8. verifies multi-agent task routing with token budgeting', () => {
    const route = readOnlySkillCatalog.routeTaskToUniversalSkills(
      'diagnose high packet loss and bgp route flapping on gcp vpc',
      { maxContextTokens: 1000 }
    );

    assert.ok(route.allocatedTokens <= 1000);
    assert.ok(route.selectedSkills.length >= 1);
    assert.ok(route.agentGuidance.claude);
    assert.ok(route.agentGuidance.cursor);
    assert.ok(route.agentGuidance.codex);
    assert.ok(route.agentGuidance.antigravity);
  });

  it('9. verifies SuperpowersSkillsEngine delegates ecosystem discovery seamlessly', () => {
    const search = superpowersSkillsEngine.searchEcosystemCatalog('bigquery', { limit: 5 });
    assert.ok(search.matchedCount > 0);
    assert.ok(search.results.some((s) => s.name.includes('bigquery')));

    const profiles = superpowersSkillsEngine.getTieredSkillProfiles();
    assert.ok(profiles.tiers.tier0_core_governance);

    const route = superpowersSkillsEngine.routeTaskToUniversalSkills('analyze audit logs in bigquery');
    assert.ok(route.selectedSkills.length >= 1);
  });

  it('10. verifies cross-harness setup scripts and root documentation exist and are readable', () => {
    assert.ok(fs.existsSync(path.join(REPO_ROOT, 'scripts', 'setup-agent-skills.ps1')));
    assert.ok(fs.existsSync(path.join(REPO_ROOT, 'scripts', 'setup-agent-skills.sh')));
    assert.ok(fs.existsSync(path.join(REPO_ROOT, 'AGENTS.md')));
    assert.ok(fs.existsSync(path.join(REPO_ROOT, 'CLAUDE.md')));
    assert.ok(fs.existsSync(path.join(REPO_ROOT, '.cursor', 'rules', 'skills.mdc')));
    assert.ok(fs.existsSync(path.join(CANONICAL_SKILLS_DIR, 'README.md')));

    const agentsMd = fs.readFileSync(path.join(REPO_ROOT, 'AGENTS.md'), 'utf8');
    assert.ok(agentsMd.includes('.agents/skills'));
    assert.ok(agentsMd.includes('986'));

    const claudeMd = fs.readFileSync(path.join(REPO_ROOT, 'CLAUDE.md'), 'utf8');
    assert.ok(claudeMd.includes('.agents/skills'));

    const skillsReadme = fs.readFileSync(path.join(CANONICAL_SKILLS_DIR, 'README.md'), 'utf8');
    assert.ok(skillsReadme.includes('Infrastructure Intelligence Core Stack'));
    assert.ok(skillsReadme.includes('986'));
  });
});
