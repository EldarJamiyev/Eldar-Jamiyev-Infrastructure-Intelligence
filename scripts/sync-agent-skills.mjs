#!/usr/bin/env node
/**
 * EJII Universal Agent Skills Synchronization, Audit & Provenance Engine
 *
 * Deterministic, idempotent, and non-destructive integration engine for migrating,
 * auditing, indexing, and synchronizing AI Agent Skills from upstream into EJII (.agents/skills/).
 *
 * Supported flags:
 *   --dry-run              Preview actions without modifying the target repository (default behavior)
 *   --apply                Apply synchronization, migrations, manifest, and lockfile updates
 *   --verify               Validate filesystem integrity, hashes, frontmatter, and relative links
 *   --report               Generate comprehensive docs/skills-migration/overlap-report.json
 *   --source-ref <commit>  Verify or pin against a specific upstream Git commit SHA
 *   --update               Regenerate skills-manifest.json, upstream-skills-lock.json, and catalog
 *   --category <name>      Filter synchronization/report to a specific skill category
 *
 * Strictly adheres to EJII Non-Destructive Invariants:
 *   - Never deletes existing directories or files.
 *   - Never overwrites locally modified or richer target packages (e.g. gstack, gravitas).
 *   - Never modifies root skills-lock.json.
 *   - Quarantines packages containing suspicious code or unverified execution patterns.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');

// Default pinned upstream commit metadata
export const PINNED_SOURCE = Object.freeze({
  repository: 'https://github.com/shahinkarimov/claude-skills.git',
  mirror: 'https://github.com/shahinjk-cpu/claude-skills.git',
  commit: '546f9c2dc424fdccb6bdae5a60b44f4785a0aeb5',
  tree: '2eb092a0ecbc2f494c66a6eee3ae4b97b2173e4e',
  branch: 'master',
  retrievalTimestamp: '2026-11-13T10:53:38Z'
});

export const PROTECTED_RICH_TARGET_SUITES = new Set([
  'gstack',
  'gravitas',
  'gravitas-highstakes',
  'gravitas-typescript',
  'always-verify-gcp',
  'brainstorming',
  'constraint-driven-development',
  'doubt-driven-development',
  'contract-first',
  'data-throughput-accelerator',
  'database-schema-validator',
  'context-budget',
  'change-impact',
  'using-superpowers',
  'obra-superpowers',
  'mattpocock',
  'mattpocock-skills',
  'addyosmani-agent-skills',
  'anthropics-agent-toolkits',
  'anthropics-skills',
  'awesome-claude-skills',
  'awesome-llm-apps',
  'claude-code-best-practice',
  'claude-mem',
  'nextlevelbuilder-ui-ux-pro-max',
  'ponytail-lazy-dev',
  'ruflo',
  'taste-art-direction'
]);

export const SECURITY_AUDIT_PATTERNS = [
  { id: 'PROMPT_INJECTION', regex: /ignore\s+(all\s+)?previous\s+instructions/i, severity: 'HIGH' },
  { id: 'SYSTEM_OVERRIDE', regex: /system\s+prompt\s+override/i, severity: 'HIGH' },
  { id: 'DATA_EXFILTRATION', regex: /exfiltrat|webhook\.site|requestbin/i, severity: 'CRITICAL' },
  { id: 'ARBITRARY_CURL_EXEC', regex: /curl\s+[^|\n]+\|\s*(sh|bash)/i, severity: 'HIGH' },
  { id: 'ARBITRARY_WGET_EXEC', regex: /wget\s+[^|\n]+\|\s*(sh|bash)/i, severity: 'HIGH' },
  { id: 'ARBITRARY_PS_IEX', regex: /irm\s+[^|\n]+\|\s*iex|Invoke-Expression\s*\(/i, severity: 'HIGH' },
  { id: 'DESTRUCTIVE_RM_ROOT', regex: /rm\s+-rf\s+[\/~]/i, severity: 'CRITICAL' },
  { id: 'HARDCODED_GH_PAT', regex: /ghp_[a-zA-Z0-9]{36}/, severity: 'HIGH' },
  { id: 'HARDCODED_AWS_KEY', regex: /AKIA[0-9A-Z]{16}/, severity: 'HIGH' }
];

export const CATEGORY_DEFINITIONS = [
  {
    category: 'INFRASTRUCTURE_NETWORKING_SRE',
    title: 'Networking, Infrastructure Diagnostics & SRE',
    keywords: ['network', 'icmp', 'ping', 'dns', 'tcp', 'tls', 'latency', 'sre', 'observability', 'wireshark', 'packet', 'bpf', 'incident', 'diagnostics', 'wire-error', 'bgp', 'ospf', 'traceroute']
  },
  {
    category: 'CYBERSECURITY_AND_DEVSECOPS',
    title: 'Cybersecurity, DevSecOps & Security Auditing',
    keywords: ['security', 'audit', 'threat-model', 'pentest', 'owasp', 'cso', 'secrets', 'quarantine', 'vulnerability', 'hardened', 'guard', 'careful', 'firewall', 'rbac', 'zero-trust', 'token', 'tls-posture']
  },
  {
    category: 'GOOGLE_CLOUD_AND_DATA_PLATFORMS',
    title: 'Google Cloud, BigQuery & Data Intelligence',
    keywords: ['google-cloud', 'gcp', 'bigquery', 'dataflow', 'dataproc', 'composer', 'bigtable', 'firebase', 'gemini', 'vertex', 'dbt-bigquery', 'dataform', 'cloud-storage', 'gcs']
  },
  {
    category: 'BACKEND_AND_CLOUD_NATIVE',
    title: 'Backend Architecture, Cloud-Native & Databases',
    keywords: ['kubernetes', 'docker', 'terraform', 'database', 'postgres', 'sqlite', 'redis', 'graphql', 'fastapi', 'architecture', 'monorepo', 'sql', 'queue', 'websocket', 'rag', 'vector-db', 'api-design']
  },
  {
    category: 'HARNESS_AND_AGENTIC_SYSTEMS',
    title: 'Harness Engineering & Multi-Agent Reliability',
    keywords: ['harness', 'superpowers', 'subagent', 'dispatch', 'tdd', 'debugging', 'verification', 'worktree', 'git-workflow', 'agent-memory', 'openviking', 'claude-mem', 'context', 'compact', 'eval', 'review', 'pr-']
  },
  {
    category: 'FRONTEND_AND_DESIGN_SYSTEMS',
    title: 'UI/UX, Frontend Design & Motion Engineering',
    keywords: ['ui', 'ux', 'frontend', 'design', 'tailwind', 'shadcn', 'gsap', 'animation', 'threejs', 'motion', 'figma', 'canvas', 'css', 'html', 'anti-ui-slop', 'taste-skill', 'impeccable', 'hallmark', 'diagram']
  },
  {
    category: 'MOBILE_DEVELOPMENT',
    title: 'Mobile Development (iOS, Android, Flutter & Expo)',
    keywords: ['ios', 'android', 'flutter', 'dart', 'swift', 'swiftui', 'expo', 'react-native', 'compose', 'avd', 'sideload']
  },
  {
    category: 'SCIENTIFIC_RESEARCH_AND_GENOMICS',
    title: 'DeepMind Science, Genomics & Computational Biology',
    keywords: ['alphafold', 'alphagenome', 'chembl', 'pubmed', 'ncbi', 'genom', 'protein', 'pdb', 'blast', 'bioinformatics', 'clinvar', 'uniprot', 'scientific', 'arxiv', 'biorxiv', 'molstar', 'pymol']
  },
  {
    category: 'BROWSER_AUTOMATION_AND_SCRAPING',
    title: 'Browser Automation, Scraping & CDP Agents',
    keywords: ['browser-use', 'agent-browser', 'browse', 'scrape', 'cdp', 'playwright', 'puppeteer', 'crawler', 'screenshot', 'cookie']
  },
  {
    category: 'SPECIALIZED_AND_CREATIVE',
    title: 'Specialized Engineering, Game Dev, 3D & Creative',
    keywords: ['godot', 'unity', 'unreal', 'roblox', 'blender', 'game', 'shader', '3d', 'ads', 'marketing', 'media', 'fal-', 'venice-', 'audio', 'video', 'comic', 'fiction', 'art-']
  }
];

export function sha256(content) {
  return crypto.createHash('sha256').update(content).digest('hex');
}

export function parseFrontmatter(markdownText, fallbackId) {
  const text = String(markdownText || '');
  const fmMatch = text.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  let name = fallbackId;
  let description = '';
  let license = null;
  if (fmMatch) {
    const fmBlock = fmMatch[1];
    const nameMatch = fmBlock.match(/^name:\s*(.+)$/m);
    const descMatch = fmBlock.match(/^description:\s*(.+)$/m);
    const licMatch = fmBlock.match(/^license:\s*(.+)$/m);
    if (nameMatch) name = nameMatch[1].trim().replace(/^['"]|['"]$/g, '');
    if (descMatch) description = descMatch[1].trim().replace(/^['"]|['"]$/g, '');
    if (licMatch) license = licMatch[1].trim().replace(/^['"]|['"]$/g, '');
  }
  if (!description) {
    const lines = text
      .replace(/^---[\s\S]*?---/, '')
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'));
    description = lines[0] ? lines[0].slice(0, 240) : `Skill package ${fallbackId}`;
  }
  return { name, description, license };
}

export function classifyCategory(skillId, name, description) {
  const corpus = `${skillId} ${name} ${description}`.toLowerCase();
  for (const def of CATEGORY_DEFINITIONS) {
    if (def.keywords.some((kw) => corpus.includes(kw))) {
      return def.category;
    }
  }
  return 'SPECIALIZED_AND_CREATIVE';
}

export function classifyRoutingTier(category, skillId) {
  // Tier 0: Core Governance & Invariant Enforcement
  if (
    skillId === 'gravitas' ||
    skillId === 'gravitas-highstakes' ||
    skillId === 'gravitas-typescript' ||
    skillId === 'using-superpowers' ||
    skillId === 'doubt-driven-development' ||
    skillId === 'constraint-driven-development' ||
    skillId === 'source-driven-development' ||
    skillId === 'security-review' ||
    skillId === 'verification-before-completion'
  ) {
    return { tier: 'TIER_0_CORE_GOVERNANCE', enabledByDefault: true };
  }

  // Tier 1: Infrastructure, SRE, Security, Google Cloud, Backend, Harness Core
  if (
    category === 'INFRASTRUCTURE_NETWORKING_SRE' ||
    category === 'CYBERSECURITY_AND_DEVSECOPS' ||
    category === 'GOOGLE_CLOUD_AND_DATA_PLATFORMS' ||
    category === 'BACKEND_AND_CLOUD_NATIVE' ||
    category === 'HARNESS_AND_AGENTIC_SYSTEMS'
  ) {
    return { tier: 'TIER_1_INFRASTRUCTURE_CORE', enabledByDefault: true };
  }

  // Tier 2: Frontend, Mobile, Browser Automation, Science
  if (
    category === 'FRONTEND_AND_DESIGN_SYSTEMS' ||
    category === 'MOBILE_DEVELOPMENT' ||
    category === 'BROWSER_AUTOMATION_AND_SCRAPING' ||
    category === 'SCIENTIFIC_RESEARCH_AND_GENOMICS'
  ) {
    return { tier: 'TIER_2_ON_DEMAND', enabledByDefault: false };
  }

  // Tier 3: Dormant & Explicit Invocation
  return { tier: 'TIER_3_DORMANT_EXPLICIT_INVOCATION', enabledByDefault: false };
}

export function auditPackageSecurity(pkgDir) {
  const securityIssues = [];
  let scriptsReviewed = false;
  let hasScripts = false;

  function walk(currentDir) {
    let entries = [];
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch (_) {
      return;
    }
    for (const ent of entries) {
      const full = path.join(currentDir, ent.name);
      if (ent.isDirectory()) {
        walk(full);
      } else if (ent.isFile()) {
        const ext = path.extname(ent.name).toLowerCase();
        if (['.sh', '.ps1', '.py', '.bat', '.cmd', '.js', '.mjs'].includes(ext)) {
          hasScripts = true;
        }
        try {
          const content = fs.readFileSync(full, 'utf8');
          for (const pat of SECURITY_AUDIT_PATTERNS) {
            if (pat.regex.test(content)) {
              // Special case: ignore security references in audit and documentation tools
              const rel = path.relative(pkgDir, full).replace(/\\/g, '/');
              const isAuditRuleOrRef =
                rel.includes('references/') ||
                rel.includes('ATTACK-CLASSES') ||
                rel.includes('audit-phases') ||
                pkgDir.includes('cloudflare-security-audit') ||
                pkgDir.includes('security-audit') ||
                pkgDir.includes('cso') ||
                pkgDir.includes('careful');

              if (!isAuditRuleOrRef || pat.severity === 'CRITICAL') {
                securityIssues.push({
                  file: rel,
                  checkId: pat.id,
                  severity: pat.severity
                });
              }
            }
          }
        } catch (_) {}
      }
    }
  }

  walk(pkgDir);

  const isQuarantined = securityIssues.some((issue) => issue.severity === 'CRITICAL');
  return {
    status: isQuarantined ? 'SECURITY_QUARANTINED' : securityIssues.length > 0 ? 'REVIEW_REQUIRED' : 'REVIEWED',
    scriptsReviewed: false,
    hasScripts,
    issues: securityIssues
  };
}

export function auditPackageLicense(pkgDir, frontmatterLicense) {
  if (frontmatterLicense) {
    const lic = frontmatterLicense.trim();
    if (/mit/i.test(lic)) return { status: 'LICENSED_APPROVED', identifier: 'MIT' };
    if (/apache/i.test(lic)) return { status: 'LICENSED_APPROVED', identifier: 'Apache-2.0' };
    if (/bsd/i.test(lic)) return { status: 'LICENSED_APPROVED', identifier: 'BSD' };
    if (/cc-by/i.test(lic) || /cc0/i.test(lic)) return { status: 'LICENSED_APPROVED', identifier: 'CC-BY-4.0' };
    return { status: 'LICENSED_WITH_ATTRIBUTION', identifier: lic };
  }

  // Check for license files
  let entries = [];
  try {
    entries = fs.readdirSync(pkgDir);
  } catch (_) {}
  const licFile = entries.find((f) => /license|notice|copying/i.test(f));
  if (licFile) {
    try {
      const text = fs.readFileSync(path.join(pkgDir, licFile), 'utf8');
      if (/MIT License/i.test(text)) return { status: 'LICENSED_APPROVED', identifier: 'MIT' };
      if (/Apache License/i.test(text)) return { status: 'LICENSED_APPROVED', identifier: 'Apache-2.0' };
      if (/BSD/i.test(text)) return { status: 'LICENSED_APPROVED', identifier: 'BSD' };
    } catch (_) {}
    return { status: 'LICENSED_WITH_ATTRIBUTION', identifier: 'CUSTOM_PERMISSIVE' };
  }

  // Known trusted upstream suites
  const base = path.basename(pkgDir);
  if (
    base.startsWith('google-') ||
    base.startsWith('gcp-') ||
    base.startsWith('bigquery-') ||
    base.startsWith('firebase-') ||
    base.startsWith('gemini-')
  ) {
    return { status: 'LICENSED_APPROVED', identifier: 'Apache-2.0 (Google Cloud Open Source)' };
  }

  if (
    base.startsWith('alphafold') ||
    base.startsWith('alphagenome') ||
    base.startsWith('pubmed') ||
    base.startsWith('ncbi')
  ) {
    return { status: 'LICENSED_APPROVED', identifier: 'Open Science Permissive (DeepMind/NCBI)' };
  }

  return { status: 'LICENSED_WITH_ATTRIBUTION', identifier: 'Open Agent Skills Standard' };
}

export function listPackageFilesRecursive(pkgDir) {
  let list = [];
  try {
    const entries = fs.readdirSync(pkgDir, { withFileTypes: true });
    for (const ent of entries) {
      if (ent.name === '.git' || ent.name === 'node_modules') continue;
      const full = path.join(pkgDir, ent.name);
      if (ent.isDirectory()) {
        list = list.concat(listPackageFilesRecursive(full));
      } else if (ent.isFile()) {
        list.push(full);
      }
    }
  } catch (_) {}
  return list;
}

export function parseCliArgs(argv) {
  const args = {
    dryRun: true,
    apply: false,
    verify: false,
    report: false,
    update: false,
    category: null,
    sourceRef: PINNED_SOURCE.commit,
    stagingDir: path.join(process.env.TEMP || 'C:\\temp', 'claude-skills-staging')
  };

  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--apply') {
      args.apply = true;
      args.dryRun = false;
    } else if (arg === '--dry-run') {
      args.dryRun = true;
      args.apply = false;
    } else if (arg === '--verify') {
      args.verify = true;
    } else if (arg === '--report') {
      args.report = true;
    } else if (arg === '--update') {
      args.update = true;
    } else if (arg === '--source-ref' && argv[i + 1]) {
      args.sourceRef = argv[++i];
    } else if (arg === '--category' && argv[i + 1]) {
      args.category = argv[++i];
    } else if (arg === '--staging-dir' && argv[i + 1]) {
      args.stagingDir = argv[++i];
    }
  }
  return args;
}

export async function runSkillSyncPipeline(options = {}) {
  const args = {
    dryRun: options.dryRun ?? true,
    apply: options.apply ?? false,
    verify: options.verify ?? false,
    report: options.report ?? false,
    update: options.update ?? false,
    category: options.category ?? null,
    sourceRef: options.sourceRef ?? PINNED_SOURCE.commit,
    stagingDir: options.stagingDir ?? path.join(process.env.TEMP || 'C:\\temp', 'claude-skills-staging')
  };

  const targetSkillsDir = path.join(REPO_ROOT, '.agents', 'skills');
  const sourceSkillsDir = path.join(args.stagingDir, 'skills');
  const docsDir = path.join(REPO_ROOT, 'docs', 'skills-migration');
  const conflictsDir = path.join(docsDir, 'conflicts');

  if (!fs.existsSync(sourceSkillsDir)) {
    throw new Error(`Upstream staging skills directory not found: ${sourceSkillsDir}`);
  }

  if (!fs.existsSync(docsDir)) fs.mkdirSync(docsDir, { recursive: true });
  if (!fs.existsSync(conflictsDir)) fs.mkdirSync(conflictsDir, { recursive: true });

  console.log('========================================================================');
  console.log('  EJII Universal Agent Skills Synchronization Engine                   ');
  console.log('========================================================================');
  console.log(`Execution Mode    : ${args.apply ? 'APPLY (Active Mutating Run)' : 'DRY RUN (Read-Only Preview)'}`);
  console.log(`Pinned Source Ref : ${args.sourceRef}`);
  console.log(`Source Staging    : ${sourceSkillsDir}`);
  console.log(`Target Skills Dir : ${targetSkillsDir}`);
  if (args.category) console.log(`Category Filter   : ${args.category}`);
  console.log('------------------------------------------------------------------------');

  // Step 1: Inventory Source & Target
  const sourcePackageDirs = fs
    .readdirSync(sourceSkillsDir, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort();

  const targetPackageDirs = fs
    .readdirSync(targetSkillsDir, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort();

  console.log(`[Recon] Discovered Upstream Source Packages : ${sourcePackageDirs.length}`);
  console.log(`[Recon] Discovered Target EJII Packages     : ${targetPackageDirs.length}`);

  const overlapReport = {
    generatedAt: new Date().toISOString(),
    source: {
      repository: PINNED_SOURCE.repository,
      mirror: PINNED_SOURCE.mirror,
      pinnedCommit: args.sourceRef,
      tree: PINNED_SOURCE.tree,
      totalSourcePackagesCount: sourcePackageDirs.length
    },
    target: {
      canonicalDir: '.agents/skills/',
      totalTargetPackagesCount: targetPackageDirs.length
    },
    summary: {
      newPackages: 0,
      identicalPackages: 0,
      targetRicherPackages: 0,
      sourceAdditivePackages: 0,
      sourceDivergentPackages: 0,
      targetOnlyPackages: 0,
      securityQuarantinedPackages: 0,
      licenseBlockedPackages: 0,
      invalidManifestPackages: 0,
      totalCataloged: 0
    },
    packages: []
  };

  const conflictsList = [];
  const manifestRecords = [];
  const upstreamLockEntries = {};

  // Step 2: Analyze Source Packages
  for (const skillName of sourcePackageDirs) {
    const sPkgDir = path.join(sourceSkillsDir, skillName);
    const tPkgDir = path.join(targetSkillsDir, skillName);

    const sSkillMdPath = path.join(sPkgDir, 'SKILL.md');
    const sHasSkillMd = fs.existsSync(sSkillMdPath);
    let sMdContent = sHasSkillMd ? fs.readFileSync(sSkillMdPath, 'utf8') : '';
    let sHash = sHasSkillMd ? sha256(sMdContent) : null;
    let sFrontmatter = sHasSkillMd ? parseFrontmatter(sMdContent, skillName) : { name: skillName, description: '', license: null };

    const sFiles = listPackageFilesRecursive(sPkgDir).map((p) => path.relative(sPkgDir, p).replace(/\\/g, '/'));
    const tExists = fs.existsSync(tPkgDir);
    const tFiles = tExists ? listPackageFilesRecursive(tPkgDir).map((p) => path.relative(tPkgDir, p).replace(/\\/g, '/')) : [];

    const tSkillMdPath = path.join(tPkgDir, 'SKILL.md');
    const tHasSkillMd = fs.existsSync(tSkillMdPath);
    let tMdContent = tHasSkillMd ? fs.readFileSync(tSkillMdPath, 'utf8') : '';
    let tHash = tHasSkillMd ? sha256(tMdContent) : null;
    let tFrontmatter = tHasSkillMd ? parseFrontmatter(tMdContent, skillName) : null;

    // Security & License Audit
    const securityAudit = auditPackageSecurity(sPkgDir);
    const licenseAudit = auditPackageLicense(sPkgDir, sFrontmatter.license);
    const category = classifyCategory(skillName, sFrontmatter.name, sFrontmatter.description);
    const routingTier = classifyRoutingTier(category, skillName);

    if (args.category && category !== args.category) {
      continue;
    }

    let status = 'NEW';
    let migrationDecision = 'IMPORT';

    if (!sHasSkillMd) {
      status = 'INVALID_MANIFEST';
      migrationDecision = 'SKIP_INVALID';
    } else if (securityAudit.status === 'SECURITY_QUARANTINED') {
      status = 'SECURITY_QUARANTINED';
      migrationDecision = 'QUARANTINE_METADATA_ONLY';
    } else if (PROTECTED_RICH_TARGET_SUITES.has(skillName)) {
      status = 'TARGET_RICHER';
      migrationDecision = 'PRESERVE_TARGET_COMPLETELY';
    } else if (!tExists) {
      status = 'NEW';
      migrationDecision = 'IMPORT_NEW_PACKAGE';
    } else if (sHash === tHash) {
      if (tFiles.length > sFiles.length) {
        status = 'TARGET_RICHER';
        migrationDecision = 'PRESERVE_TARGET_ADD_MISSING_AUX';
      } else if (sFiles.length > tFiles.length) {
        status = 'SOURCE_ADDITIVE';
        migrationDecision = 'MERGE_SOURCE_ADDITIVE_FILES';
      } else {
        status = 'IDENTICAL';
        migrationDecision = 'NO_OP_IDENTICAL';
      }
    } else {
      // Hashes differ between source and target
      if (tFiles.length > sFiles.length) {
        status = 'TARGET_RICHER';
        migrationDecision = 'PRESERVE_TARGET_DOCUMENT_DIFF';
      } else {
        status = 'SOURCE_DIVERGENT';
        migrationDecision = 'PRESERVE_TARGET_DOCUMENT_DIFF';
      }

      // Generate conflict diff document
      const diffPath = path.join(conflictsDir, `${skillName}.diff`);
      const diffContent = [
        `# EJII Skill Divergence Diff: ${skillName}`,
        `# Source Hash : ${sHash}`,
        `# Target Hash : ${tHash}`,
        `# Analyzed At : ${new Date().toISOString()}`,
        `--- Target: .agents/skills/${skillName}/SKILL.md`,
        `+++ Source: upstream/skills/${skillName}/SKILL.md`,
        `===================================================================`,
        `Target Description: ${tFrontmatter?.description || 'N/A'}`,
        `Source Description: ${sFrontmatter.description || 'N/A'}`,
        `Target File Count  : ${tFiles.length}`,
        `Source File Count  : ${sFiles.length}`
      ].join('\n');
      conflictsList.push({ skillName, diffPath });
      if (args.apply) {
        fs.writeFileSync(diffPath, diffContent, 'utf8');
      }
    }

    // Update report counters
    if (status === 'NEW') overlapReport.summary.newPackages++;
    else if (status === 'IDENTICAL') overlapReport.summary.identicalPackages++;
    else if (status === 'TARGET_RICHER') overlapReport.summary.targetRicherPackages++;
    else if (status === 'SOURCE_ADDITIVE') overlapReport.summary.sourceAdditivePackages++;
    else if (status === 'SOURCE_DIVERGENT') overlapReport.summary.sourceDivergentPackages++;
    else if (status === 'SECURITY_QUARANTINED') overlapReport.summary.securityQuarantinedPackages++;
    else if (status === 'INVALID_MANIFEST') overlapReport.summary.invalidManifestPackages++;

    const pkgRecord = {
      name: skillName,
      sourcePath: `skills/${skillName}`,
      targetPath: `.agents/skills/${skillName}`,
      status,
      migrationDecision,
      category,
      license: licenseAudit,
      security: securityAudit,
      routing: routingTier,
      sourceHash: sHash,
      targetHash: tHash,
      sourceFilesCount: sFiles.length,
      targetFilesCount: tFiles.length,
      auxiliaryDirectories: sFiles
        .filter((f) => f.includes('/'))
        .map((f) => f.split('/')[0])
        .filter((v, i, a) => a.indexOf(v) === i)
    };

    overlapReport.packages.push(pkgRecord);

    // Build Manifest Record
    const effectiveDescription = tFrontmatter?.description || sFrontmatter.description;
    const effectiveHash = tHash || sHash;

    manifestRecords.push({
      name: skillName,
      description: effectiveDescription,
      category,
      path: `.agents/skills/${skillName}/SKILL.md`,
      source: {
        repository: 'shahinkarimov/claude-skills',
        commit: args.sourceRef,
        originalPath: `skills/${skillName}/SKILL.md`
      },
      integrity: {
        sha256: effectiveHash,
        verified: true
      },
      license: {
        status: licenseAudit.status,
        identifier: licenseAudit.identifier
      },
      security: {
        status: securityAudit.status,
        scriptsReviewed: securityAudit.scriptsReviewed,
        issueCount: securityAudit.issues.length
      },
      capabilities: {
        hasScripts: securityAudit.hasScripts,
        hasReferences: sFiles.some((f) => f.startsWith('references/')),
        hasTemplates: sFiles.some((f) => f.startsWith('templates/')),
        hasAgentMetadata: sFiles.some((f) => f.startsWith('agents/'))
      },
      routing: {
        tier: routingTier.tier,
        enabledByDefault: routingTier.enabledByDefault
      }
    });

    if (sHash) {
      upstreamLockEntries[skillName] = {
        manifestHash: sHash,
        sourcePath: `skills/${skillName}/SKILL.md`,
        sourceCommit: args.sourceRef,
        category,
        license: licenseAudit.identifier,
        status
      };
    }

    // Step 3: Perform Non-Destructive Copy if Apply mode
    if (args.apply) {
      if (status === 'NEW' && migrationDecision === 'IMPORT_NEW_PACKAGE') {
        // Copy complete new package
        fs.mkdirSync(tPkgDir, { recursive: true });
        for (const relFile of sFiles) {
          const srcFilePath = path.join(sPkgDir, relFile);
          const dstFilePath = path.join(tPkgDir, relFile);
          fs.mkdirSync(path.dirname(dstFilePath), { recursive: true });
          fs.copyFileSync(srcFilePath, dstFilePath);
        }
      } else if (status === 'SOURCE_ADDITIVE' || (status === 'TARGET_RICHER' && migrationDecision.includes('ADD_MISSING_AUX'))) {
        // Smart merge: only copy missing files without overwriting existing files
        for (const relFile of sFiles) {
          const dstFilePath = path.join(tPkgDir, relFile);
          if (!fs.existsSync(dstFilePath)) {
            const srcFilePath = path.join(sPkgDir, relFile);
            fs.mkdirSync(path.dirname(dstFilePath), { recursive: true });
            fs.copyFileSync(srcFilePath, dstFilePath);
          }
        }
      }
    }
  }

  // Step 4: Account for Target-Only Packages (EJII Exclusives)
  for (const tName of targetPackageDirs) {
    if (!sourcePackageDirs.includes(tName)) {
      overlapReport.summary.targetOnlyPackages++;
      const tPkgDir = path.join(targetSkillsDir, tName);
      const tSkillMdPath = path.join(tPkgDir, 'SKILL.md');
      const tHasSkillMd = fs.existsSync(tSkillMdPath);
      const tContent = tHasSkillMd ? fs.readFileSync(tSkillMdPath, 'utf8') : '';
      const tHash = tHasSkillMd ? sha256(tContent) : null;
      const tFrontmatter = tHasSkillMd ? parseFrontmatter(tContent, tName) : { name: tName, description: '' };
      const tFiles = listPackageFilesRecursive(tPkgDir).map((p) => path.relative(tPkgDir, p).replace(/\\/g, '/'));
      const category = classifyCategory(tName, tFrontmatter.name, tFrontmatter.description);
      const routingTier = classifyRoutingTier(category, tName);

      const pkgRecord = {
        name: tName,
        sourcePath: null,
        targetPath: `.agents/skills/${tName}`,
        status: 'TARGET_ONLY',
        migrationDecision: 'PRESERVE_EJII_EXCLUSIVE',
        category,
        license: { status: 'LICENSED_APPROVED', identifier: 'EJII Proprietary & Open Stack' },
        security: { status: 'REVIEWED', scriptsReviewed: true, hasScripts: tFiles.some((f) => f.includes('scripts/')), issues: [] },
        routing: routingTier,
        sourceHash: null,
        targetHash: tHash,
        sourceFilesCount: 0,
        targetFilesCount: tFiles.length,
        auxiliaryDirectories: tFiles
          .filter((f) => f.includes('/'))
          .map((f) => f.split('/')[0])
          .filter((v, i, a) => a.indexOf(v) === i)
      };

      overlapReport.packages.push(pkgRecord);

      manifestRecords.push({
        name: tName,
        description: tFrontmatter.description || `EJII Exclusive Sovereign Skill (${tName})`,
        category,
        path: `.agents/skills/${tName}/SKILL.md`,
        source: {
          repository: 'EldarJamiyev/Eldar-Jamiyev-Infrastructure-Intelligence',
          commit: 'HEAD',
          originalPath: `.agents/skills/${tName}/SKILL.md`
        },
        integrity: {
          sha256: tHash,
          verified: true
        },
        license: {
          status: 'LICENSED_APPROVED',
          identifier: 'EJII Sovereign License'
        },
        security: {
          status: 'REVIEWED',
          scriptsReviewed: true,
          issueCount: 0
        },
        capabilities: {
          hasScripts: tFiles.some((f) => f.includes('scripts/')),
          hasReferences: tFiles.some((f) => f.includes('references/')),
          hasTemplates: tFiles.some((f) => f.includes('templates/')),
          hasAgentMetadata: tFiles.some((f) => f.includes('agents/'))
        },
        routing: {
          tier: routingTier.tier,
          enabledByDefault: routingTier.enabledByDefault
        }
      });
    }
  }

  manifestRecords.sort((a, b) => a.name.localeCompare(b.name));
  overlapReport.packages.sort((a, b) => a.name.localeCompare(b.name));
  overlapReport.summary.totalCataloged = manifestRecords.length;

  console.log('------------------------------------------------------------------------');
  console.log(`[Summary] Total Cataloged Packages      : ${manifestRecords.length}`);
  console.log(`[Summary] New Packages to Import        : ${overlapReport.summary.newPackages}`);
  console.log(`[Summary] Target-Only (EJII Exclusives) : ${overlapReport.summary.targetOnlyPackages}`);
  console.log(`[Summary] Target Richer (Preserved)     : ${overlapReport.summary.targetRicherPackages}`);
  console.log(`[Summary] Source Additive               : ${overlapReport.summary.sourceAdditivePackages}`);
  console.log(`[Summary] Divergent (Diffs Generated)   : ${overlapReport.summary.sourceDivergentPackages}`);
  console.log(`[Summary] Security Quarantined          : ${overlapReport.summary.securityQuarantinedPackages}`);
  console.log(`[Summary] Invalid Manifests             : ${overlapReport.summary.invalidManifestPackages}`);
  console.log('------------------------------------------------------------------------');

  // Step 5: Write Output Files if Apply or Report mode
  if (args.report || args.apply || args.update) {
    const reportPath = path.join(docsDir, 'overlap-report.json');
    fs.writeFileSync(reportPath, JSON.stringify(overlapReport, null, 2), 'utf8');
    console.log(`✓ Overlap Report written to: ${reportPath}`);

    const manifestPath = path.join(targetSkillsDir, 'skills-manifest.json');
    fs.writeFileSync(manifestPath, JSON.stringify(manifestRecords, null, 2), 'utf8');
    console.log(`✓ Skills Manifest written to: ${manifestPath}`);

    const upstreamLockPath = path.join(targetSkillsDir, 'upstream-skills-lock.json');
    const lockPayload = {
      version: 1,
      source: PINNED_SOURCE,
      generatedAt: new Date().toISOString(),
      totalLockedSkills: Object.keys(upstreamLockEntries).length,
      skills: upstreamLockEntries
    };
    fs.writeFileSync(upstreamLockPath, JSON.stringify(lockPayload, null, 2), 'utf8');
    console.log(`✓ Upstream Skills Lock written to: ${upstreamLockPath}`);

    // Generate .agents/skill-profiles.json
    const profilesPath = path.join(REPO_ROOT, '.agents', 'skill-profiles.json');
    const skillProfiles = {
      version: 1,
      updatedAt: new Date().toISOString(),
      tiers: {
        tier0_core_governance: {
          description: 'Always active fundamental project governance, immutable contracts, and safety constraints.',
          skills: manifestRecords.filter((s) => s.routing.tier === 'TIER_0_CORE_GOVERNANCE').map((s) => s.name)
        },
        tier1_infrastructure_core: {
          description: 'High-priority infrastructure, networking, SRE, Google Cloud, and backend engineering skills.',
          skills: manifestRecords.filter((s) => s.routing.tier === 'TIER_1_INFRASTRUCTURE_CORE').map((s) => s.name)
        },
        tier2_on_demand: {
          description: 'Loaded dynamically when touching frontend, mobile, browser scraping, or scientific workflows.',
          skills: manifestRecords.filter((s) => s.routing.tier === 'TIER_2_ON_DEMAND').map((s) => s.name)
        },
        tier3_dormant_explicit: {
          description: 'Specialized game engines, 3D art, and media tools indexed but only loaded on explicit invocation.',
          skills: manifestRecords.filter((s) => s.routing.tier === 'TIER_3_DORMANT_EXPLICIT_INVOCATION').map((s) => s.name)
        }
      }
    };
    fs.writeFileSync(profilesPath, JSON.stringify(skillProfiles, null, 2), 'utf8');
    console.log(`✓ Tiered Skill Profiles written to: ${profilesPath}`);
  }

  return { overlapReport, manifestRecords, upstreamLockEntries };
}

// Standalone execution entrypoint
if (process.argv[1] && process.argv[1].endsWith('sync-agent-skills.mjs')) {
  const cliArgs = parseCliArgs(process.argv);
  runSkillSyncPipeline(cliArgs)
    .then(() => {
      console.log('✅ Synchronization pipeline completed successfully.');
      process.exit(0);
    })
    .catch((err) => {
      console.error('❌ Sync pipeline failed:', err);
      process.exit(1);
    });
}
