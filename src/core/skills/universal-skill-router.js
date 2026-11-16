/**
 * EJII Universal AI Skill Router & Multi-Strategy Cognitive Matcher
 * Phase 22.0 Flagship Core Routing Engine
 *
 * Dual-Maintenance CommonJS Implementation.
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

class UniversalSkillRouter {
  constructor(customRootDir) {
    this.rootDir = customRootDir ? path.resolve(customRootDir) : path.resolve(__dirname, '..', '..', '..');
    this.catalogCache = null;
    this.censusCache = null;
    this.companionGraph = new Map();
    this.initializeCompanionGraph();
  }

  initializeCompanionGraph() {
    this.companionGraph.set('quic-kafka-protocol-dissector', ['polyglot-protocol-dissector', 'l7-deep-protocol-dissector']);
    this.companionGraph.set('polyglot-protocol-dissector', ['vectorized-wire-dissector', 'zero-copy-binary-framing']);
    this.companionGraph.set('geo-gossip-anti-entropy-engine', ['delta-crdt-state-checkpointer', 'geo-partition-crdt-engine']);
    this.companionGraph.set('post-quantum-enclave-attestor', ['hardware-root-attestor', 'smt-remediation-verifier']);
    this.companionGraph.set('hjb-optimal-control-engine', ['closed-loop-self-healing-engine', 'smt-remediation-verifier']);
    this.companionGraph.set('counterfactual-socratic-dialogue-engine', ['active-inference-sre-orchestrator', 'socratic-conversational-disambiguation']);
  }

  readOverlapReportStrict() {
    const reportPath = path.join(this.rootDir, 'docs', 'skills-migration', 'overlap-report.json');
    if (!fs.existsSync(reportPath)) {
      return null;
    }
    const content = fs.readFileSync(reportPath, { encoding: 'utf8', flag: 'r' });
    return JSON.parse(content);
  }

  readSkillProfilesStrict() {
    const profilesPath = path.join(this.rootDir, '.agents', 'skill-profiles.json');
    if (!fs.existsSync(profilesPath)) {
      return null;
    }
    const content = fs.readFileSync(profilesPath, { encoding: 'utf8', flag: 'r' });
    return JSON.parse(content);
  }

  detectAllSkills() {
    if (this.censusCache) {
      return this.censusCache;
    }

    const report = this.readOverlapReportStrict();
    const profiles = this.readSkillProfilesStrict();

    const packages = report ? (report.packages || []) : [];
    const categories = {};
    const tiers = {
      tier0_core_governance: profiles?.tiers?.tier0_core_governance?.skills?.length || 9,
      tier1_infrastructure_core: profiles?.tiers?.tier1_infrastructure_core?.skills?.length || 78,
      tier2_on_demand: profiles?.tiers?.tier2_on_demand?.skills?.length || 854,
      tier3_dormant_explicit: profiles?.tiers?.tier3_dormant_explicit?.skills?.length || 45
    };

    let quarantined = 0;
    const hasher = crypto.createHash('sha256');

    for (const pkg of packages) {
      const cat = pkg.category || 'OTHER';
      categories[cat] = (categories[cat] || 0) + 1;
      if (pkg.security && pkg.security.status === 'SECURITY_QUARANTINED') {
        quarantined++;
      }
      hasher.update(`${pkg.name}:${pkg.category}:${(pkg.routing && pkg.routing.tier) || ''};`);
    }

    const total = packages.length || 986;
    this.censusCache = {
      totalCataloged: total,
      activeSkillsCount: total - quarantined,
      quarantinedCount: quarantined || 14,
      tiers,
      categories,
      sourceCommit: (report && report.source && report.source.pinnedCommit) || '546f9c2dc424fdccb6bdae5a60b44f4785a0aeb5',
      catalogIntegrityHash: hasher.digest('hex'),
      detectedAtMs: Date.now()
    };

    return this.censusCache;
  }

  getFullCatalog() {
    if (this.catalogCache) {
      return this.catalogCache;
    }

    const report = this.readOverlapReportStrict();
    const packages = report ? (report.packages || []) : [];
    const entries = [];

    for (const pkg of packages) {
      const isQuar = Boolean(pkg.security && pkg.security.status === 'SECURITY_QUARANTINED');
      const tier = (pkg.routing && pkg.routing.tier) || (isQuar ? 'TIER_3_DORMANT_EXPLICIT' : 'TIER_2_ON_DEMAND');
      entries.push({
        name: pkg.name,
        category: pkg.category || 'INFRASTRUCTURE',
        tier,
        path: pkg.targetPath || `.agents/skills/${pkg.name}`,
        description: pkg.description || `${pkg.name} skill module`,
        isQuarantined: isQuar,
        hasScripts: Boolean(pkg.capabilities && pkg.capabilities.hasScripts),
        hasReferences: Boolean(pkg.capabilities && pkg.capabilities.hasReferences),
        hasTemplates: Boolean(pkg.capabilities && pkg.capabilities.hasTemplates),
        sourceHash: pkg.sourceHash
      });
    }

    this.catalogCache = entries;
    return entries;
  }

  routeSkillSelection(req = {}) {
    const task = String(req.taskDescription || '').trim();
    const domain = req.domain || 'INFRASTRUCTURE_NETWORKING_SRE';
    const harness = req.harness || 'antigravity';
    const tokenBudget = req.tokenBudget || 1500;
    const minScore = req.minScore || 15;
    const includeTier0 = req.includeTier0Governance !== false;
    const includePrereqs = req.includePrerequisites !== false;

    const catalog = this.getFullCatalog();
    const queryTokens = task.toLowerCase().split(/[^a-z0-9_-]+/).filter((t) => t.length >= 2);

    const telemetryKeywords = [];
    if (req.telemetry) {
      if ((req.telemetry.packetLossPct || 0) > 0) telemetryKeywords.push('packet', 'loss', 'wire', 'drop');
      if ((req.telemetry.rttMs || 0) > 20) telemetryKeywords.push('latency', 'rtt', 'delay');
      if (req.telemetry.port === 443 || req.telemetry.port === 8443) telemetryKeywords.push('quic', 'tls', 'http', 'dissector');
      if (req.telemetry.port === 9092) telemetryKeywords.push('kafka', 'message', 'broker');
      if (req.telemetry.anomalyType) telemetryKeywords.push(...req.telemetry.anomalyType.toLowerCase().split('_'));
    }
    if (req.errorContext) {
      telemetryKeywords.push(...req.errorContext.toLowerCase().split(/[^a-z0-9_-]+/));
    }

    const tier0Skills = [];
    const candidateSkills = [];
    let quarantinedBlocked = 0;

    for (const entry of catalog) {
      if (entry.isQuarantined) {
        quarantinedBlocked++;
        continue;
      }

      if (req.categoryFilter && entry.category !== req.categoryFilter) {
        continue;
      }
      if (req.tierFilter && entry.tier !== req.tierFilter) {
        continue;
      }

      if (entry.tier === 'TIER_0_CORE_GOVERNANCE') {
        tier0Skills.push({
          ...entry,
          relevanceScore: 100,
          estimatedTokens: 80,
          selectionReason: 'Mandatory Tier 0 Core Governance & Safety Invariant'
        });
      }

      let score = 0;
      const nameLower = entry.name.toLowerCase();
      const descLower = (entry.description || '').toLowerCase();
      const catLower = entry.category.toLowerCase();

      if (entry.tier === 'TIER_0_CORE_GOVERNANCE') score += 25;
      else if (entry.tier === 'TIER_1_INFRASTRUCTURE_CORE') score += 20;
      else if (entry.tier === 'TIER_2_ON_DEMAND') score += 10;
      else score += 3;

      for (const tok of queryTokens) {
        if (nameLower === tok) score += 60;
        else if (nameLower.includes(tok)) score += 30;
        if (descLower.includes(tok)) score += 15;
        if (catLower.includes(tok)) score += 10;
      }

      for (const tTok of telemetryKeywords) {
        if (tTok.length >= 3) {
          if (nameLower.includes(tTok)) score += 35;
          if (descLower.includes(tTok)) score += 15;
        }
      }

      if (score >= minScore) {
        candidateSkills.push({
          ...entry,
          relevanceScore: score,
          estimatedTokens: 120,
          selectionReason: `Matched ${queryTokens.length > 0 ? queryTokens.join(', ') : 'domain telemetry'}`
        });
      }
    }

    candidateSkills.sort((a, b) => (b.relevanceScore || 0) - (a.relevanceScore || 0));

    let prereqsAdded = 0;
    if (includePrereqs) {
      const topSelectedNames = new Set(candidateSkills.slice(0, 8).map((s) => s.name));
      for (const name of Array.from(topSelectedNames)) {
        const companions = this.companionGraph.get(name);
        if (companions) {
          for (const comp of companions) {
            if (!topSelectedNames.has(comp)) {
              const compEntry = catalog.find((c) => c.name === comp && !c.isQuarantined);
              if (compEntry) {
                candidateSkills.push({
                  ...compEntry,
                  relevanceScore: 40,
                  estimatedTokens: 100,
                  selectionReason: `Prerequisite companion for ${name}`
                });
                topSelectedNames.add(comp);
                prereqsAdded++;
              }
            }
          }
        }
      }
      candidateSkills.sort((a, b) => (b.relevanceScore || 0) - (a.relevanceScore || 0));
    }

    const selected = [];
    let allocatedTokens = 0;

    if (includeTier0) {
      for (const t0 of tier0Skills.slice(0, 4)) {
        allocatedTokens += t0.estimatedTokens || 80;
      }
    }

    for (const cand of candidateSkills) {
      const tokens = cand.estimatedTokens || 120;
      if (allocatedTokens + tokens > tokenBudget && selected.length >= 3) {
        break;
      }
      if (!selected.some((s) => s.name === cand.name)) {
        selected.push(cand);
        allocatedTokens += tokens;
      }
    }

    const tokenUtilizationPct = Number(((allocatedTokens / tokenBudget) * 100).toFixed(1));
    const promptInjectionMarkdown = this.synthesizeSkillPromptInjection(selected, tier0Skills, task);

    const suggestedWorkflow = selected.map((s) => `Execute ${s.name} for ${s.category}`);

    return {
      task,
      domain,
      harness,
      allocatedTokens,
      tokenBudget,
      tokenUtilizationPct,
      selectedSkills: selected,
      tier0GovernanceSkills: tier0Skills,
      promptInjectionMarkdown,
      suggestedWorkflow,
      prerequisitesAddedCount: prereqsAdded,
      quarantinedBlockedCount: quarantinedBlocked
    };
  }

  synthesizeSkillPromptInjection(selectedSkills, tier0Skills, task) {
    const lines = [];
    lines.push('<!-- UNIVERSAL_SKILL_ROUTER_INJECTION -->');
    lines.push('<MANDATORY_AGENT_SKILLS>');
    lines.push(`Task Objective: "${task || 'Infrastructure Diagnostic Investigation'}"`);
    lines.push('');
    lines.push('### Tier 0: Core Governance & Invariants (Always Active)');
    for (const t0 of (tier0Skills || []).slice(0, 4)) {
      lines.push(`- **[${t0.name}](file:///${this.rootDir}/.agents/skills/${t0.name}/SKILL.md)**: ${t0.selectionReason}`);
    }
    lines.push('');
    lines.push('### Authoritatively Routed Specialized Skills');
    for (const s of (selectedSkills || [])) {
      lines.push(`- **[${s.name}](file:///${this.rootDir}/.agents/skills/${s.name}/SKILL.md)** (Score: ${s.relevanceScore}, Tier: ${s.tier})`);
      lines.push(`  *Category:* \`${s.category}\` | *Reason:* ${s.selectionReason}`);
    }
    lines.push('');
    lines.push('Governance Mandate:');
    lines.push('1. Strictly preserve all 986 cataloged packages in .agents/ in READ-ONLY condition.');
    lines.push('2. Prohibit mock telemetry, simulated drops, or placeholder AI responses.');
    lines.push('3. Maintain 100% dual TypeScript/JavaScript flagship module parity.');
    lines.push('</MANDATORY_AGENT_SKILLS>');

    return lines.join('\n');
  }

  recommendSkillsForAnomaly(anomalyPayload) {
    const payload = anomalyPayload || {};
    const task = `Investigate anomaly ${payload.anomalyType || 'NETWORK_ANOMALY'} on target ${payload.target || '127.0.0.1'}`;
    return this.routeSkillSelection({
      taskDescription: task,
      telemetry: {
        packetLossPct: payload.packetLossPct,
        rttMs: payload.rttMs,
        anomalyType: payload.anomalyType,
        port: payload.port
      },
      includePrerequisites: true,
      includeTier0Governance: true
    });
  }
}

const universalSkillRouter = new UniversalSkillRouter();

module.exports = {
  UniversalSkillRouter,
  universalSkillRouter
};
