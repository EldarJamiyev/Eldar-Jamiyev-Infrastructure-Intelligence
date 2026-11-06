'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { multiSiteManager } = require('../src/core/multisite/multisite-manager');
const { edgeAgentService } = require('../src/core/agent/edge-agent-service');
const { predictiveHorizonEngine } = require('../src/ai/predictive-horizon-engine');
const { hypothesisArbiter } = require('../src/ai/hypothesis-arbiter');
const { timelineReconstructor } = require('../src/observability/timeline-reconstructor');
const { superpowersSkillsEngine } = require('../src/core/skills/superpowers-skills-engine');
const { EpisodicCausalMemoryEngine } = require('../src/ai/episodic-causal-memory-engine');

describe('Sovereign Fabric V6 — Zero-Simulation Reality, Data Contract & Epistemic Reasoner Suite', () => {
  it('1. purges fictional global cities and fake carrier links when includeSimulated=false', () => {
    const liveSites = multiSiteManager.getAllSites({ includeSimulated: false });
    assert.ok(liveSites.length >= 1, 'Must return at least the genuine local runtime site');
    const siteNames = liveSites.map((s) => s.name).join(' ');
    assert.ok(!/Frankfurt|London|New York|Singapore|Tokyo/i.test(siteNames), 'Must not include fictional global cities');
    assert.equal(liveSites[0].isSimulated, false);

    const liveLinks = multiSiteManager.getAllWanLinks({ includeSimulated: false });
    assert.ok(liveLinks.length >= 1, 'Must return genuine local gateway / DNS egress links');
    const providers = liveLinks.map((l) => l.provider).join(' ');
    assert.ok(!/Colt|Lumen|NTT|Singtel/i.test(providers), 'Must not include fabricated carrier names');
  });

  it('2. returns genuine Local Host Telemetry Daemon with zero simulation agents when includeSimulated=false', () => {
    const liveAgents = edgeAgentService.getAllAgents({ includeSimulated: false });
    assert.ok(liveAgents.length >= 1, 'Must return at least the local host telemetry daemon');
    for (const agent of liveAgents) {
      assert.equal(agent.isSimulated, false, 'Live agent must not be flagged as isSimulated');
      assert.equal(agent.isSampleSimulation, false, 'Live agent must not be a sample simulation');
    }
  });

  it('3. eliminates cloned dummy hostnames in PredictiveHorizonEngine and populates cut-vertex label & downstreamDependentCount', () => {
    const report = predictiveHorizonEngine.evaluatePredictiveHorizon({});
    assert.ok(Array.isArray(report.predictions) && report.predictions.length >= 1);
    const targets = report.predictions.map((p) => p.target);
    assert.ok(!targets.includes('gateway.internal'), 'Must not include hardcoded gateway.internal');
    assert.ok(!targets.includes('dns-resolver.core'), 'Must not include hardcoded dns-resolver.core');
    assert.ok(!targets.includes('auth-service.edge'), 'Must not include hardcoded auth-service.edge');

    for (const cv of report.cutVertices) {
      assert.ok(typeof cv.label === 'string' && cv.label.length > 0 && cv.label !== 'undefined');
      assert.equal(typeof cv.downstreamDependentCount, 'number');
      assert.notEqual(cv.label, '127.0.0.1', 'Loopback must not be flagged as a physical Tarjan cut-vertex SPOF');
    }
  });

  it('4. populates stepIndex, probeExecuted, and empiricalObservationSummary in HypothesisArbiter trace without undefined', async () => {
    const arb = await hypothesisArbiter.arbitrateAndExecuteClosedLoop({
      target: '127.0.0.1',
      port: 3000,
      executeClosedLoop: true,
      maxClosedLoopSteps: 2
    });
    assert.ok(Array.isArray(arb.closedLoopExecutionTrace) && arb.closedLoopExecutionTrace.length >= 1);
    for (const step of arb.closedLoopExecutionTrace) {
      assert.equal(typeof step.stepIndex, 'number');
      assert.ok(typeof step.probeExecuted === 'string' && step.probeExecuted.length > 0);
      assert.ok(typeof step.empiricalObservationSummary === 'string' && step.empiricalObservationSummary.length > 0);
    }
  });

  it('5. populates detail and summary on all TimelineReconstructor events without fabricating an outage cascade on nominal loopback', () => {
    const tl = timelineReconstructor.reconstructPreIncidentTimeline({
      target: '127.0.0.1',
      lookbackMinutes: 30
    });
    assert.ok(Array.isArray(tl.timelineEvents) && tl.timelineEvents.length >= 1);
    for (const ev of tl.timelineEvents) {
      assert.ok(typeof ev.detail === 'string' && ev.detail.length > 0 && ev.detail !== 'undefined');
      assert.ok(typeof ev.summary === 'string' && ev.summary.length > 0);
    }
  });

  it('6. populates id, skillId, phaseBadge, sourcePath, and liveContribution on all 8 Superpowers skills', () => {
    const skills = superpowersSkillsEngine.listSkills();
    assert.equal(skills.length, 8);
    for (const sk of skills) {
      assert.ok(typeof sk.id === 'string' && sk.id.length > 0 && sk.id !== 'undefined');
      assert.equal(sk.id, sk.skillId);
      assert.ok(typeof sk.phaseBadge === 'string' && sk.phaseBadge.length > 0);
      assert.ok(typeof sk.sourcePath === 'string' && sk.sourcePath.endsWith('SKILL.md'));
      assert.ok(typeof sk.liveContribution === 'string' && sk.liveContribution.length > 0);
    }
  });

  it('7. filters out static seed episodes and never fabricates ep-live-runtime-baseline when EpisodicCausalMemoryEngine.getAllEpisodes({ includeSimulated: false }) is called', () => {
    const initialLive = EpisodicCausalMemoryEngine.getAllEpisodes({ includeSimulated: false });
    for (const ep of initialLive) {
      assert.ok(!ep.episodeId.startsWith('ep-seed-'), 'Must not include static seed episodes in live mode');
      assert.notEqual(ep.episodeId, 'ep-live-runtime-baseline', 'Must never return a hardcoded ep-live-runtime-baseline episode');
    }

    const recorded = EpisodicCausalMemoryEngine.recordLiveSynthesisEpisode({
      target: '127.0.0.1:3000',
      winningDomainId: 'TRANSPORT_L4',
      probabilityPct: 68.5,
      rttMs: 1.4,
      lossPct: 0,
      summary: 'Verified L4 TCP handshake on 127.0.0.1:3000'
    });
    assert.equal(recorded.provenance, 'LIVE_RUNTIME_OBSERVATION');
    assert.equal(recorded.isSimulated, false);

    const liveEpisodesAfter = EpisodicCausalMemoryEngine.getAllEpisodes({ includeSimulated: false });
    assert.ok(liveEpisodesAfter.length >= 1);
    assert.equal(liveEpisodesAfter[0].episodeId, recorded.episodeId);
    assert.equal(liveEpisodesAfter[0].provenance, 'LIVE_RUNTIME_OBSERVATION');
  });

  it('8. operationalizes all 85+ installed skills across 6 strategic pillars from .agents/skills, agent/skills, and skills-lock.json', () => {
    const allSkills = superpowersSkillsEngine.listAllInstalledSkills();
    const summary = superpowersSkillsEngine.getSkillsSummary();
    assert.ok(allSkills.length >= 85, `Expected at least 85 installed skills, got ${allSkills.length}`);
    assert.equal(summary.totalInstalledSkillsCount, allSkills.length);
    assert.equal(summary.pillars.length, 6);
    const pillarIds = summary.pillars.map((p) => p.id);
    assert.ok(pillarIds.includes('SUPERPOWERS_ORCHESTRATION'));
    assert.ok(pillarIds.includes('GRAVITAS_HIGHSTAKES'));
    assert.ok(pillarIds.includes('GSTACK_AUTONOMOUS_SUITE'));
    assert.ok(pillarIds.includes('ARCHITECTURAL_GRILLING_DESIGN'));
    assert.ok(pillarIds.includes('ANTI_SLOP_UI_ANIMATION'));
    assert.ok(pillarIds.includes('THROUGHPUT_CONTEXT_OBSERVABILITY'));
  });

  it('9. executes live cognitive stages (Doubt-Driven Review, Constraint Floor, Context Compiler, Throughput Accelerator) during Unified Synthesis', async () => {
    const syn = await superpowersSkillsEngine.executeUnifiedSuperpowersSynthesis({
      objective: 'Verify 85-skill cognitive pipeline on 127.0.0.1:3000',
      target: '127.0.0.1',
      port: 3000,
      executeClosedLoop: true
    });
    assert.ok(syn.doubtDrivenReview && typeof syn.doubtDrivenReview.verdict === 'string');
    assert.ok(syn.constraintFloorAudit && typeof syn.constraintFloorAudit.compliant === 'boolean');
    assert.ok(syn.compiledContextWindow && syn.compiledContextWindow.tokenBudgetSavedPct > 0);
    assert.ok(syn.throughputProfile && syn.throughputProfile.inMemoryBufferScanGbps > 0);
    assert.equal(syn.throughputProfile.benchmarkMethod, 'NODE_BUFFER_UINT32_READ_LOOP');
    assert.ok(syn.totalInstalledSkillsCount >= 85);
  });

  it('10. computes Burst-Aware M/G/1 Pollaczek-Khinchine Queueing factor and Index of Dispersion in PredictiveHorizonEngine', () => {
    const report = predictiveHorizonEngine.evaluatePredictiveHorizon({});
    assert.ok(report.predictions.length >= 1);
    for (const p of report.predictions) {
      assert.equal(typeof p.mg1PollaczekKhinchineFactor, 'number');
      assert.equal(typeof p.indexOfDispersion, 'number');
      assert.equal(typeof p.coefficientOfVariationSq, 'number');
      assert.ok(typeof p.burstRegime === 'string' && p.burstRegime.length > 0);
    }
  });

  it('11. attaches Doubt-Driven Audit and 3-Tier Remediation Playbook in HypothesisArbiter', async () => {
    const arb = await hypothesisArbiter.arbitrateAndExecuteClosedLoop({
      target: '127.0.0.1',
      port: 3000,
      executeClosedLoop: true,
      maxClosedLoopSteps: 2
    });
    assert.ok(arb.doubtDrivenAudit && typeof arb.doubtDrivenAudit.claim === 'string');
    assert.ok(Array.isArray(arb.doubtDrivenAudit.epistemicConfidenceIntervalPct));
    assert.ok(arb.tieredRemediationPlaybook && typeof arb.tieredRemediationPlaybook.tier1QuickCheck === 'string');
    assert.ok(typeof arb.tieredRemediationPlaybook.tier2RootCauseFix === 'string');
    assert.ok(typeof arb.tieredRemediationPlaybook.tier3ArchitecturalHardening === 'string');
  });

  it('12. harvests kernel ARP, routing table, and active TCP socket peer topology in MultiSiteManager', () => {
    const liveSites = multiSiteManager.getAllSites({ includeSimulated: false });
    assert.ok(liveSites.length >= 1);
    const primary = liveSites[0];
    assert.equal(typeof primary.discoveredArpNeighborsCount, 'number');
    assert.equal(typeof primary.discoveredActivePeersCount, 'number');
    assert.ok(Array.isArray(primary.zones) && primary.zones.length >= 1);
  });

  it('13. indexes all 159 skill manifests (85 primary + 74 nested GStack) in strictly read-only mode with truthful on-disk inventory & SHA-256 provenance', () => {
    const fs = require('fs');
    const path = require('path');
    const summary = superpowersSkillsEngine.getSkillsSummary();
    assert.equal(summary.topLevelPackagesCount, 85);
    assert.equal(summary.nestedGstackWorkflowsCount, 74);
    assert.equal(summary.totalManifestsCount, 159);
    assert.ok(summary.agentDirectorySkillsCount >= 15);
    assert.ok(summary.lockfileSkillsCount >= 46);
    assert.equal(summary.readOnlyIntegrityStatus, 'IMMUTABLE_READ_ONLY');
    assert.equal(summary.readOnlyConstraintEnforced, true);
    assert.ok(summary.inventoryAudit, 'Must expose inventoryAudit breakdown');
    assert.ok(summary.inventoryAudit.discoveredOnDiskManifestsCount >= 46);

    const all159 = superpowersSkillsEngine.listAll159Manifests();
    assert.equal(all159.length, 159);
    for (const m of all159) {
      assert.equal(m.readOnlyProtected, true);
      if (m.installedOnDisk) {
        assert.equal(typeof m.contentSha256, 'string');
        assert.equal(m.hashProvenance, 'LIVE_DISK_SHA256');
      } else {
        assert.equal(m.contentSha256, null, `Skill ${m.skillId} not on disk must not fabricate contentSha256`);
      }
    }

    // Verify openai.yaml is classified as CONFIG_RESOURCE rather than SKILL_MD
    const openaiConfig = superpowersSkillsEngine.resolveSkillManifest('gstack/agents/openai.yaml');
    assert.ok(openaiConfig);
    assert.equal(openaiConfig.manifestType, 'CONFIG_RESOURCE');

    // Verify canonical nested gstack/autoplan and hyphenated alias gstack-autoplan resolve to .agents/skills/gstack/autoplan/SKILL.md
    const byNestedId = superpowersSkillsEngine.resolveSkillManifest('gstack/autoplan');
    const byHyphenAlias = superpowersSkillsEngine.resolveSkillManifest('gstack-autoplan');
    assert.ok(byNestedId && byNestedId.sourcePath.endsWith('gstack/autoplan/SKILL.md'));
    assert.ok(byHyphenAlias && byHyphenAlias.sourcePath.endsWith('gstack/autoplan/SKILL.md'));

    // Verify strictly read-only filesystem operations in superpowers-skills-engine.js and intact directories
    const engineSource = fs.readFileSync(path.resolve(__dirname, '../src/core/skills/superpowers-skills-engine.js'), 'utf8');
    assert.ok(!/fs\.(writeFile|writeFileSync|unlink|unlinkSync|rmSync|rmdir|mkdir|rename)/i.test(engineSource), 'Must use strictly read-only fs operations');
    assert.ok(fs.existsSync(path.resolve(__dirname, '../.agents/skills')));
    assert.ok(fs.existsSync(path.resolve(__dirname, '../agent/skills')));
    assert.ok(fs.existsSync(path.resolve(__dirname, '../skills-lock.json')));
  });

  it('14. applies context-aware relevance routing and negative-context filtering to exclude non-infrastructure skills during NOC diagnostics', () => {
    const grill = superpowersSkillsEngine.grillOperationalIntent({
      target: '127.0.0.1',
      query: 'Investigate L4 TCP handshake latency, M/G/1 queueing cliff, and DNS split-horizon timeout on 127.0.0.1:3000'
    });
    assert.ok(grill.skillRoutingReport);
    assert.equal(grill.skillRoutingReport.totalManifestsAccounted, 159);
    assert.equal(grill.skillRoutingReport.readOnlyConstraintEnforced, true);
    const activeIds = grill.activatedSkills;
    assert.ok(!activeIds.includes('ios-clean'), 'Must exclude ios-clean during infrastructure diagnostics');
    assert.ok(!activeIds.includes('ios-fix'), 'Must exclude ios-fix during infrastructure diagnostics');
    assert.ok(!activeIds.includes('browser-skills/hackernews-frontpage'), 'Must exclude hackernews-frontpage during infrastructure diagnostics');
  });

  it('15. computes genuine dynamic token budget compression and process.hrtime.bigint() throughput metrics without static constants', async () => {
    const syn = await superpowersSkillsEngine.executeUnifiedSuperpowersSynthesis({
      objective: 'Verify dynamic context token math and nanosecond throughput on 127.0.0.1:3000',
      target: '127.0.0.1',
      port: 3000,
      executeClosedLoop: true
    });
    const ctx = syn.compiledContextWindow;
    assert.ok(ctx.rawPayloadBytes > ctx.compiledPayloadBytes, 'Raw payload bytes must exceed compiled payload bytes');
    assert.ok(ctx.rawEstimatedTokens > ctx.compiledEstimatedTokens, 'Raw estimated tokens must exceed compiled tokens');
    assert.equal(ctx.tokenEstimationMethod, 'UTF8_BYTE_LENGTH_DIV_4_HEURISTIC');
    assert.ok(ctx.compiledContextPayload && Array.isArray(ctx.compiledContextPayload.retainedHypotheses));
    assert.notEqual(ctx.tokenBudgetSavedPct, 57.5, 'Must not return hardcoded 57.5% token savings');
    assert.ok(ctx.staleNoiseEvictedCount >= 1);

    const tp = syn.throughputProfile;
    assert.ok(tp.parallelExecutionDurationNs > 0);
    assert.ok(tp.totalBytesProcessed > 0);
    assert.ok(tp.bytesProcessedPerSec > 0);
    assert.notEqual(tp.simdParseThroughputGbps, 10.4, 'Must not return hardcoded 10.4 Gbps');
  });

  it('16. executes Stage-2 Cross-Engine Epistemic Fusion (100.0% posterior normalization), 4-Contract Doubt Audit, falsificationMatrix, and Conversational Bridge', async () => {
    const { executeConversationalSuperpowersBridge } = require('../src/core/chat/conversational-brain');
    const bridgeRes = await executeConversationalSuperpowersBridge(
      'Run unified superpowers synthesis on that host and check for a queueing cliff',
      { lastValidTarget: '127.0.0.1', lastPorts: [3000] }
    );
    assert.equal(bridgeRes.resolvedTarget, '127.0.0.1');
    assert.equal(bridgeRes.resolvedPort, 3000);
    assert.equal(bridgeRes.inheritedFromSession, true);
    assert.equal(bridgeRes.requiresClarification, false);

    const syn = bridgeRes.synthesis;
    assert.ok(syn.crossEngineEpistemicFusion);
    assert.equal(syn.crossEngineEpistemicFusion.posteriorSumPct, 100);
    assert.equal(syn.crossEngineEpistemicFusion.evidenceSupportStatus, 'CORROBORATED_BY_LIVE_PROBES');
    assert.ok(syn.crossEngineEpistemicFusion.consensusComponents);
    assert.equal(syn.doubtDrivenReview.contractsVerified.length, 4);
    assert.ok(Array.isArray(syn.hypothesisArbitration.counterfactualAnalysis.falsificationMatrix));
    assert.equal(syn.hypothesisArbitration.counterfactualAnalysis.falsificationMatrix.length, 5);
  });

  it('17. enforces real security & governance failures in enforceConstraintFloor (SSRF metadata IP 169.254.169.254 and POL-02 protected kernel PID 4)', () => {
    const ssrfAudit = superpowersSkillsEngine.enforceConstraintFloor(
      { target: '169.254.169.254' },
      { cutVertices: [] }
    );
    assert.equal(ssrfAudit.passed, false, 'Cloud metadata SSRF target 169.254.169.254 must fail constraint floor');
    assert.equal(ssrfAudit.compliant, false);
    const ssrfInv = ssrfAudit.invariantsChecked.find((i) => i.id === 'INV_SSRF_SAFE_TARGET');
    assert.equal(ssrfInv.status, 'FAILED');

    const pol02Audit = superpowersSkillsEngine.enforceConstraintFloor(
      { target: '127.0.0.1', proposedKillPid: 4 },
      { cutVertices: [] }
    );
    assert.equal(pol02Audit.passed, false, 'Attempting to terminate protected PID 4 must fail POL-02 invariant');
    const pol02Inv = pol02Audit.invariantsChecked.find((i) => i.id === 'INV_POL02_PROTECTED_PROCESS');
    assert.equal(pol02Inv.status, 'FAILED');
  });

  it('18. requests target clarification instead of silently defaulting to 127.0.0.1 when pronoun target is missing or session target is expired', async () => {
    const { resolvePronounInheritedTarget, executeConversationalSuperpowersBridge } = require('../src/core/chat/conversational-brain');

    const missing = resolvePronounInheritedTarget('Run synthesis on that server now', {});
    assert.equal(missing.target, null);
    assert.equal(missing.requiresClarification, true);
    assert.ok(typeof missing.clarificationPrompt === 'string' && missing.clarificationPrompt.length > 10);

    const expired = resolvePronounInheritedTarget('Check it again', {
      lastValidTarget: '10.20.30.40',
      lastTargetTimestampMs: Date.now() - 45 * 60 * 1000
    });
    assert.equal(expired.target, null);
    assert.equal(expired.sessionTargetExpired, true);
    assert.equal(expired.requiresClarification, true);

    const bridgeClarify = await executeConversationalSuperpowersBridge('Investigate that endpoint', {});
    assert.equal(bridgeClarify.requiresClarification, true);
    assert.equal(bridgeClarify.synthesis, null);
  });
});

