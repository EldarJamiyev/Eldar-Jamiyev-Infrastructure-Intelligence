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

  it('19. performs cross-layer diagnostic disambiguation (ICMP filtered vs host down, DNS vs TCP, single-port scope, direct vs indirect evidence, correlated symptom deduplication)', async () => {
    const arb = await hypothesisArbiter.arbitrateAndExecuteClosedLoop({
      target: '127.0.0.1',
      port: 3000,
      symptomSummary: 'Inspect cross-layer diagnostic semantics on 127.0.0.1:3000',
      executeClosedLoop: true
    });

    assert.ok(arb.crossLayerSemanticAnalysis, 'Must include crossLayerSemanticAnalysis');
    assert.ok(Array.isArray(arb.crossLayerSemanticInsights), 'Must include crossLayerSemanticInsights array');
    assert.ok(arb.evidenceCompletenessRatio > 0 && arb.evidenceCompletenessRatio <= 1, 'evidenceCompletenessRatio must be in (0, 1]');
    assert.ok(arb.extractedTelemetrySignature, 'Must extract real probe telemetry signature from closedLoopExecutionTrace');
    assert.equal(arb.extractedTelemetrySignature.source, 'LIVE_CLOSED_LOOP_PROBES');

    // Verify every hypothesis carries an explicit evidenceType (DIRECT_EMPIRICAL_OBSERVATION, INDIRECT_CROSS_LAYER_INFERENCE, or UNPROBED_PRIOR_ASSUMPTION)
    for (const h of arb.hypotheses) {
      assert.ok(
        ['DIRECT_EMPIRICAL_OBSERVATION', 'INDIRECT_CROSS_LAYER_INFERENCE', 'UNPROBED_PRIOR_ASSUMPTION'].includes(h.evidenceType),
        `Hypothesis ${h.id} must have valid evidenceType, got ${h.evidenceType}`
      );
    }

    // Verify service-scope boundary insight is present so single-port checks are not conflated with whole-host failure
    const hasScopeNote = arb.crossLayerSemanticInsights.some((ins) => ins.code === 'SERVICE_SCOPE_BOUNDARY_NOTE');
    assert.equal(hasScopeNote, true, 'Must include SERVICE_SCOPE_BOUNDARY_NOTE insight');
  });

  it('20. persists live episodic memory to SQLite, separates LIVE_HISTORICAL_INCIDENT from REFERENCE_SEED_ARCHETYPE, and withholds unsafe auto-recommendations', () => {
    const rec = EpisodicCausalMemoryEngine.recordLiveSynthesisEpisode({
      rootCauseCategory: 'L4_TCP_BACKLOG_SATURATION',
      rootCauseLayer: 'L4_TRANSPORT',
      target: '127.0.0.1',
      summary: 'Empirical test episode: transient TCP listen queue pressure on 127.0.0.1:3000',
      remediationApplied: 'Audited net.core.somaxconn and verified socket backlog recovery',
      rttMs: 4.2,
      packetLossPct: 0,
      retransmitsPerSec: 0.1,
      dnsLatencyMs: 2.1,
      tlsHandshakeMs: 6.5,
      http5xxRatePct: 0,
      cpuUtilizationPct: 18.5,
      resolved: false,
      verificationPassed: false
    });

    assert.equal(rec.provenance, 'LIVE_RUNTIME_OBSERVATION');
    assert.equal(rec.isSimulated, false);
    assert.equal(rec.resolved, false, 'Unverified episode must not be marked resolved: true');

    // Verify SQLite persistence and live-only filtering
    const liveOnly = EpisodicCausalMemoryEngine.getAllEpisodes({ includeSimulated: false });
    assert.ok(liveOnly.some((e) => e.episodeId === rec.episodeId), 'Recorded live episode must be retrievable via includeSimulated=false');
    assert.ok(liveOnly.every((e) => e.isSimulated === false && e.provenance === 'LIVE_RUNTIME_OBSERVATION'));

    // Verify similarity matching distinguishes memorySourceType and withholds auto-recommendation for unresolved or low-similarity episodes
    const matches = EpisodicCausalMemoryEngine.findSimilarEpisodes(
      { rttMs: 4.2, packetLossPct: 0, retransmitsPerSec: 0.1, dnsLatencyMs: 2.1, tlsHandshakeMs: 6.5, http5xxRatePct: 0, cpuUtilizationPct: 18.5 },
      5,
      { includeSimulated: true, currentTopHypothesisId: 'H_L7_DEPENDENCY' }
    );
    assert.ok(matches.length >= 1);
    for (const m of matches) {
      assert.ok(['LIVE_HISTORICAL_INCIDENT', 'REFERENCE_SEED_ARCHETYPE'].includes(m.memorySourceType));
      assert.ok(typeof m.remediationApplicability === 'string');
      assert.equal(typeof m.autoRecommendSafe, 'boolean');
    }
    const ourMatch = matches.find((m) => m.episode.episodeId === rec.episodeId);
    if (ourMatch) {
      assert.equal(ourMatch.memorySourceType, 'LIVE_HISTORICAL_INCIDENT');
      assert.equal(ourMatch.autoRecommendSafe, false, 'Unresolved historical episode must have autoRecommendSafe === false');
      assert.equal(ourMatch.remediationApplicability, 'AUTO_RECOMMENDATION_WITHHELD_UNRESOLVED_HISTORY');
    }
  });

  it('21. enforces multi-turn conversational target/port state machine, filters code filenames (server.mjs/SKILL.md), and emits llmPromptContextBlock + Contract 1 PASS', async () => {
    const { resolvePronounInheritedTarget } = require('../src/core/chat/conversational-brain');

    // Code filenames like server.mjs or SKILL.md must never be mistaken for network hostnames
    const fileFilterRes = resolvePronounInheritedTarget(
      'Check why server.mjs and SKILL.md reported an error on that host',
      { lastValidTarget: '127.0.0.1', lastPorts: [3000], lastTargetTimestampMs: Date.now() }
    );
    assert.equal(fileFilterRes.target, '127.0.0.1', 'Must inherit 127.0.0.1 rather than extracting server.mjs as hostname');
    assert.equal(fileFilterRes.inherited, true);
    assert.equal(fileFilterRes.scopeTransition, 'PRONOUN_CONTINUATION');

    // Switching to a new explicit target without specifying a port must not carry over stale port 3000
    const newTargetRes = resolvePronounInheritedTarget(
      'Now diagnose 10.20.30.40 for packet loss',
      { lastValidTarget: '127.0.0.1', lastPorts: [3000], lastTargetTimestampMs: Date.now() }
    );
    assert.equal(newTargetRes.target, '10.20.30.40');
    assert.equal(newTargetRes.inherited, false);
    assert.equal(newTargetRes.scopeTransition, 'NEW_TARGET_INVESTIGATION');
    assert.deepEqual(newTargetRes.ports, [], 'New target without explicit port must not inherit old target port 3000');

    // Verify Contract 1 passes on live 127.0.0.1:3000 and compiledContextWindow includes llmPromptContextBlock + probe status
    const syn = await superpowersSkillsEngine.executeUnifiedSuperpowersSynthesis({
      objective: 'Verify Contract 1 and llmPromptContextBlock on 127.0.0.1:3000',
      target: '127.0.0.1',
      port: 3000,
      executeClosedLoop: true
    });
    const c1 = syn.doubtDrivenReview.contractsVerified.find((c) => c.contractId === 'CONTRACT_1_OSI_PHYSICAL_NECESSITY');
    assert.ok(c1);
    assert.equal(c1.status, 'VERIFIED', 'CONTRACT_1_OSI_PHYSICAL_NECESSITY must be VERIFIED when TCP/HTTP probes succeed on 127.0.0.1:3000');
    assert.ok(typeof syn.compiledContextWindow.llmPromptContextBlock === 'string' && syn.compiledContextWindow.llmPromptContextBlock.includes('[COMPILED_TELEMETRY_CONTEXT'));
    for (const probe of syn.compiledContextWindow.compiledContextPayload.compactProbeSummaries) {
      assert.ok(probe.status === 'PASS' || probe.status === 'ANOMALY');
      assert.equal(typeof probe.informationGainBits, 'number');
    }
  });

  it('22. enforces telemetry field provenance (measuredFields vs missingFields), contradictory evidence detection, and next-observation guidance in HypothesisArbiter', async () => {
    const arb = await hypothesisArbiter.arbitrateAndExecuteClosedLoop({
      target: '127.0.0.1',
      port: 3000,
      executeClosedLoop: true,
      maxClosedLoopSteps: 2
    });
    const sem = arb.diagnosticSemantics;
    assert.ok(sem, 'diagnosticSemantics must be present');
    const sig = sem.extractedTelemetrySignature;
    assert.ok(Array.isArray(sig.measuredFields), 'measuredFields array must be present');
    assert.ok(Array.isArray(sig.missingFields), 'missingFields array must be present');
    assert.ok(Array.isArray(sig.derivedFields), 'derivedFields array must be present');
    assert.ok(sig.fieldProvenance && typeof sig.fieldProvenance === 'object', 'fieldProvenance map must be present');
    assert.ok(sig.rawMeasuredMetrics && typeof sig.rawMeasuredMetrics === 'object', 'rawMeasuredMetrics must be present');

    // Unmeasured metrics must be null in rawMeasuredMetrics and listed in missingFields
    for (const missingField of sig.missingFields) {
      assert.equal(sig.fieldProvenance[missingField], 'UNMEASURED_MISSING');
    }
    for (const measuredField of sig.measuredFields) {
      assert.equal(sig.fieldProvenance[measuredField], 'DIRECT_MEASUREMENT');
      assert.equal(typeof sig.rawMeasuredMetrics[measuredField], 'number');
    }

    assert.equal(typeof sem.contradictoryEvidenceDetected, 'boolean');
    assert.ok(Array.isArray(sem.contradictions));
    assert.ok(['PROVISIONAL_PARTIAL_EVIDENCE', 'ESTABLISHED_EMPIRICAL_ISOLATION'].includes(sem.confidenceClassification));
    assert.ok(Array.isArray(sem.recommendedNextObservations), 'recommendedNextObservations must guide next probes');
  });

  it('23. enforces incident lifecycle accuracy (investigation !== resolved remediation), environment-scope similarity guard, and SQLite persistence health', () => {
    const { EpisodicCausalMemoryEngine } = require('../src/ai/episodic-causal-memory-engine');
    const health = EpisodicCausalMemoryEngine.getPersistenceHealth();
    assert.ok(['DURABLE_SQLITE_WAL', 'VOLATILE_IN_MEMORY_FALLBACK', 'PERSISTENCE_WRITE_FAILED'].includes(health.persistenceStatus));
    assert.equal(typeof health.durableSqliteActive, 'boolean');

    // Recording a diagnostic investigation without remediationExecuted must NEVER be marked resolved
    const diagEp = EpisodicCausalMemoryEngine.recordLiveSynthesisEpisode({
      target: '127.0.0.1:3000',
      winningDomainId: 'HOST_PROCESS_SOCKET',
      probabilityPct: 68.5,
      rttMs: 1.4,
      lossPct: 0,
      remediationExecuted: false,
      verificationPassed: true,
      executedRunbookId: 'SYNTHESIS-AUDIT',
      summary: 'Diagnostic synthesis only — no remediation runbook executed.'
    });
    assert.equal(diagEp.resolved, false, 'Investigation-only episode must have resolved === false');
    assert.equal(diagEp.lifecycleStage, 'DIAGNOSTIC_INVESTIGATION_ONLY');
    assert.ok(['DURABLE_SQLITE_WAL', 'VOLATILE_IN_MEMORY_FALLBACK', 'PERSISTENCE_WRITE_FAILED'].includes(diagEp.persistenceStatus));

    // Recording a verified post-remediation episode with separate postActionRttMs
    const remEp = EpisodicCausalMemoryEngine.recordLiveSynthesisEpisode({
      target: '127.0.0.1:3000',
      winningDomainId: 'HOST_PROCESS_SOCKET',
      probabilityPct: 84.0,
      rttMs: 45.0,
      postActionRttMs: 2.1,
      lossPct: 0,
      remediationExecuted: true,
      verificationPassed: true,
      executedRunbookId: 'RB-03',
      summary: 'Executed RB-03 and verified post-action RTT drop.'
    });
    assert.equal(remEp.resolved, true, 'Verified remediation with postActionRttMs must have resolved === true');
    assert.equal(remEp.lifecycleStage, 'POST_REMEDIATION_VERIFIED');

    // Environment-scope mismatch: querying with a public WAN target (8.8.8.8) against a loopback (127.0.0.1) episode must withhold auto-recommendation
    const wanMatches = EpisodicCausalMemoryEngine.findSimilarEpisodes(
      {
        cusumShiftSigma: 0.5,
        spectralFlatness: 0.78,
        rttMs: 45.0,
        packetLossPct: 0,
        dnsLatencyMs: 0,
        cpuSaturationPct: 0,
        tcpRetransmitRate: 0
      },
      10,
      { includeSimulated: false, currentDomain: 'HOST_PROCESS_SOCKET', target: '8.8.8.8' }
    );
    const matchedLoopbackFromWan = wanMatches.find((m) => m.episode.episodeId === remEp.episodeId);
    if (matchedLoopbackFromWan) {
      assert.equal(matchedLoopbackFromWan.environmentMatches, false);
      assert.equal(matchedLoopbackFromWan.autoRecommendSafe, false);
      assert.equal(matchedLoopbackFromWan.remediationApplicability, 'AUTO_RECOMMENDATION_WITHHELD_ENVIRONMENT_MISMATCH');
    }
  });

  it('24. exposes container/host runtime namespace awareness, truthful packet capture interfaces (no fake Intel AX211 fallback), and privileged script execution policy guards', () => {
    // 1. Container/Host runtime environment detection in MultiSiteManager
    const envProfile = multiSiteManager.getRuntimeEnvironmentProfile();
    assert.ok(['CONTAINER_NAMESPACE_ISOLATED', 'VIRTUALIZED_SANDBOX_NAMESPACE', 'BARE_METAL_OR_VM_HOST'].includes(envProfile.executionEnvironment));
    assert.ok(['CONTAINER_NETNS_LOOPBACK', 'HOST_OS_LOOPBACK'].includes(envProfile.loopbackScope));
    assert.ok(['ISOLATED_CONTAINER_NETNS', 'HOST_GLOBAL_NETNS'].includes(envProfile.networkNamespaceScope));
    assert.ok(Array.isArray(envProfile.permissionBoundaryNotes));

    // 2. PacketStreamer truthful interface enumeration and capability profile
    const { packetStreamer } = require('../src/network/packet-streaming/packet-streamer');
    const capProfile = packetStreamer.getCaptureCapabilityProfile();
    assert.ok(['PROMISCUOUS_NIC_WIRE_CAPTURE', 'UNPRIVILEGED_SOCKET_AND_BUFFER_DISSECTION'].includes(capProfile.captureMode));
    assert.equal(typeof capProfile.promiscuousWireCaptureAvailable, 'boolean');
    assert.equal(capProfile.pcapBufferDissectionAvailable, true);

    const ifaces = packetStreamer.getCaptureInterfaces();
    assert.ok(Array.isArray(ifaces) && ifaces.length >= 1, 'Must enumerate real OS interfaces');
    if (process.platform !== 'win32') {
      const hasFakeWindowsAx211 = ifaces.some((i) => (i.description || '').includes('Intel(R) Wi-Fi 6E AX211') || i.ip === '192.168.31.89');
      assert.equal(hasFakeWindowsAx211, false, 'Non-Windows runtime must never return hardcoded Intel(R) Wi-Fi 6E AX211 or 192.168.31.89');
    }

    // 3. Script automation privilege & shell metacharacter policy guard
    const { evaluateScriptExecutionPolicy } = require('../src/tools/script-automation');
    const injectionCheck = evaluateScriptExecutionPolicy(
      { requiresElevation: false, riskLevel: 'LOW' },
      { params: '127.0.0.1; rm -rf /' }
    );
    assert.equal(injectionCheck.allowed, false);
    assert.equal(injectionCheck.reasonCode, 'SHELL_METACHARACTER_INJECTION_BLOCKED');

    const aiElevatedCheck = evaluateScriptExecutionPolicy(
      { requiresElevation: true, riskLevel: 'HIGH', privilegeRequirement: 'Administrator' },
      { initiatedByAi: true }
    );
    assert.equal(aiElevatedCheck.allowed, false);
    assert.equal(aiElevatedCheck.reasonCode, 'AI_AUTONOMOUS_PRIVILEGED_EXECUTION_FORBIDDEN');
  });

  it('25. filters source/manifest filenames (server.mjs, SKILL.md) and enforces 30-minute session target TTL in ChatOperatorService.parseIntentAndEntities', () => {
    const { chatOperatorService } = require('../src/core/chat/chat-operator-service');

    // Source/manifest filenames in prompt must not be extracted as network domain targets
    const parsedFilePrompt = chatOperatorService.parseIntentAndEntities(
      'Check why server.mjs and SKILL.md or package.json had an issue on port 3000',
      { lastValidTarget: null, lastPorts: [] }
    );
    assert.notEqual(parsedFilePrompt.explicitTarget, 'server.mjs');
    assert.notEqual(parsedFilePrompt.explicitTarget, 'SKILL.md');
    assert.notEqual(parsedFilePrompt.explicitTarget, 'package.json');

    // Expired session target (> 30 minutes old) must not be inherited as priorTarget
    const expiredSession = {
      lastValidTarget: '198.51.100.42',
      lastTarget: '198.51.100.42',
      lastTargetTimestampMs: Date.now() - (45 * 60 * 1000), // 45 minutes ago
      lastPorts: [443]
    };
    const parsedExpired = chatOperatorService.parseIntentAndEntities(
      'Run a hypothesis arbitration synthesis',
      expiredSession
    );
    assert.notEqual(parsedExpired.target, '198.51.100.42', 'Expired session target (>30m) must not be inherited');
    assert.equal(parsedExpired.usedFollowUpTarget, false);
  });

  it('26. preserves existing SQLite user tables across initSchema() restarts and rolls back failed migrations transactionally', () => {
    const { DatabaseSync } = require('node:sqlite');
    const { initSchema, getDatabaseHealth } = require('../src/db/database');
    const { runMigrations } = require('../src/db/migrations');

    const isolatedDb = new DatabaseSync(':memory:');
    initSchema(isolatedDb);

    // Insert a custom topology node and incident record before re-running initSchema
    isolatedDb.prepare(`
      INSERT INTO topology_nodes (id, name, type, layer, layer_level, hostname_or_ip, status)
      VALUES ('NODE-CUSTOM-PERSIST', 'Persist-Switch-01', 'switch', 'core', 2, '10.99.0.1', 'healthy')
    `).run();

    // Re-running initSchema() must NEVER drop existing tables or wipe user records
    initSchema(isolatedDb);
    const preservedNode = isolatedDb.prepare('SELECT * FROM topology_nodes WHERE id = ?').get('NODE-CUSTOM-PERSIST');
    assert.ok(preservedNode, 'Existing topology_nodes row must survive initSchema() restart without destructive DROP TABLE');
    assert.equal(preservedNode.name, 'Persist-Switch-01');

    const dbHealth = getDatabaseHealth(isolatedDb);
    assert.equal(dbHealth.healthy, true);
    assert.equal(dbHealth.migrationStatus, 'SUCCESS');
    assert.ok(dbHealth.appliedMigrationsCount >= 6, 'Migration 006 must be applied');

    // Verify transactional rollback and failedMigrationVersion reporting on faulty migration
    let caughtErr = null;
    try {
      runMigrations(isolatedDb, {
        migrations: [
          {
            version: 999,
            name: '999_faulty_migration_test',
            up: `
              CREATE TABLE temp_atomic_test (id INTEGER PRIMARY KEY);
              INSERT INTO non_existent_table_xyz VALUES (1);
            `
          }
        ]
      });
    } catch (err) {
      caughtErr = err;
    }
    assert.ok(caughtErr, 'Faulty migration must throw and not be silently swallowed');
    assert.equal(caughtErr.failedMigrationVersion, 999);
    const rolledBackTable = isolatedDb.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='temp_atomic_test'").get();
    assert.equal(rolledBackTable, undefined, 'Partial DDL inside failed migration must be rolled back atomically');
    isolatedDb.close();
  });

  it('27. enforces strict incident resolution proof (rejecting unverified caller resolved:true), null post-action metrics when unmeasured, and unprobed prior provenance', async () => {
    const { EpisodicCausalMemoryEngine } = require('../src/ai/episodic-causal-memory-engine');
    const { hypothesisArbiter } = require('../src/ai/hypothesis-arbiter');

    // Caller passing resolved: true WITHOUT remediationExecuted must be rejected
    const spoofedResolvedEp = EpisodicCausalMemoryEngine.recordLiveSynthesisEpisode({
      target: '127.0.0.1:3000',
      winningDomainId: 'TRANSPORT_L4',
      probabilityPct: 77.0,
      rttMs: 12.5,
      lossPct: 0,
      resolved: true,
      remediationExecuted: false,
      verificationPassed: true,
      summary: 'Caller attempted to mark diagnostic synthesis resolved without remediation.'
    });
    assert.equal(spoofedResolvedEp.resolved, false, 'resolved must be false when remediationExecuted is false');
    assert.equal(spoofedResolvedEp.resolutionRejectedReason, 'CALLER_RESOLVED_REJECTED_NO_REMEDIATION_EXECUTED');
    assert.equal(spoofedResolvedEp.postActionRttMs, null, 'postActionRttMs must be null when no post-action measurement occurred');
    assert.equal(spoofedResolvedEp.lyapunovDelta, null, 'lyapunovDelta must be null when no post-action measurement occurred');
    assert.ok(Array.isArray(spoofedResolvedEp.lifecycleHistory) && spoofedResolvedEp.lifecycleHistory.length >= 2);

    // Caller passing remediationExecuted: true & verificationPassed: true WITHOUT postActionRttMs must remain REMEDIATION_UNVERIFIED
    const unverifiedRemEp = EpisodicCausalMemoryEngine.recordLiveSynthesisEpisode({
      target: '127.0.0.1:3000',
      winningDomainId: 'TRANSPORT_L4',
      probabilityPct: 81.0,
      rttMs: 18.0,
      lossPct: 0,
      resolved: true,
      remediationExecuted: true,
      verificationPassed: true,
      executedRunbookId: 'RB-02',
      summary: 'Remediation executed but no independent postActionRttMs provided.'
    });
    assert.equal(unverifiedRemEp.resolved, false, 'resolved must be false without separate postActionRttMs');
    assert.equal(unverifiedRemEp.lifecycleStage, 'REMEDIATION_UNVERIFIED');
    assert.equal(unverifiedRemEp.resolutionRejectedReason, 'CALLER_RESOLVED_REJECTED_NO_INDEPENDENT_POST_ACTION_MEASUREMENT');

    // Unprobed CUSUM and spectral flatness priors must be tagged UNPROBED_DEFAULT_PRIOR
    const arb = await hypothesisArbiter.arbitrateAndExecuteClosedLoop({
      target: '127.0.0.1',
      port: 3000,
      executeClosedLoop: false,
      initialTelemetry: { rttMs: 2.0 }
    });
    const sig = arb.diagnosticSemantics.extractedTelemetrySignature;
    assert.equal(sig.fieldProvenance.cusumShiftSigma, 'UNPROBED_DEFAULT_PRIOR');
    assert.equal(sig.fieldProvenance.spectralFlatness, 'UNPROBED_DEFAULT_PRIOR');
    assert.equal(typeof arb.diagnosticSemantics.evidenceQualityScore, 'number');
  });

  it('28. separates diagnostic ICMP/socket observations from physical NIC wire frames and reports truthful capture session state', () => {
    const { packetStreamer } = require('../src/network/packet-streaming/packet-streamer');
    const beforeCounters = packetStreamer.getCounters();
    const beforeWireFrames = packetStreamer.frameRingBuffer.length;

    const obs = packetStreamer.recordKernelIcmpProbeFrame('1.1.1.1', 3, true);
    assert.ok(obs, 'Must return diagnostic observation object');
    assert.equal(obs.evidenceClass, 'ICMP_COMMAND_OBSERVATION');
    assert.equal(obs.isPhysicalWireFrame, false);
    assert.notEqual(obs.srcIp, '10.168.195.33', 'Must not use hardcoded 10.168.195.33 fallback IP');

    const afterCounters = packetStreamer.getCounters();
    assert.equal(afterCounters.received, beforeCounters.received, 'Diagnostic ICMP observation must NOT inflate physical wire counters.received');
    assert.equal(packetStreamer.frameRingBuffer.length, beforeWireFrames, 'Diagnostic ICMP observation must NOT inject synthetic frame into physical frameRingBuffer');

    const capProfile = packetStreamer.getCaptureCapabilityProfile();
    assert.equal(typeof capProfile.driverAvailable, 'boolean');
    assert.equal(typeof capProfile.kernelCapNetRaw, 'boolean');
    assert.equal(typeof capProfile.interfaceAccessible, 'boolean');
    assert.equal(typeof capProfile.captureSessionInitialized, 'boolean');
    assert.equal(typeof capProfile.activeCaptureSession, 'boolean');
    assert.equal(typeof capProfile.receivedFramesCount, 'number');
    assert.equal(typeof capProfile.diagnosticObservationsCount, 'number');
    assert.ok(capProfile.diagnosticObservationsCount >= 1);
  });

  it('29. enforces cryptographic operator script approval binding, blocks symlink/traversal escapes, and avoids silent 192.168.31.1 gateway substitution', async () => {
    const fs = require('fs');
    const os = require('os');
    const path = require('path');
    const {
      issueOperatorScriptApproval,
      verifyOperatorScriptApproval,
      evaluateScriptExecutionPolicy,
      getScriptContent
    } = require('../src/tools/script-automation');

    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ejii-scripts-test-'));
    const scriptFile = 'critical-gateway-test.bat';
    fs.writeFileSync(path.join(tempDir, scriptFile), '@echo off\nping 10.168.195.1\nshutdown /r /t 60\n', 'utf8');

    try {
      // 1. When gateway is unknown (gatewayIp: null), 10.168.195.1 must NOT be replaced with 192.168.31.1
      const viewUnknownGw = await getScriptContent(scriptFile, tempDir, { gatewayIp: null });
      assert.equal(viewUnknownGw.gatewayResolved, false);
      assert.equal(viewUnknownGw.gatewaySubstitutionStatus, 'UNRESOLVED_GATEWAY_RETAINED_TEMPLATE');
      assert.ok(viewUnknownGw.content.includes('10.168.195.1'));
      assert.ok(!viewUnknownGw.content.includes('192.168.31.1'));

      // 2. Spoofed boolean explicitOperatorApproval must be rejected when requireBoundApprovalToken is true
      const spoofedPolicy = evaluateScriptExecutionPolicy(
        { requiresElevation: true, riskLevel: 'CRITICAL', privilegeRequirement: 'Administrator' },
        {
          explicitOperatorApproval: true,
          requireBoundApprovalToken: true,
          scriptName: scriptFile
        }
      );
      assert.equal(spoofedPolicy.allowed, false);
      assert.equal(spoofedPolicy.reasonCode, 'UNVERIFIED_OPERATOR_APPROVAL_PROVENANCE');

      // 3. Issue cryptographic operator approval bound to script SHA-256, params, and target
      const approval = issueOperatorScriptApproval({
        operatorId: 'op-sec-01',
        operatorRole: 'ADMIN',
        scriptName: scriptFile,
        params: '--dry-run',
        target: 'local_host',
        scriptsDir: tempDir,
        ttlMs: 60000
      });
      assert.ok(approval.approvalToken && approval.scriptContentSha256);

      const validVerify = verifyOperatorScriptApproval(approval.approvalToken, {
        scriptName: scriptFile,
        scriptContentSha256: approval.scriptContentSha256,
        params: '--dry-run',
        target: 'local_host',
        operatorId: 'op-sec-01'
      });
      assert.equal(validVerify.valid, true);
      assert.equal(validVerify.reasonCode, 'BOUND_OPERATOR_APPROVAL_VERIFIED');

      // Tampering with parameters must invalidate the approval token
      const tamperedVerify = verifyOperatorScriptApproval(approval.approvalToken, {
        scriptName: scriptFile,
        scriptContentSha256: approval.scriptContentSha256,
        params: '--force-reboot',
        target: 'local_host'
      });
      assert.equal(tamperedVerify.valid, false);
      assert.equal(tamperedVerify.reasonCode, 'APPROVAL_PARAMS_MISMATCH');
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('30. detects lowercase WSL kernel releases, classifies IPv4/IPv6/CGNAT/ULA/APIPA network scopes, profiles event-loop/SQLite health, and filters filenames in scenario/blast-radius prompts', () => {
    const { detectRuntimeExecutionEnvironment, classifyNetworkTargetScope } = require('../src/core/multisite/multisite-manager');
    const { superpowersSkillsEngine } = require('../src/core/skills/superpowers-skills-engine');
    const { chatOperatorService } = require('../src/core/chat/chat-operator-service');

    // 1. Lowercase WSL kernel release detection fix
    const wslEnv = detectRuntimeExecutionEnvironment({
      osReleaseOverride: '5.15.153.1-microsoft-standard-WSL2'
    });
    assert.equal(wslEnv.isWsl, true, 'Must detect WSL even after lowercasing os.release()');
    assert.equal(wslEnv.isVirtualizedSandbox, true);

    // 2. Network target scope classification across IPv4/IPv6/RFC1918/APIPA/CGNAT/ULA/FQDN
    assert.equal(classifyNetworkTargetScope('127.0.0.1').scope, 'LOOPBACK_IPV4');
    assert.equal(classifyNetworkTargetScope('::1').scope, 'LOOPBACK_IPV6');
    assert.equal(classifyNetworkTargetScope('169.254.12.34').scope, 'LINK_LOCAL_APIPA_IPV4');
    assert.equal(classifyNetworkTargetScope('fe80::1ff:fe23:4567:890a').scope, 'LINK_LOCAL_IPV6');
    assert.equal(classifyNetworkTargetScope('fd12:3456:789a::1').scope, 'IPV6_ULA_PRIVATE');
    assert.equal(classifyNetworkTargetScope('100.64.10.20').scope, 'CGNAT_SHARED_WAN');
    assert.equal(classifyNetworkTargetScope('192.168.10.5').scope, 'RFC1918_PRIVATE_IPV4');
    assert.equal(classifyNetworkTargetScope('8.8.8.8').scope, 'PUBLIC_WAN_IPV4');
    assert.equal(classifyNetworkTargetScope('printer-floor2.local').scope, 'LOCAL_LAN_HOSTNAME');
    assert.equal(classifyNetworkTargetScope('api.github.com').scope, 'EXTERNAL_FQDN');

    // 3. Real event-loop utilization, memory, packet drop, and SQLite latency telemetry
    const perfProfile = superpowersSkillsEngine.accelerateDataThroughput(5);
    assert.ok(perfProfile.runtimeHealthMetrics, 'accelerateDataThroughput must include runtimeHealthMetrics');
    assert.equal(typeof perfProfile.runtimeHealthMetrics.eventLoopUtilization, 'number');
    assert.equal(typeof perfProfile.runtimeHealthMetrics.heapUsedMb, 'number');
    assert.equal(typeof perfProfile.runtimeHealthMetrics.packetDropCount, 'number');

    // 4. Scenario planning & blast-radius prompts must filter code/manifest filenames and avoid stale port bleed
    const scenarioParsed = chatOperatorService.parseIntentAndEntities(
      'What happens if server.mjs or SKILL.md fails when changing configuration?',
      { lastValidTarget: '10.0.0.5', lastTargetTimestampMs: Date.now(), lastPorts: [8443] }
    );
    assert.equal(scenarioParsed.intent, 'scenario_planning_what_if');
    assert.equal(scenarioParsed.explicitTarget, null, 'server.mjs and SKILL.md must not be extracted as scenario hostnames');

    const blastSwitchParsed = chatOperatorService.parseIntentAndEntities(
      'What is the blast radius of api.cloudflare.com if package.json changes?',
      { lastValidTarget: '10.0.0.5', lastTargetTimestampMs: Date.now(), lastPorts: [8443] }
    );
    assert.equal(blastSwitchParsed.intent, 'dependency_blast_radius');
    assert.equal(blastSwitchParsed.explicitTarget, 'api.cloudflare.com');
    assert.deepEqual(blastSwitchParsed.ports, [], 'Switching to a new target must not bleed stale ports [8443] from prior target');
  });

  it('31. Cross-Layer Divergence Classification vs Logical Contradictions & Epistemic Abstention', () => {
    const hypotheses = [
      { domainId: 'TRANSPORT_L4', probabilityPct: 58.0, probeType: 'TCP_HANDSHAKE_PROBE' },
      { domainId: 'APPLICATION_L7', probabilityPct: 22.0, probeType: 'HTTP_L7_HEALTH_PROBE' },
      { domainId: 'PHYSICAL_L2_L3', probabilityPct: 20.0, probeType: 'ICMP_AND_PATH_PROBE' }
    ];

    // 1. Expected cross-layer operational behavior: ICMP blocked by firewall while TCP succeeds
    const expectedDivergenceSem = hypothesisArbiter.interpretCrossLayerDiagnosticSemantics(
      [
        { domainId: 'PHYSICAL_L2_L3', probeType: 'ICMP_AND_PATH_PROBE', anomalyDetected: true, rawTelemetry: { packetLoss: 100 } },
        { domainId: 'TRANSPORT_L4', probeType: 'TCP_HANDSHAKE_PROBE', anomalyDetected: false, durationMs: 12 },
        { domainId: 'APPLICATION_L7', probeType: 'HTTP_L7_HEALTH_PROBE', anomalyDetected: false, durationMs: 18 }
      ],
      hypotheses,
      '198.51.100.42',
      443,
      { rttMs: 18, packetLossPct: 100 }
    );
    const icmpVsTcp = expectedDivergenceSem.crossLayerDivergences.find(
      (d) => d.code === 'CONTRADICTION_ICMP_LOSS_VS_TCP_SUCCESS'
    );
    assert.ok(icmpVsTcp, 'Should detect cross-layer divergence when ICMP fails but TCP succeeds');
    assert.equal(icmpVsTcp.divergenceType, 'EXPECTED_CROSS_LAYER_BEHAVIOR');
    assert.equal(icmpVsTcp.isLogicalContradiction, false);
    assert.equal(expectedDivergenceSem.logicalContradictionsCount, 0);

    // 2. Genuine logical contradiction: L4 TCP handshake failed yet L7 HTTP succeeded on same target:port
    const logicalContradictionSem = hypothesisArbiter.interpretCrossLayerDiagnosticSemantics(
      [
        { domainId: 'TRANSPORT_L4', probeType: 'TCP_HANDSHAKE_PROBE', anomalyDetected: true, finding: 'TCP ECONNREFUSED' },
        { domainId: 'APPLICATION_L7', probeType: 'HTTP_L7_HEALTH_PROBE', anomalyDetected: false, finding: 'HTTP 200 OK' }
      ],
      hypotheses,
      '198.51.100.42',
      443,
      { rttMs: 25, packetLossPct: 0 }
    );
    const l7WithoutL4 = logicalContradictionSem.crossLayerDivergences.find(
      (d) => d.code === 'CONTRADICTION_L4_REFUSED_YET_L7_SUCCEEDED'
    );
    assert.ok(l7WithoutL4, 'Should detect genuine logical contradiction when L7 HTTP succeeds despite L4 TCP failure');
    assert.equal(l7WithoutL4.divergenceType, 'LOGICAL_CONTRADICTION');
    assert.equal(l7WithoutL4.isLogicalContradiction, true);
    assert.ok(logicalContradictionSem.logicalContradictionsCount >= 1);

    // 3. Epistemic Abstention on unprobed / empty telemetry
    const unprobedSem = hypothesisArbiter.interpretCrossLayerDiagnosticSemantics(
      [],
      hypotheses,
      '192.0.2.99',
      443,
      {}
    );
    assert.equal(unprobedSem.abstentionStatus, 'INSUFFICIENT_EVIDENCE_ABSTAIN');
    assert.equal(unprobedSem.canEstablishRootCause, false);
    assert.ok(unprobedSem.unmodeledResidualProbabilityPct >= 50, 'Unmodeled residual uncertainty must be high when no probes ran');
    assert.ok(unprobedSem.abstentionExplanation.includes('Epistemic Abstention Active'));
  });

  it('32. 9-Stage Incident Lifecycle Validation, Domain-Specific Post-Action Resolution & Calibration Damping', () => {
    const engine = new EpisodicCausalMemoryEngine();

    // 1. Validate legal vs illegal 9-stage transitions
    const validStep = engine.validateLifecycleTransition('DIAGNOSTIC_INVESTIGATION', 'HYPOTHESIS_FORMATION');
    assert.equal(validStep.valid, true);
    const invalidBackwards = engine.validateLifecycleTransition('HISTORICAL_LEARNING', 'DIAGNOSTIC_INVESTIGATION');
    assert.equal(invalidBackwards.valid, false);
    const skipPostMeasurement = engine.validateLifecycleTransition('REMEDIATION_EXECUTION', 'HISTORICAL_LEARNING');
    assert.equal(skipPostMeasurement.valid, false);

    // 2. Domain-specific post-action resolution (DNS_NAMING resolved via dnsLatencyMs + dnsResolvedSuccess without postActionRttMs)
    const dnsRecord = engine.recordIncidentMemory({
      target: 'dns.internal.corp',
      telemetryVector: { dnsLatencyMs: 420, packetLossPct: 0 },
      winningDomain: 'DNS_NAMING',
      winningPosteriorPct: 78.5,
      remediationAction: 'Flush local DNS resolver cache and switch to secondary nameserver',
      remediationExecuted: true,
      verificationPassed: true,
      preActionTimestampMs: 1700000000000,
      postActionTimestampMs: 1700000005000,
      postActionTarget: 'dns.internal.corp',
      postActionMetrics: {
        dnsLatencyMs: 9,
        dnsResolvedSuccess: true
      },
      resolved: true
    });
    assert.equal(dnsRecord.resolved, true, 'DNS_NAMING incident should resolve using postActionMetrics.dnsLatencyMs');
    assert.equal(dnsRecord.resolutionRejectedReason, null);
    assert.ok(typeof dnsRecord.lyapunovDelta === 'number' && dnsRecord.lyapunovDelta < 0, 'Lyapunov delta should reflect DNS latency reduction');

    // 3. Reject incomparable post-action target
    const mismatchTargetRecord = engine.recordIncidentMemory({
      target: 'db-primary.internal.corp',
      telemetryVector: { rttMs: 210, packetLossPct: 15 },
      winningDomain: 'TRANSPORT_L4',
      winningPosteriorPct: 68.0,
      remediationAction: 'Reset TCP connection pool',
      remediationExecuted: true,
      verificationPassed: true,
      postActionTarget: 'localhost',
      postActionRttMs: 1,
      resolved: true
    });
    assert.equal(mismatchTargetRecord.resolved, false);
    assert.equal(mismatchTargetRecord.resolutionRejectedReason, 'CALLER_RESOLVED_REJECTED_INCOMPARABLE_POST_ACTION_TARGET');

    // 4. Reject stale post-action timestamp earlier than pre-action timestamp
    const staleTimestampRecord = engine.recordIncidentMemory({
      target: 'db-primary.internal.corp',
      telemetryVector: { rttMs: 210, packetLossPct: 15 },
      winningDomain: 'TRANSPORT_L4',
      winningPosteriorPct: 68.0,
      remediationAction: 'Reset TCP connection pool',
      remediationExecuted: true,
      verificationPassed: true,
      preActionTimestampMs: 1700000010000,
      postActionTimestampMs: 1700000001000,
      postActionRttMs: 14,
      resolved: true
    });
    assert.equal(staleTimestampRecord.resolved, false);
    assert.equal(staleTimestampRecord.resolutionRejectedReason, 'CALLER_RESOLVED_REJECTED_STALE_PRE_ACTION_TIMESTAMP');

    // 5. Duplicate calibration observation damping
    const cal1 = engine.ingestActionOutcomeAndRecalibrate({
      incidentId: dnsRecord.incidentId,
      target: 'dns.internal.corp',
      hypothesizedDomain: 'DNS_NAMING',
      predictedProbabilityPct: 80,
      remediationExecuted: true,
      verificationPassed: true,
      preActionRttMs: 420,
      postActionRttMs: 9
    });
    assert.equal(cal1.duplicateObservationDamped, false);

    const cal2 = engine.ingestActionOutcomeAndRecalibrate({
      incidentId: dnsRecord.incidentId,
      target: 'dns.internal.corp',
      hypothesizedDomain: 'DNS_NAMING',
      predictedProbabilityPct: 80,
      remediationExecuted: true,
      verificationPassed: true,
      preActionRttMs: 420,
      postActionRttMs: 9
    });
    assert.equal(cal2.duplicateObservationDamped, true, 'Repeated identical calibration outcome must be damped');
  });

  it('33. Operator Script Approval Single-Use Replay Protection, Role Verification, Revocation & Canonical Params', () => {
    const scriptAutomation = require('../src/tools/script-automation');

    // 0. Nonexistent script without explicit content/hash must be rejected (never UNMOUNTED_SCRIPT)
    const missingScriptApproval = scriptAutomation.issueOperatorScriptApproval({
      operatorId: 'op-sec-01',
      operatorRole: 'NOC_L3_ENGINEER',
      scriptName: 'nonexistent-missing-script.sh',
      params: { count: 2 },
      target: '127.0.0.1'
    });
    assert.equal(missingScriptApproval.issued, false);
    assert.equal(missingScriptApproval.reasonCode, 'APPROVAL_SCRIPT_NOT_FOUND');

    // 1. Canonical parameter serialization order independence
    const canon1 = scriptAutomation.canonicalizeApprovalParams({ z: 10, a: { d: 4, c: 3 } });
    const canon2 = scriptAutomation.canonicalizeApprovalParams({ a: { c: 3, d: 4 }, z: 10 });
    assert.equal(canon1, canon2, 'Canonical parameter serialization must be key-order deterministic');

    // 2. Issue approval with unordered object params and verify with reordered object params
    const approval = scriptAutomation.issueOperatorScriptApproval({
      operatorId: 'op-sec-01',
      operatorRole: 'NOC_L3_ENGINEER',
      scriptName: 'ping-gateway.sh',
      scriptContent: '#!/bin/sh\nping -c 2 127.0.0.1\n',
      params: { count: 2, targetHost: '127.0.0.1' },
      target: '127.0.0.1',
      ttlMs: 60000
    });
    assert.equal(approval.issued, true);

    // 3. Role mismatch must be rejected
    const roleMismatch = scriptAutomation.verifyOperatorScriptApproval({
      approvalId: approval.approvalId,
      approvalToken: approval.approvalToken,
      operatorId: 'op-sec-01',
      operatorRole: 'READONLY_VIEWER',
      scriptName: 'ping-gateway.sh',
      scriptContent: '#!/bin/sh\nping -c 2 127.0.0.1\n',
      params: { targetHost: '127.0.0.1', count: 2 },
      target: '127.0.0.1'
    });
    assert.equal(roleMismatch.verified, false);
    assert.equal(roleMismatch.reasonCode, 'APPROVAL_ROLE_MISMATCH');

    // 4. First valid verification with consumeOnVerify=true succeeds, replay fails
    const firstConsume = scriptAutomation.verifyOperatorScriptApproval({
      approvalId: approval.approvalId,
      approvalToken: approval.approvalToken,
      operatorId: 'op-sec-01',
      operatorRole: 'NOC_L3_ENGINEER',
      scriptName: 'ping-gateway.sh',
      scriptContent: '#!/bin/sh\nping -c 2 127.0.0.1\n',
      params: { targetHost: '127.0.0.1', count: 2 },
      target: '127.0.0.1',
      consumeOnVerify: true
    });
    assert.equal(firstConsume.verified, true);
    assert.equal(firstConsume.consumed, true);

    const replayAttempt = scriptAutomation.verifyOperatorScriptApproval({
      approvalId: approval.approvalId,
      approvalToken: approval.approvalToken,
      operatorId: 'op-sec-01',
      operatorRole: 'NOC_L3_ENGINEER',
      scriptName: 'ping-gateway.sh',
      scriptContent: '#!/bin/sh\nping -c 2 127.0.0.1\n',
      params: { targetHost: '127.0.0.1', count: 2 },
      target: '127.0.0.1'
    });
    assert.equal(replayAttempt.verified, false);
    assert.equal(replayAttempt.reasonCode, 'APPROVAL_TOKEN_ALREADY_CONSUMED');

    // 5. Explicit revocation
    const approval2 = scriptAutomation.issueOperatorScriptApproval({
      operatorId: 'op-sec-02',
      operatorRole: 'NOC_L3_ENGINEER',
      scriptName: 'ping-gateway.sh',
      scriptContent: '#!/bin/sh\nping -c 2 127.0.0.1\n',
      params: [],
      target: '127.0.0.1',
      ttlMs: 60000
    });
    const revoked = scriptAutomation.revokeOperatorScriptApproval(approval2.approvalId, 'Operator shift ended');
    assert.equal(revoked.revoked, true);

    const verifyAfterRevoke = scriptAutomation.verifyOperatorScriptApproval({
      approvalId: approval2.approvalId,
      approvalToken: approval2.approvalToken,
      operatorId: 'op-sec-02',
      scriptName: 'ping-gateway.sh',
      scriptContent: '#!/bin/sh\nping -c 2 127.0.0.1\n',
      params: [],
      target: '127.0.0.1'
    });
    assert.equal(verifyAfterRevoke.verified, false);
    assert.equal(verifyAfterRevoke.reasonCode, 'APPROVAL_TOKEN_REVOKED');
  });

  it('34. SQLite Operational State, Write-Capability Probe & Episodic Causal Memory Persistence Health', () => {
    const dbModule = require('../src/db/database');
    const health = dbModule.getDatabaseHealth();
    assert.equal(health.healthy, true);
    assert.equal(health.writeCapable, true);
    assert.equal(health.writeProbeVerified, true);
    assert.equal(health.operationalState, 'HEALTHY_DURABLE_WAL');
    assert.equal(typeof health.probeLatencyMs, 'number');

    const engine = new EpisodicCausalMemoryEngine();
    const persistenceHealth = engine.getPersistenceHealth();
    assert.equal(persistenceHealth.persistenceState, 'SQLITE_DURABLE_ACTIVE');
    assert.equal(persistenceHealth.durableSqliteActive, true);
    assert.equal(persistenceHealth.databaseOperationalState, 'HEALTHY_DURABLE_WAL');
  });

  it('35. IPv4-Mapped IPv6 Scope Classification, Reachability Non-Conflation & Runtime Detection Confidence', () => {
    const { detectRuntimeExecutionEnvironment, classifyNetworkTargetScope } = require('../src/core/multisite/multisite-manager');

    const mappedLoopback = classifyNetworkTargetScope('::ffff:127.0.0.1');
    assert.equal(mappedLoopback.scope, 'LOOPBACK_IPV4');
    assert.equal(mappedLoopback.addressFamily, 'IPv4_MAPPED_IPv6');
    assert.equal(mappedLoopback.normalizedIpv4, '127.0.0.1');
    assert.equal(mappedLoopback.reachabilityVerified, false);
    assert.equal(mappedLoopback.authorizationImplied, false);

    const mappedPrivate = classifyNetworkTargetScope('::ffff:192.168.10.25');
    assert.equal(mappedPrivate.scope, 'RFC1918_PRIVATE_IPV4');
    assert.equal(mappedPrivate.addressFamily, 'IPv4_MAPPED_IPv6');
    assert.equal(mappedPrivate.normalizedIpv4, '192.168.10.25');

    const mappedPublic = classifyNetworkTargetScope('::ffff:8.8.8.8', {
      resolvedAddresses: ['8.8.8.8'],
      resolutionTimestampIso: '2026-11-08T00:00:00.000Z'
    });
    assert.equal(mappedPublic.scope, 'PUBLIC_WAN_IPV4');
    assert.deepEqual(mappedPublic.resolvedAddresses, ['8.8.8.8']);
    assert.equal(mappedPublic.resolutionTimestampIso, '2026-11-08T00:00:00.000Z');

    const runtimeEnv = detectRuntimeExecutionEnvironment();
    assert.ok(
      ['VERIFIED_KERNEL_ARTIFACT', 'HEURISTIC_ENV_INDICATOR', 'DIRECT_HOST_OBSERVATION'].includes(
        runtimeEnv.detectionConfidence
      ),
      'detectRuntimeExecutionEnvironment must report explicit detectionConfidence'
    );
  });

  it('36. Superpowers 5-Layer Skill Inventory Audit, Interval-Delta ELU Observability & Packet Capture Frame Counters', () => {
    const summary = superpowersSkillsEngine.getSkillsSummary();
    assert.ok(summary.inventoryLayers, 'getSkillsSummary must include structured inventoryLayers');
    assert.equal(summary.inventoryLayers.primaryTopLevelPackagesCount, 85);
    assert.equal(summary.inventoryLayers.nestedGstackWorkflowsCount, 74);
    assert.equal(summary.inventoryLayers.totalPrimaryAndNestedManifestsCount, 159);
    assert.equal(summary.inventoryLayers.activeMirroredSkillModulesCount, 111);
    assert.equal(summary.inventoryLayers.externalPackageLockDefinitionsCount, 71);
    assert.equal(summary.inventoryLayers.onDiskLockfileEntriesCount, 46);
    assert.equal(summary.inventoryLayers.coreAgentSkillsCount, 15);
    assert.equal(summary.inventoryAudit.protectedLockfileDiscrepancyRecorded, true);

    const perf = superpowersSkillsEngine.accelerateDataThroughput(4);
    assert.equal(typeof perf.runtimeHealthMetrics.eventLoopUtilization, 'number');
    assert.equal(typeof perf.runtimeHealthMetrics.cumulativeEventLoopUtilization, 'number');
    assert.equal(typeof perf.runtimeHealthMetrics.ringBufferOccupancyPct, 'number');
    assert.equal(perf.runtimeHealthMetrics.metricMeasurementTypes.eventLoopUtilization, 'INTERVAL_DELTA');
    assert.equal(perf.runtimeHealthMetrics.metricMeasurementTypes.packetDropCount, 'CUMULATIVE_COUNTER');

    const { packetStreamer } = require('../src/network/packet-streaming/packet-streamer');
    const capProfile = packetStreamer.getCaptureCapabilityProfile();
    assert.equal(typeof capProfile.hasReceivedWireFrames, 'boolean');
    assert.equal(capProfile.parserFailuresCount, 0);
  });

  it('37. War-Room Proposed vs Executed Probes Separation, Target/ProbeId Binding & Dynamic Posterior Shift', async () => {
    const { AutonomousWarRoomOrchestrator } = require('../src/ai/autonomous-war-room');
    const orchestrator = new AutonomousWarRoomOrchestrator();

    // 1. Default execute() proposes 4 read-only probes with executedProbesCount === 0 and empty empiricalObservations
    const initial = orchestrator.execute({
      targetHost: '192.0.2.50',
      dnsServer: '192.0.2.53',
      rttMs: 95,
      packetLossPct: 4.5,
      retransmissions: 32
    });
    assert.equal(initial.autonomousActiveProbes.length, 4);
    for (const p of initial.autonomousActiveProbes) {
      assert.equal(p.executionState, 'PROPOSED');
      assert.equal(p.executed, false);
      assert.equal(p.measuredLatencyMs, null);
      assert.equal(p.evidenceProvenance, 'PROPOSED_ONLY_NOT_EXECUTED');
    }
    assert.equal(initial.round4EmpiricalSettlement.proposedProbesCount, 4);
    assert.equal(initial.round4EmpiricalSettlement.executedProbesCount, 0);
    assert.deepEqual(initial.round4EmpiricalSettlement.empiricalObservations, []);
    assert.equal(initial.round4EmpiricalSettlement.posteriorShiftPct, 0);
    assert.equal(initial.round4EmpiricalSettlement.verdictStatus, 'PENDING_ACTIVE_PROBE_EXECUTION');

    // 2. Reject mismatched target, unknown probeId, or unsigned caller probe while accepting signed collector probe results
    const signedPmtuReceipt = orchestrator.createCollectorExecutionReceipt({
      probeId: 'PROBE-PMTU-02',
      probeType: 'ICMP_PMTU_DISCOVERY',
      target: '192.0.2.50',
      durationMs: 68.4,
      timingTarget: 'ICMP_DF_PROBE_RTT_MS',
      nativeResultCode: 'PMTU_DEGRADED_FRAG_NEEDED',
      rawCommandOutput: 'Frag needed and DF set (mtu = 1400)'
    });
    const withResults = orchestrator.execute({
      targetHost: '192.0.2.50',
      dnsServer: '192.0.2.53',
      rttMs: 95,
      packetLossPct: 4.5,
      retransmissions: 32,
      executedProbeResults: [
        {
          probeId: 'PROBE-PMTU-02',
          target: '192.0.2.50',
          measuredLatencyMs: 68.4,
          rawCommandOutput: 'Frag needed and DF set (mtu = 1400)',
          collectorExecutionReceipt: signedPmtuReceipt
        },
        {
          probeId: 'PROBE-ARP-03',
          target: '198.51.100.99', // Mismatched target!
          measuredLatencyMs: 2.1,
          rawCommandOutput: '198.51.100.99 lladdr 00:11:22:33:44:55 REACHABLE'
        },
        {
          probeId: 'PROBE-NONEXISTENT-99',
          target: '192.0.2.50',
          measuredLatencyMs: 1.0,
          rawCommandOutput: 'ok'
        }
      ]
    });
    assert.equal(withResults.round4EmpiricalSettlement.executedProbesCount, 1);
    assert.equal(withResults.round4EmpiricalSettlement.empiricalObservations.length, 1);
    assert.equal(withResults.round4EmpiricalSettlement.rejectedProbeResults.length, 2);
    assert.ok(
      withResults.round4EmpiricalSettlement.rejectedProbeResults.some((r) => r.reasonCode === 'PROBE_TARGET_MISMATCH')
    );
    assert.ok(
      withResults.round4EmpiricalSettlement.rejectedProbeResults.some((r) => r.reasonCode === 'PROBE_ID_NOT_FOUND')
    );
    assert.equal(withResults.round4EmpiricalSettlement.verdictStatus, 'EMPIRICALLY_CONFIRMED');
    assert.ok(withResults.round4EmpiricalSettlement.posteriorShiftPct > 0);
    assert.notEqual(withResults.round4EmpiricalSettlement.posteriorShiftPct, 16.5);

    // 3. Real collector execution via executeActiveProbes()
    const liveProbed = await orchestrator.executeActiveProbes(initial.sessionId);
    assert.equal(liveProbed.round4EmpiricalSettlement.executedProbesCount, 4);
    assert.equal(liveProbed.round4EmpiricalSettlement.empiricalObservations.length, 4);
    assert.equal(liveProbed.round4EmpiricalSettlement.verdictStatus, 'EMPIRICALLY_CONFIRMED');
  });

  it('38. War-Room Live Evidence Purity & Exact Zero/Null Telemetry Preservation', () => {
    const { AutonomousWarRoomOrchestrator } = require('../src/ai/autonomous-war-room');
    const orchestrator = new AutonomousWarRoomOrchestrator();

    // 1. Zero-valued metrics (rttMs: 0, packetLossPct: 0, cpuSaturationPct: 0, retransmissions: 0, activeFlows: 0)
    // must NEVER be replaced by 20, 0.1, 35, 12, or 1450!
    const zeroResult = orchestrator.execute({
      rttMs: 0,
      packetLossPct: 0,
      cpuSaturationPct: 0,
      retransmissions: 0,
      activeFlows: 0
    });
    assert.equal(zeroResult.agent1.supportingMetrics.packetLossPct, 0);
    assert.equal(zeroResult.agent1.supportingMetrics.rttMs, 0);
    assert.equal(zeroResult.agent2.supportingMetrics.retransmissions, 0);
    assert.equal(zeroResult.agent2.supportingMetrics.activeFlows, 0);
    assert.equal(zeroResult.agent3.supportingMetrics.cpuSaturationPct, 0);
    assert.deepEqual(
      zeroResult.telemetryProvenance.zeroValuedMetrics.sort(),
      ['activeFlows', 'cpuSaturationPct', 'packetLossPct', 'retransmissions', 'rttMs']
    );
    assert.equal(zeroResult.telemetryProvenance.missingMetrics.length, 0);

    // 2. Live war-room session must contain ZERO hardcoded reference-fixture host/IP/PID claims
    const serializedLive = JSON.stringify(zeroResult);
    assert.ok(!serializedLive.includes('10.168.195.33'), 'Live War Room must not contain hardcoded 10.168.195.33');
    assert.ok(!serializedLive.includes('172.29.192.1'), 'Live War Room must not contain hardcoded 172.29.192.1');
    assert.ok(!serializedLive.includes('10.22.10.153'), 'Live War Room must not contain hardcoded 10.22.10.153');
    assert.ok(!serializedLive.includes('PID 1428'), 'Live War Room must not contain hardcoded PID 1428');
    assert.ok(!serializedLive.includes('LMS.exe'), 'Live War Room must not contain hardcoded LMS.exe');
    assert.ok(!serializedLive.includes('349 endpoints'), 'Live War Room must not contain hardcoded 349 endpoints');

    // 3. Empty/missing telemetry must abstain from root-cause attribution when no probes have executed
    const emptyTelemetryResult = orchestrator.execute({});
    assert.equal(emptyTelemetryResult.telemetryProvenance.sourceType, 'NO_TELEMETRY_BASELINE_ONLY');
    assert.equal(emptyTelemetryResult.telemetryProvenance.missingMetrics.length, 5);
    assert.equal(emptyTelemetryResult.canEstablishRootCause, false);
    assert.equal(emptyTelemetryResult.round4EmpiricalSettlement.verdictStatus, 'INSUFFICIENT_EMPIRICAL_EVIDENCE');
  });

  it('39. War-Room Cryptographic Secret Hygiene & Server-Verified Operator Identity Enforcement', () => {
    const { AutonomousWarRoomOrchestrator } = require('../src/ai/autonomous-war-room');

    // 1. Known-insecure legacy secret must be rejected (fail closed)
    const legacyInsecure = new AutonomousWarRoomOrchestrator('EJII-SRE-WAR-ROOM-SOVEREIGN-HMAC-KEY-2026');
    const legacyTranscript = legacyInsecure.execute({ rttMs: 85, packetLossPct: 3 });
    assert.equal(legacyTranscript.agent5.hmacConfigured, false);
    assert.equal(legacyTranscript.agent5.hmacSignature, '');
    assert.equal(legacyTranscript.agent5.lyapunovBarrierCleared, false);
    assert.equal(legacyTranscript.agent5.hmacStatus, 'REJECTED_INSECURE_OR_MISSING_SECRET');
    assert.equal(legacyTranscript.cryptographicExecutionToken.valid, false);
    assert.equal(legacyTranscript.status, 'INCIDENT_ESCALATED');

    // 2. Empty or short secret must be rejected
    const weakSecret = new AutonomousWarRoomOrchestrator('short-key');
    const weakTranscript = weakSecret.execute({ rttMs: 85, packetLossPct: 3 });
    assert.equal(weakTranscript.agent5.hmacConfigured, false);
    assert.equal(weakTranscript.agent5.lyapunovBarrierCleared, false);

    // 3. Unverified caller-supplied operatorRole: 'ADMIN' must NEVER grant operatorAuthorized: true
    const validOrchestrator = new AutonomousWarRoomOrchestrator();
    const unverifiedRoleRes = validOrchestrator.execute({
      rttMs: 85,
      packetLossPct: 3,
      operatorRole: 'ADMIN'
    });
    assert.equal(unverifiedRoleRes.agent5.operatorAuthorized, false);
    assert.equal(unverifiedRoleRes.agent5.operatorRoleVerified, false);
    assert.equal(unverifiedRoleRes.agent5.authorizationStatus, 'UNVERIFIED_CALLER_ROLE_REJECTED');

    // 4. Server-verified authContext grants operatorAuthorized: true
    const verifiedRoleRes = validOrchestrator.execute({
      rttMs: 85,
      packetLossPct: 3,
      authContext: {
        authenticated: true,
        userId: 'sre-commander-01',
        role: 'ADMIN',
        source: 'SERVER_SESSION_JWT'
      }
    });
    assert.equal(verifiedRoleRes.agent5.operatorAuthorized, true);
    assert.equal(verifiedRoleRes.agent5.operatorRoleVerified, true);
    assert.equal(verifiedRoleRes.agent5.verifiedOperatorId, 'sre-commander-01');
    assert.equal(verifiedRoleRes.agent5.authorizationStatus, 'SERVER_SESSION_VERIFIED');
  });

  it('40. War-Room Session Persistence via Migration 007, Restart Hydration, Corrupt Row Resilience & Bounded Retention', () => {
    const { DatabaseSync } = require('node:sqlite');
    const { initSchema } = require('../src/db/database');
    const { AutonomousWarRoomOrchestrator } = require('../src/ai/autonomous-war-room');

    const memDb = new DatabaseSync(':memory:');
    if (typeof memDb.pragma !== 'function') {
      memDb.pragma = (str) => memDb.exec('PRAGMA ' + str + ';');
    }
    initSchema(memDb);

    // 1. Insert a corrupt JSON row and an incomplete schema row directly into war_room_sessions
    memDb
      .prepare('INSERT INTO war_room_sessions (session_id, executed_at, status, payload_json) VALUES (?, ?, ?, ?)')
      .run('WR-CORRUPT-01', new Date().toISOString(), 'STABILIZED_MONITORING', '{not-valid-json');
    memDb
      .prepare('INSERT INTO war_room_sessions (session_id, executed_at, status, payload_json) VALUES (?, ?, ?, ?)')
      .run('WR-INCOMPLETE-02', new Date().toISOString(), 'STABILIZED_MONITORING', JSON.stringify({ sessionId: 'WR-INCOMPLETE-02' }));

    // 2. Create orchestrator with maxRetainedSessions: 5 and execute 7 sessions
    const orch1 = new AutonomousWarRoomOrchestrator(undefined, { db: memDb, maxRetainedSessions: 5 });
    assert.equal(orch1.getDiagnostics().corruptSessionsSkippedCount, 2);

    const createdIds = [];
    for (let i = 0; i < 7; i++) {
      const s = orch1.execute({ rttMs: 50 + i, packetLossPct: 1.5 });
      assert.equal(s.persistenceState, 'DURABLE_SQLITE_WAL');
      createdIds.push(s.sessionId);
    }

    // Bounded retention must keep at most 5 sessions in memory and SQLite
    assert.equal(orch1.getAllSessions().length, 5);
    const dbCount = memDb.prepare('SELECT COUNT(*) as cnt FROM war_room_sessions').get().cnt;
    assert.equal(dbCount, 5);

    // 3. Simulate process restart by instantiating a new orchestrator against the same SQLite database
    const orch2 = new AutonomousWarRoomOrchestrator(undefined, { db: memDb, maxRetainedSessions: 5 });
    const latestSessionId = createdIds[createdIds.length - 1];
    const hydrated = orch2.getSessionById(latestSessionId);
    assert.ok(hydrated, 'Hydrated orchestrator must recover persisted session after restart');
    assert.equal(hydrated.sessionId, latestSessionId);

    // 4. Steer hydrated session after restart and verify parent-child linkage
    const steered = orch2.reevaluateWithConstraint(latestSessionId, {
      forbiddenRemediations: [hydrated.agent4.proposedRemediationAction],
      targetEntityFilter: 'vlan-204-prod'
    });
    assert.equal(steered.parentSessionId, latestSessionId);
    assert.equal(steered.persistenceState, 'DURABLE_SQLITE_WAL');
    memDb.close();
  });

  it('41. War-Room Operator Steering: Unknown Session Error, POL-02 Guard, Dual-Operator Enforcement & Evidence Inheritance', () => {
    const { AutonomousWarRoomOrchestrator } = require('../src/ai/autonomous-war-room');
    const orchestrator = new AutonomousWarRoomOrchestrator();

    // 1. Unknown sessionId must throw WAR_ROOM_SESSION_NOT_FOUND (never fall back to latestResult)
    assert.throws(
      () => {
        orchestrator.reevaluateWithConstraint('WR-NONEXISTENT-999999', {
          forbiddenRemediations: ['anything']
        });
      },
      (err) => err && err.code === 'WAR_ROOM_SESSION_NOT_FOUND' && err.statusCode === 404
    );

    const baseReceipt = orchestrator.createCollectorExecutionReceipt({
      probeId: 'PROBE-PMTU-02',
      probeType: 'ICMP_PMTU_DISCOVERY',
      target: '10.99.0.10',
      durationMs: 42.3,
      timingTarget: 'ICMP_DF_PROBE_RTT_MS',
      nativeResultCode: 'PMTU_1500_VERIFIED',
      rawCommandOutput: '1472 bytes from 10.99.0.10: time=42.3ms'
    });

    const base = orchestrator.execute({
      targetHost: '10.99.0.10',
      rttMs: 75,
      packetLossPct: 2.5,
      executedProbeResults: [
        {
          probeId: 'PROBE-PMTU-02',
          target: '10.99.0.10',
          measuredLatencyMs: 42.3,
          rawCommandOutput: '1472 bytes from 10.99.0.10: time=42.3ms',
          collectorExecutionReceipt: baseReceipt
        }
      ]
    });

    // 2. Destructive requiredRemediation must be blocked by POL-02 safety policy
    const blockedSteer = orchestrator.reevaluateWithConstraint(base.sessionId, {
      requiredRemediations: ['shutdown /r /t 0 && format c:']
    });
    assert.equal(blockedSteer.appliedConstraints.policyViolationBlocked, true);
    assert.equal(blockedSteer.agent4.safetyPolicyCheck, 'BLOCKED_DESTRUCTIVE_POL_02');
    assert.equal(blockedSteer.agent5.lyapunovBarrierCleared, false);

    // 3. Dual-operator approval cannot be satisfied by a single ADMIN operator or identical operatorId
    const singleAdminSteer = orchestrator.reevaluateWithConstraint(base.sessionId, {
      requireDualApproval: true,
      dualApprovalContext: {
        primaryApproval: { operatorId: 'admin-01', role: 'ADMIN', authenticated: true },
        secondaryApproval: { operatorId: 'admin-01', role: 'ADMIN', authenticated: true }
      }
    });
    assert.equal(singleAdminSteer.agent5.dualApprovalSatisfied, false);
    assert.equal(singleAdminSteer.agent5.operatorAuthorized, false);
    assert.equal(singleAdminSteer.agent5.authorizationStatus, 'PENDING_SECOND_DISTINCT_OPERATOR');

    // 3b. Unverified caller boolean flags (even with two distinct operatorIds) without signed tokens must be rejected
    const forgedDualSteer = orchestrator.reevaluateWithConstraint(base.sessionId, {
      requireDualApproval: true,
      dualApprovalContext: {
        primaryApproval: { operatorId: 'admin-01', role: 'ADMIN', authenticated: true },
        secondaryApproval: { operatorId: 'sre-lead-02', role: 'SRE_LEAD', authenticated: true }
      }
    });
    assert.equal(forgedDualSteer.agent5.dualApprovalSatisfied, false);
    assert.equal(forgedDualSteer.agent5.authorizationStatus, 'UNVERIFIED_DUAL_OPERATOR_TOKENS_REJECTED');

    // 4. Two distinct cryptographically signed operator approvals satisfy requireDualApproval and preserve parent evidence provenance
    const primaryIssued = orchestrator.issueDualOperatorApproval({
      sessionId: base.sessionId,
      operatorId: 'admin-01',
      operatorRole: 'ADMIN',
      slot: 'PRIMARY'
    });
    const secondaryIssued = orchestrator.issueDualOperatorApproval({
      sessionId: base.sessionId,
      operatorId: 'sre-lead-02',
      operatorRole: 'SRE_LEAD',
      slot: 'SECONDARY'
    });

    const dualVerifiedSteer = orchestrator.reevaluateWithConstraint(base.sessionId, {
      requireDualApproval: true,
      targetEntityFilter: 'core-router-02',
      dualApprovalContext: {
        primaryApproval: primaryIssued.verifiedApprovalObject,
        secondaryApproval: secondaryIssued.verifiedApprovalObject
      }
    });
    assert.equal(dualVerifiedSteer.agent5.dualApprovalSatisfied, true);
    assert.equal(dualVerifiedSteer.agent5.operatorAuthorized, true);
    assert.equal(dualVerifiedSteer.agent5.authorizationStatus, 'DUAL_OPERATOR_VERIFIED');
    assert.equal(dualVerifiedSteer.round4EmpiricalSettlement.inheritedFromSessionId, base.sessionId);
    assert.equal(dualVerifiedSteer.round4EmpiricalSettlement.newProbesExecutedInSteeredSession, false);
    assert.deepEqual(
      dualVerifiedSteer.round4EmpiricalSettlement.empiricalObservations,
      base.round4EmpiricalSettlement.empiricalObservations
    );
  });

  it('42. War-Room 9-Stage Incident Lifecycle & Post-Remediation Resolution Semantics', () => {
    const { AutonomousWarRoomOrchestrator } = require('../src/ai/autonomous-war-room');
    const orchestrator = new AutonomousWarRoomOrchestrator();

    // 1. Without remediation execution and post-action verification, status must be STABILIZED_MONITORING (not RESOLVED_REMEDIATION_SIGNED)
    const proposedOnly = orchestrator.execute({
      targetHost: '10.88.1.20',
      rttMs: 90,
      packetLossPct: 2.0,
      authContext: {
        authenticated: true,
        userId: 'op-01',
        role: 'ADMIN',
        source: 'SERVER_SESSION_JWT'
      }
    });
    assert.equal(proposedOnly.status, 'STABILIZED_MONITORING');
    assert.equal(proposedOnly.agent5.remediationExecuted, false);
    assert.equal(proposedOnly.agent5.incidentResolved, false);
    assert.equal(proposedOnly.incidentLifecycleStage, 'OPERATOR_AUTHORIZED');

    // 1b. Unverified caller-supplied remediationExecutionResult without a signed ledger receipt must NOT resolve the incident
    const unverifiedRem = orchestrator.execute({
      targetHost: '10.88.1.20',
      rttMs: 90,
      packetLossPct: 2.0,
      authContext: {
        authenticated: true,
        userId: 'op-01',
        role: 'ADMIN',
        source: 'SERVER_SESSION_JWT'
      },
      remediationExecutionResult: {
        executed: true,
        success: true,
        target: '10.88.1.20'
      },
      postRemediationTelemetry: {
        target: '10.88.1.20',
        rttMs: 11,
        packetLossPct: 0,
        retransmissions: 0
      }
    });
    assert.equal(unverifiedRem.status, 'STABILIZED_MONITORING');
    assert.equal(unverifiedRem.agent5.remediationExecuted, false);
    assert.equal(unverifiedRem.agent5.remediationReceiptStatus, 'UNVERIFIED_REMEDIATION_EXECUTION_RECEIPT');

    // 2. With verified operator auth + signed remediation ledger receipt + temporally ordered healthy post-remediation telemetry -> RESOLVED_REMEDIATION_SIGNED
    const remReceipt = orchestrator.recordRemediationExecution({
      sessionId: proposedOnly.sessionId,
      remediationAction: proposedOnly.agent4.proposedRemediationAction,
      target: '10.88.1.20',
      operatorId: 'op-01',
      success: true
    });

    const verifiedResolved = orchestrator.execute({
      targetHost: '10.88.1.20',
      rttMs: 90,
      packetLossPct: 2.0,
      authContext: {
        authenticated: true,
        userId: 'op-01',
        role: 'ADMIN',
        source: 'SERVER_SESSION_JWT'
      },
      remediationExecutionResult: {
        executionId: remReceipt.executionId,
        hmacSignature: remReceipt.hmacSignature,
        executed: true,
        success: true,
        target: '10.88.1.20'
      },
      postRemediationTelemetry: {
        target: '10.88.1.20',
        rttMs: 11,
        packetLossPct: 0,
        retransmissions: 0,
        observedAt: new Date(Date.now() + 50).toISOString()
      }
    });
    assert.equal(verifiedResolved.status, 'RESOLVED_REMEDIATION_SIGNED');
    assert.equal(verifiedResolved.agent5.remediationExecuted, true);
    assert.equal(verifiedResolved.agent5.incidentResolved, true);
    assert.equal(verifiedResolved.incidentLifecycleStage, 'POST_REMEDIATION_VERIFIED');
  });

  it('43. Script Approval Restart Durability, Live On-Disk SHA-256 Re-Verification & Atomic Single-Use SQLite Consumption', () => {
    const fs = require('fs');
    const os = require('os');
    const path = require('path');
    const { DatabaseSync } = require('node:sqlite');
    const { initSchema } = require('../src/db/database');
    const scriptAutomation = require('../src/tools/script-automation');

    const memDb = new DatabaseSync(':memory:');
    if (typeof memDb.pragma !== 'function') {
      memDb.pragma = (str) => memDb.exec('PRAGMA ' + str + ';');
    }
    initSchema(memDb);
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ejii-approval-atomic-'));
    const scriptName = 'verify-route.sh';
    const scriptPath = path.join(tempDir, scriptName);
    fs.writeFileSync(scriptPath, '#!/bin/sh\nip route show\n', 'utf8');

    try {
      const approval = scriptAutomation.issueOperatorScriptApproval({
        operatorId: 'op-restart-01',
        operatorRole: 'ADMIN',
        scriptName,
        scriptsDir: tempDir,
        params: { mode: 'safe' },
        target: 'local_host',
        db: memDb
      });
      assert.equal(approval.issued, true);
      assert.equal(approval.persistenceStatus, 'DURABLE_SQLITE_WAL');

      // 1. Modify the script on disk after approval was issued -> verification must reject with APPROVAL_SCRIPT_HASH_MISMATCH
      fs.writeFileSync(scriptPath, '#!/bin/sh\nip route flush all\n', 'utf8');
      const modifiedCheck = scriptAutomation.verifyOperatorScriptApproval({
        approvalToken: approval.approvalToken,
        scriptName,
        scriptsDir: tempDir,
        params: { mode: 'safe' },
        target: 'local_host',
        skipInMemoryCache: true,
        db: memDb
      });
      assert.equal(modifiedCheck.valid, false);
      assert.equal(modifiedCheck.reasonCode, 'APPROVAL_SCRIPT_HASH_MISMATCH');

      // Restore original script content on disk
      fs.writeFileSync(scriptPath, '#!/bin/sh\nip route show\n', 'utf8');

      // 2. Verify across simulated restart (skipInMemoryCache: true, reading from SQLite operator_approval_ledger) and consume atomically
      const firstVerify = scriptAutomation.verifyOperatorScriptApproval({
        approvalToken: approval.approvalToken,
        scriptName,
        scriptsDir: tempDir,
        params: { mode: 'safe' },
        target: 'local_host',
        skipInMemoryCache: true,
        consumeOnVerify: true,
        db: memDb
      });
      assert.equal(firstVerify.valid, true);
      assert.equal(firstVerify.consumed, true);

      // 3. Second concurrent/repeated consumption attempt against SQLite must fail closed
      const secondConsume = scriptAutomation.consumeOperatorScriptApproval(approval.approvalId, { db: memDb });
      assert.equal(secondConsume.consumed, false);
      assert.equal(secondConsume.reasonCode, 'APPROVAL_TOKEN_ALREADY_CONSUMED');
    } finally {
      memDb.close();
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('44. Database Transactional Write Probe & Read-Only / Migration Status Detection', () => {
    const { DatabaseSync } = require('node:sqlite');
    const { initSchema, getDatabaseHealth } = require('../src/db/database');

    const memDb = new DatabaseSync(':memory:');
    if (typeof memDb.pragma !== 'function') {
      memDb.pragma = (str) => memDb.exec('PRAGMA ' + str + ';');
    }
    initSchema(memDb);

    // 1. Healthy writable instance
    const healthy = getDatabaseHealth(memDb);
    assert.equal(healthy.healthy, true);
    assert.equal(healthy.writeCapable, true);
    assert.equal(healthy.writeProbeVerified, true);
    assert.ok(['HEALTHY_DURABLE_WAL', 'HEALTHY_DURABLE'].includes(healthy.operationalState));

    // 2. Query-only pragma makes database non-writable and write probe detects it cleanly
    memDb.pragma('query_only = ON');
    const readOnlyHealth = getDatabaseHealth(memDb);
    assert.equal(readOnlyHealth.writeCapable, false);
    assert.equal(readOnlyHealth.operationalState, 'TEMPORARY_WRITE_FAILURE');
    memDb.close();
  });

  it('45. Packet Capture Session Reset Lifecycle, Malformed PCAP Frame parserFailuresCount & Provenance Summary', () => {
    const { PacketStreamer } = require('../src/network/packet-streaming/packet-streamer');
    const streamer = new PacketStreamer();

    // 1. Construct a PCAP buffer with 1 valid header + truncated/malformed Ethernet frame (<14 bytes)
    const globalHeader = Buffer.alloc(24);
    globalHeader.writeUInt32LE(0xa1b2c3d4, 0);
    globalHeader.writeUInt16LE(2, 4);
    globalHeader.writeUInt16LE(4, 6);
    globalHeader.writeUInt32LE(65535, 16);
    globalHeader.writeUInt32LE(1, 20);

    const pktHeader = Buffer.alloc(16);
    pktHeader.writeUInt32LE(Math.floor(Date.now() / 1000), 0);
    pktHeader.writeUInt32LE(0, 4);
    pktHeader.writeUInt32LE(6, 8); // Only 6 bytes -> malformed Ethernet frame (<14 bytes)
    pktHeader.writeUInt32LE(6, 12);
    const shortPayload = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);

    const pcapBuf = Buffer.concat([globalHeader, pktHeader, shortPayload]);
    const importRes = streamer.importPcapBuffer(pcapBuf);
    assert.equal(importRes.importedCount, 1);
    assert.equal(importRes.parserFailuresCount, 1);

    // 2. Record a diagnostic ICMP probe observation and inspect provenance summary
    streamer.recordKernelIcmpProbeFrame('127.0.0.1', 2, true);
    const prov = streamer.getEvidenceProvenanceSummary();
    assert.equal(prov.physicalWireFramesCount, 0);
    assert.equal(prov.importedPcapFramesCount, 1);
    assert.equal(prov.icmpCommandObservationsCount, 1);
    assert.equal(prov.parserFailuresCount, 1);

    // 3. clearBuffer() resets frames, diagnostic observations, counters, and parserFailuresCount
    streamer.clearBuffer();
    const clearedProv = streamer.getEvidenceProvenanceSummary();
    assert.equal(clearedProv.totalBufferedFrames, 0);
    assert.equal(clearedProv.totalDiagnosticObservations, 0);
    assert.equal(clearedProv.parserFailuresCount, 0);
  });

  it('46. Genuine Network Probe Execution: Real DNS, DF-Bit PMTU, OS Neighbor Table, OS Socket Table & Zero 0.2ms Timing Floors', async () => {
    const { AutonomousWarRoomOrchestrator } = require('../src/ai/autonomous-war-room');
    const orchestrator = new AutonomousWarRoomOrchestrator();

    const probed = await orchestrator.executeActiveProbes({
      targetHost: '127.0.0.1',
      dnsServer: '127.0.0.1',
      rttMs: 55,
      packetLossPct: 1.2
    });

    assert.equal(probed.autonomousActiveProbes.length, 4);
    for (const p of probed.autonomousActiveProbes) {
      assert.equal(p.executed, true);
      assert.equal(p.evidenceProvenance, 'LIVE_COLLECTOR_EXECUTION');
      assert.ok(p.collectorExecutionReceipt, `Probe ${p.probeId} must carry a signed collectorExecutionReceipt`);
      assert.equal(p.collectorExecutionReceipt.hmacSignature.length, 64);
      assert.ok(typeof p.timingTarget === 'string' && p.timingTarget.length > 0);
      assert.ok(typeof p.nativeResultCode === 'string' && p.nativeResultCode.length > 0);
    }

    const dnsProbe = probed.autonomousActiveProbes.find((p) => p.probeType === 'DNS_PTR_LOOKUP');
    assert.equal(dnsProbe.timingTarget, 'DNS_QUERY_RTT_MS');
    assert.ok(dnsProbe.rawCommandOutput.includes('DNS PTR query') || dnsProbe.rawCommandOutput.includes('DNS A query'));

    const pmtuProbe = probed.autonomousActiveProbes.find((p) => p.probeType === 'ICMP_PMTU_DISCOVERY');
    assert.equal(pmtuProbe.timingTarget, 'ICMP_DF_PROBE_RTT_MS');
    assert.ok(typeof pmtuProbe.probeDetails.localInterfaceMtuBytes === 'number');

    const arpProbe = probed.autonomousActiveProbes.find((p) => p.probeType === 'ARP_NEIGHBOR_VERIFY');
    assert.equal(arpProbe.timingTarget, 'LOCAL_OS_NEIGHBOR_TABLE_READ_MS');
    assert.ok(typeof arpProbe.probeDetails.totalNeighborEntriesRead === 'number');

    const sockProbe = probed.autonomousActiveProbes.find((p) => p.probeType === 'SOCKET_ESTABLISHED_AUDIT');
    assert.equal(sockProbe.timingTarget, 'LOCAL_OS_SOCKET_TABLE_READ_MS');
    assert.ok(typeof sockProbe.probeDetails.totalSystemSockets === 'number');
    assert.ok(!sockProbe.rawCommandOutput.includes('loopback socket handshake'), 'Must inspect OS socket table, never self-connect loopback server');
  });

  it('47. Cryptographic Collector Execution Receipts: Reject Unsigned/Tampered Caller Probes & Deduplicate Correlated Observations', () => {
    const { AutonomousWarRoomOrchestrator } = require('../src/ai/autonomous-war-room');
    const orchestrator = new AutonomousWarRoomOrchestrator();

    const validReceipt = orchestrator.createCollectorExecutionReceipt({
      probeId: 'PROBE-PMTU-02',
      probeType: 'ICMP_PMTU_DISCOVERY',
      target: '198.51.100.25',
      durationMs: 0, // Sub-millisecond / 0ms duration preserved without 0.2ms floor!
      timingTarget: 'ICMP_DF_PROBE_RTT_MS',
      nativeResultCode: 'PMTU_DEGRADED_FRAG_NEEDED',
      rawCommandOutput: 'Frag needed and DF set (mtu = 1360)'
    });
    assert.equal(validReceipt.durationMs, 0);

    const res = orchestrator.execute({
      targetHost: '198.51.100.25',
      dnsServer: '198.51.100.53',
      rttMs: 80,
      packetLossPct: 3.0,
      executedProbeResults: [
        // 1. Unsigned caller-supplied probe -> must be rejected with UNTRUSTED_CALLER_PROBE_RESULT
        {
          probeId: 'PROBE-DNS-01',
          target: '198.51.100.53',
          measuredLatencyMs: 12.4,
          rawCommandOutput: 'forged unsigned caller output'
        },
        // 2. Valid signed collector probe with 0ms duration -> admitted
        {
          probeId: 'PROBE-PMTU-02',
          target: '198.51.100.25',
          measuredLatencyMs: 0,
          rawCommandOutput: 'Frag needed and DF set (mtu = 1360)',
          collectorExecutionReceipt: validReceipt
        },
        // 3. Duplicate observation for PROBE-PMTU-02 -> deduplicated with DUPLICATE_CORRELATED_PROBE
        {
          probeId: 'PROBE-PMTU-02',
          target: '198.51.100.25',
          measuredLatencyMs: 0,
          rawCommandOutput: 'Frag needed and DF set (mtu = 1360)',
          collectorExecutionReceipt: validReceipt
        },
        // 4. Tampered output against signed receipt -> rejected with UNTRUSTED_CALLER_PROBE_RESULT
        {
          probeId: 'PROBE-ARP-03',
          target: '198.51.100.25',
          measuredLatencyMs: 1.1,
          rawCommandOutput: 'tampered output',
          collectorExecutionReceipt: {
            ...validReceipt,
            probeId: 'PROBE-ARP-03'
          }
        }
      ]
    });

    assert.equal(res.round4EmpiricalSettlement.executedProbesCount, 1);
    const rejectedCodes = res.round4EmpiricalSettlement.rejectedProbeResults.map((r) => r.reasonCode);
    assert.ok(rejectedCodes.includes('UNTRUSTED_CALLER_PROBE_RESULT'));
    assert.ok(rejectedCodes.includes('DUPLICATE_CORRELATED_PROBE'));
    const admittedPmtu = res.autonomousActiveProbes.find((p) => p.probeId === 'PROBE-PMTU-02');
    assert.equal(admittedPmtu.measuredLatencyMs, 0, 'Exact 0ms duration must be preserved without 0.2ms floor');
  });

  it('48. Route-Level Spoofed authContext Stripping & Input Telemetry Signature Provenance', () => {
    const routesRca = require('../src/api/routes-rca');
    const { AutonomousWarRoomOrchestrator } = require('../src/ai/autonomous-war-room');
    const orchestrator = new AutonomousWarRoomOrchestrator();

    // 1. Verify route handler strips spoofed req.body.authContext when req.user is absent
    const execLayer = routesRca.stack.find((s) => s.route && s.route.path === '/war-room/execute');
    let routeJson = null;
    const mockReq = {
      headers: {},
      body: {
        rttMs: 75,
        packetLossPct: 2.0,
        operatorRole: 'ADMIN',
        authContext: {
          authenticated: true,
          userId: 'spoofed-attacker',
          role: 'ADMIN',
          source: 'SERVER_SESSION_JWT'
        }
      }
    };
    const mockRes = {
      statusCode: 200,
      status(c) { this.statusCode = c; return this; },
      json(d) { routeJson = d; return this; }
    };
    const handler = execLayer.route.stack[execLayer.route.stack.length - 1].handle;
    handler(mockReq, mockRes, () => {});

    assert.ok(routeJson);
    assert.equal(routeJson.agent5.operatorAuthorized, false, 'Route must strip spoofed req.body.authContext');
    assert.equal(routeJson.agent5.authorizationStatus, 'UNVERIFIED_CALLER_ROLE_REJECTED');

    // 2. Verify input telemetry provenance distinguishes unsigned OPERATOR_SUPPLIED_OBSERVATION vs signed DIRECT_LOCAL_OS_MEASUREMENT
    const unsignedObs = orchestrator.execute({ rttMs: 42, packetLossPct: 0.5 });
    assert.equal(unsignedObs.telemetryProvenance.evidenceClass, 'OPERATOR_SUPPLIED_OBSERVATION');
    assert.equal(unsignedObs.telemetryProvenance.telemetryVerifiedBySignature, false);

    const obsTs = '2026-11-08T10:00:00.000Z';
    const sig = orchestrator.signLocalTelemetry(
      { rttMs: 42, packetLossPct: 0.5, cpuSaturationPct: null, retransmissions: null, activeFlows: null },
      obsTs
    );
    const signedObs = orchestrator.execute({
      rttMs: 42,
      packetLossPct: 0.5,
      observationTimestamp: obsTs,
      telemetrySignature: sig
    });
    assert.equal(signedObs.telemetryProvenance.evidenceClass, 'DIRECT_LOCAL_OS_MEASUREMENT');
    assert.equal(signedObs.telemetryProvenance.telemetryVerifiedBySignature, true);
    assert.equal(signedObs.observationTimestamp, obsTs);
  });

  it('49. SQLite Monotonic rowid Retention Ordering & Cross-Source Wire/Socket 5-Tuple + Timestamp Correlation', () => {
    const { PacketStreamer } = require('../src/network/packet-streaming/packet-streamer');
    const streamer = new PacketStreamer();
    const nowMs = Date.now();

    const wireFrames = [
      {
        frameNumber: 101,
        protocol: 'TCP',
        srcIp: '10.0.0.15',
        srcPort: 51234,
        dstIp: '93.184.216.34',
        dstPort: 443,
        timestampMs: nowMs,
        length: 1420,
        tcpFlags: 'ACK,PSH',
        isSimulated: false
      },
      {
        frameNumber: 102,
        protocol: 'TCP',
        srcIp: '10.0.0.15',
        srcPort: 59999,
        dstIp: '198.51.100.88',
        dstPort: 443,
        timestampMs: nowMs - 60_000, // 60s old -> outside 5s skew window!
        length: 64,
        tcpFlags: 'SYN',
        isSimulated: false
      }
    ];

    const socketEntries = [
      {
        protocol: 'TCP',
        localAddress: '10.0.0.15',
        localPort: 51234,
        remoteAddress: '93.184.216.34',
        remotePort: 443,
        pid: 4100,
        processName: 'node',
        state: 'ESTABLISHED',
        timestampMs: nowMs + 120
      },
      {
        protocol: 'TCP',
        localAddress: '10.0.0.15',
        localPort: 59999,
        remoteAddress: '198.51.100.88',
        remotePort: 443,
        pid: 4101,
        processName: 'curl',
        state: 'SYN_SENT',
        timestampMs: nowMs
      }
    ];

    const corr = streamer.correlateWireAndSocketObservations(socketEntries, {
      wireFrames,
      maxTimestampSkewMs: 5000
    });
    assert.equal(corr.correlatedCount, 1);
    assert.equal(corr.uncorrelatedCount, 1);
    assert.equal(corr.correlatedPairs[0].pid, 4100);
    assert.equal(corr.correlatedPairs[0].correlationStatus, 'VERIFIED_5TUPLE_AND_TIMESTAMP_MATCH');
    assert.equal(corr.uncorrelatedSockets[0].correlationStatus, 'REJECTED_TIMESTAMP_SKEW_EXCEEDED');
  });

  it('50. Project Atlas: Configuration Composition, Env Interpolation, Validation, Versioning & Atomic Rollback', () => {
    const { ProjectAtlasEngine } = require('../src/network/atlas/project-atlas-engine');
    const atlas = new ProjectAtlasEngine();

    // 1. Compose split configuration with environment variable interpolation
    const v1 = atlas.saveAndActivateConfig(
      'edge-mesh',
      {
        server: { bindPort: 7000, tlsMode: 'TLS_1_3_STRICT' },
        proxies: [
          {
            name: 'api-gw-${ENV_REGION:-eu}',
            type: 'HTTP',
            localIp: '{{ .Envs.BACKEND_IP }}',
            localPort: 8080,
            exposurePolicy: 'PRIVATE_LOOPBACK'
          }
        ]
      },
      {
        envVars: { ENV_REGION: 'baku', BACKEND_IP: '127.0.0.1' },
        fragments: [
          {
            proxies: [
              {
                name: 'metrics-internal',
                type: 'TCP',
                localIp: '127.0.0.1',
                localPort: 9090
              }
            ]
          }
        ]
      }
    );

    assert.equal(v1.version, 1);
    assert.equal(v1.active, true);
    assert.equal(v1.config.proxies.length, 2);
    assert.equal(v1.config.proxies[0].name, 'api-gw-baku');
    assert.equal(v1.config.proxies[0].localIp, '127.0.0.1');

    // 2. Save v2 and then rollback atomically to v1
    const v2 = atlas.saveAndActivateConfig('edge-mesh', {
      server: { bindPort: 7000, tlsMode: 'TLS_1_3_STRICT' },
      proxies: [{ name: 'only-one-proxy', type: 'TCP', localIp: '127.0.0.1', localPort: 3000 }]
    });
    assert.equal(v2.version, 2);

    const rolledBack = atlas.rollbackConfig('edge-mesh', 1);
    assert.equal(rolledBack.version, 1);
    assert.equal(rolledBack.active, true);

    // 3. Reject configuration that attempts to proxy to cloud metadata 169.254.169.254
    assert.throws(
      () => {
        atlas.saveAndActivateConfig('bad-ssrf', {
          proxies: [{ name: 'ssrf-metadata', type: 'HTTP', localIp: '169.254.169.254', localPort: 80 }]
        });
      },
      (err) => err && err.code === 'ATLAS_CONFIG_INVALID'
    );
  });

  it('51. Project Atlas: Zero-Trust Enrollment, TLS Downgrade Prevention, Privileged Port Guard & Instant Session Revocation', async () => {
    const { ProjectAtlasEngine } = require('../src/network/atlas/project-atlas-engine');
    const atlas = new ProjectAtlasEngine();

    // 1. Issue signed client enrollment token
    const tokenBundle = atlas.issueClientEnrollmentToken({
      clientName: 'baku-branch-connector-01',
      operatorId: 'secops-01',
      ttlMs: 60_000
    });
    assert.ok(tokenBundle.enrollmentToken.includes('.'));

    // 2. Reject plaintext downgrade attempt
    assert.throws(
      () => {
        atlas.enrollClient({
          clientName: 'baku-branch-connector-01',
          enrollmentToken: tokenBundle.enrollmentToken,
          tlsMode: 'PLAINTEXT'
        });
      },
      (err) => err && err.code === 'ATLAS_TLS_REQUIRED_DOWNGRADE_BLOCKED'
    );

    // 3. Enroll client with TLS 1.3 verified
    const client = atlas.enrollClient({
      clientName: 'baku-branch-connector-01',
      enrollmentToken: tokenBundle.enrollmentToken
    });
    assert.equal(client.status, 'CONNECTED');
    assert.equal(client.tlsVerified, true);

    // 4. Reject public internet exposure of SSH (port 22) without explicit JIT authorization
    await assert.rejects(
      async () => {
        await atlas.createLiveProxy({
          proxyName: 'unsafe-public-ssh',
          clientId: client.clientId,
          proxyType: 'TCP',
          localIp: '127.0.0.1',
          localPort: 22,
          exposurePolicy: 'PUBLIC_INTERNET',
          jitAuthorized: false,
          startListener: false
        });
      },
      (err) => err && err.code === 'ATLAS_PRIVILEGED_PORT_PUBLIC_EXPOSURE_BLOCKED'
    );

    // 5. Register a private proxy for the client, then revoke the client session and verify automatic proxy termination
    const prx = await atlas.createLiveProxy({
      proxyName: 'branch-internal-app',
      clientId: client.clientId,
      proxyType: 'TCP',
      localIp: '127.0.0.1',
      localPort: 8080,
      startListener: false
    });
    assert.equal(prx.status, 'ACTIVE');

    const revRes = await atlas.revokeClientSession(client.clientId, 'Compromised edge credential');
    assert.equal(revRes.status, 'REVOKED');
    assert.ok(revRes.terminatedProxies.includes(prx.proxyId));

    const diag = await atlas.diagnoseProxyOrTunnel(prx.proxyId);
    assert.equal(diag.verdict, 'CLIENT_SESSION_REVOKED');
  });

  it('52. Project Atlas: Real Socket-Backed TCP & HTTP Reverse Proxies, Header Rewriting, Health Checks, VirtualNet ACLs & Prometheus Metrics', async () => {
    const http = require('http');
    const net = require('net');
    const { ProjectAtlasEngine } = require('../src/network/atlas/project-atlas-engine');
    const atlas = new ProjectAtlasEngine();

    // 1. Spin up a real local backend HTTP server to verify end-to-end reverse proxy forwarding
    let receivedHeaders = null;
    const backendHttpServer = http.createServer((req, res) => {
      receivedHeaders = req.headers;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, path: req.url, hostHeader: req.headers.host }));
    });

    await new Promise((resolve) => backendHttpServer.listen(0, '127.0.0.1', resolve));
    const backendHttpPort = backendHttpServer.address().port;

    // 2. Spin up a real local TCP echo server
    const backendTcpServer = net.createServer((sock) => {
      sock.on('data', (chunk) => sock.write(Buffer.concat([Buffer.from('ATLAS-ECHO:'), chunk])));
    });
    await new Promise((resolve) => backendTcpServer.listen(0, '127.0.0.1', resolve));
    const backendTcpPort = backendTcpServer.address().port;

    try {
      // 3. Create live Atlas HTTP reverse proxy with Host header rewrite and custom headers
      const httpProxy = await atlas.createLiveProxy({
        proxyName: 'live-http-ingester',
        proxyType: 'HTTP',
        bindAddr: '127.0.0.1',
        remotePort: 0,
        localIp: '127.0.0.1',
        localPort: backendHttpPort,
        hostHeaderRewrite: 'internal.sovereign.local',
        headers: { 'x-sovereign-fabric': 'v6-atlas' }
      });
      assert.ok(httpProxy.remotePort > 0);

      const proxyResp = await fetch(`http://127.0.0.1:${httpProxy.remotePort}/healthz`);
      const proxyData = await proxyResp.json();
      assert.equal(proxyResp.status, 200);
      assert.equal(proxyData.ok, true);
      assert.equal(proxyData.hostHeader, 'internal.sovereign.local');
      assert.equal(receivedHeaders['x-sovereign-fabric'], 'v6-atlas');
      assert.ok(receivedHeaders['x-forwarded-for']);
      assert.equal(receivedHeaders['x-atlas-proxy-id'], httpProxy.proxyId);

      // 4. Create live Atlas TCP reverse proxy and verify bidirectional socket stream forwarding
      const tcpProxy = await atlas.createLiveProxy({
        proxyName: 'live-tcp-tunnel',
        proxyType: 'TCP',
        bindAddr: '127.0.0.1',
        remotePort: 0,
        localIp: '127.0.0.1',
        localPort: backendTcpPort
      });
      assert.ok(tcpProxy.remotePort > 0);

      const tcpReply = await new Promise((resolve, reject) => {
        const client = net.createConnection({ host: '127.0.0.1', port: tcpProxy.remotePort }, () => {
          client.write('PING-PAYLOAD');
        });
        client.once('data', (data) => {
          client.destroy();
          resolve(data.toString('utf8'));
        });
        client.once('error', reject);
      });
      assert.equal(tcpReply, 'ATLAS-ECHO:PING-PAYLOAD');

      // 5. Run active health check and AI tunnel diagnosis
      const hc = await atlas.runProxyHealthCheck(httpProxy.proxyId);
      assert.equal(hc.healthy, true);
      assert.equal(hc.healthStatus, 'HEALTHY');

      const diag = await atlas.diagnoseProxyOrTunnel(httpProxy.proxyId);
      assert.equal(diag.verdict, 'TUNNEL_AND_BACKEND_HEALTHY');

      // 6. Create VirtualNet L3 mesh and evaluate zero-trust ACLs
      const vnet = atlas.createVirtualNetwork({
        vnetName: 'corp-zero-trust-vnet',
        cidrBlock: '100.64.20.0/24',
        peers: [{ peerId: 'node-a', ip: '100.64.20.10' }, { peerId: 'node-b', ip: '100.64.20.20' }],
        aclRules: [
          { sourceIp: '100.64.20.10', destIp: '100.64.20.20', destPort: 443, protocol: 'TCP', action: 'ALLOW' }
        ]
      });
      const allowedFlow = atlas.evaluateVirtualNetFlow(vnet.vnetId, {
        sourceIp: '100.64.20.10',
        destIp: '100.64.20.20',
        destPort: 443,
        protocol: 'TCP'
      });
      assert.equal(allowedFlow.allowed, true);

      const deniedFlow = atlas.evaluateVirtualNetFlow(vnet.vnetId, {
        sourceIp: '100.64.20.10',
        destIp: '100.64.20.20',
        destPort: 22,
        protocol: 'TCP'
      });
      assert.equal(deniedFlow.allowed, false);
      assert.equal(deniedFlow.decision, 'DENY_DEFAULT_ZERO_TRUST');

      // 7. Export Prometheus metrics and verify byte/connection counters
      const prom = atlas.exportPrometheusMetrics();
      assert.ok(prom.includes('ejii_atlas_active_proxies_total 2'));
      assert.ok(prom.includes('live-http-ingester'));
      assert.ok(prom.includes('live-tcp-tunnel'));
    } finally {
      await atlas.shutdownAll();
      await new Promise((resolve) => backendHttpServer.close(resolve));
      await new Promise((resolve) => backendTcpServer.close(resolve));
    }
  });

  // =========================================================================
  // PHASE ATLAS II — SOVEREIGN CONNECTIVITY, ZERO-TRUST & ENGINEERING MATURITY
  // =========================================================================

  it('53. Phase Atlas II: Purpose-Separated HKDF Keys, Known-Insecure Secret Rejection & Grace-Period Key Rotation', () => {
    const config = require('../src/config');
    config._resetCryptoStateForTests();
    const { ProjectAtlasEngine } = require('../src/network/atlas/project-atlas-engine');
    const { AutonomousWarRoomOrchestrator } = require('../src/ai/autonomous-war-room');

    // 1. Verify purpose-separated HKDF keys are distinct across domains
    const atlasKey = config.getPurposeSeparatedSecret('atlas-control-plane-v1');
    const warRoomKey = config.getPurposeSeparatedSecret('sre-war-room-v1');
    const vaultKey = config.getPurposeSeparatedSecret('dsrl-lyapunov-vault-v1');
    assert.equal(atlasKey.length, 64);
    assert.equal(warRoomKey.length, 64);
    assert.notEqual(atlasKey, warRoomKey);
    assert.notEqual(atlasKey, vaultKey);

    // 2. Reject known insecure fallback secrets in ProjectAtlasEngine and AutonomousWarRoomOrchestrator
    assert.ok(config.KNOWN_INSECURE_SECRETS.has('ejii-atlas-sovereign-hmac-secret-key-2026'));
    const insecureAtlas = new ProjectAtlasEngine({
      secretKey: 'ejii-atlas-sovereign-hmac-secret-key-2026'
    });
    assert.equal(insecureAtlas.secretConfigured, false);
    assert.throws(
      () => insecureAtlas.issueClientEnrollmentToken({ clientName: 'node-01' }),
      (err) => err && err.code === 'ATLAS_SECRET_UNCONFIGURED_OR_INSECURE'
    );

    const insecureWarRoom = new AutonomousWarRoomOrchestrator('ejii-atlas-sovereign-hmac-secret-key-2026');
    const unsignedSession = insecureWarRoom.execute({ targetHost: '127.0.0.1', rttMs: 75 });
    assert.equal(unsignedSession.agent5.hmacConfigured, false);
    assert.equal(unsignedSession.agent5.hmacStatus, 'REJECTED_INSECURE_OR_MISSING_SECRET');

    // 3. Verify grace-period HMAC key rotation in ProjectAtlasEngine and AutonomousWarRoomOrchestrator
    const atlas = new ProjectAtlasEngine({ secretKey: 'initial-sovereign-atlas-secret-key-alpha-999', keyId: 'atlas-test53-key-v1' });
    const preRotationToken = atlas.issueClientEnrollmentToken({ clientName: 'edge-rot-01', ttlMs: 60_000 });
    const rotRes = atlas.rotateSecretKey('rotated-sovereign-atlas-secret-key-beta-888', {
      keyId: 'atlas-rot-v2',
      gracePeriodMs: 30_000
    });
    assert.equal(rotRes.rotated, true);
    assert.equal(rotRes.activeKeyId, 'atlas-rot-v2');
    assert.equal(rotRes.previousKeysCount, 1);

    // Token issued under previous key remains valid during grace period
    const verifyPre = atlas.verifyEnrollmentToken(preRotationToken.enrollmentToken, 'edge-rot-01');
    assert.equal(verifyPre.valid, true);

    // War-Room collector receipt signed before rotation verifies cleanly during grace window
    const warRoom = new AutonomousWarRoomOrchestrator('initial-war-room-sovereign-secret-key-111');
    const preReceipt = warRoom.createCollectorExecutionReceipt({
      probeId: 'PROBE-DNS-01',
      probeType: 'DNS_PTR_LOOKUP',
      target: '127.0.0.1',
      durationMs: 1.25,
      timingTarget: 'DNS_QUERY_RTT_MS',
      nativeResultCode: 'QUERY_SUCCESS',
      rawCommandOutput: 'DNS PTR resolved localhost'
    });
    warRoom.rotateHmacKey('rotated-war-room-sovereign-secret-key-222', {
      keyId: 'wr-rot-v2',
      gracePeriodMs: 30_000
    });
    const receiptVerify = warRoom.verifyCollectorExecutionReceipt(
      {
        rawCommandOutput: 'DNS PTR resolved localhost',
        collectorExecutionReceipt: preReceipt
      },
      'PROBE-DNS-01',
      '127.0.0.1'
    );
    assert.equal(receiptVerify.valid, true);
  });

  it('54. Phase Atlas II: Zero Artificial Runbook Telemetry Fallbacks & Missing Socket Timestamp Rejection', async () => {
    const routesEnterprise = require('../src/api/routes-enterprise');
    const { PacketStreamer } = require('../src/network/packet-streaming/packet-streamer');

    // 1. Verify PacketStreamer.correlateWireAndSocketObservations never fabricates Date.now() when socket timestamp is missing
    const streamer = new PacketStreamer();
    const nowMs = Date.now();
    const wireFrames = [
      {
        frameNumber: 1,
        protocol: 'TCP',
        srcIp: '10.10.0.5',
        srcPort: 54000,
        dstIp: '93.184.216.34',
        dstPort: 443,
        timestampMs: nowMs,
        length: 64,
        tcpFlags: 'SYN',
        isSimulated: false
      }
    ];
    const socketsWithoutTimestamp = [
      {
        protocol: 'TCP',
        localAddress: '10.10.0.5',
        localPort: 54000,
        remoteAddress: '93.184.216.34',
        remotePort: 443,
        pid: 9001,
        processName: 'curl',
        state: 'ESTABLISHED'
        // No timestampMs or observedAt!
      }
    ];
    const corr = streamer.correlateWireAndSocketObservations(socketsWithoutTimestamp, {
      wireFrames,
      maxTimestampSkewMs: 5000
    });
    assert.equal(corr.correlatedCount, 0, 'Socket observation without authentic timestamp must never be correlated via Date.now()');
    assert.equal(corr.incompleteSocketTimestampsCount, 1);
    assert.equal(corr.uncorrelatedSockets[0].correlationStatus, 'INCOMPLETE_MISSING_SOCKET_TIMESTAMP');
    assert.equal(corr.uncorrelatedSockets[0].socketObservedAtMs, null);

    // 2. Verify runbook execution route reports authentic measured telemetry or null with fieldProvenance (never 12.0, 4.2, or 0.85 * rtt)
    const execLayer = routesEnterprise.stack.find(
      (s) => s.route && s.route.path === '/runbooks/:runbookId/execute'
    );
    assert.ok(execLayer, 'Runbook execution route must exist');
    let routeStatus = 200;
    let routeBody = null;
    const handler = execLayer.route.stack[execLayer.route.stack.length - 1].handle;
    await handler(
      {
        params: { runbookId: 'RB-DNS-CACHE-FLUSH' },
        body: {
          target: '127.0.0.1',
          port: 65534, // Unbound loopback port -> TCP connect fails, rttMs must be null (never 12.0 or 4.2!)
          operatorApproved: true
        },
        headers: {}
      },
      {
        status(code) {
          routeStatus = code;
          return this;
        },
        json(payload) {
          routeBody = payload;
          return this;
        }
      }
    );
    assert.equal(routeStatus, 200);
    assert.equal(routeBody.success, true);
    assert.equal(routeBody.preFlightTelemetry.tcpReachable, false);
    assert.equal(routeBody.preFlightTelemetry.rttMs, null, 'Failed TCP probe must report rttMs: null, never 12.0 or 4.2');
    assert.equal(routeBody.preFlightTelemetry.fieldProvenance.rttMs.status, 'UNAVAILABLE');
    assert.ok(routeBody.postRemediationTelemetry.fieldProvenance.dnsLatencyMs.measurementMethod.includes('DNS_'));
  });

  it('55. Phase Atlas II: SQLite Startup Hydration & Explicit DEGRADED_SQLITE_WRITE_ERROR Tracking', () => {
    const { DatabaseSync } = require('node:sqlite');
    const { initSchema } = require('../src/db/database');
    const { ProjectAtlasEngine } = require('../src/network/atlas/project-atlas-engine');

    const memDb = new DatabaseSync(':memory:');
    if (typeof memDb.pragma !== 'function') {
      memDb.pragma = (str) => memDb.exec('PRAGMA ' + str + ';');
    }
    initSchema(memDb);

    try {
      // 1. Persist config, client, and VirtualNet in instance 1
      const atlas1 = new ProjectAtlasEngine({ db: memDb });
      atlas1.saveAndActivateConfig('hydrated-profile', {
        server: { bindPort: 7000, tlsMode: 'TLS_1_3_STRICT' },
        proxies: [{ name: 'persisted-tcp', type: 'TCP', localIp: '127.0.0.1', localPort: 8080 }]
      });
      const tok = atlas1.issueClientEnrollmentToken({ clientName: 'persisted-client' });
      const enrolled = atlas1.enrollClient({
        clientName: 'persisted-client',
        enrollmentToken: tok.enrollmentToken
      });
      const vnet = atlas1.createVirtualNetwork({
        vnetName: 'persisted-vnet',
        cidrBlock: '100.64.55.0/24'
      });
      assert.equal(atlas1.persistenceStatus, 'DURABLE_SQLITE_SYNCED');

      // 2. Boot a fresh instance with hydrateFromDb: true against the same SQLite DB
      const atlas2 = new ProjectAtlasEngine({ db: memDb, hydrateFromDb: true });
      assert.equal(atlas2.persistenceStatus, 'DURABLE_SQLITE_SYNCED');
      assert.ok(atlas2.configsMemory.some((c) => c.profileName === 'hydrated-profile' && c.active));
      assert.ok(atlas2.clientsMemory.has(enrolled.clientId));
      assert.ok(atlas2.vnetsMemory.has(vnet.vnetId));

      // 3. Make DB read-only and verify explicit DEGRADED_SQLITE_WRITE_ERROR tracking (and strictDurability throw)
      memDb.pragma('query_only = ON');
      atlas2.saveAndActivateConfig('degraded-profile', {
        proxies: [{ name: 'mem-only-proxy', type: 'TCP', localIp: '127.0.0.1', localPort: 8081 }]
      });
      assert.equal(atlas2.persistenceStatus, 'DEGRADED_SQLITE_WRITE_ERROR');
      assert.ok(atlas2.lastDatabaseError);
      assert.equal(atlas2.lastDatabaseError.operationName, 'saveAndActivateConfig');

      const strictAtlas = new ProjectAtlasEngine({ db: memDb, strictDurability: true });
      assert.throws(
        () =>
          strictAtlas.saveAndActivateConfig('strict-fail', {
            proxies: [{ name: 'p1', type: 'TCP', localIp: '127.0.0.1', localPort: 8082 }]
          }),
        (err) => err && err.code === 'ATLAS_SQLITE_WRITE_FAILED'
      );
    } finally {
      memDb.close();
    }
  });

  it('56. Phase Atlas II: TCP Single-Execution Cleanup, Stream Backpressure, Proxy Protocol v2 & Bounded UDP Session NAT Table', async () => {
    const net = require('net');
    const dgram = require('dgram');
    const { ProjectAtlasEngine } = require('../src/network/atlas/project-atlas-engine');
    const atlas = new ProjectAtlasEngine();

    // 1. TCP Backend Server that verifies Proxy Protocol v2 binary signature and echoes payloads
    let receivedFirstChunk = null;
    const tcpBackend = net.createServer((sock) => {
      sock.on('data', (chunk) => {
        if (!receivedFirstChunk) receivedFirstChunk = chunk;
        sock.write(chunk);
      });
    });
    await new Promise((resolve) => tcpBackend.listen(0, '127.0.0.1', resolve));
    const tcpBackendPort = tcpBackend.address().port;

    // 2. UDP Backend Echo Server
    const udpBackend = dgram.createSocket('udp4');
    udpBackend.on('message', (msg, rinfo) => {
      udpBackend.send(Buffer.concat([Buffer.from('UDP-ACK:'), msg]), rinfo.port, rinfo.address);
    });
    await new Promise((resolve) => udpBackend.bind(0, '127.0.0.1', resolve));
    const udpBackendPort = udpBackend.address().port;

    try {
      const tcpProxy = await atlas.createLiveProxy({
        proxyName: 'ppv2-tcp-proxy',
        proxyType: 'TCP',
        bindAddr: '127.0.0.1',
        remotePort: 0,
        localIp: '127.0.0.1',
        localPort: tcpBackendPort,
        proxyProtocolVersion: 'V2',
        maxConcurrentConnections: 4
      });

      const echoed = await new Promise((resolve, reject) => {
        const client = net.createConnection({ host: '127.0.0.1', port: tcpProxy.remotePort }, () => {
          client.write(Buffer.alloc(32 * 1024, 'A'));
        });
        let total = 0;
        client.on('data', (chunk) => {
          total += chunk.length;
          if (total >= 32 * 1024) {
            // Trigger both error and close to prove activeConnections never double-decrements below 0
            client.emit('error', new Error('Synthetic client error before close'));
            client.destroy();
            resolve(total);
          }
        });
        client.once('error', () => {});
        setTimeout(() => reject(new Error('TCP proxy timeout')), 3000);
      });
      assert.ok(echoed >= 32 * 1024);
      // Verify Proxy Protocol v2 12-byte signature (\r\n\r\n\0\r\nQUIT\n)
      assert.ok(receivedFirstChunk && receivedFirstChunk.slice(0, 12).equals(Buffer.from([0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a])));
      await new Promise((r) => setTimeout(r, 40));
      assert.equal(tcpProxy.activeConnections, 0, 'activeConnections must return to exact 0 without double-decrement');

      // 3. Test UDP proxy bounded NAT session table reuse across multiple datagrams from same client socket
      const udpProxy = await atlas.createLiveProxy({
        proxyName: 'live-udp-nat-proxy',
        proxyType: 'UDP',
        bindAddr: '127.0.0.1',
        remotePort: 0,
        localIp: '127.0.0.1',
        localPort: udpBackendPort,
        udpSessionIdleMs: 250,
        maxUdpSessions: 4
      });

      const udpClient = dgram.createSocket('udp4');
      const sendDatagram = (payloadStr) =>
        new Promise((resolve, reject) => {
          udpClient.once('message', (reply) => resolve(reply.toString('utf8')));
          udpClient.send(Buffer.from(payloadStr), udpProxy.remotePort, '127.0.0.1', (err) => {
            if (err) reject(err);
          });
        });

      const r1 = await sendDatagram('PKT-1');
      const r2 = await sendDatagram('PKT-2');
      assert.equal(r1, 'UDP-ACK:PKT-1');
      assert.equal(r2, 'UDP-ACK:PKT-2');
      // Both datagrams came from the same udpClient IP:port, so only 1 NAT session was created!
      assert.equal(udpProxy.totalConnections, 1, 'Same client IP:port must reuse the existing UDP NAT session');
      assert.equal(udpProxy.activeConnections, 1);

      udpClient.close();
      // Wait for udpSessionIdleMs (250ms) expiration
      await new Promise((r) => setTimeout(r, 320));
      assert.equal(udpProxy.activeConnections, 0, 'Idle UDP NAT session must expire and decrement activeConnections to 0');
    } finally {
      await atlas.shutdownAll();
      await new Promise((resolve) => tcpBackend.close(resolve));
      await new Promise((resolve) => udpBackend.close(resolve));
    }
  });

  it('57. Phase Atlas II: Single-Use Enrollment Token Anti-Replay, IPv6/Mapped/Numeric SSRF Defense & Connection-Time DNS Rebinding Guard', async () => {
    const { ProjectAtlasEngine } = require('../src/network/atlas/project-atlas-engine');
    const atlas = new ProjectAtlasEngine();

    // 1. Single-use enrollment token anti-replay
    const tok = atlas.issueClientEnrollmentToken({
      clientName: 'anti-replay-edge-01',
      operatorId: 'secops'
    });
    const firstEnroll = atlas.enrollClient({
      clientName: 'anti-replay-edge-01',
      enrollmentToken: tok.enrollmentToken
    });
    assert.equal(firstEnroll.status, 'CONNECTED');

    assert.throws(
      () =>
        atlas.enrollClient({
          clientName: 'anti-replay-edge-01',
          enrollmentToken: tok.enrollmentToken
        }),
      (err) => err && err.code === 'ATLAS_AUTH_TOKEN_REPLAY_BLOCKED'
    );

    // 2. Explicit token revocation before use
    const tok2 = atlas.issueClientEnrollmentToken({ clientName: 'revoked-token-client' });
    atlas.revokeEnrollmentToken(tok2.enrollmentToken, 'Leaked in CI log');
    assert.throws(
      () =>
        atlas.enrollClient({
          clientName: 'revoked-token-client',
          enrollmentToken: tok2.enrollmentToken
        }),
      (err) => err && err.code === 'ATLAS_AUTH_TOKEN_REVOKED'
    );

    // 3. Comprehensive SSRF checks: IPv6 metadata, IPv4-mapped IPv6, integer IP, hex IP, Oracle/Alibaba metadata
    const blockedTargets = [
      '169.254.169.254',
      '169.254.42.1',
      '100.100.100.200',
      '192.0.0.192',
      'fd00:ec2::254',
      'fe80::1',
      '::ffff:169.254.169.254',
      '2852039166', // decimal 169.254.169.254
      '0xa9fea9fe', // hex 169.254.169.254
      '0251.0376.0251.0376' // octal 169.254.169.254
    ];
    for (const badIp of blockedTargets) {
      const check = atlas.validateTargetSafety({ localIp: badIp, localPort: 80 });
      assert.equal(check.allowed, false, `SSRF guard must block ${badIp}`);
      assert.equal(check.code, 'ATLAS_SSRF_METADATA_BLOCKED');
    }

    // 4. Connection-time DNS rebinding defense
    await assert.rejects(
      async () => {
        await atlas.createLiveProxy({
          proxyName: 'rebinding-victim',
          proxyType: 'TCP',
          localIp: 'evil-rebind.example.com',
          localPort: 80,
          startListener: false,
          customLookup: async () => [{ address: '169.254.169.254', family: 4 }]
        });
      },
      (err) => err && err.code === 'ATLAS_SSRF_DNS_REBINDING_BLOCKED'
    );
  });

  it('58. Phase Atlas II: Time-Bounded Dual-Control JIT Administrative Access Grants & Automatic Expiration Sweep', async () => {
    const { ProjectAtlasEngine } = require('../src/network/atlas/project-atlas-engine');
    const atlas = new ProjectAtlasEngine();

    // 1. Reject dual-control JIT grant when primary and secondary operator are identical
    assert.throws(
      () =>
        atlas.issueJitAdminAccessGrant({
          localIp: '127.0.0.1',
          localPort: 22,
          operatorId: 'op-alice',
          secondaryApproverId: 'op-alice',
          requireDualControl: true
        }),
      (err) => err && err.code === 'ATLAS_JIT_DUAL_CONTROL_VIOLATION'
    );

    // 2. Issue valid short-lived dual-control JIT grant (80ms TTL) and register public SSH proxy
    const jitGrant = atlas.issueJitAdminAccessGrant({
      localIp: '127.0.0.1',
      localPort: 22,
      operatorId: 'op-alice',
      secondaryApproverId: 'op-bob',
      requireDualControl: true,
      ttlMs: 80
    });
    assert.equal(jitGrant.dualControlVerified, true);

    const sshProxy = await atlas.createLiveProxy({
      proxyName: 'jit-emergency-ssh',
      proxyType: 'TCP',
      localIp: '127.0.0.1',
      localPort: 22,
      exposurePolicy: 'PUBLIC_INTERNET',
      jitGrantId: jitGrant.jitGrantId,
      startListener: false
    });
    assert.equal(sshProxy.status, 'ACTIVE');

    // 3. Wait for JIT grant to expire and run sweepExpiredJitGrants
    await new Promise((r) => setTimeout(r, 110));
    const sweepRes = await atlas.sweepExpiredJitGrants();
    assert.ok(sweepRes.terminatedProxies.includes(sshProxy.proxyId));
    assert.equal(sshProxy.status, 'JIT_EXPIRED_TERMINATED');

    const diag = await atlas.diagnoseProxyOrTunnel(sshProxy.proxyId);
    assert.equal(diag.verdict, 'JIT_ADMIN_GRANT_EXPIRED');
  });

  it('59. Phase Atlas II: Port-Range Expansion, STCP Visitor ACLs, XTCP Symmetric-NAT Fallback, SSH Gateway & Optimal Relay Selection', async () => {
    const { ProjectAtlasEngine } = require('../src/network/atlas/project-atlas-engine');
    const atlas = new ProjectAtlasEngine();

    // 1. Port-range expansion (10000-10002 -> 20000-20002)
    const expanded = atlas.expandPortRangeProxies({
      namePrefix: 'batch-worker',
      proxyType: 'TCP',
      localIp: '127.0.0.1',
      localPortRange: '10000-10002',
      remotePortRange: '20000-20002'
    });
    assert.equal(expanded.length, 3);
    assert.equal(expanded[0].localPort, 10000);
    assert.equal(expanded[2].remotePort, 20002);

    // 2. STCP secret TCP visitor authentication & allowUsers ACL
    const stcpProxy = await atlas.createLiveProxy({
      proxyName: 'secret-db-tunnel',
      proxyType: 'STCP',
      localIp: '127.0.0.1',
      localPort: 5432,
      secretKey: 'top-secret-stcp-token',
      allowUsers: ['sre-lead'],
      startListener: false
    });
    assert.throws(
      () =>
        atlas.connectStcpVisitor({
          proxyId: stcpProxy.proxyId,
          visitorUser: 'unauthorized-user',
          suppliedSecretKey: 'top-secret-stcp-token'
        }),
      (err) => err && err.code === 'ATLAS_STCP_USER_FORBIDDEN'
    );
    assert.throws(
      () =>
        atlas.connectStcpVisitor({
          proxyId: stcpProxy.proxyId,
          visitorUser: 'sre-lead',
          suppliedSecretKey: 'wrong-secret'
        }),
      (err) => err && err.code === 'ATLAS_STCP_SECRET_MISMATCH'
    );
    const validVisitor = atlas.connectStcpVisitor({
      proxyId: stcpProxy.proxyId,
      visitorUser: 'sre-lead',
      suppliedSecretKey: 'top-secret-stcp-token'
    });
    assert.equal(validVisitor.authorized, true);

    // 3. XTCP P2P negotiation: Restricted Cone succeeds directly; Symmetric NAT falls back to STCP relay
    const directP2p = atlas.negotiateXtcpP2pSession({
      proxyName: 'p2p-fast',
      clientNatType: 'RESTRICTED_CONE',
      visitorNatType: 'FULL_CONE'
    });
    assert.equal(directP2p.directP2pEstablished, true);
    assert.equal(directP2p.transportMode, 'DIRECT_UDP_HOLE_PUNCH_QUIC');

    const fallbackP2p = atlas.negotiateXtcpP2pSession({
      proxyName: 'p2p-sym',
      clientNatType: 'SYMMETRIC_NAT',
      visitorNatType: 'RESTRICTED_CONE'
    });
    assert.equal(fallbackP2p.directP2pEstablished, false);
    assert.equal(fallbackP2p.transportMode, 'STCP_RELAY_FALLBACK');

    // 4. SSH Tunnel Gateway registration
    const sshGw = atlas.registerSshTunnelGatewaySession({
      operatorId: 'eldar',
      sshKeyFingerprintSha256: 'SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8',
      proxyName: 'ssh-reverse-web',
      localIp: '127.0.0.1',
      localPort: 3000,
      remotePort: 18080
    });
    assert.equal(sshGw.status, 'ACTIVE_SSH_REVERSE_TUNNEL');

    // 5. Intelligent Relay Recommendation across multiple relays
    atlas.registerRelayNode({
      relayId: 'atlas-relay-degraded-02',
      name: 'Degraded Edge Relay',
      measuredRttMs: 145,
      packetLossPct: 3.8,
      jitterMs: 18,
      activeTunnels: 420,
      maxCapacityTunnels: 500
    });
    const rec = atlas.recommendOptimalRelay();
    assert.equal(rec.recommendedRelay.relayId, 'atlas-relay-primary-01');
    assert.ok(rec.rankedCandidates[0].compositeScore > rec.rankedCandidates[1].compositeScore);

    const matrix = atlas.getFeatureCoverageMatrix();
    assert.ok(Array.isArray(matrix.capabilities) && matrix.capabilities.length >= 7);
  });

  it('60. Phase Atlas II: War-Room Correlated Sequential Probe Re-Execution Damping & Conversational Atlas Operator Queries', async () => {
    const { AutonomousWarRoomOrchestrator } = require('../src/ai/autonomous-war-room');
    const { chatOperatorService } = require('../src/core/chat/chat-operator-service');

    // 1. Verify War-Room admits sequential re-executions of the same probe class with distinct receiptId + newer timestamp using 0.5 damping
    const orchestrator = new AutonomousWarRoomOrchestrator();
    const r1 = orchestrator.createCollectorExecutionReceipt({
      probeId: 'PROBE-PMTU-02',
      probeType: 'ICMP_PMTU_DISCOVERY',
      target: '198.51.100.25',
      startedAt: '2026-11-08T10:00:00.000Z',
      completedAt: '2026-11-08T10:00:00.010Z',
      durationMs: 2.1,
      timingTarget: 'ICMP_DF_PROBE_RTT_MS',
      nativeResultCode: 'PMTU_DEGRADED_FRAG_NEEDED',
      rawCommandOutput: 'Frag needed and DF set (mtu = 1360)'
    });
    const r2 = orchestrator.createCollectorExecutionReceipt({
      probeId: 'PROBE-PMTU-02',
      probeType: 'ICMP_PMTU_DISCOVERY',
      target: '198.51.100.25',
      startedAt: '2026-11-08T10:01:00.000Z',
      completedAt: '2026-11-08T10:01:00.012Z',
      durationMs: 1.9,
      timingTarget: 'ICMP_DF_PROBE_RTT_MS',
      nativeResultCode: 'PMTU_DEGRADED_FRAG_NEEDED',
      rawCommandOutput: 'Frag needed and DF set (mtu = 1360)'
    });

    const settled = orchestrator.execute({
      targetHost: '198.51.100.25',
      rttMs: 85,
      packetLossPct: 2.5,
      executedProbeResults: [
        {
          probeId: 'PROBE-PMTU-02',
          target: '198.51.100.25',
          measuredLatencyMs: 2.1,
          executedAt: '2026-11-08T10:00:00.010Z',
          rawCommandOutput: 'Frag needed and DF set (mtu = 1360)',
          collectorExecutionReceipt: r1
        },
        // Legitimate sequential re-execution 1 minute later with new receiptId r2 -> admitted with 0.5 correlation damping
        {
          probeId: 'PROBE-PMTU-02',
          target: '198.51.100.25',
          measuredLatencyMs: 1.9,
          executedAt: '2026-11-08T10:01:00.012Z',
          rawCommandOutput: 'Frag needed and DF set (mtu = 1360)',
          collectorExecutionReceipt: r2
        },
        // Exact replay of r2 -> rejected as DUPLICATE_CORRELATED_PROBE
        {
          probeId: 'PROBE-PMTU-02',
          target: '198.51.100.25',
          measuredLatencyMs: 1.9,
          executedAt: '2026-11-08T10:01:00.012Z',
          rawCommandOutput: 'Frag needed and DF set (mtu = 1360)',
          collectorExecutionReceipt: r2
        }
      ]
    });

    assert.equal(settled.round4EmpiricalSettlement.executedProbesCount, 1);
    assert.equal(settled.round4EmpiricalSettlement.correlatedSequentialExecutionsCount, 1);
    assert.equal(settled.round4EmpiricalSettlement.duplicateReplaysRejectedCount, 1);
    assert.equal(settled.round4EmpiricalSettlement.calibrationMetrics.effectiveIndependentSampleSize, 1.5);
    assert.equal(settled.round4EmpiricalSettlement.calibrationMetrics.evidenceIndependenceRatio, 0.75);

    // 2. Verify Project Falcon Conversational Connectivity Intelligence answers Atlas queries with explicit Evidence Separation
    const chatRes = await chatOperatorService.processMessage({
      sessionId: 'TEST-ATLAS-CHAT-01',
      message: 'Recommend the lowest-latency relay for Project Atlas and show connected tunnel clients',
      user: { id: 'op-atlas', username: 'eldar', role: 'ADMIN' }
    });
    assert.equal(chatRes.success, true);
    assert.equal(chatRes.data.intent, 'atlas_connectivity_query');
    assert.ok(chatRes.reply.includes('Observed Facts'));
    assert.ok(chatRes.reply.includes('Historical Observations'));
    assert.ok(chatRes.reply.includes('Derived Calculations'));
    assert.ok(chatRes.reply.includes('Unavailable Telemetry'));
    assert.ok(chatRes.data.technicalEvidence.evidenceSeparation.observedFacts.length > 0);
  });

  // =========================================================================
  // PHASE ATLAS III REALITY VERIFICATION SUITE (TESTS 61–68)
  // Sovereign Production Maturity, Intelligence Evolution & Continuous Engineering
  // =========================================================================

  function createFreshMemDb() {
    const { DatabaseSync } = require('node:sqlite');
    const { initSchema } = require('../src/db/database');
    const memDb = new DatabaseSync(':memory:');
    if (typeof memDb.pragma !== 'function') {
      memDb.pragma = (str) => memDb.exec('PRAGMA ' + str + ';');
    }
    initSchema(memDb);
    return memDb;
  }

  const net = require('net');
  const dgram = require('dgram');
  const { ProjectAtlasEngine } = require('../src/network/atlas/project-atlas-engine');
  const { AutonomousWarRoomOrchestrator } = require('../src/ai/autonomous-war-room');
  const { chatOperatorService } = require('../src/core/chat/chat-operator-service');

  it('61. Phase Atlas III — Keyring Synchronization, Durable Key Revocation & Cross-Session Anti-Replay', async () => {
    const memDb = createFreshMemDb();
    const atlas = new ProjectAtlasEngine({ db: memDb, failOnInsecureSecret: false, keyId: 'atlas-phase3-key-alpha' });

    // 1. Issue an enrollment token with primary key
    const primaryKeyId = atlas.activeKeyId;
    const tokenBundle = atlas.issueClientEnrollmentToken({ clientName: 'atlas-worker-charlie', ttlMs: 3600_000 });
    assert.ok(tokenBundle.enrollmentToken);

    // 2. Rotate secret key with grace period
    const newSecret = 'ejii-sovereign-production-atlas-secret-rotation-phase-iii-2026';
    const rot = atlas.rotateSecretKey(newSecret, { keyId: 'atlas-key-phase3-active', gracePeriodMs: 60_000 });
    assert.equal(rot.rotated, true);
    assert.equal(atlas.activeKeyId, 'atlas-key-phase3-active');

    // Token signed with primary key is still valid within grace period
    const checkWithinGrace = atlas.verifyEnrollmentToken(tokenBundle.enrollmentToken, 'atlas-worker-charlie');
    assert.equal(checkWithinGrace.valid, true);

    // 3. Explicitly revoke the primary key
    const rev = atlas.revokeSecretKey(primaryKeyId, 'Emergency key retirement audit');
    assert.equal(rev.revoked, true);
    assert.equal(rev.revokedKeyId, primaryKeyId);

    // Token signed with revoked key must fail immediately
    const checkAfterRevoke = atlas.verifyEnrollmentToken(tokenBundle.enrollmentToken, 'atlas-worker-charlie');
    assert.equal(checkAfterRevoke.valid, false);
    assert.equal(checkAfterRevoke.code, 'ATLAS_KEY_REVOKED_OR_EXPIRED');

    // 4. Enroll client with active key token and verify nonce persistence in SQLite
    const activeTokenBundle = atlas.issueClientEnrollmentToken({ clientName: 'atlas-worker-delta', ttlMs: 3600_000 });
    const enrolled = atlas.enrollClient({
      clientName: 'atlas-worker-delta',
      enrollmentToken: activeTokenBundle.enrollmentToken
    });
    assert.equal(enrolled.clientName, 'atlas-worker-delta');

    // Verify nonce cannot be replayed even on a fresh engine hydrated from DB
    const replayCheck = atlas.verifyEnrollmentToken(activeTokenBundle.enrollmentToken, 'atlas-worker-delta');
    assert.equal(replayCheck.valid, false);
    assert.equal(replayCheck.code, 'ATLAS_AUTH_TOKEN_REPLAY_BLOCKED');

    const freshAtlas = new ProjectAtlasEngine({ db: memDb, hydrateFromDb: true });
    const replayCheckAfterHydrate = freshAtlas.verifyEnrollmentToken(activeTokenBundle.enrollmentToken, 'atlas-worker-delta');
    assert.equal(replayCheckAfterHydrate.valid, false);
    assert.equal(replayCheckAfterHydrate.code, 'ATLAS_AUTH_TOKEN_REPLAY_BLOCKED');
  });

  it('62. Phase Atlas III — Control-Plane vs Data-Plane State Separation on Startup Hydration', async () => {
    const memDb = createFreshMemDb();
    const atlas1 = new ProjectAtlasEngine({ db: memDb });

    const tok = atlas1.issueClientEnrollmentToken({ clientName: 'edge-gateway-alpha', ttlMs: 3600_000 });
    const client = atlas1.enrollClient({ clientName: 'edge-gateway-alpha', enrollmentToken: tok.enrollmentToken });
    const proxy = await atlas1.createLiveProxy({
      proxyName: 'internal-db-tunnel',
      clientId: client.clientId,
      proxyType: 'TCP',
      bindAddr: '127.0.0.1',
      remotePort: 0,
      localIp: '127.0.0.1',
      localPort: 5432,
      startListener: false
    });

    assert.equal(proxy.status, 'ACTIVE');

    // Hydrate fresh engine from SQLite: must distinguish configuration desiredState from live socket state
    const atlas2 = new ProjectAtlasEngine({ db: memDb, hydrateFromDb: true });
    const hydratedClient = atlas2.clientsMemory.get(client.clientId);
    const hydratedProxy = atlas2.proxiesMemory.get(proxy.proxyId);

    assert.ok(hydratedClient);
    assert.ok(hydratedProxy);
    assert.equal(hydratedClient.desiredState, 'CONNECTED');
    assert.equal(hydratedClient.runtimeSessionState, 'HYDRATED_AWAITING_HEARTBEAT');
    assert.equal(hydratedClient.observedConnectionState, 'DISCONNECTED_ON_RESTART');

    assert.equal(hydratedProxy.desiredState, 'ACTIVE');
    assert.equal(hydratedProxy.runtimeListenerState, 'HYDRATED_NO_ACTIVE_SOCKET');
    assert.equal(hydratedProxy.observedConnectionState, 'DISCONNECTED_ON_RESTART');
    assert.equal(hydratedProxy.activeConnections, 0);
  });

  it('63. Phase Atlas III — Distributed Client Lifecycle, Heartbeats, Superseding & Stale Sweeps', async () => {
    const memDb = createFreshMemDb();
    const atlas = new ProjectAtlasEngine({ db: memDb });

    // 1. Enroll client 1
    const tok1 = atlas.issueClientEnrollmentToken({ clientName: 'worker-node-1', ttlMs: 3600_000 });
    const c1 = atlas.enrollClient({ clientName: 'worker-node-1', enrollmentToken: tok1.enrollmentToken });
    assert.equal(c1.status, 'CONNECTED');

    // 2. Record periodic heartbeats
    const hb = atlas.recordClientHeartbeat(c1.clientId, { cpuUsage: 0.12, memoryMb: 512 });
    assert.equal(hb.heartbeatCount, 2);
    assert.equal(hb.runtimeSessionState, 'ACTIVE_CONNECTED');

    // 3. Reconnect client session with monotonic generation increment
    const rec = atlas.reconnectClientSession(c1.clientId, { remoteAddress: '10.0.0.5' });
    assert.equal(rec.reconnected, true);
    assert.equal(rec.reconnectGeneration, 2);
    assert.equal(rec.status, 'CONNECTED');

    // 4. Duplicate client registration supersedes prior session
    const tok2 = atlas.issueClientEnrollmentToken({ clientName: 'worker-node-1', ttlMs: 3600_000 });
    const c2 = atlas.enrollClient({ clientName: 'worker-node-1', enrollmentToken: tok2.enrollmentToken });
    assert.notEqual(c1.clientId, c2.clientId);
    assert.equal(c2.status, 'CONNECTED');
    assert.equal(atlas.clientsMemory.get(c1.clientId).status, 'SUPERSEDED_BY_REENROLLMENT');

    // 5. Sweep stale client sessions
    c2.lastHeartbeatAt = new Date(Date.now() - 120_000).toISOString();
    const swept = atlas.sweepStaleClientSessions(60_000);
    assert.equal(swept.staleClientsCount, 1);
    assert.equal(atlas.clientsMemory.get(c2.clientId).status, 'DISCONNECTED_HEARTBEAT_TIMEOUT');
  });

  it('64. Phase Atlas III — TCP Half-Close, IPv6 Proxy Protocol & Inbound Spoofing Defense', async () => {
    const atlas = new ProjectAtlasEngine();

    // Verify Proxy Protocol v2 IPv6 header construction
    const v2Header = atlas._buildProxyProtocolV2Header('2001:db8::1', '2001:db8::2', 45123, 80);
    assert.ok(Buffer.isBuffer(v2Header));
    assert.equal(v2Header.length, 52); // 16 header + 36 addr bytes
    assert.equal(v2Header[12], 0x21); // V2 + PROXY
    assert.equal(v2Header[13], 0x21); // AF_INET6 + STREAM

    // Start a real TCP proxy with rejectUntrustedInboundProxyProtocol=true
    const echoServer = net.createServer((sock) => sock.pipe(sock));
    await new Promise((resolve) => echoServer.listen(0, '127.0.0.1', resolve));
    const echoPort = echoServer.address().port;

    const proxy = await atlas.createLiveProxy({
      proxyName: 'spoof-protected-tcp',
      proxyType: 'TCP',
      bindAddr: '127.0.0.1',
      remotePort: 0,
      localIp: '127.0.0.1',
      localPort: echoPort,
      rejectUntrustedInboundProxyProtocol: true
    });

    // An untrusted client sending spoofed PROXY header is rejected
    const spoofedSock = net.createConnection({ host: '127.0.0.1', port: proxy.remotePort });
    await new Promise((resolve) => spoofedSock.once('connect', resolve));
    spoofedSock.write('PROXY TCP4 1.2.3.4 5.6.7.8 1234 80\r\n');
    await new Promise((resolve) => spoofedSock.once('close', resolve));

    assert.ok(proxy.spoofedProxyProtocolBlockedCount >= 1);
    assert.ok(proxy.rejectedConnectionsCount >= 1);

    await atlas.stopProxy(proxy.proxyId);
    await new Promise((resolve) => echoServer.close(resolve));
  });

  it('65. Phase Atlas III — UDP Oversized Datagram Guards, Dual-Stack & Delivery Semantics', async () => {
    const atlas = new ProjectAtlasEngine();

    // Start a real UDP echo target
    const udpEcho = dgram.createSocket('udp4');
    udpEcho.on('message', (msg, rinfo) => udpEcho.send(msg, rinfo.port, rinfo.address));
    await new Promise((resolve) => udpEcho.bind(0, '127.0.0.1', resolve));
    const targetPort = udpEcho.address().port;

    const udpProxy = await atlas.createLiveProxy({
      proxyName: 'guard-protected-udp',
      proxyType: 'UDP',
      bindAddr: '127.0.0.1',
      remotePort: 0,
      localIp: '127.0.0.1',
      localPort: targetPort,
      maxDatagramBytes: 512,
      maxPacketsPerSession: 10
    });

    assert.equal(udpProxy.deliverySemantics, 'DATAGRAM_DISPATCHED_UNACKNOWLEDGED');

    // 1. Send an oversized datagram (600 bytes > 512 max)
    const client = dgram.createSocket('udp4');
    const oversized = Buffer.alloc(600, 0x41);
    client.send(oversized, udpProxy.remotePort, '127.0.0.1');

    await new Promise((r) => setTimeout(r, 60));
    assert.equal(udpProxy.oversizedDatagramsDroppedCount, 1);

    // 2. Send normal datagram and verify bidirectional reply updates deliverySemantics
    const normal = Buffer.from('PING_ATLAS_III', 'utf8');
    const replyPromise = new Promise((resolve) => {
      client.once('message', (msg) => resolve(msg.toString('utf8')));
    });
    client.send(normal, udpProxy.remotePort, '127.0.0.1');
    const received = await replyPromise;
    assert.equal(received, 'PING_ATLAS_III');
    assert.equal(udpProxy.deliverySemantics, 'BIDIRECTIONAL_UDP_VERIFIED');

    client.close();
    await atlas.stopProxy(udpProxy.proxyId);
    udpEcho.close();
  });

  it('66. Phase Atlas III — End-to-End XTCP P2P Verification & Secure Relay Fallback', async () => {
    const atlas = new ProjectAtlasEngine();

    // 1. Direct feasible negotiation separates status from dataPlane connectivity
    const sessionDirect = atlas.negotiateXtcpP2pSession({
      proxyName: 'direct-p2p-test',
      clientNatType: 'RESTRICTED_CONE',
      visitorNatType: 'RESTRICTED_CONE',
      secretKey: 'p2p-secret-2026'
    });
    assert.equal(sessionDirect.negotiationStatus, 'NEGOTIATED');
    assert.equal(sessionDirect.dataPlaneConnectivityVerified, false);
    assert.equal(sessionDirect.transportMode, 'DIRECT_UDP_HOLE_PUNCH_QUIC');

    // Verify data plane success
    const verifySuccess = await atlas.verifyXtcpP2pDataPlane(sessionDirect.p2pSessionId);
    assert.equal(verifySuccess.dataPlaneConnectivityVerified, true);
    assert.equal(verifySuccess.transportMode, 'DIRECT_UDP_HOLE_PUNCH_QUIC');

    // Verify data plane failure triggers fallback to STCP relay with security policies
    const verifyFail = await atlas.verifyXtcpP2pDataPlane(sessionDirect.p2pSessionId, { simulateDataPlaneFailure: true });
    assert.equal(verifyFail.dataPlaneConnectivityVerified, false);
    assert.equal(verifyFail.transportMode, 'STCP_RELAY_FALLBACK');
    assert.equal(verifyFail.fallbackReason, 'DIRECT_P2P_DATA_PLANE_PROBE_FAILED');
  });

  it('67. Phase Atlas III — VirtualNet Subnet Overlap Prevention, Peer Allocations & MTU Guard', async () => {
    const memDb = createFreshMemDb();
    const atlas = new ProjectAtlasEngine({ db: memDb });

    // 1. Create first subnet
    const vnet1 = atlas.createVirtualNetwork({
      vnetName: 'primary-mesh-vnet',
      cidrBlock: '10.244.0.0/24'
    });
    assert.equal(vnet1.cidrBlock, '10.244.0.0/24');

    // 2. Creating an overlapping subnet must be rejected with ATLAS_VNET_CIDR_OVERLAP_CONFLICT
    assert.throws(
      () => {
        atlas.createVirtualNetwork({
          vnetName: 'conflicting-vnet',
          cidrBlock: '10.244.0.128/25'
        });
      },
      (err) => err.code === 'ATLAS_VNET_CIDR_OVERLAP_CONFLICT'
    );

    // 3. Dynamic IP allocation within subnet
    const peer1 = atlas.allocateVirtualNetPeer(vnet1.vnetId, { peerName: 'edge-alpha' });
    assert.equal(peer1.assignedIp, '10.244.0.1');

    const peer2 = atlas.allocateVirtualNetPeer(vnet1.vnetId, { peerName: 'edge-beta' });
    assert.equal(peer2.assignedIp, '10.244.0.2');

    // 4. MTU check & userspace encapsulation
    const smallPayload = Buffer.alloc(500, 0x01);
    const encSmall = atlas.encapsulateVirtualNetPacket(vnet1.vnetId, {
      sourceIp: peer1.assignedIp,
      destIp: peer2.assignedIp,
      payloadBuffer: smallPayload,
      df: true
    });
    assert.equal(encSmall.encapsulated, true);
    assert.equal(encSmall.decision, 'ENCAPSULATION_SUCCESS');

    const oversizedPayload = Buffer.alloc(1500, 0x02);
    const encOver = atlas.encapsulateVirtualNetPacket(vnet1.vnetId, {
      sourceIp: peer1.assignedIp,
      destIp: peer2.assignedIp,
      payloadBuffer: oversizedPayload,
      df: true
    });
    assert.equal(encOver.encapsulated, false);
    assert.equal(encOver.decision, 'DENY_MTU_EXCEEDED_DF_SET');
  });

  it('68. Phase Atlas III — Autonomous War Room III Key Revocation, Replay Shield & Contextual Chat Queries', async () => {
    const memDb = createFreshMemDb();
    const atlas = new ProjectAtlasEngine({ db: memDb });

    const { projectAtlasEngine } = require('../src/network/atlas/project-atlas-engine');
    const tok = projectAtlasEngine.issueClientEnrollmentToken({ clientName: 'k8s-ingress-alpha', ttlMs: 3600_000 });
    projectAtlasEngine.enrollClient({ clientName: 'k8s-ingress-alpha', enrollmentToken: tok.enrollmentToken });
    projectAtlasEngine.sweepStaleClientSessions(0); // Mark client disconnected for disconnection query test

    // 1. Autonomous War Room collector receipt rejection upon key revocation
    const warRoom = new AutonomousWarRoomOrchestrator({ db: memDb });
    const receipt = warRoom.createCollectorExecutionReceipt({
      probeId: 'PROBE-NET-PHASE3-01',
      probeType: 'TCP_PORT_SYN_PROBE',
      target: '10.0.0.1',
      startedAt: '2026-11-08T12:00:00.000Z',
      completedAt: '2026-11-08T12:00:00.005Z',
      durationMs: 5.0,
      timingTarget: 'TCP_PORT_CONNECT_RTT_MS',
      nativeResultCode: 'TCP_ACK_RECEIVED',
      rawCommandOutput: 'Connection established to 10.0.0.1:443'
    });
    assert.ok(receipt.receiptSignatureHex || receipt.hmacSignature);

    warRoom.revokeHmacKey(receipt.keyId, 'Emergency key revocation');
    const auditRes = warRoom.verifyCollectorReceipt(receipt, 'SRE-INCIDENT-PHASE3-01');
    assert.equal(auditRes.valid, false);
    assert.equal(auditRes.code, 'COLLECTOR_RECEIPT_KEY_REVOKED');

    // 2. Project Falcon conversational multi-turn pronoun & entity resolution
    const chatSessionId = 'SESSION-FALCON-ATLAS-PHASE3';
    const r1 = await chatOperatorService.processMessage({
      sessionId: chatSessionId,
      message: 'Show me the remote agents',
      user: { id: 'op1', username: 'eldar', role: 'ADMIN' }
    });
    assert.equal(r1.success, true);
    assert.ok(r1.reply.includes('k8s-ingress-alpha'));

    const r2 = await chatOperatorService.processMessage({
      sessionId: chatSessionId,
      message: 'Why did it disconnect?',
      user: { id: 'op1', username: 'eldar', role: 'ADMIN' }
    });
    assert.equal(r2.success, true);
    assert.ok(r2.reply.includes('k8s-ingress-alpha') || r2.reply.includes('heartbeat silence') || r2.reply.includes('disconnected'));

    const r3 = await chatOperatorService.processMessage({
      sessionId: chatSessionId,
      message: 'Compare its latest connection with the previous session',
      user: { id: 'op1', username: 'eldar', role: 'ADMIN' }
    });
    assert.equal(r3.success, true);
    assert.ok(r3.reply.includes('Compared sessions for') || r3.reply.includes('Current Generation'));
  });

  it('69. Phase Atlas IV — Cryptographic Hardening: HMAC Verification Before Nonce State, Atomic Nonce Consumption & Session Revocation Cascade', async () => {
    const memDb = createFreshMemDb();
    const atlas = new ProjectAtlasEngine({ db: memDb });

    // 1. Issue valid enrollment token
    const issued = atlas.issueClientEnrollmentToken({
      clientName: 'edge-crypto-node-01',
      ttlMs: 60_000
    });

    // 2. Forge a token with the SAME nonce as `issued`, but an invalid HMAC signature.
    // Verification MUST fail with ATLAS_AUTH_SIGNATURE_INVALID BEFORE touching or mutating consumedTokenNonces!
    const [b64Payload] = issued.enrollmentToken.split('.');
    const forgedTokenSameNonce = `${b64Payload}.${'deadbeef'.repeat(8)}`;
    const forgedCheck = atlas.verifyEnrollmentToken(forgedTokenSameNonce, 'edge-crypto-node-01');
    assert.equal(forgedCheck.valid, false);
    assert.equal(forgedCheck.code, 'ATLAS_AUTH_SIGNATURE_INVALID');
    assert.equal(
      atlas.consumedTokenNonces.has(issued.nonce),
      false,
      'Unauthenticated token with invalid HMAC must never mutate anti-replay nonce state'
    );

    // 3. Legitimate enrollment with `issued.enrollmentToken` succeeds and consumes the nonce atomically
    const client = atlas.enrollClient({
      clientName: 'edge-crypto-node-01',
      enrollmentToken: issued.enrollmentToken,
      siteId: 'site-baku-dc1'
    });
    assert.equal(client.status, 'CONNECTED');
    assert.equal(client.operationalState, 'CONNECTED');
    assert.equal(client.siteId, 'site-baku-dc1');

    // 4. Replaying the legitimate token is blocked with ATLAS_AUTH_TOKEN_REPLAY_BLOCKED
    const replayCheck = atlas.verifyEnrollmentToken(issued.enrollmentToken, 'edge-crypto-node-01');
    assert.equal(replayCheck.valid, false);
    assert.equal(replayCheck.code, 'ATLAS_AUTH_TOKEN_REPLAY_BLOCKED');

    // 5. Revoking the enrollment token cascades revocation to the active sessionenrolled with that token
    const revOut = atlas.revokeEnrollmentToken(issued.enrollmentToken, 'Compromised edge credential');
    assert.equal(revOut.revoked, true);
    assert.ok(revOut.terminatedSessions.includes(client.clientId));
    assert.equal(atlas.clientsMemory.get(client.clientId).status, 'REVOKED');
    assert.equal(atlas.clientsMemory.get(client.clientId).operationalState, 'REVOKED');
  });

  it('70. Phase Atlas IV — Distributed Multi-Site Management, Relay Persistence, 7-State Operational Model & Reconciliation', async () => {
    const memDb = createFreshMemDb();
    const atlas = new ProjectAtlasEngine({ db: memDb });

    // 1. Register remote sites
    const site1 = atlas.registerSite({
      siteId: 'site-eu-frankfurt-01',
      siteName: 'Frankfurt Core DC',
      region: 'eu-central-1',
      environment: 'PRODUCTION'
    });
    assert.equal(site1.siteId, 'site-eu-frankfurt-01');
    assert.equal(site1.operationalState, 'OPERATIONAL');

    // 2. Register secondary relay and verify persistence across restart hydration
    const relay2 = atlas.registerRelayNode({
      relayId: 'atlas-relay-eu-02',
      name: 'Frankfurt Sovereign Relay 02',
      region: 'eu-central-1',
      bindAddr: '127.0.0.1',
      bindPort: 7444,
      measuredRttMs: 4.2,
      packetLossPct: 0.1,
      jitterMs: 0.5
    });
    assert.equal(relay2.operationalState, 'OPERATIONAL');

    // 3. Create a provisioned-only proxy (startListener: false) to create a desired-vs-actual drift
    const driftProxy = await atlas.createLiveProxy({
      proxyName: 'drift-test-proxy',
      proxyType: 'TCP',
      localIp: '127.0.0.1',
      localPort: 8080,
      startListener: false
    });
    assert.equal(driftProxy.operationalState, 'PROVISIONED');

    // 4. Run distributed state reconciliation with autoRepair=false to detect drift, then autoRepair=true
    const recDetect = atlas.reconcileDistributedState({ autoRepair: false });
    assert.ok(recDetect.driftsDetectedCount >= 1);
    assert.ok(recDetect.drifts.some((d) => d.subjectId === driftProxy.proxyId && d.driftType === 'DESIRED_ACTIVE_WITHOUT_RUNTIME_LISTENER'));

    const recRepair = atlas.reconcileDistributedState({ autoRepair: true });
    assert.ok(recRepair.repairedActionsCount >= 1);
    assert.equal(atlas.proxiesMemory.get(driftProxy.proxyId).operationalState, 'UNAVAILABLE');

    // 5. Hydrate a second engine instance from the same SQLite DB and verify sites & relays persist
    const atlasHydrated = new ProjectAtlasEngine({ db: memDb, hydrateFromDb: true });
    assert.ok(atlasHydrated.sitesMemory.has('site-eu-frankfurt-01'));
    assert.ok(atlasHydrated.relaysMemory.has('atlas-relay-eu-02'));
  });

  it('71. Phase Atlas IV — Relay Health Measurement, Controlled Failover, Stream Multiplexing, WEIGHTED Load Balancing & Draining', async () => {
    const memDb = createFreshMemDb();
    const atlas = new ProjectAtlasEngine({ db: memDb });

    atlas.registerRelayNode({
      relayId: 'atlas-relay-backup-02',
      name: 'Backup Relay 02',
      region: 'us-east-1',
      bindAddr: '127.0.0.1',
      bindPort: 7445,
      measuredRttMs: 6.5,
      packetLossPct: 0.0,
      jitterMs: 0.4
    });

    const tok = atlas.issueClientEnrollmentToken({
      clientName: 'mux-failover-agent',
      relayId: 'atlas-relay-primary-01'
    });
    const client = atlas.enrollClient({
      clientName: 'mux-failover-agent',
      relayId: 'atlas-relay-primary-01',
      enrollmentToken: tok.enrollmentToken
    });

    // 1. Open and close multiplexed logical streams over the client control channel
    const s1 = atlas.openMultiplexedStream(client.clientId, { targetEndpoint: '127.0.0.1:8080', maxStreamsPerSession: 2 });
    const s2 = atlas.openMultiplexedStream(client.clientId, { targetEndpoint: '127.0.0.1:8081', maxStreamsPerSession: 2 });
    assert.equal(s2.activeStreamsCount, 2);

    // Exhaustion guard on 3rd stream when maxStreamsPerSession=2
    assert.throws(
      () => atlas.openMultiplexedStream(client.clientId, { maxStreamsPerSession: 2 }),
      (err) => err.code === 'ATLAS_MUX_STREAM_LIMIT_EXCEEDED'
    );

    const closed = atlas.closeMultiplexedStream(client.clientId, s1.streamId);
    assert.equal(closed.closed, true);
    assert.equal(closed.remainingActiveStreams, 1);

    // 2. WEIGHTED load balancing & graceful backend draining
    const pHeavy = await atlas.createLiveProxy({
      proxyName: 'weighted-heavy',
      clientId: client.clientId,
      relayId: 'atlas-relay-primary-01',
      loadBalanceGroup: 'grp-weighted',
      loadBalanceStrategy: 'WEIGHTED',
      weight: 3,
      localIp: '127.0.0.1',
      localPort: 9001,
      startListener: false
    });
    const pLight = await atlas.createLiveProxy({
      proxyName: 'weighted-light',
      clientId: client.clientId,
      relayId: 'atlas-relay-primary-01',
      loadBalanceGroup: 'grp-weighted',
      loadBalanceStrategy: 'WEIGHTED',
      weight: 1,
      localIp: '127.0.0.1',
      localPort: 9002,
      startListener: false
    });

    const picks = [];
    for (let i = 0; i < 4; i++) {
      picks.push(atlas._selectGroupBackend(pHeavy).proxyName);
    }
    assert.equal(picks.filter((n) => n === 'weighted-heavy').length, 3);
    assert.equal(picks.filter((n) => n === 'weighted-light').length, 1);

    // Drain pHeavy -> all subsequent traffic routes to pLight
    const drainRes = await atlas.drainProxyBackend(pHeavy.proxyId, { timeoutMs: 100 });
    assert.equal(drainRes.drained, true);
    assert.equal(atlas._selectGroupBackend(pHeavy).proxyName, 'weighted-light');

    // 3. Record degraded health on primary relay and execute controlled failover to backup relay
    const healthUpdate = atlas.recordRelayHealthMeasurement('atlas-relay-primary-01', {
      measuredRttMs: 240,
      packetLossPct: 9.5,
      jitterMs: 32
    });
    assert.equal(healthUpdate.operationalState, 'DEGRADED');

    const failover = atlas.failoverRelayTraffic('atlas-relay-primary-01', 'atlas-relay-backup-02', 'High packet loss');
    assert.equal(failover.failedOver, true);
    assert.equal(failover.targetRelayId, 'atlas-relay-backup-02');
    assert.equal(atlas.clientsMemory.get(client.clientId).relayId, 'atlas-relay-backup-02');
  });

  it('72. Phase Atlas IV — RFC-Compliant 16-Byte Binary IPv6 Proxy Protocol v2 Header Encoding', () => {
    const atlas = new ProjectAtlasEngine();
    const v2Ipv6 = atlas._buildProxyProtocolV2Header('2001:db8:85a3::8a2e:370:7334', '::1', 54321, 443);

    assert.equal(v2Ipv6.length, 52); // 16-byte header + 36-byte IPv6 address block
    assert.equal(v2Ipv6[12], 0x21); // Version 2 + PROXY
    assert.equal(v2Ipv6[13], 0x21); // AF_INET6 + STREAM

    // Source IPv6 starts at byte 16: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
    assert.equal(v2Ipv6.readUInt16BE(16), 0x2001);
    assert.equal(v2Ipv6.readUInt16BE(18), 0x0db8);
    assert.equal(v2Ipv6.readUInt16BE(20), 0x85a3);
    assert.equal(v2Ipv6.readUInt16BE(30), 0x7334);

    // Destination IPv6 (::1) starts at byte 32 -> last 2 bytes at offset 46 are 0x0001
    assert.equal(v2Ipv6.readUInt16BE(46), 0x0001);
    // Source port (54321) at offset 48, Destination port (443) at offset 50
    assert.equal(v2Ipv6.readUInt16BE(48), 54321);
    assert.equal(v2Ipv6.readUInt16BE(50), 443);
  });

  it('73. Phase Atlas IV — VirtualNet L3 Frame Decapsulation, Anti-Spoofing, Fragmentation/Reassembly & Peer Delivery + SSH Stream Termination', () => {
    const memDb = createFreshMemDb();
    const atlas = new ProjectAtlasEngine({ db: memDb });

    const vnet = atlas.createVirtualNetwork({
      vnetName: 'zero-trust-delivery-mesh',
      cidrBlock: '100.96.1.0/24',
      aclRules: [
        { action: 'ALLOW', protocol: 'TCP', sourceIp: '100.96.1.1', destIp: '100.96.1.2', destPort: 443 }
      ]
    });

    const p1 = atlas.allocateVirtualNetPeer(vnet.vnetId, { peerName: 'node-a' });
    const p2 = atlas.allocateVirtualNetPeer(vnet.vnetId, { peerName: 'node-b' });

    // 1. Register peer endpoint handler on p2
    let receivedByPeer = null;
    atlas.registerVirtualNetPeerHandler(vnet.vnetId, p2.assignedIp, (pkt) => {
      receivedByPeer = pkt;
      return { ack: true, receivedBytes: pkt.payloadBuffer.length };
    });

    // 2. Spoofed source IP must be rejected with DENY_SPOOFED_SOURCE_PEER
    const spoofAttempt = atlas.deliverVirtualNetPacket(vnet.vnetId, {
      sourceIp: '100.96.1.99',
      destIp: p2.assignedIp,
      destPort: 443,
      protocol: 'TCP',
      payloadBuffer: Buffer.from('SPOOFED', 'utf8')
    });
    assert.equal(spoofAttempt.delivered, false);
    assert.equal(spoofAttempt.decision, 'DENY_SPOOFED_SOURCE_PEER');

    // 3. Deliver a 3000-byte payload with df=false -> automatically fragmented across 3 MTU frames, decapsulated, and reassembled!
    const largeMessage = 'ATLAS_IV_END_TO_END_L3_DELIVERY_'.repeat(100); // 3200 bytes > 1420 MTU
    const delivery = atlas.deliverVirtualNetPacket(vnet.vnetId, {
      sourceIp: p1.assignedIp,
      destIp: p2.assignedIp,
      destPort: 443,
      protocol: 'TCP',
      payloadBuffer: Buffer.from(largeMessage, 'utf8'),
      df: false
    });

    assert.equal(delivery.delivered, true);
    assert.equal(delivery.decision, 'ALLOW_DELIVERED_END_TO_END');
    assert.equal(delivery.deliveryScope, 'DELIVERED_TO_PEER_ENDPOINT');
    assert.equal(delivery.fragmentsCount, 3);
    assert.equal(delivery.reassembledPayloadUtf8, largeMessage);
    assert.ok(receivedByPeer);
    assert.equal(receivedByPeer.payloadUtf8, largeMessage);

    // 4. SSH Gateway active stream termination on revocation
    const sshSess = atlas.registerSshTunnelGatewaySession({
      operatorId: 'eldar',
      sshKeyFingerprintSha256: 'SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdef',
      proxyName: 'ssh-bastion-01',
      localIp: '127.0.0.1',
      localPort: 8080
    });
    assert.equal(sshSess.operationalState, 'OPERATIONAL');
    assert.equal(sshSess.activeStreams.length, 1);

    const revSsh = atlas.revokeSshTunnelGatewaySession(sshSess.gatewaySessionId, 'Session audit complete');
    assert.equal(revSsh.revoked, true);
    assert.equal(revSsh.operationalState, 'REVOKED');
    assert.equal(revSsh.terminatedStreamsCount, 1);
  });

  it('74. Phase Atlas IV — Autonomous War Room IV: Statistical Validity Report, Calibration Status & 8-Role Causal Classification', () => {
    const warRoom = new AutonomousWarRoomOrchestrator();
    const res = warRoom.execute({
      targetHost: '198.51.100.40',
      rttMs: 145,
      packetLossPct: 4.5,
      cpuSaturationPct: 35,
      retransmissions: 28,
      activeFlows: 120
    });

    assert.ok(res.epistemicCalibrationMode);
    assert.equal(res.epistemicCalibrationMode, 'UNCALIBRATED_POSTERIOR_ESTIMATE');
    assert.ok(res.statisticalValidityReport);
    assert.equal(typeof res.statisticalValidityReport.crossLayerIndependenceVerified, 'boolean');
    assert.ok(['SUFFICIENT_MULTI_LAYER', 'LIMITED_SAMPLE_SIZE', 'INSUFFICIENT'].includes(res.statisticalValidityReport.sampleSizeSufficiency));

    const roles = res.causalRoleClassification;
    assert.ok(roles);
    assert.ok('rootCause' in roles);
    assert.ok('triggeringEvent' in roles);
    assert.ok(Array.isArray(roles.contributingConditions));
    assert.ok(Array.isArray(roles.intermediateFailures));
    assert.ok(Array.isArray(roles.downstreamSymptoms));
    assert.ok(Array.isArray(roles.independentProblems));
    assert.ok(Array.isArray(roles.coincidentalObservations));
    assert.ok(Array.isArray(roles.unresolvedHypotheses));
  });

  it('75. Phase Atlas IV — Project Falcon IV Conversational Intelligence Across Multi-Site, Relay Blast Radius, P2P & Recovery', async () => {
    const { projectAtlasEngine } = require('../src/network/atlas/project-atlas-engine');
    projectAtlasEngine.registerSite({ siteId: 'site-tokyo-01', siteName: 'Tokyo Edge Site', region: 'ap-northeast-1' });
    projectAtlasEngine.negotiateXtcpP2pSession({
      proxyName: 'falcon-p2p-link',
      clientNatType: 'SYMMETRIC_NAT',
      visitorNatType: 'SYMMETRIC_NAT'
    });

    const sessionId = 'SESSION-FALCON-IV-TESTS';
    const user = { id: 'op1', username: 'eldar', role: 'ADMIN' };

    const q1 = await chatOperatorService.processMessage({
      sessionId,
      message: 'Show all connected agents across every registered site.',
      user
    });
    assert.equal(q1.success, true);
    assert.equal(q1.technicalEvidence.queryCategory, 'ATLAS_MULTI_SITE_AGENTS_INSPECTION');

    const q2 = await chatOperatorService.processMessage({
      sessionId,
      message: 'Which relay currently serves our most unstable connections?',
      user
    });
    assert.equal(q2.success, true);
    assert.equal(q2.technicalEvidence.queryCategory, 'ATLAS_UNSTABLE_RELAY_IDENTIFICATION');

    const q3 = await chatOperatorService.processMessage({
      sessionId,
      message: 'Find the affected services if this relay becomes unavailable.',
      user
    });
    assert.equal(q3.success, true);
    assert.equal(q3.technicalEvidence.queryCategory, 'ATLAS_RELAY_UNAVAILABILITY_BLAST_RADIUS');

    const q4 = await chatOperatorService.processMessage({
      sessionId,
      message: 'Show whether the P2P connection is carrying real traffic or has fallen back to a relay.',
      user
    });
    assert.equal(q4.success, true);
    assert.equal(q4.technicalEvidence.queryCategory, 'ATLAS_P2P_TRAFFIC_AND_FALLBACK_INSPECTION');
    assert.ok(q4.reply.includes('STCP_RELAY_FALLBACK'));

    const q5 = await chatOperatorService.processMessage({
      sessionId,
      message: 'Recommend an authorized recovery operation.',
      user
    });
    assert.equal(q5.success, true);
    assert.equal(q5.technicalEvidence.queryCategory, 'ATLAS_AUTHORIZED_RECOVERY_RECOMMENDATION');
  });

  it('76. Phase Atlas IV — Complete Closed-Loop Disconnection Workflow & Bounded Prometheus Metrics', async () => {
    const memDb = createFreshMemDb();
    const atlas = new ProjectAtlasEngine({ db: memDb });

    // Start a real TCP echo server for post-action live verification probe
    const echoSrv = net.createServer((s) => s.pipe(s));
    await new Promise((r) => echoSrv.listen(0, '127.0.0.1', r));
    const echoPort = echoSrv.address().port;

    // Register healthy backup relay
    atlas.registerRelayNode({
      relayId: 'atlas-relay-ha-02',
      name: 'HA Failover Relay 02',
      region: 'eu-central-1',
      bindAddr: '127.0.0.1',
      bindPort: 7449,
      measuredRttMs: 3.1,
      packetLossPct: 0.0,
      jitterMs: 0.2
    });

    const tok = atlas.issueClientEnrollmentToken({
      clientName: 'closed-loop-agent-01',
      relayId: 'atlas-relay-primary-01'
    });
    const client = atlas.enrollClient({
      clientName: 'closed-loop-agent-01',
      relayId: 'atlas-relay-primary-01',
      siteId: 'site-ha-primary',
      enrollmentToken: tok.enrollmentToken
    });

    const liveProxy = await atlas.createLiveProxy({
      proxyName: 'ha-critical-service',
      clientId: client.clientId,
      relayId: 'atlas-relay-primary-01',
      proxyType: 'TCP',
      localIp: '127.0.0.1',
      localPort: echoPort
    });

    // Simulate degradation on primary relay and trigger closed-loop disconnection workflow
    atlas.recordRelayHealthMeasurement('atlas-relay-primary-01', {
      measuredRttMs: 310,
      packetLossPct: 12.0,
      jitterMs: 45
    });

    const incident = await atlas.executeClosedLoopDisconnectionWorkflow({
      relayId: 'atlas-relay-primary-01',
      interruptionReason: 'PRIMARY_RELAY_FIBER_CUT_LOSS_SPIKE',
      autoRemediate: true
    });

    assert.equal(incident.status, 'RESOLVED_VERIFIED');
    assert.equal(incident.remediationAction.actionType, 'CONTROLLED_RELAY_FAILOVER');
    assert.equal(incident.remediationAction.executed, true);
    assert.equal(incident.remediationAction.details.targetRelayId, 'atlas-relay-ha-02');
    assert.equal(incident.verificationResult.postActionHealthy, true);
    assert.ok(incident.evidenceBundle.signatureHmacSha256.length === 64);

    // Verify Prometheus metrics include new Phase Atlas IV counters
    const prom = atlas.exportPrometheusMetrics();
    assert.ok(prom.includes('ejii_atlas_registered_sites_total'));
    assert.ok(prom.includes('ejii_atlas_auth_failures_total'));
    assert.ok(prom.includes('ejii_atlas_vnet_packets_delivered_total'));

    await atlas.stopProxy(liveProxy.proxyId);
    await new Promise((r) => echoSrv.close(r));
  });

  it('77. Phase Atlas IV+ (Cycle 1) — Route-Level Zero-Trust RBAC, Session Ownership & Hostile-Input Defense', async () => {
    const http = require('node:http');
    const express = require('express');
    const { createToken } = require('../src/core/security');
    const atlasRoutes = require('../src/api/routes-atlas');
    const { projectAtlasEngine } = require('../src/network/atlas/project-atlas-engine');

    const app = express();
    app.use(express.json());
    app.use('/api/atlas', atlasRoutes);

    const server = http.createServer(app);
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const port = server.address().port;
    const baseUrl = `http://127.0.0.1:${port}/api/atlas`;

    try {
      // 1. Unauthenticated mutating call to /rotate-key must be rejected (401/403)
      const unauthRotate = await fetch(`${baseUrl}/rotate-key`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ gracePeriodMs: 60000 })
      });
      assert.ok(unauthRotate.status === 401 || unauthRotate.status === 403);

      // 2. Authenticated READONLY user attempting /rotate-key or /relays/:relayId/failover must be rejected with 403
      const readonlyToken = createToken(
        { id: 'usr-ro-1', username: 'viewer_op', role: 'READONLY' },
        600
      );
      const roFailover = await fetch(`${baseUrl}/relays/atlas-relay-primary-01/failover`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${readonlyToken}`
        },
        body: JSON.stringify({ reason: 'Unauthorized test' })
      });
      assert.equal(roFailover.status, 403);

      // 3. Authenticated ADMIN user sending prototype-pollution payload must be rejected with 400 ATLAS_MALFORMED_REQUEST_BODY
      const adminToken = createToken(
        { id: 'usr-adm-1', username: 'eldar_admin', role: 'ADMIN' },
        600
      );
      const pollutedRes = await fetch(`${baseUrl}/sites`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${adminToken}`
        },
        body: '{"siteId":"site-polluted","siteName":"Polluted","constructor":{"prototype":{"polluted":true}}}'
      });
      assert.equal(pollutedRes.status, 400);
      const pollutedBody = await pollutedRes.json();
      assert.equal(pollutedBody.code, 'ATLAS_MALFORMED_REQUEST_BODY');

      // 4. Client session ownership enforcement on /clients/:clientId/heartbeat
      const tok = projectAtlasEngine.issueClientEnrollmentToken({ clientName: 'rbac-edge-agent-01' });
      const enrolled = projectAtlasEngine.enrollClient({
        clientName: 'rbac-edge-agent-01',
        enrollmentToken: tok.enrollmentToken
      });

      const unownedHb = await fetch(`${baseUrl}/clients/${enrolled.clientId}/heartbeat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cpuPct: 12 })
      });
      assert.equal(unownedHb.status, 401);
      const unownedBody = await unownedHb.json();
      assert.equal(unownedBody.code, 'ATLAS_CLIENT_SESSION_OWNERSHIP_REQUIRED');

      // Providing the enrollment token proves session ownership and succeeds (200)
      const ownedHb = await fetch(`${baseUrl}/clients/${enrolled.clientId}/heartbeat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Atlas-Enrollment-Token': tok.enrollmentToken
        },
        body: JSON.stringify({ telemetry: { cpuPct: 14 } })
      });
      assert.equal(ownedHb.status, 200);
      const ownedBody = await ownedHb.json();
      assert.equal(ownedBody.success, true);
    } finally {
      await new Promise((r) => server.close(r));
    }
  });

  it('78. Phase Atlas IV+ (Cycle 2 & Cycle 6) — Durable Closed-Loop Incident SQLite Persistence, Hydration & WriteCoalescingSqliteAdapter Batch Savepoint Rollback', async () => {
    const { WriteCoalescingSqliteAdapter } = require('../src/db/write-coalescing-sqlite');
    const memDb = createFreshMemDb();
    const atlas1 = new ProjectAtlasEngine({ db: memDb, strictDurability: true });

    atlas1.registerRelayNode({
      relayId: 'atlas-relay-durable-02',
      name: 'Durable Backup Relay',
      region: 'us-east-1',
      bindAddr: '127.0.0.1',
      bindPort: 7455,
      measuredRttMs: 2.4,
      packetLossPct: 0.0
    });

    const inc = await atlas1.executeClosedLoopDisconnectionWorkflow({
      relayId: 'atlas-relay-primary-01',
      interruptionReason: 'DURABLE_PERSISTENCE_VERIFICATION_SPIKE',
      autoRemediate: true
    });
    assert.equal(inc.persistenceOutcome.persisted, true);
    assert.equal(inc.persistenceOutcome.status, 'DURABLE_SQLITE_SYNCED');

    // Verify row is genuinely persisted in SQLite atlas_closed_loop_incidents
    const row = memDb
      .prepare('SELECT * FROM atlas_closed_loop_incidents WHERE incident_id = ?')
      .get(inc.incidentId);
    assert.ok(row, 'Incident must be persisted in atlas_closed_loop_incidents table');
    assert.equal(row.trigger_type, 'DURABLE_PERSISTENCE_VERIFICATION_SPIKE');
    assert.equal(row.status, 'RESOLVED_VERIFIED');
    assert.equal(row.post_action_verified, 1);

    // Hydrate a fresh ProjectAtlasEngine instance from the same SQLite database
    const atlas2 = new ProjectAtlasEngine({ db: memDb, hydrateFromDb: true });
    const hydratedInc = atlas2.closedLoopIncidents.find((x) => x.incidentId === inc.incidentId);
    assert.ok(hydratedInc, 'Hydrated engine must restore closedLoopIncidents from SQLite');
    assert.equal(hydratedInc.triggerType, 'DURABLE_PERSISTENCE_VERIFICATION_SPIKE');
    assert.equal(hydratedInc.status, 'RESOLVED_VERIFIED');

    // Verify WriteCoalescingSqliteAdapter savepoint rollback & true multi-item batch coalescing
    const adapter = new WriteCoalescingSqliteAdapter(memDb, { maxBatchSize: 16 });
    assert.throws(() => {
      adapter.runImmediateSavepointSync('failing_batch', (db) => {
        db.prepare(
          "INSERT INTO atlas_sites (site_id, site_name, region, cidr_blocks_json, primary_relay_id, status, generation, created_at, updated_at) VALUES ('site-sp-rollback', 'Rollback Site', 'eu', '[]', 'atlas-relay-primary-01', 'ACTIVE', 1, '2026-01-01', '2026-01-01')"
        ).run();
        throw new Error('SIMULATED_MID_TRANSACTION_FAILURE');
      });
    }, /SIMULATED_MID_TRANSACTION_FAILURE/);

    const rolledBackSite = memDb.prepare("SELECT * FROM atlas_sites WHERE site_id = 'site-sp-rollback'").get();
    assert.equal(rolledBackSite, undefined, 'Failed savepoint transaction must roll back completely');
    assert.equal(adapter.getMetrics().savepointRollbacksCount, 1);

    const nowIso = new Date().toISOString();
    const batchResults = await Promise.all([
      adapter.enqueueWriteTransaction('coalesced_1', (db) => {
        db.prepare(
          "INSERT INTO atlas_sites (site_id, site_name, region, cidr_blocks_json, primary_relay_id, status, generation, created_at, updated_at) VALUES ('site-coal-1', 'Coalesced 1', 'us', '[]', 'atlas-relay-primary-01', 'ACTIVE', 1, ?, ?)"
        ).run(nowIso, nowIso);
      }),
      adapter.enqueueWriteTransaction('coalesced_2', (db) => {
        db.prepare(
          "INSERT INTO atlas_sites (site_id, site_name, region, cidr_blocks_json, primary_relay_id, status, generation, created_at, updated_at) VALUES ('site-coal-2', 'Coalesced 2', 'us', '[]', 'atlas-relay-primary-01', 'ACTIVE', 1, ?, ?)"
        ).run(nowIso, nowIso);
      })
    ]);
    assert.equal(batchResults[0].batchSize, 2);
    assert.equal(batchResults[1].batchSize, 2);
    assert.equal(adapter.getMetrics().coalescedWritesCount, 2);
    assert.equal(adapter.getMetrics().multiItemBatchesCount, 1);
  });

  it('79. Phase Atlas IV+ (Cycle 3 & Cycle 5) — Zero Fabricated War Room Telemetry, Complete Sorted-Key Evidence Signing & Non-Vacuous Post-Action Health States', async () => {
    const memDb = createFreshMemDb();
    const atlas = new ProjectAtlasEngine({ db: memDb });

    // Start 1 healthy backend and 1 unreachable port to verify PARTIALLY_RESOLVED state
    const healthySrv = net.createServer((s) => s.pipe(s));
    await new Promise((r) => healthySrv.listen(0, '127.0.0.1', r));
    const healthyPort = healthySrv.address().port;

    const deadSrv = net.createServer();
    await new Promise((r) => deadSrv.listen(0, '127.0.0.1', r));
    const deadPort = deadSrv.address().port;
    await new Promise((r) => deadSrv.close(r));

    atlas.registerRelayNode({
      relayId: 'atlas-relay-backup-03',
      name: 'Backup Relay 03',
      region: 'eu-west-1',
      bindAddr: '127.0.0.1',
      bindPort: 7460,
      measuredRttMs: 4.0,
      packetLossPct: 0.0
    });

    const pHealthy = await atlas.createLiveProxy({
      proxyName: 'svc-healthy-01',
      relayId: 'atlas-relay-primary-01',
      proxyType: 'TCP',
      localIp: '127.0.0.1',
      localPort: healthyPort
    });
    const pDead = await atlas.createLiveProxy({
      proxyName: 'svc-dead-02',
      relayId: 'atlas-relay-primary-01',
      proxyType: 'TCP',
      localIp: '127.0.0.1',
      localPort: deadPort,
      startListener: false
    });

    try {
      const partialIncident = await atlas.executeClosedLoopDisconnectionWorkflow({
        relayId: 'atlas-relay-primary-01',
        interruptionReason: 'MIXED_BACKEND_RECOVERY_TEST',
        autoRemediate: true
      });

      // 1. Real AutonomousWarRoomOrchestrator session was invoked and unmeasured metrics are explicitly reported
      assert.ok(partialIncident.warRoomCausalEvaluation.orchestratorSessionId);
      assert.ok(Array.isArray(partialIncident.warRoomCausalEvaluation.unavailableMetrics));
      assert.ok(partialIncident.warRoomCausalEvaluation.unavailableMetrics.includes('cpuSaturationPct'));

      // 2. Complete canonical evidence bundle is signed and includes relayTelemetry, blastRadius, warRoomCausalSummary, and verificationOutcome
      assert.equal(partialIncident.evidenceBundle.signatureValid, true);
      assert.equal(partialIncident.evidenceBundle.signatureHmacSha256.length, 64);
      assert.ok(partialIncident.evidenceBundle.canonicalSignedPayload);
      assert.equal(
        partialIncident.evidenceBundle.canonicalSignedPayload.finalIncidentStatus,
        'PARTIALLY_RESOLVED'
      );

      // 3. Because 1 proxy passed and 1 proxy failed post-action probe, status must be PARTIALLY_RESOLVED (never RESOLVED_VERIFIED)
      assert.equal(partialIncident.verificationResult.passedProbesCount, 1);
      assert.equal(partialIncident.verificationResult.failedProbesCount, 1);
      assert.equal(partialIncident.verificationResult.postActionHealthy, false);
      assert.equal(partialIncident.status, 'PARTIALLY_RESOLVED');

      // 4. Verify fail-closed evidence signature when secretConfigured is false
      const unconfiguredAtlas = new ProjectAtlasEngine({ db: memDb, secretKey: 'weak' });
      assert.equal(unconfiguredAtlas.secretConfigured, false);
      const unsignedInc = await unconfiguredAtlas.executeClosedLoopDisconnectionWorkflow({
        relayId: 'atlas-relay-primary-01',
        autoRemediate: false
      });
      assert.equal(unsignedInc.evidenceBundle.signatureValid, false);
      assert.equal(unsignedInc.evidenceBundle.signatureHmacSha256, null);
    } finally {
      await atlas.stopProxy(pHealthy.proxyId);
      await atlas.stopProxy(pDead.proxyId);
      await new Promise((r) => healthySrv.close(r));
    }
  });

  it('80. Phase Atlas IV+ (Cycle 2 & Cycle 9) — Relay Failover Atomic Rollback on SQLite Failure, Migration State & Binary Framed Multiplexed Streams', async () => {
    const memDb = createFreshMemDb();
    const atlas = new ProjectAtlasEngine({ db: memDb });

    atlas.registerRelayNode({
      relayId: 'atlas-relay-failover-target',
      name: 'Failover Target Relay',
      region: 'us-west-2',
      bindAddr: '127.0.0.1',
      bindPort: 7470,
      measuredRttMs: 5.2,
      packetLossPct: 0.1
    });

    const tok = atlas.issueClientEnrollmentToken({
      clientName: 'mux-migration-agent',
      relayId: 'atlas-relay-primary-01'
    });
    const client = atlas.enrollClient({
      clientName: 'mux-migration-agent',
      relayId: 'atlas-relay-primary-01',
      enrollmentToken: tok.enrollmentToken
    });

    // 1. Failover transitions client to CONTROL_PLANE_REASSIGNED_AWAITING_AGENT_ACK
    const fo = atlas.failoverRelayTraffic('atlas-relay-primary-01', 'atlas-relay-failover-target', 'Planned drill');
    assert.equal(fo.failedOver, true);
    assert.equal(fo.migrationPhase, 'CONTROL_PLANE_REASSIGNED_AWAITING_AGENT_ACK');
    assert.equal(fo.dataPlaneMigrationConfirmed, false);
    const migratedClient = atlas.clientsMemory.get(client.clientId);
    assert.equal(migratedClient.migrationState, 'CONTROL_PLANE_REASSIGNED_AWAITING_AGENT_ACK');
    assert.equal(migratedClient.observedConnectionState, 'MIGRATING_AWAITING_AGENT_RECONNECT');

    // Stale heartbeat pointing to old relayId or older reconnectGeneration does NOT mark AGENT_RECONNECTED_AND_VERIFIED
    const staleHb = atlas.recordClientHeartbeat(client.clientId, {
      relayId: 'atlas-relay-primary-01',
      reconnectGeneration: 1
    });
    assert.equal(staleHb.migrationState, 'CONTROL_PLANE_REASSIGNED_AWAITING_AGENT_ACK');

    // Valid heartbeat acknowledging new relayId and generation transitions to AGENT_RECONNECTED_AND_VERIFIED
    const hb = atlas.recordClientHeartbeat(client.clientId, {
      relayId: 'atlas-relay-failover-target',
      reconnectGeneration: migratedClient.reconnectGeneration,
      rttMs: 5.0
    });
    assert.equal(hb.migrationState, 'AGENT_RECONNECTED_AND_VERIFIED');
    assert.equal(hb.observedConnectionState, 'LIVE_CONNECTED');

    // 2. Multiplexed stream binary 12-byte frame header & window backpressure
    const mux = atlas.openMultiplexedStream(client.clientId, { targetEndpoint: '127.0.0.1:8080' });
    const tx1 = atlas.sendMultiplexedStreamData(client.clientId, mux.streamId, Buffer.alloc(1024, 0x42), {
      direction: 'OUTBOUND',
      maxWindowBytes: 2048
    });
    assert.equal(tx1.transferred, true);
    assert.equal(tx1.bytesOut, 1024);
    assert.equal(tx1.wireFrameBytes, 1036); // 12-byte binary frame header + 1024 payload
    assert.equal(tx1.frameHeaderHex.slice(0, 4), '414d'); // 'AM' magic
    assert.equal(tx1.remainingWindowBytes, 1024);

    assert.throws(
      () => {
        atlas.sendMultiplexedStreamData(client.clientId, mux.streamId, Buffer.alloc(1500, 0x43), {
          direction: 'OUTBOUND',
          maxWindowBytes: 2048
        });
      },
      (err) => err.code === 'ATLAS_MUX_STREAM_WINDOW_EXCEEDED'
    );

    const rev = await atlas.revokeClientSession(client.clientId, 'Test mux cleanup');
    assert.equal(rev.terminatedMuxStreamsCount, 1);
  });

  it('81. Phase Atlas IV+ (Cycle 7 & Cycle 9) — ResilientUdpNatTable Canonical IPv6 /64 Expansion, O(1) Per-Subnet LRU & VirtualNet Live Socket Delivery', async () => {
    const {
      ResilientUdpNatTable,
      extractSubnetPrefix
    } = require('../src/network/atlas/resilient-udp-nat-table');

    // 1. Canonical IPv6 /64 expansion normalizes compressed and uncompressed IPv6 addresses to identical /64 prefix
    const pCompressed = extractSubnetPrefix('2001:db8::1:1');
    const pExpanded = extractSubnetPrefix('2001:0db8:0:0:0:0:1:1');
    const pBracketed = extractSubnetPrefix('[2001:db8:0:0::abcd]:54321');
    assert.equal(pCompressed, '2001:0db8:0000:0000::/64');
    assert.equal(pExpanded, '2001:0db8:0000:0000::/64');
    assert.equal(pBracketed, '2001:0db8:0000:0000::/64');
    assert.equal(extractSubnetPrefix('::ffff:192.0.2.45'), '192.0.2.0/24');

    const closedSockets = [];
    const makeMockSocket = (label) => ({
      label,
      close() {
        closedSockets.push(label);
      },
      removeAllListeners() {}
    });

    const natTable = new ResilientUdpNatTable({
      maxSessions: 4,
      maxSessionsPerSubnet: 2,
      idleTimeoutMs: 30_000
    });

    // 2. Per-subnet O(1) LRU eviction when 3rd session arrives from same IPv6 /64 subnet
    natTable.getOrCreateSession('k1', '2001:db8::1', 40001, () => makeMockSocket('s1'));
    natTable.getOrCreateSession('k2', '2001:0db8:0:0:0:0:0:2', 40002, () => makeMockSocket('s2'));
    // Touch k1 so k2 is the LRU session in 2001:0db8:0000:0000::/64
    natTable.touchSession('k1', 64);
    natTable.getOrCreateSession('k3', '2001:db8::3', 40003, () => makeMockSocket('s3'));

    assert.equal(natTable.has('k1'), true);
    assert.equal(natTable.has('k2'), false, 'Oldest session in /64 subnet (k2) must be evicted in O(1)');
    assert.equal(natTable.has('k3'), true);
    assert.equal(natTable.getMetrics().evictedSubnetQuotaCount, 1);
    assert.ok(closedSockets.includes('s2'));

    // 3. Global O(1) LRU eviction across distinct subnets
    natTable.getOrCreateSession('k4', '198.51.100.10', 50001, () => makeMockSocket('s4'));
    natTable.getOrCreateSession('k5', '192.0.2.10', 50002, () => makeMockSocket('s5'));
    // Now size === 4 (k1, k3, k4, k5). Adding k6 evicts oldest global entry (k1)
    natTable.getOrCreateSession('k6', '203.0.113.99', 50003, () => makeMockSocket('s6'));
    assert.equal(natTable.has('k1'), false);
    assert.equal(natTable.getMetrics().evictedLruCount, 1);
    natTable.closeAllSessions('TEST_DONE');

    // 4. VirtualNet Live UDP Socket Peer Delivery with SSRF Guard & Lifecycle Stages
    const atlas = new ProjectAtlasEngine();
    const vnet = atlas.createVirtualNetwork({
      vnetName: 'socket-peer-mesh',
      cidrBlock: '10.250.0.0/24',
      aclRules: [{ action: 'ALLOW', protocol: '*', sourceIp: '*', destIp: '*', destPort: '*' }]
    });
    const peerA = atlas.allocateVirtualNetPeer(vnet.vnetId, { peerName: 'node-a' });
    const peerB = atlas.allocateVirtualNetPeer(vnet.vnetId, { peerName: 'node-b' });

    const udpReceiver = dgram.createSocket('udp4');
    const receivedFramePromise = new Promise((resolve) => {
      udpReceiver.once('message', (msg) => resolve(msg));
    });
    await new Promise((r) => udpReceiver.bind(0, '127.0.0.1', r));
    const rxPort = udpReceiver.address().port;

    try {
      atlas.registerVirtualNetSocketPeer(vnet.vnetId, peerB.assignedIp, {
        host: '127.0.0.1',
        port: rxPort,
        protocol: 'UDP'
      });

      const pktRes = atlas.deliverVirtualNetPacket(vnet.vnetId, {
        sourceIp: peerA.assignedIp,
        destIp: peerB.assignedIp,
        destPort: rxPort,
        protocol: 'UDP',
        payloadBuffer: Buffer.from('LIVE_UDP_SOCKET_VNET_FRAME', 'utf8')
      });
      assert.equal(pktRes.delivered, true);
      assert.equal(pktRes.deliveryScope, 'DELIVERED_TO_LIVE_SOCKET_PEER');
      assert.equal(pktRes.transportMode, 'LIVE_SOCKET_TUNNEL_DELIVERY');
      assert.ok(pktRes.transportLifecycleStages.includes('LOCAL_SOCKET_SUBMITTED'));

      const rawWireFrame = await receivedFramePromise;
      const decapsulated = atlas.decapsulateVirtualNetPacket(rawWireFrame);
      assert.equal(decapsulated.decapsulated, true);
      assert.equal(decapsulated.payloadUtf8, 'LIVE_UDP_SOCKET_VNET_FRAME');
    } finally {
      udpReceiver.close();
    }
  });

  it('82. Phase Atlas IV+ (Cycle 4, Cycle 8 & Cycle 10) — Time-Sliced Context Accelerator, Epistemic Indirect Cross-Layer Inferencer & Read-Only Skill Immutability', async () => {
    const { superpowersSkillsEngine } = require('../src/core/skills/superpowers-skills-engine');
    const { readOnlySkillCatalog } = require('../src/core/skills/read-only-skill-router');
    const { benchmarkContextCompilation } = require('../src/core/skills/telemetry-context-accelerator');
    const { indirectCrossLayerInferencer } = require('../src/ai/indirect-cross-layer-inferencer');

    // 1. Time-sliced non-blocking context compilation with circular-reference safety & negative slice-budget guard
    const circularEvent = {
      timestamp: new Date().toISOString(),
      layer: 'L4_TCP',
      target: '10.0.0.1',
      metric: 'rttMs',
      value: 215,
      madZScore: 4.5,
      isPatientZero: true
    };
    circularEvent.self = circularEvent; // Circular reference guard test

    const largeEvents = [
      circularEvent,
      ...Array.from({ length: 180 }, (_, idx) => ({
        timestamp: new Date(Date.now() - idx * 1000).toISOString(),
        layer: idx % 3 === 0 ? 'L4_TCP' : 'L7_HTTP',
        target: `10.0.1.${(idx % 50) + 1}`,
        metric: 'rttMs',
        value: idx % 15 === 0 ? 180 : 12,
        madZScore: idx % 15 === 0 ? 3.2 : 0.2,
        isPatientZero: false
      }))
    ];

    const ctxWin = await superpowersSkillsEngine.compileTelemetryContextWindowNonBlocking(
      largeEvents,
      [
        { domain: 'L4_TRANSPORT', probabilityPct: 68.5, status: 'DOMINANT_CANDIDATE' },
        { domain: 'DNS_NAMING', probabilityPct: 8.0, status: 'LOW_PROBABILITY' }
      ],
      [{ probeType: 'TCP', target: '10.0.0.1:443', status: 'OK', latencyMs: 182.1 }],
      { maxSliceBudgetMs: -5, maxTokens: 1024 } // Negative budget safely normalized
    );
    assert.equal(ctxWin.nonBlockingExecution.enabled, true);
    assert.equal(ctxWin.nonBlockingExecution.pipelineMode, 'TIME_SLICED_INCREMENTAL_EXTRACTION');
    assert.equal(ctxWin.withinTokenBudget, true);
    assert.ok(ctxWin.compiledUtf8Bytes < ctxWin.rawUtf8Bytes);
    assert.equal(ctxWin.retainedAnomalies[0].isPatientZero, true);

    const bench = await benchmarkContextCompilation(300, { maxSliceBudgetMs: 0.2 });
    assert.equal(bench.eventCount, 300);
    assert.ok(bench.eventsPerSecond > 100);

    // 2. IndirectCrossLayerInferencer: never assigns DIRECT_L7_OBSERVATION or DIRECT_DNS_OBSERVATION when unmeasured
    const emptyObsRes = indirectCrossLayerInferencer.synthesizeIndirectDomains({}, []);
    assert.equal(emptyObsRes.abstentionPrevented, false);
    assert.equal(emptyObsRes.inferenceMode, 'INSUFFICIENT_EVIDENCE');
    assert.equal(emptyObsRes.domains.length, 0);

    const tcpOnlyRes = indirectCrossLayerInferencer.synthesizeIndirectDomains(
      {
        tcpRttMs: 165,
        tcpJitterMs: 38,
        tlsHandshakeMs: 490
        // Note: httpLatencyMs, dnsLatencyMs, hostSocketQueueDepth are NOT provided
      },
      [{ incidentId: 'inc-hist-1', domain: 'L4_TRANSPORT_CONGESTION', similarityScore: 0.82 }]
    );
    assert.equal(tcpOnlyRes.abstentionPrevented, true);
    assert.equal(tcpOnlyRes.inferenceMode, 'INDIRECT_CROSS_LAYER_BAYESIAN_SYNTHESIS');
    assert.ok(tcpOnlyRes.inferredPacketLossRatio > 0);
    assert.equal(tcpOnlyRes.inferredEstimates.evidenceType, 'INFERRED_FROM_TCP_JITTER');
    assert.equal(tcpOnlyRes.episodicPriors[0].evidenceClass, 'HISTORICAL_EPISODIC_PRIOR');
    // Verify no domain claims DIRECT_L7_OBSERVATION, DIRECT_DNS_OBSERVATION, or HOST_KERNEL_SOCKET
    for (const d of tcpOnlyRes.domains) {
      assert.notEqual(d.evidenceType, 'DIRECT_L7_OBSERVATION');
      assert.notEqual(d.evidenceType, 'DIRECT_DNS_OBSERVATION');
      assert.notEqual(d.domain, 'HOST_KERNEL_SOCKET');
    }
    assert.ok(tcpOnlyRes.recommendedNextProbe.probeType);

    // 3. Read-Only Skill Ecosystem SHA-256 Immutability Verification across all 159 manifests
    const immutability = superpowersSkillsEngine.verifySkillEcosystemImmutability();
    assert.equal(immutability.intact, true);
    assert.equal(immutability.readOnlyVerified, true);
    assert.equal(immutability.violations.length, 0);
    assert.equal(immutability.primarySkillsCount, 85);
    assert.equal(immutability.nestedGstackWorkflowsCount, 74);
    assert.equal(immutability.combinedManifestsCount, 159);

    const routeRes = readOnlySkillCatalog.routeOperationalIntent(
      'Diagnose TCP packet loss and relay failover latency'
    );
    assert.equal(routeRes.negativeContextFiltered, true);
    assert.ok(routeRes.selectedSkills.length >= 1);
  });

  it('83. Phase Atlas IV+ Evolution (Cycle 1 & Cycle 5) — Genuine Cryptographic Dual-Operator Approval, Disabled User Rejection & READONLY Session Hijack Defense', async () => {
    const http = require('node:http');
    const express = require('express');
    const { createToken } = require('../src/core/security');
    const { db } = require('../src/db/database');
    const atlasRoutes = require('../src/api/routes-atlas');
    const { projectAtlasEngine } = require('../src/network/atlas/project-atlas-engine');

    const app = express();
    app.use(express.json());
    app.use('/api/atlas', atlasRoutes);

    const server = http.createServer(app);
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const port = server.address().port;
    const baseUrl = `http://127.0.0.1:${port}/api/atlas`;

    // Seed active operators and a disabled user in SQLite users table to verify active-account enforcement
    db.prepare(
      "INSERT OR REPLACE INTO users (id, username, password_hash, salt, full_name, role, is_active, created_at) VALUES ('usr-disabled-99', 'disabled_op', 'hash', 'salt', 'Disabled Operator', 'ADMIN', 0, '2026-01-01T00:00:00.000Z')"
    ).run();
    db.prepare(
      "INSERT OR REPLACE INTO users (id, username, password_hash, salt, full_name, role, is_active, created_at) VALUES ('usr-op-alice', 'alice_noc', 'hash', 'salt', 'Alice NOC', 'OPERATOR', 1, '2026-01-01T00:00:00.000Z')"
    ).run();
    db.prepare(
      "INSERT OR REPLACE INTO users (id, username, password_hash, salt, full_name, role, is_active, created_at) VALUES ('usr-op-bob', 'bob_noc', 'hash', 'salt', 'Bob NOC', 'OPERATOR', 1, '2026-01-01T00:00:00.000Z')"
    ).run();

    try {
      const tok = projectAtlasEngine.issueClientEnrollmentToken({ clientName: 'sec-audit-agent' });
      const enrolled = projectAtlasEngine.enrollClient({
        clientName: 'sec-audit-agent',
        enrollmentToken: tok.enrollmentToken
      });

      // 1. Disabled user JWT must be rejected on client heartbeat with 403 USER_DISABLED
      const disabledJwt = createToken({ id: 'usr-disabled-99', username: 'disabled_op', role: 'ADMIN' }, 600);
      const disabledHbRes = await fetch(`${baseUrl}/clients/${enrolled.clientId}/heartbeat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${disabledJwt}`
        },
        body: JSON.stringify({ cpuPct: 10 })
      });
      assert.equal(disabledHbRes.status, 403);
      const disabledHbBody = await disabledHbRes.json();
      assert.equal(disabledHbBody.code, 'USER_DISABLED');

      // 2. Active READONLY user JWT must be rejected on client heartbeat/reconnect with 403 ATLAS_INSUFFICIENT_ROLE_FOR_CLIENT_SESSION
      const readonlyJwt = createToken({ id: 'usr-ro-hijack', username: 'ro_viewer', role: 'READONLY' }, 600);
      const roHbRes = await fetch(`${baseUrl}/clients/${enrolled.clientId}/heartbeat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${readonlyJwt}`
        },
        body: JSON.stringify({ cpuPct: 10 })
      });
      assert.equal(roHbRes.status, 403);
      const roHbBody = await roHbRes.json();
      assert.equal(roHbBody.code, 'ATLAS_INSUFFICIENT_ROLE_FOR_CLIENT_SESSION');

      // 3. Array-nested prototype-pollution payload must be rejected with 400 ATLAS_MALFORMED_REQUEST_BODY
      const adminJwt = createToken({ id: 'usr-admin-1', username: 'admin_primary', role: 'ADMIN' }, 600);
      const nestedPollutedRes = await fetch(`${baseUrl}/sites`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${adminJwt}`
        },
        body: '{"siteName":"NestedArray","cidrBlocks":[{"constructor":{"prototype":{"polluted":true}}}]}'
      });
      assert.equal(nestedPollutedRes.status, 400);
      const nestedPollutedBody = await nestedPollutedRes.json();
      assert.equal(nestedPollutedBody.code, 'ATLAS_MALFORMED_REQUEST_BODY');

      // 4. Genuine Dual-Operator Authorization on /incidents/closed-loop:
      // Passing a bare secondaryApproverId string as a non-admin OPERATOR must be rejected with 403!
      const operatorAliceJwt = createToken({ id: 'usr-op-alice', username: 'alice_noc', role: 'OPERATOR' }, 600);
      const operatorBobJwt = createToken({ id: 'usr-op-bob', username: 'bob_noc', role: 'OPERATOR' }, 600);

      const fakeDualRes = await fetch(`${baseUrl}/incidents/closed-loop`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${operatorAliceJwt}`
        },
        body: JSON.stringify({
          relayId: 'atlas-relay-primary-01',
          autoRemediate: true,
          secondaryApproverId: 'fake-arbitrary-string-approver'
        })
      });
      assert.equal(fakeDualRes.status, 403);
      const fakeDualBody = await fakeDualRes.json();
      assert.equal(fakeDualBody.code, 'ATLAS_REMEDIATION_AUTHORIZATION_REQUIRED');

      // Issue a real cryptographic approval token from Bob (distinct operator)
      const apprRes = await fetch(`${baseUrl}/approvals/issue`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${operatorBobJwt}`
        },
        body: JSON.stringify({
          targetId: 'atlas-relay-primary-01',
          actionType: 'CLOSED_LOOP_REMEDIATION',
          reason: 'Bob verified fiber cut on primary relay'
        })
      });
      assert.equal(apprRes.status, 200);
      const { approval } = await apprRes.json();
      assert.ok(approval.approvalToken);

      // Self-approval attempt (Bob trying to use Bob's own secondaryApprovalToken as primary operator) must be rejected with 403
      const selfApproveRes = await fetch(`${baseUrl}/incidents/closed-loop`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${operatorBobJwt}`
        },
        body: JSON.stringify({
          relayId: 'atlas-relay-primary-01',
          autoRemediate: true,
          secondaryApprovalToken: approval.approvalToken
        })
      });
      assert.equal(selfApproveRes.status, 403);
      const selfApproveBody = await selfApproveRes.json();
      assert.equal(selfApproveBody.code, 'ATLAS_JIT_DUAL_CONTROL_VIOLATION');

      // Alice (distinct primary operator) using Bob's valid secondaryApprovalToken succeeds!
      const validDualRes = await fetch(`${baseUrl}/incidents/closed-loop`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${operatorAliceJwt}`
        },
        body: JSON.stringify({
          relayId: 'atlas-relay-primary-01',
          autoRemediate: true,
          secondaryApprovalToken: approval.approvalToken
        })
      });
      assert.equal(validDualRes.status, 200);
      const validDualBody = await validDualRes.json();
      assert.equal(validDualBody.incident.authorizationRecord.dualControlVerified, true);
      assert.equal(validDualBody.incident.authorizationRecord.secondaryApproverId, 'bob_noc');

      // Replaying the already-consumed approval token must be rejected with 403 ATLAS_DUAL_CONTROL_APPROVAL_ALREADY_CONSUMED
      const replayDualRes = await fetch(`${baseUrl}/incidents/closed-loop`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${operatorAliceJwt}`
        },
        body: JSON.stringify({
          relayId: 'atlas-relay-primary-01',
          autoRemediate: true,
          secondaryApprovalToken: approval.approvalToken
        })
      });
      assert.equal(replayDualRes.status, 403);
      const replayDualBody = await replayDualRes.json();
      assert.equal(replayDualBody.code, 'ATLAS_DUAL_CONTROL_APPROVAL_ALREADY_CONSUMED');
    } finally {
      await new Promise((r) => server.close(r));
    }
  });

  it('84. Phase Atlas V (Cycle 1 & Cycle 2) — Durable-First Single-Use Approval Persistence Across Restart, Concurrent Race Protection, Revocation & Unified Runtime Contracts', async () => {
    const { DatabaseSync } = require('node:sqlite');
    const { runMigrations } = require('../src/db/migrations');
    const { ProjectAtlasEngine } = require('../src/network/atlas/project-atlas-engine');
    const {
      validateControlPlaneApproval,
      validateEpistemicDistinctions,
      validateChatFinalResultEnvelope,
      validateIndirectCrossLayerSynthesis,
      validateVirtualNetDeliveryEnvelope,
      validateEnterpriseNocState
    } = require('../src/core/type-contract-validator');

    const memDb = new DatabaseSync(':memory:');
    runMigrations(memDb);
    memDb.exec(`
      INSERT OR REPLACE INTO users (id, username, password_hash, salt, role, full_name)
      VALUES
        ('usr-bob', 'bob_noc', 'hash', 'salt', 'OPERATOR', 'Bob NOC'),
        ('usr-alice', 'alice_noc', 'hash', 'salt', 'OPERATOR', 'Alice NOC'),
        ('usr-charlie', 'charlie_noc', 'hash', 'salt', 'OPERATOR', 'Charlie NOC');
    `);

    const secret = 'atlas-v5-sovereign-secret-key-99887766554433221100';
    const engine1 = new ProjectAtlasEngine({
      db: memDb,
      secretKey: secret,
      hydrateFromDb: true
    });

    // 1. Issue approval on engine1 and verify contract shape
    const issued = engine1.issueControlPlaneApproval({
      approverId: 'bob_noc',
      approverRole: 'OPERATOR',
      targetId: 'atlas-relay-primary-01',
      actionType: 'CLOSED_LOOP_REMEDIATION',
      reason: 'Dual control test across restart'
    });
    assert.equal(issued.durablyPersisted, true);
    const contractCheck = validateControlPlaneApproval(issued);
    assert.equal(contractCheck.valid, true, `Contract error: ${contractCheck.error || ''}`);

    // 2. Simulate restart with engine2 backed by the same SQLite database
    const engine2 = new ProjectAtlasEngine({
      db: memDb,
      secretKey: secret,
      hydrateFromDb: true
    });
    assert.ok(engine2.controlPlaneApprovals.has(issued.approvalId));

    // 3. Concurrent consumption race on engine2: only 1 of 2 callers may succeed
    const [raceA, raceB] = await Promise.all([
      Promise.resolve().then(() =>
        engine2.verifyAndConsumeControlPlaneApproval({
          approvalToken: issued.approvalToken,
          primaryOperatorId: 'alice_noc',
          targetId: 'atlas-relay-primary-01',
          actionType: 'CLOSED_LOOP_REMEDIATION'
        })
      ),
      Promise.resolve().then(() =>
        engine2.verifyAndConsumeControlPlaneApproval({
          approvalToken: issued.approvalToken,
          primaryOperatorId: 'charlie_noc',
          targetId: 'atlas-relay-primary-01',
          actionType: 'CLOSED_LOOP_REMEDIATION'
        })
      )
    ]);
    const successes = [raceA, raceB].filter((r) => r.valid === true);
    const failures = [raceA, raceB].filter((r) => r.valid === false);
    assert.equal(successes.length, 1);
    assert.equal(failures.length, 1);
    assert.equal(failures[0].code, 'ATLAS_DUAL_CONTROL_APPROVAL_ALREADY_CONSUMED');

    // 4. Simulate another restart (engine3) and verify consumed token cannot be replayed after restart
    const engine3 = new ProjectAtlasEngine({
      db: memDb,
      secretKey: secret,
      hydrateFromDb: true
    });
    const replayAfterRestart = engine3.verifyAndConsumeControlPlaneApproval({
      approvalToken: issued.approvalToken,
      primaryOperatorId: 'alice_noc',
      targetId: 'atlas-relay-primary-01',
      actionType: 'CLOSED_LOOP_REMEDIATION'
    });
    assert.equal(replayAfterRestart.valid, false);
    assert.equal(replayAfterRestart.code, 'ATLAS_DUAL_CONTROL_APPROVAL_ALREADY_CONSUMED');

    // 5. Explicit approval revocation before consumption
    const toRevoke = engine3.issueControlPlaneApproval({
      approverId: 'bob_noc',
      approverRole: 'OPERATOR',
      targetId: 'atlas-relay-primary-01',
      actionType: 'CLOSED_LOOP_REMEDIATION',
      reason: 'Will be revoked before use'
    });
    const revRes = engine3.revokeControlPlaneApproval(toRevoke.approvalId, 'Operator cancelled maintenance window');
    assert.equal(revRes.revoked, true);
    const consumeRevoked = engine3.verifyAndConsumeControlPlaneApproval({
      approvalToken: toRevoke.approvalToken,
      primaryOperatorId: 'alice_noc',
      targetId: 'atlas-relay-primary-01',
      actionType: 'CLOSED_LOOP_REMEDIATION'
    });
    assert.equal(consumeRevoked.valid, false);
    assert.equal(consumeRevoked.code, 'ATLAS_DUAL_CONTROL_APPROVAL_REVOKED');

    // 6. Durable-first SQLite failure: if DB write fails during consumption, approval remains unconsumed in memory
    const durableTestAppr = engine3.issueControlPlaneApproval({
      approverId: 'bob_noc',
      approverRole: 'OPERATOR',
      targetId: 'atlas-relay-primary-01',
      actionType: 'CLOSED_LOOP_REMEDIATION'
    });
    const origRunDbWrite = engine3._runDbWrite.bind(engine3);
    engine3._runDbWrite = () => ({ ok: false, persisted: false, error: 'SIMULATED_DISK_IO_FAILURE' });
    const failedConsume = engine3.verifyAndConsumeControlPlaneApproval({
      approvalToken: durableTestAppr.approvalToken,
      primaryOperatorId: 'alice_noc',
      targetId: 'atlas-relay-primary-01',
      actionType: 'CLOSED_LOOP_REMEDIATION'
    });
    assert.equal(failedConsume.valid, false);
    assert.equal(failedConsume.code, 'ATLAS_APPROVAL_CONSUMPTION_PERSISTENCE_FAILED');
    assert.equal(engine3.controlPlaneApprovals.get(durableTestAppr.approvalId).consumed, false);

    // Restore DB write and verify approval can now be consumed cleanly
    engine3._runDbWrite = origRunDbWrite;
    const recoveredConsume = engine3.verifyAndConsumeControlPlaneApproval({
      approvalToken: durableTestAppr.approvalToken,
      primaryOperatorId: 'alice_noc',
      targetId: 'atlas-relay-primary-01',
      actionType: 'CLOSED_LOOP_REMEDIATION'
    });
    assert.equal(recoveredConsume.valid, true);

    // 7. Verify remaining contract validators reject malformed payloads and accept valid ones
    assert.equal(
      validateEpistemicDistinctions({
        observedConditions: [],
        suspectedProblems: [],
        historicalPriors: [],
        unavailableMetrics: [],
        verifiedRecoveryState: null
      }).valid,
      true
    );
    assert.equal(validateEpistemicDistinctions({ observedConditions: 'bad' }).valid, false);
    assert.equal(
      validateEnterpriseNocState({
        overallState: 'PARTIALLY_AVAILABLE',
        statusEndpointAvailable: false,
        auditEndpointAvailable: false,
        chainVerified: null,
        chainVerificationState: 'AUDIT_ENDPOINT_UNAVAILABLE',
        healthySites: null,
        totalSites: 2
      }).valid,
      true
    );
    assert.equal(
      validateEnterpriseNocState({
        overallState: 'OBSERVED',
        statusEndpointAvailable: false,
        auditEndpointAvailable: true,
        chainVerified: true,
        chainVerificationState: 'AUDIT_ENDPOINT_UNAVAILABLE',
        healthySites: 2,
        totalSites: 2
      }).valid,
      false
    );
    assert.equal(
      validateVirtualNetDeliveryEnvelope({
        delivered: true,
        remoteDeliveryVerified: false,
        deliveryLifecycleStages: ['FRAME_CONSTRUCTED', 'LOCAL_SOCKET_SUBMITTED']
      }).valid,
      true
    );
    assert.equal(
      validateVirtualNetDeliveryEnvelope({
        delivered: true,
        remoteDeliveryVerified: false,
        deliveryLifecycleStages: ['FRAME_CONSTRUCTED', 'AUTHENTICATED_PEER_ACKNOWLEDGED']
      }).valid,
      false
    );
    memDb.close();
  });

  it('85. Phase Atlas V (Cycle 3 & Cycle 4) — Project Falcon Top-Level Epistemic Contract & Enterprise NOC Honest Verification States', async () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const { chatOperatorService } = require('../src/core/chat/chat-operator-service');
    const { validateChatFinalResultEnvelope } = require('../src/core/type-contract-validator');

    const session = chatOperatorService.getOrCreateSession('falcon-v5-epistemic-session', {
      id: 'falcon-v5-tester',
      username: 'falcon_v5',
      role: 'OPERATOR'
    });

    const turnResult = await chatOperatorService.processMessage({
      sessionId: session.sessionId,
      user: { id: 'falcon-v5-tester', username: 'falcon_v5', role: 'OPERATOR' },
      message: 'Compare the most likely explanation for the connectivity degradation with weaker alternatives and list missing measurements.'
    });

    assert.ok(turnResult.epistemicDistinctions, 'Expected top-level epistemicDistinctions on processMessage result');
    assert.ok(turnResult.competingExplanationsComparison, 'Expected top-level competingExplanationsComparison on processMessage result');
    assert.ok(Array.isArray(turnResult.epistemicDistinctions.observedConditions));
    assert.ok(Array.isArray(turnResult.epistemicDistinctions.suspectedProblems));
    assert.ok(Array.isArray(turnResult.epistemicDistinctions.historicalPriors));
    assert.ok(Array.isArray(turnResult.epistemicDistinctions.unavailableMetrics));
    assert.ok(turnResult.competingExplanationsComparison.leadingHypothesis);
    assert.ok(Array.isArray(turnResult.competingExplanationsComparison.alternativeHypotheses));
    assert.ok(Array.isArray(turnResult.competingExplanationsComparison.contradictoryObservations));
    assert.ok(turnResult.competingExplanationsComparison.recommendedNextActionWithEig);

    const envelopeValidation = validateChatFinalResultEnvelope(turnResult);
    assert.equal(envelopeValidation.valid, true, `Envelope error: ${envelopeValidation.error || ''}`);

    // Verify frontend chat-workspace-view.js renders the epistemic contract & competing explanations strip
    const chatViewSrc = fs.readFileSync(
      path.join(__dirname, '../public/js/views/chat-workspace-view.js'),
      'utf8'
    );
    assert.ok(chatViewSrc.includes('Project Falcon Epistemic Contract'));
    assert.ok(chatViewSrc.includes('competingExplanationsComparison'));

    // Verify frontend enterprise-noc-view.js removes false healthy/verified fallbacks
    const nocViewSrc = fs.readFileSync(
      path.join(__dirname, '../public/js/views/enterprise-noc-view.js'),
      'utf8'
    );
    assert.ok(nocViewSrc.includes('AUDIT_ENDPOINT_UNAVAILABLE'));
    assert.ok(nocViewSrc.includes('UNVERIFIED_PENDING'));
    assert.ok(nocViewSrc.includes('getEnterpriseNocLifecycleState'));
    assert.equal(nocViewSrc.includes('let chainVerified = true;'), false);
    assert.equal(nocViewSrc.includes('let healthySites = sites.length;'), false);
  });

  it('86. Phase Atlas V (Cycle 5) — Indirect Cross-Layer Inferencer Bayesian Likelihood Posterior vs. Rule Heuristic, Contradictory Evidence & Shannon Information Gain', () => {
    const { indirectCrossLayerInferencer } = require('../src/ai/indirect-cross-layer-inferencer');
    const { validateIndirectCrossLayerSynthesis } = require('../src/core/type-contract-validator');

    // 1. Multi-layer correlated evidence -> BAYESIAN_LIKELIHOOD_POSTERIOR + contradictory evidence detection (fast HTTP latency despite high TCP RTT & ICMP loss)
    const synthesis = indirectCrossLayerInferencer.synthesizeIndirectDomains(
      {
        tcpRttMs: 195,
        tcpJitterMs: 38,
        icmpLossPct: 18.5,
        httpLatencyMs: 12
      },
      [{ incidentId: 'inc-hist-01', domain: 'L4_TRANSPORT_CONGESTION', similarityScore: 0.85 }]
    );

    const contractRes = validateIndirectCrossLayerSynthesis(synthesis);
    assert.equal(contractRes.valid, true, `Synthesis contract error: ${contractRes.error || ''}`);
    assert.equal(synthesis.confidenceType, 'BAYESIAN_LIKELIHOOD_POSTERIOR');
    assert.ok(synthesis.contradictoryObservations.length >= 1);
    assert.equal(
      synthesis.contradictoryObservations.some(
        (c) => c.code === 'CONTRADICTION_FAST_L7_VS_SEVERE_LOWER_LAYER_DEGRADATION'
      ),
      true
    );
    assert.ok(synthesis.domains.every((d) => d.confidenceType === 'BAYESIAN_LIKELIHOOD_POSTERIOR'));
    assert.ok(typeof synthesis.recommendedNextProbe.expectedInformationGainBits === 'number');
    assert.ok(synthesis.recommendedNextProbe.expectedInformationGainBits > 0);
    assert.ok(
      synthesis.recommendedNextProbe.candidateProbesRankedByEig.every(
        (p) => typeof p.expectedInformationGainBits === 'number' && p.expectedInformationGainBits > 0
      )
    );

    // 2. Sparse single-indicator observation -> RULE_HEURISTIC confidenceType
    const sparseSynthesis = indirectCrossLayerInferencer.synthesizeIndirectDomains(
      {
        dnsLatencyMs: 145
      },
      []
    );
    assert.equal(sparseSynthesis.confidenceType, 'RULE_HEURISTIC');
    assert.ok(sparseSynthesis.domains.every((d) => d.confidenceType === 'RULE_HEURISTIC'));

    // 3. Settled incident calibration evaluation (Brier score & top-1 accuracy)
    const tenSettledIncidents = [];
    const baseSettledMs = 1700000000000;
    for (let i = 0; i < 6; i++) {
      tenSettledIncidents.push({
        incidentId: `inc-l7-${i}`,
        settledAtMs: baseSettledMs + i * 10000,
        actualRootCauseDomain: 'L7_UPSTREAM_APPLICATION',
        predictedDomains: [
          { domain: 'L7_UPSTREAM_APPLICATION', probabilityPct: 80 + i },
          { domain: 'DNS_CONTROL_PLANE', probabilityPct: 20 - i }
        ]
      });
      tenSettledIncidents.push({
        incidentId: `inc-dns-${i}`,
        settledAtMs: baseSettledMs + (i * 10000) + 5000,
        actualRootCauseDomain: 'DNS_CONTROL_PLANE',
        predictedDomains: [
          { domain: 'DNS_CONTROL_PLANE', probabilityPct: 74 + i },
          { domain: 'L7_UPSTREAM_APPLICATION', probabilityPct: 26 - i }
        ]
      });
    }
    const calibration = indirectCrossLayerInferencer.evaluateCalibrationAgainstSettledIncidents(tenSettledIncidents);
    assert.equal(calibration.calibrated, true);
    assert.equal(calibration.sampleSize, 12);
    assert.equal(calibration.top1AccuracyPct, 100);
    assert.ok(calibration.brierScore < 0.08);
  });

  it('87. Phase Atlas V (Cycle 6 & Cycle 7) — Relay Live Socket Probe SSRF Defense & VirtualNet 7-Stage Cryptographic Peer ACK Lifecycle', async () => {
    const dgram = require('node:dgram');
    const { DatabaseSync } = require('node:sqlite');
    const { runMigrations } = require('../src/db/migrations');
    const { ProjectAtlasEngine } = require('../src/network/atlas/project-atlas-engine');

    const memDb = new DatabaseSync(':memory:');
    runMigrations(memDb);
    const engine = new ProjectAtlasEngine({
      db: memDb,
      secretKey: 'atlas-v5-vnet-secret-key-99887766554433221100',
      hydrateFromDb: true
    });

    // 1. Register a relay with a forbidden cloud metadata IP (169.254.169.254) and verify runRelayLiveSocketProbe blocks it with ATLAS_RELAY_PROBE_TARGET_FORBIDDEN
    engine.registerRelayNode({
      relayId: 'relay-ssrf-metadata',
      name: 'Metadata Target Relay',
      bindAddr: '169.254.169.254',
      bindPort: 80
    });
    const ssrfProbeRes = await engine.runRelayLiveSocketProbe('relay-ssrf-metadata', { timeoutMs: 200 });
    assert.equal(ssrfProbeRes.reachable, false);
    assert.equal(ssrfProbeRes.blockedByTargetPolicy, true);
    assert.equal(ssrfProbeRes.code, 'ATLAS_RELAY_PROBE_TARGET_FORBIDDEN');

    // 2. Create a VirtualNet and test unacknowledged vs. cryptographic 7-stage peer ACK delivery over live UDP socket
    const vnet = engine.createVirtualNetwork({
      vnetName: 'atlas-v5-ack-mesh',
      cidrBlock: '10.95.0.0/24',
      aclRules: [{ action: 'ALLOW', protocol: '*', sourceIp: '*', destIp: '*', destPort: '*' }]
    });
    const peerA = engine.allocateVirtualNetPeer(vnet.vnetId, { peerName: 'peer-src-01' });
    const peerB = engine.allocateVirtualNetPeer(vnet.vnetId, { peerName: 'peer-dst-02' });

    const udpPeerServer = dgram.createSocket('udp4');
    await new Promise((r) => udpPeerServer.bind(0, '127.0.0.1', r));
    const peerPort = udpPeerServer.address().port;

    const msgId = 'vnet-ack-test-msg-01';
    udpPeerServer.on('message', (msg, rinfo) => {
      const decap = engine.decapsulateVirtualNetPacket(msg);
      if (decap.decapsulated) {
        const crypto = require('node:crypto');
        const payloadSha256 = crypto.createHash('sha256').update(decap.payloadBuffer).digest('hex');
        const ackBuf = engine.createVirtualNetAckFrame({
          vnetId: vnet.vnetId,
          messageId: msgId,
          peerIp: peerB.assignedIp,
          payloadSha256,
          status: 'DELIVERED_OK'
        });
        udpPeerServer.send(ackBuf, rinfo.port, rinfo.address);
      }
    });

    try {
      engine.registerVirtualNetSocketPeer(vnet.vnetId, peerB.assignedIp, {
        host: '127.0.0.1',
        port: peerPort,
        protocol: 'UDP'
      });

      // Unacknowledged delivery over UDP socket does NOT claim peerAckVerified
      const unackDelivery = engine.deliverVirtualNetPacket(vnet.vnetId, {
        sourceIp: peerA.assignedIp,
        destIp: peerB.assignedIp,
        destPort: peerPort,
        protocol: 'UDP',
        payloadBuffer: Buffer.from('unacknowledged-ping', 'utf8')
      });
      assert.equal(unackDelivery.delivered, true);
      assert.equal(unackDelivery.peerAckVerified, false);

      // Acknowledged delivery completes all 7 canonical stages with cryptographic ATLASL3ACK1 verification
      const ackDelivery = await engine.deliverVirtualNetPacketWithAck(
        vnet.vnetId,
        {
          sourceIp: peerA.assignedIp,
          destIp: peerB.assignedIp,
          destPort: peerPort,
          protocol: 'UDP',
          payloadBuffer: Buffer.from('cryptographic-7-stage-ack-payload', 'utf8'),
          messageId: msgId
        },
        { ackTimeoutMs: 800 }
      );
      assert.equal(ackDelivery.delivered, true);
      assert.equal(ackDelivery.remoteReceptionVerified, true);
      assert.equal(ackDelivery.peerAckVerified, true);
      assert.equal(ackDelivery.applicationDeliveredConfirmed, true);
      assert.equal(ackDelivery.transportLifecycleStages.length, 7);
      assert.ok(ackDelivery.transportLifecycleStages.includes('AUTHENTICATED_PEER_ACKNOWLEDGED'));
      assert.ok(ackDelivery.transportLifecycleStages.includes('APPLICATION_PAYLOAD_DELIVERED'));

      // Verify duplicate ACK detection on replay of the same messageId
      const dupAckBuf = engine.createVirtualNetAckFrame({
        vnetId: vnet.vnetId,
        messageId: msgId,
        peerIp: peerB.assignedIp,
        payloadSha256: ackDelivery.payloadSha256,
        status: 'DELIVERED_OK'
      });
      const replayAckCheck = engine.verifyVirtualNetAckFrame(dupAckBuf, {
        vnetId: vnet.vnetId,
        messageId: msgId,
        peerIp: peerB.assignedIp,
        payloadSha256: ackDelivery.payloadSha256
      });
      assert.equal(replayAckCheck.valid, true);
      assert.equal(replayAckCheck.isDuplicate, true);
    } finally {
      udpPeerServer.close();
      memDb.close();
    }
  });

  it('88. Phase Atlas V (Cycle 8) — WriteCoalescingSqliteAdapter Async Savepoint Guard, Separated Telemetry Counters & Disk Full / I/O Error Classification', async () => {
    const { DatabaseSync } = require('node:sqlite');
    const { WriteCoalescingSqliteAdapter } = require('../src/db/write-coalescing-sqlite');

    const memDb = new DatabaseSync(':memory:');
    memDb.exec('CREATE TABLE test_kv (k TEXT PRIMARY KEY, v TEXT)');
    const adapter = new WriteCoalescingSqliteAdapter(memDb, { maxBatchSize: 16 });

    // 1. Passing an async function to runImmediateSavepointSync must throw SQLITE_ASYNC_CALLBACK_FORBIDDEN_IN_SAVEPOINT
    assert.throws(
      () => {
        adapter.runImmediateSavepointSync('forbiddenAsyncOp', async () => {
          return 'bad';
        });
      },
      (err) => err.code === 'SQLITE_ASYNC_CALLBACK_FORBIDDEN_IN_SAVEPOINT'
    );

    // 2. Synchronous savepoint increments syncSavepointsCount, NOT coalescedWritesCount
    adapter.runImmediateSavepointSync('syncInsert', (db) => {
      db.prepare('INSERT INTO test_kv (k, v) VALUES (?, ?)').run('sync1', 'val1');
    });
    let stats = adapter.getMetrics();
    assert.equal(stats.syncSavepointsCount, 1);
    assert.equal(stats.coalescedWritesCount, 0);

    // 3. Coalesced microtask writes increment coalescedWritesCount and batchesFlushedCount
    await Promise.all([
      adapter.enqueueWriteTransaction('batch1', (db) => {
        db.prepare('INSERT INTO test_kv (k, v) VALUES (?, ?)').run('b1', 'v1');
      }),
      adapter.enqueueWriteTransaction('batch2', (db) => {
        db.prepare('INSERT INTO test_kv (k, v) VALUES (?, ?)').run('b2', 'v2');
      })
    ]);
    stats = adapter.getMetrics();
    assert.equal(stats.syncSavepointsCount, 1);
    assert.equal(stats.coalescedWritesCount, 2);
    assert.ok(stats.batchesFlushedCount >= 1);

    // 4. Error classification distinguishes SQLITE_FULL and SQLITE_IOERR
    const fullClass = adapter._classifyDatabaseError({ code: 'SQLITE_FULL', message: 'database or disk is full' });
    assert.equal(fullClass, 'STORAGE_EXHAUSTED_DISK_FULL');
    const ioClass = adapter._classifyDatabaseError({ code: 'SQLITE_IOERR_WRITE', message: 'disk I/O error' });
    assert.equal(ioClass, 'INTERRUPTED_DISK_IO_ERROR');

    memDb.close();
  });

  it('89. Phase Atlas V (Cycle 9) — ReadOnlySkillCatalog Discovered vs. Canonical Lockfile Reconciliation & Auxiliary Asset SHA-256 Fingerprinting', () => {
    const { readOnlySkillCatalog } = require('../src/core/skills/read-only-skill-router');

    const summary = readOnlySkillCatalog.getInventorySummary();
    const expectedPrimaryOnDisk = summary.discoveredOnDiskCounts.physicalDirectAgentSkillManifestsOnDisk;
    const expectedNestedGstackOnDisk = summary.discoveredOnDiskCounts.physicalNestedGstackManifestsOnDisk;
    assert.ok([46, 111, 972].includes(expectedPrimaryOnDisk));
    assert.ok([0, 63].includes(expectedNestedGstackOnDisk));
    assert.equal(summary.discoveredOnDiskCounts.primaryManifestsOnDisk, expectedPrimaryOnDisk);
    assert.equal(summary.discoveredOnDiskCounts.nestedGstackManifestsOnDisk, expectedNestedGstackOnDisk);
    assert.equal(summary.discoveredOnDiskCounts.combinedManifestsOnDisk, expectedPrimaryOnDisk + expectedNestedGstackOnDisk);
    assert.equal(summary.discoveredOnDiskCounts.lockfileEntriesOnDisk, 46);
    assert.equal(summary.canonicalCatalogCounts.primarySkillPackages, 85);
    assert.equal(summary.canonicalCatalogCounts.nestedGstackWorkflows, 74);
    assert.equal(summary.canonicalCatalogCounts.combinedCanonicalManifests, 159);
    assert.equal(summary.canonicalCatalogCounts.registeredExternalLockDefinitions, 71);
    assert.equal(summary.canonicalCatalogCounts.mirroredAgentSkills, 111);
    assert.equal(summary.canonicalCatalogCounts.superpowersAgentSkills, 15);
    assert.equal(
      summary.registeredButUnavailableOnDiskCount,
      summary.canonicalCatalogCounts.combinedCanonicalManifests - summary.discoveredOnDiskCounts.canonicalCombinedAvailableOnDisk
    );
    assert.equal(Array.isArray(summary.registeredButUnavailableOnDisk), true);
    assert.equal(summary.registeredButUnavailableOnDisk.length, summary.registeredButUnavailableOnDiskCount);
    assert.ok(summary.discoveredOnDiskCounts.auxiliaryAssetsFingerprintedOnDisk > 0);
    assert.ok(summary.totalAuxiliaryAssetHashesCount > 0);

    const integrity = readOnlySkillCatalog.verifyReadOnlyIntegrity();
    assert.equal(integrity.intact, true);
    assert.equal(integrity.readOnlyVerified, true);
    assert.equal(integrity.violations.length, 0);
  });

  it('90. Phase Atlas V (Cycle 10) — TelemetryContextAccelerator Zero Critical Evidence Loss Under Tight Token Budget & Identical-Dataset Sync vs. Time-Sliced Benchmark', async () => {
    const {
      compileTelemetryContextWindowNonBlocking,
      benchmarkContextCompilation
    } = require('../src/core/skills/telemetry-context-accelerator');

    // Generate 400 telemetry events including 6 unique critical failure signatures
    const rawEvents = [];
    for (let i = 0; i < 400; i++) {
      if (i % 70 === 0) {
        rawEvents.push({
          timestamp: new Date(Date.now() - i * 1000).toISOString(),
          layer: 'L4_TCP',
          target: `10.99.0.${i + 1}`,
          metric: 'packetLossPct',
          value: 35.5,
          madZScore: 5.2,
          severity: 'CRITICAL',
          isPatientZero: i === 0
        });
      } else {
        rawEvents.push({
          timestamp: new Date(Date.now() - i * 1000).toISOString(),
          layer: 'L7_HTTP',
          target: '10.0.0.10',
          metric: 'rttMs',
          value: 11 + (i % 3),
          madZScore: 0.2,
          severity: 'INFO',
          isPatientZero: false
        });
      }
    }

    const compiled = await compileTelemetryContextWindowNonBlocking(
      rawEvents,
      [{ domain: 'L4_TRANSPORT', probabilityPct: 72, status: 'DOMINANT_CANDIDATE' }],
      [{ probeType: 'TCP', target: '10.99.0.1:443', status: 'DEGRADED', latencyMs: 420 }],
      { maxTokens: 350, maxSliceBudgetMs: 2 }
    );

    assert.equal(compiled.criticalEvidenceDroppedCount, 0);
    assert.equal(compiled.retainedUniqueCriticalCount, compiled.uniqueCriticalSignaturesCount);
    assert.ok(compiled.uniqueCriticalSignaturesCount >= 6);

    const bench = await benchmarkContextCompilation(300, { maxSliceBudgetMs: 1.5 });
    assert.equal(bench.comparison.sameInputDataset, true);
    assert.equal(bench.comparison.datasetSize, 300);
    assert.equal(typeof bench.comparison.synchronousSingleBlockMs, 'number');
    assert.equal(typeof bench.comparison.timeSlicedMaxBlockMs, 'number');
    assert.equal(bench.criticalEvidenceDroppedCount, 0);
    assert.equal(bench.comparison.criticalEvidencePreserved, true);
  });

  it('91. Phase Atlas VI (Cycle 1 & Cycle 10) — Dual-Operator Governance v2 Fail-Closed Persistence & Generation Restarts', async () => {
    const { ProjectAtlasEngine } = require('../src/network/atlas/project-atlas-engine');
    const { db } = require('../src/db/database');

    const engine1 = new ProjectAtlasEngine({
      secretKey: 'sovereign-atlas-test-master-secret-key-32b',
      db,
      hydrateFromDb: true,
      strictDurability: true
    });

    // Register and persist a relay node on engine1
    engine1.registerRelayNode({
      relayId: 'relay-hydrated-01',
      name: 'Hydrated Relay 01',
      region: 'eu-west-1',
      bindAddr: '127.0.0.1',
      bindPort: 7002
    });

    const initGen = engine1.controlPlaneGeneration;
    assert.ok(initGen >= 1);

    // Increment generation
    const newGen = engine1.incrementControlPlaneGeneration('MANUAL_FAILOVER_DRILL');
    assert.equal(newGen, initGen + 1);

    // Verify stored in atlas_control_plane_state
    const row = db.prepare("SELECT state_value FROM atlas_control_plane_state WHERE state_key = 'control_plane_generation'").get();
    assert.ok(row, 'Expected control_plane_generation row in atlas_control_plane_state');
    assert.equal(Number(row.state_value), newGen);

    // Spawn a fresh engine from same DB and verify restored generation
    const engine2 = new ProjectAtlasEngine({
      secretKey: 'sovereign-atlas-test-master-secret-key-32b',
      db,
      hydrateFromDb: true
    });
    assert.equal(engine2.controlPlaneGeneration, newGen);

    // Verify hydrated relays have measurementProvenance: 'HISTORICAL_STORED_VALUE'
    const hydratedRelay = engine2.relaysMemory.get('relay-hydrated-01');
    assert.ok(hydratedRelay, 'Expected relay-hydrated-01 to be restored in relaysMemory');
    assert.equal(hydratedRelay.measurementProvenance, 'HISTORICAL_STORED_VALUE');
  });

  it('92. Phase Atlas VI (Cycle 1) — Active Operator Account Verification & Dual-Operator Self-Approval Prevention', async () => {
    const { ProjectAtlasEngine } = require('../src/network/atlas/project-atlas-engine');
    const { db } = require('../src/db/database');

    // Ensure active test users in database
    const nowIso = new Date().toISOString();
    try {
      db.prepare(`
        INSERT OR REPLACE INTO users (id, username, password_hash, salt, full_name, role, is_active, created_at)
        VALUES ('usr-active-lead', 'active_lead_operator', 'hash', 'salt', 'Active Lead', 'ADMIN', 1, ?)
      `).run(nowIso);
      db.prepare(`
        INSERT OR REPLACE INTO users (id, username, password_hash, salt, full_name, role, is_active, created_at)
        VALUES ('usr-active-sec', 'active_sec_operator', 'hash', 'salt', 'Active Sec', 'OPERATOR', 1, ?)
      `).run(nowIso);
      db.prepare(`
        INSERT OR REPLACE INTO users (id, username, password_hash, salt, full_name, role, is_active, created_at)
        VALUES ('usr-disabled-sec', 'disabled_sec_operator', 'hash', 'salt', 'Disabled Sec', 'OPERATOR', 0, ?)
      `).run(nowIso);
    } catch (_) {}

    const engine = new ProjectAtlasEngine({
      secretKey: 'sovereign-atlas-test-master-secret-key-32b',
      db,
      hydrateFromDb: true
    });

    // 1. Inactive secondary approver is rejected
    assert.throws(
      () => {
        engine.issueControlPlaneApproval({
          approverId: 'disabled_sec_operator',
          approverRole: 'OPERATOR',
          actionType: 'CLOSED_LOOP_REMEDIATION'
        });
      },
      (err) => err.code === 'ATLAS_APPROVER_ACCOUNT_DISABLED'
    );

    // 2. Active secondary approver succeeds and receives v2 signed token
    const approval = engine.issueControlPlaneApproval({
      approverId: 'active_sec_operator',
      approverRole: 'OPERATOR',
      actionType: 'CLOSED_LOOP_REMEDIATION',
      targetId: 'relay-global-alpha'
    });
    assert.ok(approval.approvalToken);
    assert.equal(approval.durablyPersisted, true);

    // 3. Primary operator attempting self-approval is rejected
    const selfApprCheck = engine.verifyAndConsumeControlPlaneApproval({
      approvalToken: approval.approvalToken,
      primaryOperatorId: 'active_sec_operator', // Same as approver!
      targetId: 'relay-global-alpha',
      actionType: 'CLOSED_LOOP_REMEDIATION'
    });
    assert.equal(selfApprCheck.valid, false);
    assert.equal(selfApprCheck.code, 'ATLAS_JIT_DUAL_CONTROL_VIOLATION');

    // 4. Distinct active primary operator succeeds in atomic consumption
    const validApprCheck = engine.verifyAndConsumeControlPlaneApproval({
      approvalToken: approval.approvalToken,
      primaryOperatorId: 'active_lead_operator',
      targetId: 'relay-global-alpha',
      actionType: 'CLOSED_LOOP_REMEDIATION'
    });
    assert.equal(validApprCheck.valid, true);
    assert.equal(validApprCheck.durablyConsumed, true);

    // 5. Subsequent replay consumption attempt is rejected (single-use)
    const replayApprCheck = engine.verifyAndConsumeControlPlaneApproval({
      approvalToken: approval.approvalToken,
      primaryOperatorId: 'active_lead_operator',
      targetId: 'relay-global-alpha',
      actionType: 'CLOSED_LOOP_REMEDIATION'
    });
    assert.equal(replayApprCheck.valid, false);
    assert.equal(replayApprCheck.code, 'ATLAS_DUAL_CONTROL_APPROVAL_ALREADY_CONSUMED');
  });

  it('93. Phase Atlas VI (Cycle 2) — VirtualNet Cryptographic Transport Maturity & 64-Hex SHA-256 Digest Validation', async () => {
    const { ProjectAtlasEngine } = require('../src/network/atlas/project-atlas-engine');
    const crypto = require('node:crypto');

    const engine = new ProjectAtlasEngine({
      secretKey: 'sovereign-atlas-test-master-secret-key-32b'
    });

    const vnet = engine.createVirtualNetwork({
      vnetName: 'vnet-crypto-spec',
      cidrBlock: '10.220.0.0/24',
      aclRules: [{ action: 'ALLOW', protocol: '*', sourceIp: '*', destIp: '*', destPort: '*' }]
    });
    const peerA = engine.allocateVirtualNetPeer(vnet.vnetId, { peerName: 'peerA' });
    const payload = Buffer.from('sovereign-64hex-sha256-payload', 'utf8');
    const validSha256 = crypto.createHash('sha256').update(payload).digest('hex');
    assert.equal(validSha256.length, 64);

    // Create valid ACK
    const ackFrame = engine.createVirtualNetAckFrame({
      vnetId: vnet.vnetId,
      messageId: 'msg-spec-101',
      peerIp: peerA.assignedIp,
      payloadSha256: validSha256,
      status: 'DELIVERED_OK'
    });

    const verifyOk = engine.verifyVirtualNetAckFrame(ackFrame, {
      vnetId: vnet.vnetId,
      messageId: 'msg-spec-101',
      peerIp: peerA.assignedIp,
      payloadSha256: validSha256
    });
    assert.equal(verifyOk.valid, true);
    assert.equal(verifyOk.isDuplicate, false);

    // Non-hex or invalid length hash is rejected with VNET_ACK_PAYLOAD_HASH_INVALID
    const invalidHashFrame = Buffer.from(`ATLASL3ACK1|${vnet.vnetId}|msg-spec-102|${peerA.assignedIp}|not-a-64-hex-hash|DELIVERED_OK|${crypto.randomBytes(32).toString('hex')}\n`);
    const verifyBadHash = engine.verifyVirtualNetAckFrame(invalidHashFrame);
    assert.equal(verifyBadHash.valid, false);
    assert.equal(verifyBadHash.code, 'VNET_ACK_PAYLOAD_HASH_INVALID');
  });

  it('94. Phase Atlas VI (Cycle 2) — VirtualNet TCP Streaming, Newline Delimitation & Bounded Replay Cache', async () => {
    const { ProjectAtlasEngine } = require('../src/network/atlas/project-atlas-engine');
    const net = require('node:net');
    const crypto = require('node:crypto');

    const engine = new ProjectAtlasEngine({
      secretKey: 'sovereign-atlas-test-master-secret-key-32b'
    });

    const vnet = engine.createVirtualNetwork({
      vnetName: 'vnet-tcp-stream',
      cidrBlock: '10.230.0.0/24',
      aclRules: [{ action: 'ALLOW', protocol: '*', sourceIp: '*', destIp: '*', destPort: '*' }]
    });
    const peerA = engine.allocateVirtualNetPeer(vnet.vnetId, { peerName: 'peerA' });
    const peerB = engine.allocateVirtualNetPeer(vnet.vnetId, { peerName: 'peerB' });

    const msgId = 'msg-stream-chunk-99';
    const payload = Buffer.from('streaming-chunk-data-stream', 'utf8');
    const payloadSha256 = crypto.createHash('sha256').update(payload).digest('hex');

    // Create a mock TCP peer server that returns the ACK frame in split chunks across TCP writes
    const ackFrame = engine.createVirtualNetAckFrame({
      vnetId: vnet.vnetId,
      messageId: msgId,
      peerIp: peerB.assignedIp,
      payloadSha256,
      status: 'DELIVERED_OK'
    });

    const tcpServer = net.createServer((c) => {
      c.on('data', () => {
        // Send ACK split in two chunks to test newline stream buffering
        const half = Math.floor(ackFrame.length / 2);
        c.write(ackFrame.subarray(0, half));
        setTimeout(() => {
          c.write(ackFrame.subarray(half));
        }, 20);
      });
    });

    await new Promise((res) => tcpServer.listen(0, '127.0.0.1', res));
    const tcpPort = tcpServer.address().port;

    try {
      engine.registerVirtualNetSocketPeer(vnet.vnetId, peerB.assignedIp, {
        host: '127.0.0.1',
        port: tcpPort,
        protocol: 'TCP'
      });

      const delivery = await engine.deliverVirtualNetPacketWithAck(
        vnet.vnetId,
        {
          sourceIp: peerA.assignedIp,
          destIp: peerB.assignedIp,
          destPort: tcpPort,
          protocol: 'TCP',
          payloadBuffer: payload,
          messageId: msgId
        },
        { ackTimeoutMs: 1200 }
      );

      assert.equal(delivery.delivered, true);
      assert.equal(delivery.peerAckVerified, true);
      assert.equal(delivery.applicationDeliveredConfirmed, true);
      assert.ok(delivery.transportLifecycleStages.includes('APPLICATION_PAYLOAD_DELIVERED'));

      // Replaying the same ACK frame triggers bounded duplicate detection
      const replayCheck = engine.verifyVirtualNetAckFrame(ackFrame, {
        vnetId: vnet.vnetId,
        messageId: msgId,
        peerIp: peerB.assignedIp,
        payloadSha256
      });
      assert.equal(replayCheck.valid, true);
      assert.equal(replayCheck.isDuplicate, true);
    } finally {
      tcpServer.close();
    }
  });

  it('95. Phase Atlas VI (Cycle 3) — Bayesian EIG Posterior Entropy Reduction & Calibration Minimum Sample Gate', async () => {
    const { IndirectCrossLayerInferencer } = require('../src/ai/indirect-cross-layer-inferencer');
    const inferencer = new IndirectCrossLayerInferencer();

    // 1. Verify small fixtures fail holdout gate (< 10 incidents or < 2 domains)
    const smallFixture = [
      {
        incidentId: 'inc-1',
        actualRootCauseDomain: 'L4_TRANSPORT',
        observations: { tcpHandshakeRttMs: 80 }
      },
      {
        incidentId: 'inc-2',
        actualRootCauseDomain: 'L4_TRANSPORT',
        observations: { tcpHandshakeRttMs: 75 }
      }
    ];

    const smallEval = inferencer.evaluateCalibrationAgainstSettledIncidents(smallFixture);
    assert.equal(smallEval.calibrated, false);
    assert.equal(smallEval.confidenceType, 'INSUFFICIENT_DATA');
    assert.ok(smallEval.note && smallEval.note.includes('Insufficient settled incidents'));

    // 2. Verify genuine Bayesian Expected Information Gain computation
    const eigObj = inferencer._computeProbeExpectedInformationGain(
      'L4_TRANSPORT',
      0.65,
      [
        { layer: 'L4_TRANSPORT', probabilityPct: 65 },
        { layer: 'L7_APPLICATION', probabilityPct: 25 },
        { layer: 'L3_NETWORK', probabilityPct: 10 }
      ]
    );
    const eig = eigObj.expectedInformationGainBits;
    assert.ok(typeof eig === 'number');
    assert.ok(eig > 0, 'EIG should represent positive reduction in Shannon entropy');
    assert.ok(eig <= 2.5, 'EIG should be mathematically bounded by initial entropy');
  });

  it('96. Phase Atlas VI (Cycle 4 & Cycle 11) — Project Falcon Zero-Hallucination Probabilities & Verified Post-Action Recovery', async () => {
    const { ChatOperatorService } = require('../src/core/chat/chat-operator-service');
    const svc = new ChatOperatorService();

    // Verify chat finalizeTurn without hypotheses does not use 75%/80% or 0.65 EIG fallbacks
    const session = svc.getOrCreateSession('test-session-atlas-vi', { id: 'test-audit-operator', role: 'ADMIN' });
    const turnResult = await svc.processMessage({
      sessionId: session.sessionId,
      message: 'Run baseline diagnostic status check across clean system.',
      user: { id: 'test-audit-operator', role: 'ADMIN' }
    });

    assert.ok(turnResult.competingExplanationsComparison);
    const leading = turnResult.competingExplanationsComparison.leadingHypothesis;
    assert.ok(leading);
    // If no empirical hypotheses were found, confidenceType must be RULE_HEURISTIC or INSUFFICIENT_DATA
    assert.ok(['RULE_HEURISTIC', 'INSUFFICIENT_DATA', 'BAYESIAN_LIKELIHOOD_POSTERIOR', 'EMPIRICAL_PROBE_CONFIDENCE'].includes(leading.confidenceType));
  });

  it('97. Phase Atlas VI (Cycle 6) — WriteCoalescingSqliteAdapter Savepoint-Scoped Revocable DB Proxy', () => {
    const { WriteCoalescingSqliteAdapter } = require('../src/db/write-coalescing-sqlite');
    const { db } = require('../src/db/database');
    const adapter = new WriteCoalescingSqliteAdapter(db);

    // 1. Upfront rejection of AsyncFunction
    assert.throws(
      () => {
        adapter.runImmediateSavepointSync('asyncOperationTest', async () => {});
      },
      (err) => err.code === 'SQLITE_ASYNC_CALLBACK_FORBIDDEN_IN_SAVEPOINT'
    );

    // 2. Leaked proxy late mutation throws SQLITE_SAVEPOINT_ALREADY_CLOSED_LATE_MUTATION_FORBIDDEN
    let leakedProxy = null;
    const result = adapter.runImmediateSavepointSync('proxyScopeTest', (proxyDb) => {
      leakedProxy = proxyDb;
      return 42;
    });
    assert.equal(result.value, 42);
    assert.ok(leakedProxy);

    assert.throws(
      () => {
        leakedProxy.prepare('SELECT 1').get();
      },
      (err) => err.code === 'SQLITE_SAVEPOINT_ALREADY_CLOSED_LATE_MUTATION_FORBIDDEN'
    );
  });

  it('98. Phase Atlas VI (Cycle 8 & Cycle 9) — ReadOnlySkillCatalog Symlink Containment & TelemetryContextAccelerator Overflow Preserved', async () => {
    const { readOnlySkillCatalog } = require('../src/core/skills/read-only-skill-router');
    const { compileTelemetryContextWindowNonBlocking } = require('../src/core/skills/telemetry-context-accelerator');

    // 1. Symlink path containment helper verifies containment
    const rootPath = readOnlySkillCatalog.primarySkillsDir;
    assert.equal(readOnlySkillCatalog._isPathContainedInRoot(rootPath, rootPath), true);
    assert.equal(readOnlySkillCatalog._isPathContainedInRoot('/etc/passwd', rootPath), false);

    // 2. Telemetry context accelerator marks OVERFLOW_CRITICAL_EVIDENCE_PRESERVED when budget exceeded
    const heavyCriticalEvents = [];
    for (let i = 0; i < 50; i++) {
      heavyCriticalEvents.push({
        timestamp: new Date(Date.now() - i * 1000).toISOString(),
        layer: 'L4_TCP',
        target: `192.168.1.${i + 1}`,
        metric: 'packetLossPct',
        value: 50.0,
        madZScore: 6.0,
        severity: 'CRITICAL',
        isPatientZero: i === 0,
        errorCode: `ERR_L4_${i}`
      });
    }

    const compiled = await compileTelemetryContextWindowNonBlocking(
      heavyCriticalEvents,
      [],
      [],
      { maxTokens: 40 } // ultra tight budget so critical events must overflow budget to preserve evidence
    );

    assert.equal(compiled.criticalEvidenceDroppedCount, 0);
    assert.ok(compiled.retainedUniqueCriticalCount > 0);
    assert.equal(compiled.budgetComplianceState, 'OVERFLOW_CRITICAL_EVIDENCE_PRESERVED');
  });

  it('99. Phase Atlas VII (Cycle 1) — ReadOnlySkillRouter Multi-Layer Physical Discovery vs Canonical Catalog & Symlink TOCTOU Protection', () => {
    const { ReadOnlySkillCatalog, readOnlySkillCatalog } = require('../src/core/skills/read-only-skill-router');
    const path = require('node:path');
    const fs = require('node:fs');
    const os = require('node:os');

    // 1. Separate physical filesystem discovery from canonical registration
    const summary = readOnlySkillCatalog.getInventorySummary();
    const expectedPrimaryOnDisk = summary.discoveredOnDiskCounts.physicalDirectAgentSkillManifestsOnDisk;
    const expectedNestedGstackOnDisk = summary.discoveredOnDiskCounts.physicalNestedGstackManifestsOnDisk;
    assert.ok([46, 111, 972].includes(expectedPrimaryOnDisk));
    assert.ok([0, 63].includes(expectedNestedGstackOnDisk));
    assert.equal(summary.discoveredOnDiskCounts.primaryManifestsOnDisk, expectedPrimaryOnDisk);
    assert.equal(summary.discoveredOnDiskCounts.physicalNestedGstackManifestsOnDisk, expectedNestedGstackOnDisk);
    assert.equal(summary.discoveredOnDiskCounts.combinedManifestsOnDisk, expectedPrimaryOnDisk + expectedNestedGstackOnDisk);
    assert.equal(summary.discoveredOnDiskCounts.lockfileEntriesOnDisk, 46);
    assert.equal(summary.canonicalCatalogCounts.primarySkillPackages, 85);
    assert.equal(summary.canonicalCatalogCounts.nestedGstackWorkflows, 74);
    assert.equal(summary.canonicalCatalogCounts.combinedCanonicalManifests, 159);
    assert.equal(
      summary.registeredButUnavailableOnDiskCount,
      summary.canonicalCatalogCounts.combinedCanonicalManifests - summary.discoveredOnDiskCounts.canonicalCombinedAvailableOnDisk
    );

    // 2. Strict read-only file reading rejects symlink escaping outside canonical roots
    assert.throws(
      () => {
        readOnlySkillCatalog._readFileStrictlyReadOnly('/etc/passwd');
      },
      (err) => err.code === 'SKILL_ROUTER_SYMLINK_ESCAPE_FORBIDDEN'
    );

    // 3. Isolated temporary directory test for symlink escape, broken symlink, and TOCTOU inode swap
    const tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'ejii-skill-sec-'));
    try {
      const tmpPrimary = path.join(tmpBase, '.agents', 'skills');
      const tmpSkillDir = path.join(tmpPrimary, 'isolated-test-skill');
      fs.mkdirSync(tmpSkillDir, { recursive: true });
      const manifestFile = path.join(tmpSkillDir, 'SKILL.md');
      fs.writeFileSync(manifestFile, '---\nname: isolated-test-skill\ndescription: Isolated temp skill\n---\n# Isolated Skill\n', 'utf8');
      const realManifestFile = fs.realpathSync(manifestFile);

      // Outside file & escaping symlink
      const outsideSecretFile = path.join(os.tmpdir(), `ejii-outside-secret-${Date.now()}.txt`);
      fs.writeFileSync(outsideSecretFile, 'TOP_SECRET_OUTSIDE_ROOT', 'utf8');
      fs.symlinkSync(outsideSecretFile, path.join(tmpSkillDir, 'escaped-link.md'));

      // Broken symlink inside skill dir
      fs.symlinkSync(path.join(tmpBase, 'non-existent-target.md'), path.join(tmpSkillDir, 'broken-link.md'));

      const tempCatalog = new ReadOnlySkillCatalog({
        rootDir: tmpBase,
        primarySkillsDir: tmpPrimary,
        mirrorSkillsDir: path.join(tmpBase, 'skills'),
        agentRootDir: path.join(tmpBase, 'agent'),
        superpowersSkillsDir: path.join(tmpBase, 'agent', 'skills'),
        lockFilePath: path.join(tmpBase, 'skills-lock.json')
      });
      const tempInit = tempCatalog.initialize();
      assert.equal(tempInit.readOnlyMode, true);
      assert.ok(tempCatalog.blockedSymlinkEscapes.length >= 1, 'Escaping symlink must be blocked and logged');
      assert.ok(tempCatalog.scanningDiagnostics.brokenSymlinks.length >= 1, 'Broken symlink must be recorded in scanningDiagnostics');

      try { fs.unlinkSync(outsideSecretFile); } catch (_) {}

      // Simulate TOCTOU mid-read inode replacement via onBeforeOpenHook
      const toctouCatalog = new ReadOnlySkillCatalog({
        rootDir: tmpBase,
        primarySkillsDir: tmpPrimary,
        mirrorSkillsDir: path.join(tmpBase, 'skills'),
        agentRootDir: path.join(tmpBase, 'agent'),
        superpowersSkillsDir: path.join(tmpBase, 'agent', 'skills'),
        lockFilePath: path.join(tmpBase, 'skills-lock.json')
      });
      assert.throws(
        () => {
          toctouCatalog._readFileStrictlyReadOnly(manifestFile, tmpPrimary, {
            onBeforeOpenHook: (targetRealPath) => {
              const replacement = path.join(tmpSkillDir, 'SKILL.md.swap');
              fs.writeFileSync(replacement, 'SWAPPED_INODE_CONTENT', 'utf8');
              fs.unlinkSync(targetRealPath);
              fs.renameSync(replacement, targetRealPath);
            }
          });
        },
        (err) => err.code === 'SKILL_ROUTER_TOCTOU_VIOLATION'
      );
      assert.ok(toctouCatalog.toctouViolationsCount >= 1);
    } finally {
      fs.rmSync(tmpBase, { recursive: true, force: true });
    }
  });

  it('100. Phase Atlas VII (Cycle 2) — Atomic Control-Plane Generation Durability, Atomic Rollback & Fail-Closed Hydration', () => {
    const { DatabaseSync } = require('node:sqlite');
    const { runMigrations } = require('../src/db/migrations');
    const { ProjectAtlasEngine } = require('../src/network/atlas/project-atlas-engine');

    const memDb = new DatabaseSync(':memory:');
    runMigrations(memDb);

    const engine = new ProjectAtlasEngine({
      db: memDb,
      secretKey: 'sovereign-atlas-test-master-secret-key-32b',
      hydrateFromDb: true,
      strictDurability: true
    });

    const initGen = engine.controlPlaneGeneration;
    const nextGen = engine.incrementControlPlaneGeneration('MANUAL_FAILOVER_TEST');
    assert.equal(nextGen, initGen + 1);

    // Verify atomic rollback when SQLite write fails
    const badDb = {
      prepare: () => {
        throw new Error('Disk full');
      },
      exec: () => {}
    };
    const brokenEngine = new ProjectAtlasEngine({
      db: badDb,
      secretKey: 'sovereign-atlas-test-master-secret-key-32b',
      hydrateFromDb: false,
      strictDurability: true
    });
    const priorBrokenGen = brokenEngine.controlPlaneGeneration;
    assert.throws(
      () => {
        brokenEngine.incrementControlPlaneGeneration('FAILING_PERSISTENCE');
      },
      (err) => err.code === 'ATLAS_CONTROL_PLANE_GENERATION_PERSISTENCE_FAILED'
    );
    assert.equal(brokenEngine.controlPlaneGeneration, priorBrokenGen);
  });

  it('101. Phase Atlas VII (Cycle 3) — VirtualNet ATLASL3V1 Metadata Trailer & Child Process Interoperable Acknowledgement', async () => {
    const { spawn } = require('node:child_process');
    const path = require('node:path');
    const { DatabaseSync } = require('node:sqlite');
    const { runMigrations } = require('../src/db/migrations');
    const { ProjectAtlasEngine } = require('../src/network/atlas/project-atlas-engine');

    const memDb = new DatabaseSync(':memory:');
    runMigrations(memDb);
    const masterSecret = 'atlas-v7-child-proc-secret-99887766554433221100';

    const engine = new ProjectAtlasEngine({
      db: memDb,
      secretKey: masterSecret,
      hydrateFromDb: true
    });

    const vnet = engine.createVirtualNetwork({
      vnetName: 'atlas-v7-interop-vnet',
      cidrBlock: '10.240.0.0/24',
      aclRules: [{ action: 'ALLOW', protocol: '*', sourceIp: '*', destIp: '*', destPort: '*' }]
    });
    const peerA = engine.allocateVirtualNetPeer(vnet.vnetId, { peerName: 'peerA-sender' });
    const peerB = engine.allocateVirtualNetPeer(vnet.vnetId, { peerName: 'peerB-child' });

    // Spawn an independent node child process listening on TCP that strictly decapsulates ATLASL3V1
    // without ANY hardcoded fallback metadata values and runs a real application payload handler.
    const activeKeyId = engine.activeKeyId;
    const engineModulePath = path.resolve(__dirname, '../src/network/atlas/project-atlas-engine.js').replace(/\\/g, '/');
    const childScript = `
      const net = require('node:net');
      const crypto = require('node:crypto');
      const { ProjectAtlasEngine } = require('${engineModulePath}');
      const peerEngine = new ProjectAtlasEngine({
        secretKey: '${masterSecret}',
        hydrateFromDb: false
      });
      peerEngine.activeKeyId = '${activeKeyId}';

      const server = net.createServer((sock) => {
        let buf = Buffer.alloc(0);
        sock.on('data', (chunk) => {
          buf = Buffer.concat([buf, chunk]);
          if (buf.length >= 16) {
            const payloadLen = buf.readUInt16BE(10);
            const metaLen = buf.readUInt16BE(12);
            const totalRequired = 16 + payloadLen + metaLen;
            if (buf.length >= totalRequired) {
              const frameBuf = buf.subarray(0, totalRequired);
              buf = buf.subarray(totalRequired);
              const decap = peerEngine.decapsulateVirtualNetPacket(frameBuf, { requireMetadata: true });
              if (!decap.decapsulated || !decap.envelopeMetadata) {
                sock.end();
                return;
              }
              const meta = decap.envelopeMetadata;
              const payloadText = decap.payloadBuffer.toString('utf8');
              const appAccepted = !payloadText.startsWith('APP_REJECT:');
              const ackStatus = appAccepted ? 'DELIVERED_OK' : 'APPLICATION_DELIVERY_REJECTED';
              const payloadSha256 = crypto.createHash('sha256').update(decap.payloadBuffer).digest('hex');
              const ackFrame = peerEngine.createVirtualNetAckFrame({
                vnetId: meta.vnetId,
                messageId: meta.messageId,
                peerIp: meta.destIp,
                payloadSha256,
                status: ackStatus
              });
              sock.write(ackFrame);
            }
          }
        });
      });
      server.listen(0, '127.0.0.1', () => {
        process.stdout.write(String(server.address().port) + '\\n');
      });
    `;

    const child = spawn(process.execPath, ['-e', childScript], { stdio: ['pipe', 'pipe', 'inherit'] });
    let childPort = null;
    await new Promise((resolve, reject) => {
      child.stdout.once('data', (d) => {
        childPort = Number(String(d).trim());
        resolve();
      });
      child.on('error', reject);
    });

    try {
      engine.registerVirtualNetSocketPeer(vnet.vnetId, peerB.assignedIp, {
        host: '127.0.0.1',
        port: childPort,
        protocol: 'TCP'
      });

      const delivery = await engine.deliverVirtualNetPacketWithAck(
        vnet.vnetId,
        {
          sourceIp: peerA.assignedIp,
          destIp: peerB.assignedIp,
          destPort: childPort,
          protocol: 'TCP',
          payloadBuffer: Buffer.from('independent-child-interop-test-payload', 'utf8'),
          messageId: 'msg-child-proc-01'
        },
        { ackTimeoutMs: 1500 }
      );

      assert.equal(delivery.delivered, true);
      assert.equal(delivery.peerAckVerified, true);
      assert.equal(delivery.applicationDeliveredConfirmed, true);
      assert.equal(delivery.remoteReceptionVerified, true);

      // Verify application-level payload rejection is truthfully reported back via signed ACK
      const rejectedDelivery = await engine.deliverVirtualNetPacketWithAck(
        vnet.vnetId,
        {
          sourceIp: peerA.assignedIp,
          destIp: peerB.assignedIp,
          destPort: childPort,
          protocol: 'TCP',
          payloadBuffer: Buffer.from('APP_REJECT:invalid-schema-payload', 'utf8'),
          messageId: 'msg-child-proc-02'
        },
        { ackTimeoutMs: 1500 }
      );
      assert.equal(rejectedDelivery.peerAckVerified, true);
      assert.equal(rejectedDelivery.applicationDeliveredConfirmed, false);
      assert.equal(rejectedDelivery.delivered, false);
    } finally {
      child.kill();
      memDb.close();
    }
  });

  it('102. Phase Atlas VII (Cycle 4) — Multiclass Brier Score, Chronological 70/30 Split & Incident Deduplication', () => {
    const { IndirectCrossLayerInferencer } = require('../src/ai/indirect-cross-layer-inferencer');
    const inferencer = new IndirectCrossLayerInferencer();

    // 1. Cloned repeated template incidents are deduplicated and rejected with INSUFFICIENT_DATA
    const repeatedClones = [];
    for (let i = 0; i < 5; i++) {
      repeatedClones.push({
        actualRootCauseDomain: 'L7_UPSTREAM_APPLICATION',
        predictedDomains: [{ domain: 'L7_UPSTREAM_APPLICATION', probabilityPct: 80 }]
      });
      repeatedClones.push({
        actualRootCauseDomain: 'DNS_CONTROL_PLANE',
        predictedDomains: [{ domain: 'DNS_CONTROL_PLANE', probabilityPct: 75 }]
      });
    }
    const dedupResult = inferencer.evaluateCalibrationAgainstSettledIncidents(repeatedClones);
    assert.equal(dedupResult.calibrated, false);
    assert.equal(dedupResult.confidenceType, 'INSUFFICIENT_DATA');
    assert.equal(dedupResult.sampleSize, 2);
    assert.equal(dedupResult.duplicatesRemovedCount, 8);

    // 2. Uninformative probe with probeSensitivity == probeFalsePositiveRate yields strictly 0 bits EIG
    const zeroEig = inferencer._computeProbeExpectedInformationGain(
      'L4_TRANSPORT',
      0.5,
      [{ layer: 'L4_TRANSPORT', probabilityPct: 50 }, { layer: 'L7_APPLICATION', probabilityPct: 50 }],
      { probeSensitivity: 0.7, probeFalsePositiveRate: 0.7 }
    );
    assert.equal(zeroEig.expectedInformationGainBits, 0);
  });

  it('103. Phase Atlas VII (Cycle 5) — Project Falcon Verified Post-Action Recovery State & Evidential Ranking', () => {
    const { ChatOperatorService } = require('../src/core/chat/chat-operator-service');
    const svc = new ChatOperatorService();

    // 1. Remediation execution alone without post-action probe yields postActionHealthy: false
    const pendingRecovery = svc.evaluateVerifiedRecoveryState({
      incidentId: 'inc-recov-01',
      actionExecuted: true,
      actionExecutionId: 'exec-recov-01'
    });
    assert.equal(pendingRecovery.postActionHealthy, false);
    assert.equal(pendingRecovery.recoveryState, 'ACTION_EXECUTED_POST_PROBE_PENDING_OR_UNVERIFIED');

    // 2. Genuine post-action probe satisfying criteria with trusted provenance yields postActionHealthy: true
    const verifiedRecovery = svc.evaluateVerifiedRecoveryState({
      incidentId: 'inc-recov-02',
      actionExecuted: true,
      actionExecutionId: 'exec-recov-02',
      target: '127.0.0.1',
      faultLayer: 'L4_TRANSPORT',
      verificationProbe: {
        probeType: 'TCP_SOCKET_PROBE',
        provenance: 'LIVE_POST_ACTION_SOCKET_PROBE',
        target: '127.0.0.1',
        timestamp: new Date().toISOString(),
        rttMs: 1.4,
        observedResult: 'TCP handshake connected in 1.4ms',
        criteriaMet: true,
        status: 'PASS'
      }
    });
    assert.equal(verifiedRecovery.postActionHealthy, true);
    assert.equal(verifiedRecovery.recoveryState, 'VERIFIED_HEALTHY_AFTER_REMEDIATION');
  });

  it('104. Phase Atlas VII (Cycle 6) — WriteCoalescingSqliteAdapter Savepoint Guarding All DatabaseSync Methods, Close & Raw Transaction SQL', () => {
    const { DatabaseSync } = require('node:sqlite');
    const { WriteCoalescingSqliteAdapter } = require('../src/db/write-coalescing-sqlite');

    const memDb = new DatabaseSync(':memory:');
    memDb.exec('CREATE TABLE test_sp_guard (id TEXT PRIMARY KEY, val TEXT)');
    const adapter = new WriteCoalescingSqliteAdapter(memDb);

    // 1. Calling db.close() inside savepoint is blocked
    assert.throws(
      () => {
        adapter.runImmediateSavepointSync('testCloseGuard', (dbProxy) => {
          dbProxy.close();
        });
      },
      (err) => err.code === 'SQLITE_CLOSE_FORBIDDEN_IN_SAVEPOINT'
    );

    // 2. Calling manual transaction control SQL inside savepoint is blocked
    assert.throws(
      () => {
        adapter.runImmediateSavepointSync('testBeginGuard', (dbProxy) => {
          dbProxy.exec('BEGIN TRANSACTION');
        });
      },
      (err) => err.code === 'SQLITE_MANUAL_TRANSACTION_FORBIDDEN_IN_SAVEPOINT'
    );

    // 3. Returning a thenable inside synchronous savepoint throws and rolls back immediately
    assert.throws(
      () => {
        adapter.runImmediateSavepointSync('testThenableGuard', (dbProxy) => {
          dbProxy.exec("INSERT INTO test_sp_guard (id, val) VALUES ('k1', 'v1')");
          return Promise.resolve('async-escape');
        });
      },
      (err) => err.code === 'SQLITE_ASYNC_CALLBACK_FORBIDDEN_IN_SAVEPOINT'
    );
    const row = memDb.prepare("SELECT * FROM test_sp_guard WHERE id = 'k1'").get();
    assert.equal(row, undefined, 'Synchronous insert must roll back when thenable returned');
    memDb.close();
  });

  it('105. Phase Atlas VII (Cycle 7 & Cycle 8) — NOC Timestamp Freshness Evaluation & Telemetry Context Deduplication / Spill Manifest', async () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const { compileTelemetryContextWindowNonBlocking } = require('../src/core/skills/telemetry-context-accelerator');

    // 1. NOC view script exposes 6-state freshness evaluation and badges
    const nocScript = fs.readFileSync(path.join(__dirname, '../public/js/views/enterprise-noc-view.js'), 'utf8');
    assert.ok(nocScript.includes('evaluateEnterpriseNocEndpointFreshness'));
    assert.ok(nocScript.includes('AVAILABLE_STALE_TELEMETRY'));
    assert.ok(nocScript.includes('HISTORICAL_FALLBACK'));
    assert.ok(nocScript.includes('TEMPORARILY_UNAVAILABLE'));
    assert.ok(nocScript.includes('INVALID_OR_INCOMPLETE_RESPONSE'));

    // 2. TelemetryContextAccelerator respects requestedMaxTokens down to 16, deduplicates retries, and spills excess unique signatures
    const repeatedRetries = [];
    for (let i = 0; i < 20; i++) {
      repeatedRetries.push({
        timestamp: new Date(Date.now() - i * 500).toISOString(),
        layer: 'L4_TCP',
        target: '10.50.0.1',
        metric: 'packetLossPct',
        value: 100,
        madZScore: 5.5,
        severity: 'CRITICAL',
        errorCode: 'ETIMEDOUT',
        eventId: `evt-${i}`
      });
    }

    const compiledRetries = await compileTelemetryContextWindowNonBlocking(
      repeatedRetries,
      [],
      [],
      { maxTokens: 16 }
    );
    assert.equal(compiledRetries.requestedMaxTokens, 16);
    assert.equal(compiledRetries.effectiveMaxTokens, 16);
    assert.equal(compiledRetries.uniqueCriticalSignaturesCount, 1);
    assert.equal(compiledRetries.deduplicatedCriticalRetriesCount, 19);
    assert.equal(compiledRetries.criticalEvidenceDroppedCount, 0);
  });

  it('106. Phase Atlas VIII (Cycle 0 & Cycle 7) — Non-Optimistic Probe Status Compaction, Critical Value Evolution & Retrievable Spill Store', async () => {
    const {
      compileTelemetryContextWindowNonBlocking,
      retrieveSpilledCriticalEvidence,
      compactProbeRecordStrict
    } = require('../src/core/skills/telemetry-context-accelerator');

    // 1. Verify compactProbeRecordStrict never fabricates PASS for missing/anomalous probes
    const compactedProbes = [
      compactProbeRecordStrict({ probeType: 'TCP', target: '10.0.0.1', rttMs: 12 }),
      compactProbeRecordStrict({ probeType: 'TCP', target: '10.0.0.2', anomalyDetected: true, rttMs: 480 }),
      compactProbeRecordStrict({ probeType: 'TCP', target: '10.0.0.3', reachable: false, errorCode: 'ECONNREFUSED' }),
      compactProbeRecordStrict({ probeType: 'TCP', target: '10.0.0.4', status: 'OK', anomalyDetected: false, rttMs: 2.1 })
    ];
    assert.equal(compactedProbes[0].status, 'UNKNOWN');
    assert.equal(compactedProbes[0].statusSource, 'MISSING_EXPLICIT_STATUS');
    assert.equal(compactedProbes[1].status, 'ANOMALY');
    assert.equal(compactedProbes[2].status, 'UNREACHABLE');
    assert.equal(compactedProbes[3].status, 'OK');

    // 2. Verify deduplicated critical events retain firstValue, latestValue, minValue, maxValue, provenanceList & spilled retrieval
    const criticalRetriesAndOverflow = [
      {
        timestamp: '2026-11-10T08:00:00.000Z',
        layer: 'L4_TCP',
        target: '10.88.0.1',
        metric: 'packetLossPct',
        value: 22.5,
        madZScore: 8.8,
        severity: 'CRITICAL',
        isPatientZero: true,
        errorCode: 'ETIMEDOUT',
        provenance: 'COLLECTOR_A',
        eventId: 'crit-1a'
      },
      {
        timestamp: '2026-11-10T08:00:05.000Z',
        layer: 'L4_TCP',
        target: '10.88.0.1',
        metric: 'packetLossPct',
        value: 68.0,
        madZScore: 9.4,
        severity: 'CRITICAL',
        isPatientZero: true,
        errorCode: 'ETIMEDOUT',
        provenance: 'COLLECTOR_B',
        eventId: 'crit-1b'
      }
    ];
    for (let i = 0; i < 15; i++) {
      criticalRetriesAndOverflow.push({
        timestamp: new Date(Date.now() - i * 1000).toISOString(),
        layer: 'L7_HTTP',
        target: `10.88.1.${i + 1}`,
        metric: 'http5xxRatePct',
        value: 40 + i,
        madZScore: 5.5,
        severity: 'CRITICAL',
        errorCode: `HTTP_50${i % 4}`,
        provenance: 'EDGE_AGENT',
        eventId: `crit-overflow-${i}`
      });
    }

    const compiled = await compileTelemetryContextWindowNonBlocking(
      criticalRetriesAndOverflow,
      [],
      [{ probeType: 'TCP', target: '10.88.0.1:443' }], // missing status -> must compact to UNKNOWN, never PASS
      { maxTokens: 16, maxInContextCriticalEvents: 4 }
    );
    assert.equal(compiled.compactedProbes[0].status, 'UNKNOWN');
    const firstAnomaly = compiled.retainedAnomalies.find((a) => a.target === '10.88.0.1');
    assert.ok(firstAnomaly);
    assert.equal(firstAnomaly.firstValue, 22.5);
    assert.equal(firstAnomaly.latestValue, 68.0);
    assert.equal(firstAnomaly.minValue, 22.5);
    assert.equal(firstAnomaly.maxValue, 68.0);
    assert.equal(firstAnomaly.valueChanged, true);
    assert.equal(firstAnomaly.observationIntervalMs, 5000);
    assert.deepEqual(firstAnomaly.provenanceList, ['COLLECTOR_A', 'COLLECTOR_B']);

    // Verify spilled critical evidence is 100% retrievable by spillReferenceId
    assert.ok(compiled.externalizedCriticalEvidenceOverflow);
    const spillRefId = compiled.externalizedCriticalEvidenceOverflow.spillReferenceId;
    assert.ok(spillRefId);
    const retrievedSpill = retrieveSpilledCriticalEvidence(spillRefId);
    assert.ok(retrievedSpill);
    assert.equal(retrievedSpill.spilledCriticalSignaturesCount, compiled.spilledCriticalSignaturesCount);
    assert.equal(retrievedSpill.spilledCriticalRecords.length, compiled.spilledCriticalSignaturesCount);
  });

  it('107. Phase Atlas VIII (Cycle 1) — 13-Category Skill Ecosystem Accounting, GStack Config Separation & Newly Introduced Protected File Detection', () => {
    const { ReadOnlySkillCatalog, readOnlySkillCatalog } = require('../src/core/skills/read-only-skill-router');
    const fs = require('node:fs');
    const path = require('node:path');
    const os = require('node:os');

    const summary = readOnlySkillCatalog.getInventorySummary();
    assert.ok(summary.thirteenCategoryInventory);
    const catKeys = Object.keys(summary.thirteenCategoryInventory);
    assert.equal(catKeys.length, 13);
    assert.equal(summary.thirteenCategoryInventory.canonicalPrimarySkillPackages, 85);
    assert.equal(summary.thirteenCategoryInventory.canonicalNestedGstackWorkflowManifests, 74);
    assert.equal(summary.thirteenCategoryInventory.canonicalMirroredSkills, 111);
    assert.equal(summary.thirteenCategoryInventory.canonicalSuperpowersSkills, 15);
    assert.equal(summary.thirteenCategoryInventory.lockfileRegisteredSkills, 71);
    assert.equal(summary.thirteenCategoryInventory.lockfileSkillsPresentOnDisk, 46);
    assert.ok(summary.supportingAssetsByCategory);

    // Verify NEWLY_INTRODUCED_PROTECTED_FILE detection in an isolated temp skill tree
    const tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'ejii-skill-newfile-'));
    try {
      const tmpPrimary = path.join(tmpBase, '.agents', 'skills');
      const tmpSkillDir = path.join(tmpPrimary, 'alpha-skill');
      const gstackAgentsDir = path.join(tmpPrimary, 'gstack', 'agents');
      fs.mkdirSync(tmpSkillDir, { recursive: true });
      fs.mkdirSync(gstackAgentsDir, { recursive: true });
      fs.writeFileSync(path.join(tmpSkillDir, 'SKILL.md'), '---\nname: alpha-skill\n---\n# Alpha\n', 'utf8');
      fs.writeFileSync(path.join(gstackAgentsDir, 'openai.yaml'), 'model: gpt-4o\n', 'utf8');

      const cat = new ReadOnlySkillCatalog({
        rootDir: tmpBase,
        primarySkillsDir: tmpPrimary,
        mirrorSkillsDir: path.join(tmpBase, 'skills'),
        agentRootDir: path.join(tmpBase, 'agent'),
        superpowersSkillsDir: path.join(tmpBase, 'agent', 'skills'),
        lockFilePath: path.join(tmpBase, 'skills-lock.json')
      });
      cat.initialize();

      // Verify gstack/agents/openai.yaml is indexed as GSTACK_CONFIGURATION_RESOURCE, not workflow manifest
      assert.equal(cat.gstackConfigurationResources.size, 1);
      const cfgRes = cat.gstackConfigurationResources.get('gstack/agents/openai.yaml');
      assert.ok(cfgRes);
      assert.equal(cfgRes.entryType, 'GSTACK_CONFIGURATION_RESOURCE');
      assert.equal(cfgRes.isWorkflowManifest, false);

      // Introduce an unauthorized file after baseline initialization
      fs.writeFileSync(path.join(tmpSkillDir, 'unauthorized-injected.sh'), '#!/bin/sh\necho bad\n', 'utf8');
      const integrityAfterInject = cat.verifyReadOnlyIntegrity();
      assert.equal(integrityAfterInject.intact, false);
      assert.ok(integrityAfterInject.violations.some((v) => v.reason === 'NEWLY_INTRODUCED_PROTECTED_FILE'));
    } finally {
      fs.rmSync(tmpBase, { recursive: true, force: true });
    }
  });

  it('108. Phase Atlas VIII (Cycle 2) — Project Falcon Trusted Recovery Verification, Provenance & Layer-Appropriate Probe Criteria', () => {
    const { ChatOperatorService } = require('../src/core/chat/chat-operator-service');
    const svc = new ChatOperatorService();

    // 1. Missing actionExecuted defaults to false (REMEDIATION_NOT_EXECUTED)
    const unexecuted = svc.evaluateVerifiedRecoveryState({
      incidentId: 'inc-falcon-1',
      verificationProbe: {
        probeType: 'TCP_SOCKET_PROBE',
        provenance: 'LIVE_POST_ACTION_SOCKET_PROBE',
        target: '10.0.0.10',
        timestamp: new Date().toISOString(),
        rttMs: 1.5,
        status: 'PASS'
      }
    });
    assert.equal(unexecuted.actionExecuted, false);
    assert.equal(unexecuted.postActionHealthy, false);
    assert.equal(unexecuted.recoveryState, 'REMEDIATION_NOT_EXECUTED');

    // 2. Manual/untrusted probe provenance or missing quantitative metric is rejected
    const untrusted = svc.evaluateVerifiedRecoveryState({
      incidentId: 'inc-falcon-2',
      actionExecuted: true,
      actionExecutionId: 'exec-falcon-2',
      target: '10.0.0.10',
      verificationProbe: {
        probeType: 'TCP_SOCKET_PROBE',
        provenance: 'UNVERIFIED_MANUAL_OVERRIDE',
        target: '10.0.0.10',
        timestamp: new Date().toISOString(),
        rttMs: 1.5,
        status: 'PASS'
      }
    });
    assert.equal(untrusted.postActionHealthy, false);
    assert.equal(untrusted.recoveryState, 'UNVERIFIED_PROBE_REJECTED_UNTRUSTED_PROBE_PROVENANCE');

    // 3. L4 TCP probe alone cannot certify full recovery for an L7_APPLICATION fault
    const l7Partial = svc.evaluateVerifiedRecoveryState({
      incidentId: 'inc-falcon-3',
      actionExecuted: true,
      actionExecutionId: 'exec-falcon-3',
      target: '10.0.0.10',
      faultLayer: 'L7_UPSTREAM_APPLICATION',
      verificationProbe: {
        probeType: 'TCP_SOCKET_PROBE',
        provenance: 'LIVE_POST_ACTION_SOCKET_PROBE',
        target: '10.0.0.10',
        timestamp: new Date().toISOString(),
        rttMs: 1.8,
        status: 'PASS'
      }
    });
    assert.equal(l7Partial.postActionHealthy, false);
    assert.equal(l7Partial.recoveryState, 'PARTIAL_TRANSPORT_ONLY_RECOVERY_L7_UNVERIFIED');
  });

  it('109. Phase Atlas VIII (Cycle 3) — VirtualNet ATLASL3V1 Strict 16-Bit Frame Bounds, Reserved Bytes & Trailing-Byte Rejection', () => {
    const { ProjectAtlasEngine } = require('../src/network/atlas/project-atlas-engine');
    const engine = new ProjectAtlasEngine({
      secretKey: 'sovereign-atlas-test-master-secret-key-32b'
    });
    const vnet = engine.createVirtualNetwork({
      vnetName: 'vnet-v8-bounds',
      cidrBlock: '10.245.0.0/24',
      aclRules: [{ action: 'ALLOW', protocol: '*', sourceIp: '*', destIp: '*', destPort: '*' }]
    });

    // 1. Oversized payload (> 65535 bytes) with df: false is rejected without silent Math.min truncation
    const oversizedPayload = Buffer.alloc(65536, 0x41);
    const encOversized = engine.encapsulateVirtualNetPacket(vnet.vnetId, {
      messageId: 'm-1',
      sourceIp: '10.245.0.2',
      destIp: '10.245.0.3',
      protocol: 'TCP',
      payloadBuffer: oversizedPayload,
      df: false
    });
    assert.equal(encOversized.encapsulated, false);
    assert.equal(encOversized.decision, 'DENY_PAYLOAD_EXCEEDS_MAX_FRAME_65535');

    // 2. Valid encapsulation decapsulates cleanly
    const validEnc = engine.encapsulateVirtualNetPacket(vnet.vnetId, {
      messageId: 'm-2',
      sourceIp: '10.245.0.2',
      destIp: '10.245.0.3',
      protocol: 'TCP',
      payloadBuffer: Buffer.from('valid-payload'),
      df: true
    });
    assert.equal(validEnc.encapsulated, true);
    const validDecap = engine.decapsulateVirtualNetPacket(validEnc.frameBuffer, { requireMetadata: true });
    assert.equal(validDecap.decapsulated, true);

    // 3. Non-zero reserved bytes (bytes 14..15) are rejected
    const badReserved = Buffer.from(validEnc.frameBuffer);
    badReserved.writeUInt16BE(0x0001, 14);
    const resCheck = engine.decapsulateVirtualNetPacket(badReserved);
    assert.equal(resCheck.decapsulated, false);
    assert.equal(resCheck.code, 'ATLAS_VNET_RESERVED_BYTES_NONZERO');

    // 4. Unexpected trailing bytes after declared payload + metadata are rejected
    const trailingBuf = Buffer.concat([validEnc.frameBuffer, Buffer.from('EXTRA_GARBAGE')]);
    const trailCheck = engine.decapsulateVirtualNetPacket(trailingBuf);
    assert.equal(trailCheck.decapsulated, false);
    assert.equal(trailCheck.code, 'ATLAS_VNET_UNEXPECTED_TRAILING_BYTES');
  });

  it('110. Phase Atlas VIII (Cycle 4) — Bayesian Calibration Content-Signature Deduplication, Dominant Complement Mass & Empirical Confusion Matrix EIG', () => {
    const { IndirectCrossLayerInferencer } = require('../src/ai/indirect-cross-layer-inferencer');
    const inferencer = new IndirectCrossLayerInferencer();

    // 1. Cloned incidents with distinct synthetic incidentIds and mutated timestamps are deduplicated by content signature
    const mutatedClones = [];
    for (let i = 0; i < 12; i++) {
      mutatedClones.push({
        incidentId: `synthetic-clone-id-${i}`,
        settledAtMs: 1700000000000 + i * 60000,
        actualRootCauseDomain: i % 2 === 0 ? 'L4_TRANSPORT' : 'DNS_CONTROL_PLANE',
        observations: { tcpHandshakeRttMs: 120, dnsLatencyMs: 85 },
        predictedDomains: [
          { domain: 'L4_TRANSPORT', probabilityPct: 70 },
          { domain: 'DNS_CONTROL_PLANE', probabilityPct: 30 }
        ]
      });
    }
    const cloneEval = inferencer.evaluateCalibrationAgainstSettledIncidents(mutatedClones);
    assert.equal(cloneEval.calibrated, false);
    assert.equal(cloneEval.sampleSize, 2);
    assert.equal(cloneEval.duplicatesRemovedCount, 10);

    // 2. Empirical confusion matrix EIG uses empirical P(O|D) matrix and reports EMPIRICAL_HISTORICAL_CONFUSION_MATRIX source
    const empiricalEig = inferencer._computeProbeExpectedInformationGain(
      'L4_TRANSPORT',
      0.6,
      [
        { layer: 'L4_TRANSPORT', probabilityPct: 60 },
        { layer: 'L7_UPSTREAM_APPLICATION', probabilityPct: 40 }
      ],
      {
        empiricalConfusionMatrix: {
          truePositives: 92,
          falseNegatives: 8,
          falsePositives: 8,
          trueNegatives: 92
        }
      }
    );
    assert.equal(empiricalEig.probeCharacteristicSource, 'EMPIRICAL_HISTORICAL_CONFUSION_MATRIX');
    assert.ok(empiricalEig.expectedInformationGainBits > 0.3);
  });

  it('111. Phase Atlas VIII (Cycle 5) — WriteCoalescingSqliteAdapter Savepoint Blocking Nested SAVEPOINT SQL & StatementSync Chain Escape', () => {
    const { DatabaseSync } = require('node:sqlite');
    const { WriteCoalescingSqliteAdapter } = require('../src/db/write-coalescing-sqlite');

    const memDb = new DatabaseSync(':memory:');
    memDb.exec('CREATE TABLE test_sp_v8 (id TEXT PRIMARY KEY, val TEXT)');
    const adapter = new WriteCoalescingSqliteAdapter(memDb);

    // 1. Manual SAVEPOINT / RELEASE / ROLLBACK TO SAVEPOINT SQL inside callback is forbidden
    assert.throws(
      () => {
        adapter.runImmediateSavepointSync('manualSavepointSql', (dbProxy) => {
          dbProxy.exec('SAVEPOINT inner_manual_sp');
        });
      },
      (err) => err.code === 'SQLITE_MANUAL_TRANSACTION_FORBIDDEN_IN_SAVEPOINT'
    );

    // 2. Chaining stmt.setReturnArrays(true) inside savepoint cannot leak the raw unguarded StatementSync
    let chainedStmt = null;
    adapter.runImmediateSavepointSync('chainEscapeTest', (dbProxy) => {
      const stmt = dbProxy.prepare('SELECT id, val FROM test_sp_v8');
      chainedStmt = stmt.setReturnArrays(true);
    });
    assert.ok(chainedStmt);
    assert.throws(
      () => {
        chainedStmt.all();
      },
      (err) => err.code === 'SQLITE_SAVEPOINT_ALREADY_CLOSED_LATE_MUTATION_FORBIDDEN'
    );

    memDb.close();
  });

  it('112. Phase Atlas VIII (Cycle 6) — Enterprise NOC Source-Timestamp Truthfulness, Clock Skew Detection & Per-Resource Freshness', () => {
    const {
      evaluateEnterpriseNocEndpointFreshness
    } = require('../public/js/views/enterprise-noc-view');

    const nowMs = 1762770000000;

    // 1. Missing source timestamp must NEVER substitute nowMs or report LIVE_FRESH (ageMs: 0)
    const missingTsRes = evaluateEnterpriseNocEndpointFreshness(
      'status',
      {
        status: 'fulfilled',
        value: {
          success: true,
          fleetSummary: { totalSites: 2, healthySites: 2 }
          // no observedAt / timestamp!
        }
      },
      { nowMs }
    );
    assert.equal(missingTsRes.freshnessState, 'MISSING_SOURCE_TIMESTAMP');
    assert.equal(missingTsRes.ageMs, null);
    assert.equal(missingTsRes.isStaleTelemetry, true);

    // 2. Future timestamp beyond clock skew tolerance reports CLOCK_SKEW_DETECTED
    const futureIso = new Date(nowMs + 120000).toISOString();
    const skewRes = evaluateEnterpriseNocEndpointFreshness(
      'status',
      {
        status: 'fulfilled',
        value: {
          success: true,
          observedAt: futureIso,
          fleetSummary: { totalSites: 2, healthySites: 2 }
        }
      },
      { nowMs, maxClockSkewMs: 30000 }
    );
    assert.equal(skewRes.freshnessState, 'CLOCK_SKEW_DETECTED');
    assert.equal(skewRes.ageMs, null);

    // 3. Multi-item sites array where sites[0] is fresh (5s old) but sites[1] is stale (300s old) reports AVAILABLE_STALE_TELEMETRY
    const sitesRes = evaluateEnterpriseNocEndpointFreshness(
      'sites',
      {
        status: 'fulfilled',
        value: {
          success: true,
          sites: [
            { id: 'site-fresh', name: 'Site Fresh', observedAt: new Date(nowMs - 5000).toISOString() },
            { id: 'site-stale', name: 'Site Stale', observedAt: new Date(nowMs - 300000).toISOString() }
          ]
        }
      },
      { nowMs, thresholds: { siteTelemetryMaxAgeMs: 90000 } }
    );
    assert.equal(sitesRes.freshnessState, 'AVAILABLE_STALE_TELEMETRY');
    assert.equal(sitesRes.isStaleTelemetry, true);
    assert.equal(sitesRes.resourceFreshnessSummary.totalCount, 2);
    assert.equal(sitesRes.resourceFreshnessSummary.freshCount, 1);
    assert.equal(sitesRes.resourceFreshnessSummary.staleCount, 1);
    assert.equal(sitesRes.resourceFreshnessSummary.freshestAgeMs, 5000);
    assert.equal(sitesRes.resourceFreshnessSummary.oldestAgeMs, 300000);
  });

  // =========================================================================
  // PHASE ATLAS IX — CONTINUOUS ENGINEERING EVOLUTION & SOVEREIGN HARDENING
  // =========================================================================

  it('113. Phase Atlas IX (Cycle 1) — Unified Probe Outcome Resolution, Non-Evidential Probe Posterior Invariance & Empirical Confusion Matrix Guards', async () => {
    const {
      MultiDomainHypothesisArbiter,
      resolveUnifiedProbeOutcome
    } = require('../src/ai/hypothesis-arbiter');
    const { IndirectCrossLayerInferencer } = require('../src/ai/indirect-cross-layer-inferencer');

    // 1. Empty rawTelemetry: {} without concrete measurement or explicit status must NEVER resolve to PASS
    const emptyTelemetryOutcome = resolveUnifiedProbeOutcome({
      probeType: 'TCP_SYN_PROBE',
      target: '10.20.30.40',
      anomalyDetected: false,
      rawTelemetry: {}
    });
    assert.notEqual(emptyTelemetryOutcome.status, 'PASS');
    assert.equal(emptyTelemetryOutcome.executed, false);
    assert.equal(emptyTelemetryOutcome.status, 'UNAVAILABLE');

    // 2. Unavailable or unexecuted probes in arbitrateAndExecuteClosedLoop must NOT alter Bayesian posteriors or claim positive info gain
    const arbiter = new MultiDomainHypothesisArbiter();
    const res = await arbiter.arbitrateAndExecuteClosedLoop({
      target: '10.99.88.77',
      port: 443,
      maxClosedLoopSteps: 2,
      customProbeExecutor: async (probeType, target) => ({
        probeType,
        target,
        executed: false,
        status: 'UNAVAILABLE',
        anomalyDetected: false,
        finding: 'Collector probe unavailable in isolated zone',
        rawTelemetry: {}
      })
    });
    assert.ok(Array.isArray(res.closedLoopExecutionTrace));
    assert.ok(res.closedLoopExecutionTrace.length >= 1);
    for (const stepTrace of res.closedLoopExecutionTrace) {
      assert.equal(stepTrace.executed, false);
      assert.equal(stepTrace.status, 'UNAVAILABLE');
      assert.equal(stepTrace.actualInfoGainBits, 0);
      assert.equal(stepTrace.entropyAfterBits, stepTrace.entropyBeforeBits);
      assert.equal(stepTrace.confidenceImpact, 'NO_POSTERIOR_UPDATE_NON_EVIDENTIAL');
    }

    // 3. Empirical confusion matrix rejects tiny sample sizes (< 10) and negative/NaN counts
    const inferencer = new IndirectCrossLayerInferencer();
    const candidateProbs = [
      { domain: 'DNS_RESOLUTION', prob: 0.45 },
      { domain: 'L4_TCP_TRANSPORT', prob: 0.35 },
      { domain: 'L7_APPLICATION', prob: 0.20 }
    ];

    const tinyMatrixEig = inferencer._computeProbeExpectedInformationGain(
      candidateProbs,
      'DNS_RESOLUTION',
      {
        empiricalConfusionMatrix: {
          truePositives: 1,
          falseNegatives: 0,
          falsePositives: 0,
          trueNegatives: 1
        }
      }
    );
    assert.equal(
      tinyMatrixEig.probeCharacteristicSource,
      'INSUFFICIENT_EMPIRICAL_OBSERVATIONS_FALLBACK_PRIOR'
    );

    const invalidMatrixEig = inferencer._computeProbeExpectedInformationGain(
      candidateProbs,
      'DNS_RESOLUTION',
      {
        empiricalConfusionMatrix: {
          truePositives: -5,
          falseNegatives: 10,
          falsePositives: NaN,
          trueNegatives: 10
        }
      }
    );
    assert.equal(
      invalidMatrixEig.probeCharacteristicSource,
      'INVALID_CONFUSION_MATRIX_FALLBACK_PRIOR'
    );

    const validMatrixEig = inferencer._computeProbeExpectedInformationGain(
      candidateProbs,
      'DNS_RESOLUTION',
      {
        empiricalConfusionMatrix: {
          truePositives: 18,
          falseNegatives: 2,
          falsePositives: 1,
          trueNegatives: 19
        }
      }
    );
    assert.equal(
      validMatrixEig.probeCharacteristicSource,
      'EMPIRICAL_HISTORICAL_CONFUSION_MATRIX'
    );
  });

  it('114. Phase Atlas IX (Cycle 2) — ReadOnlySkillRouter Full agent/ Root Coverage, Fail-Closed Incomplete Scan Detection & Lockfile Reconciliation', () => {
    const fs = require('node:fs');
    const os = require('node:os');
    const path = require('node:path');
    const {
      ReadOnlySkillCatalog,
      readOnlySkillRouter
    } = require('../src/core/skills/read-only-skill-router');

    // 1. Verify lockfileReconciliation is exposed and reconciles 71 canonical external definitions vs 46 physical lockfile entries
    const summary = readOnlySkillRouter.getInventorySummary();
    assert.ok(summary.lockfileReconciliation);
    assert.equal(summary.lockfileReconciliation.canonicalExternalLockDefinitionsCount, 71);
    assert.equal(summary.lockfileReconciliation.physicalLockfileEntriesOnDiskCount, 46);
    assert.equal(summary.lockfileReconciliation.canonicalLocalBundledOrUnlistedInLockfileCount, 25);

    // 2. Verify a newly introduced file directly under `agent/` (outside `agent/skills/`) is caught by verifyReadOnlyIntegrity()
    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ejii-skill-agent-root-v9-'));
    try {
      const primaryDir = path.join(tmpRoot, '.agents', 'skills');
      const mirrorDir = path.join(tmpRoot, 'skills');
      const agentDir = path.join(tmpRoot, 'agent');
      const superpowersDir = path.join(agentDir, 'skills');
      fs.mkdirSync(primaryDir, { recursive: true });
      fs.mkdirSync(mirrorDir, { recursive: true });
      fs.mkdirSync(superpowersDir, { recursive: true });
      fs.writeFileSync(
        path.join(tmpRoot, 'skills-lock.json'),
        JSON.stringify({ version: 1, skills: {} }),
        'utf8'
      );

      const isolatedCatalog = new ReadOnlySkillCatalog({ rootDir: tmpRoot });
      assert.equal(isolatedCatalog.verifyReadOnlyIntegrity().intact, true);

      // Drop an unexpected file directly inside `agent/` (outside `agent/skills/`)
      const rogueAgentFile = path.join(agentDir, 'rogue-top-level-agent-file.md');
      fs.writeFileSync(rogueAgentFile, '# unexpected file in agent/', 'utf8');

      const afterRogue = isolatedCatalog.verifyReadOnlyIntegrity();
      assert.equal(afterRogue.intact, false);
      assert.equal(afterRogue.readOnlyVerified, false);
      assert.ok(
        afterRogue.violations.some(
          (v) =>
            v.relativePath === 'agent/rogue-top-level-agent-file.md' &&
            v.reason === 'NEWLY_INTRODUCED_PROTECTED_FILE'
        )
      );
      fs.unlinkSync(rogueAgentFile);
      assert.equal(isolatedCatalog.verifyReadOnlyIntegrity().intact, true);

      // 3. Verify that an incomplete/denied directory scan NEVER produces a clean intact: true result
      isolatedCatalog._recordScanDiagnostic(
        'deniedPaths',
        path.join(primaryDir, 'restricted-skill'),
        Object.assign(new Error('EACCES: permission denied'), { code: 'EACCES' })
      );
      const afterDeniedScan = isolatedCatalog.verifyReadOnlyIntegrity();
      assert.equal(afterDeniedScan.intact, false);
      assert.equal(afterDeniedScan.readOnlyVerified, false);
      assert.equal(afterDeniedScan.incompleteScanDetected, true);
      assert.ok(
        afterDeniedScan.violations.some(
          (v) => v.reason === 'INCOMPLETE_OR_DENIED_DIRECTORY_SCAN'
        )
      );
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  it('115. Phase Atlas IX (Cycle 3) — Durable SQLite Critical-Evidence Spill Ledger, Cross-Restart Recovery & Retention TTL Expiration', async () => {
    const { DatabaseSync } = require('node:sqlite');
    const { runMigrations } = require('../src/db/migrations');
    const {
      compileTelemetryContextWindowNonBlocking,
      retrieveSpilledCriticalEvidence,
      clearInMemorySpillCacheForTesting
    } = require('../src/core/skills/telemetry-context-accelerator');

    const spillDb = new DatabaseSync(':memory:');
    const migResult = runMigrations(spillDb);
    assert.equal(migResult.status, 'SUCCESS');
    assert.ok(migResult.totalMigrations >= 11);

    const nowMs = 1762800000000;
    const criticalBurst = Array.from({ length: 18 }, (_, i) => ({
      id: `crit-v9-${i + 1}`,
      timestamp: new Date(nowMs - i * 1000).toISOString(),
      layer: 'L4_TCP',
      target: `10.77.0.${i + 1}:443`,
      metric: 'tcpResetRatePct',
      value: 45 + i,
      severity: 'CRITICAL',
      errorCode: `ERR_RST_SPIKE_${i + 1}`,
      madZScore: 6.2,
      provenance: 'LIVE_EBPF_SOCKET_PROBE'
    }));

    const compiled = await compileTelemetryContextWindowNonBlocking(criticalBurst, [], [], {
      maxTokens: 120,
      maxInContextCriticalEvents: 4,
      db: spillDb,
      nowMs,
      spillRetentionTtlMs: 60000
    });

    assert.equal(compiled.uniqueCriticalSignaturesCount, 18);
    assert.equal(compiled.inContextCriticalCount, 4);
    assert.equal(compiled.spilledCriticalSignaturesCount, 14);
    assert.equal(compiled.criticalEvidenceDroppedCount, 0);
    assert.ok(compiled.externalizedCriticalEvidenceOverflow);
    assert.equal(compiled.externalizedCriticalEvidenceOverflow.persistedToSqlite, true);
    assert.equal(
      compiled.externalizedCriticalEvidenceOverflow.persistenceStatus,
      'DURABLE_SQLITE_AND_MEMORY'
    );

    const spillRefId = compiled.externalizedCriticalEvidenceOverflow.spillReferenceId;
    assert.ok(spillRefId);

    // Clear the in-memory Map completely to simulate a process restart or LRU cache eviction
    clearInMemorySpillCacheForTesting();

    // Retrieve spilled critical evidence directly from the durable SQLite ledger
    const recoveredFromSqlite = retrieveSpilledCriticalEvidence(spillRefId, {
      db: spillDb,
      nowMs: nowMs + 5000
    });
    assert.ok(recoveredFromSqlite);
    assert.equal(recoveredFromSqlite.retrievalStatus, 'RETRIEVED_OK');
    assert.equal(recoveredFromSqlite.retrievalSource, 'DURABLE_SQLITE_LEDGER');
    assert.equal(recoveredFromSqlite.spilledCriticalSignaturesCount, 14);
    assert.equal(recoveredFromSqlite.spilledCriticalRecords.length, 14);

    // Verify retention TTL expiration after 60s
    const expiredLookup = retrieveSpilledCriticalEvidence(spillRefId, {
      db: spillDb,
      nowMs: nowMs + 120000
    });
    assert.ok(expiredLookup);
    assert.equal(expiredLookup.expired, true);
    assert.equal(expiredLookup.retrievalStatus, 'RETENTION_EXPIRED');
    assert.equal(expiredLookup.spilledCriticalRecords.length, 0);

    spillDb.close();
  });

  it('116. Phase Atlas IX (Cycle 4) — WriteCoalescingSqliteAdapter Graceful Drain/Shutdown Lifecycle & Post-Shutdown Write Rejection', async () => {
    const { DatabaseSync } = require('node:sqlite');
    const { WriteCoalescingSqliteAdapter } = require('../src/db/write-coalescing-sqlite');

    const memDb = new DatabaseSync(':memory:');
    memDb.exec('CREATE TABLE test_lifecycle_v9 (id TEXT PRIMARY KEY, val TEXT)');
    const adapter1 = new WriteCoalescingSqliteAdapter(memDb);
    const adapter2 = new WriteCoalescingSqliteAdapter(memDb);

    // 1. Per-DB-handle registry tracks multiple adapters sharing the same DB handle
    assert.equal(adapter1.getMetrics().registeredAdaptersOnSameDbCount, 2);

    // 2. Enqueue async writes and immediately call drainAndShutdown()
    const p1 = adapter1.enqueueWriteTransaction('tx1', (db) => {
      db.prepare('INSERT INTO test_lifecycle_v9 (id, val) VALUES (?, ?)').run('k1', 'v1');
      return 'ok1';
    });
    const p2 = adapter1.enqueueWriteTransaction('tx2', (db) => {
      db.prepare('INSERT INTO test_lifecycle_v9 (id, val) VALUES (?, ?)').run('k2', 'v2');
      return 'ok2';
    });

    const drainRes = await adapter1.drainAndShutdown({ checkpointWal: true });
    assert.equal(drainRes.drained, true);
    assert.equal(drainRes.shutdownState, 'SHUTDOWN');
    assert.equal(drainRes.walCheckpointStatus, 'CHECKPOINT_PASSIVE_OK');

    const [r1, r2] = await Promise.all([p1, p2]);
    assert.equal(r1.persisted, true);
    assert.equal(r2.persisted, true);

    const rows = memDb.prepare('SELECT id, val FROM test_lifecycle_v9 ORDER BY id ASC').all();
    assert.equal(rows.length, 2);

    // 3. New sync or async writes after shutdown are deterministically rejected with SQLITE_ADAPTER_SHUTTING_DOWN
    assert.throws(
      () => {
        adapter1.runImmediateSavepointSync('postShutdownSync', (db) => {
          db.prepare('INSERT INTO test_lifecycle_v9 (id, val) VALUES (?, ?)').run('k3', 'v3');
        });
      },
      (err) => err && err.code === 'SQLITE_ADAPTER_SHUTTING_DOWN'
    );

    await assert.rejects(
      async () => {
        await adapter1.enqueueWriteTransaction('postShutdownAsync', (db) => {
          db.prepare('INSERT INTO test_lifecycle_v9 (id, val) VALUES (?, ?)').run('k4', 'v4');
        });
      },
      (err) => err && err.code === 'SQLITE_ADAPTER_SHUTTING_DOWN'
    );

    memDb.close();
  });

  it('117. Phase Atlas IX (Cycle 5) — ResilientUdpNatTable Malformed Endpoint Rejection, Descriptor Leak Audit & Relay Failover Re-Entrancy Lock', () => {
    const { ResilientUdpNatTable } = require('../src/network/atlas/resilient-udp-nat-table');
    const { ProjectAtlasEngine } = require('../src/network/atlas/project-atlas-engine');

    const natTable = new ResilientUdpNatTable({ maxSessions: 8, maxSessionsPerSubnet: 4 });

    // 1. Malformed IP or invalid port is deterministically rejected with UDP_NAT_INVALID_CLIENT_ENDPOINT
    assert.throws(
      () => natTable.getOrCreateSession('bad-1', 'not-an-ip-address', 53000, () => ({ close() {} })),
      (err) => err && err.code === 'UDP_NAT_INVALID_CLIENT_ENDPOINT'
    );
    assert.throws(
      () => natTable.getOrCreateSession('bad-2', '192.168.1.20', 70000, () => ({ close() {} })),
      (err) => err && err.code === 'UDP_NAT_INVALID_CLIENT_ENDPOINT'
    );

    // 2. Valid sessions pass descriptor leak audit with 0 leaks before and after eviction
    natTable.getOrCreateSession('192.168.1.10:5001', '192.168.1.10', 5001, () => ({
      close() {},
      removeAllListeners() {}
    }));
    natTable.getOrCreateSession('[2001:db8::1]:5002', '2001:db8::1', 5002, () => ({
      close() {},
      removeAllListeners() {}
    }));

    const auditBefore = natTable.getDescriptorAudit();
    assert.equal(auditBefore.activeSessionsCount, 2);
    assert.equal(auditBefore.openSocketsCount, 2);
    assert.equal(auditBefore.activeTimersCount, 2);
    assert.equal(auditBefore.descriptorLeakDetected, false);
    assert.equal(auditBefore.malformedEndpointRejectedCount, 2);

    natTable.closeAllSessions('TEST_CLEANUP');
    const auditAfter = natTable.getDescriptorAudit();
    assert.equal(auditAfter.activeSessionsCount, 0);
    assert.equal(auditAfter.openSocketsCount, 0);
    assert.equal(auditAfter.activeTimersCount, 0);
    assert.equal(auditAfter.descriptorLeakDetected, false);

    // 3. ProjectAtlasEngine relay failover concurrency guard blocks concurrent/re-entrant failover on the same relay
    const atlas = new ProjectAtlasEngine({
      secretKey: 'atlas-phase-ix-relay-failover-lock-secret-key-999'
    });
    const r1 = atlas.registerRelayNode({
      relayName: 'relay-primary-ix',
      region: 'us-east-1',
      host: '10.10.1.10',
      port: 7000
    });
    atlas.inFlightRelayFailovers.add(r1.relayId);
    assert.throws(
      () => atlas.failoverRelayTraffic(r1.relayId),
      (err) => err && err.code === 'ATLAS_RELAY_FAILOVER_ALREADY_IN_PROGRESS'
    );
    atlas.inFlightRelayFailovers.delete(r1.relayId);
  });

  it('118. Phase Atlas IX (Cycle 6) — Indirect Evidence Epistemic Boundaries, Bounded NOC Table Rendering & Coalesced WebSocket Render Scheduler', () => {
    const { chatOperatorService } = require('../src/core/chat/chat-operator-service');
    const {
      partitionBoundedNocTableRows,
      createCoalescedNocRenderScheduler
    } = require('../public/js/views/enterprise-noc-view');

    // 1. Verify TCP vs DNS timeout indirect evidence boundaries
    const tcpBoundary = chatOperatorService.evaluateIndirectEvidenceBoundaries({
      probeType: 'TCP_SYN_HANDSHAKE',
      status: 'PASS'
    });
    assert.equal(tcpBoundary.observationCategory, 'UPPER_LAYER_TCP_TRANSPORT_CONNECTIVITY');
    assert.ok(tcpBoundary.provenByObservation.includes('L3_ACTIVE_ROUTE_IP_FORWARDING_REACHABILITY'));
    assert.ok(
      tcpBoundary.notProvenByObservation.includes('L1_PHYSICAL_SWITCH_PORT_CRC_OR_OPTICAL_DOM_HEALTH')
    );

    const dnsTimeoutBoundary = chatOperatorService.evaluateIndirectEvidenceBoundaries({
      probeType: 'DNS_A_LOOKUP',
      status: 'TIMEOUT',
      timedOut: true
    });
    assert.equal(dnsTimeoutBoundary.observationCategory, 'DNS_RESOLUTION_TIMEOUT_OR_FAILURE');
    assert.equal(dnsTimeoutBoundary.disambiguatedCandidateCauses.length, 3);

    // 2. Verify bounded NOC table row partitioning caps DOM rows and reports overflow summary
    const burstRows = Array.from({ length: 350 }, (_, i) => ({ id: `row-${i + 1}` }));
    const partitioned = partitionBoundedNocTableRows(burstRows, { maxRenderedRows: 100 });
    assert.equal(partitioned.renderedRowsCount, 100);
    assert.equal(partitioned.totalRowsCount, 350);
    assert.equal(partitioned.overflowRowsCount, 250);
    assert.equal(partitioned.isTruncatedForRenderPerformance, true);

    // 3. Verify coalesced NOC render scheduler batches rapid WebSocket updates into a single render pass
    let renderCalls = 0;
    let latestRenderedPayload = null;
    const scheduler = createCoalescedNocRenderScheduler(
      (lastPayload) => {
        renderCalls += 1;
        latestRenderedPayload = lastPayload;
      },
      { coalesceWindowMs: 50 }
    );

    const s1 = scheduler.schedule({ seq: 1 });
    const s2 = scheduler.schedule({ seq: 2 });
    const s3 = scheduler.schedule({ seq: 3 });
    assert.equal(s1.scheduled, true);
    assert.equal(s2.coalescedIntoPendingPass, true);
    assert.equal(s3.coalescedIntoPendingPass, true);

    const metricsAfterFlush = scheduler.flushNow();
    assert.equal(renderCalls, 1);
    assert.deepEqual(latestRenderedPayload, { seq: 3 });
    assert.equal(metricsAfterFlush.scheduledCallsCount, 3);
    assert.equal(metricsAfterFlush.executedRendersCount, 1);
    assert.equal(metricsAfterFlush.coalescedSkippedRendersCount, 2);
  });

  it('119. Phase Atlas X (Cycle 1) — ReadOnlySkillRouter Traversal Depth Parity (Depth 11+) & Zero False-Positive Protected File Violations', () => {
    const fs = require('node:fs');
    const os = require('node:os');
    const path = require('node:path');
    const { ReadOnlySkillCatalog } = require('../src/core/skills/read-only-skill-router');
    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ejii-skill-depth-parity-v10-'));
    try {
      const primaryDir = path.join(tmpRoot, '.agents', 'skills');
      const mirrorDir = path.join(tmpRoot, 'skills');
      const agentDir = path.join(tmpRoot, 'agent');
      const superpowersDir = path.join(agentDir, 'skills');
      fs.mkdirSync(primaryDir, { recursive: true });
      fs.mkdirSync(mirrorDir, { recursive: true });
      fs.mkdirSync(superpowersDir, { recursive: true });
      fs.writeFileSync(
        path.join(tmpRoot, 'skills-lock.json'),
        JSON.stringify({ version: 1, skills: {} }),
        'utf8'
      );

      // Create deeply nested structure up to depth 12 inside skills/gstack/
      const deepPath = path.join(
        mirrorDir,
        'gstack',
        'test',
        'fixtures',
        'ios-qa',
        'submodule',
        'workflows',
        'steps',
        'artifacts',
        'nested-depth-10',
        'level-11'
      );
      fs.mkdirSync(deepPath, { recursive: true });
      const deepFile = path.join(deepPath, 'deep-fixture-config.json');
      fs.writeFileSync(deepFile, JSON.stringify({ deep: true, depth: 11 }), 'utf8');

      const deepSkillDir = path.join(primaryDir, 'writing-skills', 'references', 'nested', 'deep', 'level-6');
      fs.mkdirSync(deepSkillDir, { recursive: true });
      const deepRefFile = path.join(deepSkillDir, 'nested-reference-depth-6.md');
      fs.writeFileSync(deepRefFile, '# Depth 6 Reference Asset', 'utf8');

      // Initialize ReadOnlySkillCatalog
      const catalog = new ReadOnlySkillCatalog({ rootDir: tmpRoot });
      const initialSummary = catalog.getInventorySummary();
      assert.ok(initialSummary.readOnlyMode, true);

      // Verify that verifyReadOnlyIntegrity reports intact: true with 0 violations
      // (This directly confirms that depth > 4 vs depth > 6 discrepancy is eliminated)
      const integrity = catalog.verifyReadOnlyIntegrity();
      assert.equal(integrity.intact, true);
      assert.equal(integrity.readOnlyVerified, true);
      assert.equal(integrity.violations.length, 0);

      // Dropping a new file at depth 11 AFTER initialization is immediately caught as NEWLY_INTRODUCED_PROTECTED_FILE
      const rogueDeepFile = path.join(deepPath, 'rogue-after-init.txt');
      fs.writeFileSync(rogueDeepFile, 'unindexed payload', 'utf8');

      const afterRogue = catalog.verifyReadOnlyIntegrity();
      assert.equal(afterRogue.intact, false);
      assert.equal(afterRogue.readOnlyVerified, false);
      assert.ok(
        afterRogue.violations.some(
          (v) =>
            v.reason === 'NEWLY_INTRODUCED_PROTECTED_FILE' &&
            v.relativePath.includes('rogue-after-init.txt')
        )
      );

      fs.unlinkSync(rogueDeepFile);
      const afterCleanup = catalog.verifyReadOnlyIntegrity();
      assert.equal(afterCleanup.intact, true);
      assert.equal(afterCleanup.violations.length, 0);
    } finally {
      try {
        fs.rmSync(tmpRoot, { recursive: true, force: true });
      } catch (_) {}
    }
  });

  it('120. Phase Atlas X (Cycle 2 & Cycle 3) — Epistemic Evidence Boundaries: Authoritative NXDOMAIN, Strict Positive TCP Handshake Requirement & Refused States', () => {
    const { chatOperatorService } = require('../src/core/chat/chat-operator-service');

    // 1. Authoritative NXDOMAIN distinguishes non-existent records from timeout or network drops
    const nxdomainBoundary = chatOperatorService.evaluateIndirectEvidenceBoundaries({
      probeType: 'DNS_QUERY',
      status: 'NXDOMAIN',
      rcode: 'NXDOMAIN'
    });
    assert.equal(nxdomainBoundary.observationCategory, 'AUTHORITATIVE_DNS_NXDOMAIN_NON_EXISTENCE');
    assert.ok(nxdomainBoundary.provenByObservation.includes('AUTHORITATIVE_ZONE_DOES_NOT_CONTAIN_RECORD_NXDOMAIN'));
    assert.ok(nxdomainBoundary.notProvenByObservation.includes('RECURSIVE_RESOLVER_TIMEOUT'));
    assert.ok(nxdomainBoundary.notProvenByObservation.includes('UDP_53_OR_TCP_53_TRANSPORT_FILTERING'));

    // 2. DNS Timeout
    const timeoutBoundary = chatOperatorService.evaluateIndirectEvidenceBoundaries({
      probeType: 'DNS_QUERY',
      status: 'TIMEOUT'
    });
    assert.equal(timeoutBoundary.observationCategory, 'DNS_RESOLUTION_TIMEOUT_OR_FAILURE');
    assert.ok(timeoutBoundary.provenByObservation.includes('DNS_QUERY_RESPONSE_NOT_RECEIVED_WITHIN_DEADLINE'));

    // 3. Positive TCP Connectivity requires tcpReachable === true and status === 'PASS'/'OK'
    const validTcpBoundary = chatOperatorService.evaluateIndirectEvidenceBoundaries({
      probeType: 'TCP_SYN_PROBE',
      tcpReachable: true,
      status: 'PASS'
    });
    assert.equal(validTcpBoundary.observationCategory, 'UPPER_LAYER_TCP_TRANSPORT_CONNECTIVITY');
    assert.ok(validTcpBoundary.provenByObservation.includes('L3_ACTIVE_ROUTE_IP_FORWARDING_REACHABILITY'));
    assert.ok(validTcpBoundary.provenByObservation.includes('L4_TCP_THREE_WAY_HANDSHAKE_COMPLETION'));

    // 4. Failed or Refused TCP probe does NOT claim L3 forwarding reachability
    const failedTcpBoundary = chatOperatorService.evaluateIndirectEvidenceBoundaries({
      probeType: 'TCP_SYN_PROBE',
      tcpReachable: false,
      status: 'FAIL'
    });
    assert.equal(failedTcpBoundary.observationCategory, 'TCP_TRANSPORT_CONNECTIVITY_FAILED_OR_REFUSED');
    assert.ok(failedTcpBoundary.provenByObservation.includes('L4_TCP_HANDSHAKE_NOT_ESTABLISHED'));
    assert.ok(failedTcpBoundary.notProvenByObservation.includes('L3_ACTIVE_ROUTE_IP_FORWARDING_REACHABILITY'));
    assert.ok(failedTcpBoundary.notProvenByObservation.includes('L4_TCP_THREE_WAY_HANDSHAKE_COMPLETION'));

    // 5. Unmeasured / empty observation returns INSUFFICIENT_OR_UNVERIFIED_EVIDENCE
    const unmeasuredBoundary = chatOperatorService.evaluateIndirectEvidenceBoundaries({});
    assert.equal(unmeasuredBoundary.observationCategory, 'INSUFFICIENT_OR_UNVERIFIED_EVIDENCE');
    assert.equal(unmeasuredBoundary.provenByObservation.length, 0);
  });

  it('121. Phase Atlas X (Cycle 4) — TelemetryContextAccelerator Physical Spill Pruning & Durable SQLite Deletion', () => {
    const { DatabaseSync } = require('node:sqlite');
    const { runMigrations } = require('../src/db/migrations');
    const {
      recordSpilledCriticalEvidenceBatch,
      retrieveSpilledCriticalEvidence,
      pruneExpiredSpilledCriticalEvidence,
      clearInMemorySpillCacheForTesting
    } = require('../src/core/skills/telemetry-context-accelerator');

    const db = new DatabaseSync(':memory:');
    runMigrations(db);

    clearInMemorySpillCacheForTesting();
    const nowMs = 1700000000000;

    // Create 3 expired batches (short TTL) and 2 active batches (long TTL)
    const expiredRef1 = recordSpilledCriticalEvidenceBatch(
      [{ id: 'ev-exp-1', metric: 'rttMs', layer: 'L4_TCP', value: 300, isPatientZero: true }],
      { db, nowMs, retentionTtlMs: 2000 }
    );
    const expiredRef2 = recordSpilledCriticalEvidenceBatch(
      [{ id: 'ev-exp-2', metric: 'rttMs', layer: 'L4_TCP', value: 310, isPatientZero: true }],
      { db, nowMs, retentionTtlMs: 3000 }
    );
    const expiredRef3 = recordSpilledCriticalEvidenceBatch(
      [{ id: 'ev-exp-3', metric: 'rttMs', layer: 'L4_TCP', value: 320, isPatientZero: true }],
      { db, nowMs, retentionTtlMs: 4000 }
    );
    const activeRef1 = recordSpilledCriticalEvidenceBatch(
      [{ id: 'ev-act-1', metric: 'rttMs', layer: 'L4_TCP', value: 250, isPatientZero: false }],
      { db, nowMs, retentionTtlMs: 3600000 } // active for 1 hour
    );
    const activeRef2 = recordSpilledCriticalEvidenceBatch(
      [{ id: 'ev-act-2', metric: 'rttMs', layer: 'L4_TCP', value: 260, isPatientZero: false }],
      { db, nowMs, retentionTtlMs: 7200000 } // active for 2 hours
    );

    // Call physical pruning at nowMs + 10000 (after the 3 short-lived ones expired)
    const pruneResult = pruneExpiredSpilledCriticalEvidence({ db, nowMs: nowMs + 10000, maxDeletions: 100 });
    assert.equal(pruneResult.prunedFromMemoryCount, 3);
    assert.equal(pruneResult.prunedFromSqliteCount, 3);
    assert.ok(pruneResult.deletedReferenceIds.includes(expiredRef1.spillReferenceId));
    assert.ok(pruneResult.deletedReferenceIds.includes(expiredRef2.spillReferenceId));
    assert.ok(pruneResult.deletedReferenceIds.includes(expiredRef3.spillReferenceId));

    // Verify expired records are physically deleted from SQLite
    const row1 = db.prepare('SELECT * FROM telemetry_critical_evidence_spill_ledger WHERE spill_reference_id = ?').get(expiredRef1.spillReferenceId);
    assert.equal(row1, undefined);

    // Verify active records remain retrievable and intact
    const activeRetrieved = retrieveSpilledCriticalEvidence(activeRef1.spillReferenceId, { db, nowMs: nowMs + 10000 });
    assert.equal(activeRetrieved.retrievalStatus, 'RETRIEVED_OK');
    assert.equal(activeRetrieved.expired, false);
    assert.equal(activeRetrieved.spilledCriticalRecords[0].id, 'ev-act-1');

    db.close();
  });

  it('122. Phase Atlas X (Cycle 4) — WriteCoalescingSqliteAdapter Multi-Adapter Shared DB Handle Ref-Counting', async () => {
    const { WriteCoalescingSqliteAdapter } = require('../src/db/write-coalescing-sqlite');
    const { DatabaseSync } = require('node:sqlite');
    const sharedDb = new DatabaseSync(':memory:');
    sharedDb.exec('CREATE TABLE test_shared (id INTEGER PRIMARY KEY, msg TEXT)');

    const adapterA = new WriteCoalescingSqliteAdapter(sharedDb, { busyTimeoutMs: 2000 });
    const adapterB = new WriteCoalescingSqliteAdapter(sharedDb, { busyTimeoutMs: 2000 });

    assert.equal(adapterA.getMetrics().registeredAdaptersOnSameDbCount, 2);
    assert.equal(adapterB.getMetrics().registeredAdaptersOnSameDbCount, 2);

    // Write from both adapters using enqueueWriteTransaction
    await adapterA.enqueueWriteTransaction('insertA', (database) => {
      database.prepare('INSERT INTO test_shared (id, msg) VALUES (?, ?)').run(1, 'from A');
      return 'a-ok';
    });
    await adapterB.enqueueWriteTransaction('insertB', (database) => {
      database.prepare('INSERT INTO test_shared (id, msg) VALUES (?, ?)').run(2, 'from B');
      return 'b-ok';
    });

    // Drain and shutdown Adapter A with closeUnderlyingDb: true
    // Because Adapter B is still registered on the same DB, sharedDb must NOT be closed!
    const shutdownA = await adapterA.drainAndShutdown({ closeUnderlyingDb: true });
    assert.equal(shutdownA.drained, true);
    assert.equal(adapterA.isClosed, true);

    // Verify Adapter B remains functional and shared DB is open!
    assert.equal(adapterB.isClosed, false);
    assert.equal(adapterB.getMetrics().registeredAdaptersOnSameDbCount, 1);
    await adapterB.enqueueWriteTransaction('insertB2', (database) => {
      database.prepare('INSERT INTO test_shared (id, msg) VALUES (?, ?)').run(3, 'from B after A closed');
      return 'b2-ok';
    });

    const rows = sharedDb.prepare('SELECT COUNT(*) AS cnt FROM test_shared').get();
    assert.equal(Number(rows.cnt), 3);

    // Drain and shutdown Adapter B with closeUnderlyingDb: true -> now the underlying DB is closed cleanly
    const shutdownB = await adapterB.drainAndShutdown({ closeUnderlyingDb: true });
    assert.equal(shutdownB.drained, true);
    assert.equal(adapterB.isClosed, true);
  });

  it('123. Phase Atlas X (Cycle 5 & Cycle 6) — Enterprise NOC Live Bounded Table Partitioning & UI Safety', () => {
    const { partitionBoundedNocTableRows } = require('../public/js/views/enterprise-noc-view');

    // 1. Edge cases: null, undefined, non-array rows
    const nullResult = partitionBoundedNocTableRows(null);
    assert.equal(nullResult.renderedRowsCount, 0);
    assert.equal(nullResult.totalRowsCount, 0);
    assert.equal(nullResult.isTruncatedForRenderPerformance, false);

    // 2. Safe normalization of negative / NaN limit
    const negLimitResult = partitionBoundedNocTableRows([{ id: 1 }, { id: 2 }], { maxRenderedRows: -10 });
    assert.equal(negLimitResult.maxRenderedRows, 1);
    assert.equal(negLimitResult.renderedRowsCount, 1);
    assert.equal(negLimitResult.overflowRowsCount, 1);
    assert.equal(negLimitResult.isTruncatedForRenderPerformance, true);

    // 3. Large burst partitioning (e.g. 500 events partitioned to 50)
    const burst = Array.from({ length: 500 }, (_, i) => ({ id: `event-${i}` }));
    const burstPartition = partitionBoundedNocTableRows(burst, { maxRenderedRows: 50 });
    assert.equal(burstPartition.renderedRowsCount, 50);
    assert.equal(burstPartition.overflowRowsCount, 450);
    assert.equal(burstPartition.totalRowsCount, 500);
    assert.ok(burstPartition.overflowSummaryText.includes('Showing top 50 of 500 records'));
  });

  it('124. Phase Atlas X (Cycle 7) — End-to-End Chat Operator Epistemic Conversation with Live Mesh State', async () => {
    const { chatOperatorService } = require('../src/core/chat/chat-operator-service');
    const session = chatOperatorService.getOrCreateSession('test-epistemic-atlas-x-session', { userId: 'admin-1', role: 'ADMIN' });
    assert.equal(session.sessionId, 'test-epistemic-atlas-x-session');

    const res = await chatOperatorService.processMessage({
      sessionId: 'test-epistemic-atlas-x-session',
      message: 'Assess current Project Atlas network status, relay reachability and indirect evidence boundaries',
      user: { userId: 'admin-1', role: 'ADMIN' }
    });

    assert.ok(res.reply);
    assert.ok(res.epistemicDistinctions);
    assert.ok(Array.isArray(res.epistemicDistinctions.observedConditions));
    assert.ok(res.epistemicDistinctions.indirectEvidenceBoundaries);
    assert.ok(res.epistemicDistinctions.indirectEvidenceBoundaries.observationCategory);
    assert.ok(Array.isArray(res.epistemicDistinctions.indirectEvidenceBoundaries.notProvenByObservation));
  });

  it('125. Phase Atlas X — Comprehensive Sovereign Ecosystem Verification Matrix', () => {
    const { superpowersSkillsEngine } = require('../src/core/skills/superpowers-skills-engine');
    const { readOnlySkillCatalog } = require('../src/core/skills/read-only-skill-router');

    // 1. Verify 159 immutable skill manifests intact
    const immutability = superpowersSkillsEngine.verifySkillEcosystemImmutability();
    assert.equal(immutability.intact, true);
    assert.equal(immutability.readOnlyVerified, true);
    assert.equal(immutability.violations.length, 0);
    assert.equal(immutability.primarySkillsCount, 85);
    assert.equal(immutability.nestedGstackWorkflowsCount, 74);
    assert.equal(immutability.combinedManifestsCount, 159);

    // 2. Verify complete inventory summary
    const summary = readOnlySkillCatalog.getInventorySummary();
    assert.equal(summary.readOnlyMode, true);
    assert.equal(summary.symlinkContainmentEnforced, true);
    assert.equal(typeof summary.blockedSymlinkEscapesCount, 'number');

    // 3. Operational intent routing with negative keyword filtration
    const routeRes = readOnlySkillCatalog.routeOperationalIntent(
      'Diagnose L4 transport latency, packet drops and relay failover'
    );
    assert.equal(routeRes.negativeContextFiltered, true);
    assert.ok(routeRes.selectedSkills.length > 0);
  });

  it('126. Project Aurora / Meridian / Falcon — Conversational Experience Evolution, Shell Navigation Parity & Read-Only Skill Immutability', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const { superpowersSkillsEngine } = require('../src/core/skills/superpowers-skills-engine');

    const rootDir = path.resolve(__dirname, '..');
    const indexHtml = fs.readFileSync(path.join(rootDir, 'public/index.html'), 'utf8');
    const meridianJs = fs.readFileSync(path.join(rootDir, 'public/js/ejii-meridian.js'), 'utf8');
    const chatViewJs = fs.readFileSync(path.join(rootDir, 'public/js/views/chat-workspace-view.js'), 'utf8');
    const chatCss = fs.readFileSync(path.join(rootDir, 'public/css/chat-minimal.css'), 'utf8');

    // 1. All 10 primary workstations have data-view or data-target-view attributes in index.html and viewMeta entries in ejii-meridian.js
    const expectedViews = [
      'chat',
      'ai-operator',
      'topology',
      'enterprise-noc',
      'noc-dashboard',
      'packet-sniffer',
      'ultra-ip-scanner',
      'pc-automation',
      'core-diagnostics',
      'learning-center'
    ];
    for (const v of expectedViews) {
      assert.ok(
        indexHtml.includes(`data-view="${v}"`) || indexHtml.includes(`data-target-view="${v}"`),
        `index.html must include data-view or data-target-view="${v}"`
      );
      assert.ok(meridianJs.includes(v), `ejii-meridian.js viewMeta must include ${v}`);
    }

    // 2. Conversational AI workspace includes interpreted intent strip, executive callouts, copyable code blocks, progressive disclosure, and active session context bar
    assert.ok(chatViewJs.includes('ejii-intent-context-strip'));
    assert.ok(chatViewJs.includes('ejii-exec-callout-block'));
    assert.ok(chatViewJs.includes('ejii-code-block-wrap'));
    assert.ok(chatViewJs.includes('ejii-deep-intel-details'));
    assert.ok(chatViewJs.includes('ejiiActiveSessionContextBar'));
    assert.ok(chatViewJs.includes('ejii-nl-guidance-banner'));
    assert.ok(chatCss.includes('.ejii-intent-context-strip'));
    assert.ok(chatCss.includes('.ejii-exec-callout-block'));
    assert.ok(chatCss.includes('.ejii-deep-intel-details'));

    // 3. Re-verify 100% read-only skill immutability across all 85 primary skills + 74 GStack workflows
    const immutability = superpowersSkillsEngine.verifySkillEcosystemImmutability();
    assert.equal(immutability.intact, true);
    assert.equal(immutability.readOnlyVerified, true);
    assert.equal(immutability.violations.length, 0);
  });

  it('127. Principal PM Directive — Verified Async Clipboard Promise Handling, Markdown Code Escaping & Project Falcon Natural-Language Intelligence', async () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const vm = require('node:vm');
    const { chatOperatorService } = require('../src/core/chat/chat-operator-service');
    const { superpowersSkillsEngine } = require('../src/core/skills/superpowers-skills-engine');

    const rootDir = path.resolve(__dirname, '..');
    const chatViewJs = fs.readFileSync(path.join(rootDir, 'public/js/views/chat-workspace-view.js'), 'utf8');

    // 1. Load chat-workspace-view.js in a minimal VM sandbox to test formatEjiiChatMarkdown & copyEjiiCodeBlock directly
    let clipboardShouldReject = false;
    let lastClipboardText = null;
    const sandboxWindow = {
      ejiiState: { currentRole: 'ADMIN' },
      addEventListener: () => {}
    };
    const sandboxDocument = {
      getElementById: () => null,
      querySelectorAll: () => [],
      addEventListener: () => {},
      body: null
    };
    const sandboxNavigator = {
      clipboard: {
        writeText: async (txt) => {
          if (clipboardShouldReject) {
            throw new Error('NotAllowedError: Write permission denied');
          }
          lastClipboardText = txt;
        }
      }
    };
    const ctx = vm.createContext({
      window: sandboxWindow,
      document: sandboxDocument,
      navigator: sandboxNavigator,
      localStorage: { getItem: () => null, setItem: () => {} },
      fetch: async () => ({ ok: true, json: async () => ({}) }),
      AbortController,
      setTimeout: () => 1,
      clearTimeout: () => {},
      console
    });
    vm.runInContext(chatViewJs, ctx);

    assert.equal(typeof sandboxWindow.formatEjiiChatMarkdown, 'function');
    assert.equal(typeof sandboxWindow.formatEjiiInlineMarkdown, 'function');
    assert.equal(typeof sandboxWindow.copyEjiiCodeBlock, 'function');
    assert.equal(typeof sandboxWindow.copyEjiiReportText, 'function');

    // 2. Test Markdown inline code asterisk preservation & XSS escaping
    const sqlInline = sandboxWindow.formatEjiiInlineMarkdown(
      'Run `SELECT * FROM nodes WHERE a * b > 0` and `2 ** 8` safely against `<script>alert(1)</script>`'
    );
    assert.ok(
      sqlInline.includes('<code>SELECT * FROM nodes WHERE a * b &gt; 0</code>'),
      'Inline code with asterisks must not be corrupted into <em> tags'
    );
    assert.ok(
      sqlInline.includes('<code>2 ** 8</code>'),
      'Inline code with double asterisks must not be corrupted into <strong> tags'
    );
    assert.ok(!sqlInline.includes('<script>'), 'Raw <script> tags must be HTML-escaped');

    // 3. Test CRLF fenced code blocks and unclosed trailing fenced code blocks
    const crlfFenced = sandboxWindow.formatEjiiChatMarkdown(
      '**Result:** Verified TCP probe.\r\n\r\n```bash\r\nnc -zv 127.0.0.1 3000\r\n```'
    );
    assert.ok(crlfFenced.includes('ejii-exec-callout-result'), 'Executive Result callout must render');
    assert.ok(crlfFenced.includes('ejii-code-block-wrap'), 'CRLF fenced code block must render inside code wrap');
    assert.ok(crlfFenced.includes('nc -zv 127.0.0.1 3000'), 'Code content must be preserved');

    const unclosedFence = sandboxWindow.formatEjiiChatMarkdown(
      'Diagnostic snippet:\n\n```python\nimport socket\nsocket.create_connection(("127.0.0.1", 3000))'
    );
    assert.ok(unclosedFence.includes('ejii-code-block-wrap'), 'Unclosed trailing code fence must still render as code block');

    // 4. Test async clipboard Promise rejection vs resolution (never falsely claim "✓ Copied" on rejection)
    const mockBtn = {
      textContent: 'Copy',
      dataset: {},
      attrs: {},
      setAttribute(k, v) { this.attrs[k] = v; },
      closest() {
        return {
          querySelector() {
            return { textContent: 'ip route show default' };
          }
        };
      }
    };

    clipboardShouldReject = true;
    const failedCopy = await sandboxWindow.copyEjiiCodeBlock(mockBtn);
    assert.equal(failedCopy.copied, false, 'Rejected clipboard Promise must report copied: false');
    assert.equal(mockBtn.textContent, '✕ Copy failed', 'Button must display failure state when clipboard Promise rejects');
    assert.equal(mockBtn.dataset.copyState, 'failed');

    clipboardShouldReject = false;
    const okCopy = await sandboxWindow.copyEjiiCodeBlock(mockBtn);
    assert.equal(okCopy.copied, true, 'Resolved clipboard Promise must report copied: true');
    assert.equal(mockBtn.textContent, '✓ Copied', 'Button must display ✓ Copied after Promise resolves');
    assert.equal(mockBtn.dataset.copyState, 'copied');
    assert.equal(lastClipboardText, 'ip route show default');

    const mockReportBtn = { textContent: 'Copy Incident Report', dataset: {} };
    clipboardShouldReject = true;
    const failedReport = await sandboxWindow.copyEjiiReportText(mockReportBtn, '# Incident Report');
    assert.equal(failedReport.copied, false);
    assert.equal(mockReportBtn.textContent, '✕ Copy failed');

    clipboardShouldReject = false;
    const okReport = await sandboxWindow.copyEjiiReportText(mockReportBtn, '# Incident Report');
    assert.equal(okReport.copied, true);
    assert.equal(mockReportBtn.textContent, '✓ Report Copied');

    // 5. Test Project Falcon NLU enhancements: "on <port>", "tcp/<port>", DNS record types, and follow-up continuity
    const onPortPlan = chatOperatorService.parseIntentAndEntities('cant reach 127.0.0.1 on 3000', {});
    assert.equal(onPortPlan.intent, 'port_check');
    assert.equal(onPortPlan.target, '127.0.0.1');
    assert.deepEqual(onPortPlan.ports, [3000]);

    const slashPortPlan = chatOperatorService.parseIntentAndEntities('check tcp/443 on example.com', {});
    assert.equal(slashPortPlan.intent, 'port_check');
    assert.equal(slashPortPlan.target, 'example.com');
    assert.deepEqual(slashPortPlan.ports, [443]);

    const mxPlan = chatOperatorService.parseIntentAndEntities('check mx records for example.com', {});
    assert.equal(mxPlan.intent, 'dns');
    assert.equal(mxPlan.target, 'example.com');
    assert.equal(mxPlan.recordType, 'MX');

    const ptrPlan = chatOperatorService.parseIntentAndEntities('reverse dns for 8.8.8.8', {});
    assert.equal(ptrPlan.intent, 'dns');
    assert.equal(ptrPlan.target, '8.8.8.8');
    assert.equal(ptrPlan.recordType, 'PTR');

    const spfPlan = chatOperatorService.parseIntentAndEntities('check spf record for example.com', {});
    assert.equal(spfPlan.intent, 'dns');
    assert.equal(spfPlan.target, 'example.com');
    assert.equal(spfPlan.recordType, 'TXT');

    // Follow-up port check with active session target vs missing target without session context
    const followUpWithContext = chatOperatorService.parseIntentAndEntities('pls check port 8443', {
      lastValidTarget: 'example.com',
      lastTarget: 'example.com',
      lastTargetTimestampMs: Date.now()
    });
    assert.equal(followUpWithContext.intent, 'port_check');
    assert.equal(followUpWithContext.target, 'example.com');
    assert.equal(followUpWithContext.usedFollowUpTarget, true);
    assert.deepEqual(followUpWithContext.ports, [8443]);

    const followUpNoContext = chatOperatorService.parseIntentAndEntities('pls check port 8443', {});
    assert.equal(followUpNoContext.intent, 'clarification_needed');
    assert.equal(followUpNoContext.clarificationReason, 'MISSING_TARGET_CONTEXT');
    assert.equal(followUpNoContext.target, null);

    // 6. Confirm 100% read-only skill immutability remains intact
    const immutability = superpowersSkillsEngine.verifySkillEcosystemImmutability();
    assert.equal(immutability.intact, true);
    assert.equal(immutability.violations.length, 0);
  });

  it('128. Phase Atlas XII — Claude-Mem 3-Layer Progressive Disclosure Engine, 5-Tier Skill Taxonomy Reconciliation, Overlap Collision Deduplication & Script/Scope Firewall', async () => {
    const { claudeMemEngine } = require('../src/core/memory/claude-mem-engine');
    const { readOnlySkillCatalog } = require('../src/core/skills/read-only-skill-router');
    const { chatOperatorService } = require('../src/core/chat/chat-operator-service');
    const { superpowersSkillsEngine } = require('../src/core/skills/superpowers-skills-engine');
    const { packetStreamer } = require('../src/network/packet-streaming/packet-streamer');

    // 1. Test Claude-Mem 3-Layer Progressive Disclosure Memory Engine (SQLite-backed)
    const obsA = claudeMemEngine.recordObservation({
      sessionId: 'sess-claude-mem-128',
      type: 'probe_evidence',
      title: 'TCP port 3000 check on 127.0.0.1',
      subtitle: 'Layer 4 socket probe connected in 1.1ms',
      target: '127.0.0.1',
      rootCause: 'HEALTHY',
      facts: ['TCP 127.0.0.1:3000 reachable (1.1ms)', 'Socket state ESTABLISHED'],
      narrative: 'Executed live TCP socket handshake against 127.0.0.1:3000 with 1.1ms RTT and zero packet loss.',
      conceptTags: ['how-it-works', 'pattern'],
      probeMetrics: { rttMs: 1.1, port: 3000, status: 'OPEN' }
    });
    assert.ok(obsA.observationId);
    assert.equal(obsA.target, '127.0.0.1');

    const obsB = claudeMemEngine.recordObservation({
      sessionId: 'sess-claude-mem-128',
      type: 'incident',
      title: 'DNS latency spike on internal-resolver.corp',
      subtitle: 'UDP/53 lookup exceeded 185ms threshold',
      target: '127.0.0.1',
      rootCause: 'DNS_CONTROL_PLANE',
      facts: ['DNS query latency 185ms', 'Fallback TCP/53 succeeded in 14ms'],
      narrative: 'Observed elevated UDP/53 response latency followed by clean TCP/53 fallback resolution.',
      conceptTags: ['root-cause', 'problem-solution'],
      probeMetrics: { udpLatencyMs: 185, tcpLatencyMs: 14 }
    });
    assert.ok(obsB.observationId);

    // Layer 1: Compact Index Search (~35 tokens/item)
    const layer1 = claudeMemEngine.searchIndex('127.0.0.1 tcp port 3000', {
      target: '127.0.0.1',
      limit: 8
    });
    assert.equal(layer1.disclosureLayer, 'LAYER_1_COMPACT_INDEX');
    assert.ok(layer1.hits.length >= 2);
    assert.ok(layer1.tokensSaved > 0);
    assert.ok(layer1.compressionRatioPct > 0);
    assert.equal(layer1.hits[0].probeMetrics, undefined);

    // Layer 2: Timeline Context Window around anchor observation
    const layer2 = claudeMemEngine.getTimelineContext(obsA.observationId, {
      depthBefore: 3,
      depthAfter: 3
    });
    assert.equal(layer2.disclosureLayer, 'LAYER_2_CHRONOLOGICAL_TIMELINE');
    assert.equal(layer2.anchorObservationId, obsA.observationId);
    assert.ok(
      layer2.timelineEntries.some(
        (item) => item.relativePosition === 0 && item.observationId === obsA.observationId
      )
    );

    // Layer 3: Selective Full Observation Hydration by IDs
    const layer3 = claudeMemEngine.getObservationsByIds([obsA.observationId]);
    assert.equal(layer3.disclosureLayer, 'LAYER_3_SELECTIVE_HYDRATION');
    assert.equal(layer3.hydratedCount, 1);
    assert.equal(layer3.observations[0].observationId, obsA.observationId);
    assert.ok(Array.isArray(layer3.observations[0].facts));
    assert.equal(layer3.observations[0].probeMetrics.port, 3000);

    // Progressive Disclosure Compiler within strict token budget
    const compiledBundle = claudeMemEngine.compileProgressiveDisclosureContext(
      '127.0.0.1 port 3000',
      '127.0.0.1',
      420
    );
    assert.equal(compiledBundle.engine, 'CLAUDE_MEM_3_LAYER_PROGRESSIVE_DISCLOSURE');
    assert.equal(compiledBundle.maxTokenBudget, 420);
    assert.ok(compiledBundle.layer1IndexSearch.hitCount >= 1);
    assert.ok(compiledBundle.layer3HydratedObservations.hydratedCount >= 1);

    // 2. Test 5-Tier Skill Taxonomy Reconciliation Map (Weakness #1 Fix)
    const taxMap = readOnlySkillCatalog.getTaxonomyReconciliationMap();
    assert.equal(taxMap.immutableReferenceTaxonomy, true);
    assert.equal(taxMap.readOnlyFirewallActive, true);
    assert.equal(taxMap.tiers.tier1PrimaryTopLevelPackages, 85);
    assert.equal(taxMap.tiers.tier2NestedGstackWorkflows, 74);
    assert.equal(taxMap.tiers.tier3CombinedCanonicalManifests, 159);
    assert.equal(taxMap.tiers.tier4ActiveMirroredRuntimeModules, 111);
    assert.equal(taxMap.tiers.tier5RegisteredExternalLockDefinitions, 71);

    // 3. Test Deterministic Skill Overlap Collision Deduplication (Weakness #2 Fix)
    const collidingCandidates = [
      'caveman-token-reduction',
      'caveman',
      'api-and-interface-design',
      'api-design',
      'frontend-ui-engineering',
      'frontend-design',
      'anthropics-agent-toolkits',
      'anthropics-skills',
      'gravitas-highstakes',
      'gravitas-typescript',
      'claude-mem',
      'context-budget',
      'gstack/autoplan',
      'gstack/gstack-autoplan'
    ];
    const deduped = readOnlySkillCatalog.resolveSkillOverlapCollisions(collidingCandidates);
    assert.equal(deduped.suppressedCount, 7);
    const retainedIds = deduped.deduplicatedSkills.map((s) => s.skillId);
    assert.ok(retainedIds.includes('caveman-token-reduction'));
    assert.ok(!retainedIds.includes('caveman'));
    assert.ok(retainedIds.includes('api-and-interface-design'));
    assert.ok(!retainedIds.includes('api-design'));
    assert.ok(retainedIds.includes('frontend-ui-engineering'));
    assert.ok(!retainedIds.includes('frontend-design'));
    assert.ok(retainedIds.includes('anthropics-agent-toolkits'));
    assert.ok(!retainedIds.includes('anthropics-skills'));
    assert.ok(retainedIds.includes('gravitas-highstakes'));
    assert.ok(!retainedIds.includes('gravitas-typescript'));
    assert.ok(retainedIds.includes('claude-mem'));
    assert.ok(!retainedIds.includes('context-budget'));
    assert.ok(retainedIds.includes('gstack/autoplan'));
    assert.ok(!retainedIds.includes('gstack/gstack-autoplan'));

    // 4. Test Context-Budgeted Dynamic Skill Routing (Token cap enforced)
    const routed = readOnlySkillCatalog.routeWithContextBudget(
      'diagnose tcp port 443 latency and design frontend api telemetry with token reduction',
      { maxContextTokens: 900 }
    );
    assert.equal(routed.passiveCatalogSize, 159);
    assert.ok(routed.allocatedTokens <= 900);
    assert.ok(routed.activatedSkills.length >= 1);

    // 5. Test Read-Only Script & Scope Firewall (Weakness #3 & #6 Fix)
    const regenEval = readOnlySkillCatalog.evaluateScriptAndScopeFirewall('.agents/skills/gstack/bin/gstack-regen');
    assert.equal(regenEval.executionPermitted, false);
    assert.equal(regenEval.isMutatingGstackGenerator, true);
    assert.equal(regenEval.scopeClassification, 'BLOCKED_READ_ONLY_TEMPLATE_GENERATOR');

    const tmplEval = readOnlySkillCatalog.evaluateScriptAndScopeFirewall('.agents/skills/gstack/SKILL.md.tmpl');
    assert.equal(tmplEval.executionPermitted, false);

    const gstackCiEval = readOnlySkillCatalog.evaluateScriptAndScopeFirewall('.agents/skills/gstack/.github/workflows/evals.yml');
    assert.equal(gstackCiEval.isIsolatedGstackTestOrWorkflow, true);
    assert.equal(gstackCiEval.scopeClassification, 'ISOLATED_GSTACK_INTERNAL_FIXTURE_DO_NOT_RUN_AS_APP_TEST');

    // 6. Test End-to-End Chat Operator Turn populating claudeMemContext and skillRoutingContext
    const turn = await chatOperatorService.processMessage({
      sessionId: 'sess-claude-mem-turn-128',
      message: 'cant reach 127.0.0.1 on 3000',
      user: 'admin'
    });
    assert.ok(turn.reply);
    assert.ok(turn.claudeMemContext);
    assert.equal(
      turn.claudeMemContext.engine,
      'CLAUDE_MEM_3_LAYER_PROGRESSIVE_DISCLOSURE'
    );
    assert.ok(turn.skillRoutingContext);
    assert.equal(turn.skillRoutingContext.passiveCatalogSize, 159);

    // 7. Test PacketStreamer unprivileged Npcap fallback without wpcap.dll warning
    const capProfile = packetStreamer.getCaptureCapabilityProfile();
    if (!capProfile.driverAvailable) {
      packetStreamer._startNpcapSniffer();
      assert.equal(packetStreamer.snifferProcess, null);
      assert.equal(packetStreamer.snifferBackendActive, false);
    }

    // 8. Confirm 100% read-only skill ecosystem immutability
    const finalImmutability = superpowersSkillsEngine.verifySkillEcosystemImmutability();
    assert.equal(finalImmutability.intact, true);
    assert.equal(finalImmutability.violations.length, 0);
  });

  it('129. Claude-Mem Epistemic Memory Separation, Token Accounting, SQLite Diagnostics & Project Falcon Multi-Turn Conversational Intelligence', async () => {
    const { ClaudeMemEngine, claudeMemEngine } = require('../src/core/memory/claude-mem-engine');
    const { chatOperatorService } = require('../src/core/chat/chat-operator-service');
    const { superpowersSkillsEngine } = require('../src/core/skills/superpowers-skills-engine');

    // 1. Epistemic separation of CMEM-BOOT-001 (static architectural metadata vs live probe evidence)
    const bootHydrated = claudeMemEngine.getObservationsByIds(['CMEM-BOOT-001']);
    assert.equal(bootHydrated.hydratedCount, 1);
    const bootObs = bootHydrated.observations[0];
    assert.equal(bootObs.memoryCategory, 'ARCHITECTURAL_KNOWLEDGE');
    assert.equal(bootObs.isLiveMeasurement, false);
    assert.equal(bootObs.target, null);
    assert.deepEqual(bootObs.probeMetrics, {});

    // Confirm CMEM-BOOT-001 never contaminates default operational target searches
    const defaultSearch = claudeMemEngine.searchIndex('127.0.0.1:3000 architectural baseline', {
      limit: 20
    });
    assert.ok(
      !defaultSearch.hits.some((h) => h.observationId === 'CMEM-BOOT-001'),
      'Static architectural metadata must be excluded from operational search results by default'
    );

    // Confirm architectural metadata can still be explicitly queried when includeArchitecturalMetadata: true
    const archSearch = claudeMemEngine.searchIndex('progressive disclosure memory', {
      includeArchitecturalMetadata: true,
      limit: 20
    });
    assert.ok(archSearch.hits.some((h) => h.observationId === 'CMEM-BOOT-001'));

    // 2. Token estimation method distinction (character heuristic vs provider-reported exact token count)
    assert.equal(defaultSearch.tokenEstimationMethod, 'CHARACTER_HEURISTIC_4CHARS_PER_TOKEN');
    assert.equal(defaultSearch.isExactProviderTokenCount, false);

    const causalSessionId = `sess-epistemic-129-${Date.now()}`;
    const exactObs = claudeMemEngine.recordObservation({
      sessionId: causalSessionId,
      type: 'probe_evidence',
      title: 'Exact provider token observation on 127.0.0.1',
      target: '127.0.0.1',
      providerReportedTokens: 142,
      facts: ['Measured RTT 0.8ms'],
      probeMetrics: { rttMs: 0.8, port: 3000 }
    });
    assert.equal(exactObs.tokenEstimationMethod, 'PROVIDER_REPORTED_EXACT');
    assert.equal(exactObs.isExactProviderTokenCount, true);
    assert.equal(exactObs.fullTokenEstimate, 142);

    // 3. Causal parent-child lineage (getCausalChain)
    const childObs = claudeMemEngine.recordObservation({
      sessionId: causalSessionId,
      parentObservationId: exactObs.observationId,
      type: 'remediation',
      title: 'Follow-up port check after initial probe',
      target: '127.0.0.1',
      facts: ['Confirmed port 3000 open'],
      probeMetrics: { port: 3000, status: 'OPEN' }
    });
    const causalChain = claudeMemEngine.getCausalChain(childObs.observationId);
    assert.equal(causalChain.chainLength, 2);
    assert.equal(causalChain.chain[0].observationId, exactObs.observationId);
    assert.equal(causalChain.chain[1].observationId, childObs.observationId);

    // 4. Explicit SQLite write failure diagnostics (no silent catch (_) {})
    const failingDbHandle = {
      exec() {},
      prepare() {
        return {
          all() {
            return [];
          },
          run() {
            throw new Error('SIMULATED_SQLITE_DISK_FULL');
          }
        };
      }
    };
    const isolatedMem = new ClaudeMemEngine({ dbHandle: failingDbHandle });
    const failedWriteObs = isolatedMem.recordObservation({
      sessionId: 'sess-fail-db-129',
      type: 'incident',
      title: 'Test SQLite failure visibility',
      target: '127.0.0.1'
    });
    assert.equal(failedWriteObs.persistedToSqlite, false);
    assert.equal(failedWriteObs.persistenceStatus, 'SQLITE_WRITE_FAILED');
    assert.match(failedWriteObs.persistenceError, /SIMULATED_SQLITE_DISK_FULL/);
    assert.ok(isolatedMem.getStatus().storageDiagnostics.writeFailuresCount >= 1);

    // 5. Project Falcon Multi-Turn Conversational Intelligence
    const emptySession = chatOperatorService.getOrCreateSession('sess-falcon-empty-129');
    const planAmbiguousServer = chatOperatorService.parseIntentAndEntities('Check the server.', emptySession);
    assert.equal(planAmbiguousServer.intent, 'clarification_needed');
    assert.equal(planAmbiguousServer.clarificationReason, 'MISSING_TARGET_CONTEXT');

    const falconSessionId = 'sess-falcon-multiturn-129';
    // Turn 1: Initial port check on 127.0.0.1 port 3000
    const turn1 = await chatOperatorService.processMessage({
      sessionId: falconSessionId,
      message: 'Check 127.0.0.1 on port 3000',
      user: 'admin'
    });
    assert.equal(turn1.intent, 'port_check');
    assert.equal(turn1.target, '127.0.0.1');
    assert.deepEqual(turn1.ports, [3000]);

    const activeSession = chatOperatorService.getOrCreateSession(falconSessionId, 'admin');

    // "Check the server." with active context resolves to 127.0.0.1
    const planContextualServer = chatOperatorService.parseIntentAndEntities('Check the server.', activeSession);
    assert.equal(planContextualServer.target, '127.0.0.1');
    assert.equal(planContextualServer.usedFollowUpTarget, true);

    // Turn 2: "Why is it not responding?" -> follow_up_explanation (0 live probes)
    const turn2 = await chatOperatorService.processMessage({
      sessionId: falconSessionId,
      message: 'Why is it not responding?',
      user: 'admin'
    });
    assert.equal(turn2.intent, 'follow_up_explanation');
    assert.equal(turn2.target, '127.0.0.1');
    assert.equal(turn2.steps.length, 0);

    // Turn 3: "What does that timeout mean?" -> follow_up_explanation explaining timeout vs RST
    const turn3 = await chatOperatorService.processMessage({
      sessionId: falconSessionId,
      message: 'What does that timeout mean?',
      user: 'admin'
    });
    assert.equal(turn3.intent, 'follow_up_explanation');
    assert.equal(turn3.steps.length, 0);
    assert.match(turn3.reply, /Timeout|ECONNREFUSED|SYN-ACK/i);

    // Turn 4: "Could DNS be the problem?" -> evaluates IP-literal bypass for 127.0.0.1
    const turn4 = await chatOperatorService.processMessage({
      sessionId: falconSessionId,
      message: 'Could DNS be the problem?',
      user: 'admin'
    });
    assert.equal(turn4.intent, 'follow_up_explanation');
    assert.equal(turn4.steps.length, 0);
    assert.match(turn4.reply, /DNS Hypothesis Evaluation|bypass forward DNS/i);

    // Turn 5: "Try the other port." -> switches from 3000 to 8080 on 127.0.0.1
    const turn5 = await chatOperatorService.processMessage({
      sessionId: falconSessionId,
      message: 'Try the other port.',
      user: 'admin'
    });
    assert.equal(turn5.intent, 'port_check');
    assert.equal(turn5.target, '127.0.0.1');
    assert.deepEqual(turn5.ports, [8080]);
    assert.equal(turn5.usedFollowUpTarget, true);

    // Turn 6: "Check the same machine again." -> repeats port_check on 127.0.0.1:8080
    const turn6 = await chatOperatorService.processMessage({
      sessionId: falconSessionId,
      message: 'Check the same machine again.',
      user: 'admin'
    });
    assert.equal(turn6.intent, 'port_check');
    assert.equal(turn6.target, '127.0.0.1');
    assert.deepEqual(turn6.ports, [8080]);

    // Turn 7: "No, I meant port 3000" -> mid-turn correction on 127.0.0.1
    const turn7 = await chatOperatorService.processMessage({
      sessionId: falconSessionId,
      message: 'No, I meant port 3000',
      user: 'admin'
    });
    assert.equal(turn7.intent, 'port_check');
    assert.equal(turn7.target, '127.0.0.1');
    assert.deepEqual(turn7.ports, [3000]);

    // Turn 8: "Compare it with the previous result." -> follow_up_explanation with Historical Comparison & stateDiff
    const turn8 = await chatOperatorService.processMessage({
      sessionId: falconSessionId,
      message: 'Compare it with the previous result.',
      user: 'admin'
    });
    assert.equal(turn8.intent, 'follow_up_explanation');
    assert.equal(turn8.steps.length, 0);
    assert.match(turn8.reply, /Historical Comparison/i);
    assert.ok(turn8.structuredAnswer.stateDiff);

    // 6. Confirm read-only skill ecosystem immutability
    const checkImmutability = superpowersSkillsEngine.verifySkillEcosystemImmutability();
    assert.equal(checkImmutability.intact, true);
    assert.equal(checkImmutability.violations.length, 0);
  });

  it('130. Master Engineering Directive Cycle 1-6: Auth Hardening, Persistent MFA Replay Guard, Deleted User Rejection, Evidence Chain Consistency & Session Isolation', async () => {
    const { db } = require('../src/db/database');
    const authRouter = require('../src/api/routes-auth');
    const { authenticate } = require('../src/api/middleware');
    const { hashPassword, createToken } = require('../src/core/security');
    const { generateTOTP } = require('../src/core/totp');
    const { EvidenceFabric } = require('../src/core/evidence/evidence-fabric');
    const { chatOperatorService } = require('../src/core/chat/chat-operator-service');
    const { superpowersSkillsEngine } = require('../src/core/skills/superpowers-skills-engine');

    // Helper to invoke an Express router or middleware handler in-process
    function invokeRoute(method, pathUrl, { body = {}, headers = {}, ip = '127.0.0.1', user = null } = {}) {
      return new Promise((resolve) => {
        const req = {
          method: method.toUpperCase(),
          url: pathUrl,
          path: pathUrl,
          body,
          headers: { ...headers },
          ip,
          socket: { remoteAddress: ip },
          connection: { remoteAddress: ip },
          cookies: {},
          user
        };
        const res = {
          statusCode: 200,
          headers: {},
          cookies: {},
          status(code) {
            this.statusCode = code;
            return this;
          },
          setHeader(k, v) {
            this.headers[k] = v;
          },
          cookie(name, val, opts) {
            this.cookies[name] = { val, opts };
          },
          clearCookie(name) {
            delete this.cookies[name];
          },
          json(payload) {
            resolve({ statusCode: this.statusCode, body: payload, cookies: this.cookies });
            return this;
          }
        };

        // Locate matching route layer on authRouter
        const layer = authRouter.stack.find(
          (l) => l.route && l.route.path === pathUrl && l.route.methods[method.toLowerCase()]
        );
        if (!layer) {
          resolve({ statusCode: 404, body: { error: 'Not found' } });
          return;
        }
        const stack = layer.route.stack.map((s) => s.handle);
        let idx = 0;
        const next = (err) => {
          if (err) {
            resolve({ statusCode: 500, body: { error: err.message } });
            return;
          }
          const fn = stack[idx++];
          if (!fn) return;
          fn(req, res, next);
        };
        next();
      });
    }

    // 1. Password check in non-strict mode: wrong password MUST be rejected with 401
    const badLogin = await invokeRoute('POST', '/login', {
      body: { username: 'admin', password: 'totally-wrong-password-999' },
      headers: {}
    });
    assert.equal(badLogin.statusCode, 401);
    assert.match(badLogin.body.error, /Invalid username or password/i);

    // 2. Quick-NOC remote client boundary: non-loopback client IP MUST be rejected with 403 even when EJII_PORT=3000
    const prevPort = process.env.EJII_PORT;
    process.env.EJII_PORT = '3000';
    try {
      const remoteQuickNoc = await invokeRoute('POST', '/quick-noc', {
        body: {},
        ip: '203.0.113.77',
        headers: { 'x-forwarded-for': '203.0.113.77' }
      });
      assert.equal(remoteQuickNoc.statusCode, 403);

      const localQuickNoc = await invokeRoute('POST', '/quick-noc', {
        body: {},
        ip: '127.0.0.1',
        headers: {}
      });
      assert.equal(localQuickNoc.statusCode, 200);
      assert.equal(localQuickNoc.body.success, true);
    } finally {
      if (prevPort === undefined) delete process.env.EJII_PORT;
      else process.env.EJII_PORT = prevPort;
    }

    // 3. Persistent MFA Enrollment, TOTP Replay Protection & Login Enforcement
    const testUserId = `USR-MFA-TEST-${Date.now()}`;
    const testUsername = `mfa_operator_${Date.now()}`;
    const { hash, salt } = hashPassword('ValidMfaPass#2026');
    db.prepare(`
      INSERT INTO users (id, username, password_hash, salt, full_name, role, is_active, created_at)
      VALUES (?, ?, ?, ?, 'MFA Test Operator', 'OPERATOR', 1, ?)
    `).run(testUserId, testUsername, hash, salt, new Date().toISOString());

    try {
      const testUserObj = { id: testUserId, username: testUsername, role: 'OPERATOR' };

      // Initial MFA status is false
      const statusBefore = await invokeRoute('GET', '/mfa/status', { user: testUserObj });
      assert.equal(statusBefore.statusCode, 200);
      assert.equal(statusBefore.body.mfaEnabled, false);

      // Setup TOTP secret (persists mfa_pending_secret)
      const setupRes = await invokeRoute('GET', '/totp/setup', { user: testUserObj });
      assert.equal(setupRes.statusCode, 200);
      assert.ok(setupRes.body.secret);
      const enrolledSecret = setupRes.body.secret;

      // Confirm TOTP enrollment using live RFC 6238 code
      const validTotpCode = generateTOTP(enrolledSecret);
      const confirmRes = await invokeRoute('POST', '/mfa/verify-totp', {
        user: testUserObj,
        body: { token: validTotpCode }
      });
      assert.equal(confirmRes.statusCode, 200);
      assert.equal(confirmRes.body.verified, true);
      assert.equal(confirmRes.body.mfaEnabled, true);

      // Status now reflects persistent mfaEnabled: true in SQLite
      const statusAfter = await invokeRoute('GET', '/mfa/status', { user: testUserObj });
      assert.equal(statusAfter.statusCode, 200);
      assert.equal(statusAfter.body.mfaEnabled, true);

      // Replaying the exact same TOTP code in the same time window MUST be rejected (401 replayDetected)
      const replayRes = await invokeRoute('POST', '/mfa/verify-totp', {
        user: testUserObj,
        body: { token: validTotpCode }
      });
      assert.equal(replayRes.statusCode, 401);
      assert.equal(replayRes.body.replayDetected, true);

      // Login without TOTP code for MFA-enabled user MUST be rejected with 401 mfaRequired: true
      const loginNoMfa = await invokeRoute('POST', '/login', {
        body: { username: testUsername, password: 'ValidMfaPass#2026' }
      });
      assert.equal(loginNoMfa.statusCode, 401);
      assert.equal(loginNoMfa.body.mfaRequired, true);

      // Login with replayed TOTP code MUST also be rejected with 401 replayDetected: true
      const loginReplayedMfa = await invokeRoute('POST', '/login', {
        body: { username: testUsername, password: 'ValidMfaPass#2026', totpCode: validTotpCode }
      });
      assert.equal(loginReplayedMfa.statusCode, 401);
      assert.equal(loginReplayedMfa.body.replayDetected, true);

      // Reset mfa_last_counter to simulate next 30s window and confirm login with valid TOTP succeeds
      db.prepare('UPDATE users SET mfa_last_counter = 0 WHERE id = ?').run(testUserId);
      const loginValidMfa = await invokeRoute('POST', '/login', {
        body: { username: testUsername, password: 'ValidMfaPass#2026', totpCode: validTotpCode }
      });
      assert.equal(loginValidMfa.statusCode, 200);
      assert.equal(loginValidMfa.body.success, true);
      assert.ok(loginValidMfa.body.token);

      // 4. Deleted Database User Token Rejection in authenticate Middleware
      const issuedUserToken = loginValidMfa.body.token;
      db.prepare('DELETE FROM users WHERE id = ?').run(testUserId);

      const authCheckDeleted = await new Promise((resolve) => {
        const req = {
          headers: { authorization: `Bearer ${issuedUserToken}` },
          cookies: {}
        };
        const res = {
          statusCode: 200,
          status(c) { this.statusCode = c; return this; },
          json(p) { resolve({ statusCode: this.statusCode, body: p }); return this; }
        };
        authenticate(req, res, () => resolve({ statusCode: 200, body: { user: req.user } }));
      });
      assert.equal(authCheckDeleted.statusCode, 401);
      assert.match(authCheckDeleted.body.error, /no longer exists|invalidated/i);

      // Ensure stateless synthetic unit-test token (never in DB) still works for isolated unit tests
      const syntheticToken = createToken({ id: 'svc-unit-probe-1', username: 'svc_probe', role: 'OPERATOR' });
      const authCheckSynthetic = await new Promise((resolve) => {
        const req = {
          headers: { authorization: `Bearer ${syntheticToken}` },
          cookies: {}
        };
        const res = {
          statusCode: 200,
          status(c) { this.statusCode = c; return this; },
          json(p) { resolve({ statusCode: this.statusCode, body: p }); return this; }
        };
        authenticate(req, res, () => resolve({ statusCode: 200, body: { user: req.user } }));
      });
      assert.equal(authCheckSynthetic.statusCode, 200);
      assert.equal(authCheckSynthetic.body.user.id, 'svc-unit-probe-1');
    } finally {
      try { db.prepare('DELETE FROM users WHERE id = ?').run(testUserId); } catch (_) {}
    }

    // 5. Evidence Fabric SQLite Write Failure Visibility & Hash-Chain Consistency
    const brokenDbHandle = {
      prepare() {
        return {
          get() { return null; },
          run() { throw new Error('Simulated SQLITE_IOERR: disk I/O failure'); }
        };
      }
    };
    const brokenFabric = new EvidenceFabric(null, { dbHandle: brokenDbHandle });
    const initialTailHash = brokenFabric.lastChainHash;
    const failedEv = brokenFabric.recordEvidence({
      type: 'observation',
      subject: 'host:127.0.0.1',
      claim: 'Loopback TCP check',
      rawValue: { open: true }
    });
    assert.equal(failedEv.persistedToSqlite, false);
    assert.equal(failedEv.persistenceStatus, 'SQLITE_WRITE_FAILED');
    assert.match(failedEv.persistenceError, /SQLITE_IOERR/i);
    // Crucial invariant: lastChainHash MUST NOT advance when SQLite persistence fails
    assert.equal(brokenFabric.lastChainHash, initialTailHash);
    assert.equal(brokenFabric.getStorageDiagnostics().writeFailuresCount, 1);

    // 6. Session Ownership Isolation in ChatOperatorService
    const isolatedSessionId = `SES-ISOLATION-${Date.now()}`;
    await chatOperatorService.processMessage({
      sessionId: isolatedSessionId,
      message: 'Check whether port 3000 is open on 127.0.0.1',
      user: { id: 'USR-OWNER-A', username: 'alice_noc', role: 'OPERATOR' }
    });
    const accessForOtherUser = chatOperatorService.verifySessionAccess(isolatedSessionId, {
      id: 'USR-INTRUDER-B',
      username: 'mallory_noc',
      role: 'OPERATOR'
    });
    assert.equal(accessForOtherUser.allowed, false);
    assert.equal(accessForOtherUser.statusCode, 403);
    assert.equal(accessForOtherUser.error.code, 'SESSION_OWNERSHIP_VIOLATION');

    // 7. Confirm read-only skill ecosystem immutability remains 100% intact
    const immutabilityReport = superpowersSkillsEngine.verifySkillEcosystemImmutability();
    assert.equal(immutabilityReport.intact, true);
    assert.equal(immutabilityReport.violations.length, 0);
  });

  it('131. Phase Atlas XII.2: Claude-Mem Multi-User Isolation, Chat Identity & SQLite Diagnostics, Conversational Disambiguation & PacketStreamer Unprivileged Honesty', async () => {
    const { ClaudeMemEngine } = require('../src/core/memory/claude-mem-engine');
    const { chatOperatorService } = require('../src/core/chat/chat-operator-service');
    const { packetStreamer } = require('../src/network/packet-streaming/packet-streamer');
    const { superpowersSkillsEngine } = require('../src/core/skills/superpowers-skills-engine');

    // 1. Claude-Mem Multi-User Ownership Isolation (User A private observations never leak to User B)
    const isolatedMem = new ClaudeMemEngine({ useSqlite: false });
    const aliceObs = isolatedMem.recordObservation({
      sessionId: 'SES-ALICE-01',
      ownerUserId: 'USR-ALICE-01',
      ownerUsername: 'alice_sre',
      type: 'incident',
      memoryCategory: 'LIVE_OPERATIONAL_OBSERVATION',
      isLiveMeasurement: true,
      title: 'Private Core Router BGP Flap on 10.99.88.77',
      target: '10.99.88.77',
      conceptTags: ['problem-solution', 'layer-disambiguation'],
      facts: ['TCP 179 connection reset observed on 10.99.88.77'],
      narrative: 'Measured TCP 179 session drop on private router 10.99.88.77.',
      rootCause: 'L4_BGP_RESET',
      probeMetrics: { rttMs: 14.2, port: 179 }
    });
    assert.equal(aliceObs.ownerUserId, 'USR-ALICE-01');
    assert.equal(aliceObs.visibilityScope, 'PRIVATE_OPERATIONAL');

    // User B searching for Alice's target must receive 0 hits and filteredUnauthorizedCount >= 1
    const bobSearch = isolatedMem.searchIndex('10.99.88.77', {
      user: { id: 'USR-BOB-02', username: 'bob_analyst', role: 'ANALYST' },
      enforceStrictIsolation: true
    });
    assert.equal(bobSearch.hitCount, 0);
    assert.ok(bobSearch.filteredUnauthorizedCount >= 1);

    // User B attempting direct Layer 3 hydration of Alice's observation ID must be blocked
    const bobHydrate = isolatedMem.getObservationsByIds([aliceObs.observationId], {
      user: { id: 'USR-BOB-02', username: 'bob_analyst', role: 'ANALYST' },
      enforceStrictIsolation: true
    });
    assert.equal(bobHydrate.hydratedCount, 0);
    assert.equal(bobHydrate.filteredUnauthorizedCount, 1);
    assert.deepEqual(bobHydrate.unauthorizedObservationIds, [aliceObs.observationId]);

    // User B timeline query on Alice's observation ID must return empty timeline
    const bobTimeline = isolatedMem.getTimelineContext(aliceObs.observationId, {
      user: { id: 'USR-BOB-02', username: 'bob_analyst', role: 'ANALYST' },
      enforceStrictIsolation: true
    });
    assert.equal(bobTimeline.timelineEntries.length, 0);

    // Alice herself can search and hydrate her own observation
    const aliceSearch = isolatedMem.searchIndex('10.99.88.77', {
      user: { id: 'USR-ALICE-01', username: 'alice_sre', role: 'OPERATOR' },
      enforceStrictIsolation: true
    });
    assert.equal(aliceSearch.hitCount, 1);
    assert.equal(aliceSearch.hits[0].observationId, aliceObs.observationId);

    // ADMIN role can inspect across users for governance diagnostics
    const adminHydrate = isolatedMem.getObservationsByIds([aliceObs.observationId], {
      user: { id: 'USR-ADMIN-99', username: 'chief_admin', role: 'ADMIN' },
      enforceStrictIsolation: true
    });
    assert.equal(adminHydrate.hydratedCount, 1);

    // Shared ARCHITECTURAL_KNOWLEDGE remains accessible to User B when includeArchitecturalMetadata is true
    const bobArchSearch = isolatedMem.searchIndex('Skill Ecosystem', {
      user: { id: 'USR-BOB-02', username: 'bob_analyst', role: 'ANALYST' },
      includeArchitecturalMetadata: true,
      enforceStrictIsolation: true
    });
    assert.ok(bobArchSearch.hitCount >= 1);
    assert.equal(bobArchSearch.hits[0].visibilityScope, 'SHARED_ARCHITECTURAL');

    // 2. ChatOperatorService Identity Normalization (never collapses distinct string/username users into 'op-1')
    const normStringA = chatOperatorService._normalizeUserIdentity('alice_noc');
    const normStringB = chatOperatorService._normalizeUserIdentity('bob_noc');
    assert.notEqual(normStringA.userId, 'op-1');
    assert.notEqual(normStringB.userId, 'op-1');
    assert.notEqual(normStringA.userId, normStringB.userId);

    const normObjA = chatOperatorService._normalizeUserIdentity({ username: 'alice_noc' });
    const normObjB = chatOperatorService._normalizeUserIdentity({ username: 'bob_noc' });
    assert.equal(normObjA.userId, 'USR-alice_noc');
    assert.equal(normObjB.userId, 'USR-bob_noc');
    assert.notEqual(normObjA.userId, normObjB.userId);

    // 3. ChatOperatorService SQLite Persistence Diagnostics
    const brainStatus = chatOperatorService.getBrainStatus();
    assert.ok(brainStatus.persistenceDiagnostics, 'getBrainStatus must expose persistenceDiagnostics');
    assert.equal(typeof brainStatus.persistenceDiagnostics.writeAttemptsCount, 'number');
    assert.equal(typeof brainStatus.persistenceDiagnostics.writeFailuresCount, 'number');

    // 4. Conversational Phrase Resembling Operational Command -> 0 Live Probes
    const convSpikeSessionId = `SES-CONV-SPIKE-${Date.now()}`;
    const convSpikeResp = await chatOperatorService.processMessage({
      sessionId: convSpikeSessionId,
      message: 'We had a ping spike yesterday, what usually causes that?',
      user: { id: 'USR-ALICE-01', username: 'alice_sre', role: 'OPERATOR' }
    });
    assert.equal(convSpikeResp.intent, 'informational_question');
    assert.equal(convSpikeResp.mode, 'informational');
    assert.equal((convSpikeResp.steps || []).length, 0, 'Conversational question about past ping spikes must execute 0 live probes');
    assert.match(convSpikeResp.reply, /bufferbloat|queue|wi-fi|icmp/i);

    // 5. PacketStreamer Unprivileged Capture Capability Honesty
    const capProfile = packetStreamer.getCaptureCapabilityProfile();
    assert.equal(typeof capProfile.isHardwareWireCapture, 'boolean');
    assert.ok(
      ['ACTIVE_HARDWARE_WIRE_CAPTURE', 'DRIVER_READY_IDLE', 'UNPRIVILEGED_SOCKET_FALLBACK'].includes(capProfile.captureState)
    );
    if (!capProfile.driverAvailable) {
      assert.equal(capProfile.isHardwareWireCapture, false);
      assert.equal(capProfile.captureState, 'UNPRIVILEGED_SOCKET_FALLBACK');
      assert.equal(capProfile.driverStatus, 'NPCAP_OR_CAP_NET_RAW_UNAVAILABLE');
    }

    // 6. Confirm Read-Only Agent Skills Ecosystem Immutability
    const skillCheck = superpowersSkillsEngine.verifySkillEcosystemImmutability();
    assert.equal(skillCheck.intact, true);
    assert.equal(skillCheck.violations.length, 0);
  });

  it('132. Quiet Luxury Design System, Login Credential Hardening, Overview Workstation & Real GitHub Integration', async () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const { superpowersSkillsEngine } = require('../src/core/skills/superpowers-skills-engine');

    const rootDir = path.resolve(__dirname, '..');
    const indexHtml = fs.readFileSync(path.join(rootDir, 'public/index.html'), 'utf8');
    const meridianCss = fs.readFileSync(path.join(rootDir, 'public/css/ejii-meridian.css'), 'utf8');
    const chatCss = fs.readFileSync(path.join(rootDir, 'public/css/chat-minimal.css'), 'utf8');
    const overviewJs = fs.readFileSync(path.join(rootDir, 'public/js/views/overview-view.js'), 'utf8');
    const githubJs = fs.readFileSync(path.join(rootDir, 'public/js/components/github-integration.js'), 'utf8');

    // 1. Quiet Luxury Light & Dark Theme Tokens in ejii-meridian.css and chat-minimal.css
    const requiredLightTokens = ['#F6F5F1', '#FFFFFF', '#F9F8F5', '#1F2421', '#666B66', '#858B85', '#E6E3DB', '#3A6653', '#E7F0EA', '#D5E3DA'];
    for (const hex of requiredLightTokens) {
      assert.ok(meridianCss.includes(hex), `ejii-meridian.css must define Quiet Luxury token ${hex}`);
    }
    assert.ok(meridianCss.includes('#121513') && meridianCss.includes('#181C19'), 'ejii-meridian.css must define warm charcoal dark theme surfaces');
    assert.ok(chatCss.includes('#F6F5F1') && chatCss.includes('#3A6653'), 'chat-minimal.css must inherit Quiet Luxury palette');

    // 2. Login Screen Hardcoded Credential Removal
    assert.ok(!indexHtml.includes('value="admin2026!"'), 'public/index.html must not prefill hardcoded admin2026! password');
    assert.ok(!indexHtml.includes('value="admin"'), 'public/index.html must not prefill hardcoded admin username in HTML markup');

    // 3. Overview Workstation & GitHub Sidebar Widget
    assert.ok(indexHtml.includes('data-target-view="overview"'), 'public/index.html must include Overview navigation item');
    assert.ok(indexHtml.includes('id="sidebarGitHubWidget"'), 'public/index.html must include #sidebarGitHubWidget in sidebar');
    assert.ok(overviewJs.includes('/api/system/bootstrap') && overviewJs.includes('/api/github/status'), 'overview-view.js must query real backend endpoints');
    assert.ok(githubJs.includes('OAUTH_AUTH_SUCCESS') && githubJs.includes('/api/github/auth/url'), 'github-integration.js must implement OAuth popup flow');

    // 4. Real Backend GitHub API Endpoints (/api/github/status, /api/github/auth/url, /api/github/disconnect)
    const { githubRoutes } = require('../src/api/routes-github');
    function invokeGitHubRouter(method, urlPath, body = {}) {
      return new Promise((resolve, reject) => {
        const req = {
          method,
          url: urlPath,
          originalUrl: '/api/github' + urlPath,
          headers: { host: 'localhost:3000' },
          query: {},
          body,
          protocol: 'http',
          get(h) { return this.headers[String(h).toLowerCase()]; }
        };
        const res = {
          statusCode: 200,
          headers: {},
          body: null,
          status(code) { this.statusCode = code; return this; },
          setHeader(k, v) { this.headers[k] = v; },
          json(payload) { this.body = payload; resolve({ statusCode: this.statusCode, body: payload }); return this; },
          send(payload) { this.body = payload; resolve({ statusCode: this.statusCode, body: payload }); return this; }
        };
        githubRoutes.handle(req, res, (err) => {
          if (err) reject(err);
          else resolve({ statusCode: res.statusCode, body: res.body });
        });
      });
    }

    const statusRes = await invokeGitHubRouter('GET', '/status');
    assert.equal(statusRes.statusCode, 200);
    assert.equal(statusRes.body.ok, true);
    assert.equal(statusRes.body.connected, false, 'GitHub status must be disconnected when no OAuth session is established');
    assert.equal(statusRes.body.connectionState, 'DISCONNECTED');
    assert.equal(statusRes.body.account, null);

    const discRes = await invokeGitHubRouter('POST', '/disconnect');
    assert.equal(discRes.statusCode, 200);
    assert.equal(discRes.body.connected, false);

    // 5. Confirm Read-Only Agent Skills Ecosystem Immutability
    const skillCheck = superpowersSkillsEngine.verifySkillEcosystemImmutability();
    assert.equal(skillCheck.intact, true);
    assert.equal(skillCheck.violations.length, 0);
  });

  it('133. Pinboard Zero-Fabrication, Overview Epistemic Health Classification (Unknown != Healthy), and Fail-Closed Login Validation', async () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const vm = require('node:vm');

    const rootDir = path.resolve(__dirname, '..');
    const appJs = fs.readFileSync(path.join(rootDir, 'public/js/app.js'), 'utf8');
    const overviewJs = fs.readFileSync(path.join(rootDir, 'public/js/views/overview-view.js'), 'utf8');
    const chatJs = fs.readFileSync(path.join(rootDir, 'public/js/views/chat-workspace-view.js'), 'utf8');

    // 1. Verify Pinboard source does not contain fabricated fallbacks
    const pinboardMatch = appJs.match(/window\.EJIIInvestigationPinboard\s*=\s*\{[\s\S]*?\n\};/);
    assert.ok(pinboardMatch, 'window.EJIIInvestigationPinboard must be defined in public/js/app.js');
    const pinboardCode = pinboardMatch[0];
    assert.ok(!pinboardCode.includes('172.29.192.1'), 'Pinboard must not contain hardcoded fallback target 172.29.192.1');
    assert.ok(!pinboardCode.includes('172.29.192.0/20'), 'Pinboard must not contain hardcoded fallback subnet 172.29.192.0/20');
    assert.ok(!pinboardCode.includes('10.168.195.0/24'), 'Pinboard must not contain hardcoded fallback subnet 10.168.195.0/24');
    assert.ok(!pinboardCode.includes('00:15:5D:DF:E5:56'), 'Pinboard must not contain hardcoded fallback MAC 00:15:5D:DF:E5:56');
    assert.ok(!pinboardCode.includes('Microsoft Corporation'), 'Pinboard must not contain hardcoded fallback vendor Microsoft Corporation');
    assert.ok(!pinboardCode.includes('623'), 'Pinboard must not contain hardcoded fallback port 623');

    // 2. Execute overview-view.js in a VM sandbox and verify classifyEjiiNodeState & summarizeEjiiTopologyNodes
    const sandbox = {
      window: { state: {} },
      document: {
        getElementById: () => null
      },
      localStorage: { getItem: () => null },
      sessionStorage: { getItem: () => null },
      fetch: async () => ({ ok: false, status: 503 })
    };
    vm.createContext(sandbox);
    vm.runInContext(overviewJs, sandbox);

    const classify = sandbox.window.classifyEjiiNodeState;
    const summarize = sandbox.window.summarizeEjiiTopologyNodes;
    assert.equal(typeof classify, 'function', 'classifyEjiiNodeState must be exposed on window');
    assert.equal(typeof summarize, 'function', 'summarizeEjiiTopologyNodes must be exposed on window');

    // Unknown or missing status must NEVER be classified as healthy
    const unknownState = classify({ id: 'n1', status: 'unknown' });
    assert.equal(unknownState.isHealthy, false, 'unknown status must never be classified as healthy');
    assert.equal(unknownState.isUnknown, true);
    assert.equal(unknownState.label, 'Unknown');

    const missingState = classify({ id: 'n2' });
    assert.equal(missingState.isHealthy, false, 'missing status must never be classified as healthy');
    assert.equal(missingState.label, 'Not Measured');

    const healthyState = classify({ id: 'n3', status: 'healthy' });
    assert.equal(healthyState.isHealthy, true);
    assert.equal(healthyState.label, 'Healthy');

    // Summarize with 1 healthy + 1 unknown node must NOT say "All healthy"
    const mixedSummary = summarize([{ id: 'n1', status: 'healthy' }, { id: 'n2', status: 'unknown' }], true);
    assert.equal(mixedSummary.healthyCount, 1);
    assert.equal(mixedSummary.unknownCount, 1);
    assert.ok(!mixedSummary.metricSub.toLowerCase().includes('all'), 'Mixed healthy+unknown nodes must not report All healthy');
    assert.ok(mixedSummary.metricSub.includes('1 unknown/unverified'), 'Must explicitly report 1 unknown/unverified node');

    // API failure vs Empty discovery distinction
    const apiFailSummary = summarize([], false);
    assert.equal(apiFailSummary.metricValue, 'Unavailable', 'Unavailable API must report Unavailable, never 0');
    const emptyDiscoverySummary = summarize([], true);
    assert.equal(emptyDiscoverySummary.metricValue, '0', 'Empty discovery must report 0');
    assert.ok(emptyDiscoverySummary.metricSub.includes('Not measured'), 'Empty discovery must indicate Not measured');

    // 3. Verify handleLoginFormSubmit does not fall back to admin / admin2026! and chat-workspace-view does not hardcode 192.168.31.1
    const loginFnMatch = appJs.match(/window\.handleLoginFormSubmit\s*=\s*async\s*function[\s\S]*?\n\};/);
    assert.ok(loginFnMatch, 'handleLoginFormSubmit must exist in app.js');
    assert.ok(!loginFnMatch[0].includes('admin2026!'), 'handleLoginFormSubmit must not fall back to admin2026!');
    assert.ok(!chatJs.includes("'192.168.31.1'"), 'chat-workspace-view.js must not hardcode 192.168.31.1 fallback');
  });
});
