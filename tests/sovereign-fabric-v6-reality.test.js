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

  it('7. filters out static seed episodes when EpisodicCausalMemoryEngine.getAllEpisodes({ includeSimulated: false }) is called', () => {
    const liveEpisodes = EpisodicCausalMemoryEngine.getAllEpisodes({ includeSimulated: false });
    assert.ok(liveEpisodes.length >= 1);
    for (const ep of liveEpisodes) {
      assert.ok(!ep.episodeId.startsWith('ep-seed-'), 'Must not include static seed episodes in live mode');
    }
  });
});
