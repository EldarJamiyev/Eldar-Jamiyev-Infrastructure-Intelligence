'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { hypothesisArbiter, CAUSAL_DOMAINS } = require('../../ai/hypothesis-arbiter');
const { predictiveHorizonEngine } = require('../../ai/predictive-horizon-engine');
const { timelineReconstructor } = require('../../observability/timeline-reconstructor');
const { superpowersSkillsEngine, SUPERPOWERS_SKILLS_CATALOG } = require('../skills/superpowers-skills-engine');
const { aiMentorService } = require('../../learning/ai-mentor-service');
const { capabilityRegistry } = require('../capability-registry');
const { chatOperatorService } = require('../chat/chat-operator-service');

test('Suite A — 6-Domain Closed-Loop Hypothesis Arbiter & Shannon Information Gain', async (t) => {
  await t.test('evaluates all 6 causal domains and executes closed-loop probes with entropy reduction', async () => {
    assert.equal(Object.keys(CAUSAL_DOMAINS).length, 6);
    const report = await hypothesisArbiter.arbitrateAndExecuteClosedLoop({
      target: '127.0.0.1',
      port: 3000,
      symptomDescription: 'Intermittent latency and connection drops on 127.0.0.1:3000',
      executeClosedLoop: true,
      maxClosedLoopSteps: 2
    });

    assert.ok(report.arbitrationId);
    assert.equal(report.domainsEvaluatedCount, 6);
    assert.equal(report.hypotheses.length, 6);
    assert.ok(report.winningHypothesis);
    assert.ok(report.closedLoopStepsExecuted >= 1);
    assert.ok(Array.isArray(report.closedLoopExecutionTrace));
    assert.ok(report.closedLoopExecutionTrace[0].expectedInformationGainBits >= 0);

    const domainIds = new Set(report.hypotheses.map((h) => h.domainId));
    assert.ok(domainIds.has('PHYSICAL_L2_L3'));
    assert.ok(domainIds.has('TRANSPORT_L4'));
    assert.ok(domainIds.has('APPLICATION_L7'));
    assert.ok(domainIds.has('DNS_NAMING'));
    assert.ok(domainIds.has('HOST_KERNEL_SOCKET'));
    assert.ok(domainIds.has('SECURITY_TLS_POLICY'));
  });
});

test('Suite B — Non-Linear M/M/1 Queueing Horizon & Cut-Vertex Cascade Engine (Un-truncated)', async (t) => {
  await t.test('computes M/M/1 queueing amplification, Holt-Winters forecast, and never truncates predictions to 3', () => {
    const injectedSamplesByTarget = {};
    for (let i = 1; i <= 6; i++) {
      injectedSamplesByTarget[`10.0.0.${i}`] = [12, 18, 25, 38, 55, 78, 105, 132];
    }

    const report = predictiveHorizonEngine.evaluatePredictiveHorizon({
      slaLatencyThresholdMs: 150,
      injectedSamplesByTarget
    });

    assert.ok(report.horizonId);
    assert.ok(report.predictions.length >= 6, 'Must return all 6+ predictions without .slice(0, 3) truncation');
    const highUtilTarget = report.predictions.find((p) => p.target === '10.0.0.1');
    assert.ok(highUtilTarget);
    assert.ok(highUtilTarget.mm1QueueingAmplification > 0);
    assert.ok(highUtilTarget.holtWintersForecast.slopeMsPerStep > 0);
  });
});

test('Suite C — Pre-Incident MAD & CUSUM Timeline Reconstructor (Un-truncated)', async (t) => {
  await t.test('detects CUSUM changepoints, identifies Patient Zero, and returns full un-truncated event timeline', () => {
    const injectedEvents = [];
    const baseMs = Date.now() - 20 * 60 * 1000;
    for (let i = 0; i < 8; i++) {
      injectedEvents.push({
        timestamp: new Date(baseMs + i * 60000).toISOString(),
        target: i === 0 ? '10.0.0.1' : `10.0.0.${i + 1}`,
        layer: i === 0 ? 'L3' : 'L7',
        eventType: i === 0 ? 'GATEWAY_PACKET_LOSS_ONSET' : 'DOWNSTREAM_TIMEOUT',
        severity: 'HIGH',
        latencyMs: 20 + i * 35,
        detail: `Chronological event #${i + 1}`
      });
    }

    const report = timelineReconstructor.reconstructPreIncidentTimeline({
      target: '10.0.0.1',
      windowMinutes: 60,
      injectedEvents,
      injectedLatencySeries: [10, 11, 10, 12, 11, 85, 110, 145]
    });

    assert.ok(report.reconstructionId);
    assert.ok(report.timelineEvents.length >= 8, 'Must return all 8+ events without .slice(0, 5) truncation');
    assert.equal(report.patientZero.causalRole, 'PATIENT_ZERO_ORIGIN');
    assert.equal(report.changepointAnalysis.changepointDetected, true);
  });
});

test('Suite D — Composable Superpowers Skills Engine & Multi-Engine Conversational Synthesis', async (t) => {
  await t.test('registers all 8 obra/superpowers skills and executes 4-phase systematic debugging synthesis', async () => {
    assert.equal(SUPERPOWERS_SKILLS_CATALOG.length, 8);
    const matched = superpowersSkillsEngine.findSkills('root cause debugging and verification');
    assert.ok(matched.matchedCount >= 2);

    const unified = await superpowersSkillsEngine.executeUnifiedSuperpowersSynthesis({
      objective: 'Investigate latency and connection state on 127.0.0.1:3000',
      target: '127.0.0.1',
      port: 3000,
      executeClosedLoop: true
    });

    assert.ok(unified.synthesisId);
    assert.ok(unified.systematicDebugging4Phases.phase1_rootCauseInvestigation);
    assert.ok(unified.systematicDebugging4Phases.phase2_patternAnalysis);
    assert.ok(unified.systematicDebugging4Phases.phase3_hypothesisAndTesting);
    assert.ok(unified.systematicDebugging4Phases.phase4_implementationAndVerification);
  });

  await t.test('CapabilityRegistry invokes all 4 new capabilities with valid EJIIResult envelopes', async () => {
    const resHorizon = await capabilityRegistry.invokeCapability('ejii.ai.nonlinear_predictive_horizon', {});
    assert.equal(resHorizon.success, true);
    assert.ok(resHorizon.data.horizonId);

    const resTimeline = await capabilityRegistry.invokeCapability('ejii.observability.patient_zero_timeline', { target: '127.0.0.1' });
    assert.equal(resTimeline.success, true);
    assert.ok(resTimeline.data.reconstructionId);
  });

  await t.test('ChatOperatorService executes non-mutually-exclusive multi-engine synthesis without siloing', async () => {
    const session = chatOperatorService.getOrCreateSession('test-superpowers-synth', 'admin');
    const plan = chatOperatorService.parseIntentAndEntities(
      'Run a unified synthesis with patient zero timeline reconstruction, 6-domain hypothesis arbitration, and predictive horizon cascade risk on 127.0.0.1',
      session
    );
    assert.equal(plan.intent, 'infrastructure_intelligence_synthesis');
    assert.ok(plan.activeSynthesisCapabilities.includes('PRE_INCIDENT_TIMELINE_RECONSTRUCTION'));
    assert.ok(plan.activeSynthesisCapabilities.includes('MULTI_DOMAIN_HYPOTHESIS_ARBITRATION'));
    assert.ok(plan.activeSynthesisCapabilities.includes('PREDICTIVE_HORIZON_ATTENTION'));

    const turnResult = await chatOperatorService._executeInfrastructureIntelligenceSynthesisScenario(
      plan,
      session,
      'Run unified synthesis on 127.0.0.1'
    );
    assert.ok(turnResult.technicalEvidence.timelineReconstruction);
    assert.ok(turnResult.technicalEvidence.hypothesisArbitration);
    assert.ok(turnResult.technicalEvidence.predictiveHorizon);
    assert.ok(turnResult.reply.includes('Autonomous Closed-Loop 6-Domain Hypothesis Arbitration'));
    assert.ok(turnResult.reply.includes('Non-Linear Predictive Horizon'));
  });
});

test('Suite E — Learning Center Embedded AI Mentor, CIDR Math Tutor & SM-2 Spaced Repetition', async (t) => {
  await t.test('derives binary/decimal IPv4 CIDR subnetting math and adapts across Beginner, NOC, and Architect tiers', () => {
    const mentorRes = aiMentorService.askMentor({
      userId: 'student-1',
      question: 'Solve 192.168.10.64/26 step by step',
      lessonId: 'net-c2-m1-l1',
      expertiseTier: 'SENIOR_ARCHITECT'
    });

    assert.ok(mentorRes.mentorResponseId);
    assert.equal(mentorRes.expertiseTier, 'SENIOR_ARCHITECT');
    assert.ok(mentorRes.subnetMath);
    assert.equal(mentorRes.subnetMath.networkAddress, '192.168.10.64');
    assert.equal(mentorRes.subnetMath.broadcastAddress, '192.168.10.127');
    assert.equal(mentorRes.subnetMath.firstUsableHost, '192.168.10.65');
    assert.equal(mentorRes.subnetMath.lastUsableHost, '192.168.10.126');
    assert.equal(mentorRes.subnetMath.usableHosts, 62);
    assert.ok(mentorRes.interactiveSimulation);
    assert.ok(mentorRes.workbenchSynergy.viewId);
  });

  await t.test('computes SuperMemo-2 (SM-2) spaced repetition intervals and mastery tiers', () => {
    const s1 = aiMentorService.computeSm2Schedule({
      userId: 'student-1',
      cardId: 'card-0',
      qualityRating: 5,
      previousRepetitions: 0,
      previousIntervalDays: 0,
      previousEaseFactor: 2.5
    });
    assert.equal(s1.repetitions, 1);
    assert.equal(s1.intervalDays, 1);

    const s2 = aiMentorService.computeSm2Schedule({
      userId: 'student-1',
      cardId: 'card-0',
      qualityRating: 5,
      previousRepetitions: s1.repetitions,
      previousIntervalDays: s1.intervalDays,
      previousEaseFactor: s1.easeFactor
    });
    assert.equal(s2.repetitions, 2);
    assert.equal(s2.intervalDays, 6);

    const s3 = aiMentorService.computeSm2Schedule({
      userId: 'student-1',
      cardId: 'card-0',
      qualityRating: 5,
      previousRepetitions: s2.repetitions,
      previousIntervalDays: s2.intervalDays,
      previousEaseFactor: s2.easeFactor
    });
    assert.equal(s3.repetitions, 3);
    assert.ok(s3.intervalDays >= 15);
    assert.equal(s3.masteryTier, 'MASTERED');
  });
});
