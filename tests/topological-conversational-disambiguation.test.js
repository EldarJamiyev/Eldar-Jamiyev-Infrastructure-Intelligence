'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  disambiguateTopologicalTarget,
  resolveTemporalScope,
  runAgenticToolLoop
} = require('../src/core/chat/conversational-brain');

test('Phase 4.0 Track 3: Multi-Tier Topological Target & Temporal Scope Disambiguation', async (t) => {
  await t.test('1. Disambiguates single distinct topological target with high confidence', () => {
    const mockGraph = {
      nodes: new Map([
        ['gw-core-01', { nodeId: 'gw-core-01', label: 'Core Gateway', resourceType: 'gateway', status: 'healthy', ipAddress: '10.0.0.1' }],
        ['db-primary-01', { nodeId: 'db-primary-01', label: 'Primary PostgreSQL', resourceType: 'service_endpoint', status: 'healthy', ipAddress: '10.0.0.50' }],
        ['sw-edge-02', { nodeId: 'sw-edge-02', label: 'Edge Switch Floor 2', resourceType: 'switch', status: 'healthy', ipAddress: '10.0.0.2' }]
      ])
    };

    const result = disambiguateTopologicalTarget('check the status on 10.0.0.50 please', { temporalGraph: mockGraph });
    assert.strictEqual(result.ambiguous, false);
    assert.strictEqual(result.matchedTarget, 'db-primary-01');
    assert.ok(result.confidence >= 0.80, `Expected confidence >= 0.80, got ${result.confidence}`);
    assert.strictEqual(result.disambiguationQuestion, null);
  });

  await t.test('2. Detects ambiguity when two topological candidates have close scores (< 0.25 delta)', () => {
    const mockGraph = {
      nodes: new Map([
        ['db-pg-cluster-01', { nodeId: 'db-pg-cluster-01', label: 'PostgreSQL Database Node 1', resourceType: 'service_endpoint', status: 'healthy' }],
        ['db-pg-cluster-02', { nodeId: 'db-pg-cluster-02', label: 'PostgreSQL Database Node 2', resourceType: 'service_endpoint', status: 'healthy' }],
        ['gw-core-01', { nodeId: 'gw-core-01', label: 'Core Gateway', resourceType: 'gateway', status: 'healthy' }]
      ])
    };

    const result = disambiguateTopologicalTarget('inspect postgresql database node cluster', { temporalGraph: mockGraph });
    assert.strictEqual(result.ambiguous, true);
    assert.ok(result.delta < 0.25, `Expected delta < 0.25, got ${result.delta}`);
    assert.ok(result.disambiguationQuestion, 'Disambiguation question must be generated');
    assert.match(result.disambiguationQuestion, /Multiple topological candidates matched/);
    assert.strictEqual(result.candidates.length >= 2, true);
  });

  await t.test('3. Health degradation status (+0.20 bias) breaks ambiguity and elevates degraded nodes', () => {
    const mockGraph = {
      nodes: new Map([
        ['db-pg-cluster-01', { nodeId: 'db-pg-cluster-01', label: 'PostgreSQL Node 1', resourceType: 'service_endpoint', status: 'healthy' }],
        ['db-pg-cluster-02', { nodeId: 'db-pg-cluster-02', label: 'PostgreSQL Node 2', resourceType: 'service_endpoint', status: 'degraded' }]
      ])
    };

    // Both match 'postgresql node', but Node 2 is degraded and gets a +0.20 score boost
    const result = disambiguateTopologicalTarget('is postgresql node down?', { temporalGraph: mockGraph });
    assert.strictEqual(result.matchedTarget, 'db-pg-cluster-02');
    const degradedCandidate = result.candidates.find((c) => c.nodeId === 'db-pg-cluster-02');
    const healthyCandidate = result.candidates.find((c) => c.nodeId === 'db-pg-cluster-01');
    assert.ok(degradedCandidate.score > healthyCandidate.score);
    assert.strictEqual(degradedCandidate.isDegraded, true);
  });

  await t.test('4. Resolves relative temporal scopes across minutes, hours, days, today, and recently', () => {
    const fixedNowMs = 1700000000000; // Fixed epoch for reproducible assertions

    const res15m = resolveTemporalScope('diagnose latency over the past 15m', { nowMs: fixedNowMs });
    assert.strictEqual(res15m.resolved, true);
    assert.strictEqual(res15m.durationSeconds, 900);
    assert.strictEqual(res15m.anchor, 'RELATIVE_WINDOW');
    assert.strictEqual(res15m.startTimeIso, new Date(fixedNowMs - 900 * 1000).toISOString());

    const res2h = resolveTemporalScope('show drops in the past 2 hours', { nowMs: fixedNowMs });
    assert.strictEqual(res2h.resolved, true);
    assert.strictEqual(res2h.durationSeconds, 7200);

    const resHour = resolveTemporalScope('what happened during the past hour?', { nowMs: fixedNowMs });
    assert.strictEqual(resHour.resolved, true);
    assert.strictEqual(resHour.durationSeconds, 3600);

    const resRecent = resolveTemporalScope('did any links fail recently?', { nowMs: fixedNowMs });
    assert.strictEqual(resRecent.resolved, true);
    assert.strictEqual(resRecent.durationSeconds, 1800);

    const resNone = resolveTemporalScope('what is the meaning of life?');
    assert.strictEqual(resNone.resolved, false);
    assert.strictEqual(resNone.durationSeconds, null);
  });

  await t.test('5. Resolves operational reboot anchor correlated against operational decisions', () => {
    const fixedNowMs = 1700000000000;
    const rebootTimeIso = new Date(fixedNowMs - (12 * 60 * 1000)).toISOString(); // 12 minutes ago

    const mockMemoryEngine = {
      listOperationalDecisions: () => [
        {
          decisionId: 'DEC-REBOOT-99',
          actionId: 'restart_service',
          rationale: 'Graceful reboot of gateway routing daemon',
          decisionType: 'REMEDIATION',
          createdAt: rebootTimeIso
        }
      ]
    };

    const resReboot = resolveTemporalScope('check packet flow after reboot', {
      nowMs: fixedNowMs,
      operationalMemoryEngine: mockMemoryEngine
    });

    assert.strictEqual(resReboot.resolved, true);
    assert.strictEqual(resReboot.anchor, 'OPERATIONAL_DECISION_REBOOT');
    assert.strictEqual(resReboot.anchorActionId, 'restart_service');
    assert.strictEqual(resReboot.durationSeconds, 720);
    assert.strictEqual(resReboot.startTimeIso, rebootTimeIso);
  });

  await t.test('6. Verifies topological disambiguation and temporal scope are attached in runAgenticToolLoop', async () => {
    const mockPlan = {
      intent: 'test_probe',
      target: '127.0.0.1',
      mode: 'operational'
    };

    const outcome = await runAgenticToolLoop({
      promptText: 'diagnose core gateway over past 15 minutes',
      initialPlan: mockPlan,
      executeSinglePlan: async (plan) => ({
        reply: 'Diagnostics verified on 127.0.0.1',
        technicalEvidence: { rttMs: 1.2 },
        structuredAnswer: { result: 'OK', meaning: 'Healthy' }
      }),
      maxSteps: 1
    });

    assert.ok(outcome.epistemicClassification, 'epistemicClassification must be present');
    assert.ok(outcome.epistemicClassification.topologicalDisambiguation, 'topologicalDisambiguation must be present');
    assert.ok(outcome.epistemicClassification.temporalScope, 'temporalScope must be present');
    assert.strictEqual(outcome.epistemicClassification.temporalScope.resolved, true);
    assert.strictEqual(outcome.epistemicClassification.temporalScope.durationSeconds, 900);
  });
});
