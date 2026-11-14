/**
 * Track 5 Verification Test Suite:
 * Episodic Playbook Lifecycle Governance, Degradation Quarantine, and SRE Replay Filtering
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { OperationalMemoryEngine } = require('../src/core/memory/operational-memory-engine');
const {
  EpisodicCausalMemoryEngine,
  PLAYBOOK_LIFECYCLE_STATES,
  validatePlaybookLifecycleTransition
} = require('../src/ai/episodic-causal-memory-engine');
const { getAuditLogs } = require('../src/core/audit-logger');

describe('Track 5: Episodic Playbook Lifecycle Governance & Degradation Quarantine', () => {
  it('Subtest 1: State transition validation respects canonical 5-state lifecycle model', () => {
    assert.strictEqual(PLAYBOOK_LIFECYCLE_STATES.CANDIDATE, 'CANDIDATE');
    assert.strictEqual(PLAYBOOK_LIFECYCLE_STATES.VERIFIED_ACTIVE, 'VERIFIED_ACTIVE');
    assert.strictEqual(PLAYBOOK_LIFECYCLE_STATES.PROBATIONARY, 'PROBATIONARY');
    assert.strictEqual(PLAYBOOK_LIFECYCLE_STATES.QUARANTINED_DEGRADED, 'QUARANTINED_DEGRADED');
    assert.strictEqual(PLAYBOOK_LIFECYCLE_STATES.SUPERSEDED, 'SUPERSEDED');

    // Valid forward transitions
    assert.strictEqual(validatePlaybookLifecycleTransition('CANDIDATE', 'VERIFIED_ACTIVE').valid, true);
    assert.strictEqual(validatePlaybookLifecycleTransition('VERIFIED_ACTIVE', 'PROBATIONARY').valid, true);
    assert.strictEqual(validatePlaybookLifecycleTransition('PROBATIONARY', 'QUARANTINED_DEGRADED').valid, true);
    assert.strictEqual(validatePlaybookLifecycleTransition('QUARANTINED_DEGRADED', 'VERIFIED_ACTIVE').valid, true);

    // Terminal SUPERSEDED state cannot transition out
    const supersededAttempt = validatePlaybookLifecycleTransition('SUPERSEDED', 'VERIFIED_ACTIVE');
    assert.strictEqual(supersededAttempt.valid, false);
    assert.ok(supersededAttempt.reason.includes('SUPERSEDED'));

    // Unrecognized states rejected
    const invalidAttempt = validatePlaybookLifecycleTransition('UNKNOWN_STATE', 'VERIFIED_ACTIVE');
    assert.strictEqual(invalidAttempt.valid, false);

    // Instance method parity
    const engine = new EpisodicCausalMemoryEngine();
    assert.strictEqual(engine.validatePlaybookLifecycleTransition('CANDIDATE', 'VERIFIED_ACTIVE').valid, true);
  });

  it('Subtest 2: Playbook progresses from CANDIDATE to VERIFIED_ACTIVE on success', () => {
    const memory = new OperationalMemoryEngine({ useSqlite: true });
    const playbookId = `RB-TEST-PROG-${Date.now()}`;

    // Initial state before execution
    const initial = memory.getPlaybookLifecycle(playbookId);
    assert.strictEqual(initial.lifecycleState, 'CANDIDATE');
    assert.strictEqual(initial.totalExecutions, 0);

    // First execution succeeds
    const execution = memory.recordPlaybookExecution(playbookId, {
      success: true,
      target: '10.0.0.1',
      rttDeltaMs: -15.4,
      executedBy: 'SRE_AGENT_TEST'
    });

    assert.strictEqual(execution.lifecycleState, 'VERIFIED_ACTIVE');
    assert.strictEqual(execution.totalExecutions, 1);
    assert.strictEqual(execution.successfulExecutions, 1);
    assert.strictEqual(execution.consecutiveFailures, 0);
    assert.strictEqual(execution.rollingSuccessRate, 1.0);
    assert.ok(execution.lastExecutedAt);

    // Health evaluation confirms usability
    const health = memory.evaluatePlaybookHealth(playbookId);
    assert.strictEqual(health.isUsable, true);
    assert.strictEqual(health.isQuarantined, false);
    assert.strictEqual(health.isDegraded, false);
    assert.strictEqual(health.confidenceMultiplier, 1.0);
  });

  it('Subtest 3: Playbook degrades to PROBATIONARY on 1 failure and QUARANTINED_DEGRADED on >= 2 consecutive failures with HMAC audit log', () => {
    const memory = new OperationalMemoryEngine({ useSqlite: true });
    const playbookId = `RB-TEST-FAIL-${Date.now()}`;

    // Step 1: Promote to VERIFIED_ACTIVE
    memory.recordPlaybookExecution(playbookId, { success: true });
    let health = memory.evaluatePlaybookHealth(playbookId);
    assert.strictEqual(health.lifecycleState, 'VERIFIED_ACTIVE');

    // Step 2: Single failure drops to PROBATIONARY
    const fail1 = memory.recordPlaybookExecution(playbookId, {
      success: false,
      failureReason: 'Socket timeout during port check'
    });
    assert.strictEqual(fail1.lifecycleState, 'PROBATIONARY');
    assert.strictEqual(fail1.consecutiveFailures, 1);
    health = memory.evaluatePlaybookHealth(playbookId);
    assert.strictEqual(health.isDegraded, true);
    assert.strictEqual(health.isQuarantined, false);
    assert.strictEqual(health.confidenceMultiplier, 0.70);

    // Step 3: Second consecutive failure triggers QUARANTINED_DEGRADED
    const fail2 = memory.recordPlaybookExecution(playbookId, {
      success: false,
      failureReason: 'Repeated ECONNREFUSED on target',
      executedBy: 'AUTONOMOUS_WATCHDOG'
    });
    assert.strictEqual(fail2.lifecycleState, 'QUARANTINED_DEGRADED');
    assert.strictEqual(fail2.consecutiveFailures, 2);
    assert.ok(fail2.quarantinedAt);
    assert.ok(fail2.quarantineReason.includes('ECONNREFUSED'));

    health = memory.evaluatePlaybookHealth(playbookId);
    assert.strictEqual(health.isUsable, false);
    assert.strictEqual(health.isQuarantined, true);
    assert.strictEqual(health.confidenceMultiplier, 0.0);

    // Verify tamper-resistant HMAC audit trail was emitted
    const auditEntries = getAuditLogs();
    const quarantineEntry = auditEntries.find(
      (e) => e.action === 'PLAYBOOK_QUARANTINE' && e.resource === `playbook://${playbookId}`
    );
    assert.ok(quarantineEntry, 'Audit log must contain PLAYBOOK_QUARANTINE entry');
    assert.ok(
      quarantineEntry.hash || quarantineEntry.tamperResistantHmac,
      'Audit log entry must contain cryptographic HMAC hash'
    );
    assert.strictEqual(quarantineEntry.details.playbookId, playbookId);
    assert.strictEqual(quarantineEntry.details.newState, 'QUARANTINED_DEGRADED');
  });

  it('Subtest 4: Experience replay filters out QUARANTINED_DEGRADED playbooks and downweights PROBATIONARY ones', () => {
    const memory = new OperationalMemoryEngine({ useSqlite: true });
    const healthyPb = `RB-HEALTHY-${Date.now()}`;
    const degradedPb = `RB-DEGRADED-${Date.now()}`;
    const quarantinedPb = `RB-QUARANTINED-${Date.now()}`;

    // Establish lifecycle states
    memory.recordPlaybookExecution(healthyPb, { success: true });

    memory.recordPlaybookExecution(degradedPb, { success: true });
    memory.recordPlaybookExecution(degradedPb, { success: false, failureReason: 'High jitter' });

    memory.recordPlaybookExecution(quarantinedPb, { success: false });
    memory.recordPlaybookExecution(quarantinedPb, { success: false, failureReason: 'Catastrophic loop' });

    // Seed historical resolutions into SQLite/memory for each
    const testTarget = `host-test-${Date.now()}.local`;
    memory.recordVerifiedResolution({
      target: testTarget,
      symptomSignature: 'DNS_HIGH_LATENCY_QUERY',
      rootCause: 'Stale resolver cache',
      resolutionSteps: healthyPb
    });
    memory.recordVerifiedResolution({
      target: testTarget,
      symptomSignature: 'DNS_HIGH_LATENCY_QUERY',
      rootCause: 'Resolver queue congestion',
      resolutionSteps: degradedPb
    });
    memory.recordVerifiedResolution({
      target: testTarget,
      symptomSignature: 'DNS_HIGH_LATENCY_QUERY',
      rootCause: 'Resolver upstream blackhole',
      resolutionSteps: quarantinedPb
    });

    // Replay historical experiences for this target & symptom
    const replay = memory.replayHistoricalExperiences({
      target: testTarget,
      symptomSignature: 'DNS_HIGH_LATENCY_QUERY',
      topK: 5
    });

    // 1. Quarantined playbook MUST be filtered out of topExperiences
    const quarantinedInTop = replay.topExperiences.some(
      (e) => e.provenRemediationRunbook === quarantinedPb || e.executedRunbookId === quarantinedPb
    );
    assert.strictEqual(quarantinedInTop, false, 'Quarantined playbook must NOT appear in topExperiences');
    assert.ok(replay.quarantinedCount >= 1, 'quarantinedCount must record quarantined candidate');

    // 2. Recommended action must be the healthy playbook
    assert.strictEqual(replay.recommendedAction, healthyPb);

    // 3. Degraded playbook composite score must reflect 0.70x penalty
    const degradedExp = replay.topExperiences.find(
      (e) => e.provenRemediationRunbook === degradedPb
    );
    if (degradedExp) {
      assert.strictEqual(degradedExp.isProbationary, true);
      assert.strictEqual(degradedExp.confidenceMultiplier, 0.70);
    }
  });

  it('Subtest 5: SRE Operator rehabilitation restores QUARANTINED playbook and clears failures', () => {
    const memory = new OperationalMemoryEngine({ useSqlite: true });
    const playbookId = `RB-REHAB-${Date.now()}`;

    // Quarantine it
    memory.recordPlaybookExecution(playbookId, { success: false });
    memory.recordPlaybookExecution(playbookId, { success: false, failureReason: 'Repeated timeout' });
    let health = memory.evaluatePlaybookHealth(playbookId);
    assert.strictEqual(health.isQuarantined, true);

    // Rehabilitate
    const rehabilitated = memory.rehabilitatePlaybook(playbookId, {
      rehabilitatedBy: 'SENIOR_SRE_OPERATOR',
      notes: 'Upstream gateway routing table repaired; playbook verified safe.',
      targetState: 'VERIFIED_ACTIVE'
    });

    assert.strictEqual(rehabilitated.lifecycleState, 'VERIFIED_ACTIVE');
    assert.strictEqual(rehabilitated.consecutiveFailures, 0);
    assert.strictEqual(rehabilitated.quarantinedAt, null);
    assert.strictEqual(rehabilitated.quarantineReason, null);
    assert.ok(rehabilitated.rehabilitatedAt);
    assert.ok(rehabilitated.rehabilitationNotes.includes('gateway routing table repaired'));

    // Check health after rehab
    health = memory.evaluatePlaybookHealth(playbookId);
    assert.strictEqual(health.isUsable, true);
    assert.strictEqual(health.isQuarantined, false);
    assert.strictEqual(health.confidenceMultiplier, 1.0);

    // Check HMAC audit entry
    const auditEntries = getAuditLogs();
    const rehabEntry = auditEntries.find(
      (e) => e.action === 'PLAYBOOK_REHABILITATION' && e.resource === `playbook://${playbookId}`
    );
    assert.ok(rehabEntry, 'Audit log must contain PLAYBOOK_REHABILITATION entry');
    assert.strictEqual(rehabEntry.details.rehabilitatedBy, 'SENIOR_SRE_OPERATOR');
    assert.strictEqual(rehabEntry.details.newState, 'VERIFIED_ACTIVE');
  });
});
