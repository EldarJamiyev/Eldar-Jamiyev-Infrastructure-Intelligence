'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { AutonomousInfrastructureOperator } = require('../operator/autonomous-infrastructure-operator');

test('AutonomousInfrastructureOperator — 9 Capabilities & Flagship Pipeline', async (t) => {
  const operator = new AutonomousInfrastructureOperator();

  await t.test('1. Proactive Briefing & Initial State covers all 9 capabilities', () => {
    const state = operator.getOperatorState();
    assert.ok(state.proactiveBriefing, 'proactiveBriefing must exist');
    assert.match(
      state.proactiveBriefing.operatorMessage,
      /I detected elevated latency on three endpoints/i,
      'Must present proactive AI Operator briefing message'
    );
    assert.equal(state.proactiveBriefing.affectedEndpoints.length, 3);
    assert.equal(state.activeTask.toolExecutionSteps.length, 6);
    assert.equal(state.crossLayerGraph.nodes.length, 6);
    assert.equal(state.operationsCouncil.agents.length, 4);
    assert.equal(state.fleetCommand.hosts.length, 6);
    assert.ok(state.predictiveIntelligence.forecasts.length >= 3);
    assert.equal(state.cockpitConfig.activeMode, 'NOC');
  });

  await t.test('2. Digital Twin mutations (remove_switch, overload_link, break_dns, reset_twin) isolate from production', () => {
    const twinSwitch = operator.mutateDigitalTwin({ action: 'remove_switch', targetId: 'twin-sw1' });
    assert.equal(twinSwitch.isolatedFromProduction, true);
    assert.equal(twinSwitch.verdict, 'CRITICAL_PARTITION_PREDICTED');
    assert.equal(twinSwitch.predictedMetrics.blastRadiusHosts, 4);

    const twinOverload = operator.mutateDigitalTwin({ action: 'overload_link', targetId: 'link-gw-sw1' });
    assert.ok(twinOverload.predictedMetrics.packetLossPct >= 14.8);

    const twinReset = operator.mutateDigitalTwin({ action: 'reset_twin' });
    assert.equal(twinReset.activePerturbations.length, 0);
    assert.equal(twinReset.verdict, 'NOMINAL_REPLICA');
  });

  await t.test('3. Natural-language directive planner & RBAC permission boundary enforcement', async () => {
    const postDirective = await operator.executeOperatorGoal({
      goal: 'Find out why the network is slow and fix whatever you safely can.',
      role: 'ADMIN',
      autoApproveLowRisk: false
    });
    assert.equal(postDirective.activeTask.goal, 'Find out why the network is slow and fix whatever you safely can.');

    // VIEWER role must be blocked from executing state-mutating self-healing
    const denied = await operator.approveAndExecuteSelfHealing({
      role: 'VIEWER',
      actionId: 'dns_cache_flush'
    });
    assert.equal(denied.approved, false);
    assert.equal(denied.status, 'DENIED_BY_RBAC');
  });

  await t.test('4. Self-Healing with Proof & Automatic Rollback when verification fails', async () => {
    const rollbackRes = await operator.approveAndExecuteSelfHealing({
      role: 'ADMIN',
      actionId: 'dns_cache_flush',
      simulateVerificationFailure: true
    });
    assert.equal(rollbackRes.status, 'ROLLED_BACK_SAFEGUARD');
    assert.equal(rollbackRes.proof.rollbackExecuted, true);
    assert.equal(rollbackRes.proof.postconditionPassed, false);

    // Now execute normal approval and verify postconditions pass
    const verifiedRes = await operator.approveAndExecuteSelfHealing({
      role: 'ADMIN',
      actionId: 'dns_cache_flush',
      simulateVerificationFailure: false
    });
    assert.equal(verifiedRes.status, 'APPLIED_AND_VERIFIED');
    assert.equal(verifiedRes.proof.postconditionPassed, true);
    assert.equal(verifiedRes.proof.rollbackExecuted, false);
    assert.ok(verifiedRes.proof.afterMetrics.endpointP95Ms < 25);
  });

  await t.test('5. Personalized Operations Cockpit modes & workspace persistence', () => {
    const helpdesk = operator.updateCockpitWorkspace({
      mode: 'HELPDESK',
      saveWorkspaceName: 'Triage Shift Alpha'
    });
    assert.equal(helpdesk.cockpitConfig.activeMode, 'HELPDESK');
    assert.equal(helpdesk.savedWorkspaces[0].name, 'Triage Shift Alpha');
  });
});
