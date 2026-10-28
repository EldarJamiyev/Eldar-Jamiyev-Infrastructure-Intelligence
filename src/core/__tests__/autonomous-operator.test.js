const test = require('node:test');
const assert = require('node:assert/strict');
const { AutonomousInfrastructureOperator } = require('../operator/autonomous-infrastructure-operator');

test('AutonomousInfrastructureOperator — Genuinely Live Telemetry, Real Execution, Honest Rollback & Autonomous Planner', async (t) => {
  const operator = new AutonomousInfrastructureOperator();

  await t.test('1. Collects genuinely live DNS, TCP, Kernel Socket, and Host Resource telemetry + Proactive Briefing', async () => {
    const state = await operator.getOperatorState();
    assert.ok(state.liveTelemetry, 'liveTelemetry must be populated from real OS/wire probes');
    assert.equal(typeof state.liveTelemetry.dnsProbe.latencyMs, 'number');
    assert.equal(typeof state.liveTelemetry.tcpServerProbe.rttMs, 'number');
    assert.equal(typeof state.liveTelemetry.kernelSockets.totalSockets, 'number');
    assert.equal(typeof state.liveTelemetry.hostResources.memUsedPct, 'number');

    assert.ok(state.proactiveBriefing);
    assert.equal(state.proactiveBriefing.status, 'AWAITING_APPROVAL');
    assert.match(state.proactiveBriefing.operatorMessage, /I detected elevated latency on three endpoints/i);
    assert.match(state.proactiveBriefing.operatorMessage, /Shall I apply it\?/i);
  });

  await t.test('2. Flagship Combination (Ideas 2, 3, 4): Cross-Layer Graph, Digital Twin, and Time Machine are populated', async () => {
    const state = await operator.getOperatorState();
    assert.equal(state.crossLayerGraph.nodes.length, 6);
    assert.equal(state.crossLayerGraph.nodes[0].layer, 'L7-APP');
    assert.equal(state.crossLayerGraph.nodes[5].layer, 'OS-PROC');
    assert.ok(state.timeMachine.keyframes.length >= 6);
    assert.ok(state.digitalTwin.nodes.length >= 5);
  });

  await t.test('3. Live Digital Twin supports removing switch, overloading link, breaking DNS, and resetting', async () => {
    const resSw = await operator.mutateDigitalTwin({ action: 'remove_switch', targetId: 'twin-sw1' });
    assert.ok(resSw.digitalTwin.activeMutations.includes('REMOVE_SWITCH:twin-sw1'));
    assert.ok(resSw.digitalTwin.predictedOutageRiskPct >= 40);

    const resLink = await operator.mutateDigitalTwin({ action: 'overload_link', targetId: 'link-gw-sw1' });
    assert.ok(resLink.digitalTwin.activeMutations.includes('OVERLOAD_LINK:link-gw-sw1'));

    const resDns = await operator.mutateDigitalTwin({ action: 'break_dns', targetId: 'twin-dns1' });
    assert.ok(resDns.digitalTwin.activeMutations.includes('BREAK_DNS:twin-dns1'));

    const resReset = await operator.mutateDigitalTwin({ action: 'reset' });
    assert.equal(resReset.digitalTwin.activeMutations.length, 0);
  });

  await t.test('4. Self-Healing with Proof enforces RBAC, executes real governedActionControlPlane, and reports Honest Rollback', async () => {
    // 4a. Read-only VIEWER role is blocked
    const denied = await operator.approveAndExecuteSelfHealing({
      role: 'VIEWER',
      actionId: 'verify_and_refresh_dns_resolution'
    });
    assert.equal(denied.allowed, false);
    assert.equal(denied.status, 'DENIED_RBAC');

    // 4b. Simulated verification failure triggers automatic rollback with Honest Rollback Report
    const rolledBack = await operator.approveAndExecuteSelfHealing({
      role: 'ADMIN',
      actionId: 'verify_and_refresh_dns_resolution',
      simulateVerificationFailure: true
    });
    assert.equal(rolledBack.allowed, true);
    assert.equal(rolledBack.status, 'ROLLED_BACK_ON_VERIFICATION_FAILURE');
    assert.equal(rolledBack.verification.rolledBack, true);
    assert.ok(rolledBack.verification.snapshotId, 'Must record pre-execution SQLite snapshot ID');
    assert.ok(rolledBack.verification.honestRollbackReport, 'Must include honestRollbackReport');
    assert.ok(Array.isArray(rolledBack.verification.honestRollbackReport.reversibleStateRestored));
    assert.ok(Array.isArray(rolledBack.verification.honestRollbackReport.nonReversibleEffects));

    // 4c. Normal approval applies fix via governedActionControlPlane and verifies live before/after metrics
    const verified = await operator.approveAndExecuteSelfHealing({
      role: 'ADMIN',
      actionId: 'verify_and_refresh_dns_resolution',
      simulateVerificationFailure: false
    });
    assert.equal(verified.allowed, true);
    assert.equal(verified.status, 'APPLIED_AND_VERIFIED');
    assert.equal(verified.verification.rolledBack, false);
    assert.equal(typeof verified.verification.beforeMetrics.liveDnsRttMs, 'number');
    assert.equal(typeof verified.verification.afterMetrics.liveDnsRttMs, 'number');
    assert.ok(verified.verification.afterMetrics.meanLatencyMs < verified.verification.beforeMetrics.meanLatencyMs);

    // Reset back to baseline anomaly for subsequent tests
    await operator.resetIncidentScenario();
  });

  await t.test('5. Autonomous Incident Commander parses natural-language directive, runs real engines, and persists to SQLite', async () => {
    const res = await operator.executeOperatorGoal({
      goal: 'Investigate slow DNS and TCP sockets on 127.0.0.1:3000 and fix whatever you safely can.',
      role: 'ADMIN',
      autoApproveLowRisk: false
    });
    assert.ok(res.activeTasks.length >= 1);
    assert.equal(res.activeTasks[0].steps.length, 5);
    assert.ok(res.persistedTaskCount >= 1);
  });

  await t.test('6. Operations Council, Multi-Host Fleet, Predictive Intelligence & Cockpit Preferences', async () => {
    const state = await operator.getOperatorState();
    assert.equal(state.operationsCouncil.agents.length, 4);
    assert.ok(state.fleetCommand.hosts.length >= 4);
    assert.ok(state.predictiveIntelligence.forecasts.length >= 3);

    const updated = await operator.updateCockpitPreferences({
      activeMode: 'SYSADMIN',
      panelOrder: ['fleet_and_predictive', 'flagship_unified_workflow', 'incident_commander_and_council']
    });
    assert.equal(updated.cockpitPreferences.activeMode, 'SYSADMIN');
    assert.equal(updated.cockpitPreferences.panelOrder[0], 'fleet_and_predictive');
  });
});
