const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('net');
const dns = require('dns');
const { db } = require('../../db/database');
const { validateSecurityConfiguration } = require('../../config');
const { AutonomousInfrastructureOperator } = require('../operator/autonomous-infrastructure-operator');

test('AutonomousInfrastructureOperator — Security Defaults, Honest Telemetry, Real Remediation, Verified Rollback & Truthful Planner', async (t) => {
  const operator = new AutonomousInfrastructureOperator();

  // Start a real ephemeral local TCP server so we can test genuine reachable vs. unreachable TCP endpoints
  const testServer = net.createServer((socket) => {
    socket.on('error', () => {});
    socket.end('OK\r\n');
  });
  await new Promise((resolve) => testServer.listen(0, '127.0.0.1', resolve));
  const listeningPort = testServer.address().port;

  t.after(() => {
    try { testServer.close(); } catch (_) {}
  });

  await t.test('1. Security Configuration: Rejects missing, default, short, or identical JWT/HMAC secrets, and blocks evaluation mode on non-loopback hosts', () => {
    const validHmac = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90';
    const validJwt = 'f0e9d8c7b6a594837261504f3e2d1c0bf0e9d8c7b6a594837261504f3e2d1c0b';

    // Identical secrets must be rejected outside loopback dev
    assert.throws(
      () => validateSecurityConfiguration({
        host: '127.0.0.1',
        port: 8443,
        env: {
          NODE_ENV: 'production',
          EJII_HMAC_SECRET: validHmac,
          EJII_JWT_SECRET: validHmac
        }
      }),
      /must be unique/i
    );

    // Non-loopback host with evaluationMode=true must be rejected even if NODE_ENV !== production
    assert.throws(
      () => validateSecurityConfiguration({
        host: '0.0.0.0',
        port: 8443,
        env: {
          NODE_ENV: 'development',
          EJII_HMAC_SECRET: validHmac,
          EJII_JWT_SECRET: validJwt,
          EJII_EVALUATION_MODE: 'true'
        }
      }),
      /Unsafe network exposure blocked.*EJII_EVALUATION_MODE=true/i
    );

    // Default password in env must be rejected on non-loopback host
    assert.throws(
      () => validateSecurityConfiguration({
        host: '0.0.0.0',
        port: 8443,
        env: {
          NODE_ENV: 'development',
          EJII_HMAC_SECRET: validHmac,
          EJII_JWT_SECRET: validJwt,
          EJII_ADMIN_PASSWORD: 'admin2026!'
        }
      }),
      /Unsafe network exposure blocked.*known default password/i
    );

    // Strong, distinct secrets on production pass validation without throwing
    assert.doesNotThrow(() =>
      validateSecurityConfiguration({
        host: '0.0.0.0',
        port: 8443,
        env: {
          NODE_ENV: 'production',
          EJII_HMAC_SECRET: validHmac,
          EJII_JWT_SECRET: validJwt
        }
      })
    );
  });

  await t.test('2. Honest Live Telemetry: No synthetic +142ms offsets, no fake fleet hosts, and remote topology nodes report null CPU/RAM', async () => {
    const state = await operator.getOperatorState();
    assert.ok(state.liveTelemetry, 'liveTelemetry must be populated from real OS/wire probes');
    assert.equal(typeof state.liveTelemetry.dnsProbe.latencyMs, 'number');
    assert.equal(typeof state.liveTelemetry.tcpServerProbe.rttMs, 'number');
    assert.equal(typeof state.liveTelemetry.kernelSockets.totalSockets, 'number');
    assert.equal(typeof state.liveTelemetry.hostResources.memUsedPct, 'number');

    // Verify Cross-Layer Graph latency equals real measured DNS + TCP latency without any +142ms synthetic offset
    const dnsNode = state.crossLayerGraph.nodes.find((n) => n.id === 'layer-dns');
    const tcpNode = state.crossLayerGraph.nodes.find((n) => n.id === 'layer-tcp');
    assert.equal(dnsNode.latencyContributionMs, Number(state.liveTelemetry.dnsProbe.latencyMs.toFixed(2)));
    assert.equal(tcpNode.latencyContributionMs, Number(state.liveTelemetry.tcpServerProbe.rttMs.toFixed(2)));
    assert.equal(
      state.crossLayerGraph.totalRequestLatencyMs,
      Number((dnsNode.latencyContributionMs + tcpNode.latencyContributionMs).toFixed(2))
    );

    // Verify Fleet Command contains zero hardcoded fictional hosts (no WIN-CORP-DC01 or LNX-PROD-INGRESS-01)
    const hostnames = state.fleetCommand.hosts.map((h) => h.hostname);
    assert.ok(!hostnames.includes('WIN-CORP-DC01'), 'Must not include synthetic WIN-CORP-DC01 host');
    assert.ok(!hostnames.includes('LNX-PROD-INGRESS-01'), 'Must not include synthetic LNX-PROD-INGRESS-01 host');
    assert.equal(state.fleetCommand.hosts[0].telemetrySource, 'LIVE_LOCAL_OS_KERNEL');
    for (const remoteNode of state.fleetCommand.hosts.slice(1)) {
      assert.equal(remoteNode.cpuPct, null, 'Topology node without host agent must report cpuPct: null');
      assert.equal(remoteNode.ramPct, null, 'Topology node without host agent must report ramPct: null');
    }

    // Verify Time Machine keyframes come from real samples / SQLite snapshots
    assert.equal(state.timeMachine.telemetrySource, 'LIVE_RING_BUFFER_AND_SQLITE_SNAPSHOTS');
    assert.ok(state.timeMachine.keyframes.length >= 2);
  });

  await t.test('3. Live Digital Twin supports counterfactual mutations and explicitly labels simulated outputs', async () => {
    const resSw = await operator.mutateDigitalTwin({ action: 'remove_switch', targetId: 'twin-sw1' });
    assert.equal(resSw.digitalTwin.epistemicLabel, 'SIMULATED_COUNTERFACTUAL_REPLICA');
    assert.ok(resSw.digitalTwin.activeMutations.includes('REMOVE_SWITCH:twin-sw1'));
    assert.ok(resSw.digitalTwin.predictedOutageRiskPct >= 40);

    const resReset = await operator.mutateDigitalTwin({ action: 'reset' });
    assert.equal(resReset.digitalTwin.activeMutations.length, 0);
  });

  await t.test('4. Remediation Semantics, Genuine Postcondition Failure (ECONNREFUSED), Verified Rollback & Fail-Closed Persistence', async () => {
    // 4a. Read-only VIEWER role is blocked
    const denied = await operator.approveAndExecuteSelfHealing({
      role: 'VIEWER',
      actionId: 'verify_and_refresh_dns_resolution'
    });
    assert.equal(denied.allowed, false);
    assert.equal(denied.status, 'DENIED_RBAC');

    // 4b. Seed a known topology_nodes row so we can verify rollback restores exact SQLite state after a genuine probe failure
    const preNodes = db.prepare('SELECT id, status, last_checked, last_latency_ms FROM topology_nodes ORDER BY id ASC').all();
    const initialDnsServers = dns.getServers();

    // Target a guaranteed closed port so TCP connection fails with ECONNREFUSED (without using simulateVerificationFailure)
    const closedPort = 65431;
    const genuineFailure = await operator.approveAndExecuteSelfHealing({
      role: 'ADMIN',
      actionId: 'verify_tcp_service_endpoint',
      target: '127.0.0.1',
      port: closedPort,
      simulateVerificationFailure: false
    });
    assert.equal(genuineFailure.allowed, true);
    assert.equal(genuineFailure.status, 'ROLLED_BACK_ON_VERIFICATION_FAILURE');
    assert.equal(genuineFailure.verification.postconditionPassed, false);
    assert.equal(genuineFailure.verification.rolledBack, true);
    assert.equal(genuineFailure.verification.rollbackVerified, true);
    assert.match(genuineFailure.verification.failureReason, /failed|ECONNREFUSED|CLOSED/i);

    // Verify SQLite topology_nodes rows and dns.getServers() were restored byte-for-byte to pre-execution state
    const restoredNodes = db.prepare('SELECT id, status, last_checked, last_latency_ms FROM topology_nodes ORDER BY id ASC').all();
    assert.deepEqual(restoredNodes, preNodes);
    assert.deepEqual(dns.getServers(), initialDnsServers);

    // 4c. Fail-closed snapshot persistence check: if ai_operator_snapshots write fails, abort before state mutation
    const origPrepare = db.prepare.bind(db);
    db.prepare = function (sql) {
      if (typeof sql === 'string' && sql.includes('INSERT INTO ai_operator_snapshots')) {
        return {
          run() {
            throw new Error('Simulated SQLite disk full error on snapshot write');
          }
        };
      }
      return origPrepare(sql);
    };
    try {
      const snapFailRes = await operator.approveAndExecuteSelfHealing({
        role: 'ADMIN',
        actionId: 'verify_and_refresh_dns_resolution',
        target: '127.0.0.1',
        port: listeningPort
      });
      assert.equal(snapFailRes.status, 'SNAPSHOT_PERSISTENCE_FAILED');
      assert.equal(snapFailRes.approved, false);
      assert.match(snapFailRes.error, /failed to persist reversible snapshot/i);
    } finally {
      db.prepare = origPrepare;
    }

    // 4d. Genuine success against the live listening TCP server on 127.0.0.1:listeningPort
    const verified = await operator.approveAndExecuteSelfHealing({
      role: 'ADMIN',
      actionId: 'verify_and_refresh_dns_resolution',
      target: '127.0.0.1',
      port: listeningPort,
      simulateVerificationFailure: false
    });
    assert.equal(verified.allowed, true);
    assert.equal(verified.status, 'APPLIED_AND_VERIFIED');
    assert.equal(verified.verification.postconditionPassed, true);
    assert.equal(verified.verification.rolledBack, false);
    assert.equal(typeof verified.verification.beforeMetrics.liveDnsRttMs, 'number');
    assert.equal(typeof verified.verification.afterMetrics.liveDnsRttMs, 'number');
    // Restore original topology_nodes rows after test
    const restoreStmt = db.prepare('UPDATE topology_nodes SET status = ?, last_checked = ?, last_latency_ms = ? WHERE id = ?');
    for (const n of preNodes) {
      restoreStmt.run(n.status, n.last_checked, n.last_latency_ms, n.id);
    }
    await operator.resetIncidentScenario();
  });

  await t.test('5. Planner Truthfulness: Preserves probe failures/uncertainties and only marks COMPLETED_AND_VERIFIED when postconditions pass', async () => {
    const preNodes = db.prepare('SELECT id, status, last_checked, last_latency_ms FROM topology_nodes ORDER BY id ASC').all();

    // 5a. Directive targeting an unreachable port (127.0.0.1:65432) with autoApproveLowRisk=true must NOT report COMPLETED_AND_VERIFIED
    const failedGoalState = await operator.executeOperatorGoal({
      goal: 'Verify TCP port 65432 on 127.0.0.1 and fix whatever you safely can.',
      role: 'ADMIN',
      autoApproveLowRisk: true
    });
    const failedTask = failedGoalState.activeTask;
    assert.equal(failedTask.status, 'ROLLED_BACK_ON_VERIFICATION_FAILURE');
    assert.equal(failedTask.steps[1].status, 'DEGRADED_FINDING');
    assert.equal(failedTask.steps[4].status, 'FAILED_AND_ROLLED_BACK');
    assert.ok(failedTask.uncertainties.length > 0, 'Must record explicit uncertainties when probes fail');

    // 5b. Directive targeting our live listening port with autoApproveLowRisk=true succeeds and marks COMPLETED_AND_VERIFIED
    const passedGoalState = await operator.executeOperatorGoal({
      goal: `Verify DNS and TCP port ${listeningPort} on 127.0.0.1 and fix whatever you safely can.`,
      role: 'ADMIN',
      autoApproveLowRisk: true
    });
    const passedTask = passedGoalState.activeTask;
    assert.equal(passedTask.status, 'COMPLETED_AND_VERIFIED');
    assert.equal(passedTask.steps[1].status, 'COMPLETED');
    assert.equal(passedTask.steps[4].status, 'COMPLETED');

    const restoreStmt = db.prepare('UPDATE topology_nodes SET status = ?, last_checked = ?, last_latency_ms = ? WHERE id = ?');
    for (const n of preNodes) {
      restoreStmt.run(n.status, n.last_checked, n.last_latency_ms, n.id);
    }
  });
});
