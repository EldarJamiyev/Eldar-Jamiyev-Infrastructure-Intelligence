'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  distributedBeliefPropagationEngine,
  DistributedBeliefPropagationEngine,
  CANONICAL_FAULT_VARIABLES,
  CANONICAL_CAUSAL_FACTORS
} = require('../src/core/agent/distributed-belief-propagation');
const { deriveAgentCredential } = require('../src/core/agent/edge-agent-service');

test('Phase 4.0 Track 5: Distributed Causal Belief Propagation & Byzantine Consensus', async (t) => {
  await t.test('1. Runs Loopy Belief Propagation and propagates evidence through causal factor nodes', () => {
    const engine = new DistributedBeliefPropagationEngine();

    // Baseline beliefs without evidence (reflects priors)
    const baseline = engine.runLoopyBeliefPropagation({});
    assert.ok(baseline.DNS_NXDOMAIN_POISON !== undefined);
    assert.ok(baseline.UPSTREAM_WAN_BLACKHOLE !== undefined);
    assert.ok(baseline.DNS_NXDOMAIN_POISON < 0.25);

    // Now inject strong evidence that UPSTREAM_WAN_BLACKHOLE is occurring (0.95)
    const posterior = engine.runLoopyBeliefPropagation({ UPSTREAM_WAN_BLACKHOLE: 0.95 });
    // Due to FACTOR_DNS_WAN, DNS_NXDOMAIN_POISON probability should increase substantially
    assert.ok(
      posterior.DNS_NXDOMAIN_POISON > baseline.DNS_NXDOMAIN_POISON,
      `Expected posterior DNS (${posterior.DNS_NXDOMAIN_POISON}) > baseline (${baseline.DNS_NXDOMAIN_POISON})`
    );
    assert.ok(posterior.UPSTREAM_WAN_BLACKHOLE >= 0.90);
  });

  await t.test('2. Generates and cryptographically verifies HMAC-SHA256 belief report signatures', () => {
    const engine = new DistributedBeliefPropagationEngine();
    const agentId = 'agent-lon-01';
    const siteId = 'site-hq-lon';
    const epoch = 42;

    const beliefs = {
      DNS_NXDOMAIN_POISON: 0.15,
      LOCAL_STACK_CONGESTION: 0.85,
      ARP_L2_ISOLATION: 0.05
    };

    const report = engine.generateSignedBeliefReport(agentId, siteId, epoch, beliefs);
    assert.strictEqual(report.agentId, agentId);
    assert.strictEqual(report.epoch, epoch);
    assert.ok(report.signature && report.signature.length === 64, 'Signature must be 64-char SHA256 hex');

    // Valid signature check
    const isValid = engine.verifyReportSignature(report);
    assert.strictEqual(isValid, true);

    // Tampered report (tampered belief value) must fail signature verification
    const tamperedReport = {
      ...report,
      beliefs: { ...report.beliefs, LOCAL_STACK_CONGESTION: 0.10 }
    };
    const isTamperedValid = engine.verifyReportSignature(tamperedReport);
    assert.strictEqual(isTamperedValid, false);
  });

  await t.test('3. Computes symmetric KL divergence between consistent and divergent distributions', () => {
    const engine = new DistributedBeliefPropagationEngine();
    const p = { A: 0.80, B: 0.20, C: 0.50 };
    const qClose = { A: 0.78, B: 0.22, C: 0.49 };
    const qFar = { A: 0.05, B: 0.95, C: 0.99 };

    const divClose = engine.computeSymmetricKLDivergence(p, qClose);
    const divFar = engine.computeSymmetricKLDivergence(p, qFar);

    assert.ok(divClose < 0.10, `Expected close divergence < 0.10, got ${divClose}`);
    assert.ok(divFar > 4.0, `Expected distant divergence > 4.0, got ${divFar}`);
  });

  await t.test('4. Achieves Byzantine quorum consensus (>= 2f + 1) while filtering forged and outlier reports', () => {
    const engine = new DistributedBeliefPropagationEngine();
    const epoch = 101;

    // Fleet of 4 agents (N = 4, f = floor(3/3) = 1, requiredQuorum = 2f + 1 = 3)
    const agent1 = 'agent-lon-01';
    const agent2 = 'agent-nyc-02';
    const agent3 = 'agent-fra-03';
    const rogueAgent = 'agent-byz-04';

    const honestBeliefs = {
      DNS_NXDOMAIN_POISON: 0.12,
      LOCAL_STACK_CONGESTION: 0.78,
      SERVICE_DAEMON_CRASH: 0.05
    };

    const r1 = engine.generateSignedBeliefReport(agent1, 'site-lon', epoch, honestBeliefs);
    const r2 = engine.generateSignedBeliefReport(agent2, 'site-nyc', epoch, {
      ...honestBeliefs,
      LOCAL_STACK_CONGESTION: 0.80
    });
    const r3 = engine.generateSignedBeliefReport(agent3, 'site-fra', epoch, {
      ...honestBeliefs,
      LOCAL_STACK_CONGESTION: 0.76
    });

    // Rogue report: forged signature
    const forgedReport = {
      agentId: rogueAgent,
      siteId: 'site-rogue',
      epoch,
      timestampIso: new Date().toISOString(),
      beliefs: { ...honestBeliefs, LOCAL_STACK_CONGESTION: 0.01 },
      signature: 'deadbeef0000111122223333444455556666777788889999aaaabbbbccccdddd'
    };

    const consensus = engine.reachByzantineConsensus([r1, r2, r3, forgedReport], epoch);
    assert.strictEqual(consensus.quorumAchieved, true);
    assert.strictEqual(consensus.totalAgentsReported, 4);
    assert.strictEqual(consensus.validSignaturesCount, 3);
    assert.strictEqual(consensus.byzantineRejectedCount, 1);
    assert.ok(consensus.rejectedAgents.includes(rogueAgent));
    assert.ok(consensus.consensusBeliefs.LOCAL_STACK_CONGESTION >= 0.76);
    assert.ok(consensus.consensusHash && consensus.consensusHash.length === 64);
  });

  await t.test('5. Enqueues belief reports to durable outbox store for disconnected edge delivery', () => {
    const engine = new DistributedBeliefPropagationEngine();
    const report = engine.generateSignedBeliefReport('agent-edge-store', 'site-remote', 55, {
      ARP_L2_ISOLATION: 0.40
    });

    const enqueued = engine.enqueueDurableBeliefReport(report);
    assert.strictEqual(enqueued, true);
  });
});
