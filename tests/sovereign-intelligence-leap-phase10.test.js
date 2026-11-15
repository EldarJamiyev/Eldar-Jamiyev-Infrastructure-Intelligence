/**
 * EJII Phase 10.0 Sovereign Autonomous Frontier Capstone Verification Suite
 *
 * Verifies all 6 Subsystems:
 * 1. Autonomous Pre-Remediation Chaos Fault Sandbox (M/M/c/K queueing, Lyapunov drift, HMAC receipts)
 * 2. Quantum-Resilient Lattice Signatures (ML-DSA / Dilithium) & Zero-Knowledge Pedersen Telemetry Prover
 * 3. Reinforcement Learning from Operator Feedback (RLOF) Policy Alignment & Bradley-Terry / DPO Prior Shifting
 * 4. Dynamic eBPF / AF_XDP Line-Rate Kernel Filter Synthesizer & Verifier Safety Checker
 * 5. Distributed Multi-Region 3-Phase Byzantine Fault Tolerant (BFT) State Machine Replication
 * 6. End-to-End Multi-Region Autonomous Incident Cascade & Sovereign Closed Loop
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

test('Phase 10.0 Capstone: Sovereign Autonomous Frontier & Resilient Infrastructure Intelligence', async (t) => {

  await t.test('1. Autonomous Pre-Remediation Chaos Fault Sandbox & Lyapunov Stability Verification', () => {
    const { ChaosFaultSandbox } = require('../src/systems/remediation/chaos-fault-sandbox');
    const sandbox = new ChaosFaultSandbox();

    // 1. Erlang-C & M/M/c/K Queueing Model
    const qModel = sandbox.calculateQueueingMetrics(120.0, 30.0, 5, 20);
    assert.ok(qModel.trafficIntensity > 0);
    assert.ok(qModel.blockingProbability >= 0.0 && qModel.blockingProbability <= 1.0);
    assert.ok(qModel.meanQueueLength >= 0);

    // 2. High-Stress Injection with Lyapunov Drift Verification
    const highStressPlan = {
      actionId: 'high_stress_drop',
      actionType: 'DSCP_TRAFFIC_CLASS',
      target: '10.0.0.1'
    };
    const currentState = { rttMs: 45.0, lossPct: 1.0, queueDepthPackets: 25.0 };
    const exp = sandbox.evaluateCandidateRemediation('saga_capstone_test', highStressPlan, currentState, {
      arrivalSurgeMultiplier: 1.5,
      serviceDegradationFactor: 0.8,
      injectedDropPct: 0.5,
      injectedLatencyMs: 15.0
    });

    assert.ok(exp.receiptId.startsWith('chaos_rcpt_'));
    assert.equal(exp.hmacSignature.length, 64, 'HMAC receipt must be a 64-char hex digest');
    assert.equal(exp.passed, true, 'Remediation must stabilize the network');
    assert.ok(exp.lyapunovDriftDeltaV < 0, 'Lyapunov drift must confirm contraction (deltaV < 0)');
  });

  await t.test('2. Quantum-Resilient Post-Quantum Attestation & Zero-Knowledge Telemetry Prover', () => {
    const { PostQuantumZkAttestor } = require('../src/security/post-quantum-zk-attestor');
    const attestor = new PostQuantumZkAttestor();

    // 1. Lattice Polynomial Ring Key Generation & Signing
    const keyPair = attestor.generatePqcKeyPair('test_seed_phase10');
    assert.equal(keyPair.secretKey.s1.length, 256);
    assert.equal(keyPair.secretKey.s2.length, 256);
    assert.equal(keyPair.publicKey.t.length, 256);

    const message = 'CRITICAL_QUORUM_ACTION:TCP_WINDOW_CLAMP:10.0.0.1';
    const sig = attestor.signLattice(message, keyPair);
    assert.equal(sig.z.length, 256);
    assert.equal(sig.challengeHash.length, 64);

    const isValid = attestor.verifyLattice(message, sig, keyPair.publicKey);
    assert.equal(isValid, true, 'Valid lattice signature must verify cleanly');

    const tampered = attestor.verifyLattice(message + '_tampered', sig, keyPair.publicKey);
    assert.equal(tampered, false, 'Tampered payload must fail lattice verification');

    // 2. Zero-Knowledge Pedersen Telemetry Range Proof
    const telemetryObj = { rttMs: 25.0, lossPct: 1.2, queueDepthPackets: 10.0 };
    const thresholds = { maxRttMs: 150.0, maxLossPct: 3.0, maxQueuePackets: 100 };
    const zkProof = attestor.generateZkPedersenCommitment(telemetryObj, thresholds);
    assert.equal(zkProof.satisfiesThresholds, true);
    assert.ok(zkProof.commitmentHex.length > 20);

    const zkValid = attestor.verifyZkCommitment(zkProof);
    assert.equal(zkValid, true, 'Zero-knowledge proof must verify without revealing raw telemetry');
  });

  await t.test('3. Reinforcement Learning from Operator Feedback (RLOF) Policy Alignment', () => {
    const { RlofPreferenceAligner } = require('../src/ai/rlof-preference-aligner');
    const { ContextualBanditPolicyEngine } = require('../src/systems/remediation/contextual-bandit-policy');

    const bandit = new ContextualBanditPolicyEngine();
    bandit.resetForTesting();
    const rlof = new RlofPreferenceAligner(bandit);
    rlof.resetForTesting();

    // 1. Natural Language Operator Feedback Parsing
    const parsed = rlof.parseOperatorFeedback('override DNS_UPSTREAM_PIVOT with TCP_WINDOW_CLAMP');
    assert.equal(parsed.matched, true);
    assert.equal(parsed.winningAction, 'TCP_WINDOW_CLAMP');
    assert.equal(parsed.losingAction, 'DNS_UPSTREAM_PIVOT');
    assert.equal(parsed.feedbackType, 'EXPLICIT_OVERRIDE');

    // 2. Bradley-Terry & DPO Computation
    const contextVector = [0.6, 0.7, 0.5, 0.2];
    const initialBT = rlof.computeBradleyTerryProbability(contextVector, 'TCP_WINDOW_CLAMP', 'DNS_UPSTREAM_PIVOT');
    assert.ok(initialBT >= 0.0 && initialBT <= 1.0);

    // 3. Alignment Step: Shift Bandit Arm Priors
    const winBefore = bandit.registerOrGetArm('TCP_WINDOW_CLAMP');
    const lossBefore = bandit.registerOrGetArm('DNS_UPSTREAM_PIVOT');
    const alphaBefore = winBefore.alpha;
    const betaBefore = lossBefore.beta;

    const alignResult = rlof.recordPreferenceAndAlign({
      winningAction: 'TCP_WINDOW_CLAMP',
      losingAction: 'DNS_UPSTREAM_PIVOT',
      contextVector,
      operatorId: 'operator-alice',
      feedbackType: 'EXPLICIT_OVERRIDE'
    });

    assert.ok(alignResult.triplet.tripletId.startsWith('TRIPLET-'));
    assert.ok(alignResult.dpoLoss > 0);
    assert.ok(bandit.registerOrGetArm('TCP_WINDOW_CLAMP').alpha > alphaBefore);
    assert.ok(bandit.registerOrGetArm('DNS_UPSTREAM_PIVOT').beta > betaBefore);

    // 4. Persistence check in SQLite WAL
    const history = rlof.getPreferenceHistory(5);
    assert.ok(history.length > 0);
    assert.equal(history[0].winningAction, 'TCP_WINDOW_CLAMP');
  });

  await t.test('4. Dynamic eBPF / AF_XDP Line-Rate Kernel Filter Synthesizer & Verifier Safety', () => {
    const { EbpfXdpSynthesizer } = require('../src/sniffer/ebpf-xdp-synthesizer');
    const xdp = new EbpfXdpSynthesizer();
    xdp.clearRules();

    // 1. Add Drop and Rate Limiter Rules
    xdp.addRule({
      ruleId: 'drop_ddos_actor',
      srcIp: '198.51.100.99',
      action: 'XDP_DROP',
      comment: 'Line-rate burst drop'
    });
    xdp.addRule({
      ruleId: 'rate_limit_client',
      srcIp: '198.51.100.100',
      action: 'XDP_PASS',
      rateLimitBytesPerSec: 2000,
      burstCapacityBytes: 4000
    });

    // 2. Synthesize Production C Program and Run Kernel Verifier Safety Check
    const prog = xdp.synthesizeXdpCProgram('xdp_capstone_filter');
    assert.equal(prog.section, 'xdp');
    assert.ok(prog.cSourceCode.includes('SEC("xdp")'));
    assert.equal(prog.verifierValidation.passed, true);
    assert.equal(prog.verifierValidation.boundedMemoryGuardsChecked, true);
    assert.equal(prog.verifierValidation.loopBoundsChecked, true);
    assert.equal(prog.verifierValidation.stackWithinLimits, true);
    assert.equal(prog.verifierValidation.instructionDepthSafe, true);

    // 3. Line-Rate Packet Evaluation
    const dropEval = xdp.evaluateRawPacket({
      srcIp: '198.51.100.99',
      dstIp: '10.0.0.1',
      byteLength: 512
    });
    assert.equal(dropEval.action, 'XDP_DROP');

    const passEval = xdp.evaluateRawPacket({
      srcIp: '10.0.0.50',
      dstIp: '10.0.0.1',
      byteLength: 512
    });
    assert.equal(passEval.action, 'XDP_PASS');
  });

  await t.test('5. Distributed Multi-Region 3-Phase BFT State Machine Replication', () => {
    const { BftStateMachineReplicator } = require('../src/core/multisite/bft-state-machine-replicator');
    const bft = new BftStateMachineReplicator();
    bft.resetForTesting();

    // Setup 4 cluster nodes (N = 3f + 1, f = 1, quorum = 2f + 1 = 3)
    bft.registerNode({ nodeId: 'node_us_east', region: 'us-east-1' });
    bft.registerNode({ nodeId: 'node_eu_central', region: 'eu-central-1' });
    bft.registerNode({ nodeId: 'node_ap_east', region: 'ap-east-1' });
    bft.registerNode({ nodeId: 'node_sa_east', region: 'sa-east-1' });

    assert.equal(bft.getQuorumThreshold(), 3);

    // Phase 1: Pre-Prepare
    const remediationState = { actionId: 'DNS_UPSTREAM_PIVOT', target: '1.1.1.1', priority: 1 };
    const prePrep = bft.proposePrePrepare(remediationState);
    assert.equal(prePrep.view, 0);
    assert.equal(prePrep.sequenceNumber, 1);

    // Phase 2: Prepare
    bft.handlePrePrepareAndPrepare(prePrep, 'node_us_east');
    bft.handlePrePrepareAndPrepare(prePrep, 'node_eu_central');
    const prep3 = bft.handlePrePrepareAndPrepare(prePrep, 'node_ap_east');
    const prepCert = bft.receivePrepare(prep3);
    assert.ok(prepCert, 'Prepared certificate must form with quorum');
    assert.equal(prepCert.type, 'PREPARED');

    // Phase 3: Commit
    bft.handleCommit('node_us_east', prepCert);
    bft.handleCommit('node_eu_central', prepCert);
    const com3 = bft.handleCommit('node_ap_east', prepCert);
    const commitLog = bft.receiveCommit(com3);
    assert.ok(commitLog, 'Transaction must commit to replicated log');
    assert.equal(commitLog.sequenceNumber, 1);
    assert.ok(commitLog.merkleRoot.length === 64);
  });

  await t.test('6. End-to-End Multi-Region Autonomous Incident Cascade & Sovereign Closed Loop', () => {
    const { ZeroCopyFlowPipeline } = require('../src/systems/streaming/zero-copy-flow-pipeline');
    const { EbpfXdpSynthesizer } = require('../src/sniffer/ebpf-xdp-synthesizer');
    const { ChaosFaultSandbox } = require('../src/systems/remediation/chaos-fault-sandbox');
    const { BftStateMachineReplicator } = require('../src/core/multisite/bft-state-machine-replicator');
    const { RlofPreferenceAligner } = require('../src/ai/rlof-preference-aligner');

    // 1. High-frequency microburst detection in zero-copy pipeline
    const pipeline = new ZeroCopyFlowPipeline(256, 128);
    const burstReport = pipeline.handleMicroBurstInterrupt({
      scale: 2,
      energyRatio: 3.4,
      hurstExponent: 0.88
    });
    assert.ok(burstReport.scale2EnergyRatio > 2.0);

    // 2. Synthesize Line-Rate eBPF XDP Mitigation
    const xdp = new EbpfXdpSynthesizer();
    const generatedRules = xdp.syncCulpritFlowsFromMicroBurst({
      topAttributedFlows: [
        { srcIp: '198.51.100.77', dstIp: '10.0.0.1', srcPort: 443, dstPort: 52145, protocol: 'TCP', suspectedAnomaly: 'FAST_RETRANSMIT_STORM' }
      ]
    });
    assert.equal(generatedRules.length, 1);
    const xdpProg = xdp.synthesizeXdpCProgram();
    assert.equal(xdpProg.verifierValidation.passed, true);

    // 3. Pre-Remediation Chaos Sandbox Stability Validation
    const sandbox = new ChaosFaultSandbox();
    const chaosExp = sandbox.evaluateCandidateRemediation(
      'saga_cascade_001',
      { actionId: 'xdp_mitigation_clamp', actionType: 'TCP_WINDOW_CLAMP', target: '10.0.0.1' },
      { rttMs: 50.0, lossPct: 2.0, queueDepthPackets: 40.0 }
    );
    assert.equal(chaosExp.passed, true);
    assert.ok(chaosExp.lyapunovDriftDeltaV < 0, 'Chaos injection confirms Lyapunov contraction');

    // 4. Distributed BFT Multi-Site Replicated State Logging
    const bft = new BftStateMachineReplicator();
    bft.resetForTesting();
    bft.registerNode({ nodeId: 'n1', region: 'us-east' });
    bft.registerNode({ nodeId: 'n2', region: 'eu-west' });
    bft.registerNode({ nodeId: 'n3', region: 'ap-south' });
    bft.registerNode({ nodeId: 'n4', region: 'sa-east' });

    const bftProposal = bft.proposePrePrepare({
      incidentId: burstReport.burstId,
      mitigationAction: 'TCP_WINDOW_CLAMP',
      chaosReceiptId: chaosExp.receiptId
    });
    bft.handlePrePrepareAndPrepare(bftProposal, 'n1');
    bft.handlePrePrepareAndPrepare(bftProposal, 'n2');
    const p3 = bft.handlePrePrepareAndPrepare(bftProposal, 'n3');
    const cert = bft.receivePrepare(p3);
    assert.ok(cert);

    bft.handleCommit('n1', cert);
    bft.handleCommit('n2', cert);
    const c3 = bft.handleCommit('n3', cert);
    const committed = bft.receiveCommit(c3);
    assert.ok(committed);
    assert.equal(committed.sequenceNumber, 1);

    // 5. RLOF Operator Feedback Loop Aligns Priors for Continuous Learning
    const rlof = new RlofPreferenceAligner();
    const align = rlof.recordPreferenceAndAlign({
      winningAction: 'TCP_WINDOW_CLAMP',
      losingAction: 'DSCP_TRAFFIC_SHAPE',
      contextVector: [0.7, 0.8, 0.6, 0.2],
      operatorId: 'lead-sre'
    });
    assert.ok(align.bradleyTerryLikelihood > 0.0);
    assert.ok(align.triplet.tripletId.startsWith('TRIPLET-'));
  });

});
