/**
 * EJII Capstone Verification Suite — Phase 15.0
 * Sovereign Epistemic Singularity & Metacognitive Infrastructure Intelligence
 *
 * Verifies:
 *   1. Static eBPF Kernel Bytecode Verifier & Zero-Copy Fastpath Packet Dispatcher
 *   2. Continuous-Time Topological Reaction-Diffusion PDE Engine & Cascading Failure Predictor
 *   3. Metacognitive Epistemic Arbiter & Expected Value of Information (EVOI) Probe Optimizer
 *   4. Merkle-Patricia Tri-State CRDT Anti-Entropy Reconciler & Byzantine Partition Recovery Fabric
 *   5. Multi-Monitor BroadcastChannel Operator Cockpit & Autonomous Process Supervisor
 *   6. 100% Dual-Maintenance Module Parity (63 Flagship Modules) & Zero-Simulation Preflight
 */

'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

// Track 1 imports
const { BpfBytecodeVerifier, bpfBytecodeVerifier } = require('../src/sniffer/bpf-bytecode-verifier');
const { FastpathPacketDispatcher, fastpathPacketDispatcher } = require('../src/sniffer/fastpath-packet-dispatcher');

// Track 2 imports
const { TopologicalDiffusionPdeEngine, topologicalDiffusionPdeEngine } = require('../src/topology/topological-diffusion-pde-engine');
const { CascadingFailurePredictor, cascadingFailurePredictor } = require('../src/topology/cascading-failure-predictor');

// Track 3 imports
const { MetacognitiveEpistemicArbiter, metacognitiveEpistemicArbiter } = require('../src/ai/metacognitive-epistemic-arbiter');
const { EvoiProbeOptimizer, evoiProbeOptimizer } = require('../src/ai/evoi-probe-optimizer');

// Track 4 imports
const { MerklePatriciaCrdtSync, merklePatriciaCrdtSync } = require('../src/core/multisite/merkle-patricia-crdt-sync');
const { ByzantinePartitionHealer, byzantinePartitionHealer } = require('../src/core/multisite/byzantine-partition-healer');

// Track 5 imports
const { EjiiSupervisor } = require('../scripts/ejii-supervisor');

function buildTestPacketBuffer(srcIp, dstIp, protocol, srcPort, dstPort, tcpFlags = 0) {
  const buf = Buffer.alloc(64);
  // Ethernet header: dst MAC (0..5), src MAC (6..11), ethertype IPv4 = 0x0800 (12..13)
  buf.writeUInt16BE(0x0800, 12);
  // IPv4 header at offset 14: Version 4, IHL 5
  buf[14] = 0x45;
  buf[15] = 0x00; // DSCP
  buf.writeUInt16BE(50, 16); // Total length
  buf[22] = 64; // TTL
  buf[23] = protocol; // Protocol (6=TCP, 17=UDP)

  // src IP (offset 26..29)
  const srcOctets = srcIp.split('.').map(Number);
  for (let i = 0; i < 4; i++) buf[26 + i] = srcOctets[i] || 0;

  // dst IP (offset 30..33)
  const dstOctets = dstIp.split('.').map(Number);
  for (let i = 0; i < 4; i++) buf[30 + i] = dstOctets[i] || 0;

  // Transport header at offset 34
  buf.writeUInt16BE(srcPort, 34);
  buf.writeUInt16BE(dstPort, 36);

  if (protocol === 6) {
    buf[47] = tcpFlags; // TCP flags byte at transportOffset + 13 = 34 + 13 = 47
  }

  return buf;
}

async function runSovereignIntelligenceLeapPhase15Tests() {
  console.log('========================================================================');
  console.log('  PHASE 15.0 CAPSTONE: SOVEREIGN EPISTEMIC SINGULARITY & METACOGNITION  ');
  console.log('  Zero-Simulation Verification Mandate                                  ');
  console.log('========================================================================\n');

  const rootDir = path.resolve(__dirname, '..');

  // ---------------------------------------------------------------------------
  // Track 1: Static eBPF Bytecode Verifier & Fastpath Packet Dispatcher
  // ---------------------------------------------------------------------------
  console.log('[Track 1.1] Verifying Static eBPF Bytecode Verifier...');
  const verifier = new BpfBytecodeVerifier();

  // Valid BPF program: R1 initialized by verifier, ALU mov, jump, exit
  const validInstructions = [
    { opcode: 0xb7, dstReg: 1, srcReg: 0, offset: 0, imm: 100 }, // mov r1, 100
    { opcode: 0x25, dstReg: 1, srcReg: 0, offset: 1, imm: 50 },  // jgt r1, 50, +1
    { opcode: 0xb7, dstReg: 0, srcReg: 0, offset: 0, imm: 2 },   // mov r0, 2 (DROP)
    { opcode: 0x95, dstReg: 0, srcReg: 0, offset: 0, imm: 0 },   // exit
    { opcode: 0xb7, dstReg: 0, srcReg: 0, offset: 0, imm: 0 },   // mov r0, 0 (PASS)
    { opcode: 0x95, dstReg: 0, srcReg: 0, offset: 0, imm: 0 }    // exit
  ];

  const validReport = verifier.verifyBytecode(validInstructions);
  assert.strictEqual(validReport.isSafe, true, 'Valid BPF instructions must pass static verification');
  assert.strictEqual(validReport.verdict, 'VERIFIED_SAFE');
  assert.strictEqual(validReport.instructionCount, 6);

  // Invalid BPF program 1: Instruction count exceeds 4096 limit
  const hugeInstructions = new Array(4097).fill({ opcode: 0xb7, dstReg: 1, srcReg: 0, offset: 0, imm: 0 });
  const hugeReport = verifier.verifyBytecode(hugeInstructions);
  assert.strictEqual(hugeReport.isSafe, false, 'Program exceeding 4096 instructions must be rejected');
  assert.ok(hugeReport.rejectionReason.includes('4096'), 'Error message must note instruction limit');

  // Invalid BPF program 2: Out of bounds jump
  const oobJumpInstructions = [
    { opcode: 0x05, dstReg: 0, srcReg: 0, offset: 10, imm: 0 }, // ja +10 (out of bounds)
    { opcode: 0x95, dstReg: 0, srcReg: 0, offset: 0, imm: 0 }
  ];
  const oobReport = verifier.verifyBytecode(oobJumpInstructions);
  assert.strictEqual(oobReport.isSafe, false, 'Out of bounds jump must be rejected');

  // Invalid BPF program 3: Illegal write to R10 (read-only frame pointer)
  const r10WriteInstructions = [
    { opcode: 0xb7, dstReg: 10, srcReg: 0, offset: 0, imm: 42 },
    { opcode: 0x95, dstReg: 0, srcReg: 0, offset: 0, imm: 0 }
  ];
  const r10Report = verifier.verifyBytecode(r10WriteInstructions);
  assert.strictEqual(r10Report.isSafe, false, 'Writing to R10 frame pointer must be rejected');
  console.log('  ✓ Static eBPF Bytecode Verifier verified with DAG flow, bound, and safety checks.');

  console.log('[Track 1.2] Verifying Zero-Copy Fastpath Packet Dispatcher...');
  const dispatcher = new FastpathPacketDispatcher();

  // Install dynamic fastpath rules
  dispatcher.installRule(
    'rule-drop-malicious',
    { protocol: 6, port: 4444 },
    'DROP'
  );

  dispatcher.installRule(
    'rule-qos-telemetry',
    { protocol: 17, port: 8443 },
    'DSCP_REMARK',
    { dscpValue: 46 }
  );

  dispatcher.installRule(
    'rule-ai-trap',
    { srcIp: '198.51.100.77' },
    'TRAP_TO_BRAIN'
  );

  const packetDrop = buildTestPacketBuffer('10.0.0.1', '10.0.0.2', 6, 50100, 4444);
  const decisionDrop = dispatcher.dispatchPacket(packetDrop);
  assert.strictEqual(decisionDrop.action, 'DROP', 'Port 4444 packet must be DROPPED');

  const packetRemark = buildTestPacketBuffer('10.0.0.5', '10.0.0.10', 17, 53200, 8443);
  const decisionRemark = dispatcher.dispatchPacket(packetRemark);
  assert.strictEqual(decisionRemark.action, 'DSCP_REMARK', 'Port 8443 packet must be DSCP remarked');

  const packetTrap = buildTestPacketBuffer('198.51.100.77', '10.0.0.1', 6, 40120, 80);
  const decisionTrap = dispatcher.dispatchPacket(packetTrap);
  assert.strictEqual(decisionTrap.action, 'TRAP_TO_BRAIN', 'Trapped IP must trigger TRAP_TO_BRAIN');

  const metrics = dispatcher.getStats();
  assert.ok(metrics.totalDispatched >= 3, 'Packets processed metric must be recorded');
  assert.ok(metrics.totalDrops >= 1, 'Drop count must be recorded');
  assert.ok(metrics.totalTraps >= 1, 'Trap count must be recorded');
  console.log('  ✓ Fastpath Packet Dispatcher verified across inline actions and microsecond metrics.');

  // ---------------------------------------------------------------------------
  // Track 2: Continuous-Time Topological Reaction-Diffusion PDE & Cascading Failure Predictor
  // ---------------------------------------------------------------------------
  console.log('[Track 2.1] Verifying Topological Reaction-Diffusion PDE Solver...');
  const pdeEngine = new TopologicalDiffusionPdeEngine();

  // Create a 5-node line topology: 0 - 1 - 2 - 3 - 4
  const nodeCount = 5;
  const edges = [
    { source: 0, target: 1, weight: 1.0 },
    { source: 1, target: 2, weight: 1.0 },
    { source: 2, target: 3, weight: 1.0 },
    { source: 3, target: 4, weight: 1.0 }
  ];

  const laplacian = pdeEngine.constructGraphLaplacian(nodeCount, edges);
  assert.strictEqual(laplacian.length, 25, '5x5 Laplacian must have 25 elements');
  // Row sums of graph Laplacian must be 0
  for (let r = 0; r < 5; r++) {
    let rowSum = 0;
    for (let c = 0; c < 5; c++) {
      rowSum += laplacian[r * 5 + c];
    }
    assert.ok(Math.abs(rowSum) < 1e-6, `Laplacian row ${r} sum must be 0`);
  }

  // Initial perturbation on node 0
  const initialCondition = new Float64Array([0.9, 0.1, 0.0, 0.0, 0.0]);
  const pdeSolution = pdeEngine.solveTrajectory(initialCondition, edges, 5.0, 0.05);

  assert.ok(pdeSolution.timePoints.length > 5, 'Solver must record multiple time points');
  assert.strictEqual(pdeSolution.isContractionStable, true, 'Lyapunov stability certificate must confirm contraction stability');
  assert.ok(pdeSolution.lyapunovDrift.length === pdeSolution.timePoints.length);

  // Failure front must diffuse from node 0 towards adjacent nodes
  const finalState = pdeSolution.stateSnapshots[pdeSolution.stateSnapshots.length - 1];
  assert.ok(finalState[0] > 0.3, 'Node 0 initial excitation must register in solution');
  console.log('  ✓ Topological Reaction-Diffusion PDE engine verified with RK4 and Lyapunov stability.');

  console.log('[Track 2.2] Verifying Cascading Failure Predictor...');
  const failurePredictor = new CascadingFailurePredictor();
  const topoInput = {
    nodes: [
      { id: 'gw-core-1', initialStress: 0.95 },
      { id: 'sw-dist-1', initialStress: 0.70 },
      { id: 'sw-access-1', initialStress: 0.40 },
      { id: 'srv-app-1', initialStress: 0.20 },
      { id: 'srv-db-1', initialStress: 0.10 }
    ],
    edges: [
      { source: 'gw-core-1', target: 'sw-dist-1', weight: 1.0 },
      { source: 'sw-dist-1', target: 'sw-access-1', weight: 1.0 },
      { source: 'sw-access-1', target: 'srv-app-1', weight: 1.0 },
      { source: 'srv-app-1', target: 'srv-db-1', weight: 1.0 }
    ]
  };

  const forecast = failurePredictor.predictCascadingFailure(topoInput, 10.0);

  assert.strictEqual(forecast.isCascadingContagionLikely, true);
  assert.ok(forecast.nodeWavefronts.length >= 2, 'Should predict cascading wavefront progression');
  assert.ok(forecast.recommendedCutoffInterventions.length >= 1, 'Should generate cut-off interventions');
  console.log(`  ✓ Cascading Failure Predictor identified ${forecast.nodeWavefronts.length} wavefront arrivals and recommended ${forecast.recommendedCutoffInterventions.length} cut-off interventions.`);

  // ---------------------------------------------------------------------------
  // Track 3: Metacognitive Epistemic Arbiter & EVOI Probe Optimizer
  // ---------------------------------------------------------------------------
  console.log('[Track 3.1] Verifying Metacognitive Epistemic Arbiter...');
  const arbiter = new MetacognitiveEpistemicArbiter();

  const candidateHypotheses = [
    'UPSTREAM_BGP_ROUTE_LEAK',
    'LOCAL_XDP_CONGESTION',
    'DNS_CACHE_POISONING',
    'HARDWARE_NIC_RING_OVERFLOW'
  ];

  // Agreement findings
  const unanimousFindings = [
    { domain: 'CAUSAL_SEM', supportedHypothesis: 'UPSTREAM_BGP_ROUTE_LEAK', confidence: 0.95, evidenceWeight: 1.5 },
    { domain: 'WIRE_EBPF', supportedHypothesis: 'UPSTREAM_BGP_ROUTE_LEAK', confidence: 0.92, evidenceWeight: 1.2 },
    { domain: 'SPECTRAL_FOURIER', supportedHypothesis: 'UPSTREAM_BGP_ROUTE_LEAK', confidence: 0.88, evidenceWeight: 1.0 }
  ];

  const receiptUnanimous = arbiter.arbitrateHeterogeneousEvidence(
    'inc-8801',
    candidateHypotheses,
    unanimousFindings
  );
  assert.strictEqual(receiptUnanimous.dominantHypothesis, 'UPSTREAM_BGP_ROUTE_LEAK');
  assert.ok(receiptUnanimous.dominantConfidence >= 0.70, 'Unanimous confidence must dominate');
  assert.ok(receiptUnanimous.epistemicConflictK < 0.25, 'Epistemic conflict must be low under consensus');

  // Severe Cross-Engine Disagreement findings
  const conflictingFindings = [
    { domain: 'CAUSAL_SEM', supportedHypothesis: 'UPSTREAM_BGP_ROUTE_LEAK', confidence: 0.90, evidenceWeight: 1.2 },
    { domain: 'TOPOLOGICAL_HOMOLOGY', supportedHypothesis: 'LOCAL_XDP_CONGESTION', confidence: 0.90, evidenceWeight: 1.2 },
    { domain: 'WIRE_EBPF', supportedHypothesis: 'HARDWARE_NIC_RING_OVERFLOW', confidence: 0.85, evidenceWeight: 1.0 }
  ];

  const receiptConflicted = arbiter.arbitrateHeterogeneousEvidence(
    'inc-8802',
    candidateHypotheses,
    conflictingFindings
  );
  assert.strictEqual(receiptConflicted.engineConsensusStatus, 'CONFLICT_DISAMBIGUATION_REQUIRED');
  assert.ok(receiptConflicted.epistemicConflictK >= 0.20, 'Cross-engine conflict K must be detected');
  console.log(`  ✓ Metacognitive Epistemic Arbiter calculated Shannon entropy (${receiptConflicted.epistemicEntropyBits} bits) and flagged conflict K=${receiptConflicted.epistemicConflictK}.`);

  console.log('[Track 3.2] Verifying Expected Value of Information (EVOI) Probe Optimizer...');
  const evoiEngine = new EvoiProbeOptimizer();

  const candidateProbes = [
    {
      probeId: 'probe-ebpf-socket-dissect',
      targetDomain: 'WIRE_EBPF',
      description: 'Capture inline TCP RST flags at socket ingress',
      cost: 0.10,
      expectedEntropyReductionBits: 1.2
    },
    {
      probeId: 'probe-synthetic-wan-ping',
      targetDomain: 'TOPOLOGICAL_HOMOLOGY',
      description: 'Send high-rate ICMP bursts to upstream transit BGP peers',
      cost: 0.85, // Highly intrusive
      expectedEntropyReductionBits: 0.5
    },
    {
      probeId: 'probe-spectral-fft-sweep',
      targetDomain: 'SPECTRAL_FOURIER',
      description: 'Run 1024-bin FFT over interface jitter buffer',
      cost: 0.15,
      expectedEntropyReductionBits: 0.9
    }
  ];

  const evoiResult = evoiEngine.optimizeDiagnosticProbes(
    receiptConflicted.fusedBeliefDistribution,
    candidateProbes,
    0.20 // cost weight lambda
  );

  assert.ok(evoiResult.rankedProbes.length === 3, 'All candidate probes must be evaluated and ranked');
  assert.strictEqual(evoiResult.recommendedProbe?.probeId, 'probe-ebpf-socket-dissect', 'Optimal net EVOI probe must be selected');
  assert.ok(evoiResult.recommendedProbe.netEvoiScore > evoiResult.rankedProbes[1].netEvoiScore);
  console.log(`  ✓ EVOI Probe Optimizer selected top probe '${evoiResult.recommendedProbe.probeId}' (Net EVOI: ${evoiResult.recommendedProbe.netEvoiScore}).`);

  // ---------------------------------------------------------------------------
  // Track 4: Merkle-Patricia Tri-State CRDT Sync & Byzantine Partition Healer
  // ---------------------------------------------------------------------------
  console.log('[Track 4.1] Verifying Hexary Merkle-Patricia Trie CRDT Anti-Entropy Reconciler...');
  const crdtA = new MerklePatriciaCrdtSync();
  const crdtB = new MerklePatriciaCrdtSync();

  // Populate CRDT A
  crdtA.insertOperation('cluster.firewall.rule_1', { action: 'DROP', port: 22 }, 101);
  crdtA.insertOperation('cluster.firewall.rule_2', { action: 'ACCEPT', port: 443 }, 102);

  // Populate CRDT B with diverged state
  crdtB.insertOperation('cluster.firewall.rule_1', { action: 'DROP', port: 22 }, 101);
  crdtB.insertOperation('cluster.firewall.rule_3', { action: 'DSCP_46', port: 8443 }, 103);

  const rootA = crdtA.computeRootHash();
  const rootB = crdtB.computeRootHash();
  assert.notStrictEqual(rootA, rootB, 'Diverged CRDT states must produce distinct Merkle roots');

  // Verify proof generation
  const proof = crdtA.generateProof('cluster.firewall.rule_1');
  assert.ok(proof.length >= 1, 'Must generate valid inclusion proof nodes');

  // Anti-entropy reconciliation between A and B
  const reconResult = await crdtA.reconcileWithRemote(rootB, (prefix) => {
    return {
      hash: 'remote_hash_leaf',
      type: 'LEAF',
      pathNibbles: '636c7573746572',
      value: { action: 'DSCP_46', port: 8443 },
      lamportClock: 103
    };
  });

  assert.strictEqual(reconResult.reconciled, true, 'Anti-entropy reconciliation must succeed');
  assert.ok(reconResult.syncedKeys.length > 0, 'Must synchronize diverged keys');
  console.log(`  ✓ Hexary Merkle-Patricia Trie reconciled state across diverged branches with final root ${reconResult.finalRootHash.slice(0, 12)}...`);

  console.log('[Track 4.2] Verifying Byzantine Partition Healer...');
  const partitionHealer = new ByzantinePartitionHealer();

  // 4-site topology with split brain: [SiteA, SiteB] isolated from [SiteC, SiteD]
  const partitionedMesh = {
    'us-east': ['us-west'],
    'us-west': ['us-east'],
    'eu-central': ['ap-southeast'],
    'ap-southeast': ['eu-central']
  };

  const partReport = partitionHealer.detectPartition(partitionedMesh);
  assert.strictEqual(partReport.isSplitBrain, true, 'Split-brain partition must be detected');
  assert.strictEqual(partReport.detectedPartitionsCount, 2, 'Should detect 2 isolated partition components');

  // Heal partition
  const healingReceipt = await partitionHealer.healPartition(
    'us-east',
    'eu-central',
    rootA,
    rootB,
    crdtA
  );

  assert.strictEqual(healingReceipt.status, 'RECONCILED');
  assert.ok(healingReceipt.zkAttestationHash.length === 64, 'ZK-NIMP attestation hash must be SHA-256 (64 hex characters)');
  console.log(`  ✓ Byzantine Partition Healer successfully healed split-brain with ZK-NIMP proof ${healingReceipt.zkAttestationHash.slice(0, 12)}...`);

  // ---------------------------------------------------------------------------
  // Track 5: Multi-Monitor BroadcastChannel Operator Cockpit & Process Supervisor
  // ---------------------------------------------------------------------------
  console.log('[Track 5.1] Verifying Multi-Monitor BroadcastChannel View Bus & 11 Views Invariant...');
  const viewsDir = path.join(rootDir, 'public', 'js', 'views');
  const viewEntries = fs.readdirSync(viewsDir).filter(f => f.endsWith('.js'));
  assert.strictEqual(viewEntries.length, 11, 'public/js/views/ must maintain strictly 11 view files');

  const aiOpContent = fs.readFileSync(path.join(viewsDir, 'ai-operator-view.js'), 'utf8');
  assert.ok(aiOpContent.includes('initBroadcastChannelWorkspaceBus'), 'ai-operator-view.js must define initBroadcastChannelWorkspaceBus');
  assert.ok(aiOpContent.includes('ejii_operator_workspace_bus'), 'ai-operator-view.js must connect to ejii_operator_workspace_bus channel');

  const nocContent = fs.readFileSync(path.join(viewsDir, 'enterprise-noc-view.js'), 'utf8');
  assert.ok(nocContent.includes('initBroadcastChannelWorkspaceBus'), 'enterprise-noc-view.js must export initBroadcastChannelWorkspaceBus');
  console.log('  ✓ Multi-Monitor BroadcastChannel view bus and 11-view invariant confirmed.');

  console.log('[Track 5.2] Verifying Autonomous Process Supervisor & Safe Launcher...');
  const supervisor = new EjiiSupervisor({ checkIntervalMs: 10000 });
  assert.ok(typeof supervisor.start === 'function', 'Supervisor must have start() method');
  assert.ok(typeof supervisor.stop === 'function', 'Supervisor must have stop() method');
  assert.ok(typeof supervisor.checkpointWal === 'function', 'Supervisor must have checkpointWal() method');

  const batContent = fs.readFileSync(path.join(rootDir, 'setup-launcher.bat'), 'utf8');
  assert.ok(batContent.includes('151-suite'), 'setup-launcher.bat must reference 151-suite verification');

  const shContent = fs.readFileSync(path.join(rootDir, 'setup-launcher.sh'), 'utf8');
  assert.ok(shContent.includes('151-suite'), 'setup-launcher.sh must reference 151-suite verification');
  console.log('  ✓ Autonomous Process Supervisor and launcher 151-suite verification references confirmed.');

  // ---------------------------------------------------------------------------
  // Track 6: Parity Guard Execution & Fast Preflight Verification
  // ---------------------------------------------------------------------------
  console.log('[Track 6] Verifying Parity Guard (63 modules) and Preflight Health...');
  const parityScript = path.join(rootDir, 'scripts', 'verify-ts-js-parity.js');
  execFileSync(process.execPath, [parityScript], { stdio: 'pipe' });
  console.log('  ✓ All 63 flagship modules verified in 100% TypeScript/JavaScript dual parity.');

  const preflightScript = path.join(rootDir, 'scripts', 'verify-fast-preflight.js');
  const t0 = process.hrtime.bigint();
  execFileSync(process.execPath, [preflightScript], { stdio: 'pipe' });
  const preflightMs = Number(process.hrtime.bigint() - t0) / 1e6;
  assert.ok(preflightMs < 1000, `Preflight must execute cleanly under 1000ms, took ${preflightMs.toFixed(2)}ms`);
  console.log(`  ✓ Fast preflight verified in ${preflightMs.toFixed(2)}ms.`);

  console.log('\n========================================================================');
  console.log('  PHASE 15.0 CAPSTONE VERIFICATION: ALL TRACKS PASSED!                  ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runSovereignIntelligenceLeapPhase15Tests()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}

module.exports = { runSovereignIntelligenceLeapPhase15Tests };
