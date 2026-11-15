/**
 * Test Suite: Phase 5.0 Track 5 Asymmetric Ed25519 Cryptographic State Vectors & Incremental Merkle Consensus
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const {
  ZkEpistemicConsensusEngine,
  zkEpistemicConsensusEngine
} = require('../src/core/agent/zk-epistemic-consensus');

describe('Phase 5.0 Track 5: Asymmetric Ed25519 Cryptographic State Vectors & Merkle Consensus', () => {

  test('Ed25519 keypair generation and authentic signature verification', () => {
    const engine = new ZkEpistemicConsensusEngine();
    const keyPairA = engine.generateAgentKeyPair();
    const keyPairB = engine.generateAgentKeyPair();

    assert.ok(keyPairA.publicKeyPem.includes('BEGIN PUBLIC KEY'));
    assert.ok(keyPairA.privateKeyPem.includes('BEGIN PRIVATE KEY'));

    const report = {
      agentId: 'agent_edge_01',
      siteId: 'site_us_east',
      epoch: 42,
      timestampIso: new Date().toISOString(),
      beliefs: { DNS_NXDOMAIN_POISON: 0.85, LOCAL_STACK_CONGESTION: 0.15 },
      metricsSummary: { rttMs: 34.5, lossPct: 1.2, queueDepth: 25 }
    };

    // Sign with Key A
    const signed = engine.signReport(report, keyPairA.privateKeyPem);
    assert.ok(signed.signature.length > 20);

    // Verify with Key A public key -> true
    const valid = engine.verifyReportSignature(signed, keyPairA.publicKeyPem);
    assert.equal(valid, true, 'Authentic signature must verify cleanly');

    // Verify with Key B public key -> false
    const invalidKey = engine.verifyReportSignature(signed, keyPairB.publicKeyPem);
    assert.equal(invalidKey, false, 'Signature checked against wrong public key must fail');

    // Tampered payload verification -> false
    const tampered = { ...signed, metricsSummary: { rttMs: 999.0, lossPct: 50.0, queueDepth: 500 } };
    const invalidTamper = engine.verifyReportSignature(tampered, keyPairA.publicKeyPem);
    assert.equal(invalidTamper, false, 'Tampered payload must fail signature verification');
  });

  test('Public key registry enrollment and retrieval via SQLite/in-memory store', () => {
    const engine = new ZkEpistemicConsensusEngine();
    const keyPair = engine.generateAgentKeyPair();

    engine.enrollAgent('agent_edge_registry_01', 'site_eu_west', keyPair.publicKeyPem);
    const retrievedPub = engine.getAgentPublicKey('agent_edge_registry_01');

    assert.equal(retrievedPub, keyPair.publicKeyPem);

    const nonExistent = engine.getAgentPublicKey('agent_unknown_nonexistent');
    assert.equal(nonExistent, null);
  });

  test('Binary Merkle Tree and O(log N) inclusion proofs across 16 edge nodes', () => {
    const engine = new ZkEpistemicConsensusEngine();
    const leafReports = [];
    const leafHashes = [];

    // Create 16 edge agent reports
    for (let i = 0; i < 16; i++) {
      const rep = {
        agentId: `agent_merkle_${i}`,
        siteId: `site_${i % 4}`,
        epoch: 100,
        timestampIso: new Date().toISOString(),
        beliefs: { DNS_NXDOMAIN_POISON: 0.1 * i },
        metricsSummary: { rttMs: 10 + i * 2, lossPct: 0.1 * i, queueDepth: i }
      };
      leafReports.push(rep);
      leafHashes.push(engine.computeLeafHash(rep));
    }

    const tree = engine.buildMerkleTree(leafHashes);
    assert.ok(tree.root.length === 64, 'Merkle root must be 64-character SHA-256 hex string');
    assert.equal(tree.levels.length, 5, '16 leaves must result in 5 tree levels (log2(16) + 1)');

    // Verify cryptographic inclusion proofs for ALL 16 leaves
    for (let i = 0; i < 16; i++) {
      const proof = engine.generateMerkleProof(i, tree, leafReports[i].agentId);
      assert.equal(proof.leafIndex, i);
      assert.equal(proof.merkleRoot, tree.root);
      assert.equal(proof.auditPath.length, 4, 'Audit path for 16 leaves must have length 4');

      const isValid = ZkEpistemicConsensusEngine.verifyMerkleProof(proof);
      assert.equal(isValid, true, `Merkle proof for leaf ${i} must verify to true`);

      // Tampered leaf hash must fail
      const tamperedProof = {
        ...proof,
        leafHash: '0000000000000000000000000000000000000000000000000000000000000000'
      };
      const isTamperedValid = ZkEpistemicConsensusEngine.verifyMerkleProof(tamperedProof);
      assert.equal(isTamperedValid, false, 'Tampered leaf hash must fail verification');
    }
  });

  test('Byzantine Fault Tolerant (BFT) Quorum Consensus with adversarial rejection', () => {
    const engine = new ZkEpistemicConsensusEngine();
    const reports = [];

    // Create 9 honest enrolled agents + 3 malicious byzantine agents
    // Total = 12 agents (N=12, f=3 tolerated, Quorum >= 2f+1 = 7)
    for (let i = 0; i < 9; i++) {
      const keyPair = engine.generateAgentKeyPair();
      const agentId = `honest_agent_${i}`;
      engine.enrollAgent(agentId, 'site_cluster_alpha', keyPair.publicKeyPem);

      const rep = {
        agentId,
        siteId: 'site_cluster_alpha',
        epoch: 50,
        timestampIso: new Date().toISOString(),
        beliefs: { DNS_NXDOMAIN_POISON: 0.70 + (i * 0.01) },
        metricsSummary: { rttMs: 25.0 + i, lossPct: 0.5, queueDepth: 10 + i }
      };

      reports.push(engine.signReport(rep, keyPair.privateKeyPem));
    }

    // Add 3 Byzantine agents: 1 with forged signature, 1 with unregistered key, 1 with corrupted payload
    const attackerKey = engine.generateAgentKeyPair();
    reports.push({
      agentId: 'byzantine_forger_01',
      siteId: 'site_cluster_alpha',
      epoch: 50,
      timestampIso: new Date().toISOString(),
      beliefs: { DNS_NXDOMAIN_POISON: 0.0 },
      metricsSummary: { rttMs: 5.0, lossPct: 0.0, queueDepth: 0 },
      signature: 'FORGED_INVALID_SIGNATURE_BASE64'
    });

    reports.push({
      agentId: 'byzantine_unregistered_02',
      siteId: 'site_cluster_alpha',
      epoch: 50,
      timestampIso: new Date().toISOString(),
      beliefs: { DNS_NXDOMAIN_POISON: 0.0 },
      metricsSummary: { rttMs: 5.0, lossPct: 0.0, queueDepth: 0 },
      signature: engine.signReport({
        agentId: 'byzantine_unregistered_02',
        siteId: 'site_cluster_alpha',
        epoch: 50,
        timestampIso: new Date().toISOString(),
        beliefs: {},
        metricsSummary: { rttMs: 5, lossPct: 0, queueDepth: 0 }
      }, attackerKey.privateKeyPem).signature
    });

    // Execute BFT consensus
    const receipt = engine.aggregateConsensus(50, reports);

    assert.equal(receipt.epoch, 50);
    assert.equal(receipt.totalAgentsReported, 11);
    assert.equal(receipt.validReportsCount, 9);
    assert.equal(receipt.byzantineRejectedCount, 2);
    assert.equal(receipt.quorumAchieved, true);
    assert.ok(receipt.rejectedAgents.includes('byzantine_forger_01'));
    assert.ok(receipt.rejectedAgents.includes('byzantine_unregistered_02'));

    // Check median consensus values
    assert.ok(receipt.consensusBeliefs['DNS_NXDOMAIN_POISON'] >= 0.70);
    assert.equal(receipt.consensusMetrics.medianRttMs, 29.0); // Median of 25..33 is 29

    // Check that Merkle proofs were generated for all valid agents
    assert.equal(Object.keys(receipt.proofs).length, 9);
    for (const validId of receipt.validAgents) {
      const proof = receipt.proofs[validId];
      assert.ok(proof);
      assert.equal(ZkEpistemicConsensusEngine.verifyMerkleProof(proof), true);
    }
  });

  test('Phase 7.0 Track 4: Batch Ed25519 Cryptographic Attestation & Rollup Quorum Receipt O(1) verification', () => {
    const crypto = require('node:crypto');
    const engine = new ZkEpistemicConsensusEngine();

    const node1Key = engine.generateAgentKeyPair();
    const node2Key = engine.generateAgentKeyPair();
    const node3Key = engine.generateAgentKeyPair();

    const payload1 = 'saga_batch_01:node_1:VOTE_COMMIT:-15.4';
    const payload2 = 'saga_batch_01:node_2:VOTE_COMMIT:-8.2';
    const payload3 = 'saga_batch_01:node_3:VOTE_COMMIT:-12.1';

    const sig1 = crypto.sign(null, Buffer.from(payload1, 'utf8'), node1Key.privateKeyPem).toString('base64url');
    const sig2 = crypto.sign(null, Buffer.from(payload2, 'utf8'), node2Key.privateKeyPem).toString('base64url');
    const sig3 = crypto.sign(null, Buffer.from(payload3, 'utf8'), node3Key.privateKeyPem).toString('base64url');

    const items = [
      { nodeId: 'node_1', payload: payload1, signature: sig1, publicKeyPem: node1Key.publicKeyPem },
      { nodeId: 'node_2', payload: payload2, signature: sig2, publicKeyPem: node2Key.publicKeyPem },
      { nodeId: 'node_3', payload: payload3, signature: sig3, publicKeyPem: node3Key.publicKeyPem }
    ];

    const receipt = engine.createBatchQuorumReceipt('saga_batch_01', items);

    assert.equal(receipt.batchReceiptId, 'saga_batch_01');
    assert.equal(receipt.isQuorumValid, true);
    assert.equal(receipt.quorumCount, 3);
    assert.equal(receipt.totalSignatures, 3);
    assert.ok(receipt.merkleRoot.length > 20);
    assert.ok(receipt.aggregatedAttestationDigest.length > 20);

    // Verify valid receipt
    const isValid = ZkEpistemicConsensusEngine.verifyBatchQuorumReceipt(receipt, 'saga_batch_01');
    assert.equal(isValid, true, 'Batch quorum receipt must verify cleanly in O(1)');

    // Verify ID mismatch fails
    const isMismatch = ZkEpistemicConsensusEngine.verifyBatchQuorumReceipt(receipt, 'wrong_saga_id');
    assert.equal(isMismatch, false, 'Batch receipt with mismatched ID must fail verification');

    // Test with one forged signature: quorum fails
    const forgedItems = [
      { nodeId: 'node_1', payload: payload1, signature: sig1, publicKeyPem: node1Key.publicKeyPem },
      { nodeId: 'node_2', payload: payload2, signature: 'forged_invalid_signature', publicKeyPem: node2Key.publicKeyPem }
    ];
    const invalidReceipt = engine.createBatchQuorumReceipt('saga_batch_bad', forgedItems);
    assert.equal(invalidReceipt.isQuorumValid, false);
    assert.equal(invalidReceipt.quorumCount, 1);
    assert.equal(invalidReceipt.totalSignatures, 2);
    assert.equal(ZkEpistemicConsensusEngine.verifyBatchQuorumReceipt(invalidReceipt), false);
  });

});
