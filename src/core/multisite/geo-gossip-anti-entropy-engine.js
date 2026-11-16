/**
 * EJII Autonomous Cross-Datacenter Geo-Gossip & Anti-Entropy Sync Engine
 * Phase 22.0 Distributed Infrastructure Layer
 *
 * Dual-Maintenance CommonJS Implementation.
 */

'use strict';

const crypto = require('node:crypto');
const { deltaCrdtStateCheckpointer } = require('./delta-crdt-state-checkpointer');

class GeoGossipAntiEntropyEngine {
  constructor(localNodeId = 'node_dc1_primary') {
    this.localNodeId = localNodeId;
    this.peers = new Map();
    this.incarnation = 1;
    this.leaseTtlMs = 15000;
  }

  registerPeer(peerId, endpoint = '127.0.0.1:9001', initialStatus = 'ALIVE') {
    const peer = {
      peerId,
      endpoint,
      status: initialStatus,
      lastSeenMs: Date.now(),
      stateMerkleRoot: '0'.repeat(64),
      vectorClock: { [peerId]: 1 },
      incarnation: 1
    };
    this.peers.set(peerId, peer);
    return peer;
  }

  updatePeerHeartbeat(peerId, stateMerkleRoot, vectorClock = {}) {
    if (peerId === this.localNodeId) {
      return true;
    }
    const peer = this.peers.get(peerId);
    if (!peer) {
      this.registerPeer(peerId, '127.0.0.1:9001', 'ALIVE');
      const newlyAdded = this.peers.get(peerId);
      newlyAdded.stateMerkleRoot = stateMerkleRoot;
      newlyAdded.vectorClock = vectorClock;
      newlyAdded.lastSeenMs = Date.now();
      return true;
    }

    peer.status = 'ALIVE';
    peer.stateMerkleRoot = stateMerkleRoot;
    peer.vectorClock = { ...peer.vectorClock, ...vectorClock };
    peer.lastSeenMs = Date.now();
    return true;
  }

  generateGossipProbe(targetPeerId) {
    const probeId = `gsp_${crypto.randomBytes(4).toString('hex')}`;
    const localState = deltaCrdtStateCheckpointer.getState();
    const localMerkle = deltaCrdtStateCheckpointer.computeStateMerkleRoot(localState);
    const vectorClock = deltaCrdtStateCheckpointer.getVectorClock();

    return {
      probeId,
      senderNodeId: this.localNodeId,
      targetPeerId,
      stateMerkleRoot: localMerkle,
      vectorClock,
      sentAtMs: Date.now()
    };
  }

  receiveGossipProbe(probe) {
    this.updatePeerHeartbeat(probe.senderNodeId, probe.stateMerkleRoot, probe.vectorClock);

    const localState = deltaCrdtStateCheckpointer.getState();
    const localMerkle = deltaCrdtStateCheckpointer.computeStateMerkleRoot(localState);
    const matched = localMerkle === probe.stateMerkleRoot;

    return {
      probeId: probe.probeId,
      matchedMerkleRoot: matched,
      antiEntropyRequired: !matched,
      localMerkleRoot: localMerkle,
      remoteMerkleRoot: probe.stateMerkleRoot,
      receivedAtMs: Date.now()
    };
  }

  evaluateQuorumLease() {
    const now = Date.now();
    let aliveCount = 1; // Include self
    const totalPeers = this.peers.size + 1;

    for (const peer of this.peers.values()) {
      if (now - peer.lastSeenMs < 10000 && peer.status === 'ALIVE') {
        aliveCount++;
      } else if (now - peer.lastSeenMs >= 10000) {
        peer.status = 'SUSPECT';
      }
    }

    const quorumThreshold = Math.floor(totalPeers / 2) + 1;
    const hasActiveLease = aliveCount >= quorumThreshold;

    return {
      hasActiveLease,
      clusterRole: hasActiveLease ? 'PRIMARY_WRITER' : 'FENCED_REPLICA',
      activePeersCount: aliveCount,
      totalPeersCount: totalPeers,
      quorumThreshold,
      leaseExpiresAtMs: now + this.leaseTtlMs
    };
  }

  getPeerTable() {
    return Array.from(this.peers.values());
  }

  getLocalNodeId() {
    return this.localNodeId;
  }
}

const geoGossipAntiEntropyEngine = new GeoGossipAntiEntropyEngine();

module.exports = {
  GeoGossipAntiEntropyEngine,
  geoGossipAntiEntropyEngine
};
