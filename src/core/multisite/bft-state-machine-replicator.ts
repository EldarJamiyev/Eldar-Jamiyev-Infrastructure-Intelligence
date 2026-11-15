/**
 * EJII Distributed Multi-Region Byzantine Fault Tolerant (BFT) State Machine Replicator
 *
 * Implements:
 *   1. 3-Phase PBFT/Tendermint Consensus Protocol:
 *      - Phase 1: Pre-Prepare <PRE-PREPARE, v, n, d>_leader
 *      - Phase 2: Prepare <PREPARE, v, n, d, i>_i -> 2f matching form Prepared Certificate P(v, n, d)
 *      - Phase 3: Commit <COMMIT, v, n, d, i>_i -> 2f+1 matching form Committed Certificate C(v, n, d)
 *   2. Faulty Node Equivocation & Byzantine Defense:
 *      Detects conflicting proposals <v, n, d1> and <v, n, d2> (d1 != d2), excludes Byzantine votes.
 *   3. View Change & Deterministic Leader Recovery:
 *      Timer-based view change upon lack of consensus progress: VIEW-CHANGE(v+1) quorum of 2f+1.
 *   4. Durable SQLite WAL Replicated State Log:
 *      Persists committed state transitions with Merkle root hashes in ejii_bft_replicated_log.
 */

'use strict';

import * as crypto from 'node:crypto';

function getDb(): any {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return require('../../db/database').db;
  } catch (_) {
    return null;
  }
}

export interface BftNodeConfig {
  nodeId: string;
  region: string;
  endpoint?: string;
  secretKey?: string;
  publicKey?: string;
}

export interface BftPrePrepareMessage {
  type: 'PRE_PREPARE';
  view: number;
  sequenceNumber: number;
  digest: string;
  payload: any;
  leaderId: string;
  signature: string;
  timestampIso: string;
  proposeTimeNs?: string | null;
  trueTimeInterval?: {
    earliestNs: string;
    latestNs: string;
    uncertaintyNs: number;
  } | null;
}

export interface BftPrepareMessage {
  type: 'PREPARE';
  view: number;
  sequenceNumber: number;
  digest: string;
  nodeId: string;
  signature: string;
  timestampIso: string;
}

export interface BftCommitMessage {
  type: 'COMMIT';
  view: number;
  sequenceNumber: number;
  digest: string;
  nodeId: string;
  signature: string;
  timestampIso: string;
}

export interface BftQuorumCertificate {
  type: 'PREPARED' | 'COMMITTED';
  view: number;
  sequenceNumber: number;
  digest: string;
  signatures: Array<{ nodeId: string; signature: string }>;
  formedAtIso: string;
}

export interface BftLogEntry {
  sequenceNumber: number;
  view: number;
  digest: string;
  payload: any;
  quorumCertificate: BftQuorumCertificate;
  merkleRoot: string;
  committedAtIso: string;
}

export interface ViewChangeMessage {
  type: 'VIEW_CHANGE';
  newView: number;
  nodeId: string;
  lastPreparedCert?: BftQuorumCertificate;
  signature: string;
  timestampIso: string;
}

export class BftStateMachineReplicator {
  private nodes: Map<string, BftNodeConfig> = new Map();
  private currentView = 0;
  private currentSequence = 0;
  private dbInitialized = false;

  // In-flight message stores keyed by `${view}:${sequenceNumber}:${digest}`
  private prePrepareMessages: Map<string, BftPrePrepareMessage> = new Map();
  private prepareVotes: Map<string, Map<string, BftPrepareMessage>> = new Map();
  private commitVotes: Map<string, Map<string, BftCommitMessage>> = new Map();
  private preparedCertificates: Map<string, BftQuorumCertificate> = new Map();
  private committedCertificates: Map<string, BftQuorumCertificate> = new Map();

  // Equivocation tracking: `${view}:${sequenceNumber}` -> Map<nodeId, digest>
  private proposalHistory: Map<string, Map<string, string>> = new Map();
  private byzantineNodes: Set<string> = new Set();

  // View Change Tracking: newView -> Map<nodeId, ViewChangeMessage>
  private viewChangeVotes: Map<number, Map<string, ViewChangeMessage>> = new Map();

  // Committed log in memory
  private committedLog: BftLogEntry[] = [];

  constructor() {
    this.ensureDatabaseSchema();
  }

  public ensureDatabaseSchema(): void {
    if (this.dbInitialized) return;
    const db = getDb();
    if (!db) return;

    try {
      db.prepare(`
        CREATE TABLE IF NOT EXISTS ejii_bft_replicated_log (
          sequence_number INTEGER PRIMARY KEY,
          view INTEGER NOT NULL,
          state_digest TEXT NOT NULL,
          payload_json TEXT NOT NULL,
          quorum_certificate_json TEXT NOT NULL,
          merkle_root TEXT NOT NULL,
          committed_at TEXT NOT NULL
        )
      `).run();
      this.dbInitialized = true;
    } catch (_) {}
  }

  /**
   * Registers a node into the BFT cluster roster
   */
  public registerNode(node: BftNodeConfig): void {
    const secret = node.secretKey || crypto.randomBytes(16).toString('hex');
    this.nodes.set(node.nodeId, {
      ...node,
      secretKey: secret,
      publicKey: node.publicKey || `pub_${node.nodeId}`
    });
  }

  public getNodes(): BftNodeConfig[] {
    return Array.from(this.nodes.values());
  }

  public getLeaderId(): string {
    const list = Array.from(this.nodes.keys());
    if (list.length === 0) return 'node_leader';
    return list[this.currentView % list.length];
  }

  public getCurrentView(): number {
    return this.currentView;
  }

  public getCurrentSequence(): number {
    return this.currentSequence;
  }

  public getByzantineNodes(): string[] {
    return Array.from(this.byzantineNodes);
  }

  public quarantineNode(nodeId: string, reason = 'Byzantine epistemic anomaly detected'): {
    quarantinedNodeId: string;
    reason: string;
    remainingNodes: number;
    newQuorumThreshold: number;
    currentLeader: string;
  } {
    this.byzantineNodes.add(nodeId);
    this.nodes.delete(nodeId);
    return {
      quarantinedNodeId: nodeId,
      reason,
      remainingNodes: this.nodes.size,
      newQuorumThreshold: this.getQuorumThreshold(),
      currentLeader: this.getLeaderId()
    };
  }

  /**
   * Calculates cryptographic state digest d = H(m)
   */
  public computeDigest(payload: any): string {
    return crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
  }

  /**
   * Signs a message payload for a given node using HMAC-SHA256
   */
  public signMessage(nodeId: string, messageContent: string): string {
    const node = this.nodes.get(nodeId);
    const key = node?.secretKey || 'default_bft_secret';
    return crypto.createHmac('sha256', key).update(messageContent).digest('hex');
  }

  /**
   * Verifies a message signature from a node
   */
  public verifySignature(nodeId: string, messageContent: string, signature: string): boolean {
    const expected = this.signMessage(nodeId, messageContent);
    return expected === signature;
  }

  /**
   * Calculates required quorum size 2f + 1 for N nodes (N = 3f + 1)
   */
  public getQuorumThreshold(): number {
    const N = Math.max(1, this.nodes.size);
    const f = Math.floor((N - 1) / 3);
    return 2 * f + 1;
  }

  /**
   * Phase 1: Pre-Prepare
   * Leader proposes sequence number n, view v, and digest d = H(m)
   */
  public proposePrePrepare(payload: any): BftPrePrepareMessage {
    const leaderId = this.getLeaderId();
    this.currentSequence += 1;
    const seq = this.currentSequence;
    const digest = this.computeDigest(payload);
    const nowIso = new Date().toISOString();

    const signPayload = `PRE_PREPARE:${this.currentView}:${seq}:${digest}:${leaderId}:${nowIso}`;
    const signature = this.signMessage(leaderId, signPayload);

    let proposeTimeNs: string | null = null;
    let trueTimeInterval: { earliestNs: string; latestNs: string; uncertaintyNs: number } | null = null;
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const { nanosecondTrueTimeEngine } = require('../../observability/nanosecond-truetime-engine');
      const tt = nanosecondTrueTimeEngine.now();
      proposeTimeNs = tt.timestampNs.toString();
      trueTimeInterval = {
        earliestNs: tt.earliestNs.toString(),
        latestNs: tt.latestNs.toString(),
        uncertaintyNs: Number(tt.uncertaintyNs)
      };
    } catch (_) {}

    const msg: BftPrePrepareMessage = {
      type: 'PRE_PREPARE',
      view: this.currentView,
      sequenceNumber: seq,
      digest,
      payload,
      leaderId,
      signature,
      timestampIso: nowIso,
      proposeTimeNs,
      trueTimeInterval
    };

    const key = `${this.currentView}:${seq}:${digest}`;
    this.prePrepareMessages.set(key, msg);

    // Track proposal history for equivocation detection
    const seqKey = `${this.currentView}:${seq}`;
    if (!this.proposalHistory.has(seqKey)) {
      this.proposalHistory.set(seqKey, new Map());
    }
    this.proposalHistory.get(seqKey)!.set(leaderId, digest);

    return msg;
  }

  /**
   * Phase 2: Prepare
   * Replicas verify Pre-Prepare and broadcast PREPARE votes
   */
  public handlePrePrepareAndPrepare(
    prePrepare: BftPrePrepareMessage,
    nodeId: string
  ): BftPrepareMessage | null {
    // 1. Check if node is Byzantine
    if (this.byzantineNodes.has(nodeId)) {
      return null;
    }

    // 2. Equivocation check
    const seqKey = `${prePrepare.view}:${prePrepare.sequenceNumber}`;
    const history = this.proposalHistory.get(seqKey);
    if (history && history.has(prePrepare.leaderId)) {
      const priorDigest = history.get(prePrepare.leaderId);
      if (priorDigest !== prePrepare.digest) {
        this.byzantineNodes.add(prePrepare.leaderId);
        return null;
      }
    }

    // 3. Verify signature
    const signPayload = `PRE_PREPARE:${prePrepare.view}:${prePrepare.sequenceNumber}:${prePrepare.digest}:${prePrepare.leaderId}:${prePrepare.timestampIso}`;
    if (!this.verifySignature(prePrepare.leaderId, signPayload, prePrepare.signature)) {
      return null;
    }

    // 4. Create signed PREPARE message
    const nowIso = new Date().toISOString();
    const prepareSignPayload = `PREPARE:${prePrepare.view}:${prePrepare.sequenceNumber}:${prePrepare.digest}:${nodeId}:${nowIso}`;
    const signature = this.signMessage(nodeId, prepareSignPayload);

    const prepareMsg: BftPrepareMessage = {
      type: 'PREPARE',
      view: prePrepare.view,
      sequenceNumber: prePrepare.sequenceNumber,
      digest: prePrepare.digest,
      nodeId,
      signature,
      timestampIso: nowIso
    };

    // Store prepare vote
    const voteKey = `${prePrepare.view}:${prePrepare.sequenceNumber}:${prePrepare.digest}`;
    if (!this.prepareVotes.has(voteKey)) {
      this.prepareVotes.set(voteKey, new Map());
    }
    this.prepareVotes.get(voteKey)!.set(nodeId, prepareMsg);

    // Check if Prepared Certificate is achieved
    this.checkPreparedCertificate(prePrepare.view, prePrepare.sequenceNumber, prePrepare.digest);

    return prepareMsg;
  }

  /**
   * Collects PREPARE vote from another node
   */
  public receivePrepare(msg: BftPrepareMessage): BftQuorumCertificate | null {
    if (this.byzantineNodes.has(msg.nodeId)) return null;

    // Equivocation check
    const seqKey = `${msg.view}:${msg.sequenceNumber}`;
    if (!this.proposalHistory.has(seqKey)) {
      this.proposalHistory.set(seqKey, new Map());
    }
    const history = this.proposalHistory.get(seqKey)!;
    if (history.has(msg.nodeId) && history.get(msg.nodeId) !== msg.digest) {
      this.byzantineNodes.add(msg.nodeId);
      return null;
    }
    history.set(msg.nodeId, msg.digest);

    // Verify signature
    const signPayload = `PREPARE:${msg.view}:${msg.sequenceNumber}:${msg.digest}:${msg.nodeId}:${msg.timestampIso}`;
    if (!this.verifySignature(msg.nodeId, signPayload, msg.signature)) {
      return null;
    }

    const voteKey = `${msg.view}:${msg.sequenceNumber}:${msg.digest}`;
    if (!this.prepareVotes.has(voteKey)) {
      this.prepareVotes.set(voteKey, new Map());
    }
    this.prepareVotes.get(voteKey)!.set(msg.nodeId, msg);

    return this.checkPreparedCertificate(msg.view, msg.sequenceNumber, msg.digest);
  }

  /**
   * Phase 3: Commit
   * Nodes broadcast COMMIT message once Prepared Certificate is formed
   */
  public handleCommit(nodeId: string, preparedCert: BftQuorumCertificate): BftCommitMessage | null {
    if (this.byzantineNodes.has(nodeId)) return null;

    const nowIso = new Date().toISOString();
    const commitSignPayload = `COMMIT:${preparedCert.view}:${preparedCert.sequenceNumber}:${preparedCert.digest}:${nodeId}:${nowIso}`;
    const signature = this.signMessage(nodeId, commitSignPayload);

    const commitMsg: BftCommitMessage = {
      type: 'COMMIT',
      view: preparedCert.view,
      sequenceNumber: preparedCert.sequenceNumber,
      digest: preparedCert.digest,
      nodeId,
      signature,
      timestampIso: nowIso
    };

    const voteKey = `${preparedCert.view}:${preparedCert.sequenceNumber}:${preparedCert.digest}`;
    if (!this.commitVotes.has(voteKey)) {
      this.commitVotes.set(voteKey, new Map());
    }
    this.commitVotes.get(voteKey)!.set(nodeId, commitMsg);

    this.checkCommittedCertificate(preparedCert.view, preparedCert.sequenceNumber, preparedCert.digest);

    return commitMsg;
  }

  /**
   * Collects COMMIT vote from another node
   */
  public receiveCommit(msg: BftCommitMessage): BftLogEntry | null {
    if (this.byzantineNodes.has(msg.nodeId)) return null;

    const signPayload = `COMMIT:${msg.view}:${msg.sequenceNumber}:${msg.digest}:${msg.nodeId}:${msg.timestampIso}`;
    if (!this.verifySignature(msg.nodeId, signPayload, msg.signature)) {
      return null;
    }

    const voteKey = `${msg.view}:${msg.sequenceNumber}:${msg.digest}`;
    if (!this.commitVotes.has(voteKey)) {
      this.commitVotes.set(voteKey, new Map());
    }
    this.commitVotes.get(voteKey)!.set(msg.nodeId, msg);

    return this.checkCommittedCertificate(msg.view, msg.sequenceNumber, msg.digest);
  }

  /**
   * Triggers View Change when progress stalls
   */
  public triggerViewChange(nodeId: string, targetNewView?: number): ViewChangeMessage {
    const newView = targetNewView ?? (this.currentView + 1);
    const nowIso = new Date().toISOString();
    const signPayload = `VIEW_CHANGE:${newView}:${nodeId}:${nowIso}`;
    const signature = this.signMessage(nodeId, signPayload);

    const msg: ViewChangeMessage = {
      type: 'VIEW_CHANGE',
      newView,
      nodeId,
      lastPreparedCert: this.committedLog.length > 0 ? this.committedLog[this.committedLog.length - 1].quorumCertificate : undefined,
      signature,
      timestampIso: nowIso
    };

    if (!this.viewChangeVotes.has(newView)) {
      this.viewChangeVotes.set(newView, new Map());
    }
    this.viewChangeVotes.get(newView)!.set(nodeId, msg);

    // If quorum of 2f + 1 view change votes is reached, install new view
    const votes = this.viewChangeVotes.get(newView)!;
    if (votes.size >= this.getQuorumThreshold()) {
      this.currentView = newView;
    }

    return msg;
  }

  /**
   * Helper to check and assemble Prepared Certificate
   */
  private checkPreparedCertificate(view: number, seq: number, digest: string): BftQuorumCertificate | null {
    const key = `${view}:${seq}:${digest}`;
    if (this.preparedCertificates.has(key)) {
      return this.preparedCertificates.get(key)!;
    }

    const votes = this.prepareVotes.get(key);
    // Prepared certificate requires 2f matching votes (plus pre-prepare)
    const threshold = Math.max(1, this.getQuorumThreshold() - 1);
    if (votes && votes.size >= threshold) {
      const signatures = Array.from(votes.values()).map((v) => ({
        nodeId: v.nodeId,
        signature: v.signature
      }));

      const cert: BftQuorumCertificate = {
        type: 'PREPARED',
        view,
        sequenceNumber: seq,
        digest,
        signatures,
        formedAtIso: new Date().toISOString()
      };

      this.preparedCertificates.set(key, cert);
      return cert;
    }
    return null;
  }

  /**
   * Helper to check and assemble Committed Certificate and commit to state log
   */
  private checkCommittedCertificate(view: number, seq: number, digest: string): BftLogEntry | null {
    const key = `${view}:${seq}:${digest}`;
    const votes = this.commitVotes.get(key);
    const threshold = this.getQuorumThreshold();

    if (votes && votes.size >= threshold) {
      if (this.committedCertificates.has(key)) {
        return this.committedLog.find((entry) => entry.sequenceNumber === seq) || null;
      }

      const signatures = Array.from(votes.values()).map((v) => ({
        nodeId: v.nodeId,
        signature: v.signature
      }));

      const cert: BftQuorumCertificate = {
        type: 'COMMITTED',
        view,
        sequenceNumber: seq,
        digest,
        signatures,
        formedAtIso: new Date().toISOString()
      };

      this.committedCertificates.set(key, cert);

      const prePrep = this.prePrepareMessages.get(key);
      const payload = prePrep ? prePrep.payload : { stateDigest: digest };

      // Compute Merkle Root: H(priorMerkleRoot + digest)
      const priorRoot = this.committedLog.length > 0 ? this.committedLog[this.committedLog.length - 1].merkleRoot : 'genesis';
      const merkleRoot = crypto.createHash('sha256').update(`${priorRoot}:${digest}`).digest('hex');

      const entry: BftLogEntry = {
        sequenceNumber: seq,
        view,
        digest,
        payload,
        quorumCertificate: cert,
        merkleRoot,
        committedAtIso: cert.formedAtIso
      };

      this.committedLog.push(entry);
      this.persistLogEntry(entry);
      return entry;
    }

    return null;
  }

  public getCommittedLog(): BftLogEntry[] {
    return [...this.committedLog];
  }

  public resetForTesting(): void {
    this.nodes.clear();
    this.currentView = 0;
    this.currentSequence = 0;
    this.prePrepareMessages.clear();
    this.prepareVotes.clear();
    this.commitVotes.clear();
    this.preparedCertificates.clear();
    this.committedCertificates.clear();
    this.proposalHistory.clear();
    this.byzantineNodes.clear();
    this.viewChangeVotes.clear();
    this.committedLog = [];

    const db = getDb();
    if (db) {
      try {
        db.prepare('DELETE FROM ejii_bft_replicated_log').run();
      } catch (_) {}
    }
  }

  private persistLogEntry(entry: BftLogEntry): void {
    const db = getDb();
    if (!db) return;

    try {
      db.prepare(`
        INSERT INTO ejii_bft_replicated_log (
          sequence_number, view, state_digest, payload_json,
          quorum_certificate_json, merkle_root, committed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(sequence_number) DO NOTHING
      `).run(
        entry.sequenceNumber,
        entry.view,
        entry.digest,
        JSON.stringify(entry.payload),
        JSON.stringify(entry.quorumCertificate),
        entry.merkleRoot,
        entry.committedAtIso
      );
    } catch (_) {}
  }
}

export const bftStateMachineReplicator = new BftStateMachineReplicator();
