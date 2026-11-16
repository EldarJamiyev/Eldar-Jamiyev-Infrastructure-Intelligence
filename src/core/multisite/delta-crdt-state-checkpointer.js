/**
 * EJII Multi-Site Delta-CRDT State Checkpointer & Partition Healing Engine
 * Phase 21.0 Distributed Infrastructure Layer
 *
 * Dual-Maintenance CommonJS Implementation.
 */

'use strict';

const crypto = require('node:crypto');
const { db } = require('../../db/database');

class DeltaCrdtStateCheckpointer {
  constructor(siteId = 'site_primary') {
    this.localSiteId = siteId;
    this.localVectorClock = { [siteId]: 1 };
    this.materializedState = new Map();
    this.ensureSchema();
    this.prepareStatements();
  }

  ensureSchema() {
    try {
      db.exec(`
        CREATE TABLE IF NOT EXISTS crdt_delta_log (
          delta_id TEXT PRIMARY KEY,
          site_id TEXT NOT NULL,
          vector_clock_json TEXT NOT NULL,
          delta_payload_json TEXT NOT NULL,
          state_merkle_root TEXT NOT NULL,
          created_at_ms INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS crdt_state_checkpoints (
          checkpoint_id TEXT PRIMARY KEY,
          epoch INTEGER NOT NULL,
          merged_state_json TEXT NOT NULL,
          state_hash TEXT NOT NULL,
          snapshot_timestamp_ms INTEGER NOT NULL
        );
      `);
    } catch (_) {
      // In-memory fallback
    }
  }

  prepareStatements() {
    try {
      this.stmtInsertDelta = db.prepare(`
        INSERT INTO crdt_delta_log (delta_id, site_id, vector_clock_json, delta_payload_json, state_merkle_root, created_at_ms)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(delta_id) DO NOTHING;
      `);
      this.stmtInsertCheckpoint = db.prepare(`
        INSERT INTO crdt_state_checkpoints (checkpoint_id, epoch, merged_state_json, state_hash, snapshot_timestamp_ms)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(checkpoint_id) DO NOTHING;
      `);
    } catch (_) {
      // Fallback
    }
  }

  computeStateMerkleRoot(state) {
    const sortedKeys = Object.keys(state).sort();
    const hash = crypto.createHash('sha256');
    for (const k of sortedKeys) {
      hash.update(`${k}:${JSON.stringify(state[k])};`);
    }
    return hash.digest('hex');
  }

  recordDelta(siteId, deltaPayload, remoteClock) {
    const now = Date.now();
    const origin = siteId || this.localSiteId;
    this.localVectorClock[origin] = (this.localVectorClock[origin] || 0) + 1;

    if (remoteClock) {
      for (const [k, v] of Object.entries(remoteClock)) {
        this.localVectorClock[k] = Math.max(this.localVectorClock[k] || 0, v);
      }
    }

    for (const [k, v] of Object.entries(deltaPayload)) {
      this.materializedState.set(k, { value: v, timestampMs: now, originSite: origin });
    }

    const stateObj = this.getState();
    const merkleRoot = this.computeStateMerkleRoot(stateObj);
    const deltaId = `delta_${origin}_${this.localVectorClock[origin]}_${crypto.randomBytes(4).toString('hex')}`;

    const deltaRecord = {
      deltaId,
      siteId: origin,
      vectorClock: { ...this.localVectorClock },
      deltaPayload,
      stateMerkleRoot: merkleRoot,
      createdAtMs: now
    };

    if (this.stmtInsertDelta) {
      try {
        this.stmtInsertDelta.run(
          deltaRecord.deltaId,
          deltaRecord.siteId,
          JSON.stringify(deltaRecord.vectorClock),
          JSON.stringify(deltaRecord.deltaPayload),
          deltaRecord.stateMerkleRoot,
          deltaRecord.createdAtMs
        );
      } catch (_) {}
    }

    return deltaRecord;
  }

  reconcileRemoteDeltas(remoteDeltas) {
    let mergedCount = 0;

    for (const delta of remoteDeltas) {
      for (const [k, remoteVal] of Object.entries(delta.deltaPayload)) {
        const localEntry = this.materializedState.get(k);
        if (!localEntry || delta.createdAtMs >= localEntry.timestampMs) {
          this.materializedState.set(k, {
            value: remoteVal,
            timestampMs: delta.createdAtMs,
            originSite: delta.siteId
          });
          mergedCount++;
        }
      }

      for (const [site, clock] of Object.entries(delta.vectorClock)) {
        this.localVectorClock[site] = Math.max(this.localVectorClock[site] || 0, clock);
      }

      if (this.stmtInsertDelta) {
        try {
          this.stmtInsertDelta.run(
            delta.deltaId,
            delta.siteId,
            JSON.stringify(delta.vectorClock),
            JSON.stringify(delta.deltaPayload),
            delta.stateMerkleRoot,
            delta.createdAtMs
          );
        } catch (_) {}
      }
    }

    const newStateHash = this.computeStateMerkleRoot(this.getState());
    return {
      mergedCount,
      newStateHash
    };
  }

  createCheckpoint(epoch = 1) {
    const now = Date.now();
    const stateObj = this.getState();
    const stateHash = this.computeStateMerkleRoot(stateObj);
    const checkpointId = `chk_${epoch}_${stateHash.substring(0, 12)}`;

    const checkpoint = {
      checkpointId,
      epoch,
      mergedState: stateObj,
      stateHash,
      snapshotTimestampMs: now
    };

    if (this.stmtInsertCheckpoint) {
      try {
        this.stmtInsertCheckpoint.run(
          checkpoint.checkpointId,
          checkpoint.epoch,
          JSON.stringify(checkpoint.mergedState),
          checkpoint.stateHash,
          checkpoint.snapshotTimestampMs
        );
      } catch (_) {}
    }

    return checkpoint;
  }

  getState() {
    const result = {};
    for (const [k, v] of this.materializedState.entries()) {
      result[k] = v.value;
    }
    return result;
  }

  getVectorClock() {
    return { ...this.localVectorClock };
  }
}

const deltaCrdtStateCheckpointer = new DeltaCrdtStateCheckpointer();

module.exports = {
  DeltaCrdtStateCheckpointer,
  deltaCrdtStateCheckpointer
};
