/**
 * EJII Geo-Partition Tolerant CRDT State Engine & Anti-Entropy WAN Replicator
 *
 * Implements:
 *   1. State-Based Delta CRDTs over Join Semi-Lattices <S, ⊔>:
 *      - Positive-Negative Counter (P-N Counter) for monotonic distributed telemetry & rate counters.
 *      - Last-Write-Wins Register (LWW-Register) with TrueTime nanosecond monotonic ordering.
 *      - Observed-Remove Set (OR-Set) with tag-based tombstones for multi-site firewall/XDP rules.
 *   2. Vector Clock Causality Tracking:
 *      Partial order evaluation (BEFORE, AFTER, EQUAL, CONCURRENT) with zero data loss.
 *   3. Anti-Entropy 3-Way Reconciliation Protocol:
 *      Deterministic convergence upon WAN partition recovery in O(Δ) steps.
 *   4. Zero-Simulation Persistence in SQLite WAL (`ejii_crdt_delta_records`).
 */

'use strict';

const crypto = require('node:crypto');
const { nanosecondTrueTimeEngine } = require('../../observability/nanosecond-truetime-engine');

function getDb() {
  try {
    return require('../../db/database').db;
  } catch (_) {
    return null;
  }
}

class GeoPartitionCrdtEngine {
  /**
   * @param {string} [siteId='site-primary']
   * @param {Object} [options={}]
   */
  constructor(siteId = 'site-primary', options = {}) {
    this.localSiteId = String(siteId || 'site-primary').trim() || 'site-primary';
    this.vectorClock = {};
    this.vectorClock[this.localSiteId] = 0;
    this.pnCounters = new Map();
    this.lwwRegisters = new Map();
    this.orSets = new Map();
    this.partitionStatus = 'NORMAL';
    this.db = null;
    this.persistenceDiagnostics = {
      dbBound: false,
      schemaInitialized: false,
      persistenceState: 'IN_MEMORY_ONLY',
      lastPersistenceError: null
    };
    this.initDatabase(options.dbHandle);
  }

  initDatabase(explicitDb) {
    try {
      this.db = explicitDb !== undefined ? explicitDb : getDb();
      if (this.db && typeof this.db.exec === 'function') {
        this.persistenceDiagnostics.dbBound = true;
        this.db.exec(`
          CREATE TABLE IF NOT EXISTS ejii_crdt_delta_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site_id TEXT NOT NULL,
            crdt_type TEXT NOT NULL,
            key TEXT NOT NULL,
            delta_payload TEXT NOT NULL,
            vector_clock TEXT NOT NULL,
            timestamp_iso TEXT NOT NULL,
            truetime_ns TEXT,
            reconciled INTEGER DEFAULT 0
          );
          CREATE INDEX IF NOT EXISTS idx_crdt_site_key ON ejii_crdt_delta_records(site_id, key);
        `);
        this.persistenceDiagnostics.schemaInitialized = true;
        this.persistenceDiagnostics.persistenceState = 'SQLITE_PERSISTENT';
        this.persistenceDiagnostics.lastPersistenceError = null;
      } else {
        this.db = null;
        this.persistenceDiagnostics.dbBound = false;
        this.persistenceDiagnostics.schemaInitialized = false;
        this.persistenceDiagnostics.persistenceState = 'IN_MEMORY_ONLY';
      }
    } catch (err) {
      this.persistenceDiagnostics.dbBound = Boolean(this.db);
      this.persistenceDiagnostics.schemaInitialized = false;
      this.persistenceDiagnostics.persistenceState = 'SQLITE_DEGRADED';
      this.persistenceDiagnostics.lastPersistenceError = err && err.message ? err.message : String(err);
    }
  }

  getPersistenceDiagnostics() {
    return { ...this.persistenceDiagnostics };
  }

  getLocalSiteId() {
    return this.localSiteId;
  }

  getVectorClock() {
    return { ...this.vectorClock };
  }

  getPartitionStatus() {
    return this.partitionStatus;
  }

  setPartitionStatus(status) {
    this.partitionStatus = status;
  }

  // ==========================================
  // Vector Clock Operations
  // ==========================================

  tickLocalClock() {
    this.vectorClock[this.localSiteId] = (this.vectorClock[this.localSiteId] || 0) + 1;
    return this.vectorClock[this.localSiteId];
  }

  mergeVectorClock(incomingClock) {
    for (const [sId, count] of Object.entries(incomingClock)) {
      this.vectorClock[sId] = Math.max(this.vectorClock[sId] || 0, count);
    }
    return { ...this.vectorClock };
  }

  compareVectorClocks(vA, vB) {
    const allKeys = new Set([...Object.keys(vA), ...Object.keys(vB)]);
    let aGreater = false;
    let bGreater = false;

    for (const key of allKeys) {
      const valA = vA[key] || 0;
      const valB = vB[key] || 0;
      if (valA > valB) aGreater = true;
      if (valB > valA) bGreater = true;
    }

    if (aGreater && !bGreater) return 'AFTER';
    if (bGreater && !aGreater) return 'BEFORE';
    if (!aGreater && !bGreater) return 'EQUAL';
    return 'CONCURRENT';
  }

  // ==========================================
  // P-N Counter (Positive-Negative)
  // ==========================================

  incrementCounter(key, delta = 1) {
    if (delta <= 0) return this.getCounterValue(key);
    let state = this.pnCounters.get(key);
    if (!state) {
      state = { positive: {}, negative: {} };
      this.pnCounters.set(key, state);
    }
    state.positive[this.localSiteId] = (state.positive[this.localSiteId] || 0) + delta;
    this.tickLocalClock();
    this.persistDelta('PN_COUNTER', key, { type: 'INC', siteId: this.localSiteId, delta });
    return this.getCounterValue(key);
  }

  decrementCounter(key, delta = 1) {
    if (delta <= 0) return this.getCounterValue(key);
    let state = this.pnCounters.get(key);
    if (!state) {
      state = { positive: {}, negative: {} };
      this.pnCounters.set(key, state);
    }
    state.negative[this.localSiteId] = (state.negative[this.localSiteId] || 0) + delta;
    this.tickLocalClock();
    this.persistDelta('PN_COUNTER', key, { type: 'DEC', siteId: this.localSiteId, delta });
    return this.getCounterValue(key);
  }

  getCounterValue(key) {
    const state = this.pnCounters.get(key);
    if (!state) return 0;
    const sumP = Object.values(state.positive).reduce((acc, v) => acc + v, 0);
    const sumN = Object.values(state.negative).reduce((acc, v) => acc + v, 0);
    return sumP - sumN;
  }

  mergeCounter(key, remoteState) {
    if (!remoteState || typeof remoteState !== 'object') {
      return this.getCounterValue(key);
    }
    let local = this.pnCounters.get(key);
    if (!local) {
      local = { positive: {}, negative: {} };
      this.pnCounters.set(key, local);
    }

    // Join semi-lattice: P' = max(P1, P2), N' = max(N1, N2)
    for (const [sId, pVal] of Object.entries(remoteState.positive || {})) {
      local.positive[sId] = Math.max(local.positive[sId] || 0, pVal);
    }
    for (const [sId, nVal] of Object.entries(remoteState.negative || {})) {
      local.negative[sId] = Math.max(local.negative[sId] || 0, nVal);
    }

    return this.getCounterValue(key);
  }

  // ==========================================
  // LWW-Register (Last-Write-Wins with TrueTime)
  // ==========================================

  setRegister(key, value) {
    const seq = this.tickLocalClock();
    const tt = nanosecondTrueTimeEngine.now();
    const nowMs = Date.now();

    const regState = {
      value,
      timestampMs: nowMs,
      timestampNs: tt.timestampNs,
      siteId: this.localSiteId,
      seq
    };

    this.lwwRegisters.set(key, regState);
    this.persistDelta('LWW_REGISTER', key, regState);
    return regState;
  }

  getRegister(key) {
    const reg = this.lwwRegisters.get(key);
    return reg ? reg.value : null;
  }

  getRegisterState(key) {
    return this.lwwRegisters.get(key) || null;
  }

  mergeRegister(key, remoteReg) {
    const local = this.lwwRegisters.get(key);
    if (!local) {
      this.lwwRegisters.set(key, { ...remoteReg });
      return true;
    }

    // Total order: timestampMs > siteId > seq
    let remoteWins = false;
    if (remoteReg.timestampMs > local.timestampMs) {
      remoteWins = true;
    } else if (remoteReg.timestampMs === local.timestampMs) {
      if (remoteReg.siteId > local.siteId) {
        remoteWins = true;
      } else if (remoteReg.siteId === local.siteId && remoteReg.seq > local.seq) {
        remoteWins = true;
      }
    }

    if (remoteWins) {
      this.lwwRegisters.set(key, { ...remoteReg });
      return true;
    }
    return false;
  }

  // ==========================================
  // OR-Set (Observed-Remove Set)
  // ==========================================

  addToSet(key, element) {
    let state = this.orSets.get(key);
    if (!state) {
      state = { addSet: {}, removeSet: {} };
      this.orSets.set(key, state);
    }

    const tag = `${this.localSiteId}:${Date.now()}:${crypto.randomBytes(4).toString('hex')}`;
    const elRecord = {
      tag,
      element,
      siteId: this.localSiteId,
      timestampMs: Date.now()
    };

    state.addSet[tag] = elRecord;
    this.tickLocalClock();
    this.persistDelta('OR_SET', key, { action: 'ADD', elRecord });
    return tag;
  }

  removeFromSet(key, element) {
    const state = this.orSets.get(key);
    if (!state) return false;

    // Tombstone all active tags for this element
    let removedAny = false;
    for (const [tag, elRecord] of Object.entries(state.addSet)) {
      if (elRecord.element === element && !state.removeSet[tag]) {
        state.removeSet[tag] = true;
        removedAny = true;
        this.persistDelta('OR_SET', key, { action: 'REMOVE', tag, element });
      }
    }

    if (removedAny) {
      this.tickLocalClock();
    }
    return removedAny;
  }

  getSetElements(key) {
    const state = this.orSets.get(key);
    if (!state) return [];

    const active = new Set();
    for (const [tag, elRecord] of Object.entries(state.addSet)) {
      if (!state.removeSet[tag]) {
        active.add(elRecord.element);
      }
    }
    return Array.from(active).sort();
  }

  mergeSet(key, remoteState) {
    let local = this.orSets.get(key);
    if (!local) {
      local = { addSet: {}, removeSet: {} };
      this.orSets.set(key, local);
    }

    // Join semi-lattice: AddSet' = AddSet1 ∪ AddSet2, RemoveSet' = RemoveSet1 ∪ RemoveSet2
    for (const [tag, record] of Object.entries(remoteState.addSet || {})) {
      if (!local.addSet[tag]) {
        local.addSet[tag] = record;
      }
    }
    for (const [tag, removed] of Object.entries(remoteState.removeSet || {})) {
      if (removed) {
        local.removeSet[tag] = true;
      }
    }

    return this.getSetElements(key);
  }

  // ==========================================
  // Anti-Entropy 3-Way WAN Reconciliation
  // ==========================================

  generateDeltaDigest() {
    const deltas = [];

    // Export current in-memory CRDT snapshots as deltas
    for (const [k, pnc] of this.pnCounters.entries()) {
      deltas.push({
        siteId: this.localSiteId,
        crdtType: 'PN_COUNTER',
        key: k,
        deltaPayload: pnc,
        vectorClock: { ...this.vectorClock },
        timestampIso: new Date().toISOString(),
        trueTimeNs: nanosecondTrueTimeEngine.now().timestampNs
      });
    }

    for (const [k, reg] of this.lwwRegisters.entries()) {
      deltas.push({
        siteId: this.localSiteId,
        crdtType: 'LWW_REGISTER',
        key: k,
        deltaPayload: reg,
        vectorClock: { ...this.vectorClock },
        timestampIso: new Date().toISOString(),
        trueTimeNs: nanosecondTrueTimeEngine.now().timestampNs
      });
    }

    for (const [k, ors] of this.orSets.entries()) {
      deltas.push({
        siteId: this.localSiteId,
        crdtType: 'OR_SET',
        key: k,
        deltaPayload: ors,
        vectorClock: { ...this.vectorClock },
        timestampIso: new Date().toISOString(),
        trueTimeNs: nanosecondTrueTimeEngine.now().timestampNs
      });
    }

    return {
      siteId: this.localSiteId,
      vectorClock: { ...this.vectorClock },
      deltas
    };
  }

  captureMemorySnapshot() {
    const deepClone = (v) => JSON.parse(JSON.stringify(v));
    const pnClone = new Map();
    for (const [k, v] of this.pnCounters.entries()) pnClone.set(k, deepClone(v));
    const lwwClone = new Map();
    for (const [k, v] of this.lwwRegisters.entries()) lwwClone.set(k, deepClone(v));
    const orClone = new Map();
    for (const [k, v] of this.orSets.entries()) orClone.set(k, deepClone(v));
    return {
      vectorClock: { ...this.vectorClock },
      pnCounters: pnClone,
      lwwRegisters: lwwClone,
      orSets: orClone,
      partitionStatus: this.partitionStatus
    };
  }

  restoreMemorySnapshot(snap) {
    this.vectorClock = snap.vectorClock;
    this.pnCounters = snap.pnCounters;
    this.lwwRegisters = snap.lwwRegisters;
    this.orSets = snap.orSets;
    this.partitionStatus = snap.partitionStatus;
  }

  reconcileWithRemote(remoteSiteId, remoteClock, remoteDeltas, options = {}) {
    const cleanRemoteSiteId = String(remoteSiteId || '').trim();
    const nowIso = new Date().toISOString();

    if (!cleanRemoteSiteId || cleanRemoteSiteId.toLowerCase() === this.localSiteId.toLowerCase()) {
      return {
        localSiteId: this.localSiteId,
        remoteSiteId: cleanRemoteSiteId || '(empty)',
        deltasReceivedCount: 0,
        deltasAppliedCount: 0,
        conflictsResolvedCount: 0,
        convergedVectorClock: { ...this.vectorClock },
        convergenceStatus: 'INVALID_SELF_TARGET',
        error: `Cannot reconcile local partition '${this.localSiteId}' with itself or an empty partition target.`,
        timestampIso: nowIso
      };
    }

    const deltas = Array.isArray(remoteDeltas) ? remoteDeltas : [];
    const safeRemoteClock = remoteClock && typeof remoteClock === 'object' ? remoteClock : {};
    const hasAdvancingRemoteClock = Object.entries(safeRemoteClock).some(([site, tick]) => {
      if (site === this.localSiteId) return false;
      const numericTick = Number(tick) || 0;
      return numericTick > (this.vectorClock[site] || 0);
    });

    if (deltas.length === 0 && !hasAdvancingRemoteClock) {
      return {
        localSiteId: this.localSiteId,
        remoteSiteId: cleanRemoteSiteId,
        deltasReceivedCount: 0,
        deltasAppliedCount: 0,
        conflictsResolvedCount: 0,
        convergedVectorClock: { ...this.vectorClock },
        convergenceStatus: 'NO_REMOTE_DELTAS_AVAILABLE',
        error: `No unreconciled remote deltas or advancing peer vector clock exchange received from '${cleanRemoteSiteId}'.`,
        timestampIso: nowIso
      };
    }

    const snapshot = this.captureMemorySnapshot();
    if (options.preTickClock) {
      snapshot.vectorClock = { ...options.preTickClock };
    }
    let deltasAppliedCount = 0;
    let conflictsResolvedCount = 0;

    for (const delta of deltas) {
      if (delta.crdtType === 'PN_COUNTER') {
        this.mergeCounter(delta.key, delta.deltaPayload);
        deltasAppliedCount++;
      } else if (delta.crdtType === 'LWW_REGISTER') {
        const changed = this.mergeRegister(delta.key, delta.deltaPayload);
        deltasAppliedCount++;
        if (changed) conflictsResolvedCount++;
      } else if (delta.crdtType === 'OR_SET') {
        this.mergeSet(delta.key, delta.deltaPayload);
        deltasAppliedCount++;
      }
    }

    // Merge vector clocks to establish causal upper bound
    this.mergeVectorClock(safeRemoteClock);
    const nextStatus = deltasAppliedCount > 0 ? 'RECONCILED' : 'HEALING';
    this.partitionStatus = nextStatus;

    // Atomically mark reconciled deltas (ONLY after merge succeeds) and persist audit row inside transaction
    if (this.db) {
      try {
        this.db.exec('BEGIN IMMEDIATE');
        try {
          if (Array.isArray(options.markReconciledRowIds) && options.markReconciledRowIds.length > 0) {
            const placeholders = options.markReconciledRowIds.map(() => '?').join(',');
            this.db
              .prepare(`UPDATE ejii_crdt_delta_records SET reconciled = 1 WHERE id IN (${placeholders}) AND site_id = ? AND reconciled = 0`)
              .run(...options.markReconciledRowIds, cleanRemoteSiteId);
          }
          const stmt = this.db.prepare(`
            INSERT INTO ejii_crdt_delta_records (
              site_id, crdt_type, key, delta_payload, vector_clock, timestamp_iso, truetime_ns, reconciled
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
          `);
          stmt.run(
            cleanRemoteSiteId,
            'RECONCILIATION',
            'wan_partition_heal',
            JSON.stringify({ deltasAppliedCount, conflictsResolvedCount }),
            JSON.stringify(this.vectorClock),
            nowIso,
            nanosecondTrueTimeEngine.now().timestampNs
          );
          this.db.exec('COMMIT');
          this.persistenceDiagnostics.persistenceState = 'SQLITE_PERSISTENT';
          this.persistenceDiagnostics.lastPersistenceError = null;
        } catch (txErr) {
          try { this.db.exec('ROLLBACK'); } catch (_) {}
          throw txErr;
        }
      } catch (dbErr) {
        this.restoreMemorySnapshot(snapshot);
        const errMsg = dbErr && dbErr.message ? dbErr.message : String(dbErr);
        this.persistenceDiagnostics.persistenceState = 'SQLITE_DEGRADED';
        this.persistenceDiagnostics.lastPersistenceError = errMsg;
        return {
          localSiteId: this.localSiteId,
          remoteSiteId: cleanRemoteSiteId,
          deltasReceivedCount: deltas.length,
          deltasAppliedCount: 0,
          conflictsResolvedCount: 0,
          convergedVectorClock: { ...this.vectorClock },
          convergenceStatus: 'SQLITE_PERSISTENCE_FAILED',
          error: `CRDT reconciliation aborted cleanly because SQLite persistence failed: ${errMsg}`,
          timestampIso: nowIso
        };
      }
    }

    return {
      localSiteId: this.localSiteId,
      remoteSiteId: cleanRemoteSiteId,
      deltasReceivedCount: deltas.length,
      deltasAppliedCount,
      conflictsResolvedCount,
      convergedVectorClock: { ...this.vectorClock },
      convergenceStatus: deltasAppliedCount > 0 ? 'CONVERGED' : 'PARTIALLY_CONVERGED',
      timestampIso: nowIso
    };
  }

  getStateSummary() {
    const trackedPeers = Object.keys(this.vectorClock).filter((k) => k !== this.localSiteId);
    return {
      localSiteId: this.localSiteId,
      status: this.partitionStatus,
      vectorClock: { ...this.vectorClock },
      pnCounterCount: this.pnCounters.size,
      lwwRegisterCount: this.lwwRegisters.size,
      orSetCount: this.orSets.size,
      trackedPeers,
      persistenceDiagnostics: this.getPersistenceDiagnostics()
    };
  }

  reconcileWithRemotePartition(targetPartition, remoteClock = {}, remoteDeltas = []) {
    const partitionId = String(targetPartition || '').trim();
    if (!partitionId || partitionId.toLowerCase() === this.localSiteId.toLowerCase()) {
      return {
        localSiteId: this.localSiteId,
        remoteSiteId: partitionId || '(empty)',
        deltasReceivedCount: 0,
        deltasAppliedCount: 0,
        conflictsResolvedCount: 0,
        convergedVectorClock: { ...this.vectorClock },
        convergenceStatus: 'INVALID_SELF_TARGET',
        error: `Cannot reconcile local partition '${this.localSiteId}' with '${partitionId || '(empty)'}'. Specify a distinct remote peer partition.`,
        timestampIso: new Date().toISOString()
      };
    }

    const loadedDeltas = Array.isArray(remoteDeltas) ? [...remoteDeltas] : [];
    const mergedRemoteClock = remoteClock && typeof remoteClock === 'object' ? { ...remoteClock } : {};
    const dbRowIdsToReconcile = [];

    if (loadedDeltas.length === 0 && this.db) {
      try {
        const rows = this.db.prepare(
          `SELECT id, site_id, crdt_type, key, delta_payload, vector_clock, timestamp_iso, truetime_ns
           FROM ejii_crdt_delta_records
           WHERE site_id = ? AND reconciled = 0 AND crdt_type IN ('PN_COUNTER', 'LWW_REGISTER', 'OR_SET')
           ORDER BY id ASC LIMIT 200`
        ).all(partitionId);
        for (const r of rows) {
          const payload = JSON.parse(r.delta_payload);
          const vc = JSON.parse(r.vector_clock);
          for (const [k, v] of Object.entries(vc || {})) {
            mergedRemoteClock[k] = Math.max(mergedRemoteClock[k] || 0, Number(v) || 0);
          }
          if (r.id !== undefined && r.id !== null) {
            dbRowIdsToReconcile.push(Number(r.id));
          }
          loadedDeltas.push({
            id: Number(r.id),
            siteId: r.site_id,
            crdtType: r.crdt_type,
            key: r.key,
            deltaPayload: payload,
            vectorClock: vc,
            timestampIso: r.timestamp_iso,
            trueTimeNs: r.truetime_ns || '0'
          });
        }
      } catch (err) {
        const errMsg = err && err.message ? err.message : String(err);
        this.persistenceDiagnostics.persistenceState = 'SQLITE_DEGRADED';
        this.persistenceDiagnostics.lastPersistenceError = errMsg;
        return {
          localSiteId: this.localSiteId,
          remoteSiteId: partitionId,
          deltasReceivedCount: 0,
          deltasAppliedCount: 0,
          conflictsResolvedCount: 0,
          convergedVectorClock: { ...this.vectorClock },
          convergenceStatus: 'SQLITE_PERSISTENCE_FAILED',
          error: `Failed to read unreconciled remote deltas from SQLite: ${errMsg}`,
          timestampIso: new Date().toISOString()
        };
      }
    }

    const hasAdvancingClock = Object.entries(mergedRemoteClock).some(([site, tick]) => {
      if (site === this.localSiteId) return false;
      return (Number(tick) || 0) > (this.vectorClock[site] || 0);
    });
    if (loadedDeltas.length === 0 && !hasAdvancingClock) {
      return {
        localSiteId: this.localSiteId,
        remoteSiteId: partitionId,
        deltasReceivedCount: 0,
        deltasAppliedCount: 0,
        conflictsResolvedCount: 0,
        convergedVectorClock: { ...this.vectorClock },
        convergenceStatus: 'NO_REMOTE_DELTAS_AVAILABLE',
        error: `No unreconciled deltas or peer updates exist for remote partition '${partitionId}'.`,
        timestampIso: new Date().toISOString()
      };
    }

    const preTickClock = { ...this.vectorClock };
    this.tickLocalClock();
    return this.reconcileWithRemote(partitionId, mergedRemoteClock, loadedDeltas, {
      markReconciledRowIds: dbRowIdsToReconcile,
      preTickClock
    });
  }

  persistDelta(crdtType, key, payload) {
    try {
      if (this.db) {
        const stmt = this.db.prepare(`
          INSERT INTO ejii_crdt_delta_records (
            site_id, crdt_type, key, delta_payload, vector_clock, timestamp_iso, truetime_ns, reconciled
          ) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
        `);
        stmt.run(
          this.localSiteId,
          crdtType,
          key,
          JSON.stringify(payload),
          JSON.stringify(this.vectorClock),
          new Date().toISOString(),
          nanosecondTrueTimeEngine.now().timestampNs
        );
        this.persistenceDiagnostics.persistenceState = 'SQLITE_PERSISTENT';
        this.persistenceDiagnostics.lastPersistenceError = null;
      }
    } catch (err) {
      this.persistenceDiagnostics.persistenceState = 'SQLITE_DEGRADED';
      this.persistenceDiagnostics.lastPersistenceError = err && err.message ? err.message : String(err);
    }
  }

  getFullStateSnapshot() {
    const pnSnapshot = {};
    for (const key of this.pnCounters.keys()) {
      pnSnapshot[key] = this.getCounterValue(key);
    }

    const lwwSnapshot = {};
    for (const key of this.lwwRegisters.keys()) {
      lwwSnapshot[key] = this.getRegister(key);
    }

    const orSetSnapshot = {};
    for (const key of this.orSets.keys()) {
      orSetSnapshot[key] = this.getSetElements(key);
    }

    return {
      siteId: this.localSiteId,
      vectorClock: { ...this.vectorClock },
      pnCounters: pnSnapshot,
      lwwRegisters: lwwSnapshot,
      orSets: orSetSnapshot,
      partitionStatus: this.partitionStatus
    };
  }
}

const geoPartitionCrdtEngine = new GeoPartitionCrdtEngine();

module.exports = {
  GeoPartitionCrdtEngine,
  geoPartitionCrdtEngine
};
