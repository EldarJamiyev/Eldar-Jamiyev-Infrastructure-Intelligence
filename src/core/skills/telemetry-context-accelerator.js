'use strict';

/**
 * EJII Project Atlas IV+ Evolution — Non-Blocking Time-Sliced Telemetry Context Accelerator
 *
 * Eliminates event-loop stalls during high-volume telemetry bursts (1,000+ raw events) by:
 *   1. Performing hypothesis filtering, MAD/CUSUM/patient-zero anomaly extraction, probe compaction,
 *      priority-ordered retention, exact UTF-8 byte accounting, and prompt synthesis incrementally
 *      across time-sliced chunks (`setImmediate`) without ever delegating back to a synchronous
 *      monolithic pass.
 *   2. Guarding BigInt slice-budget calculation against zero, negative, or sub-microsecond inputs
 *      and guaranteeing at least 1 item is processed per slice so forward progress is strictly monotonic.
 *   3. Handling circular references safely during JSON serialization via a WeakSet replacer.
 *   4. Ranking retained events by causal significance (`isPatientZero`, `|madZScore|`, provenance,
 *      and temporal recency) and computing both exact `Buffer.byteLength(..., 'utf8')` and token
 *      estimates (`Math.ceil(utf8Bytes / 4)`).
 */

const crypto = require('node:crypto');
const { performance } = require('node:perf_hooks');

const MAX_SPILL_STORE_ENTRIES = 64;
const DEFAULT_SPILL_RETENTION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const CRITICAL_EVIDENCE_SPILL_STORE = new Map();

/**
 * Phase Atlas XI — Deep-Copy Isolation Helper
 * Guarantees that callers retrieving or persisting records cannot mutate internal in-memory
 * spill store objects or re-persisted ledger rows via shared object or array references.
 */
function deepCloneEvidenceRecord(val) {
  if (val === null || typeof val !== 'object') {
    return val;
  }
  if (typeof structuredClone === 'function') {
    try {
      return structuredClone(val);
    } catch (_) {}
  }
  try {
    return JSON.parse(JSON.stringify(val));
  } catch (_) {
    if (Array.isArray(val)) {
      return val.map((x) => deepCloneEvidenceRecord(x));
    }
    const copy = {};
    for (const [k, v] of Object.entries(val)) {
      copy[k] = deepCloneEvidenceRecord(v);
    }
    return copy;
  }
}

function resolveSpillDb(explicitDb) {
  if (explicitDb !== undefined) return explicitDb;
  try {
    return require('../../db/database').db;
  } catch (_) {
    return null;
  }
}

function ensureSpillLedgerTable(db) {
  if (!db || typeof db.exec !== 'function') return false;
  db.exec(`
    CREATE TABLE IF NOT EXISTS telemetry_critical_evidence_spill_ledger (
      spill_reference_id TEXT PRIMARY KEY,
      created_at TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      expires_at_ms INTEGER NOT NULL,
      spilled_signatures_count INTEGER NOT NULL DEFAULT 0,
      spilled_occurrences_count INTEGER NOT NULL DEFAULT 0,
      total_event_ids_count INTEGER NOT NULL DEFAULT 0,
      event_ids_json TEXT NOT NULL DEFAULT '[]',
      records_json TEXT NOT NULL DEFAULT '[]',
      metadata_json TEXT NOT NULL DEFAULT '{}'
    );
  `);
  return true;
}

function clearInMemorySpillCacheForTesting() {
  const clearedCount = CRITICAL_EVIDENCE_SPILL_STORE.size;
  CRITICAL_EVIDENCE_SPILL_STORE.clear();
  return { clearedCount };
}

function recordSpilledCriticalEvidenceBatch(spilledCriticalItems = [], metadata = {}) {
  const nowMs = typeof metadata.nowMs === 'number' && Number.isFinite(metadata.nowMs) ? metadata.nowMs : Date.now();
  const retentionTtlMs =
    typeof metadata.retentionTtlMs === 'number' && Number.isFinite(metadata.retentionTtlMs) && metadata.retentionTtlMs > 0
      ? metadata.retentionTtlMs
      : DEFAULT_SPILL_RETENTION_TTL_MS;
  const expiresAtMs = nowMs + retentionTtlMs;
  const maxEntries =
    typeof metadata.maxSpillStoreEntries === 'number' && metadata.maxSpillStoreEntries >= 1
      ? Math.floor(metadata.maxSpillStoreEntries)
      : MAX_SPILL_STORE_ENTRIES;

  const spillReferenceId = `spill_${nowMs}_${crypto.randomBytes(4).toString('hex')}`;
  const fullEventIds = spilledCriticalItems.flatMap((item) =>
    Array.isArray(item.allEventIds) && item.allEventIds.length > 0
      ? item.allEventIds
      : Array.isArray(item.eventIds) && item.eventIds.length > 0
        ? item.eventIds
        : item.id
          ? [String(item.id)]
          : []
  );
  const { db: customDb, ...serializableMeta } = metadata || {};
  const createdAt = new Date(nowMs).toISOString();
  const spilledOccurrencesCount = spilledCriticalItems.reduce(
    (acc, item) => acc + (Number(item.occurrenceCount) || 1),
    0
  );
  const clonedRecords = spilledCriticalItems.map((item) => deepCloneEvidenceRecord(item));

  let persistedToSqlite = false;
  let sqlitePersistenceError = null;
  const db = resolveSpillDb(customDb);
  if (db && typeof db.prepare === 'function') {
    try {
      ensureSpillLedgerTable(db);
      db.prepare(`
        INSERT OR REPLACE INTO telemetry_critical_evidence_spill_ledger (
          spill_reference_id,
          created_at,
          created_at_ms,
          expires_at_ms,
          spilled_signatures_count,
          spilled_occurrences_count,
          total_event_ids_count,
          event_ids_json,
          records_json,
          metadata_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        spillReferenceId,
        createdAt,
        nowMs,
        expiresAtMs,
        spilledCriticalItems.length,
        spilledOccurrencesCount,
        fullEventIds.length,
        JSON.stringify(fullEventIds),
        JSON.stringify(clonedRecords),
        JSON.stringify(serializableMeta)
      );
      persistedToSqlite = true;
    } catch (err) {
      sqlitePersistenceError = err && err.message ? err.message : String(err);
    }
  }

  const entry = {
    spillReferenceId,
    createdAt,
    createdAtMs: nowMs,
    expiresAtMs,
    retentionTtlMs,
    persistedToSqlite,
    persistenceStatus: persistedToSqlite ? 'DURABLE_SQLITE_AND_MEMORY' : 'MEMORY_ONLY_FALLBACK',
    sqlitePersistenceError,
    spilledCriticalSignaturesCount: spilledCriticalItems.length,
    spilledTotalOccurrencesCount: spilledOccurrencesCount,
    totalSpilledEventIdsCount: fullEventIds.length,
    allSpilledEventIds: fullEventIds,
    spilledCriticalRecords: clonedRecords,
    ...serializableMeta
  };

  let evictedFromMemoryCount = 0;
  let evictedUnpersistedSignaturesCount = 0;
  CRITICAL_EVIDENCE_SPILL_STORE.set(spillReferenceId, entry);
  while (CRITICAL_EVIDENCE_SPILL_STORE.size > maxEntries) {
    const oldestKey = CRITICAL_EVIDENCE_SPILL_STORE.keys().next().value;
    if (!oldestKey) break;
    const oldestEntry = CRITICAL_EVIDENCE_SPILL_STORE.get(oldestKey);
    CRITICAL_EVIDENCE_SPILL_STORE.delete(oldestKey);
    evictedFromMemoryCount += 1;
    if (oldestEntry && !oldestEntry.persistedToSqlite) {
      evictedUnpersistedSignaturesCount += Number(oldestEntry.spilledCriticalSignaturesCount || 0);
    }
  }
  entry.evictedFromMemoryCount = evictedFromMemoryCount;
  entry.evictedUnpersistedSignaturesCount = evictedUnpersistedSignaturesCount;
  return entry;
}

function retrieveSpilledCriticalEvidence(spillReferenceId, options = {}) {
  if (!spillReferenceId || typeof spillReferenceId !== 'string') return null;
  const nowMs = typeof options.nowMs === 'number' && Number.isFinite(options.nowMs) ? options.nowMs : Date.now();
  const inMem = CRITICAL_EVIDENCE_SPILL_STORE.get(spillReferenceId);
  if (inMem) {
    if (typeof inMem.expiresAtMs === 'number' && nowMs >= inMem.expiresAtMs && !options.includeExpired) {
      return {
        spillReferenceId,
        expired: true,
        retrievalStatus: 'RETENTION_EXPIRED',
        retrievalSource: 'IN_MEMORY_CACHE',
        createdAt: inMem.createdAt,
        expiresAtMs: inMem.expiresAtMs,
        spilledCriticalSignaturesCount: inMem.spilledCriticalSignaturesCount,
        spilledCriticalRecords: []
      };
    }
    return {
      ...inMem,
      allSpilledEventIds: Array.isArray(inMem.allSpilledEventIds) ? [...inMem.allSpilledEventIds] : [],
      spilledCriticalRecords: Array.isArray(inMem.spilledCriticalRecords)
        ? inMem.spilledCriticalRecords.map((r) => deepCloneEvidenceRecord(r))
        : [],
      expired: false,
      retrievalStatus: 'RETRIEVED_OK',
      retrievalSource: 'IN_MEMORY_CACHE'
    };
  }

  // Fallback to durable SQLite spill ledger if evicted from memory or across process restart
  const db = resolveSpillDb(options.db);
  if (db && typeof db.prepare === 'function') {
    try {
      ensureSpillLedgerTable(db);
      const row = db
        .prepare('SELECT * FROM telemetry_critical_evidence_spill_ledger WHERE spill_reference_id = ?')
        .get(spillReferenceId);
      if (row) {
        const expiresAtMs = Number(row.expires_at_ms || 0);
        if (expiresAtMs > 0 && nowMs >= expiresAtMs && !options.includeExpired) {
          return {
            spillReferenceId: row.spill_reference_id,
            expired: true,
            retrievalStatus: 'RETENTION_EXPIRED',
            retrievalSource: 'DURABLE_SQLITE_LEDGER',
            createdAt: row.created_at,
            expiresAtMs,
            spilledCriticalSignaturesCount: Number(row.spilled_signatures_count || 0),
            spilledCriticalRecords: []
          };
        }
        const parsedIds = JSON.parse(row.event_ids_json || '[]');
        const parsedRecords = JSON.parse(row.records_json || '[]');
        const parsedMeta = JSON.parse(row.metadata_json || '{}');
        const hydrated = {
          spillReferenceId: row.spill_reference_id,
          createdAt: row.created_at,
          createdAtMs: Number(row.created_at_ms || 0),
          expiresAtMs,
          persistedToSqlite: true,
          persistenceStatus: 'DURABLE_SQLITE_HYDRATED',
          expired: false,
          retrievalStatus: 'RETRIEVED_OK',
          retrievalSource: 'DURABLE_SQLITE_LEDGER',
          spilledCriticalSignaturesCount: Number(row.spilled_signatures_count || parsedRecords.length),
          spilledTotalOccurrencesCount: Number(row.spilled_occurrences_count || parsedRecords.length),
          totalSpilledEventIdsCount: Number(row.total_event_ids_count || parsedIds.length),
          allSpilledEventIds: parsedIds,
          spilledCriticalRecords: parsedRecords.map((r) => deepCloneEvidenceRecord(r)),
          ...parsedMeta
        };
        return hydrated;
      }
    } catch (_) {}
  }

  return null;
}

/**
 * Prunes expired spilled critical evidence records from both the in-memory cache
 * and the durable SQLite spill ledger table (`telemetry_critical_evidence_spill_ledger`).
 *
 * @param {object} [options]
 * @param {object} [options.db] - Optional SQLite db instance
 * @param {number} [options.nowMs] - Current timestamp ms (defaults to Date.now())
 * @param {number} [options.maxDeletions] - Bounded deletion limit per run (defaults to 500)
 * @returns {{ prunedFromMemoryCount: number, prunedFromSqliteCount: number, deletedReferenceIds: string[], remainingMemoryCount: number, remainingSqliteCount: number }}
 */
function pruneExpiredSpilledCriticalEvidence(options = {}) {
  const nowMs = typeof options.nowMs === 'number' && Number.isFinite(options.nowMs) ? options.nowMs : Date.now();
  const maxDeletions = Math.max(1, Math.min(5000, Number(options.maxDeletions) || 500));
  let prunedFromMemoryCount = 0;
  const deletedReferenceIds = [];

  // 1. In-memory cleanup
  for (const [refId, entry] of CRITICAL_EVIDENCE_SPILL_STORE.entries()) {
    if (typeof entry.expiresAtMs === 'number' && nowMs >= entry.expiresAtMs) {
      CRITICAL_EVIDENCE_SPILL_STORE.delete(refId);
      prunedFromMemoryCount += 1;
      deletedReferenceIds.push(refId);
    }
  }

  // 2. Physical SQLite cleanup
  let prunedFromSqliteCount = 0;
  let remainingSqliteCount = 0;
  const db = resolveSpillDb(options.db);
  if (db && typeof db.prepare === 'function') {
    try {
      ensureSpillLedgerTable(db);
      const expiredRows = db
        .prepare('SELECT spill_reference_id FROM telemetry_critical_evidence_spill_ledger WHERE expires_at_ms <= ? LIMIT ?')
        .all(nowMs, maxDeletions);

      if (expiredRows && expiredRows.length > 0) {
        const deleteStmt = db.prepare('DELETE FROM telemetry_critical_evidence_spill_ledger WHERE spill_reference_id = ?');
        let count = 0;
        try {
          if (typeof db.exec === 'function') db.exec('BEGIN');
          for (const row of expiredRows) {
            deleteStmt.run(row.spill_reference_id);
            count += 1;
            if (!deletedReferenceIds.includes(row.spill_reference_id)) {
              deletedReferenceIds.push(row.spill_reference_id);
            }
          }
          if (typeof db.exec === 'function') db.exec('COMMIT');
        } catch (delErr) {
          try {
            if (typeof db.exec === 'function') db.exec('ROLLBACK');
          } catch (_) {}
          throw delErr;
        }
        prunedFromSqliteCount = count;
      }

      const countRow = db.prepare('SELECT COUNT(*) AS cnt FROM telemetry_critical_evidence_spill_ledger').get();
      remainingSqliteCount = Number(countRow?.cnt || 0);
    } catch (_) {}
  }

  return {
    prunedFromMemoryCount,
    prunedFromSqliteCount,
    deletedReferenceIds,
    remainingMemoryCount: CRITICAL_EVIDENCE_SPILL_STORE.size,
    remainingSqliteCount
  };
}

function compactProbeRecordStrict(p) {
  if (!p || typeof p !== 'object' || Array.isArray(p)) {
    return {
      probeType: 'UNKNOWN',
      target: 'unknown',
      status: 'MALFORMED_PROBE',
      statusSource: 'VALIDATION_GUARD',
      executed: false,
      anomalyDetected: false,
      latencyMs: null,
      errorCode: 'INVALID_PROBE_OBJECT'
    };
  }
  const hasKnownIdentity = Boolean(
    (typeof p.probeType === 'string' && p.probeType.trim()) ||
      (typeof p.protocol === 'string' && p.protocol.trim()) ||
      (typeof p.target === 'string' && p.target.trim()) ||
      (typeof p.domainId === 'string' && p.domainId.trim())
  );
  const rawLatency =
    typeof p.latencyMs === 'number' && Number.isFinite(p.latencyMs)
      ? p.latencyMs
      : typeof p.rttMs === 'number' && Number.isFinite(p.rttMs)
        ? p.rttMs
        : typeof p.durationMs === 'number' && Number.isFinite(p.durationMs)
          ? p.durationMs
          : null;
  const latencyMs = rawLatency !== null && rawLatency >= 0 ? Number(rawLatency.toFixed(2)) : null;
  const rawStatus = typeof p.status === 'string' ? p.status.trim().toUpperCase() : '';
  const hasExplicitError = Boolean(p.errorCode || p.error);

  if (!hasKnownIdentity && !rawStatus && latencyMs === null && p.reachable === undefined && p.anomalyDetected === undefined) {
    return {
      probeType: 'UNKNOWN',
      target: 'unknown',
      status: 'MALFORMED_PROBE',
      statusSource: 'VALIDATION_GUARD',
      executed: false,
      anomalyDetected: false,
      latencyMs: null,
      errorCode: 'EMPTY_OR_UNRECOGNIZED_PROBE'
    };
  }

  let status = 'UNKNOWN';
  let statusSource = 'UNSPECIFIED';
  let executed = p.executed !== undefined ? Boolean(p.executed) : null;

  if (rawStatus === 'MALFORMED_PROBE') {
    status = 'MALFORMED_PROBE';
    statusSource = 'EXPLICIT_STATUS';
    executed = false;
  } else if (rawStatus === 'UNEXECUTED' || p.executed === false) {
    status = 'UNEXECUTED';
    statusSource = p.executed === false ? 'EXECUTION_FLAG' : 'EXPLICIT_STATUS';
    executed = false;
  } else if (rawStatus === 'UNAVAILABLE' || p.available === false) {
    status = 'UNAVAILABLE';
    statusSource = 'EXPLICIT_STATUS';
    executed = false;
  } else if (p.reachable === false || rawStatus === 'UNREACHABLE' || rawStatus === 'TIMEOUT') {
    status = 'UNREACHABLE';
    statusSource = p.reachable === false ? 'REACHABILITY_FLAG' : 'EXPLICIT_STATUS';
    executed = true;
  } else if (
    p.anomalyDetected === true ||
    rawStatus === 'ANOMALY' ||
    rawStatus === 'DEGRADED' ||
    rawStatus === 'FAIL' ||
    rawStatus === 'FAILED' ||
    hasExplicitError
  ) {
    status = rawStatus === 'DEGRADED' ? 'DEGRADED' : 'ANOMALY';
    statusSource = rawStatus ? 'EXPLICIT_STATUS' : 'MEASURED_ANOMALY_SIGNAL';
    executed = true;
  } else if (rawStatus === 'OK' || rawStatus === 'PASS' || rawStatus === 'HEALTHY') {
    status = rawStatus === 'PASS' ? 'PASS' : 'OK';
    statusSource = 'EXPLICIT_STATUS';
    executed = true;
  } else if (
    (p.reachable === true || p.anomalyDetected === false) &&
    (latencyMs !== null || (typeof p.statusCode === 'number' && p.statusCode >= 200 && p.statusCode < 400))
  ) {
    status = 'OK';
    statusSource = 'MEASURED_EXECUTION_TELEMETRY';
    executed = true;
  } else {
    // Never optimistically assign OK/PASS when status is missing and no execution telemetry proves health
    status = 'UNKNOWN';
    statusSource = 'MISSING_EXPLICIT_STATUS';
    executed = latencyMs !== null ? true : false;
  }

  return {
    probeType: String(p.probeType || p.protocol || 'TCP'),
    target: String(p.target || 'unknown'),
    status,
    statusSource,
    executed: Boolean(executed),
    anomalyDetected: Boolean(p.anomalyDetected || status === 'ANOMALY' || status === 'DEGRADED' || status === 'UNREACHABLE'),
    latencyMs,
    ...(typeof p.statusCode === 'number' ? { statusCode: p.statusCode } : {}),
    ...(p.finding ? { finding: String(p.finding) } : {}),
    errorCode: p.errorCode || null
  };
}

function safeJsonStringify(value) {
  const seen = new WeakSet();
  try {
    return JSON.stringify(value, (_key, val) => {
      if (val !== null && typeof val === 'object') {
        if (seen.has(val)) return '[Circular]';
        seen.add(val);
      }
      return val;
    });
  } catch (_) {
    return String(value);
  }
}

function normalizeSliceBudgetNs(rawBudgetMs) {
  if (typeof rawBudgetMs === 'bigint') {
    return rawBudgetMs > 10_000n ? rawBudgetMs : 500_000n;
  }
  const numMs = Number(rawBudgetMs);
  if (!Number.isFinite(numMs) || numMs <= 0) {
    return 2_000_000n; // Default 2.0 ms in nanoseconds
  }
  const clampedMs = Math.max(0.05, Math.min(50, numMs));
  return BigInt(Math.round(clampedMs * 1_000_000));
}

function isCriticalEvidenceEvent(evt) {
  if (!evt || typeof evt !== 'object') return false;
  if (evt.isPatientZero === true) return true;
  if (String(evt.severity || '').toUpperCase() === 'CRITICAL') return true;
  if (Math.abs(Number(evt.madZScore || 0)) >= 3.0) return true;
  if (Math.abs(Number(evt.cusumShift || 0)) >= 2.5 || evt.cusumAlert === true) return true;
  return false;
}

function computeEventPriorityScore(evt) {
  let score = 0;
  if (evt.isPatientZero) score += 2000;
  if (String(evt.severity || '').toUpperCase() === 'CRITICAL') score += 1500;
  const zAbs = Math.abs(Number(evt.madZScore || 0));
  if (zAbs >= 3.0) score += 1000;
  score += Math.min(500, zAbs * 25);
  const cusum = Math.abs(Number(evt.cusumShift || 0));
  if (cusum >= 2.5 || evt.cusumAlert === true) score += 800;
  score += Math.min(200, cusum * 10);
  if (evt.provenance === 'DIRECT_SOCKET_MEASUREMENT' || evt.provenance === 'DIRECT_PROBE') {
    score += 50;
  }
  return score;
}

function updateDeduplicatedCriticalGroup(existingGroup, e, tsVal, eventIdVal, provenanceVal, numericVal, zScore) {
  const ce = existingGroup.compactEvent;
  ce.occurrenceCount = (ce.occurrenceCount || 1) + 1;
  if (tsVal) {
    if (!ce.firstSeenTimestamp && ce.ts) {
      ce.firstSeenTimestamp = ce.ts;
    }
    if (!ce.lastSeenTimestamp && ce.ts) {
      ce.lastSeenTimestamp = ce.ts;
    }
    if (!ce.firstSeenTimestamp || String(tsVal) < String(ce.firstSeenTimestamp)) {
      ce.firstSeenTimestamp = tsVal;
    }
    if (!ce.lastSeenTimestamp || String(tsVal) > String(ce.lastSeenTimestamp)) {
      ce.lastSeenTimestamp = tsVal;
      ce.ts = tsVal;
    }
    const firstMs = Date.parse(ce.firstSeenTimestamp || '');
    const lastMs = Date.parse(ce.lastSeenTimestamp || '');
    if (Number.isFinite(firstMs) && Number.isFinite(lastMs) && lastMs >= firstMs) {
      ce.observationIntervalMs = lastMs - firstMs;
    }
  }
  if (numericVal !== null) {
    if (ce.firstValue === undefined || ce.firstValue === null) {
      ce.firstValue = numericVal;
    }
    ce.latestValue = numericVal;
    ce.val = numericVal;
    ce.minValue = ce.minValue === undefined || ce.minValue === null ? numericVal : Math.min(ce.minValue, numericVal);
    ce.maxValue = ce.maxValue === undefined || ce.maxValue === null ? numericVal : Math.max(ce.maxValue, numericVal);
    if (ce.minValue !== ce.maxValue) {
      ce.valueChanged = true;
    }
  }
  if (Math.abs(zScore) > Math.abs(Number(ce.peakZScore ?? ce.zScore ?? 0))) {
    ce.peakZScore = Number(zScore.toFixed(2));
  }
  if (provenanceVal) {
    if (!Array.isArray(ce.provenanceList)) {
      ce.provenanceList = ce.provenance ? [ce.provenance] : [];
    }
    if (!ce.provenanceList.includes(provenanceVal)) {
      ce.provenanceList.push(provenanceVal);
    }
  }
  if (eventIdVal) {
    const idStr = String(eventIdVal);
    if (!Array.isArray(existingGroup.allEventIds)) {
      existingGroup.allEventIds = Array.isArray(ce.eventIds) ? [...ce.eventIds] : [];
    }
    if (!existingGroup.allEventIds.includes(idStr)) {
      existingGroup.allEventIds.push(idStr);
    }
    if (!Array.isArray(ce.eventIds)) {
      ce.eventIds = [];
    }
    if (ce.eventIds.length < 16 && !ce.eventIds.includes(idStr)) {
      ce.eventIds.push(idStr);
    }
    ce.totalEventIdsCount = existingGroup.allEventIds.length;
  }
}

async function compileTelemetryContextWindowNonBlocking(
  telemetryEvents = [],
  activeHypotheses = [],
  probeResults = [],
  options = {}
) {
  const t0 = performance.now();
  const safeEvents = Array.isArray(telemetryEvents) ? telemetryEvents : [];
  const safeHypotheses = Array.isArray(activeHypotheses) ? activeHypotheses : [];
  const safeProbes = Array.isArray(probeResults) ? probeResults : [];

  const rawRequestedTokens = options.maxTokens !== undefined ? Number(options.maxTokens) : 2048;
  const requestedMaxTokens = Number.isFinite(rawRequestedTokens) && rawRequestedTokens > 0 ? rawRequestedTokens : 2048;
  const maxTokens = Math.max(16, requestedMaxTokens);
  const tokenBudgetClampReason =
    requestedMaxTokens < 16 ? 'CLAMPED_TO_MINIMUM_16_TOKENS' : null;
  const rawRequestedBytes = options.maxBytesBudget !== undefined ? Number(options.maxBytesBudget) : maxTokens * 4;
  const maxBytesBudget = Math.max(64, Number.isFinite(rawRequestedBytes) && rawRequestedBytes > 0 ? rawRequestedBytes : maxTokens * 4);
  const maxInContextCriticalEvents = Math.max(1, Number(options.maxInContextCriticalEvents) || 64);
  const maxCriticalOverflowBytes = Math.max(256, Number(options.maxCriticalOverflowBytes) || 16384);
  const sliceBudgetNs = normalizeSliceBudgetNs(options.maxSliceBudgetMs);

  let yieldCount = 0;
  let maxSliceDurationMs = 0;
  let sliceStartNs = process.hrtime.bigint();
  let itemsInCurrentSlice = 0;

  const maybeYieldSlice = async () => {
    itemsInCurrentSlice += 1;
    if (itemsInCurrentSlice < 1) return;
    const elapsedNs = process.hrtime.bigint() - sliceStartNs;
    const elapsedMs = Number(elapsedNs) / 1e6;
    if (elapsedMs > maxSliceDurationMs) {
      maxSliceDurationMs = elapsedMs;
    }
    if (elapsedNs >= sliceBudgetNs) {
      yieldCount += 1;
      await new Promise((resolve) => setImmediate(resolve));
      sliceStartNs = process.hrtime.bigint();
      itemsInCurrentSlice = 0;
    }
  };

  let rawUtf8Bytes = 0;

  // Stage 1: Time-sliced hypothesis filtering & ranking (retain probability >= 12%)
  const candidateHypotheses = [];
  for (let i = 0; i < safeHypotheses.length; i++) {
    const h = safeHypotheses[i];
    if (h && typeof h === 'object') {
      rawUtf8Bytes += Buffer.byteLength(safeJsonStringify(h), 'utf8');
      const prob = Number(h.probabilityPct ?? h.posteriorProbabilityPct ?? 0);
      if (prob >= 12) {
        candidateHypotheses.push({
          domain: String(h.domain || h.layer || 'UNKNOWN'),
          probabilityPct: Number(prob.toFixed(1)),
          status: String(h.status || 'PLAUSIBLE_CANDIDATE'),
          evidenceType: String(h.evidenceType || 'MEASURED_OBSERVATION')
        });
      }
    }
    await maybeYieldSlice();
  }
  candidateHypotheses.sort((a, b) => b.probabilityPct - a.probabilityPct);
  const retainedHypotheses = candidateHypotheses.slice(0, 5);

  // Stage 2: Time-sliced MAD/CUSUM/Patient-Zero anomaly extraction across all telemetry events
  const scoredAnomalies = [];
  const criticalSignatureGroups = new Map();
  let totalCriticalInputCount = 0;
  let deduplicatedCriticalRetriesCount = 0;

  for (let i = 0; i < safeEvents.length; i++) {
    const e = safeEvents[i];
    if (e && typeof e === 'object') {
      const serialized = safeJsonStringify(e);
      rawUtf8Bytes += Buffer.byteLength(serialized, 'utf8');

      const zScore = Number(e.madZScore || 0);
      const isPatientZero = Boolean(e.isPatientZero);
      const isCritical = isCriticalEvidenceEvent(e);
      const isSignificant = isCritical || Math.abs(zScore) >= 1.0;

      if (isSignificant) {
        const layer = String(e.layer || e.domain || 'L3_NETWORK');
        const target = String(e.target || e.subjectId || 'unknown');
        const metric = String(e.metric || 'latencyMs');
        const severityKey = String(e.severity || (isCritical ? 'CRITICAL' : 'WARN')).toUpperCase();
        const errCodeKey = String(e.errorCode || e.code || '');
        const eventIdVal = e.eventId || e.id || undefined;
        const tsVal = e.timestamp || e.ts || null;
        const provenanceVal = String(e.provenance || 'TELEMETRY_STREAM');
        const numericVal =
          typeof e.value === 'number' && Number.isFinite(e.value) ? Number(e.value.toFixed(2)) : null;

        if (isCritical) {
          totalCriticalInputCount += 1;
          const faultSigKey = `${layer}|${target}|${metric}|${severityKey}|${errCodeKey}|${isPatientZero ? 'PZ' : 'STD'}`;
          if (criticalSignatureGroups.has(faultSigKey)) {
            const existingGroup = criticalSignatureGroups.get(faultSigKey);
            updateDeduplicatedCriticalGroup(
              existingGroup,
              e,
              tsVal,
              eventIdVal,
              provenanceVal,
              numericVal,
              zScore
            );
            deduplicatedCriticalRetriesCount += 1;
            await maybeYieldSlice();
            continue;
          }

          const compactEvent = {
            ...(eventIdVal ? { id: eventIdVal } : {}),
            ...(eventIdVal ? { eventIds: [String(eventIdVal)] } : {}),
            ts: tsVal,
            layer,
            target,
            metric,
            severity: severityKey,
            val: numericVal,
            ...(e.errorCode || e.code ? { errorCode: e.errorCode || e.code } : {}),
            zScore: Number(zScore.toFixed(2)),
            ...(Number(e.cusumShift || 0) !== 0 ? { cusum: Number(Number(e.cusumShift || 0).toFixed(2)) } : {}),
            ...(isPatientZero ? { isPatientZero: true } : {}),
            critical: true
          };
          if (numericVal !== null) {
            compactEvent.firstValue = numericVal;
            compactEvent.latestValue = numericVal;
            compactEvent.minValue = numericVal;
            compactEvent.maxValue = numericVal;
          }
          if (provenanceVal && provenanceVal !== 'TELEMETRY_STREAM') {
            compactEvent.provenance = provenanceVal;
            compactEvent.provenanceList = [provenanceVal];
          }
          const anomalyEntry = {
            compactEvent,
            allEventIds: eventIdVal ? [String(eventIdVal)] : [],
            firstSeenTimestamp: tsVal,
            lastSeenTimestamp: tsVal,
            provenance: provenanceVal,
            isCritical: true,
            isUniqueCriticalRepresentative: true,
            priorityScore: computeEventPriorityScore(e) + 5000,
            originalIndex: i
          };
          criticalSignatureGroups.set(faultSigKey, anomalyEntry);
          scoredAnomalies.push(anomalyEntry);
        } else {
          const compactEvent = {
            id: eventIdVal,
            ts: tsVal,
            layer,
            target,
            metric,
            val: numericVal,
            errorCode: e.errorCode || e.code || undefined,
            zScore: Number(zScore.toFixed(2)),
            cusum: Number(Number(e.cusumShift || 0).toFixed(2)),
            isPatientZero,
            critical: false
          };
          scoredAnomalies.push({
            compactEvent,
            isCritical: false,
            isUniqueCriticalRepresentative: false,
            priorityScore: computeEventPriorityScore(e),
            originalIndex: i
          });
        }
      }
    }
    await maybeYieldSlice();
  }

  // Sort by priorityScore descending, then most recent index descending
  scoredAnomalies.sort((a, b) => {
    if (b.priorityScore !== a.priorityScore) return b.priorityScore - a.priorityScore;
    return b.originalIndex - a.originalIndex;
  });

  // Stage 3: Time-sliced probe compaction with strict status taxonomy (no optimistic 'OK' default)
  const compactedProbes = [];
  for (let i = 0; i < safeProbes.length; i++) {
    const p = safeProbes[i];
    if (p && typeof p === 'object') {
      rawUtf8Bytes += Buffer.byteLength(safeJsonStringify(p), 'utf8');
      if (compactedProbes.length < 15) {
        compactedProbes.push(compactProbeRecordStrict(p));
      }
    } else if (p !== undefined && p !== null) {
      if (compactedProbes.length < 15) {
        compactedProbes.push(compactProbeRecordStrict(p));
      }
    }
    await maybeYieldSlice();
  }

  // Stage 4: Enforce UTF-8 byte & token budget + hard critical in-context cap with retrievable spill store
  const baseEnvelope = {
    schemaVersion: 'ejii-context-window-v2-sliced',
    retainedHypotheses,
    retainedAnomalies: [],
    compactedProbes
  };
  let currentBytes = Buffer.byteLength(safeJsonStringify(baseEnvelope), 'utf8') + 96;
  const selectedAnomalies = [];
  const spilledCriticalItems = [];
  const maxAnomaliesCap = Math.max(10, Number(options.maxRetainedAnomalies) || 32);
  let inContextCriticalCount = 0;
  let retainedUniqueCriticalCount = 0;

  for (let i = 0; i < scoredAnomalies.length; i++) {
    const entry = scoredAnomalies[i];
    const candidate = entry.compactEvent;
    const candidateBytes = Buffer.byteLength(safeJsonStringify(candidate), 'utf8') + 2;

    if (entry.isUniqueCriticalRepresentative) {
      const projectedOverflowBytes = Math.max(0, currentBytes + candidateBytes - maxBytesBudget);
      const withinCriticalCap =
        inContextCriticalCount < maxInContextCriticalEvents &&
        (inContextCriticalCount === 0 || projectedOverflowBytes <= maxCriticalOverflowBytes);

      if (withinCriticalCap) {
        selectedAnomalies.push(candidate);
        currentBytes += candidateBytes;
        inContextCriticalCount += 1;
        retainedUniqueCriticalCount += 1;
      } else {
        spilledCriticalItems.push({
          ...candidate,
          allEventIds:
            Array.isArray(entry.allEventIds) && entry.allEventIds.length > 0
              ? entry.allEventIds
              : Array.isArray(candidate.eventIds)
                ? candidate.eventIds
                : candidate.id
                  ? [String(candidate.id)]
                  : [],
          firstSeenTimestamp: candidate.firstSeenTimestamp || entry.firstSeenTimestamp || candidate.ts || null,
          lastSeenTimestamp: candidate.lastSeenTimestamp || entry.lastSeenTimestamp || candidate.ts || null,
          provenance: candidate.provenance || entry.provenance || 'TELEMETRY_STREAM'
        });
        retainedUniqueCriticalCount += 1;
      }
    } else {
      if (selectedAnomalies.length >= maxAnomaliesCap) continue;
      if (currentBytes + candidateBytes > maxBytesBudget && selectedAnomalies.length > 0) {
        continue;
      }
      selectedAnomalies.push(candidate);
      currentBytes += candidateBytes;
    }
    await maybeYieldSlice();
  }

  let spillStoreEntry = null;
  if (spilledCriticalItems.length > 0 && options.disableSpillBackingStore !== true) {
    spillStoreEntry = recordSpilledCriticalEvidenceBatch(spilledCriticalItems, {
      maxInContextCriticalEvents,
      maxCriticalOverflowBytes,
      db: options.db,
      retentionTtlMs: options.spillRetentionTtlMs,
      nowMs: options.nowMs,
      maxSpillStoreEntries: options.maxSpillStoreEntries
    });
  }

  const allSpilledIds = spilledCriticalItems.flatMap((item) =>
    Array.isArray(item.allEventIds) && item.allEventIds.length > 0
      ? item.allEventIds
      : Array.isArray(item.eventIds) && item.eventIds.length > 0
        ? item.eventIds
        : item.id
          ? [String(item.id)]
          : []
  );

  const externalizedCriticalEvidenceOverflow =
    spilledCriticalItems.length > 0
      ? {
          spillReferenceId: spillStoreEntry ? spillStoreEntry.spillReferenceId : null,
          retrievableFromBackingStore: Boolean(spillStoreEntry),
          persistedToSqlite: Boolean(spillStoreEntry && spillStoreEntry.persistedToSqlite),
          persistenceStatus: spillStoreEntry
            ? spillStoreEntry.persistenceStatus
            : 'BACKING_STORE_DISABLED',
          expiresAtMs: spillStoreEntry ? spillStoreEntry.expiresAtMs : null,
          spilledCriticalSignaturesCount: spilledCriticalItems.length,
          spilledTotalOccurrencesCount: spilledCriticalItems.reduce(
            (acc, item) => acc + (Number(item.occurrenceCount) || 1),
            0
          ),
          totalSpilledEventIdsCount: allSpilledIds.length,
          unindexedSpilledEventIdsCount: spillStoreEntry ? 0 : Math.max(0, allSpilledIds.length - 64),
          maxInContextCriticalEvents,
          maxCriticalOverflowBytes,
          spilledEventIds: allSpilledIds.slice(0, 64),
          spilledSummaries: spilledCriticalItems.slice(0, 32).map((item) => ({
            layer: item.layer,
            target: item.target,
            metric: item.metric,
            severity: item.severity || 'CRITICAL',
            errorCode: item.errorCode || null,
            occurrenceCount: item.occurrenceCount || 1,
            firstValue: item.firstValue ?? item.val ?? null,
            latestValue: item.latestValue ?? item.val ?? null,
            minValue: item.minValue ?? item.val ?? null,
            maxValue: item.maxValue ?? item.val ?? null,
            firstSeenTimestamp: item.firstSeenTimestamp || item.ts || null,
            lastSeenTimestamp: item.lastSeenTimestamp || item.ts || null,
            observationIntervalMs: item.observationIntervalMs ?? 0,
            provenance: item.provenance || 'TELEMETRY_STREAM',
            provenanceList: item.provenanceList || [item.provenance || 'TELEMETRY_STREAM']
          }))
        }
      : null;

  // If backing store is disabled or unpersisted in-memory entries were evicted, count unretained items truthfully
  const unretainedSpillSignatures =
    spilledCriticalItems.length > 0 && !spillStoreEntry
      ? Math.max(0, spilledCriticalItems.length - 32)
      : spillStoreEntry && spillStoreEntry.evictedUnpersistedSignaturesCount > 0
        ? spillStoreEntry.evictedUnpersistedSignaturesCount
        : 0;
  const criticalEvidenceDroppedCount = Math.max(
    0,
    criticalSignatureGroups.size - retainedUniqueCriticalCount + unretainedSpillSignatures
  );

  const finalPayload = {
    schemaVersion: 'ejii-context-window-v2-sliced',
    summary: {
      rawEventCount: safeEvents.length,
      retainedAnomalyCount: selectedAnomalies.length,
      retainedHypothesisCount: retainedHypotheses.length,
      retainedProbeCount: compactedProbes.length,
      uniqueCriticalSignaturesCount: criticalSignatureGroups.size,
      inContextCriticalCount,
      spilledCriticalSignaturesCount: spilledCriticalItems.length,
      deduplicatedCriticalRetriesCount,
      retainedUniqueCriticalCount,
      criticalEvidenceDroppedCount
    },
    retainedHypotheses,
    retainedAnomalies: selectedAnomalies,
    ...(externalizedCriticalEvidenceOverflow ? { externalizedCriticalEvidenceOverflow } : {}),
    compactedProbes
  };

  const promptContextBlock = `<ejii_telemetry_context_window>\n${safeJsonStringify(finalPayload)}\n</ejii_telemetry_context_window>`;
  const compiledUtf8Bytes = Buffer.byteLength(promptContextBlock, 'utf8');
  const rawTokensEstimate = Math.max(1, Math.ceil(rawUtf8Bytes / 4));
  const compiledTokensEstimate = Math.max(1, Math.ceil(compiledUtf8Bytes / 4));
  const compressionRatioPct =
    rawUtf8Bytes > compiledUtf8Bytes
      ? Number((((rawUtf8Bytes - compiledUtf8Bytes) / rawUtf8Bytes) * 100).toFixed(2))
      : 0;

  const totalDurationMs = Number((performance.now() - t0).toFixed(3));
  const withinTokenBudget = compiledTokensEstimate <= maxTokens && compiledUtf8Bytes <= maxBytesBudget;
  const criticalBudgetOverflow = !withinTokenBudget;
  const overflowBytes = Math.max(0, compiledUtf8Bytes - maxBytesBudget);
  const overflowTokens = Math.max(0, compiledTokensEstimate - maxTokens);

  return {
    schemaVersion: 'ejii-context-window-v2-sliced',
    rawEventCount: safeEvents.length,
    retainedAnomalyCount: selectedAnomalies.length,
    retainedHypothesisCount: retainedHypotheses.length,
    retainedProbeCount: compactedProbes.length,
    totalCriticalInputCount,
    uniqueCriticalSignaturesCount: criticalSignatureGroups.size,
    inContextCriticalCount,
    spilledCriticalSignaturesCount: spilledCriticalItems.length,
    deduplicatedCriticalRetriesCount,
    retainedUniqueCriticalCount,
    criticalEvidenceDroppedCount,
    externalizedCriticalEvidenceOverflow,
    rawUtf8Bytes,
    compiledUtf8Bytes,
    rawTokensEstimate,
    compiledTokensEstimate,
    requestedMaxTokens,
    effectiveMaxTokens: maxTokens,
    tokenBudgetClampReason,
    tokenBudgetLimit: maxTokens,
    maxBytesBudget,
    maxInContextCriticalEvents,
    maxCriticalOverflowBytes,
    withinTokenBudget,
    criticalBudgetOverflow,
    overflowBytes,
    overflowTokens,
    budgetComplianceState: externalizedCriticalEvidenceOverflow
      ? 'OVERFLOW_CRITICAL_EVIDENCE_SPILLED_WITH_MANIFEST'
      : criticalBudgetOverflow
        ? 'OVERFLOW_CRITICAL_EVIDENCE_PRESERVED'
        : 'WITHIN_BUDGET',
    compressionRatioPct,
    retainedHypotheses,
    retainedAnomalies: selectedAnomalies,
    compactedProbes,
    promptContextBlock,
    nonBlockingExecution: {
      enabled: true,
      pipelineMode: 'TIME_SLICED_INCREMENTAL_EXTRACTION',
      yieldCount,
      maxSliceDurationMs: Number(maxSliceDurationMs.toFixed(3)),
      totalDurationMs,
      sliceBudgetMs: Number(sliceBudgetNs) / 1e6
    }
  };
}

/**
 * Synchronous baseline context compiler used strictly by `benchmarkContextCompilation` to
 * compare synchronous blocking execution vs. time-sliced non-blocking execution on the exact
 * same telemetry dataset and identical transformation stages (Cycle 9).
 */
function compileTelemetryContextWindowSynchronousBaseline(
  telemetryEvents = [],
  activeHypotheses = [],
  probeResults = [],
  options = {}
) {
  const t0 = performance.now();
  const safeEvents = Array.isArray(telemetryEvents) ? telemetryEvents : [];
  const safeHypotheses = Array.isArray(activeHypotheses) ? activeHypotheses : [];
  const safeProbes = Array.isArray(probeResults) ? probeResults : [];
  const rawRequestedTokens = options.maxTokens !== undefined ? Number(options.maxTokens) : 2048;
  const maxTokens = Math.max(16, Number.isFinite(rawRequestedTokens) && rawRequestedTokens > 0 ? rawRequestedTokens : 2048);
  const maxBytesBudget = Math.max(64, Number(options.maxBytesBudget) || maxTokens * 4);
  const maxInContextCriticalEvents = Math.max(1, Number(options.maxInContextCriticalEvents) || 64);
  const maxCriticalOverflowBytes = Math.max(256, Number(options.maxCriticalOverflowBytes) || 16384);

  let rawUtf8Bytes = 0;

  // Stage 1: Synchronous hypothesis filtering & ranking
  const candidateHypotheses = [];
  for (let i = 0; i < safeHypotheses.length; i++) {
    const h = safeHypotheses[i];
    if (h && typeof h === 'object') {
      rawUtf8Bytes += Buffer.byteLength(safeJsonStringify(h), 'utf8');
      const prob = Number(h.probabilityPct ?? h.posteriorProbabilityPct ?? 0);
      if (prob >= 12) {
        candidateHypotheses.push({
          domain: String(h.domain || h.layer || 'UNKNOWN'),
          probabilityPct: Number(prob.toFixed(1)),
          status: String(h.status || 'PLAUSIBLE_CANDIDATE'),
          evidenceType: String(h.evidenceType || 'MEASURED_OBSERVATION')
        });
      }
    }
  }
  candidateHypotheses.sort((a, b) => b.probabilityPct - a.probabilityPct);
  const retainedHypotheses = candidateHypotheses.slice(0, 5);

  // Stage 2: Synchronous MAD/CUSUM/Critical scoring & signature deduplication
  const scoredAnomalies = [];
  const criticalSignatureGroups = new Map();
  for (let i = 0; i < safeEvents.length; i++) {
    const e = safeEvents[i];
    if (e && typeof e === 'object') {
      rawUtf8Bytes += Buffer.byteLength(safeJsonStringify(e), 'utf8');
      const zScore = Number(e.madZScore || 0);
      const isPatientZero = Boolean(e.isPatientZero);
      const isCritical = isCriticalEvidenceEvent(e);
      const isSignificant = isCritical || Math.abs(zScore) >= 1.0;
      if (isSignificant) {
        const layer = String(e.layer || e.domain || 'L3_NETWORK');
        const target = String(e.target || e.subjectId || 'unknown');
        const metric = String(e.metric || 'latencyMs');
        const severityKey = String(e.severity || (isCritical ? 'CRITICAL' : 'WARN')).toUpperCase();
        const errCodeKey = String(e.errorCode || e.code || '');
        const eventIdVal = e.eventId || e.id || undefined;
        const tsVal = e.timestamp || e.ts || null;
        const provenanceVal = String(e.provenance || 'TELEMETRY_STREAM');
        const numericVal =
          typeof e.value === 'number' && Number.isFinite(e.value) ? Number(e.value.toFixed(2)) : null;

        if (isCritical) {
          const faultSigKey = `${layer}|${target}|${metric}|${severityKey}|${errCodeKey}|${isPatientZero ? 'PZ' : 'STD'}`;
          if (criticalSignatureGroups.has(faultSigKey)) {
            const existingGroup = criticalSignatureGroups.get(faultSigKey);
            updateDeduplicatedCriticalGroup(
              existingGroup,
              e,
              tsVal,
              eventIdVal,
              provenanceVal,
              numericVal,
              zScore
            );
            continue;
          }
          const compactEvent = {
            id: eventIdVal,
            eventIds: eventIdVal ? [String(eventIdVal)] : [],
            ts: tsVal,
            firstSeenTimestamp: tsVal,
            lastSeenTimestamp: tsVal,
            occurrenceCount: 1,
            provenance: provenanceVal,
            provenanceList: [provenanceVal],
            layer,
            target,
            metric,
            severity: severityKey,
            val: numericVal,
            firstValue: numericVal,
            latestValue: numericVal,
            minValue: numericVal,
            maxValue: numericVal,
            errorCode: e.errorCode || e.code || undefined,
            zScore: Number(zScore.toFixed(2)),
            cusum: Number(Number(e.cusumShift || 0).toFixed(2)),
            isPatientZero,
            critical: true
          };
          const anomalyEntry = {
            compactEvent,
            allEventIds: eventIdVal ? [String(eventIdVal)] : [],
            isCritical: true,
            isUniqueCriticalRepresentative: true,
            priorityScore: computeEventPriorityScore(e) + 5000,
            originalIndex: i
          };
          criticalSignatureGroups.set(faultSigKey, anomalyEntry);
          scoredAnomalies.push(anomalyEntry);
        } else {
          const compactEvent = {
            id: eventIdVal,
            ts: tsVal,
            layer,
            target,
            metric,
            val: numericVal,
            errorCode: e.errorCode || e.code || undefined,
            zScore: Number(zScore.toFixed(2)),
            cusum: Number(Number(e.cusumShift || 0).toFixed(2)),
            isPatientZero,
            critical: false
          };
          scoredAnomalies.push({
            compactEvent,
            isCritical: false,
            isUniqueCriticalRepresentative: false,
            priorityScore: computeEventPriorityScore(e),
            originalIndex: i
          });
        }
      }
    }
  }
  scoredAnomalies.sort((a, b) => {
    if (b.priorityScore !== a.priorityScore) return b.priorityScore - a.priorityScore;
    return b.originalIndex - a.originalIndex;
  });

  // Stage 3: Synchronous probe compaction with strict status taxonomy
  const compactedProbes = [];
  for (let i = 0; i < safeProbes.length; i++) {
    const p = safeProbes[i];
    if (p && typeof p === 'object') {
      rawUtf8Bytes += Buffer.byteLength(safeJsonStringify(p), 'utf8');
      if (compactedProbes.length < 15) {
        compactedProbes.push(compactProbeRecordStrict(p));
      }
    } else if (p !== undefined && p !== null) {
      if (compactedProbes.length < 15) {
        compactedProbes.push(compactProbeRecordStrict(p));
      }
    }
  }

  // Stage 4: Synchronous budget selection
  const baseEnvelope = {
    schemaVersion: 'ejii-context-window-v2-sliced',
    retainedHypotheses,
    retainedAnomalies: [],
    compactedProbes
  };
  let currentBytes = Buffer.byteLength(safeJsonStringify(baseEnvelope), 'utf8') + 96;
  const selectedAnomalies = [];
  const maxAnomaliesCap = Math.max(10, Number(options.maxRetainedAnomalies) || 32);
  let inContextCriticalCount = 0;
  let retainedUniqueCriticalCount = 0;

  for (let i = 0; i < scoredAnomalies.length; i++) {
    const entry = scoredAnomalies[i];
    const candidate = entry.compactEvent;
    const candidateBytes = Buffer.byteLength(safeJsonStringify(candidate), 'utf8') + 2;
    if (entry.isUniqueCriticalRepresentative) {
      const projectedOverflowBytes = Math.max(0, currentBytes + candidateBytes - maxBytesBudget);
      if (inContextCriticalCount < maxInContextCriticalEvents && (inContextCriticalCount === 0 || projectedOverflowBytes <= maxCriticalOverflowBytes)) {
        selectedAnomalies.push(candidate);
        currentBytes += candidateBytes;
        inContextCriticalCount += 1;
      }
      retainedUniqueCriticalCount += 1;
    } else {
      if (selectedAnomalies.length >= maxAnomaliesCap) continue;
      if (currentBytes + candidateBytes > maxBytesBudget && selectedAnomalies.length > 0) continue;
      selectedAnomalies.push(candidate);
      currentBytes += candidateBytes;
    }
  }

  const finalPayload = {
    schemaVersion: 'ejii-context-window-v2-sliced',
    summary: {
      rawEventCount: safeEvents.length,
      retainedAnomalyCount: selectedAnomalies.length,
      retainedHypothesisCount: retainedHypotheses.length,
      retainedProbeCount: compactedProbes.length,
      uniqueCriticalSignaturesCount: criticalSignatureGroups.size,
      retainedUniqueCriticalCount,
      criticalEvidenceDroppedCount: Math.max(0, criticalSignatureGroups.size - retainedUniqueCriticalCount)
    },
    retainedHypotheses,
    retainedAnomalies: selectedAnomalies,
    compactedProbes
  };
  const block = `<ejii_telemetry_context_window>\n${safeJsonStringify(finalPayload)}\n</ejii_telemetry_context_window>`;
  const durationMs = Number((performance.now() - t0).toFixed(3));
  return {
    durationMs,
    rawUtf8Bytes,
    compiledUtf8Bytes: Buffer.byteLength(block, 'utf8'),
    retainedAnomalyCount: selectedAnomalies.length,
    retainedUniqueCriticalCount
  };
}

/**
 * Runs a reproducible benchmark comparing synchronous blocking vs. non-blocking time-sliced
 * context compilation on the exact same high-volume telemetry burst (Cycle 9), measuring
 * event-loop delay, latency, memory delta, critical-evidence retention, and throughput.
 */
async function benchmarkContextCompilation(eventsOrCount = 1200, options = {}) {
  const events = Array.isArray(eventsOrCount)
    ? eventsOrCount
    : Array.from({ length: Math.max(10, Number(eventsOrCount) || 1200) }, (_, idx) => ({
        timestamp: new Date(Date.now() - idx * 250).toISOString(),
        layer: idx % 5 === 0 ? 'L4_TCP' : 'L3_NETWORK',
        target: `10.42.${idx % 8}.${(idx % 250) + 1}`,
        metric: 'rttMs',
        value: idx % 20 === 0 ? 185 + (idx % 40) : 11 + (idx % 4),
        madZScore: idx % 20 === 0 ? 4.8 : 0.25,
        cusumShift: idx % 20 === 0 ? 3.2 : 0.1,
        isPatientZero: idx === 40
      }));

  const hypotheses = [
    { domain: 'L4_TRANSPORT', probabilityPct: 68.5, status: 'DOMINANT_CANDIDATE' },
    { domain: 'L3_NETWORK_PATH', probabilityPct: 24.0, status: 'PLAUSIBLE_CANDIDATE' },
    { domain: 'L7_APPLICATION', probabilityPct: 7.5, status: 'LOW_PROBABILITY' }
  ];

  const probes = [
    { probeType: 'TCP', target: '10.42.0.41:443', status: 'OK', latencyMs: 192.4 },
    { probeType: 'ICMP', target: '10.42.0.41', status: 'DEGRADED', latencyMs: 184.1 }
  ];

  // 1. Run synchronous blocking baseline on the same dataset
  const syncBaseline = compileTelemetryContextWindowSynchronousBaseline(events, hypotheses, probes, options);

  // 2. Run non-blocking time-sliced compilation with live event-loop drift monitoring
  const memBefore = process.memoryUsage().heapUsed;
  let timerChecks = 0;
  let maxTimerDriftMs = 0;
  let expectedNextTick = performance.now() + 2;

  const monitor = setInterval(() => {
    const now = performance.now();
    const drift = Math.max(0, now - expectedNextTick);
    if (drift > maxTimerDriftMs) maxTimerDriftMs = drift;
    timerChecks += 1;
    expectedNextTick = now + 2;
  }, 2);

  const t0 = performance.now();
  const compiled = await compileTelemetryContextWindowNonBlocking(events, hypotheses, probes, {
    maxTokens: options.maxTokens || 1024,
    maxSliceBudgetMs: options.maxSliceBudgetMs || 1.0
  });
  const wallClockMs = Math.max(0.1, performance.now() - t0);
  clearInterval(monitor);

  const memAfter = process.memoryUsage().heapUsed;
  const eventsPerSec = Math.round((events.length / wallClockMs) * 1000);

  return {
    eventCount: events.length,
    wallClockMs: Number(wallClockMs.toFixed(3)),
    synchronousBlockingDurationMs: syncBaseline.durationMs,
    nonBlockingMaxSliceDurationMs: compiled.nonBlockingExecution.maxSliceDurationMs,
    eventsPerSecond: eventsPerSec,
    yieldCount: compiled.nonBlockingExecution.yieldCount,
    maxSliceDurationMs: compiled.nonBlockingExecution.maxSliceDurationMs,
    maxEventLoopDriftMs: Number(maxTimerDriftMs.toFixed(3)),
    timerChecksObserved: timerChecks,
    heapDeltaBytes: Math.max(0, memAfter - memBefore),
    compressionRatioPct: compiled.compressionRatioPct,
    retainedAnomalyCount: compiled.retainedAnomalyCount,
    criticalEvidenceDroppedCount: compiled.criticalEvidenceDroppedCount,
    withinTokenBudget: compiled.withinTokenBudget,
    comparison: {
      sameInputDataset: true,
      datasetSize: events.length,
      synchronousSingleBlockMs: syncBaseline.durationMs,
      timeSlicedMaxBlockMs: compiled.nonBlockingExecution.maxSliceDurationMs,
      criticalEvidencePreserved: compiled.criticalEvidenceDroppedCount === 0
    }
  };
}

module.exports = {
  compileTelemetryContextWindowNonBlocking,
  compileTelemetryContextWindowSynchronousBaseline,
  benchmarkContextCompilation,
  recordSpilledCriticalEvidenceBatch,
  retrieveSpilledCriticalEvidence,
  pruneExpiredSpilledCriticalEvidence,
  deepCloneEvidenceRecord,
  clearInMemorySpillCacheForTesting,
  CRITICAL_EVIDENCE_SPILL_STORE,
  compactProbeRecordStrict,
  isCriticalEvidenceEvent,
  safeJsonStringify
};
