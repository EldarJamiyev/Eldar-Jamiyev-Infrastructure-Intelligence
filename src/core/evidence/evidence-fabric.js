/**
 * EJII v6 — Sovereign Intelligence Fabric
 * Part IV: Innovation One — The EJII Evidence Fabric
 *
 * First-class Evidence Graph and Provenance Ledger where every observation,
 * derived metric, anomaly, hypothesis, simulation output, policy recommendation,
 * and remediation verification is represented as a typed, provenance-stamped,
 * freshness-classified, cryptographically chained EvidenceRecord.
 */

const crypto = require('crypto');
const { db } = require('../../db/database');

const EVIDENCE_CLASSES = Object.freeze([
  'observation',
  'calculation',
  'hypothesis',
  'confirmed_finding',
  'counter_evidence',
  'missing_evidence',
  'stale_evidence',
  'simulated_result',
  'human_annotation',
  'action_result',
  'verification_result'
]);

const FRESHNESS_STATES = Object.freeze([
  'live',
  'fresh',
  'aging',
  'stale',
  'expired',
  'historical_snapshot'
]);

const COLLECTION_FIDELITY_WEIGHTS = Object.freeze({
  icmp_echo: 0.96,
  tcp_connect: 0.96,
  rfc1035_udp_dns: 0.97,
  tls_handshake: 0.98,
  pcap_dissection: 0.99,
  os_route_table: 0.95,
  arp_table: 0.94,
  procfs: 0.97,
  wmi: 0.92,
  Operator_Verify: 0.95,
  operator_feedback: 0.90,
  derived_formula: 0.88,
  bayesian_inference: 0.84,
  simulation_mm1k: 0.72,
  unavailable_probe: 0.25
});

function ensureEvidenceTables() {
  try {
    db.exec(`
      CREATE TABLE IF NOT EXISTS evidence_records (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        subject TEXT NOT NULL,
        claim TEXT NOT NULL,
        raw_value_json TEXT,
        normalized_value_json TEXT,
        unit TEXT,
        source_capability_id TEXT NOT NULL,
        collection_method TEXT NOT NULL,
        observed_at TEXT NOT NULL,
        ingested_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        freshness_state TEXT NOT NULL,
        quality_score REAL NOT NULL,
        corroborates_json TEXT NOT NULL DEFAULT '[]',
        contradicts_json TEXT NOT NULL DEFAULT '[]',
        derived_from_json TEXT NOT NULL DEFAULT '[]',
        prev_hash TEXT NOT NULL,
        integrity_hash TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_evidence_records_subject ON evidence_records(subject);
      CREATE INDEX IF NOT EXISTS idx_evidence_records_type ON evidence_records(type);
      CREATE INDEX IF NOT EXISTS idx_evidence_records_observed ON evidence_records(observed_at);

      CREATE TABLE IF NOT EXISTS evidence_findings (
        finding_id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        subject TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        inference_step TEXT NOT NULL,
        status TEXT NOT NULL,
        confidence REAL NOT NULL,
        supporting_evidence_json TEXT NOT NULL DEFAULT '[]',
        counter_evidence_json TEXT NOT NULL DEFAULT '[]',
        missing_evidence_json TEXT NOT NULL DEFAULT '[]',
        assumptions_json TEXT NOT NULL DEFAULT '[]',
        disconfirming_conditions_json TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        integrity_hash TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_evidence_findings_subject ON evidence_findings(subject);
    `);
  } catch (_) {}
}

ensureEvidenceTables();

/**
 * Compute freshness state from observation timestamp and TTL.
 * @param {string|number} observedAt
 * @param {string|number} [expiresAt]
 * @param {Object} [opts]
 * @returns {'live'|'fresh'|'aging'|'stale'|'expired'|'historical_snapshot'}
 */
function classifyFreshness(observedAt, expiresAt, opts = {}) {
  if (opts.isHistoricalSnapshot) return 'historical_snapshot';
  const nowMs = opts.nowMs || Date.now();
  const obsMs = typeof observedAt === 'number' ? observedAt : Date.parse(observedAt);
  if (!Number.isFinite(obsMs)) return 'stale';

  const ageMs = Math.max(0, nowMs - obsMs);
  const expMs = expiresAt ? (typeof expiresAt === 'number' ? expiresAt : Date.parse(expiresAt)) : obsMs + 300000;
  const ttlMs = Math.max(1000, expMs - obsMs);

  if (nowMs > expMs) return 'expired';
  const ratio = ageMs / ttlMs;
  if (ageMs <= 5000 || ratio <= 0.10) return 'live';
  if (ratio <= 0.45) return 'fresh';
  if (ratio <= 0.80) return 'aging';
  return 'stale';
}

/**
 * Deterministic quality score in [0, 1] computed from source fidelity,
 * freshness state, corroboration count, contradiction penalty, and completeness.
 */
function computeDeterministicQualityScore({
  type = 'observation',
  collectionMethod = 'icmp_echo',
  freshnessState = 'live',
  corroborates = [],
  contradicts = [],
  hasRawValue = true,
  hasNormalizedValue = true
}) {
  if (type === 'missing_evidence') return 0;

  const baseFidelity = COLLECTION_FIDELITY_WEIGHTS[collectionMethod] ||
    (type === 'simulated_result' ? 0.70 : type === 'hypothesis' ? 0.65 : 0.85);

  const freshnessMultipliers = {
    live: 1.0,
    fresh: 0.95,
    aging: 0.80,
    stale: 0.50,
    expired: 0.20,
    historical_snapshot: 0.85
  };
  const freshnessFactor = freshnessMultipliers[freshnessState] ?? 0.60;

  const completenessFactor = (hasRawValue && hasNormalizedValue) ? 1.0 : (hasRawValue || hasNormalizedValue ? 0.90 : 0.75);
  const corroborationBonus = Math.min(0.12, (Array.isArray(corroborates) ? corroborates.length : 0) * 0.04);
  const contradictionPenalty = Math.min(0.35, (Array.isArray(contradicts) ? contradicts.length : 0) * 0.12);

  const rawScore = (baseFidelity * freshnessFactor * completenessFactor) + corroborationBonus - contradictionPenalty;
  return Number(Math.max(0, Math.min(1, rawScore)).toFixed(4));
}

class EvidenceFabric {
  constructor(hmacSecret = 'EJII-V6-SOVEREIGN-EVIDENCE-FABRIC-KEY') {
    this.hmacSecret = hmacSecret;
    this.memoryRecords = new Map();
    this.memoryFindings = new Map();
    this.lastChainHash = 'GENESIS_EVIDENCE_CHAIN_V6_0000000000000000';
    ensureEvidenceTables();
    this._hydrateChainTail();
  }

  _hydrateChainTail() {
    try {
      const row = db.prepare('SELECT integrity_hash FROM evidence_records ORDER BY ingested_at DESC, rowid DESC LIMIT 1').get();
      if (row && row.integrity_hash) {
        this.lastChainHash = row.integrity_hash;
      }
    } catch (_) {}
  }

  _computeHash(payloadStr, prevHash) {
    return crypto
      .createHmac('sha256', this.hmacSecret)
      .update(`${prevHash}|${payloadStr}`)
      .digest('hex');
  }

  /**
   * Record a typed EvidenceRecord in the Evidence Fabric and SQLite ledger.
   * @param {Object} input
   * @returns {Object} EvidenceRecord
   */
  recordEvidence(input = {}) {
    ensureEvidenceTables();
    const id = input.id || `EVD-${Date.now()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const type = EVIDENCE_CLASSES.includes(input.type) ? input.type : 'observation';
    const subject = String(input.subject || 'host:local');
    const claim = String(input.claim || 'Infrastructure telemetry record');
    const rawValue = input.rawValue !== undefined ? input.rawValue : null;
    const normalizedValue = input.normalizedValue !== undefined ? input.normalizedValue : rawValue;
    const unit = input.unit !== undefined ? String(input.unit) : null;
    const sourceCapabilityId = String(input.sourceCapabilityId || 'ejii.core.telemetry');
    const collectionMethod = String(input.collectionMethod || 'direct_probe');

    const nowMs = Date.now();
    const observedAt = input.observedAt ? new Date(input.observedAt).toISOString() : new Date(nowMs).toISOString();
    const ingestedAt = input.ingestedAt ? new Date(input.ingestedAt).toISOString() : new Date(nowMs).toISOString();
    const ttlMs = typeof input.ttlMs === 'number' && input.ttlMs > 0 ? input.ttlMs : 300000;
    const expiresAt = input.expiresAt
      ? new Date(input.expiresAt).toISOString()
      : new Date(Date.parse(observedAt) + ttlMs).toISOString();

    const corroborates = Array.isArray(input.corroborates) ? Array.from(new Set(input.corroborates.map(String))) : [];
    const contradicts = Array.isArray(input.contradicts) ? Array.from(new Set(input.contradicts.map(String))) : [];
    const derivedFrom = Array.isArray(input.derivedFrom) ? Array.from(new Set(input.derivedFrom.map(String))) : [];

    // Prevent cycles in derivedFrom lineage
    const safeDerivedFrom = derivedFrom.filter((parentId) => parentId !== id && !this._createsCycle(id, parentId));

    const freshnessState = input.freshnessState && FRESHNESS_STATES.includes(input.freshnessState)
      ? input.freshnessState
      : classifyFreshness(observedAt, expiresAt, { isHistoricalSnapshot: Boolean(input.isHistoricalSnapshot) });

    const qualityScore = typeof input.qualityScore === 'number'
      ? Number(Math.max(0, Math.min(1, input.qualityScore)).toFixed(4))
      : computeDeterministicQualityScore({
          type,
          collectionMethod,
          freshnessState,
          corroborates,
          contradicts,
          hasRawValue: rawValue !== null && rawValue !== undefined,
          hasNormalizedValue: normalizedValue !== null && normalizedValue !== undefined
        });

    const prevHash = this.lastChainHash;
    const canonicalPayload = JSON.stringify({
      id,
      type,
      subject,
      claim,
      rawValue,
      normalizedValue,
      unit,
      sourceCapabilityId,
      collectionMethod,
      observedAt,
      expiresAt,
      corroborates,
      contradicts,
      derivedFrom: safeDerivedFrom
    });
    const integrityHash = this._computeHash(canonicalPayload, prevHash);
    this.lastChainHash = integrityHash;

    const record = {
      id,
      type,
      subject,
      claim,
      rawValue,
      normalizedValue,
      unit,
      sourceCapabilityId,
      collectionMethod,
      observedAt,
      ingestedAt,
      expiresAt,
      freshnessState,
      qualityScore,
      corroborates,
      contradicts,
      derivedFrom: safeDerivedFrom,
      prevHash,
      integrityHash
    };

    this.memoryRecords.set(id, record);

    try {
      db.prepare(`
        INSERT OR REPLACE INTO evidence_records (
          id, type, subject, claim, raw_value_json, normalized_value_json, unit,
          source_capability_id, collection_method, observed_at, ingested_at, expires_at,
          freshness_state, quality_score, corroborates_json, contradicts_json, derived_from_json,
          prev_hash, integrity_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        record.id,
        record.type,
        record.subject,
        record.claim,
        JSON.stringify(record.rawValue),
        JSON.stringify(record.normalizedValue),
        record.unit,
        record.sourceCapabilityId,
        record.collectionMethod,
        record.observedAt,
        record.ingestedAt,
        record.expiresAt,
        record.freshnessState,
        record.qualityScore,
        JSON.stringify(record.corroborates),
        JSON.stringify(record.contradicts),
        JSON.stringify(record.derivedFrom),
        record.prevHash,
        record.integrityHash
      );
    } catch (_) {}

    return record;
  }

  _createsCycle(targetId, candidateParentId, visited = new Set()) {
    if (targetId === candidateParentId) return true;
    if (visited.has(candidateParentId)) return false;
    visited.add(candidateParentId);
    const parent = this.getEvidenceById(candidateParentId);
    if (!parent || !Array.isArray(parent.derivedFrom)) return false;
    for (const gpId of parent.derivedFrom) {
      if (this._createsCycle(targetId, gpId, visited)) return true;
    }
    return false;
  }

  /**
   * Retrieve an EvidenceRecord by ID and dynamically refresh its freshnessState & qualityScore.
   * @param {string} id
   * @param {Object} [opts]
   * @returns {Object|null}
   */
  getEvidenceById(id, opts = {}) {
    let record = this.memoryRecords.get(id) || null;
    if (!record) {
      try {
        const row = db.prepare('SELECT * FROM evidence_records WHERE id = ?').get(id);
        if (row) {
          record = this._deserializeRow(row);
          this.memoryRecords.set(id, record);
        }
      } catch (_) {}
    }
    if (!record) return null;

    if (opts.recomputeFreshness !== false && record.freshnessState !== 'historical_snapshot') {
      const currentFreshness = classifyFreshness(record.observedAt, record.expiresAt, opts);
      const currentQuality = computeDeterministicQualityScore({
        type: record.type,
        collectionMethod: record.collectionMethod,
        freshnessState: currentFreshness,
        corroborates: record.corroborates,
        contradicts: record.contradicts,
        hasRawValue: record.rawValue !== null,
        hasNormalizedValue: record.normalizedValue !== null
      });
      return {
        ...record,
        freshnessState: currentFreshness,
        qualityScore: currentQuality
      };
    }
    return { ...record };
  }

  _deserializeRow(row) {
    const safeParse = (str, fallback) => {
      try { return str ? JSON.parse(str) : fallback; } catch (_) { return fallback; }
    };
    return {
      id: row.id,
      type: row.type,
      subject: row.subject,
      claim: row.claim,
      rawValue: safeParse(row.raw_value_json, null),
      normalizedValue: safeParse(row.normalized_value_json, null),
      unit: row.unit,
      sourceCapabilityId: row.source_capability_id,
      collectionMethod: row.collection_method,
      observedAt: row.observed_at,
      ingestedAt: row.ingested_at,
      expiresAt: row.expires_at,
      freshnessState: row.freshness_state,
      qualityScore: Number(row.quality_score),
      corroborates: safeParse(row.corroborates_json, []),
      contradicts: safeParse(row.contradicts_json, []),
      derivedFrom: safeParse(row.derived_from_json, []),
      prevHash: row.prev_hash,
      integrityHash: row.integrity_hash
    };
  }

  /**
   * Register a structured Finding / Conclusion linked to supporting, contradicting, and missing evidence.
   * Enforces the Epistemic Contract: a finding cannot be marked 'confirmed' if its only supporting
   * evidence is stale, expired, or purely simulated without live corroboration.
   */
  recordFinding(input = {}) {
    ensureEvidenceTables();
    const findingId = input.findingId || input.id || `FND-${Date.now()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const title = String(input.title || 'Infrastructure Diagnostic Finding');
    const subject = String(input.subject || 'host:local');
    const ruleId = String(input.ruleId || 'RULE-CAUSAL-01');
    const inferenceStep = String(input.inferenceStep || 'Cross-layer evidentiary deduction');
    const supportingEvidenceIds = Array.isArray(input.supportingEvidenceIds) ? input.supportingEvidenceIds.map(String) : [];
    const counterEvidenceIds = Array.isArray(input.counterEvidenceIds) ? input.counterEvidenceIds.map(String) : [];
    const missingEvidenceIds = Array.isArray(input.missingEvidenceIds) ? input.missingEvidenceIds.map(String) : [];
    const assumptions = Array.isArray(input.assumptions) ? input.assumptions.map(String) : [];
    const disconfirmingConditions = Array.isArray(input.disconfirmingConditions) ? input.disconfirmingConditions.map(String) : [];

    // Inspect supporting evidence to enforce freshness & non-simulation epistemic rules
    const supportingRecords = supportingEvidenceIds
      .map((eid) => this.getEvidenceById(eid))
      .filter(Boolean);

    const hasFreshLiveObservation = supportingRecords.some(
      (r) =>
        r.type !== 'simulated_result' &&
        r.type !== 'missing_evidence' &&
        (r.freshnessState === 'live' || r.freshnessState === 'fresh' || r.freshnessState === 'aging')
    );

    let status = input.status || 'proposed';
    const downgradeWarnings = [];

    if (status === 'confirmed' && !hasFreshLiveObservation) {
      status = supportingRecords.length > 0 ? 'supported' : 'unresolved';
      downgradeWarnings.push(
        'Finding downgraded from confirmed: no live/fresh observational evidence present (stale, expired, or simulated-only evidence cannot confirm a live root cause).'
      );
    }

    const avgQuality = supportingRecords.length > 0
      ? supportingRecords.reduce((acc, r) => acc + r.qualityScore, 0) / supportingRecords.length
      : 0.35;
    const counterPenalty = Math.min(0.45, counterEvidenceIds.length * 0.15);
    const missingPenalty = Math.min(0.30, missingEvidenceIds.length * 0.10);
    const calibratedConfidence = typeof input.confidence === 'number' && hasFreshLiveObservation
      ? Number(Math.max(0.05, Math.min(0.99, input.confidence)).toFixed(4))
      : Number(Math.max(0.05, Math.min(hasFreshLiveObservation ? 0.98 : 0.72, avgQuality - counterPenalty - missingPenalty)).toFixed(4));

    const nowIso = new Date().toISOString();
    const integrityHash = crypto
      .createHmac('sha256', this.hmacSecret)
      .update(JSON.stringify({ findingId, subject, ruleId, status, supportingEvidenceIds, counterEvidenceIds, missingEvidenceIds, calibratedConfidence }))
      .digest('hex');

    const finding = {
      findingId,
      title,
      subject,
      ruleId,
      inferenceStep,
      status,
      confidence: calibratedConfidence,
      supportingEvidenceIds,
      counterEvidenceIds,
      missingEvidenceIds,
      assumptions,
      disconfirmingConditions,
      downgradeWarnings,
      createdAt: nowIso,
      updatedAt: nowIso,
      integrityHash
    };

    this.memoryFindings.set(findingId, finding);

    try {
      db.prepare(`
        INSERT OR REPLACE INTO evidence_findings (
          finding_id, title, subject, rule_id, inference_step, status, confidence,
          supporting_evidence_json, counter_evidence_json, missing_evidence_json,
          assumptions_json, disconfirming_conditions_json, created_at, updated_at, integrity_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        finding.findingId,
        finding.title,
        finding.subject,
        finding.ruleId,
        finding.inferenceStep,
        finding.status,
        finding.confidence,
        JSON.stringify(finding.supportingEvidenceIds),
        JSON.stringify(finding.counterEvidenceIds),
        JSON.stringify(finding.missingEvidenceIds),
        JSON.stringify(finding.assumptions),
        JSON.stringify(finding.disconfirmingConditions),
        finding.createdAt,
        finding.updatedAt,
        finding.integrityHash
      );
    } catch (_) {}

    return finding;
  }

  /**
   * Trace the complete acyclic lineage graph for a Finding or EvidenceRecord:
   * Finding -> Rule / Inference Step -> Supporting Evidence -> Original Diagnostic Result -> Source Capability -> Observation Time
   * @param {string} id - findingId or evidenceId
   */
  traceLineage(id) {
    const finding = this.getFindingById(id);
    if (finding) {
      const visited = new Set();
      const buildEvidenceSubtree = (evId) => {
        if (visited.has(evId)) return { id: evId, cyclePrevented: true };
        visited.add(evId);
        const ev = this.getEvidenceById(evId);
        if (!ev) return { id: evId, status: 'missing_record' };
        return {
          evidenceId: ev.id,
          type: ev.type,
          subject: ev.subject,
          claim: ev.claim,
          value: ev.normalizedValue,
          unit: ev.unit,
          sourceCapabilityId: ev.sourceCapabilityId,
          collectionMethod: ev.collectionMethod,
          observedAt: ev.observedAt,
          freshnessState: ev.freshnessState,
          qualityScore: ev.qualityScore,
          integrityHash: ev.integrityHash,
          parentEvidence: (ev.derivedFrom || []).map((pid) => buildEvidenceSubtree(pid))
        };
      };

      return {
        lineageType: 'FINDING_PROVENANCE_CHAIN',
        findingId: finding.findingId,
        title: finding.title,
        subject: finding.subject,
        status: finding.status,
        confidence: finding.confidence,
        rule: {
          ruleId: finding.ruleId,
          inferenceStep: finding.inferenceStep
        },
        supportingLineage: finding.supportingEvidenceIds.map((eid) => buildEvidenceSubtree(eid)),
        counterLineage: finding.counterEvidenceIds.map((eid) => buildEvidenceSubtree(eid)),
        missingEvidence: finding.missingEvidenceIds.map((eid) => buildEvidenceSubtree(eid)),
        assumptions: finding.assumptions,
        disconfirmingConditions: finding.disconfirmingConditions,
        downgradeWarnings: finding.downgradeWarnings || [],
        integrityHash: finding.integrityHash,
        isAcyclic: true
      };
    }

    // Trace direct EvidenceRecord ancestry
    const rootEv = this.getEvidenceById(id);
    if (!rootEv) return null;

    const visited = new Set();
    const walk = (ev) => {
      visited.add(ev.id);
      return {
        evidenceId: ev.id,
        type: ev.type,
        subject: ev.subject,
        claim: ev.claim,
        value: ev.normalizedValue,
        unit: ev.unit,
        sourceCapabilityId: ev.sourceCapabilityId,
        collectionMethod: ev.collectionMethod,
        observedAt: ev.observedAt,
        freshnessState: ev.freshnessState,
        qualityScore: ev.qualityScore,
        integrityHash: ev.integrityHash,
        parentEvidence: (ev.derivedFrom || [])
          .filter((pid) => !visited.has(pid))
          .map((pid) => {
            const parent = this.getEvidenceById(pid);
            return parent ? walk(parent) : { evidenceId: pid, status: 'missing_record' };
          })
      };
    };

    return {
      lineageType: 'EVIDENCE_PROVENANCE_CHAIN',
      root: walk(rootEv),
      isAcyclic: true
    };
  }

  getFindingById(findingId) {
    if (this.memoryFindings.has(findingId)) {
      return this.memoryFindings.get(findingId);
    }
    try {
      const row = db.prepare('SELECT * FROM evidence_findings WHERE finding_id = ?').get(findingId);
      if (row) {
        const safeParse = (s) => { try { return JSON.parse(s || '[]'); } catch (_) { return []; } };
        const f = {
          findingId: row.finding_id,
          title: row.title,
          subject: row.subject,
          ruleId: row.rule_id,
          inferenceStep: row.inference_step,
          status: row.status,
          confidence: Number(row.confidence),
          supportingEvidenceIds: safeParse(row.supporting_evidence_json),
          counterEvidenceIds: safeParse(row.counter_evidence_json),
          missingEvidenceIds: safeParse(row.missing_evidence_json),
          assumptions: safeParse(row.assumptions_json),
          disconfirmingConditions: safeParse(row.disconfirming_conditions_json),
          downgradeWarnings: [],
          createdAt: row.created_at,
          updatedAt: row.updated_at,
          integrityHash: row.integrity_hash
        };
        this.memoryFindings.set(findingId, f);
        return f;
      }
    } catch (_) {}
    return null;
  }

  queryEvidence(filters = {}) {
    ensureEvidenceTables();
    const limit = Math.min(200, Math.max(1, Number(filters.limit) || 50));
    let rows = [];
    try {
      if (filters.subject && filters.type) {
        rows = db.prepare('SELECT * FROM evidence_records WHERE subject = ? AND type = ? ORDER BY observed_at DESC LIMIT ?')
          .all(filters.subject, filters.type, limit);
      } else if (filters.subject) {
        rows = db.prepare('SELECT * FROM evidence_records WHERE subject = ? ORDER BY observed_at DESC LIMIT ?')
          .all(filters.subject, limit);
      } else if (filters.type) {
        rows = db.prepare('SELECT * FROM evidence_records WHERE type = ? ORDER BY observed_at DESC LIMIT ?')
          .all(filters.type, limit);
      } else {
        rows = db.prepare('SELECT * FROM evidence_records ORDER BY observed_at DESC LIMIT ?')
          .all(limit);
      }
    } catch (_) {}

    const records = rows.map((r) => this.getEvidenceById(r.id) || this._deserializeRow(r));
    if (filters.freshnessState) {
      return records.filter((r) => r.freshnessState === filters.freshnessState);
    }
    return records;
  }

  listFindings(limit = 50) {
    ensureEvidenceTables();
    try {
      const rows = db.prepare('SELECT finding_id FROM evidence_findings ORDER BY updated_at DESC LIMIT ?').all(limit);
      return rows.map((r) => this.getFindingById(r.finding_id)).filter(Boolean);
    } catch (_) {
      return Array.from(this.memoryFindings.values()).slice(-limit).reverse();
    }
  }
}

const evidenceFabric = new EvidenceFabric();

module.exports = {
  EVIDENCE_CLASSES,
  FRESHNESS_STATES,
  classifyFreshness,
  computeDeterministicQualityScore,
  EvidenceFabric,
  evidenceFabric
};
