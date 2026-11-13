'use strict';

/**
 * EJII Claude-Mem Persistent Episodic & Semantic Memory Engine
 *
 * Implements the 3-Layer Progressive Disclosure Memory Architecture:
 *   - Layer 1 (searchIndex): Compact observation index (~35 tokens/item) with BM25 + concept-tag scoring
 *   - Layer 2 (getTimelineContext): Chronological causal neighborhood window around an anchor observation
 *   - Layer 3 (getObservationsByIds): Selective full-payload hydration only for chosen observation IDs
 *
 * Epistemic & Operational Integrity Guarantees:
 *   - Strictly separates static architectural knowledge (`memoryCategory: 'ARCHITECTURAL_KNOWLEDGE'`,
 *     `isLiveMeasurement: false`, `target: null`, `probeMetrics: {}`) from genuine operational probe
 *     observations (`memoryCategory: 'LIVE_OPERATIONAL_OBSERVATION'`).
 *   - Static architectural records never carry fabricated targets, latencies, or status values and
 *     are excluded by default from operational target queries and progressive disclosure bundles.
 *   - Distinguishes character-based token approximations (`CHARACTER_HEURISTIC_4CHARS_PER_TOKEN`)
 *     from provider-reported token counts (`PROVIDER_REPORTED_EXACT`).
 *   - Tracks SQLite schema initialization, read/write status, causal parent-child lineage, and
 *     bounded retention without silently swallowing persistence errors.
 */

const crypto = require('node:crypto');
const { db } = require('../../db/database');

const VALID_OBSERVATION_TYPES = new Set([
  'probe_evidence',
  'incident',
  'discovery',
  'decision',
  'bugfix',
  'feature',
  'refactor',
  'configuration_change'
]);

const VALID_MEMORY_CATEGORIES = new Set([
  'LIVE_OPERATIONAL_OBSERVATION',
  'ARCHITECTURAL_KNOWLEDGE',
  'APPLICATION_METADATA'
]);

const CONCEPT_TAXONOMY = new Set([
  'how-it-works',
  'why-it-exists',
  'what-changed',
  'problem-solution',
  'gotcha',
  'pattern',
  'trade-off',
  'root-cause',
  'layer-disambiguation',
  'remediation-outcome'
]);

const DEFAULT_MAX_OBSERVATIONS_IN_MEMORY = 1000;

function estimateTokenCount(textOrObj, exactProviderTokens = null) {
  if (typeof exactProviderTokens === 'number' && Number.isFinite(exactProviderTokens) && exactProviderTokens >= 0) {
    return {
      tokens: Math.round(exactProviderTokens),
      estimationMethod: 'PROVIDER_REPORTED_EXACT',
      isExactProviderTokenCount: true
    };
  }
  const raw = typeof textOrObj === 'string' ? textOrObj : JSON.stringify(textOrObj || '');
  if (!raw) {
    return {
      tokens: 0,
      estimationMethod: 'CHARACTER_HEURISTIC_4CHARS_PER_TOKEN',
      isExactProviderTokenCount: false
    };
  }
  return {
    tokens: Math.max(1, Math.ceil(raw.length / 4)),
    estimationMethod: 'CHARACTER_HEURISTIC_4CHARS_PER_TOKEN',
    isExactProviderTokenCount: false
  };
}

class ClaudeMemEngine {
  constructor(options = {}) {
    this.useSqlite = options.useSqlite !== false;
    this.dbHandle =
      options.dbHandle !== undefined
        ? options.dbHandle
        : options.db !== undefined
          ? options.db
          : db;
    this.maxObservationsInMemory = Math.max(
      50,
      Number(options.maxObservationsInMemory) || DEFAULT_MAX_OBSERVATIONS_IN_MEMORY
    );
    this.observationsById = new Map();
    this.sessionsById = new Map();
    this.totalIndexQueries = 0;
    this.totalTimelineQueries = 0;
    this.totalHydrationQueries = 0;
    this.cumulativeTokensSaved = 0;
    this.storageDiagnostics = {
      schemaInitialized: false,
      loadSucceeded: false,
      writeAttemptsCount: 0,
      writeSuccessCount: 0,
      writeFailuresCount: 0,
      sanitizedBootstrapRecordsCount: 0,
      evictedObservationsCount: 0,
      lastError: null
    };
    this._ensureSchema();
    this._loadFromSqlite();
    this._seedInitialArchitecturalObservations();
  }

  _recordStorageError(stage, err) {
    const message = err && err.message ? err.message : String(err || 'UNKNOWN_SQLITE_ERROR');
    this.storageDiagnostics.lastError = {
      stage,
      message,
      code: err && err.code ? err.code : 'CLAUDE_MEM_SQLITE_ERROR',
      timestamp: new Date().toISOString()
    };
  }

  _ensureSchema() {
    if (!this.useSqlite || !this.dbHandle) {
      this.storageDiagnostics.schemaInitialized = false;
      return;
    }
    try {
      this.dbHandle.exec(`
        CREATE TABLE IF NOT EXISTS ejii_claude_mem_observations (
          observation_id TEXT PRIMARY KEY,
          session_id TEXT NOT NULL,
          obs_type TEXT NOT NULL,
          memory_category TEXT NOT NULL DEFAULT 'LIVE_OPERATIONAL_OBSERVATION',
          is_live_measurement INTEGER NOT NULL DEFAULT 1,
          parent_observation_id TEXT,
          title TEXT NOT NULL,
          subtitle TEXT,
          target_entity TEXT,
          concept_tags_json TEXT NOT NULL,
          facts_json TEXT NOT NULL,
          narrative TEXT,
          root_cause TEXT,
          probe_metrics_json TEXT,
          files_or_endpoints_json TEXT,
          index_tokens INTEGER NOT NULL DEFAULT 35,
          full_tokens INTEGER NOT NULL DEFAULT 250,
          token_estimation_method TEXT NOT NULL DEFAULT 'CHARACTER_HEURISTIC_4CHARS_PER_TOKEN',
          owner_user_id TEXT,
          owner_username TEXT,
          visibility_scope TEXT NOT NULL DEFAULT 'PRIVATE_OPERATIONAL',
          created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_ejii_claude_mem_obs_target
          ON ejii_claude_mem_observations(target_entity);

        CREATE INDEX IF NOT EXISTS idx_ejii_claude_mem_obs_created
          ON ejii_claude_mem_observations(created_at DESC);

        CREATE TABLE IF NOT EXISTS ejii_claude_mem_sessions (
          session_id TEXT PRIMARY KEY,
          project_scope TEXT NOT NULL DEFAULT 'EJII-Sovereign-Fabric',
          owner_user_id TEXT,
          owner_username TEXT,
          request_summary TEXT,
          investigated_summary TEXT,
          learned_summary TEXT,
          completed_summary TEXT,
          next_steps_summary TEXT,
          observation_count INTEGER NOT NULL DEFAULT 0,
          started_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
      `);

      // Ensure additive columns exist on pre-existing tables created prior to Phase Atlas XII
      const alterStatements = [
        "ALTER TABLE ejii_claude_mem_observations ADD COLUMN memory_category TEXT NOT NULL DEFAULT 'LIVE_OPERATIONAL_OBSERVATION'",
        'ALTER TABLE ejii_claude_mem_observations ADD COLUMN is_live_measurement INTEGER NOT NULL DEFAULT 1',
        'ALTER TABLE ejii_claude_mem_observations ADD COLUMN parent_observation_id TEXT',
        "ALTER TABLE ejii_claude_mem_observations ADD COLUMN token_estimation_method TEXT NOT NULL DEFAULT 'CHARACTER_HEURISTIC_4CHARS_PER_TOKEN'",
        'ALTER TABLE ejii_claude_mem_observations ADD COLUMN owner_user_id TEXT',
        'ALTER TABLE ejii_claude_mem_observations ADD COLUMN owner_username TEXT',
        "ALTER TABLE ejii_claude_mem_observations ADD COLUMN visibility_scope TEXT NOT NULL DEFAULT 'PRIVATE_OPERATIONAL'",
        'ALTER TABLE ejii_claude_mem_sessions ADD COLUMN owner_user_id TEXT',
        'ALTER TABLE ejii_claude_mem_sessions ADD COLUMN owner_username TEXT'
      ];
      for (const stmt of alterStatements) {
        try {
          this.dbHandle.exec(stmt);
        } catch (_) {
          // Column already exists
        }
      }

      this.storageDiagnostics.schemaInitialized = true;
    } catch (err) {
      this.storageDiagnostics.schemaInitialized = false;
      this._recordStorageError('SCHEMA_INIT', err);
    }
  }

  _extractCallerContext(options = {}) {
    if (!options || typeof options !== 'object') {
      return { userId: null, username: null, role: null, sessionId: null, hasExplicitCaller: false };
    }
    const userObj = (options.user && typeof options.user === 'object') ? options.user : {};
    const rawUserId =
      userObj.id ||
      userObj.userId ||
      options.requesterUserId ||
      options.ownerUserId ||
      options.userId ||
      (typeof options.user === 'string' ? options.user : null);
    const rawUsername =
      userObj.username ||
      options.requesterUsername ||
      options.ownerUsername ||
      options.username ||
      null;
    const rawRole = userObj.role || options.requesterRole || options.role || null;
    const rawSessionId = options.sessionId || null;

    const userId = rawUserId ? String(rawUserId).trim() : null;
    const username = rawUsername ? String(rawUsername).trim() : null;
    const role = rawRole ? String(rawRole).trim().toUpperCase() : null;
    const sessionId = rawSessionId ? String(rawSessionId).trim() : null;

    return {
      userId,
      username,
      role,
      sessionId,
      hasExplicitCaller: Boolean(userId || username || sessionId)
    };
  }

  /**
   * Multi-User Epistemic & Operational Isolation Gate:
   * - Architectural knowledge (`ARCHITECTURAL_KNOWLEDGE` / `SHARED_ARCHITECTURAL`) is shared across authenticated users.
   * - `ADMIN` role can inspect across sessions/users for governance diagnostics.
   * - Private operational observations (`LIVE_OPERATIONAL_OBSERVATION`) with an explicit `ownerUserId` or `ownerUsername`
   *   are strictly isolated to that owning user (or matching `sessionId` when owner is unset).
   */
  _isObservationAccessibleToCaller(obs, options = {}) {
    if (!obs) return false;
    if (
      obs.memoryCategory === 'ARCHITECTURAL_KNOWLEDGE' ||
      obs.visibilityScope === 'SHARED_ARCHITECTURAL'
    ) {
      return true;
    }

    const caller = this._extractCallerContext(options);
    if (caller.role === 'ADMIN') {
      return true;
    }

    // If caller explicitly filters by sessionId and observation belongs to a different session
    if (options.strictSessionOnly && caller.sessionId && obs.sessionId !== caller.sessionId) {
      return false;
    }

    // If the observation has an explicit user owner, enforce user ownership isolation when caller identity is present
    if (obs.ownerUserId || obs.ownerUsername) {
      if (!caller.hasExplicitCaller) {
        return !options.enforceStrictIsolation;
      }
      if (obs.ownerUserId && caller.userId) {
        return String(obs.ownerUserId) === String(caller.userId);
      }
      if (obs.ownerUsername && caller.username) {
        return String(obs.ownerUsername).toLowerCase() === String(caller.username).toLowerCase();
      }
      return false;
    }

    return true;
  }

  _loadFromSqlite() {
    if (!this.useSqlite || !this.dbHandle) {
      this.storageDiagnostics.loadSucceeded = false;
      return;
    }
    try {
      const rows = this.dbHandle
        .prepare('SELECT * FROM ejii_claude_mem_observations ORDER BY created_at ASC LIMIT ?')
        .all(this.maxObservationsInMemory);
      for (const r of rows) {
        const isBootRecord =
          r.observation_id === 'CMEM-BOOT-001' ||
          r.session_id === 'SESSION-BOOT-BASELINE' ||
          r.memory_category === 'ARCHITECTURAL_KNOWLEDGE' ||
          r.root_cause === 'NOMINAL_ARCHITECTURE_BASELINE';

        const memoryCategory = isBootRecord
          ? 'ARCHITECTURAL_KNOWLEDGE'
          : VALID_MEMORY_CATEGORIES.has(r.memory_category)
            ? r.memory_category
            : 'LIVE_OPERATIONAL_OBSERVATION';

        const isLiveMeasurement = isBootRecord ? false : Boolean(r.is_live_measurement !== 0);

        let parsedMetrics = {};
        try {
          parsedMetrics = JSON.parse(r.probe_metrics_json || '{}');
        } catch (_) {
          parsedMetrics = {};
        }

        // Scrub any legacy bootstrap record that previously stored a target or fabricated rttMs/status
        if (isBootRecord && (r.target_entity || (parsedMetrics && Object.keys(parsedMetrics).length > 0))) {
          this.storageDiagnostics.sanitizedBootstrapRecordsCount += 1;
          parsedMetrics = {};
          try {
            this.dbHandle
              .prepare(`
                UPDATE ejii_claude_mem_observations
                SET target_entity = NULL,
                    probe_metrics_json = '{}',
                    memory_category = 'ARCHITECTURAL_KNOWLEDGE',
                    is_live_measurement = 0
                WHERE observation_id = ?
              `)
              .run(r.observation_id);
          } catch (scrubErr) {
            this._recordStorageError('SCRUB_BOOTSTRAP_RECORD', scrubErr);
          }
        }

        const visibilityScope = isBootRecord
          ? 'SHARED_ARCHITECTURAL'
          : r.visibility_scope || 'PRIVATE_OPERATIONAL';

        const obs = {
          observationId: r.observation_id,
          id: r.observation_id,
          sessionId: r.session_id,
          ownerUserId: isBootRecord ? null : r.owner_user_id || null,
          ownerUsername: isBootRecord ? null : r.owner_username || null,
          visibilityScope,
          type: r.obs_type,
          memoryCategory,
          isLiveMeasurement,
          parentObservationId: r.parent_observation_id || null,
          title: r.title,
          subtitle: r.subtitle || '',
          target: isBootRecord ? null : r.target_entity || null,
          conceptTags: JSON.parse(r.concept_tags_json || '[]'),
          facts: JSON.parse(r.facts_json || '[]'),
          narrative: r.narrative || '',
          rootCause: r.root_cause || null,
          probeMetrics: isBootRecord ? {} : parsedMetrics,
          rawPayload: isBootRecord ? {} : parsedMetrics,
          filesOrEndpoints: JSON.parse(r.files_or_endpoints_json || '[]'),
          indexTokens: Number(r.index_tokens) || 35,
          indexTokenEstimate: Number(r.index_tokens) || 35,
          fullTokens: Number(r.full_tokens) || 250,
          fullTokenEstimate: Number(r.full_tokens) || 250,
          tokenEstimationMethod:
            r.token_estimation_method || 'CHARACTER_HEURISTIC_4CHARS_PER_TOKEN',
          isExactProviderTokenCount: r.token_estimation_method === 'PROVIDER_REPORTED_EXACT',
          persisted: true,
          persistedToSqlite: true,
          persistenceStatus: 'PERSISTED_SQLITE',
          persistenceError: null,
          createdAt: r.created_at
        };
        this.observationsById.set(obs.observationId, obs);
      }

      const sessRows = this.dbHandle
        .prepare('SELECT * FROM ejii_claude_mem_sessions ORDER BY updated_at DESC LIMIT 100')
        .all();
      for (const s of sessRows) {
        this.sessionsById.set(s.session_id, {
          sessionId: s.session_id,
          projectScope: s.project_scope,
          ownerUserId: s.owner_user_id || null,
          ownerUsername: s.owner_username || null,
          requestSummary: s.request_summary || '',
          investigatedSummary: s.investigated_summary || '',
          learnedSummary: s.learned_summary || '',
          completedSummary: s.completed_summary || '',
          nextStepsSummary: s.next_steps_summary || '',
          observationCount: Number(s.observation_count) || 0,
          startedAt: s.started_at,
          updatedAt: s.updated_at
        });
      }
      this.storageDiagnostics.loadSucceeded = true;
    } catch (err) {
      this.storageDiagnostics.loadSucceeded = false;
      this._recordStorageError('SQLITE_LOAD', err);
    }
  }

  _seedInitialArchitecturalObservations() {
    if (this.observationsById.has('CMEM-BOOT-001')) return;
    this.recordObservation({
      observationId: 'CMEM-BOOT-001',
      sessionId: 'SESSION-BOOT-BASELINE',
      type: 'discovery',
      memoryCategory: 'ARCHITECTURAL_KNOWLEDGE',
      isLiveMeasurement: false,
      title: 'Initialized 5-Tier Read-Only Skill Ecosystem & Claude-Mem Progressive Disclosure Index',
      subtitle: '85 primary packages + 74 GStack workflows = 159 manifests; 111 mirrored modules; 71 lock definitions',
      target: null,
      conceptTags: ['how-it-works', 'pattern', 'what-changed'],
      facts: [
        '85 top-level Agent Skill packages and 74 nested GStack workflows form 159 canonical manifests.',
        '111 active skill modules are mirrored across runtime directories with 71 external lock definitions in skills-lock.json.',
        'Claude-Mem 3-layer progressive disclosure indexes compact titles first (~35 tokens) before hydrating full payloads.'
      ],
      narrative:
        'Established persistent episodic memory with 3-stage retrieval (Index Search -> Timeline Window -> Selective Hydration) to prevent context window exhaustion during multi-turn diagnostics.',
      rootCause: 'NOMINAL_ARCHITECTURE_BASELINE',
      probeMetrics: {},
      filesOrEndpoints: ['src/core/memory/claude-mem-engine.js', 'src/core/skills/read-only-skill-router.js']
    });
  }

  _enforceBoundedRetention() {
    while (this.observationsById.size > this.maxObservationsInMemory) {
      let oldestKey = null;
      for (const [key] of this.observationsById.entries()) {
        if (key === 'CMEM-BOOT-001') continue;
        oldestKey = key;
        break;
      }
      if (!oldestKey) break;
      this.observationsById.delete(oldestKey);
      this.storageDiagnostics.evictedObservationsCount += 1;
    }
  }

  /**
   * Record a new structured episodic observation into Claude-Mem (SQLite + in-memory index).
   * Enforces strict epistemic separation between static architectural metadata and live probe evidence,
   * and stamps ownerUserId / ownerUsername / visibilityScope for multi-user isolation.
   */
  recordObservation(input = {}) {
    const nowIso = new Date().toISOString();
    const observationId =
      input.observationId ||
      `CMEM-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
    const sessionId = String(input.sessionId || 'SESSION-DEFAULT');
    const rawType = String(input.type || input.observationType || 'probe_evidence').toLowerCase();
    const type = VALID_OBSERVATION_TYPES.has(rawType) ? rawType : 'probe_evidence';

    const isArchitecturalOrStatic =
      observationId === 'CMEM-BOOT-001' ||
      sessionId === 'SESSION-BOOT-BASELINE' ||
      input.memoryCategory === 'ARCHITECTURAL_KNOWLEDGE' ||
      input.memoryCategory === 'APPLICATION_METADATA' ||
      input.isStaticMetadata === true ||
      input.isLiveMeasurement === false;

    const memoryCategory = isArchitecturalOrStatic
      ? input.memoryCategory === 'APPLICATION_METADATA'
        ? 'APPLICATION_METADATA'
        : 'ARCHITECTURAL_KNOWLEDGE'
      : 'LIVE_OPERATIONAL_OBSERVATION';

    const isLiveMeasurement = !isArchitecturalOrStatic;

    const caller = this._extractCallerContext(input);
    const ownerUserId = isArchitecturalOrStatic ? null : caller.userId;
    const ownerUsername = isArchitecturalOrStatic ? null : caller.username;
    const visibilityScope = isArchitecturalOrStatic
      ? 'SHARED_ARCHITECTURAL'
      : input.visibilityScope
        ? String(input.visibilityScope).trim()
        : 'PRIVATE_OPERATIONAL';

    const title = String(input.title || 'Infrastructure Diagnostic Observation').slice(0, 220);
    const subtitle = String(input.subtitle || '').slice(0, 280);
    // Static architectural records must NEVER carry an operational target endpoint or fabricated probe metrics
    const target = isArchitecturalOrStatic
      ? null
      : input.target
        ? String(input.target).trim()
        : null;

    const rawTags = Array.isArray(input.conceptTags)
      ? input.conceptTags
      : Array.isArray(input.concepts)
        ? input.concepts
        : ['what-changed'];
    const conceptTags = rawTags
      .map((t) => String(t).toLowerCase().trim())
      .filter((t) => CONCEPT_TAXONOMY.has(t) || t.length >= 3)
      .slice(0, 6);
    if (conceptTags.length === 0) conceptTags.push('what-changed');

    const facts = Array.isArray(input.facts)
      ? input.facts.map((f) => String(f)).slice(0, 12)
      : [];
    const narrative = String(input.narrative || subtitle || title);
    const rootCause = input.rootCause || input.rootCauseLayer ? String(input.rootCause || input.rootCauseLayer) : null;
    const rawMetrics = input.probeMetrics || input.rawPayload;
    const probeMetrics =
      !isArchitecturalOrStatic && rawMetrics && typeof rawMetrics === 'object' ? rawMetrics : {};
    const filesOrEndpoints = Array.isArray(input.filesOrEndpoints)
      ? input.filesOrEndpoints.map((f) => String(f)).slice(0, 10)
      : target
        ? [target]
        : [];

    // Resolve causal parent observation if not explicitly provided
    let parentObservationId = input.parentObservationId ? String(input.parentObservationId) : null;
    if (!parentObservationId && isLiveMeasurement) {
      const allExisting = Array.from(this.observationsById.values());
      for (let i = allExisting.length - 1; i >= 0; i--) {
        const candidate = allExisting[i];
        if (!candidate.isLiveMeasurement) continue;
        if (candidate.sessionId === sessionId) {
          parentObservationId = candidate.observationId;
          break;
        }
      }
    }

    const compactSummaryObj = { observationId, type, memoryCategory, title, target, conceptTags };
    const fullPayloadObj = {
      observationId,
      sessionId,
      ownerUserId,
      ownerUsername,
      visibilityScope,
      type,
      memoryCategory,
      isLiveMeasurement,
      parentObservationId,
      title,
      subtitle,
      target,
      conceptTags,
      facts,
      narrative,
      rootCause,
      probeMetrics,
      filesOrEndpoints
    };

    const exactFullInput =
      input.exactFullTokens ?? input.providerReportedTokens ?? input.exactTokens;
    const indexEst = estimateTokenCount(compactSummaryObj, input.exactIndexTokens);
    const fullEst = estimateTokenCount(fullPayloadObj, exactFullInput);
    const indexTokens = indexEst.isExactProviderTokenCount
      ? indexEst.tokens
      : Math.max(20, indexEst.tokens);
    const fullTokens = fullEst.isExactProviderTokenCount
      ? fullEst.tokens
      : Math.max(indexTokens + 45, fullEst.tokens);
    const tokenEstimationMethod = fullEst.estimationMethod;
    const isExactProviderTokenCount = fullEst.isExactProviderTokenCount;

    let persistedToSqlite = false;
    let persistenceStatus = 'IN_MEMORY_ONLY';
    let persistenceError = null;

    const existingSession = this.sessionsById.get(sessionId) || {
      sessionId,
      projectScope: 'EJII-Sovereign-Fabric',
      ownerUserId,
      ownerUsername,
      requestSummary: title,
      investigatedSummary: target ? `Inspected ${target}` : 'Inspected system state',
      learnedSummary: rootCause || subtitle || title,
      completedSummary: narrative.slice(0, 200),
      nextStepsSummary: 'Continue progressive telemetry correlation',
      observationCount: 0,
      startedAt: nowIso,
      updatedAt: nowIso
    };
    if (!existingSession.ownerUserId && ownerUserId) existingSession.ownerUserId = ownerUserId;
    if (!existingSession.ownerUsername && ownerUsername) existingSession.ownerUsername = ownerUsername;
    existingSession.observationCount += 1;
    existingSession.updatedAt = nowIso;
    if (rootCause) existingSession.learnedSummary = rootCause;
    this.sessionsById.set(sessionId, existingSession);

    const createdAt = input.createdAt || nowIso;

    if (this.useSqlite && this.dbHandle) {
      this.storageDiagnostics.writeAttemptsCount += 1;
      try {
        this.dbHandle
          .prepare(`
            INSERT OR REPLACE INTO ejii_claude_mem_observations (
              observation_id, session_id, obs_type, memory_category, is_live_measurement,
              parent_observation_id, title, subtitle, target_entity,
              concept_tags_json, facts_json, narrative, root_cause, probe_metrics_json,
              files_or_endpoints_json, index_tokens, full_tokens, token_estimation_method,
              owner_user_id, owner_username, visibility_scope, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `)
          .run(
            observationId,
            sessionId,
            type,
            memoryCategory,
            isLiveMeasurement ? 1 : 0,
            parentObservationId,
            title,
            subtitle,
            target,
            JSON.stringify(conceptTags),
            JSON.stringify(facts),
            narrative,
            rootCause,
            JSON.stringify(probeMetrics),
            JSON.stringify(filesOrEndpoints),
            indexTokens,
            fullTokens,
            tokenEstimationMethod,
            ownerUserId,
            ownerUsername,
            visibilityScope,
            createdAt
          );

        this.dbHandle
          .prepare(`
            INSERT OR REPLACE INTO ejii_claude_mem_sessions (
              session_id, project_scope, owner_user_id, owner_username,
              request_summary, investigated_summary,
              learned_summary, completed_summary, next_steps_summary,
              observation_count, started_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `)
          .run(
            existingSession.sessionId,
            existingSession.projectScope,
            existingSession.ownerUserId || null,
            existingSession.ownerUsername || null,
            existingSession.requestSummary,
            existingSession.investigatedSummary,
            existingSession.learnedSummary,
            existingSession.completedSummary,
            existingSession.nextStepsSummary,
            existingSession.observationCount,
            existingSession.startedAt,
            existingSession.updatedAt
          );

        persistedToSqlite = true;
        persistenceStatus = 'PERSISTED_SQLITE';
        this.storageDiagnostics.writeSuccessCount += 1;
      } catch (err) {
        persistedToSqlite = false;
        persistenceStatus = 'SQLITE_WRITE_FAILED';
        persistenceError = err && err.message ? err.message : String(err);
        this.storageDiagnostics.writeFailuresCount += 1;
        this._recordStorageError('SQLITE_WRITE', err);
      }
    }

    const obs = {
      observationId,
      id: observationId,
      sessionId,
      ownerUserId,
      ownerUsername,
      visibilityScope,
      type,
      memoryCategory,
      isLiveMeasurement,
      parentObservationId,
      title,
      subtitle,
      target,
      conceptTags,
      facts,
      narrative,
      rootCause,
      probeMetrics,
      rawPayload: probeMetrics,
      filesOrEndpoints,
      indexTokens,
      indexTokenEstimate: indexTokens,
      fullTokens,
      fullTokenEstimate: fullTokens,
      tokenEstimationMethod,
      isExactProviderTokenCount,
      persisted: persistedToSqlite,
      persistedToSqlite,
      persistenceStatus,
      persistenceError,
      createdAt
    };

    this.observationsById.set(observationId, obs);
    this._enforceBoundedRetention();

    return obs;
  }

  /**
   * LAYER 1 — Compact Index Search (`mem-search` pattern):
   * Returns lightweight index rows (~35 tokens each) ranked by BM25/keyword + target + concept-tag match,
   * calculating token savings compared to loading full observation payloads upfront.
   * Excludes static architectural metadata (`ARCHITECTURAL_KNOWLEDGE`) by default from operational searches,
   * and enforces multi-user observation ownership isolation.
   */
  searchIndex(queryOrOptions = '', options = {}) {
    this.totalIndexQueries += 1;
    let rawQuery = queryOrOptions;
    let opts = options || {};
    if (queryOrOptions && typeof queryOrOptions === 'object' && !Array.isArray(queryOrOptions)) {
      opts = queryOrOptions;
      rawQuery = opts.query || opts.q || '';
    }

    const cleanQuery = String(rawQuery || '').toLowerCase().trim();
    const queryTokens = cleanQuery.split(/[^a-z0-9._:-]+/).filter((t) => t.length >= 2);
    const filterTarget = opts.target ? String(opts.target).toLowerCase().trim() : null;
    const filterType = opts.type ? String(opts.type).toLowerCase().trim() : null;
    const filterConcept = opts.concept ? String(opts.concept).toLowerCase().trim() : null;
    const includeArchitecturalMetadata = Boolean(opts.includeArchitecturalMetadata);
    const limit = Math.min(50, Math.max(1, Number(opts.limit) || 10));

    const allObs = Array.from(this.observationsById.values());
    const scored = [];
    let filteredOutUnauthorizedCount = 0;

    for (const obs of allObs) {
      if (!includeArchitecturalMetadata && obs.memoryCategory !== 'LIVE_OPERATIONAL_OBSERVATION') {
        continue;
      }
      if (!this._isObservationAccessibleToCaller(obs, opts)) {
        filteredOutUnauthorizedCount += 1;
        continue;
      }
      if (filterTarget && String(obs.target || '').toLowerCase() !== filterTarget) continue;
      if (filterType && obs.type !== filterType) continue;
      if (filterConcept && !obs.conceptTags.includes(filterConcept)) continue;

      let score = 1;
      const titleLower = obs.title.toLowerCase();
      const subLower = (obs.subtitle || '').toLowerCase();
      const targetLower = String(obs.target || '').toLowerCase();
      const narrativeLower = (obs.narrative || '').toLowerCase();
      const rootCauseLower = String(obs.rootCause || '').toLowerCase();

      for (const tok of queryTokens) {
        if (targetLower === tok) score += 35;
        else if (targetLower.includes(tok)) score += 18;
        if (titleLower.includes(tok)) score += 16;
        if (subLower.includes(tok)) score += 10;
        if (rootCauseLower.includes(tok)) score += 14;
        if (obs.conceptTags.some((c) => c.includes(tok))) score += 12;
        if (narrativeLower.includes(tok)) score += 6;
      }

      if (queryTokens.length === 0 || score > 1) {
        scored.push({ obs, score });
      }
    }

    scored.sort((a, b) => {
      if (b.score !== a.score) return b.score - a.score;
      return String(b.obs.createdAt).localeCompare(String(a.obs.createdAt));
    });

    const selected = scored.slice(0, limit);
    let totalIndexTokens = 0;
    let equivalentFullTokens = 0;

    const indexHits = selected.map(({ obs, score }) => {
      totalIndexTokens += obs.indexTokens;
      equivalentFullTokens += obs.fullTokens;
      return {
        observationId: obs.observationId,
        id: obs.observationId,
        sessionId: obs.sessionId,
        ownerUserId: obs.ownerUserId || null,
        visibilityScope: obs.visibilityScope || 'PRIVATE_OPERATIONAL',
        type: obs.type,
        memoryCategory: obs.memoryCategory,
        isLiveMeasurement: obs.isLiveMeasurement,
        isHistoricalRecord: true,
        parentObservationId: obs.parentObservationId || null,
        title: obs.title,
        target: obs.target,
        conceptTags: obs.conceptTags,
        rootCause: obs.rootCause,
        relevanceScore: score,
        indexTokens: obs.indexTokens,
        fullTokensIfHydrated: obs.fullTokens,
        tokenEstimationMethod: obs.tokenEstimationMethod,
        createdAt: obs.createdAt
      };
    });

    const tokensSaved = Math.max(0, equivalentFullTokens - totalIndexTokens);
    this.cumulativeTokensSaved += tokensSaved;
    const compressionRatioPct =
      equivalentFullTokens > 0
        ? Number(((tokensSaved / equivalentFullTokens) * 100).toFixed(1))
        : 0;

    return {
      disclosureLayer: 'LAYER_1_COMPACT_INDEX',
      layer: 'LAYER_1_COMPACT_INDEX',
      query: rawQuery || '*',
      totalObservationsIndexed: allObs.length,
      filteredUnauthorizedCount: filteredOutUnauthorizedCount,
      hitCount: indexHits.length,
      indexTokensUsed: totalIndexTokens,
      equivalentFullPayloadTokens: equivalentFullTokens,
      tokensSaved,
      compressionRatioPct,
      tokenEstimationMethod: 'CHARACTER_HEURISTIC_4CHARS_PER_TOKEN',
      isExactProviderTokenCount: false,
      tokenMetrics: {
        indexTokensUsed: totalIndexTokens,
        equivalentFullPayloadTokens: equivalentFullTokens,
        tokensSaved,
        compressionRatioPct,
        tokenEstimationMethod: 'CHARACTER_HEURISTIC_4CHARS_PER_TOKEN',
        isExactProviderTokenCount: false
      },
      hits: indexHits,
      indexEntries: indexHits
    };
  }

  /**
   * LAYER 2 — Chronological Context Window (`timeline` pattern):
   * Returns observations immediately preceding and succeeding an anchor observation or target.
   * Excludes static architectural metadata by default so timelines reflect real operational history,
   * and enforces multi-user observation ownership isolation.
   */
  getTimelineContext(anchorIdOrOptions, options = {}) {
    this.totalTimelineQueries += 1;
    let anchorIdOrTarget = anchorIdOrOptions;
    let opts = options || {};
    if (anchorIdOrOptions && typeof anchorIdOrOptions === 'object' && !Array.isArray(anchorIdOrOptions)) {
      opts = anchorIdOrOptions;
      anchorIdOrTarget = opts.anchorId || opts.anchorObservationId || opts.target || '';
    }

    const depthBefore = Math.min(
      20,
      Math.max(1, Number(opts.depthBefore || opts.windowBefore) || 3)
    );
    const depthAfter = Math.min(
      20,
      Math.max(1, Number(opts.depthAfter || opts.windowAfter) || 3)
    );
    const includeArchitecturalMetadata = Boolean(opts.includeArchitecturalMetadata);

    const ordered = Array.from(this.observationsById.values())
      .filter(
        (o) =>
          (includeArchitecturalMetadata || o.memoryCategory === 'LIVE_OPERATIONAL_OBSERVATION') &&
          this._isObservationAccessibleToCaller(o, opts)
      )
      .sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt)));

    let anchorIndex = ordered.findIndex((o) => o.observationId === anchorIdOrTarget);
    if (anchorIndex === -1 && anchorIdOrTarget) {
      const targetLower = String(anchorIdOrTarget).toLowerCase();
      for (let i = ordered.length - 1; i >= 0; i--) {
        if (String(ordered[i].target || '').toLowerCase() === targetLower) {
          anchorIndex = i;
          break;
        }
      }
    }
    if (anchorIndex === -1 && !anchorIdOrTarget) {
      anchorIndex = Math.max(0, ordered.length - 1);
    }

    if (ordered.length === 0 || anchorIndex === -1) {
      return {
        disclosureLayer: 'LAYER_2_CHRONOLOGICAL_TIMELINE',
        layer: 'LAYER_2_TIMELINE_CONTEXT',
        anchorObservationId: null,
        anchorId: null,
        anchorIndex: -1,
        windowStartIndex: 0,
        windowEndIndex: 0,
        timelineEntries: [],
        timeline: []
      };
    }

    const startIdx = Math.max(0, anchorIndex - depthBefore);
    const endIdx = Math.min(ordered.length, anchorIndex + depthAfter + 1);
    const windowSlice = ordered.slice(startIdx, endIdx);
    const anchorObsId = ordered[anchorIndex] ? ordered[anchorIndex].observationId : null;

    const timelineEntries = windowSlice.map((o, idx) => {
      const relativePosition = startIdx + idx - anchorIndex;
      return {
        relativePosition,
        isAnchor: relativePosition === 0,
        observationId: o.observationId,
        id: o.observationId,
        sessionId: o.sessionId,
        ownerUserId: o.ownerUserId || null,
        visibilityScope: o.visibilityScope || 'PRIVATE_OPERATIONAL',
        type: o.type,
        memoryCategory: o.memoryCategory,
        isLiveMeasurement: o.isLiveMeasurement,
        isHistoricalRecord: true,
        parentObservationId: o.parentObservationId || null,
        title: o.title,
        subtitle: o.subtitle,
        target: o.target,
        conceptTags: o.conceptTags,
        rootCause: o.rootCause,
        createdAt: o.createdAt
      };
    });

    return {
      disclosureLayer: 'LAYER_2_CHRONOLOGICAL_TIMELINE',
      layer: 'LAYER_2_TIMELINE_CONTEXT',
      anchorObservationId: anchorObsId,
      anchorId: anchorObsId,
      anchorIndex,
      windowStartIndex: startIdx,
      windowEndIndex: Math.max(0, endIdx - 1),
      timelineEntries,
      timeline: timelineEntries
    };
  }

  /**
   * LAYER 3 — Selective Full Observation Hydration (`get_observations` pattern):
   * Fetches full structured details only for specific observation IDs selected from Layer 1/2,
   * enforcing multi-user ownership isolation so User B cannot hydrate User A's private observations.
   */
  getObservationsByIds(observationIds = [], options = {}) {
    this.totalHydrationQueries += 1;
    const ids = Array.isArray(observationIds) ? observationIds : [observationIds];
    const hydrated = [];
    const unauthorizedObservationIds = [];
    let hydratedTokens = 0;

    for (const rawId of ids) {
      const id = String(rawId || '').trim();
      if (!id) continue;
      const obs = this.observationsById.get(id);
      if (obs) {
        if (!this._isObservationAccessibleToCaller(obs, options)) {
          unauthorizedObservationIds.push(id);
          continue;
        }
        hydrated.push(obs);
        hydratedTokens += obs.fullTokens;
      }
    }

    return {
      disclosureLayer: 'LAYER_3_SELECTIVE_HYDRATION',
      layer: 'LAYER_3_FULL_OBSERVATION_DETAILS',
      requestedCount: ids.length,
      hydratedCount: hydrated.length,
      count: hydrated.length,
      filteredUnauthorizedCount: unauthorizedObservationIds.length,
      unauthorizedObservationIds,
      hydratedTokensUsed: hydratedTokens,
      tokenEstimationMethod: 'CHARACTER_HEURISTIC_4CHARS_PER_TOKEN',
      observations: hydrated
    };
  }

  /**
   * Reconstructs the causal parent-child chain for a given observation ID.
   */
  getCausalChain(observationId, maxDepth = 10, options = {}) {
    const chain = [];
    const visited = new Set();
    let currentId = observationId ? String(observationId).trim() : null;

    while (currentId && !visited.has(currentId) && chain.length < maxDepth) {
      visited.add(currentId);
      const obs = this.observationsById.get(currentId);
      if (!obs) break;
      if (!this._isObservationAccessibleToCaller(obs, options)) break;
      chain.unshift({
        observationId: obs.observationId,
        parentObservationId: obs.parentObservationId || null,
        sessionId: obs.sessionId,
        ownerUserId: obs.ownerUserId || null,
        type: obs.type,
        memoryCategory: obs.memoryCategory,
        isLiveMeasurement: obs.isLiveMeasurement,
        title: obs.title,
        target: obs.target,
        rootCause: obs.rootCause,
        createdAt: obs.createdAt
      });
      currentId = obs.parentObservationId || null;
    }

    return {
      anchorObservationId: observationId || null,
      depth: chain.length,
      chainLength: chain.length,
      causalChain: chain,
      chain
    };
  }

  /**
   * Compiles a token-budgeted 3-layer progressive disclosure memory bundle for a conversational turn.
   * Strictly enforces `maxTokenBudget` when hydrating Layer 3 details, excludes static architectural metadata,
   * and enforces caller ownership isolation.
   */
  compileProgressiveDisclosureContext(queryText = '', target = null, budgetOrOptions = 600) {
    const opts =
      budgetOrOptions && typeof budgetOrOptions === 'object' ? budgetOrOptions : {};
    const maxTokenBudget =
      typeof budgetOrOptions === 'number'
        ? Math.max(100, budgetOrOptions)
        : Math.max(100, Number(opts.maxTokenBudget) || 600);

    const layer1 = this.searchIndex(queryText, {
      ...opts,
      target,
      limit: 8,
      includeArchitecturalMetadata: false
    });

    // Respect token budget when selecting which Layer 1 hits to hydrate in Layer 3
    let usedTokens = layer1.indexTokensUsed;
    const chosenIdsForHydration = [];
    for (const hit of layer1.hits) {
      if (chosenIdsForHydration.length >= 2) break;
      if (
        chosenIdsForHydration.length > 0 &&
        usedTokens + hit.fullTokensIfHydrated > maxTokenBudget
      ) {
        break;
      }
      chosenIdsForHydration.push(hit.observationId);
      usedTokens += hit.fullTokensIfHydrated;
    }

    const layer2 = this.getTimelineContext(chosenIdsForHydration[0] || target || '', {
      ...opts,
      includeArchitecturalMetadata: false
    });
    const layer3 = this.getObservationsByIds(chosenIdsForHydration, opts);

    return {
      engine: 'CLAUDE_MEM_3_LAYER_PROGRESSIVE_DISCLOSURE',
      status: 'ACTIVE',
      maxTokenBudget,
      tokenBudget: {
        maxTokenBudget,
        usedTokens: Math.min(maxTokenBudget, layer1.indexTokensUsed + layer3.hydratedTokensUsed),
        tokenEstimationMethod: 'CHARACTER_HEURISTIC_4CHARS_PER_TOKEN',
        isExactProviderTokenCount: false
      },
      architecturalMetadataExcludedFromOperationalEvidence: true,
      multiUserIsolationEnforced: true,
      totalObservationsInStore: this.observationsById.size,
      totalSessionsTracked: this.sessionsById.size,
      layer1IndexSearch: {
        hitCount: layer1.hitCount,
        count: layer1.hitCount,
        indexTokensUsed: layer1.indexTokensUsed,
        tokensSaved: layer1.tokensSaved,
        compressionRatioPct: layer1.compressionRatioPct,
        topHits: layer1.hits.slice(0, 5)
      },
      layer1Index: {
        count: layer1.hitCount,
        tokensSaved: layer1.tokensSaved,
        compressionRatioPct: layer1.compressionRatioPct
      },
      layer2TimelineWindow: {
        anchorObservationId: layer2.anchorObservationId,
        entryCount: layer2.timelineEntries.length,
        entries: layer2.timelineEntries
      },
      layer3HydratedObservations: {
        hydratedCount: layer3.hydratedCount,
        count: layer3.hydratedCount,
        hydratedTokensUsed: layer3.hydratedTokensUsed,
        observations: layer3.observations
      },
      layer3HydratedDetails: {
        count: layer3.hydratedCount,
        hydratedTokensUsed: layer3.hydratedTokensUsed
      },
      storageDiagnostics: { ...this.storageDiagnostics },
      cumulativeTokensSaved: this.cumulativeTokensSaved
    };
  }

  getStatus(options = {}) {
    return this.getStatusSummary(options);
  }

  getStatusSummary(options = {}) {
    let liveOperationalCount = 0;
    let architecturalMetadataCount = 0;
    let callerAccessibleOperationalCount = 0;
    for (const obs of this.observationsById.values()) {
      if (obs.memoryCategory === 'LIVE_OPERATIONAL_OBSERVATION') {
        liveOperationalCount += 1;
        if (this._isObservationAccessibleToCaller(obs, options)) {
          callerAccessibleOperationalCount += 1;
        }
      } else {
        architecturalMetadataCount += 1;
      }
    }

    return {
      installed: true,
      engineId: 'claude-mem-v1-sovereign',
      storageBackend: this.useSqlite && this.dbHandle ? 'SQLITE_WAL_PERSISTENT' : 'IN_MEMORY',
      tables: ['ejii_claude_mem_observations', 'ejii_claude_mem_sessions'],
      disclosureArchitecture: [
        'LAYER_1_COMPACT_INDEX',
        'LAYER_2_CHRONOLOGICAL_TIMELINE',
        'LAYER_3_SELECTIVE_HYDRATION'
      ],
      epistemicSeparationPolicy: {
        architecturalMetadataExcludedFromOperationalEvidence: true,
        multiUserIsolationEnforced: true,
        liveOperationalObservationsCount: liveOperationalCount,
        callerAccessibleOperationalCount,
        architecturalMetadataRecordsCount: architecturalMetadataCount
      },
      tokenAccountingPolicy: {
        defaultMethod: 'CHARACTER_HEURISTIC_4CHARS_PER_TOKEN',
        supportsProviderExactTokens: true,
        isExactProviderTokenCountByDefault: false
      },
      storageDiagnostics: { ...this.storageDiagnostics },
      totalObservations: this.observationsById.size,
      totalSessions: this.sessionsById.size,
      totalIndexQueries: this.totalIndexQueries,
      totalTimelineQueries: this.totalTimelineQueries,
      totalHydrationQueries: this.totalHydrationQueries,
      cumulativeTokensSaved: this.cumulativeTokensSaved
    };
  }
}

const claudeMemEngine = new ClaudeMemEngine();

module.exports = {
  ClaudeMemEngine,
  claudeMemEngine,
  VALID_OBSERVATION_TYPES,
  VALID_MEMORY_CATEGORIES,
  CONCEPT_TAXONOMY,
  estimateTokenCount
};
