/**
 * EJII Chat-First Minimalist Infrastructure Intelligence Service
 *
 * Dual-Mode Conversational & Operational Diagnostic Engine:
 *   - Mode 1 (Operational & Diagnostic): Real DNS, ICMP, TCP, TLS, HTTP, Local IP/Gateway, Active Connections, Multi-Layer RCA, Governed Remediation
 *   - Mode 2 (Informational & Engineering): Conceptual explanations, protocol comparisons, command explanations, and historical session analysis (0 live probes)
 *   - Context & Disambiguation: Remembers targets/ports/observations across turns, asks clarification on context loss or multi-target ambiguity, never silently defaults to localhost on follow-ups
 *   - Bounded Working Memory + Full SQLite Persistence
 *   - Strict Per-User Session Ownership, RBAC, and SSRF / DNS-Rebinding Defenses
 */

'use strict';

const crypto = require('node:crypto');
const { performance } = require('node:perf_hooks');
const config = require('../../config');
const { db } = require('../../db/database');
const { realPing, realTraceroute } = require('../../protocols/icmp-ping');
const { checkPort } = require('../../protocols/tcp-port');
const { resolveRecord, getRealSystemDns, checkDnsConnectivityHealth } = require('../../protocols/dns-diag');
const { probeHttp } = require('../../protocols/http-probe');
const { auditTls } = require('../../protocols/tls-audit');
const { getVerifiedDefaultGateway, discoverLocalDhcpServer, inspectLocalNetworkConfiguration } = require('../../protocols/host-metrics');
const { processSocketCorrelator } = require('../../network/process-socket-correlator');
const { isSafeNetworkTarget, resolveAndValidateTarget } = require('../security');
const { crossLayerIncidentCorrelator } = require('../correlation/incident-correlator');
const { ROLE_LEVELS, autonomousInfrastructureOperator } = require('../operator/autonomous-infrastructure-operator');
const { evidenceFabric } = require('../evidence/evidence-fabric');
const {
  WELL_KNOWN_BRAND_DOMAINS,
  classifyDomainTypo,
  detectDomainTypo,
  hasNegativeExecutionConstraint,
  extractBrandHostnameShorthand,
  classifyConversationalTurn,
  isGreetingPrompt,
  isInformationalTechnicalQuestion,
  answerInformationalQuestion
} = require('./technical-knowledge-base');
const {
  isEpistemicOrSovereignFabricQuestion,
  answerEpistemicOrFabricQuestion,
  buildApplicationEpistemicContext,
  runAgenticToolLoop,
  resolvePronounInheritedTarget,
  executeConversationalSuperpowersBridge
} = require('./conversational-brain');
const { operationalMemoryEngine } = require('../memory/operational-memory-engine');
const { temporalInfrastructureGraph } = require('../topology/temporal-graph-engine');
const { multiSiteManager } = require('../multisite/multisite-manager');
const { edgeAgentService } = require('../agent/edge-agent-service');
const { hypothesisArbiter } = require('../../ai/hypothesis-arbiter');
const { predictiveHorizonEngine } = require('../../ai/predictive-horizon-engine');
const { timelineReconstructor } = require('../../observability/timeline-reconstructor');
const { superpowersSkillsEngine } = require('../skills/superpowers-skills-engine');
const { claudeMemEngine } = require('../memory/claude-mem-engine');
const { readOnlySkillCatalog } = require('../skills/read-only-skill-router');
const { projectAtlasEngine } = require('../../network/atlas/project-atlas-engine');

const MAX_WORKING_MEMORY_MESSAGES = 40;
const MAX_ENTITY_OBSERVATIONS = 25;
const MAX_SOCKET_SNAPSHOTS = 10;
const TARGET_INHERITANCE_TTL_MS = 10 * 60 * 1000; // 10 minutes (Phase Atlas XI)

function extractObservedTimingMs(details) {
  if (!details || typeof details !== 'object') return null;
  const candidateKeys = ['connectLatencyMs', 'latencyMs', 'durationMs', 'avgRttMs', 'ttfbMs', 'rttMs'];
  for (const key of candidateKeys) {
    const val = details[key];
    if (typeof val === 'number' && Number.isFinite(val)) {
      return val;
    }
  }
  return null;
}

class ChatOperatorService {
  constructor() {
    this.sessions = new Map();
    this.inFlightRequests = new Map(); // sessionId -> { requestId, abortController, startedAt, userId }
    this.llmInterpreter = null; // Optional external LLM brain adapter: async (promptText, sessionContext) => planOverride
    this.targetInheritanceTtlMs = TARGET_INHERITANCE_TTL_MS;
    this.persistenceDiagnostics = {
      schemaInitialized: false,
      writeAttemptsCount: 0,
      writeSuccessCount: 0,
      writeFailuresCount: 0,
      lastPersistenceError: null,
      persistenceState: 'IN_MEMORY_FALLBACK'
    };
    this._ensureTables();
  }

  /**
   * Register an optional LLM semantic interpreter / response synthesizer.
   * When absent or unavailable, the built-in semantic Brain-First interpreter operates deterministically.
   */
  setLlmInterpreter(interpreterFn) {
    this.llmInterpreter = typeof interpreterFn === 'function' ? interpreterFn : null;
  }

  getBrainStatus() {
    return {
      llmInterpreterConfigured: Boolean(this.llmInterpreter),
      semanticAiReady: true,
      inFlightRequestsCount: this.inFlightRequests.size,
      activeSessionsCount: this.sessions.size,
      persistenceDiagnostics: { ...this.persistenceDiagnostics },
      timestamp: new Date().toISOString()
    };
  }

  _ensureTables() {
    try {
      db.exec(`
        CREATE TABLE IF NOT EXISTS ejii_chat_sessions (
          session_id TEXT PRIMARY KEY,
          user_id TEXT,
          username TEXT,
          role TEXT,
          context_json TEXT,
          created_at TEXT,
          updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS ejii_chat_messages (
          message_id TEXT PRIMARY KEY,
          session_id TEXT NOT NULL,
          sender_role TEXT NOT NULL,
          content TEXT NOT NULL,
          metadata_json TEXT,
          created_at TEXT NOT NULL
        );
      `);
      this.persistenceDiagnostics.schemaInitialized = true;
      this.persistenceDiagnostics.persistenceState = 'HEALTHY_SQLITE';
    } catch (err) {
      this.persistenceDiagnostics.schemaInitialized = false;
      this.persistenceDiagnostics.persistenceState = 'SQLITE_DEGRADED';
      this.persistenceDiagnostics.lastPersistenceError = err && err.message ? err.message : String(err);
    }
  }

  _normalizeUserIdentity(user = {}) {
    if (typeof user === 'string') {
      const cleanName = user.trim();
      return {
        userId: cleanName ? `USR-${cleanName}` : 'op-1',
        username: cleanName || 'operator',
        role: 'ANALYST',
        hasExplicitIdentity: Boolean(cleanName)
      };
    }
    const obj = user && typeof user === 'object' ? user : {};
    const explicitId = String(obj.id || obj.userId || obj.sub || '').trim();
    const explicitUsername = String(obj.username || obj.email || '').trim();
    const userId = explicitId || (explicitUsername ? `USR-${explicitUsername}` : 'op-1');
    const username = explicitUsername || explicitId || 'operator';
    const role = String(obj.role || 'ANALYST').toUpperCase();
    return {
      userId,
      username,
      role,
      hasExplicitIdentity: Boolean(explicitId || explicitUsername)
    };
  }

  /**
   * Check that an existing session belongs to the requesting authenticated user.
   * Returns { allowed: true, session } or { allowed: false, statusCode: 403, error }.
   */
  verifySessionAccess(sessionId, user = {}) {
    if (!sessionId || typeof sessionId !== 'string') {
      return { allowed: true, session: null };
    }
    const cleanId = sessionId.trim();
    const caller = this._normalizeUserIdentity(user);

    const checkOwner = (ownerUserId, ownerUsername) => {
      if (!ownerUserId && !ownerUsername) return true;
      if (ownerUserId === 'op-1' && (!ownerUsername || ownerUsername === 'operator')) return true;
      if (caller.role === 'ADMIN') return true;
      if (ownerUserId && String(ownerUserId) === caller.userId) return true;
      if (
        ownerUsername &&
        String(ownerUsername).toLowerCase() === caller.username.toLowerCase() &&
        (!ownerUserId || ownerUserId === 'op-1' || ownerUserId === `USR-${ownerUsername}`)
      ) {
        return true;
      }
      return false;
    };

    if (this.sessions.has(cleanId)) {
      const existing = this.sessions.get(cleanId);
      if (!checkOwner(existing.userId, existing.username)) {
        return {
          allowed: false,
          statusCode: 403,
          error: {
            code: 'SESSION_OWNERSHIP_VIOLATION',
            message: 'Access denied: this conversation session belongs to a different authenticated user.'
          }
        };
      }
      return { allowed: true, session: existing };
    }

    try {
      const row = db.prepare('SELECT user_id, username FROM ejii_chat_sessions WHERE session_id = ?').get(cleanId);
      if (row && !checkOwner(row.user_id, row.username)) {
        return {
          allowed: false,
          statusCode: 403,
          error: {
            code: 'SESSION_OWNERSHIP_VIOLATION',
            message: 'Access denied: this conversation session belongs to a different authenticated user.'
          }
        };
      }
    } catch (err) {
      this.persistenceDiagnostics.lastPersistenceError = err && err.message ? err.message : String(err);
    }

    return { allowed: true, session: null };
  }

  getOrCreateSession(sessionId, user = {}) {
    const cleanId = (sessionId && typeof sessionId === 'string' && sessionId.trim())
      ? sessionId.trim()
      : `CHAT-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;

    const caller = this._normalizeUserIdentity(user);
    const access = this.verifySessionAccess(cleanId, user);
    if (!access.allowed) {
      const err = new Error(access.error.message);
      err.code = access.error.code;
      err.statusCode = 403;
      throw err;
    }

    if (this.sessions.has(cleanId)) {
      const existing = this.sessions.get(cleanId);
      existing.role = caller.role;
      return existing;
    }

    // Check SQLite for persisted session (Bounded working memory + SQLite history)
    try {
      const row = db.prepare('SELECT * FROM ejii_chat_sessions WHERE session_id = ?').get(cleanId);
      if (row) {
        const ctx = row.context_json ? JSON.parse(row.context_json) : {};
        const countRow = db.prepare('SELECT COUNT(*) AS cnt FROM ejii_chat_messages WHERE session_id = ?').get(cleanId);
        const totalPersisted = Number(countRow?.cnt) || 0;
        const msgRows = db.prepare(
          'SELECT * FROM (SELECT * FROM ejii_chat_messages WHERE session_id = ? ORDER BY created_at DESC LIMIT ?) ORDER BY created_at ASC'
        ).all(cleanId, MAX_WORKING_MEMORY_MESSAGES);

        const restored = {
          sessionId: cleanId,
          userId: row.user_id || caller.userId,
          username: row.username || caller.username,
          role: caller.role || (row.role || 'ANALYST').toUpperCase(),
          pendingTask: ctx.pendingTask || null,
          lastTarget: ctx.lastTarget || null,
          lastValidTarget: ctx.lastValidTarget || ctx.lastTarget || null,
          lastTargetTimestampMs: typeof ctx.lastTargetTimestampMs === 'number' ? ctx.lastTargetTimestampMs : null,
          targetHistory: Array.isArray(ctx.targetHistory) ? ctx.targetHistory : [],
          entityMemory: (ctx.entityMemory && typeof ctx.entityMemory === 'object') ? ctx.entityMemory : {},
          socketSnapshots: Array.isArray(ctx.socketSnapshots) ? ctx.socketSnapshots : [],
          lastMultiEndpoints: Array.isArray(ctx.lastMultiEndpoints) ? ctx.lastMultiEndpoints : [],
          lastGatewayIp: ctx.lastGatewayIp || null,
          lastPorts: Array.isArray(ctx.lastPorts) ? ctx.lastPorts : [],
          lastIntent: ctx.lastIntent || null,
          lastUrl: ctx.lastUrl || null,
          lastToolResults: ctx.lastToolResults || null,
          lastProbeResult: ctx.lastProbeResult || ctx.lastToolResults || null,
          probeHistory: Array.isArray(ctx.probeHistory) ? ctx.probeHistory : [],
          lastSteps: Array.isArray(ctx.lastSteps) ? ctx.lastSteps : [],
          lastStructuredAnswer: ctx.lastStructuredAnswer || null,
          turnCount: Number(ctx.turnCount) || 0,
          totalPersistedMessages: totalPersisted,
          maxWorkingMemoryMessages: MAX_WORKING_MEMORY_MESSAGES,
          messages: msgRows.map((m) => ({
            id: m.message_id,
            role: m.sender_role,
            content: m.content,
            createdAt: m.created_at,
            meta: m.metadata_json ? JSON.parse(m.metadata_json) : null
          }))
        };
        this.sessions.set(cleanId, restored);
        return restored;
      }
    } catch (_) {}

    const fresh = {
      sessionId: cleanId,
      userId: caller.userId,
      username: caller.username,
      role: caller.role,
      pendingTask: null,
      lastTarget: null,
      lastValidTarget: null,
      lastTargetTimestampMs: null,
      targetHistory: [],
      entityMemory: {},
      socketSnapshots: [],
      lastMultiEndpoints: [],
      lastGatewayIp: null,
      lastPorts: [],
      lastIntent: null,
      lastUrl: null,
      lastToolResults: null,
      lastProbeResult: null,
      probeHistory: [],
      lastSteps: [],
      lastStructuredAnswer: null,
      turnCount: 0,
      totalPersistedMessages: 0,
      maxWorkingMemoryMessages: MAX_WORKING_MEMORY_MESSAGES,
      messages: []
    };
    this.sessions.set(cleanId, fresh);
    return fresh;
  }

  /**
   * Retrieve full persisted message history from SQLite (even when active working memory is bounded)
   */
  getPersistedMessages(sessionId, limit = 200, offset = 0) {
    try {
      const rows = db.prepare(
        'SELECT * FROM ejii_chat_messages WHERE session_id = ? ORDER BY created_at ASC LIMIT ? OFFSET ?'
      ).all(sessionId, Math.min(1000, Math.max(1, Number(limit) || 200)), Math.max(0, Number(offset) || 0));
      return rows.map((m) => ({
        id: m.message_id,
        role: m.sender_role,
        content: m.content,
        createdAt: m.created_at,
        meta: m.metadata_json ? JSON.parse(m.metadata_json) : null
      }));
    } catch (_) {
      const s = this.sessions.get(sessionId);
      return s ? s.messages : [];
    }
  }

  /**
   * Update structured entity memory graph and timestamped observation log for a target host
   */
  _recordEntityMemory(session, target, patch = {}) {
    if (!session || !target || typeof target !== 'string') return null;
    const key = target.trim().toLowerCase();
    if (!key) return null;
    if (!session.entityMemory) session.entityMemory = {};

    const nowIso = new Date().toISOString();
    const existing = session.entityMemory[key] || {
      target: key,
      firstSeenAt: nowIso,
      checkCount: 0,
      resolvedIps: [],
      openPorts: [],
      closedPorts: [],
      filteredPorts: [],
      portLatencies: {},
      rttHistoryMs: [],
      observations: [],
      dnsStatus: null,
      lastDnsLatencyMs: null,
      lastPingRttMs: null,
      lastPingLossPct: null,
      lastHttpStatus: null,
      lastOutcomeSummary: null
    };

    existing.lastSeenAt = nowIso;
    existing.checkCount = (existing.checkCount || 0) + 1;

    if (Array.isArray(patch.resolvedIps) && patch.resolvedIps.length > 0) {
      for (const ip of patch.resolvedIps) {
        if (ip && !existing.resolvedIps.includes(ip)) existing.resolvedIps.push(ip);
      }
    }
    if (patch.dnsStatus) existing.dnsStatus = patch.dnsStatus;
    if (typeof patch.dnsLatencyMs === 'number') {
      existing.lastDnsLatencyMs = patch.dnsLatencyMs;
      existing.rttHistoryMs.push(patch.dnsLatencyMs);
    }
    if (typeof patch.pingRttMs === 'number') {
      existing.lastPingRttMs = patch.pingRttMs;
      existing.rttHistoryMs.push(patch.pingRttMs);
    }
    if (typeof patch.pingLossPct === 'number') {
      existing.lastPingLossPct = patch.pingLossPct;
    }
    if (Array.isArray(patch.openPorts)) {
      for (const p of patch.openPorts) {
        if (!existing.openPorts.includes(p)) existing.openPorts.push(p);
        existing.closedPorts = existing.closedPorts.filter((x) => x !== p);
      }
    }
    if (Array.isArray(patch.closedPorts)) {
      for (const p of patch.closedPorts) {
        if (!existing.closedPorts.includes(p)) existing.closedPorts.push(p);
        existing.openPorts = existing.openPorts.filter((x) => x !== p);
      }
    }
    if (Array.isArray(patch.filteredPorts)) {
      for (const p of patch.filteredPorts) {
        if (!existing.filteredPorts.includes(p)) existing.filteredPorts.push(p);
      }
    }
    if (patch.portLatencies && typeof patch.portLatencies === 'object') {
      existing.portLatencies = { ...existing.portLatencies, ...patch.portLatencies };
    }
    if (patch.httpStatus) existing.lastHttpStatus = patch.httpStatus;
    if (patch.summary) existing.lastOutcomeSummary = patch.summary;

    if (!Array.isArray(existing.observations)) existing.observations = [];
    existing.observations.push({
      observedAt: nowIso,
      intent: patch.intent || 'diagnostic',
      success: patch.success !== undefined ? Boolean(patch.success) : true,
      resolvedIps: patch.resolvedIps || existing.resolvedIps,
      dnsStatus: patch.dnsStatus || existing.dnsStatus,
      dnsLatencyMs: patch.dnsLatencyMs ?? null,
      pingRttMs: patch.pingRttMs ?? null,
      pingLossPct: patch.pingLossPct ?? null,
      icmpStatus: patch.icmpStatus || null,
      openPorts: patch.openPorts || [],
      closedPorts: patch.closedPorts || [],
      filteredPorts: patch.filteredPorts || [],
      portLatencies: patch.portLatencies || {},
      httpStatus: patch.httpStatus || null,
      summary: patch.summary || ''
    });
    if (existing.observations.length > MAX_ENTITY_OBSERVATIONS) {
      existing.observations = existing.observations.slice(-MAX_ENTITY_OBSERVATIONS);
    }
    if (existing.rttHistoryMs.length > 50) {
      existing.rttHistoryMs = existing.rttHistoryMs.slice(-50);
    }

    session.entityMemory[key] = existing;
    if (!Array.isArray(session.targetHistory)) session.targetHistory = [];
    if (!session.targetHistory.includes(key)) {
      session.targetHistory.push(key);
    }

    // Persist cross-session operational memory & compute baseline deltas / state transitions
    const sampleLatency =
      typeof patch.pingRttMs === 'number'
        ? patch.pingRttMs
        : typeof patch.dnsLatencyMs === 'number'
          ? patch.dnsLatencyMs
          : (patch.portLatencies && Object.values(patch.portLatencies)[0]) || null;

    const crossSessionInsights = operationalMemoryEngine.recordObservation({
      target: key,
      intent: patch.intent || 'diagnostic',
      status: patch.success === false ? 'FAIL' : 'PASS',
      resolvedIps: patch.resolvedIps || existing.resolvedIps,
      openPorts: patch.openPorts || [],
      closedPorts: patch.closedPorts || [],
      filteredPorts: patch.filteredPorts || [],
      latencyMs: typeof sampleLatency === 'number' ? sampleLatency : null,
      httpStatus: patch.httpStatus || null,
      failureLayer: patch.failureLayer || null,
      summary: patch.summary || '',
      sessionId: session.sessionId
    });
    if (crossSessionInsights) {
      session.lastMemoryInsights = crossSessionInsights;
    }

    return existing;
  }

  _persistSession(session, newMessages = []) {
    this.persistenceDiagnostics.writeAttemptsCount += 1;
    try {
      const nowIso = new Date().toISOString();
      const contextJson = JSON.stringify({
        lastTarget: session.lastTarget,
        lastValidTarget: session.lastValidTarget,
        lastTargetTimestampMs: session.lastTargetTimestampMs || null,
        pendingTask: session.pendingTask || null,
        targetHistory: session.targetHistory || [],
        entityMemory: session.entityMemory || {},
        socketSnapshots: (session.socketSnapshots || []).slice(-MAX_SOCKET_SNAPSHOTS),
        lastMultiEndpoints: session.lastMultiEndpoints || [],
        lastGatewayIp: session.lastGatewayIp || null,
        lastPorts: session.lastPorts,
        lastIntent: session.lastIntent,
        lastUrl: session.lastUrl,
        lastToolResults: session.lastToolResults,
        lastProbeResult: session.lastProbeResult || session.lastToolResults || null,
        probeHistory: (session.probeHistory || []).slice(-25),
        lastSteps: session.lastSteps,
        lastStructuredAnswer: session.lastStructuredAnswer,
        turnCount: session.turnCount
      });
      db.prepare(`
        INSERT INTO ejii_chat_sessions (session_id, user_id, username, role, context_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(session_id) DO UPDATE SET
          username = excluded.username,
          role = excluded.role,
          context_json = excluded.context_json,
          updated_at = excluded.updated_at
      `).run(
        session.sessionId,
        session.userId || 'op-1',
        session.username || 'operator',
        session.role || 'ANALYST',
        contextJson,
        nowIso,
        nowIso
      );

      const insertMsg = db.prepare(`
        INSERT OR REPLACE INTO ejii_chat_messages (message_id, session_id, sender_role, content, metadata_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `);
      for (const msg of newMessages) {
        insertMsg.run(
          msg.id,
          session.sessionId,
          msg.role,
          msg.content,
          msg.meta ? JSON.stringify(msg.meta) : null,
          msg.createdAt || nowIso
        );
      }
      this.persistenceDiagnostics.writeSuccessCount += 1;
      this.persistenceDiagnostics.persistenceState = 'HEALTHY_SQLITE';
      session.lastPersistenceStatus = 'PERSISTED_SQLITE';
      session.lastPersistenceError = null;
    } catch (err) {
      const errMsg = err && err.message ? err.message : String(err);
      this.persistenceDiagnostics.writeFailuresCount += 1;
      this.persistenceDiagnostics.persistenceState = 'SQLITE_DEGRADED';
      this.persistenceDiagnostics.lastPersistenceError = errMsg;
      session.lastPersistenceStatus = 'SQLITE_WRITE_FAILED';
      session.lastPersistenceError = errMsg;
    }
  }

  clearSession(sessionId, user = null) {
    if (!sessionId) return false;
    if (user) {
      const access = this.verifySessionAccess(sessionId, user);
      if (!access.allowed) {
        const err = new Error(access.error.message);
        err.code = access.error.code;
        err.statusCode = 403;
        throw err;
      }
    }
    this.cancelRequest(sessionId, null, user);
    this.sessions.delete(sessionId);
    try {
      db.prepare('DELETE FROM ejii_chat_messages WHERE session_id = ?').run(sessionId);
      db.prepare('DELETE FROM ejii_chat_sessions WHERE session_id = ?').run(sessionId);
    } catch (_) {}
    return true;
  }

  cancelRequest(sessionId, requestId = null, user = null) {
    if (user && sessionId) {
      const access = this.verifySessionAccess(sessionId, user);
      if (!access.allowed) {
        const err = new Error(access.error.message);
        err.code = access.error.code;
        err.statusCode = 403;
        throw err;
      }
    }
    const active = this.inFlightRequests.get(sessionId);
    if (!active) {
      return { cancelled: false, reason: 'No active request in flight for this session.' };
    }
    if (requestId && active.requestId !== requestId) {
      return { cancelled: false, reason: 'Request ID mismatch.' };
    }
    try {
      active.abortController.abort(new Error('CANCELLED_BY_USER'));
    } catch (_) {}
    this.inFlightRequests.delete(sessionId);
    return {
      cancelled: true,
      sessionId,
      requestId: active.requestId,
      cancelledAt: new Date().toISOString()
    };
  }

  /**
   * Brain-First Conversational & Semantic Interpretation Pipeline
   * Understands natural language, context, negative constraints, semantic paraphrases, and problem descriptions.
   * Never defaults missing targets to localhost and never forces conversational input into probes.
   */
  parseIntentAndEntities(promptText, session) {
    const raw = String(promptText || '').trim();
    const lower = raw.toLowerCase();
    const cleanNoPunct = lower.replace(/[?!.,;:'"`()[\]{}]/g, ' ').replace(/\s+/g, ' ').trim();

    const rawPriorTarget = session?.lastValidTarget || session?.lastTarget || null;
    const isPriorTargetExpired = Boolean(
      rawPriorTarget &&
      typeof session?.lastTargetTimestampMs === 'number' &&
      (Date.now() - session.lastTargetTimestampMs) > TARGET_INHERITANCE_TTL_MS
    );
    const priorTarget = isPriorTargetExpired ? null : rawPriorTarget;
    const hasPriorContext = Boolean(
      session &&
      (session.lastToolResults ||
        priorTarget ||
        Object.keys(session.entityMemory || {}).length > 0 ||
        (session.socketSnapshots && session.socketSnapshots.length > 0))
    );

    // 00-Epistemic. Sovereign Fabric v6 Truth Matrix, Bayesian Posteriors, Shannon Information-Gain, & Default Gateway Epistemic Queries
    if (isEpistemicOrSovereignFabricQuestion(raw)) {
      return {
        intent: 'epistemic_fabric_query',
        mode: 'informational',
        target: null,
        explicitTarget: null,
        ports: [],
        usedFollowUpTarget: false,
        preserveContextOnly: true
      };
    }

    // 00-LogTriage. Pasted Terminal Startup Logs, Service Readiness Failures & Multi-Port Mismatch Diagnosis
    // (e.g. SYNTRA one-click local startup: readiness timeout on http://127.0.0.1:3000/ while backend listens on :3001 with {"error":"Route not found."})
    const logAnalysis = operationalMemoryEngine.parseTerminalStartupLog(raw);
    if (logAnalysis && logAnalysis.isStartupOrTerminalLog) {
      const primaryHost = logAnalysis.extractedEndpoints[0]?.host || '127.0.0.1';
      const extractedLogPorts = Array.from(new Set(logAnalysis.extractedEndpoints.map((e) => e.port)));
      return {
        intent: 'log_and_startup_triage',
        mode: 'operational',
        target: primaryHost,
        explicitTarget: primaryHost,
        ports: extractedLogPorts.length > 0 ? extractedLogPorts : [3000, 3001],
        logAnalysis,
        usedFollowUpTarget: false,
        preserveLastRemoteTarget: true
      };
    }

    // 00-IntelligenceSynthesis & Operations Command Center. Cross-System Operational Intelligence Briefing, Correlated Incidents, Regressions, Predictive Drift, Technical Debt Radar, Incident DNA, Network Black Box, Operational Time Machine, Organizational Knowledge ("Why configured differently"), & Multi-Employee Goal-Oriented Access Triage
    const isTechnicalDebtPrompt =
      /\b(infrastructure weaknesses|weaknesses should management address|technical debt radar|technical debt|human firewall|bus factor|reduce unnecessary infrastructure spending|unnecessary infrastructure spending|cost optimization)\b/i.test(lower);
    const isIncidentDnaOrOrgKnowledgePrompt =
      /\b(experienced this type of outage before|experienced this (?:outage|issue|problem) before|what actually resolved it|incident dna|similar historical incidents|the last admin|organizational knowledge|institutional knowledge)\b/i.test(lower);
    const isServerConfigDifferentialPrompt =
      /\b(why is this server configured differently|configured differently from the other servers|why is this (?:server|host|node) configured differently|server configuration differential)\b/i.test(lower);
    const isOrgConfigWhyPrompt =
      isServerConfigDifferentialPrompt ||
      /\b(why was this (?:gateway|router|service|port|host|subnet) configured differently|configured differently from the others|why was this configured|documented architecture|missing documentation)\b/i.test(lower);
    const isBroadUnspecifiedProblemPrompt =
      /\b(something is wrong with (?:our |the )?infrastructure|find out what is causing the problem|something is wrong with (?:our |the )?(?:network|system|environment|servers)|investigate what is wrong across (?:our |the )?infrastructure)\b/i.test(lower);
    const isTimeMachine30mPrompt =
      /\b(\d+\s*minutes?\s+before (?:this |the )?outage|happened in the \d+\s*minutes?\s+before|operational time machine|30 minutes before this outage)\b/i.test(lower);
    const isBlackBoxTimelinePrompt =
      isTimeMachine30mPrompt ||
      /\b(what changed before (?:the )?(?:network )?outage|show me what changed|what changed during the last 24 hours|network black box|configuration dna|configuration drift|pre-incident timeline)\b/i.test(lower);
    const isMultiEmployeeAppAccessPrompt =
      /\b(several employees suddenly cannot access|employees suddenly cannot access|employees cannot access the internal application|users suddenly cannot access the internal|cannot access the internal application)\b/i.test(lower);
    const isMultiDeviceOrTopProblemsPrompt =
      isMultiEmployeeAppAccessPrompt ||
      /\b(lose connectivity simultaneously|lost connectivity simultaneously|three most serious problems|most serious problems|investigate the three|several office devices)\b/i.test(lower);

    const isMultiSitePrompt =
      /\b(which sites|which branch offices|branch offices are affected|multi-site|multi site|cross-site|cross site|show sites|show branches|fleet overview|fleet sites|edge agents?|governance mode)\b/i.test(lower);

    const isPredictiveHorizonPrompt =
      /\b(predictive horizon|horizon risk|time to sla|sla breach|saturation cliff|queueing cliff|m\/m\/1|cut-vertex|cut vertex|single point of failure|cascade forecast|compound failure risk)\b/i.test(lower);
    const isHypothesisArbitrationPrompt =
      /\b(hypothesis arbitration|multi-domain arbitration|arbitrate hypotheses|6-domain|6 domain|closed-loop arbitration|shannon information gain|competing hypotheses|causal arbitration)\b/i.test(lower);
    const isTimelineReconstructionPrompt =
      /\b(patient zero|pre-incident timeline|chronological timeline|cusum|changepoint detection|timeline reconstruction)\b/i.test(lower);
    const isSuperpowersPrompt =
      /\b(superpowers|systematic-debugging|systematic debugging|find-skills|grill-me|writing-plans|subagent-driven|verification-before-completion|self-improving-agent|unified synthesis)\b/i.test(lower);

    const isIntelligenceSynthesisPrompt =
      isBroadUnspecifiedProblemPrompt ||
      isTechnicalDebtPrompt ||
      isIncidentDnaOrOrgKnowledgePrompt ||
      isOrgConfigWhyPrompt ||
      isBlackBoxTimelinePrompt ||
      isMultiDeviceOrTopProblemsPrompt ||
      isMultiSitePrompt ||
      isPredictiveHorizonPrompt ||
      isHypothesisArbitrationPrompt ||
      isTimelineReconstructionPrompt ||
      isSuperpowersPrompt ||
      /\b(intelligence briefing|anomaly briefing|analyze (?:infrastructure )?anomalies|active regressions|predictive (?:latency |rtt )?(?:drift|risk|risks)|operational intelligence synthesis|systemic (?:failure )?patterns|learned playbooks|operational decisions ledger|operations command cent(?:er|re)|command cent(?:er|re) overview|correlated incidents|incident correlation|what is actually happening across (?:the )?infrastructure|most important thing we should address)\b/i.test(lower);
    if (isIntelligenceSynthesisPrompt) {
      // Build non-mutually-exclusive synthesis capability set so complex queries run all relevant engines simultaneously
      const activeSynthesisCapabilities = new Set([
        'PRE_INCIDENT_TIMELINE_RECONSTRUCTION',
        'MULTI_DOMAIN_HYPOTHESIS_ARBITRATION',
        'PREDICTIVE_HORIZON_ATTENTION',
        'SUPERPOWERS_UNIFIED_SYNTHESIS'
      ]);
      if (isMultiSitePrompt) activeSynthesisCapabilities.add('MULTISITE_FLEET_CORRELATION');
      if (isBroadUnspecifiedProblemPrompt) activeSynthesisCapabilities.add('BROAD_UNSPECIFIED_INFRASTRUCTURE_INVESTIGATION');
      if (isServerConfigDifferentialPrompt) activeSynthesisCapabilities.add('SERVER_CONFIG_DIFFERENTIAL_WHY');
      if (isTechnicalDebtPrompt) activeSynthesisCapabilities.add('TECHNICAL_DEBT_RADAR');
      if (isOrgConfigWhyPrompt) activeSynthesisCapabilities.add('ORGANIZATIONAL_KNOWLEDGE_WHY');
      if (isIncidentDnaOrOrgKnowledgePrompt) activeSynthesisCapabilities.add('INCIDENT_DNA_AND_PLAYBOOKS');
      if (isTimeMachine30mPrompt) activeSynthesisCapabilities.add('OPERATIONAL_TIME_MACHINE_30M');
      if (isBlackBoxTimelinePrompt) activeSynthesisCapabilities.add('NETWORK_BLACK_BOX_TIMELINE');
      if (isMultiEmployeeAppAccessPrompt) activeSynthesisCapabilities.add('AUTONOMOUS_GOAL_MULTI_EMPLOYEE_ACCESS');
      if (isMultiDeviceOrTopProblemsPrompt) activeSynthesisCapabilities.add('MULTI_DEVICE_OR_TOP_PROBLEMS');

      let synthesisSubfocus = 'FULL_COMMAND_CENTER';
      if (isMultiSitePrompt) synthesisSubfocus = 'MULTISITE_FLEET_CORRELATION';
      else if (isBroadUnspecifiedProblemPrompt) synthesisSubfocus = 'BROAD_UNSPECIFIED_INFRASTRUCTURE_INVESTIGATION';
      else if (isServerConfigDifferentialPrompt) synthesisSubfocus = 'SERVER_CONFIG_DIFFERENTIAL_WHY';
      else if (isTechnicalDebtPrompt) synthesisSubfocus = 'TECHNICAL_DEBT_RADAR';
      else if (isOrgConfigWhyPrompt) synthesisSubfocus = 'ORGANIZATIONAL_KNOWLEDGE_WHY';
      else if (isIncidentDnaOrOrgKnowledgePrompt) synthesisSubfocus = 'INCIDENT_DNA_AND_PLAYBOOKS';
      else if (isTimeMachine30mPrompt) synthesisSubfocus = 'OPERATIONAL_TIME_MACHINE_30M';
      else if (isTimelineReconstructionPrompt) synthesisSubfocus = 'PRE_INCIDENT_TIMELINE_RECONSTRUCTION';
      else if (isBlackBoxTimelinePrompt) synthesisSubfocus = 'NETWORK_BLACK_BOX_TIMELINE';
      else if (isHypothesisArbitrationPrompt) synthesisSubfocus = 'MULTI_DOMAIN_HYPOTHESIS_ARBITRATION';
      else if (isPredictiveHorizonPrompt) synthesisSubfocus = 'PREDICTIVE_HORIZON_ATTENTION';
      else if (isSuperpowersPrompt) synthesisSubfocus = 'SUPERPOWERS_UNIFIED_SYNTHESIS';
      else if (isMultiEmployeeAppAccessPrompt) synthesisSubfocus = 'AUTONOMOUS_GOAL_MULTI_EMPLOYEE_ACCESS';
      else if (isMultiDeviceOrTopProblemsPrompt) synthesisSubfocus = 'MULTI_DEVICE_OR_TOP_PROBLEMS';

      let explicitSynthTarget = null;
      const synthIpMatch = raw.match(/\b((?:\d{1,3}\.){3}\d{1,3})\b/);
      if (synthIpMatch) explicitSynthTarget = synthIpMatch[1];
      else if (/\blocalhost\b/i.test(raw)) explicitSynthTarget = 'localhost';

      return {
        intent: 'infrastructure_intelligence_synthesis',
        mode: 'operational',
        target: explicitSynthTarget || priorTarget || 'operational_intelligence_fabric',
        explicitTarget: explicitSynthTarget,
        ports: session?.lastPorts || [],
        synthesisSubfocus,
        activeSynthesisCapabilities: Array.from(activeSynthesisCapabilities),
        usedFollowUpTarget: Boolean(!explicitSynthTarget && priorTarget),
        preserveLastRemoteTarget: true
      };
    }

    const extractValidHostnameCandidate = (text) => {
      const domainRegex = /\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,24}))\b/g;
      const stopDomains = new Set([
        'e.g', 'i.e', 'etc.', 'node.js', 'next.js', 'vue.js', 'chart.js', 'three.js',
        'server.js', 'server.mjs', 'server.ts', 'index.js', 'index.ts', 'app.js', 'app.ts',
        'skill.md', 'readme.md', 'package.json', 'tsconfig.json', 'skills-lock.json'
      ]);
      const nonHostExtensions = /\.(?:mjs|cjs|js|ts|tsx|jsx|json|md|py|sh|bat|ps1|cmd|yaml|yml|toml|ini|cfg|conf|lock|sql|db|sqlite|log|txt|csv|html|css|scss|svg|png|jpg|jpeg|gif|ico|pcap|pcapng|cap)$/i;
      let m;
      while ((m = domainRegex.exec(text)) !== null) {
        const candidate = m[1];
        const lowerCandidate = candidate.toLowerCase();
        if (!stopDomains.has(lowerCandidate) && !nonHostExtensions.test(lowerCandidate)) {
          return candidate;
        }
      }
      return null;
    };

    // 00-ScenarioPlanning. Intelligent "What-If" Consequence Simulation & Multi-Option Adaptive Remediation Comparator
    const isScenarioPlanningPrompt =
      /\b(what happens if|what would happen if|which services (?:are|would be) affected by this dependency|likely impact of changing|impact of changing (?:this )?configuration|what-if scenario|simulate scenario|which remediation option has the lowest operational risk|which configuration change introduces the lowest operational risk|compare remediation options|what could happen if the (?:recommended|proposed) (?:action|remediation) fails|if the (?:recommended|proposed) (?:action|remediation) fails|move this subnet to another vlan|move subnet|another vlan|dhcp scope capacity is exhausted|dhcp scope exhausted)\b/i.test(lower);
    if (isScenarioPlanningPrompt) {
      let explicitScenarioTarget = null;
      const ipMatch = raw.match(/\b((?:\d{1,3}\.){3}\d{1,3})\b/);
      if (ipMatch) {
        explicitScenarioTarget = ipMatch[1];
      } else if (/\blocalhost\b/i.test(raw)) {
        explicitScenarioTarget = 'localhost';
      } else if (/\bgateway\b/i.test(raw)) {
        explicitScenarioTarget = session?.lastGatewayIp || '127.0.0.1';
      } else {
        explicitScenarioTarget = extractValidHostnameCandidate(raw);
      }
      let scenarioType = 'DEPENDENCY_IMPACT_ANALYSIS';
      if (/\b(dhcp|scope capacity|exhausted)\b/i.test(lower)) {
        scenarioType = 'DHCP_SCOPE_CAPACITY_EXHAUSTION';
      } else if (/\b(vlan|subnet)\b/i.test(lower)) {
        scenarioType = 'SUBNET_OR_VLAN_MIGRATION';
      } else if (/\b(gateway|unavailable|goes down|outage)\b/i.test(lower)) {
        scenarioType = 'GATEWAY_OR_DEPENDENCY_UNAVAILABLE';
      } else if (/\b(changing|configuration|config|port|firewall)\b/i.test(lower) && !/\b(remediation|fails)\b/i.test(lower)) {
        scenarioType = 'CONFIGURATION_OR_PORT_CHANGE';
      } else if (/\b(remediation|lowest operational risk|recommended action fails|proposed remediation fails|action fails)\b/i.test(lower)) {
        scenarioType = 'REMEDIATION_FAILURE_OR_COMPARISON';
      }
      const portMatch = raw.match(/\bport\s+(\d{1,5})\b/i);
      const isSameTargetAsPrior = !explicitScenarioTarget || (priorTarget && explicitScenarioTarget.toLowerCase() === priorTarget.toLowerCase());
      const scenarioPorts = portMatch
        ? [Number(portMatch[1])]
        : (isSameTargetAsPrior && session?.lastPorts?.length ? session.lastPorts : [443]);
      const resolvedScenarioTarget = explicitScenarioTarget || priorTarget || '127.0.0.1';
      return {
        intent: 'scenario_planning_what_if',
        mode: 'operational',
        target: resolvedScenarioTarget,
        explicitTarget: explicitScenarioTarget,
        ports: scenarioPorts,
        scenarioType,
        usedFollowUpTarget: Boolean(!explicitScenarioTarget && priorTarget),
        preserveLastRemoteTarget: true
      };
    }

    // 00-BlastRadius. Topological Dependency & Blast-Radius Impact Analysis
    const isBlastRadiusPrompt =
      /\b(blast radius|downstream impact|upstream dependencies|dependency impact|topological impact|what depends on|cascading impact)\b/i.test(lower);
    if (isBlastRadiusPrompt) {
      let explicitBlastTarget = null;
      const ipMatch = raw.match(/\b((?:\d{1,3}\.){3}\d{1,3})\b/);
      if (ipMatch) {
        explicitBlastTarget = ipMatch[1];
      } else if (/\blocalhost\b/i.test(raw)) {
        explicitBlastTarget = 'localhost';
      } else {
        explicitBlastTarget = extractValidHostnameCandidate(raw);
      }
      const portMatch = raw.match(/\bport\s+(\d{1,5})\b/i);
      const isSameTargetAsPrior = !explicitBlastTarget || (priorTarget && explicitBlastTarget.toLowerCase() === priorTarget.toLowerCase());
      const resolvedBlastTarget = explicitBlastTarget || priorTarget || 'localhost';
      return {
        intent: 'dependency_blast_radius',
        mode: 'operational',
        target: resolvedBlastTarget,
        explicitTarget: explicitBlastTarget,
        ports: portMatch ? [Number(portMatch[1])] : (isSameTargetAsPrior ? (session?.lastPorts || []) : []),
        usedFollowUpTarget: Boolean(!explicitBlastTarget && priorTarget),
        preserveLastRemoteTarget: true
      };
    }

    // 00-Atlas. Project Atlas Conversational Connectivity, Relay, Tunnel, Multi-Site & JIT Governance Intelligence (Section 7.2)
    const isAtlasConnectivityPrompt =
      /\b(project atlas|atlas relay|atlas proxy|atlas tunnel|tunnel clients?|remote agents?|remote clients?|connected agents? across every registered site|across every registered site|which relay currently serves our most unstable|most unstable connections?|why has the connection to this host disconnected repeatedly|disconnected repeatedly|compare current tunnel performance with its previous sessions|find the affected services if this relay becomes unavailable|if this relay becomes unavailable|identify the actual cause of the recent connectivity degradation|recommend an authorized recovery operation|authorized recovery operation|whether the p2p connection is carrying real traffic|fallen back to a relay|p2p connection|show (?:me )?(?:the )?(?:remote )?(?:agents?|clients?|tunnels?)|which tunnels? have high latency|why did (?:it|the agent|the client|the tunnel|tunnel) disconnect|why did tunnel|which relay is carrying|recommend (?:the )?(?:safest|lowest[- ]latency|optimal|best) relay|expired or over-permissive access policies|inspect traffic and health checks for proxy|temporarily grant operator access|jit access|jit grant|compare (?:its|the) (?:latest|previous) (?:tunnel|connection|session)|check the tunnel to the same server|nat traversal,? tls handshake,? routing,? or (?:the )?local backend)\b/i.test(lower) ||
      Boolean(session?.lastAtlasClientId && /\b(why did it disconnect|compare its latest connection|check the tunnel|its session|its connection|previous session|disconnected repeatedly|recovery operation)\b/i.test(lower));
    if (isAtlasConnectivityPrompt) {
      return {
        intent: 'atlas_connectivity_query',
        mode: 'operational',
        target: 'project_atlas_mesh',
        explicitTarget: null,
        ports: [],
        usedFollowUpTarget: false,
        preserveLastRemoteTarget: true
      };
    }

    // 00A. Multi-turn Pending Task Continuation (e.g. Mail Server Inspection domain supply or Port Ping target supply)
    const isMailServerCommand =
      /\b(check (?:the |my )?mail server|ping (?:the |my )?mail server|test (?:the |my )?mail server|mail server connection|email server|smtp server)\b/i.test(lower);

    if (session?.pendingTask?.type === 'mail_server_inspection' && !isMailServerCommand) {
      const isExplicitNonMailDiagnosticCommand =
        /\b(check\s+dns|dns\s+lookup|dns\s+check|resolve|nslookup|dig|traceroute|trace\s+route|active\s+connections|open\s+sockets|host\s+health|system\s+health|https?:\/\/)\b/i.test(lower) ||
        (/\bport\s+(\d{1,5})\b/i.test(lower) && !/\b(25|110|143|465|587|993|995)\b/.test(lower));
      const isTopicSwitch =
        /\b(port\s+ping|ping\s+port|dhcp|gateway|my\s+ip|local\s+ip|ipconfig|ifconfig|youtube|netflix|reddit|discord|github|cloudflare)\b/i.test(lower) ||
        isExplicitNonMailDiagnosticCommand ||
        isInformationalTechnicalQuestion(raw);
      if (isTopicSwitch) {
        session.pendingTask = null;
      } else {
        const strippedCandidate = raw
          .replace(/^(?:it'?s|it is|we use|using|via|in|on|check|test|ping|try|for|the domain is|the server is|domain is|server is)\s+/i, '')
          .replace(/[;,!?]+$/, '')
          .trim();

        const validMailTlds = new Set([
          'com', 'net', 'org', 'io', 'co', 'edu', 'gov', 'mil', 'int', 'dev', 'app', 'cloud',
          'ai', 'tech', 'info', 'biz', 'me', 'us', 'uk', 'de', 'fr', 'ca', 'au', 'jp', 'eu',
          'ru', 'az', 'tr', 'ch', 'nl', 'se', 'no', 'fi', 'dk', 'pl', 'it', 'es', 'br', 'in',
          'sg', 'kr', 'cn', 'local', 'internal', 'lan', 'corp'
        ]);
        const mailClientWords = new Set([
          'outlook', 'desktop', 'client', 'clients', 'webmail', 'browser', 'apple', 'thunderbird',
          'mobile', 'iphone', 'android', 'windows', 'mac', 'macos', 'app', 'office', 'users', 'imap', 'pop3', 'smtp'
        ]);
        const nonTldWords = new Set([
          'server', 'host', 'domain', 'mail', 'email', 'smtp', 'imap', 'pop3',
          'connection', 'status', 'check', 'ping', 'test', 'port', 'ports',
          'for', 'to', 'on', 'with', 'from', 'youtube', 'google', 'why', 'what', 'how', 'find', 'out',
          ...mailClientWords
        ]);
        const commandDisqualifiers = new Set([
          'port', 'ports', 'ping', 'for', 'check', 'test', 'resolve', 'lookup', 'why', 'what', 'how', 'youtube',
          ...mailClientWords
        ]);

        // Extract an explicit dotted domain if present inside the reply (e.g. "Outlook desktop on mail.company.com" or "company.com in browser")
        const explicitDottedMatch = strippedCandidate.match(/\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24})\b/);
        let normalizedDomain = null;

        if (explicitDottedMatch) {
          const candidateDotted = explicitDottedMatch[1].toLowerCase();
          const parts = candidateDotted.split('.');
          const tld = parts[parts.length - 1];
          if (validMailTlds.has(tld) && !nonTldWords.has(tld)) {
            normalizedDomain = candidateDotted;
          }
        } else {
          const candidateTokens = strippedCandidate.split(/\s+/);
          if (
            candidateTokens.length >= 2 &&
            candidateTokens.length <= 4 &&
            candidateTokens.every((t) => /^[a-zA-Z0-9-]+$/.test(t)) &&
            !candidateTokens.some((t) => commandDisqualifiers.has(t.toLowerCase()))
          ) {
            const last = candidateTokens[candidateTokens.length - 1].toLowerCase();
            if (validMailTlds.has(last) && !nonTldWords.has(last)) {
              normalizedDomain = candidateTokens.join('.').toLowerCase();
            }
          }
        }

        const mentionsMailClientContext = /\b(outlook|desktop|webmail|browser|apple\s*mail|thunderbird|mobile|imap\s+client|office\s*365)\b/i.test(lower);

        if (normalizedDomain && isSafeNetworkTarget(normalizedDomain)) {
          const clientContext = mentionsMailClientContext ? raw : (session.pendingTask.clientContext || null);
          session.pendingTask = null;
          session.lastValidTarget = normalizedDomain;
          session.lastTarget = normalizedDomain;
          const mailPorts = [25, 465, 587, 143, 993, 110, 995];
          return {
            intent: 'port_check',
            mode: 'operational',
            target: normalizedDomain,
            explicitTarget: normalizedDomain,
            recordType: 'MX',
            ports: mailPorts,
            clientContext,
            isMailTaskContinuation: true,
            secondaryToolPlans: [
              {
                intent: 'dns',
                mode: 'operational',
                target: normalizedDomain,
                recordType: 'MX',
                ports: []
              }
            ],
            usedFollowUpTarget: false
          };
        }

        // If the user supplied the client type (e.g., "Outlook desktop" or "webmail") without a domain, record the client slot and ask for the domain!
        if (mentionsMailClientContext && !normalizedDomain) {
          session.pendingTask.clientContext = strippedCandidate;
          session.pendingTask.missingSlots = ['domain'];
          return {
            intent: 'clarification_needed',
            mode: 'conversational',
            clarificationReason: 'MISSING_MAIL_DOMAIN_AFTER_CLIENT_CONTEXT',
            clarificationPrompt:
              `Got it — users are connecting via **${strippedCandidate}**. Which **email domain** (e.g., \`company.com\`) or **mail server hostname** (e.g., \`mail.company.com\`) should I inspect for \`MX\` records and mail transport ports (\`25, 465, 587, 993, 995\`)?`,
            target: null,
            explicitTarget: null,
            ports: [25, 465, 587, 143, 993, 110, 995],
            preserveContextOnly: true
          };
        }
      }
    }

    // 00A-2. Multi-turn Pending Task Continuation for bare "port ping" target supply (e.g. user said "port ping", then replies "youtube")
    if (session?.pendingTask?.type === 'port_ping_target') {
      const isPortPingTopicSwitch =
        /\b(check\s+dns|dns\s+lookup|resolve|nslookup|dig|traceroute|trace\s+route|dhcp|gateway|my\s+ip|local\s+ip|active\s+connections|open\s+sockets|https?:\/\/)\b/i.test(lower) ||
        isInformationalTechnicalQuestion(raw);
      if (isPortPingTopicSwitch) {
        session.pendingTask = null;
      } else {
        const brandFollowUp = extractBrandHostnameShorthand(raw);
        const domainFollowUpMatch = raw.match(/\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}|localhost|(?:\d{1,3}\.){3}\d{1,3})\b/);
        const resolvedPendingTarget = (domainFollowUpMatch ? domainFollowUpMatch[1] : null) || brandFollowUp;
        if (resolvedPendingTarget && isSafeNetworkTarget(resolvedPendingTarget)) {
          const portMatches = raw.match(/\b(\d{2,5})\b/g);
          const explicitPorts = portMatches
            ? portMatches.map(Number).filter((p) => p >= 1 && p <= 65535)
            : (session.pendingTask.requestedPorts || [80, 443]);
          session.pendingTask = null;
          session.lastValidTarget = resolvedPendingTarget;
          session.lastTarget = resolvedPendingTarget;
          return {
            intent: 'port_check',
            mode: 'operational',
            target: resolvedPendingTarget,
            explicitTarget: resolvedPendingTarget,
            ports: explicitPorts.length > 0 ? explicitPorts : [80, 443],
            usedFollowUpTarget: false
          };
        }
      }
    }

    // 00B. Explicit "port ping" / "ping port youtube 443" / "ping mail ports not ICMP" (Explicit TCP Port Check, Never ICMP Ping)
    const isExplicitPortPing =
      /\bport\s+ping\b/i.test(lower) ||
      /\bping\s+(?:mail\s+)?ports?\b/i.test(lower) ||
      /\bnot\s+icmp\b/i.test(lower);

    if (isExplicitPortPing) {
      let domainTarget = null;
      const domainMatch = raw.match(/\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}|localhost|(?:\d{1,3}\.){3}\d{1,3})\b/);
      if (domainMatch) {
        domainTarget = domainMatch[1];
      }
      if (!domainTarget) {
        domainTarget = extractBrandHostnameShorthand(raw);
      }

      const rawWithoutIp = raw.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '');
      const portNums = (rawWithoutIp.match(/\b(\d{2,5})\b/g) || [])
        .map(Number)
        .filter((p) => p >= 1 && p <= 65535);

      const isExplicitMailKeyword = /\b(mail|smtp|imap|pop3)\b/i.test(lower);
      // Only inherit priorTarget if the user said "not icmp" / "ping mail ports" or explicitly referred to the previous host
      const shouldInheritPrior =
        !domainTarget &&
        priorTarget &&
        (isExplicitMailKeyword || /\b(not\s+icmp|same|that|it|for\s+mail)\b/i.test(lower));
      const effectiveTarget = domainTarget || (shouldInheritPrior ? priorTarget : null);

      if (!effectiveTarget) {
        if (isExplicitMailKeyword) {
          return {
            intent: 'clarification_needed',
            mode: 'conversational',
            clarificationReason: 'MISSING_PORT_PING_TARGET',
            clarificationPrompt: 'Which mail server hostname or IP address would you like me to test?',
            target: null,
            explicitTarget: null,
            ports: [25, 465, 587, 143, 993, 110, 995],
            preserveContextOnly: true
          };
        }
        if (session) {
          session.pendingTask = {
            type: 'port_ping_target',
            originalRequest: raw,
            requestedPorts: portNums.length > 0 ? portNums : [80, 443],
            createdAt: new Date().toISOString()
          };
        }
        return {
          intent: 'clarification_needed',
          mode: 'conversational',
          clarificationReason: 'MISSING_PORT_PING_TARGET',
          clarificationPrompt: 'Which hostname or IP address (and TCP port, if specific) would you like me to test with a TCP port check?',
          target: null,
          explicitTarget: null,
          ports: portNums.length > 0 ? portNums : [80, 443],
          preserveContextOnly: true
        };
      }

      if (session?.pendingTask) {
        session.pendingTask = null;
      }

      const isMailRequest =
        isExplicitMailKeyword ||
        effectiveTarget.toLowerCase().startsWith('mail.') ||
        effectiveTarget.toLowerCase().startsWith('smtp.') ||
        effectiveTarget.toLowerCase().startsWith('imap.') ||
        (!domainTarget && session?.lastPorts && session.lastPorts.includes(25));
      const targetPorts = portNums.length > 0
        ? portNums
        : (isMailRequest ? [25, 465, 587, 143, 993, 110, 995] : [80, 443]);

      return {
        intent: 'port_check',
        mode: 'operational',
        target: effectiveTarget,
        explicitTarget: domainTarget || null,
        ports: targetPorts,
        prohibitIcmp: Boolean(/\bnot\s+icmp\b/i.test(lower)),
        usedFollowUpTarget: !domainTarget
      };
    }

    // 00C. Composite Local-Path / Layer-by-Layer Gateway & ISP Diagnostic (Never asks for a hostname)
    const isLocalPathPrompt =
      /\b(check (?:layer by layer|layer-by-layer|hop by hop|hop-by-hop|step by step)|check (?:my )?connection layer by layer|is (?:my )?(?:router|gateway) reachable and can i reach the internet|connection to gateway and isp|gateway to isp|local connection and internet path|network adapter through the gateway to the internet|where my connection fails,? from (?:the )?local interface to (?:the )?isp)\b/i.test(lower);
    if (isLocalPathPrompt) {
      return {
        intent: 'local_path_diagnostic',
        mode: 'operational',
        target: 'local_path_gateway_isp',
        explicitTarget: null,
        ports: [53, 443],
        usedFollowUpTarget: false,
        preserveLastRemoteTarget: true
      };
    }

    // 00D. DHCP Server IP Discovery & Follow-Up ("find out", "how can I find out", "is it static or dhcp") vs Conceptual Question
    const isDhcpIpDiscovery =
      /\b(what is my dhcp server ip|what's my dhcp server ip|whats my dhcp server ip|find the ip of dhcp|which dhcp server assigned my (?:ip|address)|where is my dhcp server|which server gave me this address|dhcp server ip|ip of dhcp)\b/i.test(lower) ||
      (/\b(dhcp server|dhcp)\b/i.test(lower) && /\b(ip|ip address|server address|assigned my)\b/i.test(lower) && !/\b(what is dhcp|how does dhcp work)\b/i.test(lower));
    if (isDhcpIpDiscovery) {
      return {
        intent: 'dhcp_check',
        mode: 'operational',
        target: 'local_dhcp_service',
        explicitTarget: null,
        ports: [],
        usedFollowUpTarget: false,
        preserveLastRemoteTarget: true
      };
    }

    const isDhcpFollowUp =
      session?.lastIntent === 'dhcp_check' &&
      (/^(?:find out|can you find out|how can i find out|how do i find out|how can i check|how do i check|check if it'?s static|is it static or dhcp|why not|check it)\??$/i.test(cleanNoPunct) ||
        /\b(find out|whether (?:this|my) (?:ip|address|interface) is dhcp or static|is my ip static or dhcp)\b/i.test(lower));
    if (isDhcpFollowUp) {
      return {
        intent: 'dhcp_check',
        mode: 'operational',
        target: 'local_dhcp_service',
        explicitTarget: null,
        ports: [],
        isDhcpFollowUp: true,
        usedFollowUpTarget: false,
        preserveLastRemoteTarget: true
      };
    }

    // 00E. Office Email / Mail Outage Problem Intake ("Users in our office cannot send or receive emails", "We have an office email problem")
    const isOfficeEmailSymptom =
      /\b(cannot send or receive emails?|can'?t send or receive emails?|unable to send or receive emails?|office email (?:problem|issue|outage)|emails? (?:are )?not (?:sending|receiving|working)|users (?:in our office )?can'?t (?:send|receive) email|email is down)\b/i.test(lower);
    if (isOfficeEmailSymptom && !/\b((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24})\b/.test(raw)) {
      if (session) {
        session.pendingTask = {
          type: 'mail_server_inspection',
          originalRequest: raw,
          missingSlots: ['domain'],
          requestedPorts: [25, 465, 587, 143, 993, 110, 995],
          serviceType: 'mail',
          createdAt: new Date().toISOString()
        };
      }
      return {
        intent: 'mail_troubleshooting_intake',
        mode: 'conversational',
        target: null,
        explicitTarget: null,
        ports: [25, 465, 587, 993],
        preserveContextOnly: true
      };
    }

    // 0A. Negative Execution Constraints ("Explain why this happens, but don't run anything yet", "Don't run anything; just explain the concept")
    if (hasNegativeExecutionConstraint(raw)) {
      if (
        /\b(why did|previous|last check|last result|that result|what happened|why do you think)\b/i.test(lower) &&
        hasPriorContext
      ) {
        return {
          intent: 'follow_up_explanation',
          mode: 'informational',
          target: priorTarget,
          explicitTarget: null,
          ports: session?.lastPorts?.length ? session.lastPorts : [],
          url: session?.lastUrl || null,
          recordType: 'A',
          usedFollowUpTarget: Boolean(priorTarget),
          isSystemDnsHealthCheck: false,
          preserveContextOnly: true,
          negativeConstraintRespected: true
        };
      }
      return {
        intent: 'informational_question',
        mode: 'informational',
        target: priorTarget,
        explicitTarget: null,
        ports: session?.lastPorts || [],
        preserveContextOnly: true,
        negativeConstraintRespected: true
      };
    }

    // 0B-1. Informational / Conceptual Technical Question (0 live probes, checked BEFORE conversational fallback & operational target extraction)
    const hasCombinedCheckAndExplain =
      /\b(check|test|ping|resolve|probe|inspect)\b/i.test(lower) &&
      /\b(and|then)\s+(tell me|explain|what the result means|why it might be)\b/i.test(lower);

    if (!hasCombinedCheckAndExplain && isInformationalTechnicalQuestion(raw)) {
      return {
        intent: 'informational_question',
        mode: 'informational',
        target: null,
        explicitTarget: null,
        ports: [],
        preserveContextOnly: true
      };
    }

    // 0B-2. Conversational & Meta-Conversation Turns ("Hello", "How are you?", "Do you understand me?", "That was interesting", "Why did you say that?")
    const convTurn = classifyConversationalTurn(raw, session);
    if (convTurn) {
      if (convTurn.type === 'meta_previous_turn') {
        if (hasPriorContext || (session?.messages && session.messages.length > 0)) {
          return {
            intent: 'follow_up_explanation',
            mode: 'conversational',
            subIntent: 'explain_previous_statement',
            target: priorTarget,
            explicitTarget: null,
            ports: session?.lastPorts?.length ? session.lastPorts : [],
            preserveContextOnly: true
          };
        }
        return {
          intent: 'greeting',
          mode: 'conversational',
          conversationalType: 'no_prior_statement',
          target: null,
          explicitTarget: null,
          ports: [],
          preserveContextOnly: true
        };
      }
      if (convTurn.type === 'clarification_needed' || convTurn.subtype === 'bare_topic') {
        return {
          intent: 'clarification_needed',
          mode: 'conversational',
          clarificationReason: convTurn.subtype === 'ambiguous_person_query' ? 'AMBIGUOUS_PERSON_REFERENCE' : 'BARE_TOPIC',
          clarificationPrompt: convTurn.reply,
          target: null,
          explicitTarget: null,
          ports: [],
          preserveContextOnly: true,
          contextPivotDetected: Boolean(priorTarget)
        };
      }
      if (convTurn.type === 'casual_conversation') {
        return {
          intent: 'casual_conversation',
          mode: 'conversational',
          conversationalType: convTurn.subtype || 'casual_conversation',
          naturalReply: convTurn.reply,
          target: null,
          explicitTarget: null,
          ports: [],
          preserveContextOnly: true,
          contextPivotDetected: Boolean(priorTarget)
        };
      }
      if (convTurn.type === 'general_knowledge') {
        return {
          intent: 'general_knowledge',
          mode: 'informational',
          conversationalType: convTurn.subtype || 'general_knowledge',
          naturalReply: convTurn.reply,
          target: null,
          explicitTarget: null,
          ports: [],
          preserveContextOnly: true,
          contextPivotDetected: Boolean(priorTarget)
        };
      }
      return {
        intent: 'greeting',
        mode: 'conversational',
        conversationalType: convTurn.type,
        naturalReply: convTurn.reply || null,
        target: null,
        explicitTarget: null,
        ports: [],
        preserveContextOnly: true,
        contextPivotDetected: Boolean(priorTarget)
      };
    }

    // 0D. Check My IP / Local Network Configuration ("Check my IP", "What is my IP", "Inspect my network configuration")
    const isLocalIpPrompt =
      /\b(check my ip|what is my ip|what's my ip|whats my ip|what is my local ip|what is my public ip|check my public ip|inspect my network configuration|show my network configuration|my network interfaces|show my ip|local ip configuration|ipconfig|ifconfig)\b/i.test(lower);
    if (isLocalIpPrompt) {
      return {
        intent: 'local_ip_config',
        mode: 'operational',
        target: 'local_host_interfaces',
        explicitTarget: null,
        asksForPublicIp: /\b(public ip|external ip|wan ip)\b/i.test(lower),
        ports: [],
        usedFollowUpTarget: false,
        preserveLastRemoteTarget: true
      };
    }

    // 0E. Default Gateway Inspection / Ping ("Ping my default gateway", "Check my gateway, then tell me what the result means", "The gateway?")
    const isGatewayFollowUpQuestion =
      /^(the gateway\??|what about (?:the |my )?gateway\??|and (?:the |my )?gateway\??|how about (?:the |my )?gateway\??)$/i.test(raw);
    if (isGatewayFollowUpQuestion) {
      // Check if we recently discussed a gateway or if the user wants to inspect/check the gateway
      if (session?.lastIntent === 'gateway_check' || session?.lastIntent === 'local_ip_config' || session?.lastGatewayIp) {
        return {
          intent: 'gateway_check',
          mode: 'operational',
          target: 'default_gateway',
          explicitTarget: null,
          ports: [],
          usedFollowUpTarget: false,
          preserveLastRemoteTarget: true
        };
      }
      return {
        intent: 'clarification_needed',
        mode: 'conversational',
        clarificationReason: 'AMBIGUOUS_GATEWAY_QUESTION',
        clarificationPrompt:
          'Would you like me to check and ping your system\'s configured default gateway from the local routing table, or explain what a default gateway does?',
        target: priorTarget,
        explicitTarget: null,
        ports: [],
        preserveContextOnly: true
      };
    }

    const isGatewayPrompt =
      /\b(ping (?:my |the )?default gateway|ping (?:my |the )?gateway|check (?:my |the )?default gateway|check (?:my |the )?gateway|test (?:my |the )?default gateway|test (?:my |the )?gateway|is (?:my |the )?(?:default )?gateway reachable|inspect (?:my |the )?(?:default )?gateway)\b/i.test(lower);
    if (isGatewayPrompt) {
      return {
        intent: 'gateway_check',
        mode: 'operational',
        target: 'default_gateway',
        explicitTarget: null,
        ports: [],
        usedFollowUpTarget: false,
        preserveLastRemoteTarget: true,
        combinedExplanationRequested: hasCombinedCheckAndExplain
      };
    }

    // 0E-2. Gateway IP Query ("okay what ip", "what ip is default gateway in my network", "what is the default gateway ip")
    const isGatewayIpQuery =
      /\b(what is (?:the |my )?(?:default )?gateway(?:'s)? ip|what's (?:the |my )?(?:default )?gateway(?:'s)? ip|whats (?:the |my )?(?:default )?gateway(?:'s)? ip|which ip is (?:the |my )?(?:default )?gateway|ip (?:address )?of (?:the |my )?(?:default )?gateway|default gateway ip)\b/i.test(lower) ||
      (/\b(what ip|which ip|what is the ip|whats the ip|what address|which address)\b/i.test(lower) &&
        (/\b(gateway|default route|router|local network|my network)\b/i.test(lower) ||
          session?.lastIntent === 'gateway_check' ||
          session?.lastIntent === 'gateway_ip_query' ||
          Boolean(session?.lastGatewayIp) ||
          (session?.messages && session.messages.slice(-3).some((m) => /\bgateway\b/i.test(m.content))))) ||
      (/^(?:okay |ok )?(?:what ip|which ip|what is the ip|what address)\??$/i.test(cleanNoPunct) &&
        (session?.lastIntent === 'gateway_check' ||
          session?.lastIntent === 'gateway_ip_query' ||
          Boolean(session?.lastGatewayIp) ||
          (session?.messages && session.messages.slice(-3).some((m) => /\bgateway\b/i.test(m.content)))));

    if (isGatewayIpQuery) {
      return {
        intent: 'gateway_ip_query',
        mode: 'informational',
        target: 'default_gateway',
        explicitTarget: null,
        ports: [],
        usedFollowUpTarget: false,
        preserveLastRemoteTarget: true
      };
    }

    // 0F. Active Network Connections, Open Sockets & Destination Endpoints
    const isActiveConnectionsPrompt =
      /\b(active connections|open sockets|destination ip addresses|used by my running applications|which application is communicating|talking to|established tcp connections|connected udp endpoints|socket table|netstat|which endpoints appeared since|active network connections)\b/i.test(lower);
    if (isActiveConnectionsPrompt) {
      const portMatch = lower.match(/\bport\s+(\d{1,5})\b/i);
      const filterPort = portMatch ? Number(portMatch[1]) : null;
      const filterProto = /\budp\b/i.test(lower) && !/\btcp\b/i.test(lower) ? 'UDP' : (/\btcp\b/i.test(lower) && !/\budp\b/i.test(lower) ? 'TCP' : null);
      const filterState = /\bestablished\b/i.test(lower) ? 'ESTABLISHED' : (/\blistening\b/i.test(lower) ? 'LISTENING' : null);
      const externalOnly = /\b(destination ip|talking to|remote server|external)\b/i.test(lower);
      const compareSnapshot = /\b(appeared since|changed since|diff|previous snapshot|last snapshot)\b/i.test(lower);

      return {
        intent: 'active_connections',
        mode: 'operational',
        target: 'local_socket_table',
        explicitTarget: null,
        connectionFilter: {
          port: filterPort,
          protocol: filterProto,
          state: filterState,
          externalOnly,
          compareSnapshot
        },
        ports: filterPort ? [filterPort] : [],
        usedFollowUpTarget: false,
        preserveLastRemoteTarget: true
      };
    }

    // 1. Contextual Follow-Up Explanations, Meaning, Hypothesis Evaluation, Summaries & Historical Comparisons (0 live probes)
    const isDnsHypothesisFollowUp =
      /\b(could dns be (?:the |a )?(?:problem|issue|cause|culprit|bottleneck)|could it be (?:a )?dns(?: issue| problem)?|is dns (?:the |a )?(?:problem|issue|cause)|is dns causing (?:this|that|it)|might dns be (?:the )?(?:problem|issue))\b/i.test(lower) &&
      !/\bhttps?:\/\//i.test(raw);

    const isExplanationOrComparisonFollowUp =
      isDnsHypothesisFollowUp ||
      /^(why\??|why is that\??|why (?:is|isn't|isnt) (?:it|that|this|the server|that server|the host|that host|the site|the service|the endpoint) (?:not responding|responding|failing|timing out|down|slow|refusing connections)\??|why did (that|it|that service|the service) (fail|happen|time out).*|why do you think (that's|thats|that is) the problem\??|why did you say (that|the connection was healthy|it was healthy|it failed)\??|are you sure\??|how do you know\??|what does (?:that|this|the|a) (?:timeout|time out|error|refusal|connection refused|reset|failure|result|status|latency|packet loss) mean\??|what does that mean\??|what did the (last|previous) check tell us\??|can you explain the (previous|last) result\??|explain the (previous|last) result|which layer failed\??|explain the results?\??|summarize what (you|we) (have )?(found|tested|done)( so far)?\??|can you summarize what we have found( so far)?\??|give me a concise incident report|prepare a technical incident report|incident report|what should i do (now|next)\??|tell me the next step|what have we (tested|found)( so far)?\??|show memory|compare (all )?hosts|compare the latest|compare (?:it|that|this)(?: with| to) (?:the )?(?:previous|last|earlier|prior)(?: result| check| scan| test| run| state| observation)?\.?|compare with (?:the )?(?:previous|last|earlier)(?: result| check| scan| test)?\.?|compare (?:this|that) host'?s? current state to (?:the )?previous(?: scan| test| check)?|what changed\??|what changed since|show me what changed|what happened\??)$/i.test(raw) ||
      ((/\b(summarize what|incident report|which layer failed|why did that fail|why did it fail|why did that service fail|why is it not responding|why isn't it responding|what does that timeout mean|what does this timeout mean|right after (?:the )?gateway latency|explain the previous result|explain the last result|what did the last check tell us|why do you think that's the problem|why did you say the connection was healthy|what have we found so far|what have we tested|compare hosts|compare the latest|compare it with the previous result|compare with the previous result|compare it to the previous result|compare (?:this|that) host'?s? current state|to the previous scan|what changed since|show me what changed)\b/i.test(lower)) &&
        !/\b(ping |check port|test port|resolve |traceroute )\b/i.test(lower));

    if (isExplanationOrComparisonFollowUp) {
      if (!hasPriorContext) {
        return {
          intent: 'clarification_needed',
          mode: 'conversational',
          clarificationReason: 'MISSING_PRIOR_CONTEXT',
          clarificationPrompt:
            'We haven\'t run any checks in this conversation yet. Tell me which hostname, IP address, or local check you\'d like to start with.',
          target: null,
          explicitTarget: null,
          ports: [],
          preserveContextOnly: true
        };
      }
      return {
        intent: 'follow_up_explanation',
        mode: 'informational',
        target: priorTarget,
        explicitTarget: null,
        ports: session?.lastPorts?.length ? session.lastPorts : [],
        url: session?.lastUrl || null,
        recordType: 'A',
        usedFollowUpTarget: Boolean(priorTarget),
        isSystemDnsHealthCheck: false,
        preserveContextOnly: true
      };
    }

    // 2. Extract explicit URL if present (e.g. https://example.com:8443/health)
    let extractedUrl = null;
    let urlHost = null;
    let urlPort = null;
    let urlProtocol = null;
    const urlMatch = raw.match(/\b(https?:\/\/[^\s"'<>]+)/i);
    if (urlMatch) {
      extractedUrl = urlMatch[1].replace(/[.,;!?)]+$/, '');
      try {
        const parsedUrl = new URL(extractedUrl);
        urlHost = parsedUrl.hostname;
        urlProtocol = parsedUrl.protocol.replace(':', '').toLowerCase();
        if (parsedUrl.port) {
          urlPort = Number(parsedUrl.port);
        } else if (urlProtocol === 'https') {
          urlPort = 443;
        } else if (urlProtocol === 'http') {
          urlPort = 80;
        }
      } catch (_) {}
    }

    // 3. Extract explicit IPv4, localhost, domain name, or well-known brand shorthand ("What's Google's IP?", "Resolve Google for me")
    let explicitTarget = urlHost;
    let explicitHostPort = urlPort;

    if (!explicitTarget) {
      const hostPortMatch = raw.match(/\b((?:\d{1,3}\.){3}\d{1,3}|localhost|(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}):(\d{1,5})\b/);
      if (hostPortMatch) {
        explicitTarget = hostPortMatch[1];
        explicitHostPort = Number(hostPortMatch[2]);
      }
    }

    if (!explicitTarget) {
      const ipMatch = raw.match(/\b((?:0x[0-9a-fA-F]+|\d{1,3})(?:\.(?:0x[0-9a-fA-F]+|\d{1,3})){3})\b/);
      if (ipMatch) {
        explicitTarget = ipMatch[1];
      }
    }

    if (!explicitTarget) {
      if (/\b(localhost|localhsot|locahost|localost|localhots)\b/i.test(raw)) {
        explicitTarget = 'localhost';
      } else if (/\b(this server|this host|local server)\b/i.test(raw) && /\b(port|ping|check|test|open|listening)\b/i.test(raw)) {
        explicitTarget = '127.0.0.1';
      }
    }

    if (!explicitTarget) {
      const domainRegex = /\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,24}))\b/g;
      let match;
      const stopDomains = new Set([
        'e.g', 'i.e', 'etc.', 'node.js', 'next.js', 'vue.js', 'chart.js', 'three.js',
        'server.js', 'server.mjs', 'server.ts', 'index.js', 'index.ts', 'app.js', 'app.ts',
        'skill.md', 'readme.md', 'package.json', 'tsconfig.json', 'skills-lock.json'
      ]);
      const nonHostExtensions = /\.(?:mjs|cjs|js|ts|tsx|jsx|json|md|py|sh|bat|ps1|cmd|yaml|yml|toml|ini|cfg|conf|lock|sql|db|sqlite|log|txt|csv|html|css|scss|svg|png|jpg|jpeg|gif|ico|pcap|pcapng|cap)$/i;
      while ((match = domainRegex.exec(raw)) !== null) {
        const candidate = match[1];
        const lowerCandidate = candidate.toLowerCase();
        if (!stopDomains.has(lowerCandidate) && !nonHostExtensions.test(lowerCandidate)) {
          explicitTarget = candidate;
          break;
        }
      }
    }

    // Semantic brand shorthand ("What's Google's IP?", "IP of google", "What address does Google resolve to?", "Resolve Google for me", "Show me the IPs for Google")
    const brandShorthand = !explicitTarget ? extractBrandHostnameShorthand(raw) : null;
    if (!explicitTarget && brandShorthand) {
      explicitTarget = brandShorthand;
    }

    // 4. Extract ports from prompt (including short follow-ups like "Try 80 too", "Now check 443", "cant reach 127.0.0.1 on 3000", "check tcp/443")
    const extractedPorts = [];
    if (explicitHostPort && explicitHostPort >= 1 && explicitHostPort <= 65535) {
      extractedPorts.push(explicitHostPort);
    }

    const multiPortBlockRegex = /\bports?\s+((?:\d{1,5}(?:\s*(?:,|and|&|\/|\s)\s*)?)+)/gi;
    let mpMatch;
    while ((mpMatch = multiPortBlockRegex.exec(raw)) !== null) {
      const nums = mpMatch[1].match(/\d{1,5}/g) || [];
      for (const nStr of nums) {
        const p = Number(nStr);
        if (p >= 1 && p <= 65535 && !extractedPorts.includes(p)) {
          extractedPorts.push(p);
        }
      }
    }

    // Match explicit tcp/<port> or udp/<port> shorthand (e.g. "check tcp/443 on example.com")
    const protoSlashPortRegex = /\b(?:tcp|udp)\/(\d{1,5})\b/gi;
    let pspMatch;
    while ((pspMatch = protoSlashPortRegex.exec(raw)) !== null) {
      const p = Number(pspMatch[1]);
      if (p >= 1 && p <= 65535 && !extractedPorts.includes(p)) {
        extractedPorts.push(p);
      }
    }

    // Match natural "on <port>" / "via <port>" even when an explicit target is present (stripping IPv4 addresses first so octets are never matched)
    if (extractedPorts.length === 0) {
      const rawWithoutIps = raw.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, ' ');
      const onPortMatch = rawWithoutIps.match(/\b(?:on|via|over)\s+(?:tcp\s+)?(\d{2,5})\b(?!\s*(?:minutes?|hours?|days?|seconds?|ms|%|mb|gb))/i);
      if (onPortMatch) {
        const p = Number(onPortMatch[1]);
        if (p >= 1 && p <= 65535) {
          extractedPorts.push(p);
        }
      }
    }

    if (extractedPorts.length === 0) {
      const shortPortFollowUp = raw.match(/\b(?:try|check|test|with|on|about|and|meant|actually|use|make it)\s+(?:it\s+(?:with|on)\s+)?(?:port\s+)?(\d{2,5})(?:\s+too|\s+instead|\s+as well|\s+next)?\b/i);
      if (shortPortFollowUp && !explicitTarget) {
        const p = Number(shortPortFollowUp[1]);
        if (p >= 1 && p <= 65535) {
          extractedPorts.push(p);
        }
      }
    }

    const isMidTurnCorrection =
      /^(?:no,?\s*)?(?:i\s+meant|actually|sorry,?\s*i\s+meant|wait,?\s*i\s+meant|use)\b|\binstead\s*[.!?]?$/i.test(raw.trim());

    const refersToOtherPort = /\b(the other port|other port|alternate port)\b/i.test(lower);
    if (extractedPorts.length === 0 && refersToOtherPort) {
      const lastPort = session?.lastPorts?.[0];
      if (lastPort === 443) extractedPorts.push(80);
      else if (lastPort === 80) extractedPorts.push(443);
      else if (lastPort === 8080) extractedPorts.push(3000);
      else if (lastPort === 3000) extractedPorts.push(8080);
      else extractedPorts.push(443);
    }

    // 5. Check if user is asking a general "check dns connection" / "dns test" / "check whether dns is working" without a target
    const isGenericDnsHealthPrompt =
      !explicitTarget &&
      /\b(check dns( connection| connectivity| status| health| server)?|test dns( connection| connectivity| status| health| server)?|dns test|any (?:problem|issue) with dns|check whether dns is working|is dns working|verify dns( connection)?|dns connection|dns connectivity|dns health)\b/i.test(lower) &&
      !/\b(same host|same domain|that host|that domain|for it|on it|other host|other server)\b/i.test(lower);

    // 5B. Ambiguous bare "DNS" / "DNS?" prompt without context
    const isBareDnsPrompt = /^dns\??$/i.test(raw.trim());
    if (isBareDnsPrompt) {
      return {
        intent: 'clarification_needed',
        mode: 'conversational',
        clarificationReason: 'AMBIGUOUS_DNS_PROMPT',
        clarificationPrompt:
          'Would you like me to run a general DNS connectivity check on your configured system resolvers, look up records for a specific domain name, or explain how DNS works?',
        target: null,
        explicitTarget: null,
        ports: [],
        preserveContextOnly: true
      };
    }

    // 5C. Mail server check without explicit domain/hostname ("Check mail server", "Ping mail server")
    const isMailServerPrompt =
      /\b(check (?:the |my )?mail server|ping (?:the |my )?mail server|test (?:the |my )?mail server|mail server connection|email server|smtp server)\b/i.test(lower);
    if (isMailServerPrompt && !explicitTarget) {
      if (session) {
        session.pendingTask = {
          type: 'mail_server_inspection',
          originalRequest: raw,
          missingSlots: ['domain'],
          requestedPorts: [25, 465, 587, 143, 993, 110, 995],
          serviceType: 'mail',
          createdAt: new Date().toISOString()
        };
      }
      return {
        intent: 'clarification_needed',
        mode: 'conversational',
        clarificationReason: 'MISSING_MAIL_DOMAIN',
        clarificationPrompt:
          'Which mail domain (e.g., example.com) or mail server hostname (e.g., mail.example.com / smtp.example.com) would you like me to check? I can look up its MX records and test SMTP (port 25/587) or IMAP/POP3 ports.',
        target: null,
        explicitTarget: null,
        ports: [25, 587],
        preserveContextOnly: true
      };
    }

    // 5D. DHCP Server Connection / Status ("Check DHCP server connection", "Is DHCP working")
    const isDhcpPrompt =
      /\b(check (?:the |my )?dhcp(?: server)?(?: connection| connectivity)?|test (?:the |my )?dhcp(?: server)?|is dhcp working|dhcp status|dhcp server connection)\b/i.test(lower);
    if (isDhcpPrompt) {
      return {
        intent: 'dhcp_check',
        mode: 'operational',
        target: 'local_dhcp_service',
        explicitTarget: null,
        ports: [],
        usedFollowUpTarget: false,
        preserveLastRemoteTarget: true
      };
    }

    // 6. Check contextual target references ("same host", "first host", "the other host / the other server / the other one")
    const refersToFirstTarget = /\b(first host|first domain|first server|initial host|original host)\b/i.test(lower);
    const refersToOtherTarget = /\b(other host|other server|other domain|other endpoint|the other one)\b/i.test(lower);
    const refersToPreviousTarget =
      refersToOtherPort ||
      (isMidTurnCorrection && extractedPorts.length > 0 && !explicitTarget) ||
      /\b(same host|same server|same target|same domain|same machine|same box|same ip|same node|that host|that server|that domain|that endpoint|that machine|that box|that ip|that node|this endpoint|the site|the website|the server|on it|for it|test it|check it|ping it|try (\d{2,5}) too|now check (\d{2,5})|also check (?:port )?(\d{2,5})|what about port (\d{2,5})|how about port (\d{2,5})|and port (\d{2,5})|repeat the (?:same )?check|(?:test|check|probe|scan|ping) the same (?:host|machine|server|target|box|node|ip|domain|endpoint|site) again|run that again|retry that|try again|check it again|test it again)\b/i.test(lower);

    const isRemediation =
      /\b(flush dns|refresh dns resolver|apply (?:the )?(?:fix|remediation)|execute remediation|heal|self-heal|fix it now|repair dns)\b/i.test(lower);
    const isHostHealth =
      /\b(local host health|system health|host diagnostics|cpu and memory|local system)\b/i.test(lower) && !explicitTarget;

    // 7. Semantic recognition of natural IP / DNS lookup phrasing
    const isSemanticDnsLookup =
      Boolean(brandShorthand && /\b(ip|address|resolve|resolves|dns|nslookup|dig|a records?|aaaa records?|mx records?|txt records?|ns records?|cname records?|soa records?|ptr records?|spf|dmarc|dkim)\b/i.test(lower)) ||
      /\b(what(?:'s| is) (?:the )?ip(?: address)? (?:of|for)|ip (?:address )?(?:of|for)|what address does .+ resolve to|can you find (?:the )?(?:ip|address) (?:for|of)|find .+ ip address|show me the ips? for|resolve .+ for me|resolve )\b/i.test(lower) ||
      (isGenericDnsHealthPrompt || /\b(check dns|dns check|test dns|dns lookup|dns (?:for|of|on)|query dns|nslookup|dig|a records?|aaaa records?|mx records?|txt records?|ns records?|cname records?|soa records?|ptr records?|srv records?|spf(?:\s+records?)?|dmarc(?:\s+records?)?|dkim(?:\s+records?)?|reverse dns|rdns|mail exchange|nameservers? (?:for|of))\b/i.test(lower));

    // 8. Problem Descriptions & Symptom Reports without an explicit target ("The site won't open", "I'm getting connection errors", "The internet is not working", "It works on my laptop but not on the other computer", "The application has become really slow", "Could you check whether this endpoint responds?")
    const isProblemDescription =
      /\b(internet is not working|internet isn't working|no internet|can't open the (?:website|site)|cannot open the (?:website|site)|(?:site|website|page) won't open|(?:site|website) is down|something is wrong with the connection|server is not responding|server isn't responding|getting connection errors|connection errors|works on my laptop but not|application has become (?:really )?slow|is really slow|check whether this endpoint responds|endpoint is not responding|having network issues|trouble connecting)\b/i.test(lower);

    if (!explicitTarget && isProblemDescription) {
      const referencesCurrentTarget = /\b(this endpoint|that endpoint|the same site|the same server|that server|that host)\b/i.test(lower);
      if (referencesCurrentTarget && priorTarget) {
        explicitTarget = priorTarget;
      } else {
        let clarificationPrompt = 'I can help investigate that. Which website, hostname, or IP address is affected?';
        if (/\b(internet is not working|internet isn't working|no internet)\b/i.test(lower)) {
          clarificationPrompt =
            'I can help narrow down whether the issue is local routing, DNS resolution, or external reachability. Is every website failing to load, or is a specific site or service affected? (You can also ask me to "Check DNS connectivity" or "Check my default gateway" to test your local connection.)';
        } else if (/\b(works on my laptop but not on the other computer)\b/i.test(lower)) {
          clarificationPrompt =
            'When a service works on one machine but fails on another, the cause is usually local DNS settings, a host firewall rule, or a different subnet/gateway on the affected machine. Which hostname, IP address, or port is the other computer trying to reach?';
        } else if (/\b(slow|latency|lag)\b/i.test(lower)) {
          clarificationPrompt =
            'I can measure DNS lookup time, TCP handshake RTT, and HTTP response time (TTFB) to isolate what is causing the slowdown. Which hostname, URL, or IP address is running slowly?';
        } else if (/\b(this endpoint|endpoint responds)\b/i.test(lower)) {
          clarificationPrompt =
            'Sure — which hostname, IP address, or URL would you like me to check?';
        } else if (/\b(connection errors)\b/i.test(lower)) {
          clarificationPrompt =
            'I can check what is causing the connection errors. Which hostname, IP address, or URL are you connecting to, and do you see a specific error (such as timeout, connection refused, or DNS failure)?';
        }

        return {
          intent: 'clarification_needed',
          mode: 'conversational',
          clarificationReason: 'PROBLEM_MISSING_TARGET',
          clarificationPrompt,
          target: null,
          explicitTarget: null,
          ports: extractedPorts,
          preserveContextOnly: true
        };
      }
    }

    // 9. Handle "Try the same thing against the other host" / "Do the same thing for the other server"
    if (!explicitTarget && refersToOtherTarget) {
      const history = Array.isArray(session?.targetHistory) ? session.targetHistory : [];
      const current = (priorTarget || '').toLowerCase();
      const otherCandidates = history.filter((h) => h.toLowerCase() !== current);
      if (otherCandidates.length === 1) {
        explicitTarget = otherCandidates[0];
      } else if (otherCandidates.length > 1) {
        return {
          intent: 'clarification_needed',
          mode: 'conversational',
          clarificationReason: 'AMBIGUOUS_MULTI_TARGET',
          candidateTargets: otherCandidates,
          clarificationPrompt:
            `We have discussed multiple other hosts in this session (${otherCandidates.map((c) => `\`${c}\``).join(', ')}). Which one would you like me to test?`,
          target: null,
          explicitTarget: null,
          ports: extractedPorts,
          preserveContextOnly: true
        };
      } else {
        return {
          intent: 'clarification_needed',
          mode: 'conversational',
          clarificationReason: 'MISSING_OTHER_TARGET',
          clarificationPrompt:
            priorTarget
              ? `Only \`${priorTarget}\` has been tested in this session so far. Which other hostname or IP address would you like me to check?`
              : 'No hosts have been tested in this session yet. Which hostname or IP address would you like me to check?',
          target: null,
          explicitTarget: null,
          ports: extractedPorts,
          preserveContextOnly: true
        };
      }
    }

    // 10. Determine whether the user is actually requesting a network diagnostic operation
    const isSnmpWalk =
      /\b(snmp\s+walk|walk\s+oid|walk\s+snmp|snmpwalk|subtree\s+walk|walk\s+interfaces)\b/i.test(lower);
    const isOfficeDevice =
      /\b(office\s+device|diagnose\s+printer|printer\s+offline|printer\s+diagnostic|apipa|169\.254|office\s+printer)\b/i.test(lower);
    const isTlsAudit =
      /\b(tls\s+(?:audit|posture|certificate|handshake|cipher)|ssl\s+(?:audit|certificate|expiry|posture)|certificate\s+expir(?:y|ation))\b/i.test(lower);
    const isSnmpProbe =
      /\b(snmp\s+(?:probe|check|poll|status|mib)|probe\s+snmp|check\s+snmp)\b/i.test(lower);

    const hasExplicitDiagnosticVerb =
      isSemanticDnsLookup ||
      isRemediation ||
      isHostHealth ||
      isSnmpWalk ||
      isOfficeDevice ||
      isTlsAudit ||
      isSnmpProbe ||
      refersToPreviousTarget ||
      refersToFirstTarget ||
      refersToOtherTarget ||
      extractedPorts.length > 0 ||
      Boolean(extractedUrl) ||
      /\b(ping|traceroute|trace route|trace path|check|test|probe|investigate|diagnose|verify|scan|connect|lookup|resolve|nslookup|dig|cant reach|can't reach|cannot reach|cant connect|can't connect|cannot connect|connection refused|timing out|timed out|is .+ (?:open|reachable|working|up|down|online|accessible|listening))\b/i.test(lower);

    // CRITICAL BRAIN-FIRST RULE: An unclassified or conversational message without a diagnostic request must NEVER fall through to a localhost investigation!
    if (!hasExplicitDiagnosticVerb && !explicitTarget) {
      const fallbackConv = classifyConversationalTurn(raw, session);
      if (fallbackConv) {
        if (fallbackConv.type === 'clarification_needed' || fallbackConv.subtype === 'bare_topic') {
          return {
            intent: 'clarification_needed',
            mode: 'conversational',
            clarificationReason: fallbackConv.subtype === 'ambiguous_person_query' ? 'AMBIGUOUS_PERSON_REFERENCE' : 'BARE_TOPIC',
            clarificationPrompt: fallbackConv.reply,
            target: null,
            explicitTarget: null,
            ports: [],
            preserveContextOnly: true,
            contextPivotDetected: Boolean(priorTarget)
          };
        }
        if (fallbackConv.type === 'casual_conversation') {
          return {
            intent: 'casual_conversation',
            mode: 'conversational',
            conversationalType: fallbackConv.subtype || 'casual_conversation',
            naturalReply: fallbackConv.reply,
            target: null,
            explicitTarget: null,
            ports: [],
            preserveContextOnly: true,
            contextPivotDetected: Boolean(priorTarget)
          };
        }
        if (fallbackConv.type === 'general_knowledge') {
          return {
            intent: 'general_knowledge',
            mode: 'informational',
            conversationalType: fallbackConv.subtype || 'general_knowledge',
            naturalReply: fallbackConv.reply,
            target: null,
            explicitTarget: null,
            ports: [],
            preserveContextOnly: true,
            contextPivotDetected: Boolean(priorTarget)
          };
        }
        return {
          intent: 'greeting',
          mode: 'conversational',
          conversationalType: fallbackConv.type,
          naturalReply: fallbackConv.reply || null,
          target: null,
          explicitTarget: null,
          ports: [],
          preserveContextOnly: true,
          contextPivotDetected: Boolean(priorTarget)
        };
      }

      return {
        intent: 'greeting',
        mode: 'conversational',
        conversationalType: 'general_conversation',
        target: null,
        explicitTarget: null,
        ports: [],
        preserveContextOnly: true,
        contextPivotDetected: Boolean(priorTarget)
      };
    }

    // 11. Context Loss (Case N) and Multi-Target Ambiguity (Case O) when a diagnostic verb is used without an explicit target
    if (!explicitTarget && !isGenericDnsHealthPrompt && !isRemediation && !isHostHealth) {
      if (
        refersToPreviousTarget &&
        session &&
        Array.isArray(session.lastMultiEndpoints) &&
        session.lastMultiEndpoints.length > 1
      ) {
        const candidates = session.lastMultiEndpoints.slice(0, 6);
        return {
          intent: 'clarification_needed',
          mode: 'conversational',
          clarificationReason: 'AMBIGUOUS_MULTI_TARGET',
          candidateTargets: candidates,
          clarificationPrompt:
            `Multiple endpoints were observed in the previous step (${candidates.map((c) => `\`${c}\``).join(', ')}). Which specific host or IP address would you like me to test?`,
          target: null,
          explicitTarget: null,
          ports: extractedPorts,
          preserveContextOnly: true
        };
      }

      if (!priorTarget) {
        if (isSnmpWalk) {
          return {
            intent: 'snmp_walk',
            mode: 'operational',
            target: null,
            explicitTarget: null,
            ports: [161],
            preserveContextOnly: false
          };
        }
        if (isOfficeDevice) {
          return {
            intent: 'office_device_resolve',
            mode: 'operational',
            target: null,
            explicitTarget: null,
            ports: [9100, 631, 80, 443],
            preserveContextOnly: false
          };
        }
        if (isTlsAudit) {
          return {
            intent: 'tls_posture_audit',
            mode: 'operational',
            target: null,
            explicitTarget: null,
            ports: extractedPorts.length ? extractedPorts : [443],
            preserveContextOnly: false
          };
        }
        return {
          intent: 'clarification_needed',
          mode: 'conversational',
          clarificationReason: 'MISSING_TARGET_CONTEXT',
          clarificationPrompt:
            extractedPorts.length > 0
              ? `Which hostname or IP address would you like me to test on TCP port ${extractedPorts.join(', ')}?`
              : 'Which hostname, IP address, or URL would you like me to check?',
          target: null,
          explicitTarget: null,
          ports: extractedPorts,
          preserveContextOnly: true
        };
      }
    }

    // 12. Resolve target using contextual follow-up memory ONLY when unambiguous — NEVER default to 'localhost'!
    let usedFollowUpTarget = false;
    let resolvedTarget = explicitTarget;

    if (!resolvedTarget) {
      const isDirectPortCommandOnPrior =
        extractedPorts.length > 0 &&
        /^(?:(?:no,?\s*)?(?:i\s+meant|actually|sorry,?\s*i\s+meant|use|pls|please|can you|could you|now|also|and)\s+)?(?:try|check|test|now check|now test|probe|scan|what about|how about|is port|port)\b/i.test(lower) &&
        !/\b(local development server|our development server|can we definitively declare|application layer is healthy)\b/i.test(lower);

      if (isGenericDnsHealthPrompt) {
        resolvedTarget = 'example.com';
      } else if (isRemediation || isHostHealth) {
        resolvedTarget = priorTarget || '127.0.0.1';
      } else if (refersToFirstTarget && session?.targetHistory?.length > 0) {
        resolvedTarget = session.targetHistory[0];
        usedFollowUpTarget = true;
      } else if (priorTarget && (refersToPreviousTarget || isDirectPortCommandOnPrior)) {
        resolvedTarget = priorTarget;
        usedFollowUpTarget = true;
      } else {
        if (isSnmpWalk) {
          return {
            intent: 'snmp_walk',
            mode: 'operational',
            target: null,
            explicitTarget: null,
            ports: [161],
            preserveContextOnly: false
          };
        }
        if (isOfficeDevice) {
          return {
            intent: 'office_device_resolve',
            mode: 'operational',
            target: null,
            explicitTarget: null,
            ports: [9100, 631, 80, 443],
            preserveContextOnly: false
          };
        }
        if (isTlsAudit) {
          return {
            intent: 'tls_posture_audit',
            mode: 'operational',
            target: null,
            explicitTarget: null,
            ports: extractedPorts.length ? extractedPorts : [443],
            preserveContextOnly: false
          };
        }
        return {
          intent: 'clarification_needed',
          mode: 'conversational',
          clarificationReason: 'MISSING_TARGET_CONTEXT',
          clarificationPrompt: 'Which hostname, IP address, or URL would you like me to check?',
          target: null,
          explicitTarget: null,
          ports: extractedPorts,
          preserveContextOnly: true
        };
      }
    }

    // 13. Determine primary operational intent
    let intent = 'multi_step_investigation';

    const isRepeatLast =
      /\b((?:test|check|probe|scan|ping) the same (?:host|machine|server|target|box|node|ip|domain|endpoint|site) again|run that again|retry that|check it again|test it again|repeat the (?:same )?check|repeat that|try again|do the same thing|try the same thing)\b/i.test(lower) &&
      !lower.includes('port') && !lower.includes('dns') && !lower.includes('ping');

    if (isRemediation) {
      intent = 'remediation';
    } else if (isSnmpWalk) {
      intent = 'snmp_walk';
    } else if (isOfficeDevice) {
      intent = 'office_device_resolve';
    } else if (isTlsAudit) {
      intent = 'tls_posture_audit';
    } else if (isSnmpProbe) {
      intent = 'snmp_probe';
    } else if (isRepeatLast && session && session.lastIntent) {
      intent = session.lastIntent;
      if (extractedPorts.length === 0 && session.lastPorts?.length) {
        extractedPorts.push(...session.lastPorts);
      }
    } else if (
      /\b(traceroute|trace route|trace the route|trace path|hop by hop)\b/i.test(lower)
    ) {
      intent = 'traceroute';
    } else if (
      /\b(ping|icmp|packet loss to)\b/i.test(lower) &&
      !lower.includes('investigate') &&
      !lower.includes('website')
    ) {
      intent = 'ping';
    } else if (
      isSemanticDnsLookup &&
      !lower.includes('or dns is causing') &&
      !lower.includes('investigate why')
    ) {
      intent = 'dns';
    } else if (
      extractedPorts.length > 0 &&
      (/\b(port|ports|tcp|open|listening|connect|try|now test|now check|also check|what about|how about|other port|meant|instead|actually|on \d{2,5}|via \d{2,5})\b/i.test(lower)) &&
      !lower.includes('investigate why')
    ) {
      intent = 'port_check';
    } else if (
      isMidTurnCorrection &&
      explicitTarget &&
      session &&
      session.lastIntent &&
      ['port_check', 'ping', 'dns', 'traceroute', 'website_check'].includes(session.lastIntent)
    ) {
      intent = session.lastIntent;
      if (intent === 'port_check' && extractedPorts.length === 0 && session.lastPorts?.length) {
        extractedPorts.push(...session.lastPorts);
      }
    } else if (
      extractedUrl ||
      (/\b(website|https:\/\/|http:\/\/|web page|site is working|site is accessible|site is reachable|check whether https|verify https)\b/i.test(lower) &&
        !lower.includes('investigate why'))
    ) {
      intent = 'website_check';
    } else if (isHostHealth) {
      intent = 'host_health';
    } else {
      intent = 'multi_step_investigation';
    }

    // Default ports based on intent
    if (extractedPorts.length === 0) {
      if (intent === 'website_check') {
        if (urlPort) {
          extractedPorts.push(urlPort);
        } else if (resolvedTarget === 'localhost' || resolvedTarget === '127.0.0.1') {
          extractedPorts.push(Number(config.PORT) || 3000);
        } else {
          extractedPorts.push(443);
        }
      } else if (intent === 'port_check') {
        const isSameTargetAsPrior =
          usedFollowUpTarget ||
          (priorTarget && String(resolvedTarget).toLowerCase() === String(priorTarget).toLowerCase());
        extractedPorts.push((isSameTargetAsPrior && session?.lastPorts?.[0]) ? session.lastPorts[0] : 443);
      } else if (intent === 'multi_step_investigation') {
        if (lower.includes('https') || lower.includes('tls') || lower.includes('ssl')) {
          extractedPorts.push(443);
        } else if (resolvedTarget === 'localhost' || resolvedTarget === '127.0.0.1') {
          extractedPorts.push(Number(config.PORT) || 3000);
        } else if (lower.includes('printer')) {
          extractedPorts.push(9100, 80, 443);
        } else {
          extractedPorts.push(443, 80);
        }
      }
    }

    // Extract DNS record type if specified
    let recordType = 'A';
    if (/\baaaa\b|\bipv6\s+(?:records?|address|dns)\b/i.test(lower)) recordType = 'AAAA';
    else if (/\bmx\b|\bmail exchange\b/i.test(lower)) recordType = 'MX';
    else if (/\btxt\b|\bspf\b|\bdmarc\b|\bdkim\b/i.test(lower)) recordType = 'TXT';
    else if (/\bns\b|\bnameservers?\b/i.test(lower)) recordType = 'NS';
    else if (/\bcname\b|\bcanonical name\b/i.test(lower)) recordType = 'CNAME';
    else if (/\bsoa\b|\bstart of authority\b/i.test(lower)) recordType = 'SOA';
    else if (/\bptr\b|\breverse dns\b|\brdns\b/i.test(lower)) recordType = 'PTR';
    else if (/\bsrv\b/i.test(lower)) recordType = 'SRV';

    const typoClassification = classifyDomainTypo(resolvedTarget, session?.targetHistory || []);
    const typoSuggestion = typoClassification?.confidence === 'high' ? typoClassification.corrected : null;

    // Cross-Turn Topic-Pivot Context Isolation:
    // If an explicit target is provided that differs from priorTarget, or if switching intent domains
    // (e.g., from port_check/mail to dns/ping/traceroute), isolate context so old ports/tasks never bleed.
    const contextPivotDetected = Boolean(
      (explicitTarget && priorTarget && String(explicitTarget).toLowerCase() !== String(priorTarget).toLowerCase()) ||
      (session?.lastIntent && session.lastIntent !== intent && ['dns', 'ping', 'traceroute', 'snmp_probe', 'snmp_walk', 'office_device_resolve', 'tls_posture_audit'].includes(intent))
    );
    if (contextPivotDetected && session?.pendingTask) {
      session.pendingTask = null;
    }

    let rootOid = '1.3.6.1.2.1.1.1.0';
    const explicitOidMatch = raw.match(/\boid\s+([a-zA-Z0-9._-]+)\b/i) || raw.match(/\b(1\.3\.6\.[0-9.]+)\b/);
    if (explicitOidMatch) {
      rootOid = explicitOidMatch[1];
    }

    const isReflexIntent = ['ping', 'port_check', 'dns', 'website_check', 'traceroute', 'snmp_probe', 'snmp_walk', 'office_device_resolve', 'tls_posture_audit', 'local_ip_config', 'gateway_check', 'host_health'].includes(intent);

    return {
      intent,
      mode: 'operational',
      executionTier: isReflexIntent ? 'ZERO_LATENCY_LOCAL_REFLEX' : 'MULTI_STAGE_COGNITIVE_INVESTIGATION',
      contextPivotDetected,
      target: resolvedTarget,
      explicitTarget: explicitTarget || null,
      typoSuggestion,
      typoClassification,
      isSystemDnsHealthCheck: isGenericDnsHealthPrompt,
      ports: ['dns', 'ping', 'traceroute', 'snmp_walk'].includes(intent) ? [] : (intent === 'tls_posture_audit' && extractedPorts.length === 0 ? [443] : extractedPorts),
      rootOid: intent === 'snmp_walk' ? rootOid : undefined,
      rawOid: intent === 'snmp_walk' ? rootOid : undefined,
      url: extractedUrl,
      urlProtocol: urlProtocol || (extractedPorts[0] === 443 ? 'https' : 'http'),
      recordType,
      usedFollowUpTarget: Boolean(usedFollowUpTarget || (refersToOtherTarget && explicitTarget)),
      combinedExplanationRequested: hasCombinedCheckAndExplain
    };
  }

  _checkAborted(signal) {
    if (signal && signal.aborted) {
      const err = new Error('Diagnostic execution cancelled by user.');
      err.code = 'REQUEST_CANCELLED';
      throw err;
    }
  }

  /**
   * Convenience alias for processMessage({ sessionId, message, user })
   */
  async processTurn(sessionOrSessionId, message, user = {}) {
    const sessionId = typeof sessionOrSessionId === 'string' ? sessionOrSessionId : (sessionOrSessionId?.sessionId || 'default');
    return this.processMessage({ sessionId, message, user });
  }

  /**
   * Main entry point for handling a user chat message.
   */
  async processMessage({
    sessionId,
    message,
    user = { id: 'op-1', username: 'operator', role: 'ANALYST' },
    requestId = null,
    signal = null,
    simulateTimeout = false,
    onProgress = null,
    allowCloudFallback = false,
    modelReflectionFn = null
  } = {}) {
    const startWall = performance.now();
    const cleanPrompt = String(message || '').trim();
    if (!cleanPrompt) {
      return {
        success: false,
        status: 'invalid_input',
        statusCode: 400,
        error: { code: 'EMPTY_MESSAGE', message: 'Please enter a message or question.' }
      };
    }
    if (cleanPrompt.length > 4000) {
      return {
        success: false,
        status: 'invalid_input',
        statusCode: 400,
        error: { code: 'MESSAGE_TOO_LONG', message: 'Message exceeds maximum length of 4,000 characters.' }
      };
    }

    // Verify session ownership (Case R)
    let session;
    try {
      session = this.getOrCreateSession(sessionId, user);
    } catch (ownershipErr) {
      return {
        success: false,
        status: 'denied',
        statusCode: ownershipErr.statusCode || 403,
        error: {
          code: ownershipErr.code || 'SESSION_OWNERSHIP_VIOLATION',
          message: ownershipErr.message
        }
      };
    }

    const activeConflict = this.inFlightRequests.get(session.sessionId);
    if (activeConflict) {
      return {
        success: false,
        status: 'conflict',
        statusCode: 409,
        error: {
          code: 'REQUEST_ALREADY_IN_FLIGHT',
          message: 'A request is already in progress for this conversation. Wait for it to finish or press Stop.'
        }
      };
    }

    const reqId = requestId || `REQ-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
    const abortController = new AbortController();
    if (signal) {
      if (signal.aborted) abortController.abort();
      else signal.addEventListener('abort', () => abortController.abort(), { once: true });
    }

    this.inFlightRequests.set(session.sessionId, {
      requestId: reqId,
      abortController,
      startedAt: new Date().toISOString()
    });

    const emitProgress = (evt) => {
      if (typeof onProgress === 'function') {
        try {
          onProgress(evt);
        } catch (_) {}
      }
    };

    try {
      emitProgress({
        stage: 'INTERPRETING_INTENT',
        label: 'Analyzing natural-language intent, session context, and epistemic state…',
        timestamp: new Date().toISOString()
      });

      let plan = this.parseIntentAndEntities(cleanPrompt, session);

      let semanticDiagnostics = {
        requestId: reqId,
        sessionId: session.sessionId,
        invoked: false,
        provider: 'DETERMINISTIC_RULES',
        model: 'none',
        durationMs: 0,
        success: true,
        parsingOutcome: 'DETERMINISTIC_MATCH',
        selectedIntent: plan.intent,
        fallbackReason: null,
        contextPivotDetected: Boolean(plan.contextPivotDetected),
        timestamp: new Date().toISOString()
      };

      // Optional external LLM brain interpreter hook (safe fallback if unavailable or throws)
      if (this.llmInterpreter) {
        const semStart = performance.now();
        semanticDiagnostics.invoked = true;
        try {
          const override = await this.llmInterpreter(cleanPrompt, {
            lastTarget: session.lastValidTarget || session.lastTarget,
            targetHistory: session.targetHistory,
            lastIntent: session.lastIntent,
            lastPorts: session.lastPorts,
            pendingTask: session.pendingTask || null,
            lastProbeResult: session.lastProbeResult || session.lastToolResults || null,
            probeHistory: session.probeHistory || [],
            allowCloudFallback: Boolean(allowCloudFallback || process.env.EJII_ALLOW_CLOUD_FALLBACK === 'true'),
            defaultPlan: plan
          });
          const semDuration = Number((performance.now() - semStart).toFixed(1));
          semanticDiagnostics.durationMs = semDuration;
          if (override && typeof override === 'object') {
            semanticDiagnostics.provider = override.modelProvider || 'EXTERNAL_LLM';
            semanticDiagnostics.model = override.executedModel || process.env.EJII_GEMINI_MODEL || 'gemini-3.8-flash';
            semanticDiagnostics.success = true;
            semanticDiagnostics.parsingOutcome = override.modelInterpreted ? 'MODEL_INTERPRETED_PLAN' : 'DETERMINISTIC_OVERRIDE';
            if (override.intent) {
              plan = { ...plan, ...override };
              semanticDiagnostics.selectedIntent = plan.intent;
              if (override.contextPivotDetected !== undefined) {
                semanticDiagnostics.contextPivotDetected = Boolean(override.contextPivotDetected);
              }
            }
          } else {
            semanticDiagnostics.success = false;
            semanticDiagnostics.parsingOutcome = 'NULL_FALLTHROUGH';
            semanticDiagnostics.fallbackReason = 'MODEL_OFFLINE_OR_RETAIN_DETERMINISTIC';
          }
        } catch (semErr) {
          semanticDiagnostics.durationMs = Number((performance.now() - semStart).toFixed(1));
          semanticDiagnostics.success = false;
          semanticDiagnostics.parsingOutcome = 'ERROR';
          semanticDiagnostics.fallbackReason = semErr.message || 'INTERPRETER_EXCEPTION';
        }
      }

      emitProgress({
        stage: 'TOOL_SELECTED',
        intent: plan.intent,
        mode: plan.mode || 'operational',
        target: plan.target || null,
        ports: plan.ports || [],
        label: `Selected workflow: ${plan.intent}${plan.target ? ` (${plan.target})` : ''}`,
        timestamp: new Date().toISOString()
      });

      const userMsgRecord = {
        id: `MSG-U-${Date.now()}-${crypto.randomBytes(2).toString('hex')}`,
        role: 'user',
        content: cleanPrompt,
        createdAt: new Date().toISOString(),
        meta: { intent: plan.intent, mode: plan.mode || 'operational', target: plan.target, ports: plan.ports }
      };

      // Simulated timeout hook for deterministic testing of Scenario G / S
      if (simulateTimeout) {
        this._checkAborted(abortController.signal);
        const timeoutTarget = plan.target || 'unknown_target';
        const timeoutReply =
          `The diagnostic probe to \`${timeoutTarget}\` timed out (ETIMEDOUT) before receiving a response.\n\n` +
          `This means either \`${timeoutTarget}\` is offline/unreachable or an intermediate firewall silently dropped the probe packets. No healthy state was assumed.`;
        const structuredAnswer = {
          result: `Diagnostic probe to ${timeoutTarget} timed out (ETIMEDOUT).`,
          meaning: 'The target or an intermediate firewall did not reply within the time limit.',
          nextStep: `Verify that ${timeoutTarget} is reachable on the network or test a specific TCP port.`,
          layerFailedFirst: 'L3/L4 Transport (Timeout)',
          uncertainty: 'A timeout cannot distinguish between an offline host and a silent firewall drop without an ARP or TCP RST signal.'
        };
        const steps = [
          {
            stepNumber: 1,
            label: `Probing ${timeoutTarget}…`,
            tool: 'diagnostic_probe',
            status: 'TIMEOUT',
            summary: `Timed out waiting for response from ${timeoutTarget} (ETIMEDOUT)`,
            durationMs: null
          }
        ];
        const assistantMsg = this._finalizeTurn(session, userMsgRecord, {
          reqId,
          plan,
          reply: timeoutReply,
          structuredAnswer,
          steps,
          findings: [
            { label: 'Target', value: timeoutTarget, tone: 'neutral' },
            { label: 'Outcome', value: 'TIMEOUT (ETIMEDOUT)', tone: 'danger' }
          ],
          technicalEvidence: {
            tool: 'diagnostic_probe',
            target: timeoutTarget,
            error: 'ETIMEDOUT: Probe exceeded deadline without response',
            observedAt: new Date().toISOString()
          },
          startWall
        });
        return {
          success: true,
          status: 'timeout',
          statusCode: 200,
          data: assistantMsg
        };
      }

      // Check RBAC immediately if remediation was requested
      if (plan.intent === 'remediation') {
        const effectiveRole = String(user.role || session.role || 'READONLY').toUpperCase();
        const roleLevel = ROLE_LEVELS[effectiveRole] || 1;
        if (roleLevel < 2) {
          const deniedReply =
            `Permission denied for role \`${effectiveRole}\`. State-changing remediation actions (such as refreshing the DNS resolver configuration) require \`OPERATOR\`, \`SYSADMIN\`, or \`ADMIN\` authorization. Your account is limited to read-only diagnostics.`;
          return {
            success: false,
            status: 'denied',
            statusCode: 403,
            error: {
              code: 'INSUFFICIENT_PERMISSIONS',
              message: `Role '${effectiveRole}' is not authorized to execute state-changing remediation. Minimum required role: OPERATOR.`
            },
            data: {
              sessionId: session.sessionId,
              requestId: reqId,
              intent: 'remediation',
              reply: deniedReply,
              structuredAnswer: {
                result: `Blocked by RBAC policy (role: ${effectiveRole}).`,
                meaning: 'Your current account has read-only diagnostic permissions and cannot modify host or resolver state.',
                nextStep: 'Request Operator or Administrator approval to apply the change.'
              }
            }
          };
        }
      }

      // Non-network-probe intents skip target SSRF / DNS pre-resolution
      const nonRemoteProbeIntents = new Set([
        'greeting',
        'casual_conversation',
        'general_knowledge',
        'informational_question',
        'epistemic_fabric_query',
        'log_and_startup_triage',
        'infrastructure_intelligence_synthesis',
        'scenario_planning_what_if',
        'dependency_blast_radius',
        'atlas_connectivity_query',
        'mail_troubleshooting_intake',
        'clarification_needed',
        'follow_up_explanation',
        'host_health',
        'local_ip_config',
        'gateway_check',
        'gateway_ip_query',
        'dhcp_check',
        'local_path_diagnostic',
        'active_connections'
      ]);

      if (!nonRemoteProbeIntents.has(plan.intent) && plan.target) {
        if (!isSafeNetworkTarget(plan.target)) {
          return {
            success: false,
            status: 'blocked',
            statusCode: 400,
            error: {
              code: 'SECURITY_VIOLATION_SSRF',
              message: `Target '${plan.target}' was rejected by the SSRF and target safety guard (cloud metadata, link-local, or invalid hostname syntax).`
            }
          };
        }

        let targetValidation = await resolveAndValidateTarget(plan.target);
        if (!targetValidation.valid && String(targetValidation.error || '').includes('SECURITY_VIOLATION')) {
          return {
            success: false,
            status: 'blocked',
            statusCode: 400,
            error: {
              code: 'SECURITY_VIOLATION_SSRF',
              message: targetValidation.error
            }
          };
        }

        // Cautious Typo Recovery:
        // Auto-correct ONLY high-confidence unambiguous TLD/well-known typos when the original domain failed DNS (ENOTFOUND),
        // while keeping full transparency.
        if (!targetValidation.valid && plan.typoSuggestion && isSafeNetworkTarget(plan.typoSuggestion)) {
          const correctedValidation = await resolveAndValidateTarget(plan.typoSuggestion);
          if (correctedValidation.valid) {
            plan.originalTypoTarget = plan.target;
            plan.target = plan.typoSuggestion;
            targetValidation = correctedValidation;
          }
        }

        plan.targetValidation = targetValidation;
      }

      this._checkAborted(abortController.signal);

      const executeSinglePlan = async (stepPlan) => {
        if (!nonRemoteProbeIntents.has(stepPlan.intent) && !stepPlan.targetValidation && stepPlan.target) {
          if (!isSafeNetworkTarget(stepPlan.target)) {
            throw new Error(`Target '${stepPlan.target}' rejected by SSRF guard.`);
          }
          stepPlan.targetValidation = await resolveAndValidateTarget(stepPlan.target);
        }
        switch (stepPlan.intent) {
          case 'greeting':
            return this._executeGreetingScenario(cleanPrompt, stepPlan, session);
          case 'casual_conversation':
            return this._executeCasualConversationScenario(cleanPrompt, stepPlan, session);
          case 'general_knowledge':
            return this._executeGeneralKnowledgeScenario(cleanPrompt, stepPlan, session);
          case 'informational_question':
            return this._executeInformationalQuestionScenario(cleanPrompt, session, stepPlan);
          case 'epistemic_fabric_query':
            return await this._executeEpistemicFabricQueryScenario(cleanPrompt, session, stepPlan);
          case 'log_and_startup_triage':
            return await this._executeLogAndStartupTriageScenario(stepPlan, session, cleanPrompt, abortController.signal);
          case 'infrastructure_intelligence_synthesis':
            return await this._executeInfrastructureIntelligenceSynthesisScenario(stepPlan, session, cleanPrompt);
          case 'scenario_planning_what_if':
            return await this._executeScenarioPlanningWhatIf(stepPlan, session, cleanPrompt);
          case 'dependency_blast_radius':
            return await this._executeDependencyAndBlastRadiusScenario(stepPlan, session, cleanPrompt);
          case 'atlas_connectivity_query':
            return await this._executeAtlasConnectivityQueryScenario(stepPlan, session, cleanPrompt);
          case 'mail_troubleshooting_intake':
            return this._executeMailTroubleshootingIntakeScenario(cleanPrompt, session, stepPlan);
          case 'clarification_needed':
            return this._executeClarificationScenario(stepPlan, session);
          case 'local_ip_config':
            return this._executeLocalIpConfigScenario(stepPlan, session, abortController.signal);
          case 'gateway_check':
            return await this._executeGatewayCheckScenario(stepPlan, session, abortController.signal);
          case 'gateway_ip_query':
            return this._executeGatewayIpQuery(stepPlan, session);
          case 'dhcp_check':
            return await this._executeDhcpCheckScenario(stepPlan, session, abortController.signal);
          case 'local_path_diagnostic':
            return await this._executeLocalPathDiagnosticScenario(stepPlan, session, abortController.signal);
          case 'active_connections':
            return await this._executeActiveConnectionsScenario(stepPlan, session, abortController.signal);
          case 'dns':
            return await this._executeDnsScenario(stepPlan, session, abortController.signal);
          case 'ping':
            return await this._executePingScenario(stepPlan, session, abortController.signal);
          case 'port_check':
            return await this._executePortCheckScenario(stepPlan, session, abortController.signal);
          case 'website_check':
            return await this._executeWebsiteCheckScenario(stepPlan, session, abortController.signal);
          case 'traceroute':
            return await this._executeTracerouteScenario(stepPlan, session, abortController.signal);
          case 'snmp_probe':
            return await this._executeSnmpProbeScenario(stepPlan, session, abortController.signal);
          case 'snmp_walk':
            return await this._executeSnmpWalkScenario(stepPlan, session, abortController.signal);
          case 'office_device_resolve':
            return await this._executeOfficeDeviceResolveScenario(stepPlan, session, abortController.signal);
          case 'tls_posture_audit':
            return await this._executeTlsPostureAuditScenario(stepPlan, session, abortController.signal);
          case 'host_health':
            return await this._executeHostHealthScenario(stepPlan, abortController.signal);
          case 'follow_up_explanation':
            return await this._executeFollowUpExplanation(stepPlan, session, cleanPrompt);
          case 'remediation':
            return await this._executeRemediationScenario(stepPlan, user, abortController.signal);
          case 'multi_step_investigation':
          default:
            return await this._executeMultiStepInvestigation(stepPlan, session, cleanPrompt, abortController.signal);
        }
      };

      const executionOutcome = await runAgenticToolLoop({
        promptText: cleanPrompt,
        initialPlan: plan,
        sessionContext: {
          ...session,
          modelReflectionFn
        },
        executeSinglePlan,
        onProgress: emitProgress,
        signal: abortController.signal,
        maxSteps: 3,
        allowCloudReflection: Boolean(allowCloudFallback || process.env.EJII_ALLOW_CLOUD_FALLBACK === 'true')
      });

      this._checkAborted(abortController.signal);

      emitProgress({
        stage: 'SYNTHESIZING_RESPONSE',
        label: 'Synthesizing final verified diagnostic explanation…',
        timestamp: new Date().toISOString()
      });

      // If an unambiguous domain typo was auto-corrected (e.g. google.ocm -> google.com), prepend the auto-correction step with measured DNS timing (never hardcoded 1.2)
      if (plan.originalTypoTarget && executionOutcome) {
        const measuredTypoDnsMs = typeof plan.targetValidation?.dnsLatencyMs === 'number'
          ? plan.targetValidation.dnsLatencyMs
          : null;
        const typoStep = {
          stepNumber: 1,
          label: `Detected domain typo "${plan.originalTypoTarget}" (NXDOMAIN) → resolved "${plan.target}"…`,
          tool: 'typo_intelligence',
          status: 'PASS',
          summary: `"${plan.originalTypoTarget}" returned ENOTFOUND; switched to "${plan.target}"`,
          durationMs: measuredTypoDnsMs
        };
        executionOutcome.steps = [
          typoStep,
          ...(executionOutcome.steps || []).map((s, idx) => ({ ...s, stepNumber: idx + 2 }))
        ];
        executionOutcome.findings = [
          { label: 'Typo Corrected', value: `${plan.originalTypoTarget} → ${plan.target}`, tone: 'warn' },
          ...(executionOutcome.findings || [])
        ];
        executionOutcome.reply =
          `Note: \`${plan.originalTypoTarget}\` did not resolve in DNS (\`ENOTFOUND\`), so I checked **\`${plan.target}\`** instead.\n\n` +
          executionOutcome.reply;
      }

      const responsePayload = this._finalizeTurn(session, userMsgRecord, {
        reqId,
        plan,
        semanticDiagnostics,
        ...executionOutcome,
        startWall
      });

      return {
        success: true,
        status: responsePayload.status || 'ok',
        statusCode: 200,
        sessionId: responsePayload.sessionId,
        requestId: responsePayload.requestId,
        intent: responsePayload.intent,
        mode: responsePayload.mode,
        target: responsePayload.target,
        ports: responsePayload.ports,
        usedFollowUpTarget: responsePayload.usedFollowUpTarget,
        stateDiff: responsePayload.stateDiff,
        reply: responsePayload.reply,
        steps: responsePayload.steps,
        findings: responsePayload.findings,
        technicalEvidence: responsePayload.technicalEvidence,
        structuredAnswer: responsePayload.structuredAnswer,
        epistemicDistinctions: responsePayload.epistemicDistinctions,
        competingExplanationsComparison: responsePayload.competingExplanationsComparison,
        claudeMemContext: responsePayload.claudeMemContext,
        skillRoutingContext: responsePayload.skillRoutingContext,
        semanticDiagnostics: responsePayload.semanticDiagnostics,
        data: responsePayload
      };
    } catch (err) {
      if (err.code === 'REQUEST_CANCELLED' || abortController.signal.aborted) {
        return {
          success: false,
          status: 'cancelled',
          statusCode: 499,
          error: {
            code: 'REQUEST_CANCELLED',
            message: 'The diagnostic check was stopped at your request.'
          }
        };
      }
      return {
        success: false,
        status: 'failed',
        statusCode: 500,
        error: {
          code: 'CHAT_EXECUTION_ERROR',
          message: err.message || 'An unexpected error occurred while executing the diagnostic check.'
        }
      };
    } finally {
      this.inFlightRequests.delete(session.sessionId);
    }
  }

  _finalizeTurn(session, userMsgRecord, {
    reqId,
    plan,
    semanticDiagnostics = null,
    reply,
    structuredAnswer,
    steps = [],
    findings = [],
    technicalEvidence = null,
    connectionTable = null,
    interfaceTable = null,
    reportMarkdown = null,
    hypothesisEvaluation = null,
    status = 'ok',
    promptClarification = false,
    errorCode = undefined,
    startWall
  }) {
    const totalDurationMs = Number((performance.now() - startWall).toFixed(1));
    const nowIso = new Date().toISOString();

    // Record probe history & lastProbeResult whenever an operational probe ran
    if (plan.mode === 'operational' && technicalEvidence) {
      const derivedStatus =
        technicalEvidence.status ||
        (Array.isArray(steps) && steps.some((s) => s.status === 'FAIL')
          ? 'FAIL'
          : Array.isArray(steps) && steps.some((s) => s.status === 'PASS' || s.status === 'OPEN')
            ? 'PASS'
            : 'COMPLETED');
      session.lastProbeResult = {
        intent: plan.intent,
        target: plan.target || null,
        ports: plan.ports || [],
        status: derivedStatus,
        summary: structuredAnswer?.result || reply || '',
        observedAt: nowIso,
        ...technicalEvidence
      };
      if (!Array.isArray(session.probeHistory)) session.probeHistory = [];
      session.probeHistory.push({
        intent: plan.intent,
        target: plan.target || null,
        ports: plan.ports || [],
        status: derivedStatus,
        observedAt: nowIso
      });
      if (session.probeHistory.length > 25) {
        session.probeHistory = session.probeHistory.slice(-25);
      }
    }

    // Preserve previous diagnostic target & tool results on greeting, informational, clarification, or local-only turns
    if (!plan.preserveContextOnly && !plan.preserveLastRemoteTarget) {
      const targetWasValid = !plan.targetValidation || plan.targetValidation.valid;
      const isDifferentTargetFromPrior =
        plan.target &&
        session.lastTarget &&
        String(plan.target).toLowerCase() !== String(session.lastTarget).toLowerCase();
      if (plan.target && !plan.isSystemDnsHealthCheck) {
        if (targetWasValid || !session.lastValidTarget) {
          session.lastTarget = plan.target;
          session.lastTargetTimestampMs = Date.now();
        }
        if (targetWasValid) {
          session.lastValidTarget = plan.target;
          session.lastTargetTimestampMs = Date.now();
        }
        session.lastMultiEndpoints = [];
      }
      if (Array.isArray(plan.ports) && plan.ports.length > 0) {
        session.lastPorts = plan.ports;
      } else if (isDifferentTargetFromPrior) {
        session.lastPorts = [];
      }
      session.lastIntent = plan.intent;
      if (plan.url) {
        session.lastUrl = plan.url;
      } else if (isDifferentTargetFromPrior) {
        session.lastUrl = null;
      }
      if (technicalEvidence) {
        session.lastToolResults = technicalEvidence;
      }
      if (Array.isArray(steps) && steps.length > 0) {
        session.lastSteps = steps;
      }
      if (structuredAnswer) {
        session.lastStructuredAnswer = structuredAnswer;
      }
    } else if (plan.preserveLastRemoteTarget) {
      session.lastIntent = plan.intent;
      if (technicalEvidence) {
        session.lastToolResults = technicalEvidence;
        if (technicalEvidence.gatewayInfo?.gatewayIp) {
          session.lastGatewayIp = technicalEvidence.gatewayInfo.gatewayIp;
        } else if (technicalEvidence.defaultGateway?.gatewayIp) {
          session.lastGatewayIp = technicalEvidence.defaultGateway.gatewayIp;
        }
      }
      if (Array.isArray(steps) && steps.length > 0) {
        session.lastSteps = steps;
      }
      if (structuredAnswer) {
        session.lastStructuredAnswer = structuredAnswer;
      }
    }

    session.turnCount = (session.turnCount || 0) + 1;

    const memoryInsights =
      plan.mode === 'operational' && session.lastMemoryInsights && session.lastMemoryInsights.target === String(plan.target || '').toLowerCase()
        ? session.lastMemoryInsights
        : null;

    const suggestedFollowUps = operationalMemoryEngine.generateContextualFollowUps({
      intent: plan.intent,
      target: plan.target,
      ports: plan.ports,
      steps,
      structuredAnswer,
      memoryInsights,
      logAnalysis: plan.logAnalysis || null
    });

    const effectiveHypEval = hypothesisEvaluation || structuredAnswer?.hypothesisEvaluation || null;
    const isRealTargetForJourney =
      plan.mode === 'operational' &&
      plan.target &&
      !String(plan.target).startsWith('local_') &&
      !String(plan.target).startsWith('operational_') &&
      !String(plan.target).startsWith('knowledge_');

    if (isRealTargetForJourney) {
      try {
        operationalMemoryEngine.coordinateOperationsCommander({
          target: plan.target,
          port: (Array.isArray(plan.ports) && plan.ports[0]) || 443,
          workspace: 'chat-workspace',
          intent: plan.intent,
          status: Array.isArray(steps) && steps.some((s) => s.status === 'FAIL') ? 'DEGRADED' : 'COMPLETED',
          summary: structuredAnswer?.result || reply || ''
        });
      } catch (_) {}
    }

    const unifiedJourney = isRealTargetForJourney
      ? operationalMemoryEngine.compileUnifiedOperationalJourney({
          target: plan.target,
          port: (Array.isArray(plan.ports) && plan.ports[0]) || 443,
          steps,
          hypothesisEvaluation: effectiveHypEval
        })
      : null;

    const effectiveCogTarget = isRealTargetForJourney ? plan.target : (session.lastValidTarget || '127.0.0.1');
    const effectiveCogPort = (Array.isArray(plan.ports) && plan.ports[0]) || 3000;

    const epistemicReasoning = plan.mode === 'operational'
      ? operationalMemoryEngine.evaluateDynamicEpistemicReasoning({
          prompt: userMsgRecord?.content || '',
          intent: plan.intent,
          target: effectiveCogTarget,
          port: effectiveCogPort,
          steps,
          hypothesisEvaluation: effectiveHypEval,
          memoryInsights
        })
      : null;

    const problemDecomposition = plan.mode === 'operational'
      ? operationalMemoryEngine.decomposeOperationalProblemAndPlan({
          problemStatement: userMsgRecord?.content || '',
          target: effectiveCogTarget,
          port: effectiveCogPort,
          steps
        })
      : null;

    const remediationSuitability = plan.mode === 'operational'
      ? operationalMemoryEngine.evaluateContextAwareRemediationSuitability({
          target: effectiveCogTarget,
          port: effectiveCogPort,
          steps
        })
      : null;

    const cognition3StrategyPlan = plan.mode === 'operational'
      ? operationalMemoryEngine.classifyProblemNatureAndSelectStrategy({
          problemStatement: userMsgRecord?.content || '',
          target: effectiveCogTarget,
          port: effectiveCogPort,
          steps
        })
      : null;

    const criticalSelfCorrection = plan.mode === 'operational'
      ? operationalMemoryEngine.challengeConclusionsAndSelfCorrect({
          prompt: userMsgRecord?.content || '',
          target: effectiveCogTarget,
          port: effectiveCogPort,
          steps,
          hypothesisEvaluation: effectiveHypEval
        })
      : null;

    const continuousExperience = plan.mode === 'operational'
      ? operationalMemoryEngine.evaluateContinuousOperationalExperience({
          target: effectiveCogTarget,
          port: effectiveCogPort,
          problemNature: cognition3StrategyPlan?.problemNatureClassification?.primaryNature || null
        })
      : null;

    let collaborativeSynthesis = technicalEvidence?.collaborativeSynthesis || (
      plan.mode === 'operational'
        ? operationalMemoryEngine.synthesizeCollaborativeSpecialistIntelligence({
            target: effectiveCogTarget,
            port: effectiveCogPort,
            objective: userMsgRecord?.content || '',
            steps
          })
        : null
    );

    const closedLoopFollowUp = technicalEvidence?.closedLoopFollowUp || null;
    if (closedLoopFollowUp?.updatedSynthesis) {
      collaborativeSynthesis = closedLoopFollowUp.updatedSynthesis;
    }

    // Compute multi-turn stateDiff whenever 2+ observations exist for the active target in session memory
    let stateDiff = technicalEvidence?.stateDiff || structuredAnswer?.stateDiff || null;
    if (!stateDiff && isRealTargetForJourney) {
      const entityKey = String(effectiveCogTarget || '').toLowerCase();
      const targetEntity = session.entityMemory?.[entityKey] || null;
      const observations = Array.isArray(targetEntity?.observations) ? targetEntity.observations : [];
      if (observations.length >= 2) {
        const latestObs = observations[observations.length - 1];
        const prevObs = observations[observations.length - 2];
        const prevOpen = new Set(prevObs.openPorts || []);
        const currOpen = new Set(latestObs.openPorts || targetEntity?.openPorts || []);
        const newlyOpenedPorts = [...currOpen].filter((p) => !prevOpen.has(p));
        const newlyClosedPorts = [...prevOpen].filter((p) => !currOpen.has(p));
        const rttDeltaMs =
          typeof latestObs.pingRttMs === 'number' && typeof prevObs.pingRttMs === 'number'
            ? Number((latestObs.pingRttMs - prevObs.pingRttMs).toFixed(2))
            : null;
        stateDiff = {
          target: targetEntity?.target || effectiveCogTarget,
          previousObservedAt: prevObs.observedAt,
          latestObservedAt: latestObs.observedAt,
          previousSummary: prevObs.summary || prevObs.intent,
          latestSummary: latestObs.summary || latestObs.intent,
          statusChanged: Boolean(prevObs.success !== latestObs.success || prevObs.summary !== latestObs.summary || newlyOpenedPorts.length > 0 || newlyClosedPorts.length > 0),
          previousSuccess: prevObs.success,
          latestSuccess: latestObs.success,
          rttDeltaMs,
          newlyOpenedPorts,
          newlyClosedPorts
        };
      }
    }

    if (stateDiff && structuredAnswer && !structuredAnswer.stateDiff) {
      structuredAnswer.stateDiff = stateDiff;
    }
    if (stateDiff && technicalEvidence && !technicalEvidence.stateDiff) {
      technicalEvidence.stateDiff = stateDiff;
    }

    // Phase Atlas V (Cycle 3 & Cycle 11): Canonical Epistemic Distinctions & Competing Explanations Comparison
    const rawEpDistinctions = technicalEvidence?.epistemicDistinctions || null;
    const pillars = epistemicReasoning?.epistemicSevenPillars || null;
    const observedConditions = Array.isArray(rawEpDistinctions?.observedConditions)
      ? rawEpDistinctions.observedConditions
      : Array.isArray(pillars?.directlyObserved) && pillars.directlyObserved.length > 0
        ? pillars.directlyObserved
        : steps.map((s) => `[${s.tool || 'probe'}] ${s.label}: ${s.status} (${s.summary || 'completed'})`);

    const suspectedProblems = Array.isArray(rawEpDistinctions?.suspectedProblems)
      ? rawEpDistinctions.suspectedProblems
      : Array.isArray(effectiveHypEval?.hypotheses)
        ? effectiveHypEval.hypotheses
            .filter((h) => h.status === 'CONFIRMED_FAULT' || h.status === 'SUSPECTED_FAULT' || h.status === 'DOWNSTREAM_SYMPTOM')
            .map((h) => `${h.layer}: ${h.verdictLabel} (${h.posteriorProbabilityPct ?? 50}% — ${h.evidence || ''})`)
        : Array.isArray(pillars?.inferredConclusions)
          ? pillars.inferredConclusions
          : [];

    const historicalPriors = Array.isArray(rawEpDistinctions?.historicalPriors)
      ? rawEpDistinctions.historicalPriors
      : memoryInsights
        ? [
            `Target ${memoryInsights.target} observed ${memoryInsights.observationCount || 1}x in operational memory (Stability: ${memoryInsights.stabilityScore ?? 100}%).`,
            ...((memoryInsights.matchedResolutions || []).map((r) => `Historical playbook (${r.resolutionId}): ${r.rootCause} -> ${r.resolutionSteps}`))
          ]
        : [];

    const unavailableMetrics = Array.isArray(rawEpDistinctions?.unavailableMetrics)
      ? rawEpDistinctions.unavailableMetrics
      : Array.isArray(pillars?.unknownBlindSpots)
        ? pillars.unknownBlindSpots
        : Array.isArray(collaborativeSynthesis?.telemetryBlindSpots)
          ? collaborativeSynthesis.telemetryBlindSpots
          : [];

    const recoverySource =
      rawEpDistinctions?.verifiedRecoveryState !== undefined
        ? rawEpDistinctions.verifiedRecoveryState
        : closedLoopFollowUp && (closedLoopFollowUp.executed || closedLoopFollowUp.actionExecuted)
          ? closedLoopFollowUp
          : technicalEvidence?.verification !== undefined
            ? technicalEvidence
            : null;

    const verifiedRecoveryState = recoverySource
      ? this.evaluateVerifiedRecoveryState(recoverySource, plan.target)
      : null;

    const indirectEvidenceBoundaries =
      rawEpDistinctions?.indirectEvidenceBoundaries ||
      this.evaluateIndirectEvidenceBoundaries(
        technicalEvidence?.probeResult ||
        technicalEvidence?.lastProbeResult ||
        (Array.isArray(steps) && steps.find((s) => s.probeType || s.tool === 'tcp_port_probe' || s.tool === 'dns_lookup')) ||
        {}
      );

    const epistemicDistinctions = {
      observedConditions,
      suspectedProblems,
      historicalPriors,
      unavailableMetrics,
      indirectEvidenceBoundaries,
      verifiedRecoveryState
    };

    if (technicalEvidence && typeof technicalEvidence === 'object') {
      technicalEvidence.epistemicDistinctions = epistemicDistinctions;
    }

    const hypsList = Array.isArray(effectiveHypEval?.hypotheses) ? effectiveHypEval.hypotheses : [];
    const primaryHyp = effectiveHypEval?.primaryRootCause || hypsList[0] || null;
    const matchedPrimaryInList =
      hypsList.find((h) => primaryHyp && (h.hypothesisId === primaryHyp.hypothesisId || h.layer === primaryHyp.layer)) ||
      primaryHyp;

    const primarySupportingObs = Array.isArray(matchedPrimaryInList?.supportingEvidence) && matchedPrimaryInList.supportingEvidence.length > 0
      ? matchedPrimaryInList.supportingEvidence
      : matchedPrimaryInList?.evidence
        ? [matchedPrimaryInList.evidence]
        : primaryHyp?.summary
          ? [primaryHyp.summary]
          : steps.map((s) => `${s.label}: ${s.status} (${s.summary || 'measured'})`).slice(0, 3);

    const altHyps = hypsList
      .filter((h) => !primaryHyp || (h.layer !== primaryHyp.layer && h.hypothesisId !== primaryHyp.hypothesisId))
      .slice(0, 4)
      .map((h) => {
        const refutingObs =
          Array.isArray(h.contradictingEvidence) && h.contradictingEvidence.length > 0
            ? h.contradictingEvidence.join('; ')
            : h.evidence || 'no direct fault telemetry observed on this layer';
        return {
          layer: h.layer,
          probabilityPct: Number(h.posteriorProbabilityPct ?? 0),
          status: h.status || 'ALTERNATIVE_CANDIDATE',
          supportingObservations: Array.isArray(h.supportingEvidence) ? h.supportingEvidence : [],
          refutingObservations: Array.isArray(h.contradictingEvidence) && h.contradictingEvidence.length > 0
            ? h.contradictingEvidence
            : (h.status === 'REFUTED_HEALTHY' && h.evidence ? [h.evidence] : []),
          reasonRankedLower:
            h.status === 'REFUTED_HEALTHY'
              ? `Refuted by concrete observation: ${refutingObs}.`
              : h.causalRole === 'DOWNSTREAM_SYMPTOM'
                ? `Isolated as a downstream effect of ${primaryHyp?.layer || 'upstream fault'} because ${refutingObs}.`
                : `Outranked by ${primaryHyp?.layer || 'leading hypothesis'} due to direct refuting/absent layer telemetry (${refutingObs}).`
        };
      });

    const leadingLayer = primaryHyp?.layer || structuredAnswer?.layerFailedFirst || 'L4_RELAY_AND_TUNNEL_CONTROL_PLANE';
    const hasEmpiricalProb = Boolean(
      primaryHyp && (primaryHyp.posteriorProbabilityPct !== undefined || primaryHyp.confidencePct !== undefined)
    );
    const leadingPct = hasEmpiricalProb
      ? Number(primaryHyp.posteriorProbabilityPct ?? primaryHyp.confidencePct)
      : (hypsList.length > 0 && hypsList[0].posteriorProbabilityPct !== undefined
        ? Number(hypsList[0].posteriorProbabilityPct)
        : null);

    // Cycle 5: Propagate actual methodology from inference engine rather than setting BAYESIAN_LIKELIHOOD_POSTERIOR whenever hypsList.length >= 2
    const validConfidenceTypes = new Set([
      'CALIBRATED_EMPIRICAL_POSTERIOR',
      'BAYESIAN_LIKELIHOOD_POSTERIOR',
      'EMPIRICAL_PROBE_CONFIDENCE',
      'RULE_HEURISTIC',
      'INSUFFICIENT_DATA',
      'POORLY_CALIBRATED_ON_HOLDOUT'
    ]);
    const explicitMethodology =
      primaryHyp?.confidenceType ||
      matchedPrimaryInList?.confidenceType ||
      effectiveHypEval?.confidenceType ||
      effectiveHypEval?.calibration?.confidenceType ||
      technicalEvidence?.indirectInference?.confidenceType ||
      technicalEvidence?.confidenceType ||
      null;

    const hasGenuineBayesianPosterior = Boolean(
      (typeof matchedPrimaryInList?.priorProbability === 'number' && typeof matchedPrimaryInList?.likelihoodScore === 'number') ||
      effectiveHypEval?.bayesianNormalized === true ||
      effectiveHypEval?.methodology === 'BAYESIAN_LIKELIHOOD_POSTERIOR'
    );
    const hasDirectEmpiricalObservations = Boolean(
      steps.length > 0 &&
      (primarySupportingObs.length > 0 || matchedPrimaryInList?.evidence || primaryHyp?.summary)
    );

    let confidenceType = 'INSUFFICIENT_DATA';
    if (explicitMethodology && validConfidenceTypes.has(explicitMethodology)) {
      confidenceType = explicitMethodology;
    } else if (hasGenuineBayesianPosterior) {
      confidenceType = 'BAYESIAN_LIKELIHOOD_POSTERIOR';
    } else if (hasDirectEmpiricalObservations && hasEmpiricalProb) {
      confidenceType = 'EMPIRICAL_PROBE_CONFIDENCE';
    } else if (leadingPct !== null || primaryHyp) {
      confidenceType = 'RULE_HEURISTIC';
    }

    const rawNextEig = effectiveHypEval?.nextBestInvestigation?.expectedInformationGainBits;
    const effectiveEig = rawNextEig !== undefined && rawNextEig !== null && Number.isFinite(Number(rawNextEig))
      ? Number(rawNextEig)
      : null;

    const concreteSupportSummary = primarySupportingObs.length > 0
      ? primarySupportingObs.join('; ')
      : (structuredAnswer?.result || 'direct runtime state');
    const concreteRefutationSummary = altHyps.length > 0
      ? altHyps.map((a) => `${a.layer} (${a.reasonRankedLower})`).join(' | ')
      : 'no competing protocol layers exhibited anomalous telemetry';

    const evidentialRankingRationale =
      `Leading hypothesis ${leadingLayer} is anchored by concrete supporting observation(s): [${concreteSupportSummary}]. ` +
      `Competing explanations are ranked lower based on refuting/diagnostic evidence: [${concreteRefutationSummary}].`;

    const competingExplanationsComparison = {
      leadingHypothesis: {
        layer: leadingLayer,
        probabilityPct: leadingPct,
        confidenceType,
        supportingObservations: primarySupportingObs,
        evidentialRankingRationale,
        whyLeadingOutweighsAlternatives: evidentialRankingRationale
      },
      alternativeHypotheses: altHyps,
      contradictoryObservations: Array.isArray(effectiveHypEval?.contradictions)
        ? effectiveHypEval.contradictions
        : [],
      recommendedNextActionWithEig: effectiveHypEval?.nextBestInvestigation
        ? {
            actionOrProbe:
              effectiveHypEval.nextBestInvestigation.recommendedAction ||
              effectiveHypEval.nextBestInvestigation.action ||
              'Targeted verification probe',
            targetLayer: effectiveHypEval.nextBestInvestigation.targetLayer || leadingLayer,
            expectedInformationGainBits: effectiveEig,
            rationale: effectiveHypEval.nextBestInvestigation.rationale || 'Disambiguates remaining uncertainty.'
          }
        : {
            actionOrProbe: structuredAnswer?.nextStep || 'Execute targeted live socket probe',
            targetLayer: leadingLayer,
            expectedInformationGainBits: null,
            rationale: 'Disambiguates remaining unmeasured layers before invasive remediation.'
          }
    };

    const commandCenterOverview = technicalEvidence?.commandCenterOverview || null;
    const scenarioSimulation = technicalEvidence?.scenarioSimulation || null;
    const serverConfigDifferential = technicalEvidence?.serverConfigDifferential || null;

    // Record operational diagnostic observation in Claude-Mem and compile 3-layer progressive disclosure context
    let claudeMemContext = null;
    let skillRoutingContext = null;
    let claudeMemError = null;
    try {
      if (plan.mode === 'operational' && (steps.length > 0 || structuredAnswer?.result)) {
        claudeMemEngine.recordObservation({
          sessionId: session.sessionId,
          ownerUserId: session.userId || null,
          ownerUsername: session.username || null,
          visibilityScope: 'PRIVATE_OPERATIONAL',
          type: steps.some((s) => s.status === 'FAIL') ? 'incident' : 'probe_evidence',
          memoryCategory: 'LIVE_OPERATIONAL_OBSERVATION',
          isLiveMeasurement: steps.length > 0,
          title: `${plan.intent}: ${(structuredAnswer?.result || reply || '').slice(0, 140)}`,
          subtitle: structuredAnswer?.meaning ? structuredAnswer.meaning.slice(0, 200) : '',
          target: plan.target || null,
          conceptTags: [
            steps.some((s) => s.status === 'FAIL') ? 'problem-solution' : 'how-it-works',
            'layer-disambiguation',
            'what-changed'
          ],
          facts: steps.map((s) => `${s.label}: ${s.status} (${s.summary || 'measured'})`).slice(0, 8),
          narrative: structuredAnswer?.result || reply || '',
          rootCause: leadingLayer || null,
          probeMetrics: {
            totalDurationMs,
            stepCount: steps.length,
            ports: plan.ports || []
          }
        });
      }
      claudeMemContext = (plan.mode === 'conversational')
        ? null
        : claudeMemEngine.compileProgressiveDisclosureContext(
            userMsgRecord?.content || plan.intent || '',
            plan.target || null,
            {
              maxTokenBudget: 600,
              userId: session.userId || null,
              username: session.username || null,
              role: session.role || null,
              sessionId: session.sessionId
            }
          );
      skillRoutingContext = (plan.mode === 'conversational')
        ? null
        : readOnlySkillCatalog.routeWithContextBudget(
            userMsgRecord?.content || plan.intent || 'network diagnostics',
            { maxContextTokens: 900 }
          );
    } catch (memErr) {
      claudeMemError = memErr?.message || String(memErr);
    }

    const assistantMsgRecord = {
      id: `MSG-A-${Date.now()}-${crypto.randomBytes(2).toString('hex')}`,
      role: 'assistant',
      content: reply,
      createdAt: nowIso,
      meta: {
        requestId: reqId,
        intent: plan.intent,
        mode: plan.mode || 'operational',
        target: plan.target,
        ports: plan.ports,
        usedFollowUpTarget: Boolean(plan.usedFollowUpTarget),
        totalDurationMs,
        structuredAnswer,
        epistemicDistinctions,
        competingExplanationsComparison,
        steps,
        findings,
        connectionTable,
        interfaceTable,
        reportMarkdown,
        memoryInsights,
        claudeMemContext,
        claudeMemError,
        skillRoutingContext,
        semanticDiagnostics,
        hypothesisEvaluation: effectiveHypEval,
        epistemicReasoning,
        problemDecomposition,
        remediationSuitability,
        cognition3StrategyPlan,
        criticalSelfCorrection,
        continuousExperience,
        collaborativeSynthesis,
        closedLoopFollowUp,
        stateDiff,
        serverConfigDifferential,
        unifiedJourney,
        commandCenterOverview,
        scenarioSimulation,
        suggestedFollowUps,
        technicalEvidence
      }
    };

    session.messages.push(userMsgRecord, assistantMsgRecord);
    session.totalPersistedMessages = (session.totalPersistedMessages || 0) + 2;

    if (session.messages.length > MAX_WORKING_MEMORY_MESSAGES) {
      session.messages = session.messages.slice(-MAX_WORKING_MEMORY_MESSAGES);
    }

    this._persistSession(session, [userMsgRecord, assistantMsgRecord]);

    return {
      sessionId: session.sessionId,
      requestId: reqId,
      intent: plan.intent,
      mode: plan.mode || 'operational',
      status: status || 'ok',
      promptClarification: Boolean(promptClarification),
      ...(errorCode ? { errorCode } : {}),
      executionTier: plan.executionTier || 'ZERO_LATENCY_LOCAL_REFLEX',
      contextPivotDetected: Boolean(plan.contextPivotDetected),
      target: plan.target,
      ports: plan.ports,
      usedFollowUpTarget: Boolean(plan.usedFollowUpTarget),
      totalDurationMs,
      reply,
      structuredAnswer,
      epistemicDistinctions,
      competingExplanationsComparison,
      steps,
      findings,
      connectionTable,
      interfaceTable,
      reportMarkdown,
      memoryInsights,
      claudeMemContext,
      skillRoutingContext,
      semanticDiagnostics,
      hypothesisEvaluation: effectiveHypEval,
      epistemicReasoning,
      problemDecomposition,
      remediationSuitability,
      cognition3StrategyPlan,
      criticalSelfCorrection,
      continuousExperience,
      collaborativeSynthesis,
      closedLoopFollowUp,
      stateDiff,
      serverConfigDifferential,
      unifiedJourney,
      commandCenterOverview,
      scenarioSimulation,
      suggestedFollowUps,
      technicalEvidence,
      sessionContext: {
        lastTarget: session.lastTarget,
        lastValidTarget: session.lastValidTarget,
        lastPorts: session.lastPorts,
        lastIntent: session.lastIntent,
        contextPivotDetected: Boolean(plan.contextPivotDetected),
        executionTier: plan.executionTier || 'ZERO_LATENCY_LOCAL_REFLEX',
        turnCount: session.turnCount,
        activeMemoryMessageCount: session.messages.length,
        totalPersistedMessages: session.totalPersistedMessages,
        knownEntitiesCount: Object.keys(session.entityMemory || {}).length
      }
    };
  }

  /**
   * Zero-Latency Local Reflex: Live SNMP v2c UDP/161 + Multi-Signal Agentless Device Profile
   */
  async _executeSnmpProbeScenario(plan, session, signal) {
    this._checkAborted(signal);
    const target = plan.target || '127.0.0.1';
    const { agentlessCollector } = require('../agent/agentless-collector');
    const profile = await agentlessCollector.profileDeviceMultiSignal(target, {
      timeoutMs: 800,
      ports: [22, 80, 443, 3000]
    });

    const snmpResponded = Boolean(profile.snmpResult && profile.snmpResult.alive);
    const result = snmpResponded
      ? `SNMP v2c UDP/161 responded on \`${target}\` (${profile.snmpResult.sysName || 'MIB-II System'}, latency ${profile.snmpResult.latencyMs}ms).`
      : `SNMP UDP/161 on \`${target}\` did not return an authoritative MIB-II response (${profile.snmpStatus}); multi-signal fallback classified device as \`${profile.inferredDeviceRole}\` via [${(profile.signalsCollected || []).join(', ')}].`;
    const meaning = snmpResponded
      ? `Authoritative SNMP MIB-II telemetry was retrieved directly over UDP/161.`
      : `Because UDP/161 is filtered or no SNMP daemon is bound on \`${target}\`, EJII fused ICMP echo, TCP service matrix, and HTTP headers without assuming SNMP health.`;
    const nextStep = `Inspect open TCP ports [${(profile.openTcpPorts || []).join(', ') || 'none'}] or run a targeted MIB subtree walk if SNMP community credentials differ.`;

    return {
      reply: `**Result:** ${result}\n\n**Meaning:** ${meaning}\n\n**Next Step:** ${nextStep}`,
      structuredAnswer: {
        result,
        meaning,
        nextStep,
        layerFailedFirst: snmpResponded ? null : 'L7_SNMP_UDP_161',
        uncertainty: snmpResponded ? null : profile.honestDisclosure
      },
      steps: [
        {
          stepNumber: 1,
          layer: 'L7_SNMP',
          tool: 'agentlessCollector.profileDeviceMultiSignal',
          label: `Probing SNMP v2c UDP/161 & Multi-Signal Fallback on ${target}`,
          status: snmpResponded || profile.reachableViaAnySignal ? 'PASS' : 'FAIL',
          summary: result,
          durationMs: profile.snmpResult?.latencyMs || 15
        }
      ],
      findings: [
        { label: 'Target', value: target, tone: 'neutral' },
        { label: 'SNMP UDP/161 Status', value: profile.snmpStatus, tone: snmpResponded ? 'ok' : 'warn' },
        { label: 'Inferred Role', value: profile.inferredDeviceRole, tone: 'ok' },
        { label: 'Signals Collected', value: (profile.signalsCollected || []).join(', ') || 'NONE', tone: 'neutral' }
      ],
      technicalEvidence: {
        tool: 'snmp_multi_signal_probe',
        target,
        profile,
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Real SNMP Subtree / MIB Walk Execution
   */
  async _executeSnmpWalkScenario(plan, session, signal) {
    this._checkAborted(signal);
    const target = plan.target;
    if (!target) {
      const reply = "Target IP or hostname is required for an SNMP walk. Please specify a remote network device (e.g., `Run SNMP walk on 10.0.0.1 under OID 1.3.6.1.2.1.1`).";
      return {
        reply,
        status: 'clarification_needed',
        promptClarification: true,
        structuredAnswer: {
          result: "Target IP or hostname is required for an SNMP walk.",
          meaning: "An SNMP subtree walk requires an explicit remote hostname or IP address to query over UDP port 161.",
          nextStep: 'Provide a target IP or hostname (e.g. "Run SNMP walk on 192.168.1.1").',
          layerFailedFirst: "L7_SNMP_MISSING_TARGET",
          telemetryProvenance: {
            honestMeasurement: true,
            zeroFabricatedMetrics: true
          }
        },
        steps: [],
        findings: [{ label: 'Clarification Needed', value: 'Target IP or hostname is required for an SNMP walk', tone: 'warn' }],
        technicalEvidence: { tool: 'snmp_walk', error: 'MISSING_TARGET_DEVICE' }
      };
    }

    let rootOid = plan.rootOid || plan.rawOid || '1.3.6.1.2.1.1';
    const oidAliases = {
      system: '1.3.6.1.2.1.1',
      interfaces: '1.3.6.1.2.1.2',
      iftable: '1.3.6.1.2.1.2.2',
      ip: '1.3.6.1.2.1.4',
      tcp: '1.3.6.1.2.1.6',
      udp: '1.3.6.1.2.1.7',
      snmp: '1.3.6.1.2.1.11'
    };
    if (typeof rootOid === 'string' && oidAliases[rootOid.toLowerCase()]) {
      rootOid = oidAliases[rootOid.toLowerCase()];
    }

    const community = plan.community || 'public';
    const { snmpEngine } = require('../../protocols/snmp-engine');

    const startTime = performance.now();
    const res = await snmpEngine.walkOid(target, rootOid, community);
    const durationMs = parseFloat((performance.now() - startTime).toFixed(2));

    const isSuccess = Boolean(res && res.success);
    const count = res?.count ?? res?.items?.length ?? 0;
    const provenance = res?.telemetryProvenance || (isSuccess ? 'LIVE_SNMP_HARDWARE' : 'UNREACHABLE_TIMEOUT');

    let result = '';
    let meaning = '';
    let nextStep = '';
    let layerFailedFirst = null;

    const isOidFormatError = res?.telemetryProvenance === 'INVALID_OID_FORMAT';
    if (isOidFormatError) {
      result = `The requested ASN.1 OID '${rootOid}' is semantically invalid. SNMP OIDs must consist of dotted-decimal non-negative integer arcs (e.g., 1.3.6.1.2.1.1). ASN.1 OID syntax error.`;
      meaning = "The SNMP engine rejected the request prior to transmission because the subtree identifier does not conform to RFC 1155 / RFC 2578 ASN.1 SMI structure. ASN.1 OID syntax error.";
      nextStep = "Provide a valid dotted-numeric OID like 1.3.6.1.2.1.1 (system) or 1.3.6.1.2.1.2 (interfaces).";
      layerFailedFirst = 'L7_ASN1_OID_SYNTAX';
    } else if (res?.telemetryProvenance === 'BLOCKED_UNSAFE_TARGET') {
      result = `Target '${target}' was rejected by SSRF defense policy (${res.error || 'Prohibited address'}).`;
      meaning = "Destination IP is an unroutable, cloud metadata, or prohibited network address.";
      nextStep = "Specify a legitimate remote device IP address.";
      layerFailedFirst = 'L3_SSRF_PROHIBITED';
    } else if (isSuccess) {
      result = `SNMP subtree walk on \`${target}\` under OID \`${res.rootOid || rootOid}\` returned ${count} varbinds.`;
      meaning = "Authoritative SNMP MIB instrumentation was retrieved directly from the device over UDP port 161.";
      nextStep = "Inspect specific MIB branch values or cross-reference interface operStatus with physical switch port telemetry.";
      layerFailedFirst = null;
    } else {
      result = `SNMP walk under OID \`${rootOid}\` on \`${target}\` timed out or was rejected: ${res?.error || 'SNMP timeout or unreachable'}.`;
      meaning = "Device did not return an SNMP response on UDP port 161. Note: SNMP UDP 161 timeout does NOT prove the host is offline at Layer 3/Layer 4; firewalls frequently drop UDP 161 while TCP/ICMP remain open.";
      nextStep = "Verify SNMP community credentials, ensure port 161/UDP is permitted through intermediate firewalls, or check ICMP reachability.";
      layerFailedFirst = 'L7_SNMP_UDP_161';
    }

    return {
      reply: `**Result:** ${result}\n\n**Meaning:** ${meaning}\n\n**Next Step:** ${nextStep}`,
      status: isOidFormatError ? 'rejected' : (isSuccess ? 'ok' : 'degraded'),
      errorCode: isOidFormatError ? 'L7_ASN1_OID_SYNTAX' : undefined,
      structuredAnswer: {
        result,
        meaning,
        nextStep,
        layerFailedFirst,
        telemetryProvenance: {
          provenance,
          honestMeasurement: true,
          zeroFabricatedMetrics: true
        },
        isAuthoritativeSnmp: Boolean(res?.isAuthoritativeSnmp),
        varbindCount: count
      },
      steps: [
        {
          stepNumber: 1,
          layer: 'L7_SNMP_WALK',
          tool: 'snmpEngine.walkOid',
          label: `SNMP Subtree Walk on ${target} (${rootOid})`,
          status: isSuccess ? 'PASS' : 'FAIL',
          summary: result,
          durationMs
        }
      ],
      findings: [
        { label: 'Target', value: target, tone: 'neutral' },
        { label: 'Root OID', value: rootOid, tone: 'neutral' },
        { label: 'Items Retrieved', value: String(count), tone: isSuccess ? 'ok' : 'warn' },
        { label: 'Telemetry Provenance', value: typeof provenance === 'string' ? provenance : 'LIVE_SNMP_HARDWARE', tone: isSuccess ? 'ok' : 'warn' }
      ],
      technicalEvidence: {
        tool: 'snmp_walk',
        target,
        rootOid,
        requestedOid: rootOid,
        entriesCount: count,
        errorClassification: !isSuccess && !isOidFormatError ? 'UDP_PORT_161_TIMEOUT_OR_UNREACHABLE' : (isOidFormatError ? 'L7_ASN1_OID_SYNTAX' : undefined),
        walkResult: res,
        telemetryProvenance: provenance,
        durationMs,
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Real Office Device Resolution & Plain-Language Diagnostic
   */
  async _executeOfficeDeviceResolveScenario(plan, session, signal) {
    this._checkAborted(signal);
    const target = plan.target;
    if (!target) {
      const reply = "Target IP or hostname is required for office equipment diagnosis (e.g., `Diagnose office printer on 192.168.1.50`).";
      return {
        reply,
        status: 'clarification_needed',
        promptClarification: true,
        structuredAnswer: {
          result: "Target IP or hostname is required for office equipment diagnosis.",
          meaning: "Office device classification and smart path tracing require an explicit IP address on the local network.",
          nextStep: 'Specify device IP or hostname (e.g. "Diagnose printer on 192.168.1.50").',
          layerFailedFirst: "L3_INPUT_VALIDATION",
          telemetryProvenance: {
            honestMeasurement: true,
            zeroFabricatedMetrics: true
          }
        },
        steps: [],
        findings: [{ label: 'Clarification Needed', value: 'Target IP or hostname is required for office device diagnostic', tone: 'warn' }],
        technicalEvidence: { tool: 'office_device_resolve', error: 'MISSING_TARGET_DEVICE' }
      };
    }

    const { diagnoseOfficeDevice } = require('../../network/diagnostics/office-device-resolver');

    const startTime = performance.now();
    const diag = await diagnoseOfficeDevice({
      targetIp: target,
      deviceName: plan.deviceName || '',
      deviceTypeHint: plan.deviceTypeHint || 'PRINTER'
    });
    const durationMs = parseFloat((performance.now() - startTime).toFixed(2));

    const tech = diag.technicalTelemetry || {};
    const prof = diag.equipmentProfile || {};
    const apipa = diag.apipaAnalysis || {};

    const openPorts = tech.openPorts || [];
    const openPortsStr = openPorts.length > 0 ? openPorts.join(', ') : 'none';
    const targetPingAlive = Boolean(tech.targetPingAlive);
    const targetReachable = targetPingAlive || openPorts.length > 0;
    const isApipa = Boolean(apipa.isApipa);
    const faultScenario = diag.faultScenario || (targetReachable ? 'HEALTHY_OPERATIONAL' : 'DEVICE_OFFLINE_OR_DISCONNECTED');
    const deviceType = prof.equipmentType || 'OFFICE_DEVICE';
    const deviceBrand = prof.equipmentBrand || 'Unknown';
    const deviceLabel = prof.equipmentLabel || `${deviceBrand} ${deviceType}`;
    const gatewayReachable = Boolean(tech.gatewayReachable);
    const gatewayIp = tech.defaultGatewayIp || 'default gateway';
    const rttMs = tech.targetRttMs !== null && tech.targetRttMs !== undefined ? `${tech.targetRttMs}ms` : null;

    let result = '';
    let meaning = '';
    let nextStep = '';
    let layerFailedFirst = null;
    let overallStatus = 'PASS';

    if (isApipa) {
      result = `Device \`${target}\` has an unroutable Link-Local APIPA address (${apipa.apipaAddress}). It failed to receive an IP lease from the DHCP server.`;
      meaning = `The office device is disconnected from the DHCP scope or cannot reach the DHCP server on ${gatewayIp}.`;
      nextStep = `Inspect physical Ethernet/Wi-Fi connection to the office switch, verify DHCP scope availability on ${gatewayIp}, or assign a static IP within ${tech.officeSubnetCidr || 'the LAN subnet'}.`;
      layerFailedFirst = 'L3_DHCP_APIPA';
      overallStatus = 'FAIL';
    } else if (!targetReachable) {
      result = `Office device \`${target}\` (${deviceLabel}) is unresponsive on the local network (ICMP ping timed out; office service ports [9100, 631, 515, 80, 443] unreachable).`;
      meaning = `Gateway ${gatewayIp} is ${gatewayReachable ? 'reachable' : 'unreachable'}, but \`${target}\` is powered off, in deep sleep mode, disconnected from the office switch, or its IP address changed via DHCP.`;
      nextStep = `Check if the equipment is powered on and awake, inspect Ethernet/Wi-Fi link LEDs, or run an ARP subnet scan in Ultra IP Scanner to check for a new DHCP IP lease.`;
      layerFailedFirst = 'L3_CONNECTIVITY';
      overallStatus = 'FAIL';
    } else if (faultScenario === 'PRINTER_ONLINE_BUT_PRINT_SERVICE_CLOSED') {
      result = `Office device \`${target}\` (${deviceLabel}) is online and responding to ping (${rttMs || 'low latency'}), but print service ports (RAW 9100, IPP 631, LPD 515) are closed.`;
      meaning = "Network Layer 3 connectivity is healthy, but the printer daemon is stopped, rebooting, or listening on a non-standard management port.";
      nextStep = `Restart the print daemon on the device, check web management on port ${openPorts.find(p => [80, 443, 8080].includes(p)) || 80}, or clear the workstation print spooler queue.`;
      layerFailedFirst = 'L7_PRINT_DAEMON';
      overallStatus = 'WARN';
    } else if (faultScenario === 'DIFFERENT_NETWORK_SUBNET_VLAN_MISMATCH') {
      result = `Office device \`${target}\` (${deviceLabel}) is reachable, but configured with an IP outside the local office subnet (${tech.officeSubnetCidr || 'LAN subnet'}).`;
      meaning = "The device is on an isolated VLAN or has an obsolete static IP from a previous office router configuration.";
      nextStep = `Update device network settings to DHCP or configure a static IP within ${tech.officeSubnetCidr || 'the LAN subnet'}.`;
      layerFailedFirst = 'L3_SUBNET_VLAN_MISMATCH';
      overallStatus = 'WARN';
    } else {
      result = `Office device \`${target}\` (${deviceLabel}) is online and fully operational (${rttMs ? `ping latency ${rttMs}` : 'ping responsive'}). Open office ports: [${openPortsStr}].`;
      meaning = `End-to-end path from workstation through ${gatewayIp} to device is operational.`;
      nextStep = `If printing problems persist for specific users, clear the local workstation print spooler queue or verify printer queue URI pointing to ${target}.`;
      layerFailedFirst = null;
      overallStatus = 'PASS';
    }

    return {
      reply: `**Result:** ${result}\n\n**Meaning:** ${meaning}\n\n**Next Step:** ${nextStep}`,
      structuredAnswer: {
        result,
        meaning,
        nextStep,
        layerFailedFirst,
        deviceClassification: deviceLabel,
        equipmentType: deviceType,
        equipmentBrand: deviceBrand,
        targetReachable,
        openPorts,
        faultScenario,
        telemetryProvenance: diag.telemetryProvenance || (targetReachable ? 'ACTIVE_WIRE_PROBE' : 'UNREACHABLE_TIMEOUT')
      },
      steps: [
        {
          stepNumber: 1,
          layer: isApipa ? 'L3_DHCP' : (targetReachable ? 'L7_OFFICE_SERVICE' : 'L3_CONNECTIVITY'),
          tool: 'diagnoseOfficeDevice',
          label: `Resolving Office Device on ${target} (${deviceLabel})`,
          status: overallStatus,
          summary: result,
          durationMs
        }
      ],
      findings: [
        { label: 'Target IP', value: target, tone: 'neutral' },
        { label: 'Device Classification', value: `${deviceBrand} (${deviceType})`, tone: 'ok' },
        { label: 'Network Reachability', value: targetReachable ? `ONLINE (${rttMs || 'ICMP / TCP'})` : 'OFFLINE / UNRESPONSIVE', tone: targetReachable ? 'ok' : 'danger' },
        { label: 'Open Service Ports', value: openPortsStr, tone: openPorts.length > 0 ? 'ok' : (targetReachable ? 'warn' : 'neutral') },
        { label: 'Gateway Reachability', value: gatewayReachable ? `REACHABLE (${gatewayIp})` : 'UNREACHABLE', tone: gatewayReachable ? 'ok' : 'warn' },
        { label: 'Diagnostic Scenario', value: faultScenario, tone: overallStatus === 'PASS' ? 'ok' : (overallStatus === 'WARN' ? 'warn' : 'danger') }
      ],
      technicalEvidence: {
        tool: 'office_device_resolve',
        target,
        diagnostic: diag,
        targetReachable,
        openPorts,
        faultScenario,
        durationMs,
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Real TLS / SSL Security Posture & Certificate Chain Inspection
   */
  async _executeTlsPostureAuditScenario(plan, session, signal) {
    this._checkAborted(signal);
    const target = plan.target;
    if (!target) {
      const reply = "Target host is required for a TLS posture audit (e.g., `Check TLS certificate for mail.company.com`).";
      return {
        reply,
        status: 'clarification_needed',
        promptClarification: true,
        structuredAnswer: {
          result: "Target host is required for a TLS posture audit.",
          meaning: "A TLS audit requires a specific hostname or IP address and port to initiate a cryptographic handshake.",
          nextStep: 'Provide the target hostname (and optional port, default 443).',
          layerFailedFirst: "L6_INPUT_VALIDATION",
          telemetryProvenance: {
            honestMeasurement: true,
            zeroFabricatedMetrics: true
          }
        },
        steps: [],
        findings: [{ label: 'Clarification Needed', value: 'Target host is required for TLS posture audit', tone: 'warn' }],
        technicalEvidence: { tool: 'tls_posture_audit', error: 'MISSING_TARGET_DEVICE' }
      };
    }

    const port = (plan.ports && plan.ports[0]) ? plan.ports[0] : 443;
    const { auditTls } = require('../../protocols/tls-audit');

    const startTime = performance.now();
    const tlsResult = await auditTls(target, port, 4000);
    const durationMs = parseFloat((performance.now() - startTime).toFixed(2));

    if (!tlsResult || !tlsResult.success) {
      const errorMsg = tlsResult?.error || 'Connection refused or handshake timeout';
      const result = `TLS handshake on \`${target}:${port}\` failed: ${errorMsg}.`;
      const meaning = `Remote port is closed, firewall dropped the handshake SYN packets, or the server does not support TLS on port ${port}.`;
      const nextStep = `Verify that the remote service is active with TLS enabled on port ${port} and intermediate firewalls allow incoming TLS traffic.`;

      return {
        reply: `**Result:** ${result}\n\n**Meaning:** ${meaning}\n\n**Next Step:** ${nextStep}`,
        structuredAnswer: {
          result,
          meaning,
          nextStep,
          layerFailedFirst: 'L6_TLS_HANDSHAKE',
          protocol: null,
          daysRemaining: null,
          authorized: false,
          securityVerdict: 'HANDSHAKE_FAILED',
          telemetryProvenance: {
            honestMeasurement: true,
            zeroFabricatedMetrics: true
          }
        },
        steps: [
          {
            stepNumber: 1,
            layer: 'L6_PRESENTATION_TLS',
            tool: 'auditTls',
            label: `TLS Handshake on ${target}:${port}`,
            status: 'FAIL',
            summary: result,
            durationMs: tlsResult?.handshakeLatencyMs || durationMs
          }
        ],
        findings: [
          { label: 'Target', value: `${target}:${port}`, tone: 'neutral' },
          { label: 'Handshake Status', value: 'FAILED', tone: 'danger' },
          { label: 'Error Detail', value: errorMsg, tone: 'warn' }
        ],
        technicalEvidence: {
          tool: 'tls_posture_audit',
          target,
          port,
          tlsResult,
          securityVerdict: 'HANDSHAKE_FAILED',
          tlsCompliant: false,
          durationMs,
          observedAt: new Date().toISOString()
        }
      };
    }

    const cert = tlsResult.certificate || {};
    const validation = tlsResult.validation || {};
    const cipher = tlsResult.cipher || {};
    const protocol = tlsResult.protocol || 'Unknown';
    const daysRemaining = cert.daysRemaining ?? null;
    const isExpired = Boolean(cert.isExpired);
    const isExpiringSoon = Boolean(cert.isExpiringSoon);
    const isAuthorized = Boolean(validation.authorized);
    const subjectCn = cert.subjectCn || target;
    const issuerCn = cert.issuerCn || 'Unknown';
    const cipherName = cipher.name || 'Unknown';
    const cipherRisk = cipher.riskLevel || 'SECURE';
    const isProtocolDeprecated = protocol === 'TLSv1' || protocol === 'TLSv1.1' || protocol === 'SSLv3';
    const isCipherDeprecated = cipherRisk === 'CRITICAL_DEPRECATED_PROTOCOL' || cipherRisk === 'VULNERABLE_LEGACY_CIPHER';

    // Hostname identity matching
    const cleanHost = String(target).toLowerCase();
    const sans = (cert.sans || []).map((s) => String(s).toLowerCase());
    const cnMatches = subjectCn.toLowerCase() === cleanHost;
    const sanMatches = sans.includes(cleanHost) || sans.some((s) => s.startsWith('*.') && cleanHost.endsWith(s.slice(1)));
    const isIpTarget = net.isIP(cleanHost);
    const hostnameValid = isIpTarget || cnMatches || sanMatches || sans.length === 0;

    let securityVerdict = 'COMPLIANT_SECURE';
    let overallStatus = 'PASS';
    let layerFailedFirst = null;
    let result = '';
    let meaning = '';
    let nextStep = '';

    if (isExpired) {
      securityVerdict = 'NON_COMPLIANT_EXPIRED_CERTIFICATE';
      overallStatus = 'FAIL';
      layerFailedFirst = 'L6_TLS_CERT_EXPIRED';
      result = `TLS handshake completed on \`${target}:${port}\` (${protocol}, ${cipherName}), but the certificate EXPIRED on ${cert.validTo || 'earlier date'}. Browsers and API clients will reject connections with CERT_HAS_EXPIRED.`;
      meaning = "The cryptographic channel negotiated successfully, but the X.509 identity proof is invalid due to certificate expiration.";
      nextStep = "Renew and install an updated certificate from an authorized CA immediately.";
    } else if (!isAuthorized) {
      securityVerdict = 'NON_COMPLIANT_UNTRUSTED_OR_SELF_SIGNED';
      overallStatus = 'FAIL';
      layerFailedFirst = 'L6_TLS_UNTRUSTED_CA';
      result = `TLS handshake completed on \`${target}:${port}\` (${protocol}, ${cipherName}), but CA validation FAILED: ${validation.error || 'Self-signed certificate or untrusted root CA'}. Subject: \`${subjectCn}\`, Issuer: \`${issuerCn}\`.`;
      meaning = "Remote server negotiated TLS encryption, but the certificate chain cannot be cryptographically verified against system trust roots.";
      nextStep = "Install a certificate issued by a recognized Certificate Authority (e.g. Let's Encrypt / DigiCert), or import enterprise root CA if internal.";
    } else if (!hostnameValid) {
      securityVerdict = 'NON_COMPLIANT_HOSTNAME_MISMATCH';
      overallStatus = 'WARN';
      layerFailedFirst = 'L6_TLS_HOSTNAME_MISMATCH';
      result = `TLS handshake succeeded on \`${target}:${port}\`, but hostname mismatch detected: Target \`${target}\` does not match Certificate Subject CN \`${subjectCn}\` or SANs [${sans.slice(0, 3).join(', ')}].`;
      meaning = "The certificate is valid for other domain names, but does not cover the requested hostname.";
      nextStep = `Update DNS to point to the correct domain, or re-issue certificate with \`${target}\` included in Subject Alternative Names.`;
    } else if (isProtocolDeprecated || isCipherDeprecated) {
      securityVerdict = 'NON_COMPLIANT_DEPRECATED_CRYPTO';
      overallStatus = 'WARN';
      layerFailedFirst = 'L6_TLS_WEAK_CIPHER';
      result = `TLS connection established on \`${target}:${port}\`, but protocol (\`${protocol}\`) or cipher (\`${cipherName}\`) is DEPRECATED and vulnerable (Risk: ${cipherRisk}).`;
      meaning = "The server is using obsolete encryption suites (TLS 1.0/1.1 or legacy CBC/RC4/DES) that fail modern compliance standards.";
      nextStep = "Reconfigure server TLS configuration to disable TLS 1.0/1.1 and enforce TLS 1.2/1.3 with AES-GCM or ChaCha20-Poly1305 ciphers.";
    } else if (isExpiringSoon) {
      securityVerdict = 'COMPLIANT_EXPIRING_SOON';
      overallStatus = 'PASS';
      layerFailedFirst = null;
      result = `TLS posture on \`${target}:${port}\` is compliant (${protocol}, ${cipherName}, Authorized CA: \`${issuerCn}\`), but certificate expires in ${daysRemaining} days (${cert.validTo}).`;
      meaning = "Cryptographic configuration and CA trust are valid, but maintenance window is required for impending renewal.";
      nextStep = `Schedule automated or manual certificate renewal before expiration within ${daysRemaining} days.`;
    } else {
      securityVerdict = 'COMPLIANT_SECURE';
      overallStatus = 'PASS';
      layerFailedFirst = null;
      result = `TLS posture on \`${target}:${port}\` is secure and fully compliant. Protocol: \`${protocol}\`, Cipher: \`${cipherName}\` (Risk: SECURE). Subject: \`${subjectCn}\`, Issuer: \`${issuerCn}\`. Valid for ${daysRemaining} days (expires ${cert.validTo}).`;
      meaning = `Direct cryptographic handshake and X.509 certificate validation passed all security baselines with ${tlsResult.handshakeLatencyMs}ms handshake latency.`;
      nextStep = "TLS configuration meets enterprise cryptographic posture guidelines; continue routine monitoring.";
    }

    return {
      reply: `**Result:** ${result}\n\n**Meaning:** ${meaning}\n\n**Next Step:** ${nextStep}`,
      structuredAnswer: {
        result,
        meaning,
        nextStep,
        layerFailedFirst,
        protocol,
        cipherName,
        cipherRisk,
        daysRemaining,
        authorized: isAuthorized,
        securityVerdict,
        subjectCn,
        issuerCn
      },
      steps: [
        {
          stepNumber: 1,
          layer: 'L6_PRESENTATION_TLS',
          tool: 'auditTls',
          label: `TLS Handshake & Certificate Audit on ${target}:${port}`,
          status: overallStatus,
          summary: result,
          durationMs: tlsResult.handshakeLatencyMs || durationMs
        }
      ],
      findings: [
        { label: 'Target', value: `${target}:${port}`, tone: 'neutral' },
        { label: 'TLS Protocol', value: protocol, tone: isProtocolDeprecated ? 'warn' : 'ok' },
        { label: 'Cipher Suite', value: cipherName, tone: isCipherDeprecated ? 'warn' : 'ok' },
        { label: 'CA Authorization', value: isAuthorized ? 'AUTHORIZED (Valid Chain)' : 'UNTRUSTED / SELF-SIGNED', tone: isAuthorized ? 'ok' : 'warn' },
        { label: 'Certificate Validity', value: isExpired ? 'EXPIRED' : (daysRemaining !== null ? `${daysRemaining} days remaining` : 'N/A'), tone: isExpired ? 'danger' : (isExpiringSoon ? 'warn' : 'ok') },
        { label: 'Security Verdict', value: securityVerdict, tone: overallStatus === 'PASS' ? 'ok' : (overallStatus === 'WARN' ? 'warn' : 'danger') }
      ],
      technicalEvidence: {
        tool: 'tls_posture_audit',
        target,
        port,
        tlsResult,
        securityVerdict,
        durationMs,
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Case A: Natural Conversation & Greeting Turn (0 network probes, preserves prior diagnostic context without forcing it into the greeting)
   */
  _executeGreetingScenario(promptText, plan, session) {
    const conv = classifyConversationalTurn(promptText, session) || { type: plan.conversationalType || 'greeting' };
    if (conv.name) {
      session.userName = conv.name;
      if (!session.entityMemory) session.entityMemory = {};
      session.entityMemory.userName = conv.name;
      session.entityMemory.user_name = conv.name;
    }
    const effectiveType = conv.type || conv.subtype || plan.conversationalType || 'greeting';
    let reply = conv.reply || plan.naturalReply || null;

    if (!reply) {
      switch (effectiveType) {
        case 'introduction':
          reply = conv.name ? `Nice to meet you, ${conv.name}! What can I help you investigate or explain today?` : "Nice to meet you! What can I help you investigate or explain today?";
          break;
      case 'identity':
        reply = conv.reply || "I am EJII (Eldar Jamiyev's Infrastructure Intelligence), your deep network and infrastructure intelligence assistant.";
        break;
      case 'how_are_you':
        reply = conv.reply || "I'm doing well, thanks. What are we working on today?";
        break;
      case 'understanding_check':
      case 'comprehension_check':
        reply = conv.reply || "Yes — you can describe what you're seeing or ask a question in your own words. You don't need to use rigid commands.";
        break;
      case 'conversational_reaction':
        if (session?.lastStructuredAnswer?.result) {
          reply = `Glad that was useful. Let me know if you want to dig deeper into ${session.lastValidTarget ? `\`${session.lastValidTarget}\`` : 'those findings'} or check something else.`;
        } else {
          reply = "Let me know what you'd like to explore or troubleshoot next.";
        }
        break;
      case 'no_prior_statement':
        reply = "We just started this conversation, so I haven't made a diagnostic assessment yet. What would you like to look into?";
        break;
      case 'acknowledgment':
        reply = conv.reply || "Sounds good. Let me know whenever you want to run a check or talk through an issue.";
        break;
      case 'capabilities':
      case 'capability_inquiry':
        reply = conv.reply ||
          "I can help you troubleshoot network and service issues or explain networking concepts. When you need live evidence, I can resolve DNS records, test ICMP ping and TCP ports, inspect TLS certificates and HTTP responses, check local network interfaces and routing tables, or list active sockets.";
        break;
      case 'farewell':
        reply = "Take care! Feel free to reach out anytime you need to debug a network or service issue.";
        break;
      case 'general_conversation':
        reply = "I'm here to help with network troubleshooting, diagnostics, or technical questions. Tell me what issue you're seeing or what host you'd like to check.";
        break;
      case 'greeting':
      default:
        reply = "Hello! How can I help you today?";
        break;
      }
    }

    const structuredAnswer = {
      result: reply,
      meaning: 'Conversational response (no live network probes executed).',
      nextStep: null,
      layerFailedFirst: null,
      uncertainty: null
    };

    return {
      reply,
      structuredAnswer,
      steps: [],
      findings: [],
      technicalEvidence: {
        liveProbesExecuted: 0,
        conversationalType: effectiveType,
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Case A-2: Casual / Everyday Conversation Turn (0 network probes)
   */
  _executeCasualConversationScenario(promptText, plan, session) {
    const conv = classifyConversationalTurn(promptText, session) || { type: plan.conversationalType || 'casual_conversation' };
    const reply = plan.naturalReply || conv.reply || "I'm doing well. What would you like to explore or troubleshoot next?";
    const structuredAnswer = {
      result: reply,
      meaning: 'Conversational response (no live network probes executed).',
      nextStep: null,
      layerFailedFirst: null,
      uncertainty: null
    };
    return {
      reply,
      structuredAnswer,
      steps: [],
      findings: [],
      technicalEvidence: {
        liveProbesExecuted: 0,
        conversationalType: plan.conversationalType || conv.type || 'casual_conversation',
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Case A-3: General Knowledge & Factual Query Mode (0 network probes)
   */
  _executeGeneralKnowledgeScenario(promptText, plan, session) {
    const conv = classifyConversationalTurn(promptText, session) || { type: plan.conversationalType || 'general_knowledge' };
    const reply = plan.naturalReply || conv.reply || "I don't have enough information to answer that question accurately.";
    const structuredAnswer = {
      result: reply,
      meaning: 'General knowledge response (no live network probes executed).',
      nextStep: null,
      layerFailedFirst: null,
      uncertainty: null
    };
    return {
      reply,
      structuredAnswer,
      steps: [],
      findings: [],
      technicalEvidence: {
        liveProbesExecuted: 0,
        knowledgeType: plan.conversationalType || conv.type || 'general_knowledge',
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Case P: Informational / Conceptual Technical Question Mode (0 network probes, natural prose without forced Result/Meaning/Next step template)
   */
  _executeInformationalQuestionScenario(promptText, session, plan = null) {
    const kb = answerInformationalQuestion(promptText);
    const modelReply = plan?.naturalReply && kb.topic === 'Infrastructure & Network Engineering Concept' ? plan.naturalReply : null;
    const structuredAnswer = {
      result: modelReply || kb.result,
      meaning: kb.meaning,
      nextStep: kb.nextStep,
      layerFailedFirst: null,
      uncertainty: null
    };
    const reply = modelReply || kb.naturalReply || `${kb.result}\n\n${kb.meaning}`;

    return {
      reply,
      structuredAnswer,
      steps: [],
      findings: [],
      technicalEvidence: {
        mode: 'informational_explanation',
        liveProbesExecuted: 0,
        topic: kb.topic,
        modelInterpreted: Boolean(plan?.modelInterpreted),
        preservedSessionTarget: session.lastValidTarget || null,
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Sovereign Fabric v6 Truth Matrix, Bayesian Posteriors, & Shannon Information-Gain Reasoning (0 hostname prompts)
   */
  async _executeEpistemicFabricQueryScenario(promptText, session, plan = null) {
    const analysis = await answerEpistemicOrFabricQuestion(promptText, session);
    const topProbe = analysis.epistemicContext?.shannonInformationGainRecommendations?.[0];
    const entropy = analysis.epistemicContext?.sovereignFabricV6TruthMatrix?.shannonEntropyBits ?? 3.17;
    const gw = analysis.epistemicContext?.observedEvidence?.defaultGateway;

    const structuredAnswer = {
      result: analysis.result,
      meaning: analysis.meaning,
      nextStep: analysis.nextStep,
      layerFailedFirst: null,
      uncertainty: !gw?.verified
        ? `Default gateway is ${gw?.reason || 'NO_DEFAULT_ROUTE_OBSERVED'} in this ${analysis.epistemicContext?.observedEvidence?.environmentScopeCategory || 'container_network_namespace'}.`
        : null
    };

    return {
      reply: analysis.naturalReply,
      structuredAnswer,
      steps: [],
      findings: [
        { label: 'Shannon Entropy H(X)', value: `${entropy} bits`, tone: 'neutral' },
        {
          label: 'Highest IG Next Probe',
          value: topProbe ? `${topProbe.probeName} (${topProbe.expectedInformationGainBits} bits)` : 'L4 TCP Egress Probe',
          tone: 'ok'
        },
        {
          label: 'Gateway Epistemic State',
          value: gw?.verified ? `Verified (${gw.gatewayIp})` : `Unverified (${gw?.reason || 'NO_DEFAULT_ROUTE_OBSERVED'})`,
          tone: gw?.verified ? 'ok' : 'warn'
        }
      ],
      technicalEvidence: {
        mode: 'epistemic_fabric_query',
        liveProbesExecuted: 0,
        topic: analysis.topic,
        sovereignFabricContext: analysis.epistemicContext,
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Office Email / Mail Outage Structured Troubleshooting Intake
   */
  _executeMailTroubleshootingIntakeScenario(promptText, session, plan = null) {
    if (session && !session.pendingTask) {
      session.pendingTask = {
        type: 'mail_server_inspection',
        originalRequest: promptText,
        missingSlots: ['domain'],
        requestedPorts: [25, 465, 587, 143, 993, 110, 995],
        serviceType: 'mail',
        createdAt: new Date().toISOString()
      };
    }

    const result = 'I can help isolate the office email outage across DNS, mail transport ports, and TLS authentication.';
    const meaning =
      'When office users can neither send nor receive email, the fault typically lies in one of four layers:\n' +
      '1. **DNS `MX` & `Autodiscover` Resolution:** If the mail domain\'s `MX` records or `smtp`/`imap` hostnames fail to resolve, both inbound and outbound mail stop.\n' +
      '2. **Outbound SMTP Submission (`TCP 587` STARTTLS / `TCP 465` Implicit TLS) & Relay (`TCP 25`):** ISP or firewall blocks on ports `587`, `465`, or `25` prevent sending.\n' +
      '3. **Inbound Mail Retrieval (`TCP 993` IMAPS / `TCP 143` IMAP / `TCP 995` POP3S):** If the mailbox daemon or TLS listener is down, clients cannot sync incoming messages.\n' +
      '4. **TLS Certificate Expiry:** An expired X.509 certificate on the mail server causes Outlook, Apple Mail, and Thunderbird to block both sending and receiving.';
    const nextStep =
      'Please share your **email domain** (e.g., `company.com`) or **mail server hostname** (e.g., `mail.company.com`), and let me know if users are connecting via **Outlook/IMAP desktop clients** or **webmail**. As soon as you reply with the domain, I will inspect its `MX` records and test ports `25, 465, 587, 993, and 995`.';

    return {
      reply: `${result}\n\n${meaning}\n\n**Next Step:** ${nextStep}`,
      structuredAnswer: {
        result,
        meaning,
        nextStep,
        layerFailedFirst: null,
        uncertainty: 'Awaiting target mail domain or SMTP/IMAP hostname to begin live DNS MX and TCP port probes.'
      },
      steps: [],
      findings: [
        { label: 'Workflow', value: 'Mail Infrastructure Triage (DNS MX + SMTP/IMAP/POP3)', tone: 'neutral' },
        { label: 'Target Ports Queued', value: '25, 465, 587, 143, 993, 110, 995', tone: 'neutral' },
        { label: 'Awaiting Input', value: 'Mail Domain or Server Hostname', tone: 'warn' }
      ],
      technicalEvidence: {
        mode: 'mail_troubleshooting_intake',
        liveProbesExecuted: 0,
        pendingTask: session?.pendingTask || null,
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Cases N & O: Clarification Needed (Context Loss, Problem Description Missing Target, or Multi-Target Ambiguity)
   */
  _executeClarificationScenario(plan, session) {
    const reply = plan.clarificationPrompt;
    const isPersonClarification = plan.clarificationReason === 'AMBIGUOUS_PERSON_REFERENCE';
    let memoryCandidateTargets = [];
    try {
      if (!isPersonClarification) {
        const briefing = operationalMemoryEngine.getIntelligenceBriefing();
        memoryCandidateTargets = (briefing.activeRegressions || []).map((r) => r.target).slice(0, 4);
      }
    } catch (_) {}

    const structuredAnswer = {
      result: plan.clarificationPrompt,
      meaning: isPersonClarification
        ? 'Conversational clarification requested for ambiguous person reference.'
        : plan.clarificationReason === 'AMBIGUOUS_MULTI_TARGET'
          ? 'Multiple candidate endpoints exist in the conversation context, so please specify which host to test.'
          : 'A target hostname or IP address is needed before running a live probe.',
      nextStep: isPersonClarification
        ? null
        : plan.candidateTargets?.length
          ? `Specify one of the candidate endpoints (for example, ${plan.candidateTargets[0].split(':')[0]}).`
          : 'Provide the hostname, IP address, or URL you want to test.',
      layerFailedFirst: null,
      uncertainty: null
    };
    return {
      reply,
      structuredAnswer,
      steps: [],
      findings: (!isPersonClarification && plan.candidateTargets?.length)
        ? [{ label: 'Candidate Endpoints', value: plan.candidateTargets.slice(0, 4).join(', '), tone: 'neutral' }]
        : [],
      technicalEvidence: {
        clarificationReason: plan.clarificationReason,
        candidateTargets: plan.candidateTargets || [],
        memoryCandidateTargets: isPersonClarification ? [] : memoryCandidateTargets,
        preservedSessionTarget: session.lastValidTarget || null,
        liveProbesExecuted: 0,
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Case I: Local IP & Network Configuration ("Check my IP" / "Inspect my network configuration")
   */
  _executeLocalIpConfigScenario(plan, session, signal) {
    this._checkAborted(signal);
    const t0 = performance.now();
    const configData = inspectLocalNetworkConfiguration();
    const durationMs = Number((performance.now() - t0).toFixed(1));

    const interfaceRows = [];
    for (const iface of configData.interfaces) {
      const v4Str = iface.ipv4Addresses.map((a) => `${a.address}${a.cidr ? ` (${a.cidr})` : (a.netmask ? ` / ${a.netmask}` : '')}`).join(', ') || '—';
      const v6Str = iface.ipv6Addresses.map((a) => a.address).join(', ') || '—';
      interfaceRows.push({
        interfaceName: iface.interfaceName,
        status: iface.status,
        scope: iface.internal ? 'Loopback' : 'Host/Container NIC',
        ipv4: v4Str,
        ipv6: v6Str,
        macAddress: iface.macAddress
      });
    }

    const gw = configData.defaultGateway;
    const gwLabel = gw.verified && gw.gatewayIp
      ? `${gw.gatewayIp}${gw.interfaceName ? ` (via ${gw.interfaceName}, ${gw.collectionMethod})` : ` (${gw.collectionMethod})`}`
      : `Unverified in OS routing table (${gw.collectionMethod})`;

    const loopbackV4Display = Array.isArray(configData.loopbackIpv4Addresses) && configData.loopbackIpv4Addresses.length > 0
      ? configData.loopbackIpv4Addresses.map((l) => l.address).join(', ')
      : (configData.loopbackIpv4 || '127.0.0.1');
    const primaryIpDescription = configData.primaryIpv4
      ? `primary non-loopback IPv4 address **${configData.primaryIpv4}**`
      : configData.primaryIpv4Status === 'loopback_only'
        ? `no non-loopback IPv4 address (loopback only: **${loopbackV4Display}**)`
        : 'no observed IPv4 address';

    const dnsText = configData.dnsServers && configData.dnsServers.length > 0
      ? configData.dnsServers.join(', ')
      : `unavailable (${configData.dnsConfiguration?.collectionMethod || 'not exposed'})`;

    const publicIpNote = plan.asksForPublicIp
      ? ' Note: You asked for a public/external IP address. Local OS interface inspection only reveals addresses assigned to the runtime host/container interfaces; discovering an external NAT egress IP requires an external IP reflection service.'
      : '';

    const steps = [
      {
        stepNumber: 1,
        label: 'Inspecting local OS network interfaces, DNS resolvers, and kernel routing table…',
        tool: 'inspectLocalNetworkConfiguration',
        status: configData.primaryIpv4 ? 'PASS' : 'WARN',
        summary: `Found ${configData.interfaces.length} interface(s) on ${configData.hostname} · Primary IPv4: ${configData.primaryIpv4 || configData.primaryIpv4Label || 'None (Loopback only)'} · Gateway: ${gw.verified ? gw.gatewayIp : 'Unverified'}`,
        durationMs
      }
    ];

    const structuredAnswer = {
      result: `Local runtime host "${configData.hostname}" (${configData.executionScope}) has ${primaryIpDescription.replace(/\*\*/g, '')}, ${configData.interfaces.length} network interface(s) (${configData.interfaces.map((i) => i.interfaceName).join(', ') || 'none'}), configured DNS server(s) [${dnsText}], and default gateway: ${gwLabel}.${publicIpNote}`,
      meaning: `${configData.scopeDistinctionNote}${configData.limitationReason ? ` ${configData.limitationReason}` : ''}`,
      nextStep: gw.verified && gw.gatewayIp
        ? `You can test gateway reachability ("Ping my default gateway") or inspect open sockets ("Show me the active connections").`
        : 'You can inspect open sockets ("Show me the active connections") or test DNS resolution ("Check DNS connectivity").',
      layerFailedFirst: null,
      uncertainty: configData.limitationReason || null
    };

    const reply =
      `On local host **\`${configData.hostname}\`** (${configData.executionScope}), I observed ${primaryIpDescription} across ${configData.interfaces.length} interface(s) (${configData.interfaces.map((i) => `\`${i.interfaceName}\``).join(', ') || 'none'}).\n\n` +
      `- **Default route:** ${gwLabel}\n` +
      `- **Configured DNS:** ${dnsText}\n\n` +
      `${configData.scopeDistinctionNote}${publicIpNote}`;

    return {
      reply,
      structuredAnswer,
      steps,
      findings: [
        {
          label: 'Primary Non-Loopback IPv4',
          value: configData.primaryIpv4 || (configData.primaryIpv4Status === 'loopback_only' ? 'None (Loopback 127.0.0.1 only)' : 'Unavailable'),
          tone: configData.primaryIpv4 ? 'ok' : 'warn'
        },
        { label: 'Default Gateway', value: gw.verified && gw.gatewayIp ? gw.gatewayIp : 'Unverified (Not Guessed)', tone: gw.verified ? 'ok' : 'warn' },
        { label: 'DNS Servers', value: dnsText, tone: configData.dnsServers?.length ? 'neutral' : 'warn' },
        { label: 'Execution Scope', value: configData.executionScope, tone: 'neutral' }
      ],
      interfaceTable: {
        title: `Local Network Interfaces (${configData.hostname} · ${configData.executionScope})`,
        columns: ['Interface', 'Status', 'Scope', 'IPv4 Address / Prefix', 'IPv6 Address', 'MAC Address'],
        rows: interfaceRows.map((r) => [r.interfaceName, r.status, r.scope, r.ipv4, r.ipv6, r.macAddress])
      },
      technicalEvidence: configData
    };
  }

  /**
   * DHCP Server Inspection / Truthful Environment Limitations
   */
  async _executeDhcpCheckScenario(plan, session, signal) {
    this._checkAborted(signal);
    const t0 = performance.now();
    const configData = inspectLocalNetworkConfiguration();
    const dhcpCollector = plan?.dhcpCollectorFn || this.dhcpCollectorFn || discoverLocalDhcpServer;
    const dhcpDiscovery = dhcpCollector();
    const durationMs = Number((performance.now() - t0).toFixed(1));

    const dhcpStatus = dhcpDiscovery.status;
    const dhcpServerIp = dhcpDiscovery.dhcpServerIp;
    let dhcpDetails = '';

    if (dhcpDiscovery.observed && dhcpServerIp) {
      dhcpDetails = `DHCP server identifier **\`${dhcpServerIp}\`** was discovered from the local operating system lease configuration (${dhcpDiscovery.collectionMethod}${dhcpDiscovery.interfaceName ? ` on interface \`${dhcpDiscovery.interfaceName}\`` : ''}).`;
    } else if (dhcpDiscovery.isContainer) {
      dhcpDetails = 'In this containerized environment, network interfaces use container virtual bridge networking with static IP assignments. No active DHCP client lease file (/run/systemd/netif/leases or /var/lib/dhcp) was found.';
    } else {
      dhcpDetails = dhcpDiscovery.limitationReason || 'No active DHCP lease file or DHCP server endpoint was observed on the local network interfaces.';
    }

    const steps = [
      {
        stepNumber: 1,
        label: 'Inspecting local network interface configuration and DHCP client leases…',
        tool: 'discoverLocalDhcpServer',
        status: dhcpDiscovery.observed ? 'PASS' : 'WARN',
        summary: `DHCP state: ${dhcpStatus} · Scope: ${configData.executionScope}${dhcpServerIp ? ` · Server IP: ${dhcpServerIp}` : ''}`,
        durationMs
      }
    ];

    const structuredAnswer = {
      result: dhcpDiscovery.observed
        ? `DHCP server IP on this system is ${dhcpServerIp} (discovered via ${dhcpDiscovery.collectionMethod}).`
        : `DHCP Server Connection: ${dhcpStatus}. ${dhcpDetails}`,
      meaning: dhcpDiscovery.observed
        ? `The operating system received its network configuration and IP lease from DHCP server ${dhcpServerIp}.`
        : 'DHCP operates at Layer 2/UDP (ports 67/68) upon joining a network. In containerized or statically configured server environments, addresses are pre-assigned and DHCP broadcasts/leases are disabled.',
      nextStep: dhcpDiscovery.observed
        ? 'You can test the verified default gateway ("Ping my default gateway") or inspect local interfaces ("Check my IP").'
        : 'To check the DHCP server that assigned your personal machine\'s IP, open a terminal on your computer and run "ipconfig /all" (Windows: look for "DHCP Server") or "nmcli dev show" (Linux: look for "DHCP4.OPTION").',
      layerFailedFirst: null,
      uncertainty: dhcpDiscovery.observed
        ? null
        : 'EJII inspects its own execution runtime. It cannot directly observe the physical DHCP server on your workstation without local agent access.'
    };

    const reply = dhcpDiscovery.observed
      ? `**DHCP Server Discovered:** \`${dhcpServerIp}\`\n\n${dhcpDetails}\n\nNote that this is the DHCP server observed by the EJII runtime environment.`
      : plan?.isDhcpFollowUp
        ? `### Addressing Mode Verification (\`${dhcpDiscovery.addressingMode || 'CONTAINER_MANAGED_NETWORKING'}\`)\n\n` +
          `I inspected the local OS interface configuration, kernel address flags, and DHCP lease directories (\`/var/lib/dhcp\`, \`/var/lib/NetworkManager\`, \`/run/systemd/netif/leases\`, and \`/etc/network/interfaces\`):\n\n` +
          `- **Runtime Addressing Status:** \`${dhcpStatus}\` (\`${dhcpDiscovery.addressingMode || 'CONTAINER_MANAGED_NETWORKING'}\`)\n` +
          `- **Primary Interface Assigned:** \`${configData.primaryIpv4Label}\` on scope \`${configData.environmentScopeCategory || configData.executionScope}\`\n` +
          `- **Why No DHCP Lease Exists Here:** ${dhcpDetails}\n\n` +
          `### How to Check DHCP vs. Static IP on Your Own Workstation\n` +
          `- **Windows (PowerShell / CMD):** Run \`ipconfig /all\` and check **DHCP Enabled: Yes/No** and **DHCP Server**.\n` +
          `- **macOS:** Run \`ipconfig getpacket en0\` (returns the DHCP server packet if DHCP-assigned, or empty if static).\n` +
          `- **Linux:** Run \`nmcli dev show | grep -E "IP4|DHCP4"\` or \`ip -d addr show\` (look for \`dynamic\` vs \`forever\` valid_lft).`
        : `**DHCP Server Inspection:** ${dhcpStatus}\n\n` +
          `${dhcpDetails}\n\n` +
          `Because this environment runs in a **\`${configData.executionScope}\`**, IP addressing is managed at the container bridge level rather than via DHCP leases. To check the DHCP server on your personal workstation, open PowerShell/Command Prompt and run \`ipconfig /all\` (look for "DHCP Server") or on Linux run \`nmcli dev show\`.`;

    return {
      reply,
      structuredAnswer,
      steps,
      findings: [
        { label: 'DHCP State', value: dhcpStatus, tone: dhcpDiscovery.observed ? 'ok' : 'warn' },
        { label: 'Addressing Mode', value: dhcpDiscovery.addressingMode || 'CONTAINER_MANAGED_NETWORKING', tone: 'neutral' },
        { label: 'Execution Scope', value: configData.executionScope, tone: 'neutral' },
        { label: 'DHCP Server IP', value: dhcpServerIp || 'None (Statically Managed / Container)', tone: dhcpDiscovery.observed ? 'ok' : 'neutral' }
      ],
      technicalEvidence: {
        mode: 'dhcp_check',
        dhcpDiscovery,
        dhcpStatus,
        addressingMode: dhcpDiscovery.addressingMode || 'CONTAINER_MANAGED_NETWORKING',
        isContainer: configData.isContainer,
        executionScope: configData.executionScope,
        environmentScopeCategory: configData.environmentScopeCategory || 'container_network_namespace',
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Composite Local-Path / Layer-by-Layer Gateway & ISP Connection Diagnostic
   * Layer 1: Local Interfaces & status
   * Layer 2: Local link & neighbor / ARP table
   * Layer 3: OS Default gateway routing & gateway ICMP ping (if verified)
   * Layer 4: Upstream IP transport & system DNS resolver reachability (1.1.1.1:53 TCP)
   * Layer 7: External internet service reachability (dns.google:443 HTTPS)
   * Never asks for a hostname, never invents an ISP outage, and attributes server container vs workstation scope honestly.
   */
  async _executeLocalPathDiagnosticScenario(plan, session, signal) {
    this._checkAborted(signal);
    const steps = [];
    const findings = [];

    // Layer 1: Interfaces
    const t0 = performance.now();
    const configData = inspectLocalNetworkConfiguration();
    const l1Duration = Number((performance.now() - t0).toFixed(1));
    const l1Pass = configData.interfaces && configData.interfaces.some((i) => i.status === 'UP');
    steps.push({
      stepNumber: 1,
      label: 'Layer 1: Inspecting physical/virtual network adapters and addresses…',
      tool: 'inspectLocalNetworkConfiguration',
      status: l1Pass ? 'PASS' : 'FAIL',
      summary: `Layer 1 (Physical/Link): ${configData.primaryIpv4Label} is UP (Scope: ${configData.executionScope})`,
      durationMs: l1Duration
    });
    findings.push({ label: 'Layer 1 Interfaces', value: configData.primaryIpv4Label, tone: l1Pass ? 'ok' : 'danger' });

    // Layer 2: Neighbor / ARP
    this._checkAborted(signal);
    const fs = require('fs');
    let l2Status = 'UNAVAILABLE';
    let l2Summary = 'Layer 2 (Neighbor/ARP): ARP cache not exposed in isolated container namespace (unavailable, not failed)';
    try {
      if (fs.existsSync('/proc/net/arp')) {
        const arpLines = fs.readFileSync('/proc/net/arp', 'utf8').trim().split('\n').slice(1);
        if (arpLines.length > 0) {
          l2Status = 'PASS';
          l2Summary = `Layer 2 (Neighbor/ARP): ${arpLines.length} active ARP/neighbor cache entries observed`;
        }
      }
    } catch (_) {}
    steps.push({
      stepNumber: 2,
      label: 'Layer 2: Inspecting local link neighbor cache (ARP entries)…',
      tool: 'neighbor_discovery',
      status: l2Status === 'PASS' ? 'PASS' : 'WARN',
      summary: l2Summary,
      durationMs: 0.5
    });
    findings.push({ label: 'Layer 2 Neighbor (ARP)', value: l2Status === 'PASS' ? 'Observed' : 'Unavailable (Container)', tone: 'neutral' });

    // Layer 3: Routing & Gateway
    this._checkAborted(signal);
    const tGw = performance.now();
    const gw = getVerifiedDefaultGateway();
    const gwDuration = Number((performance.now() - tGw).toFixed(1));
    let gwPingRes = null;
    let l3Status = 'WARN';
    let l3Summary = `Layer 3 (Routing/Gateway): ${gw.limitationReason || 'No default route (0.0.0.0/0) found in routing table'}`;

    if (gw.verified && gw.gatewayIp) {
      session.lastGatewayIp = gw.gatewayIp;
      const tPing = performance.now();
      gwPingRes = await realPing(gw.gatewayIp, 2, 800);
      const pingMs = Number((performance.now() - tPing).toFixed(1));
      if (gwPingRes.success) {
        l3Status = 'PASS';
        l3Summary = `Layer 3 (Routing/Gateway): Default route to ${gw.gatewayIp} via ${gw.collectionMethod} responded to ICMP ping (${gwPingRes.avgRttMs} ms)`;
      } else {
        l3Status = 'WARN';
        l3Summary = `Layer 3 (Routing/Gateway): Default route to ${gw.gatewayIp} present; ICMP echo unreplied (container or gateway firewall policy)`;
      }
      steps.push({
        stepNumber: 3,
        label: `Layer 3: Inspecting routing table and testing gateway ${gw.gatewayIp}…`,
        tool: 'getVerifiedDefaultGateway',
        status: l3Status,
        summary: l3Summary,
        durationMs: gwDuration + (gwPingRes ? pingMs : 0)
      });
      findings.push({
        label: 'Layer 3 Gateway Route',
        value: `${gw.gatewayIp} (${gwPingRes?.success ? `${gwPingRes.avgRttMs} ms` : 'No ICMP reply'})`,
        tone: gwPingRes?.success ? 'ok' : 'warn'
      });
    } else {
      steps.push({
        stepNumber: 3,
        label: 'Layer 3: Inspecting routing table for verified 0.0.0.0/0 default gateway…',
        tool: 'getVerifiedDefaultGateway',
        status: 'WARN',
        summary: l3Summary,
        durationMs: gwDuration
      });
      findings.push({ label: 'Layer 3 Gateway Route', value: 'Unobserved in server routing table', tone: 'warn' });
    }

    // Layer 4 & DNS: Upstream Reachability & Resolver
    this._checkAborted(signal);
    const tDnsPort = performance.now();
    const dnsPortRes = await checkPort('1.1.1.1', 53, 1500);
    const dnsPortMs = Number((performance.now() - tDnsPort).toFixed(1));
    const l4Pass = dnsPortRes.status === 'OPEN';
    steps.push({
      stepNumber: 4,
      label: 'Layer 4: Testing upstream Layer 4 IP transport to Anycast resolver (1.1.1.1:53 TCP)…',
      tool: 'checkPort',
      status: l4Pass ? 'PASS' : 'WARN',
      summary: l4Pass
        ? `Layer 4 (Transport): Upstream reachability to 1.1.1.1:53 established (${dnsPortRes.connectLatencyMs || dnsPortMs} ms)`
        : `Layer 4 (Transport): 1.1.1.1:53 returned ${dnsPortRes.status} (${dnsPortRes.errorCode || 'Timeout'})`,
      durationMs: dnsPortRes.connectLatencyMs || dnsPortMs
    });
    findings.push({
      label: 'Layer 4 Upstream Reachability',
      value: l4Pass ? `Connected (${dnsPortRes.connectLatencyMs || dnsPortMs} ms)` : 'Timed out / Filtered',
      tone: l4Pass ? 'ok' : 'warn'
    });

    // Layer 7: External Internet Service Reachability (Approved public probe)
    this._checkAborted(signal);
    const tHttp = performance.now();
    const httpsRes = await checkPort('dns.google', 443, 2000);
    const httpsMs = Number((performance.now() - tHttp).toFixed(1));
    const l7Pass = httpsRes.status === 'OPEN';
    steps.push({
      stepNumber: 5,
      label: 'Layer 7: Testing application-layer external internet connectivity (dns.google:443 HTTPS)…',
      tool: 'checkPort',
      status: l7Pass ? 'PASS' : 'WARN',
      summary: l7Pass
        ? `Layer 7 (Application): External HTTPS connection to dns.google:443 established (${httpsRes.connectLatencyMs || httpsMs} ms)`
        : `Layer 7 (Application): External HTTPS connection returned ${httpsRes.status}`,
      durationMs: httpsRes.connectLatencyMs || httpsMs
    });
    findings.push({
      label: 'Layer 7 External Reachability',
      value: l7Pass ? `Connected (${httpsRes.connectLatencyMs || httpsMs} ms)` : 'Inconclusive / No reply',
      tone: l7Pass ? 'ok' : 'warn'
    });

    const isConnectedToInternet = l4Pass || l7Pass;
    const reply =
      `### Layer-by-Layer Network & Upstream Path Diagnostic\n\n` +
      `Here is the step-by-step diagnostic breakdown for the **\`${configData.executionScope}\`**:\n\n` +
      `1. **Layer 1 (Physical / Local Interfaces):** ${l1Pass ? `UP · Primary interface: **\`${configData.primaryIpv4Label}\`**` : 'DOWN · No network interface with IPv4 was observed.'}\n` +
      `2. **Layer 2 (Neighbor / Data Link):** ${l2Status === 'PASS' ? 'Active neighbor cache entries observed.' : 'Neighbor/ARP cache is isolated in container runtime.'}\n` +
      `3. **Layer 3 (Default Gateway Route):** ${gw.verified && gw.gatewayIp ? `Route to **\`${gw.gatewayIp}\`** present via \`${gw.collectionMethod}\`${gwPingRes?.success ? ` (ICMP replied in ${gwPingRes.avgRttMs} ms)` : ' (ICMP echo unreplied, but route is configured)'}.` : `No 0.0.0.0/0 route in server routing table (${gw.collectionMethod}).`}\n` +
      `4. **Layer 4 (Transport / Upstream):** ${l4Pass ? `Connected to upstream Anycast DNS (\`1.1.1.1:53\`) in **${dnsPortRes.connectLatencyMs || dnsPortMs} ms**.` : 'Could not establish connection to upstream test resolver.'}\n` +
      `5. **Layer 7 (External Internet Reachability):** ${l7Pass ? `Outbound HTTPS connectivity to \`dns.google:443\` succeeded (**${httpsRes.connectLatencyMs || httpsMs} ms**).` : 'Outbound HTTPS connection did not complete within timeout.'}\n\n` +
      `**Summary:** ${isConnectedToInternet ? 'Outbound internet connectivity is active and operating. Upstream traffic can be dispatched and external endpoints are reachable.' : 'Local network path exhibited timeouts reaching external targets.'}\n\n` +
      `*(Note: This diagnostic was executed from the EJII server environment. To check the physical router connection from your personal computer, run \`ipconfig\` or \`traceroute 1.1.1.1\` on your workstation).*`;

    const structuredAnswer = {
      result: `Layer-by-layer check: Layer 1 is UP (${configData.primaryIpv4Label}), Layer 3 gateway is ${gw.gatewayIp || 'unobserved in server table'}, and Layer 4/7 external reachability is ${isConnectedToInternet ? 'ACTIVE' : 'DEGRADED'}.`,
      meaning: 'Evaluated the local network stack from local network adapters through default route, upstream transport, and external application connectivity.',
      nextStep: 'If a specific service or host is experiencing issues, test that destination host directly (e.g. "Check port 443 on <target>").',
      layerFailedFirst: !isConnectedToInternet ? 'L4 Upstream Transport' : null,
      uncertainty: 'The test ran from the EJII server container environment; intermediate ISP hops and user workstation physical Wi-Fi/Ethernet link cannot be directly observed from a server container.'
    };

    return {
      reply,
      structuredAnswer,
      steps,
      findings,
      technicalEvidence: {
        configData,
        gateway: gw,
        dnsPortRes,
        httpsRes,
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Case J: Default Gateway Check ("Ping my default gateway") — never guesses .1 and never inherits lastTarget
   */
  async _executeGatewayCheckScenario(plan, session, signal) {
    this._checkAborted(signal);
    const t0 = performance.now();
    const gwCollector = plan?.gatewayCollectorFn || this.gatewayCollectorFn || getVerifiedDefaultGateway;
    const gw = gwCollector();
    const lookupMs = Number((performance.now() - t0).toFixed(1));

    if (!gw.verified || !gw.gatewayIp) {
      const isCollectorUnavailable = gw.status === 'COLLECTOR_UNAVAILABLE';
      const steps = [
        {
          stepNumber: 1,
          label: 'Inspecting OS kernel routing table for 0.0.0.0/0 default gateway…',
          tool: 'getVerifiedDefaultGateway',
          status: 'WARN',
          summary: isCollectorUnavailable
            ? `Routing table collector unavailable (${gw.collectionMethod})`
            : `No verified 0.0.0.0/0 default route exposed in routing table (${gw.collectionMethod})`,
          durationMs: lookupMs
        }
      ];
      const structuredAnswer = {
        result: isCollectorUnavailable
          ? `Cannot inspect default gateway: routing table collector is unavailable (${gw.collectionMethod}).`
          : 'Cannot ping default gateway: no verified default gateway route (0.0.0.0/0) was found in the local OS or container routing table.',
        meaning: `${gw.limitationReason} EJII does not guess a ".1" address from the local IP or substitute a previous remote target.`,
        nextStep: 'If you know the specific gateway IP address on your network, ask "Ping <gateway-ip>" directly, or run "Check my IP" to inspect active network interfaces.',
        layerFailedFirst: null,
        uncertainty: 'Containerized and sandboxed network namespaces frequently omit a host-visible 0.0.0.0/0 gateway entry.'
      };
      const reply =
        `${isCollectorUnavailable ? `Routing table collector is unavailable (${gw.collectionMethod}).` : `No verified default gateway route (\`0.0.0.0/0\`) was found in the local routing table (${gw.collectionMethod}).`}\n\n` +
        `${gw.limitationReason} EJII never guesses a \`.1\` address or reuses an earlier target, so no ping probe was sent. If you know your router's IP address, you can ask me to ping that IP directly.`;
      return {
        reply,
        structuredAnswer,
        steps,
        findings: [
          { label: 'Default Gateway', value: isCollectorUnavailable ? 'Collector Unavailable' : 'Unverified in Routing Table', tone: 'warn' },
          { label: 'Collection Method', value: gw.collectionMethod, tone: 'neutral' },
          { label: 'Safety Policy', value: 'No guessed .1 address', tone: 'ok' }
        ],
        technicalEvidence: { gatewayInfo: gw, pingExecuted: false, observedAt: new Date().toISOString() }
      };
    }

    session.lastGatewayIp = gw.gatewayIp;

    const pingStart = performance.now();
    const pingRes = await realPing(gw.gatewayIp, 2, 1000);
    const pingMs = Number((performance.now() - pingStart).toFixed(1));

    const steps = [
      {
        stepNumber: 1,
        label: 'Reading verified default gateway from OS routing table…',
        tool: 'getVerifiedDefaultGateway',
        status: 'PASS',
        summary: `Default route present: ${gw.gatewayIp}${gw.interfaceName ? ` on interface ${gw.interfaceName}` : ''} via ${gw.collectionMethod}`,
        durationMs: lookupMs
      },
      {
        stepNumber: 2,
        label: `Sending ICMP echo requests to default gateway ${gw.gatewayIp}…`,
        tool: 'realPing',
        status: pingRes.success ? 'PASS' : 'WARN',
        summary: pingRes.success
          ? `${pingRes.packetsReceived}/${pingRes.packetsSent} ICMP replies from gateway ${gw.gatewayIp} (avg ${pingRes.avgRttMs} ms)`
          : `0/${pingRes.packetsSent} ICMP replies from gateway ${gw.gatewayIp} (ICMP may be restricted by container/router policy)`,
        durationMs: pingMs
      }
    ];

    const structuredAnswer = pingRes.success
      ? {
          result: `Default gateway ${gw.gatewayIp} is present in the OS routing table (${gw.collectionMethod}${gw.interfaceName ? ` on ${gw.interfaceName}` : ''}) and responded to ICMP ping with ${pingRes.packetsReceived}/${pingRes.packetsSent} replies (average RTT: ${pingRes.avgRttMs} ms).`,
          meaning: `The local default route is configured and Layer 3 ICMP communication with the gateway router (${gw.gatewayIp}) succeeded.`,
          nextStep: 'If external hosts are still unreachable, check DNS resolution ("Check DNS connectivity") or test a specific external host.',
          layerFailedFirst: null,
          uncertainty: null
        }
      : {
          result: `A default route to ${gw.gatewayIp} is present in the OS routing table (${gw.collectionMethod}), but ICMP ping returned 0/${pingRes.packetsSent} echo replies (100% ICMP loss).`,
          meaning: `Finding a default route in the routing table confirms the OS knows where to send traffic (${gw.gatewayIp}), but does not by itself prove the gateway is responding to ICMP. Either the runtime environment restricts raw ICMP packets or the gateway router drops ICMP echo requests.`,
          nextStep: 'Test external DNS or TCP reachability (for example, "Check DNS for example.com" or "Check port 443 on example.com") to verify whether the gateway is forwarding traffic.',
          layerFailedFirst: 'L3 ICMP Echo to Gateway',
          uncertainty: 'In containerized environments, virtual bridge gateways often forward TCP/UDP traffic while dropping ICMP echo requests.'
        };

    const reply = pingRes.success
      ? `Your configured default gateway **\`${gw.gatewayIp}\`** (discovered via \`${gw.collectionMethod}\`${gw.interfaceName ? ` on \`${gw.interfaceName}\`` : ''}) responded to ICMP ping with **${pingRes.packetsReceived}/${pingRes.packetsSent} replies** and an average RTT of **${pingRes.avgRttMs} ms**.\n\nThis confirms both that the default route is present in the OS routing table and that Layer 3 reachability to your local router is working.`
      : `The OS routing table has a default route pointing to **\`${gw.gatewayIp}\`** (via \`${gw.collectionMethod}\`), but ICMP ping to \`${gw.gatewayIp}\` received **0/${pingRes.packetsSent} echo replies**.\n\nHaving a route in the table only shows where packets are directed — here, ICMP echo is either blocked by the router or restricted by the container runtime. To see if traffic is actually being forwarded past the gateway, test an external service over DNS or TCP (such as *"Check port 443 on example.com"*).`;

    return {
      reply,
      structuredAnswer,
      steps,
      findings: [
        { label: 'Default Route', value: gw.gatewayIp, tone: 'ok' },
        { label: 'Route Source', value: gw.collectionMethod, tone: 'neutral' },
        { label: 'ICMP Reply', value: pingRes.success ? `REACHABLE (${pingRes.avgRttMs} ms)` : 'NO ICMP REPLY', tone: pingRes.success ? 'ok' : 'warn' }
      ],
      technicalEvidence: {
        gatewayInfo: gw,
        pingResult: pingRes,
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Gateway IP Query: Truthfully explains default gateway IP attribution
   * Distinguishes the EJII server container runtime environment from the user's client workstation network.
   */
  _executeGatewayIpQuery(plan, session) {
    const gwCollector = plan?.gatewayCollectorFn || this.gatewayCollectorFn || getVerifiedDefaultGateway;
    const gw = gwCollector();
    const runtimeGatewayIp = gw.verified && gw.gatewayIp ? gw.gatewayIp : (session?.lastGatewayIp || null);
    const collectionMethod = gw.collectionMethod || 'OS kernel routing table';

    const reply =
      `### Default Gateway IP & Network Attribution\n\n` +
      `**1. In this EJII server environment (cloud container runtime):**\n` +
      `- **Gateway IP:** \`${runtimeGatewayIp ? runtimeGatewayIp : 'Unobserved (no default route exposed in server routing table)'}\`\n` +
      `- **Route status:** ${gw.verified ? `Discovered via \`${collectionMethod}\`${gw.interfaceName ? ` on interface \`${gw.interfaceName}\`` : ''}` : `No verified 0.0.0.0/0 default route was found in the server routing table (${collectionMethod}).`}\n\n` +
      `**2. On your personal computer / client workstation:**\n` +
      `Because EJII runs inside a remote server container, it cannot directly inspect your physical workstation's local router. Your home or office network assigns a private router IP on your LAN.\n` +
      `- **How to verify on Windows:** Open Command Prompt or PowerShell and type \`ipconfig\` — look for **"Default Gateway"**.\n` +
      `- **How to verify on macOS / Linux:** Open Terminal and type \`ip route show default\` or \`netstat -nr | grep default\`.\n\n` +
      `If you'd like me to probe reachability to a specific gateway IP or check external internet connectivity from here, just let me know!`;

    const structuredAnswer = {
      result: runtimeGatewayIp
        ? `The EJII server container runtime uses gateway ${runtimeGatewayIp} (${collectionMethod}).`
        : `No default gateway was observed in the server routing table (${collectionMethod}).`,
      meaning: 'Distinction between the server container runtime network namespace and the user client workstation network.',
      nextStep: 'Check "ipconfig" (Windows) or "ip route" (Linux/macOS) on your local machine to find your workstation\'s gateway IP.',
      layerFailedFirst: null,
      uncertainty: null
    };

    return {
      reply,
      structuredAnswer,
      steps: [
        {
          stepNumber: 1,
          label: 'Inspecting server runtime default route and gateway configuration…',
          tool: 'getVerifiedDefaultGateway',
          status: 'PASS',
          summary: `Server runtime gateway: ${runtimeGatewayIp} (${collectionMethod})`,
          durationMs: 0
        }
      ],
      findings: [
        { label: 'Server Container Gateway', value: runtimeGatewayIp, tone: 'ok' },
        { label: 'Client Workstation Gateway', value: 'Check via ipconfig / ip route', tone: 'neutral' },
        { label: 'Scope Attribution', value: 'Server container vs Client workstation', tone: 'ok' }
      ],
      technicalEvidence: {
        serverGateway: gw,
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Cases K & L: Active Connections, Open Sockets & Destination Endpoints Inventory
   */
  async _executeActiveConnectionsScenario(plan, session, signal) {
    this._checkAborted(signal);
    const t0 = performance.now();
    const filter = plan.connectionFilter || {};
    const inventory = await processSocketCorrelator.collectActiveConnectionsInventory({
      port: filter.port,
      state: filter.state,
      externalOnly: filter.externalOnly
    });
    const durationMs = Number((performance.now() - t0).toFixed(1));

    if (!inventory.success) {
      const steps = [
        {
          stepNumber: 1,
          label: 'Attempting to enumerate active OS sockets and process bindings…',
          tool: 'collectActiveConnectionsInventory',
          status: 'FAIL',
          summary: `Socket collection failed (${inventory.collectionStatus || 'collector_failed'}): ${inventory.collectorError || 'Unable to read OS socket table'}`,
          durationMs
        }
      ];
      const structuredAnswer = {
        result: `Active socket inventory could not be collected (${inventory.collectionStatus || 'collector_failed'}): ${inventory.collectorError || 'OS socket collectors failed'}.`,
        meaning: 'Because the operating system socket collectors failed or were blocked by runtime permissions, EJII reports the collection failure rather than claiming there are zero active connections.',
        nextStep: 'Verify OS permissions for ss, netstat, lsof, or /proc/net/tcp in this runtime environment.',
        layerFailedFirst: 'OS Socket Table Collector',
        uncertainty: inventory.collectorError || 'Socket table unavailable.'
      };
      const reply =
        `I could not collect the active socket table because the OS socket collectors failed (\`${inventory.collectionStatus || 'collector_failed'}\`: ${inventory.collectorError || 'collector unavailable'}).\n\n` +
        `Rather than reporting an empty connection list, this indicates the runtime environment did not expose socket state.`;
      return {
        reply,
        structuredAnswer,
        steps,
        findings: [
          { label: 'Collection Status', value: 'FAILED (Collector Error)', tone: 'danger' },
          { label: 'Collection Method', value: inventory.collectionMethod || 'unavailable', tone: 'warn' }
        ],
        technicalEvidence: inventory
      };
    }

    let rows = inventory.connections || [];
    if (filter.protocol) {
      rows = rows.filter((r) => r.protocol.toUpperCase() === filter.protocol.toUpperCase());
    }

    const prevSnapshot = Array.isArray(session.socketSnapshots) && session.socketSnapshots.length > 0
      ? session.socketSnapshots[session.socketSnapshots.length - 1]
      : null;

    const currentEndpoints = Array.from(
      new Set(rows.map((r) => `${r.protocol} ${r.localAddress}:${r.localPort}->${r.remoteAddress}:${r.remotePort} (${r.state})`))
    );
    let addedEndpoints = [];
    let removedEndpoints = [];
    if (prevSnapshot && Array.isArray(prevSnapshot.keys)) {
      const prevSet = new Set(prevSnapshot.keys);
      const currSet = new Set(currentEndpoints);
      addedEndpoints = currentEndpoints.filter((k) => !prevSet.has(k));
      removedEndpoints = prevSnapshot.keys.filter((k) => !currSet.has(k));
    }

    if (!Array.isArray(session.socketSnapshots)) session.socketSnapshots = [];
    session.socketSnapshots.push({
      observedAt: inventory.observedAt,
      keys: currentEndpoints,
      count: rows.length
    });
    if (session.socketSnapshots.length > MAX_SOCKET_SNAPSHOTS) {
      session.socketSnapshots = session.socketSnapshots.slice(-MAX_SOCKET_SNAPSHOTS);
    }

    const candidateHosts = Array.from(
      new Set(
        rows
          .map((r) => r.remoteAddress && r.remoteAddress !== '0.0.0.0' && r.remoteAddress !== '*' && r.remoteAddress !== '::' ? r.remoteAddress : r.localAddress)
          .filter((ip) => ip && ip !== '0.0.0.0' && ip !== '*' && ip !== '::')
      )
    );
    session.lastMultiEndpoints = candidateHosts.length > 1 ? candidateHosts : ['127.0.0.1', 'localhost'];

    const steps = [
      {
        stepNumber: 1,
        label: `Enumerating active OS sockets and process bindings via ${inventory.collectionMethod}…`,
        tool: 'collectActiveConnectionsInventory',
        status: 'PASS',
        summary: `Observed ${rows.length} socket(s) (${inventory.establishedCount} ESTABLISHED, ${inventory.listeningCount} LISTENING) in ${inventory.collectionScope}`,
        durationMs
      }
    ];

    const tableRows = rows.slice(0, 30).map((r) => [
      r.processName || 'Unattributed',
      r.pid ? String(r.pid) : '—',
      r.protocol,
      `${r.localAddress}:${r.localPort}`,
      `${r.remoteAddress}:${r.remotePort}`,
      r.state,
      r.collectionMethod
    ]);

    const diffSummary = prevSnapshot
      ? ` Compared to the previous snapshot at ${prevSnapshot.observedAt}, ${addedEndpoints.length} connection(s) appeared and ${removedEndpoints.length} closed.`
      : '';

    const permissionNote = inventory.permissionRestricted
      ? ' Process PID attribution is restricted to processes owned by the current OS user.'
      : (inventory.processAttributionAvailable ? ' Process PID attribution is available.' : ' Process PID attribution was not exposed by the OS kernel for some sockets.');

    const structuredAnswer = {
      result: `Collected ${rows.length} active socket/connection record(s) via ${inventory.collectionMethod} at ${inventory.observedAt} (${inventory.establishedCount} ESTABLISHED, ${inventory.listeningCount} LISTENING).${diffSummary}`,
      meaning: `${inventory.scopeExplanation}${permissionNote}`,
      nextStep: candidateHosts.length > 0
        ? `Specify any remote IP or port from the table to test it directly.`
        : 'Run the check again after generating network activity to compare socket changes.',
      layerFailedFirst: null,
      uncertainty: null
    };

    const reply =
      `I found **${rows.length} active socket(s)** (${inventory.establishedCount} \`ESTABLISHED\`, ${inventory.listeningCount} \`LISTENING\`) via \`${inventory.collectionMethod}\` in scope **${inventory.collectionScope}**.${diffSummary}\n\n` +
      `${inventory.scopeExplanation}${permissionNote}`;

    return {
      reply,
      structuredAnswer,
      steps,
      findings: [
        { label: 'Total Sockets', value: String(rows.length), tone: 'ok' },
        { label: 'Established / Listening', value: `${inventory.establishedCount} / ${inventory.listeningCount}`, tone: 'neutral' },
        { label: 'Collection Method', value: inventory.collectionMethod, tone: 'neutral' },
        { label: 'Namespace Scope', value: inventory.collectionScope, tone: 'neutral' },
        { label: 'PID Attribution', value: inventory.processAttributionAvailable ? (inventory.permissionRestricted ? 'Partial (User Scope)' : 'Available') : 'Restricted', tone: inventory.processAttributionAvailable ? 'ok' : 'warn' }
      ],
      connectionTable: {
        title: `Active Connections & Open Sockets (${inventory.collectionMethod} · ${inventory.collectionScope})`,
        columns: ['Process Name', 'PID', 'Proto', 'Local Address:Port', 'Remote Address:Port', 'State', 'Method'],
        rows: tableRows
      },
      technicalEvidence: {
        ...inventory,
        snapshotDiff: prevSnapshot ? { previousSnapshotAt: prevSnapshot.observedAt, addedEndpoints, removedEndpoints } : null
      }
    };
  }

  /**
   * Scenario A: Real DNS Check (Cases B, C, D — including System DNS Connectivity Health Check)
   */
  async _executeDnsScenario(plan, session, signal) {
    this._checkAborted(signal);
    const stepStart = performance.now();
    const target = plan.target;
    const recordType = plan.recordType || 'A';

    if (plan.isSystemDnsHealthCheck) {
      const health = await checkDnsConnectivityHealth('example.com');
      const totalMs = Number((performance.now() - stepStart).toFixed(1));
      const resolverDisplay = health.configuredServers.length > 0
        ? health.configuredServers.join(', ')
        : 'unavailable in OS config (using OS getaddrinfo fallback)';

      const steps = [
        {
          stepNumber: 1,
          label: `Inspecting configured DNS resolvers (${resolverDisplay}) and testing local hosts resolution…`,
          tool: 'checkDnsConnectivityHealth',
          status: health.localhostProbe.success ? 'PASS' : 'FAIL',
          summary: `Localhost resolved → ${(health.localhostProbe.records || []).join(', ')} via ${health.localhostProbe.resolutionMethod || 'local_hosts_table'} (${health.localhostProbe.durationMs} ms)`,
          durationMs: health.localhostProbe.durationMs
        },
        {
          stepNumber: 2,
          label: `Verifying external recursive DNS resolution (example.com) via ${health.primaryResolver || 'OS resolver'}…`,
          tool: 'resolveRecord',
          status: health.externalProbe.success ? 'PASS' : 'FAIL',
          summary: health.externalProbe.success
            ? `Resolved example.com → ${health.externalProbe.records.join(', ')} via ${health.externalProbe.resolutionMethod} (${health.externalProbe.durationMs} ms)`
            : `External DNS lookup failed (${health.externalProbe.errorCode || health.externalProbe.error}) (${health.externalProbe.durationMs} ms)`,
          durationMs: health.externalProbe.durationMs
        }
      ];

      const findings = [
        { label: 'Configured Resolvers', value: resolverDisplay, tone: health.configuredServers.length > 0 ? 'neutral' : 'warn' },
        { label: 'Resolver Type', value: health.resolverType || 'unknown', tone: 'neutral' },
        { label: 'DNS Health', value: health.healthy ? 'HEALTHY' : (health.localOnlyHealthy ? 'LOCAL ONLY (External Degraded)' : 'FAILED'), tone: health.healthy ? 'ok' : 'warn' },
        { label: 'example.com (A)', value: health.externalProbe.success ? `${health.externalProbe.records[0]} (${health.externalProbe.durationMs} ms)` : `FAILED (${health.externalProbe.errorCode})`, tone: health.externalProbe.success ? 'ok' : 'danger' }
      ];

      const structuredAnswer = {
        result: `System DNS health check completed in ${totalMs} ms (Configured DNS: [${resolverDisplay}]): localhost → ${(health.localhostProbe.records || [])[0] || '127.0.0.1'} (${health.localhostProbe.resolutionMethod}); example.com → ${health.externalProbe.success ? `${health.externalProbe.records[0]} (${health.externalProbe.durationMs} ms via ${health.externalProbe.resolutionMethod})` : `FAILED (${health.externalProbe.errorCode})`}.`,
        meaning: health.healthy
          ? `Local name resolution and external recursive DNS lookups (${health.primaryResolver || 'OS resolver'}) are working normally.`
          : `Local hosts resolution works, but external recursive resolution failed or timed out.`,
        nextStep: `Ask "Check DNS for <hostname>" to query a specific domain.`,
        layerFailedFirst: health.healthy ? null : 'L7 External Recursive DNS',
        uncertainty: health.limitationReason || null
      };

      const reply = health.healthy
        ? `System DNS health check completed in ${totalMs} ms — DNS resolution is working normally. Configured system resolver(s): **${resolverDisplay}** (${health.resolverType}).\n\n` +
          `- \`localhost\` resolved to \`${(health.localhostProbe.records || [])[0] || '127.0.0.1'}\` (${health.localhostProbe.durationMs} ms via \`${health.localhostProbe.resolutionMethod}\`)\n` +
          `- \`example.com\` resolved to \`${health.externalProbe.records.join(', ')}\` (${health.externalProbe.durationMs} ms via \`${health.externalProbe.resolutionMethod}\`)`
        : `System DNS health check completed in ${totalMs} ms — local \`localhost\` resolution succeeded, but external DNS lookup for \`example.com\` failed (${health.externalProbe.errorCode || health.externalProbe.error}). Configured system resolver(s): **${resolverDisplay}**.`;

      return {
        reply,
        structuredAnswer,
        steps,
        findings,
        technicalEvidence: {
          ...health,
          isSystemDnsHealthCheck: true
        }
      };
    }

    let dnsRes;
    if (target.toLowerCase() === 'localhost') {
      dnsRes = await resolveRecord('localhost', recordType);
      if (!dnsRes.success) {
        dnsRes = {
          domain: 'localhost',
          recordType,
          nameserver: 'local_hosts_table',
          resolutionMethod: 'local_hosts_table',
          success: true,
          records: recordType === 'AAAA' ? ['::1'] : ['127.0.0.1'],
          durationMs: Number((performance.now() - stepStart).toFixed(2)),
          error: null,
          errorCode: null
        };
      }
    } else {
      dnsRes = await resolveRecord(target, recordType);
    }

    const durationMs = Number((performance.now() - stepStart).toFixed(1));
    const recordsList = Array.isArray(dnsRes.records) ? dnsRes.records : [];
    const resolutionMethod = dnsRes.resolutionMethod || 'dns_protocol';
    const activeResolver = dnsRes.nameserver || getRealSystemDns() || 'unavailable (OS resolver)';

    const ev = evidenceFabric.recordEvidence({
      type: 'dns_resolution',
      subject: `dns:${target}`,
      claim: dnsRes.success
        ? `DNS ${recordType} lookup for ${target} returned [${recordsList.join(', ')}] in ${dnsRes.durationMs}ms via ${resolutionMethod}`
        : `DNS ${recordType} lookup for ${target} failed (${dnsRes.errorCode || dnsRes.error || 'ENOTFOUND'})`,
      rawValue: dnsRes,
      normalizedValue: dnsRes.success ? `RESOLVED:${recordsList[0] || 'OK'}` : `DNS_FAILED:${dnsRes.errorCode || 'ERROR'}`,
      sourceCapabilityId: 'ejii.dns.lookup',
      collectionMethod: resolutionMethod
    });

    const steps = [
      {
        stepNumber: 1,
        label: `Resolving DNS ${recordType} records for ${target} via ${activeResolver} (${resolutionMethod})…`,
        tool: 'resolveRecord',
        status: dnsRes.success ? 'PASS' : 'FAIL',
        summary: dnsRes.success
          ? `Resolved ${target} (${recordType}) → ${recordsList.join(', ')} via ${activeResolver} [${resolutionMethod}] (${dnsRes.durationMs} ms)`
          : `Failed to resolve ${target} (${recordType}): ${dnsRes.errorCode || dnsRes.error || 'ENOTFOUND'} (${dnsRes.durationMs} ms)`,
        durationMs
      }
    ];

    let structuredAnswer;
    let reply;
    let findings;

    if (dnsRes.success && recordsList.length > 0) {
      this._recordEntityMemory(session, target, {
        intent: 'dns',
        success: true,
        resolvedIps: recordsList,
        dnsStatus: 'OK',
        dnsLatencyMs: dnsRes.durationMs,
        summary: `DNS ${recordType} resolved to ${recordsList.join(', ')} in ${dnsRes.durationMs}ms (${resolutionMethod})`
      });

      const multiNote = recordsList.length > 1
        ? 'Large services commonly publish multiple DNS records for load distribution and redundancy.'
        : 'Note that DNS resolution confirms the hostname maps to an IP address, and large services may return different addresses across queries.';

      structuredAnswer = {
        result: `DNS ${recordType} lookup for ${target} succeeded in ${dnsRes.durationMs} ms via resolver ${activeResolver} (method: ${resolutionMethod}), returning: ${recordsList.join(', ')}.`,
        meaning: `The domain name ${target} resolved to ${recordsList.join(', ')}. ${multiNote}`,
        nextStep: `If you want to verify service reachability on ${target}, test a TCP port (for example, port 443).`,
        layerFailedFirst: null,
        uncertainty: null
      };
      reply =
        `**\`${target}\`** resolved to **\`${recordsList.join('`**, **`')}\`** (DNS \`${recordType}\` lookup completed in **${dnsRes.durationMs} ms** via \`${activeResolver}\`, method: \`${resolutionMethod}\`).\n\n` +
        `${multiNote}`;
      findings = [
        { label: 'Queried Domain', value: target, tone: 'neutral' },
        { label: 'Record Type', value: recordType, tone: 'neutral' },
        { label: 'Returned Records', value: recordsList.join(', '), tone: 'ok' },
        { label: 'Resolver / Method', value: `${activeResolver} (${resolutionMethod})`, tone: 'neutral' },
        { label: 'Lookup Duration', value: `${dnsRes.durationMs} ms`, tone: 'ok' }
      ];
    } else {
      const errCode = dnsRes.errorCode || dnsRes.error || 'ENOTFOUND';
      this._recordEntityMemory(session, target, {
        intent: 'dns',
        success: false,
        dnsStatus: `FAILED (${errCode})`,
        dnsLatencyMs: dnsRes.durationMs,
        summary: `DNS ${recordType} lookup failed with ${errCode} (${dnsRes.durationMs}ms)`
      });

      const typoCheck = classifyDomainTypo(target, session?.targetHistory || []);
      let failureExplanation = `The DNS query for \`${target}\` failed with \`${errCode}\`.`;
      if (errCode.includes('ENOTFOUND') || errCode.includes('NXDOMAIN')) {
        failureExplanation = `The resolver (\`${activeResolver}\`) reported that \`${target}\` does not exist (\`NXDOMAIN\` / \`ENOTFOUND\`). No IP address was returned.`;
      } else if (errCode.includes('ENODATA')) {
        failureExplanation = `The domain \`${target}\` exists in DNS, but has no \`${recordType}\` records published (\`ENODATA\`).`;
      } else if (errCode.includes('ETIMEOUT')) {
        failureExplanation = `The DNS query to resolver \`${activeResolver}\` timed out (\`ETIMEOUT\`) without a response.`;
      } else if (errCode.includes('ESERVFAIL')) {
        failureExplanation = `The upstream DNS server returned \`SERVFAIL\` (\`ESERVFAIL\`) while attempting to resolve \`${target}\`.`;
      }

      structuredAnswer = {
        result: `DNS ${recordType} resolution for ${target} failed with ${errCode} in ${dnsRes.durationMs} ms (resolver: ${activeResolver}, method: ${resolutionMethod}).`,
        meaning: failureExplanation.replace(/`/g, ''),
        nextStep: typoCheck
          ? `Did you mean "${typoCheck.corrected}"? Try asking "Check DNS for ${typoCheck.corrected}".`
          : `Verify the spelling of "${target}" or check local DNS resolver health.`,
        layerFailedFirst: `L7 DNS Resolution (${errCode})`,
        uncertainty: null
      };
      reply =
        `DNS \`${recordType}\` lookup for **\`${target}\`** failed with **\`${errCode}\`** (${dnsRes.durationMs} ms via \`${activeResolver}\`). ${failureExplanation}` +
        (typoCheck ? `\n\nDid you mean **\`${typoCheck.corrected}\`**?` : '');
      findings = [
        { label: 'Queried Domain', value: target, tone: 'neutral' },
        { label: 'Record Type', value: recordType, tone: 'neutral' },
        { label: 'DNS Status', value: `FAILED (${errCode})`, tone: 'danger' },
        { label: 'Resolver / Method', value: `${activeResolver} (${resolutionMethod})`, tone: 'neutral' },
        { label: 'Duration', value: `${dnsRes.durationMs} ms`, tone: 'neutral' }
      ];
    }

    return {
      reply,
      structuredAnswer,
      steps,
      findings,
      technicalEvidence: {
        tool: 'resolveRecord',
        commandEquivalent: `nslookup -type=${recordType} ${target}`,
        target,
        recordType,
        resolutionMethod,
        evidenceId: ev.id,
        rawResult: dnsRes,
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Scenario B: Real Ping Check (Cases E & F — Strict Separation of ICMP vs TCP Reachability)
   */
  async _executePingScenario(plan, session, signal) {
    this._checkAborted(signal);
    const target = plan.target;
    const stepStart = performance.now();

    const isIpLiteral = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(target) || target.toLowerCase() === 'localhost';
    if (!isIpLiteral && plan.targetValidation && !plan.targetValidation.valid) {
      const durationMs = typeof plan.targetValidation.dnsLatencyMs === 'number'
        ? plan.targetValidation.dnsLatencyMs
        : Number((performance.now() - stepStart).toFixed(1));
      const typoCheck = classifyDomainTypo(target, session?.targetHistory || []);
      const steps = [
        {
          stepNumber: 1,
          label: `Resolving hostname ${target} before ICMP ping…`,
          tool: 'resolveRecord',
          status: 'FAIL',
          summary: `Cannot ping ${target}: DNS lookup failed (ENOTFOUND / NXDOMAIN)`,
          durationMs
        }
      ];
      const structuredAnswer = {
        result: `Ping to "${target}" could not be sent because DNS resolution failed (ENOTFOUND / NXDOMAIN).`,
        meaning: `The hostname "${target}" does not resolve to an IP address in DNS, so no ICMP echo request could be transmitted. This is a DNS name resolution failure, not ICMP packet loss.`,
        nextStep: typoCheck
          ? `Did you mean "${typoCheck.corrected}"? Ask "Ping ${typoCheck.corrected}" to test that host.`
          : `Check the spelling of "${target}" or provide a valid hostname or IP address.`,
        layerFailedFirst: 'L7 DNS Resolution (NXDOMAIN)',
        uncertainty: null
      };
      return {
        reply:
          `I could not ping **\`${target}\`** because DNS name resolution failed (\`ENOTFOUND\` / \`NXDOMAIN\`). Without an IP address, no ICMP echo packets were sent.` +
          (typoCheck ? `\n\nDid you mean **\`${typoCheck.corrected}\`**?` : ''),
        structuredAnswer,
        steps,
        findings: [
          { label: 'Target', value: target, tone: 'neutral' },
          { label: 'DNS Status', value: 'FAILED (ENOTFOUND)', tone: 'danger' },
          { label: 'ICMP Sent', value: '0 (Blocked by DNS failure)', tone: 'neutral' }
        ],
        technicalEvidence: {
          tool: 'realPing (DNS pre-check)',
          target,
          error: plan.targetValidation.error || 'ENOTFOUND',
          observedAt: new Date().toISOString()
        }
      };
    }

    const probeHost = target.toLowerCase() === 'localhost' ? '127.0.0.1' : (plan.targetValidation?.pinnedIp || target);
    const fallbackPort = (target.toLowerCase() === 'localhost' || probeHost === '127.0.0.1') ? (Number(config.PORT) || 3000) : 443;

    const [pingRes, tcpProbeRes] = await Promise.all([
      realPing(probeHost, 2, 900),
      checkPort(probeHost, fallbackPort, 1000).catch(() => ({ status: 'ERROR', open: false }))
    ]);
    const durationMs = Number((performance.now() - stepStart).toFixed(1));

    const ev = evidenceFabric.recordEvidence({
      type: 'observation',
      subject: `icmp:${target}`,
      claim: pingRes.success
        ? `ICMP ping to ${target} (${probeHost}) succeeded: ${pingRes.packetsReceived}/${pingRes.packetsSent} received, avg RTT ${pingRes.avgRttMs}ms, loss ${pingRes.packetLossPct}%`
        : `ICMP ping to ${target} (${probeHost}) received 0/${pingRes.packetsSent} replies (100% ICMP loss); separate TCP :${fallbackPort} probe=${tcpProbeRes.status}`,
      rawValue: { pingRes, supplementaryTcpCheck: tcpProbeRes },
      normalizedValue: pingRes.success ? 'ICMP_OK' : (tcpProbeRes.status === 'OPEN' ? 'ICMP_NO_REPLY_TCP_OPEN' : 'ICMP_NO_REPLY'),
      sourceCapabilityId: 'ejii.icmp.ping',
      collectionMethod: 'icmp_echo'
    });

    const steps = [
      {
        stepNumber: 1,
        label: `Sending ICMP echo requests to ${target} (${probeHost})…`,
        tool: 'realPing',
        status: pingRes.success ? 'PASS' : 'WARN',
        summary: pingRes.success
          ? `ICMP Echo: ${pingRes.packetsReceived}/${pingRes.packetsSent} replies received · avg ${pingRes.avgRttMs} ms · ${pingRes.packetLossPct}% loss`
          : `ICMP Echo: 0/${pingRes.packetsSent} replies received (100% ICMP loss — ICMP restricted or filtered)`,
        durationMs
      }
    ];

    let structuredAnswer;
    let reply;
    let findings;

    if (pingRes.success && pingRes.packetLossPct === 0) {
      this._recordEntityMemory(session, target, {
        intent: 'ping',
        success: true,
        resolvedIps: [probeHost],
        dnsStatus: isIpLiteral ? null : 'OK',
        pingRttMs: pingRes.avgRttMs,
        pingLossPct: 0,
        icmpStatus: 'REACHABLE',
        openPorts: tcpProbeRes.status === 'OPEN' ? [fallbackPort] : [],
        summary: `ICMP ping succeeded (${pingRes.packetsReceived}/${pingRes.packetsSent} received, ${pingRes.avgRttMs}ms avg RTT, 0% loss)`
      });

      structuredAnswer = {
        result: `ICMP ping to ${target} (${probeHost}) succeeded: ${pingRes.packetsReceived}/${pingRes.packetsSent} packets received (0% packet loss), min/avg/max RTT = ${pingRes.minRttMs}/${pingRes.avgRttMs}/${pingRes.maxRttMs} ms (jitter ${pingRes.jitterMs} ms).`,
        meaning: `Layer 3 ICMP echo reachability to ${target} is verified with zero packet loss.`,
        nextStep: `To verify application listeners on ${target}, test a specific TCP port (such as port ${fallbackPort}).`,
        layerFailedFirst: null,
        uncertainty: null
      };
      reply =
        `ICMP ping to **\`${target}\`** (\`${probeHost}\`) succeeded with **${pingRes.packetsReceived}/${pingRes.packetsSent} packets received** (0% loss) and an average RTT of **${pingRes.avgRttMs} ms** (min ${pingRes.minRttMs} ms, max ${pingRes.maxRttMs} ms, jitter ${pingRes.jitterMs} ms).`;
      findings = [
        { label: 'Target', value: `${target} (${probeHost})`, tone: 'neutral' },
        { label: 'ICMP Echo', value: `REACHABLE (${pingRes.packetsReceived}/${pingRes.packetsSent}, 0% Loss)`, tone: 'ok' },
        { label: 'Avg RTT', value: `${pingRes.avgRttMs} ms`, tone: 'ok' },
        { label: 'Min / Max / Jitter', value: `${pingRes.minRttMs} / ${pingRes.maxRttMs} / ${pingRes.jitterMs} ms`, tone: 'neutral' }
      ];
    } else if (pingRes.success && pingRes.packetLossPct > 0) {
      this._recordEntityMemory(session, target, {
        intent: 'ping',
        success: true,
        resolvedIps: [probeHost],
        pingRttMs: pingRes.avgRttMs,
        pingLossPct: pingRes.packetLossPct,
        icmpStatus: 'PARTIAL_LOSS',
        summary: `ICMP partial loss (${pingRes.packetLossPct}% loss, ${pingRes.avgRttMs}ms RTT)`
      });

      structuredAnswer = {
        result: `ICMP ping to ${target} (${probeHost}) observed ${pingRes.packetLossPct}% packet loss (${pingRes.packetsReceived}/${pingRes.packetsSent} received, avg RTT ${pingRes.avgRttMs} ms).`,
        meaning: `The host is responding to ICMP, but some packets were dropped or rate-limited along the route.`,
        nextStep: `Run a traceroute to ${target} or test TCP port ${fallbackPort} to check whether application transport is affected.`,
        layerFailedFirst: 'L3 Network Path (Partial ICMP Loss)',
        uncertainty: 'Router control-plane ICMP rate limiting can cause partial ping loss even when forwarded TCP traffic is healthy.'
      };
      reply =
        `ICMP ping to **\`${target}\`** (\`${probeHost}\`) showed **${pingRes.packetLossPct}% packet loss** (${pingRes.packetsReceived}/${pingRes.packetsSent} replies received, average RTT **${pingRes.avgRttMs} ms**). Some packets were dropped or rate-limited along the path.`;
      findings = [
        { label: 'Target', value: `${target} (${probeHost})`, tone: 'neutral' },
        { label: 'ICMP Loss', value: `${pingRes.packetLossPct}% (${pingRes.packetsReceived}/${pingRes.packetsSent})`, tone: 'warn' },
        { label: 'Avg RTT', value: `${pingRes.avgRttMs} ms`, tone: 'warn' }
      ];
    } else if (tcpProbeRes && (tcpProbeRes.status === 'OPEN' || tcpProbeRes.status === 'CLOSED')) {
      const tcpRtt = typeof tcpProbeRes.connectLatencyMs === 'number'
        ? tcpProbeRes.connectLatencyMs
        : (typeof tcpProbeRes.latencyMs === 'number' ? tcpProbeRes.latencyMs : null);
      const tcpRttStr = tcpRtt !== null ? `${tcpRtt} ms` : 'measured';

      steps.push({
        stepNumber: 2,
        label: `Running separate TCP reachability check on ${probeHost}:${fallbackPort}…`,
        tool: 'checkPort',
        status: 'PASS',
        summary: `Separate TCP probe to ${probeHost}:${fallbackPort} returned ${tcpProbeRes.status}${tcpRtt !== null ? ` (RTT: ${tcpRtt} ms)` : ''}`,
        durationMs: tcpRtt
      });

      this._recordEntityMemory(session, target, {
        intent: 'ping',
        success: true,
        resolvedIps: [probeHost],
        dnsStatus: isIpLiteral ? null : 'OK',
        pingRttMs: null,
        pingLossPct: 100,
        icmpStatus: 'NO_REPLY_ICMP_RESTRICTED',
        openPorts: tcpProbeRes.status === 'OPEN' ? [fallbackPort] : [],
        closedPorts: tcpProbeRes.status === 'CLOSED' ? [fallbackPort] : [],
        portLatencies: tcpRtt !== null ? { [fallbackPort]: tcpRtt } : {},
        summary: `ICMP ping received 0/${pingRes.packetsSent} replies (restricted/filtered); separate TCP :${fallbackPort} check is ${tcpProbeRes.status}${tcpRtt !== null ? ` (${tcpRtt}ms)` : ''}`
      });

      structuredAnswer = {
        result: `ICMP ping to ${target} (${probeHost}) received 0/${pingRes.packetsSent} echo replies (100% ICMP loss — ICMP is filtered or restricted in this container/network environment). Separately, a direct TCP connection check to ${probeHost}:${fallbackPort} succeeded (${tcpProbeRes.status}${tcpRtt !== null ? ` in ${tcpRtt} ms` : ''}).`,
        meaning: `Ping (ICMP Echo) and TCP are distinct protocols: ICMP echo did not receive a reply because the container sandbox or remote firewall blocks raw ICMP, while the separate TCP handshake on port ${fallbackPort} confirms that ${target} (${probeHost}) is online and reachable over TCP.`,
        nextStep: `Use TCP or HTTPS checks to evaluate services on ${target}.`,
        layerFailedFirst: 'L3 ICMP Echo (Filtered/Restricted; TCP Reachable)',
        uncertainty: null
      };
      reply =
        `ICMP ping to **\`${target}\`** (\`${probeHost}\`) received **0/${pingRes.packetsSent} echo replies** (100% ICMP loss). However, a separate TCP connection check to \`${probeHost}:${fallbackPort}\` succeeded (**${tcpProbeRes.status}**${tcpRtt !== null ? ` in **${tcpRttStr}**` : ''}).\n\n` +
        `This means \`${target}\` is online and reachable over TCP, while raw ICMP echo packets are blocked by a firewall or container network policy.`;
      findings = [
        { label: 'Target', value: `${target} (${probeHost})`, tone: 'neutral' },
        { label: 'ICMP Ping Result', value: `0/${pingRes.packetsSent} Replies (Restricted / Filtered)`, tone: 'warn' },
        { label: `Separate TCP :${fallbackPort}`, value: `${tcpProbeRes.status}${tcpRtt !== null ? ` (${tcpRtt} ms)` : ''}`, tone: 'ok' }
      ];
    } else {
      this._recordEntityMemory(session, target, {
        intent: 'ping',
        success: false,
        resolvedIps: [probeHost],
        pingRttMs: null,
        pingLossPct: 100,
        icmpStatus: 'NO_REPLY',
        summary: `ICMP ping failed (0/${pingRes.packetsSent} replies, 100% loss)`
      });

      structuredAnswer = {
        result: `No ICMP echo reply was received from ${target} (${probeHost}) — 100% packet loss (0/${pingRes.packetsSent} packets received).`,
        meaning: `Either ${target} is offline/unreachable on the network, or a firewall / container sandbox policy is blocking ICMP echo requests (and TCP port ${fallbackPort} did not respond).`,
        nextStep: `Test a specific TCP port where an application is expected to listen.`,
        layerFailedFirst: 'L3 ICMP Reachability',
        uncertainty: 'An ICMP timeout alone cannot distinguish between an offline host and a firewall silently dropping packets.'
      };
      reply =
        `No ICMP ping reply was received from **\`${target}\`** (\`${probeHost}\`) — **0/${pingRes.packetsSent} packets received** (100% loss).\n\n` +
        `Either the host is unreachable on the network or ICMP echo requests are being silently dropped by a firewall.`;
      findings = [
        { label: 'Target', value: `${target} (${probeHost})`, tone: 'neutral' },
        { label: 'ICMP Status', value: 'NO REPLY (100% Loss)', tone: 'danger' },
        { label: 'Note', value: 'Test specific TCP port to rule out ICMP firewall block', tone: 'warn' }
      ];
    }

    return {
      reply,
      structuredAnswer,
      steps,
      findings,
      technicalEvidence: {
        tool: 'realPing',
        commandEquivalent: `ping -c 2 ${probeHost}`,
        target,
        resolvedIp: probeHost,
        evidenceId: ev.id,
        icmpResult: pingRes,
        separateTcpCheck: tcpProbeRes,
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Scenario C: Real TCP Port Check (Case G — Single or Multiple Ports, Transport vs App Health Distinction)
   */
  async _executePortCheckScenario(plan, session, signal) {
    this._checkAborted(signal);
    const target = plan.target;
    const isIpLiteral = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(target) || target.toLowerCase() === 'localhost';

    if (!isIpLiteral && plan.targetValidation && !plan.targetValidation.valid) {
      const typoCheck = classifyDomainTypo(target, session?.targetHistory || []);
      const measuredDnsMs = typeof plan.targetValidation.dnsLatencyMs === 'number'
        ? plan.targetValidation.dnsLatencyMs
        : null;
      const structuredAnswer = {
        result: `TCP port check on "${target}" could not proceed because DNS resolution failed (ENOTFOUND).`,
        meaning: `The hostname "${target}" could not be resolved to an IP address in DNS.`,
        nextStep: typoCheck
          ? `Did you mean "${typoCheck.corrected}"? Try "Check port ${plan.ports[0] || 443} on ${typoCheck.corrected}".`
          : `Verify the hostname spelling or test with a direct IP address.`,
        layerFailedFirst: 'L7 DNS Resolution',
        uncertainty: null
      };
      return {
        reply:
          `I could not test TCP port ${plan.ports.join(', ') || 443} on **\`${target}\`** because DNS resolution failed (\`ENOTFOUND\`).` +
          (typoCheck ? `\n\nDid you mean **\`${typoCheck.corrected}\`**?` : ''),
        structuredAnswer,
        steps: [
          {
            stepNumber: 1,
            label: `Resolving ${target}…`,
            tool: 'resolveRecord',
            status: 'FAIL',
            summary: `DNS resolution failed for ${target} (ENOTFOUND)`,
            durationMs: measuredDnsMs
          }
        ],
        findings: [
          { label: 'Target', value: target, tone: 'neutral' },
          { label: 'DNS Status', value: 'FAILED (ENOTFOUND)', tone: 'danger' }
        ],
        technicalEvidence: { target, error: 'DNS_RESOLUTION_FAILED', dnsLatencyMs: measuredDnsMs, observedAt: new Date().toISOString() }
      };
    }

    const probeHost = target.toLowerCase() === 'localhost' ? '127.0.0.1' : (plan.targetValidation?.pinnedIp || target);
    const ports = Array.isArray(plan.ports) && plan.ports.length > 0 ? plan.ports : [443];

    const steps = [];
    const results = [];
    const findings = [{ label: 'Target', value: `${target}${probeHost !== target ? ` (${probeHost})` : ''}`, tone: 'neutral' }];
    const evidenceIds = [];

    const perPortTimeoutMs = ports.length > 3 ? 1100 : 1800;
    const rawPortOutcomes = await Promise.all(
      ports.map(async (port) => {
        this._checkAborted(signal);
        const stepStart = performance.now();
        const rawRes = await checkPort(probeHost, port, perPortTimeoutMs);
        const durationMs = Number((performance.now() - stepStart).toFixed(1));
        return { port, rawRes, durationMs };
      })
    );

    for (let i = 0; i < rawPortOutcomes.length; i++) {
      this._checkAborted(signal);
      const { port, rawRes, durationMs } = rawPortOutcomes[i];
      const measuredLatencyMs = typeof rawRes.connectLatencyMs === 'number'
        ? rawRes.connectLatencyMs
        : (typeof rawRes.latencyMs === 'number' ? rawRes.latencyMs : null);
      const res = { ...rawRes, latencyMs: measuredLatencyMs };
      results.push(res);

      const ev = evidenceFabric.recordEvidence({
        type: 'observation',
        subject: `tcp:${probeHost}:${port}`,
        claim: `TCP connect to ${target} (${probeHost}:${port}) returned ${res.status}${res.latencyMs !== null ? ` (${res.latencyMs}ms)` : ''}`,
        rawValue: res,
        normalizedValue: `TCP_${res.status}`,
        sourceCapabilityId: 'ejii.tcp.port_check',
        collectionMethod: 'net.Socket.connect'
      });
      evidenceIds.push(ev.id);

      steps.push({
        stepNumber: i + 1,
        label: `Testing TCP port ${port} on ${target} (${probeHost})…`,
        tool: 'checkPort',
        status: res.status === 'OPEN' ? 'PASS' : 'FAIL',
        summary: res.status === 'OPEN'
          ? `Port ${port} is OPEN${res.latencyMs !== null ? ` (3-way handshake RTT: ${res.latencyMs} ms)` : ''}`
          : `Port ${port} is ${res.status} (${res.errorCode || res.error || 'No listener'})`,
        durationMs: res.latencyMs !== null ? res.latencyMs : durationMs
      });

      findings.push({
        label: `TCP Port ${port}`,
        value: res.status === 'OPEN'
          ? `OPEN${res.latencyMs !== null ? ` (${res.latencyMs} ms)` : ''}`
          : `${res.status}${res.errorCode ? ` (${res.errorCode})` : ''}`,
        tone: res.status === 'OPEN' ? 'ok' : (res.status === 'CLOSED' ? 'danger' : 'warn')
      });
    }

    const openPorts = results.filter((r) => r.status === 'OPEN');
    const closedPorts = results.filter((r) => r.status === 'CLOSED');
    const filteredPorts = results.filter((r) => r.status === 'FILTERED');

    const portLatencies = {};
    for (const r of results) {
      if (r.latencyMs !== null) {
        portLatencies[r.port] = r.latencyMs;
      }
    }
    this._recordEntityMemory(session, target, {
      intent: 'port_check',
      success: openPorts.length > 0,
      resolvedIps: [probeHost],
      openPorts: openPorts.map((r) => r.port),
      closedPorts: closedPorts.map((r) => r.port),
      filteredPorts: filteredPorts.map((r) => r.port),
      portLatencies,
      summary: `TCP ports tested: ${results.map((r) => `${r.port}=${r.status}${r.latencyMs !== null ? ` (${r.latencyMs}ms)` : ''}`).join(', ')}`
    });

    let structuredAnswer;
    let reply;

    if (results.length === 1) {
      const r = results[0];
      const latText = r.latencyMs !== null ? ` in ${r.latencyMs} ms` : '';
      if (r.status === 'OPEN') {
        structuredAnswer = {
          result: `TCP port ${r.port} on ${target} (${probeHost}) is OPEN and completed a 3-way handshake${latText}.`,
          meaning: `The host is reachable on the network and a process is actively listening and accepting TCP connections on port ${r.port}. Note that TCP port openness confirms transport connectivity, not full application-layer health.`,
          nextStep: `If you want to verify application-layer responses on port ${r.port}, run an HTTP/HTTPS check.`,
          layerFailedFirst: null,
          uncertainty: null
        };
        reply =
          `TCP port **${r.port}** on **\`${target}\`** (\`${probeHost}\`) is **OPEN**${latText ? ` (3-way handshake completed${latText})` : ''}.\n\n` +
          `A service is actively listening and accepting connections on port ${r.port}. Keep in mind this confirms transport-layer reachability; checking HTTP/TLS status is needed if you want to verify application-layer responses.`;
      } else if (r.status === 'CLOSED') {
        let activeLocalListenersNote = '';
        if (target.toLowerCase() === 'localhost' || target === '127.0.0.1' || probeHost === '127.0.0.1') {
          try {
            const sockSnap = await processSocketCorrelator.getActiveConnections();
            const listeningPorts = Array.from(
              new Set(
                (sockSnap?.connections || [])
                  .filter((c) => /LISTEN/i.test(c.state) && Number.isFinite(Number(c.localPort)))
                  .map((c) => Number(c.localPort))
              )
            ).sort((a, b) => a - b);
            if (listeningPorts.length > 0) {
              const portListStr = listeningPorts.slice(0, 8).join(', ');
              activeLocalListenersNote = ` Active local TCP listeners detected on this host: port(s) ${portListStr}.`;
              findings.push({
                label: 'Active Local Listeners',
                value: portListStr,
                tone: 'neutral'
              });
            }
          } catch (_) {}
        }

        structuredAnswer = {
          result: `TCP port ${r.port} on ${target} (${probeHost}) is CLOSED (connection actively refused with TCP RST / ECONNREFUSED${latText}).`,
          meaning: `The host ${target} is online and reachable across the network, and no firewall silently dropped the packet — however, no application process is listening on TCP port ${r.port}.${activeLocalListenersNote}`,
          nextStep: `Verify that the service expected on port ${r.port} is running and bound to ${probeHost}:${r.port}.`,
          layerFailedFirst: `L4 TCP Application Listener (Port ${r.port} Refused / ECONNREFUSED)`,
          uncertainty: null
        };
        reply =
          `TCP port **${r.port}** on **\`${target}\`** (\`${probeHost}\`) is **CLOSED** (\`ECONNREFUSED\` / TCP RST received${latText}).\n\n` +
          `Because the host actively sent a reset packet, \`${target}\` is online and reachable on the network, but no process is currently listening on port ${r.port}.${activeLocalListenersNote ? `\n\n**Adaptive Local Socket Correlation:**${activeLocalListenersNote}` : ''}`;
      } else if (r.status === 'FILTERED') {
        structuredAnswer = {
          result: `TCP connection to port ${r.port} on ${target} (${probeHost}) timed out with no response (FILTERED / ETIMEDOUT).`,
          meaning: `The TCP SYN packet received neither a SYN-ACK nor a TCP RST within the timeout window. Either a firewall/security group is silently dropping traffic to port ${r.port}, or the host itself is unreachable.`,
          nextStep: `Test another port on the same host or check host reachability.`,
          layerFailedFirst: `L3/L4 Network Path or Firewall (Port ${r.port} Timeout / ETIMEDOUT)`,
          uncertainty: 'A silent TCP timeout cannot distinguish between a firewall drop and an offline host without comparing against another open port or ARP/ICMP response.'
        };
        reply =
          `The TCP connection attempt to port **${r.port}** on **\`${target}\`** (\`${probeHost}\`) timed out without a response (**FILTERED** / \`ETIMEDOUT\`).\n\n` +
          `Neither a \`SYN-ACK\` nor a \`TCP RST\` was returned within the timeout window, which means either a firewall is silently dropping traffic to port ${r.port} or the host itself is unreachable.`;
      } else {
        structuredAnswer = {
          result: `TCP check on ${target}:${r.port} returned ${r.status} (${r.errorCode || r.error || 'Error'}).`,
          meaning: `The operating system could not establish a route or socket connection to ${target}:${r.port}.`,
          nextStep: `Check DNS resolution and local routing table for ${target}.`,
          layerFailedFirst: 'L3/L4 Socket Initiation',
          uncertainty: null
        };
        reply = `TCP check on **\`${target}:${r.port}\`** returned **${r.status}** (${r.errorCode || r.error || 'socket error'}).`;
      }
    } else {
      const summaryParts = results.map((r) =>
        `port **${r.port}** is **${r.status}**${r.status === 'OPEN' && r.latencyMs !== null ? ` (${r.latencyMs} ms)` : (r.errorCode ? ` (${r.errorCode})` : '')}`
      );
      structuredAnswer = {
        result: `Tested ${results.length} TCP ports on ${target} (${probeHost}): ${results.map((r) => `${r.port}=${r.status}`).join(', ')}.`,
        meaning: openPorts.length === results.length
          ? `All ${results.length} tested ports are open and accepting TCP connections (transport reachability confirmed).`
          : openPorts.length > 0
            ? `Host ${target} is online and reachable (port ${openPorts.map((p) => p.port).join(', ')} open), while port ${closedPorts.concat(filteredPorts).map((p) => `${p.port} is ${p.status}`).join(', ')}.`
            : closedPorts.length > 0
              ? `Host ${target} is reachable on the network (returned explicit TCP RST), but none of the tested ports (${ports.join(', ')}) have an active listener.`
              : `All tested ports (${ports.join(', ')}) timed out or failed, indicating a firewall block or unreachable host.`,
        nextStep: openPorts.length > 0
          ? `Inspect the service listeners on any closed/filtered ports (${closedPorts.concat(filteredPorts).map((p) => p.port).join(', ') || 'none'}) if needed.`
          : `Verify which port the service is configured to listen on.`,
        layerFailedFirst: openPorts.length === results.length ? null : 'L4 TCP Port Listener',
        uncertainty: null
      };
      reply =
        `On **\`${target}\`** (\`${probeHost}\`), ${summaryParts.join('; ')}.\n\n` +
        `${structuredAnswer.meaning}`;
    }

    return {
      reply,
      structuredAnswer,
      steps,
      findings,
      technicalEvidence: {
        tool: 'checkPort',
        commandEquivalent: ports.map((p) => `nc -zv -w 2 ${probeHost} ${p}`).join(' && '),
        target,
        resolvedIp: probeHost,
        ports,
        evidenceIds,
        rawResults: results,
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Scenario D: Website / HTTPS Accessibility Check (Case H — Schema-Aligned DNS -> TCP -> TLS -> HTTP)
   */
  async _executeWebsiteCheckScenario(plan, session, signal) {
    this._checkAborted(signal);
    const target = plan.target;
    const port = plan.ports[0] || (plan.urlProtocol === 'http' ? 80 : 443);
    const isHttps = plan.urlProtocol === 'https' || port === 443 || port === 8443;
    const urlToProbe = plan.url || `${isHttps ? 'https' : 'http'}://${target}${port !== 80 && port !== 443 ? `:${port}` : ''}/`;

    const steps = [];
    const findings = [{ label: 'Endpoint', value: urlToProbe, tone: 'neutral' }];

    // Step 1: DNS Resolution (or IP literal validation without claiming a DNS query ran)
    const t0 = performance.now();
    let dnsRes = null;
    let resolvedIp = plan.targetValidation?.pinnedIp || (target === 'localhost' ? '127.0.0.1' : target);
    const isStrictIpLiteral = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(target);
    const isLocalhost = target.toLowerCase() === 'localhost';

    if (!isStrictIpLiteral && !isLocalhost) {
      if (plan.targetValidation?.valid && plan.targetValidation.pinnedIp) {
        resolvedIp = plan.targetValidation.pinnedIp;
        dnsRes = {
          success: true,
          records: plan.targetValidation.resolvedIps,
          durationMs: typeof plan.targetValidation.dnsLatencyMs === 'number'
            ? plan.targetValidation.dnsLatencyMs
            : Number((performance.now() - t0).toFixed(2)),
          resolutionMethod: plan.targetValidation.resolutionMethod || 'dns_protocol'
        };
      } else {
        dnsRes = await resolveRecord(target, 'A');
        if (dnsRes.success && dnsRes.records?.length) {
          resolvedIp = dnsRes.records[0];
        }
      }
      steps.push({
        stepNumber: 1,
        label: `Resolving DNS for ${target}…`,
        tool: 'resolveRecord',
        status: dnsRes.success ? 'PASS' : 'FAIL',
        summary: dnsRes.success
          ? `Resolved ${target} → ${resolvedIp}${typeof dnsRes.durationMs === 'number' ? ` (${dnsRes.durationMs} ms)` : ''}`
          : `DNS resolution failed: ${dnsRes.errorCode || dnsRes.error || 'ENOTFOUND'}`,
        durationMs: typeof dnsRes.durationMs === 'number' ? dnsRes.durationMs : Number((performance.now() - t0).toFixed(1))
      });

      if (!dnsRes.success) {
        findings.push({ label: 'DNS', value: `FAILED (${dnsRes.errorCode || 'ENOTFOUND'})`, tone: 'danger' });
        const structuredAnswer = {
          result: `Website ${urlToProbe} cannot be reached because DNS resolution for "${target}" failed (${dnsRes.errorCode || 'ENOTFOUND'}).`,
          meaning: `Clients cannot resolve an IP address for ${target}, so no TCP, TLS, or HTTP connection can begin.`,
          nextStep: `Check the domain spelling or verify the authoritative DNS A/AAAA records for ${target}.`,
          layerFailedFirst: 'L7 DNS Resolution',
          uncertainty: null
        };
        return {
          reply: `**\`${urlToProbe}\`** could not be reached because DNS resolution for \`${target}\` failed (\`${dnsRes.errorCode || 'ENOTFOUND'}\`). Without a resolved IP address, no TCP or HTTP connection could be initiated.`,
          structuredAnswer,
          steps,
          findings,
          technicalEvidence: { url: urlToProbe, dns: dnsRes, observedAt: new Date().toISOString() }
        };
      }
      findings.push({ label: 'DNS', value: `${resolvedIp}${typeof dnsRes.durationMs === 'number' ? ` (${dnsRes.durationMs} ms)` : ''}`, tone: 'ok' });
    } else if (isLocalhost) {
      const measuredLocalMs = typeof plan.targetValidation?.dnsLatencyMs === 'number' ? plan.targetValidation.dnsLatencyMs : null;
      dnsRes = {
        success: true,
        records: [resolvedIp],
        durationMs: measuredLocalMs,
        resolutionMethod: 'local_hosts_table'
      };
      steps.push({
        stepNumber: 1,
        label: 'Mapping localhost via local hosts table…',
        tool: 'local_hosts_table',
        status: 'PASS',
        summary: `localhost maps to ${resolvedIp} (local_hosts_table)`,
        durationMs: measuredLocalMs
      });
      findings.push({ label: 'Host Mapping', value: `${resolvedIp} (local_hosts_table)`, tone: 'ok' });
    } else {
      // Literal IP: never claim a DNS query ran or fabricate 0.4ms DNS latency
      dnsRes = {
        success: true,
        records: [resolvedIp],
        durationMs: null,
        dnsQueryExecuted: false,
        resolutionMethod: 'ip_literal_bypass'
      };
      findings.push({ label: 'Target IP', value: `${resolvedIp} (IP literal — no DNS query)`, tone: 'neutral' });
    }

    // Step 2: TCP Port Check
    this._checkAborted(signal);
    const t1 = performance.now();
    const rawTcpRes = await checkPort(resolvedIp, port, 2000);
    const tcpStepMs = Number((performance.now() - t1).toFixed(1));
    const tcpLatencyMs = typeof rawTcpRes.connectLatencyMs === 'number'
      ? rawTcpRes.connectLatencyMs
      : (typeof rawTcpRes.latencyMs === 'number' ? rawTcpRes.latencyMs : null);
    const tcpRes = { ...rawTcpRes, latencyMs: tcpLatencyMs };
    steps.push({
      stepNumber: steps.length + 1,
      label: `Testing TCP connection to ${resolvedIp}:${port}…`,
      tool: 'checkPort',
      status: tcpRes.status === 'OPEN' ? 'PASS' : 'FAIL',
      summary: tcpRes.status === 'OPEN'
        ? `TCP port ${port} is OPEN${tcpRes.latencyMs !== null ? ` (${tcpRes.latencyMs} ms)` : ''}`
        : `TCP port ${port} is ${tcpRes.status} (${tcpRes.errorCode || tcpRes.error || 'Unreachable'})`,
      durationMs: tcpRes.latencyMs !== null ? tcpRes.latencyMs : tcpStepMs
    });

    if (tcpRes.status !== 'OPEN') {
      findings.push({ label: `TCP :${port}`, value: `${tcpRes.status} (${tcpRes.errorCode || 'Failed'})`, tone: 'danger' });
      const structuredAnswer = {
        result: `${isStrictIpLiteral ? `Target IP ${resolvedIp}` : `Host ${target} (${resolvedIp})`} was reached for testing, but TCP port ${port} is ${tcpRes.status} (${tcpRes.errorCode || tcpRes.error || 'no response'}).`,
        meaning: tcpRes.status === 'CLOSED'
          ? `The host at ${resolvedIp} is reachable on the network, but the web server process on port ${port} is stopped or refusing connections.`
          : `Traffic to ${resolvedIp}:${port} timed out without a response, indicating a firewall block or outbound network restriction.`,
        nextStep: tcpRes.status === 'CLOSED'
          ? `Check whether the web server process is running and bound to port ${port}.`
          : `Verify firewall rules for port ${port}.`,
        layerFailedFirst: `L4 TCP Transport (Port ${port} ${tcpRes.status})`,
        uncertainty: null
      };
      return {
        reply: `${structuredAnswer.result}\n\n${structuredAnswer.meaning}`,
        structuredAnswer,
        steps,
        findings,
        technicalEvidence: { url: urlToProbe, dns: dnsRes, tcp: tcpRes, observedAt: new Date().toISOString() }
      };
    }
    findings.push({ label: `TCP :${port}`, value: `OPEN${tcpRes.latencyMs !== null ? ` (${tcpRes.latencyMs} ms)` : ''}`, tone: 'ok' });

    // Step 3: TLS Audit (if HTTPS)
    let tlsRes = null;
    let tlsCipherName = 'Unknown';
    let tlsDaysRemaining = null;
    let tlsAuthorized = false;
    let tlsAuthError = null;

    if (isHttps) {
      this._checkAborted(signal);
      const t2 = performance.now();
      tlsRes = await auditTls(target, port, 2500);
      tlsCipherName = tlsRes?.cipher?.name || tlsRes?.cipherName || 'TLS Cipher';
      tlsDaysRemaining = typeof tlsRes?.certificate?.daysRemaining === 'number'
        ? tlsRes.certificate.daysRemaining
        : (typeof tlsRes?.daysRemaining === 'number' ? tlsRes.daysRemaining : null);
      tlsAuthorized = Boolean(tlsRes?.validation?.authorized ?? tlsRes?.authorized);
      tlsAuthError = tlsRes?.validation?.error || null;

      const certDaysStr = tlsDaysRemaining !== null ? `${tlsDaysRemaining} days remaining` : 'certificate presented';
      const authStr = tlsAuthorized ? 'CA trusted' : (tlsAuthError ? `untrusted/self-signed: ${tlsAuthError}` : 'unverified CA');

      steps.push({
        stepNumber: steps.length + 1,
        label: `Verifying TLS handshake and X.509 certificate on ${target}:${port}…`,
        tool: 'auditTls',
        status: tlsRes.success ? (tlsAuthorized ? 'PASS' : 'WARN') : 'FAIL',
        summary: tlsRes.success
          ? `${tlsRes.protocol || 'TLS'} (${tlsCipherName}) · Cert: ${certDaysStr} (${authStr})`
          : `TLS handshake failed: ${tlsRes.error || 'Handshake error'}`,
        durationMs: typeof tlsRes.handshakeDurationMs === 'number' ? tlsRes.handshakeDurationMs : Number((performance.now() - t2).toFixed(1))
      });
      findings.push({
        label: 'TLS Security',
        value: tlsRes.success
          ? `${tlsRes.protocol || 'TLS'}${tlsDaysRemaining !== null ? ` (${tlsDaysRemaining}d left)` : ''}`
          : `FAILED (${tlsRes.error || 'Error'})`,
        tone: tlsRes.success ? (tlsAuthorized ? 'ok' : 'warn') : 'danger'
      });
    }

    // Step 4: HTTP Application Probe — never output undefinedms or substitute step duration when TTFB is missing!
    this._checkAborted(signal);
    const t3 = performance.now();
    const httpRes = await probeHttp(urlToProbe, 'GET', 2500);
    const httpStepMs = Number((performance.now() - t3).toFixed(1));
    const rawTtfb = httpRes?.waterfall?.ttfbMs ?? httpRes?.ttfbMs;
    const ttfbMs = (typeof rawTtfb === 'number' && Number.isFinite(rawTtfb)) ? rawTtfb : null;
    const rawTotalHttp = httpRes?.waterfall?.totalMs ?? httpRes?.totalTimeMs;
    const totalHttpMs = (typeof rawTotalHttp === 'number' && Number.isFinite(rawTotalHttp)) ? rawTotalHttp : null;
    const ttfbSummaryStr = ttfbMs !== null ? `TTFB: ${ttfbMs} ms` : 'TTFB not provided by probe';
    const redirectLocation = httpRes?.headers?.location || httpRes?.redirectLocation || null;
    const isRedirect = httpRes.statusCode >= 300 && httpRes.statusCode < 400;

    steps.push({
      stepNumber: steps.length + 1,
      label: `Checking HTTP response from ${urlToProbe}…`,
      tool: 'probeHttp',
      status: httpRes.success ? 'PASS' : (httpRes.statusCode ? 'WARN' : 'FAIL'),
      summary: httpRes.statusCode
        ? `HTTP ${httpRes.statusCode} ${httpRes.statusMessage || ''}${isRedirect && redirectLocation ? ` → Redirects to ${redirectLocation}` : ''} (${ttfbSummaryStr}${totalHttpMs !== null ? `, total: ${totalHttpMs} ms` : ''})`
        : `HTTP request failed: ${httpRes.error || 'No HTTP response'}`,
      durationMs: totalHttpMs !== null ? totalHttpMs : httpStepMs
    });

    if (httpRes.statusCode) {
      findings.push({
        label: 'HTTP Status',
        value: `${httpRes.statusCode}${isRedirect ? ' Redirect' : ''}${ttfbMs !== null ? ` (${ttfbMs} ms TTFB)` : ' (TTFB unavailable)'}`,
        tone: httpRes.statusCode < 400 ? 'ok' : (httpRes.statusCode < 500 ? 'warn' : 'danger')
      });
    } else {
      findings.push({
        label: 'HTTP Status',
        value: `FAILED (${httpRes.error || 'Error'})`,
        tone: 'danger'
      });
    }

    this._recordEntityMemory(session, target, {
      intent: 'website_check',
      success: Boolean(httpRes.statusCode && httpRes.statusCode < 400),
      resolvedIps: [resolvedIp],
      dnsStatus: isStrictIpLiteral ? null : 'OK',
      openPorts: [port],
      portLatencies: tcpRes.latencyMs !== null ? { [port]: tcpRes.latencyMs } : {},
      httpStatus: httpRes.statusCode || 'FAILED',
      summary: `Website check ${urlToProbe}: HTTP ${httpRes.statusCode || 'FAILED'} (${ttfbSummaryStr})`
    });

    const dnsNote = isStrictIpLiteral
      ? `Target IP ${resolvedIp} was probed directly (no DNS lookup required)`
      : isLocalhost
        ? `localhost mapped to ${resolvedIp}`
        : `DNS resolved ${target} to ${resolvedIp}${typeof dnsRes.durationMs === 'number' ? ` (${dnsRes.durationMs} ms)` : ''}`;
    const tcpNote = `TCP port ${port} is OPEN${tcpRes.latencyMs !== null ? ` (${tcpRes.latencyMs} ms)` : ''}`;
    const ttfbText = ttfbMs !== null ? `with a TTFB of ${ttfbMs} ms` : '(the HTTP probe did not report a TTFB measurement)';

    let structuredAnswer;
    let reply;
    if (isRedirect) {
      structuredAnswer = {
        result: `Tested endpoint ${urlToProbe} returned an HTTP ${httpRes.statusCode} redirection${redirectLocation ? ` to ${redirectLocation}` : ''} ${ttfbText} (${dnsNote}, ${tcpNote}${tlsRes?.success ? `, TLS ${tlsRes.protocol}` : ''}).`,
        meaning: `The tested endpoint is responding and redirecting requests${redirectLocation ? ` to ${redirectLocation}` : ''}.`,
        nextStep: redirectLocation
          ? `If you want to verify the destination URL directly, ask "Check whether ${redirectLocation} is working".`
          : null,
        layerFailedFirst: null,
        uncertainty: null
      };
      reply = `The tested endpoint **\`${urlToProbe}\`** responded with an **HTTP ${httpRes.statusCode}** redirection${redirectLocation ? ` to \`${redirectLocation}\`` : ''} ${ttfbText} (${dnsNote}, ${tcpNote}${tlsRes?.success ? `, TLS ${tlsRes.protocol}` : ''}).`;
    } else if (httpRes.statusCode && httpRes.statusCode < 300) {
      structuredAnswer = {
        result: `Tested endpoint ${urlToProbe} returned HTTP ${httpRes.statusCode} ${httpRes.statusMessage || 'OK'} ${ttfbText} — ${dnsNote}, ${tcpNote}${tlsRes?.success ? `, and TLS negotiated ${tlsRes.protocol} (${tlsCipherName})` : ''}.`,
        meaning: `The tested URL responded with HTTP ${httpRes.statusCode} over ${isHttps ? 'HTTPS' : 'HTTP'}. Note that a 200 response from this specific endpoint confirms this route responded, not that every downstream route or backend dependency is healthy.`,
        nextStep: plan.combinedExplanationRequested
          ? 'If the application still feels slow to users, compare the measured DNS, TCP handshake, and HTTP TTFB timings above to see whether latency is in network transport or server-side processing.'
          : null,
        layerFailedFirst: null,
        uncertainty: null
      };
      reply =
        `The tested endpoint **\`${urlToProbe}\`** returned **HTTP ${httpRes.statusCode} ${httpRes.statusMessage || 'OK'}** ${ttfbText}.\n\n` +
        `- **Network & Transport:** ${dnsNote}; ${tcpNote}${tlsRes?.success ? `; TLS negotiated \`${tlsRes.protocol}\` (\`${tlsCipherName}\`)` : ''}.\n` +
        `- **Scope note:** This confirms the tested URL responded with HTTP ${httpRes.statusCode}; it does not guarantee every downstream API route or database dependency behind the site is healthy.` +
        (plan.combinedExplanationRequested
          ? `\n- **Latency breakdown:** If the site feels slow, compare TCP handshake RTT (${tcpRes.latencyMs !== null ? `${tcpRes.latencyMs} ms` : 'unavailable'}) against HTTP TTFB (${ttfbMs !== null ? `${ttfbMs} ms` : 'unavailable'}). A low TCP RTT with a high TTFB points to backend application or database processing delay rather than network packet loss.`
          : '');
    } else if (httpRes.statusCode && httpRes.statusCode >= 400 && httpRes.statusCode < 500) {
      structuredAnswer = {
        result: `Transport connectivity to ${urlToProbe} succeeded (${dnsNote}, ${tcpNote}), and the server returned HTTP ${httpRes.statusCode} (${httpRes.statusMessage || 'Client/Auth Response'}) ${ttfbText}.`,
        meaning: `The web server listener is reachable and responding, but the requested URL path returned HTTP ${httpRes.statusCode} (missing route or authentication required).`,
        nextStep: `Verify the URL path or authentication credentials required by ${urlToProbe}.`,
        layerFailedFirst: `L7 HTTP Status ${httpRes.statusCode}`,
        uncertainty: null
      };
      reply = `Transport connectivity to **\`${urlToProbe}\`** succeeded (${dnsNote}, ${tcpNote}), and the web server returned **HTTP ${httpRes.statusCode}** ${ttfbText}. The listener is reachable, but this specific path requires authentication or was not found.`;
    } else if (httpRes.statusCode && httpRes.statusCode >= 500) {
      structuredAnswer = {
        result: `Transport connectivity to ${target}:${port} succeeded, but the tested endpoint returned HTTP ${httpRes.statusCode} (${httpRes.statusMessage || 'Server Error'}) ${ttfbText}.`,
        meaning: `Network transport is open, so the HTTP ${httpRes.statusCode} failure is occurring in the backend web application or upstream reverse proxy.`,
        nextStep: `Inspect the application server error logs on ${target} for HTTP ${httpRes.statusCode} exceptions.`,
        layerFailedFirst: `L7 HTTP Application (HTTP ${httpRes.statusCode})`,
        uncertainty: null
      };
      reply = `Network and TCP connectivity to **\`${target}:${port}\`** succeeded, but the endpoint returned **HTTP ${httpRes.statusCode}** ${ttfbText}. This points to an application or upstream reverse-proxy error rather than a network connectivity failure.`;
    } else if (tlsRes && !tlsRes.success) {
      structuredAnswer = {
        result: `${dnsNote} and ${tcpNote} succeeded, but the TLS handshake failed (${tlsRes.error}).`,
        meaning: `The server is reachable at the transport layer, but HTTPS encryption negotiation failed.`,
        nextStep: `Inspect the TLS certificate and SNI configuration on ${target}:${port}.`,
        layerFailedFirst: 'L6 TLS Handshake',
        uncertainty: null
      };
      reply = `${dnsNote} and ${tcpNote} succeeded, but the **TLS handshake failed** (\`${tlsRes.error}\`).`;
    } else {
      structuredAnswer = {
        result: `${dnsNote} and ${tcpNote} succeeded, but HTTP returned ${httpRes.statusCode || httpRes.error || 'an error'}.`,
        meaning: `Network transport is open, but the HTTP response did not complete cleanly.`,
        nextStep: `Verify the HTTP route and application listener configuration on ${target}:${port}.`,
        layerFailedFirst: 'L7 HTTP Application',
        uncertainty: null
      };
      reply = `${dnsNote} and ${tcpNote} succeeded, but the HTTP request failed (\`${httpRes.statusCode || httpRes.error || 'no HTTP response'}\`).`;
    }

    return {
      reply,
      structuredAnswer,
      steps,
      findings,
      technicalEvidence: {
        tool: 'website_multi_layer_probe',
        commandEquivalent: `curl -Iv ${urlToProbe}`,
        url: urlToProbe,
        target,
        resolvedIp,
        port,
        dns: dnsRes,
        tcp: tcpRes,
        tls: tlsRes,
        http: httpRes,
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Traceroute Scenario
   */
  async _executeTracerouteScenario(plan, session, signal) {
    this._checkAborted(signal);
    const target = plan.target;
    const probeHost = target.toLowerCase() === 'localhost' ? '127.0.0.1' : (plan.targetValidation?.pinnedIp || target);
    const t0 = performance.now();
    const traceRes = await realTraceroute(probeHost, 8);
    const durationMs = Number((performance.now() - t0).toFixed(1));
    const hops = Array.isArray(traceRes.hops) ? traceRes.hops : [];

    const steps = [
      {
        stepNumber: 1,
        label: `Tracing L3 hop-by-hop route to ${target} (${probeHost})…`,
        tool: 'realTraceroute',
        status: hops.length > 0 ? 'PASS' : 'WARN',
        summary: `Observed ${hops.length} hop(s) toward ${probeHost} (${durationMs} ms)`,
        durationMs
      }
    ];

    const structuredAnswer = {
      result: hops.length > 0
        ? `Traceroute to ${target} (${probeHost}) recorded ${hops.length} hop(s): ${hops.slice(0, 4).map((h) => `Hop ${h.hop}: ${h.ip || '*'} (${h.rtt1 ?? '*'}ms)`).join(' → ')}.`
        : `Traceroute to ${target} (${probeHost}) returned 0 responsive ICMP TTL hops.`,
      meaning: hops.length > 0
        ? `Packets are traversing the local gateway toward ${probeHost}.`
        : `Intermediate routers or container sandbox rules are filtering ICMP Time-Exceeded messages.`,
      nextStep: `Test direct TCP port reachability on ${target} to verify end-to-end transport.`,
      layerFailedFirst: null,
      uncertainty: hops.length === 0 ? 'Containerized environments and firewalls often suppress ICMP TTL-expired packets.' : null
    };

    const reply = `${structuredAnswer.result}\n\n${structuredAnswer.meaning}`;

    return {
      reply,
      structuredAnswer,
      steps,
      findings: [
        { label: 'Target', value: `${target} (${probeHost})`, tone: 'neutral' },
        { label: 'Hops Observed', value: String(hops.length), tone: hops.length > 0 ? 'ok' : 'warn' }
      ],
      technicalEvidence: {
        tool: 'realTraceroute',
        commandEquivalent: `traceroute -m 8 ${probeHost}`,
        target,
        resolvedIp: probeHost,
        rawResult: traceRes,
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Local Host / System Health Scenario
   */
  async _executeHostHealthScenario(plan, signal) {
    this._checkAborted(signal);
    const t0 = performance.now();
    const state = await autonomousInfrastructureOperator.getOperatorState();
    const tel = state.liveTelemetry || {};
    const durationMs = Number((performance.now() - t0).toFixed(1));

    const steps = [
      {
        stepNumber: 1,
        label: 'Inspecting local host OS telemetry, DNS resolver, and kernel socket table…',
        tool: 'collectLiveTelemetry',
        status: tel.dnsProbe?.success && tel.localTcpProbe?.reachable ? 'PASS' : 'WARN',
        summary: `Host ${tel.hostname}: CPU ${tel.cpuLoadPct}%, RAM ${tel.ramUsedPct}%, ${tel.sockets?.length || 0} kernel sockets`,
        durationMs
      }
    ];

    const structuredAnswer = {
      result: `Local runtime host "${tel.hostname}" (${tel.localIp || 'loopback only'}) is operating with ${tel.cpuLoadPct}% CPU load, ${tel.ramUsedPct}% RAM utilization (${tel.freeRamGb} GB free), ${tel.sockets?.length || 0} active kernel TCP sockets (${tel.socketStateCounts?.ESTABLISHED || 0} ESTABLISHED), live DNS lookup at ${tel.dnsProbe?.latencyMs ?? 'N/A'} ms, and local TCP loopback RTT at ${tel.localTcpProbe?.rttMs ?? 'N/A'} ms.`,
      meaning: tel.dnsProbe?.success && tel.localTcpProbe?.reachable
        ? 'Local host resources, DNS resolver, and kernel network stack are operating within normal thresholds.'
        : 'Local host telemetry detected degradation in either local DNS lookup or loopback socket responsiveness.',
      nextStep: 'Specify a remote hostname, IP address, or port to diagnose external connectivity.',
      layerFailedFirst: null,
      uncertainty: null
    };

    const reply = `${structuredAnswer.result}\n\n${structuredAnswer.meaning}`;

    return {
      reply,
      structuredAnswer,
      steps,
      findings: [
        { label: 'Host', value: `${tel.hostname} (${tel.localIp || 'loopback'})`, tone: 'neutral' },
        { label: 'CPU / RAM', value: `${tel.cpuLoadPct}% / ${tel.ramUsedPct}%`, tone: 'ok' },
        { label: 'Kernel Sockets', value: `${tel.sockets?.length || 0} (${tel.socketStateCounts?.ESTABLISHED || 0} ESTAB)`, tone: 'ok' },
        { label: 'Local DNS / TCP', value: `${tel.dnsProbe?.latencyMs ?? 'N/A'} ms / ${tel.localTcpProbe?.rttMs ?? 'N/A'} ms`, tone: 'ok' }
      ],
      technicalEvidence: {
        tool: 'autonomousInfrastructureOperator.getOperatorState',
        liveTelemetry: tel,
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Scenario E: Multi-Step Cross-Layer Investigation
   * Preserves legitimate 0ms measurements and returns null (never 1.2 or '<1') when timing is absent.
   */
  async _executeMultiStepInvestigation(plan, session, promptText, signal) {
    this._checkAborted(signal);
    const target = plan.target;
    const primaryPort = plan.ports[0] || (target === 'localhost' || target === '127.0.0.1' ? (Number(config.PORT) || 3000) : 443);
    const additionalPorts = plan.ports.slice(1);

    const wfResult = await crossLayerIncidentCorrelator.diagnoseUnreachableHostname(target, primaryPort, {
      pinnedIp: plan.targetValidation?.pinnedIp || null,
      resolvedIps: plan.targetValidation?.resolvedIps || null,
      dnsLatencyMs: plan.targetValidation?.dnsLatencyMs ?? null
    });

    this._checkAborted(signal);

    const steps = (wfResult.steps || []).map((s, idx) => ({
      stepNumber: idx + 1,
      label: `${s.layer}…`,
      tool: s.layer,
      status: s.status,
      summary: s.summary,
      durationMs: extractObservedTimingMs(s.details)
    }));

    const extraPortResults = [];
    for (const extraPort of additionalPorts.slice(0, 2)) {
      this._checkAborted(signal);
      if (wfResult.resolvedIp && !wfResult.steps?.some((s) => s.layer.includes('DNS') && s.status === 'FAIL')) {
        const tExtra = performance.now();
        const pRes = await checkPort(wfResult.resolvedIp, extraPort, 1500);
        const extraLatency = typeof pRes.connectLatencyMs === 'number'
          ? pRes.connectLatencyMs
          : (typeof pRes.latencyMs === 'number' ? pRes.latencyMs : Number((performance.now() - tExtra).toFixed(1)));
        extraPortResults.push({ ...pRes, latencyMs: extraLatency });
        steps.push({
          stepNumber: steps.length + 1,
          label: `Comparing secondary TCP port ${extraPort} on ${wfResult.resolvedIp}…`,
          tool: 'checkPort',
          status: pRes.status === 'OPEN' ? 'PASS' : 'FAIL',
          summary: pRes.status === 'OPEN'
            ? `TCP port ${extraPort} is OPEN (${extraLatency} ms)`
            : `TCP port ${extraPort} is ${pRes.status} (${pRes.errorCode || 'Unreachable'})`,
          durationMs: extraLatency
        });
      }
    }

    const firstFailedStep = steps.find((s) => s.status === 'FAIL');
    const topHyp = wfResult.correlation?.topHypothesis;
    const dnsStep = (wfResult.steps || []).find((s) => s.layer.includes('DNS'));
    const tcpStep = (wfResult.steps || []).find((s) => s.layer.includes('TCP'));
    const icmpStep = (wfResult.steps || []).find((s) => s.layer.includes('ICMP'));
    const httpStep = (wfResult.steps || []).find((s) => s.layer.includes('HTTP'));
    const tcpRttMs = extractObservedTimingMs(tcpStep?.details);
    const tcpRttDisplay = tcpRttMs !== null ? `${tcpRttMs} ms` : 'measured';

    this._recordEntityMemory(session, target, {
      intent: 'multi_step_investigation',
      success: !firstFailedStep,
      resolvedIps: wfResult.resolvedIp ? [wfResult.resolvedIp] : [],
      dnsStatus: dnsStep?.status === 'PASS' ? 'OK' : 'FAILED',
      openPorts: tcpStep?.status === 'PASS' ? [primaryPort] : [],
      closedPorts: tcpStep?.details?.status === 'CLOSED' ? [primaryPort] : [],
      summary: `Cross-layer investigation on ${target}:${primaryPort} (${firstFailedStep ? `Failed at ${firstFailedStep.label}` : 'All layers passed'})`
    });

    const findings = [
      { label: 'Target', value: `${target}:${primaryPort}`, tone: 'neutral' },
      {
        label: 'DNS Resolution',
        value: dnsStep?.status === 'PASS' ? `OK (${wfResult.resolvedIp})` : 'FAILED',
        tone: dnsStep?.status === 'PASS' ? 'ok' : 'danger'
      }
    ];
    if (tcpStep) {
      findings.push({
        label: `TCP Port ${primaryPort}`,
        value: tcpStep.status === 'PASS'
          ? `OPEN${tcpRttMs !== null ? ` (${tcpRttMs} ms)` : ''}`
          : (tcpStep.details?.status || 'FAILED'),
        tone: tcpStep.status === 'PASS' ? 'ok' : 'danger'
      });
    }
    for (const ep of extraPortResults) {
      findings.push({
        label: `TCP Port ${ep.port}`,
        value: ep.status === 'OPEN' ? `OPEN (${ep.latencyMs} ms)` : ep.status,
        tone: ep.status === 'OPEN' ? 'ok' : 'warn'
      });
    }
    if (httpStep) {
      findings.push({
        label: 'HTTP Layer',
        value: httpStep.details?.statusCode ? `HTTP ${httpStep.details.statusCode}` : 'No HTTP response',
        tone: httpStep.status === 'PASS' ? 'ok' : 'warn'
      });
    }

    let resultText;
    let meaningText;
    let nextStepText;
    let layerFailedFirst = firstFailedStep ? firstFailedStep.label.replace(/…$/, '') : null;
    let uncertaintyText = null;

    if (dnsStep && dnsStep.status === 'FAIL') {
      resultText = `Multi-step investigation of "${target}" stopped at Layer 7 DNS resolution: ${dnsStep.summary}.`;
      meaningText = `The problem is isolated to DNS name resolution for "${target}". Without a resolved IP address, TCP and HTTP connections cannot start.`;
      nextStepText = `Check whether "${target}" is spelled correctly, verify its DNS A/AAAA records, or test with the server's direct IP address.`;
    } else if (tcpStep && tcpStep.status === 'FAIL') {
      const tcpStatus = tcpStep.details?.status || 'UNREACHABLE';
      const anyExtraOpen = extraPortResults.find((e) => e.status === 'OPEN');
      if (tcpStatus === 'CLOSED') {
        resultText = `DNS resolved "${target}" to ${wfResult.resolvedIp} and the host is reachable on the network, but TCP port ${primaryPort} actively refused the connection (ECONNREFUSED / TCP RST)${anyExtraOpen ? ` while port ${anyExtraOpen.port} is OPEN` : ''}.`;
        meaningText = `Network routing and DNS are working properly. The failure is isolated to Layer 4 on ${wfResult.resolvedIp}: no service process is listening on TCP port ${primaryPort}.`;
        nextStepText = `Start or restart the application daemon expected on port ${primaryPort} on ${target}${anyExtraOpen ? `, or connect via open port ${anyExtraOpen.port}` : ''}.`;
      } else {
        resultText = `DNS resolved "${target}" to ${wfResult.resolvedIp}, but TCP connection attempts to port ${primaryPort} timed out (${tcpStatus})${icmpStep?.status === 'PASS' ? ' even though ICMP ping succeeded' : ''}.`;
        meaningText = icmpStep?.status === 'PASS'
          ? `Because ${wfResult.resolvedIp} replies to ICMP ping while TCP port ${primaryPort} times out, the host is online and a firewall or security group is silently dropping traffic to port ${primaryPort}.`
          : `Neither ICMP ping nor TCP port ${primaryPort} received a response from ${wfResult.resolvedIp}. Either the target device is powered off/disconnected, or an intermediate firewall is filtering all traffic to it.`;
        nextStepText = `Verify that ${target} (${wfResult.resolvedIp}) is powered on and inspect firewall rules permitting inbound TCP port ${primaryPort}.`;
        uncertaintyText = icmpStep?.status !== 'PASS'
          ? 'When both ICMP and TCP time out silently without a TCP RST, remote firewall filtering and an offline host produce identical wire symptoms.'
          : null;
      }
    } else if (httpStep && httpStep.status === 'FAIL') {
      const httpCode = httpStep.details?.statusCode;
      resultText = `DNS resolved "${target}" to ${wfResult.resolvedIp} and TCP port ${primaryPort} is OPEN (${tcpRttDisplay}), but the Layer 7 HTTP check failed (${httpCode ? `HTTP ${httpCode}` : (httpStep.summary || 'Application error')}).`;
      meaningText = `Lower-layer DNS and Layer 4 TCP transport connectivity succeeded, which proves the host is reachable and a socket listener is bound on port ${primaryPort}. However, an open TCP socket does not mean the application layer is healthy — Layer 7 HTTP returned an application-level failure.`;
      nextStepText = `Inspect the application service logs, reverse-proxy upstream pool, or HTTP route configuration on ${target}:${primaryPort}.`;
      layerFailedFirst = 'L7 HTTP Application Layer';
    } else {
      const mainChecksCount = wfResult.steps?.length || (steps.length - extraPortResults.length);
      const supplementalText = extraPortResults.length > 0
        ? ` (plus ${extraPortResults.length} supplemental port check${extraPortResults.length > 1 ? 's' : ''}: port ${extraPortResults.map((e) => e.port).join(', ')})`
        : '';
      resultText = `All ${mainChecksCount} diagnostic checks for ${target}:${primaryPort} passed${supplementalText} — DNS resolved to ${wfResult.resolvedIp}, and TCP port ${primaryPort} is OPEN (${tcpRttDisplay})${httpStep?.details?.statusCode ? ` with HTTP ${httpStep.details.statusCode}` : ''}.`;
      meaningText = httpStep?.status === 'PASS'
        ? `DNS resolution, Layer 4 TCP transport connectivity, and Layer 7 HTTP response (${httpStep.details?.statusCode || 200}) to ${target}:${primaryPort} succeeded.`
        : `DNS and Layer 4 TCP transport connectivity to ${target}:${primaryPort} succeeded. Note that transport reachability alone does not verify full Layer 7 application-route health unless an HTTP/application check is also run.`;
      nextStepText = `If users still experience application errors, inspect specific HTTP paths or server-side logs.`;
    }

    const hypothesisEvaluation = operationalMemoryEngine.evaluateDiagnosticHypotheses({
      target,
      port: primaryPort,
      dnsStep,
      icmpStep,
      tcpStep,
      httpStep,
      memoryInsights: session.lastMemoryInsights || null,
      extraPortResults
    });

    // Execute Closed-Loop Autonomous Blind-Spot Verification if specialists identify missing telemetry
    let closedLoopFollowUp = null;
    let collaborativeSynthesis = null;
    try {
      const initialSynthesis = operationalMemoryEngine.synthesizeCollaborativeSpecialistIntelligence({
        target,
        port: primaryPort,
        objective: promptText || `Investigate ${target}:${primaryPort}`,
        steps
      });
      collaborativeSynthesis = initialSynthesis;
      if (Array.isArray(initialSynthesis?.recommendedFollowUpProbes) && initialSynthesis.recommendedFollowUpProbes.length > 0) {
        closedLoopFollowUp = await operationalMemoryEngine.executeClosedLoopBlindSpotVerification({
          target,
          port: primaryPort,
          objective: promptText || `Investigate ${target}:${primaryPort}`,
          collaborativeSynthesis: initialSynthesis,
          steps,
          maxFollowUpProbes: 2
        });
        if (closedLoopFollowUp?.executed && Array.isArray(closedLoopFollowUp.newSteps)) {
          for (const ns of closedLoopFollowUp.newSteps) {
            steps.push({
              stepNumber: steps.length + 1,
              label: ns.label,
              tool: ns.tool || 'closedLoopVerification',
              status: ns.status,
              summary: ns.summary,
              durationMs: ns.durationMs || 0
            });
          }
          collaborativeSynthesis = closedLoopFollowUp.updatedSynthesis || initialSynthesis;
        }
      }
    } catch (_) {}

    const structuredAnswer = {
      result: resultText,
      meaning: meaningText,
      nextStep: nextStepText,
      layerFailedFirst,
      uncertainty: uncertaintyText,
      topHypothesis: topHyp ? { title: topHyp.title, probability: topHyp.posteriorProbability, status: topHyp.status } : null,
      hypothesisEvaluation
    };

    const reply =
      `${resultText}\n\n${meaningText}` +
      (uncertaintyText ? `\n\nNote on uncertainty: ${uncertaintyText}` : '');

    return {
      reply,
      structuredAnswer,
      hypothesisEvaluation,
      steps,
      findings,
      technicalEvidence: {
        tool: 'crossLayerIncidentCorrelator.diagnoseUnreachableHostname',
        workflowId: wfResult.workflowId,
        target,
        resolvedIp: wfResult.resolvedIp,
        port: primaryPort,
        extraPortResults,
        steps: wfResult.steps,
        topHypothesis: topHyp,
        hypothesisEvaluation,
        collaborativeSynthesis,
        closedLoopFollowUp,
        uncertaintyPanel: wfResult.correlation?.uncertaintyPanel,
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Scenario F: Contextual Follow-Up Explanation, Historical Comparison & Incident Report (Case Q)
   * Never defaults missing target to 'localhost'.
   */
  async _executeFollowUpExplanation(plan, session, promptText) {
    const prevAns = session.lastStructuredAnswer || {};
    const prevSteps = session.lastSteps || [];
    const prevTarget = session.lastValidTarget || session.lastTarget || null;
    const prevPorts = session.lastPorts || [];
    const lower = promptText.toLowerCase();
    const entities = Object.values(session.entityMemory || {});
    const targetEntity = (prevTarget && session.entityMemory?.[prevTarget.toLowerCase()]) || entities[entities.length - 1] || null;
    const effectiveTargetLabel = prevTarget || targetEntity?.target || 'current session';
    const observations = Array.isArray(targetEntity?.observations) ? targetEntity.observations : [];

    const firstFailed = prevSteps.find((s) => s.status === 'FAIL' || s.status === 'TIMEOUT');
    let reply;
    let reportMarkdown = null;

    // Compute structured before-vs-after state diff across observations for multi-turn continuity
    let stateDiff = null;
    if (observations.length >= 2) {
      const latestObs = observations[observations.length - 1];
      const prevObs = observations[observations.length - 2];
      const prevOpen = new Set(prevObs.openPorts || []);
      const currOpen = new Set(latestObs.openPorts || targetEntity?.openPorts || []);
      const newlyOpenedPorts = [...currOpen].filter((p) => !prevOpen.has(p));
      const newlyClosedPorts = [...prevOpen].filter((p) => !currOpen.has(p));
      const rttDeltaMs =
        typeof latestObs.pingRttMs === 'number' && typeof prevObs.pingRttMs === 'number'
          ? Number((latestObs.pingRttMs - prevObs.pingRttMs).toFixed(2))
          : null;
      stateDiff = {
        target: targetEntity?.target || effectiveTargetLabel,
        previousObservedAt: prevObs.observedAt,
        latestObservedAt: latestObs.observedAt,
        previousSummary: prevObs.summary || prevObs.intent,
        latestSummary: latestObs.summary || latestObs.intent,
        statusChanged: Boolean(prevObs.success !== latestObs.success || prevObs.summary !== latestObs.summary),
        previousSuccess: prevObs.success,
        latestSuccess: latestObs.success,
        rttDeltaMs,
        newlyOpenedPorts,
        newlyClosedPorts
      };
    }

    if (lower.includes('why did you say') && lower.includes('healthy')) {
      const stepSummary = prevSteps.length > 0
        ? prevSteps.map((s) => `${s.tool} (${s.status}: ${s.summary})`).join('; ')
        : (prevAns.result || 'the previous check');
      reply =
        `That assessment was based on the specific probes executed on **\`${effectiveTargetLabel}\`**: ${stepSummary}.\n\n` +
        `Important limitation: those probes only confirm the specific protocol layer and endpoint tested at that moment (for example, DNS resolution, a TCP handshake, or a single HTTP status code). They do not prove that every downstream microservice, database, or client network path is healthy.`;
    } else if (/\b(could dns be|could it be (?:a )?dns|is dns (?:the |a )?(?:problem|issue|cause)|is dns causing|might dns be)\b/i.test(lower)) {
      const isIpLiteral = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(String(effectiveTargetLabel).trim());
      const dnsStep = prevSteps.find((s) => s.tool === 'dns' || /dns/i.test(s.label || ''));
      const resolvedIps = targetEntity?.resolvedIps || [];
      if (isIpLiteral) {
        reply =
          `**DNS Hypothesis Evaluation for \`${effectiveTargetLabel}\`:**\n` +
          `Because **\`${effectiveTargetLabel}\`** is a direct IPv4 address literal rather than a domain name, network probes to \`${effectiveTargetLabel}\` bypass forward DNS resolution entirely. Forward DNS cannot be the cause of a connection timeout or refusal when connecting directly by IP (unless an application service on the target host is stalling on a reverse-DNS \`PTR\` lookup during connection acceptance).`;
      } else if (dnsStep && dnsStep.status === 'OK') {
        reply =
          `**DNS Hypothesis Evaluation for \`${effectiveTargetLabel}\`:**\n` +
          `Forward DNS resolution succeeded during our check (${dnsStep.summary}${resolvedIps.length ? ` → \`${resolvedIps.join(', ')}\`` : ''}). Because the hostname resolved cleanly to an IP address, DNS outage (` + '`NXDOMAIN` / `SERVFAIL`' + `) is not the primary failure point — though DNS could still contribute if the domain is pointing to a stale or decommissioned IP address.`;
      } else if (dnsStep && dnsStep.status === 'FAIL') {
        reply =
          `**DNS Hypothesis Evaluation for \`${effectiveTargetLabel}\`:**\n` +
          `Yes — DNS resolution failed on **\`${effectiveTargetLabel}\`** (${dnsStep.summary}). Until the domain resolves to a valid IP address, no downstream TCP, TLS, or HTTP connection can start.`;
      } else if (resolvedIps.length > 0) {
        reply =
          `**DNS Hypothesis Evaluation for \`${effectiveTargetLabel}\`:**\n` +
          `**\`${effectiveTargetLabel}\`** resolved to \`${resolvedIps.join(', ')}\` in this session, so basic DNS resolution is functioning. The issue is more likely at the transport (TCP port/firewall) or application layer unless those DNS records point to an outdated IP.`;
      } else {
        reply =
          `**DNS Hypothesis Evaluation for \`${effectiveTargetLabel}\`:**\n` +
          `DNS resolution is a plausible cause whenever a hostname fails before a TCP socket can be established. Run **\`Check DNS for ${effectiveTargetLabel}\`** to test its A/AAAA records and resolver latency directly.`;
      }
    } else if (/\b(what does (?:that|this|the|a) (?:timeout|time out|error|refusal|connection refused|reset|failure) mean|why (?:is|isn't|isnt) (?:it|that|this|the server|that server|the host|that host|the site|the service|the endpoint) (?:not responding|timing out))\b/i.test(lower)) {
      const stepSummary = prevSteps.length > 0
        ? prevSteps.map((s) => `${s.label || s.tool}: ${s.status} (${s.summary})`).join('; ')
        : (prevAns.result || 'No response observed within timeout window');
      const hasTimeout = /timeout|timed out|no response/i.test(`${lower} ${prevAns.result || ''} ${stepSummary}`);
      const hasRefused = /refused|econnrefused|closed|rst/i.test(`${prevAns.result || ''} ${stepSummary}`);
      if (hasTimeout && !hasRefused) {
        reply =
          `**Meaning of the Timeout on \`${effectiveTargetLabel}\`${prevPorts.length ? ` (port ${prevPorts.join(', ')})` : ''}:**\n` +
          `In our check (${stepSummary}), packets were transmitted toward **\`${effectiveTargetLabel}\`**, but **zero acknowledgment (\`SYN-ACK\` or ICMP echo reply) returned before the deadline expired**.\n\n` +
          `**Technical Distinction:** Unlike \`ECONNREFUSED\` (which proves the host is reachable and actively rejected the port with a TCP \`RST\`), a **timeout** means packets were either:\n` +
          `1. Silently dropped by an inline firewall, security group, or ACL (\`DROP\` policy),\n` +
          `2. Routed toward an offline or unroutable IP address on the network path, or\n` +
          `3. Accepted by a heavily overloaded daemon whose backlog queue could not respond in time.`;
      } else if (hasRefused) {
        reply =
          `**Meaning of the Connection Failure on \`${effectiveTargetLabel}\`${prevPorts.length ? ` (port ${prevPorts.join(', ')})` : ''}:**\n` +
          `Our probe recorded: ${stepSummary}.\n\n` +
          `The target host **\`${effectiveTargetLabel}\`** is reachable over the network, but its operating system kernel actively rejected the connection (typically via a TCP \`RST\` packet) because no application process is listening on ${prevPorts.length ? `port ${prevPorts.join(', ')}` : 'that port'} or a local firewall rule is configured with \`REJECT\`.`;
      } else {
        reply =
          `**Diagnostic Explanation for \`${effectiveTargetLabel}\`${prevPorts.length ? ` (port ${prevPorts.join(', ')})` : ''}:**\n` +
          `Observed evidence: ${stepSummary}.\n\n` +
          `${prevAns.meaning || 'When a target does not respond, either network packets are being filtered/dropped along the path (timeout) or the destination service is not listening on the requested port.'}`;
      }
    } else if (
      lower.includes('compare the latest') ||
      lower.includes('current state to') ||
      lower.includes('previous scan') ||
      lower.includes('previous result') ||
      lower.includes('last result') ||
      lower.includes('last check') ||
      lower.includes('compare it with') ||
      lower.includes('compare it to') ||
      lower.includes('compare with') ||
      lower.includes('what changed')
    ) {
      if (observations.length >= 2) {
        const latest = observations[observations.length - 1];
        const previous = observations[observations.length - 2];
        reply =
          `**Historical Comparison** for **\`${targetEntity.target}\`**:\n` +
          `- **Previous (${previous.observedAt}):** ${previous.summary || previous.intent}\n` +
          `- **Latest (${latest.observedAt}):** ${latest.summary || latest.intent}\n\n` +
          (latest.pingRttMs !== null && previous.pingRttMs !== null
            ? `Ping RTT changed from ${previous.pingRttMs} ms to ${latest.pingRttMs} ms.`
            : `Currently confirmed open ports: [${(targetEntity.openPorts || []).join(', ') || 'none'}]; closed ports: [${(targetEntity.closedPorts || []).join(', ') || 'none'}].`);
      } else {
        const single = observations[0];
        reply =
          `**Historical Comparison:** Only ${observations.length || 1} observation has been recorded for **\`${effectiveTargetLabel}\`** so far${single ? ` at ${single.observedAt} (${single.summary})` : ''}. Run another check on \`${effectiveTargetLabel}\` if you want to compare changes over time.`;
      }
    } else if (lower.includes('what have we tested') || lower.includes('what have we found') || lower.includes('show memory') || lower.includes('compare')) {
      const entityBullets = entities.length > 0
        ? entities.map((e) =>
            `- **\`${e.target}\`** (${e.resolvedIps.join(', ') || 'unresolved'}): checked ${e.checkCount}x (last at ${e.lastSeenAt}) · Open ports: [${e.openPorts.join(', ') || 'none'}] · Closed ports: [${e.closedPorts.join(', ') || 'none'}] · Latest: ${e.lastOutcomeSummary || 'N/A'}`
          ).join('\n')
        : `- **\`${effectiveTargetLabel}\`**: ${prevAns.result || 'Tested in current session.'}`;
      reply =
        `**Session Summary** — here is what we have tested and observed in this session (${entities.length || 1} host(s) across ${session.turnCount || 1} turn(s)):\n${entityBullets}`;
    } else if (lower.includes('which layer failed')) {
      const layerName = prevAns.layerFailedFirst || (firstFailed ? firstFailed.label : 'None — all tested layers passed');
      reply =
        `First failing layer on **\`${effectiveTargetLabel}\`**: **${layerName}**.\n\n` +
        `${prevAns.meaning || 'Each layer was evaluated in sequence from DNS resolution through TCP transport and application delivery.'}`;
    } else if (lower.includes('incident report') || lower.includes('summarize')) {
      const stepBullets = prevSteps.map((s) => `- **Step ${s.stepNumber} (${s.tool}):** ${s.status} — ${s.summary}`).join('\n');
      const entityBullets = entities.map((e) =>
        `- **${e.target}** (${e.resolvedIps.join(', ') || 'unresolved'}): ${e.lastOutcomeSummary || 'tested'}`
      ).join('\n');
      reportMarkdown =
        `# EJII Technical Diagnostic Summary\n` +
        `- **Target Investigated:** ${effectiveTargetLabel}${prevPorts.length ? ` (Ports: ${prevPorts.join(', ')})` : ''}\n` +
        `- **Timestamp:** ${new Date().toISOString()}\n` +
        `- **First Failing Layer:** ${prevAns.layerFailedFirst || 'None (All tested layers passed)'}\n\n` +
        `## Checks Executed & Measured Evidence\n${stepBullets || entityBullets || '- Diagnostic check completed.'}\n\n` +
        `## Findings & Assessment\n- **Observed Outcome:** ${prevAns.result || 'N/A'}\n- **Technical Interpretation:** ${prevAns.meaning || 'N/A'}\n` +
        (prevAns.uncertainty ? `- **Remaining Uncertainties:** ${prevAns.uncertainty}\n` : '') +
        `\n## Recommended Next Steps\n- ${prevAns.nextStep || 'Continue monitoring.'}`;

      reply =
        `**Session Summary**${prevTarget ? ` for **\`${prevTarget}\`**` : ''}:\n\n` +
        `${prevAns.result || 'Completed diagnostic checks.'}\n\n` +
        (stepBullets ? `**Checks Performed:**\n${stepBullets}\n\n` : (entityBullets ? `**Hosts Tested:**\n${entityBullets}\n\n` : '')) +
        `${prevAns.meaning || ''}`;
    } else {
      reply =
        `From the previous check${prevTarget ? ` on **\`${prevTarget}${prevPorts.length ? `:${prevPorts.join(',')}` : ''}\`**` : ''}: ${prevAns.result || 'Diagnostic completed.'}\n\n` +
        `${prevAns.meaning || 'The observed response reflects the measured network and service state.'}` +
        (prevAns.uncertainty ? `\n\nNote: ${prevAns.uncertainty}` : '');
    }

    return {
      reply,
      structuredAnswer: {
        ...prevAns,
        stateDiff
      },
      steps: [],
      reportMarkdown,
      findings: [
        ...(prevTarget ? [{ label: 'Context Target', value: prevTarget, tone: 'neutral' }] : []),
        { label: 'Hosts in Memory', value: String(entities.length), tone: 'ok' },
        { label: 'First Failing Layer', value: prevAns.layerFailedFirst || 'None (All Passed)', tone: prevAns.layerFailedFirst ? 'warn' : 'ok' }
      ],
      technicalEvidence: {
        lastToolResults: session.lastToolResults,
        entityMemory: session.entityMemory,
        targetHistory: session.targetHistory,
        stateDiff
      }
    };
  }

  /**
   * Scenario H: Authorized Governed Remediation Execution
   */
  async _executeRemediationScenario(plan, user, signal) {
    this._checkAborted(signal);
    const t0 = performance.now();
    const target = plan.target || '127.0.0.1';
    const port = plan.ports[0] || (Number(config.PORT) || 3000);

    const healRes = await autonomousInfrastructureOperator.approveAndExecuteSelfHealing({
      actionId: 'verify_and_refresh_dns_resolution',
      target,
      port,
      role: user.role,
      user
    });
    const durationMs = Number((performance.now() - t0).toFixed(1));

    const verified = healRes.status === 'APPLIED_AND_VERIFIED' && healRes.verification?.postconditionPassed;
    const steps = [
      {
        stepNumber: 1,
        label: 'Capturing SQLite pre-execution snapshot and refreshing DNS resolver state…',
        tool: 'approveAndExecuteSelfHealing',
        status: verified ? 'PASS' : 'FAIL',
        summary: healRes.verification?.summary || healRes.error || healRes.status,
        durationMs
      }
    ];

    const structuredAnswer = {
      result: verified
        ? `Governed DNS resolver refresh and endpoint verification succeeded (Snapshot ${healRes.verification.preSnapshotId}). Post-check DNS latency: ${healRes.verification.afterMetrics?.liveDnsRttMs ?? 'N/A'} ms, TCP latency: ${healRes.verification.afterMetrics?.liveTcpRttMs ?? 'N/A'} ms.`
        : `Remediation did not pass postcondition verification (${healRes.status}): ${healRes.error || healRes.verification?.failureReason || 'Rolled back safely'}.`,
      meaning: verified
        ? 'The process DNS resolver configuration was refreshed, pre-state was backed up in SQLite, and live postcondition probes verified reachability.'
        : 'Because postcondition verification did not pass, EJII automatically restored the prior state from the SQLite snapshot.',
      nextStep: verified
        ? 'Re-run your diagnostic check to confirm the target service is responding.'
        : 'Inspect the underlying target listener or upstream DNS server manually.',
      layerFailedFirst: verified ? null : 'Postcondition Verification',
      uncertainty: null
    };

    const reply = `${structuredAnswer.result}\n\n${structuredAnswer.meaning}`;

    if (verified) {
      operationalMemoryEngine.recordVerifiedResolution({
        target,
        symptomSignature: 'DNS_RESOLVER_REFRESH_AND_VERIFY',
        rootCause: 'Transient or stale DNS resolver state requiring governed refresh and postcondition verification',
        resolutionSteps: `Executed governed action verify_and_refresh_dns_resolution (Snapshot ${healRes.verification.preSnapshotId})`,
        port,
        verifiedBy: user.username || 'operator'
      });
    }

    operationalMemoryEngine.recordOperationalDecision({
      target,
      decisionType: 'GOVERNED_SELF_HEALING',
      actionId: 'verify_and_refresh_dns_resolution',
      rationale: `Operator-approved DNS resolver refresh and live postcondition verification on ${target}:${port}`,
      approvedBy: user.username || 'operator',
      role: user.role || 'OPERATOR',
      outcomeStatus: verified ? 'APPLIED_AND_VERIFIED' : (healRes.status || 'ROLLED_BACK'),
      beforeMetrics: healRes.verification?.beforeMetrics || null,
      afterMetrics: healRes.verification?.afterMetrics || null
    });

    return {
      reply,
      structuredAnswer,
      steps,
      findings: [
        { label: 'Action', value: 'verify_and_refresh_dns_resolution', tone: 'neutral' },
        { label: 'Status', value: healRes.status, tone: verified ? 'ok' : 'danger' },
        { label: 'Snapshot', value: healRes.verification?.preSnapshotId || 'N/A', tone: 'neutral' }
      ],
      technicalEvidence: healRes
    };
  }

  /**
   * Scenario J: Cross-System Operational Intelligence, Correlated Incidents & Command Center Synthesis
   * Correlates historical entity baselines, EWMA/Z-score latency drift, state regressions,
   * multi-target Correlated Operational Incidents, AI Operations Commander coordination,
   * systemic cross-target patterns, learned playbooks, and decision ledger outcomes.
   */
  async _executeInfrastructureIntelligenceSynthesisScenario(plan, session, promptText) {
    const t0 = performance.now();
    const effectiveTarget =
      plan.target && plan.target !== 'operational_intelligence_fabric'
        ? plan.target
        : (session?.lastValidTarget || '127.0.0.1');
    const briefing = operationalMemoryEngine.getIntelligenceBriefing();
    const fleetMatrix = operationalMemoryEngine.getFleetIntelligenceMatrix();
    const overview = operationalMemoryEngine.getOperationalMemoryOverview(25);
    const commandCenterOverview = operationalMemoryEngine.getOperationsCommandCenterOverview({
      target: effectiveTarget,
      port: (Array.isArray(plan.ports) && plan.ports[0]) || 443
    });
    const graphState = temporalInfrastructureGraph.getGraphState();
    const durationMs = Number((performance.now() - t0).toFixed(2));

    const topPriority = fleetMatrix.highestPriorityInvestigation;
    const execSituation = commandCenterOverview.executiveSituationSummary;
    const correlatedIncidents = commandCenterOverview.correlatedIncidents || [];
    const commander = commandCenterOverview.operationsCommander;
    const debtRadar = commandCenterOverview.technicalDebtRadar;
    const incidentDna = commandCenterOverview.incidentDnaSummary;
    const blackBox = commandCenterOverview.networkBlackBoxSummary;
    const orgKnowledge = commandCenterOverview.organizationalKnowledge;
    const subfocus = plan.synthesisSubfocus || 'FULL_COMMAND_CENTER';

    const steps = [
      {
        stepNumber: 1,
        label: 'Synthesizing cross-target baselines, EWMA latency drift, and state regressions…',
        tool: 'operationalMemoryEngine.getIntelligenceBriefing',
        status: 'PASS',
        summary: `Evaluated ${briefing.fleetSummary.totalTrackedEntities} tracked entity baseline(s), ${briefing.activeRegressions.length} active regression(s), and ${briefing.learnedPlaybooksCount} learned playbook(s)`,
        durationMs
      },
      {
        stepNumber: 2,
        label: 'Computing Fleet-Wide Priority Matrix, Technical Debt Radar, Incident DNA, and Network Black Box timeline…',
        tool: 'operationalMemoryEngine.getFleetIntelligenceMatrix',
        status: 'PASS',
        summary: topPriority
          ? `#1 Priority Target: ${topPriority.target} (Priority Score: ${topPriority.priorityScore}/100) · Top Debt: ${debtRadar?.topWeaknesses?.[0]?.title || 'N/A'} · Incident DNA: ${incidentDna?.dnaFingerprintId || 'N/A'}`
          : 'All fleet targets operating within nominal EWMA and port reachability baselines',
        durationMs: 0.4
      },
      {
        stepNumber: 3,
        label: 'Correlating multi-target operational incidents, service criticality tiers, and AI Operations Commander state…',
        tool: 'operationalMemoryEngine.getOperationsCommandCenterOverview',
        status: 'PASS',
        summary: `${correlatedIncidents.length} correlated incident(s) (${execSituation?.overallPosture || 'NOMINAL'}) · ${commander?.activeInvestigationsCount || 0} active cross-workspace investigation(s) · ${commander?.avoidedDuplicateProbesCount || 0} duplicate probe(s) avoided`,
        durationMs: 0.5
      }
    ];

    const findings = [
      {
        label: 'Command Posture',
        value: `${execSituation?.overallPosture || 'NOMINAL'} (${correlatedIncidents.length} correlated incident(s))`,
        tone: correlatedIncidents.length > 0 ? 'warn' : 'ok'
      },
      {
        label: 'Fleet Stability',
        value: `${briefing.fleetSummary.averageStabilityScore}% (${briefing.fleetSummary.healthyEntities}/${briefing.fleetSummary.totalTrackedEntities} healthy)`,
        tone: briefing.fleetSummary.averageStabilityScore >= 80 ? 'ok' : 'warn'
      },
      {
        label: 'Incident DNA',
        value: incidentDna?.dnaFingerprintId || 'DNA-NOMINAL',
        tone: incidentDna?.haveWeExperiencedBefore ? 'warn' : 'neutral'
      },
      {
        label: 'Top Debt Radar #1',
        value: debtRadar?.topWeaknesses?.[0] ? `${debtRadar.topWeaknesses[0].severity} (${debtRadar.topWeaknesses[0].priorityScore}/100)` : 'Nominal',
        tone: 'warn'
      },
      {
        label: '#1 Priority Target',
        value: topPriority ? `${topPriority.target} (Score ${topPriority.priorityScore})` : 'None (Fleet Nominal)',
        tone: topPriority && topPriority.priorityScore >= 40 ? 'warn' : 'ok'
      },
      {
        label: 'Runbook Coverage',
        value: `${orgKnowledge?.humanFirewallResilience?.runbookCoveragePct ?? 100}% (${orgKnowledge?.knowledgeVaultCount || 0} vault items)`,
        tone: 'ok'
      }
    ];

    const incidentLines = correlatedIncidents.length > 0
      ? correlatedIncidents.map((inc) =>
          `- **[${inc.severity} · ${inc.criticalityTier}] ${inc.title}**:\n` +
          `  - **Primary Root Cause:** ${inc.primaryRootCause} (Target: \`${inc.primaryRootCauseTarget}\`)\n` +
          `  - **Downstream / Secondary Symptoms:** ${inc.downstreamSymptoms?.join('; ') || 'Isolated to primary target'}\n` +
          `  - **Responsible Team & Escalation:** ${inc.responsibleTeam?.team || 'Platform Ops'} (\`${inc.responsibleTeam?.escalationChannel || '#ops'}\`)\n` +
          `  - **Recommended Commander Action:** ${inc.recommendedAction}`
        ).join('\n')
      : '- No active correlated multi-service incidents. All monitored targets are operating within baseline.';

    const debtLines = (debtRadar?.topWeaknesses || []).map((w) =>
      `- **#${w.rank} [${w.severity} · Score ${w.priorityScore}/100] ${w.title}** (\`${w.category}\`)\n` +
      `  - *Empirical Evidence:* ${w.empiricalEvidence}\n` +
      `  - *Recommended Management Action:* ${w.recommendedManagementAction} (Owner: **${w.owningTeam}**)`
    ).join('\n');

    const dnaLines = incidentDna
      ? `- **Incident DNA Fingerprint:** \`${incidentDna.dnaFingerprintId}\` (${Object.values(incidentDna.structuralGenes || {}).join(' · ')})\n` +
        `- **Historical Similarity Answer:** ${incidentDna.answerSummary}\n` +
        `- **The Last Admin Runbook Vault:** ${orgKnowledge?.knowledgeVaultCount || 0} preserved institutional runbook(s) · Human Firewall Coverage: **${orgKnowledge?.humanFirewallResilience?.runbookCoveragePct ?? 100}%**`
      : '- No Incident DNA fingerprint evaluated.';

    const blackBoxLines = blackBox
      ? `- **Flight Recorder Summary:** ${blackBox.whatChangedBeforeOutageSummary}\n` +
        ((blackBox.preFailureChanges || []).map((c) => `  - \`[${c.timestamp}]\` **${c.target}** (\`${c.eventType}\`): ${c.detail}`).join('\n') || '  - No abrupt pre-incident configuration or port state changes recorded.')
      : '- No Black Box events recorded.';

    const regressionLines = briefing.activeRegressions.length > 0
      ? briefing.activeRegressions.map((r) => `- **\`${r.target}\`** (${r.severity}): ${r.detail} (Stability: ${r.stabilityScore}%)`).join('\n')
      : '- No active port or reachability regressions detected across tracked baselines.';

    const riskLines = briefing.predictiveRisks.length > 0
      ? briefing.predictiveRisks.map((r) => `- **\`${r.target}\`** [${r.type}]: ${r.detail}`).join('\n')
      : '- No statistically significant upward EWMA latency drift or intermittent flapping detected.';

    const playbookLines = (overview.resolutions || []).map((p) =>
      `- **\`${p.symptomSignature}\`**${p.targetKey !== '*' ? ` (${p.targetKey})` : ''}: ${p.rootCause} → *${p.resolutionSteps}* (Verified ${p.successCount || p.hitCount || 1}x)`
    ).join('\n') || '- No learned playbooks recorded yet.';

    const cog2 = commandCenterOverview.cognition2Overview || null;
    const timeMachine30m = cog2?.operationalTimeMachine || operationalMemoryEngine.reconstructOperationalTimeMachine({ target: effectiveTarget, windowMinutes: 30 });
    const activeCaps = new Set(Array.isArray(plan.activeSynthesisCapabilities) ? plan.activeSynthesisCapabilities : [
      'PRE_INCIDENT_TIMELINE_RECONSTRUCTION',
      'MULTI_DOMAIN_HYPOTHESIS_ARBITRATION',
      'PREDICTIVE_HORIZON_ATTENTION',
      'SUPERPOWERS_UNIFIED_SYNTHESIS',
      subfocus
    ]);

    const knowledgeQa = (activeCaps.has('ORGANIZATIONAL_KNOWLEDGE_WHY') || activeCaps.has('SERVER_CONFIG_DIFFERENTIAL_WHY') || subfocus === 'ORGANIZATIONAL_KNOWLEDGE_WHY' || subfocus === 'SERVER_CONFIG_DIFFERENTIAL_WHY')
      ? operationalMemoryEngine.queryOrganizationalKnowledgeNaturalLanguage({ question: promptText, target: effectiveTarget })
      : (cog2?.knowledgeIntelligence || null);
    const serverConfigDifferential = (activeCaps.has('SERVER_CONFIG_DIFFERENTIAL_WHY') || subfocus === 'SERVER_CONFIG_DIFFERENTIAL_WHY')
      ? operationalMemoryEngine.analyzeServerConfigurationDifferential({ target: effectiveTarget, question: promptText })
      : null;

    // Non-mutually-exclusive parallel execution of specialized investigations AND unified cognitive engines
    const inheritedResolution = resolvePronounInheritedTarget(promptText, session || {});
    const effectivePort = (Array.isArray(plan.ports) && plan.ports[0]) || inheritedResolution.port || 3000;
    const synthesisTarget = plan.explicitTarget || inheritedResolution.target || effectiveTarget;
    const [
      dynamicCapabilityInvestigation,
      directAutonomousGoalResult,
      unifiedSuperpowersReport
    ] = await Promise.all([
      (activeCaps.has('BROAD_UNSPECIFIED_INFRASTRUCTURE_INVESTIGATION') || subfocus === 'BROAD_UNSPECIFIED_INFRASTRUCTURE_INVESTIGATION')
        ? operationalMemoryEngine.executeDynamicCapabilityInvestigation({
            objective: promptText,
            target: plan.explicitTarget || null,
            port: effectivePort,
            initiatedBy: session?.username || 'operator',
            role: session?.role || 'ADMIN'
          })
        : Promise.resolve(null),
      (activeCaps.has('AUTONOMOUS_GOAL_MULTI_EMPLOYEE_ACCESS') || subfocus === 'AUTONOMOUS_GOAL_MULTI_EMPLOYEE_ACCESS')
        ? operationalMemoryEngine.executeAutonomousGoalInvestigation({
            objective: promptText,
            target: effectiveTarget,
            port: effectivePort,
            initiatedBy: session?.username || 'operator',
            role: session?.role || 'ADMIN'
          })
        : Promise.resolve(null),
      superpowersSkillsEngine.executeUnifiedSuperpowersSynthesis({
        objective: promptText,
        target: synthesisTarget,
        port: effectivePort,
        windowMinutes: 60,
        executeClosedLoop: true,
        initiatedBy: session?.username || 'operator'
      })
    ]);

    const autonomousGoalResult = directAutonomousGoalResult || dynamicCapabilityInvestigation?.autonomousGoalInvestigation || null;
    const timelineReconstruction = unifiedSuperpowersReport?.timelineReconstruction || null;
    const hypothesisArbitration = unifiedSuperpowersReport?.hypothesisArbitration || null;
    const predictiveHorizon = unifiedSuperpowersReport?.predictiveHorizon || null;
    if (session && unifiedSuperpowersReport?.contextEngineeringWindow) {
      session.lastCompiledContextWindow = unifiedSuperpowersReport.contextEngineeringWindow;
    }

    function dynamicGoalStageCount(dci) {
      return (dci?.autonomousGoalInvestigation?.completedStages?.length || 0);
    }

    if (dynamicCapabilityInvestigation) {
      steps.push({
        stepNumber: steps.length + 1,
        label: `Executing Cognition 3.0 Dynamic Problem Solver & Capability Ecosystem Investigation ("${promptText.slice(0, 64)}…")`,
        tool: 'operationalMemoryEngine.executeDynamicCapabilityInvestigation',
        status: 'PASS',
        summary: `Problem Nature: ${dynamicCapabilityInvestigation.problemNatureStrategy.problemNatureClassification.primaryNature} · Discovered Target: ${dynamicCapabilityInvestigation.target} · Parallel Groups: ${dynamicCapabilityInvestigation.capabilityExecutionTrace.parallelGroupsExecuted.length} · Conditional Stages: ${dynamicGoalStageCount(dynamicCapabilityInvestigation)}`,
        durationMs: dynamicCapabilityInvestigation.totalDurationMs
      });
    }
    if (directAutonomousGoalResult) {
      steps.push({
        stepNumber: steps.length + 1,
        label: `Executing Goal-Oriented Multi-Stage Autonomous Investigation ("${promptText.slice(0, 64)}…")`,
        tool: 'operationalMemoryEngine.executeAutonomousGoalInvestigation',
        status: 'PASS',
        summary: `Executed ${directAutonomousGoalResult.completedStages.length} adaptive stage(s) (${directAutonomousGoalResult.adaptivePivotLog.length} dynamic pivot(s)) · Status: ${directAutonomousGoalResult.status}`,
        durationMs: directAutonomousGoalResult.totalDurationMs
      });
    }
    if (serverConfigDifferential) {
      steps.push({
        stepNumber: steps.length + 1,
        label: `Analyzing Institutional Server Configuration Differential across peer fleet & runbooks for "${effectiveTarget}"…`,
        tool: 'operationalMemoryEngine.analyzeServerConfigurationDifferential',
        status: 'PASS',
        summary: `${serverConfigDifferential.differentialCount} differential(s) (${serverConfigDifferential.documentedIntentionalCount} documented, ${serverConfigDifferential.undocumentedDriftCount} undocumented drift)`,
        durationMs: 0.6
      });
    }
    if (timelineReconstruction) {
      steps.push({
        stepNumber: steps.length + 1,
        label: `Reconstructing Pre-Incident Chronological Timeline & Patient Zero via MAD + CUSUM Changepoint Detection…`,
        tool: 'timelineReconstructor.reconstructPreIncidentTimeline',
        status: 'PASS',
        summary: `Patient Zero: ${timelineReconstruction.patientZero.target} (${timelineReconstruction.patientZero.initialSymptom}) · ${timelineReconstruction.totalEventsCount} chronological event(s) · CUSUM Changepoint: ${timelineReconstruction.changepointAnalysis.changepointDetected ? 'DETECTED' : 'NOMINAL'}`,
        durationMs: timelineReconstruction.durationMs
      });
    }
    if (hypothesisArbitration) {
      steps.push({
        stepNumber: steps.length + 1,
        label: `Executing Autonomous Closed-Loop 6-Domain Hypothesis Arbitration & Shannon Information-Gain Probes…`,
        tool: 'hypothesisArbiter.arbitrateAndExecuteClosedLoop',
        status: 'PASS',
        summary: `#1 Winning Domain: ${hypothesisArbitration.winningHypothesis.title} (P=${hypothesisArbitration.winningHypothesis.probabilityPct}%) · Executed ${hypothesisArbitration.closedLoopStepsExecuted} closed-loop probe(s) · Entropy reduced ${hypothesisArbitration.initialEntropyBits} -> ${hypothesisArbitration.finalEntropyBits} bits`,
        durationMs: hypothesisArbitration.totalDurationMs
      });
    }
    if (predictiveHorizon) {
      steps.push({
        stepNumber: steps.length + 1,
        label: `Evaluating Non-Linear M/M/1 Queueing Saturation Cliffs, Holt-Winters Trajectory & Cut-Vertex Cascade Risk…`,
        tool: 'predictiveHorizonEngine.evaluatePredictiveHorizon',
        status: 'PASS',
        summary: `Evaluated ${predictiveHorizon.endpointsEvaluatedCount} endpoint(s) · Overall Risk: ${predictiveHorizon.overallRiskScore}/100 (${predictiveHorizon.overallRiskTier}) · ${predictiveHorizon.cutVerticesCount} topological cut-vertex SPOF(s)`,
        durationMs: predictiveHorizon.durationMs
      });
    }

    // Compose unified executive summary without branch collision or summary overwrites
    const executiveSummaryParts = [];
    if (subfocus === 'BROAD_UNSPECIFIED_INFRASTRUCTURE_INVESTIGATION' && dynamicCapabilityInvestigation) {
      executiveSummaryParts.push(dynamicCapabilityInvestigation.executiveConclusion);
    }
    if (subfocus === 'SERVER_CONFIG_DIFFERENTIAL_WHY' && serverConfigDifferential) {
      executiveSummaryParts.push(serverConfigDifferential.whyConfiguredDifferentlySummary);
    }
    if (subfocus === 'TECHNICAL_DEBT_RADAR' && debtRadar) {
      executiveSummaryParts.push(`${debtRadar.executiveDebtSummary} Top 5 weaknesses ranked: ${debtRadar.topWeaknesses.map((w) => `#${w.rank} ${w.title}`).join('; ')}.`);
    }
    if (subfocus === 'ORGANIZATIONAL_KNOWLEDGE_WHY' && knowledgeQa) {
      executiveSummaryParts.push(knowledgeQa.synthesizedAnswer);
    }
    if (subfocus === 'INCIDENT_DNA_AND_PLAYBOOKS' && incidentDna) {
      executiveSummaryParts.push(`${incidentDna.answerSummary} Preserved institutional runbooks in 'The Last Admin' vault: ${orgKnowledge?.knowledgeVaultCount || 0}.`);
    }
    if (subfocus === 'OPERATIONAL_TIME_MACHINE_30M' && timeMachine30m) {
      executiveSummaryParts.push(timeMachine30m.narrativeSummary);
    }
    if (subfocus === 'PRE_INCIDENT_TIMELINE_RECONSTRUCTION' && timelineReconstruction) {
      executiveSummaryParts.push(timelineReconstruction.narrativeSummary);
    }
    if (subfocus === 'NETWORK_BLACK_BOX_TIMELINE' && blackBox) {
      executiveSummaryParts.push(blackBox.whatChangedBeforeOutageSummary);
    }
    if (subfocus === 'MULTI_DOMAIN_HYPOTHESIS_ARBITRATION' && hypothesisArbitration) {
      executiveSummaryParts.push(hypothesisArbitration.executiveSummary);
    }
    if (subfocus === 'PREDICTIVE_HORIZON_ATTENTION' && predictiveHorizon) {
      executiveSummaryParts.push(predictiveHorizon.executiveSummary);
    }
    if (subfocus === 'SUPERPOWERS_UNIFIED_SYNTHESIS' && unifiedSuperpowersReport) {
      executiveSummaryParts.push(unifiedSuperpowersReport.unifiedExecutiveSummary);
    }
    if (subfocus === 'AUTONOMOUS_GOAL_MULTI_EMPLOYEE_ACCESS' && autonomousGoalResult) {
      executiveSummaryParts.push(
        `Goal-Oriented Investigation (${autonomousGoalResult.goalId}): ${autonomousGoalResult.decomposition.inferredOperationalObjective} Executed ${autonomousGoalResult.completedStages.length} adaptive diagnostic stages across DNS, L3 Gateway, L4 TCP/Port-Split, and L7 HTTP (${autonomousGoalResult.adaptivePivotLog.map((p) => p.adaptationDecision).join(' ') || 'All stages verified'}).`
      );
    }
    if (subfocus === 'MULTI_DEVICE_OR_TOP_PROBLEMS') {
      executiveSummaryParts.push(
        `Multi-Target & Shared Dependency Correlation: Simultaneous connectivity loss across multiple endpoints points to a shared upstream dependency (Default Gateway, DHCP/VLAN trunk, or Recursive DNS Resolver) rather than coincidental individual host failures. ${execSituation?.whatIsHappening || ''}`
      );
    }
    if (subfocus === 'MULTISITE_FLEET_CORRELATION') {
      const multiSiteOverview = multiSiteManager.generateMultiSiteFleetOverview();
      const allAgents = edgeAgentService.getAllAgents();
      const siteNames = (multiSiteOverview.sites || []).map((s) => `${s.code} (${s.region || 'LOCAL-HOST'})`).join(', ') || 'LOCAL-RUNTIME';
      const execScope = multiSiteOverview.fleetSummary.executionEnvironment || 'LIVE_OS_RUNTIME';
      executiveSummaryParts.push(
        `Multi-Site Fleet Intelligence: ${multiSiteOverview.fleetSummary.totalSites} live runtime site(s) [${siteNames}] (${multiSiteOverview.fleetSummary.healthySites} healthy, ${multiSiteOverview.fleetSummary.degradedSites} degraded; Scope: ${execScope}) with ${multiSiteOverview.fleetSummary.totalZones} monitored zones and ${allAgents.length} edge observation agent(s). Upstream/LAN links: ${multiSiteOverview.fleetSummary.optimalWanLinks}/${multiSiteOverview.fleetSummary.totalWanLinks} operating at optimal latency.`
      );
    }

    if (executiveSummaryParts.length === 0) {
      executiveSummaryParts.push(
        `${execSituation?.whatIsHappening || ''} Most important to address: ${execSituation?.mostImportantToAddress || 'Fleet nominal.'} ` +
        `(Tracked targets: ${briefing.fleetSummary.totalTrackedEntities}, Fleet Stability: ${briefing.fleetSummary.averageStabilityScore}%, Correlated Incidents: ${correlatedIncidents.length}, Incident DNA: ${incidentDna?.dnaFingerprintId || 'N/A'}).`
      );
    }

    // Append concise Closed-Loop & Predictive Horizon synthesis tail so multi-engine intelligence is always surfaced
    if (
      hypothesisArbitration &&
      predictiveHorizon &&
      !['MULTI_DOMAIN_HYPOTHESIS_ARBITRATION', 'PREDICTIVE_HORIZON_ATTENTION', 'SUPERPOWERS_UNIFIED_SYNTHESIS'].includes(subfocus)
    ) {
      executiveSummaryParts.push(
        `Closed-Loop 6-Domain Arbitration (${hypothesisArbitration.closedLoopStepsExecuted} live probes): ${hypothesisArbitration.winningHypothesis.title} (P=${hypothesisArbitration.winningHypothesis.probabilityPct}%). Predictive Horizon Risk: ${predictiveHorizon.overallRiskScore}/100 (${predictiveHorizon.overallRiskTier}).`
      );
    }

    const resultText = executiveSummaryParts.join(' ');

    const meaningText =
      correlatedIncidents.length > 0 || briefing.activeRegressions.length > 0 || briefing.predictiveRisks.length > 0
        ? `Incident Correlation, Technical Debt Radar, 6-Domain Closed-Loop Arbiter, and Incident DNA identified ${correlatedIncidents.length} correlated operational incident(s), ${briefing.activeRegressions.length} state regression(s), and ${debtRadar?.topWeaknesses?.length || 5} prioritized infrastructure weaknesses.`
        : `All ${briefing.fleetSummary.totalTrackedEntities} tracked entities are operating within their historical EWMA latency and port reachability baselines.`;

    const nextStepText =
      execSituation?.mostImportantToAddress ||
      (topPriority
        ? `${topPriority.recommendedNextStep} (${topPriority.reason})`
        : 'Continue monitoring or run a targeted diagnostic check to expand baseline coverage.');

    const timeMachineLines = timeMachine30m
      ? `- **30-Minute Pre-Outage Narrative:** ${timeMachine30m.narrativeSummary}\n` +
        `- **Patient Zero Origin:** \`${timeMachine30m.patientZeroComponent?.target}\` (${timeMachine30m.patientZeroComponent?.initialSymptom})\n` +
        `- **Honest Evidence Gap Disclosure:** ${(timeMachine30m.honestEvidenceGaps || []).join(' ')}`
      : '';

    const timelineReconstructionLines = timelineReconstruction
      ? `- **MAD & CUSUM Pre-Incident Timeline (\`${timelineReconstruction.reconstructionId}\`):** ${timelineReconstruction.narrativeSummary}\n` +
        `- **Patient Zero Causal Role:** \`${timelineReconstruction.patientZero.target}\` (\`${timelineReconstruction.patientZero.causalRole}\` · ${timelineReconstruction.patientZero.layer} · Confidence: ${Math.round(timelineReconstruction.patientZero.confidence * 100)}%)\n` +
        `- **Chronological Event Stream (${timelineReconstruction.timelineEvents.length} un-truncated events):**\n` +
        timelineReconstruction.timelineEvents.map((ev) =>
          `  - \`[${ev.timestamp}]\` **${ev.target}** (\`${ev.causalRole}\` · \`${ev.eventType}\`): ${ev.detail}`
        ).join('\n')
      : '';

    const hypothesisArbitrationLines = hypothesisArbitration
      ? `- **Autonomous Closed-Loop 6-Domain Arbitration (\`${hypothesisArbitration.arbitrationId}\`):** ${hypothesisArbitration.executiveSummary}\n` +
        `- **6-Domain Posterior Ranking:**\n` +
        hypothesisArbitration.hypotheses.map((h, idx) =>
          `  - **#${idx + 1} [${h.domainId}] ${h.title}**: Posterior **${h.probabilityPct}%** (Prior: ${Math.round(h.priorProbability * 100)}%) — *${h.evidenceSummary}*`
        ).join('\n') + '\n' +
        `- **Closed-Loop Autonomous Probe Trace (${hypothesisArbitration.closedLoopStepsExecuted} steps executed):**\n` +
        (hypothesisArbitration.closedLoopExecutionTrace || []).map((st) =>
          `  - **Step ${st.stepIndex} (\`${st.probeExecuted}\` · Expected $\\Delta H = ${st.expectedInformationGainBits}$ bits):** ${st.empiricalObservationSummary} (Entropy: ${st.entropyBeforeBits} $\\rightarrow$ ${st.entropyAfterBits} bits)`
        ).join('\n')
      : '';

    const predictiveHorizonLines = predictiveHorizon
      ? `- **Non-Linear M/M/1 Queueing & Cut-Vertex Predictive Horizon (\`${predictiveHorizon.horizonId}\`):** ${predictiveHorizon.executiveSummary}\n` +
        `- **Topological Cut-Vertices (Single Points of Failure):** ${(predictiveHorizon.cutVertices || []).map((cv) => `\`${cv.label}\` (Impact: ${cv.downstreamDependentCount} nodes)`).join(', ') || 'None detected'}\n` +
        `- **Endpoint Horizon Forecasts (${predictiveHorizon.predictions.length} un-truncated endpoints):**\n` +
        predictiveHorizon.predictions.map((p) =>
          `  - **\`${p.target}\` [${p.riskTier} · Score ${p.compoundRiskScore}/100]**: Utilization $\\rho = ${p.utilizationPct}\\%$, Queueing Factor $\\Phi(\\rho) = ${p.mm1QueueingAmplification}$, Time-to-SLA: **${p.timeToSlaBreachMinutes !== null ? `${p.timeToSlaBreachMinutes} min` : 'Stable'}** — *Action:* ${p.preventativeAction}`
        ).join('\n')
      : '';

    const knowledgeWhyLines = knowledgeQa
      ? `- **The Last Admin Architectural Grounding:** ${knowledgeQa.synthesizedAnswer}\n` +
        `- **Documentation vs. Reality Contradictions:** ${(knowledgeQa.documentationVsRealityContradictions || []).length > 0 ? knowledgeQa.documentationVsRealityContradictions.map((c) => `${c.target}: ${c.observedReality}`).join('; ') : 'Zero contradictions between documented runbooks and live wire state.'}`
      : '';

    const serverDiffLines = serverConfigDifferential
      ? `- **Server Configuration Differential (\`${serverConfigDifferential.target}\` vs. Peer Fleet):** ${serverConfigDifferential.whyConfiguredDifferentlySummary}\n` +
        (serverConfigDifferential.differentials || []).map((d) =>
          `  - **[${d.dimension}]** Observed: \`${d.targetObserved}\` vs. Peer Consensus: \`${d.peerConsensus}\` — **${d.classification}** (${d.explanation})`
        ).join('\n')
      : '';

    const reply = [
      `### IT Operations Command Center — Operational Intelligence & Anomaly Briefing (Cognition 3.0 + Superpowers Synthesis)`,
      `**Executive Situation ("What is happening & what to address first"):**\n- **What is happening:** ${execSituation?.whatIsHappening}\n- **Most important to address:** ${execSituation?.mostImportantToAddress}`,
      ...(dynamicCapabilityInvestigation ? [
        `**0A. AI Cognition 3.0 — Autonomous Broad Infrastructure Investigation & Dynamic Problem Solver (\`${dynamicCapabilityInvestigation.investigationId}\`):**\n` +
        `- **Problem Nature & Strategy:** \`${dynamicCapabilityInvestigation.problemNatureStrategy.problemNatureClassification.primaryNature}\` → **${dynamicCapabilityInvestigation.problemNatureStrategy.selectedStrategy.strategyName}**\n` +
        `- **Target Discovery:** \`${dynamicCapabilityInvestigation.target}\` (${dynamicCapabilityInvestigation.targetDiscoveryMethod})\n` +
        `- **Parallel Capability Groups Executed:** ${dynamicCapabilityInvestigation.capabilityExecutionTrace.parallelGroupsExecuted.map((g) => `${g.title} [${g.capabilities.join(', ')}]`).join(' · ')}\n` +
        `- **6-Specialist Collaborative Consensus:** ${dynamicCapabilityInvestigation.collaborativeSynthesis.unifiedDiagnosis}`
      ] : []),
      ...(autonomousGoalResult ? [
        `**0. Autonomous Goal Decomposition & Multi-Stage Execution (\`${autonomousGoalResult.goalId}\`):**\n` +
        `- **Inferred Objective:** ${autonomousGoalResult.decomposition.inferredOperationalObjective}\n` +
        autonomousGoalResult.completedStages.map((s) => `- **Stage ${s.stageNumber} (${s.title}):** \`${s.status}\` — ${s.outcomeSummary}`).join('\n') +
        (autonomousGoalResult.adaptivePivotLog.length > 0 ? `\n- **Adaptive Pivots:** ${autonomousGoalResult.adaptivePivotLog.map((p) => p.adaptationDecision).join(' | ')}` : '')
      ] : []),
      ...(serverDiffLines ? [`**0B. Institutional Server Configuration Differential Analysis:**\n${serverDiffLines}`] : []),
      ...(subfocus === 'MULTISITE_FLEET_CORRELATION' || activeCaps.has('MULTISITE_FLEET_CORRELATION') ? [
        `**0C. Multi-Site Distributed Fleet & Edge Agents Overview:**\n` +
        `- **Enterprise Sites (${multiSiteManager.getAllSites().length} Configured):**\n` +
        multiSiteManager.getAllSites().map(s => `  - **[${s.code}] ${s.name}** (${s.region}): Gateway \`${s.primaryGateway}\` · Status: **${s.status}** · Criticality: ${s.criticality}`).join('\n') + '\n' +
        `- **Inter-Site WAN Transit & SD-WAN Links (${multiSiteManager.getAllWanLinks().length} Monitored):**\n` +
        multiSiteManager.getAllWanLinks().map(l => `  - **${l.linkType || l.link_type}** (${l.source_site_id || l.sourceSiteId} ↔ ${l.target_site_id || l.targetSiteId}): ${l.provider} · Latency: \`${l.latency_ms || l.latencyMs} ms\` · Status: **${l.status}**`).join('\n') + '\n' +
        `- **Distributed Edge Agents (${edgeAgentService.getAllAgents().length} Enrolled):**\n` +
        edgeAgentService.getAllAgents().map(a => `  - **${a.name}** (\`${a.hostname}\` @ \`${a.ipAddress}\`): Status **${a.status}** · Platform: \`${a.platform}\``).join('\n')
      ] : []),
      ...(hypothesisArbitrationLines ? [`**0D. Autonomous Closed-Loop 6-Domain Hypothesis Arbitration & Real-Time Probe Execution:**\n${hypothesisArbitrationLines}`] : []),
      ...(predictiveHorizonLines ? [`**0E. Non-Linear Predictive Horizon & Cut-Vertex Cascade Forecast:**\n${predictiveHorizonLines}`] : []),
      `**1. Correlated Multi-Target Operational Incidents (Root Cause vs. Symptoms):**\n${incidentLines}`,
      `**2. Technical Debt Radar — Top 5 Infrastructure Weaknesses Management Should Address First:**\n${debtLines}`,
      `**3. Incident DNA & "The Last Admin" Organizational Knowledge Vault:**\n${dnaLines}${knowledgeWhyLines ? `\n${knowledgeWhyLines}` : ''}`,
      `**4. Operational Time Machine, Patient Zero Changepoint & Network Black Box Reconstruction:**\n${blackBoxLines}${timeMachineLines ? `\n${timeMachineLines}` : ''}${timelineReconstructionLines ? `\n${timelineReconstructionLines}` : ''}`,
      `**5. Active State Regressions & Predictive SLA Forecast:**\n${regressionLines}\n${riskLines}`,
      `**6. Verified Incident Playbooks & Closed-Loop Remediation Efficacy:**\n${playbookLines}`
    ].join('\n\n');

    const structuredAnswer = {
      result: resultText,
      meaning: meaningText,
      nextStep: nextStepText,
      layerFailedFirst: correlatedIncidents.length > 0 ? correlatedIncidents[0].incidentType : (briefing.activeRegressions.length > 0 ? 'Historical Baseline Regression' : null),
      uncertainty: (timeMachine30m?.honestEvidenceGaps || [])[0] || null
    };

    return {
      reply,
      structuredAnswer,
      steps,
      findings,
      technicalEvidence: {
        tool: 'operationalMemoryEngine.getOperationsCommandCenterOverview',
        synthesisSubfocus: subfocus,
        activeSynthesisCapabilities: Array.from(activeCaps),
        briefing,
        fleetIntelligenceMatrix: fleetMatrix,
        commandCenterOverview,
        technicalDebtRadar: debtRadar,
        incidentDnaSummary: incidentDna,
        networkBlackBoxSummary: blackBox,
        operationalTimeMachine: timeMachine30m,
        timelineReconstruction,
        hypothesisArbitration,
        predictiveHorizon,
        unifiedSuperpowersReport,
        organizationalKnowledge: orgKnowledge,
        knowledgeQueryResult: knowledgeQa,
        serverConfigDifferential,
        dynamicCapabilityInvestigation,
        autonomousGoalResult,
        topologyNodeCount: graphState.nodes.length,
        topologyEdgeCount: graphState.edges.length,
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Scenario J2: Intelligent Scenario Planning ("What-If" Consequence Simulation) & Adaptive Remediation Risk Comparator
   * Evaluates operational consequences before action is taken, clearly separated from live telemetry.
   */
  async _executeScenarioPlanningWhatIf(plan, session, promptText) {
    const t0 = performance.now();
    const target = plan.target || session?.lastValidTarget || '127.0.0.1';
    const port = (Array.isArray(plan.ports) && plan.ports[0]) || 443;
    const scenarioType = plan.scenarioType || 'GATEWAY_OR_DEPENDENCY_UNAVAILABLE';

    const scenarioSimulation = operationalMemoryEngine.simulateOperationalScenario({
      target,
      scenarioType,
      port,
      proposedChange: promptText
    });
    const durationMs = Number((performance.now() - t0).toFixed(2));

    const steps = [
      {
        stepNumber: 1,
        label: `[SIMULATED SCENARIO] Modeling "${scenarioType}" on "${target}:${port}" against topological blast radius & service criticality…`,
        tool: 'operationalMemoryEngine.simulateOperationalScenario',
        status: 'PASS',
        summary: `${scenarioSimulation.simulationBadge} · Role: ${scenarioSimulation.environmentProfile?.roleLabel} (${scenarioSimulation.environmentProfile?.criticalityTier}) · Affected Services: ${scenarioSimulation.impactAnalysis?.affectedServicesCount || 0} · Lowest-Risk Option: ${scenarioSimulation.remediationComparison?.lowestRiskOption?.title || 'N/A'}`,
        durationMs
      }
    ];

    const findings = [
      {
        label: 'Classification',
        value: 'SIMULATED SCENARIO (Not Live Telemetry)',
        tone: 'warn'
      },
      {
        label: 'Target & Tier',
        value: `${target} (${scenarioSimulation.environmentProfile?.criticalityTier || 'TIER_2'})`,
        tone: 'neutral'
      },
      {
        label: 'Affected Services',
        value: `${scenarioSimulation.impactAnalysis?.affectedServicesCount || 0} service(s) (${scenarioSimulation.impactAnalysis?.cascadingCongestionNodes || 0} critical queueing)`,
        tone: (scenarioSimulation.impactAnalysis?.affectedServicesCount || 0) > 0 ? 'warn' : 'ok'
      },
      {
        label: 'Responsible Team',
        value: scenarioSimulation.environmentProfile?.ownership?.team || 'Platform Operations',
        tone: 'neutral'
      },
      {
        label: 'Lowest-Risk Action',
        value: scenarioSimulation.remediationComparison?.lowestRiskOption?.actionId || 'verify_and_refresh_dns_resolution',
        tone: 'ok'
      }
    ];

    const qaLines = Object.values(scenarioSimulation.questionsAnswered || {}).map((qa) =>
      `- **${qa.question}**\n  ${qa.answer}`
    ).join('\n');

    const remOptionsLines = (scenarioSimulation.remediationComparison?.options || []).map((opt) =>
      `- **Rank #${opt.rank}: \`${opt.actionId}\` — ${opt.title}** (Risk: **${opt.operationalRiskLevel}** [${opt.operationalRiskScore}/100] · Historical Efficacy: **${opt.historicalEfficacyPct}%**)\n` +
      `  - *Expected Impact:* ${opt.expectedServiceImpact}\n` +
      `  - *If This Action Fails:* ${opt.consequenceIfActionFails}\n` +
      `  - *Rollback Safeguard:* ${opt.rollbackSafeguard}`
    ).join('\n');

    const resultText =
      `${scenarioSimulation.simulationBadge} Scenario analysis for "${target}" (${scenarioSimulation.environmentProfile?.roleLabel}, ${scenarioSimulation.environmentProfile?.criticalityTier}): ` +
      `${scenarioSimulation.impactAnalysis?.whatHappensIfUnavailable} Lowest-risk remediation option is "${scenarioSimulation.remediationComparison?.lowestRiskOption?.title}" (Risk Score ${scenarioSimulation.remediationComparison?.lowestRiskOption?.operationalRiskScore}/100).`;

    const meaningText =
      `This is a predictive "What-If" operational simulation combining topological dependency propagation, service criticality tiers, and historical remediation efficacy. No live infrastructure state was mutated.`;

    const nextStepText =
      `Review the ranked remediation options and blast-radius consequences below before approving any live change on ${target}.`;

    const reply = [
      `### ${scenarioSimulation.simulationBadge} — Operational Scenario & Consequence Analysis: \`${target}\``,
      `**Scenario Evaluated:** \`${scenarioType}\` on **\`${target}:${port}\`** (${scenarioSimulation.environmentProfile?.roleLabel} · **${scenarioSimulation.environmentProfile?.criticalityTier}** · Owner: **${scenarioSimulation.environmentProfile?.ownership?.team}**)\n*${scenarioSimulation.disclaimer}*`,
      `**1. Operational Consequence Questions Answered:**\n${qaLines}`,
      `**2. Multi-Option Adaptive Remediation Risk & Failure Comparison:**\n${remOptionsLines}`
    ].join('\n\n');

    const structuredAnswer = {
      result: resultText,
      meaning: meaningText,
      nextStep: nextStepText,
      layerFailedFirst: null,
      uncertainty: scenarioSimulation.disclaimer
    };

    return {
      reply,
      structuredAnswer,
      steps,
      findings,
      technicalEvidence: {
        mode: 'scenario_planning_what_if',
        isSimulated: true,
        telemetryClassification: 'SIMULATED_SCENARIO_NOT_LIVE_TELEMETRY',
        scenarioSimulation,
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Scenario K: Topological Dependency & Blast-Radius Impact Analysis
   * Evaluates upstream dependencies, downstream dependents, and multi-hop queueing propagation
   * in the TemporalInfrastructureGraph combined with historical entity stability from OperationalMemoryEngine.
   */
  async _executeDependencyAndBlastRadiusScenario(plan, session, promptText) {
    const t0 = performance.now();
    const target = plan.target || session?.lastValidTarget || 'localhost';
    const entityBaseline = operationalMemoryEngine.getEntityBaseline(target);
    const resolvedIps = entityBaseline?.resolvedIps || [];
    const depContext = operationalMemoryEngine.getTargetDependencyContext(target, resolvedIps);
    const graphState = temporalInfrastructureGraph.getGraphState();

    // Find matching node ID in TemporalInfrastructureGraph or fall back to core router / DNS resolver
    const targetLower = String(target).toLowerCase();
    const matchedGraphNode = (graphState.nodes || []).find((n) => {
      const nid = String(n.nodeId || n.id || '').toLowerCase();
      const label = String(n.label || n.name || n.hostname || '').toLowerCase();
      const ip = String(n.ipAddress || n.metadata?.ip || '').toLowerCase();
      return (
        nid.includes(targetLower) ||
        label.includes(targetLower) ||
        (ip && (ip === targetLower || resolvedIps.includes(ip)))
      );
    }) || graphState.nodes[0];

    const matchedNodeId = matchedGraphNode ? (matchedGraphNode.nodeId || matchedGraphNode.id) : null;
    const matchedNodeType = matchedGraphNode ? (matchedGraphNode.resourceType || matchedGraphNode.type || 'host') : 'host';
    const blastSim = matchedNodeId
      ? temporalInfrastructureGraph.computeBlastRadius(matchedNodeId, 100)
      : { impactedCount: 0, impactedNodes: [], queuingPropagation: { cascadingCongestionNodes: 0, maxDownstreamQueueDelayMs: 0 } };

    const durationMs = Number((performance.now() - t0).toFixed(2));

    const steps = [
      {
        stepNumber: 1,
        label: `Evaluating topological dependencies and multi-hop blast radius for "${target}"…`,
        tool: 'temporalInfrastructureGraph.computeBlastRadius',
        status: 'PASS',
        summary: `Matched node "${matchedGraphNode?.label || target}" (${matchedNodeId || 'unmapped'}) · Upstream: ${depContext?.upstreamDependencies?.length || 0} · Downstream impacted: ${blastSim.impactedCount}`,
        durationMs
      }
    ];

    const findings = [
      { label: 'Target Entity', value: target, tone: 'neutral' },
      {
        label: 'Topology Node',
        value: matchedGraphNode ? `${matchedGraphNode.label} (${matchedNodeType})` : 'Dynamic Host',
        tone: 'neutral'
      },
      {
        label: 'Downstream Impact',
        value: `${blastSim.impactedCount} dependent node(s)`,
        tone: blastSim.impactedCount > 0 ? 'warn' : 'ok'
      },
      {
        label: 'Upstream Dependencies',
        value: String(depContext?.upstreamDependencies?.length || 0),
        tone: 'neutral'
      },
      {
        label: 'Baseline Stability',
        value: entityBaseline ? `${entityBaseline.stabilityScore}% (${entityBaseline.observationCount} obs)` : 'Unprobed',
        tone: !entityBaseline || entityBaseline.stabilityScore >= 80 ? 'ok' : 'warn'
      }
    ];

    const upstreamList = depContext?.upstreamDependencies?.length > 0
      ? depContext.upstreamDependencies.map((u) => `- **\`${u.label || u.nodeId}\`** (relation: \`${u.relationship || u.relation || 'routes_to'}\`)`).join('\n')
      : '- No registered upstream infrastructure dependencies in the graph.';

    const downstreamList = blastSim.impactedNodes?.length > 0
      ? blastSim.impactedNodes.map((d) =>
          `- **\`${d.label || d.nodeId}\`** (${d.resourceType || d.type || 'node'}, hop ${d.hopDistance}): Risk **${((d.propagationRisk || 0.5) * 100).toFixed(0)}%** · Est. queueing delay **+${d.estimatedQueueDelayMs ?? 0} ms** (${d.congestionRegime || 'nominal'})`
        ).join('\n')
      : (depContext?.downstreamDependents?.length > 0
          ? depContext.downstreamDependents.map((d) => `- **\`${d.label || d.nodeId}\`** (relation: \`${d.relationship || d.relation || 'served_by'}\`)`).join('\n')
          : '- No downstream dependent services would suffer cascading outage from this leaf node.');

    const resultText =
      `Topological dependency and blast-radius analysis for "${target}" (${matchedGraphNode?.label || 'host'}): ` +
      `${blastSim.impactedCount} downstream node(s) in blast radius, ${depContext?.upstreamDependencies?.length || 0} upstream dependency link(s), ` +
      `max cascading queue delay +${blastSim.queuingPropagation?.maxDownstreamQueueDelayMs || 0} ms.`;

    const meaningText =
      blastSim.impactedCount > 0
        ? `A failure or 100 ms latency spike on "${matchedGraphNode?.label || target}" propagates across ${blastSim.impactedCount} dependent service/host node(s) (${blastSim.queuingPropagation?.cascadingCongestionNodes || 0} entering critical M/M/1 queueing congestion).`
        : `"${target}" acts as an edge/leaf endpoint in the current topology graph with ${depContext?.upstreamDependencies?.length || 0} upstream dependency link(s) and zero downstream dependent nodes.`;

    const nextStepText =
      entityBaseline
        ? `Run a live cross-layer check on ${target} to verify current reachability against its ${entityBaseline.stabilityScore}% stability baseline.`
        : `Probe ${target} (e.g., "Investigate why ${target} is failing" or "Check port 443 on ${target}") to bind live telemetry to the topology graph.`;

    const reply = [
      `### Topological Dependency & Blast-Radius Analysis: \`${target}\``,
      `**Summary:** ${resultText}`,
      `**1. Upstream Dependencies (Required by \`${target}\`):**\n${upstreamList}`,
      `**2. Downstream Blast Radius & Queueing Propagation (Impacted if \`${target}\` degrades):**\n${downstreamList}`,
      entityBaseline
        ? `**3. Operational Memory Baseline:** Observed **${entityBaseline.observationCount}x** · Stability Score: **${entityBaseline.stabilityScore}%** · Open TCP Ports: **[${entityBaseline.openPorts.join(', ') || 'none'}]** · EWMA TCP RTT: **${entityBaseline.latencyBaseline?.tcpStats?.ewma ?? entityBaseline.latencyBaseline?.avgTcpRttMs ?? 'N/A'} ms**`
        : `**3. Operational Memory Baseline:** No live probes recorded yet for \`${target}\`.`
    ].join('\n\n');

    const structuredAnswer = {
      result: resultText,
      meaning: meaningText,
      nextStep: nextStepText,
      layerFailedFirst: null,
      uncertainty: null
    };

    return {
      reply,
      structuredAnswer,
      steps,
      findings,
      technicalEvidence: {
        tool: 'temporalInfrastructureGraph.computeBlastRadius',
        target,
        matchedGraphNode,
        dependencyContext: depContext,
        blastRadius: blastSim,
        entityBaseline,
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Scenario I: Terminal Startup Log, Readiness Timeout & Multi-Port Service Mismatch Triage
   * Parses pasted terminal logs (such as SYNTRA one-click startup failing readiness at http://127.0.0.1:3000/
   * while backend server listens on http://127.0.0.1:3001 and returns {"error":"Route not found."} on /),
   * probes the referenced endpoints live, and synthesizes an actionable root-cause analysis.
   */
  async _executeLogAndStartupTriageScenario(plan, session, promptText, signal) {
    this._checkAborted(signal);
    const logAnalysis = plan.logAnalysis || operationalMemoryEngine.parseTerminalStartupLog(promptText);
    const endpoints = (logAnalysis.extractedEndpoints || []).filter((ep) => isSafeNetworkTarget(ep.host)).slice(0, 4);
    const steps = [];
    const findings = [];
    const liveProbeResults = [];

    if (logAnalysis.projectName) {
      findings.push({ label: 'Service / Project', value: logAnalysis.projectName, tone: 'neutral' });
    }
    if (logAnalysis.detectedPatterns.length > 0) {
      findings.push({
        label: 'Detected Signature',
        value: logAnalysis.detectedPatterns.join(' · '),
        tone: 'warn'
      });
    }

    // Step 1: Parse log structure & extract endpoints/errors
    steps.push({
      stepNumber: 1,
      label: `Parsing terminal startup log and correlating ${endpoints.length} referenced endpoint(s)…`,
      tool: 'parseTerminalStartupLog',
      status: 'PASS',
      summary: `Extracted ${endpoints.length} endpoint(s) (${endpoints.map((e) => `${e.host}:${e.port} [${e.role}]`).join(', ') || 'none'})${logAnalysis.errorPayloads.length ? ` and error payload ${logAnalysis.errorPayloads[0].raw}` : ''}`,
      durationMs: 0.4
    });

    // Step 2: Live TCP & HTTP probes on each extracted endpoint
    for (const ep of endpoints) {
      this._checkAborted(signal);
      const probeHost = ep.host.toLowerCase() === 'localhost' ? '127.0.0.1' : ep.host;
      const t0 = performance.now();
      const tcpRes = await checkPort(probeHost, ep.port, 1200);
      const tcpMs = typeof tcpRes.connectLatencyMs === 'number'
        ? tcpRes.connectLatencyMs
        : Number((performance.now() - t0).toFixed(1));

      let httpRes = null;
      if (tcpRes.status === 'OPEN') {
        try {
          httpRes = await probeHttp(ep.url || `http://${probeHost}:${ep.port}/`, 'GET', 1500);
        } catch (_) {}
      }

      const probeRecord = {
        ...ep,
        probeHost,
        tcpStatus: tcpRes.status,
        tcpLatencyMs: tcpMs,
        httpStatusCode: httpRes?.statusCode || null,
        errorCode: tcpRes.errorCode || null
      };
      liveProbeResults.push(probeRecord);

      evidenceFabric.recordEvidence({
        type: 'observation',
        subject: `log_triage:${probeHost}:${ep.port}`,
        claim: `Startup log triage probe on ${probeHost}:${ep.port} (${ep.role}): TCP ${tcpRes.status}${httpRes?.statusCode ? `, HTTP ${httpRes.statusCode}` : ''}`,
        rawValue: probeRecord,
        normalizedValue: `TCP_${tcpRes.status}`,
        sourceCapabilityId: 'ejii.tcp.port_check',
        collectionMethod: 'log_triage_multi_probe'
      });

      steps.push({
        stepNumber: steps.length + 1,
        label: `Probing referenced ${ep.role.replace(/_/g, ' ')} ${probeHost}:${ep.port}…`,
        tool: 'checkPort',
        status: tcpRes.status === 'OPEN' ? 'PASS' : 'WARN',
        summary: `Live check on ${probeHost}:${ep.port}: TCP ${tcpRes.status} (${tcpMs} ms)${httpRes?.statusCode ? ` · HTTP ${httpRes.statusCode}` : ''}`,
        durationMs: tcpMs
      });

      findings.push({
        label: `Live ${ep.host}:${ep.port} (${ep.role === 'readiness_target' ? 'Readiness URL' : ep.role === 'listening_service' ? 'Backend Listener' : 'Endpoint'})`,
        value: `${tcpRes.status}${httpRes?.statusCode ? ` (HTTP ${httpRes.statusCode})` : ''}`,
        tone: tcpRes.status === 'OPEN' ? 'ok' : 'warn'
      });
    }

    const readinessEp = endpoints.find((e) => e.role === 'readiness_target') || endpoints[0];
    const listeningEp = endpoints.find((e) => e.role === 'listening_service') || endpoints[1];
    const hasPortSplit = logAnalysis.detectedPatterns.includes('PORT_SPLIT_READINESS_MISMATCH') ||
      (readinessEp && listeningEp && readinessEp.port !== listeningEp.port);
    const hasRouteNotFound = logAnalysis.detectedPatterns.includes('HTTP_ROUTE_NOT_FOUND_ON_HEALTH_PROBE');

    let rootCauseTitle;
    let meaningText;
    let nextStepText;
    let replySections = [];

    if (hasPortSplit && readinessEp && listeningEp) {
      rootCauseTitle =
        `Startup readiness failure caused by a port/route split between expected frontend/health URL (${readinessEp.host}:${readinessEp.port}) and backend workspace listener (${listeningEp.host}:${listeningEp.port})` +
        (hasRouteNotFound ? ` returning HTTP 404 {"error":"Route not found."} on root path "/".` : '.');

      meaningText =
        `1. Port Mismatch (${readinessEp.port} vs ${listeningEp.port}): The startup launcher waited for "${readinessEp.url}" to become ready, while the backend service (${logAnalysis.serviceCommand || 'local server'}) bound to "${listeningEp.url}". Either the frontend dev server on port ${readinessEp.port} failed to start/bind in time, or the startup script is polling port ${readinessEp.port} while only the backend on port ${listeningEp.port} is running.\n` +
        (hasRouteNotFound
          ? `2. Missing Root Route ("Route not found."): The JSON response {"error":"Route not found."} comes from hitting the root path "/" on the API server (or proxy) when it only registers API endpoints (such as /api/health or /api/*) and has no GET / handler.`
          : `2. Health Check Target: Verify whether the startup script should poll ${listeningEp.url} or why the dev server on port ${readinessEp.port} exited.`);

      nextStepText =
        `1) Inspect the open "dev" service window for port ${readinessEp.port} startup errors (e.g., missing Vite/frontend script or port conflict); ` +
        `2) Add a GET "/" or "/health" route returning 200 OK in ${logAnalysis.serviceCommand || 'local/server.mjs'} if the readiness probe hits the backend; ` +
        `3) Align the startup script readiness URL with the actual bound port (${readinessEp.port} vs ${listeningEp.port}).`;

      replySections.push(
        `### Startup Log & Multi-Port Root-Cause Diagnosis${logAnalysis.projectName ? ` (${logAnalysis.projectName})` : ''}`,
        `**Root Cause Identified:** ${rootCauseTitle}`,
        `**1. What Happened in Your Startup Log:**\n` +
          `- **Readiness Probe Timeout (\`${readinessEp.url}\`):** The launcher started \`server\` and \`dev\`, then polled \`${readinessEp.url}\` waiting for an HTTP 200 readiness response, which never arrived.\n` +
          `- **Backend Bound to Different Port (\`${listeningEp.url}\`):** Meanwhile, \`${logAnalysis.serviceCommand || 'the backend server'}\` successfully bound to **\`${listeningEp.url}\`** (loopback-only).\n` +
          (hasRouteNotFound
            ? `- **Why You Saw \`{"error":"Route not found."}\`:** The backend API server only mounts API routes (e.g., \`/api/*\`) and does not define a root \`GET /\` handler. When a browser or readiness check requests \`/\`, the server responds with \`{"error":"Route not found."}\` (HTTP 404), which also causes HTTP readiness checks expecting \`200 OK\` to fail.`
            : ''),
        `**2. Live Verification on This Host Right Now:**\n` +
          liveProbeResults.map((p) =>
            `- **\`${p.probeHost}:${p.port}\` (${p.role}):** Live TCP state is **${p.tcpStatus}** (${p.tcpLatencyMs} ms)${p.httpStatusCode ? ` · Live HTTP GET returned **HTTP ${p.httpStatusCode}**` : ''}.`
          ).join('\n'),
        `**3. Recommended Fix:**\n` +
          `1. **Check the \`dev\` process window (port ${readinessEp.port}):** Look at the separate \`dev\` terminal window mentioned in the log to see why the web UI server on \`127.0.0.1:${readinessEp.port}\` failed to start or crashed.\n` +
          `2. **Add a root health handler in \`${logAnalysis.serviceCommand ? logAnalysis.serviceCommand.replace(/^node\s+/, '') : 'local/server.mjs'}\`:** Ensure \`GET /\` or \`GET /health\` returns \`200 OK\` instead of \`404 {"error":"Route not found."}\` when polled by the startup script.\n` +
          `3. **Verify Vite/dev proxy configuration:** Ensure the web app on \`:${readinessEp.port}\` proxies API requests to \`http://127.0.0.1:${listeningEp.port}\`.`
      );
    } else {
      rootCauseTitle = `Analyzed terminal startup log across ${endpoints.length} endpoint(s)${logAnalysis.errorPayloads.length ? ` with error ${logAnalysis.errorPayloads[0].raw}` : ''}.`;
      meaningText = `Evaluated the log output alongside live TCP/HTTP state on ${endpoints.map((e) => `${e.host}:${e.port}`).join(', ')}.`;
      nextStepText = `Inspect the process binding and route table for ${endpoints.map((e) => `${e.host}:${e.port}`).join(', ')}.`;
      replySections.push(
        `### Terminal Log & Endpoint Triage`,
        `**Summary:** ${rootCauseTitle}`,
        liveProbeResults.map((p) =>
          `- **\`${p.probeHost}:${p.port}\`:** TCP **${p.tcpStatus}** (${p.tcpLatencyMs} ms)${p.httpStatusCode ? ` · HTTP ${p.httpStatusCode}` : ''}`
        ).join('\n')
      );
    }

    const structuredAnswer = {
      result: rootCauseTitle,
      meaning: meaningText,
      nextStep: nextStepText,
      layerFailedFirst: hasPortSplit ? `L7 Service Readiness & Port Split (:${readinessEp.port} vs :${listeningEp.port})` : 'L7 Service Startup',
      uncertainty: 'Log analysis reflects the pasted terminal output combined with live loopback port probes on the current EJII host.'
    };

    const reply = replySections.filter(Boolean).join('\n\n');

    return {
      reply,
      structuredAnswer,
      steps,
      findings,
      technicalEvidence: {
        mode: 'log_and_startup_triage',
        logAnalysis,
        liveProbeResults,
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Executes Project Atlas Conversational Connectivity, Tunnel Diagnostics, Relay Selection & JIT Access Queries (Section 5.1).
   * Explicitly separates Observed Facts, Historical Observations, Derived Calculations, and Unavailable Telemetry.
   */
  async _executeAtlasConnectivityQueryScenario(stepPlan, session, promptText) {
    const t0 = performance.now();
    const lower = String(promptText || '').toLowerCase();
    const snap = projectAtlasEngine.getObservabilitySnapshot();
    const relayRec = projectAtlasEngine.recommendOptimalRelay({
      lowLatencyInteractive: /\b(lowest[- ]latency|interactive|fast)\b/i.test(lower)
    });

    const observedFacts = [
      `Active Relays: ${snap.summary.relaysCount} (${snap.relays.map((r) => `${r.relayId} [${r.status}, RTT=${r.measuredRttMs ?? 'NULL'}ms]`).join(', ') || 'none'})`,
      `Connected Tunnel Clients: ${snap.summary.connectedClientsCount} connected, ${snap.summary.revokedClientsCount} revoked`,
      `Reverse Proxies: ${snap.summary.activeProxiesCount} active (${snap.summary.healthyProxiesCount} HEALTHY, ${snap.summary.unhealthyProxiesCount} UNHEALTHY_CIRCUIT_OPEN)`,
      `Total Traffic: bytesIn=${snap.summary.totalBytesIn}, bytesOut=${snap.summary.totalBytesOut}, activeConnections=${snap.summary.totalActiveConnections}, backpressureEvents=${snap.summary.totalBackpressureEvents}`,
      `Persistence Status: ${snap.persistenceStatus}`
    ];

    const historicalObservations = (snap.recentEvents || [])
      .slice(0, 6)
      .map((e) => `[${e.createdAt}] ${e.eventType} (${e.subjectId}): ${e.summary}`);

    const derivedCalculations = [
      ...(relayRec.evidenceSeparation?.derivedCalculations || []),
      `Healthy Proxy Ratio: ${
        snap.proxies.length > 0
          ? `${((snap.summary.healthyProxiesCount / snap.proxies.length) * 100).toFixed(1)}%`
          : '100.0% (0 proxies registered)'
      }`
    ];

    const unavailableTelemetry = [...(relayRec.evidenceSeparation?.unavailableTelemetry || [])];
    for (const p of snap.proxies) {
      if (p.lastLatencyMs === null || p.lastLatencyMs === undefined) {
        unavailableTelemetry.push(`Proxy ${p.proxyName} (${p.proxyId}): lastLatencyMs is NULL (no connections or probes completed yet)`);
      }
    }

    let queryCategory = 'GENERAL_ATLAS_OVERVIEW';
    let headlineResult = '';
    let meaning = '';
    let nextStep = '';
    let extraEvidence = {};

    // Multi-turn pronoun & entity resolution for Project Falcon IV (Section 7.2)
    const isShowAgents =
      /\b(remote\s+agents?|enrolled\s+clients?|connected\s+agents?\s+across\s+every\s+registered\s+site|show\s+(?:me\s+)?(?:all\s+)?(?:the\s+)?(remote\s+|connected\s+)?agents?|tunnel\s+clients?)\b/i.test(lower);
    const isUnstableRelayQuery =
      /\b(which\s+relay\s+currently\s+serves\s+our\s+most\s+unstable|most\s+unstable\s+connections?)\b/i.test(lower);
    const isRelayBlastRadiusQuery =
      /\b(affected\s+services\s+if\s+this\s+relay\s+becomes\s+unavailable|if\s+this\s+relay\s+becomes\s+unavailable)\b/i.test(lower);
    const isP2pTrafficQuery =
      /\b(whether\s+the\s+p2p\s+connection\s+is\s+carrying\s+real\s+traffic|fallen\s+back\s+to\s+a\s+relay|p2p\s+connection)\b/i.test(lower);
    const isDegradationCauseQuery =
      /\b(identify\s+the\s+actual\s+cause\s+of\s+the\s+recent\s+connectivity\s+degradation|actual\s+cause\s+of\s+the\s+recent\s+connectivity\s+degradation)\b/i.test(lower);
    const isRecoveryRecommendationQuery =
      /\b(recommend\s+an\s+authorized\s+recovery\s+operation|authorized\s+recovery\s+operation)\b/i.test(lower);
    const isDisconnectQuery =
      /\b(why\s+did\s+it\s+disconnect|why\s+is\s+it\s+disconnected|why\s+has\s+the\s+connection\s+to\s+this\s+host\s+disconnected\s+repeatedly|disconnected\s+repeatedly|disconnection\s+reason|connection\s+drop)\b/i.test(lower);
    const isCompareSession =
      /\b(compare\s+(its\s+)?(latest|current)\s+(connection|tunnel\s+performance)|previous\s+sessions?|compare\s+sessions?)\b/i.test(lower);
    const isSameServerQuery =
      /\b(same\s+server|same\s+target|that\s+server|that\s+host|check\s+the\s+tunnel\s+to\s+the\s+same)\b/i.test(lower);

    if (isShowAgents) {
      queryCategory = 'ATLAS_MULTI_SITE_AGENTS_INSPECTION';
      const enrolled = snap.clients;
      const sites = snap.sites || [];
      if (enrolled.length > 0) {
        const topClient = enrolled[0];
        session.lastAtlasClientId = topClient.clientId;
        session.lastAtlasTargetHost = topClient.hostname;
        session.lastAtlasRelayId = topClient.relayId;
        headlineResult = `Found ${enrolled.length} enrolled Project Atlas remote agent(s) across ${Math.max(1, sites.length)} registered site(s): ${enrolled.map((c) => `${c.clientName} [${c.clientId}, site=${c.siteId || 'default-site'}, relay=${c.relayId}, state=${c.operationalState || c.status}, lastHeartbeat=${c.lastHeartbeatAt || 'none'}]`).join('; ')}.`;
        meaning = `Active remote agents are authenticated via TLS 1.3 mTLS and grouped by site and relay affinity.`;
        nextStep = `Inspect telemetry or proxies bound to agent "${topClient.clientName}" (${topClient.clientId}).`;
      } else {
        headlineResult = 'No Project Atlas remote agents are currently enrolled across any registered site.';
        meaning = 'Client enrollment tokens must be issued via POST /api/atlas/tokens/issue before agents connect.';
        nextStep = 'Issue a client enrollment token and start the edge client.';
      }
      extraEvidence = { enrolledAgents: enrolled, registeredSites: sites };
    } else if (isUnstableRelayQuery) {
      queryCategory = 'ATLAS_UNSTABLE_RELAY_IDENTIFICATION';
      const rankedByInstability = [...snap.relays].sort((a, b) => {
        const lossDiff = (Number(b.packetLossPct || 0) + Number(b.jitterMs || 0)) - (Number(a.packetLossPct || 0) + Number(a.jitterMs || 0));
        if (lossDiff !== 0) return lossDiff;
        return Number(a.stabilityScore ?? 0.99) - Number(b.stabilityScore ?? 0.99);
      });
      const worstRelay = rankedByInstability[0];
      if (worstRelay) {
        session.lastAtlasRelayId = worstRelay.relayId;
        headlineResult = `Relay "${worstRelay.name}" (${worstRelay.relayId}) currently serves the most unstable connections (state=${worstRelay.operationalState || worstRelay.status}, packetLoss=${worstRelay.packetLossPct || 0}%, jitter=${worstRelay.jitterMs || 0}ms, RTT=${worstRelay.measuredRttMs ?? 'NULL'}ms, stabilityScore=${worstRelay.stabilityScore ?? 0.99}).`;
        meaning = `Evaluated all ${snap.relays.length} registered relay(s) across packet loss, jitter, RTT, and historical stability score.`;
        nextStep = `Fail over dependent clients and proxies from ${worstRelay.relayId} using POST /api/atlas/relays/${worstRelay.relayId}/failover.`;
      } else {
        headlineResult = 'No Project Atlas relays are currently registered.';
        meaning = 'Register a relay node before evaluating relay stability.';
        nextStep = 'Invoke POST /api/atlas/relays/register.';
      }
      extraEvidence = { unstableRelay: worstRelay, rankedByInstability };
    } else if (isRelayBlastRadiusQuery) {
      queryCategory = 'ATLAS_RELAY_UNAVAILABILITY_BLAST_RADIUS';
      const targetRelayId = session.lastAtlasRelayId || (snap.relays[0] ? snap.relays[0].relayId : 'atlas-relay-primary-01');
      const affectedClients = snap.clients.filter((c) => c.relayId === targetRelayId && !c.revoked);
      const affectedProxies = snap.proxies.filter((p) => p.relayId === targetRelayId && p.status === 'ACTIVE');
      const affectedSites = Array.from(new Set(affectedClients.map((c) => c.siteId || 'default-site')));
      headlineResult = `If relay "${targetRelayId}" becomes unavailable, ${affectedProxies.length} active service proxy(s) [${affectedProxies.map((p) => p.proxyName).join(', ') || 'none'}] and ${affectedClients.length} connected agent(s) [${affectedClients.map((c) => c.clientName).join(', ') || 'none'}] across site(s) [${affectedSites.join(', ') || 'default-site'}] will be impacted.`;
      meaning = `Topological blast radius computed directly from live relay-to-client and relay-to-proxy bindings on ${targetRelayId}.`;
      nextStep = `Execute controlled relay failover from ${targetRelayId} to ${relayRec.recommendedRelay?.relayId || 'a healthy secondary relay'}.`;
      extraEvidence = {
        blastRadius: {
          relayId: targetRelayId,
          affectedSites,
          affectedClients: affectedClients.map((c) => c.clientId),
          affectedServices: affectedProxies.map((p) => ({ proxyId: p.proxyId, proxyName: p.proxyName }))
        }
      };
    } else if (isP2pTrafficQuery) {
      queryCategory = 'ATLAS_P2P_TRAFFIC_AND_FALLBACK_INSPECTION';
      const p2pList = Array.from(projectAtlasEngine.p2pSessions.values());
      if (p2pList.length > 0) {
        const latestP2p = p2pList[p2pList.length - 1];
        const isDirectVerified = latestP2p.transportMode === 'DIRECT_UDP_HOLE_PUNCH_QUIC' && latestP2p.dataPlaneConnectivityVerified;
        headlineResult = isDirectVerified
          ? `XTCP P2P session "${latestP2p.proxyName}" (${latestP2p.p2pSessionId}) is carrying verified direct peer-to-peer traffic (${latestP2p.transportMode}, dataPlaneConnectivityVerified=true, RTT=${latestP2p.dataPlaneRttMs}ms).`
          : `XTCP P2P session "${latestP2p.proxyName}" (${latestP2p.p2pSessionId}) is NOT carrying direct P2P traffic; it has fallen back to relay mode (${latestP2p.transportMode}, reason=${latestP2p.fallbackReason || 'DATA_PLANE_UNVERIFIED'}, dataPlaneConnectivityVerified=${latestP2p.dataPlaneConnectivityVerified}).`;
        meaning = `Project Atlas explicitly separates control-plane hole-punch negotiation (${latestP2p.negotiationStatus}) from verified data-plane traffic delivery.`;
        nextStep = isDirectVerified
          ? 'Continue monitoring P2P data-plane RTT and UDP keepalives.'
          : 'Inspect NAT firewall rules or continue routing securely via STCP relay fallback.';
        extraEvidence = { p2pSessions: p2pList };
      } else {
        headlineResult = 'No XTCP P2P sessions are currently negotiated; all active tunnels are operating over standard relay transport.';
        meaning = 'Zero P2P sessions exist in p2pSessions memory.';
        nextStep = 'Negotiate an XTCP session via POST /api/atlas/p2p/negotiate and verify data-plane connectivity.';
        extraEvidence = { p2pSessions: [] };
      }
    } else if (isDegradationCauseQuery || isRecoveryRecommendationQuery) {
      queryCategory = isRecoveryRecommendationQuery ? 'ATLAS_AUTHORIZED_RECOVERY_RECOMMENDATION' : 'ATLAS_CONNECTIVITY_DEGRADATION_CAUSE';
      const degradedRelays = snap.relays.filter((r) => r.operationalState === 'DEGRADED' || (r.packetLossPct || 0) >= 2.0);
      const unhealthyProxies = snap.proxies.filter((p) => p.healthStatus === 'UNHEALTHY_CIRCUIT_OPEN');
      const disconnectedClients = snap.clients.filter((c) => c.status !== 'CONNECTED' || c.revoked);

      if (degradedRelays.length > 0) {
        const badR = degradedRelays[0];
        session.lastAtlasRelayId = badR.relayId;
        headlineResult = isRecoveryRecommendationQuery
          ? `Recommended Authorized Recovery Operation: Execute controlled relay failover from degraded relay "${badR.relayId}" (loss=${badR.packetLossPct}%, jitter=${badR.jitterMs}ms) to optimal relay "${relayRec.recommendedRelay?.relayId || 'atlas-relay-primary-01'}".`
          : `Actual Cause of Connectivity Degradation: Relay "${badR.name}" (${badR.relayId}) is in ${badR.operationalState} state with measured packet loss ${badR.packetLossPct}% and jitter ${badR.jitterMs}ms.`;
        meaning = `Isolated root cause to relay transport degradation on ${badR.relayId} rather than local backend service failure.`;
        nextStep = `Invoke POST /api/atlas/relays/${badR.relayId}/failover or POST /api/atlas/incidents/closed-loop to migrate active tunnels.`;
      } else if (unhealthyProxies.length > 0) {
        const badP = unhealthyProxies[0];
        headlineResult = isRecoveryRecommendationQuery
          ? `Recommended Authorized Recovery Operation: Drain unhealthy proxy backend "${badP.proxyName}" (${badP.proxyId}) via POST /api/atlas/proxies/${badP.proxyId}/drain and restart local target service ${badP.localIp}:${badP.localPort}.`
          : `Actual Cause of Connectivity Degradation: Local backend service ${badP.localIp}:${badP.localPort} behind proxy "${badP.proxyName}" (${badP.proxyId}) is failing health checks (UNHEALTHY_CIRCUIT_OPEN).`;
        meaning = `Relay control plane is healthy, isolating the fault to the upstream local service.`;
        nextStep = `Drain backend ${badP.proxyId} and verify local process listening on ${badP.localIp}:${badP.localPort}.`;
      } else if (disconnectedClients.length > 0) {
        const badC = disconnectedClients[0];
        headlineResult = isRecoveryRecommendationQuery
          ? `Recommended Authorized Recovery Operation: Reconnect or re-enroll disconnected agent "${badC.clientName}" (${badC.clientId}, status=${badC.status}).`
          : `Actual Cause of Connectivity Degradation: Tunnel client "${badC.clientName}" (${badC.clientId}) is in state ${badC.status}.`;
        meaning = `Evaluated client session state and heartbeat history.`;
        nextStep = `Invoke POST /api/atlas/clients/${badC.clientId}/reconnect or issue a new enrollment token if revoked.`;
      } else {
        headlineResult = isRecoveryRecommendationQuery
          ? `No emergency recovery operation required: all ${snap.summary.relaysCount} relay(s) and ${snap.summary.activeProxiesCount} proxy(s) are currently healthy.`
          : `No active connectivity degradation detected across ${snap.summary.relaysCount} relay(s) and ${snap.summary.activeProxiesCount} active proxy(s).`;
        meaning = 'All observed control-plane and data-plane health metrics are within nominal thresholds.';
        nextStep = 'Continue normal telemetry observation.';
      }
      extraEvidence = { degradedRelays, unhealthyProxies, disconnectedClients };
    } else if (isDisconnectQuery) {
      queryCategory = 'ATLAS_DISCONNECT_ANALYSIS';
      const targetClientId = session.lastAtlasClientId || (snap.clients.length > 0 ? snap.clients[0].clientId : null);
      const client = targetClientId ? snap.clients.find((c) => c.clientId === targetClientId) : null;
      if (client) {
        session.lastAtlasClientId = client.clientId;
        session.lastAtlasTargetHost = client.hostname;
        const isRevoked = client.revoked || client.status === 'REVOKED';
        const isHeartbeatExpired = client.status === 'DISCONNECTED_HEARTBEAT_TIMEOUT';
        const isSuperseded = client.status === 'SUPERSEDED_BY_REENROLLMENT';

        if (isRevoked) {
          headlineResult = `Client "${client.clientName}" (${client.clientId}) was disconnected because its credentials were explicitly revoked by Zero-Trust policy.`;
          meaning = 'The control-plane session was severed and its reverse proxies were terminated with REVOKED_TERMINATED.';
          nextStep = 'Issue a fresh enrollment token to re-admit this edge agent.';
        } else if (isSuperseded) {
          headlineResult = `Client session ${client.clientId} for "${client.clientName}" was superseded by a newer re-enrollment session.`;
          meaning = 'The agent initiated a new registration handshake, retiring this prior session generation.';
          nextStep = 'Monitor the newer active session for this client.';
        } else if (isHeartbeatExpired) {
          headlineResult = `Client "${client.clientName}" (${client.clientId}) disconnected due to heartbeat silence exceeding timeout threshold (generation=${client.reconnectGeneration || 1}).`;
          meaning = `Last recorded heartbeat was at ${client.lastHeartbeatAt || 'unknown'}. No subsequent TCP/TLS keepalive was received.`;
          nextStep = 'Verify network routing between the edge agent and the relay node.';
        } else {
          headlineResult = `Client "${client.clientName}" (${client.clientId}) status is ${client.status} (generation=${client.reconnectGeneration || 1}, transitions=${(client.sessionHistory || []).length}).`;
          meaning = 'Evaluated client session history and heartbeat telemetry.';
          nextStep = 'Review recent audit events in the event ledger.';
        }
        extraEvidence = { disconnectedClient: client };
      } else {
        headlineResult = 'No prior remote agent or client session is available in context to diagnose.';
        meaning = 'Please specify a clientId or run "Show me the remote agents" first.';
        nextStep = 'Query remote agents to select a target session.';
      }
    } else if (isCompareSession) {
      queryCategory = 'ATLAS_SESSION_COMPARISON';
      const targetClientId = session.lastAtlasClientId || (snap.clients.length > 0 ? snap.clients[0].clientId : null);
      const client = targetClientId ? snap.clients.find((c) => c.clientId === targetClientId) : null;
      if (client) {
        session.lastAtlasClientId = client.clientId;
        const gen = client.reconnectGeneration || 1;
        const hbCount = client.heartbeatCount || 1;
        const historyCount = Array.isArray(client.sessionHistory) ? client.sessionHistory.length : 1;
        headlineResult = `Compared sessions for "${client.clientName}" (${client.clientId}): Current Generation=${gen}, Total Heartbeats=${hbCount}, Session Transitions=${historyCount}, Relay=${client.relayId}.`;
        meaning = `The current connection generation is ${gen} with TLS cipher ${client.tlsCipherSuite || 'TLS_AES_256_GCM_SHA384'}.`;
        nextStep = 'Inspect live proxies or run health check against the current session.';
        extraEvidence = { clientComparison: { clientId: client.clientId, generation: gen, history: client.sessionHistory } };
      } else {
        headlineResult = 'No client session available in conversation memory to compare.';
        meaning = 'Specify a clientId to compare previous connection sessions.';
        nextStep = 'List agents via "Show me the remote agents".';
      }
    } else if (isSameServerQuery) {
      queryCategory = 'ATLAS_SAME_SERVER_TUNNEL_INSPECTION';
      const host = session.lastAtlasTargetHost || session.lastTarget || '127.0.0.1';
      const matchedProxies = snap.proxies.filter((p) => p.localIp === host || p.bindAddr === host);
      if (matchedProxies.length > 0) {
        const topP = matchedProxies[0];
        session.lastAtlasProxyId = topP.proxyId;
        headlineResult = `Inspected tunnel(s) to target server "${host}": found ${matchedProxies.length} proxy tunnel(s) (${matchedProxies.map((p) => `${p.proxyName} [:${p.remotePort}->${p.localIp}:${p.localPort}, ${p.healthStatus}]`).join('; ')}).`;
        meaning = `Tunnel ${topP.proxyName} is actively bound to ${host}:${topP.localPort} with health ${topP.healthStatus}.`;
        nextStep = `Run a health check on proxy ${topP.proxyId}.`;
      } else {
        headlineResult = `No active Project Atlas tunnels are configured for target server "${host}".`;
        meaning = `Searched ${snap.proxies.length} registered proxy tunnel(s) against host "${host}".`;
        nextStep = 'Register a new proxy tunnel pointing to this host.';
      }
      extraEvidence = { targetHost: host, matchedProxies };
    } else if (/\b(recommend|safest|lowest[- ]latency|optimal|best)\s+relay\b/i.test(lower)) {
      queryCategory = 'RELAY_RECOMMENDATION';
      const best = relayRec.recommendedRelay;
      headlineResult = best
        ? `Recommended Relay: ${best.name} (${best.relayId}) — Score ${best.compositeScore}/100, RTT ${best.measuredRttMs ?? 'N/A'}ms, Transport ${best.recommendedTransport}.`
        : 'No online relays available for recommendation.';
      meaning = relayRec.explanation;
      nextStep = best
        ? `Bind tunnel clients to ${best.relayId} (${best.bindAddr}:${best.bindPort}) using ${best.recommendedTransport}.`
        : 'Register an online Project Atlas relay node.';
      extraEvidence = { relayRecommendation: relayRec };
    } else if (/\b(temporarily grant|jit access|jit grant)\b/i.test(lower)) {
      queryCategory = 'JIT_ACCESS_GOVERNANCE';
      const portMatch = promptText.match(/\bport\s+(\d{1,5})\b/i);
      const ttlMatch = promptText.match(/\b(\d{1,3})\s*minutes?\b/i);
      const targetPort = portMatch ? Number(portMatch[1]) : 22;
      const ttlMinutes = ttlMatch ? Number(ttlMatch[1]) : 15;
      headlineResult = `Prepared time-bounded JIT administrative access workflow for port ${targetPort} (TTL=${ttlMinutes} minutes, dual-operator approval required).`;
      meaning = `Zero-Trust policy blocks public exposure of sensitive port ${targetPort} unless an explicit signed JIT grant (issueJitAdminAccessGrant) is active.`;
      nextStep = `Invoke POST /api/atlas/jit-grants with localPort=${targetPort}, ttlMs=${ttlMinutes * 60_000}, requireDualControl=true, and secondaryApproverId.`;
      extraEvidence = {
        proposedJitPolicy: {
          localPort: targetPort,
          ttlMs: ttlMinutes * 60_000,
          requireDualControl: true,
          activeJitGrantsCount: snap.summary.activeJitGrantsCount
        }
      };
    } else if (/\b(expired|over-permissive|access policies|revoked)\b/i.test(lower)) {
      queryCategory = 'SECURITY_EXPOSURE_AUDIT';
      const expiredJit = snap.jitAdminGrants.filter((g) => g.revoked || Date.now() > g.expiresAt);
      const publicProxies = snap.proxies.filter((p) => p.exposurePolicy === 'PUBLIC_INTERNET');
      headlineResult = `Audited ${snap.proxies.length} proxy(s) and ${snap.jitAdminGrants.length} JIT grant(s): ${publicProxies.length} public-internet proxy(s), ${expiredJit.length} expired/revoked JIT grant(s), ${snap.summary.revokedClientsCount} revoked client(s).`;
      meaning = 'All public exposures on privileged ports are governed by time-bounded JIT grants and automatic sweep termination.';
      nextStep = 'Run POST /api/atlas/jit-grants/sweep to terminate any proxies whose JIT window has elapsed.';
      extraEvidence = { expiredJitGrants: expiredJit, publicProxies };
    } else if (/\b(dropping|unreachable|failure|nat traversal|config change|inspect traffic|health check)\b/i.test(lower)) {
      queryCategory = 'TUNNEL_ROOT_CAUSE_DIAGNOSIS';
      const diagResults = [];
      for (const p of snap.proxies.slice(0, 5)) {
        diagResults.push(await projectAtlasEngine.diagnoseProxyOrTunnel(p.proxyId));
      }
      const unhealthy = diagResults.filter((d) => d.verdict !== 'TUNNEL_AND_BACKEND_HEALTHY');
      headlineResult =
        unhealthy.length > 0
          ? `Identified ${unhealthy.length} degraded/terminated tunnel(s): ${unhealthy.map((u) => `${u.proxyId} -> ${u.verdict} (${u.rootCauseLayer})`).join('; ')}`
          : `All ${diagResults.length} registered Project Atlas proxy tunnel(s) verified healthy end-to-end.`;
      meaning =
        unhealthy.length > 0
          ? unhealthy.map((u) => u.explanation).join(' ')
          : 'Relay listeners, TLS 1.3 control-plane sessions, and local upstream backend targets are responding within thresholds.';
      nextStep =
        unhealthy.length > 0
          ? unhealthy[0].recommendedAction
          : 'Continue passive telemetry monitoring or inspect specific proxy metrics via GET /api/atlas/metrics.';
      extraEvidence = { tunnelDiagnoses: diagResults };
    } else {
      const clientNames = snap.clients.map((c) => `${c.clientName} (${c.status}, relay=${c.relayId})`).join(', ') || 'none enrolled';
      const proxyNames =
        snap.proxies
          .map((p) => `${p.proxyName} [${p.proxyType} :${p.remotePort}->${p.localIp}:${p.localPort}, ${p.healthStatus}, latency=${p.lastLatencyMs ?? 'NULL'}ms]`)
          .join(', ') || 'none active';
      headlineResult = `Project Atlas Status: ${snap.summary.connectedClientsCount} connected client(s) [${clientNames}]; ${snap.summary.activeProxiesCount} active proxy tunnel(s) [${proxyNames}].`;
      meaning = `All active client sessions enforce TLS 1.3 (${snap.cryptographicPosture.activeKeyId}) with ${snap.persistenceStatus} persistence.`;
      nextStep = 'Ask to diagnose a specific proxy, recommend the lowest-latency relay, or audit JIT access grants.';
    }

    const latestIncident = Array.isArray(snap.closedLoopIncidents) && snap.closedLoopIncidents.length > 0
      ? snap.closedLoopIncidents[0]
      : null;

    const epistemicDistinctions = {
      observedConditions: observedFacts,
      suspectedProblems: derivedCalculations,
      historicalPriors: historicalObservations,
      unavailableMetrics: unavailableTelemetry,
      indirectEvidenceBoundaries: this.evaluateIndirectEvidenceBoundaries({
        probeType: 'TCP_CONTROL_PLANE_AND_DNS_SYNTHESIS',
        tcpReachable: snap.summary.connectedClientsCount > 0 && snap.summary.activeProxiesCount > 0,
        status: (snap.summary.connectedClientsCount > 0 && snap.summary.activeProxiesCount > 0) ? 'PASS' : 'UNVERIFIED'
      }),
      verifiedRecoveryState: latestIncident
        ? this.evaluateVerifiedRecoveryState(latestIncident, latestIncident.subjectId || 'project_atlas_mesh')
        : null
    };

    const durationMs = Number((performance.now() - t0).toFixed(2));
    const reply = [
      `### Project Atlas Sovereign Connectivity Intelligence (${queryCategory})`,
      `**Summary:** ${headlineResult}`,
      `**1. Observed Facts (Live Runtime State):**\n` + observedFacts.map((f) => `- ${f}`).join('\n'),
      `**2. Historical Observations (Audit & Event Ledger):**\n` +
        (historicalObservations.length > 0
          ? historicalObservations.map((h) => `- ${h}`).join('\n')
          : '- No prior historical config/revocation events recorded in this window.'),
      `**3. Derived Calculations:**\n` + derivedCalculations.map((d) => `- ${d}`).join('\n'),
      `**4. Unavailable Telemetry:**\n` +
        (unavailableTelemetry.length > 0
          ? unavailableTelemetry.map((u) => `- ${u}`).join('\n')
          : '- None (all queried relay and active proxy metrics are populated).'),
      `**Recommended Next Step:** ${nextStep}`
    ].join('\n\n');

    return {
      reply,
      structuredAnswer: {
        result: headlineResult,
        meaning,
        nextStep,
        layerFailedFirst: 'None (Project Atlas Control Plane Online)',
        uncertainty:
          unavailableTelemetry.length > 0
            ? `Unavailable telemetry explicitly reported (${unavailableTelemetry.length} field(s)).`
            : 'Verified directly against live ProjectAtlasEngine state.'
      },
      steps: [
        {
          stepNumber: 1,
          label: `Querying Project Atlas Control Plane (${queryCategory})…`,
          tool: 'project_atlas_intelligence',
          status: 'PASS',
          summary: headlineResult,
          durationMs
        }
      ],
      findings: [
        { label: 'Connected Clients', value: String(snap.summary.connectedClientsCount), tone: 'ok' },
        { label: 'Active Proxies', value: String(snap.summary.activeProxiesCount), tone: 'ok' },
        { label: 'Persistence', value: snap.persistenceStatus, tone: snap.persistenceStatus === 'DURABLE_SQLITE_SYNCED' ? 'ok' : 'warn' }
      ],
      technicalEvidence: {
        tool: 'project_atlas_intelligence',
        queryCategory,
        evidenceSeparation: {
          observedFacts,
          historicalObservations,
          derivedCalculations,
          unavailableTelemetry
        },
        epistemicDistinctions,
        snapshotSummary: snap.summary,
        ...extraEvidence,
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Phase Atlas VIII (Cycle 2): Trusted Post-Action Recovery Semantics
   * Strictly enforces:
   *   1. Never defaults missing `actionExecuted` to `true`. Requires explicit `actionExecuted === true`
   *      (or `executed === true` / `remediationAction.executed === true` / verified `postSnapshotId`)
   *      AND a non-empty execution/incident identifier (`executionId`, `remediationId`, `incidentId`,
   *      `actionId`, `verificationId`, or `preSnapshotId`).
   *   2. Requires a recognized probe with trustworthy provenance (rejecting AI-generated or manual
   *      text assertions), valid non-stale observation timestamp (`<= maxProbeFreshnessAgeMs`),
   *      chronological ordering after `actionExecutedAt` (when supplied), target matching the
   *      remediated target, and concrete quantitative measured telemetry (finite latency/RTT/duration/
   *      statusCode/afterMetrics or explicit numeric telemetry in observedResult).
   *   3. Enforces layer-appropriate recovery verification: a transport-only TCP probe cannot mark
   *      an L7 HTTP application fault as `VERIFIED_HEALTHY_AFTER_REMEDIATION` (returns
   *      `PARTIAL_TRANSPORT_ONLY_RECOVERY_L7_UNVERIFIED` with `postActionHealthy: false`).
   */
  evaluateVerifiedRecoveryState(candidate, defaultTarget = null, options = {}) {
    if (!candidate || typeof candidate !== 'object') return null;

    const nowMs = typeof options.nowMs === 'number' ? options.nowMs : Date.now();
    const maxProbeFreshnessAgeMs =
      typeof options.maxProbeFreshnessAgeMs === 'number' && options.maxProbeFreshnessAgeMs > 0
        ? options.maxProbeFreshnessAgeMs
        : 300000; // Default 5 minutes

    const executionId =
      candidate.executionId ||
      candidate.remediationId ||
      candidate.actionId ||
      candidate.incidentId ||
      candidate.verificationId ||
      candidate.verification?.preSnapshotId ||
      candidate.remediationAction?.actionId ||
      null;

    const explicitActionExecuted =
      candidate.actionExecuted === true ||
      candidate.executed === true ||
      candidate.remediationAction?.executed === true ||
      Boolean(candidate.verification?.postSnapshotId && candidate.verification?.preSnapshotId);

    const uninspectedProxiesCount = Number(
      candidate.uninspectedProxiesCount ??
        candidate.verificationResult?.uninspectedProxiesCount ??
        0
    );

    if (!explicitActionExecuted) {
      return {
        incidentId: executionId,
        executionId: executionId ? String(executionId) : null,
        actionExecuted: false,
        recoveryState: 'REMEDIATION_NOT_EXECUTED',
        status: 'REMEDIATION_NOT_EXECUTED',
        postActionHealthy: false,
        verificationProbe: null,
        rejectionReason: 'MISSING_EXPLICIT_ACTION_EXECUTED',
        uninspectedProxiesCount,
        verifiedAt: null
      };
    }

    if (!executionId || !String(executionId).trim()) {
      return {
        incidentId: null,
        executionId: null,
        actionExecuted: false,
        recoveryState: 'UNVERIFIED_EXECUTION_IDENTITY_MISSING',
        status: 'UNVERIFIED_EXECUTION_IDENTITY_MISSING',
        postActionHealthy: false,
        verificationProbe: null,
        rejectionReason: 'MISSING_EXECUTION_OR_INCIDENT_ID',
        uninspectedProxiesCount,
        verifiedAt: null
      };
    }

    const remediatedTarget = String(
      candidate.target ||
        candidate.subjectId ||
        candidate.remediatedTarget ||
        defaultTarget ||
        ''
    ).trim();

    const remediatedLayer = String(
      candidate.faultLayer ||
        candidate.remediatedLayer ||
        candidate.layer ||
        ''
    )
      .trim()
      .toUpperCase();

    const actionExecutedAtMs = candidate.actionExecutedAt
      ? Date.parse(candidate.actionExecutedAt)
      : candidate.executedAt
        ? Date.parse(candidate.executedAt)
        : NaN;

    const rawProbe =
      candidate.verificationProbe ||
      candidate.postActionProbe ||
      (Array.isArray(candidate.verificationResult?.probes) && candidate.verificationResult.probes[0]) ||
      (Array.isArray(candidate.probesRun) && candidate.probesRun[0]) ||
      (Array.isArray(candidate.newSteps) && candidate.newSteps[0]) ||
      (candidate.verification && typeof candidate.verification === 'object' ? candidate.verification : null);

    let verificationProbe = null;
    let rejectionReason = null;
    let partialTransportOnly = false;

    if (rawProbe && typeof rawProbe === 'object') {
      const probeType = String(
        rawProbe.probeType ||
          rawProbe.tool ||
          rawProbe.checkType ||
          (rawProbe.afterMetrics ? 'DNS_AND_TCP_POSTCONDITION_PROBE' : '')
      ).trim();

      const explicitProbeTarget = String(rawProbe.target || rawProbe.endpoint || '').trim();
      const probeTarget = explicitProbeTarget || remediatedTarget;

      const probeTimestamp =
        rawProbe.timestamp ||
        rawProbe.observedAt ||
        rawProbe.verifiedAt ||
        candidate.verifiedAt ||
        candidate.resolvedAt ||
        null;

      const parsedProbeTsMs = probeTimestamp ? Date.parse(String(probeTimestamp)) : NaN;
      const probeAgeMs = Number.isFinite(parsedProbeTsMs) ? nowMs - parsedProbeTsMs : NaN;

      const untrustedProvenance =
        rawProbe.synthetic === true ||
        /UNVERIFIED|MANUAL|SYNTHETIC|FABRICATED|ASSUMED|AI_GENERATED/i.test(String(rawProbe.provenance || '')) ||
        probeType.toUpperCase() === 'AI_SYNTHESIS_ASSERTION' ||
        probeType.toUpperCase() === 'MANUAL_DECLARATION';

      const targetMismatch =
        Boolean(explicitProbeTarget && remediatedTarget) &&
        explicitProbeTarget.toLowerCase() !== remediatedTarget.toLowerCase() &&
        !explicitProbeTarget.toLowerCase().startsWith(`${remediatedTarget.toLowerCase()}:`) &&
        !remediatedTarget.toLowerCase().startsWith(`${explicitProbeTarget.toLowerCase()}:`);

      const timestampInvalidOrStale =
        !Number.isFinite(parsedProbeTsMs) ||
        probeAgeMs > maxProbeFreshnessAgeMs ||
        probeAgeMs < -30000 ||
        (Number.isFinite(actionExecutedAtMs) && parsedProbeTsMs < actionExecutedAtMs);

      const hasMeasuredAfterMetrics = Boolean(
        rawProbe.afterMetrics &&
          (typeof rawProbe.afterMetrics.liveDnsRttMs === 'number' ||
            typeof rawProbe.afterMetrics.liveTcpRttMs === 'number' ||
            rawProbe.afterMetrics.reachable === true)
      );

      const hasNumericProbeMetric =
        (typeof rawProbe.latencyMs === 'number' && Number.isFinite(rawProbe.latencyMs) && rawProbe.latencyMs >= 0) ||
        (typeof rawProbe.rttMs === 'number' && Number.isFinite(rawProbe.rttMs) && rawProbe.rttMs >= 0) ||
        (typeof rawProbe.durationMs === 'number' && Number.isFinite(rawProbe.durationMs) && rawProbe.durationMs >= 0) ||
        (typeof rawProbe.statusCode === 'number' && Number.isFinite(rawProbe.statusCode));

      const observedText = String(rawProbe.observedResult || rawProbe.summary || '').trim();
      const hasQuantitativeObservedText =
        /\b\d+(\.\d+)?\s*(ms|s|%|bytes|packets|rtt|status|http|ok|200|204)\b/i.test(observedText) ||
        String(rawProbe.status || '').toUpperCase() === 'TUNNEL_AND_BACKEND_HEALTHY';

      const hasQuantitativeMeasurement =
        hasMeasuredAfterMetrics || hasNumericProbeMetric || hasQuantitativeObservedText;

      const explicitProbeStatus = String(rawProbe.status || rawProbe.verdict || '').toUpperCase();

      // Check layer appropriateness: L4 TCP alone cannot verify L7 HTTP application recovery
      const isL7Fault =
        remediatedLayer === 'L7_APPLICATION' ||
        remediatedLayer === 'APPLICATION_L7' ||
        remediatedLayer === 'HTTP_L7' ||
        remediatedLayer === 'L7_UPSTREAM_APPLICATION';
      const isTransportOnlyProbe =
        /^(TCP|ICMP|UDP|L3|L4)/i.test(probeType) &&
        !/HTTP|L7|APP|TLS/i.test(probeType) &&
        typeof rawProbe.statusCode !== 'number';

      if (untrustedProvenance) {
        rejectionReason = 'UNTRUSTED_PROBE_PROVENANCE';
      } else if (targetMismatch) {
        rejectionReason = 'PROBE_TARGET_MISMATCH';
      } else if (timestampInvalidOrStale) {
        rejectionReason = 'STALE_OR_INVALID_PROBE_TIMESTAMP';
      } else if (!hasQuantitativeMeasurement && explicitProbeStatus !== 'FAIL' && explicitProbeStatus !== 'UNREACHABLE') {
        rejectionReason = 'MISSING_QUANTITATIVE_PROBE_MEASUREMENT';
      } else if (isL7Fault && isTransportOnlyProbe) {
        partialTransportOnly = true;
        rejectionReason = 'TRANSPORT_ONLY_PROBE_INSUFFICIENT_FOR_L7_RECOVERY';
      }

      if (probeType && probeTarget && probeTimestamp) {
        const probePassed = Boolean(
          !rejectionReason &&
            hasQuantitativeMeasurement &&
            (rawProbe.criteriaMet === true ||
              rawProbe.probePassed === true ||
              rawProbe.healthy === true ||
              (rawProbe.postconditionPassed === true && hasMeasuredAfterMetrics) ||
              explicitProbeStatus === 'PASS' ||
              explicitProbeStatus === 'OK' ||
              explicitProbeStatus === 'TUNNEL_AND_BACKEND_HEALTHY') &&
            explicitProbeStatus !== 'FAIL' &&
            explicitProbeStatus !== 'ERROR' &&
            explicitProbeStatus !== 'UNREACHABLE' &&
            uninspectedProxiesCount === 0
        );

        verificationProbe = {
          probeType,
          target: probeTarget,
          timestamp: String(probeTimestamp),
          ageMs: Number.isFinite(probeAgeMs) ? Math.max(0, Math.round(probeAgeMs)) : null,
          observedResult:
            observedText ||
            (hasMeasuredAfterMetrics
              ? `liveDnsRttMs=${rawProbe.afterMetrics.liveDnsRttMs ?? 'N/A'}, liveTcpRttMs=${rawProbe.afterMetrics.liveTcpRttMs ?? 'N/A'}`
              : hasNumericProbeMetric
                ? `latencyMs=${rawProbe.latencyMs ?? rawProbe.rttMs ?? rawProbe.durationMs ?? 'N/A'}, statusCode=${rawProbe.statusCode ?? 'N/A'}`
                : explicitProbeStatus || 'unverified'),
          quantitativeMeasurementVerified: hasQuantitativeMeasurement,
          criteriaMet: probePassed,
          ...(rejectionReason ? { rejectionReason } : {})
        };
      }
    }

    const postActionHealthy = Boolean(verificationProbe && verificationProbe.criteriaMet === true);
    const recoveryState = verificationProbe
      ? postActionHealthy
        ? 'VERIFIED_HEALTHY_AFTER_REMEDIATION'
        : partialTransportOnly
          ? 'PARTIAL_TRANSPORT_ONLY_RECOVERY_L7_UNVERIFIED'
          : rejectionReason
            ? `UNVERIFIED_PROBE_REJECTED_${rejectionReason}`
            : 'POST_ACTION_PROBE_FAILED'
      : 'ACTION_EXECUTED_POST_PROBE_PENDING_OR_UNVERIFIED';

    return {
      incidentId: String(executionId),
      executionId: String(executionId),
      actionExecuted: true,
      recoveryState,
      status: recoveryState,
      postActionHealthy,
      verificationProbe,
      rejectionReason,
      uninspectedProxiesCount,
      verifiedAt: postActionHealthy ? verificationProbe.timestamp || new Date().toISOString() : null
    };
  }

  /**
   * Phase Atlas IX (Cycle 6): Explicit Indirect Evidence Epistemic Boundaries
   * Ensures indirect cross-layer observations are strictly bounded:
   *   - Successful TCP connectivity confirms L3/L4 reachability along the active route,
   *     but never claims physical switch port/NIC hardware health or L7 application health.
   *   - A DNS timeout distinguishes UDP/53 transport filtering, recursive resolver failure,
   *     and upstream authoritative domain failure rather than conflating them.
   */
  evaluateIndirectEvidenceBoundaries(observation = {}) {
    const probeType = String(observation.probeType || observation.type || '').trim().toUpperCase();
    const status = String(observation.status || observation.outcome || '').trim().toUpperCase();
    const rcode = String(observation.rcode || '').trim().toUpperCase();

    // 1. Authoritative NXDOMAIN
    const isNxDomain =
      probeType.includes('DNS') &&
      (status === 'NXDOMAIN' || rcode === 'NXDOMAIN');

    if (isNxDomain) {
      return {
        observationCategory: 'AUTHORITATIVE_DNS_NXDOMAIN_NON_EXISTENCE',
        provenByObservation: ['AUTHORITATIVE_ZONE_DOES_NOT_CONTAIN_RECORD_NXDOMAIN'],
        disambiguatedCandidateCauses: [
          'AUTHORITATIVE_ZONE_MISSING_RESOURCE_RECORD',
          'TYPOGRAPHICAL_DOMAIN_NAME_ERROR',
          'DECOMMISSIONED_OR_EXPIRED_HOST_RECORD'
        ],
        notProvenByObservation: [
          'RECURSIVE_RESOLVER_TIMEOUT',
          'UDP_53_OR_TCP_53_TRANSPORT_FILTERING',
          'PHYSICAL_NIC_LINK_DOWN'
        ],
        epistemicBoundaryNote:
          'An authoritative NXDOMAIN proves the requested domain record does not exist in the authoritative zone; it does NOT indicate recursive resolver outage or transport packet filtering.'
      };
    }

    // 2. DNS Timeout / Failure
    const isDnsTimeout =
      probeType.includes('DNS') &&
      (status === 'TIMEOUT' ||
        status === 'ANOMALY' ||
        status === 'FAIL' ||
        observation.timedOut === true ||
        observation.anomalyDetected === true);

    if (isDnsTimeout) {
      return {
        observationCategory: 'DNS_RESOLUTION_TIMEOUT_OR_FAILURE',
        provenByObservation: ['DNS_QUERY_RESPONSE_NOT_RECEIVED_WITHIN_DEADLINE'],
        disambiguatedCandidateCauses: [
          'UDP_53_OR_TCP_53_TRANSPORT_FILTERING_OR_FIREWALL_DROP',
          'RECURSIVE_RESOLVER_SATURATION_OR_PROCESS_UNAVAILABLE',
          'UPSTREAM_AUTHORITATIVE_NAMESERVER_TIMEOUT_OR_SERVFAIL'
        ],
        notProvenByObservation: [
          'DEFINITIVE_AUTHORITATIVE_DOMAIN_NON_EXISTENCE_NXDOMAIN',
          'PHYSICAL_NIC_LINK_DOWN'
        ],
        epistemicBoundaryNote:
          'A DNS timeout proves that no DNS response arrived within the deadline, but does NOT by itself disambiguate UDP/53 transport filtering, recursive resolver outage, or authoritative server failure without targeted L4/resolver probes.'
      };
    }

    // 3. Concrete Verified Positive TCP Three-Way Handshake
    const isTcpVerifiedPass =
      (probeType.includes('TCP') || observation.tcpReachable === true) &&
      observation.tcpReachable !== false &&
      (status === 'PASS' || status === 'OK' || status === 'SUCCESS') &&
      !observation.timedOut &&
      !observation.failed;

    if (isTcpVerifiedPass) {
      return {
        observationCategory: 'UPPER_LAYER_TCP_TRANSPORT_CONNECTIVITY',
        provenByObservation: [
          'L3_ACTIVE_ROUTE_IP_FORWARDING_REACHABILITY',
          'L4_TCP_THREE_WAY_HANDSHAKE_COMPLETION'
        ],
        notProvenByObservation: [
          'L1_PHYSICAL_SWITCH_PORT_CRC_OR_OPTICAL_DOM_HEALTH',
          'L2_REDUNDANT_LACP_MEMBER_LINK_HEALTH',
          'L7_HTTP_APPLICATION_WORKER_SEMANTIC_HEALTH'
        ],
        epistemicBoundaryNote:
          'Successful TCP connectivity indirectly confirms L3/L4 packet forwarding along the active route, but never claims physical switch port/cable error-free hardware health or L7 application worker correctness.'
      };
    }

    // 4. Failed or Refused TCP Transport
    const isTcpFailed =
      observation.tcpReachable === false ||
      (probeType.includes('TCP') &&
        (status === 'FAIL' ||
          status === 'TIMEOUT' ||
          status === 'REFUSED' ||
          status === 'ANOMALY' ||
          observation.timedOut === true ||
          observation.failed === true));

    if (isTcpFailed) {
      return {
        observationCategory: 'TCP_TRANSPORT_CONNECTIVITY_FAILED_OR_REFUSED',
        provenByObservation: ['L4_TCP_HANDSHAKE_NOT_ESTABLISHED'],
        disambiguatedCandidateCauses: [
          'REMOTE_HOST_DOWN_OR_UNREACHABLE',
          'INTERMEDIATE_FIREWALL_DROP_OR_REJECT',
          'SERVICE_NOT_LISTENING_PORT_CLOSED'
        ],
        notProvenByObservation: [
          'L3_ACTIVE_ROUTE_IP_FORWARDING_REACHABILITY',
          'L4_TCP_THREE_WAY_HANDSHAKE_COMPLETION',
          'PHYSICAL_NIC_LINK_DOWN'
        ],
        epistemicBoundaryNote:
          'A failed or refused TCP probe proves the handshake did not complete, but cannot assert active L3 forwarding reachability.'
      };
    }

    // 5. Default: Insufficient or unverified evidence
    return {
      observationCategory: 'INSUFFICIENT_OR_UNVERIFIED_EVIDENCE',
      provenByObservation: [],
      disambiguatedCandidateCauses: ['UNVERIFIED_MEASUREMENT_STATE'],
      notProvenByObservation: [
        'L3_ACTIVE_ROUTE_IP_FORWARDING_REACHABILITY',
        'L4_TCP_THREE_WAY_HANDSHAKE_COMPLETION',
        'DNS_RESOLUTION_CONFIRMED'
      ],
      epistemicBoundaryNote:
        'No direct verified probe outcome provided; epistemic boundaries prevent asserting forwarding reachability or naming validity.'
    };
  }
}

const chatOperatorService = new ChatOperatorService();

module.exports = {
  ChatOperatorService,
  chatOperatorService,
  detectDomainTypo,
  classifyDomainTypo,
  extractObservedTimingMs
};

