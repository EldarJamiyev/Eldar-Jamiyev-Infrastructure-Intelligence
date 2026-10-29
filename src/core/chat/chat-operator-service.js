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
const { getVerifiedDefaultGateway, inspectLocalNetworkConfiguration } = require('../../protocols/host-metrics');
const { processSocketCorrelator } = require('../../network/process-socket-correlator');
const { isSafeNetworkTarget, resolveAndValidateTarget } = require('../security');
const { crossLayerIncidentCorrelator } = require('../correlation/incident-correlator');
const { ROLE_LEVELS, autonomousInfrastructureOperator } = require('../operator/autonomous-infrastructure-operator');
const { evidenceFabric } = require('../evidence/evidence-fabric');
const {
  classifyDomainTypo,
  detectDomainTypo,
  isGreetingPrompt,
  isInformationalTechnicalQuestion,
  answerInformationalQuestion
} = require('./technical-knowledge-base');

const MAX_WORKING_MEMORY_MESSAGES = 40;
const MAX_ENTITY_OBSERVATIONS = 25;
const MAX_SOCKET_SNAPSHOTS = 10;

class ChatOperatorService {
  constructor() {
    this.sessions = new Map();
    this.inFlightRequests = new Map(); // sessionId -> { requestId, abortController, startedAt, userId }
    this._ensureTables();
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
    } catch (_) {
      // Non-fatal if DB is read-only during isolated unit test
    }
  }

  _normalizeUserIdentity(user = {}) {
    const userId = String(user.id || user.userId || user.username || 'op-1').trim();
    const username = String(user.username || user.id || 'operator').trim();
    const role = String(user.role || 'ANALYST').toUpperCase();
    return { userId, username, role };
  }

  /**
   * Verify that an existing session belongs to the requesting authenticated user.
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
      // Match by userId or username
      if (ownerUserId && String(ownerUserId) === caller.userId) return true;
      if (ownerUsername && String(ownerUsername).toLowerCase() === caller.username.toLowerCase() && (!ownerUserId || ownerUserId === 'op-1')) {
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
    } catch (_) {}

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

    // Check SQLite for persisted session (Bounded working memory + unlimited SQLite history)
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
          lastTarget: ctx.lastTarget || null,
          lastValidTarget: ctx.lastValidTarget || ctx.lastTarget || null,
          targetHistory: Array.isArray(ctx.targetHistory) ? ctx.targetHistory : [],
          entityMemory: (ctx.entityMemory && typeof ctx.entityMemory === 'object') ? ctx.entityMemory : {},
          socketSnapshots: Array.isArray(ctx.socketSnapshots) ? ctx.socketSnapshots : [],
          lastMultiEndpoints: Array.isArray(ctx.lastMultiEndpoints) ? ctx.lastMultiEndpoints : [],
          lastPorts: Array.isArray(ctx.lastPorts) ? ctx.lastPorts : [],
          lastIntent: ctx.lastIntent || null,
          lastUrl: ctx.lastUrl || null,
          lastToolResults: ctx.lastToolResults || null,
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
      lastTarget: null,
      lastValidTarget: null,
      targetHistory: [],
      entityMemory: {},
      socketSnapshots: [],
      lastMultiEndpoints: [],
      lastPorts: [],
      lastIntent: null,
      lastUrl: null,
      lastToolResults: null,
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
    return existing;
  }

  _persistSession(session, newMessages = []) {
    try {
      const nowIso = new Date().toISOString();
      const contextJson = JSON.stringify({
        lastTarget: session.lastTarget,
        lastValidTarget: session.lastValidTarget,
        targetHistory: session.targetHistory || [],
        entityMemory: session.entityMemory || {},
        socketSnapshots: (session.socketSnapshots || []).slice(-MAX_SOCKET_SNAPSHOTS),
        lastMultiEndpoints: session.lastMultiEndpoints || [],
        lastPorts: session.lastPorts,
        lastIntent: session.lastIntent,
        lastUrl: session.lastUrl,
        lastToolResults: session.lastToolResults,
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
    } catch (_) {}
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
   * Parse user prompt and session context into a structured execution plan
   */
  parseIntentAndEntities(promptText, session) {
    const raw = String(promptText || '').trim();
    const lower = raw.toLowerCase();

    // 0A. Greeting / Capability Inquiry (Case A: 0 probes, preserves previous context)
    if (isGreetingPrompt(raw)) {
      return {
        intent: 'greeting',
        mode: 'conversational',
        target: session?.lastValidTarget || session?.lastTarget || null,
        explicitTarget: null,
        ports: session?.lastPorts || [],
        preserveContextOnly: true
      };
    }

    // 0B. Informational / Conceptual Technical Question (Case P: 0 probes, preserves previous context)
    if (isInformationalTechnicalQuestion(raw)) {
      return {
        intent: 'informational_question',
        mode: 'informational',
        target: session?.lastValidTarget || session?.lastTarget || null,
        explicitTarget: null,
        ports: session?.lastPorts || [],
        preserveContextOnly: true
      };
    }

    // 0C. Check My IP / Local Network Configuration (Case I: never inherits previous remote target)
    const isLocalIpPrompt =
      /\b(check my ip|what is my ip|what's my ip|what is my public ip|check my public ip|inspect my network configuration|show my network configuration|my network interfaces|show my ip|local ip configuration|ipconfig|ifconfig)\b/i.test(lower);
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

    // 0D. Default Gateway Inspection / Ping (Case J: never inherits previous remote target, never guesses .1)
    const isGatewayPrompt =
      /\b(ping (?:my |the )?default gateway|ping (?:my |the )?gateway|check (?:my |the )?default gateway|test (?:my |the )?default gateway|is (?:my |the )?default gateway reachable)\b/i.test(lower);
    if (isGatewayPrompt) {
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

    // 0E. Active Network Connections, Open Sockets & Destination Endpoints (Cases K & L)
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

    // 1. Check if the user is asking for an explanation, summary, memory recall, or historical comparison of previous findings (Case Q)
    const isExplanationOrComparisonFollowUp =
      /^(why did (that|it) fail|which layer failed|explain the results?|summarize what you|give me a concise incident report|prepare a technical incident report|incident report|what does that mean|what should i do next|tell me the next step|what have we (tested|found)|show memory|compare (all )?hosts|compare the latest|what changed since|show me what changed|what happened\??)$/i.test(lower) ||
      ((lower.includes('summarize') || lower.includes('incident report') || lower.includes('which layer failed') || lower.includes('why did that fail') || lower.includes('why did it fail') || lower.includes('explain the result') || lower.includes('what have we tested') || lower.includes('compare hosts') || lower.includes('compare the latest') || lower.includes('what changed since') || lower.includes('what happened')) &&
        !lower.includes('ping ') && !lower.includes('check port') && !lower.includes('test port'));

    if (isExplanationOrComparisonFollowUp) {
      const hasPriorDiagnosticContext = Boolean(
        session && (session.lastToolResults || Object.keys(session.entityMemory || {}).length > 0 || (session.socketSnapshots && session.socketSnapshots.length > 0))
      );
      if (!hasPriorDiagnosticContext) {
        return {
          intent: 'clarification_needed',
          mode: 'conversational',
          clarificationReason: 'MISSING_PRIOR_CONTEXT',
          clarificationPrompt:
            'There are no previous diagnostic results in this conversation yet. Which hostname, IP address, or local check (for example, `example.com`, `localhost:3000`, or `Check my IP`) would you like me to run first?',
          target: null,
          explicitTarget: null,
          ports: [],
          preserveContextOnly: true
        };
      }
      return {
        intent: 'follow_up_explanation',
        mode: 'informational',
        target: session.lastValidTarget || session.lastTarget || 'localhost',
        explicitTarget: null,
        ports: session.lastPorts?.length ? session.lastPorts : [3000],
        url: session.lastUrl || null,
        recordType: 'A',
        usedFollowUpTarget: true,
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

    // 3. Extract explicit IPv4, localhost, or domain name
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
      } else if (/\b(this server|this host|local server|local workstation|my computer)\b/i.test(raw)) {
        explicitTarget = '127.0.0.1';
      }
    }

    if (!explicitTarget) {
      const domainRegex = /\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,24}))\b/g;
      let match;
      const stopDomains = new Set(['e.g', 'i.e', 'etc.']);
      while ((match = domainRegex.exec(raw)) !== null) {
        const candidate = match[1];
        if (!stopDomains.has(candidate.toLowerCase())) {
          explicitTarget = candidate;
          break;
        }
      }
    }

    // 4. Extract ports from prompt (including short follow-ups like "Try 80 too", "Now check 443", "Test the other port")
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

    // Short port follow-up patterns: "Try 80 too", "Now check 443", "What about 8080", "Try it with 80"
    if (extractedPorts.length === 0) {
      const shortPortFollowUp = raw.match(/\b(?:try|check|test|with|on|about)\s+(?:it\s+(?:with|on)\s+)?(\d{2,5})(?:\s+too|\s+instead|\s+as well|\s+next)?\b/i);
      if (shortPortFollowUp && !explicitTarget) {
        const p = Number(shortPortFollowUp[1]);
        if (p >= 1 && p <= 65535) {
          extractedPorts.push(p);
        }
      }
    }

    // "Test the other port" follow-up support
    if (extractedPorts.length === 0 && /\b(the other port|other port|alternate port)\b/i.test(lower)) {
      const lastPort = session?.lastPorts?.[0];
      if (lastPort === 443) extractedPorts.push(80);
      else if (lastPort === 80) extractedPorts.push(443);
      else if (lastPort === 8080) extractedPorts.push(3000);
      else extractedPorts.push(443);
    }

    // 5. Check if user is asking a general "check dns connection" / "check whether dns is working" without an explicit domain (Case D)
    const isGenericDnsHealthPrompt =
      !explicitTarget &&
      /\b(check dns( connection| connectivity| status| health| server)?|test dns( connection| connectivity| server)?|check whether dns is working|is dns working|verify dns( connection)?|dns connection|dns connectivity|dns health)\b/i.test(lower) &&
      !/\b(same host|same domain|that host|that domain|for it|on it)\b/i.test(lower);

    // 6. Check for Context Loss (Case N) and Multi-Target Ambiguity (Case O)
    const refersToFirstTarget = /\b(first host|first domain|initial host|original host)\b/i.test(lower);
    const refersToPreviousTarget =
      /\b(same host|same server|same target|same domain|that host|that server|that domain|that endpoint|on it|for it|test it|check it|ping it|try (\d{2,5}) too|now check (\d{2,5})|the other port|repeat the (?:same )?check|test the same host again|run that again|retry that|try again)\b/i.test(lower);

    const isRemediation =
      /\b(flush dns|refresh dns resolver|apply (?:the )?(?:fix|remediation)|execute remediation|heal|self-heal|fix it now|repair dns)\b/i.test(lower);
    const isHostHealth =
      /\b(local host health|system health|host diagnostics|cpu and memory|local system)\b/i.test(lower) && !explicitTarget;

    if (!explicitTarget && !isGenericDnsHealthPrompt && !isRemediation && !isHostHealth) {
      // Case O: Multi-Target Ambiguity after Active Connections or multi-host comparison
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

      // Case N: Context Loss — user sent a follow-up ("Now test port 80 on the same host", "Try 80 too", "Repeat the same check") when no prior target exists
      const hasPriorTarget = Boolean(session && (session.lastValidTarget || session.lastTarget));
      if (!hasPriorTarget) {
        return {
          intent: 'clarification_needed',
          mode: 'conversational',
          clarificationReason: 'MISSING_TARGET_CONTEXT',
          clarificationPrompt:
            extractedPorts.length > 0
              ? `Which hostname or IP address would you like me to test on TCP port ${extractedPorts.join(', ')}? There is no previous target in this session yet.`
              : 'Which hostname, IP address, or URL would you like me to diagnose? Please specify a target (for example, `example.com` or `localhost:3000`).',
          target: null,
          explicitTarget: null,
          ports: extractedPorts,
          preserveContextOnly: true
        };
      }
    }

    // 7. Resolve target using contextual follow-up memory when unambiguous
    let usedFollowUpTarget = false;
    let resolvedTarget = explicitTarget;

    if (!resolvedTarget) {
      if (isGenericDnsHealthPrompt) {
        resolvedTarget = 'example.com';
      } else if (refersToFirstTarget && session?.targetHistory?.length > 0) {
        resolvedTarget = session.targetHistory[0];
        usedFollowUpTarget = true;
      } else if (session && (session.lastValidTarget || session.lastTarget)) {
        resolvedTarget = session.lastValidTarget || session.lastTarget;
        usedFollowUpTarget = true;
      } else {
        resolvedTarget = 'localhost';
      }
    }

    // 8. Determine primary intent
    let intent = 'multi_step_investigation';

    const isRepeatLast =
      /\b(test the same host again|run that again|retry that|check it again|repeat the (?:same )?check|try again)\b/i.test(lower) &&
      !lower.includes('port') && !lower.includes('dns') && !lower.includes('ping');

    if (isRemediation) {
      intent = 'remediation';
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
      (isGenericDnsHealthPrompt || /\b(check dns|dns check|test dns|dns connection|dns connectivity|resolve|nslookup|dig|dns lookup|a record|aaaa record|mx record|txt record)\b/i.test(lower)) &&
      !lower.includes('or dns is causing') &&
      !lower.includes('investigate why')
    ) {
      intent = 'dns';
    } else if (
      extractedPorts.length > 0 &&
      (/\b(port|ports|tcp|open|listening|connect|try|now test|now check|other port)\b/i.test(lower)) &&
      !lower.includes('investigate why')
    ) {
      intent = 'port_check';
    } else if (
      extractedUrl ||
      (/\b(website|https:\/\/|http:\/\/|web page|site is working|site is accessible|check whether https|verify https)\b/i.test(lower) &&
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
        extractedPorts.push(session?.lastPorts?.[0] || 443);
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
    if (/\baaaa\b/i.test(lower)) recordType = 'AAAA';
    else if (/\bmx\b/i.test(lower)) recordType = 'MX';
    else if (/\btxt\b/i.test(lower)) recordType = 'TXT';
    else if (/\bns\b/i.test(lower)) recordType = 'NS';
    else if (/\bcname\b/i.test(lower)) recordType = 'CNAME';

    const typoClassification = classifyDomainTypo(resolvedTarget, session?.targetHistory || []);
    const typoSuggestion = typoClassification?.confidence === 'high' ? typoClassification.corrected : null;

    return {
      intent,
      mode: 'operational',
      target: resolvedTarget,
      explicitTarget: explicitTarget || null,
      typoSuggestion,
      typoClassification,
      isSystemDnsHealthCheck: isGenericDnsHealthPrompt,
      ports: extractedPorts,
      url: extractedUrl,
      urlProtocol: urlProtocol || (extractedPorts[0] === 443 ? 'https' : 'http'),
      recordType,
      usedFollowUpTarget
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
   * Main entry point for handling a user chat message.
   */
  async processMessage({
    sessionId,
    message,
    user = { id: 'op-1', username: 'operator', role: 'ANALYST' },
    requestId = null,
    signal = null,
    simulateTimeout = false
  } = {}) {
    const startWall = performance.now();
    const cleanPrompt = String(message || '').trim();
    if (!cleanPrompt) {
      return {
        success: false,
        status: 'invalid_input',
        statusCode: 400,
        error: { code: 'EMPTY_MESSAGE', message: 'Please enter a diagnostic question or target to investigate.' }
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
          message: 'A diagnostic check is already in progress for this conversation. Wait for it to finish or press Stop.'
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

    try {
      const plan = this.parseIntentAndEntities(cleanPrompt, session);

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
        const timeoutTarget = plan.target || 'localhost';
        const timeoutReply =
          `**Result:** The diagnostic probe to \`${timeoutTarget}\` timed out before completing.\n\n` +
          `**Meaning:** The target host or an intermediate firewall did not respond within the allowed diagnostic window (ETIMEDOUT). No healthy result was assumed.\n\n` +
          `**Next step:** Verify that \`${timeoutTarget}\` is online and not dropping packets silently, or retry with a direct TCP port check.`;
        const structuredAnswer = {
          result: `Diagnostic probe to ${timeoutTarget} timed out (ETIMEDOUT).`,
          meaning: 'The target or an intermediate firewall did not reply within the time limit.',
          nextStep: `Verify that ${timeoutTarget} is reachable on the local network or test a specific TCP port.`,
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
            durationMs: 1500
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
            `**Result:** Permission denied for role \`${effectiveRole}\`.\n\n` +
            `**Meaning:** State-changing remediation actions (such as flushing the DNS resolver cache or reconciling host state) require \`OPERATOR\`, \`SYSADMIN\`, or \`ADMIN\` authorization. Your account is currently restricted to read-only diagnostics.\n\n` +
            `**Next step:** Sign in with an Operator or Administrator account to execute this remediation, or continue running read-only diagnostic checks.`;
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
        'informational_question',
        'clarification_needed',
        'follow_up_explanation',
        'host_health',
        'local_ip_config',
        'gateway_check',
        'active_connections'
      ]);

      if (!nonRemoteProbeIntents.has(plan.intent)) {
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

        // Cautious Typo Recovery (Part V, Section 5):
        // Auto-correct ONLY high-confidence unambiguous TLD/well-known typos when the original domain failed DNS (ENOTFOUND),
        // while keeping full transparency. For uncertain typos, report the exact failure and suggest the correction.
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

      let executionOutcome;
      switch (plan.intent) {
        case 'greeting':
          executionOutcome = this._executeGreetingScenario(session);
          break;
        case 'informational_question':
          executionOutcome = this._executeInformationalQuestionScenario(cleanPrompt, session);
          break;
        case 'clarification_needed':
          executionOutcome = this._executeClarificationScenario(plan, session);
          break;
        case 'local_ip_config':
          executionOutcome = this._executeLocalIpConfigScenario(plan, session, abortController.signal);
          break;
        case 'gateway_check':
          executionOutcome = await this._executeGatewayCheckScenario(plan, session, abortController.signal);
          break;
        case 'active_connections':
          executionOutcome = await this._executeActiveConnectionsScenario(plan, session, abortController.signal);
          break;
        case 'dns':
          executionOutcome = await this._executeDnsScenario(plan, session, abortController.signal);
          break;
        case 'ping':
          executionOutcome = await this._executePingScenario(plan, session, abortController.signal);
          break;
        case 'port_check':
          executionOutcome = await this._executePortCheckScenario(plan, session, abortController.signal);
          break;
        case 'website_check':
          executionOutcome = await this._executeWebsiteCheckScenario(plan, session, abortController.signal);
          break;
        case 'traceroute':
          executionOutcome = await this._executeTracerouteScenario(plan, session, abortController.signal);
          break;
        case 'host_health':
          executionOutcome = await this._executeHostHealthScenario(plan, abortController.signal);
          break;
        case 'follow_up_explanation':
          executionOutcome = await this._executeFollowUpExplanation(plan, session, cleanPrompt);
          break;
        case 'remediation':
          executionOutcome = await this._executeRemediationScenario(plan, user, abortController.signal);
          break;
        case 'multi_step_investigation':
        default:
          executionOutcome = await this._executeMultiStepInvestigation(plan, session, cleanPrompt, abortController.signal);
          break;
      }

      this._checkAborted(abortController.signal);

      // If an unambiguous domain typo was auto-corrected (e.g. google.ocm -> google.com), prepend the auto-correction step and note
      if (plan.originalTypoTarget && executionOutcome) {
        const typoStep = {
          stepNumber: 1,
          label: `Detected domain typo "${plan.originalTypoTarget}" (NXDOMAIN) → auto-corrected to "${plan.target}"…`,
          tool: 'typo_intelligence',
          status: 'PASS',
          summary: `"${plan.originalTypoTarget}" does not exist in DNS (ENOTFOUND); automatically switched to "${plan.target}"`,
          durationMs: 1.2
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
          `> **Auto-Corrected Typo:** \`${plan.originalTypoTarget}\` does not exist in DNS (\`ENOTFOUND\`), so EJII automatically diagnosed **\`${plan.target}\`** instead.\n\n` +
          executionOutcome.reply;
      }

      const responsePayload = this._finalizeTurn(session, userMsgRecord, {
        reqId,
        plan,
        ...executionOutcome,
        startWall
      });

      return {
        success: true,
        status: 'ok',
        statusCode: 200,
        data: responsePayload
      };
    } catch (err) {
      if (err.code === 'REQUEST_CANCELLED' || abortController.signal.aborted) {
        // Case S: Cancelled requests must never corrupt existing session context
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
    reply,
    structuredAnswer,
    steps = [],
    findings = [],
    technicalEvidence = null,
    connectionTable = null,
    interfaceTable = null,
    reportMarkdown = null,
    startWall
  }) {
    const totalDurationMs = Number((performance.now() - startWall).toFixed(1));
    const nowIso = new Date().toISOString();

    // Preserve previous diagnostic target & tool results on greeting, informational, clarification, or local-only turns
    if (!plan.preserveContextOnly && !plan.preserveLastRemoteTarget) {
      const targetWasValid = !plan.targetValidation || plan.targetValidation.valid;
      if (plan.target && !plan.isSystemDnsHealthCheck) {
        if (targetWasValid || !session.lastValidTarget) {
          session.lastTarget = plan.target;
        }
        if (targetWasValid) {
          session.lastValidTarget = plan.target;
        }
        // Single-target turn clears multi-endpoint ambiguity
        session.lastMultiEndpoints = [];
      }
      if (Array.isArray(plan.ports) && plan.ports.length > 0) {
        session.lastPorts = plan.ports;
      }
      session.lastIntent = plan.intent;
      if (plan.url) {
        session.lastUrl = plan.url;
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
      // Local IP / Gateway / Active Connections update lastToolResults but do NOT overwrite lastTarget
      session.lastIntent = plan.intent;
      if (technicalEvidence) {
        session.lastToolResults = technicalEvidence;
      }
      if (Array.isArray(steps) && steps.length > 0) {
        session.lastSteps = steps;
      }
      if (structuredAnswer) {
        session.lastStructuredAnswer = structuredAnswer;
      }
    }

    session.turnCount = (session.turnCount || 0) + 1;

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
        steps,
        findings,
        connectionTable,
        interfaceTable,
        reportMarkdown,
        technicalEvidence
      }
    };

    session.messages.push(userMsgRecord, assistantMsgRecord);
    session.totalPersistedMessages = (session.totalPersistedMessages || 0) + 2;

    // Bound active in-memory messages while keeping full history in SQLite (Case T)
    if (session.messages.length > MAX_WORKING_MEMORY_MESSAGES) {
      session.messages = session.messages.slice(-MAX_WORKING_MEMORY_MESSAGES);
    }

    this._persistSession(session, [userMsgRecord, assistantMsgRecord]);

    return {
      sessionId: session.sessionId,
      requestId: reqId,
      intent: plan.intent,
      mode: plan.mode || 'operational',
      target: plan.target,
      ports: plan.ports,
      usedFollowUpTarget: Boolean(plan.usedFollowUpTarget),
      totalDurationMs,
      reply,
      structuredAnswer,
      steps,
      findings,
      connectionTable,
      interfaceTable,
      reportMarkdown,
      technicalEvidence,
      sessionContext: {
        lastTarget: session.lastTarget,
        lastValidTarget: session.lastValidTarget,
        lastPorts: session.lastPorts,
        lastIntent: session.lastIntent,
        turnCount: session.turnCount,
        activeMemoryMessageCount: session.messages.length,
        totalPersistedMessages: session.totalPersistedMessages,
        knownEntitiesCount: Object.keys(session.entityMemory || {}).length
      }
    };
  }

  /**
   * Case A: Greeting & Conversational Turn (0 network probes, preserves prior diagnostic context)
   */
  _executeGreetingScenario(session) {
    const activeTargetNote = session.lastValidTarget
      ? ` Your current active investigation target is **\`${session.lastValidTarget}\`**${session.lastPorts?.length ? ` (port ${session.lastPorts.join(', ')})` : ''}.`
      : '';
    const structuredAnswer = {
      result: 'Hello! I am EJII — your Infrastructure & Network Diagnostic Assistant.',
      meaning: `I can run live DNS, ICMP ping, TCP port, TLS/HTTPS, local IP/gateway, and active socket checks, or answer general networking questions.${activeTargetNote}`,
      nextStep: 'Ask a question such as "Check DNS for example.com", "Check my IP", "Show me the active connections", or "Check whether port 3000 is open on localhost".',
      layerFailedFirst: null,
      uncertainty: null
    };
    const reply =
      `**Result:** ${structuredAnswer.result}\n\n` +
      `**Meaning:** ${structuredAnswer.meaning}\n\n` +
      `**Next step:** ${structuredAnswer.nextStep}`;
    return {
      reply,
      structuredAnswer,
      steps: [],
      findings: [
        { label: 'Mode', value: 'Conversational (No network probes executed)', tone: 'neutral' },
        ...(session.lastValidTarget ? [{ label: 'Preserved Context', value: session.lastValidTarget, tone: 'ok' }] : [])
      ],
      technicalEvidence: null
    };
  }

  /**
   * Case P: Informational / Technical Question Mode (0 network probes, labeled clearly as conceptual explanation)
   */
  _executeInformationalQuestionScenario(promptText, session) {
    const kb = answerInformationalQuestion(promptText);
    const structuredAnswer = {
      result: kb.result,
      meaning: kb.meaning,
      nextStep: kb.nextStep,
      layerFailedFirst: null,
      uncertainty: null
    };
    const reply =
      `**Result (${kb.topic}):** ${kb.result}\n\n` +
      `**Meaning:**\n${kb.meaning}\n\n` +
      `**Next step:** ${kb.nextStep}`;

    return {
      reply,
      structuredAnswer,
      steps: [],
      findings: [
        { label: 'Mode', value: 'Technical Explanation (0 live probes)', tone: 'neutral' },
        { label: 'Topic', value: kb.topic, tone: 'ok' },
        ...(session.lastValidTarget ? [{ label: 'Preserved Target', value: session.lastValidTarget, tone: 'neutral' }] : [])
      ],
      technicalEvidence: {
        mode: 'informational_explanation',
        liveProbesExecuted: 0,
        topic: kb.topic,
        preservedSessionTarget: session.lastValidTarget || null,
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Cases N & O: Clarification Needed (Context Loss or Multi-Target Ambiguity)
   */
  _executeClarificationScenario(plan, session) {
    const structuredAnswer = {
      result: plan.clarificationPrompt,
      meaning: plan.clarificationReason === 'AMBIGUOUS_MULTI_TARGET'
        ? 'The previous turn listed multiple network endpoints, so EJII needs to know which specific host you want to probe rather than guessing arbitrarily.'
        : 'A follow-up command was entered, but no target hostname or IP address has been established in this conversation yet. EJII never silently defaults follow-up commands to localhost.',
      nextStep: plan.candidateTargets?.length
        ? `Reply with the specific endpoint (for example: "Check port 443 on ${plan.candidateTargets[0].split(':')[0]}").`
        : 'Specify the hostname or IP address you want to test (for example: "Check port 80 on example.com").',
      layerFailedFirst: null,
      uncertainty: null
    };
    const reply =
      `**Result (Clarification Needed):** ${structuredAnswer.result}\n\n` +
      `**Meaning:** ${structuredAnswer.meaning}\n\n` +
      `**Next step:** ${structuredAnswer.nextStep}`;
    return {
      reply,
      structuredAnswer,
      steps: [],
      findings: [
        { label: 'Status', value: 'Clarification Needed', tone: 'warn' },
        ...(plan.candidateTargets?.length
          ? [{ label: 'Candidates', value: plan.candidateTargets.slice(0, 4).join(', '), tone: 'neutral' }]
          : [])
      ],
      technicalEvidence: {
        clarificationReason: plan.clarificationReason,
        candidateTargets: plan.candidateTargets || [],
        preservedSessionTarget: session.lastValidTarget || null,
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

    const publicIpNote = plan.asksForPublicIp
      ? ' Note: You asked for a public/external IP address. Local OS interface inspection only reveals host/container network interface addresses; discovering your NAT public egress IP requires querying an external IP reflection service.'
      : '';

    const steps = [
      {
        stepNumber: 1,
        label: 'Inspecting local OS network interfaces, DNS resolvers, and kernel routing table…',
        tool: 'inspectLocalNetworkConfiguration',
        status: 'PASS',
        summary: `Found ${configData.interfaces.length} interface(s) on ${configData.hostname} · Primary IPv4: ${configData.primaryIpv4} · Gateway: ${gw.verified ? gw.gatewayIp : 'Unverified'}`,
        durationMs
      }
    ];

    const structuredAnswer = {
      result: `Local host "${configData.hostname}" (${configData.executionScope}) has primary IPv4 address ${configData.primaryIpv4}, ${configData.interfaces.length} network interface(s) (${configData.interfaces.map((i) => i.interfaceName).join(', ')}), configured DNS server(s) [${configData.dnsServers.join(', ') || 'none'}], and default gateway: ${gwLabel}.${publicIpNote}`,
      meaning: `${configData.scopeDistinctionNote}`,
      nextStep: gw.verified && gw.gatewayIp
        ? `Ask "Ping my default gateway" to test L3 reachability to ${gw.gatewayIp}, or "Show me the active connections" to inspect open sockets.`
        : 'Ask "Show me the active connections" to inspect open sockets, or "Check DNS connectivity" to test name resolution.',
      layerFailedFirst: null,
      uncertainty: null
    };

    const reply =
      `**Result:** ${structuredAnswer.result}\n\n` +
      `**Meaning:** ${structuredAnswer.meaning}\n\n` +
      `**Next step:** ${structuredAnswer.nextStep}`;

    return {
      reply,
      structuredAnswer,
      steps,
      findings: [
        { label: 'Primary IPv4', value: configData.primaryIpv4, tone: 'ok' },
        { label: 'Default Gateway', value: gw.verified && gw.gatewayIp ? gw.gatewayIp : 'Unverified (Not Guessed)', tone: gw.verified ? 'ok' : 'warn' },
        { label: 'DNS Servers', value: configData.dnsServers.join(', ') || 'None', tone: 'neutral' },
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
   * Case J: Default Gateway Check ("Ping my default gateway") — never guesses .1 and never inherits lastTarget
   */
  async _executeGatewayCheckScenario(plan, session, signal) {
    this._checkAborted(signal);
    const t0 = performance.now();
    const gw = getVerifiedDefaultGateway();
    const lookupMs = Number((performance.now() - t0).toFixed(1));

    if (!gw.verified || !gw.gatewayIp) {
      const steps = [
        {
          stepNumber: 1,
          label: 'Inspecting OS kernel routing table for 0.0.0.0/0 default gateway…',
          tool: 'getVerifiedDefaultGateway',
          status: 'WARN',
          summary: `No verified 0.0.0.0/0 default route exposed in routing table (${gw.collectionMethod})`,
          durationMs: lookupMs
        }
      ];
      const structuredAnswer = {
        result: 'Cannot ping default gateway: no verified default gateway route (0.0.0.0/0) was found in the local OS or container routing table.',
        meaning: `${gw.limitationReason} EJII never guesses a ".1" address from the local IP or substitutes a previous remote target.`,
        nextStep: 'If you know the specific gateway IP address on your network, ask "Ping <gateway-ip>" directly, or run "Check my IP" to inspect your active network interfaces.',
        layerFailedFirst: null,
        uncertainty: 'Containerized and sandboxed network namespaces frequently omit a host-visible 0.0.0.0/0 gateway entry.'
      };
      const reply =
        `**Result:** ${structuredAnswer.result}\n\n` +
        `**Meaning:** ${structuredAnswer.meaning}\n\n` +
        `**Next step:** ${structuredAnswer.nextStep}`;
      return {
        reply,
        structuredAnswer,
        steps,
        findings: [
          { label: 'Default Gateway', value: 'Unverified in Routing Table', tone: 'warn' },
          { label: 'Collection Method', value: gw.collectionMethod, tone: 'neutral' },
          { label: 'Safety Policy', value: 'No guessed .1 address', tone: 'ok' }
        ],
        technicalEvidence: { gatewayInfo: gw, pingExecuted: false, observedAt: new Date().toISOString() }
      };
    }

    const pingStart = performance.now();
    const pingRes = await realPing(gw.gatewayIp, 2, 1000);
    const pingMs = Number((performance.now() - pingStart).toFixed(1));

    const steps = [
      {
        stepNumber: 1,
        label: 'Reading verified default gateway from OS routing table…',
        tool: 'getVerifiedDefaultGateway',
        status: 'PASS',
        summary: `Verified default gateway ${gw.gatewayIp}${gw.interfaceName ? ` on interface ${gw.interfaceName}` : ''} via ${gw.collectionMethod}`,
        durationMs: lookupMs
      },
      {
        stepNumber: 2,
        label: `Sending ICMP echo requests to default gateway ${gw.gatewayIp}…`,
        tool: 'realPing',
        status: pingRes.success ? 'PASS' : 'WARN',
        summary: pingRes.success
          ? `${pingRes.packetsReceived}/${pingRes.packetsSent} ICMP replies from gateway ${gw.gatewayIp} (avg ${pingRes.avgRttMs} ms)`
          : `0/${pingRes.packetsSent} ICMP replies from verified gateway ${gw.gatewayIp} (ICMP may be restricted by container/router policy)`,
        durationMs: pingMs
      }
    ];

    const structuredAnswer = pingRes.success
      ? {
          result: `Verified default gateway ${gw.gatewayIp} (obtained via ${gw.collectionMethod}${gw.interfaceName ? ` on ${gw.interfaceName}` : ''}) responded to ICMP ping with ${pingRes.packetsReceived}/${pingRes.packetsSent} replies and an average RTT of ${pingRes.avgRttMs} ms.`,
          meaning: `Your local Layer 2/Layer 3 hop to the default router (${gw.gatewayIp}) is verified and healthy.`,
          nextStep: 'If external internet hosts are still unreachable, check DNS resolution next ("Check DNS connectivity").',
          layerFailedFirst: null,
          uncertainty: null
        }
      : {
          result: `Default gateway ${gw.gatewayIp} was verified from the OS routing table (${gw.collectionMethod}), but returned 0/${pingRes.packetsSent} ICMP echo replies (100% ICMP loss).`,
          meaning: `The routing table confirms ${gw.gatewayIp} is your configured default gateway, but either the container runtime restricts raw ICMP sockets or the gateway router ignores ICMP echo requests.`,
          nextStep: 'Test external DNS or TCP reachability (e.g., "Check DNS for example.com" or "Check port 443 on example.com") to verify whether the gateway is forwarding traffic normally.',
          layerFailedFirst: 'L3 ICMP Echo to Gateway',
          uncertainty: 'In containerized environments, virtual bridge gateways often forward TCP/UDP traffic while dropping ICMP echo requests.'
        };

    const reply =
      `**Result:** ${structuredAnswer.result}\n\n` +
      `**Meaning:** ${structuredAnswer.meaning}\n\n` +
      `**Next step:** ${structuredAnswer.nextStep}`;

    return {
      reply,
      structuredAnswer,
      steps,
      findings: [
        { label: 'Verified Gateway', value: gw.gatewayIp, tone: 'ok' },
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

    let rows = inventory.connections || [];
    if (filter.protocol) {
      rows = rows.filter((r) => r.protocol.toUpperCase() === filter.protocol.toUpperCase());
    }

    // Compare with previous socket snapshot if available
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

    // Record multi-endpoint candidates so ambiguous follow-ups ("Ping that host") ask clarification (Case O)
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
        status: inventory.success ? 'PASS' : 'FAIL',
        summary: inventory.success
          ? `Observed ${rows.length} socket(s) (${inventory.establishedCount} ESTABLISHED, ${inventory.listeningCount} LISTENING) in ${inventory.collectionScope}`
          : `Socket enumeration failed: ${inventory.collectorError || 'Collector error'}`,
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
        ? `Specify any remote IP or port from the table to diagnose it directly (for example: "Check port ${rows[0]?.localPort || 3000} on ${candidateHosts[0]}").`
        : 'Ask "Show me the active connections" again after running a workload to compare socket changes.',
      layerFailedFirst: inventory.success ? null : 'OS Socket Table Collector',
      uncertainty: null
    };

    const reply =
      `**Result:** ${structuredAnswer.result}\n\n` +
      `**Meaning:** ${structuredAnswer.meaning}\n\n` +
      `**Next step:** ${structuredAnswer.nextStep}`;

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

    // Case D: General "check dns connectivity" / "check whether dns is working" health check
    if (plan.isSystemDnsHealthCheck) {
      const health = await checkDnsConnectivityHealth('example.com');
      const totalMs = Number((performance.now() - stepStart).toFixed(1));
      const steps = [
        {
          stepNumber: 1,
          label: `Inspecting configured DNS resolvers (${health.configuredServers.join(', ') || health.primaryResolver}) and testing local hosts resolution…`,
          tool: 'checkDnsConnectivityHealth',
          status: health.localhostProbe.success ? 'PASS' : 'FAIL',
          summary: `Localhost resolved → ${(health.localhostProbe.records || []).join(', ')} via ${health.localhostProbe.resolutionMethod || 'local_hosts_table'} (${health.localhostProbe.durationMs} ms)`,
          durationMs: health.localhostProbe.durationMs
        },
        {
          stepNumber: 2,
          label: `Verifying external recursive DNS resolution (example.com) via ${health.primaryResolver}…`,
          tool: 'resolveRecord',
          status: health.externalProbe.success ? 'PASS' : 'FAIL',
          summary: health.externalProbe.success
            ? `Resolved example.com → ${health.externalProbe.records.join(', ')} via ${health.externalProbe.resolutionMethod} (${health.externalProbe.durationMs} ms)`
            : `External DNS lookup failed (${health.externalProbe.errorCode || health.externalProbe.error}) (${health.externalProbe.durationMs} ms)`,
          durationMs: health.externalProbe.durationMs
        }
      ];

      const findings = [
        { label: 'Configured Resolvers', value: health.configuredServers.join(', ') || health.primaryResolver, tone: 'neutral' },
        { label: 'DNS Health', value: health.healthy ? 'HEALTHY' : (health.localOnlyHealthy ? 'LOCAL ONLY (External Degraded)' : 'FAILED'), tone: health.healthy ? 'ok' : 'warn' },
        { label: 'example.com (A)', value: health.externalProbe.success ? `${health.externalProbe.records[0]} (${health.externalProbe.durationMs} ms)` : `FAILED (${health.externalProbe.errorCode})`, tone: health.externalProbe.success ? 'ok' : 'danger' }
      ];

      const structuredAnswer = {
        result: `System DNS health check completed in ${totalMs} ms (Configured DNS: [${health.configuredServers.join(', ') || health.primaryResolver}]): localhost → ${(health.localhostProbe.records || [])[0] || '127.0.0.1'} (${health.localhostProbe.resolutionMethod}); example.com → ${health.externalProbe.success ? `${health.externalProbe.records[0]} (${health.externalProbe.durationMs} ms via ${health.externalProbe.resolutionMethod})` : `FAILED (${health.externalProbe.errorCode})`}.`,
        meaning: health.healthy
          ? `Your local DNS configuration and upstream resolver (${health.primaryResolver}) are healthy and resolving external domains cleanly.`
          : `Local hosts resolution works, but external recursive resolution via ${health.primaryResolver} failed or timed out.`,
        nextStep: `Ask "Check DNS for <hostname>" to query a specific domain or "Check my IP" to inspect full network adapter settings.`,
        layerFailedFirst: health.healthy ? null : 'L7 External Recursive DNS',
        uncertainty: null
      };

      const reply =
        `**Result:** ${structuredAnswer.result}\n\n` +
        `**Meaning:** ${structuredAnswer.meaning}\n\n` +
        `**Next step:** ${structuredAnswer.nextStep}`;

      return {
        reply,
        structuredAnswer,
        steps,
        findings,
        technicalEvidence: health
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
    const activeResolver = dnsRes.nameserver || getRealSystemDns();

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

      structuredAnswer = {
        result: `DNS ${recordType} lookup for ${target} succeeded in ${dnsRes.durationMs} ms via resolver ${activeResolver} (method: ${resolutionMethod}), returning: ${recordsList.join(', ')}.`,
        meaning: `The domain name ${target} is properly published in DNS and resolves to ${recordsList.join(', ')}. Name resolution is healthy.`,
        nextStep: `To verify service reachability on ${target}, test a TCP port next (for example: "Now test port 443 on the same host").`,
        layerFailedFirst: null,
        uncertainty: null
      };
      reply =
        `**Result:** DNS ${recordType} lookup for \`${target}\` succeeded in **${dnsRes.durationMs} ms** via \`${activeResolver}\` (\`${resolutionMethod}\`) → \`${recordsList.join(', ')}\`.\n\n` +
        `**Meaning:** ${structuredAnswer.meaning}\n\n` +
        `**Next step:** ${structuredAnswer.nextStep}`;
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
      let failureExplanation = `The DNS query for "${target}" failed with ${errCode}.`;
      if (errCode.includes('ENOTFOUND') || errCode.includes('NXDOMAIN')) {
        failureExplanation = `The DNS resolver (${activeResolver}) reported that "${target}" does not exist (NXDOMAIN / ENOTFOUND). No IP address was returned or fabricated.`;
      } else if (errCode.includes('ENODATA')) {
        failureExplanation = `The domain "${target}" exists in DNS, but has no ${recordType} records published (ENODATA).`;
      } else if (errCode.includes('ETIMEOUT')) {
        failureExplanation = `The DNS query to resolver ${activeResolver} timed out (ETIMEOUT) without a response.`;
      } else if (errCode.includes('ESERVFAIL')) {
        failureExplanation = `The upstream DNS server returned SERVFAIL (ESERVFAIL) while attempting to resolve "${target}".`;
      }

      structuredAnswer = {
        result: `DNS ${recordType} resolution for ${target} failed with ${errCode} in ${dnsRes.durationMs} ms (resolver: ${activeResolver}, method: ${resolutionMethod}).`,
        meaning: failureExplanation,
        nextStep: typoCheck
          ? `Did you mean "${typoCheck.corrected}"? Try asking "Check DNS for ${typoCheck.corrected}".`
          : `Verify the spelling of "${target}" or run "Check DNS connectivity" to verify whether your local DNS resolver is healthy.`,
        layerFailedFirst: `L7 DNS Resolution (${errCode})`,
        uncertainty: null
      };
      reply =
        `**Result:** DNS ${recordType} lookup for \`${target}\` failed with **${errCode}** (${dnsRes.durationMs} ms via \`${activeResolver}\`).\n\n` +
        `**Meaning:** ${structuredAnswer.meaning}\n\n` +
        `**Next step:** ${structuredAnswer.nextStep}`;
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
      const durationMs = Number((performance.now() - stepStart).toFixed(1));
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
        reply: `**Result:** ${structuredAnswer.result}\n\n**Meaning:** ${structuredAnswer.meaning}\n\n**Next step:** ${structuredAnswer.nextStep}`,
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

    // Run ICMP Ping and supplementary TCP port check in parallel, keeping their outcomes strictly distinct (Part V, Section 7)
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
        dnsStatus: 'OK',
        pingRttMs: pingRes.avgRttMs,
        pingLossPct: 0,
        icmpStatus: 'REACHABLE',
        openPorts: tcpProbeRes.status === 'OPEN' ? [fallbackPort] : [],
        summary: `ICMP ping succeeded (${pingRes.packetsReceived}/${pingRes.packetsSent} received, ${pingRes.avgRttMs}ms avg RTT, 0% loss)`
      });

      structuredAnswer = {
        result: `ICMP ping to ${target} (${probeHost}) succeeded: ${pingRes.packetsReceived}/${pingRes.packetsSent} packets received (0% packet loss), min/avg/max RTT = ${pingRes.minRttMs}/${pingRes.avgRttMs}/${pingRes.maxRttMs} ms (jitter ${pingRes.jitterMs} ms).`,
        meaning: `Layer 3 ICMP echo reachability to ${target} is verified and healthy with zero packet loss.`,
        nextStep: `To verify application-layer listeners on ${target}, test a specific TCP port (for example: "Now test port ${fallbackPort} on the same host").`,
        layerFailedFirst: null,
        uncertainty: null
      };
      reply =
        `**Result:** ICMP ping to \`${target}\` (\`${probeHost}\`) succeeded — **${pingRes.packetsReceived}/${pingRes.packetsSent} packets received** (0% loss) with min/avg/max RTT of **${pingRes.minRttMs} / ${pingRes.avgRttMs} / ${pingRes.maxRttMs} ms** (jitter ${pingRes.jitterMs} ms).\n\n` +
        `**Meaning:** ${structuredAnswer.meaning}\n\n` +
        `**Next step:** ${structuredAnswer.nextStep}`;
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
        `**Result:** Partial ICMP response from \`${target}\` (\`${probeHost}\`) — **${pingRes.packetLossPct}% packet loss** (${pingRes.packetsReceived}/${pingRes.packetsSent} received, avg RTT **${pingRes.avgRttMs} ms**).\n\n` +
        `**Meaning:** ${structuredAnswer.meaning}\n\n` +
        `**Next step:** ${structuredAnswer.nextStep}`;
      findings = [
        { label: 'Target', value: `${target} (${probeHost})`, tone: 'neutral' },
        { label: 'ICMP Loss', value: `${pingRes.packetLossPct}% (${pingRes.packetsReceived}/${pingRes.packetsSent})`, tone: 'warn' },
        { label: 'Avg RTT', value: `${pingRes.avgRttMs} ms`, tone: 'warn' }
      ];
    } else if (tcpProbeRes && (tcpProbeRes.status === 'OPEN' || tcpProbeRes.status === 'CLOSED')) {
      // Case F: ICMP failed/was restricted in the sandbox/firewall, while a separate TCP check succeeded.
      // CRITICAL: Never fabricate a successful ICMP ping from a TCP handshake — report both distinctly!
      const tcpRtt = tcpProbeRes.connectLatencyMs ?? tcpProbeRes.latencyMs ?? durationMs;
      steps.push({
        stepNumber: 2,
        label: `Running separate TCP reachability check on ${probeHost}:${fallbackPort}…`,
        tool: 'checkPort',
        status: 'PASS',
        summary: `Separate TCP probe to ${probeHost}:${fallbackPort} succeeded (${tcpProbeRes.status}, handshake RTT: ${tcpRtt} ms)`,
        durationMs: tcpRtt
      });

      this._recordEntityMemory(session, target, {
        intent: 'ping',
        success: true,
        resolvedIps: [probeHost],
        dnsStatus: 'OK',
        pingRttMs: null,
        pingLossPct: 100,
        icmpStatus: 'NO_REPLY_ICMP_RESTRICTED',
        openPorts: tcpProbeRes.status === 'OPEN' ? [fallbackPort] : [],
        closedPorts: tcpProbeRes.status === 'CLOSED' ? [fallbackPort] : [],
        portLatencies: { [fallbackPort]: tcpRtt },
        summary: `ICMP ping received 0/${pingRes.packetsSent} replies (restricted/filtered); separate TCP :${fallbackPort} check is ${tcpProbeRes.status} (${tcpRtt}ms)`
      });

      structuredAnswer = {
        result: `ICMP ping to ${target} (${probeHost}) received 0/${pingRes.packetsSent} echo replies (100% ICMP loss — ICMP is filtered or restricted in this container/network environment). Separately, a direct TCP connection check to ${probeHost}:${fallbackPort} succeeded (${tcpProbeRes.status} in ${tcpRtt} ms).`,
        meaning: `Ping (ICMP Echo) and TCP are distinct protocols: ICMP echo did not receive a reply because the container sandbox or remote firewall blocks raw ICMP, but the separate TCP handshake on port ${fallbackPort} proves that ${target} (${probeHost}) is online and reachable over TCP.`,
        nextStep: `Use TCP or HTTPS checks to evaluate services on ${target} (for example: "Check whether https://${target} is working" or "Now test port 80 on the same host").`,
        layerFailedFirst: 'L3 ICMP Echo (Filtered/Restricted; TCP Reachable)',
        uncertainty: null
      };
      reply =
        `**Result:** **ICMP ping** to \`${target}\` (\`${probeHost}\`) received **0/${pingRes.packetsSent} echo replies** (100% ICMP loss — ICMP is restricted or filtered). **Separately**, a TCP connection test to \`${probeHost}:${fallbackPort}\` succeeded (**${tcpProbeRes.status}**, **${tcpRtt} ms**).\n\n` +
        `**Meaning:** ${structuredAnswer.meaning}\n\n` +
        `**Next step:** ${structuredAnswer.nextStep}`;
      findings = [
        { label: 'Target', value: `${target} (${probeHost})`, tone: 'neutral' },
        { label: 'ICMP Ping Result', value: `0/${pingRes.packetsSent} Replies (Restricted / Filtered)`, tone: 'warn' },
        { label: `Separate TCP :${fallbackPort}`, value: `${tcpProbeRes.status} (${tcpRtt} ms)`, tone: 'ok' }
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
        nextStep: `Test a specific TCP port where an application is expected to listen (for example: "Now test port 80 on the same host").`,
        layerFailedFirst: 'L3 ICMP Reachability',
        uncertainty: 'An ICMP timeout alone cannot distinguish between an offline host and a firewall silently dropping packets.'
      };
      reply =
        `**Result:** No ICMP ping reply from \`${target}\` (\`${probeHost}\`) — **100% packet loss** (${pingRes.packetsSent} sent, 0 received).\n\n` +
        `**Meaning:** ${structuredAnswer.meaning}\n\n` +
        `**Next step:** ${structuredAnswer.nextStep}`;
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
        reply: `**Result:** ${structuredAnswer.result}\n\n**Meaning:** ${structuredAnswer.meaning}\n\n**Next step:** ${structuredAnswer.nextStep}`,
        structuredAnswer,
        steps: [
          {
            stepNumber: 1,
            label: `Resolving ${target}…`,
            tool: 'resolveRecord',
            status: 'FAIL',
            summary: `DNS resolution failed for ${target} (ENOTFOUND)`,
            durationMs: 1.5
          }
        ],
        findings: [
          { label: 'Target', value: target, tone: 'neutral' },
          { label: 'DNS Status', value: 'FAILED (ENOTFOUND)', tone: 'danger' }
        ],
        technicalEvidence: { target, error: 'DNS_RESOLUTION_FAILED', observedAt: new Date().toISOString() }
      };
    }

    const probeHost = target.toLowerCase() === 'localhost' ? '127.0.0.1' : (plan.targetValidation?.pinnedIp || target);
    const ports = Array.isArray(plan.ports) && plan.ports.length > 0 ? plan.ports : [443];

    const steps = [];
    const results = [];
    const findings = [{ label: 'Target', value: `${target}${probeHost !== target ? ` (${probeHost})` : ''}`, tone: 'neutral' }];
    const evidenceIds = [];

    for (let i = 0; i < ports.length; i++) {
      this._checkAborted(signal);
      const port = ports[i];
      const stepStart = performance.now();
      const rawRes = await checkPort(probeHost, port, 1800);
      const durationMs = Number((performance.now() - stepStart).toFixed(1));
      const measuredLatencyMs = rawRes.connectLatencyMs ?? rawRes.latencyMs ?? durationMs;
      const res = { ...rawRes, latencyMs: measuredLatencyMs };
      results.push(res);

      const ev = evidenceFabric.recordEvidence({
        type: 'observation',
        subject: `tcp:${probeHost}:${port}`,
        claim: `TCP connect to ${target} (${probeHost}:${port}) returned ${res.status} (${res.latencyMs}ms)`,
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
          ? `Port ${port} is OPEN (3-way handshake RTT: ${res.latencyMs} ms)`
          : `Port ${port} is ${res.status} (${res.errorCode || res.error || 'No listener'})`,
        durationMs
      });

      findings.push({
        label: `TCP Port ${port}`,
        value: res.status === 'OPEN'
          ? `OPEN (${res.latencyMs} ms)`
          : `${res.status}${res.errorCode ? ` (${res.errorCode})` : ''}`,
        tone: res.status === 'OPEN' ? 'ok' : (res.status === 'CLOSED' ? 'danger' : 'warn')
      });
    }

    const openPorts = results.filter((r) => r.status === 'OPEN');
    const closedPorts = results.filter((r) => r.status === 'CLOSED');
    const filteredPorts = results.filter((r) => r.status === 'FILTERED');

    const portLatencies = {};
    for (const r of results) {
      portLatencies[r.port] = r.latencyMs;
    }
    this._recordEntityMemory(session, target, {
      intent: 'port_check',
      success: openPorts.length > 0,
      resolvedIps: [probeHost],
      openPorts: openPorts.map((r) => r.port),
      closedPorts: closedPorts.map((r) => r.port),
      filteredPorts: filteredPorts.map((r) => r.port),
      portLatencies,
      summary: `TCP ports tested: ${results.map((r) => `${r.port}=${r.status} (${r.latencyMs}ms)`).join(', ')}`
    });

    let structuredAnswer;
    let reply;

    if (results.length === 1) {
      const r = results[0];
      if (r.status === 'OPEN') {
        structuredAnswer = {
          result: `TCP port ${r.port} on ${target} (${probeHost}) is OPEN and completed a 3-way handshake in ${r.latencyMs} ms.`,
          meaning: `The host is reachable on the network and a process is actively listening and accepting TCP connections on port ${r.port}. Note that TCP port openness confirms transport connectivity, not full application-layer health.`,
          nextStep: (r.port === 443 || r.port === 80 || r.port === 3000 || r.port === 8080 || r.port === 8443)
            ? `To verify application-layer HTTP/TLS health on port ${r.port}, ask "Check whether http${r.port === 443 || r.port === 8443 ? 's' : ''}://${target}${r.port !== 80 && r.port !== 443 ? `:${r.port}` : ''} is working".`
            : `Transport connectivity to port ${r.port} is verified. Check application logs or protocol authentication if clients report errors.`,
          layerFailedFirst: null,
          uncertainty: null
        };
      } else if (r.status === 'CLOSED') {
        structuredAnswer = {
          result: `TCP port ${r.port} on ${target} (${probeHost}) is CLOSED (connection actively refused with TCP RST / ECONNREFUSED in ${r.latencyMs} ms).`,
          meaning: `The host ${target} is online and reachable across the network, and no firewall silently dropped the packet — however, no application process is listening on TCP port ${r.port}.`,
          nextStep: `Verify that the service expected on port ${r.port} is running and bound to ${probeHost}:${r.port}, or test an alternative port (e.g., "Try ${r.port === 443 ? 80 : 443} too").`,
          layerFailedFirst: `L4 TCP Application Listener (Port ${r.port} Refused / ECONNREFUSED)`,
          uncertainty: null
        };
      } else if (r.status === 'FILTERED') {
        structuredAnswer = {
          result: `TCP connection to port ${r.port} on ${target} (${probeHost}) timed out with no response (FILTERED / ETIMEDOUT).`,
          meaning: `The TCP SYN packet received neither a SYN-ACK nor a TCP RST within the timeout window. Either a firewall/security group is silently dropping traffic to port ${r.port}, or the host itself is unreachable.`,
          nextStep: `Test another port on the same host (e.g., "Try ${r.port === 443 ? 80 : 443} too") or check DNS and host reachability ("Ping ${target}").`,
          layerFailedFirst: `L3/L4 Network Path or Firewall (Port ${r.port} Timeout / ETIMEDOUT)`,
          uncertainty: 'A silent TCP timeout cannot distinguish between a firewall drop and an offline host without comparing against another open port or ARP/ICMP response.'
        };
      } else {
        structuredAnswer = {
          result: `TCP check on ${target}:${r.port} returned ${r.status} (${r.errorCode || r.error || 'Error'}).`,
          meaning: `The operating system could not establish a route or socket connection to ${target}:${r.port}.`,
          nextStep: `Check DNS resolution and local routing table for ${target}.`,
          layerFailedFirst: 'L3/L4 Socket Initiation',
          uncertainty: null
        };
      }

      reply =
        `**Result:** ${structuredAnswer.result}\n\n` +
        `**Meaning:** ${structuredAnswer.meaning}\n\n` +
        `**Next step:** ${structuredAnswer.nextStep}`;
    } else {
      const summaryParts = results.map((r) =>
        `Port **${r.port}** is **${r.status}**${r.status === 'OPEN' ? ` (${r.latencyMs} ms)` : (r.errorCode ? ` (${r.errorCode})` : '')}`
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
          ? `Focus troubleshooting on the closed/filtered service listeners (${closedPorts.concat(filteredPorts).map((p) => p.port).join(', ') || 'none'}) or inspect HTTP status on open port ${openPorts[0].port}.`
          : `Verify which port the service is configured to listen on, or run a full multi-step investigation on ${target}.`,
        layerFailedFirst: openPorts.length === results.length ? null : 'L4 TCP Port Listener',
        uncertainty: null
      };
      reply =
        `**Result:** On \`${target}\` (\`${probeHost}\`): ${summaryParts.join('; ')}.\n\n` +
        `**Meaning:** ${structuredAnswer.meaning}\n\n` +
        `**Next step:** ${structuredAnswer.nextStep}`;
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

    // Step 1: DNS Resolution
    const t0 = performance.now();
    let dnsRes;
    let resolvedIp = plan.targetValidation?.pinnedIp || (target === 'localhost' ? '127.0.0.1' : target);
    const isIpLiteral = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(target) || target === 'localhost';

    if (!isIpLiteral) {
      if (plan.targetValidation?.valid && plan.targetValidation.pinnedIp) {
        resolvedIp = plan.targetValidation.pinnedIp;
        dnsRes = {
          success: true,
          records: plan.targetValidation.resolvedIps,
          durationMs: Number((performance.now() - t0).toFixed(2)),
          resolutionMethod: 'dns_protocol'
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
          ? `Resolved ${target} → ${resolvedIp} (${dnsRes.durationMs} ms)`
          : `DNS resolution failed: ${dnsRes.errorCode || dnsRes.error || 'ENOTFOUND'}`,
        durationMs: Number((performance.now() - t0).toFixed(1))
      });
    } else {
      dnsRes = { success: true, records: [resolvedIp], durationMs: 0.4, resolutionMethod: 'local_hosts_table' };
      steps.push({
        stepNumber: 1,
        label: `Validating target address ${target}…`,
        tool: 'resolveRecord',
        status: 'PASS',
        summary: `Target ${target} maps to ${resolvedIp}`,
        durationMs: 0.5
      });
    }

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
        reply: `**Result:** ${structuredAnswer.result}\n\n**Meaning:** ${structuredAnswer.meaning}\n\n**Next step:** ${structuredAnswer.nextStep}`,
        structuredAnswer,
        steps,
        findings,
        technicalEvidence: { url: urlToProbe, dns: dnsRes, observedAt: new Date().toISOString() }
      };
    }
    findings.push({ label: 'DNS', value: `${resolvedIp} (${dnsRes.durationMs} ms)`, tone: 'ok' });

    // Step 2: TCP Port Check
    this._checkAborted(signal);
    const t1 = performance.now();
    const rawTcpRes = await checkPort(resolvedIp, port, 2000);
    const tcpStepMs = Number((performance.now() - t1).toFixed(1));
    const tcpRes = { ...rawTcpRes, latencyMs: rawTcpRes.connectLatencyMs ?? rawTcpRes.latencyMs ?? tcpStepMs };
    steps.push({
      stepNumber: 2,
      label: `Testing TCP connection to ${resolvedIp}:${port}…`,
      tool: 'checkPort',
      status: tcpRes.status === 'OPEN' ? 'PASS' : 'FAIL',
      summary: tcpRes.status === 'OPEN'
        ? `TCP port ${port} is OPEN (${tcpRes.latencyMs} ms)`
        : `TCP port ${port} is ${tcpRes.status} (${tcpRes.errorCode || tcpRes.error || 'Unreachable'})`,
      durationMs: tcpStepMs
    });

    if (tcpRes.status !== 'OPEN') {
      findings.push({ label: `TCP :${port}`, value: `${tcpRes.status} (${tcpRes.errorCode || 'Failed'})`, tone: 'danger' });
      const structuredAnswer = {
        result: `DNS for ${target} resolved to ${resolvedIp}, but TCP port ${port} is ${tcpRes.status} (${tcpRes.errorCode || tcpRes.error || 'no response'}).`,
        meaning: tcpRes.status === 'CLOSED'
          ? `The server at ${resolvedIp} is reachable on the network, but the web server process on port ${port} is stopped or refusing connections.`
          : `Traffic to ${resolvedIp}:${port} timed out without a response, indicating a firewall block or outbound network restriction.`,
        nextStep: tcpRes.status === 'CLOSED'
          ? `Check whether the web server daemon (e.g., Nginx, Caddy, Node.js) is running and bound to port ${port}.`
          : `Verify firewall rules for port ${port} or test an alternate port such as ${port === 443 ? 80 : 3000}.`,
        layerFailedFirst: `L4 TCP Transport (Port ${port} ${tcpRes.status})`,
        uncertainty: null
      };
      return {
        reply: `**Result:** ${structuredAnswer.result}\n\n**Meaning:** ${structuredAnswer.meaning}\n\n**Next step:** ${structuredAnswer.nextStep}`,
        structuredAnswer,
        steps,
        findings,
        technicalEvidence: { url: urlToProbe, dns: dnsRes, tcp: tcpRes, observedAt: new Date().toISOString() }
      };
    }
    findings.push({ label: `TCP :${port}`, value: `OPEN (${tcpRes.latencyMs} ms)`, tone: 'ok' });

    // Step 3: TLS Audit (if HTTPS) — strictly aligned with src/protocols/tls-audit.js schema!
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
        stepNumber: 3,
        label: `Verifying TLS handshake and X.509 certificate on ${target}:${port}…`,
        tool: 'auditTls',
        status: tlsRes.success ? (tlsAuthorized ? 'PASS' : 'WARN') : 'FAIL',
        summary: tlsRes.success
          ? `${tlsRes.protocol || 'TLS'} (${tlsCipherName}) · Cert: ${certDaysStr} (${authStr})`
          : `TLS handshake failed: ${tlsRes.error || 'Handshake error'}`,
        durationMs: Number((performance.now() - t2).toFixed(1))
      });
      findings.push({
        label: 'TLS Security',
        value: tlsRes.success
          ? `${tlsRes.protocol || 'TLS'}${tlsDaysRemaining !== null ? ` (${tlsDaysRemaining}d left)` : ''}`
          : `FAILED (${tlsRes.error || 'Error'})`,
        tone: tlsRes.success ? (tlsAuthorized ? 'ok' : 'warn') : 'danger'
      });
    }

    // Step 4: HTTP Application Probe — strictly aligned with src/protocols/http-probe.js schema!
    this._checkAborted(signal);
    const t3 = performance.now();
    const httpRes = await probeHttp(urlToProbe, 'GET', 2500);
    const httpStepMs = Number((performance.now() - t3).toFixed(1));
    const ttfbMs = httpRes?.waterfall?.ttfbMs ?? httpRes?.ttfbMs ?? httpStepMs;
    const totalHttpMs = httpRes?.waterfall?.totalMs ?? httpRes?.totalTimeMs ?? httpStepMs;
    const redirectLocation = httpRes?.headers?.location || httpRes?.redirectLocation || null;
    const isRedirect = httpRes.statusCode >= 300 && httpRes.statusCode < 400;

    steps.push({
      stepNumber: isHttps ? 4 : 3,
      label: `Checking HTTP response from ${urlToProbe}…`,
      tool: 'probeHttp',
      status: httpRes.success ? 'PASS' : (httpRes.statusCode ? 'WARN' : 'FAIL'),
      summary: httpRes.statusCode
        ? `HTTP ${httpRes.statusCode} ${httpRes.statusMessage || ''}${isRedirect && redirectLocation ? ` → Redirects to ${redirectLocation}` : ''} (TTFB: ${ttfbMs} ms, total: ${totalHttpMs} ms)`
        : `HTTP request failed: ${httpRes.error || 'No HTTP response'}`,
      durationMs: httpStepMs
    });

    if (httpRes.statusCode) {
      findings.push({
        label: 'HTTP Status',
        value: `${httpRes.statusCode}${isRedirect ? ' Redirect' : ''} (${ttfbMs} ms TTFB)`,
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
      dnsStatus: 'OK',
      openPorts: [port],
      portLatencies: { [port]: tcpRes.latencyMs },
      httpStatus: httpRes.statusCode || 'FAILED',
      summary: `Website check ${urlToProbe}: HTTP ${httpRes.statusCode || 'FAILED'} (${ttfbMs}ms TTFB)`
    });

    let structuredAnswer;
    if (isRedirect) {
      structuredAnswer = {
        result: `${urlToProbe} is online and returned an HTTP ${httpRes.statusCode} redirection${redirectLocation ? ` to ${redirectLocation}` : ''} in ${ttfbMs} ms TTFB (DNS → ${resolvedIp}, TCP :${port} OPEN in ${tcpRes.latencyMs} ms${tlsRes?.success ? `, TLS ${tlsRes.protocol}` : ''}).`,
        meaning: `The web server is healthy and actively redirecting requests${redirectLocation ? ` to ${redirectLocation}` : ''}. An HTTP ${httpRes.statusCode} response is normal redirection behavior, not a server outage.`,
        nextStep: redirectLocation
          ? `If you want to verify the destination page directly, ask "Check whether ${redirectLocation} is working".`
          : 'No infrastructure fault detected.',
        layerFailedFirst: null,
        uncertainty: null
      };
    } else if (httpRes.statusCode && httpRes.statusCode < 300) {
      structuredAnswer = {
        result: `${urlToProbe} is online and working — DNS resolved to ${resolvedIp} (${dnsRes.durationMs} ms), TCP port ${port} is OPEN (${tcpRes.latencyMs} ms)${tlsRes?.success ? `, TLS negotiated ${tlsRes.protocol} (${tlsCipherName})` : ''}, and HTTP returned ${httpRes.statusCode} ${httpRes.statusMessage || 'OK'} in ${ttfbMs} ms TTFB.`,
        meaning: `Every layer from DNS and TCP transport through ${isHttps ? 'TLS encryption and ' : ''}HTTP application delivery is healthy.`,
        nextStep: `No infrastructure fault detected. If specific users still report issues, check browser caching or client-side DNS settings.`,
        layerFailedFirst: null,
        uncertainty: null
      };
    } else if (httpRes.statusCode && httpRes.statusCode >= 400 && httpRes.statusCode < 500) {
      structuredAnswer = {
        result: `Network, TCP${isHttps ? ', and TLS' : ''} connectivity to ${urlToProbe} succeeded, and the web server returned HTTP ${httpRes.statusCode} (${httpRes.statusMessage || 'Client/Auth Response'}) in ${ttfbMs} ms TTFB.`,
        meaning: `Infrastructure and web server listeners are online and responding, but the requested URL path requires authentication or was not found on the server (HTTP ${httpRes.statusCode}).`,
        nextStep: `Verify the URL path or authentication credentials required by ${urlToProbe}.`,
        layerFailedFirst: `L7 HTTP Status ${httpRes.statusCode}`,
        uncertainty: null
      };
    } else if (httpRes.statusCode && httpRes.statusCode >= 500) {
      structuredAnswer = {
        result: `Network and TCP connectivity to ${target}:${port} succeeded, but the web server returned HTTP ${httpRes.statusCode} (${httpRes.statusMessage || 'Server Error'}) in ${ttfbMs} ms TTFB.`,
        meaning: `DNS and network transport are healthy, so the fault is inside the backend web application or upstream reverse proxy.`,
        nextStep: `Inspect the application server error logs on ${target} for HTTP ${httpRes.statusCode} exceptions.`,
        layerFailedFirst: `L7 HTTP Application (HTTP ${httpRes.statusCode})`,
        uncertainty: null
      };
    } else if (tlsRes && !tlsRes.success) {
      structuredAnswer = {
        result: `DNS (${resolvedIp}) and TCP port ${port} (${tcpRes.latencyMs} ms) succeeded, but the TLS handshake failed (${tlsRes.error}).`,
        meaning: `The server is reachable at the transport layer, but HTTPS encryption negotiation failed (certificate mismatch, expired certificate, or non-TLS listener on port ${port}).`,
        nextStep: `Inspect the TLS certificate and SNI configuration on ${target}:${port}.`,
        layerFailedFirst: 'L6 TLS Handshake',
        uncertainty: null
      };
    } else {
      structuredAnswer = {
        result: `DNS (${resolvedIp}) and TCP port ${port} (${tcpRes.latencyMs} ms) succeeded, but HTTP returned ${httpRes.statusCode || httpRes.error || 'an error'}.`,
        meaning: `Network transport is open, but the HTTP response did not complete cleanly.`,
        nextStep: `Verify the HTTP route and application listener configuration on ${target}:${port}.`,
        layerFailedFirst: 'L7 HTTP Application',
        uncertainty: null
      };
    }

    const reply =
      `**Result:** ${structuredAnswer.result}\n\n` +
      `**Meaning:** ${structuredAnswer.meaning}\n\n` +
      `**Next step:** ${structuredAnswer.nextStep}`;

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

    const reply =
      `**Result:** ${structuredAnswer.result}\n\n` +
      `**Meaning:** ${structuredAnswer.meaning}\n\n` +
      `**Next step:** ${structuredAnswer.nextStep}`;

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
        summary: `Host ${tel.hostname}: CPU ${tel.cpuLoadPct}%, RAM ${tel.ramUsedPct}%, ${tel.sockets?.length || 0} kernel sockets, DNS ${tel.dnsProbe?.latencyMs}ms`,
        durationMs
      }
    ];

    const structuredAnswer = {
      result: `Local workstation "${tel.hostname}" (${tel.localIp}) is operating with ${tel.cpuLoadPct}% CPU load, ${tel.ramUsedPct}% RAM utilization (${tel.freeRamGb} GB free), ${tel.sockets?.length || 0} active kernel TCP sockets (${tel.socketStateCounts?.ESTABLISHED || 0} ESTABLISHED), live DNS lookup at ${tel.dnsProbe?.latencyMs} ms, and local TCP loopback RTT at ${tel.localTcpProbe?.rttMs} ms.`,
      meaning: tel.dnsProbe?.success && tel.localTcpProbe?.reachable
        ? 'Local host resources, DNS stub resolver, and kernel network stack are healthy and operating within normal thresholds.'
        : 'Local host telemetry detected degradation in either local DNS lookup or loopback socket responsiveness.',
      nextStep: 'Specify a remote hostname, IP address, or port to diagnose external connectivity.',
      layerFailedFirst: null,
      uncertainty: null
    };

    const reply =
      `**Result:** ${structuredAnswer.result}\n\n` +
      `**Meaning:** ${structuredAnswer.meaning}\n\n` +
      `**Next step:** ${structuredAnswer.nextStep}`;

    return {
      reply,
      structuredAnswer,
      steps,
      findings: [
        { label: 'Host', value: `${tel.hostname} (${tel.localIp})`, tone: 'neutral' },
        { label: 'CPU / RAM', value: `${tel.cpuLoadPct}% / ${tel.ramUsedPct}%`, tone: 'ok' },
        { label: 'Kernel Sockets', value: `${tel.sockets?.length || 0} (${tel.socketStateCounts?.ESTABLISHED || 0} ESTAB)`, tone: 'ok' },
        { label: 'Local DNS / TCP', value: `${tel.dnsProbe?.latencyMs} ms / ${tel.localTcpProbe?.rttMs} ms`, tone: 'ok' }
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
   */
  async _executeMultiStepInvestigation(plan, session, promptText, signal) {
    this._checkAborted(signal);
    const target = plan.target;
    const primaryPort = plan.ports[0] || (target === 'localhost' || target === '127.0.0.1' ? (Number(config.PORT) || 3000) : 443);
    const additionalPorts = plan.ports.slice(1);

    const wfResult = await crossLayerIncidentCorrelator.diagnoseUnreachableHostname(target, primaryPort, {
      pinnedIp: plan.targetValidation?.pinnedIp || null,
      resolvedIps: plan.targetValidation?.resolvedIps || null
    });

    this._checkAborted(signal);

    const steps = (wfResult.steps || []).map((s, idx) => ({
      stepNumber: idx + 1,
      label: `${s.layer}…`,
      tool: s.layer,
      status: s.status,
      summary: s.summary,
      durationMs: s.details?.connectLatencyMs || s.details?.latencyMs || s.details?.durationMs || s.details?.avgRttMs || s.details?.ttfbMs || 1.2
    }));

    const extraPortResults = [];
    for (const extraPort of additionalPorts.slice(0, 2)) {
      this._checkAborted(signal);
      if (wfResult.resolvedIp && !wfResult.steps?.some((s) => s.layer.includes('DNS') && s.status === 'FAIL')) {
        const tExtra = performance.now();
        const pRes = await checkPort(wfResult.resolvedIp, extraPort, 1500);
        extraPortResults.push(pRes);
        steps.push({
          stepNumber: steps.length + 1,
          label: `Comparing secondary TCP port ${extraPort} on ${wfResult.resolvedIp}…`,
          tool: 'checkPort',
          status: pRes.status === 'OPEN' ? 'PASS' : 'FAIL',
          summary: pRes.status === 'OPEN'
            ? `TCP port ${extraPort} is OPEN (${pRes.latencyMs} ms)`
            : `TCP port ${extraPort} is ${pRes.status} (${pRes.errorCode || 'Unreachable'})`,
          durationMs: Number((performance.now() - tExtra).toFixed(1))
        });
      }
    }

    const firstFailedStep = steps.find((s) => s.status === 'FAIL');
    const topHyp = wfResult.correlation?.topHypothesis;
    const dnsStep = (wfResult.steps || []).find((s) => s.layer.includes('DNS'));
    const tcpStep = (wfResult.steps || []).find((s) => s.layer.includes('TCP'));
    const icmpStep = (wfResult.steps || []).find((s) => s.layer.includes('ICMP'));
    const httpStep = (wfResult.steps || []).find((s) => s.layer.includes('HTTP'));
    const tcpRttMs = tcpStep?.details?.connectLatencyMs ?? tcpStep?.details?.latencyMs ?? '<1';

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
        value: tcpStep.status === 'PASS' ? `OPEN (${tcpRttMs} ms)` : (tcpStep.details?.status || 'FAILED'),
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
      resultText = `Multi-step investigation of "${target}" stopped at Layer 7 DNS resolution: ${dnsStep.summary}. Local NIC and default gateway checks passed.`;
      meaningText = `Your local network interface and default gateway are healthy, so the problem is isolated to DNS name resolution for "${target}". Without a resolved IP address, TCP and HTTP connections cannot start.`;
      nextStepText = `Check whether "${target}" is spelled correctly, verify its DNS A/AAAA records, or test with the server's direct IP address.`;
    } else if (tcpStep && tcpStep.status === 'FAIL') {
      const tcpStatus = tcpStep.details?.status || 'UNREACHABLE';
      const anyExtraOpen = extraPortResults.find((e) => e.status === 'OPEN');
      if (tcpStatus === 'CLOSED') {
        resultText = `DNS resolved "${target}" to ${wfResult.resolvedIp} and the host is reachable on the network, but TCP port ${primaryPort} actively refused the connection (ECONNREFUSED / TCP RST)${anyExtraOpen ? ` while port ${anyExtraOpen.port} is OPEN` : ''}.`;
        meaningText = `Network routing and DNS are working properly. The failure is isolated to Layer 4 on ${wfResult.resolvedIp}: no service process is listening on TCP port ${primaryPort}.`;
        nextStepText = `Start or restart the application daemon expected on port ${primaryPort} on ${target}${anyExtraOpen ? `, or connect via open port ${anyExtraOpen.port}` : ''}.`;
      } else {
        resultText = `DNS resolved "${target}" to ${wfResult.resolvedIp}, local NIC/gateway checks passed, but TCP connection attempts to port ${primaryPort} timed out (${tcpStatus})${icmpStep?.status === 'PASS' ? ' even though ICMP ping succeeded' : ''}.`;
        meaningText = icmpStep?.status === 'PASS'
          ? `Because ${wfResult.resolvedIp} replies to ICMP ping while TCP port ${primaryPort} times out, the host is online and a firewall or security group is silently dropping traffic to port ${primaryPort}.`
          : `Neither ICMP ping nor TCP port ${primaryPort} received a response from ${wfResult.resolvedIp}. Either the target device is powered off/disconnected, or an intermediate firewall is filtering all traffic to it.`;
        nextStepText = `Verify that ${target} (${wfResult.resolvedIp}) is powered on and inspect firewall rules permitting inbound TCP port ${primaryPort}.`;
        uncertaintyText = icmpStep?.status !== 'PASS'
          ? 'When both ICMP and TCP time out silently without a TCP RST, remote firewall filtering and an offline host produce identical wire symptoms.'
          : null;
      }
    } else {
      resultText = `All ${steps.length} diagnostic checks for ${target}:${primaryPort} passed — local NIC and gateway are healthy, DNS resolved to ${wfResult.resolvedIp}, and TCP port ${primaryPort} is OPEN (${tcpRttMs} ms)${httpStep?.details?.statusCode ? ` with HTTP ${httpStep.details.statusCode}` : ''}.`;
      meaningText = `DNS, network routing, and TCP service connectivity to ${target}:${primaryPort} are all operating normally.`;
      nextStepText = `If users still experience slowness or intermittent errors, test specific application endpoints or inspect server-side application logs.`;
    }

    const structuredAnswer = {
      result: resultText,
      meaning: meaningText,
      nextStep: nextStepText,
      layerFailedFirst,
      uncertainty: uncertaintyText,
      topHypothesis: topHyp ? { title: topHyp.title, probability: topHyp.posteriorProbability, status: topHyp.status } : null
    };

    const reply =
      `**Result:** ${resultText}\n\n` +
      `**Meaning:** ${meaningText}` +
      (uncertaintyText ? `\n\n**Note on uncertainty:** ${uncertaintyText}` : '') +
      `\n\n**Next step:** ${nextStepText}`;

    return {
      reply,
      structuredAnswer,
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
        uncertaintyPanel: wfResult.correlation?.uncertaintyPanel,
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Scenario F: Contextual Follow-Up Explanation, Historical Comparison & Incident Report (Case Q)
   */
  async _executeFollowUpExplanation(plan, session, promptText) {
    const prevAns = session.lastStructuredAnswer || {};
    const prevSteps = session.lastSteps || [];
    const prevTarget = session.lastValidTarget || session.lastTarget || 'localhost';
    const prevPorts = session.lastPorts || [];
    const lower = promptText.toLowerCase();
    const entities = Object.values(session.entityMemory || {});
    const targetEntity = session.entityMemory?.[prevTarget.toLowerCase()] || entities[entities.length - 1] || null;
    const observations = Array.isArray(targetEntity?.observations) ? targetEntity.observations : [];

    const firstFailed = prevSteps.find((s) => s.status === 'FAIL' || s.status === 'TIMEOUT');
    let reply;
    let reportMarkdown = null;

    if (lower.includes('compare the latest') || lower.includes('what changed since') || lower.includes('show me what changed')) {
      if (observations.length >= 2) {
        const latest = observations[observations.length - 1];
        const previous = observations[observations.length - 2];
        reply =
          `**Result (Historical Comparison for \`${targetEntity.target}\`):**\n` +
          `- **Previous Observation (${previous.observedAt}):** ${previous.summary || previous.intent}\n` +
          `- **Latest Observation (${latest.observedAt}):** ${latest.summary || latest.intent}\n\n` +
          `**Meaning:** Between ${previous.observedAt} and ${latest.observedAt}, \`${targetEntity.target}\` was tested ${observations.length} times in this session. ` +
          (latest.pingRttMs !== null && previous.pingRttMs !== null
            ? `Ping RTT changed from ${previous.pingRttMs} ms to ${latest.pingRttMs} ms.`
            : `Open ports currently verified: [${(targetEntity.openPorts || []).join(', ') || 'none'}]; closed ports: [${(targetEntity.closedPorts || []).join(', ') || 'none'}].`) +
          `\n\n**Next step:** Ask *"Repeat the same check"* to capture a fresh measurement point.`;
      } else {
        const single = observations[0];
        reply =
          `**Result (Observation History for \`${prevTarget}\`):** Only ${observations.length || 1} observation has been recorded so far${single ? ` at ${single.observedAt} (${single.summary})` : ''}.\n\n` +
          `**Meaning:** At least two diagnostic runs on \`${prevTarget}\` are needed to compute a before/after delta.\n\n` +
          `**Next step:** Run another check on \`${prevTarget}\` (e.g., *"Repeat the same check"*) and then ask to compare.`;
      }
    } else if (lower.includes('what have we tested') || lower.includes('what have we found') || lower.includes('show memory') || lower.includes('compare')) {
      const entityBullets = entities.length > 0
        ? entities.map((e) =>
            `- **\`${e.target}\`** (${e.resolvedIps.join(', ') || 'unresolved'}): checked ${e.checkCount}x (last at ${e.lastSeenAt}) · Open ports: [${e.openPorts.join(', ') || 'none'}] · Closed ports: [${e.closedPorts.join(', ') || 'none'}] · Latest: ${e.lastOutcomeSummary || 'N/A'}`
          ).join('\n')
        : `- **\`${prevTarget}\`**: ${prevAns.result || 'Tested in current session.'}`;
      reply =
        `**Result (Session Investigation Memory — ${entities.length || 1} Host(s) Tracked across ${session.turnCount || 1} Turn(s)):**\n${entityBullets}\n\n` +
        `**Meaning:** EJII records timestamped observations for every host, IP, port, and latency measurement in SQLite while keeping active working memory bounded.\n\n` +
        `**Next step:** Ask to re-test any host above or compare specific ports (e.g., *"Now test port 443 on ${prevTarget}"*).`;
    } else if (lower.includes('which layer failed')) {
      const layerName = prevAns.layerFailedFirst || (firstFailed ? firstFailed.label : 'None — all tested layers passed');
      reply =
        `**Result:** First failing layer on \`${prevTarget}\`: **${layerName}**.\n\n` +
        `**Meaning:** ${prevAns.meaning || 'The diagnostic checks evaluated each layer in sequence from local network and DNS up to TCP and HTTP.'}\n\n` +
        `**Next step:** ${prevAns.nextStep || `Run a targeted follow-up probe on ${prevTarget}.`}`;
    } else if (lower.includes('incident report') || lower.includes('summarize')) {
      const stepBullets = prevSteps.map((s) => `- **Step ${s.stepNumber} (${s.tool}):** ${s.status} — ${s.summary}`).join('\n');
      reportMarkdown =
        `# EJII Technical Diagnostic Summary\n` +
        `- **Target Investigated:** ${prevTarget}${prevPorts.length ? ` (Ports: ${prevPorts.join(', ')})` : ''}\n` +
        `- **Timestamp:** ${new Date().toISOString()}\n` +
        `- **First Failing Layer:** ${prevAns.layerFailedFirst || 'None (All tested layers passed)'}\n\n` +
        `## Checks Executed & Measured Evidence\n${stepBullets || '- Diagnostic check completed.'}\n\n` +
        `## Findings & Assessment\n- **Result:** ${prevAns.result || 'N/A'}\n- **Meaning:** ${prevAns.meaning || 'N/A'}\n` +
        (prevAns.uncertainty ? `- **Remaining Uncertainties:** ${prevAns.uncertainty}\n` : '') +
        `\n## Recommended Next Steps\n- ${prevAns.nextStep || 'Continue monitoring.'}`;

      reply =
        `**Result (Technical Incident Summary for \`${prevTarget}\`):** ${prevAns.result || 'Completed diagnostic checks.'}\n\n` +
        `**Checks Performed:**\n${stepBullets || '- Completed diagnostic probe.'}\n\n` +
        `**Meaning (Evidence-Backed Assessment):** ${prevAns.meaning || 'See step outcomes above.'}\n\n` +
        `**Next step:** ${prevAns.nextStep || 'Continue monitoring or test an alternate port.'}`;
    } else {
      reply =
        `**Result:** Regarding the previous check on \`${prevTarget}${prevPorts.length ? `:${prevPorts.join(',')}` : ''}\`: ${prevAns.result || 'Diagnostic completed.'}\n\n` +
        `**Meaning:** ${prevAns.meaning || 'The observed response reflects the live network and service state.'}\n\n` +
        `**Next step:** ${prevAns.nextStep || `Ask to test another port on ${prevTarget} if needed.`}`;
    }

    return {
      reply,
      structuredAnswer: prevAns,
      steps: [],
      reportMarkdown,
      findings: [
        { label: 'Context Target', value: prevTarget, tone: 'neutral' },
        { label: 'Hosts in Memory', value: String(Math.max(1, entities.length)), tone: 'ok' },
        { label: 'First Failing Layer', value: prevAns.layerFailedFirst || 'None (All Passed)', tone: prevAns.layerFailedFirst ? 'warn' : 'ok' }
      ],
      technicalEvidence: {
        lastToolResults: session.lastToolResults,
        entityMemory: session.entityMemory,
        targetHistory: session.targetHistory
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
        ? `Governed DNS resolver refresh and endpoint verification succeeded (Snapshot ${healRes.verification.preSnapshotId}). Post-check DNS latency: ${healRes.verification.afterMetrics?.liveDnsRttMs} ms, TCP latency: ${healRes.verification.afterMetrics?.liveTcpRttMs} ms.`
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

    const reply =
      `**Result:** ${structuredAnswer.result}\n\n` +
      `**Meaning:** ${structuredAnswer.meaning}\n\n` +
      `**Next step:** ${structuredAnswer.nextStep}`;

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
}

const chatOperatorService = new ChatOperatorService();

module.exports = {
  ChatOperatorService,
  chatOperatorService,
  detectDomainTypo,
  classifyDomainTypo
};
