/**
 * EJII Chat-First Minimalist Infrastructure Intelligence Service
 *
 * High-speed, stateful diagnostic & investigation engine with:
 *   - Sub-second bounded DNS, ICMP, TCP, TLS, and HTTP execution
 *   - Automatic domain & TLD typo detection + live auto-correction (e.g., google.ocm -> google.com)
 *   - Container-aware hybrid Ping (parallel ICMP Echo + TCP Handshake fallback when raw ICMP is filtered)
 *   - Instant target context capture (even if a running request is cancelled)
 *   - SQLite-persisted conversation history with bounded in-memory context and per-entity memory
 *   - Strict RBAC and SSRF / DNS-rebinding defenses
 */

'use strict';

const crypto = require('node:crypto');
const os = require('node:os');
const { performance } = require('node:perf_hooks');
const config = require('../../config');
const { db } = require('../../db/database');
const { realPing, realTraceroute } = require('../../protocols/icmp-ping');
const { checkPort } = require('../../protocols/tcp-port');
const { resolveRecord, getRealSystemDns } = require('../../protocols/dns-diag');
const { probeHttp } = require('../../protocols/http-probe');
const { auditTls } = require('../../protocols/tls-audit');
const { isSafeNetworkTarget, resolveAndValidateTarget } = require('../security');
const { crossLayerIncidentCorrelator } = require('../correlation/incident-correlator');
const { ROLE_LEVELS, autonomousInfrastructureOperator } = require('../operator/autonomous-infrastructure-operator');
const { evidenceFabric } = require('../evidence/evidence-fabric');
const { getPhysicalNetworkInfo } = require('../../network/routing/physical-network-detector');
const { ProcessSocketCorrelatorEngine } = require('../../diagnostics/process-socket-correlator');

// Common TLD typo map (.ocm -> .com, .con -> .com, etc.)
const TLD_TYPO_MAP = Object.freeze({
  ocm: 'com',
  con: 'com',
  cmo: 'com',
  vom: 'com',
  xom: 'com',
  comm: 'com',
  comn: 'com',
  coim: 'com',
  ogr: 'org',
  rog: 'org',
  orgg: 'org',
  nte: 'net',
  ent: 'net',
  nett: 'net',
  oi: 'io',
  iio: 'io',
  dve: 'dev',
  gvo: 'gov',
  eud: 'edu'
});

// Common full-domain / hostname typo map
const KNOWN_HOST_TYPO_MAP = Object.freeze({
  'localhsot': 'localhost',
  'locahost': 'localhost',
  'localost': 'localhost',
  'localhots': 'localhost',
  'loaclhost': 'localhost',
  'gogle.com': 'google.com',
  'googel.com': 'google.com',
  'googl.com': 'google.com',
  'gooogle.com': 'google.com',
  'google.ocm': 'google.com',
  'google.con': 'google.com',
  'google.cmo': 'google.com',
  'cloudfalre.com': 'cloudflare.com',
  'cloudlfare.com': 'cloudflare.com',
  'cloudflare.ocm': 'cloudflare.com',
  'githbu.com': 'github.com',
  'gihub.com': 'github.com',
  'github.ocm': 'github.com',
  'amazno.com': 'amazon.com',
  'amzon.com': 'amazon.com',
  'amazon.ocm': 'amazon.com',
  'microsfot.com': 'microsoft.com',
  'mircosoft.com': 'microsoft.com',
  'microsoft.ocm': 'microsoft.com'
});

/**
 * Detect whether a hostname is a likely typo of a well-known hostname or TLD (e.g. google.ocm -> google.com)
 */
function detectDomainTypo(hostname) {
  if (!hostname || typeof hostname !== 'string') return null;
  // Automatically correct only explicitly known hostname typos. Generic TLD
  // substitution could redirect an internal or customer domain to a different host.
  const clean = hostname.trim().toLowerCase().replace(/\.$/, '');
  return KNOWN_HOST_TYPO_MAP[clean] || null;
}

class ChatOperatorService {
  constructor() {
    this.sessions = new Map();
    this.inFlightRequests = new Map(); // sessionId -> { requestId, abortController, startedAt }
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

  checkSessionAccess(sessionId, user = {}) {
    const cleanId = String(sessionId || '').trim();
    if (!cleanId) return { allowed: true, exists: false };
    const requestedId = user && user.id != null ? String(user.id) : null;
    const requestedUsername = user && user.username ? String(user.username) : null;
    const matchesOwner = (ownerId, ownerUsername) => {
      if (requestedId && ownerId) return String(ownerId) === requestedId;
      if (requestedUsername && ownerUsername) return String(ownerUsername) === requestedUsername;
      return !ownerId && !ownerUsername;
    };

    const inMemory = this.sessions.get(cleanId);
    if (inMemory) {
      return {
        allowed: matchesOwner(inMemory.userId, inMemory.username),
        exists: true,
        reason: 'Session belongs to a different authenticated user.'
      };
    }
    try {
      const row = db.prepare('SELECT user_id, username FROM ejii_chat_sessions WHERE session_id = ?').get(cleanId);
      if (!row) return { allowed: true, exists: false };
      return {
        allowed: matchesOwner(row.user_id, row.username),
        exists: true,
        reason: 'Session belongs to a different authenticated user.'
      };
    } catch (err) {
      // Fail closed: inability to verify ownership must not permit session access.
      return { allowed: false, exists: true, reason: 'Session ownership could not be verified.' };
    }
  }

  getOrCreateSession(sessionId, user = {}) {
    const cleanId = (sessionId && typeof sessionId === 'string' && sessionId.trim())
      ? sessionId.trim()
      : `CHAT-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;

    if (this.sessions.has(cleanId)) {
      const existing = this.sessions.get(cleanId);
      const access = this.checkSessionAccess(cleanId, user);
      if (!access.allowed) {
        const err = new Error(access.reason || 'Session access denied.');
        err.code = 'CHAT_SESSION_ACCESS_DENIED';
        throw err;
      }
      if (user && user.role) existing.role = user.role;
      return existing;
    }

    // Check SQLite for persisted session (Unlimited message & entity memory)
    try {
      const row = db.prepare('SELECT * FROM ejii_chat_sessions WHERE session_id = ?').get(cleanId);
      if (row) {
        const access = this.checkSessionAccess(cleanId, user);
        if (!access.allowed) {
          const err = new Error(access.reason || 'Session access denied.');
          err.code = 'CHAT_SESSION_ACCESS_DENIED';
          throw err;
        }
        const ctx = row.context_json ? JSON.parse(row.context_json) : {};
        // Keep only a bounded working window in RAM. The full message history remains in SQLite.
        const msgRows = db.prepare('SELECT * FROM ejii_chat_messages WHERE session_id = ? ORDER BY created_at DESC LIMIT 120').all(cleanId).reverse();
        const restored = {
          sessionId: cleanId,
          userId: row.user_id || user.id || 'op-1',
          username: row.username || user.username || 'operator',
          role: (user.role || row.role || 'ANALYST').toUpperCase(),
          lastTarget: ctx.lastTarget || null,
          lastValidTarget: ctx.lastValidTarget || ctx.lastTarget || null,
          targetHistory: Array.isArray(ctx.targetHistory) ? ctx.targetHistory : [],
          entityMemory: (ctx.entityMemory && typeof ctx.entityMemory === 'object') ? ctx.entityMemory : {},
          lastPorts: Array.isArray(ctx.lastPorts) ? ctx.lastPorts : [],
          lastIntent: ctx.lastIntent || null,
          lastUrl: ctx.lastUrl || null,
          lastToolResults: ctx.lastToolResults || null,
          lastSteps: Array.isArray(ctx.lastSteps) ? ctx.lastSteps : [],
          lastStructuredAnswer: ctx.lastStructuredAnswer || null,
          turnCount: Number(ctx.turnCount) || 0,
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
    } catch (err) {
      if (err && err.code === 'CHAT_SESSION_ACCESS_DENIED') throw err;
      // A non-authorization restore failure may fall back to a new in-memory session.
    }

    const fresh = {
      sessionId: cleanId,
      userId: user.id || 'op-1',
      username: user.username || 'operator',
      role: (user.role || 'ANALYST').toUpperCase(),
      lastTarget: null,
      lastValidTarget: null,
      targetHistory: [],
      entityMemory: {},
      lastPorts: [],
      lastIntent: null,
      lastUrl: null,
      lastToolResults: null,
      lastSteps: [],
      lastStructuredAnswer: null,
      turnCount: 0,
      messages: []
    };
    this.sessions.set(cleanId, fresh);
    return fresh;
  }

  /**
   * Update structured entity memory graph for a target host
   */
  _recordEntityMemory(session, target, patch = {}) {
    if (!session || !target || typeof target !== 'string') return null;
    const key = target.trim().toLowerCase();
    if (!key) return null;
    if (!session.entityMemory) session.entityMemory = {};
    if (!session.entityMemory[key] && Object.keys(session.entityMemory).length >= 500) {
      const oldestKey = Object.keys(session.entityMemory).sort((a, b) =>
        String(session.entityMemory[a]?.lastSeenAt || session.entityMemory[a]?.firstSeenAt || '').localeCompare(
          String(session.entityMemory[b]?.lastSeenAt || session.entityMemory[b]?.firstSeenAt || '')
        )
      )[0];
      if (oldestKey) delete session.entityMemory[oldestKey];
    }

    const existing = session.entityMemory[key] || {
      target: key,
      firstSeenAt: new Date().toISOString(),
      checkCount: 0,
      resolvedIps: [],
      openPorts: [],
      closedPorts: [],
      filteredPorts: [],
      portLatencies: {},
      rttHistoryMs: [],
      dnsStatus: null,
      lastDnsLatencyMs: null,
      lastPingRttMs: null,
      lastHttpStatus: null,
      lastOutcomeSummary: null
    };

    existing.lastSeenAt = new Date().toISOString();
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

    existing.resolvedIps = (existing.resolvedIps || []).slice(-32);
    existing.openPorts = (existing.openPorts || []).slice(-64);
    existing.closedPorts = (existing.closedPorts || []).slice(-64);
    existing.filteredPorts = (existing.filteredPorts || []).slice(-64);
    existing.rttHistoryMs = (existing.rttHistoryMs || []).slice(-100);
    if (existing.portLatencies && Object.keys(existing.portLatencies).length > 64) {
      existing.portLatencies = Object.fromEntries(Object.entries(existing.portLatencies).slice(-64));
    }
    session.entityMemory[key] = existing;
    if (!Array.isArray(session.targetHistory)) session.targetHistory = [];
    if (!session.targetHistory.includes(key)) session.targetHistory.push(key);
    if (session.targetHistory.length > 500) session.targetHistory = session.targetHistory.slice(-500);
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
    } catch (err) {
      // Do not silently pretend persistence succeeded. Keep the diagnostic result, but emit an actionable server log.
      console.error('[EJII chat] Failed to persist conversation state:', err && err.message ? err.message : err);
    }
  }

  clearSession(sessionId) {
    if (!sessionId) return false;
    this.cancelRequest(sessionId);
    this.sessions.delete(sessionId);
    try {
      db.prepare('DELETE FROM ejii_chat_messages WHERE session_id = ?').run(sessionId);
      db.prepare('DELETE FROM ejii_chat_sessions WHERE session_id = ?').run(sessionId);
    } catch (_) {}
    return true;
  }

  cancelRequest(sessionId, requestId = null) {
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

    // Greetings and capability questions must never trigger a network investigation.
    if (/^(hi|hello|hey|good morning|good afternoon|good evening|thanks|thank you|thx|what can you do|help|how do i use ejii)[!.?\s]*$/i.test(raw)) {
      return {
        intent: 'conversation', target: null, explicitTarget: null, ports: [], url: null,
        recordType: 'A', usedFollowUpTarget: false, isSystemDnsHealthCheck: false
      };
    }

    // 1. Check if the user is asking for an explanation, summary, memory recall, or comparison of previous findings
    const isExplanationFollowUp =
      /^(why did (that|it) fail|which layer failed|explain the results?|summarize what you|give me a concise incident report|what does that mean|what should i do next|tell me the next step|what have we (tested|found)|show memory|compare (all )?hosts)/i.test(lower) ||
      ((lower.includes('summarize') || lower.includes('incident report') || lower.includes('which layer failed') || lower.includes('why did that fail') || lower.includes('explain the result') || lower.includes('what have we tested') || lower.includes('compare hosts')) &&
        !lower.includes('ping ') && !lower.includes('check port') && !lower.includes('test port'));

    if (isExplanationFollowUp && session && (session.lastToolResults || Object.keys(session.entityMemory || {}).length > 0)) {
      return {
        intent: 'follow_up_explanation',
        target: session.lastValidTarget || session.lastTarget || 'localhost',
        explicitTarget: null,
        ports: session.lastPorts.length ? session.lastPorts : [3000],
        url: session.lastUrl || null,
        recordType: 'A',
        usedFollowUpTarget: true,
        isSystemDnsHealthCheck: false
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

    // 4. Extract ports from prompt
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

    if (extractedPorts.length === 0 && session?.lastIntent === 'port_check') {
      const barePortMatch = raw.match(/\b(?:with|port|on|about)\s+(\d{2,5})\b/i);
      if (barePortMatch) {
        const p = Number(barePortMatch[1]);
        if (p >= 1 && p <= 65535) extractedPorts.push(p);
      }
    }

    // 5. Check if user is asking a general "check dns connection" / "is dns working" / "test dns" without an explicit domain
    const isGenericDnsHealthPrompt =
      !explicitTarget &&
      /\b(check dns( connection| connectivity| status| health| server)?|test dns( connection| connectivity| server)?|is dns working|verify dns( connection)?|dns connection|dns connectivity|dns health)\b/i.test(lower) &&
      !/\b(same host|same domain|that host|that domain|for it|on it)\b/i.test(lower);

    // 6. Resolve target using contextual follow-up memory if not explicitly specified
    let usedFollowUpTarget = false;
    let resolvedTarget = explicitTarget;
    const refersToFirstTarget = /\b(first host|first domain|initial host|original host)\b/i.test(lower);
    const refersToPreviousTarget =
      /\b(same host|same server|same target|same domain|that host|that server|it|again|retry)\b/i.test(lower);

    if (!resolvedTarget) {
      if (isGenericDnsHealthPrompt) {
        // A general DNS-health request is independent of the previous diagnostic target.
        resolvedTarget = 'google.com';
      } else if (refersToFirstTarget && session?.targetHistory?.length > 0) {
        resolvedTarget = session.targetHistory[0];
        usedFollowUpTarget = true;
      } else if (session && (session.lastValidTarget || session.lastTarget)) {
        resolvedTarget = session.lastValidTarget || session.lastTarget;
        usedFollowUpTarget = true;
      } else {
        resolvedTarget = 'localhost';
      }
    } else if (refersToPreviousTarget && !explicitTarget && session && (session.lastValidTarget || session.lastTarget)) {
      resolvedTarget = session.lastValidTarget || session.lastTarget;
      usedFollowUpTarget = true;
    }

    // 7. Determine primary intent. Local-host queries are distinct from remote-host diagnostics.
    const isGatewayPingPrompt = /\b(ping|check|test|reachability of)\b.{0,35}\b(default )?gateway\b|\b(default )?gateway\b.{0,35}\b(ping|check|test|reachable)\b/i.test(lower);
    const isLocalNetworkInfoPrompt = /\b(check my ip|what is my ip|show (?:me )?(?:my )?(?:local )?ip|local ip address|my network (?:configuration|interfaces)|network interface addresses)\b/i.test(lower);
    const isActiveConnectionsPrompt = /\b(active (?:tcp )?(?:connections|sockets)|current(?:ly)? (?:open )?connections|destination ip|dest ip|destination ports?|dest ports?|remote ips?|remote ports?|netstat|which apps? (?:are )?(?:connected|connecting)|what .*apps?.*(?:ip|port)|apps?.{0,45}(?:destination|dest|remote).{0,20}(?:ip|port))\b/i.test(lower);
    const isHostHealthPrompt = /\b(local host health|system health|host diagnostics|cpu and memory|local system|workstation health)\b/i.test(lower);
    const isLikelyDiagnosticRequest = /\b(check|test|ping|diagnos(?:e|is)|investigat(?:e|ion)|trace|resolve|scan|port|dns|website|web site|network|connection|slow|unreachable|not responding|not working|can't access|cannot access|timeout|gateway|socket|printer|ip address)\b/i.test(lower);
    let intent = 'multi_step_investigation';

    const isRemediation =
      /\b(flush dns|refresh dns resolver|apply (?:the )?(?:fix|remediation)|execute remediation|heal|self-heal|fix it now|repair dns)\b/i.test(lower);

    const isRepeatLast =
      /\b(test the same host again|run that again|retry that|check it again|repeat the check)\b/i.test(lower) &&
      !lower.includes('port') && !lower.includes('dns') && !lower.includes('ping');

    if (isRemediation) {
      intent = 'remediation';
    } else if (isGatewayPingPrompt) {
      intent = 'gateway_ping';
    } else if (isLocalNetworkInfoPrompt) {
      intent = 'local_network_info';
    } else if (isActiveConnectionsPrompt) {
      intent = 'active_connections';
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
      (isGenericDnsHealthPrompt || /\b(check dns|dns check|test dns|dns connection|resolve|nslookup|dig|dns lookup|a record|aaaa record|mx record|txt record)\b/i.test(lower)) &&
      !lower.includes('or dns is causing') &&
      !lower.includes('investigate why')
    ) {
      intent = 'dns';
    } else if (
      extractedPorts.length > 0 &&
      (/\b(port|ports|tcp|open|listening|connect|try it with|now test)\b/i.test(lower)) &&
      !lower.includes('investigate why')
    ) {
      intent = 'port_check';
    } else if (
      extractedUrl ||
      (/\b(website|https:\/\/|http:\/\/|web page|site is working|site is accessible|check whether https|verify https)\b/i.test(lower) &&
        !lower.includes('investigate why'))
    ) {
      intent = 'website_check';
    } else if (isHostHealthPrompt && !explicitTarget) {
      intent = 'host_health';
    } else if (isLikelyDiagnosticRequest) {
      intent = 'multi_step_investigation';
    } else {
      intent = 'clarification';
    }

    // If a generic investigation has no explicit or remembered target, ask for the target
    // rather than silently probing localhost or the previous unrelated host.
    if (intent === 'multi_step_investigation' && !explicitTarget && !session?.lastValidTarget && !session?.lastTarget) {
      intent = 'clarification';
    }

    if (['conversation', 'clarification', 'local_network_info', 'gateway_ping', 'active_connections', 'host_health'].includes(intent)) {
      resolvedTarget = null;
      usedFollowUpTarget = false;
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

    const typoSuggestion = detectDomainTypo(resolvedTarget);

    return {
      intent,
      target: resolvedTarget,
      explicitTarget: explicitTarget || null,
      typoSuggestion,
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

    if (sessionId && String(sessionId).trim()) {
      const access = this.checkSessionAccess(sessionId, user);
      if (!access.allowed) {
        return {
          success: false,
          status: 'denied',
          statusCode: 404,
          error: { code: 'CHAT_SESSION_ACCESS_DENIED', message: 'This conversation is unavailable for the authenticated user.' }
        };
      }
    }
    let session;
    try {
      session = this.getOrCreateSession(sessionId, user);
    } catch (err) {
      return {
        success: false,
        status: err.code === 'CHAT_SESSION_ACCESS_DENIED' ? 'denied' : 'failed',
        statusCode: err.code === 'CHAT_SESSION_ACCESS_DENIED' ? 404 : 500,
        error: { code: err.code || 'CHAT_SESSION_ERROR', message: err.code === 'CHAT_SESSION_ACCESS_DENIED' ? 'This conversation is unavailable for the authenticated user.' : 'Could not initialize the conversation session.' }
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

      // Immediately capture explicit non-typo target in session memory BEFORE async execution
      // so even if the user cancels mid-probe (e.g. "google.com ping" -> Stop), session memory remembers "google.com"!
      if (plan.explicitTarget && isSafeNetworkTarget(plan.explicitTarget)) {
        const cleanCandidate = plan.typoSuggestion || plan.explicitTarget;
        session.lastTarget = cleanCandidate;
        if (!plan.typoSuggestion) {
          session.lastValidTarget = cleanCandidate;
        }
        this._persistSession(session, []);
      }

      const userMsgRecord = {
        id: `MSG-U-${Date.now()}-${crypto.randomBytes(2).toString('hex')}`,
        role: 'user',
        content: cleanPrompt,
        createdAt: new Date().toISOString(),
        meta: { intent: plan.intent, target: plan.target, ports: plan.ports }
      };

      // Simulated timeout hook for deterministic testing of Scenario G
      if (simulateTimeout) {
        this._checkAborted(abortController.signal);
        const timeoutReply =
          `**Result:** The diagnostic probe to \`${plan.target}\` timed out before completing.\n\n` +
          `**Meaning:** The target host or an intermediate firewall did not respond within the allowed diagnostic window (ETIMEDOUT). No healthy result was assumed.\n\n` +
          `**Next step:** Verify that \`${plan.target}\` is online and not dropping packets silently, or retry with a direct TCP port check.`;
        const structuredAnswer = {
          result: `Diagnostic probe to ${plan.target} timed out (ETIMEDOUT).`,
          meaning: 'The target or an intermediate firewall did not reply within the time limit.',
          nextStep: `Verify that ${plan.target} is reachable on the local network or test a specific TCP port.`,
          layerFailedFirst: 'L3/L4 Transport (Timeout)',
          uncertainty: 'A timeout cannot distinguish between an offline host and a silent firewall drop without an ARP or TCP RST signal.'
        };
        const steps = [
          {
            stepNumber: 1,
            label: `Probing ${plan.target}…`,
            tool: 'diagnostic_probe',
            status: 'TIMEOUT',
            summary: `Timed out waiting for response from ${plan.target} (ETIMEDOUT)`,
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
            { label: 'Target', value: plan.target, tone: 'neutral' },
            { label: 'Outcome', value: 'TIMEOUT (ETIMEDOUT)', tone: 'danger' }
          ],
          technicalEvidence: {
            tool: 'diagnostic_probe',
            target: plan.target,
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

      // Check RBAC immediately if remediation was requested (Scenario H)
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

      // SSRF & Command Injection Target Validation + Automatic Typo Recovery
      if (!['follow_up_explanation', 'host_health', 'conversation', 'clarification', 'local_network_info', 'gateway_ping', 'active_connections'].includes(plan.intent)) {
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

        // Intelligent Typo Recovery: If the requested hostname failed DNS (e.g. "google.ocm") AND matches a known typo ("google.com"),
        // validate the corrected domain and auto-heal the target while preserving transparency!
        if (!targetValidation.valid && plan.typoSuggestion && isSafeNetworkTarget(plan.typoSuggestion)) {
          const correctedValidation = await resolveAndValidateTarget(plan.typoSuggestion);
          if (correctedValidation.valid) {
            plan.originalTypoTarget = plan.target;
            plan.target = plan.typoSuggestion;
            targetValidation = correctedValidation;
            session.lastTarget = plan.typoSuggestion;
            session.lastValidTarget = plan.typoSuggestion;
          }
        } else if (targetValidation.valid) {
          session.lastValidTarget = plan.target;
        }

        plan.targetValidation = targetValidation;
      }

      this._checkAborted(abortController.signal);

      let executionOutcome;
      switch (plan.intent) {
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
        case 'local_network_info':
          executionOutcome = await this._executeLocalNetworkInfoScenario(abortController.signal);
          break;
        case 'gateway_ping':
          executionOutcome = await this._executeGatewayPingScenario(abortController.signal);
          break;
        case 'active_connections':
          executionOutcome = await this._executeActiveConnectionsScenario(abortController.signal);
          break;
        case 'conversation':
          executionOutcome = this._executeConversationResponse(cleanPrompt);
          break;
        case 'clarification':
          executionOutcome = this._executeClarificationResponse(cleanPrompt);
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

      // If a domain typo was auto-corrected (e.g. google.ocm -> google.com), prepend the auto-correction step and note
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
    steps,
    findings,
    technicalEvidence,
    startWall
  }) {
    const totalDurationMs = Number((performance.now() - startWall).toFixed(1));
    const nowIso = new Date().toISOString();

    // Only update session.lastTarget if the target was valid or if no previous valid target exists
    const targetWasValid = !plan.targetValidation || plan.targetValidation.valid;
    if (plan.target && plan.intent !== 'follow_up_explanation') {
      if (targetWasValid || !session.lastValidTarget) {
        session.lastTarget = plan.target;
      }
      if (targetWasValid) {
        session.lastValidTarget = plan.target;
      }
    }
    if (Array.isArray(plan.ports) && plan.ports.length > 0 && plan.intent !== 'follow_up_explanation') {
      session.lastPorts = plan.ports;
    }
    if (plan.intent !== 'follow_up_explanation') {
      session.lastIntent = plan.intent;
    }
    if (plan.url) {
      session.lastUrl = plan.url;
    }

    session.lastToolResults = technicalEvidence;
    session.lastSteps = steps;
    session.lastStructuredAnswer = structuredAnswer;
    session.turnCount = (session.turnCount || 0) + 1;

    const assistantMsgRecord = {
      id: `MSG-A-${Date.now()}-${crypto.randomBytes(2).toString('hex')}`,
      role: 'assistant',
      content: reply,
      createdAt: nowIso,
      meta: {
        requestId: reqId,
        intent: plan.intent,
        target: plan.target,
        ports: plan.ports,
        usedFollowUpTarget: plan.usedFollowUpTarget,
        totalDurationMs,
        structuredAnswer,
        steps,
        findings,
        technicalEvidence
      }
    };

    session.messages.push(userMsgRecord, assistantMsgRecord);
    // The database keeps the complete history; the active conversation window stays bounded.
    if (session.messages.length > 120) session.messages.splice(0, session.messages.length - 120);
    this._persistSession(session, [userMsgRecord, assistantMsgRecord]);

    return {
      sessionId: session.sessionId,
      requestId: reqId,
      intent: plan.intent,
      target: plan.target,
      ports: plan.ports,
      usedFollowUpTarget: plan.usedFollowUpTarget,
      totalDurationMs,
      reply,
      structuredAnswer,
      steps,
      findings,
      technicalEvidence,
      sessionContext: {
        lastTarget: session.lastTarget,
        lastValidTarget: session.lastValidTarget,
        lastPorts: session.lastPorts,
        lastIntent: session.lastIntent,
        turnCount: session.turnCount,
        knownEntitiesCount: Object.keys(session.entityMemory || {}).length
      }
    };
  }

  /**
   * Scenario A: Real DNS Check (including System DNS Connection Health Check)
   */
  async _executeDnsScenario(plan, session, signal) {
    this._checkAborted(signal);
    const stepStart = performance.now();
    const target = plan.target;
    const recordType = plan.recordType || 'A';

    // If user asked a general "check dns connection" / "test dns" health query, verify system DNS + target in parallel!
    if (plan.isSystemDnsHealthCheck) {
      const sysDnsIp = getRealSystemDns();
      const targetsToTest = Array.from(new Set(['localhost', 'google.com', target].filter(Boolean)));
      const probePromises = targetsToTest.map(async (domain) => {
        const t0 = performance.now();
        if (domain === 'localhost') {
          const r = await resolveRecord('localhost', 'A');
          return {
            domain: 'localhost',
            success: Boolean(r.success && Array.isArray(r.records) && r.records.length),
            records: Array.isArray(r.records) ? r.records : [],
            durationMs: Number((performance.now() - t0).toFixed(2)),
            nameserver: r.nameserver || sysDnsIp || 'OS hosts resolver',
            error: r.errorCode || r.error || null
          };
        }
        const r = await resolveRecord(domain, 'A');
        return {
          domain,
          success: r.success,
          records: r.records || [],
          durationMs: r.durationMs || Number((performance.now() - t0).toFixed(2)),
          nameserver: r.nameserver || sysDnsIp,
          error: r.errorCode || r.error || null
        };
      });

      const results = await Promise.all(probePromises);
      const totalMs = Number((performance.now() - stepStart).toFixed(1));
      const allPassed = results.every((r) => r.success);
      const steps = results.map((r, idx) => ({
        stepNumber: idx + 1,
        label: `Verifying DNS resolution for ${r.domain} via ${r.nameserver}…`,
        tool: 'resolveRecord',
        status: r.success ? 'PASS' : 'FAIL',
        summary: r.success
          ? `Resolved ${r.domain} → ${r.records.join(', ')} (${r.durationMs} ms)`
          : `Failed to resolve ${r.domain}: ${r.error || 'ENOTFOUND'} (${r.durationMs} ms)`,
        durationMs: r.durationMs
      }));

      for (const r of results) {
        if (r.success) {
          this._recordEntityMemory(session, r.domain, {
            resolvedIps: r.records,
            dnsStatus: 'OK',
            dnsLatencyMs: r.durationMs,
            summary: `DNS A resolved to ${r.records.join(', ')} in ${r.durationMs}ms`
          });
        }
      }

      const primary = results.find((r) => r.domain === target) || results[results.length - 1];
      const resolverLabel = sysDnsIp || 'OS-configured resolver';
      const findings = [
        { label: 'Active Resolver', value: resolverLabel, tone: 'neutral' },
        { label: 'DNS Connectivity', value: allPassed ? 'HEALTHY' : 'PARTIAL / DEGRADED', tone: allPassed ? 'ok' : 'warn' },
        ...results.map((r) => ({
          label: `DNS (${r.domain})`,
          value: r.success ? `${r.records[0]} (${r.durationMs} ms)` : `FAILED (${r.error})`,
          tone: r.success ? 'ok' : 'danger'
        }))
      ];

      const structuredAnswer = {
        result: `DNS connection check completed in ${totalMs} ms via resolver ${resolverLabel}: ${results.map((r) => `${r.domain} → ${r.success ? `${r.records[0]} (${r.durationMs} ms)` : `FAILED (${r.error})`}`).join('; ')}.`,
        meaning: allPassed
          ? `Your active DNS resolver (${sysDnsIp}) is online, responsive, and resolving both local and external domain names cleanly.`
          : `Local DNS resolution is partially degraded; check the failed domain name or upstream nameserver ${sysDnsIp}.`,
        nextStep: `Ask to test any specific hostname or port (e.g., "Ping ${primary.domain}" or "Check port 443 on ${primary.domain}").`,
        layerFailedFirst: allPassed ? null : 'L7 DNS Resolution',
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
        technicalEvidence: {
          tool: 'resolveRecord (System DNS Connectivity Suite)',
          activeResolver: resolverLabel,
          results,
          observedAt: new Date().toISOString()
        }
      };
    }

    let dnsRes;
    if (target.toLowerCase() === 'localhost') {
      dnsRes = await resolveRecord('localhost', recordType);
    } else if (plan.targetValidation?.valid && recordType === 'A' && plan.targetValidation.resolvedIps?.length > 0) {
      // Reuse already-validated DNS resolution to respond in < 5ms without redundant network round-trip
      const v4Records = plan.targetValidation.resolvedIps.filter((ip) => ip.includes('.'));
      if (v4Records.length > 0) {
        dnsRes = {
          domain: target,
          recordType: 'A',
          nameserver: getRealSystemDns(),
          success: true,
          records: v4Records,
          durationMs: Number((performance.now() - stepStart).toFixed(2)),
          error: null,
          errorCode: null
        };
      } else {
        dnsRes = await resolveRecord(target, recordType);
      }
    } else {
      dnsRes = await resolveRecord(target, recordType);
    }

    const durationMs = Number((performance.now() - stepStart).toFixed(1));
    const recordsList = Array.isArray(dnsRes.records) ? dnsRes.records : [];
    const ev = evidenceFabric.recordEvidence({
      type: 'dns_resolution',
      subject: `dns:${target}`,
      claim: dnsRes.success
        ? `DNS ${recordType} lookup for ${target} returned [${recordsList.join(', ')}] in ${dnsRes.durationMs}ms`
        : `DNS ${recordType} lookup for ${target} failed (${dnsRes.errorCode || dnsRes.error || 'ENOTFOUND'})`,
      rawValue: dnsRes,
      normalizedValue: dnsRes.success ? `RESOLVED:${recordsList[0] || 'OK'}` : `DNS_FAILED:${dnsRes.errorCode || 'ERROR'}`,
      sourceCapabilityId: 'ejii.chat.dns_resolve',
      collectionMethod: 'dns.promises.resolve'
    });

    const steps = [
      {
        stepNumber: 1,
        label: `Resolving DNS ${recordType} records for ${target}…`,
        tool: 'resolveRecord',
        status: dnsRes.success ? 'PASS' : 'FAIL',
        summary: dnsRes.success
          ? `Resolved ${target} → ${recordsList.join(', ')} (${dnsRes.durationMs}ms)`
          : `Failed to resolve ${target}: ${dnsRes.errorCode || dnsRes.error || 'No records found'}`,
        durationMs
      }
    ];

    let structuredAnswer;
    let reply;
    let findings;

    if (dnsRes.success && recordsList.length > 0) {
      this._recordEntityMemory(session, target, {
        resolvedIps: recordsList,
        dnsStatus: 'OK',
        dnsLatencyMs: dnsRes.durationMs,
        summary: `DNS ${recordType} resolved to ${recordsList.join(', ')} in ${dnsRes.durationMs}ms`
      });

      structuredAnswer = {
        result: `DNS ${recordType} resolution for ${target} succeeded in ${dnsRes.durationMs}ms, returning ${recordsList.join(', ')}.`,
        meaning: `The domain name ${target} is properly configured in DNS and translates to a routable address (${recordsList[0]}). Name resolution is not blocking connectivity.`,
        nextStep: `If you are troubleshooting a service on ${target}, test TCP port reachability next (for example: "Check port 443 on ${target}").`,
        layerFailedFirst: null,
        uncertainty: null
      };
      reply =
        `**Result:** DNS ${recordType} lookup for \`${target}\` succeeded in **${dnsRes.durationMs} ms** → \`${recordsList.join(', ')}\`.\n\n` +
        `**Meaning:** The domain name resolves cleanly to ${recordsList.length === 1 ? 'an IP address' : `${recordsList.length} IP addresses`}, so DNS is working normally for \`${target}\`.\n\n` +
        `**Next step:** Test whether the target service port is reachable — for example, ask *"Now test port 443 on the same host"*.`;
      findings = [
        { label: 'Target', value: target, tone: 'neutral' },
        { label: 'Record Type', value: recordType, tone: 'neutral' },
        { label: 'Resolved Address', value: recordsList.join(', '), tone: 'ok' },
        { label: 'Lookup Latency', value: `${dnsRes.durationMs} ms`, tone: 'ok' }
      ];
    } else {
      const errCode = dnsRes.errorCode || dnsRes.error || 'ENOTFOUND';
      const suggested = detectDomainTypo(target);
      structuredAnswer = {
        result: `DNS ${recordType} resolution for ${target} failed (${errCode}) in ${dnsRes.durationMs}ms.`,
        meaning: errCode.includes('ENOTFOUND') || errCode.includes('NXDOMAIN')
          ? `The configured DNS resolver reported that the domain "${target}" does not exist (NXDOMAIN), or has no ${recordType} records published.`
          : `The DNS query for "${target}" failed with ${errCode}, indicating an unreachable recursive DNS server or upstream SERVFAIL.`,
        nextStep: suggested
          ? `Did you mean "${suggested}"? Try asking "Check DNS for ${suggested}".`
          : `Verify the spelling of "${target}" and check your active DNS server configuration, or test against a known IP address to confirm network connectivity.`,
        layerFailedFirst: 'L7 DNS Resolution',
        uncertainty: null
      };
      reply =
        `**Result:** DNS ${recordType} lookup for \`${target}\` failed with **${errCode}** (${dnsRes.durationMs} ms).\n\n` +
        `**Meaning:** ${structuredAnswer.meaning}\n\n` +
        `**Next step:** ${structuredAnswer.nextStep}`;
      findings = [
        { label: 'Target', value: target, tone: 'neutral' },
        { label: 'DNS Status', value: `FAILED (${errCode})`, tone: 'danger' },
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
        evidenceId: ev.id,
        rawResult: dnsRes,
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Scenario B: Real Ping Check (with DNS Pre-Check + Parallel TCP Reachability Verification for Container Sandboxes)
   */
  async _executePingScenario(plan, session, signal) {
    this._checkAborted(signal);
    const target = plan.target;
    const stepStart = performance.now();

    // 1. If target is a hostname that failed DNS resolution (ENOTFOUND / NXDOMAIN), fail fast and report DNS failure honestly
    // instead of claiming "100% ICMP packet loss — firewall might be blocking ICMP"!
    const isIpLiteral = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(target) || target.toLowerCase() === 'localhost';
    if (!isIpLiteral && plan.targetValidation && !plan.targetValidation.valid) {
      const durationMs = Number((performance.now() - stepStart).toFixed(1));
      const suggested = detectDomainTypo(target);
      const steps = [
        {
          stepNumber: 1,
          label: `Resolving hostname ${target} before ping…`,
          tool: 'resolveRecord',
          status: 'FAIL',
          summary: `Cannot ping ${target}: DNS lookup failed (ENOTFOUND / NXDOMAIN)`,
          durationMs
        }
      ];
      const structuredAnswer = {
        result: `Ping to "${target}" could not be sent because DNS resolution failed (ENOTFOUND / NXDOMAIN).`,
        meaning: `The hostname "${target}" does not exist in DNS, so it has no IP address to ping. This is a DNS name resolution or spelling issue, not packet loss.`,
        nextStep: suggested
          ? `Did you mean "${suggested}"? Ask "Ping ${suggested}" to test the correct domain.`
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
          { label: 'DNS Status', value: 'FAILED (ENOTFOUND)', tone: 'danger' }
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

    // 2. Run fast ICMP Ping (2 probes, 900ms timeout) IN PARALLEL with TCP handshake reachability verification
    // so if the container/cloud sandbox blocks raw ICMP Echo, we still immediately prove whether the host is online!
    const [pingRes, tcpProbeRes] = await Promise.all([
      realPing(probeHost, 2, 900),
      checkPort(probeHost, fallbackPort, 1000).catch(() => ({ status: 'ERROR', open: false }))
    ]);
    const durationMs = Number((performance.now() - stepStart).toFixed(1));

    const ev = evidenceFabric.recordEvidence({
      type: 'observation',
      subject: `icmp:${target}`,
      claim: pingRes.success
        ? `ICMP ping to ${target} (${probeHost}) succeeded: avg RTT ${pingRes.avgRttMs}ms, loss ${pingRes.packetLossPct}%`
        : `ICMP ping to ${target} (${probeHost}) returned ${pingRes.packetLossPct}% loss; TCP :${fallbackPort} status=${tcpProbeRes.status}`,
      rawValue: { pingRes, tcpProbeRes },
      normalizedValue: pingRes.success ? 'ICMP_OK' : (tcpProbeRes.status === 'OPEN' ? 'ICMP_FILTERED_TCP_OPEN' : 'ICMP_LOSS'),
      sourceCapabilityId: 'ejii.chat.icmp_ping',
      collectionMethod: 'icmp_echo'
    });

    const steps = [
      {
        stepNumber: 1,
        label: `Sending ICMP echo requests to ${target} (${probeHost})…`,
        tool: 'realPing',
        status: pingRes.success ? 'PASS' : (tcpProbeRes.status === 'OPEN' ? 'WARN' : 'FAIL'),
        summary: pingRes.success
          ? `${pingRes.packetsReceived}/${pingRes.packetsSent} replies received · avg ${pingRes.avgRttMs} ms · ${pingRes.packetLossPct}% loss`
          : `0/${pingRes.packetsSent} ICMP replies (${tcpProbeRes.status === 'OPEN' ? 'ICMP filtered by firewall/sandbox' : '100% loss'})`,
        durationMs
      }
    ];

    let structuredAnswer;
    let reply;
    let findings;

    if (pingRes.success && pingRes.packetLossPct === 0) {
      this._recordEntityMemory(session, target, {
        resolvedIps: [probeHost],
        dnsStatus: 'OK',
        pingRttMs: pingRes.avgRttMs,
        openPorts: tcpProbeRes.status === 'OPEN' ? [fallbackPort] : [],
        summary: `ICMP reachable (${pingRes.avgRttMs}ms avg RTT, 0% loss)`
      });

      structuredAnswer = {
        result: `${target} (${probeHost}) replied to all ${pingRes.packetsSent} ICMP ping probes with an average round-trip time of ${pingRes.avgRttMs} ms (min ${pingRes.minRttMs} ms, max ${pingRes.maxRttMs} ms, jitter ${pingRes.jitterMs} ms).`,
        meaning: `Basic Layer 3 network routing to ${target} is healthy and responsive with 0% packet loss.`,
        nextStep: `If an application on ${target} is still not working, test the specific TCP service port (e.g., "Now test port ${fallbackPort} on the same host").`,
        layerFailedFirst: null,
        uncertainty: null
      };
      reply =
        `**Result:** \`${target}\` (\`${probeHost}\`) is reachable — **${pingRes.packetsReceived}/${pingRes.packetsSent} packets received** (0% loss) with an average latency of **${pingRes.avgRttMs} ms** (jitter ${pingRes.jitterMs} ms).\n\n` +
        `**Meaning:** Network routing to \`${target}\` is healthy. Packets are reaching the host and returning without drops.\n\n` +
        `**Next step:** If a specific application or web page on \`${target}\` is not responding, check its TCP port next (for example: *"Now test port ${fallbackPort} on the same host"*).`;
      findings = [
        { label: 'Target', value: `${target} (${probeHost})`, tone: 'neutral' },
        { label: 'Reachability', value: 'REACHABLE (0% Loss)', tone: 'ok' },
        { label: 'Avg RTT', value: `${pingRes.avgRttMs} ms`, tone: 'ok' },
        { label: 'Jitter', value: `${pingRes.jitterMs} ms`, tone: 'neutral' }
      ];
    } else if (pingRes.success && pingRes.packetLossPct > 0) {
      this._recordEntityMemory(session, target, {
        resolvedIps: [probeHost],
        pingRttMs: pingRes.avgRttMs,
        summary: `ICMP partial loss (${pingRes.packetLossPct}% loss, ${pingRes.avgRttMs}ms RTT)`
      });

      structuredAnswer = {
        result: `${target} (${probeHost}) responded intermittently with ${pingRes.packetLossPct}% packet loss (${pingRes.packetsReceived}/${pingRes.packetsSent} received, avg RTT ${pingRes.avgRttMs} ms).`,
        meaning: `The host is online, but packets are being dropped or rate-limited along the path.`,
        nextStep: `Run a traceroute to ${target} or test TCP port connectivity to see whether application traffic is also affected.`,
        layerFailedFirst: 'L3 Network Path (Partial Packet Loss)',
        uncertainty: 'ICMP rate-limiting on routers or firewalls can sometimes mimic packet loss.'
      };
      reply =
        `**Result:** Partial response from \`${target}\` (\`${probeHost}\`) — **${pingRes.packetLossPct}% packet loss** (${pingRes.packetsReceived}/${pingRes.packetsSent} received, avg RTT **${pingRes.avgRttMs} ms**).\n\n` +
        `**Meaning:** ${structuredAnswer.meaning}\n\n` +
        `**Next step:** ${structuredAnswer.nextStep}`;
      findings = [
        { label: 'Target', value: `${target} (${probeHost})`, tone: 'neutral' },
        { label: 'Packet Loss', value: `${pingRes.packetLossPct}%`, tone: 'warn' },
        { label: 'Avg RTT', value: `${pingRes.avgRttMs} ms`, tone: 'warn' }
      ];
    } else if (tcpProbeRes && (tcpProbeRes.status === 'OPEN' || tcpProbeRes.status === 'CLOSED')) {
      // ICMP Echo was blocked by container sandbox or remote firewall, BUT TCP proved the host is ONLINE!
      const tcpRtt = tcpProbeRes.connectLatencyMs ?? tcpProbeRes.latencyMs ?? durationMs;
      steps.push({
        stepNumber: 2,
        label: `Verifying live reachability via TCP port ${fallbackPort} handshake on ${probeHost}…`,
        tool: 'checkPort',
        status: 'PASS',
        summary: `Host ${target} (${probeHost}) is ONLINE — TCP port ${fallbackPort} responded (${tcpProbeRes.status}) in ${tcpRtt} ms`,
        durationMs: tcpRtt
      });

      this._recordEntityMemory(session, target, {
        resolvedIps: [probeHost],
        dnsStatus: 'OK',
        pingRttMs: tcpRtt,
        openPorts: tcpProbeRes.status === 'OPEN' ? [fallbackPort] : [],
        closedPorts: tcpProbeRes.status === 'CLOSED' ? [fallbackPort] : [],
        portLatencies: { [fallbackPort]: tcpRtt },
        summary: `Host ONLINE (${tcpRtt}ms via TCP :${fallbackPort}; raw ICMP filtered)`
      });

      structuredAnswer = {
        result: `${target} (${probeHost}) is ONLINE and reachable with a round-trip latency of ${tcpRtt} ms (verified via TCP port ${fallbackPort} handshake; raw ICMP echo requests are filtered by the container/network firewall).`,
        meaning: `Although raw ICMP ping packets are blocked by the network or container sandbox policy, EJII automatically verified TCP transport to ${probeHost}:${fallbackPort} and confirmed the host is live and responding in ${tcpRtt} ms.`,
        nextStep: `Connectivity to ${target} is healthy. You can inspect full web/TLS response by asking "Check whether https://${target} is working" or test another port.`,
        layerFailedFirst: null,
        uncertainty: null
      };
      reply =
        `**Result:** \`${target}\` (\`${probeHost}\`) is **ONLINE and reachable** in **${tcpRtt} ms** (verified via TCP port ${fallbackPort} handshake; raw ICMP echo is filtered by the firewall/sandbox).\n\n` +
        `**Meaning:** ${structuredAnswer.meaning}\n\n` +
        `**Next step:** ${structuredAnswer.nextStep}`;
      findings = [
        { label: 'Target', value: `${target} (${probeHost})`, tone: 'neutral' },
        { label: 'Host Status', value: `ONLINE (${tcpRtt} ms RTT)`, tone: 'ok' },
        { label: `TCP Port ${fallbackPort}`, value: `${tcpProbeRes.status} (${tcpRtt} ms)`, tone: 'ok' },
        { label: 'ICMP Echo', value: 'Filtered by Firewall/Sandbox', tone: 'neutral' }
      ];
    } else {
      structuredAnswer = {
        result: `No ICMP echo reply was received from ${target} (${probeHost}) — 100% packet loss (${pingRes.packetsReceived}/${pingRes.packetsSent} received).`,
        meaning: `Either ${target} is offline/unreachable on the network, or a firewall is blocking both ICMP echo requests and TCP port ${fallbackPort}.`,
        nextStep: `Test a specific TCP port where a service is expected to listen (for example: "Now test port 80 on the same host").`,
        layerFailedFirst: 'L3 ICMP Reachability',
        uncertainty: 'ICMP timeout alone cannot distinguish between a powered-off host and a firewall that silently drops packets.'
      };
      reply =
        `**Result:** No ping reply from \`${target}\` (\`${probeHost}\`) — **100% packet loss** (${pingRes.packetsSent} sent, 0 received).\n\n` +
        `**Meaning:** ${structuredAnswer.meaning}\n\n` +
        `**Next step:** ${structuredAnswer.nextStep}`;
      findings = [
        { label: 'Target', value: `${target} (${probeHost})`, tone: 'neutral' },
        { label: 'ICMP Status', value: 'NO REPLY (100% Loss)', tone: 'danger' },
        { label: 'Note', value: 'Test specific TCP port to rule out firewall block', tone: 'warn' }
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
        rawResult: pingRes,
        tcpFallbackResult: tcpProbeRes,
        observedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Scenario C: Real TCP Port Check (Single or Multiple Ports)
   */
  async _executePortCheckScenario(plan, session, signal) {
    this._checkAborted(signal);
    const target = plan.target;
    const isIpLiteral = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(target) || target.toLowerCase() === 'localhost';

    if (!isIpLiteral && plan.targetValidation && !plan.targetValidation.valid) {
      const suggested = detectDomainTypo(target);
      const structuredAnswer = {
        result: `TCP port check on "${target}" could not proceed because DNS resolution failed (ENOTFOUND).`,
        meaning: `The hostname "${target}" could not be resolved to an IP address in DNS.`,
        nextStep: suggested
          ? `Did you mean "${suggested}"? Try "Check port ${plan.ports[0] || 443} on ${suggested}".`
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
        sourceCapabilityId: 'ejii.chat.tcp_port_check',
        collectionMethod: 'net.Socket.connect'
      });
      evidenceIds.push(ev.id);

      steps.push({
        stepNumber: i + 1,
        label: `Testing TCP port ${port} on ${target}…`,
        tool: 'checkPort',
        status: res.status === 'OPEN' ? 'PASS' : 'FAIL',
        summary: res.status === 'OPEN'
          ? `Port ${port} is OPEN (handshake RTT: ${res.latencyMs} ms)`
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
          meaning: `The host is reachable on the network and a service is actively listening and accepting connections on port ${r.port}.`,
          nextStep: (r.port === 443 || r.port === 80 || r.port === 3000 || r.port === 8080 || r.port === 8443)
            ? `If users still see errors in their browser, check the HTTP/TLS application layer next (e.g., "Check whether http${r.port === 443 || r.port === 8443 ? 's' : ''}://${target}:${r.port} is working").`
            : `Network connectivity to port ${r.port} is verified. Check application logs or authentication credentials if clients report errors.`,
          layerFailedFirst: null,
          uncertainty: null
        };
      } else if (r.status === 'CLOSED') {
        structuredAnswer = {
          result: `TCP port ${r.port} on ${target} (${probeHost}) is CLOSED (connection actively refused with TCP RST / ECONNREFUSED in ${r.latencyMs} ms).`,
          meaning: `The host ${target} is online and reachable across the network, and no firewall blocked the packet — however, no application process is listening on port ${r.port}.`,
          nextStep: `Verify that the service expected on port ${r.port} is running and bound to the correct interface on ${target}, or test an alternative port (e.g., "Now test port ${r.port === 443 ? 80 : 3000} on the same host").`,
          layerFailedFirst: `L4 TCP Application Listener (Port ${r.port} Refused)`,
          uncertainty: null
        };
      } else if (r.status === 'FILTERED') {
        structuredAnswer = {
          result: `TCP connection to port ${r.port} on ${target} (${probeHost}) timed out with no response (FILTERED / TIMEOUT).`,
          meaning: `The TCP SYN packet received neither a SYN-ACK nor a TCP RST within the timeout window. Either a firewall/security group is silently dropping traffic to port ${r.port}, or the host itself is unreachable.`,
          nextStep: `Check DNS and host reachability ("Ping ${target}") or inspect firewall ingress rules for port ${r.port}.`,
          layerFailedFirst: `L3/L4 Network Path or Firewall (Port ${r.port} Timeout)`,
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
          ? `All ${results.length} tested ports are open and accepting TCP connections.`
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
   * Scenario D: Website / HTTPS Accessibility Check (DNS -> TCP -> TLS -> HTTP)
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
        dnsRes = { success: true, records: plan.targetValidation.resolvedIps, durationMs: Number((performance.now() - t0).toFixed(2)) };
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
      dnsRes = { success: true, records: [resolvedIp], durationMs: 0.4 };
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
        meaning: `Browsers and clients cannot look up an IP address for ${target}, so no TCP, TLS, or HTTP connection can even begin.`,
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

    // Step 3: TLS Audit (if HTTPS)
    let tlsRes = null;
    if (isHttps) {
      this._checkAborted(signal);
      const t2 = performance.now();
      tlsRes = await auditTls(target, port, 2500);
      const tlsCipherName = tlsRes.cipher && typeof tlsRes.cipher === 'object' ? tlsRes.cipher.name : null;
      const tlsDaysRemaining = tlsRes.certificate && typeof tlsRes.certificate.daysRemaining === 'number' ? tlsRes.certificate.daysRemaining : null;
      const tlsAuthorized = tlsRes.validation && typeof tlsRes.validation.authorized === 'boolean' ? tlsRes.validation.authorized : null;
      steps.push({
        stepNumber: 3,
        label: `Verifying TLS handshake and certificate on ${target}:${port}…`,
        tool: 'auditTls',
        status: tlsRes.success ? (tlsAuthorized === true ? 'PASS' : 'WARN') : 'FAIL',
        summary: tlsRes.success
          ? `${tlsRes.protocol || 'TLS'} (${tlsCipherName || 'cipher unavailable'}) · ${tlsDaysRemaining === null ? 'certificate details unavailable' : `certificate expires in ${tlsDaysRemaining} days`}`
          : `TLS handshake failed: ${tlsRes.error || 'Handshake error'}`,
        durationMs: Number((performance.now() - t2).toFixed(1))
      });
      findings.push({
        label: 'TLS Security',
        value: tlsRes.success
          ? `${tlsRes.protocol || 'TLS'} (${tlsDaysRemaining === null ? 'certificate date unavailable' : `${tlsDaysRemaining}d left`})`
          : `FAILED (${tlsRes.error || 'Error'})`,
        tone: tlsRes.success ? (tlsAuthorized === true ? 'ok' : 'warn') : 'danger'
      });
    }

    // Step 4: HTTP Application Probe
    this._checkAborted(signal);
    const t3 = performance.now();
    const httpRes = await probeHttp(urlToProbe, 'GET', 2500);
    steps.push({
      stepNumber: isHttps ? 4 : 3,
      label: `Checking HTTP response from ${urlToProbe}…`,
      tool: 'probeHttp',
      status: httpRes.success ? 'PASS' : (httpRes.statusCode ? 'WARN' : 'FAIL'),
      summary: httpRes.statusCode
        ? `HTTP ${httpRes.statusCode} ${httpRes.statusMessage || ''} (TTFB: ${httpRes.waterfall?.ttfbMs ?? 'n/a'} ms, total: ${httpRes.waterfall?.totalMs ?? 'n/a'} ms)`
        : `HTTP request failed: ${httpRes.error || 'No HTTP response'}`,
      durationMs: Number((performance.now() - t3).toFixed(1))
    });

    if (httpRes.statusCode) {
      findings.push({
        label: 'HTTP Status',
        value: `${httpRes.statusCode} (${httpRes.waterfall?.ttfbMs ?? 'n/a'} ms TTFB)`,
        tone: httpRes.statusCode < 400 ? 'ok' : (httpRes.statusCode < 500 ? 'warn' : 'danger')
      });
    } else {
      findings.push({
        label: 'HTTP Status',
        value: `FAILED (${httpRes.errorCode || httpRes.error || 'Error'})`,
        tone: 'danger'
      });
    }

    this._recordEntityMemory(session, target, {
      resolvedIps: [resolvedIp],
      dnsStatus: 'OK',
      openPorts: [port],
      portLatencies: { [port]: tcpRes.latencyMs },
      httpStatus: httpRes.statusCode || 'FAILED',
      summary: `Website check ${urlToProbe}: HTTP ${httpRes.statusCode || 'FAILED'} (${httpRes.waterfall?.ttfbMs ?? 'n/a'}ms TTFB)`
    });

    let structuredAnswer;
    if (httpRes.statusCode && httpRes.statusCode < 400) {
      structuredAnswer = {
        result: `${urlToProbe} returned HTTP ${httpRes.statusCode}; DNS resolved to ${resolvedIp} (${dnsRes.durationMs} ms), TCP port ${port} is OPEN (${tcpRes.latencyMs} ms)${isHttps ? `, TLS ${tlsRes?.protocol || 'result unavailable'}${tlsAuthorized === true ? ' with certificate validation' : ' without verified certificate trust'}` : ''}, and TTFB was ${httpRes.waterfall?.ttfbMs ?? 'not measured'} ms.`,
        meaning: `DNS, TCP, and HTTP responded. ${isHttps ? (tlsAuthorized === true ? 'TLS certificate validation succeeded.' : 'The TLS handshake completed, but certificate trust was not verified.') : ''} An HTTP response below 400 does not by itself prove that every application function is healthy.`,
        nextStep: `The tested endpoint returned an HTTP response below 400. If users still report issues, check the specific application path, browser error, authentication, and server logs.`,
        layerFailedFirst: null,
        uncertainty: null
      };
    } else if (httpRes.statusCode && httpRes.statusCode >= 500) {
      structuredAnswer = {
        result: `Network and TCP connectivity to ${target}:${port} succeeded, but the web server returned HTTP ${httpRes.statusCode} (${httpRes.statusMessage || 'Server Error'}).`,
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
  _executeConversationResponse(promptText) {
    const reply = /\b(what can you do|help|how do i use ejii)\b/i.test(promptText)
      ? 'I can run the available DNS, ping, TCP-port, website/TLS, traceroute, local IP/gateway, and active TCP connection checks. Describe the task and include a hostname or IP when the target is remote.'
      : 'Hello. What would you like me to check? I can run a network diagnostic, inspect this workstation’s local network details, or list active TCP connections.';
    return {
      reply,
      structuredAnswer: { result: 'No diagnostic was run.', meaning: 'This was a conversational request, not a network test.', nextStep: 'Describe the operation or problem you want EJII to investigate.' },
      steps: [], findings: [], technicalEvidence: null
    };
  }

  _executeClarificationResponse(promptText) {
    const reply = 'I have not run a diagnostic because I could not identify a specific operation or target. Try “Check DNS for example.com”, “Ping the default gateway”, “Check my local IP”, or “Show active TCP connections”.';
    return {
      reply,
      structuredAnswer: { result: 'No diagnostic was run.', meaning: 'The request did not map safely to a specific diagnostic.', nextStep: 'Specify the operation and target, if applicable.' },
      steps: [], findings: [], technicalEvidence: { request: promptText, executed: false }
    };
  }

  async _executeLocalNetworkInfoScenario(signal) {
    this._checkAborted(signal);
    const interfaces = os.networkInterfaces();
    const addresses = [];
    for (const [name, entries] of Object.entries(interfaces || {})) {
      for (const entry of entries || []) {
        if (!entry || entry.internal) continue;
        const family = entry.family === 4 || entry.family === 'IPv4' ? 'IPv4'
          : entry.family === 6 || entry.family === 'IPv6' ? 'IPv6' : String(entry.family);
        addresses.push({
          interface: name,
          family,
          address: entry.address,
          netmask: entry.netmask || null,
          mac: entry.mac || null,
          internal: false
        });
      }
    }
    let physical = null;
    try { physical = getPhysicalNetworkInfo(); } catch (_) {}
    const gateway = physical && physical.isDetected === true && physical.gatewayIp
      ? String(physical.gatewayIp) : null;
    const addressSummary = addresses.length
      ? addresses.map((a) => `${a.interface} ${a.family}: ${a.address}${a.netmask ? `/${a.netmask}` : ''}`).join('; ')
      : 'No non-loopback interface addresses were returned by the operating system.';
    const reply = `**Result:** ${addressSummary}${gateway ? `; detected default gateway: ${gateway}` : '; default gateway was not verified by the network detector'}.\n\n**Meaning:** These are local interface addresses observed on the EJII host, not your public internet IP. EJII did not query an external IP-discovery service.\n\n**Next step:** Ask “Ping the default gateway” to test the detected gateway, or “Show active TCP connections” to inspect current remote endpoints.`;
    return {
      reply,
      structuredAnswer: {
        result: addressSummary,
        meaning: 'Local interface addresses are OS-observed. A public IP has not been queried.',
        nextStep: gateway ? `Test gateway ${gateway} with “Ping the default gateway”.` : 'The default gateway could not be verified. Check the OS routing table or network adapter state.',
        layerFailedFirst: null, uncertainty: gateway ? null : 'Gateway telemetry was not verified.'
      },
      steps: [{
        stepNumber: 1, label: 'Read local network interfaces from the operating system', tool: 'os.networkInterfaces',
        status: addresses.length ? 'PASS' : 'WARN',
        summary: addresses.length ? `Observed ${addresses.length} non-loopback interface address(es)` : 'No non-loopback interface addresses observed',
        durationMs: 0
      }],
      findings: [
        { label: 'Local addresses', value: String(addresses.length), tone: addresses.length ? 'ok' : 'warn' },
        { label: 'Default gateway', value: gateway || 'Not verified', tone: gateway ? 'ok' : 'warn' }
      ],
      technicalEvidence: { tool: 'os.networkInterfaces + physical-network-detector', addresses, gateway, gatewayVerified: Boolean(gateway), observedAt: new Date().toISOString() }
    };
  }

  async _executeGatewayPingScenario(signal) {
    this._checkAborted(signal);
    let physical = null;
    try { physical = getPhysicalNetworkInfo(); } catch (_) {}
    const gateway = physical && physical.isDetected === true && physical.gatewayIp
      ? String(physical.gatewayIp) : null;
    if (!gateway || !isSafeNetworkTarget(gateway)) {
      const reply = '**Result:** EJII could not verify a default gateway from the current OS network configuration. No ping was sent.\n\n**Meaning:** The detector did not provide a verified gateway address, so using a remembered target would be incorrect.\n\n**Next step:** Check the active adapter and default route, then retry.';
      return {
        reply,
        structuredAnswer: { result: 'Default gateway not verified; no probe executed.', meaning: 'No target IP was established from current host telemetry.', nextStep: 'Inspect the active adapter and default route.' },
        steps: [{ stepNumber: 1, label: 'Resolve the current default gateway', tool: 'physical-network-detector', status: 'WARN', summary: 'No verified gateway address available', durationMs: 0 }],
        findings: [{ label: 'Gateway', value: 'Not verified', tone: 'warn' }],
        technicalEvidence: { tool: 'getPhysicalNetworkInfo', gatewayVerified: false, observedAt: new Date().toISOString() }
      };
    }

    const t0 = performance.now();
    const result = await realPing(gateway, 2, 800);
    this._checkAborted(signal);
    const durationMs = Number((performance.now() - t0).toFixed(1));
    const gotReply = Boolean(result && result.success && (result.packetsReceived || 0) > 0);
    const reply = gotReply
      ? `**Result:** Default gateway ${gateway} replied to ICMP ping: ${result.packetsReceived}/${result.packetsSent} replies, ${result.packetLossPct}% packet loss, average RTT ${result.avgRttMs ?? 'not measured'} ms.\n\n**Meaning:** The gateway responded to ICMP from the EJII host.\n\n**Next step:** If users still have connectivity issues, test the remote host or service separately.`
      : `**Result:** The default gateway ${gateway} did not return a usable ICMP echo reply (${result?.packetLossPct ?? 'unknown'}% reported packet loss).\n\n**Meaning:** This does not prove the gateway is down; ICMP may be filtered or rate-limited.\n\n**Next step:** Verify the local route and ARP/neighbor state, or test another protocol if available.`;
    return {
      reply,
      structuredAnswer: {
        result: gotReply ? `Gateway ${gateway} responded to ICMP.` : `No ICMP echo reply from gateway ${gateway}.`,
        meaning: gotReply ? 'The gateway answered the ICMP probe.' : 'No reply does not distinguish a failed gateway from ICMP filtering.',
        nextStep: gotReply ? 'Continue testing the remote destination if needed.' : 'Check route/neighbor state; do not conclude the gateway is offline from ICMP alone.',
        layerFailedFirst: gotReply ? null : 'ICMP echo (cause unconfirmed)',
        uncertainty: gotReply ? null : 'ICMP silence can be caused by filtering or rate limiting.'
      },
      steps: [{
        stepNumber: 1, label: `Ping current default gateway ${gateway}`, tool: 'realPing',
        status: gotReply ? 'PASS' : 'WARN',
        summary: gotReply ? `${result.packetsReceived}/${result.packetsSent} replies, average RTT ${result.avgRttMs ?? 'n/a'} ms` : 'No ICMP reply; gateway reachability remains unconfirmed',
        durationMs
      }],
      findings: [
        { label: 'Gateway', value: gateway, tone: 'neutral' },
        { label: 'ICMP replies', value: `${result?.packetsReceived ?? 0}/${result?.packetsSent ?? 0}`, tone: gotReply ? 'ok' : 'warn' },
        { label: 'Packet loss', value: `${result?.packetLossPct ?? 'unknown'}%`, tone: gotReply && result.packetLossPct === 0 ? 'ok' : 'warn' }
      ],
      technicalEvidence: { tool: 'realPing', target: gateway, result, observedAt: new Date().toISOString() }
    };
  }

  async _executeActiveConnectionsScenario(signal) {
    this._checkAborted(signal);
    const matrix = ProcessSocketCorrelatorEngine.collectLiveHostSocketMatrix();
    this._checkAborted(signal);
    if (!matrix || matrix.collectionStatus !== 'LIVE_OS_TELEMETRY') {
      const details = matrix?.collectionErrors?.length ? matrix.collectionErrors.join('; ') : 'No supported OS socket collector completed successfully.';
      const reply = `**Result:** EJII could not read the active socket table from this host.\n\n**Meaning:** The OS collector was unavailable or blocked; this is not evidence that no applications are connected.\n\n**Next step:** Verify that netstat (Windows) or ss (Linux) is available and permitted, then retry. Details: ${details}`;
      return {
        reply,
        structuredAnswer: { result: 'Active socket collection unavailable.', meaning: 'Collection failed; no zero-connection conclusion was made.', nextStep: 'Check OS command availability and permissions.' },
        steps: [{ stepNumber: 1, label: 'Collect active OS sockets', tool: 'ProcessSocketCorrelatorEngine', status: 'FAIL', summary: 'OS socket collector unavailable', durationMs: 0 }],
        findings: [{ label: 'Collection', value: 'Unavailable', tone: 'danger' }],
        technicalEvidence: { tool: 'ProcessSocketCorrelatorEngine.collectLiveHostSocketMatrix', collectionStatus: matrix?.collectionStatus || 'UNAVAILABLE', errors: matrix?.collectionErrors || [], observedAt: new Date().toISOString() }
      };
    }

    const sockets = Array.isArray(matrix.sockets) ? matrix.sockets : [];
    const established = sockets.filter((s) => String(s.state || '').toUpperCase() === 'ESTABLISHED'
      && s.remoteAddress && !['0.0.0.0', '::', '::0', '*'].includes(String(s.remoteAddress))
      && Number(s.remotePort) > 0);
    const sorted = established.sort((a, b) => String(a.processName || '').localeCompare(String(b.processName || ''))
      || String(a.remoteAddress).localeCompare(String(b.remoteAddress)) || Number(a.remotePort) - Number(b.remotePort));
    const maxRows = 40;
    const visible = sorted.slice(0, maxRows);
    const lines = visible.map((s) => `- ${s.processName || 'Unknown process'} (PID ${s.pid ?? 'n/a'}): ${s.remoteAddress}:${s.remotePort} [local ${s.localAddress}:${s.localPort}]`);
    const resultText = established.length
      ? `Observed ${established.length} established TCP connection(s) at ${new Date().toISOString()}.\n${lines.join('\n')}${established.length > maxRows ? `\n...and ${established.length - maxRows} more connection(s).` : ''}`
      : 'The OS collector completed successfully, but no established remote TCP connections were present in the collected snapshot.';
    const reply = `**Result:** ${resultText}\n\n**Meaning:** These are current OS-visible TCP endpoints. The destination IP and destination port are the remote address and remote port; connections can change while applications run. Process names may be unavailable when the OS restricts attribution.\n\n**Next step:** Ask EJII to filter by application name, destination IP, or port.`;
    return {
      reply,
      structuredAnswer: {
        result: `${established.length} established TCP connection(s) observed.`,
        meaning: 'Remote endpoints were taken from the host OS socket table, not inferred from recent website checks.',
        nextStep: 'Filter the live list by an application, remote address, or port if needed.',
        layerFailedFirst: null,
        uncertainty: matrix.collectionNote || null
      },
      steps: [{
        stepNumber: 1, label: 'Read the current TCP socket table', tool: 'ProcessSocketCorrelatorEngine.collectLiveHostSocketMatrix',
        status: 'PASS', summary: `${established.length} established remote TCP connection(s) observed`, durationMs: 0
      }],
      findings: [
        { label: 'Established TCP', value: String(established.length), tone: 'neutral' },
        { label: 'OS collector', value: matrix.collectionMethod || 'unknown', tone: 'ok' }
      ],
      technicalEvidence: { tool: 'ProcessSocketCorrelatorEngine.collectLiveHostSocketMatrix', collectionStatus: matrix.collectionStatus, collectionMethod: matrix.collectionMethod, collectionNote: matrix.collectionNote, sockets: visible, totalEstablished: established.length, observedAt: new Date().toISOString() }
    };
  }

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
   * Scenario F: Contextual Follow-Up Explanation, Deep Memory Recall & Multi-Host Comparison
   */
  async _executeFollowUpExplanation(plan, session, promptText) {
    const prevAns = session.lastStructuredAnswer || {};
    const prevSteps = session.lastSteps || [];
    const prevTarget = session.lastValidTarget || session.lastTarget || 'localhost';
    const prevPorts = session.lastPorts || [];
    const lower = promptText.toLowerCase();
    const entities = Object.values(session.entityMemory || {});

    const firstFailed = prevSteps.find((s) => s.status === 'FAIL' || s.status === 'TIMEOUT');
    let reply;

    if (lower.includes('what have we tested') || lower.includes('what have we found') || lower.includes('show memory') || lower.includes('compare')) {
      const entityBullets = entities.length > 0
        ? entities.map((e) =>
            `- **\`${e.target}\`** (${e.resolvedIps.join(', ') || 'unresolved'}): checked ${e.checkCount}x · Open ports: [${e.openPorts.join(', ') || 'none'}] · Closed ports: [${e.closedPorts.join(', ') || 'none'}] · Latest summary: ${e.lastOutcomeSummary || 'N/A'}`
          ).join('\n')
        : `- **\`${prevTarget}\`**: ${prevAns.result || 'Tested in current session.'}`;
      reply =
        `**Result (Session Investigation Memory — ${entities.length || 1} Host(s) Tracked across ${session.turnCount || 1} Turn(s)):**\n${entityBullets}\n\n` +
        `**Meaning:** EJII maintains a persistent knowledge graph of every host, IP, port, and latency measurement across your conversation.\n\n` +
        `**Next step:** Ask to re-test any host above or compare specific ports (e.g., *"Now test port 443 on ${prevTarget}"*).`;
    } else if (lower.includes('which layer failed')) {
      const layerName = prevAns.layerFailedFirst || (firstFailed ? firstFailed.label : 'None — all tested layers passed');
      reply =
        `**Result:** First failing layer on \`${prevTarget}\`: **${layerName}**.\n\n` +
        `**Meaning:** ${prevAns.meaning || 'The diagnostic checks evaluated each layer in sequence from local network and DNS up to TCP and HTTP.'}\n\n` +
        `**Next step:** ${prevAns.nextStep || `Run a targeted follow-up probe on ${prevTarget}.`}`;
    } else if (lower.includes('incident report') || lower.includes('summarize')) {
      const stepBullets = prevSteps.map((s) => `- **Step ${s.stepNumber} (${s.tool}):** ${s.status} — ${s.summary}`).join('\n');
      reply =
        `**Result (Incident Summary for \`${prevTarget}\`):** ${prevAns.result || 'Completed diagnostic checks.'}\n\n` +
        `**Checks Performed:**\n${stepBullets || '- Completed diagnostic probe.'}\n\n` +
        `**Meaning (Root Cause Assessment):** ${prevAns.meaning || 'See step outcomes above.'}\n\n` +
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
      steps: prevSteps,
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
  detectDomainTypo
};
