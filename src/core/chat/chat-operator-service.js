/**
 * EJII Chat-First Minimalist Infrastructure Intelligence Service
 *
 * High-speed, stateful diagnostic & investigation engine with:
 *   - Sub-second bounded DNS, ICMP, TCP, TLS, and HTTP execution
 *   - Automatic domain & TLD typo detection + live auto-correction (e.g., google.ocm -> google.com)
 *   - Container-aware hybrid Ping (parallel ICMP Echo + TCP Handshake fallback when raw ICMP is filtered)
 *   - Instant target context capture (even if a running request is cancelled)
 *   - Unlimited persistent SQLite conversation history & per-entity knowledge graph memory
 *   - Strict RBAC and SSRF / DNS-rebinding defenses
 */

'use strict';

const crypto = require('node:crypto');
const os = require('node:os');
const dns = require('node:dns');
const { execFileSync } = require('node:child_process');
const { hostDiagnosticsEngine } = require('../../systems/diagnostics/host-diagnostics-engine');

function isIpv4Address(value) {
  const parts = String(value || '').split('.');
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function prefixLengthFromNetmask(netmask) {
  if (!isIpv4Address(netmask)) return null;
  return netmask.split('.').reduce((sum, octet) => sum + Number(octet).toString(2).padStart(8, '0').replace(/0/g, '').length, 0);
}

function readDefaultRoute() {
  try {
    if (process.platform === 'win32') {
      const command = "$r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1; if ($r) { $ip = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $r.InterfaceIndex -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' } | Select-Object -First 1; [pscustomobject]@{ gatewayIp = $r.NextHop; interfaceIndex = $r.InterfaceIndex; interfaceName = $r.InterfaceAlias; sourceIp = $ip.IPAddress } | ConvertTo-Json -Compress }";
      const output = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', command], { encoding: 'utf8', timeout: 1600, windowsHide: true });
      let route = null;
      try { route = JSON.parse(String(output || '').trim()); } catch (_) {}
      const gatewayIp = isIpv4Address(route?.gatewayIp) ? route.gatewayIp : null;
      const sourceIp = isIpv4Address(route?.sourceIp) ? route.sourceIp : null;
      return { gatewayIp, interfaceName: route?.interfaceName || null, sourceIp, source: gatewayIp ? 'OS default route' : null };
    }
    if (process.platform === 'darwin') {
      const output = execFileSync('route', ['-n', 'get', 'default'], { encoding: 'utf8', timeout: 1600 });
      const gatewayIp = output.match(/\bgateway:\s*(\d+\.\d+\.\d+\.\d+)/)?.[1] || null;
      const interfaceName = output.match(/\binterface:\s*(\S+)/)?.[1] || null;
      return { gatewayIp, interfaceName, sourceIp: null, source: gatewayIp ? 'OS default route' : null };
    }
    const output = execFileSync('ip', ['-4', 'route', 'show', 'default'], { encoding: 'utf8', timeout: 1600 });
    const routeLine = String(output || '').split(/\r?\n/).find((line) => /^default\s/.test(line.trim())) || '';
    const gatewayIp = routeLine.match(/\bvia\s+(\d+\.\d+\.\d+\.\d+)/)?.[1] || null;
    const interfaceName = routeLine.match(/\bdev\s+(\S+)/)?.[1] || null;
    const sourceIp = routeLine.match(/\bsrc\s+(\d+\.\d+\.\d+\.\d+)/)?.[1] || null;
    return { gatewayIp, interfaceName, sourceIp, source: gatewayIp ? 'OS default route' : null };
  } catch (_) {
    return { gatewayIp: null, interfaceName: null, sourceIp: null, source: null };
  }
}

function collectLocalNetworkSnapshot() {
  const interfaces = Object.entries(os.networkInterfaces()).flatMap(([name, addresses]) =>
    (addresses || [])
      .filter((address) => !address.internal && (address.family === 'IPv4' || address.family === 4) && isIpv4Address(address.address))
      .map((address) => ({
        name,
        address: address.address,
        netmask: address.netmask || null,
        cidr: address.cidr || null,
        mac: address.mac || null
      }))
  );
  const route = readDefaultRoute();
  const eligible = interfaces.filter((item) => !item.address.startsWith('169.254.'));
  const localInterface = (route.sourceIp && eligible.find((item) => item.address === route.sourceIp)) ||
    (route.interfaceName && eligible.find((item) => item.name === route.interfaceName)) || eligible[0] || null;
  const prefixLength = localInterface ? prefixLengthFromNetmask(localInterface.netmask) : null;
  return {
    hostname: os.hostname(),
    platform: os.platform(),
    interfaces: eligible,
    localInterface,
    localIp: localInterface?.address || null,
    subnetCidr: localInterface?.cidr || (localInterface && prefixLength !== null ? localInterface.address + '/' + prefixLength : null),
    gatewayIp: route.gatewayIp && isIpv4Address(route.gatewayIp) ? route.gatewayIp : null,
    gatewaySource: route.source,
    dnsServers: dns.getServers(),
    collectedAt: new Date().toISOString()
  };
}

function parseSocketEndpoint(endpoint) {
  const value = String(endpoint || '').trim();
  const match = value.match(/^(.*):(\d+)$/);
  if (!match) return null;
  const address = match[1].replace(/^\[|\]$/g, '');
  const port = Number(match[2]);
  if (!address || !Number.isInteger(port) || port < 0 || port > 65535) return null;
  return { address, port };
}
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
  const clean = hostname.trim().toLowerCase();
  if (KNOWN_HOST_TYPO_MAP[clean]) {
    return KNOWN_HOST_TYPO_MAP[clean];
  }
  const parts = clean.split('.');
  if (parts.length >= 2) {
    const tld = parts[parts.length - 1];
    if (TLD_TYPO_MAP[tld]) {
      const correctedParts = [...parts.slice(0, -1), TLD_TYPO_MAP[tld]];
      const candidate = correctedParts.join('.');
      return KNOWN_HOST_TYPO_MAP[candidate] || candidate;
    }
  }
  return null;
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

  getOrCreateSession(sessionId, user = {}) {
    const cleanId = (sessionId && typeof sessionId === 'string' && sessionId.trim())
      ? sessionId.trim()
      : `CHAT-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;

    if (this.sessions.has(cleanId)) {
      const existing = this.sessions.get(cleanId);
      if (user && user.username) existing.username = user.username;
      if (user && user.role) existing.role = user.role;
      return existing;
    }

    // Check SQLite for persisted session (Unlimited message & entity memory)
    try {
      const row = db.prepare('SELECT * FROM ejii_chat_sessions WHERE session_id = ?').get(cleanId);
      if (row) {
        const ctx = row.context_json ? JSON.parse(row.context_json) : {};
        const msgRows = db.prepare('SELECT * FROM ejii_chat_messages WHERE session_id = ? ORDER BY created_at ASC').all(cleanId);
        const restored = {
          sessionId: cleanId,
          userId: user.id || row.user_id || 'op-1',
          username: user.username || row.username || 'operator',
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
    } catch (_) {}

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

const emptyTargetPlan = (intent) => ({
      intent, target: null, explicitTarget: null, typoSuggestion: null,
      isSystemDnsHealthCheck: false, ports: [], url: null, urlProtocol: null,
      recordType: 'A', usedFollowUpTarget: false
    });

    // Handle local-host questions before considering any previous remote target.
    if (/^(hi|hello|hey|good morning|good afternoon|good evening|how are you|thanks|thank you|thx)[.!\s]*$/i.test(lower)) {
      return emptyTargetPlan('conversation');
    }
    if (/(?:\b(?:check|test|verify)\s+(?:the\s+)?(?:system\s+)?dns(?:\s+(?:connection|connectivity|status|health|server))?|\bis dns working\b|\bdns connection\b|\bdns connectivity\b|\bdns health\b)/i.test(lower) &&
        !/\b(?:for|of|on)\s+(?:(?:[a-z0-9-]+\.)+[a-z]{2,}|(?:\d{1,3}\.){3}\d{1,3})\b|\b(?:same host|same domain|that host|that domain|for it|on it)\b/i.test(lower)) {
      return { ...emptyTargetPlan('dns'), target: 'google.com', isSystemDnsHealthCheck: true };
    }
    if (/(?:\b(?:destination|dest)\s+(?:ip|address|port|ports)\b|\bactive\s+(?:tcp\s+)?connections\b|\bremote\s+(?:ip|address|ports?)\b|\bapps?\b.*\b(?:currently|using|connections|destination|dest|ports?)\b)/i.test(lower)) {
      return emptyTargetPlan('active_connections');
    }
    if (/(?:\bping\b|\bicmp\b).*\b(?:default\s+gateway|gateway|router)\b|\b(?:default\s+gateway|gateway|router)\b.*(?:\bping\b|\bicmp\b)/i.test(lower)) {
      return emptyTargetPlan('gateway_ping');
    }
    if (/\b(?:check|show|get|find|display|what is|what's|tell me)\b.*\b(?:my ip|local ip|ip address|default gateway|gateway ip|network configuration|network interface|subnet|dns servers)\b|\b(?:my ip|local ip|ip address|default gateway|gateway ip|network configuration|network interface|subnet|dns servers)\b/i.test(lower)) {
      return emptyTargetPlan('local_network_info');
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
        // Prefer lastValidTarget if it exists and is not a broken typo, otherwise test canonical google.com + system DNS
        resolvedTarget = session?.lastValidTarget || 'google.com';
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

    // 7. Determine primary intent
    let intent = 'multi_step_investigation';

    const isRemediation =
      /\b(flush dns|refresh dns resolver|apply (?:the )?(?:fix|remediation)|execute remediation|heal|self-heal|fix it now|repair dns)\b/i.test(lower);

    const isRepeatLast =
      /\b(test the same host again|run that again|retry that|check it again|repeat the check)\b/i.test(lower) &&
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
    } else if (
      /\b(local host health|system health|active sockets|host diagnostics|cpu and memory|local system)\b/i.test(lower) &&
      !explicitTarget
    ) {
      intent = 'host_health';
    } else if (
      /\b(investigate|diagnose|diagnostic|troubleshoot|online|offline|reachable|accessible|not opening|not responding|not working|slow|connection failure|website|server|host|network|gateway|router)\b/i.test(lower)
    ) {
      intent = 'multi_step_investigation';
    } else {
      intent = 'conversation';
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

    if (intent === 'conversation') {
      resolvedTarget = null;
      extractedPorts.length = 0;
      extractedUrl = null;
      usedFollowUpTarget = false;
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

    const session = this.getOrCreateSession(sessionId, user);
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
      const localOnlyIntents = ['follow_up_explanation', 'host_health', 'conversation', 'local_network_info', 'active_connections', 'gateway_ping', 'dns'];
      if (!localOnlyIntents.includes(plan.intent)) {
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

        const targetValidationStartedAt = performance.now();
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

        if (targetValidation && !targetValidation.isIpLiteral && String(plan.target || '').toLowerCase() !== 'localhost') {
          targetValidation.resolutionDurationMs = Number((performance.now() - targetValidationStartedAt).toFixed(2));
        }
        plan.targetValidation = targetValidation;
      }

      this._checkAborted(abortController.signal);

      let executionOutcome;
      switch (plan.intent) {
        case 'conversation':
          executionOutcome = await this._executeConversationScenario(cleanPrompt);
          break;
        case 'local_network_info':
          executionOutcome = await this._executeLocalNetworkInfoScenario(abortController.signal);
          break;
        case 'gateway_ping':
          executionOutcome = await this._executeGatewayPingScenario(plan, session, abortController.signal);
          break;
        case 'active_connections':
          executionOutcome = await this._executeActiveConnectionsScenario(abortController.signal);
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

      // If a domain typo was auto-corrected (e.g. google.ocm -> google.com), prepend the auto-correction step and note
      if (plan.originalTypoTarget && executionOutcome) {
        const typoStep = {
          stepNumber: 1,
          label: `Detected domain typo "${plan.originalTypoTarget}" (NXDOMAIN) → auto-corrected to "${plan.target}"…`,
          tool: 'typo_intelligence',
          status: 'PASS',
          summary: `"${plan.originalTypoTarget}" does not exist in DNS (ENOTFOUND); automatically switched to "${plan.target}"`,
          durationMs: null
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
    const contextOnlyIntent = ['conversation', 'local_network_info', 'active_connections'].includes(plan.intent);
    if (Array.isArray(plan.ports) && plan.ports.length > 0 && plan.intent !== 'follow_up_explanation' && !contextOnlyIntent) {
      session.lastPorts = plan.ports;
    }
    if (plan.intent !== 'follow_up_explanation' && !contextOnlyIntent) {
      session.lastIntent = plan.intent;
    }
    if (plan.url) {
      session.lastUrl = plan.url;
    }

    // Greetings must not erase the last diagnostic evidence needed for contextual follow-ups.
    if (plan.intent !== 'conversation') {
      session.lastToolResults = technicalEvidence;
      session.lastSteps = steps;
      session.lastStructuredAnswer = structuredAnswer;
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


  async _executeConversationScenario(promptText) {
    const lower = String(promptText || '').toLowerCase();
    const reply = /\b(thanks|thank you|thx)\b/i.test(lower)
      ? 'You are welcome. Ask me to run a diagnostic or investigate an infrastructure problem whenever you need.'
      : 'Hello! I am EJII. Tell me what you want to check—for example, ping a host, test a TCP port, check DNS, inspect your local network, or investigate a connection problem.';
    return {
      reply,
      structuredAnswer: {
        result: 'No diagnostic was requested, so no network probe was executed.',
        meaning: 'This message was handled conversationally; EJII did not infer a target from previous checks.',
        nextStep: 'Describe the host, service, or network issue you want to investigate.',
        layerFailedFirst: null,
        uncertainty: null
      },
      steps: [],
      findings: [],
      technicalEvidence: { tool: 'conversation_router', executedDiagnostic: false, observedAt: new Date().toISOString() }
    };
  }

  async _executeLocalNetworkInfoScenario(signal) {
    this._checkAborted(signal);
    const started = performance.now();
    const net = collectLocalNetworkSnapshot();
    const durationMs = Number((performance.now() - started).toFixed(2));
    const iface = net.localInterface;
    const prefix = iface ? prefixLengthFromNetmask(iface.netmask) : null;
    const subnet = iface && prefix !== null ? iface.address + '/' + prefix : (iface?.cidr || 'not available');
    const interfaceLine = iface ? iface.name + ' (' + iface.address + ')' : 'No non-loopback IPv4 interface could be read';
    const gatewayLine = net.gatewayIp ? net.gatewayIp + ' (read from the OS default route)' : 'Not confirmed (the OS route table did not provide an IPv4 default gateway)';
    const dnsLine = net.dnsServers.length ? net.dnsServers.join(', ') : 'No DNS servers reported by the Node.js resolver';
    const steps = [{
      stepNumber: 1,
      label: 'Reading local network interfaces, default route, and DNS resolver configuration…',
      tool: 'os.networkInterfaces + OS route table + dns.getServers',
      status: iface ? (net.gatewayIp ? 'PASS' : 'WARN') : 'FAIL',
      summary: iface ? 'Local IPv4 ' + iface.address + ' on ' + iface.name + '; default gateway ' + (net.gatewayIp || 'not confirmed') : 'No active non-loopback IPv4 interface was available to inspect',
      durationMs
    }];
    const structuredAnswer = {
      result: 'Local host: ' + net.hostname + '. Interface: ' + interfaceLine + '. Subnet: ' + subnet + '. Default gateway: ' + gatewayLine + '. DNS servers: ' + dnsLine + '.',
      meaning: iface && net.gatewayIp
        ? 'These values were read from the running host interfaces and operating-system route table. This reports the EJII backend host, which may differ from the browser device if EJII is accessed remotely or runs in a container.'
        : 'Some network configuration could not be confirmed from the current runtime; EJII has not substituted a guessed gateway or address.',
      nextStep: net.gatewayIp ? 'You can ask “Can you ping the default gateway?” to test ' + net.gatewayIp + '.' : 'Check the host route table and runtime network permissions, then retry.',
      layerFailedFirst: iface ? null : 'Local interface discovery',
      uncertainty: net.gatewayIp ? null : 'No IPv4 default gateway was returned by the operating-system route query.'
    };
    return {
      reply: '**Result:** ' + structuredAnswer.result + '\n\n**Meaning:** ' + structuredAnswer.meaning + '\n\n**Next step:** ' + structuredAnswer.nextStep,
      structuredAnswer,
      steps,
      findings: [
        { label: 'Local IPv4', value: net.localIp || 'Not detected', tone: iface ? 'ok' : 'danger' },
        { label: 'Default Gateway', value: net.gatewayIp || 'Not confirmed', tone: net.gatewayIp ? 'ok' : 'warn' },
        { label: 'DNS Servers', value: dnsLine, tone: net.dnsServers.length ? 'neutral' : 'warn' }
      ],
      technicalEvidence: { tool: 'collectLocalNetworkSnapshot', ...net, observedAt: new Date().toISOString() }
    };
  }

  async _executeGatewayPingScenario(plan, session, signal) {
    this._checkAborted(signal);
    const net = collectLocalNetworkSnapshot();
    const gatewayIp = net.gatewayIp;
    if (!gatewayIp || !isSafeNetworkTarget(gatewayIp)) {
      const structuredAnswer = {
        result: 'EJII could not identify a verified IPv4 default gateway from the operating-system route table, so no ping was sent.',
        meaning: 'Guessing an address such as x.x.x.1 could test the wrong device. The current runtime may not expose a default route.',
        nextStep: 'Ask “check my IP” to inspect available interface and route information, or verify the host route table.',
        layerFailedFirst: 'Default route discovery',
        uncertainty: null
      };
      return {
        reply: '**Result:** ' + structuredAnswer.result + '\n\n**Meaning:** ' + structuredAnswer.meaning + '\n\n**Next step:** ' + structuredAnswer.nextStep,
        structuredAnswer,
        steps: [{ stepNumber: 1, label: 'Reading the OS default route…', tool: 'readDefaultRoute', status: 'FAIL', summary: 'No verified IPv4 default gateway was available; ping was not executed.', durationMs: null }],
        findings: [{ label: 'Default Gateway', value: 'Not detected', tone: 'danger' }],
        technicalEvidence: { tool: 'readDefaultRoute', gatewayIp: null, pingExecuted: false, observedAt: new Date().toISOString() }
      };
    }
    plan.target = gatewayIp;
    plan.explicitTarget = gatewayIp;
    plan.targetValidation = { valid: true, pinnedIp: gatewayIp, resolvedIps: [gatewayIp], isIpLiteral: true };
    const outcome = await this._executePingScenario(plan, session, signal);
    const scopeNote = 'This checks the default gateway from the EJII backend host operating-system route table. If EJII runs remotely or in a cloud container, that gateway is not necessarily the browser user’s home or office router.';
    if (outcome.structuredAnswer) {
      outcome.structuredAnswer.meaning = `${scopeNote} ${outcome.structuredAnswer.meaning || ''}`.trim();
      outcome.reply = `**Result:** ${outcome.structuredAnswer.result || outcome.reply}\n\n**Meaning:** ${outcome.structuredAnswer.meaning}\n\n**Next step:** ${outcome.structuredAnswer.nextStep || 'Retry the gateway check if the route changes.'}`;
    }
    outcome.findings = [{ label: 'Target Role', value: 'Verified OS default gateway', tone: 'neutral' }].concat(outcome.findings || []);
    outcome.technicalEvidence = {
      ...(outcome.technicalEvidence || {}),
      gatewayDiscovery: { gatewayIp, source: net.gatewaySource },
      observedAt: new Date().toISOString()
    };
    return outcome;
  }

  async _executeActiveConnectionsScenario(signal) {
    this._checkAborted(signal);
    const started = performance.now();
    const results = await Promise.allSettled([
      hostDiagnosticsEngine.getSocketList(),
      hostDiagnosticsEngine.getProcessList(300)
    ]);
    this._checkAborted(signal);
    const socketResult = results[0];
    const processResult = results[1];
    const socketError = socketResult.status === 'rejected' ? String(socketResult.reason?.message || socketResult.reason) : null;
    const sockets = socketResult.status === 'fulfilled' && Array.isArray(socketResult.value) ? socketResult.value : [];
    const processes = processResult.status === 'fulfilled' && Array.isArray(processResult.value) ? processResult.value : [];
    const processNames = new Map(processes.filter((p) => p && p.pid != null).map((p) => [String(p.pid), p.name || p.processName || ('PID ' + p.pid)]));
    const active = sockets.filter((s) => String(s.state || '').toUpperCase() === 'ESTABLISHED').map((s) => {
      const local = parseSocketEndpoint(s.local);
      const remote = parseSocketEndpoint(s.remote);
      if (!remote || !remote.port || !remote.address || ['*', '0.0.0.0', '::', ':::', '0:0:0:0:0:0:0:0'].includes(remote.address)) return null;
      const pid = s.pid == null || s.pid === '' ? null : String(s.pid);
      return {
        application: pid ? (processNames.get(pid) || ('PID ' + pid + ' (name unavailable)')) : 'Process attribution unavailable',
        pid: pid ? Number(pid) : null,
        localAddress: local?.address || null,
        localPort: local?.port ?? null,
        destinationIp: remote.address,
        destinationPort: remote.port,
        state: String(s.state || '').toUpperCase()
      };
    }).filter(Boolean).sort((a, b) => a.application.localeCompare(b.application) || a.destinationIp.localeCompare(b.destinationIp) || a.destinationPort - b.destinationPort);
    const durationMs = Number((performance.now() - started).toFixed(2));
    const lines = active.slice(0, 30).map((c) => '- ' + c.application + ' -> ' + c.destinationIp + ':' + c.destinationPort + ' (' + c.state + (c.pid ? ', PID ' + c.pid : '') + ')').join('\n');
    const truncated = active.length > 30 ? '\n- …and ' + (active.length - 30) + ' more connection(s).' : '';
    const scopeNote = 'Collected from the EJII backend host "' + os.hostname() + '". If EJII is accessed from another computer or runs in a container, this is the backend/container network namespace—not necessarily the browser computer’s full socket table.';
    const resultText = socketError
      ? 'The OS socket collector failed: ' + socketError + '. No destination list can be verified.'
      : active.length
        ? 'Found ' + active.length + ' established TCP connection(s). Destination IPs and ports:\n' + lines + truncated
        : 'The OS socket collector returned no established TCP connections with a usable remote IP and port at the time of collection. This does not prove that no apps are using the network; access or container namespace limits may apply.';
    const structuredAnswer = {
      result: resultText,
      meaning: scopeNote,
      nextStep: socketError ? 'Check operating-system permissions and the host diagnostics collector, then retry.' : 'Ask for a specific destination or port to investigate a connection further.',
      layerFailedFirst: socketError ? 'OS socket collection' : null,
      uncertainty: processResult.status === 'rejected'
        ? 'The socket list may be available, but application names could not be collected because process inspection failed.'
        : 'Process names depend on OS permissions and the accuracy of PID attribution provided by the platform collector.'
    };
    return {
      reply: '**Result:** ' + structuredAnswer.result + '\n\n**Meaning:** ' + structuredAnswer.meaning + '\n\n**Next step:** ' + structuredAnswer.nextStep,
      structuredAnswer,
      steps: [{
        stepNumber: 1,
        label: 'Inspecting the current host TCP connection table…',
        tool: 'hostDiagnosticsEngine.getSocketList',
        status: socketError ? 'FAIL' : 'PASS',
        summary: socketError || ('Read ' + sockets.length + ' OS socket record(s); ' + active.length + ' established remote connection(s) had a usable destination.'),
        durationMs
      }],
      findings: [
        { label: 'Established TCP', value: String(active.length), tone: socketError ? 'danger' : 'neutral' },
        { label: 'Host', value: os.hostname(), tone: 'neutral' }
      ],
      technicalEvidence: {
        tool: 'hostDiagnosticsEngine.getSocketList',
        host: os.hostname(),
        socketCount: sockets.length,
        establishedConnections: active,
        processCollectionAvailable: processResult.status === 'fulfilled',
        socketCollectionError: socketError,
        observedAt: new Date().toISOString()
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
            success: true,
            records: r.success && r.records?.length ? r.records : ['127.0.0.1'],
            durationMs: Number((performance.now() - t0).toFixed(2)),
            nameserver: r.nameserver || sysDnsIp
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
      const findings = [
        { label: 'Active Resolver', value: sysDnsIp, tone: 'neutral' },
        { label: 'DNS Connectivity', value: allPassed ? 'HEALTHY' : 'PARTIAL / DEGRADED', tone: allPassed ? 'ok' : 'warn' },
        ...results.map((r) => ({
          label: `DNS (${r.domain})`,
          value: r.success ? `${r.records[0]} (${r.durationMs} ms)` : `FAILED (${r.error})`,
          tone: r.success ? 'ok' : 'danger'
        }))
      ];

      const structuredAnswer = {
        result: `DNS connection check completed in ${totalMs} ms via resolver ${sysDnsIp}: ${results.map((r) => `${r.domain} → ${r.success ? `${r.records[0]} (${r.durationMs} ms)` : `FAILED (${r.error})`}`).join('; ')}.`,
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
          activeResolver: sysDnsIp,
          results,
          observedAt: new Date().toISOString()
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
          success: true,
          records: recordType === 'AAAA' ? ['::1'] : ['127.0.0.1'],
          durationMs: Number((performance.now() - stepStart).toFixed(2)),
          error: null,
          errorCode: null,
          resolverNote: 'Resolved via local hosts table (127.0.0.1)'
        };
      }
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
            durationMs: plan.targetValidation?.resolutionDurationMs ?? null
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
        dnsRes = { success: true, records: plan.targetValidation.resolvedIps, durationMs: Number.isFinite(plan.targetValidation.resolutionDurationMs) ? plan.targetValidation.resolutionDurationMs : null };
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
          ? (Number.isFinite(dnsRes.durationMs) ? `Resolved ${target} → ${resolvedIp} (${dnsRes.durationMs} ms validation elapsed)` : `Resolved ${target} → ${resolvedIp}; timing not recorded`)
          : `DNS resolution failed: ${dnsRes.errorCode || dnsRes.error || 'ENOTFOUND'}`,
        durationMs: Number((performance.now() - t0).toFixed(1))
      });
    } else {
      dnsRes = { success: true, records: [resolvedIp], durationMs: null, lookupSkipped: true };
      steps.push({
        stepNumber: 1,
        label: `Using the direct target address ${target}…`,
        tool: 'direct_target_validation',
        status: 'PASS',
        summary: `Target ${target} uses ${resolvedIp} directly; DNS lookup skipped`,
        durationMs: null
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
    findings.push(isIpLiteral
      ? { label: 'Target Address', value: `${resolvedIp} (direct; DNS skipped)`, tone: 'neutral' }
      : { label: 'DNS', value: `${resolvedIp}${Number.isFinite(dnsRes.durationMs) ? ` (${dnsRes.durationMs} ms validation elapsed)` : ' (timing not recorded)'}`, tone: 'ok' });

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
      const tlsDaysRemaining = Number.isFinite(tlsRes.certificate?.daysRemaining) ? tlsRes.certificate.daysRemaining : null;
      const tlsAuthorized = tlsRes.validation?.authorized === true;
      steps.push({
        stepNumber: 3,
        label: `Verifying TLS handshake and certificate on ${target}:${port}…`,
        tool: 'auditTls',
        status: !tlsRes.success ? 'FAIL' : (tlsAuthorized ? 'PASS' : 'WARN'),
        summary: !tlsRes.success
          ? `TLS handshake failed: ${tlsRes.error || 'Handshake error'}`
          : `${tlsRes.protocol || 'TLS'} (${tlsRes.cipher?.name || 'cipher not reported'}); ${tlsAuthorized ? 'certificate validation passed' : 'certificate validation not trusted/verified'}${tlsDaysRemaining === null ? '' : `; ${tlsDaysRemaining} days until expiry`}`,
        durationMs: Number((performance.now() - t2).toFixed(1))
      });
      findings.push({
        label: 'TLS Security',
        value: !tlsRes.success ? `FAILED (${tlsRes.error || 'Error'})` : `${tlsRes.protocol || 'TLS'} · ${tlsAuthorized ? 'trusted' : 'not trusted'}${tlsDaysRemaining === null ? '' : ` · ${tlsDaysRemaining}d remaining`}`,
        tone: !tlsRes.success ? 'danger' : (tlsAuthorized ? 'ok' : 'warn')
      });
    }

    // Step 4: HTTP Application Probe
    this._checkAborted(signal);
    const t3 = performance.now();
    const httpRes = await probeHttp(urlToProbe, 'GET', 2500);
    const httpTtfbMs = Number.isFinite(httpRes.waterfall?.ttfbMs) ? httpRes.waterfall.ttfbMs : null;
    const httpTotalMs = Number.isFinite(httpRes.waterfall?.totalMs) ? httpRes.waterfall.totalMs : null;
    const httpTtfbLabel = httpTtfbMs === null ? 'not reported' : `${httpTtfbMs} ms`;
    const httpTotalLabel = httpTotalMs === null ? 'not reported' : `${httpTotalMs} ms`;
    steps.push({
      stepNumber: isHttps ? 4 : 3,
      label: `Checking HTTP response from ${urlToProbe}…`,
      tool: 'probeHttp',
      status: httpRes.success ? 'PASS' : (httpRes.statusCode ? 'WARN' : 'FAIL'),
      summary: httpRes.statusCode
        ? `HTTP ${httpRes.statusCode} ${httpRes.statusMessage || ''} (TTFB: ${httpTtfbLabel}, total: ${httpTotalLabel})`
        : `HTTP request failed: ${httpRes.error || 'No HTTP response'}`,
      durationMs: Number((performance.now() - t3).toFixed(1))
    });

    if (httpRes.statusCode) {
      findings.push({
        label: 'HTTP Status',
        value: `${httpRes.statusCode} (${httpTtfbLabel} TTFB)`,
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
      summary: `Website check ${urlToProbe}: HTTP ${httpRes.statusCode || 'FAILED'} (${httpTtfbLabel} TTFB)`
    });

    let structuredAnswer;
    if (httpRes.statusCode && httpRes.statusCode < 400 && (!isHttps || (tlsRes?.success && tlsRes.validation?.authorized === true))) {
      structuredAnswer = {
        result: `${urlToProbe} is online and working — DNS resolved to ${resolvedIp} (${dnsRes.durationMs} ms), TCP port ${port} is OPEN (${tcpRes.latencyMs} ms)${tlsRes?.success ? `, TLS negotiated ${tlsRes.protocol}` : ''}, and HTTP returned ${httpRes.statusCode} in ${httpTtfbMs} ms TTFB.`,
        meaning: `Every layer from DNS and TCP transport through ${isHttps ? 'TLS encryption and ' : ''}HTTP application delivery is healthy.`,
        nextStep: `No infrastructure fault detected. If specific users still report issues, check browser caching or client-side network DNS settings.`,
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
    } else if (isHttps && tlsRes?.success && tlsRes.validation?.authorized !== true) {
      structuredAnswer = {
        result: `DNS and TCP connectivity succeeded for ${target}:${port}, and HTTP returned ${httpRes.statusCode || 'no status'}, but TLS certificate validation was not confirmed as trusted.`,
        meaning: `The TLS handshake completed, but the certificate chain or hostname validation did not pass. HTTP reachability alone does not make the HTTPS endpoint trustworthy.`,
        nextStep: `Inspect the certificate issuer, subject names, validity dates, and trust-chain configuration for ${target}:${port}.`,
        layerFailedFirst: 'L6 TLS Certificate Validation',
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
      durationMs: s.details?.connectLatencyMs ?? s.details?.latencyMs ?? s.details?.durationMs ?? s.details?.avgRttMs ?? s.details?.waterfall?.ttfbMs ?? null
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

    const normalizedStatus = (step) => String(step?.status || '').toUpperCase();
    const firstFailedStep = steps.find((s) => ['FAIL', 'FAILED', 'TIMEOUT', 'ERROR', 'BLOCKED', 'DENIED'].includes(normalizedStatus(s)));
    const firstWarningStep = steps.find((s) => ['WARN', 'WARNING', 'DEGRADED', 'DEGRADED_FINDING', 'PARTIAL'].includes(normalizedStatus(s)));
    const allChecksPassed = steps.length > 0 && steps.every((s) => ['PASS', 'OK', 'COMPLETED'].includes(normalizedStatus(s)));
    const topHyp = wfResult.correlation?.topHypothesis;
    const dnsStep = (wfResult.steps || []).find((s) => s.layer.includes('DNS'));
    const tcpStep = (wfResult.steps || []).find((s) => s.layer.includes('TCP'));
    const icmpStep = (wfResult.steps || []).find((s) => s.layer.includes('ICMP'));
    const httpStep = (wfResult.steps || []).find((s) => s.layer.includes('HTTP'));
    const localNicStep = (wfResult.steps || []).find((s) => s.layer.includes('Local NIC'));
    const gatewayStep = (wfResult.steps || []).find((s) => s.layer.includes('Default Gateway'));
    const localNicConfirmed = localNicStep?.status === 'PASS';
    const gatewayConfirmed = gatewayStep?.status === 'PASS' && Boolean(gatewayStep.details?.gatewayIp);
    const tcpRttMs = tcpStep?.details?.connectLatencyMs ?? tcpStep?.details?.latencyMs ?? null;
    const tcpRttLabel = Number.isFinite(tcpRttMs) ? `${tcpRttMs} ms` : 'latency not reported';

    this._recordEntityMemory(session, target, {
      resolvedIps: wfResult.resolvedIp ? [wfResult.resolvedIp] : [],
      dnsStatus: dnsStep?.status === 'PASS' ? 'OK' : (['FAIL', 'FAILED', 'ERROR', 'TIMEOUT'].includes(normalizedStatus(dnsStep)) ? 'FAILED' : 'UNKNOWN'),
      openPorts: tcpStep?.status === 'PASS' ? [primaryPort] : [],
      closedPorts: tcpStep?.details?.status === 'CLOSED' ? [primaryPort] : [],
      summary: `Cross-layer investigation on ${target}:${primaryPort} (${firstFailedStep ? `Failed at ${firstFailedStep.label}` : allChecksPassed ? 'All checks passed' : firstWarningStep ? `Warnings at ${firstWarningStep.label}` : 'Incomplete or unverified checks'})`
    });

    const findings = [
      { label: 'Target', value: `${target}:${primaryPort}`, tone: 'neutral' },
      {
        label: 'DNS Resolution',
        value: dnsStep?.status === 'PASS' ? `OK (${wfResult.resolvedIp})` : (['FAIL', 'FAILED', 'ERROR', 'TIMEOUT'].includes(normalizedStatus(dnsStep)) ? 'FAILED' : 'NOT CONFIRMED'),
        tone: dnsStep?.status === 'PASS' ? 'ok' : (['FAIL', 'FAILED', 'ERROR', 'TIMEOUT'].includes(normalizedStatus(dnsStep)) ? 'danger' : 'warn')
      }
    ];
    if (tcpStep) {
      findings.push({
        label: `TCP Port ${primaryPort}`,
        value: tcpStep.status === 'PASS' ? `OPEN (${tcpRttLabel})` : (tcpStep.details?.status || 'FAILED'),
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
      resultText = `Multi-step investigation of "${target}" stopped at Layer 7 DNS resolution: ${dnsStep.summary}. ${localNicConfirmed ? 'A local interface IP was detected.' : 'The local interface IP was not confirmed.'} ${gatewayConfirmed ? 'The OS default route reported gateway ' + gatewayStep.details.gatewayIp + '.' : 'The OS default gateway route was not confirmed.'}`;
      meaningText = `DNS resolution failed for "${target}". The local NIC and gateway are reported separately above; this evidence does not prove that both are healthy. Without a resolved target IP, the target-specific TCP and HTTP checks cannot start.`;
      nextStepText = `Check whether "${target}" is spelled correctly, inspect the configured DNS resolver, verify its A/AAAA records, or test with the server's direct IP address.`;
    } else if (tcpStep && tcpStep.status === 'FAIL') {
      const tcpStatus = tcpStep.details?.status || 'UNREACHABLE';
      const anyExtraOpen = extraPortResults.find((e) => e.status === 'OPEN');
      if (tcpStatus === 'CLOSED') {
        resultText = `DNS resolved "${target}" to ${wfResult.resolvedIp} and the host is reachable on the network, but TCP port ${primaryPort} actively refused the connection (ECONNREFUSED / TCP RST)${anyExtraOpen ? ` while port ${anyExtraOpen.port} is OPEN` : ''}.`;
        meaningText = `Network routing and DNS are working properly. The failure is isolated to Layer 4 on ${wfResult.resolvedIp}: no service process is listening on TCP port ${primaryPort}.`;
        nextStepText = `Start or restart the application daemon expected on port ${primaryPort} on ${target}${anyExtraOpen ? `, or connect via open port ${anyExtraOpen.port}` : ''}.`;
      } else {
        resultText = `DNS resolved "${target}" to ${wfResult.resolvedIp}; ${localNicConfirmed ? 'the local interface IP was detected' : 'the local interface IP was not confirmed'}; ${gatewayConfirmed ? 'an OS default route was observed via ' + gatewayStep.details.gatewayIp : 'the OS default gateway route was not confirmed'}; TCP port ${primaryPort} timed out (${tcpStatus})${icmpStep?.status === 'PASS' ? ' while ICMP replied' : ''}.`;
        meaningText = icmpStep?.status === 'PASS'
          ? `The host at ${wfResult.resolvedIp} responded to ICMP, but the TCP connection timed out. This is consistent with filtering or a path/service policy issue, but it does not prove that a firewall is silently dropping traffic.`
          : `Neither ICMP ping nor TCP port ${primaryPort} received a response from ${wfResult.resolvedIp}. The host may be offline, routing may be broken, or traffic may be filtered; these signals do not distinguish those causes conclusively.`;
        nextStepText = `Verify reachability to ${target} (${wfResult.resolvedIp}) and inspect the route and network policies for TCP port ${primaryPort}.`;
        uncertaintyText = icmpStep?.status === 'PASS'
          ? 'A TCP timeout can result from filtering, routing/ACL policy, an asymmetric path, or endpoint problems; more evidence is needed to confirm a firewall drop.'
          : 'When both ICMP and TCP time out silently without a TCP RST, an offline host, a routing issue, and remote filtering can produce similar symptoms.';
      }
    } else if (firstWarningStep || !allChecksPassed) {
      const warningSummary = steps
        .filter((s) => !['PASS', 'OK', 'COMPLETED'].includes(normalizedStatus(s)))
        .map((s) => `${s.label.replace(/…$/, '')}: ${s.status}`)
        .slice(0, 4)
        .join('; ');
      resultText = firstFailedStep
        ? `The investigation of ${target}:${primaryPort} found a failed check: ${firstFailedStep.label.replace(/…$/, '')} (${firstFailedStep.status}).`
        : `The investigation of ${target}:${primaryPort} completed with warning(s): ${warningSummary || 'one or more checks were not confirmed PASS'}.`;
      meaningText = 'Not every diagnostic check passed. A warning or failure means the corresponding layer was not fully verified; it is not sufficient by itself to prove that the host or service is offline.';
      nextStepText = firstFailedStep
        ? `Investigate ${firstFailedStep.label.replace(/…$/, '')} first, then repeat the affected check.`
        : 'Review the warning(s), especially ICMP filtering and TLS certificate validation, and run a targeted check for the affected layer.';
      layerFailedFirst = firstFailedStep ? firstFailedStep.label.replace(/…$/, '') : (firstWarningStep ? firstWarningStep.label.replace(/…$/, '') : layerFailedFirst);
      uncertaintyText = 'A warning means a check was inconclusive or had a validation issue; do not treat it as a confirmed outage without supporting evidence.';
    } else {
      resultText = `All ${steps.length} executed diagnostic checks for ${target}:${primaryPort} returned PASS — DNS resolved to ${wfResult.resolvedIp}, and TCP port ${primaryPort} is OPEN (${tcpRttLabel})${httpStep?.details?.statusCode ? ` with HTTP ${httpStep.details.statusCode}` : ''}.`;
      meaningText = 'All executed checks returned PASS. This supports normal connectivity for the tested layers, but does not guarantee that every application feature is healthy.';
      nextStepText = 'If users still experience slowness or intermittent errors, test the affected application endpoint or inspect its server-side logs.';
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
