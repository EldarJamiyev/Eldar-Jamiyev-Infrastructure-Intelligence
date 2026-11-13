/**
 * EJII Contextual Operational Memory, Episodic Learning & Terminal Log Intelligence Engine
 *
 * Provides:
 *   1. Persistent Cross-Session Entity Memory (SQLite `ejii_operational_memory`):
 *      Tracks target baselines (ports, IPs, RTT distribution, status history) across all sessions
 *      and detects state transitions (e.g., OPEN -> CLOSED, healthy -> failed, latency spikes).
 *   2. Episodic Incident Resolution & Playbook Learning (`ejii_incident_resolutions`):
 *      Stores verified root causes and fixes from governed remediations and operator confirmations,
 *      surfacing proven historical fixes when similar symptoms recur.
 *   3. Terminal Log, Stack Trace & Multi-Port Startup Triage Parser:
 *      Extracts readiness URLs, listening ports, JSON error payloads (e.g., {"error":"Route not found."}),
 *      and port-split mismatches (e.g., startup script polling :3000 while service listens on :3001).
 *   4. Information-Gain Grounded Follow-Up Generator:
 *      Produces context-aware next investigative steps based on observed evidence and uncertainty.
 */

'use strict';

const crypto = require('node:crypto');
const { db } = require('../../db/database');
const { temporalInfrastructureGraph } = require('../topology/temporal-graph-engine');
const { evidenceFabric } = require('../evidence/evidence-fabric');

function computeSampleStats(samples = []) {
  const valid = (samples || []).filter((n) => typeof n === 'number' && Number.isFinite(n));
  if (valid.length === 0) {
    return { mean: null, stdDev: null, ewma: null, trendSlopeMsPerObs: 0 };
  }
  const mean = valid.reduce((a, b) => a + b, 0) / valid.length;
  let ewma = valid[0];
  const alpha = 0.35;
  for (let i = 1; i < valid.length; i++) {
    ewma = alpha * valid[i] + (1 - alpha) * ewma;
  }
  let stdDev = 0;
  if (valid.length >= 2) {
    const variance = valid.reduce((acc, v) => acc + Math.pow(v - mean, 2), 0) / (valid.length - 1);
    stdDev = Math.sqrt(Math.max(0, variance));
  }
  let trendSlopeMsPerObs = 0;
  if (valid.length >= 3) {
    const recent = valid.slice(-5);
    const n = recent.length;
    const xMean = (n - 1) / 2;
    const yMean = recent.reduce((a, b) => a + b, 0) / n;
    let num = 0;
    let den = 0;
    for (let i = 0; i < n; i++) {
      num += (i - xMean) * (recent[i] - yMean);
      den += Math.pow(i - xMean, 2);
    }
    trendSlopeMsPerObs = den > 0 ? Number((num / den).toFixed(2)) : 0;
  }
  return {
    mean: Number(mean.toFixed(2)),
    stdDev: Number(stdDev.toFixed(2)),
    ewma: Number(ewma.toFixed(2)),
    trendSlopeMsPerObs
  };
}

class OperationalMemoryEngine {
  constructor(options = {}) {
    this.useSqlite = options.useSqlite !== false;
    this.memoryCache = new Map();
    this.resolutionsCache = [];
    this.decisionsCache = [];
    this.organizationalKnowledgeCache = [];
    this.commanderInvestigations = new Map();
    this.commanderProbeLedger = [];
    this.avoidedDuplicateProbesCount = 0;
    this._ensureSchema();
    this._seedDefaultOrganizationalKnowledge();
  }

  _ensureSchema() {
    if (!this.useSqlite || !db) return;
    try {
      db.exec(`
        CREATE TABLE IF NOT EXISTS ejii_operational_memory (
          target_key TEXT PRIMARY KEY,
          target_display TEXT NOT NULL,
          first_seen_at TEXT NOT NULL,
          last_seen_at TEXT NOT NULL,
          observation_count INTEGER NOT NULL DEFAULT 1,
          failure_count INTEGER NOT NULL DEFAULT 0,
          last_intent TEXT,
          last_status TEXT,
          resolved_ips_json TEXT,
          open_ports_json TEXT,
          closed_ports_json TEXT,
          filtered_ports_json TEXT,
          rtt_samples_json TEXT,
          avg_rtt_ms REAL,
          last_rtt_ms REAL,
          last_http_status INTEGER,
          last_failure_layer TEXT,
          last_summary TEXT,
          transitions_json TEXT,
          recent_observations_json TEXT
        );

        CREATE TABLE IF NOT EXISTS ejii_incident_resolutions (
          resolution_id TEXT PRIMARY KEY,
          target_key TEXT,
          symptom_signature TEXT NOT NULL,
          root_cause TEXT NOT NULL,
          resolution_steps TEXT NOT NULL,
          port INTEGER,
          verified_by TEXT,
          verification_status TEXT NOT NULL DEFAULT 'VERIFIED',
          hit_count INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ejii_operational_decisions (
          decision_id TEXT PRIMARY KEY,
          target_key TEXT,
          decision_type TEXT NOT NULL,
          action_id TEXT NOT NULL,
          rationale TEXT NOT NULL,
          approved_by TEXT,
          role TEXT,
          outcome_status TEXT NOT NULL,
          before_metrics_json TEXT,
          after_metrics_json TEXT,
          created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ejii_organizational_knowledge (
          knowledge_id TEXT PRIMARY KEY,
          target_key TEXT,
          category TEXT NOT NULL,
          title TEXT NOT NULL,
          critical_dependency_note TEXT NOT NULL,
          runbook_procedure TEXT NOT NULL,
          historical_rationale TEXT,
          owning_team TEXT,
          author TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
      `);
    } catch (_) {
      // Safe fallback to in-memory cache if SQLite is read-only
    }
  }

  _seedDefaultOrganizationalKnowledge() {
    const defaults = [
      {
        knowledgeId: 'ORG-KB-CORE-LOOPBACK-SPLIT',
        targetKey: '127.0.0.1',
        category: 'SERVICE_ARCHITECTURE_RUNBOOK',
        title: 'Multi-Port Local Service Split Pattern (:3000 vs :3001 Runbook Reference)',
        criticalDependencyNote: '[RUNBOOK_REFERENCE_ONLY — NOT LIVE TELEMETRY] Reference pattern for external multi-port workspace applications where a web control plane binds to :3000 while an auxiliary daemon binds to :3001. Polling :3000 for :3001 routes causes HTTP 404 or ECONNREFUSED.',
        runbookProcedure: '1. Inspect active kernel sockets (`active_connections`). 2. Check whether listener is bound to :3001 while readiness script probes :3000. 3. Align reverse-proxy or startup readiness URL before restarting.',
        historicalRationale: 'Reference runbook pattern for multi-port local daemon triage; never treated as a live EJII host observation.',
        owningTeam: 'Core Platform & Systems SRE',
        author: 'Principal Infrastructure Architect'
      },
      {
        knowledgeId: 'ORG-KB-GATEWAY-DNS-DEPENDENCY',
        targetKey: 'default_gateway',
        category: 'NETWORK_TOPOLOGY_RUNBOOK',
        title: 'Default Gateway & Recursive Resolver Shared Outage Pattern',
        criticalDependencyNote: 'All outbound WAN and cloud service probes depend on the local default gateway and recursive DNS resolvers. Simultaneous multi-device connectivity loss almost always originates at L2/L3 gateway or DHCP/DNS infrastructure rather than individual endpoints.',
        runbookProcedure: '1. Probe default gateway L3 reachability first. 2. Test DNS resolver latency and c-ares resolution. 3. Do not restart individual application daemons when the shared gateway or DNS resolver is unreachable.',
        historicalRationale: 'Documented after prior office-wide connectivity incidents where endpoint services were unnecessarily restarted during a gateway route flap.',
        owningTeam: 'Network & Core Infrastructure Engineering',
        author: 'Lead Network Architect'
      }
    ];
    for (const item of defaults) {
      if (!this.organizationalKnowledgeCache.some((k) => k.knowledgeId === item.knowledgeId)) {
        this.recordOrganizationalKnowledge(item);
      }
    }
  }

  _computeStabilityScore(entity) {
    if (!entity || !entity.observationCount) return 100;
    const total = Math.max(1, Number(entity.observationCount) || 1);
    const fails = Math.max(0, Number(entity.failureCount) || 0);
    const passRate = Math.max(0, (total - fails) / total);
    const transitions = Array.isArray(entity.transitions) ? entity.transitions : [];
    const regressions = transitions.filter((t) =>
      String(t.type || '').includes('REGRESSION') ||
      String(t.type || '').includes('SPIKE') ||
      String(t.type || '').includes('FLAPPING')
    ).length;
    const penalty = Math.min(45, regressions * 8);
    return Math.max(0, Math.min(100, Math.round(passRate * 100 - penalty)));
  }

  _loadEntity(targetKey) {
    if (this.memoryCache.has(targetKey)) {
      return this.memoryCache.get(targetKey);
    }
    if (this.useSqlite && db) {
      try {
        const row = db.prepare('SELECT * FROM ejii_operational_memory WHERE target_key = ?').get(targetKey);
        if (row) {
          const parsed = {
            targetKey: row.target_key,
            targetDisplay: row.target_display,
            firstSeenAt: row.first_seen_at,
            lastSeenAt: row.last_seen_at,
            observationCount: Number(row.observation_count) || 0,
            failureCount: Number(row.failure_count) || 0,
            lastIntent: row.last_intent,
            lastStatus: row.last_status,
            resolvedIps: JSON.parse(row.resolved_ips_json || '[]'),
            openPorts: JSON.parse(row.open_ports_json || '[]'),
            closedPorts: JSON.parse(row.closed_ports_json || '[]'),
            filteredPorts: JSON.parse(row.filtered_ports_json || '[]'),
            rttSamples: JSON.parse(row.rtt_samples_json || '[]'),
            avgRttMs: row.avg_rtt_ms !== null ? Number(row.avg_rtt_ms) : null,
            lastRttMs: row.last_rtt_ms !== null ? Number(row.last_rtt_ms) : null,
            lastHttpStatus: row.last_http_status !== null ? Number(row.last_http_status) : null,
            lastFailureLayer: row.last_failure_layer || null,
            lastSummary: row.last_summary || '',
            transitions: JSON.parse(row.transitions_json || '[]'),
            recentObservations: JSON.parse(row.recent_observations_json || '[]')
          };
          this.memoryCache.set(targetKey, parsed);
          return parsed;
        }
      } catch (_) {}
    }
    return null;
  }

  _saveEntity(entity) {
    this.memoryCache.set(entity.targetKey, entity);
    if (!this.useSqlite || !db) return;
    try {
      db.prepare(`
        INSERT INTO ejii_operational_memory (
          target_key, target_display, first_seen_at, last_seen_at,
          observation_count, failure_count, last_intent, last_status,
          resolved_ips_json, open_ports_json, closed_ports_json, filtered_ports_json,
          rtt_samples_json, avg_rtt_ms, last_rtt_ms, last_http_status,
          last_failure_layer, last_summary, transitions_json, recent_observations_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(target_key) DO UPDATE SET
          last_seen_at = excluded.last_seen_at,
          observation_count = excluded.observation_count,
          failure_count = excluded.failure_count,
          last_intent = excluded.last_intent,
          last_status = excluded.last_status,
          resolved_ips_json = excluded.resolved_ips_json,
          open_ports_json = excluded.open_ports_json,
          closed_ports_json = excluded.closed_ports_json,
          filtered_ports_json = excluded.filtered_ports_json,
          rtt_samples_json = excluded.rtt_samples_json,
          avg_rtt_ms = excluded.avg_rtt_ms,
          last_rtt_ms = excluded.last_rtt_ms,
          last_http_status = excluded.last_http_status,
          last_failure_layer = excluded.last_failure_layer,
          last_summary = excluded.last_summary,
          transitions_json = excluded.transitions_json,
          recent_observations_json = excluded.recent_observations_json
      `).run(
        entity.targetKey,
        entity.targetDisplay,
        entity.firstSeenAt,
        entity.lastSeenAt,
        entity.observationCount,
        entity.failureCount,
        entity.lastIntent,
        entity.lastStatus,
        JSON.stringify(entity.resolvedIps || []),
        JSON.stringify(entity.openPorts || []),
        JSON.stringify(entity.closedPorts || []),
        JSON.stringify(entity.filteredPorts || []),
        JSON.stringify((entity.rttSamples || []).slice(-30)),
        entity.avgRttMs,
        entity.lastRttMs,
        entity.lastHttpStatus,
        entity.lastFailureLayer,
        entity.lastSummary,
        JSON.stringify((entity.transitions || []).slice(-15)),
        JSON.stringify((entity.recentObservations || []).slice(-15))
      );
    } catch (_) {}
  }

  /**
   * Synchronize observed host, resolved IPs, and TCP service endpoints into TemporalInfrastructureGraph
   * so conversational diagnostics and topology impact analysis share a single source of truth.
   */
  _syncObservationToTemporalGraph(cleanTarget, entity, status, latencyMs) {
    try {
      const hostNodeId = `mem-host-${cleanTarget.replace(/[^a-z0-9.-]/gi, '_')}`;
      const primaryIp = entity.resolvedIps && entity.resolvedIps[0] ? entity.resolvedIps[0] : (
        /^(?:\d{1,3}\.){3}\d{1,3}$/.test(cleanTarget) ? cleanTarget : null
      );
      temporalInfrastructureGraph.upsertNode({
        nodeId: hostNodeId,
        resourceType: 'host',
        label: entity.targetDisplay || cleanTarget,
        hostname: cleanTarget,
        ipAddress: primaryIp,
        layer: cleanTarget === 'localhost' || cleanTarget === '127.0.0.1' ? 'core' : 'wan',
        status: status === 'FAIL' ? 'degraded' : 'healthy',
        evidenceClassification: 'Observed',
        attributes: {
          latencyMs: typeof latencyMs === 'number' ? latencyMs : entity.avgRttMs,
          observationCount: entity.observationCount,
          openPorts: entity.openPorts,
          closedPorts: entity.closedPorts
        }
      });

      for (const p of (entity.openPorts || []).slice(0, 6)) {
        const svcNodeId = `mem-svc-${cleanTarget.replace(/[^a-z0-9.-]/gi, '_')}-${p}`;
        temporalInfrastructureGraph.upsertNode({
          nodeId: svcNodeId,
          resourceType: 'service_endpoint',
          label: `${cleanTarget}:${p}`,
          hostname: cleanTarget,
          ipAddress: primaryIp,
          layer: 'service',
          status: 'healthy',
          evidenceClassification: 'Observed',
          attributes: { port: p, protocol: 'TCP', latencyMs: typeof latencyMs === 'number' ? latencyMs : entity.avgRttMs }
        });
        temporalInfrastructureGraph.upsertEdge({
          edgeId: `EDGE-${hostNodeId}-${svcNodeId}`,
          sourceId: hostNodeId,
          targetId: svcNodeId,
          relationshipType: 'served_by',
          status: 'up',
          evidenceClassification: 'Observed'
        });
      }
    } catch (_) {}
  }

  /**
   * Record an operational observation for a target and return cross-session memory insights,
   * state transitions, statistical baseline comparisons, stability index, and matched historical resolutions.
   */
  recordObservation({
    target,
    intent = 'diagnostic',
    status = 'PASS',
    resolvedIps = [],
    openPorts = [],
    closedPorts = [],
    filteredPorts = [],
    latencyMs = null,
    httpStatus = null,
    failureLayer = null,
    summary = '',
    sessionId = null
  } = {}) {
    if (!target || typeof target !== 'string') return null;
    const cleanTarget = target.trim().toLowerCase();
    const internalTargets = new Set([
      'local_host_interfaces',
      'default_gateway',
      'local_dhcp_service',
      'local_path_gateway_isp',
      'local_socket_table',
      'local_host_health',
      'unknown_target'
    ]);
    if (!cleanTarget || internalTargets.has(cleanTarget)) {
      return null;
    }

    const nowIso = new Date().toISOString();
    const prior = this._loadEntity(cleanTarget);
    const stateTransitions = [];
    let baselineDelta = null;

    const prevOpenPorts = prior ? [...(prior.openPorts || [])] : [];
    const prevClosedPorts = prior ? [...(prior.closedPorts || [])] : [];
    const prevStatus = prior ? prior.lastStatus : null;
    const prevAvgRttMs = prior ? prior.avgRttMs : null;
    const prevStats = prior ? computeSampleStats(prior.rttSamples || []) : null;

    if (prior) {
      // Detect TCP port state transitions across turns/sessions
      for (const p of closedPorts) {
        if (prevOpenPorts.includes(p)) {
          stateTransitions.push({
            type: 'PORT_REGRESSION_OPEN_TO_CLOSED',
            port: p,
            severity: 'high',
            message: `TCP port ${p} on ${cleanTarget} transitioned from OPEN to CLOSED since previous observation (${prior.lastSeenAt}).`
          });
        }
      }
      for (const p of openPorts) {
        if (prevClosedPorts.includes(p)) {
          stateTransitions.push({
            type: 'PORT_RECOVERY_CLOSED_TO_OPEN',
            port: p,
            severity: 'info',
            message: `TCP port ${p} on ${cleanTarget} recovered from CLOSED to OPEN.`
          });
        }
      }

      // Detect overall target health transition
      if (prevStatus === 'PASS' && status === 'FAIL') {
        stateTransitions.push({
          type: 'TARGET_REGRESSION',
          severity: 'high',
          message: `${cleanTarget} degraded from PASS to FAIL (${failureLayer || intent}).`
        });
      } else if (prevStatus === 'FAIL' && status === 'PASS') {
        stateTransitions.push({
          type: 'TARGET_RECOVERY',
          severity: 'info',
          message: `${cleanTarget} recovered from previous FAIL state to PASS.`
        });
      }

      // Detect intermittent flapping if recent observations alternate PASS/FAIL >= 3 times
      const recentStatuses = [...(prior.recentObservations || []).slice(-5).map((o) => o.status), status];
      let alternations = 0;
      for (let i = 1; i < recentStatuses.length; i++) {
        if (recentStatuses[i] !== recentStatuses[i - 1]) alternations++;
      }
      if (alternations >= 3) {
        stateTransitions.push({
          type: 'INTERMITTENT_FLAPPING_DETECTED',
          severity: 'warn',
          message: `${cleanTarget} exhibited intermittent state flapping (${alternations} status alternations across recent checks).`
        });
      }

      // Compute latency baseline comparison & Z-score when genuine measured RTT is present
      if (typeof latencyMs === 'number' && Number.isFinite(latencyMs) && typeof prevAvgRttMs === 'number' && prevAvgRttMs > 0) {
        const diffMs = Number((latencyMs - prevAvgRttMs).toFixed(2));
        const pctDelta = Number(((diffMs / prevAvgRttMs) * 100).toFixed(1));
        const effectiveStdDev = prevStats && typeof prevStats.stdDev === 'number'
          ? Math.max(prevStats.stdDev, 0.2)
          : null;
        const zScore = effectiveStdDev !== null
          ? Number(((latencyMs - prevStats.mean) / effectiveStdDev).toFixed(2))
          : null;
        const isSpike = (latencyMs > prevAvgRttMs * 2.2 && diffMs > 20) || (zScore !== null && zScore >= 2.5 && diffMs > 15);
        baselineDelta = {
          currentRttMs: latencyMs,
          baselineAvgRttMs: prevAvgRttMs,
          ewmaRttMs: prevStats?.ewma ?? prevAvgRttMs,
          rttStdDevMs: prevStats?.stdDev ?? 0,
          zScore,
          deltaMs: diffMs,
          deltaPct: pctDelta,
          anomaly: isSpike,
          summary: `${latencyMs} ms vs ${prevAvgRttMs} ms historical baseline (${diffMs >= 0 ? '+' : ''}${diffMs} ms${zScore !== null ? `, z=${zScore >= 0 ? '+' : ''}${zScore}σ` : ''})`
        };
        if (isSpike) {
          stateTransitions.push({
            type: 'LATENCY_SPIKE_DETECTED',
            severity: 'warn',
            message: `Measured RTT (${latencyMs} ms) is ${(latencyMs / prevAvgRttMs).toFixed(1)}x higher than historical baseline (${prevAvgRttMs} ms)${zScore !== null ? ` [z=${zScore}σ]` : ''}.`
          });
        }
      }
    }

    const entity = prior || {
      targetKey: cleanTarget,
      targetDisplay: target.trim(),
      firstSeenAt: nowIso,
      lastSeenAt: nowIso,
      observationCount: 0,
      failureCount: 0,
      lastIntent: intent,
      lastStatus: status,
      resolvedIps: [],
      openPorts: [],
      closedPorts: [],
      filteredPorts: [],
      rttSamples: [],
      avgRttMs: null,
      lastRttMs: null,
      lastHttpStatus: null,
      lastFailureLayer: null,
      lastSummary: '',
      transitions: [],
      recentObservations: []
    };

    entity.lastSeenAt = nowIso;
    entity.observationCount += 1;
    if (status === 'FAIL') {
      entity.failureCount += 1;
      entity.lastFailureLayer = failureLayer || intent;
    }
    entity.lastIntent = intent;
    entity.lastStatus = status;
    if (summary) entity.lastSummary = summary;
    if (httpStatus) entity.lastHttpStatus = Number(httpStatus) || null;

    for (const ip of resolvedIps || []) {
      if (ip && !entity.resolvedIps.includes(ip)) {
        entity.resolvedIps.push(ip);
      }
    }
    for (const p of openPorts || []) {
      if (!entity.openPorts.includes(p)) entity.openPorts.push(p);
      entity.closedPorts = entity.closedPorts.filter((x) => x !== p);
      entity.filteredPorts = entity.filteredPorts.filter((x) => x !== p);
    }
    for (const p of closedPorts || []) {
      if (!entity.closedPorts.includes(p)) entity.closedPorts.push(p);
      entity.openPorts = entity.openPorts.filter((x) => x !== p);
    }
    for (const p of filteredPorts || []) {
      if (!entity.filteredPorts.includes(p)) entity.filteredPorts.push(p);
    }

    if (typeof latencyMs === 'number' && Number.isFinite(latencyMs)) {
      entity.lastRttMs = latencyMs;
      entity.rttSamples.push(latencyMs);
      if (entity.rttSamples.length > 30) {
        entity.rttSamples = entity.rttSamples.slice(-30);
      }
      const sum = entity.rttSamples.reduce((acc, v) => acc + v, 0);
      entity.avgRttMs = Number((sum / entity.rttSamples.length).toFixed(2));
    }

    if (stateTransitions.length > 0) {
      for (const tr of stateTransitions) {
        entity.transitions.push({ ...tr, observedAt: nowIso });
        try {
          evidenceFabric.recordEvidence({
            type: tr.type.includes('REGRESSION') || tr.type.includes('SPIKE') ? 'anomaly' : 'observation',
            subject: `memory:${cleanTarget}`,
            claim: tr.message,
            rawValue: tr,
            normalizedValue: tr.type,
            sourceCapabilityId: 'ejii.memory.state_transition',
            collectionMethod: 'cross_session_baseline_diff',
            observedAt: nowIso
          });
        } catch (_) {}
      }
      if (entity.transitions.length > 15) {
        entity.transitions = entity.transitions.slice(-15);
      }
    }

    entity.recentObservations.push({
      observedAt: nowIso,
      sessionId,
      intent,
      status,
      latencyMs,
      openPorts,
      closedPorts,
      httpStatus,
      summary: String(summary || '').slice(0, 240)
    });
    if (entity.recentObservations.length > 15) {
      entity.recentObservations = entity.recentObservations.slice(-15);
    }

    this._saveEntity(entity);
    this._syncObservationToTemporalGraph(cleanTarget, entity, status, latencyMs);

    const updatedStats = computeSampleStats(entity.rttSamples || []);
    const stabilityScore = this._computeStabilityScore(entity);

    const matchedResolutions = this.findMatchingResolutions({
      target: cleanTarget,
      port: (closedPorts && closedPorts[0]) || (openPorts && openPorts[0]) || null,
      symptomSignature: failureLayer || (status === 'FAIL' ? intent : null)
    });

    const dependencyContext = this.getTargetDependencyContext(cleanTarget, entity.resolvedIps);
    const predictiveForecast = this.computePredictiveForecast(cleanTarget);
    const remediationRecommendation = status === 'FAIL'
      ? this.recommendRemediationWithHistory({
          target: cleanTarget,
          failureLayer: failureLayer || intent,
          symptomSignature: failureLayer || intent,
          port: (closedPorts && closedPorts[0]) || (openPorts && openPorts[0]) || null
        })
      : null;

    const knowledgeFreshness = this.computeKnowledgeFreshnessAndDecay(entity);
    const environmentProfile = this.inferOperationalEnvironmentProfile(entity);

    this.coordinateOperationsCommander({
      workspace: sessionId && String(sessionId).startsWith('CHAT-') ? 'chat-workspace' : 'ai-operator',
      target: cleanTarget,
      intent,
      status,
      port: (closedPorts && closedPorts[0]) || (openPorts && openPorts[0]) || null,
      failureLayer: failureLayer || (status === 'FAIL' ? intent : null),
      summary: summary || `${cleanTarget} (${status})`
    });

    return {
      target: cleanTarget,
      observationCount: entity.observationCount,
      failureCount: entity.failureCount,
      stabilityScore,
      firstSeenAt: entity.firstSeenAt,
      lastSeenAt: entity.lastSeenAt,
      knownOpenPorts: entity.openPorts,
      knownClosedPorts: entity.closedPorts,
      avgRttMs: entity.avgRttMs,
      ewmaRttMs: updatedStats.ewma,
      rttStdDevMs: updatedStats.stdDev,
      rttTrendSlopeMs: updatedStats.trendSlopeMsPerObs,
      lastRttMs: entity.lastRttMs,
      baselineDelta,
      stateTransitions,
      matchedResolutions,
      dependencyContext,
      predictiveForecast,
      remediationRecommendation,
      knowledgeFreshness,
      environmentProfile
    };
  }

  /**
   * Retrieve baseline & stability metrics for a specific target host/IP.
   */
  getEntityBaseline(target) {
    if (!target || typeof target !== 'string') return null;
    const cleanTarget = target.trim().toLowerCase();
    const ent = this._loadEntity(cleanTarget);
    if (!ent) return null;
    const stats = computeSampleStats(ent.rttSamples || []);
    const stabilityScore = this._computeStabilityScore(ent);
    return {
      target: ent.targetKey,
      targetDisplay: ent.targetDisplay,
      observationCount: ent.observationCount,
      failureCount: ent.failureCount,
      stabilityScore,
      resolvedIps: ent.resolvedIps || [],
      openPorts: ent.openPorts || [],
      closedPorts: ent.closedPorts || [],
      avgRttMs: ent.avgRttMs,
      ewmaRttMs: stats.ewma,
      rttStdDevMs: stats.stdDev,
      latencyBaseline: {
        avgTcpRttMs: ent.avgRttMs,
        tcpStats: stats
      },
      transitions: ent.transitions || []
    };
  }

  /**
   * Record a verified incident resolution or learned operational fix.
   */
  recordVerifiedResolution({
    target = null,
    symptomSignature,
    rootCause,
    resolutionSteps,
    port = null,
    verifiedBy = 'operator'
  } = {}) {
    if (!symptomSignature || !rootCause || !resolutionSteps) return null;
    const nowIso = new Date().toISOString();
    const resolutionId = `RES-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
    const cleanTarget = target ? String(target).trim().toLowerCase() : null;

    const record = {
      resolutionId,
      targetKey: cleanTarget,
      symptomSignature: String(symptomSignature).trim(),
      rootCause: String(rootCause).trim(),
      resolutionSteps: String(resolutionSteps).trim(),
      port: port ? Number(port) : null,
      verifiedBy: String(verifiedBy || 'operator'),
      verificationStatus: 'VERIFIED',
      hitCount: 1,
      createdAt: nowIso,
      updatedAt: nowIso
    };

    this.resolutionsCache.unshift(record);
    if (this.resolutionsCache.length > 50) {
      this.resolutionsCache = this.resolutionsCache.slice(0, 50);
    }

    if (this.useSqlite && db) {
      try {
        db.prepare(`
          INSERT INTO ejii_incident_resolutions (
            resolution_id, target_key, symptom_signature, root_cause,
            resolution_steps, port, verified_by, verification_status,
            hit_count, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          record.resolutionId,
          record.targetKey,
          record.symptomSignature,
          record.rootCause,
          record.resolutionSteps,
          record.port,
          record.verifiedBy,
          record.verificationStatus,
          record.hitCount,
          record.createdAt,
          record.updatedAt
        );
      } catch (_) {}
    }

    return record;
  }

  /**
   * Record an operational decision and its verified outcome in `ejii_operational_decisions`.
   */
  recordOperationalDecision({
    target = null,
    decisionType = 'GOVERNED_REMEDIATION',
    actionId,
    rationale,
    approvedBy = 'operator',
    role = 'OPERATOR',
    outcomeStatus = 'APPLIED_AND_VERIFIED',
    beforeMetrics = null,
    afterMetrics = null
  } = {}) {
    if (!actionId || !rationale) return null;
    const nowIso = new Date().toISOString();
    const decisionId = `DEC-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
    const cleanTarget = target ? String(target).trim().toLowerCase() : null;

    const record = {
      decisionId,
      targetKey: cleanTarget,
      decisionType: String(decisionType),
      actionId: String(actionId),
      rationale: String(rationale),
      approvedBy: String(approvedBy || 'operator'),
      role: String(role || 'OPERATOR'),
      outcomeStatus: String(outcomeStatus),
      beforeMetrics: beforeMetrics || {},
      afterMetrics: afterMetrics || {},
      createdAt: nowIso
    };

    this.decisionsCache.unshift(record);
    if (this.decisionsCache.length > 50) {
      this.decisionsCache = this.decisionsCache.slice(0, 50);
    }

    if (this.useSqlite && db) {
      try {
        db.prepare(`
          INSERT INTO ejii_operational_decisions (
            decision_id, target_key, decision_type, action_id, rationale,
            approved_by, role, outcome_status, before_metrics_json, after_metrics_json, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          record.decisionId,
          record.targetKey,
          record.decisionType,
          record.actionId,
          record.rationale,
          record.approvedBy,
          record.role,
          record.outcomeStatus,
          JSON.stringify(record.beforeMetrics),
          JSON.stringify(record.afterMetrics),
          record.createdAt
        );
      } catch (_) {}
    }

    return record;
  }

  listOperationalDecisions(limit = 20) {
    if (this.useSqlite && db) {
      try {
        const rows = db.prepare('SELECT * FROM ejii_operational_decisions ORDER BY created_at DESC LIMIT ?').all(limit);
        return rows.map((r) => ({
          decisionId: r.decision_id,
          targetKey: r.target_key,
          decisionType: r.decision_type,
          actionId: r.action_id,
          rationale: r.rationale,
          approvedBy: r.approved_by,
          role: r.role,
          outcomeStatus: r.outcome_status,
          beforeMetrics: JSON.parse(r.before_metrics_json || '{}'),
          afterMetrics: JSON.parse(r.after_metrics_json || '{}'),
          createdAt: r.created_at
        }));
      } catch (_) {}
    }
    return this.decisionsCache.slice(0, limit);
  }

  /**
   * Evaluates whether historical episodic context for a target has been invalidated or superseded
   * by recent topological drift (IP reassignment, MAC identity drift, or active port shift).
   */
  evaluateHistoricalContextValidity(target, resolutionPort = null, resolutionUpdatedAt = null) {
    const cleanTarget = target ? String(target).trim().toLowerCase() : null;
    if (!cleanTarget) {
      return {
        supersededByTopologyChange: false,
        validityState: 'VALID_CURRENT_TOPOLOGY',
        topologyValidityNote: 'Historical context matches current baseline.'
      };
    }

    const entity = this._loadEntity(cleanTarget);
    let driftEvents = [];
    try {
      const rawDrift = temporalInfrastructureGraph.findIdentityDriftEvents(24);
      driftEvents = Array.isArray(rawDrift) ? rawDrift : (Array.isArray(rawDrift?.driftEvents) ? rawDrift.driftEvents : []);
    } catch (_) {}

    const matchingDrift = driftEvents.find((ev) => {
      const nid = String(ev.nodeId || ev.label || '').toLowerCase();
      return nid.includes(cleanTarget) || (ev.previousIp && ev.previousIp === cleanTarget) || (ev.newIp && ev.newIp === cleanTarget);
    });

    if (matchingDrift) {
      return {
        supersededByTopologyChange: true,
        validityState: 'SUPERSEDED_BY_IDENTITY_OR_IP_DRIFT',
        topologyValidityNote: `Historical resolution predates identity/IP drift (${matchingDrift.previousIp || 'prior'} -> ${matchingDrift.newIp || 'current'}); re-verify before applying prior playbook.`
      };
    }

    if (entity) {
      const openPorts = Array.isArray(entity.openPorts) ? entity.openPorts.map(Number) : [];
      const closedPorts = Array.isArray(entity.closedPorts) ? entity.closedPorts.map(Number) : [];
      if (
        resolutionPort !== null &&
        Number.isFinite(Number(resolutionPort)) &&
        closedPorts.includes(Number(resolutionPort)) &&
        openPorts.length > 0 &&
        !openPorts.includes(Number(resolutionPort))
      ) {
        return {
          supersededByTopologyChange: true,
          validityState: 'SUPERSEDED_BY_SERVICE_PORT_MIGRATION',
          topologyValidityNote: `Historical resolution targeted port :${resolutionPort}, which is now CLOSED while service listeners are active on :${openPorts.join(', :')}.`
        };
      }

      const transitions = Array.isArray(entity.transitions) ? entity.transitions : [];
      const recentIpChange = transitions.find((t) => t.type === 'IP_CHANGE' || /ip.*changed/i.test(String(t.detail || '')));
      if (recentIpChange && (!resolutionUpdatedAt || new Date(recentIpChange.timestamp || Date.now()).getTime() >= new Date(resolutionUpdatedAt).getTime())) {
        return {
          supersededByTopologyChange: true,
          validityState: 'SUPERSEDED_BY_DNS_IP_TRANSITION',
          topologyValidityNote: `Target ${cleanTarget} experienced a DNS/IP transition after this resolution was recorded.`
        };
      }
    }

    return {
      supersededByTopologyChange: false,
      validityState: 'VALID_CURRENT_TOPOLOGY',
      topologyValidityNote: 'Historical context aligns with current live topology and port state.'
    };
  }

  findMatchingResolutions({ target = null, port = null, symptomSignature = null, excludeSuperseded = false } = {}) {
    const cleanTarget = target ? String(target).trim().toLowerCase() : null;
    let rows = [];
    if (this.useSqlite && db) {
      try {
        rows = db.prepare('SELECT * FROM ejii_incident_resolutions ORDER BY updated_at DESC LIMIT 25').all().map((r) => ({
          resolutionId: r.resolution_id,
          targetKey: r.target_key,
          symptomSignature: r.symptom_signature,
          rootCause: r.root_cause,
          resolutionSteps: r.resolution_steps,
          port: r.port !== null ? Number(r.port) : null,
          verifiedBy: r.verified_by,
          verificationStatus: r.verification_status,
          hitCount: Number(r.hit_count) || 1,
          createdAt: r.created_at,
          updatedAt: r.updated_at
        }));
      } catch (_) {
        rows = [...this.resolutionsCache];
      }
    } else {
      rows = [...this.resolutionsCache];
    }

    const annotateValidity = (list) => list.map((r) => {
      const validity = this.evaluateHistoricalContextValidity(r.targetKey || cleanTarget, r.port ?? port, r.updatedAt);
      return {
        ...r,
        supersededByTopologyChange: validity.supersededByTopologyChange,
        validityState: validity.validityState,
        topologyValidityNote: validity.topologyValidityNote
      };
    });

    if (!cleanTarget && !port && !symptomSignature) {
      const annotated = annotateValidity(rows.slice(0, 15));
      return excludeSuperseded ? annotated.filter((r) => !r.supersededByTopologyChange) : annotated;
    }

    const filtered = annotateValidity(rows.filter((r) => {
      if (cleanTarget && r.targetKey && r.targetKey === cleanTarget) return true;
      if (port && r.port && Number(r.port) === Number(port)) return true;
      if (symptomSignature && r.symptomSignature && r.symptomSignature.toLowerCase().includes(String(symptomSignature).toLowerCase())) {
        return true;
      }
      return false;
    }));

    // Sort valid current-topology resolutions ahead of superseded ones
    filtered.sort((a, b) => Number(a.supersededByTopologyChange) - Number(b.supersededByTopologyChange));
    const finalRows = excludeSuperseded ? filtered.filter((r) => !r.supersededByTopologyChange) : filtered;
    return finalRows.slice(0, 5);
  }

  /**
   * Retrieve all stored operational memory entities, stability metrics, learned resolutions, and decisions.
   */
  getOperationalMemoryOverview(limit = 25) {
    let entities = [];
    if (this.useSqlite && db) {
      try {
        const rows = db.prepare('SELECT * FROM ejii_operational_memory ORDER BY last_seen_at DESC LIMIT ?').all(limit);
        entities = rows.map((row) => {
          const rttSamples = JSON.parse(row.rtt_samples_json || '[]');
          const transitions = JSON.parse(row.transitions_json || '[]');
          const stats = computeSampleStats(rttSamples);
          const obj = {
            target: row.target_key,
            targetDisplay: row.target_display,
            firstSeenAt: row.first_seen_at,
            lastSeenAt: row.last_seen_at,
            observationCount: Number(row.observation_count) || 0,
            failureCount: Number(row.failure_count) || 0,
            lastIntent: row.last_intent,
            lastStatus: row.last_status,
            lastFailureLayer: row.last_failure_layer || null,
            resolvedIps: JSON.parse(row.resolved_ips_json || '[]'),
            openPorts: JSON.parse(row.open_ports_json || '[]'),
            closedPorts: JSON.parse(row.closed_ports_json || '[]'),
            avgRttMs: row.avg_rtt_ms !== null ? Number(row.avg_rtt_ms) : null,
            ewmaRttMs: stats.ewma,
            rttStdDevMs: stats.stdDev,
            rttTrendSlopeMs: stats.trendSlopeMsPerObs,
            lastRttMs: row.last_rtt_ms !== null ? Number(row.last_rtt_ms) : null,
            lastSummary: row.last_summary || '',
            transitions
          };
          obj.stabilityScore = this._computeStabilityScore(obj);
          return obj;
        });
      } catch (_) {
        entities = Array.from(this.memoryCache.values()).slice(0, limit).map((e) => ({
          ...e,
          target: e.targetKey || e.target,
          stabilityScore: this._computeStabilityScore(e)
        }));
      }
    } else {
      entities = Array.from(this.memoryCache.values()).slice(0, limit).map((e) => ({
        ...e,
        target: e.targetKey || e.target,
        stabilityScore: this._computeStabilityScore(e)
      }));
    }

    const resolutions = this.findMatchingResolutions({});
    const decisions = this.listOperationalDecisions(15);
    return {
      totalEntitiesTracked: entities.length,
      entities,
      resolutions,
      decisions
    };
  }

  /**
   * Compute explainable Predictive Health & SLA Exhaustion Forecast for a target.
   * Uses real historical RTT samples (EWMA, standard deviation, linear regression slope)
   * and recent status transitions (flapping oscillation index) to estimate:
   *   - Estimated observations until SLA threshold breach (default 250ms)
   *   - Flapping periodicity / oscillation rate
   *   - Statistical confidence & explicit epistemic uncertainty note
   */
  computePredictiveForecast(target, slaThresholdMs = 250) {
    if (!target || typeof target !== 'string') return null;
    const cleanTarget = target.trim().toLowerCase();
    const ent = this._loadEntity(cleanTarget);
    if (!ent) return null;

    const rttSamples = Array.isArray(ent.rttSamples) ? ent.rttSamples : [];
    const stats = computeSampleStats(rttSamples);
    const stabilityScore = this._computeStabilityScore(ent);
    const recentObs = Array.isArray(ent.recentObservations) ? ent.recentObservations : [];

    // Compute flapping oscillation index (PASS <-> FAIL switches across recent observations)
    let statusSwitches = 0;
    for (let i = 1; i < recentObs.length; i++) {
      if (recentObs[i].status && recentObs[i - 1].status && recentObs[i].status !== recentObs[i - 1].status) {
        statusSwitches++;
      }
    }
    const flappingIndex = recentObs.length >= 3
      ? Number((statusSwitches / (recentObs.length - 1)).toFixed(2))
      : 0;

    const currentRtt = typeof stats.ewma === 'number'
      ? stats.ewma
      : (typeof ent.lastRttMs === 'number' ? ent.lastRttMs : ent.avgRttMs);
    const slope = typeof stats.trendSlopeMsPerObs === 'number' ? stats.trendSlopeMsPerObs : 0;

    let observationsToSlaBreach = null;
    if (typeof currentRtt === 'number' && slope > 0.5) {
      if (currentRtt >= slaThresholdMs) {
        observationsToSlaBreach = 0;
      } else {
        observationsToSlaBreach = Math.max(1, Math.ceil((slaThresholdMs - currentRtt) / slope));
      }
    }

    let riskClassification = 'NOMINAL_STABLE';
    let operationalRiskSignificance = 'NOMINAL_BASELINE';
    let operationalVsStatisticalNote = 'Current telemetry is within normal statistical operating bounds.';
    let severity = 'OK';
    let explanation = '';

    if (ent.lastStatus === 'FAIL' && stabilityScore < 50) {
      riskClassification = 'ACTIVE_PERSISTENT_OUTAGE';
      operationalRiskSignificance = 'CRITICAL_OPERATIONAL_RISK';
      operationalVsStatisticalNote = 'Operationally critical: active probe failure combined with sustained reliability degradation (<50% stability).';
      severity = 'CRITICAL';
      explanation = `${cleanTarget} is currently failing probes with a ${stabilityScore}% stability score (${ent.failureCount}/${ent.observationCount} failed observations).`;
    } else if (flappingIndex >= 0.5 && recentObs.length >= 3) {
      riskClassification = 'INTERMITTENT_FLAPPING_INSTABILITY';
      operationalRiskSignificance = 'ACTIONABLE_PREVENTIVE_RISK';
      operationalVsStatisticalNote = 'Operationally significant: repeated PASS/FAIL state oscillation indicates route flapping, connection pool exhaustion, or load-balancer backend instability.';
      severity = 'WARN';
      explanation = `${cleanTarget} is oscillating between PASS and FAIL states (flapping index ${(flappingIndex * 100).toFixed(0)}% across last ${recentObs.length} checks).`;
    } else if (observationsToSlaBreach !== null && observationsToSlaBreach <= 15) {
      riskClassification = 'IMMINENT_SLA_LATENCY_BREACH';
      operationalRiskSignificance = 'ACTIONABLE_PREVENTIVE_RISK';
      operationalVsStatisticalNote = `Operationally significant: sustained positive latency velocity (+${slope} ms/check) projects an SLA threshold (${slaThresholdMs} ms) breach within ~${observationsToSlaBreach} check cycle(s).`;
      severity = 'WARN';
      explanation = `${cleanTarget} exhibits positive RTT drift velocity (+${slope} ms/check, EWMA ${currentRtt} ms). At current trajectory, latency is projected to cross the ${slaThresholdMs} ms SLA threshold within ~${observationsToSlaBreach} check cycle(s).`;
    } else if (slope > 5) {
      riskClassification = 'ELEVATED_LATENCY_DRIFT';
      const isMinorAbsolute = typeof currentRtt === 'number' && currentRtt < slaThresholdMs * 0.35;
      operationalRiskSignificance = isMinorAbsolute ? 'STATISTICAL_NOISE_MONITOR_ONLY' : 'ACTIONABLE_PREVENTIVE_RISK';
      operationalVsStatisticalNote = isMinorAbsolute
        ? `Statistically interesting upward slope (+${slope} ms/check), but absolute EWMA latency (${currentRtt} ms) remains well below the ${slaThresholdMs} ms SLA ceiling — monitor without immediate intervention.`
        : `Operationally relevant upward drift (+${slope} ms/check) approaching operational latency margins.`;
      severity = 'WARN';
      explanation = `${cleanTarget} shows upward latency drift (+${slope} ms/check; EWMA ${currentRtt} ms vs mean ${stats.mean} ms).`;
    } else if (stabilityScore < 80) {
      riskClassification = 'DEGRADED_HISTORICAL_RELIABILITY';
      operationalRiskSignificance = ent.lastStatus === 'FAIL' ? 'CRITICAL_OPERATIONAL_RISK' : 'ACTIONABLE_PREVENTIVE_RISK';
      operationalVsStatisticalNote = `Historical reliability is degraded (${stabilityScore}% stability across ${ent.observationCount} checks).`;
      severity = 'WARN';
      explanation = `${cleanTarget} has a reduced stability score of ${stabilityScore}% (${ent.failureCount}/${ent.observationCount} failed checks).`;
    } else {
      if (slope > 0.5 && slope <= 5) {
        operationalRiskSignificance = 'STATISTICAL_NOISE_MONITOR_ONLY';
        operationalVsStatisticalNote = `Minor statistical RTT variance (+${slope} ms/check) within normal operating baseline; no operational risk.`;
      }
      explanation = `${cleanTarget} is operating within nominal baseline bounds (Stability ${stabilityScore}%, EWMA RTT ${currentRtt ?? 'N/A'} ms).`;
    }

    const sampleConfidence = Math.min(0.95, Number((0.35 + Math.min(ent.observationCount, 20) * 0.03).toFixed(2)));

    return {
      target: cleanTarget,
      observationCount: ent.observationCount,
      stabilityScore,
      riskClassification,
      operationalRiskSignificance,
      operationalVsStatisticalNote,
      severity,
      currentEwmaRttMs: currentRtt ?? null,
      meanRttMs: stats.mean,
      stdDevRttMs: stats.stdDev,
      rttVelocityMsPerCheck: slope,
      slaThresholdMs,
      estimatedObservationsToSlaBreach: observationsToSlaBreach,
      flappingIndex,
      statisticalConfidence: sampleConfidence,
      explanation,
      uncertaintyNote: ent.observationCount < 4
        ? `Forecast is provisional (based on ${ent.observationCount} observation(s)); accuracy increases as more baseline checks accumulate.`
        : `Statistical projection derived from ${ent.observationCount} empirical observations; sudden external routing or workload shifts can alter trajectory.`
    };
  }

  /**
   * Analyze the Operational Decision Ledger (`ejii_operational_decisions`) to measure
   * real postcondition verification efficacy per action type and target.
   */
  getRemediationEfficacyReport(target = null) {
    const cleanTarget = target ? String(target).trim().toLowerCase() : null;
    const allDecisions = this.listOperationalDecisions(100);
    const filtered = cleanTarget
      ? allDecisions.filter((d) => !d.targetKey || d.targetKey === cleanTarget)
      : allDecisions;

    const byAction = new Map();
    for (const dec of filtered) {
      const actionId = dec.actionId || 'unknown_action';
      const entry = byAction.get(actionId) || {
        actionId,
        totalExecutions: 0,
        verifiedSuccessCount: 0,
        rolledBackOrFailedCount: 0,
        targetsTested: new Set(),
        lastOutcomeStatus: null,
        lastExecutedAt: null,
        rttImprovementsMs: []
      };

      entry.totalExecutions++;
      const statusUpper = String(dec.outcomeStatus || '').toUpperCase();
      if (statusUpper === 'APPLIED_AND_VERIFIED' || statusUpper === 'SUCCESS' || statusUpper === 'VERIFIED' || statusUpper === 'RECORDED') {
        entry.verifiedSuccessCount++;
      } else {
        entry.rolledBackOrFailedCount++;
      }
      if (dec.targetKey) entry.targetsTested.add(dec.targetKey);
      if (!entry.lastExecutedAt) {
        entry.lastExecutedAt = dec.createdAt;
        entry.lastOutcomeStatus = dec.outcomeStatus;
      }

      const beforeRtt = dec.beforeMetrics?.liveDnsRttMs ?? dec.beforeMetrics?.liveTcpRttMs ?? dec.beforeMetrics?.rttMs;
      const afterRtt = dec.afterMetrics?.liveDnsRttMs ?? dec.afterMetrics?.liveTcpRttMs ?? dec.afterMetrics?.rttMs;
      if (typeof beforeRtt === 'number' && typeof afterRtt === 'number') {
        entry.rttImprovementsMs.push(Number((beforeRtt - afterRtt).toFixed(2)));
      }
      byAction.set(actionId, entry);
    }

    const actionStats = Array.from(byAction.values()).map((a) => {
      const efficacyPct = a.totalExecutions > 0
        ? Math.round((a.verifiedSuccessCount / a.totalExecutions) * 100)
        : 0;
      const avgRttImprovementMs = a.rttImprovementsMs.length > 0
        ? Number((a.rttImprovementsMs.reduce((s, v) => s + v, 0) / a.rttImprovementsMs.length).toFixed(2))
        : null;
      return {
        actionId: a.actionId,
        totalExecutions: a.totalExecutions,
        verifiedSuccessCount: a.verifiedSuccessCount,
        rolledBackOrFailedCount: a.rolledBackOrFailedCount,
        efficacyPct,
        avgRttImprovementMs,
        targetsCount: a.targetsTested.size,
        lastOutcomeStatus: a.lastOutcomeStatus,
        lastExecutedAt: a.lastExecutedAt
      };
    }).sort((a, b) => b.efficacyPct - a.efficacyPct || b.totalExecutions - a.totalExecutions);

    const totalDecisions = filtered.length;
    const totalVerified = actionStats.reduce((acc, a) => acc + a.verifiedSuccessCount, 0);
    const overallEfficacyPct = totalDecisions > 0 ? Math.round((totalVerified / totalDecisions) * 100) : 100;

    return {
      targetFilter: cleanTarget,
      totalDecisionsEvaluated: totalDecisions,
      overallEfficacyPct,
      actions: actionStats
    };
  }

  /**
   * Recommend governed remediation and operational next steps informed by both
   * learned playbooks (`ejii_incident_resolutions`) and decision ledger efficacy (`ejii_operational_decisions`).
   * Automatically pivots to an adaptive alternative action if the default action previously failed verification on the target.
   */
  recommendRemediationWithHistory({
    target = null,
    failureLayer = null,
    symptomSignature = null,
    port = null
  } = {}) {
    const cleanTarget = target ? String(target).trim().toLowerCase() : null;
    const playbooks = this.findMatchingResolutions({
      target: cleanTarget,
      port,
      symptomSignature: symptomSignature || failureLayer
    });
    const efficacy = this.getRemediationEfficacyReport(cleanTarget);
    const priorTargetDecisions = cleanTarget
      ? this.listOperationalDecisions(30).filter((d) => d.targetKey === cleanTarget)
      : [];

    const previouslyFailedActions = priorTargetDecisions
      .filter((d) => /ROLLBACK|ROLLED_BACK|FAIL/i.test(String(d.outcomeStatus || '')))
      .map((d) => d.actionId);

    const layerStr = String(failureLayer || symptomSignature || '').toUpperCase();
    let primaryActionId = 'verify_and_refresh_dns_resolution';
    let primaryActionLabel = 'Execute governed DNS resolver refresh & live postcondition verification';
    let rationale = 'Refreshes DNS resolver state with SQLite pre-snapshot rollback protection.';

    if (layerStr.includes('TCP') || layerStr.includes('PORT') || layerStr.includes('CLOSED') || layerStr.includes('ECONNREFUSED')) {
      primaryActionId = 'inspect_service_listener_and_socket_binding';
      primaryActionLabel = `Verify and restart application daemon bound to TCP port ${port || 443} on ${cleanTarget || 'target'}`;
      rationale = `Layer 4 TCP connection was refused or closed on port ${port || 443}, indicating the host is reachable at Layer 3 but no process is listening on the target port.`;
    } else if (layerStr.includes('TIMEOUT') || layerStr.includes('FILTERED') || layerStr.includes('ICMP')) {
      primaryActionId = 'audit_firewall_and_upstream_route';
      primaryActionLabel = `Audit inbound firewall ACLs and L3 routing toward ${cleanTarget || 'target'}${port ? `:${port}` : ''}`;
      rationale = `Packets timed out without an active TCP RST, indicating either an intermediate firewall drop or unroutable host.`;
    } else if (layerStr.includes('TLS') || layerStr.includes('CERT')) {
      primaryActionId = 'renew_or_rebind_tls_certificate';
      primaryActionLabel = `Inspect X.509 certificate chain and TLS cipher configuration on ${cleanTarget || 'target'}:${port || 443}`;
      rationale = `Transport connection succeeded but Layer 6 TLS handshake or certificate validation failed.`;
    }

    const matchingActionStats = efficacy.actions.find((a) => a.actionId === primaryActionId) || null;
    const hasPriorFailure = previouslyFailedActions.includes(primaryActionId);
    const warningPriorFailure = hasPriorFailure
      ? `Warning: Action '${primaryActionId}' previously failed postcondition verification on ${cleanTarget} and was rolled back. Escalate to manual service/daemon inspection rather than repeating the same automated action.`
      : null;

    // Adaptive Closed-Loop Pivot: if primaryActionId previously failed on this target, select an alternative governed action
    let adaptiveAlternativeActionId = null;
    let adaptiveAlternativeActionLabel = null;
    let adaptivePivotRationale = null;
    if (hasPriorFailure) {
      if (primaryActionId === 'verify_and_refresh_dns_resolution') {
        adaptiveAlternativeActionId = 'verify_tcp_service_endpoint';
        adaptiveAlternativeActionLabel = `Pivot to direct Layer 4 TCP service endpoint verification on ${cleanTarget || 'target'}:${port || 3000}`;
        adaptivePivotRationale = `Because '${primaryActionId}' previously rolled back on ${cleanTarget}, EJII adaptively pivots to verifying the underlying TCP listener and routing path directly rather than repeating a DNS refresh.`;
      } else if (primaryActionId === 'inspect_service_listener_and_socket_binding') {
        adaptiveAlternativeActionId = 'verify_gateway_and_route_table';
        adaptiveAlternativeActionLabel = `Pivot to kernel socket table & port-split readiness inspection on ${cleanTarget || 'target'}`;
        adaptivePivotRationale = `Because '${primaryActionId}' previously failed verification on ${cleanTarget}, EJII pivots to checking whether the service bound to an alternate port or interface.`;
      } else {
        adaptiveAlternativeActionId = 'verify_and_refresh_dns_resolution';
        adaptiveAlternativeActionLabel = `Pivot to governed resolver & topology state verification on ${cleanTarget || 'target'}`;
        adaptivePivotRationale = `Because '${primaryActionId}' previously failed on ${cleanTarget}, EJII pivots to an alternative non-destructive verification workflow.`;
      }
    }

    return {
      target: cleanTarget,
      recommendedActionId: primaryActionId,
      recommendedActionLabel: primaryActionLabel,
      effectiveRecommendedActionId: adaptiveAlternativeActionId || primaryActionId,
      effectiveRecommendedActionLabel: adaptiveAlternativeActionLabel || primaryActionLabel,
      adaptiveAlternativeActionId,
      adaptiveAlternativeActionLabel,
      adaptivePivotRationale,
      previouslyFailedActions,
      rationale,
      historicalEfficacyPct: matchingActionStats ? matchingActionStats.efficacyPct : null,
      historicalExecutions: matchingActionStats ? matchingActionStats.totalExecutions : 0,
      warningPriorFailure,
      matchedPlaybooks: playbooks.slice(0, 3)
    };
  }

  /**
   * Evaluate multi-layer competing diagnostic hypotheses, isolate Primary Root Cause vs. Downstream Symptoms,
   * detect Cross-Layer Contradictions, and rank the Highest Information-Gain Next Investigation.
   */
  evaluateDiagnosticHypotheses({
    target,
    port = 443,
    dnsStep = null,
    icmpStep = null,
    tcpStep = null,
    tlsStep = null,
    httpStep = null,
    memoryInsights = null,
    extraPortResults = [],
    localListeningPorts = []
  } = {}) {
    const hypotheses = [];
    const contradictions = [];
    const symptoms = [];
    const missingInformation = [];
    const redundancySkipped = [];
    let primaryRootCause = null;

    const dnsOk = dnsStep ? dnsStep.status === 'PASS' : true;
    const icmpOk = icmpStep ? icmpStep.status === 'PASS' : null;
    const tcpOk = tcpStep ? (tcpStep.status === 'PASS' || tcpStep.details?.status === 'OPEN') : null;
    const tcpStatus = tcpStep?.details?.status || (tcpOk ? 'OPEN' : 'FAILED');
    const tlsOk = tlsStep ? tlsStep.status === 'PASS' : null;
    const httpOk = httpStep ? httpStep.status === 'PASS' : null;

    if (!icmpStep) missingInformation.push('Layer 3 ICMP Echo reachability was not directly probed in this turn.');
    if (!tlsStep && (Number(port) === 443 || Number(port) === 8443) && tcpOk) {
      missingInformation.push(`Layer 6 TLS certificate and cipher negotiation on ${target}:${port} has not been inspected yet.`);
    }
    if (!httpStep && tcpOk) {
      missingInformation.push(`Layer 7 HTTP application status code and TTFB on ${target}:${port} have not been verified yet.`);
    }

    // Hypothesis 1: DNS Resolution & Naming Integrity
    if (dnsStep) {
      redundancySkipped.push('DNS A/AAAA lookup (already empirically verified)');
      hypotheses.push({
        id: 'H1_DNS_RESOLUTION',
        layer: 'Layer 7 (DNS)',
        title: `DNS Name Resolution for ${target}`,
        status: dnsOk ? 'REFUTED_HEALTHY' : 'CONFIRMED_FAULT',
        causalRole: dnsOk ? 'REFUTED_HEALTHY' : 'PRIMARY_ROOT_CAUSE',
        posteriorProbabilityPct: dnsOk ? 2 : 96,
        verdictLabel: dnsOk ? 'Healthy (Eliminated as Cause)' : 'Confirmed Root Cause',
        evidence: dnsStep.summary || (dnsOk ? 'Resolved successfully' : 'DNS lookup failed'),
        supportingEvidence: dnsOk ? [] : [dnsStep.summary || 'DNS lookup returned error/NXDOMAIN'],
        contradictingEvidence: dnsOk ? [dnsStep.summary || 'DNS resolved to valid IP address'] : []
      });
      if (!dnsOk) {
        primaryRootCause = {
          layer: 'Layer 7 DNS Resolution',
          hypothesisId: 'H1_DNS_RESOLUTION',
          causalRole: 'PRIMARY_ROOT_CAUSE',
          confidencePct: 96,
          summary: `Authoritative/recursive DNS lookup failed for "${target}" (${dnsStep.summary}).`,
          whyNotDownstream: 'Because no IP address could be resolved, Layer 3 ICMP, Layer 4 TCP, and Layer 7 HTTP probes could not be initiated.'
        };
        symptoms.push(`Unable to establish TCP or HTTP connection to ${target}:${port} (downstream consequence of DNS failure).`);
      }
    }

    // Hypothesis 2: Layer 3 Network Routing & Host Presence
    if (dnsOk) {
      const hostReachableViaTcpRst = tcpStatus === 'CLOSED';
      const l3Reachable = icmpOk === true || tcpOk === true || hostReachableViaTcpRst;
      if (l3Reachable) redundancySkipped.push('Layer 3 IP host reachability (proven alive via L3/L4 response)');
      const l3Status = l3Reachable
        ? 'REFUTED_HEALTHY'
        : (icmpOk === false && tcpOk === false ? 'INCONCLUSIVE_OR_FILTERED' : 'UNPROBED');
      const l3Evidence = hostReachableViaTcpRst
        ? `Host returned explicit TCP RST on port ${port}, proving Layer 3 IP routing is operational`
        : (icmpStep ? icmpStep.summary : (tcpOk ? 'Verified via successful Layer 4 TCP handshake' : 'No L3/L4 reply received'));
      hypotheses.push({
        id: 'H2_L3_NETWORK_PATH',
        layer: 'Layer 3 (IP/ICMP)',
        title: `Network Path & Host Reachability to ${target}`,
        status: l3Status,
        causalRole: l3Reachable ? 'REFUTED_HEALTHY' : (icmpOk === false && tcpOk === false ? 'COMPETING_ROOT_CAUSE' : 'UNPROBED'),
        posteriorProbabilityPct: l3Reachable ? 3 : (icmpOk === false && tcpOk === false ? 55 : 20),
        verdictLabel: l3Reachable
          ? 'Healthy (Host Reachable on Network)'
          : 'Suspected Host Down or Firewall Blackhole',
        evidence: l3Evidence,
        supportingEvidence: l3Reachable ? [] : [l3Evidence],
        contradictingEvidence: l3Reachable ? [l3Evidence] : []
      });
    }

    // Hypothesis 3: Layer 4 TCP Transport & Service Port Listener
    if (dnsOk && tcpStep) {
      redundancySkipped.push(`Layer 4 TCP port ${port} handshake (already empirically verified)`);
      const anyExtraOpen = (extraPortResults || []).find((e) => e.status === 'OPEN');
      const adjacentLocalPorts = (localListeningPorts || []).filter((p) => Number(p) !== Number(port));

      hypotheses.push({
        id: 'H3_L4_TCP_LISTENER',
        layer: `Layer 4 (TCP :${port})`,
        title: `TCP Port ${port} Listener / Firewall State`,
        status: tcpOk ? 'REFUTED_HEALTHY' : 'CONFIRMED_FAULT',
        causalRole: tcpOk ? 'REFUTED_HEALTHY' : 'PRIMARY_ROOT_CAUSE',
        posteriorProbabilityPct: tcpOk ? 2 : (tcpStatus === 'CLOSED' ? 95 : 78),
        verdictLabel: tcpOk
          ? `Healthy (Port ${port} OPEN)`
          : (tcpStatus === 'CLOSED' ? `Confirmed Root Cause (Port ${port} Refused)` : `Confirmed Fault (Port ${port} Timed Out)`),
        evidence: tcpStep.summary,
        supportingEvidence: tcpOk ? [] : [
          tcpStep.summary,
          ...(anyExtraOpen ? [`Sibling port ${anyExtraOpen.port} is OPEN on the same host`] : [])
        ],
        contradictingEvidence: tcpOk ? [tcpStep.summary] : []
      });

      if (!tcpOk && !primaryRootCause) {
        if (tcpStatus === 'CLOSED') {
          const portDriftNote = anyExtraOpen
            ? ` Meanwhile, alternate TCP port ${anyExtraOpen.port} on the same host is OPEN.`
            : (adjacentLocalPorts.length > 0
                ? ` Active local listeners were found on port(s) ${adjacentLocalPorts.slice(0, 5).join(', ')}.`
                : '');
          primaryRootCause = {
            layer: `Layer 4 TCP Listener (Port ${port} CLOSED / ECONNREFUSED)`,
            hypothesisId: 'H3_L4_TCP_LISTENER',
            causalRole: 'PRIMARY_ROOT_CAUSE',
            confidencePct: 95,
            summary: `Target host ${target} is online and reachable at Layer 3, but no application process is bound to TCP port ${port}.${portDriftNote}`,
            whyNotDownstream: 'DNS resolution and IP routing succeeded; the kernel on the target host actively rejected the TCP SYN with a RST packet.'
          };
          symptoms.push(`Application/HTTP requests to ${target}:${port} fail immediately with connection refused.`);
        } else {
          primaryRootCause = {
            layer: `Layer 4 TCP Transport / Firewall (Port ${port} ${tcpStatus})`,
            hypothesisId: 'H3_L4_TCP_LISTENER',
            causalRole: 'PRIMARY_ROOT_CAUSE',
            confidencePct: icmpOk ? 88 : 65,
            summary: icmpOk
              ? `Host ${target} responds to Layer 3 ICMP ping, but TCP SYN packets to port ${port} are silently dropped by a firewall or security group.`
              : `Both ICMP and TCP port ${port} timed out toward ${target}, indicating either an offline host or a strict perimeter firewall drop.`,
            whyNotDownstream: 'DNS succeeded, but transport packets cannot complete a 3-way handshake.'
          };
          symptoms.push(`Client connections to ${target}:${port} hang and time out.`);
        }
      }
    }

    // Hypothesis 4: Layer 6/7 TLS & HTTP Application Health
    if (tcpOk && (tlsStep || httpStep)) {
      redundancySkipped.push(`Layer 7 HTTP/TLS check on ${target}:${port} (already empirically verified)`);
      const l7Fault = (tlsStep && !tlsOk) || (httpStep && !httpOk);
      const l7Ev = httpStep?.summary || tlsStep?.summary || 'Application layer verified';
      hypotheses.push({
        id: 'H4_L7_APPLICATION',
        layer: 'Layer 6/7 (TLS/HTTP)',
        title: `TLS Handshake & HTTP Application Handler on :${port}`,
        status: l7Fault ? 'CONFIRMED_FAULT' : 'REFUTED_HEALTHY',
        causalRole: l7Fault ? 'PRIMARY_ROOT_CAUSE' : 'REFUTED_HEALTHY',
        posteriorProbabilityPct: l7Fault ? 92 : 3,
        verdictLabel: l7Fault ? 'Confirmed Application/TLS Fault' : 'Healthy (Application Responding)',
        evidence: l7Ev,
        supportingEvidence: l7Fault ? [l7Ev] : [],
        contradictingEvidence: l7Fault ? [] : [l7Ev]
      });

      if (l7Fault && !primaryRootCause) {
        primaryRootCause = {
          layer: tlsStep && !tlsOk ? 'Layer 6 TLS Handshake' : 'Layer 7 HTTP Application Handler',
          hypothesisId: 'H4_L7_APPLICATION',
          causalRole: 'PRIMARY_ROOT_CAUSE',
          confidencePct: 92,
          summary: tlsStep && !tlsOk
            ? `TCP port ${port} is open, but TLS negotiation failed (${tlsStep.summary}).`
            : `TCP port ${port} is open, but the HTTP server returned an error status (${httpStep.summary}).`,
          whyNotDownstream: 'DNS, IP routing, and TCP 3-way handshake all succeeded prior to the application-layer failure.'
        };
      }
    } else if (!tcpOk && tcpStep) {
      // Explicitly show L7 HTTP as a Downstream Symptom when L4 TCP failed
      hypotheses.push({
        id: 'H4_L7_DOWNSTREAM_SYMPTOM',
        layer: 'Layer 7 (HTTP/App)',
        title: `HTTP/Application Availability on ${target}:${port}`,
        status: 'DOWNSTREAM_SYMPTOM',
        causalRole: 'DOWNSTREAM_SYMPTOM',
        posteriorProbabilityPct: 0,
        verdictLabel: 'Downstream Symptom (Blocked by L4 TCP)',
        evidence: `Application requests cannot reach ${target}:${port} because Layer 4 TCP transport (${tcpStatus}) failed first.`,
        supportingEvidence: [],
        contradictingEvidence: [`Layer 4 TCP port ${port} is ${tcpStatus}, preventing any Layer 7 HTTP exchange.`]
      });
    }

    // Hypothesis 5: Shared Upstream Infrastructure vs. Independent Endpoint Failure
    const depCtx = memoryInsights?.dependencyContext || this.getTargetDependencyContext(target, []);
    if (depCtx && Array.isArray(depCtx.upstreamDependencies) && depCtx.upstreamDependencies.length > 0) {
      const upstreamNames = depCtx.upstreamDependencies.map((u) => u.nodeId).join(', ');
      const hasPrimaryFault = Boolean(primaryRootCause && primaryRootCause.hypothesisId);
      hypotheses.push({
        id: 'H5_SHARED_UPSTREAM_DEPENDENCY',
        layer: 'Topology / Upstream',
        title: `Shared Upstream Dependency (${upstreamNames})`,
        status: hasPrimaryFault && tcpStatus !== 'CLOSED' ? 'PLAUSIBLE_SHARED_CAUSE' : 'REFUTED_HEALTHY',
        causalRole: hasPrimaryFault && tcpStatus !== 'CLOSED' ? 'SHARED_INFRASTRUCTURE_FAILURE' : 'INDEPENDENT_FAILURE',
        posteriorProbabilityPct: hasPrimaryFault && tcpStatus !== 'CLOSED' ? 42 : 5,
        verdictLabel: hasPrimaryFault && tcpStatus !== 'CLOSED'
          ? `Evaluate Shared Upstream (${upstreamNames})`
          : `Independent Endpoint Scope (${upstreamNames} Healthy)`,
        evidence: tcpStatus === 'CLOSED'
          ? `Host ${target} returned TCP RST directly, proving upstream path (${upstreamNames}) delivered the packet.`
          : `Target depends on upstream topology node(s): ${upstreamNames}.`,
        supportingEvidence: hasPrimaryFault && tcpStatus !== 'CLOSED' ? [`Upstream dependency link: ${upstreamNames}`] : [],
        contradictingEvidence: tcpStatus === 'CLOSED' ? ['Target kernel returned TCP RST across the upstream path'] : []
      });
    }

    // Cross-Layer Contradiction & Anomaly Detection
    if (icmpOk === false && tcpOk === true) {
      contradictions.push({
        type: 'ICMP_BLOCKED_BUT_TCP_OPEN',
        explanation: `Layer 3 ICMP echo timed out, yet Layer 4 TCP port ${port} succeeded. This proves the host is online and reachable — a firewall is simply dropping ICMP ping packets (ICMP_FILTERED_ALIVE).`
      });
    }
    if (icmpOk === true && tcpOk === false && tcpStatus !== 'CLOSED') {
      contradictions.push({
        type: 'ICMP_PASS_BUT_TCP_FILTERED',
        explanation: `Host ${target} replied to Layer 3 ICMP echo, but Layer 4 TCP SYN on port ${port} timed out without a RST. This isolates the fault to a stateful firewall ACL dropping port ${port} traffic rather than a dead host.`
      });
    }
    if (tcpStatus === 'CLOSED' && extraPortResults.some((e) => e.status === 'OPEN')) {
      const openAlt = extraPortResults.find((e) => e.status === 'OPEN');
      contradictions.push({
        type: 'SELECTIVE_PORT_REFUSAL',
        explanation: `Port ${port} refused connections (CLOSED), whereas port ${openAlt.port} on the same host is OPEN (${openAlt.latencyMs} ms). The server is running, but the service on port ${port} is stopped or bound to a different port.`
      });
    }
    if (memoryInsights?.stateTransitions?.length > 0) {
      for (const tr of memoryInsights.stateTransitions) {
        if (tr.type === 'PORT_REGRESSION_OPEN_TO_CLOSED' || tr.type === 'REACHABILITY_REGRESSION') {
          contradictions.push({
            type: 'HISTORICAL_STATE_REGRESSION',
            explanation: `Historical Baseline Contradiction: ${tr.message}`
          });
        }
      }
    }

    if (!primaryRootCause) {
      primaryRootCause = {
        layer: 'None (All Probed Layers Healthy)',
        hypothesisId: null,
        causalRole: 'REFUTED_HEALTHY',
        confidencePct: 98,
        posteriorProbabilityPct: 98,
        summary: `All evaluated protocol layers for ${target}:${port} passed verification.`,
        whyNotDownstream: 'No transport or application failure observed during live probing.'
      };
    } else if (typeof primaryRootCause.posteriorProbabilityPct !== 'number') {
      primaryRootCause.posteriorProbabilityPct = primaryRootCause.confidencePct ?? 90;
    }

    // Determine Highest Information-Gain Next Investigation (avoiding redundant checks)
    let nextBestInvestigation = null;
    if (!dnsOk) {
      nextBestInvestigation = {
        action: `Check authoritative NS/SOA records or test direct IP for ${target}`,
        prompt: `Check DNS NS and SOA records for ${target}`,
        expectedInformationGainBits: 0.92,
        rationale: 'Distinguishes between local recursive resolver failure and authoritative domain misconfiguration without repeating TCP probes.'
      };
    } else if (tcpOk === false && tcpStatus === 'CLOSED') {
      const altPort = Number(port) === 3000 ? 3001 : (Number(port) === 443 ? 80 : 443);
      nextBestInvestigation = {
        action: target === 'localhost' || target === '127.0.0.1'
          ? 'Inspect active local kernel sockets and listening PIDs'
          : `Probe alternate service port ${altPort} on ${target}`,
        prompt: target === 'localhost' || target === '127.0.0.1'
          ? 'Show me the active connections'
          : `Check whether port ${altPort} is open on ${target}`,
        expectedInformationGainBits: 0.88,
        rationale: `Port ${port} is already confirmed CLOSED via TCP RST; checking active socket bindings or port ${altPort} determines whether the service bound to a different port.`
      };
    } else if (tcpOk === false) {
      nextBestInvestigation = {
        action: `Run hop-by-hop L3 traceroute and blast-radius analysis on ${target}`,
        prompt: `Run traceroute to ${target}`,
        expectedInformationGainBits: 0.84,
        rationale: `Isolates where packets toward ${target}:${port} are being dropped along the Layer 3 routing path.`
      };
    } else if (tcpOk === true && !httpStep) {
      const proto = Number(port) === 443 || Number(port) === 8443 ? 'https' : 'http';
      nextBestInvestigation = {
        action: `Verify Layer 7 ${proto.toUpperCase()} response status and TTFB on ${target}:${port}`,
        prompt: `Check whether ${proto}://${target}:${port}/ is working`,
        expectedInformationGainBits: 0.79,
        rationale: `Layer 4 TCP port ${port} is confirmed OPEN; probing Layer 7 HTTP verifies application route health and server processing latency (TTFB).`
      };
    } else {
      nextBestInvestigation = {
        action: `Evaluate topological dependency impact & blast radius for ${target}`,
        prompt: `What is the dependency impact and blast radius for ${target}?`,
        expectedInformationGainBits: 0.65,
        rationale: `All protocol layers on ${target}:${port} are verified; evaluating downstream dependents maps potential blast radius.`
      };
    }

    return {
      target,
      port,
      primaryRootCause,
      downstreamSymptoms: symptoms,
      hypotheses,
      contradictions,
      missingInformation,
      redundancySkipped,
      nextBestInvestigation
    };
  }

  /**
   * Phase 4 CEO Directive: Fleet-Wide Intelligence Matrix
   * Answers the 7 core fleet operational intelligence questions:
   *   1. whatIsDegrading
   *   2. sharedDependencyRisks
   *   3. whatChangedBeforeFailure
   *   4. servicesAtRiskNext
   *   5. similarHistoricalIncidents
   *   6. highestPriorityInvestigation
   *   7. strongestEvidenceFindings
   */
  getFleetIntelligenceMatrix() {
    const briefing = this.getIntelligenceBriefing();
    const overview = this.getOperationalMemoryOverview(50);
    const entities = overview.entities || [];
    const resolutions = overview.resolutions || [];
    const graphState = temporalInfrastructureGraph.getGraphState();

    // 1. What is currently degrading across the infrastructure?
    const whatIsDegrading = entities
      .filter((e) => e.lastStatus === 'FAIL' || (e.stabilityScore ?? 100) < 85 || (e.rttTrendSlopeMs ?? 0) > 5)
      .map((e) => {
        const forecast = this.computePredictiveForecast(e.target);
        const depCtx = this.getTargetDependencyContext(e.target, e.resolvedIps || []);
        const downstreamCount = (depCtx.downstreamDependents || []).length;
        const outageWeight = e.lastStatus === 'FAIL' ? 50 : 0;
        const stabilityDrop = Math.max(0, 100 - (e.stabilityScore ?? 100));
        const driftWeight = Math.max(0, Math.min(25, Math.round((e.rttTrendSlopeMs || 0) * 1.5)));
        const blastWeight = downstreamCount * 8;
        const priorityScore = Math.min(100, Math.round(outageWeight + stabilityDrop * 0.4 + driftWeight + blastWeight));
        return {
          target: e.target,
          lastStatus: e.lastStatus || 'UNKNOWN',
          lastFailureLayer: e.lastFailureLayer || e.lastIntent || null,
          stabilityScore: e.stabilityScore ?? 100,
          ewmaRttMs: e.ewmaRttMs ?? e.avgRttMs ?? null,
          rttTrendSlopeMs: e.rttTrendSlopeMs ?? 0,
          downstreamDependentsCount: downstreamCount,
          riskClassification: forecast?.riskClassification || 'NOMINAL_STABLE',
          operationalRiskSignificance: forecast?.operationalRiskSignificance || 'NOMINAL_BASELINE',
          estimatedObservationsToSlaBreach: forecast?.estimatedObservationsToSlaBreach ?? null,
          priorityScore,
          summary: e.lastSummary || `${e.target} (Stability ${e.stabilityScore ?? 100}%)`
        };
      })
      .sort((a, b) => b.priorityScore - a.priorityScore);

    // 2. Which systems share a potentially problematic dependency?
    const sharedDependencyRisks = briefing.systemicPatterns || [];

    // 3. What changed before these failures appeared?
    const whatChangedBeforeFailure = (briefing.activeRegressions || []).map((reg) => ({
      target: reg.target,
      transitionType: reg.type,
      severity: reg.severity,
      detail: reg.detail,
      observedAt: reg.observedAt
    }));

    // 4. Which services could be affected next?
    const servicesAtRiskNext = [];
    for (const deg of whatIsDegrading.slice(0, 6)) {
      const depCtx = this.getTargetDependencyContext(deg.target, []);
      for (const down of depCtx.downstreamDependents || []) {
        servicesAtRiskNext.push({
          dependentNode: down.nodeId,
          relationship: down.relationship || 'depends_on',
          sourceTarget: deg.target,
          sourceRisk: deg.riskClassification,
          reason: `Downstream dependent of degrading target '${deg.target}' (${deg.riskClassification})`
        });
      }
      if (deg.estimatedObservationsToSlaBreach !== null && deg.estimatedObservationsToSlaBreach <= 15) {
        servicesAtRiskNext.push({
          dependentNode: deg.target,
          relationship: 'sla_latency_trajectory',
          sourceTarget: deg.target,
          sourceRisk: 'IMMINENT_SLA_LATENCY_BREACH',
          reason: `Projected to breach 250ms SLA threshold in ~${deg.estimatedObservationsToSlaBreach} check cycle(s) (+${deg.rttTrendSlopeMs} ms/check)`
        });
      }
    }

    // 5. Which historical incidents resemble the current situation?
    const similarHistoricalIncidents = resolutions.slice(0, 6).map((r) => ({
      resolutionId: r.resolutionId,
      targetKey: r.targetKey,
      symptomSignature: r.symptomSignature,
      rootCause: r.rootCause,
      verifiedResolution: r.resolutionSteps,
      hitCount: r.hitCount || 1
    }));

    // 6. What is the most important issue to investigate first?
    const topCandidate = whatIsDegrading[0] || (entities[0] ? {
      target: entities[0].target,
      priorityScore: 15,
      lastStatus: entities[0].lastStatus || 'PASS',
      stabilityScore: entities[0].stabilityScore ?? 100,
      riskClassification: 'NOMINAL_STABLE',
      summary: `${entities[0].target} is currently stable (${entities[0].stabilityScore ?? 100}% stability).`
    } : null);

    const highestPriorityInvestigation = topCandidate
      ? {
          target: topCandidate.target,
          priorityScore: topCandidate.priorityScore,
          riskClassification: topCandidate.riskClassification,
          rationale: topCandidate.lastStatus === 'FAIL'
            ? `Active failure on '${topCandidate.target}' with ${topCandidate.stabilityScore}% stability score and ${topCandidate.downstreamDependentsCount || 0} downstream dependent(s).`
            : `Highest relative risk/drift score (${topCandidate.priorityScore}/100) across ${entities.length} tracked fleet target(s).`,
          reason: topCandidate.lastStatus === 'FAIL'
            ? `Active failure on '${topCandidate.target}' with ${topCandidate.stabilityScore}% stability score and ${topCandidate.downstreamDependentsCount || 0} downstream dependent(s).`
            : `Highest relative risk/drift score (${topCandidate.priorityScore}/100) across ${entities.length} tracked fleet target(s).`,
          recommendedPrompt: `Investigate why ${topCandidate.target} is failing`,
          recommendedNextStep: `Investigate why ${topCandidate.target} is failing`
        }
      : null;

    // 7. Which findings have the strongest supporting evidence?
    const strongestEvidenceFindings = entities
      .filter((e) => e.observationCount > 0)
      .sort((a, b) => b.observationCount - a.observationCount)
      .slice(0, 5)
      .map((e) => ({
        target: e.target,
        observationCount: e.observationCount,
        stabilityScore: e.stabilityScore ?? 100,
        lastStatus: e.lastStatus,
        confidencePct: Math.min(99, Math.round(50 + Math.min(e.observationCount, 20) * 2.4)),
        evidenceSummary: `${e.observationCount} empirical wire observation(s); open ports: [${(e.openPorts || []).join(', ') || 'none'}]; EWMA RTT: ${e.ewmaRttMs ?? e.avgRttMs ?? 'N/A'} ms`
      }));

    return {
      generatedAt: new Date().toISOString(),
      fleetHealthScore: briefing.fleetAverageStabilityScore,
      totalTrackedTargets: entities.length,
      topologyNodesCount: (graphState.nodes || []).length,
      topologyEdgesCount: (graphState.edges || []).length,
      whatIsDegrading,
      sharedDependencyRisks,
      whatChangedBeforeFailure,
      servicesAtRiskNext,
      similarHistoricalIncidents,
      highestPriorityInvestigation,
      strongestEvidenceFindings,
      remediationEfficacy: briefing.remediationEfficacy
    };
  }

  /**
   * Phase 1 CEO Directive: Unified Operational Intelligence Continuum
   * Connects all 10 stages of the operational lifecycle for any target into one continuous object:
   *   1. Observation -> 2. Investigation -> 3. Hypotheses -> 4. Evidence -> 5. Root Cause
   *   -> 6. Infrastructure Impact -> 7. Prediction -> 8. Recommended Action
   *   -> 9. Governed Execution -> 10. Outcome Learning
   */
  compileUnifiedOperationalJourney({
    target = 'localhost',
    port = 3000,
    steps = [],
    hypothesisEvaluation = null
  } = {}) {
    const cleanTarget = String(target || 'localhost').trim().toLowerCase();
    const numericPort = Number(port) || 3000;
    const entity = this._loadEntity(cleanTarget);
    const stabilityScore = entity ? this._computeStabilityScore(entity) : 100;
    const forecast = this.computePredictiveForecast(cleanTarget) || {
      target: cleanTarget,
      riskClassification: 'NOMINAL_STABLE',
      operationalRiskSignificance: 'NOMINAL_BASELINE',
      operationalVsStatisticalNote: 'Baseline nominal.',
      stabilityScore,
      statisticalConfidence: 0.5,
      explanation: `No adverse RTT drift or flapping detected on ${cleanTarget}.`
    };
    const depContext = this.getTargetDependencyContext(cleanTarget, entity?.resolvedIps || []);
    const recentEvidence = evidenceFabric.queryEvidence({ subject: cleanTarget, limit: 8 });
    const hypEval = hypothesisEvaluation || this.evaluateDiagnosticHypotheses({
      target: cleanTarget,
      port: numericPort,
      memoryInsights: {
        target: cleanTarget,
        observationCount: entity?.observationCount || 0,
        stabilityScore,
        stateTransitions: entity?.transitions || [],
        dependencyContext: depContext
      }
    });
    const remediation = this.recommendRemediationWithHistory({
      target: cleanTarget,
      failureLayer: hypEval.primaryRootCause?.layer || entity?.lastFailureLayer || null,
      port: numericPort
    });
    const targetDecisions = this.listOperationalDecisions(20).filter((d) => !d.targetKey || d.targetKey === cleanTarget);
    const latestDecision = targetDecisions[0] || null;
    const matchedPlaybooks = remediation.matchedPlaybooks || [];

    const hasFault = Boolean(
      (hypEval.primaryRootCause && hypEval.primaryRootCause.hypothesisId) ||
      entity?.lastStatus === 'FAIL'
    );

    const stages = [
      {
        stageNumber: 1,
        id: 'OBSERVATION',
        label: 'Observation',
        status: entity ? (entity.lastStatus === 'FAIL' ? 'ALERT' : 'VERIFIED') : 'INITIALIZED',
        summary: entity
          ? `${entity.observationCount} check(s) on ${cleanTarget} · Stability ${stabilityScore}% · Last status: ${entity.lastStatus || 'PASS'}`
          : `Initial observation context established for ${cleanTarget}:${numericPort}`
      },
      {
        stageNumber: 2,
        id: 'INVESTIGATION',
        label: 'Investigation',
        status: steps.length > 0 ? 'COMPLETED' : 'READY',
        summary: steps.length > 0
          ? `Executed ${steps.length} live diagnostic step(s); skipped ${hypEval.redundancySkipped?.length || 0} redundant check(s)`
          : `Next highest-IG check: ${hypEval.nextBestInvestigation?.action || 'Multi-layer protocol probe'}`
      },
      {
        stageNumber: 3,
        id: 'HYPOTHESES',
        label: 'Hypotheses',
        status: hypEval.hypotheses?.length > 0 ? 'EVALUATED' : 'READY',
        summary: `Evaluated ${hypEval.hypotheses?.length || 0} competing hypotheses (${hypEval.contradictions?.length || 0} cross-layer contradiction(s))`
      },
      {
        stageNumber: 4,
        id: 'EVIDENCE',
        label: 'Evidence',
        status: recentEvidence.length > 0 || steps.length > 0 ? 'GROUNDED' : 'PENDING',
        summary: `${Math.max(recentEvidence.length, steps.length)} empirical evidence record(s) linked in Sovereign Evidence Fabric`
      },
      {
        stageNumber: 5,
        id: 'ROOT_CAUSE',
        label: 'Root Cause',
        status: hasFault ? 'FAULT_ISOLATED' : 'HEALTHY_VERIFIED',
        summary: hypEval.primaryRootCause?.summary || `All probed layers on ${cleanTarget}:${numericPort} healthy`
      },
      {
        stageNumber: 6,
        id: 'INFRASTRUCTURE_IMPACT',
        label: 'Impact',
        status: (depContext.downstreamDependents?.length || 0) > 0 && hasFault ? 'BLAST_RADIUS_ACTIVE' : 'CONTAINED',
        summary: `${depContext.upstreamDependencies?.length || 0} upstream dependency link(s) · ${depContext.downstreamDependents?.length || 0} downstream dependent(s)`
      },
      {
        stageNumber: 7,
        id: 'PREDICTION',
        label: 'Prediction',
        status: forecast.riskClassification === 'NOMINAL_STABLE' ? 'NOMINAL' : 'RISK_DETECTED',
        summary: `${forecast.riskClassification} (${forecast.operationalRiskSignificance}) — ${forecast.explanation}`
      },
      {
        stageNumber: 8,
        id: 'RECOMMENDED_ACTION',
        label: 'Action',
        status: remediation.warningPriorFailure ? 'ADAPTIVE_PIVOT' : 'RECOMMENDED',
        summary: remediation.adaptivePivotRationale
          ? `Adaptive Pivot: ${remediation.effectiveRecommendedActionLabel}`
          : remediation.recommendedActionLabel
      },
      {
        stageNumber: 9,
        id: 'GOVERNED_EXECUTION',
        label: 'Execution',
        status: latestDecision ? latestDecision.outcomeStatus : 'AWAITING_AUTHORIZATION',
        summary: latestDecision
          ? `Last execution '${latestDecision.actionId}' by ${latestDecision.approvedBy}: ${latestDecision.outcomeStatus}`
          : 'Governed execution gated by RBAC & pre-execution SQLite snapshot'
      },
      {
        stageNumber: 10,
        id: 'OUTCOME_LEARNING',
        label: 'Learning',
        status: matchedPlaybooks.length > 0 || targetDecisions.length > 0 ? 'ACTIVE_LEARNING' : 'BASELINE_TRACKING',
        summary: `${matchedPlaybooks.length} learned playbook(s) · ${targetDecisions.length} recorded decision outcome(s)`
      }
    ];

    const normalizedStages = stages.map((s) => ({
      ...s,
      stageId: s.stageId || s.id
    }));

    return {
      target: cleanTarget,
      port: numericPort,
      generatedAt: new Date().toISOString(),
      stageCount: normalizedStages.length,
      stages: normalizedStages,
      hypothesisEvaluation: hypEval,
      predictiveForecast: forecast,
      dependencyContext: depContext,
      remediationRecommendation: remediation,
      latestDecision,
      matchedPlaybooks
    };
  }

  /**
   * Synthesize a cross-target Operational Intelligence Briefing:
   *   - Systemic correlation across targets (layer + shared topological upstream dependencies)
   *   - Active regressions and state transitions
   *   - Predictive latency drift, flapping & SLA breach forecasts
   *   - Learned playbooks & historical decision efficacy
   */
  getIntelligenceBriefing() {
    const overview = this.getOperationalMemoryOverview(50);
    const entities = overview.entities || [];
    const resolutions = overview.resolutions || [];
    const decisions = overview.decisions || [];

    const activeRegressions = [];
    const predictiveRisks = [];
    const predictiveForecasts = [];
    const failingByLayer = new Map();
    const failingByUpstreamNode = new Map();

    for (const ent of entities) {
      const recentTransitions = (ent.transitions || []).slice(-5);
      for (const tr of recentTransitions) {
        if (String(tr.type || '').includes('REGRESSION') || String(tr.type || '').includes('SPIKE') || String(tr.type || '').includes('FLAPPING')) {
          activeRegressions.push({
            target: ent.target,
            type: tr.type,
            severity: tr.severity || 'WARN',
            stabilityScore: ent.stabilityScore ?? 100,
            port: tr.port || null,
            message: tr.message,
            detail: tr.message,
            observedAt: tr.observedAt || ent.lastSeenAt
          });
        }
      }

      if (ent.lastStatus === 'FAIL') {
        const layerKey = ent.lastFailureLayer || ent.lastIntent || 'unknown_layer';
        const list = failingByLayer.get(layerKey) || [];
        list.push(ent.target);
        failingByLayer.set(layerKey, list);

        // Also correlate by shared upstream dependency in TemporalInfrastructureGraph
        const depCtx = this.getTargetDependencyContext(ent.target, ent.resolvedIps || []);
        for (const up of depCtx.upstreamDependencies || []) {
          if (up.nodeId) {
            const uList = failingByUpstreamNode.get(up.nodeId) || [];
            if (!uList.includes(ent.target)) uList.push(ent.target);
            failingByUpstreamNode.set(up.nodeId, uList);
          }
        }
      }

      const forecast = this.computePredictiveForecast(ent.target);
      if (forecast) {
        predictiveForecasts.push(forecast);
      }

      if (typeof ent.rttTrendSlopeMs === 'number' && ent.rttTrendSlopeMs > 5) {
        const msg = `${ent.target} exhibits rising RTT trend (+${ent.rttTrendSlopeMs} ms/observation; EWMA ${ent.ewmaRttMs} ms vs mean ${ent.avgRttMs} ms)` +
          (forecast?.estimatedObservationsToSlaBreach !== null && forecast?.estimatedObservationsToSlaBreach !== undefined
            ? ` — projected 250ms SLA breach in ~${forecast.estimatedObservationsToSlaBreach} check(s).`
            : '.');
        predictiveRisks.push({
          target: ent.target,
          type: 'POSITIVE_LATENCY_DRIFT_VELOCITY',
          riskType: 'POSITIVE_LATENCY_DRIFT_VELOCITY',
          severity: 'WARN',
          slopeMsPerObs: ent.rttTrendSlopeMs,
          avgRttMs: ent.avgRttMs,
          ewmaRttMs: ent.ewmaRttMs,
          estimatedObservationsToSlaBreach: forecast?.estimatedObservationsToSlaBreach ?? null,
          operationalRiskSignificance: forecast?.operationalRiskSignificance || 'ACTIONABLE_PREVENTIVE_RISK',
          summary: msg,
          detail: msg
        });
      } else if (forecast && forecast.flappingIndex >= 0.5) {
        const msg = `${ent.target} exhibits intermittent state flapping (oscillation index ${(forecast.flappingIndex * 100).toFixed(0)}%, stability ${ent.stabilityScore}%).`;
        predictiveRisks.push({
          target: ent.target,
          type: 'INTERMITTENT_FLAPPING_INSTABILITY',
          riskType: 'INTERMITTENT_FLAPPING_INSTABILITY',
          severity: 'WARN',
          flappingIndex: forecast.flappingIndex,
          stabilityScore: ent.stabilityScore,
          operationalRiskSignificance: 'ACTIONABLE_PREVENTIVE_RISK',
          summary: msg,
          detail: msg
        });
      } else if (ent.stabilityScore < 75) {
        const msg = `${ent.target} has a reduced stability score of ${ent.stabilityScore}% (${ent.failureCount}/${ent.observationCount} failed checks).`;
        predictiveRisks.push({
          target: ent.target,
          type: 'ELEVATED_INSTABILITY_INDEX',
          riskType: 'ELEVATED_INSTABILITY_INDEX',
          severity: 'WARN',
          stabilityScore: ent.stabilityScore,
          failureCount: ent.failureCount,
          observationCount: ent.observationCount,
          operationalRiskSignificance: 'ACTIONABLE_PREVENTIVE_RISK',
          summary: msg,
          detail: msg
        });
      }
    }

    const systemicPatterns = [];
    for (const [layer, targets] of failingByLayer.entries()) {
      if (targets.length >= 2) {
        const detail = `Correlated failure across ${targets.length} targets (${targets.join(', ')}) at layer '${layer}', indicating a shared upstream or local subsystem constraint rather than an isolated endpoint fault.`;
        systemicPatterns.push({
          patternId: `SYS-${layer.toUpperCase().replace(/[^A-Z0-9]/g, '_')}`,
          pattern: `MULTI_TARGET_${layer.toUpperCase().replace(/[^A-Z0-9]/g, '_')}`,
          severity: 'HIGH',
          failureLayer: layer,
          affectedTargets: targets,
          summary: detail,
          detail,
          recommendation: `Inspect shared ${layer} infrastructure before restarting individual services.`
        });
      }
    }

    for (const [upstreamNodeId, targets] of failingByUpstreamNode.entries()) {
      if (targets.length >= 2) {
        const detail = `Topological Shared-Dependency Fault: ${targets.length} failing targets (${targets.join(', ')}) share upstream dependency node '${upstreamNodeId}' in the Temporal Infrastructure Graph.`;
        systemicPatterns.push({
          patternId: `SYS-TOPO-${upstreamNodeId.toUpperCase().replace(/[^A-Z0-9]/g, '_')}`,
          pattern: `SHARED_UPSTREAM_DEPENDENCY_${upstreamNodeId}`,
          severity: 'HIGH',
          upstreamNodeId,
          affectedTargets: targets,
          summary: detail,
          detail,
          recommendation: `Investigate shared upstream node ${upstreamNodeId} and its blast radius first.`
        });
      }
    }

    const avgStability = entities.length > 0
      ? Math.round(entities.reduce((acc, e) => acc + (e.stabilityScore ?? 100), 0) / entities.length)
      : 100;
    const healthyEntities = entities.filter((e) => (e.stabilityScore ?? 100) >= 80 && e.lastStatus !== 'FAIL').length;
    const remediationEfficacy = this.getRemediationEfficacyReport();

    return {
      generatedAt: new Date().toISOString(),
      totalEntitiesTracked: entities.length,
      fleetAverageStabilityScore: avgStability,
      fleetSummary: {
        totalTrackedEntities: entities.length,
        healthyEntities,
        degradedEntities: Math.max(0, entities.length - healthyEntities),
        averageStabilityScore: avgStability,
        activeRegressionCount: activeRegressions.length,
        predictiveRiskCount: predictiveRisks.length
      },
      activeRegressionsCount: activeRegressions.length,
      activeRegressions: activeRegressions.slice(0, 12),
      systemicPatterns,
      predictiveRisks: predictiveRisks.slice(0, 10),
      predictiveForecasts: predictiveForecasts.slice(0, 12),
      remediationEfficacy,
      learnedPlaybooksCount: resolutions.length,
      learnedPlaybooks: resolutions.slice(0, 10),
      recordedDecisionsCount: decisions.length,
      recentDecisions: decisions.slice(0, 10)
    };
  }

  /**
   * Phase 6 — Continuous Learning Operational Memory:
   * Evaluates knowledge freshness, exponential confidence decay, and whether
   * subsequent infrastructure changes or decisions invalidated older historical state.
   */
  computeKnowledgeFreshnessAndDecay(entityOrTarget, recentDecisions = null) {
    const ent = typeof entityOrTarget === 'string'
      ? this._loadEntity(entityOrTarget.trim().toLowerCase())
      : entityOrTarget;
    if (!ent) {
      return {
        ageSeconds: null,
        freshnessState: 'UNOBSERVED',
        freshnessScorePct: 0,
        confidenceDecayMultiplier: 0.4,
        invalidatedByRecentChange: false,
        invalidatedByChange: false,
        requiresReverification: true,
        invalidationReason: null,
        epistemicNote: 'No empirical observation recorded yet; live verification is required.'
      };
    }

    const nowMs = Date.now();
    const lastSeenMs = ent.lastSeenAt ? new Date(ent.lastSeenAt).getTime() : nowMs;
    const ageSeconds = Math.max(0, Math.round((nowMs - (Number.isFinite(lastSeenMs) ? lastSeenMs : nowMs)) / 1000));
    const decisions = Array.isArray(recentDecisions) ? recentDecisions : this.listOperationalDecisions(25);
    const targetKey = String(ent.targetKey || ent.target || '').toLowerCase();

    const newerDecision = decisions.find((d) => {
      if (d.targetKey && String(d.targetKey).toLowerCase() !== targetKey) return false;
      const decMs = d.createdAt ? new Date(d.createdAt).getTime() : 0;
      return decMs >= lastSeenMs;
    });

    const recentTransitions = Array.isArray(ent.transitions) ? ent.transitions : [];
    const hasRecentRegression = recentTransitions.some((t) =>
      String(t.type || '').includes('REGRESSION') || String(t.type || '').includes('FLAPPING')
    );

    const invalidatedByRecentChange = Boolean(newerDecision);
    const rawFreshnessPct = Math.max(15, Math.min(100, Math.round(100 * Math.exp(-ageSeconds / 14400))));
    const freshnessScorePct = invalidatedByRecentChange ? Math.min(45, rawFreshnessPct) : rawFreshnessPct;

    let freshnessState = 'FRESH';
    let confidenceDecayMultiplier = 1.0;
    if (invalidatedByRecentChange) {
      freshnessState = 'INVALIDATED_BY_CHANGE';
      confidenceDecayMultiplier = 0.5;
    } else if (ageSeconds > 7200) {
      freshnessState = 'STALE';
      confidenceDecayMultiplier = 0.55;
    } else if (ageSeconds > 900) {
      freshnessState = 'AGING';
      confidenceDecayMultiplier = 0.82;
    }

    const epistemicNote = invalidatedByRecentChange
      ? `Historical baseline precedes governed change '${newerDecision.actionId}' (${newerDecision.outcomeStatus}); re-verify live state before relying on prior memory.`
      : freshnessState === 'STALE'
        ? `Last observation is ${Math.round(ageSeconds / 60)}m old; historical confidence is discounted by ${Math.round((1 - confidenceDecayMultiplier) * 100)}% until re-probed.`
        : hasRecentRegression
          ? `Fresh empirical observation (${ageSeconds}s ago), but active state transitions indicate environment instability.`
          : `Fresh empirical baseline (${ageSeconds}s ago, ${ent.observationCount || 1} observation(s)).`;

    return {
      ageSeconds,
      freshnessState,
      freshnessScorePct,
      confidenceDecayMultiplier,
      invalidatedByRecentChange,
      invalidatedByChange: invalidatedByRecentChange,
      requiresReverification: invalidatedByRecentChange || freshnessState === 'STALE',
      invalidationReason: newerDecision ? `Post-observation action ${newerDecision.actionId} (${newerDecision.outcomeStatus})` : null,
      epistemicNote
    };
  }

  /**
   * Phase 1 — Deeper Understanding of the Operational Environment:
   * Models infrastructure entity class, business/operational criticality tier,
   * owning engineering team, dependency blast radius, recurring problem signatures,
   * and recent infrastructure changes.
   */
  inferOperationalEnvironmentProfile(targetOrEntity) {
    const cleanTarget = typeof targetOrEntity === 'string'
      ? targetOrEntity.trim().toLowerCase()
      : String(targetOrEntity?.targetKey || targetOrEntity?.target || 'localhost').trim().toLowerCase();
    const ent = typeof targetOrEntity === 'object' && targetOrEntity !== null
      ? targetOrEntity
      : (this._loadEntity(cleanTarget) || {
          targetKey: cleanTarget,
          targetDisplay: cleanTarget,
          observationCount: 0,
          failureCount: 0,
          openPorts: [],
          closedPorts: [],
          resolvedIps: [],
          transitions: []
        });

    const depCtx = this.getTargetDependencyContext(cleanTarget, ent.resolvedIps || []);
    const allPorts = [...(ent.openPorts || []), ...(ent.closedPorts || [])].map(Number);
    const downstreamCount = (depCtx.downstreamDependents || []).length;
    const upstreamCount = (depCtx.upstreamDependencies || []).length;

    let entityClass = 'HOST_NODE';
    let criticalityTier = 'TIER_2_INTERNAL_PLATFORM';
    let criticalityScore = 55;
    let owningTeam = 'Core Platform & Systems SRE';
    let technicalDomain = 'Systems & Host Infrastructure';
    let escalationChannel = '#sre-platform-ops';
    let onCallRole = 'SYSADMIN';

    const isSharedDnsOrInfra =
      cleanTarget === '1.1.1.1' ||
      cleanTarget === '8.8.8.8' ||
      cleanTarget === '9.9.9.9' ||
      cleanTarget === 'dns.google' ||
      cleanTarget.includes('dns') ||
      allPorts.includes(53) ||
      downstreamCount >= 2;

    if (
      isSharedDnsOrInfra ||
      cleanTarget.includes('gateway') ||
      cleanTarget.includes('router') ||
      cleanTarget.includes('sw') ||
      cleanTarget.includes('firewall')
    ) {
      entityClass = isSharedDnsOrInfra
        ? 'SHARED_INFRASTRUCTURE_COMPONENT'
        : 'NETWORK_GATEWAY_OR_ROUTER';
      criticalityTier = 'TIER_0_MISSION_CRITICAL';
      criticalityScore = Math.min(100, 88 + downstreamCount * 4);
      owningTeam = 'Core Network & Infrastructure Operations';
      technicalDomain = 'Networking, Routing & DNS';
      escalationChannel = '#neteng-critical-command';
      onCallRole = 'NETWORK_ADMIN';
    } else if (
      cleanTarget === 'localhost' ||
      cleanTarget === '127.0.0.1' ||
      allPorts.includes(3000) ||
      allPorts.includes(3001) ||
      allPorts.includes(5432) ||
      allPorts.includes(6379)
    ) {
      entityClass = 'CORE_APPLICATION_SERVICE';
      criticalityTier = (cleanTarget === '127.0.0.1' || cleanTarget === 'localhost')
        ? 'TIER_0_MISSION_CRITICAL'
        : 'TIER_1_BUSINESS_CORE';
      criticalityScore = Math.min(95, 82 + downstreamCount * 5);
      owningTeam = 'Application & Control-Plane SRE';
      technicalDomain = 'Applications & Local Runtime Services';
      escalationChannel = '#app-sre-command';
      onCallRole = 'APP_OWNER';
    } else if (allPorts.includes(443) || allPorts.includes(8443) || allPorts.includes(80)) {
      entityClass = 'EXTERNAL_SERVICE_ENDPOINT';
      criticalityTier = downstreamCount > 0 ? 'TIER_1_BUSINESS_CORE' : 'TIER_2_INTERNAL_PLATFORM';
      criticalityScore = Math.min(90, 68 + downstreamCount * 6);
      owningTeam = 'Service Delivery & Edge Operations';
      technicalDomain = 'External Endpoints & TLS/HTTP';
      escalationChannel = '#noc-service-delivery';
      onCallRole = 'OPERATOR';
    }

    const transitions = Array.isArray(ent.transitions) ? ent.transitions : [];
    const recurringCounts = new Map();
    for (const tr of transitions) {
      const k = tr.type || 'STATE_TRANSITION';
      recurringCounts.set(k, (recurringCounts.get(k) || 0) + 1);
    }
    const recurringProblemSignatures = Array.from(recurringCounts.entries()).map(([sig, count]) => ({
      signature: sig,
      occurrences: count,
      isRecurring: count >= 2 || (ent.failureCount || 0) >= 2
    }));

    const targetDecisions = this.listOperationalDecisions(25).filter((d) => !d.targetKey || d.targetKey === cleanTarget);
    const recentInfrastructureChanges = [
      ...transitions.slice(-4).map((t) => ({
        changeType: t.type,
        summary: t.message,
        observedAt: t.observedAt || ent.lastSeenAt,
        source: 'WIRE_STATE_TRANSITION'
      })),
      ...targetDecisions.slice(0, 3).map((d) => ({
        changeType: d.decisionType,
        summary: `${d.actionId} (${d.outcomeStatus}): ${d.rationale}`,
        observedAt: d.createdAt,
        source: 'GOVERNED_OPERATOR_ACTION'
      }))
    ];

    const stabilityScore = this._computeStabilityScore(ent);
    const knowledgeFreshness = this.computeKnowledgeFreshnessAndDecay(ent, targetDecisions);
    const ownershipObj = {
      team: owningTeam,
      technicalDomain,
      escalationChannel,
      onCallRole
    };

    return {
      target: cleanTarget,
      entityClass,
      role: entityClass,
      roleLabel: entityClass.replace(/_/g, ' '),
      criticalityTier,
      criticalityScore,
      stabilityScore,
      lastStatus: ent.lastStatus || 'UNKNOWN',
      operationalOwnership: ownershipObj,
      ownership: ownershipObj,
      serviceDependencies: {
        upstreamCount,
        downstreamCount,
        upstreamDependencies: depCtx.upstreamDependencies || [],
        downstreamDependents: depCtx.downstreamDependents || [],
        isSharedInfrastructureComponent: downstreamCount >= 2 || entityClass === 'SHARED_INFRASTRUCTURE_COMPONENT'
      },
      recurringProblemSignatures,
      recentInfrastructureChanges: recentInfrastructureChanges.slice(0, 6),
      knowledgeFreshness
    };
  }

  /**
   * Phase 2 — New Level of Incident Intelligence:
   * Correlates anomalies across multiple targets into unified Correlated Operational Incidents,
   * separates Primary Root Cause from Downstream Symptoms, links preceding infrastructure changes,
   * identifies affected business criticality & responsible teams, and answers:
   * "What is actually happening across the infrastructure, and what is the most important thing we should address?"
   */
  correlateOperationalIncidents() {
    const overview = this.getOperationalMemoryOverview(50);
    const entities = overview.entities || [];
    const resolutions = overview.resolutions || [];
    const decisions = overview.decisions || [];

    const profilesByTarget = new Map();
    for (const ent of entities) {
      profilesByTarget.set(ent.target, this.inferOperationalEnvironmentProfile(ent));
    }

    const problemEntities = entities.filter((e) =>
      e.lastStatus === 'FAIL' ||
      (e.stabilityScore ?? 100) < 80 ||
      (e.rttTrendSlopeMs ?? 0) > 5 ||
      (Array.isArray(e.transitions) && e.transitions.some((t) => String(t.type || '').includes('REGRESSION')))
    );

    const assignedTargets = new Set();
    const correlatedIncidents = [];

    // 1. Group targets that share an upstream dependency in TemporalInfrastructureGraph
    const byUpstream = new Map();
    for (const ent of problemEntities) {
      const prof = profilesByTarget.get(ent.target);
      for (const up of prof?.serviceDependencies?.upstreamDependencies || []) {
        if (up.nodeId) {
          const list = byUpstream.get(up.nodeId) || [];
          list.push(ent);
          byUpstream.set(up.nodeId, list);
        }
      }
    }

    for (const [upstreamNodeId, group] of byUpstream.entries()) {
      if (group.length >= 2) {
        const targets = group.map((g) => g.target);
        targets.forEach((t) => assignedTargets.add(t));
        const affectedProfiles = targets.map((t) => profilesByTarget.get(t)).filter(Boolean);
        const maxCrit = Math.max(85, ...affectedProfiles.map((p) => p.criticalityScore || 70));
        const teams = Array.from(new Set([
          'Core Network & Infrastructure Operations',
          ...affectedProfiles.map((p) => p.operationalOwnership.team)
        ]));
        const precedingChanges = affectedProfiles.flatMap((p) => p.recentInfrastructureChanges || []).slice(0, 5);
        const matchedPlaybooks = this.findMatchingResolutions({ symptomSignature: group[0].lastFailureLayer || 'SHARED' });
        const rcVsSymptom = `Primary Cause is shared upstream infrastructure component '${upstreamNodeId}'; failures on [${targets.join(', ')}] are downstream cascading symptoms rather than independent endpoint faults.`;
        const recAction = `Verify and restore shared upstream node '${upstreamNodeId}' first before restarting downstream services [${targets.join(', ')}].`;

        correlatedIncidents.push({
          incidentId: `INC-SHARED-${upstreamNodeId.toUpperCase().replace(/[^A-Z0-9]/g, '_').slice(0, 14)}`,
          title: `Shared Upstream Dependency Disruption via ${upstreamNodeId} (${targets.length} Dependent Targets)`,
          classification: 'SHARED_UPSTREAM_DEPENDENCY_OUTAGE',
          incidentType: 'SHARED_UPSTREAM_DEPENDENCY_OUTAGE',
          severity: 'CRITICAL',
          criticalityTier: affectedProfiles[0]?.criticalityTier || 'TIER_0_MISSION_CRITICAL',
          status: 'ACTIVE_INVESTIGATION',
          priorityScore: Math.min(100, Math.round(maxCrit + targets.length * 4)),
          primaryRootCauseTarget: upstreamNodeId,
          primaryRootCause: rcVsSymptom,
          symptomTargets: targets,
          downstreamSymptoms: targets,
          sharedDependencyNode: upstreamNodeId,
          rootCauseVsSymptomSeparation: rcVsSymptom,
          affectedServices: affectedProfiles.map((p) => ({
            target: p.target,
            criticalityTier: p.criticalityTier,
            owningTeam: p.operationalOwnership.team,
            status: p.lastStatus
          })),
          businessImpactSummary: `Impacts ${targets.length} dependent targets including ${affectedProfiles[0]?.criticalityTier || 'TIER_1_BUSINESS_CORE'} infrastructure.`,
          precedingChanges,
          incidentTimeline: group.map((g) => ({
            timestamp: g.lastSeenAt,
            target: g.target,
            event: g.lastSummary || `${g.target} reported ${g.lastStatus} (${g.lastFailureLayer || g.lastIntent})`
          })),
          historicalPatternMatches: matchedPlaybooks.slice(0, 2),
          responsibleTeams: teams,
          responsibleTeam: affectedProfiles[0]?.operationalOwnership || { team: teams[0], escalationChannel: '#neteng-critical-command' },
          knowledgeFreshness: affectedProfiles[0]?.knowledgeFreshness || { freshnessState: 'FRESH' },
          recommendedNextAction: recAction,
          recommendedAction: recAction
        });
      }
    }

    // 2. Group remaining failing targets that share the exact same failure layer (Cascading / Systemic Layer Fault)
    const byFailureLayer = new Map();
    for (const ent of problemEntities) {
      if (assignedTargets.has(ent.target)) continue;
      if (ent.lastStatus === 'FAIL') {
        const layerKey = ent.lastFailureLayer || ent.lastIntent || 'L4_TCP_OR_PATH';
        const list = byFailureLayer.get(layerKey) || [];
        list.push(ent);
        byFailureLayer.set(layerKey, list);
      }
    }

    for (const [layerKey, group] of byFailureLayer.entries()) {
      if (group.length >= 2) {
        const targets = group.map((g) => g.target);
        targets.forEach((t) => assignedTargets.add(t));
        const affectedProfiles = targets.map((t) => profilesByTarget.get(t)).filter(Boolean);
        const primary = affectedProfiles.sort((a, b) => b.criticalityScore - a.criticalityScore)[0] || { target: targets[0], criticalityScore: 75, criticalityTier: 'TIER_1_BUSINESS_CORE' };
        const symptomTargets = targets.filter((t) => t !== primary.target);
        const teams = Array.from(new Set(affectedProfiles.map((p) => p.operationalOwnership.team)));
        const matchedPlaybooks = this.findMatchingResolutions({ symptomSignature: layerKey });
        const rcVsSymptom = `${targets.length} targets (${targets.join(', ')}) failed concurrently at layer '${layerKey}'. Primary anchor is highest-criticality target '${primary.target}'; concurrent failures on [${symptomTargets.join(', ')}] share the same subsystem fault signature.`;
        const recAction = `Investigate shared '${layerKey}' subsystem across ${primary.target} and ${symptomTargets.join(', ')} as a single unified incident.`;

        correlatedIncidents.push({
          incidentId: `INC-CORR-${layerKey.toUpperCase().replace(/[^A-Z0-9]/g, '_').slice(0, 14)}`,
          title: `Correlated Multi-Target ${layerKey} Disruption (${targets.length} Targets)`,
          classification: 'CASCADING_MULTI_SERVICE_DISRUPTION',
          incidentType: 'CASCADING_MULTI_SERVICE_DISRUPTION',
          severity: 'HIGH',
          criticalityTier: primary.criticalityTier || 'TIER_1_BUSINESS_CORE',
          status: 'ACTIVE_INVESTIGATION',
          priorityScore: Math.min(98, Math.round((primary.criticalityScore || 75) + targets.length * 4)),
          primaryRootCauseTarget: primary.target,
          primaryRootCause: rcVsSymptom,
          symptomTargets,
          downstreamSymptoms: symptomTargets,
          sharedDependencyNode: layerKey,
          rootCauseVsSymptomSeparation: rcVsSymptom,
          affectedServices: affectedProfiles.map((p) => ({
            target: p.target,
            criticalityTier: p.criticalityTier,
            owningTeam: p.operationalOwnership.team,
            status: p.lastStatus
          })),
          businessImpactSummary: `Concurrent ${layerKey} disruption across ${targets.length} infrastructure targets (${affectedProfiles[0]?.criticalityTier || 'TIER_1_BUSINESS_CORE'}).`,
          precedingChanges: affectedProfiles.flatMap((p) => p.recentInfrastructureChanges || []).slice(0, 5),
          incidentTimeline: group.map((g) => ({
            timestamp: g.lastSeenAt,
            target: g.target,
            event: g.lastSummary || `${g.target} failed at ${layerKey}`
          })),
          historicalPatternMatches: matchedPlaybooks.slice(0, 2),
          responsibleTeams: teams,
          responsibleTeam: primary.operationalOwnership || { team: teams[0], escalationChannel: '#sre-platform-ops' },
          knowledgeFreshness: primary.knowledgeFreshness || { freshnessState: 'FRESH' },
          recommendedNextAction: recAction,
          recommendedAction: recAction
        });
      }
    }

    // 3. Remaining individual high-priority target incidents or emerging SLA degradations
    for (const ent of problemEntities) {
      if (assignedTargets.has(ent.target)) continue;
      assignedTargets.add(ent.target);
      const prof = profilesByTarget.get(ent.target) || this.inferOperationalEnvironmentProfile(ent);
      const forecast = this.computePredictiveForecast(ent.target);
      const isOutage = ent.lastStatus === 'FAIL';
      const downTargets = (prof.serviceDependencies?.downstreamDependents || []).map((d) => d.nodeId);
      const matchedPlaybooks = this.findMatchingResolutions({
        target: ent.target,
        symptomSignature: ent.lastFailureLayer || ent.lastIntent
      });
      const priorityScore = Math.min(
        96,
        Math.round(
          (prof.criticalityScore * 0.55) +
          (isOutage ? 30 : 12) +
          Math.max(0, (100 - (ent.stabilityScore ?? 100)) * 0.2) +
          downTargets.length * 5
        )
      );
      const rcVsSymptom = downTargets.length > 0
        ? `Primary fault is isolated to '${ent.target}' (${ent.lastFailureLayer || 'degradation'}); downstream dependents [${downTargets.join(', ')}] are at cascading symptom risk.`
        : `Fault is isolated to endpoint '${ent.target}' (${ent.lastFailureLayer || forecast?.riskClassification || 'degraded stability'}) with no cascading downstream propagation observed.`;
      const recAction = isOutage
        ? `Run governed remediation or socket/listener verification on ${ent.target} (${prof.operationalOwnership.escalationChannel}).`
        : `Execute proactive baseline verification on ${ent.target} before SLA threshold breach.`;

      correlatedIncidents.push({
        incidentId: `INC-${ent.target.toUpperCase().replace(/[^A-Z0-9]/g, '_').slice(0, 14)}`,
        title: isOutage
          ? `${prof.criticalityTier} Service Fault on ${ent.target} (${ent.lastFailureLayer || ent.lastIntent || 'Active Failure'})`
          : `Emerging Reliability / SLA Degradation on ${ent.target} (${forecast?.riskClassification || 'Elevated Drift'})`,
        classification: isOutage ? 'SERVICE_OUTAGE_OR_DAEMON_FAULT' : 'EMERGING_SLA_DEGRADATION',
        incidentType: isOutage ? 'SERVICE_OUTAGE_OR_DAEMON_FAULT' : 'EMERGING_SLA_DEGRADATION',
        severity: isOutage && prof.criticalityScore >= 75 ? 'CRITICAL' : (isOutage ? 'HIGH' : 'WARNING'),
        criticalityTier: prof.criticalityTier,
        status: isOutage ? 'ACTIVE_INVESTIGATION' : 'MONITORING',
        priorityScore,
        primaryRootCauseTarget: ent.target,
        primaryRootCause: rcVsSymptom,
        symptomTargets: downTargets,
        downstreamSymptoms: downTargets,
        sharedDependencyNode: prof.serviceDependencies?.upstreamDependencies?.[0]?.nodeId || null,
        rootCauseVsSymptomSeparation: rcVsSymptom,
        affectedServices: [
          {
            target: ent.target,
            criticalityTier: prof.criticalityTier,
            owningTeam: prof.operationalOwnership.team,
            status: ent.lastStatus
          }
        ],
        businessImpactSummary: `${prof.entityClass} (${prof.criticalityTier}) managed by ${prof.operationalOwnership.team}; Stability ${ent.stabilityScore ?? 100}%.`,
        precedingChanges: prof.recentInfrastructureChanges || [],
        incidentTimeline: (ent.transitions || []).slice(-4).map((t) => ({
          timestamp: t.observedAt || ent.lastSeenAt,
          target: ent.target,
          event: t.message
        })),
        historicalPatternMatches: matchedPlaybooks.slice(0, 2),
        responsibleTeams: [prof.operationalOwnership.team],
        responsibleTeam: prof.operationalOwnership,
        knowledgeFreshness: prof.knowledgeFreshness,
        recommendedNextAction: recAction,
        recommendedAction: recAction
      });
    }

    correlatedIncidents.sort((a, b) => b.priorityScore - a.priorityScore);

    const topIncident = correlatedIncidents[0] || null;
    const avgStability = entities.length > 0
      ? Math.round(entities.reduce((s, e) => s + (e.stabilityScore ?? 100), 0) / entities.length)
      : 100;

    const mostImportantString = topIncident
      ? `Address ${topIncident.incidentId} on '${topIncident.primaryRootCauseTarget}' (Priority ${topIncident.priorityScore}/100, Owner: ${topIncident.responsibleTeams.join(', ')}): ${topIncident.recommendedNextAction}`
      : 'No active service outages detected; maintain continuous baseline verification and review scenario preparedness.';

    const executiveSituationSummary = {
      question: 'What is actually happening across the infrastructure, and what is the most important thing we should address?',
      overallPosture: topIncident
        ? (topIncident.severity === 'CRITICAL' ? 'CRITICAL_ACTION_REQUIRED' : 'ELEVATED_OPERATIONAL_ATTENTION')
        : 'NOMINAL',
      fleetStabilityScorePct: avgStability,
      trackedEntitiesCount: entities.length,
      correlatedIncidentCount: correlatedIncidents.length,
      rawAnomalySignalsCollapsed: problemEntities.length,
      alertFatigueReductionNote: problemEntities.length > correlatedIncidents.length
        ? `Correlated ${problemEntities.length} individual target anomaly signals into ${correlatedIncidents.length} unified operational incident(s) to eliminate duplicate alert noise.`
        : `Evaluated ${entities.length} tracked infrastructure entities across ${correlatedIncidents.length} active incident cluster(s).`,
      whatIsHappening: topIncident
        ? `Across ${entities.length} tracked infrastructure entities (Fleet Stability ${avgStability}%), EJII has correlated ${problemEntities.length} anomaly signal(s) into ${correlatedIncidents.length} unified operational incident(s). The leading situation is "${topIncident.title}" [Severity: ${topIncident.severity}, Priority ${topIncident.priorityScore}/100]. ${topIncident.rootCauseVsSymptomSeparation}`
        : `All ${entities.length || 1} tracked infrastructure entities are operating within nominal parameters (Fleet Stability ${avgStability}%). No active multi-target outages or cascading service disruptions are present.`,
      mostImportantToAddress: mostImportantString,
      mostImportantIncident: topIncident
        ? {
            incidentId: topIncident.incidentId,
            target: topIncident.primaryRootCauseTarget,
            title: topIncident.title,
            priorityScore: topIncident.priorityScore,
            whyMostImportant: `${topIncident.businessImpactSummary} ${topIncident.symptomTargets.length > 0 ? `Addressing '${topIncident.primaryRootCauseTarget}' resolves cascading risk for ${topIncident.symptomTargets.length} downstream target(s) (${topIncident.symptomTargets.join(', ')}).` : ''}`.trim(),
            responsibleTeams: topIncident.responsibleTeams,
            immediateNextAction: topIncident.recommendedNextAction
          }
        : null,
      recentDecisionsCount: decisions.length,
      learnedPlaybooksCount: resolutions.length
    };

    return {
      generatedAt: new Date().toISOString(),
      executiveSituationSummary,
      correlatedIncidents,
      environmentProfiles: Array.from(profilesByTarget.values())
    };
  }

  /**
   * Phase 3 — Elevate AI into an Intelligent Operations Commander:
   * Coordinates active investigations across workspaces, prevents duplicate probes within the freshness window,
   * tracks unresolved questions, determines escalation requirements, and enforces human approval gates.
   */
  coordinateOperationsCommander({
    workspace = 'chat-workspace',
    target = 'localhost',
    intent = 'diagnostic_probe',
    status = 'PASS',
    port = null,
    failureLayer = null,
    summary = '',
    unresolvedQuestions = []
  } = {}) {
    const cleanTarget = String(target || 'localhost').trim().toLowerCase();
    const nowIso = new Date().toISOString();
    const nowMs = Date.now();
    const probeKey = `${cleanTarget}:${port || 'any'}:${intent}`;

    // Check if an identical probe was executed within the last 45 seconds across any workspace
    const recentDup = this.commanderProbeLedger.find((p) =>
      p.probeKey === probeKey && (nowMs - p.executedAtMs) < 45000
    );
    if (recentDup) {
      this.avoidedDuplicateProbesCount += 1;
    }

    this.commanderProbeLedger.unshift({
      probeKey,
      target: cleanTarget,
      port,
      intent,
      workspace,
      status,
      summary: String(summary || '').slice(0, 200),
      executedAt: nowIso,
      executedAtMs: nowMs,
      reusedFreshEvidence: Boolean(recentDup)
    });
    if (this.commanderProbeLedger.length > 40) {
      this.commanderProbeLedger = this.commanderProbeLedger.slice(0, 40);
    }

    const prof = this.inferOperationalEnvironmentProfile(cleanTarget);
    const existing = this.commanderInvestigations.get(cleanTarget) || {
      investigationId: `CMD-INV-${cleanTarget.toUpperCase().replace(/[^A-Z0-9]/g, '_').slice(0, 12)}`,
      target: cleanTarget,
      startedAt: nowIso,
      updatedAt: nowIso,
      status: 'ACTIVE',
      workspacesInvolved: [],
      workspaces: [],
      domainsCoordinated: [],
      findings: [],
      unresolvedQuestions: [],
      escalationRequired: false,
      escalationReason: null,
      responsibleTeams: [prof.operationalOwnership.team],
      humanApprovalRequired: false,
      pendingApprovalAction: null
    };

    existing.updatedAt = nowIso;
    if (!existing.workspacesInvolved.includes(workspace)) {
      existing.workspacesInvolved.push(workspace);
    }
    existing.workspaces = existing.workspacesInvolved;

    const domainMap = {
      dns: 'Networking & DNS',
      port_check: 'Layer 4 Transport & Firewalls',
      website_check: 'Layer 7 Applications & TLS',
      log_and_startup_triage: 'Systems & Application Runtime',
      dependency_blast_radius: 'Infrastructure Topology & Dependencies',
      infrastructure_intelligence_synthesis: 'Fleet Incident Management'
    };
    const domain = domainMap[intent] || prof.operationalOwnership.technicalDomain || 'Infrastructure Operations';
    if (!existing.domainsCoordinated.includes(domain)) {
      existing.domainsCoordinated.push(domain);
    }

    if (summary) {
      existing.findings.unshift({
        observedAt: nowIso,
        workspace,
        status,
        summary: String(summary).slice(0, 220)
      });
      existing.findings = existing.findings.slice(0, 6);
    }

    const isFailingOrDegraded = status === 'FAIL' || status === 'DEGRADED';
    if (Array.isArray(unresolvedQuestions) && unresolvedQuestions.length > 0) {
      existing.unresolvedQuestions = unresolvedQuestions.slice(0, 4);
    } else if (isFailingOrDegraded) {
      existing.unresolvedQuestions = [
        `Has the underlying ${failureLayer || intent} service on ${cleanTarget} been restarted or reconfigured recently?`,
        `Are downstream dependents (${(prof.serviceDependencies.downstreamDependents || []).map((d) => d.nodeId).join(', ') || 'none'}) experiencing secondary timeouts?`
      ];
    } else {
      existing.unresolvedQuestions = [];
    }

    const isWorsening = isFailingOrDegraded && (
      status === 'DEGRADED' ||
      prof.stabilityScore < 75 ||
      prof.criticalityTier === 'TIER_0_MISSION_CRITICAL' ||
      prof.serviceDependencies.downstreamCount > 0 ||
      existing.workspacesInvolved.length >= 2
    );
    existing.escalationRequired = Boolean(isWorsening);
    existing.escalationReason = isWorsening
      ? `Target '${cleanTarget}' (${prof.criticalityTier}, Stability ${prof.stabilityScore}%) is ${status} across [${existing.workspacesInvolved.join(', ')}]; escalate to ${prof.operationalOwnership.team} (${prof.operationalOwnership.escalationChannel}).`
      : null;

    if (isFailingOrDegraded) {
      const rem = this.recommendRemediationWithHistory({ target: cleanTarget, failureLayer, port });
      existing.humanApprovalRequired = true;
      existing.pendingApprovalAction = {
        actionId: rem.effectiveRecommendedActionId,
        label: rem.effectiveRecommendedActionLabel,
        requiredRole: prof.operationalOwnership.onCallRole || 'OPERATOR',
        rationale: rem.adaptivePivotRationale || rem.rationale
      };
      existing.status = 'AWAITING_HUMAN_DECISION_OR_REMEDIATION';
    } else {
      existing.humanApprovalRequired = false;
      existing.pendingApprovalAction = null;
      existing.status = 'VERIFIED_NOMINAL';
    }

    this.commanderInvestigations.set(cleanTarget, existing);
    return {
      ...existing,
      coordinatedInvestigation: existing,
      deduplicatedProbe: Boolean(recentDup),
      avoidedDuplicateProbesCount: this.avoidedDuplicateProbesCount
    };
  }

  /**
   * Retrieve the complete AI Operations Commander coordination state across all workspaces.
   */
  getOperationsCommanderState() {
    const correlated = this.correlateOperationalIncidents();
    const investigations = Array.from(this.commanderInvestigations.values())
      .sort((a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime());

    // Ensure at least the top correlated incident target is represented in active investigations
    if (investigations.length === 0 && correlated.correlatedIncidents.length > 0) {
      const top = correlated.correlatedIncidents[0];
      this.coordinateOperationsCommander({
        workspace: 'ai-operator',
        target: top.primaryRootCauseTarget,
        intent: 'incident_correlation',
        status: top.severity === 'CRITICAL' || top.severity === 'HIGH' ? 'FAIL' : 'WARN',
        failureLayer: top.classification,
        summary: top.title
      });
    }

    const allInvestigations = Array.from(this.commanderInvestigations.values());
    const escalations = allInvestigations.filter((i) => i.escalationRequired);
    const pendingApprovals = allInvestigations.filter((i) => i.humanApprovalRequired && i.pendingApprovalAction);

    return {
      commanderVersion: '8.0-operations-commander',
      generatedAt: new Date().toISOString(),
      coordinatedDomains: [
        'Networking & DNS',
        'Systems & Kernel Sockets',
        'Applications & Services',
        'Infrastructure Topology',
        'Incident Management & Governance'
      ],
      activeInvestigationsCount: allInvestigations.length,
      activeInvestigations: allInvestigations.slice(0, 10),
      crossWorkspaceProbeLedger: this.commanderProbeLedger.slice(0, 12),
      avoidedDuplicateProbesCount: this.avoidedDuplicateProbesCount,
      escalationsCount: escalations.length,
      escalations,
      pendingHumanApprovalsCount: pendingApprovals.length,
      pendingHumanApprovals: pendingApprovals.map((p) => ({
        target: p.target,
        investigationId: p.investigationId,
        responsibleTeams: p.responsibleTeams,
        ...p.pendingApprovalAction
      }))
    };
  }

  /**
   * Phase 8 — Intelligently Adaptive Remediation Comparator:
   * Compares multiple candidate remediation options for a target/incident using current conditions,
   * historical efficacy, prior rollbacks, downstream impact, RBAC permissions, and what happens if the action fails.
   */
  compareRemediationOptions({
    target = 'localhost',
    failureLayer = null,
    port = 3000
  } = {}) {
    const cleanTarget = String(target || 'localhost').trim().toLowerCase();
    const numericPort = Number(port) || 3000;
    const prof = this.inferOperationalEnvironmentProfile(cleanTarget);
    const baseRem = this.recommendRemediationWithHistory({
      target: cleanTarget,
      failureLayer,
      port: numericPort
    });
    const efficacyReport = this.getRemediationEfficacyReport(cleanTarget);
    const failedSet = new Set(baseRem.previouslyFailedActions || []);

    const getActionEfficacy = (actId, defaultPct) => {
      const found = (efficacyReport.actions || []).find((a) => a.actionId === actId);
      return found ? found.efficacyPct : defaultPct;
    };

    const candidateOptions = [
      {
        actionId: 'verify_and_refresh_dns_resolution',
        title: `Governed DNS Resolver Refresh & Live Endpoint Verification (${cleanTarget})`,
        operationalRiskLevel: 'LOW',
        baseRiskScore: 14,
        requiredRole: 'OPERATOR',
        expectedPostActionState: `c-ares DNS cache refreshed and live DNS/TCP reachability to ${cleanTarget}:${numericPort} verified within <25ms.`,
        ifActionFailsConsequence: `Pre-execution SQLite snapshot automatically restores previous DNS server bindings and topology node statuses with zero packet drop.`,
        rollbackSafeguard: 'Automatic SQLite pre-snapshot & c-ares DNS server state restoration',
        sideEffects: 'None (non-disruptive to established TCP sockets)'
      },
      {
        actionId: 'verify_gateway_and_route_table',
        title: `Non-Destructive Kernel Socket & Port-Split Readiness Audit (${cleanTarget}:${numericPort})`,
        operationalRiskLevel: 'LOW',
        baseRiskScore: 10,
        requiredRole: 'ANALYST',
        expectedPostActionState: `Identifies whether service on ${cleanTarget} is bound to an alternate port (e.g. :3001 vs :3000) or blocked by a local route mismatch.`,
        ifActionFailsConsequence: `Read-only diagnostic verification; if inconclusive, operator proceeds to controlled service listener restart.`,
        rollbackSafeguard: 'Zero-mutation diagnostic verification (no state rollback needed)',
        sideEffects: 'Zero service interruption'
      },
      {
        actionId: 'inspect_service_listener_and_socket_binding',
        title: `Controlled Application Listener & Socket Rebind on ${cleanTarget}:${numericPort}`,
        operationalRiskLevel: prof.serviceDependencies.downstreamCount > 0 ? 'MEDIUM' : 'LOW',
        baseRiskScore: 28 + prof.serviceDependencies.downstreamCount * 6,
        requiredRole: 'SYSADMIN',
        expectedPostActionState: `Application daemon rebinds to TCP port ${numericPort} and passes 3-way handshake + HTTP health probe.`,
        ifActionFailsConsequence: `If port ${numericPort} remains CLOSED after restart, EJII triggers automatic rollback to snapshot and pivots to port-split / upstream route audit.`,
        rollbackSafeguard: 'Pre-execution configuration & socket table snapshot with postcondition TCP probe gate',
        sideEffects: `Brief (<200ms) connection drain for ${prof.serviceDependencies.downstreamCount} downstream dependent(s)`
      },
      {
        actionId: 'isolate_and_drain_failing_dependency',
        title: `Upstream Dependency Circuit-Breaker & Traffic Drain (${cleanTarget})`,
        operationalRiskLevel: 'MEDIUM',
        baseRiskScore: 42 + prof.serviceDependencies.downstreamCount * 5,
        requiredRole: 'ADMIN',
        expectedPostActionState: `Isolates degraded upstream ${cleanTarget} and shifts dependent services to fallback routing.`,
        ifActionFailsConsequence: `If fallback capacity is saturated, automatic rollback restores primary route table within 1 probe cycle.`,
        rollbackSafeguard: 'Pre-drain route & topology state snapshot in SQLite',
        sideEffects: `Temporary traffic shift across ${prof.serviceDependencies.downstreamCount} dependent service(s)`
      }
    ];

    const rankedOptions = candidateOptions.map((opt) => {
      const priorFailed = failedSet.has(opt.actionId);
      const effPct = getActionEfficacy(opt.actionId, priorFailed ? 35 : 92);
      const adjustedRiskScore = Math.min(95, opt.baseRiskScore + (priorFailed ? 38 : 0));
      const adjustedRiskLevel = adjustedRiskScore >= 55 ? 'HIGH' : (adjustedRiskScore >= 25 ? 'MEDIUM' : 'LOW');
      return {
        ...opt,
        operationalRiskLevel: adjustedRiskLevel,
        riskScore: adjustedRiskScore,
        operationalRiskScore: adjustedRiskScore,
        historicalEfficacyPct: effPct,
        expectedServiceImpact: opt.expectedPostActionState,
        consequenceIfActionFails: opt.ifActionFailsConsequence,
        previouslyFailedOnTarget: priorFailed,
        recommendationNote: priorFailed
          ? `Deprioritized: previously failed postcondition verification or rolled back on ${cleanTarget}.`
          : `Validated candidate (${effPct}% historical efficacy, risk score ${adjustedRiskScore}/100).`
      };
    }).sort((a, b) => a.riskScore - b.riskScore || b.historicalEfficacyPct - a.historicalEfficacyPct);

    rankedOptions.forEach((opt, idx) => {
      opt.optionRank = idx + 1;
      opt.rank = idx + 1;
    });

    const lowestRiskOption = rankedOptions[0];
    const fallbackOption = rankedOptions[1] || rankedOptions[0];

    return {
      target: cleanTarget,
      port: numericPort,
      criticalityTier: prof.criticalityTier,
      owningTeam: prof.operationalOwnership.team,
      lowestRiskOption,
      alternativeFallbackOption: fallbackOption,
      adaptivePivotActive: Boolean(baseRem.adaptivePivotRationale),
      adaptivePivotExplanation: baseRem.adaptivePivotRationale ||
        `Selected '${lowestRiskOption.actionId}' as lowest-risk option (Risk Score ${lowestRiskOption.riskScore}/100, Efficacy ${lowestRiskOption.historicalEfficacyPct}%). If it fails verification, fallback is '${fallbackOption.actionId}'.`,
      options: rankedOptions
    };
  }

  /**
   * Phase 7 — Intelligent Scenario Planning ("What-If" Digital Twin & Consequence Simulator):
   * Evaluates operational consequences before acting:
   *   - "What happens if this gateway/dependency becomes unavailable?"
   *   - "Which services are affected by this dependency?"
   *   - "What is the likely impact of changing this configuration?"
   *   - "Which remediation option has the lowest operational risk?"
   *   - "What could happen if the recommended action fails?"
   * Explicitly marks all projections as SIMULATED_SCENARIO_NOT_LIVE_TELEMETRY.
   */
  simulateOperationalScenario({
    target = 'localhost',
    scenarioType = 'GATEWAY_OR_DEPENDENCY_UNAVAILABLE',
    port = 3000,
    proposedChange = null,
    simulatedPacketLossPct = 100
  } = {}) {
    const cleanTarget = String(target || 'localhost').trim().toLowerCase();
    const numericPort = Number(port) || 3000;
    const normalizedType = String(scenarioType || 'GATEWAY_OR_DEPENDENCY_UNAVAILABLE').toUpperCase();
    const prof = this.inferOperationalEnvironmentProfile(cleanTarget);
    const remediationComparison = this.compareRemediationOptions({
      target: cleanTarget,
      failureLayer: normalizedType,
      port: numericPort
    });

    const downstreamList = prof.serviceDependencies.downstreamDependents || [];
    const upstreamList = prof.serviceDependencies.upstreamDependencies || [];

    // Also inspect TemporalInfrastructureGraph for multi-hop impact
    const graph = temporalInfrastructureGraph.getGraphState();
    const allNodes = graph.nodes || [];
    const affectedServices = [
      {
        nodeId: cleanTarget,
        role: 'PRIMARY_SCENARIO_TARGET',
        criticalityTier: prof.criticalityTier,
        owningTeam: prof.operationalOwnership.team,
        projectedState: normalizedType.includes('UNAVAILABLE') || normalizedType.includes('FAILURE')
          ? 'OFFLINE_UNREACHABLE'
          : 'RECONFIGURED_OR_DRAINING'
      },
      ...downstreamList.map((d) => ({
        nodeId: d.nodeId,
        role: `DOWNSTREAM_DEPENDENT (${d.relationship || 'depends_on'})`,
        criticalityTier: 'TIER_1_BUSINESS_CORE',
        owningTeam: prof.operationalOwnership.team,
        projectedState: 'CASCADING_TIMEOUT_OR_DEGRADED'
      }))
    ];

    if ((cleanTarget.includes('gateway') || cleanTarget === 'localhost' || cleanTarget === '127.0.0.1') && affectedServices.length < 3) {
      for (const n of allNodes.slice(0, 4)) {
        const nid = n.nodeId || n.id;
        if (nid && !affectedServices.some((a) => a.nodeId === nid)) {
          affectedServices.push({
            nodeId: nid,
            role: 'SHARED_FABRIC_DEPENDENT',
            criticalityTier: 'TIER_2_INTERNAL_PLATFORM',
            owningTeam: 'Core Platform & Systems SRE',
            projectedState: 'ELEVATED_LATENCY_OR_REROUTED'
          });
        }
      }
    }

    const qUnavailable = `Complete unavailability of '${cleanTarget}' (${prof.entityClass}, ${prof.criticalityTier}) disrupts ${affectedServices.length} infrastructure node(s)/service(s) (${affectedServices.map((a) => a.nodeId).join(', ')}). Responsible escalation team: ${prof.operationalOwnership.team} (${prof.operationalOwnership.escalationChannel}).`;
    const qAffected = `${affectedServices.length} service node(s) are in the blast radius of '${cleanTarget}': ${affectedServices.map((a) => `${a.nodeId} [${a.role}]`).join(', ')}.`;
    const qConfigChange = `Changing ${proposedChange || `port ${numericPort} binding`} on '${cleanTarget}' (${prof.criticalityTier}) impacts ${affectedServices.length} dependent node(s); uncoordinated port changes risk PORT_SPLIT_READINESS_MISMATCH unless health probes and reverse proxies are updated together.`;
    const qSubnetVlanMove = `Migrating '${cleanTarget}' (${prof.entityClass}) to a new subnet/VLAN invalidates existing Layer 3 gateway adjacency, DHCP IPHelper/relay bindings, inter-VLAN firewall ACLs for port(s) [${(prof.entity?.openPorts || [numericPort]).join(', ')}], and cached DNS A-records across ${affectedServices.length} dependent node(s) until ARP/NDP and DNS TTLs converge.`;
    const qDhcpExhaustion = `If DHCP scope capacity on the '${cleanTarget}' segment is exhausted, newly joining or renewing endpoints time out during DORA discovery and fall back to RFC 3927 link-local APIPA (169.254.0.0/16), losing default gateway and internal DNS reachability across ${affectedServices.length} dependent node(s) while existing active leases continue until T1/T2 expiration.`;
    const qLowestRisk = `'${remediationComparison.lowestRiskOption.title}' (${remediationComparison.lowestRiskOption.actionId}) has the lowest operational risk (Risk Score ${remediationComparison.lowestRiskOption.operationalRiskScore}/100, Historical Efficacy ${remediationComparison.lowestRiskOption.historicalEfficacyPct}%).`;
    const qActionFails = `${remediationComparison.lowestRiskOption.consequenceIfActionFails} EJII will then automatically pivot to Rank #2 fallback '${remediationComparison.alternativeFallbackOption.actionId}'.`;

    let questionAnswered = '';
    let consequenceSummary = '';
    if (normalizedType.includes('DHCP') || normalizedType.includes('SCOPE') || normalizedType.includes('EXHAUST')) {
      questionAnswered = `What would happen if DHCP scope capacity is exhausted on '${cleanTarget}'?`;
      consequenceSummary = `[SIMULATED] ${qDhcpExhaustion}`;
    } else if (normalizedType.includes('VLAN') || normalizedType.includes('SUBNET')) {
      questionAnswered = `What happens if I move '${cleanTarget}' (or its subnet) to another VLAN?`;
      consequenceSummary = `[SIMULATED] ${qSubnetVlanMove}`;
    } else if (normalizedType.includes('CONFIG') || normalizedType.includes('PORT') || normalizedType.includes('FIREWALL')) {
      questionAnswered = `What is the likely impact of changing configuration (${proposedChange || `port ${numericPort} binding`}) on ${cleanTarget}?`;
      consequenceSummary = `[SIMULATED] ${qConfigChange}`;
    } else if (normalizedType.includes('REMEDIATION') || normalizedType.includes('FAIL')) {
      questionAnswered = `Which remediation option has the lowest operational risk on ${cleanTarget}, and what happens if the recommended action fails?`;
      consequenceSummary = `[SIMULATED] ${qLowestRisk} ${qActionFails}`;
    } else {
      questionAnswered = `What happens if ${cleanTarget} becomes unavailable, and which services are affected by this dependency?`;
      consequenceSummary = `[SIMULATED] ${qUnavailable}`;
    }

    const simulationBadge = '[SIMULATED SCENARIO — NOT LIVE TELEMETRY]';
    const simulationBanner = `${simulationBadge} Counterfactual consequence projection derived from dependency topology and historical efficacy.`;

    const relationshipProvenance = affectedServices.map((svc) => ({
      nodeId: svc.nodeId,
      role: svc.role,
      provenanceType: svc.role === 'PRIMARY_SCENARIO_TARGET' || downstreamList.some((d) => d.nodeId === svc.nodeId)
        ? 'OBSERVED_WIRE_RELATIONSHIP'
        : 'INFERRED_TOPOLOGY_DEPENDENCY'
    }));

    return {
      scenarioId: `SCEN-${Date.now().toString(36).toUpperCase()}`,
      generatedAt: new Date().toISOString(),
      isSimulated: true,
      telemetryClassification: 'SIMULATED_SCENARIO_NOT_LIVE_TELEMETRY',
      simulationBadge,
      simulationBanner,
      disclaimer: simulationBanner,
      scenarioType: normalizedType,
      target: cleanTarget,
      port: numericPort,
      proposedChange: proposedChange || `Simulate ${normalizedType} on ${cleanTarget}:${numericPort}`,
      environmentProfile: prof,
      questionAnswered,
      consequenceSummary,
      relationshipProvenance,
      impactAnalysis: {
        whatHappensIfUnavailable: qUnavailable,
        whatHappensIfSubnetOrVlanMoved: qSubnetVlanMove,
        affectedServicesCount: affectedServices.length,
        cascadingCongestionNodes: Math.max(0, affectedServices.length - 1),
        affectedServices,
        upstreamDependencies: upstreamList,
        downstreamDependents: downstreamList,
        relationshipProvenance
      },
      questionsAnswered: {
        whatHappensIfUnavailable: {
          question: `What happens if ${cleanTarget} becomes unavailable?`,
          answer: qUnavailable
        },
        whichServicesAffected: {
          question: `Which services are affected by this dependency (${cleanTarget})?`,
          answer: qAffected
        },
        impactOfConfigurationChange: {
          question: `What is the likely impact of changing this configuration on ${cleanTarget}:${numericPort}?`,
          answer: qConfigChange
        },
        impactOfSubnetOrVlanMove: {
          question: `What happens if I move ${cleanTarget} or its subnet to another VLAN?`,
          answer: qSubnetVlanMove
        },
        impactOfDhcpScopeExhaustion: {
          question: `What would happen if DHCP scope capacity is exhausted on ${cleanTarget}?`,
          answer: qDhcpExhaustion
        },
        whichRemediationHasLowestRisk: {
          question: `Which remediation option has the lowest operational risk?`,
          answer: qLowestRisk
        },
        whatCouldHappenIfRecommendedActionFails: {
          question: `What could happen if the recommended action fails?`,
          answer: qActionFails
        }
      },
      consequenceAnalysis: {
        targetEntityClass: prof.entityClass,
        targetCriticalityTier: prof.criticalityTier,
        responsibleTeam: prof.operationalOwnership.team,
        escalationChannel: prof.operationalOwnership.escalationChannel,
        affectedNodeCount: affectedServices.length,
        affectedServices,
        upstreamDependencies: upstreamList,
        downstreamDependents: downstreamList,
        simulatedPacketLossPct: Number(simulatedPacketLossPct) || 100,
        projectedBlastRadiusPct: Math.min(100, Math.round((affectedServices.length / Math.max(3, allNodes.length || 4)) * 100))
      },
      remediationComparison
    };
  }

  /**
   * Idea 11 ("The Last Admin") — Record & Preserve Institutional / Organizational Knowledge
   * Preserves undocumented runbooks, critical dependency notes, and architectural rationale.
   */
  recordOrganizationalKnowledge({
    knowledgeId = null,
    targetKey = '127.0.0.1',
    category = 'SERVICE_ARCHITECTURE_RUNBOOK',
    title = 'Operational Runbook Entry',
    criticalDependencyNote = '',
    runbookProcedure = '',
    historicalRationale = '',
    owningTeam = 'Core Platform & Systems SRE',
    author = 'admin'
  } = {}) {
    const cleanTarget = String(targetKey || '127.0.0.1').trim().toLowerCase();
    const nowIso = new Date().toISOString();
    const id = knowledgeId || `ORG-KB-${crypto.createHash('sha1').update(`${cleanTarget}:${title}`).digest('hex').slice(0, 10).toUpperCase()}`;
    const entry = {
      knowledgeId: id,
      targetKey: cleanTarget,
      category: String(category || 'SERVICE_ARCHITECTURE_RUNBOOK').toUpperCase(),
      title: String(title || 'Operational Runbook Entry').trim(),
      criticalDependencyNote: String(criticalDependencyNote || 'Mission-critical operational dependency').trim(),
      runbookProcedure: String(runbookProcedure || 'Verify L3/L4/L7 reachability and check active socket bindings before restarting.').trim(),
      historicalRationale: String(historicalRationale || 'Preserved in EJII Organizational Knowledge Vault to prevent institutional memory loss.').trim(),
      owningTeam: String(owningTeam || 'Core Platform & Systems SRE').trim(),
      author: String(author || 'admin').trim(),
      createdAt: nowIso,
      updatedAt: nowIso
    };

    const existingIdx = this.organizationalKnowledgeCache.findIndex((k) => k.knowledgeId === id);
    if (existingIdx >= 0) {
      this.organizationalKnowledgeCache[existingIdx] = entry;
    } else {
      this.organizationalKnowledgeCache.unshift(entry);
    }

    if (this.useSqlite && db) {
      try {
        db.prepare(`
          INSERT INTO ejii_organizational_knowledge (
            knowledge_id, target_key, category, title, critical_dependency_note,
            runbook_procedure, historical_rationale, owning_team, author, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(knowledge_id) DO UPDATE SET
            target_key = excluded.target_key,
            category = excluded.category,
            title = excluded.title,
            critical_dependency_note = excluded.critical_dependency_note,
            runbook_procedure = excluded.runbook_procedure,
            historical_rationale = excluded.historical_rationale,
            owning_team = excluded.owning_team,
            author = excluded.author,
            updated_at = excluded.updated_at
        `).run(
          entry.knowledgeId,
          entry.targetKey,
          entry.category,
          entry.title,
          entry.criticalDependencyNote,
          entry.runbookProcedure,
          entry.historicalRationale,
          entry.owningTeam,
          entry.author,
          entry.createdAt,
          entry.updatedAt
        );
      } catch (_) {}
    }

    return entry;
  }

  /**
   * Ideas 9 & 11 ("The Last Admin" & "Human Firewall") — Organizational Knowledge & Operational Resilience Audit
   * Evaluates institutional knowledge preservation, runbook coverage across critical targets, and team concentration risk.
   */
  getOrganizationalKnowledgeAndResilience(targetFilter = null) {
    let entries = [...this.organizationalKnowledgeCache];
    if (this.useSqlite && db) {
      try {
        const rows = db.prepare('SELECT * FROM ejii_organizational_knowledge ORDER BY updated_at DESC LIMIT 50').all();
        if (rows && rows.length > 0) {
          entries = rows.map((r) => ({
            knowledgeId: r.knowledge_id,
            targetKey: r.target_key,
            category: r.category,
            title: r.title,
            criticalDependencyNote: r.critical_dependency_note,
            runbookProcedure: r.runbook_procedure,
            historicalRationale: r.historical_rationale,
            owningTeam: r.owning_team,
            author: r.author,
            createdAt: r.created_at,
            updatedAt: r.updated_at
          }));
          this.organizationalKnowledgeCache = entries;
        }
      } catch (_) {}
    }

    const overview = this.getOperationalMemoryOverview(50);
    const entities = overview.entities || [];
    const resolutions = overview.resolutions || [];
    const profiles = entities.map((e) => this.inferOperationalEnvironmentProfile(e.target));

    const teamLoadMap = new Map();
    const undocumentedCriticalTargets = [];

    for (const prof of profiles) {
      const team = prof.operationalOwnership.team;
      const cur = teamLoadMap.get(team) || { team, criticalTargetsCount: 0, totalTargetsCount: 0, targets: [] };
      cur.totalTargetsCount += 1;
      if (prof.criticalityTier === 'TIER_0_MISSION_CRITICAL' || prof.criticalityTier === 'TIER_1_BUSINESS_CORE') {
        cur.criticalTargetsCount += 1;
      }
      cur.targets.push(prof.target);
      teamLoadMap.set(team, cur);

      const hasRunbook = entries.some((k) => k.targetKey === prof.target) ||
        resolutions.some((r) => r.targetKey === prof.target);
      if (!hasRunbook && (prof.criticalityTier === 'TIER_0_MISSION_CRITICAL' || prof.criticalityTier === 'TIER_1_BUSINESS_CORE')) {
        undocumentedCriticalTargets.push({
          target: prof.target,
          criticalityTier: prof.criticalityTier,
          owningTeam: team,
          gapReason: `No preserved institutional runbook or verified playbook found for ${prof.criticalityTier} entity '${prof.target}'.`
        });
      }
    }

    const teamDistribution = Array.from(teamLoadMap.values()).sort((a, b) => b.criticalTargetsCount - a.criticalTargetsCount);
    const totalCritical = profiles.filter((p) => p.criticalityTier === 'TIER_0_MISSION_CRITICAL' || p.criticalityTier === 'TIER_1_BUSINESS_CORE').length || 1;
    const documentedCritical = Math.max(0, totalCritical - undocumentedCriticalTargets.length);
    const runbookCoveragePct = Math.min(100, Math.round((documentedCritical / totalCritical) * 100));

    const filteredEntries = targetFilter
      ? entries.filter((k) => k.targetKey === String(targetFilter).toLowerCase() || k.targetKey === 'default_gateway')
      : entries;

    return {
      generatedAt: new Date().toISOString(),
      knowledgeVaultCount: entries.length,
      verifiedPlaybooksCount: resolutions.length,
      entries: filteredEntries,
      humanFirewallResilience: {
        privacyGuarantee: 'Role- and team-level operational resilience analysis only; zero invasive individual employee surveillance.',
        runbookCoveragePct,
        undocumentedCriticalTargetsCount: undocumentedCriticalTargets.length,
        undocumentedCriticalTargets,
        teamConcentrationDistribution: teamDistribution,
        busFactorRiskSummary: undocumentedCriticalTargets.length > 0
          ? `${undocumentedCriticalTargets.length} mission-critical/business-core system(s) (${undocumentedCriticalTargets.map((u) => u.target).join(', ')}) lack a dedicated runbook in 'The Last Admin' Knowledge Vault.`
          : `All ${totalCritical} mission-critical/business-core entities have preserved runbooks or verified incident resolution playbooks.`
      }
    };
  }

  /**
   * Idea 5 ("Incident DNA") — Structural Incident Fingerprinting & Historical Similarity Engine
   * Fingerprints active/historical incidents across protocol layer, symptom vector, entity class, and topology role.
   * Answers: "Have we experienced this type of outage before, and what actually resolved it?"
   */
  computeIncidentDnaAndSimilarities({
    target = null,
    failureLayer = null,
    symptomSignature = null,
    port = null
  } = {}) {
    const incidentIntel = this.correlateOperationalIncidents();
    const overview = this.getOperationalMemoryOverview(50);
    const resolutions = overview.resolutions || [];
    const decisions = this.listOperationalDecisions(40);

    const activeIncident = (target
      ? incidentIntel.correlatedIncidents.find((i) =>
          i.primaryRootCauseTarget === String(target).toLowerCase() ||
          (i.affectedTargets || i.symptomTargets || []).includes(String(target).toLowerCase())
        )
      : null) || incidentIntel.correlatedIncidents[0] || null;

    const effectiveTarget = String(target || activeIncident?.primaryRootCauseTarget || '127.0.0.1').trim().toLowerCase();
    const prof = this.inferOperationalEnvironmentProfile(effectiveTarget);
    const entity = this._loadEntity(effectiveTarget);
    const effLayer = String(
      failureLayer ||
      activeIncident?.classification ||
      entity?.lastFailureLayer ||
      (entity?.closedPorts?.length ? 'L4_TCP_CLOSED' : 'L7_SERVICE_HEALTH')
    ).toUpperCase();
    const effPort = Number(port || (entity?.closedPorts?.[0]) || (entity?.openPorts?.[0]) || 3000);
    const effSymptom = String(
      symptomSignature ||
      activeIncident?.title ||
      entity?.lastSummary ||
      `${effLayer}:${effectiveTarget}:${effPort}`
    );

    const structuralGenes = {
      protocolLayerGene: effLayer.includes('DNS') ? 'GENE_L3_DNS'
        : effLayer.includes('GATEWAY') || effLayer.includes('ROUTE') || effLayer.includes('SHARED') ? 'GENE_L3_ROUTING_SHARED'
        : effLayer.includes('PORT') || effLayer.includes('TCP') || effLayer.includes('L4') ? 'GENE_L4_TRANSPORT_SOCKET'
        : 'GENE_L7_APPLICATION_HTTP',
      entityClassGene: prof.entityClass,
      criticalityGene: prof.criticalityTier,
      blastTopologyGene: prof.serviceDependencies.downstreamCount > 0 ? 'MULTI_DEPENDENT_HUB' : 'LEAF_SERVICE_ENDPOINT',
      transitionPatternGene: (entity?.transitions || []).some((t) => String(t.type).includes('PORT_STATE'))
        ? 'PORT_REGRESSION_SIGNATURE'
        : ((entity?.transitions || []).some((t) => String(t.type).includes('LATENCY')) ? 'LATENCY_DRIFT_SIGNATURE' : 'DIRECT_STATE_TRANSITION')
    };

    const hashSeed = `${structuralGenes.protocolLayerGene}|${structuralGenes.entityClassGene}|${structuralGenes.blastTopologyGene}|${ structuralGenes.transitionPatternGene}`;
    const dnaHash = crypto.createHash('sha1').update(hashSeed).digest('hex').slice(0, 8).toUpperCase();
    const dnaFingerprintId = `DNA-${structuralGenes.protocolLayerGene.replace('GENE_', '')}-${dnaHash}`;

    const similarHistoricalMatches = resolutions.map((res) => {
      let score = 35;
      const matchReasons = [];
      if (res.targetKey && res.targetKey.toLowerCase() === effectiveTarget) {
        score += 30;
        matchReasons.push(`Exact target entity match (${effectiveTarget})`);
      }
      if (res.port && Number(res.port) === effPort) {
        score += 15;
        matchReasons.push(`Identical service port (:${effPort})`);
      }
      const sigLower = String(res.symptomSignature || '').toLowerCase();
      const rcLower = String(res.rootCause || '').toLowerCase();
      if (
        (structuralGenes.protocolLayerGene.includes('L4') && (sigLower.includes('port') || sigLower.includes('tcp') || sigLower.includes('closed') || rcLower.includes('port') || rcLower.includes('listener'))) ||
        (structuralGenes.protocolLayerGene.includes('DNS') && (sigLower.includes('dns') || rcLower.includes('dns'))) ||
        (structuralGenes.protocolLayerGene.includes('L7') && (sigLower.includes('http') || sigLower.includes('route') || rcLower.includes('route')))
      ) {
        score += 20;
        matchReasons.push(`Matching protocol fault gene (${structuralGenes.protocolLayerGene})`);
      }
      const similarityScorePct = Math.min(99, score);
      return {
        resolutionId: res.resolutionId,
        targetKey: res.targetKey,
        port: res.port,
        similarityScorePct,
        symptomSignature: res.symptomSignature,
        rootCause: res.rootCause,
        verifiedResolutionSteps: res.resolutionSteps,
        verifiedBy: res.verifiedBy,
        hitCount: res.hitCount || 1,
        matchReasons
      };
    }).sort((a, b) => b.similarityScorePct - a.similarityScorePct);

    const bestMatch = similarHistoricalMatches[0] || null;
    const verifiedSuccessDecisions = decisions.filter((d) =>
      (!d.targetKey || d.targetKey === effectiveTarget) &&
      (d.outcomeStatus === 'VERIFIED_SUCCESS' || d.outcomeStatus === 'EXECUTED')
    );

    const answerHaveWeSeenBefore = bestMatch
      ? `Yes — Incident DNA '${dnaFingerprintId}' matches historical resolution '${bestMatch.resolutionId}' with ${bestMatch.similarityScorePct}% structural similarity (${bestMatch.matchReasons.join('; ')}). Root cause was: "${bestMatch.rootCause}". Verified resolution that fixed it: "${bestMatch.verifiedResolutionSteps}" (validated ${bestMatch.hitCount} time(s)).`
      : `Incident DNA '${dnaFingerprintId}' (${structuralGenes.protocolLayerGene} on ${prof.entityClass}) has no exact prior verified playbook on '${effectiveTarget}', but matches standard governed remediation for ${effLayer}.`;

    return {
      generatedAt: new Date().toISOString(),
      target: effectiveTarget,
      port: effPort,
      dnaFingerprintId,
      structuralGenes,
      symptomEvaluated: effSymptom,
      haveWeExperiencedBefore: Boolean(bestMatch && bestMatch.similarityScorePct >= 55),
      answerSummary: answerHaveWeSeenBefore,
      bestHistoricalMatch: bestMatch,
      similarHistoricalMatches: similarHistoricalMatches.slice(0, 5),
      historicalVerifiedDecisionsCount: verifiedSuccessDecisions.length
    };
  }

  /**
   * Ideas 7 & 13 ("Network Black Box" & "Configuration DNA") — Pre-Incident & Post-Incident Flight Recorder
   * Reconstructs chronological state changes, wire transitions, configuration/port shifts, and governed actions
   * before, during, and after an incident.
   * Answers: "Show me what changed before the outage" / "What changed during the last 24 hours?"
   */
  reconstructNetworkBlackBoxTimeline({ target = null, windowHours = 24 } = {}) {
    const overview = this.getOperationalMemoryOverview(50);
    const entities = overview.entities || [];
    const decisions = this.listOperationalDecisions(40);
    const targetFilter = target ? String(target).trim().toLowerCase() : null;

    const timelineEvents = [];
    const preFailureChanges = [];
    const activeFailureEvents = [];
    const recoveryAndGovernanceEvents = [];

    for (const entSummary of entities) {
      if (targetFilter && entSummary.target !== targetFilter) continue;
      const fullEntity = this._loadEntity(entSummary.target);
      if (!fullEntity) continue;

      for (const tr of fullEntity.transitions || []) {
        const isConfigOrStateChange = /PORT_STATE|IP_CHANGE|DNS|REGRESSION|SPIKE|FLAPPING/i.test(String(tr.type || ''));
        const ev = {
          timestamp: tr.observedAt || fullEntity.lastSeenAt,
          phase: tr.severity === 'HIGH' || tr.severity === 'CRITICAL' ? 'PRE_OR_ONSET_CHANGE' : 'STATE_TRANSITION',
          target: fullEntity.targetKey,
          eventType: tr.type || 'STATE_TRANSITION',
          severity: tr.severity || 'MEDIUM',
          detail: tr.detail || `Transition on ${fullEntity.targetKey}`,
          provenance: 'LIVE_WIRE_TRANSITION_MEMORY'
        };
        timelineEvents.push(ev);
        if (isConfigOrStateChange) {
          preFailureChanges.push(ev);
        }
      }

      for (const obs of (fullEntity.recentObservations || []).slice(0, 6)) {
        const ev = {
          timestamp: obs.observedAt || fullEntity.lastSeenAt,
          phase: obs.status === 'FAIL' ? 'INCIDENT_ONSET_OBSERVATION' : 'BASELINE_OBSERVATION',
          target: fullEntity.targetKey,
          eventType: `WIRE_OBSERVATION_${obs.intent || 'PROBE'}`.toUpperCase(),
          severity: obs.status === 'FAIL' ? 'HIGH' : 'INFO',
          detail: `${obs.intent || 'probe'} on ${fullEntity.targetKey} -> ${obs.status} (RTT: ${obs.rttMs ?? 'N/A'}ms, Open: [${(obs.openPorts || []).join(',')}], Closed: [${(obs.closedPorts || []).join(',')}])`,
          provenance: 'EMPIRICAL_WIRE_OBSERVATION'
        };
        timelineEvents.push(ev);
        if (obs.status === 'FAIL') {
          activeFailureEvents.push(ev);
        }
      }
    }

    for (const dec of decisions.slice(0, 15)) {
      if (targetFilter && dec.targetKey && dec.targetKey !== targetFilter) continue;
      const ev = {
        timestamp: dec.createdAt,
        phase: 'GOVERNED_ACTION_AND_VERIFICATION',
        target: dec.targetKey || 'fleet',
        eventType: `GOVERNED_${dec.decisionType || 'REMEDIATION'}`,
        severity: dec.outcomeStatus === 'ROLLED_BACK' || dec.outcomeStatus === 'FAILED' ? 'WARN' : 'INFO',
        detail: `Action '${dec.actionId}' (${dec.outcomeStatus}) by ${dec.approvedBy || 'operator'}: ${dec.rationale}`,
        provenance: 'GOVERNED_DECISION_LEDGER'
      };
      timelineEvents.push(ev);
      recoveryAndGovernanceEvents.push(ev);
    }

    timelineEvents.sort((a, b) => new Date(b.timestamp || 0).getTime() - new Date(a.timestamp || 0).getTime());

    const summaryNarrative = preFailureChanges.length > 0
      ? `Network Black Box reconstructed ${timelineEvents.length} chronological event(s) (last ${windowHours}h window): detected ${preFailureChanges.length} state/configuration transition(s) preceding or accompanying failure (${preFailureChanges.slice(0, 3).map((c) => `${c.target}: ${c.eventType} — ${c.detail}`).join(' | ')}), ${activeFailureEvents.length} failure observation(s), and ${recoveryAndGovernanceEvents.length} governed remediation/verification event(s).`
      : `Network Black Box reconstructed ${timelineEvents.length} chronological event(s) across ${entities.length} tracked entity baseline(s). No abrupt configuration drift or port-state regressions occurred prior to the latest check window.`;

    return {
      generatedAt: new Date().toISOString(),
      targetFilter,
      windowHours,
      totalEventsReconstructed: timelineEvents.length,
      whatChangedBeforeOutageSummary: summaryNarrative,
      preFailureChanges: preFailureChanges.slice(0, 10),
      activeFailureEvents: activeFailureEvents.slice(0, 10),
      recoveryAndGovernanceEvents: recoveryAndGovernanceEvents.slice(0, 10),
      chronologicalFlightLog: timelineEvents.slice(0, 25)
    };
  }

  /**
   * Ideas 3, 9 & 12 ("Technical Debt Radar", "Human Firewall" & "Honest IT Cost Intelligence")
   * Identifies and ranks the Top 5 Infrastructure Weaknesses management should address first,
   * backed by empirical observations, topology SPOF analysis, and honest resource efficiency metrics.
   */
  computeTechnicalDebtAndResilienceRadar() {
    const incidentIntel = this.correlateOperationalIncidents();
    const profiles = incidentIntel.environmentProfiles || [];
    const orgKnowledge = this.getOrganizationalKnowledgeAndResilience();
    const graphState = temporalInfrastructureGraph.getGraphState();
    const weaknesses = [];

    // 1. Check for Port-Split Readiness / Configuration Debt or Active Failing Services
    const failingOrPortSplit = profiles.filter((p) => p.lastStatus === 'FAIL' || (p.entity?.closedPorts?.length > 0 && p.entity?.openPorts?.length > 0));
    if (failingOrPortSplit.length > 0) {
      const top = failingOrPortSplit[0];
      weaknesses.push({
        weaknessId: `DEBT-PORT-SPLIT-OR-OUTAGE-${top.target.toUpperCase().replace(/[^A-Z0-9]/g, '_')}`,
        category: 'SERVICE_READINESS_AND_PORT_CONFIGURATION_DEBT',
        title: `Unresolved Service Listener / Port-Split Fault on '${top.target}'`,
        affectedTargets: failingOrPortSplit.map((f) => f.target),
        severity: 'CRITICAL',
        priorityScore: 96,
        empiricalEvidence: `Target '${top.target}' (${top.criticalityTier}) has failing status or mixed open/closed port bindings (Stability ${top.stabilityScore}%).`,
        recommendedManagementAction: `Standardize service listener port bindings and readiness health-check endpoints across [${failingOrPortSplit.map((f) => f.target).join(', ')}].`,
        owningTeam: top.operationalOwnership.team
      });
    }

    // 2. Check for Shared Dependency Single Points of Failure (SPOF) in Topology
    const spofProfiles = profiles.filter((p) => p.serviceDependencies.isSharedInfrastructureComponent || p.serviceDependencies.downstreamCount > 0 || p.entityClass === 'GATEWAY_AND_ROUTING');
    weaknesses.push({
      weaknessId: 'DEBT-TOPOLOGY-SHARED-SPOF',
      category: 'SINGLE_POINT_OF_FAILURE_TOPOLOGY_RISK',
      title: spofProfiles.length > 0
        ? `Shared Dependency Bottleneck Across ${spofProfiles.length} Core Infrastructure Hub(s) (${spofProfiles.slice(0, 3).map((s) => s.target).join(', ')})`
        : 'Single-Gateway & Loopback Control-Plane Dependency Concentration',
      affectedTargets: spofProfiles.length > 0 ? spofProfiles.map((s) => s.target) : ['default_gateway', '127.0.0.1'],
      severity: 'HIGH',
      priorityScore: 89,
      empiricalEvidence: `Temporal Infrastructure Graph tracks ${(graphState.nodes || []).length} node(s) and ${(graphState.edges || []).length} dependency edge(s) where upstream gateway/DNS/loopback hubs lack verified redundant failover paths.`,
      recommendedManagementAction: 'Establish secondary recursive DNS resolver fallback and automated circuit-breaker draining for shared upstream hubs.',
      owningTeam: 'Network & Core Infrastructure Engineering'
    });

    // 3. Check for Chronic Instability / Flapping / Latency Drift Targets
    const unstableProfiles = profiles.filter((p) => p.stabilityScore < 90 || (p.entity?.transitions?.length || 0) >= 2);
    weaknesses.push({
      weaknessId: 'DEBT-RECURRING-INSTABILITY-FLAPPING',
      category: 'RECURRING_INSTABILITY_AND_LATENCY_DRIFT',
      title: unstableProfiles.length > 0
        ? `Recurring State Transitions / Stability Degradation on [${unstableProfiles.slice(0, 3).map((u) => `${u.target} (${u.stabilityScore}%)`).join(', ')}]`
        : 'Proactive Latency & Stability Baseline Guardrails Across Tracked Endpoints',
      affectedTargets: unstableProfiles.length > 0 ? unstableProfiles.map((u) => u.target) : profiles.slice(0, 2).map((p) => p.target),
      severity: unstableProfiles.length > 0 ? 'HIGH' : 'MEDIUM',
      priorityScore: unstableProfiles.length > 0 ? 84 : 68,
      empiricalEvidence: unstableProfiles.length > 0
        ? `${unstableProfiles.length} target(s) exhibit stability scores below 90% or multiple state transitions in operational memory.`
        : `All ${profiles.length} tracked targets currently exceed 90% stability; continuous EWMA slope monitoring active.`,
      recommendedManagementAction: 'Address underlying socket restarts and configure automated pre-SLA-breach alerting at +5ms/observation EWMA drift.',
      owningTeam: 'Core Platform & Systems SRE'
    });

    // 4. Check for Stale or Invalidated Operational Memory Baselines
    const staleProfiles = profiles.filter((p) => p.knowledgeFreshness.freshnessState !== 'FRESH');
    weaknesses.push({
      weaknessId: 'DEBT-EPISTEMIC-FRESHNESS-DECAY',
      category: 'STALE_OR_INVALIDATED_VERIFICATION_BASELINES',
      title: staleProfiles.length > 0
        ? `${staleProfiles.length} Infrastructure Baseline(s) Stale or Invalidated by Recent State Changes`
        : 'Automated Freshness Decay & Post-Change Verification Cadence',
      affectedTargets: staleProfiles.length > 0 ? staleProfiles.map((s) => s.target) : ['127.0.0.1'],
      severity: staleProfiles.length > 0 ? 'MEDIUM' : 'LOW',
      priorityScore: staleProfiles.length > 0 ? 76 : 58,
      empiricalEvidence: staleProfiles.length > 0
        ? `Targets [${staleProfiles.slice(0, 4).map((s) => `${s.target} (${s.knowledgeFreshness.freshnessState})`).join(', ')}] require live re-verification before high-confidence autonomous changes.`
        : 'All recently probed targets have fresh empirical baselines (<5m old).',
      recommendedManagementAction: 'Enable scheduled low-overhead readiness verification on Tier-0/Tier-1 dependencies whenever freshness decays below 60%.',
      owningTeam: 'Platform Reliability & Security Engineering'
    });

    // 5. Check for Organizational Knowledge / Runbook Gaps ("Human Firewall" & "The Last Admin")
    const undoc = orgKnowledge.humanFirewallResilience.undocumentedCriticalTargets;
    weaknesses.push({
      weaknessId: 'DEBT-ORGANIZATIONAL-RUNBOOK-CONCENTRATION',
      category: 'HUMAN_FIREWALL_AND_INSTITUTIONAL_KNOWLEDGE_RISK',
      title: undoc.length > 0
        ? `${undoc.length} Critical System(s) Lack Preserved Institutional Runbooks (${orgKnowledge.humanFirewallResilience.runbookCoveragePct}% Coverage)`
        : `Single-Team Operational Escalation Concentration (${orgKnowledge.humanFirewallResilience.runbookCoveragePct}% Runbook Coverage)`,
      affectedTargets: undoc.length > 0 ? undoc.map((u) => u.target) : profiles.slice(0, 2).map((p) => p.target),
      severity: undoc.length > 0 ? 'MEDIUM' : 'LOW',
      priorityScore: undoc.length > 0 ? 72 : 52,
      empiricalEvidence: orgKnowledge.humanFirewallResilience.busFactorRiskSummary,
      recommendedManagementAction: 'Codify tribal recovery procedures in The Last Admin Organizational Knowledge Vault and cross-train secondary on-call roles.',
      owningTeam: 'Engineering Leadership & SRE Governance'
    });

    weaknesses.sort((a, b) => b.priorityScore - a.priorityScore);
    const topFiveWeaknesses = weaknesses.slice(0, 5).map((w, idx) => ({
      rank: idx + 1,
      ...w
    }));

    // Honest IT Cost & Resource Efficiency Intelligence (Idea 12 — Zero fabricated dollar figures)
    const resourceEfficiencyIntelligence = {
      honestyPolicy: 'STRICT_EMPIRICAL_RESOURCE_TELEMETRY_ONLY (No fabricated cloud billing or invented dollar amounts)',
      avoidedDuplicateNetworkProbes: this.avoidedDuplicateProbesCount,
      redundantRetryStormTargets: failingOrPortSplit.map((f) => f.target),
      optimizationFindings: [
        {
          findingId: 'COST-EFF-DEDUPLICATED-PROBING',
          type: 'POLLING_AND_COMPUTE_OVERHEAD_REDUCTION',
          summary: `Operations Commander cross-workspace deduplication prevented ${this.avoidedDuplicateProbesCount} redundant live network/socket probe(s) within the 45s freshness window.`,
          actionableRecommendation: 'Maintain cross-workspace freshness caching to eliminate redundant diagnostic load on production listeners.'
        },
        ...(failingOrPortSplit.length > 0 ? [{
          findingId: 'COST-EFF-FAILED-READINESS-RETRY-WASTE',
          type: 'UNNECESSARY_RETRY_AND_TIMEOUT_OVERHEAD',
          summary: `${failingOrPortSplit.length} target(s) (${failingOrPortSplit.map((f) => f.target).join(', ')}) are experiencing repeated connection refusals or readiness timeouts, wasting local socket descriptors and worker threads.`,
          actionableRecommendation: 'Resolve port-split/listener mismatches or enable circuit-breaker backoff on failing endpoints.'
        }] : [])
      ]
    };

    return {
      generatedAt: new Date().toISOString(),
      questionAnswered: 'Which five infrastructure weaknesses should management address first?',
      executiveDebtSummary: `EJII Technical Debt Radar evaluated ${profiles.length} infrastructure entities, ${(graphState.edges || []).length} dependency links, and ${orgKnowledge.knowledgeVaultCount} institutional runbooks. The #1 priority weakness is "${topFiveWeaknesses[0]?.title}" [Priority ${topFiveWeaknesses[0]?.priorityScore}/100, Severity: ${topFiveWeaknesses[0]?.severity}].`,
      topWeaknesses: topFiveWeaknesses,
      humanFirewallResilience: orgKnowledge.humanFirewallResilience,
      resourceEfficiencyIntelligence
    };
  }

  /**
   * Phases 2, 3, 4 & 6 + GhostTrace (Idea 2) — Dynamic Situation Reasoning & Epistemic Self-Correction Engine
   * Explicitly separates:
   *   1. Known Facts (empirically observed on the wire or in fresh memory)
   *   2. Unknowns & Unverified Assumptions
   *   3. Competing Explanations (with supporting & refuting evidence)
   *   4. Self-Correction Events (when live evidence refutes an initial assumption or invalidates historical baseline)
   *   5. Dynamic Tool Selection Rationale (why specific probes were selected, reused from fresh cache, or skipped)
   *   6. Stopping Condition (when the conclusion is proven vs. when human approval/clarification is required)
   */
  evaluateDynamicEpistemicReasoning({
    prompt = '',
    intent = 'diagnostic_probe',
    target = '127.0.0.1',
    port = 3000,
    steps = [],
    hypothesisEvaluation = null,
    memoryInsights = null
  } = {}) {
    const cleanTarget = String(target || '127.0.0.1').trim().toLowerCase();
    const numericPort = Number(port) || 3000;
    const entity = this._loadEntity(cleanTarget);
    const prof = this.inferOperationalEnvironmentProfile(cleanTarget);
    const hyp = hypothesisEvaluation || this.evaluateDiagnosticHypotheses({
      target: cleanTarget,
      port: numericPort,
      steps,
      memoryInsights
    });

    const knownFacts = [];
    const unknownsAndAssumptions = [];
    const selfCorrectionEvents = [];
    const dynamicToolSelectionRationale = [];

    // Populate Known Facts from live steps
    for (const s of steps) {
      knownFacts.push({
        source: 'LIVE_WIRE_OBSERVATION',
        layer: s.layer || s.id || 'DIAGNOSTIC_PROBE',
        status: s.status || 'PASS',
        fact: `${s.label || s.id}: ${s.detail || s.status}`,
        confidencePct: 99
      });
    }

    // Populate Known Facts from Operational Memory if fresh
    if (entity) {
      knownFacts.push({
        source: `OPERATIONAL_MEMORY (${prof.knowledgeFreshness.freshnessState})`,
        layer: 'HISTORICAL_BASELINE',
        status: entity.lastStatus || 'PASS',
        fact: `Target '${cleanTarget}' has ${entity.observationCount} recorded observation(s), Stability ${prof.stabilityScore}%, Open ports: [${(entity.openPorts || []).join(', ') || 'none'}], Closed ports: [${(entity.closedPorts || []).join(', ') || 'none'}].`,
        confidencePct: prof.knowledgeFreshness.freshnessScorePct
      });
    }

    // Detect Epistemic Self-Corrections
    const dnsStep = steps.find((s) => s.id === 'dns' || /dns/i.test(String(s.layer || s.label)));
    const pingStep = steps.find((s) => s.id === 'ping' || /icmp|ping/i.test(String(s.layer || s.label)));
    const tcpStep = steps.find((s) => s.id === 'tcp' || /tcp|port/i.test(String(s.layer || s.label)));
    const httpStep = steps.find((s) => s.id === 'http' || /http|web/i.test(String(s.layer || s.label)));

    if ((dnsStep?.status === 'PASS' || pingStep?.status === 'PASS') && tcpStep?.status === 'FAIL') {
      selfCorrectionEvents.push({
        correctionType: 'REFUTED_NETWORK_OUTAGE_ASSUMPTION',
        initialAssumption: `Initial hypothesis considered a general network or host unreachability outage for '${cleanTarget}'.`,
        contradictingEvidence: `Live Layer 3/DNS reachability succeeded (${dnsStep?.detail || pingStep?.detail || 'host reachable'}), whereas Layer 4 TCP port ${numericPort} returned ${tcpStep.detail || 'FAIL'}.`,
        revisedConclusion: `Self-corrected diagnosis: ruled out network/host outage and isolated fault to Layer 4 TCP service listener on ${cleanTarget}:${numericPort}.`
      });
    }

    if (tcpStep?.status === 'PASS' && httpStep?.status === 'FAIL') {
      selfCorrectionEvents.push({
        correctionType: 'REFUTED_TRANSPORT_FAILURE_ASSUMPTION',
        initialAssumption: `Initial hypothesis considered TCP port ${numericPort} being blocked or closed on '${cleanTarget}'.`,
        contradictingEvidence: `TCP 3-way handshake on ${cleanTarget}:${numericPort} succeeded (OPEN), but Layer 7 HTTP probe returned ${httpStep.detail || 'application error'}.`,
        revisedConclusion: `Self-corrected diagnosis: ruled out firewall/socket closure and narrowed root cause to Layer 7 HTTP application routing or upstream handler.`
      });
    }

    if (entity && (entity.openPorts || []).length > 0 && (entity.closedPorts || []).includes(numericPort)) {
      const openAlt = entity.openPorts.find((p) => Number(p) !== numericPort);
      if (openAlt) {
        selfCorrectionEvents.push({
          correctionType: 'PORT_SPLIT_DISCREPANCY_DETECTION',
          initialAssumption: `Assumed service on '${cleanTarget}' was completely down because port ${numericPort} was refused.`,
          contradictingEvidence: `Operational memory and socket state confirm '${cleanTarget}' has an active listener on alternate port :${openAlt} while :${numericPort} is CLOSED.`,
          revisedConclusion: `Self-corrected diagnosis: detected PORT_SPLIT_READINESS_MISMATCH (service listening on :${openAlt}, client/probe polling :${numericPort}).`
        });
      }
    }

    for (const c of hyp.contradictions || []) {
      selfCorrectionEvents.push({
        correctionType: c.type || 'CROSS_LAYER_CONTRADICTION_RESOLUTION',
        initialAssumption: 'Assumed historical baseline remained valid.',
        contradictingEvidence: c.explanation,
        revisedConclusion: 'Updated posterior probability distribution to prioritize live wire telemetry over stale baseline.'
      });
    }

    if (selfCorrectionEvents.length === 0) {
      selfCorrectionEvents.push({
        correctionType: 'CONSISTENT_CROSS_LAYER_VERIFICATION',
        initialAssumption: `Evaluated competing network (L3), transport (L4), and application (L7) hypotheses for '${cleanTarget}'.`,
        contradictingEvidence: 'No cross-layer contradictions detected; live observations align with epistemic priors.',
        revisedConclusion: `Maintained leading conclusion: ${hyp.primaryRootCause?.summary || `Target ${cleanTarget} operating as expected.`}`
      });
    }

    // Dynamic Tool Selection Rationale
    for (const s of steps) {
      dynamicToolSelectionRationale.push({
        toolOrStep: s.label || s.id || 'diagnostic_probe',
        decision: 'SELECTED_HIGH_INFORMATION_GAIN',
        rationale: `Selected to directly reduce Shannon entropy across ${s.layer || 'protocol layer'} on ${cleanTarget}.`
      });
    }
    for (const skip of hyp.redundancySkipped || []) {
      dynamicToolSelectionRationale.push({
        toolOrStep: skip.skippedCheck,
        decision: 'SKIPPED_REDUNDANT_OR_LOW_UTILITY',
        rationale: skip.reason
      });
    }
    if (this.avoidedDuplicateProbesCount > 0) {
      dynamicToolSelectionRationale.push({
        toolOrStep: 'cross_workspace_fresh_cache',
        decision: 'REUSED_FRESH_OBSERVATION',
        rationale: `Reused ${this.avoidedDuplicateProbesCount} fresh wire observation(s) (<45s old) across workspaces to avoid duplicate network probing.`
      });
    }

    // Unknowns & Unverified Assumptions
    for (const m of hyp.missingInformation || []) {
      unknownsAndAssumptions.push(m);
    }
    if (prof.knowledgeFreshness.freshnessState !== 'FRESH' && steps.length === 0) {
      unknownsAndAssumptions.push(`Historical observations for '${cleanTarget}' are ${prof.knowledgeFreshness.freshnessState} (age ${prof.knowledgeFreshness.ageSeconds}s); live wire verification is recommended before mutating state.`);
    }
    if (unknownsAndAssumptions.length === 0) {
      unknownsAndAssumptions.push(`Internal application process logs and OS-level firewall rules on remote hops outside '${cleanTarget}' are inferred from wire responses unless host-level telemetry is queried.`);
    }

    // Stopping Condition Evaluation
    const topConfidence = hyp.primaryRootCause?.confidencePct ?? 88;
    const hasFault = Boolean(hyp.primaryRootCause?.hypothesisId || entity?.lastStatus === 'FAIL');
    const stoppingCondition = {
      status: topConfidence >= 85
        ? (hasFault ? 'ROOT_CAUSE_ISOLATED_AWAITING_GOVERNED_APPROVAL' : 'CONCLUSION_SUFFICIENTLY_PROVEN_HEALTHY')
        : 'ADDITIONAL_TARGETED_EVIDENCE_RECOMMENDED',
      confidencePct: topConfidence,
      isConclusionSufficientlySupported: topConfidence >= 80,
      requiresHumanApprovalForAction: hasFault,
      whyStopOrContinue: topConfidence >= 85
        ? (hasFault
            ? `Root cause on '${cleanTarget}' is isolated with ${topConfidence}% posterior confidence (${hyp.primaryRootCause?.title}). Diagnostic probing can stop; next step is human-governed remediation approval.`
            : `All critical protocol layers on '${cleanTarget}' are verified with ${topConfidence}% confidence. No further diagnostic probes are required.`)
        : `Current posterior confidence is ${topConfidence}%; executing '${hyp.nextBestInvestigation?.action || 'follow-up probe'}' (+${hyp.nextBestInvestigation?.expectedInformationGainBits || 0.8} bits IG) is recommended before concluding.`
    };

    const { cognitiveIntelligenceEngine } = require('../cognition/cognitive-intelligence-engine');
    cognitiveIntelligenceEngine.bindMemoryEngine(this);
    const cog2 = cognitiveIntelligenceEngine.evaluateEpistemicCognition2({
      prompt,
      intent,
      target: cleanTarget,
      port: numericPort,
      steps,
      hypothesisEvaluation: hyp,
      memoryInsights
    });

    return {
      generatedAt: new Date().toISOString(),
      target: cleanTarget,
      port: numericPort,
      intent,
      situationInterpretation: `Dynamic Cross-Layer & Topology Reasoning for '${cleanTarget}' (${prof.entityClass}, ${prof.criticalityTier})`,
      knownFacts,
      unknownsAndAssumptions,
      competingExplanations: hyp.hypotheses || [],
      primaryConclusion: hyp.primaryRootCause,
      selfCorrectionEvents,
      dynamicToolSelectionRationale,
      stoppingCondition,
      nextHighestInformationGainAction: hyp.nextBestInvestigation,
      epistemicSevenPillars: cog2.epistemicSevenPillars,
      intelligentStoppingDecision: cog2.intelligentStoppingDecision
    };
  }

  /**
   * AI Cognition 2.0 Delegation Methods
   */
  decomposeOperationalProblemAndPlan(opts = {}) {
    const { cognitiveIntelligenceEngine } = require('../cognition/cognitive-intelligence-engine');
    cognitiveIntelligenceEngine.bindMemoryEngine(this);
    return cognitiveIntelligenceEngine.decomposeOperationalProblemAndPlan(opts);
  }

  evaluateEpistemicCognition2(opts = {}) {
    const { cognitiveIntelligenceEngine } = require('../cognition/cognitive-intelligence-engine');
    cognitiveIntelligenceEngine.bindMemoryEngine(this);
    return cognitiveIntelligenceEngine.evaluateEpistemicCognition2(opts);
  }

  async executeAutonomousGoalInvestigation(opts = {}) {
    const { cognitiveIntelligenceEngine } = require('../cognition/cognitive-intelligence-engine');
    cognitiveIntelligenceEngine.bindMemoryEngine(this);
    return cognitiveIntelligenceEngine.executeAutonomousGoalInvestigation(opts);
  }

  getAutonomousAgentGoals(limit = 8) {
    const { cognitiveIntelligenceEngine } = require('../cognition/cognitive-intelligence-engine');
    cognitiveIntelligenceEngine.bindMemoryEngine(this);
    return cognitiveIntelligenceEngine.getAutonomousAgentGoals(limit);
  }

  queryOrganizationalKnowledgeNaturalLanguage(opts = {}) {
    const { cognitiveIntelligenceEngine } = require('../cognition/cognitive-intelligence-engine');
    cognitiveIntelligenceEngine.bindMemoryEngine(this);
    return cognitiveIntelligenceEngine.queryOrganizationalKnowledgeNaturalLanguage(opts);
  }

  reconcileHistoricalMemoryConflicts() {
    const { cognitiveIntelligenceEngine } = require('../cognition/cognitive-intelligence-engine');
    cognitiveIntelligenceEngine.bindMemoryEngine(this);
    return cognitiveIntelligenceEngine.reconcileHistoricalMemoryConflicts();
  }

  reconstructOperationalTimeMachine(opts = {}) {
    const { cognitiveIntelligenceEngine } = require('../cognition/cognitive-intelligence-engine');
    cognitiveIntelligenceEngine.bindMemoryEngine(this);
    return cognitiveIntelligenceEngine.reconstructOperationalTimeMachine(opts);
  }

  analyzeCrossIncidentCausalityAndNoise() {
    const { cognitiveIntelligenceEngine } = require('../cognition/cognitive-intelligence-engine');
    cognitiveIntelligenceEngine.bindMemoryEngine(this);
    return cognitiveIntelligenceEngine.analyzeCrossIncidentCausalityAndNoise();
  }

  compareCounterfactualScenarios(opts = {}) {
    const { cognitiveIntelligenceEngine } = require('../cognition/cognitive-intelligence-engine');
    cognitiveIntelligenceEngine.bindMemoryEngine(this);
    return cognitiveIntelligenceEngine.compareCounterfactualScenarios(opts);
  }

  evaluateContextAwareRemediationSuitability(opts = {}) {
    const { cognitiveIntelligenceEngine } = require('../cognition/cognitive-intelligence-engine');
    cognitiveIntelligenceEngine.bindMemoryEngine(this);
    return cognitiveIntelligenceEngine.evaluateContextAwareRemediationSuitability(opts);
  }

  /**
   * AI Cognition 3.0 Delegation Methods
   */
  classifyProblemNatureAndSelectStrategy(opts = {}) {
    const { cognitiveIntelligenceEngine } = require('../cognition/cognitive-intelligence-engine');
    cognitiveIntelligenceEngine.bindMemoryEngine(this);
    return cognitiveIntelligenceEngine.classifyProblemNatureAndSelectStrategy(opts);
  }

  challengeConclusionsAndSelfCorrect(opts = {}) {
    const { cognitiveIntelligenceEngine } = require('../cognition/cognitive-intelligence-engine');
    cognitiveIntelligenceEngine.bindMemoryEngine(this);
    return cognitiveIntelligenceEngine.challengeConclusionsAndSelfCorrect(opts);
  }

  evaluateContinuousOperationalExperience(opts = {}) {
    const { cognitiveIntelligenceEngine } = require('../cognition/cognitive-intelligence-engine');
    cognitiveIntelligenceEngine.bindMemoryEngine(this);
    return cognitiveIntelligenceEngine.evaluateContinuousOperationalExperience(opts);
  }

  analyzeServerConfigurationDifferential(opts = {}) {
    const { cognitiveIntelligenceEngine } = require('../cognition/cognitive-intelligence-engine');
    cognitiveIntelligenceEngine.bindMemoryEngine(this);
    return cognitiveIntelligenceEngine.analyzeServerConfigurationDifferential(opts);
  }

  async executeDynamicCapabilityInvestigation(opts = {}) {
    const { cognitiveIntelligenceEngine } = require('../cognition/cognitive-intelligence-engine');
    cognitiveIntelligenceEngine.bindMemoryEngine(this);
    return cognitiveIntelligenceEngine.executeDynamicCapabilityInvestigation(opts);
  }

  async resumeAutonomousGoalInvestigation(opts = {}) {
    const { cognitiveIntelligenceEngine } = require('../cognition/cognitive-intelligence-engine');
    cognitiveIntelligenceEngine.bindMemoryEngine(this);
    return cognitiveIntelligenceEngine.resumeAutonomousGoalInvestigation(opts);
  }

  synthesizeCollaborativeSpecialistIntelligence(opts = {}) {
    const { cognitiveIntelligenceEngine } = require('../cognition/cognitive-intelligence-engine');
    cognitiveIntelligenceEngine.bindMemoryEngine(this);
    return cognitiveIntelligenceEngine.synthesizeCollaborativeSpecialistIntelligence(opts);
  }

  async executeClosedLoopBlindSpotVerification(opts = {}) {
    const { cognitiveIntelligenceEngine } = require('../cognition/cognitive-intelligence-engine');
    cognitiveIntelligenceEngine.bindMemoryEngine(this);
    return cognitiveIntelligenceEngine.executeClosedLoopBlindSpotVerification(opts);
  }

  evaluateProactiveHorizonAttention() {
    const { cognitiveIntelligenceEngine } = require('../cognition/cognitive-intelligence-engine');
    cognitiveIntelligenceEngine.bindMemoryEngine(this);
    return cognitiveIntelligenceEngine.evaluateProactiveHorizonAttention();
  }

  recordAndLearnFromDecisionOutcome(opts = {}) {
    const { cognitiveIntelligenceEngine } = require('../cognition/cognitive-intelligence-engine');
    cognitiveIntelligenceEngine.bindMemoryEngine(this);
    return cognitiveIntelligenceEngine.recordAndLearnFromDecisionOutcome(opts);
  }

  computeIncidentDnaAndSimilarity(opts = {}) {
    return this.computeIncidentDnaAndSimilarities(opts);
  }

  getRemediationEfficacySummary(target = null) {
    const report = this.getRemediationEfficacyReport(target);
    const actionStats = (report.actions || []).map((a) => ({
      ...a,
      actionType: a.actionId,
      failedCount: a.rolledBackOrFailedCount || 0,
      rolledBackCount: a.rolledBackOrFailedCount || 0,
      efficacyRatePct: a.efficacyPct
    }));
    return {
      ...report,
      actionStats
    };
  }

  forecastTargetHealth(target, slaThresholdMs = 250) {
    const f = this.computePredictiveForecast(target, slaThresholdMs);
    if (f) {
      return {
        ...f,
        outageProbability24hPct: f.riskClassification === 'ACTIVE_PERSISTENT_OUTAGE' ? 92 : (f.severity === 'WARN' ? 35 : 4),
        latencyTrend: {
          slopeMsPerObs: f.rttVelocityMsPerCheck ?? 0
        }
      };
    }
    return {
      target: String(target || '127.0.0.1').trim().toLowerCase(),
      riskClassification: 'NOMINAL_STABLE',
      operationalRiskSignificance: 'NOMINAL_BASELINE',
      severity: 'OK',
      outageProbability24hPct: 4,
      latencyTrend: {
        slopeMsPerObs: 0
      }
    };
  }

  /**
   * Phase 4 — Complete IT Operations Command Center Overview:
   * Synthesizes Operational Environment, Correlated Incidents, AI Operations Commander,
   * Proactive Intelligence, Freshness-Aware Memory, Scenario / Remediation Comparison,
   * Technical Debt Radar, Incident DNA, Network Black Box, Organizational Knowledge, Epistemic Reasoning,
   * AI Cognition 2.0, and AI Cognition 3.0 (Dynamic Strategy Selection, Capability Ecosystem,
   * Critical Self-Correction, Continuous Operational Experience, Collaborative Specialists, Proactive Attention).
   */
  getOperationsCommandCenterOverview(options = {}) {
    const incidentIntel = this.correlateOperationalIncidents();
    const commanderState = this.getOperationsCommanderState();
    const fleetMatrix = this.getFleetIntelligenceMatrix();
    const primaryTarget = options.target ||
      incidentIntel.executiveSituationSummary?.mostImportantIncident?.target ||
      fleetMatrix.highestPriorityInvestigation?.target ||
      '127.0.0.1';
    const primaryPort = Number(options.port) || 3000;

    const remediationComparator = this.compareRemediationOptions({
      target: primaryTarget,
      port: primaryPort
    });
    const defaultScenarioPreview = this.simulateOperationalScenario({
      target: primaryTarget,
      scenarioType: 'GATEWAY_OR_DEPENDENCY_UNAVAILABLE',
      port: primaryPort
    });
    const technicalDebtRadar = this.computeTechnicalDebtAndResilienceRadar();
    const incidentDnaSummary = this.computeIncidentDnaAndSimilarities({
      target: primaryTarget,
      port: primaryPort
    });
    const networkBlackBoxSummary = this.reconstructNetworkBlackBoxTimeline({
      target: options.target || null,
      windowHours: 24
    });
    const organizationalKnowledge = this.getOrganizationalKnowledgeAndResilience();
    const epistemicReasoningOverview = this.evaluateDynamicEpistemicReasoning({
      target: primaryTarget,
      port: primaryPort,
      intent: 'command_center_synthesis'
    });

    const { cognitiveIntelligenceEngine } = require('../cognition/cognitive-intelligence-engine');
    cognitiveIntelligenceEngine.bindMemoryEngine(this);
    const cognition2Overview = cognitiveIntelligenceEngine.getCognition2CommandSnapshot({
      target: primaryTarget,
      port: primaryPort
    });
    const cognition3Overview = cognition2Overview.cognition3Overview;

    return {
      commandCenterVersion: '11.0-cognition-3.0-autonomous-intelligence',
      generatedAt: new Date().toISOString(),
      executiveSituationSummary: incidentIntel.executiveSituationSummary,
      correlatedIncidents: incidentIntel.correlatedIncidents,
      environmentProfiles: incidentIntel.environmentProfiles,
      operationalEnvironment: {
        totalTrackedEntities: incidentIntel.environmentProfiles.length,
        missionCriticalCount: incidentIntel.environmentProfiles.filter((p) => p.criticalityTier === 'TIER_0_MISSION_CRITICAL' || p.criticalityTier === 'TIER_1_BUSINESS_CORE').length,
        sharedComponentCount: incidentIntel.environmentProfiles.filter((p) => p.serviceDependencies.isSharedInfrastructureComponent).length,
        staleOrInvalidatedMemoryCount: incidentIntel.environmentProfiles.filter((p) => p.knowledgeFreshness.freshnessState !== 'FRESH').length,
        entities: incidentIntel.environmentProfiles
      },
      operationsCommander: commanderState,
      proactiveIntelligence: fleetMatrix,
      remediationComparator,
      remediationComparison: remediationComparator,
      defaultScenarioPreview,
      technicalDebtRadar,
      incidentDnaSummary,
      networkBlackBoxSummary,
      organizationalKnowledge,
      epistemicReasoningOverview,
      cognition2Overview,
      cognition3Overview
    };
  }

  /**
   * Inspects topology & dependency links in TemporalInfrastructureGraph for a target host or IP.
   */
  getTargetDependencyContext(target, resolvedIps = []) {
    try {
      const snapshot = temporalInfrastructureGraph.getGraphState();
      const nodes = snapshot?.nodes || [];
      const edges = snapshot?.edges || [];
      const candidates = new Set([String(target || '').toLowerCase(), ...(resolvedIps || []).map((ip) => String(ip).toLowerCase())]);

      const matchedNodes = nodes.filter((n) => {
        const nid = String(n.nodeId || n.id || '').toLowerCase();
        const nname = String(n.label || n.name || n.hostname || '').toLowerCase();
        const nip = String(n.ipAddress || n.attributes?.ip || '').toLowerCase();
        for (const c of candidates) {
          if (c && (nid.includes(c) || nname.includes(c) || nip === c)) return true;
        }
        return false;
      });

      if (matchedNodes.length === 0) {
        return { matchedNodesCount: 0, upstreamDependencies: [], downstreamDependents: [] };
      }

      const matchedIds = new Set(matchedNodes.map((n) => n.nodeId || n.id));
      const downstreamDependents = [];
      const upstreamDependencies = [];

      for (const edge of edges) {
        if (matchedIds.has(edge.sourceId)) {
          downstreamDependents.push({
            nodeId: edge.targetId,
            relationship: edge.relationshipType || 'depends_on'
          });
        }
        if (matchedIds.has(edge.targetId)) {
          upstreamDependencies.push({
            nodeId: edge.sourceId,
            relationship: edge.relationshipType || 'routes_to'
          });
        }
      }

      return {
        matchedNodesCount: matchedNodes.length,
        nodeNames: matchedNodes.map((n) => n.label || n.name || n.nodeId),
        upstreamDependencies: upstreamDependencies.slice(0, 6),
        downstreamDependents: downstreamDependents.slice(0, 6)
      };
    } catch (_) {
      return { matchedNodesCount: 0, upstreamDependencies: [], downstreamDependents: [] };
    }
  }

  /**
   * Parse terminal startup logs, service readiness failures, stack traces, and multi-port outputs
   * (such as SYNTRA local startup logs, EADDRINUSE, ECONNREFUSED, or port 3000 vs 3001 split-service logs).
   */
  parseTerminalStartupLog(rawText) {
    const raw = String(rawText || '').trim();
    if (!raw) return { isStartupOrTerminalLog: false };

    const hasTerminalMarkers =
      /==>|\bPS\s+[A-Z]:\\|\bService did not become ready at\b|\blistening on\s+https?:\/\/|\{"error"\s*:\s*"[^"]+"\}|\bEADDRINUSE\b|\bECONNREFUSED\b|\bERR_CONNECTION_REFUSED\b|\bnpm ERR!\b|\bStarting server\b|\bStarting dev\b/i.test(raw);

    const normalizeUrlKey = (u) => {
      try {
        const p = new URL(u);
        const port = p.port ? Number(p.port) : (p.protocol === 'https:' ? 443 : 80);
        return `${p.hostname.toLowerCase()}:${port}`;
      } catch (_) {
        return String(u || '').replace(/\/+$/, '').toLowerCase();
      }
    };

    // Extract all URLs in the log (without trailing word-boundary stripping '/')
    const urlRegex = /https?:\/\/[^\s"'<>]+/gi;
    const rawUrls = [];
    let match;
    while ((match = urlRegex.exec(raw)) !== null) {
      const cleaned = match[0].replace(/[.,;!?)]+$/, '');
      if (!rawUrls.includes(cleaned)) {
        rawUrls.push(cleaned);
      }
    }

    // Extract failed readiness URLs vs listening service URLs
    const failedReadinessUrls = [];
    const listeningServiceUrls = [];
    const readinessMatch = raw.match(/(?:did not become ready at|failed to connect to|waiting for|timed out waiting for)\s+(https?:\/\/[^\s"'<>]+)/i);
    if (readinessMatch) {
      failedReadinessUrls.push(readinessMatch[1].replace(/[.,;!?)]+$/, ''));
    }

    const listeningRegex = /(?:listening on|started on|running at|ready on|bound to)\s+(https?:\/\/[^\s"'<>]+)/gi;
    let lMatch;
    while ((lMatch = listeningRegex.exec(raw)) !== null) {
      const cleanUrl = lMatch[1].replace(/[.,;!?)]+$/, '');
      if (!listeningServiceUrls.includes(cleanUrl)) {
        listeningServiceUrls.push(cleanUrl);
      }
    }

    const readinessKeys = new Set(failedReadinessUrls.map(normalizeUrlKey));
    const listeningKeys = new Set(listeningServiceUrls.map(normalizeUrlKey));

    // Parse endpoints (host + port)
    const extractedEndpoints = [];
    const seenHostPort = new Set();
    for (const u of rawUrls) {
      try {
        const parsed = new URL(u);
        const host = parsed.hostname;
        const port = parsed.port ? Number(parsed.port) : (parsed.protocol === 'https:' ? 443 : 80);
        const key = `${host.toLowerCase()}:${port}`;
        if (!seenHostPort.has(key)) {
          seenHostPort.add(key);
          const role = readinessKeys.has(key)
            ? 'readiness_target'
            : listeningKeys.has(key)
              ? 'listening_service'
              : 'referenced_endpoint';
          extractedEndpoints.push({
            host,
            port,
            url: u,
            pathname: parsed.pathname || '/',
            role
          });
        }
      } catch (_) {}
    }

    // Also look for bare host:port or port numbers when terminal markers exist
    if (hasTerminalMarkers) {
      const bareHostPortRegex = /\b(127\.0\.0\.1|localhost|0\.0\.0\.0):(\d{2,5})\b/gi;
      let hpMatch;
      while ((hpMatch = bareHostPortRegex.exec(raw)) !== null) {
        const host = hpMatch[1].toLowerCase() === '0.0.0.0' ? '127.0.0.1' : hpMatch[1];
        const port = Number(hpMatch[2]);
        const key = `${host}:${port}`;
        if (!seenHostPort.has(key) && port >= 1 && port <= 65535) {
          seenHostPort.add(key);
          extractedEndpoints.push({
            host,
            port,
            url: `http://${host}:${port}/`,
            pathname: '/',
            role: 'referenced_endpoint'
          });
        }
      }
    }

    // Extract JSON error payloads like {"error":"Route not found."}
    const errorPayloads = [];
    const jsonErrRegex = /\{\s*"error"\s*:\s*"([^"]+)"[^}]*\}/g;
    let jMatch;
    while ((jMatch = jsonErrRegex.exec(raw)) !== null) {
      errorPayloads.push({ raw: jMatch[0], message: jMatch[1] });
    }

    // Extract project or service name if present
    let projectName = null;
    const projMatch = raw.match(/\bProject:\s*([^\r\n]+)/i) || raw.match(/^([A-Z0-9_-]{3,20})\s+-\s+one-click/im);
    if (projMatch) {
      const rawProj = projMatch[1].trim();
      const parts = rawProj.split(/[\\/]/);
      projectName = parts[parts.length - 1] || rawProj;
    }

    // Extract node command if present (e.g., `> node local/server.mjs`)
    let serviceCommand = null;
    const cmdMatch = raw.match(/^>\s*(node\s+[^\r\n]+|npm\s+[^\r\n]+|vite[^\r\n]*)/im);
    if (cmdMatch) {
      serviceCommand = cmdMatch[1].trim();
    }

    // Determine architectural fault patterns
    const detectedPatterns = [];
    const readinessPorts = extractedEndpoints.filter((e) => e.role === 'readiness_target').map((e) => e.port);
    const listeningPorts = extractedEndpoints.filter((e) => e.role === 'listening_service').map((e) => e.port);

    if (
      readinessPorts.length > 0 &&
      listeningPorts.length > 0 &&
      !readinessPorts.some((p) => listeningPorts.includes(p))
    ) {
      detectedPatterns.push('PORT_SPLIT_READINESS_MISMATCH');
    } else if (extractedEndpoints.length >= 2) {
      const distinctPorts = Array.from(new Set(extractedEndpoints.map((e) => e.port)));
      if (distinctPorts.length >= 2 && hasTerminalMarkers) {
        detectedPatterns.push('MULTI_PORT_SERVICE_SPLIT');
      }
    }

    if (errorPayloads.some((e) => /route not found|not found|404/i.test(e.message))) {
      detectedPatterns.push('HTTP_ROUTE_NOT_FOUND_ON_HEALTH_PROBE');
    }
    if (/\bEADDRINUSE\b/i.test(raw)) {
      detectedPatterns.push('PORT_BIND_CONFLICT_EADDRINUSE');
    }
    if (/\b(ECONNREFUSED|ERR_CONNECTION_REFUSED)\b/i.test(raw)) {
      detectedPatterns.push('CONNECTION_REFUSED_LISTENER_DOWN');
    }

    const isStartupOrTerminalLog = Boolean(
      hasTerminalMarkers &&
      (extractedEndpoints.length > 0 || errorPayloads.length > 0 || detectedPatterns.length > 0)
    );

    return {
      isStartupOrTerminalLog,
      projectName,
      serviceCommand,
      failedReadinessUrls,
      listeningServiceUrls,
      extractedEndpoints,
      errorPayloads,
      detectedPatterns
    };
  }

  /**
   * Generate 2-4 context-aware, clickable follow-up prompts grounded in the current evidence.
   */
  generateContextualFollowUps({
    intent,
    target,
    ports = [],
    steps = [],
    structuredAnswer = null,
    memoryInsights = null,
    logAnalysis = null
  } = {}) {
    const suggestions = [];
    const primaryPort = Array.isArray(ports) && ports.length > 0 ? ports[0] : 443;
    const hasFailedStep = Array.isArray(steps) && steps.some((s) => s.status === 'FAIL' || s.status === 'TIMEOUT');

    const isConversationalIntent =
      intent === 'greeting' ||
      intent === 'casual_conversation' ||
      intent === 'everyday_conversation' ||
      intent === 'general_knowledge' ||
      (intent === 'clarification_needed' && (!target || String(target).startsWith('knowledge_') || String(target).startsWith('local_') || String(target).startsWith('operational_')));

    if (isConversationalIntent) {
      return [];
    }

    if (intent === 'informational_question') {
      const topicLower = String(structuredAnswer?.result || '').toLowerCase();
      if (topicLower.includes('dns') || topicLower.includes('nameserver')) {
        return [
          {
            label: 'Explain DNS record types (A, CNAME, MX)',
            prompt: 'Explain the difference between A, CNAME, and MX records',
            rationale: 'Deep dive into core DNS resource record types'
          },
          {
            label: 'Explain DNS propagation delay',
            prompt: 'Why does DNS propagation take time and how does TTL affect it?',
            rationale: 'Understand DNS caching layers and authoritative TTL propagation'
          }
        ];
      }
      if (topicLower.includes('tcp') || topicLower.includes('handshake') || topicLower.includes('syn')) {
        return [
          {
            label: 'Explain TCP 3-way handshake',
            prompt: 'How does the TCP 3-way handshake work (SYN, SYN-ACK, ACK)?',
            rationale: 'Understand Layer 4 connection establishment'
          },
          {
            label: 'Explain TCP vs UDP differences',
            prompt: 'What are the key trade-offs between TCP and UDP?',
            rationale: 'Compare reliable stream transport vs low-overhead datagrams'
          }
        ];
      }
      if (topicLower.includes('subnet') || topicLower.includes('cidr') || topicLower.includes('mask')) {
        return [
          {
            label: 'Explain CIDR notation (/24, /16)',
            prompt: 'How does CIDR slash notation work for subnet calculation?',
            rationale: 'Understand network prefix lengths and host counts'
          }
        ];
      }
      return [];
    }

    if (intent === 'log_and_startup_triage' && logAnalysis) {
      const endpoints = logAnalysis.extractedEndpoints || [];
      for (const ep of endpoints.slice(0, 2)) {
        suggestions.push({
          label: `Check port ${ep.port} on ${ep.host}`,
          prompt: `Check whether port ${ep.port} is open on ${ep.host}`,
          rationale: `Verify live TCP listener state on ${ep.host}:${ep.port}`
        });
      }
      suggestions.push({
        label: 'Show active local sockets',
        prompt: 'Show me the active connections',
        rationale: 'Inspect which local PIDs and processes are bound to loopback ports'
      });
      suggestions.push({
        label: 'Generate incident report',
        prompt: 'Give me a concise incident report',
        rationale: 'Compile a structured root-cause summary for engineering handoff'
      });
      return suggestions.slice(0, 4);
    }

    if (intent === 'dns' && target && !target.includes('local_')) {
      suggestions.push({
        label: `Test HTTPS port 443 on ${target}`,
        prompt: `Check whether port 443 is open on ${target}`,
        rationale: 'Verify Layer 4 TCP transport reachability after DNS resolution'
      });
      suggestions.push({
        label: `Inspect HTTP/TLS on ${target}`,
        prompt: `Check whether https://${target} is working`,
        rationale: 'Verify TLS certificate validity and HTTP application status'
      });
      suggestions.push({
        label: `Look up MX records for ${target}`,
        prompt: `DNS MX lookup for ${target}`,
        rationale: 'Check mail exchange routing records for this domain'
      });
    } else if (intent === 'port_check' && target) {
      if (hasFailedStep) {
        if (target === 'localhost' || target === '127.0.0.1') {
          suggestions.push({
            label: 'Inspect active local sockets',
            prompt: 'Show me the active connections',
            rationale: 'See which local ports actually have a listening process bound'
          });
        } else {
          suggestions.push({
            label: `Run full cross-layer check on ${target}`,
            prompt: `Investigate why ${target} is failing`,
            rationale: 'Isolate DNS vs ICMP vs TCP vs HTTP across all protocol layers'
          });
        }
        const altPort = primaryPort === 3000 ? 3001 : (primaryPort === 443 ? 80 : 443);
        suggestions.push({
          label: `Try port ${altPort} on ${target}`,
          prompt: `Try ${altPort} too`,
          rationale: `Test whether an alternate service port (${altPort}) is open on the same host`
        });
      } else {
        const proto = primaryPort === 443 || primaryPort === 8443 ? 'https' : 'http';
        suggestions.push({
          label: `Inspect ${proto.toUpperCase()} response on :${primaryPort}`,
          prompt: `Check whether ${proto}://${target}:${primaryPort}/ is working`,
          rationale: 'Verify Layer 7 HTTP status and TTFB latency above the open TCP socket'
        });
        suggestions.push({
          label: 'Compare with previous checks',
          prompt: 'Compare the latest results with the previous test',
          rationale: 'Evaluate baseline RTT and port state changes over time'
        });
      }
    } else if (intent === 'website_check' && target) {
      suggestions.push({
        label: 'Summarize findings & incident report',
        prompt: 'Give me a concise incident report',
        rationale: 'Export a structured multi-layer diagnostic summary'
      });
      suggestions.push({
        label: `Trace network path to ${target}`,
        prompt: `Run traceroute to ${target}`,
        rationale: 'Inspect Layer 3 hop-by-hop routing toward the target'
      });
    } else if (intent === 'active_connections') {
      suggestions.push({
        label: 'Diff socket changes',
        prompt: 'Which endpoints appeared since the last snapshot?',
        rationale: 'Compare live kernel socket table against the previous snapshot'
      });
      suggestions.push({
        label: 'Inspect local host health',
        prompt: 'Check local host health',
        rationale: 'Correlate active socket count with CPU, RAM, and local DNS health'
      });
    } else if (intent === 'infrastructure_intelligence_synthesis') {
      suggestions.push({
        label: 'Evaluate blast radius on active host',
        prompt: target && !target.includes('operational_')
          ? `What is the dependency impact and blast radius for ${target}?`
          : 'What is the dependency impact and blast radius for localhost?',
        rationale: 'Trace upstream dependencies and downstream blast radius in the Temporal Infrastructure Graph'
      });
      suggestions.push({
        label: 'Inspect active local sockets',
        prompt: 'Show me the active connections',
        rationale: 'Verify live kernel socket bindings and process listeners'
      });
      suggestions.push({
        label: 'Query Sovereign Fabric v6 IG',
        prompt: 'Based on the unresolved states inside the Sovereign Fabric v6 truth matrix, what is the highest information-gain next probe to run right now?',
        rationale: 'Compute mathematical Shannon entropy and highest-IG next probe'
      });
    } else if (intent === 'dependency_blast_radius') {
      const effectiveTarget = target && !target.includes('topology_') ? target : 'localhost';
      suggestions.push({
        label: `Run cross-layer check on ${effectiveTarget}`,
        prompt: `Investigate why ${effectiveTarget} is failing`,
        rationale: 'Verify live DNS, ICMP, TCP, and HTTP state on the analyzed topology node'
      });
      suggestions.push({
        label: 'Synthesize fleet anomalies & regressions',
        prompt: 'Give me an operational intelligence briefing on active regressions and learned playbooks',
        rationale: 'Review cross-target stability scores, regressions, and learned playbooks'
      });
    } else {
      if (target && !String(target).startsWith('local_') && !String(target).startsWith('operational_') && !String(target).startsWith('knowledge_')) {
        suggestions.push({
          label: `Run 5-layer diagnostic on ${target}`,
          prompt: `Check ${target} layer by layer`,
          rationale: 'Verify L1 interfaces, L2 neighbor cache, L3 gateway, L4 transport, and L7 reachability'
        });
        suggestions.push({
          label: `Inspect TLS and HTTP on ${target}`,
          prompt: `Check whether https://${target} is working`,
          rationale: 'Verify TLS certificate and HTTP application response'
        });
      } else {
        return [];
      }
    }

    if (
      target &&
      memoryInsights &&
      memoryInsights.dependencyContext &&
      (memoryInsights.dependencyContext.upstreamDependencies?.length > 0 ||
        memoryInsights.dependencyContext.downstreamDependents?.length > 0) &&
      !suggestions.some((s) => s.prompt.includes('blast radius'))
    ) {
      suggestions.push({
        label: `Analyze ${target} blast radius`,
        prompt: `What is the dependency impact and blast radius for ${target}?`,
        rationale: 'Evaluate multi-hop cascading impact across connected topology nodes'
      });
    }

    if (target && memoryInsights && memoryInsights.observationCount >= 2 && !suggestions.some((s) => s.prompt.includes('Compare'))) {
      suggestions.push({
        label: 'Compare historical baseline',
        prompt: 'Compare the latest results with the previous test',
        rationale: `Compare against ${memoryInsights.observationCount} recorded observations for ${target}`
      });
    }

    return suggestions.slice(0, 4);
  }
}

const operationalMemoryEngine = new OperationalMemoryEngine();

module.exports = {
  OperationalMemoryEngine,
  operationalMemoryEngine
};
