/**
 * EJII v6 — Sovereign Intelligence Fabric
 * Part V: Innovation Two — The Temporal Infrastructure Graph
 *
 * Upgrades the L1–L6 topology engine, office equipment inventory, routing radix
 * audit, and Telemetry DVR into a unified Temporal Infrastructure Graph with
 * canonical resource types, 10 typed relationships, historical timestamp queries,
 * snapshot diffing, upstream change causality, and explicit identity reconciliation.
 */

const crypto = require('crypto');
const { db } = require('../../db/database');
const { topologyEngine } = require('../../network/topology/topology-engine');
const { evidenceFabric } = require('../evidence/evidence-fabric');

const CANONICAL_RESOURCE_TYPES = Object.freeze([
  'host',
  'interface',
  'ip_address',
  'subnet',
  'gateway',
  'router',
  'switch',
  'dns_resolver',
  'service_endpoint',
  'process',
  'socket',
  'equipment_asset',
  'policy_rule',
  'incident',
  'investigation',
  'evidence'
]);

const TYPED_RELATIONSHIPS = Object.freeze([
  'connected_to',
  'routes_to',
  'member_of',
  'depends_on',
  'resolves_to',
  'served_by',
  'hosted_on',
  'observed_by',
  'affected_by',
  'evidenced_by'
]);

function ensureTemporalGraphTables() {
  try {
    db.exec(`
      CREATE TABLE IF NOT EXISTS temporal_graph_nodes (
        node_id TEXT PRIMARY KEY,
        resource_type TEXT NOT NULL,
        label TEXT NOT NULL,
        ip_address TEXT,
        mac_address TEXT,
        hostname TEXT,
        layer TEXT,
        status TEXT NOT NULL DEFAULT 'healthy',
        attributes_json TEXT NOT NULL DEFAULT '{}',
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        valid_from TEXT NOT NULL,
        valid_to TEXT,
        confidence REAL NOT NULL DEFAULT 0.95,
        evidence_ids_json TEXT NOT NULL DEFAULT '[]'
      );
      CREATE INDEX IF NOT EXISTS idx_tg_nodes_type ON temporal_graph_nodes(resource_type);
      CREATE INDEX IF NOT EXISTS idx_tg_nodes_ip ON temporal_graph_nodes(ip_address);

      CREATE TABLE IF NOT EXISTS temporal_graph_edges (
        edge_id TEXT PRIMARY KEY,
        source_id TEXT NOT NULL,
        target_id TEXT NOT NULL,
        relationship_type TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'up',
        attributes_json TEXT NOT NULL DEFAULT '{}',
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        valid_from TEXT NOT NULL,
        valid_to TEXT,
        confidence REAL NOT NULL DEFAULT 0.95,
        evidence_ids_json TEXT NOT NULL DEFAULT '[]'
      );
      CREATE INDEX IF NOT EXISTS idx_tg_edges_src_tgt ON temporal_graph_edges(source_id, target_id);

      CREATE TABLE IF NOT EXISTS temporal_graph_history (
        snapshot_id TEXT PRIMARY KEY,
        captured_at_ms INTEGER NOT NULL,
        captured_at_iso TEXT NOT NULL,
        trigger_reason TEXT NOT NULL,
        nodes_json TEXT NOT NULL,
        edges_json TEXT NOT NULL,
        reconciliation_json TEXT NOT NULL DEFAULT '[]'
      );
      CREATE INDEX IF NOT EXISTS idx_tg_history_time ON temporal_graph_history(captured_at_ms);

      CREATE TABLE IF NOT EXISTS temporal_causal_edges (
        id TEXT PRIMARY KEY,
        source_id TEXT NOT NULL,
        target_id TEXT NOT NULL,
        f_statistic REAL NOT NULL,
        f_critical REAL NOT NULL,
        effect_size REAL NOT NULL,
        lag_order INTEGER NOT NULL,
        sample_size INTEGER NOT NULL,
        p_value REAL NOT NULL,
        is_causal INTEGER NOT NULL,
        discovered_at TEXT NOT NULL,
        attributes_json TEXT NOT NULL DEFAULT '{}'
      );
      CREATE INDEX IF NOT EXISTS idx_tce_src_tgt ON temporal_causal_edges(source_id, target_id);
    `);
  } catch (_) {}
}

ensureTemporalGraphTables();

// ============================================================================
// Dynamic Granger Causal Discovery Mathematical Engine (Track 2)
// ============================================================================

/**
 * Log-gamma function via Lanczos approximation (g=7, n=9)
 */
function lgamma(z) {
  const p = [
    0.99999999999980993,
    676.5203681218851,
    -1259.1392167224028,
    771.32342877765313,
    -176.61502916214059,
    12.507343278686905,
    -0.138571095856205,
    9.9843695780195716e-6,
    1.5056327351493116e-7
  ];
  if (z < 0.5) {
    return Math.log(Math.PI / Math.sin(Math.PI * z)) - lgamma(1 - z);
  }
  z -= 1;
  let x = p[0];
  for (let i = 1; i < p.length; i++) {
    x += p[i] / (z + i);
  }
  const t = z + 7.5;
  return 0.5 * Math.log(2 * Math.PI) + (z + 0.5) * Math.log(t) - t + Math.log(x);
}

/**
 * Regularized incomplete beta function I_x(a, b) via Lentz continued fractions
 */
function regularizedIncompleteBeta(x, a, b) {
  if (x <= 0) return 0;
  if (x >= 1) return 1;
  if (x > (a + 1) / (a + b + 2)) {
    return 1 - regularizedIncompleteBeta(1 - x, b, a);
  }
  const TINY = 1e-30;
  const STOP = 1e-10;
  const lbeta = lgamma(a) + lgamma(b) - lgamma(a + b);
  const front = Math.exp(Math.log(x) * a + Math.log(1 - x) * b - lbeta) / a;
  let f = 1.0, c = 1.0, d = 0.0;
  for (let m = 1; m <= 100; m++) {
    let numerator;
    if (m % 2 === 0) {
      const k = m / 2;
      numerator = (k * (b - k) * x) / ((a + 2 * k - 1) * (a + 2 * k));
    } else {
      const k = (m - 1) / 2;
      numerator = -((a + k) * (a + b + k) * x) / ((a + 2 * k) * (a + 2 * k + 1));
    }
    d = 1.0 + numerator * d;
    if (Math.abs(d) < TINY) d = TINY;
    d = 1.0 / d;
    c = 1.0 + numerator / c;
    if (Math.abs(c) < TINY) c = TINY;
    const delta = c * d;
    f *= delta;
    if (Math.abs(delta - 1.0) < STOP) break;
  }
  return front * (f - 1.0);
}

/**
 * F-distribution critical value F_crit(df1, df2, alpha)
 */
function computeFCritical(df1, df2, alpha = 0.05) {
  if (df2 <= 0) return Infinity;
  if (df1 === 2) {
    // Exact closed-form solution for df1 = 2
    return (df2 / 2) * (Math.pow(alpha, -2 / df2) - 1);
  }
  // Robust numerical bisection on incomplete beta CDF
  let low = 0.001, high = 100.0;
  for (let iter = 0; iter < 40; iter++) {
    const mid = (low + high) / 2;
    const x = (df1 * mid) / (df1 * mid + df2);
    const pVal = 1 - regularizedIncompleteBeta(x, df1 / 2, df2 / 2);
    if (pVal > alpha) {
      low = mid;
    } else {
      high = mid;
    }
  }
  return (low + high) / 2;
}

/**
 * Gaussian elimination with partial pivoting and ridge stabilization
 */
function solveLinearSystem(A, b) {
  const n = b.length;
  const M = A.map((row) => [...row]);
  const x = [...b];

  for (let i = 0; i < n; i++) {
    let maxRow = i;
    for (let k = i + 1; k < n; k++) {
      if (Math.abs(M[k][i]) > Math.abs(M[maxRow][i])) {
        maxRow = k;
      }
    }
    const tempRow = M[i];
    M[i] = M[maxRow];
    M[maxRow] = tempRow;
    const tempB = x[i];
    x[i] = x[maxRow];
    x[maxRow] = tempB;

    if (Math.abs(M[i][i]) < 1e-12) {
      M[i][i] += 1e-6;
    }

    for (let k = i + 1; k < n; k++) {
      const c = M[k][i] / M[i][i];
      for (let j = i; j < n; j++) {
        M[k][j] -= c * M[i][j];
      }
      x[k] -= c * x[i];
    }
  }

  const result = new Array(n).fill(0);
  for (let i = n - 1; i >= 0; i--) {
    let sum = x[i];
    for (let j = i + 1; j < n; j++) {
      sum -= M[i][j] * result[j];
    }
    result[i] = sum / (Math.abs(M[i][i]) < 1e-12 ? 1e-6 : M[i][i]);
  }
  return result;
}

/**
 * Ordinary Least Squares (OLS) Regression
 */
function fitOLS(Z, y) {
  const M = Z.length;
  const K = Z[0].length;
  const A = Array.from({ length: K }, () => new Array(K).fill(0));
  const b = new Array(K).fill(0);

  for (let i = 0; i < M; i++) {
    const zi = Z[i];
    const yi = y[i];
    for (let r = 0; r < K; r++) {
      b[r] += zi[r] * yi;
      for (let c = r; c < K; c++) {
        const prod = zi[r] * zi[c];
        A[r][c] += prod;
        if (r !== c) A[c][r] += prod;
      }
    }
  }

  const theta = solveLinearSystem(A, b);

  let rss = 0;
  const residuals = new Array(M);
  for (let i = 0; i < M; i++) {
    let yHat = 0;
    for (let j = 0; j < K; j++) {
      yHat += Z[i][j] * theta[j];
    }
    const res = y[i] - yHat;
    residuals[i] = res;
    rss += res * res;
  }

  return { theta, residuals, rss };
}

/**
 * Dynamic Temporal Granger Causal Discovery
 * Evaluates whether telemetry stream X Granger-causes stream Y.
 *
 * Restricted Model:   Y_t = c_1 + sum_{i=1}^p alpha_i Y_{t-i} + eps_{1,t}
 * Unrestricted Model: Y_t = c_2 + sum_{i=1}^p alpha_i Y_{t-i} + sum_{j=1}^q beta_j X_{t-j} + eps_{2,t}
 * F-statistic:        F = ((RSS_R - RSS_U) / q) / (RSS_U / (N - (p + q + 1)))
 * Dynamic Effect Size: Delta sigma = 1 - (RSS_U / RSS_R)
 */
function computeGrangerCausality(streamX, streamY, lagOrder = 2, options = {}) {
  const p = Math.max(1, parseInt(lagOrder, 10) || 2);
  const q = p;

  const getVal = (item) => {
    if (typeof item === 'number') return item;
    if (item && typeof item.value === 'number') return item.value;
    if (item && typeof item.rttMs === 'number') return item.rttMs;
    if (item && typeof item.packetLossPct === 'number') return item.packetLossPct;
    return Number(item) || 0;
  };

  const xVals = Array.isArray(streamX) ? streamX.map(getVal) : [];
  const yVals = Array.isArray(streamY) ? streamY.map(getVal) : [];
  const N = Math.min(xVals.length, yVals.length);

  const minRequiredSamples = 2 * Math.max(p, q) + 3;
  if (N < minRequiredSamples) {
    return {
      fStatistic: 0,
      fCritical: 0,
      pValue: 1.0,
      isCausal: false,
      effectSize: 0,
      lagOrder: p,
      sampleSize: N,
      reason: 'INSUFFICIENT_SAMPLES',
      restrictedRss: 0,
      unrestrictedRss: 0
    };
  }

  const M = N - Math.max(p, q);
  const df1 = q;
  const df2 = M - (p + q + 1);

  if (df2 <= 0) {
    return {
      fStatistic: 0,
      fCritical: 0,
      pValue: 1.0,
      isCausal: false,
      effectSize: 0,
      lagOrder: p,
      sampleSize: N,
      reason: 'DEGREES_OF_FREEDOM_EXHAUSTED',
      restrictedRss: 0,
      unrestrictedRss: 0
    };
  }

  const yReg = new Array(M);
  const Z_R = Array.from({ length: M }, () => new Array(p + 1));
  const Z_U = Array.from({ length: M }, () => new Array(p + q + 1));

  const offset = Math.max(p, q);
  for (let i = 0; i < M; i++) {
    const t = offset + i;
    yReg[i] = yVals[t];

    Z_R[i][0] = 1.0;
    for (let lag = 1; lag <= p; lag++) {
      Z_R[i][lag] = yVals[t - lag];
    }

    Z_U[i][0] = 1.0;
    for (let lag = 1; lag <= p; lag++) {
      Z_U[i][lag] = yVals[t - lag];
    }
    for (let lag = 1; lag <= q; lag++) {
      Z_U[i][p + lag] = xVals[t - lag];
    }
  }

  const fitR = fitOLS(Z_R, yReg);
  const fitU = fitOLS(Z_U, yReg);

  const rssR = fitR.rss;
  const rssU = Math.min(rssR, fitU.rss);

  const num = Math.max(0, rssR - rssU) / df1;
  const den = Math.max(1e-12, rssU) / df2;
  const fStatistic = num / den;

  const alpha = options.alpha || 0.05;
  const fCritical = computeFCritical(df1, df2, alpha);

  let pValue;
  if (df1 === 2) {
    // Exact analytical closed-form solution for df1 = 2
    pValue = Math.pow(1 + (2 / df2) * fStatistic, -df2 / 2);
  } else {
    const xBeta = (df1 * fStatistic) / (df1 * fStatistic + df2);
    pValue = Math.max(0, Math.min(1.0, 1 - regularizedIncompleteBeta(xBeta, df1 / 2, df2 / 2)));
  }

  const effectSize = rssR > 1e-12 ? Math.max(0, Math.min(1.0, 1 - (rssU / rssR))) : 0;
  const isCausal = fStatistic > fCritical && pValue < alpha && effectSize > 0.02;

  return {
    fStatistic: Number(fStatistic.toFixed(4)),
    fCritical: Number(fCritical.toFixed(4)),
    pValue: Number(pValue.toFixed(6)),
    isCausal,
    effectSize: Number(effectSize.toFixed(4)),
    lagOrder: p,
    sampleSize: N,
    degreesOfFreedom: { df1, df2 },
    restrictedRss: Number(rssR.toFixed(6)),
    unrestrictedRss: Number(rssU.toFixed(6))
  };
}

class TemporalInfrastructureGraph {
  constructor() {
    this.nodes = new Map();
    this.edges = new Map();
    this.snapshots = [];
    this.reconciliationCandidates = [];
    this.identityHistory = [];
    ensureTemporalGraphTables();
  }

  /**
   * Synchronize live L1–L6 topology, equipment inventory, and DHCP/IP events
   * into the Temporal Infrastructure Graph and record a temporal snapshot.
   */
  syncFromLiveInfrastructure(triggerReason = 'periodic_observation') {
    ensureTemporalGraphTables();
    const nowMs = Date.now();
    const nowIso = new Date(nowMs).toISOString();

    let liveTopo = { nodes: [], edges: [] };
    try {
      liveTopo = topologyEngine.getTopology() || { nodes: [], edges: [] };
    } catch (_) {}

    const mapNodeType = (n) => {
      if (n.type === 'router' || n.layer === 'edge') return 'gateway';
      if (n.type === 'switch' || n.layer === 'core') return 'switch';
      if (n.type === 'subnet' || (n.hostname_or_ip && n.hostname_or_ip.includes('/'))) return 'subnet';
      if (n.type === 'service' || n.layer === 'service') return 'service_endpoint';
      if (n.type === 'wan' || n.layer === 'wan') return 'router';
      return 'host';
    };

    for (const n of liveTopo.nodes || []) {
      const resourceType = mapNodeType(n);
      const existing = this.nodes.get(n.id);

      // Record observation evidence for node presence
      const ev = evidenceFabric.recordEvidence({
        type: 'observation',
        subject: `node:${n.id}`,
        claim: `Resource ${n.name} (${n.hostname_or_ip}) observed in state ${n.status || 'healthy'} at layer ${n.layer}`,
        rawValue: { id: n.id, ip: n.hostname_or_ip, mac: n.mac_address, status: n.status, latencyMs: n.last_latency_ms },
        normalizedValue: n.status || 'healthy',
        unit: 'state',
        sourceCapabilityId: 'ejii.topology.l1_l6_discovery',
        collectionMethod: n.evidenceClassification === 'Configured' ? 'os_route_table' : 'arp_table',
        observedAt: nowIso
      });

      // Check for IP or MAC drift on existing node
      if (existing && ((existing.ipAddress && n.hostname_or_ip && existing.ipAddress !== n.hostname_or_ip) ||
          (existing.macAddress && n.mac_address && existing.macAddress !== n.mac_address))) {
        this.identityHistory.push({
          eventId: `IDRIFT-${nowMs}-${crypto.randomBytes(3).toString('hex')}`,
          nodeId: n.id,
          previousIp: existing.ipAddress,
          currentIp: n.hostname_or_ip,
          previousMac: existing.macAddress,
          currentMac: n.mac_address,
          observedAt: nowIso,
          observedAtMs: nowMs,
          reason: 'IP_OR_MAC_BINDING_CHANGE'
        });
      }

      const temporalNode = {
        nodeId: n.id,
        resourceType,
        label: n.name || n.id,
        ipAddress: n.hostname_or_ip || null,
        macAddress: n.mac_address || null,
        hostname: n.name || n.id,
        layer: n.layer || 'access',
        status: n.status || 'healthy',
        attributes: {
          vendor: n.vendor || 'Unknown',
          latencyMs: n.last_latency_ms ?? null,
          evidenceClassification: n.evidenceClassification || 'Observed',
          ifName: n.if_name || null
        },
        firstSeenAt: existing ? existing.firstSeenAt : nowIso,
        lastSeenAt: nowIso,
        validFrom: existing ? existing.validFrom : nowIso,
        validTo: null,
        confidence: typeof n.confidence === 'number'
          ? n.confidence
          : (n.last_latency_ms != null
            ? Number(Math.max(0.5, Math.min(0.99, 1.0 - (n.last_latency_ms / 500))).toFixed(3))
            : (n.evidenceClassification === 'Observed' ? 0.90 : null)),
        confidenceType: typeof n.confidence === 'number'
          ? 'EXPLICIT_SPECIFIED'
          : (n.last_latency_ms != null
            ? 'EMPIRICALLY_MEASURED_PROBE'
            : (n.evidenceClassification === 'Observed' ? 'HEURISTIC_OBSERVED' : 'UNKNOWN_UNMEASURED')),
        evidenceIds: existing
          ? Array.from(new Set([...existing.evidenceIds.slice(-4), ev.id]))
          : [ev.id]
      };

      this.nodes.set(n.id, temporalNode);
    }

    for (const e of liveTopo.edges || []) {
      const existingEdge = this.edges.get(e.id);
      const srcNode = this.nodes.get(e.source_id);
      const tgtNode = this.nodes.get(e.target_id);

      let relationshipType = 'connected_to';
      if (srcNode && tgtNode) {
        if (srcNode.resourceType === 'subnet' || tgtNode.resourceType === 'subnet') {
          relationshipType = 'member_of';
        } else if (srcNode.resourceType === 'gateway' || tgtNode.resourceType === 'gateway') {
          relationshipType = 'routes_to';
        } else if (tgtNode.resourceType === 'service_endpoint') {
          relationshipType = 'depends_on';
        }
      }

      const temporalEdge = {
        edgeId: e.id,
        sourceId: e.source_id,
        targetId: e.target_id,
        relationshipType,
        status: e.status || 'up',
        attributes: {
          linkType: e.link_type || 'ethernet',
          bandwidthMbps: e.bandwidth_mbps ?? 1000,
          utilizationPct: e.utilization_pct ?? 0,
          latencyMs: e.latency_ms ?? null,
          packetRate: e.packet_rate ?? 0
        },
        firstSeenAt: existingEdge ? existingEdge.firstSeenAt : nowIso,
        lastSeenAt: nowIso,
        validFrom: existingEdge ? existingEdge.validFrom : nowIso,
        validTo: null,
        confidence: (srcNode?.confidence != null && tgtNode?.confidence != null)
          ? Math.min(srcNode.confidence, tgtNode.confidence)
          : (e.evidenceClassification === 'Observed' ? 0.90 : null),
        evidenceIds: existingEdge ? existingEdge.evidenceIds : []
      };

      this.edges.set(e.id, temporalEdge);
    }

    // Reconcile equipment inventory & DHCP events for ambiguous identity candidates
    this._reconcileIdentities(nowIso, nowMs);

    const snapshot = this.captureSnapshot(triggerReason, nowMs);
    return {
      syncedAt: nowIso,
      nodeCount: this.nodes.size,
      edgeCount: this.edges.size,
      snapshotId: snapshot.snapshotId,
      reconciliationCandidates: this.reconciliationCandidates
    };
  }

  /**
   * Explicit Identity Reconciliation across ARP, DHCP, Equipment Inventory, and Topology.
   * Generates reconciliationCandidates whenever MAC randomization, duplicate IPs, or DHCP lease churn is detected.
   */
  _reconcileIdentities(nowIso, nowMs) {
    const candidates = [];
    const ipToNodes = new Map();
    const macToNodes = new Map();

    for (const node of this.nodes.values()) {
      if (node.ipAddress && !node.ipAddress.includes('/')) {
        const list = ipToNodes.get(node.ipAddress) || [];
        list.push(node);
        ipToNodes.set(node.ipAddress, list);
      }
      if (node.macAddress) {
        const list = macToNodes.get(node.macAddress) || [];
        list.push(node);
        macToNodes.set(node.macAddress, list);

        // Check locally administered / randomized MAC bit (IEEE 802 U/L bit 0x02 in first octet)
        const cleanHex = node.macAddress.replace(/[^0-9A-Fa-f]/g, '');
        if (cleanHex.length >= 2) {
          const firstByte = parseInt(cleanHex.slice(0, 2), 16);
          if (!Number.isNaN(firstByte) && (firstByte & 0x02) !== 0) {
            candidates.push({
              candidateId: `RECON-MAC-RAND-${node.nodeId}`,
              ambiguityType: 'LOCALLY_ADMINISTERED_RANDOMIZED_MAC',
              entities: [node.nodeId],
              ipAddress: node.ipAddress,
              macAddress: node.macAddress,
              reconciliationConfidence: 0.62,
              resolutionPolicy: 'DO_NOT_AUTO_MERGE_BY_MAC_ALONE',
              explanation: `Entity ${node.label} uses a locally administered/randomized MAC (${node.macAddress}); DHCP lease transitions require hostname/SNI corroboration.`
            });
          }
        }
      }
    }

    for (const [ip, list] of ipToNodes.entries()) {
      if (list.length > 1) {
        candidates.push({
          candidateId: `RECON-IP-COLLISION-${ip}`,
          ambiguityType: 'SHARED_OR_CHURNED_IP_BINDING',
          entities: list.map((n) => n.nodeId),
          ipAddress: ip,
          reconciliationConfidence: 0.55,
          resolutionPolicy: 'KEEP_DISTINCT_UNTIL_ARP_VERIFIED',
          explanation: `Multiple graph entities (${list.map((n) => n.nodeId).join(', ')}) reference IP ${ip}. Retained as distinct candidates to prevent silent record corruption.`
        });
      }
    }

    // Inspect SQLite dhcp_and_ip_events table if populated
    try {
      const dhcpRows = db.prepare('SELECT * FROM dhcp_and_ip_events ORDER BY observed_at DESC LIMIT 25').all();
      for (const row of dhcpRows) {
        if (row.previous_ip && row.ip_address && row.previous_ip !== row.ip_address) {
          this.identityHistory.push({
            eventId: row.event_id || `DHCP-${nowMs}`,
            nodeId: row.mac_address || row.hostname || row.ip_address,
            previousIp: row.previous_ip,
            currentIp: row.ip_address,
            previousMac: row.mac_address || null,
            currentMac: row.mac_address || null,
            observedAt: row.observed_at || nowIso,
            observedAtMs: Date.parse(row.observed_at) || nowMs,
            reason: row.event_type || 'DHCP_LEASE_RENEWAL_CHURN'
          });
        }
      }
    } catch (_) {}

    this.reconciliationCandidates = candidates;
    return candidates;
  }

  /**
   * Add or update a node in the Temporal Graph.
   */
  upsertNode(nodeInput) {
    const nowIso = new Date().toISOString();
    const nodeId = String(nodeInput.nodeId || nodeInput.id || `NODE-${Date.now()}`);
    const resourceType = CANONICAL_RESOURCE_TYPES.includes(nodeInput.resourceType)
      ? nodeInput.resourceType
      : 'host';
    const existing = this.nodes.get(nodeId);

    if (existing && ((existing.ipAddress && nodeInput.ipAddress && existing.ipAddress !== nodeInput.ipAddress) ||
        (existing.macAddress && nodeInput.macAddress && existing.macAddress !== nodeInput.macAddress))) {
      this.identityHistory.push({
        eventId: `IDRIFT-${Date.now()}-${crypto.randomBytes(2).toString('hex')}`,
        nodeId,
        previousIp: existing.ipAddress,
        currentIp: nodeInput.ipAddress || existing.ipAddress,
        previousMac: existing.macAddress,
        currentMac: nodeInput.macAddress || existing.macAddress,
        observedAt: nodeInput.observedAt || nowIso,
        observedAtMs: nodeInput.observedAt ? Date.parse(nodeInput.observedAt) : Date.now(),
        reason: 'IP_OR_MAC_BINDING_CHANGE'
      });
    }

    const record = {
      nodeId,
      resourceType,
      label: String(nodeInput.label || nodeInput.name || nodeId),
      ipAddress: nodeInput.ipAddress ?? (existing ? existing.ipAddress : null),
      macAddress: nodeInput.macAddress ?? (existing ? existing.macAddress : null),
      hostname: nodeInput.hostname ?? (existing ? existing.hostname : nodeId),
      layer: nodeInput.layer || (existing ? existing.layer : 'access'),
      status: nodeInput.status || (existing ? existing.status : 'healthy'),
      attributes: {
        ...(existing ? existing.attributes : {}),
        ...(nodeInput.attributes || {})
      },
      firstSeenAt: existing ? existing.firstSeenAt : (nodeInput.observedAt || nowIso),
      lastSeenAt: nodeInput.observedAt || nowIso,
      validFrom: existing ? existing.validFrom : (nodeInput.validFrom || nowIso),
      validTo: nodeInput.validTo || null,
      confidence: typeof nodeInput.confidence === 'number'
        ? nodeInput.confidence
        : (nodeInput.evidenceClassification === 'Observed' ? 0.90 : null),
      evidenceIds: Array.isArray(nodeInput.evidenceIds)
        ? nodeInput.evidenceIds
        : (existing ? existing.evidenceIds : [])
    };

    this.nodes.set(nodeId, record);
    return record;
  }

  /**
   * Add or update a typed relationship edge in the Temporal Graph.
   */
  upsertEdge(edgeInput) {
    const nowIso = new Date().toISOString();
    const edgeId = String(edgeInput.edgeId || edgeInput.id || `EDGE-${edgeInput.sourceId}-${edgeInput.targetId}`);
    const relationshipType = TYPED_RELATIONSHIPS.includes(edgeInput.relationshipType)
      ? edgeInput.relationshipType
      : 'connected_to';
    const existing = this.edges.get(edgeId);

    const record = {
      edgeId,
      sourceId: String(edgeInput.sourceId),
      targetId: String(edgeInput.targetId),
      relationshipType,
      status: edgeInput.status || (existing ? existing.status : 'up'),
      attributes: {
        ...(existing ? existing.attributes : {}),
        ...(edgeInput.attributes || {})
      },
      firstSeenAt: existing ? existing.firstSeenAt : (edgeInput.observedAt || nowIso),
      lastSeenAt: edgeInput.observedAt || nowIso,
      validFrom: existing ? existing.validFrom : (edgeInput.validFrom || nowIso),
      validTo: edgeInput.validTo || null,
      confidence: typeof edgeInput.confidence === 'number'
        ? edgeInput.confidence
        : (edgeInput.evidenceClassification === 'Observed' ? 0.85 : null),
      evidenceIds: Array.isArray(edgeInput.evidenceIds)
        ? edgeInput.evidenceIds
        : (existing ? existing.evidenceIds : [])
    };

    this.edges.set(edgeId, record);
    return record;
  }

  /**
   * Capture a point-in-time snapshot of the Temporal Infrastructure Graph.
   */
  captureSnapshot(triggerReason = 'manual_snapshot', customTimestampMs = Date.now()) {
    const snapshotId = `TGSNAP-${customTimestampMs}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const capturedAtIso = new Date(customTimestampMs).toISOString();
    const nodesCopy = Array.from(this.nodes.values()).map((n) => JSON.parse(JSON.stringify(n)));
    const edgesCopy = Array.from(this.edges.values()).map((e) => JSON.parse(JSON.stringify(e)));

    const snap = {
      snapshotId,
      capturedAtMs: customTimestampMs,
      capturedAtIso,
      triggerReason,
      nodes: nodesCopy,
      edges: edgesCopy,
      reconciliationCandidates: [...this.reconciliationCandidates]
    };

    this.snapshots.push(snap);
    this.snapshots.sort((a, b) => a.capturedAtMs - b.capturedAtMs);
    if (this.snapshots.length > 200) {
      this.snapshots.shift();
    }

    try {
      db.prepare(`
        INSERT OR REPLACE INTO temporal_graph_history (
          snapshot_id, captured_at_ms, captured_at_iso, trigger_reason, nodes_json, edges_json, reconciliation_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(
        snap.snapshotId,
        snap.capturedAtMs,
        snap.capturedAtIso,
        snap.triggerReason,
        JSON.stringify(snap.nodes),
        JSON.stringify(snap.edges),
        JSON.stringify(snap.reconciliationCandidates)
      );
    } catch (_) {}

    return snap;
  }

  /**
   * Query 1: "What was the topology at timestamp T?"
   */
  getTopologyAtTimestamp(timestampInput) {
    if (this.snapshots.length === 0) {
      this.syncFromLiveInfrastructure('initial_hydration');
    }
    const targetMs = typeof timestampInput === 'number' ? timestampInput : Date.parse(timestampInput);
    if (!Number.isFinite(targetMs)) {
      const latest = this.snapshots[this.snapshots.length - 1];
      return {
        queryTimestampMs: Date.now(),
        snapshot: latest,
        exactMatch: true,
        dataGapDetected: false
      };
    }

    // Find closest snapshot <= targetMs, or earliest if targetMs precedes all snapshots
    let best = this.snapshots[0];
    for (const s of this.snapshots) {
      if (s.capturedAtMs <= targetMs) {
        best = s;
      } else if (Math.abs(s.capturedAtMs - targetMs) < Math.abs(best.capturedAtMs - targetMs)) {
        best = s;
      }
    }

    const deltaMs = Math.abs(targetMs - best.capturedAtMs);
    const dataGapDetected = deltaMs > 120000;

    return {
      queryTimestampMs: targetMs,
      matchedSnapshotId: best.snapshotId,
      matchedTimestampMs: best.capturedAtMs,
      deltaMs,
      dataGapDetected,
      gapAdvisory: dataGapDetected
        ? `Nearest snapshot differs by ${(deltaMs / 1000).toFixed(1)}s; interval contains unrecorded telemetry window.`
        : null,
      snapshot: best
    };
  }

  /**
   * Query 2: "What changed between timestamp T1 and T2?"
   */
  diffSnapshots(t1Input, t2Input) {
    if (this.snapshots.length === 0) {
      this.syncFromLiveInfrastructure('initial_hydration');
    }
    const res1 = this.getTopologyAtTimestamp(t1Input);
    const res2 = this.getTopologyAtTimestamp(t2Input);
    const s1 = res1.snapshot;
    const s2 = res2.snapshot;

    const map1Nodes = new Map((s1.nodes || []).map((n) => [n.nodeId, n]));
    const map2Nodes = new Map((s2.nodes || []).map((n) => [n.nodeId, n]));

    const addedNodes = [];
    const removedNodes = [];
    const modifiedNodes = [];

    for (const [id, n2] of map2Nodes.entries()) {
      if (!map1Nodes.has(id)) {
        addedNodes.push(n2);
      } else {
        const n1 = map1Nodes.get(id);
        const changes = [];
        if (n1.status !== n2.status) changes.push({ field: 'status', before: n1.status, after: n2.status });
        if (n1.ipAddress !== n2.ipAddress) changes.push({ field: 'ipAddress', before: n1.ipAddress, after: n2.ipAddress });
        if (n1.macAddress !== n2.macAddress) changes.push({ field: 'macAddress', before: n1.macAddress, after: n2.macAddress });
        if ((n1.attributes?.latencyMs ?? null) !== (n2.attributes?.latencyMs ?? null)) {
          changes.push({ field: 'latencyMs', before: n1.attributes?.latencyMs ?? null, after: n2.attributes?.latencyMs ?? null });
        }
        if (changes.length > 0) {
          modifiedNodes.push({ nodeId: id, label: n2.label, resourceType: n2.resourceType, changes });
        }
      }
    }

    for (const [id, n1] of map1Nodes.entries()) {
      if (!map2Nodes.has(id)) {
        removedNodes.push(n1);
      }
    }

    const map1Edges = new Map((s1.edges || []).map((e) => [e.edgeId, e]));
    const map2Edges = new Map((s2.edges || []).map((e) => [e.edgeId, e]));

    const addedEdges = [];
    const removedEdges = [];
    const modifiedEdges = [];

    for (const [id, e2] of map2Edges.entries()) {
      if (!map1Edges.has(id)) {
        addedEdges.push(e2);
      } else {
        const e1 = map1Edges.get(id);
        const changes = [];
        if (e1.status !== e2.status) changes.push({ field: 'status', before: e1.status, after: e2.status });
        if ((e1.attributes?.utilizationPct ?? 0) !== (e2.attributes?.utilizationPct ?? 0)) {
          changes.push({ field: 'utilizationPct', before: e1.attributes?.utilizationPct, after: e2.attributes?.utilizationPct });
        }
        if (changes.length > 0) {
          modifiedEdges.push({ edgeId: id, sourceId: e2.sourceId, targetId: e2.targetId, relationshipType: e2.relationshipType, changes });
        }
      }
    }

    for (const [id, e1] of map1Edges.entries()) {
      if (!map2Edges.has(id)) {
        removedEdges.push(e1);
      }
    }

    const spanMs = Math.abs(s2.capturedAtMs - s1.capturedAtMs);
    const dataGapDetected = res1.dataGapDetected || res2.dataGapDetected || spanMs > 300000;

    return {
      t1SnapshotId: s1.snapshotId,
      t2SnapshotId: s2.snapshotId,
      t1TimestampIso: s1.capturedAtIso,
      t2TimestampIso: s2.capturedAtIso,
      intervalStatus: dataGapDetected ? 'INCOMPLETE_INTERVAL_WITH_GAP' : 'CONTINUOUS',
      dataGapDetected,
      addedNodes,
      removedNodes,
      modifiedNodes,
      addedEdges,
      removedEdges,
      modifiedEdges,
      totalChanges:
        addedNodes.length +
        removedNodes.length +
        modifiedNodes.length +
        addedEdges.length +
        removedEdges.length +
        modifiedEdges.length
    };
  }

  /**
   * Query 3: "Which upstream change preceded this service degradation?"
   */
  findPrecedingUpstreamChanges(serviceNodeId, incidentTimestampMs = Date.now(), lookbackMs = 600000) {
    if (this.snapshots.length < 2) {
      this.syncFromLiveInfrastructure('baseline_before_check');
    }
    const tBefore = incidentTimestampMs - lookbackMs;
    const diff = this.diffSnapshots(tBefore, incidentTimestampMs);

    // Identify upstream nodes connected to or routing toward serviceNodeId
    const upstreamNodeIds = new Set();
    for (const edge of this.edges.values()) {
      if (edge.targetId === serviceNodeId) upstreamNodeIds.add(edge.sourceId);
      if (edge.sourceId === serviceNodeId) upstreamNodeIds.add(edge.targetId);
      if (edge.relationshipType === 'routes_to' || edge.relationshipType === 'depends_on') {
        upstreamNodeIds.add(edge.sourceId);
        upstreamNodeIds.add(edge.targetId);
      }
    }

    const upstreamNodeChanges = diff.modifiedNodes.filter(
      (m) => upstreamNodeIds.has(m.nodeId) || m.resourceType === 'gateway' || m.resourceType === 'router' || m.resourceType === 'switch'
    );
    const upstreamEdgeChanges = diff.modifiedEdges.filter(
      (e) => upstreamNodeIds.has(e.sourceId) || upstreamNodeIds.has(e.targetId) || e.targetId === serviceNodeId
    );

    return {
      serviceNodeId,
      incidentTimestampIso: new Date(incidentTimestampMs).toISOString(),
      lookbackWindowSeconds: Math.round(lookbackMs / 1000),
      upstreamNodeChanges,
      upstreamEdgeChanges,
      precedingChangesCount: upstreamNodeChanges.length + upstreamEdgeChanges.length
    };
  }

  /**
   * Query 4: "Which endpoints have changed IP or MAC binding over the last 24 hours?"
   */
  findIdentityDriftEvents(windowHours = 24) {
    const cutoffMs = Date.now() - windowHours * 3600 * 1000;
    const events = this.identityHistory.filter((ev) => (ev.observedAtMs || Date.now()) >= cutoffMs);
    return {
      windowHours,
      count: events.length,
      events,
      reconciliationCandidates: this.reconciliationCandidates
    };
  }

  /**
   * Continuous Laplacian Heat Diffusion Engine
   * Solves p_t = exp(-t * L) * v_0, where L = I - D^(-1/2) * A * D^(-1/2)
   * via truncated Taylor series / Chebyshev polynomial expansion (k = 6 terms).
   *
   * @param {string} sourceNodeId
   * @param {number} [t=1.0] - Continuous diffusion time parameter
   * @param {Object} [options={}] - Options including persistToEvidenceDag
   * @returns {Object} Diffusion contours and degradation probabilities across topology
   */
  computeLaplacianHeatDiffusion(sourceNodeId, t = 1.0, options = {}) {
    if (this.nodes.size === 0) {
      this.syncFromLiveInfrastructure('initial_load');
    }
    const startNode = this.nodes.get(sourceNodeId);
    if (!startNode) {
      return {
        sourceNodeId,
        sourceLabel: null,
        diffusionTimeT: t,
        expansionTerms: 6,
        nodeCount: 0,
        diffusionContours: []
      };
    }

    const nodeList = Array.from(this.nodes.values());
    const N = nodeList.length;
    if (N === 0) {
      return {
        sourceNodeId,
        sourceLabel: startNode.label,
        diffusionTimeT: t,
        expansionTerms: 6,
        nodeCount: 0,
        diffusionContours: []
      };
    }

    const nodeIndexMap = new Map();
    nodeList.forEach((n, idx) => nodeIndexMap.set(n.nodeId, idx));
    const sourceIdx = nodeIndexMap.get(sourceNodeId);
    if (sourceIdx === undefined) {
      return {
        sourceNodeId,
        sourceLabel: startNode.label,
        diffusionTimeT: t,
        expansionTerms: 6,
        nodeCount: N,
        diffusionContours: []
      };
    }

    // Build symmetric adjacency list with edge confidence weights
    const adjacency = Array.from({ length: N }, () => []);
    const degrees = new Float64Array(N);

    for (const edge of this.edges.values()) {
      const u = nodeIndexMap.get(edge.sourceId);
      const v = nodeIndexMap.get(edge.targetId);
      if (u !== undefined && v !== undefined && u !== v) {
        const weight = typeof edge.confidence === 'number' && edge.confidence > 0 ? edge.confidence : 1.0;
        adjacency[u].push({ neighbor: v, weight });
        adjacency[v].push({ neighbor: u, weight });
        degrees[u] += weight;
        degrees[v] += weight;
      }
    }

    // Handle isolated nodes: minimum degree 1.0 to prevent division by zero
    for (let i = 0; i < N; i++) {
      if (degrees[i] <= 0) degrees[i] = 1.0;
    }

    // Normalized Laplacian operator: (L * x)_i = x_i - \sum_{j \in N(i)} (A_{i,j} / \sqrt{d_i * d_j}) * x_j
    const applyLaplacian = (xVec) => {
      const out = new Float64Array(N);
      for (let i = 0; i < N; i++) {
        let sumNeighbors = 0;
        const sqrtDi = Math.sqrt(degrees[i]);
        for (const { neighbor: j, weight } of adjacency[i]) {
          const sqrtDj = Math.sqrt(degrees[j]);
          sumNeighbors += (weight / (sqrtDi * sqrtDj)) * xVec[j];
        }
        out[i] = xVec[i] - sumNeighbors;
      }
      return out;
    };

    // Initial impulse vector v_0: 1.0 at sourceNode, 0.0 elsewhere
    const v0 = new Float64Array(N);
    v0[sourceIdx] = 1.0;

    // Truncated Taylor series expansion of exp(-t * L) * v_0 for k = 0..6:
    // p_t = \sum_{k=0}^{6} ((-t)^k / k!) * (L^k * v_0)
    const pt = new Float64Array(N);
    for (let i = 0; i < N; i++) pt[i] = v0[i]; // k = 0 term: 1.0 * v_0

    let currentLPower = v0;
    let factorial = 1;
    let tPower = 1;

    for (let k = 1; k <= 6; k++) {
      currentLPower = applyLaplacian(currentLPower);
      factorial *= k;
      tPower *= t;
      const coeff = (Math.pow(-1, k) * tPower) / factorial;
      for (let i = 0; i < N; i++) {
        pt[i] += coeff * currentLPower[i];
      }
    }

    // Format diffusion contours with clamped degradation probabilities
    const diffusionContours = [];
    for (let i = 0; i < N; i++) {
      const node = nodeList[i];
      const rawProb = pt[i];
      const prob = Number(Math.max(0.0, Math.min(1.0, rawProb)).toFixed(4));
      const contourLevel = prob >= 0.60
        ? 'HIGH_DEGRADATION'
        : (prob >= 0.30
            ? 'MODERATE_DEGRADATION'
            : (prob >= 0.05 ? 'MARGINAL_EXPOSURE' : 'MINIMAL_EXPOSURE'));

      diffusionContours.push({
        nodeId: node.nodeId,
        label: node.label || node.hostname || node.nodeId,
        resourceType: node.resourceType || 'host',
        degradationProbability: prob,
        contourLevel,
        isSource: i === sourceIdx
      });
    }

    // Sort descending by degradation probability
    diffusionContours.sort((a, b) => b.degradationProbability - a.degradationProbability);

    // Causal DAG Integration: persist diffusion blast-radius profiles into evidenceFabric DAG edges
    if (options.persistToEvidenceDag !== false && evidenceFabric) {
      try {
        const nowIso = new Date().toISOString();
        if (typeof evidenceFabric._persistDagNode === 'function') {
          if (!evidenceFabric.dagNodes.has(sourceNodeId)) {
            evidenceFabric._persistDagNode({
              nodeId: sourceNodeId,
              nodeType: 'topology_node',
              subject: sourceNodeId,
              label: startNode.label || sourceNodeId,
              payload: { resourceType: startNode.resourceType },
              qualityScore: 1.0,
              freshnessState: 'live',
              createdAt: nowIso,
              updatedAt: nowIso
            });
          }
        }

        for (const c of diffusionContours) {
          if (c.nodeId === sourceNodeId || c.degradationProbability < 0.05) continue;
          if (typeof evidenceFabric._persistDagNode === 'function' && !evidenceFabric.dagNodes.has(c.nodeId)) {
            evidenceFabric._persistDagNode({
              nodeId: c.nodeId,
              nodeType: 'topology_node',
              subject: c.nodeId,
              label: c.label || c.nodeId,
              payload: { resourceType: c.resourceType },
              qualityScore: 1.0,
              freshnessState: 'live',
              createdAt: nowIso,
              updatedAt: nowIso
            });
          }
          if (typeof evidenceFabric._persistDagEdge === 'function') {
            evidenceFabric._persistDagEdge({
              edgeId: `EDG-DIFFUSION-${sourceNodeId}-${c.nodeId}`,
              sourceNodeId,
              targetNodeId: c.nodeId,
              relationType: 'DIFFUSION_BLAST_RADIUS',
              weight: c.degradationProbability,
              metadata: {
                diffusionTimeT: t,
                contourLevel: c.contourLevel,
                degradationProbability: c.degradationProbability
              },
              createdAt: nowIso
            });
          }
        }
      } catch (_) {}
    }

    return {
      sourceNodeId,
      sourceLabel: startNode.label,
      diffusionTimeT: t,
      expansionTerms: 6,
      nodeCount: N,
      diffusionContours
    };
  }

  /**
   * Query 5: Multi-hop Topological Blast-Radius, Continuous Laplacian Diffusion & M/M/1 Queueing Delay
   */
  computeBlastRadius(sourceNodeId, injectedLatencyMs = 100, options = {}) {
    if (this.nodes.size === 0) {
      this.syncFromLiveInfrastructure('initial_load');
    }
    const startNode = this.nodes.get(sourceNodeId);
    if (!startNode) {
      return {
        sourceNodeId,
        impactedCount: 0,
        impactedNodes: [],
        queuingPropagation: { cascadingCongestionNodes: 0, maxDownstreamQueueDelayMs: 0 }
      };
    }

    // 1. Continuous Laplacian Heat Diffusion
    const laplacianDiffusion = this.computeLaplacianHeatDiffusion(sourceNodeId, options.diffusionTimeT ?? 1.0, options);
    const contourMap = new Map();
    for (const c of (laplacianDiffusion.diffusionContours || [])) {
      contourMap.set(c.nodeId, c);
    }

    // 2. Multi-hop traversal and M/M/1 queuing propagation
    const visited = new Set([sourceNodeId]);
    const queue = [{ nodeId: sourceNodeId, hopDistance: 0 }];
    const impactedNodes = [];
    let maxDownstreamQueueDelayMs = 0;
    let cascadingCongestionNodes = 0;

    while (queue.length > 0) {
      const current = queue.shift();
      if (current.hopDistance >= 4) continue;

      for (const edge of this.edges.values()) {
        let nextId = null;
        if (edge.sourceId === current.nodeId && !visited.has(edge.targetId)) {
          nextId = edge.targetId;
        } else if (
          edge.targetId === current.nodeId &&
          (edge.relationshipType === 'depends_on' || edge.relationshipType === 'served_by') &&
          !visited.has(edge.sourceId)
        ) {
          nextId = edge.sourceId;
        }

        if (nextId) {
          visited.add(nextId);
          const nextHop = current.hopDistance + 1;
          const nodeObj = this.nodes.get(nextId);
          if (nodeObj) {
            const attenuation = Math.pow(0.68, nextHop - 1);
            const propagationRisk = Number(Math.max(0.15, Math.min(0.98, 0.9 * attenuation)).toFixed(2));
            const utilPct = Number(edge.attributes?.utilizationPct ?? 35);
            const rho = Math.min(0.95, Math.max(0.1, (utilPct + injectedLatencyMs * 0.25 * attenuation) / 100));
            const estimatedQueueDelayMs = Number(((injectedLatencyMs * attenuation) * (1 / (1 - rho) - 1) * 0.35).toFixed(1));
            if (estimatedQueueDelayMs > maxDownstreamQueueDelayMs) {
              maxDownstreamQueueDelayMs = estimatedQueueDelayMs;
            }
            const congestionRegime = rho >= 0.8 ? 'critical_saturation' : (rho >= 0.55 ? 'elevated_queueing' : 'nominal');
            if (rho >= 0.8) cascadingCongestionNodes++;

            const contourInfo = contourMap.get(nodeObj.nodeId);
            const degradationProbability = contourInfo ? contourInfo.degradationProbability : propagationRisk;
            const contourLevel = contourInfo ? contourInfo.contourLevel : 'MODERATE_DEGRADATION';

            impactedNodes.push({
              nodeId: nodeObj.nodeId,
              label: nodeObj.label || nodeObj.hostname || nodeObj.nodeId,
              resourceType: nodeObj.resourceType || 'host',
              type: nodeObj.resourceType || 'host',
              hopDistance: nextHop,
              relationshipType: edge.relationshipType,
              propagationRisk,
              degradationProbability,
              contourLevel,
              estimatedQueueDelayMs,
              congestionRegime
            });
            queue.push({ nodeId: nextId, hopDistance: nextHop });
          }
        }
      }
    }

    return {
      sourceNodeId,
      sourceLabel: startNode.label,
      injectedLatencyMs,
      impactedCount: impactedNodes.length,
      impactedNodes,
      laplacianDiffusion,
      queuingPropagation: {
        cascadingCongestionNodes,
        maxDownstreamQueueDelayMs
      }
    };
  }

  /**
   * Query 6: Enterprise Topology Complexity Audit (HA Redundancy Pairs, Circular Dependencies & Visibility Gaps)
   */
  analyzeEnterpriseDependencyComplexity(customNodes = null, customEdges = null, options = {}) {
    if (this.nodes.size === 0 && !customNodes) {
      this.syncFromLiveInfrastructure('initial_load');
    }
    const { disambiguateUpstreamVsDownstreamSymptoms } = require('../rca-engine');
    const nodesList = Array.isArray(customNodes)
      ? customNodes
      : Array.from(this.nodes.values()).map((n) => ({
          id: n.nodeId,
          role: n.resourceType,
          location: n.layer || 'ENTERPRISE_TIER',
          status: String(n.status || 'healthy').toUpperCase() === 'HEALTHY' ? 'PASS' : String(n.status || 'PASS').toUpperCase(),
          haGroup: n.attributes?.haGroup || n.attributes?.redundancyGroup || null,
          redundancyMode: n.attributes?.redundancyMode || 'ACTIVE_ACTIVE',
          quorumMinHealthy: n.attributes?.quorumMinHealthy || 1,
          clusterLoadPct: n.attributes?.clusterLoadPct || 0,
          memberCapacityPct: n.attributes?.memberCapacityPct || 100,
          failbackInProgress: Boolean(n.attributes?.failbackInProgress),
          firstAnomalyTimestampMs: n.attributes?.firstAnomalyTimestampMs ?? null,
          timestampUnreliable: Boolean(n.attributes?.timestampUnreliable),
          probed: n.attributes?.probed !== false
        }));
    const edgesList = Array.isArray(customEdges)
      ? customEdges
      : Array.from(this.edges.values()).map((e) => ({
          from: e.sourceId,
          to: e.targetId,
          relationship: e.relationshipType
        }));

    return disambiguateUpstreamVsDownstreamSymptoms({
      nodes: nodesList,
      edges: edgesList,
      clockSkewToleranceMs: options?.clockSkewToleranceMs ?? 50
    });
  }

  /**
   * Compute Granger causality between two telemetry streams
   */
  computeGrangerCausality(streamX, streamY, lagOrder = 2, options = {}) {
    return computeGrangerCausality(streamX, streamY, lagOrder, options);
  }

  /**
   * Discover dynamic Granger causality between streamX and streamY.
   * If statistically significant (F > F_crit, p < 0.05, effectSize > 0.02),
   * dynamically upserts a directed causal edge in memory and persists to SQLite.
   */
  discoverAndUpsertCausalEdge({
    sourceId,
    targetId,
    streamX,
    streamY,
    lagOrder = 2,
    sourceLabel = null,
    targetLabel = null,
    options = {}
  }) {
    if (!sourceId || !targetId) {
      throw new Error('sourceId and targetId are required for causal edge discovery');
    }

    const granger = computeGrangerCausality(streamX, streamY, lagOrder, options);
    const edgeId = `CAUSAL_${sourceId}_${targetId}`;

    if (granger.isCausal) {
      // 1. Ensure source and target nodes exist in graph
      if (!this.nodes.has(sourceId)) {
        this.upsertNode({
          nodeId: sourceId,
          resourceType: 'service_endpoint',
          label: sourceLabel || sourceId,
          layer: 'ENTERPRISE_TIER',
          status: 'healthy'
        });
      }
      if (!this.nodes.has(targetId)) {
        this.upsertNode({
          nodeId: targetId,
          resourceType: 'service_endpoint',
          label: targetLabel || targetId,
          layer: 'ENTERPRISE_TIER',
          status: 'healthy'
        });
      }

      // 2. Upsert causal edge into temporal graph
      this.upsertEdge({
        edgeId,
        sourceId,
        targetId,
        relationshipType: 'depends_on',
        status: 'causal_active',
        confidence: Number(Math.min(0.99, Math.max(0.70, granger.effectSize)).toFixed(4)),
        attributes: {
          causalGranger: true,
          fStatistic: granger.fStatistic,
          fCritical: granger.fCritical,
          pValue: granger.pValue,
          effectSize: granger.effectSize,
          lagOrder: granger.lagOrder,
          sampleSize: granger.sampleSize,
          sourceLabel: sourceLabel || sourceId,
          targetLabel: targetLabel || targetId
        }
      });

      // 3. Persist to SQLite temporal_causal_edges with WAL durability
      try {
        db.prepare(`
          INSERT INTO temporal_causal_edges (
            id, source_id, target_id, f_statistic, f_critical, effect_size,
            lag_order, sample_size, p_value, is_causal, discovered_at, attributes_json
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            f_statistic = excluded.f_statistic,
            f_critical = excluded.f_critical,
            effect_size = excluded.effect_size,
            lag_order = excluded.lag_order,
            sample_size = excluded.sample_size,
            p_value = excluded.p_value,
            is_causal = excluded.is_causal,
            discovered_at = excluded.discovered_at,
            attributes_json = excluded.attributes_json
        `).run(
          edgeId,
          sourceId,
          targetId,
          granger.fStatistic,
          granger.fCritical,
          granger.effectSize,
          granger.lagOrder,
          granger.sampleSize,
          granger.pValue,
          1,
          new Date().toISOString(),
          JSON.stringify({
            sourceLabel: sourceLabel || sourceId,
            targetLabel: targetLabel || targetId,
            degreesOfFreedom: granger.degreesOfFreedom,
            restrictedRss: granger.restrictedRss,
            unrestrictedRss: granger.unrestrictedRss
          })
        );
      } catch (err) {
        console.error('Failed to persist temporal_causal_edges row:', err.message);
      }
    }

    return {
      edgeId,
      sourceId,
      targetId,
      ...granger
    };
  }

  /**
   * Retrieve causal ancestors for a given target entity.
   */
  getCausalAncestors(targetId) {
    if (!targetId) return [];
    try {
      const rows = db.prepare(`
        SELECT * FROM temporal_causal_edges
        WHERE target_id = ? AND is_causal = 1
        ORDER BY effect_size DESC, f_statistic DESC
      `).all(targetId);
      if (rows && rows.length > 0) {
        return rows.map((r) => ({
          edgeId: r.id,
          sourceId: r.source_id,
          targetId: r.target_id,
          fStatistic: r.f_statistic,
          fCritical: r.f_critical,
          effectSize: r.effect_size,
          lagOrder: r.lag_order,
          sampleSize: r.sample_size,
          pValue: r.p_value,
          discoveredAt: r.discovered_at,
          attributes: JSON.parse(r.attributes_json || '{}')
        }));
      }
    } catch (_) {}

    // In-memory fallback
    return Array.from(this.edges.values())
      .filter((e) => e.targetId === targetId && e.attributes?.causalGranger)
      .map((e) => ({
        edgeId: e.edgeId,
        sourceId: e.sourceId,
        targetId: e.targetId,
        fStatistic: e.attributes.fStatistic,
        fCritical: e.attributes.fCritical,
        effectSize: e.attributes.effectSize,
        lagOrder: e.attributes.lagOrder,
        sampleSize: e.attributes.sampleSize,
        pValue: e.attributes.pValue,
        discoveredAt: e.attributes.discoveredAt || null,
        attributes: e.attributes
      }));
  }

  /**
   * Return all discovered causal edges across the infrastructure
   */
  getCausalGraph() {
    try {
      const rows = db.prepare(`
        SELECT * FROM temporal_causal_edges
        WHERE is_causal = 1
        ORDER BY effect_size DESC
      `).all();
      return rows.map((r) => ({
        edgeId: r.id,
        sourceId: r.source_id,
        targetId: r.target_id,
        fStatistic: r.f_statistic,
        fCritical: r.f_critical,
        effectSize: r.effect_size,
        lagOrder: r.lag_order,
        pValue: r.p_value,
        discoveredAt: r.discovered_at,
        attributes: JSON.parse(r.attributes_json || '{}')
      }));
    } catch (_) {
      return Array.from(this.edges.values())
        .filter((e) => e.attributes?.causalGranger)
        .map((e) => ({
          edgeId: e.edgeId,
          sourceId: e.sourceId,
          targetId: e.targetId,
          fStatistic: e.attributes.fStatistic,
          fCritical: e.attributes.fCritical,
          effectSize: e.attributes.effectSize,
          lagOrder: e.attributes.lagOrder,
          pValue: e.attributes.pValue,
          discoveredAt: e.attributes.discoveredAt || null,
          attributes: e.attributes
        }));
    }
  }

  getGraphState() {
    if (this.nodes.size === 0) {
      this.syncFromLiveInfrastructure('initial_load');
    }
    return {
      canonicalResourceTypes: CANONICAL_RESOURCE_TYPES,
      typedRelationships: TYPED_RELATIONSHIPS,
      nodes: Array.from(this.nodes.values()),
      edges: Array.from(this.edges.values()),
      snapshotCount: this.snapshots.length,
      reconciliationCandidates: this.reconciliationCandidates,
      identityDriftEvents: this.identityHistory.slice(-25)
    };
  }
}

const temporalInfrastructureGraph = new TemporalInfrastructureGraph();

module.exports = {
  CANONICAL_RESOURCE_TYPES,
  TYPED_RELATIONSHIPS,
  TemporalInfrastructureGraph,
  temporalInfrastructureGraph,
  computeGrangerCausality
};
