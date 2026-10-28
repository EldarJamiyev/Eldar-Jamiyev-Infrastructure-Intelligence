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
    `);
  } catch (_) {}
}

ensureTemporalGraphTables();

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
        confidence: n.evidenceClassification === 'Observed' ? 0.96 : 0.85,
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
        confidence: 0.94,
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
      confidence: typeof nodeInput.confidence === 'number' ? nodeInput.confidence : 0.95,
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
      confidence: typeof edgeInput.confidence === 'number' ? edgeInput.confidence : 0.95,
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
  temporalInfrastructureGraph
};
