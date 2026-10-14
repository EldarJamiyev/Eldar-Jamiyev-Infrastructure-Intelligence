/**
 * EJII Root Cause Analysis (RCA) & Dependency Correlation Engine
 * Deterministic DAG dependency modeling, alarm suppression, and evidence synthesis.
 */

const crypto = require('crypto');
const { db } = require('../db/database');
const { logAction } = require('./audit-logger');

/**
 * Fetch all nodes with their parent-child dependency relationships
 */
function getDependencyTopology() {
  const nodes = db.prepare('SELECT * FROM nodes').all();
  const nodeMap = new Map();

  for (const node of nodes) {
    nodeMap.set(node.id, {
      ...node,
      children: [],
      metadata: node.metadata ? JSON.parse(node.metadata) : {}
    });
  }

  // Populate children
  for (const node of nodeMap.values()) {
    if (node.parent_id && nodeMap.has(node.parent_id)) {
      nodeMap.get(node.parent_id).children.push(node.id);
    }
  }

  return { nodes, nodeMap };
}

/**
 * Check if any upstream ancestor of a node is currently down or critical
 * @param {string} nodeId 
 * @param {Map} nodeMap 
 */
function findDownstreamOrAncestorFailure(nodeId, nodeMap) {
  let current = nodeMap.get(nodeId);
  const visited = new Set();
  if (nodeId) visited.add(nodeId);

  while (current && current.parent_id) {
    if (visited.has(current.parent_id)) {
      // Cycle detected in topological DAG — break immediately to prevent infinite loop
      break;
    }
    visited.add(current.parent_id);

    const parent = nodeMap.get(current.parent_id);
    if (!parent) break;

    // Check if the parent has an active critical incident
    const activeIncident = db.prepare(`
      SELECT * FROM incidents 
      WHERE primary_node_id = ? AND status IN ('open', 'investigating')
    `).get(parent.id);

    if (activeIncident) {
      return {
        hasParentFailure: true,
        rootParent: parent,
        incident: activeIncident
      };
    }

    current = parent;
  }

  return { hasParentFailure: false, rootParent: null, incident: null };
}

/**
 * Analyze an infrastructure failure event and correlate with dependency DAG
 * @param {Object} params
 * @param {string} params.nodeId
 * @param {string} params.metricType ('ping', 'port', 'http', 'snmp', 'cpu', 'disk')
 * @param {string} params.errorDescription
 * @param {Object} params.telemetryPayload
 */
function correlateAndReportIncident({ nodeId, metricType, errorDescription, telemetryPayload }) {
  const { nodeMap } = getDependencyTopology();
  const node = nodeMap.get(nodeId);

  if (!node) {
    return null;
  }

  // Check if an ancestor node is already marked as failed
  const ancestorCheck = findDownstreamOrAncestorFailure(nodeId, nodeMap);

  if (ancestorCheck.hasParentFailure) {
    // Suppress alert storm! Increment suppressed_count on parent incident
    db.prepare(`
      UPDATE incidents 
      SET suppressed_count = suppressed_count + 1 
      WHERE id = ?
    `).run(ancestorCheck.incident.id);

    logAction({
      userId: 'SYSTEM_RCA',
      username: 'RCA Correlation Engine',
      role: 'system',
      action: 'ALERT_SUPPRESSED',
      resource: `Node:${node.name}`,
      details: `Suppressed secondary alert for ${node.name} (${node.hostname_or_ip}) because parent ${ancestorCheck.rootParent.name} is already DOWN.`
    });

    return {
      status: 'SUPPRESSED',
      parentIncidentId: ancestorCheck.incident.id,
      rootNode: ancestorCheck.rootParent.name,
      message: `Alert suppressed: Dependent on failed ancestor [${ancestorCheck.rootParent.name}].`
    };
  }

  // Check if this node already has an open incident
  const existing = db.prepare(`
    SELECT * FROM incidents 
    WHERE primary_node_id = ? AND status IN ('open', 'investigating')
  `).get(nodeId);

  if (existing) {
    return {
      status: 'EXISTING_INCIDENT',
      incidentId: existing.id,
      message: 'Active incident already open for this node.'
    };
  }

  // Synthesize Root Cause Analysis & Structured Evidence
  const incidentId = 'INC-' + crypto.randomBytes(4).toString('hex').toUpperCase();
  const timestamp = new Date().toISOString();

  let title = `Infrastructure Degradation: ${node.name}`;
  let severity = 'P2_HIGH';
  let whatHappened = '';
  let rootCause = '';
  let supportingEvidence = '';
  let remediationPlan = '';

  if (metricType === 'ping') {
    title = `Connectivity Loss: ${node.name} (${node.hostname_or_ip})`;
    severity = node.type === 'gateway' || node.type === 'router' ? 'P1_CRITICAL' : 'P2_HIGH';
    whatHappened = `Node [${node.name}] stopped responding to ICMP echo requests. 100% packet loss detected.`;
    rootCause = `Layer 3 network unreachability. Target host is powered down, link interface is severed, or routing path is down.`;
    supportingEvidence = `Probe Timestamp: ${timestamp}\nPacket Loss: 100%\nPackets Sent: ${telemetryPayload.packetsSent || 4}, Received: 0\nDuration: ${telemetryPayload.durationMs || 0}ms\nRaw Error: ${errorDescription || 'Request timed out'}`;
    remediationPlan = `1. Check physical/virtual power state for host [${node.name}].\n2. Inspect switch port status connecting to ${node.hostname_or_ip}.\n3. Verify default gateway ARP table and routing table entries.`;
  } else if (metricType === 'port') {
    title = `Service Port Inaccessible: ${node.name}:${telemetryPayload.port || ''}`;
    severity = 'P2_HIGH';
    whatHappened = `Port ${telemetryPayload.port} on [${node.name}] is unreachable. Socket status: ${telemetryPayload.status || 'CLOSED'}.`;
    rootCause = telemetryPayload.status === 'CLOSED'
      ? `Host is online, but target service daemon is stopped or not listening on port ${telemetryPayload.port} (ECONNREFUSED).`
      : `Packets to port ${telemetryPayload.port} are being silently discarded by firewall or network ACL (ETIMEDOUT).`;
    supportingEvidence = `Target: ${node.hostname_or_ip}:${telemetryPayload.port}\nSocket Status: ${telemetryPayload.status}\nError: ${errorDescription}\nConnect Latency: ${telemetryPayload.connectLatencyMs || 0}ms`;
    remediationPlan = telemetryPayload.status === 'CLOSED'
      ? `1. Check if the underlying service process is running.\n2. Restart the application daemon via EJII Safe Automation.\n3. Review host application logs for crashes.`
      : `1. Inspect host local firewall rules (Windows Defender / iptables).\n2. Verify network security group (NSG) and edge firewall policies.`;
  } else if (metricType === 'disk') {
    const driveName = telemetryPayload.mount || telemetryPayload.drive || 'System Storage';
    const usedPct = telemetryPayload.usedPercentage !== undefined ? `${telemetryPayload.usedPercentage}%` : 'Threshold Exceeded';
    title = `Storage Capacity Warning: ${node.name} [${driveName}]`;
    severity = 'P2_HIGH';
    whatHappened = `Storage volume [${driveName}] on [${node.name}] has exceeded safe operational capacity.`;
    rootCause = `Volume usage at ${usedPct} capacity.`;
    supportingEvidence = `Drive: ${driveName}\nTotal: ${telemetryPayload.totalFormatted || 'N/A'}\nFree: ${telemetryPayload.freeFormatted || 'N/A'}\nUsed: ${usedPct}`;
    remediationPlan = `1. Execute disk cleanup or delete stale logs.\n2. Expand virtual disk volume size if on hypervisor.\n3. Inspect rogue temp directories.`;
  } else {
    whatHappened = `Anomaly detected on [${node.name}]: ${errorDescription}`;
    rootCause = `Telemetry anomaly triggered threshold violation for metric [${metricType}].`;
    supportingEvidence = JSON.stringify(telemetryPayload, null, 2);
    remediationPlan = `1. Investigate metric [${metricType}] historical graphs.\n2. Check host event logs.`;
  }

  // Insert Incident
  db.prepare(`
    INSERT INTO incidents (
      id, title, status, severity, primary_node_id, what_happened, 
      root_cause, supporting_evidence, remediation_plan, suppressed_count, detected_at
    ) VALUES (?, ?, 'open', ?, ?, ?, ?, ?, ?, 0, ?)
  `).run(
    incidentId,
    title,
    severity,
    nodeId,
    whatHappened,
    rootCause,
    supportingEvidence,
    remediationPlan,
    timestamp
  );

  // Update Node status
  db.prepare('UPDATE nodes SET status = ? WHERE id = ?').run(
    severity === 'P1_CRITICAL' ? 'critical' : 'warning',
    nodeId
  );

  logAction({
    userId: 'SYSTEM_RCA',
    username: 'RCA Correlation Engine',
    role: 'system',
    action: 'INCIDENT_CREATED',
    resource: incidentId,
    details: `Incident created for ${node.name}: ${title} [${severity}]`
  });

  return {
    status: 'NEW_INCIDENT',
    incidentId,
    title,
    severity
  };
}

/**
 * Resolve an active incident
 */
function resolveIncident(incidentId, userId, username, role = 'admin', resolutionNotes = '') {
  const timestamp = new Date().toISOString();
  const incident = db.prepare('SELECT * FROM incidents WHERE id = ?').get(incidentId);

  if (!incident) {
    return { success: false, error: 'Incident not found.' };
  }

  db.prepare(`
    UPDATE incidents 
    SET status = 'resolved', resolved_at = ?, resolved_by = ? 
    WHERE id = ?
  `).run(timestamp, username || userId, incidentId);

  // Re-evaluate node status
  db.prepare("UPDATE nodes SET status = 'healthy' WHERE id = ?").run(incident.primary_node_id);

  logAction({
    userId,
    username,
    role: role || 'admin',
    action: 'INCIDENT_RESOLVED',
    resource: incidentId,
    details: `Resolved incident [${incidentId}]. Notes: ${resolutionNotes}`
  });

  return { success: true, incidentId, resolvedAt: timestamp };
}

module.exports = {
  getDependencyTopology,
  correlateAndReportIncident,
  resolveIncident
};
