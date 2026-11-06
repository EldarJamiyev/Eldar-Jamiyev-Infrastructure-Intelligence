/**
 * EJII Test Suite: Root Cause Analysis (RCA) & Correlation Engine
 */

const assert = require('assert');
const { db } = require('../src/db/database');
const { correlateAndReportIncident, resolveIncident, getDependencyTopology } = require('../src/core/rca-engine');

async function runRcaTests() {
  console.log('\n--- Running RCA & Dependency Correlation Test Suite ---');

  // Test 1: Topology DAG verification
  console.log('Testing Dependency DAG Construction...');
  const { nodes, nodeMap } = getDependencyTopology();
  assert.ok(nodes.length >= 4, 'Topology must have seeded nodes');
  assert.ok(nodeMap.has('NODE-GW-01'), 'Must include Gateway node');
  assert.ok(nodeMap.has('NODE-LOCAL-HOST'), 'Must include Local Host node');
  console.log(`✓ Dependency DAG verified: ${nodes.length} nodes loaded.`);

  // Ensure clean test baseline by resolving any prior active incidents on test nodes
  db.prepare("UPDATE incidents SET status = 'resolved' WHERE primary_node_id IN ('NODE-GW-01', 'NODE-LOCAL-HOST') AND status != 'resolved'").run();

  // Test 2: Primary Incident Creation on Gateway Failure
  console.log('Testing Primary Incident Generation on Root Node Failure...');
  const gwIncident = correlateAndReportIncident({
    nodeId: 'NODE-GW-01',
    metricType: 'ping',
    errorDescription: '100% Packet Loss on Gateway Uplink',
    telemetryPayload: { packetsSent: 4, packetsReceived: 0, packetLossPct: 100, durationMs: 2000 }
  });

  assert.ok(gwIncident.incidentId, 'Must create an incident ID');
  assert.strictEqual(gwIncident.status, 'NEW_INCIDENT', 'Must register as a new incident');
  console.log(`✓ Primary incident created: ${gwIncident.incidentId} [${gwIncident.title}]`);

  // Test 3: Downstream Symptom Alarm Suppression
  console.log('Testing Downstream Alert Suppression when Parent is DOWN...');
  const childSuppressed = correlateAndReportIncident({
    nodeId: 'NODE-LOCAL-HOST', // Child of NODE-GW-01
    metricType: 'ping',
    errorDescription: 'Connection timed out',
    telemetryPayload: { packetsSent: 4, packetsReceived: 0, packetLossPct: 100 }
  });

  assert.strictEqual(childSuppressed.status, 'SUPPRESSED', 'Child alert must be suppressed');
  assert.strictEqual(childSuppressed.parentIncidentId, gwIncident.incidentId, 'Suppression must link to parent incident');
  console.log(`✓ Alert suppression verified: Suppressed secondary alarm on NODE-LOCAL-HOST -> Parent: ${childSuppressed.rootNode}`);

  // Test 4: Structured Evidence & Remediation Plan in Incident Record
  console.log('Testing Evidence & Remediation Plan Synthesis...');
  const incidentRec = db.prepare('SELECT * FROM incidents WHERE id = ?').get(gwIncident.incidentId);
  assert.ok(incidentRec.what_happened.length > 10, 'What Happened explanation must be populated');
  assert.ok(incidentRec.root_cause.length > 10, 'Root Cause explanation must be populated');
  assert.ok(incidentRec.supporting_evidence.includes('Packet Loss'), 'Supporting Evidence must include telemetry');
  assert.ok(incidentRec.remediation_plan.includes('1.'), 'Remediation plan must be structured steps');
  assert.ok(incidentRec.suppressed_count >= 1, 'Suppressed count must reflect suppressed children');
  console.log(`✓ Incident synthesis verified:\n  What: ${incidentRec.what_happened}\n  Cause: ${incidentRec.root_cause}\n  Suppressed Count: ${incidentRec.suppressed_count}`);

  // Test 5: Incident Resolution
  console.log('Testing Incident Resolution...');
  const resResult = resolveIncident(gwIncident.incidentId, 'USR-SYSADMIN-01', 'sysadmin', 'Gateway uplink restored.');
  assert.strictEqual(resResult.success, true, 'Resolution must succeed');
  const resolvedRec = db.prepare('SELECT status, resolved_by FROM incidents WHERE id = ?').get(gwIncident.incidentId);
  assert.strictEqual(resolvedRec.status, 'resolved', 'Incident status must be resolved');
  console.log(`✓ Incident resolution verified: Status=${resolvedRec.status}, ResolvedBy=${resolvedRec.resolved_by}`);

  console.log('--- RCA & Correlation Engine Test Suite PASSED ---\n');
}

if (require.main === module) {
  runRcaTests().catch((err) => {
    console.error('RCA Tests FAILED:', err);
    process.exit(1);
  });
}

module.exports = { runRcaTests };
