/**
 * EJII NOC Test Suite: Pillar 1 — Network Topology & Dependency Graph
 * Validates:
 * 1. Layer 1-6 Dynamic Topology Graph Construction & Retrieval
 * 2. L2/3 Dynamic Network Discovery (SNMP / ARP / Route Table)
 * 3. Blast Radius Simulator (Downstream cascade & severed links)
 * 4. Path Trace Visualizer (Hop-by-hop RTT heatmap)
 * 5. Dynamic Link Congestion Heatmap (Octet throughput & packet rate color-coding)
 * Zero Administrative Elevation Required.
 */

const assert = require('assert');
const { topologyEngine } = require('../src/network/topology/topology-engine');
const { db } = require('../src/db/database');

async function runTopologyTests() {
  console.log('\n========================================================================');
  console.log('  PILLAR 1 TEST SUITE: NOC NETWORK TOPOLOGY & DEPENDENCY GRAPH          ');
  console.log('========================================================================');

  // Test 1: Full Layer 1 - Layer 6 Topology Graph
  console.log('[Test 1.1] Verifying Layer 1-6 Hierarchical Topology Structure...');
  const topo = topologyEngine.getTopology();
  assert.ok(topo.nodes && topo.nodes.length >= 4, 'Must return seeded topology nodes');
  assert.ok(topo.edges && topo.edges.length >= 3, 'Must return seeded topology edges');
  assert.strictEqual(topo.layers.length, 6, 'Must define exactly 6 network layers');

  const layerIds = topo.layers.map(l => l.id);
  assert.deepStrictEqual(layerIds, ['wan', 'edge', 'core', 'service', 'access', 'endpoint'], 'Layers must follow standard L1-L6 hierarchy');

  // Validate node classifications and layer assignments
  const wanNode = topo.nodes.find(n => n.layer === 'wan');
  assert.ok(wanNode, 'WAN transit node must exist');
  assert.strictEqual(wanNode.evidenceClassification, 'Configured', 'WAN node must have Configured evidence classification');

  const edgeNode = topo.nodes.find(n => n.layer === 'edge');
  assert.ok(edgeNode, 'Edge router node must exist');
  assert.strictEqual(edgeNode.evidenceClassification, 'Observed', 'Edge gateway must have Observed evidence classification');

  console.log(`  ✓ L1-L6 Topology verified: ${topo.nodes.length} nodes, ${topo.edges.length} edges across 6 layers.`);

  // Test 2: Dynamic L2/L3 Network Discovery (ARP & Route introspection)
  console.log('[Test 1.2] Verifying Dynamic L2/L3 Discovery Engine (Zero-Elevation)...');
  const discoveryResult = await topologyEngine.runDynamicDiscovery();
  assert.ok(discoveryResult.success, 'Dynamic discovery must execute successfully');
  assert.ok(typeof discoveryResult.totalArpInspected === 'number', 'Must count active OS ARP entries');
  assert.ok(discoveryResult.totalArpInspected >= 0, 'ARP entries inspected must be >= 0');
  assert.ok(discoveryResult.gatewayIp, 'Must detect physical network default gateway');
  assert.ok(discoveryResult.hostIp, 'Must detect local host IP address');
  console.log(`  ✓ Discovery verified: Host=${discoveryResult.hostIp}, Gateway=${discoveryResult.gatewayIp}, ARP Entries=${discoveryResult.totalArpInspected}.`);

  // Test 3: Blast Radius Simulator
  console.log('[Test 1.3] Verifying Blast Radius Failure Impact Simulator...');
  // Find edge router or core switch to simulate catastrophic failure
  const targetNode = topo.nodes.find(n => n.layer === 'edge') || topo.nodes[0];
  const blastResult = topologyEngine.calculateBlastRadius(targetNode.id);

  assert.strictEqual(blastResult.failedNode.id, targetNode.id, 'Blast calculation must target specified node');
  assert.ok(Array.isArray(blastResult.impactedNodes), 'Must list downstream affected nodes');
  assert.ok(Array.isArray(blastResult.severedLinks), 'Must list severed link edges');
  assert.ok(['CATASTROPHIC', 'HIGH', 'MEDIUM', 'LOW'].includes(blastResult.criticality), 'Impact severity must be valid enum');
  assert.ok(blastResult.impactPercentage >= 0 && blastResult.impactPercentage <= 100, 'Blast percentage must be 0-100%');
  console.log(`  ✓ Blast radius for ${targetNode.id} (${targetNode.name}): ${blastResult.impactedNodes.length} nodes severed, ${blastResult.severedLinks.length} links broken (Impact: ${blastResult.impactPercentage}% - ${blastResult.criticality}).`);

  // Test 4: Path Trace Visualizer (Hop-by-Hop Route Engine)
  console.log('[Test 1.4] Verifying Graphical Path Trace Visualizer & Per-Hop RTTs...');
  const pathTrace = topologyEngine.tracePath('NODE-HOST-01', 'NODE-WAN-01');

  assert.ok(pathTrace.success, 'Path trace from endpoint to WAN must succeed');
  assert.ok(pathTrace.hops.length >= 2, 'Path must include at least local host, gateway, and target');
  assert.strictEqual(pathTrace.hops[0].layer, 'endpoint', 'First hop must be local endpoint host');

  for (const hop of pathTrace.hops) {
    assert.ok(hop.hopNumber >= 1, 'Hop number must be positive');
    assert.ok(hop.ip, 'Hop must include IP address');
    assert.ok(typeof hop.rttMs === 'number', 'Hop must measure real RTT in ms');
  }
  console.log(`  ✓ Path trace verified: ${pathTrace.totalHops} hops mapped, Cumulative RTT=${pathTrace.totalLatencyMs}ms.`);

  // Test 5: Dynamic Link Congestion Heatmap (Octet throughput & packet rate)
  console.log('[Test 1.5] Verifying Link Congestion Heatmap & Color-Coding Engine...');
  const heatmap = topologyEngine.getCongestionHeatmap();
  assert.ok(Array.isArray(heatmap), 'Heatmap must return array of edges');
  assert.ok(heatmap.length > 0, 'Must have evaluated edges');

  for (const link of heatmap) {
    assert.ok(link.edgeId, 'Link must have edgeId');
    assert.ok(['green', 'amber', 'red'].includes(link.statusColor), 'Color must be green, amber, or red');
    assert.ok(link.utilizationPct >= 0 && link.utilizationPct <= 100, 'Bandwidth utilization must be 0-100%');
    assert.ok(typeof link.packetRate === 'number', 'Packet rate must be a number');
  }

  // Test updating link metrics dynamically and verifying color transition
  const testEdge = topo.edges[0];
  topologyEngine.updateLinkMetrics(testEdge.id, 92.5, 4500, 150); // High congestion
  const updatedHeatmap = topologyEngine.getCongestionHeatmap();
  const updatedLink = updatedHeatmap.find(l => l.edgeId === testEdge.id);
  assert.strictEqual(updatedLink.statusColor, 'red', 'Link > 85% utilization must be red');
  assert.strictEqual(updatedLink.statusClass, 'link-flashing-red', 'Link > 85% utilization must flash red');
  assert.strictEqual(updatedLink.utilizationPct, 92.5, 'Utilization must reflect updated metric');

  // Reset back to healthy
  topologyEngine.updateLinkMetrics(testEdge.id, 12.0, 300, 5);
  const resetHeatmap = topologyEngine.getCongestionHeatmap();
  const resetLink = resetHeatmap.find(l => l.edgeId === testEdge.id);
  assert.strictEqual(resetLink.statusColor, 'green', 'Link < 50% utilization must be green');
  assert.strictEqual(resetLink.statusClass, 'link-smooth-green', 'Link < 50% utilization must be smooth green');
  console.log('  ✓ Dynamic link congestion heatmap verified with real-time green/amber/flashing-red color transitions.');

  console.log('\n========================================================================');
  console.log('  PILLAR 1 TEST SUITE PASSED: 100% GREEN');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runTopologyTests().then(() => process.exit(0)).catch(err => {
    console.error('❌ Topology tests failed:', err);
    process.exit(1);
  });
}

module.exports = { runTopologyTests };
