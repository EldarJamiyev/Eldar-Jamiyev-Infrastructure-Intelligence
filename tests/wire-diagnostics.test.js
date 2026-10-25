/**
 * EJII NOC Test Suite: Pillar 4 — Isolated Wire Diagnostics (Zero Elevation)
 * Validates:
 * 1. High-Performance Asynchronous Ping/ICMP Flooder & Sweeper (concurrency pool)
 * 2. Passive BGP & OSPF Route Listener (Wire multicast/peering frame processor)
 * 3. Wire-Level Transport Error & Problem Finder (MTU Black Holes, TCP RSTs, Retransmissions, Broadcast Storms)
 * 4. Network Anomaly SQLite Persistence & Eviction
 */

const assert = require('assert');
const { wireDiagnostics } = require('../src/network/diagnostics/wire-diagnostics');
const { db } = require('../src/db/database');

async function runWireDiagnosticsTests() {
  console.log('\n========================================================================');
  console.log('  PILLAR 4 TEST SUITE: ISOLATED WIRE DIAGNOSTICS & HELPER TOOLS         ');
  console.log('========================================================================');

  // Test 1: Asynchronous Ping/ICMP Sweeper
  console.log('[Test 4.1] Verifying High-Throughput Asynchronous Ping Sweeper (Zero-Elevation)...');
  // Generate a test pool of 10 nodes (mix of loopback, common public DNS, and unreachable IPs)
  const probeNodes = [
    { id: 'SWEEP-01', hostname_or_ip: '127.0.0.1', name: 'Loopback 1' },
    { id: 'SWEEP-02', hostname_or_ip: '127.0.0.2', name: 'Loopback 2' },
    { id: 'SWEEP-03', hostname_or_ip: '8.8.8.8', name: 'Google DNS 1' },
    { id: 'SWEEP-04', hostname_or_ip: '1.1.1.1', name: 'Cloudflare DNS' },
    { id: 'SWEEP-05', hostname_or_ip: '192.0.2.1', name: 'TEST-NET-1 (Unreachable)' }
  ];

  const sweepStartTime = Date.now();
  const sweepRes = await wireDiagnostics.asyncSweepNodes(probeNodes, 10, 600);
  const sweepDuration = Date.now() - sweepStartTime;

  assert.ok(sweepRes.success, 'Async sweep must succeed');
  assert.strictEqual(sweepRes.totalProbed, probeNodes.length, 'Must have probed all nodes in batch');
  assert.ok(sweepRes.healthyCount >= 2, 'Loopback and public DNS must be healthy');
  assert.ok(sweepRes.probesPerSecond > 0, 'Probes per second must be recorded');
  assert.ok(sweepDuration < 5000, 'Batch sweep must complete within 5 seconds due to concurrency');

  console.log(`  ✓ Async Sweeper passed: Probed ${sweepRes.totalProbed} nodes in ${sweepDuration}ms (${sweepRes.probesPerSecond} probes/sec). Healthy: ${sweepRes.healthyCount}, Unreachable: ${sweepRes.unreachableCount}.`);

  // Test 2: Passive BGP & OSPF Route Listener
  console.log('[Test 4.2] Verifying Passive BGP & OSPF Route Listener...');
  // Feed simulated wire-level routing frames
  const ospfHelloWireFrame = {
    protocol: 'OSPF',
    protocolNum: 89,
    srcIp: '10.168.195.1',
    dstIp: '224.0.0.5',
    srcPort: 0,
    dstPort: 0,
    ifName: 'Intel Wi-Fi 6E'
  };

  const bgpPeeringWireFrame = {
    protocol: 'TCP',
    protocolNum: 6,
    srcIp: '198.51.100.1',
    dstIp: '10.168.195.1',
    srcPort: 179,
    dstPort: 49152,
    ifName: 'Intel Wi-Fi 6E'
  };

  const nonRoutingFrame = {
    protocol: 'UDP',
    protocolNum: 17,
    srcIp: '10.168.195.33',
    dstIp: '8.8.8.8',
    srcPort: 53210,
    dstPort: 53
  };

  const ospfEvent = wireDiagnostics.processWireRoutingFrame(ospfHelloWireFrame);
  assert.ok(ospfEvent, 'OSPF Hello multicast frame must generate a routing event');
  assert.strictEqual(ospfEvent.protocol, 'OSPF');
  assert.strictEqual(ospfEvent.type, 'OSPF_HELLO_PACKET');
  assert.strictEqual(ospfEvent.destIp, '224.0.0.5');

  const bgpEvent = wireDiagnostics.processWireRoutingFrame(bgpPeeringWireFrame);
  assert.ok(bgpEvent, 'BGP port 179 frame must generate a routing event');
  assert.strictEqual(bgpEvent.protocol, 'BGP');
  assert.strictEqual(bgpEvent.type, 'BGP_KEEPALIVE_UPDATE');

  const ignoredEvent = wireDiagnostics.processWireRoutingFrame(nonRoutingFrame);
  assert.strictEqual(ignoredEvent, null, 'Non-routing frame must be cleanly ignored');

  const routeList = wireDiagnostics.getRoutingEvents(10);
  assert.ok(routeList.success, 'getRoutingEvents must succeed');
  assert.ok(routeList.events.length >= 2, 'Route list must contain both events');
  console.log(`  ✓ Route listener passed: Captured [${ospfEvent.protocol}] Hello & [${bgpEvent.protocol}] Peering events.`);

  // Test 3: Wire-Level Transport Error & Problem Finder
  console.log('[Test 4.3] Verifying Wire Error Finder (MTU Black Holes, TCP RST Drops, Broadcast Storms)...');
  wireDiagnostics.clearAnomalies();

  // A. MTU Black Hole Detection (ICMP Type 3 Code 4: Fragmentation Needed)
  const mtuErrorFrame = {
    srcIp: '198.51.100.254',
    dstIp: '10.168.195.33',
    protocol: 'ICMP',
    icmp: { type: 3, code: 4, typeDesc: 'Destination Unreachable (Fragmentation Needed)' }
  };
  const mtuAnomalies = wireDiagnostics.inspectWireErrors(mtuErrorFrame);
  assert.ok(mtuAnomalies.length > 0, 'Must flag MTU Black Hole anomaly');
  assert.strictEqual(mtuAnomalies[0].anomaly_type, 'MTU_BLACK_HOLE');
  assert.strictEqual(mtuAnomalies[0].severity, 'critical');

  // B. TCP Connection Reset / RST Attack Detection
  const rstFrame = {
    srcIp: '10.22.12.204',
    dstIp: '10.168.195.33',
    srcPort: 443,
    dstPort: 54321,
    protocol: 'TCP'
  };
  const rstAnalysis = { streamId: 104, isRst: true };
  const rstAnomalies = wireDiagnostics.inspectWireErrors(rstFrame, rstAnalysis);
  assert.ok(rstAnomalies.length > 0, 'Must flag TCP RST Drop anomaly');
  assert.strictEqual(rstAnomalies[0].anomaly_type, 'TCP_RST_DROP');
  assert.strictEqual(rstAnomalies[0].severity, 'warning');

  // C. TCP Retransmission Detection
  const retxFrame = {
    srcIp: '10.168.195.33',
    dstIp: '10.22.12.204',
    srcPort: 54321,
    dstPort: 443,
    protocol: 'TCP'
  };
  const retxAnalysis = { streamId: 104, isRetransmission: true };
  const retxAnomalies = wireDiagnostics.inspectWireErrors(retxFrame, retxAnalysis);
  assert.ok(retxAnomalies.length > 0, 'Must flag TCP Retransmission anomaly');
  assert.strictEqual(retxAnomalies[0].anomaly_type, 'TCP_RETRANSMISSION');

  // D. Broadcast Storm Detection (> 150 ARP/DHCP frames in 1s)
  wireDiagnostics.broadcastStats.arpCount = 180;
  wireDiagnostics.broadcastStats.lastResetMs = Date.now() - 1500; // Trigger reset window
  const bcastFrame = {
    srcIp: '10.168.195.99',
    dstIp: '255.255.255.255',
    dstMac: 'FF:FF:FF:FF:FF:FF',
    protocol: 'ARP'
  };
  const stormAnomalies = wireDiagnostics.inspectWireErrors(bcastFrame);
  assert.ok(stormAnomalies.length > 0, 'Must flag Broadcast Storm anomaly');
  assert.strictEqual(stormAnomalies[0].anomaly_type, 'BROADCAST_STORM');
  assert.strictEqual(stormAnomalies[0].severity, 'critical');

  // Verify SQLite persistence
  const savedAnomalies = wireDiagnostics.getAnomalies(50);
  assert.ok(savedAnomalies.success);
  assert.ok(savedAnomalies.anomalies.length >= 4, 'All 4 anomalies must be persisted in database');

  const types = savedAnomalies.anomalies.map(a => a.anomaly_type);
  assert.ok(types.includes('MTU_BLACK_HOLE'), 'Must store MTU_BLACK_HOLE');
  assert.ok(types.includes('TCP_RST_DROP'), 'Must store TCP_RST_DROP');
  assert.ok(types.includes('TCP_RETRANSMISSION'), 'Must store TCP_RETRANSMISSION');
  assert.ok(types.includes('BROADCAST_STORM'), 'Must store BROADCAST_STORM');

  console.log(`  ✓ Wire Error Finder passed: Detected and persisted 4 transport anomalies (${types.join(', ')}).`);

  console.log('\n========================================================================');
  console.log('  PILLAR 4 TEST SUITE PASSED: 100% GREEN');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runWireDiagnosticsTests().then(() => process.exit(0)).catch(err => {
    console.error('❌ Wire Diagnostics tests failed:', err);
    process.exit(1);
  });
}

module.exports = { runWireDiagnosticsTests };
