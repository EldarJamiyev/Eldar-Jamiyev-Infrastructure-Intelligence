/**
 * Regression Test Suite: NOC Packet Integrity, Evidence Classification & Flow Matrix
 * Verifies commit 8b90490 audit findings and NOC repairs under Zero-Simulation Doctrine.
 */

const assert = require('assert');
const { packetStreamer } = require('../src/network/packet-streaming/packet-streamer');

async function runNocIntegrityRegressionTests() {
  console.log('\n========================================================================');
  console.log('  SUITE 13: NOC PACKET INTEGRITY, FLOW MATRIX & EVIDENCE TOPOLOGY REGRESSION');
  console.log('========================================================================');

  // [Test 13.1] Strict Transport Protocol Separation (TCP vs Application TLS/DNS)
  console.log('[Test 13.1] Verifying Transport Protocol Integrity (TCP port 443 without TLS records)...');
  const dummyTcpConn = {
    protocol: 'TCP',
    localIp: '10.168.195.33',
    localPort: 54321,
    remoteIp: '10.22.12.204',
    remotePort: 443,
    state: 'ESTABLISHED',
    pid: 1234
  };
  const synthFrame = await packetStreamer._synthesizeDissectedFrame(dummyTcpConn, 1001);
  assert.strictEqual(synthFrame.protocol, 'TCP', 'Transport protocol must remain TCP on wire level');
  assert.strictEqual(synthFrame.serviceName, 'HTTPS/TLS', 'Service inferred by port must be HTTPS/TLS');
  assert.ok(synthFrame.summary.includes('[TCP]'), 'Summary must contain transport protocol [TCP]');
  console.log('  ✓ Transport protocol correctly decoupled from application service.');

  // [Test 13.2] Strict TCP Socket State Reporting (No Collapsing into TIME_WAIT)
  console.log('[Test 13.2] Verifying TCP Socket State Separation (CLOSE_WAIT, FIN_WAIT, TIME_WAIT)...');
  const closeWaitConn = {
    protocol: 'TCP',
    localIp: '10.168.195.33',
    localPort: 50123,
    remoteIp: '10.22.12.204',
    remotePort: 443,
    state: 'CLOSE_WAIT',
    pid: 0
  };
  const closeWaitFrame = await packetStreamer._synthesizeDissectedFrame(closeWaitConn, 1002);
  assert.strictEqual(closeWaitFrame.processName, '[Closed Session (CLOSE_WAIT)]', 'CLOSE_WAIT socket must not be labeled TIME_WAIT');
  assert.ok(closeWaitFrame.processTooltip.includes('CLOSE_WAIT'), 'Tooltip must accurately describe CLOSE_WAIT');

  const finWaitConn = {
    protocol: 'TCP',
    localIp: '10.168.195.33',
    localPort: 50124,
    remoteIp: '10.22.12.204',
    remotePort: 443,
    state: 'FIN_WAIT_2',
    pid: 0
  };
  const finWaitFrame = await packetStreamer._synthesizeDissectedFrame(finWaitConn, 1003);
  assert.strictEqual(finWaitFrame.processName, '[Closed Session (FIN_WAIT_2)]', 'FIN_WAIT_2 socket must preserve state identity');

  const timeWaitConn = {
    protocol: 'TCP',
    localIp: '10.168.195.33',
    localPort: 50125,
    remoteIp: '10.22.12.204',
    remotePort: 443,
    state: 'TIME_WAIT',
    pid: 0
  };
  const timeWaitFrame = await packetStreamer._synthesizeDissectedFrame(timeWaitConn, 1004);
  assert.strictEqual(timeWaitFrame.processName, '[Closed Session (TIME_WAIT)]', 'TIME_WAIT socket correctly recognized');
  console.log('  ✓ Distinct TCP socket states strictly preserved without misattribution.');

  // [Test 13.3] Reverse DNS PTR vs URL Formatting Integrity
  console.log('[Test 13.3] Verifying Reverse DNS PTR formatting (never prefix with https://)...');
  packetStreamer.reverseDnsMap.set('142.250.185.78', {
    hostname: 'fra16s50-in-f14.1e100.net',
    source: 'Reverse DNS PTR Query',
    confidence: 'MEDIUM',
    timestamp: Date.now()
  });
  const ptrRawFrame = {
    srcIp: '10.168.195.33',
    srcPort: 51234,
    dstIp: '142.250.185.78',
    dstPort: 443,
    protocol: 'TCP',
    tcp: { flags: { ack: true } },
    summary: 'TCP Segment'
  };
  packetStreamer._ingestNpcapFrame(ptrRawFrame);
  assert.ok(ptrRawFrame.urlResolution, 'Frame must have urlResolution');
  assert.strictEqual(ptrRawFrame.urlResolution.method, 'Reverse DNS PTR', 'Method must be Reverse DNS PTR');
  assert.strictEqual(ptrRawFrame.urlResolution.isLinkable, false, 'PTR record must not be linkable');
  assert.ok(!ptrRawFrame.urlResolution.hostnameOrUrl.startsWith('https://'), 'PTR must not have https:// prefix');
  assert.strictEqual(ptrRawFrame.urlResolution.hostnameOrUrl, 'fra16s50-in-f14.1e100.net');
  console.log('  ✓ Reverse DNS PTR records strictly separated from web URLs.');

  // [Test 13.4] NirSoft Flow Matrix Latency & Throughput Integrity
  console.log('[Test 13.4] Verifying Flow Matrix Latency (null when unmeasured, no hardcoded 1ms)...');
  packetStreamer.clearBuffer();
  const wireFrame1 = {
    timestamp: new Date().toISOString(),
    srcIp: '10.168.195.33',
    srcPort: 45678,
    dstIp: '10.22.12.204',
    dstPort: 443,
    protocol: 'TCP',
    wireLength: 120,
    tcp: { flags: { ack: true } },
    tcpAnalysis: { rttMs: null } // Handshake was not captured, RTT is unmeasured
  };
  packetStreamer._updateFlowFromWireFrame(wireFrame1);
  const flows = packetStreamer.getFlows(10);
  assert.ok(flows.length > 0, 'Flow must be created in flowTable');
  const flow = flows[0];
  assert.strictEqual(flow.latency, null, 'Flow latency must be null when unmeasured, never hardcoded 1ms');
  assert.ok(Number(flow.dataSpeed) >= 0.1, 'Flow dataSpeed must reflect measured byte transfer');
  console.log('  ✓ Flow matrix latency strictly authentic (null when unmeasured).');

  // [Test 13.5] Packet Accounting Counter Invariants
  console.log('[Test 13.5] Verifying Counter Invariants (received >= accepted >= decoded >= delivered)...');
  const counters = packetStreamer.getCounters();
  assert.ok(counters.received >= counters.accepted, 'received must be >= accepted');
  assert.ok(counters.accepted >= counters.decoded, 'accepted must be >= decoded');
  assert.ok(counters.decoded >= counters.delivered, 'decoded must be >= delivered');
  console.log(`  ✓ Packet accounting counters mathematically consistent: Recv=${counters.received}, Acc=${counters.accepted}, Dec=${counters.decoded}, Del=${counters.delivered}`);

  // [Test 13.6] Topology Evidence Classification & Subnet Typing
  console.log('[Test 13.6] Verifying Topology Evidence Model & Subnet Semantics (/api/network/topology)...');
  const { getDependencyTopology } = require('../src/core/rca-engine');
  const topoData = getDependencyTopology();
  assert.ok(topoData.nodes && topoData.nodes.length >= 4, 'Base topology nodes present');

  // Check routes-network enrichment logic directly
  const req = {};
  const mockRes = {
    json: function(payload) {
      assert.ok(payload.nodes, 'Topology payload must contain nodes');
      assert.ok(payload.layers && payload.layers.length === 6, 'Must define exactly 6 enterprise layers');

      const node8888 = payload.nodes.find(n => n.hostname_or_ip === '8.8.8.8');
      assert.ok(node8888, 'Node 8.8.8.8 must be present');
      assert.strictEqual(node8888.evidenceClassification, 'Configured', '8.8.8.8 must be classified as Configured');
      assert.strictEqual(node8888.layer, 'wan', '8.8.8.8 must be in layer wan');

      const nodeGw1 = payload.nodes.find(n => n.layer === 'edge' || n.hostname_or_ip === '10.168.195.1' || n.hostname_or_ip === '192.168.31.1');
      assert.ok(nodeGw1, 'Default gateway must be present');
      assert.strictEqual(nodeGw1.evidenceClassification, 'Observed', 'Default gateway must be classified as Observed');

      const nodeSubnet = payload.nodes.find(n => n.hostname_or_ip.includes('/24') || n.id === 'NODE-LAN-SUBNET' || n.id === 'NODE-LAN-01');
      assert.ok(nodeSubnet, 'Subnet LAN scope node must be present');
      assert.strictEqual(nodeSubnet.type, 'subnet', 'Subnet node must have type: subnet, not switch');
      assert.strictEqual(nodeSubnet.layer, 'access', 'Subnet node must be in layer access');

      const nodeHost = payload.nodes.find(n => n.layer === 'endpoint' || n.hostname_or_ip === '10.168.195.33' || n.hostname_or_ip === '192.168.31.89' || n.hostname_or_ip === '127.0.0.1');
      assert.ok(nodeHost, 'Local workstation host node must be present');
      assert.strictEqual(nodeHost.evidenceClassification, 'Observed', 'Local host must be classified as Observed');

      console.log(`  ✓ Topology nodes verified: 8.8.8.8 (Configured), ${nodeGw1.hostname_or_ip} (Observed Gateway), ${nodeSubnet.hostname_or_ip} (Observed Subnet LAN Scope), ${nodeHost.hostname_or_ip} (Observed Host NIC).`);
    }
  };

  const routesNetwork = require('../src/api/routes-network');
  // Find /topology handler from router stack
  const topoLayer = routesNetwork.stack.find(l => l.route && l.route.path === '/topology');
  assert.ok(topoLayer, 'Route /topology must exist in routes-network');
  topoLayer.route.stack[0].handle(req, mockRes);

  console.log('\n========================================================================');
  console.log('  SUITE 13 PASSED: 100% SUCCESSFUL COMPLETION');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runNocIntegrityRegressionTests().then(() => process.exit(0)).catch(err => {
    console.error(err);
    process.exit(1);
  });
}

module.exports = { runNocIntegrityRegressionTests };
