/**
 * EJII Test Suite: Wireshark-Grade Workstation & AI Packet Dissection Engine
 * Verifies Physical Network Interface Enumeration, Device Binding,
 * Natural Language to Wireshark AST Compilation, and Bayesian Packet Explainer.
 */

'use strict';

const assert = require('assert');
const { packetStreamer } = require('../src/network/packet-streaming/packet-streamer');
const { PacketExplainEngine } = require('../src/network/packet-decoding/packet-explain-engine');
const { validateFilter } = require('../src/network/packet-decoding/filter-compiler');

async function runWiresharkAiWorkstationTests() {
  console.log('\n--- Running Wireshark AI Workstation & Dissector Suite ---');

  // Test 1: Network Capture Interface Enumeration
  console.log('Testing Network Capture Interface Enumeration...');
  const interfaces = packetStreamer.getCaptureInterfaces();
  assert.ok(Array.isArray(interfaces), 'Interfaces must be an array');
  assert.ok(interfaces.length >= 2, 'Must discover at least physical and loopback adapters');
  const physicalNic = interfaces.find(i => i.isPhysical);
  assert.ok(physicalNic, 'Must identify at least one physical network interface');
  const loopbackNic = interfaces.find(i => i.name === '\\Device\\NPF_Loopback' || i.alias === 'Loopback');
  assert.ok(loopbackNic, 'Must identify loopback capture adapter');
  console.log(`✓ Interfaces Enumerated (${interfaces.length} devices found, Active Physical: ${physicalNic.description})`);

  // Test 2: Dynamic Interface Device Binding
  console.log('Testing Interface Device Binding & Switching...');
  const originalDevice = packetStreamer.selectedDevice;
  const switchRes = packetStreamer.setCaptureDevice(physicalNic.name);
  assert.strictEqual(switchRes.success, true, 'setCaptureDevice must return success');
  assert.strictEqual(packetStreamer.selectedDevice, physicalNic.name, 'selectedDevice must match physical NIC');
  // Revert device
  packetStreamer.setCaptureDevice(originalDevice);
  console.log('✓ Interface Device Binding verified successfully.');

  // Test 3: Natural Language to Wireshark AST Filter Compiler
  console.log('Testing Natural Language to Wireshark AST Filter Compiler...');
  const testQueries = [
    {
      nl: 'show all tcp resets to 192.168.31.1',
      expectedSub: 'tcp.flags.reset == 1',
      expectedIp: '192.168.31.1'
    },
    {
      nl: 'retransmissions',
      expectedSub: 'tcp.analysis.retransmission'
    },
    {
      nl: 'tls handshakes',
      expectedSub: 'tls.handshake.type == 1'
    },
    {
      nl: 'dns queries',
      expectedSub: 'dns.flags.response == 0'
    },
    {
      nl: 'http errors 400 or higher',
      expectedSub: 'http.response.code >= 400'
    },
    {
      nl: 'quic traffic',
      expectedSub: 'quic'
    },
    {
      nl: 'zero window',
      expectedSub: 'tcp.window_size == 0'
    }
  ];

  for (const q of testQueries) {
    const res = packetStreamer.translateNaturalLanguageToFilter(q.nl);
    assert.strictEqual(res.success, true, `Query "${q.nl}" must succeed`);
    assert.strictEqual(res.valid, true, `Query "${q.nl}" must produce valid Wireshark AST: ${res.filter}`);
    assert.ok(res.filter.includes(q.expectedSub), `Filter must contain ${q.expectedSub}, got: ${res.filter}`);
    if (q.expectedIp) {
      assert.ok(res.filter.includes(q.expectedIp), `Filter must contain IP ${q.expectedIp}`);
    }
    // Cross-validate with independent AST compiler
    const astCheck = validateFilter(res.filter);
    assert.strictEqual(astCheck.valid, true, `AST compiler must accept generated filter: ${res.filter}`);
  }
  console.log(`✓ All ${testQueries.length} Natural Language queries compiled into valid Wireshark AST.`);

  // Test 4: Bayesian AI Packet Explainer on TCP RST Frame
  console.log('Testing AI Packet Explainer on TCP RST Packet...');
  const rstFrame = {
    frameNumber: 42,
    timestamp: '2026-10-17T12:00:00.000Z',
    wireLength: 60,
    protocol: 'TCP',
    srcIp: '192.168.31.89',
    dstIp: '192.168.31.1',
    srcPort: 58210,
    dstPort: 443,
    ethernet: {
      srcMac: '70:15:fb:6b:f3:46',
      dstMac: '50:64:2b:4b:dd:31',
      ethertype: '0x0800'
    },
    ipv4: {
      version: 4,
      ihl: 20,
      ttl: 64,
      identification: 12345,
      flags: { df: true, mf: false },
      checksum: '0x1a2b',
      srcIp: '192.168.31.89',
      dstIp: '192.168.31.1'
    },
    tcp: {
      srcPort: 58210,
      dstPort: 443,
      seq: 1000,
      ack: 0,
      flags: { rst: true },
      flagNames: ['RST'],
      windowSize: 0,
      checksum: '0x3c4d'
    }
  };

  const rstExplanation = PacketExplainEngine.explain(rstFrame);
  assert.strictEqual(rstExplanation.success, true);
  assert.strictEqual(rstExplanation.severity, 'CRITICAL', 'RST + Zero Window must be CRITICAL severity');
  assert.ok(rstExplanation.plainEnglish.includes('TCP Hard Reset'), 'Must explain TCP reset in plain English');
  assert.ok(rstExplanation.anomalies.some(a => a.type === 'TCP_RST_TERMINATION'), 'Must detect TCP_RST_TERMINATION');
  assert.ok(rstExplanation.anomalies.some(a => a.type === 'TCP_ZERO_WINDOW'), 'Must detect TCP_ZERO_WINDOW');
  assert.ok(rstExplanation.recommendedFilter.includes('tcp.port == 443'), 'Must provide scoped isolation filter');
  assert.ok(rstExplanation.remediation.length >= 2, 'Must provide concrete remediation steps');
  console.log(`✓ AI Explainer on TCP RST passed: Severity=${rstExplanation.severity}, Anomalies=${rstExplanation.anomalies.length}`);

  // Test 5: AI Packet Explainer on TLS ClientHello Frame
  console.log('Testing AI Packet Explainer on TLS ClientHello Frame...');
  const tlsFrame = {
    frameNumber: 43,
    timestamp: '2026-10-17T12:00:01.000Z',
    wireLength: 512,
    protocol: 'TLS',
    srcIp: '192.168.31.89',
    dstIp: '142.251.142.110',
    srcPort: 52100,
    dstPort: 443,
    ethernet: {
      srcMac: '70:15:fb:6b:f3:46',
      dstMac: '50:64:2b:4b:dd:31',
      ethertype: '0x0800'
    },
    ipv4: {
      version: 4,
      ihl: 20,
      ttl: 64,
      srcIp: '192.168.31.89',
      dstIp: '142.251.142.110'
    },
    tcp: {
      srcPort: 52100,
      dstPort: 443,
      seq: 2000,
      ack: 1000,
      flags: { ack: true, psh: true },
      flagNames: ['ACK', 'PSH'],
      windowSize: 64240
    },
    tls: {
      version: 'TLSv1.3',
      contentType: 'Handshake (ClientHello)',
      sni: 'taxes.gov.az',
      cipherSuite: 'TLS_AES_256_GCM_SHA384'
    }
  };

  const tlsExplanation = PacketExplainEngine.explain(tlsFrame);
  assert.strictEqual(tlsExplanation.success, true);
  assert.strictEqual(tlsExplanation.severity, 'NOMINAL', 'Valid TLS ClientHello must be NOMINAL severity');
  assert.ok(tlsExplanation.plainEnglish.includes('taxes.gov.az'), 'Must identify SNI target host');
  assert.ok(tlsExplanation.rfcStandards.some(s => s.includes('RFC 8446')), 'Must reference RFC 8446');
  console.log(`✓ AI Explainer on TLS passed: Target=${tlsExplanation.endpoints.resolvedTarget || 'taxes.gov.az'}, RFC=${tlsExplanation.rfcStandards.join(', ')}`);

  console.log('--- Wireshark AI Workstation & Dissector Suite PASSED ---\n');
}

if (require.main === module) {
  runWiresharkAiWorkstationTests().catch((err) => {
    console.error('Wireshark AI Workstation Tests FAILED:', err);
    process.exit(1);
  });
}

module.exports = { runWiresharkAiWorkstationTests };
