// tests/suite-92-multipath-dscp-ecn-qos-auditor.test.js
/**
 * EJII Test Suite 92: Multi-Path DSCP / ECN QoS Auditor & Path MTU Analyzer
 * Verifies 8-bit TOS decoding into 6-bit DSCP & 2-bit ECN (RFC 3168), Expedited Forwarding (EF),
 * QoS bleaching detection, PMTU DF-bit fragmentation hazards, and the /api/network/qos-dscp-audit endpoint.
 */

'use strict';

const assert = require('node:assert/strict');
const { MultipathQosAuditor } = require('../src/topology/multipath-qos-auditor');
const routesNetwork = require('../src/api/routes-network');

async function runSuite92MultipathQosAuditor() {
  console.log('========================================================================');
  console.log('  === [SUITE 92] MULTIPATH DSCP / ECN QOS & PMTU AUDITOR ===            ');
  console.log('========================================================================\n');

  // [92.1] 8-Bit TOS Decoding into 6-Bit DSCP and 2-Bit ECN
  console.log('[Test 92.1] Decoding standard and specialized TOS byte combinations...');
  // Default Best Effort (CS0) without ECN: TOS = 0x00
  const tosBestEffort = MultipathQosAuditor.decodeTosByte(0x00);
  assert.ok(tosBestEffort.dscp.name.includes('CS0'), 'DSCP must be CS0');
  assert.strictEqual(tosBestEffort.dscp.dscpValue, 0);
  assert.strictEqual(tosBestEffort.ecn.code, 'NOT_ECT');
  assert.strictEqual(tosBestEffort.ecn.isCongested, false);
  console.log(`  ✓ CS0 (Best Effort) decoded: DSCP=${tosBestEffort.dscp.name}, ECN=${tosBestEffort.ecn.code}`);

  // Expedited Forwarding (EF 46) with RFC 3168 CE (Congestion Experienced: bits 11 = 0x03)
  // TOS = (46 << 2) | 3 = 184 | 3 = 187 (0xBB)
  const tosEfCongested = MultipathQosAuditor.decodeTosByte(0xbb);
  assert.strictEqual(tosEfCongested.dscp.dscpValue, 46);
  assert.ok(tosEfCongested.dscp.name.includes('EF'), 'DSCP must be EF');
  assert.strictEqual(tosEfCongested.dscp.category, 'EXPEDITED_FORWARDING');
  assert.strictEqual(tosEfCongested.ecn.code, 'CE');
  assert.strictEqual(tosEfCongested.ecn.isCongested, true);
  console.log(`  ✓ EF (Telephony 46) with ECN CE decoded: DSCP=${tosEfCongested.dscp.name}, ECN=${tosEfCongested.ecn.code} (Congested=true)`);

  // Assured Forwarding AF41 (34) with ECT(0): TOS = (34 << 2) | 2 = 136 | 2 = 138 (0x8A)
  const tosAf41 = MultipathQosAuditor.decodeTosByte(0x8a);
  assert.strictEqual(tosAf41.dscp.dscpValue, 34);
  assert.ok(tosAf41.dscp.name.includes('AF41'), 'DSCP must be AF41');
  assert.strictEqual(tosAf41.ecn.code, 'ECT_0');
  console.log(`  ✓ AF41 with ECT(0) decoded: DSCP=${tosAf41.dscp.name}, ECN=${tosAf41.ecn.code}`);

  // [92.2] QoS Bleaching Detection (Voice Stream Remarked to CS0)
  console.log('[Test 92.2] Detecting downstream QoS bleaching of real-time RTP traffic...');
  const wireSample = [
    // Legit EF frame on VoIP port 5060
    { tos: 46 << 2, length: 128, dfBit: false, srcPort: 5060, dstPort: 5060, srcIp: '10.1.1.5', dstIp: '10.1.1.20' },
    // Bleached VoIP frame (Port 5060 arriving with TOS 0)
    { tos: 0, length: 128, dfBit: false, srcPort: 5060, dstPort: 5060, srcIp: '10.1.1.5', dstIp: '10.1.1.20' },
    // ECN Congestion Experience frame
    { tos: (26 << 2) | 3, length: 64, dfBit: true, srcPort: 443, dstPort: 51200, srcIp: '1.1.1.1', dstIp: '10.1.1.20' },
    // Jumbo MTU hazard: 1514 bytes with DF bit set
    { tos: 0, length: 1514, dfBit: true, srcPort: 80, dstPort: 51201, srcIp: '10.1.1.1', dstIp: '10.1.1.20' }
  ];

  const report = MultipathQosAuditor.auditWireFrames(wireSample);
  assert.ok(report, 'Audit report must be generated');
  assert.strictEqual(report.totalPacketsAudited, 4);
  assert.strictEqual(report.ecnDistribution['CE'], 1, 'Must count 1 Congestion Experienced frame');
  assert.strictEqual(report.activeEcnCongestionCount, 1);
  assert.ok(Array.isArray(report.violations), 'Violations must be an array');
  const bleachingViolation = report.violations.find(v => v.type === 'QOS_BLEACHING');
  assert.ok(bleachingViolation, 'Must flag QoS bleaching when SIP/RTP has TOS 0');
  console.log(`  ✓ QoS Bleaching flagged: type=${bleachingViolation.type}, desc=${bleachingViolation.description}`);

  // [92.3] Path MTU (PMTU) DF-Bit Fragmentation Hazards
  console.log('[Test 92.3] Auditing PMTU DF-bit fragmentation hazards for frames > 1500 bytes...');
  assert.ok(report.pmtuDistribution.pmtuRiskCount >= 1, 'Must detect PMTU hazard frame');
  const pmtuViolation = report.violations.find(v => v.type === 'PMTU_FRAGMENTATION_RISK');
  assert.ok(pmtuViolation, 'Must flag PMTU risk in violations');
  console.log(`  ✓ PMTU DF-bit fragmentation hazard detected for frame with length 1514: ${pmtuViolation.description}`);

  // [92.4] REST API Endpoint: GET /api/network/qos-dscp-audit
  console.log('[Test 92.4] Testing GET /api/network/qos-dscp-audit via Express router stack...');
  const qosLayer = routesNetwork.stack.find(s => s.route && s.route.path === '/qos-dscp-audit');
  assert.ok(qosLayer, 'Route GET /qos-dscp-audit must exist in routes-network.js');

  let qosJson = null;
  const mockReq = { query: {} };
  const mockRes = {
    statusCode: 200,
    status(c) { this.statusCode = c; return this; },
    json(d) { qosJson = d; return this; }
  };
  const handler = qosLayer.route.stack[qosLayer.route.stack.length - 1].handle;
  handler(mockReq, mockRes, () => {});

  assert.ok(qosJson, 'Route must respond with JSON');
  assert.strictEqual(qosJson.success, true);
  assert.ok(qosJson.totalPacketsAudited >= 4);
  assert.ok(qosJson.dscpDistribution, 'dscpDistribution must be returned');
  assert.ok(qosJson.ecnDistribution, 'ecnDistribution must be returned');
  console.log(`  ✓ GET /api/network/qos-dscp-audit returned 200 OK: ${qosJson.totalPacketsAudited} frames audited, CE count=${qosJson.ecnDistribution.CE}`);

  console.log('\n========================================================================');
  console.log('  SUITE 92 PASSED: MULTIPATH DSCP / ECN QOS AUDITOR 100% GREEN          ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runSuite92MultipathQosAuditor().catch((err) => {
    console.error('Suite 92 failed:', err);
    process.exit(1);
  });
}

module.exports = {
  runSuite92MultipathQosAuditor,
  runSuite92: runSuite92MultipathQosAuditor
};
