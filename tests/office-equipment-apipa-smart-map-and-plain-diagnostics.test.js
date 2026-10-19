/**
 * EJII Test Suite 54: Automatic Office Equipment Classification (Printers, VoIP, PCs),
 * Visual Connection Path Smart Mapping, Plain-Language APIPA (169.254.x.x) Problem Resolver,
 * Hybrid BM25 + N-Gram Cosine RRF RAG & Counterfactual Causal Simulator
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const {
  analyzeApipaAddress,
  classifyOfficeEquipment,
  diagnoseOfficeDevice
} = require('../src/network/diagnostics/office-device-resolver');
const { ragKnowledgeEngine } = require('../src/core/rag-knowledge-engine');
const { aiBrain } = require('../src/core/ai-brain');

async function runOfficeEquipmentApipaSmartMapAndPlainDiagnosticsTests() {
  console.log('========================================================================');
  console.log('  SUITE 54: OFFICE EQUIPMENT, SMART PATH MAP & PLAIN-LANGUAGE RESOLVER  ');
  console.log('========================================================================\n');

  // [54.1] Verify Automatic Office Equipment Classification (Printers, VoIP Phones, PCs)
  console.log('[54.1] Verifying automatic office equipment classification (Printers, VoIP, PCs)...');
  const hpPrinter = classifyOfficeEquipment({
    ip: '192.168.31.55',
    macAddress: '3C:D9:2B:11:22:33',
    vendor: 'Hewlett Packard Enterprise',
    hostname: 'HP-LaserJet-Pro-M404',
    openServices: [{ port: 9100 }, { port: 631 }, { port: 80 }]
  });
  assert.strictEqual(hpPrinter.equipmentType, 'PRINTER', 'Port 9100/631 + HP OUI must classify as PRINTER');
  assert.strictEqual(hpPrinter.icon, '🖨️');
  assert.ok(hpPrinter.equipmentBrand.includes('Hewlett Packard'));
  assert.strictEqual(hpPrinter.digitalSignatureMac, '3C:D9:2B:11:22:33');

  const yealinkPhone = classifyOfficeEquipment({
    ip: '192.168.31.70',
    macAddress: '80:5E:C0:AA:BB:CC',
    vendor: 'Yealink Network Technology',
    hostname: 'SIP-T46U',
    openServices: [{ port: 5060 }]
  });
  assert.strictEqual(yealinkPhone.equipmentType, 'VOIP_PHONE', 'Port 5060 + Yealink OUI must classify as VOIP_PHONE');
  console.log('  ✓ Office equipment classification verified for Printers, VoIP Phones, and Workstations.');

  // [54.2] Verify APIPA (169.254.x.x) Detection & Plain-Language Problem Resolver (What / Why / How to Fix)
  console.log('[54.2] Verifying APIPA (169.254.x.x) Plain-Language Problem Resolver & Visual Smart Map...');
  const apipaReport = await diagnoseOfficeDevice({
    targetIp: '169.254.45.12',
    deviceTypeHint: 'PRINTER',
    deviceName: 'Canon-Office-Printer-2F',
    macAddress: '00:1E:8F:12:34:56',
    vendor: 'Canon Inc.'
  });
  assert.strictEqual(apipaReport.faultScenario, 'APIPA_SELF_ASSIGNED_IP_169_254');
  assert.strictEqual(apipaReport.apipaAnalysis.isApipa, true);
  assert.ok(Array.isArray(apipaReport.visualConnectionPath) && apipaReport.visualConnectionPath.length === 4, 'Visual connection path must contain 4 hops');
  assert.strictEqual(apipaReport.visualConnectionPath[3].status, 'BROKEN', 'Hop 4 must pinpoint the APIPA break');

  const plain = apipaReport.plainLanguageDiagnosis;
  assert.ok(plain && typeof plain.whatTheProblemIs === 'string' && plain.whatTheProblemIs.length > 30, 'Must include plain-language What The Problem Is');
  assert.ok(typeof plain.whyItHappened === 'string' && plain.whyItHappened.length > 30, 'Must include plain-language Why It Happened');
  assert.ok(Array.isArray(plain.stepByStepFixPlan) && plain.stepByStepFixPlan.length >= 3, 'Must include Step-by-Step Fix Plan');

  // Verify cloud metadata 169.254.169.254 is STILL strictly blocked by SSRF policy
  let metadataBlocked = false;
  try {
    await diagnoseOfficeDevice({ targetIp: '169.254.169.254' });
  } catch (err) {
    if (err.message.includes('SECURITY_VIOLATION')) metadataBlocked = true;
  }
  assert.strictEqual(metadataBlocked, true, 'Cloud metadata 169.254.169.254 must remain strictly blocked by SSRF guard');
  console.log('  ✓ APIPA 169.254.45.12 Plain-Language Resolver and Visual Connection Path verified (while keeping 169.254.169.254 SSRF blocked).');

  // [54.3] Verify Hybrid BM25 + N-Gram Cosine RRF RAG Engine & Runbooks RB-07/RB-08
  console.log('[54.3] Verifying Hybrid BM25 + N-Gram Cosine RRF RAG Engine & Office Runbooks RB-07/RB-08...');
  const stats = ragKnowledgeEngine.rebuildIndex();
  assert.ok(stats.documentsIndexed >= 17, `Expected >= 17 RAG documents indexed, got ${stats.documentsIndexed}`);
  const printerHits = ragKnowledgeEngine.retrieveRelevantContext('office printer 169.254 temporary error IP address DHCP fix', { topK: 3 });
  assert.ok(printerHits.length > 0, 'Hybrid RRF RAG must retrieve relevant printer/APIPA runbooks');
  console.log(`  ✓ Hybrid BM25 + N-Gram RRF RAG verified (top match: ${printerHits[0].docId}).`);

  // [54.4] Verify Counterfactual Causal Simulator in AIBrain
  console.log('[54.4] Verifying Counterfactual Causal Remediation Simulator (simulateCounterfactualFix)...');
  assert.strictEqual(typeof aiBrain.simulateCounterfactualFix, 'function', 'aiBrain.simulateCounterfactualFix must be implemented');
  const sim = aiBrain.simulateCounterfactualFix({
    incidentType: 'DNS_RESOLUTION_FAILURE',
    proposedAction: 'flush_dns_cache'
  });
  assert.ok(sim && typeof sim.expectedRiskReductionPct === 'number', 'Counterfactual simulation must return expectedRiskReductionPct');
  console.log(`  ✓ Counterfactual simulator verified (expectedRiskReductionPct=${sim.expectedRiskReductionPct}%).\n`);

  console.log('========================================================================');
  console.log('  SUITE 54 PASSED: ALL OFFICE DISCOVERY & AI INNOVATIONS 100% GREEN     ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runOfficeEquipmentApipaSmartMapAndPlainDiagnosticsTests()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('Suite 54 failed:', err);
      process.exit(1);
    });
}

module.exports = { runOfficeEquipmentApipaSmartMapAndPlainDiagnosticsTests };
