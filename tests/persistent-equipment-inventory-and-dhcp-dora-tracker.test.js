/**
 * EJII Test Suite 57: Persistent Office Equipment Inventory & DHCP (DORA) Event Tracker
 * 
 * Verifies:
 * [57.1] Transactional SQLite Schema Migrations & Table Integrity
 * [57.2] Equipment Inventory Upsert & Automatic APIPA Regression Detection
 * [57.3] DHCP DORA Wire Event Recording & Time-Ordered Event Auditing
 * [57.4] Inventory Filtering & Summary KPI Aggregation
 * [57.5] Local Windows Print Spooler Inspector & WSD Port Advisory
 */

'use strict';

const assert = require('assert');
const { db } = require('../src/db/database');
const { equipmentInventoryRepository } = require('../src/db/equipment-inventory-repository');
const { inspectLocalWindowsPrintSpooler } = require('../src/network/diagnostics/office-device-resolver');

async function runPersistentEquipmentInventoryAndDhcpDoraTrackerTests() {
  console.log('========================================================================');
  console.log('  SUITE 57: PERSISTENT OFFICE EQUIPMENT INVENTORY & DHCP DORA TRACKER    ');
  console.log('  WAL-Backed Inventory, APIPA Regression Guard & Spooler Telemetry      ');
  console.log('========================================================================\n');

  // [57.1] Verify Schema Tables Exist
  console.log('[57.1] Verifying office_equipment_inventory and dhcp_and_ip_events schema...');
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('office_equipment_inventory', 'dhcp_and_ip_events', 'schema_migrations')").all();
  const tableNames = tables.map(t => t.name);
  assert.ok(tableNames.includes('office_equipment_inventory'), 'office_equipment_inventory table must exist');
  assert.ok(tableNames.includes('dhcp_and_ip_events'), 'dhcp_and_ip_events table must exist');
  assert.ok(tableNames.includes('schema_migrations'), 'schema_migrations table must exist');
  console.log('  ✓ Database schema verified with WAL-backed persistent tables.');

  // [57.2] Verify Equipment Record Upsert & APIPA Regression Detection
  console.log('[57.2] Testing equipment upsert and automatic APIPA regression tracking...');
  const testMac = '3C:D9:2B:11:22:33';
  const goodIp = '192.168.31.50';

  // 1. Initial healthy lease
  const rec1 = equipmentInventoryRepository.upsertEquipmentRecord({
    macAddress: testMac,
    currentIp: goodIp,
    hostname: 'HP-ColorLaserJet-PRO',
    equipmentType: 'PRINTER',
    equipmentBrand: 'HP Inc.',
    openPorts: '9100,631,80',
    source: 'TEST_SUITE_57'
  });

  assert.strictEqual(rec1.mac_address, testMac);
  assert.strictEqual(rec1.current_ip, goodIp);
  assert.strictEqual(rec1.last_known_good_ip, goodIp);
  assert.strictEqual(rec1.is_apipa, 0);

  // 2. Fault: Device falls back to APIPA (169.254.45.67) due to DHCP scope exhaustion
  const apipaIp = '169.254.45.67';
  const rec2 = equipmentInventoryRepository.upsertEquipmentRecord({
    macAddress: testMac,
    currentIp: apipaIp,
    source: 'PASSIVE_WIRE_ARP'
  });

  assert.strictEqual(rec2.current_ip, apipaIp);
  assert.strictEqual(rec2.is_apipa, 1, 'is_apipa must be set to 1');
  assert.strictEqual(rec2.last_known_good_ip, goodIp, 'last_known_good_ip must be preserved when falling back to APIPA');
  assert.ok(rec2.apipa_reverted_count >= 1, 'apipa_reverted_count must increment');
  console.log(`  ✓ APIPA regression detected: Current=${rec2.current_ip}, Preserved Last Good=${rec2.last_known_good_ip}, RevertedCount=${rec2.apipa_reverted_count}`);

  // [57.3] Verify DHCP DORA Event Recording
  console.log('[57.3] Testing DHCP DORA frame event logging...');
  equipmentInventoryRepository.recordDhcpOrIpEvent({
    eventType: 'DHCP DISCOVER',
    clientMac: testMac,
    hostname: 'HP-ColorLaserJet-PRO',
    serverIp: '0.0.0.0',
    details: 'Broadcast discovery from office printer'
  });

  equipmentInventoryRepository.recordDhcpOrIpEvent({
    eventType: 'DHCP ACK',
    clientMac: testMac,
    offeredIp: goodIp,
    serverIp: '192.168.31.1',
    hostname: 'HP-ColorLaserJet-PRO',
    details: 'Lease assigned for 86400s'
  });

  const recentEvents = equipmentInventoryRepository.getRecentDhcpEvents(10);
  assert.ok(Array.isArray(recentEvents) && recentEvents.length >= 2, 'Must return logged DHCP events');
  const hasAck = recentEvents.some(e => e.event_type === 'DHCP ACK' && (e.mac_address === testMac || e.client_mac === testMac));
  assert.ok(hasAck, 'Recent events must include the recorded DHCP ACK');
  console.log(`  ✓ DHCP event logging verified: ${recentEvents.length} recent events retrieved.`);

  // [57.4] Verify Equipment Summary Counts & Filtered Inventory
  console.log('[57.4] Testing inventory summary KPIs and type filtering...');
  const summary = equipmentInventoryRepository.getEquipmentSummaryCounts();
  assert.ok(summary.totalCount >= 1, 'Total equipment count must be >= 1');
  assert.ok(summary.apipaCount >= 1, 'APIPA count must be >= 1');
  assert.ok(typeof summary.printersCount === 'number');

  const printers = equipmentInventoryRepository.getInventory({ equipmentType: 'PRINTER' });
  assert.ok(Array.isArray(printers) && printers.length >= 1, 'Must find at least 1 printer in inventory');
  assert.strictEqual(printers[0].mac_address, testMac);
  console.log(`  ✓ Inventory KPIs verified: Total=${summary.totalCount}, APIPA=${summary.apipaCount}, Printers=${summary.printersCount}`);

  // [57.5] Verify Local Windows Print Spooler Inspector
  console.log('[57.5] Testing local Windows Print Spooler inspector...');
  const spoolerReport = await inspectLocalWindowsPrintSpooler(3500);
  assert.ok(spoolerReport, 'Spooler report must be returned');
  assert.ok(typeof spoolerReport.spoolerServiceStatus === 'string', 'spoolerServiceStatus must be string');
  assert.ok(Array.isArray(spoolerReport.printers), 'printers must be an array');
  assert.ok(Array.isArray(spoolerReport.ports), 'ports must be an array');
  assert.ok(typeof spoolerReport.stuckJobsCount === 'number', 'stuckJobsCount must be number');
  assert.ok(typeof spoolerReport.wsdPortWarning === 'boolean', 'wsdPortWarning must be boolean');
  assert.ok(typeof spoolerReport.plainSummary === 'string', 'plainSummary must be string');
  console.log(`  ✓ Spooler inspector executed: Status=${spoolerReport.spoolerServiceStatus}, Printers=${spoolerReport.printers.length}, StuckJobs=${spoolerReport.stuckJobsCount}, WSDWarning=${spoolerReport.wsdPortWarning}`);

  console.log('\n>>> ALL SUITE 57 PERSISTENT EQUIPMENT INVENTORY & DHCP TRACKER TESTS PASSED 100% GREEN.\n');
}

if (require.main === module) {
  runPersistentEquipmentInventoryAndDhcpDoraTrackerTests().then(() => {
    process.exit(0);
  }).catch((err) => {
    console.error('Suite 57 failed:', err);
    process.exit(1);
  });
}

module.exports = {
  runPersistentEquipmentInventoryAndDhcpDoraTrackerTests,
  runSuite57: runPersistentEquipmentInventoryAndDhcpDoraTrackerTests
};
