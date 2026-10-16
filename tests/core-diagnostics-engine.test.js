/**
 * Test Suite 24: Core Diagnostics Engine & 4-Pillar Host Ingestion Test Suite
 * Verifies real hardware telemetry collection, CIM/PowerShell parsing,
 * 4-pillar health aggregation, process/socket tables, and AI Brain health synthesis.
 */

'use strict';

const assert = require('node:assert/strict');
const { hostDiagnosticsEngine } = require('../src/systems/diagnostics/host-diagnostics-engine');
const { aiBrain } = require('../src/core/ai-brain');

async function runCoreDiagnosticsEngineTests() {
  console.log('\n========================================================================');
  console.log('  SUITE 24: CORE DIAGNOSTICS & 4-PILLAR HARDWARE INGESTION SUITE       ');
  console.log('  Real Host Telemetry, WMI/CIM Ingestion & AI Brain Health Synthesis   ');
  console.log('========================================================================');

  // 1. Pillar 1: Network & Connectivity Layer
  console.log('[24.1] Testing Pillar 1: Network & Connectivity Layer ingestion...');
  const netPillar = await hostDiagnosticsEngine.collectNetworkPillar();
  assert.ok(netPillar, 'Network pillar must be returned');
  assert.ok(['HEALTHY', 'DEGRADED', 'CRITICAL'].includes(netPillar.status), `Status must be valid pillar status, got: ${netPillar.status}`);
  assert.ok(Array.isArray(netPillar.details.adapters), 'Adapters must be an array');
  assert.ok(netPillar.details.socketCounts, 'Socket counts must exist');
  assert.ok(typeof netPillar.details.socketCounts.ESTABLISHED === 'number');
  assert.ok(typeof netPillar.details.socketCounts.LISTEN === 'number');
  assert.ok(typeof netPillar.summary === 'string');
  console.log(`  ✓ Network Pillar verified: ${netPillar.status} (${netPillar.details.adapters.length} adapters, ${netPillar.details.socketCounts.ESTABLISHED} established sockets).`);

  // 2. Pillar 2: Storage & File System Integrity
  console.log('[24.2] Testing Pillar 2: Storage, Volumes & SMART status...');
  const storagePillar = await hostDiagnosticsEngine.collectStoragePillar();
  assert.ok(storagePillar, 'Storage pillar must be returned');
  assert.ok(['HEALTHY', 'DEGRADED', 'CRITICAL'].includes(storagePillar.status));
  assert.ok(Array.isArray(storagePillar.details.volumes), 'Volumes must be an array');
  assert.ok(typeof storagePillar.details.smartStatus === 'string');
  if (storagePillar.details.volumes.length > 0) {
    const v0 = storagePillar.details.volumes[0];
    assert.ok(v0.DriveLetter, 'Volume must have DriveLetter');
    assert.ok(typeof v0.SizeGB === 'number');
    assert.ok(typeof v0.FreeGB === 'number');
  }
  console.log(`  ✓ Storage Pillar verified: ${storagePillar.status} (${storagePillar.details.volumes.length} volume(s), SMART: ${storagePillar.details.smartStatus}).`);

  // 3. Pillar 3: Resource Allocation & Supercharged Task Manager
  console.log('[24.3] Testing Pillar 3: Resource Allocation & Process Explorer...');
  const resPillar = await hostDiagnosticsEngine.collectResourcePillar();
  assert.ok(resPillar, 'Resource pillar must be returned');
  assert.ok(['HEALTHY', 'DEGRADED', 'CRITICAL'].includes(resPillar.status));
  assert.ok(resPillar.details.cores > 0, 'Must have at least 1 CPU core');
  assert.ok(resPillar.details.totalRamGB > 0, 'Total RAM must be > 0 GB');
  assert.ok(typeof resPillar.details.cpuLoadPct === 'number');
  assert.ok(typeof resPillar.details.ramUsedPct === 'number');
  assert.ok(Array.isArray(resPillar.details.topProcesses), 'Top processes must be an array');
  console.log(`  ✓ Resource Pillar verified: ${resPillar.status} (CPU: ${resPillar.details.cpuLoadPct}%, RAM: ${resPillar.details.ramUsedPct}% of ${resPillar.details.totalRamGB} GB, ${resPillar.details.topProcesses.length} processes).`);

  // 4. Pillar 4: Peripherals, Subsystems & Drivers
  console.log('[24.4] Testing Pillar 4: Peripherals & Drivers...');
  const periphPillar = await hostDiagnosticsEngine.collectPeripheralsPillar();
  assert.ok(periphPillar, 'Peripherals pillar must be returned');
  assert.ok(['HEALTHY', 'DEGRADED', 'CRITICAL'].includes(periphPillar.status));
  assert.ok(Array.isArray(periphPillar.details.degradedDevices));
  assert.ok(typeof periphPillar.details.spoolerStatus === 'string');
  console.log(`  ✓ Peripherals Pillar verified: ${periphPillar.status} (Spooler: ${periphPillar.details.spoolerStatus}, Degraded PnP: ${periphPillar.details.degradedDevices.length}).`);

  // 5. Full 4-Pillar System Audit Aggregation
  console.log('[24.5] Testing Full 4-Pillar System Audit Aggregation...');
  const fullAudit = await hostDiagnosticsEngine.runFullSystemAudit(true);
  assert.ok(fullAudit.timestamp);
  assert.ok(fullAudit.durationMs >= 0);
  assert.ok(fullAudit.host.hostname);
  assert.ok(fullAudit.pillars.network);
  assert.ok(fullAudit.pillars.storage);
  assert.ok(fullAudit.pillars.resource);
  assert.ok(fullAudit.pillars.peripherals);
  assert.ok(Array.isArray(fullAudit.anomalies));
  assert.ok(Array.isArray(fullAudit.stagedRecipes));
  console.log(`  ✓ Full Audit completed in ${fullAudit.durationMs}ms: Overall Status ${fullAudit.overallStatus}, ${fullAudit.anomalies.length} anomalies, ${fullAudit.stagedRecipes.length} staged recipes.`);

  // 6. AI Brain Health Synthesis Integration
  console.log('[24.6] Testing AI Brain Health Synthesis Integration...');
  const synthesis = aiBrain.evaluateHostHealth(fullAudit);
  assert.ok(synthesis, 'Synthesis must be generated');
  assert.strictEqual(synthesis.overallStatus, fullAudit.overallStatus);
  assert.ok(typeof synthesis.summary === 'string');
  assert.ok(typeof synthesis.plainEnglishReport === 'string');
  assert.ok(typeof synthesis.recommendedAction === 'string');
  console.log(`  ✓ AI Brain Synthesis: "${synthesis.summary}" -> Action: [${synthesis.recommendedAction}]`);

  // 7. Process & Socket Detailed Queries
  console.log('[24.7] Testing Detailed Process & Socket Tables...');
  const procs = await hostDiagnosticsEngine.getProcessTable();
  const sockets = await hostDiagnosticsEngine.getSocketTable();
  assert.ok(Array.isArray(procs));
  assert.ok(Array.isArray(sockets));
  if (procs.length > 0) {
    assert.ok(procs[0].pid != null);
    assert.ok(procs[0].name);
  }
  console.log(`  ✓ Process Explorer table: ${procs.length} procs; Socket matrix: ${sockets.length} active sockets.`);

  console.log('\n>>> ALL SUITE 24 CORE DIAGNOSTICS ENGINE TESTS PASSED (ZERO DEFECTS).\n');
}

if (require.main === module) {
  runCoreDiagnosticsEngineTests().catch((err) => {
    console.error('Suite 24 failed:', err);
    process.exit(1);
  });
}

module.exports = { runCoreDiagnosticsEngineTests };
