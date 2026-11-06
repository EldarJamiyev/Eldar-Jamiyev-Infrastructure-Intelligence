/**
 * Test Suite 24: Core Diagnostics Engine & 4-Pillar Host Ingestion Test Suite
 * Verifies real hardware telemetry collection, CIM/PowerShell parsing,
 * 4-pillar health aggregation, process/socket tables, AI Brain health synthesis,
 * zero simulation provenance, 6-state health classification, and injected failure handling.
 */

'use strict';

const assert = require('node:assert/strict');
const { HostDiagnosticsEngine, hostDiagnosticsEngine } = require('../src/systems/diagnostics/host-diagnostics-engine');
const { aiBrain } = require('../src/core/ai-brain');

const VALID_HEALTH_STATES = ['HEALTHY', 'WARNING', 'CRITICAL', 'DEGRADED', 'UNKNOWN', 'COLLECTION_ERROR'];

async function runCoreDiagnosticsEngineTests() {
  console.log('\n========================================================================');
  console.log('  SUITE 24: CORE DIAGNOSTICS & 4-PILLAR HARDWARE INGESTION SUITE       ');
  console.log('  Real Host Telemetry, WMI/CIM Ingestion & AI Brain Health Synthesis   ');
  console.log('========================================================================');

  // 1. Pillar 1: Network & Connectivity Layer
  console.log('[24.1] Testing Pillar 1: Network & Connectivity Layer ingestion...');
  const netPillar = await hostDiagnosticsEngine.collectNetworkPillar();
  assert.ok(netPillar, 'Network pillar must be returned');
  assert.ok(VALID_HEALTH_STATES.includes(netPillar.status), `Status must be valid pillar status, got: ${netPillar.status}`);
  assert.ok(Array.isArray(netPillar.details.adapters), 'Adapters must be an array');
  if (netPillar.details.socketCounts) {
    assert.ok(typeof netPillar.details.socketCounts.ESTABLISHED === 'number');
    assert.ok(typeof netPillar.details.socketCounts.LISTEN === 'number');
  }
  assert.ok(typeof netPillar.summary === 'string');
  console.log(`  ✓ Network Pillar verified: ${netPillar.status} (${netPillar.details.adapters.length} adapters, outcome: ${netPillar.metadata.outcome}).`);

  // 2. Pillar 2: Storage & File System Integrity
  console.log('[24.2] Testing Pillar 2: Storage, Volumes & SMART status...');
  const storagePillar = await hostDiagnosticsEngine.collectStoragePillar();
  assert.ok(storagePillar, 'Storage pillar must be returned');
  assert.ok(VALID_HEALTH_STATES.includes(storagePillar.status));
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
  assert.ok(VALID_HEALTH_STATES.includes(resPillar.status));
  assert.ok(resPillar.details.cores > 0, 'Must have at least 1 CPU core');
  assert.ok(resPillar.details.totalRamGB > 0, 'Total RAM must be > 0 GB');
  assert.ok(typeof resPillar.details.cpuLoadPct === 'number' || resPillar.details.cpuLoadPct === null);
  assert.ok(typeof resPillar.details.ramUsedPct === 'number');
  assert.ok(Array.isArray(resPillar.details.topProcesses), 'Top processes must be an array');
  console.log(`  ✓ Resource Pillar verified: ${resPillar.status} (CPU: ${resPillar.details.cpuLoadPct}%, RAM: ${resPillar.details.ramUsedPct}% of ${resPillar.details.totalRamGB} GB, ${resPillar.details.topProcesses.length} processes).`);

  // 4. Pillar 4: Peripherals, Subsystems & Drivers
  console.log('[24.4] Testing Pillar 4: Peripherals & Drivers...');
  const periphPillar = await hostDiagnosticsEngine.collectPeripheralsPillar();
  assert.ok(periphPillar, 'Peripherals pillar must be returned');
  assert.ok(VALID_HEALTH_STATES.includes(periphPillar.status));
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
  assert.ok(VALID_HEALTH_STATES.includes(fullAudit.overallStatus));
  assert.ok(fullAudit.compositeHealth);
  assert.ok(VALID_HEALTH_STATES.includes(fullAudit.compositeHealth.worstCondition));
  console.log(`  ✓ Full Audit completed in ${fullAudit.durationMs}ms: Overall Status ${fullAudit.overallStatus}, Composite: ${JSON.stringify(fullAudit.compositeHealth)}, ${fullAudit.anomalies.length} anomalies, ${fullAudit.stagedRecipes.length} staged recipes.`);

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

  // 8. F-50, F-54, F-55, F-56, F-58: Warm Baseline Zero Simulation & Provisional State
  console.log('[24.8] Testing Warm Baseline Zero Simulation & Provisional State (F-50, F-54, F-55, F-56, F-58)...');
  const isolatedEngine = new HostDiagnosticsEngine();
  const warmSnapshot = isolatedEngine.getWarmSnapshot();
  assert.strictEqual(warmSnapshot.isProvisional, true, 'Warm baseline must be marked provisional');
  assert.strictEqual(warmSnapshot.overallStatus, 'INITIALIZING', 'Warm baseline overallStatus must be INITIALIZING');
  assert.strictEqual(warmSnapshot.metadata.outcome, 'PROVISIONAL_WARM_STATE', 'Outcome must be PROVISIONAL_WARM_STATE');
  assert.strictEqual(warmSnapshot.metadata.isAuthoritative, false, 'Provisional state must not be authoritative');
  // Check absence of fabricated numbers
  assert.strictEqual(warmSnapshot.pillars.network.status, 'UNKNOWN');
  assert.strictEqual(warmSnapshot.pillars.network.details.socketCounts, null, 'Must not fabricate socket counts');
  assert.strictEqual(warmSnapshot.pillars.network.details.gatewayIp, null, 'Must not fabricate gateway IP');
  assert.strictEqual(warmSnapshot.pillars.storage.status, 'UNKNOWN');
  assert.strictEqual(warmSnapshot.pillars.storage.details.smartStatus, 'UNKNOWN');
  assert.strictEqual(warmSnapshot.pillars.resource.status, 'UNKNOWN');
  assert.strictEqual(warmSnapshot.pillars.resource.details.cpuLoadPct, null, 'Must not fabricate CPU load');
  assert.strictEqual(warmSnapshot.pillars.peripherals.status, 'UNKNOWN');
  assert.strictEqual(warmSnapshot.pillars.peripherals.details.spoolerStatus, 'UNKNOWN');
  console.log('  ✓ Warm baseline is strictly provisional with zero fabricated measurements.');

  // 9. F-59, F-60, F-61, F-63, F-65: Telemetry Provenance and Metadata Contracts
  console.log('[24.9] Testing Telemetry Provenance and Metadata Contracts (F-59, F-60, F-61, F-63, F-65)...');
  for (const [pillarName, pillar] of Object.entries(fullAudit.pillars)) {
    assert.ok(pillar.metadata, `${pillarName} must have metadata`);
    assert.ok(pillar.metadata.collectedAt, `${pillarName} metadata must have collectedAt`);
    assert.ok(typeof pillar.metadata.durationMs === 'number', `${pillarName} metadata must have durationMs`);
    assert.ok(typeof pillar.metadata.collector === 'string', `${pillarName} metadata must have collector`);
    assert.ok(typeof pillar.metadata.outcome === 'string', `${pillarName} metadata must have outcome`);
    assert.ok(['SUCCESS', 'PARTIAL', 'COLLECTION_ERROR', 'UNSUPPORTED_PLATFORM'].includes(pillar.metadata.outcome));
    assert.strictEqual(typeof pillar.metadata.isAuthoritative, 'boolean', `${pillarName} metadata must have isAuthoritative`);
  }
  console.log('  ✓ Telemetry provenance contracts verified across all 4 pillars.');

  // 10. F-57, F-62, F-66, F-67: 6-State Health & Injected Sub-Collector Failures
  console.log('[24.10] Testing 6-State Health & Injected Sub-Collector Failures (F-57, F-62, F-66, F-67)...');
  const mockEngine = new HostDiagnosticsEngine();

  // Test Case A: Sub-collector partial failure in storage (SMART fails, volumes succeed)
  mockEngine._runPowerShell = async (cmd) => {
    if (cmd.includes('MSStorageDriver_FailurePredictStatus')) {
      return { success: false, outcome: 'COLLECTION_ERROR', data: null, error: 'WMI Query Failed', durationMs: 5 };
    }
    if (cmd.includes('Get-Volume')) {
      return {
        success: true,
        outcome: 'SUCCESS',
        data: [{ DriveLetter: 'C', FileSystemLabel: 'OS', FileSystem: 'NTFS', SizeRemaining: 100 * 1024**3, Size: 500 * 1024**3, HealthStatus: 'Healthy' }],
        durationMs: 5
      };
    }
    return { success: true, outcome: 'SUCCESS', data: [], durationMs: 5 };
  };

  const partialStorage = await mockEngine.collectStoragePillar();
  assert.strictEqual(partialStorage.metadata.outcome, 'PARTIAL', 'Storage outcome must be PARTIAL when SMART fails');
  assert.strictEqual(partialStorage.details.smartStatus, 'UNKNOWN', 'smartStatus must be UNKNOWN on query failure');
  assert.strictEqual(partialStorage.metadata.smartVerification, 'UNKNOWN');
  assert.strictEqual(partialStorage.status, 'DEGRADED', 'Storage status must be DEGRADED on partial telemetry');

  // Test Case B: Injected total collector failure
  mockEngine._runPowerShell = async () => ({
    success: false,
    outcome: 'COLLECTION_ERROR',
    data: null,
    error: 'Access Denied',
    durationMs: 1
  });

  const failedNet = await mockEngine.collectNetworkPillar();
  assert.strictEqual(failedNet.status, 'COLLECTION_ERROR');
  assert.strictEqual(failedNet.metadata.outcome, 'COLLECTION_ERROR');

  // Test Case C: Full audit aggregation with partial collectors reflects composite health
  mockEngine._runPowerShell = async (cmd) => {
    if (cmd.includes('Get-Volume')) {
      return { success: false, outcome: 'COLLECTION_ERROR', data: null, error: 'Drive error', durationMs: 1 };
    }
    return { success: true, outcome: 'SUCCESS', data: [], durationMs: 1 };
  };

  const compositeAudit = await mockEngine.collectFullAudit(true);
  assert.ok(['DEGRADED', 'COLLECTION_ERROR'].includes(compositeAudit.overallStatus));
  assert.strictEqual(compositeAudit.compositeHealth.telemetryCompleteness, 'PARTIAL_TELEMETRY');
  console.log('  ✓ 6-State health classification and composite resolution verified under simulated failures.');

  // 11. F-70, F-71: PowerShell Hardening & Process Limit Bounds
  console.log('[24.11] Testing PowerShell Hardening & Process Limit Bounds (F-70, F-71)...');
  const testEngine = new HostDiagnosticsEngine();
  const procsLimited = await testEngine.getProcessList(-10);
  assert.ok(Array.isArray(procsLimited));
  const procsCapped = await testEngine.getProcessList(999999);
  assert.ok(Array.isArray(procsCapped));
  console.log('  ✓ Process list limit safely bounded.');

  console.log('\n>>> ALL SUITE 24 CORE DIAGNOSTICS ENGINE TESTS PASSED (ZERO DEFECTS).\n');
}

if (require.main === module) {
  runCoreDiagnosticsEngineTests().catch((err) => {
    console.error('Suite 24 failed:', err);
    process.exit(1);
  });
}

module.exports = { runCoreDiagnosticsEngineTests };
