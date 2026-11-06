// tests/suite-76-process-socket-behavioral-matrix.test.ts
import * as assert from 'node:assert';
import {
  ProcessSocketCorrelatorEngine,
  SocketEntry,
  ProcessEntry
} from '../src/diagnostics/process-socket-correlator';

export async function runSuite76ProcessSocketBehavioralMatrix(): Promise<void> {
  console.log('=== [SUITE 76] PROCESS-SOCKET BEHAVIORAL MATRIX & RFC 6056 TELEMETRY VERIFICATION ===');

  // 1. C2 Beaconing Periodicity & Coefficient of Variation (CV = sigma / mu)
  console.log('[76.1] Verifying C2 beaconing coefficient of variation (CV < 0.15)...');
  // Periodic beacon: every 5000ms with tiny jitter
  const periodicTimestamps = [10000, 15005, 20010, 25000, 30005, 35010]; // intervals: 5005, 5005, 4990, 5005, 5005
  const beaconingMetrics = ProcessSocketCorrelatorEngine.computeBeaconingMetrics(periodicTimestamps);
  assert.strictEqual(beaconingMetrics.sampleCount, 6, 'Must have 6 samples');
  assert.ok(beaconingMetrics.coefficientOfVariation < 0.05, `CV must be extremely low (< 0.05) for periodic beaconing, got ${beaconingMetrics.coefficientOfVariation}`);
  assert.strictEqual(beaconingMetrics.beaconingSuspected, true, 'Beaconing suspected must be true');
  assert.ok(beaconingMetrics.periodicityScore > 0.95, `Periodicity score must exceed 0.95, got ${beaconingMetrics.periodicityScore}`);

  // Random traffic: highly irregular intervals
  const randomTimestamps = [1000, 1500, 9200, 9400, 25000, 25100, 48000];
  const randomMetrics = ProcessSocketCorrelatorEngine.computeBeaconingMetrics(randomTimestamps);
  assert.strictEqual(randomMetrics.beaconingSuspected, false, 'Beaconing must not be suspected for random intervals');
  assert.ok(randomMetrics.coefficientOfVariation > 0.5, `CV must be high (> 0.5), got ${randomMetrics.coefficientOfVariation}`);

  // 2. RFC 6056 Ephemeral Port Saturation & Time-to-Exhaustion Projection
  console.log('[76.2] Verifying RFC 6056 ephemeral port exhaustion telemetry & time-to-exhaustion...');
  const simulatedSockets: SocketEntry[] = [];
  const simulatedProcesses: ProcessEntry[] = [
    { pid: 1001, name: 'leak_worker.exe', memoryMb: 150 },
    { pid: 1002, name: 'nginx.exe', memoryMb: 80 }
  ];

  // Populate 8192 ephemeral ports for leak_worker (50% of 16384 pool)
  for (let p = 49152; p < 49152 + 8192; p++) {
    simulatedSockets.push({
      protocol: 'TCP',
      localAddress: '127.0.0.1',
      localPort: p,
      remoteAddress: '93.184.216.34',
      remotePort: 443,
      state: 'TIME_WAIT',
      pid: 1001
    });
  }

  // Populate 10 listening sockets for nginx
  for (let p = 80; p < 90; p++) {
    simulatedSockets.push({
      protocol: 'TCP',
      localAddress: '0.0.0.0',
      localPort: p,
      remoteAddress: '0.0.0.0',
      remotePort: 0,
      state: 'LISTENING',
      pid: 1002
    });
  }

  // Burn rate: 100 ports per second
  const matrix = ProcessSocketCorrelatorEngine.analyzeSocketProcessMatrix(
    simulatedSockets,
    simulatedProcesses,
    { 1001: periodicTimestamps },
    100
  );

  const eph = matrix.ephemeralTelemetry;
  assert.strictEqual(eph.totalDynamicRange, 16384, 'Total dynamic range per RFC 6056 must be 16384');
  assert.strictEqual(eph.activeEphemeralCount, 8192, 'Active ephemeral count must be 8192');
  assert.strictEqual(Math.round(eph.saturationPct), 50, 'Saturation must be 50%');
  assert.strictEqual(eph.timeWaitRatio, 1.0, 'All ephemeral sockets are in TIME_WAIT, ratio must be 1.0');
  assert.strictEqual(eph.status, 'WARNING', 'Status at 50% saturation must be WARNING');

  // Remaining: 8192 ports / 100 ports per sec = ~81-82 seconds
  assert.ok(eph.estimatedSecondsToPortExhaustion !== null);
  assert.ok(
    eph.estimatedSecondsToPortExhaustion >= 80 && eph.estimatedSecondsToPortExhaustion <= 83,
    `Estimated seconds to exhaustion should be ~81-82s, got ${eph.estimatedSecondsToPortExhaustion}`
  );

  // Check attribution on leak_worker
  const proc1 = matrix.processes.find(p => p.pid === 1001);
  assert.ok(proc1, 'leak_worker must be attributed');
  assert.strictEqual(proc1?.ephemeralPortsUsed, 8192, 'Must record 8192 ephemeral ports used');
  assert.strictEqual(proc1?.timeWaitSockets, 8192, 'Must record 8192 TIME_WAIT sockets');
  assert.strictEqual(proc1?.beaconingMetrics.beaconingSuspected, true, 'leak_worker must trigger beaconing alert');

  // 3. Live Host Extraction & Attribution
  console.log('[76.3] Verifying unprivileged live OS socket & process correlation...');
  const liveReport = ProcessSocketCorrelatorEngine.runLiveExtractionAndAnalysis();
  assert.ok(liveReport.totalSockets >= 1, `Live host total sockets must be >= 1, got ${liveReport.totalSockets}`);
  assert.ok(liveReport.processes.length >= 1, 'Live host attributed processes must be >= 1');
  assert.ok(liveReport.ephemeralTelemetry.totalDynamicRange === 16384, 'Live report must follow RFC 6056');
  assert.ok(liveReport.timestampIso.length > 15, 'Timestamp must be valid ISO string');

  console.log(`  ✓ Extracted ${liveReport.totalSockets} active sockets across ${liveReport.processes.length} processes.`);
  console.log('✓ Suite 76 passed: Process-Socket Behavioral Matrix 100% verified.\n');
}

if (require.main === module) {
  runSuite76ProcessSocketBehavioralMatrix().then(() => process.exit(0)).catch(err => {
    console.error(err);
    process.exit(1);
  });
}
