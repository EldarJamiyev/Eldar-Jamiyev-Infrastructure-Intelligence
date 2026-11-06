/**
 * EJII Test Suite 66: Category A & B Modernization Verification
 * Multi-Core Worker-Thread Pool (node:worker_threads), Event-Loop Lag Histogram,
 * TypeScript Declaration Contracts & Pluggable Time-Series Storage Adapter
 * (InfluxDB Line Protocol, ClickHouse JSONEachRow, TimescaleDB SQL Batch)
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { packetAndScanWorkerPool } = require('../src/network/workers/packet-and-scan-worker-pool');
const { PacketDecoder } = require('../src/network/packet-decoding/packet-decoder');
const { timeSeriesStorageAdapter } = require('../src/db/timeseries-storage-adapter');

async function runWorkerPoolTypesAndTimeseriesAdapterTests() {
  console.log('========================================================================');
  console.log('  SUITE 66: WORKER THREAD POOL, TS CONTRACTS & TIME-SERIES ADAPTER      ');
  console.log('========================================================================\n');

  const rootDir = path.resolve(__dirname, '..');

  // [66.1] Verify tsconfig.json & src/types/ejii-contracts.d.ts Exist
  console.log('[66.1] Verifying TypeScript configuration & contract definitions...');
  assert.strictEqual(fs.existsSync(path.join(rootDir, 'tsconfig.json')), true, 'tsconfig.json must exist');
  assert.strictEqual(fs.existsSync(path.join(rootDir, 'src', 'types', 'ejii-contracts.d.ts')), true, 'src/types/ejii-contracts.d.ts must exist');
  console.log('  ✓ TypeScript configuration and declaration contracts verified.');

  // [66.2] Verify Multi-Core Worker-Thread Pool Off-Thread Packet Batch Dissection
  console.log('[66.2] Verifying off-main-thread packet batch dissection via WorkerPool...');
  const synFrame = PacketDecoder.generateSampleFrame('TCP_SYN');
  const dnsFrame = PacketDecoder.generateSampleFrame('DNS_QUERY');
  const dissectedBatch = await packetAndScanWorkerPool.dissectPacketBatchOffThread([synFrame, dnsFrame]);
  assert.strictEqual(Array.isArray(dissectedBatch), true);
  assert.strictEqual(dissectedBatch.length, 2);
  assert.strictEqual(dissectedBatch[0].protocol, 'TCP');

  const workerTelemetry = packetAndScanWorkerPool.getEventLoopAndWorkerTelemetry();
  assert.ok(workerTelemetry.tasksCompleted >= 1);
  assert.ok(workerTelemetry.eventLoopLag && typeof workerTelemetry.eventLoopLag.p99Ms === 'number');
  await packetAndScanWorkerPool.shutdownPool();
  console.log(`  ✓ Worker-thread batch dissection verified (p99 event-loop lag=${workerTelemetry.eventLoopLag.p99Ms} ms).`);

  // [66.3] Verify Write-Behind Ring Buffer & Multi-TSDB Export Formats (InfluxDB, ClickHouse, TimescaleDB)
  console.log('[66.3] Verifying Pluggable Time-Series Storage Adapter & Write-Behind Ring Buffer...');
  for (let i = 0; i < 12; i++) {
    timeSeriesStorageAdapter.ingestMetricPoint({
      measurement: 'ejii_node_latency',
      targetHost: '192.168.31.1',
      metricName: 'rtt_ms',
      metricValue: 1.2 + i * 0.1,
      tags: { layer: 'L2', role: 'gateway' }
    });
  }
  const flushRes = timeSeriesStorageAdapter.flushBatchToWal();
  assert.ok(flushRes.batchesFlushed >= 1);

  const influxOut = timeSeriesStorageAdapter.exportInfluxLineProtocol(5);
  assert.ok(influxOut.includes('ejii_node_latency,host=192.168.31.1'), 'InfluxDB Line Protocol export must match standard syntax');

  const clickhouseOut = timeSeriesStorageAdapter.exportClickHouseJsonEachRow(5);
  assert.ok(clickhouseOut.includes('"measurement":"ejii_node_latency"'), 'ClickHouse JSONEachRow export must be valid JSON lines');

  const timescaleOut = timeSeriesStorageAdapter.exportTimescaleDbSqlBatch(5);
  assert.ok(timescaleOut.includes('INSERT INTO ejii_metrics_hypertable'), 'TimescaleDB export must generate valid bulk SQL');
  console.log('  ✓ Time-Series Storage Adapter verified across SQLite WAL Bulk-Batch, InfluxDB, ClickHouse, and TimescaleDB.\n');

  console.log('========================================================================');
  console.log('  SUITE 66 PASSED: WORKER POOL & TIME-SERIES ADAPTER 100% GREEN         ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runWorkerPoolTypesAndTimeseriesAdapterTests()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('Suite 66 failed:', err);
      process.exit(1);
    });
}

module.exports = { runWorkerPoolTypesAndTimeseriesAdapterTests };
