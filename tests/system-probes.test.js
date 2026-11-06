/**
 * EJII Test Suite: Host & Server Metrics Driver
 */

const assert = require('assert');
const { getHostMetrics, getServices, getProcesses, getEventLogs } = require('../src/protocols/host-metrics');

async function runSystemTests() {
  console.log('\n--- Running Host & Server Metrics Test Suite ---');

  // Test 1: Real Host Hardware & OS Metrics
  console.log('Testing Real Host Metrics Collection...');
  const host = await getHostMetrics(true);
  assert.ok(host.hostname, 'Hostname must be defined');
  assert.ok(host.cpu.model, 'CPU model must be detected');
  assert.ok(host.cpu.cores > 0, 'CPU cores must be > 0');
  assert.ok(host.memory.totalBytes > 0, 'Total memory must be > 0');
  assert.ok(host.memory.usedPercentage >= 0 && host.memory.usedPercentage <= 100, 'Memory used % must be between 0 and 100');
  assert.ok(Array.isArray(host.disks), 'Disks must be an array');
  assert.ok(host.disks.length > 0, 'Must detect at least one logical drive');
  console.log(`✓ Real Host Metrics passed: CPU=${host.cpu.model} (${host.cpu.cores} cores), RAM=${host.memory.usedFormatted}/${host.memory.totalFormatted} (${host.memory.usedPercentage}%), Disks=${host.disks.length}`);

  // Test 2: Windows / System Services
  console.log('Testing Services Enumeration...');
  const services = await getServices();
  assert.ok(Array.isArray(services), 'Services must return an array');
  assert.ok(services.length > 0, 'Must discover active services');
  console.log(`✓ Services check passed: Found ${services.length} services (e.g. ${services[0].name}: ${services[0].status})`);

  // Test 3: Top Processes
  console.log('Testing Process Table Query...');
  const processes = await getProcesses(10);
  assert.ok(Array.isArray(processes), 'Processes must return an array');
  assert.ok(processes.length > 0, 'Must discover active processes');
  assert.ok(processes[0].pid > 0, 'Process must have valid PID');
  assert.ok(processes[0].workingSetMB >= 0, 'Working set memory must be non-negative');
  console.log(`✓ Process check passed: Top process=${processes[0].name} (PID ${processes[0].pid}, RAM ${processes[0].workingSetMB} MB)`);

  console.log('--- Host & Server Metrics Test Suite PASSED ---\n');
}

if (require.main === module) {
  runSystemTests().catch((err) => {
    console.error('System Tests FAILED:', err);
    process.exit(1);
  });
}

module.exports = { runSystemTests };
