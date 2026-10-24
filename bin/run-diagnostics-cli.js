#!/usr/bin/env node
/**
 * EJII CLI Diagnostics Tool
 * Standalone terminal tool for running real low-level diagnostics.
 */

const { realPing, realTraceroute } = require('../src/protocols/icmp-ping');
const { checkPort, scanPorts } = require('../src/protocols/tcp-port');
const { resolveRecord } = require('../src/protocols/dns-diag');
const { auditTls } = require('../src/protocols/tls-audit');
const { probeHttp } = require('../src/protocols/http-probe');
const { getHostMetrics } = require('../src/protocols/host-metrics');
const { verifyChainIntegrity } = require('../src/core/audit-logger');

async function main() {
  const args = process.argv.slice(2);
  const command = args[0] ? args[0].toLowerCase() : 'help';
  const target = args[1];

  console.log('================================================================');
  console.log('  EJII — Infrastructure Intelligence CLI Utility               ');
  console.log('  Zero-Simulation Mode: Real OS & Socket Telemetry             ');
  console.log('================================================================');

  switch (command) {
    case 'ping':
      if (!target) return console.error('Usage: node bin/run-diagnostics-cli.js ping <host>');
      console.log(`Pinging ${target}...`);
      const ping = await realPing(target);
      console.log(JSON.stringify(ping, null, 2));
      break;

    case 'port':
      if (!target || !args[2]) return console.error('Usage: node bin/run-diagnostics-cli.js port <host> <port>');
      console.log(`Checking port ${args[2]} on ${target}...`);
      const port = await checkPort(target, parseInt(args[2], 10));
      console.log(JSON.stringify(port, null, 2));
      break;

    case 'sweep':
      if (!target) return console.error('Usage: node bin/run-diagnostics-cli.js sweep <host>');
      console.log(`Sweeping common ports on ${target}...`);
      const sweep = await scanPorts(target);
      console.log(`Scanned ${sweep.totalScanned} ports. Open: ${sweep.openCount}, Filtered: ${sweep.filteredCount}, Closed: ${sweep.closedCount}`);
      sweep.results.filter(r => r.open).forEach(r => console.log(`  [OPEN] Port ${r.port} (${r.service}) - ${r.connectLatencyMs}ms`));
      break;

    case 'dns':
      if (!target) return console.error('Usage: node bin/run-diagnostics-cli.js dns <domain>');
      console.log(`Resolving ${target}...`);
      const dns = await resolveRecord(target, 'A');
      console.log(JSON.stringify(dns, null, 2));
      break;

    case 'tls':
      if (!target) return console.error('Usage: node bin/run-diagnostics-cli.js tls <domain>');
      console.log(`Auditing TLS on ${target}:443...`);
      const tls = await auditTls(target, 443);
      console.log(JSON.stringify(tls, null, 2));
      break;

    case 'http':
      if (!target) return console.error('Usage: node bin/run-diagnostics-cli.js http <url>');
      console.log(`Probing ${target}...`);
      const http = await probeHttp(target);
      console.log(JSON.stringify(http, null, 2));
      break;

    case 'host':
      console.log('Querying host hardware and OS telemetry...');
      const host = await getHostMetrics(true);
      console.log(`Host: ${host.hostname} (${host.osDetails.caption})`);
      console.log(`CPU: ${host.cpu.model} (${host.cpu.cores} cores, Load: ${host.cpu.loadPercentage}%)`);
      console.log(`RAM: ${host.memory.usedFormatted} used of ${host.memory.totalFormatted} (${host.memory.usedPercentage}%)`);
      console.log(`Disks: ${host.disks.map(d => `${d.mount} ${d.usedPercentage}% (${d.freeFormatted} free)`).join(', ')}`);
      break;

    case 'audit-verify':
      console.log('Verifying cryptographic HMAC audit chain...');
      const audit = verifyChainIntegrity();
      console.log(JSON.stringify(audit, null, 2));
      break;

    case '--json':
    case 'json': {
      const { getPhysicalNetworkInfo } = require('../src/network/routing/physical-network-detector');
      const { hostDiagnosticsEngine } = require('../src/systems/diagnostics/host-diagnostics-engine');
      const { aiBrain } = require('../src/core/ai-brain');

      const netInfo = getPhysicalNetworkInfo ? getPhysicalNetworkInfo() : null;
      let hostAudit = null;
      try {
        hostAudit = (hostDiagnosticsEngine.getWarmSnapshot ? hostDiagnosticsEngine.getWarmSnapshot() : null) || await hostDiagnosticsEngine.collectFullAudit(false);
      } catch (e) {
        hostAudit = { error: e.message };
      }
      const brainState = aiBrain.getLiveState ? aiBrain.getLiveState() : null;

      const summary = {
        timestamp: new Date().toISOString(),
        network: netInfo,
        host: hostAudit,
        aiBrain: brainState
      };
      console.log(JSON.stringify(summary, null, 2));
      break;
    }

    default:
      console.log('Commands:');
      console.log('  ping <host>            Run real ICMP ping with RTT and jitter');
      console.log('  port <host> <port>     Test single TCP port connection');
      console.log('  sweep <host>           Scan 23 common enterprise ports');
      console.log('  dns <domain>           Resolve RFC 1035 DNS record');
      console.log('  tls <domain>           Audit TLS/SSL certificate & cipher');
      console.log('  http <url>             Execute synthetic HTTP probe with waterfall');
      console.log('  host                   Inspect local machine CPU, RAM, & Disks');
      console.log('  audit-verify           Cryptographically verify audit log hash chain');
      break;
  }
}

main().then(() => process.exit(0)).catch((err) => {
  console.error(err);
  process.exit(1);
});
