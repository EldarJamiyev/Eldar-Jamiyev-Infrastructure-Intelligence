/**
 * EJII Test Suite 67: Category C & D Modernization Verification
 * CNCF Prometheus Exposition Format (/metrics), OpenTelemetry W3C OTLP Exporter,
 * Grafana v11 Dashboard Model & Linux-Native (/proc/meminfo, /proc/net/dev, /proc/net/arp, /proc/net/tcp) Parity
 */

const assert = require('assert');
const { cncfObservabilityExporter } = require('../src/integrations/observability/cncf-observability-exporter');
const {
  parseProcMeminfo,
  parseProcNetDev,
  parseProcNetArp,
  parseProcNetTcp,
  collectLinuxParityTelemetry
} = require('../src/systems/linux/linux-native-telemetry');

async function runCncfPrometheusOtelAndLinuxParityTests() {
  console.log('========================================================================');
  console.log('  SUITE 67: CNCF PROMETHEUS/OTEL/GRAFANA & LINUX KERNEL PARITY          ');
  console.log('========================================================================\n');

  // [67.1] Verify Prometheus Exposition Format Generation
  console.log('[67.1] Verifying CNCF Prometheus Exposition Format...');
  const promText = cncfObservabilityExporter.generatePrometheusMetrics();
  assert.ok(promText.includes('# HELP ejii_topology_node_latency_ms'), 'Must include Prometheus # HELP header');
  assert.ok(promText.includes('# TYPE ejii_topology_node_latency_ms gauge'), 'Must include Prometheus # TYPE header');
  assert.ok(promText.includes('ejii_ai_brain_shannon_entropy_bits'), 'Must export AI Brain Shannon entropy gauge');
  console.log('  ✓ Prometheus Exposition Format verified.');

  // [67.2] Verify OpenTelemetry W3C Trace Span & Grafana v11 Dashboard Provisioner
  console.log('[67.2] Verifying OpenTelemetry OTLP spans & Grafana v11 Dashboard JSON...');
  const span = cncfObservabilityExporter.recordOtelSpan({
    name: 'GET /api/network/topology',
    kind: 'SERVER',
    durationMs: 4.2,
    attributes: { 'http.status_code': 200, 'ejii.pillar': 'NOC_TOPOLOGY' }
  });
  assert.ok(span.traceparent && /^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/.test(span.traceparent), 'Must generate valid W3C traceparent');

  const otlpPayload = cncfObservabilityExporter.exportOtelTracesJson();
  assert.ok(Array.isArray(otlpPayload.resourceSpans) && otlpPayload.resourceSpans.length > 0);

  const grafanaDash = cncfObservabilityExporter.generateGrafanaDashboardModel();
  assert.strictEqual(grafanaDash.uid, 'ejii-noc-enterprise-v1');
  assert.ok(Array.isArray(grafanaDash.panels) && grafanaDash.panels.length >= 4);
  console.log(`  ✓ OpenTelemetry W3C traceparent (${span.traceparent}) and Grafana v11 dashboard verified.`);

  // [67.3] Verify Linux-Native /proc Parsers (/proc/meminfo, /proc/net/dev, /proc/net/arp, /proc/net/tcp)
  console.log('[67.3] Verifying Linux-native /proc kernel parsers...');
  const mem = parseProcMeminfo('MemTotal:       16384000 kB\nMemFree:         2048000 kB\nMemAvailable:    8192000 kB\nSwapTotal:       4096000 kB\nSwapFree:        4096000 kB\n');
  assert.strictEqual(mem.totalMb, 16000);
  assert.strictEqual(mem.availableMb, 8000);
  assert.strictEqual(mem.memPercent, 50.0);

  const netDevs = parseProcNetDev('Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n  eth0: 10485760   12000    0    2    0     0          0         0  5242880    8000    0    0    0     0       0          0\n');
  assert.strictEqual(netDevs.length, 1);
  assert.strictEqual(netDevs[0].interface, 'eth0');
  assert.strictEqual(netDevs[0].rxDrops, 2);

  const arpEntries = parseProcNetArp('IP address       HW type     Flags       HW address            Mask     Device\n192.168.31.1     0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n');
  assert.strictEqual(arpEntries.length, 1);
  assert.strictEqual(arpEntries[0].macAddress, 'AA:BB:CC:DD:EE:FF');

  const tcpSockets = parseProcNetTcp('  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:20FB 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0\n');
  assert.strictEqual(tcpSockets.length, 1);
  assert.strictEqual(tcpSockets[0].localIp, '127.0.0.1');
  assert.strictEqual(tcpSockets[0].localPort, 8443);
  assert.strictEqual(tcpSockets[0].state, 'LISTEN');

  const parity = collectLinuxParityTelemetry();
  assert.ok(parity && parity.platform);
  console.log('  ✓ Linux-native /proc/meminfo, /proc/net/dev, /proc/net/arp, and /proc/net/tcp parsers verified.\n');

  console.log('========================================================================');
  console.log('  SUITE 67 PASSED: CNCF OBSERVABILITY & LINUX PARITY 100% GREEN         ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runCncfPrometheusOtelAndLinuxParityTests()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('Suite 67 failed:', err);
      process.exit(1);
    });
}

module.exports = { runCncfPrometheusOtelAndLinuxParityTests };
