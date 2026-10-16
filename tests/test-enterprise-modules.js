/**
 * EJI Enterprise Modules Test Suite
 * Validates ITSM, CMDB & IPAM, Monitoring & Alerting, Drift, Chaos Lab, Services, and Control Loop.
 */

const assert = require('assert');
const TicketRepository = require('../src/database/repositories/ticket-repository');
const CmdbRepository = require('../src/database/repositories/cmdb-repository');
const MonitoringRepository = require('../src/database/repositories/monitoring-repository');
const DriftRepository = require('../src/database/repositories/drift-repository');
const ChaosRepository = require('../src/database/repositories/chaos-repository');
const ServiceRepository = require('../src/database/repositories/service-repository');
const IpamService = require('../src/network/routing/ipam-service');
const DriftEngine = require('../src/drift/diffing/drift-engine');
const ChaosEngine = require('../src/chaos/lab/chaos-engine');
const AlertEvaluator = require('../src/monitoring/alerting/alert-evaluator');
const SlaEngine = require('../src/helpdesk/sla/sla-engine');
const ControlLoopEngine = require('../src/core/control-loop/control-loop-engine');
const PacketDecoder = require('../src/network/packet-decoding/packet-decoder');
const ProcessForensics = require('../src/systems/processes/process-forensics');

async function runEnterpriseTests() {
  console.log('========================================================================');
  console.log('  EJI — Eldar Jamiyev\'s Infrastructure Intelligence Platform');
  console.log('  ENTERPRISE DOMAIN MODULES & CONTROL LOOP TEST SUITE');
  console.log('========================================================================\n');

  // Test 1: ITSM & SLA Lifecycle
  console.log('Testing ITSM Tickets & SLA Lifecycle...');
  const ticket = TicketRepository.createTicket({
    title: 'Core Switch SFP Module Intermittent Link Flapping',
    description: 'Interface TenGigabitEthernet1/0/1 is experiencing CRC error bursts.',
    category: 'incident',
    priority: 'P1_CRITICAL',
    requesterName: 'Senior Network Engineer',
    assignedTeam: 'network_admin'
  });
  assert(ticket && ticket.id.startsWith('TCK-'), 'Ticket creation must return valid TCK ID');
  assert(ticket.sla_target_response_at !== null, 'P1 ticket must calculate response SLA');
  
  const comment = TicketRepository.addComment({
    ticketId: ticket.id,
    authorName: 'Eldar Jamiyev',
    commentText: 'Technician dispatched with replacement 10G-LR optic.',
    isInternal: 0
  });
  assert(comment && comment.id.startsWith('CMT-'), 'Comment must be recorded');

  const slaMetrics = SlaEngine.getSlaMetrics();
  assert(typeof slaMetrics.totalTickets === 'number', 'SLA metrics must return total count');
  console.log(`✓ ITSM Ticket ${ticket.id} and SLA evaluation verified.`);

  // Test 2: CMDB & IPAM Subnet Allocation
  console.log('Testing CMDB Hardware & IPAM Subnet Allocation...');
  const hwCi = CmdbRepository.createHardwareCi({
    assetTag: 'TAG-TEST-SRV-' + Date.now().toString().slice(-4),
    model: 'PowerEdge R750',
    vendor: 'Dell EMC',
    formFactor: 'rackmount_server',
    location: 'Primary Datacenter',
    rackUnit: 'U24-U26',
    ramGb: 128,
    storageGb: 4000
  });
  assert(hwCi && hwCi.id.startsWith('CI-HW-'), 'Hardware CI must be persisted');

  const iface = CmdbRepository.addInterface({
    ciId: hwCi.id,
    interfaceName: 'eth0',
    macAddress: '00:50:56:AB:CD:EF',
    ipv4Address: '192.168.31.250'
  });
  assert(iface && iface.id.startsWith('IFACE-'), 'Interface must be attached');

  const parsedCidr = IpamService.parseCidr('192.168.31.0/24');
  assert.strictEqual(parsedCidr.usableHosts, 254, 'Usable hosts for /24 must be 254');
  const nextIp = IpamService.findNextFreeIp('192.168.31.0/24');
  assert(nextIp && nextIp.nextFreeIp, 'Next free IP must be found');
  console.log(`✓ CMDB CI ${hwCi.id} and IPAM subnet allocation verified (Next IP: ${nextIp.nextFreeIp}).`);

  // Test 3: Monitoring & Threshold Alert Evaluation
  console.log('Testing Monitoring Alert Rules & Threshold Evaluation...');
  const alertResults = AlertEvaluator.evaluateSample({
    ciId: hwCi.id,
    metricName: 'cpu_percent',
    value: 94.8,
    targetCiType: 'server_windows'
  });
  assert(Array.isArray(alertResults), 'Alert evaluator must return array of firing alerts');
  const alertStats = MonitoringRepository.getAlertStatistics();
  assert(alertStats.totalAlerts > 0, 'Total alerts count must be greater than 0');
  console.log(`✓ Monitoring alert evaluation verified (${alertResults.length} firing alerts).`);

  // Test 4: Configuration Drift Detection & Diffing
  console.log('Testing Configuration Drift Engine & Diffing...');
  const baseline = DriftRepository.upsertBaseline({
    targetCiId: hwCi.id,
    name: 'Hardware Base Policy',
    baselineType: 'security_policy',
    expectedState: { firewall: 'active', rootLogin: 'disabled', telemetryAgent: 'running' }
  });
  assert(baseline && baseline.id.startsWith('BASE-'), 'Baseline must be stored');

  const liveState = { firewall: 'inactive', rootLogin: 'disabled', telemetryAgent: 'running', roguePort: 9999 };
  const driftResult = DriftEngine.evaluateCiDrift(baseline.id, liveState);
  assert.strictEqual(driftResult.hasDrift, true, 'Drift must be detected');
  assert(driftResult.diff.modified.length > 0, 'Modified properties must be captured');
  console.log(`✓ Configuration Drift Engine verified: ${driftResult.diff.diffSummary} (Severity: ${driftResult.severity}).`);

  // Test 5: Chaos Engineering Lab Execution & Self-Healing
  console.log('Testing Chaos Lab Fault Injection & Guardrails...');
  const chaosRes = await ChaosEngine.executeExperiment('CHAOS-DNS-LATENCY', 'test_operator');
  assert.strictEqual(chaosRes.success, true, 'Experiment must succeed safely');
  assert.strictEqual(chaosRes.execution.status, 'completed', 'Execution must transition to completed');
  assert(chaosRes.execution.detection_latency_ms > 0, 'Detection latency must be measured');
  console.log(`✓ Chaos experiment ${chaosRes.execution.id} verified with ${chaosRes.execution.detection_latency_ms}ms detection latency.`);

  // Test 6: Business Service Catalog & Dependency Topology
  console.log('Testing Business Service Catalog & Dependency Graph...');
  const serviceMap = ServiceRepository.getServiceMap();
  assert(serviceMap.nodes.length >= 4, 'Service map must contain seeded business services');
  assert(serviceMap.edges.length >= 2, 'Service map must contain dependencies');
  console.log(`✓ Business Service Catalog verified (${serviceMap.nodes.length} services, ${serviceMap.edges.length} dependency edges).`);

  // Test 7: RFC Packet Dissection & Process Forensics
  console.log('Testing RFC Packet Dissection & Process Forensics...');
  const sampleFrame = PacketDecoder.generateSampleFrame('TCP_SYN');
  const dissected = PacketDecoder.dissectFrame(sampleFrame);
  assert.strictEqual(dissected.ethernet.typeStr, 'IPv4', 'EtherType must be IPv4');
  assert.strictEqual(dissected.ip.protocolStr, 'TCP', 'IP Protocol must be TCP');
  assert.strictEqual(dissected.transport.flags.syn, true, 'TCP SYN flag must be set');

  const forensics = ProcessForensics.analyzeSystemSecurity();
  assert(forensics.totalProcessesScanned > 0, 'Processes must be scanned');
  assert(forensics.listeningSocketsCount > 0, 'Sockets must be detected');
  console.log(`✓ Packet Dissection & Process Forensics verified (${forensics.totalProcessesScanned} processes, ${forensics.listeningSocketsCount} sockets).`);

  // Test 8: 13-Stage NEXUS Autonomous Control Loop
  console.log('Testing 13-Stage NEXUS Autonomous Control Loop...');
  const loopEngine = new ControlLoopEngine();
  const loopResult = await loopEngine.runLoop([
    { ciId: hwCi.id, metric: 'cpu_percent', value: 96.2, status: 'critical' }
  ], {
    baselineIntent: { [hwCi.id]: { desiredState: 'HEALTHY' } },
    userContext: { username: 'test_autonomous_agent', role: 'sysadmin' }
  });
  assert(loopResult && loopResult.loopId.startsWith('LOOP-'), 'Control loop must generate LOOP- ID');
  assert.strictEqual(Object.keys(loopResult.stages).length, 13, 'Control loop must have exactly 13 stages');
  assert.strictEqual(loopResult.stages.observe.stage, 'OBSERVE');
  assert.strictEqual(loopResult.stages.reconcile.stage, 'RECONCILE');
  console.log(`✓ 13-Stage Control Loop ${loopResult.loopId} completed in ${loopResult.totalDurationMs}ms (Final: ${loopResult.finalState}).`);

  // Teardown: Clean up test artifacts so test runs do not accumulate duplicate rows
  try {
    const { db } = require('../src/db/database');
    db.prepare('DELETE FROM ticket_comments WHERE ticket_id = ?').run(ticket.id);
    db.prepare('DELETE FROM helpdesk_tickets WHERE id = ?').run(ticket.id);
    db.prepare('DELETE FROM cmdb_interfaces WHERE ci_id = ?').run(hwCi.id);
    db.prepare('DELETE FROM cmdb_hardware WHERE id = ?').run(hwCi.id);
    try { db.prepare('DELETE FROM cmdb_items WHERE id = ?').run(hwCi.id); } catch (e) {}
    db.prepare('DELETE FROM monitoring_alerts WHERE ci_id = ?').run(hwCi.id);
    db.prepare('DELETE FROM drift_baselines WHERE id = ?').run(baseline.id);
    db.prepare('DELETE FROM chaos_executions WHERE id = ?').run(chaosRes.execution.id);
  } catch (teardownErr) {
    console.warn('[Test Teardown Notice]:', teardownErr.message);
  }

  console.log('\n========================================================================');
  console.log('  ALL 8/8 ENTERPRISE DOMAIN MODULE TESTS PASSED PERFECTLY');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runEnterpriseTests().catch(err => {
    console.error('Enterprise test suite failed:', err);
    process.exit(1);
  });
}

module.exports = { runEnterpriseTests };
