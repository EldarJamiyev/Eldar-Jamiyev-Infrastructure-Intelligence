/**
 * EJII 14-Tool Unified API Routes
 * Subsuming Wireshark, Nmap, PuTTY, Sysinternals, IP Scanner, iPerf, Netcat, Fiddler,
 * Nagios/PRTG, Packet Tracer, BleachBit, HWiNFO, FileZilla, and MTR into a single engine.
 */

const express = require('express');
const router = express.Router();
const { authenticate, requireRole } = require('./middleware');
const { ROLES } = require('../core/security');
const { logAction } = require('../core/audit-logger');

// Engines
const { dissectPacket, parsePcapBuffer } = require('../tools/wireshark-engine');
const { runNmapScan, fingerprintOperatingSystem } = require('../tools/nmap-engine');
const { getProcessTree, getTcpViewConnections, getProcessModules } = require('../tools/sysinternals-forensics');
const { sweepSubnet, getArpTable } = require('../tools/ip-scanner');
const { benchmarkTcpLoopback, benchmarkUdpJitter } = require('../tools/iperf-engine');
const { netcatTcp, netcatUdp } = require('../tools/netcat-hub');
const { pollInterfaceMetrics } = require('../tools/monitoring-daemon');
const { tracePacketPath, getRoutingTable } = require('../tools/packet-tracer');
const { auditSystemHygiene, vacuumDatabase } = require('../tools/bleachbit-hygiene');
const { getHardwareTelemetry } = require('../tools/hwinfo-telemetry');
const { listDirectory, compareFiles } = require('../tools/filezilla-sftp');
const { runMtrSession } = require('../tools/mtr-engine');
const { launchNativeTool } = require('../tools/putty-bridge');

router.use(authenticate);

// 1. Wireshark Engine
router.post('/wireshark/dissect', (req, res) => {
  try {
    const { hexPayload } = req.body;
    if (!hexPayload) return res.status(400).json({ error: 'hexPayload string is required.' });
    const buffer = Buffer.from(hexPayload.replace(/[^0-9a-fA-F]/g, ''), 'hex');
    const result = dissectPacket(buffer);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Dissection error: ' + err.message });
  }
});

// 2. Nmap Engine
router.post('/nmap/scan', requireRole(ROLES.NETWORK_ADMIN, ROLES.SYSADMIN, ROLES.APP_OWNER), async (req, res) => {
  try {
    const { host, ports } = req.body;
    if (!host) return res.status(400).json({ error: 'host is required.' });
    const result = await runNmapScan(host, ports);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Nmap scan error: ' + err.message });
  }
});

// 3. Sysinternals & Process Explorer
router.get('/sysinternals/tree', requireRole(ROLES.SYSADMIN, ROLES.APP_OWNER), async (req, res) => {
  try {
    const result = await getProcessTree();
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Process tree error: ' + err.message });
  }
});

router.get('/sysinternals/tcpview', requireRole(ROLES.NETWORK_ADMIN, ROLES.SYSADMIN, ROLES.APP_OWNER), async (req, res) => {
  try {
    const result = await getTcpViewConnections();
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'TCPView error: ' + err.message });
  }
});

router.get('/sysinternals/modules/:pid', requireRole(ROLES.SYSADMIN, ROLES.APP_OWNER), async (req, res) => {
  try {
    const result = await getProcessModules(req.params.pid);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Module inspection error: ' + err.message });
  }
});

// 4. Advanced IP Scanner
router.post('/ipscanner/sweep', requireRole(ROLES.NETWORK_ADMIN, ROLES.APP_OWNER), async (req, res) => {
  try {
    const { subnetBase = '192.168.1', start = 1, end = 30 } = req.body;
    const result = await sweepSubnet(subnetBase, parseInt(start, 10), parseInt(end, 10));
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Subnet sweep error: ' + err.message });
  }
});

router.get('/ipscanner/arp', async (req, res) => {
  try {
    const table = await getArpTable();
    res.json({ count: table.length, table });
  } catch (err) {
    res.status(500).json({ error: 'ARP table error: ' + err.message });
  }
});

// 5. iPerf Benchmarking
router.post('/iperf/tcp', requireRole(ROLES.NETWORK_ADMIN, ROLES.SYSADMIN, ROLES.APP_OWNER), async (req, res) => {
  try {
    const { durationSeconds = 2 } = req.body;
    const result = await benchmarkTcpLoopback(durationSeconds);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'TCP benchmark error: ' + err.message });
  }
});

router.post('/iperf/udp', requireRole(ROLES.NETWORK_ADMIN, ROLES.SYSADMIN, ROLES.APP_OWNER), async (req, res) => {
  try {
    const { packets = 100 } = req.body;
    const result = await benchmarkUdpJitter(parseInt(packets, 10) || 100);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'UDP jitter benchmark error: ' + err.message });
  }
});

// 6. Netcat Hub
router.post('/netcat/tcp', requireRole(ROLES.NETWORK_ADMIN, ROLES.SYSADMIN, ROLES.APP_OWNER), async (req, res) => {
  try {
    const { host, port, payload, timeoutMs } = req.body;
    const result = await netcatTcp({ host, port, payload, timeoutMs });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Netcat error: ' + err.message });
  }
});

// 7. Monitoring Daemon (PRTG / Nagios)
router.post('/monitoring/poll', requireRole(ROLES.NETWORK_ADMIN, ROLES.APP_OWNER), async (req, res) => {
  try {
    const { host, community = 'public', port = 161 } = req.body;
    const result = await pollInterfaceMetrics(host, community, parseInt(port, 10));
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Monitoring poll error: ' + err.message });
  }
});

// 8. Cisco Packet Tracer
router.post('/packet-tracer/trace', requireRole(ROLES.NETWORK_ADMIN, ROLES.SYSADMIN, ROLES.APP_OWNER), async (req, res) => {
  try {
    const { destinationIp } = req.body;
    if (!destinationIp) return res.status(400).json({ error: 'destinationIp is required.' });
    const result = await tracePacketPath(destinationIp);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Packet tracer error: ' + err.message });
  }
});

router.get('/packet-tracer/routes', requireRole(ROLES.NETWORK_ADMIN, ROLES.SYSADMIN, ROLES.APP_OWNER), async (req, res) => {
  try {
    const routes = await getRoutingTable();
    res.json({ count: routes.length, routes });
  } catch (err) {
    res.status(500).json({ error: 'Routing table error: ' + err.message });
  }
});

// 9. BleachBit System Hygiene
router.get('/bleachbit/audit', requireRole(ROLES.SYSADMIN, ROLES.APP_OWNER), (req, res) => {
  try {
    const audit = auditSystemHygiene();
    res.json(audit);
  } catch (err) {
    res.status(500).json({ error: 'Hygiene audit error: ' + err.message });
  }
});

router.post('/bleachbit/vacuum', requireRole(ROLES.APP_OWNER), (req, res) => {
  try {
    const result = vacuumDatabase();
    logAction({
      userId: req.user.id,
      username: req.user.username,
      role: req.user.role,
      action: 'SYSTEM_VACUUM',
      resource: 'EJII_DATABASE',
      details: 'SQLite database vacuumed and index stats analyzed.'
    });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Vacuum error: ' + err.message });
  }
});

// 10. HWiNFO & CPU-Z Telemetry
router.get('/hwinfo/telemetry', requireRole(ROLES.SYSADMIN, ROLES.APP_OWNER), async (req, res) => {
  try {
    const telemetry = await getHardwareTelemetry();
    res.json(telemetry);
  } catch (err) {
    res.status(500).json({ error: 'HWiNFO error: ' + err.message });
  }
});

// 11. FileZilla Subsystem
router.get('/filezilla/list', requireRole(ROLES.SYSADMIN, ROLES.APP_OWNER), async (req, res) => {
  try {
    const dir = req.query.dir || process.cwd();
    const result = await listDirectory(dir);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Directory list error: ' + err.message });
  }
});

router.post('/filezilla/compare', requireRole(ROLES.SYSADMIN, ROLES.APP_OWNER), async (req, res) => {
  try {
    const { sourceFile, destFile } = req.body;
    const result = await compareFiles(sourceFile, destFile);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'File compare error: ' + err.message });
  }
});

// 12. MTR Subsystem
router.post('/mtr/run', requireRole(ROLES.NETWORK_ADMIN, ROLES.SYSADMIN, ROLES.APP_OWNER), async (req, res) => {
  try {
    const { host, cycles = 2 } = req.body;
    if (!host) return res.status(400).json({ error: 'host is required.' });
    const result = await runMtrSession(host, parseInt(cycles, 10) || 2);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'MTR session error: ' + err.message });
  }
});

// 13. PuTTY Protocol Bridge
router.post('/putty/launch', requireRole(ROLES.SYSADMIN, ROLES.APP_OWNER), (req, res) => {
  try {
    const { tool = 'powershell', target = 'localhost' } = req.body;
    const result = launchNativeTool(tool, target);
    logAction({
      userId: req.user.id,
      username: req.user.username,
      role: req.user.role,
      action: 'NATIVE_TOOL_LAUNCHED',
      resource: `${tool}:${target}`,
      details: result.message || result.error
    });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Launch error: ' + err.message });
  }
});

module.exports = router;
