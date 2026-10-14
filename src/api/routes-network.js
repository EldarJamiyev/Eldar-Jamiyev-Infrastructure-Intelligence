/**
 * EJII Network Management API Routes
 * High-precision tools for Network Administrators: SNMP walking, port sweeps, TLS audits, topology DAG.
 */

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { authenticate, requireRole } = require('./middleware');
const { ROLES } = require('../core/security');
const { scanPorts } = require('../protocols/tcp-port');
const { checkPropagation } = require('../protocols/dns-diag');
const { auditTls } = require('../protocols/tls-audit');
const { getSystemInfo, walkOid, STANDARD_OIDS } = require('../protocols/snmp-engine');
const { getDependencyTopology } = require('../core/rca-engine');
const { db } = require('../db/database');
const { logAction } = require('../core/audit-logger');

// Restrict all routes in this file to Network Admins, Sysadmins, and App Owners
router.use(authenticate, requireRole(ROLES.NETWORK_ADMIN, ROLES.SYSADMIN, ROLES.APP_OWNER));

/**
 * POST /api/network/port-scan
 */
router.post('/port-scan', async (req, res) => {
  try {
    const { host, ports, concurrency = 10, timeoutMs = 2000 } = req.body;
    if (!host) return res.status(400).json({ error: 'Target host is required.' });

    const safeConcurrency = Math.min(Math.max(1, parseInt(concurrency, 10) || 10), 100);
    const safeTimeoutMs = Math.min(Math.max(200, parseInt(timeoutMs, 10) || 2000), 10000);

    let safePorts = null;
    if (Array.isArray(ports)) {
      safePorts = ports
        .map(p => parseInt(p, 10))
        .filter(p => !isNaN(p) && p >= 1 && p <= 65535)
        .slice(0, 1000); // Prevent unbounded port lists
    }

    const result = await scanPorts(host, safePorts, safeConcurrency, safeTimeoutMs);

    logAction({
      userId: req.user.id,
      username: req.user.username,
      role: req.user.role,
      action: 'NETWORK_PORT_SCAN',
      resource: host,
      details: `Scanned ${result.totalScanned} ports on ${host}. Open: ${result.openCount}, Filtered: ${result.filteredCount}`
    });

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Port scan failed: ' + err.message });
  }
});

/**
 * POST /api/network/dns-propagation
 */
router.post('/dns-propagation', async (req, res) => {
  const { domain, recordType = 'A' } = req.body;
  if (!domain) return res.status(400).json({ error: 'Domain is required.' });

  const result = await checkPropagation(domain, recordType);

  logAction({
    userId: req.user.id,
    username: req.user.username,
    role: req.user.role,
    action: 'NETWORK_DNS_PROPAGATION',
    resource: domain,
    details: `Propagation check for ${domain} [${recordType}]: Consistent: ${result.isConsistent}`
  });

  res.json(result);
});

/**
 * POST /api/network/tls-audit
 */
router.post('/tls-audit', async (req, res) => {
  const { host, port = 443, timeoutMs = 4000 } = req.body;
  if (!host) return res.status(400).json({ error: 'Host is required.' });

  const result = await auditTls(host, parseInt(port, 10) || 443, timeoutMs);

  logAction({
    userId: req.user.id,
    username: req.user.username,
    role: req.user.role,
    action: 'NETWORK_TLS_AUDIT',
    resource: `${host}:${port}`,
    details: `TLS Audit: ${result.success ? `Protocol ${result.protocol}, Days remaining: ${result.certificate.daysRemaining}` : `Failed: ${result.error}`}`
  });

  res.json(result);
});

/**
 * POST /api/network/snmp
 */
router.post('/snmp', async (req, res) => {
  const { host, community = 'public', port = 161, mode = 'system', rootOid = null } = req.body;
  if (!host) return res.status(400).json({ error: 'Host is required.' });

  let result;
  if (mode === 'walk') {
    result = await walkOid(host, rootOid || STANDARD_OIDS.ifDescr, community, parseInt(port, 10) || 161);
  } else {
    result = await getSystemInfo(host, community, parseInt(port, 10) || 161);
  }

  logAction({
    userId: req.user.id,
    username: req.user.username,
    role: req.user.role,
    action: 'NETWORK_SNMP_QUERY',
    resource: `${host}:${port}`,
    details: `SNMP ${mode}: Success: ${result.success}`
  });

  res.json(result);
});

/**
 * GET /api/network/topology
 */
router.get('/topology', (req, res) => {
  const { nodes } = getDependencyTopology();
  res.json({ nodes });
});

/**
 * POST /api/network/topology/node
 */
router.post('/topology/node', requireRole(ROLES.NETWORK_ADMIN, ROLES.APP_OWNER), (req, res) => {
  const { name, hostname_or_ip, type, parent_id, snmp_community = 'public', snmp_version = '2c', check_interval_sec = 30 } = req.body;

  if (!name || !hostname_or_ip || !type) {
    return res.status(400).json({ error: 'name, hostname_or_ip, and type are required.' });
  }

  // Validate parent_id if provided
  if (parent_id) {
    const parentNode = db.prepare('SELECT id FROM nodes WHERE id = ?').get(parent_id);
    if (!parentNode) {
      return res.status(400).json({ error: `Specified parent node [${parent_id}] does not exist.` });
    }
  }

  const id = 'NODE-' + crypto.randomBytes(4).toString('hex').toUpperCase();

  db.prepare(`
    INSERT INTO nodes (id, name, hostname_or_ip, type, parent_id, snmp_community, snmp_version, check_interval_sec, status, last_checked)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'unknown', ?)
  `).run(
    id,
    name.trim(),
    hostname_or_ip.trim(),
    type.trim(),
    parent_id || null,
    snmp_community,
    snmp_version,
    parseInt(check_interval_sec, 10) || 30,
    new Date().toISOString()
  );

  logAction({
    userId: req.user.id,
    username: req.user.username,
    role: req.user.role,
    action: 'TOPOLOGY_NODE_CREATED',
    resource: id,
    details: `Added node [${name}] (${hostname_or_ip}) of type [${type}]`
  });

  res.json({ success: true, nodeId: id });
});

/**
 * DELETE /api/network/topology/node/:id
 */
router.delete('/topology/node/:id', requireRole(ROLES.NETWORK_ADMIN, ROLES.APP_OWNER), (req, res) => {
  const nodeId = req.params.id;

  const node = db.prepare('SELECT * FROM nodes WHERE id = ?').get(nodeId);
  if (!node) {
    return res.status(404).json({ error: 'Node not found.' });
  }

  db.prepare('DELETE FROM nodes WHERE id = ?').run(nodeId);

  logAction({
    userId: req.user.id,
    username: req.user.username,
    role: req.user.role,
    action: 'TOPOLOGY_NODE_DELETED',
    resource: nodeId,
    details: `Deleted node [${node.name}] (${node.hostname_or_ip})`
  });

  res.json({ success: true, message: 'Node deleted successfully.' });
});

module.exports = router;
