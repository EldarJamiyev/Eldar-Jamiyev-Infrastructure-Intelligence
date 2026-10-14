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
const { getArpTable } = require('../tools/ip-scanner');

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

/**
 * GET /api/network/assets
 * Enriched asset inventory with search, filters, and relationship context
 */
router.get('/assets', (req, res) => {
  const { type, status, is_managed, search } = req.query;
  let query = 'SELECT * FROM nodes WHERE 1=1';
  const params = [];

  if (type) {
    query += ' AND type = ?';
    params.push(type);
  }
  if (status) {
    query += ' AND status = ?';
    params.push(status);
  }
  if (is_managed !== undefined) {
    query += ' AND is_managed = ?';
    params.push(parseInt(is_managed, 10));
  }
  if (search) {
    query += ' AND (name LIKE ? OR hostname_or_ip LIKE ? OR mac_address LIKE ? OR vendor LIKE ? OR tags LIKE ?)';
    const searchWildcard = `%${search.trim()}%`;
    params.push(searchWildcard, searchWildcard, searchWildcard, searchWildcard, searchWildcard);
  }

  query += ' ORDER BY created_at DESC, id ASC';

  // Fallback to order by id if created_at does not exist in nodes
  try {
    const assets = db.prepare(query).all(...params);
    res.json({ count: assets.length, assets });
  } catch (err) {
    const fallbackQuery = query.replace('ORDER BY created_at DESC, id ASC', 'ORDER BY id ASC');
    const assets = db.prepare(fallbackQuery).all(...params);
    res.json({ count: assets.length, assets });
  }
});

/**
 * PUT /api/network/assets/:id
 * Update asset attributes, tags, assigned owner, and metadata
 */
router.put('/assets/:id', requireRole(ROLES.NETWORK_ADMIN, ROLES.SYSADMIN, ROLES.APP_OWNER), (req, res) => {
  const { name, vendor, os_name, os_version, model, serial_number, location, assigned_to, is_managed, tags, snmp_community, check_interval_sec } = req.body;
  const asset = db.prepare('SELECT * FROM nodes WHERE id = ?').get(req.params.id);

  if (!asset) {
    return res.status(404).json({ error: 'Asset not found.' });
  }

  const updates = [];
  const params = [];

  if (name) { updates.push('name = ?'); params.push(name.trim()); }
  if (vendor !== undefined) { updates.push('vendor = ?'); params.push(vendor ? vendor.trim() : null); }
  if (os_name !== undefined) { updates.push('os_name = ?'); params.push(os_name ? os_name.trim() : null); }
  if (os_version !== undefined) { updates.push('os_version = ?'); params.push(os_version ? os_version.trim() : null); }
  if (model !== undefined) { updates.push('model = ?'); params.push(model ? model.trim() : null); }
  if (serial_number !== undefined) { updates.push('serial_number = ?'); params.push(serial_number ? serial_number.trim() : null); }
  if (location !== undefined) { updates.push('location = ?'); params.push(location ? location.trim() : null); }
  if (assigned_to !== undefined) { updates.push('assigned_to = ?'); params.push(assigned_to ? assigned_to.trim() : null); }
  if (is_managed !== undefined) { updates.push('is_managed = ?'); params.push(is_managed ? 1 : 0); }
  if (tags !== undefined) { updates.push('tags = ?'); params.push(tags ? tags.trim() : null); }
  if (snmp_community !== undefined) { updates.push('snmp_community = ?'); params.push(snmp_community.trim()); }
  if (check_interval_sec !== undefined) { updates.push('check_interval_sec = ?'); params.push(parseInt(check_interval_sec, 10) || 30); }

  if (updates.length === 0) {
    return res.status(400).json({ error: 'No fields to update.' });
  }

  params.push(req.params.id);
  db.prepare(`UPDATE nodes SET ${updates.join(', ')} WHERE id = ?`).run(...params);

  logAction({
    userId: req.user.id,
    username: req.user.username,
    role: req.user.role,
    action: 'ASSET_UPDATED',
    resource: req.params.id,
    details: `Updated asset [${name || asset.name}] (${asset.hostname_or_ip})`
  });

  res.json({ success: true, message: 'Asset updated successfully.' });
});

/**
 * POST /api/network/discovery/import-arp
 * Read real host ARP table, filter broadcast/multicast, and register discovered devices
 */
router.post('/discovery/import-arp', requireRole(ROLES.NETWORK_ADMIN, ROLES.APP_OWNER), async (req, res) => {
  try {
    const arpEntries = await getArpTable();
    const existingNodes = db.prepare('SELECT hostname_or_ip, mac_address FROM nodes').all();
    const existingIps = new Set(existingNodes.map(n => n.hostname_or_ip));

    const imported = [];
    const now = new Date().toISOString();

    const insertStmt = db.prepare(`
      INSERT INTO nodes (
        id, name, hostname_or_ip, type, parent_id, status, last_checked,
        mac_address, vendor, discovery_source, is_managed, tags
      ) VALUES (?, ?, ?, ?, 'NODE-GW-01', 'unknown', ?, ?, ?, 'arp_discovery', 0, 'discovered,unmanaged')
    `);

    for (const entry of arpEntries) {
      const ip = entry.ip;
      // Skip loopback, multicast (224.x.x.x - 239.x.x.x), and broadcast (255.255.255.255)
      if (ip.startsWith('224.') || ip.startsWith('239.') || ip === '255.255.255.255' || ip === '127.0.0.1') {
        continue;
      }
      if (existingIps.has(ip)) {
        // Update MAC address if missing
        db.prepare("UPDATE nodes SET mac_address = ?, vendor = COALESCE(vendor, ?) WHERE hostname_or_ip = ? AND mac_address IS NULL")
          .run(entry.mac, entry.vendor, ip);
        continue;
      }

      const id = 'NODE-DISC-' + crypto.randomBytes(3).toString('hex').toUpperCase();
      const nodeName = `${entry.vendor !== 'Unknown Vendor' ? entry.vendor : 'Host'} (${ip})`;

      insertStmt.run(id, nodeName, ip, 'workstation', now, entry.mac, entry.vendor);
      existingIps.add(ip);
      imported.push({ id, ip, mac: entry.mac, vendor: entry.vendor });
    }

    logAction({
      userId: req.user.id,
      username: req.user.username,
      role: req.user.role,
      action: 'ARP_DISCOVERY_IMPORTED',
      resource: 'NETWORK_DISCOVERY',
      details: `Imported ${imported.length} new devices from authentic ARP table into asset inventory.`
    });

    res.json({
      success: true,
      totalArpEntries: arpEntries.length,
      importedCount: imported.length,
      imported
    });
  } catch (err) {
    res.status(500).json({ error: 'ARP discovery import failed: ' + err.message });
  }
});

/**
 * GET /api/network/telemetry/:nodeId
 * Time-series telemetry query for latency and availability trends
 */
router.get('/telemetry/:nodeId', (req, res) => {
  const limit = Math.min(Math.max(1, parseInt(req.query.limit, 10) || 50), 200);
  const records = db.prepare(`
    SELECT id, node_id, metric_type, metric_name, value, unit, status, timestamp
    FROM telemetry_history
    WHERE node_id = ?
    ORDER BY timestamp DESC LIMIT ?
  `).all(req.params.nodeId, limit);

  res.json({
    nodeId: req.params.nodeId,
    count: records.length,
    telemetry: records.reverse() // Return chronological for graphing
  });
});

module.exports = router;
