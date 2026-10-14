/**
 * EJII Root Cause Analysis (RCA) API Routes
 * Incident tracking, correlation evaluation, and evidence review.
 */

const express = require('express');
const router = express.Router();
const { authenticate, requireRole } = require('./middleware');
const { ROLES } = require('../core/security');
const { db } = require('../db/database');
const { correlateAndReportIncident, resolveIncident } = require('../core/rca-engine');
const { realPing } = require('../protocols/icmp-ping');

router.use(authenticate);

/**
 * GET /api/rca/incidents
 */
router.get('/incidents', (req, res) => {
  const status = req.query.status;
  let query = `
    SELECT i.*, n.name as node_name, n.hostname_or_ip, n.type as node_type
    FROM incidents i
    JOIN nodes n ON i.primary_node_id = n.id
  `;
  const params = [];

  if (status) {
    query += ' WHERE i.status = ?';
    params.push(status);
  }

  query += ' ORDER BY i.detected_at DESC LIMIT 50';

  const incidents = db.prepare(query).all(...params);
  res.json({ count: incidents.length, incidents });
});

/**
 * GET /api/rca/incidents/:id
 */
router.get('/incidents/:id', (req, res) => {
  const incident = db.prepare(`
    SELECT i.*, n.name as node_name, n.hostname_or_ip, n.type as node_type, n.parent_id
    FROM incidents i
    JOIN nodes n ON i.primary_node_id = n.id
    WHERE i.id = ?
  `).get(req.params.id);

  if (!incident) {
    return res.status(404).json({ error: 'Incident not found.' });
  }

  res.json({ incident });
});

/**
 * POST /api/rca/correlate
 * Execute a live probe against a node and evaluate through the RCA DAG engine
 */
router.post('/correlate', requireRole(ROLES.NETWORK_ADMIN, ROLES.SYSADMIN, ROLES.APP_OWNER), async (req, res) => {
  try {
    const { nodeId } = req.body;
    if (!nodeId) return res.status(400).json({ error: 'nodeId is required.' });

    const node = db.prepare('SELECT * FROM nodes WHERE id = ?').get(nodeId);
    if (!node) return res.status(404).json({ error: 'Node not found.' });

    // Execute real live probe
    const pingRes = await realPing(node.hostname_or_ip, 2, 1000);

    if (!pingRes.success || pingRes.packetLossPct === 100) {
      const correlation = correlateAndReportIncident({
        nodeId: node.id,
        metricType: 'ping',
        errorDescription: pingRes.error || '100% Packet Loss on ICMP Probe',
        telemetryPayload: pingRes
      });
      return res.json({ probeResult: pingRes, correlation });
    }

    // If healthy, update node to healthy
    db.prepare("UPDATE nodes SET status = 'healthy', last_checked = ?, last_latency_ms = ? WHERE id = ?")
      .run(new Date().toISOString(), pingRes.avgRttMs || 0, node.id);

    res.json({
      probeResult: pingRes,
      status: 'NODE_HEALTHY',
      message: `Probe succeeded. Node ${node.name} is responding normally.`
    });
  } catch (err) {
    res.status(500).json({ error: 'Correlation failed: ' + err.message });
  }
});

/**
 * POST /api/rca/incidents/:id/resolve
 */
router.post('/incidents/:id/resolve', requireRole(ROLES.SYSADMIN, ROLES.NETWORK_ADMIN, ROLES.APP_OWNER), (req, res) => {
  const { notes = 'Resolved by operator.' } = req.body;
  const result = resolveIncident(req.params.id, req.user.id, req.user.username, req.user.role, notes);

  if (!result.success) {
    return res.status(400).json(result);
  }

  res.json(result);
});

module.exports = router;
