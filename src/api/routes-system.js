/**
 * EJII System Administrator API Routes
 * Real server and host metrics, services, process tables, and Windows Event Logs.
 */

const express = require('express');
const router = express.Router();
const { authenticate, requireRole } = require('./middleware');
const { ROLES } = require('../core/security');
const { getHostMetrics, getServices, getProcesses, getEventLogs } = require('../protocols/host-metrics');
// Restrict system administrator routes to Sysadmin and App Owner
router.use(authenticate, requireRole(ROLES.SYSADMIN, ROLES.NETWORK_ADMIN, ROLES.APP_OWNER));

/**
 * GET /api/system/host
 */
router.get('/host', async (req, res) => {
  try {
    const forceRefresh = req.query.refresh === 'true';
    const metrics = await getHostMetrics(forceRefresh);
    res.json(metrics);
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve host metrics: ' + err.message });
  }
});

/**
 * GET /api/system/services
 */
router.get('/services', async (req, res) => {
  try {
    const filter = req.query.filter || '';
    const services = await getServices(filter);
    res.json({ count: services.length, services });
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve services: ' + err.message });
  }
});

/**
 * GET /api/system/processes
 */
router.get('/processes', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit, 10) || 25;
    const processes = await getProcesses(limit);
    res.json({ count: processes.length, processes });
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve processes: ' + err.message });
  }
});

/**
 * GET /api/system/events
 */
router.get('/events', async (req, res) => {
  try {
    const logName = req.query.logName || 'System';
    const maxEvents = parseInt(req.query.limit, 10) || 15;
    const events = await getEventLogs(logName, maxEvents);
    res.json({ logName, count: events.length, events });
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve event logs: ' + err.message });
  }
});

module.exports = router;
