/**
 * EJII Automation API Routes
 * Safe execution, dual-custody approval gates, and dry-run simulations.
 */

const express = require('express');
const router = express.Router();
const { authenticate, requireRole } = require('./middleware');
const { ROLES } = require('../core/security');
const { db } = require('../db/database');
const { requestAction, reviewAction, executeAction } = require('../automation/execution-engine');

router.use(authenticate);

/**
 * GET /api/automation/actions
 */
router.get('/actions', (req, res) => {
  const actions = db.prepare(`
    SELECT a.*, u.username as requester_username, u.full_name as requester_fullname,
           appr.username as approver_username
    FROM automation_actions a
    JOIN users u ON a.requested_by_id = u.id
    LEFT JOIN users appr ON a.approved_by_id = appr.id
    ORDER BY a.requested_at DESC LIMIT 50
  `).all();

  res.json({ count: actions.length, actions });
});

/**
 * POST /api/automation/request
 */
router.post('/request', requireRole(ROLES.SYSADMIN, ROLES.NETWORK_ADMIN, ROLES.APP_OWNER), (req, res) => {
  const { actionType, targetHost = 'localhost', targetResource, parameters = {}, dryRun = false } = req.body;

  if (!actionType) {
    return res.status(400).json({ error: 'actionType is required.' });
  }

  const result = requestAction({
    actionType,
    targetHost,
    targetResource,
    parameters,
    user: req.user,
    dryRun: Boolean(dryRun)
  });

  if (!result.success) {
    return res.status(400).json(result);
  }

  res.json(result);
});

/**
 * POST /api/automation/actions/:id/review
 * Application Owner Dual-Custody Approval Gate
 */
router.post('/actions/:id/review', requireRole(ROLES.APP_OWNER), (req, res) => {
  const { approved, comment = '' } = req.body;

  if (typeof approved !== 'boolean') {
    return res.status(400).json({ error: 'approved boolean field is required.' });
  }

  const result = reviewAction(req.params.id, {
    approved,
    comment,
    user: req.user
  });

  if (!result.success) {
    return res.status(400).json(result);
  }

  res.json(result);
});

/**
 * POST /api/automation/actions/:id/execute
 */
router.post('/actions/:id/execute', requireRole(ROLES.SYSADMIN, ROLES.APP_OWNER), async (req, res) => {
  try {
    const result = await executeAction(req.params.id, req.user);

    if (!result.success) {
      return res.status(400).json(result);
    }

    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, error: 'Execution engine error: ' + err.message });
  }
});

module.exports = router;
