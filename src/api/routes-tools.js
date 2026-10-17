/**
 * EJII Diagnostic Tools & Sandboxed Execution API Routes
 * Mount point: /api/tools
 * Provides authenticated, schema-validated execution of authorized network diagnostics.
 */

'use strict';

const express = require('express');
const router = express.Router();
const { toolSandbox, ToolExecutionError } = require('../core/tool-sandbox');
const { authenticate } = require('./middleware');
const { isSafeNetworkTarget } = require('../core/ai-brain');

// Mandatory cryptographic authentication on all diagnostic tool routes
router.use(authenticate);

/**
 * Extract user context strictly from verified server-side session (req.user).
 * ZERO TRUST: Client-sent headers (e.g. X-EJII-Role, X-EJII-User) are strictly rejected.
 */
function extractUserContext(req) {
  if (!req.user) {
    throw new ToolExecutionError('Authentication required. Cryptographically verified session token missing.', 401);
  }
  return {
    role: (req.user.role || 'READONLY').toUpperCase(),
    username: req.user.username || 'unknown',
    id: req.user.id
  };
}

/**
 * GET /api/tools/roster
 * Return list of all available diagnostic tools, schemas, and required RBAC roles
 */
router.get('/roster', (req, res) => {
  try {
    const roster = toolSandbox.getToolRoster();
    res.json({
      success: true,
      timestamp: new Date().toISOString(),
      tools: roster
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/tools/execute
 * Execute a sandboxed diagnostic probe with strict schema validation
 */
router.post('/execute', async (req, res) => {
  const { tool, params } = req.body || {};

  if (!tool) {
    return res.status(400).json({
      success: false,
      error: "Missing required parameter 'tool' in request body."
    });
  }

  const targetHost = params && (params.target || params.ip || params.domain || params.host);
  if (targetHost && !isSafeNetworkTarget(String(targetHost).trim())) {
    return res.status(400).json({
      success: false,
      error: 'Target rejected by SSRF defense policy',
      code: 'SSRF_REJECTED'
    });
  }

  const userContext = extractUserContext(req);

  try {
    const output = await toolSandbox.executeTool(tool, params || {}, userContext);
    res.json({
      success: true,
      data: output
    });
  } catch (err) {
    if (err instanceof ToolExecutionError) {
      return res.status(err.statusCode || 400).json({
        success: false,
        error: err.message,
        code: err.name
      });
    }
    res.status(500).json({
      success: false,
      error: `Internal tool execution failure: ${err.message}`
    });
  }
});

/**
 * GET /api/tools/audit
 * View recent audit log entries
 */
router.get('/audit', (req, res) => {
  const userContext = extractUserContext(req);
  const allowed = ['ADMIN', 'NETWORK_ADMIN', 'SYSADMIN', 'ANALYST'];
  if (!allowed.includes(userContext.role)) {
    return res.status(403).json({ error: 'Access denied: Audit log requires ANALYST or ADMIN role.' });
  }

  const limit = Math.min(200, parseInt(req.query.limit || 50, 10));
  const logs = toolSandbox.getAuditLog(limit);
  res.json({
    success: true,
    total: logs.length,
    auditLog: logs
  });
});

module.exports = router;
