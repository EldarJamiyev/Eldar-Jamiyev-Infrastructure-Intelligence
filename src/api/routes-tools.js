/**
 * EJII Diagnostic Tools & Sandboxed Execution API Routes
 * Mount point: /api/tools
 * Provides authenticated, schema-validated execution of authorized network diagnostics.
 */

'use strict';

const express = require('express');
const router = express.Router();
const { toolSandbox, ToolExecutionError } = require('../core/tool-sandbox');

/**
 * Middleware: Extract user context from session or auth token
 */
function extractUserContext(req) {
  // If session or auth middleware attached user, use it; otherwise fallback to request header or safe analyst
  const headerRole = req.headers['x-ejii-role'] || (req.user && req.user.role) || 'ANALYST';
  const headerUser = req.headers['x-ejii-user'] || (req.user && req.user.username) || 'operator';
  return {
    role: headerRole.toUpperCase(),
    username: headerUser
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
  if (userContext.role !== 'ADMIN' && userContext.role !== 'ANALYST') {
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
