/**
 * EJII Host Diagnostics & Autonomous Remediation API Routes
 * Mount point: /api/diagnostics
 * Provides live 4-pillar hardware inspection, dry-run remediation preview with HMAC action tokens,
 * and authenticated remediation execution with tamper-resistant audit verification.
 */

'use strict';

const express = require('express');
const router = express.Router();
const { hostDiagnosticsEngine } = require('../systems/diagnostics/host-diagnostics-engine');
const { autonomousRemediationEngine } = require('../systems/remediation/autonomous-remediation-engine');
const { authenticate, requireRole, requirePermission } = require('./middleware');
const { verifyAuditLogIntegrity, getAuditLogs } = require('../core/audit-logger');

// Full 4-Pillar Host Diagnostic Audit
router.get('/host/audit', authenticate, async (req, res) => {
  try {
    const forceFresh = req.query.fresh === 'true';
    const audit = await hostDiagnosticsEngine.collectFullAudit(forceFresh);
    res.json({
      success: true,
      timestamp: new Date().toISOString(),
      ...audit
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Process Explorer Table
router.get('/host/processes', authenticate, async (req, res) => {
  try {
    const limit = Math.max(1, Math.min(100, parseInt(req.query.limit, 10) || 50));
    const processes = await hostDiagnosticsEngine.getProcessList(limit);
    res.json({
      success: true,
      count: processes.length,
      processes
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Live Network Sockets Matrix
router.get('/host/sockets', authenticate, async (req, res) => {
  try {
    const sockets = await hostDiagnosticsEngine.getSocketList();
    res.json({
      success: true,
      count: sockets.length,
      sockets
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Recipe Catalog
router.get('/remediation/recipes', authenticate, (req, res) => {
  try {
    const recipes = autonomousRemediationEngine.getRecipeCatalog();
    res.json({
      success: true,
      count: recipes.length,
      recipes
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Remediation Dry-Run Preview with Cryptographic Action Token (F-11, S-05)
router.post('/remediation/preview', authenticate, async (req, res) => {
  try {
    const { recipeId, params } = req.body || {};
    if (!recipeId) {
      return res.status(400).json({ success: false, error: "Missing required parameter 'recipeId'." });
    }

    const userContext = {
      role: (req.user.role || 'OPERATOR').toUpperCase(),
      username: req.user.username || 'operator',
      id: req.user.id
    };

    const preview = await autonomousRemediationEngine.executePreview(recipeId, params || {}, userContext);
    res.json({
      success: true,
      preview
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// Execute Audited Remediation (Requires authentication & host.remediation.execute capability: ADMIN or SYSADMIN)
router.post('/remediation/execute', authenticate, requireRole('ADMIN', 'SYSADMIN'), async (req, res) => {
  try {
    const userContext = {
      role: (req.user.role || 'SYSADMIN').toUpperCase(),
      username: req.user.username || 'operator',
      id: req.user.id
    };

    const outcome = await autonomousRemediationEngine.executeRemediation(req.body, userContext);
    res.json({
      success: outcome.success,
      outcome
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// Remediation Audit Trail
router.get('/remediation/log', authenticate, (req, res) => {
  try {
    const limit = Math.max(1, Math.min(100, parseInt(req.query.limit, 10) || 50));
    const memoryLogs = autonomousRemediationEngine.getRemediationLog(limit);
    const fileAuditLogs = getAuditLogs(limit);

    res.json({
      success: true,
      total: fileAuditLogs.length || memoryLogs.length,
      logs: fileAuditLogs.length > 0 ? fileAuditLogs : memoryLogs
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Cryptographic Audit Trail Verification Endpoint (F-04)
router.get('/remediation/audit-verify', authenticate, requireRole('ADMIN', 'SYSADMIN', 'ANALYST'), (req, res) => {
  try {
    const verification = verifyAuditLogIntegrity();
    res.json({
      success: true,
      verification
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Rolling Telemetry Trends & Velocity Analysis (Section 5)
router.get(['/host/trends', '/trends'], authenticate, (req, res) => {
  try {
    const windowSec = Math.max(10, parseInt(req.query.window, 10) || 300);
    const analysis = hostDiagnosticsEngine.getTrendAnalysis(windowSec);
    res.json({
      success: true,
      ...analysis
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
