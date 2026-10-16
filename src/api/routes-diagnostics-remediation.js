/**
 * EJII Host Diagnostics & Autonomous Remediation API Routes
 * Exposes 4-pillar host hardware inspection, process explorer, and audited remediation recipes.
 */

'use strict';

const express = require('express');
const router = express.Router();
const { hostDiagnosticsEngine } = require('../systems/diagnostics/host-diagnostics-engine');
const { autonomousRemediationEngine } = require('../systems/remediation/autonomous-remediation-engine');
const { aiBrain } = require('../core/ai-brain');
const { authenticate, requireRole } = require('./middleware');

// Public or Operator-accessible audit retrieval
router.get('/host/audit', async (req, res) => {
  try {
    const forceRefresh = req.query.force === 'true';
    const audit = await hostDiagnosticsEngine.runFullSystemAudit(forceRefresh);

    // AI Brain plain English synthesis
    let brainSynthesis = null;
    try {
      brainSynthesis = aiBrain.evaluateHostHealth(audit);
    } catch (e) {
      brainSynthesis = {
        summary: `Host operational: ${audit.overallStatus}. ${audit.anomalies.length} anomaly(ies) observed.`,
        recommendedAction: audit.stagedRecipes[0] || 'none'
      };
    }

    res.json({
      success: true,
      timestamp: audit.timestamp,
      host: audit.host,
      overallStatus: audit.overallStatus,
      pillars: audit.pillars,
      anomalies: audit.anomalies,
      stagedRecipes: audit.stagedRecipes,
      brainSynthesis
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Real Process Explorer Table
router.get('/host/processes', async (req, res) => {
  try {
    const procs = await hostDiagnosticsEngine.getProcessTable();
    res.json({
      success: true,
      count: procs.length,
      processes: procs
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Active TCP Socket Table
router.get('/host/sockets', async (req, res) => {
  try {
    const sockets = await hostDiagnosticsEngine.getSocketTable();
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
router.get('/remediation/recipes', (req, res) => {
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

// Remediation Dry-Run Preview
router.post('/remediation/preview', async (req, res) => {
  try {
    const { recipeId, params } = req.body || {};
    if (!recipeId) {
      return res.status(400).json({ success: false, error: "Missing required parameter 'recipeId'." });
    }
    const preview = await autonomousRemediationEngine.executePreview(recipeId, params || {});
    res.json({
      success: true,
      preview
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// Execute Audited Remediation (Requires authentication & OPERATOR role)
router.post('/remediation/execute', authenticate, requireRole('OPERATOR'), async (req, res) => {
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

    const outcome = await autonomousRemediationEngine.executeRemediation(recipeId, params || {}, userContext);
    res.json({
      success: outcome.success,
      outcome
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// Remediation Audit Log
router.get('/remediation/log', authenticate, requireRole('OPERATOR'), (req, res) => {
  try {
    const limit = Math.min(100, parseInt(req.query.limit || 50, 10));
    const logs = autonomousRemediationEngine.getRemediationLog(limit);
    res.json({
      success: true,
      total: logs.length,
      logs
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
