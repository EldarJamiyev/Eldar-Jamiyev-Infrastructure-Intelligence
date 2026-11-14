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
const { remediationGovernanceEngine } = require('../core/governance/remediation-governance');
const { authenticate, requireRole, requirePermission, validateMutatingCsrfOrigin } = require('./middleware');
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
router.post('/remediation/preview', authenticate, validateMutatingCsrfOrigin, async (req, res) => {
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
router.post('/remediation/execute', authenticate, requireRole('ADMIN', 'SYSADMIN'), validateMutatingCsrfOrigin, async (req, res) => {
  try {
    const userContext = {
      role: (req.user.role || 'SYSADMIN').toUpperCase(),
      username: req.user.username || 'operator',
      id: req.user.id
    };

    const govMode = remediationGovernanceEngine.getGovernanceMode();

    // 1. In ADVISORY mode, require explicit cryptographic HITL approval:
    // Either a signed preview actionToken (Phase 1 -> Phase 2 HITL workflow),
    // OR explicit governance approval credentials (approvalId & approvalToken).
    // Direct raw recipe executions ({ recipeId, params }) without either are strictly blocked.
    if (govMode === 'ADVISORY') {
      const { approvalId, approvalToken, actionToken } = req.body;
      if (approvalId && approvalToken) {
        const approval = remediationGovernanceEngine.approveRemediation(approvalId, userContext, approvalToken);
        if (!approval.success) {
          return res.status(403).json({
            success: false,
            error: `GOVERNANCE_GATE_BLOCKED: ${approval.error}`
          });
        }
      } else if (!actionToken) {
        return res.status(403).json({
          success: false,
          error: 'GOVERNANCE_GATE_BLOCKED: Governance mode is ADVISORY. Direct execution without a signed preview actionToken or cryptographic approval token (approvalId & approvalToken) is forbidden.'
        });
      }
    } else if (govMode === 'CONTROLLED_CANARY') {
      // 2. In CONTROLLED_CANARY mode, evaluate Damped Lyapunov Stability on telemetry trajectory if provided
      if (req.body.telemetryTrajectory && Array.isArray(req.body.telemetryTrajectory)) {
        const baseline = req.body.baselineMetric || { latencyMs: 20, packetLossPct: 0, cpuPct: 10 };
        const stability = remediationGovernanceEngine.evaluateDampedLyapunovStability(baseline, req.body.telemetryTrajectory);
        if (!stability.stable) {
          return res.status(409).json({
            success: false,
            error: `CANARY_STABILITY_VIOLATION: Damped Lyapunov stability check failed (${stability.verdict}). Fleet rollout halted.`,
            stability
          });
        }
      }
    } else if (govMode === 'RESTRICTED_AUTONOMOUS') {
      // 3. In RESTRICTED_AUTONOMOUS mode, verify script canonical integrity
      if (req.body.recipeId && req.body.scriptContent) {
        const check = remediationGovernanceEngine.verifyScriptIntegrity(req.body.recipeId, req.body.scriptContent);
        if (!check.valid) {
          return res.status(403).json({
            success: false,
            error: 'AUTONOMOUS_POLICY_VIOLATION: Script content failed canonical signature verification. Only approved canonical scripts can execute autonomously.'
          });
        }
      }
    }

    const outcome = await autonomousRemediationEngine.executeRemediation(req.body, userContext);

    // Chained audit record
    remediationGovernanceEngine.recordAuditEntry({
      actionId: outcome.recipeId || req.body.recipeId || 'REMEDIATION_EXEC',
      userId: userContext.username || userContext.id || 'admin',
      actionType: 'REMEDIATION_EXECUTED',
      target: req.body.target || req.body.targetHost || 'HOST_LOCAL',
      scriptSha256: outcome.scriptHash || 'N/A',
      status: outcome.success ? 'SUCCESS' : 'FAILED',
      details: {
        governanceMode: govMode,
        outcomeSuccess: outcome.success,
        error: outcome.error || null
      }
    });

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

// Dual-Custody Remediation Action Handlers
const { handleActionsList, handleActionReview } = require('./webauthn-automation');
router.get(['/actions', '/automation/actions'], authenticate, handleActionsList);
router.post(['/actions/:id/review', '/automation/actions/:id/review'], authenticate, requireRole('OPERATOR', 'NOC_OPERATOR', 'SYSADMIN', 'NETWORK_ADMIN', 'ADMIN'), handleActionReview);

module.exports = router;
