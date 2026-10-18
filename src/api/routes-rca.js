/**
 * EJII Evidence-Driven Root Cause Analysis (RCA) API Routes
 * Mount point: /api/rca
 * Exposes evidence-first diagnostic evaluations, dual-mode incident briefings, and probe execution.
 */

'use strict';

const express = require('express');
const router = express.Router();
const { aiBrain, isSafeNetworkTarget, resolveAndValidateTarget } = require('../core/ai-brain');
const { diagnosticReasoningEngine } = require('../core/rca-engine');
const { incidentBriefingProvider } = require('../core/llm-provider');
const { authenticate, requirePermission, requireRole } = require('./middleware');
const { SCHEMA_BOUNDS } = require('../core/brain-config-schema');
const { ragKnowledgeEngine } = require('../core/rag-knowledge-engine');
const { unifiedInvestigationEngine } = require('../core/unified-investigation-engine');

/**
 * POST /api/rca/generate
 * Generate deterministic, evidence-grounded RCA with dual-mode briefing
 */
router.post('/generate', async (req, res) => {
  try {
    const params = req.body || {};
    const target = params.target || params.destIp || '10.22.12.204';
    const port = parseInt(params.port || params.destPort || 443, 10);
    const incidentType = params.incidentType || 'TCP_SYN_TIMEOUT';

    // 1. Diagnose through AI Brain and Bayesian Reasoning Engine
    const brainDiag = aiBrain.diagnoseIncident({
      incidentType,
      destIp: target,
      destPort: port,
      ...params
    });

    // 2. Deep protocol RFC evaluation from DiagnosticReasoningEngine
    const deepDiag = diagnosticReasoningEngine.analyzeIncident({
      incidentType,
      destIp: target,
      destPort: port,
      ...params
    });

    // Merge dual-mode briefings and evidence ledger
    const dualBriefing = incidentBriefingProvider.synthesizeBriefing(
      { ...brainDiag, ...deepDiag },
      { destIp: target, destPort: port, ...params }
    );

    res.json({
      success: true,
      timestamp: new Date().toISOString(),
      target: `${target}:${port}`,
      incidentType,
      topHypothesis: brainDiag.topHypothesis || deepDiag.expertDiagnosticMode?.rankedHypotheses?.[0],
      rankedHypotheses: brainDiag.rankedHypotheses || deepDiag.expertDiagnosticMode?.rankedHypotheses || [],
      distinguishingProbes: brainDiag.distinguishingProbes || deepDiag.expertDiagnosticMode?.recommendedDistinguishingTests || [],
      briefing: dualBriefing,
      expertAnalysis: deepDiag.expertDiagnosticMode || null,
      simpleSummary: deepDiag.simpleOperatorMode || dualBriefing.simpleOperatorMode
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: `RCA Generation failed: ${err.message}`
    });
  }
});

/**
 * GET /api/rca/briefing
 * Return current real-time executive NOC briefing
 */
router.get('/briefing', (req, res) => {
  try {
    const activeIncidents = Array.from(aiBrain.activeIncidents.values());

    if (activeIncidents.length > 0) {
      const topIncident = activeIncidents[activeIncidents.length - 1];
      return res.json({
        success: true,
        status: 'ACTIVE_INCIDENT',
        incidentKey: topIncident.incidentKey,
        target: topIncident.target,
        timestamp: topIncident.updatedAt,
        briefing: topIncident.briefing,
        activeIncidentsCount: activeIncidents.length
      });
    }

    // Nominal operation briefing
    const nominalBriefing = incidentBriefingProvider.synthesizeBriefing({
      incidentType: 'NORMAL_OPERATION',
      topHypothesis: {
        label: 'Nominal Infrastructure Health',
        confidence: 98,
        category: 'NOMINAL_OPERATION'
      },
      rankedHypotheses: [
        { rank: 1, label: 'Nominal Infrastructure Health', confidence: 98, category: 'NOMINAL_OPERATION' }
      ]
    }, {
      destIp: 'Internal Network',
      destPort: 0
    });

    res.json({
      success: true,
      status: 'NOMINAL',
      timestamp: new Date().toISOString(),
      briefing: nominalBriefing,
      activeIncidentsCount: 0
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/rca/history
 * Return recent RCA investigations
 */
router.get('/history', (req, res) => {
  try {
    const limit = Math.min(100, parseInt(req.query.limit || 30, 10));
    const history = (aiBrain.incidentHistory || []).slice(-limit).reverse();
    res.json({
      success: true,
      total: history.length,
      history
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/rca/active
 * Return all currently active incidents
 */
router.get('/active', (req, res) => {
  try {
    const active = Array.from(aiBrain.activeIncidents.values()).map(inc => ({
      incidentKey: inc.incidentKey,
      incidentType: inc.incidentType,
      target: inc.target,
      destPort: inc.destPort,
      topHypothesis: inc.topHypothesis?.label,
      confidence: inc.topHypothesis?.confidence,
      createdAt: inc.createdAt,
      updatedAt: inc.updatedAt
    }));
    res.json({
      success: true,
      count: active.length,
      activeIncidents: active
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/rca/probe
 * Dispatch a distinguishing probe to refine an active RCA investigation
 */
router.post('/probe', authenticate, requirePermission('network.diagnostics.execute'), async (req, res) => {
  const { probeType, target, params } = req.body || {};
  if (!probeType || !target) {
    return res.status(400).json({ error: "Missing required fields 'probeType' and 'target'." });
  }

  if (!isSafeNetworkTarget(target)) {
    return res.status(400).json({
      success: false,
      error: `Security rejection: Target '${target}' is invalid or blocked by SSRF defense policy.`
    });
  }

  try {
    let result;
    if (probeType === 'PATH_MTU_DF_SWEEP' || probeType === 'pmtu_sweep') {
      result = await toolSandbox.executeTool('pmtu_sweep', { target, ...params }, { role: req.user?.role || 'ANALYST', username: req.user?.username || 'rca-agent' });
    } else if (probeType === 'ICMP_PING' || probeType === 'ping') {
      result = await toolSandbox.executeTool('ping', { target, ...params }, { role: req.user?.role || 'ANALYST', username: req.user?.username || 'rca-agent' });
    } else if (probeType === 'TCP_HANDSHAKE' || probeType === 'tcp_handshake') {
      const port = parseInt(params?.port || 443, 10);
      result = await toolSandbox.executeTool('tcp_handshake', { target, port, ...params }, { role: req.user?.role || 'ANALYST', username: req.user?.username || 'rca-agent' });
    } else {
      result = await aiBrain.executeDistinguishingProbe(probeType, target, params || {});
    }

    res.json({
      success: true,
      probeType,
      target,
      result
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: `Probe execution failed: ${err.message}`
    });
  }
});

/**
 * GET /api/rca/brain/self-update-status
 * Returns live AI Brain dynamic configuration, drift telemetry, and circuit breaker status.
 */
router.get('/brain/self-update-status', authenticate, requirePermission('telemetry.read'), (req, res) => {
  try {
    const status = aiBrain.getSelfUpdateStatus();
    res.json({
      success: true,
      status,
      schemaBounds: SCHEMA_BOUNDS
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/rca/brain/self-update/optimize
 * Triggers an autonomous or operator-overridden AI Brain self-optimization cycle through the sandbox gate.
 */
router.post('/brain/self-update/optimize', authenticate, requirePermission('system.config.manage'), async (req, res) => {
  try {
    const { proposedConfigOverride, forceResetCircuitBreaker } = req.body || {};
    const result = await aiBrain.optimizeBrainParameters({
      triggerSource: `OPERATOR_API:${req.user?.username || 'admin'}`,
      proposedConfigOverride,
      forceResetCircuitBreaker: Boolean(forceResetCircuitBreaker)
    });

    if (!result.success) {
      return res.status(400).json(result);
    }

    res.json(result);
  } catch (err) {
    res.status(400).json({
      success: false,
      status: 'OPTIMIZATION_REJECTED',
      error: err.message
    });
  }
});

/**
 * POST /api/rca/brain/self-update/rollback
 * Restores the prior stable AI Brain configuration in memory and on disk.
 */
router.post('/brain/self-update/rollback', authenticate, requirePermission('system.config.manage'), (req, res) => {
  try {
    const result = aiBrain.rollbackToStable(null, `Operator manual rollback by ${req.user?.username || 'admin'}`);
    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/rca/brain/investigate
 * Runs an autonomous multi-step diagnostic investigation on physical wire using AI Brain.
 */
router.post('/brain/investigate', authenticate, requirePermission('network.diagnostics.execute'), async (req, res) => {
  try {
    const { target, targetIp, port, targetPort, maxSteps } = req.body || {};
    const candidateIp = targetIp || target || '127.0.0.1';
    const candidatePort = parseInt(targetPort || port || 443, 10);
    const steps = parseInt(maxSteps || 4, 10);

    try {
      await resolveAndValidateTarget(candidateIp);
    } catch (secErr) {
      return res.status(400).json({
        success: false,
        error: `Security rejection: Target '${candidateIp}' is invalid or blocked by SSRF defense policy (${secErr.message}).`
      });
    }

    const outcome = await aiBrain.runAutonomousInvestigation({
      targetIp: candidateIp,
      targetPort: candidatePort,
      maxSteps: steps
    });

    if (!outcome.success) {
      return res.status(400).json(outcome);
    }

    res.json(outcome);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/rca/brain/feedback
 * Records explicit operator feedback on an incident root cause hypothesis and updates calibration weights.
 */
router.post('/brain/feedback', authenticate, requirePermission('network.diagnostics.execute'), (req, res) => {
  try {
    const { incidentKey, verdict, confirmedHypothesisId, operatorNotes } = req.body || {};
    if (!incidentKey || !verdict || !confirmedHypothesisId) {
      return res.status(400).json({
        success: false,
        error: "Missing required parameters: 'incidentKey', 'verdict', and 'confirmedHypothesisId' are required."
      });
    }

    const outcome = aiBrain.recordOperatorFeedback({
      incidentKey,
      verdict,
      confirmedHypothesisId,
      operatorNotes,
      userId: req.user?.username || 'operator'
    });

    res.json(outcome);
  } catch (err) {
    res.status(400).json({
      success: false,
      error: `Feedback processing failed: ${err.message}`
    });
  }
});

const { aiModelOrchestrator } = require('../core/ai-model-orchestrator');

/**
 * GET /api/rca/brain/orchestrator-status
 * Multi-Model AI Orchestrator status, conditional gate config, and localOnlyPolicy state
 */
router.get('/brain/orchestrator-status', authenticate, (req, res) => {
  try {
    const status = aiModelOrchestrator.getStatus();
    res.json({
      success: true,
      status,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/rca/brain/orchestrator-config
 * Updates Multi-Model AI Orchestrator settings (localOnlyPolicy, confidenceThreshold, preferredProvider)
 */
router.post('/brain/orchestrator-config', authenticate, requirePermission('system.config.manage'), (req, res) => {
  try {
    const updated = aiModelOrchestrator.updateConfig(req.body || {});
    res.json({
      success: true,
      message: 'AI Model Orchestrator configuration updated.',
      status: updated,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/rca/investigate-unified
 * Executes 5-stage cross-section guided investigation across all 5 EJII views
 */
router.post('/investigate-unified', authenticate, requirePermission('network.diagnostics.execute'), async (req, res) => {
  try {
    const report = await unifiedInvestigationEngine.runGuidedInvestigation(req.body || {});
    res.json({
      success: true,
      investigationId: report.investigationId,
      report,
      ...report,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    const status = err.message && err.message.includes('SECURITY_VIOLATION') ? 403 : 500;
    res.status(status).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/rca/investigate-unified/:id/verify
 * Re-tests target endpoint post-fix to confirm resolution
 */
router.post('/investigate-unified/:id/verify', authenticate, requirePermission('network.diagnostics.execute'), async (req, res) => {
  try {
    const result = await unifiedInvestigationEngine.verifyInvestigationResolution(req.params.id);
    res.json({
      success: true,
      ...result,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    const status = err.message && err.message.includes('not found') ? 404 : 500;
    res.status(status).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/rca/rag/search
 * Queries local RAG knowledge base using BM25 ranking
 */
router.get('/rag/search', authenticate, requirePermission('telemetry.read'), (req, res) => {
  try {
    const q = req.query.q || '';
    const topK = Number(req.query.limit) || 5;
    const results = ragKnowledgeEngine.retrieveRelevantContext(q, { topK });
    res.json({
      success: true,
      query: q,
      count: results.length,
      results,
      citations: results,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/rca/brain/second-opinion
 * Runs second-opinion verification on high-impact incident hypotheses with RAG citations
 */
router.post('/brain/second-opinion', authenticate, requirePermission('telemetry.read'), async (req, res) => {
  try {
    const secondOpinion = await aiModelOrchestrator.verifyHighImpactDiagnosis({
      bayesianEvaluation: req.body?.evaluation || req.body?.bayesianEvaluation || {},
      telemetryContext: req.body?.context || req.body?.telemetryContext || {},
      ragEngine: ragKnowledgeEngine
    });
    res.json({
      success: true,
      secondOpinion,
      ...secondOpinion,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;

