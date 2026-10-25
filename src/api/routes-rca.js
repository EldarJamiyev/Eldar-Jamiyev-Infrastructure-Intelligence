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

/**
 * GET /api/rca/notifications
 * Returns recent dispatched notifications from AI Brain & system events
 */
router.get('/notifications', authenticate, requirePermission('telemetry.read'), (req, res) => {
  try {
    const notifications = typeof aiBrain.getDispatchedNotifications === 'function'
      ? aiBrain.getDispatchedNotifications()
      : [];
    res.json({
      success: true,
      count: notifications.length,
      notifications,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/rca/brain/providers-health
 * Returns multi-model provider health matrix and deterministic routing status
 */
router.get('/brain/providers-health', authenticate, requirePermission('telemetry.read'), (req, res) => {
  try {
    const { aiModelOrchestrator } = require('../core/ai-model-orchestrator');
    const matrix = aiModelOrchestrator.getProviderHealthMatrix();
    res.json({
      success: true,
      matrix,
      ...matrix
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/rca/brain/counterfactual-simulate
 * Causal do-calculus simulation of candidate remediation actions
 */
router.post('/brain/counterfactual-simulate', authenticate, requirePermission('telemetry.read'), (req, res) => {
  try {
    const simulation = aiBrain.simulateCounterfactualFix(req.body || {});
    res.json({
      success: true,
      ...simulation,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/rca/brain/shared-outages
 * Correlates concurrent failing targets across subnets and parent switches/gateways
 */
router.get('/brain/shared-outages', authenticate, requirePermission('telemetry.read'), (req, res) => {
  try {
    const windowMs = parseInt(req.query.windowMs || 120000, 10);
    const result = aiBrain.correlateSharedUpstreamFaults(windowMs);
    res.json({
      success: true,
      ...result
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/rca/brain/context-window-preview
 * Previews token budgeting, exponential half-life temporal decay weighting,
 * and prioritized 3-tier context assembly for LLM prompts
 */
router.post('/brain/context-window-preview', authenticate, requirePermission('telemetry.read'), (req, res) => {
  try {
    const { ContextWindowManager } = require('../core/context-window-manager');
    const {
      maxTokens = 4096,
      halfLifeSec = 120,
      events = [],
      baselineSnapshot = null,
      runbookSnippets = [],
      activeIncidents = []
    } = req.body || {};

    const mgr = new ContextWindowManager({ maxContextTokens: maxTokens, halfLifeSec });
    const result = mgr.buildContextPayload({
      events,
      baselineSnapshot,
      runbookSnippets,
      activeIncidents
    });

    res.json({
      success: true,
      ...result
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/rca/brain/autonomous-workflow
 * Executes closed-loop autonomous goal-driven task planning, multi-step investigation,
 * episodic memory calibration, counterfactual simulation, and 8-invariant self-validation.
 */
router.post('/brain/autonomous-workflow', authenticate, requirePermission('network.diagnostics.execute'), async (req, res) => {
  try {
    const { goal, targetHost, targetPort, processName, deviceTypeHint } = req.body || {};
    const report = await aiBrain.planAndExecuteAutonomousWorkflow({
      goal,
      targetHost,
      targetPort,
      processName,
      deviceTypeHint,
      userRole: req.user?.role || 'ADMIN'
    });
    res.json({
      success: true,
      report
    });
  } catch (err) {
    res.status(err.message?.includes('SECURITY_VIOLATION') ? 400 : 500).json({
      success: false,
      error: err.message
    });
  }
});

/**
 * GET /api/rca/brain/autonomous-workflow/history
 * Returns recent persisted autonomous workflow executions from SQLite WAL
 */
router.get('/brain/autonomous-workflow/history', authenticate, requirePermission('telemetry.read'), (req, res) => {
  try {
    const { brainPersistenceRepository } = require('../db/brain-persistence-repository');
    const limit = parseInt(req.query.limit || 20, 10);
    const history = typeof brainPersistenceRepository.getRecentAutonomousWorkflowRuns === 'function'
      ? brainPersistenceRepository.getRecentAutonomousWorkflowRuns(limit)
      : [];
    res.json({
      success: true,
      count: history.length,
      history
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/rca/gitops/drift
 * Returns declarative GitOps Infrastructure-as-Code (IaC) drift report
 */
router.get('/gitops/drift', authenticate, requirePermission('telemetry.read'), (req, res) => {
  try {
    const { gitopsReconciliationEngine } = require('../core/gitops-reconciliation-engine');
    const report = gitopsReconciliationEngine.detectInfrastructureDrift();
    res.json({
      success: true,
      report,
      ...report
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/rca/gitops/reconcile
 * Executes safe autonomous reconciliation of infrastructure drift
 */
router.post('/gitops/reconcile', authenticate, requirePermission('network.diagnostics.execute'), (req, res) => {
  try {
    const { gitopsReconciliationEngine } = require('../core/gitops-reconciliation-engine');
    const { autoHealSafeTopologyDrift = true } = req.body || {};
    const result = gitopsReconciliationEngine.reconcileDrift({ autoHealSafeTopologyDrift });
    res.json({
      success: true,
      result,
      ...result
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/rca/investigations/start
 * Starts a stateful Planner-Executor-Critic investigation session (EJII Phase 4)
 */
router.post('/investigations/start', async (req, res) => {
  try {
    const { investigationPlannerExecutorCritic } = require('../core/unified-investigation-engine');
    const { brainPersistenceRepository } = require('../db/brain-persistence-repository');

    const request = req.body || {};
    const operatorRole = req.user?.role || request.operatorRole || 'OPERATOR';

    const plan = investigationPlannerExecutorCritic.buildInvestigationPlan({
      ...request,
      operatorRole
    });

    // Execute investigation session
    const session = await investigationPlannerExecutorCritic.executeInvestigationSession(plan.sessionId);

    // Retrieve similar historical cases from CBR
    let similarHistoricalIncidents = [];
    if (brainPersistenceRepository && typeof brainPersistenceRepository.findSimilarHistoricalIncidents === 'function') {
      try {
        similarHistoricalIncidents = brainPersistenceRepository.findSimilarHistoricalIncidents(
          session.symptomType,
          session.evidenceLedger,
          5
        );
      } catch (_) {}
    }

    res.json({
      success: true,
      sessionId: session.sessionId,
      state: session.state,
      symptomType: session.symptomType,
      topHypothesisId: session.topHypothesisId,
      calibratedConfidence: session.calibratedConfidence,
      criticPassed: session.criticPassed,
      criticEvaluation: session.criticEvaluation,
      steps: session.steps,
      evidenceLedger: session.evidenceLedger,
      hypothesisHistory: session.hypothesisHistory,
      recommendedActions: session.recommendedActions,
      similarHistoricalIncidents,
      session
    });
  } catch (err) {
    res.status(500).json({ success: false, error: `Failed to start investigation: ${err.message}` });
  }
});

/**
 * GET /api/rca/investigations/:sessionId
 * Returns the complete investigation state, step DAG progress, and evidence ledger
 */
router.get('/investigations/:sessionId', (req, res) => {
  try {
    const { sessionId } = req.params;
    const { investigationPlannerExecutorCritic } = require('../core/unified-investigation-engine');
    const { brainPersistenceRepository } = require('../db/brain-persistence-repository');

    let session = investigationPlannerExecutorCritic.activeSessions.get(sessionId);
    if (!session && brainPersistenceRepository && typeof brainPersistenceRepository.getInvestigationSession === 'function') {
      session = brainPersistenceRepository.getInvestigationSession(sessionId);
    }

    if (!session) {
      return res.status(404).json({ success: false, error: `Investigation session ${sessionId} not found.` });
    }

    let similarHistoricalIncidents = [];
    if (brainPersistenceRepository && typeof brainPersistenceRepository.findSimilarHistoricalIncidents === 'function') {
      try {
        similarHistoricalIncidents = brainPersistenceRepository.findSimilarHistoricalIncidents(
          session.symptomType,
          session.evidenceLedger || [],
          5
        );
      } catch (_) {}
    }

    res.json({
      success: true,
      sessionId: session.sessionId,
      state: session.state,
      symptomType: session.symptomType,
      topHypothesisId: session.topHypothesisId,
      calibratedConfidence: session.calibratedConfidence,
      criticPassed: session.criticPassed,
      criticEvaluation: session.criticEvaluation,
      steps: session.steps,
      evidenceLedger: session.evidenceLedger,
      hypothesisHistory: session.hypothesisHistory,
      recommendedActions: session.recommendedActions,
      similarHistoricalIncidents,
      session
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/rca/investigations
 * Returns recent investigation sessions
 */
router.get('/investigations', (req, res) => {
  try {
    const { brainPersistenceRepository } = require('../db/brain-persistence-repository');
    const limit = parseInt(req.query.limit || 25, 10);
    const investigations = brainPersistenceRepository ? brainPersistenceRepository.listRecentInvestigations(limit) : [];
    res.json({
      success: true,
      count: investigations.length,
      investigations
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/rca/investigations/:sessionId/cancel
 * Cancels an active investigation session mid-flight
 */
router.post('/investigations/:sessionId/cancel', (req, res) => {
  try {
    const { sessionId } = req.params;
    const { reason = 'Operator cancelled via API' } = req.body || {};
    const { investigationPlannerExecutorCritic } = require('../core/unified-investigation-engine');

    const session = investigationPlannerExecutorCritic.cancelInvestigationSession(sessionId, reason);
    res.json({
      success: true,
      sessionId: session.sessionId,
      state: session.state,
      cancelled: session.cancelled,
      cancellationReason: session.cancellationReason,
      steps: session.steps
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/rca/investigations/:sessionId/verify-remediation
 * Executes closed-loop post-remediation verification
 */
router.post('/investigations/:sessionId/verify-remediation', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const remediationRecord = req.body || {};
    const { investigationPlannerExecutorCritic } = require('../core/unified-investigation-engine');

    const verification = await investigationPlannerExecutorCritic.verifyRemediationOutcome(sessionId, remediationRecord);
    res.json({
      success: true,
      sessionId,
      verificationOutcome: verification.verificationOutcome,
      verification
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;


