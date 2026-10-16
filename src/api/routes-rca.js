/**
 * EJII Evidence-Driven Root Cause Analysis (RCA) API Routes
 * Mount point: /api/rca
 * Exposes evidence-first diagnostic evaluations, dual-mode incident briefings, and probe execution.
 */

'use strict';

const express = require('express');
const router = express.Router();
const { aiBrain } = require('../core/ai-brain');
const { diagnosticReasoningEngine } = require('../core/rca-engine');
const { incidentBriefingProvider } = require('../core/llm-provider');
const { toolSandbox } = require('../core/tool-sandbox');

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
router.post('/probe', async (req, res) => {
  const { probeType, target, params } = req.body || {};
  if (!probeType || !target) {
    return res.status(400).json({ error: "Missing required fields 'probeType' and 'target'." });
  }

  try {
    let result;
    if (probeType === 'PATH_MTU_DF_SWEEP' || probeType === 'pmtu_sweep') {
      result = await toolSandbox.executeTool('pmtu_sweep', { target, ...params }, { role: 'ANALYST', username: 'rca-agent' });
    } else if (probeType === 'ICMP_PING' || probeType === 'ping') {
      result = await toolSandbox.executeTool('ping', { target, ...params }, { role: 'ANALYST', username: 'rca-agent' });
    } else if (probeType === 'TCP_HANDSHAKE' || probeType === 'tcp_handshake') {
      const port = parseInt(params?.port || 443, 10);
      result = await toolSandbox.executeTool('tcp_handshake', { target, port, ...params }, { role: 'ANALYST', username: 'rca-agent' });
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

module.exports = router;
