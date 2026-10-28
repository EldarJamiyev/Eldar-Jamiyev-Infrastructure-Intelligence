/**
 * EJII v6 — Sovereign Intelligence Fabric REST API Router (/api/v6)
 *
 * Exposes:
 *   - Part III: Unified Capability Registry & EJIIResult<T> Invocation
 *   - Part IV:  Evidence Fabric, Quality Scoring & Acyclic Lineage Tracing
 *   - Part V:   Temporal Infrastructure Graph, Historical Queries & Snapshot Diffing
 *   - Part VI:  Cross-Layer Incident Correlation & 10-Step Unreachable-Hostname Workflow
 *   - Part VII: Explainable Causal Investigation, Counterfactuals & Uncertainty Panel
 *   - Part VIII: Trace-Driven Digital Twin & Chaos Simulation Branching
 *   - Part IX:  Policy Intelligence & Multi-Target Configuration Governance
 *   - Part X:   Governed Remediation, Postcondition Verification & Academy Bridge
 */

const express = require('express');
const router = express.Router();
const { createEjiiResult } = require('../core/contracts/ejii-result');
const { capabilityRegistry } = require('../core/capability-registry');
const { evidenceFabric, EVIDENCE_CLASSES, FRESHNESS_STATES } = require('../core/evidence/evidence-fabric');
const { temporalInfrastructureGraph } = require('../core/topology/temporal-graph-engine');
const { crossLayerIncidentCorrelator } = require('../core/correlation/incident-correlator');
const {
  simulationBranchManager,
  policyGovernanceEngine,
  governedActionControlPlane
} = require('../core/governance/action-control-plane');
const { verifyToken } = require('../core/security');
const { authenticate } = require('./middleware');
const { ROLE_LEVELS, autonomousInfrastructureOperator } = require('../core/operator/autonomous-infrastructure-operator');

/**
 * Resolves the cryptographically verified user from `req.user` (populated by `authenticate`).
 * Strictly blocks any attempt to escalate privileges via `req.body.role` or `req.body.operatorRole`.
 * Permits voluntary role downgrade ONLY when an authenticated higher-privilege user (e.g. ADMIN)
 * explicitly tests least-privilege RBAC boundaries.
 */
function resolveVerifiedUser(req, minRole = null) {
  const verified = req.user;
  if (!verified || !verified.role) {
    return { allowed: false, status: 401, error: 'Authentication required. Verified JWT session missing.' };
  }
  const actualRole = String(verified.role).toUpperCase();
  const actualLevel = ROLE_LEVELS[actualRole] || 1;

  const requestedOverride = (req.body && (req.body.role || req.body.operatorRole))
    ? String(req.body.role || req.body.operatorRole).toUpperCase()
    : null;

  let effectiveRole = actualRole;
  let effectiveLevel = actualLevel;

  if (requestedOverride && requestedOverride !== actualRole) {
    const requestedLevel = ROLE_LEVELS[requestedOverride] || 1;
    if (requestedLevel > actualLevel) {
      return {
        allowed: false,
        status: 403,
        error: `PRIVILEGE_ESCALATION_BLOCKED: Authenticated role '${actualRole}' cannot escalate to '${requestedOverride}' via request body.`
      };
    }
    effectiveRole = requestedOverride;
    effectiveLevel = requestedLevel;
  }

  if (minRole) {
    const minLevel = ROLE_LEVELS[String(minRole).toUpperCase()] || 1;
    if (effectiveLevel < minLevel) {
      return {
        allowed: false,
        status: 403,
        error: `INSUFFICIENT_PERMISSIONS: Operation requires minimum role '${minRole}', current role is '${effectiveRole}'.`
      };
    }
  }

  return {
    allowed: true,
    user: requestedOverride && requestedOverride !== actualRole
      ? { ...verified, role: effectiveRole, authenticatedRole: actualRole, isDowngradedSimulation: true }
      : { ...verified, role: actualRole, authenticatedRole: actualRole }
  };
}

// GET /api/v6/overview — Complete v6 Sovereign Intelligence Fabric state summary
router.get('/overview', (req, res) => {
  try {
    const graphState = temporalInfrastructureGraph.getGraphState();
    const recentEvidence = evidenceFabric.queryEvidence({ limit: 25 });
    const recentFindings = evidenceFabric.listFindings(15);
    const capabilities = capabilityRegistry.listCapabilities();
    const actions = governedActionControlPlane.listActionDefinitions();
    const branches = simulationBranchManager.listBranches();
    const uncertainty = crossLayerIncidentCorrelator.latestInvestigation?.uncertaintyPanel ||
      crossLayerIncidentCorrelator.buildUncertaintyPanel('localhost:443', recentEvidence, []);

    res.json(createEjiiResult({
      success: true,
      capabilityId: 'ejii.v6.fabric.overview',
      requestId: req.requestId,
      correlationId: req.correlationId,
      source: { module: 'routes-v6-fabric', method: 'GET /api/v6/overview', privilege: 'unprivileged', fidelity: 'live' },
      status: 'ok',
      data: {
        version: '6.0.0-sovereign-intelligence-fabric',
        lifecycleLoop: [
          'Discover', 'Observe', 'Correlate', 'Investigate', 'Explain', 'Simulate',
          'Plan', 'Authorize', 'Execute', 'Verify', 'Learn', 'Improve'
        ],
        capabilitiesCount: capabilities.length,
        capabilities,
        evidenceClasses: EVIDENCE_CLASSES,
        freshnessStates: FRESHNESS_STATES,
        recentEvidence,
        recentFindings,
        temporalGraph: {
          nodeCount: graphState.nodes.length,
          edgeCount: graphState.edges.length,
          snapshotCount: graphState.snapshotCount,
          reconciliationCandidates: graphState.reconciliationCandidates,
          identityDriftEvents: graphState.identityDriftEvents
        },
        uncertaintyPanel: uncertainty,
        simulationBranches: branches,
        governedActions: actions,
        recentExecutions: governedActionControlPlane.listExecutions(10)
      },
      evidenceIds: recentEvidence.slice(0, 8).map((e) => e.id)
    }));
  } catch (err) {
    res.status(500).json(createEjiiResult({
      success: false,
      capabilityId: 'ejii.v6.fabric.overview',
      status: 'failed',
      error: { code: 'OVERVIEW_ERROR', message: err.message }
    }));
  }
});

// Part III: Capability Registry
router.get('/capabilities', (req, res) => {
  const list = capabilityRegistry.listCapabilities({
    domain: req.query.domain,
    executionMode: req.query.executionMode
  });
  res.json(createEjiiResult({
    success: true,
    capabilityId: 'ejii.v6.capability_registry',
    requestId: req.requestId,
    correlationId: req.correlationId,
    status: 'ok',
    data: { count: list.length, capabilities: list }
  }));
});

router.post('/capabilities/:id/invoke', authenticate, async (req, res) => {
  const authCheck = resolveVerifiedUser(req);
  if (!authCheck.allowed) {
    return res.status(authCheck.status).json(createEjiiResult({
      success: false,
      capabilityId: req.params.id,
      status: 'denied',
      error: { code: 'AUTH_OR_ESCALATION_DENIED', message: authCheck.error }
    }));
  }
  const envelope = await capabilityRegistry.invokeCapability(req.params.id, req.body || {}, {
    requestId: req.requestId,
    correlationId: req.correlationId,
    user: authCheck.user
  });
  res.status(envelope.status === 'denied' ? 403 : envelope.success ? 200 : 400).json(envelope);
});

// Part IV: Evidence Fabric & Lineage
router.get('/evidence', (req, res) => {
  const records = evidenceFabric.queryEvidence({
    subject: req.query.subject,
    type: req.query.type,
    freshnessState: req.query.freshnessState,
    limit: req.query.limit
  });
  res.json(createEjiiResult({
    success: true,
    capabilityId: 'ejii.v6.evidence_fabric.query',
    status: 'ok',
    data: { count: records.length, records, findings: evidenceFabric.listFindings(20) },
    evidenceIds: records.map((r) => r.id)
  }));
});

router.post('/evidence', authenticate, (req, res) => {
  const authCheck = resolveVerifiedUser(req, 'OPERATOR');
  if (!authCheck.allowed) {
    return res.status(authCheck.status).json(createEjiiResult({
      success: false,
      capabilityId: 'ejii.v6.evidence_fabric.record',
      status: 'denied',
      error: { code: 'AUTH_REQUIRED', message: authCheck.error }
    }));
  }
  const body = req.body || {};
  if (!body.type || typeof body.type !== 'string' || !body.subject || typeof body.subject !== 'string' || !body.claim || typeof body.claim !== 'string') {
    return res.status(400).json(createEjiiResult({
      success: false,
      capabilityId: 'ejii.v6.evidence_fabric.record',
      status: 'invalid_input',
      error: { code: 'VALIDATION_FAILED', message: 'Fields type, subject, and claim are required strings.' }
    }));
  }
  if (body.type.length > 64 || body.subject.length > 256 || body.claim.length > 2048) {
    return res.status(400).json(createEjiiResult({
      success: false,
      capabilityId: 'ejii.v6.evidence_fabric.record',
      status: 'invalid_input',
      error: { code: 'VALIDATION_FAILED', message: 'Field length limits exceeded (type: 64, subject: 256, claim: 2048).' }
    }));
  }
  const rec = evidenceFabric.recordEvidence({
    ...body,
    recordedBy: authCheck.user.username,
    operatorRole: authCheck.user.role
  });
  res.json(createEjiiResult({
    success: true,
    capabilityId: 'ejii.v6.evidence_fabric.record',
    status: 'ok',
    data: rec,
    evidenceIds: [rec.id]
  }));
});

router.get('/evidence/:id/lineage', (req, res) => {
  const lineage = evidenceFabric.traceLineage(req.params.id);
  if (!lineage) {
    return res.status(404).json(createEjiiResult({
      success: false,
      capabilityId: 'ejii.v6.evidence_fabric.lineage',
      status: 'failed',
      error: { code: 'LINEAGE_NOT_FOUND', message: `No Finding or EvidenceRecord found for '${req.params.id}'` }
    }));
  }
  res.json(createEjiiResult({
    success: true,
    capabilityId: 'ejii.v6.evidence_fabric.lineage',
    status: 'ok',
    data: lineage
  }));
});

// Part V: Temporal Infrastructure Graph
router.get('/temporal-graph', (req, res) => {
  if (req.query.sync === 'true') {
    temporalInfrastructureGraph.syncFromLiveInfrastructure('api_request');
  }
  if (req.query.timestamp) {
    const historical = temporalInfrastructureGraph.getTopologyAtTimestamp(req.query.timestamp);
    return res.json(createEjiiResult({
      success: true,
      capabilityId: 'ejii.v6.temporal_graph.at_timestamp',
      status: 'ok',
      data: historical
    }));
  }
  const state = temporalInfrastructureGraph.getGraphState();
  res.json(createEjiiResult({
    success: true,
    capabilityId: 'ejii.v6.temporal_graph.state',
    status: 'ok',
    data: state
  }));
});

router.get('/temporal-graph/diff', (req, res) => {
  const t1 = req.query.t1 ? Number(req.query.t1) || req.query.t1 : Date.now() - 60000;
  const t2 = req.query.t2 ? Number(req.query.t2) || req.query.t2 : Date.now();
  const diff = temporalInfrastructureGraph.diffSnapshots(t1, t2);
  res.json(createEjiiResult({
    success: true,
    capabilityId: 'ejii.v6.temporal_graph.diff',
    status: 'ok',
    data: diff
  }));
});

// Part VI & VII: Cross-Layer Incident Correlation & Explainable Causal Investigation
router.post('/correlate', authenticate, (req, res) => {
  const authCheck = resolveVerifiedUser(req, 'ANALYST');
  if (!authCheck.allowed) {
    return res.status(authCheck.status).json(createEjiiResult({
      success: false,
      capabilityId: 'ejii.correlation.cross_layer_rca',
      status: 'denied',
      error: { code: 'AUTH_REQUIRED', message: authCheck.error }
    }));
  }
  const body = req.body || {};
  if (body.target && typeof body.target === 'string') {
    const rawTarget = body.target.trim();
    if (/^169\.254\.169\.254$/i.test(rawTarget) || /metadata\.google/i.test(rawTarget)) {
      return res.status(400).json(createEjiiResult({
        success: false,
        capabilityId: 'ejii.correlation.cross_layer_rca',
        status: 'blocked',
        error: { code: 'SECURITY_VIOLATION_SSRF', message: 'Target hostname rejected by SSRF guard.' }
      }));
    }
  }
  const report = crossLayerIncidentCorrelator.correlateSignals(body);
  res.json(createEjiiResult({
    success: true,
    capabilityId: 'ejii.correlation.cross_layer_rca',
    source: { module: 'CrossLayerIncidentCorrelator', method: 'correlateSignals', privilege: authCheck.user.role, fidelity: 'derived' },
    status: 'ok',
    data: report,
    evidenceIds: (report.evidenceRecords || []).map((e) => e.id)
  }));
});

router.post('/diagnose-hostname', authenticate, async (req, res) => {
  const authCheck = resolveVerifiedUser(req, 'ANALYST');
  if (!authCheck.allowed) {
    return res.status(authCheck.status).json(createEjiiResult({
      success: false,
      capabilityId: 'ejii.diagnostics.unreachable_hostname_workflow',
      status: 'denied',
      error: { code: 'AUTH_REQUIRED', message: authCheck.error }
    }));
  }
  try {
    const rawHost = String((req.body && (req.body.hostname || req.body.target)) || 'localhost').trim();
    const port = Math.max(1, Math.min(65535, Number((req.body && req.body.port) || 3000)));

    // SSRF & injection protection: block cloud metadata and invalid characters
    if (/^169\.254\.169\.254$/i.test(rawHost) || /metadata\.google/i.test(rawHost) || /[^a-zA-Z0-9.-]/.test(rawHost)) {
      return res.status(400).json(createEjiiResult({
        success: false,
        capabilityId: 'ejii.diagnostics.unreachable_hostname_workflow',
        status: 'blocked',
        error: { code: 'SECURITY_VIOLATION_SSRF', message: 'Target hostname rejected by SSRF guard.' }
      }));
    }

    const result = await crossLayerIncidentCorrelator.diagnoseUnreachableHostname(rawHost, port);
    res.json(createEjiiResult({
      success: true,
      capabilityId: 'ejii.diagnostics.unreachable_hostname_workflow',
      status: 'ok',
      data: result,
      evidenceIds: (result.correlation?.evidenceRecords || []).map((e) => e.id)
    }));
  } catch (err) {
    res.status(500).json(createEjiiResult({
      success: false,
      capabilityId: 'ejii.diagnostics.unreachable_hostname_workflow',
      status: 'failed',
      error: { code: 'DIAGNOSE_HOSTNAME_ERROR', message: err.message }
    }));
  }
});

// Part VIII: Trace-Driven Digital Twin & Chaos Branching
router.post('/simulation/branch', (req, res) => {
  const branch = simulationBranchManager.createSimulationBranch(req.body || {});
  res.json(createEjiiResult({
    success: true,
    capabilityId: 'ejii.simulation.digital_twin_branch',
    source: { module: 'SimulationBranchManager', method: 'createSimulationBranch', privilege: 'operator', fidelity: 'simulated' },
    status: 'ok',
    data: branch,
    evidenceIds: branch.evidenceId ? [branch.evidenceId] : []
  }));
});

router.get('/simulation/branch/:id/export', (req, res) => {
  const bundle = simulationBranchManager.exportExperimentBundle(req.params.id);
  if (!bundle) {
    return res.status(404).json(createEjiiResult({
      success: false,
      capabilityId: 'ejii.simulation.export',
      status: 'failed',
      error: { code: 'BRANCH_NOT_FOUND', message: `Simulation branch '${req.params.id}' not found` }
    }));
  }
  res.json(createEjiiResult({
    success: true,
    capabilityId: 'ejii.simulation.export',
    source: { module: 'SimulationBranchManager', method: 'exportExperimentBundle', privilege: 'operator', fidelity: 'simulated' },
    status: 'ok',
    data: bundle
  }));
});

// Part IX: Policy Intelligence & Governance Compiler
router.post('/policy/compile', (req, res) => {
  const compiled = policyGovernanceEngine.compileAndAuditPolicies(req.body || {});
  res.json(createEjiiResult({
    success: true,
    capabilityId: 'ejii.security.policy_governance_compiler',
    source: { module: 'PolicyGovernanceEngine', method: 'compileAndAuditPolicies', privilege: 'operator', fidelity: 'derived' },
    status: 'ok',
    data: compiled
  }));
});

// Part X: Governed Remediation & Postcondition Verification Control Plane
router.get('/actions', (req, res) => {
  res.json(createEjiiResult({
    success: true,
    capabilityId: 'ejii.governance.list_actions',
    status: 'ok',
    data: {
      actions: governedActionControlPlane.listActionDefinitions(),
      recentExecutions: governedActionControlPlane.listExecutions(20)
    }
  }));
});

router.post('/actions/:id/preview', authenticate, (req, res) => {
  const authCheck = resolveVerifiedUser(req, 'ANALYST');
  if (!authCheck.allowed) {
    return res.status(authCheck.status).json(createEjiiResult({
      success: false,
      capabilityId: 'ejii.governance.preview_action',
      status: 'denied',
      error: { code: 'AUTH_REQUIRED', message: authCheck.error }
    }));
  }
  const preview = governedActionControlPlane.previewAction(req.params.id, req.body || {});
  res.status(preview.success ? 200 : 404).json(createEjiiResult({
    success: preview.success,
    capabilityId: 'ejii.governance.preview_action',
    status: preview.success ? 'ok' : 'failed',
    data: preview
  }));
});

router.post('/actions/:id/execute', authenticate, async (req, res) => {
  const authCheck = resolveVerifiedUser(req, 'OPERATOR');
  if (!authCheck.allowed) {
    return res.status(authCheck.status).json(createEjiiResult({
      success: false,
      capabilityId: 'ejii.governance.verified_remediation',
      status: 'denied',
      error: { code: 'AUTH_OR_ESCALATION_DENIED', message: authCheck.error }
    }));
  }
  const result = await governedActionControlPlane.executeGovernedAction(req.params.id, req.body || {}, authCheck.user);
  const statusCode = result.status === 'denied' ? 403 : result.success ? 200 : 400;
  res.status(statusCode).json(createEjiiResult({
    success: result.success,
    capabilityId: 'ejii.governance.verified_remediation',
    status: result.status || (result.success ? 'ok' : 'failed'),
    data: result,
    evidenceIds: [result.actionEvidenceId, result.verificationEvidenceId].filter(Boolean),
    ...(result.error ? { error: result.error } : {})
  }));
});

// Part XI: Autonomous Infrastructure Operator & 9-Capability Flagship Orchestration (Strict JWT Auth)
router.get('/operator/state', authenticate, async (req, res) => {
  try {
    const state = await autonomousInfrastructureOperator.getOperatorState();
    res.json(createEjiiResult({
      success: true,
      capabilityId: 'ejii.operator.state',
      status: 'ok',
      data: {
        ...state,
        authenticatedOperator: {
          username: req.user.username,
          role: req.user.role
        }
      }
    }));
  } catch (err) {
    res.status(500).json(createEjiiResult({
      success: false,
      capabilityId: 'ejii.operator.state',
      status: 'failed',
      error: { code: 'OPERATOR_STATE_ERROR', message: err.message }
    }));
  }
});

router.post('/operator/directive', authenticate, async (req, res) => {
  try {
    const authCheck = resolveVerifiedUser(req);
    if (!authCheck.allowed) {
      return res.status(authCheck.status).json(createEjiiResult({
        success: false,
        capabilityId: 'ejii.operator.directive',
        status: 'denied',
        error: { code: 'PRIVILEGE_ESCALATION_BLOCKED', message: authCheck.error }
      }));
    }
    const state = await autonomousInfrastructureOperator.executeOperatorGoal({
      goal: req.body && req.body.goal,
      user: authCheck.user,
      autoApproveLowRisk: Boolean(req.body && req.body.autoApproveLowRisk)
    });
    res.json(createEjiiResult({
      success: true,
      capabilityId: 'ejii.operator.directive',
      status: 'ok',
      data: state
    }));
  } catch (err) {
    res.status(500).json(createEjiiResult({
      success: false,
      capabilityId: 'ejii.operator.directive',
      status: 'failed',
      error: { code: 'OPERATOR_DIRECTIVE_ERROR', message: err.message }
    }));
  }
});

router.post('/operator/approve-heal', authenticate, async (req, res) => {
  try {
    const authCheck = resolveVerifiedUser(req);
    if (!authCheck.allowed) {
      return res.status(authCheck.status).json(createEjiiResult({
        success: false,
        capabilityId: 'ejii.operator.self_healing',
        status: 'denied',
        error: { code: 'PRIVILEGE_ESCALATION_BLOCKED', message: authCheck.error }
      }));
    }
    const result = await autonomousInfrastructureOperator.approveAndExecuteSelfHealing({
      taskId: req.body && req.body.taskId,
      actionId: (req.body && req.body.actionId) || 'verify_and_refresh_dns_resolution',
      target: (req.body && req.body.target) || '127.0.0.1',
      port: Number(req.body && req.body.port) || 3000,
      role: authCheck.user.role,
      user: authCheck.user,
      simulateVerificationFailure: Boolean(req.body && req.body.simulateVerificationFailure)
    });
    const isDenied = result.status === 'DENIED_BY_RBAC' || result.status === 'DENIED_RBAC' || result.allowed === false;
    const code = isDenied ? 403 : 200;
    res.status(code).json(createEjiiResult({
      success: !isDenied,
      capabilityId: 'ejii.operator.self_healing',
      status: isDenied ? 'denied' : 'ok',
      data: result,
      ...(result.error ? { error: { code: 'RBAC_DENIED', message: result.error } } : {})
    }));
  } catch (err) {
    res.status(500).json(createEjiiResult({
      success: false,
      capabilityId: 'ejii.operator.self_healing',
      status: 'failed',
      error: { code: 'SELF_HEALING_ERROR', message: err.message }
    }));
  }
});

router.post('/operator/digital-twin', authenticate, async (req, res) => {
  try {
    const twinRes = await autonomousInfrastructureOperator.mutateDigitalTwin({
      action: (req.body && req.body.action) || 'break_dns',
      targetId: (req.body && req.body.targetId) || 'twin-sw1'
    });
    res.json(createEjiiResult({
      success: true,
      capabilityId: 'ejii.operator.digital_twin',
      status: 'ok',
      data: twinRes
    }));
  } catch (err) {
    res.status(500).json(createEjiiResult({
      success: false,
      capabilityId: 'ejii.operator.digital_twin',
      status: 'failed',
      error: { code: 'DIGITAL_TWIN_ERROR', message: err.message }
    }));
  }
});

router.post('/operator/cockpit', authenticate, async (req, res) => {
  try {
    const updated = await autonomousInfrastructureOperator.updateCockpitPreferences(req.body || {});
    res.json(createEjiiResult({
      success: true,
      capabilityId: 'ejii.operator.cockpit',
      status: 'ok',
      data: updated
    }));
  } catch (err) {
    res.status(500).json(createEjiiResult({
      success: false,
      capabilityId: 'ejii.operator.cockpit',
      status: 'failed',
      error: { code: 'COCKPIT_ERROR', message: err.message }
    }));
  }
});

router.post('/operator/reset-incident', authenticate, async (req, res) => {
  try {
    const state = await autonomousInfrastructureOperator.resetIncidentScenario();
    res.json(createEjiiResult({
      success: true,
      capabilityId: 'ejii.operator.reset_incident',
      status: 'ok',
      data: state
    }));
  } catch (err) {
    res.status(500).json(createEjiiResult({
      success: false,
      capabilityId: 'ejii.operator.reset_incident',
      status: 'failed',
      error: { code: 'RESET_INCIDENT_ERROR', message: err.message }
    }));
  }
});

module.exports = router;

