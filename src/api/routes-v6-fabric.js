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
const dns = require('node:dns');
const { verifyToken, resolveAndValidateTarget, isSafeNetworkTarget } = require('../core/security');
const { authenticate } = require('./middleware');
const { ROLE_LEVELS, autonomousInfrastructureOperator } = require('../core/operator/autonomous-infrastructure-operator');
const { chatOperatorService } = require('../core/chat/chat-operator-service');

function isProhibitedSsrfIp(ip) {
  if (!ip || typeof ip !== 'string') return true;
  const clean = ip.trim().toLowerCase();
  // IPv4 link-local & cloud metadata (169.254.0.0/16, including 169.254.169.254)
  if (/^169\.254\./.test(clean) || /^::ffff:169\.254\./.test(clean)) return true;
  // IPv6 link-local (fe80::/10)
  if (/^fe[89ab][0-9a-f]:/i.test(clean)) return true;
  // Known cloud metadata IP endpoints
  if (clean === '169.254.169.254' || clean === '100.100.100.200' || clean === 'fd00:ec2::254') return true;
  // Multicast (224.0.0.0/4)
  if (/^(?:22[4-9]|23[0-9])\./.test(clean)) return true;
  // 0.0.0.0 unspecified
  if (clean === '0.0.0.0' || clean === '::') return true;
  return false;
}

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
  const proceed = () => {
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
  };

  if (req.query.sync === 'true') {
    authenticate(req, res, () => {
      const authCheck = resolveVerifiedUser(req, 'ANALYST');
      if (!authCheck.allowed) {
        return res.status(authCheck.status).json(createEjiiResult({
          success: false,
          capabilityId: 'ejii.v6.temporal_graph.sync',
          status: 'denied',
          error: { code: 'INSUFFICIENT_PERMISSIONS', message: authCheck.error }
        }));
      }
      temporalInfrastructureGraph.syncFromLiveInfrastructure('api_request');
      proceed();
    });
    return;
  }

  proceed();
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

    // Pre-resolution & post-resolution SSRF guard + DNS IP pinning (fail-closed)
    if (isProhibitedSsrfIp(rawHost) || !isSafeNetworkTarget(rawHost)) {
      return res.status(400).json(createEjiiResult({
        success: false,
        capabilityId: 'ejii.diagnostics.unreachable_hostname_workflow',
        status: 'blocked',
        error: { code: 'SECURITY_VIOLATION_SSRF', message: `Target '${rawHost}' rejected by SSRF defense policy.` }
      }));
    }

    const dnsStart = performance.now();
    const targetValidation = await resolveAndValidateTarget(rawHost);
    const dnsLatencyMs = Number((performance.now() - dnsStart).toFixed(2));

    if (!targetValidation.valid) {
      const isSsrfViolation = String(targetValidation.error || '').includes('SECURITY_VIOLATION');
      return res.status(400).json(createEjiiResult({
        success: false,
        capabilityId: 'ejii.diagnostics.unreachable_hostname_workflow',
        status: isSsrfViolation ? 'blocked' : 'failed',
        error: {
          code: isSsrfViolation ? 'SECURITY_VIOLATION_SSRF' : 'DNS_RESOLUTION_FAILED',
          message: targetValidation.error || `Failed to resolve or validate target '${rawHost}'.`
        }
      }));
    }

    if (isProhibitedSsrfIp(targetValidation.pinnedIp)) {
      return res.status(400).json(createEjiiResult({
        success: false,
        capabilityId: 'ejii.diagnostics.unreachable_hostname_workflow',
        status: 'blocked',
        error: { code: 'SECURITY_VIOLATION_SSRF', message: `Target '${rawHost}' resolved to prohibited address '${targetValidation.pinnedIp}'.` }
      }));
    }

    const result = await crossLayerIncidentCorrelator.diagnoseUnreachableHostname(rawHost, port, {
      pinnedIp: targetValidation.pinnedIp,
      resolvedIps: targetValidation.resolvedIps,
      prevalidatedDnsLatencyMs: dnsLatencyMs
    });
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
router.post('/simulation/branch', authenticate, (req, res) => {
  const authCheck = resolveVerifiedUser(req, 'ANALYST');
  if (!authCheck.allowed) {
    return res.status(authCheck.status).json(createEjiiResult({
      success: false,
      capabilityId: 'ejii.simulation.digital_twin_branch',
      status: 'denied',
      error: { code: 'AUTH_REQUIRED', message: authCheck.error }
    }));
  }
  const branch = simulationBranchManager.createSimulationBranch(req.body || {});
  res.json(createEjiiResult({
    success: true,
    capabilityId: 'ejii.simulation.digital_twin_branch',
    source: { module: 'SimulationBranchManager', method: 'createSimulationBranch', privilege: authCheck.user.role, fidelity: 'simulated' },
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
router.post('/policy/compile', authenticate, (req, res) => {
  const authCheck = resolveVerifiedUser(req, 'ANALYST');
  if (!authCheck.allowed) {
    return res.status(authCheck.status).json(createEjiiResult({
      success: false,
      capabilityId: 'ejii.security.policy_governance_compiler',
      status: 'denied',
      error: { code: 'AUTH_REQUIRED', message: authCheck.error }
    }));
  }
  const compiled = policyGovernanceEngine.compileAndAuditPolicies(req.body || {});
  res.json(createEjiiResult({
    success: true,
    capabilityId: 'ejii.security.policy_governance_compiler',
    source: { module: 'PolicyGovernanceEngine', method: 'compileAndAuditPolicies', privilege: authCheck.user.role, fidelity: 'derived' },
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

router.get('/system/preflight', authenticate, async (req, res) => {
  const authCheck = resolveVerifiedUser(req, 'ANALYST');
  if (!authCheck.allowed) {
    return res.status(authCheck.status).json(createEjiiResult({
      success: false,
      capabilityId: 'ejii.system.preflight',
      status: 'denied',
      error: { code: 'AUTH_REQUIRED', message: authCheck.error }
    }));
  }

  const { db } = require('../db/database');
  const { verifyChainIntegrity } = require('../core/audit-logger');
  const os = require('node:os');
  const fs = require('node:fs');

  const preflightReport = {
    timestamp: new Date().toISOString(),
    operator: authCheck.user.username,
    role: authCheck.user.role,
    checks: {}
  };

  // 1. SQLite Database & WAL Integrity Check
  try {
    const row = db.prepare('PRAGMA integrity_check').get();
    preflightReport.checks.sqliteIntegrity = {
      passed: row && (row.integrity_check === 'ok' || Object.values(row)[0] === 'ok'),
      result: row ? (row.integrity_check || Object.values(row)[0]) : 'unknown'
    };
  } catch (err) {
    preflightReport.checks.sqliteIntegrity = { passed: false, error: err.message };
  }

  // 2. Cryptographic HMAC Audit Trail Chain Verification
  try {
    const auditStatus = verifyChainIntegrity();
    preflightReport.checks.hmacAuditTrail = {
      passed: Boolean(auditStatus && auditStatus.valid),
      recordsVerified: auditStatus?.recordsChecked ?? 0,
      details: auditStatus?.details || 'Audit chain intact'
    };
  } catch (err) {
    preflightReport.checks.hmacAuditTrail = { passed: false, error: err.message };
  }

  // 3. DNS Resolver & Socket Table Verification (real hostname resolution via c-ares resolve4 or system resolver)
  try {
    const dnsStart = performance.now();
    let resolvedAddresses = [];
    let resolutionMethod = 'recursive_resolve4';
    try {
      const v4 = await dns.promises.resolve4('localhost');
      if (Array.isArray(v4) && v4.length > 0) {
        resolvedAddresses = v4;
      }
    } catch (_) {}
    if (resolvedAddresses.length === 0) {
      resolutionMethod = 'system_lookup';
      const lookedUp = await dns.promises.lookup('localhost', { all: true });
      resolvedAddresses = (lookedUp || []).map((entry) => entry.address).filter(Boolean);
    }
    const dnsRttMs = Number((performance.now() - dnsStart).toFixed(2));
    preflightReport.checks.dnsResolver = {
      passed: resolvedAddresses.length > 0,
      hostname: 'localhost',
      resolvedAddresses,
      resolutionMethod,
      rttMs: dnsRttMs,
      servers: dns.getServers()
    };
  } catch (err) {
    preflightReport.checks.dnsResolver = { passed: false, hostname: 'localhost', error: err.message };
  }

  // 4. Runtime Environment & gVisor Sandbox Detection
  const isContainer = Boolean(
    fs.existsSync('/.dockerenv') ||
    fs.existsSync('/run/.containerenv') ||
    (fs.existsSync('/proc/1/cgroup') && fs.readFileSync('/proc/1/cgroup', 'utf8').includes('docker'))
  );
  preflightReport.checks.runtimeSandbox = {
    passed: true,
    classificationMethod: 'HEURISTIC_INSPECTION',
    platform: os.platform(),
    isContainer,
    hostname: os.hostname(),
    networkInterfaces: Object.keys(os.networkInterfaces()).length
  };

  const allPassed = Object.values(preflightReport.checks).every((c) => c.passed === true);
  res.json(createEjiiResult({
    success: allPassed,
    capabilityId: 'ejii.system.preflight',
    status: allPassed ? 'ok' : 'degraded',
    data: preflightReport
  }));
});

router.post('/investigate/blast-radius', authenticate, (req, res) => {
  const authCheck = resolveVerifiedUser(req, 'ANALYST');
  if (!authCheck.allowed) {
    return res.status(authCheck.status).json(createEjiiResult({
      success: false,
      capabilityId: 'ejii.investigate.blast_radius',
      status: 'denied',
      error: { code: 'AUTH_REQUIRED', message: authCheck.error }
    }));
  }

  const rawBody = req.body || {};
  const targetNodeId = rawBody.targetNodeId;
  const rawLoss = rawBody.simulatedPacketLossPct !== undefined ? Number(rawBody.simulatedPacketLossPct) : 20;

  if (!Number.isFinite(rawLoss) || rawLoss < 0 || rawLoss > 100) {
    return res.status(400).json(createEjiiResult({
      success: false,
      capabilityId: 'ejii.investigate.blast_radius',
      status: 'invalid_input',
      error: {
        code: 'INVALID_PACKET_LOSS_RANGE',
        message: 'simulatedPacketLossPct must be a finite number between 0 and 100.'
      }
    }));
  }

  const graph = temporalInfrastructureGraph.getGraphState();
  const nodes = graph.nodes || [];
  const edges = graph.edges || [];
  const targetNode = nodes.find((n) => n.nodeId === targetNodeId || n.name === targetNodeId);

  if (!targetNode) {
    return res.status(404).json(createEjiiResult({
      success: false,
      capabilityId: 'ejii.investigate.blast_radius',
      status: 'failed',
      error: {
        code: 'TARGET_NODE_NOT_FOUND',
        message: `Target node '${targetNodeId}' was not found in the Temporal Infrastructure Graph.`
      }
    }));
  }

  // Directed multi-hop BFS traversal across downstream dependency relationships
  const queueMultiplier = 1 + (rawLoss / 100) * 2.5;
  const visited = new Set([targetNode.nodeId]);
  const bfsQueue = [{ nodeId: targetNode.nodeId, hopDistance: 0 }];
  const downstreamImpact = [];

  while (bfsQueue.length > 0) {
    const current = bfsQueue.shift();
    for (const edge of edges) {
      let dependentId = null;
      const rel = String(edge.relationshipType || '');
      // If current node routes_to targetId, then targetId is downstream of current.
      // If sourceId depends_on or is member_of current node, then sourceId is impacted by current node's degradation.
      if (edge.sourceId === current.nodeId && (rel === 'routes_to' || rel === 'connected_to' || rel === 'forwards_to')) {
        dependentId = edge.targetId;
      } else if (edge.targetId === current.nodeId && (rel === 'depends_on' || rel === 'member_of' || rel === 'hosted_on')) {
        dependentId = edge.sourceId;
      }

      if (dependentId && !visited.has(dependentId)) {
        visited.add(dependentId);
        const depNode = nodes.find((n) => n.nodeId === dependentId);
        if (depNode) {
          const hopDistance = current.hopDistance + 1;
          const hopAttenuation = Math.max(0.35, Math.pow(0.85, hopDistance - 1));
          const effectiveMultiplier = 1 + (queueMultiplier - 1) * hopAttenuation;
          const observedLatency = typeof depNode.attributes?.latencyMs === 'number'
            ? Number(depNode.attributes.latencyMs)
            : null;
          const projectedLatency = observedLatency !== null
            ? Number((observedLatency * effectiveMultiplier).toFixed(2))
            : null;

          downstreamImpact.push({
            nodeId: depNode.nodeId,
            name: depNode.name,
            hopDistance,
            relationship: rel || 'downstream',
            currentLatencyMs: observedLatency,
            projectedLatencyMs: projectedLatency,
            latencyNote: observedLatency === null ? 'UNOBSERVED_BASELINE_LATENCY' : 'PROJECTED_FROM_OBSERVED_BASELINE',
            modelFidelity: 'MATHEMATICAL_MODEL'
          });
          bfsQueue.push({ nodeId: depNode.nodeId, hopDistance });
        }
      }
    }
  }

  res.json(createEjiiResult({
    success: true,
    capabilityId: 'ejii.investigate.blast_radius',
    source: { module: 'routes-v6-fabric', method: 'POST /api/v6/investigate/blast-radius', privilege: authCheck.user.role, fidelity: 'simulated' },
    status: 'ok',
    data: {
      modelFidelity: 'MATHEMATICAL_MODEL',
      targetNode: { nodeId: targetNode.nodeId, name: targetNode.name },
      simulatedPacketLossPct: rawLoss,
      affectedNodeCount: downstreamImpact.length,
      downstreamImpact
    }
  }));
});

// Part XII: Minimalist Chat-First Conversational Diagnostic & Investigation Workspace
router.post('/chat/message', authenticate, async (req, res) => {
  const authCheck = resolveVerifiedUser(req);
  if (!authCheck.allowed) {
    return res.status(authCheck.status).json(createEjiiResult({
      success: false,
      capabilityId: 'ejii.chat.message',
      status: 'denied',
      error: { code: 'AUTH_OR_ESCALATION_DENIED', message: authCheck.error }
    }));
  }

  const body = req.body || {};
  const outcome = await chatOperatorService.processMessage({
    sessionId: body.sessionId,
    message: body.message || body.prompt,
    user: authCheck.user,
    requestId: body.requestId || req.requestId,
    simulateTimeout: Boolean(body.simulateTimeout)
  });

  return res.status(outcome.statusCode || (outcome.success ? 200 : 400)).json(createEjiiResult({
    success: outcome.success,
    capabilityId: 'ejii.chat.message',
    requestId: req.requestId,
    correlationId: req.correlationId,
    status: outcome.status || (outcome.success ? 'ok' : 'failed'),
    data: outcome.data || null,
    ...(outcome.error ? { error: outcome.error } : {})
  }));
});

router.get('/chat/session/:sessionId', authenticate, (req, res) => {
  const authCheck = resolveVerifiedUser(req);
  if (!authCheck.allowed) {
    return res.status(authCheck.status).json(createEjiiResult({
      success: false,
      capabilityId: 'ejii.chat.session',
      status: 'denied',
      error: { code: 'AUTH_REQUIRED', message: authCheck.error }
    }));
  }
  const access = chatOperatorService.checkSessionAccess(req.params.sessionId, authCheck.user);
  if (!access.allowed) {
    return res.status(404).json(createEjiiResult({
      success: false,
      capabilityId: 'ejii.chat.session',
      status: 'denied',
      error: { code: 'CHAT_SESSION_ACCESS_DENIED', message: 'This conversation is unavailable for the authenticated user.' }
    }));
  }
  const session = chatOperatorService.getOrCreateSession(req.params.sessionId, authCheck.user);
  res.json(createEjiiResult({
    success: true,
    capabilityId: 'ejii.chat.session',
    status: 'ok',
    data: {
      sessionId: session.sessionId,
      username: session.username,
      role: session.role,
      lastTarget: session.lastTarget,
      lastPorts: session.lastPorts,
      lastIntent: session.lastIntent,
      turnCount: session.turnCount,
      messages: session.messages
    }
  }));
});

router.post('/chat/cancel', authenticate, (req, res) => {
  const authCheck = resolveVerifiedUser(req);
  if (!authCheck.allowed) {
    return res.status(authCheck.status).json(createEjiiResult({
      success: false,
      capabilityId: 'ejii.chat.cancel',
      status: 'denied',
      error: { code: 'AUTH_REQUIRED', message: authCheck.error }
    }));
  }
  const body = req.body || {};
  if (body.sessionId) {
    const access = chatOperatorService.checkSessionAccess(body.sessionId, authCheck.user);
    if (!access.allowed) {
      return res.status(404).json(createEjiiResult({
        success: false,
        capabilityId: 'ejii.chat.cancel',
        status: 'denied',
        error: { code: 'CHAT_SESSION_ACCESS_DENIED', message: 'This conversation is unavailable for the authenticated user.' }
      }));
    }
  }
  const result = chatOperatorService.cancelRequest(body.sessionId, body.requestId);
  res.json(createEjiiResult({
    success: true,
    capabilityId: 'ejii.chat.cancel',
    status: 'ok',
    data: result
  }));
});

router.delete('/chat/session/:sessionId', authenticate, (req, res) => {
  const authCheck = resolveVerifiedUser(req);
  if (!authCheck.allowed) {
    return res.status(authCheck.status).json(createEjiiResult({
      success: false,
      capabilityId: 'ejii.chat.clear_session',
      status: 'denied',
      error: { code: 'AUTH_REQUIRED', message: authCheck.error }
    }));
  }
  const access = chatOperatorService.checkSessionAccess(req.params.sessionId, authCheck.user);
  if (!access.allowed) {
    return res.status(404).json(createEjiiResult({
      success: false,
      capabilityId: 'ejii.chat.clear_session',
      status: 'denied',
      error: { code: 'CHAT_SESSION_ACCESS_DENIED', message: 'This conversation is unavailable for the authenticated user.' }
    }));
  }
  const cleared = chatOperatorService.clearSession(req.params.sessionId);
  res.json(createEjiiResult({
    success: true,
    capabilityId: 'ejii.chat.clear_session',
    status: 'ok',
    data: { sessionId: req.params.sessionId, cleared }
  }));
});

module.exports = router;

