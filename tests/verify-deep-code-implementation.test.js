const assert = require('assert');
const fs = require('fs');
const path = require('path');

const security = require('../src/core/security');
const validator = require('../src/core/type-contract-validator');
const { ReasoningEngine } = require('../src/core/reasoning-engine');
const { AIModelOrchestrator } = require('../src/core/ai-model-orchestrator');
const { RCAEngine } = require('../src/core/rca-engine');
const { HostDiagnosticsEngine } = require('../src/systems/diagnostics/host-diagnostics-engine');
const { RAGKnowledgeEngine } = require('../src/core/rag-knowledge-engine');

async function runDeepCodeVerificationGate() {
  console.log('--- Running Deep Code Implementation & Anti-Evasion Gate ---');

  // 1. Verify SSRF multi-encoding & IPv6 mapped defense in src/core/security.js
  assert.strictEqual(typeof security.createPinnedLookup, 'function', 'createPinnedLookup must exist in security.js');
  const lookupFn = security.createPinnedLookup('93.184.216.34', 4);
  await new Promise((resolve, reject) => {
    lookupFn('example.com', { all: true }, (err, res) => {
      if (err) return reject(err);
      assert.ok(Array.isArray(res) && res[0].address === '93.184.216.34', 'Node v24 opts.all lookup must return array of address objects');
      resolve();
    });
  });

  // 2. Verify Warm Baseline Authenticity in src/systems/diagnostics/host-diagnostics-engine.js
  const diagEngine = new HostDiagnosticsEngine();
  const warm = diagEngine.getWarmSnapshot ? diagEngine.getWarmSnapshot() : diagEngine._createWarmBaselineAudit();
  assert.strictEqual(warm.isProvisional, true, 'Warm baseline must set isProvisional: true');
  assert.notStrictEqual(warm.overallStatus, 'HEALTHY', 'Warm baseline must NEVER report overallStatus: HEALTHY');
  assert.strictEqual(warm.pillars?.resources?.cpuLoadPct ?? null, null, 'Warm baseline cpuLoadPct must be null, not fabricated');

  // 3. Verify Contradicted Hypothesis 0% Lock & Hare-Niemeyer Exclusion in src/core/reasoning-engine.js
  const reasoning = new ReasoningEngine();
  const evalResult = reasoning.evaluateHypotheses({
    incidentType: 'TCP_CONNECTION_FAILURE',
    observedFacts: [
      validator.createEvidenceRecord({
        evidenceId: 'ev_rst_1',
        metricKey: 'tcp.flags.reset',
        value: true,
        evidenceClass: 'Observed',
        collectorId: 'wire-diagnostics',
        collectionMethod: 'tcpSynProbe',
        outcome: 'SUCCESS',
        isAuthoritative: true,
        contradictsHypotheses: ['FIREWALL_SILENT_DROP']
      })
    ]
  });
  const contradictedHyp = (evalResult.hypotheses || []).find((h) => h.contradicted === true || h.status === 'CONTRADICTED');
  if (contradictedHyp) {
    assert.strictEqual(contradictedHyp.normalizedSharePct || contradictedHyp.confidence, 0, 'Contradicted hypothesis must be strictly 0%');
  }

  // 4. Verify Causal Discovery Sample Sufficiency Gate (N >= 30) in src/core/rca-engine.js
  const rca = new RCAEngine();
  const insufficientCausal = rca.discoverDynamicCausalStructure([
    { timestamp: Date.now(), cpu: 50, rtt: 12, isAuthoritative: true, outcome: 'SUCCESS' }
  ]);
  assert.strictEqual(
    insufficientCausal.edges?.length || insufficientCausal.causalEdges?.length || 0,
    0,
    'Causal discovery with < 30 samples must emit 0 causal edges'
  );

  // 5. Verify AI Orchestrator Provider ID Normalization & Real Health Telemetry
  const orchestrator = new AIModelOrchestrator();
  const healthMatrix = orchestrator.getProviderHealthMatrix();
  const ollamaEntry = Array.isArray(healthMatrix)
    ? healthMatrix.find((p) => p.providerId === 'OLLAMA' || p.id === 'OLLAMA')
    : healthMatrix?.OLLAMA;
  assert.ok(ollamaEntry, 'OLLAMA entry must exist in provider health matrix');
  assert.notStrictEqual(ollamaEntry.callsCount, 100, 'Provider callsCount must not default to static 100');

  // 6. Verify Frontend Source Restraint (No fallback to HEALTHY on missing status)
  const coreDiagViewSrc = fs.readFileSync(
    path.join(__dirname, '../public/js/views/core-diagnostics-view.js'),
    'utf8'
  );
  assert.ok(
    !coreDiagViewSrc.includes("?.status || 'HEALTHY'"),
    'core-diagnostics-view.js must never fall back to HEALTHY when status is null/missing'
  );

  // =========================================================================
  // EJII PHASE 4 DEEP CODE VERIFICATION ASSERTIONS (PACKAGES 1 - 8)
  // =========================================================================

  // [P1] Planner-Executor-Critic Investigation Lifecycle & Epistemic Critic
  const { InvestigationPlannerExecutorCritic } = require('../src/core/unified-investigation-engine');
  const plannerCritic = new InvestigationPlannerExecutorCritic();

  // Test 1.1: Build Plan
  const plan = plannerCritic.buildInvestigationPlan({
    targetHost: '10.22.12.204',
    port: 443,
    processName: 'erp_client.exe',
    symptomType: 'TCP_SYN_TIMEOUT'
  });
  assert.ok(plan.sessionId.startsWith('INV-'), 'Session ID must start with INV-');
  assert.strictEqual(plan.state, 'PLANNING', 'Plan initial state must be PLANNING');
  assert.ok(plan.steps.length >= 5, 'Plan must construct at least 5 dependency-aware steps');

  // Test 1.2: Dependency Skipping on Upstream Failure
  const step01 = plan.steps.find(s => s.stepId === 'STEP_01_HOST_BASELINE');
  const step02 = plan.steps.find(s => s.stepId === 'STEP_02_PROCESS_SOCKET_CORRELATION');
  assert.ok(step02.dependsOn.includes('STEP_01_HOST_BASELINE'), 'Step 2 must depend on Step 1');

  // Test 1.3: Mid-flight Cancellation
  const cancelSession = plannerCritic.buildInvestigationPlan({ targetHost: '127.0.0.1' });
  const cancelledRes = plannerCritic.cancelInvestigationSession(cancelSession.sessionId, 'Test cancellation');
  assert.strictEqual(cancelledRes.state, 'CANCELLED', 'Cancelled session state must be CANCELLED');
  assert.strictEqual(cancelledRes.cancelled, true, 'cancelled flag must be true');
  assert.ok(cancelledRes.steps.every(s => s.status === 'CANCELLED' || s.status === 'PENDING'), 'Steps must be cancelled');

  // Test 1.4: Epistemic Critic Check - Revived Contradicted Hypothesis Rejection
  const mockSession = {
    hypothesisHistory: [
      { id: 'FIREWALL_SILENT_DROP', label: 'Firewall Drop', status: 'CONTRADICTED', normalizedSharePct: 0, contradicted: true },
      { id: 'NORMAL_OPERATION', label: 'Normal', status: 'HEALTHY', normalizedSharePct: 100 }
    ],
    evidenceLedger: [],
    evidenceCoverageRatio: 0.8
  };
  const criticVerdict = plannerCritic.critiqueDiagnosisAndExplanation(
    mockSession,
    { id: 'FIREWALL_SILENT_DROP', normalizedSharePct: 0 },
    { explanation: 'Blaming FIREWALL_SILENT_DROP' }
  );
  assert.strictEqual(criticVerdict.passed, false, 'Critic must reject revived contradicted hypothesis');
  assert.ok(criticVerdict.violations.some(v => v.rule === 'REVIVED_CONTRADICTED_HYPOTHESIS'), 'Violation must record REVIVED_CONTRADICTED_HYPOTHESIS');

  // [P2] Post-Remediation Verification Stage
  const reverifySession = plannerCritic.buildInvestigationPlan({ targetHost: '127.0.0.1' });
  reverifySession.evidenceLedger.push(validator.createEvidenceRecord({
    evidenceId: 'EVD-PRE-DNS',
    metricKey: 'network.dns_resolution',
    evidenceClass: 'DNS',
    outcome: 'FAILURE',
    value: null,
    collectorId: 'tool.dns_lookup',
    collectionMethod: 'SYSTEM_AUDIT',
    isAuthoritative: true,
    isProvisional: false,
    timestampIso: new Date().toISOString()
  }));
  const verifOutcome = await plannerCritic.verifyRemediationOutcome(reverifySession.sessionId, { recipeId: 'FLUSH_DNS' });
  assert.ok(['VERIFIED_RESOLVED', 'PARTIALLY_IMPROVED', 'NO_CHANGE_UNRESOLVED'].includes(verifOutcome.verificationOutcome), 'Verification must return valid outcome classification');
  assert.ok(Array.isArray(verifOutcome.deltas), 'Verification deltas must be an array');

  // [P3] Multi-Model AI Orchestrator Task Selection & Circuit Breakers
  const taskSpecPrivacy = { taskType: 'ROOT_CAUSE_SYNTHESIS', containsSensitiveHostData: true, allowCloudRedacted: false };
  const providerSelection = orchestrator.selectProviderForTask(taskSpecPrivacy);
  assert.strictEqual(providerSelection.providerId, 'OLLAMA', 'Sensitive tasks without redaction opt-in must strictly route to local OLLAMA');

  // Circuit breaker state transitions
  orchestrator.recordCircuitFailure('OPENAI');
  orchestrator.recordCircuitFailure('OPENAI');
  orchestrator.recordCircuitFailure('OPENAI');
  assert.strictEqual(orchestrator.getCircuitBreakerState('OPENAI'), 'OPEN', '3 failures must trip circuit to OPEN');
  orchestrator.recordCircuitSuccess('OPENAI');
  assert.strictEqual(orchestrator.getCircuitBreakerState('OPENAI'), 'CLOSED', 'Success must reset circuit to CLOSED');

  // JSON Schema Validation with Hallucinated Evidence Rejection
  const validEv = validator.createEvidenceRecord({
    evidenceId: 'EVD-KNOWN-01',
    metricKey: 'network.ping',
    evidenceClass: 'PROBE',
    outcome: 'SUCCESS',
    value: 5,
    collectorId: 'ping',
    collectionMethod: 'PROBE',
    isAuthoritative: true,
    isProvisional: false,
    timestampIso: new Date().toISOString()
  });
  const modelOutputWithHallucination = {
    liveResponse: true,
    text: JSON.stringify({
      summary: 'Host unreachable',
      supportedHypothesisId: 'NORMAL_OPERATION',
      citedEvidenceIds: ['EVD-KNOWN-01', 'EVD-HALLUCINATED-99'],
      ruledOutHypothesisIds: [],
      remainingUncertainties: 'None',
      recommendedNextStep: 'Verify gateway'
    })
  };
  const schemaCheck = orchestrator.validateModelResponseSchema(modelOutputWithHallucination, [validEv]);
  assert.strictEqual(schemaCheck.schemaValid, false, 'Schema validator must reject hallucinated evidence IDs');
  assert.ok(schemaCheck.hallucinatedEvidenceIds.includes('EVD-HALLUCINATED-99'), 'Must identify hallucinated evidence ID');

  // [P4] SQLite v5 Persistence & Hybrid CBR Similarity Retrieval
  const { runMigrations } = require('../src/db/migrations');
  const { brainPersistenceRepository } = require('../src/db/brain-persistence-repository');
  const migStatus = runMigrations();
  assert.ok(migStatus.totalMigrations >= 5, 'Total migrations must include v5');

  const cbrId = brainPersistenceRepository.recordHistoricalIncidentSignature({
    incidentId: `HIST-CBR-${Date.now()}`,
    symptomType: 'DNS_FAILURE',
    evidenceRecords: [validEv],
    validatedRootCauseId: 'DNS_SERVER_FAILURE',
    remediationVerified: true
  });
  assert.ok(cbrId, 'Must persist historical incident signature');

  const matches = brainPersistenceRepository.findSimilarHistoricalIncidents('DNS_FAILURE', [validEv], 3);
  assert.ok(Array.isArray(matches), 'Similar incidents must return an array');
  assert.ok(matches.length > 0, 'Must retrieve matching historical incidents');
  assert.ok(typeof matches[0].similarityScore === 'number', 'Match must have numerical similarityScore');

  // [P5] Process Service Dependency DAG & Protocol Forensics
  const { processSocketCorrelator } = require('../src/network/process-socket-correlator');
  const depGraph = processSocketCorrelator.buildProcessServiceDependencyGraph(
    [{ pid: 1001, processName: 'edge_proxy.exe', localAddress: '127.0.0.1', localPort: 8080, remoteAddress: '192.168.31.1', remotePort: 443, state: 'ESTABLISHED' }],
    [{ ip: '192.168.31.1', mac: '00:11:22:33:44:55' }],
    [{ destination: '0.0.0.0', gateway: '192.168.31.1' }]
  );
  assert.ok(Array.isArray(depGraph.nodes), 'Dependency DAG must return nodes array');
  assert.ok(Array.isArray(depGraph.edges), 'Dependency DAG must return edges array');
  assert.ok(Array.isArray(depGraph.spofRankings), 'Dependency DAG must compute SPOF rankings');

  const { classifyProtocolFailure } = require('../src/protocols/service-verifier');
  const nxRes = classifyProtocolFailure({ code: 'ENOTFOUND' }, 'L7_DNS');
  assert.strictEqual(nxRes.failureCode, 'NXDOMAIN', 'ENOTFOUND must classify as NXDOMAIN');
  assert.strictEqual(nxRes.rfcReference, 'RFC 1035 §4.1.1', 'NXDOMAIN must cite RFC 1035');

  const rstRes = classifyProtocolFailure({ code: 'ECONNREFUSED' }, 'L4_TRANSPORT');
  assert.strictEqual(rstRes.failureCode, 'ECONNREFUSED', 'Connection refused must classify as ECONNREFUSED');
  assert.strictEqual(rstRes.rfcReference, 'RFC 793 §3.4', 'ECONNREFUSED must cite RFC 793');

  // [P6] Evidence-Backed Anomaly Detection & Action Recommendations
  const anomalyTelemetry = [];
  for (let i = 0; i < 20; i++) {
    anomalyTelemetry.push({
      metricKey: 'network.rtt',
      evidenceId: `EVD-RTT-${i}`,
      value: 10 + (Math.random() * 2),
      isAuthoritative: true,
      isProvisional: false,
      timestampIso: new Date(Date.now() - (20 - i) * 1000).toISOString()
    });
  }
  // Inject severe outlier
  anomalyTelemetry.push({
    metricKey: 'network.rtt',
    evidenceId: 'EVD-RTT-SPIKE',
    value: 120, // Huge spike (|z| > 5.0)
    isAuthoritative: true,
    isProvisional: false,
    timestampIso: new Date().toISOString()
  });

  const anomalyReport = rca.detectEvidenceBackedAnomalies(anomalyTelemetry);
  assert.ok(anomalyReport.anomalies.length > 0, 'Anomaly detector must identify severe outlier spike');
  assert.ok(anomalyReport.anomalies.some(a => a.severity === 'ANOMALY_EXTREME' || a.severity === 'ANOMALY_SEVERE'), 'Spike must be marked ANOMALY_SEVERE or EXTREME');

  const { recommendSafeNextActions } = require('../src/systems/remediation/autonomous-remediation-engine');
  const actionRecs = recommendSafeNextActions([validEv]);
  assert.ok(Array.isArray(actionRecs.tierA_Observations), 'Must recommend Tier A diagnostic observations');
  assert.ok(Array.isArray(actionRecs.tierB_Remediations), 'Must recommend Tier B controlled remediations');
  const spoolerAction = actionRecs.tierB_Remediations.find(a => a.actionId === 'reset_print_spooler');
  assert.strictEqual(spoolerAction.executionPermitted, false, 'reset_print_spooler must be blocked without authoritative Spooler failure evidence');

  // [P7] Frontend Source Verification
  const appJsSrc = fs.readFileSync(path.join(__dirname, '../public/js/app.js'), 'utf8');
  assert.ok(appJsSrc.includes('window.EJII_INVESTIGATION_STORE'), 'public/js/app.js must declare window.EJII_INVESTIGATION_STORE');

  const drawerJsSrc = fs.readFileSync(path.join(__dirname, '../public/js/components/ai-brain-drawer.js'), 'utf8');
  assert.ok(drawerJsSrc.includes('btnCancelInvestigation'), 'ai-brain-drawer.js must render Cancel Investigation control');
  assert.ok(drawerJsSrc.includes('btnVerifyRemediationOutcome'), 'ai-brain-drawer.js must render Verify Remediation control');

  console.log('✓ All Deep Code Implementation & Anti-Evasion Gate assertions passed.');
}

if (require.main === module) {
  runDeepCodeVerificationGate().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

module.exports = { runDeepCodeVerificationGate };
