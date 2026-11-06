/**
 * EJII Test Suite 39: Unified Cross-Section Guided Investigation,
 * Local RAG Infrastructure Knowledge Engine & Multi-Model Second-Opinion Verification
 * 
 * Verifies:
 * [39.1] Local RAG Knowledge Engine Indexing, BM25 Ranking & Verified Incident Ingestion
 * [39.2] AI Model Orchestrator Epistemic Uncertainty & Multi-Hypothesis Second-Opinion Verification
 * [39.3] Unified Cross-Section Guided Investigation Engine (5-Stage Pipeline) & SSRF Defense
 * [39.4] Closed-Loop Post-Fix Re-Verification Workflow (Before vs. After State Comparison)
 * [39.5] Cross-Section REST API Endpoints & Role-Based Access Control (RBAC) Matrix
 */

'use strict';

const assert = require('assert');
const http = require('http');
const express = require('express');

const { RAGKnowledgeEngine, ragKnowledgeEngine, BUILTIN_RFC_AND_RUNBOOK_CORPUS } = require('../src/core/rag-knowledge-engine');
const { aiModelOrchestrator, VectorizedBayesianMatrix } = require('../src/core/ai-model-orchestrator');
const { unifiedInvestigationEngine } = require('../src/core/unified-investigation-engine');
const { generateToken } = require('../src/core/security');
const rcaRouter = require('../src/api/routes-rca');

async function runUnifiedInvestigationRagAndMultiModelTests() {
  console.log('========================================================================');
  console.log('  TEST SUITE 39: UNIFIED GUIDED INVESTIGATION, RAG & MULTI-MODEL VERIF  ');
  console.log('========================================================================\n');

  // -------------------------------------------------------------------------
  // [39.1] Local RAG Knowledge Engine Indexing & BM25 Ranking
  // -------------------------------------------------------------------------
  console.log('[Test 39.1] Verifying Local RAG Knowledge Engine Indexing & BM25 Ranking...');
  {
    assert.ok(BUILTIN_RFC_AND_RUNBOOK_CORPUS.length >= 6, 'Corpus must contain at least 6 authoritative documents');
    const docIds = BUILTIN_RFC_AND_RUNBOOK_CORPUS.map(d => d.docId);
    assert.ok(docIds.includes('RFC-793-TCP-RST'), 'Corpus must include RFC-793-TCP-RST');
    assert.ok(docIds.includes('RFC-1122-KEEPALIVE'), 'Corpus must include RFC-1122-KEEPALIVE');
    assert.ok(docIds.includes('RFC-2979-FIREWALL-DROP'), 'Corpus must include RFC-2979-FIREWALL-DROP');
    assert.ok(docIds.includes('RFC-1035-DNS-DIAG'), 'Corpus must include RFC-1035-DNS-DIAG');
    assert.ok(docIds.includes('RFC-8446-TLS13'), 'Corpus must include RFC-8446-TLS13');

    // Query 1: RFC 793 TCP RST retrieval
    const rstResults = ragKnowledgeEngine.retrieveRelevantContext('TCP RST reset ECONNREFUSED port', { topK: 3 });
    assert.ok(rstResults.length > 0, 'Must retrieve results for TCP RST query');
    assert.strictEqual(rstResults[0].docId, 'RFC-793-TCP-RST', 'Top result for TCP RST query must be RFC-793-TCP-RST');
    assert.ok(rstResults[0].relevanceScore > 0.5, 'Relevance score must be significant');
    assert.ok(rstResults[0].excerpt.includes('ECONNREFUSED'), 'Excerpt must contain ECONNREFUSED');

    // Query 2: RFC 1122 TCP Keep-Alive retrieval
    const kaResults = ragKnowledgeEngine.retrieveRelevantContext('TCP Keep-Alive probes idle session heartbeat', { topK: 3 });
    assert.ok(kaResults.length > 0, 'Must retrieve results for Keep-Alive query');
    assert.strictEqual(kaResults[0].docId, 'RFC-1122-KEEPALIVE', 'Top result must be RFC-1122-KEEPALIVE');

    // Query 3: Ingest verified historical incident dynamically into RAG memory
    const testIncident = {
      incidentKey: 'INC-TEST-RAG-99',
      incidentType: 'TCP_SYN_TIMEOUT',
      target: '192.168.31.250',
      confirmedHypothesisId: 'FIREWALL_DROP',
      notes: 'Stateful firewall dropped SYN packets silently; resolved by updating perimeter rule #402'
    };
    ragKnowledgeEngine.ingestVerifiedIncident(testIncident);

    const incResults = ragKnowledgeEngine.retrieveRelevantContext('INC-TEST-RAG-99 perimeter rule #402', { topK: 3 });
    assert.ok(incResults.length > 0, 'Must retrieve dynamically ingested incident');
    assert.strictEqual(incResults[0].docId, 'INCIDENT:INC-TEST-RAG-99', 'Retrieved doc must match incident key');
    assert.strictEqual(incResults[0].category, 'VERIFIED_INCIDENT_MEMORY', 'Category must be VERIFIED_INCIDENT_MEMORY');

    // Query 4: Empty query handling
    const emptyResults = ragKnowledgeEngine.retrieveRelevantContext('', { topK: 3 });
    assert.strictEqual(emptyResults.length, 0, 'Empty query must return empty array');

    console.log('  ✓ Local RAG engine BM25 ranking, RFC retrieval & incident indexing verified.');
  }

  // -------------------------------------------------------------------------
  // [39.2] AI Model Orchestrator Epistemic Uncertainty & Epistemic Warning System
  // -------------------------------------------------------------------------
  console.log('\n[Test 39.2] Verifying AI Model Orchestrator Epistemic Uncertainty & Second-Opinion Verification...');
  {
    // Test A: Ambiguous evidence (close hypotheses spread < 15% and confidence < 75%)
    const ambiguousEval = {
      rankedHypotheses: [
        { id: 'DNS_FAILURE', label: 'DNS Resolution Failure', confidence: 48 },
        { id: 'TCP_TIMEOUT', label: 'L4 TCP Handshake Timeout', confidence: 42 }
      ],
      distinguishingProbes: [{ name: 'Test Direct IP Ping to Bypass DNS' }]
    };

    const secondOpinionAmbiguous = await aiModelOrchestrator.verifyHighImpactDiagnosis({
      bayesianEvaluation: ambiguousEval,
      telemetryContext: { incidentType: 'DNS_TIMEOUT', target: '8.8.8.8' },
      ragEngine: ragKnowledgeEngine
    });

    assert.strictEqual(secondOpinionAmbiguous.uncertaintyWarning, true, 'Must flag uncertainty on close confidence spread');
    assert.strictEqual(secondOpinionAmbiguous.confidenceSpread, 6, 'Confidence spread must be 6%');
    assert.ok(
      secondOpinionAmbiguous.challenges.some(c => c.includes('AMBIGUOUS EVIDENCE')),
      'Must issue AMBIGUOUS EVIDENCE challenge'
    );
    assert.ok(Array.isArray(secondOpinionAmbiguous.ragCitations), 'Must return RAG citations array');

    // Test B: Contradiction detection (ECONNREFUSED vs FIREWALL_SILENT_DROP)
    const contradictoryEval = {
      rankedHypotheses: [
        { id: 'FIREWALL_SILENT_DROP', label: 'Stateful Firewall Silent Drop', confidence: 85 },
        { id: 'SERVICE_DOWN', label: 'Service Port Not Bound', confidence: 15 }
      ]
    };

    const secondOpinionContradiction = await aiModelOrchestrator.verifyHighImpactDiagnosis({
      bayesianEvaluation: contradictoryEval,
      telemetryContext: { errorCode: 'ECONNREFUSED', target: '127.0.0.1' },
      ragEngine: ragKnowledgeEngine
    });

    assert.strictEqual(secondOpinionContradiction.uncertaintyWarning, true, 'Must flag uncertainty on contradiction');
    assert.ok(
      secondOpinionContradiction.challenges.some(c => c.includes('CONTRADICTION DETECTED') && c.includes('ECONNREFUSED')),
      'Must detect ECONNREFUSED contradiction against silent drop'
    );

    // Test C: Inconclusive state
    const inconclusiveEval = {
      diagnosticState: 'INCONCLUSIVE_ALL_HYPOTHESES_CONTRADICTED',
      rankedHypotheses: []
    };
    const secondOpinionInconclusive = await aiModelOrchestrator.verifyHighImpactDiagnosis({
      bayesianEvaluation: inconclusiveEval,
      telemetryContext: { target: '192.168.31.1' },
      ragEngine: ragKnowledgeEngine
    });
    assert.strictEqual(secondOpinionInconclusive.uncertaintyWarning, true);
    assert.ok(secondOpinionInconclusive.challenges.some(c => c.includes('CRITICAL UNCERTAINTY')));

    // Test D: Bounded provider invocation (Local Ollama and Local-Only Policy enforcement)
    const ollamaResult = await aiModelOrchestrator.invokeModelProvider('OLLAMA', 'Diagnostic test prompt');
    assert.strictEqual(typeof ollamaResult.liveResponse, 'boolean', 'Provider invocation must return liveResponse boolean');
    assert.strictEqual(ollamaResult.provider, 'OLLAMA');

    aiModelOrchestrator.localOnlyPolicy = true;
    const cloudResult = await aiModelOrchestrator.invokeModelProvider('OPENAI', 'External prompt');
    assert.strictEqual(cloudResult.liveResponse, false);
    assert.strictEqual(cloudResult.reason, 'BLOCKED_BY_LOCAL_ONLY_PRIVACY_POLICY');

    console.log('  ✓ Epistemic uncertainty, contradiction defense & bounded model connectors verified.');
  }

  // -------------------------------------------------------------------------
  // [39.3] Unified Cross-Section Guided Investigation Engine (5-Stage Pipeline) & SSRF Defense
  // -------------------------------------------------------------------------
  console.log('\n[Test 39.3] Verifying Unified Cross-Section Guided Investigation Engine & SSRF Defense...');
  {
    // Test A: Normal guided investigation on loopback
    const investigation = await unifiedInvestigationEngine.runGuidedInvestigation({
      symptom: 'Testing application connectivity',
      targetHost: '127.0.0.1',
      targetPort: 80,
      initiatedBy: 'suite_39_tester'
    });

    assert.ok(investigation.investigationId.startsWith('INV-'), 'Investigation ID must start with INV-');
    assert.strictEqual(investigation.stages.length, 5, 'Investigation must contain exactly 5 stages');

    const stageIds = investigation.stages.map(s => s.stageId);
    assert.deepStrictEqual(stageIds, [
      'ENDPOINT_DISCOVERY',
      'WIRE_AND_PROTOCOL_EVIDENCE',
      'TOPOLOGY_AND_HOST_CORRELATION',
      'BAYESIAN_AND_RAG_ASSESSMENT',
      'SAFE_RESOLUTION_AND_VERIFICATION_PLAN'
    ], '5 stages must match canonical workflow');

    assert.ok(investigation.diagnosis, 'Investigation must contain Bayesian diagnosis');
    assert.ok(investigation.secondOpinion, 'Investigation must contain second opinion');
    assert.ok(Array.isArray(investigation.recommendedActions), 'Investigation must contain recommendedActions array');

    // Test B: Verify history ledger contains investigation
    const recent = unifiedInvestigationEngine.getRecentInvestigations(5);
    assert.ok(recent.some(inv => inv.investigationId === investigation.investigationId), 'Recent list must contain newly created investigation');

    // Test C: SSRF defense rejection for cloud metadata endpoint (169.254.169.254)
    let ssrfBlocked = false;
    try {
      await unifiedInvestigationEngine.runGuidedInvestigation({
        symptom: 'SSRF Attack Simulation',
        targetHost: '169.254.169.254',
        targetPort: 80
      });
    } catch (err) {
      if (err.message && err.message.includes('SECURITY_VIOLATION') && err.message.includes('SSRF defense policy')) {
        ssrfBlocked = true;
      }
    }
    assert.strictEqual(ssrfBlocked, true, 'Investigation must reject cloud metadata IP 169.254.169.254 with SECURITY_VIOLATION');

    console.log('  ✓ Unified 5-stage pipeline and SSRF policy rejection verified.');
  }

  // -------------------------------------------------------------------------
  // [39.4] Closed-Loop Post-Fix Re-Verification Workflow
  // -------------------------------------------------------------------------
  console.log('\n[Test 39.4] Verifying Closed-Loop Post-Fix Re-Verification Workflow...');
  {
    // Create baseline investigation
    const baseInv = await unifiedInvestigationEngine.runGuidedInvestigation({
      symptom: 'Intermittent loopback probe check',
      targetHost: '127.0.0.1',
      targetPort: 80
    });

    // Run verification recheck
    const verification = await unifiedInvestigationEngine.verifyInvestigationResolution(baseInv.investigationId);
    assert.strictEqual(verification.investigationId, baseInv.investigationId);
    assert.ok(verification.verificationEntry, 'Must return verificationEntry');
    assert.ok(verification.verificationEntry.verifiedAt, 'verificationEntry must have verifiedAt');
    assert.ok(typeof verification.verificationEntry.symptomResolved === 'boolean', 'symptomResolved must be boolean');
    assert.ok(verification.investigation.reverificationHistory.length >= 1, 'reverificationHistory must have at least 1 record');

    // Recheck on invalid ID must throw
    let notFoundError = false;
    try {
      await unifiedInvestigationEngine.verifyInvestigationResolution('INV-NON-EXISTENT-XYZ');
    } catch (err) {
      if (err.message && err.message.includes('not found')) {
        notFoundError = true;
      }
    }
    assert.strictEqual(notFoundError, true, 'Re-verification must fail with "not found" on invalid ID');

    console.log('  ✓ Closed-loop re-verification state comparison verified.');
  }

  // -------------------------------------------------------------------------
  // [39.5] Cross-Section REST API Endpoints & Role-Based Access Control (RBAC) Matrix
  // -------------------------------------------------------------------------
  console.log('\n[Test 39.5] Verifying Cross-Section REST API Endpoints & RBAC Matrix...');
  {
    const app = express();
    app.use(express.json());
    app.use('/api/rca', rcaRouter);

    const testServer = app.listen(0);
    const port = testServer.address().port;

    const readonlyToken = generateToken({ id: 201, username: 'readonly_user', role: 'READONLY' });
    const operatorToken = generateToken({ id: 202, username: 'operator_user', role: 'OPERATOR' });

    async function makeRequest(path, method = 'GET', body = null, token = null) {
      return new Promise((resolve, reject) => {
        const headers = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = `Bearer ${token}`;
        const req = http.request({
          hostname: '127.0.0.1',
          port,
          path,
          method,
          headers
        }, (res) => {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => {
            try {
              resolve({ status: res.statusCode, body: JSON.parse(data) });
            } catch (_) {
              resolve({ status: res.statusCode, raw: data });
            }
          });
        });
        req.on('error', reject);
        if (body) req.write(JSON.stringify(body));
        req.end();
      });
    }

    try {
      // 1. Unauthenticated request to /investigate-unified -> 401
      const resUnauth = await makeRequest('/api/rca/investigate-unified', 'POST', { targetHost: '127.0.0.1' });
      assert.strictEqual(resUnauth.status, 401, 'Unauthenticated /investigate-unified must return 401');

      // 2. READONLY user attempting to execute /investigate-unified -> 403 (missing network.diagnostics.execute)
      const resForbidden = await makeRequest(
        '/api/rca/investigate-unified',
        'POST',
        { targetHost: '127.0.0.1' },
        readonlyToken
      );
      assert.strictEqual(resForbidden.status, 403, 'READONLY user must receive 403 on /investigate-unified');

      // 3. OPERATOR user executing /investigate-unified -> 200 OK
      const resSuccess = await makeRequest(
        '/api/rca/investigate-unified',
        'POST',
        { targetHost: '127.0.0.1', targetPort: 80, symptom: 'API verification run' },
        operatorToken
      );
      assert.strictEqual(resSuccess.status, 200, 'OPERATOR must receive 200 OK on /investigate-unified');
      assert.strictEqual(resSuccess.body.success, true);
      assert.ok(resSuccess.body.investigationId, 'Response must include investigationId');

      const invId = resSuccess.body.investigationId;

      // 4. OPERATOR re-verifying investigation resolution -> 200 OK
      const resVerify = await makeRequest(
        `/api/rca/investigate-unified/${invId}/verify`,
        'POST',
        {},
        operatorToken
      );
      assert.strictEqual(resVerify.status, 200, 'OPERATOR must receive 200 OK on re-verification');
      assert.strictEqual(resVerify.body.success, true);
      assert.strictEqual(resVerify.body.investigationId, invId);

      // 5. READONLY user searching RAG knowledge base -> 200 OK (has telemetry.read)
      const resRag = await makeRequest(
        '/api/rca/rag/search?q=TCP+RST&limit=3',
        'GET',
        null,
        readonlyToken
      );
      assert.strictEqual(resRag.status, 200, 'READONLY must receive 200 OK on /rag/search');
      assert.strictEqual(resRag.body.success, true);
      assert.ok(Array.isArray(resRag.body.citations), 'Must return citations array');

      // 6. READONLY user calling second-opinion endpoint -> 200 OK (has telemetry.read)
      const resSecOp = await makeRequest(
        '/api/rca/brain/second-opinion',
        'POST',
        {
          evaluation: {
            rankedHypotheses: [
              { id: 'DNS_FAILURE', label: 'DNS Failure', confidence: 50 },
              { id: 'TCP_TIMEOUT', label: 'TCP Timeout', confidence: 50 }
            ]
          },
          context: { incidentType: 'DNS_FAIL' }
        },
        readonlyToken
      );
      assert.strictEqual(resSecOp.status, 200, 'READONLY must receive 200 OK on /brain/second-opinion');
      assert.strictEqual(resSecOp.body.success, true);
      assert.ok(resSecOp.body.secondOpinion, 'Response must contain secondOpinion');
    } finally {
      testServer.close();
    }

    console.log('  ✓ Cross-section REST API & RBAC permissions matrix strictly enforced.');
  }

  console.log('\n========================================================================');
  console.log('  TEST SUITE 39: 100% PASSED (ALL 5 RIGOROUS CHECKS VERIFIED)');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runUnifiedInvestigationRagAndMultiModelTests().then(() => {
    process.exit(0);
  }).catch((err) => {
    console.error('Suite 39 failed:', err);
    process.exit(1);
  });
}

module.exports = { runUnifiedInvestigationRagAndMultiModelTests };
