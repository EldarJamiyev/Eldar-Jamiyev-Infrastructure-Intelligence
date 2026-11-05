/**
 * Test Suite 40: Investigation Integrity, Endpoint Correlation & Zero-Simulation RCA
 * Verifies:
 * [40.1] F-01 & F-04: Strict process matching; non-existent process returns ENDPOINT_NOT_FOUND_FOR_PROCESS
 * [40.2] F-02: Provisional warm baseline results in hostContext.overallStatus === 'UNKNOWN'
 * [40.3] F-03: Strict positive check for DNS pass; missing/failed stage does not pass as OK
 * [40.4] F-06 & F-75: Zero hardcoded fake IPs (10.168.195.33, 10.22.12.204, 10.168.195.1) in RCA engine
 * [40.5] F-74: Zero hardcoded fake latencies (2.4ms, 3800ms, 1.2ms) in RCA engine
 * [40.6] F-77: Observed facts conform to EvidenceRecord contracts (evidenceClass, outcome, isAuthoritative)
 */

'use strict';

const assert = require('assert');
const { unifiedInvestigationEngine } = require('../src/core/unified-investigation-engine');
const { DiagnosticReasoningEngine } = require('../src/core/rca-engine');
const { aiBrain } = require('../src/core/ai-brain');

async function runInvestigationIntegrityTests() {
  console.log('========================================================================');
  console.log('  TEST SUITE 40: INVESTIGATION INTEGRITY & ZERO-SIMULATION RCA (F-01..77) ');
  console.log('========================================================================\n');

  // [40.1] F-01 & F-04: Strict process matching & non-existent process handling
  console.log('[Test 40.1] Verifying strict process matching & ENDPOINT_NOT_FOUND_FOR_PROCESS (F-01, F-04)...');
  {
    const inv = await unifiedInvestigationEngine.runGuidedInvestigation({
      symptom: 'Testing non-existent process query',
      processQuery: 'phantom_non_existent_process_999999',
      initiatedBy: 'test_suite_40'
    });

    assert.strictEqual(inv.overallVerdict, 'ENDPOINT_NOT_FOUND_FOR_PROCESS', 'Must report ENDPOINT_NOT_FOUND_FOR_PROCESS when no process matches');
    assert.strictEqual(inv.targetHost, null, 'Must not arbitrarily pick target host when process query fails');
    assert.strictEqual(inv.stages[0].status, 'ENDPOINT_NOT_FOUND_FOR_PROCESS', 'Stage 1 status must be ENDPOINT_NOT_FOUND_FOR_PROCESS');
    assert.strictEqual(inv.stages[0].evidence.matchedProcess, null, 'Must NOT fallback to discoveredEndpoints[0]');
    console.log('  ✓ Process query non-match correctly terminates Stage 1 with ENDPOINT_NOT_FOUND_FOR_PROCESS.');
  }

  // [40.2] F-02: Provisional warm snapshot treats hostContext as UNKNOWN
  console.log('\n[Test 40.2] Verifying hostContext treats provisional warm baseline as UNKNOWN (F-02)...');
  {
    const savedSnapshot = aiBrain.lastHostHealthSnapshot;
    try {
      // Simulate provisional warm baseline
      aiBrain.lastHostHealthSnapshot = {
        overallStatus: 'INITIALIZING',
        isProvisional: true
      };

      const inv = await unifiedInvestigationEngine.runGuidedInvestigation({
        symptom: 'Testing provisional host context handling',
        targetHost: '127.0.0.1',
        targetPort: 80
      });

      const hostCorrelationStage = inv.stages.find(s => s.stageId === 'TOPOLOGY_AND_HOST_CORRELATION');
      assert.ok(hostCorrelationStage, 'Must contain TOPOLOGY_AND_HOST_CORRELATION stage');
      assert.strictEqual(hostCorrelationStage.evidence.hostContext.overallStatus, 'UNKNOWN', 'Provisional warm state must be treated as UNKNOWN (no fake HEALTHY)');
      assert.strictEqual(hostCorrelationStage.evidence.hostContext.isProvisional, true);
      console.log('  ✓ Provisional warm baseline correctly yields hostContext.overallStatus === "UNKNOWN".');
    } finally {
      aiBrain.lastHostHealthSnapshot = savedSnapshot;
    }
  }

  // [40.3] F-03: Strict positive check for DNS pass
  console.log('\n[Test 40.3] Verifying strict positive check for DNS pass (F-03)...');
  {
    // If dnsStage status is 'COLLECTION_ERROR' or missing, dnsOk must be false, resulting in DNS_RESOLUTION_FAILURE
    const inv = await unifiedInvestigationEngine.runGuidedInvestigation({
      symptom: 'Testing unresolvable domain DNS failure path',
      targetHost: 'unresolvable.invalid.internal.corp',
      targetPort: 80
    });

    const bayesianStage = inv.stages.find(s => s.stageId === 'BAYESIAN_AND_RAG_ASSESSMENT');
    assert.ok(bayesianStage);
    assert.strictEqual(bayesianStage.evidence.incidentType, 'DNS_RESOLUTION_FAILURE', 'Unresolvable domain must trigger DNS_RESOLUTION_FAILURE');
    console.log('  ✓ Strict positive DNS check correctly detects unresolvable domain as DNS_RESOLUTION_FAILURE.');
  }

  // [40.4] F-06 & F-75: Zero hardcoded fake IPs in RCA Engine
  console.log('\n[Test 40.4] Verifying zero hardcoded fake IPs in RCA Engine (F-06, F-75)...');
  {
    const rca = new DiagnosticReasoningEngine();
    const result = rca.analyzeIncident({
      incidentType: 'TCP_SYN_TIMEOUT'
    });

    const serialized = JSON.stringify(result);
    assert.ok(!serialized.includes('10.168.195.33'), 'Must NOT contain fake IP 10.168.195.33');
    assert.ok(!serialized.includes('10.22.12.204'), 'Must NOT contain fake IP 10.22.12.204');
    assert.ok(!serialized.includes('10.168.195.1'), 'Must NOT contain fake gateway IP 10.168.195.1');

    const gwProbe = result.expertDiagnosticMode.recommendedDistinguishingTests.find(t => t.testId === 'TEST-GATEWAY-PING');
    assert.ok(gwProbe, 'Must include gateway ping probe');
    assert.notStrictEqual(gwProbe.target, '10.168.195.1', 'Gateway probe must be dynamically resolved, not 10.168.195.1');
    console.log(`  ✓ RCA engine verified: Zero fake 10.x IPs; dynamic gateway resolved to: ${gwProbe.target}`);
  }

  // [40.5] F-74: Zero hardcoded fake latencies in RCA Engine
  console.log('\n[Test 40.5] Verifying zero hardcoded fake latencies in RCA Engine (F-74)...');
  {
    const rca = new DiagnosticReasoningEngine();
    const result = rca.analyzeIncident({
      incidentType: 'HIGH_HANDSHAKE_VS_APP_LATENCY'
      // Notice: No handshakeLatencyMs or appLatencyMs passed!
    });

    const serialized = JSON.stringify(result);
    assert.ok(!serialized.includes('2.4ms'), 'Must NOT synthesize fake 2.4ms latency');
    assert.ok(!serialized.includes('3800ms'), 'Must NOT synthesize fake 3800ms latency');

    // Test TCP_RST_REJECT without measuredRttMs
    const rstResult = rca.analyzeIncident({
      incidentType: 'TCP_RST_REJECT'
    });
    const rstSerialized = JSON.stringify(rstResult);
    assert.ok(!rstSerialized.includes('1.2ms'), 'Must NOT synthesize fake 1.2ms RST delta');
    console.log('  ✓ RCA engine verified: Zero fake latencies synthesized when unobserved.');
  }

  // [40.6] F-77: Observed facts conform to EvidenceRecord contracts
  console.log('\n[Test 40.6] Verifying EvidenceRecord contracts on observed facts (F-77)...');
  {
    const rca = new DiagnosticReasoningEngine();
    const result = rca.analyzeIncident({
      incidentType: 'TCP_SYN_TIMEOUT',
      destIp: '192.168.31.100',
      destPort: 443
    });

    for (const fact of result.expertDiagnosticMode.confirmedObservedFacts) {
      if (fact.evidenceType === 'Observed') {
        assert.strictEqual(fact.evidenceClass, 'OBSERVED_FACT', 'Observed fact must have evidenceClass OBSERVED_FACT');
        assert.strictEqual(fact.outcome, 'CONFIRMED', 'Observed fact must have outcome CONFIRMED');
        assert.strictEqual(fact.isAuthoritative, true, 'Observed fact must be authoritative');
      }
    }
    console.log('  ✓ Observed facts strictly adhere to EvidenceRecord contract standards.');
  }

  console.log('\n========================================================================');
  console.log('  TEST SUITE 40: 100% PASSED (ALL 6 RIGOROUS INVESTIGATION CHECKS)      ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runInvestigationIntegrityTests().catch(err => {
    console.error('Suite 40 FAILED:', err);
    process.exit(1);
  });
}

module.exports = { runInvestigationIntegrityTests };
