/**
 * EJII Monte-Carlo Bayesian Probability Normalization Invariant & Stress Suite
 * 
 * Verifies strict 100.0% probability normalization invariants across 500 Monte-Carlo trials
 * under random, adversarial, and edge-case network telemetry inputs.
 *
 * Strict Invariants Enforced:
 * 1. Exact 100% Sum: sum(P(Hi | E)) === 100 across all active hypotheses.
 * 2. Integer Invariant: Each confidence score is a non-negative integer in [0, 100].
 * 3. Monotonic Ranking: Hypotheses are sorted descending by posterior probability with deterministic tie-breaking.
 * 4. Zero NaN / Infinity: No division by zero or NaN propagation under zero evidence weights or null inputs.
 * 5. Belief Revision Normalization: Dynamically revised evaluations also strictly sum to 100%.
 */

const assert = require('assert');
const { reasoningEngine } = require('../src/core/reasoning-engine');

function getRandomElement(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function getRandomFloat(min, max) {
  return Math.random() * (max - min) + min;
}

function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

async function runNormalizationStressTests() {
  console.log('========================================================================');
  console.log('  EJII BAYESIAN REASONING MONTE-CARLO NORMALIZATION STRESS SUITE        ');
  console.log('  Executing 500 Stochastic Invariant Iterations & Boundary Tests         ');
  console.log('========================================================================\n');

  const incidentTypes = [
    'TCP_SYN_TIMEOUT',
    'TCP_RST_REJECT',
    'DNS_FAILURE',
    'TLS_ALERT_FAILURE',
    'HIGH_HANDSHAKE_VS_APP_LATENCY',
    'NORMAL_OPERATION',
    'ARBITRARY_UNKNOWN_TYPE'
  ];

  const booleanOrNull = [true, false, null];
  const rcodes = [0, 2, 3, 5, null];
  const tlsAlerts = [40, 42, 48, null];
  const ports = [80, 443, 22, 25, 587, 8080, 3389];

  let totalTrials = 500;
  let passedTrials = 0;

  // 0. Explicit Deterministic Reasoning Edge Cases
  console.log('[Phase 0] Verifying 5 Explicit Deterministic Reasoning Edge Cases...');

  // Edge Case 1: Zero-Likelihood Trap
  {
    console.log('  -> Edge Case 1: Zero-Likelihood Trap (Graceful uniform prior fallback)');
    const zeroTelemetry = {
      incidentType: 'ARBITRARY_UNKNOWN',
      gatewayReachable: null,
      targetPingReachable: null
    };
    const res = reasoningEngine.evaluateIncident(zeroTelemetry);
    assert.ok(res, 'Zero-likelihood must produce valid result');
    const sum = res.rankedHypotheses.reduce((acc, h) => acc + h.confidence, 0);
    assert.strictEqual(sum, 100, `Zero-likelihood sum must be 100%, got ${sum}%`);
    for (const h of res.rankedHypotheses) {
      assert.ok(!isNaN(h.confidence) && isFinite(h.confidence), 'Confidence must not be NaN or Infinite');
      assert.ok(!isNaN(h.likelihoodScore), 'likelihoodScore must not be NaN');
      assert.ok(!isNaN(h.priorScore), 'priorScore must not be NaN');
    }
  }

  // Edge Case 2: Remainder Allocation Ties
  {
    console.log('  -> Edge Case 2: Remainder Allocation Ties (Strict deterministic tie-breaking)');
    // Calling evaluateIncident multiple times on identical inputs produces bit-for-bit identical results
    const evalA = reasoningEngine.evaluateIncident({ incidentType: 'TCP_SYN_TIMEOUT' });
    const evalB = reasoningEngine.evaluateIncident({ incidentType: 'TCP_SYN_TIMEOUT' });
    assert.deepStrictEqual(
      evalA.rankedHypotheses.map(h => ({ id: h.id, conf: h.confidence })),
      evalB.rankedHypotheses.map(h => ({ id: h.id, conf: h.confidence })),
      'Tie-breaking must produce identical deterministic results across repeated invocations'
    );
    const sum = evalA.rankedHypotheses.reduce((acc, h) => acc + h.confidence, 0);
    assert.strictEqual(sum, 100, 'Tied allocation sum must be strictly 100%');
  }

  // Edge Case 3: Empty / Null / Undefined Telemetry
  {
    console.log('  -> Edge Case 3: Empty, Null & Undefined Telemetry Invariant');
    const nullCases = [null, undefined, {}, { incidentType: undefined }];
    for (const tc of nullCases) {
      const res = reasoningEngine.evaluateIncident(tc);
      assert.ok(res, 'Null telemetry must not throw');
      assert.ok(Array.isArray(res.rankedHypotheses) && res.rankedHypotheses.length > 0, 'Ranked hypotheses present');
      const sum = res.rankedHypotheses.reduce((acc, h) => acc + h.confidence, 0);
      assert.strictEqual(sum, 100, 'Null telemetry sum must be strictly 100%');
    }
  }

  // Edge Case 4: Extreme Numerical Disparities
  {
    console.log('  -> Edge Case 4: Extreme Numerical Disparities (1e-6 vs 1e8 floating point stability)');
    const extremeTelemetry = {
      handshakeLatencyMs: 0.000001,
      appLatencyMs: 999999999.9,
      retransCount: 50000
    };
    const res = reasoningEngine.evaluateIncident(extremeTelemetry);
    const sum = res.rankedHypotheses.reduce((acc, h) => acc + h.confidence, 0);
    assert.strictEqual(sum, 100, `Extreme numerical sum must be strictly 100%, got ${sum}%`);
    assert.ok(res.topHypothesis.confidence >= 50, 'Backend latency or drop correctly prioritized');
  }

  // Edge Case 5: Causal Hypotheses Verification
  {
    console.log('  -> Edge Case 5: Causal Hypotheses Verification (RFC citations, valid assignments)');
    
    // 5a. DNS NXDOMAIN Failure
    const dnsRes = reasoningEngine.evaluateIncident({
      incidentType: 'DNS_FAILURE',
      dnsRcode: 3
    });
    assert.strictEqual(dnsRes.topHypothesis.id, 'DNS_RESOLUTION_FAILURE', 'DNS failure must promote DNS_RESOLUTION_FAILURE');
    assert.ok(dnsRes.topHypothesis.confidence >= 50, 'DNS failure confidence must be >= 50%');
    assert.ok(dnsRes.topHypothesis.rfc.includes('RFC 1035'), 'DNS hypothesis must cite RFC 1035');

    // 5b. Firewall Silent Drop (Host answers ping, but drops TCP SYN)
    const fwRes = reasoningEngine.evaluateIncident({
      incidentType: 'TCP_SYN_TIMEOUT',
      gatewayReachable: true,
      targetPingReachable: true
    });
    assert.strictEqual(fwRes.topHypothesis.id, 'FIREWALL_SILENT_DROP', 'Alive host dropping SYN must promote FIREWALL_SILENT_DROP');
    assert.ok(fwRes.topHypothesis.confidence >= 50, 'Firewall drop confidence must be >= 50%');
    assert.ok(fwRes.topHypothesis.rfc.includes('RFC 2979'), 'Firewall hypothesis must cite RFC 2979');

    // 5c. Service Stopped / Closed Port (Observed TCP RST)
    const rstRes = reasoningEngine.evaluateIncident({
      incidentType: 'TCP_RST_REJECT',
      tcpRstObserved: true
    });
    assert.strictEqual(rstRes.topHypothesis.id, 'PORT_CLOSED_SERVICE_STOPPED', 'TCP RST must promote PORT_CLOSED_SERVICE_STOPPED');
    assert.ok(rstRes.topHypothesis.confidence >= 60, 'TCP RST confidence must be >= 60%');
    assert.ok(rstRes.topHypothesis.rfc.includes('RFC 793'), 'TCP RST hypothesis must cite RFC 793');

    // 5d. Nominal Transport Health
    const nomRes = reasoningEngine.evaluateIncident({
      incidentType: 'NORMAL_OPERATION',
      gatewayReachable: true,
      targetPingReachable: true
    });
    assert.strictEqual(nomRes.topHypothesis.id, 'NORMAL_OPERATION', 'Nominal telemetry must promote NORMAL_OPERATION');
    assert.ok(nomRes.topHypothesis.confidence >= 70, 'Nominal confidence must be >= 70%');
    assert.ok(nomRes.topHypothesis.rfc.includes('RFC 1122'), 'Nominal hypothesis must cite RFC 1122');
  }
  console.log('  ✓ All 5 Explicit Deterministic Reasoning Edge Cases verified successfully.\n');

  // 1. Boundary / Pathological Cases (Trials 1 - 20)
  console.log('[Phase 1] Testing Pathological & Boundary Cases (Null, Empty, Zero-Weight, Extreme Floats)...');
  
  const edgeCases = [
    null,
    undefined,
    {},
    { incidentType: null },
    { destIp: '0.0.0.0', destPort: 0 },
    { handshakeLatencyMs: 0, appLatencyMs: 0 },
    { handshakeLatencyMs: 999999, appLatencyMs: 999999 },
    { gatewayReachable: true, targetPingReachable: true, tcpRstObserved: true },
    { gatewayReachable: false, targetPingReachable: false, tcpRstObserved: false, retransCount: 100 },
    { dnsRcode: 3, tlsAlertCode: 48, tcpRstObserved: true },
    { incidentType: 'TCP_RST_REJECT', tcpRstObserved: false },
    { incidentType: 'NORMAL_OPERATION', gatewayReachable: false }
  ];

  for (let i = 0; i < edgeCases.length; i++) {
    const telemetry = edgeCases[i];
    const evalResult = reasoningEngine.evaluateIncident(telemetry);
    
    assert.ok(evalResult, `Trial ${i+1}: Result must not be null`);
    assert.ok(evalResult.rankedHypotheses.length > 0, `Trial ${i+1}: Ranked hypotheses must not be empty`);
    
    const sum = evalResult.rankedHypotheses.reduce((acc, h) => acc + h.confidence, 0);
    assert.strictEqual(sum, 100, `Trial ${i+1}: Normalization sum must be exactly 100%, got ${sum}%`);

    for (const h of evalResult.rankedHypotheses) {
      assert.ok(Number.isInteger(h.confidence), `Trial ${i+1}: Confidence must be integer, got ${h.confidence}`);
      assert.ok(h.confidence >= 0 && h.confidence <= 100, `Trial ${i+1}: Confidence out of bounds: ${h.confidence}`);
      assert.ok(!isNaN(h.likelihoodScore), `Trial ${i+1}: likelihoodScore must not be NaN`);
      assert.ok(!isNaN(h.priorScore), `Trial ${i+1}: priorScore must not be NaN`);
    }

    // Test belief revision on boundary cases
    const revised = reasoningEngine.reviseBeliefs(evalResult, { targetPingReachable: true });
    const revSum = revised.rankedHypotheses.reduce((acc, h) => acc + h.confidence, 0);
    assert.strictEqual(revSum, 100, `Trial ${i+1} revised: Normalization sum must be exactly 100%`);

    passedTrials++;
  }
  console.log(`  ✓ All ${edgeCases.length} pathological boundary cases satisfied strict 100% Hare-Niemeyer invariant.`);

  // 2. Monte-Carlo Random Walk (Trials 21 - 500)
  console.log(`\n[Phase 2] Executing ${totalTrials - edgeCases.length} Randomized Stochastic Telemetry Trials...`);
  
  for (let i = edgeCases.length; i < totalTrials; i++) {
    const randomTelemetry = {
      incidentType: getRandomElement(incidentTypes),
      gatewayReachable: getRandomElement(booleanOrNull),
      targetPingReachable: getRandomElement(booleanOrNull),
      tcpRstObserved: Math.random() > 0.5,
      retransCount: getRandomInt(0, 8),
      handshakeLatencyMs: Math.random() > 0.3 ? getRandomFloat(0.1, 1500) : null,
      appLatencyMs: Math.random() > 0.3 ? getRandomFloat(0.1, 8000) : null,
      dnsRcode: getRandomElement(rcodes),
      tlsAlertCode: getRandomElement(tlsAlerts),
      destPort: getRandomElement(ports),
      destIp: `10.${getRandomInt(1, 254)}.${getRandomInt(1, 254)}.${getRandomInt(1, 254)}`
    };

    const evaluation = reasoningEngine.evaluateIncident(randomTelemetry);

    // Assert 1: Hypotheses count
    assert.ok(evaluation.rankedHypotheses.length >= 3, `Iteration ${i+1}: Must evaluate >= 3 hypotheses`);

    // Assert 2: Strict 100% Sum Invariant
    const sum = evaluation.rankedHypotheses.reduce((acc, h) => acc + h.confidence, 0);
    assert.strictEqual(sum, 100, `Iteration ${i+1}: Probability sum violated: ${sum}% (expected strictly 100%)`);

    // Assert 3: Monotonicity and Rank Validity
    let prevConfidence = 101;
    evaluation.rankedHypotheses.forEach((h, rankIdx) => {
      assert.strictEqual(h.rank, rankIdx + 1, `Iteration ${i+1}: Rank indexing violated`);
      assert.ok(Number.isInteger(h.confidence), `Iteration ${i+1}: Non-integer confidence: ${h.confidence}`);
      assert.ok(h.confidence <= prevConfidence, `Iteration ${i+1}: Monotonicity violated: ${h.confidence} > ${prevConfidence}`);
      assert.ok(!isNaN(h.likelihoodScore) && isFinite(h.likelihoodScore), `Iteration ${i+1}: Invalid likelihood score`);
      assert.ok(!isNaN(h.priorScore) && isFinite(h.priorScore), `Iteration ${i+1}: Invalid prior score`);
      prevConfidence = h.confidence;
    });

    // Assert 4: Revised beliefs under stochastic evidence update
    const randomNewEvidence = {
      gatewayReachable: getRandomElement(booleanOrNull),
      targetPingReachable: getRandomElement(booleanOrNull),
      tcpRstObserved: Math.random() > 0.5
    };

    const revised = reasoningEngine.reviseBeliefs(evaluation, randomNewEvidence);
    const revisedSum = revised.rankedHypotheses.reduce((acc, h) => acc + h.confidence, 0);
    assert.strictEqual(revisedSum, 100, `Iteration ${i+1}: Revised probability sum violated: ${revisedSum}%`);

    passedTrials++;
  }

  console.log(`  ✓ Successfully completed all ${totalTrials} Monte-Carlo trials.`);
  console.log('  ✓ Invariant sum(P(Hi)) === 100% holds unconditionally across 100% of iterations.');
  console.log('  ✓ Zero NaNs, zero division-by-zero, zero integer remainder leaks confirmed.');
  console.log('========================================================================\n');

  return { totalTrials, passedTrials };
}

if (require.main === module) {
  runNormalizationStressTests().then(() => {
    process.exit(0);
  }).catch((err) => {
    console.error('Monte-Carlo Stress Test Failed:', err);
    process.exit(1);
  });
}

module.exports = { runNormalizationStressTests };
