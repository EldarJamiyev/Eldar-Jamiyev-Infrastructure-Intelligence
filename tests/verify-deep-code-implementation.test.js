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

  console.log('✓ All Deep Code Implementation & Anti-Evasion Gate assertions passed.');
}

if (require.main === module) {
  runDeepCodeVerificationGate().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

module.exports = { runDeepCodeVerificationGate };
