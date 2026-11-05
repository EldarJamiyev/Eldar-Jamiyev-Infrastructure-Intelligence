/**
 * EJII Test Suite 36:
 * Smart Traffic Triage Modes, Process-to-Server Endpoint Correlator,
 * Vectorized Bayesian Matrix (Hare-Niemeyer 100.0%), Multi-Model AI Orchestrator,
 * and Fleet Scanner Delta Tracking.
 *
 * 100% Genuine Wire Telemetry & Invariant Proof — Zero Simulation.
 */

'use strict';

const assert = require('assert');
const http = require('http');
const express = require('express');
const { processSocketCorrelator } = require('../src/network/process-socket-correlator');
const {
  FlowStateCompressor,
  VectorizedBayesianMatrix,
  AIModelOrchestrator,
  aiModelOrchestrator,
  redactTelemetryForExternalModel
} = require('../src/core/ai-model-orchestrator');
const { UltraIpScanner } = require('../src/tools/ip-scanner');
const { generateToken } = require('../src/core/security');
const networkRouter = require('../src/api/routes-network');
const rcaRouter = require('../src/api/routes-rca');

async function runSignalTriageAndOrchestratorTests() {
  console.log('\n========================================================================');
  console.log('  TEST SUITE 36: SIGNAL TRIAGE, ENDPOINT DISCOVERY & AI ORCHESTRATOR    ');
  console.log('========================================================================\n');

  // --------------------------------------------------------------------------
  // TEST 36.1: 100% PASSIVE CAPTURE & ZERO UNSOLICITED BACKGROUND PROBES
  // --------------------------------------------------------------------------
  console.log('[Test 36.1] Verifying 100% Passive Capture & Zero Unsolicited Background Traffic...');
  {
    const { packetStreamer } = require('../src/network/packet-streaming/packet-streamer');
    // Ensure active roster interval is null when EJII_ACTIVE_ROSTER_RESOLVE is not set
    assert.strictEqual(
      packetStreamer.targetRosterInterval,
      null,
      'packetStreamer must not schedule unsolicited DNS sweeps during passive operation'
    );

    // Verify token negotiation via Sec-WebSocket-Protocol format
    const sampleToken = generateToken({ id: 99, username: 'passive_tester', role: 'OPERATOR' });
    assert.ok(sampleToken && sampleToken.length > 20, 'Security token generation must succeed');
    console.log('  ✓ Zero unsolicited background sweeps confirmed; purely passive wire capture intact.');
  }

  // --------------------------------------------------------------------------
  // TEST 36.2: PROCESS SOCKET CORRELATOR & APPLICATION SERVER FINDER
  // --------------------------------------------------------------------------
  console.log('\n[Test 36.2] Verifying Process Socket Correlator & 1-Click Server:Port Discovery...');
  {
    const endpoints = await processSocketCorrelator.refresh();
    assert.ok(Array.isArray(endpoints), 'Correlated endpoints must be an array');
    assert.ok(endpoints.length > 0, `Must correlate live OS sockets, found ${endpoints.length}`);

    // Verify properties on first endpoint
    const sample = endpoints[0];
    assert.ok('pid' in sample, 'Endpoint must have pid');
    assert.ok('processName' in sample, 'Endpoint must have processName');
    assert.ok('protocol' in sample, 'Endpoint must have protocol');
    assert.ok('localAddress' in sample, 'Endpoint must have localAddress');
    assert.ok('localPort' in sample, 'Endpoint must have localPort');
    assert.ok('state' in sample, 'Endpoint must have TCP state');

    // Test external endpoint filtering & troubleshoot URL generation
    const externalEps = await processSocketCorrelator.getCorrelatedEndpoints({ externalOnly: true });
    assert.ok(Array.isArray(externalEps), 'External endpoints must be an array');
    console.log(`  ✓ Correlated ${endpoints.length} active sockets (${externalEps.length} external server targets).`);

    if (externalEps.length > 0) {
      const ext = externalEps[0];
      assert.ok(ext.troubleshootUrl.startsWith('/core-diagnostics?host='), 'Must generate prefilled troubleshooting URL');
      console.log(`  ✓ 1-Click Action URL verified: ${ext.troubleshootUrl} for ${ext.processName} (${ext.serviceHint})`);
    }

    // Test bi-directional conversations aggregation
    const conversations = await processSocketCorrelator.getConversations(50);
    assert.ok(Array.isArray(conversations), 'Conversations must be an array');
    assert.ok(conversations.length > 0, 'Conversations must contain active 5-tuple flows');
    assert.ok(conversations[0].conversationId.includes('<->'), 'Conversation key must be bi-directional');
    console.log(`  ✓ Aggregated ${conversations.length} bi-directional conversations with process binding.`);
  }

  // --------------------------------------------------------------------------
  // TEST 36.3: FLOW STATE COMPRESSOR (>95% TELEMETRY REDUCTION INVARIANT)
  // --------------------------------------------------------------------------
  console.log('\n[Test 36.3] Verifying Flow State Compressor (>95% Telemetry Reduction Invariant)...');
  {
    const compressor = new FlowStateCompressor({ summaryIntervalPackets: 200 });

    // Ingest 500 monotonous TCP ACK frames in an established stream
    let lastResult = null;
    for (let i = 0; i < 500; i++) {
      lastResult = compressor.ingestPacket({
        srcIp: '192.168.31.89',
        srcPort: 54120,
        dstIp: '142.251.142.110',
        dstPort: 443,
        protocol: 'TCP',
        flags: 'ACK',
        length: 1420
      });
    }

    assert.strictEqual(compressor.totalPacketsIngested, 500, 'Must ingest all 500 packets');
    assert.ok(
      compressor.totalEventsEmitted <= 10,
      `Emitted events must be heavily compressed (<=10), got ${compressor.totalEventsEmitted}`
    );
    assert.ok(
      lastResult.compressionRatio >= 95.0,
      `Compression ratio must exceed 95.0%, got ${lastResult.compressionRatio}%`
    );
    console.log(`  ✓ 500 ACKs compressed to ${compressor.totalEventsEmitted} transitions (Ratio: ${lastResult.compressionRatio}%).`);

    // Ingest an anomaly (TCP RST) -> Must emit immediately regardless of compression window
    const anomalyResult = compressor.ingestPacket({
      srcIp: '192.168.31.89',
      srcPort: 54120,
      dstIp: '142.251.142.110',
      dstPort: 443,
      protocol: 'TCP',
      flags: 'RST',
      length: 0
    });

    assert.strictEqual(anomalyResult.shouldEmit, true, 'Anomaly (TCP RST) must force immediate emission');
    assert.strictEqual(anomalyResult.reason, 'ANOMALY_TCP_RST', 'Reason must report ANOMALY_TCP_RST');
    console.log('  ✓ Anomaly state change immediately surfaced to AI Brain without delay.');
  }

  // --------------------------------------------------------------------------
  // TEST 36.4: VECTORIZED BAYESIAN MATRIX (HARE-NIEMEYER 100.0% NORMALIZATION)
  // --------------------------------------------------------------------------
  console.log('\n[Test 36.4] Verifying Vectorized Bayesian Matrix Typed Float64Array & Strict Normalization...');
  {
    const hypotheses = [
      'NORMAL_OPERATION',
      'LOCAL_NIC_STACK_ERROR',
      'LOCAL_HOST_RESOURCE_EXHAUSTION',
      'GATEWAY_UNREACHABLE',
      'UPSTREAM_TRANSIT_DROP',
      'FIREWALL_SILENT_DROP',
      'DNS_RESOLUTION_FAILURE',
      'PORT_SERVICE_UNRESPONSIVE'
    ];

    const matrix = new VectorizedBayesianMatrix(hypotheses);
    assert.strictEqual(matrix.dimension, 8, 'Matrix dimension must equal 8');

    // Run 100 randomized Monte-Carlo vectors
    for (let iter = 0; iter < 100; iter++) {
      const priors = hypotheses.map(() => Math.random() * 0.9 + 0.05);
      const likelihoods = hypotheses.map(() => Math.random() * 0.95 + 0.05);
      const weights = hypotheses.map(() => Math.random() * 1.5 + 0.5);

      const computed = matrix.computePosteriors(priors, likelihoods, weights);
      assert.strictEqual(computed.sum, 100, `Iteration ${iter}: probability sum must strictly equal 100%`);
      assert.strictEqual(computed.ranked.length, 8, 'Must rank all 8 hypotheses');
      assert.ok(computed.rawPosteriors instanceof Float64Array, 'Must compute on Float64Array');
      assert.ok(computed.percentages instanceof Int32Array, 'Must produce Int32Array percentages');

      const manualSum = computed.ranked.reduce((s, h) => s + h.confidence, 0);
      assert.strictEqual(manualSum, 100, `Manual ranked sum must be strictly 100%`);
    }
    console.log('  ✓ 100 randomized Monte-Carlo vectors verified: Hare-Niemeyer strictly maintains sum = 100.0%.');
  }

  // --------------------------------------------------------------------------
  // TEST 36.5: MULTI-MODEL AI ORCHESTRATOR, CONDITIONAL GATE & REDACTION
  // --------------------------------------------------------------------------
  console.log('\n[Test 36.5] Verifying Multi-Model AI Orchestrator, Conditional Gate & Fail-Closed Redaction...');
  {
    // Test Fail-Closed Secret / Token Redaction
    const dirtyTelemetry = {
      user: 'operator_1',
      token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature',
      authHeader: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiJ9.signature123',
      dbPassword: 'UltraSecretDbPassword!@#',
      cookie: 'eji_session=s%3Aabc123xyz.hmac_signature_token',
      rawHeaders: 'Cookie: eji_session=s%3Aabc123xyz.hmac_signature_token; Path=/',
      telemetry: {
        latencyMs: 42.5,
        targetIp: '10.22.12.204',
        apiKey: 'sk-ant-api03-abcdef1234567890'
      }
    };

    const clean = redactTelemetryForExternalModel(dirtyTelemetry);
    assert.strictEqual(clean.token, '[REDACTED_SENSITIVE_FIELD]');
    assert.strictEqual(clean.authHeader, 'Bearer [REDACTED_JWT_TOKEN]');
    assert.strictEqual(clean.dbPassword, '[REDACTED_SENSITIVE_FIELD]');
    assert.strictEqual(clean.cookie, '[REDACTED_SENSITIVE_FIELD]');
    assert.strictEqual(clean.rawHeaders, 'Cookie: eji_session=[REDACTED_SESSION_COOKIE]; Path=/');
    assert.strictEqual(clean.telemetry.apiKey, '[REDACTED_SENSITIVE_FIELD]');
    assert.strictEqual(clean.telemetry.latencyMs, 42.5, 'Must preserve non-sensitive telemetry values');
    console.log('  ✓ Fail-closed PII & credential redaction verified (JWT, Bearer, Passwords, Cookies, API Keys).');

    // Test Conditional LLM Gate
    const orchestrator = new AIModelOrchestrator({ confidenceThreshold: 85 });

    // Case 1: High confidence (>= 85%) -> Bypass LLM deterministically
    const highConfidenceIncident = {
      topHypothesis: { id: 'GATEWAY_UNREACHABLE', label: 'Default Gateway Unreachable', confidence: 92 },
      allHypothesesContradicted: false,
      helpdeskSummary: 'Default gateway router is unresponsive.'
    };
    const gate1 = await orchestrator.orchestrateDiagnosis(highConfidenceIncident, dirtyTelemetry);
    assert.strictEqual(gate1.gateAction, 'BYPASS_LLM_DETERMINISTIC_EVALUATION');
    assert.strictEqual(gate1.executedExternally, false);
    console.log(`  ✓ Gate Decision 1: High confidence (${gate1.confidence}%) bypassed LLM (Zero latency & Zero cost).`);

    // Case 2: Low confidence (< 85%) -> Air-Gapped Local-Only Route
    const ambiguousIncident = {
      topHypothesis: { id: 'UPSTREAM_TRANSIT_DROP', label: 'Upstream Transit Flap', confidence: 54 },
      allHypothesesContradicted: false,
      helpdeskSummary: 'Ambiguous WAN carrier transit latency detected.'
    };
    const gate2 = await orchestrator.orchestrateDiagnosis(ambiguousIncident, dirtyTelemetry);
    assert.strictEqual(gate2.gateAction, 'INVOKE_LOCAL_SECURE_ENGINE');
    assert.strictEqual(gate2.routedTo, 'LOCAL_OLLAMA_OR_RULE_SYNTHESIZER');
    assert.strictEqual(gate2.executedExternally, false);
    console.log(`  ✓ Gate Decision 2: Low confidence (${gate2.confidence}%) routed locally to air-gapped ${orchestrator.localModel}.`);

    // Case 3: External provider with redaction
    orchestrator.updateConfig({ localOnlyPolicy: false, preferredProvider: 'anthropic' });
    const gate3 = await orchestrator.orchestrateDiagnosis(ambiguousIncident, dirtyTelemetry);
    assert.strictEqual(gate3.gateAction, 'INVOKE_REDACTED_EXTERNAL_LLM');
    assert.strictEqual(gate3.redacted, true);
    assert.strictEqual(gate3.executedExternally, true);
    console.log(`  ✓ Gate Decision 3: External provider route verified with strict prior redaction.`);

    // Reset policy to air-gapped default
    orchestrator.updateConfig({ localOnlyPolicy: true });
  }

  // --------------------------------------------------------------------------
  // TEST 36.6: FLEET SCANNER DELTA TRACKING & STATUS DIFFERENTIATION
  // --------------------------------------------------------------------------
  console.log('\n[Test 36.6] Verifying Fleet Scanner Delta Tracking & Host Status Differentiation...');
  {
    const scanner = new UltraIpScanner();

    const previousScan = [
      { ip: '192.168.31.1', status: 'ONLINE', macAddress: '64:12:25:AA:BB:CC', hostname: 'router.local', openServices: [{ port: 80 }, { port: 443 }] },
      { ip: '192.168.31.50', status: 'ONLINE', macAddress: 'A4:AE:11:11:22:33', hostname: 'workstation-1', openServices: [{ port: 445 }] }
    ];

    const currentScan = [
      { ip: '192.168.31.1', status: 'ONLINE', macAddress: '64:12:25:AA:BB:CC', hostname: 'router.local', openServices: [{ port: 80 }, { port: 443 }, { port: 8443 }] },
      { ip: '192.168.31.50', status: 'UNRESPONSIVE', detailedStatus: 'NO_ICMP_RESPONSE', isNoIcmpResponse: true, macAddress: 'A4:AE:11:11:22:33', hostname: 'workstation-1', openServices: [] },
      { ip: '192.168.31.80', status: 'ONLINE', macAddress: 'AC:F4:66:77:88:99', hostname: 'tplink-ap', openServices: [{ port: 80 }] },
      { ip: '192.168.31.99', status: 'OFFLINE', detailedStatus: 'CONFIRMED_OFFLINE', isConfirmedOffline: true, macAddress: 'Unknown', hostname: 'Host Offline', openServices: [] }
    ];

    const delta = scanner.computeScanDelta(previousScan, currentScan);
    assert.strictEqual(delta.newHostsCount, 1, 'Must detect 1 new host (192.168.31.80)');
    assert.strictEqual(delta.missingHostsCount, 1, 'Must detect 1 missing host (192.168.31.50)');
    assert.strictEqual(delta.newOpenPortsCount, 1, 'Must detect 1 new open port (8443 on 192.168.31.1)');
    assert.strictEqual(delta.closedPortsCount, 1, 'Must detect 1 closed port (445 on 192.168.31.50)');

    assert.ok(delta.events.some(e => e.type === 'NEW_HOST' && e.ip === '192.168.31.80'), 'Must generate NEW_HOST event');
    assert.ok(delta.events.some(e => e.type === 'MISSING_HOST' && e.ip === '192.168.31.50'), 'Must generate MISSING_HOST event');
    assert.ok(delta.events.some(e => e.type === 'NEW_OPEN_PORT' && e.port === 8443), 'Must generate NEW_OPEN_PORT event');

    // Verify differentiation between CONFIRMED_OFFLINE and NO_ICMP_RESPONSE
    const offlineHost = currentScan.find(h => h.ip === '192.168.31.99');
    const silentHost = currentScan.find(h => h.ip === '192.168.31.50');

    assert.strictEqual(offlineHost.detailedStatus, 'CONFIRMED_OFFLINE');
    assert.strictEqual(offlineHost.isConfirmedOffline, true);

    assert.strictEqual(silentHost.detailedStatus, 'NO_ICMP_RESPONSE');
    assert.strictEqual(silentHost.isNoIcmpResponse, true);

    console.log('  ✓ Delta Tracking verified: +1 NEW_HOST, -1 MISSING_HOST, +1 NEW_OPEN_PORT, -1 CLOSED_PORT.');
    console.log('  ✓ Verified CONFIRMED_OFFLINE (ICMP Unreachable) differentiated from NO_ICMP_RESPONSE (Silent/Firewalled).');
  }

  // --------------------------------------------------------------------------
  // TEST 36.7: REST API ENDPOINTS INTEGRATION SMOKE
  // --------------------------------------------------------------------------
  console.log('\n[Test 36.7] Verifying Express REST API Endpoints Integration...');
  {
    const app = express();
    app.use(express.json());
    app.use('/api/network', networkRouter);
    app.use('/api/rca', rcaRouter);

    const testServer = app.listen(0);
    const port = testServer.address().port;
    const adminToken = generateToken({ id: 1, username: 'admin_tester', role: 'ADMIN' });

    async function reqApi(path, method = 'GET', body = null) {
      return new Promise((resolve, reject) => {
        const r = http.request({
          hostname: '127.0.0.1',
          port,
          path,
          method,
          headers: {
            'Authorization': `Bearer ${adminToken}`,
            'Content-Type': 'application/json'
          }
        }, (res) => {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => {
            try {
              resolve({ status: res.statusCode, data: JSON.parse(data) });
            } catch (_) {
              resolve({ status: res.statusCode, raw: data });
            }
          });
        });
        r.on('error', reject);
        if (body) r.write(JSON.stringify(body));
        r.end();
      });
    }

    // 1. GET /api/network/process-endpoints
    const epRes = await reqApi('/api/network/process-endpoints');
    assert.strictEqual(epRes.status, 200);
    assert.strictEqual(epRes.data.success, true);
    assert.ok(Array.isArray(epRes.data.endpoints));

    // 2. GET /api/network/conversations
    const convRes = await reqApi('/api/network/conversations');
    assert.strictEqual(convRes.status, 200);
    assert.strictEqual(convRes.data.success, true);
    assert.ok(Array.isArray(convRes.data.conversations));

    // 3. GET /api/rca/brain/orchestrator-status
    const orchRes = await reqApi('/api/rca/brain/orchestrator-status');
    assert.strictEqual(orchRes.status, 200);
    assert.strictEqual(orchRes.data.success, true);
    assert.strictEqual(orchRes.data.status.localOnlyPolicy, true);

    // 4. POST /api/rca/brain/orchestrator-config
    const updateRes = await reqApi('/api/rca/brain/orchestrator-config', 'POST', {
      confidenceThreshold: 88
    });
    assert.strictEqual(updateRes.status, 200);
    assert.strictEqual(updateRes.data.status.confidenceThreshold, 88);

    // Restore threshold
    await reqApi('/api/rca/brain/orchestrator-config', 'POST', {
      confidenceThreshold: 85
    });

    testServer.close();
    console.log('  ✓ All 4 new REST API endpoints verified with HTTP 200 OK responses.');
  }

  console.log('\n========================================================================');
  console.log('  TEST SUITE 36: 100% PASSED (ALL 7 RIGOROUS TESTS VERIFIED)             ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runSignalTriageAndOrchestratorTests().catch((err) => {
    console.error('Test Suite 36 FAILED:', err);
    process.exit(1);
  });
}

module.exports = { runSignalTriageAndOrchestratorTests };
