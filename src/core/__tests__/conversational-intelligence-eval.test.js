/**
 * EJII Project Falcon & Sovereign Fabric v6 — Conversational Intelligence Evaluation Suite
 *
 * Verifies all 9 Section 3 Transcript Failures, all 12 Section 8 Evaluation Categories,
 * and all P0/P1 Assessment & Executive Engineering Mandate requirements:
 *   1. DNS Record-Type Preservation ("DNS MX lookup for Google" -> recordType: 'MX')
 *   2. Conceptual L4 TCP vs L7 Application Health (0 probes, no priorTarget inheritance)
 *   3. Office Email Outage Structured Troubleshooting Intake + Multi-Word Client Follow-Up ("Outlook desktop" never becomes outlook.desktop)
 *   4. Multi-Turn Interruption & Topic Switch ("port ping for youtube", "ping port youtube 443", bare "port ping" -> "youtube")
 *   5. DHCP Discovery & Follow-Up Continuity ("find out" / "how can I check")
 *   6. Sovereign Fabric v6 Truth Matrix, EvidenceFabric DAG Lineage & Exact Mathematical Shannon Information-Gain
 *   7. Default Gateway Epistemic Explanation (NO_DEFAULT_ROUTE_OBSERVED)
 *   8. Host Metrics POSIX CPU Tick Delta vs Load Average Separation, Zero Fabricated Disks & 4-Tier Environment Scope
 *   9. Native Gemini Function Declarations Delivery, All 12 Function-to-Intent Mappings & Iterative Plan->Execute->Observe->Reflect Loop
 *  10. Real-Time SSE Progress Callback Emission & Provider Health Matrix GOOGLE_GEMINI Telemetry Isolation
 */

'use strict';

const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');

const { chatOperatorService } = require('../chat/chat-operator-service');
const { semanticAiInterpreter } = require('../chat/semantic-ai-interpreter');
const {
  EJII_FUNCTION_DECLARATIONS,
  computeShannonEntropyFromDistribution,
  computeExpectedProbeInformationGain,
  computeLiveInformationGainAnalysis,
  buildApplicationEpistemicContext,
  isEpistemicOrSovereignFabricQuestion,
  mapFunctionCallToExecutionPlan,
  runAgenticToolLoop
} = require('../chat/conversational-brain');
const { aiModelOrchestrator, redactTelemetryForExternalModel } = require('../ai-model-orchestrator');
const { evidenceFabric } = require('../evidence/evidence-fabric');
const hostMetrics = require('../../protocols/host-metrics');

describe('EJII Conversational Intelligence & Technical Quality Evaluation Suite', () => {
  before(() => {
    chatOperatorService.setLlmInterpreter(semanticAiInterpreter);
  });

  it('1. Preserves MX recordType for "DNS MX lookup for Google" (Transcript Failure #1)', async () => {
    const sessionId = 'EVAL-MX-' + Date.now();
    const user = { id: 'u-eval-1', username: 'admin', role: 'ADMIN' };

    const plan = await semanticAiInterpreter('DNS MX lookup for Google', {
      defaultPlan: chatOperatorService.parseIntentAndEntities('DNS MX lookup for Google', {})
    });
    assert.ok(plan, 'Semantic interpreter should return a plan for DNS MX lookup for Google');
    assert.equal(plan.intent, 'dns');
    assert.equal(plan.target, 'google.com');
    assert.equal(plan.recordType, 'MX', 'Must preserve MX recordType instead of overwriting with A');

    const res = await chatOperatorService.processMessage({
      sessionId,
      message: 'DNS MX lookup for Google',
      user
    });
    assert.equal(res.success, true);
    assert.equal(res.data.intent, 'dns');
    assert.equal(res.data.target, 'google.com');
    assert.equal(res.data.technicalEvidence.recordType, 'MX');
  });

  it('2. Answers conceptual L4 TCP socket vs L7 Application health question with 0 probes and without inheriting google.com (Transcript Failure #3)', async () => {
    const sessionId = 'EVAL-L4L7-' + Date.now();
    const user = { id: 'u-eval-2', username: 'admin', role: 'ADMIN' };

    // Turn 1: Establish google.com in session context
    await chatOperatorService.processMessage({
      sessionId,
      message: 'Resolve google.com',
      user
    });

    // Turn 2: Ask conceptual question mentioning port 3000 and local development server
    const conceptualPrompt =
      'Since our local development server has a completely open and responsive TCP socket on port 3000, can we definitively declare that the application layer is healthy?';
    const res = await chatOperatorService.processMessage({
      sessionId,
      message: conceptualPrompt,
      user
    });

    assert.equal(res.success, true);
    assert.equal(res.data.intent, 'informational_question');
    assert.equal(res.data.steps.length, 0, 'Conceptual question must execute 0 live network probes');
    assert.equal(res.data.technicalEvidence.liveProbesExecuted, 0);
    assert.match(res.data.reply, /No — an open and responsive TCP socket/i);
    assert.match(res.data.reply, /Layer 4|3-way handshake|Layer 7/i);
    assert.doesNotMatch(res.data.reply, /google\.com.*3000/i, 'Must never inherit google.com onto port 3000');
  });

  it('3. Initiates structured mail troubleshooting intake and handles multi-word client follow-up ("Outlook desktop") without inventing outlook.desktop (Transcript Failure #4 & P1 Assessment)', async () => {
    const sessionId = 'EVAL-MAIL-' + Date.now();
    const user = { id: 'u-eval-3', username: 'admin', role: 'ADMIN' };

    const res = await chatOperatorService.processMessage({
      sessionId,
      message: 'Users in our office cannot send or receive emails',
      user
    });

    assert.equal(res.success, true);
    assert.equal(res.data.intent, 'mail_troubleshooting_intake');
    assert.equal(res.data.steps.length, 0);
    assert.match(res.data.reply, /can neither send nor receive email/i, 'Must not contain "canneither" typo');
    assert.match(res.data.reply, /MX/i);
    assert.match(res.data.reply, /587|465|993/);
    assert.match(res.data.reply, /email domain|mail server hostname/i);

    const session = chatOperatorService.getOrCreateSession(sessionId, user);
    assert.equal(session.pendingTask?.type, 'mail_server_inspection');

    // Follow-up Turn 2: User supplies client context "Outlook desktop" without domain
    const clientFollowUp = await chatOperatorService.processMessage({
      sessionId,
      message: 'Outlook desktop',
      user
    });
    assert.equal(clientFollowUp.success, true);
    assert.equal(clientFollowUp.data.intent, 'clarification_needed');
    assert.equal(clientFollowUp.data.steps.length, 0, 'Must not probe fake domain outlook.desktop');
    assert.doesNotMatch(clientFollowUp.data.reply, /outlook\.desktop/i, 'Must never join "Outlook desktop" into outlook.desktop');
    assert.match(clientFollowUp.data.reply, /Outlook desktop/i);
    assert.match(clientFollowUp.data.reply, /email domain|mail server hostname/i);
    assert.equal(session.pendingTask?.type, 'mail_server_inspection', 'Pending mail task must remain active awaiting domain');
    assert.equal(session.pendingTask?.clientContext, 'Outlook desktop');

    // Follow-up Turn 3: User supplies domain "example.com" -> triggers mail ports + MX plan
    const domainPlan = chatOperatorService.parseIntentAndEntities('example.com', session);
    assert.equal(domainPlan.intent, 'port_check');
    assert.equal(domainPlan.recordType, 'MX');
    assert.equal(domainPlan.target, 'example.com');
    assert.ok(domainPlan.ports.includes(587));
    assert.ok(Array.isArray(domainPlan.secondaryToolPlans) && domainPlan.secondaryToolPlans.length === 1);
    assert.equal(domainPlan.secondaryToolPlans[0].intent, 'dns');
    assert.equal(domainPlan.secondaryToolPlans[0].recordType, 'MX');
  });

  it('4. Cancels stale mail pendingTask on topic switch to YouTube port ping and never fabricates port.ping.for.youtube (Transcript Failure #5)', async () => {
    const sessionId = 'EVAL-YT-' + Date.now();
    const user = { id: 'u-eval-4', username: 'admin', role: 'ADMIN' };

    // Turn 1: Trigger mail pendingTask
    await chatOperatorService.processMessage({
      sessionId,
      message: 'Check mail server',
      user
    });
    const session = chatOperatorService.getOrCreateSession(sessionId, user);
    assert.equal(session.pendingTask?.type, 'mail_server_inspection');

    // Turn 2: Switch topic with "port ping for youtube"
    const plan1 = chatOperatorService.parseIntentAndEntities('port ping for youtube', session);
    assert.equal(plan1.intent, 'port_check');
    assert.equal(plan1.target, 'youtube.com', 'Must resolve youtube brand shorthand to youtube.com, never port.ping.for.youtube');
    assert.ok(!plan1.ports.includes(25), 'Must not pollute youtube port check with mail port 25');
    assert.deepEqual(plan1.ports, [80, 443]);

    // Turn 3: Bare "port ping" followed by "youtube"
    session.lastTarget = null;
    session.lastValidTarget = null;
    const barePlan = chatOperatorService.parseIntentAndEntities('port ping', session);
    assert.equal(barePlan.intent, 'clarification_needed');
    assert.doesNotMatch(barePlan.clarificationPrompt, /mail server/i, 'Generic port ping must not ask for a mail server');
    assert.equal(session.pendingTask?.type, 'port_ping_target');

    const followUpPlan = chatOperatorService.parseIntentAndEntities('youtube', session);
    assert.equal(followUpPlan.intent, 'port_check');
    assert.equal(followUpPlan.target, 'youtube.com');
    assert.deepEqual(followUpPlan.ports, [80, 443]);

    // Turn 4: "ping port youtube 443"
    const plan443 = chatOperatorService.parseIntentAndEntities('ping port youtube 443', session);
    assert.equal(plan443.intent, 'port_check');
    assert.equal(plan443.target, 'youtube.com');
    assert.deepEqual(plan443.ports, [443]);
  });

  it('5. Maintains DHCP conversational continuity on "find out" follow-up (Transcript Failure #6)', async () => {
    const sessionId = 'EVAL-DHCP-' + Date.now();
    const user = { id: 'u-eval-5', username: 'admin', role: 'ADMIN' };

    const turn1 = await chatOperatorService.processMessage({
      sessionId,
      message: 'What is my DHCP server IP?',
      user
    });
    assert.equal(turn1.success, true);
    assert.equal(turn1.data.intent, 'dhcp_check');

    const turn2 = await chatOperatorService.processMessage({
      sessionId,
      message: 'find out',
      user
    });
    assert.equal(turn2.success, true);
    assert.equal(turn2.data.intent, 'dhcp_check');
    assert.match(turn2.data.reply, /Addressing Mode Verification|ipconfig \/all|nmcli/i);
  });

  it('6. Computes exact mathematical Shannon Information Gain IG(X;Y) = H(X) - sum P(y)H(X|Y=y) and connects to EvidenceFabric DAG (Transcript Failures #8 & #9 & P0 Assessment)', async () => {
    // 6a. Verify exact mathematical Shannon IG formula on a known 2-hypothesis uniform prior (H(X) = 1.0 bit)
    const uniformPrior = [
      { id: 'HYP_A', probability: 0.5 },
      { id: 'HYP_B', probability: 0.5 }
    ];
    // Deterministic discriminating probe: P(pass | HYP_A) = 0.999, P(pass | HYP_B) = 0.001
    const nearPerfectProbe = computeExpectedProbeInformationGain(uniformPrior, {
      HYP_A: 0.999,
      HYP_B: 0.001
    });
    assert.ok(nearPerfectProbe, 'Must return mathematical IG result');
    assert.equal(nearPerfectProbe.priorEntropyBits, 1.0);
    assert.equal(nearPerfectProbe.pPass, 0.5);
    assert.equal(nearPerfectProbe.pFail, 0.5);
    assert.ok(nearPerfectProbe.expectedInformationGainBits > 0.95, 'Near-perfect discriminator on 1-bit prior must yield ~0.99 bits IG (not a fixed 1.42 floor)');

    // Uninformative probe: P(pass | HYP_A) = 0.5, P(pass | HYP_B) = 0.5 -> IG must be strictly 0 bits!
    const zeroInfoProbe = computeExpectedProbeInformationGain(uniformPrior, {
      HYP_A: 0.5,
      HYP_B: 0.5
    });
    assert.equal(zeroInfoProbe.expectedInformationGainBits, 0, 'Uninformative probe must yield 0.00 bits IG (proving no hardcoded floor exists)');

    // Empty prior distribution must return null (not fabricated 3.17)
    assert.equal(computeExpectedProbeInformationGain([], {}), null);

    // 6b. Record a live evidence record in EvidenceFabric and verify buildApplicationEpistemicContext links to it
    const recordedEv = evidenceFabric.recordEvidence({
      type: 'observation',
      subject: 'tcp:127.0.0.1:3000',
      claim: 'Unit test verification of EvidenceFabric lineage connection',
      rawValue: { status: 'OPEN' },
      normalizedValue: 'TCP_OPEN',
      sourceCapabilityId: 'ejii.test.eval',
      collectionMethod: 'tcp_connect'
    });
    const epistemicCtx = buildApplicationEpistemicContext({});
    assert.ok(epistemicCtx.sovereignFabricV6TruthMatrix.evidenceFabricLineage.totalRecordsCount >= 1);
    assert.equal(
      epistemicCtx.sovereignFabricV6TruthMatrix.evidenceFabricLineage.latestChainHash,
      recordedEv.integrityHash
    );
    assert.ok(
      epistemicCtx.sovereignFabricV6TruthMatrix.topHypotheses.every((h) => h.status !== 'OBSERVED_CONCLUSIVE'),
      'Unobserved Bayesian posteriors must never be labeled OBSERVED_CONCLUSIVE'
    );

    // 6c. End-to-end conversational query for Sovereign Fabric v6 Truth Matrix & Gateway Epistemics
    const sessionId = 'EVAL-FABRIC-' + Date.now();
    const user = { id: 'u-eval-6', username: 'admin', role: 'ADMIN' };
    const igPrompt =
      'Based on the unresolved states inside the Sovereign Fabric v6 truth matrix, what is the highest information-gain next probe to run right now?';
    assert.equal(isEpistemicOrSovereignFabricQuestion(igPrompt), true);

    const res = await chatOperatorService.processMessage({
      sessionId,
      message: igPrompt,
      user
    });

    assert.equal(res.success, true);
    assert.equal(res.data.intent, 'epistemic_fabric_query');
    assert.equal(res.data.steps.length, 0);
    assert.match(res.data.reply, /Sovereign Fabric v6/i);
    assert.match(res.data.reply, /Shannon entropy|bits/i);
    assert.doesNotMatch(res.data.reply, /Which hostname, IP address, or URL would you like me to check/i);

    const gwPrompt = 'Why is the default gateway unverified in this environment and what does NO_DEFAULT_ROUTE_OBSERVED mean?';
    const gwRes = await chatOperatorService.processMessage({
      sessionId,
      message: gwPrompt,
      user
    });
    assert.equal(gwRes.success, true);
    assert.equal(gwRes.data.intent, 'epistemic_fabric_query');
    assert.match(gwRes.data.reply, /NO_DEFAULT_ROUTE_OBSERVED|UNVERIFIED/i);
  });

  it('7. Verifies POSIX CPU tick delta separation from loadavg, zero fabricated disk metrics, 4-tier environment scope, and 3-tier redaction', async () => {
    const netConfig = hostMetrics.inspectLocalNetworkConfiguration();
    assert.ok(
      ['cloud_sandbox_runtime', 'container_network_namespace', 'physical_workstation', 'remote_diagnostic_target'].includes(
        netConfig.environmentScopeCategory
      ),
      'Must expose valid 4-tier environmentScopeCategory'
    );

    const metrics = await hostMetrics.getHostMetrics(true);
    assert.equal(metrics.cpu.measurementMethod, 'posix_cpu_tick_delta', 'POSIX CPU usage must use tick delta measurement, not loadavg');
    assert.equal(typeof metrics.cpu.usagePercentage, 'number');
    assert.equal(typeof metrics.cpu.loadAverage1m, 'number', '1m load average must be exposed separately from CPU tick usage');
    assert.ok(metrics.diskCollectionStatus, 'Must include explicit diskCollectionStatus object');
    for (const d of metrics.disks) {
      assert.notEqual(d.volumeName, 'System Primary', 'Must never contain fabricated 512GB Windows fallback disk');
    }

    const services = await hostMetrics.getServices();
    assert.ok(Array.isArray(services) && services.length > 0);
    assert.ok(
      services.every((s) => s.entityType === 'SYSTEM_SERVICE' || s.entityType === 'RUNNING_PROCESS'),
      'Every POSIX service entry must distinguish SYSTEM_SERVICE vs RUNNING_PROCESS'
    );

    // Verify 3-tier redaction
    const sample = {
      authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.sig',
      contact: 'Reach admin@corp.example.com or (415) 555-2671 on internal node 10.24.1.99 (aa:bb:cc:dd:ee:ff)'
    };
    const tier2Scrubbed = redactTelemetryForExternalModel(sample);
    assert.equal(tier2Scrubbed.authorization, '[REDACTED_SENSITIVE_FIELD]');
    assert.match(tier2Scrubbed.contact, /\[REDACTED_EMAIL\]/);
    assert.match(tier2Scrubbed.contact, /\[REDACTED_PHONE\]/);
    assert.match(tier2Scrubbed.contact, /10\.24\.1\.99/, 'Tier 2 keeps IP addresses intact for diagnostic reasoning unless Tier 3 is enabled');

    const tier3Scrubbed = redactTelemetryForExternalModel(sample, { anonymizeInfrastructure: true });
    assert.match(tier3Scrubbed.contact, /\[REDACTED_PRIVATE_IP\]/);
    assert.match(tier3Scrubbed.contact, /\[REDACTED_MAC\]/);
  });

  it('8. Verifies all 12 mapFunctionCallToExecutionPlan mappings and native Gemini tool declaration delivery in semanticAiInterpreter (P0 Assessment)', async () => {
    const expectedMappings = [
      { call: { name: 'dns_lookup', args: { domain: 'example.com', recordType: 'MX' } }, expectedIntent: 'dns', expectedTarget: 'example.com' },
      { call: { name: 'tcp_port_probe', args: { target: 'example.com', ports: [443, 8443] } }, expectedIntent: 'port_check', expectedTarget: 'example.com' },
      { call: { name: 'icmp_ping', args: { target: '1.1.1.1' } }, expectedIntent: 'ping', expectedTarget: '1.1.1.1' },
      { call: { name: 'http_tls_inspect', args: { target: 'https://example.com', port: 443 } }, expectedIntent: 'website_check', expectedTarget: 'https://example.com' },
      { call: { name: 'inspect_local_network', args: {} }, expectedIntent: 'local_ip_config', expectedTarget: 'local_host_interfaces' },
      { call: { name: 'inspect_default_gateway', args: {} }, expectedIntent: 'gateway_check', expectedTarget: 'default_gateway' },
      { call: { name: 'inspect_dhcp_status', args: {} }, expectedIntent: 'dhcp_check', expectedTarget: 'local_dhcp_service' },
      { call: { name: 'run_5_layer_path_diagnostic', args: {} }, expectedIntent: 'local_path_diagnostic', expectedTarget: 'local_path_gateway_isp' },
      { call: { name: 'query_sovereign_fabric_v6', args: { questionFocus: 'information_gain_next_probe' } }, expectedIntent: 'epistemic_fabric_query', expectedTarget: null },
      { call: { name: 'inspect_host_health', args: {} }, expectedIntent: 'host_health', expectedTarget: 'local_host_health' },
      { call: { name: 'inspect_active_sockets', args: { portFilter: 3000 } }, expectedIntent: 'active_connections', expectedTarget: 'local_socket_table' },
      { call: { name: 'run_traceroute', args: { target: '1.1.1.1' } }, expectedIntent: 'traceroute', expectedTarget: '1.1.1.1' }
    ];

    for (const item of expectedMappings) {
      const mapped = mapFunctionCallToExecutionPlan(item.call, {});
      assert.ok(mapped, `Mapping must succeed for ${item.call.name}`);
      assert.equal(mapped.intent, item.expectedIntent, `Tool ${item.call.name} must map to intent '${item.expectedIntent}'`);
      assert.equal(mapped.target, item.expectedTarget);
    }

    // Verify semanticAiInterpreter passes EJII_FUNCTION_DECLARATIONS to invokeWithBoundedRetry when invoking the model
    let capturedOptions = null;
    const origInvoke = aiModelOrchestrator.invokeWithBoundedRetry.bind(aiModelOrchestrator);
    aiModelOrchestrator.invokeWithBoundedRetry = async (prov, prompt, opts) => {
      capturedOptions = opts;
      return {
        liveResponse: true,
        isMock: true,
        provider: 'GOOGLE_GEMINI',
        model: 'gemini-3.8-flash',
        executedModel: 'gemini-3.8-flash',
        functionCalls: [
          { name: 'dns_lookup', args: { domain: 'cloudflare.com', recordType: 'AAAA' } },
          { name: 'tcp_port_probe', args: { target: 'cloudflare.com', ports: [443] } }
        ],
        text: ''
      };
    };

    try {
      const interpreted = await semanticAiInterpreter(
        'Please perform an unconventional custom audit of cloudflare ipv6 records and then test its TLS port',
        { provider: 'CUSTOM_TEST_HOOK', defaultPlan: null, forceModelInterpretation: true }
      );
      assert.ok(capturedOptions, 'aiModelOrchestrator.invokeWithBoundedRetry must be called');
      assert.ok(Array.isArray(capturedOptions.tools), 'tools array must be passed to invokeWithBoundedRetry');
      assert.equal(
        capturedOptions.tools[0].functionDeclarations.length,
        EJII_FUNCTION_DECLARATIONS.length,
        'All EJII_FUNCTION_DECLARATIONS must be passed to the model'
      );
      assert.equal(interpreted.intent, 'dns');
      assert.equal(interpreted.target, 'cloudflare.com');
      assert.equal(interpreted.recordType, 'AAAA');
      assert.equal(interpreted.secondaryToolPlans.length, 1);
      assert.equal(interpreted.secondaryToolPlans[0].intent, 'port_check');
    } finally {
      aiModelOrchestrator.invokeWithBoundedRetry = origInvoke;
    }
  });

  it('9. Executes iterative Plan -> Execute -> Observe -> Reflect multi-step tool loop and streams live progress stages (P0 & P1 Assessment)', async () => {
    const sessionId = 'EVAL-LOOP-' + Date.now();
    const user = { id: 'u-eval-9', username: 'admin', role: 'ADMIN' };
    const progressEvents = [];
    const reflectionObservations = [];

    // Use modelReflectionFn to verify that step 1's actual tool output is fed back into reflection to trigger step 2
    const outcome = await chatOperatorService.processMessage({
      sessionId,
      message: 'Check whether port 3000 is open on localhost',
      user,
      onProgress: (evt) => progressEvents.push(evt),
      modelReflectionFn: async ({ observationSummary, stepIndex }) => {
        reflectionObservations.push({ stepIndex, observationSummary });
        if (stepIndex === 1) {
          return {
            functionCall: {
              name: 'inspect_active_sockets',
              args: { portFilter: 3000 }
            }
          };
        }
        return {
          complete: true,
          synthesis: 'Verified both TCP port 3000 handshake and local kernel socket table listener.'
        };
      }
    });

    assert.equal(outcome.success, true);
    assert.equal(reflectionObservations.length, 2, 'Reflection callback must be invoked after each executed tool step');
    assert.equal(reflectionObservations[0].observationSummary.executedIntent, 'port_check');
    assert.equal(reflectionObservations[1].observationSummary.executedIntent, 'active_connections');
    assert.equal(outcome.data.technicalEvidence.mode, 'agentic_multi_step_loop');
    assert.equal(outcome.data.technicalEvidence.iterationsExecuted, 2);
    assert.match(outcome.data.reply, /Verified both TCP port 3000 handshake and local kernel socket table listener/i);

    // Verify real-time progress stages were emitted in order during execution
    const stages = progressEvents.map((e) => e.stage);
    assert.ok(stages.includes('INTERPRETING_INTENT'));
    assert.ok(stages.includes('TOOL_SELECTED'));
    assert.ok(stages.includes('PROBE_EXECUTING'));
    assert.ok(stages.includes('PROBE_COMPLETED'));
    assert.ok(stages.includes('REFLECTING_ON_EVIDENCE'));
    assert.ok(stages.includes('SYNTHESIZING_RESPONSE'));

    // Verify Provider Health Matrix GOOGLE_GEMINI telemetry bucket isolation
    const matrix = aiModelOrchestrator.getProviderHealthMatrix();
    const geminiEntry = matrix.providers.find((p) => p.id === 'gemini_cloud');
    assert.ok(geminiEntry, 'gemini_cloud provider entry must exist in health matrix');
    assert.equal(geminiEntry.providerId, 'GOOGLE_GEMINI');
    assert.equal(geminiEntry.callsCount, aiModelOrchestrator.providerTelemetry.GOOGLE_GEMINI.callsCount);
  });

  it('10. Verifies AIModelOrchestrator getProviderHealthMatrix GOOGLE_GEMINI vs OPENAI telemetry isolation and requestedModel/executedModel consistency (P1 Assessment)', () => {
    const prevGeminiCalls = aiModelOrchestrator.providerTelemetry.GOOGLE_GEMINI.callsCount;
    const prevOpenAiCalls = aiModelOrchestrator.providerTelemetry.OPENAI.callsCount;
    try {
      aiModelOrchestrator.providerTelemetry.GOOGLE_GEMINI.callsCount = 77;
      aiModelOrchestrator.providerTelemetry.OPENAI.callsCount = 3;
      const matrix = aiModelOrchestrator.getProviderHealthMatrix();
      const geminiProvider = matrix.providers.find((p) => p.id === 'gemini_cloud');
      assert.ok(geminiProvider);
      assert.equal(
        geminiProvider.callsCount,
        77,
        'gemini_cloud must read GOOGLE_GEMINI.callsCount (77), never OPENAI.callsCount (3)'
      );
    } finally {
      aiModelOrchestrator.providerTelemetry.GOOGLE_GEMINI.callsCount = prevGeminiCalls;
      aiModelOrchestrator.providerTelemetry.OPENAI.callsCount = prevOpenAiCalls;
    }
  });

  it('11. Persists lastProbeResult and probeHistory on session state for follow-up reasoning and Bayesian likelihood conditioning (P1 Assessment)', async () => {
    const sessionId = 'EVAL-PROBE-HIST-' + Date.now();
    const user = { id: 'u-eval-11', username: 'admin', role: 'ADMIN' };

    const turn = await chatOperatorService.processMessage({
      sessionId,
      message: 'Check whether port 3000 is open on localhost',
      user
    });
    assert.equal(turn.success, true);

    const session = chatOperatorService.getOrCreateSession(sessionId, user);
    assert.ok(session.lastProbeResult, 'session.lastProbeResult must be populated after operational probe');
    assert.equal(session.lastProbeResult.intent, 'port_check');
    assert.equal(session.lastProbeResult.status, 'PASS');
    assert.ok(Array.isArray(session.probeHistory) && session.probeHistory.length >= 1, 'session.probeHistory must retain executed probe history');

    // Verify Bayesian information-gain analysis conditions on session.lastProbeResult
    const igWithSession = buildApplicationEpistemicContext(session);
    assert.equal(igWithSession.sessionState.lastProbeSummary, session.lastProbeResult.summary);
  });

  it('12. Executes live Gemini API native function calling with EJII_FUNCTION_DECLARATIONS when GEMINI_API_KEY is present (P0 Live Verification)', async () => {
    if (!process.env.GEMINI_API_KEY || !process.env.GEMINI_API_KEY.trim()) {
      return;
    }
    const prevPolicy = aiModelOrchestrator.localOnlyPolicy;
    aiModelOrchestrator.localOnlyPolicy = false;
    try {
      const liveToolPlan = await semanticAiInterpreter(
        'Use your diagnostic tools to look up MX records for cloudflare.com.',
        {
          forceModelInterpretation: true,
          allowCloudFallback: true
        }
      );
      assert.ok(liveToolPlan, 'Live Gemini invocation with EJII_FUNCTION_DECLARATIONS must return a plan');
      assert.equal(liveToolPlan.modelInterpreted, true);
      assert.equal(liveToolPlan.isMockModel, false);
      assert.equal(liveToolPlan.intent, 'dns');
      assert.equal(liveToolPlan.target, 'cloudflare.com');
      assert.equal(liveToolPlan.recordType, 'MX');
    } finally {
      aiModelOrchestrator.localOnlyPolicy = prevPolicy;
    }
  });

  it('13. Verifies Unified Capability Registry provides all 12 Gemini tool schemas and maps tool plans with zero drift', () => {
    const { capabilityRegistry, EJII_FUNCTION_DECLARATIONS } = require('../capability-registry');
    const decls = capabilityRegistry.getFunctionDeclarations();
    assert.equal(decls.length, 12, 'Must export exactly 12 Gemini function declarations');
    assert.equal(EJII_FUNCTION_DECLARATIONS.length, 12);

    const toolNames = decls.map((d) => d.name);
    const expected = [
      'dns_lookup',
      'tcp_port_probe',
      'icmp_ping',
      'http_tls_inspect',
      'inspect_local_network',
      'inspect_default_gateway',
      'inspect_dhcp_status',
      'run_5_layer_path_diagnostic',
      'query_sovereign_fabric_v6',
      'inspect_host_health',
      'inspect_active_sockets',
      'run_traceroute'
    ];
    for (const name of expected) {
      assert.ok(toolNames.includes(name), `Missing function declaration: ${name}`);
      const single = capabilityRegistry.getFunctionDeclaration(name);
      assert.ok(single && single.name === name);
    }

    const plan = capabilityRegistry.mapFunctionCallToPlan('tcp_port_probe', { target: '1.1.1.1', ports: [443, 80] });
    assert.equal(plan.intent, 'port_check');
    assert.equal(plan.target, '1.1.1.1');
    assert.deepEqual(plan.ports, [443, 80]);
  });
});


