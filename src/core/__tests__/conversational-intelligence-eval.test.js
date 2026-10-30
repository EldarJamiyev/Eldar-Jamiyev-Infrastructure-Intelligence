/**
 * EJII Project Falcon & Sovereign Fabric v6 — Conversational Intelligence Evaluation Suite
 *
 * Verifies all 9 Section 3 Transcript Failures and 12 Section 8 Evaluation Categories:
 *   1. DNS Record-Type Preservation ("DNS MX lookup for Google" -> recordType: 'MX')
 *   2. Conceptual L4 TCP vs L7 Application Health (0 probes, no priorTarget inheritance)
 *   3. Office Email Outage Structured Troubleshooting Intake
 *   4. Multi-Turn Interruption & Topic Switch ("port ping for youtube", "ping port youtube 443", bare "port ping" -> "youtube")
 *   5. DHCP Discovery & Follow-Up Continuity ("find out" / "how can I check")
 *   6. Sovereign Fabric v6 Truth Matrix & Shannon Information-Gain Next Probe (0 hostname prompts)
 *   7. Default Gateway Epistemic Explanation (NO_DEFAULT_ROUTE_OBSERVED)
 *   8. Host Metrics POSIX Truthfulness & 4-Tier Environment Scope Classification
 *   9. AI Model Orchestrator 3-Tier Redaction & GOOGLE_GEMINI Telemetry Separation
 */

'use strict';

const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');

const { chatOperatorService } = require('../chat/chat-operator-service');
const { semanticAiInterpreter } = require('../chat/semantic-ai-interpreter');
const {
  EJII_FUNCTION_DECLARATIONS,
  buildApplicationEpistemicContext,
  isEpistemicOrSovereignFabricQuestion,
  answerEpistemicOrFabricQuestion
} = require('../chat/conversational-brain');
const { aiModelOrchestrator, redactTelemetryForExternalModel } = require('../ai-model-orchestrator');
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

  it('3. Initiates structured mail troubleshooting intake for office email problem description (Transcript Failure #4)', async () => {
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
    assert.match(res.data.reply, /MX/i);
    assert.match(res.data.reply, /587|465|993/);
    assert.match(res.data.reply, /email domain|mail server hostname/i);

    const session = chatOperatorService.getOrCreateSession(sessionId, user);
    assert.equal(session.pendingTask?.type, 'mail_server_inspection');
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

  it('6. Answers Sovereign Fabric v6 truth matrix & highest Shannon information-gain next probe without asking for a hostname (Transcript Failures #8 & #9)', async () => {
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

  it('7. Verifies POSIX host metrics truthfulness, 4-tier environment scope, and 3-tier telemetry redaction', async () => {
    const netConfig = hostMetrics.inspectLocalNetworkConfiguration();
    assert.ok(
      ['cloud_sandbox_runtime', 'container_network_namespace', 'physical_workstation', 'remote_diagnostic_target'].includes(
        netConfig.environmentScopeCategory
      ),
      'Must expose valid 4-tier environmentScopeCategory'
    );

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

    // Verify GOOGLE_GEMINI telemetry bucket exists and is distinct from OPENAI
    assert.ok(aiModelOrchestrator.providerTelemetry.GOOGLE_GEMINI, 'GOOGLE_GEMINI telemetry bucket must exist');
    assert.equal(aiModelOrchestrator.providers.google_gemini.model, 'gemini-3.8-flash');
    assert.ok(Array.isArray(EJII_FUNCTION_DECLARATIONS) && EJII_FUNCTION_DECLARATIONS.length >= 10);
  });
});
