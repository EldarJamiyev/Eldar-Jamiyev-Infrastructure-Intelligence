/**
 * EJII Project Falcon Conversational Intelligence, Contextual UX & Production Excellence Tests
 *
 * Verifies:
 * 1. "is muhammed oglan?" and third-party ambiguous entity disambiguation (0 live probes, 0 follow-up chips).
 * 2. Multilingual capabilities across English, Azerbaijani, Turkish, and Russian.
 * 3. Topic switching cleanly clears plan.target to null (contextPivotDetected: true) while safely preserving session.lastValidTarget.
 * 4. Structured semanticDiagnostics observability (provider, model, parsingOutcome, latency, selectedIntent).
 * 5. operationalMemoryEngine follow-up recommendations return [] for conversational/factual queries and empty collections never render empty callouts.
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { chatOperatorService } = require('../src/core/chat/chat-operator-service');
const { operationalMemoryEngine } = require('../src/core/memory/operational-memory-engine');
const { detectLanguage, classifyConversationalTurn } = require('../src/core/chat/technical-knowledge-base');
const { semanticAiInterpreter, getSemanticInterpreterMetrics } = require('../src/core/chat/semantic-ai-interpreter');

test('Falcon Turn 1: "is muhammed oglan?" ambiguous person inquiry handling', async () => {
  const sessionId = `test-falcon-ambig-${Date.now()}`;
  const user = { id: 'admin-1', username: 'admin', role: 'ADMIN' };
  const session = chatOperatorService.getOrCreateSession(sessionId, user);

  // Intent parsing
  const plan = chatOperatorService.parseIntentAndEntities('is muhammed oglan?', session);
  assert.equal(plan.intent, 'clarification_needed');
  assert.equal(plan.mode, 'conversational');
  assert.equal(plan.clarificationReason, 'AMBIGUOUS_PERSON_REFERENCE');
  assert.equal(plan.target, null, 'plan.target must be null for person inquiries');
  assert.equal(plan.explicitTarget, null);

  // Full request execution
  const res = await chatOperatorService.processMessage({
    sessionId,
    message: 'is muhammed oglan?',
    user
  });

  assert.equal(res.success, true);
  assert.equal(res.intent, 'clarification_needed');
  assert.equal(res.mode, 'conversational');
  assert.equal(res.target, null);
  assert.equal(res.steps.length, 0, 'Must execute 0 live network probes');
  assert.equal(res.findings.length, 0, 'Must produce 0 network findings');
  assert.ok(res.reply.includes('Muhammed'), 'Reply should acknowledge the requested name');
  assert.ok(
    res.reply.includes('Hansı') || res.reply.includes('Which'),
    'Reply must ask which Muhammed is meant without fabricating assertions'
  );

  // Recommendations / Next steps must be strictly empty
  assert.equal(res.structuredAnswer?.nextStep, null, 'Must not force an operational nextStep');
  assert.deepEqual(res.data.suggestedFollowUps, [], 'Must return 0 follow-up diagnostic action chips');

  // semanticDiagnostics observability
  assert.ok(res.semanticDiagnostics, 'semanticDiagnostics must be exposed on response');
  assert.equal(typeof res.semanticDiagnostics.requestId, 'string');
  assert.equal(typeof res.semanticDiagnostics.durationMs, 'number');
  assert.equal(res.semanticDiagnostics.selectedIntent, 'clarification_needed');
  assert.equal(res.semanticDiagnostics.success, true);
});

test('Falcon Turn 2: Multilingual person inquiries across AZ, TR, RU, EN', () => {
  const azMatch = classifyConversationalTurn('məhəmməd oğlandır?');
  assert.ok(azMatch && azMatch.matched);
  assert.equal(azMatch.subtype, 'ambiguous_person_query');
  assert.ok(azMatch.reply.includes('Hansı'));

  const trMatch = classifyConversationalTurn('Ali erkek midir?');
  assert.ok(trMatch && trMatch.matched);
  assert.equal(trMatch.subtype, 'ambiguous_person_query');
  assert.ok(trMatch.reply.includes('Hangi'));

  const ruMatch = classifyConversationalTurn('кто такой Мухаммед?');
  assert.ok(ruMatch && ruMatch.matched);
  assert.equal(ruMatch.subtype, 'ambiguous_person_query');
  assert.ok(ruMatch.reply.includes('Какого именно'));

  const enMatch = classifyConversationalTurn('is John a boy?');
  assert.ok(enMatch && enMatch.matched);
  assert.equal(enMatch.subtype, 'ambiguous_person_query');
  assert.ok(enMatch.reply.includes('Which John'));
});

test('Falcon Turn 3: Multilingual Greetings (AZ, TR, RU, EN) execute 0 probes and yield 0 follow-ups', async () => {
  const sessionId = `test-falcon-greetings-${Date.now()}`;
  const user = { id: 'admin-1', username: 'admin', role: 'ADMIN' };

  const testCases = [
    { text: 'salam', langCheck: 'az', expectedWord: 'Salam' },
    { text: 'merhaba', langCheck: 'tr', expectedWord: 'Merhaba' },
    { text: 'здравствуйте', langCheck: 'ru', expectedWord: 'Здравствуйте' },
    { text: 'hello', langCheck: 'en', expectedWord: 'Hello' }
  ];

  for (const tc of testCases) {
    const res = await chatOperatorService.processMessage({
      sessionId,
      message: tc.text,
      user
    });
    assert.equal(res.success, true);
    assert.equal(res.intent, 'greeting');
    assert.equal(res.mode, 'conversational');
    assert.equal(res.target, null);
    assert.equal(res.steps.length, 0);
    assert.ok(res.reply.includes(tc.expectedWord));
    assert.deepEqual(res.data.suggestedFollowUps, []);
  }
});

test('Falcon Turn 4: Multilingual Casual Conversation & Weather Inquiries', async () => {
  const sessionId = `test-falcon-casual-${Date.now()}`;
  const user = { id: 'admin-1', username: 'admin', role: 'ADMIN' };

  // "how are you" in Azerbaijani
  const azRes = await chatOperatorService.processMessage({
    sessionId,
    message: 'necəsən?',
    user
  });
  assert.equal(azRes.success, true);
  assert.equal(azRes.intent, 'casual_conversation');
  assert.equal(azRes.target, null);
  assert.equal(azRes.steps.length, 0);
  assert.deepEqual(azRes.data.suggestedFollowUps, []);

  // Weather inquiry in English
  const weatherRes = await chatOperatorService.processMessage({
    sessionId,
    message: 'what is the weather today?',
    user
  });
  assert.equal(weatherRes.success, true);
  assert.equal(weatherRes.intent, 'casual_conversation');
  assert.ok(weatherRes.reply.includes('meteorological sensors'));
  assert.equal(weatherRes.steps.length, 0);
  assert.deepEqual(weatherRes.data.suggestedFollowUps, []);

  // Technical joke in English
  const jokeRes = await chatOperatorService.processMessage({
    sessionId,
    message: 'tell me a joke',
    user
  });
  assert.equal(jokeRes.success, true);
  assert.equal(jokeRes.intent, 'casual_conversation');
  assert.ok(jokeRes.reply.length > 10);
  assert.equal(jokeRes.steps.length, 0);
  assert.deepEqual(jokeRes.data.suggestedFollowUps, []);
});

test('Falcon Turn 5: General Knowledge & Factual Queries execute 0 probes and answer accurately', async () => {
  const sessionId = `test-falcon-gk-${Date.now()}`;
  const user = { id: 'admin-1', username: 'admin', role: 'ADMIN' };

  // Capital of Azerbaijan
  const capRes = await chatOperatorService.processMessage({
    sessionId,
    message: 'what is the capital of Azerbaijan?',
    user
  });
  assert.equal(capRes.success, true);
  assert.equal(capRes.intent, 'general_knowledge');
  assert.ok(capRes.reply.includes('Baku') || capRes.reply.includes('Bakı'));
  assert.equal(capRes.steps.length, 0);
  assert.deepEqual(capRes.data.suggestedFollowUps, []);

  // Speed of light
  const speedRes = await chatOperatorService.processMessage({
    sessionId,
    message: 'what is the speed of light?',
    user
  });
  assert.equal(speedRes.success, true);
  assert.equal(speedRes.intent, 'general_knowledge');
  assert.ok(speedRes.reply.includes('299,792,458'));
  assert.equal(speedRes.steps.length, 0);

  // System creator inquiry
  const creatorRes = await chatOperatorService.processMessage({
    sessionId,
    message: 'who created you?',
    user
  });
  assert.equal(creatorRes.success, true);
  assert.ok(creatorRes.reply.includes('Eldar Jamiyev'));
  assert.equal(creatorRes.steps.length, 0);
});

test('Falcon Turn 6: Topic switching clears plan.target to null without losing session target memory', async () => {
  const sessionId = `test-falcon-pivot-${Date.now()}`;
  const user = { id: 'admin-1', username: 'admin', role: 'ADMIN' };

  // Step 1: Probe local host port 3000
  const turn1 = await chatOperatorService.processMessage({
    sessionId,
    message: 'Check whether port 3000 is open on 127.0.0.1',
    user
  });
  assert.equal(turn1.success, true);
  assert.equal(turn1.target, '127.0.0.1');

  const sessionAfterTurn1 = chatOperatorService.getOrCreateSession(sessionId, user);
  assert.equal(sessionAfterTurn1.lastValidTarget, '127.0.0.1');

  // Step 2: Casual turn / ambiguous query
  const turn2Plan = chatOperatorService.parseIntentAndEntities('is muhammed oglan?', sessionAfterTurn1);
  assert.equal(turn2Plan.target, null, 'Target must NOT leak into the casual turn');
  assert.equal(turn2Plan.contextPivotDetected, true, 'contextPivotDetected must be flagged');

  const turn2 = await chatOperatorService.processMessage({
    sessionId,
    message: 'is muhammed oglan?',
    user
  });
  assert.equal(turn2.success, true);
  assert.equal(turn2.target, null, 'Response target must be null');
  assert.equal(turn2.steps.length, 0, 'Zero live probes must execute on 127.0.0.1');
  assert.deepEqual(turn2.data.suggestedFollowUps, [], 'Zero diagnostic suggestions');

  // Verify session memory still remembers 127.0.0.1
  const sessionAfterTurn2 = chatOperatorService.getOrCreateSession(sessionId, user);
  assert.equal(sessionAfterTurn2.lastValidTarget, '127.0.0.1', 'lastValidTarget must be safely preserved');

  // Step 3: Follow-up operational query references the remembered host
  const turn3Plan = chatOperatorService.parseIntentAndEntities('Check port 3000 too', sessionAfterTurn2);
  assert.equal(turn3Plan.target, '127.0.0.1', 'Must correctly recall 127.0.0.1 from session memory');
});

test('Falcon Turn 7: operationalMemoryEngine.generateContextualFollowUps cleanliness', () => {
  // Greetings, casual conversation, general knowledge must return []
  assert.deepEqual(operationalMemoryEngine.generateContextualFollowUps({ intent: 'greeting' }), []);
  assert.deepEqual(operationalMemoryEngine.generateContextualFollowUps({ intent: 'casual_conversation' }), []);
  assert.deepEqual(operationalMemoryEngine.generateContextualFollowUps({ intent: 'general_knowledge' }), []);
  assert.deepEqual(operationalMemoryEngine.generateContextualFollowUps({ intent: 'clarification_needed' }), []);

  // Conceptual informational questions return conceptual follow-ups, never operational probes
  const dnsConceptual = operationalMemoryEngine.generateContextualFollowUps({
    intent: 'informational_question',
    structuredAnswer: { result: 'DNS maps human-readable names to IP addresses.' }
  });
  assert.ok(dnsConceptual.length > 0);
  assert.ok(dnsConceptual[0].label.includes('DNS'));
  assert.ok(!dnsConceptual.some((s) => s.label.includes('local path diagnostic')));

  // Generic fallback with no target returns []
  const emptyTargetFallback = operationalMemoryEngine.generateContextualFollowUps({
    intent: 'custom_intent',
    target: null
  });
  assert.deepEqual(emptyTargetFallback, []);
});

test('Falcon Turn 8: semanticDiagnostics schema and security guarantees', async () => {
  const sessionId = `test-falcon-diag-${Date.now()}`;
  const user = { id: 'admin-1', username: 'admin', role: 'ADMIN' };

  const res = await chatOperatorService.processMessage({
    sessionId,
    message: 'What is the speed of light?',
    user
  });

  const diag = res.semanticDiagnostics;
  assert.ok(diag, 'semanticDiagnostics must be present');
  assert.equal(typeof diag.requestId, 'string');
  assert.equal(typeof diag.sessionId, 'string');
  assert.equal(typeof diag.provider, 'string');
  assert.equal(typeof diag.model, 'string');
  assert.equal(typeof diag.durationMs, 'number');
  assert.equal(typeof diag.success, 'boolean');
  assert.equal(typeof diag.parsingOutcome, 'string');
  assert.equal(diag.selectedIntent, 'general_knowledge');
  assert.equal(typeof diag.timestamp, 'string');

  // Ensure no secrets leaked in serialization
  const serialized = JSON.stringify(diag);
  assert.ok(!serialized.includes('AIzaSy'), 'No API keys in diagnostics');
  assert.ok(!serialized.includes('bearer'), 'No bearer tokens in diagnostics');
});
