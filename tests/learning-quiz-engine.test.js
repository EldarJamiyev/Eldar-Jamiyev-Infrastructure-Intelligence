/**
 * EJII Learning Center — Test Suite: Quiz Engine & Authoritative Server Scoring
 * Verifies answer secrecy in client serialization and rigorous server-side evaluation.
 */

'use strict';

const assert = require('node:assert/strict');
const { prepareQuizForClient, scoreQuizAttempt } = require('../src/learning/quiz-engine');
const { getQuiz } = require('../src/learning/catalog');

console.log('========================================================================');
console.log('  TEST: EJII LEARNING CENTER QUIZ ENGINE & AUTHORITATIVE SCORING');
console.log('========================================================================');

// Test 1: Answer Secrecy
console.log('[Test 1] Verifying answer secrecy in prepareQuizForClient()...');
const rawQuiz = getQuiz('quiz-network-fundamentals');
assert.ok(rawQuiz, 'quiz-network-fundamentals must exist');

const clientQuiz = prepareQuizForClient(rawQuiz);
assert.ok(clientQuiz, 'Client quiz must be produced');
assert.equal(clientQuiz.id, rawQuiz.id);
assert.equal(clientQuiz.title, rawQuiz.title);
assert.equal(clientQuiz.questions.length, rawQuiz.questions.length);

// Verify no question in clientQuiz contains answer leaks
for (const q of clientQuiz.questions) {
  assert.equal(q.correctOptionIds, undefined, `Question ${q.id} must not leak correctOptionIds`);
  assert.equal(q.correctAnswers, undefined, `Question ${q.id} must not leak correctAnswers`);
  assert.equal(q.correctIndex, undefined, `Question ${q.id} must not leak correctIndex`);
  assert.equal(q.explanation, undefined, `Question ${q.id} must not leak explanation before submit`);
}
console.log('  ✓ Answer secrecy strictly verified: 0% answer leakage to browser.');

// Test 2: Perfect Score Submission
console.log('[Test 2] Simulating 100% perfect quiz attempt...');
const perfectAnswers = {
  'q-net-fund-1': 1,                 // Layer 3 (Network Layer)
  'q-net-fund-2': [0, 1],            // MAC and FCS
  'q-net-fund-3': 0,                 // True
  'q-net-fund-4': 1,                 // ARP
  'q-net-fund-5': 'FCS'              // Frame Check Sequence
};

const perfectResult = scoreQuizAttempt(rawQuiz, perfectAnswers);
assert.equal(perfectResult.quizId, rawQuiz.id);
assert.equal(perfectResult.passed, true, 'Perfect attempt must pass');
assert.equal(perfectResult.scorePercentage, 100, 'Score should be 100%');
assert.equal(perfectResult.correctCount, rawQuiz.questions.length);
assert.ok(Array.isArray(perfectResult.review));
assert.equal(perfectResult.review.length, rawQuiz.questions.length);

for (const rev of perfectResult.review) {
  assert.equal(rev.isCorrect, true);
  assert.ok(rev.explanation && rev.explanation.length > 10, 'Review should contain detailed explanation');
}
console.log(`  ✓ Perfect attempt verified: ${perfectResult.scorePercentage}% score, passed=true.`);

// Test 3: Failing Score Submission
console.log('[Test 3] Simulating failing quiz attempt...');
const failingAnswers = {
  'q-net-fund-1': 0,                 // Incorrect (Layer 1)
  'q-net-fund-2': [1],               // Partial incorrect
  'q-net-fund-3': 1,                 // False (incorrect)
  'q-net-fund-4': 2,                 // DNS (incorrect)
  'q-net-fund-5': 'WRONG_ANSWER'     // Incorrect
};

const failingResult = scoreQuizAttempt(rawQuiz, failingAnswers);
assert.equal(failingResult.passed, false, 'Failing attempt must fail');
assert.ok(failingResult.scorePercentage < rawQuiz.passThreshold, 'Score must be below threshold');
assert.equal(failingResult.correctCount, 0);
console.log(`  ✓ Failing attempt verified: ${failingResult.scorePercentage}% score, passed=false.`);

// Test 4: Short-Answer Flexibility
console.log('[Test 4] Verifying short-answer case-insensitivity and whitespace trimming...');
const flexAnswers = {
  ...perfectAnswers,
  'q-net-fund-5': '  fcs  '          // lowercase with padding whitespace
};
const flexResult = scoreQuizAttempt(rawQuiz, flexAnswers);
const fcsReview = flexResult.review.find(r => r.questionId === 'q-net-fund-5');
assert.ok(fcsReview, 'Review for FCS must exist');
assert.equal(fcsReview.isCorrect, true, 'Whitespace and case should be tolerated');
console.log('  ✓ Short answer flexibility verified (case-insensitive & trimmed).');

// Test 5: Multiple Select Strict Evaluation
console.log('[Test 5] Verifying strict multiple-select grading (no partial credit for missing items)...');
const partialAnswers = {
  ...perfectAnswers,
  'q-net-fund-2': [0]                // Only selected 1 out of 2 required options
};
const partialResult = scoreQuizAttempt(rawQuiz, partialAnswers);
const q2Review = partialResult.review.find(r => r.questionId === 'q-net-fund-2');
assert.equal(q2Review.isCorrect, false, 'Incomplete multiple select should be marked incorrect');
console.log('  ✓ Strict multiple select verified: partial selection marked incorrect.');

console.log('========================================================================');
console.log('  SUITE PASSED: 100% QUIZ ENGINE INTEGRITY VERIFIED');
console.log('========================================================================');
