/**
 * EJII Learning Center — Test Suite: Client-Side Hash Router
 * Verifies deep link parsing, parameter extraction, and route href generation.
 */

'use strict';

const assert = require('node:assert/strict');
const Router = require('../public/js/learning/learning-router');

console.log('========================================================================');
console.log('  TEST: EJII LEARNING CENTER HASH ROUTER SPECIFICATION');
console.log('========================================================================');

const parse = Router.parseRoute;
const href = Router.getRouteHref;

// 1. Hub Route
console.log('[Test 1] Verifying Academy Hub Route...');
assert.deepEqual(parse('#/learning'), { view: 'hub' });
assert.deepEqual(parse('#learning'), { view: 'hub' });
assert.deepEqual(parse('learning'), { view: 'hub' });
assert.equal(href({ view: 'hub' }), '#/learning');
console.log('  ✓ Hub route verified.');

// 2. Track Routes
console.log('[Test 2] Verifying Track Routes...');
assert.deepEqual(parse('#/learning/network'), { view: 'track', trackId: 'network' });
assert.deepEqual(parse('#/learning/system'), { view: 'track', trackId: 'system' });
assert.deepEqual(parse('#/learning/track/network'), { view: 'track', trackId: 'network' });
assert.equal(href({ view: 'track', trackId: 'network' }), '#/learning/network');
console.log('  ✓ Track routes verified.');

// 3. Course Routes
console.log('[Test 3] Verifying Course Routes...');
assert.deepEqual(parse('#/learning/course/network-fundamentals'), { view: 'course', courseId: 'network-fundamentals' });
assert.deepEqual(parse('#/learning/course/windows-server'), { view: 'course', courseId: 'windows-server' });
assert.equal(href({ view: 'course', courseId: 'network-fundamentals' }), '#/learning/course/network-fundamentals');
console.log('  ✓ Course routes verified.');

// 4. Lesson Routes
console.log('[Test 4] Verifying Lesson Routes...');
assert.deepEqual(parse('#/learning/lesson/net-osi-model'), { view: 'lesson', lessonId: 'net-osi-model' });
assert.deepEqual(parse('#/learning/lesson/sys-win-kernel-services'), { view: 'lesson', lessonId: 'sys-win-kernel-services' });
assert.equal(href({ view: 'lesson', lessonId: 'net-osi-model' }), '#/learning/lesson/net-osi-model');
console.log('  ✓ Lesson routes verified.');

// 5. Quiz Routes
console.log('[Test 5] Verifying Quiz Routes...');
assert.deepEqual(parse('#/learning/quiz/quiz-network-fundamentals'), { view: 'quiz', quizId: 'quiz-network-fundamentals' });
assert.equal(href({ view: 'quiz', quizId: 'quiz-network-fundamentals' }), '#/learning/quiz/quiz-network-fundamentals');
console.log('  ✓ Quiz routes verified.');

// 6. Educational Lab Routes
console.log('[Test 6] Verifying Lab Routes...');
assert.deepEqual(parse('#/learning/lab/net-subnetting-trainer'), { view: 'lab', labId: 'net-subnetting-trainer' });
assert.deepEqual(parse('#/learning/lab/sys-linux-sandbox'), { view: 'lab', labId: 'sys-linux-sandbox' });
assert.equal(href({ view: 'lab', labId: 'net-subnetting-trainer' }), '#/learning/lab/net-subnetting-trainer');
console.log('  ✓ Lab routes verified.');

// 7. Progress & Flashcards Routes
console.log('[Test 7] Verifying Progress & Flashcards Routes...');
assert.deepEqual(parse('#/learning/progress'), { view: 'progress' });
assert.equal(href({ view: 'progress' }), '#/learning/progress');

assert.deepEqual(parse('#/learning/flashcards'), { view: 'flashcards' });
assert.equal(href({ view: 'flashcards' }), '#/learning/flashcards');
console.log('  ✓ Progress and Flashcards routes verified.');

// 8. Non-learning routes
console.log('[Test 8] Verifying Non-learning route isolation...');
assert.equal(parse('#/topology'), null);
assert.equal(parse('#packet-sniffer'), null);
assert.equal(parse(''), null);
console.log('  ✓ Non-learning routes properly rejected (returned null).');

console.log('========================================================================');
console.log('  SUITE PASSED: 100% LEARNING HASH ROUTER SPECIFICATION VERIFIED');
console.log('========================================================================');
