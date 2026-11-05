/**
 * EJII Learning Center — Test Suite: API Endpoints & SQLite Persistence
 * Verifies authenticated /api/learning/* routes against an isolated in-memory test database.
 */

'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');
const { DatabaseSync } = require('node:sqlite');
const { initLearningSchema } = require('../src/db/learning-schema');
const { progressService } = require('../src/learning/progress-service');
const routesLearning = require('../src/api/routes-learning');

console.log('========================================================================');
console.log('  TEST: EJII LEARNING CENTER API & SQLITE PERSISTENCE');
console.log('========================================================================');

async function run() {
  // 1. Initialize isolated in-memory test database
  const testDb = new DatabaseSync(':memory:');
  initLearningSchema(testDb);
  progressService.setDatabase(testDb);

  // 2. Setup mock Express application
  const app = express();
  app.use(express.json());

  // Mock authenticated user middleware for tests
  app.use((req, res, next) => {
    req.user = { id: 'test-admin', username: 'admin.eldar', role: 'admin' };
    next();
  });

  app.use('/api/learning', routesLearning);

  // 3. Start ephemeral HTTP server
  const server = http.createServer(app);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}/api/learning`;

  async function apiGet(path) {
    const res = await fetch(`${baseUrl}${path}`);
    const data = await res.json();
    return { status: res.status, data };
  }

  async function apiPost(path, body) {
    const res = await fetch(`${baseUrl}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await res.json();
    return { status: res.status, data };
  }

  async function apiPut(path, body) {
    const res = await fetch(`${baseUrl}${path}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await res.json();
    return { status: res.status, data };
  }

  try {
    // Test 1: GET /catalog
    console.log('[Test 1] GET /api/learning/catalog...');
    const catRes = await apiGet('/catalog');
    assert.equal(catRes.status, 200);
    assert.equal(catRes.data.success, true);
    assert.equal(catRes.data.tracks.length, 2);
    assert.equal(catRes.data.courseCount, 8);
    console.log('  ✓ Catalog returned 2 tracks and 8 courses.');

    // Test 2: GET /tracks/:trackId
    console.log('[Test 2] GET /api/learning/tracks/network...');
    const trackRes = await apiGet('/tracks/network');
    assert.equal(trackRes.status, 200);
    assert.equal(trackRes.data.track.id, 'network');
    assert.equal(trackRes.data.track.courses.length, 4);
    console.log('  ✓ Track endpoint verified with 4 courses.');

    // Test 3: GET /courses/:courseId
    console.log('[Test 3] GET /api/learning/courses/network-fundamentals...');
    const courseRes = await apiGet('/courses/network-fundamentals');
    assert.equal(courseRes.status, 200);
    assert.equal(courseRes.data.course.id, 'network-fundamentals');
    assert.equal(courseRes.data.course.modules.length, 3);
    console.log('  ✓ Course endpoint verified with 3 modules.');

    // Test 4: GET /lessons/:lessonId
    console.log('[Test 4] GET /api/learning/lessons/net-osi-model...');
    const lessonRes = await apiGet('/lessons/net-osi-model');
    assert.equal(lessonRes.status, 200);
    assert.ok(lessonRes.data.lesson);
    assert.equal(lessonRes.data.lesson.id, 'net-osi-model');
    assert.ok(lessonRes.data.navigation, 'Should include prev/next navigation');
    console.log('  ✓ Lesson endpoint verified with curriculum navigation.');

    // Test 5: GET /quizzes/:quizId (Answer Secrecy)
    console.log('[Test 5] GET /api/learning/quizzes/quiz-network-fundamentals...');
    const quizRes = await apiGet('/quizzes/quiz-network-fundamentals');
    assert.equal(quizRes.status, 200);
    assert.ok(quizRes.data.quiz);
    for (const q of quizRes.data.quiz.questions) {
      assert.equal(q.correctOptionIds, undefined);
      assert.equal(q.correctAnswers, undefined);
    }
    console.log('  ✓ Quiz client serialization verified: 0 answer leaks.');

    // Test 6: POST /quizzes/:quizId/attempts
    console.log('[Test 6] POST /api/learning/quizzes/quiz-network-fundamentals/attempts...');
    const submitRes = await apiPost('/quizzes/quiz-network-fundamentals/attempts', {
      answers: {
        'q-net-fund-1': 1,
        'q-net-fund-2': [0, 1],
        'q-net-fund-3': 0,
        'q-net-fund-4': 1,
        'q-net-fund-5': 'FCS'
      }
    });
    assert.ok(submitRes.status === 200 || submitRes.status === 201, `Status should be 200 or 201, got ${submitRes.status}`);
    assert.equal(submitRes.data.result.passed, true);
    assert.equal(submitRes.data.result.scorePercentage, 100);
    console.log('  ✓ Authoritative server scoring passed attempt (100%).');

    // Test 7: GET /progress and POST /progress
    console.log('[Test 7] Progress tracking: POST /progress and GET /progress...');
    const markRes = await apiPost('/progress', {
      lessonId: 'net-osi-model',
      status: 'completed'
    });
    assert.equal(markRes.status, 200);

    const progRes = await apiGet('/progress');
    assert.equal(progRes.status, 200);
    assert.ok(progRes.data.progress.lessonProgress['net-osi-model']);
    assert.equal(progRes.data.progress.lessonProgress['net-osi-model'].status, 'completed');
    assert.equal(progRes.data.progress.stats.completedCount, 1);
    console.log('  ✓ User progress persisted in SQLite.');

    // Test 8: Bookmarks
    console.log('[Test 8] Bookmarks: POST /bookmarks and GET /bookmarks...');
    const bmPost = await apiPost('/bookmarks', { lessonId: 'net-osi-model' });
    assert.equal(bmPost.status, 200);
    assert.equal(bmPost.data.bookmarked, true);

    const bmGet = await apiGet('/bookmarks');
    assert.equal(bmGet.status, 200);
    assert.equal(bmGet.data.bookmarks.length, 1);
    assert.equal(bmGet.data.bookmarks[0].lesson_id, 'net-osi-model');

    // Toggle off
    const bmToggle = await apiPost('/bookmarks', { lessonId: 'net-osi-model' });
    assert.equal(bmToggle.data.bookmarked, false);
    console.log('  ✓ Bookmark toggle and retrieval verified.');

    // Test 9: Notes
    console.log('[Test 9] Private Notes: PUT /notes/:lessonId and GET /notes/:lessonId...');
    const putNote = await apiPut('/notes/net-osi-model', { note: 'Remember: Layer 3 = Packets, Layer 2 = Frames.' });
    assert.equal(putNote.status, 200);

    const getNote = await apiGet('/notes/net-osi-model');
    assert.equal(getNote.status, 200);
    const noteText = typeof getNote.data.note === 'object' && getNote.data.note ? getNote.data.note.note_text : getNote.data.note;
    assert.equal(noteText, 'Remember: Layer 3 = Packets, Layer 2 = Frames.');
    console.log('  ✓ Personal study notes persisted and retrieved.');

    // Test 10: Recommendations & Search
    console.log('[Test 10] Recommendations & Search queries...');
    const recs = await apiGet('/recommendations');
    assert.equal(recs.status, 200);
    assert.ok(Array.isArray(recs.data.recommendations));

    const search = await apiGet('/search?q=subnetting');
    assert.equal(search.status, 200);
    assert.ok(search.data.results.length > 0);
    console.log(`  ✓ Recommendations and Search (${search.data.results.length} hits) verified.`);

  } finally {
    server.close();
    testDb.close();
  }

  console.log('========================================================================');
  console.log('  SUITE PASSED: 100% LEARNING API ENDPOINTS & SQLITE VERIFIED');
  console.log('========================================================================');
}

run().catch(err => {
  console.error('[API Test Suite Failure]:', err);
  process.exit(1);
});
