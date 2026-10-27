/**
 * EJII Learning Center — Test Suite: Curriculum & Catalog Structural Integrity
 * Tests all 2 tracks, 8 courses, 24 modules, 72 lessons, 8 quizzes, and 8 labs.
 * Asserts DAG prerequisite acyclicity, content richness, and schema compliance.
 */

'use strict';

const assert = require('node:assert/strict');
const { getCatalog, getTrack, getCourse, getLesson, getQuiz, getLab, validateCurriculum, searchCatalog } = require('../src/learning/catalog');

console.log('========================================================================');
console.log('  TEST: EJII LEARNING CENTER CURRICULUM CATALOG INTEGRITY');
console.log('========================================================================');

// Test 1: Full validation check
console.log('[Test 1] Executing validateCurriculum() integrity verification...');
const validation = validateCurriculum();
assert.equal(validation.valid, true, `Curriculum validation failed: ${validation.errors.join('; ')}`);
console.log('  ✓ Curriculum validation passed: Zero structural errors or DAG cycles.');

// Test 2: Catalog Summary Counts
console.log('[Test 2] Verifying exact catalog summary counts...');
const catalog = getCatalog();
assert.ok(catalog, 'Catalog should exist');
assert.equal(catalog.summary.totalTracks, 2, 'Exactly 2 learning tracks');
assert.equal(catalog.summary.totalCourses, 8, 'Exactly 8 courses');
assert.equal(catalog.summary.totalModules, 24, 'Exactly 24 curriculum modules');
assert.equal(catalog.summary.totalLessons, 72, 'Exactly 72 substantive lessons');
assert.equal(catalog.summary.totalQuizzes, 8, 'Exactly 8 course quizzes');
assert.equal(catalog.summary.totalLabs, 8, 'Exactly 8 educational labs');
console.log(`  ✓ Counts verified: ${catalog.summary.totalCourses} courses, ${catalog.summary.totalModules} modules, ${catalog.summary.totalLessons} lessons, ${catalog.summary.totalLabs} labs.`);

// Test 3: Track Inspections
console.log('[Test 3] Verifying Track structures (Network Academy vs System Academy)...');
const netTrack = getTrack('network');
assert.ok(netTrack, 'Network track must exist');
assert.equal(netTrack.id, 'network');
assert.equal(netTrack.courses.length, 4, 'Network track has 4 courses');

const sysTrack = getTrack('system');
assert.ok(sysTrack, 'System track must exist');
assert.equal(sysTrack.id, 'system');
assert.equal(sysTrack.courses.length, 4, 'System track has 4 courses');
console.log('  ✓ Both tracks verified with 4 courses each.');

// Test 4: Substantive Lesson Content Quality
console.log('[Test 4] Verifying depth and substance of all 72 lessons...');
let totalCodeBlocks = 0;
let totalTables = 0;
let totalCallouts = 0;
let totalKnowledgeChecks = 0;

for (const track of catalog.tracks) {
  for (const course of track.courses) {
    assert.equal(course.modules.length, 3, `Course ${course.id} must have exactly 3 modules`);
    for (const mod of course.modules) {
      assert.equal(mod.lessons.length, 3, `Module ${mod.id} must have exactly 3 lessons`);
      for (const lesson of mod.lessons) {
        assert.ok(lesson.title && lesson.title.length > 5, `Lesson ${lesson.id} must have a descriptive title`);
        assert.ok(Array.isArray(lesson.objectives) && lesson.objectives.length >= 2, `Lesson ${lesson.id} must have at least 2 objectives`);
        assert.ok(lesson.content && lesson.content.length >= 500, `Lesson ${lesson.id} content must be substantive (got ${lesson.content ? lesson.content.length : 0} chars)`);

        if (lesson.content.includes('```')) totalCodeBlocks++;
        if (lesson.content.includes('|')) totalTables++;
        if (lesson.content.includes('> [!')) totalCallouts++;
        if (lesson.knowledgeCheck) {
          totalKnowledgeChecks++;
          assert.ok(lesson.knowledgeCheck.question, `Knowledge check in ${lesson.id} must have a question`);
          assert.equal(lesson.knowledgeCheck.options.length, 4, `Knowledge check in ${lesson.id} must have 4 options`);
          assert.ok(lesson.knowledgeCheck.correctIndex >= 0 && lesson.knowledgeCheck.correctIndex <= 3, `Knowledge check in ${lesson.id} valid correctIndex`);
          assert.ok(lesson.knowledgeCheck.explanation, `Knowledge check in ${lesson.id} must have an explanation`);
        }
      }
    }
  }
}
assert.ok(totalCodeBlocks >= 30, `Expected substantive code blocks across curriculum (found ${totalCodeBlocks})`);
assert.ok(totalTables >= 20, `Expected markdown reference tables across curriculum (found ${totalTables})`);
assert.ok(totalCallouts >= 20, `Expected callout alerts across curriculum (found ${totalCallouts})`);
assert.equal(totalKnowledgeChecks, 72, `Every single lesson must have an inline knowledge check (found ${totalKnowledgeChecks})`);
console.log(`  ✓ Content audit passed: 72 lessons, ${totalCodeBlocks} code blocks, ${totalTables} reference tables, ${totalCallouts} callouts, 72 knowledge checks.`);

// Test 5: Quiz Definitions
console.log('[Test 5] Verifying 8 course quizzes...');
for (const track of catalog.tracks) {
  for (const course of track.courses) {
    const quiz = getQuiz(course.quizId);
    assert.ok(quiz, `Quiz ${course.quizId} for course ${course.id} must exist`);
    assert.ok(quiz.questions.length >= 5, `Quiz ${quiz.id} must have at least 5 questions`);
    assert.ok(quiz.passThreshold >= 70, `Quiz ${quiz.id} pass threshold >= 70%`);
  }
}
console.log('  ✓ 8 Course Quizzes verified with questions and passing criteria.');

// Test 6: Educational Lab Definitions
console.log('[Test 6] Verifying 8 educational labs...');
const expectedLabIds = [
  'net-subnetting-trainer',
  'net-packet-journey',
  'net-vlan-lab',
  'net-routing-explorer',
  'sys-powershell-sandbox',
  'sys-linux-sandbox',
  'sys-active-directory-lab',
  'sys-dns-dhcp-lab'
];
for (const labId of expectedLabIds) {
  const lab = getLab(labId);
  assert.ok(lab, `Lab ${labId} must exist`);
  assert.ok(lab.objectives.length >= 2, `Lab ${labId} must have objectives`);
  assert.ok(lab.supportedModes.length >= 1, `Lab ${labId} must have supported modes`);
}
console.log('  ✓ All 8 educational labs verified.');

// Test 7: Catalog Search
console.log('[Test 7] Verifying catalog search...');
const subnetResults = searchCatalog('subnetting');
assert.ok(subnetResults.length > 0, 'Search for "subnetting" should return results');
const powershellResults = searchCatalog('powershell');
assert.ok(powershellResults.length > 0, 'Search for "powershell" should return results');
console.log(`  ✓ Search helper verified: found ${subnetResults.length} hits for 'subnetting', ${powershellResults.length} hits for 'powershell'.`);

console.log('========================================================================');
console.log('  SUITE PASSED: 100% CURRICULUM CATALOG INTEGRITY VERIFIED');
console.log('========================================================================');
