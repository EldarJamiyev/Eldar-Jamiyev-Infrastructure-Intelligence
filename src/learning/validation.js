/**
 * EJII Learning Center — Input Validation Service
 * Validates route parameters, identifiers, request bodies, note sizes, and quiz submissions.
 */

'use strict';

const { getCourse, getLesson, getQuiz, getTrack, getLab } = require('./catalog');

const MAX_NOTE_LENGTH = 10000;
const VALID_PROGRESS_STATUSES = new Set(['not_started', 'in_progress', 'completed']);

function validateTrackId(trackId) {
  if (!trackId || typeof trackId !== 'string') return { valid: false, error: 'Track ID must be a non-empty string' };
  const track = getTrack(trackId);
  if (!track) return { valid: false, error: `Track not found: ${trackId}` };
  return { valid: true, track };
}

function validateCourseId(courseId) {
  if (!courseId || typeof courseId !== 'string') return { valid: false, error: 'Course ID must be a non-empty string' };
  const course = getCourse(courseId);
  if (!course) return { valid: false, error: `Course not found: ${courseId}` };
  return { valid: true, course };
}

function validateLessonId(lessonId) {
  if (!lessonId || typeof lessonId !== 'string') return { valid: false, error: 'Lesson ID must be a non-empty string' };
  const lesson = getLesson(lessonId);
  if (!lesson) return { valid: false, error: `Lesson not found: ${lessonId}` };
  return { valid: true, lesson };
}

function validateQuizId(quizId) {
  if (!quizId || typeof quizId !== 'string') return { valid: false, error: 'Quiz ID must be a non-empty string' };
  const quiz = getQuiz(quizId);
  if (!quiz) return { valid: false, error: `Quiz not found: ${quizId}` };
  return { valid: true, quiz };
}

function validateProgressStatus(status) {
  if (!status || !VALID_PROGRESS_STATUSES.has(status)) {
    return {
      valid: false,
      error: `Invalid status. Must be one of: ${Array.from(VALID_PROGRESS_STATUSES).join(', ')}`
    };
  }
  return { valid: true };
}

function validateNoteBody(body) {
  if (typeof body !== 'string') {
    return { valid: false, error: 'Note body must be a string' };
  }
  if (body.length > MAX_NOTE_LENGTH) {
    return { valid: false, error: `Note exceeds maximum length of ${MAX_NOTE_LENGTH} characters` };
  }
  return { valid: true };
}

function validateQuizSubmission(submission) {
  if (!submission || typeof submission !== 'object') {
    return { valid: false, error: 'Quiz submission body must be an object' };
  }
  if (!submission.answers || typeof submission.answers !== 'object') {
    return { valid: false, error: 'Missing or malformed "answers" map in submission' };
  }
  return { valid: true };
}

module.exports = {
  validateTrackId,
  validateCourseId,
  validateLessonId,
  validateQuizId,
  validateProgressStatus,
  validateNoteBody,
  validateQuizSubmission,
  MAX_NOTE_LENGTH
};
