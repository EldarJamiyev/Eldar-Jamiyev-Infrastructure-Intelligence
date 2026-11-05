/**
 * EJII Learning Center Schema (Additive & Non-Destructive)
 * Tables for user-scoped lesson progress, quiz attempts, bookmarks, notes, and activity.
 */

'use strict';

const { db: defaultDb } = require('./database');

function initLearningSchema(databaseInstance = defaultDb) {
  if (!databaseInstance) return;

  databaseInstance.exec(`
    CREATE TABLE IF NOT EXISTS learning_lesson_progress (
      user_id TEXT NOT NULL,
      lesson_id TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('not_started', 'in_progress', 'completed')),
      started_at TEXT,
      completed_at TEXT,
      last_accessed_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      PRIMARY KEY (user_id, lesson_id)
    );
    CREATE INDEX IF NOT EXISTS idx_learning_progress_user_status ON learning_lesson_progress(user_id, status);

    CREATE TABLE IF NOT EXISTS learning_quiz_attempts (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      quiz_id TEXT NOT NULL,
      lesson_id TEXT,
      course_id TEXT NOT NULL,
      score INTEGER NOT NULL CHECK (score >= 0),
      max_score INTEGER NOT NULL CHECK (max_score >= 0),
      passed INTEGER NOT NULL CHECK (passed IN (0, 1)),
      answers_json TEXT NOT NULL,
      duration_seconds INTEGER,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_learning_attempts_user_quiz ON learning_quiz_attempts(user_id, quiz_id);
    CREATE INDEX IF NOT EXISTS idx_learning_attempts_user_date ON learning_quiz_attempts(user_id, created_at);

    CREATE TABLE IF NOT EXISTS learning_bookmarks (
      user_id TEXT NOT NULL,
      lesson_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      PRIMARY KEY (user_id, lesson_id)
    );

    CREATE TABLE IF NOT EXISTS learning_notes (
      user_id TEXT NOT NULL,
      lesson_id TEXT NOT NULL,
      body TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      PRIMARY KEY (user_id, lesson_id)
    );

    CREATE TABLE IF NOT EXISTS learning_activity (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      activity_type TEXT NOT NULL,
      entity_id TEXT NOT NULL,
      metadata_json TEXT,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_learning_activity_user_date ON learning_activity(user_id, created_at);
  `);
}

// Auto-initialize with default database instance
try {
  initLearningSchema(defaultDb);
} catch (err) {
  console.error('[EJII Learning Schema] Initialization error:', err.message);
}

module.exports = {
  initLearningSchema
};
