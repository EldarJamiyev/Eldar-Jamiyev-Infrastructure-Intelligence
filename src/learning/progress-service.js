/**
 * EJII Learning Center — Progress & State Persistence Service
 * User-scoped database operations for lesson completions, quiz attempts,
 * bookmarks, study notes, and deterministic course recommendations.
 */

'use strict';

const crypto = require('crypto');
const { db: defaultDb } = require('../db/database');
const { getCourse, getLesson, getCourses, getLessons } = require('./catalog');

class ProgressService {
  constructor(database = defaultDb) {
    this.db = database;
  }

  setDatabase(database) {
    this.db = database;
  }

  /**
   * Get progress record for a single lesson
   */
  getLessonProgress(userId, lessonId) {
    if (!userId || !lessonId) return null;
    const stmt = this.db.prepare(`
      SELECT user_id, lesson_id, status, started_at, completed_at, last_accessed_at, updated_at
      FROM learning_lesson_progress
      WHERE user_id = ? AND lesson_id = ?
    `);
    return stmt.get(userId, lessonId) || null;
  }

  /**
   * Update progress status (not_started, in_progress, completed)
   */
  updateLessonProgress(userId, lessonId, status) {
    if (!userId || !lessonId || !status) throw new Error('Missing required arguments');

    const now = new Date().toISOString();
    const existing = this.getLessonProgress(userId, lessonId);

    let startedAt = existing ? existing.started_at : now;
    let completedAt = existing ? existing.completed_at : null;

    if (status === 'completed' && !completedAt) {
      completedAt = now;
    }

    const upsertStmt = this.db.prepare(`
      INSERT INTO learning_lesson_progress (user_id, lesson_id, status, started_at, completed_at, last_accessed_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(user_id, lesson_id) DO UPDATE SET
        status = excluded.status,
        completed_at = COALESCE(learning_lesson_progress.completed_at, excluded.completed_at),
        last_accessed_at = excluded.last_accessed_at,
        updated_at = excluded.updated_at
    `);

    upsertStmt.run(userId, lessonId, status, startedAt, completedAt, now, now);

    // Record activity
    try {
      this.db.prepare(`
        INSERT INTO learning_activity (user_id, activity_type, entity_id, metadata_json, created_at)
        VALUES (?, ?, ?, ?, ?)
      `).run(userId, status === 'completed' ? 'lesson_completed' : 'lesson_accessed', lessonId, JSON.stringify({ status }), now);
    } catch (_) {}

    return this.getLessonProgress(userId, lessonId);
  }

  /**
   * Get all completed lesson IDs for a user
   */
  getUserCompletedLessonIds(userId) {
    if (!userId) return [];
    const rows = this.db.prepare(`
      SELECT lesson_id FROM learning_lesson_progress
      WHERE user_id = ? AND status = 'completed'
    `).all(userId);
    return rows.map(r => r.lesson_id);
  }

  /**
   * Get completion metrics for a course
   */
  getCourseCompletion(userId, courseId) {
    const course = getCourse(courseId);
    if (!course) return { completedCount: 0, totalCount: 0, percent: 0 };

    const courseLessons = getLessons().filter(l => l.courseId === courseId);
    const totalCount = courseLessons.length;
    if (totalCount === 0) return { completedCount: 0, totalCount: 0, percent: 0 };

    const placeholders = courseLessons.map(() => '?').join(',');
    const stmt = this.db.prepare(`
      SELECT COUNT(*) as count FROM learning_lesson_progress
      WHERE user_id = ? AND status = 'completed' AND lesson_id IN (${placeholders})
    `);

    const result = stmt.get(userId, ...courseLessons.map(l => l.id));
    const completedCount = result ? Number(result.count) : 0;
    const percent = Math.round((completedCount / totalCount) * 100);

    return {
      completedCount,
      totalCount,
      percent
    };
  }

  /**
   * Comprehensive learning dashboard summary for a user
   */
  getUserDashboard(userId) {
    if (!userId) return null;

    const allCourses = getCourses();
    const allLessons = getLessons();

    // 1. Completed lessons
    const completedRows = this.db.prepare(`
      SELECT lesson_id, completed_at, last_accessed_at FROM learning_lesson_progress
      WHERE user_id = ? AND status = 'completed'
      ORDER BY completed_at DESC
    `).all(userId);

    const completedLessonIds = new Set(completedRows.map(r => r.lesson_id));

    // 2. Course completions
    let coursesStartedCount = 0;
    let coursesCompletedCount = 0;
    const courseProgressMap = {};

    for (const c of allCourses) {
      const cLessons = allLessons.filter(l => l.courseId === c.id);
      const cCompleted = cLessons.filter(l => completedLessonIds.has(l.id)).length;
      const cPercent = cLessons.length > 0 ? Math.round((cCompleted / cLessons.length) * 100) : 0;

      if (cCompleted > 0) coursesStartedCount++;
      if (cPercent === 100) coursesCompletedCount++;

      courseProgressMap[c.id] = {
        courseId: c.id,
        completedCount: cCompleted,
        totalCount: cLessons.length,
        percent: cPercent
      };
    }

    // 3. Quiz attempts stats
    const quizStats = this.db.prepare(`
      SELECT COUNT(*) as totalAttempts,
             COALESCE(AVG(score * 100.0 / NULLIF(max_score, 0)), 0) as avgScore,
             SUM(passed) as totalPassed
      FROM learning_quiz_attempts
      WHERE user_id = ?
    `).get(userId);

    // 4. Last accessed lesson
    const lastAccessedRow = this.db.prepare(`
      SELECT lesson_id, status, last_accessed_at FROM learning_lesson_progress
      WHERE user_id = ?
      ORDER BY last_accessed_at DESC
      LIMIT 1
    `).get(userId);

    let lastLesson = null;
    if (lastAccessedRow) {
      const l = getLesson(lastAccessedRow.lesson_id);
      if (l) {
        lastLesson = {
          id: l.id,
          title: l.title,
          courseId: l.courseId,
          trackId: l.trackId,
          status: lastAccessedRow.status,
          lastAccessedAt: lastAccessedRow.last_accessed_at
        };
      }
    }

    // 5. Recent activity
    const recentActivity = this.db.prepare(`
      SELECT activity_type, entity_id, created_at
      FROM learning_activity
      WHERE user_id = ?
      ORDER BY created_at DESC
      LIMIT 10
    `).all(userId);

    // 6. Bookmarks count
    const bookmarksCountRow = this.db.prepare(`
      SELECT COUNT(*) as count FROM learning_bookmarks WHERE user_id = ?
    `).get(userId);

    // 7. Notes count
    const notesCountRow = this.db.prepare(`
      SELECT COUNT(*) as count FROM learning_notes WHERE user_id = ?
    `).get(userId);

    const allProgressRows = this.db.prepare(`
      SELECT lesson_id, status, started_at, completed_at, last_accessed_at, updated_at
      FROM learning_lesson_progress
      WHERE user_id = ?
    `).all(userId);
    const lessonProgress = {};
    for (const row of allProgressRows) {
      lessonProgress[row.lesson_id] = row;
    }

    const overallPercentage = allLessons.length > 0 ? Math.round((completedLessonIds.size / allLessons.length) * 100) : 0;

    return {
      lessonProgress,
      stats: {
        totalLessons: allLessons.length,
        completedCount: completedLessonIds.size,
        overallPercentage
      },
      totalCompletedLessons: completedLessonIds.size,
      totalCatalogLessons: allLessons.length,
      overallPercent: overallPercentage,
      coursesStartedCount,
      coursesCompletedCount,
      courseProgressMap,
      quizStats: {
        totalAttempts: Number(quizStats?.totalAttempts || 0),
        avgScorePercent: Math.round(Number(quizStats?.avgScore || 0)),
        totalPassed: Number(quizStats?.totalPassed || 0)
      },
      lastAccessedLesson: lastLesson,
      recentActivity,
      bookmarksCount: Number(bookmarksCountRow?.count || 0),
      notesCount: Number(notesCountRow?.count || 0)
    };
  }

  /**
   * Persist a completed quiz attempt
   */
  recordQuizAttempt(userId, attemptData) {
    if (!userId || !attemptData) throw new Error('Invalid arguments');

    const attemptId = 'att_' + crypto.randomUUID();
    const now = new Date().toISOString();

    const stmt = this.db.prepare(`
      INSERT INTO learning_quiz_attempts (
        id, user_id, quiz_id, lesson_id, course_id, score, max_score, passed,
        answers_json, duration_seconds, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      attemptId,
      userId,
      attemptData.quizId,
      attemptData.lessonId || null,
      attemptData.courseId,
      attemptData.score,
      attemptData.maxScore,
      attemptData.passed ? 1 : 0,
      JSON.stringify(attemptData.answers || {}),
      attemptData.durationSeconds || 0,
      now
    );

    // Record activity
    try {
      this.db.prepare(`
        INSERT INTO learning_activity (user_id, activity_type, entity_id, metadata_json, created_at)
        VALUES (?, ?, ?, ?, ?)
      `).run(
        userId,
        'quiz_attempt',
        attemptData.quizId,
        JSON.stringify({ score: attemptData.score, maxScore: attemptData.maxScore, passed: attemptData.passed }),
        now
      );
    } catch (_) {}

    return {
      id: attemptId,
      ...attemptData,
      createdAt: now
    };
  }

  /**
   * Get user's recent quiz attempts
   */
  getRecentQuizAttempts(userId, limit = 10) {
    if (!userId) return [];
    return this.db.prepare(`
      SELECT id, quiz_id, course_id, score, max_score, passed, duration_seconds, created_at
      FROM learning_quiz_attempts
      WHERE user_id = ?
      ORDER BY created_at DESC
      LIMIT ?
    `).all(userId, limit);
  }

  /**
   * User Bookmarks
   */
  getUserBookmarks(userId) {
    if (!userId) return [];
    const rows = this.db.prepare(`
      SELECT b.lesson_id, b.created_at
      FROM learning_bookmarks b
      WHERE b.user_id = ?
      ORDER BY b.created_at DESC
    `).all(userId);

    return rows.map(r => {
      const l = getLesson(r.lesson_id);
      return {
        lessonId: r.lesson_id,
        lesson_id: r.lesson_id,
        createdAt: r.created_at,
        created_at: r.created_at,
        lesson: l ? {
          id: l.id,
          title: l.title,
          courseId: l.courseId,
          trackId: l.trackId,
          difficulty: l.difficulty,
          estimatedMinutes: l.estimatedMinutes
        } : null
      };
    }).filter(b => b.lesson !== null);
  }

  setBookmark(userId, lessonId, bookmarked) {
    if (!userId || !lessonId) throw new Error('Missing arguments');

    if (bookmarked) {
      const now = new Date().toISOString();
      this.db.prepare(`
        INSERT OR IGNORE INTO learning_bookmarks (user_id, lesson_id, created_at)
        VALUES (?, ?, ?)
      `).run(userId, lessonId, now);
      return { bookmarked: true, lessonId };
    } else {
      this.db.prepare(`
        DELETE FROM learning_bookmarks WHERE user_id = ? AND lesson_id = ?
      `).run(userId, lessonId);
      return { bookmarked: false, lessonId };
    }
  }

  isBookmarked(userId, lessonId) {
    if (!userId || !lessonId) return false;
    const row = this.db.prepare(`
      SELECT 1 FROM learning_bookmarks WHERE user_id = ? AND lesson_id = ?
    `).get(userId, lessonId);
    return Boolean(row);
  }

  /**
   * User Notes
   */
  getUserNote(userId, lessonId) {
    if (!userId || !lessonId) return null;
    const row = this.db.prepare(`
      SELECT body, created_at, updated_at
      FROM learning_notes
      WHERE user_id = ? AND lesson_id = ?
    `).get(userId, lessonId);

    if (!row) return null;
    return {
      userId,
      lessonId,
      body: row.body,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  saveUserNote(userId, lessonId, body) {
    if (!userId || !lessonId) throw new Error('Missing arguments');
    const now = new Date().toISOString();

    if (!body || body.trim() === '') {
      this.db.prepare('DELETE FROM learning_notes WHERE user_id = ? AND lesson_id = ?').run(userId, lessonId);
      return { deleted: true, lessonId };
    }

    this.db.prepare(`
      INSERT INTO learning_notes (user_id, lesson_id, body, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(user_id, lesson_id) DO UPDATE SET
        body = excluded.body,
        updated_at = excluded.updated_at
    `).run(userId, lessonId, body.trim(), now, now);

    return this.getUserNote(userId, lessonId);
  }

  /**
   * Deterministic course & lesson recommendation engine
   */
  getRecommendations(userId) {
    const allCourses = getCourses();
    const allLessons = getLessons();
    const completedLessonIds = new Set(this.getUserCompletedLessonIds(userId));

    // Find first course with unmet lessons where prerequisites are met
    for (const course of allCourses) {
      // Check prerequisites
      const prereqsMet = (course.prerequisites || []).every(prereqId => {
        const prereqLessons = allLessons.filter(l => l.courseId === prereqId);
        return prereqLessons.every(pl => completedLessonIds.has(pl.id));
      });

      if (prereqsMet) {
        const uncompletedInCourse = allLessons.filter(l => l.courseId === course.id && !completedLessonIds.has(l.id));
        if (uncompletedInCourse.length > 0) {
          const nextLesson = uncompletedInCourse[0];
          return {
            hasRecommendation: true,
            reason: completedLessonIds.size === 0
              ? 'Recommended starting lesson for your educational track.'
              : `Continue your progress in ${course.title}.`,
            course: {
              id: course.id,
              title: course.title,
              trackId: course.trackId
            },
            lesson: {
              id: nextLesson.id,
              title: nextLesson.title,
              difficulty: nextLesson.difficulty,
              estimatedMinutes: nextLesson.estimatedMinutes,
              objectives: nextLesson.objectives
            }
          };
        }
      }
    }

    // If all courses completed
    return {
      hasRecommendation: false,
      reason: 'Outstanding achievement! You have completed all courses in the catalog.',
      course: null,
      lesson: null
    };
  }
}

const progressService = new ProgressService();

module.exports = {
  ProgressService,
  progressService
};
