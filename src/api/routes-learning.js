/**
 * EJII Learning Center API Routes
 * Implements authenticated endpoints for Curriculum Catalog, Lessons, Progress Tracking,
 * Bookmarks, Notes, Quizzes, and Recommendations.
 */

'use strict';

const express = require('express');
const router = express.Router();
const { authenticate } = require('./middleware');
const {
  getTracks,
  getTrack,
  getCourses,
  getCourse,
  getModules,
  getModule,
  getLessons,
  getLesson,
  getQuizzes,
  getQuiz,
  getLabs,
  getLab,
  searchCatalog
} = require('../learning/catalog');
const {
  validateTrackId,
  validateCourseId,
  validateLessonId,
  validateQuizId,
  validateProgressStatus,
  validateNoteBody,
  validateQuizSubmission
} = require('../learning/validation');
const { prepareQuizForClient, scoreQuizAttempt } = require('../learning/quiz-engine');
const { progressService } = require('../learning/progress-service');

// Optional auth helper: enriches response with user context if authenticated, but does not block
function optionalAuthenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authenticate(req, res, next);
  } else if (req.cookies && req.cookies.eji_session) {
    return authenticate(req, res, next);
  }
  next();
}

/**
 * GET /api/learning/catalog
 * Complete curriculum catalog overview
 */
router.get('/catalog', (req, res) => {
  try {
    const tracks = getTracks();
    const courses = getCourses();
    const modules = getModules();
    const lessons = getLessons();
    const labs = getLabs();

    res.json({
      success: true,
      timestamp: new Date().toISOString(),
      tracks: tracks.map(t => ({
        ...t,
        courseCount: (t.courseIds || []).length
      })),
      courseCount: courses.length,
      moduleCount: modules.length,
      lessonCount: lessons.length,
      labCount: labs.length,
      courses: courses.map(c => ({
        id: c.id,
        trackId: c.trackId,
        slug: c.slug,
        title: c.title,
        subtitle: c.subtitle,
        description: c.description,
        level: c.level,
        estimatedMinutes: c.estimatedMinutes,
        prerequisites: c.prerequisites,
        accent: c.accent,
        moduleCount: (c.moduleIds || []).length,
        lessonCount: lessons.filter(l => l.courseId === c.id).length
      }))
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to retrieve catalog: ' + err.message });
  }
});

/**
 * GET /api/learning/tracks/:trackId
 */
router.get('/tracks/:trackId', (req, res) => {
  const { valid, track, error } = validateTrackId(req.params.trackId);
  if (!valid) return res.status(404).json({ success: false, error });

  const allCourses = getCourses();
  const allLessons = getLessons();
  const trackCourses = allCourses.filter(c => c.trackId === track.id).map(c => ({
    ...c,
    lessonCount: allLessons.filter(l => l.courseId === c.id).length
  }));

  res.json({
    success: true,
    track,
    courses: trackCourses
  });
});

/**
 * GET /api/learning/courses/:courseId
 */
router.get('/courses/:courseId', optionalAuthenticate, (req, res) => {
  const { valid, course, error } = validateCourseId(req.params.courseId);
  if (!valid) return res.status(404).json({ success: false, error });

  const courseModules = getModules().filter(m => m.courseId === course.id);
  const courseLessons = getLessons().filter(l => l.courseId === course.id);

  // Compute user progress if authenticated
  let userCompletion = null;
  if (req.user && req.user.id) {
    userCompletion = progressService.getCourseCompletion(req.user.id, course.id);
  }

  res.json({
    success: true,
    course,
    modules: courseModules.map(m => ({
      ...m,
      lessons: courseLessons.filter(l => l.moduleId === m.id).map(l => ({
        id: l.id,
        title: l.title,
        slug: l.slug,
        difficulty: l.difficulty,
        estimatedMinutes: l.estimatedMinutes,
        objectives: l.objectives
      }))
    })),
    userCompletion
  });
});

/**
 * GET /api/learning/lessons/:lessonId
 */
router.get('/lessons/:lessonId', optionalAuthenticate, (req, res) => {
  const { valid, lesson, error } = validateLessonId(req.params.lessonId);
  if (!valid) return res.status(404).json({ success: false, error });

  const course = getCourse(lesson.courseId);
  const moduleInfo = getModule(lesson.moduleId);

  let userProgress = null;
  let isBookmarked = false;
  let userNote = null;

  if (req.user && req.user.id) {
    userProgress = progressService.getLessonProgress(req.user.id, lesson.id);
    isBookmarked = progressService.isBookmarked(req.user.id, lesson.id);
    userNote = progressService.getUserNote(req.user.id, lesson.id);

    // Auto mark in_progress if not started
    if (!userProgress || userProgress.status === 'not_started') {
      userProgress = progressService.updateLessonProgress(req.user.id, lesson.id, 'in_progress');
    }
  }

  // Linked labs
  const labs = (lesson.labIds || []).map(labId => getLab(labId)).filter(Boolean);

  const prevLesson = lesson.prevLessonId ? getLesson(lesson.prevLessonId) : null;
  const nextLesson = lesson.nextLessonId ? getLesson(lesson.nextLessonId) : null;
  const navigation = {
    prev: prevLesson ? { id: prevLesson.id, title: prevLesson.title } : null,
    next: nextLesson ? { id: nextLesson.id, title: nextLesson.title } : null
  };

  res.json({
    success: true,
    lesson,
    course: course ? { id: course.id, title: course.title, trackId: course.trackId } : null,
    module: moduleInfo ? { id: moduleInfo.id, title: moduleInfo.title } : null,
    navigation,
    labs,
    userState: {
      progress: userProgress,
      isBookmarked,
      note: userNote ? userNote.body : ''
    }
  });
});

/**
 * GET /api/learning/progress
 * Authenticated user dashboard
 */
router.get('/progress', authenticate, (req, res) => {
  try {
    const dashboard = progressService.getUserDashboard(req.user.id);
    res.json({
      success: true,
      user: {
        id: req.user.id,
        username: req.user.username,
        role: req.user.role
      },
      dashboard,
      progress: dashboard
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to retrieve progress: ' + err.message });
  }
});

/**
 * POST /api/learning/progress
 */
router.post('/progress', authenticate, (req, res) => {
  const lessonId = req.body && req.body.lessonId;
  const { valid: lValid, lesson, error: lError } = validateLessonId(lessonId);
  if (!lValid) return res.status(404).json({ success: false, error: lError });

  const status = req.body && req.body.status;
  const { valid: sValid, error: sError } = validateProgressStatus(status);
  if (!sValid) return res.status(400).json({ success: false, error: sError });

  try {
    const updated = progressService.updateLessonProgress(req.user.id, lesson.id, status);
    res.json({
      success: true,
      progress: updated
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to update progress: ' + err.message });
  }
});

/**
 * PATCH /api/learning/progress/:lessonId
 */
router.patch('/progress/:lessonId', authenticate, (req, res) => {
  const { valid: lValid, lesson, error: lError } = validateLessonId(req.params.lessonId);
  if (!lValid) return res.status(404).json({ success: false, error: lError });

  const status = req.body && req.body.status;
  const { valid: sValid, error: sError } = validateProgressStatus(status);
  if (!sValid) return res.status(400).json({ success: false, error: sError });

  try {
    const updated = progressService.updateLessonProgress(req.user.id, lesson.id, status);
    res.json({
      success: true,
      progress: updated
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to update progress: ' + err.message });
  }
});

/**
 * GET /api/learning/bookmarks
 */
router.get('/bookmarks', authenticate, (req, res) => {
  try {
    const bookmarks = progressService.getUserBookmarks(req.user.id);
    res.json({
      success: true,
      bookmarks
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to retrieve bookmarks: ' + err.message });
  }
});

/**
 * POST /api/learning/bookmarks (Toggle bookmark)
 */
router.post('/bookmarks', authenticate, (req, res) => {
  const lessonId = req.body && req.body.lessonId;
  const { valid, lesson, error } = validateLessonId(lessonId);
  if (!valid) return res.status(404).json({ success: false, error });

  try {
    const isCurrently = progressService.isBookmarked(req.user.id, lesson.id);
    const newStatus = req.body.bookmarked !== undefined ? Boolean(req.body.bookmarked) : !isCurrently;
    const result = progressService.setBookmark(req.user.id, lesson.id, newStatus);
    res.json({
      success: true,
      bookmarked: newStatus,
      ...result
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to toggle bookmark: ' + err.message });
  }
});

/**
 * PUT /api/learning/bookmarks/:lessonId
 */
router.put('/bookmarks/:lessonId', authenticate, (req, res) => {
  const { valid, lesson, error } = validateLessonId(req.params.lessonId);
  if (!valid) return res.status(404).json({ success: false, error });

  const isBookmarked = req.body && typeof req.body.bookmarked === 'boolean' ? req.body.bookmarked : true;

  try {
    const result = progressService.setBookmark(req.user.id, lesson.id, isBookmarked);
    res.json({
      success: true,
      ...result
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to set bookmark: ' + err.message });
  }
});

/**
 * GET /api/learning/notes/:lessonId
 */
router.get('/notes/:lessonId', authenticate, (req, res) => {
  const { valid, lesson, error } = validateLessonId(req.params.lessonId);
  if (!valid) return res.status(404).json({ success: false, error });

  try {
    const note = progressService.getUserNote(req.user.id, lesson.id);
    res.json({
      success: true,
      note: note ? (note.note_text || note.body || '') : '',
      updatedAt: note ? note.updatedAt : null
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to retrieve note: ' + err.message });
  }
});

/**
 * PUT /api/learning/notes/:lessonId
 */
router.put('/notes/:lessonId', authenticate, (req, res) => {
  const { valid: lValid, lesson, error: lError } = validateLessonId(req.params.lessonId);
  if (!lValid) return res.status(404).json({ success: false, error: lError });

  const body = req.body && typeof req.body.body === 'string' ? req.body.body :
               (req.body && typeof req.body.note === 'string' ? req.body.note : '');
  const { valid: bValid, error: bError } = validateNoteBody(body);
  if (!bValid) return res.status(400).json({ success: false, error: bError });

  try {
    const result = progressService.saveUserNote(req.user.id, lesson.id, body);
    res.json({
      success: true,
      saved: true,
      note: result ? (result.note_text || result.body || '') : ''
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to save note: ' + err.message });
  }
});

/**
 * GET /api/learning/quizzes/:quizId
 * Returns sanitized questions without answer keys
 */
router.get('/quizzes/:quizId', (req, res) => {
  const { valid, quiz, error } = validateQuizId(req.params.quizId);
  if (!valid) return res.status(404).json({ success: false, error });

  const sanitized = prepareQuizForClient(quiz);
  res.json({
    success: true,
    quiz: sanitized
  });
});

/**
 * POST /api/learning/quizzes/:quizId/attempts
 * Server-side verified evaluation and scoring
 */
router.post('/quizzes/:quizId/attempts', authenticate, (req, res) => {
  const { valid: qValid, quiz, error: qError } = validateQuizId(req.params.quizId);
  if (!qValid) return res.status(404).json({ success: false, error: qError });

  const { valid: sValid, error: sError } = validateQuizSubmission(req.body);
  if (!sValid) return res.status(400).json({ success: false, error: sError });

  try {
    const scored = scoreQuizAttempt(quiz, req.body);
    const recorded = progressService.recordQuizAttempt(req.user.id, {
      ...scored,
      lessonId: req.body.lessonId || null
    });

    res.status(201).json({
      success: true,
      attempt: recorded,
      result: scored
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Quiz evaluation failed: ' + err.message });
  }
});

/**
 * GET /api/learning/recommendations
 */
router.get('/recommendations', authenticate, (req, res) => {
  try {
    const recommendation = progressService.getRecommendations(req.user.id);
    const recsList = (recommendation && recommendation.hasRecommendation && recommendation.lesson) ? [{
      courseId: recommendation.course ? recommendation.course.id : '',
      courseTitle: recommendation.course ? recommendation.course.title : '',
      lessonId: recommendation.lesson.id,
      lessonTitle: recommendation.lesson.title,
      reason: recommendation.reason
    }] : [];

    res.json({
      success: true,
      recommendation,
      recommendations: recsList
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to generate recommendation: ' + err.message });
  }
});

/**
 * GET /api/learning/search?q=...
 */
router.get('/search', (req, res) => {
  const query = req.query.q || '';
  const results = searchCatalog(query);
  res.json({
    success: true,
    query,
    results
  });
});

module.exports = router;
