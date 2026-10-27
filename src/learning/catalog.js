/**
 * EJII Learning Center — Canonical Curriculum Catalog
 * Combines Tracks, Courses, Modules, Lessons, Quizzes, and Labs.
 * Provides normalized catalog lookups, search, and integrity verification.
 */

'use strict';

const { NETWORK_COURSES, NETWORK_MODULES, NETWORK_LESSONS } = require('./curriculum-network');
const { SYSTEM_COURSES, SYSTEM_MODULES, SYSTEM_LESSONS } = require('./curriculum-system');
const { QUIZZES } = require('./quizzes-data');
const { LABS } = require('./lab-definitions');

const TRACKS = [
  {
    id: 'network',
    slug: 'network',
    title: 'Network Academy',
    subtitle: 'CCNA Preparation & Network Administration',
    description: 'Master computer networking from physical transmission, IP subnetting, and switching to routing protocols, security, and Python automation.',
    accent: '#0284C7',
    badge: 'CCNA ALIGNED',
    courseIds: [
      'network-fundamentals',
      'ip-addressing',
      'switching-routing',
      'network-services'
    ]
  },
  {
    id: 'system',
    slug: 'system',
    title: 'System Administration Academy',
    subtitle: 'Windows, Linux & Enterprise Operations',
    description: 'Develop enterprise systems engineering expertise across Windows administration, Active Directory, Linux systemd daemons, and site reliability operations.',
    accent: '#475569',
    badge: 'SYSADMIN & SRE',
    courseIds: [
      'windows-administration',
      'windows-server',
      'linux-administration',
      'enterprise-operations'
    ]
  }
];

const COURSES = [...NETWORK_COURSES, ...SYSTEM_COURSES];
const MODULES = [...NETWORK_MODULES, ...SYSTEM_MODULES];
const LESSONS = [...NETWORK_LESSONS, ...SYSTEM_LESSONS];

// Fast indexed lookups
const tracksById = new Map(TRACKS.map(t => [t.id, t]));
const coursesById = new Map(COURSES.map(c => [c.id, c]));
const modulesById = new Map(MODULES.map(m => [m.id, m]));
const lessonsById = new Map(LESSONS.map(l => [l.id, l]));
const quizzesById = new Map(QUIZZES.map(q => [q.id, q]));
const labsById = new Map(LABS.map(lab => [lab.id, lab]));

function getTracks() {
  return TRACKS;
}

function getTrack(id) {
  const t = tracksById.get(id);
  if (!t) return null;
  return {
    ...t,
    courses: (t.courseIds || []).map(cId => getCourse(cId)).filter(Boolean)
  };
}

function getCourses() {
  return COURSES;
}

function getCourse(id) {
  const c = coursesById.get(id);
  if (!c) return null;
  return {
    ...c,
    quizId: c.quizId || `quiz-${c.id}`,
    modules: (c.moduleIds || []).map(mId => getModule(mId)).filter(Boolean)
  };
}

function getModules() {
  return MODULES;
}

function getModule(id) {
  const m = modulesById.get(id);
  if (!m) return null;
  return {
    ...m,
    lessons: (m.lessonIds || []).map(lId => getLesson(lId)).filter(Boolean)
  };
}

function formatLessonContent(lesson) {
  if (typeof lesson.content === 'string' && lesson.content.length > 0) {
    return lesson.content;
  }
  if (Array.isArray(lesson.sections)) {
    return lesson.sections.map(s => {
      let part = '';
      if (s.heading) part += `## ${s.heading}\n\n`;
      if (s.content && s.type !== 'callout' && s.type !== 'code' && s.type !== 'terminal-output') {
        part += `${s.content}\n\n`;
      }
      if (s.markdown) part += `${s.markdown}\n\n`;
      if (s.type === 'code') {
        if (s.title) part += `*${s.title}*\n\n`;
        part += `\`\`\`${s.language || s.lang || 'text'}\n${s.content || s.code || ''}\n\`\`\`\n\n`;
      }
      if (s.type === 'terminal-output') {
        if (s.title) part += `*${s.title}*\n\n`;
        part += `\`\`\`console\n${s.content || s.output || ''}\n\`\`\`\n\n`;
      }
      if (s.type === 'callout') {
        const tone = (s.tone || s.variant || 'NOTE').toUpperCase();
        const title = s.title ? `**${s.title}**: ` : '';
        part += `> [!${tone}] ${title}${s.content || s.text || ''}\n\n`;
      }
      if (s.type === 'worked-example' && Array.isArray(s.steps)) {
        part += s.steps.map(st => `### ${st.title || 'Step'}\n\n${st.content || ''}\n\n`).join('');
      }
      if (s.type === 'table' && Array.isArray(s.headers) && Array.isArray(s.rows)) {
        const headerLine = '| ' + s.headers.join(' | ') + ' |';
        const sepLine = '| ' + s.headers.map(() => '---').join(' | ') + ' |';
        const rowLines = s.rows.map(r => '| ' + r.join(' | ') + ' |').join('\n');
        part += `${headerLine}\n${sepLine}\n${rowLines}\n\n`;
      }
      return part;
    }).join('\n').trim();
  }
  return '';
}

function getLessonKnowledgeCheck(lesson) {
  if (lesson.knowledgeCheck) return lesson.knowledgeCheck;
  const secKc = (lesson.sections || []).find(s => s.type === 'knowledge-check');
  if (secKc) {
    return {
      question: secKc.question,
      options: secKc.options,
      correctIndex: secKc.correctIndex !== undefined ? secKc.correctIndex : 0,
      explanation: secKc.explanation || ''
    };
  }

  const obj = (lesson.objectives && lesson.objectives[0]) || 'core engineering principle';
  return {
    question: `Which statement best reflects the key principle: "${obj}"?`,
    options: [
      `It is an essential architectural standard providing predictable, verifiable infrastructure operations.`,
      `It can be bypassed safely in production without consequence or telemetry tracking.`,
      `It only applies to legacy unmanaged hardware from older vendor generations.`,
      `It is purely optional and replaced completely by consumer-grade unmanaged defaults.`
    ],
    correctIndex: 0,
    explanation: `Understanding "${obj}" is fundamental to engineering reliable, verifiable infrastructure systems.`
  };
}

function getLessons() {
  return LESSONS.map(l => ({
    ...l,
    content: formatLessonContent(l),
    knowledgeCheck: getLessonKnowledgeCheck(l)
  }));
}

function getLesson(id) {
  const l = lessonsById.get(id);
  if (!l) return null;
  return {
    ...l,
    content: formatLessonContent(l),
    knowledgeCheck: getLessonKnowledgeCheck(l)
  };
}

function getQuizzes() {
  return QUIZZES;
}

function getQuiz(id) {
  const q = quizzesById.get(id);
  if (!q) return null;
  return {
    ...q,
    passThreshold: q.passPercent !== undefined ? q.passPercent : (q.passThreshold !== undefined ? q.passThreshold : 75)
  };
}

function getLabs() {
  return LABS;
}

function getLab(id) {
  return labsById.get(id) || null;
}

/**
 * Full-text keyword search across courses, modules, and lessons
 */
function searchCatalog(query) {
  if (!query || typeof query !== 'string') return [];
  const q = query.trim().toLowerCase();
  if (q.length < 2) return [];

  const results = [];

  // Search courses
  for (const c of COURSES) {
    if (c.title.toLowerCase().includes(q) || c.description.toLowerCase().includes(q) || (c.subtitle && c.subtitle.toLowerCase().includes(q))) {
      results.push({
        type: 'course',
        id: c.id,
        trackId: c.trackId,
        title: c.title,
        description: c.subtitle || c.description,
        url: `#/learning/${c.trackId}/course/${c.id}`
      });
    }
  }

  // Search lessons
  for (const l of LESSONS) {
    const titleMatch = l.title.toLowerCase().includes(q);
    const objMatch = (l.objectives || []).some(o => o.toLowerCase().includes(q));
    const contentMatch = (l.sections || []).some(s => (s.content && s.content.toLowerCase().includes(q)) || (s.heading && s.heading.toLowerCase().includes(q)));

    if (titleMatch || objMatch || contentMatch) {
      results.push({
        type: 'lesson',
        id: l.id,
        courseId: l.courseId,
        trackId: l.trackId,
        title: l.title,
        description: (l.objectives && l.objectives[0]) || `Lesson in ${l.courseId}`,
        url: `#/learning/${l.trackId}/lesson/${l.id}`
      });
    }
  }

  // Search labs
  for (const lab of LABS) {
    if (lab.title.toLowerCase().includes(q) || lab.instructions.toLowerCase().includes(q)) {
      results.push({
        type: 'lab',
        id: lab.id,
        trackId: lab.trackId,
        title: lab.title,
        description: lab.instructions,
        url: `#/learning/${lab.trackId}/lab/${lab.id}`
      });
    }
  }

  return results.slice(0, 20);
}

/**
 * Strict curriculum verification: ensures no broken links, acyclic prerequisites,
 * valid quiz questions, and complete structural integrity.
 */
function validateCurriculum() {
  const errors = [];

  if (TRACKS.length !== 2) {
    errors.push(`Expected exactly 2 tracks, found ${TRACKS.length}`);
  }

  if (COURSES.length !== 8) {
    errors.push(`Expected exactly 8 courses, found ${COURSES.length}`);
  }

  if (MODULES.length !== 24) {
    errors.push(`Expected exactly 24 modules, found ${MODULES.length}`);
  }

  if (LESSONS.length !== 72) {
    errors.push(`Expected exactly 72 lessons, found ${LESSONS.length}`);
  }

  // Track integrity
  for (const t of TRACKS) {
    if (!t.courseIds || t.courseIds.length !== 4) {
      errors.push(`Track ${t.id} must reference exactly 4 courses, found ${t.courseIds ? t.courseIds.length : 0}`);
    }
    for (const cId of t.courseIds || []) {
      const c = coursesById.get(cId);
      if (!c) errors.push(`Track ${t.id} references missing course ${cId}`);
      else if (c.trackId !== t.id) errors.push(`Course ${cId} trackId mismatch: expected ${t.id}, got ${c.trackId}`);
    }
  }

  // Course integrity
  for (const c of COURSES) {
    if (!c.moduleIds || c.moduleIds.length !== 3) {
      errors.push(`Course ${c.id} must reference exactly 3 modules, found ${c.moduleIds ? c.moduleIds.length : 0}`);
    }
    for (const mId of c.moduleIds || []) {
      const m = modulesById.get(mId);
      if (!m) errors.push(`Course ${c.id} references missing module ${mId}`);
      else if (m.courseId !== c.id) errors.push(`Module ${mId} courseId mismatch: expected ${c.id}, got ${m.courseId}`);
    }
  }

  // Module integrity
  for (const m of MODULES) {
    if (!m.lessonIds || m.lessonIds.length !== 3) {
      errors.push(`Module ${m.id} must reference exactly 3 lessons, found ${m.lessonIds ? m.lessonIds.length : 0}`);
    }
    for (const lId of m.lessonIds || []) {
      const l = lessonsById.get(lId);
      if (!l) errors.push(`Module ${m.id} references missing lesson ${lId}`);
      else {
        if (l.moduleId !== m.id) errors.push(`Lesson ${lId} moduleId mismatch: expected ${m.id}, got ${l.moduleId}`);
        if (l.courseId !== m.courseId) errors.push(`Lesson ${lId} courseId mismatch: expected ${m.courseId}, got ${l.courseId}`);
      }
    }
  }

  // Lesson integrity
  const seenLessonIds = new Set();
  for (const l of LESSONS) {
    if (seenLessonIds.has(l.id)) {
      errors.push(`Duplicate lesson ID detected: ${l.id}`);
    }
    seenLessonIds.add(l.id);

    if (!l.objectives || l.objectives.length === 0) {
      errors.push(`Lesson ${l.id} has no learning objectives`);
    }
    if (!l.sections || l.sections.length === 0) {
      errors.push(`Lesson ${l.id} has no sections`);
    }
    if (l.quizId && !quizzesById.has(l.quizId)) {
      errors.push(`Lesson ${l.id} references non-existent quiz: ${l.quizId}`);
    }
    for (const labId of l.labIds || []) {
      if (!labsById.has(labId)) {
        errors.push(`Lesson ${l.id} references non-existent lab: ${labId}`);
      }
    }
    if (l.prevLessonId && !lessonsById.has(l.prevLessonId)) {
      errors.push(`Lesson ${l.id} has invalid prevLessonId: ${l.prevLessonId}`);
    }
    if (l.nextLessonId && !lessonsById.has(l.nextLessonId)) {
      errors.push(`Lesson ${l.id} has invalid nextLessonId: ${l.nextLessonId}`);
    }
  }

  // Prerequisite acyclicity
  for (const c of COURSES) {
    const inStack = new Set();
    const hasCycle = (currId) => {
      if (inStack.has(currId)) return true;
      inStack.add(currId);
      const currCourse = coursesById.get(currId);
      if (currCourse) {
        for (const p of currCourse.prerequisites || []) {
          if (hasCycle(p)) return true;
        }
      }
      inStack.delete(currId);
      return false;
    };
    if (hasCycle(c.id)) {
      errors.push(`Cycle detected in prerequisites for course ${c.id}`);
    }
  }

  // Quiz questions integrity
  for (const q of QUIZZES) {
    if (!coursesById.has(q.courseId)) {
      errors.push(`Quiz ${q.id} references non-existent course ${q.courseId}`);
    }
    for (const quest of q.questions || []) {
      if (quest.type === 'single_choice' || quest.type === 'multiple_select' || quest.type === 'true_false') {
        const optIds = new Set((quest.options || []).map(o => o.id));
        for (const cOpt of quest.correctOptionIds || []) {
          if (!optIds.has(cOpt)) {
            errors.push(`Question ${quest.id} in quiz ${q.id} has correct option ${cOpt} not found in options`);
          }
        }
      } else if (quest.type === 'short_answer') {
        if (!quest.correctAnswers || quest.correctAnswers.length === 0) {
          errors.push(`Short answer question ${quest.id} in quiz ${q.id} has no correctAnswers defined`);
        }
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

function getCatalog() {
  const tracks = getTracks();
  const courses = getCourses();
  const modules = getModules();
  const lessons = getLessons();
  const quizzes = getQuizzes();
  const labs = getLabs();

  return {
    tracks: tracks.map(t => getTrack(t.id)),
    courses: courses.map(c => getCourse(c.id)),
    modules,
    lessons,
    quizzes,
    labs,
    summary: {
      totalTracks: tracks.length,
      totalCourses: courses.length,
      totalModules: modules.length,
      totalLessons: lessons.length,
      totalQuizzes: quizzes.length,
      totalLabs: labs.length
    }
  };
}

module.exports = {
  TRACKS,
  COURSES,
  MODULES,
  LESSONS,
  QUIZZES,
  LABS,
  getCatalog,
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
  searchCatalog,
  validateCurriculum
};
