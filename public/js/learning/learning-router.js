/**
 * EJII Learning Center — Client-Side Hash Router
 * Parses and handles deep links (#/learning/...) with history and popstate support.
 */

'use strict';

if (typeof window !== 'undefined') {
  window.EJIILearning = window.EJIILearning || {};
}

(function() {
  function parseRoute(hashString) {
    const raw = (hashString || '').trim().replace(/^#\/?/, '');
    if (!raw.startsWith('learning')) {
      return null;
    }

    const segments = raw.split('/').filter(Boolean); // e.g. ['learning', 'lesson', 'net-foundations-01']

    if (segments.length === 1) {
      return { view: 'hub' };
    }

    const first = segments[1];

    if (first === 'network' || first === 'system') {
      return { view: 'track', trackId: first };
    }

    if (first === 'track' && segments[2]) {
      return { view: 'track', trackId: segments[2] };
    }

    if (first === 'course' && segments[2]) {
      return { view: 'course', courseId: segments[2] };
    }

    if (first === 'lesson' && segments[2]) {
      return { view: 'lesson', lessonId: segments[2] };
    }

    if (first === 'quiz' && segments[2]) {
      return { view: 'quiz', quizId: segments[2] };
    }

    if (first === 'lab' && segments[2]) {
      return { view: 'lab', labId: segments[2] };
    }

    if (first === 'progress') {
      return { view: 'progress' };
    }

    if (first === 'flashcards') {
      return { view: 'flashcards' };
    }

    return { view: 'hub' };
  }

  function getRouteHref(route) {
    if (!route || !route.view) return '#/learning';
    switch (route.view) {
      case 'hub': return '#/learning';
      case 'track': return `#/learning/${route.trackId}`;
      case 'course': return `#/learning/course/${route.courseId}`;
      case 'lesson': return `#/learning/lesson/${route.lessonId}`;
      case 'quiz': return `#/learning/quiz/${route.quizId}`;
      case 'lab': return `#/learning/lab/${route.labId}`;
      case 'progress': return '#/learning/progress';
      case 'flashcards': return '#/learning/flashcards';
      default: return '#/learning';
    }
  }

  const Router = {
    parseRoute,
    getRouteHref,
    currentRoute: null,
    listeners: new Set(),

    init(onChange) {
      if (typeof onChange === 'function') {
        this.listeners.add(onChange);
      }

      if (typeof window !== 'undefined') {
        window.addEventListener('hashchange', () => {
          this.handleHashChange();
        });
      }
    },

    handleHashChange() {
      if (typeof window === 'undefined') return;
      const parsed = parseRoute(window.location.hash);
      if (parsed) {
        this.currentRoute = parsed;
        for (const cb of this.listeners) {
          try { cb(parsed); } catch (_) {}
        }
      }
    },

    navigate(href, replace = false) {
      if (typeof window === 'undefined') return;
      const cleanHref = href.startsWith('#') ? href : '#' + href;
      if (replace) {
        window.location.replace(cleanHref);
      } else {
        window.location.hash = cleanHref;
      }
    }
  };

  if (typeof window !== 'undefined') {
    window.EJIILearning.Router = Router;
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = Router;
  }
})();
