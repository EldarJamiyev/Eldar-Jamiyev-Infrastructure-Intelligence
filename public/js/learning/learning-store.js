/**
 * EJII Learning Center — Reactive UI Store
 * Holds cached catalog, user progress, bookmarks, and active navigation state.
 */

'use strict';

if (typeof window !== 'undefined') {
  window.EJIILearning = window.EJIILearning || {};
}

(function() {
  const store = {
    catalog: null,
    progress: {
      lessonProgress: {},
      quizAttempts: [],
      stats: { totalLessons: 72, completedCount: 0, overallPercentage: 0 }
    },
    bookmarks: new Set(),
    notes: {},
    currentRoute: null,
    subscribers: new Set(),

    subscribe(callback) {
      if (typeof callback === 'function') {
        this.subscribers.add(callback);
        return () => this.subscribers.delete(callback);
      }
      return () => {};
    },

    notify() {
      for (const cb of this.subscribers) {
        try { cb(this); } catch (_) {}
      }
    },

    setCatalog(cat) {
      this.catalog = cat;
      this.notify();
    },

    setProgress(prog) {
      this.progress = prog || this.progress;
      this.notify();
    },

    setLessonCompleted(lessonId) {
      if (!this.progress.lessonProgress) this.progress.lessonProgress = {};
      this.progress.lessonProgress[lessonId] = { status: 'completed', completedAt: new Date().toISOString() };
      
      const completed = Object.values(this.progress.lessonProgress).filter(p => p.status === 'completed').length;
      const total = (this.catalog && this.catalog.summary && this.catalog.summary.totalLessons) || 72;
      this.progress.stats = {
        totalLessons: total,
        completedCount: completed,
        overallPercentage: Math.round((completed / total) * 100)
      };
      this.notify();
    },

    isLessonCompleted(lessonId) {
      return Boolean(this.progress &&
                     this.progress.lessonProgress &&
                     this.progress.lessonProgress[lessonId] &&
                     this.progress.lessonProgress[lessonId].status === 'completed');
    },

    setBookmarks(bookmarksList) {
      this.bookmarks = new Set((bookmarksList || []).map(b => (typeof b === 'string' ? b : b.lesson_id || b.lessonId)));
      this.notify();
    },

    toggleBookmark(lessonId) {
      if (this.bookmarks.has(lessonId)) {
        this.bookmarks.delete(lessonId);
      } else {
        this.bookmarks.add(lessonId);
      }
      this.notify();
    },

    isBookmarked(lessonId) {
      return this.bookmarks.has(lessonId);
    },

    setNote(lessonId, noteText) {
      this.notes[lessonId] = noteText;
      this.notify();
    },

    getNote(lessonId) {
      return this.notes[lessonId] || '';
    }
  };

  if (typeof window !== 'undefined') {
    window.EJIILearning.Store = store;
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = store;
  }
})();
