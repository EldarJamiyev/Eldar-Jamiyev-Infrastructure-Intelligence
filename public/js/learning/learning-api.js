/**
 * EJII Learning Center — API Client
 * Wraps communication with /api/learning endpoints, supporting token authentication and offline fallback.
 */

'use strict';

if (typeof window !== 'undefined') {
  window.EJIILearning = window.EJIILearning || {};
}

(function() {
  async function request(endpoint, options = {}) {
    if (typeof window !== 'undefined' && typeof window.api === 'function') {
      return window.api(`/learning${endpoint}`, options);
    }

    const headers = {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    };

    const token = (typeof window !== 'undefined' && window.state && window.state.token) ||
                  (typeof localStorage !== 'undefined' && localStorage.getItem('ejii_token'));
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const url = `/api/learning${endpoint}`;
    const res = await fetch(url, {
      ...options,
      headers
    });

    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(data.error || `HTTP ${res.status}: ${res.statusText}`);
    }
    return data;
  }

  const LearningApi = {
    async getCatalog() {
      return request('/catalog');
    },

    async getTrack(trackId) {
      return request(`/tracks/${encodeURIComponent(trackId)}`);
    },

    async getCourse(courseId) {
      return request(`/courses/${encodeURIComponent(courseId)}`);
    },

    async getLesson(lessonId) {
      return request(`/lessons/${encodeURIComponent(lessonId)}`);
    },

    async getProgress() {
      return request('/progress');
    },

    async updateProgress(lessonId, status) {
      return request('/progress', {
        method: 'POST',
        body: JSON.stringify({ lessonId, status })
      });
    },

    async getBookmarks() {
      return request('/bookmarks');
    },

    async toggleBookmark(lessonId) {
      return request('/bookmarks', {
        method: 'POST',
        body: JSON.stringify({ lessonId })
      });
    },

    async getNote(lessonId) {
      return request(`/notes/${encodeURIComponent(lessonId)}`);
    },

    async saveNote(lessonId, note) {
      return request(`/notes/${encodeURIComponent(lessonId)}`, {
        method: 'PUT',
        body: JSON.stringify({ note })
      });
    },

    async getQuiz(quizId) {
      return request(`/quizzes/${encodeURIComponent(quizId)}`);
    },

    async submitQuizAttempt(quizId, answers) {
      return request(`/quizzes/${encodeURIComponent(quizId)}/attempts`, {
        method: 'POST',
        body: JSON.stringify({ answers })
      });
    },

    async getRecommendations() {
      return request('/recommendations');
    },

    async search(query) {
      return request(`/search?q=${encodeURIComponent(query)}`);
    }
  };

  if (typeof window !== 'undefined') {
    window.EJIILearning.Api = LearningApi;
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = LearningApi;
  }
})();
