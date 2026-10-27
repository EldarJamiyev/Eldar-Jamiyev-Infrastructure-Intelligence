/**
 * EJII Learning Center — Master View Controller
 * Integrates router, store, API, and view dispatching into #main-content.
 */

'use strict';

(function() {
  window.EJIILearning = window.EJIILearning || {};

  async function renderLearningCenterView(targetContainer) {
    const container = targetContainer || document.getElementById('main-content');
    if (!container) return;

    const api = window.EJIILearning.Api;
    const store = window.EJIILearning.Store;
    const router = window.EJIILearning.Router;

    // Show initial elegant loading placeholder
    container.innerHTML = `
      <div class="ejii-learning-container" style="text-align: center; padding: 60px 20px;">
        <div style="font-size: 24px; color: var(--accent-primary); margin-bottom: 12px;">&#9881;</div>
        <div style="font-size: 16px; font-weight: 600; color: var(--text-primary);">Loading Sovereign Learning Center...</div>
        <div style="font-size: 12px; color: var(--text-muted); margin-top: 6px;">Synchronizing curriculum catalog and authenticated progress ledger</div>
      </div>
    `;

    try {
      // 1. Fetch catalog and progress in parallel
      const [catalogRes, progressRes] = await Promise.all([
        api.getCatalog().catch(() => ({ catalog: null })),
        api.getProgress().catch(() => ({ progress: null }))
      ]);

      const catalog = catalogRes.catalog || null;
      const progress = progressRes.progress || {
        lessonProgress: {},
        quizAttempts: [],
        stats: { totalLessons: 72, completedCount: 0, overallPercentage: 0 }
      };

      if (catalog) store.setCatalog(catalog);
      if (progress) store.setProgress(progress);

      // 2. Fetch bookmarks
      try {
        const bmRes = await api.getBookmarks();
        if (bmRes && bmRes.bookmarks) {
          store.setBookmarks(bmRes.bookmarks);
        }
      } catch (_) {}

      // 3. Dispatch route handler
      async function routeView(route) {
        const activeRoute = route || router.parseRoute(window.location.hash) || { view: 'hub' };

        if (activeRoute.view === 'hub') {
          window.EJIILearning.CatalogViews.renderHub(container, catalog, store.progress);
        } else if (activeRoute.view === 'track') {
          const track = (catalog.tracks || []).find(t => t.id === activeRoute.trackId);
          if (track) {
            window.EJIILearning.CatalogViews.renderTrack(container, track, store.progress);
          } else {
            window.EJIILearning.CatalogViews.renderHub(container, catalog, store.progress);
          }
        } else if (activeRoute.view === 'course') {
          try {
            const courseRes = await api.getCourse(activeRoute.courseId);
            window.EJIILearning.CourseView.renderCourse(container, courseRes.course, store.progress);
          } catch (err) {
            container.innerHTML = `<div class="ejii-learning-container"><p>Error loading course: ${err.message}</p></div>`;
          }
        } else if (activeRoute.view === 'lesson') {
          try {
            const lessonRes = await api.getLesson(activeRoute.lessonId);
            window.EJIILearning.LessonView.renderLesson(container, lessonRes);
          } catch (err) {
            container.innerHTML = `<div class="ejii-learning-container"><p>Error loading lesson: ${err.message}</p></div>`;
          }
        } else if (activeRoute.view === 'quiz') {
          try {
            const quizRes = await api.getQuiz(activeRoute.quizId);
            window.EJIILearning.QuizView.renderQuiz(container, quizRes);
          } catch (err) {
            container.innerHTML = `<div class="ejii-learning-container"><p>Error loading quiz: ${err.message}</p></div>`;
          }
        } else if (activeRoute.view === 'lab') {
          const labModule = window.EJIILearning.Labs && window.EJIILearning.Labs[activeRoute.labId];
          if (labModule && typeof labModule.render === 'function') {
            container.innerHTML = `
              <div class="ejii-learning-container">
                <div style="margin-bottom: 16px;">
                  <a href="#/learning" class="ejii-learning-btn ejii-learning-btn--secondary" style="font-size: 12px; padding: 4px 10px; min-height: 28px;">
                    &larr; Back to Learning Hub
                  </a>
                </div>
                <div id="activeLabMount"></div>
              </div>
            `;
            const labMount = container.querySelector('#activeLabMount');
            labModule.render(labMount);
          } else {
            container.innerHTML = `<div class="ejii-learning-container"><p>Educational lab '${activeRoute.labId}' is loading or not found.</p><a href="#/learning" class="ejii-learning-btn ejii-learning-btn--secondary">&larr; Back to Hub</a></div>`;
          }
        } else if (activeRoute.view === 'progress') {
          try {
            const [recsRes, bmRes] = await Promise.all([
              api.getRecommendations().catch(() => ({ recommendations: [] })),
              api.getBookmarks().catch(() => ({ bookmarks: [] }))
            ]);
            window.EJIILearning.ProgressView.renderProgress(container, {
              catalog,
              progress: store.progress,
              recommendations: recsRes.recommendations || [],
              bookmarks: bmRes.bookmarks || []
            });
          } catch (err) {
            container.innerHTML = `<div class="ejii-learning-container"><p>Error loading progress: ${err.message}</p></div>`;
          }
        } else if (activeRoute.view === 'flashcards') {
          window.EJIILearning.FlashcardsView.renderFlashcards(container);
        } else {
          window.EJIILearning.CatalogViews.renderHub(container, catalog, store.progress);
        }
      }

      // Initialize hash router
      router.init((newRoute) => {
        if (window.state && window.state.currentView === 'learning-center') {
          routeView(newRoute);
        }
      });

      // Render initial view
      routeView();

    } catch (err) {
      container.innerHTML = `
        <div class="ejii-learning-container" style="padding: 40px 20px; text-align: center;">
          <h2 style="color: var(--status-critical, #be123c);">Failed to Initialize Learning Center</h2>
          <p style="color: var(--text-secondary); margin-top: 8px;">${err.message}</p>
          <button onclick="window.renderLearningCenterView()" class="ejii-learning-btn ejii-learning-btn--primary" style="margin-top: 16px;">
            &#8635; Retry Connection
          </button>
        </div>
      `;
    }
  }

  window.renderLearningCenterView = renderLearningCenterView;
})();
