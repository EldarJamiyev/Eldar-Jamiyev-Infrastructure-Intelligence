/**
 * EJII Learning Center — Master View Controller
 * Integrates router, store, API, and view dispatching into #main-content.
 */

'use strict';

(function() {
  window.EJIILearning = window.EJIILearning || {};

  async function renderLearningCenterView(targetContainer) {
    const container = targetContainer || document.getElementById('mainContent') || document.getElementById('main-content');
    if (!container) return;

    const api = window.EJIILearning.Api;
    const store = window.EJIILearning.Store;
    const router = window.EJIILearning.Router;

    // Show initial elegant loading placeholder only on first load
    if (!store.catalog) {
      container.innerHTML = `
        <div class="ejii-learning-container" style="text-align: center; padding: 60px 20px;">
          <div style="font-size: 24px; color: var(--accent-primary); margin-bottom: 12px;">&#9881;</div>
          <div style="font-size: 16px; font-weight: 600; color: var(--text-primary);">Loading Sovereign Learning Center...</div>
          <div style="font-size: 12px; color: var(--text-muted); margin-top: 6px;">Synchronizing curriculum catalog and authenticated progress ledger</div>
        </div>
      `;
    }

    try {
      // 1. Fetch catalog and progress in parallel
      const [catalogRes, progressRes] = await Promise.all([
        api.getCatalog().catch(() => ({ catalog: null })),
        api.getProgress().catch(() => ({ progress: null }))
      ]);

      const catalog = (catalogRes && (catalogRes.catalog || (catalogRes.tracks ? catalogRes : null))) || null;
      const progress = (progressRes && (progressRes.progress || progressRes.dashboard)) || {
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
          if (!catalog) {
            container.innerHTML = `
              <div class="ejii-learning-container" style="text-align: center; padding: 60px 20px;">
                <h3 style="color: var(--text-primary); margin-bottom: 8px;">Learning Curriculum Offline or Initializing</h3>
                <p style="color: var(--text-secondary); margin-bottom: 16px;">The curriculum catalog is currently synchronizing with the EJII backend engine.</p>
                <button onclick="window.renderLearningCenterView()" class="ejii-learning-btn ejii-learning-btn--primary">Retry Connection</button>
              </div>
            `;
            return;
          }
          window.EJIILearning.CatalogViews.renderHub(container, catalog, store.progress);
        } else if (activeRoute.view === 'track') {
          const track = ((catalog && catalog.tracks) || []).find(t => t.id === activeRoute.trackId || t.slug === activeRoute.trackId || (activeRoute.trackId && activeRoute.trackId.startsWith(t.id)));
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
          if (!activeRoute.quizId || activeRoute.quizId === 'undefined' || activeRoute.quizId === 'null') {
            window.location.hash = '#/learning';
            return;
          }
          try {
            const quizRes = await api.getQuiz(activeRoute.quizId);
            window.EJIILearning.QuizView.renderQuiz(container, quizRes);
          } catch (err) {
            container.innerHTML = `
              <div class="ejii-learning-container" style="padding: 24px;">
                <p style="color: var(--status-error); margin-bottom: 12px;">Error loading quiz: ${err.message}</p>
                <a href="#/learning" class="ejii-learning-btn ejii-learning-btn--secondary">&larr; Return to Learning Hub</a>
              </div>
            `;
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

        mountSocraticMentorBanner(container, activeRoute);
      }

      function mountSocraticMentorBanner(rootEl, activeRoute) {
        if (!rootEl || rootEl.querySelector('#ejiiSocraticMentorBar')) return;
        const bar = document.createElement('div');
        bar.id = 'ejiiSocraticMentorBar';
        bar.style.cssText = 'margin-bottom:14px;padding:12px 16px;border-radius:10px;background:var(--bg-surface,#ffffff);border:1px solid var(--border-default,#e2e8f0);box-shadow:var(--shadow-sm);';
        const labOrTopic = activeRoute?.labId || activeRoute?.courseId || activeRoute?.lessonId || 'packet-dissection';
        bar.innerHTML = `
          <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;">
            <div style="flex:1;min-width:260px;">
              <div style="font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:0.06em;color:var(--accent-primary,#1d4ed8);">
                🎓 Adaptive AI Socratic Tutor &amp; Live-Telemetry Lab Mentor
              </div>
              <div style="font-size:12.5px;color:var(--text-secondary);margin-top:2px;">
                Ask the AI Mentor for a guiding Socratic question, first-principles explanation, or progressive hint tied to live EJII telemetry.
              </div>
            </div>
            <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
              <input type="text" id="ejiiSocraticQuestionInput" class="form-input" placeholder="Ask Socratic Mentor (e.g., Why does TCP RST happen?)..." style="font-size:12px;padding:5px 10px;min-width:240px;" />
              <button type="button" class="btn btn-primary" style="font-size:11.5px;padding:5px 12px;font-weight:700;" onclick="window.askEjiiSocraticMentor('${String(labOrTopic).replace(/'/g, '')}')">
                🧠 Ask Socratic Tutor
              </button>
            </div>
          </div>
          <div id="ejiiSocraticMentorResponse" style="display:none;margin-top:10px;padding:10px 12px;border-radius:8px;background:var(--bg-surface-subtle,#f8fafc);border-left:3px solid var(--accent-primary,#1d4ed8);font-size:12px;line-height:1.5;"></div>
        `;
        rootEl.insertBefore(bar, rootEl.firstChild);
      }

      window.askEjiiSocraticMentor = async function(labIdOrTopic) {
        const inputEl = document.getElementById('ejiiSocraticQuestionInput');
        const outEl = document.getElementById('ejiiSocraticMentorResponse');
        if (!outEl) return;
        const q = (inputEl && inputEl.value ? inputEl.value.trim() : '') || 'Give me a Socratic hint for this topic';
        outEl.style.display = 'block';
        outEl.innerHTML = `<strong>AI Socratic Mentor:</strong> Synthesizing guiding question and conceptual insight...`;
        try {
          const res = await window.api('/api/enterprise/socratic-mentor', {
            method: 'POST',
            body: JSON.stringify({
              labId: labIdOrTopic || 'packet-dissection',
              commandOrAnswer: q,
              userAction: q,
              question: q
            })
          });
          const m = res?.mentorResponse || res || {};
          const esc = window.escapeHtml || ((s) => String(s ?? ''));
          outEl.innerHTML = `
            <div style="font-weight:700;color:var(--text-primary);margin-bottom:4px;">🤔 Socratic Guiding Question: ${esc(m.socraticQuestion || '')}</div>
            <div style="color:var(--text-secondary);margin-bottom:4px;"><strong>First-Principles Insight:</strong> ${esc(m.conceptualInsight || '')}</div>
            <div style="font-family:var(--font-mono);font-size:11px;color:var(--accent-primary);">💡 Progressive Hint: ${esc(m.progressiveHint || '')} &bull; Suggested Probe: <code>${esc(m.suggestedNextCommand || '')}</code></div>
          `;
        } catch (err) {
          outEl.innerHTML = `<span style="color:var(--status-critical,#dc2626);">Mentor notice: ${err.message}</span>`;
        }
      };

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
