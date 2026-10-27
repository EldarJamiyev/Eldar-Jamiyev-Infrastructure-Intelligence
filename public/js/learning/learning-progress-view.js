/**
 * EJII Learning Center — Personal Progress & Certification Dashboard
 * Displays verified user progress, course completion percentages, quiz scores,
 * bookmarked lessons, recent study notes, and curriculum recommendations.
 */

'use strict';

if (typeof window !== 'undefined') {
  window.EJIILearning = window.EJIILearning || {};
}

(function() {
  async function renderProgress(containerEl, data) {
    if (!containerEl) return;

    const { catalog, progress, recommendations, bookmarks } = data;
    const renderer = window.EJIILearning.Renderer;

    const stats = progress.stats || { totalLessons: 72, completedCount: 0, overallPercentage: 0 };
    const lessonProgress = progress.lessonProgress || {};
    const quizAttempts = progress.quizAttempts || [];

    const breadcrumbs = [
      { label: 'Learning Center', href: '#/learning' },
      { label: 'My Learning Records', href: '#/learning/progress' }
    ];

    containerEl.innerHTML = `
      <div class="ejii-learning-container">
        ${renderer.renderBreadcrumbs(breadcrumbs)}

        <!-- Overview Hero -->
        <div class="ejii-learning-hero" style="padding: 24px;">
          <span class="ejii-learning-badge ejii-learning-badge--accent" style="margin-bottom: 8px;">SOVEREIGN LEARNING RECORD</span>
          <h1 class="ejii-learning-hero-title">Engineering Progress &amp; Certification Metrics</h1>
          <p class="ejii-learning-hero-subtitle">
            Authenticated personal learning ledger stored securely in your private EJII database. All metrics reflect actual lesson completions and verified exam attempts.
          </p>

          <div class="ejii-learning-hero-stats">
            <div class="ejii-learning-stat-item">
              <span class="ejii-learning-stat-value">${stats.completedCount}</span>
              <span class="ejii-learning-stat-label">Completed Lessons</span>
            </div>
            <div class="ejii-learning-stat-item">
              <span class="ejii-learning-stat-value">${stats.overallPercentage}%</span>
              <span class="ejii-learning-stat-label">Overall Completion</span>
            </div>
            <div class="ejii-learning-stat-item">
              <span class="ejii-learning-stat-value">${quizAttempts.length}</span>
              <span class="ejii-learning-stat-label">Quiz Attempts</span>
            </div>
            <div class="ejii-learning-stat-item">
              <span class="ejii-learning-stat-value">${bookmarks ? bookmarks.length : 0}</span>
              <span class="ejii-learning-stat-label">Bookmarked Lessons</span>
            </div>
          </div>
        </div>

        <!-- Next Recommended Steps -->
        ${recommendations && recommendations.length > 0 ? `
          <div style="background: var(--bg-surface); border: 1px solid var(--border-default); border-radius: 10px; padding: 20px; margin-bottom: 28px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
              <h2 style="font-size: 16px; font-weight: 700; margin: 0; color: var(--text-primary);">&#9670; RECOMMENDED NEXT LESSONS</h2>
              <span class="ejii-learning-badge ejii-learning-badge--accent">Prerequisite-Aware</span>
            </div>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px;">
              ${recommendations.map(r => `
                <div style="background: var(--bg-surface-subtle); border: 1px solid var(--border-subtle); border-radius: 6px; padding: 12px; display: flex; justify-content: space-between; align-items: center;">
                  <div>
                    <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 600;">${r.courseTitle}</div>
                    <div style="font-size: 13.5px; font-weight: 600; color: var(--text-primary); margin: 2px 0;">${r.lessonTitle}</div>
                  </div>
                  <a href="#/learning/lesson/${r.lessonId}" class="ejii-learning-btn ejii-learning-btn--primary" style="font-size: 11px; padding: 4px 10px; min-height: 28px; white-space: nowrap;">
                    Resume &rarr;
                  </a>
                </div>
              `).join('')}
            </div>
          </div>
        ` : ''}

        <!-- Course-by-Course Completion Breakdown -->
        <h2 style="font-size: 18px; font-weight: 700; margin: 0 0 16px 0;">Course Mastery Matrix</h2>
        <div class="ejii-learning-grid" style="grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));">
          ${(catalog.tracks || []).flatMap(t => t.courses || []).map(course => {
            const courseLessons = course.modules ? course.modules.flatMap(m => m.lessons) : [];
            const cCompleted = courseLessons.filter(l => lessonProgress[l.id] && lessonProgress[l.id].status === 'completed').length;
            const cTotal = courseLessons.length || 9;
            const cPercent = Math.round((cCompleted / cTotal) * 100);

            // Check if user passed the quiz
            const passedQuiz = quizAttempts.some(a => a.quiz_id === course.quizId && a.passed);

            return `
              <div class="ejii-learning-card" style="padding: 18px;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                  <span class="ejii-learning-badge" style="font-size: 10px;">${course.trackId.toUpperCase()}</span>
                  ${passedQuiz ? `<span class="ejii-learning-badge ejii-learning-badge--completed">EXAM PASSED</span>` : ''}
                </div>
                <h4 style="font-size: 14.5px; font-weight: 700; margin: 0 0 6px 0; color: var(--text-primary);">${course.title}</h4>
                
                <div style="margin: 8px 0;">
                  <div style="display: flex; justify-content: space-between; font-size: 11px; color: var(--text-secondary); margin-bottom: 4px;">
                    <span>${cCompleted} / ${cTotal} Lessons</span>
                    <span style="font-weight: 700;">${cPercent}%</span>
                  </div>
                  <div class="ejii-learning-progress-track" style="margin: 0; height: 5px;">
                    <div class="ejii-learning-progress-bar ${cPercent === 100 ? 'ejii-learning-progress-bar--completed' : ''}" style="width: ${cPercent}%;"></div>
                  </div>
                </div>

                <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 12px; padding-top: 10px; border-top: 1px solid var(--border-subtle);">
                  <a href="#/learning/course/${course.id}" style="font-size: 12px; color: var(--accent-primary); text-decoration: none; font-weight: 600;">Syllabus</a>
                  <a href="#/learning/quiz/${course.quizId}" style="font-size: 12px; color: var(--text-secondary); text-decoration: none;">Final Quiz</a>
                </div>
              </div>
            `;
          }).join('')}
        </div>

        <!-- Bookmarks Section -->
        ${bookmarks && bookmarks.length > 0 ? `
          <div style="margin-top: 28px; background: var(--bg-surface); border: 1px solid var(--border-default); border-radius: 10px; padding: 20px;">
            <h2 style="font-size: 16px; font-weight: 700; margin: 0 0 12px 0;">Bookmarked Study Lessons</h2>
            <div style="display: flex; flex-direction: column; gap: 8px;">
              ${bookmarks.map(b => `
                <div style="display: flex; justify-content: space-between; align-items: center; padding: 8px 12px; background: var(--bg-surface-subtle); border-radius: 6px;">
                  <a href="#/learning/lesson/${b.lesson_id || b.lessonId}" style="font-size: 13.5px; font-weight: 600; color: var(--text-primary); text-decoration: none;">
                    &#9733; ${b.lesson_title || b.lesson_id || b.lessonId}
                  </a>
                  <a href="#/learning/lesson/${b.lesson_id || b.lessonId}" class="ejii-learning-btn ejii-learning-btn--secondary" style="font-size: 11px; padding: 2px 8px; min-height: 26px;">
                    Open Lesson &rarr;
                  </a>
                </div>
              `).join('')}
            </div>
          </div>
        ` : ''}
      </div>
    `;
  }

  const ProgressView = {
    renderProgress
  };

  if (typeof window !== 'undefined') {
    window.EJIILearning.ProgressView = ProgressView;
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = ProgressView;
  }
})();
