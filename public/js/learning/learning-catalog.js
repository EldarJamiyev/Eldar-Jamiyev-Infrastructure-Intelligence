/**
 * EJII Learning Center — Academy Hub & Track Catalog Views
 * High-density executive cards for tracks, courses, educational labs, and progress metrics.
 */

'use strict';

if (typeof window !== 'undefined') {
  window.EJIILearning = window.EJIILearning || {};
}

(function() {
  function renderHub(containerEl, catalog, progress) {
    if (!containerEl) return;
    const completedCount = (progress && progress.stats && progress.stats.completedCount) || 0;
    const totalLessons = (catalog && catalog.summary && catalog.summary.totalLessons) || (catalog && catalog.lessonCount) || 72;
    const percent = Math.round((completedCount / totalLessons) * 100);

    containerEl.innerHTML = `
      <div class="ejii-learning-container">
        <!-- Hero Banner -->
        <div class="ejii-learning-hero">
          <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 16px;">
            <div>
              <span class="ejii-learning-badge ejii-learning-badge--accent" style="margin-bottom: 8px;">SOVEREIGN ACADEMY EXPANSION</span>
              <h1 class="ejii-learning-hero-title">EJII Infrastructure Engineering Academy</h1>
              <p class="ejii-learning-hero-subtitle">
                Two exhaustive professional engineering academies covering the complete Cisco CCNA 200-301 blueprint and Enterprise Windows, Linux, and Cloud Systems Administration.
              </p>
            </div>
            <div style="min-width: 200px;">
              <div style="display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 4px;">
                <span style="font-weight: 600;">Overall Progress</span>
                <span style="color: var(--accent-primary); font-weight: 700;">${percent}%</span>
              </div>
              <div class="ejii-learning-progress-track">
                <div class="ejii-learning-progress-bar ${percent === 100 ? 'ejii-learning-progress-bar--completed' : ''}" style="width: ${percent}%;"></div>
              </div>
              <div style="font-size: 11px; color: var(--text-muted); text-align: right;">${completedCount} of ${totalLessons} lessons completed</div>
            </div>
          </div>

          <div class="ejii-learning-hero-stats">
            <div class="ejii-learning-stat-item">
              <span class="ejii-learning-stat-value">2</span>
              <span class="ejii-learning-stat-label">Specialist Academies</span>
            </div>
            <div class="ejii-learning-stat-item">
              <span class="ejii-learning-stat-value">8</span>
              <span class="ejii-learning-stat-label">Comprehensive Courses</span>
            </div>
            <div class="ejii-learning-stat-item">
              <span class="ejii-learning-stat-value">24</span>
              <span class="ejii-learning-stat-label">Curriculum Modules</span>
            </div>
            <div class="ejii-learning-stat-item">
              <span class="ejii-learning-stat-value">72</span>
              <span class="ejii-learning-stat-label">Substantive Lessons</span>
            </div>
            <div class="ejii-learning-stat-item">
              <span class="ejii-learning-stat-value">8</span>
              <span class="ejii-learning-stat-label">Simulated Labs</span>
            </div>
            <div class="ejii-learning-stat-item">
              <span class="ejii-learning-stat-value">8</span>
              <span class="ejii-learning-stat-label">Scored Course Quizzes</span>
            </div>
          </div>
        </div>

        <!-- Quick Links Toolbar -->
        <div style="display: flex; gap: 12px; margin-bottom: 24px; flex-wrap: wrap;">
          <a href="#/learning/network" class="ejii-learning-btn ejii-learning-btn--primary">Explore Network Academy</a>
          <a href="#/learning/system" class="ejii-learning-btn ejii-learning-btn--primary">Explore System Academy</a>
          <a href="#/learning/progress" class="ejii-learning-btn ejii-learning-btn--secondary">My Learning Records</a>
          <a href="#/learning/flashcards" class="ejii-learning-btn ejii-learning-btn--secondary">Revision Flashcards</a>
        </div>

        <!-- Academies (Tracks) Grid -->
        <h2 style="font-size: 18px; font-weight: 700; margin: 0 0 16px 0;">Available Learning Tracks</h2>
        <div class="ejii-learning-grid">
          ${((catalog && catalog.tracks) || []).map(track => {
            const isNet = track.id === 'network';
            const courses = track.courses || [];
            return `
              <div class="ejii-learning-card">
                <div class="ejii-learning-card-header">
                  <div>
                    <span class="ejii-learning-badge ejii-learning-badge--accent">${track.estimatedHours || 40} Hours</span>
                    <h3 class="ejii-learning-card-title" style="margin-top: 8px;">${track.title}</h3>
                  </div>
                </div>
                <p class="ejii-learning-card-desc">${track.description}</p>
                
                <div style="margin-bottom: 14px; font-size: 12px; color: var(--text-secondary);">
                  <strong>Syllabus Includes:</strong>
                  <ul style="margin: 6px 0 0 16px; padding: 0;">
                    ${courses.map(c => `<li>${c.title} (${c.lessonCount || (c.modules ? c.modules.reduce((a, m) => a + (m.lessons ? m.lessons.length : 0), 0) : 0)} lessons)</li>`).join('')}
                  </ul>
                </div>

                <div class="ejii-learning-card-footer">
                  <span style="font-size: 12px; color: var(--text-muted);">${courses.length} Courses &bull; 36 Lessons</span>
                  <a href="#/learning/${track.id}" class="ejii-learning-btn ejii-learning-btn--primary" style="font-size: 12px; padding: 6px 14px; min-height: 32px;">
                    Enter Track &rarr;
                  </a>
                </div>
              </div>
            `;
          }).join('')}
        </div>

        <!-- Simulated Educational Labs Grid -->
        <div style="margin-top: 24px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
            <div>
              <h2 style="font-size: 18px; font-weight: 700; margin: 0;">Interactive Educational Labs</h2>
              <p style="font-size: 12px; color: var(--text-secondary); margin: 4px 0 0 0;">
                Deterministic simulation environments for practicing subnetting, 802.1Q VLANs, routing, and administrative sandboxes.
              </p>
            </div>
            <span class="ejii-learning-badge ejii-learning-badge--accent">8 Zero-Risk Labs</span>
          </div>

          <div class="ejii-learning-grid" style="grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));">
            ${((catalog && catalog.labs) || []).map(lab => `
              <div class="ejii-learning-card" style="padding: 16px;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                  <span class="ejii-learning-badge" style="font-size: 10px;">${(lab.trackId || '').toUpperCase()}</span>
                  <span class="ejii-learning-badge ejii-learning-badge--warning" style="font-size: 10px;">${lab.difficulty || 'Intermediate'}</span>
                </div>
                <h4 style="font-size: 14px; font-weight: 700; margin: 0 0 6px 0; color: var(--text-primary);">${lab.title}</h4>
                <p style="font-size: 12px; color: var(--text-secondary); margin: 0 0 12px 0; line-height: 1.4;">${lab.instructions || ''}</p>
                <div style="margin-top: auto; display: flex; justify-content: space-between; align-items: center;">
                  <span style="font-size: 11px; color: var(--text-muted);">&sim;${lab.estimatedMinutes || 30} mins</span>
                  <a href="#/learning/lab/${lab.id}" class="ejii-learning-btn ejii-learning-btn--secondary" style="font-size: 11px; padding: 4px 10px; min-height: 28px;">
                    Launch Lab &#9658;
                  </a>
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
    `;
  }

  function renderTrack(containerEl, track, progress) {
    if (!containerEl || !track) return;
    const breadcrumbs = [
      { label: 'Learning Center', href: '#/learning' },
      { label: track.title, href: `#/learning/${track.id}` }
    ];

    containerEl.innerHTML = `
      <div class="ejii-learning-container">
        ${window.EJIILearning.Renderer.renderBreadcrumbs(breadcrumbs)}

        <!-- Track Header -->
        <div class="ejii-learning-hero" style="padding: 24px;">
          <span class="ejii-learning-badge ejii-learning-badge--accent" style="margin-bottom: 8px;">SPECIALIST ACADEMY TRACK</span>
          <h1 class="ejii-learning-hero-title">${track.title}</h1>
          <p class="ejii-learning-hero-subtitle">${track.description}</p>
          <div style="display: flex; gap: 16px; font-size: 13px; color: var(--text-secondary);">
            <span><strong>${track.courses.length}</strong> Courses</span>
            <span>&bull;</span>
            <span><strong>36</strong> Lessons</span>
            <span>&bull;</span>
            <span><strong>${track.estimatedHours}</strong> Estimated Study Hours</span>
          </div>
        </div>

        <!-- Courses in Track -->
        <h2 style="font-size: 18px; font-weight: 700; margin: 24px 0 16px 0;">Courses in this Track</h2>
        <div class="ejii-learning-grid">
          ${track.courses.map((course, idx) => {
            return `
              <div class="ejii-learning-card">
                <div class="ejii-learning-card-header">
                  <div>
                    <span class="ejii-learning-badge" style="margin-bottom: 6px;">Course ${idx + 1} of 4</span>
                    <h3 class="ejii-learning-card-title">${course.title}</h3>
                  </div>
                  <span class="ejii-learning-badge ejii-learning-badge--accent">${course.difficulty}</span>
                </div>
                <p class="ejii-learning-card-desc">${course.description}</p>

                <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 12px;">
                  <div><strong>Modules:</strong> ${course.modules ? course.modules.length : 3} &bull; <strong>Lessons:</strong> ${course.lessonCount || 9}</div>
                  <div style="margin-top: 4px; color: var(--text-muted);">&sim;${course.estimatedHours} Hours estimated</div>
                </div>

                <div class="ejii-learning-card-footer">
                  <a href="#/learning/course/${course.id}" class="ejii-learning-btn ejii-learning-btn--primary" style="font-size: 12px; padding: 6px 14px; min-height: 32px; width: 100%;">
                    View Curriculum &amp; Start &rarr;
                  </a>
                </div>
              </div>
            `;
          }).join('')}
        </div>
      </div>
    `;
  }

  const CatalogViews = {
    renderHub,
    renderTrack
  };

  if (typeof window !== 'undefined') {
    window.EJIILearning.CatalogViews = CatalogViews;
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = CatalogViews;
  }
})();
