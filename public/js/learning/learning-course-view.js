/**
 * EJII Learning Center — Course Syllabus & Curriculum View
 * Displays course syllabus, module cards, lesson links, prerequisites, and quiz link.
 */

'use strict';

if (typeof window !== 'undefined') {
  window.EJIILearning = window.EJIILearning || {};
}

(function() {
  function renderCourse(containerEl, course, progress) {
    if (!containerEl || !course) return;

    const trackTitle = course.trackId === 'network' ? 'Network Academy' : 'System Administration Academy';
    const trackHref = `#/learning/${course.trackId}`;

    const breadcrumbs = [
      { label: 'Learning Center', href: '#/learning' },
      { label: trackTitle, href: trackHref },
      { label: course.title, href: `#/learning/course/${course.id}` }
    ];

    const store = window.EJIILearning.Store;

    containerEl.innerHTML = `
      <div class="ejii-learning-container">
        ${window.EJIILearning.Renderer.renderBreadcrumbs(breadcrumbs)}

        <!-- Course Header Card -->
        <div class="ejii-learning-hero" style="padding: 24px;">
          <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 12px;">
            <div>
              <span class="ejii-learning-badge ejii-learning-badge--accent" style="margin-bottom: 8px;">COURSE SYLLABUS</span>
              <h1 class="ejii-learning-hero-title">${course.title}</h1>
              <p class="ejii-learning-hero-subtitle">${course.description}</p>
            </div>
            <div style="display: flex; gap: 8px; flex-wrap: wrap;">
              <a href="#/learning/quiz/${course.quizId}" class="ejii-learning-btn ejii-learning-btn--primary">
                &#9998; Take Course Final Quiz
              </a>
            </div>
          </div>

          <div style="display: flex; gap: 16px; font-size: 13px; color: var(--text-secondary); margin-top: 12px; flex-wrap: wrap;">
            <span><strong>Difficulty:</strong> ${course.difficulty}</span>
            <span>&bull;</span>
            <span><strong>Duration:</strong> &sim;${course.estimatedHours} Hours</span>
            <span>&bull;</span>
            <span><strong>Modules:</strong> ${course.modules ? course.modules.length : 0}</span>
            <span>&bull;</span>
            <span><strong>Lessons:</strong> ${course.modules ? course.modules.reduce((acc, m) => acc + m.lessons.length, 0) : 0}</span>
          </div>

          ${course.prerequisites && course.prerequisites.length > 0 ? `
            <div style="margin-top: 14px; padding-top: 10px; border-top: 1px solid var(--border-subtle); font-size: 12px; color: var(--text-secondary);">
              <strong>Prerequisites:</strong> ${course.prerequisites.join(', ')}
            </div>
          ` : ''}
        </div>

        <!-- Modules & Lessons List -->
        <h2 style="font-size: 18px; font-weight: 700; margin: 28px 0 16px 0;">Curriculum Modules</h2>
        <div style="display: flex; flex-direction: column; gap: 20px;">
          ${(course.modules || []).map((mod, modIdx) => `
            <div style="background: var(--bg-surface); border: 1px solid var(--border-default); border-radius: 10px; padding: 20px;">
              <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; border-bottom: 1px solid var(--border-subtle); padding-bottom: 10px;">
                <div>
                  <span class="ejii-learning-badge" style="font-size: 11px;">Module ${modIdx + 1}</span>
                  <h3 style="font-size: 16px; font-weight: 700; margin: 4px 0 2px 0;">${mod.title}</h3>
                  <div style="font-size: 12px; color: var(--text-secondary);">${mod.description}</div>
                </div>
                <span style="font-size: 12px; color: var(--text-muted);">${mod.lessons.length} Lessons</span>
              </div>

              <!-- Lesson Items in Module -->
              <div style="display: flex; flex-direction: column; gap: 8px;">
                ${mod.lessons.map((lesson, lesIdx) => {
                  const isDone = store ? store.isLessonCompleted(lesson.id) : false;
                  return `
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px 14px; background: var(--bg-surface-subtle); border: 1px solid var(--border-subtle); border-radius: 6px; flex-wrap: wrap; gap: 8px;">
                      <div style="display: flex; align-items: center; gap: 10px;">
                        <span style="display: inline-flex; align-items: center; justify-content: center; width: 22px; height: 22px; border-radius: 50%; font-size: 11px; font-weight: 700; ${isDone ? 'background: #ecfdf5; color: #0d7a5f; border: 1px solid #10b981;' : 'background: var(--bg-surface); color: var(--text-muted); border: 1px solid var(--border-default);'}">
                          ${isDone ? '&#10003;' : (lesIdx + 1)}
                        </span>
                        <div>
                          <a href="#/learning/lesson/${lesson.id}" style="font-size: 13.5px; font-weight: 600; color: var(--text-primary); text-decoration: none;">
                            ${lesson.title}
                          </a>
                          <div style="font-size: 11.5px; color: var(--text-secondary);">&sim;${lesson.estimatedMinutes} mins</div>
                        </div>
                      </div>

                      <div style="display: flex; align-items: center; gap: 8px;">
                        ${isDone ? `<span class="ejii-learning-badge ejii-learning-badge--completed">Completed</span>` : ''}
                        <a href="#/learning/lesson/${lesson.id}" class="ejii-learning-btn ejii-learning-btn--secondary" style="font-size: 12px; padding: 4px 10px; min-height: 28px;">
                          ${isDone ? 'Review' : 'Start'} &rarr;
                        </a>
                      </div>
                    </div>
                  `;
                }).join('')}
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  const CourseView = {
    renderCourse
  };

  if (typeof window !== 'undefined') {
    window.EJIILearning.CourseView = CourseView;
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = CourseView;
  }
})();
