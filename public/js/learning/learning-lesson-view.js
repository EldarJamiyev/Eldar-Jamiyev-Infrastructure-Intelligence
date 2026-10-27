/**
 * EJII Learning Center — 2-Pane Lesson Reader View
 * Responsive 2-column reader with collapsible syllabus sidebar, rich markdown rendering,
 * inline knowledge checks, progress persistence, bookmarks, and private note taking.
 */

'use strict';

if (typeof window !== 'undefined') {
  window.EJIILearning = window.EJIILearning || {};
}

(function() {
  async function renderLesson(containerEl, lessonData) {
    if (!containerEl || !lessonData || !lessonData.lesson) return;

    const { lesson, course, navigation } = lessonData;
    const store = window.EJIILearning.Store;
    const api = window.EJIILearning.Api;
    const renderer = window.EJIILearning.Renderer;

    const isCompleted = store.isLessonCompleted(lesson.id);
    const isBookmarked = store.isBookmarked(lesson.id);

    // Fetch existing note for this lesson
    let existingNote = store.getNote(lesson.id);
    if (!existingNote && api) {
      try {
        const noteRes = await api.getNote(lesson.id);
        if (noteRes && noteRes.note) {
          existingNote = noteRes.note.note_text || '';
          store.setNote(lesson.id, existingNote);
        }
      } catch (_) {}
    }

    const breadcrumbs = [
      { label: 'Learning Center', href: '#/learning' },
      { label: course.title, href: `#/learning/course/${course.id}` },
      { label: lesson.title, href: `#/learning/lesson/${lesson.id}` }
    ];

    containerEl.innerHTML = `
      <div class="ejii-learning-container">
        ${renderer.renderBreadcrumbs(breadcrumbs)}

        <div class="ejii-learning-reader">
          <!-- Left Sidebar: Course Syllabus Outline -->
          <div class="ejii-learning-reader-sidebar">
            <div style="font-size: 11px; font-weight: 700; text-transform: uppercase; color: var(--text-muted); margin-bottom: 4px;">
              COURSE SYLLABUS
            </div>
            <a href="#/learning/course/${course.id}" style="font-size: 14px; font-weight: 700; color: var(--text-primary); text-decoration: none; display: block; margin-bottom: 16px;">
              ${course.title}
            </a>

            ${(course.modules || []).map(mod => `
              <div class="ejii-learning-tree-module">
                <div class="ejii-learning-tree-module-title">${mod.title}</div>
                ${mod.lessons.map(l => {
                  const active = l.id === lesson.id;
                  const done = store.isLessonCompleted(l.id);
                  return `
                    <a href="#/learning/lesson/${l.id}" class="ejii-learning-tree-lesson ${active ? 'ejii-learning-tree-lesson--active' : ''}">
                      <span style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; margin-right: 6px;">
                        ${l.title}
                      </span>
                      <span style="font-size: 11px; flex-shrink: 0;">${done ? '&#10003;' : ''}</span>
                    </a>
                  `;
                }).join('')}
              </div>
            `).join('')}

            <div style="margin-top: 16px; padding-top: 12px; border-top: 1px solid var(--border-subtle);">
              <a href="#/learning/quiz/${course.quizId}" class="ejii-learning-btn ejii-learning-btn--secondary" style="width: 100%; font-size: 12px; padding: 6px 10px; min-height: 32px;">
                &#9998; Course Final Quiz
              </a>
            </div>
          </div>

          <!-- Main Content Pane -->
          <div class="ejii-learning-reader-content">
            <!-- Lesson Header Row -->
            <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 12px; margin-bottom: 16px; border-bottom: 1px solid var(--border-subtle); padding-bottom: 14px;">
              <div>
                <span class="ejii-learning-badge ejii-learning-badge--accent" style="margin-bottom: 6px;">&sim;${lesson.estimatedMinutes} MIN READ</span>
                <h1 style="font-size: 24px; font-weight: 700; margin: 4px 0 0 0; color: var(--text-primary); letter-spacing: -0.02em;">
                  ${lesson.title}
                </h1>
              </div>

              <!-- Top Action Controls -->
              <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
                <button id="btnBookmark" class="ejii-learning-btn ejii-learning-btn--secondary" style="font-size: 12px; padding: 6px 12px; min-height: 32px;">
                  ${isBookmarked ? '&#9733; Bookmarked' : '&#9734; Bookmark'}
                </button>
                <button id="btnToggleComplete" class="ejii-learning-btn ${isCompleted ? 'ejii-learning-btn--secondary' : 'ejii-learning-btn--primary'}" style="font-size: 12px; padding: 6px 14px; min-height: 32px;">
                  ${isCompleted ? '&#10003; Completed' : 'Mark Completed'}
                </button>
              </div>
            </div>

            <!-- Learning Objectives Box -->
            ${lesson.objectives && lesson.objectives.length > 0 ? `
              <div class="ejii-learning-callout" style="margin-top: 0;">
                <div style="font-weight: 700; margin-bottom: 4px; color: var(--accent-primary);">&#9670; KEY LEARNING OBJECTIVES</div>
                <ul style="margin: 4px 0 0 16px; padding: 0;">
                  ${lesson.objectives.map(obj => `<li>${renderer.escapeHtml(obj)}</li>`).join('')}
                </ul>
              </div>
            ` : ''}

            <!-- Rendered Markdown Body -->
            <div class="ejii-learning-article">
              ${renderer.renderMarkdown(lesson.content)}
            </div>

            <!-- Inline Knowledge Check -->
            ${lesson.knowledgeCheck ? renderer.renderKnowledgeCheck(lesson.knowledgeCheck) : ''}

            <!-- Bottom Navigation Controls -->
            <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 36px; padding-top: 20px; border-top: 1px solid var(--border-subtle); flex-wrap: wrap; gap: 12px;">
              <div>
                ${navigation && navigation.prev ? `
                  <a href="#/learning/lesson/${navigation.prev.id}" class="ejii-learning-btn ejii-learning-btn--secondary">
                    &larr; Previous: ${navigation.prev.title}
                  </a>
                ` : `
                  <a href="#/learning/course/${course.id}" class="ejii-learning-btn ejii-learning-btn--secondary">
                    &larr; Course Syllabus
                  </a>
                `}
              </div>

              <div>
                ${navigation && navigation.next ? `
                  <a href="#/learning/lesson/${navigation.next.id}" class="ejii-learning-btn ejii-learning-btn--primary">
                    Next: ${navigation.next.title} &rarr;
                  </a>
                ` : `
                  <a href="#/learning/quiz/${course.quizId}" class="ejii-learning-btn ejii-learning-btn--primary">
                    Take Final Course Quiz &rarr;
                  </a>
                `}
              </div>
            </div>

            <!-- Personal Notes Editor -->
            <div class="ejii-learning-notes-panel">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <span style="font-weight: 700; font-size: 13px; color: var(--text-primary);">&#9998; Private Engineer's Study Notes</span>
                <span id="noteSaveStatus" style="font-size: 11px; color: var(--text-muted);">Saved to database</span>
              </div>
              <textarea id="lessonNoteInput" class="ejii-learning-textarea" placeholder="Type personal notes, commands, or takeaways for this lesson...">${existingNote}</textarea>
              <div style="display: flex; justify-content: flex-end; margin-top: 8px;">
                <button id="btnSaveNote" class="ejii-learning-btn ejii-learning-btn--secondary" style="font-size: 11px; padding: 4px 10px; min-height: 28px;">
                  Save Notes
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;

    // Event Wiring: Bookmark Toggle
    const btnBookmark = containerEl.querySelector('#btnBookmark');
    if (btnBookmark) {
      btnBookmark.addEventListener('click', async () => {
        store.toggleBookmark(lesson.id);
        const bookmarked = store.isBookmarked(lesson.id);
        btnBookmark.innerHTML = bookmarked ? '&#9733; Bookmarked' : '&#9734; Bookmark';
        if (api) {
          try { await api.toggleBookmark(lesson.id); } catch (_) {}
        }
      });
    }

    // Event Wiring: Mark Complete Toggle
    const btnComplete = containerEl.querySelector('#btnToggleComplete');
    if (btnComplete) {
      btnComplete.addEventListener('click', async () => {
        const currentlyDone = store.isLessonCompleted(lesson.id);
        const newStatus = currentlyDone ? 'in_progress' : 'completed';
        
        if (newStatus === 'completed') {
          store.setLessonCompleted(lesson.id);
          btnComplete.className = 'ejii-learning-btn ejii-learning-btn--secondary';
          btnComplete.innerHTML = '&#10003; Completed';
        } else {
          delete store.progress.lessonProgress[lesson.id];
          btnComplete.className = 'ejii-learning-btn ejii-learning-btn--primary';
          btnComplete.innerHTML = 'Mark Completed';
        }

        if (api) {
          try { await api.updateProgress(lesson.id, newStatus); } catch (_) {}
        }
      });
    }

    // Event Wiring: Inline Knowledge Check Interaction
    const kcBlock = containerEl.querySelector('#kc-block');
    if (kcBlock && lesson.knowledgeCheck) {
      const options = kcBlock.querySelectorAll('.ejii-learning-check-option');
      const feedback = kcBlock.querySelector('#kc-feedback');

      options.forEach(opt => {
        opt.addEventListener('click', () => {
          const isCorrect = opt.getAttribute('data-correct') === 'true';
          options.forEach(o => {
            o.style.pointerEvents = 'none';
            if (o.getAttribute('data-correct') === 'true') {
              o.className = 'ejii-learning-check-option ejii-learning-check-option--correct';
            }
          });

          if (!isCorrect) {
            opt.className = 'ejii-learning-check-option ejii-learning-check-option--incorrect';
          }

          feedback.style.display = 'block';
          feedback.innerHTML = `
            <div style="font-weight: 700; color: ${isCorrect ? 'var(--status-nominal)' : 'var(--status-critical)'}; margin-bottom: 4px;">
              ${isCorrect ? '&#10003; Correct!' : '&#10007; Incorrect.'}
            </div>
            <div style="color: var(--text-secondary); line-height: 1.4;">${renderer.escapeHtml(lesson.knowledgeCheck.explanation)}</div>
          `;
        });
      });
    }

    // Event Wiring: Note saving
    const noteInput = containerEl.querySelector('#lessonNoteInput');
    const noteStatus = containerEl.querySelector('#noteSaveStatus');
    const btnSaveNote = containerEl.querySelector('#btnSaveNote');

    let debounceTimer = null;
    async function saveNote() {
      if (!noteInput || !api) return;
      const text = noteInput.value;
      store.setNote(lesson.id, text);
      if (noteStatus) noteStatus.textContent = 'Saving...';
      try {
        await api.saveNote(lesson.id, text);
        if (noteStatus) noteStatus.textContent = 'Saved to database';
      } catch (err) {
        if (noteStatus) noteStatus.textContent = 'Save failed';
      }
    }

    if (btnSaveNote) {
      btnSaveNote.addEventListener('click', saveNote);
    }

    if (noteInput) {
      noteInput.addEventListener('input', () => {
        if (noteStatus) noteStatus.textContent = 'Unsaved changes...';
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(saveNote, 1500);
      });
    }
  }

  const LessonView = {
    renderLesson
  };

  if (typeof window !== 'undefined') {
    window.EJIILearning.LessonView = LessonView;
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = LessonView;
  }
})();
