/**
 * EJII Learning Center — Interactive Quiz Taker & Server Scored Review
 * Handles single-choice, multiple-select, true/false, and short-answer questions.
 * Submits attempts to /api/learning/quizzes/:quizId/attempts for authoritative server-side scoring.
 */

'use strict';

if (typeof window !== 'undefined') {
  window.EJIILearning = window.EJIILearning || {};
}

(function() {
  async function renderQuiz(containerEl, quizData) {
    if (!containerEl || !quizData || !quizData.quiz) return;

    const { quiz, recentAttempts } = quizData;
    const api = window.EJIILearning.Api;
    const renderer = window.EJIILearning.Renderer;

    const breadcrumbs = [
      { label: 'Learning Center', href: '#/learning' },
      { label: quiz.title, href: `#/learning/quiz/${quiz.id}` }
    ];

    let userAnswers = {};
    let submissionResult = null;
    let isSubmitting = false;

    function renderUI() {
      containerEl.innerHTML = `
        <div class="ejii-learning-container">
          ${renderer.renderBreadcrumbs(breadcrumbs)}

          <!-- Quiz Title Banner -->
          <div class="ejii-learning-hero" style="padding: 24px;">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 12px;">
              <div>
                <span class="ejii-learning-badge ejii-learning-badge--accent" style="margin-bottom: 8px;">COURSE COMPREHENSIVE EXAM</span>
                <h1 class="ejii-learning-hero-title">${quiz.title}</h1>
                <p class="ejii-learning-hero-subtitle">${quiz.description}</p>
              </div>
              <div style="text-align: right;">
                <div style="font-size: 13px; color: var(--text-secondary);">Pass Threshold</div>
                <div style="font-size: 24px; font-weight: 700; color: var(--accent-primary);">${quiz.passThreshold}%</div>
              </div>
            </div>

            <div style="display: flex; gap: 16px; font-size: 13px; color: var(--text-secondary); margin-top: 12px; flex-wrap: wrap;">
              <span><strong>${quiz.questions.length}</strong> Questions</span>
              <span>&bull;</span>
              <span><strong>Server-Evaluated:</strong> Immediate Objective Scoring</span>
              <span>&bull;</span>
              <span><strong>Unlimited Retakes:</strong> Mastery Learning Model</span>
            </div>
          </div>

          <!-- Submission Result Banner (if submitted) -->
          ${submissionResult ? `
            <div style="background: ${submissionResult.passed ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.12)'}; border: 1px solid ${submissionResult.passed ? '#10b981' : '#ef4444'}; border-radius: 10px; padding: 24px; margin-bottom: 24px;">
              <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
                <div>
                  <span class="ejii-learning-badge ${submissionResult.passed ? 'ejii-learning-badge--completed' : 'ejii-learning-badge--danger'}" style="font-size: 12px; margin-bottom: 6px;">
                    ${submissionResult.passed ? '&#10003; PASSED' : '&#10007; NOT PASSED'}
                  </span>
                  <h2 style="font-size: 22px; font-weight: 700; margin: 4px 0 2px 0; color: var(--text-primary);">
                    Score: ${submissionResult.scorePercentage}% (${submissionResult.correctCount} of ${submissionResult.totalQuestions} correct)
                  </h2>
                  <div style="font-size: 13px; color: var(--text-secondary);">
                    ${submissionResult.passed ?
                      'Congratulations! You have demonstrated verified mastery of this course blueprint.' :
                      `A minimum score of ${submissionResult.passThreshold}% is required to pass. Review the detailed explanations below and retake when ready.`}
                  </div>
                </div>

                <button id="btnRetakeQuiz" class="ejii-learning-btn ejii-learning-btn--primary">
                  &#8635; Retake Exam
                </button>
              </div>
            </div>
          ` : ''}

          <!-- Questions List -->
          <div style="display: flex; flex-direction: column; gap: 20px;">
            ${quiz.questions.map((q, idx) => {
              const reviewItem = submissionResult && submissionResult.review ? submissionResult.review.find(r => r.questionId === q.id) : null;
              const isCorrect = reviewItem ? reviewItem.isCorrect : null;

              return `
                <div class="ejii-learning-card" style="${reviewItem ? (isCorrect ? 'border-left: 4px solid #10b981;' : 'border-left: 4px solid #ef4444;') : ''}">
                  <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px;">
                    <div style="display: flex; align-items: center; gap: 8px;">
                      <span class="ejii-learning-badge" style="font-weight: 700;">Question ${idx + 1}</span>
                      <span class="ejii-learning-badge" style="font-size: 10px;">${q.type.replace('_', ' ').toUpperCase()}</span>
                    </div>
                    ${reviewItem ? `
                      <span class="ejii-learning-badge ${isCorrect ? 'ejii-learning-badge--completed' : 'ejii-learning-badge--danger'}">
                        ${isCorrect ? '&#10003; Correct' : '&#10007; Incorrect'}
                      </span>
                    ` : ''}
                  </div>

                  <div style="font-size: 14.5px; font-weight: 600; color: var(--text-primary); margin-bottom: 14px; line-height: 1.5;">
                    ${renderer.escapeHtml(q.prompt)}
                  </div>

                  <!-- Options based on question type -->
                  ${q.type === 'single_choice' || q.type === 'true_false' ? `
                    <div style="display: flex; flex-direction: column; gap: 8px;">
                      ${q.options.map((opt, optIdx) => `
                        <label style="display: flex; gap: 10px; align-items: flex-start; cursor: pointer; padding: 10px 14px; border-radius: 6px; background: var(--bg-surface-subtle); border: 1px solid var(--border-default);">
                          <input type="radio" name="q_${q.id}" value="${optIdx}" ${userAnswers[q.id] === optIdx ? 'checked' : ''} ${submissionResult ? 'disabled' : ''} style="margin-top: 3px;">
                          <span style="font-size: 13.5px; color: var(--text-primary);">${renderer.escapeHtml(opt)}</span>
                        </label>
                      `).join('')}
                    </div>
                  ` : ''}

                  ${q.type === 'multiple_select' ? `
                    <div style="font-size: 11px; color: var(--text-muted); margin-bottom: 8px;">(Select all options that apply)</div>
                    <div style="display: flex; flex-direction: column; gap: 8px;">
                      ${q.options.map((opt, optIdx) => {
                        const checked = Array.isArray(userAnswers[q.id]) && userAnswers[q.id].includes(optIdx);
                        return `
                          <label style="display: flex; gap: 10px; align-items: flex-start; cursor: pointer; padding: 10px 14px; border-radius: 6px; background: var(--bg-surface-subtle); border: 1px solid var(--border-default);">
                            <input type="checkbox" name="q_${q.id}" value="${optIdx}" ${checked ? 'checked' : ''} ${submissionResult ? 'disabled' : ''} style="margin-top: 3px;">
                            <span style="font-size: 13.5px; color: var(--text-primary);">${renderer.escapeHtml(opt)}</span>
                          </label>
                        `;
                      }).join('')}
                    </div>
                  ` : ''}

                  ${q.type === 'short_answer' ? `
                    <div style="margin-top: 6px;">
                      <input type="text" id="input_${q.id}" class="ejii-learning-input" value="${userAnswers[q.id] || ''}" ${submissionResult ? 'disabled' : ''} placeholder="Type exact answer (case-insensitive)..." style="width: 100%; max-width: 400px; font-family: monospace;">
                    </div>
                  ` : ''}

                  <!-- Review Breakdown & Explanation -->
                  ${reviewItem ? `
                    <div style="background: rgba(255,255,255,0.03); border-top: 1px solid var(--border-subtle); margin-top: 14px; padding-top: 12px; font-size: 12.5px; line-height: 1.5;">
                      <div style="font-weight: 600; color: var(--text-primary); margin-bottom: 4px;">
                        Explanation:
                      </div>
                      <div style="color: var(--text-secondary); margin-bottom: 6px;">
                        ${renderer.escapeHtml(reviewItem.explanation)}
                      </div>
                      ${!isCorrect ? `
                        <div style="color: var(--status-nominal); font-weight: 600; font-family: monospace; font-size: 12px;">
                          Accepted Solution: ${Array.isArray(reviewItem.correctAnswer) ? reviewItem.correctAnswer.join(', ') : reviewItem.correctAnswer}
                        </div>
                      ` : ''}
                    </div>
                  ` : ''}
                </div>
              `;
            }).join('')}
          </div>

          <!-- Bottom Submit Row -->
          ${!submissionResult ? `
            <div style="display: flex; justify-content: flex-end; margin-top: 28px; padding-top: 16px; border-top: 1px solid var(--border-subtle);">
              <button id="btnSubmitQuiz" class="ejii-learning-btn ejii-learning-btn--primary" ${isSubmitting ? 'disabled' : ''} style="font-size: 14px; padding: 10px 24px; min-height: 42px;">
                ${isSubmitting ? 'Evaluating Submission...' : 'Submit Exam for Verification &rarr;'}
              </button>
            </div>
          ` : ''}
        </div>
      `;

      // Wire Inputs
      quiz.questions.forEach(q => {
        if (q.type === 'single_choice' || q.type === 'true_false') {
          containerEl.querySelectorAll(`input[name="q_${q.id}"]`).forEach(radio => {
            radio.addEventListener('change', (e) => {
              userAnswers[q.id] = Number(e.target.value);
            });
          });
        } else if (q.type === 'multiple_select') {
          containerEl.querySelectorAll(`input[name="q_${q.id}"]`).forEach(box => {
            box.addEventListener('change', () => {
              const checked = [];
              containerEl.querySelectorAll(`input[name="q_${q.id}"]:checked`).forEach(c => {
                checked.push(Number(c.value));
              });
              userAnswers[q.id] = checked;
            });
          });
        } else if (q.type === 'short_answer') {
          const input = containerEl.querySelector(`#input_${q.id}`);
          if (input) {
            input.addEventListener('input', (e) => {
              userAnswers[q.id] = e.target.value.trim();
            });
          }
        }
      });

      // Submit Button
      const btnSubmit = containerEl.querySelector('#btnSubmitQuiz');
      if (btnSubmit) {
        btnSubmit.addEventListener('click', async () => {
          isSubmitting = true;
          renderUI();

          try {
            const res = await api.submitQuizAttempt(quiz.id, userAnswers);
            submissionResult = res.result;
            isSubmitting = false;
            renderUI();
            window.scrollTo({ top: 0, behavior: 'smooth' });
          } catch (err) {
            alert('Failed to submit exam: ' + err.message);
            isSubmitting = false;
            renderUI();
          }
        });
      }

      // Retake Button
      const btnRetake = containerEl.querySelector('#btnRetakeQuiz');
      if (btnRetake) {
        btnRetake.addEventListener('click', () => {
          userAnswers = {};
          submissionResult = null;
          renderUI();
          window.scrollTo({ top: 0, behavior: 'smooth' });
        });
      }
    }

    renderUI();
  }

  const QuizView = {
    renderQuiz
  };

  if (typeof window !== 'undefined') {
    window.EJIILearning.QuizView = QuizView;
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = QuizView;
  }
})();
