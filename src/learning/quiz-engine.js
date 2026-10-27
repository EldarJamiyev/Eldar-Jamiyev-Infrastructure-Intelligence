/**
 * EJII Learning Center — Server-Side Quiz Scoring Engine
 * Evaluates submissions, verifies answer correctness, enforces passing criteria,
 * and shields correct answers from clients prior to submission.
 */

'use strict';

/**
 * Sanitizes a quiz definition for safe client consumption (strips answer keys).
 */
function prepareQuizForClient(quiz) {
  if (!quiz) return null;
  return {
    id: quiz.id,
    courseId: quiz.courseId,
    title: quiz.title,
    passPercent: quiz.passPercent,
    questionCount: (quiz.questions || []).length,
    questions: (quiz.questions || []).map(q => ({
      id: q.id,
      type: q.type,
      prompt: q.prompt,
      points: q.points || 1,
      options: (q.options || []).map(opt => ({
        id: opt.id,
        text: opt.text
      }))
    }))
  };
}

function resolveOptionId(userAns, question) {
  if (userAns === null || userAns === undefined) return null;
  if (typeof userAns === 'number' && question.options && question.options[userAns]) {
    return question.options[userAns].id;
  }
  if (typeof userAns === 'string') {
    const trimmed = userAns.trim();
    if (question.options && question.options.some(o => o.id === trimmed)) {
      return trimmed;
    }
    const num = Number(trimmed);
    if (!isNaN(num) && question.options && question.options[num]) {
      return question.options[num].id;
    }
    return trimmed;
  }
  return String(userAns).trim();
}

/**
 * Evaluates a user submission against the server-side quiz definition.
 */
function scoreQuizAttempt(quiz, submission) {
  if (!quiz || !quiz.questions) {
    throw new Error('Invalid quiz definition');
  }

  const userAnswers = (submission && submission.answers) ? submission.answers : (submission || {});
  let earnedScore = 0;
  let maxScore = 0;
  const review = [];

  for (const question of quiz.questions) {
    const qPoints = question.points || 1;
    maxScore += qPoints;

    const userAns = userAnswers[question.id];
    let isCorrect = false;
    let awardedPoints = 0;

    switch (question.type) {
      case 'single_choice':
      case 'true_false': {
        const selectedId = resolveOptionId(userAns, question);
        const correctId = (question.correctOptionIds && question.correctOptionIds[0]) || null;
        if (selectedId && correctId && selectedId === correctId) {
          isCorrect = true;
          awardedPoints = qPoints;
        }
        break;
      }

      case 'multiple_select': {
        const rawList = Array.isArray(userAns) ? userAns : (userAns !== null && userAns !== undefined ? [userAns] : []);
        const selectedIds = rawList.map(a => resolveOptionId(a, question)).filter(Boolean);
        const correctSet = new Set((question.correctOptionIds || []).map(id => String(id).trim()));
        const userSet = new Set(selectedIds);

        // Strict set equality: must match all correct options with NO incorrect extras
        if (correctSet.size > 0 && userSet.size === correctSet.size) {
          let allMatch = true;
          for (const optId of userSet) {
            if (!correctSet.has(optId)) {
              allMatch = false;
              break;
            }
          }
          if (allMatch) {
            isCorrect = true;
            awardedPoints = qPoints;
          }
        }
        break;
      }

      case 'short_answer': {
        const userText = typeof userAns === 'string' ? userAns.trim().toUpperCase() : '';
        const allowedAnswers = (question.correctAnswers || []).map(a => a.trim().toUpperCase());
        if (userText && allowedAnswers.includes(userText)) {
          isCorrect = true;
          awardedPoints = qPoints;
        }
        break;
      }

      default:
        isCorrect = false;
    }

    earnedScore += awardedPoints;

    review.push({
      questionId: question.id,
      prompt: question.prompt,
      type: question.type,
      userAnswer: userAns !== undefined ? userAns : null,
      correctOptionIds: question.correctOptionIds || null,
      correctAnswers: question.correctAnswers || null,
      isCorrect,
      pointsEarned: awardedPoints,
      maxPoints: qPoints,
      explanation: question.explanation || ''
    });
  }

  const scorePercent = maxScore > 0 ? Math.round((earnedScore / maxScore) * 100) : 0;
  const passThreshold = typeof quiz.passPercent === 'number' ? quiz.passPercent : (typeof quiz.passThreshold === 'number' ? quiz.passThreshold : 80);
  const passed = scorePercent >= passThreshold;
  const correctCount = review.filter(r => r.isCorrect).length;

  return {
    quizId: quiz.id,
    courseId: quiz.courseId,
    score: earnedScore,
    maxScore,
    scorePercent,
    scorePercentage: scorePercent,
    passPercent: passThreshold,
    passThreshold,
    passed,
    correctCount,
    totalQuestions: review.length,
    durationSeconds: Number(submission && submission.durationSeconds) || 0,
    review
  };
}

module.exports = {
  prepareQuizForClient,
  scoreQuizAttempt
};
