/**
 * EJII Reinforcement Learning from Operator Feedback (RLOF) Policy Alignment Engine
 *
 * Implements:
 *   1. Bradley-Terry Pairwise Preference Model:
 *      P(y_w > y_l | x) = \sigma(r_\theta(x, y_w) - r_\theta(x, y_l))
 *   2. Direct Preference Optimization (DPO) Implicit Reward Loss & Gradients:
 *      \mathcal{L}_{DPO}(\theta; \theta_{ref}) = -E_{(x, y_w, y_l)} [\log \sigma(\beta \log \frac{\pi_\theta(y_w|x)}{\pi_{ref}(y_w|x)} - \beta \log \frac{\pi_\theta(y_l|x)}{\pi_{ref}(y_l|x)})]
 *   3. Contextual Multi-Armed Bandit Arm Prior Alignment:
 *      Shifts Thompson Sampling Beta(\alpha, \beta) posteriors and LinUCB bias vector b_a
 *      based on real human SRE operator chat actions, approvals, and overrides.
 *   4. Durable SQLite WAL Persistence:
 *      Persists preference triplets (x, y_w, y_l, operatorId, timestamp) in ejii_rlof_preference_triplets.
 */

'use strict';

const crypto = require('node:crypto');
const { contextualBanditPolicy } = require('../systems/remediation/contextual-bandit-policy');

function getDb() {
  try {
    return require('../db/database').db;
  } catch (_) {
    return null;
  }
}

const FEATURE_DIMENSION = 4;
const DEFAULT_BETA_DPO = 0.5;
const DEFAULT_LEARNING_RATE = 0.25;

class RlofPreferenceAligner {
  constructor(banditEngine) {
    this.banditEngine = banditEngine || contextualBanditPolicy;
    this.dbInitialized = false;
    this.inMemoryTriplets = [];
    this.weights = new Map();
    this.ensureDatabaseSchema();
  }

  ensureDatabaseSchema() {
    if (this.dbInitialized) return;
    const db = getDb();
    if (!db) return;

    try {
      db.prepare(`
        CREATE TABLE IF NOT EXISTS ejii_rlof_preference_triplets (
          triplet_id TEXT PRIMARY KEY,
          session_id TEXT,
          operator_id TEXT NOT NULL,
          context_vector_json TEXT NOT NULL,
          winning_action TEXT NOT NULL,
          losing_action TEXT NOT NULL,
          bradley_terry_prob REAL NOT NULL,
          dpo_loss REAL NOT NULL,
          feedback_type TEXT NOT NULL,
          timestamp TEXT NOT NULL
        )
      `).run();
      this.dbInitialized = true;
    } catch (_) {}
  }

  /**
   * Sigmoid activation with numerical overflow clamping
   */
  sigmoid(z) {
    if (z > 30.0) return 1.0;
    if (z < -30.0) return 0.0;
    return 1.0 / (1.0 + Math.exp(-z));
  }

  /**
   * Retrieves or initializes linear reward model weights for an action
   */
  getActionWeight(action) {
    if (!this.weights.has(action)) {
      this.weights.set(action, {
        theta: new Array(FEATURE_DIMENSION).fill(0.0),
        bias: 0.0
      });
    }
    return this.weights.get(action);
  }

  normalizeContextVector(contextVector) {
    if (contextVector === undefined || contextVector === null) {
      return [0.5, 0.5, 0.5, 0.2];
    }
    if (!Array.isArray(contextVector) || contextVector.length !== FEATURE_DIMENSION) {
      throw new RangeError(`contextVector must be a ${FEATURE_DIMENSION}-element numeric array`);
    }
    for (let i = 0; i < contextVector.length; i++) {
      const v = contextVector[i];
      if (typeof v !== 'number' || !Number.isFinite(v)) {
        throw new RangeError(`contextVector[${i}] contains non-finite value`);
      }
    }
    return [...contextVector];
  }

  /**
   * Calculates linear scalar reward r_\theta(x, y) = \theta_y^T x + b_y
   */
  computeReward(contextVector, action) {
    const safeCtx = this.normalizeContextVector(contextVector);
    const w = this.getActionWeight(action);
    const dot = safeCtx.reduce((sum, xi, i) => sum + xi * (w.theta[i] || 0.0), 0.0);
    return dot + w.bias;
  }

  /**
   * Computes Bradley-Terry pairwise preference probability:
   * P(y_w > y_l | x) = \sigma(r_\theta(x, y_w) - r_\theta(x, y_l))
   */
  computeBradleyTerryProbability(contextVector, winningAction, losingAction) {
    const rW = this.computeReward(contextVector, winningAction);
    const rL = this.computeReward(contextVector, losingAction);
    const deltaR = rW - rL;
    return Number(this.sigmoid(deltaR).toFixed(6));
  }

  /**
   * Computes DPO loss and explicit analytic gradients with respect to weights
   */
  computeDpoLossAndGradients(contextVector, winningAction, losingAction, betaDpo = DEFAULT_BETA_DPO) {
    const safeCtx = this.normalizeContextVector(contextVector);
    if (typeof betaDpo !== 'number' || !Number.isFinite(betaDpo) || betaDpo <= 0) {
      throw new RangeError('betaDpo must be a positive finite number');
    }
    const safeBeta = betaDpo;
    const rW = this.computeReward(safeCtx, winningAction);
    const rL = this.computeReward(safeCtx, losingAction);
    const margin = safeBeta * (rW - rL);

    // DPO loss: -log(sigma(margin)) = log(1 + exp(-margin))
    let dpoLoss;
    if (margin > 30.0) {
      dpoLoss = Math.exp(-margin);
    } else if (margin < -30.0) {
      dpoLoss = -margin;
    } else {
      dpoLoss = Math.log(1.0 + Math.exp(-margin));
    }

    // Gradient factor: -beta * (1 - sigma(margin))
    const sigM = this.sigmoid(margin);
    const factor = safeBeta * (1.0 - sigM);

    // Negative gradient direction for winning: gradW = -factor * x
    const gradW = safeCtx.map((xi) => -factor * xi);
    // Positive gradient direction for losing: gradL = factor * x
    const gradL = safeCtx.map((xi) => factor * xi);

    return {
      dpoLoss: Number(dpoLoss.toFixed(6)),
      gradW,
      gradL,
      margin: Number(margin.toFixed(6))
    };
  }

  /**
   * Parses natural language chat statements for explicit operator feedback / overrides
   */
  parseOperatorFeedback(prompt) {
    const clean = String(prompt || '').trim();
    if (!clean) return { matched: false, rawText: clean };

    // 1. Reject questions, negated commands, conditionals, quoted strings, and declarative protocol explanations
    if (
      clean.includes('?') ||
      /^["'`].*["'`]$/.test(clean) ||
      /^(?:why|what|how|when|where|who|which|can|could|would|should|is|are|does|do|did|explain|tell\s+me|don't|do\s+not|never|avoid|refuse|if|unless|whenever|suppose|assuming|in\s+case)\b/i.test(clean) ||
      /\b(?:do\s+not|don't|dont|never|avoid|refuse\s+to|must\s+not|should\s+not|shouldn't|cannot|can't|not\s+to)\s+(?:ever\s+|please\s+|automatically\s+)?(?:approve|reject|prefer|override|use|run|execute)\b/i.test(clean) ||
      /\b(?:if|when|whenever|unless)\s+[^,.;]+,\s*(?:please\s+|do\s+not\s+|don't\s+)?(?:approve|reject|prefer|override)\b/i.test(clean) ||
      /^(?:a|an|the|this|that|these|those|firewalls?|routers?|switches?|servers?|clients?|hosts?|kernels?|daemons?|policies|rules?|packets?|connections?)\b[^,.;]*\b(?:can|may|will|might|could|should|would|often|typically|usually|automatically)?\s*(?:approve|reject|prefer|override)s?\b/i.test(clean) ||
      /["'`][^"'`]*\b(?:approve|reject|prefer|override)\b[^"'`]*["'`]/i.test(clean)
    ) {
      return { matched: false, rawText: clean };
    }

    const NON_ACTION_NOUNS = new Set([
      'PORT', 'PORTS', 'PACKET', 'PACKETS', 'CONNECTION', 'CONNECTIONS', 'REQUEST', 'REQUESTS',
      'TRAFFIC', 'FRAME', 'FRAMES', 'PING', 'ICMP', 'TCP', 'UDP', 'DNS', 'HTTP', 'HTTPS', 'TLS',
      'SSL', 'SERVER', 'CLIENT', 'HOST', 'IT', 'THAT', 'THIS', 'THEM', 'ALL', 'ANYTHING',
      'A', 'AN', 'THE', 'SYN', 'RST', 'ACK', 'RULE', 'RULES', 'POLICY', 'FIREWALL', 'ROUTER'
    ]);

    const isValidActionToken = (token) => {
      if (!token) return false;
      const upper = String(token).toUpperCase();
      if (NON_ACTION_NOUNS.has(upper) || upper.length < 2) return false;
      return true;
    };

    // 1. "prefer <ActionA> over <ActionB>"
    const preferMatch = clean.match(/^(?:please\s+|i\s+|we\s+|operator\s+|always\s+)?prefer\s+(?:action\s+|remediation\s+)?([A-Za-z0-9_\-]+)\s+over\s+(?:action\s+|remediation\s+)?([A-Za-z0-9_\-]+)\s*[.!]*$/i);
    if (preferMatch && isValidActionToken(preferMatch[1]) && isValidActionToken(preferMatch[2])) {
      return {
        matched: true,
        feedbackType: 'PREFERENCE_RANKING',
        winningAction: preferMatch[1].toUpperCase(),
        losingAction: preferMatch[2].toUpperCase(),
        rawText: clean
      };
    }

    // 2. "reject <ActionA>, use <ActionB>" / "reject <ActionA> prefer <ActionB>"
    const rejectUseMatch = clean.match(/^(?:please\s+|i\s+|we\s+|operator\s+)?reject\s+(?:action\s+|remediation\s+)?([A-Za-z0-9_\-]+)[,\s]+(?:and\s+)?(?:use|prefer|switch to)\s+(?:action\s+|remediation\s+)?([A-Za-z0-9_\-]+)\s*[.!]*$/i);
    if (rejectUseMatch && isValidActionToken(rejectUseMatch[1]) && isValidActionToken(rejectUseMatch[2])) {
      return {
        matched: true,
        feedbackType: 'EXPLICIT_OVERRIDE',
        winningAction: rejectUseMatch[2].toUpperCase(),
        losingAction: rejectUseMatch[1].toUpperCase(),
        rawText: clean
      };
    }

    // 3. "override <ActionA> with <ActionB>"
    const overrideMatch = clean.match(/^(?:please\s+|i\s+|we\s+|operator\s+)?override\s+(?:action\s+|remediation\s+)?([A-Za-z0-9_\-]+)\s+with\s+(?:action\s+|remediation\s+)?([A-Za-z0-9_\-]+)\s*[.!]*$/i);
    if (overrideMatch && isValidActionToken(overrideMatch[1]) && isValidActionToken(overrideMatch[2])) {
      return {
        matched: true,
        feedbackType: 'EXPLICIT_OVERRIDE',
        winningAction: overrideMatch[2].toUpperCase(),
        losingAction: overrideMatch[1].toUpperCase(),
        rawText: clean
      };
    }

    // 4. "approve <ActionA> [instead of <ActionB>] [because ...]"
    const approveMatch = clean.match(/^(?:please\s+|i\s+|we\s+|operator\s+)?approve\s+(?:action\s+|remediation\s+)?([A-Za-z0-9_\-]+)(?:\s+(?:instead of|rather than|over)\s+(?:action\s+|remediation\s+)?([A-Za-z0-9_\-]+))?(?:\s+(?:because|since|due to|for|on)\b.*)?\s*[.!]*$/i);
    if (approveMatch && isValidActionToken(approveMatch[1]) && (!approveMatch[2] || isValidActionToken(approveMatch[2]))) {
      return {
        matched: true,
        feedbackType: 'EXPLICIT_APPROVAL',
        winningAction: approveMatch[1].toUpperCase(),
        losingAction: approveMatch[2] ? approveMatch[2].toUpperCase() : 'BASELINE_NOOP',
        rawText: clean
      };
    }

    // 5. "reject <ActionA> [because ...]"
    const rejectOnlyMatch = clean.match(/^(?:please\s+|i\s+|we\s+|operator\s+)?reject\s+(?:action\s+|remediation\s+)?([A-Za-z0-9_\-]+)(?:\s+[A-Za-z0-9_\-]+)?(?:\s+(?:because|since|due to|for|on)\b.*)?\s*[.!]*$/i);
    if (rejectOnlyMatch && isValidActionToken(rejectOnlyMatch[1])) {
      return {
        matched: true,
        feedbackType: 'MANUAL_REJECTION',
        winningAction: 'BASELINE_NOOP',
        losingAction: rejectOnlyMatch[1].toUpperCase(),
        rawText: clean
      };
    }

    return { matched: false, rawText: clean };
  }

  /**
   * Records preference triplet, updates Bradley-Terry / DPO weights, and aligns Contextual Bandit arm priors
   */
  recordPreferenceAndAlign(params) {
    const winningAction = String(params?.winningAction || '').toUpperCase();
    const losingAction = String(params?.losingAction || '').toUpperCase();
    const contextVector = this.normalizeContextVector(params?.contextVector);
    const operatorId = params?.operatorId || 'operator-sre-1';
    const sessionId = params?.sessionId || 'session-global';
    const feedbackType = params?.feedbackType || 'EXPLICIT_OVERRIDE';
    if (params?.learningRate !== undefined && (typeof params.learningRate !== 'number' || !Number.isFinite(params.learningRate) || params.learningRate <= 0)) {
      throw new RangeError('learningRate must be a positive finite number');
    }
    if (params?.betaDpo !== undefined && (typeof params.betaDpo !== 'number' || !Number.isFinite(params.betaDpo) || params.betaDpo <= 0)) {
      throw new RangeError('betaDpo must be a positive finite number');
    }
    const lr = params?.learningRate ?? DEFAULT_LEARNING_RATE;
    const betaDpo = params?.betaDpo ?? DEFAULT_BETA_DPO;

    // 1. Calculate Bradley-Terry Probability and DPO gradients
    const btProb = this.computeBradleyTerryProbability(contextVector, winningAction, losingAction);
    const { dpoLoss, gradW, gradL } = this.computeDpoLossAndGradients(
      contextVector,
      winningAction,
      losingAction,
      betaDpo
    );

    // 2. Perform Gradient Descent on Linear Reward Model Weights
    const wWin = this.getActionWeight(winningAction);
    const wLoss = this.getActionWeight(losingAction);

    for (let i = 0; i < FEATURE_DIMENSION; i++) {
      wWin.theta[i] -= lr * gradW[i];
      wLoss.theta[i] -= lr * gradL[i];
    }
    wWin.bias += lr * (1.0 - btProb);
    wLoss.bias -= lr * btProb;

    // Gradient norm
    const gradNorm = Math.sqrt(
      gradW.reduce((sum, g) => sum + g * g, 0.0) +
      gradL.reduce((sum, g) => sum + g * g, 0.0)
    );

    // 3. Shift Contextual Bandit Arm Priors in contextualBanditPolicy
    const winArm = this.banditEngine.registerOrGetArm(winningAction);
    const lossArm = this.banditEngine.registerOrGetArm(losingAction);

    winArm.alpha = Number((winArm.alpha + lr * btProb).toFixed(4));
    winArm.pulls += 1;
    winArm.successes += 1;
    for (let i = 0; i < FEATURE_DIMENSION; i++) {
      winArm.vectorB[i] = Number(((winArm.vectorB[i] || 0) + lr * contextVector[i]).toFixed(4));
    }

    lossArm.beta = Number((lossArm.beta + lr * (1.0 - btProb + 0.5)).toFixed(4));
    lossArm.pulls += 1;
    lossArm.failures += 1;
    for (let i = 0; i < FEATURE_DIMENSION; i++) {
      lossArm.vectorB[i] = Number(((lossArm.vectorB[i] || 0) - lr * contextVector[i]).toFixed(4));
    }

    if (typeof this.banditEngine.persistArm === 'function') {
      this.banditEngine.persistArm(winArm);
      this.banditEngine.persistArm(lossArm);
    }

    // 4. Create and persist preference triplet
    const tripletId = `TRIPLET-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const triplet = {
      tripletId,
      sessionId,
      operatorId,
      contextVector,
      winningAction,
      losingAction,
      bradleyTerryProb: btProb,
      dpoLoss,
      feedbackType,
      timestamp: new Date().toISOString()
    };

    this.inMemoryTriplets.push(triplet);
    this.persistTriplet(triplet);

    return {
      triplet,
      winningArmPrior: {
        armId: winArm.armId,
        priorAlpha: winArm.alpha,
        priorBeta: winArm.beta
      },
      losingArmPrior: {
        armId: lossArm.armId,
        priorAlpha: lossArm.alpha,
        priorBeta: lossArm.beta
      },
      bradleyTerryLikelihood: btProb,
      gradientNorm: Number(gradNorm.toFixed(6)),
      dpoLoss
    };
  }

  getPreferenceHistory(limit = 50) {
    const db = getDb();
    if (db) {
      try {
        const rows = db.prepare(
          'SELECT * FROM ejii_rlof_preference_triplets ORDER BY timestamp DESC LIMIT ?'
        ).all(limit);
        if (rows && rows.length > 0) {
          return rows.map((r) => ({
            tripletId: r.triplet_id,
            sessionId: r.session_id,
            operatorId: r.operator_id,
            contextVector: JSON.parse(r.context_vector_json),
            winningAction: r.winning_action,
            losingAction: r.losing_action,
            bradleyTerryProb: r.bradley_terry_prob,
            dpoLoss: r.dpo_loss,
            feedbackType: r.feedback_type,
            timestamp: r.timestamp
          }));
        }
      } catch (_) {}
    }
    return this.inMemoryTriplets.slice(-limit);
  }

  getPolicyWeights(action) {
    return this.getActionWeight(action);
  }

  resetForTesting() {
    this.inMemoryTriplets = [];
    this.weights.clear();
    const db = getDb();
    if (db) {
      try {
        db.prepare('DELETE FROM ejii_rlof_preference_triplets').run();
      } catch (_) {}
    }
  }

  persistTriplet(triplet) {
    const db = getDb();
    if (!db) return;
    try {
      db.prepare(`
        INSERT INTO ejii_rlof_preference_triplets (
          triplet_id, session_id, operator_id, context_vector_json,
          winning_action, losing_action, bradley_terry_prob, dpo_loss,
          feedback_type, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        triplet.tripletId,
        triplet.sessionId || null,
        triplet.operatorId,
        JSON.stringify(triplet.contextVector),
        triplet.winningAction,
        triplet.losingAction,
        triplet.bradleyTerryProb,
        triplet.dpoLoss,
        triplet.feedbackType,
        triplet.timestamp
      );
    } catch (_) {}
  }
}

const rlofPreferenceAligner = new RlofPreferenceAligner();

module.exports = {
  RlofPreferenceAligner,
  rlofPreferenceAligner
};
