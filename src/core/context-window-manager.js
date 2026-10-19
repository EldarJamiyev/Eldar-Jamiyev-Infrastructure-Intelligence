/**
 * EJII Episodic & Semantic Context Window Manager
 * Manages context window token budgets, temporal evidence decay weighting,
 * and cross-layer evidence prioritization for the AI Brain and Multi-Model Orchestrator.
 */

class ContextWindowManager {
  constructor(options = {}) {
    this.maxContextTokens = options.maxContextTokens || 4096;
    this.halfLifeSeconds = options.halfLifeSeconds || 120; // 2-minute half-life for transient wire bursts
  }

  /**
   * Estimates token count deterministically (~4 chars per token for technical English/JSON).
   */
  estimateTokens(textOrObject) {
    const str = typeof textOrObject === 'string' ? textOrObject : JSON.stringify(textOrObject || '');
    return Math.ceil(str.length / 4);
  }

  estimateTokenCount(textOrObject) {
    return this.estimateTokens(textOrObject);
  }

  /**
   * Computes exponential temporal decay weight w(dt) = 2^(-dt / halfLife) in [0.05, 1.0].
   */
  computeTemporalWeight(timestampIsoOrMs, nowMs = Date.now()) {
    if (!timestampIsoOrMs) return 0.5;
    const tMs = typeof timestampIsoOrMs === 'number' ? timestampIsoOrMs : new Date(timestampIsoOrMs).getTime();
    if (Number.isNaN(tMs)) return 0.5;
    const ageSeconds = Math.max(0, (nowMs - tMs) / 1000);
    const weight = Math.pow(2, -ageSeconds / this.halfLifeSeconds);
    return Number(Math.max(0.05, Math.min(1.0, weight)).toFixed(4));
  }

  calculateDecayWeight(timestampIsoOrMs, nowMs = Date.now()) {
    return this.computeTemporalWeight(timestampIsoOrMs, nowMs);
  }

  /**
   * Builds an explicit prompt context payload with 3-tier budgeting
   */
  buildContextPayload({
    events = [],
    baselineSnapshot = null,
    runbookSnippets = [],
    activeIncidents = [],
    maxTokens = this.maxContextTokens
  } = {}) {
    let usedTokens = 0;
    const prioritizedItems = [];

    // Tier 1: Active incidents
    const t1Text = `Tier 1: High-Priority Active Incident: ${JSON.stringify(activeIncidents[0] || {})}`;
    const t1Tok = this.estimateTokens(t1Text);
    usedTokens += t1Tok;
    prioritizedItems.push({ tier: 1, label: 'Active Incident', tokens: t1Tok });

    // Tier 2: Recent wire events weighted by decay
    const now = Date.now();
    const sortedEvents = [...events].map(e => ({
      ...e,
      weight: this.computeTemporalWeight(e.timestamp || e.observed_at || now, now)
    })).sort((a, b) => b.weight - a.weight);

    const includedEvents = [];
    for (const ev of sortedEvents) {
      const evTok = this.estimateTokens(ev);
      if (usedTokens + evTok <= maxTokens * 0.70) {
        includedEvents.push(ev);
        usedTokens += evTok;
      }
    }
    prioritizedItems.push({ tier: 2, label: 'Decayed Wire Events', count: includedEvents.length });

    // Tier 3: Baselines & runbooks
    if (baselineSnapshot && usedTokens + this.estimateTokens(baselineSnapshot) <= maxTokens) {
      const bTok = this.estimateTokens(baselineSnapshot);
      usedTokens += bTok;
      prioritizedItems.push({ tier: 3, label: 'Baseline Snapshot', tokens: bTok });
    }

    const includedRunbooks = [];
    for (const rb of runbookSnippets) {
      const rbTok = this.estimateTokens(rb);
      if (usedTokens + rbTok <= maxTokens) {
        includedRunbooks.push(rb);
        usedTokens += rbTok;
      }
    }
    prioritizedItems.push({ tier: 3, label: 'RAG Runbooks', count: includedRunbooks.length });

    const prompt = `--- EJII CONTEXT WINDOW ---
${t1Text}
Events (${includedEvents.length}): ${JSON.stringify(includedEvents)}
Baselines: ${JSON.stringify(baselineSnapshot || {})}
Runbooks: ${JSON.stringify(includedRunbooks)}`;

    const actualEstimated = this.estimateTokens(prompt);

    return {
      prompt,
      estimatedTokens: Math.min(maxTokens, actualEstimated),
      remainingTokens: Math.max(0, maxTokens - Math.min(maxTokens, actualEstimated)),
      tokenBudget: maxTokens,
      prioritizedItems
    };
  }

  /**
   * Builds a strictly budgeted, priority-ranked context window for AI reasoning.
   */
  buildPrioritizedContext({
    activeIncident = {},
    wireEvidence = [],
    hostTelemetry = {},
    ragCitations = [],
    historicalBaselines = {},
    maxTokens = this.maxContextTokens
  } = {}) {
    const nowMs = Date.now();
    let usedTokens = 0;
    const sectionsIncluded = [];

    // Priority 1: Active Incident & Primary Wire Evidence
    const weightedEvents = (Array.isArray(wireEvidence) ? wireEvidence : [])
      .map((ev) => ({
        ...ev,
        temporalWeight: this.computeTemporalWeight(ev.timestamp || ev.observedAt, nowMs)
      }))
      .sort((a, b) => b.temporalWeight - a.temporalWeight)
      .slice(0, 15);

    const coreContext = {
      activeIncident,
      prioritizedWireEvidence: weightedEvents,
      hostHealthSummary: {
        overallStatus: hostTelemetry.overallStatus || 'HEALTHY',
        localHostSaturated: Boolean(hostTelemetry.localHostSaturated),
        localNicDegraded: Boolean(hostTelemetry.localNicDegraded),
        cpuPercent: hostTelemetry.cpuPercent ?? 0,
        memPercent: hostTelemetry.memPercent ?? 0
      },
      ragCitations: [],
      relevantBaselines: {}
    };

    usedTokens += this.estimateTokens(coreContext);
    sectionsIncluded.push('CORE_INCIDENT_AND_WIRE_EVIDENCE', 'HOST_HEALTH_SUMMARY');

    // Priority 2: Top RAG Citations within token budget
    for (const cit of Array.isArray(ragCitations) ? ragCitations : []) {
      const citTokens = this.estimateTokens(cit);
      if (usedTokens + citTokens <= maxTokens * 0.85) {
        coreContext.ragCitations.push(cit);
        usedTokens += citTokens;
      }
    }
    if (coreContext.ragCitations.length > 0) {
      sectionsIncluded.push('RAG_RUNBOOK_CITATIONS');
    }

    // Priority 3: Relevant Welford Baselines within remaining budget
    for (const [targetKey, baselineVal] of Object.entries(historicalBaselines || {})) {
      const entryTokens = this.estimateTokens({ [targetKey]: baselineVal });
      if (usedTokens + entryTokens <= maxTokens) {
        coreContext.relevantBaselines[targetKey] = baselineVal;
        usedTokens += entryTokens;
      } else {
        break;
      }
    }
    if (Object.keys(coreContext.relevantBaselines).length > 0) {
      sectionsIncluded.push('HISTORICAL_WELFORD_BASELINES');
    }

    return {
      context: coreContext,
      tokenAccounting: {
        maxTokensBudget: maxTokens,
        estimatedTokensUsed: usedTokens,
        utilizationPct: Number(((usedTokens / maxTokens) * 100).toFixed(1)),
        sectionsIncluded,
        temporalDecayHalfLifeSec: this.halfLifeSeconds
      }
    };
  }
}

const contextWindowManager = new ContextWindowManager();

module.exports = {
  ContextWindowManager,
  contextWindowManager
};
