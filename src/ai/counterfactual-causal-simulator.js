/**
 * EJII Pearlian Structural Causal Model (SCM) Counterfactual Simulator
 *
 * Implements Judea Pearl's 3-step counterfactual algorithm (Abduction, Action, Prediction)
 * over structural causal graphs to evaluate what network outcomes would have been under
 * candidate interventions do(X=x*) given observed evidence E=e.
 * Dual-Maintenance CommonJS Implementation.
 */

'use strict';

class CounterfactualCausalSimulator {
  constructor() {
    this.totalSimulations = 0;
    this.highRiskCounterfactuals = 0;
  }

  simulateCounterfactual(causalDag, observedEvidence, intervention) {
    this.totalSimulations++;
    const simulationId = `cf_${Date.now()}_${Math.floor(Math.random() * 10000)}`;

    const variables = (causalDag && causalDag.variables) || {};
    const targetVar = (causalDag && causalDag.targetVariable) || 'packetLossPct';
    const evidence = observedEvidence || {};

    // Step 1: Abduction — calculate exogenous noise U_i = Obs_i - Sum(w_ij * Obs_j) - baseMean
    const abducedU = {};
    for (const [varName, node] of Object.entries(variables)) {
      const obsVal = evidence[varName] !== undefined ? evidence[varName] : node.baseMean;
      let parentContribution = 0;
      const parents = node.parents || [];
      for (const parent of parents) {
        const parentVal = evidence[parent] !== undefined ? evidence[parent] : ((variables[parent] && variables[parent].baseMean) || 0);
        const weight = (node.equationWeights && node.equationWeights[parent] !== undefined) ? node.equationWeights[parent] : 0.5;
        parentContribution += weight * parentVal;
      }
      abducedU[varName] = Number((obsVal - parentContribution - node.baseMean).toFixed(4));
    }

    // Step 2 & 3: Action & Prediction — modify DAG with do(X=x*) and propagate forward
    const counterfactualValues = {};

    for (const [varName, node] of Object.entries(variables)) {
      if (intervention && varName === intervention.variable) {
        // do(X = x*) overrides natural mechanism
        counterfactualValues[varName] = intervention.value;
      } else {
        let parentContribution = 0;
        const parents = node.parents || [];
        for (const parent of parents) {
          const parentVal = counterfactualValues[parent] !== undefined
            ? counterfactualValues[parent]
            : (evidence[parent] !== undefined ? evidence[parent] : ((variables[parent] && variables[parent].baseMean) || 0));
          const weight = (node.equationWeights && node.equationWeights[parent] !== undefined) ? node.equationWeights[parent] : 0.5;
          parentContribution += weight * parentVal;
        }
        const u = abducedU[varName] !== undefined ? abducedU[varName] : 0;
        const predicted = parentContribution + node.baseMean + u;
        counterfactualValues[varName] = Number(Math.max(0.0, predicted).toFixed(4));
      }
    }

    const obsTarget = evidence[targetVar] !== undefined ? evidence[targetVar] : ((variables[targetVar] && variables[targetVar].baseMean) || 0);
    const cfTarget = counterfactualValues[targetVar] !== undefined ? counterfactualValues[targetVar] : obsTarget;
    const targetOutcomeDiff = Number((cfTarget - obsTarget).toFixed(4));
    const isHarmful = targetOutcomeDiff > 5.0 || cfTarget > 25.0; // Significant harm

    if (isHarmful) {
      this.highRiskCounterfactuals++;
    }

    return {
      simulationId,
      observedEvidence: evidence,
      intervention,
      abducedExogenousNoise: abducedU,
      counterfactualOutcomes: counterfactualValues,
      targetOutcomeDiff,
      isHarmful
    };
  }

  computeProbabilityOfHarm(result, slaLimit = 10.0) {
    if (!result || !result.counterfactualOutcomes) return 0.0;
    const targetVal = result.counterfactualOutcomes['packetLossPct'] || 0.0;
    if (targetVal > slaLimit) {
      const excess = targetVal - slaLimit;
      const prob = Math.min(1.0, 0.5 + (excess / (slaLimit * 2)));
      return Number(prob.toFixed(3));
    }
    return 0.05;
  }

  getMetrics() {
    return {
      totalSimulations: this.totalSimulations,
      highRiskCounterfactuals: this.highRiskCounterfactuals
    };
  }
}

const counterfactualCausalSimulator = new CounterfactualCausalSimulator();

module.exports = {
  CounterfactualCausalSimulator,
  counterfactualCausalSimulator
};
