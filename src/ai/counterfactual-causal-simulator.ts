/**
 * EJII Pearlian Structural Causal Model (SCM) Counterfactual Simulator
 *
 * Implements Judea Pearl's 3-step counterfactual algorithm (Abduction, Action, Prediction)
 * over structural causal graphs to evaluate what network outcomes would have been under
 * candidate interventions do(X=x*) given observed evidence E=e.
 * Dual-Maintenance TypeScript Reference.
 */

export interface CausalVariableNode {
  name: string;
  parents: string[];
  equationWeights: Record<string, number>;
  baseMean: number;
}

export interface CausalDagDefinition {
  variables: Record<string, CausalVariableNode>;
  targetVariable: string;
}

export interface CounterfactualSimulationResult {
  simulationId: string;
  observedEvidence: Record<string, number>;
  intervention: { variable: string; value: number };
  abducedExogenousNoise: Record<string, number>;
  counterfactualOutcomes: Record<string, number>;
  targetOutcomeDiff: number;
  isHarmful: boolean;
}

export class CounterfactualCausalSimulator {
  private totalSimulations: number = 0;
  private highRiskCounterfactuals: number = 0;

  constructor() {}

  public simulateCounterfactual(
    causalDag: CausalDagDefinition,
    observedEvidence: Record<string, number>,
    intervention: { variable: string; value: number }
  ): CounterfactualSimulationResult {
    this.totalSimulations++;
    const simulationId = `cf_${Date.now()}_${Math.floor(Math.random() * 10000)}`;

    const variables = causalDag?.variables || {};
    const targetVar = causalDag?.targetVariable || 'packetLossPct';

    // Step 1: Abduction — calculate exogenous noise U_i = Obs_i - Sum(w_ij * Obs_j) - baseMean
    const abducedU: Record<string, number> = {};
    for (const [varName, node] of Object.entries(variables)) {
      const obsVal = observedEvidence[varName] !== undefined ? observedEvidence[varName] : node.baseMean;
      let parentContribution = 0;
      for (const parent of node.parents) {
        const parentVal = observedEvidence[parent] !== undefined ? observedEvidence[parent] : (variables[parent]?.baseMean || 0);
        const weight = node.equationWeights[parent] || 0.5;
        parentContribution += weight * parentVal;
      }
      abducedU[varName] = Number((obsVal - parentContribution - node.baseMean).toFixed(4));
    }

    // Step 2 & 3: Action & Prediction — modify DAG with do(X=x*) and propagate forward
    const counterfactualValues: Record<string, number> = {};

    // Topological forward evaluation
    for (const [varName, node] of Object.entries(variables)) {
      if (varName === intervention.variable) {
        // do(X = x*) overrides natural mechanism
        counterfactualValues[varName] = intervention.value;
      } else {
        let parentContribution = 0;
        for (const parent of node.parents) {
          const parentVal = counterfactualValues[parent] !== undefined
            ? counterfactualValues[parent]
            : (observedEvidence[parent] !== undefined ? observedEvidence[parent] : (variables[parent]?.baseMean || 0));
          const weight = node.equationWeights[parent] || 0.5;
          parentContribution += weight * parentVal;
        }
        const u = abducedU[varName] !== undefined ? abducedU[varName] : 0;
        const predicted = parentContribution + node.baseMean + u;
        counterfactualValues[varName] = Number(Math.max(0.0, predicted).toFixed(4));
      }
    }

    const obsTarget = observedEvidence[targetVar] !== undefined ? observedEvidence[targetVar] : (variables[targetVar]?.baseMean || 0);
    const cfTarget = counterfactualValues[targetVar] !== undefined ? counterfactualValues[targetVar] : obsTarget;
    const targetOutcomeDiff = Number((cfTarget - obsTarget).toFixed(4));
    const isHarmful = targetOutcomeDiff > 5.0 || cfTarget > 25.0; // Significant harm

    if (isHarmful) {
      this.highRiskCounterfactuals++;
    }

    return {
      simulationId,
      observedEvidence,
      intervention,
      abducedExogenousNoise: abducedU,
      counterfactualOutcomes: counterfactualValues,
      targetOutcomeDiff,
      isHarmful
    };
  }

  public computeProbabilityOfHarm(
    result: CounterfactualSimulationResult,
    slaLimit: number = 10.0
  ): number {
    if (!result || !result.counterfactualOutcomes) return 0.0;
    const targetVal = result.counterfactualOutcomes['packetLossPct'] || 0.0;
    if (targetVal > slaLimit) {
      const excess = targetVal - slaLimit;
      const prob = Math.min(1.0, 0.5 + (excess / (slaLimit * 2)));
      return Number(prob.toFixed(3));
    }
    return 0.05;
  }

  public getMetrics(): { totalSimulations: number; highRiskCounterfactuals: number } {
    return {
      totalSimulations: this.totalSimulations,
      highRiskCounterfactuals: this.highRiskCounterfactuals
    };
  }
}

export const counterfactualCausalSimulator = new CounterfactualCausalSimulator();
