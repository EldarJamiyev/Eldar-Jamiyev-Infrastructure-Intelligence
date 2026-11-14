/**
 * EJII Phase 4.0 Track 5 — Distributed Causal Belief Propagation & Cryptographic Consensus
 *
 * Implements:
 *   1. Factor Graph Message Passing (Loopy Belief Propagation) with Damped Updates (lambda = 0.50)
 *   2. Cryptographically Signed Belief Reports via HMAC-SHA256 Edge Credentials
 *   3. Byzantine Quorum Verification (>= 2f + 1 where N >= 3f + 1) & KL Outlier Detection
 *   4. Resilient Store-and-Forward Integration for Disconnected Edge Agents
 */

'use strict';

Object.defineProperty(exports, '__esModule', { value: true });
exports.distributedBeliefPropagationEngine = exports.DistributedBeliefPropagationEngine = exports.CANONICAL_CAUSAL_FACTORS = exports.CANONICAL_FAULT_VARIABLES = void 0;

const crypto = require('node:crypto');
const { db } = require('../../db/database');
const { deriveAgentCredential } = require('./edge-agent-service');

const CANONICAL_FAULT_VARIABLES = [
  { variableId: 'DNS_NXDOMAIN_POISON', label: 'Authoritative DNS Cache Poisoning', prior: 0.10, belief: 0.10 },
  { variableId: 'LOCAL_STACK_CONGESTION', label: 'Local TCP Socket Buffer Saturation', prior: 0.15, belief: 0.15 },
  { variableId: 'ARP_L2_ISOLATION', label: 'Layer 2 ARP Gateway Drop', prior: 0.08, belief: 0.08 },
  { variableId: 'MTU_BLACKHOLE_FRAGMENT', label: 'Path MTU Blackhole Packet Drop', prior: 0.05, belief: 0.05 },
  { variableId: 'SERVICE_DAEMON_CRASH', label: 'Target Service Process Termination', prior: 0.12, belief: 0.12 },
  { variableId: 'UPSTREAM_WAN_BLACKHOLE', label: 'Upstream Transit ISP Blackhole', prior: 0.07, belief: 0.07 }
];
exports.CANONICAL_FAULT_VARIABLES = CANONICAL_FAULT_VARIABLES;

const CANONICAL_CAUSAL_FACTORS = [
  {
    factorId: 'FACTOR_DNS_WAN',
    variableA: 'UPSTREAM_WAN_BLACKHOLE',
    variableB: 'DNS_NXDOMAIN_POISON',
    compatibilityMatrix: [[0.90, 0.10], [0.30, 0.70]]
  },
  {
    factorId: 'FACTOR_CONGESTION_MTU',
    variableA: 'LOCAL_STACK_CONGESTION',
    variableB: 'MTU_BLACKHOLE_FRAGMENT',
    compatibilityMatrix: [[0.85, 0.15], [0.40, 0.60]]
  },
  {
    factorId: 'FACTOR_ARP_WAN',
    variableA: 'ARP_L2_ISOLATION',
    variableB: 'UPSTREAM_WAN_BLACKHOLE',
    compatibilityMatrix: [[0.92, 0.08], [0.60, 0.40]]
  }
];
exports.CANONICAL_CAUSAL_FACTORS = CANONICAL_CAUSAL_FACTORS;

class DistributedBeliefPropagationEngine {
  constructor(options = {}) {
    this.variables = new Map();
    const vars = options.variables || CANONICAL_FAULT_VARIABLES;
    for (const v of vars) {
      this.variables.set(v.variableId, { ...v, belief: v.prior });
    }
    this.factors = options.factors ? [...options.factors] : [...CANONICAL_CAUSAL_FACTORS];
    this.dampingFactor = typeof options.dampingFactor === 'number' ? options.dampingFactor : 0.50;
  }

  /**
   * Executes damped Loopy Belief Propagation on the causal factor graph until convergence.
   */
  runLoopyBeliefPropagation(evidence = {}, options = {}) {
    const maxIterations = options.maxIterations || 20;
    const eps = options.convergenceEps || 1e-4;

    const msgVarToFactor = new Map();
    const msgFactorToVar = new Map();

    for (const f of this.factors) {
      msgVarToFactor.set(`${f.variableA}->${f.factorId}`, [0.5, 0.5]);
      msgVarToFactor.set(`${f.variableB}->${f.factorId}`, [0.5, 0.5]);
      msgFactorToVar.set(`${f.factorId}->${f.variableA}`, [0.5, 0.5]);
      msgFactorToVar.set(`${f.factorId}->${f.variableB}`, [0.5, 0.5]);
    }

    const currentPriors = new Map();
    for (const [varId, vNode] of this.variables.entries()) {
      if (evidence[varId] !== undefined) {
        const ev = Math.max(0.001, Math.min(0.999, Number(evidence[varId])));
        currentPriors.set(varId, [1 - ev, ev]);
      } else {
        const p = Math.max(0.001, Math.min(0.999, vNode.prior));
        currentPriors.set(varId, [1 - p, p]);
      }
    }

    let converged = false;

    for (let iter = 0; iter < maxIterations; iter++) {
      let maxDiff = 0.0;

      // 1. Update factor to variable messages
      for (const f of this.factors) {
        const vA = f.variableA;
        const vB = f.variableB;

        const msgBtoF = msgVarToFactor.get(`${vB}->${f.factorId}`) || [0.5, 0.5];
        const msgAtoF = msgVarToFactor.get(`${vA}->${f.factorId}`) || [0.5, 0.5];

        const newFA0 = f.compatibilityMatrix[0][0] * msgBtoF[0] + f.compatibilityMatrix[0][1] * msgBtoF[1];
        const newFA1 = f.compatibilityMatrix[1][0] * msgBtoF[0] + f.compatibilityMatrix[1][1] * msgBtoF[1];
        const sumFA = (newFA0 + newFA1) || 1.0;
        const normFA = [newFA0 / sumFA, newFA1 / sumFA];

        const newFB0 = f.compatibilityMatrix[0][0] * msgAtoF[0] + f.compatibilityMatrix[1][0] * msgAtoF[1];
        const newFB1 = f.compatibilityMatrix[0][1] * msgAtoF[0] + f.compatibilityMatrix[1][1] * msgAtoF[1];
        const sumFB = (newFB0 + newFB1) || 1.0;
        const normFB = [newFB0 / sumFB, newFB1 / sumFB];

        const oldFA = msgFactorToVar.get(`${f.factorId}->${vA}`) || [0.5, 0.5];
        const dampedFA = [
          (1 - this.dampingFactor) * oldFA[0] + this.dampingFactor * normFA[0],
          (1 - this.dampingFactor) * oldFA[1] + this.dampingFactor * normFA[1]
        ];
        msgFactorToVar.set(`${f.factorId}->${vA}`, dampedFA);

        const oldFB = msgFactorToVar.get(`${f.factorId}->${vB}`) || [0.5, 0.5];
        const dampedFB = [
          (1 - this.dampingFactor) * oldFB[0] + this.dampingFactor * normFB[0],
          (1 - this.dampingFactor) * oldFB[1] + this.dampingFactor * normFB[1]
        ];
        msgFactorToVar.set(`${f.factorId}->${vB}`, dampedFB);
      }

      // 2. Update variable to factor messages
      for (const f of this.factors) {
        const vA = f.variableA;
        const vB = f.variableB;
        const priorA = currentPriors.get(vA) || [0.5, 0.5];
        const priorB = currentPriors.get(vB) || [0.5, 0.5];

        let prodA0 = priorA[0];
        let prodA1 = priorA[1];
        for (const otherF of this.factors) {
          if (otherF.factorId !== f.factorId && (otherF.variableA === vA || otherF.variableB === vA)) {
            const inMsg = msgFactorToVar.get(`${otherF.factorId}->${vA}`) || [1, 1];
            prodA0 *= inMsg[0];
            prodA1 *= inMsg[1];
          }
        }
        const sumA = (prodA0 + prodA1) || 1.0;
        msgVarToFactor.set(`${vA}->${f.factorId}`, [prodA0 / sumA, prodA1 / sumA]);

        let prodB0 = priorB[0];
        let prodB1 = priorB[1];
        for (const otherF of this.factors) {
          if (otherF.factorId !== f.factorId && (otherF.variableA === vB || otherF.variableB === vB)) {
            const inMsg = msgFactorToVar.get(`${otherF.factorId}->${vB}`) || [1, 1];
            prodB0 *= inMsg[0];
            prodB1 *= inMsg[1];
          }
        }
        const sumB = (prodB0 + prodB1) || 1.0;
        msgVarToFactor.set(`${vB}->${f.factorId}`, [prodB0 / sumB, prodB1 / sumB]);
      }

      // 3. Compute marginal beliefs and check convergence
      for (const [varId, vNode] of this.variables.entries()) {
        if (evidence[varId] !== undefined) {
          vNode.belief = Number(evidence[varId]);
          continue;
        }

        const prior = currentPriors.get(varId) || [0.5, 0.5];
        let b0 = prior[0];
        let b1 = prior[1];

        for (const f of this.factors) {
          if (f.variableA === varId || f.variableB === varId) {
            const inMsg = msgFactorToVar.get(`${f.factorId}->${varId}`) || [1, 1];
            b0 *= inMsg[0];
            b1 *= inMsg[1];
          }
        }

        const sumB = (b0 + b1) || 1.0;
        const newBelief = b1 / sumB;
        const diff = Math.abs(newBelief - vNode.belief);
        if (diff > maxDiff) maxDiff = diff;
        vNode.belief = newBelief;
      }

      if (maxDiff < eps) {
        converged = true;
        break;
      }
    }

    const resultMap = {};
    for (const [varId, vNode] of this.variables.entries()) {
      resultMap[varId] = Math.round(vNode.belief * 10000) / 10000;
    }
    return resultMap;
  }

  /**
   * Generates a cryptographically signed belief report for an edge agent.
   */
  generateSignedBeliefReport(agentId, siteId, epoch, beliefs, secretKey) {
    const key = secretKey || deriveAgentCredential(agentId);
    const priors = {};
    for (const [vId, vNode] of this.variables.entries()) {
      priors[vId] = vNode.prior;
    }

    const timestampIso = new Date().toISOString();
    const sortedKeys = Object.keys(beliefs || {}).sort();
    const normalizedBeliefs = {};
    for (const k of sortedKeys) {
      normalizedBeliefs[k] = beliefs[k];
    }

    const payload = `${agentId}:${siteId}:${epoch}:${JSON.stringify(normalizedBeliefs)}`;
    const signature = crypto.createHmac('sha256', key).update(payload).digest('hex');

    return {
      agentId,
      siteId,
      epoch,
      timestampIso,
      beliefs: normalizedBeliefs,
      priors,
      signature
    };
  }

  /**
   * Verifies the HMAC-SHA256 signature of an edge agent's belief report.
   */
  verifyReportSignature(report, secretKey) {
    if (!report || !report.agentId || !report.signature) return false;
    const key = secretKey || deriveAgentCredential(report.agentId);

    const sortedKeys = Object.keys(report.beliefs || {}).sort();
    const normalizedBeliefs = {};
    for (const k of sortedKeys) {
      normalizedBeliefs[k] = report.beliefs[k];
    }

    const payload = `${report.agentId}:${report.siteId}:${report.epoch}:${JSON.stringify(normalizedBeliefs)}`;
    const expectedSig = crypto.createHmac('sha256', key).update(payload).digest('hex');

    try {
      return crypto.timingSafeEqual(Buffer.from(report.signature, 'hex'), Buffer.from(expectedSig, 'hex'));
    } catch (_) {
      return false;
    }
  }

  /**
   * Computes symmetric Kullback-Leibler (KL) divergence between two belief vectors.
   */
  computeSymmetricKLDivergence(p = {}, q = {}) {
    let div = 0.0;
    const keys = Object.keys(p);
    for (const k of keys) {
      const p1 = Math.max(1e-5, Math.min(1 - 1e-5, p[k] ?? 0.5));
      const q1 = Math.max(1e-5, Math.min(1 - 1e-5, q[k] ?? 0.5));
      const p0 = 1 - p1;
      const q0 = 1 - q1;

      const klPQ = p1 * Math.log(p1 / q1) + p0 * Math.log(p0 / q0);
      const klQP = q1 * Math.log(q1 / p1) + q0 * Math.log(q0 / p0);
      div += (klPQ + klQP);
    }
    return Math.round(div * 1000) / 1000;
  }

  /**
   * Aggregates distributed belief reports across edge fleet and verifies Byzantine consensus (>= 2f + 1).
   */
  reachByzantineConsensus(reports = [], epoch = 1, options = {}) {
    const klThreshold = options.klThreshold || 4.5;
    const epochReports = (reports || []).filter((r) => r.epoch === epoch);
    const N = epochReports.length;
    const fTolerated = Math.max(0, Math.floor((N - 1) / 3));
    const requiredQuorum = Math.min(N, 2 * fTolerated + 1);

    const validSignedReports = [];
    const rejectedAgents = [];

    // Step 1: Cryptographic signature verification
    for (const r of epochReports) {
      if (this.verifyReportSignature(r)) {
        validSignedReports.push(r);
      } else {
        rejectedAgents.push(r.agentId);
      }
    }

    if (validSignedReports.length < requiredQuorum || validSignedReports.length === 0) {
      return {
        epoch,
        quorumAchieved: false,
        totalAgentsReported: N,
        validSignaturesCount: validSignedReports.length,
        byzantineRejectedCount: rejectedAgents.length,
        fTolerated,
        consensusBeliefs: {},
        rejectedAgents,
        consensusHash: ''
      };
    }

    // Step 2: Preliminary median consensus for outlier detection
    const allVarKeys = Object.keys(validSignedReports[0].beliefs || {});
    const medianBeliefs = {};

    for (const vKey of allVarKeys) {
      const vals = validSignedReports.map((r) => r.beliefs[vKey] ?? 0.5).sort((a, b) => a - b);
      const mid = Math.floor(vals.length / 2);
      medianBeliefs[vKey] = vals.length % 2 !== 0 ? vals[mid] : (vals[mid - 1] + vals[mid]) / 2;
    }

    // Step 3: Byzantine outlier filtering via symmetric KL divergence
    const nonByzantineReports = [];
    for (const r of validSignedReports) {
      const kl = this.computeSymmetricKLDivergence(r.beliefs, medianBeliefs);
      if (kl <= klThreshold) {
        nonByzantineReports.push(r);
      } else {
        rejectedAgents.push(r.agentId);
      }
    }

    const quorumAchieved = nonByzantineReports.length >= requiredQuorum;

    // Step 4: Final consensus belief aggregation
    const consensusBeliefs = {};
    for (const vKey of allVarKeys) {
      const vals = nonByzantineReports.map((r) => r.beliefs[vKey] ?? 0.5).sort((a, b) => a - b);
      const mid = Math.floor(vals.length / 2);
      const robustVal = vals.length % 2 !== 0 ? vals[mid] : (vals[mid - 1] + vals[mid]) / 2;
      consensusBeliefs[vKey] = Math.round(robustVal * 10000) / 10000;
    }

    const consensusHash = crypto
      .createHash('sha256')
      .update(`${epoch}:${JSON.stringify(consensusBeliefs)}`)
      .digest('hex');

    return {
      epoch,
      quorumAchieved,
      totalAgentsReported: N,
      validSignaturesCount: validSignedReports.length,
      byzantineRejectedCount: rejectedAgents.length,
      fTolerated,
      consensusBeliefs,
      rejectedAgents,
      consensusHash
    };
  }

  /**
   * Persists an outgoing belief report to the durable edge agent outbox table.
   */
  enqueueDurableBeliefReport(report) {
    try {
      if (db && typeof db.prepare === 'function') {
        const stmt = db.prepare(`
          INSERT OR REPLACE INTO edge_agent_durable_outbox
            (task_id, agent_id, lease_epoch, result_json, attempts, queued_at)
          VALUES
            (?, ?, ?, ?, 1, ?)
        `);
        stmt.run(
          `BELIEF_${report.epoch}_${Date.now()}`,
          report.agentId,
          report.epoch,
          JSON.stringify(report),
          Date.now()
        );
        return true;
      }
    } catch (_) {}
    return false;
  }
}
exports.DistributedBeliefPropagationEngine = DistributedBeliefPropagationEngine;

const distributedBeliefPropagationEngine = new DistributedBeliefPropagationEngine();
exports.distributedBeliefPropagationEngine = distributedBeliefPropagationEngine;
