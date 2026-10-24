/**
 * EJII Enterprise Runtime Type Contract Validator
 * Enforces schema compliance against src/types/ejii-contracts.d.ts
 * Provides zero-overhead, production-grade schema validation and Universal Epistemic Envelopes.
 */

const VALID_EPISTEMIC_STATES = Object.freeze(['OBSERVED', 'INFERRED', 'RECOMMENDED', 'VERIFIED']);
const VALID_LIVENESS_STATES = Object.freeze([
  'CURRENTLY_OBSERVED',
  'RECENTLY_OBSERVED',
  'HISTORICAL',
  'UNREACHABLE_UNDER_CURRENT_TEST',
  'UNKNOWN'
]);
const VALID_SCORE_SEMANTICS = Object.freeze([
  'PHYSICAL_TRUTH',
  'PROBABILITY_MARGIN',
  'BAYESIAN_POSTERIOR',
  'CONFIDENCE_SCORE',
  'FORMAL_VERIFICATION'
]);

class TypeContractValidator {
  /**
   * Validate ITopologyNode
   */
  static validateTopologyNode(node) {
    if (!node || typeof node !== 'object') {
      return { valid: false, error: 'Node must be a non-null object' };
    }
    const requiredFields = ['id', 'name', 'hostname_or_ip', 'type', 'layer', 'layer_level', 'status'];
    for (const f of requiredFields) {
      if (node[f] === undefined || node[f] === null) {
        return { valid: false, error: `Missing required field: ${f}` };
      }
    }
    const validLayers = ['wan', 'edge', 'core', 'service', 'access', 'endpoint'];
    if (!validLayers.includes(node.layer)) {
      return { valid: false, error: `Invalid layer: ${node.layer}` };
    }
    if (typeof node.layer_level !== 'number' || node.layer_level < 1 || node.layer_level > 6) {
      return { valid: false, error: `Invalid layer_level: ${node.layer_level} (must be 1-6)` };
    }
    return { valid: true };
  }

  /**
   * Validate ITopologyEdge
   */
  static validateTopologyEdge(edge) {
    if (!edge || typeof edge !== 'object') {
      return { valid: false, error: 'Edge must be a non-null object' };
    }
    const required = ['id', 'source_id', 'target_id', 'link_type', 'status', 'bandwidth_mbps'];
    for (const f of required) {
      if (edge[f] === undefined || edge[f] === null) {
        return { valid: false, error: `Missing required field: ${f}` };
      }
    }
    return { valid: true };
  }

  /**
   * Validate ITimeSeriesPoint
   */
  static validateTimeSeriesPoint(point) {
    if (!point || typeof point !== 'object') {
      return { valid: false, error: 'Point must be a non-null object' };
    }
    if (typeof point.metric !== 'string' || !point.metric) {
      return { valid: false, error: 'Invalid or missing metric name' };
    }
    if (typeof point.value !== 'number' || isNaN(point.value)) {
      return { valid: false, error: 'Invalid or non-numeric value' };
    }
    return { valid: true };
  }

  /**
   * Validate IGitOpsDesiredState
   */
  static validateGitOpsDesiredState(state) {
    if (!state || typeof state !== 'object') {
      return { valid: false, error: 'Desired state must be an object' };
    }
    if (!state.baseline || typeof state.baseline !== 'object') {
      return { valid: false, error: 'Missing baseline object in desired state' };
    }
    if (!Array.isArray(state.baseline.requiredLayers)) {
      return { valid: false, error: 'baseline.requiredLayers must be an array' };
    }
    return { valid: true };
  }

  /**
   * Validate IPacketFrame
   */
  static validatePacketFrame(frame) {
    if (!frame || typeof frame !== 'object') {
      return { valid: false, error: 'Frame must be a non-null object' };
    }
    if (!frame.srcIp || !frame.dstIp) {
      return { valid: false, error: 'Frame missing srcIp or dstIp' };
    }
    return { valid: true };
  }

  /**
   * Classify temporal & reachability lifecycle state from observation timestamp and probe status
   * @param {string|number|Date|null} timestamp 
   * @param {boolean} [failed=false] 
   * @param {number} [now=Date.now()]
   * @returns {'CURRENTLY_OBSERVED'|'RECENTLY_OBSERVED'|'HISTORICAL'|'UNREACHABLE_UNDER_CURRENT_TEST'|'UNKNOWN'}
   */
  static classifyTemporalLiveness(timestamp, failed = false, now = Date.now()) {
    if (failed) {
      return 'UNREACHABLE_UNDER_CURRENT_TEST';
    }
    if (!timestamp) {
      return 'UNKNOWN';
    }
    const timeMs = new Date(timestamp).getTime();
    if (isNaN(timeMs)) {
      return 'UNKNOWN';
    }
    const ageMs = Math.max(0, now - timeMs);
    if (ageMs <= 60000) {
      return 'CURRENTLY_OBSERVED'; // within 60s
    }
    if (ageMs <= 600000) {
      return 'RECENTLY_OBSERVED'; // within 10 minutes
    }
    return 'HISTORICAL'; // older than 10 minutes
  }

  /**
   * Validate Epistemic Envelope
   * @param {object} envelope
   * @returns {{ valid: boolean, error?: string }}
   */
  static validateEpistemicEnvelope(envelope) {
    if (!envelope || typeof envelope !== 'object') {
      return { valid: false, error: 'Epistemic envelope must be a non-null object' };
    }
    if (!VALID_EPISTEMIC_STATES.includes(envelope.epistemicState)) {
      return { valid: false, error: `Invalid epistemicState: ${envelope.epistemicState}` };
    }
    if (!envelope.sourceAdapter || typeof envelope.sourceAdapter !== 'string') {
      return { valid: false, error: 'Missing or invalid sourceAdapter string' };
    }
    if (envelope.scoreSemantics && !VALID_SCORE_SEMANTICS.includes(envelope.scoreSemantics)) {
      return { valid: false, error: `Invalid scoreSemantics: ${envelope.scoreSemantics}` };
    }
    if (envelope.livenessState && !VALID_LIVENESS_STATES.includes(envelope.livenessState)) {
      return { valid: false, error: `Invalid livenessState: ${envelope.livenessState}` };
    }
    return { valid: true };
  }

  /**
   * Attach a validated Universal Epistemic Envelope to an object
   * @param {object} target 
   * @param {object} meta
   * @returns {object} Target object enriched with _epistemic
   */
  static attachEpistemicEnvelope(target, meta = {}) {
    if (!target || typeof target !== 'object') {
      return target;
    }
    const epistemicState = VALID_EPISTEMIC_STATES.includes(meta.epistemicState)
      ? meta.epistemicState
      : 'OBSERVED';

    let defaultSemantics = 'PHYSICAL_TRUTH';
    let defaultVerified = true;
    if (epistemicState === 'INFERRED') {
      defaultSemantics = 'BAYESIAN_POSTERIOR';
      defaultVerified = false;
    } else if (epistemicState === 'RECOMMENDED') {
      defaultSemantics = 'CONFIDENCE_SCORE';
      defaultVerified = false;
    } else if (epistemicState === 'VERIFIED') {
      defaultSemantics = 'FORMAL_VERIFICATION';
      defaultVerified = true;
    }

    const envelope = {
      epistemicState,
      sourceAdapter: meta.sourceAdapter || 'ejii.core.system',
      observedAt: meta.observedAt || new Date().toISOString(),
      scoreSemantics: meta.scoreSemantics || defaultSemantics,
      verified: typeof meta.verified === 'boolean' ? meta.verified : defaultVerified,
      livenessState: meta.livenessState || (meta.observedAt ? TypeContractValidator.classifyTemporalLiveness(meta.observedAt) : 'CURRENTLY_OBSERVED')
    };

    if (meta.inferenceMethod) {
      envelope.inferenceMethod = meta.inferenceMethod;
    }
    if (meta.verificationCriterion) {
      envelope.verificationCriterion = meta.verificationCriterion;
    }

    target._epistemic = envelope;
    return target;
  }
}

function attachEpistemicEnvelope(target, meta = {}) {
  return TypeContractValidator.attachEpistemicEnvelope(target, meta);
}

function classifyTemporalLiveness(timestamp, failed = false, now = Date.now()) {
  return TypeContractValidator.classifyTemporalLiveness(timestamp, failed, now);
}

module.exports = {
  TypeContractValidator,
  VALID_EPISTEMIC_STATES,
  VALID_LIVENESS_STATES,
  VALID_SCORE_SEMANTICS,
  attachEpistemicEnvelope,
  classifyTemporalLiveness
};
