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

const VALID_EVIDENCE_CLASSES = Object.freeze(['Observed', 'OS', 'Management', 'Inferred', 'Configured', 'Unknown']);
const VALID_COLLECTION_OUTCOMES = Object.freeze([
  'SUCCESS',
  'PARTIAL',
  'TIMEOUT',
  'PERMISSION_DENIED',
  'UNSUPPORTED_PLATFORM',
  'COLLECTION_ERROR',
  'PROVISIONAL_WARM_STATE'
]);
const VALID_HYPOTHESIS_STATUSES = Object.freeze([
  'SUPPORTED',
  'CONTRADICTED',
  'INSUFFICIENT_EVIDENCE',
  'PLAUSIBLE_UNVERIFIED'
]);
const VALID_INVOCATION_DECISIONS = Object.freeze([
  'INVOKED',
  'BYPASSED_HIGH_EVIDENCE_CONFIDENCE',
  'BLOCKED_PRIVACY_POLICY',
  'PROVIDER_UNAVAILABLE',
  'DETERMINISTIC_CONFIG_DEFAULT'
]);
const VALID_PROVIDER_IDS = Object.freeze(['OLLAMA', 'OPENAI', 'ANTHROPIC', 'NONE']);

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

  /**
   * Validate EvidenceRecord (Section 2.1)
   * @param {object} record
   * @returns {{ valid: boolean, error?: string }}
   */
  static validateEvidenceRecord(record) {
    if (!record || typeof record !== 'object') {
      return { valid: false, error: 'EvidenceRecord must be a non-null object' };
    }
    if (typeof record.evidenceId !== 'string' || !record.evidenceId) {
      return { valid: false, error: 'Missing or empty evidenceId' };
    }
    if (typeof record.metricKey !== 'string' || !record.metricKey) {
      return { valid: false, error: 'Missing or empty metricKey' };
    }
    if (!VALID_COLLECTION_OUTCOMES.includes(record.outcome)) {
      return { valid: false, error: `Invalid collection outcome: ${record.outcome}` };
    }
    // Strict Contract Rule: value must be null when outcome !== 'SUCCESS'
    if (record.outcome !== 'SUCCESS' && record.value !== null) {
      return { valid: false, error: `Value must be null when outcome is ${record.outcome}` };
    }
    if (!VALID_EVIDENCE_CLASSES.includes(record.evidenceClass)) {
      return { valid: false, error: `Invalid evidenceClass: ${record.evidenceClass}` };
    }
    if (typeof record.collectorId !== 'string' || !record.collectorId) {
      return { valid: false, error: 'Missing or empty collectorId' };
    }
    if (typeof record.collectionMethod !== 'string' || !record.collectionMethod) {
      return { valid: false, error: 'Missing or empty collectionMethod' };
    }
    if (typeof record.timestampIso !== 'string' || !record.timestampIso) {
      return { valid: false, error: 'Missing or empty timestampIso' };
    }
    if (typeof record.isAuthoritative !== 'boolean') {
      return { valid: false, error: 'isAuthoritative must be a boolean' };
    }
    if (!Array.isArray(record.supportsHypotheses)) {
      return { valid: false, error: 'supportsHypotheses must be an array' };
    }
    if (!Array.isArray(record.contradictsHypotheses)) {
      return { valid: false, error: 'contradictsHypotheses must be an array' };
    }
    return { valid: true };
  }

  /**
   * Create an authoritative or provisional EvidenceRecord conforming strictly to Section 2.1
   */
  static createEvidenceRecord(params = {}) {
    const outcome = VALID_COLLECTION_OUTCOMES.includes(params.outcome) ? params.outcome : 'SUCCESS';
    const evidenceClass = VALID_EVIDENCE_CLASSES.includes(params.evidenceClass) ? params.evidenceClass : 'Observed';
    const nowIso = params.timestampIso || new Date().toISOString();
    const nowMs = Date.now();
    const timeMs = new Date(nowIso).getTime();
    const freshnessMs = typeof params.freshnessMs === 'number' ? params.freshnessMs : Math.max(0, nowMs - (isNaN(timeMs) ? nowMs : timeMs));
    
    // Strict value enforcement: null when outcome !== 'SUCCESS'
    const value = outcome === 'SUCCESS' ? (params.value !== undefined ? params.value : null) : null;

    const record = {
      evidenceId: params.evidenceId || ('ev_' + Math.random().toString(36).substring(2, 11) + '_' + Date.now().toString(36)),
      metricKey: params.metricKey || 'unknown.metric',
      value,
      unit: params.unit || undefined,
      evidenceClass,
      collectorId: params.collectorId || 'core:generic-collector',
      collectionMethod: params.collectionMethod || 'runtime:direct',
      timestampIso: nowIso,
      freshnessMs,
      targetIdentity: params.targetIdentity && typeof params.targetIdentity === 'object'
        ? {
            host: params.targetIdentity.host,
            pinnedIp: params.targetIdentity.pinnedIp || null,
            pid: params.targetIdentity.pid || null,
            processName: params.targetIdentity.processName || null,
            interfaceId: params.targetIdentity.interfaceId || null
          }
        : { host: undefined, pinnedIp: null, pid: null, processName: null, interfaceId: null },
      outcome,
      errorDetails: params.errorDetails || null,
      measurementUncertainty: typeof params.measurementUncertainty === 'number' ? params.measurementUncertainty : null,
      isAuthoritative: typeof params.isAuthoritative === 'boolean' ? params.isAuthoritative : (outcome === 'SUCCESS' && evidenceClass !== 'Inferred' && evidenceClass !== 'Unknown'),
      supportsHypotheses: Array.isArray(params.supportsHypotheses) ? params.supportsHypotheses : [],
      contradictsHypotheses: Array.isArray(params.contradictsHypotheses) ? params.contradictsHypotheses : []
    };

    return record;
  }

  /**
   * Validate HypothesisEvaluation (Section 2.2)
   */
  static validateHypothesisEvaluation(hypo) {
    if (!hypo || typeof hypo !== 'object') {
      return { valid: false, error: 'HypothesisEvaluation must be a non-null object' };
    }
    if (typeof hypo.hypothesisId !== 'string' || !hypo.hypothesisId) {
      return { valid: false, error: 'Missing or empty hypothesisId' };
    }
    if (typeof hypo.title !== 'string' || !hypo.title) {
      return { valid: false, error: 'Missing or empty title' };
    }
    if (!VALID_HYPOTHESIS_STATUSES.includes(hypo.status)) {
      return { valid: false, error: `Invalid status: ${hypo.status}` };
    }
    if (typeof hypo.priorProbability !== 'number') {
      return { valid: false, error: 'priorProbability must be a number' };
    }
    if (typeof hypo.normalizedPosterior !== 'number') {
      return { valid: false, error: 'normalizedPosterior must be a number' };
    }
    if (hypo.status === 'CONTRADICTED' && hypo.normalizedPosterior !== 0) {
      return { valid: false, error: 'Contradicted hypothesis must have normalizedPosterior exactly 0' };
    }
    if (!['EMPIRICALLY_CALIBRATED', 'RULE_HEURISTIC', 'INSUFFICIENT_DATA'].includes(hypo.confidenceType)) {
      return { valid: false, error: `Invalid confidenceType: ${hypo.confidenceType}` };
    }
    return { valid: true };
  }

  /**
   * Validate ModelOrchestrationResult (Section 2.3)
   */
  static validateModelOrchestrationResult(res) {
    if (!res || typeof res !== 'object') {
      return { valid: false, error: 'ModelOrchestrationResult must be a non-null object' };
    }
    if (!VALID_INVOCATION_DECISIONS.includes(res.invocationDecision)) {
      return { valid: false, error: `Invalid invocationDecision: ${res.invocationDecision}` };
    }
    if (!VALID_PROVIDER_IDS.includes(res.providerId)) {
      return { valid: false, error: `Invalid providerId: ${res.providerId}` };
    }
    if (!res.privacyGate || typeof res.privacyGate !== 'object') {
      return { valid: false, error: 'Missing privacyGate object' };
    }
    if (!res.transportState || typeof res.transportState !== 'object') {
      return { valid: false, error: 'Missing transportState object' };
    }
    if (!res.inferenceState || typeof res.inferenceState !== 'object') {
      return { valid: false, error: 'Missing inferenceState object' };
    }
    return { valid: true };
  }
}

function attachEpistemicEnvelope(target, meta = {}) {
  return TypeContractValidator.attachEpistemicEnvelope(target, meta);
}

function classifyTemporalLiveness(timestamp, failed = false, now = Date.now()) {
  return TypeContractValidator.classifyTemporalLiveness(timestamp, failed, now);
}

function createEvidenceRecord(params = {}) {
  return TypeContractValidator.createEvidenceRecord(params);
}

function validateEvidenceRecord(record) {
  return TypeContractValidator.validateEvidenceRecord(record);
}

function validateHypothesisEvaluation(hypo) {
  return TypeContractValidator.validateHypothesisEvaluation(hypo);
}

function validateModelOrchestrationResult(res) {
  return TypeContractValidator.validateModelOrchestrationResult(res);
}

module.exports = {
  TypeContractValidator,
  VALID_EPISTEMIC_STATES,
  VALID_LIVENESS_STATES,
  VALID_SCORE_SEMANTICS,
  VALID_EVIDENCE_CLASSES,
  VALID_COLLECTION_OUTCOMES,
  VALID_HYPOTHESIS_STATUSES,
  VALID_INVOCATION_DECISIONS,
  VALID_PROVIDER_IDS,
  attachEpistemicEnvelope,
  classifyTemporalLiveness,
  createEvidenceRecord,
  validateEvidenceRecord,
  validateHypothesisEvaluation,
  validateModelOrchestrationResult
};
