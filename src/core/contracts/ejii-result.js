/**
 * EJII v6 — Sovereign Intelligence Fabric
 * Part III: Standardized Capability Result Envelope Contract (EJIIResult<T>)
 *
 * Guarantees every diagnostic, discovery, analytical, simulation, and remediation
 * capability returns a provenance-stamped, fresh-classified, evidence-linked envelope.
 */

const crypto = require('crypto');

const VALID_FIDELITIES = new Set([
  'live',
  'live_observed',
  'derived',
  'cached',
  'cached_telemetry',
  'simulated',
  'partial_live_collection',
  'baseline_snapshot',
  'unavailable',
  'unsupported'
]);

const VALID_STATUSES = new Set([
  'ok',
  'degraded',
  'partial',
  'unavailable',
  'denied',
  'failed'
]);

/**
 * Create a standardized EJIIResult<T> envelope.
 * @template T
 * @param {Object} opts
 * @returns {Object} EJIIResult<T>
 */
function createEjiiResult(opts = {}) {
  const nowIso = new Date().toISOString();
  const success = opts.success !== undefined ? Boolean(opts.success) : opts.status !== 'failed' && opts.status !== 'denied';
  const capabilityId = String(opts.capabilityId || 'ejii.core.unknown');
  const requestId = String(opts.requestId || `REQ-${crypto.randomBytes(6).toString('hex')}`);
  const correlationId = String(opts.correlationId || `CID-${crypto.randomBytes(6).toString('hex')}`);
  const observedAt = opts.observedAt || nowIso;
  const ingestedAt = opts.ingestedAt || nowIso;

  const rawSource = opts.source || {};
  const fidelity = VALID_FIDELITIES.has(rawSource.fidelity) ? rawSource.fidelity : 'live';
  const source = {
    module: String(rawSource.module || capabilityId),
    method: String(rawSource.method || 'direct_invocation'),
    privilege: String(rawSource.privilege || 'unprivileged'),
    platform: String(rawSource.platform || process.platform),
    fidelity
  };

  let status = opts.status;
  if (!VALID_STATUSES.has(status)) {
    status = success ? 'ok' : 'failed';
  }

  const envelope = {
    success,
    capabilityId,
    requestId,
    correlationId,
    observedAt,
    ingestedAt,
    source,
    status,
    data: opts.data !== undefined ? opts.data : null,
    evidenceIds: Array.isArray(opts.evidenceIds) ? opts.evidenceIds.map(String) : [],
    warnings: Array.isArray(opts.warnings) ? opts.warnings.map(String) : []
  };

  if (opts.error) {
    envelope.error = {
      code: String(opts.error.code || 'EJII_CAPABILITY_ERROR'),
      message: String(opts.error.message || 'Capability execution encountered an error'),
      recoverable: opts.error.recoverable !== undefined ? Boolean(opts.error.recoverable) : true,
      ...(opts.error.remediationHint ? { remediationHint: String(opts.error.remediationHint) } : {})
    };
  }

  return envelope;
}

/**
 * Validate whether an object conforms to the EJIIResult<T> contract.
 * @param {any} candidate
 * @returns {{ valid: boolean, errors: string[] }}
 */
function validateEjiiResult(candidate) {
  const errors = [];
  if (!candidate || typeof candidate !== 'object') {
    return { valid: false, errors: ['Result must be a non-null object'] };
  }
  if (typeof candidate.success !== 'boolean') errors.push('Missing boolean success');
  if (typeof candidate.capabilityId !== 'string' || !candidate.capabilityId) errors.push('Missing capabilityId');
  if (typeof candidate.requestId !== 'string' || !candidate.requestId) errors.push('Missing requestId');
  if (typeof candidate.correlationId !== 'string' || !candidate.correlationId) errors.push('Missing correlationId');
  if (typeof candidate.observedAt !== 'string') errors.push('Missing observedAt ISO timestamp');
  if (typeof candidate.ingestedAt !== 'string') errors.push('Missing ingestedAt ISO timestamp');
  if (!candidate.source || typeof candidate.source !== 'object') {
    errors.push('Missing source metadata');
  } else {
    if (!VALID_FIDELITIES.has(candidate.source.fidelity)) {
      errors.push(`Invalid source.fidelity: ${candidate.source.fidelity}`);
    }
  }
  if (!VALID_STATUSES.has(candidate.status)) {
    errors.push(`Invalid status: ${candidate.status}`);
  }
  if (!Array.isArray(candidate.evidenceIds)) errors.push('evidenceIds must be an array');
  if (!Array.isArray(candidate.warnings)) errors.push('warnings must be an array');

  return { valid: errors.length === 0, errors };
}

module.exports = {
  VALID_FIDELITIES,
  VALID_STATUSES,
  createEjiiResult,
  validateEjiiResult
};
