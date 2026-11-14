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
    ok: success,
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
      category: String(opts.error.category || 'EXECUTION_ERROR'),
      recoverable: opts.error.recoverable !== undefined ? Boolean(opts.error.recoverable) : true,
      ...(opts.error.remediationHint ? { remediationHint: String(opts.error.remediationHint) } : {})
    };
  }

  return envelope;
}

/**
 * Checks whether an object already conforms to the EJIIResult<T> envelope.
 * @param {any} candidate
 * @returns {boolean}
 */
function isEjiiResult(candidate) {
  return Boolean(
    candidate &&
    typeof candidate === 'object' &&
    typeof candidate.success === 'boolean' &&
    typeof candidate.capabilityId === 'string' &&
    typeof candidate.status === 'string' &&
    candidate.source &&
    typeof candidate.source === 'object'
  );
}

/**
 * Standardizes any protocol probe result or error into a canonical EJIIResult<T> envelope.
 * @param {string} capabilityId
 * @param {any} rawResult
 * @param {Object} [options]
 * @returns {Object} EJIIResult<T>
 */
function wrapProtocolProbeResult(capabilityId, rawResult, options = {}) {
  if (isEjiiResult(rawResult)) {
    return rawResult;
  }
  const isErr = rawResult instanceof Error;
  const isSuccess = !isErr && Boolean(
    rawResult &&
    (rawResult.success === true ||
     rawResult.open === true ||
     rawResult.alive === true ||
     rawResult.reachable === true ||
     rawResult.healthy === true ||
     (rawResult.status && (rawResult.status === 'OPEN' || rawResult.status === 'ok' || rawResult.status === 'RESOLVED' || rawResult.status === 'VERIFIED')))
  );

  let status = isSuccess ? 'ok' : 'failed';
  if (rawResult?.status === 'SECURITY_BLOCKED' || rawResult?.status === 'ACCESS_DENIED') {
    status = 'denied';
  } else if (rawResult?.status === 'FILTERED' || rawResult?.status === 'DEGRADED') {
    status = 'degraded';
  } else if (rawResult?.status === 'partial') {
    status = 'partial';
  }

  let errorObj = null;
  if (!isSuccess) {
    const code = rawResult?.errorCode || rawResult?.code || (isErr ? rawResult.name : 'PROTOCOL_PROBE_ERROR');
    const msg = rawResult?.error || (isErr ? rawResult.message : (rawResult?.summary || 'Protocol probe failed or unanswered'));
    errorObj = {
      code: String(code),
      message: String(msg),
      category: rawResult?.errorCategory || 'NETWORK_TRANSPORT_ERROR',
      recoverable: rawResult?.recoverable !== false,
      ...(rawResult?.remediationHint ? { remediationHint: String(rawResult.remediationHint) } : {})
    };
  }

  return createEjiiResult({
    success: isSuccess,
    capabilityId: String(capabilityId || 'ejii.protocols.unknown'),
    requestId: options.requestId,
    correlationId: options.correlationId,
    observedAt: options.observedAt || new Date().toISOString(),
    source: {
      module: String(capabilityId || 'ejii.protocols.unknown'),
      method: options.method || 'wire_socket_probe',
      privilege: options.privilege || 'unprivileged',
      platform: process.platform,
      fidelity: options.fidelity || 'live'
    },
    status,
    data: rawResult,
    evidenceIds: options.evidenceIds || [],
    warnings: options.warnings || [],
    error: errorObj
  });
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
  validateEjiiResult,
  wrapProtocolProbeResult,
  isEjiiResult
};
