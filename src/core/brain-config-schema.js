/**
 * EJII AI Brain Dynamic Configuration Schema & Deterministic Gatekeeper Contract
 * Enforces strict type safety, numeric boundary invariants, and SHA-256 fingerprinting
 * for autonomous self-updating AI Brain parameters without external dependencies.
 */

'use strict';

const crypto = require('crypto');

const DEFAULT_BRAIN_CONFIG = Object.freeze({
  version: '1.0.0',
  brainTickIntervalMs: 5000,
  maxEvents: 500,
  maxHistory: 100,
  adaptiveLatencyMultiplier: 3.0,
  minimumLatencyFloorMs: 100,
  minBaselineSamples: 3,
  establishedSampleThreshold: 5,
  incidentPruneTimeoutMs: 300000,
  anomalyDriftTriggerRatio: 0.15,
  minEventsForSelfUpdate: 10,
  selfUpdateCooldownMs: 60000,
  watchdogWindowMs: 30000,
  maxConsecutiveRollbacks: 3
});

const SCHEMA_BOUNDS = Object.freeze({
  brainTickIntervalMs: { type: 'integer', min: 1000, max: 60000 },
  maxEvents: { type: 'integer', min: 50, max: 5000 },
  maxHistory: { type: 'integer', min: 20, max: 1000 },
  adaptiveLatencyMultiplier: { type: 'number', min: 1.5, max: 10.0 },
  minimumLatencyFloorMs: { type: 'integer', min: 10, max: 2000 },
  minBaselineSamples: { type: 'integer', min: 2, max: 50 },
  establishedSampleThreshold: { type: 'integer', min: 3, max: 100 },
  incidentPruneTimeoutMs: { type: 'integer', min: 30000, max: 1800000 },
  anomalyDriftTriggerRatio: { type: 'number', min: 0.05, max: 0.80 },
  minEventsForSelfUpdate: { type: 'integer', min: 5, max: 500 },
  selfUpdateCooldownMs: { type: 'integer', min: 5000, max: 3600000 },
  watchdogWindowMs: { type: 'integer', min: 5000, max: 300000 },
  maxConsecutiveRollbacks: { type: 'integer', min: 1, max: 10 }
});

class BrainConfigValidationError extends Error {
  constructor(issues) {
    super(`BrainConfig validation failed: ${issues.map(i => `${i.field}: ${i.message}`).join('; ')}`);
    this.name = 'BrainConfigValidationError';
    this.code = 'BRAIN_CONFIG_SCHEMA_VIOLATION';
    this.issues = issues;
  }
}

/**
 * Strictly validates a proposed configuration object against SCHEMA_BOUNDS.
 * Rejects unknown keys, prototype pollution, non-finite numbers, and out-of-range values.
 */
function parseBrainConfig(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new BrainConfigValidationError([{ field: 'root', message: 'Configuration must be a plain JSON object.' }]);
  }

  const issues = [];
  const allowedKeys = new Set(['version', ...Object.keys(SCHEMA_BOUNDS)]);

  for (const key of Object.keys(input)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      issues.push({ field: key, message: 'Prototype pollution keys are strictly prohibited.' });
      continue;
    }
    if (!allowedKeys.has(key)) {
      issues.push({ field: key, message: `Unrecognized configuration key "${key}".` });
    }
  }

  const merged = {
    version: typeof input.version === 'string' && /^[0-9]+\.[0-9]+\.[0-9]+$/.test(input.version)
      ? input.version
      : DEFAULT_BRAIN_CONFIG.version
  };

  for (const [key, rule] of Object.entries(SCHEMA_BOUNDS)) {
    const val = input[key] !== undefined ? input[key] : DEFAULT_BRAIN_CONFIG[key];

    if (typeof val !== 'number' || !Number.isFinite(val)) {
      issues.push({ field: key, message: `Expected finite ${rule.type}, received ${typeof val} (${val}).` });
      continue;
    }

    if (rule.type === 'integer' && !Number.isInteger(val)) {
      issues.push({ field: key, message: `Expected integer for "${key}", received float ${val}.` });
      continue;
    }

    if (val < rule.min || val > rule.max) {
      issues.push({ field: key, message: `Value ${val} out of bounds [${rule.min},${rule.max}].` });
      continue;
    }

    merged[key] = rule.type === 'number' ? Number(val.toFixed(4)) : val;
  }

  // Cross-field logical invariant: establishedSampleThreshold >= minBaselineSamples
  if (
    typeof merged.establishedSampleThreshold === 'number' &&
    typeof merged.minBaselineSamples === 'number' &&
    merged.establishedSampleThreshold < merged.minBaselineSamples
  ) {
    issues.push({
      field: 'establishedSampleThreshold',
      message: `establishedSampleThreshold (${merged.establishedSampleThreshold}) must be >= minBaselineSamples (${merged.minBaselineSamples}).`
    });
  }

  if (issues.length > 0) {
    throw new BrainConfigValidationError(issues);
  }

  return merged;
}

/**
 * Safe parse wrapper returning { success, data, error }
 */
function safeParseBrainConfig(input) {
  try {
    const data = parseBrainConfig(input);
    return { success: true, data };
  } catch (error) {
    return {
      success: false,
      error,
      issues: error.issues || [{ field: 'unknown', message: error.message }]
    };
  }
}

/**
 * Computes a deterministic SHA-256 hash over the canonical configuration fields.
 */
function hashBrainConfig(config) {
  const canonical = {};
  for (const key of Object.keys(DEFAULT_BRAIN_CONFIG).sort()) {
    canonical[key] = config[key];
  }
  return crypto.createHash('sha256').update(JSON.stringify(canonical)).digest('hex');
}

module.exports = {
  DEFAULT_BRAIN_CONFIG,
  SCHEMA_BOUNDS,
  BrainConfigValidationError,
  parseBrainConfig,
  safeParseBrainConfig,
  hashBrainConfig
};
