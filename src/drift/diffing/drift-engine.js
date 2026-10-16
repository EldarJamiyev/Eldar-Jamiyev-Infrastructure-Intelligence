/**
 * EJI Configuration Drift Diff Engine
 * Authoritative cryptographic comparison between expected baseline state and live observed system state.
 */

const crypto = require('crypto');
const DriftRepository = require('../../database/repositories/drift-repository');

class DriftEngine {
  /**
   * Compute deterministic SHA-256 hash of a JSON object (canonical key ordering)
   */
  static computeHash(data) {
    const canonical = this.canonicalize(data);
    return crypto.createHash('sha256').update(JSON.stringify(canonical)).digest('hex');
  }

  /**
   * Sort keys alphabetically for deterministic hashing
   */
  static canonicalize(obj) {
    if (obj === null || typeof obj !== 'object') {
      return obj;
    }
    if (Array.isArray(obj)) {
      return obj.map(item => this.canonicalize(item));
    }
    const sorted = {};
    const keys = Object.keys(obj).sort();
    for (const key of keys) {
      sorted[key] = this.canonicalize(obj[key]);
    }
    return sorted;
  }

  /**
   * Perform deep structural diff between expected and observed state
   */
  static diffStates(expected, observed, path = '') {
    const added = [];
    const removed = [];
    const modified = [];

    // Check for removed or modified keys
    if (expected && typeof expected === 'object' && !Array.isArray(expected)) {
      for (const key of Object.keys(expected)) {
        const currentPath = path ? `${path}.${key}` : key;
        if (!(key in observed)) {
          removed.push({
            path: currentPath,
            expected: expected[key],
            observed: undefined
          });
        } else if (typeof expected[key] === 'object' && expected[key] !== null) {
          const subDiff = this.diffStates(expected[key], observed[key], currentPath);
          added.push(...subDiff.added);
          removed.push(...subDiff.removed);
          modified.push(...subDiff.modified);
        } else if (expected[key] !== observed[key]) {
          modified.push({
            path: currentPath,
            expected: expected[key],
            observed: observed[key]
          });
        }
      }

      // Check for added keys in observed
      for (const key of Object.keys(observed)) {
        const currentPath = path ? `${path}.${key}` : key;
        if (!(key in expected)) {
          added.push({
            path: currentPath,
            expected: undefined,
            observed: observed[key]
          });
        }
      }
    } else if (Array.isArray(expected) && Array.isArray(observed)) {
      // Set-based array comparison
      const expectedSet = new Set(expected.map(x => (typeof x === 'object' ? JSON.stringify(x) : x)));
      const observedSet = new Set(observed.map(x => (typeof x === 'object' ? JSON.stringify(x) : x)));

      for (const item of expected) {
        const key = typeof item === 'object' ? JSON.stringify(item) : item;
        if (!observedSet.has(key)) {
          removed.push({ path: `${path}[]`, expected: item, observed: undefined });
        }
      }
      for (const item of observed) {
        const key = typeof item === 'object' ? JSON.stringify(item) : item;
        if (!expectedSet.has(key)) {
          added.push({ path: `${path}[]`, expected: undefined, observed: item });
        }
      }
    } else if (expected !== observed) {
      modified.push({
        path: path || 'root',
        expected,
        observed
      });
    }

    const hasDrift = added.length > 0 || removed.length > 0 || modified.length > 0;
    return {
      hasDrift,
      added,
      removed,
      modified,
      diffSummary: `${added.length} added, ${removed.length} removed, ${modified.length} modified`
    };
  }

  /**
   * Determine drift severity based on modified paths and critical infrastructure terms
   */
  static assessDriftSeverity(diff) {
    if (!diff.hasDrift) return 'P4_LOW';

    const criticalTerms = ['firewall', 'security', 'dns', 'sshd', 'root', 'admin', 'auth', 'port', 'gateway'];
    const allItems = [...diff.modified, ...diff.removed, ...diff.added];

    for (const item of allItems) {
      const pathLower = String(item.path).toLowerCase();
      const valStr = JSON.stringify(item.expected) + JSON.stringify(item.observed);
      if (criticalTerms.some(t => pathLower.includes(t) || valStr.toLowerCase().includes(t))) {
        return 'P1_CRITICAL';
      }
    }

    if (diff.modified.length > 3 || diff.removed.length > 2) {
      return 'P2_HIGH';
    }

    return 'P3_MEDIUM';
  }

  /**
   * Evaluate drift for a given target CI against its baseline in the database
   */
  static evaluateCiDrift(baselineId, observedState) {
    const baseline = DriftRepository.getBaselineById(baselineId);
    if (!baseline) throw new Error(`Baseline ${baselineId} not found`);

    const diff = this.diffStates(baseline.expectedState, observedState);
    const severity = this.assessDriftSeverity(diff);

    const observation = DriftRepository.recordObservation({
      baselineId: baseline.id,
      targetCiId: baseline.target_ci_id,
      observedState,
      diff,
      hasDrift: diff.hasDrift,
      severity
    });

    return {
      baseline,
      diff,
      observation,
      hasDrift: diff.hasDrift,
      severity
    };
  }
}

module.exports = DriftEngine;
