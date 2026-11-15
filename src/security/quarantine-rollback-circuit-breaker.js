/**
 * EJII Quarantine Rollback Circuit Breaker
 *
 * Tracks remediation execution frequency and failure rates per target infrastructure node.
 * Automatically trips a quarantine circuit to prevent flapping action storms and cascading brownouts.
 * Dual-Maintenance CommonJS Implementation.
 */

'use strict';

class QuarantineRollbackCircuitBreaker {
  constructor(thresholdCount = 3, windowMs = 600000) {
    this.executionHistory = new Map();
    this.quarantinedDevices = new Map();
    this.thresholdCount = thresholdCount;
    this.windowMs = windowMs;
  }

  /**
   * Records an execution event for a target device and evaluates the quarantine circuit.
   */
  recordActionExecution(deviceId, actionId) {
    const now = Date.now();

    if (!this.executionHistory.has(deviceId)) {
      this.executionHistory.set(deviceId, []);
    }

    const history = this.executionHistory.get(deviceId);
    // Prune history outside window
    const recent = history.filter((t) => now - t <= this.windowMs);
    recent.push(now);
    this.executionHistory.set(deviceId, recent);

    if (recent.length >= this.thresholdCount) {
      this.quarantinedDevices.set(deviceId, {
        quarantinedAt: now,
        reason: `Exceeded threshold of ${this.thresholdCount} actions in ${this.windowMs / 1000}s window (trigger: ${actionId})`
      });

      return {
        isQuarantined: true,
        failureCount: recent.length
      };
    }

    const isAlreadyQuarantined = this.quarantinedDevices.has(deviceId);
    return {
      isQuarantined: isAlreadyQuarantined,
      failureCount: recent.length
    };
  }

  /**
   * Checks whether a device is currently quarantined.
   */
  isDeviceQuarantined(deviceId) {
    return this.quarantinedDevices.has(deviceId);
  }

  /**
   * Releases a device from quarantine.
   */
  releaseQuarantine(deviceId) {
    return this.quarantinedDevices.delete(deviceId);
  }

  /**
   * Resets execution history for a device.
   */
  resetDeviceHistory(deviceId) {
    this.executionHistory.delete(deviceId);
    this.quarantinedDevices.delete(deviceId);
  }

  /**
   * Returns operational circuit breaker metrics.
   */
  getMetrics() {
    return {
      devicesMonitored: this.executionHistory.size,
      quarantinedDevicesCount: this.quarantinedDevices.size
    };
  }
}

const quarantineRollbackCircuitBreaker = new QuarantineRollbackCircuitBreaker();

module.exports = {
  QuarantineRollbackCircuitBreaker,
  quarantineRollbackCircuitBreaker
};
