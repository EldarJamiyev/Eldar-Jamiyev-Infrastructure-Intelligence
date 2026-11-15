/**
 * EJII Quarantine Rollback Circuit Breaker
 *
 * Tracks remediation execution frequency and failure rates per target infrastructure node.
 * Automatically trips a quarantine circuit to prevent flapping action storms and cascading brownouts.
 * Dual-Maintenance TypeScript Reference.
 */

export interface QuarantineStatusReceipt {
  deviceId: string;
  isQuarantined: boolean;
  failureCount: number;
  quarantineReason?: string;
  timestamp: number;
}

export class QuarantineRollbackCircuitBreaker {
  private executionHistory: Map<string, number[]> = new Map();
  private quarantinedDevices: Map<string, { quarantinedAt: number; reason: string }> = new Map();
  private thresholdCount: number = 3;
  private windowMs: number = 600000; // 10 minutes

  constructor(thresholdCount: number = 3, windowMs: number = 600000) {
    this.thresholdCount = thresholdCount;
    this.windowMs = windowMs;
  }

  /**
   * Records an execution event for a target device and evaluates the quarantine circuit.
   */
  public recordActionExecution(
    deviceId: string,
    actionId: string
  ): { isQuarantined: boolean; failureCount: number } {
    const now = Date.now();

    if (!this.executionHistory.has(deviceId)) {
      this.executionHistory.set(deviceId, []);
    }

    const history = this.executionHistory.get(deviceId)!;
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
  public isDeviceQuarantined(deviceId: string): boolean {
    return this.quarantinedDevices.has(deviceId);
  }

  /**
   * Releases a device from quarantine.
   */
  public releaseQuarantine(deviceId: string): boolean {
    return this.quarantinedDevices.delete(deviceId);
  }

  /**
   * Resets execution history for a device.
   */
  public resetDeviceHistory(deviceId: string): void {
    this.executionHistory.delete(deviceId);
    this.quarantinedDevices.delete(deviceId);
  }

  /**
   * Returns operational circuit breaker metrics.
   */
  public getMetrics(): { devicesMonitored: number; quarantinedDevicesCount: number } {
    return {
      devicesMonitored: this.executionHistory.size,
      quarantinedDevicesCount: this.quarantinedDevices.size
    };
  }
}

export const quarantineRollbackCircuitBreaker = new QuarantineRollbackCircuitBreaker();
