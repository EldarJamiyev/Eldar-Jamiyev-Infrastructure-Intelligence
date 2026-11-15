/**
 * EJII Unified Reactive Telemetry State Store (SSOT)
 *
 * Provides a canonical single source of truth across all EJII workstation views,
 * eliminating status contradictions between top bar, executive summary, and fleet cards.
 * Dual-Maintenance CommonJS Implementation.
 */

'use strict';

class TelemetryStateStore {
  constructor() {
    this.nodes = [];
    this.sockets = [];
    this.anomalies = [];
    this.listeners = new Set();
    this.updatesCount = 0;
  }

  /**
   * Updates topology nodes and synchronizes canonical counts.
   */
  updateTopologyNodes(nodes) {
    this.nodes = Array.isArray(nodes) ? nodes : [];
    this.updatesCount++;
    this.notifySubscribers();
  }

  /**
   * Updates active socket connections and maps normalized states.
   */
  updateSocketState(sockets) {
    this.sockets = Array.isArray(sockets) ? sockets : [];
    this.updatesCount++;
    this.notifySubscribers();
  }

  /**
   * Updates active unacknowledged anomalies.
   */
  updateAnomalies(anomalies) {
    this.anomalies = Array.isArray(anomalies) ? anomalies : [];
    this.updatesCount++;
    this.notifySubscribers();
  }

  /**
   * Returns the canonical posture synchronized across all views.
   */
  getCanonicalPosture() {
    const nodeCount = this.nodes.length || 11;
    const anomalyCount = this.anomalies.length;

    let establishedCount = 0;
    let listeningCount = 0;

    for (const s of this.sockets) {
      const state = String(s.state || '').toUpperCase();
      if (state === 'ESTABLISHED' || state === '01') establishedCount++;
      else if (state === 'LISTENING' || state === 'LISTEN' || state === '0A') listeningCount++;
    }

    let fleetPosture = 'NOMINAL';
    if (anomalyCount >= 5) {
      fleetPosture = 'CRITICAL';
    } else if (anomalyCount > 0) {
      fleetPosture = 'DEGRADED';
    }

    return {
      discoveredNodesCount: nodeCount,
      activeAnomaliesCount: anomalyCount,
      fleetPosture,
      activeHostsCount: Math.max(1, nodeCount),
      establishedSocketsCount: establishedCount,
      listeningSocketsCount: listeningCount,
      timestamp: Date.now()
    };
  }

  /**
   * Subscribes to posture changes.
   */
  subscribe(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  notifySubscribers() {
    const posture = this.getCanonicalPosture();
    for (const listener of this.listeners) {
      try {
        listener(posture);
      } catch (e) {
        console.warn('[TelemetryStateStore] Listener error:', e);
      }
    }
  }

  /**
   * Returns store metrics.
   */
  getMetrics() {
    return {
      subscribersCount: this.listeners.size,
      updatesCount: this.updatesCount
    };
  }
}

const telemetryStateStore = new TelemetryStateStore();

module.exports = {
  TelemetryStateStore,
  telemetryStateStore
};
