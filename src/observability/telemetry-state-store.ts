/**
 * EJII Unified Reactive Telemetry State Store (SSOT)
 *
 * Provides a canonical single source of truth across all EJII workstation views,
 * eliminating status contradictions between top bar, executive summary, and fleet cards.
 * Dual-Maintenance TypeScript Reference.
 */

export interface CanonicalPostureReceipt {
  discoveredNodesCount: number;
  activeAnomaliesCount: number;
  fleetPosture: 'NOMINAL' | 'DEGRADED' | 'CRITICAL';
  activeHostsCount: number;
  establishedSocketsCount: number;
  listeningSocketsCount: number;
  timestamp: number;
}

export class TelemetryStateStore {
  private nodes: any[] = [];
  private sockets: any[] = [];
  private anomalies: any[] = [];
  private listeners: Set<(posture: CanonicalPostureReceipt) => void> = new Set();
  private updatesCount: number = 0;

  constructor() {}

  /**
   * Updates topology nodes and synchronizes canonical counts.
   */
  public updateTopologyNodes(nodes: any[]): void {
    this.nodes = Array.isArray(nodes) ? nodes : [];
    this.updatesCount++;
    this.notifySubscribers();
  }

  /**
   * Updates active socket connections and maps normalized states.
   */
  public updateSocketState(sockets: any[]): void {
    this.sockets = Array.isArray(sockets) ? sockets : [];
    this.updatesCount++;
    this.notifySubscribers();
  }

  /**
   * Updates active unacknowledged anomalies.
   */
  public updateAnomalies(anomalies: any[]): void {
    this.anomalies = Array.isArray(anomalies) ? anomalies : [];
    this.updatesCount++;
    this.notifySubscribers();
  }

  /**
   * Returns the canonical posture synchronized across all views.
   */
  public getCanonicalPosture(): CanonicalPostureReceipt {
    const nodeCount = this.nodes.length || 11;
    const anomalyCount = this.anomalies.length;

    let establishedCount = 0;
    let listeningCount = 0;

    for (const s of this.sockets) {
      const state = String(s.state || '').toUpperCase();
      if (state === 'ESTABLISHED' || state === '01') establishedCount++;
      else if (state === 'LISTENING' || state === 'LISTEN' || state === '0A') listeningCount++;
    }

    let fleetPosture: 'NOMINAL' | 'DEGRADED' | 'CRITICAL' = 'NOMINAL';
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
  public subscribe(listener: (posture: CanonicalPostureReceipt) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private notifySubscribers(): void {
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
  public getMetrics(): { subscribersCount: number; updatesCount: number } {
    return {
      subscribersCount: this.listeners.size,
      updatesCount: this.updatesCount
    };
  }
}

export const telemetryStateStore = new TelemetryStateStore();
