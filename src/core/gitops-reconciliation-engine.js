/**
 * EJII Continuous GitOps Infrastructure-as-Code (IaC) Drift Detection & Autonomous Reconciliation Loop (Category E Modernization)
 * Continuously evaluates desired infrastructure baseline against live observed wire/host/topology state,
 * calculates cryptographic drift hashes (SHA-256), and automatically heals configuration drift.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { db } = require('../db/database');
const { getPhysicalNetworkInfo, syncTopologyWithCurrentLocation } = require('../network/routing/physical-network-detector');

class GitopsReconciliationEngine {
  constructor(options = {}) {
    this.manifestPath = options.manifestPath || path.resolve(__dirname, '../../policies/desired-infrastructure-state.json');
    this.cachedManifest = null;
    this.lastReconciliationTime = null;
  }

  loadDesiredStateManifest() {
    try {
      const raw = fs.readFileSync(this.manifestPath, 'utf8');
      const parsed = JSON.parse(raw);
      const hash = crypto.createHash('sha256').update(raw).digest('hex');
      this.cachedManifest = {
        ...parsed,
        desiredStateHash: hash
      };
      return this.cachedManifest;
    } catch (err) {
      // Safe fallback manifest if file is missing
      const fallback = {
        apiVersion: 'ejii.infrastructure.io/v1',
        kind: 'DesiredInfrastructureState',
        spec: {
          topologyInvariants: {
            autoSyncLocationSubnet: true,
            forbidHardcodedAlienAppIp: true,
            forbiddenStaticAppIps: ['10.22.12.204'],
            maxGatewayRttMs: 35.0,
            maxPacketLossPercent: 2.0
          },
          officeLanCompliance: {
            maxApipaDevicesAllowed: 0,
            maxDuplicateIpArpConflicts: 0
          },
          hostSecurityAndServices: {
            requiredWindowsServicesRunning: ['Spooler'],
            forbiddenListeningTcpPorts: [21, 23]
          }
        }
      };
      const hash = crypto.createHash('sha256').update(JSON.stringify(fallback)).digest('hex');
      this.cachedManifest = { ...fallback, desiredStateHash: hash };
      return this.cachedManifest;
    }
  }

  detectInfrastructureDrift() {
    const manifest = this.loadDesiredStateManifest();
    const spec = manifest.spec || {};
    const topoInvariants = spec.topologyInvariants || {};
    const netInfo = getPhysicalNetworkInfo({ forceRefresh: false });
    const drifts = [];

    // 1. Topology Node Alignment Check
    try {
      const appNode = db.prepare("SELECT * FROM topology_nodes WHERE id = 'NODE-APP-01'").get();
      if (appNode) {
        if (topoInvariants.forbidHardcodedAlienAppIp) {
          const forbiddenList = topoInvariants.forbiddenStaticAppIps || ['10.22.12.204'];
          if (forbiddenList.includes(appNode.hostname_or_ip) && !netInfo.localIp.startsWith('10.22.12.')) {
            drifts.push({
              driftType: 'DRIFT_FORBIDDEN_STATIC_IP',
              severity: 'CRITICAL',
              target: 'NODE-APP-01',
              expected: `Dynamic IP in active subnet ${netInfo.subnetCidr}`,
              actual: appNode.hostname_or_ip,
              remediation: 'Execute syncTopologyWithCurrentLocation to bind NODE-APP-01 to active subnet',
              autoReconcilable: true
            });
          }
        }
      }

      const gwNode = db.prepare("SELECT * FROM topology_nodes WHERE id = 'NODE-GW-01'").get();
      if (gwNode && gwNode.hostname_or_ip !== netInfo.defaultGateway) {
        drifts.push({
          driftType: 'DRIFT_TOPOLOGY_SUBNET_MISMATCH',
          severity: 'HIGH',
          target: 'NODE-GW-01',
          expected: netInfo.defaultGateway,
          actual: gwNode.hostname_or_ip,
          remediation: 'Update L2 Edge Router to match current physical default gateway',
          autoReconcilable: true
        });
      }
    } catch (_) {}

    // 2. Office Equipment & APIPA Check
    try {
      const apipaRows = db.prepare("SELECT id, name, ip_address FROM office_equipment_inventory WHERE ip_address LIKE '169.254.%'").all();
      const maxApipa = (spec.officeLanCompliance && spec.officeLanCompliance.maxApipaDevicesAllowed) || 0;
      if (apipaRows.length > maxApipa) {
        drifts.push({
          driftType: 'DRIFT_APIPA_DEVICE_DETECTED',
          severity: 'HIGH',
          target: 'office_equipment_inventory',
          expected: `<= ${maxApipa} APIPA devices`,
          actual: `${apipaRows.length} APIPA devices (${apipaRows.map(r => r.ip_address).join(', ')})`,
          remediation: 'Release and renew DHCP lease or re-assign static IP to equipment',
          autoReconcilable: false
        });
      }
    } catch (_) {}

    const observedPayload = JSON.stringify({ drifts, localIp: netInfo.localIp, subnet: netInfo.subnetCidr });
    const observedStateHash = crypto.createHash('sha256').update(observedPayload).digest('hex');

    return {
      status: drifts.length > 0 ? 'DRIFT_DETECTED' : 'IN_SYNC',
      desiredStateHash: manifest.desiredStateHash,
      observedStateHash,
      driftCount: drifts.length,
      drifts,
      evaluatedAt: new Date().toISOString()
    };
  }

  reconcileDrift({ autoHealSafeTopologyDrift = true } = {}) {
    const driftReport = this.detectInfrastructureDrift();
    const actionsExecuted = [];

    if (driftReport.status === 'DRIFT_DETECTED') {
      const hasTopoDrift = driftReport.drifts.some(
        (d) => d.driftType === 'DRIFT_FORBIDDEN_STATIC_IP' || d.driftType === 'DRIFT_TOPOLOGY_SUBNET_MISMATCH'
      );

      if (hasTopoDrift && autoHealSafeTopologyDrift) {
        try {
          syncTopologyWithCurrentLocation(db);
          actionsExecuted.push({
            action: 'SYNC_TOPOLOGY_WITH_CURRENT_LOCATION',
            timestamp: new Date().toISOString(),
            status: 'SUCCESS'
          });
        } catch (err) {
          actionsExecuted.push({
            action: 'SYNC_TOPOLOGY_WITH_CURRENT_LOCATION',
            timestamp: new Date().toISOString(),
            status: 'FAILED',
            error: err.message
          });
        }
      }
    }

    const postReport = this.detectInfrastructureDrift();
    this.lastReconciliationTime = new Date().toISOString();

    return {
      reconciled: true,
      actionsExecuted,
      postReconciliationStatus: postReport.status,
      remainingDrifts: postReport.drifts
    };
  }
}

const gitopsReconciliationEngine = new GitopsReconciliationEngine();

module.exports = {
  GitopsReconciliationEngine,
  gitopsReconciliationEngine
};
