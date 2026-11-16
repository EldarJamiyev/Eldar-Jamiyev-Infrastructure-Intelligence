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
      if (!this.manifestPath || !fs.existsSync(this.manifestPath)) {
        this.cachedManifest = {
          manifestPresent: false,
          manifestPath: this.manifestPath || null,
          status: 'MANIFEST_MISSING',
          desiredStateHash: null,
          spec: null
        };
        return this.cachedManifest;
      }
      const raw = fs.readFileSync(this.manifestPath, 'utf8');
      const parsed = JSON.parse(raw);
      const hash = crypto.createHash('sha256').update(raw).digest('hex');
      this.cachedManifest = {
        ...parsed,
        manifestPresent: true,
        manifestPath: this.manifestPath,
        status: 'MANIFEST_LOADED',
        desiredStateHash: hash
      };
      return this.cachedManifest;
    } catch (err) {
      this.cachedManifest = {
        manifestPresent: false,
        manifestPath: this.manifestPath || null,
        status: 'MANIFEST_INVALID_OR_UNREADABLE',
        error: err && err.message ? err.message : String(err),
        desiredStateHash: null,
        spec: null
      };
      return this.cachedManifest;
    }
  }

  detectInfrastructureDrift() {
    const manifest = this.loadDesiredStateManifest();
    const netInfo = getPhysicalNetworkInfo({ forceRefresh: false });

    if (!manifest.manifestPresent || !manifest.spec) {
      const observedPayload = JSON.stringify({ drifts: [], localIp: netInfo.localIp, subnet: netInfo.subnetCidr });
      const observedStateHash = crypto.createHash('sha256').update(observedPayload).digest('hex');
      return {
        status: manifest.status || 'MANIFEST_MISSING',
        manifestPresent: false,
        manifestPath: manifest.manifestPath,
        error: manifest.error || 'Desired infrastructure state manifest file not found on disk.',
        desiredStateHash: null,
        observedStateHash,
        driftCount: 0,
        drifts: [],
        evaluatedAt: new Date().toISOString()
      };
    }

    const spec = manifest.spec || {};
    const topoInvariants = spec.topologyInvariants || {};
    const drifts = [];

    // 1. Topology Node Alignment Check
    try {
      const appNode = db.prepare("SELECT * FROM topology_nodes WHERE id = 'NODE-APP-01'").get();
      if (appNode) {
        if (topoInvariants.forbidHardcodedAlienAppIp) {
          const forbiddenList = topoInvariants.forbiddenStaticAppIps || ['10.22.12.204'];
          if (forbiddenList.includes(appNode.hostname_or_ip) && !(netInfo.localIp || '').startsWith('10.22.12.')) {
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
      const expectedGw = netInfo.defaultGateway || '127.0.0.1';
      if (gwNode && gwNode.hostname_or_ip !== expectedGw) {
        drifts.push({
          driftType: 'DRIFT_TOPOLOGY_SUBNET_MISMATCH',
          severity: 'HIGH',
          target: 'NODE-GW-01',
          expected: expectedGw,
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

    // 3. Explicit Custom Invariant Drifts (e.g. requiredNodesPresent in desired-state spec)
    if (Array.isArray(topoInvariants.requiredNodeIds)) {
      for (const reqNodeId of topoInvariants.requiredNodeIds) {
        try {
          const found = db.prepare('SELECT id FROM topology_nodes WHERE id = ?').get(String(reqNodeId));
          if (!found) {
            drifts.push({
              driftType: 'DRIFT_MISSING_REQUIRED_TOPOLOGY_NODE',
              severity: 'HIGH',
              target: String(reqNodeId),
              expected: `Topology node ${reqNodeId} present`,
              actual: 'MISSING',
              remediation: `Provision or discover required node ${reqNodeId}`,
              autoReconcilable: false
            });
          }
        } catch (_) {}
      }
    }

    const observedPayload = JSON.stringify({ drifts, localIp: netInfo.localIp, subnet: netInfo.subnetCidr });
    const observedStateHash = crypto.createHash('sha256').update(observedPayload).digest('hex');

    return {
      status: drifts.length > 0 ? 'DRIFT_DETECTED' : 'IN_SYNC',
      manifestPresent: true,
      manifestPath: manifest.manifestPath,
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

    if (!driftReport.manifestPresent || driftReport.status === 'MANIFEST_MISSING' || driftReport.status === 'MANIFEST_INVALID_OR_UNREADABLE') {
      this.lastReconciliationTime = new Date().toISOString();
      return {
        reconciled: false,
        reconciliationLifecycleState: 'MANIFEST_MISSING',
        manifestPresent: false,
        actionsExecuted,
        postReconciliationStatus: driftReport.status,
        remainingDrifts: []
      };
    }

    if (driftReport.status === 'IN_SYNC') {
      this.lastReconciliationTime = new Date().toISOString();
      return {
        reconciled: true,
        reconciliationLifecycleState: 'NO_DRIFT_DETECTED',
        manifestPresent: true,
        actionsExecuted,
        postReconciliationStatus: 'IN_SYNC',
        remainingDrifts: []
      };
    }

    const hasTopoDrift = driftReport.drifts.some(
      (d) => d.driftType === 'DRIFT_FORBIDDEN_STATIC_IP' || d.driftType === 'DRIFT_TOPOLOGY_SUBNET_MISMATCH'
    );
    const hasAnyAutoReconcilable = driftReport.drifts.some((d) => d.autoReconcilable === true);

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

    const postReport = this.detectInfrastructureDrift();
    this.lastReconciliationTime = new Date().toISOString();

    const hadActionFailure = actionsExecuted.some((a) => a.status === 'FAILED');
    const remainingDrifts = Array.isArray(postReport.drifts) ? postReport.drifts : [];
    const reconciled = postReport.status === 'IN_SYNC' && remainingDrifts.length === 0 && !hadActionFailure;

    let reconciliationLifecycleState = 'DRIFT_DETECTED';
    if (reconciled) {
      reconciliationLifecycleState = 'POSTCONDITION_VERIFIED';
    } else if (hadActionFailure) {
      reconciliationLifecycleState = 'ACTION_FAILED';
    } else if (hasAnyAutoReconcilable && !autoHealSafeTopologyDrift) {
      reconciliationLifecycleState = 'AWAITING_OPERATOR_AUTHORIZATION';
    } else if (actionsExecuted.length === 0 && !hasAnyAutoReconcilable) {
      reconciliationLifecycleState = 'NO_PERMITTED_ACTION_AVAILABLE';
    } else if (actionsExecuted.length > 0 && remainingDrifts.length < driftReport.drifts.length && remainingDrifts.length > 0) {
      reconciliationLifecycleState = 'ACTION_PARTIALLY_COMPLETED';
    } else if (actionsExecuted.length > 0 && remainingDrifts.length > 0) {
      reconciliationLifecycleState = 'POSTCONDITION_VERIFICATION_FAILED';
    }

    return {
      reconciled,
      reconciliationLifecycleState,
      manifestPresent: true,
      actionsExecuted,
      postReconciliationStatus: postReport.status,
      remainingDrifts
    };
  }
}

const gitopsReconciliationEngine = new GitopsReconciliationEngine();

module.exports = {
  GitopsReconciliationEngine,
  gitopsReconciliationEngine
};
