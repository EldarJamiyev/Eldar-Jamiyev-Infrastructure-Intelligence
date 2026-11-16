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
    this.db = options.dbHandle || db;
    this.physicalDetector = typeof options.physicalDetector === 'function' ? options.physicalDetector : getPhysicalNetworkInfo;
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
      if (!parsed || typeof parsed !== 'object' || !parsed.spec || typeof parsed.spec !== 'object') {
        this.cachedManifest = {
          manifestPresent: false,
          manifestPath: this.manifestPath,
          status: 'MANIFEST_INVALID',
          error: 'Desired infrastructure state manifest JSON is missing required "spec" object.',
          desiredStateHash: null,
          spec: null
        };
        return this.cachedManifest;
      }
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
      const isSyntaxOrSchema = err instanceof SyntaxError || (err && /JSON/i.test(String(err.message || '')));
      this.cachedManifest = {
        manifestPresent: false,
        manifestPath: this.manifestPath || null,
        status: isSyntaxOrSchema ? 'MANIFEST_INVALID' : 'MANIFEST_UNREADABLE',
        error: err && err.message ? err.message : String(err),
        desiredStateHash: null,
        spec: null
      };
      return this.cachedManifest;
    }
  }

  detectInfrastructureDrift() {
    const manifest = this.loadDesiredStateManifest();
    const netInfo = this.physicalDetector({ forceRefresh: false });

    if (!manifest.manifestPresent || !manifest.spec) {
      const observedPayload = JSON.stringify({ drifts: [], localIp: netInfo.localIp, subnet: netInfo.subnetCidr });
      const observedStateHash = crypto.createHash('sha256').update(observedPayload).digest('hex');
      return {
        status: manifest.status && manifest.status !== 'MANIFEST_LOADED' ? manifest.status : 'MANIFEST_MISSING',
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
    const liveStateErrors = [];

    // 1. Topology Node Alignment Check
    try {
      const appNode = this.db.prepare("SELECT * FROM topology_nodes WHERE id = 'NODE-APP-01'").get();
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

      const gwNode = this.db.prepare("SELECT * FROM topology_nodes WHERE id = 'NODE-GW-01'").get();
      const expectedGw = (netInfo.gatewayVerified && netInfo.defaultGateway)
        ? netInfo.defaultGateway
        : 'NO_DEFAULT_ROUTE_OBSERVED';
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
    } catch (err) {
      liveStateErrors.push({ check: 'topology_nodes', error: err && err.message ? err.message : String(err) });
    }

    // 2. Office Equipment & APIPA Check
    try {
      const apipaRows = this.db.prepare("SELECT device_id, device_name, current_ip FROM office_equipment_inventory WHERE current_ip LIKE '169.254.%' OR is_apipa_fault = 1").all();
      const maxApipa = (spec.officeLanCompliance && spec.officeLanCompliance.maxApipaDevicesAllowed) || 0;
      if (apipaRows.length > maxApipa) {
        drifts.push({
          driftType: 'DRIFT_APIPA_DEVICE_DETECTED',
          severity: 'HIGH',
          target: 'office_equipment_inventory',
          expected: `<= ${maxApipa} APIPA devices`,
          actual: `${apipaRows.length} APIPA devices (${apipaRows.map(r => r.current_ip).join(', ')})`,
          remediation: 'Release and renew DHCP lease or re-assign static IP to equipment',
          autoReconcilable: false
        });
      }
    } catch (err) {
      liveStateErrors.push({ check: 'office_equipment_inventory', error: err && err.message ? err.message : String(err) });
    }

    // 3. Explicit Custom Invariant Drifts (e.g. requiredNodesPresent in desired-state spec)
    if (Array.isArray(topoInvariants.requiredNodeIds)) {
      for (const reqNodeId of topoInvariants.requiredNodeIds) {
        try {
          const found = this.db.prepare('SELECT id FROM topology_nodes WHERE id = ?').get(String(reqNodeId));
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
        } catch (err) {
          liveStateErrors.push({ check: `required_node:${reqNodeId}`, error: err && err.message ? err.message : String(err) });
        }
      }
    }

    const liveStateAvailable = liveStateErrors.length === 0;
    const status = !liveStateAvailable
      ? 'LIVE_STATE_UNAVAILABLE'
      : (drifts.length > 0 ? 'DRIFT_DETECTED' : 'IN_SYNC');

    const observedPayload = JSON.stringify({ drifts, liveStateAvailable, localIp: netInfo.localIp, subnet: netInfo.subnetCidr });
    const observedStateHash = crypto.createHash('sha256').update(observedPayload).digest('hex');

    return {
      status,
      liveStateAvailable,
      ...(liveStateErrors.length > 0 ? { liveStateErrors } : {}),
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

    if (!driftReport.manifestPresent || ['MANIFEST_MISSING', 'MANIFEST_INVALID', 'MANIFEST_UNREADABLE'].includes(driftReport.status)) {
      this.lastReconciliationTime = new Date().toISOString();
      const lifecycleState = driftReport.status || 'MANIFEST_MISSING';
      return {
        reconciled: false,
        reconciliationLifecycleState: lifecycleState,
        manifestPresent: false,
        error: driftReport.error || null,
        actionsExecuted,
        postReconciliationStatus: lifecycleState,
        remainingDrifts: []
      };
    }

    if (driftReport.status === 'LIVE_STATE_UNAVAILABLE') {
      this.lastReconciliationTime = new Date().toISOString();
      return {
        reconciled: false,
        reconciliationLifecycleState: 'LIVE_STATE_UNAVAILABLE',
        manifestPresent: true,
        liveStateErrors: driftReport.liveStateErrors || [],
        actionsExecuted,
        postReconciliationStatus: 'LIVE_STATE_UNAVAILABLE',
        remainingDrifts: driftReport.drifts || []
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
        syncTopologyWithCurrentLocation(this.db);
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
