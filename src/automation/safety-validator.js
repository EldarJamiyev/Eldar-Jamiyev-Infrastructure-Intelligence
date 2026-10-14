/**
 * EJII Automation Safety Validator
 * Pre-flight verification, protected process isolation, and risk classification.
 */

const { PROTECTED_SYSTEM_PROCESSES, AUTOMATION_TIERS } = require('../config');

/**
 * Validate an automation action before queuing or execution
 * @param {Object} params
 * @param {string} params.actionType
 * @param {string} params.targetHost
 * @param {string} params.targetResource
 * @param {Object} params.parameters
 */
function validateActionSafety({ actionType, targetHost, targetResource, parameters = {} }) {
  const cleanType = String(actionType).toLowerCase();

  // Tier 1: Read-Only Diagnostics
  if (cleanType === 'custom_diagnostic' || cleanType === 'ping_sweep') {
    return {
      allowed: true,
      tier: AUTOMATION_TIERS.TIER_1.level,
      requiresApproval: AUTOMATION_TIERS.TIER_1.requiresApproval,
      dryRunPlan: `Diagnostic scan on ${targetHost}. No system state changes will occur.`
    };
  }

  // Tier 2: Non-Destructive Remediation
  if (cleanType === 'flush_dns') {
    return {
      allowed: true,
      tier: AUTOMATION_TIERS.TIER_2.level,
      requiresApproval: AUTOMATION_TIERS.TIER_2.requiresApproval,
      dryRunPlan: `Clear and reset the DNS client resolver cache on ${targetHost || 'localhost'}. Zero downtime expected.`
    };
  }

  // Tier 3: Process Termination (Requires strict safety checks)
  if (cleanType === 'kill_process') {
    const processName = String(targetResource || '').toLowerCase().trim();
    const pid = parameters.pid ? parseInt(parameters.pid, 10) : null;

    if (!pid || pid <= 4 || !Number.isFinite(pid)) {
      return {
        allowed: false,
        reason: `CRITICAL SAFETY GUARD: Invalid or protected PID [${parameters.pid}]. PID must be a positive integer greater than 4 (System Kernel boundary).`
      };
    }

    const normProcName = processName.replace(/\.exe$/i, '');
    for (const rawProc of PROTECTED_SYSTEM_PROCESSES) {
      const normProtected = rawProc.replace(/\.exe$/i, '');
      if (normProcName === normProtected) {
        return {
          allowed: false,
          reason: `CRITICAL SAFETY GUARD: Process [${processName}] is a protected core operating system service. Termination blocked to prevent kernel crash.`
        };
      }
    }

    return {
      allowed: true,
      tier: AUTOMATION_TIERS.TIER_3.level,
      requiresApproval: AUTOMATION_TIERS.TIER_3.requiresApproval,
      dryRunPlan: `Terminate target process [${processName}] (PID: ${pid}). Will release working set memory and process handles. High impact: requires Application Owner approval.`
    };
  }

  // Tier 3: Service Restart
  if (cleanType === 'restart_service') {
    const serviceName = String(targetResource || '').trim();
    if (!serviceName || /[^a-zA-Z0-9_.-]/.test(serviceName)) {
      return {
        allowed: false,
        reason: 'Invalid service name format. Contains disallowed special characters.'
      };
    }

    return {
      allowed: true,
      tier: AUTOMATION_TIERS.TIER_3.level,
      requiresApproval: AUTOMATION_TIERS.TIER_3.requiresApproval,
      dryRunPlan: `Gracefully stop and restart system service [${serviceName}]. Brief temporary unavailability of service during restart cycle. Requires Application Owner approval.`
    };
  }

  // Tier 3: Network Adapter Reset
  if (cleanType === 'adapter_reset') {
    const adapterName = String(targetResource || '').trim();
    if (!adapterName || /[^a-zA-Z0-9_ .-]/.test(adapterName)) {
      return {
        allowed: false,
        reason: 'Invalid adapter name format. Contains disallowed special characters or is empty.'
      };
    }
    return {
      allowed: true,
      tier: AUTOMATION_TIERS.TIER_3.level,
      requiresApproval: AUTOMATION_TIERS.TIER_3.requiresApproval,
      dryRunPlan: `Disable and re-enable network adapter [${adapterName}]. Will cause temporary loss of network connectivity during reset cycle. Requires Application Owner approval.`
    };
  }

  return {
    allowed: false,
    reason: `Unknown or unsupported automation action type: [${actionType}].`
  };
}

module.exports = {
  validateActionSafety
};
