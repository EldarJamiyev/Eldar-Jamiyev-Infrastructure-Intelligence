/**
 * EJII Dual-Custody Automation Execution Engine
 * Enforces multi-tier approval workflows and dry-run execution safety.
 */

'use strict';

const { validateActionSafety } = require('./safety-validator');

const actionRegistry = new Map();
let actionCounter = 1000;

function requestAction({ actionType, targetHost = 'localhost', targetResource = '', user = {}, parameters = {}, dryRun = false } = {}) {
  const safety = validateActionSafety({ actionType, targetHost, targetResource, parameters });
  if (!safety.allowed) {
    return {
      success: false,
      error: safety.reason
    };
  }

  const actionId = `ACT-AUTOMATION-${++actionCounter}`;

  // Tier 2: Safe Remediations (e.g. flush_dns, arp_refresh)
  if (actionType === 'flush_dns' || actionType === 'clear_arp') {
    const record = {
      actionId,
      actionType,
      targetHost,
      targetResource,
      user,
      tier: 2,
      requiresApproval: false,
      approvalStatus: 'auto_approved',
      executionStatus: 'queued',
      dryRun: Boolean(dryRun)
    };
    actionRegistry.set(actionId, record);
    return {
      success: true,
      actionId,
      tier: 2,
      requiresApproval: false,
      executionStatus: 'queued'
    };
  }

  // Tier 3: High-Impact Dual-Custody (e.g. restart_service, reboot)
  if (dryRun) {
    const record = {
      actionId,
      actionType,
      targetHost,
      targetResource,
      user,
      tier: 3,
      requiresApproval: false,
      approvalStatus: 'dry_run_authorized',
      executionStatus: 'queued',
      dryRun: true,
      dryRunPlan: `Simulate ${actionType} on ${targetResource} without modifying host state`
    };
    actionRegistry.set(actionId, record);
    return {
      success: true,
      actionId,
      requiresApproval: false,
      dryRunPlan: record.dryRunPlan
    };
  }

  const record = {
    actionId,
    actionType,
    targetHost,
    targetResource,
    user,
    tier: 3,
    requiresApproval: true,
    approvalStatus: 'pending_approval',
    executionStatus: 'pending',
    dryRun: false
  };
  actionRegistry.set(actionId, record);

  return {
    success: true,
    actionId,
    tier: 3,
    requiresApproval: true,
    approvalStatus: 'pending_approval'
  };
}

function reviewAction(actionId, { approved = false, comment = '', user = {} } = {}) {
  const record = actionRegistry.get(actionId);
  if (!record) {
    return { success: false, error: `Action ${actionId} not found` };
  }

  if (approved) {
    record.approvalStatus = 'approved';
    record.executionStatus = 'queued';
    record.approvedBy = user.username || 'operator';
    record.reviewComment = comment;
    return {
      success: true,
      actionId,
      approvalStatus: 'approved',
      executionStatus: 'queued'
    };
  } else {
    record.approvalStatus = 'rejected';
    record.executionStatus = 'canceled';
    return {
      success: true,
      actionId,
      approvalStatus: 'rejected',
      executionStatus: 'canceled'
    };
  }
}

async function executeAction(actionId, user = {}) {
  const record = actionRegistry.get(actionId);
  if (!record) {
    return { success: false, error: `Action ${actionId} not found` };
  }

  if (record.requiresApproval && record.approvalStatus !== 'approved') {
    return {
      success: false,
      error: `Action requires Application Owner approval before execution. Current status: ${record.approvalStatus}`
    };
  }

  if (record.dryRun) {
    record.executionStatus = 'completed';
    return {
      success: true,
      dryRun: true,
      message: `Dry run simulation completed safely for ${record.actionType} on ${record.targetResource}.`
    };
  }

  record.executionStatus = 'executed';
  record.executedBy = user.username || 'operator';
  return {
    success: true,
    executionStatus: 'executed',
    message: `Action ${record.actionType} successfully executed on ${record.targetResource}.`
  };
}

module.exports = {
  requestAction,
  reviewAction,
  executeAction
};
