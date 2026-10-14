/**
 * EJII Safe Automation Execution Engine
 * Dual-custody gates, dry-run simulation, execution sandbox, and audit verification.
 */

const { exec } = require('child_process');
const crypto = require('crypto');
const { db } = require('../db/database');
const { IS_WINDOWS } = require('../config');
const { validateActionSafety } = require('./safety-validator');
const { logAction } = require('../core/audit-logger');

/**
 * Request an automation action
 */
function requestAction({ actionType, targetHost = 'localhost', targetResource, parameters = {}, user, dryRun = false, incidentId = null }) {
  const safety = validateActionSafety({ actionType, targetHost, targetResource, parameters });

  if (!safety.allowed) {
    return {
      success: false,
      error: safety.reason
    };
  }

  const actionId = 'ACT-' + crypto.randomBytes(4).toString('hex').toUpperCase();
  const timestamp = new Date().toISOString();
  const requiresApproval = safety.requiresApproval && !dryRun;
  const initialApprovalStatus = requiresApproval ? 'pending_approval' : 'not_required';
  const initialExecutionStatus = 'queued';

  db.prepare(`
    INSERT INTO automation_actions (
      id, action_type, tier, target_host, target_resource, parameters,
      requested_by_id, requested_by_role, approval_status, execution_status,
      dry_run, requested_at, incident_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    actionId,
    actionType,
    safety.tier,
    targetHost,
    targetResource || '',
    JSON.stringify(parameters),
    user.id,
    user.role,
    initialApprovalStatus,
    initialExecutionStatus,
    dryRun ? 1 : 0,
    timestamp,
    incidentId || null
  );

  logAction({
    userId: user.id,
    username: user.username,
    role: user.role,
    action: dryRun ? 'AUTOMATION_DRY_RUN_REQUESTED' : 'AUTOMATION_REQUESTED',
    resource: actionId,
    details: `Action [${actionType}] on [${targetResource}] (Tier ${safety.tier}). Requires Approval: ${requiresApproval}`
  });

  return {
    success: true,
    actionId,
    tier: safety.tier,
    requiresApproval,
    dryRunPlan: safety.dryRunPlan,
    approvalStatus: initialApprovalStatus,
    executionStatus: initialExecutionStatus
  };
}

/**
 * Approve or reject an automation action (Application Owner dual-custody gate)
 */
function reviewAction(actionId, { approved, comment, user }) {
  const action = db.prepare('SELECT * FROM automation_actions WHERE id = ?').get(actionId);

  if (!action) {
    return { success: false, error: 'Automation action not found.' };
  }

  if (action.approval_status !== 'pending_approval') {
    return { success: false, error: `Action is in state '${action.approval_status}', cannot review.` };
  }

  const approvalStatus = approved ? 'approved' : 'rejected';
  const executionStatus = approved ? 'queued' : 'cancelled';

  db.prepare(`
    UPDATE automation_actions 
    SET approval_status = ?, approved_by_id = ?, approval_comment = ?, execution_status = ? 
    WHERE id = ?
  `).run(approvalStatus, user.id, comment || '', executionStatus, actionId);

  logAction({
    userId: user.id,
    username: user.username,
    role: user.role,
    action: approved ? 'AUTOMATION_APPROVED' : 'AUTOMATION_REJECTED',
    resource: actionId,
    details: `Dual-custody review by ${user.username}: ${approvalStatus.toUpperCase()}. Comment: ${comment || 'None'}`
  });

  return {
    success: true,
    actionId,
    approvalStatus,
    executionStatus
  };
}

/**
 * Execute an approved or non-gated automation action
 */
function executeAction(actionId, user) {
  return new Promise((resolve) => {
    const action = db.prepare('SELECT * FROM automation_actions WHERE id = ?').get(actionId);

    if (!action) {
      return resolve({ success: false, error: 'Action record not found.' });
    }

    if (action.approval_status === 'pending_approval') {
      return resolve({ success: false, error: 'Cannot execute: Action requires Application Owner approval first.' });
    }

    if (action.approval_status === 'rejected') {
      return resolve({ success: false, error: 'Cannot execute: Action was rejected by Application Owner.' });
    }

    if (action.dry_run === 1) {
      return resolve({
        success: true,
        dryRun: true,
        message: 'Dry run completed. No real system changes made.'
      });
    }

    // Re-verify safety pre-flight
    const params = action.parameters ? JSON.parse(action.parameters) : {};
    const safety = validateActionSafety({
      actionType: action.action_type,
      targetHost: action.target_host,
      targetResource: action.target_resource,
      parameters: params
    });

    if (!safety.allowed) {
      db.prepare("UPDATE automation_actions SET execution_status = 'failed', execution_error = ? WHERE id = ?")
        .run(safety.reason, actionId);
      return resolve({ success: false, error: safety.reason });
    }

    // Construct OS command safely
    let cmd = '';
    if (action.action_type === 'flush_dns') {
      cmd = IS_WINDOWS ? 'ipconfig /flushdns' : 'resolvectl flush-caches || systemd-resolve --flush-caches';
    } else if (action.action_type === 'restart_service') {
      const cleanService = action.target_resource.replace(/[^a-zA-Z0-9_.-]/g, '');
      cmd = IS_WINDOWS
        ? `powershell.exe -NoProfile -Command "Restart-Service -Name '${cleanService}' -Force"`
        : `systemctl restart ${cleanService}`;
    } else if (action.action_type === 'kill_process') {
      const pid = params.pid ? parseInt(params.pid, 10) : null;
      if (!pid) {
        return resolve({ success: false, error: 'Target PID missing for process termination.' });
      }
      cmd = IS_WINDOWS
        ? `taskkill /F /PID ${pid}`
        : `kill -9 ${pid}`;
    } else if (action.action_type === 'adapter_reset') {
      const cleanAdapter = String(action.target_resource || '').replace(/[^a-zA-Z0-9_ .-]/g, '');
      cmd = IS_WINDOWS
        ? `powershell.exe -NoProfile -Command "Restart-NetAdapter -Name '${cleanAdapter}'"`
        : `ip link set ${cleanAdapter} down && ip link set ${cleanAdapter} up`;
    } else if (action.action_type === 'custom_diagnostic') {
      const target = String(action.target_host || '127.0.0.1').replace(/[^a-zA-Z0-9.-]/g, '');
      cmd = IS_WINDOWS ? `ping.exe -n 2 -w 1000 ${target}` : `ping -c 2 -W 1 ${target}`;
    } else if (action.action_type === 'ping_sweep') {
      cmd = IS_WINDOWS ? 'arp -a' : 'ip neigh show || arp -n';
    } else {
      return resolve({ success: false, error: 'Execution handler for this action type not implemented.' });
    }

    db.prepare("UPDATE automation_actions SET execution_status = 'running' WHERE id = ?").run(actionId);

    exec(cmd, { timeout: 15000 }, (error, stdout, stderr) => {
      const timestamp = new Date().toISOString();
      const output = (stdout || '').trim();
      const errOutput = (stderr || '').trim() || (error ? error.message : null);
      let isSuccess = !error;

      // Post-action state verification callback
      const finalize = (verifiedSuccess, verifiedOutput) => {
        const finalSuccess = verifiedSuccess !== undefined ? verifiedSuccess : isSuccess;
        const finalOutput = verifiedOutput || output;

        db.prepare(`
          UPDATE automation_actions 
          SET execution_status = ?, execution_output = ?, execution_error = ?, executed_at = ? 
          WHERE id = ?
        `).run(finalSuccess ? 'success' : 'failed', finalOutput, errOutput, timestamp, actionId);

        logAction({
          userId: user ? user.id : 'SYSTEM',
          username: user ? user.username : 'System',
          role: user ? user.role : 'system',
          action: finalSuccess ? 'AUTOMATION_EXECUTION_SUCCESS' : 'AUTOMATION_EXECUTION_FAILED',
          resource: actionId,
          details: `Executed [${action.action_type}] on [${action.target_resource}]. Result: ${finalSuccess ? 'SUCCESS' : 'FAILED'}`
        });

        // Automatically append remediation result to linked incident if present
        if (action.incident_id) {
          try {
            const noteMsg = `Remediation action [${action.action_type}] (${action.id}) ${finalSuccess ? 'completed successfully' : 'failed'}. Result: ${finalOutput || errOutput}`;
            const existingInc = db.prepare('SELECT operator_notes FROM incidents WHERE id = ?').get(action.incident_id);
            if (existingInc) {
              const updatedNotes = (existingInc.operator_notes ? existingInc.operator_notes + '\n---\n' : '') + `[${timestamp}] Safe Remediation Engine: ${noteMsg}`;
              db.prepare('UPDATE incidents SET operator_notes = ? WHERE id = ?').run(updatedNotes, action.incident_id);
            }
          } catch (e) {}
        }

        resolve({
          success: finalSuccess,
          actionId,
          output: finalOutput,
          error: errOutput,
          executedAt: timestamp
        });
      };

      // Post-action state verification for service restart
      if (isSuccess && action.action_type === 'restart_service' && IS_WINDOWS) {
        const cleanSvc = action.target_resource.replace(/[^a-zA-Z0-9_.-]/g, '');
        const verifyCmd = `powershell.exe -NoProfile -Command "(Get-Service -Name '${cleanSvc}').Status"`;
        exec(verifyCmd, { timeout: 5000 }, (vErr, vOut) => {
          const svcStatus = (vOut || '').trim();
          if (svcStatus === 'Running') {
            finalize(true, `Service [${cleanSvc}] restarted and verified Running. ${output}`);
          } else {
            finalize(false, `Service [${cleanSvc}] restart completed but state verification returned: ${svcStatus || 'Unknown'}. ${output}`);
          }
        });
      } else {
        finalize();
      }
    });
  });
}

module.exports = {
  requestAction,
  reviewAction,
  executeAction
};
