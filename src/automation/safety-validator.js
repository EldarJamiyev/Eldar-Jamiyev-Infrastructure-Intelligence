/**
 * EJII Automation Safety Validator
 * Enforces kernel OS process protection and safety guardrails.
 */

'use strict';

const PROTECTED_PROCESSES = new Set([
  'csrss.exe', 'csrss',
  'lsass.exe', 'lsass',
  'smss.exe', 'smss',
  'services.exe', 'services',
  'wininit.exe', 'wininit',
  'system'
]);

function validateActionSafety({ actionType, targetHost = 'localhost', targetResource = '', parameters = {} } = {}) {
  const normResource = String(targetResource).toLowerCase().trim();
  const pid = parameters?.pid;

  if (actionType === 'kill_process' || actionType === 'terminate_process') {
    if (pid === 4 || pid === '4') {
      return {
        allowed: false,
        reason: 'CRITICAL SAFETY GUARD: PID 4 (System Kernel) is strictly protected from termination.'
      };
    }
    for (const p of PROTECTED_PROCESSES) {
      if (normResource === p || normResource.endsWith('\\' + p) || normResource.endsWith('/' + p)) {
        return {
          allowed: false,
          reason: `CRITICAL SAFETY GUARD: Operating system core process '${targetResource}' is strictly protected from termination.`
        };
      }
    }
  }

  return {
    allowed: true,
    reason: 'Action passed safety policy checks.'
  };
}

module.exports = {
  validateActionSafety,
  PROTECTED_PROCESSES
};
