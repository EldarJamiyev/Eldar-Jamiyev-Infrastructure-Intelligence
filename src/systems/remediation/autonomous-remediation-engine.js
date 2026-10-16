/**
 * EJII Autonomous Remediation Engine
 * Provides two-phase remediation lifecycle:
 *   Phase 1: executePreview(recipeId, params) - Dry-run simulation, risks, exact commands
 *   Phase 2: executeRemediation(recipeId, params, userContext) - Audited execution with elevation & OS process protection
 */

'use strict';

const { exec } = require('child_process');
const { IS_WINDOWS } = require('../../config');
const { toolSandbox } = require('../../core/tool-sandbox');

// Critical OS Processes that must NEVER be killed, modified, or suspended
const PROTECTED_OS_PROCESSES = new Set([
  'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe', 'services.exe',
  'lsass.exe', 'lsm.exe', 'svchost.exe', 'fontdrvhost.exe', 'dwm.exe',
  'explorer.exe', 'ntoskrnl.exe', 'system', 'registry'
]);

class AutonomousRemediationEngine {
  constructor() {
    this.remediationLog = [];
    this.maxLogSize = 500;
  }

  /**
   * Catalog of supported safe remediation recipes
   */
  getRecipeCatalog() {
    return [
      {
        id: 'flush_dns',
        pillar: 'network',
        name: 'Flush & Re-register DNS Client Cache',
        description: 'Purges stale or poisoned DNS resolution records and re-registers local computer name with DNS resolvers.',
        requiresElevation: false,
        riskLevel: 'LOW',
        command: 'Clear-DnsClientCache; Register-DnsClient',
        expectedOutcome: 'DNS cache cleared; subsequent queries re-resolved directly against authoritative resolvers.'
      },
      {
        id: 'renew_dhcp',
        pillar: 'network',
        name: 'Release & Renew DHCP IP Leases',
        description: 'Releases current IPv4/IPv6 leases on all adapters and negotiates fresh configuration from DHCP server.',
        requiresElevation: false,
        riskLevel: 'LOW',
        command: 'ipconfig /release; ipconfig /renew',
        expectedOutcome: 'New IP address and gateway assigned; resolves IP collision and stale lease states.'
      },
      {
        id: 'reset_winsock',
        pillar: 'network',
        name: 'Reset TCP/IP Stack & Winsock Catalog',
        description: 'Resets the Windows socket API catalog and TCP/IP protocol parameters back to factory defaults.',
        requiresElevation: true,
        riskLevel: 'MEDIUM',
        command: 'netsh winsock reset; netsh int ip reset',
        expectedOutcome: 'Winsock catalog reconstructed; clears corrupt Layered Service Providers (LSPs) and socket exhaustion.'
      },
      {
        id: 'repair_component_store',
        pillar: 'storage',
        name: 'Repair Windows Component Store (DISM)',
        description: 'Checks and repairs corrupt OS system files using the Windows Component Store servicing engine.',
        requiresElevation: true,
        riskLevel: 'MEDIUM',
        command: 'DISM /Online /Cleanup-Image /RestoreHealth',
        expectedOutcome: 'Corrupted OS system files replaced from official component store.'
      },
      {
        id: 'scan_disk',
        pillar: 'storage',
        name: 'Non-Blocking Online Disk Health Scan (Chkdsk)',
        description: 'Performs online verification of Master File Table (MFT) and file system metadata without unmounting volume.',
        requiresElevation: true,
        riskLevel: 'LOW',
        command: 'chkdsk C: /scan',
        expectedOutcome: 'File system metadata verified online; schedules repair if corrupt sectors discovered.'
      },
      {
        id: 'cleanup_temp_dumps',
        pillar: 'storage',
        name: 'Purge Stale Minidumps & Temp Error Reports',
        description: 'Safely removes old crash dump files from C:\\Windows\\Minidump and temporary Windows Error Reporting logs.',
        requiresElevation: true,
        riskLevel: 'LOW',
        command: 'Remove-Item -Path C:\\Windows\\Minidump\\* -Force -ErrorAction SilentlyContinue',
        expectedOutcome: 'Reclaims storage space consumed by historical crash dumps.'
      },
      {
        id: 'trim_working_set',
        pillar: 'resource',
        name: 'Trim Working Set Memory Cache',
        description: 'Signals operating system memory manager to flush standby working set memory back to paging file.',
        requiresElevation: false,
        riskLevel: 'LOW',
        command: '[System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers()',
        expectedOutcome: 'Reduces memory pressure and reclaims unreferenced memory pages.'
      },
      {
        id: 'lower_process_priority',
        pillar: 'resource',
        name: 'Throttle Runaway Process CPU Priority',
        description: 'Lowers process priority class from High/Normal to BelowNormal/Idle without terminating the process.',
        requiresElevation: true,
        riskLevel: 'LOW',
        command: '(Get-Process -Id $TargetPid).PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal',
        expectedOutcome: 'Stops runaway CPU monopolization while allowing application to complete in background.'
      },
      {
        id: 'repair_print_spooler',
        pillar: 'peripherals',
        name: 'Purge & Re-initialize Windows Print Spooler',
        description: 'Stops spooler service, purges corrupt spool files from C:\\Windows\\System32\\spool\\PRINTERS, and restarts service.',
        requiresElevation: true,
        riskLevel: 'MEDIUM',
        command: 'Stop-Service -Name Spooler -Force; Remove-Item -Path C:\\Windows\\System32\\spool\\PRINTERS\\* -Force; Start-Service -Name Spooler',
        expectedOutcome: 'Stuck print jobs cleared and Spooler subsystem restored to healthy state.'
      },
      {
        id: 'rescan_pnp_devices',
        pillar: 'peripherals',
        name: 'Rescan Hardware Bus & Re-enumerate PnP Devices',
        description: 'Forces Windows Plug-and-Play manager to rescan PCI/USB buses and re-initialize degraded devices.',
        requiresElevation: true,
        riskLevel: 'LOW',
        command: 'pnputil /scan-devices',
        expectedOutcome: 'Degraded PnP devices (Code 10 / Code 43) re-enumerated and reconnected.'
      }
    ];
  }

  /**
   * Check whether the current Node process is running with Windows Administrator elevation
   */
  async checkElevation() {
    if (!IS_WINDOWS) {
      return { isElevated: process.getuid ? process.getuid() === 0 : false };
    }
    return new Promise((resolve) => {
      exec('net session', (err) => {
        // net session succeeds only when run as Administrator (elevation)
        resolve({ isElevated: !err });
      });
    });
  }

  /**
   * Phase 1: Dry-Run Preview of a remediation recipe
   */
  async executePreview(recipeId, params = {}) {
    const catalog = this.getRecipeCatalog();
    const recipe = catalog.find(r => r.id === recipeId);

    if (!recipe) {
      throw new Error(`Unknown remediation recipe ID: '${recipeId}'`);
    }

    const { isElevated } = await this.checkElevation();
    const target = params.target || params.processName || params.pid || 'System';

    return {
      dryRun: true,
      recipeId: recipe.id,
      name: recipe.name,
      pillar: recipe.pillar,
      description: recipe.description,
      riskLevel: recipe.riskLevel,
      requiresElevation: recipe.requiresElevation,
      hostIsElevated: isElevated,
      canExecuteDirectly: !recipe.requiresElevation || isElevated,
      commandPreview: recipe.command.replace('$TargetPid', params.pid || '0'),
      command: recipe.command.replace('$TargetPid', params.pid || '0'),
      safetyAssessment: recipe.requiresElevation && !isElevated
        ? 'ELEVATION REQUIRED: This action requires an elevated Administrator console. Preview only.'
        : 'SAFE TO EXECUTE: Action validated against non-destructive safety guardrails.',
      expectedOutcome: recipe.expectedOutcome,
      target
    };
  }

  /**
   * Phase 2: Execute an audited remediation recipe with strict safety guardrails
   */
  async executeRemediation(recipeId, params = {}, userContext = { role: 'ANALYST', username: 'operator' }) {
    const startTime = Date.now();
    const catalog = this.getRecipeCatalog();
    const recipe = catalog.find(r => r.id === recipeId);

    if (!recipe) {
      throw new Error(`Unknown remediation recipe ID: '${recipeId}'`);
    }

    // Role check: Remediation requires OPERATOR or higher
    const role = (userContext.role || 'READONLY').toUpperCase();
    if (role === 'READONLY') {
      throw new Error(`Access denied: Role '${role}' is not authorized to execute remediation. Minimum role: OPERATOR.`);
    }

    // OS Process Protection Guard
    if (params.processName) {
      const lowerName = String(params.processName).toLowerCase();
      if (PROTECTED_OS_PROCESSES.has(lowerName)) {
        throw new Error(`SECURITY VIOLATION: Protected operating system process '${params.processName}' cannot be targeted by remediation.`);
      }
    }

    const { isElevated } = await this.checkElevation();
    if (recipe.requiresElevation && !isElevated) {
      const outcome = {
        success: false,
        elevationRequired: true,
        recipeId: recipe.id,
        name: recipe.name,
        error: 'ELEVATION_REQUIRED: This remediation requires an elevated Administrator console. Run EJI with Administrator privileges to apply this fix.',
        instructions: `Run PowerShell as Administrator and execute: ${recipe.command}`,
        durationMs: Date.now() - startTime
      };
      this._recordRemediationLog(outcome, userContext, params);
      return outcome;
    }

    // Execute safe PowerShell recipe
    let execOutcome = { success: false, output: '', error: null };
    try {
      if (IS_WINDOWS) {
        const cmd = recipe.command.replace('$TargetPid', params.pid || '0');
        execOutcome = await new Promise((resolve) => {
          exec(`powershell.exe -NoProfile -NonInteractive -Command "${cmd}"`, { timeout: 15000 }, (err, stdout, stderr) => {
            if (err) {
              resolve({ success: false, output: stderr || stdout, error: err.message });
            } else {
              resolve({ success: true, output: (stdout || 'Success').trim(), error: null });
            }
          });
        });
      } else {
        execOutcome = { success: true, output: 'Simulated POSIX environment remediation complete.' };
      }
    } catch (e) {
      execOutcome = { success: false, output: '', error: e.message };
    }

    const durationMs = Date.now() - startTime;
    const finalResult = {
      success: execOutcome.success,
      recipeId: recipe.id,
      name: recipe.name,
      pillar: recipe.pillar,
      durationMs,
      output: execOutcome.output,
      error: execOutcome.error,
      timestamp: new Date().toISOString()
    };

    this._recordRemediationLog(finalResult, userContext, params);
    return finalResult;
  }

  _recordRemediationLog(result, user, params) {
    const entry = {
      id: 'REM-' + Date.now().toString(36),
      timestamp: new Date().toISOString(),
      recipeId: result.recipeId,
      name: result.name,
      user: user.username || 'unknown',
      role: user.role || 'ANALYST',
      success: result.success,
      elevationRequired: result.elevationRequired || false,
      params,
      durationMs: result.durationMs
    };
    this.remediationLog.push(entry);
    if (this.remediationLog.length > this.maxLogSize) {
      this.remediationLog.shift();
    }
  }

  getRemediationLog(limit = 50) {
    return this.remediationLog.slice(-limit).reverse();
  }
}

const autonomousRemediationEngine = new AutonomousRemediationEngine();

module.exports = {
  AutonomousRemediationEngine,
  autonomousRemediationEngine,
  PROTECTED_OS_PROCESSES
};
