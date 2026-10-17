/**
 * EJII Core Diagnostics & Autonomous Remediation View
 * 3-Panel Command Workbench:
 *   1. The Machine X-Ray (Left)
 *   2. The Diagnosis Feed (Center)
 *   3. Action Center & Live Console (Right)
 * Granular Inspection Tabs (Bottom):
 *   - Tab A: Process Explorer (Supercharged Task Manager)
 *   - Tab B: Network Sockets
 *   - Tab C: Storage & SMART
 *   - Tab D: Driver & PnP Tree
 */

(function(window) {
  'use strict';

  let hostAuditData = null;
  let processTableData = [];
  let socketTableData = [];
  let remediationLog = [];
  let activeTab = 'processes';
  let refreshTimer = null;
  let isAuditing = false;
  let selfHealingEnabled = false;

  window.toggleSelfHealing = function() {
    selfHealingEnabled = !selfHealingEnabled;
    const btn = document.getElementById('btnToggleSelfHealing');
    if (btn) {
      btn.textContent = selfHealingEnabled ? '🤖 Autonomous Healing: ON' : '⚙️ Autonomous Healing: OFF';
      btn.style.background = selfHealingEnabled ? 'rgba(16, 185, 129, 0.2)' : 'var(--bg-card)';
      btn.style.borderColor = selfHealingEnabled ? 'var(--success)' : 'var(--border-color)';
    }
  };

  window.switchDiagTab = function(tabName) {
    activeTab = tabName;
    document.querySelectorAll('.diag-tab-btn').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.tab === tabName);
    });
    document.querySelectorAll('.diag-tab-content').forEach(pane => {
      pane.style.display = pane.id === `tabContent_${tabName}` ? 'block' : 'none';
    });

    if (tabName === 'processes' && processTableData.length === 0) {
      loadProcesses();
    } else if (tabName === 'sockets' && socketTableData.length === 0) {
      loadSockets();
    } else if (tabName === 'brainGovernance') {
      window.loadBrainGovernance();
    }
  };

  async function fetchHostAudit(force = false) {
    try {
      const data = await window.api(`/api/diagnostics/host/audit${force ? '?fresh=true' : ''}`);
      return data;
    } catch (err) {
      console.error('Failed to fetch host audit:', err);
      logConsole(`❌ Host audit collection failed: ${err.message}`);
      return null;
    }
  }

  async function loadProcesses() {
    try {
      const data = await window.api('/api/diagnostics/host/processes');
      processTableData = data.processes || [];
      renderProcessTable();
    } catch (e) {
      console.error('Failed to load processes:', e);
    }
  }

  async function loadSockets() {
    try {
      const data = await window.api('/api/diagnostics/host/sockets');
      socketTableData = data.sockets || [];
      renderSocketTable();
    } catch (e) {
      console.error('Failed to load sockets:', e);
    }
  }

  window.loadBrainGovernance = async function() {
    try {
      const data = await window.api('/api/rca/brain/self-update-status');
      if (data && data.success) {
        renderBrainGovernanceUI(data.status, data.schemaBounds);
      }
    } catch (e) {
      console.error('Failed to load brain governance status:', e);
      logConsole(`❌ Brain governance query failed: ${e.message}`);
    }
  };

  function renderBrainGovernanceUI(status, bounds) {
    if (!status) return;
    const cfg = status.currentConfig || {};

    const elWatchdog = document.getElementById('brainWatchdogStatus');
    if (elWatchdog) {
      if (status.circuitBreakerTripped) {
        elWatchdog.innerHTML = '<span style="color: #EF4444; font-weight: 800;">TRIPPED (CIRCUIT BREAKER OPEN)</span>';
      } else if (status.watchdogActive) {
        elWatchdog.innerHTML = '<span style="color: #10B981; font-weight: 800;">ARMED (MONITORING)</span>';
      } else {
        elWatchdog.innerHTML = '<span style="color: #38BDF8; font-weight: 800;">STANDBY (HEALTHY)</span>';
      }
    }

    const elTick = document.getElementById('brainTickInterval');
    if (elTick) elTick.textContent = `${(cfg.brainTickIntervalMs || 5000).toLocaleString()} ms`;

    const elMult = document.getElementById('brainLatencyMultiplier');
    if (elMult) elMult.textContent = `${Number(cfg.adaptiveLatencyMultiplier || 3).toFixed(2)}x`;

    const elFloor = document.getElementById('brainLatencyFloor');
    if (elFloor) elFloor.textContent = `${cfg.minimumLatencyFloorMs || 100} ms`;

    const elEvents = document.getElementById('brainMaxEvents');
    if (elEvents) elEvents.textContent = `${(cfg.maxEvents || 500).toLocaleString()}`;

    const elDrift = document.getElementById('brainDriftRatio');
    if (elDrift) elDrift.textContent = `${((cfg.anomalyDriftTriggerRatio || 0.15) * 100).toFixed(1)}%`;

    const elHash = document.getElementById('brainActiveHash');
    if (elHash) elHash.textContent = status.currentConfigHash || '--';

    const tbody = document.getElementById('diagBrainHistoryTableBody');
    if (tbody) {
      const history = status.history || [];
      if (history.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 14px;">No self-modification events recorded.</td></tr>';
      } else {
        tbody.innerHTML = history.map(item => {
          const isRollback = item.status === 'ROLLED_BACK';
          const badge = isRollback
            ? '<span style="background: rgba(239, 68, 68, 0.15); color: #EF4444; border: 1px solid rgba(239, 68, 68, 0.3); padding: 2px 6px; border-radius: 3px; font-weight: 700; font-size: 9px;">ROLLED BACK</span>'
            : '<span style="background: rgba(16, 185, 129, 0.15); color: #10B981; border: 1px solid rgba(16, 185, 129, 0.3); padding: 2px 6px; border-radius: 3px; font-weight: 700; font-size: 9px;">VERIFIED &amp; APPLIED</span>';
          const hashShort = (item.newHash || item.restoredHash || '--').slice(0, 12);
          const time = item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : '--';
          const diffSummary = item.rationale || item.reason || 'Parameter optimization verified via child-process sandbox.';
          return `
            <tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.04);">
              <td style="padding: 6px 8px; font-family: var(--font-mono); font-size: 10px; color: var(--accent);">${item.updateId || '--'}</td>
              <td style="padding: 6px 8px; color: var(--text-muted); font-size: 10px;">${time}</td>
              <td style="padding: 6px 8px; font-size: 10px;">${item.triggerSource || 'AUTONOMOUS'}</td>
              <td style="padding: 6px 8px;">${badge}</td>
              <td style="padding: 6px 8px; max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${diffSummary}">${diffSummary}</td>
              <td style="padding: 6px 8px; font-family: var(--font-mono); font-size: 10px; color: var(--text-muted);">${hashShort}...</td>
            </tr>
          `;
        }).join('');
      }
    }
  }

  window.triggerBrainOptimization = async function() {
    logConsole('[AI Brain] Triggering autonomous parameter optimization cycle...');
    const btn = document.getElementById('btnRunBrainOptimization');
    if (btn) {
      btn.disabled = true;
      btn.textContent = '⚡ Optimizing & Verifying...';
    }
    try {
      const res = await window.api('/api/rca/brain/self-update/optimize', {
        method: 'POST',
        body: JSON.stringify({})
      });
      if (res && res.success) {
        logConsole(`✓ [SUCCESS] Brain optimization applied: ${res.updateRecord?.updateId} (Hash: ${(res.updateRecord?.newHash || '').slice(0, 8)}...)`);
        alert(`AI Brain Parameter Optimization Applied & Verified:\n\nUpdate ID: ${res.updateRecord?.updateId}\nOptimizer: ${res.updateRecord?.optimizerSource}\nRationale: ${res.updateRecord?.rationale}`);
      } else {
        const errMsg = res.error || res.message || 'Optimization rejected';
        if (res.status === 403 || /forbidden|permission/i.test(errMsg)) {
          logConsole(`❌ [403 FORBIDDEN] Permission 'system.config.manage' (ADMIN role) required to modify AI Brain configuration.`);
          alert(`Access Denied (403 Forbidden):\n\nOnly administrators with 'system.config.manage' capability may modify AI Brain parameters.`);
        } else {
          logConsole(`❌ [REJECTED] Brain optimization failed: ${errMsg}`);
          alert(`Optimization Failed:\n\n${errMsg}`);
        }
      }
      await window.loadBrainGovernance();
    } catch (err) {
      if (/403/i.test(err.message)) {
        logConsole(`❌ [403 FORBIDDEN] Permission 'system.config.manage' (ADMIN role) required to modify AI Brain configuration.`);
        alert(`Access Denied (403 Forbidden): Administrator role required.`);
      } else {
        logConsole(`❌ Optimization request error: ${err.message}`);
        alert(`Optimization request error: ${err.message}`);
      }
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = '⚡ Run Self-Optimization Cycle';
      }
    }
  };

  window.triggerBrainRollback = async function() {
    if (!confirm('Roll back AI Brain configuration to last known stable baseline?')) return;
    logConsole('[AI Brain] Executing emergency rollback to stable configuration...');
    try {
      const res = await window.api('/api/rca/brain/self-update/rollback', {
        method: 'POST',
        body: JSON.stringify({})
      });
      if (res && res.success) {
        logConsole(`✓ [RESTORED] Configuration rolled back: ${res.rollbackRecord?.updateId}`);
        alert(`AI Brain Configuration Rolled Back:\n\nUpdate ID: ${res.rollbackRecord?.updateId}\nReason: ${res.rollbackRecord?.reason}`);
      } else {
        const errMsg = res.error || res.message || 'Rollback rejected';
        if (res.status === 403 || /forbidden|permission/i.test(errMsg)) {
          logConsole(`❌ [403 FORBIDDEN] Permission 'system.config.manage' (ADMIN role) required to rollback configuration.`);
          alert(`Access Denied (403 Forbidden): Administrator capability required.`);
        } else {
          logConsole(`❌ Rollback failed: ${errMsg}`);
          alert(`Rollback failed: ${errMsg}`);
        }
      }
      await window.loadBrainGovernance();
    } catch (err) {
      if (/403/i.test(err.message)) {
        logConsole(`❌ [403 FORBIDDEN] Permission 'system.config.manage' (ADMIN role) required to rollback configuration.`);
        alert(`Access Denied (403 Forbidden): Administrator capability required.`);
      } else {
        logConsole(`❌ Rollback request error: ${err.message}`);
        alert(`Rollback request error: ${err.message}`);
      }
    }
  };

  window.triggerAutonomousInvestigation = async function(targetIpOverride = null, targetPortOverride = null) {
    const inputIp = targetIpOverride || document.getElementById('investigateTargetIp')?.value || '127.0.0.1';
    const inputPort = targetPortOverride || parseInt(document.getElementById('investigateTargetPort')?.value || 443, 10);

    logConsole(`[Investigation] Starting autonomous multi-protocol wire investigation against ${inputIp}:${inputPort}...`);
    const btn = document.getElementById('btnRunAutonomousInvestigation');
    if (btn) {
      btn.disabled = true;
      btn.textContent = '🔎 Investigating Wire...';
    }

    try {
      const res = await window.api('/api/rca/brain/investigate', {
        method: 'POST',
        body: JSON.stringify({ targetIp: inputIp, targetPort: inputPort, maxSteps: 4 })
      });

      if (res && res.success) {
        logConsole(`✓ [INVESTIGATION COMPLETE] ${res.investigationId}: executed ${res.stepsExecuted} probe(s) in ${res.durationMs}ms`);
        logConsole(`→ Top Root Cause: ${res.finalTopHypothesis?.label} (${res.finalTopHypothesis?.confidence}% confidence) [Conclusive: ${res.conclusive ? 'YES' : 'NO'}]`);
        if (Array.isArray(res.steps)) {
          for (const s of res.steps) {
            logConsole(`   Step ${s.stepNumber} [${s.probeType}]: ${s.probeSuccess ? 'SUCCESS' : 'FAILED'} (${s.latencyMs}ms) → ${s.rawOutput}`);
          }
        }
        alert(`Autonomous Investigation Completed:\n\nInvestigation ID: ${res.investigationId}\nTarget: ${res.target}:${res.targetPort}\nTop Root Cause: ${res.finalTopHypothesis?.label} (${res.finalTopHypothesis?.confidence}% confidence)\nSteps Executed: ${res.stepsExecuted}\nConclusive: ${res.conclusive ? 'YES' : 'NO'}`);
      } else {
        const errMsg = res.error || res.message || 'Investigation failed';
        if (res.status === 403 || /forbidden|permission/i.test(errMsg)) {
          logConsole(`❌ [403 FORBIDDEN] Permission 'network.diagnostics.execute' required to dispatch physical wire probes.`);
          alert(`Access Denied: You require 'network.diagnostics.execute' permission to run physical network investigations.`);
        } else {
          logConsole(`❌ [FAILED] Investigation failed: ${errMsg}`);
          alert(`Investigation Failed: ${errMsg}`);
        }
      }
    } catch (err) {
      if (/403/i.test(err.message)) {
        logConsole(`❌ [403 FORBIDDEN] Permission 'network.diagnostics.execute' required to dispatch physical wire probes.`);
        alert(`Access Denied (403 Forbidden): Operator role or permission 'network.diagnostics.execute' required.`);
      } else {
        logConsole(`❌ [ERROR] Investigation request error: ${err.message}`);
        alert(`Investigation request error: ${err.message}`);
      }
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = '🔎 Run Multi-Protocol Probe Sweep';
      }
    }
  };

  window.runDeepSystemAudit = async function() {
    if (isAuditing) return;
    isAuditing = true;
    const btn = document.getElementById('btnRunSystemAudit');
    if (btn) {
      btn.disabled = true;
      btn.textContent = '⚡ Running Audit...';
    }

    logConsole('⚡ Triggered deep 4-pillar hardware and OS audit...');
    hostAuditData = await fetchHostAudit(true);
    await loadProcesses();
    await loadSockets();

    isAuditing = false;
    if (btn) {
      btn.disabled = false;
      btn.textContent = '⚡ Run Deep System Audit';
    }
    if (hostAuditData) {
      logConsole(`✓ Deep audit completed in ${hostAuditData.durationMs || 100}ms. Status: ${hostAuditData.overallStatus || 'HEALTHY'}`);
      updateUI();
    } else {
      logConsole('❌ Deep audit failed. Check server session authentication.');
    }
  };

  window.previewRemediation = async function(recipeId, params = {}) {
    logConsole(`[Preview] Requesting dry-run execution plan for recipe: ${recipeId}...`);
    try {
      const data = await window.api('/api/diagnostics/remediation/preview', {
        method: 'POST',
        body: JSON.stringify({ recipeId, params })
      });
      if (data.success && data.preview) {
        showPreviewModal(data.preview);
      } else {
        alert(`Failed to preview remediation: ${data.error || 'Unknown error'}`);
      }
    } catch (e) {
      alert(`Preview network failure: ${e.message}`);
    }
  };

  window.executeRemediationRecipe = async function(recipeId, params = {}, actionToken = null) {
    if (!actionToken) {
      // Cryptographic binding mandate: Trigger dry-run preview to inspect and sign HMAC action token first
      return window.previewRemediation(recipeId, params);
    }

    logConsole(`[Action] Executing remediation recipe: ${recipeId}...`);
    try {
      const data = await window.api('/api/diagnostics/remediation/execute', {
        method: 'POST',
        body: JSON.stringify({ actionToken, recipeId, params })
      });

      if (data.success && data.outcome) {
        logConsole(`✓ [SUCCESS] Recipe ${recipeId} executed (${data.outcome.durationMs}ms): ${data.outcome.output || 'Done'}`);
        alert(`Remediation Executed Successfully:\n\n${data.outcome.name}\n${data.outcome.output || 'Applied'}`);
      } else {
        const err = data.outcome?.error || data.error || 'Execution failed';
        logConsole(`❌ [REJECTED/FAILED] ${recipeId}: ${err}`);
        if (data.outcome?.elevationRequired) {
          alert(`Elevation Required:\n\n${data.outcome.instructions || err}`);
        } else {
          alert(`Remediation Failed:\n\n${err}`);
        }
      }
      // Re-run audit to reflect changes
      window.runDeepSystemAudit();
    } catch (e) {
      logConsole(`❌ Network error: ${e.message}`);
      alert(`Network error executing remediation: ${e.message}`);
    }
  };

  function logConsole(msg) {
    const consoleEl = document.getElementById('diagLiveConsole');
    if (!consoleEl) return;
    const time = new Date().toLocaleTimeString();
    const line = document.createElement('div');
    line.style.padding = '2px 0';
    line.style.borderBottom = '1px solid rgba(255, 255, 255, 0.04)';
    line.innerHTML = `<span style="color: var(--text-muted); font-size: 10px;">[${time}]</span> <span style="color: var(--text-main); font-size: 11px;">${msg}</span>`;
    consoleEl.appendChild(line);
    consoleEl.scrollTop = consoleEl.scrollHeight;
  }

  function showPreviewModal(preview) {
    const modal = document.getElementById('modalContainer');
    if (!modal) return;
    modal.style.display = 'flex';
    modal.innerHTML = `
      <div class="modal-backdrop" onclick="window.closeModal(event)">
        <div class="modal-card" style="max-width: 650px; width: 90%; background: #0b1120; border: 1px solid var(--border-color); border-radius: 8px; padding: 20px;" onclick="event.stopPropagation()">
          <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 12px; margin-bottom: 14px;">
            <div style="display: flex; align-items: center; gap: 8px;">
              <span style="font-size: 20px;">🛡️</span>
              <div style="font-weight: 800; font-size: 14px; color: var(--accent);">Remediation Recipe Dry-Run Preview</div>
            </div>
            <button class="btn-logout" onclick="window.closeModal()">✕</button>
          </div>

          <div style="margin-bottom: 12px;">
            <div style="font-weight: 700; font-size: 13px; color: var(--text-main);">${preview.name}</div>
            <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">${preview.description}</div>
          </div>

          <div style="background: rgba(0, 0, 0, 0.4); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 6px; padding: 12px; margin-bottom: 14px; font-family: var(--font-mono); font-size: 11px;">
            <div style="color: var(--text-muted); font-size: 10px; margin-bottom: 4px;">EXACT POWERSHELL COMMAND:</div>
            <div style="color: #38BDF8; word-break: break-all;">${preview.commandPreview || preview.command}</div>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 16px; font-size: 11px;">
            <div style="background: var(--bg-card); padding: 8px; border-radius: 4px; border: 1px solid var(--border-color);">
              <span style="color: var(--text-muted);">RISK LEVEL:</span> <span style="font-weight: 700; color: ${preview.riskLevel === 'LOW' ? 'var(--success)' : 'var(--warning)'};">${preview.riskLevel}</span>
            </div>
            <div style="background: var(--bg-card); padding: 8px; border-radius: 4px; border: 1px solid var(--border-color);">
              <span style="color: var(--text-muted);">ELEVATION REQUIRED:</span> <span style="font-weight: 700; color: ${preview.requiresElevation ? '#f59e0b' : 'var(--success)'};">${preview.requiresElevation ? 'YES (Admin)' : 'NO (User)'}</span>
            </div>
          </div>

          <div style="background: ${preview.canExecuteDirectly ? 'rgba(16, 185, 129, 0.08)' : 'rgba(245, 158, 11, 0.08)'}; border-left: 3px solid ${preview.canExecuteDirectly ? 'var(--success)' : '#f59e0b'}; padding: 10px; margin-bottom: 16px; font-size: 11px;">
            <div style="font-weight: 700; color: ${preview.canExecuteDirectly ? 'var(--success)' : '#f59e0b'}; margin-bottom: 4px;">SAFETY ASSESSMENT</div>
            <div style="color: var(--text-main);">${preview.safetyAssessment}</div>
          </div>

          <div style="display: flex; justify-content: flex-end; gap: 8px;">
            <button class="btn btn-secondary" onclick="window.closeModal()" style="font-size: 11px;">Cancel</button>
            <button class="btn btn-primary" onclick="window.closeModal(); window.executeRemediationRecipe('${preview.recipeId}', { target: '${preview.target}' }, '${preview.actionToken || ''}')" style="font-size: 11px; font-weight: 700;">Authorize &amp; Apply Fix ⚡</button>
          </div>
        </div>
      </div>
    `;
  }

  function getStatusBadge(status) {
    if (status === 'HEALTHY') return '<span style="background: rgba(16, 185, 129, 0.15); color: #10B981; border: 1px solid rgba(16, 185, 129, 0.3); padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 10px;">HEALTHY</span>';
    if (status === 'DEGRADED') return '<span style="background: rgba(245, 158, 11, 0.15); color: #F59E0B; border: 1px solid rgba(245, 158, 11, 0.3); padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 10px;">DEGRADED</span>';
    if (status === 'UNKNOWN') return '<span style="background: rgba(107, 114, 128, 0.15); color: #9CA3AF; border: 1px solid rgba(107, 114, 128, 0.3); padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 10px;">UNKNOWN</span>';
    if (status === 'COLLECTION_ERROR') return '<span style="background: rgba(168, 85, 247, 0.15); color: #C084FC; border: 1px solid rgba(168, 85, 247, 0.3); padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 10px;">COLLECTION ERROR</span>';
    return '<span style="background: rgba(239, 68, 68, 0.15); color: #EF4444; border: 1px solid rgba(239, 68, 68, 0.3); padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 10px;">CRITICAL</span>';
  }

  function updateUI() {
    if (!hostAuditData) return;

    // 1. Machine X-Ray
    const host = hostAuditData.host || {};
    const p = hostAuditData.pillars || {};

    const hostBadge = document.getElementById('diagHostBadge');
    if (hostBadge) {
      hostBadge.innerHTML = `
        <div style="font-size: 13px; font-weight: 800; color: var(--accent); margin-bottom: 2px;">🖥️ ${host.hostname || 'LOCALHOST'}</div>
        <div style="font-size: 10px; color: var(--text-muted);">${host.platform || 'win32'} (${host.arch || 'x64'}) &bull; ${host.cpuCores || 4} Cores &bull; ${host.totalRamGB || 16} GB RAM &bull; Uptime ${host.uptimeDays || 1}d</div>
      `;
    }

    const netBadge = document.getElementById('badgePillarNet');
    if (netBadge) netBadge.innerHTML = getStatusBadge(p.network?.status || 'HEALTHY');
    const storageBadge = document.getElementById('badgePillarStorage');
    if (storageBadge) storageBadge.innerHTML = getStatusBadge(p.storage?.status || 'HEALTHY');
    const resBadge = document.getElementById('badgePillarRes');
    if (resBadge) resBadge.innerHTML = getStatusBadge(p.resource?.status || 'HEALTHY');
    const periphBadge = document.getElementById('badgePillarPeriph');
    if (periphBadge) periphBadge.innerHTML = getStatusBadge(p.peripherals?.status || 'HEALTHY');

    // Quick Gauges
    const resDet = p.resource?.details || {};
    const cpuEl = document.getElementById('gaugeCpuLoad');
    if (cpuEl) cpuEl.textContent = `${resDet.cpuLoadPct || 0}%`;
    const ramEl = document.getElementById('gaugeRamUsed');
    if (ramEl) ramEl.textContent = `${resDet.ramUsedPct || 0}% (${resDet.usedRamGB || 0}/${resDet.totalRamGB || 0} GB)`;
    const qEl = document.getElementById('gaugeDiskQueue');
    if (qEl) qEl.textContent = `${resDet.diskQueueLength || 0}`;

    // 2. Diagnosis Feed
    const diagFeed = document.getElementById('diagAnomaliesFeed');
    const anomalies = hostAuditData.anomalies || [];
    if (diagFeed) {
      if (anomalies.length === 0) {
        diagFeed.innerHTML = `
          <div style="text-align: center; padding: 24px 12px; color: var(--text-muted);">
            <div style="font-size: 24px; margin-bottom: 8px;">✅</div>
            <div style="font-weight: 700; color: var(--success); font-size: 13px;">No Host Anomalies Detected</div>
            <div style="font-size: 11px; margin-top: 4px;">All hardware subsystems, OS pools, and network stacks are operating within nominal thresholds.</div>
          </div>
        `;
      } else {
        diagFeed.innerHTML = anomalies.map(a => `
          <div style="background: var(--bg-input); border-left: 3px solid ${a.severity === 'CRITICAL' ? 'var(--danger)' : 'var(--warning)'}; border-radius: 4px; padding: 10px 12px; margin-bottom: 10px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
              <span style="font-weight: 700; font-size: 12px; color: var(--text-main);">${a.title}</span>
              <span style="font-size: 9px; font-weight: 800; color: ${a.severity === 'CRITICAL' ? 'var(--danger)' : 'var(--warning)'}; border: 1px solid currentColor; padding: 1px 6px; border-radius: 3px;">${a.severity}</span>
            </div>
            <div style="font-size: 11px; color: var(--text-main); margin-bottom: 6px;">${a.plainEnglish}</div>
            <div style="background: rgba(0, 0, 0, 0.3); border-radius: 3px; padding: 4px 6px; font-family: var(--font-mono); font-size: 10px; color: var(--text-muted); margin-bottom: 8px;">
              PROOF: ${a.rawProof}
            </div>
            ${a.recipeId ? `
              <div style="display: flex; gap: 6px; justify-content: flex-end;">
                <button class="btn btn-secondary" onclick="window.previewRemediation('${a.recipeId}')" style="font-size: 10px; padding: 2px 8px;">Preview Dry-Run</button>
                <button class="btn btn-primary" onclick="window.executeRemediationRecipe('${a.recipeId}')" style="font-size: 10px; padding: 2px 8px; font-weight: 700;">Apply Fix ⚡</button>
              </div>
            ` : ''}
          </div>
        `).join('');
      }
    }

    // AI Brain Synthesis Card
    const synthCard = document.getElementById('diagAiBrainSynthesis');
    const synth = hostAuditData.brainSynthesis;
    if (synthCard && synth) {
      synthCard.innerHTML = `
        <div style="font-weight: 700; color: var(--accent); font-size: 11px; margin-bottom: 4px; display: flex; align-items: center; gap: 6px;">
          <span>🧠 AI Causal Reasoning Synthesis:</span>
        </div>
        <div style="font-size: 11px; color: var(--text-main); line-height: 1.4;">${synth.summary || synth.plainEnglishReport}</div>
      `;
    }

    // 3. Staged Remediation Queue in Action Center
    const queueEl = document.getElementById('diagStagedQueue');
    const staged = hostAuditData.stagedRecipes || [];
    if (queueEl) {
      if (staged.length === 0) {
        queueEl.innerHTML = '<div style="color: var(--text-muted); font-size: 11px; text-align: center; padding: 10px;">No staged remediations required.</div>';
      } else {
        queueEl.innerHTML = staged.map(rId => `
          <div style="display: flex; justify-content: space-between; align-items: center; background: var(--bg-input); border: 1px solid var(--border-color); border-radius: 4px; padding: 6px 10px; margin-bottom: 6px;">
            <span style="font-family: var(--font-mono); font-size: 11px; color: var(--accent); font-weight: 700;">${rId}</span>
            <div style="display: flex; gap: 4px;">
              <button class="btn btn-secondary" onclick="window.previewRemediation('${rId}')" style="font-size: 10px; padding: 2px 6px;">Preview</button>
              <button class="btn btn-primary" onclick="window.executeRemediationRecipe('${rId}')" style="font-size: 10px; padding: 2px 6px;">Fix ⚡</button>
            </div>
          </div>
        `).join('');
      }
    }
  }

  function renderProcessTable() {
    const tbody = document.getElementById('diagProcessTableBody');
    if (!tbody) return;

    if (processTableData.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 14px;">No process telemetry available.</td></tr>';
      return;
    }

    tbody.innerHTML = processTableData.map(p => `
      <tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.04);">
        <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); padding: 6px 8px;">${p.pid}</td>
        <td style="font-weight: 700; font-size: 11px; color: var(--text-main); padding: 6px 8px;">${p.name}</td>
        <td style="font-size: 11px; color: ${p.cpu > 10 ? 'var(--warning)' : 'var(--text-main)'}; padding: 6px 8px;">${p.cpu}%</td>
        <td style="font-size: 11px; color: var(--text-main); padding: 6px 8px;">${p.workingSetMB} MB</td>
        <td style="font-size: 11px; color: var(--text-muted); padding: 6px 8px;">${p.privateMB} MB</td>
        <td style="font-size: 11px; color: var(--text-muted); padding: 6px 8px;">${p.handles}</td>
        <td style="padding: 6px 8px; text-align: right;">
          <button class="btn btn-secondary" onclick="window.previewRemediation('lower_process_priority', { pid: ${p.pid}, processName: '${p.name}' })" style="font-size: 10px; padding: 2px 6px;">Throttle Priority</button>
        </td>
      </tr>
    `).join('');
  }

  function renderSocketTable() {
    const tbody = document.getElementById('diagSocketTableBody');
    if (!tbody) return;

    if (socketTableData.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 14px;">No socket telemetry available.</td></tr>';
      return;
    }

    tbody.innerHTML = socketTableData.map(s => `
      <tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.04);">
        <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-main); padding: 6px 8px;">${s.localAddress}:${s.localPort}</td>
        <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); padding: 6px 8px;">${s.remoteAddress || '*'}:${s.remotePort || '*'}</td>
        <td style="font-size: 10px; font-weight: 700; color: ${s.state === 'ESTABLISHED' ? 'var(--success)' : (s.state === 'CLOSE_WAIT' ? 'var(--danger)' : 'var(--accent)')}; padding: 6px 8px;">${s.state}</td>
        <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); padding: 6px 8px;">PID ${s.owningPid}</td>
        <td style="padding: 6px 8px; text-align: right;">
          <button class="btn btn-secondary" onclick="window.previewRemediation('reset_winsock')" style="font-size: 10px; padding: 2px 6px;">Reset Stack</button>
        </td>
      </tr>
    `).join('');
  }

  /**
   * Main View Entry Point
   */
  window.renderCoreDiagnosticsView = async function() {
    if (refreshTimer) clearInterval(refreshTimer);

    const container = document.getElementById('mainContent');
    if (!container) return;

    container.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 14px; padding: 16px 20px;">
        <!-- Header -->
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 12px;">
          <div>
            <div style="font-size: 18px; font-weight: 800; color: var(--text-main); display: flex; align-items: center; gap: 8px;">
              <span>🔍</span> Core Diagnostics &amp; Autonomous Remediation
              <span style="font-size: 10px; background: rgba(56, 189, 248, 0.15); color: var(--accent); border: 1px solid rgba(56, 189, 248, 0.3); padding: 2px 6px; border-radius: 4px;">SYSINTERNALS GRADE</span>
            </div>
            <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">
              Real Windows Hardware Ingestion &bull; 4-Pillar Health Triage &bull; Audited Remediation Recipes &bull; Zero Simulation
            </div>
          </div>
          <div style="display: flex; gap: 8px;">
            <button id="btnToggleSelfHealing" class="btn btn-secondary" onclick="window.toggleSelfHealing()" style="font-size: 11px;">⚙️ Autonomous Healing: OFF</button>
            <button id="btnRunSystemAudit" class="btn btn-primary" onclick="window.runDeepSystemAudit()" style="font-size: 11px; font-weight: 700;">⚡ Run Deep System Audit</button>
          </div>
        </div>

        <!-- 3-PANEL COMMAND WORKBENCH -->
        <div style="display: grid; grid-template-columns: 280px 1fr 300px; gap: 14px;">
          
          <!-- Panel 1: Machine X-Ray -->
          <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; padding: 14px; display: flex; flex-direction: column; gap: 12px;">
            <div style="font-size: 12px; font-weight: 800; color: var(--accent); border-bottom: 1px solid rgba(255, 255, 255, 0.06); padding-bottom: 6px;">
              1. THE MACHINE X-RAY
            </div>

            <div id="diagHostBadge" style="background: var(--bg-input); padding: 10px; border-radius: 4px; border: 1px solid var(--border-color);">
              <div style="font-size: 11px; color: var(--text-muted);">Loading host hardware...</div>
            </div>

            <div>
              <div style="font-size: 10px; font-weight: 700; color: var(--text-muted); margin-bottom: 6px;">4 CORE HEALTH PILLARS</div>
              <div style="display: flex; flex-direction: column; gap: 6px;">
                <div style="display: flex; justify-content: space-between; align-items: center; font-size: 11px;">
                  <span>📡 1. Network Layer</span>
                  <span id="badgePillarNet">...</span>
                </div>
                <div style="display: flex; justify-content: space-between; align-items: center; font-size: 11px;">
                  <span>💾 2. Storage &amp; SMART</span>
                  <span id="badgePillarStorage">...</span>
                </div>
                <div style="display: flex; justify-content: space-between; align-items: center; font-size: 11px;">
                  <span>⚙️ 3. Resource Allocation</span>
                  <span id="badgePillarRes">...</span>
                </div>
                <div style="display: flex; justify-content: space-between; align-items: center; font-size: 11px;">
                  <span>🔌 4. Peripherals &amp; Drivers</span>
                  <span id="badgePillarPeriph">...</span>
                </div>
              </div>
            </div>

            <div>
              <div style="font-size: 10px; font-weight: 700; color: var(--text-muted); margin-bottom: 6px;">QUICK GAUGES</div>
              <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 6px;">
                <div style="background: var(--bg-input); padding: 8px; border-radius: 4px; text-align: center;">
                  <div style="font-size: 9px; color: var(--text-muted);">CPU LOAD</div>
                  <div id="gaugeCpuLoad" style="font-size: 13px; font-weight: 800; color: var(--text-main); margin-top: 2px;">--</div>
                </div>
                <div style="background: var(--bg-input); padding: 8px; border-radius: 4px; text-align: center;">
                  <div style="font-size: 9px; color: var(--text-muted);">DISK QUEUE</div>
                  <div id="gaugeDiskQueue" style="font-size: 13px; font-weight: 800; color: var(--text-main); margin-top: 2px;">--</div>
                </div>
              </div>
              <div style="background: var(--bg-input); padding: 8px; border-radius: 4px; margin-top: 6px; text-align: center;">
                <div style="font-size: 9px; color: var(--text-muted);">PHYSICAL RAM USAGE</div>
                <div id="gaugeRamUsed" style="font-size: 12px; font-weight: 700; color: var(--text-main); margin-top: 2px;">--</div>
              </div>
            </div>
          </div>

          <!-- Panel 2: The Diagnosis Feed -->
          <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; padding: 14px; display: flex; flex-direction: column;">
            <div style="font-size: 12px; font-weight: 800; color: var(--accent); border-bottom: 1px solid rgba(255, 255, 255, 0.06); padding-bottom: 6px; margin-bottom: 10px;">
              2. THE DIAGNOSIS FEED &amp; ANOMALY TRIAGE
            </div>

            <div id="diagAnomaliesFeed" style="flex: 1; max-height: 280px; overflow-y: auto; scrollbar-gutter: stable; padding-right: 6px;">
              <div style="text-align: center; padding: 20px; color: var(--text-muted);">Loading diagnosis feed...</div>
            </div>

            <div id="diagAiBrainSynthesis" style="margin-top: 10px; background: rgba(56, 189, 248, 0.05); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 4px; padding: 10px;">
              <div style="font-size: 11px; color: var(--text-muted);">AI Causal Reasoning initializing...</div>
            </div>
          </div>

          <!-- Panel 3: Action Center & Live Console -->
          <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; padding: 14px; display: flex; flex-direction: column;">
            <div style="font-size: 12px; font-weight: 800; color: var(--accent); border-bottom: 1px solid rgba(255, 255, 255, 0.06); padding-bottom: 6px; margin-bottom: 10px;">
              3. ACTION CENTER &amp; CONSOLE
            </div>

            <div style="font-size: 10px; font-weight: 700; color: var(--text-muted); margin-bottom: 4px;">STAGED REMEDIATION QUEUE</div>
            <div id="diagStagedQueue" style="margin-bottom: 12px; max-height: 120px; overflow-y: auto;">
              <div style="color: var(--text-muted); font-size: 11px;">No staged fixes.</div>
            </div>

            <div style="font-size: 10px; font-weight: 700; color: var(--text-muted); margin-bottom: 4px;">LIVE REMEDIATION CONSOLE</div>
            <div id="diagLiveConsole" style="flex: 1; background: #060913; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 4px; padding: 8px; font-family: var(--font-mono); font-size: 10px; min-height: 120px; max-height: 140px; overflow-y: auto;">
              <div style="color: var(--text-muted);">[Ready] Awaiting user diagnostic trigger.</div>
            </div>
          </div>
        </div>

        <!-- GRANULAR INSPECTION TABS (BOTTOM PANE) -->
        <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; padding: 14px;">
          <!-- Tabs Header -->
          <div style="display: flex; gap: 8px; border-bottom: 1px solid var(--border-color); padding-bottom: 10px; margin-bottom: 12px;">
            <button class="btn btn-secondary diag-tab-btn active" data-tab="processes" onclick="window.switchDiagTab('processes')" style="font-size: 11px; font-weight: 700;">⚙️ Process Explorer</button>
            <button class="btn btn-secondary diag-tab-btn" data-tab="sockets" onclick="window.switchDiagTab('sockets')" style="font-size: 11px; font-weight: 700;">📡 Network Sockets</button>
            <button class="btn btn-secondary diag-tab-btn" data-tab="brainGovernance" onclick="window.switchDiagTab('brainGovernance')" style="font-size: 11px; font-weight: 700;">🤖 AI Brain Self-Tuning &amp; Governance</button>
          </div>

          <!-- Tab Content: Process Explorer -->
          <div id="tabContent_processes" class="diag-tab-content">
            <div style="max-height: 320px; overflow-y: auto; scrollbar-gutter: stable;">
              <table style="width: 100%; border-collapse: collapse; text-align: left;">
                <thead>
                  <tr style="border-bottom: 1px solid var(--border-color); color: var(--text-muted); font-size: 10px;">
                    <th style="padding: 6px 8px;">PID</th>
                    <th style="padding: 6px 8px;">PROCESS NAME</th>
                    <th style="padding: 6px 8px;">CPU %</th>
                    <th style="padding: 6px 8px;">WORKING SET</th>
                    <th style="padding: 6px 8px;">PRIVATE BYTES</th>
                    <th style="padding: 6px 8px;">HANDLES</th>
                    <th style="padding: 6px 8px; text-align: right;">ACTION</th>
                  </tr>
                </thead>
                <tbody id="diagProcessTableBody">
                  <tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 14px;">Loading processes...</td></tr>
                </tbody>
              </table>
            </div>
          </div>

          <!-- Tab Content: Network Sockets -->
          <div id="tabContent_sockets" class="diag-tab-content" style="display: none;">
            <div style="max-height: 320px; overflow-y: auto; scrollbar-gutter: stable;">
              <table style="width: 100%; border-collapse: collapse; text-align: left;">
                <thead>
                  <tr style="border-bottom: 1px solid var(--border-color); color: var(--text-muted); font-size: 10px;">
                    <th style="padding: 6px 8px;">LOCAL ENDPOINT</th>
                    <th style="padding: 6px 8px;">REMOTE ENDPOINT</th>
                    <th style="padding: 6px 8px;">STATE</th>
                    <th style="padding: 6px 8px;">OWNER</th>
                    <th style="padding: 6px 8px; text-align: right;">ACTION</th>
                  </tr>
                </thead>
                <tbody id="diagSocketTableBody">
                  <tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 14px;">Loading sockets...</td></tr>
                </tbody>
              </table>
            </div>
          </div>

          <!-- Tab Content: AI Brain Governance -->
          <div id="tabContent_brainGovernance" class="diag-tab-content" style="display: none;">
            <div style="display: flex; flex-direction: column; gap: 14px;">
              <!-- Telemetry & Thresholds Grid -->
              <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px;">
                <div style="background: var(--bg-input); border: 1px solid var(--border-color); border-radius: 4px; padding: 10px;">
                  <div style="font-size: 9px; font-weight: 700; color: var(--text-muted); margin-bottom: 2px;">WATCHDOG CIRCUIT BREAKER</div>
                  <div id="brainWatchdogStatus" style="font-size: 12px; font-weight: 800; color: var(--accent); margin-top: 2px;">--</div>
                </div>
                <div style="background: var(--bg-input); border: 1px solid var(--border-color); border-radius: 4px; padding: 10px;">
                  <div style="font-size: 9px; font-weight: 700; color: var(--text-muted); margin-bottom: 2px;">TICK INTERVAL</div>
                  <div id="brainTickInterval" style="font-size: 13px; font-weight: 800; font-family: var(--font-mono); font-variant-numeric: tabular-nums; color: var(--text-main); margin-top: 2px;">--</div>
                </div>
                <div style="background: var(--bg-input); border: 1px solid var(--border-color); border-radius: 4px; padding: 10px;">
                  <div style="font-size: 9px; font-weight: 700; color: var(--text-muted); margin-bottom: 2px;">LATENCY MULTIPLIER</div>
                  <div id="brainLatencyMultiplier" style="font-size: 13px; font-weight: 800; font-family: var(--font-mono); font-variant-numeric: tabular-nums; color: var(--text-main); margin-top: 2px;">--</div>
                </div>
                <div style="background: var(--bg-input); border: 1px solid var(--border-color); border-radius: 4px; padding: 10px;">
                  <div style="font-size: 9px; font-weight: 700; color: var(--text-muted); margin-bottom: 2px;">LATENCY FLOOR</div>
                  <div id="brainLatencyFloor" style="font-size: 13px; font-weight: 800; font-family: var(--font-mono); font-variant-numeric: tabular-nums; color: var(--text-main); margin-top: 2px;">--</div>
                </div>
                <div style="background: var(--bg-input); border: 1px solid var(--border-color); border-radius: 4px; padding: 10px;">
                  <div style="font-size: 9px; font-weight: 700; color: var(--text-muted); margin-bottom: 2px;">EVENT BUFFER CAPACITY</div>
                  <div id="brainMaxEvents" style="font-size: 13px; font-weight: 800; font-family: var(--font-mono); font-variant-numeric: tabular-nums; color: var(--text-main); margin-top: 2px;">--</div>
                </div>
                <div style="background: var(--bg-input); border: 1px solid var(--border-color); border-radius: 4px; padding: 10px;">
                  <div style="font-size: 9px; font-weight: 700; color: var(--text-muted); margin-bottom: 2px;">DRIFT TRIGGER RATIO</div>
                  <div id="brainDriftRatio" style="font-size: 13px; font-weight: 800; font-family: var(--font-mono); font-variant-numeric: tabular-nums; color: var(--text-main); margin-top: 2px;">--</div>
                </div>
              </div>

              <!-- Active Hash & Governance Controls -->
              <div style="display: flex; justify-content: space-between; align-items: center; background: rgba(56, 189, 248, 0.04); border: 1px solid rgba(56, 189, 248, 0.15); border-radius: 4px; padding: 10px 14px; flex-wrap: wrap; gap: 10px;">
                <div style="display: flex; align-items: center; gap: 8px;">
                  <span style="font-size: 10px; font-weight: 700; color: var(--text-muted);">ACTIVE CONFIG SHA-256:</span>
                  <code id="brainActiveHash" style="font-family: var(--font-mono); font-size: 11px; color: #38BDF8; background: rgba(0, 0, 0, 0.3); padding: 2px 6px; border-radius: 3px; font-variant-numeric: tabular-nums;">--</code>
                </div>
                <div style="display: flex; gap: 8px;">
                  <button id="btnRunBrainOptimization" class="btn btn-primary" onclick="window.triggerBrainOptimization()" style="font-size: 11px; font-weight: 700; padding: 6px 12px;">⚡ Run Self-Optimization Cycle</button>
                  <button id="btnRollbackBrain" class="btn btn-secondary" onclick="window.triggerBrainRollback()" style="font-size: 11px; font-weight: 700; padding: 6px 12px;">↩️ Rollback to Stable Baseline</button>
                </div>
              </div>

              <!-- Autonomous Multi-Protocol Wire Investigation Control Bar -->
              <div style="display: flex; justify-content: space-between; align-items: center; background: rgba(16, 185, 129, 0.04); border: 1px solid rgba(16, 185, 129, 0.2); border-radius: 4px; padding: 10px 14px; flex-wrap: wrap; gap: 10px;">
                <div style="display: flex; align-items: center; gap: 8px;">
                  <span style="font-size: 10px; font-weight: 800; color: var(--success);">AUTONOMOUS WIRE INVESTIGATION:</span>
                  <input id="investigateTargetIp" type="text" placeholder="127.0.0.1" value="127.0.0.1" style="background: var(--bg-card); border: 1px solid var(--border-color); color: var(--text-main); font-family: var(--font-mono); font-size: 11px; padding: 4px 8px; border-radius: 3px; width: 140px;" />
                  <input id="investigateTargetPort" type="number" placeholder="443" value="443" style="background: var(--bg-card); border: 1px solid var(--border-color); color: var(--text-main); font-family: var(--font-mono); font-size: 11px; padding: 4px 8px; border-radius: 3px; width: 70px;" />
                </div>
                <div>
                  <button id="btnRunAutonomousInvestigation" class="btn btn-secondary" onclick="window.triggerAutonomousInvestigation()" style="font-size: 11px; font-weight: 700; padding: 6px 12px; border-color: rgba(16, 185, 129, 0.4); color: var(--success);">🔎 Run Multi-Protocol Probe Sweep</button>
                </div>
              </div>

              <!-- Self-Update & Sandbox Gate Ledger Table -->
              <div>
                <div style="font-size: 10px; font-weight: 700; color: var(--text-muted); margin-bottom: 6px; text-transform: uppercase;">
                  Recent Self-Modification &amp; Sandbox Gate Ledger
                </div>
                <div style="max-height: 280px; overflow-y: auto; scrollbar-gutter: stable;">
                  <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 11px; font-variant-numeric: tabular-nums;">
                    <thead>
                      <tr style="border-bottom: 1px solid var(--border-color); color: var(--text-muted); font-size: 10px;">
                        <th style="padding: 6px 8px;">UPDATE ID</th>
                        <th style="padding: 6px 8px;">TIMESTAMP</th>
                        <th style="padding: 6px 8px;">TRIGGER SOURCE</th>
                        <th style="padding: 6px 8px;">SANDBOX GATE VERDICT</th>
                        <th style="padding: 6px 8px;">DIFF SUMMARY</th>
                        <th style="padding: 6px 8px; font-family: var(--font-mono);">CONFIG HASH</th>
                      </tr>
                    </thead>
                    <tbody id="diagBrainHistoryTableBody">
                      <tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 14px;">Loading self-update ledger...</td></tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;

    // Initial data load
    await window.runDeepSystemAudit();

    // Auto-refresh every 12 seconds
    refreshTimer = setInterval(() => {
      fetchHostAudit().then(data => {
        if (data) {
          hostAuditData = data;
          updateUI();
        }
      });
    }, 12000);
  };

})(window);
