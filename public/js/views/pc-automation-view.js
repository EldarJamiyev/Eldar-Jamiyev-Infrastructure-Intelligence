/**
 * EJII Workstation Section 4: Automation of Local PC Settings (BAT Files @ e:\Scripts)
 * High-Speed Script Execution Bridge & Interactive Cyber Terminal
 * 100% Real OS Execution — Zero Simulation Doctrine.
 */

(function(window) {
  'use strict';

  let discoveredScripts = [];
  let activeCategoryFilter = 'all';
  let activeSearchTerm = '';
  let lastExecutedScript = null;
  let isExecuting = false;

  async function renderPcAutomationView() {
    const container = document.getElementById('mainContent');
    if (!container) return;

    const routeGen = window.currentRouteGeneration;
    const bootstrapScripts = window.EJIIStore?.bootstrap?.scripts;
    if (bootstrapScripts?.scripts && discoveredScripts.length === 0) {
      discoveredScripts = bootstrapScripts.scripts;
    }

    try {
      const data = (discoveredScripts.length > 0) ? { scripts: discoveredScripts, mountMetadata: bootstrapScripts?.mountMetadata } : await window.api('/api/network/automation/scripts');
      discoveredScripts = data?.scripts || [];

      container.innerHTML = `
        <div class="pc-automation-workstation" style="display: flex; flex-direction: column; height: calc(100vh - 80px); gap: 12px;">
          <!-- Top Header Banner -->
          <div class="card" style="margin: 0; padding: 12px 18px; border: 1px solid var(--border-default); background: var(--bg-surface); box-shadow: var(--shadow-sm); flex-shrink: 0;">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
              <div style="display: flex; align-items: center; gap: 10px;">
                <div style="width: 32px; height: 32px; border-radius: 6px; background: #EEF2FF; color: var(--accent-primary); display: flex; align-items: center; justify-content: center; font-size: 16px;">⚡</div>
                <div>
                  <div class="card-title" style="margin: 0; font-size: 14px; font-weight: 700; letter-spacing: -0.01em; color: var(--text-primary);">
                    Automation of Local PC Settings (BAT Files @ e:\\Scripts)
                  </div>
                  <div style="font-size: 11px; color: var(--text-secondary); font-family: var(--font-mono); margin-top: 2px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                    <span>📁 Mount: <code>${data?.mountMetadata?.activeDir || data?.directory || 'data/scripts_mount/Scripts'}</code></span>
                    <span>&bull;</span>
                    <span>Mode: <code>${data?.mountMetadata?.mountMode || 'VIRTUAL_MOUNT_FALLBACK'}</code></span>
                    <span>&bull;</span>
                    <span>Verified Scripts: <strong>${data?.mountMetadata?.scriptCount || discoveredScripts.length}</strong></span>
                  </div>
                </div>
              </div>

              <div style="display: flex; gap: 8px; align-items: center;">
                <button class="btn btn-secondary" onclick="window.checkLocalPrintSpoolerModal()" style="font-size: 11px; padding: 4px 10px; font-weight: 600; border-radius: 6px;" title="Inspect local Windows Print Spooler service, WSD ports, and stuck print jobs">
                  🖨️ Check Local Print Spooler
                </button>
                <button class="btn btn-secondary" onclick="window.showScriptHistory()" style="font-size: 11px; padding: 4px 12px; font-weight: 700; border-radius: 6px;">
                  📜 Execution History
                </button>
                <button class="btn btn-primary" onclick="window.rescanAutomationScripts()" style="font-size: 11px; padding: 4px 12px; font-weight: 700; border-radius: 6px;">
                  ↻ Rescan Folder
                </button>
              </div>
            </div>

            <!-- Category Pills & Search Filter -->
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; margin-top: 12px; padding-top: 10px; border-top: 1px solid var(--border-default);">
              <div class="segmented-control" style="display: inline-flex; gap: 2px; background: var(--bg-surface-subtle); padding: 2px; border-radius: 6px; border: 1px solid var(--border-default); flex-wrap: wrap;" id="automationCategoryPills">
                <button class="btn btn-primary btn-cat-pill" data-cat="all" onclick="window.setAutomationCategory('all')" style="font-size: 11px; padding: 3px 10px; border-radius: 4px;">
                  All Scripts (${discoveredScripts.length})
                </button>
                <button class="btn btn-secondary btn-cat-pill" data-cat="Network & DHCP" onclick="window.setAutomationCategory('Network & DHCP')" style="font-size: 11px; padding: 3px 10px; border-radius: 4px; border: none; background: transparent;">
                  🌐 Network &amp; DHCP
                </button>
                <button class="btn btn-secondary btn-cat-pill" data-cat="Printer & Spooler" onclick="window.setAutomationCategory('Printer & Spooler')" style="font-size: 11px; padding: 3px 10px; border-radius: 4px; border: none; background: transparent;">
                  🖨️ Printer &amp; Spooler
                </button>
                <button class="btn btn-secondary btn-cat-pill" data-cat="Security & Access" onclick="window.setAutomationCategory('Security & Access')" style="font-size: 11px; padding: 3px 10px; border-radius: 4px; border: none; background: transparent;">
                  🛡️ Security &amp; Access
                </button>
                <button class="btn btn-secondary btn-cat-pill" data-cat="System & Disk" onclick="window.setAutomationCategory('System & Disk')" style="font-size: 11px; padding: 3px 10px; border-radius: 4px; border: none; background: transparent;">
                  ⚡ System &amp; Disk
                </button>
              </div>

              <div style="display: flex; align-items: center; gap: 8px;">
                <input type="text" id="automationSearchInput" class="form-input" placeholder="Search scripts by title, command, tag..." style="width: 250px; font-size: 11px; padding: 4px 10px; border-radius: 6px;" oninput="window.onAutomationSearchChange(this.value)">
              </div>
            </div>
          </div>

          <!-- Main Dual Layout: Script Cards Grid (Left/Top) + Live Execution Terminal (Right/Bottom) -->
          <div style="display: grid; grid-template-columns: 1.15fr 0.85fr; flex: 1; gap: 12px; overflow: hidden;">
            <!-- Left Pane: Script Cards Grid -->
            <div class="card" style="margin: 0; display: flex; flex-direction: column; overflow: hidden; border: 1px solid var(--border-default); background: var(--bg-surface); box-shadow: var(--shadow-sm);">
              <div style="padding: 10px 14px; background: var(--bg-surface-subtle); border-bottom: 1px solid var(--border-default); font-size: 11px; font-weight: 700; color: var(--text-secondary); display: flex; justify-content: space-between; align-items: center;">
                <span>AVAILABLE AUTOMATION SCRIPTS (<span id="visibleScriptCount">${discoveredScripts.length}</span>)</span>
                <span style="font-size: 10px; color: var(--text-muted);">Click [▶ Run] to execute safely</span>
              </div>

              <div id="scriptCardsContainer" style="flex: 1; overflow-y: auto; padding: 12px; display: grid; grid-template-columns: 1fr; gap: 10px; scrollbar-gutter: stable; background: var(--bg-canvas);">
                <!-- Populated dynamically -->
              </div>
            </div>

            <!-- Right Pane: Live High-Density Execution Console / Terminal -->
            <div class="card" style="margin: 0; display: flex; flex-direction: column; overflow: hidden; background: var(--bg-terminal, #0F172A); border: 1px solid var(--border-terminal, #334155); box-shadow: var(--shadow-sm);">
              <!-- Terminal Header Bar with traffic light dots -->
              <div style="background: var(--bg-terminal-subtle, #1E293B); border-bottom: 1px solid var(--border-terminal, #334155); padding: 8px 14px; display: flex; justify-content: space-between; align-items: center; flex-shrink: 0;">
                <div style="display: flex; align-items: center; gap: 8px;">
                  <div style="display: flex; gap: 5px; align-items: center; margin-right: 4px;">
                    <span style="width: 10px; height: 10px; border-radius: 50%; background: #EF4444; display: inline-block;"></span>
                    <span style="width: 10px; height: 10px; border-radius: 50%; background: #F59E0B; display: inline-block;"></span>
                    <span style="width: 10px; height: 10px; border-radius: 50%; background: #10B981; display: inline-block;"></span>
                  </div>
                  <span style="font-family: var(--font-mono); font-size: 11px; font-weight: 700; color: #F8FAFC;">
                    EJII Host Execution Terminal &bull; e:\\Scripts
                  </span>
                </div>

                <div style="display: flex; gap: 6px; align-items: center;">
                  <span id="terminalStatusBadge" style="display: none; font-size: 10px; font-family: var(--font-mono); font-weight: 700; padding: 2px 8px; border-radius: 4px;"></span>
                  <span id="terminalDurationBadge" style="display: none; font-size: 10px; font-family: var(--font-mono); color: #94A3B8;"></span>
                  <button class="btn btn-secondary" onclick="window.copyTerminalOutput()" style="font-size: 10px; padding: 2px 8px; border-radius: 4px; border-color: #334155; color: #E2E8F0; background: #0F172A;">Copy</button>
                  <button class="btn btn-secondary" onclick="window.clearTerminalOutput()" style="font-size: 10px; padding: 2px 8px; border-radius: 4px; border-color: #334155; color: #E2E8F0; background: #0F172A;">Clear</button>
                  <button id="terminalRerunBtn" class="btn btn-secondary" onclick="window.rerunLastScript()" style="font-size: 10px; padding: 2px 8px; border-radius: 4px; display: none;">↻ Re-run</button>
                </div>
              </div>

              <!-- Terminal Body Output -->
              <div id="terminalOutput" style="flex: 1; padding: 14px; font-family: var(--font-mono); font-size: 11.5px; line-height: 1.5; color: #F8FAFC; overflow-y: auto; scrollbar-gutter: stable; user-select: text; white-space: pre-wrap; word-break: break-all;">
<span style="color: #64748B;">// EJII Host PC Automation Console ready.
// Select any script on the left and click [▶ Run] to execute directly against the host OS.
// All stdout, stderr, exit codes, and execution latency will stream here in real-time.</span>
              </div>
            </div>
          </div>
        </div>

        <!-- Script Inspection Modal -->
        <div id="scriptInspectionModal" class="modal-backdrop" style="display: none;" onclick="window.closeScriptModal(event)">
          <div class="modal-card" style="max-width: 800px; width: 90%; max-height: 85vh; overflow-y: auto; scrollbar-gutter: stable; padding-right: 20px;" onclick="event.stopPropagation()">
            <div class="modal-header" style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 10px;">
              <div>
                <div id="modalScriptTitle" style="font-weight: 800; font-size: 15px; color: var(--accent);">Script Title</div>
                <div id="modalScriptMeta" style="font-size: 11px; color: var(--text-muted); font-family: var(--font-mono); margin-top: 2px;"></div>
              </div>
              <button class="btn-logout" onclick="window.closeScriptModal()">✕</button>
            </div>
            <div style="padding: 16px 0;">
              <pre id="modalScriptContent" style="background: #060911; border: 1px solid var(--border-color); border-radius: 6px; padding: 14px; font-family: var(--font-mono); font-size: 11.5px; color: #E2E8F0; overflow-x: auto; max-height: 50vh; white-space: pre-wrap; word-break: break-all;"></pre>
            </div>
            <div class="modal-footer" style="display: flex; justify-content: flex-end; gap: 8px; border-top: 1px solid var(--border-color); padding-top: 10px;">
              <button class="btn btn-secondary" onclick="window.closeScriptModal()">Close</button>
              <button id="modalRunBtn" class="btn btn-primary" style="font-weight: 700;">▶ Run This Script</button>
            </div>
          </div>
        </div>

        <!-- Script History Modal -->
        <div id="scriptHistoryModal" class="modal-backdrop" style="display: none;" onclick="window.closeScriptHistoryModal(event)">
          <div class="modal-card" style="max-width: 860px; width: 92%; max-height: 85vh; overflow-y: auto; scrollbar-gutter: stable; padding-right: 20px;" onclick="event.stopPropagation()">
            <div class="modal-header" style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 10px;">
              <div>
                <div style="font-weight: 800; font-size: 15px; color: var(--accent);">📜 Host Automation Execution Ledger</div>
                <div style="font-size: 11px; color: var(--text-muted); font-family: var(--font-mono); margin-top: 2px;">
                  Audited execution history of host scripts &bull; Privilege tracking &bull; Elevation advisories
                </div>
              </div>
              <button class="btn-logout" onclick="window.closeScriptHistoryModal()">✕</button>
            </div>
            <div id="scriptHistoryModalContent" style="padding: 16px 0;">
              <div style="color: var(--text-dim); font-size: 12px; text-align: center; padding: 20px;">Loading history...</div>
            </div>
            <div class="modal-footer" style="display: flex; justify-content: flex-end; gap: 8px; border-top: 1px solid var(--border-color); padding-top: 10px;">
              <button class="btn btn-secondary" onclick="window.closeScriptHistoryModal()">Close</button>
            </div>
          </div>
        </div>
      `;

      renderScriptCards();
    } catch (err) {
      container.innerHTML = `<div class="card" style="color: var(--danger); padding: 24px;">Failed to load Automation Suite: ${err.message}</div>`;
    }
  }

  window.renderPcAutomationView = renderPcAutomationView;

  window.rescanAutomationScripts = function() {
    renderPcAutomationView();
  };

  window.setAutomationCategory = function(cat) {
    activeCategoryFilter = cat;
    document.querySelectorAll('.btn-cat-pill').forEach(btn => {
      btn.classList.toggle('btn-primary', btn.dataset.cat === cat);
      btn.classList.toggle('btn-secondary', btn.dataset.cat !== cat);
    });
    renderScriptCards();
  };
  window.filterScriptCategory = window.setAutomationCategory;

  window.onAutomationSearchChange = function(q) {
    activeSearchTerm = (q || '').toLowerCase().trim();
    renderScriptCards();
  };

  function renderScriptCards() {
    const container = document.getElementById('scriptCardsContainer');
    const countEl = document.getElementById('visibleScriptCount');
    if (!container) return;

    let filtered = discoveredScripts.slice();

    if (activeCategoryFilter !== 'all') {
      filtered = filtered.filter(s => {
        const cat = s.category || '';
        if (activeCategoryFilter === 'Network & DHCP') {
          return cat === 'Network & DNS Stack' || /network|dhcp|dns|ip/i.test(cat + ' ' + s.title);
        }
        if (activeCategoryFilter === 'Printer & Spooler') {
          return /spooler|printer|print/i.test(cat + ' ' + s.title);
        }
        if (activeCategoryFilter === 'System & Disk') {
          return /system|diagnostics|disk|performance|hardware/i.test(cat + ' ' + s.title);
        }
        return cat === activeCategoryFilter;
      });
    }

    if (activeSearchTerm) {
      filtered = filtered.filter(s =>
        s.title.toLowerCase().includes(activeSearchTerm) ||
        s.filename.toLowerCase().includes(activeSearchTerm) ||
        s.description.toLowerCase().includes(activeSearchTerm) ||
        s.category.toLowerCase().includes(activeSearchTerm)
      );
    }

    if (countEl) countEl.textContent = filtered.length;

    if (filtered.length === 0) {
      container.innerHTML = `
        <div style="padding: 30px; text-align: center; color: var(--text-dim); font-size: 12px;">
          No automation scripts match the selected filter.
        </div>
      `;
      return;
    }

    container.innerHTML = filtered.map(s => {
      const typeBadge = s.executionType === 'powershell'
        ? `<span style="background: #EFF6FF; border: 1px solid #BFDBFE; color: #1D4ED8; font-weight: 700; padding: 2px 6px; border-radius: 4px; font-size: 9.5px; font-family: var(--font-mono);">PS1</span>`
        : `<span style="background: #FFFBEB; border: 1px solid #FDE68A; color: #D97706; font-weight: 700; padding: 2px 6px; border-radius: 4px; font-size: 9.5px; font-family: var(--font-mono);">BAT</span>`;

      const privBadge = s.requiresElevation
        ? `<span style="background: #FEF2F2; border: 1px solid #FECACA; color: #DC2626; font-weight: 700; padding: 2px 6px; border-radius: 4px; font-size: 9.5px;">🛡️ Administrator</span>`
        : `<span style="background: #ECFDF5; border: 1px solid #A7F3D0; color: #059669; font-weight: 700; padding: 2px 6px; border-radius: 4px; font-size: 9.5px;">👤 Standard User</span>`;

      const riskBadge = s.riskLevel === 'CRITICAL'
        ? `<span style="background: #FEF2F2; border: 1px solid #FECACA; color: #DC2626; font-weight: 700; padding: 2px 6px; border-radius: 4px; font-size: 9.5px;">CRITICAL</span>`
        : (s.riskLevel === 'HIGH'
          ? `<span style="background: #FFF7ED; border: 1px solid #FED7AA; color: #EA580C; font-weight: 700; padding: 2px 6px; border-radius: 4px; font-size: 9.5px;">HIGH</span>`
          : (s.riskLevel === 'MEDIUM'
            ? `<span style="background: #FFFBEB; border: 1px solid #FDE68A; color: #D97706; font-weight: 700; padding: 2px 6px; border-radius: 4px; font-size: 9.5px;">MEDIUM</span>`
            : `<span style="background: #F1F5F9; border: 1px solid #E2E8F0; color: #475569; font-weight: 700; padding: 2px 6px; border-radius: 4px; font-size: 9.5px;">LOW</span>`));

      return `
        <div class="script-card" style="background: var(--bg-surface, #FFFFFF); border: 1px solid var(--border-default, #E5E7EB); border-radius: 8px; padding: 12px 14px; box-shadow: var(--shadow-sm); transition: border-color 0.15s ease, box-shadow 0.15s ease;" onmouseenter="this.style.borderColor='var(--accent-primary)'" onmouseleave="this.style.borderColor='var(--border-default)'">
          <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 8px;">
            <div style="flex: 1;">
              <div style="display: flex; align-items: center; gap: 6px; flex-wrap: wrap;">
                <span style="font-weight: 700; font-size: 13px; color: var(--text-primary);">${escapeHtml(s.title)}</span>
                <span style="background: var(--bg-surface-subtle); color: var(--text-secondary); font-size: 9.5px; font-weight: 600; padding: 1px 6px; border-radius: 4px; border: 1px solid var(--border-default);">
                  ${escapeHtml(s.categoryBadge || s.category)}
                </span>
                ${privBadge}
                ${riskBadge}
                ${typeBadge}
              </div>
              <div style="font-size: 10.5px; color: var(--text-secondary); font-family: var(--font-mono); margin-top: 3px;">
                ${escapeHtml(s.filename)} &bull; ${s.sizeBytes} bytes
              </div>
              <div style="font-size: 11px; color: var(--text-secondary); margin-top: 5px; line-height: 1.4;">
                ${escapeHtml(s.description)}
              </div>
            </div>

            <div style="display: flex; gap: 6px; align-items: center; flex-shrink: 0;">
              <button class="btn btn-secondary" onclick="window.viewScriptCode('${encodeURIComponent(s.filename)}')" style="font-size: 11px; padding: 4px 8px; border-radius: 4px;" title="Inspect raw script commands">
                👁 View Code
              </button>
              <button class="btn btn-primary" onclick="window.runScriptByName('${encodeURIComponent(s.filename)}')" style="font-size: 11px; padding: 4px 12px; font-weight: 700; border-radius: 4px;" title="Execute script immediately on host">
                ▶ Run Script
              </button>
            </div>
          </div>
        </div>
      `;
    }).join('');
  }

  window.runScriptByName = async function(encodedFilename) {
    const filename = decodeURIComponent(encodedFilename);
    const terminal = document.getElementById('terminalOutput');
    const badge = document.getElementById('terminalStatusBadge');
    const durationBadge = document.getElementById('terminalDurationBadge');
    const rerunBtn = document.getElementById('terminalRerunBtn');

    lastExecutedScript = filename;
    if (rerunBtn) rerunBtn.style.display = 'inline-block';

    if (badge) {
      badge.style.display = 'inline-block';
      badge.style.background = 'rgba(56, 189, 248, 0.2)';
      badge.style.color = '#38BDF8';
      badge.textContent = 'EXECUTING...';
    }

    if (terminal) {
      terminal.innerHTML = `<span style="color: #38BDF8;">$ e:\\Scripts\\${filename}</span>\n<span style="color: #64748B;">[Executing on Host Windows OS...]</span>\n`;
    }

    try {
      const res = await window.api('/api/network/automation/execute', {
        method: 'POST',
        body: JSON.stringify({ scriptName: filename })
      });

      if (badge) {
        if (res.exitCode === 0) {
          badge.style.background = 'rgba(16, 185, 129, 0.2)';
          badge.style.color = '#10B981';
          badge.textContent = `EXIT CODE: 0 [SUCCESS]`;
        } else {
          badge.style.background = 'rgba(239, 68, 68, 0.2)';
          badge.style.color = '#EF4444';
          badge.textContent = `EXIT CODE: ${res.exitCode} [FAILED]`;
        }
      }

      if (durationBadge) {
        durationBadge.style.display = 'inline-block';
        durationBadge.textContent = `${res.durationMs} ms`;
      }

      let formattedOut = '';
      if (res.elevationAdvisory) {
        formattedOut += `<div style="background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; border-radius: 6px; padding: 10px; margin-bottom: 12px; color: #fca5a5; font-size: 11.5px;"><b>⚠️ ELEVATION ADVISORY:</b><br>${escapeHtml(res.elevationAdvisory)}</div>`;
      }
      if (res.stdout) {
        formattedOut += `<span style="color: #F8FAFC;">${escapeHtml(res.stdout)}</span>\n`;
      }
      if (res.stderr) {
        formattedOut += `<span style="color: #EF4444; font-weight: 700;">[STDERR]\n${escapeHtml(res.stderr)}</span>\n`;
      }
      if (!res.stdout && !res.stderr) {
        formattedOut += `<span style="color: #10B981;">[Command finished with no output. Exit code: ${res.exitCode}]</span>\n`;
      }

      if (terminal) {
        terminal.innerHTML = `
<span style="color: #38BDF8;">$ e:\\Scripts\\${filename}</span>
<span style="color: #64748B;">[Duration: ${res.durationMs} ms &bull; Engine: ${res.executionType}]</span>

${formattedOut}
<span style="color: #10B981;">$ _</span>`;
        terminal.scrollTop = terminal.scrollHeight;
      }
    } catch (err) {
      if (badge) {
        badge.style.background = 'rgba(239, 68, 68, 0.2)';
        badge.style.color = '#EF4444';
        badge.textContent = err.message && err.message.includes('403') ? 'ACCESS DENIED (403)' : 'EXECUTION ERROR';
      }
      if (terminal) {
        const isRbac = err.message && (err.message.includes('403') || err.message.toLowerCase().includes('forbidden') || err.message.toLowerCase().includes('access denied'));
        const rbacHint = isRbac
          ? `\n<div style="background: rgba(239,68,68,0.15); border: 1px solid rgba(239,68,68,0.3); border-radius: 6px; padding: 10px; margin-top: 8px; color: #fca5a5; font-size: 11px;">` +
            `<b>🛡️ [RBAC RESTRICTION]</b> Host script execution requires <b>ADMIN</b>, <b>SYSADMIN</b>, or <b>NETWORK_ADMIN</b> role.<br>` +
            `The current session lacks the required capability. Please switch to the Lead Architect & Admin profile.` +
            `</div>`
          : '';
        terminal.innerHTML += `\n<span style="color: #EF4444; font-weight: 700;">Error: ${escapeHtml(err.message)}</span>${rbacHint}\n<span style="color: #64748B;">$ _</span>`;
        terminal.scrollTop = terminal.scrollHeight;
      }
    }
  };

  window.rerunLastScript = function() {
    if (lastExecutedScript) {
      window.runScriptByName(encodeURIComponent(lastExecutedScript));
    }
  };

  window.viewScriptCode = async function(encodedFilename) {
    const filename = decodeURIComponent(encodedFilename);
    const modal = document.getElementById('scriptInspectionModal');
    const titleEl = document.getElementById('modalScriptTitle');
    const metaEl = document.getElementById('modalScriptMeta');
    const contentEl = document.getElementById('modalScriptContent');
    const runBtn = document.getElementById('modalRunBtn');

    if (!modal) return;
    modal.style.display = 'flex';

    if (titleEl) titleEl.textContent = filename;
    if (metaEl) metaEl.textContent = 'Loading script contents...';
    if (contentEl) contentEl.textContent = 'Loading...';

    try {
      const data = await window.api('/api/network/automation/view', {
        method: 'POST',
        body: JSON.stringify({ scriptName: filename })
      });

      if (metaEl) {
        metaEl.textContent = `Category: ${data.category?.category || 'General'} | Type: ${data.executionType} | Size: ${data.sizeBytes} B | Modified: ${data.lastModified}`;
      }
      if (contentEl) {
        contentEl.textContent = data.content;
      }
      if (runBtn) {
        runBtn.onclick = () => {
          window.closeScriptModal();
          window.runScriptByName(encodeURIComponent(filename));
        };
      }
    } catch (err) {
      if (contentEl) contentEl.textContent = 'Failed to load script: ' + err.message;
    }
  };

  window.closeScriptModal = function(e) {
    const modal = document.getElementById('scriptInspectionModal');
    if (modal) modal.style.display = 'none';
  };

  window.showScriptHistory = async function() {
    const modal = document.getElementById('scriptHistoryModal');
    const content = document.getElementById('scriptHistoryModalContent');
    if (!modal) return;
    modal.style.display = 'flex';
    if (content) {
      content.innerHTML = '<div style="color: var(--text-dim); font-size: 12px; text-align: center; padding: 24px;">Loading audited execution ledger...</div>';
    }

    try {
      const res = await window.api('/api/network/scripts/history');
      const list = res?.history || [];
      if (list.length === 0) {
        if (content) {
          content.innerHTML = `
            <div style="padding: 30px; text-align: center; color: var(--text-muted); font-size: 12px;">
              No host scripts have been executed during this session yet.<br>
              <span style="font-size: 11px; color: #64748B;">Run any script from the Automation console to populate this ledger.</span>
            </div>
          `;
        }
        return;
      }

      const rows = list.map(item => {
        const timeStr = item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : '--:--:--';
        const statusBadge = item.exitCode === 0
          ? '<span style="background: rgba(16, 185, 129, 0.2); color: #10B981; font-weight: 700; padding: 2px 6px; border-radius: 4px; font-size: 10px;">SUCCESS (0)</span>'
          : `<span style="background: rgba(239, 68, 68, 0.2); color: #EF4444; font-weight: 700; padding: 2px 6px; border-radius: 4px; font-size: 10px;">EXIT (${item.exitCode})</span>`;

        const advisory = item.elevationAdvisory
          ? `<div style="margin-top: 4px; font-size: 10px; color: #FCA5A5; background: rgba(239, 68, 68, 0.1); border-left: 2px solid #EF4444; padding: 2px 6px; border-radius: 2px;">⚠️ ${escapeHtml(item.elevationAdvisory)}</div>`
          : '';

        return `
          <tr style="border-bottom: 1px solid rgba(255,255,255,0.05); font-size: 11.5px;">
            <td style="padding: 8px 10px; font-family: var(--font-mono); color: #94A3B8;">${timeStr}</td>
            <td style="padding: 8px 10px; font-weight: 600; color: #F1F5F9;">
              ${escapeHtml(item.scriptName)}
              ${advisory}
            </td>
            <td style="padding: 8px 10px; font-family: var(--font-mono); font-size: 10.5px; color: #38BDF8;">${escapeHtml(item.executionType || 'cmd')}</td>
            <td style="padding: 8px 10px;">${statusBadge}</td>
            <td style="padding: 8px 10px; font-family: var(--font-mono); color: #94A3B8;">${item.durationMs ?? 0} ms</td>
            <td style="padding: 8px 10px; text-align: right;">
              <button class="btn btn-secondary" onclick="window.closeScriptHistoryModal(); window.runScriptByName('${encodeURIComponent(item.scriptName)}');" style="font-size: 10px; padding: 2px 8px;">
                ▶ Re-run
              </button>
            </td>
          </tr>
        `;
      }).join('');

      if (content) {
        content.innerHTML = `
          <div style="max-height: 55vh; overflow-y: auto; scrollbar-gutter: stable;">
            <table style="width: 100%; border-collapse: collapse; text-align: left;">
              <thead>
                <tr style="border-bottom: 1px solid rgba(255,255,255,0.1); font-size: 10.5px; color: var(--text-dim); text-transform: uppercase;">
                  <th style="padding: 6px 10px;">Time</th>
                  <th style="padding: 6px 10px;">Script</th>
                  <th style="padding: 6px 10px;">Type</th>
                  <th style="padding: 6px 10px;">Status</th>
                  <th style="padding: 6px 10px;">Duration</th>
                  <th style="padding: 6px 10px; text-align: right;">Action</th>
                </tr>
              </thead>
              <tbody>
                ${rows}
              </tbody>
            </table>
          </div>
        `;
      }
    } catch (err) {
      if (content) {
        content.innerHTML = `<div style="color: var(--danger); padding: 16px; font-size: 12px;">Failed to load script history: ${escapeHtml(err.message)}</div>`;
      }
    }
  };

  window.closeScriptHistoryModal = function(e) {
    const modal = document.getElementById('scriptHistoryModal');
    if (modal) modal.style.display = 'none';
  };

  window.copyTerminalOutput = function() {
    const terminal = document.getElementById('terminalOutput');
    if (terminal) {
      window.navigator.clipboard.writeText(terminal.innerText);
      alert('Terminal output copied to clipboard.');
    }
  };

  window.clearTerminalOutput = function() {
    const terminal = document.getElementById('terminalOutput');
    const badge = document.getElementById('terminalStatusBadge');
    const durationBadge = document.getElementById('terminalDurationBadge');
    if (badge) badge.style.display = 'none';
    if (durationBadge) durationBadge.style.display = 'none';
    if (terminal) {
      terminal.innerHTML = `<span style="color: #64748B;">// Terminal cleared. Ready for next command.</span>\n<span style="color: #10B981;">$ _</span>`;
    }
  };

  function escapeHtml(str) {
    return String(str || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

})(window);
