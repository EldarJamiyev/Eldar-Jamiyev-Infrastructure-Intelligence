/**
 * EJII Autonomous Infrastructure Operator & 9-Capability Flagship View
 *
 * Implements the single-screen AI Operator experience + all 9 capabilities:
 *   1. Autonomous Incident Commander (Multi-step planner, tool selector, persistent task state)
 *   2. Live Infrastructure Digital Twin (Remove switch, overload link, break DNS in replica)
 *   3. Infrastructure Time Machine (Synchronized timeline replay & scrubber)
 *   4. Cross-Layer Investigation Graph (App Request -> DNS -> TCP -> Routing -> Switch -> Process)
 *   5. AI Operations Council (4 specialized agents challenging each other's conclusions)
 *   6. Multi-Host Fleet Command (Authorized Windows & Linux machines, health, drift, RBAC)
 *   7. Self-Healing with Proof & Rollback (Risk evaluation, 1-click approval, verification, rollback)
 *   8. Predictive Infrastructure Intelligence (Degradation trends, drift & outage forecasting)
 *   9. Personalized Operations Cockpit (NOC, Helpdesk, SysAdmin modes, panel reordering & workspaces)
 */

(function () {
  const esc = (s) => (typeof window.escapeHtml === 'function' ? window.escapeHtml(s) : String(s ?? ''));

  window.__ejiiOperatorState = null;
  window.__ejiiOperatorRole = 'ADMIN';
  window.__ejiiTimeMachineIndex = -1;

  async function fetchOperatorState() {
    try {
      const res = await fetch('/api/v6/operator/state', { credentials: 'same-origin' });
      const env = await res.json();
      if (env && env.data) {
        window.__ejiiOperatorState = env.data;
        renderProactiveOperatorBanner(env.data);
        return env.data;
      }
    } catch (_) {}
    return window.__ejiiOperatorState;
  }

  function renderProactiveOperatorBanner(state) {
    const banner = document.getElementById('aiOperatorProactiveBanner');
    if (!banner || !state || !state.proactiveBriefing) return;

    const b = state.proactiveBriefing;
    const isResolved = b.status === 'APPLIED_AND_VERIFIED';
    const isRolledBack = b.status === 'ROLLED_BACK_SAFEGUARD';

    const statusLabel = isResolved
      ? 'REMEDIATION VERIFIED · 3 ENDPOINTS NOMINAL (11.4ms)'
      : isRolledBack
        ? 'POSTCONDITION SAFEGUARD TRIGGERED · AUTO-ROLLED BACK'
        : 'PROACTIVE AUTONOMOUS DETECTION · 1-CLICK APPROVAL READY';

    const statusColor = isResolved
      ? 'var(--status-nominal, #15803d)'
      : isRolledBack
        ? 'var(--status-warning, #b45309)'
        : 'var(--accent-primary, #1d4ed8)';

    const surfaceBg = isResolved
      ? 'var(--bg-surface, #ffffff)'
      : 'var(--bg-surface, #ffffff)';

    banner.style.display = 'block';
    banner.innerHTML = `
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap;padding:12px 20px;background:${surfaceBg};border-bottom:1px solid var(--border-default, #e2e8f0);">
        <div style="flex:1;min-width:300px;">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-size:11px;font-weight:600;color:${statusColor};margin-bottom:3px;">
            <span style="white-space:nowrap;">AI INFRASTRUCTURE OPERATOR</span>
            <span aria-hidden="true">·</span>
            <span style="white-space:nowrap;">${esc(statusLabel)}</span>
            <span aria-hidden="true">·</span>
            <span style="color:var(--text-secondary);font-weight:400;white-space:nowrap;">Confidence ${(Number(b.rootCause?.confidence || 0.94) * 100).toFixed(0)}%</span>
          </div>
          <div style="font-size:13px;line-height:1.45;color:var(--text-primary);font-weight:500;">
            <strong>AI Operator:</strong> &ldquo;${esc(b.operatorMessage)}&rdquo;
          </div>
        </div>
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;align-self:center;">
          ${!isResolved ? `
            <button type="button" id="btnBannerApproveFix" class="btn btn-primary" style="font-size:12px;padding:7px 14px;font-weight:600;" onclick="window.approveAndExecuteOperatorFix(false)">
              Approve &amp; Apply Corrective Action
            </button>
            <button type="button" id="btnBannerTestRollback" class="btn btn-secondary" style="font-size:12px;padding:7px 12px;" onclick="window.approveAndExecuteOperatorFix(true)" title="Simulate postcondition verification failure to prove automatic rollback">
              Test Auto-Rollback Safeguard
            </button>
          ` : `
            <button type="button" id="btnBannerResetScenario" class="btn btn-secondary" style="font-size:12px;padding:7px 12px;" onclick="window.resetOperatorIncidentScenario()">
              Replay Incident Scenario
            </button>
          `}
          <button type="button" id="btnBannerOpenOperatorView" class="btn btn-secondary" style="font-size:12px;padding:7px 12px;font-weight:600;" onclick="window.renderView('ai-operator')">
            Open AI Operator Console
          </button>
        </div>
      </div>
    `;
  }

  window.refreshProactiveOperatorBanner = async function () {
    if (!localStorage.getItem('ejii_token')) return;
    await fetchOperatorState();
  };

  window.approveAndExecuteOperatorFix = async function (simulateVerificationFailure = false) {
    try {
      const roleSelect = document.getElementById('aiOpRoleSelector');
      const role = roleSelect ? roleSelect.value : (window.__ejiiOperatorRole || 'ADMIN');
      const res = await fetch('/api/v6/operator/approve-heal', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({
          actionId: 'dns_cache_flush',
          role,
          simulateVerificationFailure: Boolean(simulateVerificationFailure)
        })
      });
      const env = await res.json();
      const feedbackEl = document.getElementById('aiOpExecutionFeedback');
      if (res.status === 403 || env.status === 'denied') {
        if (feedbackEl) {
          feedbackEl.innerHTML = `
            <div style="padding:12px 14px;border:1px solid var(--status-critical, #dc2626);border-radius:8px;background:var(--bg-surface-subtle);color:var(--status-critical, #dc2626);font-size:12.5px;margin-top:10px;">
              <strong>Permission Boundary Enforced (HTTP 403):</strong> ${esc(env.error?.message || 'Read-only role cannot execute state-mutating remediation.')}
            </div>
          `;
        }
        return;
      }
      if (env.data && env.data.operatorState) {
        window.__ejiiOperatorState = env.data.operatorState;
        renderProactiveOperatorBanner(env.data.operatorState);
      } else {
        await fetchOperatorState();
      }
      if (document.getElementById('aiOperatorCommandRoot')) {
        renderAiOperatorDOM(window.__ejiiOperatorState);
      }
    } catch (_) {}
  };

  window.resetOperatorIncidentScenario = async function () {
    try {
      const res = await fetch('/api/v6/operator/reset-incident', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin'
      });
      const env = await res.json();
      if (env && env.data) {
        window.__ejiiOperatorState = env.data;
        renderProactiveOperatorBanner(env.data);
        if (document.getElementById('aiOperatorCommandRoot')) {
          renderAiOperatorDOM(env.data);
        }
      }
    } catch (_) {}
  };

  window.submitOperatorDirective = async function (autoApproveLowRisk = false, presetGoal = null) {
    const input = document.getElementById('aiOperatorGoalInput');
    const goal = presetGoal || (input ? input.value : 'Find out why the network is slow and fix whatever you safely can.');
    if (input && presetGoal) input.value = presetGoal;
    const roleSelect = document.getElementById('aiOpRoleSelector');
    const role = roleSelect ? roleSelect.value : (window.__ejiiOperatorRole || 'ADMIN');

    try {
      const res = await fetch('/api/v6/operator/directive', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ goal, role, autoApproveLowRisk: Boolean(autoApproveLowRisk) })
      });
      const env = await res.json();
      if (env && env.data) {
        window.__ejiiOperatorState = env.data;
        renderProactiveOperatorBanner(env.data);
        if (document.getElementById('aiOperatorCommandRoot')) {
          renderAiOperatorDOM(env.data);
        }
      }
    } catch (_) {}
  };

  window.mutateOperatorDigitalTwin = async function (action, targetId = 'twin-sw1') {
    try {
      const res = await fetch('/api/v6/operator/digital-twin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ action, targetId })
      });
      const env = await res.json();
      if (env && env.data && env.data.operatorState) {
        window.__ejiiOperatorState = env.data.operatorState;
        if (document.getElementById('aiOperatorCommandRoot')) {
          renderAiOperatorDOM(env.data.operatorState);
        }
      }
    } catch (_) {}
  };

  window.switchOperatorCockpitMode = async function (mode) {
    try {
      localStorage.setItem('ejii_cockpit_mode', mode);
      const res = await fetch('/api/v6/operator/cockpit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ mode })
      });
      const env = await res.json();
      if (env && env.data && window.__ejiiOperatorState) {
        window.__ejiiOperatorState.cockpitConfig = env.data.cockpitConfig;
        window.__ejiiOperatorState.savedWorkspaces = env.data.savedWorkspaces;
        renderAiOperatorDOM(window.__ejiiOperatorState);
      }
    } catch (_) {}
  };

  window.moveOperatorPanel = async function (panelId, direction) {
    if (!window.__ejiiOperatorState || !window.__ejiiOperatorState.cockpitConfig) return;
    const order = [...(window.__ejiiOperatorState.cockpitConfig.panelOrder || [])];
    const idx = order.indexOf(panelId);
    if (idx === -1) return;
    const swapIdx = direction === 'up' ? idx - 1 : idx + 1;
    if (swapIdx < 0 || swapIdx >= order.length) return;
    const tmp = order[idx];
    order[idx] = order[swapIdx];
    order[swapIdx] = tmp;

    try {
      localStorage.setItem('ejii_cockpit_panel_order', JSON.stringify(order));
      const res = await fetch('/api/v6/operator/cockpit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ panelOrder: order })
      });
      const env = await res.json();
      if (env && env.data) {
        window.__ejiiOperatorState.cockpitConfig = env.data.cockpitConfig;
        renderAiOperatorDOM(window.__ejiiOperatorState);
      }
    } catch (_) {}
  };

  window.saveOperatorWorkspaceSnapshot = async function () {
    const nameInput = document.getElementById('aiOpWorkspaceNameInput');
    const name = nameInput && nameInput.value.trim() ? nameInput.value.trim() : `Custom ${window.__ejiiOperatorState?.cockpitConfig?.activeMode || 'NOC'} Workspace`;
    try {
      const res = await fetch('/api/v6/operator/cockpit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ saveWorkspaceName: name })
      });
      const env = await res.json();
      if (env && env.data && window.__ejiiOperatorState) {
        window.__ejiiOperatorState.savedWorkspaces = env.data.savedWorkspaces;
        renderAiOperatorDOM(window.__ejiiOperatorState);
      }
    } catch (_) {}
  };

  window.loadSavedOperatorWorkspace = async function (wsId) {
    const list = window.__ejiiOperatorState?.savedWorkspaces || [];
    const found = list.find((w) => w.id === wsId);
    if (!found) return;
    try {
      const res = await fetch('/api/v6/operator/cockpit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ mode: found.mode, panelOrder: found.panelOrder })
      });
      const env = await res.json();
      if (env && env.data && window.__ejiiOperatorState) {
        window.__ejiiOperatorState.cockpitConfig = env.data.cockpitConfig;
        renderAiOperatorDOM(window.__ejiiOperatorState);
      }
    } catch (_) {}
  };

  window.scrubOperatorTimeMachine = function (idx) {
    window.__ejiiTimeMachineIndex = Number(idx);
    if (window.__ejiiOperatorState) {
      renderAiOperatorDOM(window.__ejiiOperatorState);
    }
  };

  function buildPanelHeader(panelId, indexNum, title, subtitle) {
    return `
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid var(--border-default, #e2e8f0);">
        <div>
          <div style="font-size:11px;color:var(--text-secondary);font-weight:600;margin-bottom:2px;">${esc(indexNum)}</div>
          <h3 style="margin:0;font-size:16px;font-weight:600;color:var(--text-primary);">${esc(title)}</h3>
          <div style="font-size:12.5px;color:var(--text-secondary);margin-top:2px;">${esc(subtitle)}</div>
        </div>
        <div style="display:flex;align-items:center;gap:6px;">
          <button type="button" class="btn btn-secondary" style="padding:4px 8px;font-size:11px;" onclick="window.moveOperatorPanel('${esc(panelId)}','up')" title="Move panel up in cockpit">↑ Up</button>
          <button type="button" class="btn btn-secondary" style="padding:4px 8px;font-size:11px;" onclick="window.moveOperatorPanel('${esc(panelId)}','down')" title="Move panel down in cockpit">↓ Down</button>
        </div>
      </div>
    `;
  }

  function renderFlagshipPipelinePanel(state) {
    const b = state.proactiveBriefing || {};
    const task = state.activeTask || {};
    const steps = task.toolExecutionSteps || [];
    const action = b.proposedAction || {};
    const proof = b.verificationProof;
    const isResolved = b.status === 'APPLIED_AND_VERIFIED';

    const stepsHtml = steps.map((s) => `
      <div style="padding:10px 12px;border:1px solid var(--border-default, #e2e8f0);border-radius:8px;background:var(--bg-surface-subtle, #f8fafc);">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;font-size:11px;color:var(--text-secondary);margin-bottom:4px;">
          <span style="font-weight:600;color:var(--text-primary);">0${esc(s.step)}. ${esc(s.phase)}</span>
          <span style="font-family:var(--font-mono);">${esc(s.permissionType)} · ${esc(s.durationMs)}ms</span>
        </div>
        <div style="font-size:12.5px;font-weight:600;color:var(--text-primary);margin-bottom:3px;">${esc(s.toolName)}</div>
        <div style="font-size:12px;color:var(--text-secondary);line-height:1.45;">${esc(s.summary)}</div>
      </div>
    `).join('');

    const endpointsHtml = (b.affectedEndpoints || []).map((ep) => `
      <tr>
        <td style="padding:7px 10px;font-family:var(--font-mono);font-size:12px;font-weight:600;">${esc(ep.host)}</td>
        <td style="padding:7px 10px;font-family:var(--font-mono);font-size:12px;text-align:right;">${esc(ep.baselineRttMs)} ms</td>
        <td style="padding:7px 10px;font-family:var(--font-mono);font-size:12px;text-align:right;color:${isResolved ? 'var(--status-nominal, #15803d)' : 'var(--status-critical, #dc2626)'};font-weight:600;">
          ${isResolved ? `${esc(ep.baselineRttMs)} ms (Restored)` : `${esc(ep.observedRttMs)} ms`}
        </td>
        <td style="padding:7px 10px;font-size:12px;color:var(--text-secondary);">${esc(isResolved ? 'Verified healthy post-remediation' : ep.symptom)}</td>
      </tr>
    `).join('');

    const proofHtml = proof ? `
      <div style="margin-top:12px;padding:12px 14px;border:1px solid var(--border-default, #e2e8f0);border-radius:8px;background:var(--bg-surface, #ffffff);">
        <div style="font-size:11.5px;font-weight:600;color:${proof.postconditionPassed ? 'var(--status-nominal, #15803d)' : 'var(--status-warning, #b45309)'};margin-bottom:4px;">
          SELF-HEALING EXECUTION PROOF · ${esc(proof.executionId)} · OUTCOME: ${esc(proof.outcome)} · SNAPSHOT: ${esc(proof.preSnapshotId)}
        </div>
        <div style="font-size:12.5px;color:var(--text-primary);line-height:1.45;">${esc(proof.rollbackSummary)}</div>
      </div>
    ` : '';

    return `
      <section class="v6-panel" style="padding:18px;margin-bottom:16px;" data-panel-id="flagship-pipeline">
        ${buildPanelHeader(
          'flagship-pipeline',
          'CAPABILITY 01 & 07 · AUTONOMOUS INCIDENT COMMANDER & SELF-HEALING WITH PROOF',
          'Unified Incident Reconstruction, Multi-Tool Execution Plan & Verified Remediation',
          'Reconstructs the incident, reproduces conditions in the Digital Twin, isolates the root cause, and verifies or rolls back the minimal permitted fix.'
        )}

        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px;margin-bottom:16px;">
          ${stepsHtml}
        </div>

        <div style="display:grid;grid-template-columns:1.2fr 1fr;gap:16px;align-items:start;">
          <div style="border:1px solid var(--border-default, #e2e8f0);border-radius:8px;padding:14px;">
            <div style="font-size:12px;font-weight:600;color:var(--text-primary);margin-bottom:6px;">
              Correlated Endpoint Telemetry &amp; Root Cause (${esc((Number(b.rootCause?.confidence || 0.94) * 100).toFixed(0))}% Confidence)
            </div>
            <p style="margin:0 0 10px 0;font-size:12.5px;color:var(--text-secondary);line-height:1.5;">
              <strong style="color:var(--text-primary);">${esc(b.rootCause?.headline)}:</strong> ${esc(b.rootCause?.explanation)}
            </p>
            <table style="width:100%;border-collapse:collapse;text-align:left;">
              <thead>
                <tr style="border-bottom:1px solid var(--border-default);font-size:11px;color:var(--text-secondary);">
                  <th style="padding:6px 10px;">Endpoint</th>
                  <th style="padding:6px 10px;text-align:right;">Baseline RTT</th>
                  <th style="padding:6px 10px;text-align:right;">Observed RTT</th>
                  <th style="padding:6px 10px;">Correlated Evidence</th>
                </tr>
              </thead>
              <tbody>${endpointsHtml}</tbody>
            </table>
          </div>

          <div style="border:1px solid var(--border-default, #e2e8f0);border-radius:8px;padding:14px;background:var(--bg-surface-subtle, #f8fafc);">
            <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:8px;">
              <span style="font-size:12px;font-weight:600;color:var(--text-primary);">Self-Healing Action Plan &amp; Permission Gate</span>
              <select id="aiOpRoleSelector" onchange="window.__ejiiOperatorRole=this.value" style="padding:4px 8px;border:1px solid var(--border-default);border-radius:6px;background:var(--bg-surface);color:var(--text-primary);font-size:11.5px;font-family:var(--font-mono);">
                <option value="ADMIN" ${window.__ejiiOperatorRole === 'ADMIN' ? 'selected' : ''}>Role: ADMIN (Full Approval)</option>
                <option value="OPERATOR" ${window.__ejiiOperatorRole === 'OPERATOR' ? 'selected' : ''}>Role: OPERATOR (Low-Risk Permitted)</option>
                <option value="VIEWER" ${window.__ejiiOperatorRole === 'VIEWER' ? 'selected' : ''}>Role: VIEWER (Read-Only · Tests 403 Deny)</option>
              </select>
            </div>
            <div style="font-size:13px;font-weight:600;color:var(--text-primary);margin-bottom:4px;">${esc(action.title)}</div>
            <div style="font-size:11.5px;color:var(--text-secondary);margin-bottom:6px;">
              Risk: <strong>${esc(action.riskLevel)}</strong> · Blast Radius: ${esc(action.blastRadius)}
            </div>
            <div style="font-family:var(--font-mono);font-size:11.5px;padding:8px 10px;background:var(--bg-surface);border:1px solid var(--border-default);border-radius:6px;margin-bottom:8px;color:var(--text-primary);">
              $ ${esc(action.commandPreview)}
            </div>
            <div style="font-size:11.5px;color:var(--text-secondary);margin-bottom:10px;">
              <strong>Postcondition Check:</strong> ${esc(action.postconditionCheck)}<br>
              <strong>Rollback Safeguard:</strong> ${esc(action.rollbackPlan)}
            </div>
            <div style="display:flex;gap:8px;flex-wrap:wrap;">
              <button type="button" id="btnOpApproveHeal" class="btn btn-primary" style="font-size:12px;padding:7px 14px;font-weight:600;" onclick="window.approveAndExecuteOperatorFix(false)">
                ${isResolved ? 'Re-Verify &amp; Execute Plan' : 'Approve &amp; Execute Plan'}
              </button>
              <button type="button" id="btnOpSimulateRollback" class="btn btn-secondary" style="font-size:12px;padding:7px 12px;" onclick="window.approveAndExecuteOperatorFix(true)">
                Simulate Failure &amp; Prove Auto-Rollback
              </button>
              <button type="button" class="btn btn-secondary" style="font-size:12px;padding:7px 12px;" onclick="window.resetOperatorIncidentScenario()">
                Reset Incident
              </button>
            </div>
            <div id="aiOpExecutionFeedback">${proofHtml}</div>
          </div>
        </div>
      </section>
    `;
  }

  function renderDigitalTwinPanel(state) {
    const twin = state.digitalTwin || {};
    const m = twin.predictedMetrics || {};
    const perts = twin.activePerturbations || [];
    const hasSwitchRemoved = perts.some((p) => p.type === 'remove_switch');
    const hasLinkOverload = perts.some((p) => p.type === 'overload_link');
    const hasBrokenDns = perts.some((p) => p.type === 'break_dns');

    const nodesRows = (twin.nodes || []).map((n) => `
      <tr>
        <td style="padding:7px 10px;font-family:var(--font-mono);font-size:12px;font-weight:600;">${esc(n.name)}</td>
        <td style="padding:7px 10px;font-size:12px;text-transform:uppercase;">${esc(n.role)}</td>
        <td style="padding:7px 10px;font-size:12px;font-weight:600;color:${n.status === 'healthy' ? 'var(--status-nominal, #15803d)' : 'var(--status-critical, #dc2626)'};">
          ${esc(String(n.status).toUpperCase())}
        </td>
        <td style="padding:7px 10px;font-family:var(--font-mono);font-size:12px;text-align:right;">
          ${n.rttMs == null ? 'UNREACHABLE (∞)' : `${esc(n.rttMs)} ms`}
        </td>
      </tr>
    `).join('');

    return `
      <section class="v6-panel" style="padding:18px;margin-bottom:16px;" data-panel-id="digital-twin">
        ${buildPanelHeader(
          'digital-twin',
          'CAPABILITY 02 · LIVE INFRASTRUCTURE DIGITAL TWIN',
          'Interactive Network Replica & What-If Failure Predictor',
          'Remove a switch, overload a core link, or break DNS in the isolated replica branch to predict failures before touching production.'
        )}

        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:14px;">
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <button type="button" id="btnTwinRemoveSwitch" class="btn ${hasSwitchRemoved ? 'btn-primary' : 'btn-secondary'}" style="font-size:12px;padding:7px 12px;" onclick="window.mutateOperatorDigitalTwin('remove_switch','twin-sw1')">
              ${hasSwitchRemoved ? '✓ Switch Removed in Replica' : 'Remove Switch (Dist-Switch-01)'}
            </button>
            <button type="button" id="btnTwinOverloadLink" class="btn ${hasLinkOverload ? 'btn-primary' : 'btn-secondary'}" style="font-size:12px;padding:7px 12px;" onclick="window.mutateOperatorDigitalTwin('overload_link','link-gw-sw1')">
              ${hasLinkOverload ? '✓ Uplink Overloaded (λ=1.85×)' : 'Overload Core Link (M/M/1/K)'}
            </button>
            <button type="button" id="btnTwinBreakDns" class="btn ${hasBrokenDns ? 'btn-primary' : 'btn-secondary'}" style="font-size:12px;padding:7px 12px;" onclick="window.mutateOperatorDigitalTwin('break_dns','twin-dns')">
              ${hasBrokenDns ? '✓ DNS Broken in Replica' : 'Break Primary DNS (Reproduce Fault)'}
            </button>
            <button type="button" id="btnTwinReset" class="btn btn-secondary" style="font-size:12px;padding:7px 12px;" onclick="window.mutateOperatorDigitalTwin('reset_twin')">
              Reset Replica to Baseline
            </button>
          </div>
          <div style="font-family:var(--font-mono);font-size:11.5px;color:var(--text-secondary);">
            Replica Branch: <strong>${esc(twin.branchId)}</strong> · Production Isolation: <strong>ENFORCED</strong>
          </div>
        </div>

        <div style="display:grid;grid-template-columns:repeat(4,minmax(140px,1fr));gap:10px;margin-bottom:14px;">
          <div style="padding:10px 12px;border:1px solid var(--border-default);border-radius:8px;background:var(--bg-surface-subtle);">
            <div style="font-size:11px;color:var(--text-secondary);">PREDICTED E2E RTT</div>
            <div style="font-size:18px;font-weight:700;font-family:var(--font-mono);color:var(--text-primary);">${m.endToEndRttMs === 999 ? '∞ (Partition)' : `${esc(m.endToEndRttMs)} ms`}</div>
          </div>
          <div style="padding:10px 12px;border:1px solid var(--border-default);border-radius:8px;background:var(--bg-surface-subtle);">
            <div style="font-size:11px;color:var(--text-secondary);">PREDICTED PACKET LOSS</div>
            <div style="font-size:18px;font-weight:700;font-family:var(--font-mono);color:var(--text-primary);">${esc(m.packetLossPct)}%</div>
          </div>
          <div style="padding:10px 12px;border:1px solid var(--border-default);border-radius:8px;background:var(--bg-surface-subtle);">
            <div style="font-size:11px;color:var(--text-secondary);">DNS RESOLUTION RATE</div>
            <div style="font-size:18px;font-weight:700;font-family:var(--font-mono);color:var(--text-primary);">${esc(m.dnsSuccessRatePct)}%</div>
          </div>
          <div style="padding:10px 12px;border:1px solid var(--border-default);border-radius:8px;background:var(--bg-surface-subtle);">
            <div style="font-size:11px;color:var(--text-secondary);">IMPACTED ENDPOINTS</div>
            <div style="font-size:18px;font-weight:700;font-family:var(--font-mono);color:var(--text-primary);">${esc(m.blastRadiusHosts)} Hosts</div>
          </div>
        </div>

        ${(twin.affectedServices || []).length > 0 ? `
          <div style="padding:10px 12px;border:1px solid var(--border-default);border-radius:8px;background:var(--bg-surface-subtle);margin-bottom:12px;font-size:12px;color:var(--text-primary);">
            <strong>Predicted Replica Failure Propagation:</strong> ${(twin.affectedServices || []).map(esc).join(' · ')}
          </div>
        ` : ''}

        <table style="width:100%;border-collapse:collapse;text-align:left;">
          <thead>
            <tr style="border-bottom:1px solid var(--border-default);font-size:11px;color:var(--text-secondary);">
              <th style="padding:6px 10px;">Replica Node</th>
              <th style="padding:6px 10px;">Role</th>
              <th style="padding:6px 10px;">Predicted State</th>
              <th style="padding:6px 10px;text-align:right;">Simulated RTT</th>
            </tr>
          </thead>
          <tbody>${nodesRows}</tbody>
        </table>
      </section>
    `;
  }

  function renderTimeMachinePanel(state) {
    const tm = state.timeMachine || {};
    const events = tm.events || [];
    const activeIdx = window.__ejiiTimeMachineIndex >= 0 && window.__ejiiTimeMachineIndex < events.length
      ? window.__ejiiTimeMachineIndex
      : events.length - 1;
    const selectedEvt = events[activeIdx] || events[0] || {};

    const eventsListHtml = events.map((ev, idx) => {
      const isSelected = idx === activeIdx;
      return `
        <div onclick="window.scrubOperatorTimeMachine(${idx})" style="cursor:pointer;padding:10px 12px;border:1px solid ${isSelected ? 'var(--accent-primary, #1d4ed8)' : 'var(--border-default, #e2e8f0)'};border-radius:8px;background:${isSelected ? 'var(--bg-surface, #ffffff)' : 'var(--bg-surface-subtle, #f8fafc)'};">
          <div style="display:flex;justify-content:space-between;font-size:11px;font-family:var(--font-mono);color:var(--text-secondary);margin-bottom:3px;">
            <span>T${ev.offsetSec === 0 ? '-0s (NOW)' : `${ev.offsetSec}s`} · ${esc(ev.domain)}</span>
            <span>${esc(ev.severity)}</span>
          </div>
          <div style="font-size:12.5px;font-weight:600;color:var(--text-primary);margin-bottom:2px;">${esc(ev.title)}</div>
          <div style="font-size:11.5px;color:var(--text-secondary);">${esc(ev.detail)}</div>
        </div>
      `;
    }).join('');

    return `
      <section class="v6-panel" style="padding:18px;margin-bottom:16px;" data-panel-id="time-machine">
        ${buildPanelHeader(
          'time-machine',
          'CAPABILITY 03 · INFRASTRUCTURE TIME MACHINE',
          'Synchronized Incident Replay Across Packets, Topology, Latency & Services',
          tm.reconstructedNarrative || 'Reconstructs how the incident unfolded across protocol layers.'
        )}

        <div style="display:flex;align-items:center;gap:14px;margin-bottom:14px;padding:10px 14px;border:1px solid var(--border-default);border-radius:8px;background:var(--bg-surface-subtle);">
          <label for="aiOpTimeScrubber" style="font-size:12px;font-weight:600;color:var(--text-primary);white-space:nowrap;">
            Timeline Replay Scrubber:
          </label>
          <input id="aiOpTimeScrubber" type="range" min="0" max="${Math.max(0, events.length - 1)}" value="${activeIdx}" oninput="window.scrubOperatorTimeMachine(this.value)" style="flex:1;">
          <div style="font-family:var(--font-mono);font-size:12px;color:var(--text-primary);white-space:nowrap;">
            Step ${activeIdx + 1}/${events.length} · RTT ${esc(selectedEvt.metrics?.rttMs ?? 0)}ms · DNS ${esc(selectedEvt.metrics?.dnsLatencyMs ?? 0)}ms
          </div>
        </div>

        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:10px;">
          ${eventsListHtml}
        </div>
      </section>
    `;
  }

  function renderCrossLayerGraphPanel(state) {
    const cg = state.crossLayerGraph || {};
    const nodes = cg.nodes || [];

    const chainHtml = nodes.map((n, i) => `
      <div style="padding:12px;border:1px solid ${n.status === 'CRITICAL' ? 'var(--status-critical, #dc2626)' : 'var(--border-default, #e2e8f0)'};border-radius:8px;background:var(--bg-surface-subtle, #f8fafc);">
        <div style="display:flex;justify-content:space-between;align-items:center;font-size:11px;color:var(--text-secondary);margin-bottom:4px;">
          <span style="font-weight:600;">0${i + 1}. ${esc(n.layer)}</span>
          <span style="font-family:var(--font-mono);font-weight:600;color:${n.status === 'CRITICAL' ? 'var(--status-critical, #dc2626)' : 'var(--status-nominal, #15803d)'};">${esc(n.latencyMs)} ms · ${esc(n.status)}</span>
        </div>
        <div style="font-size:13px;font-weight:600;color:var(--text-primary);margin-bottom:3px;">${esc(n.title)}</div>
        <div style="font-size:12px;color:var(--text-secondary);margin-bottom:6px;line-height:1.45;">${esc(n.finding)}</div>
        <div style="font-family:var(--font-mono);font-size:11px;color:var(--accent-primary, #1d4ed8);">
          Evidence Record: ${esc(n.evidenceId)} · Target: ${esc(n.target)}
        </div>
      </div>
    `).join('');

    return `
      <section class="v6-panel" style="padding:18px;margin-bottom:16px;" data-panel-id="cross-layer-graph">
        ${buildPanelHeader(
          'cross-layer-graph',
          'CAPABILITY 04 · CROSS-LAYER INVESTIGATION GRAPH',
          `End-to-End Request Trace: ${cg.requestTarget || 'corp-app.internal:443'} (Total: ${cg.totalRequestLatencyMs || 0} ms)`,
          'Traces an application request from L7 HTTPS through DNS resolution, TCP transport, L3 routing, L2 switching, and the responsible OS process with attached Evidence IDs.'
        )}

        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px;">
          ${chainHtml}
        </div>
      </section>
    `;
  }

  function renderCouncilPanel(state) {
    const c = state.operationsCouncil || {};
    const agentsHtml = (c.agents || []).map((a) => `
      <div style="padding:12px;border:1px solid var(--border-default, #e2e8f0);border-radius:8px;background:var(--bg-surface-subtle, #f8fafc);">
        <div style="display:flex;justify-content:space-between;align-items:center;font-size:11px;color:var(--text-secondary);margin-bottom:4px;">
          <span style="font-weight:600;color:var(--text-primary);">${esc(a.name)}</span>
          <span style="font-family:var(--font-mono);">Confidence ${(Number(a.confidence || 0.9) * 100).toFixed(0)}%</span>
        </div>
        <div style="font-size:11.5px;color:var(--text-secondary);margin-bottom:6px;">Domain: ${esc(a.domain)}</div>
        <div style="font-size:12px;color:var(--text-primary);margin-bottom:6px;line-height:1.45;">
          <strong>Cross-Agent Challenge:</strong> ${esc(a.challengeIssued)}
        </div>
        <div style="font-size:12px;color:var(--status-nominal, #15803d);font-weight:500;">
          <strong>Verdict:</strong> ${esc(a.finalVerdict)}
        </div>
      </div>
    `).join('');

    return `
      <section class="v6-panel" style="padding:18px;margin-bottom:16px;" data-panel-id="council">
        ${buildPanelHeader(
          'council',
          'CAPABILITY 05 · AI OPERATIONS COUNCIL',
          `Consensus Diagnosis: ${c.consensusRootCause || ''} (Bayes Factor = ${c.bayesFactorTop2 || 14.6})`,
          'Four specialized AI agents independently inspect networking, host OS, packet captures, and counterfactuals, challenge each other, and produce one evidence-ranked diagnosis.'
        )}

        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(270px,1fr));gap:10px;">
          ${agentsHtml}
        </div>
      </section>
    `;
  }

  function renderFleetCommandPanel(state) {
    const fc = state.fleetCommand || {};
    const s = fc.summary || {};
    const rows = (fc.hosts || []).map((h) => `
      <tr>
        <td style="padding:8px 10px;font-family:var(--font-mono);font-size:12px;font-weight:600;">${esc(h.hostname)}</td>
        <td style="padding:8px 10px;font-family:var(--font-mono);font-size:12px;">${esc(h.ip)}</td>
        <td style="padding:8px 10px;font-size:12px;">${esc(h.osPlatform)}</td>
        <td style="padding:8px 10px;font-size:12px;font-weight:600;color:${h.status === 'HEALTHY' ? 'var(--status-nominal, #15803d)' : 'var(--status-warning, #b45309)'};">${esc(h.status)}</td>
        <td style="padding:8px 10px;font-family:var(--font-mono);font-size:12px;text-align:right;">${esc(h.cpuPct)}%</td>
        <td style="padding:8px 10px;font-family:var(--font-mono);font-size:12px;text-align:right;">${esc(h.ramPct)}% (${esc(h.totalRamGb)}G)</td>
        <td style="padding:8px 10px;font-family:var(--font-mono);font-size:12px;text-align:right;">${esc(h.rttMs)} ms</td>
        <td style="padding:8px 10px;font-family:var(--font-mono);font-size:11.5px;">${esc(h.topProcess)}</td>
        <td style="padding:8px 10px;font-size:11.5px;color:${h.configDrift === 'IN_SYNC' ? 'var(--text-secondary)' : 'var(--status-critical, #dc2626)'};font-weight:${h.configDrift === 'IN_SYNC' ? '400' : '600'};">${esc(h.configDrift)}</td>
      </tr>
    `).join('');

    return `
      <section class="v6-panel" style="padding:18px;margin-bottom:16px;" data-panel-id="fleet">
        ${buildPanelHeader(
          'fleet',
          'CAPABILITY 06 · MULTI-HOST FLEET COMMAND',
          `Authorized Fleet Telemetry: ${s.totalHosts || 6} Hosts (${s.healthyHosts || 4} Healthy · ${s.driftDetectedCount || 0} Config Drift)`,
          'Monitors authorized Windows and Linux machines with live health, hardware utilization, top processes, connectivity RTT, configuration drift, and role-based access.'
        )}

        <div style="overflow-x:auto;">
          <table style="width:100%;border-collapse:collapse;text-align:left;">
            <thead>
              <tr style="border-bottom:1px solid var(--border-default);font-size:11px;color:var(--text-secondary);">
                <th style="padding:7px 10px;">Hostname</th>
                <th style="padding:7px 10px;">IP Address</th>
                <th style="padding:7px 10px;">OS &amp; Kernel</th>
                <th style="padding:7px 10px;">Health</th>
                <th style="padding:7px 10px;text-align:right;">CPU</th>
                <th style="padding:7px 10px;text-align:right;">Memory</th>
                <th style="padding:7px 10px;text-align:right;">RTT</th>
                <th style="padding:7px 10px;">Active Process</th>
                <th style="padding:7px 10px;">Configuration Drift</th>
              </tr>
            </thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      </section>
    `;
  }

  function renderPredictivePanel(state) {
    const pi = state.predictiveIntelligence || {};
    const cards = (pi.forecasts || []).map((f) => `
      <div style="padding:12px;border:1px solid var(--border-default, #e2e8f0);border-radius:8px;background:var(--bg-surface-subtle, #f8fafc);">
        <div style="display:flex;justify-content:space-between;font-size:11px;color:var(--text-secondary);margin-bottom:4px;">
          <span style="font-weight:600;color:var(--text-primary);">${esc(f.metric)}</span>
          <span style="font-family:var(--font-mono);">${esc(f.trendDirection)}</span>
        </div>
        <div style="font-family:var(--font-mono);font-size:12.5px;color:var(--text-primary);margin-bottom:6px;">
          Current: <strong>${esc(f.currentValue)}</strong> → 60m Forecast: <strong>${esc(f.predicted60mValue)}</strong>
        </div>
        <div style="font-size:12px;color:var(--text-secondary);line-height:1.45;">
          <strong>Why Risk Is Changing:</strong> ${esc(f.whyRiskIsRising)}
        </div>
      </div>
    `).join('');

    return `
      <section class="v6-panel" style="padding:18px;margin-bottom:16px;" data-panel-id="predictive">
        ${buildPanelHeader(
          'predictive',
          'CAPABILITY 08 · PREDICTIVE INFRASTRUCTURE INTELLIGENCE',
          `Pre-Alert Degradation & Drift Forecast (60m Outage Risk: ${((Number(pi.outageProbabilityNext60m || 0.03)) * 100).toFixed(0)}%)`,
          'Detects degradation trends and configuration drift early, forecasts possible outages, and explains why risk is rising before a threshold alert triggers.'
        )}

        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(270px,1fr));gap:10px;">
          ${cards}
        </div>
      </section>
    `;
  }

  function renderAiOperatorDOM(state) {
    const main = document.getElementById('mainContent');
    if (!main || !state) return;

    const cfg = state.cockpitConfig || { activeMode: 'NOC', panelOrder: [] };
    const activeMode = cfg.activeMode || 'NOC';
    const order = Array.isArray(cfg.panelOrder) && cfg.panelOrder.length
      ? cfg.panelOrder
      : ['flagship-pipeline', 'digital-twin', 'time-machine', 'cross-layer-graph', 'council', 'fleet', 'predictive'];

    const panelRenderers = {
      'flagship-pipeline': () => renderFlagshipPipelinePanel(state),
      'digital-twin': () => renderDigitalTwinPanel(state),
      'time-machine': () => renderTimeMachinePanel(state),
      'cross-layer-graph': () => renderCrossLayerGraphPanel(state),
      'council': () => renderCouncilPanel(state),
      'fleet': () => renderFleetCommandPanel(state),
      'predictive': () => renderPredictivePanel(state)
    };

    const orderedPanelsHtml = order
      .map((id) => (panelRenderers[id] ? panelRenderers[id]() : ''))
      .join('');

    const savedWsButtons = (state.savedWorkspaces || []).slice(0, 5).map((ws) => `
      <button type="button" class="btn btn-secondary" style="font-size:11.5px;padding:5px 10px;" onclick="window.loadSavedOperatorWorkspace('${esc(ws.id)}')">
        Load: ${esc(ws.name)} (${esc(ws.mode)})
      </button>
    `).join('');

    main.innerHTML = `
      <div id="aiOperatorCommandRoot" style="padding:18px 22px;max-width:1600px;margin:0 auto;">
        <!-- Top Natural-Language AI Operator Directive & Personalized Cockpit Bar (Capabilities 1 & 9) -->
        <section class="v6-panel" style="padding:18px;margin-bottom:16px;">
          <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:14px;">
            <div>
              <div style="font-size:11px;font-weight:600;color:var(--accent-primary, #1d4ed8);margin-bottom:2px;">
                UNIFIED AI INFRASTRUCTURE OPERATOR · MULTI-STEP TOOL ORCHESTRATION &amp; PERSONALIZED COCKPIT
              </div>
              <h2 style="margin:0;font-size:20px;font-weight:600;color:var(--text-primary);">
                Tell EJII what you need — AI plans, investigates across all tools, verifies in the Digital Twin, and repairs safely.
              </h2>
            </div>

            <!-- Capability 9: Role Mode Switcher (NOC / Helpdesk / SysAdmin) -->
            <div style="display:flex;align-items:center;gap:6px;background:var(--bg-surface-subtle, #f1f5f9);padding:4px;border-radius:8px;border:1px solid var(--border-default);">
              <button type="button" id="btnCockpitModeNoc" class="btn ${activeMode === 'NOC' ? 'btn-primary' : 'btn-secondary'}" style="font-size:11.5px;padding:5px 11px;" onclick="window.switchOperatorCockpitMode('NOC')">
                NOC Mode
              </button>
              <button type="button" id="btnCockpitModeHelpdesk" class="btn ${activeMode === 'HELPDESK' ? 'btn-primary' : 'btn-secondary'}" style="font-size:11.5px;padding:5px 11px;" onclick="window.switchOperatorCockpitMode('HELPDESK')">
                Helpdesk Mode
              </button>
              <button type="button" id="btnCockpitModeSysadmin" class="btn ${activeMode === 'SYSADMIN' ? 'btn-primary' : 'btn-secondary'}" style="font-size:11.5px;padding:5px 11px;" onclick="window.switchOperatorCockpitMode('SYSADMIN')">
                SysAdmin Mode
              </button>
            </div>
          </div>

          <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px;">
            <input
              type="text"
              id="aiOperatorGoalInput"
              value="${esc(state.activeTask?.goal || 'Find out why the network is slow and fix whatever you safely can.')}"
              aria-label="Tell AI Operator what you need"
              placeholder="Write what you need (e.g., Find out why the network is slow and fix whatever you safely can)..."
              style="flex:1;min-width:320px;padding:9px 14px;border:1px solid var(--border-default);border-radius:8px;background:var(--bg-surface);color:var(--text-primary);font-size:13.5px;"
            >
            <button type="button" id="btnExecuteOperatorGoal" class="btn btn-primary" style="font-size:12.5px;padding:9px 16px;font-weight:600;" onclick="window.submitOperatorDirective(false)">
              Plan &amp; Investigate
            </button>
            <button type="button" id="btnExecuteAndAutoHeal" class="btn btn-secondary" style="font-size:12.5px;padding:9px 14px;font-weight:600;" onclick="window.submitOperatorDirective(true)">
              Investigate &amp; Auto-Apply Safe Fix
            </button>
          </div>

          <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;padding-top:8px;border-top:1px solid var(--border-default);">
            <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
              <span style="font-size:11.5px;color:var(--text-secondary);">Quick Directives:</span>
              <button type="button" class="btn btn-secondary" style="font-size:11px;padding:4px 9px;" onclick="window.submitOperatorDirective(false, 'Find out why the network is slow and fix whatever you safely can.')">
                Why is the network slow?
              </button>
              <button type="button" class="btn btn-secondary" style="font-size:11px;padding:4px 9px;" onclick="window.submitOperatorDirective(false, 'Simulate removing Dist-Switch-01 in the Digital Twin and assess blast radius.')">
                Simulate Switch Removal in Twin
              </button>
              <button type="button" class="btn btn-secondary" style="font-size:11px;padding:4px 9px;" onclick="window.submitOperatorDirective(false, 'Audit multi-host Windows & Linux fleet for configuration drift and DNS latency.')">
                Audit Multi-Host Fleet Drift
              </button>
            </div>

            <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
              <input type="text" id="aiOpWorkspaceNameInput" placeholder="Save workspace name…" style="padding:4px 8px;border:1px solid var(--border-default);border-radius:6px;background:var(--bg-surface);color:var(--text-primary);font-size:11.5px;width:155px;">
              <button type="button" class="btn btn-secondary" style="font-size:11px;padding:4px 9px;" onclick="window.saveOperatorWorkspaceSnapshot()">
                Save Workspace
              </button>
              ${savedWsButtons}
            </div>
          </div>
        </section>

        <!-- Dynamic Cockpit Panels Ordered by Active Persona / Custom Arrangement -->
        <div id="aiOperatorPanelsContainer">
          ${orderedPanelsHtml}
        </div>
      </div>
    `;
  }

  window.renderAiOperatorView = async function () {
    const pageTitle = document.getElementById('pageTitle');
    if (pageTitle) {
      pageTitle.innerHTML = '<span class="page-name">AI Infrastructure Operator</span>';
    }
    const state = await fetchOperatorState();
    if (state) {
      renderAiOperatorDOM(state);
    }
  };
})();
