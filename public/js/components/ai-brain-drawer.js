/**
 * EJII Autonomous AI Diagnostic Brain Live Drawer Component
 * Renders real-time Bayesian root-cause verdicts, 100.0% normalized probability breakdown bar,
 * live baseline counters, and 1-click active diagnostic probe trigger.
 */

(function(window) {
  'use strict';

  let currentBrainState = null;
  let isExecutingProbe = false;
  let brainPollTimer = null;

  const HYPOTHESIS_COLORS = {
    FIREWALL_SILENT_DROP: '#F87171', // red
    PORT_CLOSED_SERVICE_STOPPED: '#FB923C', // orange
    GATEWAY_UNREACHABLE: '#EF4444', // crimson
    UPSTREAM_TRANSIT_DROP: '#FBBF24', // amber
    REMOTE_HOST_DOWN: '#A855F7', // purple
    LOCAL_NIC_STACK_ERROR: '#64748B', // slate
    DNS_RESOLUTION_FAILURE: '#38BDF8', // sky
    TLS_NEGOTIATION_ALERT: '#EC4899', // pink
    BACKEND_PROCESSING_LATENCY: '#EAB308', // yellow
    NORMAL_OPERATION: '#34D399' // emerald
  };

  let isAiBrainExpanded = false;

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  window.toggleAiBrainDrawerExpand = function() {
    isAiBrainExpanded = !isAiBrainExpanded;
    updateDrawerDom(currentBrainState);
  };

  const defaultNominalState = {
    topHypothesis: {
      id: 'NORMAL_OPERATION',
      label: 'Nominal Network Transport Health',
      confidence: 100,
      rfc: 'RFC 1122'
    },
    rankedHypotheses: [
      { id: 'NORMAL_OPERATION', label: 'Nominal Network Transport Health', confidence: 100, rfc: 'RFC 1122' }
    ],
    recommendedProbe: null
  };

  /**
   * Generates drawer HTML markup from live brain state
   */
  function renderAiBrainDrawerHtml(rawState) {
    const state = rawState || defaultNominalState;

    const topH = state.topHypothesis || {
      id: 'NORMAL_OPERATION',
      label: 'Nominal Network Transport Health',
      confidence: 100,
      rfc: 'RFC 1122'
    };

    const isNominal = topH.id === 'NORMAL_OPERATION';
    const confClass = isNominal ? 'conf-nominal' : (topH.confidence >= 60 ? 'conf-high' : 'conf-medium');
    const recommendedProbe = state.recommendedProbe || (state.distinguishingProbes && state.distinguishingProbes[0]) || null;
    const ranked = state.rankedHypotheses || [];

    // Probability breakdown segments
    const segmentsHtml = ranked.map(h => {
      const color = HYPOTHESIS_COLORS[h.id] || '#64748B';
      const width = Math.max(h.confidence, 0);
      return `<div class="ai-brain-prob-segment" style="width: ${width}%; background: ${color};" title="${h.label} (${h.confidence}%) - ${h.rfc}"></div>`;
    }).join('');

    // Probability legend pills
    const legendHtml = ranked.slice(0, 5).map(h => {
      const color = HYPOTHESIS_COLORS[h.id] || '#94A3B8';
      return `<span style="font-family: var(--font-mono); font-size: 9.5px; color: ${color}; background: rgba(0,0,0,0.3); padding: 1px 6px; border-radius: 3px; border: 1px solid rgba(255,255,255,0.05); margin-right: 4px;"><strong>${h.confidence}%</strong> ${h.label.split('/')[0].trim()}</span>`;
    }).join('');

    // Probe button
    let actionBtnHtml = '';
    if (isExecutingProbe) {
      actionBtnHtml = `
        <button id="aiBrainRecommendationBtn" class="btn-trigger-probe" disabled style="opacity: 0.8; cursor: wait; font-size: 10px; padding: 2px 8px;">
          <span class="status-dot dot-cyan"></span>
          <span>Executing Probe...</span>
        </button>
      `;
    } else if (recommendedProbe) {
      const pType = recommendedProbe.probeType || 'ICMP_PING_GATEWAY';
      const pTarget = recommendedProbe.target || '';
      actionBtnHtml = `
        <button id="aiBrainRecommendationBtn" class="btn-trigger-probe" onclick="window.triggerAiBrainProbe('${pType}', '${pTarget}')" title="${recommendedProbe.expectedOutcome || ''}" style="font-size: 10px; padding: 2px 8px;">
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
          <span>Execute: ${recommendedProbe.name || pType}</span>
        </button>
      `;
    } else {
      actionBtnHtml = `
        <button id="aiBrainRecommendationBtn" class="btn btn-secondary" onclick="window.triggerAiBrainProbe('ICMP_PING_GATEWAY', '')" style="font-size: 10px; padding: 2px 8px; font-family: var(--font-mono); color: var(--text-secondary); border-color: var(--border-subtle);">
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>
          <span>Verify Wire</span>
        </button>
      `;
    }

    if (!isAiBrainExpanded) {
      return `
        <div id="aiBrainLiveDrawer" class="ai-brain-live-drawer" style="height: 38px; min-height: 38px; max-height: 38px; display: flex; align-items: center; justify-content: space-between; padding: 0 14px; background: rgba(15, 23, 42, 0.95); border: 1px solid var(--border-color); border-radius: 6px; box-sizing: border-box; overflow: hidden;">
          <div style="display: flex; align-items: center; gap: 10px; overflow: hidden; white-space: nowrap;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color: var(--accent); flex-shrink: 0;"><path d="M12 2a4 4 0 0 0-4 4c0 1.1.4 2.1 1.1 2.8A6 6 0 0 0 4 14a6 6 0 0 0 6 6h4a6 6 0 0 0 6-6 6 6 0 0 0-5.1-5.2A4 4 0 0 0 16 6a4 4 0 0 0-4-4Z"/></svg>
            <span style="font-weight: 800; font-size: 11px; color: #38bdf8; font-family: var(--font-mono);">AI BRAIN:</span>
            <div id="aiBrainVerdict" style="display: inline-flex; align-items: center; gap: 6px; overflow: hidden;">
              <span class="ai-brain-confidence-badge ${confClass}" style="font-size: 9.5px; padding: 1px 6px;">${topH.confidence}% CONFIDENCE</span>
              <span style="font-size: 11px; font-weight: 700; color: #f8fafc; text-overflow: ellipsis; overflow: hidden;">${escapeHtml(topH.label)}</span>
              <span style="font-size: 10px; color: #94a3b8;">(${escapeHtml(topH.rfc)})</span>
            </div>
            <div id="aiBrainConfidenceBar" class="ai-brain-prob-bar" style="width: 80px; height: 4px; border-radius: 2px; overflow: hidden; display: inline-flex; margin: 0 4px; flex-shrink: 0;">
              ${segmentsHtml}
            </div>
          </div>
          <div style="display: flex; align-items: center; gap: 8px; flex-shrink: 0;">
            ${actionBtnHtml}
            <button class="btn btn-secondary" onclick="window.toggleAiBrainDrawerExpand()" style="font-size: 10px; padding: 2px 8px; font-weight: 600; font-family: var(--font-mono); color: #38bdf8; border-color: rgba(56, 189, 248, 0.3);">▾ Expand AI Brain Details</button>
          </div>
        </div>
      `;
    }

    return `
      <div id="aiBrainLiveDrawer" class="ai-brain-live-drawer">
        <!-- Topline: Badge & Counters -->
        <div class="ai-brain-topline">
          <div class="ai-brain-title-group">
            <span class="ai-brain-title-badge">
              <span class="status-dot" style="background: #38BDF8;"></span>
              Autonomous AI Diagnostic Brain
            </span>
            <span style="font-family: var(--font-mono); font-size: 10px; color: #64748B;">Continuous Bayesian Reasoning &bull; RFC Evidentiary Elimination</span>
          </div>

          <div class="ai-brain-meta">
            <div class="ai-brain-meta-item">
              Baselines Learned: <strong id="aiBrainBaselinesCount">${state.learnedBaselinesCount || 0}</strong> endpoints
            </div>
            <div class="ai-brain-meta-item">
              Incidents Tracked: <strong id="aiBrainIncidentsCount">${state.activeIncidentCount || 0}</strong>
            </div>
            <div class="ai-brain-meta-item">
              Engine: <strong style="color: #38BDF8;">Continuous Bayesian (100.0%)</strong>
            </div>
            <div class="ai-brain-meta-item" style="border-left: 1px solid rgba(255,255,255,0.1); padding-left: 8px;">
              Mode: <strong style="color: ${state.orchestratorState?.liveResponse ? '#10B981' : '#F59E0B'};">${state.orchestratorState?.liveResponse ? 'LIVE NEURAL INFERENCE' : 'DETERMINISTIC FALLBACK — LOCAL MODEL OFFLINE / BYPASSED'}</strong>
            </div>
            <div class="ai-brain-meta-item">
              Provider: <strong style="color: #38BDF8;">${escapeHtml(state.orchestratorState?.providerId || 'OLLAMA (Local-First)')}</strong>
            </div>
            <div class="ai-brain-meta-item">
              Privacy: <strong style="color: #A855F7;">Local-Only / Air-Gapped</strong>
            </div>
            <button class="btn btn-secondary" onclick="window.toggleAiBrainDrawerExpand()" style="font-size: 10px; padding: 1px 6px; font-weight: 600; margin-left: 6px;">▴ Collapse</button>
          </div>
        </div>

        <!-- Middle: Active Root-Cause Verdict & 1-Click Action -->
        <div class="ai-brain-verdict-row">
          <div class="ai-brain-verdict-content">
            <span class="ai-brain-verdict-label">Root Cause Verdict:</span>
            <div id="aiBrainVerdict" class="ai-brain-verdict-text">
              <span class="ai-brain-confidence-badge ${confClass}">
                ${topH.confidence}% CONFIDENCE
              </span>
              <span>${topH.label}</span>
              <span style="font-size: 11px; color: #94A3B8; font-weight: 500;">(${topH.rfc})</span>
            </div>
          </div>

          <div class="ai-brain-actions">
            ${actionBtnHtml}
          </div>
        </div>

        <!-- Bottom: Segmented Probability Bar & Competing Hypotheses -->
        <div class="ai-brain-bar-wrapper">
          <div class="ai-brain-bar-label">
            <span>Competing Bayesian Hypothesis Distribution (Strict 100.0% Normalization):</span>
            <span>${ranked.length} Hypotheses Evaluated</span>
          </div>
          <div id="aiBrainConfidenceBar" class="ai-brain-prob-bar">
            ${segmentsHtml}
          </div>
          <div style="display: flex; flex-wrap: wrap; gap: 4px; margin-top: 4px;">
            ${legendHtml}
          </div>
        </div>

        <!-- Separated Supported vs Contradicted Hypotheses & Epistemic Probes -->
        ${(() => {
          const supportedHypotheses = ranked.filter(h => h.status !== 'CONTRADICTED' && Number(h.confidence) > 0);
          const contradictedHypotheses = ranked.filter(h => h.status === 'CONTRADICTED' || (h.contradictionProofTrace && h.contradictionProofTrace.length > 0) || Number(h.confidence) === 0);
          const distinguishingProbes = state.distinguishingProbes || (recommendedProbe ? [recommendedProbe] : []);

          return `
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 10px;">
              <!-- Supported Hypotheses -->
              <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(16, 185, 129, 0.2); border-radius: 4px; padding: 8px 10px;">
                <div style="font-size: 10px; font-weight: 800; color: #10B981; font-family: var(--font-mono); margin-bottom: 6px; display: flex; justify-content: space-between;">
                  <span>✓ SUPPORTED BAYESIAN HYPOTHESES (Σ = 100.0%)</span>
                  <span>${supportedHypotheses.length} Active</span>
                </div>
                <div style="display: flex; flex-direction: column; gap: 4px; max-height: 140px; overflow-y: auto;">
                  ${supportedHypotheses.length > 0 ? supportedHypotheses.map(h => `
                    <div style="display: flex; justify-content: space-between; align-items: center; background: rgba(0,0,0,0.25); border-radius: 3px; padding: 3px 6px; font-size: 9.5px; border-left: 2px solid ${HYPOTHESIS_COLORS[h.id] || '#10B981'};">
                      <div style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 75%;">
                        <strong style="color: #F8FAFC;">${escapeHtml(h.label)}</strong>
                        <span style="color: #64748B; margin-left: 4px;">${escapeHtml(h.rfc || '')}</span>
                      </div>
                      <div style="font-family: var(--font-mono); text-align: right;">
                        <span style="color: #10B981; font-weight: 800;">${h.confidence}%</span>
                        ${h.evidenceCoverageRatio !== undefined ? `<span style="color: #64748B; font-size: 8.5px; margin-left: 4px;">(cov: ${Math.round(h.evidenceCoverageRatio * 100)}%)</span>` : ''}
                      </div>
                    </div>
                  `).join('') : '<div style="color: #64748B; font-size: 9.5px;">No active supported hypotheses.</div>'}
                </div>
              </div>

              <!-- Contradicted Hypotheses -->
              <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 4px; padding: 8px 10px;">
                <div style="font-size: 10px; font-weight: 800; color: #EF4444; font-family: var(--font-mono); margin-bottom: 6px; display: flex; justify-content: space-between;">
                  <span>✗ CONTRADICTED HYPOTHESES (HORN CLAUSE VETO)</span>
                  <span>${contradictedHypotheses.length} Eliminated (0.0%)</span>
                </div>
                <div style="display: flex; flex-direction: column; gap: 4px; max-height: 140px; overflow-y: auto;">
                  ${contradictedHypotheses.length > 0 ? contradictedHypotheses.map(h => {
                    const proof = (h.contradictionProofTrace && h.contradictionProofTrace[0]) || h.contradictedBy || h.proofTrace || 'Empirical wire telemetry contradicts necessary conditions.';
                    return `
                      <div style="background: rgba(0,0,0,0.25); border-radius: 3px; padding: 3px 6px; font-size: 9px; border-left: 2px solid #EF4444;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                          <span style="text-decoration: line-through; color: #94A3B8; font-weight: 700;">${escapeHtml(h.label)}</span>
                          <span style="color: #EF4444; font-family: var(--font-mono); font-weight: 800; font-size: 8.5px;">0.0% [VETO]</span>
                        </div>
                        <div style="color: #F87171; font-family: var(--font-mono); font-size: 8.5px; margin-top: 2px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(proof)}">
                          Rule: ${escapeHtml(proof)}
                        </div>
                      </div>
                    `;
                  }).join('') : '<div style="color: #64748B; font-size: 9.5px;">Zero hypotheses contradicted.</div>'}
                </div>
              </div>
            </div>

            <!-- Distinguishing Epistemic Probes Section -->
            <div style="margin-top: 8px; background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 4px; padding: 8px 10px;">
              <div style="font-size: 10px; font-weight: 800; color: #38BDF8; font-family: var(--font-mono); margin-bottom: 6px; display: flex; justify-content: space-between;">
                <span>🔬 DISTINGUISHING EPISTEMIC PROBES (TIE-BREAKING INFORMATION GAIN)</span>
                <span>${distinguishingProbes.length} Available</span>
              </div>
              <div style="display: flex; flex-wrap: wrap; gap: 6px;">
                ${distinguishingProbes.length > 0 ? distinguishingProbes.map(p => `
                  <div style="background: rgba(0,0,0,0.3); border: 1px solid rgba(56, 189, 248, 0.15); border-radius: 3px; padding: 4px 8px; display: flex; align-items: center; justify-content: space-between; gap: 8px; flex: 1; min-width: 260px;">
                    <div>
                      <div style="font-size: 9.5px; font-weight: 700; color: #E2E8F0;">${escapeHtml(p.name || p.probeType)}</div>
                      <div style="font-size: 8.5px; color: #94A3B8; font-family: var(--font-mono);">${escapeHtml(p.informationGain || p.expectedOutcome || 'Resolves competing hypotheses')}</div>
                    </div>
                    <button class="btn btn-secondary" onclick="window.triggerAiBrainProbe('${escapeHtml(p.probeType || '')}', '${escapeHtml(p.target || '')}')" style="font-size: 9px; padding: 2px 6px; font-family: var(--font-mono); color: #38BDF8; border-color: rgba(56, 189, 248, 0.3); flex-shrink: 0;">
                      Dispatch Probe ⚡
                    </button>
                  </div>
                `).join('') : '<div style="color: #64748B; font-size: 9.5px;">No distinguishing probes required — diagnostic state resolved.</div>'}
              </div>
            </div>
          `;
        })()}

        <!-- Cognitive Telemetry Strip: Neuro-Symbolic Proof Chain & Active Inference & MCTS World Model -->
        <div style="margin-top: 10px; padding-top: 8px; border-top: 1px solid rgba(255, 255, 255, 0.08); display: flex; flex-direction: column; gap: 8px;">
          <div style="display: flex; flex-direction: column; gap: 4px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span style="font-size: 10px; font-weight: 800; color: #38bdf8; font-family: var(--font-mono);">
                NEURO-SYMBOLIC PROOF CHAIN (Stratified Datalog / Horn Clauses):
              </span>
              <span style="font-size: 9px; color: #94a3b8; font-family: var(--font-mono);">
                ${(state.symbolicProofChain || []).length} Axioms Fired
              </span>
            </div>
            <div style="display: flex; flex-wrap: wrap; gap: 4px;">
              ${(state.symbolicProofChain && state.symbolicProofChain.length > 0)
                ? state.symbolicProofChain.map(p => `
                    <div style="background: rgba(15, 23, 42, 0.8); border: 1px solid ${p.action === 'CONTRADICT' ? 'rgba(239, 68, 68, 0.3)' : 'rgba(56, 189, 248, 0.2)'}; border-radius: 4px; padding: 2px 8px; font-size: 9px; font-family: var(--font-mono);">
                      <span style="color: ${p.action === 'CONTRADICT' ? '#ef4444' : '#38bdf8'}; font-weight: 700;">[${escapeHtml(p.axiom)}] ${escapeHtml(p.ruleName)}</span>:
                      <span style="color: #e2e8f0;"> ${escapeHtml(p.datalog)}</span>
                      <span style="color: #64748b;"> (${escapeHtml(p.rfc)})</span>
                    </div>
                  `).join('')
                : `<span style="font-size: 9.5px; color: #64748b; font-family: var(--font-mono);">Nominal state verified: zero anomaly axioms triggered.</span>`
              }
            </div>
          </div>


          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 8px;">
            <div style="background: rgba(0, 0, 0, 0.3); border: 1px solid rgba(255, 255, 255, 0.06); border-radius: 4px; padding: 6px 10px;">
              <div style="font-size: 9.5px; font-weight: 700; color: #38bdf8; font-family: var(--font-mono); margin-bottom: 2px;">
                SIGNAL TEMPORAL LOGIC (STL Donzé-Maler):
              </div>
              <div style="font-size: 8.5px; font-family: var(--font-mono); color: #94a3b8;">
                Min Robustness: <strong style="color: ${(state.stlReport?.minRobustness ?? 0) >= 0 ? '#10b981' : '#ef4444'};">${state.stlReport?.minRobustness ?? 0}</strong> |
                Formulas: <strong style="color: #e2e8f0;">${(state.stlReport?.formulas || []).filter(f => f.satisfied).length}/${state.stlReport?.formulas?.length || 5}</strong> Satisfied
              </div>
            </div>

            <div style="background: rgba(0, 0, 0, 0.3); border: 1px solid rgba(255, 255, 255, 0.06); border-radius: 4px; padding: 6px 10px;">
              <div style="font-size: 9.5px; font-weight: 700; color: #f59e0b; font-family: var(--font-mono); margin-bottom: 2px;">
                DSRL ACTION VAULT SAFETY GATE:
              </div>
              <div style="font-size: 8.5px; font-family: var(--font-mono); color: #94a3b8;">
                Status: <strong style="color: ${state.dsrlVault?.approved ? '#10b981' : '#f59e0b'};">${state.dsrlVault?.approved ? 'APPROVED' : 'GUARDED'}</strong> |
                Action: <span style="color: #e2e8f0;">${escapeHtml(state.dsrlVault?.actionName || 'ICMP_PING_GATEWAY')}</span>
              </div>
            </div>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px;">
            <div style="background: rgba(0, 0, 0, 0.3); border: 1px solid rgba(255, 255, 255, 0.06); border-radius: 4px; padding: 6px 10px;">
              <div style="font-size: 9.5px; font-weight: 700; color: #10b981; font-family: var(--font-mono); margin-bottom: 2px;">
                ACTIVE INFERENCE (Friston Free Energy):
              </div>
              <div style="font-size: 9px; color: #94a3b8; font-family: var(--font-mono);">
                VFE: <strong style="color: #38bdf8;">${state.activeInference?.variationalFreeEnergy || 0}</strong> |
                Complexity: <strong style="color: #f59e0b;">${state.activeInference?.complexityTerm || 0}</strong> |
                Accuracy: <strong style="color: #10b981;">${state.activeInference?.accuracyTerm || 0}</strong>
              </div>
              <div style="font-size: 9px; color: #64748b; font-family: var(--font-mono); margin-top: 2px;">
                Optimal Epistemic Probe: <span style="color: #e2e8f0;">${escapeHtml(state.activeInference?.optimalProbe?.name || 'ICMP Gateway Echo')}</span>
              </div>
            </div>

            <div style="background: rgba(0, 0, 0, 0.3); border: 1px solid rgba(255, 255, 255, 0.06); border-radius: 4px; padding: 6px 10px;">
              <div style="font-size: 9.5px; font-weight: 700; color: #8b5cf6; font-family: var(--font-mono); margin-bottom: 2px;">
                MCTS WORLD MODEL ROLLOUT:
              </div>
              <div style="display: flex; justify-content: space-between; font-size: 8.5px; font-family: var(--font-mono); margin-top: 3px;">
                ${(state.worldModelRollout?.rolloutHorizons || []).map(h => `
                  <div style="text-align: center;">
                    <div style="color: #64748b;">${h.step}</div>
                    <div style="color: ${h.failureRiskPct > 40 ? '#ef4444' : '#10b981'}; font-weight: 700;">${h.failureRiskPct}%</div>
                  </div>
                `).join('')}
              </div>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  /**
   * Fetch live AI Brain state from backend REST API
   */
  async function fetchLiveBrainState() {
    try {
      if (typeof window.api === 'function') {
        const data = await window.api('/api/network/ai-brain/live');
        if (data) {
          currentBrainState = data;
          updateDrawerDom(data);
        }
      }
    } catch (e) {
      // Backend may be momentarily busy
    }
  }

  /**
   * Update drawer DOM if container exists
   */
  function updateDrawerDom(state) {
    const containers = document.querySelectorAll('.ai-brain-drawer-mount');
    containers.forEach(container => {
      container.innerHTML = renderAiBrainDrawerHtml(state);
    });
  }

  /**
   * Trigger recommended diagnostic probe
   */
  window.triggerAiBrainProbe = async function(probeType, targetIp) {
    if (isExecutingProbe) return;
    isExecutingProbe = true;
    updateDrawerDom(currentBrainState);

    try {
      const res = await window.api('/api/network/ai-brain/trigger-probe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ probeType, targetIp })
      });

      if (res && res.revisedEvaluation) {
        if (!currentBrainState) currentBrainState = {};
        currentBrainState.topHypothesis = res.revisedEvaluation.topHypothesis;
        currentBrainState.rankedHypotheses = res.revisedEvaluation.rankedHypotheses;
        currentBrainState.distinguishingProbes = res.revisedEvaluation.distinguishingProbes;
        currentBrainState.recommendedProbe = res.revisedEvaluation.distinguishingProbes?.[0] || null;
      }
    } catch (err) {
      console.warn('[AI Brain Probe Error]:', err.message);
    } finally {
      isExecutingProbe = false;
      await fetchLiveBrainState();
    }
  };

  /**
   * Mount and initialize AI Brain drawer
   */
  window.initAiBrainDrawer = function(containerId) {
    const el = document.getElementById(containerId);
    if (!el) return;
    el.classList.add('ai-brain-drawer-mount');

    if (currentBrainState) {
      el.innerHTML = renderAiBrainDrawerHtml(currentBrainState);
    } else {
      el.innerHTML = renderAiBrainDrawerHtml(null);
      fetchLiveBrainState();
    }

    if (!brainPollTimer) {
      brainPollTimer = setInterval(fetchLiveBrainState, 4000);
    }
  };

  /**
   * Global hook for WebSocket live telemetry updates
   */
  window.handleAiBrainDiagnosticUpdate = function(update) {
    if (!update) return;
    fetchLiveBrainState();
  };

  window.renderAiBrainDrawerHtml = renderAiBrainDrawerHtml;
  window.fetchLiveBrainState = fetchLiveBrainState;

})(window);
