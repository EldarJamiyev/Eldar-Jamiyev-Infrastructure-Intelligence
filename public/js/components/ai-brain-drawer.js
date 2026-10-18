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

  window.toggleAiBrainDrawerExpand = function() {
    isAiBrainExpanded = !isAiBrainExpanded;
    updateDrawerDom(currentBrainState);
  };

  /**
   * Generates drawer HTML markup from live brain state
   */
  function renderAiBrainDrawerHtml(state) {
    if (!state) {
      return `
        <div id="aiBrainLiveDrawer" class="ai-brain-live-drawer" style="height: 38px; min-height: 38px; max-height: 38px; display: flex; align-items: center; justify-content: space-between; padding: 0 14px; background: rgba(15, 23, 42, 0.95); border: 1px solid var(--border-color); border-radius: 6px; box-sizing: border-box;">
          <div style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); display: flex; align-items: center; gap: 8px;">
            <span>🧠 Initializing Autonomous AI Diagnostic Brain (Continuous Bayesian Ingestion)...</span>
          </div>
        </div>
      `;
    }

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
          <span>⚡</span>
          <span>Execute: ${recommendedProbe.name || pType}</span>
        </button>
      `;
    } else {
      actionBtnHtml = '';
    }

    if (!isAiBrainExpanded) {
      return `
        <div id="aiBrainLiveDrawer" class="ai-brain-live-drawer" style="height: 38px; min-height: 38px; max-height: 38px; display: flex; align-items: center; justify-content: space-between; padding: 0 14px; background: rgba(15, 23, 42, 0.95); border: 1px solid var(--border-color); border-radius: 6px; box-sizing: border-box; overflow: hidden;">
          <div style="display: flex; align-items: center; gap: 10px; overflow: hidden; white-space: nowrap;">
            <span style="font-size: 14px;">🧠</span>
            <span style="font-weight: 800; font-size: 11px; color: #38bdf8; font-family: var(--font-mono);">AI BRAIN:</span>
            <span class="ai-brain-confidence-badge ${confClass}" style="font-size: 9.5px; padding: 1px 6px;">${topH.confidence}% CONFIDENCE</span>
            <span style="font-size: 11px; font-weight: 700; color: #f8fafc; text-overflow: ellipsis; overflow: hidden;">${escapeHtml(topH.label)}</span>
            <span style="font-size: 10px; color: #94a3b8;">(${escapeHtml(topH.rfc)})</span>
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
