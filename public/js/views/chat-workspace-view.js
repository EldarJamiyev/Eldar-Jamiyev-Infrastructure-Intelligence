/**
 * EJII Minimalist Chat-First Conversational Workspace View
 *
 * Default authenticated experience for Eldar Jamiyev's Infrastructure Intelligence.
 * Presents a calm, clean, centered conversational interface where users ask diagnostic
 * and investigation questions in plain language and receive verified answers backed
 * by real backend protocol probes.
 */

(function () {
  'use strict';

  const esc = (s) => (
    typeof window.escapeHtml === 'function'
      ? window.escapeHtml(s)
      : String(s ?? '')
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#39;')
  );

  const STARTER_PROMPTS = [
    'Check whether port 443 is reachable.',
    'Why is the website not responding?',
    'Check DNS resolution for this hostname.',
    'Compare the previous network result.',
    'Explain the timeout in simple terms.',
    'Check whether port 3000 is open on localhost'
  ];

  const STARTER_PROMPT_TAGS = ['TCP', 'HTTP', 'DNS', 'Compare', 'Explain', 'Local'];

  const chatState = {
    sessionId: null,
    messages: [],
    inFlight: false,
    activeRequestId: null,
    abortController: null,
    liveProgressStepText: '',
    progressTimer: null,
    lastContext: null,
    restoredSessionId: null
  };

  window.__ejiiChatState = chatState;

  function getOrInitSessionId() {
    if (chatState.sessionId) return chatState.sessionId;
    try {
      const saved = sessionStorage.getItem('ejii_chat_session_id');
      if (saved) {
        chatState.sessionId = saved;
        return saved;
      }
    } catch (_) {}
    const generated = 'CHAT-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).slice(2, 7).toUpperCase();
    chatState.sessionId = generated;
    try {
      sessionStorage.setItem('ejii_chat_session_id', generated);
    } catch (_) {}
    return generated;
  }

  async function ensureChatAuthToken() {
    let token = (window.state && window.state.token) || localStorage.getItem('ejii_token');
    if (token) return token;
    if (window.isEvaluationMode !== true) return null;
    try {
      const res = await fetch('/api/auth/quick-noc', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      if (res.ok) {
        const data = await res.json().catch(() => null);
        if (data && data.token) {
          token = data.token;
          if (window.state) {
            window.state.token = data.token;
            window.state.user = data.user || window.state.user;
          }
          try { localStorage.setItem('ejii_token', data.token); } catch (_) {}
          if (typeof window.hideLoginScreen === 'function') window.hideLoginScreen();
        }
      }
    } catch (_) {}
    return token;
  }

  async function restoreSessionHistoryIfNeeded() {
    const sessionId = getOrInitSessionId();
    if (!sessionId || chatState.messages.length > 0 || chatState.restoredSessionId === sessionId) {
      return;
    }
    try {
      const token = await ensureChatAuthToken();
      const headers = {};
      if (token) headers.Authorization = 'Bearer ' + token;
      const res = await fetch(`/api/v6/chat/session/${encodeURIComponent(sessionId)}?full=true`, {
        method: 'GET',
        headers,
        credentials: 'same-origin'
      });
      if (!res.ok) return;
      chatState.restoredSessionId = sessionId;
      const envelope = await res.json().catch(() => null);
      const data = envelope && envelope.data ? envelope.data : null;
      if (data && Array.isArray(data.messages) && data.messages.length > 0 && chatState.messages.length === 0) {
        chatState.messages = data.messages.map((m) => ({
          id: m.id || ('M-' + Date.now() + '-' + Math.random().toString(36).slice(2, 5)),
          role: m.role || 'assistant',
          content: m.content || '',
          createdAt: m.createdAt || new Date().toISOString(),
          meta: m.meta || {}
        }));
        if (data.lastValidTarget || data.lastTarget) {
          chatState.lastContext = {
            lastTarget: data.lastValidTarget || data.lastTarget,
            lastPorts: data.lastPorts || [],
            lastIntent: data.lastIntent || null
          };
        }
        updateThreadDom();
      }
    } catch (_) {
      // Transient fetch failure: do not lock restoredSessionId so subsequent render can retry
    }
  }

  function formatInlineMarkdown(str) {
    const raw = String(str || '').replace(/\u0000/g, '');
    const inlineCodeSpans = [];
    const withCodeTokens = raw.replace(/`([^`\n]+)`/g, (_, codeText) => {
      const idx = inlineCodeSpans.length;
      inlineCodeSpans.push(`<code>${esc(codeText)}</code>`);
      return `\u0000EJII_INLINE_CODE_${idx}\u0000`;
    });
    let safe = esc(withCodeTokens);
    safe = safe.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    safe = safe.replace(/\*([^*]+)\*/g, '<em>$1</em>');
    safe = safe.replace(/\u0000EJII_INLINE_CODE_(\d+)\u0000/g, (_, idxStr) => {
      return inlineCodeSpans[Number(idxStr)] || '';
    });
    return safe;
  }

  async function copyTextToClipboardVerified(text) {
    const payload = String(text || '');
    if (!payload) {
      return { copied: false, method: 'none', error: 'EMPTY_TEXT' };
    }
    let lastError = null;
    if (typeof navigator !== 'undefined' && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
      try {
        await navigator.clipboard.writeText(payload);
        return { copied: true, method: 'clipboard_api' };
      } catch (err) {
        lastError = err;
      }
    }
    if (
      typeof document !== 'undefined' &&
      document.body &&
      typeof document.createElement === 'function' &&
      typeof document.execCommand === 'function'
    ) {
      let ta = null;
      try {
        ta = document.createElement('textarea');
        ta.value = payload;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.top = '-9999px';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        if (typeof ta.select === 'function') ta.select();
        const ok = document.execCommand('copy') === true;
        document.body.removeChild(ta);
        if (ok) {
          return { copied: true, method: 'exec_command_fallback' };
        }
      } catch (fallbackErr) {
        lastError = lastError || fallbackErr;
        if (ta && ta.parentNode) {
          try { ta.parentNode.removeChild(ta); } catch (_) {}
        }
      }
    }
    return {
      copied: false,
      method: 'none',
      error: lastError && lastError.message ? lastError.message : 'CLIPBOARD_UNAVAILABLE'
    };
  }

  window.copyTextToClipboardVerified = copyTextToClipboardVerified;

  window.copyEjiiCodeBlock = async function (btnEl) {
    if (!btnEl) return { copied: false, error: 'MISSING_BUTTON' };
    const wrap = typeof btnEl.closest === 'function' ? btnEl.closest('.ejii-code-block-wrap') : null;
    const codeEl = wrap && typeof wrap.querySelector === 'function' ? wrap.querySelector('code') : null;
    const text = codeEl ? codeEl.textContent : (btnEl.dataset && btnEl.dataset.copyText ? btnEl.dataset.copyText : '');
    if (!text) return { copied: false, error: 'EMPTY_CODE' };
    const prevLabel = btnEl.dataset && btnEl.dataset.originalLabel ? btnEl.dataset.originalLabel : (btnEl.textContent || 'Copy');
    if (btnEl.dataset && !btnEl.dataset.originalLabel) {
      btnEl.dataset.originalLabel = prevLabel;
    }
    const result = await copyTextToClipboardVerified(text);
    if (result.copied) {
      btnEl.textContent = '✓ Copied';
      if (btnEl.dataset) btnEl.dataset.copyState = 'copied';
      if (typeof btnEl.setAttribute === 'function') btnEl.setAttribute('aria-label', 'Code copied to clipboard');
    } else {
      btnEl.textContent = '✕ Copy failed';
      if (btnEl.dataset) btnEl.dataset.copyState = 'failed';
      if (typeof btnEl.setAttribute === 'function') btnEl.setAttribute('aria-label', 'Failed to copy code to clipboard');
    }
    setTimeout(() => {
      btnEl.textContent = prevLabel;
      if (btnEl.dataset) delete btnEl.dataset.copyState;
    }, 1800);
    return result;
  };

  window.copyEjiiReportText = async function (btnEl, reportText) {
    if (!btnEl) return { copied: false, error: 'MISSING_BUTTON' };
    const prevLabel = btnEl.dataset && btnEl.dataset.originalLabel ? btnEl.dataset.originalLabel : (btnEl.textContent || 'Copy Incident Report');
    if (btnEl.dataset && !btnEl.dataset.originalLabel) {
      btnEl.dataset.originalLabel = prevLabel;
    }
    const result = await copyTextToClipboardVerified(reportText);
    if (result.copied) {
      btnEl.textContent = '✓ Report Copied';
      if (btnEl.dataset) btnEl.dataset.copyState = 'copied';
    } else {
      btnEl.textContent = '✕ Copy failed';
      if (btnEl.dataset) btnEl.dataset.copyState = 'failed';
    }
    setTimeout(() => {
      btnEl.textContent = prevLabel;
      if (btnEl.dataset) delete btnEl.dataset.copyState;
    }, 2000);
    return result;
  };

  window.clearEjiiChatTargetContext = function () {
    chatState.lastContext = null;
    updateThreadDom();
    const inp = document.getElementById('ejiiChatInput');
    if (inp) inp.focus();
  };

  function formatStructuredMarkdown(text) {
    const raw = String(text || '').replace(/\u0000/g, '').replace(/\r\n?/g, '\n');
    if (!raw.trim()) return '';

    // Extract fenced code blocks first (supporting LF/CRLF, optional language tag, and unclosed trailing fences)
    const codeBlocks = [];
    const pushCodeBlock = (lang, code) => {
      const idx = codeBlocks.length;
      const cleanLang = (lang || 'shell').trim() || 'shell';
      codeBlocks.push(`
        <div class="ejii-code-block-wrap">
          <div class="ejii-code-block-header">
            <span>${esc(cleanLang)}</span>
            <button type="button" class="ejii-code-copy-btn" onclick="window.copyEjiiCodeBlock(this)">Copy</button>
          </div>
          <pre class="ejii-code-pre"><code>${esc(String(code || '').replace(/^\n+|\n+$/g, ''))}</code></pre>
        </div>
      `);
      return `\n\n\u0000EJII_CODE_BLOCK_${idx}\u0000\n\n`;
    };

    let withPlaceholders = raw.replace(/```([a-zA-Z0-9_.-]*)[ \t]*\n([\s\S]*?)```/g, (_, lang, code) => {
      return pushCodeBlock(lang, code);
    });
    // Also handle unclosed trailing fenced code blocks at the end of a message
    withPlaceholders = withPlaceholders.replace(/```([a-zA-Z0-9_.-]*)[ \t]*\n([\s\S]+)$/g, (_, lang, code) => {
      return pushCodeBlock(lang, code);
    });

    const paragraphs = withPlaceholders.split(/\n\n+/).filter(Boolean);
    return paragraphs.map((p) => {
      const trimmed = p.trim();
      const codeMatch = trimmed.match(/^\u0000EJII_CODE_BLOCK_(\d+)\u0000$/);
      if (codeMatch) {
        return codeBlocks[Number(codeMatch[1])] || '';
      }

      // Executive hierarchy callouts: **Result:**, **Meaning:**, **Next step:**
      const execMatch = trimmed.match(/^\*\*(Result|Meaning|Next step|Direct Answer|Root Cause|Recommended Action):\*\*\s*([\s\S]*)$/i);
      if (execMatch) {
        const rawLabel = execMatch[1];
        const bodyText = (execMatch[2] || '').trim();
        if (!bodyText || /^(none|n\/a|not applicable|-)$/i.test(bodyText)) {
          return '';
        }
        const lowerLabel = rawLabel.toLowerCase();
        const modClass = lowerLabel.includes('result') || lowerLabel.includes('answer')
          ? 'ejii-exec-callout-result'
          : lowerLabel.includes('next') || lowerLabel.includes('action')
            ? 'ejii-exec-callout-next'
            : 'ejii-exec-callout-meaning';
        return `
          <div class="ejii-exec-callout-block ${modClass}">
            <span class="ejii-exec-callout-label">${esc(rawLabel)}:</span>
            <span>${formatInlineMarkdown(bodyText).replace(/\n/g, '<br>')}</span>
          </div>
        `;
      }

      // Bulleted or numbered lists
      const lines = trimmed.split('\n');
      const isBulletList = lines.length > 0 && lines.every((l) => /^\s*[-*•]\s+/.test(l));
      if (isBulletList) {
        const items = lines.map((l) => `<li>${formatInlineMarkdown(l.replace(/^\s*[-*•]\s+/, ''))}</li>`).join('');
        return `<ul class="ejii-answer-list">${items}</ul>`;
      }
      const isNumberedList = lines.length > 1 && lines.every((l) => /^\s*\d+\.\s+/.test(l));
      if (isNumberedList) {
        const items = lines.map((l) => `<li>${formatInlineMarkdown(l.replace(/^\s*\d+\.\s+/, ''))}</li>`).join('');
        return `<ol class="ejii-answer-list">${items}</ol>`;
      }

      const isCallout = trimmed.startsWith('> ');
      const isHeading = /^#{1,4}\s+/.test(trimmed);
      const contentText = isCallout
        ? trimmed.slice(2)
        : (isHeading ? trimmed.replace(/^#{1,4}\s+/, '') : trimmed);
      const safe = formatInlineMarkdown(contentText).replace(/\n/g, '<br>');
      if (isCallout) {
        return `<div class="ejii-answer-section ejii-callout-surface">${safe}</div>`;
      }
      if (isHeading) {
        return `<div class="ejii-answer-section"><strong>${safe}</strong></div>`;
      }
      return `<p class="ejii-answer-section">${safe}</p>`;
    }).join('');
  }

  window.formatEjiiChatMarkdown = formatStructuredMarkdown;
  window.formatEjiiInlineMarkdown = formatInlineMarkdown;

  function renderMessageItem(msg) {
    if (msg.role === 'user') {
      return `
        <div class="ejii-msg-row ejii-msg-user" data-msg-id="${esc(msg.id)}">
          <div class="ejii-msg-user-bubble">${esc(msg.content)}</div>
        </div>
      `;
    }

    const meta = msg.meta || {};
    const steps = Array.isArray(meta.steps) ? meta.steps : [];
    const findings = Array.isArray(meta.findings) ? meta.findings : [];
    const evidence = meta.technicalEvidence || null;
    const hasDiagnosticActivity = steps.length > 0 || Boolean(meta.connectionTable) || Boolean(meta.interfaceTable);
    const durationLabel = hasDiagnosticActivity && typeof meta.totalDurationMs === 'number' && Number.isFinite(meta.totalDurationMs)
      ? `${meta.totalDurationMs} ms`
      : '';

    const stepsHtml = steps.length > 0 ? `
      <div class="ejii-step-list" aria-label="Executed diagnostic steps">
        ${steps.map((s) => {
          const rawStatus = (s && s.status) ? String(s.status).toUpperCase() : null;
          const isPass = rawStatus === 'PASS' || rawStatus === 'OK' || rawStatus === 'COMPLETED';
          const isWarn = rawStatus === 'WARN' || rawStatus === 'DEGRADED';
          const isFail = rawStatus === 'FAIL' || rawStatus === 'ERROR' || rawStatus === 'TIMEOUT';
          const icon = isPass ? '✓' : (isWarn ? '!' : (isFail ? '✕' : '•'));
          const cls = isPass
            ? 'ejii-step-status-pass'
            : (isWarn
              ? 'ejii-step-status-warn'
              : (isFail
                ? 'ejii-step-status-fail'
                : 'ejii-step-status-unknown'));
          const stepDur = typeof s.durationMs === 'number' && Number.isFinite(s.durationMs)
            ? `<span class="ejii-step-duration">${s.durationMs} ms</span>`
            : '';
          return `
            <div class="ejii-step-item">
              <div class="ejii-step-left">
                <span class="ejii-step-status-icon ${cls}" aria-hidden="true">${icon}</span>
                <span>${esc(s.summary || s.label)}</span>
              </div>
              ${stepDur}
            </div>
          `;
        }).join('')}
      </div>
    ` : '';

    const findingsHtml = findings.length > 0 ? `
      <div class="ejii-findings-row" aria-label="Key diagnostic findings">
        ${findings.map((f) => {
          const toneCls = f.tone === 'ok'
            ? 'ejii-finding-ok'
            : f.tone === 'warn'
              ? 'ejii-finding-warn'
              : f.tone === 'danger'
                ? 'ejii-finding-danger'
                : '';
          return `
            <div class="ejii-finding-item ${toneCls}">
              <span class="ejii-finding-label">${esc(f.label)}:</span>
              <span class="ejii-finding-value">${esc(f.value)}</span>
            </div>
          `;
        }).join('')}
      </div>
    ` : '';

    const tableSpec = meta.connectionTable || meta.interfaceTable || null;
    const tableHtml = tableSpec && Array.isArray(tableSpec.columns) && Array.isArray(tableSpec.rows) && tableSpec.rows.length > 0 ? `
      <div class="ejii-structured-table-wrapper" role="region" aria-label="${esc(tableSpec.title || 'Structured Telemetry Table')}">
        ${tableSpec.title ? `<div class="ejii-structured-table-title">${esc(tableSpec.title)}</div>` : ''}
        <table class="ejii-structured-table">
          <thead>
            <tr>
              ${tableSpec.columns.map((col) => `<th>${esc(col)}</th>`).join('')}
            </tr>
          </thead>
          <tbody>
            ${tableSpec.rows.map((row) => `
              <tr>
                ${(Array.isArray(row) ? row : []).map((cell) => `<td>${esc(cell)}</td>`).join('')}
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    ` : '';

    const mem = meta.memoryInsights || null;
    const depCtx = mem && mem.dependencyContext ? mem.dependencyContext : null;
    const hasDependencies = depCtx && (
      (Array.isArray(depCtx.upstreamDependencies) && depCtx.upstreamDependencies.length > 0) ||
      (Array.isArray(depCtx.downstreamDependents) && depCtx.downstreamDependents.length > 0)
    );
    const hasMemoryContext = mem && (
      mem.observationCount >= 1 ||
      (Array.isArray(mem.stateTransitions) && mem.stateTransitions.length > 0) ||
      (Array.isArray(mem.matchedResolutions) && mem.matchedResolutions.length > 0) ||
      hasDependencies
    );
    const forecast = mem && mem.predictiveForecast ? mem.predictiveForecast : null;
    const remRec = mem && mem.remediationRecommendation ? mem.remediationRecommendation : null;
    const memoryHtml = hasMemoryContext ? `
      <div class="ejii-memory-strip" role="region" aria-label="Operational memory and baseline comparison">
        <div class="ejii-memory-meta">
          <span class="ejii-memory-tag">Operational Memory</span>
          <span>Target <code>${esc(mem.target)}</code> observed ${esc(String(mem.observationCount))}x</span>
          ${typeof mem.stabilityScore === 'number' ? `<span>· Stability: <strong>${esc(String(mem.stabilityScore))}%</strong></span>` : ''}
          ${mem.baselineDelta ? `<span>· Baseline RTT: ${esc(mem.baselineDelta.summary)}</span>` : (typeof mem.ewmaRttMs === 'number' ? `<span>· EWMA RTT: ${esc(String(mem.ewmaRttMs))} ms</span>` : (typeof mem.avgRttMs === 'number' ? `<span>· Avg RTT: ${esc(String(mem.avgRttMs))} ms</span>` : ''))}
          ${hasDependencies ? `<span>· Topology: ${esc(String((depCtx.upstreamDependencies || []).length))} upstream / ${esc(String((depCtx.downstreamDependents || []).length))} downstream</span>` : ''}
          ${forecast && forecast.riskClassification !== 'NOMINAL_STABLE' ? `<span>· Forecast: <strong>${esc(forecast.riskClassification)}</strong></span>` : ''}
        </div>
        ${Array.isArray(mem.stateTransitions) && mem.stateTransitions.length > 0 ? `
          <div class="ejii-memory-transitions">
            ${mem.stateTransitions.map((tr) => `<div class="ejii-memory-transition-item">State transition: ${esc(tr.message)}</div>`).join('')}
          </div>
        ` : ''}
        ${forecast && forecast.riskClassification !== 'NOMINAL_STABLE' ? `
          <div class="ejii-memory-transitions">
            <div class="ejii-memory-transition-item">Predictive Forecast: ${esc(forecast.explanation)}</div>
          </div>
        ` : ''}
        ${remRec && remRec.warningPriorFailure ? `
          <div class="ejii-memory-transitions">
            <div class="ejii-memory-transition-item">${esc(remRec.warningPriorFailure)}</div>
          </div>
        ` : ''}
        ${remRec && remRec.adaptivePivotRationale ? `
          <div class="ejii-memory-transitions">
            <div class="ejii-memory-transition-item"><strong>Adaptive Closed-Loop Pivot:</strong> ${esc(remRec.adaptivePivotRationale)}</div>
          </div>
        ` : ''}
        ${Array.isArray(mem.matchedResolutions) && mem.matchedResolutions.length > 0 ? `
          <div class="ejii-memory-resolutions">
            ${mem.matchedResolutions.map((r) => `<div class="ejii-memory-resolution-item">Learned Playbook (${esc(r.resolutionId)}): ${esc(r.rootCause)} → ${esc(r.resolutionSteps)}</div>`).join('')}
          </div>
        ` : ''}
      </div>
    ` : '';

    const hypEval = meta.hypothesisEvaluation || (meta.structuredAnswer && meta.structuredAnswer.hypothesisEvaluation) || null;
    const hypHtml = (hypEval && Array.isArray(hypEval.hypotheses) && hypEval.hypotheses.length > 0) ? `
      <div class="ejii-memory-strip" role="region" aria-label="Hypothesis evaluation and root-cause disambiguation">
        <div class="ejii-memory-meta">
          <span class="ejii-memory-tag">Competing Hypotheses &amp; Root-Cause Matrix</span>
          ${hypEval.primaryRootCause ? `<span><strong>Primary Cause (${esc(String(hypEval.primaryRootCause.posteriorProbabilityPct ?? hypEval.primaryRootCause.confidencePct ?? 90))}%):</strong> ${esc(hypEval.primaryRootCause.layer)} — ${esc(hypEval.primaryRootCause.summary)}</span>` : ''}
        </div>
        ${Array.isArray(hypEval.downstreamSymptoms) && hypEval.downstreamSymptoms.length > 0 ? `
          <div class="ejii-memory-resolutions">
            <div class="ejii-memory-resolution-item"><strong>Downstream Symptom(s):</strong> ${esc(hypEval.downstreamSymptoms.join(' · '))}</div>
          </div>
        ` : ''}
        <div class="ejii-findings-row" style="margin-top:4px;">
          ${hypEval.hypotheses.map((h) => {
            const isFault = h.status === 'CONFIRMED_FAULT';
            const isSymptom = h.status === 'DOWNSTREAM_SYMPTOM' || h.causalRole === 'DOWNSTREAM_SYMPTOM';
            const isHealthy = h.status === 'REFUTED_HEALTHY';
            const cls = isFault ? 'ejii-finding-danger' : (isHealthy ? 'ejii-finding-ok' : 'ejii-finding-warn');
            const confBadge = typeof h.posteriorProbabilityPct === 'number' && (isFault || isSymptom || h.status === 'SUSPECTED_FAULT')
              ? ` (${h.posteriorProbabilityPct}%)`
              : '';
            return `
              <div class="ejii-finding-item ${cls}" title="${esc(h.evidence || '')}">
                <span class="ejii-finding-label">${esc(h.layer)}:</span>
                <span class="ejii-finding-value">${esc(h.verdictLabel)}${esc(confBadge)}</span>
              </div>
            `;
          }).join('')}
        </div>
        ${hypEval.nextBestInvestigation ? `
          <div class="ejii-memory-transitions">
            <div class="ejii-memory-transition-item">
              <strong>Highest Information-Gain Next Probe (${esc(String(hypEval.nextBestInvestigation.expectedInformationGainBits))} bits):</strong>
              ${esc(hypEval.nextBestInvestigation.rationale)}
            </div>
          </div>
        ` : ''}
        ${Array.isArray(hypEval.contradictions) && hypEval.contradictions.length > 0 ? `
          <div class="ejii-memory-transitions">
            ${hypEval.contradictions.map((c) => `<div class="ejii-memory-transition-item">Cross-Layer Anomaly [${esc(c.type)}]: ${esc(c.explanation)}</div>`).join('')}
          </div>
        ` : ''}
      </div>
    ` : '';

    const journey = meta.unifiedJourney || null;
    const journeyHtml = (journey && Array.isArray(journey.stages) && journey.stages.length > 0 && hasDiagnosticActivity) ? `
      <div class="ejii-memory-strip" role="region" aria-label="10-Stage Unified Operational Journey Continuum">
        <div class="ejii-memory-meta">
          <span class="ejii-memory-tag">Unified Operational Journey</span>
          <span>10-Stage Closed-Loop Continuum for <code>${esc(journey.target)}</code></span>
        </div>
        <div class="ejii-findings-row" style="margin-top:4px;">
          ${journey.stages.map((st) => {
            const cls = st.status === 'VERIFIED' || st.status === 'NOMINAL' || st.status === 'LEARNED'
              ? 'ejii-finding-ok'
              : (st.status === 'FAULT_ISOLATED' || st.status === 'ACTION_REQUIRED' || st.status === 'BLAST_RADIUS_ACTIVE' || st.status === 'DRIFT_WARNING')
                ? 'ejii-finding-warn'
                : 'ejii-finding-neutral';
            return `
              <div class="ejii-finding-item ${cls}" title="${esc(st.summary || '')}">
                <span class="ejii-finding-label">${esc(String(st.stageNumber))}. ${esc(st.stageId.replace(/_/g, ' '))}:</span>
                <span class="ejii-finding-value">${esc(st.status)}</span>
              </div>
            `;
          }).join('')}
        </div>
      </div>
    ` : '';

    const hasFailedStep = steps.some((s) => s.status === 'FAIL' || s.status === 'WARN' || s.status === 'TIMEOUT');
    const actionTarget = meta.target && !String(meta.target).includes('local_') && !String(meta.target).includes('operational_')
      ? meta.target
      : null;

    const workstationActionsHtml = (hasDiagnosticActivity || meta.reportMarkdown || actionTarget) ? `
      <div class="ejii-card-actions-bar" aria-label="Operational actions and workstation handoff">
        ${meta.reportMarkdown ? `
          <button
            type="button"
            class="ejii-header-btn"
            onclick="window.copyEjiiReportText(this, ${esc(JSON.stringify(meta.reportMarkdown))})"
          >
            Copy Incident Report
          </button>
        ` : ''}
        ${actionTarget ? `
          <button
            type="button"
            class="ejii-header-btn"
            onclick="window.sendEjiiChatMessage(${esc(JSON.stringify(`What is the dependency impact and blast radius for ${actionTarget}?`))})"
          >
            Analyze Blast Radius
          </button>
          <button
            type="button"
            class="ejii-header-btn"
            onclick="window.sendEjiiChatMessage(${esc(JSON.stringify(`What happens if ${actionTarget} becomes unavailable?`))})"
          >
            Simulate What-If Scenario
          </button>
          <button
            type="button"
            class="ejii-header-btn"
            onclick="window.switchToAdvancedToolView('topology')"
          >
            Inspect in Topology →
          </button>
        ` : ''}
        ${hasFailedStep ? `
          <button
            type="button"
            class="ejii-header-btn"
            onclick="window.sendEjiiChatMessage('Execute governed DNS resolver refresh and verify')"
          >
            Execute Governed DNS Refresh
          </button>
          <button
            type="button"
            class="ejii-header-btn"
            onclick="window.switchToAdvancedToolView('ai-operator')"
          >
            Open AI Operator →
          </button>
        ` : ''}
      </div>
    ` : '';

    const cc = meta.commandCenterOverview;
    const commandCenterHtml = cc ? `
      <div class="ejii-memory-strip" aria-label="IT Operations Command Center Executive Situation">
        <div class="ejii-memory-strip-header">
          <span class="ejii-memory-badge">IT Operations Command Center · Posture: ${esc(cc.executiveSituationSummary?.overallPosture || 'NOMINAL')}</span>
          <span class="ejii-memory-pill">Correlated Incidents: <strong>${esc((cc.correlatedIncidents || []).length)}</strong></span>
          <span class="ejii-memory-pill">Deduped Probes: <strong>${esc(cc.operationsCommander?.avoidedDuplicateProbesCount ?? 0)}</strong></span>
        </div>
        <div class="ejii-memory-note">
          <strong>Situation:</strong> ${esc(cc.executiveSituationSummary?.whatIsHappening || '')}
        </div>
        <div class="ejii-memory-note">
          <strong>Priority Action:</strong> ${esc(cc.executiveSituationSummary?.mostImportantToAddress || '')}
        </div>
      </div>
    ` : '';

    const sim = meta.scenarioSimulation;
    const scenarioSimHtml = sim ? `
      <div class="ejii-memory-strip" aria-label="Simulated Operational Scenario">
        <div class="ejii-memory-strip-header">
          <span class="ejii-memory-badge ejii-tone-warn">${esc(sim.simulationBadge || '[SIMULATED SCENARIO — NOT LIVE TELEMETRY]')}</span>
          <span class="ejii-memory-pill">Role: <strong>${esc(sim.environmentProfile?.roleLabel || 'Host')} (${esc(sim.environmentProfile?.criticalityTier || 'TIER_2')})</strong></span>
          <span class="ejii-memory-pill">Owner: <strong>${esc(sim.environmentProfile?.ownership?.team || 'Platform Ops')}</strong></span>
        </div>
        <div class="ejii-memory-note">
          <strong>If Unavailable:</strong> ${esc(sim.impactAnalysis?.whatHappensIfUnavailable || '')}
        </div>
        ${sim.remediationComparison?.lowestRiskOption ? `
          <div class="ejii-memory-note">
            <strong>Lowest-Risk Remediation:</strong> ${esc(sim.remediationComparison.lowestRiskOption.title)} (Risk ${esc(sim.remediationComparison.lowestRiskOption.operationalRiskScore)}/100 · Efficacy ${esc(sim.remediationComparison.lowestRiskOption.historicalEfficacyPct)}%)
          </div>
        ` : ''}
      </div>
    ` : '';

    const followUps = Array.isArray(meta.suggestedFollowUps) ? meta.suggestedFollowUps : [];
    const followUpsHtml = followUps.length > 0 ? `
      <div class="ejii-followup-strip" aria-label="Recommended next investigative steps">
        <span class="ejii-followup-label">Next steps:</span>
        <div class="ejii-followup-chips">
          ${followUps.map((f) => `
            <button
              type="button"
              class="ejii-followup-chip"
              title="${esc(f.rationale || f.prompt)}"
              onclick="window.sendEjiiChatMessage(${esc(JSON.stringify(f.prompt))})"
            >
              <span>${esc(f.label)}</span>
              <span aria-hidden="true">→</span>
            </button>
          `).join('')}
        </div>
      </div>
    ` : '';

    const evidenceHtml = (evidence && (hasDiagnosticActivity || findings.length > 0)) ? `
      <details class="ejii-evidence-details">
        <summary>Technical details &amp; raw probe output</summary>
        <pre class="ejii-evidence-pre">${esc(JSON.stringify(evidence, null, 2))}</pre>
      </details>
    ` : '';

    const ep = meta.epistemicReasoning;
    const decomp = meta.problemDecomposition;
    const remSuit = meta.remediationSuitability;
    const cog3Strat = meta.cognition3StrategyPlan;
    const selfCorr = meta.criticalSelfCorrection;
    const collab = meta.collaborativeSynthesis;
    const closedLoop = meta.closedLoopFollowUp || evidence?.closedLoopFollowUp || null;
    const ans = meta.structuredAnswer || {};
    const stateDiff = meta.stateDiff || ans.stateDiff || evidence?.stateDiff || null;
    const pillars = ep?.epistemicSevenPillars;

    const stateDiffHtml = stateDiff ? `
      <div class="ejii-memory-strip" aria-label="Multi-Turn Diagnostic State Differential" style="border-left: 3px solid #0ea5e9;">
        <div class="ejii-memory-strip-header">
          <span class="ejii-memory-badge">Multi-Turn State Diff · ${esc(stateDiff.target)}</span>
          <span class="ejii-memory-pill">Status Changed: <strong>${stateDiff.statusChanged ? 'YES' : 'NO (STABLE)'}</strong></span>
          ${typeof stateDiff.rttDeltaMs === 'number' ? `<span class="ejii-memory-pill">RTT Δ: <strong>${stateDiff.rttDeltaMs > 0 ? `+${stateDiff.rttDeltaMs}` : stateDiff.rttDeltaMs} ms</strong></span>` : ''}
          ${Array.isArray(stateDiff.newlyOpenedPorts) && stateDiff.newlyOpenedPorts.length > 0 ? `<span class="ejii-memory-pill">Newly Open: <strong>:${esc(stateDiff.newlyOpenedPorts.join(', :'))}</strong></span>` : ''}
          ${Array.isArray(stateDiff.newlyClosedPorts) && stateDiff.newlyClosedPorts.length > 0 ? `<span class="ejii-memory-pill">Newly Closed: <strong>:${esc(stateDiff.newlyClosedPorts.join(', :'))}</strong></span>` : ''}
        </div>
        <div class="ejii-memory-note">
          <strong>Previous (${esc(stateDiff.previousObservedAt || 'prior turn')}):</strong> ${esc(stateDiff.previousSummary || 'N/A')} &rarr;
          <strong>Latest (${esc(stateDiff.latestObservedAt || 'current turn')}):</strong> ${esc(stateDiff.latestSummary || 'N/A')}
        </div>
      </div>
    ` : '';

    const epistemicHtml = (ep && hasDiagnosticActivity) ? `
      <div class="ejii-memory-strip" aria-label="Dynamic Epistemic Reasoning and Self-Correction">
        <div class="ejii-memory-strip-header">
          <span class="ejii-memory-badge">AI Cognition 4.0 · ${esc(cog3Strat?.problemNatureClassification?.primaryNature || ep.stoppingCondition?.status || 'VERIFIED')}</span>
          <span class="ejii-memory-pill">Strategy: <strong>${esc(cog3Strat?.selectedStrategy?.strategyId || 'ADAPTIVE')}</strong></span>
          <span class="ejii-memory-pill">Observed: <strong>${esc((pillars?.directlyObserved || ep.knownFacts || []).length)}</strong></span>
          <span class="ejii-memory-pill">Confidence: <strong>${esc(closedLoop?.afterConfidencePct ?? collab?.consensusConfidencePct ?? selfCorr?.epistemicCalibration?.calibratedConfidencePct ?? ep.stoppingCondition?.confidencePct ?? 90)}%</strong> (H=${esc(ep.intelligentStoppingDecision?.residualShannonEntropyBits ?? 0.42)}b)</span>
        </div>
        ${cog3Strat ? `
          <div class="ejii-memory-note">
            <strong>Adaptive Strategy (${esc(cog3Strat.selectedStrategy?.strategyName)}):</strong> ${esc(cog3Strat.selectedStrategy?.rationale)} · <strong>Parallel Groups:</strong> ${esc((cog3Strat.capabilitySelectionPlan?.parallelExecutionGroups || []).length)}
          </div>
        ` : (decomp ? `
          <div class="ejii-memory-note">
            <strong>Problem Decomposition (${esc(decomp.problemScopeClassification)}):</strong> ${esc(decomp.inferredOperationalObjective)}
          </div>
        ` : '')}
        ${selfCorr && (selfCorr.challengedAssumptions || []).length > 0 ? `
          <div class="ejii-memory-note">
            <strong>Critical Assumption Challenger:</strong> ${esc(selfCorr.challengedAssumptions[0].whyChallenged)}
          </div>
        ` : ''}
        ${collab ? `
          <div class="ejii-memory-note">
            <strong>6-Specialist Collaborative Consensus (${esc(collab.consensusConfidencePct)}% · ${esc(collab.observedDomainCount ?? collab.specialistCount ?? 6)}/${esc(collab.specialistCount || 6)} Observed Domains):</strong> ${esc(collab.unifiedDiagnosis)}
          </div>
          ${collab.evidenceWeightingRationale ? `
            <div class="ejii-memory-note ejii-text-muted-sm">
              <strong>Evidence Weighting &amp; Calibration:</strong> ${esc(collab.evidenceWeightingRationale)}
            </div>
          ` : ''}
          ${collab.compoundMultiCauseAnalysis?.isCompoundIncident ? `
            <div class="ejii-memory-note ejii-text-warning-strong">
              <strong>Compound Multi-Cause Incident Detected (${esc(collab.compoundMultiCauseAnalysis.activeFaultCount)} concurrent faults):</strong> ${esc(collab.compoundMultiCauseAnalysis.explanation)}
            </div>
          ` : ''}
          ${Array.isArray(collab.crossExaminationDebate) && collab.crossExaminationDebate.length > 0 ? `
            <div class="ejii-memory-note">
              <strong>Cross-Examination Rebuttal (${esc(collab.crossExaminationDebate[0].challenger)} &rarr; ${esc(collab.crossExaminationDebate[0].challenged)}):</strong> ${esc(collab.crossExaminationDebate[0].rebuttal)} <em>(${esc(collab.crossExaminationDebate[0].resolution)})</em>
            </div>
          ` : ''}
          ${closedLoop && closedLoop.executed ? `
            <div class="ejii-memory-note ${closedLoop.confidenceDeltaPct < 0 ? 'ejii-text-warning-strong' : ''}">
              <strong>Closed-Loop Autonomous Blind-Spot Verification:</strong> Executed ${esc(closedLoop.probesRun.length)} follow-up probe(s) (${esc(closedLoop.probesRun.map(p => `${p.probeType}:${p.status}`).join(', '))}) &bull; Confidence ${esc(closedLoop.beforeConfidencePct)}% &rarr; <strong>${esc(closedLoop.afterConfidencePct)}%</strong> (${esc(closedLoop.hypothesisReassessment?.status || 'VERIFIED')})
            </div>
          ` : ''}
          ${Array.isArray(collab.telemetryBlindSpots) && collab.telemetryBlindSpots.length > 0 ? `
            <div class="ejii-memory-note">
              <strong>Remaining Telemetry Blind Spots:</strong> ${esc(collab.telemetryBlindSpots.join(' | '))}
            </div>
          ` : ''}
          ${Array.isArray(collab.recommendedFollowUpProbes) && collab.recommendedFollowUpProbes.length > 0 ? `
            <div class="ejii-memory-note" style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-top:4px;">
              <strong>Recommended Verification Probes:</strong>
              ${collab.recommendedFollowUpProbes.map((fp) => {
                const probePrompt = `Run ${fp.probeType} on ${fp.target}`;
                return `
                  <button type="button" class="ejii-followup-chip" data-followup-prompt="${esc(probePrompt)}" onclick="window.sendEjiiChatMessage(${esc(JSON.stringify(probePrompt))})" style="padding:2px 8px;font-size:11px;">
                    Verify ${esc(fp.probeType)} (${esc(fp.target)}) →
                  </button>
                `;
              }).join('')}
            </div>
          ` : ''}
        ` : ''}
        ${remSuit ? `
          <div class="ejii-memory-note">
            <strong>Context-Comparable Remediation (${esc(remSuit.comparabilityScorePct)}% Match):</strong> ${esc(remSuit.whyHistoricalSolutionWorked)}
          </div>
        ` : ''}
        <div class="ejii-memory-note">
          <strong>Stopping Condition:</strong> ${esc(ep.intelligentStoppingDecision?.rationale || ep.stoppingCondition?.whyStopOrContinue || '')}
        </div>
      </div>
    ` : '';

    const epDist = meta.epistemicDistinctions || meta.technicalEvidence?.epistemicDistinctions || null;
    const compExp = meta.competingExplanationsComparison || null;
    const epDistHtml = (epDist && (hasDiagnosticActivity || (epDist.observedConditions || []).length > 0 || (epDist.unavailableMetrics || []).length > 0)) ? `
      <div class="ejii-memory-strip" role="region" aria-label="Epistemic Truth and Provenance Disambiguation">
        <div class="ejii-memory-strip-header">
          <span class="ejii-memory-badge">Project Falcon Epistemic Contract</span>
          <span class="ejii-memory-pill">Observed Facts: <strong>${esc((epDist.observedConditions || []).length)}</strong></span>
          <span class="ejii-memory-pill">Suspected / Inferred: <strong>${esc((epDist.suspectedProblems || []).length)}</strong></span>
          <span class="ejii-memory-pill">Historical Priors: <strong>${esc((epDist.historicalPriors || []).length)}</strong></span>
          <span class="ejii-memory-pill">Unavailable Metrics: <strong>${esc((epDist.unavailableMetrics || []).length)}</strong></span>
          ${epDist.verifiedRecoveryState ? `<span class="ejii-memory-pill">Recovery State: <strong>${esc(epDist.verifiedRecoveryState.recoveryState || (epDist.verifiedRecoveryState.postActionHealthy ? 'VERIFIED_HEALTHY_AFTER_REMEDIATION' : epDist.verifiedRecoveryState.actionExecuted ? 'ACTION_EXECUTED_POST_PROBE_PENDING_OR_UNVERIFIED' : 'REMEDIATION_NOT_EXECUTED'))}</strong></span>` : ''}
        </div>
        ${epDist.verifiedRecoveryState && epDist.verifiedRecoveryState.verificationProbe ? `
          <div class="ejii-memory-note">
            <strong>Post-Action Verification Probe (${esc(epDist.verifiedRecoveryState.verificationProbe.probeType)} on ${esc(epDist.verifiedRecoveryState.verificationProbe.target)}):</strong> ${esc(epDist.verifiedRecoveryState.verificationProbe.observedResult)} (${epDist.verifiedRecoveryState.postActionHealthy ? 'VERIFIED HEALTHY' : esc(epDist.verifiedRecoveryState.rejectionReason || 'UNVERIFIED / FAILED')})
          </div>
        ` : ''}
        ${compExp && compExp.leadingHypothesis ? `
          <div class="ejii-memory-note">
            <strong>Why Leading Hypothesis Outweighs Alternatives (${esc(compExp.leadingHypothesis.confidenceType)}):</strong> ${esc(compExp.leadingHypothesis.evidentialRankingRationale || compExp.leadingHypothesis.whyLeadingOutweighsAlternatives)}
          </div>
        ` : ''}
        ${Array.isArray(epDist.unavailableMetrics) && epDist.unavailableMetrics.length > 0 ? `
          <div class="ejii-memory-note">
            <strong>Unmeasured / Unavailable Metrics:</strong> ${esc(epDist.unavailableMetrics.slice(0, 4).join(' · '))}
          </div>
        ` : ''}
      </div>
    ` : '';

    // Build truthful Interpreted Intent & Target Context Strip when backend metadata is present
    const hasIntentContext = Boolean(meta.intent || meta.target || (Array.isArray(meta.ports) && meta.ports.length > 0));
    const cleanTarget = meta.target && !String(meta.target).startsWith('local_') && !String(meta.target).startsWith('operational_')
      ? String(meta.target)
      : (meta.target ? String(meta.target).replace(/_/g, ' ') : '');
    const portsList = Array.isArray(meta.ports) && meta.ports.length > 0 ? meta.ports.join(', ') : '';
    const intentContextHtml = hasIntentContext ? `
      <div class="ejii-intent-context-strip" role="region" aria-label="Interpreted diagnostic intent and target context">
        <div class="ejii-intent-context-left">
          ${meta.intent ? `<span class="ejii-intent-pill ejii-intent-pill-primary">Intent: ${esc(String(meta.intent).replace(/_/g, ' '))}</span>` : ''}
          ${cleanTarget ? `<span class="ejii-intent-pill ejii-intent-pill-target">Target: ${esc(cleanTarget)}</span>` : ''}
          ${portsList ? `<span class="ejii-intent-pill">Port${meta.ports.length > 1 ? 's' : ''}: ${esc(portsList)}</span>` : ''}
          ${meta.mode ? `<span class="ejii-intent-pill">Mode: ${esc(String(meta.mode))}</span>` : ''}
        </div>
        <div class="ejii-intent-context-right">
          ${steps.length > 0 ? `<span class="ejii-intent-pill">${esc(String(steps.length))} live probe${steps.length === 1 ? '' : 's'}</span>` : ''}
        </div>
      </div>
    ` : '';

    const isOperationalOrEpistemic = meta.mode === 'operational' || meta.intent === 'epistemic_fabric_query' || meta.intent === 'log_and_startup_triage';
    const cmem = meta.claudeMemContext || null;
    const sroute = meta.skillRoutingContext || null;
    const claudeMemHtml = ((cmem || sroute) && (isOperationalOrEpistemic || hasDiagnosticActivity)) ? `
      <div class="ejii-memory-strip" role="region" aria-label="Claude-Mem progressive disclosure and context-budgeted skill routing">
        <div class="ejii-memory-strip-header">
          <span class="ejii-memory-badge">Claude-Mem 3-Layer Progressive Disclosure</span>
          ${cmem && cmem.layer1IndexSearch ? `
            <span class="ejii-memory-pill">L1 Index Hits: <strong>${esc(String(cmem.layer1IndexSearch.hitCount))}</strong> (${esc(String(cmem.layer1IndexSearch.indexTokensUsed))} tok)</span>
            <span class="ejii-memory-pill">Saved: <strong>${esc(String(cmem.layer1IndexSearch.tokensSaved))} tok (${esc(String(cmem.layer1IndexSearch.compressionRatioPct))}%)</strong></span>
          ` : ''}
          ${sroute ? `
            <span class="ejii-memory-pill">Taxonomy: <strong>85+74=159 Manifests · 111 Modules · 71 Locks</strong></span>
            <span class="ejii-memory-pill">Deduped Collisions: <strong>${esc(String(sroute.overlapCollisionsSuppressedCount || 0))}</strong></span>
          ` : ''}
        </div>
        ${cmem && cmem.layer1IndexSearch && Array.isArray(cmem.layer1IndexSearch.topHits) && cmem.layer1IndexSearch.topHits.length > 0 ? `
          <div class="ejii-memory-note">
            <strong>Recent Episodic Observations:</strong> ${cmem.layer1IndexSearch.topHits.slice(0, 3).map((h) => `<code>${esc(h.observationId)}</code> ${esc(h.title)}`).join(' · ')}
          </div>
        ` : ''}
      </div>
    ` : '';

    // Deep epistemic & multi-layer diagnostic blocks: grouped into an accessible progressive-disclosure section
    const deepBlocks = [
      claudeMemHtml,
      stateDiffHtml,
      epDistHtml,
      hypHtml,
      epistemicHtml,
      journeyHtml,
      commandCenterHtml,
      scenarioSimHtml,
      memoryHtml
    ].filter(Boolean);

    const deepIntelHtml = deepBlocks.length > 0 ? `
      <details class="ejii-deep-intel-details">
        <summary class="ejii-deep-intel-summary">
          <span>Deep Diagnostic &amp; Epistemic Intelligence (${deepBlocks.length} layer${deepBlocks.length === 1 ? '' : 's'})</span>
          <span class="ejii-deep-intel-summary-badges">
            ${hypEval && hypEval.primaryRootCause ? `<span class="ejii-intent-pill ejii-intent-pill-primary">${esc(hypEval.primaryRootCause.layer)} (${esc(String(hypEval.primaryRootCause.posteriorProbabilityPct ?? hypEval.primaryRootCause.confidencePct ?? 90))}%)</span>` : ''}
            ${epDist ? `<span class="ejii-intent-pill">Observed: ${esc(String((epDist.observedConditions || []).length))}</span>` : ''}
            <span>▾</span>
          </span>
        </summary>
        <div class="ejii-deep-intel-body">
          ${deepBlocks.join('')}
        </div>
      </details>
    ` : '';

    return `
      <div class="ejii-msg-row ejii-msg-assistant" data-msg-id="${esc(msg.id)}">
        <div class="ejii-msg-assistant-card">
          <div class="ejii-assistant-header">
            <span class="ejii-assistant-badge">EJII Diagnostic Assistant</span>
            ${durationLabel ? `<span class="ejii-tabular-nums">Completed in ${esc(durationLabel)}</span>` : ''}
          </div>
          ${intentContextHtml}
          <div class="ejii-answer-body">
            ${formatStructuredMarkdown(msg.content)}
          </div>
          ${findingsHtml}
          ${stepsHtml}
          ${tableHtml}
          ${deepIntelHtml}
          ${workstationActionsHtml}
          ${followUpsHtml}
          ${evidenceHtml}
        </div>
      </div>
    `;
  }

  function updateThreadDom() {
    const emptyStateEl = document.getElementById('ejiiChatEmptyState');
    const threadEl = document.getElementById('ejiiChatThread');
    const scrollEl = document.getElementById('ejiiChatScrollContainer');
    const sendBtn = document.getElementById('ejiiChatSendBtn');
    const stopBtn = document.getElementById('ejiiChatStopBtn');
    const inputEl = document.getElementById('ejiiChatInput');
    const ctxBarEl = document.getElementById('ejiiActiveSessionContextBar');

    if (ctxBarEl) {
      const activeTarget = chatState.lastContext && (chatState.lastContext.lastValidTarget || chatState.lastContext.lastTarget);
      const activePorts = chatState.lastContext && Array.isArray(chatState.lastContext.lastPorts) && chatState.lastContext.lastPorts.length > 0
        ? chatState.lastContext.lastPorts.join(', ')
        : '';
      if (activeTarget) {
        ctxBarEl.style.display = 'flex';
        ctxBarEl.innerHTML = `
          <div class="ejii-active-context-items">
            <span>Active follow-up context:</span>
            <span class="ejii-active-context-tag">Target: ${esc(activeTarget)}</span>
            ${activePorts ? `<span class="ejii-active-context-tag">Ports: ${esc(activePorts)}</span>` : ''}
            <span class="ejii-text-muted-sm">Follow-ups like &ldquo;that server&rdquo; or &ldquo;check port 443&rdquo; inherit this target automatically</span>
          </div>
          <button type="button" class="ejii-active-context-clear" onclick="window.clearEjiiChatTargetContext()" title="Clear inherited target context">
            ✕ Clear context
          </button>
        `;
      } else {
        ctxBarEl.style.display = 'none';
        ctxBarEl.innerHTML = '';
      }
    }

    const hasMessages = chatState.messages.length > 0 || chatState.inFlight;
    if (emptyStateEl) {
      emptyStateEl.style.display = hasMessages ? 'none' : 'flex';
    }

    if (threadEl) {
      let html = chatState.messages.map(renderMessageItem).join('');
      if (chatState.inFlight) {
        html += `
          <div class="ejii-msg-row ejii-msg-assistant" id="ejiiChatLiveProgress">
            <div class="ejii-live-progress-card" role="status" aria-live="polite">
              <span class="ejii-pulse-dot" aria-hidden="true"></span>
              <span id="ejiiChatProgressLabel">${esc(chatState.liveProgressStepText || 'Running live diagnostic probe…')}</span>
            </div>
          </div>
        `;
      }
      threadEl.innerHTML = html;
      threadEl.style.display = hasMessages ? 'flex' : 'none';
    }

    if (sendBtn) {
      const val = inputEl ? inputEl.value.trim() : '';
      sendBtn.disabled = chatState.inFlight || !val;
      sendBtn.style.display = chatState.inFlight ? 'none' : 'inline-flex';
    }
    if (stopBtn) {
      stopBtn.style.display = chatState.inFlight ? 'inline-flex' : 'none';
    }

    if (scrollEl && hasMessages) {
      scrollEl.scrollTop = scrollEl.scrollHeight;
    }
  }

  function startProgressStepTicker(promptText) {
    stopProgressStepTicker();
    const lower = String(promptText || '').toLowerCase();
    const isConceptualOrEpistemic =
      /\b(what is|how does|explain|difference between|can we definitively declare|sovereign fabric|truth matrix|information[- ]gain|shannon entropy|why is (?:the |my )?default gateway)\b/i.test(lower);

    let stages = [
      'Interpreting intent and session context…',
      'Executing verified diagnostic checks…',
      'Synthesizing evidence…'
    ];
    if (isConceptualOrEpistemic) {
      stages = ['Reasoning over conversation & technical knowledge…'];
    } else if (lower.includes('dns')) {
      stages = ['Querying DNS records…', 'Measuring lookup latency…'];
    } else if (lower.includes('ping') && !lower.includes('port')) {
      stages = ['Sending ICMP echo requests…', 'Measuring round-trip latency and packet loss…'];
    } else if (lower.includes('port')) {
      stages = ['Initiating TCP 3-way handshake…', 'Verifying port listener state…'];
    } else if (lower.includes('https') || lower.includes('website') || lower.includes('http')) {
      stages = ['Resolving DNS…', 'Testing TCP connection…', 'Verifying TLS & HTTP response…'];
    }

    let idx = 0;
    chatState.liveProgressStepText = stages[0];
    if (stages.length > 1) {
      chatState.progressTimer = setInterval(() => {
        idx = Math.min(stages.length - 1, idx + 1);
        chatState.liveProgressStepText = stages[idx];
        const lbl = document.getElementById('ejiiChatProgressLabel');
        if (lbl) lbl.textContent = chatState.liveProgressStepText;
      }, 650);
    }
  }

  function stopProgressStepTicker() {
    if (chatState.progressTimer) {
      clearInterval(chatState.progressTimer);
      chatState.progressTimer = null;
    }
  }

  window.sendEjiiChatMessage = async function (overridePrompt) {
    if (chatState.inFlight) return;
    const inputEl = document.getElementById('ejiiChatInput');
    const rawText = typeof overridePrompt === 'string'
      ? overridePrompt.trim()
      : (inputEl ? inputEl.value.trim() : '');

    if (!rawText) return;

    if (inputEl && typeof overridePrompt !== 'string') {
      inputEl.value = '';
      inputEl.style.height = 'auto';
    }

    const sessionId = getOrInitSessionId();
    const requestId = 'REQ-' + Date.now().toString(36).toUpperCase();
    const userMsg = {
      id: 'U-' + Date.now(),
      role: 'user',
      content: rawText,
      createdAt: new Date().toISOString()
    };

    chatState.messages.push(userMsg);
    chatState.inFlight = true;
    chatState.activeRequestId = requestId;
    chatState.abortController = new AbortController();
    startProgressStepTicker(rawText);
    updateThreadDom();

    try {
      const token = await ensureChatAuthToken();
      const headers = { 'Content-Type': 'application/json', Accept: 'text/event-stream, application/json' };
      if (token) headers.Authorization = 'Bearer ' + token;

      let res = await fetch('/api/v6/chat/stream', {
        method: 'POST',
        headers,
        credentials: 'same-origin',
        signal: chatState.abortController.signal,
        body: JSON.stringify({
          sessionId,
          requestId,
          message: rawText
        })
      });

      let envelope = null;
      const contentType = String(res.headers.get('content-type') || '').toLowerCase();

      if (res.ok && contentType.includes('text/event-stream') && res.body && typeof res.body.getReader === 'function') {
        const reader = res.body.getReader();
        const decoder = new TextDecoder('utf-8');
        let buffer = '';
        let currentEvent = 'message';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const frames = buffer.split('\n\n');
          buffer = frames.pop() || '';

          for (const frame of frames) {
            const lines = frame.split('\n');
            currentEvent = 'message';
            let dataLine = '';
            for (const line of lines) {
              if (line.startsWith('event:')) {
                currentEvent = line.slice(6).trim();
              } else if (line.startsWith('data:')) {
                dataLine += line.slice(5).trim();
              }
            }
            if (!dataLine) continue;
            try {
              const parsed = JSON.parse(dataLine);
              if (currentEvent === 'stage' && parsed.label) {
                stopProgressStepTicker();
                chatState.liveProgressStepText = parsed.label;
                const lbl = document.getElementById('ejiiChatProgressLabel');
                if (lbl) lbl.textContent = parsed.label;
              } else if (currentEvent === 'step' && (parsed.summary || parsed.label)) {
                stopProgressStepTicker();
                chatState.liveProgressStepText = parsed.summary || parsed.label;
                const lbl = document.getElementById('ejiiChatProgressLabel');
                if (lbl) lbl.textContent = chatState.liveProgressStepText;
              } else if (currentEvent === 'result') {
                envelope = parsed;
              }
            } catch (_) {}
          }
        }
      } else {
        envelope = await res.json().catch(() => ({}));
      }

      stopProgressStepTicker();

      if (res.ok && envelope && envelope.data) {
        const d = envelope.data;
        chatState.lastContext = d.sessionContext || null;
        chatState.messages.push({
          id: 'A-' + Date.now(),
          role: 'assistant',
          content: d.reply || 'Diagnostic completed.',
          createdAt: new Date().toISOString(),
          meta: {
            requestId: d.requestId,
            intent: d.intent,
            mode: d.mode,
            target: d.target,
            ports: d.ports,
            totalDurationMs: d.totalDurationMs,
            structuredAnswer: d.structuredAnswer,
            epistemicDistinctions: d.epistemicDistinctions || d.technicalEvidence?.epistemicDistinctions || null,
            competingExplanationsComparison: d.competingExplanationsComparison || null,
            steps: d.steps || [],
            findings: d.findings || [],
            connectionTable: d.connectionTable || null,
            interfaceTable: d.interfaceTable || null,
            reportMarkdown: d.reportMarkdown || null,
            memoryInsights: d.memoryInsights || null,
            hypothesisEvaluation: d.hypothesisEvaluation || null,
            epistemicReasoning: d.epistemicReasoning || null,
            problemDecomposition: d.problemDecomposition || null,
            remediationSuitability: d.remediationSuitability || null,
            cognition3StrategyPlan: d.cognition3StrategyPlan || null,
            criticalSelfCorrection: d.criticalSelfCorrection || null,
            continuousExperience: d.continuousExperience || null,
            collaborativeSynthesis: d.collaborativeSynthesis || null,
            unifiedJourney: d.unifiedJourney || null,
            commandCenterOverview: d.commandCenterOverview || null,
            scenarioSimulation: d.scenarioSimulation || null,
            suggestedFollowUps: d.suggestedFollowUps || [],
            technicalEvidence: d.technicalEvidence || null
          }
        });
        if (d.target && !String(d.target).includes('local_') && !String(d.target).includes('operational_')) {
          window.__ejiiSharedOperationalContext = {
            target: d.target,
            ports: d.ports || [3000],
            intent: d.intent,
            hypothesisEvaluation: d.hypothesisEvaluation || null,
            unifiedJourney: d.unifiedJourney || null,
            updatedAt: new Date().toISOString()
          };
        }
      } else {
        const errMsg = envelope?.error?.message || envelope?.data?.reply || `Request returned status ${res.status}.`;
        const replyText = envelope?.data?.reply ||
          `**Result:** Diagnostic request could not be completed (${errMsg}).\n\n` +
          `**Meaning:** The server rejected or could not process this target or action.\n\n` +
          `**Next step:** Check the hostname or permissions and try again.`;
        chatState.messages.push({
          id: 'A-ERR-' + Date.now(),
          role: 'assistant',
          content: replyText,
          createdAt: new Date().toISOString(),
          meta: {
            steps: [],
            findings: [{ label: 'Status', value: envelope?.error?.code || `HTTP ${res.status}`, tone: 'danger' }],
            technicalEvidence: envelope?.error || envelope
          }
        });
      }
    } catch (err) {
      stopProgressStepTicker();
      if (err && (err.name === 'AbortError' || String(err.message).includes('abort'))) {
        chatState.messages.push({
          id: 'A-CANCEL-' + Date.now(),
          role: 'assistant',
          content: '**Result:** Diagnostic check stopped.\n\n**Meaning:** You cancelled the running diagnostic probe before completion.\n\n**Next step:** Enter a new question whenever you are ready.',
          createdAt: new Date().toISOString(),
          meta: {
            steps: [],
            findings: [{ label: 'Status', value: 'Cancelled by user', tone: 'warn' }]
          }
        });
      } else {
        chatState.messages.push({
          id: 'A-NETERR-' + Date.now(),
          role: 'assistant',
          content: `**Result:** Network error while communicating with EJII backend (${err.message || 'Connection failed'}).\n\n**Meaning:** The browser could not complete the request to the local diagnostic service.\n\n**Next step:** Verify the server is running and try again.`,
          createdAt: new Date().toISOString(),
          meta: {
            steps: [],
            findings: [{ label: 'Error', value: err.message || 'Request failed', tone: 'danger' }]
          }
        });
      }
    } finally {
      chatState.inFlight = false;
      chatState.activeRequestId = null;
      chatState.abortController = null;
      updateThreadDom();
      const inp = document.getElementById('ejiiChatInput');
      if (inp) inp.focus();
    }
  };

  window.stopEjiiChatMessage = async function () {
    if (!chatState.inFlight) return;
    const sessionId = chatState.sessionId;
    const requestId = chatState.activeRequestId;
    if (chatState.abortController) {
      try {
        chatState.abortController.abort();
      } catch (_) {}
    }
    try {
      const token = (window.state && window.state.token) || localStorage.getItem('ejii_token');
      const headers = { 'Content-Type': 'application/json' };
      if (token) headers.Authorization = 'Bearer ' + token;
      await fetch('/api/v6/chat/cancel', {
        method: 'POST',
        headers,
        body: JSON.stringify({ sessionId, requestId })
      });
    } catch (_) {}
  };

  window.resetEjiiChatSession = async function () {
    if (chatState.inFlight) {
      await window.stopEjiiChatMessage();
    }
    const oldSessionId = chatState.sessionId;
    chatState.messages = [];
    chatState.lastContext = null;
    chatState.sessionId = null;
    try {
      sessionStorage.removeItem('ejii_chat_session_id');
    } catch (_) {}
    if (oldSessionId) {
      try {
        const token = (window.state && window.state.token) || localStorage.getItem('ejii_token');
        const headers = {};
        if (token) headers.Authorization = 'Bearer ' + token;
        fetch(`/api/v6/chat/session/${encodeURIComponent(oldSessionId)}`, {
          method: 'DELETE',
          headers
        }).catch(() => {});
      } catch (_) {}
    }
    getOrInitSessionId();
    updateThreadDom();
    const inp = document.getElementById('ejiiChatInput');
    if (inp) {
      inp.value = '';
      inp.focus();
    }
  };

  window.toggleChatTheme = function () {
    const html = document.documentElement;
    const current = html.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
    const next = current === 'dark' ? 'light' : 'dark';
    if (typeof window.setTheme === 'function') {
      window.setTheme(next);
    } else {
      if (next === 'dark') html.setAttribute('data-theme', 'dark');
      else html.removeAttribute('data-theme');
      try { localStorage.setItem('ejii_theme', next); } catch (_) {}
    }
  };

  window.switchToAdvancedToolView = function (viewName) {
    document.body.classList.remove('ejii-chat-first-active');
    if (typeof window.renderView === 'function') {
      window.renderView(viewName);
    }
  };

  window.refreshEjiiOperationalMemoryDrawer = async function () {
    const bodyEl = document.getElementById('ejiiChatMemoryDrawerBody');
    if (!bodyEl) return;
    bodyEl.innerHTML = '<div class="ejii-memory-drawer-empty">Loading operational intelligence briefing &amp; persistent memory…</div>';
    try {
      const token = await ensureChatAuthToken();
      const headers = {};
      if (token) headers.Authorization = 'Bearer ' + token;

      const [overviewRes, briefingRes, matrixRes] = await Promise.all([
        fetch('/api/v6/memory/overview?limit=15', { headers, credentials: 'same-origin' }),
        fetch('/api/v6/memory/intelligence-briefing', { headers, credentials: 'same-origin' }),
        fetch('/api/v6/intelligence/fleet-matrix', { headers, credentials: 'same-origin' })
      ]);

      const overviewEnv = await overviewRes.json().catch(() => null);
      const briefingEnv = await briefingRes.json().catch(() => null);
      const matrixEnv = await matrixRes.json().catch(() => null);

      const data = overviewEnv && overviewEnv.data ? overviewEnv.data : { entities: [], resolutions: [], decisions: [] };
      const briefing = briefingEnv && briefingEnv.data ? briefingEnv.data : null;
      const fleetMatrix = matrixEnv && matrixEnv.data ? matrixEnv.data : null;
      const entities = Array.isArray(data.entities) ? data.entities : [];
      const resolutions = Array.isArray(data.resolutions) ? data.resolutions : [];
      const decisions = Array.isArray(data.decisions) ? data.decisions : (briefing?.recentDecisions || []);

      const fleet = briefing && briefing.fleetSummary ? briefing.fleetSummary : {
        totalTrackedEntities: entities.length,
        averageStabilityScore: 100,
        activeRegressionCount: 0,
        predictiveRiskCount: 0
      };

      const efficacyPct = briefing?.remediationEfficacy?.overallEfficacyPct ?? 100;
      const kpiHtml = `
        <div class="ejii-memory-kpi-bar" aria-label="Fleet Operational Intelligence Summary">
          <div class="ejii-memory-kpi-item">
            <span class="ejii-memory-kpi-label">Tracked Targets</span>
            <span class="ejii-memory-kpi-value ejii-tabular-nums">${esc(String(fleet.totalTrackedEntities))}</span>
          </div>
          <div class="ejii-memory-kpi-item">
            <span class="ejii-memory-kpi-label">Avg Stability</span>
            <span class="ejii-memory-kpi-value ejii-tabular-nums">${esc(String(fleet.averageStabilityScore))}%</span>
          </div>
          <div class="ejii-memory-kpi-item">
            <span class="ejii-memory-kpi-label">Active Regressions</span>
            <span class="ejii-memory-kpi-value ejii-tabular-nums">${esc(String(fleet.activeRegressionCount || 0))}</span>
          </div>
          <div class="ejii-memory-kpi-item">
            <span class="ejii-memory-kpi-label">Learned Playbooks</span>
            <span class="ejii-memory-kpi-value ejii-tabular-nums">${esc(String(resolutions.length))} · ${esc(String(efficacyPct))}% Efficacy</span>
          </div>
        </div>
      `;

      const topPriority = fleetMatrix?.highestPriorityInvestigation || null;
      const sharedRisks = Array.isArray(fleetMatrix?.sharedDependencyRisks) ? fleetMatrix.sharedDependencyRisks : [];
      const atRiskNext = Array.isArray(fleetMatrix?.servicesAtRiskNext) ? fleetMatrix.servicesAtRiskNext : [];

      const priorityHtml = topPriority ? `
        <div class="ejii-memory-res-section">
          <div class="ejii-memory-res-heading">Fleet Priority Triage &amp; Shared Dependency Matrix</div>
          <div class="ejii-memory-entity-row">
            <div class="ejii-memory-entity-main">
              <strong>#1 Priority Investigation: <code>${esc(topPriority.target)}</code> (Priority Score ${esc(String(topPriority.priorityScore))}/100)</strong>
              <button
                type="button"
                class="ejii-header-btn"
                style="padding:2px 8px;font-size:11px;"
                onclick="window.toggleEjiiOperationalMemoryDrawer(); window.sendEjiiChatMessage(${esc(JSON.stringify(topPriority.recommendedNextStep))})"
              >
                Investigate Now
              </button>
            </div>
            <div class="ejii-memory-entity-sub">${esc(topPriority.reason)}</div>
          </div>
          ${sharedRisks.map((sr) => `
            <div class="ejii-memory-entity-row">
              <div class="ejii-memory-entity-main">
                <strong>Shared Dependency Risk: <code>${esc(sr.dependencyLabel)}</code></strong>
                <span class="ejii-tabular-nums">${esc(sr.severity)}</span>
              </div>
              <div class="ejii-memory-entity-sub">${esc(sr.explanation)}</div>
            </div>
          `).join('')}
          ${atRiskNext.slice(0, 3).map((ar) => `
            <div class="ejii-memory-entity-row">
              <div class="ejii-memory-entity-main">
                <strong>Service At Risk Next: <code>${esc(ar.serviceLabel)}</code></strong>
                <span class="ejii-tabular-nums">${esc(ar.predictedPropagationRisk)}</span>
              </div>
              <div class="ejii-memory-entity-sub">${esc(ar.reason)}</div>
            </div>
          `).join('')}
        </div>
      ` : '';

      const regressions = Array.isArray(briefing?.activeRegressions) ? briefing.activeRegressions : [];
      const risks = Array.isArray(briefing?.predictiveRisks) ? briefing.predictiveRisks : [];
      const alertsHtml = (regressions.length > 0 || risks.length > 0) ? `
        <div class="ejii-memory-res-section">
          <div class="ejii-memory-res-heading">Active Regressions &amp; Predictive Latency Drift (${regressions.length + risks.length})</div>
          ${regressions.map((reg) => `
            <div class="ejii-memory-entity-row">
              <div class="ejii-memory-entity-main">
                <strong><code>${esc(reg.target)}</code> · ${esc(reg.type)}</strong>
                <span class="ejii-tabular-nums">Stability: ${esc(String(reg.stabilityScore))}%</span>
              </div>
              <div class="ejii-memory-entity-sub">${esc(reg.detail)}</div>
            </div>
          `).join('')}
          ${risks.map((rk) => `
            <div class="ejii-memory-entity-row">
              <div class="ejii-memory-entity-main">
                <strong><code>${esc(rk.target)}</code> · ${esc(rk.type)}</strong>
                <span class="ejii-tabular-nums">${esc(rk.severity)}</span>
              </div>
              <div class="ejii-memory-entity-sub">${esc(rk.detail)}</div>
            </div>
          `).join('')}
        </div>
      ` : '';

      const entityRows = entities.length > 0 ? `
        <div class="ejii-memory-res-section">
          <div class="ejii-memory-res-heading">Tracked Entity Baselines (${entities.length})</div>
          ${entities.map((e) => `
            <div class="ejii-memory-entity-row">
              <div class="ejii-memory-entity-main">
                <div>
                  <strong><code>${esc(e.target)}</code></strong>
                  <span class="ejii-tabular-nums" style="margin-left:6px;color:var(--chat-text-secondary);">${esc(String(e.observationCount))} checks · Stability ${esc(String(e.stabilityScore ?? 100))}% · ${esc(e.lastStatus || 'OK')}${typeof e.ewmaRttMs === 'number' ? ` · EWMA ${esc(String(e.ewmaRttMs))} ms` : (typeof e.avgRttMs === 'number' ? ` · avg ${esc(String(e.avgRttMs))} ms` : '')}</span>
                </div>
                <button
                  type="button"
                  class="ejii-header-btn"
                  style="padding:2px 8px;font-size:11px;"
                  onclick="window.toggleEjiiOperationalMemoryDrawer(); window.sendEjiiChatMessage(${esc(JSON.stringify(`Investigate why ${e.target} is failing`))})"
                >
                  Re-verify
                </button>
              </div>
              <div class="ejii-memory-entity-sub">
                IPs: [${esc((e.resolvedIps || []).join(', ') || 'none')}] · Open ports: [${esc((e.openPorts || []).join(', ') || 'none')}] · Closed: [${esc((e.closedPorts || []).join(', ') || 'none')}]
              </div>
            </div>
          `).join('')}
        </div>
      ` : '<div class="ejii-memory-drawer-empty">No cross-session entity baselines recorded yet. Run a diagnostic probe to populate operational memory.</div>';

      const resRows = `
        <div class="ejii-memory-res-section">
          <div class="ejii-memory-res-heading">Verified Remediations &amp; Learned Playbooks (${resolutions.length})</div>
          ${resolutions.map((r) => `
            <div class="ejii-memory-entity-row">
              <div class="ejii-memory-entity-main">
                <strong><code>${esc(r.symptomSignature)}</code> ${r.targetKey && r.targetKey !== '*' ? `on <code>${esc(r.targetKey)}</code>` : ''}</strong>
                <span class="ejii-tabular-nums" style="font-size:11px;color:var(--chat-text-muted);">Verified ${esc(String(r.successCount || 1))}x</span>
              </div>
              <div class="ejii-memory-entity-sub">${esc(r.rootCause)} → ${esc(r.resolutionSteps)}</div>
            </div>
          `).join('')}
          <form class="ejii-playbook-form" id="ejiiNewPlaybookForm" onsubmit="window.submitNewOperationalPlaybook(event)">
            <div class="ejii-memory-res-heading" style="margin-bottom:4px;">Record New Verified Incident Playbook</div>
            <div class="ejii-playbook-form-grid">
              <input type="text" id="pbTargetInput" class="ejii-playbook-input" placeholder="Target host (e.g. localhost or *)" aria-label="Playbook target host" />
              <input type="text" id="pbSignatureInput" class="ejii-playbook-input" placeholder="Symptom signature (e.g. TCP_PORT_3000_CLOSED)" required aria-label="Symptom signature" />
              <input type="text" id="pbRootCauseInput" class="ejii-playbook-input" placeholder="Verified root cause" required aria-label="Verified root cause" />
              <input type="text" id="pbStepsInput" class="ejii-playbook-input" placeholder="Verified resolution steps" required aria-label="Verified resolution steps" />
            </div>
            <div style="display:flex;align-items:center;justify-content:space-between;margin-top:6px;">
              <span id="pbSubmitStatus" style="font-size:11.5px;color:var(--chat-text-secondary);"></span>
              <button type="submit" id="btnSubmitPlaybook" class="ejii-header-btn" style="font-weight:600;">Save Playbook to Memory</button>
            </div>
          </form>
        </div>
      `;

      const decisionRows = decisions.length > 0 ? `
        <div class="ejii-memory-res-section">
          <div class="ejii-memory-res-heading">Operational Decision &amp; Outcome Ledger (${decisions.length})</div>
          ${decisions.slice(0, 5).map((d) => `
            <div class="ejii-memory-entity-row">
              <div class="ejii-memory-entity-main">
                <strong><code>${esc(d.actionId)}</code> on <code>${esc(d.targetKey)}</code></strong>
                <span class="ejii-tabular-nums" style="font-size:11px;">${esc(d.outcomeStatus)} · ${esc(d.approvedBy)} (${esc(d.role)})</span>
              </div>
              <div class="ejii-memory-entity-sub">${esc(d.rationale)}</div>
            </div>
          `).join('')}
        </div>
      ` : '';

      bodyEl.innerHTML = kpiHtml + priorityHtml + alertsHtml + entityRows + resRows + decisionRows;
    } catch (_) {
      bodyEl.innerHTML = '<div class="ejii-memory-drawer-empty">Unable to load operational memory snapshot.</div>';
    }
  };

  window.submitNewOperationalPlaybook = async function (event) {
    if (event && typeof event.preventDefault === 'function') event.preventDefault();
    const targetEl = document.getElementById('pbTargetInput');
    const sigEl = document.getElementById('pbSignatureInput');
    const rcEl = document.getElementById('pbRootCauseInput');
    const stepsEl = document.getElementById('pbStepsInput');
    const statusEl = document.getElementById('pbSubmitStatus');
    const symptomSignature = sigEl ? sigEl.value.trim() : '';
    const rootCause = rcEl ? rcEl.value.trim() : '';
    const resolutionSteps = stepsEl ? stepsEl.value.trim() : '';
    const target = targetEl && targetEl.value.trim() ? targetEl.value.trim() : '*';
    if (!symptomSignature || !rootCause || !resolutionSteps) return;

    if (statusEl) statusEl.textContent = 'Saving playbook…';
    try {
      const token = await ensureChatAuthToken();
      const headers = { 'Content-Type': 'application/json' };
      if (token) headers.Authorization = 'Bearer ' + token;
      const res = await fetch('/api/v6/memory/resolutions', {
        method: 'POST',
        headers,
        credentials: 'same-origin',
        body: JSON.stringify({ target, symptomSignature, rootCause, resolutionSteps })
      });
      if (res.ok) {
        if (statusEl) statusEl.textContent = '✓ Playbook saved to persistent memory';
        await window.refreshEjiiOperationalMemoryDrawer();
      } else {
        const err = await res.json().catch(() => ({}));
        if (statusEl) statusEl.textContent = err?.error?.message || 'Could not save playbook';
      }
    } catch (e) {
      if (statusEl) statusEl.textContent = 'Error saving playbook';
    }
  };

  window.toggleEjiiOperationalMemoryDrawer = async function () {
    const drawer = document.getElementById('ejiiChatMemoryDrawer');
    if (!drawer) return;
    const isHidden = drawer.style.display === 'none' || !drawer.style.display;
    if (!isHidden) {
      drawer.style.display = 'none';
      return;
    }
    drawer.style.display = 'block';
    await window.refreshEjiiOperationalMemoryDrawer();
  };

  window.renderChatWorkspaceView = function () {
    const main = document.getElementById('mainContent');
    if (!main) return;

    document.body.classList.add('ejii-chat-first-active');
    getOrInitSessionId();

    const activePinned = (window.EJIIInvestigationPinboard && typeof window.EJIIInvestigationPinboard.getPinned === 'function')
      ? window.EJIIInvestigationPinboard.getPinned()
      : null;
    const sitTarget = (activePinned && !activePinned.incompleteContext && activePinned.target)
      || (window.EJIISituationalMemory && (window.EJIISituationalMemory.activeTargetIp || window.EJIISituationalMemory.activeTarget))
      || (chatState.lastContext && chatState.lastContext.lastTarget)
      || null;
    const sitHyp = (window.EJIISituationalMemory && window.EJIISituationalMemory.activeHypothesis) || null;
    const sitRunbook = (window.EJIISituationalMemory && window.EJIISituationalMemory.activeRunbookId) || 'RB-04';

    main.innerHTML = `
      <div class="ejii-chat-shell" id="ejiiChatWorkspace">
        <!-- Region 1: Calm Workspace Header -->
        <header class="ejii-minimal-header" id="ejiiMinimalHeader">
          <div class="ejii-minimal-brand">
            <span class="ejii-minimal-mark">AI Assistant</span>
            <span class="ejii-minimal-title">Conversational Infrastructure &amp; Protocol Investigator</span>
          </div>

          <div class="ejii-minimal-header-right">
            <div class="ejii-connection-indicator" id="ejiiChatConnectionStatus" title="Connected to local diagnostic engine">
              <span class="ejii-connection-dot" aria-hidden="true"></span>
              <span>Live Probes Ready</span>
            </div>

            <button type="button" class="ejii-header-btn" id="btnChatMemoryDrawer" onclick="window.toggleEjiiOperationalMemoryDrawer()" title="Inspect persistent cross-session operational memory and baselines">
              Memory
            </button>

            <button type="button" class="ejii-header-btn" id="btnChatNewConversation" onclick="window.resetEjiiChatSession()" title="Start a new diagnostic conversation">
              New chat
            </button>

            <details class="ejii-tools-dropdown" id="ejiiAdvancedToolsDropdown">
              <summary class="ejii-header-btn" title="Open specialist network and host views">
                Workstations ▾
              </summary>
              <div class="ejii-tools-menu" role="menu">
                <button type="button" class="ejii-tools-menu-item" onclick="window.switchToAdvancedToolView('overview')">
                  <span>Workspace Overview</span><span>→</span>
                </button>
                <button type="button" class="ejii-tools-menu-item" onclick="window.switchToAdvancedToolView('ai-operator')">
                  <span>AI Operator Console</span><span>→</span>
                </button>
                <button type="button" class="ejii-tools-menu-item" onclick="window.switchToAdvancedToolView('topology')">
                  <span>Network Overview</span><span>→</span>
                </button>
                <button type="button" class="ejii-tools-menu-item" onclick="window.switchToAdvancedToolView('noc-dashboard')">
                  <span>NOC Dual-Pane Center</span><span>→</span>
                </button>
                <button type="button" class="ejii-tools-menu-item" onclick="window.switchToAdvancedToolView('packet-sniffer')">
                  <span>Packet Analysis</span><span>→</span>
                </button>
                <button type="button" class="ejii-tools-menu-item" onclick="window.switchToAdvancedToolView('ultra-ip-scanner')">
                  <span>IP &amp; Asset Discovery</span><span>→</span>
                </button>
                <button type="button" class="ejii-tools-menu-item" onclick="window.switchToAdvancedToolView('core-diagnostics')">
                  <span>Diagnostics &amp; Recovery</span><span>→</span>
                </button>
                <button type="button" class="ejii-tools-menu-item" onclick="window.switchToAdvancedToolView('pc-automation')">
                  <span>Host Automation</span><span>→</span>
                </button>
                <button type="button" class="ejii-tools-menu-item" onclick="window.switchToAdvancedToolView('learning-center')">
                  <span>Learning Center</span><span>→</span>
                </button>
              </div>
            </details>
          </div>
        </header>

        <!-- Collapsible Cross-Session Operational Memory Drawer -->
        <section id="ejiiChatMemoryDrawer" class="ejii-memory-drawer" style="display:none" aria-label="Persistent Operational Memory">
          <div class="ejii-memory-drawer-header">
            <span>Persistent Cross-Session Operational Memory &amp; Baselines</span>
            <button type="button" class="ejii-header-btn" onclick="window.toggleEjiiOperationalMemoryDrawer()">Close</button>
          </div>
          <div id="ejiiChatMemoryDrawerBody" class="ejii-memory-drawer-body"></div>
        </section>

        <!-- Contextual Situational Memory Bar (Only visible when an active target is pinned or selected) -->
        <div id="ejiiChatSituationalRibbon" style="display:${sitTarget ? 'flex' : 'none'};align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;padding:6px 20px;background:var(--bg-surface-subtle, #F9F8F5);border-bottom:1px solid var(--border-default, #E6E3DB);font-size:11.5px;color:var(--text-secondary, #666B66);">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
            <span style="font-weight:600;color:var(--accent-primary, #3A6653);">Active Target Context:</span>
            <code id="chatSitMemTarget" style="font-family:var(--font-mono);color:var(--text-primary, #1F2421);">${esc(sitTarget || 'None selected')}</code>
            ${sitHyp ? `<span>·</span><span id="chatSitMemHyp">${esc(sitHyp)}</span>` : ''}
          </div>
          <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
            ${sitTarget ? `
              <button type="button" class="ejii-header-btn" onclick="window.launchRunbookWizardModal && window.launchRunbookWizardModal('${esc(sitRunbook)}', '${esc(sitTarget)}')">
                Runbook (${esc(sitRunbook)})
              </button>
              <button type="button" class="ejii-header-btn" onclick="window.openAiBrainDrawer && window.openAiBrainDrawer('${esc(sitTarget)}')">
                7-Engine Analysis
              </button>
            ` : ''}
          </div>
        </div>

        <!-- Region 2: Primary Conversation Area -->
        <div class="ejii-chat-scroll-container" id="ejiiChatScrollContainer">
          <div class="ejii-chat-column">
            <!-- Empty State (Disappears after first message) -->
            <div class="ejii-chat-empty-state" id="ejiiChatEmptyState">
              <h1 class="ejii-empty-heading">What would you like me to investigate?</h1>
              <p class="ejii-empty-subtitle">
                Ask in plain language to check DNS, ping a host, test TCP ports, verify HTTPS, or investigate why a service is unreachable.
              </p>
              <div class="ejii-nl-guidance-banner" role="note" aria-label="Natural language input guidance">
                <span class="ejii-nl-guidance-badge">Natural Language Ready</span>
                <span>No strict command syntax required — everyday questions, shorthand (<code>check dns example.com</code>), raw error logs, and follow-ups (<code>that server</code>, <code>check port 443 on same host</code>) work naturally.</span>
              </div>
              <div class="ejii-starter-prompts" id="ejiiStarterPrompts">
                ${STARTER_PROMPTS.map((prompt, i) => `
                  <button
                    type="button"
                    class="ejii-starter-prompt-btn"
                    id="ejiiStarterPrompt${i + 1}"
                    onclick="window.sendEjiiChatMessage(${esc(JSON.stringify(prompt))})"
                  >
                    <span class="ejii-starter-prompt-left">
                      <span class="ejii-starter-protocol-tag">${esc(STARTER_PROMPT_TAGS[i] || 'Probe')}</span>
                      <span>${esc(prompt)}</span>
                    </span>
                    <span class="ejii-starter-arrow" aria-hidden="true">→</span>
                  </button>
                `).join('')}
              </div>
            </div>

            <!-- Active Conversation Thread -->
            <div class="ejii-chat-thread" id="ejiiChatThread" style="display:none" aria-live="polite"></div>
          </div>
        </div>

        <!-- Region 3: Bottom Message Composer -->
        <form
          class="ejii-composer-region"
          id="ejiiChatComposerForm"
          onsubmit="event.preventDefault(); window.sendEjiiChatMessage();"
        >
          <div id="ejiiActiveSessionContextBar" class="ejii-active-context-bar" style="display:none" aria-live="polite"></div>
          <div class="ejii-composer-box">
            <textarea
              id="ejiiChatInput"
              class="ejii-composer-textarea"
              rows="1"
              placeholder="Ask in plain English — e.g. 'Check whether port 3000 is open on localhost', 'dns example.com', or paste an error log..."
              aria-label="Ask EJII to diagnose a host, check DNS, test a port, or investigate a network problem"
            ></textarea>
            <div class="ejii-composer-actions">
              <button type="submit" id="ejiiChatSendBtn" class="ejii-btn-send" disabled>
                Send
              </button>
              <button
                type="button"
                id="ejiiChatStopBtn"
                class="ejii-btn-stop"
                style="display:none"
                onclick="window.stopEjiiChatMessage()"
              >
                Stop
              </button>
            </div>
          </div>
          <div class="ejii-composer-footer-hints">
            <span><span class="ejii-composer-kbd">Enter</span> to send · <span class="ejii-composer-kbd">Shift+Enter</span> for new line · <span class="ejii-composer-kbd">/</span> to focus · <span class="ejii-composer-kbd">Ctrl+K</span> Command Palette</span>
            <span>Backed by live OS &amp; network protocol probes · Never alters your input</span>
          </div>
        </form>
      </div>
    `;

    const inputEl = document.getElementById('ejiiChatInput');
    const sendBtn = document.getElementById('ejiiChatSendBtn');
    if (inputEl) {
      inputEl.addEventListener('input', function () {
        this.style.height = 'auto';
        this.style.height = Math.min(160, this.scrollHeight) + 'px';
        if (sendBtn && !chatState.inFlight) {
          sendBtn.disabled = !this.value.trim();
        }
      });

      inputEl.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' && !e.shiftKey) {
          e.preventDefault();
          if (!chatState.inFlight && this.value.trim()) {
            window.sendEjiiChatMessage();
          }
        }
      });

      inputEl.focus();
    }

    if (!window._ejiiChatSlashShortcutBound) {
      window._ejiiChatSlashShortcutBound = true;
      document.addEventListener('keydown', function (e) {
        if (e.key !== '/' || e.ctrlKey || e.metaKey || e.altKey) return;
        const activeTag = document.activeElement && document.activeElement.tagName
          ? document.activeElement.tagName.toUpperCase()
          : '';
        if (activeTag === 'INPUT' || activeTag === 'TEXTAREA' || activeTag === 'SELECT' || (document.activeElement && document.activeElement.isContentEditable)) {
          return;
        }
        const chatInp = document.getElementById('ejiiChatInput');
        if (chatInp && chatInp.offsetParent !== null) {
          e.preventDefault();
          chatInp.focus();
        }
      });
    }

    updateThreadDom();
    restoreSessionHistoryIfNeeded();
  };
})();
