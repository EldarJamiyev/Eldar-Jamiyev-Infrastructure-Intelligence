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

  const esc = (s) => (typeof window.escapeHtml === 'function' ? window.escapeHtml(s) : String(s ?? ''));

  const STARTER_PROMPTS = [
    'Check whether port 3000 is open on localhost',
    'Check DNS for example.com',
    'Investigate why 127.0.0.1:8080 is not responding'
  ];

  const chatState = {
    sessionId: null,
    messages: [],
    inFlight: false,
    activeRequestId: null,
    abortController: null,
    liveProgressStepText: '',
    progressTimer: null,
    lastContext: null
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

  function formatStructuredMarkdown(text) {
    const raw = String(text || '');
    const paragraphs = raw.split(/\n\n+/).filter(Boolean);
    return paragraphs.map((p) => {
      const trimmed = p.trim();
      const isCallout = trimmed.startsWith('> ');
      const contentText = isCallout ? trimmed.slice(2) : trimmed;
      let safe = esc(contentText);
      // Format **bold**
      safe = safe.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
      // Format *italic*
      safe = safe.replace(/\*([^*]+)\*/g, '<em>$1</em>');
      // Format `code`
      safe = safe.replace(/`([^`]+)`/g, '<code>$1</code>');
      // Format newline inside paragraph
      safe = safe.replace(/\n/g, '<br>');
      if (isCallout) {
        return `<div class="ejii-answer-section" style="border-left: 3px solid #D97706; background: rgba(217, 119, 6, 0.08); padding: 8px 12px; border-radius: 6px; font-size: 13.5px; margin-bottom: 12px;">${safe}</div>`;
      }
      return `<p class="ejii-answer-section">${safe}</p>`;
    }).join('');
  }

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

    const reportBtnHtml = meta.reportMarkdown ? `
      <div style="margin-top: 10px;">
        <button
          type="button"
          class="ejii-header-btn"
          onclick="navigator.clipboard && navigator.clipboard.writeText(${esc(JSON.stringify(meta.reportMarkdown))}); this.textContent = '✓ Report Copied';"
        >
          Copy Incident Report
        </button>
      </div>
    ` : '';

    const evidenceHtml = (evidence && (hasDiagnosticActivity || findings.length > 0)) ? `
      <details class="ejii-evidence-details">
        <summary>Technical details &amp; raw probe output</summary>
        <pre class="ejii-evidence-pre">${esc(JSON.stringify(evidence, null, 2))}</pre>
      </details>
    ` : '';

    return `
      <div class="ejii-msg-row ejii-msg-assistant" data-msg-id="${esc(msg.id)}">
        <div class="ejii-msg-assistant-card">
          <div class="ejii-assistant-header">
            <span class="ejii-assistant-badge">EJII Diagnostic Assistant</span>
            ${durationLabel ? `<span>Completed in ${esc(durationLabel)}</span>` : ''}
          </div>
          ${stepsHtml}
          ${findingsHtml}
          ${tableHtml}
          <div class="ejii-answer-body">
            ${formatStructuredMarkdown(msg.content)}
          </div>
          ${reportBtnHtml}
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
    let stages = [
      'Validating target and checking DNS…',
      'Testing live socket reachability…',
      'Correlating evidence…'
    ];
    if (lower.includes('dns')) {
      stages = ['Querying DNS records…', 'Measuring lookup latency…'];
    } else if (lower.includes('ping')) {
      stages = ['Sending ICMP echo requests…', 'Measuring round-trip latency and packet loss…'];
    } else if (lower.includes('port')) {
      stages = ['Initiating TCP 3-way handshake…', 'Verifying port listener state…'];
    } else if (lower.includes('https') || lower.includes('website') || lower.includes('http')) {
      stages = ['Resolving DNS…', 'Testing TCP connection…', 'Verifying TLS & HTTP response…'];
    }

    let idx = 0;
    chatState.liveProgressStepText = stages[0];
    chatState.progressTimer = setInterval(() => {
      idx = Math.min(stages.length - 1, idx + 1);
      chatState.liveProgressStepText = stages[idx];
      const lbl = document.getElementById('ejiiChatProgressLabel');
      if (lbl) lbl.textContent = chatState.liveProgressStepText;
    }, 650);
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
      const token = (window.state && window.state.token) || localStorage.getItem('ejii_token');
      const headers = { 'Content-Type': 'application/json' };
      if (token) headers.Authorization = 'Bearer ' + token;

      const res = await fetch('/api/v6/chat/message', {
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

      const envelope = await res.json().catch(() => ({}));
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
            steps: d.steps || [],
            findings: d.findings || [],
            connectionTable: d.connectionTable || null,
            interfaceTable: d.interfaceTable || null,
            reportMarkdown: d.reportMarkdown || null,
            technicalEvidence: d.technicalEvidence || null
          }
        });
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
    ensureBackToChatTopbarButton();
    if (typeof window.renderView === 'function') {
      window.renderView(viewName);
    }
  };

  function ensureBackToChatTopbarButton() {
    const topbarLeft = document.querySelector('.topbar-left');
    if (!topbarLeft || document.getElementById('btnBackToChatWorkspace')) return;
    const btn = document.createElement('button');
    btn.id = 'btnBackToChatWorkspace';
    btn.type = 'button';
    btn.className = 'topbar-action';
    btn.style.marginRight = '10px';
    btn.style.fontWeight = '600';
    btn.innerHTML = '← Back to Chat';
    btn.onclick = function () {
      window.renderView('chat');
    };
    topbarLeft.insertBefore(btn, topbarLeft.firstChild);
  }

  window.renderChatWorkspaceView = function () {
    const main = document.getElementById('mainContent');
    if (!main) return;

    document.body.classList.add('ejii-chat-first-active');
    getOrInitSessionId();

    const username = (window.state && window.state.user && (window.state.user.username || window.state.user.fullName)) || 'operator';
    const userRole = (window.state && window.state.user && window.state.user.role) || 'ADMIN';

    main.innerHTML = `
      <div class="ejii-chat-shell" id="ejiiChatWorkspace">
        <!-- Region 1: Compact Top Header -->
        <header class="ejii-minimal-header" id="ejiiMinimalHeader">
          <div class="ejii-minimal-brand">
            <span class="ejii-minimal-mark">EJII</span>
            <span class="ejii-minimal-title">Eldar Jamiyev's Infrastructure Intelligence</span>
          </div>

          <div class="ejii-minimal-header-right">
            <div class="ejii-connection-indicator" id="ejiiChatConnectionStatus" title="Connected to local diagnostic engine">
              <span class="ejii-connection-dot" aria-hidden="true"></span>
              <span>Connected</span>
            </div>

            <button type="button" class="ejii-header-btn" id="btnChatNewConversation" onclick="window.resetEjiiChatSession()" title="Start a new diagnostic conversation">
              New chat
            </button>

            <details class="ejii-tools-dropdown" id="ejiiAdvancedToolsDropdown">
              <summary class="ejii-header-btn" title="Open specialist network and host views">
                Tools ▾
              </summary>
              <div class="ejii-tools-menu" role="menu">
                <button type="button" class="ejii-tools-menu-item" onclick="window.switchToAdvancedToolView('topology')">
                  <span>Network Topology</span><span>→</span>
                </button>
                <button type="button" class="ejii-tools-menu-item" onclick="window.switchToAdvancedToolView('packet-sniffer')">
                  <span>Packet Analysis</span><span>→</span>
                </button>
                <button type="button" class="ejii-tools-menu-item" onclick="window.switchToAdvancedToolView('ultra-ip-scanner')">
                  <span>IP &amp; Asset Scanner</span><span>→</span>
                </button>
                <button type="button" class="ejii-tools-menu-item" onclick="window.switchToAdvancedToolView('core-diagnostics')">
                  <span>Diagnostics Workbench</span><span>→</span>
                </button>
                <button type="button" class="ejii-tools-menu-item" onclick="window.switchToAdvancedToolView('pc-automation')">
                  <span>Host Automation</span><span>→</span>
                </button>
                <button type="button" class="ejii-tools-menu-item" onclick="window.switchToAdvancedToolView('ai-operator')">
                  <span>Autonomous Operator Console</span><span>→</span>
                </button>
                <button type="button" class="ejii-tools-menu-item" onclick="window.switchToAdvancedToolView('learning-center')">
                  <span>Learning Center</span><span>→</span>
                </button>
              </div>
            </details>

            <button type="button" class="ejii-header-btn" id="btnChatThemeToggle" onclick="window.toggleChatTheme()" title="Toggle light or dark theme" aria-label="Toggle theme">
              ◐
            </button>

            <span class="ejii-connection-indicator" id="ejiiChatUserBadge" style="padding:0 4px;">
              ${esc(username)} (${esc(userRole)})
            </span>

            <button type="button" class="ejii-header-btn" id="btnChatSignOut" onclick="document.getElementById('btnLogout') && document.getElementById('btnLogout').click()" title="Sign out">
              Sign out
            </button>
          </div>
        </header>

        <!-- Region 2: Primary Conversation Area -->
        <div class="ejii-chat-scroll-container" id="ejiiChatScrollContainer">
          <div class="ejii-chat-column">
            <!-- Empty State (Disappears after first message) -->
            <div class="ejii-chat-empty-state" id="ejiiChatEmptyState">
              <h1 class="ejii-empty-heading">What would you like me to investigate?</h1>
              <p class="ejii-empty-subtitle">
                Ask in plain language to check DNS, ping a host, test TCP ports, verify HTTPS, or investigate why a service is unreachable.
              </p>
              <div class="ejii-starter-prompts" id="ejiiStarterPrompts">
                ${STARTER_PROMPTS.map((prompt, i) => `
                  <button
                    type="button"
                    class="ejii-starter-prompt-btn"
                    id="ejiiStarterPrompt${i + 1}"
                    onclick="window.sendEjiiChatMessage(${esc(JSON.stringify(prompt))})"
                  >
                    <span>${esc(prompt)}</span>
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
          <div class="ejii-composer-box">
            <textarea
              id="ejiiChatInput"
              class="ejii-composer-textarea"
              rows="1"
              placeholder="Ask EJII to diagnose a host, check DNS, test a port, or investigate a network problem..."
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
          <div class="ejii-composer-hint">
            Press Enter to send · Shift+Enter for a new line · Backed by live host &amp; network probes
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

    updateThreadDom();
  };
})();
