window.escapeHtml = function(str) {
  return String(str === null || str === undefined ? '' : str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
};
window.escapeAttr = function(str) {
  return String(str === null || str === undefined ? '' : str)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
};
var escapeHtml = window.escapeHtml;
var escapeAttr = window.escapeAttr;

// State Management
const state = {
  token: localStorage.getItem('ejii_token') || null,
  user: null,
  currentView: 'noc',
  nodes: [],
  edges: [],
  ws: null
};

window.state = state;
window.api = api;
window.renderView = renderView;

// Universal Cross-Pillar Target Context & Investigation Store
window.EJIIStore = window.EJIIStore || {};
window.EJIIStore.activeInvestigationContext = null;

window.pivotToTargetContext = function(pivotParams = {}) {
  const { targetIp, hostname, macAddress, pid, targetView, port } = pivotParams;

  window.EJIIStore.activeInvestigationContext = {
    targetIp: targetIp || null,
    hostname: hostname || null,
    macAddress: macAddress || null,
    pid: pid || null,
    port: port || 443,
    timestamp: new Date().toISOString()
  };

  const viewAliases = {
    '1': 'topology',
    'noc': 'topology',
    'topology': 'topology',
    '2': 'packet-sniffer',
    'sniffer': 'packet-sniffer',
    'packet-sniffer': 'packet-sniffer',
    '3': 'ultra-ip-scanner',
    'scanner': 'ultra-ip-scanner',
    'ultra-ip-scanner': 'ultra-ip-scanner',
    '4': 'pc-automation',
    'automation': 'pc-automation',
    'pc-automation': 'pc-automation',
    '5': 'core-diagnostics',
    'diagnostics': 'core-diagnostics',
    'core-diagnostics': 'core-diagnostics'
  };

  const destination = viewAliases[targetView] || 'topology';
  if (typeof window.renderView === 'function') {
    window.renderView(destination);
  }

  window.dispatchEvent(new CustomEvent('ejii:pivot-context', {
    detail: window.EJIIStore.activeInvestigationContext
  }));
};


/**
 * Local Time Formatters
 */
window.formatLocalTime = function(isoStr, includeMs = true) {
  if (!isoStr) return '';
  const d = new Date(isoStr);
  if (isNaN(d.getTime())) return isoStr;
  const pad = (n) => String(n).padStart(2, '0');
  const padMs = (n) => String(n).padStart(3, '0');
  const time = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  return includeMs ? `${time}.${padMs(d.getMilliseconds())}` : time;
};

window.formatLocalDateTime = function(isoStr) {
  if (!isoStr) return '';
  const d = new Date(isoStr);
  if (isNaN(d.getTime())) return isoStr;
  const pad = (n) => String(n).padStart(2, '0');
  const padMs = (n) => String(n).padStart(3, '0');
  return `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${padMs(d.getMilliseconds())}`;
};

/**
 * Universal HTML Escape utility
 */
// window.escapeHtml and window.escapeAttr already declared at top of file


/**
 * Universal Authenticated API Fetcher
 */
async function api(endpoint, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {})
  };

  if (state.token) {
    headers['Authorization'] = `Bearer ${state.token}`;
  }

  try {
    const res = await fetch(endpoint, { ...options, headers });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || `HTTP ${res.status}: ${res.statusText}`);
    }
    return data;
  } catch (err) {
    console.error(`[API Error] ${endpoint}:`, err);
    throw err;
  }
}

let wsReconnectTimer = null;

/**
 * Initialize WebSocket Live Connection
 */
function initWebSocket() {
  if (wsReconnectTimer) {
    clearTimeout(wsReconnectTimer);
    wsReconnectTimer = null;
  }

  if (state.ws) {
    try {
      state.ws.onclose = null; // Prevent reconnect storm on intentional close
      state.ws.close();
    } catch (e) {}
    state.ws = null;
  }

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/`;
  const subprotocols = state.token ? ['token', state.token] : undefined;
  
  try {
    state.ws = subprotocols ? new WebSocket(wsUrl, subprotocols) : new WebSocket(wsUrl);

    state.ws.onopen = () => {
      const el = document.getElementById('wsStatusText');
      if (el) el.textContent = 'Live Wire Connected';
      const dot = document.querySelector('.status-dot');
      if (dot) dot.style.backgroundColor = '#10b981';

      // Request live wire frame streaming if authenticated
      if (state.token && state.ws && state.ws.readyState === WebSocket.OPEN) {
        state.ws.send(JSON.stringify({ type: 'START_PACKET_STREAM' }));
      }
    };

    state.ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (!msg || typeof msg !== 'object') return;

        if (msg.type === 'PACKET_STREAM_FRAME' && typeof window.handleLivePacketFrame === 'function') {
          const frame = msg.payload || msg.frame;
          if (frame?.counters && typeof window.handlePacketStats === 'function') {
            window.handlePacketStats(frame.counters);
          }
          window.handleLivePacketFrame(frame);
        } else if (msg.type === 'PACKET_STATS' && typeof window.handlePacketStats === 'function') {
          window.handlePacketStats(msg.payload || msg);
        } else if (msg.type === 'CAPTURE_STATUS' && typeof window.handleCaptureStatus === 'function') {
          window.handleCaptureStatus(msg.payload || msg);
        } else if (msg.type === 'FLOW_STREAM_UPDATE' && typeof window.handleLiveFlowUpdate === 'function') {
          window.handleLiveFlowUpdate(msg.payload?.flows || msg.flows);
        } else if (msg.type === 'NETWORK_ANOMALY') {
          // Anomaly Flash: pulse orange/red on topology canvas
          if (typeof window.flashTopologyAnomaly === 'function') {
            window.flashTopologyAnomaly(msg.payload);
          }
          loadTopbarStats();
        } else if (msg.type === 'AI_BRAIN_DIAGNOSTIC_UPDATE') {
          if (typeof window.handleAiBrainDiagnosticUpdate === 'function') {
            window.handleAiBrainDiagnosticUpdate(msg.payload || msg);
          }
          if (typeof window.handleAiBrainLiveUpdate === 'function') {
            window.handleAiBrainLiveUpdate(msg.payload || msg);
          }
        } else if (msg.type === 'NODE_ALERT' || msg.type === 'NODE_UPDATE') {
          loadTopbarStats();
        }
      } catch (e) {
        if (!window._lastWsErrLog || Date.now() - window._lastWsErrLog > 5000) {
          window._lastWsErrLog = Date.now();
          console.warn('[EJII WebSocket] Malformed message ignored:', e.message);
        }
      }
    };

    state.ws.onclose = () => {
      const el = document.getElementById('wsStatusText');
      if (el) el.textContent = 'Disconnected (Reconnecting...)';
      const dot = document.querySelector('.status-dot');
      if (dot) dot.style.backgroundColor = '#ef4444';
      if (wsReconnectTimer) clearTimeout(wsReconnectTimer);
      wsReconnectTimer = setTimeout(initWebSocket, 4000);
    };
  } catch (e) {
    console.warn('WebSocket init failed:', e);
  }
}

window.initWebSocket = initWebSocket;

/**
 * Update Topbar Stats (BPF Filter, Anomalies, Nodes)
 */
async function loadTopbarStats() {
  if (!state.token) return;
  try {
    const [statusRes, anomRes, topoRes] = await Promise.allSettled([
      api('/api/network/capture/status'),
      api('/api/network/tools/anomalies?limit=5'),
      api('/api/network/topology')
    ]);

    if (statusRes.status === 'fulfilled' && statusRes.value) {
      const bpfEl = document.getElementById('topbarBpfFilter');
      if (bpfEl) {
        bpfEl.textContent = statusRes.value.bpfFilter ? `[BPF: ${statusRes.value.bpfFilter}]` : '[ALL WIRE]';
      }
    }

    if (anomRes.status === 'fulfilled' && anomRes.value) {
      const anomEl = document.getElementById('topbarAnomaliesCount');
      if (anomEl) {
        anomEl.textContent = anomRes.value.count || 0;
        anomEl.style.color = anomRes.value.count > 0 ? '#ef4444' : 'var(--warning)';
      }
    }

    if (topoRes.status === 'fulfilled' && topoRes.value) {
      const nodesEl = document.getElementById('topbarNodesCount');
      if (nodesEl) {
        nodesEl.textContent = topoRes.value.nodes?.length || 6;
      }
    }
  } catch (e) {}
}

/**
 * Dedicated Standalone Login Screen Controller
 */
function showLoginScreen() {
  const loginScreen = document.getElementById('loginScreen');
  const app = document.getElementById('app');
  if (loginScreen) loginScreen.style.display = 'flex';
  if (app) app.style.display = 'none';

  const errAlert = document.getElementById('loginErrorAlert');
  if (errAlert) errAlert.style.display = 'none';

  loadLoginTelemetry();
}

async function loadLoginTelemetry() {
  try {
    const info = await api('/api/network/physical-info').catch(() => null);
    if (info) {
      const gwEl = document.getElementById('loginTelGateway');
      const subEl = document.getElementById('loginTelSubnet');
      const hostEl = document.getElementById('loginTelHost');
      if (gwEl && info.gatewayIp) gwEl.textContent = info.gatewayIp;
      if (subEl && info.subnetCidr) subEl.textContent = info.subnetCidr;
      if (hostEl && info.hostIp) hostEl.textContent = `${info.hostIp}`;
    }
  } catch (e) {}
}

async function checkAuthConfig() {
  try {
    const authConfig = await api('/api/auth/config').catch(() => null);
    if (authConfig && authConfig.evaluationMode === false) {
      const pillsContainer = document.getElementById('evaluationLoginPills');
      const quickCta = document.getElementById('evaluationQuickCta');
      const divider = document.getElementById('evaluationLoginDivider');
      if (pillsContainer) pillsContainer.style.display = 'none';
      if (quickCta) quickCta.style.display = 'none';
      if (divider) divider.style.display = 'none';

      const userInp = document.getElementById('loginUsername');
      const passInp = document.getElementById('loginPassword');
      if (userInp) userInp.value = '';
      if (passInp) passInp.value = '';
      window.isEvaluationMode = false;
    } else {
      window.isEvaluationMode = true;
    }
  } catch (e) {
    window.isEvaluationMode = true;
  }
}

function hideLoginScreen() {
  const loginScreen = document.getElementById('loginScreen');
  const app = document.getElementById('app');
  if (loginScreen) loginScreen.style.display = 'none';
  if (app) app.style.display = 'flex';
}

window.showLoginScreen = function() {
  showLoginScreen();
  checkAuthConfig();
};
window.hideLoginScreen = hideLoginScreen;

let selectedProfileUsername = 'admin';

window.selectLoginProfile = function(username, password) {
  if (window.isEvaluationMode === false) return;
  selectedProfileUsername = username;
  const userInp = document.getElementById('loginUsername');
  const passInp = document.getElementById('loginPassword');
  if (userInp) userInp.value = username;
  if (passInp) passInp.value = password;

  document.querySelectorAll('.login-role-btn').forEach(btn => {
    btn.style.borderColor = 'rgba(255,255,255,0.08)';
    btn.style.background = 'var(--bg-input)';
    btn.style.color = 'var(--text-muted)';
  });

  const activeBtn = document.getElementById(`pill-${username}`);
  if (activeBtn) {
    activeBtn.style.borderColor = 'var(--accent)';
    activeBtn.style.background = 'rgba(56, 189, 248, 0.15)';
    activeBtn.style.color = '#38bdf8';
  }
};

/**
 * 1-Click Quick Operator Login
 */
window.quickNocLogin = async function() {
  if (window.isEvaluationMode === false) {
    const errAlert = document.getElementById('loginErrorAlert');
    const errMsg = document.getElementById('loginErrorMessage');
    if (errAlert && errMsg) {
      errAlert.style.display = 'flex';
      errMsg.textContent = 'Quick NOC login is disabled in production environments.';
    }
    return;
  }
  try {
    const res = await api('/api/auth/quick-noc', {
      method: 'POST',
      body: JSON.stringify({ username: selectedProfileUsername || 'admin' })
    });
    state.token = res.token;
    state.user = res.user;
    localStorage.setItem('ejii_token', res.token);
    initWebSocket();
    hideLoginScreen();
    updateUserBadge();
    loadTopbarStats();
    renderView('topology');
  } catch (err) {
    const errAlert = document.getElementById('loginErrorAlert');
    const errMsg = document.getElementById('loginErrorMessage');
    if (errAlert && errMsg) {
      errAlert.style.display = 'flex';
      errMsg.textContent = err.message || 'Login failed.';
    }
  }
};

window.handleLoginFormSubmit = async function(event) {
  event.preventDefault();
  const username = document.getElementById('loginUsername').value;
  const password = document.getElementById('loginPassword').value;

  const errAlert = document.getElementById('loginErrorAlert');
  const errMsg = document.getElementById('loginErrorMessage');
  const submitBtn = document.getElementById('btnSubmitLogin');

  if (errAlert) errAlert.style.display = 'none';
  if (submitBtn) {
    submitBtn.disabled = true;
    document.getElementById('loginBtnText').textContent = 'Authenticating...';
  }

  try {
    const res = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password })
    });

    state.token = res.token;
    state.user = res.user;
    localStorage.setItem('ejii_token', res.token);
    initWebSocket();
    hideLoginScreen();
    updateUserBadge();
    loadTopbarStats();
    renderView('topology');
  } catch (err) {
    if (errAlert && errMsg) {
      errAlert.style.display = 'flex';
      errMsg.textContent = err.message || 'Invalid username or password.';
    }
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      document.getElementById('loginBtnText').textContent = 'Sign In';
    }
  }
};

function updateUserBadge() {
  const badgeArea = document.getElementById('userBadgeArea');
  const nameEl = document.getElementById('userDisplayName');
  const roleEl = document.getElementById('userRoleTag');

  if (state.user) {
    if (badgeArea) badgeArea.style.display = 'flex';
    if (nameEl) nameEl.textContent = state.user.fullName || state.user.username;
    if (roleEl) roleEl.textContent = 'UNPRIVILEGED NOC';
  }
}

window.currentRouteGeneration = 0;
window.EJIIStore = window.EJIIStore || { bootstrap: null, cache: {} };

async function loadWarmBootstrap() {
  if (!state.token) return null;
  try {
    const data = await api('/api/system/bootstrap');
    if (data && data.ok) {
      window.EJIIStore.bootstrap = data;
      if (data.network?.topology && typeof window.setNocTopologyData === 'function') {
        window.setNocTopologyData(data.network.topology);
      }
      if (data.sniffer?.counters && typeof window.handlePacketStats === 'function') {
        window.handlePacketStats({ counters: data.sniffer.counters });
      }
      return data;
    }
  } catch (e) {}
  return null;
}
window.loadWarmBootstrap = loadWarmBootstrap;

/**
 * Universal View Renderer for the 4 Dedicated Workstations
 */
function renderView(viewName = 'topology') {
  let target = viewName;
  if (target === 'noc') target = 'topology';
  if (target === 'ip-scanner') target = 'ultra-ip-scanner';

  state.currentView = target;
  window.currentRouteGeneration = (window.currentRouteGeneration || 0) + 1;
  const currentGen = window.currentRouteGeneration;

  // Highlight active nav link
  document.querySelectorAll('.nav-link').forEach(link => {
    const linkView = link.dataset.view;
    const isActive = linkView === target ||
      (linkView === 'ultra-ip-scanner' && target === 'ip-scanner') ||
      (linkView === 'ip-scanner' && target === 'ultra-ip-scanner') ||
      (linkView === 'noc' && target === 'topology');
    link.classList.toggle('active', isActive);
  });

  if (target === 'topology') {
    if (typeof window.renderTopologyStandaloneView === 'function') {
      window.renderTopologyStandaloneView();
    } else if (typeof window.renderNocView === 'function') {
      window.renderNocView();
    }
  } else if (target === 'packet-sniffer') {
    if (typeof window.renderPacketSnifferStandaloneView === 'function') {
      window.renderPacketSnifferStandaloneView();
    }
  } else if (target === 'ultra-ip-scanner' || target === 'ip-scanner') {
    if (typeof window.renderUltraIpScannerView === 'function') {
      window.renderUltraIpScannerView();
    }
  } else if (target === 'pc-automation') {
    if (typeof window.renderPcAutomationView === 'function') {
      window.renderPcAutomationView();
    }
  } else if (target === 'core-diagnostics') {
    if (typeof window.renderCoreDiagnosticsView === 'function') {
      window.renderCoreDiagnosticsView();
    }
  } else {
    if (typeof window.renderTopologyStandaloneView === 'function') {
      window.renderTopologyStandaloneView();
    }
  }
}

/**
 * Modals & Interactive Workbenches
 */
window.openWireDiagnosticsModal = function() {
  const modalContainer = document.getElementById('modalContainer');
  if (!modalContainer) return;

  modalContainer.style.display = 'flex';
  modalContainer.innerHTML = `
    <div class="modal-backdrop" onclick="window.closeModal(event)">
      <div class="modal-card" style="max-width: 800px; width: 90%; max-height: 85vh; overflow-y: auto; scrollbar-gutter: stable; padding-right: 20px;" onclick="event.stopPropagation()">
        <div class="modal-header" style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 10px;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-size: 20px;">🛠️</span>
            <div>
              <div style="font-weight: 800; font-size: 15px; color: var(--accent);">Isolated Wire Diagnostics Hub (Zero Elevation)</div>
              <div style="font-size: 11px; color: var(--text-muted);">Concurrent Ping Flooder, Passive BGP/OSPF Listener, Transport Error Finder</div>
            </div>
          </div>
          <button class="btn-logout" onclick="window.closeModal()">✕</button>
        </div>

        <div style="padding: 16px 0;">
          <!-- 1. Concurrent Async Ping Flooder / Sweeper -->
          <div style="background: var(--bg-input); border: 1px solid var(--border-color); border-radius: 6px; padding: 14px; margin-bottom: 16px;">
            <div style="font-weight: 700; font-size: 13px; color: var(--text-main); margin-bottom: 6px; display: flex; align-items: center; gap: 6px;">
              <span>⚡ 1. Asynchronous Ping / ICMP Flooder (Concurrent Sweeper)</span>
            </div>
            <p style="font-size: 11px; color: var(--text-muted); margin-bottom: 10px;">
              Probes hundreds of mapped nodes per second asynchronously without OS handle exhaustion or admin rights.
            </p>
            <div style="display: flex; gap: 8px;">
              <input type="text" id="sweepTargetsInput" class="form-input" placeholder="Leave empty to sweep all mapped nodes, or comma separated IPs" style="flex: 1; font-size: 11px;">
              <button class="btn btn-primary" onclick="window.runAsyncPingSweep()" style="font-size: 11px; padding: 4px 12px; font-weight: 700;">Start Sweep ⚡</button>
            </div>
            <div id="sweepResultOutput" style="margin-top: 10px; max-height: 160px; overflow-y: auto; font-family: var(--font-mono); font-size: 11px; scrollbar-gutter: stable; padding-right: 10px;"></div>
          </div>

          <!-- 2. Passive BGP & OSPF Listener -->
          <div style="background: var(--bg-input); border: 1px solid var(--border-color); border-radius: 6px; padding: 14px; margin-bottom: 16px;">
            <div style="font-weight: 700; font-size: 13px; color: var(--text-main); margin-bottom: 6px; display: flex; align-items: center; justify-content: space-between;">
              <span>📡 2. Passive BGP &amp; OSPF Route Listener</span>
              <button class="btn btn-secondary" onclick="window.refreshRoutingEvents()" style="font-size: 10px; padding: 2px 8px;">↻ Refresh</button>
            </div>
            <p style="font-size: 11px; color: var(--text-muted); margin-bottom: 10px;">
              Passively listens for OSPF hello multicast (224.0.0.5/6) and BGP keepalives (TCP 179) to update topology routing states.
            </p>
            <div id="routingEventsOutput" style="max-height: 140px; overflow-y: auto; font-family: var(--font-mono); font-size: 11px; scrollbar-gutter: stable; padding-right: 10px;">
              Awaiting route multicast traffic on physical wire...
            </div>
          </div>

          <!-- 3. Wire-Level Error & Problem Finder -->
          <div style="background: var(--bg-input); border: 1px solid var(--border-color); border-radius: 6px; padding: 14px;">
            <div style="font-weight: 700; font-size: 13px; color: var(--text-main); margin-bottom: 6px; display: flex; align-items: center; justify-content: space-between;">
              <span>🚨 3. Wire-Level Transport Error &amp; Problem Finder</span>
              <div style="display: flex; gap: 6px;">
                <button class="btn btn-secondary" onclick="window.refreshAnomaliesList()" style="font-size: 10px; padding: 2px 8px;">↻ Refresh</button>
                <button class="btn btn-secondary" onclick="window.clearAnomaliesList()" style="font-size: 10px; padding: 2px 8px;">Clear</button>
              </div>
            </div>
            <p style="font-size: 11px; color: var(--text-muted); margin-bottom: 10px;">
              Monitors transport layer degradation: MTU black holes, TCP RST drops, DNS resolution spikes, and broadcast storms.
            </p>
            <div id="anomaliesListOutput" style="max-height: 180px; overflow-y: auto; font-family: var(--font-mono); font-size: 11px; scrollbar-gutter: stable; padding-right: 14px;">
              Scanning wire streams...
            </div>
          </div>
        </div>
      </div>
    </div>
  `;
  window.refreshRoutingEvents();
  window.refreshAnomaliesList();
};

window.runAsyncPingSweep = async function() {
  const out = document.getElementById('sweepResultOutput');
  if (out) out.innerHTML = '<span style="color: var(--accent);">Initiating concurrent unprivileged ping sweep...</span>';

  const raw = document.getElementById('sweepTargetsInput')?.value?.trim();
  let targets = null;
  if (raw) {
    targets = raw.split(',').map(s => s.trim()).filter(Boolean);
  }

  try {
    const res = await api('/api/network/tools/async-sweep', {
      method: 'POST',
      body: JSON.stringify({ targets, concurrency: 30, timeoutMs: 600 })
    });

    if (out) {
      out.innerHTML = `
        <div style="color: var(--success); font-weight: 700; margin-bottom: 6px;">
          ✓ Swept ${res.totalProbed} nodes in ${res.durationMs}ms (${res.probesPerSecond} probes/sec). Online: ${res.healthyCount}, Unreachable: ${res.unreachableCount}
        </div>
        <table class="data-table" style="font-size: 11px;">
          <thead>
            <tr><th>Target</th><th>Status</th><th>Latency</th><th>Method</th></tr>
          </thead>
          <tbody>
            ${res.results.slice(0, 15).map(r => `
              <tr>
                <td style="font-weight: 600;">${r.target}</td>
                <td><span style="color: ${r.status === 'healthy' ? 'var(--success)' : 'var(--danger)'}; font-weight: 700;">${r.status.toUpperCase()}</span></td>
                <td>${r.latencyMs !== null ? r.latencyMs + ' ms' : '—'}</td>
                <td style="color: var(--text-dim);">${r.method}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      `;
    }
  } catch (err) {
    if (out) out.innerHTML = `<span style="color: var(--danger);">Sweep error: ${err.message}</span>`;
  }
};

window.refreshRoutingEvents = async function() {
  const out = document.getElementById('routingEventsOutput');
  try {
    const res = await api('/api/network/tools/routing-events?limit=20');
    if (out) {
      if (res.events && res.events.length > 0) {
        out.innerHTML = res.events.map(e => `
          <div style="padding: 4px 0; border-bottom: 1px solid rgba(255,255,255,0.05); display: flex; justify-content: space-between;">
            <span><b style="color: var(--accent);">${e.protocol}:</b> ${e.summary}</span>
            <span style="color: var(--text-dim);">${window.formatLocalTime(e.timestamp)}</span>
          </div>
        `).join('');
      } else {
        out.innerHTML = '<span style="color: var(--text-dim);">Passively listening on wire... (OSPF multicasts 224.0.0.5 or BGP TCP 179 will appear here dynamically)</span>';
      }
    }
  } catch (e) {}
};

window.refreshAnomaliesList = async function() {
  const out = document.getElementById('anomaliesListOutput');
  try {
    const res = await api('/api/network/tools/anomalies?limit=20');
    if (out) {
      if (res.anomalies && res.anomalies.length > 0) {
        out.innerHTML = res.anomalies.map(a => `
          <div style="padding: 7px 0; border-bottom: 1px solid rgba(255,255,255,0.05); display: flex; justify-content: space-between; align-items: flex-start; gap: 12px;">
            <div style="flex: 1; min-width: 0; word-break: break-word;">
              <span style="color: ${a.severity === 'critical' ? '#ef4444' : '#f59e0b'}; font-weight: 700;">[${a.anomaly_type}]</span>
              <span style="margin-left: 6px; color: var(--text-main);">${a.details}</span>
            </div>
            <span style="color: var(--text-dim); font-size: 10px; flex-shrink: 0; min-width: 85px; text-align: right; margin-left: 12px; white-space: nowrap;">${window.formatLocalTime(a.timestamp)}</span>
          </div>
        `).join('');
      } else {
        out.innerHTML = '<span style="color: var(--success);">✓ Clean Wire: Zero MTU black holes, RST bursts, or broadcast storms detected.</span>';
      }
    }
  } catch (e) {}
};

window.clearAnomaliesList = async function() {
  await api('/api/network/tools/anomalies/clear', { method: 'POST' });
  window.refreshAnomaliesList();
};

window.openPcapVaultModal = function() {
  const modalContainer = document.getElementById('modalContainer');
  if (!modalContainer) return;

  modalContainer.style.display = 'flex';
  modalContainer.innerHTML = `
    <div class="modal-backdrop" onclick="window.closeModal(event)">
      <div class="modal-card" style="max-width: 600px; width: 90%;" onclick="event.stopPropagation()">
        <div class="modal-header" style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 10px;">
          <div style="font-weight: 800; font-size: 15px; color: var(--accent);">📁 PCAP Capture Vault</div>
          <button class="btn-logout" onclick="window.closeModal()">✕</button>
        </div>
        <div style="padding: 20px 0;">
          <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 16px;">
            Export active buffer to standard libpcap format for Wireshark inspection, or import offline PCAPs for deep dissection.
          </p>
          <div style="display: flex; gap: 10px;">
            <button class="btn btn-primary" onclick="window.downloadPcapExport()" style="flex: 1; padding: 10px; font-weight: 700;">
              ⬇ Export Current PCAP Buffer
            </button>
            <button class="btn btn-secondary" onclick="window.triggerImportPcap()" style="flex: 1; padding: 10px; font-weight: 700;">
              ⬆ Import Offline PCAP
            </button>
          </div>
        </div>
      </div>
    </div>
  `;
};

window.closeModal = function() {
  const modalContainer = document.getElementById('modalContainer');
  if (modalContainer) modalContainer.style.display = 'none';
};

/**
 * Global Keyboard Shortcuts (Ctrl+K: Command Palette, Ctrl+H: Field Manual)
 */
document.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    if (typeof window.toggleCommandPalette === 'function') window.toggleCommandPalette();
  }
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'h') {
    e.preventDefault();
    if (typeof window.toggleJuniorAdminCheatSheet === 'function') window.toggleJuniorAdminCheatSheet();
  }
  if (e.key === 'Escape') {
    window.closeModal();
    const cp = document.getElementById('commandPalette');
    if (cp) cp.style.display = 'none';
    const ctx = document.getElementById('nocContextMenu');
    if (ctx) ctx.style.display = 'none';
  }
});

/**
 * Cross-View Investigation Router:
 * Allows any view (View 1 Topology, View 2 Sniffer, View 3 Scanner, View 4 PC Scripts, View 5 AI Workflow)
 * to pin an active investigation target, populate #ejiiActiveTargetContextBar, and pivot across views.
 */
window.setEjiiInvestigationTarget = function(target, targetPort = 443) {
  if (!target) return;
  const targetObj = typeof target === 'object' ? target : { ip: target, port: targetPort || 443 };
  const ip = targetObj.ip || targetObj.targetIp || '127.0.0.1';
  const port = targetObj.port || targetObj.targetPort || 443;
  const hostname = targetObj.hostname || targetObj.name || '';
  const mac = targetObj.macAddress || targetObj.mac || '';
  const brand = targetObj.equipmentBrand || targetObj.vendor || '';
  const icon = targetObj.icon || '🎯';

  state.activeTarget = { ...targetObj, ip, port, hostname, mac, brand, icon };
  state.selectedTarget = ip;
  state.selectedPort = port;

  const bar = document.getElementById('ejiiActiveTargetContextBar');
  if (bar) {
    bar.style.display = 'flex';
    bar.style.alignItems = 'center';
    bar.style.gap = '12px';
    bar.style.padding = '8px 16px';
    bar.style.background = 'linear-gradient(90deg, #1E293B, #0F172A)';
    bar.style.borderBottom = '1px solid var(--accent, #38BDF8)';
    bar.innerHTML = `
      <div class="eji-context-info" style="display: flex; align-items: center; gap: 8px;">
        <span class="context-icon" style="font-size: 16px;">${icon}</span>
        <strong style="color: var(--accent, #38BDF8);">${ip}${port ? ':' + port : ''}</strong>
        ${hostname ? `<span class="context-host" style="color: var(--text-dim, #94A3B8); font-size: 12px;">(${hostname})</span>` : ''}
        ${brand ? `<span class="context-brand badge badge-info" style="font-size: 10px; background: rgba(56,189,248,0.2); padding: 2px 6px; border-radius: 4px;">${brand}</span>` : ''}
        ${mac && mac !== 'Unknown' ? `<code style="font-size: 10px; color: var(--text-dim, #94A3B8);">${mac}</code>` : ''}
      </div>
      <div class="eji-context-pivots" style="display: flex; align-items: center; gap: 6px; margin-left: auto;">
        <button class="btn btn-secondary btn-xs" onclick="window.renderView('topology')" title="Inspect in Topology">🗺️ 1. View in Topology</button>
        <button class="btn btn-secondary btn-xs" onclick="window.filterSnifferByTarget('${ip}')" title="Filter packets in Sniffer">🦈 2. Filter in Sniffer</button>
        <button class="btn btn-secondary btn-xs" onclick="window.inspectScannerTarget('${ip}')" title="Inspect Office Equipment in Scanner">📡 3. Inspect in Scanner</button>
        <button class="btn btn-secondary btn-xs" onclick="window.renderView('pc-automation')" title="Execute remediation scripts">🛠️ 4. PC Scripts</button>
        <button class="btn btn-primary btn-xs" onclick="window.runAiWorkflowForTarget('${ip}', ${port})" title="Run Closed-Loop AI Goal Workflow">🧠 5. Run AI Workflow</button>
        <button class="btn btn-outline btn-xs" onclick="window.clearEjiiInvestigationTarget()" title="Clear active target context">✕ Clear</button>
      </div>
    `;
  }
};

window.clearEjiiInvestigationTarget = function() {
  state.activeTarget = null;
  const bar = document.getElementById('ejiiActiveTargetContextBar');
  if (bar) {
    bar.style.display = 'none';
    bar.innerHTML = '';
  }
};

window.pivotActiveTargetToView = function(viewName) {
  if (typeof renderView === 'function') {
    renderView(viewName);
  }
};

window.filterSnifferByTarget = function(ip) {
  renderView('packet-sniffer');
  setTimeout(() => {
    const input = document.getElementById('bpfFilterInput');
    if (input) {
      input.value = `host ${ip}`;
      if (typeof window.applyBpfFilter === 'function') window.applyBpfFilter(`host ${ip}`);
    }
  }, 100);
};

window.inspectScannerTarget = function(ip) {
  renderView('ultra-ip-scanner');
  setTimeout(() => {
    if (typeof window.diagnoseOfficeEquipmentModal === 'function') {
      window.diagnoseOfficeEquipmentModal(ip);
    }
  }, 100);
};

window.runAiWorkflowForTarget = function(ip, port = 80) {
  renderView('core-diagnostics');
  setTimeout(() => {
    const targetInput = document.getElementById('workflowTargetInput');
    const portInput = document.getElementById('workflowPortInput');
    if (targetInput) targetInput.value = ip;
    if (portInput) portInput.value = port;
    if (typeof window.runAutonomousWorkflowFromUi === 'function') {
      window.runAutonomousWorkflowFromUi();
    }
  }, 100);
};

// App Initialization
window.addEventListener('DOMContentLoaded', async () => {
  initWebSocket();

  // Sign out button
  const btnLogout = document.getElementById('btnLogout');
  if (btnLogout) {
    btnLogout.addEventListener('click', async () => {
      try { await api('/api/auth/logout', { method: 'POST' }); } catch (e) {}
      state.token = null;
      state.user = null;
      localStorage.removeItem('ejii_token');
      initWebSocket();
      showLoginScreen();
    });
  }

  // Check existing session or show login
  if (state.token) {
    try {
      const [me] = await Promise.all([
        api('/api/auth/me'),
        loadWarmBootstrap()
      ]);
      state.user = me.user;
      hideLoginScreen();
      updateUserBadge();
      loadTopbarStats();
      renderView('topology');
    } catch (e) {
      showLoginScreen();
    }
  } else {
    showLoginScreen();
  }
});
