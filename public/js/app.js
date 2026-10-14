/**
 * EJII — Eldar Jamiyev's Infrastructure Intelligence
 * Frontend Single Page Application Engine
 */

// State Management
const state = {
  token: localStorage.getItem('ejii_token') || null,
  user: null,
  currentView: 'helpdesk',
  incidents: [],
  nodes: [],
  ws: null
};

// Preset credentials for rapid role switching
const DEMO_ACCOUNTS = {
  helpdesk: { username: 'helpdesk', password: 'HelpdeskPassword2026!', label: 'Helpdesk Technician' },
  network_admin: { username: 'netadmin', password: 'NetadminPassword2026!', label: 'Network Administrator' },
  sysadmin: { username: 'sysadmin', password: 'SysadminPassword2026!', label: 'System Administrator' },
  app_owner: { username: 'appowner', password: 'AppownerPassword2026!', label: 'Application Owner' }
};

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

/**
 * Initialize WebSocket Live Connection
 */
function initWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/`;
  
  try {
    state.ws = new WebSocket(wsUrl);

    state.ws.onopen = () => {
      document.getElementById('wsStatusText').textContent = 'Live Telemetry Connected';
      document.querySelector('.status-dot').style.backgroundColor = '#10b981';
    };

    state.ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === 'NODE_ALERT') {
          loadTopbarStats();
          if (state.currentView === 'rca') renderRcaView();
        } else if (msg.type === 'NODE_UPDATE') {
          loadTopbarStats();
        }
      } catch (e) {}
    };

    state.ws.onclose = () => {
      document.getElementById('wsStatusText').textContent = 'Disconnected (Reconnecting...)';
      document.querySelector('.status-dot').style.backgroundColor = '#ef4444';
      setTimeout(initWebSocket, 4000);
    };
  } catch (e) {
    console.warn('WebSocket init failed:', e);
  }
}

/**
 * Update Topbar Stats
 */
async function loadTopbarStats() {
  if (!state.token) return;
  try {
    const [incidentsRes, topologyRes] = await Promise.allSettled([
      api('/api/rca/incidents?status=open'),
      api('/api/network/topology')
    ]);

    if (incidentsRes.status === 'fulfilled' && incidentsRes.value) {
      document.getElementById('topbarIncidentsCount').textContent = incidentsRes.value.count || 0;
    }
    if (topologyRes.status === 'fulfilled' && topologyRes.value) {
      document.getElementById('topbarNodesCount').textContent = topologyRes.value.nodes.length || 0;
    }
  } catch (e) {}
}

/**
 * Handle Login
 */
async function login(username, password) {
  try {
    const res = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password })
    });

    state.token = res.token;
    state.user = res.user;
    localStorage.setItem('ejii_token', res.token);
    updateUserBadge();
    loadTopbarStats();
    renderView(state.currentView);
  } catch (err) {
    alert(`Login failed: ${err.message}`);
  }
}

/**
 * Handle Logout
 */
function logout() {
  state.token = null;
  state.user = null;
  localStorage.removeItem('ejii_token');
  updateUserBadge();
  renderLoginView();
}

/**
 * Update User Badge in Sidebar
 */
function updateUserBadge() {
  const badgeArea = document.getElementById('userBadgeArea');
  if (!state.user) {
    badgeArea.style.display = 'none';
    return;
  }

  badgeArea.style.display = 'flex';
  document.getElementById('userDisplayName').textContent = state.user.fullName;
  const roleTag = document.getElementById('userRoleTag');
  roleTag.textContent = state.user.role.replace('_', ' ');
  roleTag.className = `user-role-tag role-${state.user.role}`;
}

/**
 * View Router
 */
function renderView(viewName) {
  state.currentView = viewName;

  // Update navigation active state
  document.querySelectorAll('.nav-link').forEach((link) => {
    link.classList.toggle('active', link.dataset.view === viewName);
  });

  const titles = {
    helpdesk: '🔍 Helpdesk Diagnostics Workbench',
    network: '🌐 Network Administrator Operations',
    sysadmin: '🖥️ System Administrator Health & Controls',
    rca: '⚡ Root Cause Analysis & Problem Investigation',
    automation: '🛡️ Safe Remediation & Automation Engine',
    tools: '🛠️ 14-Tool Unified Subsystems Hub',
    appowner: '👑 Application Owner Governance & Audit'
  };

  document.getElementById('pageTitle').innerHTML = titles[viewName] || 'EJII Platform';

  if (!state.token) {
    renderLoginView();
    return;
  }

  switch (viewName) {
    case 'helpdesk': renderHelpdeskView(); break;
    case 'network': renderNetworkView(); break;
    case 'sysadmin': renderSysadminView(); break;
    case 'rca': renderRcaView(); break;
    case 'automation': renderAutomationView(); break;
    case 'tools': renderToolsView(); break;
    case 'appowner': renderAppOwnerView(); break;
    default: renderHelpdeskView();
  }
}

/**
 * VIEW: Login & Quick Role Switcher
 */
function renderLoginView() {
  const container = document.getElementById('mainContent');
  container.innerHTML = `
    <div style="max-width: 600px; margin: 40px auto;">
      <div class="card">
        <div class="card-header">
          <div class="card-title">🔐 EJII Authentication & Operational Role Selection</div>
        </div>

        <p style="color: var(--text-muted); margin-bottom: 20px;">
          Select one of the four operational roles to authenticate directly, or enter manual credentials:
        </p>

        <div class="grid-2" style="margin-bottom: 24px;">
          <button class="btn btn-secondary" onclick="login('${DEMO_ACCOUNTS.helpdesk.username}', '${DEMO_ACCOUNTS.helpdesk.password}')" style="justify-content: flex-start; padding: 12px;">
            <div style="text-align: left;">
              <div style="font-weight: 700; color: #a7f3d0;">Helpdesk Technician</div>
              <div style="font-size: 11px; color: var(--text-muted);">Diagnostics & Plain-Language Guidance</div>
            </div>
          </button>

          <button class="btn btn-secondary" onclick="login('${DEMO_ACCOUNTS.network_admin.username}', '${DEMO_ACCOUNTS.network_admin.password}')" style="justify-content: flex-start; padding: 12px;">
            <div style="text-align: left;">
              <div style="font-weight: 700; color: #bfdbfe;">Network Administrator</div>
              <div style="font-size: 11px; color: var(--text-muted);">SNMP, Port Sweeps, TLS & Topology</div>
            </div>
          </button>

          <button class="btn btn-secondary" onclick="login('${DEMO_ACCOUNTS.sysadmin.username}', '${DEMO_ACCOUNTS.sysadmin.password}')" style="justify-content: flex-start; padding: 12px;">
            <div style="text-align: left;">
              <div style="font-weight: 700; color: #e9d5ff;">System Administrator</div>
              <div style="font-size: 11px; color: var(--text-muted);">Host Metrics, Services, Processes & RCA</div>
            </div>
          </button>

          <button class="btn btn-secondary" onclick="login('${DEMO_ACCOUNTS.app_owner.username}', '${DEMO_ACCOUNTS.app_owner.password}')" style="justify-content: flex-start; padding: 12px;">
            <div style="text-align: left;">
              <div style="font-weight: 700; color: #fbcfe8;">Application Owner</div>
              <div style="font-size: 11px; color: var(--text-muted);">Governance, Dual Approvals & Audit HMAC</div>
            </div>
          </button>
        </div>

        <form id="customLoginForm" onsubmit="handleManualLogin(event)">
          <div class="form-group">
            <label class="form-label">Username</label>
            <input type="text" class="form-input" id="manualUsername" required placeholder="e.g. sysadmin">
          </div>
          <div class="form-group">
            <label class="form-label">Password</label>
            <input type="password" class="form-input" id="manualPassword" required placeholder="••••••••••••">
          </div>
          <button type="submit" class="btn btn-primary" style="width: 100%;">Sign In with Credentials</button>
        </form>
      </div>
    </div>
  `;
}

window.handleManualLogin = function(e) {
  e.preventDefault();
  const u = document.getElementById('manualUsername').value;
  const p = document.getElementById('manualPassword').value;
  login(u, p);
};

/**
 * VIEW: Helpdesk Diagnostics
 */
function renderHelpdeskView() {
  const container = document.getElementById('mainContent');
  container.innerHTML = `
    <div class="grid-2">
      <!-- Diagnostic Controls -->
      <div class="card">
        <div class="card-header">
          <div class="card-title">⚡ Rapid Infrastructure Diagnostics</div>
        </div>

        <div class="form-group">
          <label class="form-label">Diagnostic Tool</label>
          <select class="form-select" id="diagType" onchange="toggleDiagFields()">
            <option value="ping">Real ICMP Ping (Latency & Packet Loss)</option>
            <option value="port">TCP Port Socket Probe (Service Status)</option>
            <option value="dns">Direct DNS Resolution (RFC 1035)</option>
            <option value="http">HTTP/HTTPS Synthetic Waterfall</option>
            <option value="traceroute">Traceroute (Multi-Hop Route)</option>
          </select>
        </div>

        <div class="form-group">
          <label class="form-label">Target Host / IP / Domain</label>
          <input type="text" class="form-input" id="diagTarget" value="127.0.0.1" placeholder="e.g. 127.0.0.1 or google.com">
          <div style="margin-top: 6px; display: flex; gap: 6px;">
            <button class="btn btn-secondary" style="padding: 2px 8px; font-size: 11px;" onclick="setDiagTarget('127.0.0.1')">Localhost</button>
            <button class="btn btn-secondary" style="padding: 2px 8px; font-size: 11px;" onclick="setDiagTarget('10.168.195.1')">Subnet Gateway</button>
            <button class="btn btn-secondary" style="padding: 2px 8px; font-size: 11px;" onclick="setDiagTarget('google.com')">google.com</button>
          </div>
        </div>

        <div class="form-group" id="portFieldGroup" style="display: none;">
          <label class="form-label">TCP Port</label>
          <input type="number" class="form-input" id="diagPort" value="80" placeholder="e.g. 80, 443, 3389">
        </div>

        <button class="btn btn-primary" id="btnRunDiag" onclick="executeDiagnostic()" style="width: 100%;">
          Run Live Diagnostic Probe
        </button>
      </div>

      <!-- Quick Guidance -->
      <div class="card">
        <div class="card-header">
          <div class="card-title">💡 Operational Principles</div>
        </div>
        <p style="color: var(--text-muted); margin-bottom: 12px;">
          <strong>Zero-Simulation Guarantee:</strong> All diagnostics trigger actual system kernel sockets and protocol packets. No simulated or randomized test results are ever produced.
        </p>
        <ul style="color: var(--text-dim); padding-left: 20px; font-size: 12px; display: flex; flex-direction: column; gap: 8px;">
          <li><strong>CLOSED (ECONNREFUSED):</strong> The host machine is online, but no application process is currently listening on the specified port.</li>
          <li><strong>FILTERED (ETIMEDOUT):</strong> Packets were sent, but dropped with zero response. Indicates a hardware or software firewall blocking traffic.</li>
          <li><strong>DOWN (100% Loss):</strong> Host machine is powered down, link is severed, or ICMP is disabled on the edge.</li>
        </ul>
      </div>
    </div>

    <!-- Results Display -->
    <div class="card" id="diagResultCard" style="display: none;">
      <div class="card-header">
        <div class="card-title">📊 Live Diagnostic Output & Plain-Language Explanation</div>
      </div>

      <!-- Automated Plain-English Synthesis -->
      <div class="explanation-card" id="explanationCard">
        <h4>📋 Plain-Language Problem Assessment</h4>
        <p id="expWhatHappened"></p>
        <h4 style="color: #fbbf24;">🔍 Technical Reason</h4>
        <p id="expWhyFailed"></p>
        <h4 style="color: #34d399;">🛠️ Recommended Action</h4>
        <div id="expRecommendation" style="white-space: pre-line; color: var(--text-muted);"></div>
      </div>

      <div style="margin-top: 16px;">
        <label class="form-label">Raw Telemetry Socket Payload</label>
        <div class="console-box" id="diagRawConsole"></div>
      </div>
    </div>
  `;
}

window.setDiagTarget = function(t) {
  document.getElementById('diagTarget').value = t;
};

window.toggleDiagFields = function() {
  const type = document.getElementById('diagType').value;
  document.getElementById('portFieldGroup').style.display = type === 'port' ? 'block' : 'none';
};

window.executeDiagnostic = async function() {
  const type = document.getElementById('diagType').value;
  const target = document.getElementById('diagTarget').value.trim();
  const port = document.getElementById('diagPort') ? document.getElementById('diagPort').value : null;
  const btn = document.getElementById('btnRunDiag');

  if (!target) return alert('Target host is required.');

  btn.disabled = true;
  btn.textContent = 'Probing...';

  try {
    let res;
    if (type === 'ping') {
      res = await api('/api/diagnostics/ping', { method: 'POST', body: JSON.stringify({ host: target }) });
    } else if (type === 'port') {
      res = await api('/api/diagnostics/port', { method: 'POST', body: JSON.stringify({ host: target, port: parseInt(port, 10) }) });
    } else if (type === 'dns') {
      res = await api('/api/diagnostics/dns', { method: 'POST', body: JSON.stringify({ domain: target }) });
    } else if (type === 'http') {
      res = await api('/api/diagnostics/http', { method: 'POST', body: JSON.stringify({ url: target }) });
    } else if (type === 'traceroute') {
      res = await api('/api/diagnostics/traceroute', { method: 'POST', body: JSON.stringify({ host: target }) });
    }

    document.getElementById('diagResultCard').style.display = 'block';

    if (res.explanation) {
      document.getElementById('expWhatHappened').textContent = res.explanation.whatHappened || 'Telemetry collected.';
      document.getElementById('expWhyFailed').textContent = res.explanation.whyItFailed || 'None.';
      document.getElementById('expRecommendation').textContent = res.explanation.recommendation || 'None.';
    }

    document.getElementById('diagRawConsole').textContent = JSON.stringify(res.result || res, null, 2);
  } catch (err) {
    alert(`Diagnostic error: ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Run Live Diagnostic Probe';
  }
};

/**
 * VIEW: Network Administrator
 */
async function renderNetworkView() {
  const container = document.getElementById('mainContent');
  container.innerHTML = `<div style="color: var(--text-muted);">Loading live network topology...</div>`;

  try {
    const topology = await api('/api/network/topology');
    const nodes = topology.nodes || [];

    container.innerHTML = `
      <!-- Topology Overview -->
      <div class="card" style="margin-bottom: 20px;">
        <div class="card-header">
          <div class="card-title">🌐 Network Dependency DAG & Node Topology</div>
          <button class="btn btn-secondary" onclick="renderAddNodeModal()">+ Add Topology Node</button>
        </div>

        <div class="table-responsive">
          <table class="table">
            <thead>
              <tr>
                <th>Node Name</th>
                <th>Target IP / Host</th>
                <th>Type</th>
                <th>Parent Dependency</th>
                <th>Status</th>
                <th>Last Latency</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              ${nodes.map(n => `
                <tr>
                  <td><strong>${n.name}</strong></td>
                  <td><code>${n.hostname_or_ip}</code></td>
                  <td><span class="badge badge-open">${n.type}</span></td>
                  <td>${n.parent_id || '<span style="color: var(--text-dim);">Root Gateway</span>'}</td>
                  <td><span class="badge badge-${n.status}">${n.status}</span></td>
                  <td>${n.last_latency_ms !== null ? `${n.last_latency_ms} ms` : 'N/A'}</td>
                  <td>
                    <button class="btn btn-secondary" style="padding: 2px 8px; font-size: 11px;" onclick="probeNodeLive('${n.id}')">Probe</button>
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>

      <!-- Network Operations Workbenches -->
      <div class="grid-2">
        <!-- Port Scanner Sweep -->
        <div class="card">
          <div class="card-header">
            <div class="card-title">🔍 High-Concurrency TCP Port Sweep</div>
          </div>
          <div class="form-group">
            <label class="form-label">Target Host</label>
            <input type="text" class="form-input" id="sweepHost" value="127.0.0.1">
          </div>
          <button class="btn btn-primary" onclick="runPortSweep()">Run 23-Port Sweep</button>
          <div id="sweepResultBox" style="margin-top: 14px; display: none;">
            <div class="console-box" id="sweepConsole"></div>
          </div>
        </div>

        <!-- TLS / SSL Certificate Auditor -->
        <div class="card">
          <div class="card-header">
            <div class="card-title">🔒 TLS/SSL Security & Cipher Auditor</div>
          </div>
          <div class="form-group">
            <label class="form-label">HTTPS Domain</label>
            <input type="text" class="form-input" id="tlsTarget" value="google.com">
          </div>
          <button class="btn btn-primary" onclick="runTlsAudit()">Audit TLS Certificate</button>
          <div id="tlsResultBox" style="margin-top: 14px; display: none;">
            <div class="console-box" id="tlsConsole"></div>
          </div>
        </div>
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<div class="card"><p style="color: var(--danger);">Failed to load network view: ${err.message}</p></div>`;
  }
}

window.probeNodeLive = async function(nodeId) {
  try {
    const res = await api('/api/rca/correlate', { method: 'POST', body: JSON.stringify({ nodeId }) });
    alert(`Probe complete: ${res.status || 'OK'} - ${res.message || 'Analyzed'}`);
    renderNetworkView();
  } catch (e) {
    alert(`Probe failed: ${e.message}`);
  }
};

window.runPortSweep = async function() {
  const host = document.getElementById('sweepHost').value.trim();
  const consoleBox = document.getElementById('sweepConsole');
  document.getElementById('sweepResultBox').style.display = 'block';
  consoleBox.textContent = `Scanning 23 common enterprise ports on [${host}]...`;

  try {
    const res = await api('/api/network/port-scan', { method: 'POST', body: JSON.stringify({ host }) });
    consoleBox.textContent = JSON.stringify(res, null, 2);
  } catch (e) {
    consoleBox.textContent = `Sweep failed: ${e.message}`;
  }
};

window.runTlsAudit = async function() {
  const host = document.getElementById('tlsTarget').value.trim();
  const consoleBox = document.getElementById('tlsConsole');
  document.getElementById('tlsResultBox').style.display = 'block';
  consoleBox.textContent = `Performing TLS handshake with [${host}:443]...`;

  try {
    const res = await api('/api/network/tls-audit', { method: 'POST', body: JSON.stringify({ host, port: 443 }) });
    consoleBox.textContent = JSON.stringify(res, null, 2);
  } catch (e) {
    consoleBox.textContent = `TLS audit failed: ${e.message}`;
  }
};

/**
 * VIEW: System Administrator
 */
async function renderSysadminView() {
  const container = document.getElementById('mainContent');
  container.innerHTML = `<div style="color: var(--text-muted);">Querying live operating system hardware telemetry...</div>`;

  try {
    const [host, services, processes, events] = await Promise.all([
      api('/api/system/host'),
      api('/api/system/services'),
      api('/api/system/processes?limit=15'),
      api('/api/system/events?limit=10')
    ]);

    container.innerHTML = `
      <!-- Hardware Telemetry Meters -->
      <div class="grid-3">
        <!-- CPU Card -->
        <div class="card">
          <div class="card-header">
            <div class="card-title">🖥️ Processor (CPU)</div>
          </div>
          <div class="metric-large">${host.cpu.loadPercentage}%</div>
          <div class="progress-bar-container">
            <div class="progress-fill" style="width: ${host.cpu.loadPercentage}%;"></div>
          </div>
          <div class="metric-sub">${host.cpu.model} (${host.cpu.cores} Cores)</div>
        </div>

        <!-- Memory Card -->
        <div class="card">
          <div class="card-header">
            <div class="card-title">🧠 Physical Memory (RAM)</div>
          </div>
          <div class="metric-large">${host.memory.usedPercentage}%</div>
          <div class="progress-bar-container">
            <div class="progress-fill" style="width: ${host.memory.usedPercentage}%;"></div>
          </div>
          <div class="metric-sub">${host.memory.usedFormatted} used of ${host.memory.totalFormatted}</div>
        </div>

        <!-- Storage Card -->
        <div class="card">
          <div class="card-header">
            <div class="card-title">💾 Storage Volumes</div>
          </div>
          ${host.disks.map(d => `
            <div style="margin-bottom: 8px;">
              <div style="display: flex; justify-content: space-between; font-size: 12px;">
                <span>${d.mount} (${d.volumeName})</span>
                <span>${d.usedPercentage}% (${d.freeFormatted} free)</span>
              </div>
              <div class="progress-bar-container">
                <div class="progress-fill" style="width: ${d.usedPercentage}%; background-color: ${d.usedPercentage > 85 ? 'var(--danger)' : 'var(--accent)'};"></div>
              </div>
            </div>
          `).join('')}
        </div>
      </div>

      <!-- Top Processes Table -->
      <div class="card" style="margin-bottom: 20px;">
        <div class="card-header">
          <div class="card-title">📊 Top Running Processes (Live Windows Kernel)</div>
        </div>
        <div class="table-responsive">
          <table class="table">
            <thead>
              <tr>
                <th>PID</th>
                <th>Process Name</th>
                <th>Working Set RAM</th>
                <th>CPU Seconds</th>
                <th>Safety Guard</th>
              </tr>
            </thead>
            <tbody>
              ${processes.processes.map(p => `
                <tr>
                  <td><code>${p.pid}</code></td>
                  <td><strong>${p.name}</strong></td>
                  <td>${p.workingSetMB} MB</td>
                  <td>${p.cpuSeconds}s</td>
                  <td>
                    ${['csrss', 'lsass', 'services', 'explorer', 'system', 'wininit', 'node'].includes(p.name.toLowerCase())
                      ? '<span class="badge badge-healthy">Protected Kernel</span>'
                      : '<span class="badge badge-open">Remediable</span>'}
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>

      <!-- System Services & Event Logs -->
      <div class="grid-2">
        <div class="card">
          <div class="card-header">
            <div class="card-title">⚙️ Windows Services (${services.count} Discovered)</div>
          </div>
          <div style="max-height: 280px; overflow-y: auto;">
            <table class="table">
              <thead><tr><th>Service</th><th>State</th><th>Action</th></tr></thead>
              <tbody>
                ${services.services.slice(0, 15).map(s => `
                  <tr>
                    <td><strong>${s.name}</strong><br><span style="font-size: 11px; color: var(--text-dim);">${s.displayName}</span></td>
                    <td><span class="badge badge-${s.status === 'Running' ? 'healthy' : 'warning'}">${s.status}</span></td>
                    <td>
                      <button class="btn btn-secondary" style="padding: 2px 6px; font-size: 11px;" onclick="requestServiceRestart('${s.name}')">Restart</button>
                    </td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            <div class="card-title">📜 Windows Event Log (System Errors)</div>
          </div>
          <div style="max-height: 280px; overflow-y: auto;">
            ${events.events.length === 0
              ? '<p style="color: var(--text-muted);">No recent error events found in System log.</p>'
              : events.events.map(e => `
                <div style="border-bottom: 1px solid var(--border-color); padding: 8px 0;">
                  <div style="display: flex; justify-content: space-between; font-size: 11px; color: var(--text-dim);">
                    <span>${e.provider} (ID: ${e.id})</span>
                    <span>${new Date(e.timestamp).toLocaleTimeString()}</span>
                  </div>
                  <div style="font-size: 12px; color: var(--text-main); margin-top: 4px;">${e.message}</div>
                </div>
              `).join('')}
          </div>
        </div>
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<div class="card"><p style="color: var(--danger);">Failed to load system view: ${err.message}</p></div>`;
  }
}

window.requestServiceRestart = async function(serviceName) {
  try {
    const res = await api('/api/automation/request', {
      method: 'POST',
      body: JSON.stringify({
        actionType: 'restart_service',
        targetHost: 'localhost',
        targetResource: serviceName
      })
    });
    alert(`Automation Request Created: ${res.actionId}\nTier: ${res.tier}\nApproval Required: ${res.requiresApproval}\nStatus: Placed in Application Owner Approval Queue.`);
  } catch (e) {
    alert(`Request failed: ${e.message}`);
  }
};

/**
 * VIEW: Root Cause Analysis (RCA) Hub
 */
async function renderRcaView() {
  const container = document.getElementById('mainContent');
  container.innerHTML = `<div style="color: var(--text-muted);">Loading RCA Incidents...</div>`;

  try {
    const res = await api('/api/rca/incidents');
    const incidents = res.incidents || [];

    container.innerHTML = `
      <div class="card">
        <div class="card-header">
          <div class="card-title">⚡ Incident Correlation & Root Cause Investigations (${incidents.length})</div>
        </div>

        ${incidents.length === 0 ? '<p style="color: var(--text-muted);">Zero active infrastructure incidents. All monitored nodes are healthy.</p>' : `
          <div class="table-responsive">
            <table class="table">
              <thead>
                <tr>
                  <th>Incident ID</th>
                  <th>Severity</th>
                  <th>Primary Node</th>
                  <th>Title</th>
                  <th>Suppressed Alarms</th>
                  <th>Detected At</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                ${incidents.map(inc => `
                  <tr>
                    <td><code>${inc.id}</code></td>
                    <td><span class="badge badge-critical">${inc.severity}</span></td>
                    <td><strong>${inc.node_name}</strong></td>
                    <td>${inc.title}</td>
                    <td><span class="badge badge-warning">${inc.suppressed_count} Alarms Suppressed</span></td>
                    <td>${new Date(inc.detected_at).toLocaleTimeString()}</td>
                    <td><span class="badge badge-${inc.status === 'resolved' ? 'healthy' : 'critical'}">${inc.status}</span></td>
                    <td>
                      <button class="btn btn-primary" style="padding: 2px 8px; font-size: 11px;" onclick="inspectIncidentModal('${inc.id}')">Inspect RCA</button>
                    </td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        `}
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<div class="card"><p style="color: var(--danger);">Failed to load RCA incidents: ${err.message}</p></div>`;
  }
}

window.inspectIncidentModal = async function(incidentId) {
  try {
    const res = await api(`/api/rca/incidents/${incidentId}`);
    const inc = res.incident;

    const modal = document.getElementById('modalContainer');
    modal.style.display = 'flex';
    modal.innerHTML = `
      <div class="modal-overlay" onclick="closeModal(event)">
        <div class="modal-dialog" onclick="event.stopPropagation()">
          <div class="modal-header">
            <div class="card-title">🔎 Root Cause Investigation: ${inc.id}</div>
            <button class="btn-logout" onclick="closeModal()">✕</button>
          </div>
          <div class="modal-body">
            <div style="margin-bottom: 12px;">
              <span class="badge badge-critical">${inc.severity}</span>
              <span class="badge badge-warning">${inc.suppressed_count} Secondary Symptoms Suppressed</span>
            </div>
            
            <h4 style="color: var(--accent); margin-bottom: 4px;">What Happened</h4>
            <p style="color: var(--text-main); margin-bottom: 14px;">${inc.what_happened}</p>

            <h4 style="color: #fbbf24; margin-bottom: 4px;">Identified Root Cause</h4>
            <p style="color: var(--text-main); margin-bottom: 14px;">${inc.root_cause}</p>

            <h4 style="color: #a7f3d0; margin-bottom: 4px;">Supporting Evidence (Telemetry)</h4>
            <div class="console-box" style="margin-bottom: 14px;">${inc.supporting_evidence}</div>

            <h4 style="color: #38bdf8; margin-bottom: 4px;">Recommended Remediation Plan</h4>
            <p style="white-space: pre-line; color: var(--text-muted);">${inc.remediation_plan}</p>
          </div>
          <div class="modal-footer">
            ${inc.status !== 'resolved' ? `
              <button class="btn btn-success" onclick="resolveIncidentAction('${inc.id}')">Mark Incident Resolved</button>
            ` : '<span style="color: var(--success); font-weight: 600;">Incident is Resolved</span>'}
            <button class="btn btn-secondary" onclick="closeModal()">Close</button>
          </div>
        </div>
      </div>
    `;
  } catch (e) {
    alert(`Failed to load incident details: ${e.message}`);
  }
};

window.resolveIncidentAction = async function(incidentId) {
  try {
    await api(`/api/rca/incidents/${incidentId}/resolve`, {
      method: 'POST',
      body: JSON.stringify({ notes: 'Resolved by operator via EJII UI.' })
    });
    alert('Incident marked as resolved.');
    closeModal();
    renderRcaView();
    loadTopbarStats();
  } catch (e) {
    alert(`Resolve failed: ${e.message}`);
  }
};

/**
 * VIEW: Safe Automation
 */
async function renderAutomationView() {
  const container = document.getElementById('mainContent');
  container.innerHTML = `<div style="color: var(--text-muted);">Loading Automation Engine...</div>`;

  try {
    const res = await api('/api/automation/actions');
    const actions = res.actions || [];

    container.innerHTML = `
      <div class="grid-2" style="margin-bottom: 20px;">
        <!-- Submit Action -->
        <div class="card">
          <div class="card-header">
            <div class="card-title">⚡ Safe Remediation Playbook Dispatcher</div>
          </div>
          <div class="form-group">
            <label class="form-label">Remediation Action Type</label>
            <select class="form-select" id="autoActionType">
              <option value="flush_dns">Flush DNS Client Resolver Cache (Tier 2 - Safe)</option>
              <option value="restart_service">Restart System Service (Tier 3 - Dual Approval)</option>
              <option value="kill_process">Terminate Rogue Process by PID (Tier 3 - Guarded)</option>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">Target Resource Name or PID</label>
            <input type="text" class="form-input" id="autoTargetResource" value="Spooler" placeholder="e.g. Spooler or PID">
          </div>
          <div class="form-group" style="display: flex; align-items: center; gap: 8px;">
            <input type="checkbox" id="autoDryRun">
            <label for="autoDryRun" style="font-size: 13px; color: var(--text-main); cursor: pointer;">Execute as Dry-Run (Simulation Plan Only)</label>
          </div>
          <button class="btn btn-primary" onclick="submitAutomation()">Submit Remediation Action</button>
        </div>

        <!-- Safety Architecture Card -->
        <div class="card">
          <div class="card-header">
            <div class="card-title">🛡️ Safety Guardrails Architecture</div>
          </div>
          <ul style="color: var(--text-dim); padding-left: 20px; font-size: 12px; display: flex; flex-direction: column; gap: 8px;">
            <li><strong>Protected Kernel Isolation:</strong> Calls targeting core system processes (<code>csrss</code>, <code>lsass</code>, <code>services</code>, <code>wininit</code>, PID 4) are physically rejected before execution.</li>
            <li><strong>Tier 3 Dual-Custody Approval Gate:</strong> High-impact actions are held in <code>pending_approval</code> until authorized by an Application Owner.</li>
            <li><strong>Cryptographic Execution Trail:</strong> Every invocation appends an HMAC-SHA256 record to the immutable audit log.</li>
          </ul>
        </div>
      </div>

      <!-- Action History -->
      <div class="card">
        <div class="card-header">
          <div class="card-title">📜 Automation Queue & Execution History</div>
        </div>
        <div class="table-responsive">
          <table class="table">
            <thead>
              <tr>
                <th>Action ID</th>
                <th>Type</th>
                <th>Tier</th>
                <th>Resource</th>
                <th>Requester</th>
                <th>Approval</th>
                <th>Execution</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              ${actions.map(a => `
                <tr>
                  <td><code>${a.id}</code></td>
                  <td><strong>${a.action_type}</strong></td>
                  <td><span class="badge badge-open">Tier ${a.tier}</span></td>
                  <td><code>${a.target_resource}</code></td>
                  <td>${a.requester_username} (${a.requested_by_role})</td>
                  <td><span class="badge badge-${a.approval_status === 'approved' ? 'healthy' : (a.approval_status === 'pending_approval' ? 'warning' : 'open')}">${a.approval_status}</span></td>
                  <td><span class="badge badge-${a.execution_status === 'success' ? 'healthy' : (a.execution_status === 'failed' ? 'critical' : 'warning')}">${a.execution_status}</span></td>
                  <td>
                    ${a.approval_status !== 'pending_approval' && a.execution_status === 'queued' ? `
                      <button class="btn btn-primary" style="padding: 2px 8px; font-size: 11px;" onclick="runExecuteAction('${a.id}')">Execute</button>
                    ` : '<span style="color: var(--text-dim); font-size: 11px;">Completed/Gated</span>'}
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<div class="card"><p style="color: var(--danger);">Failed to load automation view: ${err.message}</p></div>`;
  }
}

window.submitAutomation = async function() {
  const actionType = document.getElementById('autoActionType').value;
  const targetResource = document.getElementById('autoTargetResource').value.trim();
  const dryRun = document.getElementById('autoDryRun').checked;

  try {
    const res = await api('/api/automation/request', {
      method: 'POST',
      body: JSON.stringify({ actionType, targetResource, dryRun })
    });
    alert(`Automation Dispatched: ${res.actionId}\nTier: ${res.tier}\nApproval Required: ${res.requiresApproval}\nPlan: ${res.dryRunPlan}`);
    renderAutomationView();
  } catch (e) {
    alert(`Automation submission rejected: ${e.message}`);
  }
};

window.runExecuteAction = async function(actionId) {
  try {
    const res = await api(`/api/automation/actions/${actionId}/execute`, { method: 'POST' });
    alert(`Execution Complete: Result: ${res.success ? 'SUCCESS' : 'FAILED'}\nOutput: ${res.output || res.error}`);
    renderAutomationView();
  } catch (e) {
    alert(`Execution failed: ${e.message}`);
  }
};

/**
 * VIEW: Application Owner Governance
 */
async function renderAppOwnerView() {
  const container = document.getElementById('mainContent');
  container.innerHTML = `<div style="color: var(--text-muted);">Loading Governance & Cryptographic Audit Trail...</div>`;

  try {
    const [auditRes, actionsRes, usersRes, healthRes] = await Promise.all([
      api('/api/admin/audit-logs?limit=15'),
      api('/api/automation/actions'),
      api('/api/admin/users'),
      api('/api/admin/system-health')
    ]);

    const pendingApprovals = (actionsRes.actions || []).filter(a => a.approval_status === 'pending_approval');

    container.innerHTML = `
      <!-- Pending Approvals (Dual-Custody Gate) -->
      <div class="card" style="margin-bottom: 20px; border-left: 4px solid var(--warning);">
        <div class="card-header">
          <div class="card-title">⏳ Dual-Custody Approval Gate (${pendingApprovals.length} Pending)</div>
        </div>
        ${pendingApprovals.length === 0 ? '<p style="color: var(--text-muted);">No pending remediation actions requiring authorization.</p>' : `
          <div class="table-responsive">
            <table class="table">
              <thead>
                <tr>
                  <th>Action ID</th>
                  <th>Action</th>
                  <th>Resource</th>
                  <th>Requester</th>
                  <th>Time</th>
                  <th>Decision</th>
                </tr>
              </thead>
              <tbody>
                ${pendingApprovals.map(p => `
                  <tr>
                    <td><code>${p.id}</code></td>
                    <td><strong>${p.action_type}</strong></td>
                    <td><code>${p.target_resource}</code></td>
                    <td>${p.requester_username}</td>
                    <td>${new Date(p.requested_at).toLocaleTimeString()}</td>
                    <td>
                      <button class="btn btn-success" style="padding: 2px 8px; font-size: 11px;" onclick="reviewActionDecision('${p.id}', true)">Approve</button>
                      <button class="btn btn-danger" style="padding: 2px 8px; font-size: 11px;" onclick="reviewActionDecision('${p.id}', false)">Reject</button>
                    </td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        `}
      </div>

      <!-- Audit Trail & Integrity Check -->
      <div class="card" style="margin-bottom: 20px;">
        <div class="card-header">
          <div class="card-title">🛡️ Cryptographic Tamper-Evident Audit Trail (HMAC-SHA256)</div>
          <button class="btn btn-primary" onclick="verifyAuditIntegrityLive()">Verify Hash Chain Integrity</button>
        </div>
        <div id="auditVerifyStatusBox" style="display: none; padding: 10px; margin-bottom: 12px; border-radius: 6px;"></div>
        <div class="table-responsive">
          <table class="table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Timestamp</th>
                <th>User</th>
                <th>Role</th>
                <th>Action</th>
                <th>Resource</th>
                <th>HMAC-SHA256 Chain Hash</th>
              </tr>
            </thead>
            <tbody>
              ${auditRes.logs.map(l => `
                <tr>
                  <td>${l.id}</td>
                  <td style="font-size: 11px; color: var(--text-dim);">${new Date(l.timestamp).toLocaleTimeString()}</td>
                  <td><strong>${l.username || 'System'}</strong></td>
                  <td><span class="user-role-tag role-${l.role}">${l.role}</span></td>
                  <td><code>${l.action}</code></td>
                  <td>${l.resource}</td>
                  <td><code style="font-size: 10px; color: #a5f3fc;">${l.hash.slice(0, 16)}...${l.hash.slice(-8)}</code></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>

      <!-- User Management & System Health -->
      <div class="grid-2">
        <div class="card">
          <div class="card-header">
            <div class="card-title">👥 User & Role Administration (${usersRes.count})</div>
          </div>
          <table class="table">
            <thead><tr><th>Username</th><th>Full Name</th><th>Role</th><th>Status</th></tr></thead>
            <tbody>
              ${usersRes.users.map(u => `
                <tr>
                  <td><strong>${u.username}</strong></td>
                  <td>${u.full_name}</td>
                  <td><span class="user-role-tag role-${u.role}">${u.role}</span></td>
                  <td><span class="badge badge-${u.is_active ? 'healthy' : 'critical'}">${u.is_active ? 'Active' : 'Disabled'}</span></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>

        <div class="card">
          <div class="card-header">
            <div class="card-title">⚙️ EJII Platform Health</div>
          </div>
          <div class="grid-2" style="margin-bottom: 12px;">
            <div>
              <div class="metric-large">${healthRes.memory.rssMb} MB</div>
              <div class="metric-sub">Process RSS Memory</div>
            </div>
            <div>
              <div class="metric-large">${healthRes.database.sizeFormatted}</div>
              <div class="metric-sub">SQLite Database Size</div>
            </div>
          </div>
          <div style="font-size: 12px; color: var(--text-dim);">
            <div>Node Version: ${healthRes.nodeVersion}</div>
            <div>Daemon Uptime: ${healthRes.uptimeSeconds} seconds</div>
            <div>Total Audit Entries: ${healthRes.database.totalAuditRecords}</div>
          </div>
        </div>
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<div class="card"><p style="color: var(--danger);">Failed to load App Owner view: ${err.message}</p></div>`;
  }
}

window.reviewActionDecision = async function(actionId, approved) {
  const comment = prompt(`Enter ${approved ? 'Approval' : 'Rejection'} audit notes:`, approved ? 'Authorized by Application Owner.' : 'Rejected.');
  if (comment === null) return;

  try {
    await api(`/api/automation/actions/${actionId}/review`, {
      method: 'POST',
      body: JSON.stringify({ approved, comment })
    });
    alert(`Action ${approved ? 'Approved' : 'Rejected'}.`);
    renderAppOwnerView();
  } catch (e) {
    alert(`Review failed: ${e.message}`);
  }
};

window.verifyAuditIntegrityLive = async function() {
  const box = document.getElementById('auditVerifyStatusBox');
  box.style.display = 'block';
  box.textContent = 'Verifying sequential SHA-256 HMAC hash links...';
  box.style.backgroundColor = 'rgba(56, 189, 248, 0.15)';
  box.style.color = '#38bdf8';

  try {
    const res = await api('/api/admin/audit-verify');
    if (res.valid) {
      box.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
      box.style.color = '#34d399';
      box.textContent = `✓ ${res.message} (Zero records altered or deleted)`;
    } else {
      box.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
      box.style.color = '#f87171';
      box.textContent = `❌ ${res.message}`;
    }
  } catch (e) {
    box.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
    box.style.color = '#f87171';
    box.textContent = `Verification error: ${e.message}`;
  }
};

window.closeModal = function() {
  document.getElementById('modalContainer').style.display = 'none';
};

/**
 * 14-Tool Unified Subsystems Hub View
 */
function renderToolsView() {
  const container = document.getElementById('mainContent');
  container.innerHTML = `
    <div style="display: flex; flex-direction: column; gap: 1.5rem;">
      <div class="panel" style="background: linear-gradient(135deg, rgba(30, 41, 59, 0.7), rgba(15, 23, 42, 0.9)); border: 1px solid var(--border);">
        <div class="panel-header">
          <div class="panel-title">🛠️ 14-Tool Integrated Intelligence Engine</div>
          <span class="user-role-tag" style="background: var(--accent); color: #000;">Zero-Simulation Active</span>
        </div>
        <p style="color: var(--text-muted); font-size: 0.9rem; margin-top: 0.5rem;">
          EJII natively subsumes the capabilities of Wireshark, Nmap, PuTTY, Sysinternals, Advanced IP Scanner, iPerf, Netcat, Fiddler, Nagios, Cisco Packet Tracer, BleachBit, HWiNFO, FileZilla, and MTR into a unified operating-system and protocol intelligence engine.
        </p>
      </div>

      <!-- Grid of Tool Actions -->
      <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 1.25rem;">
        
        <!-- 1. Wireshark -->
        <div class="panel">
          <div class="panel-title">🦈 Wireshark Packet Dissector</div>
          <p style="color: var(--text-muted); font-size: 0.85rem; margin: 0.5rem 0;">Decodes L2 Ethernet II, L3 IPv4/IPv6, L4 TCP/UDP, and L7 HTTP/DNS frame payloads.</p>
          <button class="btn btn-primary" style="width: 100%; margin-top: 0.5rem;" onclick="runWiresharkDemo()">Dissect Sample Packet</button>
          <div id="wiresharkResult" style="margin-top: 0.75rem;"></div>
        </div>

        <!-- 2. Nmap -->
        <div class="panel">
          <div class="panel-title">🛡️ Nmap Security & OS Audit</div>
          <p style="color: var(--text-muted); font-size: 0.85rem; margin: 0.5rem 0;">TCP Connect scanning (-sT), service version probe (-sV), and OS stack fingerprinting (-O).</p>
          <div style="display: flex; gap: 0.5rem; margin-top: 0.5rem;">
            <input type="text" id="nmapTarget" class="input" value="127.0.0.1" style="flex: 1;" placeholder="Target IP">
            <button class="btn btn-primary" onclick="runNmapTool()">Scan Host</button>
          </div>
          <div id="nmapResult" style="margin-top: 0.75rem;"></div>
        </div>

        <!-- 3. Sysinternals -->
        <div class="panel">
          <div class="panel-title">⚙️ Sysinternals & TCPView</div>
          <p style="color: var(--text-muted); font-size: 0.85rem; margin: 0.5rem 0;">Process tree hierarchy (PPID &rarr; PID DAG) and TCPView live socket-to-process table.</p>
          <div style="display: flex; gap: 0.5rem; margin-top: 0.5rem;">
            <button class="btn btn-primary" style="flex: 1;" onclick="runSysinternalsTree()">Process Tree</button>
            <button class="btn btn-secondary" style="flex: 1;" onclick="runSysinternalsTcpView()">TCPView</button>
          </div>
          <div id="sysinternalsResult" style="margin-top: 0.75rem;"></div>
        </div>

        <!-- 4. Advanced IP Scanner -->
        <div class="panel">
          <div class="panel-title">📡 Advanced IP Subnet Scanner</div>
          <p style="color: var(--text-muted); font-size: 0.85rem; margin: 0.5rem 0;">Subnet sweep with live ARP table polling and IEEE MAC OUI vendor resolution.</p>
          <div style="display: flex; gap: 0.5rem; margin-top: 0.5rem;">
            <input type="text" id="ipScanSubnet" class="input" value="127.0.0" style="flex: 1;" placeholder="Subnet (e.g. 192.168.1)">
            <button class="btn btn-primary" onclick="runIpScannerTool()">Sweep</button>
            <button class="btn btn-secondary" onclick="runArpTableTool()">ARP Table</button>
          </div>
          <div id="ipScannerResult" style="margin-top: 0.75rem;"></div>
        </div>

        <!-- 5. iPerf Benchmarking -->
        <div class="panel">
          <div class="panel-title">⚡ iPerf Bandwidth & Jitter</div>
          <p style="color: var(--text-muted); font-size: 0.85rem; margin: 0.5rem 0;">Active TCP socket bandwidth saturation and UDP RFC 3550 interarrival jitter benchmark.</p>
          <div style="display: flex; gap: 0.5rem; margin-top: 0.5rem;">
            <button class="btn btn-primary" style="flex: 1;" onclick="runIperfTcpTool()">TCP Throughput</button>
            <button class="btn btn-secondary" style="flex: 1;" onclick="runIperfUdpTool()">UDP Jitter</button>
          </div>
          <div id="iperfResult" style="margin-top: 0.75rem;"></div>
        </div>

        <!-- 6. Netcat Socket Hub -->
        <div class="panel">
          <div class="panel-title">🔌 Netcat (nc) Socket Hub</div>
          <p style="color: var(--text-muted); font-size: 0.85rem; margin: 0.5rem 0;">Raw TCP/UDP socket streaming, port listener, and raw banner grabbing.</p>
          <div style="display: flex; gap: 0.5rem; margin-top: 0.5rem;">
            <input type="text" id="ncHost" class="input" value="127.0.0.1" style="flex: 2;" placeholder="Host">
            <input type="number" id="ncPort" class="input" value="8443" style="flex: 1;" placeholder="Port">
            <button class="btn btn-primary" onclick="runNetcatTool()">Connect</button>
          </div>
          <div id="netcatResult" style="margin-top: 0.75rem;"></div>
        </div>

        <!-- 7. Cisco Packet Tracer -->
        <div class="panel">
          <div class="panel-title">🌐 Cisco Packet Tracer L2/L3</div>
          <p style="color: var(--text-muted); font-size: 0.85rem; margin: 0.5rem 0;">L2/L3 route path evaluation, longest prefix match, and ARP next-hop resolution stepper.</p>
          <div style="display: flex; gap: 0.5rem; margin-top: 0.5rem;">
            <input type="text" id="ptDest" class="input" value="8.8.8.8" style="flex: 1;" placeholder="Destination IP">
            <button class="btn btn-primary" onclick="runPacketTracerTool()">Trace Path</button>
          </div>
          <div id="packetTracerResult" style="margin-top: 0.75rem;"></div>
        </div>

        <!-- 8. BleachBit System Hygiene -->
        <div class="panel">
          <div class="panel-title">🧹 BleachBit System Hygiene</div>
          <p style="color: var(--text-muted); font-size: 0.85rem; margin: 0.5rem 0;">Temporary file reclamation audit and SQLite database vacuuming.</p>
          <div style="display: flex; gap: 0.5rem; margin-top: 0.5rem;">
            <button class="btn btn-secondary" style="flex: 1;" onclick="runBleachBitAudit()">Audit Cache</button>
            <button class="btn btn-primary" style="flex: 1;" onclick="runBleachBitVacuum()">Vacuum DB</button>
          </div>
          <div id="bleachBitResult" style="margin-top: 0.75rem;"></div>
        </div>

        <!-- 9. HWiNFO & CPU-Z -->
        <div class="panel">
          <div class="panel-title">💻 HWiNFO Bare-Metal Telemetry</div>
          <p style="color: var(--text-muted); font-size: 0.85rem; margin: 0.5rem 0;">SMBIOS motherboard info, CPU core topology, RAM SPD slots, and S.M.A.R.T. disk health.</p>
          <button class="btn btn-primary" style="width: 100%; margin-top: 0.5rem;" onclick="runHwinfoTool()">Inspect Hardware</button>
          <div id="hwinfoResult" style="margin-top: 0.75rem;"></div>
        </div>

        <!-- 10. FileZilla Differential Transfer -->
        <div class="panel">
          <div class="panel-title">📁 FileZilla Differential Sync</div>
          <p style="color: var(--text-muted); font-size: 0.85rem; margin: 0.5rem 0;">SHA-256 cryptographic checksumming and differential file sync analysis.</p>
          <button class="btn btn-primary" style="width: 100%; margin-top: 0.5rem;" onclick="runFilezillaTool()">Verify Package Hashes</button>
          <div id="filezillaResult" style="margin-top: 0.75rem;"></div>
        </div>

        <!-- 11. MTR Path Analysis -->
        <div class="panel">
          <div class="panel-title">📈 MTR Multi-Hop Path Analysis</div>
          <p style="color: var(--text-muted); font-size: 0.85rem; margin: 0.5rem 0;">Continuous multi-hop path analysis with packet loss, min/avg/max RTT, and jitter per hop.</p>
          <div style="display: flex; gap: 0.5rem; margin-top: 0.5rem;">
            <input type="text" id="mtrHost" class="input" value="127.0.0.1" style="flex: 1;" placeholder="Host">
            <button class="btn btn-primary" onclick="runMtrTool()">Run MTR</button>
          </div>
          <div id="mtrResult" style="margin-top: 0.75rem;"></div>
        </div>

        <!-- 12. PuTTY Native Bridge -->
        <div class="panel">
          <div class="panel-title">🖥️ PuTTY & Native Protocol Bridge</div>
          <p style="color: var(--text-muted); font-size: 0.85rem; margin: 0.5rem 0;">One-click native launcher for Windows RDP (mstsc), OpenSSH, and PowerShell administrative consoles.</p>
          <div style="display: flex; gap: 0.5rem; margin-top: 0.5rem;">
            <button class="btn btn-primary" style="flex: 1;" onclick="runPuTTYLaunch('powershell')">PowerShell</button>
            <button class="btn btn-secondary" style="flex: 1;" onclick="runPuTTYLaunch('rdp')">RDP (mstsc)</button>
          </div>
          <div id="puttyResult" style="margin-top: 0.75rem;"></div>
        </div>

      </div>
    </div>
  `;
}

// Tool Action Handlers
window.runWiresharkDemo = async function() {
  const box = document.getElementById('wiresharkResult');
  box.innerHTML = '<div style="color: var(--accent);">Dissecting raw packet frame...</div>';
  const sampleHex = '001A11223344000C29AABBCC0800450000281234400080060000C0A80132C0A80101D431005000000001000000005002FFFF00000000';
  try {
    const res = await api('/api/tools/wireshark/dissect', { method: 'POST', body: JSON.stringify({ hexPayload: sampleHex }) });
    box.innerHTML = `
      <pre style="background: rgba(0,0,0,0.5); padding: 0.5rem; border-radius: 4px; font-size: 0.75rem; overflow-x: auto; color: #a7f3d0;">
L2: ${res.layers.ethernet?.srcMac} -> ${res.layers.ethernet?.dstMac} (${res.layers.ethernet?.etherType})
L3: ${res.layers.ipv4?.srcIp} -> ${res.layers.ipv4?.dstIp} (TTL=${res.layers.ipv4?.ttl})
L4: TCP Port ${res.layers.tcp?.srcPort} -> ${res.layers.tcp?.dstPort} [SYN=${res.layers.tcp?.flags?.syn}]
      </pre>`;
  } catch (e) {
    box.innerHTML = `<div style="color: #f87171;">Error: ${e.message}</div>`;
  }
};

window.runNmapTool = async function() {
  const host = document.getElementById('nmapTarget').value;
  const box = document.getElementById('nmapResult');
  box.innerHTML = '<div style="color: var(--accent);">Scanning host & fingerprinting OS...</div>';
  try {
    const res = await api('/api/tools/nmap/scan', { method: 'POST', body: JSON.stringify({ host, ports: [22, 80, 443, 8443] }) });
    box.innerHTML = `
      <div style="font-size: 0.8rem; background: rgba(0,0,0,0.4); padding: 0.5rem; border-radius: 4px;">
        <div><strong>OS Fingerprint:</strong> ${res.osFingerprint?.osGuess} (${res.osFingerprint?.confidencePct}%)</div>
        <div><strong>Scanned:</strong> ${res.totalPortsScanned} ports in ${res.durationMs}ms (Open: ${res.openPortsCount})</div>
      </div>`;
  } catch (e) {
    box.innerHTML = `<div style="color: #f87171;">Error: ${e.message}</div>`;
  }
};

window.runSysinternalsTree = async function() {
  const box = document.getElementById('sysinternalsResult');
  box.innerHTML = '<div style="color: var(--accent);">Enumerating process tree DAG...</div>';
  try {
    const res = await api('/api/tools/sysinternals/tree');
    box.innerHTML = `
      <div style="font-size: 0.8rem; background: rgba(0,0,0,0.4); padding: 0.5rem; border-radius: 4px;">
        <div><strong>Active Processes:</strong> ${res.totalProcesses} across ${res.rootCount} root trees</div>
        <div><strong>Top Root:</strong> ${res.tree?.[0]?.name} (PID ${res.tree?.[0]?.pid}) - ${res.tree?.[0]?.children?.length || 0} child procs</div>
      </div>`;
  } catch (e) {
    box.innerHTML = `<div style="color: #f87171;">Error: ${e.message}</div>`;
  }
};

window.runSysinternalsTcpView = async function() {
  const box = document.getElementById('sysinternalsResult');
  box.innerHTML = '<div style="color: var(--accent);">Reading TCPView socket table...</div>';
  try {
    const res = await api('/api/tools/sysinternals/tcpview');
    const first = res.connections?.[0];
    box.innerHTML = `
      <div style="font-size: 0.8rem; background: rgba(0,0,0,0.4); padding: 0.5rem; border-radius: 4px;">
        <div><strong>Mapped Sockets:</strong> ${res.count} active sockets</div>
        ${first ? `<div><strong>Sample:</strong> [${first.proto}] ${first.local} &rarr; ${first.proc} (PID ${first.pid})</div>` : ''}
      </div>`;
  } catch (e) {
    box.innerHTML = `<div style="color: #f87171;">Error: ${e.message}</div>`;
  }
};

window.runIpScannerTool = async function() {
  const base = document.getElementById('ipScanSubnet').value;
  const box = document.getElementById('ipScannerResult');
  box.innerHTML = '<div style="color: var(--accent);">Sweeping subnet...</div>';
  try {
    const res = await api('/api/tools/ipscanner/sweep', { method: 'POST', body: JSON.stringify({ subnetBase: base, start: 1, end: 15 }) });
    box.innerHTML = `
      <div style="font-size: 0.8rem; background: rgba(0,0,0,0.4); padding: 0.5rem; border-radius: 4px;">
        <div><strong>Scanned:</strong> ${res.totalScanned} hosts in ${res.durationMs}ms</div>
        <div><strong>Discovered:</strong> ${res.discoveredCount} active hosts</div>
      </div>`;
  } catch (e) {
    box.innerHTML = `<div style="color: #f87171;">Error: ${e.message}</div>`;
  }
};

window.runArpTableTool = async function() {
  const box = document.getElementById('ipScannerResult');
  box.innerHTML = '<div style="color: var(--accent);">Reading host ARP cache...</div>';
  try {
    const res = await api('/api/tools/ipscanner/arp');
    box.innerHTML = `
      <div style="font-size: 0.8rem; background: rgba(0,0,0,0.4); padding: 0.5rem; border-radius: 4px;">
        <div><strong>ARP Cache Entries:</strong> ${res.count} cached hardware bindings</div>
        ${res.table?.[0] ? `<div><strong>Sample:</strong> ${res.table[0].ip} &rarr; ${res.table[0].mac} (${res.table[0].vendor})</div>` : ''}
      </div>`;
  } catch (e) {
    box.innerHTML = `<div style="color: #f87171;">Error: ${e.message}</div>`;
  }
};

window.runIperfTcpTool = async function() {
  const box = document.getElementById('iperfResult');
  box.innerHTML = '<div style="color: var(--accent);">Running TCP saturation benchmark...</div>';
  try {
    const res = await api('/api/tools/iperf/tcp', { method: 'POST', body: JSON.stringify({ durationSeconds: 1 }) });
    box.innerHTML = `
      <div style="font-size: 0.8rem; background: rgba(0,0,0,0.4); padding: 0.5rem; border-radius: 4px;">
        <div style="color: #34d399; font-weight: bold;">Throughput: ${res.throughputMbps} Mbps</div>
        <div>Transferred: ${res.megabytesTransferred} MB in ${res.durationSeconds}s</div>
      </div>`;
  } catch (e) {
    box.innerHTML = `<div style="color: #f87171;">Error: ${e.message}</div>`;
  }
};

window.runIperfUdpTool = async function() {
  const box = document.getElementById('iperfResult');
  box.innerHTML = '<div style="color: var(--accent);">Calculating RFC 3550 UDP jitter...</div>';
  try {
    const res = await api('/api/tools/iperf/udp', { method: 'POST', body: JSON.stringify({ packets: 30 }) });
    box.innerHTML = `
      <div style="font-size: 0.8rem; background: rgba(0,0,0,0.4); padding: 0.5rem; border-radius: 4px;">
        <div style="color: #38bdf8;">RFC 3550 Jitter: ${res.rfc3550JitterMs} ms</div>
        <div>Packets: ${res.packetsReceived}/${res.packetsSent} (Loss: ${res.packetLossPct}%)</div>
      </div>`;
  } catch (e) {
    box.innerHTML = `<div style="color: #f87171;">Error: ${e.message}</div>`;
  }
};

window.runNetcatTool = async function() {
  const host = document.getElementById('ncHost').value;
  const port = document.getElementById('ncPort').value;
  const box = document.getElementById('netcatResult');
  box.innerHTML = '<div style="color: var(--accent);">Piping raw socket...</div>';
  try {
    const res = await api('/api/tools/netcat/tcp', { method: 'POST', body: JSON.stringify({ host, port: parseInt(port, 10), payload: 'GET / HTTP/1.0' }) });
    box.innerHTML = `
      <div style="font-size: 0.8rem; background: rgba(0,0,0,0.4); padding: 0.5rem; border-radius: 4px;">
        <div><strong>Status:</strong> ${res.success ? 'Connected' : 'Refused / Timeout'} (${res.latencyMs}ms)</div>
        <div><strong>Bytes Received:</strong> ${res.receivedBytes}</div>
      </div>`;
  } catch (e) {
    box.innerHTML = `<div style="color: #f87171;">Error: ${e.message}</div>`;
  }
};

window.runPacketTracerTool = async function() {
  const dest = document.getElementById('ptDest').value;
  const box = document.getElementById('packetTracerResult');
  box.innerHTML = '<div style="color: var(--accent);">Stepping L2/L3 packet path...</div>';
  try {
    const res = await api('/api/tools/packet-tracer/trace', { method: 'POST', body: JSON.stringify({ destinationIp: dest }) });
    box.innerHTML = `
      <div style="font-size: 0.8rem; background: rgba(0,0,0,0.4); padding: 0.5rem; border-radius: 4px;">
        <div><strong>Route Match:</strong> ${res.matchedRoute?.prefix} (Interface: ${res.matchedRoute?.interface})</div>
        <div><strong>Next-Hop:</strong> ${res.nextHop} [MAC: ${res.nextHopMac}]</div>
        <div><strong>Steps Evaluated:</strong> ${res.traversalSteps?.length} steps</div>
      </div>`;
  } catch (e) {
    box.innerHTML = `<div style="color: #f87171;">Error: ${e.message}</div>`;
  }
};

window.runBleachBitAudit = async function() {
  const box = document.getElementById('bleachBitResult');
  box.innerHTML = '<div style="color: var(--accent);">Auditing reclaimable cache...</div>';
  try {
    const res = await api('/api/tools/bleachbit/audit');
    box.innerHTML = `
      <div style="font-size: 0.8rem; background: rgba(0,0,0,0.4); padding: 0.5rem; border-radius: 4px;">
        <div style="color: #34d399;">Reclaimable: ${res.totalReclaimableFormatted}</div>
        <div>Categories Audited: ${res.categories?.length}</div>
      </div>`;
  } catch (e) {
    box.innerHTML = `<div style="color: #f87171;">Error: ${e.message}</div>`;
  }
};

window.runBleachBitVacuum = async function() {
  const box = document.getElementById('bleachBitResult');
  box.innerHTML = '<div style="color: var(--accent);">Vacuuming SQLite database...</div>';
  try {
    const res = await api('/api/tools/bleachbit/vacuum', { method: 'POST' });
    box.innerHTML = `
      <div style="font-size: 0.8rem; background: rgba(0,0,0,0.4); padding: 0.5rem; border-radius: 4px; color: #34d399;">
        ✓ ${res.message} (DB Size: ${res.sizeAfterFormatted})
      </div>`;
  } catch (e) {
    box.innerHTML = `<div style="color: #f87171;">Error: ${e.message}</div>`;
  }
};

window.runHwinfoTool = async function() {
  const box = document.getElementById('hwinfoResult');
  box.innerHTML = '<div style="color: var(--accent);">Querying CIM hardware sensors...</div>';
  try {
    const res = await api('/api/tools/hwinfo/telemetry');
    box.innerHTML = `
      <div style="font-size: 0.8rem; background: rgba(0,0,0,0.4); padding: 0.5rem; border-radius: 4px;">
        <div><strong>CPU:</strong> ${res.cpu?.name} (${res.cpu?.physicalCores} Cores / ${res.cpu?.logicalThreads} Threads)</div>
        <div><strong>RAM:</strong> ${res.memory?.totalCapacityGB} GB across ${res.memory?.modulesCount} slot(s)</div>
        <div><strong>Board:</strong> ${res.motherboard?.motherboardVendor} ${res.motherboard?.motherboardModel}</div>
      </div>`;
  } catch (e) {
    box.innerHTML = `<div style="color: #f87171;">Error: ${e.message}</div>`;
  }
};

window.runFilezillaTool = async function() {
  const box = document.getElementById('filezillaResult');
  box.innerHTML = '<div style="color: var(--accent);">Computing SHA-256 hashes...</div>';
  try {
    const res = await api('/api/tools/filezilla/compare', { method: 'POST', body: JSON.stringify({ sourceFile: 'package.json', destFile: 'package.json' }) });
    box.innerHTML = `
      <div style="font-size: 0.8rem; background: rgba(0,0,0,0.4); padding: 0.5rem; border-radius: 4px;">
        <div><strong>Status:</strong> ${res.status}</div>
        <div style="word-break: break-all;"><strong>SHA-256:</strong> ${res.sourceHash}</div>
      </div>`;
  } catch (e) {
    box.innerHTML = `<div style="color: #f87171;">Error: ${e.message}</div>`;
  }
};

window.runMtrTool = async function() {
  const host = document.getElementById('mtrHost').value;
  const box = document.getElementById('mtrResult');
  box.innerHTML = '<div style="color: var(--accent);">Running multi-hop MTR trace...</div>';
  try {
    const res = await api('/api/tools/mtr/run', { method: 'POST', body: JSON.stringify({ host, cycles: 2 }) });
    const first = res.table?.[0];
    box.innerHTML = `
      <div style="font-size: 0.8rem; background: rgba(0,0,0,0.4); padding: 0.5rem; border-radius: 4px;">
        <div><strong>Hops Analyzed:</strong> ${res.totalHops}</div>
        ${first ? `<div><strong>Hop 1:</strong> ${first.ip} - Loss: ${first.lossPct}% (Avg RTT: ${first.avgRttMs}ms)</div>` : ''}
      </div>`;
  } catch (e) {
    box.innerHTML = `<div style="color: #f87171;">Error: ${e.message}</div>`;
  }
};

window.runPuTTYLaunch = async function(tool) {
  const box = document.getElementById('puttyResult');
  box.innerHTML = `<div style="color: var(--accent);">Spawning native ${tool}...</div>`;
  try {
    const res = await api('/api/tools/putty/launch', { method: 'POST', body: JSON.stringify({ tool, target: '127.0.0.1' }) });
    box.innerHTML = `<div style="font-size: 0.8rem; color: #34d399; margin-top: 0.5rem;">✓ ${res.message}</div>`;
  } catch (e) {
    box.innerHTML = `<div style="color: #f87171;">Error: ${e.message}</div>`;
  }
};

// Global Navigation Listener
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.nav-link').forEach((link) => {
    link.addEventListener('click', () => {
      const view = link.dataset.view;
      renderView(view);
    });
  });

  document.getElementById('btnLogout').addEventListener('click', logout);

  initWebSocket();

  // If token exists, load user profile
  if (state.token) {
    api('/api/auth/me')
      .then(res => {
        state.user = res.user;
        updateUserBadge();
        loadTopbarStats();
        renderView(state.currentView);
      })
      .catch(() => {
        logout();
      });
  } else {
    renderLoginView();
  }
});
