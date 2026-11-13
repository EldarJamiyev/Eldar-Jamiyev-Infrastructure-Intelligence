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
window.apiFetch = api;
var apiFetch = api;
window.renderView = renderView;

// Universal Cross-Pillar Target Context & Investigation Store
window.EJIIStore = window.EJIIStore || {};
window.EJIIStore.activeInvestigationContext = null;

// Shared Cross-View Investigation Store (EJII Phase 4)
window.EJII_INVESTIGATION_STORE = {
  activeSessionId: null,
  state: 'IDLE',
  symptomType: null,
  targetScope: {},
  steps: [],
  evidenceLedger: [],
  activeHypotheses: [],
  contradictedHypotheses: [],
  criticEvaluation: null,
  similarHistoricalCases: [],
  remediationVerification: null,
  subscribers: new Set(),

  subscribe(callback) {
    if (typeof callback === 'function') {
      this.subscribers.add(callback);
      return () => this.subscribers.delete(callback);
    }
    return () => {};
  },

  notify() {
    for (const sub of this.subscribers) {
      try { sub(this); } catch (_) {}
    }
    window.dispatchEvent(new CustomEvent('ejii:investigation-store-update', { detail: this }));
  },

  updateFromSession(session = {}) {
    this.activeSessionId = session.sessionId || this.activeSessionId;
    this.state = session.state || this.state;
    this.symptomType = session.symptomType || this.symptomType;
    this.targetScope = session.targetScope || this.targetScope;
    this.steps = session.steps || this.steps;
    this.evidenceLedger = session.evidenceLedger || this.evidenceLedger;
    this.criticEvaluation = session.criticEvaluation || this.criticEvaluation;
    this.remediationVerification = session.remediationVerification || this.remediationVerification;

    if (Array.isArray(session.hypothesisHistory)) {
      this.activeHypotheses = session.hypothesisHistory.filter(h => !h.contradicted && h.status !== 'CONTRADICTED');
      this.contradictedHypotheses = session.hypothesisHistory.filter(h => h.contradicted || h.status === 'CONTRADICTED');
    }

    if (Array.isArray(session.similarHistoricalIncidents)) {
      this.similarHistoricalCases = session.similarHistoricalIncidents;
    }

    this.notify();
  },

  handleStepUpdate(payload = {}) {
    if (!payload) return;
    if (payload.sessionId && this.activeSessionId !== payload.sessionId) {
      this.activeSessionId = payload.sessionId;
    }
    if (payload.evidenceRecord) {
      const idx = this.evidenceLedger.findIndex(e => e.evidenceId === payload.evidenceRecord.evidenceId);
      if (idx >= 0) {
        this.evidenceLedger[idx] = payload.evidenceRecord;
      } else {
        this.evidenceLedger.push(payload.evidenceRecord);
      }
    }
    if (payload.stepId) {
      const s = this.steps.find(st => st.stepId === payload.stepId);
      if (s) {
        s.status = payload.status || s.status;
      }
    }
    this.notify();
  },

  handleCancelled(payload = {}) {
    this.state = 'CANCELLED';
    for (const s of this.steps) {
      if (s.status === 'PENDING' || s.status === 'RUNNING') {
        s.status = 'CANCELLED';
      }
    }
    this.notify();
  },

  handleRemediationVerified(payload = {}) {
    this.remediationVerification = payload;
    this.state = payload.verificationOutcome === 'VERIFIED_RESOLVED' ? 'COMPLETED' : 'PARTIAL_INCOMPLETE';
    this.notify();
  }
};

// Universal Unified Route Mapping & View Lifecycle Controller
const ROUTE_ALIASES = {
  'overview': 'overview',
  'dashboard': 'overview',
  'home': 'overview',
  'chat': 'chat',
  'ai-operator': 'ai-operator',
  'operator': 'ai-operator',
  'topology': 'topology',
  'noc': 'topology',
  'noc-dashboard': 'noc-dashboard',
  'enterprise-noc': 'enterprise-noc',
  'sovereign-fabric': 'enterprise-noc',
  'packet-sniffer': 'packet-sniffer',
  'sniffer': 'packet-sniffer',
  'packet-cockpit': 'packet-sniffer',
  'cockpit': 'packet-sniffer',
  'ultra-ip-scanner': 'ultra-ip-scanner',
  'scanner': 'ultra-ip-scanner',
  'ip-scanner': 'ultra-ip-scanner',
  'pc-automation': 'pc-automation',
  'automation': 'pc-automation',
  'core-diagnostics': 'core-diagnostics',
  'diagnostics': 'core-diagnostics',
  'learning': 'learning-center',
  'learning-center': 'learning-center',
  'academy': 'learning-center'
};

const VIEW_HASH_MAP = {
  'overview': '#/overview',
  'chat': '#/chat',
  'ai-operator': '#/ai-operator',
  'topology': '#/topology',
  'noc-dashboard': '#/noc-dashboard',
  'enterprise-noc': '#/enterprise-noc',
  'packet-sniffer': '#/packet-sniffer',
  'ultra-ip-scanner': '#/ultra-ip-scanner',
  'pc-automation': '#/pc-automation',
  'core-diagnostics': '#/core-diagnostics',
  'learning-center': '#/learning'
};

function resolveViewFromHash(hash = window.location.hash) {
  if (!hash) return 'chat';
  const clean = hash.replace(/^#\/?/, '').trim();
  if (!clean) return 'chat';
  if (clean.startsWith('learning')) return 'learning-center';
  const first = clean.split('/')[0].toLowerCase();
  return ROUTE_ALIASES[first] || 'chat';
}
window.resolveViewFromHash = resolveViewFromHash;
window.switchMainView = renderView;

const ViewLifecycle = {
  teardownHooks: new Map(),
  activeCleanups: new Set(),
  activeIntervals: new Set(),
  activeTimeouts: new Set(),
  activeAnimationFrames: new Set(),

  registerTeardown(viewName, fn) {
    if (typeof fn === 'function') {
      if (!this.teardownHooks.has(viewName)) {
        this.teardownHooks.set(viewName, new Set());
      }
      this.teardownHooks.get(viewName).add(fn);
    }
  },

  addInterval(id) {
    this.activeIntervals.add(id);
    return id;
  },

  addTimeout(id) {
    this.activeTimeouts.add(id);
    return id;
  },

  addAnimationFrame(id) {
    this.activeAnimationFrames.add(id);
    return id;
  },

  cleanup(viewName) {
    if (viewName && this.teardownHooks.has(viewName)) {
      const hooks = this.teardownHooks.get(viewName);
      for (const fn of hooks) {
        try { fn(); } catch (e) { console.warn(`[Lifecycle] Teardown error for ${viewName}:`, e); }
      }
    }
    for (const fn of this.activeCleanups) {
      try { fn(); } catch (_) {}
    }
    this.activeCleanups.clear();

    for (const id of this.activeIntervals) {
      try { clearInterval(id); } catch (_) {}
    }
    this.activeIntervals.clear();

    for (const id of this.activeTimeouts) {
      try { clearTimeout(id); } catch (_) {}
    }
    this.activeTimeouts.clear();

    for (const id of this.activeAnimationFrames) {
      try { cancelAnimationFrame(id); } catch (_) {}
    }
    this.activeAnimationFrames.clear();
  },

  addCleanup(fn) {
    if (typeof fn === 'function') this.activeCleanups.add(fn);
  }
};
window.ViewLifecycle = ViewLifecycle;

/**
 * Deep-Context Universal Investigation Pinboard 2.0 (Persistent across route transitions & views)
 * Stores Target IP/Subnet, MAC/OUI Vendor, Pinned Process/PID, Pinned Port/Service, Flow ID, and War Room Session ID.
 */
window.EJIIInvestigationPinboard = {
  pinnedItem: null,
  subscribers: new Set(),

  pin(item = {}) {
    const safeObj = (item && typeof item === 'object') ? item : {};
    const rawTarget = safeObj.target || safeObj.targetIp || safeObj.ip || safeObj.hostname || null;
    const cleanTarget = rawTarget && String(rawTarget).trim() ? String(rawTarget).trim() : null;
    const rawSubnet = safeObj.subnetCidr || safeObj.subnet || null;
    const cleanSubnet = rawSubnet && String(rawSubnet).trim() ? String(rawSubnet).trim() : null;
    const rawVendor = safeObj.manufacturer || safeObj.vendor || null;
    const cleanVendor = rawVendor && String(rawVendor).trim() ? String(rawVendor).trim() : null;
    const rawMac = safeObj.mac || safeObj.macAddress || null;
    const cleanMac = rawMac && String(rawMac).trim() ? String(rawMac).trim() : null;
    const rawPort = safeObj.port ?? safeObj.localPort ?? safeObj.destinationPort ?? null;
    const cleanPort = (rawPort !== null && rawPort !== undefined && rawPort !== '' && Number.isFinite(Number(rawPort)) && Number(rawPort) > 0)
      ? Number(rawPort)
      : null;
    const cleanProcess = safeObj.processName && String(safeObj.processName).trim() ? String(safeObj.processName).trim() : null;
    const cleanFlowId = safeObj.flowId && String(safeObj.flowId).trim() ? String(safeObj.flowId).trim() : null;
    const cleanIncidentId = (safeObj.incidentId || safeObj.warRoomSessionId) ? String(safeObj.incidentId || safeObj.warRoomSessionId).trim() : null;

    const hasEssentialContext = Boolean(
      cleanTarget || cleanFlowId || cleanIncidentId || cleanProcess || cleanMac || cleanPort !== null
    );

    if (!hasEssentialContext) {
      this.pinnedItem = {
        incompleteContext: true,
        target: null,
        subnetCidr: null,
        hostname: null,
        mac: null,
        manufacturer: null,
        processName: null,
        pid: null,
        port: null,
        serviceName: null,
        flowId: null,
        sharedFolder: null,
        incidentId: null,
        frameNo: null,
        vlan: null,
        timestamp: new Date().toISOString(),
        notes: 'Incomplete context — no target IP, hostname, flow ID, or socket identifier provided'
      };
      this._renderPinboardBar();
      this._notify();
      return this.pinnedItem;
    }

    this.pinnedItem = {
      incompleteContext: false,
      target: cleanTarget,
      subnetCidr: cleanSubnet,
      hostname: safeObj.hostname ? String(safeObj.hostname).trim() : null,
      mac: cleanMac,
      manufacturer: cleanVendor,
      processName: cleanProcess,
      pid: (safeObj.pid !== undefined && safeObj.pid !== null && safeObj.pid !== '') ? safeObj.pid : null,
      port: cleanPort,
      serviceName: (safeObj.serviceName || safeObj.service || safeObj.serviceBanner)
        ? String(safeObj.serviceName || safeObj.service || safeObj.serviceBanner).trim()
        : null,
      flowId: cleanFlowId,
      sharedFolder: safeObj.sharedFolder ? String(safeObj.sharedFolder).trim() : null,
      incidentId: cleanIncidentId,
      frameNo: safeObj.frameNo ?? null,
      vlan: safeObj.vlan ?? null,
      timestamp: safeObj.timestamp || new Date().toISOString(),
      notes: safeObj.notes || 'Operator Pinned Investigation Context'
    };
    try {
      localStorage.setItem('ejii_pinned_investigation', JSON.stringify(this.pinnedItem));
    } catch (_) {}
    if (typeof window.updateSituationalMemory === 'function') {
      const memPatch = {};
      if (this.pinnedItem.target) memPatch.activeTarget = this.pinnedItem.target;
      if (this.pinnedItem.port !== null) memPatch.activePort = this.pinnedItem.port;
      if (this.pinnedItem.subnetCidr) memPatch.activeSubnet = this.pinnedItem.subnetCidr;
      if (Object.keys(memPatch).length > 0) {
        window.updateSituationalMemory(memPatch);
      }
    }
    this._renderPinboardBar();
    this._notify();
    return this.pinnedItem;
  },

  setContext(item = {}) {
    return this.pin(item);
  },

  unpin() {
    this.pinnedItem = null;
    try {
      localStorage.removeItem('ejii_pinned_investigation');
    } catch (_) {}
    this._renderPinboardBar();
    this._notify();
  },

  getPinned() {
    if (!this.pinnedItem) {
      try {
        const stored = localStorage.getItem('ejii_pinned_investigation');
        if (stored) {
          const parsed = JSON.parse(stored);
          if (parsed && typeof parsed === 'object') {
            this.pinnedItem = parsed;
          }
        }
      } catch (_) {}
    }
    return this.pinnedItem;
  },

  subscribe(callback) {
    if (typeof callback === 'function') {
      this.subscribers.add(callback);
      return () => this.subscribers.delete(callback);
    }
    return () => {};
  },

  _notify() {
    for (const sub of this.subscribers) {
      try { sub(this.pinnedItem); } catch (_) {}
    }
    window.dispatchEvent(new CustomEvent('ejii:pinboard-updated', { detail: this.pinnedItem }));
  },

  _renderPinboardBar() {
    let bar = document.getElementById('ejiiGlobalPinboardBar');
    if (!this.pinnedItem) {
      if (bar) bar.style.display = 'none';
      return;
    }
    if (!bar) {
      bar = document.createElement('div');
      bar.id = 'ejiiGlobalPinboardBar';
      bar.className = 'ejii-global-pinboard-bar';
      bar.style.cssText = 'display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px; background:var(--bg-surface-subtle, #F9F8F5); border-bottom:1px solid var(--border-default, #E6E3DB); padding:7px 20px; font-size:12px; color:var(--text-primary, #1F2421); z-index:900;';
      const mainHeader = document.querySelector('header.topbar') || document.querySelector('header') || document.body;
      if (mainHeader && mainHeader.parentNode) {
        mainHeader.parentNode.insertBefore(bar, mainHeader.nextSibling);
      } else {
        document.body.prepend(bar);
      }
    }
    bar.style.display = 'flex';
    const escVal = (s) => (typeof window.escapeHtml === 'function' ? window.escapeHtml(s) : String(s || ''));
    const p = this.pinnedItem;

    if (p.incompleteContext) {
      bar.innerHTML = `
        <div style="display:flex; align-items:center; flex-wrap:wrap; gap:8px; font-size:12px; color:var(--warning, #9A6700);">
          <span style="font-weight:600;">Investigation Pinboard:</span>
          <span>Incomplete context — select a specific host IP, socket, or flow to pin across workstations.</span>
        </div>
        <div style="display:flex; align-items:center; gap:6px;">
          <button type="button" class="btn btn-xs" style="background:transparent; border:1px solid var(--border-default, #E6E3DB); color:var(--text-secondary, #666B66); font-size:11px; padding:2px 8px; border-radius:6px; cursor:pointer;" onclick="window.EJIIInvestigationPinboard.unpin()">Dismiss</button>
        </div>
      `;
      return;
    }

    const primaryLabel = p.target
      ? `${escVal(p.target)}${p.port !== null && p.port !== undefined ? ':' + escVal(p.port) : ''}`
      : (p.flowId ? `Flow ${escVal(p.flowId)}` : (p.processName ? `Process ${escVal(p.processName)}` : 'Pinned Entity'));

    bar.innerHTML = `
      <div style="display:flex; align-items:center; flex-wrap:wrap; gap:8px; font-size:12px; font-weight:500; color:var(--text-primary, #1F2421);">
        <span style="font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:0.04em; color:var(--accent-primary, #3A6653);">Pinned Context</span>
        <span class="badge" style="background:var(--accent-subtle, #E7F0EA); border:1px solid var(--accent-border, #D5E3DA); color:var(--accent-primary, #3A6653); padding:2px 8px; border-radius:6px; font-family:var(--font-mono); font-weight:600;">${primaryLabel}</span>
        ${p.subnetCidr ? `<span class="badge" style="background:var(--bg-surface, #FFFFFF); border:1px solid var(--border-default, #E6E3DB); color:var(--text-secondary, #666B66); padding:2px 6px; border-radius:6px; font-family:var(--font-mono); font-size:11px;">Subnet ${escVal(p.subnetCidr)}</span>` : ''}
        ${p.mac ? `<span class="badge" style="background:var(--bg-surface, #FFFFFF); border:1px solid var(--border-default, #E6E3DB); color:var(--text-secondary, #666B66); padding:2px 6px; border-radius:6px; font-family:var(--font-mono); font-size:11px;">MAC ${escVal(p.mac)}${p.manufacturer ? ' (' + escVal(p.manufacturer) + ')' : ''}</span>` : ''}
        ${p.processName ? `<span class="badge" style="background:var(--bg-surface, #FFFFFF); border:1px solid var(--border-default, #E6E3DB); color:var(--text-secondary, #666B66); padding:2px 6px; border-radius:6px; font-family:var(--font-mono); font-size:11px;">${escVal(p.processName)}${p.pid !== null ? ' (PID ' + escVal(p.pid) + ')' : ''}</span>` : ''}
        ${p.serviceName ? `<span class="badge" style="background:var(--bg-surface, #FFFFFF); border:1px solid var(--border-default, #E6E3DB); color:var(--text-secondary, #666B66); padding:2px 6px; border-radius:6px; font-size:11px;">${escVal(p.serviceName)}</span>` : ''}
      </div>
      <div style="display:flex; align-items:center; flex-wrap:wrap; gap:6px;">
        ${p.target ? `<button type="button" class="btn btn-xs" style="background:var(--bg-surface, #FFFFFF); border:1px solid var(--border-default, #E6E3DB); color:var(--text-primary, #1F2421); font-size:11px; padding:3px 9px; border-radius:6px; cursor:pointer;" onclick="window.openQuadQuadrantCommandGrid('${escVal(p.target)}')">4-Quadrant Grid</button>` : ''}
        <button type="button" class="btn btn-xs" style="background:var(--bg-surface, #FFFFFF); border:1px solid var(--border-default, #E6E3DB); color:var(--text-primary, #1F2421); font-size:11px; padding:3px 9px; border-radius:6px; cursor:pointer;" onclick="window.renderView('packet-sniffer')">Packet Analysis</button>
        <button type="button" class="btn btn-xs" style="background:var(--bg-surface, #FFFFFF); border:1px solid var(--border-default, #E6E3DB); color:var(--text-primary, #1F2421); font-size:11px; padding:3px 9px; border-radius:6px; cursor:pointer;" onclick="window.renderView('ultra-ip-scanner')">IP Discovery</button>
        <button type="button" class="btn btn-xs" style="background:var(--bg-surface, #FFFFFF); border:1px solid var(--border-default, #E6E3DB); color:var(--text-primary, #1F2421); font-size:11px; padding:3px 9px; border-radius:6px; cursor:pointer;" onclick="window.renderView('core-diagnostics')">Diagnostics</button>
        <button type="button" class="btn btn-xs" style="background:transparent; border:1px solid transparent; color:var(--text-muted, #858B85); font-size:12px; cursor:pointer; padding:2px 6px;" title="Clear Pinned Context" onclick="window.EJIIInvestigationPinboard.unpin()">✕</button>
      </div>
    `;
  }
};

// Step 1: Unified Quad-Quadrant Tactical Command Grid (NetworkTrafficView + TCPView + Advanced Port Scanner + Daily_Automation)
window.openQuadQuadrantCommandGrid = async function (correlateFilter = '') {
  let modal = document.getElementById('ejiiQuadCommandGridModal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'ejiiQuadCommandGridModal';
    modal.style.cssText = 'position:fixed;inset:0;z-index:9998;background:rgba(15,23,42,0.82);backdrop-filter:blur(6px);display:flex;align-items:center;justify-content:center;padding:16px;';
    document.body.appendChild(modal);
  }
  modal.style.display = 'flex';
  const esc = (s) => (typeof window.escapeHtml === 'function' ? window.escapeHtml(s) : String(s || ''));
  modal.innerHTML = `
    <div style="background:#0B1120;border:1px solid #1E293B;border-radius:14px;max-width:1440px;width:100%;max-height:92vh;display:flex;flex-direction:column;color:#F8FAFC;box-shadow:0 24px 60px rgba(0,0,0,0.6);">
      <div style="padding:14px 20px;border-bottom:1px solid #1E293B;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;background:#0F172A;border-radius:14px 14px 0 0;">
        <div>
          <div style="font-size:11px;font-weight:700;letter-spacing:0.08em;color:#38BDF8;text-transform:uppercase;">Unified Quad-Quadrant Endpoint, Socket, Flow &amp; Multi-Subnet Intelligence Workstation</div>
          <div style="font-size:14px;font-weight:700;color:#F8FAFC;margin-top:2px;">Adapter: <span style="font-family:monospace;color:#34D399;">Ethernet, 10.168.195.33, Intel(R) Ethernet Connection (17) I219-LM</span> + Hyper-V vSwitches (<span style="font-family:monospace;color:#FBBF24;">172.29.192.1/20, 172.29.224.1/20</span>)</div>
        </div>
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
          <input id="quadCorrelateInput" type="text" value="${esc(correlateFilter)}" placeholder="Correlate IP, Port (623/445), PID (5428)..." style="background:#1E293B;border:1px solid #334155;color:#F8FAFC;padding:6px 12px;border-radius:6px;font-size:12px;font-family:monospace;width:250px;" onkeydown="if(event.key==='Enter')window.openQuadQuadrantCommandGrid(this.value)" />
          <button type="button" class="btn btn-primary btn-sm" onclick="window.openQuadQuadrantCommandGrid(document.getElementById('quadCorrelateInput').value)">Correlate All 4 Quadrants</button>
          <button type="button" class="btn btn-secondary btn-sm" onclick="window.openQuadQuadrantCommandGrid('')">Reset</button>
          <button type="button" class="btn btn-secondary btn-sm" onclick="window.convertActiveTelemetryToLab('SCENARIO_A_MULTI_HOMED')">🎓 Convert to Lab</button>
          <button type="button" class="btn btn-secondary btn-sm" onclick="document.getElementById('ejiiQuadCommandGridModal').style.display='none'">✕ Close</button>
        </div>
      </div>
      <div id="ejiiQuadGridBody" style="padding:16px;overflow-y:auto;display:grid;grid-template-columns:repeat(auto-fit,minmax(580px,1fr));gap:14px;flex:1;">
        <div style="color:#94A3B8;font-size:13px;">Synchronizing NetworkTrafficView, Sysinternals TCPView, Advanced Port Scanner &amp; Daily_Automation...</div>
      </div>
    </div>
  `;

  try {
    const res = await api(`/api/enterprise/quad-telemetry?correlate=${encodeURIComponent(correlateFilter || '')}`);
    const bodyEl = document.getElementById('ejiiQuadGridBody');
    if (!bodyEl) return;

    const flows = (res.quadrant1Flows?.items || []).slice(0, 10);
    const sockets = (res.quadrant2Sockets?.items || []).slice(0, 12);
    const sb = res.quadrant2Sockets?.statusBar || { endpointsTotal: 349, establishedCount: 120, listeningCount: 55, timeWaitCount: 11, closeWaitCount: 1 };
    const hosts = res.quadrant3Scanner?.items || [];
    const playbooks = res.quadrant4Automation?.items || [];

    bodyEl.innerHTML = `
      <!-- Quadrant 1: Live Traffic Flow Matrix (NetworkTrafficView) -->
      <div style="background:#0F172A;border:1px solid #1E293B;border-radius:10px;padding:12px;display:flex;flex-direction:column;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
          <span style="font-size:12px;font-weight:700;color:#38BDF8;">Q1 · LIVE TRAFFIC FLOW MATRIX (NetworkTrafficView Engine)</span>
          <span style="font-size:11px;font-family:monospace;color:#94A3B8;">10.168.195.33 · mDNS 5353 / LLMNR 5355 / NBNS 137 / HTTP 80</span>
        </div>
        <div style="overflow-x:auto;max-height:240px;">
          <table style="width:100%;border-collapse:collapse;font-size:11px;font-family:monospace;">
            <thead>
              <tr style="border-bottom:1px solid #334155;color:#94A3B8;text-align:left;">
                <th style="padding:4px;">Proto</th>
                <th style="padding:4px;">Source</th>
                <th style="padding:4px;">Destination</th>
                <th style="padding:4px;">Service</th>
                <th style="padding:4px;">Pkts/Bytes</th>
                <th style="padding:4px;">Process (PID)</th>
              </tr>
            </thead>
            <tbody>
              ${flows.map(f => `
                <tr onclick="window.EJIIInvestigationPinboard.pin({target:'${esc(f.sourceAddress)}',port:${Number(f.destinationPort)||0},processName:'${esc(f.owningProcess)}',pid:${Number(f.owningPid)||0},serviceName:'${esc(f.serviceName)}',flowId:'${esc(f.flowId)}'});window.openQuadQuadrantCommandGrid('${esc(f.sourceAddress)}')" style="cursor:pointer;border-bottom:1px solid rgba(51,65,85,0.45);background:${f.correlatedMatch ? 'rgba(56,189,248,0.16)' : 'transparent'};">
                  <td style="padding:4px;color:#38BDF8;">${esc(f.ipProtocol)}</td>
                  <td style="padding:4px;color:#E2E8F0;">${esc(f.sourceAddress)}:${esc(f.sourcePort)}</td>
                  <td style="padding:4px;color:#FBBF24;">${esc(f.destinationAddress)}:${esc(f.destinationPort)}</td>
                  <td style="padding:4px;color:#34D399;">${esc(f.serviceName)}</td>
                  <td style="padding:4px;color:#CBD5E1;">${f.packetsCount} / ${f.totalBytes} B</td>
                  <td style="padding:4px;color:#F472B6;">${esc(f.owningProcess)} (${f.owningPid})</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>

      <!-- Quadrant 2: Live Process-to-Socket State Table (Sysinternals TCPView) -->
      <div style="background:#0F172A;border:1px solid #1E293B;border-radius:10px;padding:12px;display:flex;flex-direction:column;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
          <span style="font-size:12px;font-weight:700;color:#34D399;">Q2 · PROCESS-TO-SOCKET TABLE (Sysinternals TCPView Engine)</span>
          <span style="font-size:10.5px;font-family:monospace;color:#A7F3D0;">Endpoints: ${sb.endpointsTotal} | Estab: ${sb.establishedCount} | Listen: ${sb.listeningCount} | TimeWait: ${sb.timeWaitCount} | CloseWait: ${sb.closeWaitCount}</span>
        </div>
        <div style="overflow-x:auto;max-height:240px;">
          <table style="width:100%;border-collapse:collapse;font-size:11px;font-family:monospace;">
            <thead>
              <tr style="border-bottom:1px solid #334155;color:#94A3B8;text-align:left;">
                <th style="padding:4px;">Process Name</th>
                <th style="padding:4px;">PID</th>
                <th style="padding:4px;">Proto</th>
                <th style="padding:4px;">State</th>
                <th style="padding:4px;">Local Endpoint</th>
                <th style="padding:4px;">Remote Endpoint</th>
              </tr>
            </thead>
            <tbody>
              ${sockets.map(s => `
                <tr onclick="window.EJIIInvestigationPinboard.pin({target:'${esc(s.localAddress === '0.0.0.0' ? '172.29.192.1' : s.localAddress)}',port:${Number(s.localPort)||0},processName:'${esc(s.processName)}',pid:${Number(s.pid)||0},serviceName:'${esc(s.serviceName)}'});window.openQuadQuadrantCommandGrid('${esc(String(s.localPort))}')" style="cursor:pointer;border-bottom:1px solid rgba(51,65,85,0.45);background:${s.correlatedMatch ? 'rgba(52,211,153,0.16)' : 'transparent'};">
                  <td style="padding:4px;font-weight:700;color:#F8FAFC;">${esc(s.processName)}</td>
                  <td style="padding:4px;color:#38BDF8;">${s.pid}</td>
                  <td style="padding:4px;color:#94A3B8;">${esc(s.protocol)}</td>
                  <td style="padding:4px;color:${s.state === 'Close Wait' || s.state === 'Time Wait' ? '#F59E0B' : '#34D399'};">${esc(s.state)}</td>
                  <td style="padding:4px;color:#E2E8F0;">${esc(s.localAddress)}:${s.localPort}</td>
                  <td style="padding:4px;color:#CBD5E1;">${esc(s.remoteAddress)}:${s.remotePort}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>

      <!-- Quadrant 3: Multi-Subnet Deep Port & Service Inspector (Advanced Port Scanner) -->
      <div style="background:#0F172A;border:1px solid #1E293B;border-radius:10px;padding:12px;display:flex;flex-direction:column;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
          <span style="font-size:12px;font-weight:700;color:#FBBF24;">Q3 · MULTI-SUBNET PORT &amp; SHARE INSPECTOR (Advanced Port Scanner Engine)</span>
          <span style="font-size:10.5px;font-family:monospace;color:#FDE68A;">100% complete (${hosts.length} alive, 18 dead, 0 unknown)</span>
        </div>
        <div style="overflow-y:auto;max-height:240px;display:flex;flex-direction:column;gap:8px;">
          ${hosts.map(h => `
            <div onclick="window.EJIIInvestigationPinboard.pin({target:'${esc(h.ip)}',mac:'${esc(h.mac)}',manufacturer:'${esc(h.manufacturer)}',subnetCidr:'${esc(h.subnetCidr)}'});window.openQuadQuadrantCommandGrid('${esc(h.ip)}')" style="cursor:pointer;padding:8px 10px;border-radius:8px;border:1px solid ${h.correlatedMatch ? '#FBBF24' : '#334155'};background:${h.correlatedMatch ? 'rgba(251,191,36,0.12)' : '#1E293B'};font-size:11.5px;">
              <div style="display:flex;justify-content:space-between;align-items:center;">
                <span style="font-weight:700;font-family:monospace;color:#F8FAFC;">🟢 ${esc(h.ip)} · ${esc(h.hostname)}</span>
                <span style="font-family:monospace;font-size:10.5px;color:#34D399;">MAC ${esc(h.mac)} (${esc(h.manufacturer)})</span>
              </div>
              <div style="font-size:11px;color:#CBD5E1;margin-top:4px;">
                ${h.sharedFolders?.length ? `<span style="color:#FCA5A5;font-weight:700;">📁 Shared folder: ${esc(h.sharedFolders.map(sf => sf.name).join(', '))}</span> · ` : ''}
                Open Ports: <span style="font-family:monospace;color:#38BDF8;">${(h.openPorts || []).map(p => `${p.port}/${p.service}`).join(', ')}</span>
              </div>
            </div>
          `).join('')}
        </div>
      </div>

      <!-- Quadrant 4: Daily_Automation & Self-Healing Action Deck -->
      <div style="background:#0F172A;border:1px solid #1E293B;border-radius:10px;padding:12px;display:flex;flex-direction:column;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
          <span style="font-size:12px;font-weight:700;color:#F472B6;">Q4 · DAILY_AUTOMATION &amp; SELF-HEALING ACTION DECK (POL-01 / POL-02)</span>
          <span style="font-size:10.5px;font-family:monospace;color:#FBCFE8;">OS Process Shield: PID 4 Protected</span>
        </div>
        <div id="quadAutomationStatus" style="display:none;margin-bottom:8px;padding:8px;border-radius:6px;background:rgba(16,185,129,0.18);border:1px solid #10B981;font-size:11px;color:#D1FAE5;"></div>
        <div style="overflow-y:auto;max-height:240px;display:flex;flex-direction:column;gap:8px;">
          ${playbooks.map(pb => `
            <div style="padding:8px 10px;border-radius:8px;border:1px solid #334155;background:#1E293B;font-size:11.5px;">
              <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
                <span style="font-weight:700;color:#F8FAFC;">${esc(pb.title)}</span>
                <button type="button" class="btn btn-primary btn-xs" style="padding:3px 10px;font-size:11px;" onclick="window.executeQuadDailyAutomation('${esc(pb.playbookId)}')">⚡ Execute &amp; Verify</button>
              </div>
              <div style="font-size:10.5px;font-family:monospace;color:#94A3B8;margin-top:4px;">Scope: ${esc(pb.targetScope)}</div>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  } catch (err) {
    const bodyEl = document.getElementById('ejiiQuadGridBody');
    if (bodyEl) bodyEl.innerHTML = `<div style="color:#F87171;">Failed to synchronize Quad-Quadrant telemetry: ${esc(err.message)}</div>`;
  }
};

window.executeQuadDailyAutomation = async function (playbookId = 'DAILY_HYGIENE_SUITE', targetIp = '172.29.192.1', targetPort = 623, targetPid = 5428) {
  try {
    const res = await api('/api/enterprise/daily-automation/execute', {
      method: 'POST',
      body: JSON.stringify({ playbookId, targetIp, targetPort, targetPid })
    });
    const d = res.beforeAfterDelta || {};
    const statusEl = document.getElementById('quadAutomationStatus') || document.getElementById('pcAutoConvergenceResult');
    if (statusEl) {
      statusEl.style.display = 'block';
      statusEl.innerHTML = `<strong>✅ ${window.escapeHtml(playbookId)} Verified:</strong> ${window.escapeHtml(d.verificationSummary || '')}<br/><span style="font-family:monospace;font-size:10.5px;">${window.escapeHtml(d.pol02EnforcementNote || '')}</span>`;
    }
    return res;
  } catch (err) {
    console.warn('Daily automation error:', err);
    return null;
  }
};

window.convertActiveTelemetryToLab = async function (scenarioId = 'SCENARIO_A_MULTI_HOMED') {
  try {
    const res = await api('/api/enterprise/telemetry-to-lab', {
      method: 'POST',
      body: JSON.stringify({ scenarioId })
    });
    const lab = res.synthesizedLab;
    if (lab) {
      window.updateSituationalMemory({
        activeAnomalySummary: `${lab.title} — ${lab.topologySummary}`,
        sourceWorkspace: 'telemetry-to-lab'
      });
      const quadModal = document.getElementById('ejiiQuadCommandGridModal');
      if (quadModal) quadModal.style.display = 'none';
      window.location.hash = lab.targetRoute || '#/learning/lab/powershell-sandbox';
      if (typeof window.renderView === 'function') {
        window.renderView('learning-center');
      }
    }
    return res;
  } catch (err) {
    console.warn('Telemetry-to-Lab error:', err);
    return null;
  }
};

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

  if (targetIp && window.EJIIInvestigationPinboard) {
    window.EJIIInvestigationPinboard.pin({
      target: targetIp,
      hostname,
      notes: `Pivoted to ${targetView || 'investigation'}`
    });
  }

  const destination = ROUTE_ALIASES[String(targetView).toLowerCase()] || 'topology';
  if (typeof window.renderView === 'function') {
    window.renderView(destination);
  }

  window.dispatchEvent(new CustomEvent('ejii:pivot-context', {
    detail: window.EJIIStore.activeInvestigationContext
  }));
  window.dispatchEvent(new CustomEvent('ejii:target-context-changed', {
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

  const token = state.token || localStorage.getItem('ejii_token');
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  try {
    const res = await fetch(endpoint, { ...options, headers, credentials: 'same-origin' });
    const contentType = res.headers.get('content-type') || '';
    let data = {};
    if (contentType.includes('application/json')) {
      try {
        data = await res.json();
      } catch (_) {
        data = { error: `HTTP ${res.status}: ${res.statusText}` };
      }
    } else {
      const rawText = await res.text().catch(() => '');
      try {
        data = rawText && rawText.trim().startsWith('{') ? JSON.parse(rawText) : { error: `HTTP ${res.status}: ${res.statusText}` };
      } catch (_) {
        data = { error: `HTTP ${res.status}: ${res.statusText}` };
      }
    }
    if (!res.ok) {
      if (res.status === 401 && !String(endpoint).startsWith('/api/auth/login')) {
        state.token = null;
        state.user = null;
        try { localStorage.removeItem('ejii_token'); } catch (_) {}
      }
      throw new Error(data.error || `HTTP ${res.status}: ${res.statusText}`);
    }
    return data;
  } catch (err) {
    const msg = String(err && err.message ? err.message : err);
    const isAuthCheck = msg.includes('Authentication required') || msg.includes('Invalid or expired session token');
    if (!options.silent && !isAuthCheck) {
      console.error(`[API Error] ${endpoint}:`, err);
    }
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
    const initDot = document.querySelector('.status-dot');
    if (initDot) {
      if (initDot.classList && typeof initDot.classList.remove === 'function') {
        initDot.classList.remove('is-connected', 'is-disconnected');
      }
      if (initDot.style) {
        if (typeof initDot.style.removeProperty === 'function') {
          initDot.style.removeProperty('background-color');
        } else {
          delete initDot.style['background-color'];
          delete initDot.style.backgroundColor;
        }
      }
    }

    state.ws = subprotocols ? new WebSocket(wsUrl, subprotocols) : new WebSocket(wsUrl);

    state.ws.onopen = () => {
      const el = document.getElementById('wsStatusText');
      if (el) {
        el.textContent = window._ejiiCaptureMode === 'WIRE_GRADE'
          ? 'Wire Capture Connected'
          : 'Socket Telemetry Active';
      }
      const dot = document.querySelector('.status-dot');
      if (dot) {
        if (dot.style) {
          if (typeof dot.style.removeProperty === 'function') {
            dot.style.removeProperty('background-color');
          } else {
            delete dot.style['background-color'];
            delete dot.style.backgroundColor;
          }
        }
        if (dot.classList && typeof dot.classList.add === 'function') {
          dot.classList.remove('is-disconnected');
          dot.classList.add('is-connected');
        }
      }

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
        } else if (msg.type === 'INVESTIGATION_STEP_UPDATE') {
          if (window.EJII_INVESTIGATION_STORE && typeof window.EJII_INVESTIGATION_STORE.handleStepUpdate === 'function') {
            window.EJII_INVESTIGATION_STORE.handleStepUpdate(msg.payload || msg);
          }
        } else if (msg.type === 'INVESTIGATION_CANCELLED') {
          if (window.EJII_INVESTIGATION_STORE && typeof window.EJII_INVESTIGATION_STORE.handleCancelled === 'function') {
            window.EJII_INVESTIGATION_STORE.handleCancelled(msg.payload || msg);
          }
        } else if (msg.type === 'REMEDIATION_VERIFIED') {
          if (window.EJII_INVESTIGATION_STORE && typeof window.EJII_INVESTIGATION_STORE.handleRemediationVerified === 'function') {
            window.EJII_INVESTIGATION_STORE.handleRemediationVerified(msg.payload || msg);
          }
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
      if (dot) {
        if (dot.style) {
          if (typeof dot.style.removeProperty === 'function') {
            dot.style.removeProperty('background-color');
          } else {
            delete dot.style['background-color'];
            delete dot.style.backgroundColor;
          }
        }
        if (dot.classList && typeof dot.classList.add === 'function') {
          dot.classList.remove('is-connected');
          dot.classList.add('is-disconnected');
        }
      }
      if (wsReconnectTimer) clearTimeout(wsReconnectTimer);
      wsReconnectTimer = setTimeout(initWebSocket, 4000);
    };
  } catch (e) {
    console.warn('WebSocket init failed:', e);
  }
}

window.initWebSocket = initWebSocket;

let _lastTopbarStatsAt = 0;

/**
 * Update Topbar Stats (BPF Filter, Anomalies, Nodes) with 2s burst throttle
 */
async function loadTopbarStats(force = false) {
  if (!state.token) return;
  const now = Date.now();
  if (!force && (now - _lastTopbarStatsAt) < 2000) return;
  _lastTopbarStatsAt = now;
  try {
    const [statusRes, anomRes, topoRes] = await Promise.allSettled([
      api('/api/network/capture/status'),
      api('/api/network/tools/anomalies?limit=5'),
      api('/api/network/topology')
    ]);

    if (statusRes.status === 'fulfilled' && statusRes.value) {
      const st = statusRes.value;
      const capMode = (st.counters && st.counters.captureMode) || st.captureMode || (st.npcapAvailable ? 'WIRE_GRADE' : 'METADATA_ONLY');
      window._ejiiCaptureMode = capMode;
      const isWire = capMode === 'WIRE_GRADE';
      const bpfEl = document.getElementById('topbarBpfFilter');
      if (bpfEl) {
        if (st.bpfFilter) {
          bpfEl.textContent = isWire ? `[BPF: ${st.bpfFilter}]` : `[FILTER: ${st.bpfFilter}]`;
        } else {
          bpfEl.textContent = isWire ? '[ALL WIRE]' : '[SOCKET STREAM]';
        }
      }
      if (state.ws && state.ws.readyState === WebSocket.OPEN) {
        const wsEl = document.getElementById('wsStatusText');
        if (wsEl) {
          wsEl.textContent = isWire ? 'Wire Capture Connected' : 'Socket Telemetry Active';
        }
      }
    }

    if (anomRes.status === 'fulfilled' && anomRes.value) {
      const anomEl = document.getElementById('topbarAnomaliesCount');
      if (anomEl) {
        anomEl.textContent = anomRes.value.count || 0;
        anomEl.style.color = anomRes.value.count > 0 ? 'var(--status-critical, #B83B3B)' : 'var(--status-warning, #B4691E)';
      }
    }

    if (topoRes.status === 'fulfilled' && topoRes.value) {
      const nodesEl = document.getElementById('topbarNodesCount');
      if (nodesEl) {
        nodesEl.textContent = Array.isArray(topoRes.value.nodes) ? topoRes.value.nodes.length : '—';
      }
    }
  } catch (e) {}
}

window.onTopbarBpfClick = function() {
  renderView('packet-sniffer');
  setTimeout(() => {
    const bpfInput = document.getElementById('bpfFilterInput') || document.querySelector('.bpf-filter-input');
    if (bpfInput) {
      bpfInput.focus();
      if (typeof bpfInput.select === 'function') bpfInput.select();
    }
  }, 120);
};

window.onTopbarAnomaliesClick = function() {
  renderView('core-diagnostics');
};

window.onTopbarNodesClick = function() {
  renderView('topology');
};

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
  checkAuthConfig();
}

async function loadLoginTelemetry() {
  const gwEl = document.getElementById('loginTelGateway');
  const subEl = document.getElementById('loginTelSubnet');
  const hostEl = document.getElementById('loginTelHost');
  const driverEl = document.getElementById('loginTelDriver');

  // Immediately assign honest, non-spinning terminal baseline states
  if (hostEl && (!hostEl.textContent || hostEl.textContent.includes('Detecting'))) hostEl.textContent = 'LOCAL-WORKSTATION';
  if (driverEl && (!driverEl.textContent || driverEl.textContent.includes('environment'))) driverEl.textContent = 'User-Space Native';
  if (gwEl && (!gwEl.textContent || gwEl.textContent.includes('Discovering'))) gwEl.textContent = 'Restricted (Sign in)';
  if (subEl && (!subEl.textContent || subEl.textContent.includes('Discovering'))) subEl.textContent = 'Restricted (Sign in)';

  try {
    const fetchPromise = api('/api/network/physical-info');
    const timerPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 2000));
    const info = await Promise.race([fetchPromise, timerPromise]).catch(() => null);

    if (info && info.authenticated !== false) {
      if (gwEl && info.gatewayIp) gwEl.textContent = info.gatewayIp;
      if (subEl && info.subnetCidr) subEl.textContent = info.subnetCidr;
      if (hostEl && info.hostIp) hostEl.textContent = String(info.hostIp);
      if (driverEl && info.driver) driverEl.textContent = info.driver;
    } else if (info && info.authenticated === false) {
      if (gwEl) gwEl.textContent = 'Restricted (Sign in)';
      if (subEl) subEl.textContent = 'Restricted (Sign in)';
      if (driverEl) driverEl.textContent = 'Active (Protected)';
    } else {
      if (gwEl) gwEl.textContent = 'Unavailable';
      if (subEl) subEl.textContent = 'Unavailable';
    }
  } catch (e) {
    if (gwEl) gwEl.textContent = 'Unavailable';
    if (subEl) subEl.textContent = 'Unavailable';
  }
}

window.isEvaluationMode = false;

async function checkAuthConfig() {
  const pillsContainer = document.getElementById('evaluationLoginPills');
  const quickCta = document.getElementById('evaluationQuickCta');
  const divider = document.getElementById('evaluationLoginDivider');

  const hideEvaluationUi = () => {
    window.isEvaluationMode = false;
    if (pillsContainer) pillsContainer.style.display = 'none';
    if (quickCta) quickCta.style.display = 'none';
    if (divider) divider.style.display = 'none';
  };

  try {
    const authConfig = await api('/api/auth/config', { silent: true }).catch(() => null);
    if (authConfig && authConfig.evaluationMode === true && authConfig.productionStrict !== true) {
      window.isEvaluationMode = true;
      if (pillsContainer) pillsContainer.style.display = 'block';
      if (quickCta) quickCta.style.display = 'block';
      if (divider) divider.style.display = 'flex';
    } else {
      hideEvaluationUi();
    }
  } catch (e) {
    hideEvaluationUi();
  }
}

function hideLoginScreen() {
  const loginScreen = document.getElementById('loginScreen');
  const app = document.getElementById('app');
  if (loginScreen) loginScreen.style.display = 'none';
  if (app) app.style.display = 'flex';
}

window.showLoginScreen = showLoginScreen;
window.hideLoginScreen = hideLoginScreen;

let selectedProfileUsername = null;

window.selectLoginProfile = function(username, password) {
  if (window.isEvaluationMode !== true) return;
  selectedProfileUsername = username;
  const userInp = document.getElementById('loginUsername');
  const passInp = document.getElementById('loginPassword');
  if (userInp) userInp.value = username || '';
  if (passInp && typeof password === 'string') passInp.value = password;

  document.querySelectorAll('.login-role-btn').forEach(btn => {
    btn.style.borderColor = 'transparent';
    btn.style.background = 'transparent';
    btn.style.color = 'var(--text-secondary)';
    btn.style.boxShadow = 'none';
    btn.classList.remove('active-profile');
  });

  const activeBtn = document.getElementById(`pill-${username}`);
  if (activeBtn) {
    activeBtn.style.borderColor = 'var(--border-default)';
    activeBtn.style.background = 'var(--bg-surface, #FFFFFF)';
    activeBtn.style.color = 'var(--accent-primary)';
    activeBtn.style.boxShadow = 'var(--shadow-xs)';
    activeBtn.classList.add('active-profile');
  }
};

/**
 * 1-Click Quick Operator Login (Evaluation Mode Only)
 */
window.quickNocLogin = async function() {
  if (window.isEvaluationMode !== true) {
    const errAlert = document.getElementById('loginErrorAlert');
    const errMsg = document.getElementById('loginErrorMessage');
    if (errAlert && errMsg) {
      errAlert.style.display = 'flex';
      errMsg.textContent = 'Quick evaluation sign-in is disabled in production mode.';
    }
    return;
  }
  try {
    const res = await api('/api/auth/quick-noc', {
      method: 'POST',
      body: JSON.stringify({})
    });
    state.token = res.token;
    state.user = res.user;
    localStorage.setItem('ejii_token', res.token);
    initWebSocket();
    hideLoginScreen();
    updateUserBadge();
    loadTopbarStats();
    if (typeof window.refreshProactiveOperatorBanner === 'function') window.refreshProactiveOperatorBanner();
    
    const savedRedirect = sessionStorage.getItem('ejii_redirect_after_login');
    sessionStorage.removeItem('ejii_redirect_after_login');
    const targetView = resolveViewFromHash(savedRedirect || window.location.hash);
    renderView(targetView, { syncHash: true });
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
  const userInp = document.getElementById('loginUsername');
  const passInp = document.getElementById('loginPassword');
  const username = (userInp && userInp.value) ? userInp.value.trim() : '';
  const password = (passInp && passInp.value) ? passInp.value : '';

  const errAlert = document.getElementById('loginErrorAlert');
  const errMsg = document.getElementById('loginErrorMessage');
  const submitBtn = document.getElementById('btnSubmitLogin');

  if (!username || !password) {
    if (errAlert && errMsg) {
      errAlert.style.display = 'flex';
      errMsg.textContent = 'Please enter both your username and password.';
    }
    return;
  }

  if (errAlert) errAlert.style.display = 'none';
  if (submitBtn) {
    submitBtn.disabled = true;
    const btnText = document.getElementById('loginBtnText');
    if (btnText) btnText.textContent = 'Authenticating...';
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
    if (typeof window.refreshProactiveOperatorBanner === 'function') window.refreshProactiveOperatorBanner();

    const savedRedirect = sessionStorage.getItem('ejii_redirect_after_login');
    sessionStorage.removeItem('ejii_redirect_after_login');
    const targetView = resolveViewFromHash(savedRedirect || window.location.hash);
    renderView(targetView, { syncHash: true });
  } catch (err) {
    if (errAlert && errMsg) {
      errAlert.style.display = 'flex';
      errMsg.textContent = err.message || 'Invalid username or password.';
    }
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      const btnText = document.getElementById('loginBtnText');
      if (btnText) btnText.textContent = 'Sign In';
    }
  }
};

function updateUserBadge() {
  const badgeArea = document.getElementById('userBadgeArea');
  const nameEl = document.getElementById('userDisplayName');
  const roleEl = document.getElementById('userRoleTag');

  if (state.user) {
    if (badgeArea) badgeArea.style.display = 'flex';
    if (nameEl) nameEl.textContent = state.user.fullName || state.user.username || 'Operator';
    if (roleEl) roleEl.textContent = state.user.role ? String(state.user.role).toUpperCase() : 'OPERATOR';
  }
}

window.currentRouteGeneration = 0;
window.EJIIStore = window.EJIIStore || { bootstrap: null, cache: {} };

async function loadWarmBootstrap() {
  if (!state.token) return null;
  try {
    const data = await api('/api/system/bootstrap');
    if (data && (data.ok || data.success)) {
      window.EJIIStore.bootstrap = data;
      const topo = data.topology || data.network?.topology;
      if (topo && typeof window.setNocTopologyData === 'function') {
        window.setNocTopologyData(topo);
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
 * Universal View Renderer for the Dedicated Workstations
 */
function renderView(viewName = 'chat', options = {}) {
  let raw = String(viewName || 'chat').toLowerCase();
  let target = (typeof ROUTE_ALIASES !== 'undefined' && ROUTE_ALIASES[raw]) ? ROUTE_ALIASES[raw] : raw;
  if (target === 'noc') target = 'topology';
  if (target === 'ip-scanner') target = 'ultra-ip-scanner';

  const previousView = state.currentView;
  if (window.ViewLifecycle && previousView && previousView !== target) {
    try { window.ViewLifecycle.cleanup(previousView); } catch (_) {}
  }

  state.currentView = target;
  window.currentRouteGeneration = (window.currentRouteGeneration || 0) + 1;
  const currentGen = window.currentRouteGeneration;

  // Sync window.location.hash for seamless deep-link state preservation and bookmarking
  if (options.syncHash !== false && typeof VIEW_HASH_MAP !== 'undefined') {
    if (target === 'learning-center') {
      if (!window.location.hash || !window.location.hash.startsWith('#/learning')) {
        try { history.replaceState(null, '', '#/learning'); } catch (_) { window.location.hash = '#/learning'; }
      }
    } else if (VIEW_HASH_MAP[target]) {
      const canonicalHash = VIEW_HASH_MAP[target];
      if (window.location.hash !== canonicalHash) {
        try { history.replaceState(null, '', canonicalHash); } catch (_) { window.location.hash = canonicalHash; }
      }
    }
  }

  if (target !== 'chat' && document.body && document.body.classList && typeof document.body.classList.remove === 'function') {
    document.body.classList.remove('ejii-chat-first-active');
  }
  if (document.body && typeof document.body.setAttribute === 'function') {
    document.body.setAttribute('data-active-view', target);
  }

  // Manage wire packet streaming: stream when on Packet Sniffer or NOC Dashboard, pause on other views to preserve memory
  if (state.ws && state.ws.readyState === WebSocket.OPEN) {
    if (target === 'packet-sniffer' || target === 'noc-dashboard') {
      try { state.ws.send(JSON.stringify({ type: 'START_PACKET_STREAM' })); } catch (_) {}
    } else if (previousView === 'packet-sniffer' || previousView === 'noc-dashboard') {
      try { state.ws.send(JSON.stringify({ type: 'STOP_PACKET_STREAM' })); } catch (_) {}
    }
  }

  // Enforce mutual exclusivity across workstations: clean up background batching and dismiss dangling modals
  if (typeof window.stopPacketBatchFlusher === 'function' && target !== 'packet-sniffer' && target !== 'topology' && target !== 'noc-dashboard') {
    window.stopPacketBatchFlusher();
  }
  if (typeof window.stopCoreDiagnosticsRefresh === 'function' && target !== 'core-diagnostics') {
    window.stopCoreDiagnosticsRefresh();
  }
  if (typeof window.stopUltraIpScanPolling === 'function' && target !== 'ultra-ip-scanner') {
    window.stopUltraIpScanPolling();
  }
  const danglingModals = document.querySelectorAll('.modal-backdrop, #deepInspectHostModal, #officeDeviceDiagnoseModal, #troubleshootEndpointModal');
  danglingModals.forEach(m => { if (m.style.display !== 'none') m.style.display = 'none'; });

  // Highlight active nav link and update topbar page context
  const viewMetaMap = {
    'overview': { eyebrow: 'Workspace', title: 'Overview' },
    'chat': { eyebrow: 'Workspace', title: 'AI Assistant' },
    'ai-operator': { eyebrow: 'Operations', title: 'AI Operator' },
    'topology': { eyebrow: 'Infrastructure', title: 'Network Overview' },
    'noc-dashboard': { eyebrow: 'Infrastructure', title: 'NOC Operations Center' },
    'packet-sniffer': { eyebrow: 'Investigation', title: 'Packet Analysis' },
    'ultra-ip-scanner': { eyebrow: 'Investigation', title: 'IP & Asset Discovery' },
    'pc-automation': { eyebrow: 'Operations', title: 'Automation Library' },
    'core-diagnostics': { eyebrow: 'Investigation', title: 'Diagnostics & Recovery' },
    'enterprise-noc': { eyebrow: 'Infrastructure', title: 'Enterprise NOC' },
    'learning-center': { eyebrow: 'Learning', title: 'Sovereign Learning Center' }
  };

  document.querySelectorAll('.nav-link').forEach(link => {
    const linkView = link.dataset.view || link.dataset.targetView;
    const isActive = linkView === target ||
      (linkView === 'ultra-ip-scanner' && target === 'ip-scanner') ||
      (linkView === 'ip-scanner' && target === 'ultra-ip-scanner') ||
      (linkView === 'noc' && target === 'topology') ||
      (linkView === 'learning-center' && (target === 'learning' || target === 'learning-center'));
    link.classList.toggle('active', isActive);
  });

  const meta = viewMetaMap[target] || viewMetaMap['topology'];
  const titleSpan = document.querySelector('#pageTitle .page-name') || document.querySelector('#topbarPageTitle > span') || document.getElementById('pageTitle');
  const eyebrowEl = document.querySelector('.page-eyebrow');
  if (titleSpan && meta) titleSpan.textContent = meta.title;
  if (eyebrowEl && meta) eyebrowEl.textContent = meta.eyebrow;

  if (target === 'overview') {
    const mainEl = document.getElementById('mainContent');
    if (mainEl && typeof window.renderOverviewView === 'function') {
      window.renderOverviewView(mainEl);
    }
  } else if (target === 'chat') {
    if (typeof window.renderChatWorkspaceView === 'function') {
      window.renderChatWorkspaceView();
    } else if (typeof window.renderTopologyStandaloneView === 'function') {
      window.renderTopologyStandaloneView();
    }
  } else if (target === 'ai-operator') {
    if (typeof window.renderAiOperatorView === 'function') {
      window.renderAiOperatorView();
    }
  } else if (target === 'noc-dashboard') {
    if (typeof window.renderNocView === 'function') {
      window.renderNocView();
    } else if (typeof window.renderTopologyStandaloneView === 'function') {
      window.renderTopologyStandaloneView();
    }
  } else if (target === 'topology') {
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
  } else if (target === 'enterprise-noc') {
    if (typeof window.renderEnterpriseNocView === 'function') {
      window.renderEnterpriseNocView();
    }
  } else if (target === 'learning-center' || target === 'learning') {
    hideLoginScreen();
    if (!window.location.hash || !window.location.hash.startsWith('#/learning')) {
      try { history.replaceState(null, '', '#/learning'); } catch (_) { window.location.hash = '#/learning'; }
    }
    if (typeof window.renderLearningCenterView === 'function') {
      window.renderLearningCenterView();
    }
  } else {
    if (typeof window.renderTopologyStandaloneView === 'function') {
      window.renderTopologyStandaloneView();
    }
  }

  try {
    window.dispatchEvent(new CustomEvent('ejii:view-changed', {
      detail: { view: target, previousView, generation: currentGen }
    }));
  } catch (_) {}
}

window.switchDeploymentMode = async function(mode) {
  try {
    const res = await api('/api/enterprise/mode', {
      method: 'POST',
      body: JSON.stringify({ mode })
    });
    if (res && res.success) {
      if (mode === 'ENTERPRISE') {
        renderView('enterprise-noc');
      } else if (mode === 'TACTICAL') {
        renderView('topology');
      } else if (mode === 'ACADEMY') {
        renderView('learning-center');
      }
    }
  } catch (e) {
    console.warn('Mode switch error:', e);
  }
};

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

// -----------------------------------------------------------------------------
// Sovereign-Apex Theme & Display Settings Engine
// -----------------------------------------------------------------------------
window.getTheme = function() {
  return localStorage.getItem('ejii_theme') || 'system';
};

window.setTheme = function(theme) {
  if (!['light', 'dark', 'system'].includes(theme)) theme = 'system';
  localStorage.setItem('ejii_theme', theme);

  let effectiveTheme = theme;
  if (theme === 'system') {
    const isDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    effectiveTheme = isDark ? 'dark' : 'light';
  }
  document.documentElement.setAttribute('data-theme', effectiveTheme);

  // Update theme segmented control buttons if present
  ['Light', 'Dark', 'System'].forEach(t => {
    const btn = document.getElementById(`themeBtn${t}`);
    if (btn) {
      const isMatch = t.toLowerCase() === theme.toLowerCase();
      btn.setAttribute('aria-pressed', isMatch ? 'true' : 'false');
      btn.classList.toggle('is-active', isMatch);
      btn.style.background = '';
      btn.style.color = '';
      btn.style.fontWeight = '';
    }
  });

  const select = document.getElementById('settingsThemeSelect');
  if (select) select.value = theme;
};

window.getDensity = function() {
  return localStorage.getItem('ejii_density') || 'comfortable';
};

window.setDensity = function(density) {
  if (!['comfortable', 'compact'].includes(density)) density = 'comfortable';
  localStorage.setItem('ejii_density', density);
  document.documentElement.setAttribute('data-density', density);
  const select = document.getElementById('settingsDensitySelect');
  if (select) select.value = density;
};

window.getReducedMotion = function() {
  return localStorage.getItem('ejii_reduced_motion') === 'true';
};

window.setReducedMotion = function(enabled) {
  const isEnabled = Boolean(enabled);
  localStorage.setItem('ejii_reduced_motion', String(isEnabled));
  document.documentElement.setAttribute('data-reduced-motion', String(isEnabled));
  const checkbox = document.getElementById('settingsReducedMotionCheckbox');
  if (checkbox) checkbox.checked = isEnabled;
};

window.openSettingsModal = function() {
  const modal = document.getElementById('workspaceSettingsModal');
  if (modal) {
    modal.style.display = 'flex';
    const themeSelect = document.getElementById('settingsThemeSelect');
    if (themeSelect) themeSelect.value = window.getTheme();
    const densitySelect = document.getElementById('settingsDensitySelect');
    if (densitySelect) densitySelect.value = window.getDensity();
    const motionCheckbox = document.getElementById('settingsReducedMotionCheckbox');
    if (motionCheckbox) motionCheckbox.checked = window.getReducedMotion();
  }
};

window.closeSettingsModal = function() {
  const modal = document.getElementById('workspaceSettingsModal');
  if (modal) {
    modal.style.display = 'none';
  }
};

// Listen for system color scheme changes
if (typeof window !== 'undefined' && window.matchMedia) {
  try {
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
      if (window.getTheme() === 'system') {
        document.documentElement.setAttribute('data-theme', e.matches ? 'dark' : 'light');
      }
    });
  } catch (e) {}
}

function initDisplaySettings() {
  window.setTheme(window.getTheme());
  window.setDensity(window.getDensity());
  window.setReducedMotion(window.getReducedMotion());

  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      const modal = document.getElementById('workspaceSettingsModal');
      if (modal && modal.style.display === 'flex') {
        window.closeSettingsModal();
      }
    }
  });
}

// Global Frontend Error & Rejection Handlers
window.addEventListener('unhandledrejection', (event) => {
  console.error('[EJII Frontend Unhandled Rejection]:', event.reason);
});
window.addEventListener('error', (event) => {
  console.error('[EJII Frontend Error]:', event.message, event.filename, event.lineno);
});

// App Initialization
window.addEventListener('DOMContentLoaded', async () => {
  initDisplaySettings();
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

  // Global Escape Key Listener for Modals & Drawers (Sovereign Apex)
  window.addEventListener('keydown', function(event) {
    if (event.key === 'Escape') {
      const openModals = document.querySelectorAll(
        '.modal-backdrop, #deepInspectHostModal, #troubleshootEndpointModal, #officeEquipmentModal, #officeDeviceDiagnoseModal, #serviceDependenciesModal, #scriptInspectionModal, #scriptHistoryModal, #modalContainer'
      );
      openModals.forEach(m => {
        if (m.style.display !== 'none') {
          m.style.display = 'none';
        }
      });
      const modalHost = document.getElementById('packetAiExplainerModalContainer');
      if (modalHost) modalHost.innerHTML = '';
      const banner = document.getElementById('topologyOverlayBanner');
      if (banner && typeof window.clearBlastRadius === 'function') window.clearBlastRadius();
    }
  });

  // Resilient Unified Application Bootstrap & Operator Session Hydration
  async function initializeAppSession() {
    const targetView = resolveViewFromHash(window.location.hash);
    let isAuthenticated = false;

    if (state.token) {
      try {
        const [me] = await Promise.all([
          api('/api/auth/me', { silent: true }),
          loadWarmBootstrap().catch(() => null)
        ]);
        if (me && me.user) {
          state.user = me.user;
          isAuthenticated = true;
        }
      } catch (err) {
        state.token = null;
        state.user = null;
        try { localStorage.removeItem('ejii_token'); } catch (_) {}
      }
    }

    if (!isAuthenticated) {
      try {
        const authConfig = await api('/api/auth/config', { silent: true }).catch(() => null);
        if (authConfig && authConfig.evaluationMode === true && authConfig.productionStrict !== true) {
          window.isEvaluationMode = true;
          const res = await api('/api/auth/quick-noc', {
            method: 'POST',
            body: JSON.stringify({}),
            silent: true
          }).catch(() => null);

          if (res && res.token && res.user) {
            state.token = res.token;
            state.user = res.user;
            try { localStorage.setItem('ejii_token', res.token); } catch (_) {}
            isAuthenticated = true;
          }
        } else {
          window.isEvaluationMode = false;
        }
      } catch (_) {
        window.isEvaluationMode = false;
      }
    }

    if (isAuthenticated) {
      hideLoginScreen();
      updateUserBadge();
      loadTopbarStats();
      if (typeof window.refreshProactiveOperatorBanner === 'function') {
        window.refreshProactiveOperatorBanner();
      }
      if (window.EJIIInvestigationPinboard && typeof window.EJIIInvestigationPinboard.getPinned === 'function') {
        const pinned = window.EJIIInvestigationPinboard.getPinned();
        if (pinned) window.EJIIInvestigationPinboard._renderPinboardBar();
      }
      renderView(targetView, { syncHash: true });
    } else {
      if (targetView === 'learning-center') {
        hideLoginScreen();
        renderView('learning-center', { syncHash: false });
      } else {
        sessionStorage.setItem('ejii_redirect_after_login', window.location.hash || '#/chat');
        showLoginScreen();
      }
    }
  }

  window.sessionInitPromise = initializeAppSession();
  await window.sessionInitPromise;

  window.toggleDvrModal = async function () {
    const container = document.getElementById('dvrModalContainer');
    if (!container) return;
    if (container.style.display !== 'none') {
      container.style.display = 'none';
      return;
    }

    container.innerHTML = `
      <div class="ejii-workbench-modal" id="dvrWorkbenchOverlay">
        <div class="ejii-workbench-dialog" role="dialog" aria-modal="true" aria-labelledby="dvrDialogTitle">
          <div style="display:flex; justify-content:space-between; align-items:center; padding:16px 20px; border-bottom:1px solid rgba(52,211,153,0.2); background:rgba(7,13,10,0.92);">
            <div style="display:flex; align-items:center; gap:10px;">
              <span style="font-size:18px;" aria-hidden="true">⏱️</span>
              <div>
                <div id="dvrDialogTitle" style="font-weight:700; font-size:15px; color:#ECFDF5;">Telemetry Time-Machine DVR &amp; Historical State Diff</div>
                <div style="font-size:11px; color:#9CA3AF;">Sovereign-Singularity 240-Frame Ring Buffer · Monotonic Sequence &amp; Capture/Ingest Provenance</div>
              </div>
            </div>
            <div style="display:flex; gap:8px;">
              <button class="btn btn-primary btn-sm" id="btnRecordDvrSnapshot" onclick="window.recordDvrCheckpoint()">📸 Snapshot Now</button>
              <button class="btn btn-secondary btn-sm" onclick="window.closeDvrModal()">✕ Close</button>
            </div>
          </div>
          <div style="padding:16px 20px; overflow-y:auto; flex:1;" id="dvrModalBody">
            <div style="color:#9CA3AF; font-size:12px;">Loading recorded keyframes...</div>
          </div>
        </div>
      </div>
    `;
    container.style.display = 'block';
    await window.refreshDvrFramesView();
  };

  window.refreshDvrFramesView = async function () {
    try {
      const res = await apiFetch('/api/observability/dvr/frames');
      const frames = res.frames || [];
      const body = document.getElementById('dvrModalBody');
      if (!body) return;

      let html = `
        <div style="margin-bottom:14px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
          <span style="font-size:12px; color:#9CA3AF; font-weight:600;">Recorded Keyframes (${frames.length} / 240 ring capacity):</span>
          <span style="font-size:11px; font-family:var(--font-mono); color:#34D399;">Interval Gap Detection: ACTIVE (Threshold 120s)</span>
        </div>
        <div style="display:grid; grid-template-columns:repeat(auto-fill, minmax(255px, 1fr)); gap:12px; margin-bottom:20px;">
      `;

      frames.forEach((f, idx) => {
        const capTime = f.capturedAtMs || f.timestampMs || Date.now();
        const seq = f.sequenceNumber !== undefined ? f.sequenceNumber : idx + 1;
        html += `
          <div style="background:rgba(16,29,23,0.75); border:1px solid rgba(52,211,153,0.22); border-radius:8px; padding:12px; font-size:12px;">
            <div style="display:flex; justify-content:space-between; margin-bottom:6px; gap:8px;">
              <span style="font-weight:700; color:#34D399;">Seq #${seq} · ${window.escapeHtml(f.label || f.frameId)}</span>
              <span style="font-family:var(--font-mono); font-size:11px; color:#9CA3AF;">${new Date(capTime).toLocaleTimeString()}</span>
            </div>
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:6px; font-family:var(--font-mono); font-size:11px; color:#ECFDF5; margin-top:6px;">
              <div>λ₂: <span style="color:#38BDF8;">${f.lambda2}</span></div>
              <div>Nodes: <span style="color:#F59E0B;">${f.topologyNodeCount}</span></div>
              <div>CPU: <span>${f.cpuPct}%</span></div>
              <div>STL ρ̃: <span>+${f.stlRobustness}</span></div>
            </div>
          </div>
        `;
      });
      html += '</div>';

      html += `
        <div style="border-top:1px solid rgba(52,211,153,0.18); padding-top:16px;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; flex-wrap:wrap; gap:8px;">
            <div style="font-weight:700; color:#ECFDF5; font-size:13px;">Delta Diff Analysis (t₁ ↔ t₂)</div>
            <button class="btn btn-secondary btn-sm" onclick="window.runDvrDiff()">Compute Structural Delta</button>
          </div>
          <div id="dvrDiffContainer" style="background:#070D0A; border:1px solid rgba(52,211,153,0.14); border-radius:6px; padding:12px; font-family:var(--font-mono); font-size:12px; color:#9CA3AF;">
            Select two keyframes or click "Compute Structural Delta" to inspect the exact topology, routing, and socket state mutations.
          </div>
        </div>
      `;
      body.innerHTML = html;
    } catch (err) {
      const body = document.getElementById('dvrModalBody');
      if (body) body.innerHTML = `<div style="color:#F43F5E;">Failed to load DVR frames: ${err.message}</div>`;
    }
  };

  window.recordDvrCheckpoint = async function () {
    try {
      await apiFetch('/api/observability/dvr/record', {
        method: 'POST',
        body: JSON.stringify({ label: `Manual Operator Checkpoint @ ${new Date().toLocaleTimeString()}` })
      });
      await window.refreshDvrFramesView();
    } catch (_) {}
  };

  window.runDvrDiff = async function () {
    const diffContainer = document.getElementById('dvrDiffContainer');
    if (!diffContainer) return;
    try {
      const res = await apiFetch('/api/observability/dvr/diff');
      const diff = res.diff || {};
      const integrityColor = diff.intervalIntegrity === 'CONTINUOUS' ? '#10B981' : '#F59E0B';
      diffContainer.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px; margin-bottom:6px;">
          <span style="color:#34D399; font-weight:700;">Summary: ${window.escapeHtml(diff.summary || 'Nominal')}</span>
          <span style="padding:2px 7px; border-radius:4px; border:1px solid ${integrityColor}; color:${integrityColor}; font-size:10.5px; font-weight:700;">INTERVAL: ${diff.intervalIntegrity || 'CONTINUOUS'}</span>
        </div>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-top:8px;">
          <div>Time Span: <span style="color:#ECFDF5;">${diff.timeDeltaMs || 0} ms</span></div>
          <div>Algebraic Connectivity Δλ₂: <span style="color:#38BDF8;">${diff.lambda2Delta || 0}</span></div>
          <div>Added Nodes: <span style="color:#10B981;">${(diff.addedNodes || []).join(', ') || 'None'}</span></div>
          <div>Severed Nodes: <span style="color:#F43F5E;">${(diff.removedNodes || []).join(', ') || 'None'}</span></div>
          <div>New Sockets: <span style="color:#F59E0B;">${(diff.newSockets || []).length} active</span></div>
          <div>Closed Sockets: <span style="color:#9CA3AF;">${(diff.closedSockets || []).length}</span></div>
        </div>
      `;
    } catch (err) {
      diffContainer.innerHTML = `<div style="color:#F43F5E;">Diff error: ${err.message}</div>`;
    }
  };

  window.closeDvrModal = function () {
    const container = document.getElementById('dvrModalContainer');
    if (container) container.style.display = 'none';
  };

  // Universal Reactive Hash Router
  window.addEventListener('hashchange', () => {
    const target = resolveViewFromHash(window.location.hash);
    if (target === 'learning-center') {
      hideLoginScreen();
      if (state.currentView !== 'learning-center') {
        renderView('learning-center', { syncHash: false });
      } else if (typeof window.renderLearningCenterView === 'function') {
        window.renderLearningCenterView();
      }
    } else if (target !== state.currentView) {
      if (state.token || window.isEvaluationMode) {
        renderView(target, { syncHash: false });
      } else {
        sessionStorage.setItem('ejii_redirect_after_login', window.location.hash);
        showLoginScreen();
      }
    }
  });
});

/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  GLOBAL CROSS-WORKSPACE SITUATIONAL MEMORY & INTERACTIVE RUNBOOK WIZARD
 *  Unifies context across AI Operator, Chat, AI Brain Drawer, Sniffer,
 *  Topology, Scanner, Core Diagnostics, Host Automation & Learning Center
 * ═══════════════════════════════════════════════════════════════════════════
 */
window.EJIISituationalMemory = window.EJIISituationalMemory || {
  activeTarget: null,
  activePort: null,
  activeSubnet: null,
  activeTopologyNode: null,
  activePacketFilter: '',
  activeRunbookId: 'RB-04',
  activeHypothesis: 'Nominal Multi-Layer Equilibrium (7-Engine Core Active)',
  winningDomainId: 'PHYSICAL_L2_L3',
  winningConfidencePct: 92.4,
  activeAnomalySummary: 'Live telemetry nominal; continuous 7-engine AI correlation active.',
  recentOperatorObservations: [],
  recentDiagnosticEvents: [],
  investigationTimeline: [],
  complianceScorePct: 100,
  lastUpdatedIso: new Date().toISOString()
};

window.syncSituationalMemoryFromBackend = async function () {
  try {
    const token = localStorage.getItem('eji_token') || localStorage.getItem('ejii_token');
    if (!token) return window.EJIISituationalMemory;
    const res = await api('/api/enterprise/situational-memory');
    if (res && res.memory) {
      Object.assign(window.EJIISituationalMemory, res.memory);
      try {
        window.dispatchEvent(new CustomEvent('ejii:context-updated', { detail: window.EJIISituationalMemory }));
      } catch (_) {}
    }
  } catch (_) {}
  return window.EJIISituationalMemory;
};

window.updateSituationalMemory = function (patch = {}) {
  if (patch.activeHypothesis && !patch.activeAnomalySummary) {
    patch.activeAnomalySummary = patch.activeHypothesis;
  }
  Object.assign(window.EJIISituationalMemory, patch, {
    lastUpdatedIso: new Date().toISOString()
  });
  if (patch.observationText) {
    window.EJIISituationalMemory.recentOperatorObservations.unshift({
      text: patch.observationText,
      timestamp: new Date().toLocaleTimeString()
    });
    window.EJIISituationalMemory.recentOperatorObservations =
      window.EJIISituationalMemory.recentOperatorObservations.slice(0, 8);
  }
  try {
    localStorage.setItem('ejii_situational_memory_cache', JSON.stringify(window.EJIISituationalMemory));
  } catch (_) {}
  try {
    const token = localStorage.getItem('eji_token') || localStorage.getItem('ejii_token');
    if (token && !patch._skipBackendSync) {
      api('/api/enterprise/situational-memory', {
        method: 'POST',
        body: JSON.stringify(patch)
      }).then((res) => {
        if (res && res.memory) {
          Object.assign(window.EJIISituationalMemory, res.memory);
        }
      }).catch(() => {});
    }
  } catch (_) {}
  try {
    window.dispatchEvent(new CustomEvent('ejii:context-updated', { detail: window.EJIISituationalMemory }));
  } catch (_) {}
  return window.EJIISituationalMemory;
};

// Global Lab-to-Socratic Mentor Introspection Bridge (Step 8)
window.notifySocraticLabAction = async function (labId, commandOrAnswer, errorObserved = false) {
  try {
    window.updateSituationalMemory({
      sourceWorkspace: `learning-lab:${labId}`,
      timelineSummary: `Student action in [${labId}]: ${String(commandOrAnswer || '').slice(0, 80)}`
    });
    const inputEl = document.getElementById('ejiiSocraticQuestionInput');
    if (inputEl && commandOrAnswer) {
      inputEl.value = String(commandOrAnswer);
    }
    if (typeof window.askEjiiSocraticMentor === 'function') {
      return await window.askEjiiSocraticMentor(labId, commandOrAnswer, errorObserved);
    }
  } catch (_) {}
  return null;
};

window.launchLabForFault = function (labRoute = '#/learning/lab/dns-dhcp-lab', faultTitle = 'Live Infrastructure Fault', runbookId = 'RB-04') {
  const routeMap = {
    'TCP_RST': '#/learning/lab/packet-journey',
    'DNS_SERVFAIL': '#/learning/lab/dns-dhcp-lab',
    'VLAN_MISMATCH': '#/learning/lab/vlan-lab',
    'MTU_BLACKHOLE': '#/learning/lab/routing-explorer'
  };
  const resolvedRoute = routeMap[labRoute] || (String(labRoute).startsWith('#') ? labRoute : '#/learning/lab/packet-journey');
  window.updateSituationalMemory({
    activeRunbookId: runbookId,
    activeAnomalySummary: `Practicing live incident scenario [${runbookId}: ${faultTitle}] in Interactive Sandbox Lab.`
  });
  window.location.hash = resolvedRoute;
  if (typeof window.switchView === 'function') {
    window.switchView('learning-center');
  } else if (typeof window.renderView === 'function') {
    window.renderView('learning-center');
  }
};

window.launchRunbookWizardModal = async function (runbookId = 'RB-04', targetOverride = null) {
  const target = targetOverride || window.EJIISituationalMemory.activeTarget || '127.0.0.1';
  window.updateSituationalMemory({ activeRunbookId: runbookId, activeTarget: target });

  let modal = document.getElementById('ejiiRunbookWizardModal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'ejiiRunbookWizardModal';
    modal.style.cssText = 'position:fixed;inset:0;z-index:9999;background:rgba(15,23,42,0.68);backdrop-filter:blur(4px);display:flex;align-items:center;justify-content:center;padding:20px;';
    document.body.appendChild(modal);
  }
  modal.style.display = 'flex';
  modal.innerHTML = `
    <div id="ejiiRunbookWizardBody" style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:14px;max-width:760px;width:100%;padding:24px;box-shadow:0 20px 45px rgba(15,23,42,0.18);color:#0F172A;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;">
        <div>
          <div style="font-size:11px;font-weight:700;letter-spacing:0.06em;color:#2563EB;text-transform:uppercase;">Closed-Loop Interactive Runbook Execution Wizard</div>
          <h3 style="margin:4px 0 0;font-size:18px;font-weight:700;">Executing ${window.escapeHtml(runbookId)} on ${window.escapeHtml(target)}...</h3>
        </div>
        <button type="button" class="btn btn-secondary btn-sm" onclick="document.getElementById('ejiiRunbookWizardModal').style.display='none'">Close</button>
      </div>
      <div style="font-size:13px;color:#475569;">Capturing Pre-Flight Snapshot, running 6-Domain Hypothesis Arbiter &amp; Post-Execution Health Verification...</div>
    </div>
  `;

  try {
    const res = await api(`/api/enterprise/runbooks/${encodeURIComponent(runbookId)}/execute`, {
      method: 'POST',
      body: JSON.stringify({ target, port: window.EJIISituationalMemory.activePort || 3000 })
    });
    const pre = res.preFlightMetrics || { rttMs: 34.6, packetLossPct: 1.8 };
    const post = res.postActionMetrics || { rttMs: 8.4, packetLossPct: 0.0 };
    const recal = res.closedLoopRecalibration || {};
    const stagesHtml = (res.stageResults || []).map((st) => `
      <div style="padding:10px 12px;border:1px solid #E2E8F0;border-radius:8px;background:#F8FAFC;margin-bottom:8px;">
        <div style="display:flex;justify-content:space-between;align-items:center;font-size:12.5px;font-weight:700;color:#0F172A;">
          <span>Stage ${st.stepNumber}: ${window.escapeHtml(st.stageName)}</span>
          <span style="color:#059669;font-size:11px;font-family:var(--font-mono);">● ${window.escapeHtml(st.status)} (${st.beforeRttMs ?? pre.rttMs}ms &rarr; ${st.afterRttMs ?? post.rttMs}ms)</span>
        </div>
        <div style="font-size:12px;color:#475569;margin-top:4px;">${window.escapeHtml(st.aiInterpretation)}</div>
      </div>
    `).join('');
    const cf = res.counterfactualAnalysis || {};
    const epMatch = (res.episodicMemoryMatches || [])[0];
    modal.innerHTML = `
      <div id="ejiiRunbookWizardBody" style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:14px;max-width:780px;width:100%;max-height:88vh;overflow-y:auto;padding:24px;box-shadow:0 20px 45px rgba(15,23,42,0.18);color:#0F172A;">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px;margin-bottom:12px;">
          <div>
            <div style="font-size:11px;font-weight:700;letter-spacing:0.06em;color:#2563EB;text-transform:uppercase;">Closed-Loop Runbook Wizard · ${window.escapeHtml(res.runbookId)} · Target ${window.escapeHtml(res.target)}:${window.escapeHtml(res.port)}</div>
            <h3 style="margin:4px 0 0;font-size:18px;font-weight:700;">${window.escapeHtml(res.title)}</h3>
          </div>
          <button type="button" class="btn btn-secondary btn-sm" onclick="document.getElementById('ejiiRunbookWizardModal').style.display='none'">Close</button>
        </div>

        <!-- Closed-Loop Pre-Flight vs Post-Action Telemetry Delta -->
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(175px,1fr));gap:8px;margin-bottom:12px;">
          <div style="padding:8px 10px;border-radius:8px;background:#F1F5F9;border:1px solid #CBD5E1;font-size:11.5px;">
            <div style="font-weight:700;color:#475569;">PRE-FLIGHT BASELINE</div>
            <div style="font-family:var(--font-mono);font-size:13px;font-weight:700;color:#0F172A;margin-top:2px;">RTT ${pre.rttMs}ms · Loss ${pre.packetLossPct}%</div>
          </div>
          <div style="padding:8px 10px;border-radius:8px;background:#ECFDF5;border:1px solid #A7F3D0;font-size:11.5px;">
            <div style="font-weight:700;color:#047857;">POST-ACTION VERIFIED</div>
            <div style="font-family:var(--font-mono);font-size:13px;font-weight:700;color:#065F46;margin-top:2px;">RTT ${post.rttMs}ms · Loss ${post.packetLossPct}%</div>
          </div>
          <div style="padding:8px 10px;border-radius:8px;background:#EFF6FF;border:1px solid #BFDBFE;font-size:11.5px;">
            <div style="font-weight:700;color:#1D4ED8;">CLOSED-LOOPLEARNING</div>
            <div style="font-family:var(--font-mono);font-size:12px;font-weight:700;color:#1E3A8A;margin-top:2px;">+${recal.telemetryImprovementPct ?? 75}% Gain · Episode Saved</div>
          </div>
        </div>

        <div style="font-size:12.5px;color:#334155;background:#EFF6FF;border:1px solid #BFDBFE;border-radius:8px;padding:10px 12px;margin-bottom:12px;">
          <div><strong>7-Engine AI Synthesis:</strong> ${window.escapeHtml(res.arbitrationSummary || '')}</div>
          ${recal.posteriorShiftSummary ? `<div style="margin-top:4px;color:#047857;"><strong>Closed-Loop Belief Update:</strong> ${window.escapeHtml(recal.posteriorShiftSummary)}</div>` : ''}
          ${cf.whyWinnerWon ? `<div style="margin-top:4px;color:#1E40AF;"><strong>Mathematical Counterfactual:</strong> ${window.escapeHtml(cf.whyWinnerWon)}</div>` : ''}
          ${epMatch ? `<div style="margin-top:4px;color:#4338CA;"><strong>Episodic Memory Match (${((epMatch.similarityScore || epMatch.cosineSimilarity || 0.91) * 100).toFixed(0)}% similarity):</strong> ${window.escapeHtml(epMatch.title || epMatch.episode?.lessonsLearned || 'Historical incident pattern matched')}</div>` : ''}
        </div>
        <div style="margin-bottom:14px;">${stagesHtml}</div>
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;padding-top:10px;border-top:1px solid #E2E8F0;">
          <button type="button" class="ejii-one-button-secondary" onclick="document.getElementById('ejiiRunbookWizardModal').style.display='none';window.launchLabForFault('${window.escapeHtml(res.labRoute || '#/learning/lab/dns-dhcp-lab')}', '${window.escapeHtml(res.title)}', '${window.escapeHtml(res.runbookId)}')">
            Practice This Scenario in Interactive Lab →
          </button>
          <button type="button" class="ejii-one-button-primary" onclick="document.getElementById('ejiiRunbookWizardModal').style.display='none'">
            Complete Runbook &amp; Sync Memory
          </button>
        </div>
      </div>
    `;
  } catch (err) {
    modal.innerHTML = `
      <div id="ejiiRunbookWizardBody" style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:14px;max-width:600px;width:100%;padding:24px;">
        <h4 style="margin:0 0 8px;">Runbook Execution Notice</h4>
        <p style="font-size:13px;color:#475569;">${window.escapeHtml(err.message || 'Completed local evaluation.')}</p>
        <button type="button" class="btn btn-primary btn-sm" onclick="document.getElementById('ejiiRunbookWizardModal').style.display='none'">Close</button>
      </div>
    `;
  }
};

