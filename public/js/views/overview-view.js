/**
 * EJII — Calm Executive & Engineering Overview Workstation
 * Quiet Luxury Design System: Grounded 100% in real backend endpoints
 * (/api/system/bootstrap, /api/network/topology, /api/v6/claude-mem/status, /api/github/status).
 *
 * Strict Epistemic & Data Integrity Contract:
 * - Unknown, missing, or unrecognized node status NEVER counts as Healthy.
 * - Explicitly distinguishes: Healthy, Warning, Degraded, Critical, Offline,
 *   Unreachable, Unknown, Not Measured, Unavailable, and Stale Telemetry.
 * - Distinguishes an empty discovery table (0 nodes) from an API failure (Unavailable).
 * - Never infers gateway health from a gateway node's presence alone.
 */

(function () {
  'use strict';

  const STALE_THRESHOLD_MS = 10 * 60 * 1000; // 10 minutes

  const overviewState = {
    loading: false,
    lastUpdated: null,
    lastUpdatedIso: null,
    preflight: null,
    topology: null,
    topologyError: null,
    claudeMem: null,
    claudeMemError: null,
    github: null,
    error: null
  };

  function esc(val) {
    if (val === null || val === undefined) return '';
    return String(val).replace(/[<>&"']/g, function (c) {
      return { '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function getGreeting() {
    const hr = new Date().getHours();
    if (hr < 12) return 'Good morning';
    if (hr < 18) return 'Good afternoon';
    return 'Good evening';
  }

  function getOperatorDisplayName() {
    if (window.state && window.state.user && (window.state.user.fullName || window.state.user.username)) {
      return window.state.user.fullName || window.state.user.username;
    }
    try {
      const userRaw = localStorage.getItem('ejii_user');
      if (userRaw) {
        const parsed = JSON.parse(userRaw);
        if (parsed && (parsed.displayName || parsed.fullName || parsed.username)) {
          return parsed.displayName || parsed.fullName || parsed.username;
        }
      }
    } catch (_) {}
    const nameEl = document.getElementById('userDisplayName');
    if (nameEl && nameEl.textContent && nameEl.textContent.trim()) {
      return nameEl.textContent.trim();
    }
    return 'Operator';
  }

  function getAuthHeaders() {
    const headers = { 'Accept': 'application/json' };
    try {
      const token = (window.state && window.state.token) || localStorage.getItem('ejii_token') || sessionStorage.getItem('ejii_token');
      if (token) headers['Authorization'] = 'Bearer ' + token;
    } catch (_) {}
    return headers;
  }

  async function fetchJsonSafe(url) {
    try {
      const res = await fetch(url, { headers: getAuthHeaders(), credentials: 'same-origin' });
      if (!res.ok) return { _httpStatus: res.status, _ok: false, _error: `HTTP ${res.status}` };
      const data = await res.json();
      return { ...data, _httpStatus: res.status, _ok: true };
    } catch (err) {
      return { _ok: false, _error: err && err.message ? err.message : 'Network error' };
    }
  }

  /**
   * Explicitly classifies a topology node into one of the canonical operational states:
   * - 'healthy'
   * - 'warning'
   * - 'degraded'
   * - 'critical'
   * - 'offline'
   * - 'unreachable'
   * - 'stale'
   * - 'not_measured'
   * - 'unknown'
   *
   * Unknown or unrecognized status is NEVER classified as 'healthy'.
   */
  function classifyNodeState(n) {
    if (!n || typeof n !== 'object') {
      return { key: 'unknown', label: 'Unknown', badgeClass: 'ql-badge-neutral', isHealthy: false, isUnhealthy: false, isUnknown: true, isStale: false };
    }

    // Check for stale timestamp if last_seen / updated_at is provided
    const rawTs = n.last_seen || n.updated_at || n.timestamp || null;
    if (rawTs) {
      const parsedMs = new Date(rawTs).getTime();
      if (Number.isFinite(parsedMs) && (Date.now() - parsedMs) > STALE_THRESHOLD_MS) {
        return { key: 'stale', label: 'Stale Telemetry', badgeClass: 'ql-badge-warning', isHealthy: false, isUnhealthy: false, isUnknown: true, isStale: true };
      }
    }

    const rawStatus = (n.status !== undefined && n.status !== null) ? String(n.status).trim().toLowerCase() : '';
    if (!rawStatus) {
      return { key: 'not_measured', label: 'Not Measured', badgeClass: 'ql-badge-neutral', isHealthy: false, isUnhealthy: false, isUnknown: true, isStale: false };
    }

    if (rawStatus === 'healthy' || rawStatus === 'online' || rawStatus === 'up' || rawStatus === 'reachable') {
      return { key: 'healthy', label: 'Healthy', badgeClass: 'ql-badge-success', isHealthy: true, isUnhealthy: false, isUnknown: false, isStale: false };
    }
    if (rawStatus === 'warning' || rawStatus === 'warn') {
      return { key: 'warning', label: 'Warning', badgeClass: 'ql-badge-warning', isHealthy: false, isUnhealthy: true, isUnknown: false, isStale: false };
    }
    if (rawStatus === 'degraded' || rawStatus === 'high_latency' || rawStatus === 'packet_loss') {
      return { key: 'degraded', label: 'Degraded', badgeClass: 'ql-badge-warning', isHealthy: false, isUnhealthy: true, isUnknown: false, isStale: false };
    }
    if (rawStatus === 'critical' || rawStatus === 'error' || rawStatus === 'fault') {
      return { key: 'critical', label: 'Critical', badgeClass: 'ql-badge-danger', isHealthy: false, isUnhealthy: true, isUnknown: false, isStale: false };
    }
    if (rawStatus === 'offline' || rawStatus === 'down') {
      return { key: 'offline', label: 'Offline', badgeClass: 'ql-badge-danger', isHealthy: false, isUnhealthy: true, isUnknown: false, isStale: false };
    }
    if (rawStatus === 'unreachable' || rawStatus === 'timeout') {
      return { key: 'unreachable', label: 'Unreachable', badgeClass: 'ql-badge-danger', isHealthy: false, isUnhealthy: true, isUnknown: false, isStale: false };
    }
    if (rawStatus === 'stale') {
      return { key: 'stale', label: 'Stale Telemetry', badgeClass: 'ql-badge-warning', isHealthy: false, isUnhealthy: false, isUnknown: true, isStale: true };
    }
    if (rawStatus === 'not_measured' || rawStatus === 'unmeasured' || rawStatus === 'pending') {
      return { key: 'not_measured', label: 'Not Measured', badgeClass: 'ql-badge-neutral', isHealthy: false, isUnhealthy: false, isUnknown: true, isStale: false };
    }
    if (rawStatus === 'unavailable') {
      return { key: 'unavailable', label: 'Unavailable', badgeClass: 'ql-badge-neutral', isHealthy: false, isUnhealthy: false, isUnknown: true, isStale: false };
    }

    return { key: 'unknown', label: 'Unknown', badgeClass: 'ql-badge-neutral', isHealthy: false, isUnhealthy: false, isUnknown: true, isStale: false };
  }

  function summarizeTopologyNodes(nodes, topologyAvailable) {
    if (!topologyAvailable) {
      return {
        available: false,
        total: null,
        healthyCount: 0,
        unhealthyCount: 0,
        unknownCount: 0,
        staleCount: 0,
        unhealthyNodes: [],
        unknownNodes: [],
        metricValue: 'Unavailable',
        metricSub: 'API unavailable',
        summaryPhrase: 'Topology telemetry unavailable (API error or unauthenticated)'
      };
    }

    const list = Array.isArray(nodes) ? nodes : [];
    if (list.length === 0) {
      return {
        available: true,
        total: 0,
        healthyCount: 0,
        unhealthyCount: 0,
        unknownCount: 0,
        staleCount: 0,
        unhealthyNodes: [],
        unknownNodes: [],
        metricValue: '0',
        metricSub: 'Not measured (no probe run)',
        summaryPhrase: '0 topology nodes discovered (active probe not yet executed)'
      };
    }

    let healthyCount = 0;
    let unhealthyCount = 0;
    let unknownCount = 0;
    let staleCount = 0;
    const unhealthyNodes = [];
    const unknownNodes = [];

    list.forEach((n) => {
      const cls = classifyNodeState(n);
      if (cls.isHealthy) {
        healthyCount += 1;
      } else if (cls.isUnhealthy) {
        unhealthyCount += 1;
        unhealthyNodes.push({ node: n, classification: cls });
      } else {
        unknownCount += 1;
        if (cls.isStale) staleCount += 1;
        unknownNodes.push({ node: n, classification: cls });
      }
    });

    let metricSub = '';
    let summaryPhrase = '';

    if (healthyCount === list.length && unhealthyCount === 0 && unknownCount === 0) {
      metricSub = `All ${healthyCount} verified healthy`;
      summaryPhrase = `${list.length} discovered topology node${list.length === 1 ? '' : 's'} (${healthyCount} verified healthy)`;
    } else {
      const subParts = [];
      if (healthyCount > 0) subParts.push(`${healthyCount} healthy`);
      if (unhealthyCount > 0) subParts.push(`${unhealthyCount} degraded/unreachable`);
      if (unknownCount > 0) subParts.push(`${unknownCount} unknown/unverified`);
      metricSub = subParts.join(' · ') || 'Status unverified';
      summaryPhrase = `${list.length} discovered topology node${list.length === 1 ? '' : 's'} (${metricSub})`;
    }

    return {
      available: true,
      total: list.length,
      healthyCount,
      unhealthyCount,
      unknownCount,
      staleCount,
      unhealthyNodes,
      unknownNodes,
      metricValue: String(list.length),
      metricSub,
      summaryPhrase
    };
  }

  async function refreshOverviewDashboard() {
    overviewState.loading = true;
    renderOverviewDom();

    const [bootstrap, topology, claudeMem, github] = await Promise.all([
      fetchJsonSafe('/api/system/bootstrap'),
      fetchJsonSafe('/api/network/topology'),
      fetchJsonSafe('/api/v6/claude-mem/status'),
      fetchJsonSafe('/api/github/status')
    ]);

    overviewState.preflight = bootstrap && bootstrap._ok ? bootstrap : null;

    if (topology && topology._ok && Array.isArray(topology.nodes)) {
      overviewState.topology = topology;
      overviewState.topologyError = null;
    } else if (bootstrap && bootstrap._ok && bootstrap.topology && Array.isArray(bootstrap.topology.nodes)) {
      overviewState.topology = bootstrap.topology;
      overviewState.topologyError = null;
    } else {
      overviewState.topology = null;
      overviewState.topologyError = (topology && topology._error) || 'Unavailable';
    }

    if (claudeMem && claudeMem._ok) {
      overviewState.claudeMem = claudeMem.data || claudeMem;
      overviewState.claudeMemError = null;
    } else {
      overviewState.claudeMem = null;
      overviewState.claudeMemError = (claudeMem && claudeMem._error) || 'Unavailable';
    }

    overviewState.github = github && github._ok ? github : (window.ejiiGitHubIntegration ? window.ejiiGitHubIntegration.getState() : null);
    overviewState.lastUpdated = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    overviewState.lastUpdatedIso = new Date().toISOString();
    overviewState.loading = false;

    renderOverviewDom();
  }

  function buildOperationalSummarySentence(topoSummary) {
    if (overviewState.loading && !overviewState.lastUpdated) {
      return 'Querying live host telemetry, physical topology discovery, and persistent memory state…';
    }
    const parts = [topoSummary.summaryPhrase];

    if (overviewState.preflight) {
      const sniffer = overviewState.preflight.sniffer || {};
      const capMode = (sniffer.counters && sniffer.counters.captureMode)
        || (sniffer.active ? 'ACTIVE_STREAM' : 'METADATA_ONLY');
      parts.push(`packet engine in ${capMode} mode`);
    } else {
      parts.push('packet engine status unavailable');
    }

    if (overviewState.github && overviewState.github.connected && overviewState.github.account) {
      const repoName = overviewState.github.selectedRepo ? overviewState.github.selectedRepo.fullName : ('@' + overviewState.github.account.login);
      parts.push(`GitHub linked to ${repoName}`);
    } else {
      parts.push('GitHub integration disconnected');
    }

    return parts.join(' · ') + '.';
  }

  function renderOverviewDom() {
    const container = document.getElementById('overviewDashboardRoot');
    if (!container) return;

    const topologyAvailable = Boolean(overviewState.topology && Array.isArray(overviewState.topology.nodes));
    const nodes = topologyAvailable ? overviewState.topology.nodes : [];
    const edges = (overviewState.topology && Array.isArray(overviewState.topology.edges))
      ? overviewState.topology.edges
      : [];
    const topoSummary = summarizeTopologyNodes(nodes, topologyAvailable);

    const gatewayNode = nodes.find((n) => n.role === 'gateway' || n.layer === 'edge' || n.layer_level === 2) || null;
    const gatewayClassification = gatewayNode ? classifyNodeState(gatewayNode) : null;
    let gatewayValueLabel = 'Unavailable';
    let gatewaySubLabel = 'API unavailable';
    if (topologyAvailable) {
      if (gatewayNode) {
        gatewayValueLabel = gatewayNode.hostname_or_ip || gatewayNode.name || 'Detected';
        const rttPart = (typeof gatewayNode.last_latency_ms === 'number' && Number.isFinite(gatewayNode.last_latency_ms))
          ? `${gatewayNode.last_latency_ms.toFixed(1)} ms RTT`
          : 'RTT not measured';
        gatewaySubLabel = `${gatewayClassification.label} · ${rttPart}`;
      } else {
        gatewayValueLabel = 'Not observed';
        gatewaySubLabel = 'No default route node in table';
      }
    }

    const sniffer = (overviewState.preflight && overviewState.preflight.sniffer) || {};
    const captureModeLabel = (sniffer.counters && sniffer.counters.captureMode)
      || (sniffer.active ? 'Active Stream' : (overviewState.preflight ? 'OS Metadata' : 'Unavailable'));
    const isWireGrade = Boolean(sniffer.counters && sniffer.counters.captureMode === 'WIRE_GRADE');

    const memAvailable = Boolean(overviewState.claudeMem && typeof overviewState.claudeMem.totalObservations === 'number');
    const memCountLabel = memAvailable
      ? String(overviewState.claudeMem.totalObservations)
      : 'Unavailable';

    const gh = overviewState.github || { connected: false, connectionState: 'DISCONNECTED' };
    const ghConnected = Boolean(gh.connected && gh.account);

    // Recent operational events & warnings grounded in real state
    const operationalEvents = [];
    topoSummary.unhealthyNodes.slice(0, 4).forEach(({ node: n, classification: cls }) => {
      const isCrit = cls.key === 'critical' || cls.key === 'offline' || cls.key === 'unreachable';
      operationalEvents.push({
        severity: isCrit ? 'critical' : 'warning',
        badge: cls.label,
        title: `Node ${n.name || n.hostname_or_ip || n.id} reported ${cls.label}`,
        detail: `Address: ${n.hostname_or_ip || 'Unknown'} · Latency: ${typeof n.last_latency_ms === 'number' ? n.last_latency_ms.toFixed(1) + ' ms' : 'Not measured'}`,
        actionView: 'topology'
      });
    });

    topoSummary.unknownNodes.slice(0, 2).forEach(({ node: n, classification: cls }) => {
      operationalEvents.push({
        severity: 'neutral',
        badge: cls.label,
        title: `Node ${n.name || n.hostname_or_ip || n.id} has ${cls.label.toLowerCase()} status`,
        detail: `Address: ${n.hostname_or_ip || 'Unknown'} · Run a live reachability probe to verify health.`,
        actionView: 'core-diagnostics'
      });
    });

    if (!isWireGrade && overviewState.preflight) {
      operationalEvents.push({
        severity: 'info',
        badge: 'Capability Notice',
        title: `Packet inspection running in ${captureModeLabel} mode`,
        detail: 'Kernel Npcap/libpcap wire driver not attached; using OS socket & flow telemetry.',
        actionView: 'packet-sniffer'
      });
    }
    if (gh.syncEvents && Array.isArray(gh.syncEvents)) {
      gh.syncEvents.slice(0, 3).forEach((evt) => {
        operationalEvents.push({
          severity: 'neutral',
          badge: 'GitHub',
          title: evt.summary || evt.type,
          detail: evt.detail || (evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : ''),
          actionModal: 'github'
        });
      });
    }

    container.innerHTML = `
      <div class="ql-overview-shell">
        <!-- Top Greeting & Operational Summary -->
        <header class="ql-overview-header">
          <div class="ql-overview-title-group">
            <div class="ql-overview-eyebrow">Workspace Overview</div>
            <h1 class="ql-overview-heading">${esc(getGreeting())}, ${esc(getOperatorDisplayName())}</h1>
            <p class="ql-overview-summary">${esc(buildOperationalSummarySentence(topoSummary))}</p>
          </div>
          <div class="ql-overview-header-actions">
            <span class="ql-updated-stamp">${overviewState.lastUpdated ? 'Updated ' + esc(overviewState.lastUpdated) : 'Synchronizing…'}</span>
            <button type="button" class="ql-btn ql-btn-secondary" onclick="window.refreshOverviewDashboard()">
              ${overviewState.loading ? 'Refreshing…' : 'Refresh Telemetry'}
            </button>
            <button type="button" class="ql-btn ql-btn-primary" onclick="window.switchMainView('chat')">
              Ask AI Assistant
            </button>
          </div>
        </header>

        <!-- Restrained Quick-Entry Cards -->
        <section class="ql-quick-actions-grid" aria-label="Primary Workstations">
          <button type="button" class="ql-quick-card" onclick="window.switchMainView('chat')">
            <div class="ql-quick-card-top">
              <span class="ql-quick-card-title">AI Assistant</span>
              <span class="ql-quick-card-arrow">→</span>
            </div>
            <p class="ql-quick-card-desc">Investigate reachability, DNS, latency, and routing in plain language.</p>
          </button>

          <button type="button" class="ql-quick-card" onclick="window.switchMainView('topology')">
            <div class="ql-quick-card-top">
              <span class="ql-quick-card-title">Network Overview</span>
              <span class="ql-quick-card-arrow">→</span>
            </div>
            <p class="ql-quick-card-desc">${topologyAvailable && nodes.length > 0 ? `${nodes.length} discovered node${nodes.length === 1 ? '' : 's'} &amp; ${edges.length} link${edges.length === 1 ? '' : 's'}` : 'Inspect physical L2/L3 topology &amp; gateway paths'}.</p>
          </button>

          <button type="button" class="ql-quick-card" onclick="window.switchMainView('core-diagnostics')">
            <div class="ql-quick-card-top">
              <span class="ql-quick-card-title">Diagnostics &amp; Recovery</span>
              <span class="ql-quick-card-arrow">→</span>
            </div>
            <p class="ql-quick-card-desc">Run verified host sockets, SLA forecasting, and audited remediation.</p>
          </button>

          <button type="button" class="ql-quick-card" onclick="window.openGitHubIntegrationModal()">
            <div class="ql-quick-card-top">
              <span class="ql-quick-card-title">GitHub Integration</span>
              <span class="ql-quick-card-arrow">→</span>
            </div>
            <p class="ql-quick-card-desc">${ghConnected ? `Connected as @${esc(gh.account.login)}` : 'Connect repository commits &amp; CI workflows'}.</p>
          </button>
        </section>

        <!-- Two-Column Primary Operational Grid -->
        <div class="ql-overview-main-grid">
          <!-- Left Column: Live Infrastructure & Topology Posture -->
          <div class="ql-overview-col">
            <section class="ql-surface-card">
              <div class="ql-card-header">
                <div>
                  <h2 class="ql-card-title">Infrastructure &amp; Topology Posture</h2>
                  <p class="ql-card-subtitle">Live nodes, gateway status, and packet capture driver state</p>
                </div>
                <button type="button" class="ql-btn ql-btn-secondary" onclick="window.switchMainView('topology')">
                  Open Topology Map
                </button>
              </div>

              <div class="ql-metric-strip">
                <div class="ql-metric-cell">
                  <span class="ql-metric-label">Discovered Nodes</span>
                  <span class="ql-metric-value mono">${esc(topoSummary.metricValue)}</span>
                  <span class="ql-metric-sub">${esc(topoSummary.metricSub)}</span>
                </div>
                <div class="ql-metric-cell">
                  <span class="ql-metric-label">Default Gateway</span>
                  <span class="ql-metric-value mono">${esc(gatewayValueLabel)}</span>
                  <span class="ql-metric-sub">${esc(gatewaySubLabel)}</span>
                </div>
                <div class="ql-metric-cell">
                  <span class="ql-metric-label">Capture Engine</span>
                  <span class="ql-metric-value mono">${esc(captureModeLabel)}</span>
                  <span class="ql-metric-sub">${overviewState.preflight ? (isWireGrade ? 'Hardware wire capture' : 'Socket / OS metadata') : 'Telemetry unavailable'}</span>
                </div>
              </div>

              ${!topologyAvailable ? `
                <div class="ql-empty-inline">
                  Topology endpoint is currently <strong>Unavailable</strong> (${esc(overviewState.topologyError || 'API unreachable')}). Authenticate or refresh telemetry to query live nodes.
                </div>
              ` : (nodes.length > 0 ? (() => {
                const totalNodes = Math.max(1, topoSummary.total || nodes.length);
                const healthyPct = ((topoSummary.healthyCount / totalNodes) * 100).toFixed(1);
                const unhealthyPct = ((topoSummary.unhealthyCount / totalNodes) * 100).toFixed(1);
                const stalePct = ((topoSummary.staleCount / totalNodes) * 100).toFixed(1);
                const unverifiedCount = Math.max(0, topoSummary.unknownCount - topoSummary.staleCount);
                const unknownPct = ((unverifiedCount / totalNodes) * 100).toFixed(1);

                const measuredLatencies = nodes
                  .map((n) => (typeof n.last_latency_ms === 'number' && Number.isFinite(n.last_latency_ms) ? n.last_latency_ms : null))
                  .filter((v) => v !== null);
                const maxRtt = measuredLatencies.length > 0 ? Math.max(25, ...measuredLatencies) : 100;

                return `
                <div class="ql-posture-viz-wrap" aria-label="Infrastructure Posture Distribution">
                  <div class="ql-posture-bar-header">
                    <span class="ql-posture-bar-title">Posture Distribution (${nodes.length} Discovered Node${nodes.length === 1 ? '' : 's'})</span>
                    <span class="mono">${measuredLatencies.length}/${nodes.length} RTT measured</span>
                  </div>
                  <div class="ql-posture-bar-track" role="img" aria-label="${esc(topoSummary.summaryPhrase)}">
                    ${topoSummary.healthyCount > 0 ? `<div class="ql-posture-seg ql-posture-seg-healthy" style="width:${healthyPct}%" title="Healthy: ${topoSummary.healthyCount}"></div>` : ''}
                    ${topoSummary.unhealthyCount > 0 ? `<div class="ql-posture-seg ql-posture-seg-unhealthy" style="width:${unhealthyPct}%" title="Degraded / Unreachable: ${topoSummary.unhealthyCount}"></div>` : ''}
                    ${topoSummary.staleCount > 0 ? `<div class="ql-posture-seg ql-posture-seg-stale" style="width:${stalePct}%" title="Stale Telemetry: ${topoSummary.staleCount}"></div>` : ''}
                    ${unverifiedCount > 0 ? `<div class="ql-posture-seg ql-posture-seg-unknown" style="width:${unknownPct}%" title="Unknown / Not Measured: ${unverifiedCount}"></div>` : ''}
                  </div>
                  <div class="ql-posture-legend">
                    <span class="ql-posture-legend-item"><span class="ql-posture-legend-dot" style="background:var(--status-nominal)"></span>Healthy: <strong>${topoSummary.healthyCount}</strong></span>
                    <span class="ql-posture-legend-item"><span class="ql-posture-legend-dot" style="background:var(--status-critical)"></span>Degraded/Unreachable: <strong>${topoSummary.unhealthyCount}</strong></span>
                    ${topoSummary.staleCount > 0 ? `<span class="ql-posture-legend-item"><span class="ql-posture-legend-dot" style="background:var(--status-warning)"></span>Stale: <strong>${topoSummary.staleCount}</strong></span>` : ''}
                    <span class="ql-posture-legend-item"><span class="ql-posture-legend-dot" style="background:var(--text-muted);opacity:0.65"></span>Unknown/Not Measured: <strong>${unverifiedCount}</strong></span>
                  </div>
                </div>
                <div class="ql-table-wrap">
                  <table class="ql-clean-table">
                    <thead>
                      <tr>
                        <th>Node</th>
                        <th>Address</th>
                        <th>Role</th>
                        <th>RTT</th>
                        <th>Status</th>
                        <th style="text-align:right">Context</th>
                      </tr>
                    </thead>
                    <tbody>
                      ${nodes.slice(0, 6).map((n) => {
                        const cls = classifyNodeState(n);
                        const hasRtt = typeof n.last_latency_ms === 'number' && Number.isFinite(n.last_latency_ms);
                        const rttLabel = hasRtt
                          ? `${n.last_latency_ms.toFixed(1)} ms`
                          : 'Not measured';
                        const rttPct = hasRtt ? Math.min(100, Math.max(8, Math.round((n.last_latency_ms / maxRtt) * 100))) : 0;
                        const rttToneClass = hasRtt ? (n.last_latency_ms > 150 ? 'is-crit' : (n.last_latency_ms > 60 ? 'is-warn' : '')) : '';
                        const targetAddr = n.hostname_or_ip || n.ip || n.name || n.id || '';
                        const rawLabel = n.name || n.hostname_or_ip || n.id || 'Node';
                        const cleanNodeLabel = rawLabel.replace(/\s*\([^)]+\)\s*$/, '').trim() || rawLabel;
                        const roleLabel = n.role || n.layer || 'endpoint';
                        return `
                          <tr onclick="window.switchMainView('topology')" style="cursor:pointer;">
                            <td class="ql-td-primary">${esc(cleanNodeLabel)}</td>
                            <td class="mono">${esc(n.hostname_or_ip || 'Unknown')}</td>
                            <td>${esc(roleLabel)}</td>
                            <td class="mono">
                              ${hasRtt ? `
                                <div class="ql-rtt-cell" style="min-width:86px;gap:6px;">
                                  <div class="ql-rtt-bar-track" style="width:36px;" aria-hidden="true">
                                    <div class="ql-rtt-bar-fill ${rttToneClass}" style="width:${rttPct}%"></div>
                                  </div>
                                  <span>${esc(rttLabel)}</span>
                                </div>
                              ` : `<span style="color:var(--text-muted)">${esc(rttLabel)}</span>`}
                            </td>
                            <td><span class="ql-status-badge ${cls.badgeClass}"><span class="ql-badge-dot"></span>${esc(cls.label)}</span></td>
                            <td style="text-align:right" onclick="event.stopPropagation();">
                              <div class="ql-row-actions">
                                ${targetAddr ? `<button type="button" class="ql-row-action-btn" onclick="window.pinOverviewNodeTarget('${esc(targetAddr)}', '${esc(cleanNodeLabel)}', '${esc(roleLabel)}', event)" title="Pin this node as active investigation context">Pin</button>` : ''}
                              </div>
                            </td>
                          </tr>
                        `;
                      }).join('')}
                    </tbody>
                  </table>
                </div>
                `;
              })() : `
                <div class="ql-empty-inline">
                  0 topology nodes discovered in current table (<strong>Not Measured</strong>). Open <strong>Network Overview</strong> or <strong>IP &amp; Asset Discovery</strong> to trigger an active subnet probe.
                </div>
              `)}
            </section>

            <section class="ql-surface-card">
              <div class="ql-card-header">
                <div>
                  <h2 class="ql-card-title">Sovereign AI &amp; Persistent Memory</h2>
                  <p class="ql-card-subtitle">Evidence-grounded diagnostics &amp; Claude-Mem observation store</p>
                </div>
                <button type="button" class="ql-btn ql-btn-secondary" onclick="window.switchMainView('chat')">
                  Open AI Assistant
                </button>
              </div>
              <div class="ql-ai-overview-row">
                <div class="ql-ai-stat">
                  <span class="ql-metric-label">Stored Observations</span>
                  <span class="ql-metric-value mono">${esc(memCountLabel)}</span>
                </div>
                <div class="ql-ai-stat">
                  <span class="ql-metric-label">Isolation Policy</span>
                  <span class="ql-metric-value">Per-User Scoped</span>
                </div>
                <div class="ql-ai-stat">
                  <span class="ql-metric-label">Execution Mode</span>
                  <span class="ql-metric-value">Verified OS Probes</span>
                </div>
              </div>
            </section>
          </div>

          <!-- Right Column: Operational Events & GitHub Repository Integration -->
          <div class="ql-overview-col">
            <section class="ql-surface-card" id="overviewGitHubCardContainer">
              ${buildOverviewGitHubCardHtml(gh, overviewState.loading)}
            </section>

            <section class="ql-surface-card">
              <div class="ql-card-header">
                <div>
                  <h2 class="ql-card-title">Operational Notices &amp; Recent Activity</h2>
                  <p class="ql-card-subtitle">Verified warnings, capability boundaries, and sync events</p>
                </div>
              </div>
              ${operationalEvents.length > 0 ? `
                <div class="ql-event-list">
                  ${operationalEvents.map((ev) => `
                    <div class="ql-event-item">
                      <div class="ql-event-top">
                        <span class="ql-status-badge ql-badge-${ev.severity === 'critical' ? 'danger' : (ev.severity === 'warning' ? 'warning' : (ev.severity === 'info' ? 'info' : 'neutral'))}">
                          <span class="ql-badge-dot"></span>${esc(ev.badge)}
                        </span>
                        <span class="ql-event-title">${esc(ev.title)}</span>
                      </div>
                      <p class="ql-event-detail">${esc(ev.detail)}</p>
                    </div>
                  `).join('')}
                </div>
              ` : `
                <div class="ql-empty-inline">
                  No active infrastructure warnings or anomalies detected across current probes.
                </div>
              `}
            </section>
          </div>
        </div>
      </div>
    `;
  }

  function buildOverviewGitHubCardHtml(gh, isBusy) {
    const isConnected = Boolean(gh && gh.connected && gh.account);
    const connState = (gh && gh.connectionState) || 'DISCONNECTED';

    let badge = '<span class="gh-status-pill gh-status-disconnected"><span class="gh-status-dot"></span>Disconnected</span>';
    if (isBusy) {
      badge = '<span class="gh-status-pill gh-status-loading"><span class="gh-status-dot"></span>Syncing…</span>';
    } else if (isConnected) {
      badge = '<span class="gh-status-pill gh-status-connected"><span class="gh-status-dot"></span>Connected</span>';
    } else if (connState === 'RATE_LIMITED') {
      badge = '<span class="gh-status-pill gh-status-warning"><span class="gh-status-dot"></span>Rate Limited</span>';
    }

    if (!isConnected) {
      return `
        <div class="ql-card-header">
          <div>
            <h2 class="ql-card-title">GitHub Repository &amp; CI Sync</h2>
            <p class="ql-card-subtitle">Real OAuth account connection &amp; workflow visibility</p>
          </div>
          ${badge}
        </div>
        <div class="ql-gh-overview-empty">
          <p>No GitHub account is currently connected. Connect your GitHub account to track repository branches, latest commits, and GitHub Actions workflow status alongside network operations.</p>
          <div class="ql-gh-overview-actions">
            <button type="button" class="ql-btn ql-btn-primary" onclick="window.ejiiGitHubIntegration ? window.ejiiGitHubIntegration.connect() : window.openGitHubIntegrationModal()">
              Connect GitHub Account
            </button>
            <button type="button" class="ql-btn ql-btn-secondary" onclick="window.openGitHubIntegrationModal()">
              Configure Settings
            </button>
          </div>
        </div>
      `;
    }

    const repo = gh.selectedRepo;
    const commit = gh.latestCommit;
    const wf = gh.latestWorkflow;

    return `
      <div class="ql-card-header">
        <div>
          <h2 class="ql-card-title">GitHub Repository &amp; CI Sync</h2>
          <p class="ql-card-subtitle">Connected as @${esc(gh.account.login)}</p>
        </div>
        ${badge}
      </div>
      <div class="ql-gh-connected-summary">
        <div class="gh-repo-kv-grid">
          <div class="gh-kv-item">
            <span class="gh-kv-label">Repository</span>
            <span class="gh-kv-val mono">${repo ? esc(repo.fullName) : 'None selected'}</span>
          </div>
          <div class="gh-kv-item">
            <span class="gh-kv-label">Branch</span>
            <span class="gh-kv-val mono">${repo ? esc(repo.defaultBranch) : '—'}</span>
          </div>
        </div>
        ${commit ? `
          <div class="gh-commit-box">
            <div class="gh-commit-top">
              <span class="gh-commit-sha mono">${esc(commit.shortSha || commit.sha)}</span>
              <span class="gh-commit-msg">${esc(commit.message)}</span>
            </div>
          </div>
        ` : ''}
        <div class="ql-gh-overview-actions" style="margin-top: 12px;">
          <button type="button" class="ql-btn ql-btn-secondary" onclick="window.ejiiGitHubIntegration && window.ejiiGitHubIntegration.sync()">
            Sync Repository
          </button>
          <button type="button" class="ql-btn ql-btn-secondary" onclick="window.openGitHubIntegrationModal()">
            Manage Repository (${wf ? esc(wf.conclusion || wf.status) : 'Details'})
          </button>
        </div>
      </div>
    `;
  }

  function renderOverviewView(targetContainer) {
    const container = targetContainer || document.getElementById('overviewContainer');
    if (!container) return;
    if (!document.getElementById('overviewDashboardRoot')) {
      container.innerHTML = '<div id="overviewDashboardRoot"></div>';
    }
    renderOverviewDom();
    refreshOverviewDashboard();
  }

  window.classifyEjiiNodeState = classifyNodeState;
  window.summarizeEjiiTopologyNodes = summarizeTopologyNodes;
  window.renderOverviewView = renderOverviewView;
  window.refreshOverviewDashboard = refreshOverviewDashboard;
  window.pinOverviewNodeTarget = function (targetIp, nodeLabel, roleLabel, ev) {
    if (ev && typeof ev.stopPropagation === 'function') ev.stopPropagation();
    if (!targetIp) return;
    if (window.EJIIInvestigationPinboard && typeof window.EJIIInvestigationPinboard.pin === 'function') {
      window.EJIIInvestigationPinboard.pin({
        target: targetIp,
        ip: targetIp,
        hostname: nodeLabel || targetIp,
        role: roleLabel || 'endpoint',
        sourceWorkspace: 'overview'
      });
    }
    if (typeof window.updateSituationalMemory === 'function') {
      window.updateSituationalMemory({
        activeTarget: targetIp,
        activeTargetIp: targetIp,
        activeTopologyNode: nodeLabel || targetIp,
        sourceWorkspace: 'overview'
      });
    }
    if (ev && ev.currentTarget) {
      const btn = ev.currentTarget;
      const orig = btn.textContent;
      btn.textContent = '✓ Pinned';
      setTimeout(() => { btn.textContent = orig; }, 1400);
    }
  };
  window.renderOverviewGitHubCard = function (ghStatus, isBusy) {
    overviewState.github = ghStatus;
    const card = document.getElementById('overviewGitHubCardContainer');
    if (card) {
      card.innerHTML = buildOverviewGitHubCardHtml(ghStatus, isBusy);
    }
  };
})();
