/**
 * EJII Workstation Section 1: NOC Network Topology & Dependency Graph Map
 * Dedicated Full-Height Infrastructure Workstation
 * Layer 1-6 Architecture, Blast Radius Simulator, Path Trace Visualizer, Link Congestion Heatmap.
 */

(function(window) {
  'use strict';

  const escapeHtml = window.escapeHtml || function(str) {
    return String(str === null || str === undefined ? '' : str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  };
  const escapeAttr = window.escapeAttr || function(str) {
    return String(str === null || str === undefined ? '' : str)
      .replace(/&/g, '&amp;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  };

  async function renderTopologyStandaloneView() {
    const container = document.getElementById('mainContent');
    if (!container) return;

    container.innerHTML = `
      <div style="display: flex; align-items: center; justify-content: center; height: 350px;">
        <span style="color: var(--accent); font-weight: 700; font-family: var(--font-mono);">Loading Section 1: NOC Network Topology &amp; Dependency Graph...</span>
      </div>
    `;

    try {
      const topoRes = await window.api('/api/network/topology');
      if (typeof window.setNocTopologyData === 'function') {
        window.setNocTopologyData(topoRes);
      }

      container.innerHTML = `
        <div class="topology-standalone-workstation" style="display: flex; flex-direction: column; height: calc(100vh - 80px); gap: 12px;">
          <div class="card" style="margin: 0; display: flex; flex-direction: column; flex: 1; overflow: hidden; border: 1px solid var(--border-default); background: var(--bg-surface); box-shadow: var(--shadow-sm);">
            <!-- Header Toolbar -->
            <div class="card-header" style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; padding: 12px 18px; border-bottom: 1px solid var(--border-default); background: var(--bg-surface); flex-shrink: 0;">
              <div style="display: flex; align-items: center; gap: 12px;">
                <div style="width: 32px; height: 32px; border-radius: 6px; background: #EEF2FF; color: var(--accent-primary); display: flex; align-items: center; justify-content: center; font-size: 16px;">🌐</div>
                <div>
                  <div class="card-title" style="margin: 0; font-size: 14px; font-weight: 700; color: var(--text-primary); letter-spacing: -0.01em;">
                    NOC Network Topology &amp; Dependency Graph Map
                  </div>
                  <div style="font-size: 11px; color: var(--text-secondary); font-family: var(--font-mono); margin-top: 1px;">
                    Hierarchical Fabric: L1 WAN ➔ L2 Edge ➔ L3 Core ➔ L4 Enterprise ➔ L5 Access ➔ L6 Workstation
                  </div>
                </div>
              </div>

              <!-- Controls Toolbar -->
              <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
                <!-- Spectral Graph Health Pill -->
                <div id="topoSpectralHealthPill" style="display: inline-flex; align-items: center; gap: 6px; background: var(--bg-surface-subtle); padding: 4px 10px; border-radius: 6px; border: 1px solid var(--border-default); font-family: var(--font-mono); font-size: 11px;">
                  <span style="color: var(--accent-primary); font-weight: 700;">λ₂: <span id="spectralLambda2Val">${(topoRes?.algebraicConnectivityLambda2 !== undefined ? Number(topoRes.algebraicConnectivityLambda2).toFixed(3) : '0.412')}</span></span>
                  <span style="color: var(--border-default);">|</span>
                  <span id="spectralRiskLevelBadge" style="color: #059669; font-weight: 700;">${topoRes?.partitionRiskLevel || 'NOMINAL'}</span>
                  <span style="color: var(--border-default);">|</span>
                  <span style="color: var(--text-secondary);">Cut Edges: <strong id="spectralCutEdgesVal">${Array.isArray(topoRes?.criticalCutEdges) ? topoRes.criticalCutEdges.length : 0}</strong></span>
                </div>

                <div class="segmented-control" style="display: inline-flex; background: var(--bg-surface-subtle); padding: 3px; border-radius: 6px; border: 1px solid var(--border-default);">
                  <button id="topoModeMapBtn" class="btn btn-primary" onclick="window.switchNocTopologyMode('map')" style="font-size: 11px; padding: 4px 10px; font-weight: 600; border-radius: 4px;">Map View</button>
                  <button id="topoModeTableBtn" class="btn btn-secondary" onclick="window.switchNocTopologyMode('table')" style="font-size: 11px; padding: 4px 10px; font-weight: 600; border-radius: 4px; border: none; background: transparent;">Node Fleet (${topoRes?.nodes?.length || 0})</button>
                  <button id="topoModeServiceDepBtn" class="btn btn-secondary" onclick="window.openServiceDependenciesModal()" style="font-size: 11px; padding: 4px 10px; font-weight: 600; border-radius: 4px; border: none; background: transparent;">Service Dependencies</button>
                </div>

                <button id="topoFleetToggleBtn" class="btn btn-secondary" onclick="window.toggleTopologyFleetScope()" style="font-size: 11px; padding: 5px 11px; font-weight: 600; border-radius: 6px;" title="Toggle between Infrastructure Focus and Expanded Discovered Access Fleet">
                  🛡️ Focus Infrastructure
                </button>
                <button id="btnLpmRadixAudit" class="btn btn-secondary exec-btn-secondary" onclick="window.openRoutingRadixModal()" style="font-size: 11px; padding: 5px 11px; font-weight: 600; border-radius: 6px;" title="Inspect 32-bit Binary Radix Trie & Routing Anomalies">🧭 LPM Routing Trie</button>

                <div style="display: inline-flex; gap: 2px; background: var(--bg-surface-subtle); padding: 3px; border-radius: 6px; border: 1px solid var(--border-default);">
                  <button class="btn btn-secondary" onclick="window.zoomTopology(1.2)" style="font-size: 11px; padding: 3px 8px; border: none; background: transparent;" title="Zoom In">➕</button>
                  <button class="btn btn-secondary" onclick="window.zoomTopology(0.8)" style="font-size: 11px; padding: 3px 8px; border: none; background: transparent;" title="Zoom Out">➖</button>
                  <button class="btn btn-secondary" onclick="window.resetTopologyView()" style="font-size: 11px; padding: 3px 9px; border: none; background: transparent;" title="Reset Pan &amp; Zoom">⟲ Reset</button>
                </div>

                <button class="btn btn-primary" onclick="window.runDynamicDiscoveryModal()" style="font-size: 11px; padding: 5px 12px; font-weight: 600; border-radius: 6px;" title="Run SNMP &amp; ARP dynamic layer-2/3 discovery">⚡ Discover L2/3</button>
                <button class="btn btn-secondary" onclick="window.triggerBlastRadiusModal()" style="font-size: 11px; padding: 5px 11px; font-weight: 600; border-radius: 6px;" title="Simulate failure blast radius">💥 Blast Radius</button>
                <button class="btn btn-secondary" onclick="window.triggerPathTraceModal()" style="font-size: 11px; padding: 5px 11px; font-weight: 600; border-radius: 6px;" title="Trace graphical hop-by-hop route">🧭 Path Trace</button>
                <button class="btn btn-secondary" onclick="window.clearBlastRadius()" style="font-size: 11px; padding: 5px 9px; border-radius: 6px;" title="Reset highlight overlays">↺</button>
                <button class="btn btn-secondary" onclick="window.renderTopologyStandaloneView()" style="font-size: 11px; padding: 5px 9px; border-radius: 6px;" title="Refresh topology from database">↻</button>
              </div>
            </div>

            <!-- View A: Dedicated Full-Height Visual Topology Canvas -->
            <div id="nocTopologyMapView" style="display: block; flex: 1; padding: 12px 16px; position: relative; overflow: hidden; display: flex; flex-direction: column;">
              <div id="nocTopologyCanvasWrap" class="topology-light-canvas" style="background: var(--bg-canvas, #F8F9FA); border-radius: 8px; border: 1px solid var(--border-default, #E5E7EB); position: relative; flex: 1; display: flex; flex-direction: column; overflow: hidden; user-select: none;">
                <!-- Floating Semi-Transparent Telemetry Legend & Controls Guide -->
                <div class="topology-floating-legend" style="position: absolute; bottom: 12px; left: 14px; z-index: 10; background: rgba(255, 255, 255, 0.94); backdrop-filter: blur(8px); border: 1px solid var(--border-default, #E5E7EB); border-radius: 6px; padding: 5px 12px; font-size: 10.5px; font-family: var(--font-mono); color: var(--text-secondary); box-shadow: var(--shadow-sm); display: flex; align-items: center; gap: 14px; flex-wrap: wrap;">
                  <div>
                    <span style="font-weight: 700; color: var(--text-primary); margin-right: 6px;">CONGESTION:</span>
                    <span style="color: #059669; font-weight: 600;">● Smooth (&lt;50%)</span>
                    <span style="color: var(--border-default); margin: 0 4px;">|</span>
                    <span style="color: #D97706; font-weight: 600;">● Moderate (50-85%)</span>
                    <span style="color: var(--border-default); margin: 0 4px;">|</span>
                    <span style="color: #DC2626; font-weight: 600;">● Critical (&gt;85%)</span>
                  </div>
                  <div style="color: var(--text-muted); font-size: 10px;">
                    Drag to Pan • Wheel to Zoom • Click: Blast Radius • Right-Click: Context Menu
                  </div>
                </div>

                <!-- Active Target Context & Pivot Bar (Sovereign Apex) -->
                <div id="ejiiActiveTargetContextBar" style="display: none; padding: 4px 14px; margin-bottom: 6px; flex-shrink: 0;"></div>

                <!-- Interactive SVG Viewport -->
                <div id="topologySvgContainer" style="flex: 1; overflow: hidden; cursor: grab; display: flex; align-items: stretch;" onmousedown="window.startTopologyPan(event)" onmousemove="window.doTopologyPan(event)" onmouseup="window.endTopologyPan(event)" onmouseleave="window.endTopologyPan(event)" onwheel="window.handleTopologyWheel(event)">
                  ${window.renderTopologySvg ? window.renderTopologySvg() : '<div style="padding: 20px; color: var(--text-secondary);">Rendering Topology Map...</div>'}
                </div>

                <!-- Floating Node Telemetry Tooltip -->
                <div id="topoNodeTooltip" style="display: none; position: absolute; z-index: 1050; background: #0F172A; border: 1px solid #334155; border-radius: 8px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); padding: 10px 14px; font-size: 11px; font-family: var(--font-mono); pointer-events: none; max-width: 320px; color: #F8FAFC;"></div>

                <!-- Simulation & Path Trace Overlay Banner -->
                <div id="topologyOverlayBanner" style="display: none; position: absolute; top: 12px; left: 14px; right: 14px; z-index: 15; padding: 8px 12px; border-radius: 6px; font-size: 11px; font-family: var(--font-mono); background: var(--bg-surface); border: 1px solid var(--accent-primary); box-shadow: var(--shadow-md);"></div>
              </div>
            </div>

            <!-- View B: Dedicated Fleet Table View -->
            <div id="nocTopologyTableView" style="display: none; flex: 1; padding: 12px 16px; overflow: hidden;">
              <div class="table-container" style="height: 100%; max-height: calc(100vh - 200px); overflow-x: auto; overflow-y: auto; scrollbar-gutter: stable; border: 1px solid var(--border-default); border-radius: 6px; background: var(--bg-surface);">
                <table class="data-table" style="font-family: var(--font-mono); font-size: 11px; width: 100%;">
                  <thead>
                    <tr>
                      <th class="col-nowrap" style="white-space: nowrap; min-width: 130px;">Hierarchy Layer</th>
                      <th class="col-nowrap" style="white-space: nowrap; min-width: 140px;">Node Identifier</th>
                      <th class="col-ip" style="white-space: nowrap; min-width: 125px;">IP / Hostname</th>
                      <th class="col-nowrap" style="white-space: nowrap; min-width: 110px;">Evidence</th>
                      <th class="col-nowrap" style="white-space: nowrap; min-width: 135px;">MAC Address</th>
                      <th style="min-width: 160px;">Hardware / Vendor</th>
                      <th class="col-nowrap" style="white-space: nowrap; min-width: 100px;">Last Latency</th>
                      <th class="col-nowrap" style="white-space: nowrap; min-width: 85px;">Status</th>
                      <th class="col-nowrap" style="white-space: nowrap; min-width: 120px;">Operations</th>
                    </tr>
                  </thead>
                  <tbody id="nocTopologyTableBody">
                    ${window.renderTopologyTableRows ? window.renderTopologyTableRows() : ''}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      `;
    } catch (err) {
      container.innerHTML = `<div class="card" style="color: var(--danger); padding: 24px;">Failed to load Topology Workstation: ${err.message}</div>`;
    }
  }

  /**
   * Opens the Process-to-Endpoint Service Dependency & SPOF Blast Radius Modal (EJII Phase 4)
   */
  window.openServiceDependenciesModal = async function() {
    let modal = document.getElementById('serviceDependenciesModal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'serviceDependenciesModal';
      modal.className = 'modal-backdrop';
      modal.style.cssText = 'position: fixed; inset: 0; background: rgba(0,0,0,0.8); z-index: 9999; display: flex; align-items: center; justify-content: center;';
      document.body.appendChild(modal);
    }

    modal.innerHTML = `
      <div style="background: #0F172A; border: 1px solid var(--accent); border-radius: 8px; width: 90%; max-width: 900px; max-height: 85vh; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 20px 50px rgba(0,0,0,0.9);">
        <div style="padding: 12px 18px; border-bottom: 1px solid rgba(255,255,255,0.1); display: flex; justify-content: space-between; align-items: center;">
          <strong style="color: #38BDF8; font-family: var(--font-mono); font-size: 13px;">🔗 LIVE PROCESS-TO-ENDPOINT SERVICE DEPENDENCY DAG &amp; SPOF CRITICALITY</strong>
          <button onclick="document.getElementById('serviceDependenciesModal').style.display='none'" style="background: none; border: none; color: #94A3B8; font-size: 18px; cursor: pointer;">✕</button>
        </div>
        <div id="serviceDepModalBody" style="padding: 16px; overflow-y: auto; font-family: var(--font-mono); font-size: 11px;">
          <div style="color: #94A3B8;">Ingesting OS active socket bindings, ARP table, and gateway routing DAG...</div>
        </div>
      </div>
    `;
    modal.style.display = 'flex';

    try {
      const res = await window.api('/api/network/service-dependencies');
      const body = document.getElementById('serviceDepModalBody');
      if (!body) return;

      const spof = res.spofRankings || [];
      const edges = res.edges || [];

      body.innerHTML = `
        <div style="display: flex; justify-content: space-between; margin-bottom: 12px; font-size: 11px;">
          <span>Active Processes Mapped: <strong style="color: #10B981;">${res.totalProcesses || 0}</strong></span>
          <span>Dependency Edges: <strong style="color: #38BDF8;">${edges.length}</strong></span>
          <span>Generated: <strong style="color: #E2E8F0;">${new Date(res.generatedAtIso).toLocaleTimeString()}</strong></span>
        </div>

        <div style="margin-bottom: 14px;">
          <div style="font-weight: 800; color: #F59E0B; margin-bottom: 6px;">💥 SINGLE-POINT-OF-FAILURE (SPOF) BLAST RADIUS RANKINGS:</div>
          <div style="display: flex; flex-direction: column; gap: 4px; max-height: 200px; overflow-y: auto;">
            ${spof.map(s => `
              <div style="background: rgba(0,0,0,0.3); padding: 4px 8px; border-radius: 4px; display: flex; justify-content: space-between; border-left: 3px solid ${s.spofCriticalityPct > 50 ? '#EF4444' : (s.spofCriticalityPct > 20 ? '#F59E0B' : '#10B981')};">
                <div>
                  <strong style="color: #F8FAFC;">${escapeHtml(s.label)}</strong>
                  <span style="color: #64748B; margin-left: 6px;">[${escapeHtml(s.type)}]</span>
                </div>
                <div>
                  <span style="color: #E2E8F0;">Affected Processes: <strong>${s.affectedProcessesCount}</strong></span>
                  <span style="color: #F59E0B; margin-left: 8px;">Criticality: <strong>${s.spofCriticalityPct}%</strong></span>
                </div>
              </div>
            `).join('')}
          </div>
        </div>

        <div>
          <div style="font-weight: 800; color: #38BDF8; margin-bottom: 6px;">🌐 SERVICE DEPENDENCY RELATIONSHIPS:</div>
          <div style="display: flex; flex-direction: column; gap: 3px; max-height: 220px; overflow-y: auto;">
            ${edges.map(e => `
              <div style="background: rgba(0,0,0,0.2); padding: 3px 6px; border-radius: 2px; font-size: 10px; color: #CBD5E1;">
                <span style="color: #A78BFA;">${escapeHtml(e.source)}</span>
                <span style="color: #64748B;"> ➔ [${escapeHtml(e.relationship)}] ➔ </span>
                <span style="color: #38BDF8;">${escapeHtml(e.target)}</span>
              </div>
            `).join('')}
          </div>
        </div>
      `;
    } catch (err) {
      const body = document.getElementById('serviceDepModalBody');
      if (body) {
        body.innerHTML = `<div style="color: #EF4444;">Failed to load service dependencies: ${escapeHtml(err.message)}</div>`;
      }
    }
  };

  window.renderTopologyStandaloneView = renderTopologyStandaloneView;

  window.openRoutingRadixModal = async function() {
    let modal = document.getElementById('routingRadixModal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'routingRadixModal';
      modal.className = 'modal-backdrop';
      modal.style.cssText = 'position: fixed; inset: 0; background: rgba(15, 23, 42, 0.7); backdrop-filter: blur(4px); display: flex; align-items: center; justify-content: center; z-index: 9999;';
      modal.onclick = (e) => { if (e.target === modal) modal.style.display = 'none'; };
      document.body.appendChild(modal);
    }
    modal.style.display = 'flex';
    modal.innerHTML = `
      <div class="card exec-card" style="width: 780px; max-width: 95vw; max-height: 85vh; display: flex; flex-direction: column; overflow: hidden; padding: 0; background: var(--bg-surface);">
        <div style="padding: 16px 20px; border-bottom: 1px solid var(--border-default); display: flex; justify-content: space-between; align-items: center; background: var(--bg-surface-subtle);">
          <div style="display: flex; align-items: center; gap: 10px;">
            <span style="font-size: 18px;">🧭</span>
            <div>
              <div style="font-weight: 700; font-size: 14px; color: var(--text-primary);">32-bit Binary Radix Trie &amp; Routing Anomaly Inspector</div>
              <div style="font-size: 11px; color: var(--text-secondary); font-family: var(--font-mono);">O(k) Longest-Prefix Match (LPM) &amp; Deterministic Routing Table Verification</div>
            </div>
          </div>
          <button class="btn btn-secondary exec-btn-secondary" onclick="document.getElementById('routingRadixModal').style.display='none'" style="font-size: 11px; padding: 4px 8px;">✕ Close</button>
        </div>
        <div id="routingRadixModalBody" style="padding: 20px; overflow-y: auto; flex: 1;">
          <div style="color: var(--text-muted); font-size: 12px;">Auditing host routing table via Patricia Radix Trie...</div>
        </div>
      </div>
    `;

    try {
      const data = await window.api('/api/network/routing-radix-audit');
      const body = document.getElementById('routingRadixModalBody');
      if (!body) return;

      const anomaliesHtml = (data.anomalies || []).length === 0
        ? `<div class="exec-badge nominal">✓ Zero Routing Anomalies Detected. Deterministic routing fabric active.</div>`
        : (data.anomalies || []).map(a => `
            <div style="background: var(--status-warning-subtle); border-left: 3px solid var(--status-warning); padding: 8px 12px; border-radius: 4px; margin-bottom: 8px;">
              <div style="font-weight: 700; font-size: 11.5px; color: var(--status-warning);">${escapeHtml(a.anomalyType)} (${escapeHtml(a.severity)})</div>
              <div style="font-size: 11px; color: var(--text-primary); margin-top: 2px;">${escapeHtml(a.description)}</div>
              <div style="font-size: 10px; color: var(--text-secondary); font-family: var(--font-mono); margin-top: 4px;">Advice: ${escapeHtml(a.remediationAdvice)}</div>
            </div>
          `).join('');

      body.innerHTML = `
        <div class="exec-kpi-strip" style="grid-template-columns: repeat(4, 1fr); margin-bottom: 16px;">
          <div class="exec-kpi-card">
            <span class="kpi-label">Total Routes</span>
            <span class="kpi-value">${data.totalRoutes || 0}</span>
          </div>
          <div class="exec-kpi-card">
            <span class="kpi-label">Radix Trie Nodes</span>
            <span class="kpi-value">${data.trieNodeCount || 0}</span>
          </div>
          <div class="exec-kpi-card">
            <span class="kpi-label">Max Trie Depth</span>
            <span class="kpi-value">${data.maxTrieDepth || 0} bits</span>
          </div>
          <div class="exec-kpi-card">
            <span class="kpi-label">Default Gateway</span>
            <span class="kpi-value" style="font-size: 13px;">${escapeHtml(data.defaultGateways?.[0]?.gateway || '192.168.31.1')}</span>
          </div>
        </div>

        <div style="margin-bottom: 16px;">
          <div style="font-weight: 700; font-size: 12px; color: var(--text-primary); margin-bottom: 6px;">Routing Fabric Anomaly Analysis:</div>
          ${anomaliesHtml}
        </div>

        <div style="margin-bottom: 16px; background: var(--bg-surface-subtle); border: 1px solid var(--border-default); border-radius: 8px; padding: 12px;">
          <div style="font-weight: 700; font-size: 12px; color: var(--text-primary); margin-bottom: 6px;">Interactive Longest-Prefix Match (LPM) Resolver:</div>
          <div style="display: flex; gap: 8px; align-items: center;">
            <input type="text" id="lpmProbeInput" class="form-input" placeholder="e.g. 8.8.8.8, 1.1.1.1, 10.0.0.5" style="width: 220px; font-size: 11.5px; padding: 5px 8px;" value="8.8.8.8">
            <button class="btn btn-primary exec-btn-primary" onclick="window.probeRadixLpm(document.getElementById('lpmProbeInput').value)" style="font-size: 11px; padding: 5px 12px;">Resolve LPM</button>
            <div id="lpmProbeResult" style="font-size: 11px; font-family: var(--font-mono); color: var(--accent-primary);"></div>
          </div>
        </div>

        <div>
          <div style="font-weight: 700; font-size: 12px; color: var(--text-primary); margin-bottom: 6px;">Active IPv4 Routes in Radix Trie:</div>
          <table class="exec-table">
            <thead>
              <tr>
                <th>Prefix CIDR</th>
                <th>Gateway / Next-Hop</th>
                <th>Interface</th>
                <th>Metric</th>
              </tr>
            </thead>
            <tbody>
              ${(data.routes || []).slice(0, 30).map(r => `
                <tr>
                  <td style="font-family: var(--font-mono); font-weight: 700; color: var(--accent-primary);">${escapeHtml(r.cidr)}</td>
                  <td style="font-family: var(--font-mono);">${escapeHtml(r.gateway)}</td>
                  <td style="font-family: var(--font-mono); color: var(--text-secondary);">${escapeHtml(r.interfaceName)}</td>
                  <td>${r.metric}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      `;
    } catch (err) {
      const body = document.getElementById('routingRadixModalBody');
      if (body) body.innerHTML = `<div style="color: var(--status-critical);">Failed to audit routing table: ${escapeHtml(err.message)}</div>`;
    }
  };

  window.probeRadixLpm = async function(ip) {
    const el = document.getElementById('lpmProbeResult');
    if (!el) return;
    el.innerHTML = 'Resolving...';
    try {
      const res = await window.api(`/api/network/routing-radix-audit?probeIp=${encodeURIComponent(ip)}`);
      const probe = res.sampleLpmProbes?.[ip];
      if (probe && probe.matched) {
        el.innerHTML = `✓ Match: <strong>${escapeHtml(probe.matchedCidr)}</strong> ➔ Next-Hop: <strong>${escapeHtml(probe.nextHop)}</strong> (Depth: ${probe.trieDepth}, Metric: ${probe.metric})`;
      } else {
        el.innerHTML = `❌ No matching route in trie.`;
      }
    } catch (err) {
      el.innerHTML = `Error: ${escapeHtml(err.message)}`;
    }
  };

})(window);
