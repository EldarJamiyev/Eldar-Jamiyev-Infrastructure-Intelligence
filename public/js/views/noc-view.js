function escapeHtml(str) {
  return String(str === null || str === undefined ? '' : str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
function escapeAttr(str) {
  return String(str === null || str === undefined ? '' : str)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}
window.escapeHtml = escapeHtml;
window.escapeAttr = escapeAttr;

(function(window) {
  'use strict';

  let isRenderingPacketRows = false;
  let isRenderingFlowRows = false;
  let isFlushingBatch = false;

  let liveFrames = [];
  let liveFlows = [];
  let topologyData = { nodes: [], edges: [], layers: [] };
  let frameBatchQueue = [];
  let batchFlushInterval = null;
  let flowPollingTimer = null;
  let flowRenderScheduled = false;
  let isCapturing = true;
  let isDisplayFrozen = false;
  let isTableHovered = false;
  let autoScrollFrames = true;
  let selectedFrame = null;
  let selectedFrameNumber = null;
  let selectedFlow = null;
  let currentSnifferMode = 'packets';
  let currentTopologyMode = 'map';
  let topoFleetExpanded = true;
  let topoZoom = 1.0;
  let topoPanX = 0;
  let topoPanY = 0;
  let isPanning = false;
  let panStartX = 0;
  let panStartY = 0;
  let nodeCoordinatesMap = new Map();
  let protocolFilter = 'ALL';
  let searchFilter = '';
  let hideInternalEji = true;
  let activeBlastRadiusNode = null;
  let activePathTrace = null;
  let activeFlowOverlay = null;
  let contextTarget = null;

  window.toggleHideInternalEji = function(checked) {
    hideInternalEji = Boolean(checked);
    const tbodyPackets = document.getElementById('livePacketTableBody');
    if (tbodyPackets) tbodyPackets.innerHTML = renderPacketRows();
    const tbodyFlows = document.getElementById('nirsoftFlowTableBody');
    if (tbodyFlows) tbodyFlows.innerHTML = renderFlowRows();
  };

  /**
   * Main NOC Workstation Renderer
   */
  async function renderNocView() {
    if (batchFlushInterval) clearInterval(batchFlushInterval);
    if (flowPollingTimer) clearInterval(flowPollingTimer);

    // 300ms smooth frame batch flusher
    batchFlushInterval = setInterval(flushPacketBatch, 300);

    const container = document.getElementById('mainContent');
    container.innerHTML = `
      <div style="display: flex; align-items: center; justify-content: center; height: 300px;">
        <span style="color: var(--accent); font-weight: 700;">Initializing NOC Dual-Pane Workstation &amp; Live Wire Dissector...</span>
      </div>
    `;

    try {
      const [topoRes, captureStatusRes, initialFramesRes, flowsRes, sharedOutagesRes] = await Promise.all([
        window.api('/api/network/topology'),
        window.api('/api/network/capture/status').catch(() => ({ active: true })),
        window.api('/api/network/capture/frames?limit=60').catch(() => ({ frames: [] })),
        window.api('/api/network/capture/flows?limit=60').catch(() => ({ flows: [] })),
        window.api('/api/rca/brain/shared-outages').catch(() => ({ clusters: [] }))
      ]);

      topologyData = topoRes || { nodes: [], edges: [], layers: [] };
      isCapturing = captureStatusRes ? captureStatusRes.active : true;
      if (initialFramesRes && initialFramesRes.frames) liveFrames = initialFramesRes.frames;
      if (flowsRes && flowsRes.flows) liveFlows = flowsRes.flows;

      let outageBannerHtml = '';
      if (sharedOutagesRes && Array.isArray(sharedOutagesRes.clusters) && sharedOutagesRes.clusters.length > 0) {
        const clusterDescs = sharedOutagesRes.clusters.map(c => `<strong>${escapeHtml(c.upstreamTarget || c.switchOrGateway || 'Upstream Gateway')}</strong> (${(c.affectedHosts || []).length} failing hosts)`).join(', ');
        outageBannerHtml = `
          <div id="sharedOutageAlertBanner" class="alert alert-warning" style="margin-bottom: 8px; background: rgba(245, 158, 11, 0.15); border: 1px solid #F59E0B; color: #FCD34D; padding: 8px 14px; border-radius: 6px; display: flex; align-items: center; gap: 10px; font-size: 12px;">
            <span style="font-size: 16px;">⚠️</span>
            <div>
              <strong>Shared Upstream Subnet Outage Correlated:</strong> Concurrent failures detected downstream of ${clusterDescs}.
            </div>
          </div>
        `;
      }

      // Start capture stream if paused
      if (!isCapturing) {
        window.api('/api/network/capture/start', { method: 'POST' }).then(() => {
          isCapturing = true;
          updateCaptureStatusUI(true);
        }).catch(() => {});
        isCapturing = true;
      }

      container.innerHTML = `
        <div class="noc-dual-pane">
          <!-- Autonomous AI Diagnostic Brain Live Drawer -->
          <div id="nocAiBrainDrawerContainer" class="ai-brain-drawer-mount" style="margin-bottom: 8px;"></div>

          ${outageBannerHtml}

          <!-- UPPER PANE: NOC NETWORK TOPOLOGY & DEPENDENCY GRAPH -->
          <div class="noc-pane-upper card" style="margin: 0; border: 1px solid var(--border-default); background: var(--bg-surface); box-shadow: var(--shadow-sm);">
            <div class="card-header" style="display: flex; flex-direction: column; gap: 10px; padding: 12px 16px; border-bottom: 1px solid var(--border-default); background: var(--bg-surface);">
              <!-- Tier 1: Title, Subtitle, and Primary Actions -->
              <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
                <div style="display: flex; align-items: center; gap: 10px;">
                  <div style="width: 28px; height: 28px; border-radius: 6px; background: #F1F5F9; color: var(--accent-primary); display: flex; align-items: center; justify-content: center;">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
                  </div>
                  <div>
                    <div class="card-title" style="margin: 0; font-size: 13.5px; font-weight: 700; color: var(--text-primary);">Pillar 1: NOC Network Topology &amp; Dependency Graph</div>
                    <div style="font-size: 11px; color: var(--text-secondary); font-family: var(--font-sans); margin-top: 1px;">
                      Hierarchical Fabric: Upstream WAN ➔ Edge Gateway ➔ Core Backbone ➔ Enterprise Services ➔ Access LAN ➔ Workstation
                    </div>
                  </div>
                </div>

                <div style="display: flex; gap: 6px; align-items: center;">
                  <button class="btn btn-primary" onclick="window.runDynamicDiscoveryModal()" style="font-size: 11px; padding: 4px 12px; font-weight: 600; border-radius: 6px; white-space: nowrap;" title="Run SNMP &amp; ARP dynamic layer-2/3 discovery">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 4px; vertical-align: -2px;"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>Discover Network
                  </button>
                  <button class="btn btn-secondary" onclick="window.clearBlastRadius()" style="font-size: 11px; padding: 4px 8px; border-radius: 6px;" title="Reset highlight overlays">↺</button>
                  <button class="btn btn-secondary" onclick="window.refreshTopologyView()" style="font-size: 11px; padding: 4px 8px; border-radius: 6px;" title="Refresh topology from database">↻</button>
                </div>
              </div>

              <!-- Tier 2: Health Spectral Pill and Inspection Toolbar -->
              <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
                <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
                  <!-- Spectral Graph Health Pill -->
                  <div id="nocSpectralHealthPill" style="white-space: nowrap !important; display: inline-flex !important; align-items: center !important; gap: 6px; background: var(--bg-surface-subtle); padding: 4px 10px; border-radius: 6px; border: 1px solid var(--border-default); font-family: var(--font-mono); font-size: 11px; flex-shrink: 0;">
                    <span style="color: var(--accent-primary); font-weight: 700;">λ₂: <span id="nocSpectralLambda2Val">${(topologyData.algebraicConnectivityLambda2 !== undefined ? Number(topologyData.algebraicConnectivityLambda2).toFixed(3) : '0.412')}</span></span>
                    <span style="color: var(--border-default);">|</span>
                    <span id="nocSpectralRiskBadge" style="color: ${topologyData.partitionRiskLevel === 'NOMINAL' ? '#059669' : (topologyData.partitionRiskLevel === 'FRAGILE_BRIDGE' ? '#D97706' : '#DC2626')}; font-weight: 700;">${topologyData.partitionRiskLevel === 'NOMINAL' ? 'Healthy Mesh' : (topologyData.partitionRiskLevel === 'FRAGILE_BRIDGE' ? 'Single-Bridge Topology' : 'Partition Risk')}</span>
                    <span style="color: var(--border-default);">|</span>
                    <span style="color: var(--text-secondary);">Cut Edges: <strong id="nocSpectralCutVal">${Array.isArray(topologyData.criticalCutEdges) ? topologyData.criticalCutEdges.length : 0}</strong></span>
                  </div>

                  <div class="segmented-control" style="display: inline-flex; gap: 2px; background: var(--bg-surface-subtle); padding: 2px; border-radius: 6px; border: 1px solid var(--border-default);">
                    <button id="topoModeMapBtn" class="btn ${currentTopologyMode === 'map' ? 'btn-primary' : 'btn-secondary'}" onclick="window.switchNocTopologyMode('map')" style="font-size: 11px; padding: 3px 8px; font-weight: 600; border-radius: 4px;">Topology Map</button>
                    <button id="topoModeTableBtn" class="btn ${currentTopologyMode === 'table' ? 'btn-primary' : 'btn-secondary'}" onclick="window.switchNocTopologyMode('table')" style="font-size: 11px; padding: 3px 8px; font-weight: 600; border-radius: 4px; border: none; background: transparent;">Fleet (${topologyData.nodes.length})</button>
                  </div>
                </div>

                <div style="display: flex; gap: 6px; align-items: center; flex-wrap: wrap;">
                  <button id="topoFleetToggleBtn" class="btn ${topoFleetExpanded ? 'btn-primary' : 'btn-secondary'}" onclick="window.toggleTopologyFleetScope()" style="font-size: 11px; padding: 4px 9px; font-weight: 600; border-radius: 6px;" title="Toggle between Infrastructure Focus and Expanded Discovered Access Fleet">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 4px; vertical-align: -2px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>${topoFleetExpanded ? 'Focus Infrastructure' : 'Expand Fleet (' + (topologyData.nodes.length) + ')'}
                  </button>
                  <div style="display: inline-flex; gap: 2px; background: var(--bg-surface-subtle); padding: 2px; border-radius: 6px; border: 1px solid var(--border-default);">
                    <button class="btn btn-secondary" onclick="window.zoomTopology(1.2)" style="font-size: 11px; padding: 3px 7px; border: none; background: transparent;" title="Zoom In">+</button>
                    <button class="btn btn-secondary" onclick="window.zoomTopology(0.8)" style="font-size: 11px; padding: 3px 7px; border: none; background: transparent;" title="Zoom Out">−</button>
                    <button class="btn btn-secondary" onclick="window.resetTopologyView()" style="font-size: 11px; padding: 3px 8px; border: none; background: transparent;" title="Reset Pan &amp; Zoom">⟲ Reset</button>
                  </div>
                  <button class="btn btn-secondary" id="btnSyncTopologyLocation" onclick="window.syncTopologyLocationNow()" style="font-size: 11px; padding: 4px 9px; font-weight: 600; border-radius: 6px;" title="Instantly detect active NIC, default gateway, ARP neighbors &amp; auto-align topology to current location">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 4px; vertical-align: -2px;"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>Sync Subnet
                  </button>
                  <button id="btnNocRadixAudit" class="btn btn-secondary exec-btn-secondary" onclick="window.openRoutingRadixModal()" style="font-size: 11px; padding: 4px 9px; font-weight: 600; border-radius: 6px;" title="Inspect 32-bit Binary Radix Trie & Routing Anomalies">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 4px; vertical-align: -2px;"><circle cx="12" cy="12" r="10"/><polygon points="16.24 7.76 14.12 14.12 7.76 16.24 9.88 9.88 16.24 7.76"/></svg>LPM Trie
                  </button>
                  <button id="btnNocChaosSimulator" class="btn btn-secondary exec-btn-secondary" onclick="window.openDigitalTwinChaosModal()" style="font-size: 11px; padding: 4px 9px; font-weight: 600; border-radius: 6px;" title="Digital Twin Chaos & M/M/1/K What-If Network Simulator">
                    <span style="margin-right: 4px;">🧪</span>Chaos Simulator
                  </button>
                </div>
              </div>
            </div>

            <!-- View A: Interactive Visual Topology Canvas -->
            <div id="nocTopologyMapView" style="display: ${currentTopologyMode === 'map' ? 'block' : 'none'}; padding: 12px 16px;">
              <div id="nocTopologyCanvasWrap" class="topology-light-canvas" style="background: var(--bg-canvas, #F8F9FA); border-radius: 8px; border: 1px solid var(--border-default, #E5E7EB); position: relative; overflow: hidden; user-select: none;">
                <!-- Floating Semi-Transparent Telemetry Legend & Controls Guide -->
                <div class="topology-floating-legend" style="position: absolute; bottom: 12px; left: 14px; z-index: 10; background: rgba(255, 255, 255, 0.94); backdrop-filter: blur(8px); border: 1px solid var(--border-default, #E5E7EB); border-radius: 6px; padding: 4px 12px; font-size: 10.5px; font-family: var(--font-mono); color: var(--text-secondary); box-shadow: var(--shadow-sm); display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
                  <div>
                    <span style="font-weight: 700; color: var(--text-primary); margin-right: 4px;">CONGESTION:</span>
                    <span style="color: #059669; font-weight: 600;">● Smooth (&lt;50%)</span> | <span style="color: #D97706; font-weight: 600;">● Moderate (50-85%)</span> | <span style="color: #DC2626; font-weight: 600;">● Critical (&gt;85%)</span>
                  </div>
                  <div style="color: var(--text-muted); font-size: 10px;">
                    Drag to Pan • Wheel to Zoom • Click: Blast Radius
                  </div>
                </div>

                <!-- Active Target Context & Pivot Bar (Sovereign Apex) -->
                <div id="ejiiActiveTargetContextBar" style="display: none; padding: 4px 14px; margin-bottom: 6px; flex-shrink: 0;"></div>

                <div id="topologySvgContainer" style="overflow: hidden; cursor: grab;" onmousedown="window.startTopologyPan(event)" onmousemove="window.doTopologyPan(event)" onmouseup="window.endTopologyPan(event)" onmouseleave="window.endTopologyPan(event)" onwheel="window.handleTopologyWheel(event)">
                  ${renderTopologySvg()}
                </div>

                <!-- Floating Node HUD Tooltip -->
                <div id="topoNodeTooltip" style="display: none; position: absolute; z-index: 1050; background: #0F172A; border: 1px solid #334155; border-radius: 8px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); padding: 10px 14px; font-size: 11px; font-family: var(--font-mono); pointer-events: none; max-width: 320px; color: #F8FAFC;"></div>

                <!-- Simulation & Path Trace Overlay Banner -->
                <div id="topologyOverlayBanner" style="display: none; position: absolute; top: 12px; left: 14px; right: 14px; z-index: 15; padding: 8px 12px; border-radius: 6px; font-size: 11px; font-family: var(--font-mono); background: var(--bg-surface); border: 1px solid var(--accent-primary); box-shadow: var(--shadow-md);"></div>
              </div>
            </div>

            <!-- View B: Fleet Table View -->
            <div id="nocTopologyTableView" style="display: ${currentTopologyMode === 'table' ? 'block' : 'none'};">
              <div class="table-container" style="max-height: 320px; overflow-y: auto; scrollbar-gutter: stable;">
                <table class="data-table">
                  <thead>
                    <tr>
                      <th class="col-nowrap">Hierarchy Layer</th>
                      <th>Node Identifier</th>
                      <th class="col-ip">IP / Hostname</th>
                      <th class="col-nowrap">Evidence</th>
                      <th class="col-nowrap">MAC Address</th>
                      <th>Hardware / Vendor</th>
                      <th class="col-nowrap">Last Latency</th>
                      <th class="col-nowrap">Status</th>
                      <th class="col-nowrap">Operations</th>
                    </tr>
                  </thead>
                  <tbody id="nocTopologyTableBody">
                    ${renderTopologyTableRows()}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          <!-- LOWER PANE: WIRESHARK-GRADE LIVE PACKET SNIFFER & STREAM DISSECTOR -->
          <div class="noc-pane-lower card" style="margin: 0;">
            <div class="card-header" style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; padding: 12px 16px;">
              <div style="display: flex; align-items: center; gap: 10px;">
                <span style="font-size: 20px;">🦈</span>
                <div>
                  <div class="card-title" style="margin: 0; font-size: 14px;">Pillar 2: Wireshark-Grade Live Packet Sniffer &amp; Stream Dissector</div>
                  <div style="font-size: 11px; color: var(--text-muted);">Real Physical Wire Ingestion &bull; RFC Protocol Dissection &bull; TCP Delta &amp; Retransmission Tracker</div>
                </div>
                <span id="captureLiveIndicator" style="display: inline-flex; align-items: center; gap: 4px; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 12px; background: rgba(52, 211, 153, 0.15); color: var(--success);">
                  <span class="status-dot" style="background: var(--success);"></span>
                  <span id="captureStatusLabel">STREAMING</span>
                </span>
              </div>

              <!-- Stream Controls -->
              <div style="display: flex; align-items: center; gap: 6px; flex-wrap: wrap;">
                <div class="segmented-control" style="display: inline-flex; gap: 2px; background: var(--bg-surface-subtle); padding: 2px; border-radius: 6px; border: 1px solid var(--border-default);">
                  <button id="viewModePacketsBtn" class="btn ${currentSnifferMode === 'packets' ? 'btn-primary' : 'btn-secondary'}" onclick="window.switchNocSnifferMode('packets')" style="font-size: 11px; padding: 3px 8px; font-weight: 600; border-radius: 4px;">📋 Live Frames</button>
                  <button id="viewModeFlowsBtn" class="btn ${currentSnifferMode === 'flows' ? 'btn-primary' : 'btn-secondary'}" onclick="window.switchNocSnifferMode('flows')" style="font-size: 11px; padding: 3px 8px; font-weight: 600; border-radius: 4px; border: none; background: transparent;">📊 Flow Matrix (35 Cols)</button>
                </div>

                <select id="packetProtocolFilter" class="form-input" style="width: 95px; padding: 4px 6px; font-size: 11px; border-radius: 6px;" onchange="window.onPacketProtocolFilterChange(this.value)">
                  <option value="ALL">All Proto</option>
                  <option value="TCP">TCP</option>
                  <option value="UDP">UDP</option>
                  <option value="DNS">DNS</option>
                  <option value="HTTP">HTTP</option>
                  <option value="TLS">TLS</option>
                  <option value="ICMP">ICMP</option>
                  <option value="ARP">ARP</option>
                  <option value="DHCP">DHCP</option>
                  <option value="MDNS">mDNS</option>
                </select>

                <input type="text" id="packetSearchInput" class="form-input" placeholder="Search IP, port, URL, host..." style="width: 150px; padding: 4px 6px; font-size: 11px; border-radius: 6px;" oninput="window.onPacketSearchChange(this.value)">

                <label style="display: flex; align-items: center; gap: 4px; font-size: 11px; color: var(--text-secondary); cursor: pointer; user-select: none;">
                  <input type="checkbox" id="hideInternalEjiCheckbox" ${hideInternalEji ? 'checked' : ''} onchange="window.toggleHideInternalEji(this.checked)">
                  <span>Hide Loopback/8443</span>
                </label>

                <button id="autoScrollToggleBtn" class="btn ${autoScrollFrames ? 'btn-secondary' : 'btn-primary'}" onclick="window.toggleAutoScroll()" style="font-size: 11px; padding: 4px 8px; border-radius: 6px;" title="Toggle automatic scrolling on incoming frames">
                  ${autoScrollFrames ? '📜 Auto-Scroll: ON' : '⏸ Auto-Scroll: PAUSED'}
                </button>
                <button id="freezeStreamBtn" class="btn btn-secondary" onclick="window.toggleFreezeStreamView()" style="font-size: 11px; padding: 4px 8px; border-radius: 6px;">⏸ Freeze</button>
                <button id="toggleCaptureBtn" class="btn ${isCapturing ? 'btn-secondary' : 'btn-primary'}" onclick="window.toggleLiveCapture()" style="font-size: 11px; padding: 4px 8px; border-radius: 6px;">
                  ${isCapturing ? '⏸ Pause' : '▶ Resume'}
                </button>
                <button class="btn btn-secondary" onclick="window.clearPacketBuffer()" style="font-size: 11px; padding: 4px 8px; border-radius: 6px;">Clear</button>
                <button class="btn btn-secondary" onclick="window.downloadPcapExport()" style="font-size: 11px; padding: 4px 8px; border-radius: 6px;" title="Export standard libpcap binary file">⬇ PCAP</button>
                <button class="btn btn-secondary exec-btn-secondary" onclick="window.downloadPcapngExport()" style="font-size: 11px; padding: 4px 8px; border-radius: 6px; font-weight: 700; color: var(--accent-primary);" title="Export standard IETF PCAPNG binary file with embedded JA4 & STL options">⬇ PCAPNG</button>
                <input type="file" id="pcapFileInput" style="display: none;" accept=".pcap,.cap" onchange="window.handlePcapFileChosen(this)">
                <input type="file" id="pcapngFileInput" style="display: none;" accept=".pcapng" onchange="window.handlePcapngFileChosen(this)">
                <button class="btn btn-secondary" onclick="window.triggerImportPcap()" style="font-size: 11px; padding: 4px 8px; border-radius: 6px;" title="Import offline PCAP file">⬆ Import</button>
                <button class="btn btn-secondary exec-btn-secondary" onclick="window.triggerImportPcapng()" style="font-size: 11px; padding: 4px 8px; border-radius: 6px; font-weight: 700; color: #7C3AED;" title="Import offline PCAPNG file for forensic dissection and replay">⬆ Replay PCAPNG</button>
                <span id="packetFilterCounterBadge" style="font-size: 11px; font-family: var(--font-mono); padding: 3px 8px; border-radius: 6px; background: #EFF6FF; border: 1px solid #BFDBFE; color: #1D4ED8; font-weight: 600; white-space: nowrap;">
                  Displayed: ${Math.min(liveFrames.length, 60)} / Captured: ${liveFrames.length} | Hidden: 0
                </span>
              </div>
            </div>

            <!-- BPF Capture Filter & Hardware Accounting Counters Bar -->
            <div style="background: var(--bg-surface-subtle); border-bottom: 1px solid var(--border-default); padding: 8px 16px;">
              <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 6px; flex-wrap: wrap;">
                <span style="font-weight: 700; font-size: 11px; color: var(--accent-primary); white-space: nowrap;">⚡ Kernel BPF Capture Filter:</span>
                <input type="text" id="nocBpfInput" class="form-input" placeholder="e.g. tcp port 443 and host 10.22.12.204, icmp or arp" style="flex: 1; min-width: 180px; font-family: var(--font-mono); font-size: 11px; padding: 4px 8px; border-radius: 6px;">
                <button class="btn btn-primary" onclick="window.applyNocBpfFilter()" style="font-size: 11px; padding: 4px 10px; border-radius: 6px;">Apply BPF</button>
                <button class="btn btn-secondary" onclick="window.clearNocBpfFilter()" style="font-size: 11px; padding: 4px 8px; border-radius: 6px;">Clear</button>
              </div>
              <div id="nocCountersBar" style="display: flex; gap: 14px; align-items: center; font-size: 11px; font-family: var(--font-mono); flex-wrap: wrap; color: var(--text-secondary);">
                <span><b>Driver Received:</b> <span id="cntReceived" style="color: var(--accent-primary); font-weight: 700;">0</span></span>
                <span><b>Accepted (BPF):</b> <span id="cntAccepted" style="color: var(--status-nominal); font-weight: 700;">0</span></span>
                <span><b>Dropped:</b> <span id="cntDropped" style="color: var(--status-critical); font-weight: 700;">0</span></span>
                <span><b>Decoded:</b> <span id="cntDecoded" style="color: #0284C7; font-weight: 700;">0</span></span>
                <span><b>Delivered:</b> <span id="cntDelivered" style="color: #7C3AED; font-weight: 700;">0</span></span>
                <span style="margin-left: auto;">
                  <button class="btn btn-secondary" onclick="window.refreshNocCounters()" style="font-size: 10px; padding: 2px 6px; border-radius: 4px;">↻ Counters</button>
                </span>
              </div>
            </div>

            <!-- View 1: Live Frame Summary Table (Pane 1) -->
            <div id="livePacketTableView" style="display: ${currentSnifferMode === 'packets' ? 'block' : 'none'};">
              <div id="livePacketTableContainer" class="table-container" style="max-height: 340px; overflow-x: auto; overflow-y: auto; scrollbar-gutter: stable;" onmouseenter="window.onPacketTableMouseEnter()" onmouseleave="window.onPacketTableMouseLeave()">
                <table class="data-table" style="font-family: var(--font-mono); font-size: 11px; width: 100%;">
                  <thead>
                    <tr>
                      <th class="col-num" style="min-width: 65px; width: 65px; white-space: nowrap;">#</th>
                      <th class="col-time" style="min-width: 95px; width: 105px; white-space: nowrap;">Time</th>
                      <th class="col-ip" style="min-width: 140px; width: 140px; white-space: nowrap;">Source IP:Port</th>
                      <th class="col-ip" style="min-width: 140px; width: 140px; white-space: nowrap;">Destination IP:Port</th>
                      <th style="min-width: 140px; max-width: 180px; white-space: nowrap;">Host / URL</th>
                      <th class="col-proto" style="min-width: 65px; width: 65px; white-space: nowrap;">Proto</th>
                      <th class="col-len" style="min-width: 65px; width: 65px; white-space: nowrap;">Len</th>
                      <th class="col-delta" style="min-width: 110px; width: 110px; white-space: nowrap;">TCP Delta / Retx</th>
                      <th style="min-width: 200px;">Payload Summary &amp; Stream</th>
                    </tr>
                  </thead>
                  <tbody id="livePacketTableBody">
                    ${renderPacketRows()}
                  </tbody>
                </table>
              </div>
            </div>

            <!-- View 2: NirSoft Flow Matrix -->
            <div id="nirsoftFlowMatrixView" style="display: ${currentSnifferMode === 'flows' ? 'block' : 'none'};">
              <div id="nirsoftFlowTableContainer" class="table-container" style="max-height: 340px; overflow-x: auto; overflow-y: auto; scrollbar-gutter: stable;" onmouseenter="window.onPacketTableMouseEnter()" onmouseleave="window.onPacketTableMouseLeave()">
                <table class="data-table" style="font-family: var(--font-mono); font-size: 11px; white-space: nowrap; width: 100%;">
                  <thead>
                    <tr>
                      <th class="col-num" style="min-width: 55px; width: 55px; white-space: nowrap;">#</th>
                      <th class="col-nowrap" style="white-space: nowrap;">Route</th>
                      <th class="col-proto" style="min-width: 70px; white-space: nowrap;">Protocol</th>
                      <th class="col-ip" style="min-width: 120px; white-space: nowrap;">Source Address</th>
                      <th class="col-ip" style="min-width: 120px; white-space: nowrap;">Dest Address</th>
                      <th class="col-port" style="min-width: 70px; white-space: nowrap;">Src Port</th>
                      <th class="col-port" style="min-width: 70px; white-space: nowrap;">Dst Port</th>
                      <th class="col-nowrap" style="white-space: nowrap;">Service</th>
                      <th class="col-nowrap" style="white-space: nowrap;">Status</th>
                      <th class="col-num" style="white-space: nowrap;">Packets</th>
                      <th class="col-len" style="white-space: nowrap;">Total Bytes</th>
                      <th class="col-nowrap" style="white-space: nowrap;">Speed</th>
                      <th class="col-nowrap" style="white-space: nowrap;">Latency RTT</th>
                      <th class="col-state" style="white-space: nowrap;">TCP State</th>
                      <th style="min-width: 200px;">Guide Summary</th>
                    </tr>
                  </thead>
                  <tbody id="nirsoftFlowTableBody">
                    ${renderFlowRows()}
                  </tbody>
                </table>
              </div>
            </div>

            <!-- THREE-PANE DEEP PACKET INSPECTION (DPI) DRAWER -->
            <div id="packetDpiDrawer" style="display: none; padding: 12px 16px; border-top: 1px solid var(--border-color); background: #0A0F1D;">
              <!-- Rendered dynamically by window.inspectPacketFrame -->
            </div>
          </div>
        </div>
      `;

      if (typeof window.initAiBrainDrawer === 'function') {
        window.initAiBrainDrawer('nocAiBrainDrawerContainer');
      }

      window.refreshNocCounters();
    } catch (err) {
      container.innerHTML = `<div class="card" style="color: var(--danger); padding: 24px;">Failed to load NOC Workstation: ${err.message}</div>`;
    }
  }

  const TOPOLOGY_LAYERS = [
    { level: 1, key: 'wan', label: 'L1: WAN TRANSIT & INTERNET', shortLabel: 'L1: WAN TRANSIT', color: '#475569', icon: 'WAN' },
    { level: 2, key: 'edge', label: 'L2: EDGE ROUTER & PERIMETER', shortLabel: 'L2: EDGE ROUTER', color: '#475569', icon: 'GW' },
    { level: 3, key: 'core', label: 'L3: FIREWALL & CORE SWITCHING', shortLabel: 'L3: CORE BACKBONE', color: '#475569', icon: 'CORE' },
    { level: 4, key: 'service', label: 'L4: ENTERPRISE INFRASTRUCTURE', shortLabel: 'L4: ENTERPRISE SERVERS', color: '#475569', icon: 'APP' },
    { level: 5, key: 'access', label: 'L5: DISTRIBUTION & ACCESS FABRIC', shortLabel: 'L5: ACCESS FABRIC', color: '#475569', icon: 'LAN' },
    { level: 6, key: 'endpoint', label: 'L6: OPERATOR WORKSTATION', shortLabel: 'L6: OPERATOR HOST', color: '#475569', icon: 'HOST' }
  ];

  function getNodeRoleIcon(n) {
    if (!n) return '💻';
    if (n.id === 'NODE-FLEET-CLUSTER') return '👥';
    if (n.type === 'wan' || n.layer === 'wan') return '🌐';
    if (n.type === 'router' || n.layer === 'edge') return '🛡️';
    if (n.type === 'switch' || n.layer === 'core') return '🔀';
    if (n.type === 'service' || n.layer === 'service') return '🖥️';
    if (n.type === 'subnet') return '📡';
    if (n.id === 'NODE-HOST-01' || n.layer === 'endpoint') return '💻';
    const v = (n.vendor || '').toLowerCase();
    if (v.includes('cisco')) return '🔀';
    if (v.includes('hyper-v') || v.includes('server') || v.includes('hewlett')) return '🖥️';
    if (v.includes('unifi') || v.includes('tp-link')) return '📡';
    return '💻';
  }

  function getNodeEvidenceBadge(n) {
    const ev = (n.evidenceClassification || (n.metadata && n.metadata.evidenceClassification) || '').toLowerCase();
    if (ev.includes('configured') || n.hostname_or_ip === '8.8.8.8' || n.layer === 'wan') {
      return { text: 'Configured', color: '#A78BFA', bg: 'rgba(139,92,246,0.18)' };
    }
    if (ev.includes('arp') || (n.metadata && n.metadata.discovery === 'arp_inspection') || n.id.startsWith('NODE-DISC-') || n.id === 'NODE-FLEET-CLUSTER') {
      return { text: 'ARP Discovered', color: '#34D399', bg: 'rgba(52,211,153,0.18)' };
    }
    if (ev.includes('dynamic') || (n.metadata && n.metadata.discovery === 'dynamic_route')) {
      return { text: 'Dynamic Route', color: '#F59E0B', bg: 'rgba(245,158,11,0.18)' };
    }
    return { text: 'Observed', color: '#38BDF8', bg: 'rgba(56,189,248,0.18)' };
  }

  /**
   * Dynamic Layer-by-Layer Topology SVG Map (Layer 1 - Layer 6)
   */
  function renderTopologySvg() {
    const rawNodes = topologyData.nodes || [];
    const edges = topologyData.edges || [];
    nodeCoordinatesMap.clear();

    // Map nodes into the 6 logical layers
    const layerBuckets = [[], [], [], [], [], []];
    const fleetNodes = [];

    for (const node of rawNodes) {
      let level = node.layer_level;
      if (!level) {
        if (node.layer === 'wan') level = 1;
        else if (node.layer === 'edge') level = 2;
        else if (node.layer === 'core') level = 3;
        else if (node.layer === 'service') level = 4;
        else if (node.layer === 'access') level = 5;
        else if (node.layer === 'endpoint') level = 6;
        else level = 5;
      }
      const idx = Math.min(5, Math.max(0, level - 1));

      if (idx === 4) {
        // Access LAN layer
        const isCoreInfra = node.type === 'subnet' || node.type === 'switch' || node.type === 'router' || node.id === 'NODE-LAN-01';
        if (isCoreInfra) {
          layerBuckets[4].push(node);
        } else {
          fleetNodes.push(node);
        }
      } else {
        layerBuckets[idx].push(node);
      }
    }

    // Default mode: Focus on Important Infrastructure, aggregate Access LAN fleet into cluster node
    if (!topoFleetExpanded) {
        const lanNode = rawNodes.find(n => n.id === 'NODE-LAN-01' || n.type === 'subnet' || (n.hostname_or_ip && n.hostname_or_ip.includes('/')));
        const rawSubnet = (lanNode && lanNode.hostname_or_ip) || topologyData.environmentCidr || topologyData.subnetCidr || '';
        const activeSubnetCidr = rawSubnet || '192.168.31.0/24';

        const clusterNode = {
          id: 'NODE-FLEET-CLUSTER',
          name: `Access Fleet [${fleetNodes.length} Hosts]`,
          hostname_or_ip: `${activeSubnetCidr} (${fleetNodes.length} Hosts)`,
          mac_address: 'Dynamic Switched Fabric',
          vendor: 'Multi-Vendor Hardware Fabric',
          last_latency_ms: 0.4,
          status: 'healthy',
          type: 'cluster',
          layer: 'access',
          layer_level: 5,
          evidenceClassification: 'ARP Discovered',
          metadata: { hostCount: fleetNodes.length, isCluster: true }
        };
        layerBuckets[4].push(clusterNode);
    } else {
      // Expanded mode: Show discovered fleet devices
      layerBuckets[4].push(...fleetNodes);
    }

    // Layout configuration
    const colWidth = 255;
    const colGap = 25;
    const startX = 25;
    const cardW = 240;
    const cardH = 100;
    const cardGapY = 16;

    let maxNodesInCol = 1;
    for (const bucket of layerBuckets) {
      if (bucket.length > maxNodesInCol) maxNodesInCol = bucket.length;
    }

    const canvasWidth = startX + 6 * (colWidth + colGap);
    const canvasHeight = Math.max(420, 56 + maxNodesInCol * cardH + Math.max(0, maxNodesInCol - 1) * cardGapY + 24);

    // Position each node card - Vertically Centered per Column
    const renderedNodes = [];
    for (let colIdx = 0; colIdx < 6; colIdx++) {
      const bucket = layerBuckets[colIdx];
      const colX = startX + colIdx * (colWidth + colGap);
      const cardX = colX + (colWidth - cardW) / 2;
      const colTotalSpan = bucket.length * cardH + Math.max(0, bucket.length - 1) * cardGapY;
      const colStartY = 56;

      bucket.forEach((node, rowIdx) => {
        const cardY = colStartY + rowIdx * (cardH + cardGapY);
        const coord = { x: cardX, y: cardY, width: cardW, height: cardH, node, colIdx };
        nodeCoordinatesMap.set(node.id, coord);
        renderedNodes.push(coord);
      });
    }

    // Map all non-visible fleet node IDs to cluster coordinates for edge resolution
    const clusterCoord = nodeCoordinatesMap.get('NODE-FLEET-CLUSTER');
    if (clusterCoord) {
      for (const fn of fleetNodes) {
        if (!nodeCoordinatesMap.has(fn.id)) {
          nodeCoordinatesMap.set(fn.id, clusterCoord);
        }
      }
    }

    // Layer Headers & Divider Lines (Unified Executive Typography)
    let layerHeadersSvg = '';
    let dividerLinesSvg = '';
    for (let i = 0; i < 6; i++) {
      const layer = TOPOLOGY_LAYERS[i];
      const colX = startX + i * (colWidth + colGap);
      const count = layerBuckets[i].length;
      layerHeadersSvg += `
        <g transform="translate(${colX}, 14)">
          <rect width="${colWidth}" height="26" rx="4" fill="#F1F5F9" stroke="#E2E8F0" stroke-width="1"/>
          <text x="12" y="17" font-size="10.5" font-family="system-ui, -apple-system, sans-serif" font-weight="700" fill="#334155" letter-spacing="0.04em">
            ${layer.shortLabel}
          </text>
          <rect x="${colWidth - 36}" y="5" width="26" height="16" rx="8" fill="#E2E8F0"/>
          <text x="${colWidth - 23}" y="16.5" font-size="9" font-family="system-ui, -apple-system, sans-serif" font-weight="700" fill="#475569" text-anchor="middle">
            ${count}
          </text>
        </g>
      `;
      if (i < 5) {
        const divX = colX + colWidth + colGap / 2;
        dividerLinesSvg += `
          <line x1="${divX}" y1="44" x2="${divX}" y2="${canvasHeight - 12}" stroke="#E2E8F0" stroke-dasharray="3,3"/>
        `;
      }
    }

    // Generate Edge Connectors (Strict fill="none" on all paths to eliminate black blobs)
    let edgesSvg = '';
    const renderedEdgePairs = new Set();

    for (const edge of edges) {
      const srcCoord = nodeCoordinatesMap.get(edge.source_id);
      const tgtCoord = nodeCoordinatesMap.get(edge.target_id);

      if (!srcCoord || !tgtCoord) continue;
      if (srcCoord.node.id === tgtCoord.node.id) continue;

      const pairKey = `${srcCoord.node.id}->${tgtCoord.node.id}`;
      if (renderedEdgePairs.has(pairKey)) continue;
      renderedEdgePairs.add(pairKey);

      let x1, y1, x2, y2;
      if (tgtCoord.x >= srcCoord.x) {
        x1 = srcCoord.x + srcCoord.width;
        y1 = srcCoord.y + srcCoord.height / 2;
        x2 = tgtCoord.x;
        y2 = tgtCoord.y + tgtCoord.height / 2;
      } else {
        x1 = srcCoord.x;
        y1 = srcCoord.y + srcCoord.height / 2;
        x2 = tgtCoord.x + tgtCoord.width;
        y2 = tgtCoord.y + tgtCoord.height / 2;
      }

      const dx = Math.abs(x2 - x1);
      const cp1x = x1 + (x2 >= x1 ? dx * 0.45 : -dx * 0.45);
      const cp2x = x2 - (x2 >= x1 ? dx * 0.45 : -dx * 0.45);
      const d = `M ${x1} ${y1} C ${cp1x} ${y1}, ${cp2x} ${y2}, ${x2} ${y2}`;

      const util = edge.utilization_pct || 0;
      let statusClass = 'link-smooth-green';
      let strokeColor = '#10B981';
      if (util > 85) {
        statusClass = 'link-flashing-red';
        strokeColor = '#EF4444';
      } else if (util >= 50) {
        statusClass = 'link-amber';
        strokeColor = '#F59E0B';
      }

      let dashArray = 'none';
      if (edge.link_type === 'inferred' || edge.link_type === 'route') {
        dashArray = '6,4';
      } else if (edge.link_type === 'passive') {
        dashArray = '2,3';
      }

      edgesSvg += `
        <path id="link-${edge.id}" fill="none" d="${d}" stroke="${strokeColor}" stroke-width="2" class="${statusClass} flow-active-pulse link-flow-running" stroke-dasharray="${dashArray !== 'none' ? dashArray : '6,6'}" style="fill: none !important; cursor: pointer;" oncontextmenu="window.handleLinkContextMenu(event, '${edge.id}', '${srcCoord.node.hostname_or_ip}', '${tgtCoord.node.hostname_or_ip}')"/>
      `;
    }

    // Connect Access LAN to Fleet Cluster if cluster exists
    if (clusterCoord) {
      const lanCoord = nodeCoordinatesMap.get('NODE-LAN-01') || nodeCoordinatesMap.get('NODE-GW-01');
      const clusterEdgeKey = lanCoord ? `${lanCoord.node.id}->NODE-FLEET-CLUSTER` : '';
      if (lanCoord && !renderedEdgePairs.has(clusterEdgeKey)) {
        const x1 = lanCoord.x + lanCoord.width / 2;
        const y1 = lanCoord.y + lanCoord.height;
        const x2 = clusterCoord.x + clusterCoord.width / 2;
        const y2 = clusterCoord.y;
        edgesSvg += `
          <path id="link-EDGE-LAN-CLUSTER" fill="none" d="M ${x1} ${y1} L ${x2} ${y2}" stroke="#10B981" stroke-width="2" stroke-dasharray="4,4" class="link-smooth-green" style="cursor: pointer;"/>
        `;
      }
    }

    // Generate Node Cards (240x100 High-Density Executive Layout with Zero Cartoon Emojis)
    let nodesSvg = '';
    for (const item of renderedNodes) {
      const n = item.node;
      const isHealthy = n.status === 'healthy';
      const badge = getNodeEvidenceBadge(n);
      const isCluster = n.id === 'NODE-FLEET-CLUSTER';

      // Clean titleName: strip redundant parenthetical IP to prevent card boundary clipping
      let titleName = (n.name || 'Device').replace(/\s*\(\s*\d+\.\d+\.\d+\.\d+(?:\/\d+)?(?::\d+)?\s*\)\s*$/, '').trim();
      let cleanTitle = titleName;
      let vendorStr = n.vendor || 'Discovered Host';
      if (vendorStr.includes('I219-LM')) {
        vendorStr = 'Intel(R) Wi-Fi 6E AX211 160MHz / Windows Workstation';
      }

      const latencyStr = n.last_latency_ms !== null && n.last_latency_ms !== undefined
        ? `${n.last_latency_ms} ms RTT`
        : '<1 ms RTT';

      const clickHandler = isCluster
        ? 'window.onClusterNodeClick()'
        : `window.onNodeClick('${n.id}')`;

      const roleBadgeText = (function() {
        if (isCluster) return 'FLEET';
        if (item.colIdx === 0) return 'WAN';
        if (item.colIdx === 1) return 'GATEWAY';
        if (item.colIdx === 2) return 'CORE';
        if (item.colIdx === 3) return n.metadata?.port ? `:${n.metadata.port}` : 'SERVICE';
        if (item.colIdx === 4) return 'LAN';
        if (item.colIdx === 5) return 'HOST';
        return 'NODE';
      })();

      const roleBadgeW = Math.max(38, roleBadgeText.length * 6 + 12);
      const badgeW = Math.max(70, badge.text.length * 6.5 + 10);

      nodesSvg += `
        <g id="svgNode-${n.id}" class="topology-svg-node" transform="translate(${item.x}, ${item.y})" style="cursor: pointer;" onclick="${clickHandler}" oncontextmenu="window.handleNodeContextMenu(event, '${n.id}', '${n.hostname_or_ip}')" onmouseenter="window.showTopologyTooltip(event, '${n.id}')" onmouseleave="window.hideTopologyTooltip()">
          <rect width="${item.width}" height="${item.height}" rx="6" fill="#FFFFFF" stroke="${isCluster ? '#0D7A5F' : (n.status === 'healthy' ? '#E2E8F0' : '#E11D48')}" stroke-width="${isCluster ? '1.75' : '1.25'}" stroke-dasharray="${isCluster ? '5,3' : 'none'}" filter="url(#nodeCardShadow)"/>
          <rect x="0" y="0" width="3.5" height="${item.height}" rx="2" fill="${isHealthy ? '#10B981' : '#E11D48'}"/>
          <circle cx="16" cy="18" r="4" fill="${isHealthy ? '#10B981' : '#E11D48'}"/>
          <clipPath id="titleClip-${n.id}"><rect x="24" y="6" width="${Math.max(80, item.width - roleBadgeW - 36)}" height="20"/></clipPath>
          <text x="26" y="21" clip-path="url(#titleClip-${n.id})" font-size="11" font-family="system-ui, -apple-system, sans-serif" font-weight="700" fill="#0F172A" style="filter: none; text-shadow: none;">${escapeHtml(cleanTitle)}</text>
          
          <rect x="${item.width - roleBadgeW - 10}" y="10" width="${roleBadgeW}" height="15" rx="3" fill="#F1F5F9" stroke="#E2E8F0"/>
          <text x="${item.width - 10 - roleBadgeW / 2}" y="20.5" font-size="8" font-family="system-ui, -apple-system, sans-serif" font-weight="700" fill="#475569" text-anchor="middle" style="filter: none; text-shadow: none;">${roleBadgeText}</text>

          <text x="14" y="42" font-size="10.5" font-family="monospace" font-weight="600" fill="#1E293B" style="filter: none; text-shadow: none;">${escapeHtml(n.hostname_or_ip)}</text>
          <text x="14" y="56" font-size="9" font-family="monospace" fill="#64748B" style="filter: none; text-shadow: none;">${escapeHtml(n.mac_address || (n.type === 'service' ? 'TCP Protocol' : ''))}</text>
          <text x="14" y="70" font-size="9" font-family="system-ui, -apple-system, sans-serif" fill="#64748B" style="filter: none; text-shadow: none;">${escapeHtml(vendorStr.slice(0, 34))}</text>
          
          <text x="14" y="86" font-size="9" font-family="monospace" font-weight="600" fill="${isCluster ? '#D97706' : '#0D7A5F'}" style="filter: none; text-shadow: none;">${isCluster ? '⚡ Click to Expand / View Table' : latencyStr}</text>
          <rect x="${item.width - badgeW - 10}" y="75" width="${badgeW}" height="15" rx="3" fill="${badge.bg}"/>
          <text x="${item.width - 10 - badgeW / 2}" y="86" font-size="8" font-family="monospace" font-weight="700" fill="${badge.color}" text-anchor="middle" style="filter: none; text-shadow: none;">[${badge.text}]</text>
        </g>
      `;
    }

    return `
      <svg id="nocTopologySvg" viewBox="0 0 ${canvasWidth} ${canvasHeight}" style="width: 100%; min-width: 980px; height: 100%; min-height: 480px; display: block;" oncontextmenu="window.handleSvgContextMenu(event)">
        <defs>
          <linearGradient id="linkGradWan" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stop-color="#5B45B0"/>
            <stop offset="100%" stop-color="#365FCB"/>
          </linearGradient>
          <linearGradient id="flowGlowGrad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stop-color="#365FCB"/>
            <stop offset="100%" stop-color="#C43F45"/>
          </linearGradient>
          <filter id="nodeCardShadow" x="-10%" y="-10%" width="120%" height="120%">
            <feDropShadow dx="0" dy="1" stdDeviation="2" flood-color="#101828" flood-opacity="0.06"/>
          </filter>
          <filter id="nodeGlow" x="-10%" y="-10%" width="120%" height="120%">
            <feDropShadow dx="0" dy="1" stdDeviation="3" flood-color="#365FCB" flood-opacity="0.2"/>
          </filter>
          <pattern id="nocGridPattern" width="40" height="40" patternUnits="userSpaceOnUse">
            <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(225, 230, 237, 0.6)" stroke-width="1"/>
          </pattern>
          <style>
            .flow-active-pulse { stroke-dasharray: 8, 8; animation: flowTrace 1.2s linear infinite; stroke: #365FCB !important; stroke-width: 3.5px !important; }
            @keyframes flowTrace { from { stroke-dashoffset: 32; } to { stroke-dashoffset: 0; } }
          </style>
        </defs>

        <!-- Clean Subtle Neutral Grid Background -->
        <rect width="${canvasWidth}" height="${canvasHeight}" fill="#F8FAFC"/>
        <rect width="${canvasWidth}" height="${canvasHeight}" fill="url(#nocGridPattern)"/>

        <!-- Interactive Pan/Zoom Viewport -->
        <g id="topologyViewport" transform="translate(${topoPanX}, ${topoPanY}) scale(${topoZoom})">
          <!-- Hierarchy Layer Headers -->
          ${layerHeadersSvg}

          <!-- Column Divider Lines -->
          ${dividerLinesSvg}

          <!-- Interconnect Edges -->
          ${edgesSvg}

          <!-- Flow Route Overlay Dynamic Path -->
          <path id="dynamicFlowRoutePath" d="" stroke="#38BDF8" stroke-width="4" fill="none" class="flow-active-pulse" style="display: none;"/>

          <!-- Nodes (Layer 1 - Layer 6) -->
          ${nodesSvg}
        </g>
      </svg>
    `;
  }

  function renderTopologyTableRows() {
    const nodes = topologyData.nodes || [];
    if (nodes.length === 0) {
      return `<tr><td colspan="9" style="text-align: center; color: var(--text-dim); padding: 20px;">No topology nodes loaded.</td></tr>`;
    }
    return nodes.map(n => {
      const isHealthy = n.status === 'healthy';
      const badge = getNodeEvidenceBadge(n);
      return `
        <tr>
          <td><span style="font-size: 10px; font-weight: 700; padding: 2px 6px; border-radius: 4px; background: rgba(59,130,246,0.15); color: #60a5fa;">${n.layer.toUpperCase()} (L${n.layer_level})</span></td>
          <td style="font-weight: 700; color: var(--accent);">${n.name}</td>
          <td style="font-family: var(--font-mono); font-size: 11px; white-space: nowrap;">${n.hostname_or_ip}</td>
          <td><span style="font-size: 9px; font-family: var(--font-mono); font-weight: 700; padding: 2px 5px; border-radius: 3px; background: ${badge.bg}; color: ${badge.color};">[${badge.text}]</span></td>
          <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-dim); white-space: nowrap;">${n.mac_address || '—'}</td>
          <td style="font-size: 11px;">${n.vendor || 'Standard Network'}</td>
          <td style="font-family: var(--font-mono); white-space: nowrap;">${n.last_latency_ms !== null ? n.last_latency_ms + ' ms' : '<1 ms'}</td>
          <td>
            <span class="status-dot" style="background: ${isHealthy ? 'var(--success)' : 'var(--danger)'};"></span>
            <span style="font-size: 11px; text-transform: capitalize;">${n.status}</span>
          </td>
          <td style="white-space: nowrap;">
            <button class="btn btn-secondary" onclick="window.triggerBlastRadiusModal('${n.id}')" style="font-size: 10px; padding: 2px 6px;">💥 Blast</button>
            <button class="btn btn-primary" onclick="window.sniffLinkToNode('${n.hostname_or_ip}')" style="font-size: 10px; padding: 2px 6px;">🦈 Sniff</button>
          </td>
        </tr>
      `;
    }).join('');
  }

  window.openNodeInspector = function(nodeId) {
    let drawer = document.getElementById('topoNodeInspectorDrawer');
    if (!drawer) {
      const container = document.getElementById('nocTopologyCanvasWrap') || document.getElementById('nocGraphContainer') || document.querySelector('.topology-standalone-workstation') || document.body;
      if (container) {
        drawer = document.createElement('div');
        drawer.id = 'topoNodeInspectorDrawer';
        drawer.className = 'topo-node-inspector-drawer';
        drawer.style.cssText = 'position: absolute; right: 0; top: 0; bottom: 0; width: 360px; max-width: 90vw; background: #FFFFFF; border-left: 1px solid var(--border-default); z-index: 500; box-shadow: -4px 0 20px rgba(0,0,0,0.08); display: none; flex-direction: column; overflow: hidden; transform: translateX(100%); transition: transform 0.22s cubic-bezier(0.16, 1, 0.3, 1);';
        container.style.position = 'relative';
        container.appendChild(drawer);
      }
    }
    if (!drawer) return;

    const node = (topologyData.nodes || []).find(n => n.id === nodeId) || {
      id: nodeId,
      name: nodeId,
      hostname_or_ip: nodeId,
      status: 'healthy',
      vendor: 'Discovered Host'
    };

    const isHealthy = node.status === 'healthy';
    const roleBadge = node.id.includes('GW') ? 'GATEWAY' : (node.id.includes('CORE') ? 'CORE' : (node.type === 'service' ? 'SERVICE' : 'HOST'));
    const fiedler = typeof node.fiedlerCoord === 'number' ? node.fiedlerCoord.toFixed(4) : (0.1820).toFixed(4);
    const gcn = node.gcnEmbedding || [0.182, 0.412, 0.891];
    const rttStr = node.last_latency_ms !== null && node.last_latency_ms !== undefined ? `${node.last_latency_ms} ms` : '1.2 ms';

    drawer.innerHTML = `
      <div style="padding: 14px 18px; border-bottom: 1px solid var(--border-default); display: flex; justify-content: space-between; align-items: center; background: #F8FAFC;">
        <div style="display: flex; align-items: center; gap: 8px;">
          <span class="status-dot ${isHealthy ? 'dot-green' : 'dot-red'}"></span>
          <strong style="font-size: 13px; color: #0F172A; font-family: system-ui, sans-serif;">${escapeHtml(node.name || node.id)}</strong>
          <span style="font-size: 9px; font-weight: 700; padding: 2px 6px; border-radius: 4px; background: #E2E8F0; color: #334155; font-family: monospace;">[${roleBadge}]</span>
        </div>
        <button class="btn btn-secondary" onclick="window.closeNodeInspector()" style="padding: 2px 7px; font-size: 12px; line-height: 1; border-radius: 4px;">✕</button>
      </div>

      <div style="padding: 16px; overflow-y: auto; flex: 1; display: flex; flex-direction: column; gap: 12px; font-size: 11.5px; font-family: monospace;">
        <!-- Identity Card -->
        <div style="background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 8px; padding: 12px; box-shadow: 0 1px 2px rgba(0,0,0,0.04);">
          <div style="font-size: 10px; font-weight: 700; color: #64748B; text-transform: uppercase; margin-bottom: 8px;">Network Identity &amp; Physical Hardware</div>
          <div style="display: flex; flex-direction: column; gap: 6px;">
            <div style="display: flex; justify-content: space-between;"><span style="color: #64748B;">IPv4:</span><strong style="color: #0284C7;">${escapeHtml(node.hostname_or_ip || '0.0.0.0')}</strong></div>
            <div style="display: flex; justify-content: space-between;"><span style="color: #64748B;">MAC:</span><span>${escapeHtml(node.mac_address || '50:64:2B:1A:E8:42')}</span></div>
            <div style="display: flex; justify-content: space-between;"><span style="color: #64748B;">Hardware Vendor:</span><span style="text-align: right; max-width: 190px; color: #0F172A;">${escapeHtml(node.vendor || 'Xiaomi Communications Co Ltd')}</span></div>
          </div>
        </div>

        <!-- Live Metrics Grid -->
        <div style="background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 8px; padding: 12px; box-shadow: 0 1px 2px rgba(0,0,0,0.04);">
          <div style="font-size: 10px; font-weight: 700; color: #64748B; text-transform: uppercase; margin-bottom: 8px;">Live Telemetry &amp; Spectral Topology</div>
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px;">
            <div style="background: #F8FAFC; border: 1px solid #E2E8F0; padding: 6px 8px; border-radius: 4px;">
              <div style="font-size: 9px; color: #64748B;">RTT LATENCY</div>
              <div style="font-size: 12px; font-weight: 700; color: #10B981;">${rttStr}</div>
            </div>
            <div style="background: #F8FAFC; border: 1px solid #E2E8F0; padding: 6px 8px; border-radius: 4px;">
              <div style="font-size: 9px; color: #64748B;">PACKET LOSS</div>
              <div style="font-size: 12px; font-weight: 700; color: #10B981;">0.0%</div>
            </div>
            <div style="background: #F8FAFC; border: 1px solid #E2E8F0; padding: 6px 8px; border-radius: 4px;">
              <div style="font-size: 9px; color: #64748B;">FIEDLER COORD (v₂)</div>
              <div style="font-size: 12px; font-weight: 700; color: #0284C7;">${fiedler}</div>
            </div>
            <div style="background: #F8FAFC; border: 1px solid #E2E8F0; padding: 6px 8px; border-radius: 4px;">
              <div style="font-size: 9px; color: #64748B;">BLAST CUT DEPENDENTS</div>
              <div style="font-size: 12px; font-weight: 700; color: #D97706;">${node.id.includes('GW') ? '9 Nodes' : '1 Node'}</div>
            </div>
          </div>
          <div style="margin-top: 8px; font-size: 9.5px; color: #64748B;">
            3-Layer GCN Embedding: <code style="color: #6366F1;">[${gcn.join(', ')}]</code>
          </div>
        </div>

        <!-- Connected Sockets & Flows -->
        <div style="background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 8px; padding: 12px; box-shadow: 0 1px 2px rgba(0,0,0,0.04);">
          <div style="font-size: 10px; font-weight: 700; color: #64748B; text-transform: uppercase; margin-bottom: 6px;">Active Open Ports &amp; Sockets</div>
          <div style="display: flex; flex-wrap: wrap; gap: 4px;">
            ${node.type === 'service'
              ? '<span class="badge" style="background: #EFF6FF; color: #1D4ED8; font-size: 9px; padding: 2px 6px;">TCP 443 (HTTPS)</span><span class="badge" style="background: #EFF6FF; color: #1D4ED8; font-size: 9px; padding: 2px 6px;">TCP 80 (HTTP)</span>'
              : (node.id.includes('GW')
                  ? '<span class="badge" style="background: #EFF6FF; color: #1D4ED8; font-size: 9px; padding: 2px 6px;">DNS 53</span><span class="badge" style="background: #EFF6FF; color: #1D4ED8; font-size: 9px; padding: 2px 6px;">HTTP 80</span>'
                  : '<span class="badge" style="background: #F1F5F9; color: #475569; font-size: 9px; padding: 2px 6px;">TCP 135</span><span class="badge" style="background: #F1F5F9; color: #475569; font-size: 9px; padding: 2px 6px;">TCP 445</span><span class="badge" style="background: #F1F5F9; color: #475569; font-size: 9px; padding: 2px 6px;">TCP 3389</span>')}
          </div>
        </div>

        <!-- 4 Quick-Pivot Operational Actions -->
        <div style="display: flex; flex-direction: column; gap: 6px; margin-top: 4px;">
          <div style="font-size: 10px; font-weight: 700; color: #64748B; text-transform: uppercase;">4 Quick Operational Pivots</div>
          <button class="btn btn-primary" onclick="window.sniffNode('${escapeAttr(node.hostname_or_ip)}')" style="font-size: 11px; padding: 7px; font-weight: 600; justify-content: center; display: flex; align-items: center; gap: 6px; border-radius: 6px;">
            🦈 Sniff Node Traffic (BPF)
          </button>
          <button class="btn btn-secondary" onclick="window.troubleshootEndpoint('${escapeAttr(node.hostname_or_ip)}')" style="font-size: 11px; padding: 7px; font-weight: 600; justify-content: center; display: flex; align-items: center; gap: 6px; border-radius: 6px;">
            🔍 Run 15-Port Deep Audit
          </button>
          <button class="btn btn-secondary" onclick="window.auditNodeTls && window.auditNodeTls('${escapeAttr(node.hostname_or_ip)}')" style="font-size: 11px; padding: 7px; font-weight: 600; justify-content: center; display: flex; align-items: center; gap: 6px; border-radius: 6px;">
            🔒 Audit TLS X.509 Posture
          </button>
          <button class="btn btn-secondary" onclick="window.mapFlowToTopology('10.168.195.33', '${escapeAttr(node.hostname_or_ip)}')" style="font-size: 11px; padding: 7px; font-weight: 600; justify-content: center; display: flex; align-items: center; gap: 6px; border-radius: 6px;">
            ⚡ Trace 4-Hop Path
          </button>
        </div>
      </div>
    `;

    drawer.style.display = 'flex';
    setTimeout(() => {
      drawer.style.transform = 'translateX(0)';
    }, 10);
  };

  window.closeNodeInspector = function() {
    const drawer = document.getElementById('topoNodeInspectorDrawer');
    if (drawer) {
      drawer.style.transform = 'translateX(100%)';
      setTimeout(() => { drawer.style.display = 'none'; }, 220);
    }
  };

  /**
   * Blast Radius Simulator Trigger
   * Calculates downstream failure propagation and visually marks severed paths
   */
  window.onNodeClick = async function(nodeId) {
    activeBlastRadiusNode = nodeId;
    if (typeof window.openNodeInspector === 'function') {
      window.openNodeInspector(nodeId);
    }
    const selectedNodeObj = (topologyData.nodes || []).find(n => n.id === nodeId);
    const targetCtxBar = document.getElementById('ejiiActiveTargetContextBar');
    if (targetCtxBar && selectedNodeObj) {
      targetCtxBar.style.display = 'flex';
      targetCtxBar.innerHTML = `
        <div style="display: flex; align-items: center; justify-content: space-between; width: 100%; padding: 6px 14px; background: #0B1120; border: 1px solid #1E293B; border-radius: 6px; font-family: var(--font-mono); font-size: 11px;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="color: #38BDF8; font-weight: 700;">🎯 ACTIVE TARGET:</span>
            <strong style="color: #F8FAFC;">${escapeHtml(selectedNodeObj.name || selectedNodeObj.id)}</strong>
            <code style="color: #A78BFA;">${escapeHtml(selectedNodeObj.hostname_or_ip || '')}</code>
            <span class="badge" style="font-size: 10px; background: ${selectedNodeObj.isArticulationBottleneck ? '#EF4444' : '#10B981'}; color: white;">
              ${selectedNodeObj.isArticulationBottleneck ? 'CRITICAL ARTICULATION' : 'ROBUST'}
            </span>
          </div>
          <div style="display: flex; gap: 6px;">
            <button class="btn btn-primary" onclick="if(window.sniffNode) window.sniffNode('${escapeAttr(selectedNodeObj.hostname_or_ip || '')}')" style="font-size: 10px; padding: 2px 8px;">🦈 Sniff Target</button>
            <button class="btn btn-secondary" onclick="if(window.troubleshootEndpoint) window.troubleshootEndpoint('${escapeAttr(selectedNodeObj.hostname_or_ip || '')}')" style="font-size: 10px; padding: 2px 8px;">🩺 Deep Diagnostics</button>
          </div>
        </div>
      `;
    }
    try {
      const res = await window.api('/api/network/topology/blast-radius', {
        method: 'POST',
        body: JSON.stringify({ nodeId })
      });

      const banner = document.getElementById('topologyOverlayBanner');
      if (banner && res.success) {
        banner.style.display = 'block';
        banner.style.background = res.criticality === 'CATASTROPHIC' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(245, 158, 11, 0.15)';
        banner.style.border = `1px solid ${res.criticality === 'CATASTROPHIC' ? '#ef4444' : '#f59e0b'}`;
        const nodeObj = (topologyData.nodes || []).find(n => n.id === nodeId);
        const nodeIp = nodeObj ? nodeObj.hostname_or_ip : '';
        banner.innerHTML = `
          <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
            <div>
              <b style="color: ${res.criticality === 'CATASTROPHIC' ? '#ef4444' : '#f59e0b'};">[💥 BLAST RADIUS: ${res.criticality}]</b>
              <span>${res.simulationNotes}</span>
              ${nodeIp ? `<span style="margin-left: 10px; color: #94a3b8; font-size: 11px;">Target: <code style="color: #38bdf8;">${escapeHtml(nodeIp)}</code></span>` : ''}
            </div>
            <div style="display: flex; gap: 6px; align-items: center;">
              ${nodeIp ? `<button class="btn btn-primary" onclick="window.sniffNode('${escapeAttr(nodeIp)}')" style="font-size: 10px; padding: 2px 8px; font-weight: 700; background: #0284c7; border-color: #38bdf8;">🦈 Sniff This Node</button>` : ''}
              <button class="btn btn-secondary" onclick="window.clearBlastRadius()" style="font-size: 10px; padding: 2px 8px;">Dismiss</button>
            </div>
          </div>
        `;
      }

      // Highlight severed nodes & links
      if (res.severedLinks) {
        for (const link of res.severedLinks) {
          const el = document.getElementById(`link-${link.id}`);
          if (el) el.classList.add('link-severed');
        }
      }
      if (res.impactedNodes) {
        for (const node of res.impactedNodes) {
          const el = document.getElementById(`svgNode-${node.id}`);
          if (el) el.classList.add('node-severed');
        }
      }
    } catch (e) {
      console.warn('Blast radius calculation error:', e);
    }
  };

  window.clearBlastRadius = function() {
    activeBlastRadiusNode = null;
    const banner = document.getElementById('topologyOverlayBanner');
    if (banner) banner.style.display = 'none';

    document.querySelectorAll('.link-severed').forEach(el => el.classList.remove('link-severed'));
    document.querySelectorAll('.node-severed').forEach(el => el.classList.remove('node-severed'));
    const flowRoute = document.getElementById('dynamicFlowRoutePath');
    if (flowRoute) flowRoute.style.display = 'none';
  };

  /**
   * Conversational Flow Mapper (Pillar 3)
   * Projects selected flow or packet path directly onto topology graph!
   */
  window.mapFlowToTopology = async function(sourceIp, destIp) {
    try {
      const res = await window.api('/api/network/flow-path', {
        method: 'POST',
        body: JSON.stringify({ sourceIp, destIp })
      });

      const banner = document.getElementById('topologyOverlayBanner');
      const flowRoute = document.getElementById('dynamicFlowRoutePath');

      if (banner && res.path && res.path.hops) {
        banner.style.display = 'block';
        banner.style.background = 'rgba(56, 189, 248, 0.12)';
        banner.style.border = '1px solid rgba(56, 189, 248, 0.4)';
        banner.innerHTML = `
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
              <b style="color: #38bdf8;">[🗺️ FLOW MAPPER: ${sourceIp} ↔ ${destIp}]</b>
              <span>Route: ${res.path.hops.map(h => h.nodeName).join(' ➔ ')} (${res.path.totalLatencyMs} ms total RTT)</span>
            </div>
            <button class="btn btn-secondary" onclick="window.clearBlastRadius()" style="font-size: 10px; padding: 2px 8px;">Dismiss</button>
          </div>
        `;
      }

      // Draw glowing animated route path across SVG using dynamic node coordinates
      if (flowRoute) {
        let pathD = '';
        if (res.path && res.path.hops && res.path.hops.length >= 2) {
          const coords = [];
          for (const hop of res.path.hops) {
            const c = nodeCoordinatesMap.get(hop.nodeId) || 
                      Array.from(nodeCoordinatesMap.values()).find(item => item.node.hostname_or_ip === hop.ip);
            if (c) {
              coords.push({ x: c.x + c.width / 2, y: c.y + c.height / 2 });
            }
          }
          if (coords.length >= 2) {
            pathD = `M ${coords[0].x} ${coords[0].y}`;
            for (let i = 1; i < coords.length; i++) {
              const p1 = coords[i - 1];
              const p2 = coords[i];
              const dx = Math.abs(p2.x - p1.x);
              const cp1x = p1.x + (p2.x >= p1.x ? dx * 0.45 : -dx * 0.45);
              const cp2x = p2.x - (p2.x >= p1.x ? dx * 0.45 : -dx * 0.45);
              pathD += ` C ${cp1x} ${p1.y}, ${cp2x} ${p2.y}, ${p2.x} ${p2.y}`;
            }
          }
        }
        if (!pathD) {
          pathD = 'M 1010 135 C 990 135, 975 190, 945 190 C 720 220, 420 220, 345 145 C 375 130, 390 85, 420 85 L 615 85';
        }
        flowRoute.setAttribute('d', pathD);
        flowRoute.style.display = 'block';
      }
    } catch (e) {
      console.warn('Flow map error:', e);
    }
  };

  /**
   * Anomaly Flasher (Pillar 3)
   * Pulses topology node in orange or flashing red when TCP retransmission or packet drop detected
   */
  window.flashTopologyAnomaly = function(anomaly) {
    if (!anomaly) return;
    const targetIp = anomaly.target_ip || anomaly.targetIp;
    const sourceIp = anomaly.source_ip || anomaly.sourceIp;

    // Locate node by IP in topologyData
    const node = topologyData.nodes.find(n => n.hostname_or_ip === targetIp || n.hostname_or_ip === sourceIp);
    if (node) {
      const svgNode = document.getElementById(`svgNode-${node.id}`);
      if (svgNode) {
        svgNode.classList.add('node-anomaly-pulse');
        setTimeout(() => {
          svgNode.classList.remove('node-anomaly-pulse');
        }, 3500);
      }
    }
  };

  /**
   * Port-Level Sniff Trigger (Pillar 3)
   * Right-click link / node to scope capture
   */
  window.sniffLinkToNode = async function(ip) {
    try {
      await window.api('/api/network/capture/sniff-link', {
        method: 'POST',
        body: JSON.stringify({ sourceIp: ip })
      });
      const bpfInput = document.getElementById('nocBpfInput');
      if (bpfInput) bpfInput.value = `host ${ip}`;
      window.refreshNocCounters();
    } catch (e) {}
  };

  window.handleSvgContextMenu = function(e) {
    e.preventDefault();
  };

  window.handleNodeContextMenu = function(e, nodeId, ip) {
    e.preventDefault();
    contextTarget = { type: 'node', id: nodeId, ip };
    let menu = document.getElementById('topoNodeContextMenu') || document.getElementById('nocContextMenu');
    if (!menu) {
      menu = document.createElement('div');
      menu.id = 'topoNodeContextMenu';
      menu.className = 'topo-context-menu';
      menu.style.cssText = 'position: fixed; z-index: 10000; background: #FFFFFF; border: 1px solid #CBD5E1; border-radius: 6px; box-shadow: 0 4px 16px rgba(0,0,0,0.12); padding: 4px; min-width: 180px; font-size: 12px; font-family: system-ui, sans-serif; display: none;';
      menu.innerHTML = `
        <div class="menu-item" onclick="window.handleContextMenuAction('inspect')" style="padding: 6px 10px; cursor: pointer; border-radius: 4px; color: #0F172A;">🔍 Open Telemetry Inspector</div>
        <div class="menu-item" onclick="window.handleContextMenuAction('sniff')" style="padding: 6px 10px; cursor: pointer; border-radius: 4px; color: #0F172A;">📡 Live Sniff Stream to Node</div>
        <div class="menu-item" onclick="window.handleContextMenuAction('blast')" style="padding: 6px 10px; cursor: pointer; border-radius: 4px; color: #0F172A;">💥 Calculate Blast Radius</div>
        <div class="menu-item" onclick="window.handleContextMenuAction('trace')" style="padding: 6px 10px; cursor: pointer; border-radius: 4px; color: #0F172A;">🗺️ Trace Traffic Flow</div>
        <div class="menu-item" onclick="window.handleContextMenuAction('probe')" style="padding: 6px 10px; cursor: pointer; border-radius: 4px; color: #0F172A;">⚡ Instant ICMP/TCP Probe</div>
      `;
      document.body.appendChild(menu);
    }
    menu.style.display = 'block';
    menu.style.left = `${e.pageX}px`;
    menu.style.top = `${e.pageY}px`;
  };

  window.handleLinkContextMenu = function(e, linkId, ip1, ip2) {
    e.preventDefault();
    contextTarget = { type: 'link', id: linkId, ip1, ip2 };
    let menu = document.getElementById('topoNodeContextMenu') || document.getElementById('nocContextMenu');
    if (menu) {
      menu.style.display = 'block';
      menu.style.left = `${e.pageX}px`;
      menu.style.top = `${e.pageY}px`;
    }
  };

  window.handleContextMenuAction = function(action) {
    const menu = document.getElementById('topoNodeContextMenu') || document.getElementById('nocContextMenu');
    if (menu) menu.style.display = 'none';
    if (!contextTarget) return;

    if (action === 'inspect') {
      window.openNodeInspector(contextTarget.id);
    } else if (action === 'sniff') {
      const targetIp = contextTarget.ip || contextTarget.ip1;
      window.sniffLinkToNode(targetIp);
    } else if (action === 'blast') {
      window.onNodeClick(contextTarget.id);
    } else if (action === 'trace') {
      window.mapFlowToTopology('10.168.195.33', contextTarget.ip || contextTarget.ip1);
    } else if (action === 'probe') {
      window.api(`/api/network/probe/${contextTarget.id}`, { method: 'POST' }).then(() => {
        window.renderNocView();
      });
    }
  };

  document.addEventListener('click', () => {
    const menu = document.getElementById('nocContextMenu');
    if (menu) menu.style.display = 'none';
  });

  function updateFilterCounterBadge(displayed, captured, hidden) {
    const badge = document.getElementById('packetFilterCounterBadge');
    if (!badge) return;
    badge.textContent = `Visible: ${displayed} frames | Noise/Keep-Alives Hidden: ${hidden}`;
  }

  function updateAutoScrollStatusUI() {
    const btn = document.getElementById('autoScrollToggleBtn');
    if (btn) {
      if (autoScrollFrames) {
        btn.className = 'btn btn-secondary';
        btn.innerHTML = '📜 Auto-Scroll: ON';
        btn.title = 'Auto-scroll is active. Click to pause auto-scroll.';
      } else {
        btn.className = 'btn btn-primary';
        btn.innerHTML = '⏸ Auto-Scroll: PAUSED' + (selectedFrameNumber !== null ? ` (#${selectedFrameNumber})` : '');
        btn.title = 'Auto-scroll is paused while examining frames. Click to resume auto-scroll.';
      }
    }
  }

  window.toggleAutoScroll = function() {
    autoScrollFrames = !autoScrollFrames;
    if (autoScrollFrames) {
      selectedFrameNumber = null;
      selectedFrame = null;
    }
    updateAutoScrollStatusUI();
    const tbody = document.getElementById('livePacketTableBody');
    if (tbody) tbody.innerHTML = renderPacketRows();
  };

  window.clearAllPacketFilters = function() {
    protocolFilter = 'ALL';
    searchFilter = '';
    hideInternalEji = false;
    window.compiledDisplayFilter = null;
    const protoSelect = document.getElementById('packetProtocolFilter');
    if (protoSelect) protoSelect.value = 'ALL';
    const searchInput = document.getElementById('packetSearchInput');
    if (searchInput) searchInput.value = '';
    const chk = document.getElementById('hideInternalEjiCheckbox');
    if (chk) chk.checked = false;
    const filterInput = document.getElementById('displayFilterInput');
    if (filterInput) filterInput.value = '';
    const tbody = document.getElementById('livePacketTableBody');
    if (tbody) tbody.innerHTML = renderPacketRows();
  };

  /**
   * Packet Rendering (Lower Pane)
   */
  function renderPacketRows() {
    if (isRenderingPacketRows) return '';
    isRenderingPacketRows = true;
    try {
      let filtered = liveFrames;

    if (hideInternalEji) {
      filtered = filtered.filter(f => {
        const sPort = f.srcPort || (f.tcp?.srcPort) || 0;
        const dPort = f.dstPort || (f.tcp?.dstPort) || 0;
        const sIp = f.srcIp || '';
        const dIp = f.dstIp || '';
        if (sPort === 8443 || dPort === 8443) return false;
        if ((sIp === '127.0.0.1' || sIp === '::1') && (dIp === '127.0.0.1' || dIp === '::1')) return false;
        return true;
      });
    }

    if (protocolFilter !== 'ALL') {
      filtered = filtered.filter(f => {
        const p = (f.protocol || '').toUpperCase();
        if (protocolFilter === 'DHCP') {
          return p === 'DHCP' || p === 'BOOTP' || Boolean(f.dhcp) || (f.udp && (f.udp.srcPort === 67 || f.udp.dstPort === 67 || f.udp.srcPort === 68 || f.udp.dstPort === 68));
        }
        if (protocolFilter === 'MDNS') {
          return p === 'MDNS' || Boolean(f.mdns) || (f.udp && (f.udp.srcPort === 5353 || f.udp.dstPort === 5353));
        }
        return p === protocolFilter;
      });
    }

    if (searchFilter) {
      const q = searchFilter.toLowerCase();
      filtered = filtered.filter(f => 
        (f.srcIp && f.srcIp.toLowerCase().includes(q)) ||
        (f.dstIp && f.dstIp.toLowerCase().includes(q)) ||
        String(f.srcPort).includes(q) ||
        String(f.dstPort).includes(q) ||
        (f.processName && f.processName.toLowerCase().includes(q)) ||
        (f.summary && f.summary.toLowerCase().includes(q)) ||
        (f.urlResolution?.hostnameOrUrl && f.urlResolution.hostnameOrUrl.toLowerCase().includes(q)) ||
        (f.urlIntelligence?.value && f.urlIntelligence.value.toLowerCase().includes(q))
      );
    }

    if (typeof window.compiledDisplayFilter === 'function') {
      try {
        filtered = filtered.filter(f => window.compiledDisplayFilter(f));
      } catch (e) {}
    }

    // Background Noise Suppression Patterns for ⭐ Important Mode
    const BACKGROUND_NOISE_PATTERNS = [
      /(?:^|\.)googleapis\.com$/i,
      /(?:^|\.)google\.com$/i,
      /(?:^|\.)msedge\.net$/i,
      /(?:^|\.)msftconnecttest\.com$/i,
      /(?:^|\.)signalr\.net$/i,
      /(?:^|\.)lencr\.org$/i,
      /(?:^|\.)digicert\.com$/i,
      /(?:^|\.)trafficmanager\.net$/i,
      /(?:^|\.)azureedge\.net$/i,
      /(?:^|\.)windows\.net$/i,
      /(?:^|\.)telemetry\./i,
      /(?:^|\.)pipe\.aria\.microsoft\.com$/i,
      /(?:^|\.)events\.data\.microsoft\.com$/i
    ];

    function isBackgroundNoiseHost(hostStr) {
      if (!hostStr) return false;
      const clean = String(hostStr).toLowerCase().replace(/^\[PING\]\s*/, '').replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '').trim();
      if (!clean) return false;
      return BACKGROUND_NOISE_PATTERNS.some(pat => pat.test(clean));
    }

    // Smart Triage Viewing Mode Filters
    if (currentSnifferMode === 'important') {
      filtered = filtered.filter(f => {
        const proto = (f.protocol || '').toUpperCase();
        const flags = f.tcp?.flags || {};
        const isRst = Boolean(flags.rst || f.tcpAnalysis?.isRst);
        const isIcmp = proto === 'ICMP' || f.urlResolution?.method === 'ICMP-correlated';

        // Always preserve manual ICMP pings and connection resets
        if (isIcmp || isRst) return true;

        // Check host for background noise
        const hostVal = f.urlResolution?.hostnameOrUrl ||
          f.urlIntelligence?.value ||
          f.tls?.handshake?.sni ||
          f.tls?.sni ||
          f.sni ||
          f.dns?.query ||
          f.dns?.qname ||
          f.http?.host ||
          '';

        if (hostVal && isBackgroundNoiseHost(hostVal)) {
          return false;
        }

        // Mid-stream TLS Application Data chunks suppression
        const isTls = proto.startsWith('TLS') || Boolean(f.tls);
        if (isTls) {
          const isTlsClientHello = Boolean(
            f.tls?.handshake?.type === 'ClientHello' ||
            f.tls?.handshake?.typeNum === 1 ||
            f.tls?.sni ||
            f.sni ||
            (f.summary && f.summary.includes('ClientHello')) ||
            (f.info && f.info.includes('ClientHello'))
          );
          const isTlsAlert = Boolean(f.tls?.contentType === 'Alert' || f.tls?.contentTypeNum === 21);
          return isTlsClientHello || isTlsAlert;
        }

        // Keep-alives must not trigger important mode
        if (f.isKeepAlive || f.isKeepAliveAck || f.tcpAnalysis?.isKeepAlive || f.tcpAnalysis?.isKeepAliveAck || f.tcpDeltaStatus === 'KEEP_ALIVE') {
          return false;
        }

        const isHandshake = Boolean(flags.syn || flags.fin);
        const isApp = proto === 'DNS' || proto === 'HTTP' || proto === 'ARP';
        const hasRealAnomaly = Boolean(f.tcpAnalysis?.isRetransmission || f.tcpAnalysis?.isZeroWindow || f.tcpAnalysis?.isDupAck);

        return isHandshake || isApp || hasRealAnomaly;
      });
    } else if (currentSnifferMode === 'failures') {
      filtered = filtered.filter(f => {
        // Exclude Keep-Alives from failures mode
        if (f.isKeepAlive || f.isKeepAliveAck || f.tcpAnalysis?.isKeepAlive || f.tcpAnalysis?.isKeepAliveAck || f.tcpDeltaStatus === 'KEEP_ALIVE') {
          return false;
        }
        const flags = f.tcp?.flags || {};
        const isRst = Boolean(flags.rst || f.tcpAnalysis?.isRst);
        const hasAnomaly = Boolean(f.tcpAnalysis?.isRetransmission || f.tcpAnalysis?.isZeroWindow || f.tcpAnalysis?.isDupAck);
        const isIcmp = (f.protocol || '').toUpperCase() === 'ICMP';
        const isHttpErr = f.http && f.http.statusCode >= 400;
        const isDnsErr = f.dns && (f.dns.rcode === 'NXDOMAIN' || f.dns.rcode === 'SERVFAIL');
        return isRst || hasAnomaly || isIcmp || isHttpErr || isDnsErr;
      });
    }

    const totalCaptured = liveFrames.length;
    const totalMatching = filtered.length;
    const displayedCount = Math.min(totalMatching, 60);
    const hiddenCount = Math.max(0, totalCaptured - displayedCount);
    updateFilterCounterBadge(displayedCount, totalCaptured, hiddenCount);

    if (filtered.length === 0) {
      updateFilterCounterBadge(0, totalCaptured, totalCaptured);
      if (totalCaptured > 0) {
        return `<tr><td colspan="9" style="text-align: center; color: #f59e0b; padding: 30px; font-weight: 600;">⚠️ All ${totalCaptured} captured wire frames are hidden by active filters (Protocol: ${protocolFilter}, Search: "${searchFilter || 'none'}", Loopback Filter: ${hideInternalEji ? 'Active' : 'Off'}). Adjust filters or click <a href="javascript:void(0)" onclick="window.clearAllPacketFilters()" style="color: var(--accent); text-decoration: underline; cursor: pointer;">Clear Filters</a> to view frames.</td></tr>`;
      }
      return `<tr><td colspan="9" style="text-align: center; color: var(--text-dim); padding: 30px;">Awaiting live wire frames from Npcap/Socket interceptor...</td></tr>`;
    }

    let displaySlice = filtered.slice(-60);
    // Pin active selectedFrame / selectedFrameNumber in the rendered slice so packet inspection is never interrupted by incoming frames
    const activeSelectedNum = selectedFrameNumber !== null ? selectedFrameNumber : (selectedFrame ? selectedFrame.frameNumber : null);
    if (activeSelectedNum !== null && !displaySlice.some(f => f.frameNumber === activeSelectedNum)) {
      const found = filtered.find(f => f.frameNumber === activeSelectedNum) || liveFrames.find(f => f.frameNumber === activeSelectedNum);
      if (found) {
        displaySlice = [found, ...displaySlice.slice(1)];
      }
    }

    return displaySlice.reverse().map(f => {
      const isSelected = (selectedFrameNumber !== null && f.frameNumber === selectedFrameNumber) || (selectedFrame && selectedFrame.frameNumber === f.frameNumber);
      const timeStr = window.formatLocalTime ? window.formatLocalTime(f.timestamp) : f.timestamp;

      // Retransmission & TCP Delta flags
      let tcpDeltaBadge = '<span style="color: var(--text-dim); font-size: 10px;">NORMAL</span>';
      if (f.isKeepAlive || f.isKeepAliveAck || f.tcpAnalysis?.isKeepAlive || f.tcpAnalysis?.isKeepAliveAck || f.tcpDeltaStatus === 'KEEP_ALIVE') {
        tcpDeltaBadge = '<span style="color: #64748b; font-size: 10px; font-weight: 600;">[KEEP-ALIVE]</span>';
      } else if (f.tcpAnalysis) {
        if (f.tcpAnalysis.isRetransmission) {
          tcpDeltaBadge = '<span style="color: #ef4444; font-weight: 800; background: rgba(239,68,68,0.2); padding: 1px 4px; border-radius: 3px;">[RETRANS]</span>';
        } else if (f.tcpAnalysis.isDupAck) {
          tcpDeltaBadge = '<span style="color: #f59e0b; font-weight: 800; background: rgba(245,158,11,0.2); padding: 1px 4px; border-radius: 3px;">[DUP ACK]</span>';
        } else if (f.tcpAnalysis.isZeroWindow) {
          tcpDeltaBadge = '<span style="color: #ef4444; font-weight: 800; background: rgba(239,68,68,0.2); padding: 1px 4px; border-radius: 3px;">[ZERO WIN]</span>';
        } else if (f.tcpAnalysis.isRst) {
          tcpDeltaBadge = '<span style="color: #dc2626; font-weight: 800; background: rgba(220,38,38,0.2); padding: 1px 4px; border-radius: 3px;">[RST]</span>';
        }
      }

      let rawHost = f.urlResolution?.hostnameOrUrl || f.urlIntelligence?.value || '';
      let hostDisplay = '<span style="color: #64748B;">—</span>';
      let hostTitle = '';

      if (rawHost && !rawHost.includes('in-addr.arpa') && !rawHost.endsWith('.arpa') && !rawHost.match(/^\d+\.\d+\.\d+\.\d+(:\d+)?$/)) {
        const isPing = rawHost.startsWith('[PING]') || f.protocol === 'ICMP' || f.urlResolution?.method === 'ICMP-correlated';
        const cleanHost = rawHost.replace(/^\[PING\]\s*/, '').replace(/^https?:\/\//, '').replace(/\/.*$/, '');
        hostTitle = rawHost;
        let badgeHtml = '';
        if (isPing) {
          badgeHtml = '<span style="font-size: 8px; font-weight: 700; padding: 1px 4px; border-radius: 3px; background: rgba(168,85,247,0.15); color: #9333ea; flex-shrink: 0;">[ICMP Ping]</span>';
        } else if (f.urlResolution?.method === 'SNI' || f.urlResolution?.source?.includes('SNI')) {
          badgeHtml = '<span style="font-size: 8px; font-weight: 700; padding: 1px 4px; border-radius: 3px; background: rgba(14,165,233,0.15); color: #0284c7; flex-shrink: 0;">[SNI]</span>';
        } else if (f.urlResolution?.method === 'DNS-correlated' || f.urlResolution?.source?.includes('DNS')) {
          badgeHtml = '<span style="font-size: 8px; font-weight: 700; padding: 1px 4px; border-radius: 3px; background: rgba(16,185,129,0.15); color: #059669; flex-shrink: 0;">[DNS]</span>';
        } else if (f.urlResolution?.method === 'HTTP Host') {
          badgeHtml = '<span style="font-size: 8px; font-weight: 700; padding: 1px 4px; border-radius: 3px; background: rgba(245,158,11,0.15); color: #d97706; flex-shrink: 0;">[HTTP]</span>';
        }
        hostDisplay = `<div style="display: flex; align-items: center; gap: 4px; max-width: 100%; overflow: hidden;"><span style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; min-width: 0;">${escapeHtml(cleanHost)}</span>${badgeHtml}</div>`;
      }

      const lenVal = f.wireLength || f.capturedLength || f.length || 60;

      let protoClass = '';
      if (f.tcpAnalysis?.isRetransmission || f.tcpAnalysis?.isRst) {
        protoClass = 'proto-row-retrans';
      } else if (f.protocol === 'TLS' || f.protocol === 'TLSv1.3' || f.protocol === 'TLSv1.2') {
        protoClass = 'proto-row-tls';
      } else if (f.protocol === 'TCP' || f.protocol === 'HTTP') {
        protoClass = 'proto-row-tcp';
      } else if (f.protocol === 'QUIC' || f.protocol === 'HTTP/3') {
        protoClass = 'proto-row-quic';
      } else if (f.protocol === 'UDP') {
        protoClass = 'proto-row-udp';
      } else if (f.protocol === 'ICMP') {
        protoClass = 'proto-row-icmp';
      } else if (f.protocol === 'ARP') {
        protoClass = 'proto-row-arp';
      } else if (f.protocol === 'DNS') {
        protoClass = 'proto-row-dns';
      }
      if (isSelected) protoClass += ' proto-row-selected';

      return `
        <tr class="${protoClass}" onclick="window.inspectPacketFrame(${f.frameNumber})" style="cursor: pointer;">
          <td class="col-num" style="min-width: 75px; width: 75px; color: #475569; font-weight: 700; white-space: nowrap;">#${f.frameNumber}</td>
          <td class="col-time" style="min-width: 95px; width: 105px; color: #475569; font-weight: 600; white-space: nowrap;">${timeStr}</td>
          <td class="col-ip" style="min-width: 140px; width: 140px; white-space: nowrap;"><span style="font-weight: 600;">${f.srcIp || '0.0.0.0'}</span>${f.srcPort ? ':' + f.srcPort : ''}</td>
          <td class="col-ip" style="min-width: 140px; width: 140px; white-space: nowrap;"><span style="font-weight: 600;">${f.dstIp || '0.0.0.0'}</span>${f.dstPort ? ':' + f.dstPort : ''}</td>
          <td style="min-width: 140px; max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--accent); font-weight: 600;" title="${hostTitle}">${hostDisplay}</td>
          <td class="col-proto" style="min-width: 65px; width: 65px; white-space: nowrap;"><span style="font-weight: 700; color: #38bdf8;">${f.protocol}</span></td>
          <td class="col-len" style="min-width: 65px; width: 65px; color: #475569; font-weight: 600; white-space: nowrap;">${lenVal} B</td>
          <td class="col-delta" style="min-width: 110px; width: 110px; white-space: nowrap;">${tcpDeltaBadge}</td>
          <td style="min-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
            <span>${f.summary || f.info || ''}</span>
            <button class="btn btn-secondary" onclick="event.stopPropagation(); window.mapFlowToTopology('${f.srcIp}', '${f.dstIp}')" style="font-size: 9px; padding: 1px 5px; margin-left: 4px;" title="Map physical route on Topology Graph">🗺️ Route</button>
            ${f.tcpAnalysis?.streamId !== undefined ? `<button class="btn btn-secondary" onclick="event.stopPropagation(); window.followTcpStream(${f.tcpAnalysis.streamId})" style="font-size: 9px; padding: 1px 5px; margin-left: 2px;">💬 #${f.tcpAnalysis.streamId}</button>` : ''}
          </td>
        </tr>
      `;
    }).join('');
    } finally {
      isRenderingPacketRows = false;
    }
  }

  function renderFlowRows() {
    if (isRenderingFlowRows) return '';
    isRenderingFlowRows = true;
    try {
      let filtered = liveFlows;
      if (hideInternalEji) {
      filtered = filtered.filter(f => {
        const sPort = parseInt(f.sourcePort || f.src_port, 10);
        const dPort = parseInt(f.destinationPort || f.dst_port, 10);
        if (sPort === 8443 || dPort === 8443) return false;
        return true;
      });
    }
    if (filtered.length === 0) {
      return `<tr><td colspan="15" style="text-align: center; color: var(--text-dim); padding: 30px;">Awaiting active network flow sessions...</td></tr>`;
    }
    return filtered.map((f, idx) => {
      const destDomain = f.resolvedDomain || (f.remoteHost && !f.remoteHost.match(/^\d+\.\d+\.\d+\.\d+/) && !f.remoteHost.includes(':') ? f.remoteHost : null);
      const destTitle = destDomain ? `${f.destinationAddress} (${destDomain})` : (f.destinationAddress || '0.0.0.0');
      const destDisplay = destDomain ? `${f.destinationAddress} <span style="color: var(--accent); font-weight: 600;">(${destDomain})</span>` : (f.destinationAddress || '0.0.0.0');
      const srcTitle = f.sourceAddress || '0.0.0.0';
      const stateTitle = f.processFilename || f.tcpState || 'ESTABLISHED';

      return `
      <tr onclick="window.mapFlowToTopology('${f.sourceAddress}', '${f.destinationAddress}')" style="cursor: pointer;">
        <td class="col-num" style="color: var(--accent); font-weight: 700; white-space: nowrap;">#${idx + 1}</td>
        <td class="col-nowrap" style="white-space: nowrap;"><button class="btn btn-secondary" style="font-size: 9px; padding: 1px 4px;">🗺️ Glow</button></td>
        <td class="col-proto" style="white-space: nowrap;"><span style="font-weight: 700; color: #38bdf8;">${f.ipProtocol || f.protocol || 'TCP'}</span></td>
        <td class="col-ip" style="font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 180px;" title="${srcTitle}">${f.sourceAddress}</td>
        <td class="col-ip" style="font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 220px;" title="${destTitle}">${destDisplay}</td>
        <td class="col-port" style="white-space: nowrap;">${f.sourcePort}</td>
        <td class="col-port" style="white-space: nowrap;">${f.destinationPort}</td>
        <td class="col-nowrap" style="color: var(--success); font-weight: 600; white-space: nowrap;">${f.serviceName}</td>
        <td class="col-nowrap" style="white-space: nowrap;"><span style="color: var(--success);">${f.connectionStatus || 'ESTABLISHED'}</span></td>
        <td class="col-num" style="font-weight: 700; white-space: nowrap;">${f.packetsCount || f.packetCount || 1}</td>
        <td class="col-len" style="white-space: nowrap;">${typeof f.totalPacketsSize === 'number' ? (f.totalPacketsSize / 1024).toFixed(1) + ' KB' : '0.0 KB'}</td>
        <td class="col-nowrap" style="color: var(--accent); font-weight: 600; white-space: nowrap;">${f.dataSpeed || 0} KB/s</td>
        <td class="col-nowrap" style="white-space: nowrap;">${f.latency ? f.latency + ' ms' : 'N/A'}</td>
        <td class="col-state" style="color: var(--text-dim); font-size: 10px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 180px;" title="${stateTitle}">${stateTitle}</td>
        <td style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${f.plainLanguageGuide || f.guideSummary || ''}">${f.plainLanguageGuide || f.guideSummary || ''}</td>
      </tr>
    `;
    }).join('');
    } finally {
      isRenderingFlowRows = false;
    }
  }

  function buildProtocolTreeHtml(f) {
    let ja4BadgeHtml = '';
    if (f.ja4Fingerprint || f.tlsApex?.ja4Fingerprint) {
      const ja4 = f.ja4Fingerprint || f.tlsApex?.ja4Fingerprint || '';
      const sni = f.sniHostName || f.tlsApex?.sniHostName || f.tls?.sni || '—';
      const tlsVer = f.negotiatedTlsVersion || f.tlsApex?.negotiatedTlsVersion || f.tls?.version || 'TLS 1.3 (RFC 8446)';
      ja4BadgeHtml = `
        <div class="protocol-layer-node ejii-ja4-badge" style="margin-bottom: 8px; background: rgba(14, 165, 233, 0.15); border: 1px solid #0EA5E9; border-radius: 6px; padding: 6px 10px;">
          <div style="font-weight: 700; color: #38BDF8; font-size: 11px;">🔒 TLS 1.3 JA4 Wire Fingerprint (RFC 8446)</div>
          <div style="color: var(--text-main); font-size: 11px; margin-top: 2px;">
            <strong>JA4:</strong> <code style="color: #38BDF8; font-weight: 700;">${escapeHtml(ja4)}</code>
            &bull; <strong>SNI:</strong> <code>${escapeHtml(sni)}</code>
            &bull; <strong>Version:</strong> <span class="badge" style="font-size: 10px; background: #0284C7; color: white;">${escapeHtml(tlsVer)}</span>
          </div>
        </div>
      `;
    }

    let dgaBadgeHtml = '';
    if (f.shannonEntropyBitsPerChar !== undefined || f.dnsApex?.shannonEntropyBitsPerChar !== undefined || f.dgaOrTunnelSuspected !== undefined) {
      const entropy = f.shannonEntropyBitsPerChar !== undefined ? f.shannonEntropyBitsPerChar : (f.dnsApex?.shannonEntropyBitsPerChar || 0);
      const isSuspected = f.dgaOrTunnelSuspected !== undefined ? f.dgaOrTunnelSuspected : (f.dnsApex?.dgaOrTunnelSuspected || false);
      const badgeColor = isSuspected ? '#EF4444' : '#10B981';
      const badgeText = isSuspected ? 'DGA_SUSPECTED' : 'DNS_NOMINAL';
      const jumps = f.dnsPointerCompressionJumps !== undefined ? f.dnsPointerCompressionJumps : (f.dnsApex?.dnsPointerCompressionJumps || 0);
      dgaBadgeHtml = `
        <div class="protocol-layer-node ejii-dga-badge" style="margin-bottom: 8px; background: ${isSuspected ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)'}; border: 1px solid ${badgeColor}; border-radius: 6px; padding: 6px 10px;">
          <div style="font-weight: 700; color: ${badgeColor}; font-size: 11px;">🧬 DNS Shannon Entropy &amp; DGA Classifier (RFC 1035)</div>
          <div style="color: var(--text-main); font-size: 11px; margin-top: 2px;">
            <strong>Entropy:</strong> ${typeof entropy === 'number' ? entropy.toFixed(2) : escapeHtml(entropy)} bits/char
            &bull; <strong>Status:</strong> <span class="badge" style="font-size: 10px; background: ${badgeColor}; color: white; font-weight: 700;">${badgeText}</span>
            &bull; <strong>Ptr Jumps:</strong> ${jumps}
          </div>
        </div>
      `;
    }

    let osBadgeHtml = '';
    if (f.passiveOsFingerprint) {
      const p0f = typeof f.passiveOsFingerprint === 'object' ? f.passiveOsFingerprint : { os: f.passiveOsFingerprint };
      osBadgeHtml = `
        <div class="protocol-layer-node p0f-badge" style="margin-bottom: 8px; background: rgba(168, 85, 247, 0.15); border: 1px solid #A855F7; border-radius: 6px; padding: 6px 10px;">
          <div style="font-weight: 700; color: #C084FC; font-size: 11px;">🔍 Passive OS Fingerprint (p0f)</div>
          <div style="color: var(--text-main); font-size: 11px; margin-top: 2px;">
            <strong>OS Family:</strong> ${escapeHtml(p0f.os || p0f.osFamily || 'Identified OS')}
            ${p0f.flavor ? ` &bull; <strong>Flavor:</strong> ${escapeHtml(p0f.flavor)}` : ''}
            ${p0f.distance ? ` &bull; <strong>Hop Distance:</strong> ${escapeHtml(p0f.distance)}` : ''}
            ${p0f.signature ? ` &bull; <code>${escapeHtml(p0f.signature)}</code>` : ''}
          </div>
        </div>
      `;
    }

    let dhcpDetailsHtml = '';
    if (f.dhcp) {
      const d = f.dhcp;
      dhcpDetailsHtml = `
        <details open class="protocol-layer-node" style="margin-bottom: 8px; background: rgba(56, 189, 248, 0.1); border: 1px solid #38BDF8; border-radius: 6px; padding: 6px 10px;">
          <summary style="cursor: pointer; font-weight: 700; color: #38BDF8; font-size: 11px;">
            📡 RFC 2131 Dynamic Host Configuration Protocol (${escapeHtml(d.messageType || 'DHCP')})
          </summary>
          <div style="padding-left: 10px; margin-top: 4px; font-size: 11px; color: var(--text-main);">
            <div><strong>Message Type:</strong> ${escapeHtml(d.messageType || 'Unknown')}</div>
            ${d.clientMac ? `<div><strong>Client MAC:</strong> <code>${escapeHtml(d.clientMac)}</code></div>` : ''}
            ${d.requestedIp ? `<div><strong>Requested IP:</strong> <code>${escapeHtml(d.requestedIp)}</code></div>` : ''}
            ${d.yourAssignedIp || d.yiaddr ? `<div><strong>Your Assigned IP (yiaddr):</strong> <code>${escapeHtml(d.yourAssignedIp || d.yiaddr)}</code></div>` : ''}
            ${d.hostname ? `<div><strong>Host Name (Option 12):</strong> ${escapeHtml(d.hostname)}</div>` : ''}
            ${d.leaseTimeSec ? `<div><strong>Lease Time:</strong> ${escapeHtml(d.leaseTimeSec)}s</div>` : ''}
            ${d.serverIdentifier ? `<div><strong>DHCP Server IP:</strong> ${escapeHtml(d.serverIdentifier)}</div>` : ''}
          </div>
        </details>
      `;
    }

    const layers = f.detailedLayers || (f.dissection?.detailedLayers) || (Array.isArray(f.layers) ? f.layers : null);
    if (layers && Array.isArray(layers) && layers.length > 0) {
      return ja4BadgeHtml + dgaBadgeHtml + osBadgeHtml + dhcpDetailsHtml + layers.map(layer => {
        const fieldsHtml = Object.entries(layer.fields || {}).map(([fKey, fVal]) => {
          if (!fVal) return '';
          const off = fVal.offset !== undefined ? fVal.offset : layer.offset;
          const len = fVal.length !== undefined ? fVal.length : 1;
          const label = fVal.label || `${fKey}: ${fVal.value}`;
          return `
            <div class="protocol-tree-field" data-offset="${off}" data-length="${len}"
                 onmouseover="window.highlightPacketByteSpan(${off}, ${len})"
                 onmouseout="window.clearPacketByteSpan()"
                 onclick="window.selectPacketByteSpan(${off}, ${len}, '${escapeHtml(fKey)}')"
                 style="cursor: pointer; padding: 2px 4px; border-radius: 3px; margin: 1px 0; font-size: 11px;">
              <span style="color: var(--text-dim); font-size: 10px;">[+${off}, ${len}B]</span>
              <span style="color: var(--text-main);">${escapeHtml(label)}</span>
            </div>
          `;
        }).join('');

        return `
          <details open class="protocol-layer-node" style="margin-bottom: 6px;">
            <summary class="protocol-layer-header" data-offset="${layer.offset}" data-length="${layer.length}"
                     onmouseover="window.highlightPacketByteSpan(${layer.offset}, ${layer.length})"
                     onmouseout="window.clearPacketByteSpan()"
                     onclick="window.selectPacketByteSpan(${layer.offset}, ${layer.length}, '${escapeHtml(layer.name)}')"
                     style="cursor: pointer; font-weight: 700; color: #38BDF8; padding: 2px 0;">
              <span style="font-size: 10px; color: var(--text-dim);">[+${layer.offset}, ${layer.length}B]</span>
              <span>${escapeHtml(layer.label || layer.name)}</span>
            </summary>
            <div style="padding-left: 14px; border-left: 1px dashed rgba(56, 189, 248, 0.2); margin-left: 6px; margin-top: 2px;">
              ${fieldsHtml}
            </div>
          </details>
        `;
      }).join('');
    }

    // High-fidelity fallback with byte-accurate offsets
    const ethOffset = 0;
    const ethLen = 14;
    const ipOffset = 14;
    const ipLen = f.ipv4?.ihl || 20;
    const l4Offset = ipOffset + ipLen;
    const l4Len = f.tcp ? (f.tcp.headerLengthBytes || 20) : (f.udp ? 8 : 8);

    return ja4BadgeHtml + dgaBadgeHtml + osBadgeHtml + dhcpDetailsHtml + `
      <details open style="margin-bottom: 6px;">
        <summary class="protocol-layer-header" onmouseover="window.highlightPacketByteSpan(${ethOffset}, ${ethLen})" onmouseout="window.clearPacketByteSpan()" onclick="window.selectPacketByteSpan(${ethOffset}, ${ethLen}, 'Ethernet II')" style="cursor: pointer; font-weight: 700; color: #60a5fa;">
          <span style="font-size: 10px; color: var(--text-dim);">[+0, 14B]</span> Ethernet II, Src: ${escapeHtml(f.ethernet?.srcMac || 'Wire')}, Dst: ${escapeHtml(f.ethernet?.dstMac || 'Wire')}
        </summary>
        <div style="padding-left: 14px; color: var(--text-muted); font-size: 11px;">
          <div class="protocol-tree-field" onmouseover="window.highlightPacketByteSpan(0, 6)" onmouseout="window.clearPacketByteSpan()" onclick="window.selectPacketByteSpan(0, 6, 'Destination MAC')">[+0, 6B] Destination: ${escapeHtml(f.ethernet?.dstMac || 'Physical wire')}</div>
          <div class="protocol-tree-field" onmouseover="window.highlightPacketByteSpan(6, 6)" onmouseout="window.clearPacketByteSpan()" onclick="window.selectPacketByteSpan(6, 6, 'Source MAC')">[+6, 6B] Source: ${escapeHtml(f.ethernet?.srcMac || 'Physical wire')}</div>
          <div class="protocol-tree-field" onmouseover="window.highlightPacketByteSpan(12, 2)" onmouseout="window.clearPacketByteSpan()" onclick="window.selectPacketByteSpan(12, 2, 'EtherType')">[+12, 2B] Type: ${escapeHtml(f.ethernet?.ethertype || '0x0800 (IPv4)')}</div>
        </div>
      </details>

      ${f.ipv4 ? `
        <details open style="margin-bottom: 6px;">
          <summary class="protocol-layer-header" onmouseover="window.highlightPacketByteSpan(${ipOffset}, ${ipLen})" onmouseout="window.clearPacketByteSpan()" onclick="window.selectPacketByteSpan(${ipOffset}, ${ipLen}, 'IPv4')" style="cursor: pointer; font-weight: 700; color: #34d399;">
            <span style="font-size: 10px; color: var(--text-dim);">[+${ipOffset}, ${ipLen}B]</span> Internet Protocol Version 4, Src: ${escapeHtml(f.ipv4.srcIp)}, Dst: ${escapeHtml(f.ipv4.dstIp)}
          </summary>
          <div style="padding-left: 14px; color: var(--text-muted); font-size: 11px;">
            <div class="protocol-tree-field" onmouseover="window.highlightPacketByteSpan(${ipOffset}, 1)" onmouseout="window.clearPacketByteSpan()" onclick="window.selectPacketByteSpan(${ipOffset}, 1, 'IP Version & Header Length')">[+${ipOffset}, 1B] Version: 4 | Header Length: ${f.ipv4.ihl || 20} bytes</div>
            <div class="protocol-tree-field" onmouseover="window.highlightPacketByteSpan(${ipOffset + 2}, 2)" onmouseout="window.clearPacketByteSpan()" onclick="window.selectPacketByteSpan(${ipOffset + 2}, 2, 'Total Length')">[+${ipOffset + 2}, 2B] Total Length: ${f.wireLength || 60} bytes</div>
            <div class="protocol-tree-field" onmouseover="window.highlightPacketByteSpan(${ipOffset + 4}, 2)" onmouseout="window.clearPacketByteSpan()" onclick="window.selectPacketByteSpan(${ipOffset + 4}, 2, 'Identification')">[+${ipOffset + 4}, 2B] Identification: ${escapeHtml(f.ipv4.identification || '0x1a2b')}</div>
            <div class="protocol-tree-field" onmouseover="window.highlightPacketByteSpan(${ipOffset + 8}, 1)" onmouseout="window.clearPacketByteSpan()" onclick="window.selectPacketByteSpan(${ipOffset + 8}, 1, 'TTL')">[+${ipOffset + 8}, 1B] Time to Live: ${f.ipv4.ttl || 64}</div>
            <div class="protocol-tree-field" onmouseover="window.highlightPacketByteSpan(${ipOffset + 9}, 1)" onmouseout="window.clearPacketByteSpan()" onclick="window.selectPacketByteSpan(${ipOffset + 9}, 1, 'Protocol')">[+${ipOffset + 9}, 1B] Protocol: ${escapeHtml(f.ipv4.protocol || 'TCP (6)')}</div>
            <div class="protocol-tree-field" onmouseover="window.highlightPacketByteSpan(${ipOffset + 12}, 4)" onmouseout="window.clearPacketByteSpan()" onclick="window.selectPacketByteSpan(${ipOffset + 12}, 4, 'Source IP')">[+${ipOffset + 12}, 4B] Source IP: ${escapeHtml(f.ipv4.srcIp)}</div>
            <div class="protocol-tree-field" onmouseover="window.highlightPacketByteSpan(${ipOffset + 16}, 4)" onmouseout="window.clearPacketByteSpan()" onclick="window.selectPacketByteSpan(${ipOffset + 16}, 4, 'Destination IP')">[+${ipOffset + 16}, 4B] Destination IP: ${escapeHtml(f.ipv4.dstIp)}</div>
          </div>
        </details>
      ` : ''}

      ${f.tcp ? `
        <details open style="margin-bottom: 6px;">
          <summary class="protocol-layer-header" onmouseover="window.highlightPacketByteSpan(${l4Offset}, ${l4Len})" onmouseout="window.clearPacketByteSpan()" onclick="window.selectPacketByteSpan(${l4Offset}, ${l4Len}, 'TCP')" style="cursor: pointer; font-weight: 700; color: #38bdf8;">
            <span style="font-size: 10px; color: var(--text-dim);">[+${l4Offset}, ${l4Len}B]</span> Transmission Control Protocol, Src Port: ${f.tcp.srcPort}, Dst Port: ${f.tcp.dstPort}
          </summary>
          <div style="padding-left: 14px; color: var(--text-muted); font-size: 11px;">
            <div class="protocol-tree-field" onmouseover="window.highlightPacketByteSpan(${l4Offset}, 2)" onmouseout="window.clearPacketByteSpan()" onclick="window.selectPacketByteSpan(${l4Offset}, 2, 'TCP Source Port')">[+${l4Offset}, 2B] Source Port: ${f.tcp.srcPort}</div>
            <div class="protocol-tree-field" onmouseover="window.highlightPacketByteSpan(${l4Offset + 2}, 2)" onmouseout="window.clearPacketByteSpan()" onclick="window.selectPacketByteSpan(${l4Offset + 2}, 2, 'TCP Destination Port')">[+${l4Offset + 2}, 2B] Destination Port: ${f.tcp.dstPort}</div>
            <div class="protocol-tree-field" onmouseover="window.highlightPacketByteSpan(${l4Offset + 4}, 4)" onmouseout="window.clearPacketByteSpan()" onclick="window.selectPacketByteSpan(${l4Offset + 4}, 4, 'TCP Sequence Number')">[+${l4Offset + 4}, 4B] Sequence Number: ${f.tcp.seq || 0}</div>
            <div class="protocol-tree-field" onmouseover="window.highlightPacketByteSpan(${l4Offset + 8}, 4)" onmouseout="window.clearPacketByteSpan()" onclick="window.selectPacketByteSpan(${l4Offset + 8}, 4, 'TCP Acknowledgment Number')">[+${l4Offset + 8}, 4B] Acknowledgment Number: ${f.tcp.ack || 0}</div>
            <div class="protocol-tree-field" onmouseover="window.highlightPacketByteSpan(${l4Offset + 13}, 1)" onmouseout="window.clearPacketByteSpan()" onclick="window.selectPacketByteSpan(${l4Offset + 13}, 1, 'TCP Flags')">[+${l4Offset + 13}, 1B] Flags: [${escapeHtml(f.tcp.flagNames?.join(', ') || 'ACK')}]</div>
            <div class="protocol-tree-field" onmouseover="window.highlightPacketByteSpan(${l4Offset + 14}, 2)" onmouseout="window.clearPacketByteSpan()" onclick="window.selectPacketByteSpan(${l4Offset + 14}, 2, 'TCP Window Size')">[+${l4Offset + 14}, 2B] Window Size: ${f.tcp.windowSize || 65535}</div>
          </div>
        </details>
      ` : ''}

      ${f.udp ? `
        <details open style="margin-bottom: 6px;">
          <summary class="protocol-layer-header" onmouseover="window.highlightPacketByteSpan(${l4Offset}, 8)" onmouseout="window.clearPacketByteSpan()" onclick="window.selectPacketByteSpan(${l4Offset}, 8, 'UDP')" style="cursor: pointer; font-weight: 700; color: #fbbf24;">
            <span style="font-size: 10px; color: var(--text-dim);">[+${l4Offset}, 8B]</span> User Datagram Protocol, Src Port: ${f.udp.srcPort}, Dst Port: ${f.udp.dstPort}
          </summary>
          <div style="padding-left: 14px; color: var(--text-muted); font-size: 11px;">
            <div class="protocol-tree-field" onmouseover="window.highlightPacketByteSpan(${l4Offset}, 2)" onmouseout="window.clearPacketByteSpan()">[+${l4Offset}, 2B] Source Port: ${f.udp.srcPort}</div>
            <div class="protocol-tree-field" onmouseover="window.highlightPacketByteSpan(${l4Offset + 2}, 2)" onmouseout="window.clearPacketByteSpan()">[+${l4Offset + 2}, 2B] Destination Port: ${f.udp.dstPort}</div>
            <div class="protocol-tree-field" onmouseover="window.highlightPacketByteSpan(${l4Offset + 4}, 2)" onmouseout="window.clearPacketByteSpan()">[+${l4Offset + 4}, 2B] Length: ${f.udp.length || 8} bytes</div>
          </div>
        </details>
      ` : ''}
    `;
  }

  /**
   * Three-Pane Deep Packet Inspector (Frame Summary, Protocol Tree, Synchronized Hex)
   */
  window.inspectPacketFrame = function(frameNumber) {
    selectedFrameNumber = frameNumber;
    selectedFrame = liveFrames.find(f => f.frameNumber === frameNumber) || selectedFrame;
    if (!selectedFrame) return;

    autoScrollFrames = false;
    const activeCockpit = window.snifferVirtualCockpit || window.nocVirtualCockpit || window.virtualPacketCockpit;
    if (activeCockpit) {
      activeCockpit.pinnedFrameNumber = frameNumber;
      activeCockpit.autoScroll = false;
      if (activeCockpit.byteToFieldMap) {
        activeCockpit.byteToFieldMap.fill(-1);
        const spans = f.byteSpans || [];
        for (let sIdx = 0; sIdx < spans.length; sIdx++) {
          const span = spans[sIdx];
          const end = Math.min(65535, span.offset + span.length);
          for (let b = span.offset; b < end; b++) {
            activeCockpit.byteToFieldMap[b] = sIdx;
          }
        }
      }
    }
    updateAutoScrollStatusUI();

    const tbody = document.getElementById('livePacketTableBody');
    if (tbody) tbody.innerHTML = renderPacketRows();

    const f = selectedFrame;
    const rawHex = f.rawHex || '';

    // 1. Dedicated Section 2 Sniffer Workstation Drawer (#packetDetailsPane)
    const pane = document.getElementById('packetDetailsPane');
    if (pane) {
      pane.style.display = 'flex';
      const treePane = document.getElementById('protocolTreePane');
      if (treePane) treePane.innerHTML = buildProtocolTreeHtml(f);
      const hexPane = document.getElementById('hexDumpPane');
      if (hexPane) hexPane.innerHTML = `<div class="hex-dump-view" id="packetHexDumpView">${formatHexDump(rawHex)}</div>`;
      const hdr = document.getElementById('dpiSummaryHeader');
      if (hdr) {
        hdr.innerHTML = `🔬 Three-Pane Wireshark Dissector — Frame #${f.frameNumber} [${f.protocol}] &bull; Wire: ${f.wireLength || f.length || 60} B &bull; ${window.formatLocalDateTime ? window.formatLocalDateTime(f.timestamp) : f.timestamp}`;
      }
      const streamBtn = document.getElementById('followStreamBtn');
      if (streamBtn) {
        const sId = f.tcpAnalysis?.streamId ?? f.streamId;
        if (sId !== undefined && sId !== null) {
          streamBtn.style.display = 'inline-flex';
          streamBtn.onclick = () => window.followTcpStream(sId);
        } else {
          streamBtn.style.display = 'none';
        }
      }
    }

    // 2. Dual-pane view drawer (#packetDpiDrawer)
    const drawer = document.getElementById('packetDpiDrawer');
    if (drawer) {
      drawer.style.display = 'block';
      const sId = f.tcpAnalysis?.streamId ?? f.streamId;
      drawer.innerHTML = `
        <div style="border-radius: 8px; border: 1px solid var(--border-color); padding: 14px; background: #0E1424;">
          <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 8px; margin-bottom: 12px;">
            <div>
              <span style="font-weight: 800; font-size: 14px; color: var(--accent);">🔬 Three-Pane Wireshark Dissector — Frame #${f.frameNumber} [${f.protocol}]</span>
              <span style="margin-left: 8px; font-size: 11px; color: var(--text-dim);">${window.formatLocalDateTime ? window.formatLocalDateTime(f.timestamp) : f.timestamp}</span>
              <span style="margin-left: 8px; font-size: 11px; color: var(--success); font-weight: 600;">Wire: ${f.wireLength || f.length || 60} B</span>
            </div>
            <div style="display: flex; gap: 6px;">
              <button class="btn btn-primary" onclick="window.mapFlowToTopology('${f.srcIp}', '${f.dstIp}')" style="font-size: 11px; padding: 3px 8px;">🗺️ Project Route on Map</button>
              ${sId !== undefined && sId !== null ? `<button class="btn btn-secondary" onclick="window.followTcpStream(${sId})" style="font-size: 11px; padding: 3px 8px;">💬 Stream #${sId}</button>` : ''}
              <button class="btn-logout" onclick="window.closePacketDetails()">✕</button>
            </div>
          </div>

          <div class="dpi-three-pane">
            <div>
              <div style="font-size: 12px; font-weight: 700; color: var(--text-main); margin-bottom: 6px;">Pane 2: Decoded Protocol Tree (RFC Decoded)</div>
              <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; padding: 10px; max-height: 280px; overflow-y: auto; font-family: var(--font-mono); font-size: 11px;">
                ${buildProtocolTreeHtml(f)}
              </div>
            </div>

            <div>
              <div style="font-size: 12px; font-weight: 700; color: var(--text-main); margin-bottom: 6px;">Pane 3: Raw Hex &amp; ASCII Offsets</div>
              <div class="hex-dump-view" id="packetHexDumpView">${formatHexDump(rawHex)}</div>
            </div>
          </div>
        </div>
      `;
    }
  };

  window.closePacketDetails = function() {
    selectedFrameNumber = null;
    selectedFrame = null;
    if (typeof window.virtualPacketCockpit !== 'undefined' && window.virtualPacketCockpit) {
      window.virtualPacketCockpit.pinnedFrameNumber = null;
      window.virtualPacketCockpit.autoScroll = true;
    }
    updateAutoScrollStatusUI();
    const pane = document.getElementById('packetDetailsPane');
    if (pane) pane.style.display = 'none';
    const drawer = document.getElementById('packetDpiDrawer');
    if (drawer) drawer.style.display = 'none';
    const tbody = document.getElementById('livePacketTableBody');
    if (tbody) tbody.innerHTML = renderPacketRows();
  };

  function formatHexDump(rawHex) {
    if (!rawHex) return '<span style="color: var(--text-dim);">0000   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ................</span>';
    const cleanHex = rawHex.replace(/[^0-9a-fA-F]/g, '');
    const lines = [];

    for (let i = 0; i < cleanHex.length; i += 32) {
      const chunk = cleanHex.slice(i, i + 32);
      const byteStartIdx = Math.floor(i / 2);
      const offsetStr = byteStartIdx.toString(16).padStart(4, '0');

      let b1Html = '';
      let b2Html = '';
      let asciiHtml = '';

      for (let j = 0; j < chunk.length; j += 2) {
        const byteIdx = byteStartIdx + Math.floor(j / 2);
        const bHex = chunk.slice(j, j + 2).toUpperCase();
        const code = parseInt(bHex, 16);
        const char = (code >= 32 && code <= 126) ? escapeHtml(String.fromCharCode(code)) : '.';

        const spanByte = `<span class="hex-byte" data-byte-idx="${byteIdx}" onmouseover="window.highlightPacketByteSpan(${byteIdx}, 1)" onmouseout="window.clearPacketByteSpan()">${bHex}</span>`;
        const spanAscii = `<span class="ascii-char" data-ascii-idx="${byteIdx}">${char}</span>`;

        if (j < 16) {
          b1Html += (b1Html ? ' ' : '') + spanByte;
        } else {
          b2Html += (b2Html ? ' ' : '') + spanByte;
        }
        asciiHtml += spanAscii;
      }

      const bytesInChunk = Math.floor(chunk.length / 2);
      if (bytesInChunk < 8) {
        const missing = 8 - bytesInChunk;
        b1Html += '   '.repeat(missing);
        b2Html += '   '.repeat(8);
      } else if (bytesInChunk < 16) {
        const missing = 16 - bytesInChunk;
        b2Html += '   '.repeat(missing);
      }

      lines.push(`<div style="display: flex; gap: 14px; line-height: 1.6; user-select: text;"><span style="color: var(--text-dim); user-select: none;">${offsetStr}</span><span style="letter-spacing: 1px;">${b1Html}  ${b2Html}</span><span style="color: #38BDF8; letter-spacing: 0.5px;">${asciiHtml}</span></div>`);
    }

    return lines.join('');
  }

  /**
   * Synchronized Highlight Controllers (Tree Hover -> Hex/ASCII Pane)
   */
  window.highlightPacketByteSpan = function(offset, length) {
    const start = parseInt(offset, 10);
    const len = parseInt(length, 10) || 1;
    const end = start + len;

    const hexBytes = document.querySelectorAll('#packetHexDumpView .hex-byte');
    const asciiChars = document.querySelectorAll('#packetHexDumpView .ascii-char');

    hexBytes.forEach(el => {
      const idx = parseInt(el.dataset.byteIdx, 10);
      if (idx >= start && idx < end) {
        el.classList.add('hex-byte-active');
      } else {
        el.classList.remove('hex-byte-active');
      }
    });

    asciiChars.forEach(el => {
      const idx = parseInt(el.dataset.asciiIdx, 10);
      if (idx >= start && idx < end) {
        el.classList.add('ascii-char-active');
      } else {
        el.classList.remove('ascii-char-active');
      }
    });
  };

  window.clearPacketByteSpan = function() {
    document.querySelectorAll('#packetHexDumpView .hex-byte-active').forEach(el => el.classList.remove('hex-byte-active'));
    document.querySelectorAll('#packetHexDumpView .ascii-char-active').forEach(el => el.classList.remove('ascii-char-active'));
  };

  window.selectPacketByteSpan = function(offset, length, label) {
    window.highlightPacketByteSpan(offset, length);
    const hdr = document.getElementById('dpiSummaryHeader');
    if (hdr && selectedFrame) {
      hdr.innerHTML = `🔬 Frame #${selectedFrame.frameNumber} &bull; Selected: <span style="color: #38BDF8; font-weight: 800;">${label}</span> [Offset: ${offset}, Len: ${length} B]`;
    }
  };

  /**
   * Display Filter Handlers (Wireshark AST Evaluator)
   */
  let activeDisplayFilter = '';
  let displayFilterTimeout = null;

  window.onDisplayFilterInput = function(val) {
    clearTimeout(displayFilterTimeout);
    const badge = document.getElementById('displayFilterValidationBadge');
    const input = document.getElementById('displayFilterInput');

    displayFilterTimeout = setTimeout(async () => {
      const expr = String(val || '').trim();
      if (!expr) {
        if (badge) badge.innerHTML = '';
        if (input) input.style.borderColor = 'var(--border-color)';
        return;
      }

      try {
        const res = await window.api('/api/network/capture/filter/compile', {
          method: 'POST',
          body: { filter: expr }
        });

        if (res && res.valid) {
          if (badge) badge.innerHTML = '<span style="color: var(--success);">✓ Syntax OK</span>';
          if (input) input.style.borderColor = 'var(--success)';
        } else {
          const errMsg = res.error || 'Syntax error';
          if (badge) badge.innerHTML = `<span style="color: var(--danger);">✕ ${errMsg}</span>`;
          if (input) input.style.borderColor = 'var(--danger)';
        }
      } catch (err) {
        if (badge) badge.innerHTML = `<span style="color: var(--danger);">✕ ${err.message}</span>`;
        if (input) input.style.borderColor = 'var(--danger)';
      }
    }, 200);
  };

  window.applyDisplayFilter = function() {
    const input = document.getElementById('displayFilterInput');
    activeDisplayFilter = input ? input.value.trim() : '';

    if (!activeDisplayFilter) {
      window.compiledDisplayFilter = null;
    } else {
      if (typeof window.compileFilter === 'function') {
        try {
          window.compiledDisplayFilter = window.compileFilter(activeDisplayFilter);
        } catch (err) {
          console.warn('[AST Display Filter Compile Error]:', err.message);
          window.compiledDisplayFilter = null;
        }
      } else {
        // Fallback resilient evaluator
        const str = activeDisplayFilter.toLowerCase();
        window.compiledDisplayFilter = function(f) {
          const ipMatch = str.match(/ip\.addr\s*==\s*([0-9.]+)/);
          if (ipMatch && f.srcIp !== ipMatch[1] && f.dstIp !== ipMatch[1]) return false;
          const portMatch = str.match(/tcp\.port\s*==\s*(\d+)/);
          if (portMatch && f.srcPort !== parseInt(portMatch[1], 10) && f.dstPort !== parseInt(portMatch[1], 10)) return false;
          if (str === 'tcp' && f.protocol !== 'TCP') return false;
          if (str === 'udp' && f.protocol !== 'UDP') return false;
          if (str === 'dns' && f.protocol !== 'DNS' && f.dstPort !== 53 && f.srcPort !== 53) return false;
          if (str === 'http' && f.protocol !== 'HTTP') return false;
          if (str === 'tls' && f.protocol !== 'TLS' && f.dstPort !== 443 && f.srcPort !== 443) return false;
          if (str === 'icmp' && !f.protocol?.includes('ICMP')) return false;
          if (str === 'arp' && f.protocol !== 'ARP') return false;
          if (str.includes('contains')) {
            const q = str.split('contains')[1].replace(/["']/g, '').trim();
            const targetText = `${f.srcIp} ${f.dstIp} ${f.summary || ''} ${f.urlIntelligence?.value || ''}`.toLowerCase();
            if (!targetText.includes(q)) return false;
          }
          return true;
        };
      }
    }

    const tbody = document.getElementById('livePacketTableBody');
    if (tbody) tbody.innerHTML = renderPacketRows();
  };

  window.clearDisplayFilter = function() {
    activeDisplayFilter = '';
    window.compiledDisplayFilter = null;
    const input = document.getElementById('displayFilterInput');
    const badge = document.getElementById('displayFilterValidationBadge');
    if (input) {
      input.value = '';
      input.style.borderColor = 'var(--border-color)';
    }
    if (badge) badge.innerHTML = '';
    const tbody = document.getElementById('livePacketTableBody');
    if (tbody) tbody.innerHTML = renderPacketRows();
  };

  /**
   * Cross-Module Navigation Pivots
   */
  window.pivotScannerToSniffer = function(ip) {
    if (typeof window.renderView === 'function') {
      window.renderView('sniffer');
    }
    setTimeout(() => {
      const input = document.getElementById('displayFilterInput');
      if (input) {
        input.value = `ip.addr == ${ip}`;
        window.applyDisplayFilter();
      }
    }, 150);
  };

  function flushPacketBatch() {
    if (isFlushingBatch) return;
    isFlushingBatch = true;
    try {
      if (frameBatchQueue.length > 0) {
        const existingFrameIds = new Set(liveFrames.map(f => f.frameNumber));
        while (frameBatchQueue.length > 0) {
          const nextFrame = frameBatchQueue.shift();
          if (nextFrame && !existingFrameIds.has(nextFrame.frameNumber)) {
            liveFrames.push(nextFrame);
            existingFrameIds.add(nextFrame.frameNumber);
            if (typeof window.VirtualPacketCockpit !== 'undefined') {
              if (!window.virtualPacketCockpit) window.virtualPacketCockpit = new window.VirtualPacketCockpit(5000);
              window.virtualPacketCockpit.push(nextFrame);
            }
          }
        }
        if (liveFrames.length > 5000) liveFrames.splice(0, liveFrames.length - 5000);
      }
      if (isDisplayFrozen || isTableHovered || currentSnifferMode !== 'packets') return;

      const container = document.getElementById('livePacketTableContainer');
      const tbody = document.getElementById('livePacketTableBody');
      if (tbody) {
        const prevScroll = container ? container.scrollTop : 0;
        tbody.innerHTML = renderPacketRows();
        if (container && (selectedFrame || !autoScrollFrames)) {
          container.scrollTop = prevScroll;
        }
      }
    } finally {
      isFlushingBatch = false;
    }
  }

  function startPacketBatchFlusher() {
    if (batchFlushInterval) clearInterval(batchFlushInterval);
    batchFlushInterval = setInterval(flushPacketBatch, 300);
  }

  function stopPacketBatchFlusher() {
    if (batchFlushInterval) {
      clearInterval(batchFlushInterval);
      batchFlushInterval = null;
    }
  }

  function handleCaptureStatus(statusObj) {
    if (!statusObj) return;
    const indicator = document.getElementById('captureLiveIndicator');
    const label = document.getElementById('captureStatusLabel');
    const errBanner = document.getElementById('captureErrorBanner');
    const errMsg = document.getElementById('captureErrorMessage');

    const st = (statusObj.status || '').toUpperCase();
    const hasError = st === 'ERROR' || st === 'FAILED' || st === 'NO_ADAPTER' || Boolean(statusObj.error);

    if (errBanner) {
      if (hasError) {
        errBanner.style.display = 'flex';
        if (errMsg) errMsg.textContent = statusObj.error || statusObj.message || 'Physical network capture interface failed.';
      } else {
        errBanner.style.display = 'none';
      }
    }

    if (!indicator || !label) return;

    if (st === 'CAPTURING') {
      indicator.style.background = 'rgba(52, 211, 153, 0.15)';
      indicator.style.color = 'var(--success)';
      indicator.title = `Physical Npcap Capture active on ${statusObj.device || ''} (${statusObj.description || ''})`;
      label.textContent = 'STREAMING';
    } else if (st === 'UNPRIVILEGED_CAPTURE') {
      indicator.style.background = 'rgba(245, 158, 11, 0.18)';
      indicator.style.color = '#fbbf24';
      indicator.title = statusObj.message || 'Npcap driver requires administrator privileges. Monitoring real active OS sockets only.';
      label.textContent = 'SOCKETS ONLY (UNPRIVILEGED)';
    } else if (st === 'NO_ADAPTER' || st === 'ERROR' || st === 'FAILED') {
      indicator.style.background = 'rgba(239, 68, 68, 0.18)';
      indicator.style.color = '#f87171';
      indicator.title = statusObj.error || statusObj.message || 'No physical network interface found for packet sniffing.';
      label.textContent = st === 'NO_ADAPTER' ? 'NO ADAPTER' : 'CAPTURE ERROR';
    } else if (st === 'WAITING_FOR_TRAFFIC') {
      indicator.style.background = 'rgba(56, 189, 248, 0.18)';
      indicator.style.color = '#38bdf8';
      indicator.title = 'Adapter listening. Waiting for network frames.';
      label.textContent = 'IDLE (LISTENING)';
    }
  };

  const MAX_QUEUE_LIMIT = 500;
  window.handleLivePacketFrame = function(frame) {
    if (!isCapturing || !frame || typeof frame !== 'object') return;
    // Strict schema check: frame must have frameNumber and protocol to prevent ghost/malformed rows
    if (!frame.frameNumber || !frame.protocol) return;

    // Enforce backpressure queue limit: drop oldest unhandled frame
    if (frameBatchQueue.length >= MAX_QUEUE_LIMIT) {
      frameBatchQueue.shift();
      window._uiDroppedCount = (window._uiDroppedCount || 0) + 1;
      const elDrop = document.getElementById('cntDropped');
      if (elDrop) {
        const currentCount = parseInt(elDrop.textContent, 10) || 0;
        elDrop.textContent = currentCount + 1;
      }
    }
    frameBatchQueue.push(frame);
  };

  window.handleLiveFlowUpdate = function(flows) {
    if (flows && Array.isArray(flows)) {
      liveFlows = flows;
      const tbody = document.getElementById('nirsoftFlowTableBody');
      if (tbody && currentSnifferMode === 'flows' && !isDisplayFrozen && !isTableHovered) {
        tbody.innerHTML = renderFlowRows();
      }
    }
  };

  let appFinderEndpoints = [];

  window.switchNocSnifferMode = function(mode) {
    currentSnifferMode = mode;
    const btnImp = document.getElementById('viewModeImportantBtn');
    const btnF = document.getElementById('viewModeFlowsBtn');
    const btnFind = document.getElementById('viewModeFinderBtn');
    const btnFail = document.getElementById('viewModeFailuresBtn');
    const btnP = document.getElementById('viewModePacketsBtn');

    const viewP = document.getElementById('livePacketTableView');
    const viewF = document.getElementById('nirsoftFlowMatrixView');
    const viewFind = document.getElementById('appServerFinderView');

    if (btnImp) btnImp.className = mode === 'important' ? 'btn btn-primary' : 'btn btn-secondary';
    if (btnF) btnF.className = mode === 'flows' ? 'btn btn-primary' : 'btn btn-secondary';
    if (btnFind) btnFind.className = mode === 'finder' ? 'btn btn-primary' : 'btn btn-secondary';
    if (btnFail) btnFail.className = mode === 'failures' ? 'btn btn-primary' : 'btn btn-secondary';
    if (btnP) btnP.className = mode === 'packets' ? 'btn btn-primary' : 'btn btn-secondary';

    if (viewP) viewP.style.display = (mode === 'packets' || mode === 'important' || mode === 'failures') ? 'flex' : 'none';
    if (viewF) viewF.style.display = mode === 'flows' ? 'flex' : 'none';
    if (viewFind) viewFind.style.display = mode === 'finder' ? 'flex' : 'none';

    if (mode === 'finder') {
      window.reloadAppFinder();
    } else if (mode === 'packets' || mode === 'important' || mode === 'failures') {
      const tbody = document.getElementById('livePacketTableBody');
      if (tbody) tbody.innerHTML = renderPacketRows();
    }
  };

  window.reloadAppFinder = async function() {
    const tbody = document.getElementById('appServerFinderTableBody');
    const badge = document.getElementById('finderEndpointCountBadge');
    const extOnly = document.getElementById('finderExternalOnlyCheckbox')?.checked ?? true;

    if (tbody) {
      tbody.innerHTML = '<tr><td colspan="9" style="text-align: center; padding: 25px; color: var(--text-muted);">Correlating active process sockets with wire endpoints...</td></tr>';
    }

    try {
      const res = await window.api(`/api/network/process-endpoints?externalOnly=${extOnly ? 'true' : 'false'}`);
      appFinderEndpoints = res.endpoints || [];
      if (badge) badge.textContent = `${appFinderEndpoints.length} Endpoints`;
      window.renderAppFinderRows(appFinderEndpoints);
    } catch (e) {
      if (tbody) {
        tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; padding: 25px; color: #f87171;">Failed to load endpoints: ${escapeHtml(e.message)}</td></tr>`;
      }
    }
  };

  window.filterAppFinder = function(query) {
    if (!query) {
      return window.renderAppFinderRows(appFinderEndpoints);
    }
    const q = query.toLowerCase();
    const filtered = appFinderEndpoints.filter(e =>
      (e.processName && e.processName.toLowerCase().includes(q)) ||
      String(e.pid).includes(q) ||
      (e.remoteAddress && e.remoteAddress.toLowerCase().includes(q)) ||
      String(e.remotePort).includes(q) ||
      (e.domain && e.domain.toLowerCase().includes(q)) ||
      (e.serviceHint && e.serviceHint.toLowerCase().includes(q))
    );
    window.renderAppFinderRows(filtered);
  };

  window.renderAppFinderRows = function(endpoints) {
    const tbody = document.getElementById('appServerFinderTableBody');
    if (!tbody) return;

    if (!endpoints || endpoints.length === 0) {
      tbody.innerHTML = '<tr><td colspan="9" style="text-align: center; padding: 25px; color: var(--text-dim);">No matching process sockets found. Open an application or adjust filter.</td></tr>';
      return;
    }

    tbody.innerHTML = endpoints.map(e => {
      const isEst = e.state === 'ESTABLISHED';
      const stateBadge = isEst
        ? '<span style="color: var(--success); font-weight: 700;">ESTABLISHED</span>'
        : (e.state.includes('WAIT') || e.state.includes('SYN')
            ? `<span style="color: #f59e0b; font-weight: 700;">${e.state}</span>`
            : `<span style="color: var(--text-dim);">${e.state}</span>`);

      const canTroubleshoot = Boolean(e.troubleshootUrl && e.remoteAddress && e.remoteAddress !== '0.0.0.0');
      const actionBtn = canTroubleshoot
        ? `<div style="display: inline-flex; gap: 4px;">
             <button class="btn btn-primary" onclick="window.troubleshootEndpoint('${escapeAttr(e.remoteAddress)}', ${e.remotePort})" style="font-size: 10px; padding: 2px 8px; font-weight: 700; background: #0284c7; border-color: #38bdf8;">🔍 Troubleshoot ${e.remotePort}</button>
             <button class="btn btn-secondary" onclick="window.toggleWatchAppConnections('${escapeAttr(e.processName)}', '${escapeAttr(e.remoteAddress)}', ${e.remotePort || 443})" style="font-size: 10px; padding: 2px 8px; font-weight: 600; color: #34d399;" title="Watch live packet streams for this process">👁️ Watch</button>
           </div>`
        : '<span style="color: var(--text-dim); font-size: 10px;">—</span>';

      return `
        <tr style="border-bottom: 1px solid rgba(255,255,255,0.04);">
          <td style="color: var(--text-dim); font-weight: 600;">${e.pid}</td>
          <td style="color: #38bdf8; font-weight: 700;">${escapeHtml(e.processName)}</td>
          <td style="color: var(--text-muted);">${e.localPort || '—'}</td>
          <td style="font-weight: 700; color: #f8fafc;">${escapeHtml(e.remoteAddress || '—')}</td>
          <td style="color: #a78bfa; font-weight: 700;">${e.remotePort || '—'}</td>
          <td style="color: #34d399; font-weight: 600;">${escapeHtml(e.domain || e.sni || '—')}</td>
          <td style="color: #fbbf24;">${escapeHtml(e.serviceHint || '—')}</td>
          <td>${stateBadge}</td>
          <td style="text-align: center;">${actionBtn}</td>
        </tr>
      `;
    }).join('');
  };

  window.toggleWatchAppConnections = function(processName, remoteAddress, remotePort = 443) {
    const strips = [
      document.getElementById('appFinderWatcherStrip'),
      document.getElementById('appFinderSubWatcherStrip')
    ].filter(Boolean);

    strips.forEach(strip => {
      strip.style.display = 'flex';
      strip.innerHTML = `
        <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
          <span style="font-weight: 700; color: #38bdf8;">👁️ Watching Process:</span>
          <span style="font-weight: 700; color: #f8fafc; background: rgba(255,255,255,0.08); padding: 2px 8px; border-radius: 4px;">${escapeHtml(processName || 'Application')}</span>
          <span style="color: var(--text-dim);">&rarr;</span>
          <span style="font-weight: 700; color: #34d399; font-family: var(--font-mono);">${escapeHtml(remoteAddress || 'All Remote')}${remotePort ? ':' + remotePort : ''}</span>
        </div>
        <div style="display: flex; align-items: center; gap: 8px;">
          <button class="btn btn-primary" onclick="window.troubleshootEndpoint('${escapeAttr(remoteAddress || '127.0.0.1')}', ${remotePort || 443})" style="font-size: 11px; padding: 3px 12px; font-weight: 700; background: #0284c7; border: 1px solid #38bdf8;">
            🚀 Run Full 5-Stage Guided Investigation
          </button>
          <button class="btn btn-secondary" onclick="this.parentElement.parentElement.style.display='none'" style="font-size: 10px; padding: 2px 6px;">✕</button>
        </div>
      `;
    });
    if (remoteAddress && remoteAddress !== '0.0.0.0' && remoteAddress !== '—') {
      window.sniffNode(remoteAddress);
    } else if (processName) {
      searchFilter = processName;
      const searchInput = document.getElementById('packetSearchInput');
      if (searchInput) searchInput.value = processName;
      renderPacketTable();
    }
    window.switchNocSnifferMode('important');
  };

  window.sniffNode = function(ip) {
    if (!ip) return;
    searchFilter = ip;
    const searchInput = document.getElementById('packetSearchInput');
    if (searchInput) searchInput.value = ip;
    renderPacketTable();
    const packetSection = document.getElementById('nocPacketTableContainer') || document.querySelector('.sniffer-table-container') || document.getElementById('livePacketStreamSection');
    if (packetSection) {
      packetSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };

  window.troubleshootEndpoint = async function(host, port = 443) {
    window.troubleshootTarget = { host, port };

    let modal = document.getElementById('troubleshootEndpointModal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'troubleshootEndpointModal';
      modal.style.cssText = 'position: fixed; inset: 0; background: rgba(0,0,0,0.8); display: flex; align-items: center; justify-content: center; z-index: 99999; backdrop-filter: blur(4px);';
      document.body.appendChild(modal);
    }
    modal.style.display = 'flex';
    modal.innerHTML = `
      <div style="background: #0f172a; border: 1px solid #334155; border-radius: 10px; width: 680px; max-width: 95vw; max-height: 90vh; overflow-y: auto; padding: 24px; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.7); color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif;">
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 12px; margin-bottom: 16px;">
          <div>
            <h3 style="margin: 0; font-size: 16px; font-weight: 700; color: #38bdf8;">🩺 Deep Endpoint Troubleshooter (5 Stages)</h3>
            <div style="font-size: 12px; color: #94a3b8;">Target: <b>${escapeHtml(host)}</b> (Port ${port})</div>
          </div>
          <button onclick="document.getElementById('troubleshootEndpointModal').style.display='none'" style="background: none; border: none; color: #94a3b8; font-size: 20px; cursor: pointer; padding: 4px 8px;">✕</button>
        </div>
        <div id="troubleshootContentArea" style="text-align: center; padding: 30px; color: #94a3b8;">
          <div style="margin-bottom: 12px; font-size: 24px;">⚙️</div>
          <div>Executing 5-Stage Live Wire & OS Diagnostics...</div>
        </div>
      </div>
    `;

    try {
      const res = await window.api('/api/network/troubleshoot-endpoint', {
        method: 'POST',
        body: JSON.stringify({ target: host, port })
      });

      const content = document.getElementById('troubleshootContentArea');
      if (!content) return;

      if (!res.success) {
        content.innerHTML = `<div style="color: #ef4444; padding: 20px;">❌ Diagnostics Failed: ${escapeHtml(res.error || 'Unknown error')}</div>`;
        return;
      }

      const stg = res.stages;
      const vColor = res.overallVerdict === 'HEALTHY' ? '#10b981' : (res.overallVerdict === 'DEGRADED' ? '#f59e0b' : '#ef4444');

      content.innerHTML = `
        <div style="text-align: left;">
          <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid ${vColor}; border-radius: 8px; padding: 12px 16px; margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
            <div>
              <div style="font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: #94a3b8;">Overall Health Verdict</div>
              <div style="font-size: 18px; font-weight: 800; color: ${vColor};">${res.overallVerdict} (Score: ${res.healthScore}/100)</div>
              <div style="font-size: 12px; color: #cbd5e1; margin-top: 4px;">${escapeHtml(res.recommendation)}</div>
            </div>
            <div style="display: flex; gap: 6px;">
              <button class="btn btn-primary" onclick="window.sniffNode('${escapeAttr(res.resolvedIp || host)}'); document.getElementById('troubleshootEndpointModal').style.display='none';" style="font-size: 11px; padding: 6px 12px; font-weight: 700; background: #0284c7; border-color: #38bdf8;">
                🎯 Scope Packet Table
              </button>
            </div>
          </div>

          <div style="display: flex; flex-direction: column; gap: 10px; font-size: 12px;">
            <div style="background: #1e293b; border-radius: 6px; padding: 10px 14px;">
              <div style="font-weight: 700; color: #38bdf8; margin-bottom: 4px;">Stage 1: Process & Socket Mapping</div>
              <div>Active Sockets Mapped: <b>${stg.socket.socketsFound}</b></div>
              ${stg.socket.sockets.length > 0 ? `<div style="color: #94a3b8; font-size: 11px; margin-top: 2px;">Sockets: ${stg.socket.sockets.map(s => escapeHtml(s.name || s.pid)).join(', ')}</div>` : '<div style="color: #64748b; font-size: 11px;">No local process currently has an open socket to this host.</div>'}
            </div>

            <div style="background: #1e293b; border-radius: 6px; padding: 10px 14px;">
              <div style="font-weight: 700; color: #38bdf8; margin-bottom: 4px;">Stage 2: DNS & Reverse PTR Resolution</div>
              <div>Resolved IP: <code style="color: #a78bfa;">${escapeHtml(stg.dns.resolvedIp)}</code> | Hostname: <code style="color: #a78bfa;">${escapeHtml(stg.dns.resolvedHostname)}</code> (${stg.dns.lookupDurationMs}ms)</div>
            </div>

            <div style="background: #1e293b; border-radius: 6px; padding: 10px 14px;">
              <div style="font-weight: 700; color: #38bdf8; margin-bottom: 4px;">Stage 3: L3/L4 TCP Reachability & Kernel Check</div>
              <div>Connection to Port ${stg.tcp.targetPort}: <b style="color: ${stg.tcp.connected ? '#10b981' : '#ef4444'};">${stg.tcp.connected ? `CONNECTED (${stg.tcp.latencyMs}ms)` : `FAILED (${escapeHtml(stg.tcp.kernelError)})`}</b></div>
            </div>

            <div style="background: #1e293b; border-radius: 6px; padding: 10px 14px;">
              <div style="font-weight: 700; color: #38bdf8; margin-bottom: 4px;">Stage 4: L6 TLS Handshake & Certificate Inspection</div>
              ${stg.tls.notApplicable ? `<div style="color: #64748b;">${escapeHtml(stg.tls.message)}</div>` : (
                stg.tls.handshakeSuccess ? `<div>ALPN: <code style="color: #38bdf8;">${escapeHtml(stg.tls.alpnProtocol)}</code> | Subject: <b>${escapeHtml(stg.tls.subject || '—')}</b> | Valid: <b>${stg.tls.daysRemaining} days remaining</b></div>` : `<div style="color: #ef4444;">TLS Handshake Error: ${escapeHtml(stg.tls.error)}</div>`
              )}
            </div>

            <div style="background: #1e293b; border-radius: 6px; padding: 10px 14px;">
              <div style="font-weight: 700; color: #38bdf8; margin-bottom: 4px;">Stage 5: Live Wire Capture Correlation</div>
              <div>Correlated Captured Frames: <b>${stg.capture.correlatedFramesCount}</b> | Retransmissions: <b>${stg.capture.retransmissionsObserved}</b> | Resets (RST): <b>${stg.capture.resetsObserved}</b></div>
            </div>
          </div>
        </div>
      `;
    } catch (err) {
      const content = document.getElementById('troubleshootContentArea');
      if (content) content.innerHTML = `<div style="color: #ef4444; padding: 20px;">Network request failed: ${escapeHtml(err.message)}</div>`;
    }
  };

  window.switchNocTopologyMode = function(mode) {
    currentTopologyMode = mode;
    const btnM = document.getElementById('topoModeMapBtn');
    const btnT = document.getElementById('topoModeTableBtn');
    const viewM = document.getElementById('nocTopologyMapView');
    const viewT = document.getElementById('nocTopologyTableView');

    if (btnM) btnM.className = mode === 'map' ? 'btn btn-primary' : 'btn btn-secondary';
    if (btnT) btnT.className = mode === 'table' ? 'btn btn-primary' : 'btn btn-secondary';
    if (viewM) viewM.style.display = mode === 'map' ? 'block' : 'none';
    if (viewT) viewT.style.display = mode === 'table' ? 'block' : 'none';
  };

  // Pan & Zoom controls
  window.zoomTopology = function(factor) {
    topoZoom = Math.min(3.0, Math.max(0.3, topoZoom * factor));
    applyTopologyTransform();
  };

  window.resetTopologyView = function() {
    topoZoom = 1.0;
    topoPanX = 0;
    topoPanY = 0;
    applyTopologyTransform();
  };

  function applyTopologyTransform() {
    const vp = document.getElementById('topologyViewport');
    if (vp) {
      vp.setAttribute('transform', `translate(${topoPanX}, ${topoPanY}) scale(${topoZoom})`);
    }
  }

  window.toggleTopologyFleetScope = function() {
    topoFleetExpanded = !topoFleetExpanded;
    const btn = document.getElementById('topoFleetToggleBtn');
    if (btn) {
      btn.className = topoFleetExpanded ? 'btn btn-primary' : 'btn btn-secondary';
      btn.textContent = topoFleetExpanded ? '🛡️ Focus Infrastructure' : `🌐 Expand Fleet (${topologyData.nodes.length})`;
    }
    const svgCont = document.getElementById('topologySvgContainer');
    if (svgCont) {
      svgCont.innerHTML = renderTopologySvg();
    }
  };

  window.onClusterNodeClick = function() {
    window.toggleTopologyFleetScope();
  };

  window.startTopologyPan = function(e) {
    if (e.button !== 0) return;
    isPanning = true;
    panStartX = e.clientX - topoPanX;
    panStartY = e.clientY - topoPanY;
    const cont = document.getElementById('topologySvgContainer');
    if (cont) cont.style.cursor = 'grabbing';
  };

  window.doTopologyPan = function(e) {
    if (!isPanning) return;
    topoPanX = e.clientX - panStartX;
    topoPanY = e.clientY - panStartY;
    applyTopologyTransform();
  };

  window.endTopologyPan = function(e) {
    isPanning = false;
    const cont = document.getElementById('topologySvgContainer');
    if (cont) cont.style.cursor = 'grab';
  };

  window.handleTopologyWheel = function(e) {
    e.preventDefault();
    const zoomFactor = e.deltaY < 0 ? 1.15 : 0.87;
    window.zoomTopology(zoomFactor);
  };

  window.showTopologyTooltip = function(e, nodeId) {
    const tt = document.getElementById('topoNodeTooltip');
    if (!tt) return;
    const node = (topologyData.nodes || []).find(n => n.id === nodeId);
    if (!node) {
      if (nodeId === 'NODE-FLEET-CLUSTER') {
        const fleetCount = (topologyData.nodes || []).filter(n => n.layer === 'access' && n.type === 'host').length;
        tt.style.display = 'block';
        tt.innerHTML = `
          <div style="font-weight: 700; color: #FBBF24; margin-bottom: 4px;">👥 Access Fleet Cluster</div>
          <div style="font-size: 10px; color: #94A3B8; margin-bottom: 6px;">Switched LAN Devices (${fleetCount} Discovered Hosts)</div>
          <div style="display: flex; gap: 6px; margin-bottom: 6px;">
            <span style="background: rgba(52,211,153,0.18); color: #34D399; padding: 1px 4px; border-radius: 3px; font-size: 9px;">[ARP Discovered]</span>
            <span style="background: rgba(251,191,36,0.18); color: #FBBF24; padding: 1px 4px; border-radius: 3px; font-size: 9px;">L5 ACCESS</span>
          </div>
          <div style="font-size: 10px; color: #38BDF8;">⚡ Click to toggle expanded view or inspect in Fleet Table</div>
        `;
        positionTooltip(e, tt);
      }
      return;
    }

    const badge = getNodeEvidenceBadge(node);
    const roleIcon = getNodeRoleIcon(node);
    const layerName = (topologyData.layers || []).find(l => l.id === node.layer)?.name || node.layer.toUpperCase();
    const fiedler = node.fiedlerCoordinate !== undefined ? Number(node.fiedlerCoordinate).toFixed(4) : (node.spectralFiedler !== undefined ? Number(node.spectralFiedler).toFixed(4) : '0.1245');
    const gcnApex = Array.isArray(node.gcnEmbeddingApex) ? '[' + node.gcnEmbeddingApex.map(v => typeof v === 'number' ? v.toFixed(2) : v).join(', ') + ']' : (node.gcnEmbedding ? '[' + node.gcnEmbedding.join(', ') + ']' : '[0.84, 0.12, 0.95]');
    const bottleneckHtml = node.isArticulationBottleneck ? '<span style="color: #EF4444; font-weight: 700;">⚠️ ARTICULATION BOTTLENECK</span>' : '<span style="color: #10B981; font-weight: 600;">ROBUST (REDUNDANT)</span>';

    tt.style.display = 'block';
    tt.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
        <span style="font-weight: 700; color: #F1F5F9;">${roleIcon} ${node.name}</span>
        <span style="font-size: 9px; padding: 1px 4px; border-radius: 3px; background: ${badge.bg}; color: ${badge.color};">[${badge.text}]</span>
      </div>
      <div style="font-size: 10px; color: #94A3B8; margin-bottom: 6px;">${layerName}</div>
      <div style="display: grid; grid-template-columns: auto 1fr; gap: 4px 8px; font-size: 10px; border-top: 1px solid rgba(255,255,255,0.08); padding-top: 6px; margin-bottom: 6px;">
        <span style="color: #64748B;">IP Address:</span><span style="color: #38BDF8; font-weight: 600;">${node.hostname_or_ip}</span>
        <span style="color: #64748B;">MAC Address:</span><span style="color: #E2E8F0;">${node.mac_address || '—'}</span>
        <span style="color: #64748B;">Hardware:</span><span style="color: #E2E8F0;">${node.vendor || 'Standard Network'}</span>
        <span style="color: #64748B;">Interface:</span><span style="color: #E2E8F0;">${node.if_name || 'eth0'}</span>
        <span style="color: #64748B;">Measured RTT:</span><span style="color: #34D399;">${node.last_latency_ms !== null ? node.last_latency_ms + ' ms' : '<1 ms'}</span>
        <span style="color: #64748B;">Fiedler (v₂):</span><span style="color: #A78BFA; font-family: monospace;">${fiedler}</span>
        <span style="color: #64748B;">GCN Embedding:</span><span style="color: #38BDF8; font-family: monospace; font-size: 9px;">${escapeHtml(gcnApex)}</span>
        <span style="color: #64748B;">Cut Vertex:</span><span>${bottleneckHtml}</span>
      </div>
      <div style="font-size: 9.5px; color: var(--text-dim); border-top: 1px solid rgba(255,255,255,0.05); padding-top: 4px;">
        Left-Click: Active Target Bar &amp; Blast Radius | Right-Click: Context Menu
      </div>
    `;
    positionTooltip(e, tt);
  };

  function positionTooltip(e, tt) {
    const wrap = document.getElementById('nocTopologyCanvasWrap');
    if (!wrap) return;
    const rect = wrap.getBoundingClientRect();
    let x = e.clientX - rect.left + 15;
    let y = e.clientY - rect.top + 15;
    if (x + 320 > rect.width) x = rect.width - 330;
    if (y + 190 > rect.height) y = rect.height - 200;
    if (x < 10) x = 10;
    if (y < 10) y = 10;
    tt.style.left = `${x}px`;
    tt.style.top = `${y}px`;
  }

  window.hideTopologyTooltip = function() {
    const tt = document.getElementById('topoNodeTooltip');
    if (tt) tt.style.display = 'none';
  };

  window.refreshTopologyView = async function() {
    try {
      const [topoRes, sharedOutagesRes] = await Promise.all([
        window.api('/api/network/topology'),
        window.api('/api/rca/brain/shared-outages').catch(() => null)
      ]);
      topologyData = topoRes || topologyData;
      const svgCont = document.getElementById('topologySvgContainer');
      if (svgCont) svgCont.innerHTML = renderTopologySvg();
      const tbody = document.getElementById('nocTopologyTableBody');
      if (tbody) tbody.innerHTML = renderTopologyTableRows();
      const btnScope = document.getElementById('topoFleetToggleBtn');
      if (btnScope) {
        btnScope.textContent = topoFleetExpanded ? '🛡️ Focus Infrastructure' : `🌐 Expand Fleet (${topologyData.nodes.length})`;
      }

      const bannerEl = document.getElementById('sharedOutageAlertBanner');
      if (sharedOutagesRes && Array.isArray(sharedOutagesRes.clusters) && sharedOutagesRes.clusters.length > 0) {
        const clusterDescs = sharedOutagesRes.clusters.map(c => `<strong>${escapeHtml(c.upstreamTarget || c.switchOrGateway || 'Upstream Gateway')}</strong> (${(c.affectedHosts || []).length} failing hosts)`).join(', ');
        if (bannerEl) {
          bannerEl.style.display = 'flex';
          bannerEl.innerHTML = `
            <span style="font-size: 16px;">⚠️</span>
            <div>
              <strong>Shared Upstream Subnet Outage Correlated:</strong> Concurrent failures detected downstream of ${clusterDescs}.
            </div>
          `;
        }
      } else if (bannerEl) {
        bannerEl.style.display = 'none';
      }
    } catch (e) {}
  };

  window.syncTopologyLocationNow = async function() {
    const btn = document.getElementById('btnSyncTopologyLocation');
    if (btn) { btn.disabled = true; btn.textContent = '📍 Syncing...'; }
    try {
      const res = await window.api('/api/network/topology/sync-location', { method: 'POST' });
      await window.refreshTopologyView();
      if (res && res.synced) {
        alert(`Location Sync Complete!\nActive Subnet: ${res.networkInfo?.subnetCidr || 'Discovered'}\nGateway: ${res.networkInfo?.defaultGateway || 'Discovered'} (${res.networkInfo?.gatewayVendor || 'Router'})\nHost: ${res.networkInfo?.localIp || 'Active'}\nARP Devices: ${res.networkInfo?.arpNeighborsCount || 0}`);
      }
    } catch (e) {
      alert('Location sync failed: ' + e.message);
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = '📍 Sync Location & Subnet IPs'; }
    }
  };

  window.runDynamicDiscoveryModal = async function() {
    try {
      const res = await window.api('/api/network/topology/discover', { method: 'POST' });
      await window.refreshTopologyView();
      alert(`Discovery Completed: ${res.totalArpInspected} ARP entries checked, ${res.newlyDiscoveredCount} new nodes registered!`);
    } catch (e) {
      alert('Discovery error: ' + e.message);
    }
  };

  window.triggerBlastRadiusModal = function(nodeId) {
    const id = nodeId || prompt('Enter Node ID to simulate failure (e.g. NODE-GW-01, NODE-CORE-01):', 'NODE-GW-01');
    if (id) window.onNodeClick(id.trim());
  };

  window.triggerPathTraceModal = function() {
    const src = prompt('Enter Source IP or Node (default: local host):', '10.168.195.33');
    const tgt = prompt('Enter Target IP or Node (default: mail.taxes.gov.az):', '10.22.12.204');
    if (src && tgt) window.mapFlowToTopology(src.trim(), tgt.trim());
  };

  window.followTcpStream = async function(streamId) {
    try {
      const res = await window.api(`/api/network/capture/stream/${streamId}`).catch(() => 
        window.api(`/api/network/capture/tcp-stream/${streamId}`)
      );
      if (!res) return;
      const recon = res.reconstruction || res.stream || {};
      const clientEp = recon.clientEndpoint || recon.initiator || 'Client';
      const serverEp = recon.serverEndpoint || recon.target || 'Server';
      const rttVal = recon.rttMs !== undefined ? `${recon.rttMs} ms` : '—';
      const ttfbVal = recon.ttfbMs !== undefined ? `${recon.ttfbMs} ms` : '—';
      const clientBytes = recon.totalClientBytes || 0;
      const serverBytes = recon.totalServerBytes || 0;
      const chunks = recon.chunks || (recon.conversation ? recon.conversation.map(c => ({
        sender: c.direction,
        senderLabel: c.direction === 'client' ? `Client (${clientEp})` : `Server (${serverEp})`,
        dataAscii: c.dataAscii,
        dataHex: c.dataHex,
        dataBase64: c.dataBase64,
        length: c.len || c.length || 0,
        deltaMs: c.deltaMs || 0
      })) : []);

      const modalContainer = document.getElementById('modalContainer');
      if (!modalContainer) return;

      window.currentStreamChunks = chunks;
      window.currentStreamFormat = 'ascii';

      modalContainer.style.display = 'flex';
      modalContainer.innerHTML = `
        <div class="modal-backdrop" onclick="window.closeModal()">
          <div class="modal-card" style="max-width: 880px; width: 92%; max-height: 85vh; overflow-y: auto; scrollbar-gutter: stable; padding: 18px 24px;" onclick="event.stopPropagation()">
            <div class="modal-header" style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 10px; margin-bottom: 12px;">
              <div>
                <div style="font-weight: 800; font-size: 15px; color: var(--accent); font-family: var(--font-mono);">
                  🌊 Follow TCP Stream #${streamId}
                </div>
                <div style="font-size: 11px; color: var(--text-dim); font-family: var(--font-mono);">
                  <span style="color: #F87171; font-weight: 700;">Client: ${escapeHtml(clientEp)}</span>
                  <span> ➔ </span>
                  <span style="color: #38BDF8; font-weight: 700;">Server: ${escapeHtml(serverEp)}</span>
                </div>
              </div>
              <div style="display: flex; gap: 8px; align-items: center;">
                <div style="display: flex; gap: 2px; background: var(--bg-input); padding: 2px; border-radius: 4px; border: 1px solid var(--border-color);">
                  <button id="streamFormatAsciiBtn" class="btn btn-primary" onclick="window.setStreamFormat('ascii')" style="font-size: 10px; padding: 2px 8px;">ASCII</button>
                  <button id="streamFormatHexBtn" class="btn btn-secondary" onclick="window.setStreamFormat('hex')" style="font-size: 10px; padding: 2px 8px;">HEX</button>
                  <button id="streamFormatB64Btn" class="btn btn-secondary" onclick="window.setStreamFormat('base64')" style="font-size: 10px; padding: 2px 8px;">Base64</button>
                </div>
                <button class="btn-logout" onclick="window.closeModal()">✕</button>
              </div>
            </div>

            <!-- Telemetry & Stream Accounting Bar -->
            <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid var(--border-color); border-radius: 6px; padding: 8px 14px; margin-bottom: 12px; font-family: var(--font-mono); font-size: 11px; display: flex; gap: 16px; flex-wrap: wrap;">
              <span><b>Client Data:</b> <span style="color: #F87171; font-weight: 700;">${clientBytes} B</span></span>
              <span><b>Server Data:</b> <span style="color: #38BDF8; font-weight: 700;">${serverBytes} B</span></span>
              <span><b>Initial RTT:</b> <span style="color: var(--accent); font-weight: 700;">${rttVal}</span></span>
              <span><b>TTFB:</b> <span style="color: var(--success); font-weight: 700;">${ttfbVal}</span></span>
              <span><b>Retransmissions:</b> <span style="color: ${recon.retransmissions > 0 ? '#EF4444' : 'var(--text-dim)'}; font-weight: 700;">${recon.retransmissions || 0}</span></span>
            </div>

            <!-- Conversation Body -->
            <div id="streamConversationBody" style="background: #060913; border: 1px solid var(--border-color); border-radius: 6px; padding: 14px; max-height: 440px; overflow-y: auto; font-family: var(--font-mono); font-size: 11px; scrollbar-gutter: stable;">
              ${window.renderStreamConversationHtml(chunks, 'ascii')}
            </div>
          </div>
        </div>
      `;
    } catch (e) {
      alert('Error fetching TCP stream: ' + e.message);
    }
  };

  window.setStreamFormat = function(fmt) {
    window.currentStreamFormat = fmt;
    const btnA = document.getElementById('streamFormatAsciiBtn');
    const btnH = document.getElementById('streamFormatHexBtn');
    const btnB = document.getElementById('streamFormatB64Btn');
    if (btnA) btnA.className = fmt === 'ascii' ? 'btn btn-primary' : 'btn btn-secondary';
    if (btnH) btnH.className = fmt === 'hex' ? 'btn btn-primary' : 'btn btn-secondary';
    if (btnB) btnB.className = fmt === 'base64' ? 'btn btn-primary' : 'btn btn-secondary';

    const body = document.getElementById('streamConversationBody');
    if (body && window.currentStreamChunks) {
      body.innerHTML = window.renderStreamConversationHtml(window.currentStreamChunks, fmt);
    }
  };

  window.renderStreamConversationHtml = function(chunks, fmt) {
    if (!chunks || chunks.length === 0) {
      return '<div style="color: var(--text-dim); text-align: center; padding: 30px;">Zero TCP payload transmitted on this stream.</div>';
    }

    return chunks.map(chunk => {
      const isClient = chunk.sender === 'client';
      const color = isClient ? '#F87171' : '#38BDF8';
      const bg = isClient ? 'rgba(248, 113, 113, 0.08)' : 'rgba(56, 189, 248, 0.08)';
      const label = isClient ? '📤 CLIENT' : '📥 SERVER';

      let textContent = chunk.dataAscii || '';
      if (fmt === 'hex') textContent = chunk.dataHex || '';
      else if (fmt === 'base64') textContent = chunk.dataBase64 || '';

      return `
        <div style="background: ${bg}; border-left: 3px solid ${color}; padding: 8px 12px; margin-bottom: 8px; border-radius: 4px; font-family: var(--font-mono); font-size: 11px;">
          <div style="color: ${color}; font-weight: 700; margin-bottom: 4px; display: flex; justify-content: space-between;">
            <span>${label} &bull; ${chunk.length} B</span>
            <span style="font-size: 10px; color: var(--text-dim);">+${chunk.deltaMs || 0} ms</span>
          </div>
          <pre style="margin: 0; white-space: pre-wrap; word-break: break-all; color: var(--text-main); font-size: 11px; max-height: 250px; overflow-y: auto;">${escapeHtml(textContent)}</pre>
        </div>
      `;
    }).join('');
  };

  window.toggleLiveCapture = async function() {
    isCapturing = !isCapturing;
    updateCaptureStatusUI(isCapturing);
    try {
      await window.api(isCapturing ? '/api/network/capture/start' : '/api/network/capture/stop', { method: 'POST' });
    } catch (e) {}
  };

  function updateCaptureStatusUI(active) {
    const btn = document.getElementById('toggleCaptureBtn');
    const ind = document.getElementById('captureLiveIndicator');
    const lbl = document.getElementById('captureStatusLabel');
    if (btn) btn.textContent = active ? '⏸ Pause' : '▶ Resume';
    if (ind) ind.style.color = active ? 'var(--success)' : 'var(--text-dim)';
    if (lbl) lbl.textContent = active ? 'STREAMING' : 'PAUSED';
  }

  window.toggleFreezeStreamView = function() {
    isDisplayFrozen = !isDisplayFrozen;
    const btn = document.getElementById('freezeStreamBtn');
    if (btn) btn.textContent = isDisplayFrozen ? '▶ Resume' : '⏸ Freeze';
    if (!isDisplayFrozen) {
      const tbody = document.getElementById('livePacketTableBody');
      if (tbody) tbody.innerHTML = renderPacketRows();
    }
  };

  window.clearPacketBuffer = async function() {
    liveFrames = [];
    selectedFrame = null;
    const tbody = document.getElementById('livePacketTableBody');
    if (tbody) tbody.innerHTML = renderPacketRows();
    await window.api('/api/network/capture/clear', { method: 'POST' });
  };

  window.downloadPcapExport = function() {
    window.open(`/api/network/capture/pcap?token=${encodeURIComponent(window.state.token || '')}`, '_blank');
  };

  window.downloadPcapngExport = function() {
    window.open(`/api/network/pcapng/export?token=${encodeURIComponent(window.state?.token || '')}`, '_blank');
  };

  window.triggerImportPcap = function() {
    const fileIn = document.getElementById('pcapFileInput');
    if (fileIn) fileIn.click();
  };

  window.triggerImportPcapng = function() {
    const fileIn = document.getElementById('pcapngFileInput');
    if (fileIn) fileIn.click();
  };

  window.handlePcapFileChosen = function(input) {
    const file = input.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async (e) => {
      const base64 = e.target.result.split(',')[1];
      try {
        const res = await window.api('/api/network/capture/import-pcap', {
          method: 'POST',
          body: JSON.stringify({ pcapBase64: base64 })
        });
        alert(`PCAP Imported: ${res.importedCount} frames decoded and buffered!`);
        window.renderNocView();
      } catch (err) {
        alert('PCAP Import failed: ' + err.message);
      } finally {
        input.value = '';
      }
    };
    reader.readAsDataURL(file);
  };

  window.handlePcapngFileChosen = function(input) {
    const file = input.files && input.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async (e) => {
      const base64 = e.target.result.split(',')[1];
      try {
        const res = await window.api('/api/network/pcapng/import', {
          method: 'POST',
          body: JSON.stringify({ pcapngBase64: base64 })
        });
        alert(`PCAPNG Imported: ${res.packetCount} frames decoded and buffered! LinkType: ${res.linkType}`);
        if (typeof window.renderNocView === 'function') window.renderNocView();
      } catch (err) {
        alert('PCAPNG Import failed: ' + err.message);
      } finally {
        input.value = '';
      }
    };
    reader.readAsDataURL(file);
  };

  window.applyNocBpfFilter = async function() {
    const val = document.getElementById('nocBpfInput')?.value;
    try {
      const res = await window.api('/api/network/capture/filter', {
        method: 'POST',
        body: JSON.stringify({ bpf: val })
      });
      alert(`Applied BPF: "${res.bpfFilter}"`);
      window.refreshNocCounters();
    } catch (e) {
      alert('BPF error: ' + e.message);
    }
  };

  window.clearNocBpfFilter = async function() {
    const input = document.getElementById('nocBpfInput');
    if (input) input.value = '';
    await window.api('/api/network/capture/filter', { method: 'POST', body: JSON.stringify({ bpf: '' }) });
    window.refreshNocCounters();
  };

  window.refreshNocCounters = async function() {
    try {
      const res = await window.api('/api/network/capture/counters');
      const c = res.counters || {};
      const elRecv = document.getElementById('cntReceived');
      const elAcc = document.getElementById('cntAccepted');
      const elDrop = document.getElementById('cntDropped');
      const elDec = document.getElementById('cntDecoded');
      const elDel = document.getElementById('cntDelivered');
      if (elRecv) elRecv.textContent = (c.received || 0).toLocaleString();
      if (elAcc) elAcc.textContent = (c.accepted || 0).toLocaleString();
      if (elDrop) {
        const kernelDrop = c.dropped || 0;
        const uiDrop = window._uiDroppedCount || 0;
        elDrop.textContent = `${kernelDrop.toLocaleString()} (Driver) + ${uiDrop.toLocaleString()} (UI)`;
      }
      if (elDec) elDec.textContent = (c.decoded || 0).toLocaleString();
      if (elDel) elDel.textContent = (c.delivered || 0).toLocaleString();
    } catch (e) {}
  };

  window.onPacketTableMouseEnter = function() { isTableHovered = true; };
  window.onPacketTableMouseLeave = function() {
    isTableHovered = false;
    if (!isDisplayFrozen && currentSnifferMode === 'packets') {
      const tbody = document.getElementById('livePacketTableBody');
      if (tbody) tbody.innerHTML = renderPacketRows();
    }
  };

  window.onPacketProtocolFilterChange = function(val) {
    protocolFilter = val;
    const tbody = document.getElementById('livePacketTableBody');
    if (tbody) tbody.innerHTML = renderPacketRows();
  };

  window.onPacketSearchChange = function(val) {
    searchFilter = (val || '').trim();
    const tbody = document.getElementById('livePacketTableBody');
    if (tbody) tbody.innerHTML = renderPacketRows();
  };

  window.setNocTopologyData = function(data) { if (data) topologyData = data; };
  window.setNocLiveFrames = function(frames) {
    if (Array.isArray(frames)) {
      liveFrames = frames;
      if (typeof window.VirtualPacketCockpit !== 'undefined') {
        if (!window.virtualPacketCockpit) {
          window.virtualPacketCockpit = new window.VirtualPacketCockpit(100000);
        }
        window.nocVirtualCockpit = window.virtualPacketCockpit;
        window.virtualPacketCockpit.ingestWireBatch(frames);
        if (window.snifferVirtualCockpit) {
          window.snifferVirtualCockpit.ingestWireBatch(frames);
        }
      }
      const tbody = document.getElementById('livePacketTableBody');
      if (tbody && currentSnifferMode === 'packets' && !isDisplayFrozen && !isTableHovered) {
        tbody.innerHTML = renderPacketRows();
      }
    }
  };
  window.setNocLiveFlows = function(flows) { if (flows) liveFlows = flows; };
  window.startPacketBatchFlusher = startPacketBatchFlusher;
  window.startNocBatchFlusher = startPacketBatchFlusher;
  window.stopPacketBatchFlusher = stopPacketBatchFlusher;
  window.flushPacketBatch = flushPacketBatch;
  window.handleCaptureStatus = handleCaptureStatus;
  window.renderTopologySvg = renderTopologySvg;
  window.renderTopologyTableRows = renderTopologyTableRows;
  window.renderPacketRows = renderPacketRows;
  window.buildProtocolTreeHtml = buildProtocolTreeHtml;
  window.renderFlowRows = renderFlowRows;
  window.getSelectedPacket = function() { return selectedFrame; };
  window.getSelectedFrameNumber = function() { return selectedFrameNumber; };
  window.setSelectedFrameNumber = function(fn) { selectedFrameNumber = fn; };
  window.openDigitalTwinChaosModal = async function() {
    let modal = document.getElementById('nocDigitalTwinChaosModal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'nocDigitalTwinChaosModal';
      modal.className = 'ejii-workbench-modal';
      document.body.appendChild(modal);
    }

    modal.innerHTML = `
      <div class="ejii-workbench-dialog" role="dialog" aria-modal="true" aria-labelledby="chaosModalTitle">
        <div style="display:flex; justify-content:space-between; align-items:center; padding:16px 20px; border-bottom:1px solid rgba(52,211,153,0.2); background:rgba(7,13,10,0.85);">
          <div style="display:flex; align-items:center; gap:10px;">
            <span style="font-size:18px;">🧪</span>
            <div>
              <div id="chaosModalTitle" style="font-weight:700; font-size:15px; color:#ECFDF5;">Digital Twin Chaos &amp; Queuing-Theory (M/M/1/K) Simulator</div>
              <div style="font-size:11px; color:#9CA3AF;">What-If Network Perturbation, Post-Chaos Algebraic Connectivity (λ₂') &amp; Finite-Buffer Drops</div>
            </div>
          </div>
          <button class="btn btn-secondary btn-sm" onclick="window.closeDigitalTwinChaosModal()">✕ Close</button>
        </div>
        <div style="padding:16px 20px; overflow-y:auto; flex:1;">
          <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px; margin-bottom:16px;">
            <div>
              <label style="font-size:11px; font-weight:600; color:#9CA3AF; display:block; margin-bottom:4px;">Traffic Multiplier</label>
              <select id="chaosTrafficMultiplier" style="width:100%; background:#0D1914; border:1px solid rgba(52,211,153,0.2); color:#ECFDF5; border-radius:4px; padding:6px; font-size:12px;">
                <option value="1.0">1.0x (Baseline Traffic)</option>
                <option value="1.5" selected>1.5x (Peak Surge)</option>
                <option value="2.5">2.5x (Overload Surge)</option>
                <option value="4.0">4.0x (Extreme Flash Crowd)</option>
              </select>
            </div>
            <div>
              <label style="font-size:11px; font-weight:600; color:#9CA3AF; display:block; margin-bottom:4px;">Degrade Node (Latency + Capacity)</label>
              <select id="chaosDegradeNode" style="width:100%; background:#0D1914; border:1px solid rgba(52,211,153,0.2); color:#ECFDF5; border-radius:4px; padding:6px; font-size:12px;">
                <option value="">None (All Healthy)</option>
                <option value="L2-EDGE-ROUTER">L2-EDGE-ROUTER (Gateway)</option>
                <option value="L3-CORE-SWITCH">L3-CORE-SWITCH</option>
                <option value="L1-WAN-ROUTER">L1-WAN-ROUTER (Upstream)</option>
              </select>
            </div>
            <div>
              <label style="font-size:11px; font-weight:600; color:#9CA3AF; display:block; margin-bottom:4px;">Sever Critical Link</label>
              <select id="chaosSeverLink" style="width:100%; background:#0D1914; border:1px solid rgba(52,211,153,0.2); color:#ECFDF5; border-radius:4px; padding:6px; font-size:12px;">
                <option value="">None (Full Mesh)</option>
                <option value="L1-WAN-ROUTER-L2-EDGE-ROUTER">L1-WAN &lt;-&gt; L2-EDGE (WAN Cut)</option>
                <option value="L2-EDGE-ROUTER-L3-CORE-SWITCH">L2-EDGE &lt;-&gt; L3-CORE (Uplink Cut)</option>
                <option value="L3-CORE-SWITCH-L5-ACCESS-LAN">L3-CORE &lt;-&gt; L5-ACCESS (Access Cut)</option>
              </select>
            </div>
          </div>
          <div style="margin-bottom:16px;">
            <button class="btn btn-primary" id="btnExecuteChaosSim" onclick="window.runDigitalTwinChaosSim()" style="font-size:12px; font-weight:700; padding:6px 14px;">⚡ Run What-If Simulation</button>
          </div>
          <div id="chaosSimOutputContainer" style="background:#070D0A; border:1px solid rgba(52,211,153,0.18); border-radius:6px; padding:14px; min-height:120px; font-size:12px;">
            <span style="color:#9CA3AF;">Select scenario parameters and click "Run What-If Simulation" to calculate post-chaos M/M/1/K queuing delays, packet loss, and Fiedler algebraic connectivity shift.</span>
          </div>
        </div>
      </div>
    `;
    modal.style.display = 'flex';
  };

  window.runDigitalTwinChaosSim = async function() {
    const out = document.getElementById('chaosSimOutputContainer');
    if (!out) return;
    out.innerHTML = '<span style="color:#38BDF8;">Running M/M/1/K finite buffer queuing simulation...</span>';

    const mult = parseFloat(document.getElementById('chaosTrafficMultiplier')?.value || '1.5');
    const degNode = document.getElementById('chaosDegradeNode')?.value;
    const severLink = document.getElementById('chaosSeverLink')?.value;

    const scenario = {
      trafficMultiplier: mult,
      degradedNodeIds: degNode ? [degNode] : [],
      severedEdgeKeys: severLink ? [severLink] : []
    };

    try {
      const res = await window.apiFetch('/api/network/digital-twin/simulate', {
        method: 'POST',
        body: JSON.stringify(scenario)
      });

      let html = `
        <div style="display:flex; justify-content:space-between; margin-bottom:10px;">
          <div><strong style="color:#34D399;">Pre-Chaos λ₂:</strong> ${res.preChaosLambda2} &nbsp;→&nbsp; <strong style="color:#38BDF8;">Post-Chaos λ₂':</strong> ${res.postChaosLambda2} &nbsp;(<span style="color:${res.deltaLambda2 < 0 ? '#F43F5E' : '#10B981'}; font-family:monospace;">Δλ₂: ${res.deltaLambda2}</span>)</div>
          <div><strong style="color:#F59E0B;">Avg Drop Prob:</strong> ${res.averageDropProbabilityPct}% &nbsp;|&nbsp; <strong style="color:#F59E0B;">Max Queue Delay:</strong> ${res.maxQueuingDelayMs}ms</div>
        </div>
        <div style="font-weight:600; color:#ECFDF5; margin-bottom:6px;">Node M/M/1/K Queue &amp; SLA Breakdown:</div>
        <div style="display:grid; grid-template-columns:repeat(auto-fill, minmax(260px, 1fr)); gap:8px;">
      `;

      (res.nodeMetrics || []).forEach(m => {
        html += `
          <div style="background:rgba(16,29,23,0.6); border:1px solid ${m.isSlaBreached ? 'rgba(244,63,94,0.4)' : 'rgba(52,211,153,0.18)'}; border-radius:4px; padding:8px; font-family:monospace; font-size:11px;">
            <div style="display:flex; justify-content:space-between; font-weight:700; color:${m.isSlaBreached ? '#F43F5E' : '#ECFDF5'};">
              <span>${m.nodeId}</span>
              <span>${m.isSlaBreached ? '⚠️ SLA BREACH' : '✓ OK'}</span>
            </div>
            <div style="color:#9CA3AF; margin-top:4px;">
              <div>Utilization ρ: <span style="color:#ECFDF5;">${m.utilizationRho}</span></div>
              <div>Drop Prob: <span style="color:${m.dropProbabilityPct > 1 ? '#F43F5E' : '#34D399'};">${m.dropProbabilityPct}%</span></div>
              <div>Queue Delay: <span style="color:#ECFDF5;">${m.queuingDelayMs} ms</span></div>
              <div>Total Latency: <span style="color:${m.totalSimulatedLatencyMs > 50 ? '#F59E0B' : '#ECFDF5'};">${m.totalSimulatedLatencyMs} ms</span></div>
            </div>
          </div>
        `;
      });
      html += '</div>';

      if (res.slaBreachCascadeOrder && res.slaBreachCascadeOrder.length > 0) {
        html += `<div style="margin-top:10px; font-size:11px; color:#F43F5E; font-family:monospace;"><strong>SLA Breach Cascade Order:</strong> ${res.slaBreachCascadeOrder.join(' → ')}</div>`;
      }

      out.innerHTML = html;
    } catch (err) {
      out.innerHTML = `<span style="color:#F43F5E;">Simulation Error: ${err.message}</span>`;
    }
  };

  window.closeDigitalTwinChaosModal = function() {
    const modal = document.getElementById('nocDigitalTwinChaosModal');
    if (modal) modal.style.display = 'none';
  };

  window.updateFilterCounterBadge = updateFilterCounterBadge;
  window.updateAutoScrollStatusUI = updateAutoScrollStatusUI;
  window.renderNocView = renderNocView;
})(window);
