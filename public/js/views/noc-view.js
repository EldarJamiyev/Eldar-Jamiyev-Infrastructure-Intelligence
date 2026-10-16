/**
 * EJII Pure NOC Topology & Wireshark-Grade Live Packet Dissection Workstation
 * Upper Pane: Layer 1-6 Topology Graph, Blast Radius Simulator, Path Trace Visualizer, Link Congestion Heatmap.
 * Lower Pane: 3-Pane Deep Packet Inspector (Frame Summary, Protocol Tree, Synchronized Hex/ASCII), TCP Delta Tracker, NirSoft Flow Matrix.
 * Integration: Port-Level Capture Trigger, Conversational Flow Route Mapper, Anomaly Flasher.
 */

(function(window) {
  'use strict';

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
  let selectedFlow = null;
  let currentSnifferMode = 'packets';
  let currentTopologyMode = 'map';
  let topoFleetExpanded = false;
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
      const [topoRes, captureStatusRes, initialFramesRes, flowsRes] = await Promise.all([
        window.api('/api/network/topology'),
        window.api('/api/network/capture/status').catch(() => ({ active: true })),
        window.api('/api/network/capture/frames?limit=60').catch(() => ({ frames: [] })),
        window.api('/api/network/capture/flows?limit=60').catch(() => ({ flows: [] }))
      ]);

      topologyData = topoRes || { nodes: [], edges: [], layers: [] };
      isCapturing = captureStatusRes ? captureStatusRes.active : true;
      if (initialFramesRes && initialFramesRes.frames) liveFrames = initialFramesRes.frames;
      if (flowsRes && flowsRes.flows) liveFlows = flowsRes.flows;

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

          <!-- UPPER PANE: NOC NETWORK TOPOLOGY & DEPENDENCY GRAPH -->
          <div class="noc-pane-upper card" style="margin: 0;">
            <div class="card-header" style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; padding: 12px 16px;">
              <div style="display: flex; align-items: center; gap: 10px;">
                <span style="font-size: 20px;">🌐</span>
                <div>
                  <div class="card-title" style="margin: 0; font-size: 14px;">Pillar 1: NOC Network Topology &amp; Dependency Graph</div>
                  <div style="font-size: 11px; color: var(--text-muted);">
                    Hierarchical Physical/Logical Link Fabric: Upstream WAN ➔ Edge Gateway ➔ Core Backbone ➔ Enterprise Services ➔ Access LAN ➔ Workstation
                  </div>
                </div>
              </div>

              <!-- Topology Controls -->
              <div style="display: flex; gap: 6px; align-items: center; flex-wrap: wrap;">
                <div style="display: flex; gap: 2px; background: var(--bg-input); padding: 2px; border-radius: 6px; border: 1px solid var(--border-color);">
                  <button id="topoModeMapBtn" class="btn ${currentTopologyMode === 'map' ? 'btn-primary' : 'btn-secondary'}" onclick="window.switchNocTopologyMode('map')" style="font-size: 11px; padding: 3px 8px; font-weight: 600;">🗺️ Topology Map</button>
                  <button id="topoModeTableBtn" class="btn ${currentTopologyMode === 'table' ? 'btn-primary' : 'btn-secondary'}" onclick="window.switchNocTopologyMode('table')" style="font-size: 11px; padding: 3px 8px; font-weight: 600;">📋 Node Fleet (${topologyData.nodes.length})</button>
                </div>
                <button id="topoFleetToggleBtn" class="btn ${topoFleetExpanded ? 'btn-primary' : 'btn-secondary'}" onclick="window.toggleTopologyFleetScope()" style="font-size: 11px; padding: 3px 8px; font-weight: 600;" title="Toggle between Infrastructure Focus and Expanded Discovered Access Fleet">
                  ${topoFleetExpanded ? '🛡️ Focus Infrastructure' : '🌐 Expand Fleet (' + (topologyData.nodes.length) + ')'}
                </button>
                <div style="display: flex; gap: 2px; background: var(--bg-input); padding: 2px; border-radius: 6px; border: 1px solid var(--border-color);">
                  <button class="btn btn-secondary" onclick="window.zoomTopology(1.2)" style="font-size: 11px; padding: 3px 7px;" title="Zoom In">➕</button>
                  <button class="btn btn-secondary" onclick="window.zoomTopology(0.8)" style="font-size: 11px; padding: 3px 7px;" title="Zoom Out">➖</button>
                  <button class="btn btn-secondary" onclick="window.resetTopologyView()" style="font-size: 11px; padding: 3px 8px;" title="Reset Pan &amp; Zoom">⟲ Reset</button>
                </div>
                <button class="btn btn-primary" onclick="window.runDynamicDiscoveryModal()" style="font-size: 11px; padding: 4px 10px; font-weight: 600;" title="Run SNMP &amp; ARP dynamic layer-2/3 discovery">⚡ Discover Network</button>
                <button class="btn btn-secondary" onclick="window.clearBlastRadius()" style="font-size: 11px; padding: 4px 8px;" title="Reset highlight overlays">↺ Reset</button>
                <button class="btn btn-secondary" onclick="window.refreshTopologyView()" style="font-size: 11px; padding: 4px 8px;" title="Refresh topology from database">↻</button>
              </div>
            </div>

            <!-- View A: Interactive Visual Topology Canvas -->
            <div id="nocTopologyMapView" style="display: ${currentTopologyMode === 'map' ? 'block' : 'none'}; padding: 12px 16px;">
              <div id="nocTopologyCanvasWrap" style="background: #080D1A; border-radius: 8px; border: 1px solid rgba(255,255,255,0.08); padding: 14px; position: relative; overflow: hidden; user-select: none;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; border-bottom: 1px solid rgba(255,255,255,0.06); padding-bottom: 6px; font-size: 10px; font-family: var(--font-mono); color: var(--text-dim); flex-wrap: wrap; gap: 8px;">
                  <div>
                    <span><b>HEATMAP CONGESTION:</b> <span style="color: #10B981;">● Smooth Green (&lt;50%)</span> | <span style="color: #F59E0B;">● Amber (50-85%)</span> | <span style="color: #EF4444;">● Flashing Red (&gt;85%)</span></span>
                  </div>
                  <div>
                    <span><b>CONTROLS:</b> Drag to Pan | Scroll to Zoom | Click Node: Blast Radius | Right-Click: Context Menu</span>
                  </div>
                </div>

                <div id="topologySvgContainer" style="overflow: hidden; cursor: grab;" onmousedown="window.startTopologyPan(event)" onmousemove="window.doTopologyPan(event)" onmouseup="window.endTopologyPan(event)" onmouseleave="window.endTopologyPan(event)" onwheel="window.handleTopologyWheel(event)">
                  ${renderTopologySvg()}
                </div>

                <!-- Floating Node HUD Tooltip -->
                <div id="topoNodeTooltip" style="display: none; position: absolute; z-index: 1050; background: #0F172A; border: 1px solid var(--accent); border-radius: 8px; box-shadow: 0 10px 30px rgba(0,0,0,0.8); padding: 10px 14px; font-size: 11px; font-family: var(--font-mono); pointer-events: none; max-width: 320px; color: #E2E8F0;"></div>

                <!-- Simulation & Path Trace Overlay Banner -->
                <div id="topologyOverlayBanner" style="display: none; margin-top: 10px; padding: 8px 12px; border-radius: 6px; font-size: 11px; font-family: var(--font-mono);"></div>
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
                <div style="display: flex; gap: 2px; background: var(--bg-input); padding: 2px; border-radius: 6px; border: 1px solid var(--border-color);">
                  <button id="viewModePacketsBtn" class="btn ${currentSnifferMode === 'packets' ? 'btn-primary' : 'btn-secondary'}" onclick="window.switchNocSnifferMode('packets')" style="font-size: 11px; padding: 3px 8px; font-weight: 600;">📋 Live Frames</button>
                  <button id="viewModeFlowsBtn" class="btn ${currentSnifferMode === 'flows' ? 'btn-primary' : 'btn-secondary'}" onclick="window.switchNocSnifferMode('flows')" style="font-size: 11px; padding: 3px 8px; font-weight: 600;">📊 Flow Matrix (35 Cols)</button>
                </div>

                <select id="packetProtocolFilter" class="form-input" style="width: 95px; padding: 4px 6px; font-size: 11px;" onchange="window.onPacketProtocolFilterChange(this.value)">
                  <option value="ALL">All Proto</option>
                  <option value="TCP">TCP</option>
                  <option value="UDP">UDP</option>
                  <option value="DNS">DNS</option>
                  <option value="HTTP">HTTP</option>
                  <option value="TLS">TLS</option>
                  <option value="ICMP">ICMP</option>
                  <option value="ARP">ARP</option>
                </select>

                <input type="text" id="packetSearchInput" class="form-input" placeholder="Search IP, port, URL, host..." style="width: 150px; padding: 4px 6px; font-size: 11px;" oninput="window.onPacketSearchChange(this.value)">

                <label style="display: flex; align-items: center; gap: 4px; font-size: 10px; color: var(--text-dim); cursor: pointer; user-select: none;">
                  <input type="checkbox" id="hideInternalEjiCheckbox" ${hideInternalEji ? 'checked' : ''} onchange="window.toggleHideInternalEji(this.checked)">
                  <span>Hide Loopback/8443</span>
                </label>

                <button id="freezeStreamBtn" class="btn btn-secondary" onclick="window.toggleFreezeStreamView()" style="font-size: 11px; padding: 4px 8px;">⏸ Freeze</button>
                <button id="toggleCaptureBtn" class="btn ${isCapturing ? 'btn-secondary' : 'btn-primary'}" onclick="window.toggleLiveCapture()" style="font-size: 11px; padding: 4px 8px;">
                  ${isCapturing ? '⏸ Pause' : '▶ Resume'}
                </button>
                <button class="btn btn-secondary" onclick="window.clearPacketBuffer()" style="font-size: 11px; padding: 4px 8px;">Clear</button>
                <button class="btn btn-secondary" onclick="window.downloadPcapExport()" style="font-size: 11px; padding: 4px 8px;" title="Export standard libpcap binary file">⬇ PCAP</button>
                <input type="file" id="pcapFileInput" style="display: none;" accept=".pcap,.cap" onchange="window.handlePcapFileChosen(this)">
                <button class="btn btn-secondary" onclick="window.triggerImportPcap()" style="font-size: 11px; padding: 4px 8px;" title="Import offline PCAP file">⬆ Import</button>
              </div>
            </div>

            <!-- BPF Capture Filter & Hardware Accounting Counters Bar -->
            <div style="background: rgba(15, 23, 42, 0.6); border-bottom: 1px solid var(--border-color); padding: 8px 16px;">
              <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 6px; flex-wrap: wrap;">
                <span style="font-weight: 700; font-size: 11px; color: var(--accent); white-space: nowrap;">⚡ Kernel BPF Capture Filter:</span>
                <input type="text" id="nocBpfInput" class="form-input" placeholder="e.g. tcp port 443 and host 10.22.12.204, icmp or arp" style="flex: 1; min-width: 180px; font-family: var(--font-mono); font-size: 11px; padding: 4px 8px;">
                <button class="btn btn-primary" onclick="window.applyNocBpfFilter()" style="font-size: 11px; padding: 4px 10px;">Apply BPF</button>
                <button class="btn btn-secondary" onclick="window.clearNocBpfFilter()" style="font-size: 11px; padding: 4px 8px;">Clear</button>
              </div>
              <div id="nocCountersBar" style="display: flex; gap: 14px; align-items: center; font-size: 11px; font-family: var(--font-mono); flex-wrap: wrap;">
                <span><b>Driver Received:</b> <span id="cntReceived" style="color: var(--accent); font-weight: 700;">0</span></span>
                <span><b>Accepted (BPF):</b> <span id="cntAccepted" style="color: var(--success); font-weight: 700;">0</span></span>
                <span><b>Dropped:</b> <span id="cntDropped" style="color: var(--danger); font-weight: 700;">0</span></span>
                <span><b>Decoded:</b> <span id="cntDecoded" style="color: #38bdf8; font-weight: 700;">0</span></span>
                <span><b>Delivered:</b> <span id="cntDelivered" style="color: #a78bfa; font-weight: 700;">0</span></span>
                <span style="margin-left: auto;">
                  <button class="btn btn-secondary" onclick="window.refreshNocCounters()" style="font-size: 10px; padding: 2px 6px;">↻ Counters</button>
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
    { level: 1, key: 'wan', label: 'L1: WAN TRANSIT & INTERNET', shortLabel: 'L1: WAN TRANSIT', color: '#8B5CF6', icon: '🌐' },
    { level: 2, key: 'edge', label: 'L2: EDGE ROUTER & PERIMETER', shortLabel: 'L2: EDGE ROUTER', color: '#3B82F6', icon: '🛡️' },
    { level: 3, key: 'core', label: 'L3: FIREWALL & CORE SWITCHING', shortLabel: 'L3: CORE BACKBONE', color: '#38BDF8', icon: '🔀' },
    { level: 4, key: 'service', label: 'L4: ENTERPRISE INFRASTRUCTURE', shortLabel: 'L4: ENTERPRISE SERVERS', color: '#34D399', icon: '🖥️' },
    { level: 5, key: 'access', label: 'L5: DISTRIBUTION & ACCESS FABRIC', shortLabel: 'L5: ACCESS FABRIC', color: '#FBBF24', icon: '📡' },
    { level: 6, key: 'endpoint', label: 'L6: OPERATOR WORKSTATION', shortLabel: 'L6: OPERATOR HOST', color: '#818CF8', icon: '💻' }
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
      if (fleetNodes.length > 0) {
        const clusterNode = {
          id: 'NODE-FLEET-CLUSTER',
          name: `Access Fleet [${fleetNodes.length} Hosts]`,
          hostname_or_ip: `10.168.195.0/24 (${fleetNodes.length} Hosts)`,
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
      }
    } else {
      // Expanded mode: Show discovered fleet devices
      layerBuckets[4].push(...fleetNodes);
    }

    // Layout configuration
    const colWidth = 230;
    const colGap = 25;
    const startX = 25;
    const cardW = 200;
    const cardH = 100;
    const cardGapY = 18;

    let maxNodesInCol = 1;
    for (const bucket of layerBuckets) {
      if (bucket.length > maxNodesInCol) maxNodesInCol = bucket.length;
    }

    const canvasWidth = startX + 6 * (colWidth + colGap);
    const canvasHeight = Math.max(300, 48 + maxNodesInCol * (cardH + cardGapY) + 20);

    // Position each node card
    const renderedNodes = [];
    for (let colIdx = 0; colIdx < 6; colIdx++) {
      const bucket = layerBuckets[colIdx];
      const colX = startX + colIdx * (colWidth + colGap);
      const cardX = colX + (colWidth - cardW) / 2;

      bucket.forEach((node, rowIdx) => {
        let cardY;
        if (bucket.length === 1) {
          cardY = Math.max(50, Math.round((canvasHeight - cardH) / 2));
        } else if (bucket.length === 2) {
          cardY = 48 + rowIdx * 115;
        } else {
          cardY = 48 + rowIdx * (cardH + cardGapY);
        }

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

    // Layer Headers & Divider Lines
    let layerHeadersSvg = '';
    let dividerLinesSvg = '';
    for (let i = 0; i < 6; i++) {
      const layer = TOPOLOGY_LAYERS[i];
      const colX = startX + i * (colWidth + colGap);
      const centerX = colX + colWidth / 2;
      const count = layerBuckets[i].length;
      layerHeadersSvg += `
        <text x="${centerX}" y="22" font-size="9.5" font-family="monospace" font-weight="700" fill="${layer.color}" text-anchor="middle">
          ${layer.shortLabel} <tspan fill="#64748B" font-size="8">(${count})</tspan>
        </text>
      `;
      if (i < 5) {
        const divX = colX + colWidth + colGap / 2;
        dividerLinesSvg += `
          <line x1="${divX}" y1="30" x2="${divX}" y2="${canvasHeight - 10}" stroke="rgba(255,255,255,0.06)" stroke-dasharray="3,3"/>
        `;
      }
    }

    // Generate Edge Connectors
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
        <path id="link-${edge.id}" d="${d}" stroke="${strokeColor}" stroke-width="2.5" class="${statusClass}" stroke-dasharray="${dashArray}" style="cursor: pointer;" oncontextmenu="window.handleLinkContextMenu(event, '${edge.id}', '${srcCoord.node.hostname_or_ip}', '${tgtCoord.node.hostname_or_ip}')"/>
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
          <path id="link-EDGE-LAN-CLUSTER" d="M ${x1} ${y1} L ${x2} ${y2}" stroke="#34D399" stroke-width="2.2" stroke-dasharray="4,4" class="link-smooth-green" style="cursor: pointer;"/>
        `;
      }
    }

    // Generate Node Cards
    let nodesSvg = '';
    for (const item of renderedNodes) {
      const n = item.node;
      const layer = TOPOLOGY_LAYERS[item.colIdx] || TOPOLOGY_LAYERS[4];
      const isHealthy = n.status === 'healthy';
      const roleIcon = getNodeRoleIcon(n);
      const badge = getNodeEvidenceBadge(n);
      const isCluster = n.id === 'NODE-FLEET-CLUSTER';

      let titleName = n.name || 'Device';
      if (titleName.length > 32) titleName = titleName.substring(0, 30) + '…';
      let vendorStr = n.vendor || 'Discovered Host';
      if (vendorStr.length > 28) vendorStr = vendorStr.substring(0, 26) + '…';

      const latencyStr = n.last_latency_ms !== null && n.last_latency_ms !== undefined
        ? `${n.last_latency_ms} ms RTT`
        : '<1 ms RTT';

      const clickHandler = isCluster
        ? 'window.onClusterNodeClick()'
        : `window.onNodeClick('${n.id}')`;

      const badgeW = badge.text.length * 6.5 + 10;

      nodesSvg += `
        <g id="svgNode-${n.id}" class="topology-svg-node" transform="translate(${item.x}, ${item.y})" style="cursor: pointer;" onclick="${clickHandler}" oncontextmenu="window.handleNodeContextMenu(event, '${n.id}', '${n.hostname_or_ip}')" onmouseenter="window.showTopologyTooltip(event, '${n.id}')" onmouseleave="window.hideTopologyTooltip()">
          <rect width="${item.width}" height="${item.height}" rx="8" fill="#0F1424" stroke="${isCluster ? '#34D399' : layer.color}" stroke-width="${isCluster ? '2' : '1.6'}" stroke-dasharray="${isCluster ? '5,3' : 'none'}" filter="url(#nodeGlow)"/>
          <circle cx="16" cy="19" r="4.5" fill="${isHealthy ? '#34D399' : '#EF4444'}"/>
          <text x="26" y="23" font-size="11">${roleIcon}</text>
          <text x="44" y="23" font-size="11" font-weight="700" fill="#E2E8F0">${titleName}</text>
          <text x="14" y="43" font-size="10" font-family="monospace" font-weight="700" fill="${isCluster ? '#34D399' : layer.color}">${n.hostname_or_ip}</text>
          <text x="14" y="59" font-size="9" fill="#94A3B8">${vendorStr}</text>
          <text x="14" y="73" font-size="9" fill="${isCluster ? '#FBBF24' : '#34D399'}">${isCluster ? '⚡ Click to Expand / View Table' : latencyStr}</text>
          <rect x="12" y="79" width="${badgeW}" height="15" rx="3" fill="${badge.bg}"/>
          <text x="${12 + badgeW / 2}" y="90" font-size="8" font-family="monospace" font-weight="700" fill="${badge.color}" text-anchor="middle">[${badge.text}]</text>
        </g>
      `;
    }

    return `
      <svg id="nocTopologySvg" viewBox="0 0 ${canvasWidth} ${canvasHeight}" style="width: 100%; min-width: 980px; height: 100%; min-height: 480px; display: block;" oncontextmenu="window.handleSvgContextMenu(event)">
        <defs>
          <linearGradient id="linkGradWan" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stop-color="#8B5CF6"/>
            <stop offset="100%" stop-color="#3B82F6"/>
          </linearGradient>
          <linearGradient id="flowGlowGrad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stop-color="#38BDF8"/>
            <stop offset="100%" stop-color="#F43F5E"/>
          </linearGradient>
          <filter id="nodeGlow" x="-20%" y="-20%" width="140%" height="140%">
            <feDropShadow dx="0" dy="2" stdDeviation="4" flood-color="#000" flood-opacity="0.6"/>
          </filter>
          <pattern id="nocGridPattern" width="40" height="40" patternUnits="userSpaceOnUse">
            <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(255, 255, 255, 0.025)" stroke-width="1"/>
          </pattern>
          <style>
            .flow-active-pulse { stroke-dasharray: 8, 8; animation: flowTrace 1.2s linear infinite; stroke: #38BDF8 !important; stroke-width: 3.5px !important; }
            @keyframes flowTrace { from { stroke-dashoffset: 32; } to { stroke-dashoffset: 0; } }
          </style>
        </defs>

        <!-- Subtle NOC Cyber Grid Background -->
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

  /**
   * Blast Radius Simulator Trigger
   * Calculates downstream failure propagation and visually marks severed paths
   */
  window.onNodeClick = async function(nodeId) {
    activeBlastRadiusNode = nodeId;
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
        banner.innerHTML = `
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
              <b style="color: ${res.criticality === 'CATASTROPHIC' ? '#ef4444' : '#f59e0b'};">[💥 BLAST RADIUS: ${res.criticality}]</b>
              <span>${res.simulationNotes}</span>
            </div>
            <button class="btn btn-secondary" onclick="window.clearBlastRadius()" style="font-size: 10px; padding: 2px 8px;">Dismiss</button>
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
    const menu = document.getElementById('nocContextMenu');
    if (menu) {
      menu.style.display = 'block';
      menu.style.left = `${e.pageX}px`;
      menu.style.top = `${e.pageY}px`;
    }
  };

  window.handleLinkContextMenu = function(e, linkId, ip1, ip2) {
    e.preventDefault();
    contextTarget = { type: 'link', id: linkId, ip1, ip2 };
    const menu = document.getElementById('nocContextMenu');
    if (menu) {
      menu.style.display = 'block';
      menu.style.left = `${e.pageX}px`;
      menu.style.top = `${e.pageY}px`;
    }
  };

  window.handleContextMenuAction = function(action) {
    const menu = document.getElementById('nocContextMenu');
    if (menu) menu.style.display = 'none';
    if (!contextTarget) return;

    if (action === 'sniff') {
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

  /**
   * Packet Rendering (Lower Pane)
   */
  function renderPacketRows() {
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
      filtered = filtered.filter(f => (f.protocol || '').toUpperCase() === protocolFilter);
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

    if (filtered.length === 0) {
      return `<tr><td colspan="9" style="text-align: center; color: var(--text-dim); padding: 30px;">Awaiting live wire frames from Npcap/Socket interceptor...</td></tr>`;
    }

    return filtered.slice(-60).reverse().map(f => {
      const isSelected = selectedFrame && selectedFrame.frameNumber === f.frameNumber;
      const timeStr = window.formatLocalTime ? window.formatLocalTime(f.timestamp) : f.timestamp;

      // Retransmission & TCP Delta flags
      let tcpDeltaBadge = '<span style="color: var(--text-dim); font-size: 10px;">NORMAL</span>';
      if (f.tcpAnalysis) {
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
      let hostDisplay = '<span style="color: var(--text-dim);">—</span>';
      let hostTitle = '';

      if (rawHost && !rawHost.includes('in-addr.arpa') && !rawHost.endsWith('.arpa') && !rawHost.match(/^\d+\.\d+\.\d+\.\d+(:\d+)?$/)) {
        const isPing = rawHost.startsWith('[PING]') || f.protocol === 'ICMP' || f.urlResolution?.method === 'ICMP-correlated';
        const cleanHost = rawHost.replace(/^\[PING\]\s*/, '').replace(/^https?:\/\//, '').replace(/\/.*$/, '');
        hostTitle = rawHost;
        let badgeHtml = '';
        if (isPing) {
          badgeHtml = '<span style="font-size: 8px; font-weight: 700; padding: 1px 4px; border-radius: 3px; background: rgba(168,85,247,0.25); color: #c084fc; margin-left: 4px;">[ICMP Ping]</span>';
          hostDisplay = `<span style="color: #c084fc; font-weight: 700;">${cleanHost}</span>${badgeHtml}`;
        } else {
          if (f.urlResolution?.method === 'SNI' || f.urlResolution?.source?.includes('SNI')) {
            badgeHtml = '<span style="font-size: 8px; font-weight: 700; padding: 1px 4px; border-radius: 3px; background: rgba(56,189,248,0.2); color: #38bdf8; margin-left: 4px;">[TLS SNI]</span>';
          } else if (f.urlResolution?.method === 'DNS-correlated' || f.urlResolution?.source?.includes('DNS')) {
            badgeHtml = '<span style="font-size: 8px; font-weight: 700; padding: 1px 4px; border-radius: 3px; background: rgba(52,211,153,0.2); color: #34d399; margin-left: 4px;">[DNS Correlated]</span>';
          } else if (f.urlResolution?.method === 'HTTP Host') {
            badgeHtml = '<span style="font-size: 8px; font-weight: 700; padding: 1px 4px; border-radius: 3px; background: rgba(245,158,11,0.2); color: #fbbf24; margin-left: 4px;">[HTTP]</span>';
          }
          hostDisplay = `<span>${cleanHost}</span>${badgeHtml}`;
        }
      }

      const lenVal = f.wireLength || f.capturedLength || f.length || 60;

      return `
        <tr onclick="window.inspectPacketFrame(${f.frameNumber})" style="cursor: pointer; background: ${isSelected ? 'rgba(56, 189, 248, 0.12)' : 'inherit'};">
          <td class="col-num" style="min-width: 65px; width: 65px; color: var(--text-dim); font-weight: 700; white-space: nowrap;">#${f.frameNumber}</td>
          <td class="col-time" style="min-width: 95px; width: 105px; color: var(--text-dim); white-space: nowrap;">${timeStr}</td>
          <td class="col-ip" style="min-width: 140px; width: 140px; white-space: nowrap;"><span style="font-weight: 600;">${f.srcIp || '0.0.0.0'}</span>${f.srcPort ? ':' + f.srcPort : ''}</td>
          <td class="col-ip" style="min-width: 140px; width: 140px; white-space: nowrap;"><span style="font-weight: 600;">${f.dstIp || '0.0.0.0'}</span>${f.dstPort ? ':' + f.dstPort : ''}</td>
          <td style="min-width: 140px; max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--accent); font-weight: 600;" title="${hostTitle}">${hostDisplay}</td>
          <td class="col-proto" style="min-width: 65px; width: 65px; white-space: nowrap;"><span style="font-weight: 700; color: #38bdf8;">${f.protocol}</span></td>
          <td class="col-len" style="min-width: 65px; width: 65px; color: var(--text-dim); white-space: nowrap;">${lenVal} B</td>
          <td class="col-delta" style="min-width: 110px; width: 110px; white-space: nowrap;">${tcpDeltaBadge}</td>
          <td style="min-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
            <span>${f.summary || f.info || ''}</span>
            <button class="btn btn-secondary" onclick="event.stopPropagation(); window.mapFlowToTopology('${f.srcIp}', '${f.dstIp}')" style="font-size: 9px; padding: 1px 5px; margin-left: 4px;" title="Map physical route on Topology Graph">🗺️ Route</button>
            ${f.tcpAnalysis?.streamId !== undefined ? `<button class="btn btn-secondary" onclick="event.stopPropagation(); window.followTcpStream(${f.tcpAnalysis.streamId})" style="font-size: 9px; padding: 1px 5px; margin-left: 2px;">💬 #${f.tcpAnalysis.streamId}</button>` : ''}
          </td>
        </tr>
      `;
    }).join('');
  }

  function renderFlowRows() {
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
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function buildProtocolTreeHtml(f) {
    const layers = f.detailedLayers || (f.dissection?.detailedLayers) || (Array.isArray(f.layers) ? f.layers : null);
    if (layers && Array.isArray(layers) && layers.length > 0) {
      return layers.map(layer => {
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

    return `
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
    selectedFrame = liveFrames.find(f => f.frameNumber === frameNumber);
    if (!selectedFrame) return;

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
    selectedFrame = null;
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
      window.compiledDisplayFilter = function(f) {
        const str = activeDisplayFilter.toLowerCase();
        // Check ip.addr
        const ipMatch = str.match(/ip\.addr\s*==\s*([0-9.]+)/);
        if (ipMatch) {
          const target = ipMatch[1];
          if (f.srcIp !== target && f.dstIp !== target) return false;
        }
        // Check tcp.port
        const portMatch = str.match(/tcp\.port\s*==\s*(\d+)/);
        if (portMatch) {
          const p = parseInt(portMatch[1], 10);
          if (f.srcPort !== p && f.dstPort !== p) return false;
        }
        // Check protocol presence
        if (str === 'tcp' && f.protocol !== 'TCP') return false;
        if (str === 'udp' && f.protocol !== 'UDP') return false;
        if (str === 'dns' && f.protocol !== 'DNS' && f.dstPort !== 53 && f.srcPort !== 53) return false;
        if (str === 'http' && f.protocol !== 'HTTP') return false;
        if (str === 'tls' && f.protocol !== 'TLS' && f.dstPort !== 443 && f.srcPort !== 443) return false;
        if (str === 'icmp' && !f.protocol?.includes('ICMP')) return false;
        if (str === 'arp' && f.protocol !== 'ARP') return false;

        // Check contains
        if (str.includes('contains')) {
          const q = str.split('contains')[1].replace(/["']/g, '').trim();
          const targetText = `${f.srcIp} ${f.dstIp} ${f.summary || ''} ${f.urlIntelligence?.value || ''}`.toLowerCase();
          if (!targetText.includes(q)) return false;
        }
        return true;
      };
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
    if (frameBatchQueue.length > 0) {
      while (frameBatchQueue.length > 0) liveFrames.push(frameBatchQueue.shift());
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
  }

  window.handleCaptureStatus = function(statusObj) {
    if (!statusObj) return;
    const indicator = document.getElementById('captureLiveIndicator');
    const label = document.getElementById('captureStatusLabel');
    if (!indicator || !label) return;

    const st = statusObj.status;
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
    } else if (st === 'NO_ADAPTER') {
      indicator.style.background = 'rgba(239, 68, 68, 0.18)';
      indicator.style.color = '#f87171';
      indicator.title = statusObj.message || 'No physical network interface found for packet sniffing.';
      label.textContent = 'NO ADAPTER';
    } else if (st === 'WAITING_FOR_TRAFFIC') {
      indicator.style.background = 'rgba(56, 189, 248, 0.18)';
      indicator.style.color = '#38bdf8';
      indicator.title = 'Adapter listening. Waiting for network frames.';
      label.textContent = 'IDLE (LISTENING)';
    }
  };

  window.handleLivePacketFrame = function(frame) {
    if (!isCapturing || !frame) return;
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

  window.switchNocSnifferMode = function(mode) {
    currentSnifferMode = mode;
    const btnP = document.getElementById('viewModePacketsBtn');
    const btnF = document.getElementById('viewModeFlowsBtn');
    const viewP = document.getElementById('livePacketTableView');
    const viewF = document.getElementById('nirsoftFlowMatrixView');

    if (btnP) btnP.className = mode === 'packets' ? 'btn btn-primary' : 'btn btn-secondary';
    if (btnF) btnF.className = mode === 'flows' ? 'btn btn-primary' : 'btn btn-secondary';
    if (viewP) viewP.style.display = mode === 'packets' ? 'flex' : 'none';
    if (viewF) viewF.style.display = mode === 'flows' ? 'flex' : 'none';
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
      </div>
      <div style="font-size: 9.5px; color: var(--text-dim); border-top: 1px solid rgba(255,255,255,0.05); padding-top: 4px;">
        Left-Click: Blast Radius Simulator | Right-Click: Context Menu
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
      const topoRes = await window.api('/api/network/topology');
      topologyData = topoRes || topologyData;
      const svgCont = document.getElementById('topologySvgContainer');
      if (svgCont) svgCont.innerHTML = renderTopologySvg();
      const tbody = document.getElementById('nocTopologyTableBody');
      if (tbody) tbody.innerHTML = renderTopologyTableRows();
      const btnScope = document.getElementById('topoFleetToggleBtn');
      if (btnScope) {
        btnScope.textContent = topoFleetExpanded ? '🛡️ Focus Infrastructure' : `🌐 Expand Fleet (${topologyData.nodes.length})`;
      }
    } catch (e) {}
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

  window.triggerImportPcap = function() {
    const fileIn = document.getElementById('pcapFileInput');
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
      if (elRecv) elRecv.textContent = c.received || 0;
      if (elAcc) elAcc.textContent = c.accepted || 0;
      if (elDrop) elDrop.textContent = c.dropped || 0;
      if (elDec) elDec.textContent = c.decoded || 0;
      if (elDel) elDel.textContent = c.delivered || 0;
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
  window.setNocLiveFrames = function(frames) { if (frames) liveFrames = frames; };
  window.setNocLiveFlows = function(flows) { if (flows) liveFlows = flows; };
  window.renderTopologySvg = renderTopologySvg;
  window.renderTopologyTableRows = renderTopologyTableRows;
  window.renderPacketRows = renderPacketRows;
  window.renderFlowRows = renderFlowRows;
  window.renderNocView = renderNocView;
})(window);
