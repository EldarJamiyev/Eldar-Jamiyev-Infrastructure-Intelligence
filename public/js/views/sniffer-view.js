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

  let currentInterfaces = [];
  let activeCaptureDevice = null;
  let isNlPanelOpen = false;

  async function renderPacketSnifferStandaloneView() {
    const container = document.getElementById('mainContent');
    if (!container) return;

    try {
      const routeGen = window.currentRouteGeneration;

      // Build interface options from cached if available
      const ifaceOptionsHtml = (currentInterfaces || []).map(i => {
        const isSelected = activeCaptureDevice ? (activeCaptureDevice === i.name) : Boolean(i.isDefault);
        const label = i.ip ? `${i.description} [${i.ip}]` : i.description;
        return `<option value="${escapeAttr(i.name)}" ${isSelected ? 'selected' : ''}>${escapeHtml(label)}</option>`;
      }).join('');

      container.innerHTML = `
        <div class="sniffer-standalone-workstation" style="display: flex; flex-direction: column; height: calc(100vh - 80px); gap: 10px;">
          <!-- Autonomous AI Diagnostic Brain Live Drawer -->
          <div id="snifferAiBrainDrawerContainer" class="ai-brain-drawer-mount" style="flex-shrink: 0;"></div>

          <div class="card" style="margin: 0; display: flex; flex-direction: column; flex: 1; overflow: hidden; border: 1px solid var(--border-default); background: var(--bg-surface); box-shadow: var(--shadow-sm);">
            <!-- Header Stream & Profile Bar -->
            <div class="card-header" style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; padding: 10px 18px; border-bottom: 1px solid var(--border-default); background: var(--bg-surface); flex-shrink: 0;">
              <div style="display: flex; align-items: center; gap: 10px;">
                <div style="width: 32px; height: 32px; border-radius: 6px; background: #EFF6FF; color: var(--accent-primary); display: flex; align-items: center; justify-content: center; font-size: 16px;">🦈</div>
                <div>
                  <div class="card-title" style="margin: 0; font-size: 14px; font-weight: 700; letter-spacing: -0.01em; color: var(--text-primary);">
                    Wireshark-Grade Live Packet Sniffer &amp; Stream Dissector
                  </div>
                  <div style="font-size: 11px; color: var(--text-secondary); font-family: var(--font-mono);">
                    Physical Npcap Wire Driver &bull; L2-L7 RFC Binary Tree &bull; TCP Stream Delta &amp; Retransmission Engine
                  </div>
                </div>
                <span id="captureLiveIndicator" style="display: inline-flex; align-items: center; gap: 5px; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 12px; background: #ECFDF5; border: 1px solid #A7F3D0; color: #059669; margin-left: 8px;">
                  <span class="status-dot" style="background: #059669;"></span>
                  <span id="captureStatusLabel">STREAMING</span>
                </span>
                <span id="packetFilterCounterBadge" style="display: inline-flex; align-items: center; gap: 4px; font-size: 11px; font-weight: 600; padding: 2px 9px; border-radius: 12px; background: #EFF6FF; border: 1px solid #BFDBFE; color: #1D4ED8; font-family: var(--font-mono); margin-left: 8px;">
                  Visible: 0 frames | Hidden: 0
                </span>
              </div>

              <!-- Stream Controls & Hardware Interface Selector -->
              <div style="display: flex; align-items: center; gap: 6px; flex-wrap: wrap;">
                <!-- Physical Network Interface Selector -->
                <div style="display: flex; align-items: center; gap: 4px; background: var(--bg-surface-subtle); border: 1px solid var(--border-default); border-radius: 6px; padding: 3px 8px;">
                  <span style="font-size: 11px; font-family: var(--font-mono); color: var(--text-primary); font-weight: 700;">📡 NIC:</span>
                  <select id="captureInterfaceSelect" class="form-input" style="max-width: 210px; font-size: 11px; padding: 2px 6px; font-family: var(--font-mono); border: none; background: transparent; color: var(--text-primary);" onchange="window.onCaptureInterfaceChange(this.value)">
                    ${ifaceOptionsHtml || '<option value="">Default Physical NIC</option>'}
                  </select>
                </div>

                <div class="segmented-control" style="display: inline-flex; gap: 2px; background: var(--bg-surface-subtle); padding: 2px; border-radius: 6px; border: 1px solid var(--border-default); flex-wrap: wrap;">
                  <button id="viewModeImportantBtn" class="btn btn-primary" onclick="window.switchNocSnifferMode('important')" style="font-size: 11px; padding: 3px 8px; font-weight: 600; border-radius: 4px;" title="Handshakes, HTTP, DNS, TLS SNI, Anomaly Frames">Important</button>
                  <button id="viewModeFlowsBtn" class="btn btn-secondary" onclick="window.switchNocSnifferMode('flows')" style="font-size: 11px; padding: 3px 8px; font-weight: 600; border-radius: 4px; border: none; background: transparent;" title="Bi-directional Conversations & Flow Matrix">Conversations</button>
                  <button id="viewModeFinderBtn" class="btn btn-secondary" onclick="window.switchNocSnifferMode('finder')" style="font-size: 11px; padding: 3px 8px; font-weight: 600; border-radius: 4px; border: none; background: transparent; color: #0284C7;" title="App Server & Port Finder (Correlate Process to Remote Server)">App Finder</button>
                  <button id="viewModeFailuresBtn" class="btn btn-secondary" onclick="window.switchNocSnifferMode('failures')" style="font-size: 11px; padding: 3px 8px; font-weight: 600; border-radius: 4px; border: none; background: transparent; color: #DC2626;" title="TCP RST, Retransmissions, Zero-Window, ICMP Unreachable">Failures Only</button>
                  <button id="viewModePacketsBtn" class="btn btn-secondary" onclick="window.switchNocSnifferMode('packets')" style="font-size: 11px; padding: 3px 8px; font-weight: 600; border-radius: 4px; border: none; background: transparent;" title="All Unfiltered Raw Packets">All Packets</button>
                </div>

                <select id="packetProtocolFilter" class="form-input" style="width: 95px; padding: 4px 6px; font-size: 11px; border-radius: 6px;" onchange="window.onPacketProtocolFilterChange(this.value)">
                  <option value="ALL">All Proto</option>
                  <option value="TCP">TCP</option>
                  <option value="UDP">UDP</option>
                  <option value="DNS">DNS</option>
                  <option value="HTTP">HTTP</option>
                  <option value="TLS">TLS</option>
                  <option value="QUIC">QUIC</option>
                  <option value="ICMP">ICMP</option>
                  <option value="ARP">ARP</option>
                  <option value="DHCP">DHCP</option>
                  <option value="MDNS">mDNS</option>
                </select>

                <input type="text" id="packetSearchInput" class="form-input" placeholder="Search IP, port, host..." style="width: 140px; padding: 4px 8px; font-size: 11px; border-radius: 6px;" oninput="window.onPacketSearchChange(this.value)">

                <label style="display: flex; align-items: center; gap: 4px; font-size: 11px; color: var(--text-secondary); cursor: pointer; user-select: none;">
                  <input type="checkbox" id="hideInternalEjiCheckbox" checked onchange="window.toggleHideInternalEji(this.checked)">
                  <span>Hide 8443</span>
                </label>

                <button id="freezeStreamBtn" class="btn btn-secondary" onclick="window.toggleFreezeStreamView()" style="font-size: 11px; padding: 4px 8px; border-radius: 6px;">⏸ Freeze</button>
                <button id="toggleCaptureBtn" class="btn btn-secondary" onclick="window.toggleLiveCapture()" style="font-size: 11px; padding: 4px 8px; border-radius: 6px;">⏸ Pause</button>
                <button class="btn btn-secondary" onclick="window.clearPacketBuffer()" style="font-size: 11px; padding: 4px 8px; border-radius: 6px;">Clear</button>

                <!-- Dedicated Direct PCAP & PCAPNG I/O Controls -->
                <button class="btn btn-secondary" onclick="window.downloadPcapExport()" style="font-size: 11px; padding: 4px 8px; font-weight: 600; color: var(--accent-primary); border-radius: 6px;" title="Export standard libpcap binary file for Wireshark">⬇ PCAP</button>
                <button class="btn btn-secondary exec-btn-secondary" onclick="window.downloadPcapngExport()" style="font-size: 11px; padding: 4px 8px; font-weight: 700; color: var(--accent-primary); border-radius: 6px;" title="Export standard IETF PCAPNG binary file with embedded JA4 & STL options for Wireshark">⬇ PCAPNG</button>
                <input type="file" id="pcapFileInput" style="display: none;" accept=".pcap,.cap" onchange="window.handlePcapFileChosen(this)">
                <input type="file" id="pcapngFileInput" style="display: none;" accept=".pcapng" onchange="window.handlePcapngFileChosen(this)">
                <button class="btn btn-secondary" onclick="window.triggerImportPcap()" style="font-size: 11px; padding: 4px 8px; font-weight: 600; color: #7C3AED; border-radius: 6px;" title="Import offline PCAP file for forensic dissection">⬆ Import</button>
                <button class="btn btn-secondary exec-btn-secondary" onclick="window.triggerImportPcapng()" style="font-size: 11px; padding: 4px 8px; font-weight: 700; color: #7C3AED; border-radius: 6px;" title="Import offline PCAPNG file for forensic dissection and replay">⬆ Replay PCAPNG</button>

                <!-- Inspector Drawer Toggle -->
                <button class="btn btn-secondary" onclick="window.togglePacketInspectorDrawer()" style="font-size: 11px; padding: 4px 8px; border-radius: 6px;" title="Toggle 3-Pane Inspection Drawer">◫ Inspector</button>
                <button class="btn btn-secondary" onclick="window.openWireDiagnosticsModal()" style="font-size: 11px; padding: 4px 8px; border-radius: 6px;" title="Open Wire Diagnostics Hub">Tools</button>
              </div>
            </div>

            <!-- BPF Capture Filter & Hardware Accounting Counters Bar -->
            <div style="background: var(--bg-surface-subtle); border-bottom: 1px solid var(--border-default); padding: 6px 18px; flex-shrink: 0;">
              <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 4px; flex-wrap: wrap;">
                <span style="font-weight: 700; font-size: 11px; color: var(--accent-primary); white-space: nowrap; font-family: var(--font-mono);">⚡ Kernel BPF Filter:</span>
                <input type="text" id="nocBpfInput" class="form-input" placeholder="e.g. tcp port 443 and host 192.168.31.89, icmp or arp" style="flex: 1; min-width: 200px; font-family: var(--font-mono); font-size: 11px; padding: 3px 8px; border-radius: 6px;">
                <button class="btn btn-primary" onclick="window.applyNocBpfFilter()" style="font-size: 11px; padding: 3px 10px; font-weight: 700; border-radius: 6px;">Apply BPF</button>
                <button class="btn btn-secondary" onclick="window.clearNocBpfFilter()" style="font-size: 11px; padding: 3px 8px; border-radius: 6px;">Clear</button>
              </div>
              <div id="nocCountersBar" style="display: flex; gap: 14px; align-items: center; font-size: 10px; font-family: var(--font-mono); flex-wrap: wrap; color: var(--text-secondary);">
                <span><b>Driver Received:</b> <span id="cntReceived" style="color: var(--accent-primary); font-weight: 700;">0</span></span>
                <span><b>Accepted (BPF):</b> <span id="cntAccepted" style="color: var(--status-nominal); font-weight: 700;">0</span></span>
                <span><b>Dropped:</b> <span id="cntDropped" style="color: var(--status-critical); font-weight: 700;">0</span></span>
                <span><b>Decoded:</b> <span id="cntDecoded" style="color: #0284C7; font-weight: 700;">0</span></span>
                <span><b>Delivered:</b> <span id="cntDelivered" style="color: #7C3AED; font-weight: 700;">0</span></span>
                <span style="margin-left: auto;">
                  <button class="btn btn-secondary" onclick="window.refreshNocCounters()" style="font-size: 10px; padding: 1px 6px; border-radius: 4px;">↻ Counters</button>
                </span>
              </div>
            </div>

            <!-- Dynamic Wireshark Display Filter Bar (AST Evaluator) + AI Assistant -->
            <div style="background: var(--bg-surface); border-bottom: 1px solid var(--border-default); padding: 6px 18px; flex-shrink: 0;">
              <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
                <span style="font-weight: 700; font-size: 11px; color: var(--text-primary); white-space: nowrap; font-family: var(--font-mono);">🔍 Display Filter (Wireshark AST):</span>
                <div style="position: relative; flex: 1; min-width: 240px; display: flex; align-items: center;">
                  <input type="text" id="displayFilterInput" class="form-input"
                         placeholder='e.g. ip.addr == 192.168.31.1 && tcp.port == 443, !tcp.flags.syn, dns, http.response.code >= 400'
                         style="width: 100%; font-family: var(--font-mono); font-size: 11px; padding: 4px 10px; padding-right: 170px; transition: border-color 0.2s, background-color 0.2s;"
                         oninput="window.onDisplayFilterInput(this.value)"
                         onkeydown="if(event.key === 'Enter') window.applyDisplayFilter()">
                  <span id="displayFilterValidationBadge" style="position: absolute; right: 10px; font-size: 10px; font-family: var(--font-mono); font-weight: 700; pointer-events: none; color: var(--text-dim);"></span>
                </div>
                <button class="btn btn-primary" onclick="window.applyDisplayFilter()" style="font-size: 11px; padding: 4px 12px; font-weight: 700;">Apply Filter</button>
                <button class="btn btn-secondary" onclick="window.clearDisplayFilter()" style="font-size: 11px; padding: 4px 8px;">Clear</button>

                <!-- Natural Language AI Filter Toggle -->
                <button id="btnToggleNlFilter" class="btn btn-secondary" onclick="window.toggleNlFilterPanel()" style="font-size: 11px; padding: 4px 10px; font-weight: 700; color: #A78BFA; border-color: rgba(167, 139, 250, 0.4);" title="Ask AI Brain to build Wireshark filter from plain English">AI Filter</button>
              </div>

              <!-- AI Natural Language Query Assistant Panel -->
              <div id="nlFilterAssistantPanel" style="display: none; margin-top: 8px; padding-top: 8px; border-top: 1px dashed rgba(255, 255, 255, 0.1);">
                <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 6px;">
                  <span style="font-size: 11px; color: #A78BFA; font-weight: 700; font-family: var(--font-mono);">💬 Plain English Query:</span>
                  <input type="text" id="nlFilterQueryInput" class="form-input"
                         placeholder="e.g. 'show tcp resets to 192.168.31.1', 'quic traffic', 'retransmissions', 'tls handshakes', 'http 404 errors'"
                         style="flex: 1; font-size: 11px; padding: 3px 8px; font-family: var(--font-mono);"
                         onkeydown="if(event.key === 'Enter') window.compileNlFilter(this.value)">
                  <button class="btn btn-primary" onclick="window.compileNlFilter(document.getElementById('nlFilterQueryInput').value)" style="font-size: 11px; padding: 3px 12px; font-weight: 700; background: #8B5CF6; border-color: #7C3AED;">Translate to AST</button>
                </div>
                <!-- Quick Suggestion Chips -->
                <div style="display: flex; gap: 6px; flex-wrap: wrap; align-items: center;">
                  <span style="font-size: 10px; color: var(--text-dim);">Quick Filters:</span>
                  <button class="btn btn-secondary" onclick="window.compileNlFilter('show all tcp resets')" style="font-size: 10px; padding: 1px 6px;">TCP Resets (RST)</button>
                  <button class="btn btn-secondary" onclick="window.compileNlFilter('retransmissions')" style="font-size: 10px; padding: 1px 6px;">Retransmissions</button>
                  <button class="btn btn-secondary" onclick="window.compileNlFilter('keep alive packets')" style="font-size: 10px; padding: 1px 6px;">Keep-Alives (RFC 1122)</button>
                  <button class="btn btn-secondary" onclick="window.compileNlFilter('tls client hello')" style="font-size: 10px; padding: 1px 6px;">TLS Handshakes</button>
                  <button class="btn btn-secondary" onclick="window.compileNlFilter('dns queries')" style="font-size: 10px; padding: 1px 6px;">DNS Queries</button>
                  <button class="btn btn-secondary" onclick="window.compileNlFilter('http errors 400 or higher')" style="font-size: 10px; padding: 1px 6px;">HTTP Errors</button>
                  <button class="btn btn-secondary" onclick="window.compileNlFilter('zero window')" style="font-size: 10px; padding: 1px 6px;">Zero Window</button>
                  <button class="btn btn-secondary" onclick="window.compileNlFilter('quic traffic')" style="font-size: 10px; padding: 1px 6px;">QUIC / HTTP/3</button>
                  <span id="nlFilterExplanation" style="margin-left: 8px; font-size: 10px; color: #34D399; font-style: italic;"></span>
                </div>
              </div>
            </div>

            <!-- Explicit Capture Failure Banner -->
            <div id="captureErrorBanner" style="display: none; background: rgba(239, 68, 68, 0.15); border-bottom: 1px solid rgba(239, 68, 68, 0.4); padding: 8px 18px; color: #f87171; font-size: 11px; font-family: var(--font-mono); align-items: center; gap: 8px; flex-shrink: 0;">
              <span style="font-weight: 800;">⚠️ CAPTURE FAULT:</span>
              <span id="captureErrorMessage">Npcap wire interceptor offline.</span>
            </div>

            <!-- Live Application Endpoint Watcher Strip -->
            <div id="appFinderWatcherStrip" style="display: none; background: rgba(56, 189, 248, 0.08); border-bottom: 1px solid rgba(56, 189, 248, 0.25); padding: 8px 18px; font-size: 11px; font-family: var(--font-mono); color: #f8fafc; align-items: center; justify-content: space-between; gap: 12px; flex-shrink: 0;"></div>

            <!-- View 1: Live Frame Summary Table -->
            <div id="livePacketTableView" style="display: flex; flex: 1; overflow: hidden; flex-direction: column;">
              <div id="livePacketTableContainer" class="table-container" style="flex: 1; overflow-x: auto; overflow-y: auto; scrollbar-gutter: stable;" onmouseenter="window.onPacketTableMouseEnter()" onmouseleave="window.onPacketTableMouseLeave()">
                <table class="data-table" style="font-family: var(--font-mono); font-size: 11px; width: 100%;">
                  <thead>
                    <tr>
                      <th class="col-num" style="min-width: 75px; width: 75px; white-space: nowrap;">#</th>
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
                    ${window.renderPacketRows ? window.renderPacketRows() : ''}
                  </tbody>
                </table>
              </div>
            </div>

            <!-- View 2: NirSoft Flow Matrix Table -->
            <div id="nirsoftFlowMatrixView" style="display: none; flex: 1; overflow: hidden; flex-direction: column;">
              <div id="nirsoftFlowTableContainer" class="table-container" style="flex: 1; overflow-x: auto; overflow-y: auto; scrollbar-gutter: stable;">
                <table class="data-table" style="font-family: var(--font-mono); font-size: 11px; width: 100%;">
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
                    ${window.renderFlowRows ? window.renderFlowRows() : ''}
                  </tbody>
                </table>
              </div>
            </div>

            <!-- View 3: App Server & Port Finder View -->
            <div id="appServerFinderView" style="display: none; flex: 1; overflow: hidden; flex-direction: column;">
              <div style="background: rgba(15, 23, 42, 0.7); border-bottom: 1px solid var(--border-color); padding: 8px 18px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; flex-shrink: 0;">
                <div style="display: flex; align-items: center; gap: 8px;">
                  <span style="font-weight: 700; font-size: 12px; color: #38bdf8; font-family: var(--font-mono);">🖥️ Process Sockets &amp; Remote Server Endpoints</span>
                  <span id="finderEndpointCountBadge" style="font-size: 10px; font-weight: 700; padding: 2px 6px; border-radius: 10px; background: rgba(56, 189, 248, 0.2); color: #38bdf8;">0 Endpoints</span>
                </div>
                <div style="display: flex; gap: 8px; align-items: center;">
                  <input type="text" id="finderSearchInput" class="form-input" placeholder="Filter process (e.g. chrome, node, sql)..." style="font-size: 11px; padding: 3px 8px; width: 220px;" oninput="window.filterAppFinder(this.value)">
                  <label style="display: flex; align-items: center; gap: 4px; font-size: 11px; color: var(--text-dim); cursor: pointer; user-select: none;">
                    <input type="checkbox" id="finderExternalOnlyCheckbox" checked onchange="window.reloadAppFinder()">
                    <span>External Only</span>
                  </label>
                  <button class="btn btn-secondary" onclick="window.reloadAppFinder()" style="font-size: 11px; padding: 3px 8px;">↻ Refresh</button>
                </div>
              </div>
              <div id="appFinderSubWatcherStrip" style="display: none; background: rgba(56, 189, 248, 0.08); border-bottom: 1px solid rgba(56, 189, 248, 0.25); padding: 8px 18px; font-size: 11px; font-family: var(--font-mono); color: #f8fafc; align-items: center; justify-content: space-between; gap: 12px; flex-shrink: 0;"></div>
              <div class="table-container" style="flex: 1; overflow-x: auto; overflow-y: auto;">
                <table class="data-table" style="font-family: var(--font-mono); font-size: 11px; width: 100%;">
                  <thead>
                    <tr>
                      <th style="width: 70px;">PID</th>
                      <th style="min-width: 140px;">Process Name</th>
                      <th style="width: 80px;">Local Port</th>
                      <th style="min-width: 140px;">Remote Server IP</th>
                      <th style="width: 90px;">Remote Port</th>
                      <th style="min-width: 160px;">Domain / TLS SNI</th>
                      <th style="min-width: 140px;">Detected Service</th>
                      <th style="width: 110px;">TCP State</th>
                      <th style="min-width: 160px; text-align: center;">1-Click Action</th>
                    </tr>
                  </thead>
                  <tbody id="appServerFinderTableBody">
                    <tr><td colspan="9" style="text-align: center; padding: 30px; color: var(--text-muted);">Querying active process sockets...</td></tr>
                  </tbody>
                </table>
              </div>
            </div>

            <!-- LOWER 3-PANE DEEP PACKET INSPECTION (DPI) DRAWER -->
            <div id="packetDetailsPane" style="display: none; height: 280px; min-height: 180px; max-height: 440px; border-top: 1px solid var(--border-default); background: var(--bg-surface); flex-direction: column; flex-shrink: 0;">
              <div style="background: var(--bg-surface-subtle); padding: 6px 16px; border-bottom: 1px solid var(--border-default); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 6px;">
                <span id="dpiSummaryHeader" style="font-weight: 700; font-size: 11px; color: var(--text-primary); font-family: var(--font-mono);">
                  🔍 3-Pane Deep Packet Inspector (Frame Summary &bull; RFC Protocol Tree &bull; Synchronized Hex/ASCII)
                </span>
                <div style="display: flex; gap: 6px; align-items: center;">
                  <!-- AI Frame Explainer Button -->
                  <button id="btnAiExplainPacket" class="btn btn-primary" onclick="window.aiExplainCurrentPacket()" style="font-size: 11px; padding: 3px 10px; font-weight: 700; border-radius: 4px;">🧠 Explain with AI</button>
                  <button id="followStreamBtn" class="btn btn-secondary" onclick="window.followTcpStream()" style="font-size: 10px; padding: 3px 8px; border-radius: 4px; display: none;">🌊 Follow Stream</button>
                  <button class="btn btn-secondary" onclick="window.closePacketDetails()" style="font-size: 10px; padding: 3px 8px; border-radius: 4px;">✕ Close</button>
                </div>
              </div>

              <div style="display: grid; grid-template-columns: 1fr 1fr; flex: 1; overflow: hidden;">
                <!-- Pane 2: RFC Protocol Dissection Tree -->
                <div id="protocolTreePane" style="border-right: 1px solid var(--border-default); background: var(--bg-surface); overflow-y: auto; padding: 10px 14px; font-family: var(--font-mono); font-size: 11px; scrollbar-gutter: stable; color: var(--text-primary);">
                  <div style="color: var(--text-muted); padding: 12px; text-align: center;">Select a frame from the packet table to inspect its RFC protocol decode tree.</div>
                </div>

                <!-- Pane 3: Hexdump & ASCII Synchronized Inspector -->
                <div id="hexDumpPane" style="overflow-y: auto; padding: 10px 14px; font-family: var(--font-mono); font-size: 11px; background: var(--bg-terminal, #0F172A); border-left: 1px solid var(--border-terminal, #334155); color: #E2E8F0; scrollbar-gutter: stable;">
                  <div style="color: #94A3B8; padding: 12px; text-align: center;">Raw payload bytes will be dissected here in synchronized Hex &amp; ASCII format.</div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- AI Deep Forensic Packet Explainer Modal Container -->
        <div id="packetAiExplainerModalContainer"></div>
      `;

      // Mount Autonomous Virtual Packet Cockpit (Sovereign Apex)
      if (typeof window.VirtualPacketCockpit !== 'undefined') {
        window.snifferVirtualCockpit = new window.VirtualPacketCockpit({
          tableViewportEl: document.getElementById('livePacketTableContainer'),
          treePaneEl: document.getElementById('protocolTreePane'),
          hexPaneEl: document.getElementById('hexDumpPane'),
          statusBadgeEl: document.getElementById('freezeStreamBtn')
        });
      }

      if (typeof window.startPacketBatchFlusher === 'function') {
        window.startPacketBatchFlusher();
      } else if (typeof window.startNocBatchFlusher === 'function') {
        window.startNocBatchFlusher();
      }

      if (typeof window.flushPacketBatch === 'function') {
        window.flushPacketBatch();
      }

      // Mount AI Brain Drawer immediately
      if (typeof window.initAiBrainDrawer === 'function') {
        window.initAiBrainDrawer('snifferAiBrainDrawerContainer');
      }

      if (typeof window.refreshNocCounters === 'function') {
        window.refreshNocCounters();
      }

      // Stale-While-Revalidate background hydration (0ms blocking delay)
      Promise.all([
        window.api('/api/network/capture/status').catch(() => ({ active: true })),
        window.api('/api/network/capture/frames?limit=100').catch(() => ({ frames: [] })),
        window.api('/api/network/capture/flows?limit=100').catch(() => ({ flows: [] })),
        window.api('/api/network/capture/interfaces').catch(() => ({ interfaces: [], activeDevice: null }))
      ]).then(([statusRes, framesRes, flowsRes, ifaceRes]) => {
        if (window.currentRouteGeneration !== routeGen) return;

        if (framesRes?.frames && typeof window.setNocLiveFrames === 'function') {
          window.setNocLiveFrames(framesRes.frames);
          if (typeof window.VirtualPacketCockpit !== 'undefined') {
            if (!window.snifferVirtualCockpit) {
              window.snifferVirtualCockpit = new window.VirtualPacketCockpit({
                tableViewportEl: document.getElementById('livePacketTableContainer'),
                treePaneEl: document.getElementById('protocolTreePane'),
                hexPaneEl: document.getElementById('hexDumpPane'),
                statusBadgeEl: document.getElementById('autoScrollToggleBtn')
              });
            }
            window.snifferVirtualCockpit.ingestWireBatch(framesRes.frames);
          }
          const tbody = document.getElementById('livePacketTableBody');
          if (tbody && typeof window.renderPacketRows === 'function') {
            tbody.innerHTML = window.renderPacketRows();
          }
        }
        if (flowsRes?.flows && typeof window.setNocLiveFlows === 'function') {
          window.setNocLiveFlows(flowsRes.flows);
          const flowBody = document.getElementById('nirsoftFlowTableBody');
          if (flowBody && typeof window.renderFlowRows === 'function') {
            flowBody.innerHTML = window.renderFlowRows();
          }
        }

        currentInterfaces = ifaceRes?.interfaces || [];
        activeCaptureDevice = ifaceRes?.activeDevice || null;

        const ifaceSelect = document.getElementById('captureInterfaceSelect');
        if (ifaceSelect && currentInterfaces.length > 0) {
          ifaceSelect.innerHTML = currentInterfaces.map(i => {
            const isSelected = activeCaptureDevice ? (activeCaptureDevice === i.name) : Boolean(i.isDefault);
            const label = i.ip ? `${i.description} [${i.ip}]` : i.description;
            return `<option value="${escapeAttr(i.name)}" ${isSelected ? 'selected' : ''}>${escapeHtml(label)}</option>`;
          }).join('');
        }

        if (statusRes && typeof window.handleCaptureStatus === 'function') {
          window.handleCaptureStatus(statusRes);
        }

        const frames = (framesRes?.frames && framesRes.frames.length > 0) ? framesRes.frames : (window.getNocLiveFrames ? window.getNocLiveFrames() : []);
        if (frames.length > 0 && typeof window.inspectPacketFrame === 'function') {
          const targetFrame = frames[frames.length - 1];
          if (targetFrame && targetFrame.frameNumber) {
            window.inspectPacketFrame(targetFrame.frameNumber);
          }
        }
      }).catch(e => {
        console.warn('[Sniffer Background Hydration Warning]:', e.message);
      });
    } catch (err) {
      console.error('[SNIFFER-VIEW-LOAD-ERROR]', err);
      container.innerHTML = `<div class="card" style="color: var(--danger); padding: 24px;">Failed to load Live Packet Sniffer: ${escapeHtml(err.message)}<pre style="margin-top: 10px; font-size: 11px; color: var(--text-muted); white-space: pre-wrap;">${escapeHtml(err.stack || '')}</pre></div>`;
    }
  }

  // ---------------------------------------------------------------------------
  // Interface Switching Controller
  // ---------------------------------------------------------------------------
  window.onCaptureInterfaceChange = async function(deviceName) {
    if (!deviceName) return;
    try {
      const res = await window.api('/api/network/capture/interface', {
        method: 'POST',
        body: JSON.stringify({ device: deviceName })
      });
      activeCaptureDevice = deviceName;
      if (typeof window.showToast === 'function') {
        window.showToast(`Active capture bound to: ${deviceName}`);
      }
    } catch (err) {
      alert(`Failed to switch capture interface: ${err.message}`);
    }
  };

  // ---------------------------------------------------------------------------
  // Natural Language Filter Controller
  // ---------------------------------------------------------------------------
  window.toggleNlFilterPanel = function() {
    const panel = document.getElementById('nlFilterAssistantPanel');
    if (!panel) return;
    isNlPanelOpen = !isNlPanelOpen;
    panel.style.display = isNlPanelOpen ? 'block' : 'none';
    const btn = document.getElementById('btnToggleNlFilter');
    if (btn) {
      btn.style.background = isNlPanelOpen ? 'rgba(167, 139, 250, 0.2)' : '';
    }
    if (isNlPanelOpen) {
      const input = document.getElementById('nlFilterQueryInput');
      if (input) input.focus();
    }
  };

  window.compileNlFilter = async function(query) {
    const q = (query || '').trim();
    if (!q) return;

    const explEl = document.getElementById('nlFilterExplanation');
    if (explEl) explEl.textContent = 'Translating query with AI Brain...';

    try {
      const res = await window.api('/api/network/tools/nl-filter', {
        method: 'POST',
        body: JSON.stringify({ query: q })
      });

      if (res && res.filter) {
        const filterInput = document.getElementById('displayFilterInput');
        if (filterInput) {
          filterInput.value = res.filter;
          if (typeof window.onDisplayFilterInput === 'function') {
            window.onDisplayFilterInput(res.filter);
          }
          if (typeof window.applyDisplayFilter === 'function') {
            window.applyDisplayFilter();
          }
        }
        if (explEl) {
          explEl.textContent = `✓ Generated: ${res.filter} (${res.explanation})`;
        }
      }
    } catch (err) {
      if (explEl) explEl.textContent = `Error: ${err.message}`;
    }
  };

  // ---------------------------------------------------------------------------
  // AI Packet Explainer Modal Controller
  // ---------------------------------------------------------------------------
  window.aiExplainCurrentPacket = async function() {
    const selected = window.getSelectedPacket ? window.getSelectedPacket() : null;
    if (!selected) {
      alert('Please select a packet from the table first to generate an AI explanation.');
      return;
    }

    const modalHost = document.getElementById('packetAiExplainerModalContainer');
    if (!modalHost) return;

    modalHost.innerHTML = `
      <div class="modal-backdrop" onclick="window.closeAiPacketExplainerModal(event)" style="position: fixed; inset: 0; background: rgba(0,0,0,0.75); display: flex; align-items: center; justify-content: center; z-index: 2000;">
        <div class="modal-card" style="background: #0B1120; border: 1px solid var(--border-color); border-radius: 8px; width: 90%; max-width: 820px; max-height: 85vh; overflow-y: auto; padding: 20px; box-shadow: 0 16px 36px rgba(0,0,0,0.8);" onclick="event.stopPropagation()">
          <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 12px; margin-bottom: 16px;">
            <div style="display: flex; align-items: center; gap: 8px;">
              <span style="font-size: 24px;">🧠</span>
              <div>
                <h3 style="margin: 0; font-size: 16px; font-weight: 800; color: var(--accent);">
                  AI Forensic Analysis — Frame #${selected.frameNumber} [${selected.protocol}]
                </h3>
                <span style="font-size: 11px; color: var(--text-dim); font-family: var(--font-mono);">
                  RFC Standards &bull; Bayesian Anomaly Classifier &bull; Wire Protocol Analysis
                </span>
              </div>
            </div>
            <button class="btn btn-secondary" onclick="window.closeAiPacketExplainerModal()" style="font-size: 12px; padding: 2px 8px;">✕</button>
          </div>
          <div id="packetAiExplainerBody" style="display: flex; align-items: center; justify-content: center; height: 180px;">
            <span style="color: var(--accent); font-family: var(--font-mono);">Synthesizing protocol telemetry with AI Brain...</span>
          </div>
        </div>
      </div>
    `;

    try {
      const report = await window.api('/api/network/tools/packet-explain', {
        method: 'POST',
        body: JSON.stringify({ frameNumber: selected.frameNumber, frame: selected })
      });

      const body = document.getElementById('packetAiExplainerBody');
      if (!body) return;

      const sevColor = report.severity === 'CRITICAL' ? '#EF4444' :
                       (report.severity === 'HIGH' ? '#F97316' :
                       (report.severity === 'MEDIUM' ? '#F59E0B' :
                       (report.severity === 'LOW' ? '#38BDF8' : '#10B981')));

      const anomaliesHtml = report.anomalies && report.anomalies.length > 0 ? report.anomalies.map(a => `
        <div style="background: rgba(239, 68, 68, 0.1); border-left: 3px solid ${sevColor}; padding: 8px 12px; border-radius: 4px; margin-bottom: 8px;">
          <div style="font-weight: 700; color: ${sevColor}; font-size: 12px;">⚠️ ${escapeHtml(a.title)}</div>
          <div style="color: var(--text-main); font-size: 11px; margin-top: 2px;">${escapeHtml(a.description)}</div>
        </div>
      `).join('') : '<div style="color: #10B981; font-size: 11px;">✓ No protocol errors, resets, or retransmissions detected on this frame.</div>';

      const remediationHtml = report.remediation && report.remediation.length > 0 ? report.remediation.map(r => `
        <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid var(--border-color); padding: 8px 12px; border-radius: 4px; margin-bottom: 6px;">
          <div style="font-weight: 700; color: #38BDF8; font-size: 11px;">Step ${r.step}: ${escapeHtml(r.action)}</div>
          <div style="color: var(--text-muted); font-size: 11px; font-family: var(--font-mono); margin-top: 2px;">${escapeHtml(r.detail)}</div>
        </div>
      `).join('') : '<div style="color: var(--text-dim); font-size: 11px;">No active remediation required. Frame operates within nominal baseline.</div>';

      const rfcBadges = (report.rfcStandards || []).map(rfc => `
        <span style="font-size: 10px; font-family: var(--font-mono); background: rgba(56, 189, 248, 0.15); color: #38BDF8; padding: 2px 6px; border-radius: 4px; border: 1px solid rgba(56, 189, 248, 0.3);">${escapeHtml(rfc)}</span>
      `).join(' ');

      body.style.display = 'block';
      body.style.height = 'auto';
      body.innerHTML = `
        <div style="display: flex; flex-direction: column; gap: 14px;">
          <!-- Severity and Synthesis Card -->
          <div style="background: rgba(15, 23, 42, 0.8); border: 1px solid var(--border-color); border-radius: 6px; padding: 12px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
              <span style="font-weight: 700; font-size: 12px; color: var(--text-main);">Session Role &amp; Synthesis:</span>
              <span style="font-size: 11px; font-weight: 800; font-family: var(--font-mono); padding: 2px 8px; border-radius: 12px; background: rgba(0,0,0,0.4); color: ${sevColor}; border: 1px solid ${sevColor};">
                SEVERITY: ${report.severity}
              </span>
            </div>
            <p style="margin: 0; font-size: 12px; line-height: 1.5; color: var(--text-main);">
              ${escapeHtml(report.plainEnglish)}
            </p>
            <div style="margin-top: 8px; display: flex; gap: 6px; flex-wrap: wrap;">
              ${rfcBadges}
            </div>
          </div>

          <!-- Anomalies / Red Flags -->
          <div>
            <div style="font-weight: 700; font-size: 12px; color: var(--text-main); margin-bottom: 6px;">Protocol Health &amp; Anomaly Analysis:</div>
            ${anomaliesHtml}
          </div>

          <!-- Recommended Wireshark Filter -->
          <div style="background: rgba(10, 16, 30, 0.9); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 6px; padding: 10px 14px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
              <span style="font-size: 11px; font-weight: 700; color: #38BDF8; font-family: var(--font-mono);">Recommended Isolation Filter:</span>
              <button class="btn btn-secondary" onclick="window.applyRecommendedFilter('${escapeAttr(report.recommendedFilter)}')" style="font-size: 10px; padding: 2px 8px;">Apply to Sniffer</button>
            </div>
            <code style="font-family: var(--font-mono); font-size: 11px; color: #34D399; background: rgba(0,0,0,0.5); padding: 4px 8px; border-radius: 4px; display: block;">
              ${escapeHtml(report.recommendedFilter)}
            </code>
          </div>

          <!-- Recommended Engineering Remediation -->
          <div>
            <div style="font-weight: 700; font-size: 12px; color: var(--text-main); margin-bottom: 6px;">Actionable Remediation &amp; Next Steps:</div>
            ${remediationHtml}
          </div>
        </div>
      `;
    } catch (err) {
      const body = document.getElementById('packetAiExplainerBody');
      if (body) {
        body.innerHTML = `<div style="color: var(--danger); padding: 12px;">Failed to generate AI packet explanation: ${err.message}</div>`;
      }
    }
  };

  window.closeAiPacketExplainerModal = function() {
    const modalHost = document.getElementById('packetAiExplainerModalContainer');
    if (modalHost) modalHost.innerHTML = '';
  };

  window.applyRecommendedFilter = function(filterStr) {
    window.closeAiPacketExplainerModal();
    const filterInput = document.getElementById('displayFilterInput');
    if (filterInput) {
      filterInput.value = filterStr;
      if (typeof window.onDisplayFilterInput === 'function') {
        window.onDisplayFilterInput(filterStr);
      }
      if (typeof window.applyDisplayFilter === 'function') {
        window.applyDisplayFilter();
      }
    }
  };

  window.togglePacketInspectorDrawer = function() {
    const pane = document.getElementById('packetDetailsPane');
    if (!pane) return;
    const isHidden = (pane.style.display === 'none' || !pane.style.display);
    pane.style.display = isHidden ? 'flex' : 'none';
  };

  if (!window.troubleshootEndpoint) {
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
                <button class="btn btn-primary" onclick="if(window.sniffNode) window.sniffNode('${escapeAttr(res.resolvedIp || host)}'); document.getElementById('troubleshootEndpointModal').style.display='none';" style="font-size: 11px; padding: 6px 12px; font-weight: 700; background: #0284c7; border-color: #38bdf8;">
                  🎯 Scope Packet Table
                </button>
              </div>
            </div>

            <div style="display: flex; flex-direction: column; gap: 10px; font-size: 12px;">
              <div style="background: #1e293b; border-radius: 6px; padding: 10px 14px;">
                <div style="font-weight: 700; color: #38bdf8; margin-bottom: 4px;">Stage 1: Process & Socket Mapping</div>
                <div>Active Sockets Mapped: <b>${stg.socket?.socketsFound || 0}</b></div>
                ${(stg.socket?.sockets && stg.socket.sockets.length > 0) ? `<div style="color: #94a3b8; font-size: 11px; margin-top: 2px;">Sockets: ${stg.socket.sockets.map(s => escapeHtml(s.name || s.pid)).join(', ')}</div>` : '<div style="color: #64748b; font-size: 11px;">No local process currently has an open socket to this host.</div>'}
              </div>

              <div style="background: #1e293b; border-radius: 6px; padding: 10px 14px;">
                <div style="font-weight: 700; color: #38bdf8; margin-bottom: 4px;">Stage 2: DNS & Reverse PTR Resolution</div>
                <div>Resolved IP: <code style="color: #a78bfa;">${escapeHtml(stg.dns?.resolvedIp || host)}</code> | Hostname: <code style="color: #a78bfa;">${escapeHtml(stg.dns?.resolvedHostname || '—')}</code> (${stg.dns?.lookupDurationMs || 0}ms)</div>
              </div>

              <div style="background: #1e293b; border-radius: 6px; padding: 10px 14px;">
                <div style="font-weight: 700; color: #38bdf8; margin-bottom: 4px;">Stage 3: L3/L4 TCP Reachability & Kernel Check</div>
                <div>Connection to Port ${stg.tcp?.targetPort || port}: <b style="color: ${stg.tcp?.connected ? '#10b981' : '#ef4444'};">${stg.tcp?.connected ? `CONNECTED (${stg.tcp?.latencyMs}ms)` : `FAILED (${escapeHtml(stg.tcp?.kernelError || 'Refused')})`}</b></div>
              </div>

              <div style="background: #1e293b; border-radius: 6px; padding: 10px 14px;">
                <div style="font-weight: 700; color: #38bdf8; margin-bottom: 4px;">Stage 4: L6 TLS Handshake & Certificate Inspection</div>
                ${stg.tls?.notApplicable ? `<div style="color: #64748b;">${escapeHtml(stg.tls?.message || 'N/A')}</div>` : (
                  stg.tls?.handshakeSuccess ? `<div>ALPN: <code style="color: #38bdf8;">${escapeHtml(stg.tls?.alpnProtocol || '—')}</code> | Subject: <b>${escapeHtml(stg.tls?.subject || '—')}</b> | Valid: <b>${stg.tls?.daysRemaining || 0} days remaining</b></div>` : `<div style="color: #ef4444;">TLS Handshake Error: ${escapeHtml(stg.tls?.error || 'Failed')}</div>`
                )}
              </div>

              <div style="background: #1e293b; border-radius: 6px; padding: 10px 14px;">
                <div style="font-weight: 700; color: #38bdf8; margin-bottom: 4px;">Stage 5: Live Wire Capture Correlation</div>
                <div>Correlated Captured Frames: <b>${stg.capture?.correlatedFramesCount || 0}</b> | Retransmissions: <b>${stg.capture?.retransmissionsObserved || 0}</b> | Resets (RST): <b>${stg.capture?.resetsObserved || 0}</b></div>
              </div>
            </div>
          </div>
        `;
      } catch (err) {
        const content = document.getElementById('troubleshootContentArea');
        if (content) content.innerHTML = `<div style="color: #ef4444; padding: 20px;">Network request failed: ${escapeHtml(err.message)}</div>`;
      }
    };
  }

  window.initSnifferCockpit = function() {
    if (typeof window.VirtualPacketCockpit !== 'undefined') {
      window.snifferVirtualCockpit = new window.VirtualPacketCockpit({
        tableViewportEl: document.getElementById('livePacketTableContainer'),
        treePaneEl: document.getElementById('protocolTreePane'),
        hexPaneEl: document.getElementById('hexDumpPane'),
        statusBadgeEl: document.getElementById('freezeStreamBtn')
      });
      return window.snifferVirtualCockpit;
    }
    return null;
  };

  if (!window.renderPacketRows && typeof window.VirtualPacketCockpit !== 'undefined') {
    window.renderPacketRows = function() {
      const frames = (typeof window.getNocLiveFrames === 'function') ? window.getNocLiveFrames() : [];
      return frames.map(f => window.VirtualPacketCockpit.renderTableRowHtml(f, false)).join('');
    };
  }

  window.renderPacketSnifferStandaloneView = renderPacketSnifferStandaloneView;

  if (!window.downloadPcapngExport) {
    window.downloadPcapngExport = function() {
      window.open(`/api/network/pcapng/export?token=${encodeURIComponent(window.state?.token || '')}`, '_blank');
    };
  }

  if (!window.triggerImportPcapng) {
    window.triggerImportPcapng = function() {
      const fileIn = document.getElementById('pcapngFileInput');
      if (fileIn) fileIn.click();
    };
  }

  if (!window.handlePcapngFileChosen) {
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
  }

})(window);
