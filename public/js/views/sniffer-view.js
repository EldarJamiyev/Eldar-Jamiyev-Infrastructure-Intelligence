/**
 * EJII Workstation Section 2: Wireshark-Grade Live Packet Sniffer & Stream Dissector
 * Dedicated Full-Height Packet Dissection Workstation
 * Real Physical Wire Ingestion, RFC Binary Protocol Dissectors, TCP Delta Tracker, 35-Column Flow Matrix.
 */

(function(window) {
  'use strict';

  async function renderPacketSnifferStandaloneView() {
    const container = document.getElementById('mainContent');
    if (!container) return;

    container.innerHTML = `
      <div style="display: flex; align-items: center; justify-content: center; height: 350px;">
        <span style="color: var(--accent); font-weight: 700; font-family: var(--font-mono);">Connecting Section 2: Wireshark-Grade Live Wire Dissector...</span>
      </div>
    `;

    try {
      // Ensure sniffer is running and fetch initial frames/flows
      const [statusRes, framesRes, flowsRes] = await Promise.all([
        window.api('/api/network/capture/status').catch(() => ({ active: true })),
        window.api('/api/network/capture/frames?limit=100').catch(() => ({ frames: [] })),
        window.api('/api/network/capture/flows?limit=100').catch(() => ({ flows: [] }))
      ]);

      if (framesRes?.frames && typeof window.setNocLiveFrames === 'function') {
        window.setNocLiveFrames(framesRes.frames);
      }
      if (flowsRes?.flows && typeof window.setNocLiveFlows === 'function') {
        window.setNocLiveFlows(flowsRes.flows);
      }

      container.innerHTML = `
        <div class="sniffer-standalone-workstation" style="display: flex; flex-direction: column; height: calc(100vh - 80px); gap: 10px;">
          <!-- Autonomous AI Diagnostic Brain Live Drawer -->
          <div id="snifferAiBrainDrawerContainer" class="ai-brain-drawer-mount" style="flex-shrink: 0;"></div>

          <div class="card" style="margin: 0; display: flex; flex-direction: column; flex: 1; overflow: hidden;">
            <!-- Header Stream & Profile Bar -->
            <div class="card-header" style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; padding: 12px 18px; border-bottom: 1px solid var(--border-color); flex-shrink: 0;">
              <div style="display: flex; align-items: center; gap: 10px;">
                <span style="font-size: 22px;">🦈</span>
                <div>
                  <div class="card-title" style="margin: 0; font-size: 15px; font-weight: 800; letter-spacing: -0.2px;">
                    2. Wireshark-Grade Live Packet Sniffer &amp; Stream Dissector
                  </div>
                  <div style="font-size: 11px; color: var(--text-muted); font-family: var(--font-mono);">
                    Physical Npcap Wire Driver &bull; L2-L7 RFC Binary Tree &bull; TCP Stream Delta &amp; Retransmission Engine
                  </div>
                </div>
                <span id="captureLiveIndicator" style="display: inline-flex; align-items: center; gap: 4px; font-size: 11px; font-weight: 700; padding: 3px 10px; border-radius: 12px; background: rgba(52, 211, 153, 0.15); color: var(--success); margin-left: 8px;">
                  <span class="status-dot" style="background: var(--success);"></span>
                  <span id="captureStatusLabel">STREAMING</span>
                </span>
              </div>

              <!-- Stream Controls & Direct PCAP Buttons -->
              <div style="display: flex; align-items: center; gap: 6px; flex-wrap: wrap;">
                <div style="display: flex; gap: 2px; background: var(--bg-input); padding: 2px; border-radius: 6px; border: 1px solid var(--border-color);">
                  <button id="viewModePacketsBtn" class="btn btn-primary" onclick="window.switchNocSnifferMode('packets')" style="font-size: 11px; padding: 4px 10px; font-weight: 600;">📋 Live Frames</button>
                  <button id="viewModeFlowsBtn" class="btn btn-secondary" onclick="window.switchNocSnifferMode('flows')" style="font-size: 11px; padding: 4px 10px; font-weight: 600;">📊 Flow Matrix (35 Cols)</button>
                </div>

                <select id="packetProtocolFilter" class="form-input" style="width: 100px; padding: 4px 6px; font-size: 11px;" onchange="window.onPacketProtocolFilterChange(this.value)">
                  <option value="ALL">All Proto</option>
                  <option value="TCP">TCP</option>
                  <option value="UDP">UDP</option>
                  <option value="DNS">DNS</option>
                  <option value="HTTP">HTTP</option>
                  <option value="TLS">TLS</option>
                  <option value="ICMP">ICMP</option>
                  <option value="ARP">ARP</option>
                </select>

                <input type="text" id="packetSearchInput" class="form-input" placeholder="Search IP, port, URL, host..." style="width: 165px; padding: 4px 8px; font-size: 11px;" oninput="window.onPacketSearchChange(this.value)">

                <label style="display: flex; align-items: center; gap: 4px; font-size: 11px; color: var(--text-dim); cursor: pointer; user-select: none;">
                  <input type="checkbox" id="hideInternalEjiCheckbox" checked onchange="window.toggleHideInternalEji(this.checked)">
                  <span>Hide Loopback/8443</span>
                </label>

                <button id="freezeStreamBtn" class="btn btn-secondary" onclick="window.toggleFreezeStreamView()" style="font-size: 11px; padding: 4px 10px;">⏸ Freeze</button>
                <button id="toggleCaptureBtn" class="btn btn-secondary" onclick="window.toggleLiveCapture()" style="font-size: 11px; padding: 4px 10px;">⏸ Pause</button>
                <button class="btn btn-secondary" onclick="window.clearPacketBuffer()" style="font-size: 11px; padding: 4px 8px;">Clear</button>

                <!-- Dedicated Direct PCAP I/O Controls -->
                <button class="btn btn-secondary" onclick="window.downloadPcapExport()" style="font-size: 11px; padding: 4px 10px; font-weight: 600; color: #38BDF8;" title="Export standard libpcap binary file for Wireshark">⬇ Export PCAP</button>
                <input type="file" id="pcapFileInput" style="display: none;" accept=".pcap,.cap" onchange="window.handlePcapFileChosen(this)">
                <button class="btn btn-secondary" onclick="window.triggerImportPcap()" style="font-size: 11px; padding: 4px 10px; font-weight: 600; color: #A78BFA;" title="Import offline PCAP file for forensic dissection">⬆ Import PCAP</button>

                <button class="btn btn-secondary" onclick="window.openWireDiagnosticsModal()" style="font-size: 11px; padding: 4px 8px;" title="Open Wire Diagnostics Hub">🛠️ Diagnostics</button>
              </div>
            </div>

            <!-- BPF Capture Filter & Hardware Accounting Counters Bar -->
            <div style="background: rgba(15, 23, 42, 0.6); border-bottom: 1px solid var(--border-color); padding: 8px 18px; flex-shrink: 0;">
              <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 6px; flex-wrap: wrap;">
                <span style="font-weight: 700; font-size: 11px; color: var(--accent); white-space: nowrap; font-family: var(--font-mono);">⚡ Kernel BPF Capture Filter:</span>
                <input type="text" id="nocBpfInput" class="form-input" placeholder="e.g. tcp port 443 and host 10.168.195.1, icmp or arp" style="flex: 1; min-width: 220px; font-family: var(--font-mono); font-size: 11px; padding: 4px 10px;">
                <button class="btn btn-primary" onclick="window.applyNocBpfFilter()" style="font-size: 11px; padding: 4px 12px; font-weight: 700;">Apply BPF</button>
                <button class="btn btn-secondary" onclick="window.clearNocBpfFilter()" style="font-size: 11px; padding: 4px 8px;">Clear</button>
              </div>
              <div id="nocCountersBar" style="display: flex; gap: 16px; align-items: center; font-size: 11px; font-family: var(--font-mono); flex-wrap: wrap;">
                <span><b>Driver Received:</b> <span id="cntReceived" style="color: var(--accent); font-weight: 700;">0</span></span>
                <span><b>Accepted (BPF):</b> <span id="cntAccepted" style="color: var(--success); font-weight: 700;">0</span></span>
                <span><b>Dropped:</b> <span id="cntDropped" style="color: var(--danger); font-weight: 700;">0</span></span>
                <span><b>Decoded:</b> <span id="cntDecoded" style="color: #38bdf8; font-weight: 700;">0</span></span>
                <span><b>Delivered:</b> <span id="cntDelivered" style="color: #a78bfa; font-weight: 700;">0</span></span>
                <span style="margin-left: auto;">
                  <button class="btn btn-secondary" onclick="window.refreshNocCounters()" style="font-size: 10px; padding: 2px 8px;">↻ Counters</button>
                </span>
              </div>
            </div>

            <!-- Dynamic Wireshark Display Filter Bar (AST Evaluator) -->
            <div style="background: rgba(10, 16, 30, 0.85); border-bottom: 1px solid var(--border-color); padding: 6px 18px; flex-shrink: 0;">
              <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
                <span style="font-weight: 700; font-size: 11px; color: #38BDF8; white-space: nowrap; font-family: var(--font-mono);">🔍 Display Filter (Wireshark AST):</span>
                <div style="position: relative; flex: 1; min-width: 260px; display: flex; align-items: center;">
                  <input type="text" id="displayFilterInput" class="form-input"
                         placeholder='e.g. ip.addr == 10.168.195.1 && tcp.port == 443, !tcp.flags.syn, dns, http.response.code >= 400'
                         style="width: 100%; font-family: var(--font-mono); font-size: 11px; padding: 4px 10px; padding-right: 180px; transition: border-color 0.2s, background-color 0.2s;"
                         oninput="window.onDisplayFilterInput(this.value)"
                         onkeydown="if(event.key === 'Enter') window.applyDisplayFilter()">
                  <span id="displayFilterValidationBadge" style="position: absolute; right: 10px; font-size: 10px; font-family: var(--font-mono); font-weight: 700; pointer-events: none; color: var(--text-dim);"></span>
                </div>
                <button class="btn btn-primary" onclick="window.applyDisplayFilter()" style="font-size: 11px; padding: 4px 12px; font-weight: 700;">Apply Filter</button>
                <button class="btn btn-secondary" onclick="window.clearDisplayFilter()" style="font-size: 11px; padding: 4px 8px;">Clear</button>
              </div>
            </div>

            <!-- View 1: Live Frame Summary Table -->
            <div id="livePacketTableView" style="display: flex; flex: 1; overflow: hidden; flex-direction: column;">
              <div id="livePacketTableContainer" class="table-container" style="flex: 1; overflow-x: auto; overflow-y: auto; scrollbar-gutter: stable;" onmouseenter="window.onPacketTableMouseEnter()" onmouseleave="window.onPacketTableMouseLeave()">
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

            <!-- LOWER 3-PANE DEEP PACKET INSPECTION (DPI) DRAWER -->
            <div id="packetDetailsPane" style="display: none; height: 260px; min-height: 180px; max-height: 420px; border-top: 2px solid var(--border-color); background: #0A0E1A; flex-direction: column; flex-shrink: 0;">
              <div style="background: rgba(15, 23, 42, 0.9); padding: 6px 16px; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center;">
                <span id="dpiSummaryHeader" style="font-weight: 700; font-size: 11px; color: var(--accent); font-family: var(--font-mono);">
                  🔍 3-Pane Deep Packet Inspector (Frame Summary &bull; RFC Protocol Tree &bull; Synchronized Hex/ASCII)
                </span>
                <div style="display: flex; gap: 8px; align-items: center;">
                  <button id="followStreamBtn" class="btn btn-secondary" onclick="window.followTcpStream()" style="font-size: 10px; padding: 2px 8px; display: none;">🌊 Follow Stream</button>
                  <button class="btn btn-secondary" onclick="window.closePacketDetails()" style="font-size: 10px; padding: 2px 6px;">✕ Close</button>
                </div>
              </div>

              <div style="display: grid; grid-template-columns: 1fr 1fr; flex: 1; overflow: hidden;">
                <!-- Pane 2: RFC Protocol Dissection Tree -->
                <div id="protocolTreePane" style="border-right: 1px solid var(--border-color); overflow-y: auto; padding: 10px 14px; font-family: var(--font-mono); font-size: 11px; scrollbar-gutter: stable;">
                  <div style="color: var(--text-dim); padding: 12px; text-align: center;">Select a frame from the packet table to inspect its RFC protocol decode tree.</div>
                </div>

                <!-- Pane 3: Hexdump & ASCII Synchronized Inspector -->
                <div id="hexDumpPane" style="overflow-y: auto; padding: 10px 14px; font-family: var(--font-mono); font-size: 11px; background: #060911; scrollbar-gutter: stable;">
                  <div style="color: var(--text-dim); padding: 12px; text-align: center;">Raw payload bytes will be dissected here in synchronized Hex &amp; ASCII format.</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      `;

      if (typeof window.initAiBrainDrawer === 'function') {
        window.initAiBrainDrawer('snifferAiBrainDrawerContainer');
      }

      if (typeof window.refreshNocCounters === 'function') {
        window.refreshNocCounters();
      }
    } catch (err) {
      container.innerHTML = `<div class="card" style="color: var(--danger); padding: 24px;">Failed to load Live Packet Sniffer: ${err.message}</div>`;
    }
  }

  window.renderPacketSnifferStandaloneView = renderPacketSnifferStandaloneView;

})(window);
