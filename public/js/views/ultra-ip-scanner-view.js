/**
 * EJII Workstation Section 3: Ultra IP & Infrastructure Fleet Scanner
 * Dedicated High-Throughput Subnet Sweeper & Multi-Protocol Fingerprinting Engine
 * Exceeding Advanced IP Scanner & Angry IP Scanner.
 */

(function(window) {
  'use strict';

  let currentScanResults = [];
  let scanPollingTimer = null;
  let activeFilterChip = 'all';
  let activeSearchQuery = '';
  let isScanning = false;
  let hideNoPing = false;

  async function renderUltraIpScannerView() {
    const container = document.getElementById('mainContent');
    if (!container) return;

    // Detect default physical subnet from live environment
    let defaultSubnet = '10.168.195.0/24';
    try {
      const physRes = await window.api('/api/network/physical-info').catch(() => null);
      if (physRes?.subnetCidr) {
        defaultSubnet = physRes.subnetCidr;
      } else {
        const topoRes = await window.api('/api/network/topology').catch(() => null);
        if (topoRes?.nodes) {
          const subnetNode = topoRes.nodes.find(n => n.hostname_or_ip && n.hostname_or_ip.includes('/24'));
          if (subnetNode) defaultSubnet = subnetNode.hostname_or_ip;
        }
      }
    } catch (e) {}

    container.innerHTML = `
      <div class="ultra-ip-scanner-workstation" style="display: flex; flex-direction: column; height: calc(100vh - 80px); gap: 12px;">
        <div class="card" style="margin: 0; display: flex; flex-direction: column; flex: 1; overflow: hidden;">
          <!-- Top Header -->
          <div class="card-header" style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; padding: 12px 18px; border-bottom: 1px solid var(--border-color); flex-shrink: 0;">
            <div style="display: flex; align-items: center; gap: 10px;">
              <span style="font-size: 22px;">📡</span>
              <div>
                <div class="card-title" style="margin: 0; font-size: 15px; font-weight: 800; letter-spacing: -0.2px;">
                  3. Ultra IP &amp; Infrastructure Fleet Scanner
                </div>
                <div style="font-size: 11px; color: var(--text-muted); font-family: var(--font-mono);">
                  High-Speed Multi-Threaded Subnet Sweep &bull; NetBIOS / mDNS / Reverse DNS &bull; Port Auditing &bull; Wake-On-LAN
                </div>
              </div>
            </div>

            <div style="display: flex; align-items: center; gap: 8px;">
              <button class="btn btn-secondary" onclick="window.exportScannerCsv()" style="font-size: 11px; padding: 4px 10px; font-weight: 600;" title="Export Excel / Sheets CSV spreadsheet">📄 Export CSV</button>
              <button class="btn btn-secondary" onclick="window.exportScannerJson()" style="font-size: 11px; padding: 4px 10px; font-weight: 600;" title="Export full JSON payload">📋 Export JSON</button>
              <button class="btn btn-secondary" onclick="window.printScannerReport()" style="font-size: 11px; padding: 4px 10px; font-weight: 600;" title="Print official NOC Fleet Inventory Report">🖨️ Print Report</button>
            </div>
          </div>

          <!-- Target & Scan Control Toolbar -->
          <div style="background: rgba(15, 23, 42, 0.6); border-bottom: 1px solid var(--border-color); padding: 10px 18px; flex-shrink: 0;">
            <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 8px;">
              <span style="font-weight: 700; font-size: 11px; color: var(--accent); font-family: var(--font-mono); white-space: nowrap;">Target Subnet / Range:</span>
              <input type="text" id="scannerSubnetInput" class="form-input" value="${defaultSubnet}" placeholder="e.g. 10.168.195.0/24, 192.168.1.1-254" style="width: 220px; font-family: var(--font-mono); font-size: 11px; padding: 4px 8px;">
              <button class="btn btn-secondary" onclick="window.autoDetectSubnet()" style="font-size: 11px; padding: 4px 8px;" title="Auto-detect active local physical network subnet">⚡ Auto-Detect</button>

              <span style="font-weight: 700; font-size: 11px; color: var(--text-dim); margin-left: 8px;">Profile:</span>
              <select id="scannerProfileSelect" class="form-input" style="width: 220px; font-size: 11px; padding: 4px 6px;">
                <option value="edr_conservative" selected>🛡️ EDR-Conservative (Neighbor + ICMP + Target)</option>
                <option value="fast">⚡ Fast Audit (Essential 80, 445)</option>
                <option value="deep">🔍 Deep Audit (Extended Port Check)</option>
              </select>

              <span style="font-weight: 700; font-size: 11px; color: var(--text-dim); margin-left: 6px;">Workers:</span>
              <select id="scannerConcurrencySelect" class="form-input" style="width: 85px; font-size: 11px; padding: 4px 6px;">
                <option value="4">4</option>
                <option value="8" selected>8 (Safe)</option>
                <option value="12">12</option>
              </select>

              <button id="startScanBtn" class="btn btn-primary" onclick="window.startSubnetScan()" style="font-size: 11px; padding: 4px 14px; font-weight: 700; margin-left: auto;">
                ▶ Start Scan ⚡
              </button>
              <button id="stopScanBtn" class="btn btn-secondary" onclick="window.stopSubnetScan()" style="font-size: 11px; padding: 4px 10px;" disabled>
                ⏹ Stop
              </button>
              <button class="btn btn-secondary" onclick="window.clearScanResults()" style="font-size: 11px; padding: 4px 8px;">
                Clear
              </button>
            </div>

            <!-- Live Progress Bar & Telemetry Counters -->
            <div id="scannerProgressWrap" style="display: none; flex-direction: column; gap: 4px; margin-top: 6px;">
              <div style="display: flex; justify-content: space-between; font-size: 11px; font-family: var(--font-mono); color: var(--text-dim); flex-wrap: wrap; gap: 8px;">
                <span>Phase: <b id="progPhase" style="color: #38BDF8;">Idle</b></span>
                <span>Scanning: <b id="progScannedCount" style="color: var(--accent);">0</b> / <span id="progTotalCount">254</span> hosts</span>
                <span>Online / Fresh: <b id="progOnlineCount" style="color: var(--success);">0</b></span>
                <span id="progDeltaWrap" style="display: none;">Delta: <b id="progDeltaBadge" style="color: #38BDF8; font-weight: 700;">0 Changes</b></span>
                <span>Probes: <b id="progProbesSent" style="color: #F59E0B;">0</b></span>
                <span>Bytes: <b id="progBytesTransferred" style="color: #A78BFA;">0 KB</b></span>
                <span>Speed: <b id="progScanRate" style="color: #38BDF8;">0</b> hosts/sec</span>
                <span>Progress: <b id="progPercent" style="color: var(--accent);">0%</b></span>
              </div>
              <div style="background: rgba(255,255,255,0.06); height: 6px; border-radius: 3px; overflow: hidden;">
                <div id="progBarInner" style="background: linear-gradient(90deg, var(--accent), var(--success)); height: 100%; width: 0%; transition: width 0.15s ease;"></div>
              </div>
            </div>
          </div>

          <!-- Filter & Search Chips Bar -->
          <div style="background: rgba(15, 23, 42, 0.4); border-bottom: 1px solid var(--border-color); padding: 8px 18px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; flex-shrink: 0;">
            <div style="display: flex; gap: 6px; align-items: center; flex-wrap: wrap;">
              <span style="font-size: 11px; font-weight: 700; color: var(--text-dim);">Filter:</span>
              <button class="btn ${activeFilterChip === 'all' ? 'btn-primary' : 'btn-secondary'}" onclick="window.setScannerFilterChip('all')" style="font-size: 10px; padding: 2px 8px;">All (<span id="chipCountAll">0</span>)</button>
              <button class="btn ${activeFilterChip === 'online' ? 'btn-primary' : 'btn-secondary'}" onclick="window.setScannerFilterChip('online')" style="font-size: 10px; padding: 2px 8px;">Online (<span id="chipCountOnline">0</span>)</button>
              <button class="btn ${activeFilterChip === 'printers' ? 'btn-primary' : 'btn-secondary'}" onclick="window.setScannerFilterChip('printers')" style="font-size: 10px; padding: 2px 8px;">🖨️ Printers</button>
              <button class="btn ${activeFilterChip === 'computers' ? 'btn-primary' : 'btn-secondary'}" onclick="window.setScannerFilterChip('computers')" style="font-size: 10px; padding: 2px 8px;">💻 Computers</button>
              <button class="btn ${activeFilterChip === 'phones' ? 'btn-primary' : 'btn-secondary'}" onclick="window.setScannerFilterChip('phones')" style="font-size: 10px; padding: 2px 8px;">📞 Phones</button>
              <button class="btn ${activeFilterChip === 'network_gear' ? 'btn-primary' : 'btn-secondary'}" onclick="window.setScannerFilterChip('network_gear')" style="font-size: 10px; padding: 2px 8px;">🌐 Network Gear</button>
              <button class="btn ${activeFilterChip === 'apipa_issues' ? 'btn-primary' : 'btn-secondary'}" onclick="window.setScannerFilterChip('apipa_issues')" style="font-size: 10px; padding: 2px 8px;">⚠️ APIPA / Issues</button>
            </div>

            <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
              <div style="display: flex; align-items: center; gap: 4px; background: rgba(15, 23, 42, 0.6); border: 1px solid var(--border-color); border-radius: 4px; padding: 2px 6px;">
                <input type="text" id="apipaQuickDiagInput" class="form-input" placeholder="e.g. 169.254.45.12" style="width: 130px; font-size: 11px; padding: 2px 6px; font-family: var(--font-mono); border: none; background: transparent;">
                <button class="btn btn-secondary" onclick="window.quickDiagnoseOfficeDevice()" style="font-size: 10px; padding: 2px 6px; font-weight: 700; color: #38bdf8;" title="Plain-language problem resolver & visual smart path mapper">🩺 Diagnose</button>
              </div>
              <label style="display: flex; align-items: center; gap: 4px; font-size: 11px; color: var(--text-dim); cursor: pointer; user-select: none; margin-left: 4px;">
                <input type="checkbox" id="hideNoPingCheckbox" onchange="window.toggleHideNoPing(this.checked)">
                <span>Hide NO PING</span>
              </label>
              <input type="text" id="scannerSearchInput" class="form-input" placeholder="Search IP, hostname, vendor, port..." style="width: 180px; font-size: 11px; padding: 4px 8px;" oninput="window.onScannerSearchChange(this.value)">
            </div>
          </div>

          <!-- Visible Scan Delta Summary Banner -->
          <div id="scannerDeltaSummaryBanner" style="display: none; background: rgba(56, 189, 248, 0.08); border-bottom: 1px solid rgba(56, 189, 248, 0.25); padding: 8px 18px; font-size: 11px; font-family: var(--font-mono); color: #e2e8f0;"></div>

          <!-- Fleet Data Table View -->
          <div style="flex: 1; overflow: hidden; display: flex; flex-direction: column;">
            <div class="table-container" style="flex: 1; overflow-x: auto; overflow-y: auto; scrollbar-gutter: stable;">
              <table class="data-table" style="font-family: var(--font-mono); font-size: 11px; width: 100%;">
                <thead>
                  <tr>
                    <th class="col-nowrap" style="width: 110px; min-width: 110px; white-space: nowrap; text-align: center;">Status</th>
                    <th style="min-width: 170px;">Device / NetBIOS Hostname</th>
                    <th class="col-ip" style="min-width: 125px; white-space: nowrap;">IPv4 Address</th>
                    <th class="col-nowrap" style="min-width: 135px; white-space: nowrap;">MAC Address</th>
                    <th style="min-width: 160px;">Hardware Manufacturer</th>
                    <th class="col-nowrap" style="min-width: 130px; white-space: nowrap;">Category</th>
                    <th style="min-width: 170px;">Open Services &amp; Connect</th>
                    <th class="col-nowrap" style="width: 80px; min-width: 80px; white-space: nowrap;">RTT</th>
                    <th class="col-nowrap" style="min-width: 200px; white-space: nowrap;">NOC Operations</th>
                  </tr>
                </thead>
                <tbody id="scannerFleetTableBody">
                  <tr>
                    <td colspan="9" style="text-align: center; padding: 35px; color: var(--text-dim);">
                      Enter a subnet range (e.g. <code>${defaultSubnet}</code>) and click <b>[▶ Start Scan ⚡]</b> to sweep the fleet.
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    `;

    // Check if scan is already active or pre-load cached ARP table
    try {
      const statusRes = await window.api('/api/network/scanner/status');
      if (statusRes && statusRes.status === 'scanning') {
        isScanning = true;
        pollScanStatus();
      } else {
        // Pre-fill with existing ARP table for instant feedback
        const arpRes = await window.api('/api/network/arp');
        if (arpRes?.entries && arpRes.entries.length > 0) {
          currentScanResults = arpRes.entries.map(e => ({
            ip: e.ip,
            status: 'CACHED_ARP',
            hostname: e.ip,
            macAddress: e.mac,
            vendor: e.vendor || 'Discovered Host',
            latencyMs: 0.4,
            openServices: [],
            category: e.ip.endsWith('.1') ? '🌐 Gateway / Router' : '💻 Network Host'
          }));
          renderScannerRows();
        }
      }
    } catch (e) {}
  }

  window.renderUltraIpScannerView = renderUltraIpScannerView;
  window.renderIpScannerView = renderUltraIpScannerView; // Alias

  window.autoDetectSubnet = async function() {
    try {
      const topoRes = await window.api('/api/network/topology');
      const subnetNode = topoRes?.nodes?.find(n => n.hostname_or_ip && n.hostname_or_ip.includes('/24'));
      if (subnetNode) {
        const input = document.getElementById('scannerSubnetInput');
        if (input) input.value = subnetNode.hostname_or_ip;
      }
    } catch (e) {}
  };

  window.startSubnetScan = async function() {
    const input = document.getElementById('scannerSubnetInput');
    const subnet = input ? input.value.trim() : '10.168.195.0/24';
    const profile = document.getElementById('scannerProfileSelect')?.value || 'edr_conservative';
    const concurrency = parseInt(document.getElementById('scannerConcurrencySelect')?.value || '8', 10);

    const startBtn = document.getElementById('startScanBtn');
    const stopBtn = document.getElementById('stopScanBtn');
    const progressWrap = document.getElementById('scannerProgressWrap');

    if (startBtn) startBtn.disabled = true;
    if (stopBtn) stopBtn.disabled = false;
    if (progressWrap) progressWrap.style.display = 'flex';

    isScanning = true;

    try {
      await window.api('/api/network/scanner/start', {
        method: 'POST',
        body: JSON.stringify({ subnet, profile, concurrency })
      });
      pollScanStatus();
    } catch (err) {
      alert('Failed to start scan: ' + err.message);
      if (startBtn) startBtn.disabled = false;
      if (stopBtn) stopBtn.disabled = true;
      isScanning = false;
    }
  };

  window.stopSubnetScan = async function() {
    try {
      await window.api('/api/network/scanner/stop', { method: 'POST' });
    } catch (e) {}
    isScanning = false;
    if (scanPollingTimer) clearInterval(scanPollingTimer);
    const startBtn = document.getElementById('startScanBtn');
    const stopBtn = document.getElementById('stopScanBtn');
    if (startBtn) startBtn.disabled = false;
    if (stopBtn) stopBtn.disabled = true;
  };

  window.clearScanResults = function() {
    currentScanResults = [];
    renderScannerRows();
  };

  function pollScanStatus() {
    if (scanPollingTimer) clearInterval(scanPollingTimer);

    scanPollingTimer = setInterval(async () => {
      try {
        const res = await window.api('/api/network/scanner/status');
        if (!res) return;

        // Update progress bar
        const progPhase = document.getElementById('progPhase');
        const progScanned = document.getElementById('progScannedCount');
        const progTotal = document.getElementById('progTotalCount');
        const progOnline = document.getElementById('progOnlineCount');
        const progProbes = document.getElementById('progProbesSent');
        const progBytes = document.getElementById('progBytesTransferred');
        const progRate = document.getElementById('progScanRate');
        const progPercent = document.getElementById('progPercent');
        const barInner = document.getElementById('progBarInner');

        if (progPhase && res.phase) progPhase.textContent = res.phase;
        if (progScanned) progScanned.textContent = res.scanned;
        if (progTotal) progTotal.textContent = res.total;
        if (progOnline) progOnline.textContent = res.onlineCount;
        if (progProbes) progProbes.textContent = res.probesSent || 0;
        if (progBytes) progBytes.textContent = `${((res.bytesTransferred || 0) / 1024).toFixed(1)} KB`;
        if (progRate) progRate.textContent = res.scanRate;
        if (progPercent) progPercent.textContent = `${res.percent}%`;
        if (barInner) barInner.style.width = `${res.percent}%`;

        if (res.deltaSummary && res.deltaSummary.events && res.deltaSummary.events.length > 0) {
          const deltaWrap = document.getElementById('progDeltaWrap');
          const deltaBadge = document.getElementById('progDeltaBadge');
          if (deltaWrap) deltaWrap.style.display = 'inline';
          if (deltaBadge) deltaBadge.textContent = `+${res.deltaSummary.newHostsCount || 0} new, -${res.deltaSummary.missingHostsCount || 0} lost, ${res.deltaSummary.changedMacsCount || 0} mac-chg`;

          const banner = document.getElementById('scannerDeltaSummaryBanner');
          if (banner) {
            banner.style.display = 'flex';
            banner.innerHTML = `
              <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
                <span style="font-weight: 700; color: #38bdf8;">📡 Fleet Scan Delta:</span>
                <span style="color: #34d399; font-weight: 700;">+${res.deltaSummary.newHostsCount || 0} New Hosts</span>
                <span style="color: #f87171; font-weight: 700;">-${res.deltaSummary.missingHostsCount || 0} Missing</span>
                <span style="color: #fbbf24; font-weight: 700;">${res.deltaSummary.changedMacsCount || 0} MAC Changes</span>
                <span style="color: #38bdf8; font-weight: 700;">+${res.deltaSummary.newOpenPortsCount || 0} New Ports</span>
                <span style="color: #94a3b8; font-weight: 700;">-${res.deltaSummary.closedPortsCount || 0} Closed Ports</span>
              </div>
            `;
          }
        }

        if (res.hosts && res.hosts.length > 0) {
          currentScanResults = res.hosts;
          renderScannerRows();
        }

        if (res.status !== 'scanning') {
          clearInterval(scanPollingTimer);
          isScanning = false;
          const startBtn = document.getElementById('startScanBtn');
          const stopBtn = document.getElementById('stopScanBtn');
          if (startBtn) startBtn.disabled = false;
          if (stopBtn) stopBtn.disabled = true;
        }
      } catch (err) {
        clearInterval(scanPollingTimer);
      }
    }, 400);
  }

  window.setScannerFilterChip = function(chip) {
    activeFilterChip = chip;
    document.querySelectorAll('.filter-chip').forEach(btn => btn.classList.remove('btn-primary'));
    renderScannerRows();
  };

  window.onScannerSearchChange = function(query) {
    activeSearchQuery = (query || '').toLowerCase().trim();
    renderScannerRows();
  };

  window.toggleHideNoPing = function(checked) {
    hideNoPing = Boolean(checked);
    renderScannerRows();
  };

  function getHostSortTier(h) {
    const st = String(h.status || '').toUpperCase();
    if (st === 'ONLINE' || st === 'ACTIVE' || st === 'RECENTLY_SEEN') return 1;
    if (st.includes('CACHED') || st.includes('ARP') || (h.macAddress && h.macAddress !== 'Unknown' && h.macAddress !== 'N/A' && h.macAddress !== '00:00:00:00:00:00' && h.macAddress !== '— (No MAC Observed)')) return 2;
    return 3; // NO_ICMP_RESPONSE, UNRESPONSIVE, CONFIRMED_OFFLINE
  }
  window.getHostSortTier = getHostSortTier;

  function renderScannerRows() {
    const tbody = document.getElementById('scannerFleetTableBody');
    if (!tbody) return;

    let filtered = currentScanResults.slice();

    // Hide NO PING (Unresponsive) if checked
    if (hideNoPing) {
      filtered = filtered.filter(h => {
        const st = String(h.status || h.detailedStatus || '').toUpperCase();
        return st !== 'NO_ICMP_RESPONSE' && st !== 'UNRESPONSIVE' && st !== 'NO PING';
      });
    }

    // Filter chip logic
    if (activeFilterChip === 'online') {
      filtered = filtered.filter(h => h.status === 'ONLINE' || h.status === 'RECENTLY_SEEN');
    } else if (activeFilterChip === 'printers') {
      filtered = filtered.filter(h => h.equipmentProfile?.equipmentType === 'PRINTER' || /printer|laserjet|officejet|epson|canon|brother|ricoh|xerox/i.test((h.category || '') + ' ' + (h.hostname || '') + ' ' + (h.vendor || '')));
    } else if (activeFilterChip === 'computers') {
      filtered = filtered.filter(h => h.equipmentProfile?.equipmentType === 'COMPUTER' || /computer|workstation|pc|desktop|laptop|server/i.test((h.category || '') + ' ' + (h.hostname || '')));
    } else if (activeFilterChip === 'phones') {
      filtered = filtered.filter(h => h.equipmentProfile?.equipmentType === 'VOIP_PHONE' || /phone|voip|sip|yealink|polycom|snom|cisco ip/i.test((h.category || '') + ' ' + (h.hostname || '') + ' ' + (h.vendor || '')));
    } else if (activeFilterChip === 'network_gear' || activeFilterChip === 'gateways') {
      filtered = filtered.filter(h => h.equipmentProfile?.equipmentType === 'NETWORK_INFRASTRUCTURE' || (h.category || '').includes('Gateway') || (h.category || '').includes('Router') || (h.category || '').includes('Switch'));
    } else if (activeFilterChip === 'apipa_issues') {
      filtered = filtered.filter(h => h.ip.startsWith('169.254.') || h.equipmentProfile?.isApipaFault || h.status === 'NO_ICMP_RESPONSE' || h.status === 'UNRESPONSIVE');
    } else if (activeFilterChip === 'servers') {
      filtered = filtered.filter(h => (h.category || '').includes('Server') || (h.category || '').includes('Windows'));
    } else if (activeFilterChip === 'services') {
      filtered = filtered.filter(h => h.openServices && h.openServices.length > 0);
    }

    // Search query logic
    if (activeSearchQuery) {
      filtered = filtered.filter(h =>
        h.ip.includes(activeSearchQuery) ||
        (h.hostname && h.hostname.toLowerCase().includes(activeSearchQuery)) ||
        (h.vendor && h.vendor.toLowerCase().includes(activeSearchQuery)) ||
        (h.macAddress && h.macAddress.toLowerCase().includes(activeSearchQuery)) ||
        (h.category && h.category.toLowerCase().includes(activeSearchQuery)) ||
        (h.openServices && h.openServices.some(s => s.name.toLowerCase().includes(activeSearchQuery) || String(s.port).includes(activeSearchQuery)))
      );
    }

    // Deterministic 3-Tier Sorting immediately before render
    filtered.sort((a, b) => {
      const tierDiff = getHostSortTier(a) - getHostSortTier(b);
      if (tierDiff !== 0) return tierDiff;
      const portsA = Array.isArray(a.openServices) ? a.openServices.length : 0;
      const portsB = Array.isArray(b.openServices) ? b.openServices.length : 0;
      if (portsB !== portsA) return portsB - portsA;
      const ipA = String(a.ip || '').split('.').map(Number);
      const ipB = String(b.ip || '').split('.').map(Number);
      for (let i = 0; i < 4; i++) {
        if ((ipA[i] || 0) !== (ipB[i] || 0)) return (ipA[i] || 0) - (ipB[i] || 0);
      }
      return 0;
    });

    // Update counts
    const countAll = document.getElementById('chipCountAll');
    const countOnline = document.getElementById('chipCountOnline');
    if (countAll) countAll.textContent = currentScanResults.length;
    if (countOnline) countOnline.textContent = currentScanResults.filter(h => h.status === 'ONLINE' || h.status === 'RECENTLY_SEEN').length;

    if (filtered.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="9" style="text-align: center; padding: 28px; color: var(--text-dim);">
            No hosts match the current filter or search criteria.
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = filtered.map(h => {
      let statusDot = '';
      const st = String(h.status || h.detailedStatus || '').toUpperCase();
      if (st === 'ONLINE' || st === 'ACTIVE') {
        statusDot = `<span class="status-dot" style="background: #10B981; box-shadow: 0 0 6px #10B981;"></span> <span style="color: #34D399; font-weight: 700;">● ONLINE</span>`;
      } else if (st === 'RECENTLY_SEEN' || st === 'FRESH_ARP') {
        statusDot = `<span class="status-dot" style="background: #06B6D4; box-shadow: 0 0 6px #06B6D4;"></span> <span style="color: #38BDF8; font-weight: 700;">FRESH_ARP</span>`;
      } else if (st === 'CONFIRMED_OFFLINE' || st === 'OFFLINE') {
        statusDot = `<span class="status-dot" style="background: #EF4444; box-shadow: 0 0 6px #EF4444;"></span> <span style="color: #F87171; font-weight: 700;" title="${escapeAttr(h.probeLimitations || 'Gateway reported Destination Host Unreachable (ICMP Type 3 Code 1)')}">OFFLINE</span>`;
      } else if (st === 'NO_ICMP_RESPONSE' || st === 'UNRESPONSIVE' || st === 'NO PING') {
        statusDot = `<span class="status-dot" style="background: #F59E0B;"></span> <span style="color: #FBBF24; font-weight: 600;" title="No ICMP Echo reply within timeout; host is either unallocated, offline, or dropping ping">NO PING</span>`;
      } else if (st.includes('CACHED') || st.includes('ARP')) {
        statusDot = `<span class="status-dot" style="background: #64748B;"></span> <span style="color: #94A3B8;">ARP CACHED</span>`;
      } else {
        statusDot = `<span class="status-dot" style="background: #475569;"></span> <span style="color: #64748B;">${escapeHtml(h.status || 'UNKNOWN')}</span>`;
      }

      // Quick connect badges
      let serviceBadges = '';
      if (h.openServices && h.openServices.length > 0) {
        serviceBadges = h.openServices.map(s => {
          let badgeColor = 'rgba(56, 189, 248, 0.2)';
          let textColor = '#38BDF8';
          let clickAction = '';

          if (s.port === 80) clickAction = `window.open('http://${h.ip}', '_blank')`;
          else if (s.port === 443) clickAction = `window.open('https://${h.ip}', '_blank')`;
          else if (s.port === 445) clickAction = `window.navigator.clipboard.writeText('\\\\\\\\${h.ip}')`;

          if (s.risk === 'warning') { badgeColor = 'rgba(245, 158, 11, 0.2)'; textColor = '#FBBF24'; }
          if (s.risk === 'danger') { badgeColor = 'rgba(239, 68, 68, 0.2)'; textColor = '#EF4444'; }

          return `<span style="display: inline-block; background: ${badgeColor}; color: ${textColor}; padding: 1px 6px; border-radius: 4px; font-size: 10px; font-weight: 700; margin: 1px 2px; cursor: pointer;" title="Port ${s.port} (${s.name}) - Click to connect" onclick="${clickAction}">${s.name}:${s.port}</span>`;
        }).join('');
      } else {
        serviceBadges = '<span style="color: var(--text-dim); font-size: 10px;">None probed</span>';
      }

      const latencyDisplay = (h.latencyMs !== null && h.latencyMs !== undefined)
        ? `<div style="color: #34D399; font-weight: 600;">${h.latencyMs} ms</div>${h.latencySource ? `<div style="font-size: 9px; color: #64748B;">[${h.latencySource}]</div>` : ''}`
        : (h.status === 'UNRESPONSIVE' ? `<span style="color: #64748B; font-size: 10px;">timed out</span>` : `<span style="color: var(--text-dim);">&lt;1 ms</span>`);

      const hasMac = Boolean(h.macAddress && h.macAddress !== 'Unknown' && h.macAddress !== 'N/A' && h.macAddress !== '00:00:00:00:00:00' && h.macAddress !== '— (No MAC Observed)');
      const macDisplay = hasMac ? escapeHtml(h.macAddress) : '—';
      const vendorDisplay = hasMac ? escapeHtml(h.vendor || h.manufacturer || 'Standard Network Device') : '— (No MAC Observed)';
      const eqIcon = h.equipmentProfile?.icon ? `${h.equipmentProfile.icon} ` : '';
      const categoryDisplay = escapeHtml(eqIcon + (h.equipmentProfile?.equipmentLabel || h.category || (h.status === 'ONLINE' ? 'Network Endpoint' : 'Unoccupied / Silent IP')));

      return `
        <tr>
          <td class="col-nowrap" style="text-align: center; white-space: nowrap;">${statusDot}</td>
          <td>
            <div style="font-weight: 700; color: #E2E8F0;">${escapeHtml(h.hostname || h.ip)}</div>
            ${h.computerName ? `<div style="font-size: 9.5px; color: #38BDF8;">[${escapeHtml(h.nameSource || (h.reverseDns ? 'PTR' : 'NetBIOS'))}: ${escapeHtml(h.computerName)}]</div>` : ''}
          </td>
          <td class="col-ip" style="white-space: nowrap; font-weight: 700; color: var(--accent);">${escapeHtml(h.ip)}</td>
          <td class="col-nowrap" style="white-space: nowrap; color: #94A3B8;">${macDisplay}</td>
          <td style="color: #CBD5E1;">${vendorDisplay}</td>
          <td class="col-nowrap" style="white-space: nowrap;">${categoryDisplay}</td>
          <td>${serviceBadges}</td>
          <td class="col-nowrap" style="white-space: nowrap;">${latencyDisplay}</td>
          <td class="col-nowrap" style="white-space: nowrap;">
            <div style="display: flex; gap: 4px; align-items: center;">
              <button class="btn btn-secondary" onclick="window.diagnoseOfficeEquipmentModal('${h.ip}', '${h.equipmentProfile?.equipmentType || ''}', '${escapeAttr(h.hostname || '')}', '${h.macAddress || ''}', '${escapeAttr(h.vendor || '')}')" style="font-size: 10px; padding: 2px 6px; font-weight: 700; color: #a78bfa;" title="Plain-language diagnostic & 4-hop visual smart connection map">🩺 Diagnose</button>
              <button class="btn btn-secondary" onclick="window.inspectHostDeep('${h.ip}')" style="font-size: 10px; padding: 2px 6px; font-weight: 700; color: #38bdf8;" title="Execute deep 15-port enterprise inspection, OUI vendor, and OS fingerprint">🔬 Inspect</button>
              <button class="btn btn-secondary" onclick="window.sniffHostOnWire('${h.ip}')" style="font-size: 10px; padding: 2px 6px;" title="Set BPF filter to host ${h.ip} and switch to Live Packet Sniffer">🦈 Sniff</button>
              <button class="btn btn-secondary" onclick="window.addHostToTopology('${h.ip}', '${h.hostname}', '${h.macAddress}', '${h.vendor}')" style="font-size: 10px; padding: 2px 6px;" title="Register host into dynamic Layer 1-6 topology map">🗺️ Map</button>
              <button class="btn btn-secondary" onclick="window.sendWolToHost('${h.macAddress}')" style="font-size: 10px; padding: 2px 6px;" title="Transmit Wake-on-LAN magic packet">⏰ WOL</button>
              <button class="btn btn-secondary" onclick="window.copySmbSharePath('${h.ip}')" style="font-size: 10px; padding: 2px 6px;" title="Copy \\\\${h.ip} SMB share path">📂 Share</button>
            </div>
          </td>
        </tr>
      `;
    }).join('');
  }

  // Deep Host Inspection Drawer (Section 3)
  window.inspectHostDeep = async function(ip) {
    let modal = document.getElementById('deepInspectHostModal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'deepInspectHostModal';
      modal.style.cssText = 'position: fixed; inset: 0; background: rgba(0,0,0,0.8); display: flex; align-items: center; justify-content: center; z-index: 99999; backdrop-filter: blur(4px);';
      document.body.appendChild(modal);
    }
    modal.style.display = 'flex';
    modal.innerHTML = `
      <div style="background: #0f172a; border: 1px solid #334155; border-radius: 10px; width: 680px; max-width: 95vw; max-height: 90vh; overflow-y: auto; padding: 24px; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.7); color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif;">
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 12px; margin-bottom: 16px;">
          <div>
            <h3 style="margin: 0; font-size: 16px; font-weight: 700; color: #38bdf8;">🔬 Deep Host Intelligence &amp; Inspection</h3>
            <div style="font-size: 12px; color: #94a3b8;">Target Host: <b style="color: #38bdf8;">${escapeHtml(ip)}</b></div>
          </div>
          <button onclick="document.getElementById('deepInspectHostModal').style.display='none'" style="background: none; border: none; color: #94a3b8; font-size: 20px; cursor: pointer; padding: 4px 8px;">✕</button>
        </div>
        <div id="deepInspectContent" style="text-align: center; padding: 30px; color: #94a3b8;">
          <div style="font-size: 24px; margin-bottom: 10px;">⚙️</div>
          <div>Probing 15 Enterprise Ports, Reverse PTR, OUI Vendor, OS Fingerprint &amp; Latency Jitter...</div>
        </div>
      </div>
    `;

    try {
      const res = await window.api('/api/network/scanner/inspect-host', {
        method: 'POST',
        body: JSON.stringify({ ip })
      });

      const content = document.getElementById('deepInspectContent');
      if (!content) return;

      if (!res.success) {
        content.innerHTML = `<div style="color: #ef4444; padding: 20px;">❌ Inspection Failed: ${escapeHtml(res.error || 'Unknown error')}</div>`;
        return;
      }

      const openServicesHtml = res.openServices && res.openServices.length > 0
        ? res.openServices.map(s => `<span style="background: rgba(56, 189, 248, 0.2); color: #38bdf8; padding: 3px 8px; border-radius: 4px; font-weight: 700; font-size: 11px;">Port ${s.port} (${escapeHtml(s.service)})</span>`).join(' ')
        : '<span style="color: #64748b; font-size: 12px;">No probed enterprise ports open.</span>';

      content.innerHTML = `
        <div style="text-align: left; display: flex; flex-direction: column; gap: 12px; font-size: 12px;">
          <!-- Top Row Summary -->
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
            <div style="background: #1e293b; padding: 12px; border-radius: 6px;">
              <div style="color: #94a3b8; font-size: 11px;">Hostname</div>
              <div style="font-weight: 700; font-size: 14px; color: #f8fafc; margin-top: 2px;">${escapeHtml(res.hostname || res.ip)}</div>
            </div>
            <div style="background: #1e293b; padding: 12px; border-radius: 6px;">
              <div style="color: #94a3b8; font-size: 11px;">Hardware OUI Vendor</div>
              <div style="font-weight: 700; font-size: 14px; color: #f8fafc; margin-top: 2px;">${escapeHtml(res.vendor || 'Unknown')}</div>
              <div style="color: #64748b; font-size: 10px; font-family: monospace;">${escapeHtml(res.macAddress || 'Unknown MAC')}</div>
            </div>
          </div>

          <!-- OS Fingerprint & Latency -->
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
            <div style="background: #1e293b; padding: 12px; border-radius: 6px;">
              <div style="color: #94a3b8; font-size: 11px;">Estimated OS Family</div>
              <div style="font-weight: 700; font-size: 13px; color: #a78bfa; margin-top: 2px;">${escapeHtml(res.osEstimate.os)}</div>
              <div style="color: #64748b; font-size: 10px;">Confidence: <b>${res.osEstimate.confidence}</b></div>
            </div>
            <div style="background: #1e293b; padding: 12px; border-radius: 6px;">
              <div style="color: #94a3b8; font-size: 11px;">Latency Jitter Telemetry (4 probes)</div>
              <div style="font-weight: 700; font-size: 13px; color: #34d399; margin-top: 2px;">Avg: ${res.pingStats.avgLatencyMs !== null ? `${res.pingStats.avgLatencyMs}ms` : '—'} (Jitter: ${res.pingStats.jitterMs}ms)</div>
              <div style="color: #64748b; font-size: 10px;">Loss: ${res.pingStats.packetLossPct}% (Min: ${res.pingStats.minLatencyMs}ms / Max: ${res.pingStats.maxLatencyMs}ms)</div>
            </div>
          </div>

          <!-- Open Enterprise Ports -->
          <div style="background: #1e293b; padding: 12px; border-radius: 6px;">
            <div style="color: #94a3b8; font-size: 11px; margin-bottom: 6px;">Open Enterprise Ports (${res.openServices ? res.openServices.length : 0} discovered)</div>
            <div style="display: flex; flex-wrap: wrap; gap: 6px;">
              ${openServicesHtml}
            </div>
          </div>

          <!-- Footer Action Buttons -->
          <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 8px;">
            <button class="btn btn-secondary" onclick="document.getElementById('deepInspectHostModal').style.display='none'">Close</button>
            <button class="btn btn-primary" onclick="document.getElementById('deepInspectHostModal').style.display='none'; window.sniffHostOnWire('${escapeAttr(res.ip)}');" style="font-weight: 700; background: #0284c7; border-color: #38bdf8;">🦈 Sniff Host in Wireshark</button>
          </div>
        </div>
      `;
    } catch (e) {
      const content = document.getElementById('deepInspectContent');
      if (content) content.innerHTML = `<div style="color: #ef4444; padding: 20px;">Request failed: ${escapeHtml(e.message)}</div>`;
    }
  };

  // 1-Click NOC Operations
  window.autoDetectSubnet = async function() {
    const input = document.getElementById('scannerSubnetInput');
    if (!input) return;
    try {
      const res = await window.api('/api/network/physical-info');
      if (res?.subnetCidr) {
        input.value = res.subnetCidr;
      }
    } catch (e) {
      console.warn('Auto-detect subnet failed:', e);
    }
  };

  window.sniffHostOnWire = function(ip) {
    if (typeof window.applyBpfFromScanner === 'function') {
      window.applyBpfFromScanner(`host ${ip}`);
    } else {
      window.renderView('packet-sniffer');
      setTimeout(() => {
        const bpfInput = document.getElementById('nocBpfInput');
        if (bpfInput) {
          bpfInput.value = `host ${ip}`;
          if (typeof window.applyNocBpfFilter === 'function') window.applyNocBpfFilter();
        }
        const dispInput = document.getElementById('displayFilterInput');
        if (dispInput) {
          dispInput.value = `ip.addr == ${ip}`;
          if (typeof window.applyDisplayFilter === 'function') window.applyDisplayFilter();
        }
      }, 200);
    }
  };

  window.addHostToTopology = async function(ip, hostname, mac, vendor) {
    try {
      const res = await window.api('/api/network/scanner/add-to-topology', {
        method: 'POST',
        body: JSON.stringify({ ip, hostname, mac, vendor, category: 'workstation' })
      });
      alert(res.message || `Host ${ip} registered into Topology.`);
    } catch (err) {
      alert('Failed to add to topology: ' + err.message);
    }
  };

  window.sendWolToHost = async function(mac) {
    if (!mac || mac === 'Unknown') {
      return alert('Valid physical MAC address required to transmit Wake-on-LAN magic packet.');
    }
    try {
      const res = await window.api('/api/network/scanner/wol', {
        method: 'POST',
        body: JSON.stringify({ macAddress: mac })
      });
      alert(`⚡ Wake-on-LAN Magic Packet (102 Bytes) successfully broadcasted to ${mac}!`);
    } catch (err) {
      alert('Wake-on-LAN failed: ' + err.message);
    }
  };

  window.copySmbSharePath = function(ip) {
    window.navigator.clipboard.writeText(`\\\\${ip}`);
    alert(`SMB UNC Path "\\\\${ip}" copied to clipboard.`);
  };

  // Export handlers
  window.exportScannerCsv = function() {
    if (currentScanResults.length === 0) return alert('No scan data available to export.');
    let csv = 'Status,IP,Hostname,NetBIOS,MAC,Vendor,Category,Latency_ms,Open_Ports\n';
    for (const h of currentScanResults) {
      const ports = (h.openServices || []).map(s => `${s.name}:${s.port}`).join(';');
      csv += `"${h.status}","${h.ip}","${h.hostname || ''}","${h.computerName || ''}","${h.macAddress || ''}","${h.vendor || ''}","${h.category || ''}","${h.latencyMs || ''}","${ports}"\n`;
    }
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ejii-fleet-inventory-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  window.exportScannerJson = function() {
    if (currentScanResults.length === 0) return alert('No scan data available to export.');
    const jsonStr = JSON.stringify(currentScanResults, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ejii-fleet-inventory-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  window.printScannerReport = function() {
    window.print();
  };

  // Quick APIPA & Office Device Troubleshooter
  window.quickDiagnoseOfficeDevice = function() {
    const input = document.getElementById('apipaQuickDiagInput');
    const val = (input?.value || '').trim();
    if (!val) {
      return alert('Please enter a target IP (e.g. 169.254.45.12 or printer IP).');
    }
    window.diagnoseOfficeEquipmentModal(val, 'PRINTER', 'Office Device', '', '');
  };

  // Visual Connection Path & Plain-Language Problem Resolver Modal
  window.diagnoseOfficeEquipmentModal = async function(ip, deviceType = '', name = '', mac = '', vendor = '') {
    let modal = document.getElementById('officeDeviceDiagnoseModal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'officeDeviceDiagnoseModal';
      modal.style.cssText = 'position: fixed; inset: 0; background: rgba(0,0,0,0.85); display: flex; align-items: center; justify-content: center; z-index: 99999; backdrop-filter: blur(4px);';
      document.body.appendChild(modal);
    }
    modal.style.display = 'flex';
    modal.innerHTML = `
      <div style="background: #0f172a; border: 1px solid #334155; border-radius: 12px; width: 780px; max-width: 95vw; max-height: 90vh; overflow-y: auto; padding: 24px; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.8); color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif;">
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 12px; margin-bottom: 16px;">
          <div style="display: flex; align-items: center; gap: 10px;">
            <span style="font-size: 24px;">🩺</span>
            <div>
              <h3 style="margin: 0; font-size: 16px; font-weight: 800; color: #38bdf8;">Visual Smart Path &amp; Plain-Language Problem Resolver</h3>
              <div style="font-size: 11px; color: #94a3b8;">Target Device: <b style="color: #38bdf8;">${escapeHtml(ip)}</b> ${name ? `(${escapeHtml(name)})` : ''}</div>
            </div>
          </div>
          <div style="display: flex; align-items: center; gap: 8px;">
            <button onclick="window.diagnoseOfficeEquipmentModal('${escapeAttr(ip)}', '${escapeAttr(deviceType)}', '${escapeAttr(name)}', '${escapeAttr(mac)}', '${escapeAttr(vendor)}')" class="btn btn-secondary" style="font-size: 11px; padding: 4px 10px; display: inline-flex; align-items: center; gap: 4px; background: rgba(56, 189, 248, 0.15); border: 1px solid #0284c7; color: #38bdf8; border-radius: 6px; cursor: pointer;">
              ↻ Re-Test Device Now
            </button>
            <button onclick="document.getElementById('officeDeviceDiagnoseModal').style.display='none'" style="background: none; border: none; color: #94a3b8; font-size: 20px; cursor: pointer; padding: 4px 8px;">✕</button>
          </div>
        </div>
        <div id="officeDiagLoading" style="text-align: center; padding: 40px; color: #94a3b8;">
          <div style="font-size: 28px; margin-bottom: 12px;">⚙️</div>
          <div>Tracing 4-hop physical connection path, probing RFC 3927 link-local state, and synthesizing plain-language repair plan...</div>
        </div>
        <div id="officeDiagContent" style="display: none; flex-direction: column; gap: 16px;"></div>
      </div>
    `;

    try {
      const res = await window.api('/api/network/office-device/diagnose', {
        method: 'POST',
        body: JSON.stringify({
          targetIp: ip,
          deviceTypeHint: deviceType,
          deviceName: name,
          macAddress: mac,
          vendor
        })
      });

      const loading = document.getElementById('officeDiagLoading');
      const content = document.getElementById('officeDiagContent');
      if (loading) loading.style.display = 'none';
      if (content) {
        content.style.display = 'flex';

        // Section A: Visual Connection Path
        const pathHops = (res.visualConnectionPath || []).map((hop, idx) => {
          const isBroken = hop.status === 'BROKEN';
          const badgeBg = isBroken ? '#ef4444' : '#10b981';
          const badgeText = isBroken ? '✕ BROKEN HERE' : '● OK';
          const icon = hop.icon || '📦';
          const arrow = idx < res.visualConnectionPath.length - 1 ? `<span style="color: ${isBroken ? '#ef4444' : '#64748b'}; font-size: 16px; font-weight: 800; margin: 0 4px;">───▶</span>` : '';

          return `
            <div style="display: flex; align-items: center; gap: 6px;">
              <div style="background: ${isBroken ? 'rgba(239, 68, 68, 0.15)' : 'rgba(15, 23, 42, 0.8)'}; border: 1px solid ${isBroken ? '#ef4444' : '#334155'}; border-radius: 8px; padding: 10px 12px; min-width: 130px; text-align: center; box-shadow: ${isBroken ? '0 0 12px rgba(239,68,68,0.3)' : 'none'};">
                <div style="font-size: 20px; margin-bottom: 4px;">${icon}</div>
                <div style="font-size: 11px; font-weight: 700; color: ${isBroken ? '#fca5a5' : '#e2e8f0'};">${escapeHtml(hop.title || hop.name || 'Network Hop')}</div>
                <div style="font-size: 10px; color: #94a3b8; font-family: var(--font-mono);">${escapeHtml(hop.ip || hop.role || '')}</div>
                <span style="display: inline-block; margin-top: 6px; background: ${badgeBg}; color: #fff; font-size: 9px; font-weight: 800; padding: 1px 6px; border-radius: 4px;">${badgeText}</span>
              </div>
              ${arrow}
            </div>
          `;
        }).join('');

        // Section B: Plain Language Summary
        const plain = res.plainLanguageDiagnosis || {};
        const steps = (plain.stepByStepFixPlan || []).map((s, i) => `
          <li style="margin-bottom: 8px; color: #cbd5e1; font-size: 12px; line-height: 1.5;">
            <b style="color: #38bdf8;">Step ${i + 1}:</b> ${escapeHtml(s)}
          </li>
        `).join('');

        content.innerHTML = `
          <!-- Section A: Visual Connection Path -->
          <div style="background: rgba(30, 41, 59, 0.6); border: 1px solid #334155; border-radius: 8px; padding: 14px;">
            <div style="font-size: 12px; font-weight: 700; color: #38bdf8; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 12px;">
              Section A: Visual Connection Path (Smart Map)
            </div>
            <div style="display: flex; align-items: center; justify-content: space-between; overflow-x: auto; padding: 8px 4px;">
              ${pathHops}
            </div>
          </div>

          <!-- Section B: Automated Problem Resolver -->
          <div style="display: flex; flex-direction: column; gap: 12px;">
            <div style="background: rgba(239, 68, 68, 0.08); border-left: 4px solid #ef4444; border-radius: 4px; padding: 12px 16px;">
              <div style="font-size: 11px; font-weight: 700; color: #f87171; text-transform: uppercase; margin-bottom: 4px;">
                1. What the Problem Is
              </div>
              <div style="font-size: 13px; font-weight: 600; color: #f1f5f9; line-height: 1.4;">
                ${escapeHtml(plain.whatTheProblemIs || 'Connectivity failure detected on target device.')}
              </div>
            </div>

            <div style="background: rgba(245, 158, 11, 0.08); border-left: 4px solid #f59e0b; border-radius: 4px; padding: 12px 16px;">
              <div style="font-size: 11px; font-weight: 700; color: #fbbf24; text-transform: uppercase; margin-bottom: 4px;">
                2. Why It Happened (Root Cause)
              </div>
              <div style="font-size: 12px; color: #cbd5e1; line-height: 1.5;">
                ${escapeHtml(plain.whyItHappened || 'Device was unable to complete DHCP handshake or communicate with local gateway.')}
              </div>
            </div>

            <div style="background: rgba(56, 189, 248, 0.08); border-left: 4px solid #38bdf8; border-radius: 4px; padding: 12px 16px;">
              <div style="font-size: 11px; font-weight: 700; color: #38bdf8; text-transform: uppercase; margin-bottom: 8px;">
                3. Step-by-Step Plan on How to Fix It
              </div>
              <ol style="margin: 0; padding-left: 18px;">
                ${steps}
              </ol>
            </div>
          </div>

          <!-- Quick Action Buttons -->
          <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-top: 4px; border-top: 1px solid #1e293b; padding-top: 14px;">
            <button class="btn btn-primary" onclick="window.runQuickScriptAction('restart-print-spooler.ps1')" style="font-size: 11px; padding: 6px 12px;">
              🔄 Restart Print Spooler
            </button>
            <button class="btn btn-secondary" onclick="window.runQuickScriptAction('flush-dns-cache.ps1')" style="font-size: 11px; padding: 6px 12px;">
              🌐 Flush DNS &amp; Renew IP
            </button>
            <button class="btn btn-secondary" onclick="window.inspectHostDeep('${escapeAttr(ip)}')" style="font-size: 11px; padding: 6px 12px; color: #38bdf8;">
              🔬 Deep 15-Port Host Inspection
            </button>
          </div>
        `;
      }
    } catch (err) {
      const content = document.getElementById('officeDiagContent');
      const loading = document.getElementById('officeDiagLoading');
      if (loading) loading.style.display = 'none';
      if (content) {
        content.style.display = 'block';
        content.innerHTML = `
          <div style="background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; border-radius: 8px; padding: 16px; color: #fca5a5;">
            <b>Diagnostic Error:</b> ${escapeHtml(err.message)}
          </div>
        `;
      }
    }
  };

  window.runQuickScriptAction = async function(scriptName) {
    try {
      const res = await window.api('/api/network/automation/execute', {
        method: 'POST',
        body: JSON.stringify({ scriptName })
      });
      alert(`Script "${scriptName}" executed successfully.\nOutput:\n${res.stdout || res.output || 'Execution complete.'}`);
    } catch (err) {
      alert(`Failed to execute script "${scriptName}": ${err.message}`);
    }
  };

  window.checkLocalPrintSpoolerModal = async function() {
    let modal = document.getElementById('localSpoolerModal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'localSpoolerModal';
      modal.style.cssText = 'position: fixed; inset: 0; background: rgba(0,0,0,0.85); display: flex; align-items: center; justify-content: center; z-index: 99999; backdrop-filter: blur(4px);';
      document.body.appendChild(modal);
    }
    modal.style.display = 'flex';
    modal.innerHTML = `
      <div style="background: #0f172a; border: 1px solid #334155; border-radius: 12px; width: 720px; max-width: 95vw; max-height: 90vh; overflow-y: auto; padding: 24px; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.8); color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif;">
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 12px; margin-bottom: 16px;">
          <div style="display: flex; align-items: center; gap: 10px;">
            <span style="font-size: 24px;">🖨️</span>
            <div>
              <h3 style="margin: 0; font-size: 16px; font-weight: 800; color: #38bdf8;">Windows Print Spooler &amp; Local Printer Health</h3>
              <div style="font-size: 11px; color: #94a3b8;">Local Workstation Host Print Architecture Inspection</div>
            </div>
          </div>
          <button onclick="document.getElementById('localSpoolerModal').style.display='none'" style="background: none; border: none; color: #94a3b8; font-size: 20px; cursor: pointer; padding: 4px 8px;">✕</button>
        </div>
        <div id="spoolerModalBody" style="padding: 20px 0;">
          <div style="text-align: center; color: #94a3b8;">Inspecting Windows Spooler service, local queues, and port bindings...</div>
        </div>
      </div>
    `;

    try {
      const data = await window.api('/api/network/office-device/local-spooler');
      const bodyEl = document.getElementById('spoolerModalBody');
      if (!bodyEl) return;

      const isRunning = (data.spoolerServiceStatus || '').toLowerCase() === 'running';
      const statusColor = isRunning ? '#10b981' : '#ef4444';

      let printersHtml = '';
      if (Array.isArray(data.printers) && data.printers.length > 0) {
        printersHtml = data.printers.map(p => `
          <div style="background: rgba(30, 41, 59, 0.6); border: 1px solid #334155; border-radius: 8px; padding: 12px; margin-bottom: 8px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <b style="color: #f1f5f9;">${escapeHtml(p.name)}</b>
              <span style="font-size: 11px; background: rgba(56, 189, 248, 0.15); color: #38bdf8; padding: 2px 8px; border-radius: 4px;">Port: ${escapeHtml(p.portName)}</span>
            </div>
            <div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">Driver: ${escapeHtml(p.driverName)} | Status: ${escapeHtml(p.printerStatus)} | Jobs in Queue: <b>${p.jobCount}</b></div>
            ${p.isWsdPort ? '<div style="font-size: 11px; color: #fbbf24; margin-top: 6px;">⚠️ Warning: Configured on WSD port. May drop offline on IP changes; configure Standard TCP/IP port instead.</div>' : ''}
          </div>
        `).join('');
      } else {
        printersHtml = '<div style="color: #94a3b8; font-style: italic;">No local printers installed or detected.</div>';
      }

      bodyEl.innerHTML = `
        <div style="display: flex; gap: 16px; margin-bottom: 16px;">
          <div style="flex: 1; background: rgba(15, 23, 42, 0.6); border: 1px solid #334155; border-radius: 8px; padding: 12px;">
            <div style="font-size: 11px; color: #64748b;">SPOOLER SERVICE</div>
            <div style="font-size: 18px; font-weight: bold; color: ${statusColor};">${escapeHtml(data.spoolerServiceStatus)}</div>
          </div>
          <div style="flex: 1; background: rgba(15, 23, 42, 0.6); border: 1px solid #334155; border-radius: 8px; padding: 12px;">
            <div style="font-size: 11px; color: #64748b;">STUCK / PENDING JOBS</div>
            <div style="font-size: 18px; font-weight: bold; color: ${data.stuckJobsCount > 0 ? '#f59e0b' : '#10b981'};">${data.stuckJobsCount}</div>
          </div>
          <div style="flex: 1; background: rgba(15, 23, 42, 0.6); border: 1px solid #334155; border-radius: 8px; padding: 12px;">
            <div style="font-size: 11px; color: #64748b;">WSD PORT WARNING</div>
            <div style="font-size: 18px; font-weight: bold; color: ${data.wsdPortWarning ? '#f59e0b' : '#10b981'};">${data.wsdPortWarning ? 'YES' : 'NONE'}</div>
          </div>
        </div>
        <div style="margin-bottom: 16px; padding: 12px; background: rgba(30, 41, 59, 0.4); border-radius: 8px; font-size: 13px; color: #cbd5e1;">
          ${escapeHtml(data.plainSummary || '')}
        </div>
        <h4 style="margin: 0 0 8px 0; font-size: 13px; color: #94a3b8; text-transform: uppercase;">Installed Printers (${data.printers?.length || 0})</h4>
        ${printersHtml}
      `;
    } catch (err) {
      const bodyEl = document.getElementById('spoolerModalBody');
      if (bodyEl) {
        bodyEl.innerHTML = `<div style="color: #ef4444;">Error inspecting print spooler: ${escapeHtml(err.message)}</div>`;
      }
    }
  };

})(window);
