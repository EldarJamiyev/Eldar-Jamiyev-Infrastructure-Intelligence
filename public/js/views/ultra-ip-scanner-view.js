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
              <button class="btn ${activeFilterChip === 'online' ? 'btn-primary' : 'btn-secondary'}" onclick="window.setScannerFilterChip('online')" style="font-size: 10px; padding: 2px 8px;">Online Only (<span id="chipCountOnline">0</span>)</button>
              <button class="btn ${activeFilterChip === 'gateways' ? 'btn-primary' : 'btn-secondary'}" onclick="window.setScannerFilterChip('gateways')" style="font-size: 10px; padding: 2px 8px;">🌐 Gateways &amp; Routers</button>
              <button class="btn ${activeFilterChip === 'servers' ? 'btn-primary' : 'btn-secondary'}" onclick="window.setScannerFilterChip('servers')" style="font-size: 10px; padding: 2px 8px;">🖥️ Servers / Windows</button>
              <button class="btn ${activeFilterChip === 'services' ? 'btn-primary' : 'btn-secondary'}" onclick="window.setScannerFilterChip('services')" style="font-size: 10px; padding: 2px 8px;">⚡ Exposed Services</button>
            </div>

            <div style="display: flex; align-items: center; gap: 8px;">
              <label style="display: flex; align-items: center; gap: 4px; font-size: 11px; color: var(--text-dim); cursor: pointer; user-select: none; margin-left: 6px;">
                <input type="checkbox" id="hideNoPingCheckbox" onchange="window.toggleHideNoPing(this.checked)">
                <span>Hide NO PING (Unresponsive)</span>
              </label>
              <input type="text" id="scannerSearchInput" class="form-input" placeholder="Search IP, hostname, vendor, port..." style="width: 220px; font-size: 11px; padding: 4px 8px;" oninput="window.onScannerSearchChange(this.value)">
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
    } else if (activeFilterChip === 'gateways') {
      filtered = filtered.filter(h => (h.category || '').includes('Gateway') || (h.category || '').includes('Router') || (h.category || '').includes('Switch'));
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
      const categoryDisplay = escapeHtml(h.category || (h.status === 'ONLINE' ? 'Network Endpoint' : 'Unoccupied / Silent IP'));

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

})(window);
