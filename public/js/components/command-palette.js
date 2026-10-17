/**
 * EJI Global Command Palette (Ctrl+K)
 * Enterprise keyboard-driven navigation and operational action dispatcher.
 */

(function(window) {
  'use strict';

  let isOpen = false;
  let selectedIndex = 0;
  let currentResults = [];

  const STATIC_COMMANDS = [
    // Dedicated NOC Workstations
    { id: 'view-topology', category: 'Navigation', title: 'Go to NOC Topology & Device Graph (Pillar 1)', icon: '🗺️', action: () => window.renderView('topology') },
    { id: 'view-sniffer', category: 'Navigation', title: 'Go to Live Wire Packet Sniffer & NirSoft Flow Matrix (Pillars 2 & 3)', icon: '📡', action: () => window.renderView('packet-sniffer') },
    { id: 'view-diagnostics', category: 'Navigation', title: 'Go to 4-Pillar Host Diagnostics & AI Brain (Pillar 4)', icon: '🧠', action: () => window.renderView('core-diagnostics') },
    { id: 'view-scanner', category: 'Navigation', title: 'Go to Ultra IP & Fleet Scanner (Pillar 6)', icon: '🔍', action: () => window.renderView('ultra-ip-scanner') },
    { id: 'view-automation', category: 'Navigation', title: 'Go to Local PC Automation & Safe BAT Execution (Pillar 7)', icon: '⚙️', action: () => window.renderView('pc-automation') },

    // Real Operational Actions
    { id: 'act-discover-topology', category: 'Action', title: 'Run L2/L3 Network Topology Auto-Discovery', icon: '🔄', action: async () => {
      try {
        const res = await window.api('/api/network/topology/discover', { method: 'POST' });
        alert(`Discovery initiated: Found ${res.discoveredCount || (res.topology && res.topology.nodes ? res.topology.nodes.length : 0)} active network devices.`);
        if (window.renderView) window.renderView('topology');
      } catch (e) { alert('Topology discovery failed: ' + e.message); }
    }},
    { id: 'act-host-audit', category: 'Action', title: 'Execute 4-Pillar Host Diagnostics System Audit', icon: '📊', action: async () => {
      try {
        const res = await window.api('/api/diagnostics/host/audit');
        alert(`Host Audit Complete!\nOverall Status: ${res.overallStatus || 'OK'}\nNetwork: ${res.pillars?.network?.status || 'HEALTHY'}\nStorage: ${res.pillars?.storage?.status || 'HEALTHY'}\nResource: ${res.pillars?.resource?.status || 'HEALTHY'}`);
        if (window.renderView) window.renderView('core-diagnostics');
      } catch (e) { alert('Host audit failed: ' + e.message); }
    }},
    { id: 'act-audit-verify', category: 'Action', title: 'Verify Cryptographic Remediation & Audit Chain', icon: '🔐', action: async () => {
      try {
        const res = await window.api('/api/diagnostics/remediation/audit-verify');
        alert(`Audit Integrity: ${res.valid ? 'VALID ✓' : 'BROKEN ⚠️'}\n${res.message || 'Chain intact.'}`);
      } catch (e) { alert('Audit verification failed: ' + e.message); }
    }},
    { id: 'act-wire-diagnostics', category: 'Action', title: 'Open Isolated Wire Diagnostics Hub (Zero Elevation)', icon: '🛠️', action: () => {
      if (typeof window.openWireDiagnosticsModal === 'function') window.openWireDiagnosticsModal();
    }},
    { id: 'act-dissect-sample', category: 'Action', title: 'Dissect Live TCP/IP Packet in Sniffer', icon: '🔬', action: () => {
      window.renderView('packet-sniffer');
      setTimeout(() => { if (typeof window.runPacketDissection === 'function') window.runPacketDissection(); }, 200);
    }},
    { id: 'act-incident-standard', category: 'Operational Guide', title: 'Open Incident Reporting Standard (mail.taxes.gov.az)', icon: '📢', action: () => {
      if (typeof window.toggleJuniorAdminCheatSheet === 'function') {
        window.toggleJuniorAdminCheatSheet();
        if (typeof window.switchManualTab === 'function') window.switchManualTab('standard');
      }
    }}
  ];

  function openPalette() {
    const modal = document.getElementById('commandPalette');
    const input = document.getElementById('commandPaletteInput');
    if (!modal || !input) return;

    isOpen = true;
    modal.style.display = 'flex';
    input.value = '';
    input.focus();
    selectedIndex = 0;
    renderResults(STATIC_COMMANDS);
  }

  function closePalette() {
    const modal = document.getElementById('commandPalette');
    if (!modal) return;
    isOpen = false;
    modal.style.display = 'none';
  }

  function renderResults(items) {
    currentResults = items;
    const list = document.getElementById('commandPaletteResults');
    if (!list) return;

    if (items.length === 0) {
      list.innerHTML = `<li style="padding: 16px; text-align: center; color: var(--text-dim);">No matching commands or entities found</li>`;
      return;
    }

    list.innerHTML = items.map((item, idx) => `
      <li class="command-palette-item ${idx === selectedIndex ? 'selected' : ''}" data-idx="${idx}">
        <div style="display: flex; align-items: center; gap: 10px;">
          <span style="font-size: 16px;">${item.icon || '⚡'}</span>
          <div>
            <div style="font-weight: 500; font-size: 13px;">${item.title}</div>
            <div style="font-size: 10px; color: var(--text-dim); text-transform: uppercase;">${item.category}</div>
          </div>
        </div>
        <span class="command-palette-kbd">↵ Select</span>
      </li>
    `).join('');

    // Attach click handlers
    list.querySelectorAll('.command-palette-item').forEach(el => {
      el.addEventListener('click', () => {
        const idx = parseInt(el.dataset.idx, 10);
        executeItem(currentResults[idx]);
      });
    });
  }

  function executeItem(item) {
    if (!item) return;
    closePalette();
    if (typeof item.action === 'function') {
      item.action();
    }
  }

  function filterItems(query) {
    const q = query.toLowerCase().trim();
    if (!q) {
      renderResults(STATIC_COMMANDS);
      return;
    }

    const filtered = STATIC_COMMANDS.filter(item =>
      item.title.toLowerCase().includes(q) ||
      item.category.toLowerCase().includes(q)
    );

    selectedIndex = 0;
    renderResults(filtered);
  }

  function initCommandPalette() {
    window.addEventListener('keydown', (e) => {
      // Ctrl+K or Cmd+K
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        if (isOpen) closePalette();
        else openPalette();
      }

      if (!isOpen) return;

      if (e.key === 'Escape') {
        e.preventDefault();
        closePalette();
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (currentResults.length > 0) {
          selectedIndex = (selectedIndex + 1) % currentResults.length;
          renderResults(currentResults);
        }
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (currentResults.length > 0) {
          selectedIndex = (selectedIndex - 1 + currentResults.length) % currentResults.length;
          renderResults(currentResults);
        }
      } else if (e.key === 'Enter') {
        e.preventDefault();
        if (currentResults[selectedIndex]) {
          executeItem(currentResults[selectedIndex]);
        }
      }
    });

    const input = document.getElementById('commandPaletteInput');
    if (input) {
      input.addEventListener('input', (e) => filterItems(e.target.value));
    }

    const backdrop = document.getElementById('commandPalette');
    if (backdrop) {
      backdrop.addEventListener('click', (e) => {
        if (e.target === backdrop) closePalette();
      });
    }

    const btn = document.getElementById('btnOpenCommandPalette');
    if (btn) {
      btn.addEventListener('click', openPalette);
    }
  }

  window.openCommandPalette = openPalette;
  window.closeCommandPalette = closePalette;
  window.initCommandPalette = initCommandPalette;

})(window);
