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
    // Views
    { id: 'view-eoc', category: 'Navigation', title: 'Go to Executive Operations Center (EOC)', icon: '🌐', action: () => window.renderView('eoc') },
    { id: 'view-itsm', category: 'Navigation', title: 'Go to ITSM Service Desk & SLAs', icon: '🎫', action: () => window.renderView('itsm') },
    { id: 'view-cmdb', category: 'Navigation', title: 'Go to Enterprise CMDB & IPAM', icon: '📦', action: () => window.renderView('cmdb') },
    { id: 'view-noc', category: 'Navigation', title: 'Go to NOC Topology & Packets', icon: '📡', action: () => window.renderView('noc') },
    { id: 'view-systems', category: 'Navigation', title: 'Go to Systems Admin Center (SAC)', icon: '🖥️', action: () => window.renderView('systems') },
    { id: 'view-observability', category: 'Navigation', title: 'Go to Observability & Alert Matrix', icon: '📊', action: () => window.renderView('observability') },
    { id: 'view-rca', category: 'Navigation', title: 'Go to Incident Intelligence & RCA', icon: '⚡', action: () => window.renderView('rca') },
    { id: 'view-automation', category: 'Navigation', title: 'Go to Safe Automation & Remediations', icon: '🛡️', action: () => window.renderView('automation') },
    { id: 'view-drift', category: 'Navigation', title: 'Go to Configuration Drift Intelligence', icon: '🔍', action: () => window.renderView('drift') },
    { id: 'view-chaos', category: 'Navigation', title: 'Go to Resilience & Chaos Lab', icon: '🧪', action: () => window.renderView('chaos') },
    { id: 'view-services', category: 'Navigation', title: 'Go to Business Service Catalog', icon: '🏢', action: () => window.renderView('services') },
    { id: 'view-governance', category: 'Navigation', title: 'Go to Audit, Security & Governance', icon: '🔒', action: () => window.renderView('governance') },

    // Operational Actions
    { id: 'act-control-loop', category: 'Action', title: 'Run 13-Stage Autonomous Control Loop Cycle', icon: '🔄', action: async () => {
      try {
        const res = await window.api('/api/control-loop/cycle', { method: 'POST', body: JSON.stringify({}) });
        alert(`Control Loop executed: ${res.finalState} in ${res.totalDurationMs}ms (Stages: ${Object.keys(res.stages).length})`);
        if (window.state && window.state.currentView === 'eoc') window.renderView('eoc');
      } catch (e) { alert('Control Loop failed: ' + e.message); }
    }},
    { id: 'act-sla-eval', category: 'Action', title: 'Trigger Real-Time SLA Breach Evaluation', icon: '⏱️', action: async () => {
      try {
        const res = await window.api('/api/itsm/sla-metrics');
        alert(`SLA Evaluation Complete: ${res.recentBreaches.breachedCount} new breaches found. Total Compliance: ${res.metrics.complianceRatePercent}%`);
        if (window.state && window.state.currentView === 'itsm') window.renderView('itsm');
      } catch (e) { alert('SLA Eval failed: ' + e.message); }
    }},
    { id: 'act-audit-verify', category: 'Action', title: 'Verify Cryptographic HMAC Audit Chain', icon: '🔐', action: async () => {
      try {
        const res = await window.api('/api/admin/audit-verify');
        alert(`HMAC Audit Integrity: ${res.valid ? 'VALID ✓' : 'BROKEN ⚠️'}\n${res.message}`);
      } catch (e) { alert('Audit verification failed: ' + e.message); }
    }},
    { id: 'act-dissect-sample', category: 'Action', title: 'Dissect Sample TCP/IP Frame in NOC', icon: '🔬', action: () => {
      window.renderView('noc');
      setTimeout(() => { if (typeof window.runPacketDissection === 'function') window.runPacketDissection(); }, 200);
    }},
    { id: 'act-incident-standard', category: 'Operational Guide', title: 'Open Incident Reporting Standard & Live Probe (mail.taxes.gov.az)', icon: '📢', action: () => {
      window.toggleJuniorAdminCheatSheet();
      window.switchManualTab('standard');
    }},
    { id: 'act-new-taxes-ticket', category: 'Action', title: 'Create Diagnostic Ticket for mail.taxes.gov.az', icon: '🎫', action: () => {
      window.renderView('itsm');
      setTimeout(() => {
        window.openNewTicketModal();
        setTimeout(() => window.fillTicketTaxesPreset(), 50);
      }, 200);
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
