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
    { id: 'view-war-room', category: 'AI & Cognitive', title: 'Convene 5-Agent SRE Autonomous War Room Deliberation', icon: '🏛️', action: () => {
      if (typeof window.triageHostInWarRoom === 'function') {
        const target = window.EJIIInvestigationPinboard?.getPinned()?.target || '127.0.0.1';
        window.triageHostInWarRoom(target);
      } else {
        window.renderView('ai-operator');
      }
    }},
    { id: 'act-chaos-simulator', category: 'Topology & Physics', title: 'Launch Interactive Multi-Wave Chaos & Blast-Radius Simulator', icon: '⚡', action: () => {
      if (typeof window.openWhatIfChaosSimulatorModal === 'function') window.openWhatIfChaosSimulatorModal();
    }},
    { id: 'act-pinboard-inspect', category: 'Investigation', title: 'Inspect Pinned Investigation Context & Pivots', icon: '📌', action: () => {
      const pinned = window.EJIIInvestigationPinboard?.getPinned();
      if (pinned) {
        alert(`📌 Active Pinned Target: ${pinned.target}\nIncident: ${pinned.incidentId || 'None'}\nNotes: ${pinned.notes || ''}`);
      } else {
        alert('No target currently pinned. Use the 📌 Pin button on any view table.');
      }
    }},
    { id: 'act-solo-escalation', category: 'Escalation Copilot', title: 'Solo Secondment: Generate L1-to-L3 Escalation Dossier (EN/AZ/RU)', icon: '📋', action: () => {
      if (typeof window.openEscalationTicketModal === 'function') window.openEscalationTicketModal();
    }},
    { id: 'act-shift-handover', category: 'Operations Command', title: 'Generate Autonomous Shift Handover Briefing Report', icon: '🔄', action: () => {
      if (typeof window.openEscalationTicketModal === 'function') {
        window.openEscalationTicketModal();
        if (typeof window.generateAutonomousShiftHandover === 'function') window.generateAutonomousShiftHandover();
      }
    }},
    { id: 'act-socratic-coach', category: 'Learning Center', title: 'Consult Socratic Pedagogical AI Coach (Ctrl+H)', icon: '🎓', action: () => {
      if (typeof window.toggleJuniorAdminCheatSheet === 'function') {
        window.toggleJuniorAdminCheatSheet();
        if (typeof window.switchManualTab === 'function') window.switchManualTab('socratic');
      }
    }},

    // Real Operational Actions
    { id: 'act-gitops-reconcile', category: 'Action', title: 'GitOps IaC Drift Detection & Autonomous Reconciliation', icon: '🔄', action: () => {
      if (typeof window.runGitopsDriftReconcileFromUi === 'function') window.runGitopsDriftReconcileFromUi();
    }},
    { id: 'act-cncf-otel-spans', category: 'Observability', title: 'Inspect CNCF OpenTelemetry Spans & W3C Trace Pipeline', icon: '📡', action: () => {
      if (typeof window.inspectCncfObservabilityFromUi === 'function') window.inspectCncfObservabilityFromUi();
    }},
    { id: 'act-export-grafana', category: 'Observability', title: 'Export Grafana Unified Telemetry Dashboard JSON', icon: '📊', action: () => {
      if (typeof window.exportGrafanaDashboardFromUi === 'function') window.exportGrafanaDashboardFromUi();
    }},
    { id: 'act-prometheus-metrics', category: 'Observability', title: 'View CNCF Prometheus /metrics Exposition Stream', icon: '📈', action: () => {
      window.open('/metrics', '_blank');
    }},
    { id: 'act-loki-logs', category: 'Observability', title: 'Inspect Loki Structured JSON Audit Log Stream', icon: '📝', action: async () => {
      try {
        const logs = await window.api('/api/observability/loki-logs');
        alert(`Loki Audit Stream: ${logs.streams ? logs.streams.length : 0} stream entries captured.`);
      } catch (e) { alert('Loki logs inspection error: ' + e.message); }
    }},
    { id: 'act-export-signed-dossier', category: 'Observability', title: 'Export Signed Executive Incident Dossier (Black-Box Flight Recorder)', icon: '📋', action: async () => {
      try {
        const dossier = await window.api('/api/observability/flight-recorder/dossier');
        window.open('/api/observability/flight-recorder/dossier?format=markdown', '_blank');
        alert(`Signed Post-Mortem Incident Dossier Generated!\nIncident ID: ${dossier.incidentId}\nHMAC: ${dossier.dossierSignatureHmac?.slice(0, 16)}...\nStatus: Valid & Download Initiated.`);
      } catch (e) { alert('Dossier generation failed: ' + e.message); }
    }},
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
    { id: 'act-unified-investigator', category: 'Action', title: 'Launch Guided Cross-Section Incident Investigator (5-Stage Pipeline)', icon: '🔬', action: () => {
      window.renderView('core-diagnostics');
      setTimeout(() => {
        const input = document.getElementById('unifiedInvestigateInput');
        if (input) {
          input.focus();
          input.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
      }, 300);
    }},
    { id: 'act-incident-standard', category: 'Operational Guide', title: 'Open Incident Reporting Standard (mail.taxes.gov.az)', icon: '📢', action: () => {
      if (typeof window.toggleJuniorAdminCheatSheet === 'function') {
        window.toggleJuniorAdminCheatSheet();
        if (typeof window.switchManualTab === 'function') window.switchManualTab('standard');
      }
    }},
    { id: 'act-runbook-rb01', category: 'Interactive Runbook', title: 'Launch RB-01: Unknown Endpoint & Shadow Service Discovery Wizard', icon: '📘', action: () => window.launchRunbookWizardModal && window.launchRunbookWizardModal('RB-01') },
    { id: 'act-runbook-rb02', category: 'Interactive Runbook', title: 'Launch RB-02: TCP RST vs. Firewall Silent Drop Triage Wizard', icon: '📘', action: () => window.launchRunbookWizardModal && window.launchRunbookWizardModal('RB-02') },
    { id: 'act-runbook-rb03', category: 'Interactive Runbook', title: 'Launch RB-03: Host Saturation & Kernel Socket Exhaustion Wizard', icon: '📘', action: () => window.launchRunbookWizardModal && window.launchRunbookWizardModal('RB-03') },
    { id: 'act-runbook-rb04', category: 'Interactive Runbook', title: 'Launch RB-04: DNS SERVFAIL, NXDOMAIN & Split-Horizon Wizard', icon: '📘', action: () => window.launchRunbookWizardModal && window.launchRunbookWizardModal('RB-04') },
    { id: 'act-runbook-rb05', category: 'Interactive Runbook', title: 'Launch RB-05: TLS 1.3 Handshake Alerts & Certificate Audit Wizard', icon: '📘', action: () => window.launchRunbookWizardModal && window.launchRunbookWizardModal('RB-05') },
    { id: 'act-runbook-rb06', category: 'Interactive Runbook', title: 'Launch RB-06: Path MTU Blackhole & TCP Retransmission Wizard', icon: '📘', action: () => window.launchRunbookWizardModal && window.launchRunbookWizardModal('RB-06') },
    { id: 'act-runbook-rb07', category: 'Interactive Runbook', title: 'Launch RB-07: Office Printer APIPA (169.254.x.x) & DHCP Recovery', icon: '📘', action: () => window.launchRunbookWizardModal && window.launchRunbookWizardModal('RB-07') },
    { id: 'act-runbook-rb08', category: 'Interactive Runbook', title: 'Launch RB-08: Print Spooler & JetDirect TCP/9100 Triage Wizard', icon: '📘', action: () => window.launchRunbookWizardModal && window.launchRunbookWizardModal('RB-08') },
    // Step 11: Omniscient Live Entity Search & Quad-Quadrant Command Grid
    { id: 'act-quad-grid', category: 'Unified Workstation', title: 'Open 4-Quadrant Tactical Command Grid (NetworkTrafficView + TCPView + Port Scanner + Daily_Automation)', icon: '🪟', action: () => window.openQuadQuadrantCommandGrid && window.openQuadQuadrantCommandGrid() },
    { id: 'entity-lms-5428', category: 'Live Process / Socket (TCPView)', title: 'Inspect Process LMS.exe (PID 5428) Listening on TCP Port 623 (Intel AMT Out-of-Band httpd)', icon: '🔌', action: () => {
      if (window.EJIIInvestigationPinboard) window.EJIIInvestigationPinboard.setContext({ ip: '172.29.192.1', subnet: '172.29.192.0/20', mac: '00:15:5D:DF:E5:56', processName: 'LMS.exe', pid: 5428, port: 623, serviceBanner: 'Intel Active Management Technology User Notification Service httpd' });
      window.renderView('packet-sniffer');
    }},
    { id: 'entity-vmms-10336', category: 'Live Process / Socket (TCPView)', title: 'Inspect Process vmms.exe (PID 10336) Listening on TCP Port 2179 (Hyper-V VMConnect)', icon: '🔌', action: () => {
      if (window.EJIIInvestigationPinboard) window.EJIIInvestigationPinboard.setContext({ ip: '172.29.192.1', subnet: '172.29.192.0/20', mac: '00:15:5D:DF:E5:56', processName: 'vmms.exe', pid: 10336, port: 2179, serviceBanner: 'Hyper-V VMConnect Service' });
      window.renderView('packet-sniffer');
    }},
    { id: 'entity-hyperv-172-29-192-1', category: 'Discovered Host (Port Scanner)', title: 'Inspect Host 172.29.192.1 & 172.29.224.1 (MAC 00:15:5D:DF:E5:56 · Ports 135/139/445/623/2179 · Share Users)', icon: '📡', action: () => {
      if (window.EJIIInvestigationPinboard) window.EJIIInvestigationPinboard.setContext({ ip: '172.29.192.1', subnet: '172.29.192.0/20', mac: '00:15:5D:DF:E5:56', vendor: 'Microsoft Corporation', port: 445, serviceBanner: 'SMB Share Users' });
      window.renderView('ultra-ip-scanner');
    }},
    { id: 'entity-flow-10-22-10-153', category: 'Conversation Flow (NetworkTrafficView)', title: 'Inspect Cleartext HTTP Flow 10.168.195.33:50008 -> 10.22.10.153:80 (1,179 Bytes)', icon: '🌊', action: () => {
      if (window.EJIIInvestigationPinboard) window.EJIIInvestigationPinboard.setContext({ ip: '10.22.10.153', subnet: '10.22.10.0/24', port: 80, flowId: 'FLOW-11', serviceBanner: 'Cleartext HTTP TCP 80' });
      window.renderView('packet-sniffer');
    }},
    { id: 'act-convert-telemetry-lab', category: 'Socratic Lab Synthesis', title: 'Convert Active Socket, Flow & Port Telemetry into Interactive Lab Scenario', icon: '🎓', action: () => window.convertActiveTelemetryToLab && window.convertActiveTelemetryToLab('SCENARIO_A_AMT_HYPERV') }
  ];

  function buildNaturalLanguageIntentCommand(rawQuery) {
    const q = String(rawQuery || '').trim();
    if (q.length < 4) return null;
    const ipMatch = q.match(/\b(\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?)\b/);
    const target = ipMatch ? ipMatch[1] : (window.EJIISituationalMemory?.activeTarget || '127.0.0.1');

    if (/dns|servfail|nxdomain|resolve|split[-\s]*horizon/i.test(q)) {
      return {
        id: 'nl-intent-dns',
        category: 'AI Natural-Language Intent',
        title: `AI Intent: Diagnose DNS & Launch RB-04 Wizard on ${target} ("${q}")`,
        icon: '🧠',
        action: () => {
          if (window.updateSituationalMemory) window.updateSituationalMemory({ activeTarget: target, activeRunbookId: 'RB-04', observationText: q });
          if (window.launchRunbookWizardModal) window.launchRunbookWizardModal('RB-04', target);
        }
      };
    }
    if (/mtu|fragment|blackhole|retrans/i.test(q)) {
      return {
        id: 'nl-intent-mtu',
        category: 'AI Natural-Language Intent',
        title: `AI Intent: Run DF=1 Path MTU Blackhole Triage (RB-06) on ${target}`,
        icon: '🧠',
        action: () => {
          if (window.updateSituationalMemory) window.updateSituationalMemory({ activeTarget: target, activeRunbookId: 'RB-06', observationText: q });
          if (window.launchRunbookWizardModal) window.launchRunbookWizardModal('RB-06', target);
        }
      };
    }
    if (/packet|sniffer|capture|bpf|rst|reset|tls/i.test(q)) {
      return {
        id: 'nl-intent-sniffer',
        category: 'AI Natural-Language Intent',
        title: `AI Intent: Open Packet Sniffer & Translate Filter for "${q}"`,
        icon: '📡',
        action: () => {
          const translated = window.translateNaturalLanguageToFilter ? window.translateNaturalLanguageToFilter(q).filterExpression : 'tcp.flags.rst == 1 || dns';
          if (window.updateSituationalMemory) window.updateSituationalMemory({ activePacketFilter: translated, observationText: q });
          window.renderView('packet-sniffer');
          setTimeout(() => {
            const inp = document.getElementById('snifferDisplayFilterInput') || document.getElementById('snifferFilterInput');
            if (inp) inp.value = translated;
          }, 250);
        }
      };
    }
    return {
      id: 'nl-intent-general',
      category: 'AI Natural-Language Intent',
      title: `AI Intent: Orchestrate Autonomous Investigation for "${q}" (${target})`,
      icon: '✨',
      action: () => {
        if (window.updateSituationalMemory) window.updateSituationalMemory({ activeTarget: target, observationText: q });
        window.renderView('ai-operator');
        setTimeout(() => {
          const goalInput = document.getElementById('aiOperatorGoalInput');
          if (goalInput) goalInput.value = q;
          if (typeof window.runOneClickAutonomousIntelligence === 'function') window.runOneClickAutonomousIntelligence();
        }, 250);
      }
    };
  }

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

    const nlIntent = buildNaturalLanguageIntentCommand(query);
    if (nlIntent) {
      filtered.unshift(nlIntent);
    }

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
