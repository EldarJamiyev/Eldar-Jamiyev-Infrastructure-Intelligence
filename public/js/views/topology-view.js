/**
 * EJII Workstation Section 1: NOC Network Topology & Dependency Graph Map
 * Dedicated Full-Height Infrastructure Workstation
 * Layer 1-6 Architecture, Blast Radius Simulator, Path Trace Visualizer, Link Congestion Heatmap.
 */

(function(window) {
  'use strict';

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
          <div class="card" style="margin: 0; display: flex; flex-direction: column; flex: 1; overflow: hidden;">
            <!-- Header Toolbar -->
            <div class="card-header" style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; padding: 12px 18px; border-bottom: 1px solid var(--border-color); flex-shrink: 0;">
              <div style="display: flex; align-items: center; gap: 10px;">
                <span style="font-size: 22px;">🗺️</span>
                <div>
                  <div class="card-title" style="margin: 0; font-size: 15px; font-weight: 800; letter-spacing: -0.2px;">
                    1. NOC Network Topology &amp; Dependency Graph Map
                  </div>
                  <div style="font-size: 11px; color: var(--text-muted); font-family: var(--font-mono);">
                    Hierarchical Link Fabric: L1 WAN ➔ L2 Edge ➔ L3 Core ➔ L4 Enterprise ➔ L5 Access ➔ L6 Workstation
                  </div>
                </div>
              </div>

              <!-- Controls -->
              <div style="display: flex; gap: 6px; align-items: center; flex-wrap: wrap;">
                <div style="display: flex; gap: 2px; background: var(--bg-input); padding: 2px; border-radius: 6px; border: 1px solid var(--border-color);">
                  <button id="topoModeMapBtn" class="btn btn-primary" onclick="window.switchNocTopologyMode('map')" style="font-size: 11px; padding: 4px 10px; font-weight: 600;">🗺️ Map View</button>
                  <button id="topoModeTableBtn" class="btn btn-secondary" onclick="window.switchNocTopologyMode('table')" style="font-size: 11px; padding: 4px 10px; font-weight: 600;">📋 Node Fleet (${topoRes?.nodes?.length || 0})</button>
                  <button id="topoModeServiceDepBtn" class="btn btn-secondary" onclick="window.openServiceDependenciesModal()" style="font-size: 11px; padding: 4px 10px; font-weight: 600;">🔗 Service Dependencies</button>
                </div>

                <button id="topoFleetToggleBtn" class="btn btn-secondary" onclick="window.toggleTopologyFleetScope()" style="font-size: 11px; padding: 4px 10px; font-weight: 600;" title="Toggle between Infrastructure Focus and Expanded Discovered Access Fleet">
                  🛡️ Focus Infrastructure
                </button>

                <div style="display: flex; gap: 2px; background: var(--bg-input); padding: 2px; border-radius: 6px; border: 1px solid var(--border-color);">
                  <button class="btn btn-secondary" onclick="window.zoomTopology(1.2)" style="font-size: 11px; padding: 4px 8px;" title="Zoom In">➕</button>
                  <button class="btn btn-secondary" onclick="window.zoomTopology(0.8)" style="font-size: 11px; padding: 4px 8px;" title="Zoom Out">➖</button>
                  <button class="btn btn-secondary" onclick="window.resetTopologyView()" style="font-size: 11px; padding: 4px 10px;" title="Reset Pan &amp; Zoom">⟲ Reset View</button>
                </div>

                <button class="btn btn-primary" onclick="window.runDynamicDiscoveryModal()" style="font-size: 11px; padding: 4px 12px; font-weight: 600;" title="Run SNMP &amp; ARP dynamic layer-2/3 discovery">⚡ Discover L2/3</button>
                <button class="btn btn-secondary" onclick="window.triggerBlastRadiusModal()" style="font-size: 11px; padding: 4px 10px; font-weight: 600;" title="Simulate failure blast radius">💥 Blast Radius</button>
                <button class="btn btn-secondary" onclick="window.triggerPathTraceModal()" style="font-size: 11px; padding: 4px 10px; font-weight: 600;" title="Trace graphical hop-by-hop route">🧭 Path Trace</button>
                <button class="btn btn-secondary" onclick="window.clearBlastRadius()" style="font-size: 11px; padding: 4px 8px;" title="Reset highlight overlays">↺ Reset</button>
                <button class="btn btn-secondary" onclick="window.renderTopologyStandaloneView()" style="font-size: 11px; padding: 4px 8px;" title="Refresh topology from database">↻</button>
              </div>
            </div>

            <!-- View A: Dedicated Full-Height Visual Topology Canvas -->
            <div id="nocTopologyMapView" style="display: block; flex: 1; padding: 14px 18px; position: relative; overflow: hidden; display: flex; flex-direction: column;">
              <div id="nocTopologyCanvasWrap" style="background: #080D1A; border-radius: 8px; border: 1px solid rgba(255,255,255,0.08); padding: 14px; position: relative; flex: 1; display: flex; flex-direction: column; overflow: hidden; user-select: none;">
                <!-- Telemetry Legend & Controls Guide -->
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; border-bottom: 1px solid rgba(255,255,255,0.06); padding-bottom: 8px; font-size: 11px; font-family: var(--font-mono); color: var(--text-dim); flex-wrap: wrap; gap: 8px;">
                  <div>
                    <span><b>HEATMAP CONGESTION:</b> <span style="color: #10B981;">● Smooth Green (&lt;50%)</span> | <span style="color: #F59E0B;">● Amber (50-85%)</span> | <span style="color: #EF4444;">● Flashing Red (&gt;85%)</span></span>
                  </div>
                  <div>
                    <span><b>CONTROLS:</b> Drag Canvas to Pan | Mouse Wheel to Zoom | Click Node: Blast Radius | Right-Click: Context Menu</span>
                  </div>
                </div>

                <!-- Interactive SVG Viewport -->
                <div id="topologySvgContainer" style="flex: 1; overflow: hidden; cursor: grab; display: flex; align-items: stretch;" onmousedown="window.startTopologyPan(event)" onmousemove="window.doTopologyPan(event)" onmouseup="window.endTopologyPan(event)" onmouseleave="window.endTopologyPan(event)" onwheel="window.handleTopologyWheel(event)">
                  ${window.renderTopologySvg ? window.renderTopologySvg() : '<div style="padding: 20px;">Rendering Topology Map...</div>'}
                </div>

                <!-- Floating Node Telemetry Tooltip -->
                <div id="topoNodeTooltip" style="display: none; position: absolute; z-index: 1050; background: #0F172A; border: 1px solid var(--accent); border-radius: 8px; box-shadow: 0 10px 30px rgba(0,0,0,0.8); padding: 10px 14px; font-size: 11px; font-family: var(--font-mono); pointer-events: none; max-width: 320px; color: #E2E8F0;"></div>

                <!-- Simulation & Path Trace Overlay Banner -->
                <div id="topologyOverlayBanner" style="display: none; margin-top: 10px; padding: 8px 12px; border-radius: 6px; font-size: 11px; font-family: var(--font-mono);"></div>
              </div>
            </div>

            <!-- View B: Dedicated Fleet Table View -->
            <div id="nocTopologyTableView" style="display: none; flex: 1; padding: 14px 18px; overflow: hidden;">
              <div class="table-container" style="height: 100%; max-height: calc(100vh - 200px); overflow-x: auto; overflow-y: auto; scrollbar-gutter: stable;">
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

})(window);
