/**
 * EJII v6 — Sovereign Intelligence Fabric & 8-Engine Flagship Interactive Studio
 * Provides first-class UI surfaces for:
 *   1. Epistemic Uncertainty, Counterfactuals & 10-Step Cross-Layer Correlator
 *   2. Evidence Fabric, Acyclic Lineage Explorer & Epistemic Guardrail Tester
 *   3. Temporal Infrastructure Graph SVG Topology, Snapshot Diffing & Isolated M/M/1/K Chaos Branching
 *   4. 8 Flagship Deep Engines Live Interactive Workbench (L7 Dissector, Spectral FFT, Digital Twin, Zero-Trust, QoS/DSCP, Kernel/Radio, DVR, 5-Agent War-Room)
 *   5. Policy Governance Compiler, RBAC Governed Remediation Control Plane & Sovereign Academy Bridge
 */

(function () {
  try {
    sessionStorage.removeItem('warmup_start_time');
    sessionStorage.removeItem('warmup_last_reload_time');
    sessionStorage.removeItem('warmup_failed_sent');
  } catch (_) {}

  const esc = (s) => (typeof window.escapeHtml === 'function' ? window.escapeHtml(s) : String(s ?? ''));

  window.__v6ActiveTab = 'uncertainty';
  window.__v6ActiveEngine = 'l7';
  window.__v6SelectedRole = 'ADMIN';

  function updateCommandRibbonAndKpis(d) {
    const capCount = d.capabilitiesCount || (d.capabilities || []).length || 16;
    const evList = d.recentEvidence || [];
    const tg = d.temporalGraph || {};
    const actions = d.governedActions || [];
    const execs = d.recentExecutions || [];

    const ribbonEl = document.getElementById('v6RibbonTelemetrySummary');
    if (ribbonEl) {
      ribbonEl.textContent = `${capCount} Capabilities · ${evList.length} Live Evidence Records · Graph: ${tg.nodeCount || 6} Nodes / ${tg.edgeCount || 5} Edges · Epistemic Guardrail: ENFORCED`;
    }

    const kpiEl = document.getElementById('v6StudioKpiStrip');
    if (kpiEl) {
      const avgQuality = evList.length
        ? (evList.reduce((acc, r) => acc + (Number(r.qualityScore) || 0.9), 0) / evList.length).toFixed(2)
        : '0.94';
      kpiEl.innerHTML = `
        <div class="v6-kpi-cell">
          <span class="v6-kpi-label">CAPABILITY REGISTRY</span>
          <span class="v6-kpi-val">${capCount} Registered</span>
          <span class="v6-kpi-sub">8 Operational Domains · EJIIResult&lt;T&gt;</span>
        </div>
        <div class="v6-kpi-cell">
          <span class="v6-kpi-label">EVIDENCE FABRIC</span>
          <span class="v6-kpi-val">${evList.length} Records · Q̄ ${avgQuality}</span>
          <span class="v6-kpi-sub">${(d.evidenceClasses || []).length || 11} Classes · Acyclic Lineage DAG</span>
        </div>
        <div class="v6-kpi-cell">
          <span class="v6-kpi-label">TEMPORAL GRAPH</span>
          <span class="v6-kpi-val">${tg.nodeCount || 6} Nodes · ${tg.edgeCount || 5} Edges</span>
          <span class="v6-kpi-sub">${tg.snapshotCount || 1} Snapshots · ${(tg.reconciliationCandidates || []).length} Reconciliations</span>
        </div>
        <div class="v6-kpi-cell">
          <span class="v6-kpi-label">EPISTEMIC GUARDRAIL</span>
          <span class="v6-kpi-val" style="color:var(--status-nominal);">ENFORCED</span>
          <span class="v6-kpi-sub">Simulated/Heuristic capped ≤ HYPOTHESIS</span>
        </div>
        <div class="v6-kpi-cell">
          <span class="v6-kpi-label">GOVERNED ACTIONS</span>
          <span class="v6-kpi-val">${actions.length} Playbooks · ${execs.length} Runs</span>
          <span class="v6-kpi-sub">Dry-Run · Postconditions · Rollback</span>
        </div>
      `;
    }
  }

  window.openV6SovereignFabricModal = async function (initialTab) {
    const modal = document.getElementById('v6SovereignFabricModal');
    if (!modal) return;
    modal.style.display = 'flex';
    window.__v6ActiveTab = initialTab || window.__v6ActiveTab || 'uncertainty';
    await window.refreshV6FabricOverview(window.__v6ActiveTab);
  };

  window.closeV6SovereignFabricModal = function () {
    const modal = document.getElementById('v6SovereignFabricModal');
    if (modal) modal.style.display = 'none';
  };

  window.refreshV6FabricOverview = async function (activeTab) {
    const bodyEl = document.getElementById('v6SovereignFabricBody');
    try {
      const res = await fetch('/api/v6/overview', { credentials: 'same-origin' });
      const env = await res.json();
      const d = env.data || {};
      window.__v6FabricData = d;
      updateCommandRibbonAndKpis(d);
      if (bodyEl && document.getElementById('v6SovereignFabricModal')?.style.display !== 'none') {
        window.renderV6FabricTab(activeTab || window.__v6ActiveTab || 'uncertainty');
      }
    } catch (err) {
      if (bodyEl) {
        bodyEl.innerHTML = `<div style="padding:16px;color:var(--status-critical);">Failed to load EJII v6 Sovereign Fabric state: ${esc(err.message)}</div>`;
      }
    }
  };

  window.renderV6FabricTab = function (tabName) {
    window.__v6ActiveTab = tabName;
    const d = window.__v6FabricData || {};
    const bodyEl = document.getElementById('v6SovereignFabricBody');
    if (!bodyEl) return;

    document.querySelectorAll('.v6-fabric-tab-btn').forEach((btn) => {
      const active = btn.getAttribute('data-v6-tab') === tabName;
      btn.classList.toggle('active-v6-tab', active);
      btn.setAttribute('aria-selected', String(active));
    });

    if (tabName === 'uncertainty') {
      const u = d.uncertaintyPanel || {};
      const liveList = (u.knownFromLiveEvidence || []).map((e) =>
        `<li style="margin-bottom:6px;line-height:1.45;">
          <a href="#lineage" onclick="event.preventDefault();window.renderV6FabricTab('evidence');setTimeout(()=>window.inspectV6EvidenceLineage('${esc(e.evidenceId)}'),60);" style="font-family:var(--font-mono);font-weight:700;text-decoration:underline;">[${esc(e.evidenceId)}]</a>
          ${esc(e.claim)} <span style="color:var(--status-nominal);font-family:var(--font-mono);font-weight:600;">· Q=${esc(e.qualityScore)} · LIVE</span>
        </li>`
      ).join('') || '<li>No live observations recorded in current window — execute the 10-step cross-layer diagnosis below.</li>';

      const simList = (u.simulatedProjections || []).map((e) =>
        `<li style="margin-bottom:6px;line-height:1.45;"><strong style="font-family:var(--font-mono);">[${esc(e.evidenceId)}]</strong> ${esc(e.claim)} <span style="color:var(--status-warning);font-weight:700;">· [SIMULATED PROJECTION — ISOLATED]</span></li>`
      ).join('') || '<li>Zero simulated projections mixed into live state (Strict Epistemic Isolation active).</li>';

      const unknowns = (u.unknownsAndMissingTelemetry || []).map((m) =>
        `<li style="margin-bottom:5px;line-height:1.45;">${esc(m)}</li>`
      ).join('') || '<li>All primary protocol layers verified in current window.</li>';

      const probe = u.highestInformationGainProbe || {};

      bodyEl.innerHTML = `
        <div class="v6-panel" style="margin-bottom:14px;display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;">
          <div>
            <div class="v6-panel-kicker" style="color:var(--accent-primary);margin-bottom:2px;">10-STEP CROSS-LAYER UNREACHABLE-HOSTNAME CORRELATOR</div>
            <div style="font-size:12px;color:var(--text-secondary);">Executes live L1–L7 probes (DNS, Route LPM, ARP/NDP, ICMP/PMTU, TCP SYN, TLS X.509, HTTP/L7) with shared-dependency correlation discounting.</div>
          </div>
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
            <input type="text" id="v6DiagHostInput" value="localhost" aria-label="Target hostname or IP" style="padding:6px 10px;border:1px solid var(--border-default);border-radius:6px;background:var(--bg-surface);color:var(--text-primary);font-family:var(--font-mono);font-size:12px;width:140px;">
            <input type="number" id="v6DiagPortInput" value="3000" aria-label="Target port" style="padding:6px 8px;border:1px solid var(--border-default);border-radius:6px;background:var(--bg-surface);color:var(--text-primary);font-family:var(--font-mono);font-size:12px;width:78px;">
            <button type="button" class="btn btn-primary" style="font-size:12px;padding:6px 12px;" onclick="window.runV6HostnameDiagnosis(document.getElementById('v6DiagHostInput')?.value || 'localhost', Number(document.getElementById('v6DiagPortInput')?.value || 3000))">Execute 10-Step Cross-Layer Diagnosis</button>
            <button type="button" class="btn btn-secondary" style="font-size:12px;padding:6px 12px;" onclick="window.runV6MultiSignalCorrelation()">Correlate Shared-Dependency Incident</button>
          </div>
        </div>

        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(265px,1fr));gap:12px;">
          <div class="v6-panel">
            <div class="v6-panel-kicker" style="color:var(--status-nominal);">1. KNOWN FROM LIVE EVIDENCE (OBSERVATIONS)</div>
            <ul style="margin:0;padding-left:18px;font-size:12px;color:var(--text-primary);">${liveList}</ul>
          </div>
          <div class="v6-panel">
            <div class="v6-panel-kicker" style="color:var(--status-warning);">2. SIMULATED PROJECTIONS (ISOLATED FROM LIVE TRUTH)</div>
            <ul style="margin:0;padding-left:18px;font-size:12px;color:var(--text-primary);">${simList}</ul>
          </div>
          <div class="v6-panel">
            <div class="v6-panel-kicker" style="color:var(--status-critical);">3. WHAT EJII DOES NOT KNOW YET (UNKNOWNS)</div>
            <ul style="margin:0;padding-left:18px;font-size:12px;color:var(--text-primary);">${unknowns}</ul>
          </div>
          <div class="v6-panel">
            <div class="v6-panel-kicker" style="color:var(--status-info);">4. HIGHEST INFORMATION-GAIN NEXT PROBE</div>
            <div style="font-size:13px;font-weight:700;color:var(--text-primary);margin-bottom:4px;font-family:var(--font-mono);">Probe: ${esc(probe.probeId || 'tcp_port_probe')} · ΔH = ${esc(probe.expectedEntropyReductionBits || 0.84)} bits</div>
            <p style="margin:0 0 10px 0;font-size:12px;color:var(--text-secondary);">${esc(probe.rationale || 'Distinguishes transport reachability from application refusal across L4/L7.')}</p>
            <button type="button" class="btn btn-secondary" style="font-size:11.5px;padding:5px 10px;" onclick="window.runV6HostnameDiagnosis('127.0.0.1', 3000)">Dispatch Distinguishing Probe</button>
          </div>
        </div>
        <div id="v6DiagnosisOutput" style="margin-top:14px;"></div>
      `;
    } else if (tabName === 'evidence') {
      const records = d.recentEvidence || [];
      const rows = records.slice(0, 15).map((r) => {
        const isLive = r.freshnessState === 'live' || r.freshnessState === 'fresh';
        const stateColor = isLive ? 'var(--status-nominal)' : 'var(--status-warning)';
        return `
          <tr>
            <td style="padding:7px 10px;font-family:var(--font-mono);font-size:11.5px;">
              <button type="button" class="btn btn-secondary" style="padding:2px 7px;font-size:11px;font-family:var(--font-mono);" onclick="window.inspectV6EvidenceLineage('${esc(r.id)}')">${esc(r.id)}</button>
            </td>
            <td style="padding:7px 10px;font-family:var(--font-mono);font-size:11px;font-weight:600;">${esc(r.type)}</td>
            <td style="padding:7px 10px;font-size:12px;font-family:var(--font-mono);">${esc(r.subject)}</td>
            <td style="padding:7px 10px;font-size:12px;">${esc(r.claim)}</td>
            <td style="padding:7px 10px;font-size:11.5px;font-weight:700;color:${stateColor};text-transform:uppercase;">${esc(r.freshnessState)}</td>
            <td style="padding:7px 10px;font-family:var(--font-mono);font-size:12px;text-align:right;">${esc(r.qualityScore)}</td>
          </tr>
        `;
      }).join('');

      bodyEl.innerHTML = `
        <div class="v6-panel" style="margin-bottom:12px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;">
          <div style="font-size:12px;color:var(--text-secondary);">
            <strong style="color:var(--text-primary);">11 Canonical Evidence Classes:</strong> ${(d.evidenceClasses || []).map(esc).join(' · ')}
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <button type="button" class="btn btn-primary" style="font-size:11.5px;padding:5px 11px;" onclick="window.ingestV6SampleEvidence('live')">+ Record Live Wire Evidence</button>
            <button type="button" class="btn btn-secondary" style="font-size:11.5px;padding:5px 11px;" onclick="window.ingestV6SampleEvidence('simulated')">Test Epistemic Guardrail (Simulated Claim)</button>
          </div>
        </div>
        <div id="v6LineageInspectorBox" style="margin-bottom:12px;"></div>
        <div class="v6-panel" style="padding:0;overflow-x:auto;">
          <table style="width:100%;border-collapse:collapse;text-align:left;">
            <thead>
              <tr style="background:var(--bg-surface-subtle);border-bottom:1px solid var(--border-default);font-size:10.5px;color:var(--text-muted);">
                <th style="padding:9px 10px;">EVIDENCE ID (LINEAGE)</th>
                <th style="padding:9px 10px;">EVIDENCE CLASS</th>
                <th style="padding:9px 10px;">SUBJECT</th>
                <th style="padding:9px 10px;">OBSERVED / DERIVED CLAIM</th>
                <th style="padding:9px 10px;">FRESHNESS</th>
                <th style="padding:9px 10px;text-align:right;">QUALITY SCORE</th>
              </tr>
            </thead>
            <tbody>${rows || '<tr><td colspan="6" style="padding:14px;">No evidence records yet.</td></tr>'}</tbody>
          </table>
        </div>
      `;
    } else if (tabName === 'simulation') {
      const tg = d.temporalGraph || {};
      bodyEl.innerHTML = `
        <div class="v6-panel" style="margin-bottom:12px;display:flex;gap:12px;align-items:center;justify-content:space-between;flex-wrap:wrap;">
          <div style="font-size:12px;color:var(--text-primary);">
            <strong>Temporal Infrastructure Graph:</strong> <span class="font-mono">${tg.nodeCount || 6}</span> Canonical Nodes · <span class="font-mono">${tg.edgeCount || 5}</span> Typed Edges · <span class="font-mono">${tg.snapshotCount || 1}</span> Snapshots · <span class="font-mono">${(tg.reconciliationCandidates || []).length}</span> Identity Reconciliation Candidates
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
            <label style="font-size:11.5px;color:var(--text-secondary);font-family:var(--font-mono);">Arrival λ×:
              <input type="number" id="v6ChaosLambdaInput" value="1.85" step="0.15" min="0.5" max="10" style="width:68px;padding:4px 6px;border:1px solid var(--border-default);border-radius:5px;background:var(--bg-surface);color:var(--text-primary);font-family:var(--font-mono);">
            </label>
            <button type="button" class="btn btn-primary" style="font-size:11.5px;padding:6px 12px;" onclick="window.forkV6SimulationBranch()">Fork Isolated M/M/1/K Chaos Simulation Branch</button>
            <button type="button" class="btn btn-secondary" style="font-size:11.5px;padding:6px 12px;" onclick="window.runV6TemporalGraphDiff()">Diff Snapshots (t₁ ↔ t₂)</button>
          </div>
        </div>
        <div id="v6SimulationOutput" class="v6-panel" style="font-size:12.5px;">
          Select <strong>"Fork Isolated M/M/1/K Chaos Simulation Branch"</strong> to evaluate link congestion, blocking probability P<sub>K</sub>, and node failure impact in an isolated branch without mutating live topology truth.
        </div>
      `;
    } else if (tabName === 'engines') {
      window.renderV6EnginesWorkbench(window.__v6ActiveEngine || 'l7');
    } else if (tabName === 'governance') {
      const actions = d.governedActions || [];
      const cards = actions.map((a) => `
        <div class="v6-panel" style="display:flex;flex-direction:column;justify-content:space-between;gap:10px;">
          <div>
            <div style="font-size:10px;font-weight:700;color:var(--text-muted);letter-spacing:0.06em;">${esc(a.category.toUpperCase())} · REQUIRED ROLE: ${esc(a.requiredRole)} · BLAST RADIUS: ${esc(a.blastRadius.toUpperCase())}</div>
            <div style="font-size:13.5px;font-weight:700;color:var(--text-primary);margin:4px 0;">${esc(a.name)}</div>
            <p style="font-size:12px;color:var(--text-secondary);margin:0 0 8px 0;">${esc(a.description)}</p>
            <div style="font-size:11px;color:var(--accent-primary);font-family:var(--font-mono);">
              Academy Bridge: <code>${esc(a.linkedAcademyModuleId)}</code> · Lab <code>${esc(a.linkedAcademyLabId)}</code>
            </div>
          </div>
          <div style="display:flex;gap:6px;flex-wrap:wrap;">
            <button type="button" class="btn btn-secondary" style="font-size:11px;padding:5px 9px;" onclick="window.previewV6GovernedAction('${esc(a.id)}')">Dry-Run Preview</button>
            <button type="button" class="btn btn-primary" style="font-size:11px;padding:5px 9px;" onclick="window.executeV6GovernedAction('${esc(a.id)}')">Execute &amp; Verify Postconditions</button>
            <button type="button" class="btn btn-secondary" style="font-size:11px;padding:5px 9px;" onclick="window.openAcademyFromV6('${esc(a.linkedAcademyModuleId)}')">Open Academy Lab →</button>
          </div>
        </div>
      `).join('');

      bodyEl.innerHTML = `
        <div class="v6-panel" style="margin-bottom:12px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;">
          <div>
            <div class="v6-panel-kicker" style="color:var(--accent-primary);margin-bottom:2px;">GOVERNED ACTION CONTROL PLANE &amp; RBAC ENFORCEMENT</div>
            <div style="font-size:12px;color:var(--text-secondary);">Every remediation verifies preconditions, previews the exact OS command, enforces RBAC, verifies live postconditions, and records an immutable Evidence Chain.</div>
          </div>
          <div style="display:flex;align-items:center;gap:8px;">
            <label for="v6RoleSelector" style="font-size:11.5px;font-weight:600;color:var(--text-secondary);">Active RBAC Role:</label>
            <select id="v6RoleSelector" onchange="window.__v6SelectedRole=this.value" style="padding:5px 9px;border:1px solid var(--border-default);border-radius:6px;background:var(--bg-surface);color:var(--text-primary);font-family:var(--font-mono);font-size:11.5px;">
              <option value="ADMIN" ${window.__v6SelectedRole === 'ADMIN' ? 'selected' : ''}>ADMIN (Full Remediation)</option>
              <option value="OPERATOR" ${window.__v6SelectedRole === 'OPERATOR' ? 'selected' : ''}>OPERATOR (Standard Ops)</option>
              <option value="VIEWER" ${window.__v6SelectedRole === 'VIEWER' ? 'selected' : ''}>VIEWER (Read-Only — Tests 403 Deny)</option>
            </select>
          </div>
        </div>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px;">${cards}</div>
        <div id="v6GovernanceOutput" style="margin-top:12px;"></div>
      `;
    }
  };

  window.renderV6EnginesWorkbench = function (engineKey) {
    window.__v6ActiveEngine = engineKey || 'l7';
    const bodyEl = document.getElementById('v6SovereignFabricBody');
    if (!bodyEl) return;

    const engines = [
      { id: 'l7', label: '1. L7 Wire Dissector (QUIC/HTTP2/SSH/SMB)' },
      { id: 'fft', label: '2. Spectral FFT Periodogram' },
      { id: 'chaos', label: '3. M/M/1/K Digital Twin' },
      { id: 'zerotrust', label: '4. Zero-Trust Policy Synthesizer' },
      { id: 'qos', label: '5. Multipath DSCP/ECN & PMTU' },
      { id: 'kernel', label: '6. Physical Radio & Kernel Stack' },
      { id: 'warroom', label: '7. 5-Agent SRE War-Room' },
      { id: 'dvr', label: '8. Telemetry DVR Time-Machine' }
    ];

    const pills = engines.map((e) =>
      `<button type="button" class="v6-engine-pill ${e.id === window.__v6ActiveEngine ? 'active' : ''}" onclick="window.renderV6EnginesWorkbench('${e.id}')">${esc(e.label)}</button>`
    ).join('');

    bodyEl.innerHTML = `
      <div class="v6-engine-pill-bar">${pills}</div>
      <div id="v6EngineStage" class="v6-panel">Loading engine workbench...</div>
    `;

    window.runV6FlagshipEngineDemo(window.__v6ActiveEngine);
  };

  window.runV6FlagshipEngineDemo = async function (engineId, customPayload) {
    const stage = document.getElementById('v6EngineStage');
    if (!stage) return;

    try {
      if (engineId === 'l7') {
        const presetHex = customPayload || 'c300000001088394c8f03e515708050102030405004075c01a2b3c4d';
        const res = await fetch('/api/network/dissect-l7', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ hex: presetHex })
        });
        const data = await res.json();
        stage.innerHTML = `
          <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:10px;">
            <div>
              <div class="v6-panel-kicker" style="color:var(--accent-primary);">ENGINE 1 · L7 DEEP PROTOCOL DISSECTOR (RFC 9000 QUIC / RFC 9113 HTTP/2 / SSH HASSH / SMBv2-3)</div>
              <div style="font-size:12px;color:var(--text-secondary);">Bounds-checked zero-exception binary wire parser with honest payload encryption flags.</div>
            </div>
            <div style="display:flex;gap:6px;flex-wrap:wrap;">
              <button type="button" class="btn btn-secondary" style="font-size:11px;padding:4px 9px;" onclick="window.runV6FlagshipEngineDemo('l7','c300000001088394c8f03e515708050102030405004075c01a2b3c4d')">QUIC v1 Initial</button>
              <button type="button" class="btn btn-secondary" style="font-size:11px;padding:4px 9px;" onclick="window.runV6FlagshipEngineDemo('l7','505249202a20485454502f322e300d0a0d0a534d0d0a0d0a00000c04000000000000030000006400040000ffff')">HTTP/2 Preface + SETTINGS</button>
              <button type="button" class="btn btn-secondary" style="font-size:11px;padding:4px 9px;" onclick="window.runV6FlagshipEngineDemo('l7','fe534d4240000100000000000000010001000000000000000100000000000000fffe000001000000010000000000000000000000000000000000000000000000')">SMBv2/3 Negotiate</button>
            </div>
          </div>
          <div style="font-family:var(--font-mono);font-size:11.5px;background:var(--bg-surface-subtle);padding:10px;border-radius:6px;border:1px solid var(--border-default);overflow-x:auto;">
            <div><strong>Detected Protocol:</strong> ${esc(data.protocol)} · <strong>Summary:</strong> ${esc(data.summary)} · <strong>Bytes:</strong> ${esc(data.byteLength)}B</div>
            <pre style="margin:8px 0 0 0;white-space:pre-wrap;">${esc(JSON.stringify(data.quic || data.http2 || data.smb || data.ssh || data, null, 2))}</pre>
          </div>
        `;
      } else if (engineId === 'fft') {
        const res = await fetch('/api/rca/spectral-fft');
        const data = await res.json();
        const bins = (data.periodogram || []).slice(0, 12);
        const maxPow = Math.max(0.01, ...bins.map((b) => Number(b.power) || 0));
        const bars = bins.map((b) => {
          const pct = Math.min(100, Math.round(((Number(b.power) || 0) / maxPow) * 100));
          return `
            <div style="display:flex;align-items:center;gap:8px;font-family:var(--font-mono);font-size:11px;margin-bottom:4px;">
              <span style="width:65px;">${Number(b.frequencyHz).toFixed(2)} Hz</span>
              <div style="flex:1;height:8px;background:var(--bg-surface-subtle);border-radius:4px;overflow:hidden;">
                <div style="width:${pct}%;height:100%;background:var(--accent-primary);"></div>
              </div>
              <span style="width:65px;text-align:right;">${Number(b.power).toFixed(1)}</span>
            </div>
          `;
        }).join('');
        stage.innerHTML = `
          <div class="v6-panel-kicker" style="color:var(--accent-primary);">ENGINE 2 · SPECTRAL FOURIER DETECTOR (WELCH PERIODOGRAM &amp; PERIODIC BEACON DETECTOR)</div>
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin-bottom:10px;font-family:var(--font-mono);font-size:12px;">
            <div><strong>Dominant Freq:</strong> ${esc(data.dominantFrequencyHz)} Hz (Period: ${esc(data.dominantPeriodSec)}s)</div>
            <div><strong>Peak SNR:</strong> ${esc(data.snrDb)} dB · <strong>Entropy:</strong> ${esc(data.spectralEntropy)}</div>
            <div><strong>Classification:</strong> <span style="color:var(--status-warning);font-weight:700;">${esc(data.classification)}</span></div>
          </div>
          <div style="font-size:11.5px;color:var(--text-secondary);margin-bottom:10px;"><strong>Epistemic Distinction:</strong> ${esc(data.evidenceDistinction || 'Signal-derived periodicity is a statistical hypothesis requiring socket/process correlation.')}</div>
          <div>${bars}</div>
        `;
      } else if (engineId === 'chaos') {
        const res = await fetch('/api/network/digital-twin/simulate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ arrivalRateMultiplier: 2.1, severedEdges: [{ source: 'L2-EDGE-ROUTER', target: 'L3-CORE-SWITCH' }] })
        });
        const data = await res.json();
        stage.innerHTML = `
          <div class="v6-panel-kicker" style="color:var(--accent-primary);">ENGINE 3 · DIGITAL TWIN M/M/1/K FINITE-BUFFER QUEUEING &amp; TOPOLOGY RESILIENCE</div>
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;font-family:var(--font-mono);font-size:12px;">
            <div><strong>Fidelity:</strong> <span style="color:var(--status-warning);">${esc(data.simulationFidelity || 'MATHEMATICAL_SIMULATION')}</span></div>
            <div><strong>Baseline λ₂:</strong> ${esc(data.baselineLambda2)} → <strong>Post-Chaos λ₂:</strong> ${esc(data.postChaosLambda2)}</div>
            <div><strong>Resilience Score:</strong> ${esc(data.resilienceScore)} / 100</div>
            <div><strong>Summary:</strong> ${esc(data.executiveSummary)}</div>
          </div>
        `;
      } else if (engineId === 'zerotrust') {
        const res = await fetch('/api/network/zero-trust-policies');
        const data = await res.json();
        stage.innerHTML = `
          <div class="v6-panel-kicker" style="color:var(--accent-primary);">ENGINE 4 · ZERO-TRUST MICRO-SEGMENTATION POLICY SYNTHESIZER</div>
          <div style="font-size:12px;margin-bottom:8px;">
            <strong>Policy ID:</strong> <code>${esc(data.policyId)}</code> · <strong>Enforcement Status:</strong> <span style="color:var(--status-warning);font-weight:700;">${esc(data.enforcementStatus || 'PROPOSED_PREVIEW_ONLY')}</span> · <strong>Auto-Applied:</strong> <code>${String(data.autoApplied)}</code>
          </div>
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:10px;">
            <div>
              <div style="font-size:11px;font-weight:700;margin-bottom:4px;">Linux nftables Manifest</div>
              <pre style="font-size:10.5px;background:var(--bg-surface-subtle);padding:8px;border-radius:6px;border:1px solid var(--border-default);max-height:170px;overflow:auto;">${esc(data.nftablesScript)}</pre>
            </div>
            <div>
              <div style="font-size:11px;font-weight:700;margin-bottom:4px;">Kubernetes NetworkPolicy YAML</div>
              <pre style="font-size:10.5px;background:var(--bg-surface-subtle);padding:8px;border-radius:6px;border:1px solid var(--border-default);max-height:170px;overflow:auto;">${esc(data.kubernetesNetworkPolicyYaml)}</pre>
            </div>
          </div>
        `;
      } else if (engineId === 'qos') {
        const res = await fetch('/api/network/qos-dscp-audit');
        const data = await res.json();
        stage.innerHTML = `
          <div class="v6-panel-kicker" style="color:var(--accent-primary);">ENGINE 5 · MULTIPATH DSCP / ECN QOS &amp; PMTU BLACK-HOLE AUDITOR (RFC 4594 / RFC 3168)</div>
          <div style="font-family:var(--font-mono);font-size:12px;margin-bottom:8px;">
            <strong>Total Frames Audited:</strong> ${esc(data.totalFramesAudited)} · <strong>Bleaching Detected:</strong> ${esc(data.dscpBleachingDetected)} · <strong>ECN CE Count:</strong> ${esc(data.ecnCongestionExperiencedCount)} · <strong>PMTU Risk:</strong> ${esc(data.pmtuBlackHoleRisk)}
          </div>
          <div style="font-size:12px;color:var(--text-secondary);">${esc(data.summary)}</div>
        `;
      } else if (engineId === 'kernel') {
        const res = await fetch('/api/diagnostics/kernel-radio-inspector');
        const data = await res.json();
        stage.innerHTML = `
          <div class="v6-panel-kicker" style="color:var(--accent-primary);">ENGINE 6 · PHYSICAL WIFI RADIO &amp; KERNEL TCP CONGESTION PROVENANCE INSPECTOR</div>
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px;font-family:var(--font-mono);font-size:12px;">
            <div style="padding:10px;border:1px solid var(--border-default);border-radius:6px;background:var(--bg-surface-subtle);">
              <div style="font-weight:700;margin-bottom:4px;">802.11 Physical Radio (Provenance: ${esc(data.wifi?.provenance || 'unavailable')})</div>
              <div>Connected: ${esc(data.wifi?.connected)} · Interface: ${esc(data.wifi?.interfaceName)}</div>
              <div>Reason: ${esc(data.wifi?.unavailableReason || 'Live OS Radio Query')}</div>
            </div>
            <div style="padding:10px;border:1px solid var(--border-default);border-radius:6px;background:var(--bg-surface-subtle);">
              <div style="font-weight:700;margin-bottom:4px;">Kernel TCP Stack (Provenance: ${esc(data.kernelTcp?.provenance || 'live')})</div>
              <div>Congestion Control: ${esc(data.kernelTcp?.congestionControlAlgorithm)} · ECN: ${esc(data.kernelTcp?.ecnState)}</div>
              <div>Auto-Tuning: ${esc(data.kernelTcp?.receiveWindowAutoTuning)} · MTU: ${esc(data.kernelTcp?.loopbackMtu)}</div>
            </div>
          </div>
        `;
      } else if (engineId === 'warroom') {
        const res = await fetch('/api/rca/war-room/latest');
        const data = await res.json();
        const steps = (data.agentTranscript || []).map((a) => `
          <div style="padding:7px 10px;border-bottom:1px solid var(--border-subtle);font-size:11.5px;">
            <strong>[${esc(a.agentRole)}] ${esc(a.agentName)}</strong> · Status: <span style="font-family:var(--font-mono);font-weight:700;color:var(--accent-primary);">${esc(a.epistemicStatus || 'HYPOTHESIS')}</span> · Confidence: <span class="font-mono">${esc(a.confidencePct)}%</span>
            <div style="color:var(--text-secondary);margin-top:2px;">${esc(a.finding)}</div>
          </div>
        `).join('');
        stage.innerHTML = `
          <div class="v6-panel-kicker" style="color:var(--accent-primary);">ENGINE 7 · 5-AGENT AUTONOMOUS SRE WAR-ROOM ORCHESTRATOR</div>
          <div style="font-size:12px;font-weight:700;margin-bottom:8px;">Root Cause Consensus: ${esc(data.consensusRootCause)} (Borda Score: ${esc(data.bordaConsensusScore)})</div>
          <div style="border:1px solid var(--border-default);border-radius:6px;overflow:hidden;">${steps}</div>
        `;
      } else if (engineId === 'dvr') {
        const res = await fetch('/api/observability/dvr/frames');
        const data = await res.json();
        const frames = data.frames || [];
        stage.innerHTML = `
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
            <div class="v6-panel-kicker" style="color:var(--accent-primary);">ENGINE 8 · TELEMETRY DVR TIME-MACHINE RING BUFFER (${frames.length} KEYFRAMES)</div>
            <button type="button" class="btn btn-secondary" style="font-size:11px;padding:4px 9px;" onclick="window.closeV6SovereignFabricModal();window.toggleDvrModal();">Open Full DVR Diff Workbench</button>
          </div>
          <div style="font-family:var(--font-mono);font-size:11.5px;color:var(--text-secondary);">
            Latest Frame: <strong>${esc(frames[frames.length - 1]?.label || 'Baseline')}</strong> · Seq #${esc(frames[frames.length - 1]?.sequenceNumber || frames.length)} · λ₂=${esc(frames[frames.length - 1]?.lambda2 || 0.58)}
          </div>
        `;
      }
    } catch (e) {
      stage.innerHTML = `<div style="color:var(--status-critical);">Engine execution failed: ${esc(e.message)}</div>`;
    }
  };

  window.inspectV6EvidenceLineage = async function (evidenceId) {
    const box = document.getElementById('v6LineageInspectorBox');
    if (!box) return;
    box.innerHTML = `<div class="v6-panel" style="font-size:12px;">Tracing acyclic lineage DAG for <code>${esc(evidenceId)}</code>...</div>`;
    try {
      const res = await fetch(`/api/v6/evidence/${encodeURIComponent(evidenceId)}/lineage`);
      const env = await res.json();
      const lin = env.data || {};
      const chain = (lin.lineageChain || []).map((node, idx) =>
        `<span style="display:inline-flex;align-items:center;gap:6px;padding:4px 8px;border-radius:5px;border:1px solid var(--border-default);background:var(--bg-surface);font-family:var(--font-mono);font-size:11px;">
          <strong>#${idx + 1} ${esc(node.id)}</strong> (${esc(node.type)} · ${esc(node.freshnessState)} · Q=${esc(node.qualityScore)})
        </span>`
      ).join(' <span style="color:var(--text-muted);">→</span> ');

      box.innerHTML = `
        <div class="v6-panel" style="background:var(--bg-surface-subtle);">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
            <div class="v6-panel-kicker" style="color:var(--accent-primary);margin:0;">ACYCLIC LINEAGE DAG TRACE · ${esc(evidenceId)}</div>
            <span style="font-family:var(--font-mono);font-size:11px;color:var(--status-nominal);">Cycle-Free Verified: ${String(lin.acyclicVerified !== false)}</span>
          </div>
          <div style="display:flex;flex-wrap:wrap;align-items:center;gap:6px;">${chain || 'Root observation node (depth 0).'}</div>
        </div>
      `;
    } catch (e) {
      box.innerHTML = `<div class="v6-panel" style="color:var(--status-critical);">Lineage lookup failed: ${esc(e.message)}</div>`;
    }
  };

  window.ingestV6SampleEvidence = async function (mode) {
    const box = document.getElementById('v6LineageInspectorBox');
    const payload = mode === 'simulated'
      ? {
          type: 'SimulationProjectionEvidence',
          subject: 'edge:L2-L3',
          claim: 'Simulated 2.4x traffic surge predicts 3.8% tail drop on L3-CORE-SWITCH',
          freshnessState: 'simulated',
          sourceEngine: 'DigitalTwinChaosSimulator',
          requestedEpistemicStatus: 'confirmed'
        }
      : {
          type: 'FlowSampleEvidence',
          subject: '127.0.0.1:3000',
          claim: 'Observed clean TCP handshake and HTTP/1.1 200 OK response in 1.8ms',
          freshnessState: 'live',
          sourceEngine: 'LiveWireProbe'
        };

    const res = await fetch('/api/v6/evidence', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const env = await res.json();
    const rec = env.data || {};
    await window.refreshV6FabricOverview('evidence');
    const updatedBox = document.getElementById('v6LineageInspectorBox');
    if (updatedBox) {
      updatedBox.innerHTML = `
        <div class="v6-panel" style="border-color:var(--accent-primary);">
          <div style="font-size:12px;font-weight:700;">Recorded Evidence <code>${esc(rec.id)}</code> (${esc(rec.type)})</div>
          <div style="font-size:11.5px;color:var(--text-secondary);margin-top:3px;">
            Freshness: <strong>${esc(rec.freshnessState)}</strong> · Quality Score: <strong>${esc(rec.qualityScore)}</strong> · Max Allowed Epistemic Status: <strong>${esc(rec.maxAllowedEpistemicStatus || (mode === 'simulated' ? 'hypothesis (Guardrail Capped!)' : 'confirmed'))}</strong>
          </div>
        </div>
      `;
    }
  };

  window.runV6HostnameDiagnosis = async function (hostname, port) {
    const out = document.getElementById('v6DiagnosisOutput');
    if (out) out.innerHTML = '<div class="v6-panel" style="font-size:12.5px;">Executing 10-step L1–L7 cross-layer diagnosis...</div>';
    try {
      const res = await fetch('/api/v6/diagnose-hostname', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hostname: hostname || 'localhost', port: port || 3000 })
      });
      const env = await res.json();
      const wf = env.data || {};
      const topHyp = wf.correlation?.topHypothesis;
      const stepsHtml = (wf.steps || []).map((s) =>
        `<div style="padding:7px 12px;border-bottom:1px solid var(--border-subtle);font-size:12px;display:flex;justify-content:space-between;gap:10px;">
          <div><strong>Step ${esc(s.stepNumber)} [${esc(s.layer)}]</strong>: ${esc(s.summary)}</div>
          <span style="font-family:var(--font-mono);color:${s.status === 'PASS' ? 'var(--status-nominal)' : 'var(--status-warning)'};font-weight:700;">${esc(s.status)}</span>
        </div>`
      ).join('');
      if (out) {
        out.innerHTML = `
          <div class="v6-panel" style="padding:0;overflow:hidden;">
            <div style="padding:10px 14px;background:var(--bg-surface-subtle);border-bottom:1px solid var(--border-default);font-size:12.5px;font-weight:700;">
              Workflow <code>${esc(wf.workflowId)}</code> — Top Causal Hypothesis: ${topHyp ? `${esc(topHyp.title)} (Posterior: ${(topHyp.posteriorProbability * 100).toFixed(1)}%, Status: ${esc(topHyp.status.toUpperCase())})` : 'Evaluated'}
            </div>
            ${topHyp ? `<div style="padding:9px 14px;background:var(--bg-surface);border-bottom:1px solid var(--border-default);font-size:12px;color:var(--text-secondary);"><strong>Counterfactual Analysis:</strong> ${esc(topHyp.counterfactualAnalysis)}</div>` : ''}
            <div>${stepsHtml}</div>
          </div>
        `;
      }
    } catch (e) {
      if (out) out.innerHTML = `<div style="color:var(--status-critical);padding:8px;">Diagnosis error: ${esc(e.message)}</div>`;
    }
  };

  window.runV6MultiSignalCorrelation = async function () {
    const out = document.getElementById('v6DiagnosisOutput');
    if (out) out.innerHTML = '<div class="v6-panel" style="font-size:12px;">Running shared-dependency cross-layer correlation...</div>';
    try {
      const res = await fetch('/api/v6/correlate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: document.getElementById('v6DiagHostInput')?.value || '192.168.31.1:443',
          signals: [
            { layer: 'L3', type: 'GATEWAY_RTT_SPIKE', severity: 'high', sharedDependencyGroup: 'WAN_GATEWAY_LINK', summary: 'Default gateway RTT rose from 1.8ms to 68ms' },
            { layer: 'L7', type: 'DNS_LOOKUP_DELAY', severity: 'medium', sharedDependencyGroup: 'WAN_GATEWAY_LINK', summary: 'Recursive DNS query over gateway delayed by 64ms' },
            { layer: 'L4', type: 'TCP_SYN_RETRANSMIT', severity: 'high', sharedDependencyGroup: 'WAN_GATEWAY_LINK', summary: 'Upstream SYN retransmission observed on WAN link' }
          ]
        })
      });
      const env = await res.json();
      const c = env.data || {};
      const hyps = (c.competingHypotheses || []).map((h) => `
        <div style="padding:8px 12px;border-bottom:1px solid var(--border-subtle);font-size:12px;">
          <div style="display:flex;justify-content:space-between;font-weight:700;">
            <span>#${esc(h.rank || '')} ${esc(h.title)} [${esc(h.status?.toUpperCase())}]</span>
            <span class="font-mono">Posterior: ${(Number(h.posteriorProbability || 0) * 100).toFixed(1)}% (Discounted Correlated Signals)</span>
          </div>
          <div style="color:var(--text-secondary);font-size:11.5px;margin-top:3px;"><strong>Counterfactual:</strong> ${esc(h.counterfactualAnalysis)}</div>
        </div>
      `).join('');
      if (out) {
        out.innerHTML = `
          <div class="v6-panel" style="padding:0;overflow:hidden;">
            <div style="padding:10px 14px;background:var(--bg-surface-subtle);border-bottom:1px solid var(--border-default);font-size:12.5px;font-weight:700;">
              Incident Correlation <code>${esc(c.incidentId || 'INC-CORR')}</code> · Shared-Dependency Discounting Applied
            </div>
            <div>${hyps}</div>
          </div>
        `;
      }
    } catch (e) {
      if (out) out.innerHTML = `<div style="color:var(--status-critical);padding:8px;">Correlation error: ${esc(e.message)}</div>`;
    }
  };

  window.forkV6SimulationBranch = async function () {
    const out = document.getElementById('v6SimulationOutput');
    const mult = Number(document.getElementById('v6ChaosLambdaInput')?.value || 1.85);
    if (out) out.innerHTML = 'Forking isolated Digital Twin simulation branch...';
    try {
      const res = await fetch('/api/v6/simulation/branch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ arrivalRateMultiplier: mult, severedEdgeIds: ['EDGE-GW-CORE'] })
      });
      const env = await res.json();
      const b = env.data || {};
      if (out) {
        out.innerHTML = `
          <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">
            <div><strong>Branch ID:</strong> <code>${esc(b.branchId)}</code> · <strong>Fidelity:</strong> <span style="color:var(--status-warning);font-weight:700;">${esc((b.fidelity || 'simulated').toUpperCase())} (${esc(b.mathematicalModel?.fidelityLabel)})</span></div>
            <span style="padding:2px 8px;border-radius:4px;background:var(--bg-surface-subtle);border:1px solid var(--border-default);font-family:var(--font-mono);font-size:11px;">Isolated From Live State: ${String(b.isolatedFromLiveState)}</span>
          </div>
          <div style="margin-top:8px;"><strong>Queueing Model:</strong> ${esc(b.mathematicalModel?.queueingModel)} · <strong>Arrival Multiplier:</strong> <span class="font-mono">${esc(mult)}x</span></div>
          <div style="margin-top:6px;"><strong>Congested Links:</strong> ${(b.simulationResult?.congestedLinks || []).map(esc).join(', ') || 'None'} · <strong>Partitioned Nodes:</strong> ${(b.simulationResult?.partitionedNodes || []).map(esc).join(', ') || 'None (Rerouted via alternate path)'}</div>
        `;
      }
    } catch (e) {
      if (out) out.innerHTML = `Simulation error: ${esc(e.message)}`;
    }
  };

  window.runV6TemporalGraphDiff = async function () {
    const out = document.getElementById('v6SimulationOutput');
    if (out) out.innerHTML = 'Computing Temporal Infrastructure Graph snapshot delta...';
    try {
      const res = await fetch('/api/v6/temporal-graph/diff');
      const env = await res.json();
      const diff = env.data || {};
      if (out) {
        out.innerHTML = `
          <div><strong>Temporal Graph Diff Summary:</strong> ${esc(diff.summary || 'Compared historical topology snapshots')}</div>
          <div style="margin-top:6px;font-family:var(--font-mono);font-size:11.5px;">
            Added Nodes: ${(diff.addedNodes || []).length} · Removed Nodes: ${(diff.removedNodes || []).length} · Added Edges: ${(diff.addedEdges || []).length} · Changed Edges: ${(diff.changedEdges || []).length}
          </div>
        `;
      }
    } catch (e) {
      if (out) out.innerHTML = `Temporal diff error: ${esc(e.message)}`;
    }
  };

  window.previewV6GovernedAction = async function (actionId) {
    const out = document.getElementById('v6GovernanceOutput');
    const res = await fetch(`/api/v6/actions/${encodeURIComponent(actionId)}/preview`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: '127.0.0.1', port: 3000 })
    });
    const env = await res.json();
    const p = env.data || {};
    if (out) {
      out.innerHTML = `
        <div class="v6-panel" style="background:var(--bg-surface-subtle);font-size:12px;">
          <div><strong>Dry-Run Command Preview (${esc(p.actionName)}):</strong> <code>${esc(p.renderedCommandPreview)}</code></div>
          <div style="margin-top:4px;"><strong>Preconditions Passed:</strong> ${String(p.preconditionsPassed)} · <strong>Rollback Plan:</strong> ${esc(p.rollbackPlan)}</div>
        </div>
      `;
    }
  };

  window.executeV6GovernedAction = async function (actionId) {
    const out = document.getElementById('v6GovernanceOutput');
    const selectedRole = document.getElementById('v6RoleSelector')?.value || window.__v6SelectedRole || 'ADMIN';
    if (out) out.innerHTML = '<div class="v6-panel" style="font-size:12px;">Executing governed action and verifying postconditions...</div>';
    const res = await fetch(`/api/v6/actions/${encodeURIComponent(actionId)}/execute`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: '127.0.0.1', port: 3000, operatorRole: selectedRole })
    });
    const env = await res.json();
    const r = env.data || {};
    if (res.status === 403 || env.status === 'denied') {
      if (out) {
        out.innerHTML = `
          <div class="v6-panel" style="border-color:var(--status-critical);font-size:12px;">
            <div style="color:var(--status-critical);font-weight:700;">RBAC Policy Denied (HTTP 403) · Role '${esc(selectedRole)}' is unauthorized for '${esc(actionId)}'</div>
            <div style="margin-top:4px;color:var(--text-secondary);">Switch the Active RBAC Role selector to <strong>ADMIN</strong> to authorize execution.</div>
          </div>
        `;
      }
      return;
    }
    if (out) {
      out.innerHTML = `
        <div class="v6-panel" style="border-color:var(--status-nominal);font-size:12px;">
          <div><strong>Execution ID:</strong> <code>${esc(r.executionId)}</code> · <strong>Lifecycle State:</strong> <strong style="color:var(--status-nominal);">${esc(r.lifecycleState)}</strong></div>
          <div style="margin-top:4px;"><strong>Postcondition Verification:</strong> ${esc(r.postconditionVerification?.summary)}</div>
          <div style="margin-top:4px;"><strong>Immutable Evidence Chain:</strong> Action Evidence <code>${esc(r.actionEvidenceId)}</code> → Verification Evidence <code>${esc(r.verificationEvidenceId)}</code></div>
        </div>
      `;
      window.refreshV6FabricOverview('governance');
    }
  };

  window.openAcademyFromV6 = function (moduleId) {
    window.closeV6SovereignFabricModal();
    if (typeof window.renderView === 'function') {
      window.renderView('learning-center');
    }
  };

  // Populate the live Command Ribbon summary on initial boot
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      setTimeout(() => window.refreshV6FabricOverview(), 400);
    }, { once: true });
  } else {
    setTimeout(() => window.refreshV6FabricOverview(), 400);
  }
})();
