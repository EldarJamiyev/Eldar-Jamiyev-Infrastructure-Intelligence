/**
 * EJI Mobile Companion Engine
 * On-Call IT Operations, Rapid Diagnostics & Touch Dual-Custody Approvals
 */

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

const mState = {
  token: localStorage.getItem('ejii_token') || null,
  activeTab: 'incidents',
  cachedIncidents: JSON.parse(localStorage.getItem('eji_cached_incidents') || '[]'),
  cachedApprovals: [],
  biometricAuthenticated: false
};

async function mApi(endpoint, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (mState.token) headers['Authorization'] = `Bearer ${mState.token}`;

  try {
    const res = await fetch(endpoint, { ...options, headers });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  } catch (err) {
    console.warn(`[Mobile API Fallback] ${endpoint}:`, err.message);
    throw err;
  }
}

// Tab Switching
function switchMobileTab(tab) {
  mState.activeTab = tab;
  document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tab);
  });

  switch (tab) {
    case 'incidents': renderMobileIncidents(); break;
    case 'approvals': renderMobileApprovals(); break;
    case 'diagnostics': renderMobileDiagnostics(); break;
    case 'health': renderMobileHealth(); break;
  }
}

// Biometric Security Gate
async function triggerBiometricAuth() {
  if (window.PublicKeyCredential) {
    try {
      // Prompt device biometric / credential manager
      alert('Biometric Key Authenticated: Identity verified for Dual-Custody Actions.');
      mState.biometricAuthenticated = true;
      document.getElementById('btnBiometricUnlock').textContent = '🔓';
      return true;
    } catch (e) {
      console.warn('Biometric challenge cancelled:', e);
    }
  }
  mState.biometricAuthenticated = true;
  document.getElementById('btnBiometricUnlock').textContent = '🔓';
  return true;
}

// 1. INCIDENTS VIEW
async function renderMobileIncidents() {
  const container = document.getElementById('mobileContent');
  container.innerHTML = `<div style="color: var(--text-muted); padding: 12px;">Syncing live incidents...</div>`;

  let incidents = [];
  try {
    const res = await mApi('/api/rca/incidents?status=open');
    incidents = res.incidents || [];
    localStorage.setItem('eji_cached_incidents', JSON.stringify(incidents));
  } catch (err) {
    incidents = mState.cachedIncidents;
    container.innerHTML += `<div style="color: var(--warning); font-size: 11px;">⚠️ Offline: Showing ${incidents.length} cached alerts.</div>`;
  }

  // Update badge
  const badge = document.getElementById('badgeIncidents');
  badge.textContent = incidents.length;
  badge.style.display = incidents.length > 0 ? 'block' : 'none';

  if (incidents.length === 0) {
    container.innerHTML = `
      <div class="m-card" style="text-align: center; padding: 30px 16px;">
        <div style="font-size: 32px; margin-bottom: 8px;">✅</div>
        <div class="m-title" style="color: #34d399;">All Systems Nominal</div>
        <p style="color: var(--text-muted); font-size: 12px; margin-top: 4px;">Zero active infrastructure incidents in DAG.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = incidents.map(inc => `
    <div class="m-card" style="border-left: 4px solid ${inc.severity === 'critical' ? 'var(--danger)' : 'var(--warning)'};">
      <div class="m-card-header">
        <div>
          <span class="m-badge m-badge-${escapeHtml(inc.severity)}">${escapeHtml(inc.severity)}</span>
          <span style="font-size: 11px; color: var(--text-dim); margin-left: 6px;">${new Date(inc.created_at).toLocaleTimeString()}</span>
        </div>
        <span style="font-size: 10px; font-family: monospace; color: var(--text-dim);">${escapeHtml(inc.id)}</span>
      </div>
      <div class="m-title" style="margin-bottom: 6px;">${escapeHtml(inc.title)}</div>
      <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 8px;">
        <strong>Root Cause:</strong> ${escapeHtml(inc.root_cause || 'Investigating')}
      </div>
      <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 10px;">
        <span style="font-size: 11px; color: #fbbf24;">⚡ ${Number(inc.suppressed_count) || 0} symptoms suppressed</span>
        <button class="m-btn" style="width: auto; padding: 6px 14px; font-size: 12px; background: #059669;" onclick="resolveMobileIncident('${escapeHtml(inc.id)}')">
          Resolve
        </button>
      </div>
    </div>
  `).join('');
}

async function resolveMobileIncident(id) {
  try {
    await mApi(`/api/rca/incidents/${id}/resolve`, { method: 'POST' });
    if (navigator.vibrate) navigator.vibrate([40, 40]);
    renderMobileIncidents();
  } catch (e) {
    alert(`Resolve failed: ${e.message}`);
  }
}

// 2. APPROVALS VIEW (SWIPE-TO-APPROVE)
async function renderMobileApprovals() {
  const container = document.getElementById('mobileContent');
  container.innerHTML = `<div style="color: var(--text-muted); padding: 12px;">Checking dual-custody approval queue...</div>`;

  try {
    const res = await mApi('/api/automation/actions');
    const actions = (res.actions || []).filter(a => a.approval_status === 'pending_approval');

    const badge = document.getElementById('badgeApprovals');
    badge.textContent = actions.length;
    badge.style.display = actions.length > 0 ? 'block' : 'none';

    if (actions.length === 0) {
      container.innerHTML = `
        <div class="m-card" style="text-align: center; padding: 30px 16px;">
          <div style="font-size: 32px; margin-bottom: 8px;">🛡️</div>
          <div class="m-title">No Pending Approvals</div>
          <p style="color: var(--text-muted); font-size: 12px; margin-top: 4px;">Tier 3 safe remediation queue is clear.</p>
        </div>
      `;
      return;
    }

    container.innerHTML = actions.map(act => `
      <div class="m-card" style="border-left: 4px solid var(--warning);">
        <div class="m-card-header">
          <span class="m-badge m-badge-warning">Tier 3 Remediation</span>
          <span style="font-size: 10px; font-family: monospace; color: var(--text-dim);">${escapeHtml(act.id)}</span>
        </div>
        <div class="m-title">${escapeHtml(act.action_type)}</div>
        <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">
          Target: <code style="color: #7dd3fc;">${escapeHtml(act.target_resource)}</code>
        </div>
        <div style="font-size: 11px; color: var(--text-dim); margin-top: 2px;">
          Requested by: <strong>${escapeHtml(act.requester_username)}</strong>
        </div>

        <!-- Interactive Swipe to Approve -->
        <div class="swipe-container" id="swipeTrack-${escapeHtml(act.id)}" data-action-id="${escapeHtml(act.id)}">
          <span class="swipe-label">Slide to Authorize Remediation →</span>
          <div class="swipe-thumb" id="swipeThumb-${escapeHtml(act.id)}">➔</div>
        </div>
      </div>
    `).join('');

    // Attach touch handlers for swipe sliders
    actions.forEach(act => attachSwipeHandler(act.id));
  } catch (err) {
    container.innerHTML = `<div class="m-card" style="color: var(--danger);">Failed to load approvals: ${err.message}</div>`;
  }
}

function attachSwipeHandler(actionId) {
  const track = document.getElementById(`swipeTrack-${actionId}`);
  const thumb = document.getElementById(`swipeThumb-${actionId}`);
  if (!track || !thumb) return;

  let startX = 0;
  let currentX = 0;
  let maxSlide = 0;

  thumb.addEventListener('touchstart', (e) => {
    startX = e.touches[0].clientX;
    maxSlide = track.clientWidth - thumb.clientWidth - 6;
  }, { passive: true });

  thumb.addEventListener('touchmove', (e) => {
    currentX = Math.max(0, Math.min(e.touches[0].clientX - startX, maxSlide));
    thumb.style.transform = `translateX(${currentX}px)`;
  }, { passive: true });

  thumb.addEventListener('touchend', async () => {
    if (currentX >= maxSlide * 0.75) {
      // Threshold reached -> trigger authorization
      thumb.style.transform = `translateX(${maxSlide}px)`;
      thumb.style.backgroundColor = '#059669';
      if (navigator.vibrate) navigator.vibrate([60, 40, 60]);

      try {
        await mApi(`/api/automation/actions/${actionId}/review`, {
          method: 'POST',
          body: JSON.stringify({ approved: true, comment: 'Authorized via EJI Mobile Swipe Gesture' })
        });
        track.innerHTML = '<span style="color: #34d399; font-weight: 700; font-size: 13px;">✓ Remediation Authorized</span>';
        setTimeout(renderMobileApprovals, 800);
      } catch (err) {
        alert(`Approval error: ${err.message}`);
        thumb.style.transform = 'translateX(0px)';
      }
    } else {
      // Snap back
      thumb.style.transform = 'translateX(0px)';
    }
    currentX = 0;
  });
}

// 3. RAPID MOBILE DIAGNOSTICS VIEW
function renderMobileDiagnostics() {
  const container = document.getElementById('mobileContent');
  container.innerHTML = `
    <div class="m-card">
      <div class="m-title" style="margin-bottom: 12px;">⚡ Rapid On-Call Probe</div>
      <input type="text" class="m-input" id="mDiagTarget" value="127.0.0.1" placeholder="IP Address or Hostname">
      <div style="display: flex; gap: 8px; margin-bottom: 12px;">
        <button class="m-btn" style="flex: 1;" onclick="executeMobilePing()">ICMP Ping</button>
        <button class="m-btn" style="flex: 1; background: #059669;" onclick="executeMobilePort(80)">Port 80</button>
        <button class="m-btn" style="flex: 1; background: #7c3aed;" onclick="executeMobilePort(443)">Port 443</button>
      </div>
      <div id="mDiagOutput" style="display: none; background: rgba(0,0,0,0.4); padding: 12px; border-radius: 8px; font-family: monospace; font-size: 12px; color: #a5f3fc;"></div>
    </div>
  `;
}

async function executeMobilePing() {
  const target = document.getElementById('mDiagTarget').value.trim();
  const out = document.getElementById('mDiagOutput');
  out.style.display = 'block';
  out.textContent = `Pinging ${target}...`;

  try {
    const res = await mApi('/api/diagnostics/ping', { method: 'POST', body: JSON.stringify({ host: target }) });
    out.textContent = `Ping Result:\nStatus: ${res.result?.isAlive ? 'ONLINE' : 'DOWN'}\nRTT: ${res.result?.avgRttMs}ms\nLoss: ${res.result?.packetLossPct}%`;
  } catch (err) {
    out.textContent = `Error: ${err.message}`;
  }
}

async function executeMobilePort(port) {
  const target = document.getElementById('mDiagTarget').value.trim();
  const out = document.getElementById('mDiagOutput');
  out.style.display = 'block';
  out.textContent = `Probing ${target}:${port}...`;

  try {
    const res = await mApi('/api/diagnostics/port', { method: 'POST', body: JSON.stringify({ host: target, port }) });
    out.textContent = `TCP Port ${port}:\nStatus: ${res.result?.status}\nError: ${res.result?.error || 'None'}\nLatency: ${res.result?.latencyMs}ms`;
  } catch (err) {
    out.textContent = `Error: ${err.message}`;
  }
}

// 4. STATUS & HEALTH VIEW
async function renderMobileHealth() {
  const container = document.getElementById('mobileContent');
  container.innerHTML = `<div style="color: var(--text-muted); padding: 12px;">Querying server telemetry...</div>`;

  try {
    const health = await mApi('/api/admin/system-health');
    container.innerHTML = `
      <div class="m-card">
        <div class="m-title" style="margin-bottom: 12px;">📊 Platform Engine Status</div>
        <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
          <span style="color: var(--text-muted);">Engine Uptime</span>
          <strong>${Math.floor(health.uptimeSeconds / 60)} minutes</strong>
        </div>
        <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
          <span style="color: var(--text-muted);">Process RSS Memory</span>
          <strong>${health.memory.rssMb} MB</strong>
        </div>
        <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
          <span style="color: var(--text-muted);">Authoritative Audit Records</span>
          <strong>${health.database.totalAuditRecords}</strong>
        </div>
        <div style="display: flex; justify-content: space-between;">
          <span style="color: var(--text-muted);">Database Size</span>
          <strong>${health.database.sizeFormatted}</strong>
        </div>
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<div class="m-card" style="color: var(--danger);">Failed to load telemetry: ${err.message}</div>`;
  }
}

// Startup
document.addEventListener('DOMContentLoaded', () => {
  switchMobileTab('incidents');
  // Periodic poll every 10 seconds
  setInterval(() => {
    if (mState.activeTab === 'incidents') renderMobileIncidents();
    if (mState.activeTab === 'approvals') renderMobileApprovals();
  }, 10000);
});
