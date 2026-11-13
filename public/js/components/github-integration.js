/**
 * EJII — Real GitHub Account & Repository Integration Component
 * Manages sidebar connection status, OAuth popup flow, repository selection,
 * commit/workflow synchronization, and the GitHub Integration Modal.
 * Zero-Simulation Standard: Never displays Connected unless verified by /api/github/status.
 */

(function () {
  'use strict';

  const state = {
    loading: false,
    syncing: false,
    reposLoading: false,
    status: {
      connectionState: 'DISCONNECTED',
      connected: false,
      oauthConfigured: false,
      callbackUrl: window.location.origin + '/auth/github/callback',
      account: null,
      selectedRepo: null,
      latestCommit: null,
      latestCommits: [],
      latestWorkflow: null,
      latestWorkflows: [],
      rateLimit: null,
      syncEvents: [],
      lastError: null,
      lastSyncedAt: null
    },
    repos: [],
    uiNotice: null
  };

  function esc(val) {
    if (val === null || val === undefined) return '';
    return String(val).replace(/[<>&"']/g, function (c) {
      return { '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function formatRelativeTime(iso) {
    if (!iso) return 'Not yet synced';
    const ts = Date.parse(iso);
    if (Number.isNaN(ts)) return String(iso);
    const diffSec = Math.max(0, Math.floor((Date.now() - ts) / 1000));
    if (diffSec < 60) return 'Just now';
    if (diffSec < 3600) return Math.floor(diffSec / 60) + 'm ago';
    if (diffSec < 86400) return Math.floor(diffSec / 3600) + 'h ago';
    return Math.floor(diffSec / 86400) + 'd ago';
  }

  function getAuthHeaders() {
    const headers = { 'Content-Type': 'application/json' };
    try {
      const token = localStorage.getItem('ejii_token') || sessionStorage.getItem('ejii_token');
      if (token) headers['Authorization'] = 'Bearer ' + token;
    } catch (_) {}
    return headers;
  }

  async function fetchGitHubStatus() {
    state.loading = true;
    renderAllGitHubSurfaces();
    try {
      const res = await fetch('/api/github/status', { headers: getAuthHeaders() });
      const data = await res.json();
      if (data && typeof data === 'object') {
        state.status = {
          ...state.status,
          ...data,
          connected: Boolean(data.connected && data.connectionState === 'CONNECTED' && data.account)
        };
      }
    } catch (err) {
      state.status.connectionState = 'ERROR';
      state.status.connected = false;
      state.status.lastError = 'Unable to reach EJII GitHub service: ' + (err.message || 'Network error');
    } finally {
      state.loading = false;
      renderAllGitHubSurfaces();
      window.dispatchEvent(new CustomEvent('ejii:github-status-updated', { detail: state.status }));
    }
    return state.status;
  }

  async function fetchAccessibleRepos() {
    if (!state.status.connected) return [];
    state.reposLoading = true;
    renderModalIfOpen();
    try {
      const res = await fetch('/api/github/repos', { headers: getAuthHeaders() });
      const data = await res.json();
      if (res.ok && data && Array.isArray(data.repos)) {
        state.repos = data.repos;
      } else if (data && data.error) {
        state.uiNotice = { type: 'warning', text: data.error };
      }
    } catch (err) {
      state.uiNotice = { type: 'error', text: 'Failed to load repositories: ' + err.message };
    } finally {
      state.reposLoading = false;
      renderModalIfOpen();
    }
    return state.repos;
  }

  async function startGitHubOAuthFlow() {
    state.uiNotice = null;
    state.loading = true;
    renderAllGitHubSurfaces();

    try {
      const res = await fetch('/api/github/auth/url', { headers: getAuthHeaders() });
      const data = await res.json();

      if (!res.ok || !data || !data.url) {
        state.loading = false;
        state.uiNotice = {
          type: 'warning',
          text: (data && data.error)
            ? data.error
            : 'GitHub OAuth is not configured on this server. Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET to enable OAuth login.'
        };
        openGitHubIntegrationModal();
        renderAllGitHubSurfaces();
        return;
      }

      const authWindow = window.open(
        data.url,
        'github_oauth_popup',
        'width=600,height=700,menubar=no,toolbar=no,location=no,status=no'
      );

      if (!authWindow) {
        state.loading = false;
        state.uiNotice = {
          type: 'warning',
          text: 'Popup window was blocked by the browser. Please allow popups for this site and try again.'
        };
        openGitHubIntegrationModal();
        renderAllGitHubSurfaces();
      }
    } catch (err) {
      state.loading = false;
      state.uiNotice = {
        type: 'error',
        text: 'Could not initiate GitHub OAuth flow: ' + (err.message || 'Unknown error')
      };
      renderAllGitHubSurfaces();
    }
  }

  async function selectGitHubRepository(fullName) {
    if (!fullName) return;
    state.syncing = true;
    state.uiNotice = null;
    renderAllGitHubSurfaces();
    try {
      const res = await fetch('/api/github/select-repo', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ fullName })
      });
      const data = await res.json();
      if (res.ok && data) {
        state.status = {
          ...state.status,
          ...data,
          connected: Boolean(data.connected && data.connectionState === 'CONNECTED' && data.account)
        };
        state.uiNotice = { type: 'success', text: 'Active repository updated to ' + fullName + '.' };
      } else {
        state.uiNotice = { type: 'error', text: (data && data.error) || 'Could not select repository.' };
      }
    } catch (err) {
      state.uiNotice = { type: 'error', text: 'Repository selection failed: ' + err.message };
    } finally {
      state.syncing = false;
      renderAllGitHubSurfaces();
      window.dispatchEvent(new CustomEvent('ejii:github-status-updated', { detail: state.status }));
    }
  }

  async function syncGitHubNow() {
    state.syncing = true;
    state.uiNotice = null;
    renderAllGitHubSurfaces();
    try {
      const res = await fetch('/api/github/sync', {
        method: 'POST',
        headers: getAuthHeaders()
      });
      const data = await res.json();
      if (data && typeof data === 'object') {
        state.status = {
          ...state.status,
          ...data,
          connected: Boolean(data.connected && data.connectionState === 'CONNECTED' && data.account)
        };
        if (res.ok) {
          state.uiNotice = { type: 'success', text: 'Synchronized latest commits and workflow status from GitHub.' };
        } else {
          state.uiNotice = { type: 'warning', text: data.error || data.lastError || 'Sync completed with warnings.' };
        }
      }
    } catch (err) {
      state.uiNotice = { type: 'error', text: 'GitHub synchronization failed: ' + err.message };
    } finally {
      state.syncing = false;
      renderAllGitHubSurfaces();
      window.dispatchEvent(new CustomEvent('ejii:github-status-updated', { detail: state.status }));
    }
  }

  async function disconnectGitHubAccount() {
    state.syncing = true;
    state.uiNotice = null;
    renderAllGitHubSurfaces();
    try {
      const res = await fetch('/api/github/disconnect', {
        method: 'POST',
        headers: getAuthHeaders()
      });
      const data = await res.json();
      if (data && typeof data === 'object') {
        state.status = {
          ...state.status,
          ...data,
          connected: false
        };
        state.repos = [];
        state.uiNotice = { type: 'info', text: 'GitHub account disconnected.' };
      }
    } catch (err) {
      state.uiNotice = { type: 'error', text: 'Failed to disconnect GitHub account: ' + err.message };
    } finally {
      state.syncing = false;
      renderAllGitHubSurfaces();
      window.dispatchEvent(new CustomEvent('ejii:github-status-updated', { detail: state.status }));
    }
  }

  function renderSidebarWidget() {
    const el = document.getElementById('sidebarGitHubWidget');
    if (!el) return;

    const st = state.status;
    const isConnected = Boolean(st.connected && st.account);
    const connState = st.connectionState || 'DISCONNECTED';

    let badgeLabel = 'Disconnected';
    let badgeClass = 'gh-status-pill gh-status-disconnected';
    if (state.loading || state.syncing) {
      badgeLabel = 'Syncing…';
      badgeClass = 'gh-status-pill gh-status-loading';
    } else if (isConnected) {
      badgeLabel = 'Connected';
      badgeClass = 'gh-status-pill gh-status-connected';
    } else if (connState === 'RATE_LIMITED') {
      badgeLabel = 'Rate Limited';
      badgeClass = 'gh-status-pill gh-status-warning';
    } else if (connState === 'UNAUTHORIZED' || connState === 'ERROR') {
      badgeLabel = connState === 'UNAUTHORIZED' ? 'Auth Expired' : 'Error';
      badgeClass = 'gh-status-pill gh-status-error';
    }

    if (isConnected) {
      const repoLabel = st.selectedRepo ? st.selectedRepo.fullName : 'Select repository…';
      const branchLabel = st.selectedRepo ? st.selectedRepo.defaultBranch : '—';
      el.innerHTML = `
        <div class="gh-sidebar-card" onclick="window.openGitHubIntegrationModal()" role="button" tabindex="0" aria-label="Manage GitHub Integration">
          <div class="gh-sidebar-top">
            <div class="gh-sidebar-brand">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.403 5.403 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4"/><path d="M9 18c-4.51 2-5-2-7-2"/></svg>
              <span>GitHub</span>
            </div>
            <span class="${badgeClass}"><span class="gh-status-dot"></span>${esc(badgeLabel)}</span>
          </div>
          <div class="gh-sidebar-account">
            ${st.account.avatarUrl ? `<img src="${esc(st.account.avatarUrl)}" alt="" class="gh-sidebar-avatar">` : ''}
            <div class="gh-sidebar-meta">
              <div class="gh-sidebar-user">@${esc(st.account.login)}</div>
              <div class="gh-sidebar-repo" title="${esc(repoLabel)}">${esc(repoLabel)} (${esc(branchLabel)})</div>
            </div>
          </div>
        </div>
      `;
    } else {
      el.innerHTML = `
        <div class="gh-sidebar-card" onclick="window.openGitHubIntegrationModal()" role="button" tabindex="0" aria-label="Connect GitHub Account">
          <div class="gh-sidebar-top">
            <div class="gh-sidebar-brand">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.403 5.403 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4"/><path d="M9 18c-4.51 2-5-2-7-2"/></svg>
              <span>GitHub Account</span>
            </div>
            <span class="${badgeClass}"><span class="gh-status-dot"></span>${esc(badgeLabel)}</span>
          </div>
          <div class="gh-sidebar-cta">Connect repository &amp; CI status</div>
        </div>
      `;
    }
  }

  function renderModalIfOpen() {
    const modal = document.getElementById('ejiiGitHubModalOverlay');
    if (!modal || modal.style.display === 'none') return;
    modal.innerHTML = buildModalInnerHtml();
  }

  function buildWorkflowBadge(wf) {
    if (!wf) {
      return '<span class="gh-wf-badge gh-wf-neutral">No workflow runs reported</span>';
    }
    const conclusion = String(wf.conclusion || wf.status || '').toLowerCase();
    let cls = 'gh-wf-neutral';
    let label = wf.conclusion || wf.status || 'Unknown';
    if (conclusion === 'success') {
      cls = 'gh-wf-success';
      label = 'Passing';
    } else if (conclusion === 'failure' || conclusion === 'cancelled' || conclusion === 'timed_out') {
      cls = 'gh-wf-danger';
      label = 'Failed';
    } else if (conclusion === 'in_progress' || conclusion === 'queued') {
      cls = 'gh-wf-warning';
      label = 'Running';
    }
    return `<span class="gh-wf-badge ${cls}"><span class="gh-status-dot"></span>${esc(wf.name)}: ${esc(label)}</span>`;
  }

  function buildModalInnerHtml() {
    const st = state.status;
    const isConnected = Boolean(st.connected && st.account);
    const connState = st.connectionState || 'DISCONNECTED';

    let statusPill = '<span class="gh-status-pill gh-status-disconnected"><span class="gh-status-dot"></span>Disconnected</span>';
    if (state.loading || state.syncing) {
      statusPill = '<span class="gh-status-pill gh-status-loading"><span class="gh-status-dot"></span>Synchronizing…</span>';
    } else if (isConnected) {
      statusPill = '<span class="gh-status-pill gh-status-connected"><span class="gh-status-dot"></span>Connected</span>';
    } else if (connState === 'RATE_LIMITED') {
      statusPill = '<span class="gh-status-pill gh-status-warning"><span class="gh-status-dot"></span>Rate Limited</span>';
    } else if (connState === 'UNAUTHORIZED' || connState === 'ERROR') {
      statusPill = `<span class="gh-status-pill gh-status-error"><span class="gh-status-dot"></span>${esc(connState)}</span>`;
    }

    const noticeHtml = state.uiNotice
      ? `<div class="gh-modal-notice gh-notice-${esc(state.uiNotice.type)}">${esc(state.uiNotice.text)}</div>`
      : (st.lastError
          ? `<div class="gh-modal-notice gh-notice-warning">${esc(st.lastError)}</div>`
          : '');

    let bodyHtml = '';
    if (!isConnected) {
      bodyHtml = `
        <div class="gh-empty-state">
          <div class="gh-empty-icon">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.403 5.403 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4"/><path d="M9 18c-4.51 2-5-2-7-2"/></svg>
          </div>
          <h3 class="gh-empty-title">Connect your GitHub Account</h3>
          <p class="gh-empty-desc">
            Link your GitHub account via OAuth 2.0 to inspect repository branches, recent commits, and GitHub Actions workflow runs alongside infrastructure diagnostics. Access tokens are stored strictly on the server.
          </p>
          <div class="gh-empty-actions">
            <button type="button" class="ql-btn ql-btn-primary" onclick="window.ejiiGitHubIntegration.connect()" ${state.loading ? 'disabled' : ''}>
              ${state.loading ? 'Opening GitHub Authorization…' : 'Connect GitHub Account'}
            </button>
            <button type="button" class="ql-btn ql-btn-secondary" onclick="window.ejiiGitHubIntegration.refreshStatus()">
              Check Connection Status
            </button>
          </div>
          <div class="gh-oauth-config-box">
            <div class="gh-oauth-config-header">
              <span>OAuth Server Configuration</span>
              <span class="gh-config-flag ${st.oauthConfigured ? 'is-ready' : 'is-missing'}">
                ${st.oauthConfigured ? 'Credentials Configured' : 'Credentials Not Configured'}
              </span>
            </div>
            <p class="gh-oauth-config-note">
              Register the following Authorization Callback URL in your GitHub OAuth App settings and provide <code>GITHUB_CLIENT_ID</code> and <code>GITHUB_CLIENT_SECRET</code> in the server environment:
            </p>
            <div class="gh-callback-url-row">
              <code>${esc(st.callbackUrl || (window.location.origin + '/auth/github/callback'))}</code>
            </div>
          </div>
        </div>
      `;
    } else {
      const acct = st.account;
      const repo = st.selectedRepo;
      const commit = st.latestCommit;
      const wf = st.latestWorkflow;

      const repoOptions = state.repos.length > 0
        ? state.repos.map((r) => `<option value="${esc(r.fullName)}" ${repo && repo.fullName === r.fullName ? 'selected' : ''}>${esc(r.fullName)} (${esc(r.defaultBranch)})</option>`).join('')
        : (repo ? `<option value="${esc(repo.fullName)}" selected>${esc(repo.fullName)} (${esc(repo.defaultBranch)})</option>` : '<option value="">No repositories loaded</option>');

      bodyHtml = `
        <div class="gh-connected-grid">
          <div class="gh-section-card">
            <div class="gh-section-label">Authenticated Account</div>
            <div class="gh-account-row">
              ${acct.avatarUrl ? `<img src="${esc(acct.avatarUrl)}" alt="" class="gh-account-avatar">` : ''}
              <div class="gh-account-details">
                <div class="gh-account-name">${esc(acct.name || acct.login)}</div>
                <div class="gh-account-handle">@${esc(acct.login)}</div>
              </div>
              <div class="gh-account-actions">
                <button type="button" class="ql-btn ql-btn-secondary" onclick="window.ejiiGitHubIntegration.sync()" ${state.syncing ? 'disabled' : ''}>
                  ${state.syncing ? 'Syncing…' : 'Sync Now'}
                </button>
                <button type="button" class="ql-btn ql-btn-danger-subtle" onclick="window.ejiiGitHubIntegration.disconnect()" ${state.syncing ? 'disabled' : ''}>
                  Disconnect
                </button>
              </div>
            </div>
          </div>

          <div class="gh-section-card">
            <div class="gh-section-header-row">
              <div class="gh-section-label">Active Repository</div>
              <button type="button" class="ql-link-btn" onclick="window.ejiiGitHubIntegration.loadRepos()">
                ${state.reposLoading ? 'Loading list…' : 'Load repositories'}
              </button>
            </div>
            <div class="gh-repo-selector-row">
              <select class="ql-select" onchange="window.ejiiGitHubIntegration.selectRepo(this.value)" aria-label="Select GitHub Repository">
                ${repoOptions}
              </select>
            </div>
            ${repo ? `
              <div class="gh-repo-kv-grid">
                <div class="gh-kv-item">
                  <span class="gh-kv-label">Repository</span>
                  <span class="gh-kv-val mono">${esc(repo.fullName)}</span>
                </div>
                <div class="gh-kv-item">
                  <span class="gh-kv-label">Default Branch</span>
                  <span class="gh-kv-val mono">${esc(repo.defaultBranch)}</span>
                </div>
                <div class="gh-kv-item">
                  <span class="gh-kv-label">Visibility</span>
                  <span class="gh-kv-val">${repo.private ? 'Private' : 'Public'}</span>
                </div>
                <div class="gh-kv-item">
                  <span class="gh-kv-label">Last Synchronized</span>
                  <span class="gh-kv-val">${esc(formatRelativeTime(st.lastSyncedAt))}</span>
                </div>
              </div>
            ` : '<p class="gh-muted-note">No repository selected yet.</p>'}
          </div>

          <div class="gh-section-card">
            <div class="gh-section-label">Latest Commit &amp; CI Workflow Status</div>
            ${commit ? `
              <div class="gh-commit-box">
                <div class="gh-commit-top">
                  <span class="gh-commit-sha mono">${esc(commit.shortSha || commit.sha)}</span>
                  <span class="gh-commit-msg">${esc(commit.message)}</span>
                </div>
                <div class="gh-commit-sub">
                  <span>Author: ${esc(commit.author)}</span>
                  <span>•</span>
                  <span>${esc(formatRelativeTime(commit.date))}</span>
                </div>
              </div>
            ` : '<p class="gh-muted-note">No commit metadata available for the selected repository.</p>'}
            <div class="gh-workflow-row">
              ${buildWorkflowBadge(wf)}
            </div>
          </div>
        </div>
      `;
    }

    return `
      <div class="gh-modal-dialog" role="dialog" aria-modal="true" aria-labelledby="ghModalTitle" onclick="event.stopPropagation()">
        <div class="gh-modal-header">
          <div>
            <div class="gh-modal-eyebrow">Source Control &amp; CI Telemetry</div>
            <h2 id="ghModalTitle" class="gh-modal-title">GitHub Account Integration</h2>
          </div>
          <div class="gh-modal-header-right">
            ${statusPill}
            <button type="button" class="gh-modal-close" onclick="window.closeGitHubIntegrationModal()" aria-label="Close GitHub modal">✕</button>
          </div>
        </div>
        ${noticeHtml}
        <div class="gh-modal-body">
          ${bodyHtml}
        </div>
      </div>
    `;
  }

  function openGitHubIntegrationModal() {
    let modal = document.getElementById('ejiiGitHubModalOverlay');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'ejiiGitHubModalOverlay';
      modal.className = 'gh-modal-overlay';
      modal.addEventListener('click', function () {
        closeGitHubIntegrationModal();
      });
      document.body.appendChild(modal);
    }
    modal.innerHTML = buildModalInnerHtml();
    modal.style.display = 'flex';
    if (state.status.connected && state.repos.length === 0) {
      fetchAccessibleRepos();
    }
  }

  function closeGitHubIntegrationModal() {
    const modal = document.getElementById('ejiiGitHubModalOverlay');
    if (modal) {
      modal.style.display = 'none';
    }
  }

  function renderAllGitHubSurfaces() {
    renderSidebarWidget();
    renderModalIfOpen();
    if (typeof window.renderOverviewGitHubCard === 'function') {
      window.renderOverviewGitHubCard(state.status, state.loading || state.syncing);
    }
  }

  // Listen for OAuth popup completion messages
  window.addEventListener('message', function (event) {
    const data = event && event.data;
    if (!data || typeof data !== 'object') return;
    if (data.type === 'OAUTH_AUTH_SUCCESS' && (!data.provider || data.provider === 'github')) {
      state.uiNotice = {
        type: 'success',
        text: data.message || 'GitHub account connected.'
      };
      fetchGitHubStatus().then(function () {
        fetchAccessibleRepos();
      });
    } else if (data.type === 'OAUTH_AUTH_ERROR' && (!data.provider || data.provider === 'github')) {
      state.loading = false;
      state.uiNotice = {
        type: 'warning',
        text: data.message || 'GitHub authorization was not completed.'
      };
      fetchGitHubStatus();
    }
  });

  window.openGitHubIntegrationModal = openGitHubIntegrationModal;
  window.closeGitHubIntegrationModal = closeGitHubIntegrationModal;
  window.ejiiGitHubIntegration = {
    getState: function () { return state.status; },
    refreshStatus: fetchGitHubStatus,
    connect: startGitHubOAuthFlow,
    loadRepos: fetchAccessibleRepos,
    selectRepo: selectGitHubRepository,
    sync: syncGitHubNow,
    disconnect: disconnectGitHubAccount,
    openModal: openGitHubIntegrationModal,
    closeModal: closeGitHubIntegrationModal
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      renderSidebarWidget();
      fetchGitHubStatus();
    });
  } else {
    renderSidebarWidget();
    fetchGitHubStatus();
  }
})();
