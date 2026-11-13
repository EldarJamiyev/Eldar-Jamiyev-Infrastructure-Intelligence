/**
 * EJII — Real GitHub Account & Repository Integration Routes
 * Implements OAuth 2.0 authorization code flow with popup callback,
 * server-side token storage, and live GitHub REST API v3 synchronization.
 * Zero-Simulation Standard: Never fabricates connected state, commits, or CI runs.
 */

'use strict';

const express = require('express');
const crypto = require('crypto');
const https = require('https');
const { db } = require('../db/database');

const router = express.Router();

// Ensure server-side storage table exists for GitHub OAuth session metadata (tokens stay strictly server-side)
try {
  db.exec(`
    CREATE TABLE IF NOT EXISTS github_integration_state (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      connection_state TEXT NOT NULL DEFAULT 'DISCONNECTED',
      access_token_enc TEXT,
      github_user_json TEXT,
      selected_repo_json TEXT,
      latest_commits_json TEXT,
      latest_workflows_json TEXT,
      rate_limit_json TEXT,
      sync_events_json TEXT,
      last_error TEXT,
      last_synced_at TEXT,
      updated_at TEXT DEFAULT (datetime('now'))
    );
  `);
} catch (_) {}

// Ephemeral CSRF state store for OAuth flow (maps state -> { createdAt, redirectUri })
const pendingOAuthStates = new Map();

function cleanupExpiredStates() {
  const now = Date.now();
  for (const [key, val] of pendingOAuthStates.entries()) {
    if (now - val.createdAt > 10 * 60 * 1000) {
      pendingOAuthStates.delete(key);
    }
  }
}

function getOAuthConfig(req) {
  const clientId = (process.env.GITHUB_CLIENT_ID || '').trim();
  const clientSecret = (process.env.GITHUB_CLIENT_SECRET || '').trim();
  const configured = Boolean(clientId && clientSecret);

  let baseUrl = (process.env.APP_URL || '').trim().replace(/\/+$/, '');
  if (!baseUrl && req) {
    const proto = (req.headers['x-forwarded-proto'] || req.protocol || 'http').split(',')[0].trim();
    const host = req.headers['x-forwarded-host'] || req.headers.host || 'localhost:3000';
    baseUrl = `${proto}://${host}`;
  }
  const redirectUri = `${baseUrl}/auth/github/callback`;
  return { clientId, clientSecret, configured, baseUrl, redirectUri };
}

function getStoredState() {
  try {
    const row = db.prepare('SELECT * FROM github_integration_state WHERE id = 1').get();
    if (!row) {
      return {
        connectionState: 'DISCONNECTED',
        accessToken: null,
        user: null,
        selectedRepo: null,
        latestCommits: [],
        latestWorkflows: [],
        rateLimit: null,
        syncEvents: [],
        lastError: null,
        lastSyncedAt: null
      };
    }
    return {
      connectionState: row.connection_state || 'DISCONNECTED',
      accessToken: row.access_token_enc || null,
      user: safeJsonParse(row.github_user_json, null),
      selectedRepo: safeJsonParse(row.selected_repo_json, null),
      latestCommits: safeJsonParse(row.latest_commits_json, []),
      latestWorkflows: safeJsonParse(row.latest_workflows_json, []),
      rateLimit: safeJsonParse(row.rate_limit_json, null),
      syncEvents: safeJsonParse(row.sync_events_json, []),
      lastError: row.last_error || null,
      lastSyncedAt: row.last_synced_at || null
    };
  } catch (err) {
    return {
      connectionState: 'ERROR',
      accessToken: null,
      user: null,
      selectedRepo: null,
      latestCommits: [],
      latestWorkflows: [],
      rateLimit: null,
      syncEvents: [],
      lastError: err.message,
      lastSyncedAt: null
    };
  }
}

function saveStoredState(patch) {
  const current = getStoredState();
  const next = { ...current, ...patch };
  try {
    db.prepare(`
      INSERT INTO github_integration_state (
        id, connection_state, access_token_enc, github_user_json, selected_repo_json,
        latest_commits_json, latest_workflows_json, rate_limit_json, sync_events_json,
        last_error, last_synced_at, updated_at
      ) VALUES (
        1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now')
      )
      ON CONFLICT(id) DO UPDATE SET
        connection_state = excluded.connection_state,
        access_token_enc = excluded.access_token_enc,
        github_user_json = excluded.github_user_json,
        selected_repo_json = excluded.selected_repo_json,
        latest_commits_json = excluded.latest_commits_json,
        latest_workflows_json = excluded.latest_workflows_json,
        rate_limit_json = excluded.rate_limit_json,
        sync_events_json = excluded.sync_events_json,
        last_error = excluded.last_error,
        last_synced_at = excluded.last_synced_at,
        updated_at = datetime('now')
    `).run(
      next.connectionState || 'DISCONNECTED',
      next.accessToken || null,
      next.user ? JSON.stringify(next.user) : null,
      next.selectedRepo ? JSON.stringify(next.selectedRepo) : null,
      JSON.stringify(Array.isArray(next.latestCommits) ? next.latestCommits : []),
      JSON.stringify(Array.isArray(next.latestWorkflows) ? next.latestWorkflows : []),
      next.rateLimit ? JSON.stringify(next.rateLimit) : null,
      JSON.stringify(Array.isArray(next.syncEvents) ? next.syncEvents.slice(0, 20) : []),
      next.lastError || null,
      next.lastSyncedAt || null
    );
  } catch (_) {}
  return next;
}

function safeJsonParse(str, fallback) {
  if (!str) return fallback;
  try {
    return JSON.parse(str);
  } catch (_) {
    return fallback;
  }
}

function appendSyncEvent(events, type, summary, detail = null) {
  const list = Array.isArray(events) ? [...events] : [];
  list.unshift({
    id: 'gh-evt-' + crypto.randomBytes(4).toString('hex'),
    type,
    summary,
    detail,
    timestamp: new Date().toISOString()
  });
  return list.slice(0, 20);
}

/**
 * Performs an HTTPS request to GitHub API or OAuth endpoint.
 */
function githubRequest(options, postBody = null) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let raw = '';
      res.on('data', (chunk) => { raw += chunk; });
      res.on('end', () => {
        const rateLimit = {
          limit: res.headers['x-ratelimit-limit'] ? Number(res.headers['x-ratelimit-limit']) : null,
          remaining: res.headers['x-ratelimit-remaining'] ? Number(res.headers['x-ratelimit-remaining']) : null,
          resetAt: res.headers['x-ratelimit-reset']
            ? new Date(Number(res.headers['x-ratelimit-reset']) * 1000).toISOString()
            : null
        };
        let parsed = null;
        try {
          parsed = raw ? JSON.parse(raw) : {};
        } catch (_) {
          parsed = { raw };
        }
        resolve({
          statusCode: res.statusCode || 500,
          headers: res.headers,
          data: parsed,
          rateLimit
        });
      });
    });
    req.on('error', (err) => reject(err));
    req.setTimeout(10000, () => {
      req.destroy(new Error('GitHub API request timed out after 10s'));
    });
    if (postBody) {
      req.write(postBody);
    }
    req.end();
  });
}

async function fetchGitHubApi(apiPath, accessToken) {
  const headers = {
    'User-Agent': 'EJII-Infrastructure-Intelligence/6.0',
    'Accept': 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28'
  };
  if (accessToken) {
    headers['Authorization'] = `Bearer ${accessToken}`;
  }
  return githubRequest({
    hostname: 'api.github.com',
    port: 443,
    path: apiPath,
    method: 'GET',
    headers
  });
}

async function syncRepositoryTelemetry(accessToken, owner, repo, currentEvents = []) {
  const repoRes = await fetchGitHubApi(`/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`, accessToken);
  if (repoRes.statusCode === 401) {
    return {
      connectionState: 'UNAUTHORIZED',
      lastError: 'GitHub access token expired or was revoked. Please reconnect your GitHub account.',
      rateLimit: repoRes.rateLimit
    };
  }
  if (repoRes.statusCode === 403 && repoRes.rateLimit && repoRes.rateLimit.remaining === 0) {
    return {
      connectionState: 'RATE_LIMITED',
      lastError: `GitHub API rate limit reached. Resets at ${repoRes.rateLimit.resetAt || 'next window'}.`,
      rateLimit: repoRes.rateLimit
    };
  }
  if (repoRes.statusCode < 200 || repoRes.statusCode >= 300) {
    return {
      connectionState: 'CONNECTED',
      lastError: (repoRes.data && repoRes.data.message) ? repoRes.data.message : `Repository lookup returned HTTP ${repoRes.statusCode}`,
      rateLimit: repoRes.rateLimit
    };
  }

  const repoData = repoRes.data || {};
  const selectedRepo = {
    id: repoData.id,
    name: repoData.name,
    owner: repoData.owner ? repoData.owner.login : owner,
    fullName: repoData.full_name || `${owner}/${repo}`,
    private: Boolean(repoData.private),
    defaultBranch: repoData.default_branch || 'main',
    description: repoData.description || '',
    htmlUrl: repoData.html_url || `https://github.com/${owner}/${repo}`,
    updatedAt: repoData.updated_at || null,
    pushedAt: repoData.pushed_at || null,
    openIssuesCount: typeof repoData.open_issues_count === 'number' ? repoData.open_issues_count : 0,
    stargazersCount: typeof repoData.stargazers_count === 'number' ? repoData.stargazers_count : 0
  };

  // Fetch latest commits on default branch
  let latestCommits = [];
  try {
    const commitsRes = await fetchGitHubApi(
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/commits?per_page=5`,
      accessToken
    );
    if (commitsRes.statusCode === 200 && Array.isArray(commitsRes.data)) {
      latestCommits = commitsRes.data.map((c) => ({
        sha: c.sha,
        shortSha: c.sha ? String(c.sha).slice(0, 7) : '',
        message: c.commit && c.commit.message ? String(c.commit.message).split('\n')[0] : '',
        author: (c.commit && c.commit.author && c.commit.author.name) || (c.author && c.author.login) || 'Unknown',
        authorAvatar: (c.author && c.author.avatar_url) || null,
        date: (c.commit && c.commit.author && c.commit.author.date) || null,
        htmlUrl: c.html_url || null
      }));
    }
  } catch (_) {}

  // Fetch latest GitHub Actions workflow runs
  let latestWorkflows = [];
  try {
    const runsRes = await fetchGitHubApi(
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/actions/runs?per_page=5`,
      accessToken
    );
    if (runsRes.statusCode === 200 && runsRes.data && Array.isArray(runsRes.data.workflow_runs)) {
      latestWorkflows = runsRes.data.workflow_runs.map((r) => ({
        id: r.id,
        name: r.name || r.display_title || 'Workflow',
        displayTitle: r.display_title || r.name || '',
        status: r.status || 'unknown',
        conclusion: r.conclusion || null,
        branch: r.head_branch || selectedRepo.defaultBranch,
        headSha: r.head_sha ? String(r.head_sha).slice(0, 7) : '',
        event: r.event || '',
        createdAt: r.created_at || null,
        updatedAt: r.updated_at || null,
        htmlUrl: r.html_url || null
      }));
    }
  } catch (_) {}

  const syncEvents = appendSyncEvent(
    currentEvents,
    'REPO_SYNC',
    `Synchronized ${selectedRepo.fullName} (${selectedRepo.defaultBranch})`,
    latestCommits[0] ? `Latest commit ${latestCommits[0].shortSha}: ${latestCommits[0].message}` : 'Metadata updated'
  );

  return {
    connectionState: 'CONNECTED',
    selectedRepo,
    latestCommits,
    latestWorkflows,
    rateLimit: repoRes.rateLimit,
    syncEvents,
    lastError: null,
    lastSyncedAt: new Date().toISOString()
  };
}

function buildPublicStatusPayload(req) {
  const oauth = getOAuthConfig(req);
  const state = getStoredState();
  const isConnected = state.connectionState === 'CONNECTED' && Boolean(state.accessToken && state.user);

  return {
    ok: true,
    connectionState: isConnected ? 'CONNECTED' : (state.connectionState === 'CONNECTED' ? 'DISCONNECTED' : state.connectionState),
    connected: isConnected,
    oauthConfigured: oauth.configured,
    callbackUrl: oauth.redirectUri,
    account: isConnected ? state.user : null,
    selectedRepo: isConnected ? state.selectedRepo : null,
    latestCommit: (isConnected && Array.isArray(state.latestCommits) && state.latestCommits.length > 0)
      ? state.latestCommits[0]
      : null,
    latestCommits: isConnected ? state.latestCommits : [],
    latestWorkflow: (isConnected && Array.isArray(state.latestWorkflows) && state.latestWorkflows.length > 0)
      ? state.latestWorkflows[0]
      : null,
    latestWorkflows: isConnected ? state.latestWorkflows : [],
    rateLimit: state.rateLimit || null,
    syncEvents: state.syncEvents || [],
    lastError: state.lastError || null,
    lastSyncedAt: isConnected ? state.lastSyncedAt : null
  };
}

/**
 * GET /api/github/status
 * Returns real connection state, connected account, selected repository, commits, and CI status.
 */
router.get('/status', (req, res) => {
  res.json(buildPublicStatusPayload(req));
});

/**
 * GET /api/github/auth/url
 * Constructs the GitHub OAuth authorization URL for popup authentication.
 */
router.get('/auth/url', (req, res) => {
  cleanupExpiredStates();
  const oauth = getOAuthConfig(req);
  if (!oauth.configured) {
    return res.status(400).json({
      ok: false,
      oauthConfigured: false,
      callbackUrl: oauth.redirectUri,
      error: 'GitHub OAuth credentials (GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET) are not configured in the server environment.'
    });
  }

  const state = crypto.randomBytes(20).toString('hex');
  pendingOAuthStates.set(state, {
    createdAt: Date.now(),
    redirectUri: oauth.redirectUri
  });

  const params = new URLSearchParams({
    client_id: oauth.clientId,
    redirect_uri: oauth.redirectUri,
    scope: 'read:user repo workflow',
    state
  });

  res.json({
    ok: true,
    oauthConfigured: true,
    url: `https://github.com/login/oauth/authorize?${params.toString()}`,
    callbackUrl: oauth.redirectUri
  });
});

/**
 * Shared OAuth callback handler for /auth/github/callback and /api/github/callback
 */
async function handleGitHubOAuthCallback(req, res) {
  cleanupExpiredStates();
  const { code, state, error, error_description } = req.query || {};

  if (error) {
    const msg = error_description || error || 'GitHub authorization was cancelled or denied.';
    saveStoredState({
      connectionState: 'DISCONNECTED',
      lastError: String(msg)
    });
    return res.status(400).send(renderOAuthPopupHtml(false, msg));
  }

  if (!code || !state || !pendingOAuthStates.has(String(state))) {
    const msg = 'Invalid or expired OAuth state parameter. Please try connecting again.';
    return res.status(400).send(renderOAuthPopupHtml(false, msg));
  }

  const stateRecord = pendingOAuthStates.get(String(state));
  pendingOAuthStates.delete(String(state));

  const oauth = getOAuthConfig(req);
  if (!oauth.configured) {
    const msg = 'Server is missing GITHUB_CLIENT_ID or GITHUB_CLIENT_SECRET.';
    return res.status(500).send(renderOAuthPopupHtml(false, msg));
  }

  try {
    const postData = JSON.stringify({
      client_id: oauth.clientId,
      client_secret: oauth.clientSecret,
      code: String(code),
      redirect_uri: stateRecord.redirectUri || oauth.redirectUri
    });

    const tokenRes = await githubRequest({
      hostname: 'github.com',
      port: 443,
      path: '/login/oauth/access_token',
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData),
        'User-Agent': 'EJII-Infrastructure-Intelligence/6.0'
      }
    }, postData);

    const accessToken = tokenRes.data && tokenRes.data.access_token;
    if (!accessToken) {
      const errMsg = (tokenRes.data && (tokenRes.data.error_description || tokenRes.data.error)) || 'Failed to exchange authorization code for token.';
      saveStoredState({
        connectionState: 'ERROR',
        lastError: errMsg
      });
      return res.status(400).send(renderOAuthPopupHtml(false, errMsg));
    }

    // Fetch authenticated user profile
    const userRes = await fetchGitHubApi('/user', accessToken);
    if (userRes.statusCode !== 200 || !userRes.data || !userRes.data.login) {
      const errMsg = 'Could not verify GitHub user identity after token exchange.';
      saveStoredState({
        connectionState: 'UNAUTHORIZED',
        lastError: errMsg
      });
      return res.status(401).send(renderOAuthPopupHtml(false, errMsg));
    }

    const userProfile = {
      id: userRes.data.id,
      login: userRes.data.login,
      name: userRes.data.name || userRes.data.login,
      avatarUrl: userRes.data.avatar_url || null,
      htmlUrl: userRes.data.html_url || `https://github.com/${userRes.data.login}`,
      publicRepos: userRes.data.public_repos || 0,
      totalPrivateRepos: userRes.data.total_private_repos || 0
    };

    const current = getStoredState();
    const events = appendSyncEvent(
      current.syncEvents,
      'ACCOUNT_CONNECTED',
      `Authenticated GitHub account @${userProfile.login}`,
      userProfile.name
    );

    // Attempt to auto-select user's most recently updated repository or EJII repository if available
    let initialRepoSync = {};
    try {
      const reposRes = await fetchGitHubApi('/user/repos?sort=updated&per_page=15', accessToken);
      if (reposRes.statusCode === 200 && Array.isArray(reposRes.data) && reposRes.data.length > 0) {
        const preferred = reposRes.data.find((r) =>
          String(r.name || '').toLowerCase().includes('infrastructure-intelligence')
        ) || reposRes.data[0];
        if (preferred && preferred.owner && preferred.owner.login && preferred.name) {
          initialRepoSync = await syncRepositoryTelemetry(
            accessToken,
            preferred.owner.login,
            preferred.name,
            events
          );
        }
      }
    } catch (_) {}

    saveStoredState({
      connectionState: 'CONNECTED',
      accessToken,
      user: userProfile,
      rateLimit: userRes.rateLimit,
      syncEvents: events,
      lastError: null,
      lastSyncedAt: new Date().toISOString(),
      ...initialRepoSync
    });

    return res.status(200).send(renderOAuthPopupHtml(true, `Connected as @${userProfile.login}`));
  } catch (err) {
    saveStoredState({
      connectionState: 'ERROR',
      lastError: err.message
    });
    return res.status(500).send(renderOAuthPopupHtml(false, err.message));
  }
}

function renderOAuthPopupHtml(success, message) {
  const safeMsg = String(message || '').replace(/[<>&"']/g, (c) => ({
    '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;'
  }[c]));
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>EJII — GitHub Authentication</title>
  <style>
    body {
      margin: 0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: #F6F5F1;
      color: #1F2421;
      font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    .card {
      background: #FFFFFF;
      border: 1px solid #E6E3DB;
      border-radius: 14px;
      padding: 28px 32px;
      max-width: 400px;
      text-align: center;
      box-shadow: 0 8px 24px rgba(24, 28, 25, 0.06);
    }
    .title {
      font-size: 17px;
      font-weight: 600;
      margin: 0 0 8px;
    }
    .desc {
      font-size: 14px;
      color: #666B66;
      margin: 0;
      line-height: 1.5;
    }
  </style>
</head>
<body>
  <div class="card">
    <h1 class="title">${success ? 'GitHub Account Connected' : 'GitHub Connection Notice'}</h1>
    <p class="desc">${safeMsg}</p>
  </div>
  <script>
    (function() {
      try {
        if (window.opener) {
          window.opener.postMessage({
            type: ${success ? "'OAUTH_AUTH_SUCCESS'" : "'OAUTH_AUTH_ERROR'"},
            provider: 'github',
            message: ${JSON.stringify(String(message || ''))}
          }, '*');
          setTimeout(function() { window.close(); }, 450);
        }
      } catch (e) {}
    })();
  </script>
</body>
</html>`;
}

router.get('/callback', handleGitHubOAuthCallback);

/**
 * GET /api/github/repos
 * Lists accessible repositories for the authenticated GitHub user.
 */
router.get('/repos', async (req, res) => {
  const state = getStoredState();
  if (state.connectionState !== 'CONNECTED' || !state.accessToken) {
    return res.status(401).json({
      ok: false,
      error: 'GitHub account is not connected.'
    });
  }

  try {
    const reposRes = await fetchGitHubApi('/user/repos?sort=updated&per_page=30', state.accessToken);
    if (reposRes.statusCode === 401) {
      saveStoredState({
        connectionState: 'UNAUTHORIZED',
        lastError: 'GitHub token expired or was revoked.'
      });
      return res.status(401).json({ ok: false, error: 'GitHub token expired or was revoked.' });
    }
    if (reposRes.statusCode === 403 && reposRes.rateLimit && reposRes.rateLimit.remaining === 0) {
      saveStoredState({
        connectionState: 'RATE_LIMITED',
        rateLimit: reposRes.rateLimit,
        lastError: 'GitHub API rate limit exceeded.'
      });
      return res.status(429).json({ ok: false, error: 'GitHub API rate limit exceeded.', rateLimit: reposRes.rateLimit });
    }
    const list = Array.isArray(reposRes.data) ? reposRes.data.map((r) => ({
      id: r.id,
      name: r.name,
      owner: r.owner ? r.owner.login : '',
      fullName: r.full_name,
      private: Boolean(r.private),
      defaultBranch: r.default_branch || 'main',
      description: r.description || '',
      updatedAt: r.updated_at || null,
      htmlUrl: r.html_url || null
    })) : [];

    saveStoredState({ rateLimit: reposRes.rateLimit });
    return res.json({ ok: true, repos: list, rateLimit: reposRes.rateLimit });
  } catch (err) {
    return res.status(502).json({ ok: false, error: err.message });
  }
});

/**
 * POST /api/github/select-repo
 * Selects the active repository and fetches its real commits and CI runs.
 */
router.post('/select-repo', async (req, res) => {
  const state = getStoredState();
  if (state.connectionState !== 'CONNECTED' || !state.accessToken) {
    return res.status(401).json({
      ok: false,
      error: 'Connect your GitHub account before selecting a repository.'
    });
  }

  const fullName = String((req.body && req.body.fullName) || '').trim();
  const parts = fullName.split('/').filter(Boolean);
  const owner = (req.body && req.body.owner) || parts[0];
  const repo = (req.body && req.body.repo) || parts[1];

  if (!owner || !repo) {
    return res.status(400).json({
      ok: false,
      error: 'Both repository owner and name (owner/repo) are required.'
    });
  }

  try {
    const syncPatch = await syncRepositoryTelemetry(state.accessToken, owner, repo, state.syncEvents);
    saveStoredState(syncPatch);
    return res.json(buildPublicStatusPayload(req));
  } catch (err) {
    saveStoredState({ lastError: err.message });
    return res.status(502).json({ ok: false, error: err.message });
  }
});

/**
 * POST /api/github/sync
 * Manually triggers a live refresh of the connected GitHub account and selected repository.
 */
router.post('/sync', async (req, res) => {
  const state = getStoredState();
  if (state.connectionState !== 'CONNECTED' || !state.accessToken) {
    return res.status(401).json({
      ok: false,
      error: 'GitHub account is not connected.'
    });
  }

  try {
    const userRes = await fetchGitHubApi('/user', state.accessToken);
    if (userRes.statusCode === 401) {
      saveStoredState({
        connectionState: 'UNAUTHORIZED',
        lastError: 'GitHub session is no longer authorized. Please reconnect.'
      });
      return res.status(401).json(buildPublicStatusPayload(req));
    }
    if (userRes.statusCode === 403 && userRes.rateLimit && userRes.rateLimit.remaining === 0) {
      saveStoredState({
        connectionState: 'RATE_LIMITED',
        rateLimit: userRes.rateLimit,
        lastError: 'GitHub API rate limit reached.'
      });
      return res.status(429).json(buildPublicStatusPayload(req));
    }

    let syncPatch = {
      rateLimit: userRes.rateLimit,
      lastSyncedAt: new Date().toISOString(),
      lastError: null
    };

    if (state.selectedRepo && state.selectedRepo.owner && state.selectedRepo.name) {
      syncPatch = await syncRepositoryTelemetry(
        state.accessToken,
        state.selectedRepo.owner,
        state.selectedRepo.name,
        state.syncEvents
      );
    }

    saveStoredState(syncPatch);
    return res.json(buildPublicStatusPayload(req));
  } catch (err) {
    saveStoredState({ lastError: err.message });
    return res.status(502).json({ ok: false, error: err.message });
  }
});

/**
 * POST /api/github/disconnect
 * Clears the stored server-side GitHub token and resets state to DISCONNECTED.
 */
router.post('/disconnect', (req, res) => {
  const current = getStoredState();
  const events = appendSyncEvent(
    current.syncEvents,
    'ACCOUNT_DISCONNECTED',
    current.user && current.user.login
      ? `Disconnected GitHub account @${current.user.login}`
      : 'Disconnected GitHub integration'
  );
  saveStoredState({
    connectionState: 'DISCONNECTED',
    accessToken: null,
    user: null,
    selectedRepo: null,
    latestCommits: [],
    latestWorkflows: [],
    lastError: null,
    lastSyncedAt: null,
    syncEvents: events
  });
  return res.json(buildPublicStatusPayload(req));
});

router.githubRoutes = router;
router.handleGitHubOAuthCallback = handleGitHubOAuthCallback;

module.exports = router;
module.exports.githubRoutes = router;
module.exports.handleGitHubOAuthCallback = handleGitHubOAuthCallback;
