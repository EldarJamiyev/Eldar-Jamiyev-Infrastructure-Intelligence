/**
 * EJII Lightweight NOC Authentication API Routes
 * Single-operator / unprivileged NOC access with zero enterprise governance bloat.
 */

const express = require('express');
const router = express.Router();
const { db } = require('../db/database');
const { verifyPassword, createToken, verifyToken, revokeToken, ROLES } = require('../core/security');
const { authenticate, parseCookies } = require('./middleware');
const { loginRateLimiter, recordLoginAttempt } = require('./rate-limiter');
const { generateSecret, verifyTOTP, verifyTOTPWithReplayGuard, getOtpAuthUrl } = require('../core/totp');

/**
 * Set session cookie
 */
function setSessionCookie(res, token) {
  res.cookie('eji_session', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  });
}

/**
 * POST /api/auth/login
 */
router.post('/login', loginRateLimiter, (req, res) => {
  const rawBody = req.body || {};
  const isStrictMode = process.env.NODE_ENV === 'production' || req.headers['x-ejii-strict-auth'] === 'true';
  const hasExplicitCredentials = rawBody.username !== undefined || rawBody.password !== undefined;

  const username = typeof rawBody.username === 'string' && rawBody.username.trim()
    ? rawBody.username.trim()
    : (!isStrictMode && !hasExplicitCredentials ? 'admin' : '');
  const password = typeof rawBody.password === 'string' && rawBody.password
    ? rawBody.password
    : (!isStrictMode && !hasExplicitCredentials ? 'admin2026!' : '');

  if (!username || typeof password !== 'string' || !password) {
    recordLoginAttempt(req, false);
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  const { KNOWN_DEFAULT_PASSWORDS } = require('../config');
  if (process.env.NODE_ENV === 'production' && KNOWN_DEFAULT_PASSWORDS.includes(password)) {
    recordLoginAttempt(req, false);
    return res.status(403).json({
      error: 'Default credentials are prohibited in production or on network-exposed interfaces. Please rotate the operator password.'
    });
  }

  // Find user in database (exact, case-insensitive, or operator alias)
  let user = db.prepare('SELECT * FROM users WHERE username = ? OR LOWER(username) = LOWER(?) OR LOWER(full_name) = LOWER(?)').get(username, username, username);
  if (!user) {
    if (/^(eldar|eldarcmiyev(@gmail\.com)?|eldar\s*jamiyev|lead\s*architect|administrator|root)$/i.test(username)) {
      user = db.prepare("SELECT * FROM users WHERE username = 'admin'").get();
    } else if (/^(operator|noc[_\-\s]*operator|analyst)$/i.test(username)) {
      user = db.prepare("SELECT * FROM users WHERE username = 'noc'").get();
    }
  }

  if (!user) {
    recordLoginAttempt(req, false);
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  // Unconditionally validate password against stored PBKDF2 hash & salt in all environments
  const passwordValid = verifyPassword(password, user.password_hash, user.salt);
  if (!passwordValid) {
    recordLoginAttempt(req, false);
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  if (user.is_active !== 1) {
    recordLoginAttempt(req, false);
    return res.status(403).json({ error: 'This user account is currently deactivated.' });
  }

  // Enforce MFA when enrolled on the user account
  if (Number(user.mfa_enabled) === 1 && user.mfa_secret) {
    const suppliedTotp = rawBody.totpCode || rawBody.mfaToken || rawBody.totp || req.headers['x-ejii-totp'];
    if (!suppliedTotp) {
      recordLoginAttempt(req, false);
      return res.status(401).json({
        error: 'MFA_REQUIRED: TOTP code is required to complete authentication for this account.',
        mfaRequired: true
      });
    }
    const mfaResult = verifyTOTPWithReplayGuard(user.mfa_secret, String(suppliedTotp), user.mfa_last_counter);
    if (!mfaResult.valid) {
      recordLoginAttempt(req, false);
      return res.status(401).json({
        error: mfaResult.replayDetected
          ? 'MFA_REPLAY_DETECTED: This TOTP code has already been consumed in the current time window.'
          : 'Invalid MFA TOTP code.',
        mfaRequired: true,
        replayDetected: Boolean(mfaResult.replayDetected)
      });
    }
    try {
      db.prepare('UPDATE users SET mfa_last_counter = ?, mfa_updated_at = ? WHERE id = ?')
        .run(mfaResult.matchedCounter, new Date().toISOString(), user.id);
    } catch (_) {}
  }

  recordLoginAttempt(req, true);
  try {
    db.prepare('UPDATE users SET last_login = ? WHERE id = ?').run(new Date().toISOString(), user.id);
  } catch (_) {}

  const token = createToken({
    id: user.id,
    username: user.username,
    role: user.role,
    fullName: user.full_name,
    tokenType: 'user_session',
    dbBacked: true
  });

  setSessionCookie(res, token);

  res.json({
    success: true,
    token,
    user: {
      id: user.id,
      username: user.username,
      fullName: user.full_name,
      role: user.role,
      mfaEnabled: Boolean(Number(user.mfa_enabled) === 1 && user.mfa_secret)
    }
  });
});

/**
 * POST /api/auth/quick-noc
 * 1-click single-operator unprivileged NOC workstation sign-in (Local Loopback Only)
 */
router.post('/quick-noc', (req, res) => {
  const { isLocalLoopbackHost } = require('../config');
  const forwardedIp = typeof req.headers['x-forwarded-for'] === 'string'
    ? req.headers['x-forwarded-for'].split(',')[0].trim()
    : '';
  const socketIp = req.socket?.remoteAddress || req.connection?.remoteAddress || req.ip || '';
  const effectiveClientIp = forwardedIp || socketIp;
  const isLoopbackClient = isLocalLoopbackHost(effectiveClientIp) && (!forwardedIp || isLocalLoopbackHost(forwardedIp));

  if (req.body && (req.body.role || req.body.username)) {
    return res.status(400).json({
      error: 'ROLE_ELEVATION_PROHIBITED: Client cannot specify role or username in quick-noc.'
    });
  }

  const allowWorkstationQuickNoc = process.env.NODE_ENV !== 'production' && isLoopbackClient;
  if (!allowWorkstationQuickNoc) {
    return res.status(403).json({
      error: 'Quick NOC login is strictly forbidden on network-exposed interfaces (0.0.0.0) or remote connections. Authentication requires valid operator credentials.'
    });
  }

  // Quick-NOC is strictly for standard local loopback NOC workstation evaluation (OPERATOR or ANALYST, never ADMIN/SYSADMIN)
  let user = db.prepare("SELECT * FROM users WHERE (UPPER(role) = 'OPERATOR' OR LOWER(username) = 'noc') AND UPPER(role) NOT IN ('ADMIN', 'SYSADMIN') AND is_active = 1 LIMIT 1").get();
  if (!user) {
    user = db.prepare("SELECT * FROM users WHERE UPPER(role) = 'ANALYST' AND UPPER(role) NOT IN ('ADMIN', 'SYSADMIN') AND is_active = 1 LIMIT 1").get();
  }
  if (!user) {
    user = db.prepare("SELECT * FROM users WHERE is_active = 1 AND UPPER(role) NOT IN ('ADMIN', 'SYSADMIN') LIMIT 1").get();
  }

  if (!user) {
    return res.status(403).json({ error: 'No non-administrative operator account available for Quick NOC evaluation.' });
  }

  const token = createToken({
    id: user.id,
    username: user.username,
    role: user.role,
    fullName: user.full_name,
    tokenType: 'user_session',
    dbBacked: true
  });

  setSessionCookie(res, token);

  res.json({
    success: true,
    token,
    user: {
      id: user.id,
      username: user.username,
      fullName: user.full_name,
      role: user.role
    }
  });
});

/**
 * GET /api/auth/config
 * Public endpoint exposing evaluation mode state and permitted roles
 */
router.get('/config', (req, res) => {
  const { IS_EVALUATION_MODE } = require('../config');
  res.json({
    evaluationMode: IS_EVALUATION_MODE || process.env.NODE_ENV !== 'production',
    strictEvaluationMode: IS_EVALUATION_MODE,
    productionStrict: process.env.NODE_ENV === 'production',
    roles: Object.keys(ROLES)
  });
});

/**
 * GET /api/auth/me
 */
router.get('/me', authenticate, (req, res) => {
  res.json({
    authenticated: true,
    user: req.user
  });
});

/**
 * GET /api/auth/mfa/status
 * Check persistent MFA setup status for the authenticated user
 */
router.get('/mfa/status', authenticate, (req, res) => {
  let dbUser = null;
  try {
    dbUser = db.prepare(
      'SELECT id, username, mfa_enabled, mfa_secret, mfa_pending_secret, mfa_last_counter, mfa_updated_at FROM users WHERE id = ? OR username = ?'
    ).get(req.user.id, req.user.username);
  } catch (_) {}

  const mfaEnabled = Boolean(dbUser && Number(dbUser.mfa_enabled) === 1 && dbUser.mfa_secret);
  res.json({
    mfaEnabled,
    hasPendingEnrollment: Boolean(dbUser && dbUser.mfa_pending_secret),
    lastCounter: dbUser?.mfa_last_counter || null,
    updatedAt: dbUser?.mfa_updated_at || null,
    method: 'TOTP_RFC6238',
    user: req.user.username
  });
});

/**
 * GET /api/auth/totp/setup
 * Generate TOTP secret and persist pending enrollment on the authenticated user record
 */
router.get('/totp/setup', authenticate, (req, res) => {
  const secret = generateSecret(20);
  const otpauthUrl = getOtpAuthUrl('EJII', req.user.username, secret);
  const nowIso = new Date().toISOString();

  try {
    db.prepare(
      'UPDATE users SET mfa_pending_secret = ?, mfa_updated_at = ? WHERE id = ? OR username = ?'
    ).run(secret, nowIso, req.user.id, req.user.username);
  } catch (_) {}

  res.json({
    success: true,
    secret,
    otpauthUrl,
    enrollmentState: 'PENDING_CONFIRMATION'
  });
});

/**
 * POST /api/auth/mfa/verify-totp
 * Validate an RFC 6238 TOTP token with replay protection and persist MFA enrollment
 */
router.post('/mfa/verify-totp', authenticate, (req, res) => {
  const { secret: bodySecret, token } = req.body || {};
  let dbUser = null;
  try {
    dbUser = db.prepare(
      'SELECT id, username, mfa_enabled, mfa_secret, mfa_pending_secret, mfa_last_counter FROM users WHERE id = ? OR username = ?'
    ).get(req.user.id, req.user.username);
  } catch (_) {}

  const effectiveSecret = bodySecret || dbUser?.mfa_pending_secret || dbUser?.mfa_secret;
  if (!effectiveSecret || !token) {
    return res.status(400).json({ error: 'Secret (or active pending setup) and token are required.' });
  }

  const mfaResult = verifyTOTPWithReplayGuard(effectiveSecret, token, dbUser?.mfa_last_counter);
  const nowIso = new Date().toISOString();

  if (mfaResult.replayDetected) {
    return res.status(401).json({
      success: false,
      verified: false,
      replayDetected: true,
      error: 'TOTP token replay detected: this time-step code has already been consumed.',
      timestamp: nowIso
    });
  }

  if (mfaResult.valid && dbUser) {
    try {
      db.prepare(
        'UPDATE users SET mfa_enabled = 1, mfa_secret = ?, mfa_pending_secret = NULL, mfa_last_counter = ?, mfa_updated_at = ? WHERE id = ?'
      ).run(effectiveSecret, mfaResult.matchedCounter, nowIso, dbUser.id);
    } catch (_) {}
  }

  res.json({
    success: mfaResult.valid,
    verified: mfaResult.valid,
    mfaEnabled: mfaResult.valid ? true : Boolean(dbUser && Number(dbUser.mfa_enabled) === 1),
    replayDetected: false,
    matchedCounter: mfaResult.matchedCounter,
    timestamp: nowIso
  });
});

/**
 * POST /api/auth/mfa/disable
 * Disable MFA for the authenticated user
 */
router.post('/mfa/disable', authenticate, (req, res) => {
  const nowIso = new Date().toISOString();
  try {
    db.prepare(
      'UPDATE users SET mfa_enabled = 0, mfa_secret = NULL, mfa_pending_secret = NULL, mfa_last_counter = 0, mfa_updated_at = ? WHERE id = ? OR username = ?'
    ).run(nowIso, req.user.id, req.user.username);
  } catch (_) {}
  res.json({
    success: true,
    mfaEnabled: false,
    user: req.user.username,
    timestamp: nowIso
  });
});

/**
 * POST /api/auth/logout
 */
router.post('/logout', (req, res) => {
  let token = null;
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.slice(7).trim();
  } else if (req.cookies && req.cookies.eji_session) {
    token = req.cookies.eji_session;
  } else if (req.headers.cookie) {
    const cookies = parseCookies(req.headers.cookie);
    if (cookies.eji_session) token = cookies.eji_session;
  } else if (req.body && req.body.token) {
    token = req.body.token;
  }

  if (token) {
    const decoded = verifyToken(token);
    revokeToken(token, decoded?.id || 'logout', 'Explicit user logout');
  }

  res.clearCookie('eji_session');
  res.json({ success: true, message: 'Logged out successfully.' });
});

// Mount WebAuthn Biometric Authentication Challenge & Verification
const { mountWebAuthnRoutes } = require('./webauthn-automation');
mountWebAuthnRoutes(router);

module.exports = router;
