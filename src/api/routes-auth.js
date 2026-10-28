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
const { generateSecret, verifyTOTP, getOtpAuthUrl } = require('../core/totp');

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
  const { username, password } = req.body || {};

  if (!username || typeof password !== 'string' || !password) {
    recordLoginAttempt(req, false);
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  const { HOST, KNOWN_DEFAULT_PASSWORDS, isLocalLoopbackHost } = require('../config');
  const clientIp = req.ip || req.socket?.remoteAddress || '';
  const isClientLoopback = isLocalLoopbackHost(clientIp);
  const isNetworkExposed = (!isLocalLoopbackHost(HOST) && !isClientLoopback) && process.env.NODE_ENV !== 'test';
  if ((process.env.NODE_ENV === 'production' || isNetworkExposed) && KNOWN_DEFAULT_PASSWORDS.includes(password)) {
    recordLoginAttempt(req, false);
    return res.status(403).json({
      error: 'Default credentials are prohibited in production or on network-exposed interfaces. Please rotate the operator password.'
    });
  }

  // Find user in database
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.trim());

  if (!user) {
    recordLoginAttempt(req, false);
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  // Cryptographically verify password against stored PBKDF2 hash & salt
  if (!verifyPassword(password, user.password_hash, user.salt)) {
    recordLoginAttempt(req, false);
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  if (user.is_active !== 1) {
    recordLoginAttempt(req, false);
    return res.status(403).json({ error: 'This user account is currently deactivated.' });
  }

  recordLoginAttempt(req, true);

  const token = createToken({
    id: user.id,
    username: user.username,
    role: user.role,
    fullName: user.full_name
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
 * POST /api/auth/quick-noc
 * 1-click single-operator unprivileged NOC workstation sign-in (Local Loopback / Evaluation Only)
 */
router.post('/quick-noc', (req, res) => {
  const { IS_EVALUATION_MODE, HOST, isLocalLoopbackHost } = require('../config');
  const clientIp = req.ip || req.connection?.remoteAddress || '';
  const isLoopbackClient = isLocalLoopbackHost(clientIp);
  const isLoopbackHost = isLocalLoopbackHost(HOST);

  if (req.body && (req.body.role || req.body.username)) {
    return res.status(400).json({
      error: 'ROLE_ELEVATION_PROHIBITED: Client cannot specify role or username in quick-noc.'
    });
  }

  if (!IS_EVALUATION_MODE || process.env.NODE_ENV === 'production' || !isLoopbackHost || !isLoopbackClient) {
    return res.status(403).json({
      error: 'Quick NOC login is strictly forbidden on network-exposed interfaces (0.0.0.0) or remote connections. Authentication requires valid operator credentials.'
    });
  }

  // Quick-NOC is strictly for standard local loopback NOC workstation evaluation (OPERATOR or ANALYST, never ADMIN/SYSADMIN)
  // Unconditionally mandate non-administrative role on every lookup branch
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
    fullName: user.full_name
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
    evaluationMode: IS_EVALUATION_MODE,
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
 * Check MFA setup status for the authenticated user
 */
router.get('/mfa/status', authenticate, (req, res) => {
  res.json({
    mfaEnabled: false,
    method: 'TOTP_RFC6238',
    user: req.user.username
  });
});

/**
 * GET /api/auth/totp/setup
 * Generate TOTP secret and provisioning URI for the user
 */
router.get('/totp/setup', authenticate, (req, res) => {
  const secret = generateSecret(20);
  const otpauthUrl = getOtpAuthUrl('EJII', req.user.username, secret);
  res.json({
    success: true,
    secret,
    otpauthUrl
  });
});

/**
 * POST /api/auth/mfa/verify-totp
 * Verify an RFC 6238 TOTP token
 */
router.post('/mfa/verify-totp', authenticate, (req, res) => {
  const { secret, token } = req.body || {};
  if (!secret || !token) {
    return res.status(400).json({ error: 'Secret and token are required.' });
  }
  const valid = verifyTOTP(secret, token);
  res.json({
    success: valid,
    verified: valid,
    timestamp: new Date().toISOString()
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

module.exports = router;
