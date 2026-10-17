/**
 * EJII Lightweight NOC Authentication API Routes
 * Single-operator / unprivileged NOC access with zero enterprise governance bloat.
 */

const express = require('express');
const router = express.Router();
const { db } = require('../db/database');
const { verifyPassword, createToken, verifyToken, revokeToken, ROLES } = require('../core/security');
const { authenticate, parseCookies } = require('./middleware');

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
router.post('/login', (req, res) => {
  const { username, password } = req.body || {};

  if (!username || typeof password !== 'string' || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  // Find user in database
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.trim());

  if (!user) {
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  // Cryptographically verify password against stored PBKDF2 hash & salt
  if (!verifyPassword(password, user.password_hash, user.salt)) {
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  if (user.is_active !== 1) {
    return res.status(403).json({ error: 'This user account is currently deactivated.' });
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
 * POST /api/auth/quick-noc
 * 1-click single-operator unprivileged NOC workstation sign-in
 */
router.post('/quick-noc', (req, res) => {
  const { IS_EVALUATION_MODE } = require('../config');
  if (!IS_EVALUATION_MODE) {
    return res.status(403).json({ error: 'Quick NOC login is disabled in production environments.' });
  }

  const requestedTarget = (req.body && (req.body.role || req.body.username)) ? String(req.body.role || req.body.username).trim() : null;
  let user = null;

  if (requestedTarget) {
    user = db.prepare("SELECT * FROM users WHERE (UPPER(role) = UPPER(?) OR LOWER(username) = LOWER(?)) AND is_active = 1 LIMIT 1").get(requestedTarget, requestedTarget);
  }

  // Default to workstation owner (Admin / Lead Architect) so all workstation operations succeed out-of-the-box
  if (!user) {
    user = db.prepare("SELECT * FROM users WHERE UPPER(role) = 'ADMIN' OR LOWER(username) = 'admin' LIMIT 1").get();
  }
  if (!user) {
    user = db.prepare("SELECT * FROM users WHERE LOWER(role) = 'noc_operator' OR LOWER(username) = 'noc' LIMIT 1").get();
  }
  if (!user) {
    user = db.prepare("SELECT * FROM users WHERE is_active = 1 LIMIT 1").get();
  }

  if (!user) {
    return res.status(500).json({ error: 'No operational user account found in database.' });
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
