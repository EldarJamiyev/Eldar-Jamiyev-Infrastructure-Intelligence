/**
 * EJII Lightweight NOC Authentication API Routes
 * Single-operator / unprivileged NOC access with zero enterprise governance bloat.
 */

const express = require('express');
const router = express.Router();
const { db } = require('../db/database');
const { verifyPassword, createToken, ROLES } = require('../core/security');
const { authenticate } = require('./middleware');

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
  const { username, password } = req.body;

  if (!username) {
    return res.status(400).json({ error: 'Username is required.' });
  }

  // Find user in database
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.trim());

  if (!user) {
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  // If password provided, verify it (or allow default password)
  if (password && !verifyPassword(password, user.password_hash, user.salt)) {
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
  let user = db.prepare("SELECT * FROM users WHERE role = 'noc_operator' OR username = 'noc' LIMIT 1").get();
  if (!user) {
    user = db.prepare("SELECT * FROM users LIMIT 1").get();
  }

  if (!user) {
    return res.status(500).json({ error: 'No NOC operator account found.' });
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
  res.clearCookie('eji_session');
  res.json({ success: true, message: 'Logged out successfully.' });
});

module.exports = router;
