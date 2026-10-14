/**
 * EJII Authentication API Routes
 */

const express = require('express');
const router = express.Router();
const { db } = require('../db/database');
const { verifyPassword, createToken, ROLES } = require('../core/security');
const { logAction } = require('../core/audit-logger');
const { authenticate } = require('./middleware');

/**
 * POST /api/auth/login
 */
router.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.trim());

  if (!user || !verifyPassword(password, user.password_hash, user.salt)) {
    logAction({
      userId: null,
      username: username.trim(),
      role: 'anonymous',
      action: 'LOGIN_FAILED',
      resource: 'AUTH',
      details: 'Failed authentication attempt: Invalid credentials.',
      ipAddress: req.ip || '127.0.0.1'
    });
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  if (user.is_active !== 1) {
    return res.status(403).json({ error: 'This user account is currently deactivated.' });
  }

  // Update last login
  const now = new Date().toISOString();
  db.prepare('UPDATE users SET last_login = ? WHERE id = ?').run(now, user.id);

  const token = createToken({
    id: user.id,
    username: user.username,
    role: user.role
  });

  logAction({
    userId: user.id,
    username: user.username,
    role: user.role,
    action: 'LOGIN_SUCCESS',
    resource: 'AUTH',
    details: `User logged in with role: ${user.role}`,
    ipAddress: req.ip || '127.0.0.1'
  });

  res.json({
    token,
    user: {
      id: user.id,
      username: user.username,
      fullName: user.full_name,
      role: user.role,
      lastLogin: now
    }
  });
});

/**
 * GET /api/auth/me
 */
router.get('/me', authenticate, (req, res) => {
  res.json({
    user: {
      id: req.user.id,
      username: req.user.username,
      fullName: req.user.full_name,
      role: req.user.role
    }
  });
});

/**
 * POST /api/auth/logout
 */
router.post('/logout', authenticate, (req, res) => {
  logAction({
    userId: req.user.id,
    username: req.user.username,
    role: req.user.role,
    action: 'LOGOUT',
    resource: 'AUTH',
    details: 'User logged out.',
    ipAddress: req.ip || '127.0.0.1'
  });

  res.json({ success: true, message: 'Logged out successfully.' });
});

module.exports = router;
