/**
 * EJII Application Owner Governance & Administration API Routes
 * User management, role provisioning, cryptographic audit verification, and system health.
 */

const express = require('express');
const router = express.Router();
const fs = require('fs');
const crypto = require('crypto');
const { authenticate, requireRole } = require('./middleware');
const { ROLES, hashPassword } = require('../core/security');
const { db } = require('../db/database');
const { getAuditLogs, verifyChainIntegrity, logAction } = require('../core/audit-logger');
const { DB_PATH } = require('../config');

// Application Owner exclusive access
router.use(authenticate, requireRole(ROLES.APP_OWNER));

/**
 * GET /api/admin/users
 */
router.get('/users', (req, res) => {
  const users = db.prepare('SELECT id, username, full_name, role, is_active, created_at, last_login FROM users ORDER BY created_at ASC').all();
  res.json({ count: users.length, users });
});

/**
 * POST /api/admin/users
 */
router.post('/users', (req, res) => {
  const { username, password, fullName, role } = req.body;

  if (!username || !password || !fullName || !role) {
    return res.status(400).json({ error: 'username, password, fullName, and role are required.' });
  }

  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
  }

  const validRoles = Object.values(ROLES);
  if (!validRoles.includes(role)) {
    return res.status(400).json({ error: `Invalid role. Must be one of: [${validRoles.join(', ')}]` });
  }

  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username.trim());
  if (existing) {
    return res.status(400).json({ error: 'Username already in use.' });
  }

  const id = 'USR-' + crypto.randomBytes(4).toString('hex').toUpperCase();
  const { hash, salt } = hashPassword(password);
  const now = new Date().toISOString();

  db.prepare(`
    INSERT INTO users (id, username, password_hash, salt, full_name, role, is_active, created_at)
    VALUES (?, ?, ?, ?, ?, ?, 1, ?)
  `).run(id, username.trim(), hash, salt, fullName.trim(), role, now);

  logAction({
    userId: req.user.id,
    username: req.user.username,
    role: req.user.role,
    action: 'USER_CREATED',
    resource: id,
    details: `Created new user [${username}] with role [${role}]`
  });

  res.json({ success: true, userId: id });
});

/**
 * PUT /api/admin/users/:id/status
 */
router.put('/users/:id/status', (req, res) => {
  const { isActive, newPassword } = req.body;
  const userId = req.params.id;

  const targetUser = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!targetUser) {
    return res.status(404).json({ error: 'User not found.' });
  }

  // Prevent disabling the only app_owner if it's oneself
  if (targetUser.role === ROLES.APP_OWNER && targetUser.id === req.user.id && isActive === 0) {
    return res.status(400).json({ error: 'Cannot deactivate your own Application Owner account.' });
  }

  if (isActive !== undefined) {
    const activeVal = isActive === 1 || isActive === true ? 1 : (isActive === 0 || isActive === false ? 0 : null);
    if (activeVal === null) {
      return res.status(400).json({ error: 'isActive must be 0 (inactive) or 1 (active).' });
    }
    db.prepare('UPDATE users SET is_active = ? WHERE id = ?').run(activeVal, userId);
  }

  if (newPassword) {
    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters long.' });
    }
    const { hash, salt } = hashPassword(newPassword);
    db.prepare('UPDATE users SET password_hash = ?, salt = ? WHERE id = ?').run(hash, salt, userId);
  }

  logAction({
    userId: req.user.id,
    username: req.user.username,
    role: req.user.role,
    action: 'USER_UPDATED',
    resource: userId,
    details: `Updated user [${targetUser.username}]. Active: ${isActive !== undefined ? isActive : targetUser.is_active}`
  });

  res.json({ success: true, message: 'User updated successfully.' });
});

/**
 * GET /api/admin/audit-logs
 */
router.get('/audit-logs', (req, res) => {
  const limit = parseInt(req.query.limit, 10) || 50;
  const offset = parseInt(req.query.offset, 10) || 0;
  const action = req.query.action || null;

  const logs = getAuditLogs(limit, offset, action);
  const total = db.prepare('SELECT COUNT(*) as count FROM audit_logs').get().count;

  res.json({ total, count: logs.length, logs });
});

/**
 * GET /api/admin/audit-verify
 * Cryptographic validation of the sequential HMAC-SHA256 hash chain
 */
router.get('/audit-verify', (req, res) => {
  const result = verifyChainIntegrity();

  logAction({
    userId: req.user.id,
    username: req.user.username,
    role: req.user.role,
    action: 'AUDIT_CHAIN_VERIFIED',
    resource: 'AUDIT_TRAIL',
    details: `Integrity check: ${result.valid ? 'VALID' : 'TAMPERED'}. Records checked: ${result.totalRecords}`
  });

  res.json(result);
});

/**
 * GET /api/admin/system-health
 */
router.get('/system-health', (req, res) => {
  const mem = process.memoryUsage();
  let dbSizeBytes = 0;
  try {
    const stat = fs.statSync(DB_PATH);
    dbSizeBytes = stat.size;
  } catch (e) {
    console.warn('[DB Stat Warning]:', e.message);
  }

  const nodeCount = db.prepare('SELECT COUNT(*) as c FROM nodes').get().c;
  const incidentCount = db.prepare("SELECT COUNT(*) as c FROM incidents WHERE status = 'open'").get().c;
  const auditCount = db.prepare('SELECT COUNT(*) as c FROM audit_logs').get().c;

  res.json({
    engine: 'EJII Enterprise Core Engine v1.0',
    uptimeSeconds: Math.floor(process.uptime()),
    nodeVersion: process.version,
    processId: process.pid,
    memory: {
      rssMb: parseFloat((mem.rss / 1024 / 1024).toFixed(2)),
      heapUsedMb: parseFloat((mem.heapUsed / 1024 / 1024).toFixed(2)),
      heapTotalMb: parseFloat((mem.heapTotal / 1024 / 1024).toFixed(2))
    },
    database: {
      path: DB_PATH,
      sizeFormatted: `${(dbSizeBytes / 1024).toFixed(1)} KB`,
      totalNodes: nodeCount,
      activeIncidents: incidentCount,
      totalAuditRecords: auditCount
    }
  });
});

module.exports = router;
