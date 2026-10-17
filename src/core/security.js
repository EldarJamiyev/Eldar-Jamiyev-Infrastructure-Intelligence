/**
 * EJII Security & Capability-Based Authorization Module
 * Cryptographically verified token generation, PBKDF2 hashing, and granular capability-based RBAC.
 */

'use strict';

const crypto = require('crypto');
const { JWT_SECRET } = require('../config');

// Explicit Distinct NOC Roles
const ROLES = {
  ADMIN: 'ADMIN',
  APP_OWNER: 'APP_OWNER',
  SYSADMIN: 'SYSADMIN',
  NETWORK_ADMIN: 'NETWORK_ADMIN',
  ANALYST: 'ANALYST',
  OPERATOR: 'OPERATOR',
  NOC_OPERATOR: 'NOC_OPERATOR',
  HELPDESK: 'HELPDESK',
  READONLY: 'READONLY'
};

// Granular Capability Mapping per Role
const ROLE_CAPABILITIES = {
  ADMIN: [
    'system.config.manage',
    'users.roles.manage',
    'host.remediation.execute',
    'host.remediation.preview',
    'network.capture.execute',
    'network.diagnostics.execute',
    'telemetry.read'
  ],
  APP_OWNER: [
    'system.config.manage',
    'users.roles.manage',
    'host.remediation.execute',
    'host.remediation.preview',
    'network.capture.execute',
    'network.diagnostics.execute',
    'telemetry.read'
  ],
  SYSADMIN: [
    'host.remediation.execute',
    'host.remediation.preview',
    'network.diagnostics.execute',
    'telemetry.read'
  ],
  NETWORK_ADMIN: [
    'network.capture.execute',
    'network.diagnostics.execute',
    'host.remediation.preview',
    'telemetry.read'
  ],
  ANALYST: [
    'network.diagnostics.execute',
    'host.remediation.preview',
    'telemetry.read'
  ],
  OPERATOR: [
    'network.diagnostics.execute',
    'host.remediation.preview',
    'telemetry.read'
  ],
  NOC_OPERATOR: [
    'network.diagnostics.execute',
    'host.remediation.preview',
    'telemetry.read'
  ],
  HELPDESK: [
    'network.diagnostics.execute',
    'host.remediation.preview',
    'telemetry.read'
  ],
  READONLY: [
    'telemetry.read'
  ]
};

/**
 * Hash a plain password using PBKDF2 SHA-512 with a salt
 */
function hashPassword(password, salt = null) {
  const generatedSalt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, generatedSalt, 10000, 64, 'sha512').toString('hex');
  return {
    hash,
    salt: generatedSalt
  };
}

/**
 * Verify a plain password against stored hash and salt
 */
function verifyPassword(plainPassword, storedHash, salt) {
  const { hash } = hashPassword(plainPassword, salt);
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(storedHash, 'hex'));
}

/**
 * Generate a signed JWT-like session token
 */
function createToken(payload, expiresInSeconds = 86400) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const jti = payload.jti || (crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex'));
  const tokenPayload = {
    ...payload,
    jti,
    iat: now,
    exp: now + expiresInSeconds
  };
  const body = Buffer.from(JSON.stringify(tokenPayload)).toString('base64url');
  const signature = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${signature}`;
}

/**
 * Verify token validity and signature
 */
function verifyToken(token) {
  if (!token || typeof token !== 'string') return null;
  if (isTokenRevoked(token)) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [header, body, signature] = parts;
  const expectedSig = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');

  if (Buffer.from(signature).length !== Buffer.from(expectedSig).length ||
      !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSig))) {
    return null;
  }

  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      return null;
    }
    return payload;
  } catch (err) {
    return null;
  }
}

const revokedTokens = new Set();
const revokedUsers = new Set();

function generateToken(user, expiresIn = 86400) {
  const role = (user.role || 'NOC_OPERATOR').toUpperCase();
  return createToken({ id: user.id, username: user.username, role }, expiresIn);
}

function revokeToken(token, userId = null, reason = 'User logout') {
  if (!token || typeof token !== 'string') return false;
  revokedTokens.add(token);
  try {
    const { db } = require('../db/database');
    db.prepare(`
      INSERT OR REPLACE INTO revoked_tokens (token, user_id, reason, revoked_at)
      VALUES (?, ?, ?, ?)
    `).run(token, userId || null, reason, new Date().toISOString());
  } catch (e) {}
  return true;
}

function revokeAllUserTokens(userId, reason = 'Bulk user revocation') {
  if (!userId) return false;
  revokedUsers.add(userId);
  try {
    const { db } = require('../db/database');
    db.prepare(`
      INSERT OR REPLACE INTO revoked_tokens (token, user_id, reason, revoked_at)
      VALUES (?, ?, ?, ?)
    `).run(`USER_BULK_${userId}_${Date.now()}`, userId, reason, new Date().toISOString());
  } catch (e) {}
  return true;
}

function clearRevokedUser(userId) {
  if (userId) revokedUsers.delete(userId);
  return true;
}

function isTokenRevoked(token) {
  if (!token || typeof token !== 'string') return false;
  if (revokedTokens.has(token)) return true;

  // Check if token payload has userId in revokedUsers
  try {
    const parts = token.split('.');
    if (parts.length === 3) {
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
      if (payload.id && revokedUsers.has(payload.id)) return true;
    }
  } catch (e) {}

  // Check persistent SQLite database
  try {
    const { db } = require('../db/database');
    const row = db.prepare('SELECT 1 FROM revoked_tokens WHERE token = ?').get(token);
    if (row) return true;
  } catch (e) {}

  return false;
}

/**
 * Strict capability-based permission checker
 */
function hasPermission(role, permission) {
  if (!role || !permission) return false;
  const normalizedRole = String(role).toUpperCase();
  const permissions = ROLE_CAPABILITIES[normalizedRole] || [];
  
  if (permissions.includes(permission)) return true;

  // Map legacy diag:* scoped permissions to network.diagnostics.execute
  if (permission.startsWith('diag:') && permissions.includes('network.diagnostics.execute')) {
    return true;
  }

  // Map legacy network:* scoped permissions
  if (permission.startsWith('network:') && (permissions.includes('network.capture.execute') || permissions.includes('network.diagnostics.execute'))) {
    return true;
  }

  // Map legacy system:* scoped permissions
  if (permission.startsWith('system:') && (permissions.includes('host.remediation.execute') || permissions.includes('host.remediation.preview'))) {
    return true;
  }

  // Map legacy admin:* scoped permissions
  if (permission.startsWith('admin:') && (permissions.includes('system.config.manage') || permissions.includes('users.roles.manage'))) {
    return true;
  }

  return false;
}

/**
 * Get all capabilities granted to a specific role
 */
function getRoleCapabilities(role) {
  const normalizedRole = String(role || '').toUpperCase();
  return ROLE_CAPABILITIES[normalizedRole] ? [...ROLE_CAPABILITIES[normalizedRole]] : [];
}

module.exports = {
  ROLES,
  ROLE_CAPABILITIES,
  hashPassword,
  verifyPassword,
  createToken,
  generateToken,
  verifyToken,
  revokeToken,
  revokeAllUserTokens,
  clearRevokedUser,
  isTokenRevoked,
  hasPermission,
  getRoleCapabilities
};
