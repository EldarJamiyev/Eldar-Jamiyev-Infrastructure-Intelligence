/**
 * EJII Security & Authentication Module
 * Cryptographic operations, password hashing, token generation, and RBAC matrix.
 */

const crypto = require('crypto');
const { JWT_SECRET } = require('../config');

// Role definitions
const ROLES = {
  HELPDESK: 'helpdesk',
  NETWORK_ADMIN: 'network_admin',
  SYSADMIN: 'sysadmin',
  APP_OWNER: 'app_owner'
};

// Permission capabilities matrix
const PERMISSIONS = {
  // Read-only diagnostics
  'diag:ping': [ROLES.HELPDESK, ROLES.NETWORK_ADMIN, ROLES.SYSADMIN, ROLES.APP_OWNER],
  'diag:traceroute': [ROLES.HELPDESK, ROLES.NETWORK_ADMIN, ROLES.SYSADMIN, ROLES.APP_OWNER],
  'diag:port_test': [ROLES.HELPDESK, ROLES.NETWORK_ADMIN, ROLES.SYSADMIN, ROLES.APP_OWNER],
  'diag:dns_test': [ROLES.HELPDESK, ROLES.NETWORK_ADMIN, ROLES.SYSADMIN, ROLES.APP_OWNER],
  'diag:http_check': [ROLES.HELPDESK, ROLES.NETWORK_ADMIN, ROLES.SYSADMIN, ROLES.APP_OWNER],
  'diag:simple_summary': [ROLES.HELPDESK, ROLES.NETWORK_ADMIN, ROLES.SYSADMIN, ROLES.APP_OWNER],

  // Network-specific permissions
  'network:snmp_poll': [ROLES.NETWORK_ADMIN, ROLES.APP_OWNER],
  'network:port_scan': [ROLES.NETWORK_ADMIN, ROLES.SYSADMIN, ROLES.APP_OWNER],
  'network:topology_edit': [ROLES.NETWORK_ADMIN, ROLES.APP_OWNER],
  'network:tls_audit': [ROLES.NETWORK_ADMIN, ROLES.SYSADMIN, ROLES.APP_OWNER],
  'network:dns_propagation': [ROLES.NETWORK_ADMIN, ROLES.APP_OWNER],

  // System-specific permissions
  'system:host_metrics': [ROLES.SYSADMIN, ROLES.NETWORK_ADMIN, ROLES.APP_OWNER],
  'system:service_list': [ROLES.SYSADMIN, ROLES.APP_OWNER],
  'system:process_list': [ROLES.SYSADMIN, ROLES.APP_OWNER],
  'system:event_log_view': [ROLES.SYSADMIN, ROLES.APP_OWNER],
  'system:automation_request': [ROLES.SYSADMIN, ROLES.NETWORK_ADMIN, ROLES.APP_OWNER],

  // Application Owner / Administration permissions
  'admin:user_manage': [ROLES.APP_OWNER],
  'admin:audit_verify': [ROLES.APP_OWNER],
  'admin:approval_action': [ROLES.APP_OWNER],
  'admin:settings_edit': [ROLES.APP_OWNER],
  'admin:system_health': [ROLES.APP_OWNER, ROLES.SYSADMIN]
};

/**
 * Hash a plain password using PBKDF2 SHA-512 with a salt
 */
function hashPassword(password, salt = null) {
  const generatedSalt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, generatedSalt, 100000, 64, 'sha512').toString('hex');
  return {
    hash,
    salt: generatedSalt
  };
}

/**
 * Verify a plain password against stored hash and salt
 */
function verifyPassword(password, storedHash, salt) {
  const { hash } = hashPassword(password, salt);
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(storedHash, 'hex'));
}

const { db } = require('../db/database');

/**
 * Hash a session token using SHA-256 for persistent revocation tracking
 */
function hashToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

/**
 * Revoke an active session token
 */
function revokeToken(token, userId = 'unknown') {
  if (!token) return false;
  const tokenHash = hashToken(token);
  const decoded = verifyToken(token, false);
  const expiresAt = decoded && decoded.exp ? new Date(decoded.exp * 1000).toISOString() : new Date(Date.now() + 86400000).toISOString();
  const user = decoded && decoded.id ? decoded.id : userId;
  try {
    db.prepare('INSERT OR REPLACE INTO revoked_tokens (token_hash, user_id, revoked_at, expires_at) VALUES (?, ?, ?, ?)').run(
      tokenHash,
      user,
      new Date().toISOString(),
      expiresAt
    );
    return true;
  } catch (err) {
    return false;
  }
}

/**
 * Check if a token has been explicitly revoked
 */
function isTokenRevoked(token) {
  if (!token) return true;
  const tokenHash = hashToken(token);
  try {
    const row = db.prepare('SELECT token_hash FROM revoked_tokens WHERE token_hash = ?').get(tokenHash);
    if (row) return true;

    // Check if user has an active bulk revocation record
    const decoded = verifyToken(token, false);
    if (decoded && decoded.id) {
      const userRevoked = db.prepare('SELECT token_hash FROM revoked_tokens WHERE user_id = ? AND token_hash LIKE ?').get(decoded.id, 'USER_ALL_%');
      if (userRevoked) return true;
    }
    return false;
  } catch (e) {
    return false;
  }
}

/**
 * Revoke all active session tokens for a given user ID
 */
function revokeAllUserTokens(userId) {
  if (!userId) return false;
  try {
    db.prepare('INSERT OR REPLACE INTO revoked_tokens (token_hash, user_id, revoked_at, expires_at) VALUES (?, ?, ?, ?)').run(
      `USER_ALL_${userId}_${Date.now()}`,
      userId,
      new Date().toISOString(),
      new Date(Date.now() + 86400000).toISOString()
    );
    return true;
  } catch (e) {
    return false;
  }
}

/**
 * Create a signed lightweight token for session auth
 */
function createToken(payload, expiresInHours = 24) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const exp = now + (expiresInHours * 3600);
  const jti = crypto.randomBytes(8).toString('hex');
  const data = Buffer.from(JSON.stringify({ ...payload, exp, iat: now, jti })).toString('base64url');
  const signature = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${data}`).digest('base64url');
  return `${header}.${data}.${signature}`;
}

/**
 * Verify and decode token with revocation check
 */
function verifyToken(token, checkRevocation = true) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [header, data, signature] = parts;
  const expectedSig = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${data}`).digest('base64url');
  
  try {
    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSig))) {
      return null;
    }
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      return null; // Expired
    }
    if (checkRevocation && isTokenRevoked(token)) {
      return null; // Revoked
    }
    return payload;
  } catch (err) {
    return null;
  }
}

/**
 * Check if a role has a given permission
 */
function hasPermission(role, permission) {
  const allowedRoles = PERMISSIONS[permission];
  if (!allowedRoles) return false;
  return allowedRoles.includes(role);
}

module.exports = {
  ROLES,
  PERMISSIONS,
  hashPassword,
  verifyPassword,
  createToken,
  generateToken: createToken,
  verifyToken,
  revokeToken,
  isTokenRevoked,
  revokeAllUserTokens,
  hasPermission
};
