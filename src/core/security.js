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
  SYSADMIN: 'SYSADMIN',
  NETWORK_ADMIN: 'NETWORK_ADMIN',
  ANALYST: 'ANALYST',
  OPERATOR: 'OPERATOR',
  NOC_OPERATOR: 'NOC_OPERATOR',
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
  const tokenPayload = {
    ...payload,
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

function generateToken(user, expiresIn = 86400) {
  const role = (user.role || 'NOC_OPERATOR').toUpperCase();
  return createToken({ id: user.id, username: user.username, role }, expiresIn);
}

function revokeToken(token, userId, reason) {
  revokedTokens.add(token);
  return true;
}

function isTokenRevoked(token) {
  return revokedTokens.has(token);
}

/**
 * Strict capability-based permission checker
 */
function hasPermission(role, permission) {
  if (!role || !permission) return false;
  const normalizedRole = String(role).toUpperCase();
  const permissions = ROLE_CAPABILITIES[normalizedRole] || [];
  return permissions.includes(permission);
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
  isTokenRevoked,
  hasPermission,
  getRoleCapabilities
};
