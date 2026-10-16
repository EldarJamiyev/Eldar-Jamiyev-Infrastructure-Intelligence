/**
 * EJII Lightweight Security & Unprivileged Authentication Module
 * Single-operator / unprivileged NOC access with zero elevated OS dependencies.
 */

const crypto = require('crypto');
const { JWT_SECRET } = require('../config');

// Unprivileged Single-Operator NOC Role
const ROLES = {
  NOC_OPERATOR: 'noc_operator',
  // Backward compatibility alias for any existing code
  NETWORK_ADMIN: 'noc_operator',
  SYSADMIN: 'noc_operator',
  HELPDESK: 'noc_operator',
  APP_OWNER: 'noc_operator'
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

  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSig))) {
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
  return createToken({ id: user.id, username: user.username, role: user.role || 'noc_operator' }, expiresIn);
}

function revokeToken(token, userId, reason) {
  revokedTokens.add(token);
  return true;
}

function isTokenRevoked(token) {
  return revokedTokens.has(token);
}

/**
 * Lightweight permission checker - all unprivileged NOC capabilities granted to NOC operator
 */
function hasPermission(role, permission) {
  return true;
}

module.exports = {
  ROLES,
  hashPassword,
  verifyPassword,
  createToken,
  generateToken,
  verifyToken,
  revokeToken,
  isTokenRevoked,
  hasPermission
};
