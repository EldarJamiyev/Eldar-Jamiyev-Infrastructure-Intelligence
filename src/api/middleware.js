/**
 * EJII Capability & Role Middleware
 * Enforces cryptographic session verification, explicit role checking, and granular capability-based access control.
 */

'use strict';

const { verifyToken, hasPermission } = require('../core/security');
const { db } = require('../db/database');

function parseCookies(header) {
  const list = {};
  if (!header) return list;
  header.split(';').forEach(cookie => {
    const parts = cookie.split('=');
    if (parts.length >= 2) {
      list[parts[0].trim()] = decodeURIComponent(parts.slice(1).join('=').trim());
    }
  });
  return list;
}

/**
 * Middleware to extract and verify Bearer JWT token or session cookie
 */
function authenticate(req, res, next) {
  let token = null;
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.slice(7).trim();
  } else if (req.query && req.query.token) {
    token = String(req.query.token).trim();
  } else if (req.cookies && req.cookies.eji_session) {
    token = req.cookies.eji_session;
  } else if (req.headers.cookie) {
    const cookies = parseCookies(req.headers.cookie);
    if (cookies.eji_session) {
      token = cookies.eji_session;
    }
  }

  if (!token) {
    return res.status(401).json({ error: 'Authentication required. Bearer token or session cookie missing.' });
  }

  const decoded = verifyToken(token);

  if (!decoded) {
    return res.status(401).json({ error: 'Invalid or expired session token.' });
  }

  // Verify user is active in database
  let user = null;
  if (decoded.id) {
    user = db.prepare('SELECT id, username, full_name, role, is_active FROM users WHERE id = ?').get(decoded.id);
  } else if (decoded.username) {
    user = db.prepare('SELECT id, username, full_name, role, is_active FROM users WHERE username = ?').get(decoded.username);
  }

  if (user) {
    if (user.is_active !== 1) {
      return res.status(403).json({ error: 'User account is disabled.' });
    }
    req.user = {
      id: user.id,
      username: user.username,
      full_name: user.full_name,
      role: (decoded.role || user.role || 'READONLY').toUpperCase()
    };
  } else {
    // Cryptographically verified token for system or service accounts
    req.user = {
      id: decoded.id || 'SVC-' + (decoded.username || 'user'),
      username: decoded.username || 'authenticated_user',
      full_name: decoded.fullName || decoded.username || 'Authenticated User',
      role: (decoded.role || 'READONLY').toUpperCase()
    };
  }
  next();
}

// Monotonic Role Hierarchy (preserved for reference)
const ROLE_HIERARCHY = {
  ADMIN: 4,
  NETWORK_ADMIN: 4,
  SYSADMIN: 4,
  ANALYST: 3,
  OPERATOR: 2,
  NOC_OPERATOR: 2,
  READONLY: 1
};

/**
 * Strict role checking middleware:
 * Enforces EXPLICIT role membership without unintended numeric cross-role escalation.
 * If requireRole('ADMIN') is requested, only ADMIN is authorized.
 */
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required. Verified session missing.' });
    }

    const userRole = (req.user.role || 'READONLY').toUpperCase();
    const normalizedAllowed = allowedRoles.map(r => String(r).toUpperCase());

    // Explicit role match OR ADMIN superuser inheritance across operational routes (F-01 resolved)
    const isAuthorized = normalizedAllowed.includes(userRole) || (userRole === 'ADMIN');

    if (!isAuthorized) {
      return res.status(403).json({
        error: `Access denied: Role '${req.user.role}' lacks sufficient privileges. Required role: [${allowedRoles.join(', ')}].`
      });
    }

    next();
  };
}

/**
 * Granular capability-based permission middleware (F-03)
 */
function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required. Verified session missing.' });
    }
    const userRole = (req.user.role || 'READONLY').toUpperCase();
    if (!hasPermission(userRole, permission)) {
      return res.status(403).json({
        error: `Access denied: Role '${userRole}' lacks required capability '${permission}'.`
      });
    }
    next();
  };
}

module.exports = {
  authenticate,
  requireRole,
  requirePermission,
  ROLE_HIERARCHY
};
