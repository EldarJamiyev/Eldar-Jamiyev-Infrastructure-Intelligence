/**
 * EJII Lightweight NOC Middleware
 * Streamlined, unprivileged single-operator authentication with zero enterprise overhead.
 */

const { verifyToken } = require('../core/security');
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
  const user = db.prepare('SELECT id, username, full_name, role, is_active FROM users WHERE id = ?').get(decoded.id);

  if (!user || user.is_active !== 1) {
    return res.status(403).json({ error: 'User account is disabled or does not exist.' });
  }

  req.user = user;
  next();
}

/**
 * Middleware for NOC operations (allows all authenticated unprivileged NOC operators)
 */
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthenticated.' });
    }
    next();
  };
}

function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthenticated.' });
    }
    next();
  };
}

module.exports = {
  authenticate,
  requireRole,
  requirePermission
};
