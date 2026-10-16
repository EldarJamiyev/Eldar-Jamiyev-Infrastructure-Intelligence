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
 * Middleware to enforce strict RBAC role hierarchy
 */
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required. Verified session missing.' });
    }

    const userRole = (req.user.role || 'READONLY').toUpperCase();
    const userLevel = ROLE_HIERARCHY[userRole] || 1;

    // Check if user has explicit match or satisfies minimum hierarchy level
    const normalizedAllowed = allowedRoles.map(r => String(r).toUpperCase());
    const minRequiredLevel = Math.min(...normalizedAllowed.map(r => ROLE_HIERARCHY[r] || 2));

    const isAuthorized = normalizedAllowed.includes(userRole) || userLevel >= minRequiredLevel;

    if (!isAuthorized) {
      return res.status(403).json({
        error: `Access denied: Role '${req.user.role}' lacks sufficient privileges. Required role: [${allowedRoles.join(', ')}].`
      });
    }

    next();
  };
}

function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required.' });
    }
    const userRole = (req.user.role || 'READONLY').toUpperCase();
    if (userRole === 'READONLY' && permission !== 'read') {
      return res.status(403).json({
        error: `Access denied: Permission '${permission}' requires OPERATOR or higher.`
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
