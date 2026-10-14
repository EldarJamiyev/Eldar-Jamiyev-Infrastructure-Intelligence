/**
 * EJII API Middleware
 * Authentication, Authorization, Role enforcement, and Permission verification.
 */

const { verifyToken, hasPermission } = require('../core/security');
const { db } = require('../db/database');

/**
 * Middleware to extract and verify Bearer JWT token
 */
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required. Bearer token missing.' });
  }

  const token = authHeader.slice(7).trim();
  const decoded = verifyToken(token);

  if (!decoded) {
    return res.status(401).json({ error: 'Invalid or expired session token.' });
  }

  // Verify user is still active in database
  const user = db.prepare('SELECT id, username, full_name, role, is_active FROM users WHERE id = ?').get(decoded.id);

  if (!user || user.is_active !== 1) {
    return res.status(403).json({ error: 'User account is disabled or does not exist.' });
  }

  req.user = user;
  next();
}

/**
 * Middleware to require one of the specified roles
 * @param {string[]} allowedRoles 
 */
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthenticated.' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: `Access Denied. Role '${req.user.role}' is not authorized. Required: [${allowedRoles.join(', ')}]`
      });
    }

    next();
  };
}

/**
 * Middleware to require a specific permission
 * @param {string} permission 
 */
function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthenticated.' });
    }

    if (!hasPermission(req.user.role, permission)) {
      return res.status(403).json({
        error: `Permission Denied. Role '${req.user.role}' lacks permission: '${permission}'`
      });
    }

    next();
  };
}

module.exports = {
  authenticate,
  requireRole,
  requirePermission
};
