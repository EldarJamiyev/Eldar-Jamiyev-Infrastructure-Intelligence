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
  if (req.user) {
    return next();
  }
  let token = null;
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.slice(7).trim();

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
      role: String(user.role || 'READONLY').toUpperCase()
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

const crypto = require('crypto');
const { performance } = require('perf_hooks');

const apiTelemetryBuffer = [];
let totalApiRequests = 0;
let totalApiErrors = 0;
let totalApiDurationMs = 0;

const { cncfObservabilityExporter } = require('../integrations/observability/cncf-observability-exporter');

function requestCorrelationAndTelemetryMiddleware(req, res, next) {
  const reqId = req.headers['x-request-id'] || `REQ-${crypto.randomBytes(6).toString('hex')}`;
  req.id = reqId;
  res.setHeader('X-Request-Id', reqId);

  // W3C Trace Context pipeline (00-<traceId>-<spanId>-01)
  let traceId = null;
  const spanId = crypto.randomBytes(8).toString('hex');
  const incomingTraceparent = req.headers['traceparent'];
  if (incomingTraceparent && typeof incomingTraceparent === 'string' && /^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$/i.test(incomingTraceparent.trim())) {
    const parts = incomingTraceparent.trim().split('-');
    traceId = parts[1];
  } else {
    traceId = crypto.randomBytes(16).toString('hex');
  }
  const traceparent = `00-${traceId}-${spanId}-01`;
  req.traceId = traceId;
  req.spanId = spanId;
  req.traceparent = traceparent;
  res.setHeader('traceparent', traceparent);

  const startMs = performance.now();
  totalApiRequests++;

  res.on('finish', () => {
    const durationMs = Number((performance.now() - startMs).toFixed(2));
    totalApiDurationMs += durationMs;
    if (res.statusCode >= 400) {
      totalApiErrors++;
    }

    const record = {
      id: reqId,
      traceId,
      spanId,
      traceparent,
      method: req.method,
      path: req.originalUrl || req.url,
      statusCode: res.statusCode,
      durationMs,
      timestamp: new Date().toISOString()
    };

    apiTelemetryBuffer.push(record);
    if (apiTelemetryBuffer.length > 500) {
      apiTelemetryBuffer.shift();
    }

    try {
      cncfObservabilityExporter.recordOtelSpan({
        name: `HTTP ${req.method} ${req.baseUrl || ''}${req.path || ''}`,
        kind: 'SERVER',
        durationMs,
        traceId,
        spanId,
        attributes: {
          'http.method': req.method,
          'http.target': req.originalUrl || req.url,
          'http.status_code': res.statusCode,
          'http.route': req.baseUrl || req.path
        },
        status: { code: res.statusCode >= 500 ? 'ERROR' : 'OK' }
      });
    } catch (_) {}
  });

  next();
}

function getApiTelemetry() {
  const recent = [...apiTelemetryBuffer];
  const count = recent.length;
  const durations = recent.map(r => r.durationMs).sort((a, b) => a - b);
  const p95 = durations.length > 0 ? durations[Math.floor(durations.length * 0.95)] : 0;
  const avg = count > 0 ? Number((durations.reduce((a, b) => a + b, 0) / count).toFixed(2)) : 0;

  return {
    totalRequests: totalApiRequests,
    totalErrors: totalApiErrors,
    errorRate: totalApiRequests > 0 ? Number(((totalApiErrors / totalApiRequests) * 100).toFixed(2)) : 0,
    bufferCount: count,
    avgLatencyMs: avg,
    p95LatencyMs: p95 || 0,
    recentRequests: recent.slice(-50).reverse(),
    capturedAt: new Date().toISOString()
  };
}

module.exports = {
  authenticate,
  requireRole,
  requirePermission,
  parseCookies,
  requestCorrelationAndTelemetryMiddleware,
  getApiTelemetry,
  ROLE_HIERARCHY
};
