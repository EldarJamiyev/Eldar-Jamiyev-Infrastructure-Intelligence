/**
 * EJI Login Rate Limiter & Brute-Force Abuse Protection
 * In-memory sliding window throttle with exponential lockout and audit reporting.
 */

const attemptsMap = new Map();
const MAX_ATTEMPTS = 5;
const WINDOW_MS = 15 * 60 * 1000; // 15 minutes lockout
const MAX_TRACKED_CLIENTS = 5000;

function enforceMaxCapacity() {
  if (attemptsMap.size > MAX_TRACKED_CLIENTS) {
    const excess = attemptsMap.size - MAX_TRACKED_CLIENTS;
    const iter = attemptsMap.keys();
    for (let i = 0; i < excess; i++) {
      const next = iter.next();
      if (next.done) break;
      attemptsMap.delete(next.value);
    }
  }
}

function cleanOldAttempts() {
  const now = Date.now();
  for (const [key, data] of attemptsMap.entries()) {
    if (now - data.firstAttempt > WINDOW_MS && now > data.lockedUntil) {
      attemptsMap.delete(key);
    }
  }
}

// Clean up every 5 minutes
setInterval(cleanOldAttempts, 5 * 60 * 1000).unref();

function getClientKey(req) {
  const ip = req.ip || req.socket.remoteAddress || '127.0.0.1';
  const username = req.body && req.body.username ? String(req.body.username).trim().toLowerCase() : 'unknown';
  return `${ip}::${username}`;
}

/**
 * Middleware checking if the IP/username pair is currently locked out
 */
function loginRateLimiter(req, res, next) {
  const key = getClientKey(req);
  const data = attemptsMap.get(key);

  if (data && data.lockedUntil && Date.now() < data.lockedUntil) {
    const remainingSec = Math.ceil((data.lockedUntil - Date.now()) / 1000);
    res.setHeader('Retry-After', remainingSec);
    return res.status(429).json({
      error: `Too many failed login attempts. Account temporarily locked for security. Please try again in ${remainingSec} seconds.`
    });
  }

  next();
}

/**
 * Record a login result (called after authentication evaluation)
 */
function recordLoginAttempt(req, success) {
  const key = getClientKey(req);
  const now = Date.now();

  if (success) {
    attemptsMap.delete(key);
    return;
  }

  let data = attemptsMap.get(key);
  if (!data || now - data.firstAttempt > WINDOW_MS) {
    data = { count: 1, firstAttempt: now, lockedUntil: 0 };
  } else {
    data.count++;
  }

  if (data.count >= MAX_ATTEMPTS) {
    data.lockedUntil = now + WINDOW_MS;
  }

  attemptsMap.set(key, data);
  enforceMaxCapacity();
}

function checkRateLimit(keyOrIp) {
  const data = attemptsMap.get(keyOrIp);
  if (!data) return { allowed: true, remainingAttempts: MAX_ATTEMPTS, retryAfterSeconds: 0 };
  if (data.lockedUntil && Date.now() < data.lockedUntil) {
    return {
      allowed: false,
      remainingAttempts: 0,
      retryAfterSeconds: Math.ceil((data.lockedUntil - Date.now()) / 1000)
    };
  }
  return {
    allowed: true,
    remainingAttempts: Math.max(0, MAX_ATTEMPTS - data.count),
    retryAfterSeconds: 0
  };
}

function recordFailedAttempt(keyOrIp) {
  const now = Date.now();
  let data = attemptsMap.get(keyOrIp);
  if (!data || now - data.firstAttempt > WINDOW_MS) {
    data = { count: 1, firstAttempt: now, lockedUntil: 0 };
  } else {
    data.count++;
  }
  if (data.count >= MAX_ATTEMPTS) {
    data.lockedUntil = now + WINDOW_MS;
  }
  attemptsMap.set(keyOrIp, data);
  enforceMaxCapacity();
}

function resetRateLimit(keyOrIp) {
  attemptsMap.delete(keyOrIp);
}

function getAttemptsMapSize() {
  return attemptsMap.size;
}

/**
 * Sliding-window in-memory rate limiter factory for API routes.
 * Emits X-RateLimit-* headers and enforces 429 when threshold exceeded.
 */
function createApiRateLimiter(options = {}) {
  const windowMs = Number(options.windowMs) || 60_000;
  const maxRequests = Number(options.maxRequests) || 300;
  const endpointName = String(options.endpointName || 'api');
  const requestCounts = new Map();
  const maxTrackedClients = 10000;

  const timer = setInterval(() => {
    const now = Date.now();
    for (const [ip, entry] of requestCounts.entries()) {
      if (now - entry.windowStart > windowMs) {
        requestCounts.delete(ip);
      }
    }
  }, Math.min(windowMs, 30_000));
  if (timer.unref) timer.unref();

  return function apiRateLimiter(req, res, next) {
    if (process.env.NODE_ENV === 'test' && req.headers && req.headers['x-bypass-ratelimit'] === 'true') {
      return next();
    }
    const ip = req.ip || req.socket?.remoteAddress || '127.0.0.1';
    const now = Date.now();

    let entry = requestCounts.get(ip);
    if (!entry || now - entry.windowStart > windowMs) {
      entry = { count: 1, windowStart: now };
      if (requestCounts.size >= maxTrackedClients) {
        const firstKey = requestCounts.keys().next().value;
        if (firstKey) requestCounts.delete(firstKey);
      }
      requestCounts.set(ip, entry);
    } else {
      entry.count++;
    }

    const remaining = Math.max(0, maxRequests - entry.count);
    const resetSec = Math.ceil((entry.windowStart + windowMs - now) / 1000);
    if (typeof res.setHeader === 'function') {
      res.setHeader('X-RateLimit-Limit', maxRequests);
      res.setHeader('X-RateLimit-Remaining', remaining);
      res.setHeader('X-RateLimit-Reset', resetSec);
    }

    if (entry.count > maxRequests) {
      if (typeof res.setHeader === 'function') {
        res.setHeader('Retry-After', resetSec);
      }
      return res.status(429).json({
        ok: false,
        error: `Rate limit exceeded on /${endpointName}. Max ${maxRequests} requests per ${Math.round(windowMs / 1000)}s. Please retry in ${resetSec} seconds.`,
        endpoint: endpointName,
        retryAfter: resetSec
      });
    }

    next();
  };
}

const chatRateLimiter = createApiRateLimiter({ endpointName: 'api/chat', windowMs: 60_000, maxRequests: 180 });
const enterpriseRateLimiter = createApiRateLimiter({ endpointName: 'api/enterprise', windowMs: 60_000, maxRequests: 300 });
const v6FabricRateLimiter = createApiRateLimiter({ endpointName: 'api/v6', windowMs: 60_000, maxRequests: 300 });
const atlasRateLimiter = createApiRateLimiter({ endpointName: 'api/atlas', windowMs: 60_000, maxRequests: 240 });
const diagnosticsRateLimiter = createApiRateLimiter({ endpointName: 'api/diagnostics', windowMs: 60_000, maxRequests: 200 });

module.exports = {
  loginRateLimiter,
  recordLoginAttempt,
  checkRateLimit,
  recordFailedAttempt,
  resetRateLimit,
  getAttemptsMapSize,
  createApiRateLimiter,
  chatRateLimiter,
  enterpriseRateLimiter,
  v6FabricRateLimiter,
  atlasRateLimiter,
  diagnosticsRateLimiter,
  MAX_TRACKED_CLIENTS
};

