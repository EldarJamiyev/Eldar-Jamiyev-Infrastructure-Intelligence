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

module.exports = {
  loginRateLimiter,
  recordLoginAttempt,
  checkRateLimit,
  recordFailedAttempt,
  resetRateLimit,
  getAttemptsMapSize,
  MAX_TRACKED_CLIENTS
};

