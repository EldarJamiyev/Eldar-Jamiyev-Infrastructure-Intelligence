/**
 * EJII Security & Capability-Based Authorization Module
 * Cryptographically verified token generation, PBKDF2 hashing, and granular capability-based RBAC.
 */

'use strict';

const crypto = require('crypto');
const net = require('net');
const dns = require('dns');
const { JWT_SECRET } = require('../config');

// Explicit Distinct NOC Roles
const ROLES = {
  ADMIN: 'ADMIN',
  APP_OWNER: 'APP_OWNER',
  SYSADMIN: 'SYSADMIN',
  NETWORK_ADMIN: 'NETWORK_ADMIN',
  ANALYST: 'ANALYST',
  OPERATOR: 'OPERATOR',
  NOC_OPERATOR: 'NOC_OPERATOR',
  HELPDESK: 'HELPDESK',
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
  APP_OWNER: [
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
  HELPDESK: [
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
  const jti = payload.jti || (crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex'));
  const tokenPayload = {
    ...payload,
    jti,
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
  if (isTokenRevoked(token)) return null;
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
const revokedUsers = new Set();

function generateToken(user, expiresIn = 86400) {
  const role = (user.role || 'NOC_OPERATOR').toUpperCase();
  return createToken({ id: user.id, username: user.username, role }, expiresIn);
}

function revokeToken(token, userId = null, reason = 'User logout') {
  if (!token || typeof token !== 'string') return false;
  revokedTokens.add(token);
  try {
    const { db } = require('../db/database');
    db.prepare(`
      INSERT OR REPLACE INTO revoked_tokens (token, user_id, reason, revoked_at)
      VALUES (?, ?, ?, ?)
    `).run(token, userId || null, reason, new Date().toISOString());
  } catch (e) {}
  return true;
}

function revokeAllUserTokens(userId, reason = 'Bulk user revocation') {
  if (!userId) return false;
  revokedUsers.add(userId);
  const nowIso = new Date().toISOString();
  try {
    const { db } = require('../db/database');
    db.prepare(`
      INSERT OR REPLACE INTO revoked_tokens (token, user_id, reason, revoked_at)
      VALUES (?, ?, ?, ?)
    `).run(`USER_BULK_${userId}_${Date.now()}`, userId, reason, nowIso);
  } catch (e) {}
  return true;
}

function clearRevokedUser(userId) {
  if (!userId) return true;
  revokedUsers.delete(userId);
  try {
    const { db } = require('../db/database');
    db.prepare(`DELETE FROM revoked_tokens WHERE user_id = ? AND token LIKE 'USER_BULK_%'`).run(userId);
  } catch (e) {}
  return true;
}

function isTokenRevoked(token) {
  if (!token || typeof token !== 'string') return false;
  if (revokedTokens.has(token)) return true;

  let payload = null;
  try {
    const parts = token.split('.');
    if (parts.length === 3) {
      payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
      if (payload.id && revokedUsers.has(payload.id)) return true;
    }
  } catch (e) {}

  // Check persistent SQLite database for exact token revocation or bulk user revocation (F-52)
  try {
    const { db } = require('../db/database');
    const row = db.prepare('SELECT 1 FROM revoked_tokens WHERE token = ?').get(token);
    if (row) return true;

    if (payload && payload.id) {
      // Check if user has an active bulk revocation record issued at or after token issuance
      const bulkRow = db.prepare(
        "SELECT revoked_at FROM revoked_tokens WHERE user_id = ? AND token LIKE 'USER_BULK_%' ORDER BY id DESC LIMIT 1"
      ).get(payload.id);

      if (bulkRow && bulkRow.revoked_at) {
        const revokedTimeMs = new Date(bulkRow.revoked_at).getTime();
        const tokenIatMs = (payload.iat || 0) * 1000;
        // If token was issued at or before bulk revocation timestamp, it is revoked across restarts
        if (tokenIatMs <= revokedTimeMs + 1000) {
          revokedUsers.add(payload.id);
          return true;
        }
      }
    }
  } catch (e) {}

  return false;
}

/**
 * Strict capability-based permission checker
 */
function hasPermission(role, permission) {
  if (!role || !permission) return false;
  const normalizedRole = String(role).toUpperCase();
  const permissions = ROLE_CAPABILITIES[normalizedRole] || [];
  
  if (permissions.includes(permission)) return true;

  // Map legacy diag:* scoped permissions to network.diagnostics.execute
  if (permission.startsWith('diag:') && permissions.includes('network.diagnostics.execute')) {
    return true;
  }

  // Map legacy network:* scoped permissions
  if (permission.startsWith('network:') && (permissions.includes('network.capture.execute') || permissions.includes('network.diagnostics.execute'))) {
    return true;
  }

  // Map legacy system:* scoped permissions
  if (permission.startsWith('system:') && (permissions.includes('host.remediation.execute') || permissions.includes('host.remediation.preview'))) {
    return true;
  }

  // Map legacy admin:* scoped permissions
  if (permission.startsWith('admin:') && (permissions.includes('system.config.manage') || permissions.includes('users.roles.manage'))) {
    return true;
  }

  return false;
}

/**
 * Get all capabilities granted to a specific role
 */
function getRoleCapabilities(role) {
  const normalizedRole = String(role || '').toUpperCase();
  return ROLE_CAPABILITIES[normalizedRole] ? [...ROLE_CAPABILITIES[normalizedRole]] : [];
}


/**
 * Helper to validate an IPv4 32-bit unsigned integer against SSRF / non-routable ranges.
 * Preserves RFC 1918 (10/8, 172.16/12, 192.168/16) and Loopback (127/8) for NOC diagnostics.
 */
function isAllowedIPv4Int(ipInt) {
  const unsigned = ipInt >>> 0;
  const b1 = (unsigned >>> 24) & 0xff;
  const b2 = (unsigned >>> 16) & 0xff;

  // Block 0.0.0.0/8 ("this" network)
  if (b1 === 0) return false;
  // Block 169.254.0.0/16 (RFC 3927 Link-Local & Cloud Metadata 169.254.169.254)
  if (b1 === 169 && b2 === 254) return false;
  // Block 224.0.0.0/4 (Multicast) and 240.0.0.0/4 (Reserved / Broadcast 255.255.255.255)
  if (b1 >= 224) return false;

  return true;
}

/**
 * Parses standard dotted-quad IPv4 string into a 32-bit unsigned integer, or returns null.
 * Rejects leading-zero octal octets (e.g., 0251.0372.0251.0372).
 */
function parseStrictIPv4ToInt(ipv4Str) {
  if (typeof ipv4Str !== 'string') return null;
  const parts = ipv4Str.split('.');
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    if (part.length > 1 && part.startsWith('0')) return null; // Reject octal notation
    const num = Number(part);
    if (!Number.isInteger(num) || num < 0 || num > 255) return null;
    result = ((result << 8) | num) >>> 0;
  }
  return result >>> 0;
}

/**
 * Standardize hostname and IPv4/IPv6 validation (F-35).
 * Blocks command injection, decimal dword IPs, hex/octal IPs, cloud metadata hostnames,
 * IPv4 link-local (169.254.0.0/16), IPv6 link-local (fe80::/10), AWS IPv6 metadata (fd00:ec2::254),
 * and IPv4-mapped/compatible IPv6 addresses.
 * Strictly preserves RFC 1918 private subnets and loopback (127.0.0.1, ::1).
 */
function isSafeNetworkTarget(rawTarget) {
  if (typeof rawTarget !== 'string') return false;
  const trimmed = rawTarget.trim();
  if (trimmed.length === 0 || trimmed.length > 253) return false;

  // 1. Block shell metacharacters, whitespace, path traversal, and control chars
  if (/[;&|`$><\n\r\0\\'"(){}\s]|\.\./.test(trimmed)) return false;

  // Strip optional IPv6 brackets for inspection
  const unbracketed = trimmed.startsWith('[') && trimmed.endsWith(']')
    ? trimmed.slice(1, -1)
    : trimmed;
  if (unbracketed.includes('[') || unbracketed.includes(']')) return false;

  const lower = unbracketed.toLowerCase();

  // 2. Block pure integer / dword IPs (e.g. 2852039166) and hex literals (e.g. 0xa9fea9fe)
  if (/^\d+$/.test(lower) || /^0x[0-9a-f]+$/i.test(lower)) return false;

  // 3. Block cloud metadata hostnames
  const blockedHostnames = new Set([
    'metadata',
    'instance-data',
    'metadata.google.internal',
    'metadata.goog',
    '169.254.169.254.nip.io',
    '169.254.169.254.xip.io'
  ]);
  if (blockedHostnames.has(lower) || lower.endsWith('.metadata.google.internal') || lower.endsWith('.internal.cloudapp.net')) {
    return false;
  }

  // 4. If it looks like a dotted-quad (all segments numeric/hex/octal), validate strictly as IPv4
  if (/^[0-9a-fx.]+$/i.test(lower) && lower.includes('.')) {
    const ipInt = parseStrictIPv4ToInt(lower);
    if (ipInt === null) return false;
    return isAllowedIPv4Int(ipInt);
  }

  // 5. Check IPv6 addresses (including IPv4-mapped and IPv4-compatible IPv6)
  const ipVersion = net.isIP(unbracketed);
  if (ipVersion === 4) {
    const ipInt = parseStrictIPv4ToInt(unbracketed);
    return ipInt !== null && isAllowedIPv4Int(ipInt);
  }

  if (ipVersion === 6) {
    // Allow IPv6 loopback ::1
    if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') return true;
    // Block unspecified ::
    if (lower === '::' || lower === '0:0:0:0:0:0:0:0') return false;
    // Block AWS IPv6 IMDS (fd00:ec2::254)
    if (lower.startsWith('fd00:ec2:') || lower === 'fd00:ec2::254') return false;
    // Block IPv6 link-local (fe80::/10 -> fe80..febf) and multicast (ff00::/8)
    if (/^fe[89ab][0-9a-f]:/.test(lower) || lower.startsWith('fe80:') || lower.startsWith('ff')) return false;

    // Extract embedded IPv4 from ::ffff:w.x.y.z or ::w.x.y.z
    const lastColonIdx = lower.lastIndexOf(':');
    const tail = lower.slice(lastColonIdx + 1);
    if (tail.includes('.')) {
      const embeddedInt = parseStrictIPv4ToInt(tail);
      if (embeddedInt === null || !isAllowedIPv4Int(embeddedInt)) return false;
    }

    // Extract hex-encoded IPv4 from ::ffff:a9fe:a9fe or 0:0:0:0:0:ffff:a9fe:a9fe
    const hexMappedMatch = lower.match(/(?:^|:)ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (hexMappedMatch) {
      const high16 = parseInt(hexMappedMatch[1], 16);
      const low16 = parseInt(hexMappedMatch[2], 16);
      const mappedInt = (((high16 << 16) | low16) >>> 0);
      if (!isAllowedIPv4Int(mappedInt)) return false;
    }

    return true;
  }

  // 6. Validate as strict RFC-1123 hostname
  if (unbracketed.includes(':')) return false;
  const labels = lower.split('.');
  for (const label of labels) {
    if (!label || label.length > 63) return false;
    if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) return false;
  }
  // Reject if TLD is purely numeric (prevents partial IPv4 shorthand like 169.254.43518)
  if (/^\d+$/.test(labels[labels.length - 1])) return false;

  return true;
}

/**
 * Centralized Target Resolver, Validator & DNS IP-Pinning (F-05).
 * Resolves a target hostname or IP, verifies all resolved IPs against SSRF policy,
 * and returns { valid, hostname, safeTarget, pinnedIp, addressFamily, resolvedIps, isIpLiteral, error }.
 */
async function resolveAndValidateTarget(rawTarget) {
  if (typeof rawTarget !== 'string' || !rawTarget.trim()) {
    return {
      valid: false,
      hostname: rawTarget || '',
      safeTarget: rawTarget || '',
      pinnedIp: null,
      addressFamily: null,
      resolvedIps: [],
      isIpLiteral: false,
      error: 'TARGET_REQUIRED: Target host or IP address is empty.'
    };
  }

  const clean = rawTarget.trim().replace(/^https?:\/\//i, '').split('/')[0];
  const unbracketed = clean.replace(/^\[|\]$/g, '');

  if (!isSafeNetworkTarget(unbracketed)) {
    return {
      valid: false,
      hostname: clean,
      safeTarget: clean,
      pinnedIp: null,
      addressFamily: null,
      resolvedIps: [],
      isIpLiteral: false,
      error: `SECURITY_VIOLATION: Target "${clean}" rejected by SSRF defense policy.`
    };
  }

  const ipVersion = net.isIP(unbracketed);
  if (ipVersion !== 0) {
    return {
      valid: true,
      hostname: unbracketed,
      safeTarget: unbracketed,
      pinnedIp: unbracketed,
      addressFamily: ipVersion,
      resolvedIps: [unbracketed],
      isIpLiteral: true,
      error: null
    };
  }

  // Resolve hostname via DNS
  const dnsPromises = dns.promises;
  const resolvedIps = [];

  if (unbracketed.toLowerCase() === 'localhost') {
    resolvedIps.push('127.0.0.1', '::1');
  } else {
    try {
      const v4 = await dnsPromises.resolve4(unbracketed).catch(() => []);
      const v6 = await dnsPromises.resolve6(unbracketed).catch(() => []);
      resolvedIps.push(...v4, ...v6);
    } catch (_) {}

    if (resolvedIps.length === 0) {
      try {
        const lookups = await dnsPromises.lookup(unbracketed, { all: true }).catch(() => []);
        if (Array.isArray(lookups)) {
          for (const l of lookups) {
            if (l && l.address && !resolvedIps.includes(l.address)) {
              resolvedIps.push(l.address);
            }
          }
        }
      } catch (_) {}
    }
  }

  if (resolvedIps.length === 0) {
    return {
      valid: false,
      hostname: unbracketed,
      safeTarget: unbracketed,
      pinnedIp: null,
      addressFamily: null,
      resolvedIps: [],
      isIpLiteral: false,
      error: 'DNS_RESOLUTION_FAILED: Hostname does not resolve to any IPv4 or IPv6 address.'
    };
  }

  // Check every resolved address against SSRF policy (DNS Rebinding defense)
  for (const ip of resolvedIps) {
    if (!isSafeNetworkTarget(ip)) {
      return {
        valid: false,
        hostname: unbracketed,
        safeTarget: unbracketed,
        pinnedIp: null,
        addressFamily: null,
        resolvedIps,
        isIpLiteral: false,
        error: `SECURITY_VIOLATION: Hostname "${unbracketed}" resolved to forbidden address "${ip}" (DNS Rebinding SSRF blocked).`
      };
    }
  }

  // Select authoritative pinned IP: prefer IPv4
  const preferredIp = resolvedIps.find(ip => net.isIP(ip) === 4) || resolvedIps[0];
  const family = net.isIP(preferredIp) === 6 ? 6 : 4;

  return {
    valid: true,
    hostname: unbracketed,
    safeTarget: unbracketed,
    pinnedIp: preferredIp,
    addressFamily: family,
    resolvedIps,
    isIpLiteral: false,
    error: null
  };
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
  revokeAllUserTokens,
  clearRevokedUser,
  isTokenRevoked,
  hasPermission,
  getRoleCapabilities,
  isSafeNetworkTarget,
  isAllowedIPv4Int,
  parseStrictIPv4ToInt,
  resolveAndValidateTarget
};
