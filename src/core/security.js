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


const IPV4_RESTRICTED_CIDRS = [
  { name: 'THIS_NETWORK', base: 0x00000000, mask: 0xFF000000, category: 'RESERVED' },       // 0.0.0.0/8
  { name: 'LOOPBACK', base: 0x7F000000, mask: 0xFF000000, category: 'LOOPBACK' },           // 127.0.0.0/8
  { name: 'RFC1918_10', base: 0x0A000000, mask: 0xFF000000, category: 'PRIVATE' },          // 10.0.0.0/8
  { name: 'RFC1918_172', base: 0xAC100000, mask: 0xFFF00000, category: 'PRIVATE' },         // 172.16.0.0/12
  { name: 'RFC1918_192', base: 0xC0A80000, mask: 0xFFFF0000, category: 'PRIVATE' },         // 192.168.0.0/16
  { name: 'LINK_LOCAL_APIPA', base: 0xA9FE0000, mask: 0xFFFF0000, category: 'LINK_LOCAL' }, // 169.254.0.0/16
  { name: 'CLOUD_METADATA', base: 0xA9FEA9FE, mask: 0xFFFFFFFF, category: 'METADATA' },     // 169.254.169.254/32
  { name: 'CGNAT', base: 0x64400000, mask: 0xFFC00000, category: 'SHARED_CGNAT' },          // 100.64.0.0/10
  { name: 'MULTICAST', base: 0xE0000000, mask: 0xF0000000, category: 'MULTICAST' },         // 224.0.0.0/4
  { name: 'BROADCAST', base: 0xFFFFFFFF, mask: 0xFFFFFFFF, category: 'BROADCAST' }          // 255.255.255.255/32
];

/**
 * Parses standard, octal, hex, or integer-encoded IPv4 strings into an unsigned 32-bit integer.
 * Returns null if the input is not an IPv4 representation.
 */
function parseAnyIPv4EncodingToUint32(rawHost) {
  if (typeof rawHost !== 'string') return null;
  const trimmed = rawHost.trim();
  if (!trimmed) return null;

  // Pure single integer (e.g., "2130706433") or single hex (e.g., "0x7f000001")
  if (/^(0x[0-9a-fA-F]+|\d+)$/.test(trimmed)) {
    const val = trimmed.startsWith('0x') || trimmed.startsWith('0X')
      ? Number.parseInt(trimmed, 16)
      : Number.parseInt(trimmed, 10);
    if (Number.isInteger(val) && val >= 0 && val <= 0xFFFFFFFF) {
      return val >>> 0;
    }
    return null;
  }

  const parts = trimmed.split('.');
  if (parts.length < 2 || parts.length > 4) return null;

  const parsedParts = [];
  for (const part of parts) {
    if (!/^(0x[0-9a-fA-F]+|0[0-7]+|\d+)$/.test(part)) return null;
    let num;
    if (part.startsWith('0x') || part.startsWith('0X')) {
      num = Number.parseInt(part, 16);
    } else if (part.length > 1 && part.startsWith('0')) {
      num = Number.parseInt(part, 8);
    } else {
      num = Number.parseInt(part, 10);
    }
    if (!Number.isInteger(num) || num < 0) return null;
    parsedParts.push(num);
  }

  if (parsedParts.length === 4) {
    if (parsedParts.some((p) => p > 255)) return null;
    return (((parsedParts[0] << 24) | (parsedParts[1] << 16) | (parsedParts[2] << 8) | parsedParts[3]) >>> 0);
  }
  if (parsedParts.length === 3) {
    if (parsedParts[0] > 255 || parsedParts[1] > 255 || parsedParts[2] > 0xFFFF) return null;
    return (((parsedParts[0] << 24) | (parsedParts[1] << 16) | parsedParts[2]) >>> 0);
  }
  if (parsedParts.length === 2) {
    if (parsedParts[0] > 255 || parsedParts[1] > 0xFFFFFF) return null;
    return (((parsedParts[0] << 24) | parsedParts[1]) >>> 0);
  }
  return null;
}

function uint32ToCanonicalIPv4(uint32) {
  return [
    (uint32 >>> 24) & 0xFF,
    (uint32 >>> 16) & 0xFF,
    (uint32 >>> 8) & 0xFF,
    uint32 & 0xFF
  ].join('.');
}

function classifyIPv4Uint32(uint32, policy = {}) {
  // Cloud metadata is unconditionally blocked regardless of allowPrivate/allowLoopback
  if ((uint32 >>> 0) === 0xA9FEA9FE || (uint32 >>> 0) === 0x646464C8) {
    return { allowed: false, reason: 'CLOUD_METADATA_PROHIBITED', range: 'CLOUD_METADATA' };
  }
  for (const cidr of IPV4_RESTRICTED_CIDRS) {
    if (((uint32 & cidr.mask) >>> 0) === (cidr.base >>> 0)) {
      if (cidr.category === 'LOOPBACK' && policy.allowLoopback !== false) continue;
      if (cidr.category === 'PRIVATE' && policy.allowPrivate !== false) continue;
      if (cidr.category === 'LINK_LOCAL' && policy.allowLinkLocal === true) continue;
      return { allowed: false, reason: `RESTRICTED_RANGE_${cidr.name}`, range: cidr.name };
    }
  }
  return { allowed: true, reason: null, range: 'PUBLIC_UNICAST' };
}

function classifyIPv6Address(ipv6Str, policy = {}) {
  const normalized = ipv6Str.trim().toLowerCase().replace(/%.+$/, ''); // Strip zone index
  if (normalized === '::' || normalized === '0:0:0:0:0:0:0:0') {
    return { allowed: false, reason: 'IPV6_UNSPECIFIED_PROHIBITED' };
  }
  if (normalized === '::1' || normalized === '0:0:0:0:0:0:0:1') {
    return policy.allowLoopback !== false
      ? { allowed: true, reason: null, range: 'IPV6_LOOPBACK' }
      : { allowed: false, reason: 'IPV6_LOOPBACK_PROHIBITED' };
  }
  if (normalized.startsWith('fd00:ec2:') || normalized.startsWith('fe80::169.254.169.254') || normalized.includes('169.254.169.254')) {
    return { allowed: false, reason: 'IPV6_CLOUD_METADATA_PROHIBITED' };
  }
  // Extract embedded IPv4 from ::ffff:a.b.c.d or ::ffff:xxxx:yyyy
  if (normalized.startsWith('::ffff:')) {
    const tail = normalized.slice(7);
    const v4Int = parseAnyIPv4EncodingToUint32(tail);
    if (v4Int !== null) {
      return classifyIPv4Uint32(v4Int, policy);
    }
    const hexMatch = tail.match(/^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (hexMatch) {
      const hi = Number.parseInt(hexMatch[1], 16);
      const lo = Number.parseInt(hexMatch[2], 16);
      const mappedUint32 = (((hi << 16) | lo) >>> 0);
      return classifyIPv4Uint32(mappedUint32, policy);
    }
  }
  if (normalized.startsWith('fe80:') && policy.allowLinkLocal !== true) {
    return { allowed: false, reason: 'IPV6_LINK_LOCAL_PROHIBITED' };
  }
  if ((normalized.startsWith('fc') || normalized.startsWith('fd')) && policy.allowPrivate === false) {
    return { allowed: false, reason: 'IPV6_ULA_PRIVATE_PROHIBITED' };
  }
  if (normalized.startsWith('ff')) {
    return { allowed: false, reason: 'IPV6_MULTICAST_PROHIBITED' };
  }
  return { allowed: true, reason: null, range: 'IPV6_UNICAST' };
}

/**
 * Creates a custom DNS lookup callback bound to a pre-validated IP and address family.
 * Conforms strictly to Node.js v24 lookup options contracts (both opts.all = true and false).
 */
function createPinnedLookup(pinnedIp, addressFamily = 4) {
  const family = Number(addressFamily) === 6 ? 6 : 4;
  return function pinnedLookup(hostname, options, callback) {
    let cb = callback;
    let opts = options;
    if (typeof opts === 'function') {
      cb = opts;
      opts = {};
    }
    if (typeof cb !== 'function') return;

    if (opts && opts.all === true) {
      return process.nextTick(() => cb(null, [{ address: pinnedIp, family }]));
    }
    return process.nextTick(() => cb(null, pinnedIp, family));
  };
}

/**
 * Helper to validate an IPv4 32-bit unsigned integer against SSRF / non-routable ranges.
 * Preserves RFC 1918 (10/8, 172.16/12, 192.168/16) and Loopback (127/8) for NOC diagnostics.
 */
function isAllowedIPv4Int(ipInt) {
  const classification = classifyIPv4Uint32(ipInt, { allowLoopback: true, allowPrivate: true });
  return classification.allowed;
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
function isSafeNetworkTarget(rawTarget, policy = {}) {
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

  // 2. Check for multi-encoding IPv4 (octal, hex, dword, shortened)
  const v4Int = parseAnyIPv4EncodingToUint32(unbracketed);
  if (v4Int !== null) {
    // If input was octal, hex, or pure integer, verify it doesn't try to evade standard dot-decimal checks
    const classification = classifyIPv4Uint32(v4Int, policy);
    return classification.allowed;
  }

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

  // 4. Check IPv6 addresses (including IPv4-mapped and IPv4-compatible IPv6)
  if (unbracketed.includes(':') || net.isIPv6(unbracketed)) {
    const classification = classifyIPv6Address(unbracketed, policy);
    return classification.allowed;
  }

  // 5. Validate as strict RFC-1123 hostname
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
 * and returns { valid, hostname, safeTarget, pinnedIp, addressFamily, resolvedIps, isIpLiteral, lookup, error }.
 */
async function resolveAndValidateTarget(rawTarget, policy = {}) {
  if (typeof rawTarget !== 'string' || !rawTarget.trim()) {
    return {
      valid: false,
      hostname: rawTarget || '',
      safeTarget: rawTarget || '',
      pinnedIp: null,
      addressFamily: null,
      resolvedIps: [],
      isIpLiteral: false,
      lookup: null,
      error: 'TARGET_REQUIRED: Target host or IP address is empty.'
    };
  }

  const clean = rawTarget.trim().replace(/^https?:\/\//i, '').split('/')[0];
  const unbracketed = clean.replace(/^\[|\]$/g, '');

  if (!isSafeNetworkTarget(unbracketed, policy)) {
    return {
      valid: false,
      hostname: clean,
      safeTarget: clean,
      pinnedIp: null,
      addressFamily: null,
      resolvedIps: [],
      isIpLiteral: false,
      lookup: null,
      error: `SECURITY_VIOLATION: Target "${clean}" rejected by SSRF defense policy.`
    };
  }

  const v4Int = parseAnyIPv4EncodingToUint32(unbracketed);
  if (v4Int !== null) {
    const canonical = uint32ToCanonicalIPv4(v4Int);
    return {
      valid: true,
      hostname: unbracketed,
      safeTarget: canonical,
      pinnedIp: canonical,
      addressFamily: 4,
      resolvedIps: [canonical],
      isIpLiteral: true,
      lookup: createPinnedLookup(canonical, 4),
      error: null
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
      lookup: createPinnedLookup(unbracketed, ipVersion),
      error: null
    };
  }

  // Resolve hostname via DNS with strict sub-second timeout guard to prevent multi-second OS getaddrinfo stalls
  const dnsPromises = dns.promises;
  const resolvedIps = [];
  const raceTimeout = (promise, ms, fallbackVal = []) => {
    let timer;
    return Promise.race([
      promise,
      new Promise((resolve) => {
        timer = setTimeout(() => resolve(fallbackVal), ms);
      })
    ]).finally(() => clearTimeout(timer));
  };

  if (unbracketed.toLowerCase() === 'localhost') {
    resolvedIps.push('127.0.0.1', '::1');
  } else {
    try {
      const fastResolver = new dnsPromises.Resolver({ timeout: 750, tries: 1 });
      const [v4, v6] = await Promise.all([
        raceTimeout(fastResolver.resolve4(unbracketed).catch(() => []), 850, []),
        raceTimeout(fastResolver.resolve6(unbracketed).catch(() => []), 850, [])
      ]);
      resolvedIps.push(...v4, ...v6);
    } catch (_) {}

    if (resolvedIps.length === 0) {
      try {
        const lookups = await raceTimeout(
          dnsPromises.lookup(unbracketed, { all: true }).catch(() => []),
          850,
          []
        );
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
      lookup: null,
      error: 'DNS_RESOLUTION_FAILED: Hostname does not resolve to any IPv4 or IPv6 address.'
    };
  }

  // Check every resolved address against SSRF policy (DNS Rebinding defense)
  for (const ip of resolvedIps) {
    if (!isSafeNetworkTarget(ip, policy)) {
      return {
        valid: false,
        hostname: unbracketed,
        safeTarget: unbracketed,
        pinnedIp: null,
        addressFamily: null,
        resolvedIps,
        isIpLiteral: false,
        lookup: null,
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
    lookup: createPinnedLookup(preferredIp, family),
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
  resolveAndValidateTarget,
  IPV4_RESTRICTED_CIDRS,
  parseAnyIPv4EncodingToUint32,
  uint32ToCanonicalIPv4,
  classifyIPv4Uint32,
  classifyIPv6Address,
  createPinnedLookup
};
