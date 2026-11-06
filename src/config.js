/**
 * EJII — Eldar Jamiyev's Infrastructure Intelligence
 * Configuration & Cryptographic Secret Hygiene Module
 */

'use strict';

const path = require('path');
const os = require('os');
const fs = require('fs');
const crypto = require('crypto');

const PORT = parseInt(process.env.EJII_PORT || '8443', 10);
// Secure default: Bind strictly to loopback 127.0.0.1 to avoid exposing NOC workstation on public networks
const HOST = process.env.EJII_HOST || '127.0.0.1';
const DATA_DIR = process.env.EJII_DATA_DIR ? path.resolve(process.env.EJII_DATA_DIR) : path.join(__dirname, '..', 'data');
const DB_PATH = process.env.EJII_DB_PATH || path.join(DATA_DIR, 'ejii.sqlite');

// Ensure writable data directory exists immediately
try {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
} catch (e) {
  console.error('[CONFIG INIT ERROR]: Failed to create data directory at ' + DATA_DIR, e.message);
}

// Known legacy/placeholder secrets that are strictly forbidden in production or non-local exposure
const KNOWN_INSECURE_SECRETS = new Set([
  'EJII-ENTERPRISE-INTELLIGENCE-HMAC-SECURE-KEY-2026',
  'EJII-ENTERPRISE-TOKEN-KEY-98471298471928471',
  'ejii-super-secret-jwt-key-change-in-production',
  'changeme',
  'default',
  'secret',
  'password'
]);

const KNOWN_DEFAULT_PASSWORDS = Object.freeze([
  'admin2026!',
  'sysadmin2026!',
  'netadmin2026!',
  'noc2026!'
]);

function isLocalLoopbackHost(host = HOST) {
  const h = String(host || '').trim().toLowerCase();
  return h === '127.0.0.1' || h === 'localhost' || h === '::1' || h === '::ffff:127.0.0.1';
}

function isWildcardBindingHost(host = HOST) {
  const h = String(host || '').trim().toLowerCase();
  return h === '0.0.0.0' || h === '::' || h === '0:0:0:0:0:0:0:0' || h === '::ffff:0.0.0.0';
}

/**
 * Load or generate per-installation cryptographically random 256-bit secrets for local development
 * so that no installation ever relies on a static secret committed to source control.
 */
function loadOrCreateLocalDevSecrets(dataDir = DATA_DIR) {
  const secDir = path.join(dataDir, 'security');
  const secretsFile = path.join(secDir, '.local_instance_secrets.json');
  try {
    if (fs.existsSync(secretsFile)) {
      const parsed = JSON.parse(fs.readFileSync(secretsFile, 'utf8'));
      if (
        parsed &&
        typeof parsed.hmacSecret === 'string' && parsed.hmacSecret.length >= 64 &&
        typeof parsed.jwtSecret === 'string' && parsed.jwtSecret.length >= 64 &&
        parsed.hmacSecret !== parsed.jwtSecret
      ) {
        return parsed;
      }
    }
    if (!fs.existsSync(secDir)) {
      fs.mkdirSync(secDir, { recursive: true });
    }
    const generated = {
      hmacSecret: crypto.randomBytes(32).toString('hex'),
      jwtSecret: crypto.randomBytes(32).toString('hex'),
      createdAt: new Date().toISOString()
    };
    fs.writeFileSync(secretsFile, JSON.stringify(generated, null, 2), { mode: 0o600, encoding: 'utf8' });
    return generated;
  } catch (_) {
    return {
      hmacSecret: crypto.randomBytes(32).toString('hex'),
      jwtSecret: crypto.randomBytes(32).toString('hex')
    };
  }
}

/**
 * Validates JWT, HMAC, and network exposure configuration.
 * - Requires strong (>=32 chars), non-default, unique (HMAC !== JWT) secrets outside local-only development.
 * - Prevents unsafe network exposure (non-loopback HOST, including wildcard 0.0.0.0) with default credentials or evaluation mode.
 */
function isTemplateEnvPlaceholder(sec) {
  if (!sec || typeof sec !== 'string') return false;
  const s = sec.trim();
  return /^PLACEHOLDER_/i.test(s) || /^MY_/i.test(s);
}

function isPlaceholderSecret(sec) {
  if (!sec || typeof sec !== 'string') return true;
  const s = sec.trim();
  return KNOWN_INSECURE_SECRETS.has(s) || isTemplateEnvPlaceholder(s);
}

function validateSecurityConfiguration(opts = {}) {
  const env = opts.env || process.env;
  const host = opts.host || env.EJII_HOST || HOST;
  const port = Number(opts.port || env.EJII_PORT || PORT);
  const isProduction = env.NODE_ENV === 'production';
  const isLoopback = isLocalLoopbackHost(host);
  const isWildcard = isWildcardBindingHost(host);
  const isDevContainerWildcard =
    !isProduction &&
    isWildcard &&
    opts.requireExplicitSecretsOnWildcard !== true &&
    env.EJII_REQUIRE_EXPLICIT_SECRETS !== 'true';
  const requiresExplicitSecrets =
    isProduction ||
    env.EJII_REQUIRE_EXPLICIT_SECRETS === 'true' ||
    (!isLoopback && !isDevContainerWildcard && env.NODE_ENV !== 'test');

  const rawHmac = env.EJII_HMAC_SECRET;
  const rawJwt = env.EJII_JWT_SECRET;
  const hmac = isPlaceholderSecret(rawHmac) ? null : rawHmac;
  const jwt = isPlaceholderSecret(rawJwt) ? null : rawJwt;

  if (requiresExplicitSecrets) {
    if (!hmac || hmac.length < 32) {
      throw new Error(
        'FATAL CONFIGURATION ERROR: Outside local-only development (or in NODE_ENV=production), EJII_HMAC_SECRET must be explicitly configured with at least 32 characters. Refusing to boot with missing or insecure default secret.'
      );
    }
    if (!jwt || jwt.length < 32) {
      throw new Error(
        'FATAL CONFIGURATION ERROR: Outside local-only development (or in NODE_ENV=production), EJII_JWT_SECRET must be explicitly configured with at least 32 characters. Refusing to boot with missing or insecure default secret.'
      );
    }
    if (hmac === jwt) {
      throw new Error(
        'FATAL CONFIGURATION ERROR: EJII_HMAC_SECRET and EJII_JWT_SECRET must be unique (distinct cryptographic keys are required for JWT session signing vs. HMAC audit log chaining).'
      );
    }
  } else {
    // In local development or container dev, template env placeholders (PLACEHOLDER_*) fall back to per-instance random local secrets,
    // while explicitly configured known-default, weak (<32 chars), or identical secrets are rejected.
    if (
      rawHmac &&
      typeof rawHmac === 'string' &&
      rawHmac.trim().length > 0 &&
      !isTemplateEnvPlaceholder(rawHmac) &&
      (!hmac || hmac.length < 32)
    ) {
      throw new Error('FATAL CONFIGURATION ERROR: Configured EJII_HMAC_SECRET must be at least 32 characters and cannot be a known default secret.');
    }
    if (
      rawJwt &&
      typeof rawJwt === 'string' &&
      rawJwt.trim().length > 0 &&
      !isTemplateEnvPlaceholder(rawJwt) &&
      (!jwt || jwt.length < 32)
    ) {
      throw new Error('FATAL CONFIGURATION ERROR: Configured EJII_JWT_SECRET must be at least 32 characters and cannot be a known default secret.');
    }
    if (hmac && jwt && hmac === jwt) {
      throw new Error('FATAL CONFIGURATION ERROR: EJII_HMAC_SECRET and EJII_JWT_SECRET must be unique.');
    }
  }

  // Prevent unsafe network exposure (any non-loopback host, including 0.0.0.0) with evaluation mode or default admin password
  if (!isLoopback && env.NODE_ENV !== 'test') {
    if (env.EJII_EVALUATION_MODE === 'true') {
      throw new Error(
        `FATAL CONFIGURATION ERROR: Unsafe network exposure blocked. Cannot enable EJII_EVALUATION_MODE=true when bound to non-loopback interface (${host}).`
      );
    }
    if (env.EJII_ADMIN_PASSWORD && KNOWN_DEFAULT_PASSWORDS.includes(env.EJII_ADMIN_PASSWORD)) {
      throw new Error(
        `FATAL CONFIGURATION ERROR: Unsafe network exposure blocked. Cannot use known default password when bound to non-loopback interface (${host}).`
      );
    }
  }
}

validateSecurityConfiguration();

const localSecrets = loadOrCreateLocalDevSecrets(DATA_DIR);
const HMAC_SECRET = (!isPlaceholderSecret(process.env.EJII_HMAC_SECRET) && process.env.EJII_HMAC_SECRET.length >= 32)
  ? process.env.EJII_HMAC_SECRET
  : localSecrets.hmacSecret;
const JWT_SECRET = (!isPlaceholderSecret(process.env.EJII_JWT_SECRET) && process.env.EJII_JWT_SECRET.length >= 32)
  ? process.env.EJII_JWT_SECRET
  : localSecrets.jwtSecret;

// Protected system processes that can NEVER be terminated by automation
const PROTECTED_SYSTEM_PROCESSES = [
  'system',
  'system idle process',
  'smss.exe',
  'csrss.exe',
  'wininit.exe',
  'services.exe',
  'lsass.exe',
  'winlogon.exe',
  'explorer.exe',
  'svchost.exe',
  'dwm.exe',
  'node.exe'
];

// Tier classification for Automation Actions
const AUTOMATION_TIERS = {
  TIER_1: {
    level: 1,
    name: 'Diagnostic / Read-Only',
    requiresApproval: false,
    description: 'Ping, traceroute, port scan, metric capture.'
  },
  TIER_2: {
    level: 2,
    name: 'Safe Non-Destructive Remediation',
    requiresApproval: false,
    description: 'Flush DNS cache, test socket connection, query event logs.'
  },
  TIER_3: {
    level: 3,
    name: 'High-Impact / Destructive Remediation',
    requiresApproval: true,
    description: 'Restart services, terminate rogue processes, bounce network adapters. Requires Application Owner dual-custody approval.'
  }
};

// Evaluation mode is strictly forbidden in production, and ONLY permitted on local loopback hosts (never 0.0.0.0)
const IS_EVALUATION_MODE =
  process.env.NODE_ENV !== 'production' &&
  process.env.EJII_EVALUATION_MODE === 'true' &&
  (isLocalLoopbackHost(HOST) || process.env.NODE_ENV === 'test');

module.exports = {
  PORT,
  HOST,
  DATA_DIR,
  DB_PATH,
  HMAC_SECRET,
  JWT_SECRET,
  KNOWN_INSECURE_SECRETS,
  KNOWN_DEFAULT_PASSWORDS,
  isLocalLoopbackHost,
  isWildcardBindingHost,
  validateSecurityConfiguration,
  PROTECTED_SYSTEM_PROCESSES,
  AUTOMATION_TIERS,
  IS_EVALUATION_MODE,
  IS_WINDOWS: os.platform() === 'win32',
  IS_LINUX: os.platform() === 'linux',
  PLATFORM: os.platform()
};
