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
  'EJII-SRE-WAR-ROOM-SOVEREIGN-HMAC-KEY-2026',
  'EJII-ENTERPRISE-TOKEN-KEY-98471298471928471',
  'ejii-atlas-sovereign-hmac-secret-key-2026',
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

function isInsecureOrWeakSecret(sec, minLen = 16) {
  if (!sec || typeof sec !== 'string') return true;
  const s = sec.trim();
  if (s.length < minLen) return true;
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

/**
 * Purpose-separated HKDF-SHA256 Key Derivation & Keyring Rotation Manager.
 * Ensures that Atlas Control Plane, SRE War Room, DSRL Lyapunov Vault, and Flight Recorder
 * use cryptographically isolated keys and can rotate keys independently with grace-period verification.
 */
const PURPOSE_ENV_MAP = Object.freeze({
  'atlas-control-plane-v1': 'EJII_ATLAS_HMAC_SECRET',
  'sre-war-room-v1': 'EJII_WAR_ROOM_HMAC_SECRET',
  'dsrl-lyapunov-vault-v1': 'EJII_VAULT_HMAC_SECRET',
  'incident-flight-recorder-v1': 'EJII_FLIGHT_RECORDER_HMAC_SECRET',
  'telemetry-provenance-v1': 'EJII_TELEMETRY_HMAC_SECRET'
});

const purposeKeyRings = new Map();
const revokedPurposeKeyIds = new Map(); // purpose -> Set<keyId>

function getSqliteDbSafe() {
  try {
    return require('./db/database').db || null;
  } catch (_) {
    return null;
  }
}

function computeSecretFingerprint(secret) {
  return crypto.createHash('sha256').update(`ejii-key-fp-v1:${String(secret || '')}`).digest('hex');
}

function persistKeyVersionState(purpose, keyId, secret, status, meta = {}) {
  const db = meta.db || getSqliteDbSafe();
  if (!db || typeof db.prepare !== 'function') return false;
  try {
    const now = Date.now();
    const fp = computeSecretFingerprint(secret);
    db.prepare(`
      INSERT INTO crypto_key_versions (
        purpose, key_id, secret_fingerprint_sha256, status,
        created_at_ms, rotated_at_ms, expires_at_ms, revoked_at_ms, revocation_reason
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(purpose, key_id) DO UPDATE SET
        status = excluded.status,
        rotated_at_ms = COALESCE(excluded.rotated_at_ms, crypto_key_versions.rotated_at_ms),
        expires_at_ms = COALESCE(excluded.expires_at_ms, crypto_key_versions.expires_at_ms),
        revoked_at_ms = COALESCE(excluded.revoked_at_ms, crypto_key_versions.revoked_at_ms),
        revocation_reason = COALESCE(excluded.revocation_reason, crypto_key_versions.revocation_reason)
    `).run(
      purpose,
      keyId,
      fp,
      status,
      meta.createdAtMs || now,
      meta.rotatedAtMs || null,
      meta.expiresAtMs || null,
      meta.revokedAtMs || null,
      meta.revocationReason || null
    );
    return true;
  } catch (_) {
    return false;
  }
}

function isPurposeKeyRevokedOrExpiredInDb(purpose, keyId, customDb = null, options = {}) {
  const cleanPurpose = String(purpose || 'default-purpose-v1').trim();
  const cleanKeyId = String(keyId || '').trim();
  if (!cleanKeyId) return false;

  const db = customDb || getSqliteDbSafe();
  if (db && typeof db.prepare !== 'function') {
    const memSet = revokedPurposeKeyIds.get(cleanPurpose);
    return Boolean(memSet && memSet.has(cleanKeyId));
  }

  try {
    const row = db
      .prepare('SELECT status, expires_at_ms, revoked_at_ms FROM crypto_key_versions WHERE purpose = ? AND key_id = ?')
      .get(cleanPurpose, cleanKeyId);
    if (row) {
      if (row.status === 'REVOKED' || row.revoked_at_ms) {
        if (!customDb) {
          if (!revokedPurposeKeyIds.has(cleanPurpose)) revokedPurposeKeyIds.set(cleanPurpose, new Set());
          revokedPurposeKeyIds.get(cleanPurpose).add(cleanKeyId);
        }
        return true;
      }
      if (!options.onlyExplicitRevocation && (row.status === 'EXPIRED' || (row.expires_at_ms && Date.now() > Number(row.expires_at_ms)))) {
        return true;
      }
      return false;
    }
  } catch (_) {}

  if (customDb) {
    return false;
  }

  const memSet = revokedPurposeKeyIds.get(cleanPurpose);
  if (memSet && memSet.has(cleanKeyId)) return true;
  return false;
}

function _resetCryptoStateForTests() {
  purposeKeyRings.clear();
  revokedPurposeKeyIds.clear();
  try {
    const db = getSqliteDbSafe();
    if (db && typeof db.prepare === 'function') {
      db.prepare('DELETE FROM crypto_key_versions').run();
    }
  } catch (_) {}
}

function derivePurposeKeyMaterial(baseSecret, purposeContext) {
  const cleanPurpose = String(purposeContext || 'default-purpose-v1').trim();
  if (typeof crypto.hkdfSync === 'function') {
    const derived = crypto.hkdfSync(
      'sha256',
      Buffer.from(String(baseSecret), 'utf8'),
      Buffer.from('ejii-sovereign-hkdf-salt-v1', 'utf8'),
      Buffer.from(`ejii-purpose:${cleanPurpose}`, 'utf8'),
      32
    );
    return Buffer.from(derived).toString('hex');
  }
  return crypto
    .createHmac('sha256', `ejii-hkdf-fallback:${cleanPurpose}`)
    .update(String(baseSecret))
    .digest('hex');
}

function getPurposeKeyRing(purposeContext = 'default-purpose-v1', options = {}) {
  const cleanPurpose = String(purposeContext || 'default-purpose-v1').trim();
  const envKeyName = PURPOSE_ENV_MAP[cleanPurpose];
  const envOverride = envKeyName ? process.env[envKeyName] : null;
  const now = Date.now();

  if (envOverride && !isInsecureOrWeakSecret(envOverride, 16)) {
    const keyId = `kid-${cleanPurpose}-${crypto.createHash('sha256').update(envOverride).digest('hex').slice(0, 8)}`;
    const isRevoked = isPurposeKeyRevokedOrExpiredInDb(cleanPurpose, keyId, options.db);
    return {
      purpose: cleanPurpose,
      activeKeyId: isRevoked ? null : keyId,
      activeSecret: isRevoked ? null : envOverride.trim(),
      configured: !isRevoked,
      reason: isRevoked ? 'KEY_REVOKED_OR_EXPIRED' : 'ENV_OVERRIDE_ACTIVE',
      previousKeys: (purposeKeyRings.get(cleanPurpose)?.previousKeys || []).filter(
        (k) => k.expiresAtMs > now && !isPurposeKeyRevokedOrExpiredInDb(cleanPurpose, k.keyId, options.db)
      )
    };
  }

  // If global EJII_HMAC_SECRET was explicitly overridden in process.env (e.g. in tests), respect it if valid
  const rawGlobalEnv = process.env.EJII_HMAC_SECRET;
  if (rawGlobalEnv && isInsecureOrWeakSecret(rawGlobalEnv, 16) && !isTemplateEnvPlaceholder(rawGlobalEnv)) {
    return {
      purpose: cleanPurpose,
      activeKeyId: null,
      activeSecret: null,
      configured: false,
      reason: 'REJECTED_INSECURE_OR_WEAK_SECRET',
      previousKeys: []
    };
  }

  const existingRing = purposeKeyRings.get(cleanPurpose);
  if (existingRing && existingRing.activeSecret && !existingRing.derivedFromEnv) {
    existingRing.previousKeys = existingRing.previousKeys.filter(
      (k) => k.expiresAtMs > now && !isPurposeKeyRevokedOrExpiredInDb(cleanPurpose, k.keyId, options.db)
    );
    if (isPurposeKeyRevokedOrExpiredInDb(cleanPurpose, existingRing.activeKeyId, options.db)) {
      return {
        purpose: cleanPurpose,
        activeKeyId: null,
        activeSecret: null,
        configured: false,
        reason: 'ACTIVE_KEY_REVOKED',
        previousKeys: existingRing.previousKeys
      };
    }
    return existingRing;
  }

  const baseMaterial = (!isInsecureOrWeakSecret(rawGlobalEnv, 16)) ? rawGlobalEnv.trim() : HMAC_SECRET;
  const derivedSecret = derivePurposeKeyMaterial(baseMaterial, cleanPurpose);
  const keyId = `kid-${cleanPurpose}-${derivedSecret.slice(0, 8)}`;
  if (isPurposeKeyRevokedOrExpiredInDb(cleanPurpose, keyId, options.db)) {
    return {
      purpose: cleanPurpose,
      activeKeyId: null,
      activeSecret: null,
      configured: false,
      reason: 'DERIVED_KEY_REVOKED_OR_EXPIRED',
      previousKeys: existingRing
        ? existingRing.previousKeys.filter(
            (k) => k.expiresAtMs > now && !isPurposeKeyRevokedOrExpiredInDb(cleanPurpose, k.keyId, options.db)
          )
        : []
    };
  }
  const ring = {
    purpose: cleanPurpose,
    activeKeyId: keyId,
    activeSecret: derivedSecret,
    configured: true,
    derivedFromEnv: true,
    previousKeys: existingRing
      ? existingRing.previousKeys.filter(
          (k) => k.expiresAtMs > now && !isPurposeKeyRevokedOrExpiredInDb(cleanPurpose, k.keyId, options.db)
        )
      : []
  };
  purposeKeyRings.set(cleanPurpose, ring);
  return ring;
}

function getPurposeSeparatedSecret(purposeContext = 'default-purpose-v1') {
  const ring = getPurposeKeyRing(purposeContext);
  return ring.activeSecret;
}

function rotatePurposeKey(purposeContext, newSecretMaterial, options = {}) {
  const cleanPurpose = String(purposeContext || 'default-purpose-v1').trim();
  if (isInsecureOrWeakSecret(newSecretMaterial, 16)) {
    const err = new Error(`Refusing to rotate key for purpose "${cleanPurpose}": secret is weak (<16 chars) or on the known-insecure blocklist.`);
    err.code = 'WEAK_OR_INSECURE_SECRET_REJECTED';
    throw err;
  }
  const now = Date.now();
  const gracePeriodMs = Math.max(50, Number(options.gracePeriodMs) || 3600_000);
  const currentRing = getPurposeKeyRing(cleanPurpose, { db: options.db });
  const previousKeys = [...(currentRing.previousKeys || [])].filter(
    (k) => k.expiresAtMs > now && !isPurposeKeyRevokedOrExpiredInDb(cleanPurpose, k.keyId, options.db)
  );
  if (currentRing.activeSecret && currentRing.activeKeyId) {
    const expiresAtMs = now + gracePeriodMs;
    previousKeys.unshift({
      keyId: currentRing.activeKeyId,
      secret: currentRing.activeSecret,
      rotatedAtMs: now,
      expiresAtMs
    });
    persistKeyVersionState(cleanPurpose, currentRing.activeKeyId, currentRing.activeSecret, 'RETIRING_GRACE', {
      db: options.db,
      rotatedAtMs: now,
      expiresAtMs
    });
  }
  const derivedOrDirect = options.deriveWithHkdf === true
    ? derivePurposeKeyMaterial(newSecretMaterial.trim(), cleanPurpose)
    : newSecretMaterial.trim();
  const newKeyId = options.keyId || `kid-${cleanPurpose}-${crypto.createHash('sha256').update(derivedOrDirect).digest('hex').slice(0, 8)}`;

  if (isPurposeKeyRevokedOrExpiredInDb(cleanPurpose, newKeyId, options.db)) {
    const err = new Error(`Refusing to rotate key for purpose "${cleanPurpose}": keyId "${newKeyId}" was previously revoked or retired.`);
    err.code = 'REVOKED_KEY_REUSE_BLOCKED';
    throw err;
  }

  const updatedRing = {
    purpose: cleanPurpose,
    activeKeyId: newKeyId,
    activeSecret: derivedOrDirect,
    configured: true,
    derivedFromEnv: false,
    rotatedAt: new Date(now).toISOString(),
    previousKeys: previousKeys.slice(0, 5)
  };
  purposeKeyRings.set(cleanPurpose, updatedRing);
  persistKeyVersionState(cleanPurpose, newKeyId, derivedOrDirect, 'ACTIVE', {
    db: options.db,
    createdAtMs: now
  });

  return {
    purpose: cleanPurpose,
    activeKeyId: updatedRing.activeKeyId,
    previousKeysRetainedCount: updatedRing.previousKeys.length,
    gracePeriodMs,
    rotatedAt: updatedRing.rotatedAt
  };
}

function revokePurposeKey(purposeContext, keyIdToRevoke, reason = 'Operator key revocation', options = {}) {
  const cleanPurpose = String(purposeContext || 'default-purpose-v1').trim();
  const cleanKeyId = String(keyIdToRevoke || '').trim();
  if (!cleanKeyId) {
    throw new Error('keyIdToRevoke is required.');
  }
  if (!options.db) {
    if (!revokedPurposeKeyIds.has(cleanPurpose)) {
      revokedPurposeKeyIds.set(cleanPurpose, new Set());
    }
    revokedPurposeKeyIds.get(cleanPurpose).add(cleanKeyId);

    const ring = purposeKeyRings.get(cleanPurpose);
    if (ring) {
      ring.previousKeys = (ring.previousKeys || []).filter((k) => k.keyId !== cleanKeyId);
      if (ring.activeKeyId === cleanKeyId) {
        ring.activeSecret = null;
        ring.activeKeyId = null;
        ring.configured = false;
      }
    }
  }

  persistKeyVersionState(cleanPurpose, cleanKeyId, cleanKeyId, 'REVOKED', {
    db: options.db,
    revokedAtMs: Date.now(),
    revocationReason: reason
  });

  return {
    revoked: true,
    purpose: cleanPurpose,
    keyId: cleanKeyId,
    reason,
    revokedAt: new Date().toISOString()
  };
}

function verifyPurposeHmac(purposeContext, canonicalPayload, signatureHex, options = {}) {
  if (!signatureHex || typeof signatureHex !== 'string') {
    return { valid: false, matchedKeyId: null, reason: 'MISSING_SIGNATURE' };
  }
  const cleanPurpose = String(purposeContext || 'default-purpose-v1').trim();
  if (options.requiredKeyId && isPurposeKeyRevokedOrExpiredInDb(cleanPurpose, options.requiredKeyId, options.db)) {
    return { valid: false, matchedKeyId: null, reason: 'KEY_ID_REVOKED_OR_EXPIRED' };
  }

  const ring = getPurposeKeyRing(cleanPurpose, { db: options.db });
  const candidates = [];
  if (ring.activeSecret && ring.activeKeyId) {
    candidates.push({ keyId: ring.activeKeyId, secret: ring.activeSecret });
  }
  for (const prev of ring.previousKeys || []) {
    if (prev && prev.secret && prev.expiresAtMs > Date.now()) {
      candidates.push({ keyId: prev.keyId, secret: prev.secret });
    }
  }

  const sigBuf = Buffer.from(signatureHex, 'utf8');
  for (const c of candidates) {
    if (isPurposeKeyRevokedOrExpiredInDb(cleanPurpose, c.keyId, options.db)) continue;
    const expected = crypto.createHmac('sha256', c.secret).update(String(canonicalPayload)).digest('hex');
    const expBuf = Buffer.from(expected, 'utf8');
    if (sigBuf.length === expBuf.length && crypto.timingSafeEqual(sigBuf, expBuf)) {
      return { valid: true, matchedKeyId: c.keyId, reason: 'VERIFIED' };
    }
  }
  return { valid: false, matchedKeyId: null, reason: 'SIGNATURE_MISMATCH_OR_EXPIRED' };
}

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
  isInsecureOrWeakSecret,
  validateSecurityConfiguration,
  derivePurposeKeyMaterial,
  getPurposeKeyRing,
  getPurposeSeparatedSecret,
  rotatePurposeKey,
  revokePurposeKey,
  isPurposeKeyRevokedOrExpiredInDb,
  _resetCryptoStateForTests,
  verifyPurposeHmac,
  PROTECTED_SYSTEM_PROCESSES,
  AUTOMATION_TIERS,
  IS_EVALUATION_MODE,
  IS_WINDOWS: os.platform() === 'win32',
  IS_LINUX: os.platform() === 'linux',
  PLATFORM: os.platform()
};

