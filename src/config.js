/**
 * EJII — Eldar Jamiyev's Infrastructure Intelligence
 * Configuration Module
 */

const path = require('path');
const os = require('os');
const fs = require('fs');

const PORT = parseInt(process.env.EJII_PORT || '8443', 10);
// Secure default: Bind strictly to loopback 127.0.0.1 to avoid exposing unprivileged NOC workstation on public networks
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

const DEFAULT_HMAC_SECRET = 'EJII-ENTERPRISE-INTELLIGENCE-HMAC-SECURE-KEY-2026';
const DEFAULT_JWT_SECRET = 'EJII-ENTERPRISE-TOKEN-KEY-98471298471928471';

function validateSecurityConfiguration() {
  const isProduction = process.env.NODE_ENV === 'production';
  const hmac = process.env.EJII_HMAC_SECRET;
  const jwt = process.env.EJII_JWT_SECRET;

  if (isProduction) {
    if (!hmac || hmac === DEFAULT_HMAC_SECRET || hmac.length < 32) {
      throw new Error('FATAL CONFIGURATION ERROR: In production mode (NODE_ENV=production), EJII_HMAC_SECRET must be explicitly configured with at least 32 characters. Refusing to boot with missing or insecure default secret.');
    }
    if (!jwt || jwt === DEFAULT_JWT_SECRET || jwt.length < 32) {
      throw new Error('FATAL CONFIGURATION ERROR: In production mode (NODE_ENV=production), EJII_JWT_SECRET must be explicitly configured with at least 32 characters. Refusing to boot with missing or insecure default secret.');
    }
  }
}

validateSecurityConfiguration();

const HMAC_SECRET = process.env.EJII_HMAC_SECRET || DEFAULT_HMAC_SECRET;
const JWT_SECRET = process.env.EJII_JWT_SECRET || DEFAULT_JWT_SECRET;

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
  'node.exe' // Prevent EJII from killing itself
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

const IS_EVALUATION_MODE = process.env.EJII_EVALUATION_MODE === 'true' || (process.env.NODE_ENV !== 'production' && process.env.EJII_EVALUATION_MODE !== 'false');

module.exports = {
  PORT,
  HOST,
  DATA_DIR,
  DB_PATH,
  HMAC_SECRET,
  JWT_SECRET,
  PROTECTED_SYSTEM_PROCESSES,
  AUTOMATION_TIERS,
  IS_EVALUATION_MODE,
  IS_WINDOWS: os.platform() === 'win32',
  IS_LINUX: os.platform() === 'linux',
  PLATFORM: os.platform(),
  validateSecurityConfiguration,
  DEFAULT_HMAC_SECRET,
  DEFAULT_JWT_SECRET
};
