/**
 * EJII — Eldar Jamiyev's Infrastructure Intelligence
 * Configuration Module
 */

const path = require('path');
const os = require('os');

const PORT = parseInt(process.env.EJII_PORT || '8443', 10);
// Secure default: Bind strictly to loopback 127.0.0.1 to avoid exposing unprivileged NOC workstation on public networks
const HOST = process.env.EJII_HOST || '127.0.0.1';
const DATA_DIR = process.env.EJII_DATA_DIR || path.join(__dirname, '..', 'data');
const DB_PATH = path.join(DATA_DIR, 'ejii.sqlite');
const HMAC_SECRET = process.env.EJII_HMAC_SECRET || 'EJII-ENTERPRISE-INTELLIGENCE-HMAC-SECURE-KEY-2026';
const JWT_SECRET = process.env.EJII_JWT_SECRET || 'EJII-ENTERPRISE-TOKEN-KEY-98471298471928471';

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

module.exports = {
  PORT,
  HOST,
  DATA_DIR,
  DB_PATH,
  HMAC_SECRET,
  JWT_SECRET,
  PROTECTED_SYSTEM_PROCESSES,
  AUTOMATION_TIERS,
  IS_WINDOWS: os.platform() === 'win32',
  IS_LINUX: os.platform() === 'linux',
  PLATFORM: os.platform()
};
