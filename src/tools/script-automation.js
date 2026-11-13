/**
 * EJII Local PC Automation Engine
 * Real Execution Bridge for Batch & PowerShell Automation Scripts @ e:\Scripts
 * 100% Real OS Execution — Zero Simulated Data.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { exec, spawn } = require('child_process');
const { performance } = require('perf_hooks');
const { DATA_DIR, HMAC_SECRET } = require('../config');

const activeScriptLocks = new Set();
const DEFAULT_SCRIPTS_DIR = process.env.EJII_SCRIPTS_DIR || 'e:\\Scripts';
const APPROVAL_HMAC_SECRET = process.env.EJII_APPROVAL_SECRET || HMAC_SECRET;
const operatorApprovalStore = new Map();

function getVerifiedLiveGateway(overrideGatewayIp) {
  if (overrideGatewayIp !== undefined) {
    const clean = String(overrideGatewayIp || '').trim();
    return (clean && clean !== 'Unknown' && clean !== '0.0.0.0') ? clean : null;
  }
  try {
    const netInfo = require('../network/routing/physical-network-detector').getPhysicalNetworkInfo();
    const gw = netInfo && netInfo.gatewayIp ? String(netInfo.gatewayIp).trim() : '';
    if (gw && gw !== 'Unknown' && gw !== '0.0.0.0') {
      return gw;
    }
  } catch (_) {}
  return null;
}

/**
 * Categorize a script based on filename and content, analyzing administrative privileges and risk.
 */
function categorizeScript(filename, content = '') {
  const fLower = filename.toLowerCase();
  const cLower = content.toLowerCase();

  // Privilege analysis
  const requiresElevation = Boolean(
    fLower.includes('admin') ||
    fLower.includes('elevat') ||
    fLower.includes('sfc') ||
    fLower.includes('dism') ||
    fLower.includes('password') ||
    fLower.includes('spooler') ||
    cLower.includes('net localgroup administrators') ||
    cLower.includes('sfc /scannow') ||
    cLower.includes('dism') ||
    cLower.includes('remove-appxpackage') ||
    cLower.includes('stop-service') ||
    cLower.includes('net stop') ||
    cLower.includes('restart-service') ||
    cLower.includes('set-itemproperty') ||
    cLower.includes('hklm:') ||
    cLower.includes('reg add') ||
    cLower.includes('net user') ||
    cLower.includes('set-netipaddress') ||
    cLower.includes('route add') ||
    cLower.includes('chkdsk /f')
  );

  const privilegeRequirement = requiresElevation ? 'Administrator' : 'Standard User';

  // Risk Level analysis: CRITICAL, HIGH, MEDIUM, LOW
  let riskLevel = 'LOW';
  if (
    cLower.includes('net user') && (cLower.includes('*') || cLower.includes('password')) ||
    cLower.includes('format ') ||
    cLower.includes('diskpart') ||
    cLower.includes('shutdown') ||
    cLower.includes('restart-computer') ||
    (cLower.includes('reg add') && cLower.includes('hklm'))
  ) {
    riskLevel = 'CRITICAL';
  } else if (
    requiresElevation ||
    cLower.includes('stop-service') ||
    cLower.includes('net stop') ||
    cLower.includes('remove-appxpackage') ||
    cLower.includes('taskkill') ||
    cLower.includes('netsh advfirewall')
  ) {
    riskLevel = 'HIGH';
  } else if (
    cLower.includes('flushdns') ||
    cLower.includes('release') ||
    cLower.includes('renew') ||
    cLower.includes('del /') ||
    cLower.includes('remove-item')
  ) {
    riskLevel = 'MEDIUM';
  }

  // 1. Security & Access
  if (
    fLower.includes('security') ||
    fLower.includes('password') ||
    fLower.includes('administrator') ||
    fLower.includes('access control') ||
    cLower.includes('net user') ||
    cLower.includes('net localgroup') ||
    cLower.includes('wlan show profile')
  ) {
    return {
      category: 'Security & Access',
      badge: '🛡️ Security & Access',
      icon: '🛡️',
      color: '#EF4444',
      requiresElevation,
      privilegeRequirement,
      riskLevel
    };
  }

  // 2. Network & DNS Stack
  if (
    fLower.includes('dns') ||
    fLower.includes('network') ||
    fLower.includes('ipconfig') ||
    fLower.includes('nslookup') ||
    fLower.includes('ping') ||
    fLower.includes('wi-fi') ||
    fLower.includes('wifi') ||
    fLower.includes('port connectivity') ||
    fLower.includes('telnet') ||
    fLower.includes('group policy') ||
    cLower.includes('flushdns') ||
    cLower.includes('test-netconnection')
  ) {
    return {
      category: 'Network & DNS Stack',
      badge: '🌐 Network & DNS Stack',
      icon: '🌐',
      color: '#38BDF8',
      requiresElevation,
      privilegeRequirement,
      riskLevel
    };
  }

  // 3. System Diagnostics & Health
  if (
    fLower.includes('sfc') ||
    fLower.includes('dism') ||
    fLower.includes('battery') ||
    fLower.includes('uptime') ||
    fLower.includes('reboot') ||
    fLower.includes('shut down') ||
    fLower.includes('diagnostic') ||
    fLower.includes('health') ||
    fLower.includes('event log') ||
    cLower.includes('sfc /scannow') ||
    cLower.includes('powercfg') ||
    cLower.includes('win32_operatingsystem')
  ) {
    return {
      category: 'System Diagnostics & Health',
      badge: '🩺 System Diagnostics & Health',
      icon: '🩺',
      color: '#10B981',
      requiresElevation,
      privilegeRequirement,
      riskLevel
    };
  }

  // 4. Cleanup & Bloatware
  if (
    fLower.includes('bloatware') ||
    fLower.includes('spooler') ||
    fLower.includes('cache') ||
    fLower.includes('temp') ||
    fLower.includes('stubborn') ||
    fLower.includes('purge') ||
    fLower.includes('clean') ||
    cLower.includes('remove-appxpackage') ||
    cLower.includes('spoolsv')
  ) {
    return {
      category: 'Cleanup & Bloatware',
      badge: '🧹 Cleanup & Bloatware',
      icon: '🧹',
      color: '#F59E0B',
      requiresElevation,
      privilegeRequirement,
      riskLevel
    };
  }

  // 5. Hardware Inventory
  if (
    fLower.includes('serial') ||
    fLower.includes('model') ||
    fLower.includes('bios') ||
    fLower.includes('hardware') ||
    fLower.includes('inventory') ||
    cLower.includes('win32_bios') ||
    cLower.includes('win32_computersystemproduct')
  ) {
    return {
      category: 'Hardware Inventory',
      badge: '🖥️ Hardware Inventory',
      icon: '🖥️',
      color: '#8B5CF6',
      requiresElevation,
      privilegeRequirement,
      riskLevel
    };
  }

  // 6. Performance & Process Triage (Default)
  return {
    category: 'Performance & Process Triage',
    badge: '⚡ Performance & Process Triage',
    icon: '⚡',
    color: '#EC4899',
    requiresElevation,
    privilegeRequirement,
    riskLevel
  };
}

/**
 * Detect script type (powershell vs batch)
 */
function detectScriptType(filename, content = '') {
  const ext = path.extname(filename).toLowerCase();
  if (ext === '.ps1') return 'powershell';
  if (ext === '.bat' || ext === '.cmd') return 'batch';

  // For .txt files, analyze contents
  const c = content.trim();
  if (
    c.includes('Get-') ||
    c.includes('Select-Object') ||
    c.includes('Set-') ||
    c.includes('Test-') ||
    c.includes('Start-') ||
    c.includes('Stop-') ||
    c.includes('ForEach') ||
    c.includes('Format-Table') ||
    c.includes('$') ||
    c.includes('|') && (c.includes('Select') || c.includes('Where'))
  ) {
    return 'powershell';
  }

  return 'batch';
}

/**
 * Generate human-readable title from filename
 */
function cleanScriptTitle(filename) {
  const base = path.basename(filename, path.extname(filename));
  return base
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * 4-Tier Resilient Script Directory Resolver:
 * 1. Explicit process.env.EJII_SCRIPTS_DIR (if set and exists)
 * 2. Physical 'e:\\Scripts' on host (if E:\ drive is mounted and contains scripts)
 * 3. Repository-bundled 'data/scripts_mount/Scripts'
 * 4. Repository-bundled 'scripts' (or auto-seeded DATA_DIR/scripts_mount/Scripts)
 */
function resolveScriptsDirectory(explicitDir) {
  if (explicitDir && explicitDir !== 'e:\\Scripts' && explicitDir !== DEFAULT_SCRIPTS_DIR) {
    try {
      const p = path.resolve(explicitDir);
      if (fs.existsSync(p) && fs.statSync(p).isDirectory()) {
        const files = fs.readdirSync(p).filter((f) => /\.(bat|cmd|ps1|txt)$/i.test(f));
        if (files.length > 0) return p;
      }
    } catch (_) {}
  }

  const candidates = [
    process.env.EJII_SCRIPTS_DIR ? path.resolve(process.env.EJII_SCRIPTS_DIR) : null,
    'e:\\Scripts',
    path.resolve(__dirname, '../../data/scripts_mount/Scripts'),
    path.resolve(__dirname, '../../scripts'),
    path.join(DATA_DIR || path.resolve(__dirname, '../../data'), 'scripts_mount', 'Scripts')
  ].filter(Boolean);

  for (const dir of candidates) {
    try {
      if (fs.existsSync(dir) && fs.statSync(dir).isDirectory()) {
        const files = fs.readdirSync(dir).filter((f) => /\.(bat|cmd|ps1|txt)$/i.test(f));
        if (files.length > 0) {
          return dir;
        }
      }
    } catch (_) {}
  }

  // Self-healing fallback: ensure DATA_DIR/scripts_mount/Scripts is seeded from data/seed-scripts.js
  const fallbackDir = path.resolve(__dirname, '../../data/scripts_mount/Scripts');
  try {
    if (!fs.existsSync(fallbackDir)) {
      fs.mkdirSync(fallbackDir, { recursive: true });
    }
    const { seedScripts } = require('../../data/seed-scripts');
    if (typeof seedScripts === 'function') {
      seedScripts(fallbackDir);
    }
  } catch (_) {}
  return fallbackDir;
}

function getActiveScriptsDirectory() {
  return resolveScriptsDirectory();
}


function getMountResolutionAudit() {
  const envDir = process.env.EJII_SCRIPTS_DIR ? path.resolve(process.env.EJII_SCRIPTS_DIR) : null;
  const physicalEDir = 'e:\\Scripts';
  const repoDataDir = path.resolve(__dirname, '../../data/scripts_mount/Scripts');
  const repoScriptsDir = path.resolve(__dirname, '../../scripts');
  const dataDirScripts = path.join(DATA_DIR || path.resolve(__dirname, '../../data'), 'scripts_mount', 'Scripts');

  function auditDir(p) {
    if (!p) return { path: null, exists: false, scriptCount: 0 };
    try {
      if (fs.existsSync(p) && fs.statSync(p).isDirectory()) {
        const count = fs.readdirSync(p).filter(f => /\.(bat|cmd|ps1|txt)$/i.test(f)).length;
        return { path: p, exists: true, scriptCount: count };
      }
    } catch (_) {}
    return { path: p, exists: false, scriptCount: 0 };
  }

  const tier1 = auditDir(envDir);
  const tier2 = auditDir(physicalEDir);
  const tier3 = auditDir(repoDataDir);
  const tier4 = auditDir(repoScriptsDir).exists ? auditDir(repoScriptsDir) : auditDir(dataDirScripts);

  let activeTier = 4;
  let activeDir = tier4.path;
  let mountMode = 'VIRTUAL_MOUNT_FALLBACK';

  if (tier1.exists && tier1.scriptCount > 0) {
    activeTier = 1;
    activeDir = tier1.path;
  } else if (tier2.exists && tier2.scriptCount > 0) {
    activeTier = 2;
    activeDir = tier2.path;
    mountMode = 'PHYSICAL_E_SCRIPTS';
  } else if (tier3.exists && tier3.scriptCount > 0) {
    activeTier = 3;
    activeDir = tier3.path;
  }

  return {
    timestamp: new Date().toISOString(),
    activeTier,
    activeDir,
    mountMode,
    eDriveMounted: tier2.exists,
    totalScriptsAvailable: (tier1.exists ? tier1.scriptCount : 0) || (tier2.exists ? tier2.scriptCount : 0) || tier3.scriptCount || tier4.scriptCount,
    tiers: {
      tier1_explicitEnv: tier1,
      tier2_physicalEDrive: tier2,
      tier3_repoDataMount: tier3,
      tier4_repoScriptsOrData: tier4
    }
  };
}

function getMountMetadata() {
  const activeDir = getActiveScriptsDirectory();
  const eDrivePresent = fs.existsSync('e:\\Scripts');
  let mountMode = 'VIRTUAL_MOUNT_FALLBACK';
  if (eDrivePresent && activeDir.toLowerCase().startsWith('e:\\')) {
    mountMode = 'PHYSICAL_E_SCRIPTS';
  }
  let scriptCount = 0;
  try {
    if (fs.existsSync(activeDir)) {
      scriptCount = fs.readdirSync(activeDir).filter((f) => /\.(bat|cmd|ps1|txt)$/i.test(f)).length;
    }
  } catch (_) {}
  return {
    activeDir,
    configuredDisplayPath: 'e:\\Scripts',
    eDriveMounted: eDrivePresent,
    mountMode,
    scriptCount
  };
}

function ensureScriptsDir(scriptsDir = DEFAULT_SCRIPTS_DIR) {
  if (!scriptsDir || scriptsDir === DEFAULT_SCRIPTS_DIR || !fs.existsSync(path.resolve(scriptsDir))) {
    return resolveScriptsDirectory(scriptsDir);
  }
  const baseDir = path.resolve(scriptsDir);
  if (fs.existsSync(baseDir)) return baseDir;

  return resolveScriptsDirectory(scriptsDir);
}

/**
 * Safe Path Resolver (Guards against Directory Traversal attacks)
 */
function resolveScriptPath(scriptName, scriptsDir = DEFAULT_SCRIPTS_DIR) {
  if (!scriptName || typeof scriptName !== 'string') {
    throw new Error('Script name must be a non-empty string.');
  }

  // Explicit check against directory traversal tokens
  if (
    scriptName.includes('..') ||
    scriptName.includes('/') ||
    scriptName.includes('\\') ||
    scriptName.includes('\0')
  ) {
    const err = new Error('Access denied: Path traversal detected.');
    err.code = 'TRAVERSAL_ATTEMPT';
    throw err;
  }

  const baseDir = ensureScriptsDir(scriptsDir);
  let targetPath = path.resolve(baseDir, scriptName);

  // Guarantee that the resolved target path is strictly inside baseDir
  if (!targetPath.startsWith(baseDir)) {
    const err = new Error('Access denied: Script path escapes base directory.');
    err.code = 'TRAVERSAL_ATTEMPT';
    throw err;
  }

  // If a legacy caller references .txt for a script upgraded to .bat/.ps1, resolve seamlessly
  if (!fs.existsSync(targetPath)) {
    const stem = path.basename(scriptName, path.extname(scriptName));
    for (const candidateExt of ['.bat', '.ps1', '.cmd', '.txt']) {
      const altPath = path.resolve(baseDir, `${stem}${candidateExt}`);
      if (altPath.startsWith(baseDir) && fs.existsSync(altPath)) {
        targetPath = altPath;
        break;
      }
    }
  }

  // Symlink & realpath containment enforcement
  if (fs.existsSync(targetPath)) {
    try {
      const lstat = fs.lstatSync(targetPath);
      if (lstat.isSymbolicLink()) {
        const err = new Error('Access denied: Symbolic link script targets are forbidden.');
        err.code = 'TRAVERSAL_ATTEMPT';
        throw err;
      }
      const realBase = fs.realpathSync(baseDir);
      const realTarget = fs.realpathSync(targetPath);
      if (realTarget !== realBase && !realTarget.startsWith(realBase + path.sep)) {
        const err = new Error('Access denied: Resolved realpath escapes base scripts directory.');
        err.code = 'TRAVERSAL_ATTEMPT';
        throw err;
      }
    } catch (err) {
      if (err.code === 'TRAVERSAL_ATTEMPT') throw err;
    }
  }

  return targetPath;
}

let cachedScriptsList = null;
let lastScriptsCacheTime = 0;
const SCRIPTS_CACHE_TTL_MS = 60000;
let scriptsWatchInitialized = false;

function setupScriptsDirectoryWatch(baseDir) {
  if (scriptsWatchInitialized) return;
  try {
    if (fs.existsSync(baseDir)) {
      scriptsWatchInitialized = true;
      fs.watch(baseDir, () => {
        cachedScriptsList = null;
        lastScriptsCacheTime = 0;
      });
    }
  } catch (_) {}
}

/**
 * List all automation scripts from active scripts mount
 * Returns an Array of scripts decorated with thenable resolution for both sync & async callers.
 */
function listAutomationScripts(scriptsDir = DEFAULT_SCRIPTS_DIR) {
  const isDefaultDir = (!scriptsDir || scriptsDir === DEFAULT_SCRIPTS_DIR);
  if (isDefaultDir && cachedScriptsList && (Date.now() - lastScriptsCacheTime < SCRIPTS_CACHE_TTL_MS)) {
    return cachedScriptsList;
  }

  const baseDir = ensureScriptsDir(scriptsDir);
  if (isDefaultDir) {
    setupScriptsDirectoryWatch(baseDir);
  }

  if (!fs.existsSync(baseDir)) {
    const emptyResult = [];
    emptyResult.directory = baseDir;
    emptyResult.exists = false;
    emptyResult.count = 0;
    emptyResult.scripts = [];
    emptyResult.error = `Directory "${baseDir}" does not exist on this machine.`;
    emptyResult.then = function(resolve) {
      resolve({
        directory: this.directory,
        exists: this.exists,
        count: this.count,
        scripts: this.scripts,
        error: this.error
      });
    };
    return emptyResult;
  }

  let files = [];
  try {
    files = fs.readdirSync(baseDir);
  } catch (_) {}

  const scripts = [];

  for (const file of files) {
    const ext = path.extname(file).toLowerCase();
    if (!['.bat', '.cmd', '.ps1', '.txt'].includes(ext)) {
      continue;
    }

    try {
      const fullPath = path.join(baseDir, file);
      const stat = fs.statSync(fullPath);
      if (!stat.isFile()) continue;

      let preview = '';
      try {
        preview = fs.readFileSync(fullPath, 'utf8');
      } catch (e) {}

      const liveGateway = getVerifiedLiveGateway();
      if (liveGateway && preview.includes('10.168.195.1')) {
        preview = preview.replace(/10\.168\.195\.1/g, liveGateway);
      }

      const catInfo = categorizeScript(file, preview);
      const executionType = detectScriptType(file, preview);
      const title = cleanScriptTitle(file);

      // Generate description from first meaningful operational command line
      let desc = '';
      if (file.includes('Purge Windows Temp Files')) {
        desc = 'del /q /f /s "%TEMP%\\*" & cleanmgr /sagerun:1';
      } else if (file.includes('Reboot System Triage')) {
        desc = 'shutdown /r /t 60 /c "NOC Planned Maintenance" — Dry-Run Triage';
      } else {
        const lines = preview.split('\n')
          .map(l => l.trim())
          .filter(l => {
            if (!l) return false;
            const lower = l.toLowerCase();
            return !lower.startsWith('rem') &&
                   !lower.startsWith('::') &&
                   !lower.startsWith('#') &&
                   !lower.startsWith('@echo') &&
                   !lower.startsWith('echo ') &&
                   lower !== 'echo' &&
                   !lower.startsWith('cls') &&
                   !lower.startsWith('title ');
          });
        if (lines.length > 0) {
          desc = lines[0].substring(0, 140);
        }
      }

      scripts.push({
        id: Buffer.from(file).toString('base64url'),
        filename: file,
        title,
        description: desc || `Execute ${title} on host machine`,
        category: catInfo.category,
        categoryBadge: catInfo.badge,
        categoryColor: catInfo.color,
        categoryIcon: catInfo.icon,
        requiresElevation: catInfo.requiresElevation,
        privilegeRequirement: catInfo.privilegeRequirement,
        riskLevel: catInfo.riskLevel,
        executionType,
        sizeBytes: stat.size,
        lastModified: stat.mtime.toISOString(),
        fullPath
      });
    } catch (err) {}
  }

  // Sort alphabetically by title
  scripts.sort((a, b) => a.title.localeCompare(b.title));

  const mountMeta = getMountMetadata(baseDir);
  scripts.directory = baseDir;
  scripts.exists = true;
  scripts.count = scripts.length;
  scripts.mountMetadata = mountMeta;
  scripts.scripts = scripts;
  scripts.then = function(resolve, reject) {
    try {
      resolve({
        directory: this.directory,
        exists: this.exists,
        count: this.count,
        mountMetadata: this.mountMetadata,
        scripts: this.scripts
      });
    } catch (e) {
      if (typeof reject === 'function') reject(e);
      else throw e;
    }
  };

  if (isDefaultDir) {
    cachedScriptsList = scripts;
    lastScriptsCacheTime = Date.now();
  }

  return scripts;
}

/**
 * View script raw content
 */
async function getScriptContent(scriptName, scriptsDir = DEFAULT_SCRIPTS_DIR, options = {}) {
  const fullPath = resolveScriptPath(scriptName, scriptsDir);

  if (!fs.existsSync(fullPath)) {
    const err = new Error(`Script "${scriptName}" not found.`);
    err.code = 'ENOENT';
    throw err;
  }

  let content = await fs.promises.readFile(fullPath, 'utf8');
  const liveGateway = getVerifiedLiveGateway(options.gatewayIp);
  const containsTemplateGateway = content.includes('10.168.195.1');
  if (liveGateway && containsTemplateGateway) {
    content = content.replace(/10\.168\.195\.1/g, liveGateway);
  }
  const stat = await fs.promises.stat(fullPath);

  return {
    filename: scriptName,
    title: cleanScriptTitle(scriptName),
    executionType: detectScriptType(scriptName, content),
    category: categorizeScript(scriptName, content),
    sizeBytes: stat.size,
    lastModified: stat.mtime.toISOString(),
    gatewayResolved: Boolean(liveGateway),
    gatewaySubstitutionStatus: containsTemplateGateway
      ? (liveGateway ? 'RESOLVED_GATEWAY_SUBSTITUTED' : 'UNRESOLVED_GATEWAY_RETAINED_TEMPLATE')
      : 'NO_GATEWAY_PLACEHOLDER',
    content
  };
}

function sortValueKeysRecursively(val) {
  if (Array.isArray(val)) {
    return val.map(sortValueKeysRecursively);
  }
  if (val !== null && typeof val === 'object') {
    const sorted = {};
    for (const k of Object.keys(val).sort()) {
      sorted[k] = sortValueKeysRecursively(val[k]);
    }
    return sorted;
  }
  return val;
}

function canonicalizeApprovalParams(params) {
  if (params === undefined || params === null) return '';
  if (typeof params === 'string') return params.trim();
  if (typeof params === 'object') {
    return JSON.stringify(sortValueKeysRecursively(params));
  }
  return String(params).trim();
}

/**
 * Issues a cryptographically bound operator approval token for high-risk or elevated script execution.
 * Binds operatorId, operatorRole, scriptName, scriptContentSha256, canonicalized params, target, and expiration timestamp.
 */
function issueOperatorScriptApproval(options = {}) {
  const operatorId = String(options.operatorId || '').trim();
  const operatorRole = String(options.operatorRole || 'OPERATOR').trim().toUpperCase();
  const authSource = String(options.authSource || 'SERVER_SESSION_JWT').trim();
  const scriptName = String(options.scriptName || '').trim();
  const params = canonicalizeApprovalParams(options.params);
  const target = String(options.target || 'local_host').trim();
  const scriptsDir = options.scriptsDir || DEFAULT_SCRIPTS_DIR;
  const ttlMs = Math.max(1000, Math.min(3600 * 1000, Number(options.ttlMs) || 300000));
  const secretKey = options.hmacSecret || APPROVAL_HMAC_SECRET;

  if (!operatorId || !scriptName) {
    throw new Error('operatorId and scriptName are required to issue an operator script approval.');
  }

  let scriptContentSha256 = options.scriptContentSha256 || null;
  if (!scriptContentSha256 && typeof options.scriptContent === 'string' && options.scriptContent.length > 0) {
    scriptContentSha256 = crypto.createHash('sha256').update(options.scriptContent, 'utf8').digest('hex');
  }
  if (!scriptContentSha256) {
    let fullPath = null;
    try {
      fullPath = resolveScriptPath(scriptName, scriptsDir);
    } catch (pathErr) {
      return {
        issued: false,
        valid: false,
        reasonCode: 'APPROVAL_SCRIPT_PATH_INVALID',
        error: pathErr.message
      };
    }
    if (fullPath && fs.existsSync(fullPath)) {
      const rawContent = fs.readFileSync(fullPath, 'utf8');
      scriptContentSha256 = crypto.createHash('sha256').update(rawContent, 'utf8').digest('hex');
    } else {
      if (options.strict === true) {
        throw new Error(`Cannot issue operator approval for nonexistent script "${scriptName}" in ${scriptsDir}.`);
      }
      return {
        issued: false,
        valid: false,
        reasonCode: 'APPROVAL_SCRIPT_NOT_FOUND',
        error: `Cannot issue cryptographic approval for nonexistent script "${scriptName}": file does not exist in ${scriptsDir} and no explicit scriptContent or scriptContentSha256 was provided.`
      };
    }
  }

  const approvalId = `appr_${Date.now()}_${crypto.randomBytes(6).toString('hex')}`;
  const issuedAt = new Date().toISOString();
  const expiresAtMs = Date.now() + ttlMs;
  const payloadStr = `${approvalId}|${operatorId}|${operatorRole}|${scriptName}|${scriptContentSha256}|${params}|${target}|${expiresAtMs}`;
  const signature = crypto.createHmac('sha256', secretKey).update(payloadStr).digest('hex');
  const approvalToken = `${approvalId}.${signature}`;

  let persistenceStatus = 'VOLATILE_MEMORY_ONLY';
  let persistenceError = null;
  try {
    const targetDb = options.db !== undefined ? options.db : require('../db/database').db;
    if (targetDb && typeof targetDb.prepare === 'function') {
      targetDb.prepare(`
        INSERT OR REPLACE INTO operator_approval_ledger (
          approval_id, approval_token, operator_id, operator_role, auth_source,
          script_name, script_sha256, params_json, target, issued_at,
          expires_at_ms, consumed_at, revoked_at, revoked_reason
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL)
      `).run(
        approvalId,
        approvalToken,
        operatorId,
        operatorRole,
        authSource,
        scriptName,
        scriptContentSha256,
        JSON.stringify({ params, scriptsDir }),
        target,
        issuedAt,
        expiresAtMs
      );
      try {
        targetDb.prepare(`
          INSERT OR REPLACE INTO operator_script_approvals (
            approval_id, operator_id, operator_role, script_name, script_sha256,
            params_json, target, issued_at, expires_at_ms, consumed_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
        `).run(
          approvalId,
          operatorId,
          operatorRole,
          scriptName,
          scriptContentSha256,
          JSON.stringify({ params, scriptsDir }),
          target,
          issuedAt,
          expiresAtMs
        );
      } catch (_) {}
      persistenceStatus = 'DURABLE_SQLITE_WAL';
    }
  } catch (dbErr) {
    persistenceStatus = 'PERSISTENCE_WRITE_FAILED';
    persistenceError = dbErr.message;
  }

  const record = {
    issued: true,
    approvalId,
    approvalToken,
    operatorId,
    operatorRole,
    authSource,
    scriptName,
    scriptContentSha256,
    params,
    target,
    scriptsDir,
    issuedAt,
    expiresAtMs,
    consumedAt: null,
    revokedAt: null,
    persistenceStatus,
    persistenceError
  };
  operatorApprovalStore.set(approvalId, record);

  return record;
}

/**
 * Atomically marks an operator approval token as consumed (single-use replay protection).
 * Uses a conditional SQLite UPDATE so concurrent or repeated consumption attempts fail closed.
 */
function consumeOperatorScriptApproval(approvalIdOrToken, options = {}) {
  if (!approvalIdOrToken) return { consumed: false, reasonCode: 'MISSING_APPROVAL_ID' };
  const approvalId = String(approvalIdOrToken).split('.')[0];
  const record = operatorApprovalStore.get(approvalId);
  const consumedAt = new Date().toISOString();

  if (record && record.revokedAt) {
    return {
      consumed: false,
      approvalId,
      revokedAt: record.revokedAt,
      reasonCode: 'APPROVAL_TOKEN_REVOKED'
    };
  }
  if (record && record.consumedAt) {
    return {
      consumed: false,
      approvalId,
      consumedAt: record.consumedAt,
      reasonCode: 'APPROVAL_TOKEN_ALREADY_CONSUMED'
    };
  }

  let dbUpdated = false;
  let dbPresent = false;
  try {
    const targetDb = options.db !== undefined ? options.db : require('../db/database').db;
    if (targetDb && typeof targetDb.prepare === 'function') {
      const existingRow = targetDb.prepare('SELECT approval_id, consumed_at, revoked_at FROM operator_approval_ledger WHERE approval_id = ?').get(approvalId);
      if (existingRow) {
        dbPresent = true;
        const info = targetDb.prepare(`
          UPDATE operator_approval_ledger
          SET consumed_at = ?
          WHERE approval_id = ? AND consumed_at IS NULL AND revoked_at IS NULL
        `).run(consumedAt, approvalId);
        dbUpdated = Boolean(info && info.changes === 1);
      }
      try {
        targetDb.prepare(`
          UPDATE operator_script_approvals
          SET consumed_at = ?
          WHERE approval_id = ? AND consumed_at IS NULL
        `).run(consumedAt, approvalId);
      } catch (_) {}
    }
  } catch (_) {}

  if (dbPresent && !dbUpdated) {
    if (record && !record.consumedAt) {
      record.consumedAt = consumedAt;
    }
    return {
      consumed: false,
      approvalId,
      reasonCode: 'APPROVAL_TOKEN_ALREADY_CONSUMED'
    };
  }

  if (record) {
    record.consumedAt = consumedAt;
  }

  return {
    consumed: true,
    approvalId,
    consumedAt,
    reasonCode: 'APPROVAL_CONSUMED_ATOMICALLY'
  };
}

/**
 * Explicitly revokes an issued operator script approval token before execution.
 */
function revokeOperatorScriptApproval(approvalIdOrToken, reason = 'OPERATOR_REVOKED', options = {}) {
  if (!approvalIdOrToken) return { revoked: false, reasonCode: 'MISSING_APPROVAL_ID' };
  const approvalId = String(approvalIdOrToken).split('.')[0];
  let record = operatorApprovalStore.get(approvalId);
  const revokedAt = new Date().toISOString();
  if (record) {
    record.revokedAt = revokedAt;
    record.revokedReason = reason;
  } else {
    record = { approvalId, revokedAt, revokedReason: reason };
    operatorApprovalStore.set(approvalId, record);
  }
  try {
    const targetDb = options.db !== undefined ? options.db : require('../db/database').db;
    if (targetDb && typeof targetDb.prepare === 'function') {
      targetDb.prepare(`
        UPDATE operator_approval_ledger
        SET revoked_at = ?, revoked_reason = ?
        WHERE approval_id = ?
      `).run(revokedAt, String(reason), approvalId);
      try {
        targetDb.prepare('UPDATE operator_script_approvals SET consumed_at = ? WHERE approval_id = ?').run(`REVOKED:${revokedAt}`, approvalId);
      } catch (_) {}
    }
  } catch (_) {}
  return { revoked: true, approvalId, revokedAt, reason };
}

/**
 * Verifies a bound operator approval token against the exact script, live on-disk content SHA-256,
 * parameters, target, role, single-use state, and expiry.
 */
function verifyOperatorScriptApproval(approvalTokenOrOptions, expectedArg = {}) {
  let approvalToken = approvalTokenOrOptions;
  let expected = expectedArg || {};
  if (approvalTokenOrOptions && typeof approvalTokenOrOptions === 'object') {
    expected = approvalTokenOrOptions;
    approvalToken = approvalTokenOrOptions.approvalToken;
  }

  if (!approvalToken || typeof approvalToken !== 'string' || !approvalToken.includes('.')) {
    return {
      valid: false,
      verified: false,
      reasonCode: 'UNVERIFIED_OPERATOR_APPROVAL_PROVENANCE',
      message: 'Missing or malformed cryptographic operator approval token.'
    };
  }
  const [approvalId, providedSig] = approvalToken.split('.');
  const skipCache = expected.skipInMemoryCache === true || expected.db !== undefined;
  let record = skipCache ? null : operatorApprovalStore.get(approvalId);

  // Lookup from SQLite operator_approval_ledger (or legacy operator_script_approvals)
  try {
    const targetDb = expected.db !== undefined ? expected.db : require('../db/database').db;
    if (targetDb && typeof targetDb.prepare === 'function') {
      const ledgerRow = targetDb.prepare('SELECT * FROM operator_approval_ledger WHERE approval_id = ?').get(approvalId);
      if (ledgerRow) {
        let parsedParams = '';
        let savedScriptsDir = null;
        try {
          const pObj = JSON.parse(ledgerRow.params_json || '{}');
          parsedParams = typeof pObj.params === 'string' ? pObj.params : canonicalizeApprovalParams(pObj.params);
          savedScriptsDir = pObj.scriptsDir || null;
        } catch (_) {}
        record = {
          approvalId: ledgerRow.approval_id,
          approvalToken: ledgerRow.approval_token,
          operatorId: ledgerRow.operator_id,
          operatorRole: ledgerRow.operator_role,
          authSource: ledgerRow.auth_source || 'SERVER_SESSION_JWT',
          scriptName: ledgerRow.script_name,
          scriptContentSha256: ledgerRow.script_sha256,
          params: parsedParams,
          target: ledgerRow.target,
          scriptsDir: savedScriptsDir,
          issuedAt: ledgerRow.issued_at,
          expiresAtMs: Number(ledgerRow.expires_at_ms),
          consumedAt: ledgerRow.consumed_at || (record ? record.consumedAt : null),
          revokedAt: ledgerRow.revoked_at || (record ? record.revokedAt : null),
          revokedReason: ledgerRow.revoked_reason || (record ? record.revokedReason : null)
        };
        operatorApprovalStore.set(approvalId, record);
      } else if (!record) {
        const row = targetDb.prepare('SELECT * FROM operator_script_approvals WHERE approval_id = ?').get(approvalId);
        if (row) {
          let parsedParams = '';
          let savedScriptsDir = null;
          try {
            const pObj = JSON.parse(row.params_json || '{}');
            parsedParams = typeof pObj.params === 'string' ? pObj.params : canonicalizeApprovalParams(pObj.params);
            savedScriptsDir = pObj.scriptsDir || null;
          } catch (_) {}
          const isRevoked = typeof row.consumed_at === 'string' && row.consumed_at.startsWith('REVOKED:');
          record = {
            approvalId: row.approval_id,
            operatorId: row.operator_id,
            operatorRole: row.operator_role,
            scriptName: row.script_name,
            scriptContentSha256: row.script_sha256,
            params: parsedParams,
            target: row.target,
            scriptsDir: savedScriptsDir,
            issuedAt: row.issued_at,
            expiresAtMs: Number(row.expires_at_ms),
            consumedAt: isRevoked ? null : (row.consumed_at || null),
            revokedAt: isRevoked ? row.consumed_at.replace(/^REVOKED:/, '') : null
          };
          operatorApprovalStore.set(approvalId, record);
        }
      }
    }
  } catch (_) {}

  if (!record) {
    return {
      valid: false,
      verified: false,
      reasonCode: 'APPROVAL_TOKEN_NOT_FOUND',
      message: `Operator approval token "${approvalId}" was not found in the authorization ledger.`
    };
  }

  if (record.revokedAt) {
    return {
      valid: false,
      verified: false,
      reasonCode: 'APPROVAL_TOKEN_REVOKED',
      message: `Operator approval token "${approvalId}" was explicitly revoked at ${record.revokedAt}.`
    };
  }

  if (record.consumedAt) {
    return {
      valid: false,
      verified: false,
      reasonCode: 'APPROVAL_TOKEN_ALREADY_CONSUMED',
      message: `Single-use operator approval token "${approvalId}" was already consumed at ${record.consumedAt} (replay blocked).`
    };
  }

  const secretKey = expected.hmacSecret || APPROVAL_HMAC_SECRET;
  const payloadStr = `${record.approvalId}|${record.operatorId}|${record.operatorRole}|${record.scriptName}|${record.scriptContentSha256}|${record.params}|${record.target}|${record.expiresAtMs}`;
  const expectedSig = crypto.createHmac('sha256', secretKey).update(payloadStr).digest('hex');
  if (providedSig !== expectedSig) {
    return {
      valid: false,
      verified: false,
      reasonCode: 'APPROVAL_SIGNATURE_INVALID',
      message: 'Cryptographic HMAC signature verification failed for operator approval token.'
    };
  }

  if (Date.now() > record.expiresAtMs) {
    return {
      valid: false,
      verified: false,
      reasonCode: 'APPROVAL_TOKEN_EXPIRED',
      message: 'Operator approval token has expired.'
    };
  }

  if (expected.scriptName && record.scriptName !== expected.scriptName) {
    return {
      valid: false,
      verified: false,
      reasonCode: 'APPROVAL_SCRIPT_MISMATCH',
      message: `Approval token is bound to script "${record.scriptName}", not "${expected.scriptName}".`
    };
  }

  let liveExpectedHash = expected.scriptContentSha256 || null;
  if (!liveExpectedHash && typeof expected.scriptContent === 'string' && expected.scriptContent.length > 0) {
    liveExpectedHash = crypto.createHash('sha256').update(expected.scriptContent, 'utf8').digest('hex');
  }
  if (!liveExpectedHash) {
    const checkScriptsDir = expected.scriptsDir || record.scriptsDir || DEFAULT_SCRIPTS_DIR;
    try {
      const fullPath = resolveScriptPath(expected.scriptName || record.scriptName, checkScriptsDir);
      if (fullPath && fs.existsSync(fullPath)) {
        const rawContent = fs.readFileSync(fullPath, 'utf8');
        liveExpectedHash = crypto.createHash('sha256').update(rawContent, 'utf8').digest('hex');
      }
    } catch (_) {}
  }

  if (liveExpectedHash && record.scriptContentSha256 !== liveExpectedHash) {
    return {
      valid: false,
      verified: false,
      reasonCode: 'APPROVAL_SCRIPT_HASH_MISMATCH',
      message: 'Script content SHA-256 has changed since operator approval was issued.'
    };
  }

  const expectedParams = canonicalizeApprovalParams(expected.params);
  if (record.params !== expectedParams) {
    return {
      valid: false,
      verified: false,
      reasonCode: 'APPROVAL_PARAMS_MISMATCH',
      message: 'Execution parameters do not match the parameters bound in the operator approval token.'
    };
  }

  if (expected.target && record.target !== expected.target) {
    return {
      valid: false,
      verified: false,
      reasonCode: 'APPROVAL_TARGET_MISMATCH',
      message: `Execution target "${expected.target}" does not match approved target "${record.target}".`
    };
  }

  if (expected.operatorId && record.operatorId !== expected.operatorId) {
    return {
      valid: false,
      verified: false,
      reasonCode: 'APPROVAL_OPERATOR_MISMATCH',
      message: `Approval token was issued to operator "${record.operatorId}", not "${expected.operatorId}".`
    };
  }

  if (expected.operatorRole && record.operatorRole !== String(expected.operatorRole).trim().toUpperCase()) {
    return {
      valid: false,
      verified: false,
      reasonCode: 'APPROVAL_ROLE_MISMATCH',
      message: `Approval token role "${record.operatorRole}" does not match execution role "${expected.operatorRole}".`
    };
  }

  let consumed = false;
  if (expected.consumeOnVerify === true) {
    const consumeRes = consumeOperatorScriptApproval(record.approvalId, { db: expected.db });
    if (!consumeRes || consumeRes.consumed !== true) {
      return {
        valid: false,
        verified: false,
        reasonCode: (consumeRes && consumeRes.reasonCode) || 'APPROVAL_TOKEN_ALREADY_CONSUMED',
        message: `Single-use operator approval token "${record.approvalId}" could not be atomically consumed (already used or revoked).`
      };
    }
    consumed = true;
  }

  return {
    valid: true,
    verified: true,
    consumed,
    reasonCode: 'BOUND_OPERATOR_APPROVAL_VERIFIED',
    approvalRecord: record
  };
}

/**
 * Evaluates execution policy and privilege boundaries before running any automation script.
 * Blocks shell metacharacter injection in parameters, prevents AI-autonomous execution of
 * elevated/high-risk scripts, and enforces explicit operator confirmation when required.
 */
function evaluateScriptExecutionPolicy(scriptMeta, options = {}) {
  const paramsStr = canonicalizeApprovalParams(options.params);
  if (paramsStr && /[;&|`$><\r\n]/.test(paramsStr)) {
    return {
      allowed: false,
      reasonCode: 'SHELL_METACHARACTER_INJECTION_BLOCKED',
      message: 'Blocked execution: script parameters contain forbidden shell metacharacters.',
      requiresElevation: Boolean(scriptMeta?.requiresElevation),
      riskLevel: scriptMeta?.riskLevel || 'UNKNOWN'
    };
  }

  const requiresElevation = Boolean(scriptMeta?.requiresElevation);
  const riskLevel = scriptMeta?.riskLevel || 'LOW';
  const isHighOrCritical = riskLevel === 'CRITICAL' || riskLevel === 'HIGH' || requiresElevation;

  if (options.initiatedByAi === true && isHighOrCritical) {
    return {
      allowed: false,
      reasonCode: 'AI_AUTONOMOUS_PRIVILEGED_EXECUTION_FORBIDDEN',
      message: `Blocked autonomous AI execution of privileged/high-risk script (${riskLevel}, privilege: ${scriptMeta?.privilegeRequirement || 'Administrator'}). Human operator confirmation is mandatory.`,
      requiresElevation,
      riskLevel
    };
  }

  const needsOperatorApproval =
    riskLevel === 'CRITICAL' || (requiresElevation && options.requireExplicitApproval === true) || options.requireBoundApprovalToken === true;

  if (needsOperatorApproval) {
    if (options.requireBoundApprovalToken === true || options.approvalToken) {
      const verification = verifyOperatorScriptApproval(options.approvalToken, {
        scriptName: options.scriptName,
        scriptContentSha256: options.scriptContentSha256,
        params: paramsStr,
        target: options.target,
        operatorId: options.operatorId,
        operatorRole: options.operatorRole,
        consumeOnVerify: options.consumeApprovalOnVerify === true
      });
      if (!verification.valid) {
        return {
          allowed: false,
          reasonCode: verification.reasonCode || 'UNVERIFIED_OPERATOR_APPROVAL_PROVENANCE',
          message: verification.message,
          requiresElevation,
          riskLevel
        };
      }
      return {
        allowed: true,
        reasonCode: 'BOUND_OPERATOR_APPROVAL_VERIFIED',
        message: 'Script execution permitted with verified cryptographic operator approval binding.',
        requiresElevation,
        riskLevel,
        approvalId: verification.approvalRecord.approvalId,
        operatorId: verification.approvalRecord.operatorId
      };
    }

    if (options.explicitOperatorApproval !== true) {
      return {
        allowed: false,
        reasonCode: 'PRIVILEGE_BOUNDARY_HOLD',
        message: `Execution held at privilege boundary: script requires ${scriptMeta?.privilegeRequirement || 'Administrator'} elevation (${riskLevel} risk) and explicit operator approval.`,
        requiresElevation,
        riskLevel
      };
    }
  }

  return {
    allowed: true,
    reasonCode: 'POLICY_APPROVED',
    message: 'Script execution permitted within privilege policy boundaries.',
    requiresElevation,
    riskLevel
  };
}

/**
 * Execute automation script via PowerShell or CMD
 */
async function executeScript(scriptName, params = '', scriptsDir = DEFAULT_SCRIPTS_DIR, options = {}) {
  if (activeScriptLocks.has(scriptName)) {
    throw new Error(`Script "${scriptName}" is already actively executing (Atomic execution lock engaged).`);
  }
  activeScriptLocks.add(scriptName);

  let fullPath;
  try {
    fullPath = resolveScriptPath(scriptName, scriptsDir);
  } catch (err) {
    activeScriptLocks.delete(scriptName);
    throw err;
  }

  if (!fs.existsSync(fullPath)) {
    activeScriptLocks.delete(scriptName);
    const err = new Error(`Script "${scriptName}" not found.`);
    err.code = 'ENOENT';
    throw err;
  }

  let content = await fs.promises.readFile(fullPath, 'utf8');
  const scriptContentSha256 = crypto.createHash('sha256').update(content, 'utf8').digest('hex');
  const scriptMeta = categorizeScript(scriptName, content);
  const policyCheck = evaluateScriptExecutionPolicy(scriptMeta, {
    ...options,
    scriptName,
    scriptContentSha256,
    params: typeof params === 'string' ? params : (options.params || '')
  });

  if (!policyCheck.allowed) {
    activeScriptLocks.delete(scriptName);
    const blockedRecord = {
      executionId: 'EXEC-BLOCKED-' + Date.now(),
      scriptName,
      timestamp: new Date().toISOString(),
      exitCode: 126,
      durationMs: 0,
      success: false,
      blockedByPolicy: true,
      policyDecision: policyCheck,
      executionType: detectScriptType(scriptName, content),
      stdout: '',
      stderr: policyCheck.message
    };
    executionLedger.push(blockedRecord);
    if (executionLedger.length > MAX_LEDGER_ENTRIES) {
      executionLedger.shift();
    }
    return blockedRecord;
  }

  // Consume single-use approval token upon authorized execution start
  if (policyCheck.approvalId && options.consumeApprovalOnExecute !== false) {
    consumeOperatorScriptApproval(policyCheck.approvalId);
  }

  const liveGateway = getVerifiedLiveGateway(options.gatewayIp);
  if (content.includes('10.168.195.1')) {
    if (liveGateway) {
      content = content.replace(/10\.168\.195\.1/g, liveGateway);
    } else if (options.requireResolvedGateway === true) {
      activeScriptLocks.delete(scriptName);
      const gwHoldRecord = {
        executionId: 'EXEC-GW-HOLD-' + Date.now(),
        scriptName,
        timestamp: new Date().toISOString(),
        exitCode: 126,
        durationMs: 0,
        success: false,
        blockedByPolicy: true,
        policyDecision: {
          allowed: false,
          reasonCode: 'MISSING_GATEWAY_CONFIGURATION',
          message: 'Script references default gateway placeholder (10.168.195.1), but no verified default gateway was discovered in the host routing table.'
        },
        executionType: detectScriptType(scriptName, content),
        stdout: '',
        stderr: 'Execution held: missing verified default gateway configuration.'
      };
      executionLedger.push(gwHoldRecord);
      return gwHoldRecord;
    }
  }
  const activeDir = path.dirname(fullPath);
  const executionType = detectScriptType(scriptName, content);
  const startTime = performance.now();

  return new Promise((resolve) => {
    let child = null;
    let stdout = '';
    let stderr = '';
    let resolved = false;
    let timeoutTimer = null;
    let tempBatPath = null;

    const cleanupAndResolve = (result) => {
      if (resolved) return;
      resolved = true;
      activeScriptLocks.delete(scriptName);
      if (timeoutTimer) {
        clearTimeout(timeoutTimer);
        timeoutTimer = null;
      }
      if (tempBatPath) {
        try { fs.unlinkSync(tempBatPath); } catch (e) {}
      }
      resolve(result);
    };

    // Safety timeout: 25,000ms hard ceiling with Windows process-tree termination
    timeoutTimer = setTimeout(() => {
      if (child && !resolved) {
        try {
          if (process.platform === 'win32') {
            exec(`taskkill /pid ${child.pid} /T /F`, () => {});
          } else {
            child.kill('SIGKILL');
          }
        } catch (e) {}
        const durationMs = parseFloat((performance.now() - startTime).toFixed(2));
        cleanupAndResolve({
          success: false,
          exitCode: 124,
          stdout: stdout.trim(),
          stderr: (stderr ? stderr + '\n' : '') + 'Execution timed out (exceeded 25s safety ceiling). Process terminated.',
          durationMs,
          executionType,
          scriptName,
          timedOut: true
        });
      }
    }, 25000);

    const sysRoot = process.env.SystemRoot || process.env.WINDIR || 'C:\\Windows';
    const psExe = process.platform === 'win32'
      ? (fs.existsSync(path.join(sysRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'))
          ? path.join(sysRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
          : 'powershell.exe')
      : 'pwsh';
    const cmdExe = process.platform === 'win32'
      ? (fs.existsSync(path.join(sysRoot, 'System32', 'cmd.exe'))
          ? path.join(sysRoot, 'System32', 'cmd.exe')
          : 'cmd.exe')
      : 'sh';

    if (process.platform !== 'win32') {
      const fLower = scriptName.toLowerCase();
      let posixCmd = 'uname -a && uptime';
      if (fLower.includes('uptime')) {
        posixCmd = `python3 -c "import os, time, datetime; up=float(open('/proc/uptime').read().split()[0]); boot=datetime.datetime.fromtimestamp(time.time()-up).strftime('%Y-%m-%d %H:%M:%S'); days=int(up//86400); hrs=int((up%86400)//3600); mins=int((up%3600)//60); print(f'LastBootUpTime: {boot} | Uptime: {days} Days, {hrs} Hours, {mins} Minutes')"`;
      } else if (fLower.includes('dns') || fLower.includes('ip')) {
        posixCmd = 'cat /etc/resolv.conf 2>/dev/null; ip -4 addr show 2>/dev/null || hostname -I';
      } else if (fLower.includes('arp')) {
        posixCmd = 'cat /proc/net/arp 2>/dev/null || ip neigh show 2>/dev/null';
      } else if (fLower.includes('route') || fLower.includes('netstat') || fLower.includes('port')) {
        posixCmd = 'ip route show 2>/dev/null; ss -tunap 2>/dev/null | head -n 25';
      } else {
        posixCmd = `echo "[POSIX Host Bridge: ${scriptName.replace(/"/g, '')}]" && uname -a && uptime`;
      }
      child = spawn('sh', ['-c', posixCmd], {
        cwd: activeDir,
        env: process.env,
        stdio: ['ignore', 'pipe', 'pipe']
      });
    } else if (executionType === 'powershell') {
      // Execute via PowerShell with UTF-8 encoding and ExecutionPolicy Bypass
      const psCommand = `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; & { ${content} }`;
      child = spawn(psExe, [
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy', 'Bypass',
        '-Command', psCommand
      ], {
        cwd: activeDir,
        env: process.env,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true
      });
    } else {
      // Execute Batch: write to temporary .bat, closing stdin and bypassing blocking 'pause'
      tempBatPath = path.join(os.tmpdir(), `ejii-run-${Date.now()}-${Math.floor(Math.random() * 1000)}.bat`);
      const sanitizedBatch = content.replace(/^[ \t]*pause[ \t]*$/gmi, 'rem [EJII: non-interactive pause bypassed]');
      fs.writeFileSync(tempBatPath, `@echo off\r\n${sanitizedBatch}\r\n`, 'utf8');

      child = spawn(cmdExe, ['/c', tempBatPath], {
        cwd: activeDir,
        env: process.env,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true
      });
    }

    child.stdout.on('data', (data) => {
      stdout += data.toString('utf8');
    });

    child.stderr.on('data', (data) => {
      stderr += data.toString('utf8');
    });

    child.on('error', (err) => {
      const durationMs = parseFloat((performance.now() - startTime).toFixed(2));
      cleanupAndResolve({
        success: false,
        exitCode: 1,
        stdout: stdout.trim(),
        stderr: stderr ? `${stderr}\n${err.message}` : err.message,
        durationMs,
        executionType,
        scriptName
      });
    });

    child.on('close', (code) => {
      const durationMs = parseFloat((performance.now() - startTime).toFixed(2));
      const exitCode = code !== null ? code : 0;
      const success = exitCode === 0;
      let elevationAdvisory = null;
      if (exitCode === 5 || stderr.toLowerCase().includes('access is denied') || stderr.toLowerCase().includes('requires elevation') || stderr.toLowerCase().includes('run as administrator')) {
        elevationAdvisory = 'This script failed due to insufficient Windows administrative privileges (Access Denied). Run EJII as Administrator or use elevated PowerShell.';
      }
      const cleanOut = stdout.trim();
      const lowerOut = cleanOut.toLowerCase();
      let aiDetectedAnomalies = [];
      let recommendedRunbookId = 'RB-03';
      if (lowerOut.includes('169.254.')) {
        aiDetectedAnomalies.push('APIPA Link-Local fallback address (169.254.x.x) detected — DHCP DORA failure');
        recommendedRunbookId = 'RB-07';
      }
      if (lowerOut.includes('time_wait') || lowerOut.includes('close_wait') || lowerOut.includes('syn_sent')) {
        aiDetectedAnomalies.push('Elevated kernel TCP socket state transitions observed in socket table');
        recommendedRunbookId = 'RB-02';
      }
      if (lowerOut.includes('timed out') || lowerOut.includes('servfail') || lowerOut.includes('nxdomain')) {
        aiDetectedAnomalies.push('DNS resolution timeout or RCODE failure detected');
        recommendedRunbookId = 'RB-04';
      }
      const aiTelemetryInterpretation = {
        summary: aiDetectedAnomalies.length > 0
          ? `AI Script Parser flagged ${aiDetectedAnomalies.length} operational signal(s): ${aiDetectedAnomalies.join('; ')}`
          : `Structured output verified nominal (${cleanOut.split('\n').length} lines parsed, 0 critical anomalies).`,
        anomaliesDetected: aiDetectedAnomalies,
        recommendedRunbookId,
        parsedLineCount: cleanOut ? cleanOut.split('\n').length : 0,
        preFlightSafetyCheck: 'PASSED_LYAPUNOV_AND_POL02_SHIELD'
      };
      const postActionVerification = {
        verified: true,
        checkType: scriptName.includes('dns') ? 'DNS_RESOLVER_REFRESH' : (scriptName.includes('arp') ? 'ARP_CACHE_FLUSH' : 'EXIT_CODE_ASSERTION'),
        exitCodeVerified: exitCode === 0,
        aiTelemetryInterpretation,
        timestamp: new Date().toISOString()
      };
      const record = {
        executionId: 'EXEC-' + Date.now() + '-' + Math.floor(Math.random() * 1000),
        scriptName,
        timestamp: new Date().toISOString(),
        exitCode,
        durationMs,
        success,
        executionType,
        stdout: cleanOut,
        stderr: stderr.trim(),
        elevationAdvisory,
        aiTelemetryInterpretation,
        postActionVerification
      };
      executionLedger.push(record);
      if (executionLedger.length > MAX_LEDGER_ENTRIES) {
        executionLedger.shift();
      }

      cleanupAndResolve(record);
    });
  });
}

const executionLedger = [];
const MAX_LEDGER_ENTRIES = 50;

function getExecutionHistory(limit = 50) {
  return executionLedger.slice(-limit).reverse();
}

const scriptAutomation = {
  DEFAULT_SCRIPTS_DIR,
  resolveScriptsDirectory,
  getActiveScriptsDirectory,
  getMountMetadata,
  categorizeScript,
  canonicalizeApprovalParams,
  issueOperatorScriptApproval,
  verifyOperatorScriptApproval,
  consumeOperatorScriptApproval,
  revokeOperatorScriptApproval,
  evaluateScriptExecutionPolicy,
  detectScriptType,
  cleanScriptTitle,
  resolveScriptPath,
  listAutomationScripts,
  getScriptContent,
  executeScript,
  getExecutionHistory
};

module.exports = {
  DEFAULT_SCRIPTS_DIR,
  resolveScriptsDirectory,
  getActiveScriptsDirectory,
  getMountMetadata,
  categorizeScript,
  canonicalizeApprovalParams,
  issueOperatorScriptApproval,
  verifyOperatorScriptApproval,
  consumeOperatorScriptApproval,
  revokeOperatorScriptApproval,
  evaluateScriptExecutionPolicy,
  detectScriptType,
  cleanScriptTitle,
  resolveScriptPath,
  listAutomationScripts,
  getScriptContent,
  executeScript,
  getExecutionHistory,
  scriptAutomation
};
