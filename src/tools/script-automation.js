/**
 * EJII Local PC Automation Engine
 * Real Execution Bridge for Batch & PowerShell Automation Scripts @ e:\Scripts
 * 100% Real OS Execution — Zero Simulated Data.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { exec, spawn } = require('child_process');
const { performance } = require('perf_hooks');
const { DATA_DIR } = require('../config');

const DEFAULT_SCRIPTS_DIR = process.env.EJII_SCRIPTS_DIR || 'e:\\Scripts';

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
  const targetPath = path.resolve(baseDir, scriptName);

  // Guarantee that the resolved target path is strictly inside baseDir
  if (!targetPath.startsWith(baseDir)) {
    const err = new Error('Access denied: Script path escapes base directory.');
    err.code = 'TRAVERSAL_ATTEMPT';
    throw err;
  }

  return targetPath;
}

/**
 * List all automation scripts from active scripts mount
 * Returns an Array of scripts decorated with thenable resolution for both sync & async callers.
 */
function listAutomationScripts(scriptsDir = DEFAULT_SCRIPTS_DIR) {
  const baseDir = ensureScriptsDir(scriptsDir);

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

      let liveGateway = '192.168.31.1';
      try {
        const netInfo = require('../network/routing/physical-network-detector').getPhysicalNetworkInfo();
        liveGateway = netInfo.gatewayIp || '192.168.31.1';
      } catch (_) {}

      if (preview.includes('10.168.195.1')) {
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

  return scripts;
}

/**
 * View script raw content
 */
async function getScriptContent(scriptName, scriptsDir = DEFAULT_SCRIPTS_DIR) {
  const fullPath = resolveScriptPath(scriptName, scriptsDir);

  if (!fs.existsSync(fullPath)) {
    const err = new Error(`Script "${scriptName}" not found.`);
    err.code = 'ENOENT';
    throw err;
  }

  let content = await fs.promises.readFile(fullPath, 'utf8');
  const netInfo = require('../network/routing/physical-network-detector').getPhysicalNetworkInfo();
  const liveGateway = netInfo.gatewayIp || '192.168.31.1';
  if (content.includes('10.168.195.1')) {
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
    content
  };
}

/**
 * Execute automation script via PowerShell or CMD
 */
async function executeScript(scriptName, params = '', scriptsDir = DEFAULT_SCRIPTS_DIR) {
  const fullPath = resolveScriptPath(scriptName, scriptsDir);

  if (!fs.existsSync(fullPath)) {
    const err = new Error(`Script "${scriptName}" not found.`);
    err.code = 'ENOENT';
    throw err;
  }

  let content = await fs.promises.readFile(fullPath, 'utf8');
  const netInfo = require('../network/routing/physical-network-detector').getPhysicalNetworkInfo();
  const liveGateway = netInfo.gatewayIp || '192.168.31.1';
  if (content.includes('10.168.195.1')) {
    content = content.replace(/10\.168\.195\.1/g, liveGateway);
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

    if (executionType === 'powershell') {
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
      const record = {
        executionId: 'EXEC-' + Date.now() + '-' + Math.floor(Math.random() * 1000),
        scriptName,
        timestamp: new Date().toISOString(),
        exitCode,
        durationMs,
        success,
        executionType,
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        elevationAdvisory
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
  detectScriptType,
  cleanScriptTitle,
  resolveScriptPath,
  listAutomationScripts,
  getScriptContent,
  executeScript,
  getExecutionHistory,
  scriptAutomation
};
