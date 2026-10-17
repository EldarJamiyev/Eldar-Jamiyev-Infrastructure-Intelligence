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

const DEFAULT_SCRIPTS_DIR = process.env.EJII_SCRIPTS_DIR || 'e:\\Scripts';

/**
 * Categorize a script based on filename and content
 */
function categorizeScript(filename, content = '') {
  const fLower = filename.toLowerCase();
  const cLower = content.toLowerCase();

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
      color: '#EF4444'
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
      color: '#38BDF8'
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
      color: '#10B981'
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
      color: '#F59E0B'
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
      color: '#8B5CF6'
    };
  }

  // 6. Performance & Process Triage (Default)
  return {
    category: 'Performance & Process Triage',
    badge: '⚡ Performance & Process Triage',
    icon: '⚡',
    color: '#EC4899'
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

function ensureScriptsDir(scriptsDir = DEFAULT_SCRIPTS_DIR) {
  const baseDir = path.resolve(scriptsDir);
  if (fs.existsSync(baseDir)) return baseDir;

  if (process.platform === 'win32' && baseDir.toLowerCase().startsWith('e:\\')) {
    const localMount = path.resolve(__dirname, '../../data/scripts_mount');
    if (fs.existsSync(localMount)) {
      try {
        require('child_process').execSync(`subst E: "${localMount}"`, { stdio: 'ignore' });
      } catch (e) {}
    }
  }
  return baseDir;
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
 * List all automation scripts from e:\Scripts
 */
async function listAutomationScripts(scriptsDir = DEFAULT_SCRIPTS_DIR) {
  const baseDir = ensureScriptsDir(scriptsDir);

  if (!fs.existsSync(baseDir)) {
    return {
      directory: baseDir,
      exists: false,
      count: 0,
      scripts: [],
      error: `Directory "${baseDir}" does not exist on this machine.`
    };
  }

  const files = await fs.promises.readdir(baseDir);
  const scripts = [];

  for (const file of files) {
    const ext = path.extname(file).toLowerCase();
    if (!['.bat', '.cmd', '.ps1', '.txt'].includes(ext)) {
      continue;
    }

    try {
      const fullPath = path.join(baseDir, file);
      const stat = await fs.promises.stat(fullPath);
      if (!stat.isFile()) continue;

      let preview = '';
      try {
        const fileContent = await fs.promises.readFile(fullPath, 'utf8');
        preview = fileContent;
      } catch (e) {}

      const catInfo = categorizeScript(file, preview);
      const executionType = detectScriptType(file, preview);
      const title = cleanScriptTitle(file);

      // Generate description from first meaningful operational command line
      let desc = '';
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

      scripts.push({
        id: Buffer.from(file).toString('base64url'),
        filename: file,
        title,
        description: desc || `Execute ${title} on host machine`,
        category: catInfo.category,
        categoryBadge: catInfo.badge,
        categoryColor: catInfo.color,
        categoryIcon: catInfo.icon,
        executionType,
        sizeBytes: stat.size,
        lastModified: stat.mtime.toISOString(),
        fullPath
      });
    } catch (err) {}
  }

  // Sort alphabetically by title
  scripts.sort((a, b) => a.title.localeCompare(b.title));

  return {
    directory: baseDir,
    exists: true,
    count: scripts.length,
    scripts
  };
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

  const content = await fs.promises.readFile(fullPath, 'utf8');
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

  const content = await fs.promises.readFile(fullPath, 'utf8');
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

    if (executionType === 'powershell') {
      // Execute via PowerShell with UTF-8 encoding and ExecutionPolicy Bypass
      const psCommand = `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; & { ${content} }`;
      child = spawn('powershell.exe', [
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy', 'Bypass',
        '-Command', psCommand
      ], {
        cwd: scriptsDir,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true
      });
    } else {
      // Execute Batch: write to temporary .bat, closing stdin and bypassing blocking 'pause'
      tempBatPath = path.join(os.tmpdir(), `ejii-run-${Date.now()}-${Math.floor(Math.random() * 1000)}.bat`);
      const sanitizedBatch = content.replace(/^[ \t]*pause[ \t]*$/gmi, 'rem [EJII: non-interactive pause bypassed]');
      fs.writeFileSync(tempBatPath, `@echo off\r\n${sanitizedBatch}\r\n`, 'utf8');

      child = spawn('cmd.exe', ['/c', tempBatPath], {
        cwd: scriptsDir,
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
      cleanupAndResolve({
        success: code === 0,
        exitCode: code !== null ? code : 0,
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        durationMs,
        executionType,
        scriptName
      });
    });
  });
}

module.exports = {
  DEFAULT_SCRIPTS_DIR,
  categorizeScript,
  detectScriptType,
  cleanScriptTitle,
  resolveScriptPath,
  listAutomationScripts,
  getScriptContent,
  executeScript
};
