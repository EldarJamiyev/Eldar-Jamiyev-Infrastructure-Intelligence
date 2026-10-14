/**
 * EJI Desktop Application Launcher & Process Supervisor
 * Automatically boots backend server and launches in dedicated App Window mode
 * Supports Electron, Chromium/Edge App Mode, or System Default Browser
 */

const { exec, spawn } = require('child_process');
const path = require('path');
const http = require('http');
const fs = require('fs');

const PORT = process.env.EJII_PORT || 8443;
const SERVER_URL = `http://localhost:${PORT}`;

console.log('========================================================================');
console.log("  EJI — Eldar Jamiyev's Infrastructure Intelligence Desktop Launcher   ");
console.log('========================================================================');

// Check if electron is available
const electronPath = path.join(__dirname, '..', 'node_modules', '.bin', process.platform === 'win32' ? 'electron.cmd' : 'electron');

if (fs.existsSync(electronPath)) {
  console.log('[EJI Desktop] Electron runtime detected. Launching native Electron container...');
  const electronProc = spawn(electronPath, [path.join(__dirname, '..', 'desktop', 'main.js')], {
    stdio: 'inherit',
    env: { ...process.env, EJII_PORT: String(PORT) }
  });
  electronProc.on('exit', (code) => process.exit(code || 0));
} else {
  // Spawn backend server process
  const serverPath = path.join(__dirname, '..', 'src', 'server.js');
  console.log(`[EJI Desktop] Starting backend daemon: ${serverPath}`);

  const serverProc = spawn('node', [serverPath], {
    stdio: 'inherit',
    env: { ...process.env, PORT: String(PORT) }
  });

  // Wait for server to bind port
  let pollCount = 0;
  const maxPolls = 30;

  const checkAndLaunch = () => {
    pollCount++;
    const req = http.get(SERVER_URL, () => {
      console.log(`[EJI Desktop] Server active on port ${PORT}. Opening dedicated window...`);
      launchAppWindow(SERVER_URL);
    });

    req.on('error', () => {
      if (pollCount < maxPolls) {
        setTimeout(checkAndLaunch, 300);
      } else {
        console.error(`[EJI Desktop] Server failed to respond on port ${PORT} within 9 seconds.`);
        launchAppWindow(SERVER_URL);
      }
    });
  };

  setTimeout(checkAndLaunch, 400);

  function launchAppWindow(url) {
    let launchCmd = '';

    if (process.platform === 'win32') {
      // Look for Edge or Chrome for dedicated standalone window mode (--app)
      const edgePath = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
      const chromePath = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';

      if (fs.existsSync(edgePath)) {
        launchCmd = `"${edgePath}" --app="${url}" --window-size=1440,900 --user-data-dir="%TEMP%\\eji-edge-profile"`;
      } else if (fs.existsSync(chromePath)) {
        launchCmd = `"${chromePath}" --app="${url}" --window-size=1440,900 --user-data-dir="%TEMP%\\eji-chrome-profile"`;
      } else {
        launchCmd = `start "" "${url}"`;
      }
    } else if (process.platform === 'darwin') {
      launchCmd = `open -a "Google Chrome" --args --app="${url}" || open "${url}"`;
    } else {
      launchCmd = `google-chrome --app="${url}" || xdg-open "${url}"`;
    }

    console.log(`[EJI Desktop] Executing desktop shell: ${launchCmd}`);
    const appWindow = exec(launchCmd, (err) => {
      if (err) {
        console.warn(`[EJI Desktop] Fallback to default browser: start ${url}`);
        exec(`start "" "${url}"`);
      }
    });

    appWindow.on('exit', () => {
      console.log('[EJI Desktop] Desktop window closed. Terminating backend daemon...');
      serverProc.kill('SIGINT');
      process.exit(0);
    });
  }

  // Graceful shutdown
  const shutdown = () => {
    console.log('\n[EJI Desktop] Shutting down EJI Desktop supervisor...');
    try {
      serverProc.kill('SIGINT');
    } catch (e) {}
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
  process.on('exit', () => {
    try { serverProc.kill('SIGINT'); } catch (e) {}
  });
}
