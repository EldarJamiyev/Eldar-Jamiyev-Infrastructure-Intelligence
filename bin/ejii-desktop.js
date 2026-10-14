/**
 * EJII Desktop Application Launcher
 * Boots the server and launches the default desktop browser in app mode.
 */

const { exec, spawn } = require('child_process');
const path = require('path');
const { PORT } = require('../src/config');

console.log('Starting EJII Enterprise Intelligence Platform Desktop Application...');

// Start the server process
const serverPath = path.join(__dirname, '..', 'src', 'server.js');
const serverProc = spawn('node', [serverPath], {
  stdio: 'inherit',
  detached: false
});

const url = `http://localhost:${PORT}`;

// Wait 1.5s for server to bind port, then open application window
setTimeout(() => {
  console.log(`Opening EJII Enterprise Dashboard: ${url}`);
  const startCmd = process.platform === 'win32'
    ? `start "" "${url}"`
    : process.platform === 'darwin'
      ? `open "${url}"`
      : `xdg-open "${url}"`;

  exec(startCmd, (err) => {
    if (err) {
      console.log(`Open your browser and navigate to: ${url}`);
    }
  });
}, 1500);

process.on('SIGINT', () => {
  serverProc.kill();
  process.exit(0);
});
