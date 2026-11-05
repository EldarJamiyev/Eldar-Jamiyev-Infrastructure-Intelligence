/**
 * EJI Desktop Main Process (Electron Architecture)
 * Process Supervisor, Single-Instance Lock & Secure Isolated Window
 */

const { app, BrowserWindow, Tray, Menu, ipcMain } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let mainWindow = null;
let tray = null;
let serverProcess = null;
const PORT = process.env.EJII_PORT || process.env.PORT || 8443;
const SERVER_URL = `http://localhost:${PORT}`;

// Enforce single instance lock
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });

  app.whenReady().then(initDesktopApp);
}

function initDesktopApp() {
  startServerProcess();
  createWindow();
  setupTray();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
}

function startServerProcess() {
  const serverScript = path.join(__dirname, '..', 'src', 'server.js');
  console.log(`[EJI Desktop] Spawning backend supervisor: ${serverScript}`);

  serverProcess = spawn(process.execPath, [serverScript], {
    env: { ...process.env, PORT: String(PORT) },
    stdio: 'inherit'
  });

  serverProcess.on('exit', (code, sig) => {
    console.log(`[EJI Desktop] Server process exited (code=${code}, sig=${sig})`);
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1024,
    minHeight: 700,
    title: "EJI — Eldar Jamiyev's Infrastructure Intelligence",
    backgroundColor: '#0b0f19',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      preload: path.join(__dirname, 'preload.js')
    }
  });

  // Poll until backend server is ready before loading
  let attempts = 0;
  const pollServer = () => {
    attempts++;
    const req = http.get(SERVER_URL, (res) => {
      console.log(`[EJI Desktop] Server reachable on attempt ${attempts}. Loading UI.`);
      mainWindow.loadURL(SERVER_URL);
    });

    req.on('error', () => {
      if (attempts < 30) {
        setTimeout(pollServer, 300);
      } else {
        mainWindow.loadURL(`data:text/html,<h3>Failed to connect to backend server on port ${PORT}.</h3>`);
      }
    });
  };

  pollServer();

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

function setupTray() {
  // Setup tray menu for background operations
  try {
    const iconPath = path.join(__dirname, '..', 'public', 'favicon.ico');
    tray = new Tray(iconPath);
    const contextMenu = Menu.buildFromTemplate([
      { label: 'Open EJI Dashboard', click: () => mainWindow && mainWindow.show() },
      { type: 'separator' },
      { label: 'Quit Platform', click: () => app.quit() }
    ]);
    tray.setToolTip("EJI Enterprise Infrastructure Intelligence");
    tray.setContextMenu(contextMenu);
  } catch (e) {
    // Tray icon optional if ICO not on disk
  }
}

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('will-quit', () => {
  if (serverProcess) {
    console.log('[EJI Desktop] Terminating backend server process...');
    serverProcess.kill('SIGINT');
  }
});
