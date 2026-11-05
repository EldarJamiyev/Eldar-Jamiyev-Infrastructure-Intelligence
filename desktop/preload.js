/**
 * EJI Desktop Preload Script
 * Secure IPC Context Bridge (Context Isolation Enforced)
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('ejiDesktop', {
  platform: process.platform,
  version: '1.0.0',
  isDesktop: true,
  sendNotification: (title, body) => {
    ipcRenderer.send('desktop-notify', { title, body });
  },
  onServerStatus: (callback) => {
    ipcRenderer.on('server-status', (event, data) => callback(data));
  }
});
