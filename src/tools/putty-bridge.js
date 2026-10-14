/**
 * EJII PuTTY & Native Terminal Protocol Bridge
 * Spawns native system tools (mstsc, putty, powershell, ssh) with strict input validation.
 * 100% Genuine OS Bridge — Zero Simulated Data.
 */

const { spawn } = require('child_process');
const { IS_WINDOWS } = require('../config');

/**
 * Launch an authorized local administrative desktop tool
 * @param {string} tool ('rdp', 'ssh', 'powershell')
 * @param {string} targetHost 
 */
function launchNativeTool(tool, targetHost = 'localhost') {
  if (!IS_WINDOWS) {
    return { success: false, error: 'Native desktop tool launching is only supported on Windows.' };
  }

  const cleanTarget = targetHost.trim().replace(/[^a-zA-Z0-9.-]/g, '');

  let processName = '';
  let args = [];

  switch (tool.toLowerCase()) {
    case 'rdp':
    case 'mstsc':
      processName = 'mstsc.exe';
      args = [`/v:${cleanTarget}`];
      break;

    case 'ssh':
      processName = 'cmd.exe';
      args = ['/c', 'start', 'ssh', cleanTarget];
      break;

    case 'powershell':
      processName = 'cmd.exe';
      args = ['/c', 'start', 'powershell.exe', '-NoExit'];
      break;

    case 'putty':
      processName = 'putty.exe';
      args = [cleanTarget];
      break;

    default:
      return { success: false, error: `Unauthorized or unknown tool: [${tool}]` };
  }

  try {
    const child = spawn(processName, args, { detached: true, stdio: 'ignore' });
    child.unref();

    return {
      success: true,
      launchedTool: tool,
      target: cleanTarget,
      message: `Launched ${processName} for target ${cleanTarget}.`
    };
  } catch (err) {
    return {
      success: false,
      error: `Failed to launch ${processName}: ${err.message}`
    };
  }
}

module.exports = {
  launchNativeTool
};
