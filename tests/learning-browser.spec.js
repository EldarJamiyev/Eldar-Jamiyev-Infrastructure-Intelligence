/**
 * Sovereign Learning Center & Academy Real-Browser Screenshot & Invariant Spec
 * Uses real headless Chrome to render the Sovereign Learning Center across
 * viewports (Desktop 1440x900 and Mobile 390x844) and verifies visual rendering.
 *
 * Zero-Simulation Mandate:
 * - Real headless browser execution
 * - Real HTTP server
 * - Real rendered DOM and styles
 * - Output saved to conversation artifact directory
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { spawn } = require('node:child_process');

console.log('=== [SPEC] SOVEREIGN LEARNING CENTER REAL-BROWSER VALIDATION ===');

const ARTIFACT_DIR = path.resolve('C:/Users/eldar/.gemini/antigravity/brain/fc841c7c-48e9-482c-96c9-05a82ceeba38');
const CHROME_PATH = process.env.CHROME_BIN || 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const PORT = process.env.EJII_PORT || process.env.PORT || 8443;
const BASE_URL = `http://127.0.0.1:${PORT}`;

// 1. Verify Chrome binary exists
if (!fs.existsSync(CHROME_PATH)) {
  console.error(`Chrome binary not found at ${CHROME_PATH}`);
  process.exit(1);
}
console.log(`✓ Chrome binary detected: ${CHROME_PATH}`);

// Ensure artifact dir exists
if (!fs.existsSync(ARTIFACT_DIR)) {
  fs.mkdirSync(ARTIFACT_DIR, { recursive: true });
}

// Helper: check if server is running
function checkServerHealth(url, timeoutMs = 2000) {
  return new Promise((resolve) => {
    const req = http.get(`${url}/api/health`, { timeout: timeoutMs }, (res) => {
      resolve(res.statusCode === 200);
    });
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
  });
}

// Helper: run chrome screenshot
function captureScreenshot(url, outputPath, width = 1440, height = 900) {
  return new Promise((resolve, reject) => {
    const args = [
      '--headless=new',
      '--no-sandbox',
      '--disable-gpu',
      '--disable-software-rasterizer',
      '--disable-extensions',
      `--window-size=${width},${height}`,
      '--virtual-time-budget=3500',
      `--screenshot=${outputPath}`,
      url
    ];

    console.log(`  [Chrome] Capturing ${url} (${width}x${height}) -> ${path.basename(outputPath)}...`);
    const proc = spawn(CHROME_PATH, args, { stdio: ['ignore', 'pipe', 'pipe'] });

    let stderr = '';
    proc.stderr.on('data', (d) => { stderr += d.toString(); });

    proc.on('close', (code) => {
      if (fs.existsSync(outputPath)) {
        const stats = fs.statSync(outputPath);
        resolve({ code, size: stats.size, path: outputPath });
      } else {
        reject(new Error(`Screenshot failed to create ${outputPath}. Exit code: ${code}. Stderr: ${stderr}`));
      }
    });

    proc.on('error', reject);
  });
}

async function runBrowserSuite() {
  let serverProc = null;
  const isAlreadyRunning = await checkServerHealth(BASE_URL);

  if (isAlreadyRunning) {
    console.log(`✓ EJII server is already online and healthy at ${BASE_URL}`);
  } else {
    console.log(`Starting EJII server on port ${PORT}...`);
    serverProc = spawn(process.execPath, [path.join(__dirname, '..', 'src', 'server.js')], {
      env: { ...process.env, PORT: String(PORT), EJII_PORT: String(PORT) },
      stdio: ['ignore', 'pipe', 'pipe']
    });

    serverProc.stdout.on('data', (d) => {
      const msg = d.toString();
      if (msg.includes('listening') || msg.includes('8443')) {
        console.log(`  [Server] ${msg.trim()}`);
      }
    });

    serverProc.stderr.on('data', (d) => {
      console.error(`  [Server Error] ${d.toString().trim()}`);
    });

    // Wait up to 15 seconds for health
    let healthy = false;
    for (let i = 0; i < 30; i++) {
      await new Promise((r) => setTimeout(r, 500));
      healthy = await checkServerHealth(BASE_URL);
      if (healthy) break;
    }

    if (!healthy) {
      if (serverProc) serverProc.kill();
      throw new Error(`EJII server failed to become healthy at ${BASE_URL} within 15 seconds.`);
    }
    console.log(`✓ EJII server successfully started and healthy at ${BASE_URL}`);
  }

  try {
    // Test 1: Desktop Screenshot (1440x900) - Learning Hub
    const desktopHubPath = path.join(ARTIFACT_DIR, 'learning-hub-desktop-1440.png');
    const resDesktop = await captureScreenshot(`${BASE_URL}/#/learning`, desktopHubPath, 1440, 900);
    console.log(`  ✓ Desktop Learning Hub captured: ${resDesktop.size} bytes`);
    assert.ok(resDesktop.size > 50000, `Desktop screenshot must exceed 50KB, got ${resDesktop.size}`);

    // Test 2: Mobile Screenshot (390x844) - Learning Hub
    const mobileHubPath = path.join(ARTIFACT_DIR, 'learning-hub-mobile-390.png');
    const resMobile = await captureScreenshot(`${BASE_URL}/#/learning`, mobileHubPath, 390, 844);
    console.log(`  ✓ Mobile Learning Hub captured: ${resMobile.size} bytes`);
    assert.ok(resMobile.size > 30000, `Mobile screenshot must exceed 30KB, got ${resMobile.size}`);

    // Test 3: Desktop Screenshot (1440x900) - Network Academy Track
    const trackPath = path.join(ARTIFACT_DIR, 'learning-track-network-1440.png');
    const resTrack = await captureScreenshot(`${BASE_URL}/#/learning/track/network-academy`, trackPath, 1440, 900);
    console.log(`  ✓ Network Academy Track captured: ${resTrack.size} bytes`);
    assert.ok(resTrack.size > 50000, `Track screenshot must exceed 50KB, got ${resTrack.size}`);

    // Test 4: Desktop Screenshot (1440x900) - Subnetting Trainer Simulated Lab
    const labPath = path.join(ARTIFACT_DIR, 'learning-lab-subnetting-1440.png');
    const resLab = await captureScreenshot(`${BASE_URL}/#/learning/lab/subnetting-trainer`, labPath, 1440, 900);
    console.log(`  ✓ Subnetting Trainer Lab captured: ${resLab.size} bytes`);
    assert.ok(resLab.size > 50000, `Lab screenshot must exceed 50KB, got ${resLab.size}`);

    // Test 5: Desktop Screenshot (1440x900) - Packet Journey Simulated Lab
    const journeyLabPath = path.join(ARTIFACT_DIR, 'learning-lab-packet-journey-1440.png');
    const resJourney = await captureScreenshot(`${BASE_URL}/#/learning/lab/packet-journey`, journeyLabPath, 1440, 900);
    console.log(`  ✓ Packet Journey Lab captured: ${resJourney.size} bytes`);
    assert.ok(resJourney.size > 50000, `Packet Journey lab screenshot must exceed 50KB, got ${resJourney.size}`);

    console.log('\n===============================================================');
    console.log('  ALL 5 REAL-BROWSER SCREENSHOT VERIFICATIONS PASSED (100%)');
    console.log('  Visual artifacts saved to:');
    console.log(`  ${ARTIFACT_DIR}`);
    console.log('===============================================================');
  } finally {
    if (serverProc) {
      console.log('Cleaning up spawned test server process...');
      serverProc.kill('SIGINT');
      try {
        process.kill(serverProc.pid);
      } catch (_) {}
    }
  }
}

runBrowserSuite().catch((err) => {
  console.error('\n❌ Browser verification failed:', err);
  process.exit(1);
});
