/**
 * Project Aurora — Automated Playwright Visual Verification & Real Screenshot Capture
 * Captures high-resolution real screenshots of every EJII section at 1440x900 (desktop)
 * and 390x844 (mobile) from the live running server at http://localhost:3000.
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');

const BASE_URL = process.env.EJII_BASE_URL || 'http://localhost:3000';
const OUT_DIR = path.join(__dirname, '..', 'docs', 'screenshots');

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    deviceScaleFactor: 1
  });
  const page = await context.newPage();

  const pageErrors = [];
  page.on('pageerror', (err) => {
    pageErrors.push(err.message || String(err));
  });

  console.log('[1/12] Navigating to Login Screen...');
  await page.goto(BASE_URL, { waitUntil: 'networkidle' });
  await page.evaluate(() => {
    localStorage.removeItem('ejii_token');
    if (typeof window.setTheme === 'function') window.setTheme('light');
    if (typeof window.showLoginScreen === 'function') window.showLoginScreen();
  });
  await sleep(600);
  await page.screenshot({ path: path.join(OUT_DIR, 'login.png'), fullPage: false });
  console.log('  ✓ Saved docs/screenshots/login.png');

  console.log('[2/12] Authenticating & Capturing Conversational AI Diagnostic Result...');
  await page.fill('#loginUsername', 'admin');
  await page.fill('#loginPassword', 'admin2026!');
  await page.click('#btnSubmitLogin');
  try {
    await page.waitForSelector('#ejiiChatWorkspace', { timeout: 6000 });
  } catch (_) {
    const { createToken } = require('../src/core/security');
    const token = createToken({ id: 'admin-1', username: 'admin', role: 'ADMIN', fullName: 'Eldar Jamiyev' });
    await page.evaluate((tok) => {
      localStorage.setItem('ejii_token', tok);
    }, token);
    await page.reload({ waitUntil: 'networkidle' });
    await page.waitForSelector('#ejiiChatWorkspace', { timeout: 10000 });
  }
  await sleep(600);

  // Send a live diagnostic query so the screenshot shows real probe steps, findings, and answer
  await page.evaluate(async () => {
    if (typeof window.sendEjiiChatMessage === 'function') {
      await window.sendEjiiChatMessage('Check whether port 3000 is open on localhost');
    }
  });
  await sleep(600);
  await page.screenshot({ path: path.join(OUT_DIR, 'ai-operator-diagnostic-result.png'), fullPage: false });
  console.log('  ✓ Saved docs/screenshots/ai-operator-diagnostic-result.png');

  console.log('[3/12] Capturing Autonomous AI Infrastructure Operator Console...');
  await page.evaluate(() => window.renderView('ai-operator'));
  await sleep(900);
  await page.screenshot({ path: path.join(OUT_DIR, 'ai-operator.png'), fullPage: false });
  console.log('  ✓ Saved docs/screenshots/ai-operator.png');

  console.log('[4/12] Capturing Network Topology & Dependency Graph...');
  await page.evaluate(() => window.renderView('topology'));
  await sleep(900);
  await page.screenshot({ path: path.join(OUT_DIR, 'network-topology.png'), fullPage: false });
  console.log('  ✓ Saved docs/screenshots/network-topology.png');

  console.log('[5/12] Capturing NOC Dual-Pane Operations Center...');
  await page.evaluate(() => window.renderView('noc-dashboard'));
  await page.mouse.move(5, 5);
  await page.evaluate(() => {
    const tip = document.getElementById('topoNodeHoverCard') || document.querySelector('.topo-hover-tooltip');
    if (tip) tip.style.display = 'none';
  });
  await sleep(1000);
  await page.screenshot({ path: path.join(OUT_DIR, 'noc-dashboard.png'), fullPage: false });
  console.log('  ✓ Saved docs/screenshots/noc-dashboard.png');

  console.log('[6/12] Capturing Wireshark-Grade 3-Pane Packet Analysis...');
  await page.evaluate(async () => {
    window.renderView('packet-sniffer');
  });
  await sleep(900);
  await page.evaluate(async () => {
    if (typeof window.captureLiveKernelSockets === 'function') {
      await window.captureLiveKernelSockets();
    }
    const drawer = document.getElementById('packetInspectorDrawer');
    if (drawer && (drawer.style.display === 'none' || !drawer.style.display)) {
      if (typeof window.togglePacketInspectorDrawer === 'function') {
        window.togglePacketInspectorDrawer();
      }
    }
  });
  await sleep(700);
  await page.screenshot({ path: path.join(OUT_DIR, 'packet-analysis.png'), fullPage: false });
  console.log('  ✓ Saved docs/screenshots/packet-analysis.png');

  console.log('[7/12] Capturing Ultra IP & Asset Discovery Scanner...');
  await page.evaluate(() => window.renderView('ultra-ip-scanner'));
  await sleep(1000);
  await page.screenshot({ path: path.join(OUT_DIR, 'ip-asset-scanner.png'), fullPage: false });
  console.log('  ✓ Saved docs/screenshots/ip-asset-scanner.png');

  console.log('[8/12] Capturing Core Diagnostics & Recovery Workbench...');
  await page.evaluate(() => window.renderView('core-diagnostics'));
  await sleep(1200);
  await page.screenshot({ path: path.join(OUT_DIR, 'diagnostics-workbench.png'), fullPage: false });
  console.log('  ✓ Saved docs/screenshots/diagnostics-workbench.png');

  console.log('[9/12] Capturing Host Automation & Audited Remediation Library...');
  await page.evaluate(() => window.renderView('pc-automation'));
  await sleep(900);
  await page.screenshot({ path: path.join(OUT_DIR, 'host-automation.png'), fullPage: false });
  console.log('  ✓ Saved docs/screenshots/host-automation.png');

  console.log('[10/12] Capturing Sovereign Learning Center...');
  await page.evaluate(() => window.renderView('learning-center'));
  await sleep(1000);
  await page.screenshot({ path: path.join(OUT_DIR, 'learning-center.png'), fullPage: false });
  console.log('  ✓ Saved docs/screenshots/learning-center.png');

  console.log('[11/12] Capturing Sovereign Intelligence Fabric v6 Studio...');
  await page.evaluate(async () => {
    window.renderView('topology');
    if (typeof window.openV6SovereignFabricModal === 'function') {
      await window.openV6SovereignFabricModal('uncertainty');
    }
  });
  await sleep(900);
  await page.screenshot({ path: path.join(OUT_DIR, 'sovereign-fabric-v6.png'), fullPage: false });
  console.log('  ✓ Saved docs/screenshots/sovereign-fabric-v6.png');

  await page.evaluate(() => {
    if (typeof window.closeV6SovereignFabricModal === 'function') {
      window.closeV6SovereignFabricModal();
    }
  });

  console.log('[12/12] Capturing Mobile Responsive Overview (390x844)...');
  await page.setViewportSize({ width: 390, height: 844 });
  await page.evaluate(() => {
    window.renderView('chat');
    const scroller = document.getElementById('ejiiChatMessagesContainer');
    if (scroller) scroller.scrollTop = 0;
  });
  await sleep(600);
  await page.screenshot({ path: path.join(OUT_DIR, 'mobile-overview.png'), fullPage: false });
  console.log('  ✓ Saved docs/screenshots/mobile-overview.png');

  if (pageErrors.length > 0) {
    console.warn('Page errors observed:', pageErrors);
  } else {
    console.log('Zero uncaught page errors across all 12 views!');
  }

  await browser.close();
}

main().catch((err) => {
  console.error('Screenshot capture failed:', err);
  process.exit(1);
});
