---
name: browser-use
description: AI browser automation and stealth DOM interaction. Drives headless and headed browser workflows, interactive verification suites, and accessibility-tree parsing across web applications and operational dashboards.
license: MIT
---

# Browser Use — Autonomous Browser Automation & DOM Verification

*Browser Use* enables AI agents to interact with web interfaces, web sockets, and DOM trees with human-like fidelity. In the EJII platform, it drives automated verification of the **12 Operational Cockpit Views**, validating real-time SVG re-rendering, WebSocket backpressure, and interactive 3-pane packet dissection.

---

## 🚀 Core Capabilities

1. **Accessibility-Tree & Semantic DOM Navigation**:
   - Locates elements using ARIA roles, test IDs, and semantic paths rather than fragile CSS classes.
2. **Stealth Headless & Headed Execution**:
   - Automates Chromium/WebKit/Firefox instances without triggering anti-bot or canvas fingerprinting traps.
3. **Visual Regression & Layout Verification**:
   - Takes full-page screenshots, verifies viewport containment, and catches layout overflows.

---

## 💻 EJII Integration: Cockpit Verification Runner

In EJII, `browser-use` powers the automated end-to-end verification suites (`tests/verify-e2e-browser-workflow.js`):

```javascript
import { chromium } from 'playwright';

export async function auditCockpitViews(serverUrl = 'http://127.0.0.1:8443') {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1920, height: 1080 } });
  const page = await context.newPage();

  // 1. Authenticate with secure session token
  await page.goto(`${serverUrl}/login`);
  await page.fill('#username', 'noc');
  await page.fill('#password', 'noc2026!');
  await page.click('#btnLogin');

  // 2. Verify Wireshark-Grade 3-Pane Packet Dissector
  await page.waitForSelector('#viewPacketSniffer', { state: 'visible' });
  const packetTableRows = await page.$$eval('#packetList tbody tr', rows => rows.length);
  console.assert(packetTableRows > 0, 'Packet table must display incoming wire frames');

  // 3. Verify Hex/ASCII Synchronized Highlighting
  await page.click('#packetList tbody tr:first-child');
  await page.waitForSelector('.hex-byte.selected');

  await browser.close();
}
```
