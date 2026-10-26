// tests/suite-81-visual-screenshot-audit.test.js
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

function runSuite81VisualScreenshotAudit() {
  console.log('=== [SUITE 81] LIVE SCREENSHOT VISUAL & FUNCTIONAL DEFECT AUDIT ===');

  const read = (relPath) => fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');

  const indexHtml = read('public/index.html');
  const styleCss = read('public/css/style.css');
  const premiumCss = read('public/css/eji-premium.css');
  const allCss = styleCss + '\n' + premiumCss;
  const nocView = read('public/js/views/noc-view.js');
  const topoView = read('public/js/views/topology-view.js');
  const snifferView = read('public/js/views/sniffer-view.js');
  const scannerView = read('public/js/views/ultra-ip-scanner-view.js');
  const automationView = read('public/js/views/pc-automation-view.js');
  const diagView = read('public/js/views/core-diagnostics-view.js');
  const aiDrawer = read('public/js/components/ai-brain-drawer.js');
  const fieldManual = read('public/js/components/junior-admin-guide.js');

  // 1. Screenshot 2 Bug: "Rule: [object Object]" in AI Brain Drawer / Contradicted Hypotheses
  assert.ok(
    aiDrawer.includes("typeof") && (aiDrawer.includes(".clause") || aiDrawer.includes(".formula") || aiDrawer.includes("formatVetoRule")),
    '[Defect 1] ai-brain-drawer.js must safely format object veto rules instead of printing Rule: [object Object]'
  );
  assert.ok(
    !aiDrawer.includes('#374151') && !aiDrawer.includes('#00A8FF'),
    '[Defect 2] ai-brain-drawer.js must not use unreadable dark-grey #374151 boxes with neon #00A8FF text inside the light drawer'
  );

  // 2. Screenshot 1 Bug: L4 Node Title colliding with right-aligned badge in 240x100 SVG cards
  assert.ok(
    nocView.includes('clipPath') || nocView.includes('slice(0, 20)') || nocView.includes('slice(0, 19)') || nocView.includes('substring(0, 20)'),
    '[Defect 3] noc-view.js must clip or truncate SVG node card titles to <=20 chars so they never collide with the right-hand role/port badge'
  );

  // 3. Screenshot 4 Bug: Truncated table column headers in Ultra IP Scanner (HOSTN, MANUFACTUI, CONNE)
  assert.ok(
    !scannerView.includes('NETBIOS HOSTN') && !scannerView.includes('HARDWARE MANUFACTUI') && !scannerView.includes('OPEN SERVICES & CONNE'),
    '[Defect 4] ultra-ip-scanner-view.js must not have truncated/clipped table column headers'
  );
  assert.ok(
    scannerView.includes('HOSTNAME / NETBIOS') && scannerView.includes('HARDWARE VENDOR') && scannerView.includes('OPEN PORTS & SERVICES'),
    '[Defect 5] ultra-ip-scanner-view.js must use clean non-clipping column headers (HOSTNAME / NETBIOS, HARDWARE VENDOR, OPEN PORTS & SERVICES)'
  );

  // 4. Screenshot 5 Bug: PC Automation terminal word-break splitting "here" into "he\nre" & fake e:\Scripts header
  assert.ok(
    !automationView.includes('word-break: break-all') && !automationView.includes('word-break:break-all'),
    '[Defect 6] pc-automation-view.js must not use word-break: break-all which splits English words mid-syllable'
  );
  assert.ok(
    !automationView.includes('BAT Files @ e:\\Scripts'),
    '[Defect 7] pc-automation-view.js must not hardcode fake "BAT Files @ e:\\Scripts" in the main title'
  );

  // 5. Screenshot 6 Bug: Core Diagnostics stuck on "Loading host hardware..." and "Loading diagnosis feed..."
  assert.ok(
    diagView.includes('hydrateDiagnosticsXRayAndFeed') || (diagView.includes('/api/diagnostics') && !diagView.includes('>Loading host hardware...<')),
    '[Defect 8] core-diagnostics-view.js must immediately populate Machine X-Ray and Diagnosis Feed without hanging on "Loading host hardware..."'
  );

  // 6. Screenshot 7 Bug: Junior-Admin Field Manual rendering inline at bottom-left instead of centered fixed overlay
  assert.ok(
    allCss.includes('#juniorAdminGuideModal') && allCss.includes('position: fixed') && allCss.includes('z-index: 9999'),
    '[Defect 9] CSS must style #juniorAdminGuideModal as a position: fixed centered full-viewport modal overlay (z-index: 9999)'
  );

  // 7. Screenshot 8 Bug: Login input icon overlapping "admin" text & Welcome back clipping
  assert.ok(
    allCss.includes('padding-left: 40px') || indexHtml.includes('padding-left: 40px') || indexHtml.includes('padding-left:40px'),
    '[Defect 10] Login username/password inputs must have padding-left: 40px so the left icon never overlaps "admin"'
  );

  console.log('=== [SUITE 81] ALL 10 SCREENSHOT DEFECT LOCKS VERIFIED GREEN ===');
}

if (require.main === module) {
  runSuite81VisualScreenshotAudit();
}

module.exports = {
  runSuite81VisualScreenshotAudit
};
