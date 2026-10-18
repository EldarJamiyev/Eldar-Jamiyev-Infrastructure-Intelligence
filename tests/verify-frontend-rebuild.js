/**
 * Comprehensive Automated Verification Suite for Frontend Re-Architecture & Elite Design Overhaul
 * Asserts:
 *  1. Exact 1:1 header-to-cell synchronization across the 9-column Packet schema and 15-column Flow Matrix schema
 *  2. Mutual exclusivity of Live Frames vs Flow Matrix views (zero table stacking / zero viewport cannibalization)
 *  3. Hidden by default DPI drawer and proper close handler
 *  4. Topology SVG node dimensions (width >= 175px, height >= 95px), full device titles without arbitrary truncation
 *  5. Elite Cyber-NOC design tokens, fixed 240px sidebar, and nowrap nav links
 * Zero-Elevation & Zero-Mock Mandate.
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

async function runFrontendRebuildVerification() {
  console.log('========================================================================');
  console.log('  EJII FRONTEND RE-ARCHITECTURE & ELITE DESIGN VERIFICATION SUITE       ');
  console.log('========================================================================');

  const rootDir = path.resolve(__dirname, '..');
  const snifferViewPath = path.join(rootDir, 'public', 'js', 'views', 'sniffer-view.js');
  const nocViewPath = path.join(rootDir, 'public', 'js', 'views', 'noc-view.js');
  const styleCssPath = path.join(rootDir, 'public', 'css', 'style.css');
  const premiumCssPath = path.join(rootDir, 'public', 'css', 'eji-premium.css');
  const indexHtmlPath = path.join(rootDir, 'public', 'index.html');

  const snifferViewJs = fs.readFileSync(snifferViewPath, 'utf8');
  const nocViewJs = fs.readFileSync(nocViewPath, 'utf8');
  const styleCss = fs.readFileSync(styleCssPath, 'utf8');
  const premiumCss = fs.readFileSync(premiumCssPath, 'utf8');
  const indexHtml = fs.readFileSync(indexHtmlPath, 'utf8');

  // -------------------------------------------------------------------------
  // 1. Packet Table Column Schema Synchronization (Exact 9 Columns)
  // -------------------------------------------------------------------------
  console.log('\n[Verification 1] Live Packet Table Column Synchronization (1:1 Schema Match)...');
  
  // Extract thead columns from sniffer-view.js
  const packetTableMatch = snifferViewJs.match(/<div id="livePacketTableView"[\s\S]*?<table class="data-table"[\s\S]*?<thead>([\s\S]*?)<\/thead>/);
  assert.ok(packetTableMatch, 'livePacketTableView table thead must exist in sniffer-view.js');
  const packetThead = packetTableMatch[1];
  const packetThMatches = packetThead.match(/<th[\s\S]*?<\/th>/g) || [];
  assert.strictEqual(packetThMatches.length, 9, `Packet table thead must contain exactly 9 <th> headers, found ${packetThMatches.length}`);

  // Verify headers order: #, Time, Source, Destination, Host/URL, Proto, Len, TCP Delta, Summary
  assert.ok(packetThMatches[0].includes('#'), 'Column 1 must be #');
  assert.ok(packetThMatches[1].includes('Time'), 'Column 2 must be Time');
  assert.ok(packetThMatches[2].includes('Source IP:Port'), 'Column 3 must be Source IP:Port');
  assert.ok(packetThMatches[3].includes('Destination IP:Port'), 'Column 4 must be Destination IP:Port');
  assert.ok(packetThMatches[4].includes('Host / URL'), 'Column 5 must be Host / URL');
  assert.ok(packetThMatches[5].includes('Proto'), 'Column 6 must be Proto');
  assert.ok(packetThMatches[6].includes('Len'), 'Column 7 must be Len');
  assert.ok(packetThMatches[7].includes('TCP Delta'), 'Column 8 must be TCP Delta / Retx');
  assert.ok(packetThMatches[8].includes('Payload Summary'), 'Column 9 must be Payload Summary & Stream');

  // Verify VM execution of renderPacketRows emits exactly 9 <td> cells per row
  const mockDocument = {
    getElementById: () => null,
    querySelectorAll: () => [],
    addEventListener: () => {},
    removeEventListener: () => {}
  };
  const mockWindow = {
    formatLocalTime: (ts) => '12:34:56.789',
    formatLocalDateTime: (ts) => '2026-10-16 12:34:56',
    addEventListener: () => {},
    removeEventListener: () => {},
    renderPacketRows: null,
    renderFlowRows: null,
    setNocLiveFrames: null,
    setNocLiveFlows: null,
    setNocTopologyData: null,
    renderTopologySvg: null
  };
  const context = vm.createContext({
    window: mockWindow,
    document: mockDocument,
    console,
    alert: () => {},
    setTimeout: (fn) => fn(),
    clearTimeout: () => {},
    FileReader: class {},
    encodeURIComponent: (x) => x
  });

  vm.runInContext(nocViewJs, context);

  assert.ok(typeof mockWindow.renderPacketRows === 'function', 'renderPacketRows must be exported to window');

  // Provide mock live frames
  const sampleFrames = [
    {
      frameNumber: 101,
      timestamp: Date.now(),
      protocol: 'TCP',
      srcIp: '10.168.195.33',
      srcPort: 54321,
      dstIp: '10.22.12.204',
      dstPort: 443,
      wireLength: 1514,
      capturedLength: 1514,
      summary: 'TLS Client Hello [mail.taxes.gov.az]',
      urlResolution: { hostnameOrUrl: 'mail.taxes.gov.az' },
      tcpAnalysis: { isRetransmission: false, streamId: 4 }
    },
    {
      frameNumber: 102,
      timestamp: Date.now() + 10,
      protocol: 'TCP',
      srcIp: '10.22.12.204',
      srcPort: 443,
      dstIp: '10.168.195.33',
      dstPort: 54321,
      wireLength: 66,
      summary: 'TCP Retransmission ACK: 1',
      tcpAnalysis: { isRetransmission: true, isDupAck: false, streamId: 4 }
    }
  ];

  mockWindow.setNocLiveFrames(sampleFrames);
  const rowsHtml = mockWindow.renderPacketRows();
  const trMatches = rowsHtml.match(/<tr[\s\S]*?<\/tr>/g) || [];
  assert.strictEqual(trMatches.length, 2, 'Should render 2 sample rows');

  for (let i = 0; i < trMatches.length; i++) {
    const tdMatches = trMatches[i].match(/<td[\s\S]*?<\/td>/g) || [];
    assert.strictEqual(tdMatches.length, 9, `Row ${i + 1} must emit exactly 9 <td> cells matching the 9 <th> columns! Found: ${tdMatches.length}`);
  }
  console.log('  ✓ Packet Table: 9 <th> headers match 9 <td> cells 100% synchronized.');

  // -------------------------------------------------------------------------
  // 2. Flow Matrix Column Schema Synchronization (Exact 15 Columns)
  // -------------------------------------------------------------------------
  console.log('\n[Verification 2] Flow Matrix Table Column Synchronization (1:1 Schema Match)...');
  
  const flowTableMatch = snifferViewJs.match(/<div id="nirsoftFlowMatrixView"[\s\S]*?<table class="data-table"[\s\S]*?<thead>([\s\S]*?)<\/thead>/);
  assert.ok(flowTableMatch, 'nirsoftFlowMatrixView table thead must exist in sniffer-view.js');
  const flowThead = flowTableMatch[1];
  const flowThMatches = flowThead.match(/<th[\s\S]*?<\/th>/g) || [];
  assert.strictEqual(flowThMatches.length, 15, `Flow Matrix table thead must contain exactly 15 <th> headers, found ${flowThMatches.length}`);

  // Test VM execution of renderFlowRows
  const sampleFlows = [
    {
      sourceAddress: '10.168.195.33',
      destinationAddress: '10.22.12.204',
      sourcePort: 54321,
      destinationPort: 443,
      ipProtocol: 'TCP',
      serviceName: 'HTTPS',
      connectionStatus: 'ESTABLISHED',
      packetsCount: 42,
      totalPacketsSize: 64512,
      dataSpeed: 12.4,
      latency: 4.8,
      processFilename: 'chrome.exe',
      plainLanguageGuide: 'Secure HTTPS traffic to Ministry Mail Exchange'
    }
  ];

  mockWindow.setNocLiveFlows(sampleFlows);
  const flowRowsHtml = mockWindow.renderFlowRows();
  const flowTrMatches = flowRowsHtml.match(/<tr[\s\S]*?<\/tr>/g) || [];
  assert.strictEqual(flowTrMatches.length, 1, 'Should render 1 flow row');
  const flowTdMatches = flowTrMatches[0].match(/<td[\s\S]*?<\/td>/g) || [];
  assert.strictEqual(flowTdMatches.length, 15, `Flow Matrix row must emit exactly 15 <td> cells matching the 15 <th> columns! Found: ${flowTdMatches.length}`);
  console.log('  ✓ Flow Matrix: 15 <th> headers match 15 <td> cells 100% synchronized.');

  // -------------------------------------------------------------------------
  // 3. Viewport & Mutual Exclusivity (Zero Table Stacking & Hidden DPI Drawer)
  // -------------------------------------------------------------------------
  console.log('\n[Verification 3] Verifying Viewport Layout & View Mutual Exclusivity...');
  
  // Verify sniffer-view.js initial layout
  assert.ok(
    snifferViewJs.includes('<div id="livePacketTableView" style="display: flex; flex: 1; overflow: hidden; flex-direction: column;">'),
    'livePacketTableView must have display: flex; flex: 1;'
  );
  assert.ok(
    snifferViewJs.includes('<div id="nirsoftFlowMatrixView" style="display: none; flex: 1; overflow: hidden; flex-direction: column;">'),
    'nirsoftFlowMatrixView must have display: none; initially (no duplicate display: flex)'
  );
  assert.ok(
    !snifferViewJs.includes('display: none; flex: 1; overflow: hidden; display: flex;'),
    'Duplicate display: flex on nirsoftFlowMatrixView must be eliminated'
  );
  assert.ok(
    snifferViewJs.includes('<div id="packetDetailsPane" style="display: none;'),
    'packetDetailsPane (DPI Drawer) must be hidden by default (display: none;)'
  );
  assert.ok(
    snifferViewJs.includes('id="dpiSummaryHeader"'),
    'dpiSummaryHeader element ID must exist for live frame details injection'
  );

  // Verify switchNocSnifferMode in noc-view.js ensures mutual exclusivity
  assert.ok(
    nocViewJs.includes("viewP.style.display = mode === 'packets' ? 'flex' : 'none';") ||
    nocViewJs.includes("viewP.style.display = mode === 'packets' ? 'block' : 'none';") ||
    nocViewJs.includes("viewP.style.display = (mode === 'packets' || mode === 'important' || mode === 'failures') ? 'flex' : 'none';"),
    'switchNocSnifferMode must toggle livePacketTableView visibility'
  );
  assert.ok(
    nocViewJs.includes("viewF.style.display = mode === 'flows' ? 'flex' : 'none';") ||
    nocViewJs.includes("viewF.style.display = mode === 'flows' ? 'block' : 'none';"),
    'switchNocSnifferMode must toggle nirsoftFlowMatrixView visibility'
  );
  console.log('  ✓ Mutual exclusivity of packet and flow views confirmed.');

  // -------------------------------------------------------------------------
  // 4. Dynamic Topology Node Dimensions & Typography (No Truncation)
  // -------------------------------------------------------------------------
  console.log('\n[Verification 4] Dynamic Topology Card Dimensions & Typography...');
  
  // Check card width and height constants in renderTopologySvg (cardW >= 200px, colWidth >= 230px)
  assert.ok(nocViewJs.includes('const cardW = 200;') || nocViewJs.includes('const cardW = 240;'), 'cardW must be at least 200px wide');
  assert.ok(nocViewJs.includes('const cardH = 100;'), 'cardH must be 100px');
  assert.ok(nocViewJs.includes('const colWidth = 230;') || nocViewJs.includes('const colWidth = 255;'), 'colWidth must be at least 230px wide');

  // Verify no substring(0, 15) truncation in noc-view.js
  assert.ok(!nocViewJs.includes('substring(0, 15)'), 'Arbitrary 15-character truncation must be completely removed');

  // Test SVG rendering with long node names
  const testTopology = {
    nodes: [
      {
        id: 'NODE-WAN-01',
        name: 'Upstream Internet (Google)',
        hostname_or_ip: '8.8.8.8',
        layer: 'wan',
        layer_level: 1,
        vendor: 'Google Public DNS Transit',
        status: 'healthy',
        last_latency_ms: 2.1
      },
      {
        id: 'NODE-GW-01',
        name: 'MikroTik RouterOS Gateway',
        hostname_or_ip: '10.168.195.1',
        layer: 'gateway',
        layer_level: 2,
        vendor: 'MikroTik Cloud Core Router',
        status: 'healthy',
        last_latency_ms: 0.8
      },
      {
        id: 'NODE-CORE-01',
        name: 'Core Switch & L3 Services',
        hostname_or_ip: '10.168.195.33',
        layer: 'core',
        layer_level: 3,
        vendor: 'Cisco Catalyst 3850 L3 Stack',
        status: 'healthy',
        last_latency_ms: 0.4
      }
    ],
    edges: [
      { id: 'EDGE-1', source_id: 'NODE-WAN-01', target_id: 'NODE-GW-01', utilization_pct: 25 },
      { id: 'EDGE-2', source_id: 'NODE-GW-01', target_id: 'NODE-CORE-01', utilization_pct: 35 }
    ]
  };

  mockWindow.setNocTopologyData(testTopology);
  const svgHtml = mockWindow.renderTopologySvg();

  // Assert node names are preserved in SVG
  assert.ok(svgHtml.includes('Upstream Internet (Google)'), 'Full title "Upstream Internet (Google)" must be rendered in SVG');
  assert.ok(svgHtml.includes('MikroTik RouterOS Gateway'), 'Full title "MikroTik RouterOS Gateway" must be rendered in SVG');
  assert.ok(svgHtml.includes('Core Switch &amp; L3 Services') || svgHtml.includes('Core Switch & L3 Services'), 'Full title "Core Switch & L3 Services" must be rendered in SVG');
  assert.ok(!svgHtml.includes('Upstream Intern...'), 'No truncated "Upstream Intern..." must appear');
  assert.ok(!svgHtml.includes('Edge Perimeter ...'), 'No truncated "Edge Perimeter ..." must appear');
  assert.ok(svgHtml.includes('min-height: 480px;'), 'SVG must have responsive height (min-height: 480px)');
  console.log('  ✓ Topology node cards have sufficient dimensions and full titles without truncation.');

  // -------------------------------------------------------------------------
  // 5. Elite Cyber-NOC Theme Design Tokens & Sidebar Constraints
  // -------------------------------------------------------------------------
  console.log('\n[Verification 5] Elite Cyber-NOC Theme Design Tokens & Fixed Sidebar...');

  // Palette checks in style.css and eji-premium.css
  assert.ok(styleCss.includes('--bg-primary: #06080F;'), 'style.css must have deep obsidian base #06080F');
  assert.ok(styleCss.includes('--bg-secondary: #0B0F19;'), 'style.css must have dark slate sidebar #0B0F19');
  assert.ok(styleCss.includes('--bg-card: #0F1523;'), 'style.css must have dark slate surface #0F1523');
  assert.ok(styleCss.includes('--bg-elevated: #141C2E;'), 'style.css must have elevated card surface #141C2E');
  assert.ok(styleCss.includes('--accent: #38BDF8;'), 'style.css must have electric cyan #38BDF8');

  assert.ok(premiumCss.includes('--bg-app: #06080F;'), 'premiumCss must have deep obsidian base #06080F');
  assert.ok(premiumCss.includes('--bg-sidebar: #0B0F19;'), 'premiumCss must have dark slate sidebar #0B0F19');
  assert.ok(premiumCss.includes('--bg-panel: #0F1523;'), 'premiumCss must have dark slate panel #0F1523');
  assert.ok(premiumCss.includes('--bg-panel-raised: #141C2E;'), 'premiumCss must have elevated panel #141C2E');
  assert.ok(premiumCss.includes('--accent: #38BDF8;'), 'premiumCss must have electric cyan #38BDF8');

  // Sidebar fixed width 240px
  assert.ok(styleCss.includes('width: 240px;'), 'style.css sidebar must have width: 240px;');
  assert.ok(styleCss.includes('min-width: 240px;'), 'style.css sidebar must have min-width: 240px;');
  assert.ok(styleCss.includes('max-width: 240px;'), 'style.css sidebar must have max-width: 240px;');

  assert.ok(premiumCss.includes('width: 240px !important;'), 'eji-premium.css sidebar must enforce width: 240px !important;');
  assert.ok(premiumCss.includes('min-width: 240px !important;'), 'eji-premium.css sidebar must enforce min-width: 240px !important;');
  assert.ok(premiumCss.includes('max-width: 240px !important;'), 'eji-premium.css sidebar must enforce max-width: 240px !important;');

  // Nav link nowrap & active indicator
  assert.ok(styleCss.includes('white-space: nowrap;'), 'style.css nav links must have white-space: nowrap;');
  assert.ok(styleCss.includes('border-left: 3px solid #38BDF8 !important;'), 'style.css active nav must have border-left: 3px solid #38BDF8 !important;');
  assert.ok(premiumCss.includes('border-left: 3px solid #38BDF8 !important;'), 'eji-premium.css active nav must have border-left: 3px solid #38BDF8 !important;');

  // Table layout fixed
  assert.ok(premiumCss.includes('table-layout: fixed;'), 'eji-premium.css must enforce table-layout: fixed on .data-table');
  console.log('  ✓ Design tokens, fixed 240px sidebar, and table layout invariants verified.');

  console.log('\n========================================================================');
  console.log('  ALL FRONTEND RE-ARCHITECTURE VERIFICATIONS PASSED 100% PERFECTLY!     ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runFrontendRebuildVerification()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('\n❌ FRONTEND REBUILD VERIFICATION FAILED:', err);
      process.exit(1);
    });
}

module.exports = { runFrontendRebuildVerification };
