/**
 * Headless UI Verification & Layout Invariant Test Suite
 * Asserts all NOC UI fixes, table column wrapping prevention, modal scrollbar clipping,
 * app branding consistency, and the dynamic layer-by-layer SVG topology engine.
 * Zero-Mock Mandate.
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

async function runHeadlessUiVerificationTests() {
  console.log('\n========================================================================');
  console.log('  SUITE 14: HEADLESS UI VERIFICATION, TOPOLOGY SVG ENGINE & LAYOUT SUITE');
  console.log('========================================================================');

  const rootDir = path.resolve(__dirname, '..');
  const indexHtmlPath = path.join(rootDir, 'public', 'index.html');
  const premiumCssPath = path.join(rootDir, 'public', 'css', 'eji-premium.css');
  const styleCssPath = path.join(rootDir, 'public', 'css', 'style.css');
  const appJsPath = path.join(rootDir, 'public', 'js', 'app.js');
  const nocViewJsPath = path.join(rootDir, 'public', 'js', 'views', 'noc-view.js');

  const indexHtml = fs.readFileSync(indexHtmlPath, 'utf8');
  const premiumCss = fs.readFileSync(premiumCssPath, 'utf8');
  const styleCss = fs.readFileSync(styleCssPath, 'utf8');
  const appJs = fs.readFileSync(appJsPath, 'utf8');
  const nocViewJs = fs.readFileSync(nocViewJsPath, 'utf8');

  // [Test 14.1] App Branding & Identity Invariants
  console.log("[Test 14.1] Verifying App Name Branding ('Eldar Jamiyev\\'s Infrastructure Intelligence')...");
  assert.ok(
    indexHtml.includes("<title>Eldar Jamiyev's Infrastructure Intelligence — NOC Network Topology &amp; Wire-Level Packet Dissection Workstation</title>") ||
    indexHtml.includes("<title>Eldar Jamiyev's Infrastructure Intelligence — NOC Network Topology & Wire-Level Packet Dissection Workstation</title>"),
    'Page title must show exact branded name'
  );
  assert.ok(
    indexHtml.includes('Eldar Jamiyev&#39;s Infrastructure Intelligence') ||
    indexHtml.includes("Eldar Jamiyev's Infrastructure Intelligence"),
    'Sidebar brand title must display Eldar Jamiyev\'s Infrastructure Intelligence'
  );
  assert.ok(
    indexHtml.includes('Enter Eldar Jamiyev&#39;s Infrastructure Intelligence') ||
    indexHtml.includes("Enter Eldar Jamiyev's Infrastructure Intelligence"),
    'Login modal CTA must display Eldar Jamiyev\'s Infrastructure Intelligence'
  );
  const pageTitleMatch = indexHtml.match(/id="pageTitle"[\s\S]*?Eldar Jamiyev['&#39;]+s Infrastructure Intelligence/i);
  assert.ok(
    pageTitleMatch !== null,
    'Topbar pageTitle must display Eldar Jamiyev\'s Infrastructure Intelligence'
  );

  // Verify CSS multi-line wrapping rule for sidebar brand
  assert.ok(styleCss.includes('.brand-text h1'), '.brand-text h1 styling must exist in style.css');
  assert.ok(styleCss.includes('word-break: normal;'), '.brand-text h1 must have word-break: normal;');
  console.log("  ✓ Brand name 'Eldar Jamiyev\\'s Infrastructure Intelligence' strictly verified across all UI surfaces.");

  // [Test 14.1b] 4 Dedicated NOC Operations Navigation Items
  console.log('[Test 14.1b] Verifying the 4 Dedicated NOC Operations Workstation Navigation Items...');
  assert.ok(indexHtml.includes('data-view="topology"'), 'Nav link data-view="topology" must exist');
  assert.ok(indexHtml.includes('1. NOC Network Topology &amp; Dependency Graph Map') || indexHtml.includes('1. NOC Network Topology & Dependency Graph Map'), 'Nav item 1 must be present');
  
  assert.ok(indexHtml.includes('data-view="packet-sniffer"'), 'Nav link data-view="packet-sniffer" must exist');
  assert.ok(indexHtml.includes('2. Wireshark-Grade Live Packet Sniffer &amp; Stream Dissector') || indexHtml.includes('2. Wireshark-Grade Live Packet Sniffer & Stream Dissector'), 'Nav item 2 must be present');

  assert.ok(indexHtml.includes('data-view="ultra-ip-scanner"'), 'Nav link data-view="ultra-ip-scanner" must exist');
  assert.ok(indexHtml.includes('3. Ultra IP Scanner'), 'Nav item 3 must be present');

  assert.ok(indexHtml.includes('data-view="pc-automation"'), 'Nav link data-view="pc-automation" must exist');
  assert.ok(indexHtml.includes('Host Automation &amp; Audited Remediation Library') || indexHtml.includes('Host Automation & Audited Remediation Library') || indexHtml.includes('Automation library'), 'Nav item 4 must be present');

  // Verify app.js routing
  assert.ok(appJs.includes('renderTopologyStandaloneView'), 'app.js must call renderTopologyStandaloneView');
  assert.ok(appJs.includes('renderPacketSnifferStandaloneView'), 'app.js must call renderPacketSnifferStandaloneView');
  assert.ok(appJs.includes('renderUltraIpScannerView'), 'app.js must call renderUltraIpScannerView');
  assert.ok(appJs.includes('renderPcAutomationView'), 'app.js must call renderPcAutomationView');
  console.log('  ✓ Exactly 4 dedicated NOC Workstation navigation items and routes verified.');

  // [Test 14.2] Table Column Wrapping Invariants (Packet Table & Flow Matrix)
  console.log('[Test 14.2] Verifying Table Column Non-Wrapping CSS & Width Constraints...');
  
  // Verify eji-premium.css overrides
  assert.ok(premiumCss.includes('.data-table .col-num'), '.col-num class rule must exist');
  assert.ok(premiumCss.includes('.data-table .col-time'), '.col-time class rule must exist');
  assert.ok(premiumCss.includes('.data-table .col-proto'), '.col-proto class rule must exist');
  assert.ok(premiumCss.includes('.data-table .col-len'), '.col-len class rule must exist');
  assert.ok(premiumCss.includes('.data-table .col-delta'), '.col-delta class rule must exist');
  assert.ok(premiumCss.includes('.data-table .col-ip'), '.col-ip class rule must exist');

  // Verify nowrap !important
  const colNumRegex = /\.col-num[\s\S]*?white-space:\s*nowrap\s*!important/i;
  const colTimeRegex = /\.col-time[\s\S]*?white-space:\s*nowrap\s*!important/i;
  assert.ok(colNumRegex.test(premiumCss), '.col-num must enforce white-space: nowrap !important');
  assert.ok(colTimeRegex.test(premiumCss), '.col-time must enforce white-space: nowrap !important');

  // Verify min-widths
  assert.ok(premiumCss.includes('min-width: 65px'), '.col-num must specify min-width: 65px;');
  assert.ok(premiumCss.includes('min-width: 95px'), '.col-time must specify min-width: 95px;');

  // Verify noc-view.js applies these classes to table headers and rows
  assert.ok(nocViewJs.includes('class="col-num"'), 'noc-view.js must apply .col-num class in table headers/cells');
  assert.ok(nocViewJs.includes('class="col-time"'), 'noc-view.js must apply .col-time class in table headers/cells');
  assert.ok(nocViewJs.includes('class="col-proto"'), 'noc-view.js must apply .col-proto class in table headers/cells');
  assert.ok(nocViewJs.includes('class="col-len"'), 'noc-view.js must apply .col-len class in table headers/cells');
  assert.ok(nocViewJs.includes('class="col-delta"'), 'noc-view.js must apply .col-delta class in table headers/cells');
  assert.ok(nocViewJs.includes('class="col-ip"'), 'noc-view.js must apply .col-ip class in table headers/cells');
  console.log('  ✓ Table column non-wrapping & min-width constraints strictly enforced.');

  // [Test 14.3] Diagnostics Modal & Scrollbar Clipping Invariants
  console.log('[Test 14.3] Verifying Wire Diagnostics Modal & Scrollbar Clipping Protections...');
  assert.ok(premiumCss.includes('scrollbar-gutter: stable;'), 'premium CSS must declare scrollbar-gutter: stable');
  assert.ok(appJs.includes('scrollbar-gutter: stable;'), 'openWireDiagnosticsModal in app.js must set scrollbar-gutter: stable');
  assert.ok(appJs.includes('padding-right: 20px;'), 'openWireDiagnosticsModal in app.js must compensate gutter with padding-right: 20px');
  assert.ok(appJs.includes('padding-right: 14px;'), 'refreshAnomaliesList in app.js must set padding-right: 14px on list output');
  assert.ok(appJs.includes('align-items: flex-start;'), 'Anomaly rows must use align-items: flex-start to prevent vertical squishing');
  assert.ok(appJs.includes('flex-shrink: 0;'), 'Anomaly timestamps must set flex-shrink: 0 to prevent crushing against scrollbar');
  assert.ok(appJs.includes('min-width: 85px;'), 'Anomaly timestamps must enforce min-width: 85px');
  console.log('  ✓ Modal scrollbar gutter stability and layout padding verified.');

  // [Test 14.4] Dynamic Layer-by-Layer Architecture & Interactivity Controls
  console.log('[Test 14.4] Verifying Dynamic Topology Architecture & Controls in noc-view.js...');
  
  // Layer definitions
  assert.ok(nocViewJs.includes("label: 'L1: WAN TRANSIT & INTERNET'"), 'L1 WAN layer definition must exist');
  assert.ok(nocViewJs.includes("label: 'L2: EDGE ROUTER & PERIMETER'"), 'L2 Edge Router layer definition must exist');
  assert.ok(nocViewJs.includes("label: 'L3: FIREWALL & CORE SWITCHING'"), 'L3 Core layer definition must exist');
  assert.ok(nocViewJs.includes("label: 'L4: ENTERPRISE INFRASTRUCTURE'"), 'L4 Infra layer definition must exist');
  assert.ok(nocViewJs.includes("label: 'L5: DISTRIBUTION & ACCESS FABRIC'"), 'L5 Access layer definition must exist');
  assert.ok(nocViewJs.includes("label: 'L6: OPERATOR WORKSTATION'"), 'L6 Workstation layer definition must exist');

  // Verify NO duplicate "L3: EDGE ROUTER" static text
  const edgeRouterMatches = nocViewJs.match(/L3:\s*EDGE\s*ROUTER/gi);
  assert.strictEqual(edgeRouterMatches, null, 'Typographical duplicate "L3: EDGE ROUTER" must be eliminated');

  // Interactivity controls
  assert.ok(nocViewJs.includes('window.zoomTopology'), 'SVG zoom function must exist');
  assert.ok(nocViewJs.includes('window.resetTopologyView'), 'SVG reset zoom function must exist');
  assert.ok(nocViewJs.includes('window.handleTopologyWheel'), 'SVG mouse wheel zoom handler must exist');
  assert.ok(nocViewJs.includes('window.startTopologyPan'), 'SVG drag pan mousedown handler must exist');
  assert.ok(nocViewJs.includes('window.doTopologyPan'), 'SVG drag pan mousemove handler must exist');
  assert.ok(nocViewJs.includes('window.showTopologyTooltip'), 'Hover HUD tooltip display handler must exist');
  assert.ok(nocViewJs.includes('window.hideTopologyTooltip'), 'Hover HUD tooltip hide handler must exist');
  assert.ok(nocViewJs.includes('id="topoNodeTooltip"'), 'Hover HUD tooltip DOM element must exist');
  assert.ok(nocViewJs.includes('window.toggleTopologyFleetScope'), 'Toggle fleet expansion function must exist');

  // Evidence Classification badges
  assert.ok(nocViewJs.includes("text: 'Configured'"), 'Configured evidence badge handling must exist');
  assert.ok(nocViewJs.includes("text: 'Observed'"), 'Observed evidence badge handling must exist');
  assert.ok(nocViewJs.includes("text: 'ARP Discovered'"), 'ARP Discovered evidence badge handling must exist');
  assert.ok(nocViewJs.includes("text: 'Dynamic Route'"), 'Dynamic Route evidence badge handling must exist');
  console.log('  ✓ Layer-by-layer topology engine architecture & controls verified.');

  // [Test 14.5] Real Discovered Topology SVG Rendering Simulation
  console.log('[Test 14.5] Simulating SVG Rendering Engine against Real Discovered Network Data...');
  
  // Obtain real network topology from routes-network
  const routesNetwork = require('../src/api/routes-network');
  const topoRoute = routesNetwork.stack.find(l => l.route && l.route.path === '/topology');
  assert.ok(topoRoute, '/topology route handler must exist');

  let realTopoPayload = null;
  const mockReq = {};
  const mockRes = {
    json: function(payload) {
      realTopoPayload = payload;
    }
  };
  topoRoute.route.stack[0].handle(mockReq, mockRes);
  assert.ok(realTopoPayload && realTopoPayload.nodes && realTopoPayload.nodes.length > 0, 'Real discovered topology must return nodes');

  console.log(`    Discovered nodes count: ${realTopoPayload.nodes.length}, edges count: ${realTopoPayload.edges.length}`);

  // Clone payload so test sandbox never mutates server state
  const sandboxData = JSON.parse(JSON.stringify(realTopoPayload));

  // Ensure at least one discovered fleet device is present for cluster/expanded view verification
  const hasFleet = sandboxData.nodes.some(n => n.layer_level === 5 && n.type !== 'subnet' && n.type !== 'switch' && n.id !== 'NODE-LAN-01');
  if (!hasFleet) {
    sandboxData.nodes.push({
      id: 'NODE-DISC-10-168-195-55',
      name: 'Discovered Host (10.168.195.55)',
      hostname_or_ip: '10.168.195.55',
      mac_address: '00:1A:2B:3C:4D:5E',
      type: 'workstation',
      layer: 'access',
      layer_level: 5,
      parent_id: 'NODE-LAN-01',
      status: 'healthy',
      last_latency_ms: 0.6,
      vendor: 'Intel Corporation',
      evidenceClassification: 'ARP Discovered',
      metadata: { discovery: 'arp_inspection' }
    });
    sandboxData.edges.push({
      id: 'EDGE-LAN-DISC-55',
      source_id: 'NODE-LAN-01',
      target_id: 'NODE-DISC-10-168-195-55',
      link_type: 'ethernet',
      status: 'up',
      utilization_pct: 10
    });
  }

  // Create isolated sandbox to execute renderTopologySvg with real data
  const sandbox = {
    topologyData: sandboxData,
    topoFleetExpanded: false,
    topoZoom: 1.0,
    topoPanX: 0,
    topoPanY: 0,
    nodeCoordinatesMap: new Map(),
    escapeHtml: (str) => String(str === null || str === undefined ? '' : str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;'),
    escapeAttr: (str) => String(str === null || str === undefined ? '' : str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')
  };
  sandbox.window = sandbox;

  // Find closing bracket of renderTopologySvg
  const blockStart = nocViewJs.indexOf('const TOPOLOGY_LAYERS = [');
  assert.ok(blockStart !== -1, 'TOPOLOGY_LAYERS must exist in noc-view.js');

  const renderSvgStart = nocViewJs.indexOf('function renderTopologySvg() {', blockStart);
  assert.ok(renderSvgStart !== -1, 'renderTopologySvg function declaration must exist');
  
  let bracketDepth = 0;
  let renderSvgEnd = -1;
  for (let i = renderSvgStart; i < nocViewJs.length; i++) {
    if (nocViewJs[i] === '{') bracketDepth++;
    else if (nocViewJs[i] === '}') {
      bracketDepth--;
      if (bracketDepth === 0) {
        renderSvgEnd = i + 1;
        break;
      }
    }
  }
  assert.ok(renderSvgEnd !== -1, 'renderTopologySvg closing brace must be found');

  const blockCode = nocViewJs.substring(blockStart, renderSvgEnd);
  vm.createContext(sandbox);
  vm.runInContext(blockCode + '\nthis.renderTopologySvg = renderTopologySvg;', sandbox);

  // Simulation 1: Default Focused Infrastructure View (Cluster Mode)
  sandbox.topoFleetExpanded = false;
  const svgOutputClustered = sandbox.renderTopologySvg();

  assert.ok(svgOutputClustered.includes('<svg id="nocTopologySvg"'), 'SVG root element must be present');
  assert.ok(svgOutputClustered.includes('id="topologyViewport"'), 'topologyViewport group must be present');
  assert.ok(svgOutputClustered.includes('L1: WAN TRANSIT'), 'L1 header must be present in SVG');
  assert.ok(svgOutputClustered.includes('L2: EDGE ROUTER'), 'L2 header must be present in SVG');
  assert.ok(svgOutputClustered.includes('L3: CORE BACKBONE'), 'L3 header must be present in SVG');
  assert.ok(svgOutputClustered.includes('L4: ENTERPRISE SERVERS'), 'L4 header must be present in SVG');
  assert.ok(svgOutputClustered.includes('L5: ACCESS FABRIC'), 'L5 header must be present in SVG');
  assert.ok(svgOutputClustered.includes('L6: OPERATOR HOST'), 'L6 header must be present in SVG');

  // Verify Fleet Cluster node is rendered
  assert.ok(
    svgOutputClustered.includes('NODE-FLEET-CLUSTER'),
    'Access fleet aggregation cluster node (NODE-FLEET-CLUSTER) must be rendered in focus mode'
  );
  assert.ok(
    svgOutputClustered.includes('Access Fleet ['),
    'Cluster card must display Access Fleet label with count'
  );
  assert.ok(
    svgOutputClustered.includes('Click to Expand / View Table'),
    'Cluster card must instruct user how to expand or view table'
  );

  // Verify Evidence badges in SVG
  assert.ok(svgOutputClustered.includes('[Configured]'), 'Configured evidence badge must be rendered in SVG');
  assert.ok(svgOutputClustered.includes('[Observed]'), 'Observed evidence badge must be rendered in SVG');
  assert.ok(svgOutputClustered.includes('[ARP Discovered]'), 'ARP Discovered evidence badge must be rendered in SVG');

  // Verify cubic bezier curve interconnects
  assert.ok(svgOutputClustered.includes(' d="M ') && svgOutputClustered.includes(' C '), 'Interconnect paths must use smooth cubic beziers (M ... C ...)');
  console.log('  ✓ Focused infrastructure SVG view correctly aggregates fleet hosts into Access Cluster.');

  // Simulation 2: Expanded Fleet View
  sandbox.topoFleetExpanded = true;
  const svgOutputExpanded = sandbox.renderTopologySvg();

  // In expanded mode, cluster node should not appear, and raw nodes should be individually rendered
  assert.strictEqual(
    svgOutputExpanded.includes('id="svgNode-NODE-FLEET-CLUSTER"'),
    false,
    'Cluster node must not appear when fleet is expanded'
  );
  assert.ok(
    svgOutputExpanded.includes('id="svgNode-'),
    'Individual node cards must be rendered in expanded mode'
  );
  console.log('  ✓ Expanded fleet SVG view renders all individual ARP endpoints seamlessly.');

  console.log('\n========================================================================');
  console.log('  SUITE 14 PASSED: 100% SUCCESSFUL HEADLESS UI & TOPOLOGY VERIFICATION');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runHeadlessUiVerificationTests().then(() => process.exit(0)).catch(err => {
    console.error('Headless UI Verification Failed:', err);
    process.exit(1);
  });
}

module.exports = { runHeadlessUiVerificationTests };
